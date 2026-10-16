#!/usr/bin/env python3
"""Differential check: generated PER layout table  vs  the pycrate oracle.

`tools/asn1gen.py` walks pycrate's ASN.1 schema and emits a declarative table;
`tools/lte_per.py` interprets that table with no pycrate at runtime. Both were
written by reading the specification and pycrate's structure, so the only thing
that can establish whether the pair is right is encoding the *same value* two
ways and comparing the bits.

This script does that, over many randomly generated values per type. It is
deliberately driven by **pycrate's** object graph, not by the generated table:
generating the test values from the table under test would assume the thing
being checked.

Why random values rather than a handful of hand-written ones: the constructs
that break a PER codec are the ones nobody writes by hand -- a sequence whose
only present component is the last optional, a list at exactly its maximum
size, an integer sitting on its upper bound, an extension addition present on
its own. A fixed few vectors never reach them.

Four properties this script insists on, all of which an earlier version got
wrong in ways that still produced a green run:

* **Every table type is exercised, or named in EXCUSED with a reason.**  The
  table emits 1031 types; checking only the handful of roots left the leaf
  definitions -- which the roots are built out of, and which are where a wrong
  constraint hides -- unexamined.  A type with zero cases fails the run.
* **A root is looked up in every namespace `asn1gen.py` walks.**  Searching
  one module silently skipped `HandoverCommand`, which lives in
  EUTRA-InterNodeDefinitions, and reported the skip as a footnote.
* **Every table node is audited against the pycrate object it came from.**
  Bit comparison only proves that a construct the generator *did emit* encodes
  correctly; it says nothing about a construct the generator dropped or
  approximated, which encodes to something self-consistent.  The audit compares
  node kind, component order, presence-bit membership, defaults, constraints,
  sizes, choice and enumeration alternatives and extension-addition nesting
  against pycrate directly.
* **Constraint shapes are read as pycrate writes them.**  `get_const()['val']`
  is an ASN1Set, not a dict; reading `.lb`/`.ub` off it raised, the old code
  treated every constrained type as unconstrained, pycrate rejected every
  generated value, and the four types that hit this reported zero cases while
  the run exited 0.

Run it with the oracle interpreter, which has pycrate:

    /home/ysl/.lte-oracles/venv/bin/python \\
        tools/lte-per-oracle/verify_per.py --table tools/lte_rrc_layout.py

Exit 0 when every case agrees and every type was covered, 1 on any
disagreement, uncovered type or audit mismatch, 2 if it could not set up.
"""

import argparse
import copy
import hashlib
import importlib.util
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.normpath(os.path.join(HERE, os.pardir))

# Table types this run may not exercise, mapping the type name to the reason.
# An entry is a hole in the evidence and is printed as one; the honest thing is
# to keep this empty and fix whatever cannot be driven.
EXCUSED = {}

# pycrate's TYPE name -> the node kind `asn1gen.py` emits for it.  SET maps to
# the same kind as SEQUENCE: the generator refuses a SET whose canonical order
# differs from its declaration order, so the two encode identically.
KIND = {
    "SEQUENCE": "seq",
    "SET": "seq",
    "CHOICE": "choice",
    "SEQUENCE OF": "seqof",
    "SET OF": "seqof",
    "INTEGER": "int",
    "ENUMERATED": "enum",
    "BOOLEAN": "bool",
    "BIT STRING": "bits",
    "OCTET STRING": "octets",
    "NULL": "null",
}

AGGREGATES = ("SEQUENCE", "SET", "CHOICE", "SEQUENCE OF", "SET OF")

# A failure that means the two encoders produced different bits.  Everything
# else is a hole in the evidence rather than a disagreement.
BIT_KINDS = ("encode", "decode", "disagree", "roundtrip")


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def is_stub(obj):
    """A named aggregate pycrate left unexpanded until it is dereferenced."""
    return (obj.TYPE in AGGREGATES
            and getattr(obj, "_root", None) is None
            and getattr(obj, "_cont", None) is None)


# ---------------------------------------------------------------------------
# Constraint reading.
#
# pycrate keeps a constraint as an ASN1Set whose `root` is a list of either
# bare values (a single permitted value, e.g. SIZE(3)) or range objects with
# .lb/.ub.  The first version of this script indexed `const['val']['root']` and
# read `.lb`/`.ub` off the result: an ASN1Set is not subscriptable, the lookup
# raised, the handler returned "no constraint", and the generator then fed
# out-of-range values to pycrate.  Every case was rejected before it could be
# compared, so the types that hit this reported zero cases and the run passed.
#
# `ext` is not None for an extensible constraint; the root ranges below then
# cover only the root part.
# ---------------------------------------------------------------------------

def ranges_of(cset):
    """The root ranges of a pycrate constraint, as ``[(lb, ub), ...]``.

    Returns None when there is no constraint, and raises ValueError for a shape
    that cannot be turned into ranges (multi-valued entries, open bounds).
    Silently falling back to a default range is what let a whole class of types
    go untested, so an unreadable shape is an error rather than a default.
    """
    if cset is None or cset == "":
        return None
    root = getattr(cset, "root", None)
    if not root:
        return None
    out = []
    for r in root:
        lb = getattr(r, "lb", None)
        ub = getattr(r, "ub", None)
        if lb is None and ub is None:
            if isinstance(r, bool) or not isinstance(r, int):
                raise ValueError("constraint entry %r has no bounds" % (r,))
            out.append((r, r))
        elif lb is None or ub is None:
            raise ValueError("open-ended constraint %r..%r" % (lb, ub))
        else:
            out.append((lb, ub))
    return out or None


def size_of(obj):
    """``[lb, ub]`` for a SIZE constraint, or None."""
    r = ranges_of(getattr(obj, "_const_sz", None))
    if r is None:
        return None
    if len(r) != 1:
        raise ValueError("multi-range SIZE constraint %r" % (r,))
    return [r[0][0], r[0][1]]


def value_range_of(obj):
    """``(ranges, ext)`` for an INTEGER value constraint; ranges may be None."""
    cset = getattr(obj, "_const_val", None)
    return ranges_of(cset), (getattr(cset, "ext", None) is not None)


# ---------------------------------------------------------------------------
# Random value generation, driven by the pycrate object graph.
# ---------------------------------------------------------------------------

class Gen(object):
    def __init__(self, rnd, max_elem=3, depth_limit=16):
        self.rnd = rnd
        self.max_elem = max_elem
        self.depth_limit = depth_limit

    def _size(self, obj, default_lo=1, default_hi=2):
        try:
            r = size_of(obj)
        except ValueError:
            r = None
        if r is None:
            lo, hi = default_lo, default_hi
        else:
            lo, hi = r
        hi = min(hi, lo + self.max_elem)
        if hi < lo:
            hi = lo
        return self.rnd.randint(lo, hi)

    def _int(self, obj):
        r, ext = value_range_of(obj)
        if r is None:
            return self.rnd.choice([0, 1, -1, 127, 255, 65535])
        lo, hi = r[self.rnd.randrange(len(r))]
        if ext and self.rnd.random() < 0.25:
            # An extension addition: outside the root range but still a value
            # the type admits.  Root-only values never reach that branch of the
            # codec.
            return hi + 1 + self.rnd.randint(0, 3)
        # Hit the bounds often: off-by-one in a range is the classic defect.
        return self.rnd.choice([lo, hi, self.rnd.randint(lo, hi), lo, hi])

    # -- the generator -----------------------------------------------------
    def value(self, obj, depth=0):
        t = obj.TYPE
        if depth > self.depth_limit:
            return self._minimal(obj, depth)

        if t == "BOOLEAN":
            return self.rnd.choice([True, False])
        if t == "NULL":
            return 0
        if t == "INTEGER":
            return self._int(obj)
        if t == "ENUMERATED":
            # _cont covers the extension additions as well as the root items,
            # so a random pick exercises both encodings.
            return self.rnd.choice(list(obj._cont))
        if t == "BIT STRING":
            n = self._size(obj, 1, 8)
            return (self.rnd.getrandbits(n), n)
        if t == "OCTET STRING":
            n = self._size(obj, 1, 4)
            return bytes(self.rnd.getrandbits(8) for _ in range(n))
        if t in ("SEQUENCE OF", "SET OF"):
            n = self._size(obj, 1, 2)
            elem = obj._cont
            return [self.value(elem, depth + 1) for _ in range(n)]
        if t == "CHOICE":
            # _cont includes the extension alternatives.
            pick = self.rnd.choice(list(obj._cont))
            return (pick, self.value(obj._cont[pick], depth + 1))
        if t in ("SEQUENCE", "SET"):
            return self._seq(obj, depth)
        raise ValueError("unhandled TYPE %r" % t)

    def _seq(self, obj, depth):
        out = {}
        for name in list(getattr(obj, "_root_mand", None) or []):
            out[name] = self.value(obj._cont[name], depth + 1)
        opt = list(getattr(obj, "_root_opt", None) or [])
        # Uniform presence is not enough on its own: the shapes that break the
        # presence bitmap are "only the last optional present" and "every
        # optional present", and both are vanishingly rare under 50/50 when a
        # sequence has a dozen optionals.
        roll = self.rnd.random()
        if roll < 0.2 and opt:
            present = [opt[self.rnd.randrange(len(opt))]]
        elif roll < 0.35 and opt:
            present = list(opt)
        else:
            present = [n for n in opt if self.rnd.random() < 0.5]
        for name in present:
            out[name] = self._optional(obj._cont[name], depth)
        self._extadds(obj, out, depth)
        return out

    def _optional(self, child, depth):
        """A component value, biased towards its DEFAULT when it has one.

        A DEFAULT component sits in the parent's presence bitmap exactly like
        an OPTIONAL one, and canonical PER encodes the two spellings of it --
        present-and-equal-to-the-default, which is dropped, and
        present-and-different -- as different bits.  Both have to be sent.
        """
        d = getattr(child, "_def", None)
        if d is not None and self.rnd.random() < 0.5:
            return d
        return self.value(child, depth + 1)

    def _extadds(self, obj, out, depth):
        nest = getattr(obj, "_ext_nest", None)
        if not nest:
            return
        ident = getattr(obj, "_ext_ident", None) or {}
        groups = getattr(obj, "_ext_group_obj", None) or {}
        for entry in nest:
            if isinstance(entry, list):
                # A group is named once in the bitmap and every present member
                # is written into one open type; the members are individually
                # optional, so a partly present group is legal and is what a
                # decoder is most likely to get wrong.
                gobj = groups.get(ident.get(entry[0]))
                if gobj is None:
                    continue
                for inner in entry:
                    if self.rnd.random() < 0.3:
                        out[inner] = self.value(gobj._cont[inner], depth + 1)
            elif self.rnd.random() < 0.3:
                out[entry] = self.value(obj._cont[entry], depth + 1)

    @staticmethod
    def _floor(obj, lo_default=0):
        """The smallest length a constrained string or list type may take."""
        try:
            r = size_of(obj)
        except ValueError:
            r = None
        return r[0] if r else lo_default

    def _minimal(self, obj, depth):
        """The smallest value the schema allows, used past the depth limit.

        Everything that can be left out is left out; a length sits at its floor
        and a choice takes its first alternative.  A mandatory chain cannot
        cycle -- that would describe a type no value can inhabit -- so this
        terminates, and it keeps the type being tested rather than reporting it
        as ungeneratable.  Reporting a type as having no cases is the one
        outcome this script exists to refuse.
        """
        if depth > self.depth_limit + 40:
            raise ValueError("mandatory cycle at %s" % (obj._name,))
        t = obj.TYPE
        if t == "BOOLEAN":
            return False
        if t == "NULL":
            return 0
        if t == "INTEGER":
            r = value_range_of(obj)
            return r[0][0] if r else 0
        if t == "ENUMERATED":
            names = list(obj._root) or list(obj._ext or [])
            if not names:
                raise ValueError("ENUMERATED %s has no items" % (obj._name,))
            return names[0]
        if t == "BIT STRING":
            return (0, self._floor(obj))
        if t == "OCTET STRING":
            return bytes(self._floor(obj))
        if t in ("SEQUENCE OF", "SET OF"):
            return [self._minimal(obj._cont, depth + 1)
                    for _ in range(self._floor(obj))]
        if t == "CHOICE":
            names = list(obj._root) or list(obj._ext or [])
            if not names:
                raise ValueError("CHOICE %s has no alternatives" % (obj._name,))
            return (names[0], self._minimal(obj._cont[names[0]], depth + 1))
        if t in ("SEQUENCE", "SET"):
            return dict(
                (name, self._minimal(obj._cont[name], depth + 1))
                for name in list(getattr(obj, "_root_mand", None) or [])
            )
        raise ValueError("unhandled TYPE %r" % t)


def pycrate_bits(obj):
    """The object's unaligned PER encoding, as a bit string, and its length.

    Derived from pycrate's own encoder, so it is the oracle for the
    comparison.  ``bl`` can be zero (an empty open type); ``format(v, "00b")``
    would yield a spurious "0" bit there, so the empty case is spelled out.
    """
    out = []
    n = 0
    for _t, v, bl in obj._to_per():
        if isinstance(v, int):
            out.append(format(v, "0%db" % bl) if bl else "")
        elif isinstance(v, bytes):
            out.append("".join(format(b, "08b") for b in v)[:bl])
        else:
            out.append(str(v))
        n += bl
    return "".join(out), n


# ---------------------------------------------------------------------------
# Audit: every table node against the pycrate object it was generated from.
#
# The differential phase can only fail on a construct the generator *did*
# emit.  A construct it dropped, flattened or defaulted encodes to something
# self-consistent, so no amount of bit comparison finds it.  These checks walk
# the table and the live pycrate graph side by side instead.
# ---------------------------------------------------------------------------

class Audit(object):
    def __init__(self, types, index):
        self.types = types
        self.index = index
        self.mismatch = []
        self.nodes = 0
        self.unsupported = []

    def bad(self, where, msg):
        self.mismatch.append("%s: %s" % (where, msg))
        return None

    def run(self):
        for key in sorted(self.types):
            obj = self.index.get(key)
            if obj is None:
                self.bad(key, "table type does not resolve to a pycrate object")
                continue
            self.node(self.types[key], obj, key)
        return self.mismatch

    # -- dispatch ----------------------------------------------------------
    def node(self, node, obj, where):
        self.nodes += 1
        if not isinstance(node, dict):
            return self.bad(where, "table node is not a dict")
        k = node.get("k")
        if k == "unsupported":
            self.unsupported.append((where, node.get("why")))
            return None
        if k == "ref":
            return self.ref(node, obj, where)
        atype = getattr(obj, "TYPE", None)
        want = KIND.get(atype)
        if want is None:
            return self.bad(where, "pycrate TYPE %r has no table node kind" % (atype,))
        if k != want:
            return self.bad(where, "table node %r but pycrate TYPE is %r" % (k, atype))
        return getattr(self, "chk_" + k)(node, obj, where)

    def ref(self, node, obj, where):
        key = node.get("t")
        tgt = self.index.get(key)
        if tgt is None:
            return self.bad(where, "ref %r does not resolve to a pycrate type" % (key,))
        if key not in self.types:
            return self.bad(where, "ref %r is not itself in the table" % (key,))
        if getattr(tgt, "TYPE", None) != getattr(obj, "TYPE", None):
            return self.bad(where, "ref %r is a %r, the component is a %r"
                            % (key, tgt.TYPE, getattr(obj, "TYPE", None)))
        if getattr(tgt, "_param", None):
            return self.bad(where, "ref %r is an unbound parameterized template" % (key,))
        if is_stub(obj):
            return None
        a = getattr(obj, "_root", None)
        b = getattr(tgt, "_root", None)
        if (a is None) != (b is None):
            return self.bad(where, "ref %r has components %r, the component has %r"
                            % (key, b, a))
        if a is not None and tuple(a) != tuple(b):
            return self.bad(where, "ref %r has components %r, the component has %r"
                            % (key, tuple(b), tuple(a)))
        return None

    # -- constraint / size -------------------------------------------------
    def _const(self, node, obj, attr, field, low, high, where):
        try:
            got = ranges_of(getattr(obj, attr, None))
        except ValueError as exc:
            return self.bad(where, "pycrate %s is not a single range (%s)" % (attr, exc))
        if got is None:
            if node.get(field) is not None:
                return self.bad(where, "table %s is %r but pycrate has no %s"
                                % (field, node.get(field), attr))
            return None
        if len(got) != 1:
            return self.bad(where, "pycrate %s has %d ranges; the table can hold "
                                   "one" % (attr, len(got)))
        lb, ub = got[0]
        if (lb, ub) != (low, high):
            return self.bad(where, "table %s is %r but pycrate %s is %r"
                            % (field, (low, high), attr, (lb, ub)))
        return None

    def chk_int(self, node, obj, where):
        lb, ub = node.get("lb"), node.get("ub")
        self._const(node, obj, "_const_val", "lb", lb, ub, where)
        cset = getattr(obj, "_const_val", None)
        have = cset is not None and cset != ""
        if have and getattr(cset, "ext", None) is not None:
            self.bad(where, "pycrate value constraint is extensible; the table "
                            "cannot express an extension-addition value")
        if node.get("ext") and not have:
            self.bad(where, "table says the INTEGER is extensible but pycrate "
                            "carries no value constraint")
        return None

    def chk_bits(self, node, obj, where):
        return self._size(node, obj, where)

    def chk_seqof(self, node, obj, where):
        self._size(node, obj, where)
        elem = getattr(obj, "_cont", None)
        if elem is None:
            return self.bad(where, "pycrate SEQUENCE OF has no element type")
        # The element is a node of its own.  Not descending here left 307
        # nodes -- every element type that is not a named type -- outside the
        # "every table node is compared" claim.
        return self.node(node.get("of"), elem, where + ".<elem>")

    def _size(self, node, obj, where):
        size = node.get("size")
        low = size[0] if size else None
        high = size[1] if size else None
        self._const(node, obj, "_const_sz", "size", low, high, where)
        cset = getattr(obj, "_const_sz", None)
        if cset is not None and cset != "" and getattr(cset, "ext", None) is not None:
            self.bad(where, "pycrate SIZE constraint is extensible; the table "
                            "cannot express an extension-addition length")
        if size and size[1] >= 65536:
            # X.691 sends a length whose upper bound reaches 65536 with an
            # unconstrained length determinant, not with the offset bits the
            # table's `size` implies.  No type in these namespaces is that
            # large, so the divergence is latent -- but the table cannot say
            # which encoding applies, so it must not be emitted silently.
            self.bad(where, "SIZE upper bound %d needs an unconstrained length "
                            "determinant, which the table cannot express" % size[1])
        return None

    def chk_octets(self, node, obj, where):
        self._size(node, obj, where)
        cc = getattr(obj, "_const_cont", None)
        want = getattr(cc, "_name", None) if cc is not None else None
        got = node.get("containing")
        if (want or None) != (got or None):
            self.bad(where, "table containing=%r but pycrate CONTAINING is %r"
                            % (got, want))
        return None

    def chk_bool(self, node, obj, where):
        return None

    def chk_null(self, node, obj, where):
        return None

    # -- structures --------------------------------------------------------
    @staticmethod
    def _default_form(child):
        """Whether a DEFAULT has a spelling the table can carry."""
        d = getattr(child, "_def", None)
        if d is None or isinstance(d, bool) or isinstance(d, int) or isinstance(d, str):
            return True
        return (isinstance(d, tuple) and len(d) == 2
                and all(isinstance(x, int) for x in d))

    def chk_seq(self, node, obj, where):
        order = list(obj._root)
        if getattr(obj, "TYPE", None) == "SET":
            canon = getattr(obj, "_root_canon", None)
            if canon is None or list(canon) != order:
                self.bad(where, "SET canonical order %r differs from the "
                                "declaration order %r the table emits"
                         % (canon, order))
        names = [c[0] for c in node["comp"]]
        if names != order:
            return self.bad(where, "table components %r but pycrate has %r"
                            % (names, order))
        if node.get("ext") != (getattr(obj, "_ext", None) is not None):
            self.bad(where, "table ext=%r but pycrate _ext is %s"
                     % (node.get("ext"),
                        "set" if getattr(obj, "_ext", None) is not None else "None"))
        # The bit that matters is not the ASN.1 OPTIONAL keyword but whether
        # pycrate puts the component in its presence bitmap, and that is
        # OPTIONAL *or* DEFAULT.
        preamble = list(getattr(obj, "_root_opt", None) or [])
        for name, cnode, opt, dflt in node["comp"]:
            child = obj._cont[name]
            if not self._default_form(child):
                self.bad("%s.%s" % (where, name),
                         "pycrate DEFAULT %r has no spelling the table carries"
                         % (getattr(child, "_def", None),))
            if bool(opt or dflt is not None) != (name in preamble):
                self.bad("%s.%s" % (where, name),
                         "table says presence bit %r (optional=%r default=%r) but "
                         "pycrate's preamble %r %s it"
                         % (bool(opt or dflt is not None), opt, dflt, preamble,
                            "contains" if name in preamble else "does not contain"))
            if dflt != getattr(child, "_def", None):
                self.bad("%s.%s" % (where, name), "table default %r but pycrate %r"
                         % (dflt, getattr(child, "_def", None)))
            self.node(cnode, child, "%s.%s" % (where, name))
        return self.extadd(node.get("extadd") or [], obj, where)

    def extadd(self, entries, obj, where):
        ext = getattr(obj, "_ext", None)
        if ext is None:
            if entries:
                self.bad(where, "table has extension additions for a type "
                                "pycrate says is not extensible")
            return None
        nest = getattr(obj, "_ext_nest", None)
        if nest is None:
            return self.bad(where, "pycrate has _ext but no _ext_nest")
        flat = []
        for entry in nest:
            flat.extend(entry if isinstance(entry, list) else [entry])
        if flat != list(ext):
            self.bad(where, "_ext_nest %r does not cover _ext %r in order"
                     % (nest, list(ext)))
        if len(entries) != len(nest):
            return self.bad(where, "table has %d extension entr(ies), pycrate has "
                                   "%d" % (len(entries), len(nest)))
        ident = getattr(obj, "_ext_ident", None) or {}
        groups = getattr(obj, "_ext_group_obj", None) or {}
        for entry, want in zip(entries, nest):
            if isinstance(want, list):
                if entry.get("k") != "extgrp":
                    self.bad(where, "table extension entry %r is not a group for "
                                    "pycrate's group %r" % (entry.get("k"), want))
                    continue
                if list(entry.get("names") or []) != list(want):
                    self.bad(where, "table extension group %r but pycrate has %r"
                             % (entry.get("names"), want))
                    continue
                ids = set(ident.get(n) for n in want)
                if len(ids) != 1:
                    # pycrate takes the group object from the first *present*
                    # member, so members spread over two groups would make the
                    # encoding depend on which member happened to come first.
                    self.bad(where, "extension group %r spans group ids %r"
                             % (want, ids))
                    continue
                gobj = groups.get(ident.get(want[0]))
                if gobj is None:
                    self.bad(where, "extension group %r has no group object" % (want,))
                    continue
                self.node(entry["node"], gobj, "%s.<ext %s>" % (where, "|".join(want)))
            else:
                if entry.get("k") != "extone":
                    self.bad(where, "table extension entry %r is not a single "
                                    "addition for pycrate's %r"
                             % (entry.get("k"), want))
                    continue
                if entry.get("name") != want:
                    self.bad(where, "table extension %r but pycrate has %r"
                             % (entry.get("name"), want))
                    continue
                if want not in obj._cont:
                    self.bad(where, "extension %r is not a component of the "
                                    "sequence" % (want,))
                    continue
                self.node(entry["node"], obj._cont[want], "%s.%s" % (where, want))
        return None

    def chk_choice(self, node, obj, where):
        alts = [a[0] for a in node["alts"]]
        if alts != list(obj._root):
            return self.bad(where, "table alternatives %r but pycrate has %r"
                            % (alts, list(obj._root)))
        if node.get("ext") != (getattr(obj, "_ext", None) is not None):
            self.bad(where, "table ext=%r but pycrate _ext is %s"
                     % (node.get("ext"),
                        "set" if getattr(obj, "_ext", None) is not None else "None"))
        ext = [a[0] for a in node.get("extadd") or []]
        if ext != list(getattr(obj, "_ext", None) or []):
            self.bad(where, "table extension alternatives %r but pycrate has %r"
                     % (ext, list(getattr(obj, "_ext", None) or [])))
            return None
        for name, cnode in node["alts"]:
            self.node(cnode, obj._cont[name], "%s.%s" % (where, name))
        for name, cnode in node.get("extadd") or []:
            self.node(cnode, obj._cont[name], "%s.%s" % (where, name))
        return None

    def chk_enum(self, node, obj, where):
        if list(node["names"]) != list(obj._root):
            return self.bad(where, "table items %r but pycrate has %r"
                            % (node["names"], list(obj._root)))
        ext = getattr(obj, "_ext", None)
        if node.get("ext") is None:
            if ext is not None:
                self.bad(where, "table says not extensible but pycrate _ext is %r"
                         % (list(ext),))
        elif list(ext or []) != list(node["ext"]):
            self.bad(where, "table extension items %r but pycrate has %r"
                     % (node["ext"], list(ext or [])))
        if len(node["names"]) + len(node.get("ext") or []) != len(obj._cont):
            self.bad(where, "table carries %d item(s), pycrate has %d"
                     % (len(node["names"]) + len(node.get("ext") or []),
                        len(obj._cont)))
        return None


# ---------------------------------------------------------------------------
# Differential run.
# ---------------------------------------------------------------------------

class Series(object):
    """What one type's differential run produced."""

    __slots__ = ("cases", "agrees", "entries", "fails")

    def __init__(self):
        self.cases = 0          # values pycrate encoded and ours had to match
        self.agrees = 0
        self.entries = []       # (value, pycrate bits) for the agreed cases
        self.fails = []         # (kind, text)


def run_series(rnd, codec, key, obj, cases, fresh):
    """Encode `cases` random values with pycrate and with the table codec.

    `obj` is reused across cases unless `fresh` is set.  pycrate's set_val
    replaces the whole value, so reuse cannot leak a previous case's value into
    the next one -- and deep-copying a root object costs over a second, which
    is what kept the old script at 40 cases over 9 types.  The caller proves
    the two modes agree rather than assuming it.
    """
    res = Series()
    gen = Gen(rnd)
    attempts = 0
    limit = max(cases * 8, 8)
    work = None
    while res.cases < cases and attempts < limit:
        attempts += 1
        if work is None or fresh:
            work = copy.deepcopy(obj)
        try:
            val = gen.value(work)
        except Exception as exc:
            # Generation is driven by the same object every attempt, so a
            # failure here will not become a success by retrying.
            res.fails.append(("harness", "%s: could not generate a value: %s"
                              % (key, exc)))
            break
        try:
            work.set_val(val)
        except Exception as exc:
            if attempts >= limit:
                res.fails.append(("gen", "%s: pycrate rejected every generated "
                                         "value, last: %s" % (key, exc)))
            continue
        try:
            want, _wbits = pycrate_bits(work)
        except Exception as exc:
            # pycrate declining to encode a value it accepted is an oracle
            # problem, not a codec problem; it is still not a tested case.
            if attempts >= limit:
                res.fails.append(("oracle", "%s: pycrate could not encode its own "
                                            "value: %s" % (key, exc)))
            continue
        res.cases += 1

        try:
            got = codec.encode_bits(key, val)
        except Exception as exc:
            res.fails.append(("encode", "%s: encode raised %s\n    value=%r\n"
                                        "    want=%s" % (key, exc, val, want)))
            continue
        if got != want:
            first = next((i for i in range(min(len(got), len(want)))
                          if got[i] != want[i]), min(len(got), len(want)))
            res.fails.append(("disagree",
                              "%s: DISAGREE at bit %d (pycrate %d bits, ours %d)\n"
                              "    value=%r\n    want=%s\n    got =%s"
                              % (key, first, len(want), len(got), val, want, got)))
            continue
        try:
            back = codec.decode_bits(key, want)
            again = codec.encode_bits(key, back)
        except Exception as exc:
            res.fails.append(("decode", "%s: decode raised %s\n    value=%r\n"
                                        "    bits=%s" % (key, exc, val, want)))
            continue
        if again != want:
            res.fails.append(("roundtrip", "%s: round-trip differs\n    value=%r\n"
                                           "    want=%s\n    again=%s"
                              % (key, val, want, again)))
            continue
        res.agrees += 1
        res.entries.append((val, want))
    return res


def build_index(asn1gen):
    """``{table key: pycrate object}`` for every named type in every namespace.

    Built with the generator's own registry and key function, so the index
    cannot disagree with the table about what a key means.
    """
    reg, by_name = asn1gen.build_registry()
    key_of, collisions = asn1gen.make_key_of(reg, by_name)
    index = {}
    for _modname, mod in asn1gen.MODULES:
        for attr in sorted(vars(mod)):
            if attr.startswith("_"):
                continue
            obj = getattr(mod, attr)
            if not hasattr(obj, "TYPE"):
                continue
            key = key_of.get(id(obj))
            if key is not None and key not in index:
                index[key] = obj
    return index, collisions


def digest(entries, n):
    h = hashlib.sha256()
    for _val, want in entries[:n]:
        h.update(want.encode("ascii"))
        h.update(b"\x00")
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", required=True,
                    help="generated layout table (tools/asn1gen.py --out ...)")
    ap.add_argument("--per", default=os.path.join(HERE, "..", "lte_per.py"),
                    help="the PER engine to test")
    ap.add_argument("--cases", type=int, default=40,
                    help="random values per root type (default 40)")
    ap.add_argument("--leaf-cases", type=int, default=12,
                    help="random values per non-root type (default 12)")
    ap.add_argument("--seed", type=int, default=20261016)
    ap.add_argument("--only", default=None,
                    help="comma-separated type names to restrict to; coverage "
                         "accounting is disabled for a restricted run")
    ap.add_argument("--fresh-check", type=int, default=12,
                    help="how many types to re-run with a fresh object per case "
                         "to prove that reuse changes nothing (default 12)")
    ap.add_argument("--fresh-cases", type=int, default=6,
                    help="cases per type in the fresh-object check (default 6)")
    ap.add_argument("--no-audit", action="store_true",
                    help="skip the table-vs-pycrate structural audit")
    ap.add_argument("--verbose", action="store_true",
                    help="print a line for every type, not just the roots")
    args = ap.parse_args(argv)

    try:
        from pycrate_asn1dir import RRCLTE  # noqa: F401  (the import is the check)
    except ImportError:
        sys.stderr.write(
            "this check needs pycrate; run it with the oracle interpreter:\n"
            "  /home/ysl/.lte-oracles/venv/bin/python %s --table ...\n"
            % os.path.relpath(__file__))
        return 2

    try:
        asn1gen = load_module(os.path.join(TOOLS, "asn1gen.py"), "asn1gen")
    except Exception as exc:
        sys.stderr.write("cannot load tools/asn1gen.py: %s\n" % exc)
        return 2

    per = load_module(os.path.abspath(args.per), "lte_per")
    tbl = load_module(os.path.abspath(args.table), "lte_rrc_layout")
    codec = per.codec_from_module(tbl)

    types = dict(getattr(tbl, "TYPES", {}) or {})
    roots = list(getattr(tbl, "ROOTS", []) or [])
    if not types:
        sys.stderr.write("the table declares no TYPES; nothing to check\n")
        return 2

    try:
        index, collisions = build_index(asn1gen)
    except Exception as exc:
        sys.stderr.write("cannot index the pycrate namespaces: %s\n" % exc)
        return 2

    restricted = bool(args.only)
    selected = list(types)
    if restricted:
        selected = [t for t in args.only.split(",") if t]
        missing = [t for t in selected if t not in types]
        if missing:
            sys.stderr.write("not in the table: %s\n" % ", ".join(missing))
            return 2
        roots = [t for t in roots if t in selected]

    # -- structural audit ---------------------------------------------------
    failures = []           # (kind, text)
    audit_nodes = 0
    unsupported = []
    if not args.no_audit:
        audit = Audit(types, index)
        audit.run()
        audit_nodes = audit.nodes
        unsupported = audit.unsupported
        failures.extend(("audit", m) for m in audit.mismatch)

    # -- differential run ---------------------------------------------------
    total_cases = total_agrees = 0
    zero_cases = []
    unresolved = []
    ran = set()
    rnd_seed = "verify_per:%d:" % args.seed
    fresh_keys = set()
    if args.fresh_check > 0:
        fresh_keys.update(roots)
        step = max(1, len(selected) // max(1, args.fresh_check))
        fresh_keys.update(selected[::step][:args.fresh_check])

    print("  %-40s %6s  %s" % ("type", "cases", "check"))
    for key in selected:
        obj = index.get(key)
        if obj is None:
            unresolved.append(key)
            print("  %-40s %6s  %s" % (key, "-", "UNRESOLVED"))
            if not restricted:
                failures.append(("unresolved", "%s: no pycrate object in any "
                                               "namespace the generator walks"
                                   % key))
            continue
        want_cases = args.cases if key in roots else args.leaf_cases
        try:
            res = run_series(random.Random(rnd_seed + key), codec, key, obj,
                             want_cases, False)
        except Exception as exc:            # a crash is a failure, not a skip
            res = Series()
            res.fails.append(("harness", "%s: harness crashed: %s" % (key, exc)))
        ran.add(key)
        total_cases += res.cases
        total_agrees += res.agrees
        failures.extend((k, t) for k, t in res.fails)
        if res.cases == 0:
            zero_cases.append(key)

        note = "ok" if not res.fails else "%d FAILURE(S)" % len(res.fails)
        if key in fresh_keys and res.cases > 0:
            n = min(args.fresh_cases, res.cases)
            fresh = run_series(random.Random(rnd_seed + key), codec, key, obj,
                               n, True)
            if fresh.fails:
                failures.extend(("fresh", "%s: fresh-object run: %s" % (key, t))
                                for _k, t in fresh.fails)
                note = "fresh-object FAILED"
            elif digest(fresh.entries, n) != digest(res.entries, n):
                failures.append(("fresh", "%s: reusing one object per case changed "
                                          "the encoded values -- the fast path is "
                                          "not equivalent to a fresh deep copy"
                                          % key))
                note = "fresh-object MISMATCH"
            else:
                note += ", reuse==fresh(%d)" % n
        if key not in roots and not args.verbose and not res.fails:
            continue
        print("  %-40s %6d  %s" % (key, res.cases, note))

    # -- coverage -----------------------------------------------------------
    excused = {k: v for k, v in EXCUSED.items() if k in types}
    stale = [k for k in EXCUSED if k not in types]
    uncovered = [k for k in sorted(types) if k not in ran and k not in unresolved]
    if not restricted:
        for k in uncovered:
            failures.append(("uncovered", "%s: not exercised and not in EXCUSED" % k))
        for k in zero_cases:
            failures.append(("nocase", "%s: 0 cases -- a type nothing was checked "
                                       "against cannot be reported as verified" % k))
        for k in stale:
            failures.append(("stale", "EXCUSED names %s, which is not in the table" % k))

    exercised = sum(1 for k in types if k in ran)
    bit_fails = [t for k, t in failures if k in BIT_KINDS]
    other = [t for k, t in failures if k not in BIT_KINDS]

    print()
    print("types checked : %d of %d table type(s), %d root type(s)%s"
          % (len(selected) - len(unresolved), len(types), len(roots),
             " (restricted run: coverage accounting off)" if restricted else ""))
    if not restricted:
        print("coverage      : %d exercised, %d excused, %d unresolved, "
              "%d with zero cases" % (exercised, len(excused), len(unresolved),
                                      len(uncovered) + len(zero_cases)))
    print("struct audit  : %d node(s) compared, %d mismatch(es), "
          "%d unsupported node(s)"
          % (audit_nodes, len([t for k, t in failures if k == "audit"]),
             len(unsupported)))
    print("fresh-object  : %d type(s) re-run, 0 mismatch(es)"
          % len(fresh_keys) if args.fresh_check > 0 else
          "fresh-object  : not checked")
    print("cases         : %d" % total_cases)
    print("agree         : %d" % total_agrees)
    print("disagree      : %d" % len(bit_fails))
    if unsupported:
        print()
        print("constructs the generator refused to emit:")
        for where, why in unsupported[:20]:
            print("  %s: %s" % (where, why))
    if other:
        print()
        print("coverage / audit failures:")
        for t in other[:10]:
            print("  " + t)
        if len(other) > 10:
            print("  ... and %d more" % (len(other) - 10))
    if bit_fails:
        print()
        for t in bit_fails[:10]:
            print("  " + t)
        if len(bit_fails) > 10:
            print("  ... and %d more" % (len(bit_fails) - 10))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
