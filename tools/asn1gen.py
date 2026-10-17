#!/usr/bin/env python3
"""Generate a declarative unaligned-PER layout table for LTE RRC types.

Reads the ASN.1 structure of 3GPP TS 36.331 message types out of the pycrate
oracle and emits a plain-data Python table that ``tools/lte_per.py`` interprets.

pycrate is a **build-time oracle only**.  It is LGPL v2.1+; no pycrate source is
copied into this repository and the emitted table imports nothing at all.  This
script itself must be run with the oracle interpreter::

    /home/ysl/.lte-oracles/venv/bin/python tools/asn1gen.py --out /tmp/asn1gen/lte_rrc_layout.py

Output is deterministic: types are emitted in sorted order and every node's keys
are written in a fixed order, so re-running the generator on the same pycrate
build produces a byte-identical file.
"""

import argparse
import datetime
import os
import sys

from pycrate_asn1dir import RRCLTE

# --------------------------------------------------------------------------
# Namespaces the generator resolves named-type references against.
# --------------------------------------------------------------------------

MODULES = [
    ("EUTRA-RRC-Definitions", RRCLTE.EUTRA_RRC_Definitions),
    ("EUTRA-InterNodeDefinitions", RRCLTE.EUTRA_InterNodeDefinitions),
    ("EUTRA-UE-Variables", RRCLTE.EUTRA_UE_Variables),
    ("EUTRA-Sidelink-Preconf", RRCLTE.EUTRA_Sidelink_Preconf),
    ("PC5-RRC-Definitions", RRCLTE.PC5_RRC_Definitions),
    ("NBIOT-RRC-Definitions", RRCLTE.NBIOT_RRC_Definitions),
    ("NBIOT-InterNodeDefinitions", RRCLTE.NBIOT_InterNodeDefinitions),
    ("NBIOT-UE-Variables", RRCLTE.NBIOT_UE_Variables),
]

MODULE_ALIASES = {
    "RRC": "EUTRA-RRC-Definitions",
    "INTER": "EUTRA-InterNodeDefinitions",
    "UEVAR": "EUTRA-UE-Variables",
    "SIDELINK": "EUTRA-Sidelink-Preconf",
    "PC5": "PC5-RRC-Definitions",
    "NBIOT": "NBIOT-RRC-Definitions",
    "NBIOTINTER": "NBIOT-InterNodeDefinitions",
    "NBIOTUEVAR": "NBIOT-UE-Variables",
}

DEFAULT_TYPES = [
    "SystemInformationBlockType1",
    "SystemInformationBlockType2",
    "SystemInformationBlockType3",
    "SystemInformationBlockType4",
    "SystemInformationBlockType5",
    "SystemInformationBlockType6",
    "SystemInformationBlockType7",
    "SystemInformationBlockType8",
    # SIB9 to SIB13 are decoded by the generic engine rather than a transcribed
    # codec, so their roots have to be in the table. TS 36.331 never defines
    # SIB12 or SIB13 in an unsuffixed form -- they enter at Rel-9 -- and
    # pycrate names them accordingly. hasattr(module,
    # "SystemInformationBlockType13") is False and tells you nothing; the -r9
    # spelling is the only one that exists, and grepping RRCLTE.py finds it
    # where the unsuffixed name cannot.
    "SystemInformationBlockType9",
    "SystemInformationBlockType10",
    "SystemInformationBlockType11",
    "SystemInformationBlockType12_r9",
    "SystemInformationBlockType13_r9",
    "RRCConnectionReconfiguration",
    "INTER.HandoverCommand",
]

# The ASN.1 namespaces this generator can be pointed at.  The table format and
# the engine are the same for both; only the pycrate modules, the default
# module for an unqualified --types entry, and the default root set differ.
# Adding a family here is the whole cost of a second protocol -- a second
# generator would be a second implementation of the same closure walk.
FAMILIES = {}


def _register_rrc():
    FAMILIES["rrc"] = {
        "modules": MODULES,
        "aliases": MODULE_ALIASES,
        "default_module": "EUTRA-RRC-Definitions",
        "default_types": DEFAULT_TYPES,
        "out": "lte_rrc_layout.py",
        "description": "LTE RRC (TS 36.331)",
    }


def _register_lpp():
    """LPP (TS 37.355), the positioning protocol.

    The forged position report needs the ProvideLocationInformation half, but
    a table is generated per family and the whole closure of LPP_Message is
    cheaper to carry than a second table for each message type.
    """
    from pycrate_asn1dir import LPP

    FAMILIES["lpp"] = {
        "modules": [
            ("LPP-PDU-Definitions", LPP.LPP_PDU_Definitions),
            ("LPP-Broadcast-Definitions", LPP.LPP_Broadcast_Definitions),
        ],
        "aliases": {
            "PDU": "LPP-PDU-Definitions",
            "BCAST": "LPP-Broadcast-Definitions",
        },
        "default_module": "LPP-PDU-Definitions",
        "default_types": ["LPP_Message"],
        "out": "lpp_layout.py",
        "description": "LPP (TS 37.355)",
    }


DEFAULT_MODULE = "EUTRA-RRC-Definitions"


def use_family(name):
    """Point the module-level namespace globals at one ASN.1 family.

    Called once from main() so that every function below keeps reading the
    same globals it always did; a family is a data switch, not a second code
    path.
    """
    global MODULES, MODULE_ALIASES, DEFAULT_TYPES, DEFAULT_MODULE
    fam = FAMILIES[name]
    MODULES = fam["modules"]
    MODULE_ALIASES = fam["aliases"]
    DEFAULT_TYPES = fam["default_types"]
    DEFAULT_MODULE = fam["default_module"]


# The ASN.1 constructs this generator can express.  Everything else becomes an
# ``unsupported`` marker so the engine refuses instead of mis-encoding.
KNOWN_TYPES = (
    "SEQUENCE",
    "SET",
    "CHOICE",
    "SEQUENCE OF",
    "SET OF",
    "INTEGER",
    "ENUMERATED",
    "BOOLEAN",
    "BIT STRING",
    "OCTET STRING",
    "NULL",
)


class Unsupported(Exception):
    """A construct the generator cannot express in the table."""


# --------------------------------------------------------------------------
# Oracle access helpers.
# --------------------------------------------------------------------------


def typeref_of(obj):
    """The raw ``get_typeref()`` target, or None if the type is inline."""
    try:
        tr = obj.get_typeref()
    except Exception:
        return None
    return None if tr is obj else tr


def _is_stub(obj):
    """True for an aggregate that carries no structure of its own.

    pycrate leaves a component as a bare reference stub in a few places, and
    an *unbound parameterized template* (``_param`` truthy, e.g. ``SetupRelease``)
    always looks like this.
    """
    return (
        getattr(obj, "TYPE", None)
        in ("SEQUENCE", "SET", "CHOICE", "SEQUENCE OF", "SET OF")
        and getattr(obj, "_root", None) is None
        and getattr(obj, "_cont", None) is None
    )


def _is_const(v):
    """True for a non-empty ASN1Set constraint; pycrate uses '' as "absent"."""
    return v is not None and v != ""


def _single_range(cset, what):
    """``(lb, ub)`` of a single-entry root constraint set."""
    if cset.ext is not None:
        raise Unsupported("extensible %s constraint" % what)
    root = list(cset.root)
    if len(root) != 1:
        raise Unsupported(
            "%s constraint with %d root entries (multi-range is not implemented)"
            % (what, len(root))
        )
    entry = root[0]
    if isinstance(entry, int):
        return (entry, entry)
    lb = getattr(entry, "lb", None)
    ub = getattr(entry, "ub", None)
    if lb is None or ub is None:
        raise Unsupported("%s constraint entry %r" % (what, entry))
    return (lb, ub)


def _default_of(child):
    """The DEFAULT value of a component, as a plain Python literal."""
    dflt = getattr(child, "_def", None)
    if dflt is None:
        return None
    if isinstance(dflt, bool) or isinstance(dflt, int) or isinstance(dflt, str):
        return dflt
    if isinstance(dflt, tuple) and len(dflt) == 2 and all(
        isinstance(x, int) for x in dflt
    ):
        return dflt
    raise Unsupported("DEFAULT value %r has no literal form" % (dflt,))


# --------------------------------------------------------------------------
# The walker.
# --------------------------------------------------------------------------


class Generator(object):
    """Turns pycrate objects into layout-table nodes."""

    def __init__(self, registry, key_of):
        self.registry = registry        # id(obj) -> (module, asn1_name)
        self.key_of = key_of            # id(obj) -> table key
        self.emitted = {}               # table key -> node
        self.unsupported = {}           # table key -> [ "path: reason", ... ]
        self.aliases = {}               # extra keys discovered mid-walk
        self._queue = []

    # -- registry ---------------------------------------------------------

    def key_for(self, obj):
        key = self.key_of.get(id(obj))
        if key is None:
            # A named type the registry did not cover; register it on the fly
            # under its ASN.1 name so the reference stays symbolic.
            key = self.aliases.get(id(obj))
            if key is None:
                key = canonical(getattr(obj, "_name", None) or "anonymous")
                self.aliases[id(obj)] = key
            self.key_of[id(obj)] = key
        return key

    def register(self, obj):
        """Queue a named type for emission and return its table key."""
        key = self.key_for(obj)
        if key not in self.emitted and key not in self._queue:
            self._queue.append((key, obj))
        return key

    # -- node construction ------------------------------------------------

    def ref_target(self, obj):
        """The named type this component should reference, or None to inline.

        ``get_typeref()`` alone is not trustworthy.  For a *parameterized* type
        (``SetupRelease { X }``) it returns the **unbound template**
        (``_param`` truthy, ``_root is None``) while ``obj`` itself carries the
        concrete substituted structure -- referencing that template would emit
        a table entry with no components.  So a reference is only taken when the
        target is a registered named type, is bound, and is structurally the
        same shape as this component.
        """
        tr = typeref_of(obj)
        if tr is None:
            return None
        if id(tr) not in self.registry:
            return None
        if getattr(tr, "_param", None):
            return None
        if getattr(tr, "TYPE", None) != getattr(obj, "TYPE", None):
            return None
        if _is_stub(obj):
            # obj is a bare stub: it has no structure of its own, so the
            # referenced type is the only way to encode it.
            if _is_stub(tr):
                return None
            return tr
        obj_root = getattr(obj, "_root", None)
        tr_root = getattr(tr, "_root", None)
        if (obj_root is None) != (tr_root is None):
            return None
        if obj_root is not None and tuple(obj_root) != tuple(tr_root):
            return None
        return tr

    def node(self, obj, path, owner, allow_ref=True):
        if allow_ref:
            tr = self.ref_target(obj)
            if tr is not None:
                return {"k": "ref", "t": self.register(tr)}
        try:
            return self.inline_node(obj, path, owner)
        except Unsupported as exc:
            self.unsupported.setdefault(owner, []).append("%s: %s" % (path, exc))
            return {"k": "unsupported", "why": str(exc)}

    def inline_node(self, obj, path, owner):
        atype = getattr(obj, "TYPE", None)
        if atype not in KNOWN_TYPES:
            raise Unsupported(
                "ASN.1 type %r is not implemented" % (atype,)
            )
        if _is_stub(obj):
            raise Unsupported(
                "aggregate with no components (unbound parameterized type?)"
            )
        handler = getattr(self, "_n_" + atype.replace(" ", "_").lower())
        return handler(obj, path, owner)

    # SEQUENCE / SET ------------------------------------------------------

    def _n_sequence(self, obj, path, owner):
        return self._sequence(obj, path, owner, "SEQUENCE")

    def _n_set(self, obj, path, owner):
        return self._sequence(obj, path, owner, "SET")

    def _sequence(self, obj, path, owner, label):
        order = list(obj._root)
        if label == "SET":
            canon = getattr(obj, "_root_canon", None)
            if canon is None or list(canon) != order:
                raise Unsupported(
                    "SET whose canonical component order differs from "
                    "declaration order"
                )
        comp = []
        for name in order:
            child = obj._cont[name]
            comp.append(
                [
                    name,
                    self.node(child, "%s.%s" % (path, name), owner),
                    bool(child._opt),
                    _default_of(child),
                ]
            )
        return {
            "k": "seq",
            "ext": obj._ext is not None,
            "comp": comp,
            "extadd": self._extadd(obj, path, owner),
        }

    def _extadd(self, obj, path, owner):
        if obj._ext is None:
            return []
        nest = getattr(obj, "_ext_nest", None)
        if nest is None:
            raise Unsupported(
                "extensible SEQUENCE with %d addition(s) but no _ext_nest "
                "grouping information" % len(obj._ext)
            )
        groups = getattr(obj, "_ext_group_obj", None) or {}
        ident = getattr(obj, "_ext_ident", None) or {}
        flat = []
        for entry in nest:
            flat.extend(entry if isinstance(entry, list) else [entry])
        if flat != list(obj._ext):
            raise Unsupported("_ext_nest does not cover _ext in order")
        out = []
        for i, entry in enumerate(nest):
            if isinstance(entry, list):
                names = list(entry)
                gid = ident.get(names[0])
                if gid is None or gid not in groups:
                    raise Unsupported(
                        "extension group %r has no group object" % (names,)
                    )
                out.append(
                    {
                        "k": "extgrp",
                        "names": names,
                        "node": self.node(
                            groups[gid],
                            "%s.<ext %d>" % (path, i),
                            owner,
                            allow_ref=False,
                        ),
                    }
                )
            else:
                if entry not in obj._cont:
                    raise Unsupported(
                        "extension addition %r is not a component" % (entry,)
                    )
                out.append(
                    {
                        "k": "extone",
                        "name": entry,
                        "node": self.node(
                            obj._cont[entry], "%s.%s" % (path, entry), owner
                        ),
                    }
                )
        return out

    # CHOICE --------------------------------------------------------------

    def _n_choice(self, obj, path, owner):
        alts = [
            [name, self.node(obj._cont[name], "%s.%s" % (path, name), owner)]
            for name in obj._root
        ]
        extadd = [
            [name, self.node(obj._cont[name], "%s.%s" % (path, name), owner)]
            for name in (obj._ext or [])
        ]
        return {
            "k": "choice",
            "ext": obj._ext is not None,
            "alts": alts,
            "extadd": extadd,
        }

    # SEQUENCE OF / SET OF ------------------------------------------------

    def _n_sequence_of(self, obj, path, owner):
        return {
            "k": "seqof",
            "size": self._size(obj, path),
            "ext": False,
            "of": self.node(obj._cont, "%s[]" % path, owner),
        }

    def _n_set_of(self, obj, path, owner):
        return self._n_sequence_of(obj, path, owner)

    # INTEGER -------------------------------------------------------------

    def _n_integer(self, obj, path, owner):
        cset = getattr(obj, "_const_val", None)
        if not _is_const(cset):
            return {"k": "int", "lb": None, "ub": None, "ext": False}
        ext = cset.ext is not None
        lb, ub = _single_range(cset, "value")
        return {"k": "int", "lb": lb, "ub": ub, "ext": ext}

    # ENUMERATED ----------------------------------------------------------

    def _n_enumerated(self, obj, path, owner):
        names = list(obj._root)
        ext = list(obj._ext) if obj._ext is not None else None
        if len(names) + len(ext or []) != len(obj._cont):
            raise Unsupported("ENUMERATED whose _cont does not match _root+_ext")
        return {"k": "enum", "names": names, "ext": ext}

    # BOOLEAN / NULL ------------------------------------------------------

    def _n_boolean(self, obj, path, owner):
        return {"k": "bool"}

    def _n_null(self, obj, path, owner):
        return {"k": "null"}

    # BIT STRING / OCTET STRING -------------------------------------------

    def _n_bit_string(self, obj, path, owner):
        return {"k": "bits", "size": self._size(obj, path), "ext": False}

    def _n_octet_string(self, obj, path, owner):
        containing = None
        cc = getattr(obj, "_const_cont", None)
        name = getattr(cc, "_name", None) if cc is not None else None
        if name:
            containing = name
        return {
            "k": "octets",
            "size": self._size(obj, path),
            "ext": False,
            "containing": containing,
        }

    # -- helpers ----------------------------------------------------------

    def _size(self, obj, path):
        cset = getattr(obj, "_const_sz", None)
        if not _is_const(cset):
            return None
        lb, ub = _single_range(cset, "size")
        if ub >= 65536:
            # X.691 10.9/11.9: an upper bound of 65536 or more drops the length
            # back to an unconstrained determinant, which [lb, ub] cannot say.
            # The engine would write the offset bits instead, so refuse rather
            # than emit a size the engine reads differently from pycrate.
            raise Unsupported(
                "SIZE upper bound %d selects an unconstrained length determinant"
                % ub
            )
        return [lb, ub]

    # -- driver -----------------------------------------------------------

    def run(self, roots):
        for key, obj in roots:
            self.register(obj)
        while self._queue:
            key, obj = self._queue.pop(0)
            if key in self.emitted:
                continue
            self.emitted[key] = self.node(obj, key, key)
        return self.emitted


# --------------------------------------------------------------------------
# Registry and type resolution.
# --------------------------------------------------------------------------


def build_registry():
    """``{id(obj): (module, asn1_name)}`` plus the reverse lookup by name."""
    reg = {}
    by_name = {}
    for modname, mod in MODULES:
        for attr in sorted(vars(mod)):
            if attr.startswith("_"):
                continue
            obj = getattr(mod, attr)
            if not hasattr(obj, "TYPE"):
                continue
            name = getattr(obj, "_name", None) or attr
            reg[id(obj)] = (modname, canonical(name))
            by_name.setdefault(canonical(name), []).append((modname, attr))
    return reg, by_name


def canonical(name):
    """Fold an ASN.1 name to its table-key spelling.

    ASN.1 identifiers use hyphens where Python identifiers use underscores.
    The table is keyed the Python way throughout -- for a type passed to
    ``--types`` (via ``resolve_type``) and for one reached through a named-type
    reference (via ``build_registry``) alike -- so a key is always usable as
    ``getattr(module, key)`` and the two entry points cannot disagree.
    """
    return name.replace("-", "_")



def make_key_of(reg, by_name):
    """Table keys: the ASN.1 name, qualified by module when ambiguous."""
    collisions = {n: v for n, v in by_name.items() if len(v) > 1}
    key_of = {}
    for oid, (modname, name) in reg.items():
        if len(by_name[name]) == 1:
            key_of[oid] = name
        else:
            key_of[oid] = "%s::%s" % (modname, name)
    return key_of, collisions


def resolve_type(spec, modules_by_name):
    """Resolve ``Name`` or ``Module.Name`` (module may be an alias)."""
    if "." in spec:
        modpart, name = spec.rsplit(".", 1)
        modname = MODULE_ALIASES.get(modpart.upper(), modpart)
    else:
        modname, name = DEFAULT_MODULE, spec
    mod = modules_by_name.get(modname)
    if mod is None:
        raise SystemExit(
            "asn1gen: unknown module %r in --types entry %r (known: %s)"
            % (modname, spec, ", ".join(sorted(modules_by_name)))
        )
    obj = getattr(mod, name, None)
    if obj is None:
        obj = getattr(mod, name.replace("-", "_"), None)
    if obj is None or not hasattr(obj, "TYPE"):
        raise SystemExit(
            "asn1gen: module %s has no type %r" % (modname, name)
        )
    return canonical(name), obj


# --------------------------------------------------------------------------
# Deterministic source rendering.
# --------------------------------------------------------------------------


def _scalar(value):
    return (
        value is None
        or isinstance(value, (bool, int, float, str))
        or (isinstance(value, tuple) and all(_scalar(x) for x in value))
    )


def render(value, indent=0):
    """Render a node as Python source with stable, diffable formatting."""
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = []
        for key, sub in value.items():
            lines.append(
                "%s%r: %s" % (" " * (indent + 4), key, render(sub, indent + 4))
            )
        return "{\n" + ",\n".join(lines) + ",\n" + pad + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(_scalar(x) for x in value) and sum(
            len(repr(x)) for x in value
        ) + 2 * len(value) < 72:
            return "[" + ", ".join(repr(x) for x in value) + "]"
        lines = [
            "%s%s" % (" " * (indent + 4), render(x, indent + 4)) for x in value
        ]
        return "[\n" + ",\n".join(lines) + ",\n" + pad + "]"
    return repr(value)


def emit_table(types, roots, unsupported, collisions, generated_at):
    out = []
    out.append('"""Generated unaligned-PER layout table for LTE RRC (TS 36.331).')
    out.append("")
    out.append("Produced by tools/asn1gen.py -- DO NOT EDIT BY HAND.")
    out.append("")
    out.append("Oracle:    pycrate %s" % _pycrate_version())
    out.append("Generated: %s" % generated_at)
    out.append("")
    out.append("This file is plain data: it imports nothing and is consumed by")
    out.append("tools/lte_per.py, which implements the PER engine.")
    out.append("")
    out.append("TYPES maps an ASN.1 type name to a layout node:")
    out.append("  ref      {t: <type name>}")
    out.append("  bool     {}                                  True/False, 1 bit")
    out.append("  null     {}                                  no bits")
    out.append("  int      {lb, ub, ext}                       constrained whole number")
    out.append("  enum     {names, ext}                        constrained index")
    out.append("  bits     {size, ext}                         size [N,N] == fixed")
    out.append("  octets   {size, ext, containing}             containing is a note only")
    out.append("  seq      {ext, comp, extadd}                 comp = [name, node, optional, default]")
    out.append("  choice   {ext, alts, extadd}                 alts = [name, node]")
    out.append("  seqof    {size, ext, of}")
    out.append("  unsupported {why}                            engine raises PerError")
    out.append("Extension additions are one OPEN TYPE each:")
    out.append("  {k: extgrp, names, node}   a group of additions, node is its seq")
    out.append("  {k: extone, name, node}    a lone addition, node is that component")
    out.append('"""')
    out.append("")
    out.append("# Explicitly requested root types (--types), in the order given.")
    out.append("ROOTS = [")
    for r in roots:
        out.append("    %r," % r)
    out.append("]")
    out.append("")
    out.append("# Reason strings for every construct the generator could not express.")
    out.append("# Keyed by the type that contains it; the engine raises PerError on them.")
    out.append("UNSUPPORTED = {")
    for key in sorted(unsupported):
        reasons = sorted(set(unsupported[key]))
        out.append("    %r: [" % key)
        for reason in reasons:
            out.append("        %r," % reason)
        out.append("    ],")
    out.append("}")
    out.append("")
    if collisions:
        out.append(
            "# ASN.1 names present in more than one namespace, emitted "
            "module-qualified:"
        )
        for name in sorted(collisions):
            mods = ", ".join(sorted(m for m, _ in collisions[name]))
            out.append("#   %s: %s" % (name, mods))
        out.append("")
    out.append("TYPES = {")
    for key in sorted(types):
        out.append("    %r: %s," % (key, render(types[key], 4)))
    out.append("}")
    out.append("")
    return "\n".join(out)


def _pycrate_version():
    # pycrate_asn1rt.utils has no VERSION attribute (it never had one), so the
    # table used to record its oracle as "pycrate unknown" -- which is exactly
    # the provenance a differential check has to be able to pin down.
    try:
        from importlib.metadata import version

        return version("pycrate")
    except Exception:
        pass
    try:
        from pycrate_asn1rt.utils import VERSION

        return VERSION if isinstance(VERSION, str) else ".".join(
            str(x) for x in VERSION
        )
    except Exception:
        return "unknown"


def generate(specs=None, verbose=False):
    """Build the table.  Returns ``(types, roots, unsupported, collisions)``."""
    specs = list(DEFAULT_TYPES if specs is None else specs)
    modules_by_name = dict(MODULES)
    reg, by_name = build_registry()
    key_of, collisions = make_key_of(reg, by_name)

    roots = []
    for spec in specs:
        name, obj = resolve_type(spec, modules_by_name)
        # A root whose bare name is shared with another namespace keeps the
        # module-qualified key make_key_of gave it: forcing the bare name here
        # would put two different definitions under one table key and let the
        # second silently overwrite the first.
        key = name
        if len(by_name.get(name, ())) > 1 and key_of.get(id(obj)):
            key = key_of[id(obj)]
        key_of[id(obj)] = key
        roots.append((key, obj))

    gen = Generator(reg, key_of)
    types = gen.run(roots)
    for aid, key in gen.aliases.items():
        if key not in types:
            types[key] = {"k": "unsupported", "why": "type not found in registry"}
    if verbose:
        sys.stderr.write(
            "asn1gen: %d root type(s), %d type(s) emitted, %d with unsupported "
            "constructs, %d name collision(s)\n"
            % (len(roots), len(types), len(gen.unsupported), len(collisions))
        )
    return types, [r[0] for r in roots], gen.unsupported, collisions


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a declarative unaligned-PER layout table for "
        "LTE RRC or LPP from the pycrate ASN.1 oracle."
    )
    parser.add_argument(
        "--family",
        default="rrc",
        choices=("rrc", "lpp"),
        help="which ASN.1 namespace to generate for (default: rrc)",
    )
    parser.add_argument(
        "--types",
        default=None,
        help="comma separated type list, e.g. "
        "'SystemInformationBlockType1,INTER.HandoverCommand'. Defaults to the "
        "family's root set: SIB1..SIB8 + RRCConnectionReconfiguration + "
        "HandoverCommand for rrc, LPP_Message for lpp.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="output path (default: tools/<family> layout name)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress the progress summary"
    )
    args = parser.parse_args(argv)

    _register_rrc()
    if args.family == "lpp":
        _register_lpp()
    use_family(args.family)
    if args.out is None:
        args.out = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), FAMILIES[args.family]["out"]
        )

    specs = None
    if args.types:
        specs = [t.strip() for t in args.types.split(",") if t.strip()]

    types, roots, unsupported, collisions = generate(
        specs, verbose=not args.quiet
    )

    parent = os.path.dirname(os.path.abspath(args.out))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    text = emit_table(
        types,
        roots,
        unsupported,
        collisions,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    with open(args.out, "w") as fh:
        fh.write(text)

    if not args.quiet:
        sys.stderr.write(
            "asn1gen: wrote %s (%d bytes, %d types)\n"
            % (args.out, len(text), len(types))
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
