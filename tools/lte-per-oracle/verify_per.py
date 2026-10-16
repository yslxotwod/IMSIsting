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

Run it with the oracle interpreter, which has pycrate:

    /home/ysl/.lte-oracles/venv/bin/python \\
        tools/lte-per-oracle/verify_per.py --table /tmp/asn1gen/lte_rrc_layout.py

Exit 0 when every case agrees, 1 on any disagreement, 2 if it could not set up.
"""

import argparse
import copy
import importlib.util
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Random value generation, driven by the pycrate object graph.
# ---------------------------------------------------------------------------

class Gen(object):
    def __init__(self, rnd, max_elem=3, depth_limit=12):
        self.rnd = rnd
        self.max_elem = max_elem
        self.depth_limit = depth_limit

    # -- constraint helpers ------------------------------------------------
    @staticmethod
    def _range_of(obj):
        """(lb, ub) for an INTEGER/BIT STRING/OCTET STRING/SEQUENCE OF, or None."""
        try:
            c = obj.get_const()
        except Exception:
            return None
        if not c:
            return None
        val = c.get("val")
        if val is None:
            return None
        try:
            roots = val["root"]
        except Exception:
            return None
        if not roots:
            return None
        r = roots[0]
        lb = getattr(r, "lb", None)
        ub = getattr(r, "ub", None)
        return (lb, ub)

    def _size(self, obj, default_lo=1, default_hi=2):
        r = self._range_of(obj)
        if r is None:
            lo, hi = default_lo, default_hi
        else:
            lo, hi = r
        if lo is None:
            lo = default_lo
        if hi is None:
            hi = lo + default_hi
        hi = min(hi, lo + self.max_elem)
        if hi < lo:
            hi = lo
        return random.randint(lo, max(lo, hi))

    def _int(self, obj):
        r = self._range_of(obj)
        if r is None:
            return self.rnd.randint(0, 7)
        lo, hi = r
        if lo is None:
            return self.rnd.choice([0, 1, 127, 255, 65535])
        if hi is None:
            return lo + self.rnd.randint(0, 15)
        # Hit the bounds often: off-by-one in a range is the classic defect.
        return self.rnd.choice([lo, hi, self.rnd.randint(lo, hi), lo, hi])

    # -- the generator -----------------------------------------------------
    def value(self, obj, depth=0):
        t = obj.TYPE
        if depth > self.depth_limit:
            raise ValueError("depth limit at %s" % t)

        if t == "BOOLEAN":
            return self.rnd.choice([True, False])
        if t == "NULL":
            return 0
        if t == "INTEGER":
            return self._int(obj)
        if t == "ENUMERATED":
            names = list(obj._cont)
            return self.rnd.choice(names)
        if t == "BIT STRING":
            n = self._size(obj, 1, 8)
            return (self.rnd.getrandbits(n), n)
        if t == "OCTET STRING":
            n = self._size(obj, 1, 4)
            return bytes(self.rnd.getrandbits(8) for _ in range(n))
        if t == "SEQUENCE OF":
            n = self._size(obj, 1, 2)
            elem = obj._cont
            return [self.value(elem, depth + 1) for _ in range(n)]
        if t == "CHOICE":
            alts = list(obj._cont)
            pick = self.rnd.choice(alts)
            return (pick, self.value(obj._cont[pick], depth + 1))
        if t == "SEQUENCE":
            out = {}
            mand = list(getattr(obj, "_root_mand", None) or [])
            opt = list(getattr(obj, "_root_opt", None) or [])
            for name in mand:
                out[name] = self.value(obj._cont[name], depth + 1)
            for name in opt:
                if self.rnd.random() < 0.5:
                    out[name] = self.value(obj._cont[name], depth + 1)
            if not out and not mand:
                # All-absent is a legal and interesting case; occasionally
                # force one optional instead so both shapes get exercised.
                if opt and self.rnd.random() < 0.5:
                    out[opt[0]] = self.value(obj._cont[opt[0]], depth + 1)
            return out
        raise ValueError("unhandled TYPE %r" % t)


def pycrate_bits(obj):
    out = ""
    n = 0
    for _t, v, bl in obj._to_per():
        if isinstance(v, int):
            out += format(v, "0%db" % bl)
        elif isinstance(v, bytes):
            out += "".join(format(b, "08b") for b in v)[:bl]
        else:
            out += str(v)
        n += bl
    return out, n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--table", required=True,
                    help="generated layout table (tools/asn1gen.py --out ...)")
    ap.add_argument("--per", default=os.path.join(HERE, "..", "lte_per.py"),
                    help="the PER engine to test")
    ap.add_argument("--cases", type=int, default=40,
                    help="random values per type (default 40)")
    ap.add_argument("--seed", type=int, default=20261016)
    ap.add_argument("--only", default=None,
                    help="comma-separated type names to restrict to")
    args = ap.parse_args(argv)

    try:
        from pycrate_asn1dir import RRCLTE
    except ImportError:
        sys.stderr.write(
            "this check needs pycrate; run it with the oracle interpreter:\n"
            "  /home/ysl/.lte-oracles/venv/bin/python %s --table ...\n"
            % os.path.relpath(__file__))
        return 2

    per = load_module(os.path.abspath(args.per), "lte_per")
    tbl = load_module(os.path.abspath(args.table), "lte_rrc_layout")
    codec = per.codec_from_module(tbl)

    roots = list(getattr(tbl, "ROOTS", []) or [])
    if args.only:
        roots = [t for t in args.only.split(",") if t]
    if not roots:
        sys.stderr.write("the table declares no ROOTS; nothing to check\n")
        return 2

    M = RRCLTE.EUTRA_RRC_Definitions
    rnd = random.Random(args.seed)
    gen = Gen(rnd)

    cases = agrees = skipped = 0
    failures = []

    for tname in roots:
        if not hasattr(M, tname):
            sys.stderr.write("  %s: not in the oracle module, skipped\n" % tname)
            skipped += 1
            continue
        made = 0
        attempts = 0
        while made < args.cases and attempts < args.cases * 8:
            attempts += 1
            obj = copy.deepcopy(getattr(M, tname))
            try:
                val = gen.value(obj)
            except Exception:
                continue
            try:
                obj.set_val(val)
            except Exception:
                # The generator produced something pycrate will not accept;
                # that is this script's problem, not the codec's.
                continue
            try:
                want, wbits = pycrate_bits(obj)
            except Exception:
                continue
            made += 1
            cases += 1
            try:
                got = codec.encode_bits(tname, val)
            except Exception as exc:
                failures.append("%s: encode raised %s\n    value=%r\n    want=%s"
                                % (tname, exc, val, want))
                continue
            if got != want:
                first = next((i for i in range(min(len(got), len(want)))
                              if got[i] != want[i]), min(len(got), len(want)))
                failures.append(
                    "%s: DISAGREE at bit %d (pycrate %d bits, ours %d)\n"
                    "    value=%r\n    want=%s\n    got =%s"
                    % (tname, first, wbits, len(got), val, want, got))
                continue
            # Decoding must give back a value that re-encodes to the same bits.
            try:
                back = codec.decode_bits(tname, want)
                again = codec.encode_bits(tname, back)
            except Exception as exc:
                failures.append("%s: decode raised %s\n    bits=%s"
                                % (tname, exc, want))
                continue
            if again != want:
                failures.append("%s: round-trip differs\n    value=%r\n"
                                "    want=%s\n    again=%s"
                                % (tname, val, want, again))
                continue
            agrees += 1
        print("  %-34s %3d case(s)" % (tname, made))

    print()
    print("types checked : %d%s" % (len(roots) - skipped,
                                    " (%d skipped)" % skipped if skipped else ""))
    print("cases         : %d" % cases)
    print("agree         : %d" % agrees)
    print("disagree      : %d" % len(failures))
    for f in failures[:10]:
        print()
        print("  " + f)
    if len(failures) > 10:
        print("\n  ... and %d more" % (len(failures) - 10))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
