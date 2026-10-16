#!/usr/bin/env python3
"""Check the CRS and MBSFN reference signals against srsRAN release_23_11.

Both reference signals are QPSK constellations, so the meaningful content of
every resource element is one of four exact values, +-(1 +- j)/sqrt(2). That
decides how this file compares them:

  * the POSITION of every reference element and the QPSK bit pair carried on
    it are compared exactly -- no tolerance can hide a wrong subcarrier or a
    wrong symbol, and a wrong m' offset in the sequence shifts every value
    while leaving the positions untouched, which is exactly the failure a
    length or unit-power check cannot see;
  * the complex values are compared against the CLOSED FORM of TS 36.211
    6.10.1.1/6.10.2.1 with a tolerance derived from the oracle's own measured
    error, not from a round number. srsRAN computes the reference symbols in
    single precision, so its values differ from the exact +-(1 +- j)/sqrt(2)
    by an amount this file measures over every dumped RE and doubles as the
    comparison tolerance. (The PSS comparison in this directory once failed
    against a correct implementation because its tolerance was a round 1e-6
    below srsRAN's actual float32 error; the rule recorded there applies
    here.)

Oracle directory comes from $IMSISTING_ORACLE.
"""

import importlib.util
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.environ.get("IMSISTING_ORACLE", "/tmp/ltephy/oracle")
DUMP = os.path.join(ORACLE, "crs", "dump.txt")

if not os.path.exists(DUMP):
    print("no srsRAN CRS dump at %s" % DUMP)
    print("run ./tools/check-lte-phy-oracle.sh to build it")
    sys.exit(2)

spec = importlib.util.spec_from_file_location(
    "lte_phy", os.path.join(HERE, "..", "lte_phy.py"))
lp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lp)

Q = 1.0 / math.sqrt(2.0)

# keyed (n_rb, cell_id, cp, sf, port) -> {(l, k): value}; and the MBSFN dump.
crs = {}
mbsfn = {}
with open(DUMP) as f:
    for line in f:
        fld = line.split()
        if not fld:
            continue
        if fld[0] == "PORTSYMS":
            crs_portsyms = (int(fld[1]), int(fld[2]))
            continue
        v = complex(float(fld[-2]), float(fld[-1]))
        n_rb, ident, cp, sf = int(fld[1]), int(fld[2]), int(fld[3]), int(fld[4])
        if fld[0] == "CRS":
            port, l, k = int(fld[5]), int(fld[6]), int(fld[7])
            crs.setdefault((n_rb, ident, cp, sf, port), {})[(l, k)] = v
        elif fld[0] == "MBSFN":
            l, k = int(fld[5]), int(fld[6])
            mbsfn.setdefault((n_rb, ident, sf), {})[(l, k)] = v
        else:
            raise SystemExit("unexpected dump line: %r" % line)

if not crs:
    print("empty CRS dump at %s" % DUMP)
    sys.exit(2)

# --- srsRAN's own error against the closed-form constellation -------------
# Every dumped value is one of four exact points; the distance from the value
# to its own nearest exact point is srsRAN's single-precision error, and it is
# the only thing standing between the two implementations that is not a real
# disagreement.
measured = 0.0
for tbl in (crs, mbsfn):
    for d in tbl.values():
        for v in d.values():
            exact = complex(Q if v.real > 0 else -Q, Q if v.imag > 0 else -Q)
            measured = max(measured, abs(v - exact))
TOL = max(2.0 * measured, 1e-12)
print("oracle error against the closed-form QPSK points: %.3e "
      "(tolerance %.3e)" % (measured, TOL))

fails = 0
checked = 0
re_checked = 0
worst = 0.0


def compare(tag, mine, theirs):
    """mine/theirs: {(l, k): value}. Positions and QPSK bits exactly, values
    within the measured tolerance."""
    global fails, checked, re_checked, worst
    checked += 1
    re_checked += len(theirs)
    bad = 0
    for pos in sorted(set(mine) | set(theirs)):
        a, b = mine.get(pos), theirs.get(pos)
        if a is None or b is None:
            if bad < 4:
                print("  %s %s: %s has no reference element" %
                      (tag, pos, "we" if a is None else "srsRAN"))
            bad += 1
            continue
        d = abs(a - b)
        worst = max(worst, d)
        # Bit pair first: this is the exact part of the comparison.
        if (a.real > 0) != (b.real > 0) or (a.imag > 0) != (b.imag > 0):
            if bad < 4:
                print("  %s %s: QPSK symbol differs %r vs %r" % (tag, pos, a, b))
            bad += 1
        elif d > TOL:
            if bad < 4:
                print("  %s %s: %.9g vs %.9g differs by %.3e > %.3e"
                      % (tag, pos, a.real, b.real, d, TOL))
            bad += 1
    if bad:
        print("%-34s **MISMATCH** %d of %d REs" % (tag, bad, len(theirs)))
        fails += 1


# --- CRS ------------------------------------------------------------------
for (n_rb, cid, cp, sf, port) in sorted(crs):
    mine = {(l, k): v for l, k, v in
            lp.crs_subframe(n_rb, cid, subframe=sf, extended_cp=bool(cp),
                            ports=(port,))}
    compare("CRS n_rb=%d id=%d cp=%d sf=%d p=%d" % (n_rb, cid, cp, sf, port),
            mine, crs[(n_rb, cid, cp, sf, port)])

# --- MBSFN, TS 36.211 6.10.2 ---------------------------------------------
for (n_rb, area, sf) in sorted(mbsfn):
    mine = {}
    for s in (0, 1):
        # Extended prefix only, so a slot is 6 symbols: MBSFN symbol 2 of a
        # slot is subframe symbol s*6 + 2.
        for l, k, v in lp.mbsfn_rs_symbol_map(n_rb, 2 * sf + s, area):
            mine[(s * 6 + l, k)] = v
    compare("MBSFN n_rb=%d area=%d sf=%d" % (n_rb, area, sf),
            mine, mbsfn[(n_rb, area, sf)])

# --- reference density, srsRAN's own count --------------------------------
# srsran_refsignal_cs_nof_pilots_x_slot() states how many reference elements
# a slot holds per resource block for 2 and for 4 antenna ports: 8 and 12.
# Ours must add up to the same number, port by port and symbol by symbol.
for nports, want in ((2, crs_portsyms[0]), (4, crs_portsyms[1])):
    got = 0
    for p in range(nports):
        symbols = (0, 4) if p in (0, 1) else (1,)
        for l in symbols:
            got += len(lp.crs_re_positions(100, 0, p, l, 1))
    if got != 100 * want:
        print("reference density for %d ports: %d REs per slot, srsRAN says %d"
              % (nports, got, 100 * want))
        fails += 1

print("cases: %d, reference elements: %d, worst value difference: %.3e"
      % (checked, re_checked, worst))
print("MISMATCHES: %d" % fails)
sys.exit(1 if fails else 0)
