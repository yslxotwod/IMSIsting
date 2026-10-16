#!/usr/bin/env python3
"""Check layer mapping and precoding against srsRAN release_23_11.

Both stages move complex samples, so the comparison is floating point; the
tolerance below is 5e-7, comfortably above single-precision rounding for
these magnitudes and far below anything a wrong layer index or precoding
matrix could hide. Length must match exactly: a wrong number of layers or
antenna ports changes the length, not just the values.

Oracle directory comes from $IMSISTING_ORACLE.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.environ.get("IMSISTING_ORACLE", "/tmp/ltephy/oracle")
DUMP = os.path.join(ORACLE, "mimo", "dump.txt")

if not os.path.exists(DUMP):
    print("no srsRAN MIMO dump at %s" % DUMP)
    print("run ./tools/check-lte-phy-oracle.sh to build it")
    sys.exit(2)

spec = importlib.util.spec_from_file_location(
    "lte_phy", os.path.join(HERE, "..", "lte_phy.py"))
lp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lp)

M = 16
d = [complex(0.1 * (i % 17) - 0.8, 0.05 * (i % 13) - 0.3) for i in range(M)]

R = {}
with open(DUMP) as f:
    for line in f:
        fld = line.split()
        if fld:
            R[fld[0]] = [complex(float(fld[i]), float(fld[i + 1]))
                         for i in range(1, len(fld), 2)]

TOL = 5e-7
worst = {}


def chk(tag, mine, theirs):
    e = max((abs(mine[i] - theirs[i]) for i in range(min(len(mine), len(theirs)))),
            default=0.0)
    worst[tag] = (e, len(mine), len(theirs))
    return e


chk("DIN", d, R["DIN"])
chk("layer_map_single", lp.layer_map_single(d)[0], R["LAYERMAP_SINGLE_1"])
for nl in (2, 4):
    x = lp.layer_map_diversity(d, nl)
    for l in range(nl):
        chk("layer_map_diversity_%d_L%d" % (nl, l), x[l], R["LAYERMAP_DIV_%d_L%d" % (nl, l)])
for sc in (0.5, 1.0, 1.5, 2.0):
    chk("precode_single_sc%.1f" % sc, lp.precode_single([d], sc)[0],
        R["PRECODE_SINGLE_sc%.1f" % sc])
for np in (2, 4):
    y = lp.precode_diversity(lp.layer_map_diversity(d, np), np, 1.0)
    for p in range(np):
        key = [k for k in R if k.startswith("PRECODE_DIV_%d_P%d_" % (np, p))][0]
        chk("precode_diversity_%d_P%d" % (np, p), y[p], R[key])

fails = 0
for k in sorted(worst):
    e, lm, lt = worst[k]
    ok = e < TOL and lm == lt
    if not ok:
        fails += 1
    print("%-28s maxdiff %.3e  len %d/%d  %s"
          % (k, e, lm, lt, "OK" if ok else "**MISMATCH**"))

print("MISMATCHES: %d" % fails)
sys.exit(1 if fails else 0)
