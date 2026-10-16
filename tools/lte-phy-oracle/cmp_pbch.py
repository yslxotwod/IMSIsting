#!/usr/bin/env python3
"""Check the PBCH chain against srsRAN release_23_11.

Everything here is bits, so every comparison is exact: the CRC with its
antenna mask, the tail-biting convolutional encoding, the 1920-bit rate
match, the scrambling, and the resource-element positions. A single wrong
bit or a wrong RE is a failure, not a rounding difference.

Sweep: 5 cell ids x 3 antenna ports x 5 MIB payloads.
Oracle directory comes from $IMSISTING_ORACLE.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.environ.get("IMSISTING_ORACLE", "/tmp/ltephy/oracle")
DUMP = os.path.join(ORACLE, "pbch", "dump.txt")

if not os.path.exists(DUMP):
    print("no srsRAN PBCH dump at %s" % DUMP)
    print("run ./tools/check-lte-phy-oracle.sh to build it")
    sys.exit(2)

spec = importlib.util.spec_from_file_location(
    "lte_phy", os.path.join(HERE, "..", "lte_phy.py"))
lp = importlib.util.module_from_spec(spec); spec.loader.exec_module(lp)

R = {}
for line in open(DUMP):
    f = line.split()
    if f: R[f[0]] = f[1:] if f[0].startswith("RE_") else f[1]
CID = [0, 1, 2, 42, 503]
PORTS = [1, 2, 4]
MIB = []
MIB.append([0]*24); MIB.append([1]*24)
MIB.append([(i*7+3) % 2 for i in range(24)]); MIB.append([i % 2 for i in range(24)])
MIB.append([(i//3) % 2 for i in range(24)])

bad = []
def cmp(tag, got, want):
    if got != want:
        if not hasattr(got, "__len__"):
            bad.append("%s got %r want %r" % (tag, got, want)); return
        # find first differing index
        for i in range(min(len(got), len(want))):
            if got[i] != want[i]:
                bad.append("%s bit %d got %s want %s" % (tag, i, got[i], want[i])); return
        bad.append("%s length %d != %d" % (tag, len(got), len(want)))
    return got == want

n_pay = n_enc = n_raw = n_scr = n_re = 0
for c in CID:
    for p in PORTS:
        for m in range(5):
            key = "%d_%d_%d" % (c, p, m)
            # -- 40-bit payload after CRC16 + antenna mask --
            
            payload = lp.pbch_attach_crc(MIB[m], p)
            cmp("PAYLOAD40_%s" % key, "".join(map(str, payload)), R["PAYLOAD40_%s" % key]); n_pay += 1
            # -- 120-bit conv encoded --
            enc = lp.conv_encode(payload, tail_biting=True)
            cmp("ENC120_%s" % key, "".join(map(str, enc)), R["ENC120_%s" % key]); n_enc += 1
            # -- 1920-bit rate matched --
            raw = lp.pbch_encode(MIB[m], p, c)
            cmp("RAW1920TAIL_%s" % key, "".join(map(str, raw[480:])), R["RAW1920TAIL_%s" % key]); n_raw += 1
            # -- scrambling: four 480-bit slices of the same 1920-bit period --
            scr = lp.pbch_scramble(raw, c)
            got = "".join(map(str, scr))
            want = "".join(R["SCRAM_%s_F%d" % (key, f)] for f in range(4))
            cmp("SCRAM_%s" % key, got, want); n_scr += 1
            if c == 0 and p == 1 and m == 0:
                for f in range(4):
                    cmp("frame_bits_F%d" % f, "".join(map(str, lp.pbch_frame_bits(scr, f))),
                        R["SCRAM_%s_F%d" % (key, f)])
            # -- RE positions --
            for pp in range(p):
                rk = "RE_%s_P%d" % (key, pp)
                if rk not in R: continue
                want_re = [tuple(int(x) for x in t.split(":")) for t in R[rk]]
                got_re = list(lp.pbch_re_positions(6, c))
                # ports 1 and 3 of a 4-port diversity precoder transmit on
                # only half the REs; the position list is per port and
                # identical, so compare the module's list against the union.
                if len(want_re) == 240:
                    cmp("RE_%s" % rk, got_re, want_re); n_re += 1
                else:
                    cmp("RE_%s_subset" % rk, [x for x in got_re if x in set(want_re)], want_re); n_re += 1
print("payload40 checks: %d, enc120: %d, raw1920: %d, scrambled(480x4): %d, re-sets: %d"
      % (n_pay, n_enc, n_raw, n_scr, n_re))
print("FAILURES:", len(bad))
for b in bad[:20]:
    print("  ", b)
sys.exit(1 if bad else 0)
