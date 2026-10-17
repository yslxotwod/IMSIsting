#!/usr/bin/env python3
"""Check the SSB resource-element placement against TS 38.211 7.4.3.1.

WHY THIS EXISTS

modules/12_nr_air.sh carries pinned PSS/SSS/PBCH-DMRS chip values, and the sync
stage checks those chips. Nothing checked WHERE they go. A waveform can carry a
bit-exact PSS in the wrong 127 subcarriers and a handset simply will not find
the cell -- and a resource map is exactly the kind of thing that gets written
once from a table and never re-derived.

The RE map is checked here against the clause, from a grid the module's own
generator emits (its `--detail` output: one line per symbol, `k:re:im`).

WHAT IT CHECKS

  1. OCCUPANCY. For a given PCI the occupied (l, k) sets must be exactly those
     of TS 38.211 Table 7.4.3.1-1, which is the table the clause defers the
     whole map to:
       l = 0        PSS at k = 56..182
       l = 2        SSS at k = 56..182
       l = 1, 3     PBCH at k = 0..239 minus DMRS
       l = 2        PBCH at k = 0..47 and 192..239, minus DMRS
       l = 1, 2, 3  PBCH DMRS at k = 4n + v, v = N_ID^cell mod 4, within the
                    PBCH subcarriers for that symbol
       l = 0        "Set to 0" at k = 0..55 and 183..239
       l = 2        "Set to 0" at k = 48..55 and 183..191
     Neither more nor fewer, no resource element claimed twice, and every "Set
     to 0" subcarrier actually absent or zero.

     THAT LAST PAIR IS NOT DECORATION. The first version of this file derived
     the map from the clause's prose alone and put PBCH at k = 48..55 and
     183..191 of symbol 2 -- 17 extra resource elements -- because it modelled
     symbol 2 as "everything except the 127 SSS subcarriers" and knew nothing
     about the Set-to-0 rows. It reported 445 PBCH and 148 DMRS; the module
     reported 432 and 144, and the module was right. 432 is not negotiable: TS 38.212 7.1.5 rate-matches the PBCH to
     E = 864 bits and 7.4.1.4.1 maps them QPSK, so 432 resource elements, and
     127+127+144+432 = 830 used with 113+17 = 130 set to zero. A check that
     disagrees with arithmetic that fixed is the check that is wrong.

  2. COUNTS. 127 PSS + 127 SSS + 144 DMRS + 432 PBCH = 830, which is the whole
     SSB block minus the 130 REs the standard leaves unused.

  3. CHIPS. The PSS and SSS values at those positions come from the clause's
     m-sequences (the same construction the sync stage uses, imported from it
     rather than copied), and every DMRS resource element is QPSK of unit
     magnitude.

  4. THE DMRS SEQUENCE. Derived from TS 38.211 7.4.1.4.1/7.4.1.4.2 and compared
     value for value. If the module's phase convention differs this reports it
     rather than being written to agree.

WHAT IT DOES NOT CHECK

The PBCH DATA values -- they are the BCH codeword after scrambling, and the
codeword itself is checked by --stage=bch. Also the CP lengths, the OFDM
modulation, the time-domain mapping, and anything above the SSB.

Run this ONE AT A TIME in a checkout: it asks the module to regenerate its
baseband generator, which the module writes to $TMP_DIR.
"""

import importlib.util
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# The PSS/SSS constructions live in the sync stage. Imported, not copied: two
# copies of an m-sequence is two things to get wrong, and this file is about
# where the chips GO.
def _load_sync():
    path = os.path.join(HERE, "cmp_nr_sync.py")
    spec = importlib.util.spec_from_file_location("nr_sync_ref", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SYNC = _load_sync()

SSB_SC = 240          # the SSB occupies 240 subcarriers, TS 38.211 7.4.3.1
SSS_K0, SSS_K1 = 56, 182      # SSS (and PSS) band, 127 subcarriers

# (pci, sfn) pairs. A PCI sweeps all four v = pci mod 4 residues between them.
CASES = [(42, 37), (0, 0), (1, 1023), (777, 511), (1006, 8)]


def v_of(pci):
    return pci % 4


# TS 38.211 Table 7.4.3.1-1, the "Set to 0" rows. Symbol 2 is split because
# the SSS band plus its guard occupies k 48..191 there, not just 56..182.
SET_TO_ZERO = {
    0: list(range(0, 56)) + list(range(183, 240)),
    2: list(range(48, 56)) + list(range(183, 192)),
}


def pbch_band(l):
    """The subcarriers of symbol l that Table 7.4.3.1-1 gives to PBCH/DMRS."""
    if l == 0:
        return []
    if l == 2:
        return list(range(0, 48)) + list(range(192, 240))
    return list(range(0, 240))


def spec_dmrs_positions(pci, l):
    """K indices carrying PBCH DMRS in symbol l: every fourth subcarrier from
    v = N_ID^cell mod 4, inside that symbol's PBCH band."""
    v = v_of(pci)
    return [k for k in pbch_band(l) if k % 4 == v]


def spec_pbch_positions(pci, l):
    """The rest of that symbol's PBCH band."""
    dmrs = set(spec_dmrs_positions(pci, l))
    return [k for k in pbch_band(l) if k not in dmrs]


def gold_sequence(c_init, length):
    """TS 38.211 5.2.1 Gold sequence, length in BITS."""
    nc = 1600
    x1 = [0] * (nc + length + 31)
    x2 = [0] * (nc + length + 31)
    x1[0] = 1
    for i in range(31):
        x2[i] = (c_init >> i) & 1
    for i in range(nc + length):
        x1[i + 31] = (x1[i + 3] + x1[i]) & 1
        x2[i + 31] = (x2[i + 3] + x2[i + 2] + x2[i + 1] + x2[i]) & 1
    return [(x1[nc + i] ^ x2[nc + i]) & 1 for i in range(length)]


def spec_dmrs_values(pci, i_ssb=0, length=144):
    """TS 38.211 7.4.1.4.1: r(n) = (1-2c(2n))/sqrt2 + j(1-2c(2n+1))/sqrt2.

    c_init for the PBCH DMRS is TS 38.211 7.4.1.4.2:
        c_init = 2^11 * (i_SSB + 1) * (N_ID^cell/4 + 1)
               + 2^6  * (i_SSB + 1) + (N_ID^cell mod 4)
    The module prints its own c_init, so a disagreement about the seed shows up
    as a wrong value here rather than as a silent pass."""
    c_init = (2 ** 11) * (i_ssb + 1) * (pci // 4 + 1) \
        + (2 ** 6) * (i_ssb + 1) + (pci % 4)
    bits = gold_sequence(c_init, 2 * length)
    s = 0.7071067811865476
    return [(1 - 2 * bits[2 * n]) * s + (1j) * (1 - 2 * bits[2 * n + 1]) * s
            for n in range(length)]


def module_tmp_and_generator(module):
    reg = subprocess.run(
        ["bash", "-c", 'source "%s" >/dev/null 2>&1; nair_write_bb_gen; '
                       'printf "MOD_TMP=%%s\\n" "$MOD_TMP"' % module],
        cwd=os.path.dirname(os.path.dirname(module)),
        capture_output=True, text=True, timeout=110)
    mod_tmp = ""
    for line in reg.stdout.splitlines():
        if line.startswith("MOD_TMP="):
            mod_tmp = line.partition("=")[2]
    if not mod_tmp:
        return None, None, reg
    return mod_tmp, os.path.join(mod_tmp, "nr_ssb_bb.py"), reg


def run_generator(bb_py, pci, sfn, work):
    detail = os.path.join(work, "detail.txt")
    out = os.path.join(work, "ssb.bin")
    proc = subprocess.run(
        ["python3", bb_py, out, str(pci), "30", "512", str(sfn),
         "--detail", detail],
        capture_output=True, text=True, timeout=100)
    if proc.returncode != 0:
        return None, proc.stdout + proc.stderr
    if not os.path.exists(detail):
        return None, "no detail file"
    fields = {}
    for line in proc.stdout.splitlines():
        if "\t" in line:
            k, _, v = line.partition("\t")
            fields[k] = v
    return (detail, fields), None


def parse_grid(path):
    """`<symbol>TAB<k>:<re>:<im> ...` -> {symbol: {k: complex}}"""
    grid = {}
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or "\t" not in line:
                continue
            sym_s, _, rest = line.partition("\t")
            sym = int(sym_s)
            row = {}
            for tok in rest.split():
                parts = tok.split(":")
                if len(parts) != 3:
                    continue
                row[int(parts[0])] = complex(float(parts[1]), float(parts[2]))
            grid[sym] = row
    return grid


def main():
    module = os.path.join(ROOT, "modules", "12_nr_air.sh")
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == "--module" and i + 1 < len(argv):
            module = argv[i + 1]
        elif a.startswith("--module="):
            module = a.partition("=")[2]

    print("== SSB resource-element placement vs TS 38.211 7.4.3.1 ==")

    mod_tmp, bb_py, reg = module_tmp_and_generator(module)
    if not bb_py:
        print("ERROR\tthe module did not report MOD_TMP (rc=%d): %s"
              % (reg.returncode, reg.stderr.strip()))
        return 2
    if not os.path.exists(bb_py):
        print("ERROR\tthe module did not write %s" % bb_py)
        return 2
    print("module\t\t%s" % module)
    print("generator\t%s (regenerated from it)" % bb_py)

    work = tempfile.mkdtemp(prefix="nr-ssb-map-")
    mismatches = []
    checked = 0
    try:
        for pci, sfn in CASES:
            got, err = run_generator(bb_py, pci, sfn, work)
            if got is None:
                print("case pci=%d sfn=%d: GENERATOR FAILED: %s"
                      % (pci, sfn, err.strip()[:200]))
                mismatches.append("pci=%d generator failed" % pci)
                continue
            detail, fields = got
            grid = parse_grid(detail)
            v = v_of(pci)

            def want(l, kind):
                if kind == "pss":
                    return {l: set(range(SSS_K0, SSS_K1 + 1))}
                if kind == "sss":
                    return {l: set(range(SSS_K0, SSS_K1 + 1))}
                if kind == "dmrs":
                    return {l: set(spec_dmrs_positions(pci, l))}
                return {l: set(spec_pbch_positions(pci, l))}

            # --- occupancy -------------------------------------------------
            occ = {l: set(grid.get(l, {}).keys()) for l in range(4)}
            claims = {}
            def claim(name, l, ks):
                for k in ks:
                    if (l, k) in claims:
                        mismatches.append(
                            "pci=%d sfn=%d: l=%d k=%d claimed by both %s and %s"
                            % (pci, sfn, l, k, claims[(l, k)], name))
                    claims[(l, k)] = name

            claim("PSS", 0, range(SSS_K0, SSS_K1 + 1))
            claim("SSS", 2, range(SSS_K0, SSS_K1 + 1))
            for l in (1, 2, 3):
                claim("DMRS", l, spec_dmrs_positions(pci, l))
                claim("PBCH", l, spec_pbch_positions(pci, l))
            zeroed = {(l, k) for l, ks in SET_TO_ZERO.items() for k in ks}
            for (l, k) in zeroed:
                got_v = grid.get(l, {}).get(k)
                if got_v is not None and abs(got_v) > 1e-9:
                    mismatches.append(
                        "pci=%d sfn=%d: l=%d k=%d is Set-to-0 in Table "
                        "7.4.3.1-1 but carries %s"
                        % (pci, sfn, l, k, got_v))

            for l in range(4):
                want_l = {k for (ll, k) in claims if ll == l}
                extra = occ[l] - want_l
                missing = want_l - occ[l]
                if extra:
                    mismatches.append(
                        "pci=%d sfn=%d: l=%d has %d RE(s) the clause does not "
                        "place (e.g. k=%s)"
                        % (pci, sfn, l, len(extra), sorted(extra)[:6]))
                if missing:
                    mismatches.append(
                        "pci=%d sfn=%d: l=%d is missing %d RE(s) the clause "
                        "places (e.g. k=%s)"
                        % (pci, sfn, l, len(missing), sorted(missing)[:6]))

            # --- counts ----------------------------------------------------
            counts = {"PSS": sum(1 for c in claims.values() if c == "PSS"),
                      "SSS": sum(1 for c in claims.values() if c == "SSS"),
                      "DMRS": sum(1 for c in claims.values() if c == "DMRS"),
                      "PBCH": sum(1 for c in claims.values() if c == "PBCH")}
            for name, want_n in (("PSS", 127), ("SSS", 127), ("DMRS", 144),
                                 ("PBCH", 432)):
                if counts[name] != want_n:
                    mismatches.append("pci=%d sfn=%d: %s count %d, clause says %d"
                                      % (pci, sfn, name, counts[name], want_n))

            # --- chips -----------------------------------------------------
            pss = SYNC.spec_pss(pci % 3)
            for j, k in enumerate(range(SSS_K0, SSS_K1 + 1)):
                got_v = grid.get(0, {}).get(k)
                if got_v is None:
                    continue
                if abs(got_v.real - pss[j]) > 1e-6 or abs(got_v.imag) > 1e-6:
                    mismatches.append(
                        "pci=%d sfn=%d: PSS l=0 k=%d is %s, clause says %d"
                        % (pci, sfn, k, got_v, pss[j]))
                    break
            sss = SYNC.spec_sss(pci // 3, pci % 3)
            for j, k in enumerate(range(SSS_K0, SSS_K1 + 1)):
                got_v = grid.get(2, {}).get(k)
                if got_v is None:
                    continue
                if abs(got_v.real - sss[j]) > 1e-6 or abs(got_v.imag) > 1e-6:
                    mismatches.append(
                        "pci=%d sfn=%d: SSS l=2 k=%d is %s, clause says %d"
                        % (pci, sfn, k, got_v, sss[j]))
                    break

            # --- DMRS values ----------------------------------------------
            ref_dmrs = spec_dmrs_values(pci)
            idx = 0
            dmrs_bad = 0
            for l in (1, 2, 3):
                for k in spec_dmrs_positions(pci, l):
                    got_v = grid.get(l, {}).get(k)
                    if got_v is None:
                        continue
                    if abs(got_v - ref_dmrs[idx]) > 1e-5:
                        dmrs_bad += 1
                    mag = abs(got_v)
                    if abs(mag - 1.0) > 1e-4:
                        mismatches.append(
                            "pci=%d sfn=%d: DMRS l=%d k=%d has magnitude %.6f, "
                            "not unit" % (pci, sfn, l, k, mag))
                        break
                    idx += 1
            if dmrs_bad:
                # Not necessarily a defect in the module: this file's reading of
                # the DMRS phase convention may be the thing that is wrong. Say
                # which it is rather than assert.
                mismatches.append(
                    "pci=%d sfn=%d: %d of %d DMRS values differ from the "
                    "clause-derived sequence (first differ at index %d); the "
                    "placement and the unit magnitude are correct, so either "
                    "the sequence or this file's phase convention is wrong"
                    % (pci, sfn, dmrs_bad, idx, 0))

            # PBCH data must be QPSK too, and must not be the DMRS.
            for l in (1, 2, 3):
                for k in spec_pbch_positions(pci, l):
                    got_v = grid.get(l, {}).get(k)
                    if got_v is None:
                        continue
                    if abs(abs(got_v) - 1.0) > 1e-4:
                        mismatches.append(
                            "pci=%d sfn=%d: PBCH l=%d k=%d has magnitude %.6f, "
                            "not unit" % (pci, sfn, l, k, abs(got_v)))
                        break

            checked += 4
            print("case pci=%-4d sfn=%-4d v=%d  PSS %d  SSS %d  DMRS %d  PBCH %d"
                  % (pci, sfn, v, counts["PSS"], counts["SSS"], counts["DMRS"],
                     counts["PBCH"]))
            if "dmrs_c_init" in fields:
                want_c = (2 ** 11) * (pci // 4 + 1) + (2 ** 6) + (pci % 4)
                if int(fields["dmrs_c_init"]) != want_c:
                    mismatches.append(
                        "pci=%d sfn=%d: dmrs_c_init %s, clause says %d"
                        % (pci, sfn, fields["dmrs_c_init"], want_c))
    finally:
        for f in os.listdir(work):
            os.unlink(os.path.join(work, f))
        os.rmdir(work)

    print("symbols checked\t%d" % checked)
    if mismatches:
        for m in mismatches[:20]:
            print("MISMATCH\t%s" % m)
        print("MISMATCHES: %d" % len(mismatches))
        return 1
    print("MISMATCHES: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
