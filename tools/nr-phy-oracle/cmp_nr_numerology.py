#!/usr/bin/env python3
"""Cross-check the NR carrier numerology against the published tables.

What this checks, and why each part is worth checking
-----------------------------------------------------
modules/12_nr_air.sh derives three numbers that go straight into an SDR
call, and none of them is observable after the fact -- a radio asked for the
wrong sample rate does not report an error, it just does not work:

    nair_n_rb_for(scs_khz, bw_mhz)   -> N_RB   (resource blocks)
    nair_fft_size_for(scs, bw)       -> N_FFT  (smallest power of two with
                                                >=85% occupancy)
    nair_sample_rate_hz(scs, bw)     -> f_s = N_FFT * scs

TS 38.104 Table 5.3.2-1 (FR1) and 5.3.2-2 (FR2-1) fix N_RB per (scs,
bandwidth). This file writes those tables out again from the published
values and compares cell by cell, which catches a transcription error.

Then it checks the DERIVATION rather than the result:

  * N_FFT must be the SMALLEST power of two satisfying 2^i * 0.85 >= N_RB*12.
    Testing minimality is what makes this a check rather than a restatement:
    a table of N_FFT values that happens to be right today would pass a
    membership test and fail here if it were ever too large.

  * f_s must land on the published OFDM sample rate ladder
    7.68 / 15.36 / 30.72 / 61.44 / 122.88 / 245.76 / 491.52 Msps.

What this canNOT prove, stated rather than implied
--------------------------------------------------
py3gpp's nrOFDMInfo() implements the SAME rule:

    for i in range(20):
        if 2 ** i * 0.85 >= nrb * 12:
            Nfft = 2 ** i
            break

so agreement with py3gpp corroborates our IMPLEMENTATION of the rule and
nothing more. It is not two independent derivations. The rule's authority is
TS 38.104 itself; the table above is where the independent part lives. This
note exists because "cross-checked against py3gpp" in a comment reads as
stronger evidence than it is, and the difference matters when the number is
handed to hardware.

Usage:  cmp_nr_numerology.py [--module PATH] [--quiet]
Exit:   0 every cell matches and every derived value is minimal and on the
           ladder
        1 something disagrees
"""

import argparse
import os
import subprocess
import sys

# ── TS 38.104 Table 5.3.2-1, FR1 ────────────────────────────────────────
# Written out from the published table. Keyed scs_kHz -> {bw_MHz: N_RB}.
FR1 = {
    15: {3: 15, 5: 25, 7: 35, 10: 52, 15: 79, 20: 106, 25: 133, 30: 160,
         35: 188, 40: 216, 45: 242, 50: 270},
    30: {5: 11, 10: 24, 15: 38, 20: 51, 25: 65, 30: 78, 35: 92, 40: 106,
         45: 119, 50: 133, 60: 162, 70: 189, 80: 217, 90: 245, 100: 273},
    60: {10: 11, 15: 18, 20: 24, 25: 31, 30: 38, 35: 44, 40: 51, 45: 58,
         50: 65, 60: 79, 70: 93, 80: 107, 90: 121, 100: 135},
}

# ── TS 38.104 Table 5.3.2-2, FR2-1 ──────────────────────────────────────
# Only the 120 kHz row is reachable through nair_n_rb_for(); the table's
# 60 kHz column for 50/100/200 MHz is deliberately NOT modelled because this
# module's bands are FR1, where the 60 kHz row above wins.
FR2_1 = {
    120: {50: 32, 100: 66, 200: 132, 400: 264},
}

# The OFDM sample rates NR implementations support. 3.84 and 1.92 are here
# because a 3 MHz / 15 kHz carrier (N_RB 15, N_FFT 256) derives to 3.84 Msps
# and is a real configuration -- TS 38.104 Table 5.3.2-1 has the row. The
# first draft of this file listed only the 7.68-and-up ladder, and reported
# that cell as a defect in the module. It was a defect in the ladder.
LADDER_HZ = [1_920_000, 3_840_000, 7_680_000, 15_360_000, 30_720_000,
             61_440_000, 122_880_000, 245_760_000, 491_520_000]


class Module:
    """Calls the numerology helpers in one bash process."""

    SEP = "\x1e"

    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            sys.exit("cmp_nr_numerology: module not found: %s" % path)

    def call_pairs(self, fn, pairs):
        if not pairs:
            return []
        lines = "\n".join("%s %s" % (s, b) for s, b in pairs) + "\n"
        script = (
            'source "$1" </dev/null >/dev/null 2>&1 || exit 9\n'
            'shift\n'
            'fn="$1"; shift\n'
            'while read -r a b; do\n'
            '  [ -z "$a" ] && continue\n'
            '  out=$("$fn" "$a" "$b" 2>/dev/null); r=$?\n'
            '  printf "%s|%s\\036" "$r" "$out"\n'
            'done\n'
        )
        p = subprocess.run(
            ["bash", "-c", script, "bash", self.path, fn],
            input=lines, capture_output=True, text=True,
        )
        if p.returncode != 0:
            raise RuntimeError("sourcing %s failed (exit %d): %s"
                               % (self.path, p.returncode,
                                  (p.stderr or "").strip()[:300]))
        out = []
        for rec in p.stdout.split(self.SEP):
            if not rec.strip():
                continue
            rc, _, val = rec.partition("|")
            out.append((int(rc), val.strip()))
        if len(out) != len(pairs):
            raise RuntimeError("expected %d results, got %d"
                               % (len(pairs), len(out)))
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    module_path = args.module or os.path.join(root, "modules", "12_nr_air.sh")
    mod = Module(module_path)

    print("== NR carrier numerology vs TS 38.104 5.3.2")
    print("   module : %s" % module_path)

    problems = []
    checked = 0

    table = {}
    table.update({s: dict(r) for s, r in FR1.items()})
    for s, r in FR2_1.items():
        table.setdefault(s, {}).update(r)

    pairs = [(s, b) for s in sorted(table) for b in sorted(table[s])]

    # ── 1. N_RB against the published table ─────────────────────────────
    nrb_results = mod.call_pairs("nair_n_rb_for", pairs)
    print("\n-- N_RB (TS 38.104 Table 5.3.2-1 FR1, 5.3.2-2 FR2-1)")
    for (scs, bw), (rc, val) in zip(pairs, nrb_results):
        want = table[scs][bw]
        checked += 1
        if rc != 0:
            problems.append("N_RB scs=%d bw=%d: the module refused it (rc=%d)"
                            % (scs, bw, rc))
        elif not val.isdigit() or int(val) != want:
            problems.append("N_RB scs=%d bw=%d: ours=%s table=%d"
                            % (scs, bw, val, want))
    n_nrb = len(pairs)
    print("   %d cells checked, %d disagree"
          % (n_nrb, sum(1 for p in problems if p.startswith("N_RB"))))

    # ── 2. N_FFT is the smallest power of two with >=85% occupancy ──────
    #
    # Minimality is the point. A derived or transcribed N_FFT that is merely
    # a power of two and big enough would pass a rounding test; requiring
    # N_FFT/2 to FAIL the occupancy test is what pins the derivation.
    fft_results = mod.call_pairs("nair_fft_size_for", pairs)
    print("\n-- N_FFT minimality (2^i * 0.85 >= N_RB * 12, smallest such i)")
    nfft_bad = 0
    for (scs, bw), (rc, val) in zip(pairs, fft_results):
        want_nrb = table[scs][bw]
        checked += 1
        if rc != 0 or not val.isdigit():
            problems.append("N_FFT scs=%d bw=%d: the module refused it" % (scs, bw))
            nfft_bad += 1
            continue
        nfft = int(val)
        if nfft & (nfft - 1):
            problems.append("N_FFT scs=%d bw=%d: %d is not a power of two"
                            % (scs, bw, nfft))
            nfft_bad += 1
            continue
        if nfft * 85 < want_nrb * 1200:
            problems.append("N_FFT scs=%d bw=%d: %d does not hold 85%% of "
                            "N_RB=%d * 12" % (scs, bw, nfft, want_nrb))
            nfft_bad += 1
            continue
        if (nfft // 2) * 85 >= want_nrb * 1200:
            problems.append("N_FFT scs=%d bw=%d: %d is not minimal, %d "
                            "would already satisfy the rule"
                            % (scs, bw, nfft, nfft // 2))
            nfft_bad += 1
    print("   %d cells checked, %d disagree" % (n_nrb, nfft_bad))

    # ── 3. f_s lands on the published sample rate ladder ────────────────
    fs_results = mod.call_pairs("nair_sample_rate_hz", pairs)
    print("\n-- f_s = N_FFT * scs, on the published rate ladder")
    fs_bad = 0
    seen = set()
    for (scs, bw), (rc, val), (_, nfft_s) in zip(pairs, fs_results, fft_results):
        checked += 1
        if rc != 0 or not val.isdigit():
            problems.append("f_s scs=%d bw=%d: the module refused it" % (scs, bw))
            fs_bad += 1
            continue
        fs = int(val)
        seen.add(fs)
        if fs not in LADDER_HZ:
            problems.append("f_s scs=%d bw=%d: %d Hz is not on the ladder"
                            % (scs, bw, fs))
            fs_bad += 1
            continue
        if nfft_s.isdigit() and fs != int(nfft_s) * scs * 1000:
            problems.append("f_s scs=%d bw=%d: %d != N_FFT %s * %d kHz"
                            % (scs, bw, fs, nfft_s, scs))
            fs_bad += 1
    print("   %d cells checked, %d disagree" % (n_nrb, fs_bad))
    print("   ladder values produced: %s"
          % " ".join("%d" % v for v in sorted(seen)))

    # ── 4. the combination the spec does not define must be refused ─────
    #
    # A carrier the table has no row for has no sample rate to hand a radio.
    # Returning one would be the failure mode this whole stage exists for.
    print("\n-- undefined combinations must be refused, not guessed")
    bad = [(120, 5), (15, 400), (30, 3), (60, 3), (15, 100), (240, 100)]
    for fn, label in (("nair_n_rb_for", "N_RB"),
                      ("nair_fft_size_for", "N_FFT"),
                      ("nair_sample_rate_hz", "f_s")):
        for (scs, bw), (rc, val) in zip(bad, mod.call_pairs(fn, bad)):
            checked += 1
            if rc == 0:
                problems.append("%s scs=%d bw=%d: the table has no such row, "
                                "but the module returned %s"
                                % (label, scs, bw, val))
    print("   %d rejected combinations x 3 helpers" % len(bad))

    # ── honesty note ───────────────────────────────────────────────────
    print("\n-- note: py3gpp's nrOFDMInfo() applies the SAME 0.85 rule as")
    print("   nair_fft_size_for(), so agreement with it corroborates the")
    print("   implementation and not the rule. The independent material")
    print("   here is the TS 38.104 table; see this file's docstring.")

    if problems:
        print("\n  MISMATCHES: %d" % len(problems))
        for p in problems[:40]:
            print("    %s" % p)
        if len(problems) > 40:
            print("    ... and %d more" % (len(problems) - 40))
        print("\n== the NR numerology does NOT match TS 38.104 5.3.2")
        return 1

    print("\n  cells checked: %d" % checked)
    print("  MISMATCHES: 0")
    print("\n== the NR numerology matches TS 38.104 5.3.2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
