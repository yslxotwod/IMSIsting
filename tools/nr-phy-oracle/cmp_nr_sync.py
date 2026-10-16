#!/usr/bin/env python3
"""Cross-check modules/12_nr_air.sh's NR synchronisation sequences against
TS 38.211 7.4.2, and against an independent implementation.

Why this exists
---------------
nair_pss_sequence() and nair_sss_sequence() were written from the
specification, and the vectors asserted by the module were computed from the
same reading of it. A transcription can be self-consistently wrong: if the
author misread a clause, the generator, the vectors and the selftest all
encode the same misreading, and the selftest passes forever. No amount of
internal consistency can detect it, because the error is in the reading, not
in the arithmetic.

This script therefore compares against something OUTSIDE this tree. That is
the entire point, and it is why the reference below is written from the
clause text rather than transcribed from our module.

What it checks
--------------
  PSS  d_PSS(n) = 1 - 2*x((n + 43*N_ID(2)) mod 127)          TS 38.211 7.4.2.2
  SSS  d_SSS(n) = [1-2*x0((n+m0) mod 127)]*[1-2*x1((n+m1) mod 127)]
                                                            TS 38.211 7.4.2.3
       m0 = 15*floor(N_ID(1)/112) + 5*N_ID(2),  m1 = N_ID(1) mod 112

Both sequences come from the same degree-7 generator polynomial family but
NOT the same polynomial, and this is the trap:

  x0(i+7) = (x0(i+4) + x0(i)) mod 2      <- x^7 + x^4 + 1
  x1(i+7) = (x1(i+1) + x1(i)) mod 2      <- x^7 + x + 1
  x0 = x1 = [1,0,0,0,0,0,0] as x(0..6)

The clause writes the initialisation in REVERSED index order --
[x(6) x(5) x(4) x(3) x(2) x(1) x(0)] = [0 0 0 0 0 0 1] -- which reads as
x(0)=1 and x(1..6)=0.

An earlier version of our module got all three parts of this wrong at once
(x0 seeded with the PSS initialisation, x1 seeded all-ones, and x1 given
x0's tap). The result disagreed with the standard on all 1008 cell
identities while looking entirely plausible, and its own selftest was happy.
That is the failure mode this file is built to catch.

The PSS initialisation is different again, and correctly so:
  x(i+7) = (x(i+4) + x(i)) mod 2,  x = [0,1,1,0,1,1,1] as x(0..6)

That ordering is the same kind of reversed-notation trap, so PSS is checked
here too rather than assumed correct because it was noticed first.

Negative control
----------------
This comparator is paired with tools/nr-phy-oracle/negative-control.sh, which
puts the LTE seeding described above back into a scratch copy of the module
and requires this file to reject it. tools/check-nr-phy-oracle.sh runs that
control first and aborts if it does not pass. Run it after any change to the
comparison logic: a comparator that has never been observed to fail is not
evidence that the module is correct. `--limit N` exists for that control, so
it can fail on 30 cell identities instead of all 1008.

Tolerance
---------
None, and none is needed. PSS and SSS chips are integers in {-1,+1}
produced from mod-2 arithmetic; there is no floating-point stage anywhere in
either sequence. Every comparison below is exact. (Contrast the LTE oracle,
where srsRAN computes PSS in single precision and a tolerance had to be
DERIVED from its measured error rather than guessed.)

What this does NOT cover, stated rather than papered over
--------------------------------------------------------
  - It does not check the PSS/SSS resource-element positions (TS 38.211
    7.4.2.1 / 7.4.3), only the sequences themselves.
  - It does not check nrPBCH/nrPBCHDMRS, PRACH, or any higher layer stage.
  - The independent-implementation cross-check is OPTIONAL: it needs
    py3gpp, which is AGPL-3.0 and therefore never vendored here. Without it
    the spec check still runs, and the script says so rather than quietly
    reporting a narrower result as a full one.

Licensing
---------
py3gpp (https://github.com/catkira/py3gpp) is AGPL-3.0. Like srsRAN_4G in
the LTE oracle, it is installed into a virtualenv OUTSIDE this repository,
is never committed, and its source is never copied into this tree. It is
imported here as an external library and called as a black box. This file
and the reference implementation in it are ours, written from TS 38.211.

Usage
-----
  python3 tools/nr-phy-oracle/cmp_nr_sync.py [--module PATH] [--quiet]

Exit: 0 if every checked sequence agrees, 1 otherwise.
"""

import argparse
import os
import subprocess
import sys

L = 127

# ── The reference, written from TS 38.211 7.4.2 ─────────────────────────
#
# Deliberately built from the generator recurrences rather than from any
# precomputed table: a table copied out of the module would defeat the
# purpose of the check.

PSS_INIT = [0, 1, 1, 0, 1, 1, 1]   # x(0..6), TS 38.211 7.4.2.2
SSS_INIT = [1, 0, 0, 0, 0, 0, 0]   # x0(0..6) = x1(0..6), TS 38.211 7.4.2.3


def mseq(init, tap_a, tap_b):
    """Degree-7 m-sequence: x(i+7) = (x(i+tap_a) + x(i+tap_b)) mod 2."""
    x = [0] * L
    for i in range(7):
        x[i] = init[i]
    for i in range(L - 7):
        x[i + 7] = (x[i + tap_a] + x[i + tap_b]) % 2
    return x


def spec_pss(n_id_2):
    """TS 38.211 7.4.2.2: d_PSS(n) = 1 - 2*x((n + 43*N_ID(2)) mod 127)."""
    x = mseq(PSS_INIT, 4, 0)
    return [1 - 2 * x[(n + 43 * n_id_2) % L] for n in range(L)]


def spec_sss(n_id_1, n_id_2):
    """TS 38.211 7.4.2.3. Note x1's tap is (i+1), not (i+4)."""
    x0 = mseq(SSS_INIT, 4, 0)
    x1 = mseq(SSS_INIT, 1, 0)
    m0 = 15 * (n_id_1 // 112) + 5 * n_id_2
    m1 = n_id_1 % 112
    return [
        (1 - 2 * x0[(n + m0) % L]) * (1 - 2 * x1[(n + m1) % L]) for n in range(L)
    ]


# ── The module under test ───────────────────────────────────────────────

class Module:
    """Calls the module's sequence functions by sourcing it in bash.

    modules/12_nr_air.sh guards its CLI with
    `[[ "${BASH_SOURCE[0]}" == "$0" ]]`, so sourcing it defines the
    functions without running the command dispatcher.

    The whole sweep goes through ONE bash process. Sourcing the module costs
    tens of milliseconds and the SSS sweep is 1008 cases, so a process per
    case took minutes and presented as a hang -- which is how this was
    written first. Sourcing once and looping inside bash is the difference
    between a check that runs in a second and one nobody will run.
    """

    SEP = "\x1e"  # record separator between cases

    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            sys.exit("cmp_nr_sync: module not found: %s" % path)

    def batch(self, fn, arglist):
        """Run `fn` once per entry in arglist; return a list of int lists."""
        if not arglist:
            return []
        # The trailing newline matters: `read` returns non-zero at EOF with
        # no delimiter, so a list that does not end in one loses its last
        # case without any error.
        cases = "\n".join(" ".join(str(a) for a in args) for args in arglist) + "\n"
        script = (
            'source "$1" </dev/null >/dev/null 2>&1 || exit 9\n'
            'shift\n'
            'while IFS= read -r c; do\n'
            '  [ -z "$c" ] && continue\n'
            '  printf "%s\\n" "$(' + fn + ' $c)"\n'
            '  printf "\\036"\n'
            'done\n'
        )
        p = subprocess.run(
            ["bash", "-c", script, "bash", self.path],
            input=cases, capture_output=True, text=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "sourcing %s or calling %s failed (exit %d): %s"
                % (self.path, fn, p.returncode, (p.stderr or "").strip()[:300])
            )
        results = []
        for rec in p.stdout.split(self.SEP):
            toks = rec.split()
            if toks:
                results.append([int(t) for t in toks])
        if len(results) != len(arglist):
            raise RuntimeError(
                "%s returned %d records for %d cases"
                % (fn, len(results), len(arglist))
            )
        return results


# ── The independent implementation (optional) ───────────────────────────

def load_py3gpp():
    try:
        import numpy as np
        from py3gpp import nrPSS, nrSSS
    except Exception as exc:  # noqa: BLE001 - any import failure means "absent"
        return None, str(exc)

    def pss(pci):
        return [int(v) for v in np.real(nrPSS(pci)).astype(int)]

    def sss(pci):
        return [int(v) for v in np.real(nrSSS(pci)).astype(int)]

    return (pss, sss), None


# ── The sweep ───────────────────────────────────────────────────────────

# Every cell identity, so a bug that only appears past the m0/m1 region
# boundary at N_ID(1)=112 cannot hide. Enumerating all 1008 costs nothing:
# these are 127-element integer sequences.
PSS_CASES = [(n2,) for n2 in range(3)]
SSS_CASES = [(n1, n2) for n1 in range(336) for n2 in range(3)]


def diff_report(ours, ref, limit=8):
    bad = [n for n, (a, b) in enumerate(zip(ours, ref)) if a != b]
    if not bad:
        return None
    first = bad[:limit]
    detail = ", ".join("n=%d ours=%+d ref=%+d" % (n, ours[n], ref[n]) for n in first)
    if len(bad) > limit:
        detail += ", ... (%d of %d chips differ)" % (len(bad), len(ours))
    return detail


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--module", default=None,
                    help="path to 12_nr_air.sh (default: <repo>/modules/12_nr_air.sh)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--limit", type=int, default=0, metavar="N",
                    help="check only the first N cell identities (0 = all 1008). "
                         "Used by the negative control, which only needs enough "
                         "cases to fail loudly, not the full sweep.")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    module_path = args.module or os.path.join(root, "modules", "12_nr_air.sh")
    mod = Module(module_path)

    ref, why_absent = load_py3gpp()

    print("== NR synchronisation sequences vs TS 38.211 7.4.2")
    print("   module: %s" % module_path)
    if ref:
        import py3gpp  # noqa: F401 - only for the version string
        print("   independent implementation: py3gpp %s (AGPL-3.0, external)"
              % getattr(py3gpp, "__version__", "?"))
    else:
        print("   independent implementation: ABSENT (%s)" % why_absent.splitlines()[0])
        print("   -> spec check only; re-run under tools/check-nr-phy-oracle.sh")
        print("      for the two-implementation result")

    mismatches = 0
    checks = 0

    # ── PSS ──
    print("\n-- PSS (TS 38.211 7.4.2.2), all 3 values of N_ID(2)")
    our_pss = mod.batch("nair_pss_sequence", PSS_CASES)
    for (n2,), ours in zip(PSS_CASES, our_pss):
        ref_spec = spec_pss(n2)
        checks += 1
        if len(ours) != L:
            print("  PSS n2=%d LENGTH: ours=%d want=%d  MISMATCH" % (n2, len(ours), L))
            mismatches += 1
            continue
        d = diff_report(ours, ref_spec)
        if d:
            print("  PSS n2=%d MISMATCH vs spec: %s" % (n2, d))
            mismatches += 1
        elif ref:
            pss_fn, _ = ref
            dp = diff_report(ours, pss_fn(n2))
            if dp:
                print("  PSS n2=%d MISMATCH vs py3gpp: %s" % (n2, dp))
                mismatches += 1
            elif not args.quiet:
                print("  PSS n2=%d ok (spec + py3gpp, 127 chips exact)" % n2)
        elif not args.quiet:
            print("  PSS n2=%d ok (spec, 127 chips exact)" % n2)

    # ── SSS ──
    sss_cases = SSS_CASES[:args.limit] if args.limit > 0 else SSS_CASES
    if args.limit > 0:
        print("\n-- SSS (TS 38.211 7.4.2.3), first %d of 1008 cell identities"
              % len(sss_cases))
    else:
        print("\n-- SSS (TS 38.211 7.4.2.3), all 1008 cell identities")
    bad_spec = []
    bad_py = []
    our_sss = mod.batch("nair_sss_sequence", sss_cases)
    for (n1, n2), ours in zip(sss_cases, our_sss):
        pci = 3 * n1 + n2
        checks += 1
        if len(ours) != L:
            bad_spec.append((pci, "LENGTH ours=%d want=%d" % (len(ours), L)))
            continue
        d = diff_report(ours, spec_sss(n1, n2))
        if d:
            bad_spec.append((pci, d))
            continue
        if ref:
            _, sss_fn = ref
            dp = diff_report(ours, sss_fn(pci))
            if dp:
                bad_py.append((pci, dp))

    if bad_spec:
        print("  SSS vs spec: %d of %d cell identities MISMATCH"
              % (len(bad_spec), len(sss_cases)))
        for pci, d in bad_spec[:6]:
            print("    pci=%d: %s" % (pci, d))
        if len(bad_spec) > 6:
            print("    ... and %d more" % (len(bad_spec) - 6))
        mismatches += len(bad_spec)
    else:
        print("  SSS vs spec: all %d cell identities agree" % len(sss_cases))

    if ref:
        if bad_py:
            print("  SSS vs py3gpp: %d of %d MISMATCH"
                  % (len(bad_py), len(sss_cases)))
            for pci, d in bad_py[:6]:
                print("    pci=%d: %s" % (pci, d))
            mismatches += len(bad_py)
        else:
            print("  SSS vs py3gpp: all %d cell identities agree" % len(sss_cases))
    elif not bad_spec:
        print("  SSS vs py3gpp: skipped (absent)")

    # ── verdict ──
    print("\n  sequences checked: %d, chips compared: %d"
          % (checks, checks * L))
    if mismatches:
        print("  MISMATCHES: %d" % mismatches)
        print("\n== NR synchronisation sequences do NOT match TS 38.211")
        return 1
    print("  MISMATCHES: 0")
    if ref:
        print("\n== NR synchronisation sequences agree with TS 38.211, and")
        print("   with py3gpp -- two independent readings of the same clause")
    else:
        print("\n== NR synchronisation sequences agree with TS 38.211")
        print("   (single-reference run: py3gpp was not importable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
