#!/usr/bin/env python3
"""Negative control for cmp_nr_numerology.py.

Two-sided, like negative-control-mib.py: the UNMUTATED copy of the module
must make the comparator return 0, so a comparator that always fails is
caught, and each MUTATED copy must make it return non-zero, so a comparator
that always passes is caught.

The mutations are the three ways this stage could actually be fooled:

  1. a single wrong N_RB digit -- the transcription error the table check
     exists to find;
  2. an N_FFT that is a power of two and large enough but NOT minimal -- the
     case a membership test would pass and the minimality test must not;
  3. an f_s off the published ladder -- the number that goes to the radio.

The scratch copy is byte-compared against the real file before and after,
so no mutation can leak into modules/12_nr_air.sh.

Usage:  negative-control-numerology.py [--module PATH] [--quiet]
Exit:   0 the comparator was shown to be able to pass AND to fail
        1 it was not
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CMP = os.path.join(HERE, "cmp_nr_numerology.py")

MUTATIONS = [
    (
        "one N_RB digit wrong in the 15 kHz row (35 MHz: 188 -> 187)",
        "30:160 35:188 40:216",
        "30:160 35:187 40:216",
    ),
    (
        "N_FFT doubled, so it is a power of two and large enough but not "
        "minimal",
        "echo $(( 1 << i ))",
        "echo $(( 1 << (i + 1) ))",
    ),
    (
        "f_s halved, so it leaves the published sample rate ladder",
        "echo $(( scs * 1000 * nfft ))",
        "echo $(( scs * 1000 * nfft / 2 ))",
    ),
]


def run(cmp_path, module_path, quiet):
    p = subprocess.run(
        [sys.executable, cmp_path, "--module", module_path]
        + (["--quiet"] if quiet else []),
        capture_output=True, text=True, timeout=110,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(HERE))
    module = args.module or os.path.join(root, "modules", "12_nr_air.sh")
    if not os.path.exists(module):
        sys.exit("negative-control-numerology: module not found: %s" % module)
    if not os.path.exists(CMP):
        sys.exit("negative-control-numerology: comparator not found: %s" % CMP)

    original = open(module, "rb").read()

    print("== negative control for cmp_nr_numerology.py")
    print("   module : %s" % module)

    tmp = tempfile.mkdtemp(prefix="nr-num-negctl-")
    scratch = os.path.join(tmp, "mutated.sh")
    failures = []
    try:
        shutil.copyfile(module, scratch)
        rc, out = run(CMP, scratch, True)
        if rc == 0:
            print("   ok    unmutated copy            comparator returns 0")
        else:
            print("   FAIL  unmutated copy            comparator returns %d" % rc)
            for line in out.strip().splitlines()[-6:]:
                print("           %s" % line)
            failures.append("the comparator does not pass the unmutated "
                            "module, so it cannot be evidence about anything")

        for desc, find, repl in MUTATIONS:
            text = original.decode("utf-8", "surrogateescape")
            n = text.count(find)
            if n != 1:
                print("   FAIL  %-44s  mutation target appears %d times, "
                      "not once -- the control tested nothing"
                      % (desc.split("(")[0].strip()[:44], n))
                failures.append("mutation target not found exactly once: %s" % find)
                continue
            mutated = text.replace(find, repl).encode("utf-8", "surrogateescape")
            if mutated == original:
                failures.append("no-op mutation: %s" % find)
                continue
            with open(scratch, "wb") as fh:
                fh.write(mutated)
            rc, out = run(CMP, scratch, True)
            tag = desc.split("(")[0].strip()[:44]
            if rc != 0:
                print("   ok    %-44s comparator returns %d" % (tag, rc))
            else:
                print("   FAIL  %-44s comparator still returns 0 -- it cannot "
                      "detect this defect" % tag)
                failures.append("comparator did not detect: %s" % desc)
            if open(module, "rb").read() != original:
                sys.exit("negative-control-numerology: the REAL module changed "
                         "during the run -- refusing to continue")

        with open(scratch, "wb") as fh:
            fh.write(original)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if open(module, "rb").read() != original:
        sys.exit("negative-control-numerology: the REAL module changed during the run")

    print()
    if failures:
        print("NEGCTL-NUM: the comparator was NOT shown to be discriminating")
        for f in failures:
            print("  - %s" % f)
        return 1
    print("NEGCTL-NUM: the comparator passes the true module and rejects all "
          "%d reintroduced defects" % len(MUTATIONS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
