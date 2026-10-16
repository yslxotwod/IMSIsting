#!/usr/bin/env python3
"""Negative control for cmp_nr_mib.py.

A comparator that always returns 1 "passes" every negative control, and a
comparator that always returns 0 passes every real run. This script closes
both directions with the same fixture:

  * the UNMUTATED copy of the module must make the comparator return 0, so a
    comparator that always fails is caught; and
  * each MUTATED copy must make it return non-zero, so a comparator that
    always passes is caught.

Every mutation is one of the defects this comparator was written to find, or
a defect it names in its output. The scratch copy is byte-compared against
the real file before and after, so a mutation can never leak into
modules/12_nr_air.sh.

Usage:  negative-control-mib.py [--module PATH] [--quiet]
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
CMP = os.path.join(HERE, "cmp_nr_mib.py")

# (description, exact text in the module, replacement)
#
# The strings are the module's own source, not paraphrases: if nr-air
# reformats the decoder the replacement will not match and this control will
# say so instead of silently testing nothing.
MUTATIONS = [
    (
        "the CHOICE selector is dropped again and every field shifts one bit "
        "early (the original defect)",
        "sfn=$(_nair_bit 1 6)",
        "sfn=$(_nair_bit 0 6)",
    ),
    (
        "cellBarred is reported inverted, so a normal cell reads as barred",
        "$([[ $barred -eq 1 ]] && echo notBarred || echo barred)",
        "$([[ $barred -eq 1 ]] && echo barred || echo notBarred)",
    ),
    (
        "the messageClassExtension guard is disabled, so a non-MIB payload "
        "is reported as a MIB",
        "if (( choice != 0 )); then",
        "if (( choice != 0 )) && false; then",
    ),
]


def run(cmp_path, module_path, quiet):
    p = subprocess.run(
        [sys.executable, cmp_path, "--module", module_path] + (["--quiet"] if quiet else []),
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
        sys.exit("negative-control-mib: module not found: %s" % module)
    if not os.path.exists(CMP):
        sys.exit("negative-control-mib: comparator not found: %s" % CMP)

    original = open(module, "rb").read()

    print("== negative control for cmp_nr_mib.py")
    print("   module : %s" % module)

    tmp = tempfile.mkdtemp(prefix="mib-negctl-")
    scratch = os.path.join(tmp, "mutated.sh")
    failures = []
    try:
        # ── direction 1: the unmutated copy must PASS ────────────────────
        shutil.copyfile(module, scratch)
        rc, out = run(CMP, scratch, True)
        if rc == 0:
            print("   ok    unmutated copy            comparator returns 0")
        else:
            print("   FAIL  unmutated copy            comparator returns %d" % rc)
            tail = "\n".join(out.strip().splitlines()[-6:])
            for line in tail.splitlines():
                print("           %s" % line)
            failures.append("the comparator does not pass the unmutated module, "
                            "so it cannot be evidence about anything")

        # ── direction 2: every mutation must FAIL ────────────────────────
        for desc, find, repl in MUTATIONS:
            text = original.decode("utf-8", "surrogateescape")
            n = text.count(find)
            if n != 1:
                print("   FAIL  %-24s  the mutation target appears %d times, "
                      "not once -- the control tested nothing"
                      % ("", n))
                failures.append("mutation target not found exactly once: %s" % find)
                continue
            mutated = text.replace(find, repl).encode("utf-8", "surrogateescape")
            if mutated == original:
                print("   FAIL  mutation was a no-op")
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
            # The mutation must not have touched the real file.
            if open(module, "rb").read() != original:
                sys.exit("negative-control-mib: the REAL module changed during "
                         "the run -- refusing to continue")

        # restore and confirm the control is repeatable
        with open(scratch, "wb") as fh:
            fh.write(original)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if open(module, "rb").read() != original:
        sys.exit("negative-control-mib: the REAL module changed during the run")

    print()
    if failures:
        print("NEGCTL-MIB: the comparator was NOT shown to be discriminating")
        for f in failures:
            print("  - %s" % f)
        return 1
    print("NEGCTL-MIB: the comparator passes the true module and rejects all "
          "%d reintroduced defects" % len(MUTATIONS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
