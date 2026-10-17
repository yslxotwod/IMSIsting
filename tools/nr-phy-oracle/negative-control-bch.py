#!/usr/bin/env python3
"""Two-sided negative control for tools/nr-phy-oracle/cmp_nr_bch.py.

A comparator that always passes proves nothing, and neither does one that
always fails. This runs it in both directions:

  DIRECTION 1 -- it must PASS the real module. If cmp_nr_bch.py is broken (a
  crash, a bad table, an assertion that never holds), this is what catches it.

  DIRECTION 2 -- it must FAIL a module with a known defect reintroduced. Each
  mutation below is a defect that would produce a plausible-looking waveform
  and a wrong one.

WHY THE MODULE IS COPIED AND NOT EDITED IN PLACE

The last time a negative-control harness mutated a module where it stood,
modules/15_downgrade.sh was left empty (2773 lines lost, recovered only from a
session store). So every mutation here is applied to a COPY inside a scratch
tree that mirrors the repository with symlinks, and the repository's own module
is never opened for writing. The control byte-compares the real module before
and after and refuses to report if it changed.

MUTATIONS

  A  payload_generate: the 3rd and 2nd SFN LSBs swapped -- a payload
     interleaving defect. Everything downstream is then a valid codeword for
     the WRONG payload, which is exactly the kind of error a "does it decode"
     test cannot see.
  B  subblock_interleave: `i = k % 32` instead of `i = (32*k)//n` -- permutes
     32 elements at a time instead of 32 chunks, so the rate-matched output is
     wrong while remaining the right length.
  C  crc24c: the D^20 term dropped from gCRC24C -- a one-bit change to the
     polynomial, producing 24 bits of parity that look entirely reasonable.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
REAL_MODULE = os.path.join(ROOT, "modules", "12_nr_air.sh")
COMPARATOR = os.path.join(HERE, "cmp_nr_bch.py")

MUTATIONS = [
    ("A payload_generate: SFN 3rd/2nd LSB swapped",
     "a[PBCH_G[7]] = (sfn >> 2) & 1",
     "a[PBCH_G[7]] = (sfn >> 1) & 1"),
    ("B subblock_interleave: 32 chunks -> 32 elements",
     "i = (32 * k) // n",
     "i = k % 32"),
    ("C crc24c: gCRC24C with the D^20 term dropped",
     "for e in (24, 23, 21, 20, 17, 15, 13, 12, 8, 4, 2, 1, 0):",
     "for e in (24, 23, 21, 17, 15, 13, 12, 8, 4, 2, 1, 0):"),
]


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def build_tree(dest, module_src):
    """Mirror the repo with symlinks, with a real modules/ holding a real copy
    of the module under test. The module derives its own root and temp dir from
    its location, so a scratch tree gets its own generated generator."""
    os.makedirs(dest, exist_ok=True)
    for name in sorted(os.listdir(ROOT)):
        # `tmp` is left out deliberately: the module's generated baseband
        # generator is written under $TMP_DIR, and if every scratch tree shared
        # the repository's generator then a control run and a real run would
        # read each other's file. Each scratch tree gets its own.
        if name in ("modules", ".git", "tmp"):
            continue
        os.symlink(os.path.join(ROOT, name), os.path.join(dest, name))
    os.makedirs(os.path.join(dest, "tmp"), exist_ok=True)
    mods = os.path.join(dest, "modules")
    os.makedirs(mods, exist_ok=True)
    for name in sorted(os.listdir(os.path.join(ROOT, "modules"))):
        if name == "12_nr_air.sh":
            continue
        os.symlink(os.path.join(ROOT, "modules", name), os.path.join(mods, name))
    shutil.copyfile(module_src, os.path.join(mods, "12_nr_air.sh"))
    os.chmod(os.path.join(mods, "12_nr_air.sh"), 0o755)


def run_comparator(module_path, tree):
    env = dict(os.environ)
    env["NR_BCH_MODULE"] = module_path
    # Point the module's temp dir at this scratch tree so its regenerated
    # generator is private to this run. The comparator discovers the path by
    # asking the module, so nothing else needs to be told.
    env["TMP_DIR"] = os.path.join(tree, "tmp")
    env.pop("NR_BCH_BB", None)
    proc = subprocess.run([sys.executable, COMPARATOR], cwd=tree, env=env,
                          capture_output=True, text=True, timeout=115)
    return proc.returncode, proc.stdout


def main():
    before = sha(REAL_MODULE)
    work = tempfile.mkdtemp(prefix="nr-bch-negctl-")
    failures = []

    # DIRECTION 1: the comparator must pass the module as it stands.
    tree = os.path.join(work, "pristine")
    build_tree(tree, REAL_MODULE)
    rc, out = run_comparator(os.path.join(tree, "modules", "12_nr_air.sh"), tree)
    if rc != 0:
        failures.append("PRECHECK: the comparator rejects the real module (rc=%d)" % rc)
        print("PRECHECK FAILED (rc=%d)" % rc)
        print(out[-2000:])
    else:
        print("PRECHECK ok: the comparator passes the module unmodified")

    # DIRECTION 2: each reintroduced defect must be caught.
    for i, (label, old, new) in enumerate(MUTATIONS):
        src = open(REAL_MODULE).read()
        if old not in src:
            failures.append("%s: anchor not found" % label)
            print("ANCHOR NOT FOUND: %s" % label)
            continue
        if label.startswith("C"):
            mutated = src.replace(old, new, 1)     # generator's copy only
        else:
            mutated = src.replace(old, new)
        if mutated == src:
            failures.append("%s: mutation changed nothing" % label)
            continue
        tree = os.path.join(work, "m%d" % i)
        build_tree(tree, REAL_MODULE)
        mpath = os.path.join(tree, "modules", "12_nr_air.sh")
        with open(mpath, "w") as fh:
            fh.write(mutated)
        rc, out = run_comparator(mpath, tree)
        if rc == 0:
            failures.append("%s: comparator still passed" % label)
            print("NOT CAUGHT: %s" % label)
        else:
            first = [l for l in out.splitlines() if l.startswith("MISMATCH")]
            print("caught: %s -> rc=%d, %d mismatch line(s)%s"
                  % (label, rc, len(first),
                     (", first: " + first[0][:90]) if first else ""))

    after = sha(REAL_MODULE)
    if before != after:
        # This control never opens the real module for writing, so a change
        # here is a CONCURRENT WRITER -- the module's owner editing it while
        # the control ran. Either way the run is not evidence: the precheck and
        # the mutations were then measured against different revisions.
        print("NEGCTL-BCH: not evidence -- modules/12_nr_air.sh changed during "
              "the run (%s -> %s)." % (before[:12], after[:12]))
        print("  Nothing here writes that file, so a live writer is editing it. "
              "Re-run once it is idle; a control measured across two revisions "
              "of the module means nothing.")
        shutil.rmtree(work, ignore_errors=True)
        return 2

    shutil.rmtree(work, ignore_errors=True)

    if failures:
        print("NEGCTL-BCH: FAILED")
        for f in failures:
            print("  %s" % f)
        return 1
    print("NEGCTL-BCH: the comparator passes the true module and rejects all "
          "%d reintroduced defects" % len(MUTATIONS))
    print("module sha unchanged: %s" % before)
    return 0


if __name__ == "__main__":
    sys.exit(main())
