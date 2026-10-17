#!/usr/bin/env python3
"""Two-sided negative control for tools/nr-phy-oracle/cmp_nr_ssb_map.py.

  DIRECTION 1 -- the comparator must PASS the module as it stands. This is what
  catches a comparator that is broken rather than strict.

  DIRECTION 2 -- it must FAIL the module with each defect below reintroduced.
  Every one of these produces a waveform that transmits happily and that no
  handset will synchronise to, which is exactly the class of error a "does it
  run" check cannot see.

MUTATIONS

  A  the DMRS comb offset `v = pci % 4` shifted to `(pci + 1) % 4`. The SSB
     still occupies every subcarrier it should, the power is right, the chips
     are right -- and the DMRS sits on the wrong comb, so a receiver that
     correlates against v finds nothing.
  B  symbol 2's left PBCH block widened from k 0..47 to k 0..55, so the DMRS
     comb reaches into the subcarriers TS 38.211 Table 7.4.3.1-1 marks "Set to
     0" and 8 PBCH resource elements become DMRS.
  C  the DMRS c_init loses its `+ v` term, so the seed is wrong and every DMRS
     chip is wrong while the positions stay perfect.

WHY A COPY, AND WHY A PRIVATE TMP_DIR

The mutation is applied inside a scratch tree that mirrors the repository with
symlinks, never to the module where it stands: the last in-place mutation
harness in this tree left modules/15_downgrade.sh empty and over a thousand
lines had to be rebuilt. Each scratch tree also gets its own $TMP_DIR, because
the module writes its generated baseband generator there and a shared path lets
a control run and a real run read each other's file.
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
COMPARATOR = os.path.join(HERE, "cmp_nr_ssb_map.py")

MUTATIONS = [
    ("A the DMRS comb offset shifted by one",
     "    v = pci % 4\n    dmrs_k = {1: list(range(v, 240, 4)),",
     "    v = (pci + 1) % 4\n    dmrs_k = {1: list(range(v, 240, 4)),"),
    ("B symbol 2's left PBCH block widened into the Set-to-0 band",
     "2: list(range(v, 48, 4)) + list(range(192 + v, 240, 4)),",
     "2: list(range(v, 56, 4)) + list(range(192 + v, 240, 4)),"),
    ("C the DMRS c_init loses its + v term",
     "c_init = (2 ** 11) * (i_ssb + 1) * (pci // 4 + 1) + 64 * (i_ssb + 1) + v",
     "c_init = (2 ** 11) * (i_ssb + 1) * (pci // 4 + 1) + 64 * (i_ssb + 1) + 0"),
    # D matters more than A, B and C together. The module has its own guards --
    # a DMRS RE count, a PBCH RE count, a pinned DMRS chip table -- and A, B and
    # C all trip one of them, so they show the module protects itself (which is
    # good) but not that THIS comparator discriminates. D slides symbol 2's
    # upper PBCH block down by one subcarrier: still 48 subcarriers, so both
    # counts still pass, and no pin covers the placement. Only the occupancy
    # check here can see it, as one Set-to-0 subcarrier being driven and one
    # PBCH subcarrier going missing.
    ("D symbol 2's upper PBCH block slid one subcarrier down (module's own "
     "guards all pass)",
     "else list(range(48)) + list(range(192, 240)))",
     "else list(range(48)) + list(range(191, 239)))"),
]


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def build_tree(dest, module_src):
    os.makedirs(dest, exist_ok=True)
    for name in sorted(os.listdir(ROOT)):
        if name in ("modules", ".git", "tmp"):
            continue
        os.symlink(os.path.join(ROOT, name), os.path.join(dest, name))
    os.makedirs(os.path.join(dest, "tmp"), exist_ok=True)
    mods = os.path.join(dest, "modules")
    os.makedirs(mods, exist_ok=True)
    for name in sorted(os.listdir(os.path.join(ROOT, "modules"))):
        if name == "12_nr_air.sh":
            continue
        os.symlink(os.path.join(ROOT, "modules", name),
                   os.path.join(mods, name))
    shutil.copyfile(module_src, os.path.join(mods, "12_nr_air.sh"))
    os.chmod(os.path.join(mods, "12_nr_air.sh"), 0o755)


def run_comparator(module_path, tree):
    """Run the comparator against THE MODULE PATH GIVEN.

    This function's first version ignored its argument and invoked the
    comparator bare, so all three mutants were reported as missed while the
    comparator was really re-checking the repository's own module. That made the
    control report a defect in the comparator that did not exist AND would have
    hidden a real one. The path is passed explicitly and the comparator echoes
    it, so a future regression shows up as the wrong path in the output."""
    env = dict(os.environ)
    env["TMP_DIR"] = os.path.join(tree, "tmp")
    proc = subprocess.run([sys.executable, COMPARATOR, "--module", module_path],
                          cwd=tree, env=env, capture_output=True, text=True,
                          timeout=110)
    return proc.returncode, proc.stdout


def main():
    before = sha(REAL_MODULE)
    work = tempfile.mkdtemp(prefix="nr-ssb-negctl-")
    failures = []

    tree = os.path.join(work, "pristine")
    build_tree(tree, REAL_MODULE)
    rc, out = run_comparator(os.path.join(tree, "modules", "12_nr_air.sh"), tree)
    if rc != 0:
        failures.append("PRECHECK: the comparator rejects the real module (rc=%d)"
                        % rc)
        print("PRECHECK FAILED (rc=%d)" % rc)
        print(out[-2500:])
    else:
        print("PRECHECK ok: the comparator passes the module unmodified")

    for i, (label, old, new) in enumerate(MUTATIONS):
        src = open(REAL_MODULE).read()
        if old not in src:
            failures.append("%s: anchor not found" % label)
            print("ANCHOR NOT FOUND: %s" % label)
            continue
        mutated = src.replace(old, new, 1)
        tree = os.path.join(work, "m%d" % i)
        build_tree(tree, REAL_MODULE)
        mpath = os.path.join(tree, "modules", "12_nr_air.sh")
        with open(mpath, "w") as fh:
            fh.write(mutated)
        os.chmod(mpath, 0o755)
        rc, out = run_comparator(mpath, tree)
        if mpath not in out:
            failures.append("%s: the comparator did not check the mutated "
                            "module (it reported a different path)" % label)
            print("WRONG MODULE: %s" % label)
            continue
        if rc == 0:
            failures.append("%s: comparator still passed" % label)
            print("NOT CAUGHT: %s" % label)
        else:
            first = [l for l in out.splitlines() if l.startswith("MISMATCH")]
            failed = [l for l in first if "generator failed" in l]
            how = ("the module's own guards refused to emit" if failed
                   else "this comparator caught it")
            print("caught: %s\n        -> %s (%d mismatch line(s)); %s"
                  % (label, how, len(first),
                     (first[0][9:110]) if first else ""))

    after = sha(REAL_MODULE)
    shutil.rmtree(work, ignore_errors=True)
    if before != after:
        print("NEGCTL-SSB: not evidence -- modules/12_nr_air.sh changed during "
              "the run (%s -> %s)." % (before[:12], after[:12]))
        print("  Nothing here writes that file, so a live writer is editing it.")
        return 2

    if failures:
        print("NEGCTL-SSB: FAILED")
        for f in failures:
            print("  %s" % f)
        return 1
    print("NEGCTL-SSB: the comparator passes the true module and rejects all "
          "%d reintroduced defects" % len(MUTATIONS))
    print("module sha unchanged: %s" % before)
    return 0


if __name__ == "__main__":
    sys.exit(main())
