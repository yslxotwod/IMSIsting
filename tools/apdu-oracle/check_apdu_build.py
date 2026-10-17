#!/usr/bin/env python3
"""Differential check for the C-/R-APDU coding of modules/16_sim.sh.

The module builds command APDUs (`--build-apdu`), parses them back
(`--parse-apdu`) and labels status words. This checker states ISO/IEC 7816-4
§5.1 (cases 1, 2S, 3S, 4S, 2E, 3E, 4E) and §5.1.4 (SW1 classes) independently
and compares, so a field that quietly moved cannot agree with itself and pass.

ISO/IEC 7816-4 §5.1:

  case 1   header only                                   CLA INS P1 P2
  case 2S  header, Le one byte                            ... LE
  case 3S  header, Lc one byte, data                      ... LC DATA
  case 4S  header, Lc, data, Le                           ... LC DATA LE
  case 2E  header, 00, Le two bytes                       ... 00 LE1 LE2
  case 3E  header, 00, Lc two bytes, data                 ... 00 LC1 LC2 DATA
  case 4E  header, 00, Lc, data, Le two bytes             ... 00 LC1 LC2 DATA LE1 LE2

  Le = 256 is encoded 00 in the short form and Le = 65536 is encoded 0000 in
  the extended one. Extended is mandatory when Lc > 255 or Le > 256. This
  checker also takes four hex digits of Le as the CLI's way of asking for the
  extended form, which is this tree's convention and not ISO's.

ISO/IEC 7816-4 §5.1.4, SW1 classes:

  90 success | 61 success, SW2 bytes still available | 62 warning, state may
  have changed | 63 warning, state changed | 64 execution error | 65 execution
  error, memory | 67 checking error, length | 68 checking error, CLA function
  | 69 checking error, command not allowed | 6A checking error, parameters |
  6B checking error, parameters/offset | 6C checking error, Le | 6D checking
  error, INS | 6E checking error, CLA | 6F checking error, no diagnosis

  A warning is not a failure in the clause, so the module's exit codes for
  warnings are its own policy and this checker only asserts the class word;
  success must exit 0 and an error must not.

The second implementation is pySim's `pySim.utils.parse_command_apdu`, which
implements the same four short cases and no extended form.

Usage:  python3 tools/apdu-oracle/check_apdu_build.py [--negctl] [--verbose]
Exit:   0 all cases agree, 1 a case disagrees, 2 the environment is unusable.
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULE = os.environ.get("SIM_MODULE", os.path.join(ROOT, "modules", "16_sim.sh"))

CASES = 0
MISMATCHES = []


def report(name, ok, detail=""):
    global CASES
    CASES += 1
    if not ok:
        MISMATCHES.append("%s: %s" % (name, detail))


def run(module, *args):
    try:
        p = subprocess.run(["bash", module] + list(args), capture_output=True,
                           text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, {}, str(exc)
    fields = {}
    for line in p.stdout.splitlines():
        if "\t" in line:
            k, _, v = line.partition("\t")
            fields.setdefault(k, v)
    return p.returncode, fields, p.stdout


# ── the independent statement of the case layout ─────────────────────────
def le_from_arg(text):
    """None, or (Le value, forced-extended). Four hex digits ask for extended."""
    if text is None:
        return None, False
    v = int(text, 16)
    if len(text) == 4:
        return (65536 if v == 0 else v), True
    return (256 if v == 0 else v), False


def reference(cla, ins, p1, p2, data, le, force_extended):
    """Return (bytes hex, case label, lc or None, le or None)."""
    hdr = "%02X%02X%02X%02X" % (cla, ins, p1, p2)
    lc = None if data is None else len(data)
    extended = force_extended or (lc is not None and lc > 255) or (
        le is not None and le > 256)
    if data is None and le is None:
        return hdr, "1", None, None
    if data is None:
        if extended:
            word = 0 if le == 65536 else le
            return hdr + "00%04X" % word, "2E", None, le
        return hdr + "%02X" % (0 if le == 256 else le), "2S", None, le
    if extended:
        body = hdr + "00%04X" % lc + data.hex().upper()
        if le is None:
            return body, "3E", lc, None
        word = 0 if le == 65536 else le
        return body + "%04X" % word, "4E", lc, le
    body = hdr + "%02X" % lc + data.hex().upper()
    if le is None:
        return body, "3S", lc, None
    return body + "%02X" % (0 if le == 256 else le), "4S", lc, le


def pysim_parser():
    for path in (os.environ.get("PYSIM_PATH"), "/home/ysl/.lte-oracles/pysim"):
        if path and path not in sys.path and os.path.isdir(path):
            sys.path.append(path)
    stub = os.environ.get("PYSIM_STUB", "/home/ysl/.ota-oracles/stub")
    if stub and stub not in sys.path and os.path.isdir(stub):
        sys.path.append(stub)
    try:
        from pySim.utils import parse_command_apdu
    except Exception:
        return None
    return parse_command_apdu


SHORT_SW = {
    0x9000: "success", 0x6A82: "error", 0x6A83: "error", 0x6A86: "error",
    0x6982: "error", 0x6983: "error", 0x6985: "error", 0x6D00: "error",
    0x6E00: "error", 0x6F00: "error", 0x6700: "error", 0x6881: "error",
    0x6282: "warning", 0x6281: "warning", 0x6300: "warning", 0x6400: "error",
    0x6500: "error", 0x6A80: "error", 0x6C05: "error", 0x6C00: "error",
}


def check_build(module, pyparse, verbose):
    payload = bytes(range(1, 98)) * 4
    cases = [
        # (cla, ins, p1, p2, data, Le argument text)
        (0x00, 0xA4, 0x04, 0x00, None, None),
        (0x00, 0xA4, 0x04, 0x00, None, "0A"),
        (0x00, 0xA4, 0x04, 0x00, None, "00"),
        (0x00, 0xB0, 0x00, 0x00, None, "FF"),
        (0xA0, 0xB0, 0x00, 0x00, bytes.fromhex("3F00"), None),
        (0xA0, 0xB0, 0x00, 0x00, bytes.fromhex("3F00"), "0A"),
        (0xA0, 0xB0, 0x00, 0x00, bytes.fromhex("3F00"), "00"),
        (0xA0, 0xDA, 0x00, 0x00, payload[:255], None),
        (0xA0, 0xDA, 0x00, 0x00, payload[:255], "10"),
        (0xA0, 0xDA, 0x00, 0x00, payload[:256], None),
        (0xA0, 0xDA, 0x00, 0x00, payload[:300], "0100"),
        (0x00, 0xB0, 0x00, 0x00, None, "0100"),
        (0x00, 0xB0, 0x00, 0x00, None, "0000"),
        (0xA0, 0xDA, 0x00, 0x00, payload[:255], "0100"),
        (0xA0, 0xDA, 0x00, 0x00, payload[:256], None),
        (0xA0, 0xDA, 0x00, 0x00, bytes.fromhex("3F00"), "0000"),
        (0xA0, 0xDA, 0x00, 0x00, bytes.fromhex("3F00"), "03E8"),
    ]
    for cla, ins, p1, p2, data, le_arg in cases:
        dhex = data.hex().upper() if data is not None else None
        name = "build/%02X%02X/d%d/%s" % (
            cla, ins, len(data) if data is not None else 0, le_arg or "-")
        argv = ["--build-apdu", "%02X" % cla, "%02X" % ins, "%02X" % p1,
                "%02X" % p2]
        if dhex is not None:
            argv.append(dhex)
            if le_arg is not None:
                argv.append(le_arg)
        elif le_arg is not None:
            argv.extend(["", le_arg])
        rc, f, out = run(module, *argv)
        le, force = le_from_arg(le_arg)
        ref_hex, ref_case, ref_lc, ref_le = reference(
            cla, ins, p1, p2, data, le, force)
        report(name + "/hex", rc == 0 and f.get("apdu_hex") == ref_hex,
               "ours %s clause %s (rc=%d %s)" % (f.get("apdu_hex"), ref_hex, rc,
                                                 out.strip().replace("\t", " ")[:120]))
        report(name + "/case", f.get("case") == ref_case,
               "ours %s clause %s" % (f.get("case"), ref_case))
        report(name + "/length", f.get("length") == str(len(ref_hex) // 2),
               "ours %s clause %d" % (f.get("length"), len(ref_hex) // 2))
        want_le = "-" if ref_le is None else str(ref_le)
        report(name + "/le", f.get("le") == want_le,
               "ours %s clause %s" % (f.get("le"), want_le))
        want_lc = str(ref_lc if ref_lc is not None else 0)
        report(name + "/lc", f.get("lc") == want_lc,
               "ours %s clause %s" % (f.get("lc"), want_lc))

        if pyparse is not None and len(ref_hex) // 2 <= 261:
            try:
                their_case, their_lc, their_le, their_data = pyparse(
                    bytes.fromhex(ref_hex))
            except Exception as exc:
                their_case, their_lc, their_le, their_data = (
                    "error:%s" % exc, None, None, b"")
            if not isinstance(their_case, str) and their_case <= 4:
                report(name + "/pysim-case", their_case == int(ref_case[0]),
                       "pysim %s clause %s" % (their_case, ref_case[0]))
                want_pl = 0 if ref_le in (None, 256) and ref_le != 256 else ref_le
                if ref_le is None:
                    want_pl = 0
                report(name + "/pysim-le", their_le == want_pl,
                       "pysim le %s clause %s" % (their_le, want_pl))

        # The parser has to read the builder's own bytes back to the same
        # fields -- a build and a parse that disagree is the defect this
        # module cannot afford.
        rc, p, pout = run(module, "--parse-apdu", ref_hex)
        report(name + "/parse-case", rc == 0 and p.get("case") == ref_case,
               "rc=%d case %s clause %s" % (rc, p.get("case"), ref_case))
        report(name + "/parse-cla", p.get("cla") == "%02X" % cla, p.get("cla"))
        report(name + "/parse-length",
               p.get("length") == str(len(ref_hex) // 2), p.get("length"))
        report(name + "/parse-lc", p.get("lc") == want_lc,
               "ours %s clause %s" % (p.get("lc"), want_lc))
        if verbose:
            print("ok\t%s\t%s" % (name, ref_hex))
    return len(cases)


def check_sw(module, verbose):
    for sw, klass in SHORT_SW.items():
        name = "sw/%04X" % sw
        rc, f, out = run(module, "--parse-apdu", "%04X" % sw)
        label = f.get("status", "")
        word = label.split(":")[0].split(" ")[0]
        report(name + "/class", word == klass,
               "ours %r clause %s" % (label, klass))
        if klass == "success":
            report(name + "/exit", rc == 0, "rc=%d want 0" % rc)
        elif klass == "error":
            report(name + "/exit", rc != 0, "rc=%d want nonzero" % rc)
        if verbose:
            print("ok\t%s\t%s" % (name, label))

    # The residual byte count lives in SW2 for 61xx and 6Cxx only.
    for sw, n in ((0x6110, 16), (0x61FF, 255), (0x6C05, 5), (0x6C00, 0)):
        rc, f, _ = run(module, "--parse-apdu", "%04X" % sw)
        klass = "success" if sw >> 8 == 0x61 else "error"
        report("sw/%04X/length" % sw, f.get("length_byte") == str(n),
               "ours %s clause %d" % (f.get("length_byte"), n))
        report("sw/%04X/class" % sw,
               f.get("status", "").split(":")[0].split(" ")[0] == klass,
               f.get("status"))
    # Any other SW2 is not a length, however it looks.
    rc, f, _ = run(module, "--parse-apdu", "6A82")
    report("sw/6A82/no-length", f.get("length_byte") == "-", f.get("length_byte"))
    return len(SHORT_SW)


MUTANTS = [
    ("le-256-reports-zero",
     'local v=$(( 16#$le )); (( v == 0 )) && v=256\n                body+=$(sim_byte "$v"); le_out="$v"',
     'local v=$(( 16#$le ))\n                body+=$(sim_byte "$v"); le_out="$v"'),
    ("lc-written-after-data",
     'case="3S"; body+=$(printf \'%02X%s\' "$lc" "$data")',
     'case="3S"; body+=$(printf \'%s%02X\' "$data" "$lc")'),
    ("four-hex-digits-do-not-ask-for-extended",
     '[[ "$le" =~ ^[0-9a-fA-F]{4}$ ]] && extended=1',
     ':'),
    ("4E-le-0000-reports-zero",
     'local v4=$(( 16#$le )); (( v4 == 0 )) && v4=65536',
     'local v4=$(( 16#$le ))'),
    ("sw-class-swapped",
     '6983) echo "error: authentication method blocked (PIN/PUK/ADM locked)" ;;',
     '6983) echo "success: authentication method blocked" ;;'),
]


def negctl(verbose):
    ok = True
    source = open(MODULE, encoding="utf-8").read()
    for name, old, new in MUTANTS:
        if old not in source:
            print("NEGCTL\tSKIP\t%s: anchor not found in %s"
                  % (name, os.path.basename(MODULE)))
            ok = False
            continue
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, os.path.basename(MODULE))
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(source.replace(old, new, 1))
            for link in ("tools", "loot"):
                src = os.path.join(ROOT, link)
                if os.path.isdir(src) and not os.path.exists(os.path.join(td, link)):
                    try:
                        os.symlink(src, os.path.join(td, link))
                    except OSError:
                        pass
            saved = list(MISMATCHES)
            globals()["MISMATCHES"] = []
            globals()["CASES"] = 0
            pyparse = pysim_parser()
            check_build(target, pyparse, verbose)
            check_sw(target, verbose)
            caught = bool(MISMATCHES)
            if verbose and caught:
                for m in MISMATCHES[:3]:
                    print("negctl\tsaw\t%s" % m)
            globals()["MISMATCHES"] = saved
            print("NEGCTL\t%s\t%s" % ("CAUGHT" if caught else "MISSED", name))
            if not caught:
                ok = False
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--negctl", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(MODULE):
        print("ERROR\tmodule not found: %s" % MODULE)
        return 2

    pyparse = pysim_parser()
    check_build(MODULE, pyparse, args.verbose)
    check_sw(MODULE, args.verbose)
    print("CASES\t%d" % CASES)
    for m in MISMATCHES[:40]:
        print("MISMATCH\t%s" % m)
    print("MISMATCHES\t%d" % len(MISMATCHES))
    if MISMATCHES:
        print("RESULT\tFAIL(%d)" % len(MISMATCHES))
        return 1
    print("RESULT\tPASS")
    if args.negctl:
        return 0 if negctl(args.verbose) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
