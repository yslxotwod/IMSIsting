#!/usr/bin/env python3
"""Differential check of the STK proactive command against pySim.

The claim under test is the octet order of the Command Details value: TS 31.111
6.4.4 (and TS 102 223 8.6) make it command number, type of command, command
qualifier. modules/52_stk.sh used to write type, qualifier, zero -- the type in
the command number's place -- and, because its own parser read the same way,
nothing caught it. pySim's CommandDetails/DeviceIdentities declarations are an
independent statement of the same order; this compares the two.

Exit 0 pass, 1 mismatch, 2 cannot run (no pySim).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULE = os.environ.get("STK_MODULE", os.path.join(ROOT, "modules", "52_stk.sh"))
PYSIM_PATH = os.environ.get("PYSIM_PATH", "/home/ysl/.lte-oracles/pysim")
PYSIM_STUB = os.environ.get("PYSIM_STUB", "/home/ysl/.ota-oracles/stub")

CASES = 0
MISMATCHES = []


def report(name, ok, detail=""):
    global CASES
    CASES += 1
    if not ok:
        MISMATCHES.append("%s: %s" % (name, detail))


def load_pysim():
    for path in (PYSIM_STUB, PYSIM_PATH):
        if path and path not in sys.path and os.path.isdir(path):
            sys.path.append(path)
    try:
        from pySim.cat import CommandDetails, DeviceIdentities
    except Exception as exc:  # pragma: no cover - environment dependent
        print("SKIP\tpySim not importable: %s" % exc)
        return None
    return CommandDetails, DeviceIdentities


def build(module, number, ctype, qual, src, dst):
    p = subprocess.run(["bash", module, "--build", "%02X" % ctype, "%02X" % qual,
                        "%02X" % src, "%02X" % dst, "%02X" % number],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def tlvs(hexstr):
    """Split a D0 envelope into {tag: value-hex}, one level deep."""
    out = {}
    h = hexstr.lower()
    if not h.startswith("d0"):
        return out
    off = 1
    length = int(h[off * 2:off * 2 + 2], 16)
    off += 1
    if length > 127:
        n = length & 0x7F
        length = int(h[off * 2:(off + n) * 2], 16)
        off += n
    while off * 2 < len(h):
        tag = h[off * 2:off * 2 + 2]
        off += 1
        l = int(h[off * 2:off * 2 + 2], 16)
        off += 1
        if l > 127:
            k = l & 0x7F
            l = int(h[off * 2:(off + k) * 2], 16)
            off += k
        out.setdefault(tag, h[off * 2:(off + l) * 2])
        off += l
    return out


def check(pysim, module):
    CommandDetails, DeviceIdentities = pysim
    cases = [
        (1, 0x10, 0x00, 0x81, 0x82),   # SET UP CALL
        (7, 0x21, 0x80, 0x81, 0x82),   # DISPLAY TEXT, high priority
        (255, 0x13, 0x00, 0x81, 0x82), # SEND SS
        (1, 0x15, 0x00, 0x81, 0x82),   # LAUNCH BROWSER
        (2, 0x24, 0x00, 0x81, 0x82),   # OPEN CHANNEL
    ]
    for number, ctype, qual, src, dst in cases:
        cd = CommandDetails()
        cd.from_dict({"command_details": {"command_number": number,
                                          "type_of_command": ctype,
                                          "command_qualifier": qual}})
        ref_cd = cd.to_bytes().hex()
        di = DeviceIdentities()
        di.from_dict({"device_identities": {"source_dev_id": "uicc",
                                            "dest_dev_id": "terminal"}})
        ref_di = di.to_bytes().hex()

        rc, out, err = build(module, number, ctype, qual, src, dst)
        got = tlvs(out)
        report("cd/%02X-%02X-%02X" % (number, ctype, qual),
               rc == 0 and got.get("01") == ref_cd,
               "ours %s pySim %s %s" % (got.get("01"), ref_cd, err))
        report("di/%02X-%02X" % (number, ctype),
               rc == 0 and got.get("02") == ref_di,
               "ours %s pySim %s" % (got.get("02"), ref_di))

    # The parser must read the same three octets back in the same order.
    rc, out, err = build(module, 7, 0x10, 0x00, 0x81, 0x82)
    p = subprocess.run(["bash", module, "--parse", out], capture_output=True,
                       text=True, timeout=60)
    fields = {}
    for line in p.stdout.splitlines():
        if "\t" in line:
            k, _, v = line.partition("\t")
            fields.setdefault(k, v)
    report("parse/number", fields.get("command_number") == "07", str(fields.get("command_number")))
    report("parse/type", fields.get("cmd_type") == "10", str(fields.get("cmd_type")))
    report("parse/qualifier", fields.get("qualifier") == "00", str(fields.get("qualifier")))
    report("parse/name", fields.get("cmd_name") == "SET UP CALL", str(fields.get("cmd_name")))

    # A card sends the comprehension-required tags (0x81/0x82), so the parser
    # has to read those too; the value is identical.
    rc, out, _ = build(module, 7, 0x10, 0x00, 0x81, 0x82)
    cr = out.replace("D0", "D0").replace("0103", "8103").replace("0202", "8202")
    p = subprocess.run(["bash", module, "--parse", cr], capture_output=True,
                       text=True, timeout=60)
    report("parse/comprehension-required",
           "cmd_name\tSET UP CALL" in p.stdout and p.returncode == 0,
           p.stdout[:120])


MUTANTS = [
    ("type-in-command-number-position", 'cd=$(stk_tlv 01 "${number}${type}${qualifier}")',
     'cd=$(stk_tlv 01 "${type}${qualifier}00")'),
    ("device-identities-swapped", 'di=$(stk_tlv 02 "${src}${dst}")',
     'di=$(stk_tlv 02 "${dst}${src}")'),
    ("command-number-dropped", 'cd=$(stk_tlv 01 "${number}${type}${qualifier}")',
     'cd=$(stk_tlv 01 "${type}${qualifier}")'),
]


def negctl(verbose):
    pysim = load_pysim()
    if pysim is None:
        print("SKIP\tnegative control needs pySim")
        return False
    ok = True
    source = open(MODULE, encoding="utf-8").read()
    for name, old, new in MUTANTS:
        if old not in source:
            print("MUTANT\t%s\tNOT APPLICABLE (anchor missing)" % name)
            ok = False
            continue
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "52_stk.sh")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(source.replace(old, new, 1))
            for link in ("tools",):
                src = os.path.join(ROOT, link)
                if os.path.isdir(src):
                    os.symlink(src, os.path.join(td, link))
            before = len(MISMATCHES)
            globals()["MISMATCHES"] = []
            globals()["CASES"] = 0
            check(pysim, target)
            caught = bool(MISMATCHES)
            globals()["MISMATCHES"] = []
            globals()["CASES"] = 0
            print("NEGCTL\t%s\t%s" % ("CAUGHT" if caught else "MISSED", name))
            if not caught:
                ok = False
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--negctl", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.negctl:
        return 0 if negctl(args.verbose) else 1

    if not os.path.isfile(MODULE):
        print("ERROR\tmodule not found: %s" % MODULE)
        return 2
    pysim = load_pysim()
    if pysim is None:
        return 2
    check(pysim, MODULE)
    print("CASES\t%d" % CASES)
    for m in MISMATCHES[:40]:
        print("MISMATCH\t%s" % m)
    print("MISMATCHES\t%d" % len(MISMATCHES))
    if MISMATCHES:
        print("RESULT\tFAIL(%d)" % len(MISMATCHES))
        return 1
    print("RESULT\tPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
