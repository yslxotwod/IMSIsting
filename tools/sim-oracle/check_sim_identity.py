#!/usr/bin/env python3
"""Differential check for the SIM identity codecs (EF_ICCID, EF_IMSI).

modules/16_sim.sh decodes both records. Rather than trust its reading, this
checker states the two layouts independently from the clause's own prose,
encodes records from that statement, and compares what the module decodes.

EF_ICCID (TS 31.102 §4.2.1): a transparent EF of ten octets, every octet two
digits with the low nibble first. There is no marker octet and no length
prefix inside the record -- 98 68 is the digits 8 9 8 6, which is why the
Chinese ICCIDs in the wild read 8986. An odd digit count ends with the filler
nibble F in the high half of the last octet. A nineteen- or twenty-digit
ICCID's last digit is the Luhn check digit (ITU-T E.118); the digits after
the two-digit issuer identification "89" begin with the country's calling
code, not with an MCC.

EF_IMSI (TS 31.102 §4.2.2): byte 1 counts the octets that follow it. The
first of those carries the parity of the digit count in its low nibble (1
even, 9 odd) and the first IMSI digit in its high nibble, so a nibble swap
leaves the parity as the leading character -- it is not a digit. The digit
count is at most fifteen.

Where pySim is importable its enc_iccid and enc_imsi are a second
implementation and have to agree with the encoders below -- octet for octet
for an odd digit count, and for an even one by decoding to the same IMSI,
since enc_imsi pads to a whole extra octet where the clause pads a nibble.

Usage:  python3 tools/sim-oracle/check_sim_identity.py [--negctl] [--verbose]
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
    """Run a module verb and return (rc, {key: value}, raw stdout)."""
    try:
        p = subprocess.run(["bash", module] + list(args), capture_output=True,
                           text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, {}, str(exc)
    fields = {}
    for line in p.stdout.splitlines():
        if "\t" in line:
            k, _, v = line.partition("\t")
            fields.setdefault(k, v)
    return p.returncode, fields, p.stdout


# ── the independent statement of both layouts ────────────────────────────
def swap_nibbles(digits):
    if len(digits) % 2:
        digits += "f"
    return "".join(digits[i + 1] + digits[i] for i in range(0, len(digits), 2))


def icc_decode(ef):
    digits = swap_nibbles(ef.lower())
    if digits.endswith("f"):
        digits = digits[:-1]
    return digits


def icc_encode(iccid):
    return swap_nibbles(iccid)


def luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check(payload):
    """The digit that makes payload+digit a Luhn-valid string."""
    for d in range(10):
        if luhn_ok(payload + str(d)):
            return str(d)
    raise AssertionError("no check digit")

# ITU-T E.118: the calling codes this checker generates records for.
CALLING_CODES = ("1", "7", "44", "49", "86", "91", "971")


def imsi_encode(imsi):
    parity = "9" if len(imsi) % 2 else "1"
    body = swap_nibbles(parity + imsi)
    return "%02x" % (len(body) // 2) + body


def imsi_decode(ef):
    ef = ef.lower()
    n = len(ef) // 2
    first = int(ef[0:2], 16)
    length_byte = None
    body = ef
    if 1 <= first <= 9 and first + 1 <= n:
        length_byte = first
        body = ef[2:]
    swapped = swap_nibbles(body)
    indicator, rest = swapped[0], swapped[1:].rstrip("f")
    parity = "odd" if indicator == "9" else "even" if indicator == "1" else None
    return {"imsi": rest, "parity": parity, "length_byte": length_byte,
            "body_bytes": len(body) // 2, "filler": "F" if swapped[1:] != swapped[1:].rstrip("f") else "none"}


# ── pySim cross-check ────────────────────────────────────────────────────
def pysim():
    for path in (os.environ.get("PYSIM_PATH"), "/home/ysl/.lte-oracles/pysim"):
        if path and path not in sys.path and os.path.isdir(path):
            sys.path.append(path)
    stub = os.environ.get("PYSIM_STUB", "/home/ysl/.ota-oracles/stub")
    if stub and stub not in sys.path and os.path.isdir(stub):
        sys.path.append(stub)
    try:
        from pySim.utils import enc_iccid, enc_imsi, dec_iccid
    except Exception:
        return None
    return enc_iccid, enc_imsi, dec_iccid


def check_iccid(module, pysim_fns, verbose):
    enc_iccid = pysim_fns[0] if pysim_fns else None
    cases = 0
    for code in CALLING_CODES:
        for tail in ("0000000000000", "1234567890123", "9876543210987"):
            for total in (19, 20):
                payload = ("89" + code + tail)[:total - 1]
                if len(payload) < total - 1:
                    payload = payload.ljust(total - 1, "0")
                iccid = payload + luhn_check(payload)
                ef = icc_encode(iccid)
                name = "iccid/%s/%d" % (code, total)
                cases += 1
                report(name + "/reference",
                       icc_decode(ef) == iccid, "%s" % icc_decode(ef))
                rc, f, out = run(module, "--decode-iccid", ef)
                report(name + "/digits", rc == 0 and f.get("iccid") == iccid,
                       "rc=%d %s" % (rc, out.strip()[:120]))
                report(name + "/length", f.get("length") == str(total), f.get("length"))
                report(name + "/issuer", f.get("issuer") == "89", f.get("issuer"))
                report(name + "/calling-code", f.get("calling_code") == code,
                       f.get("calling_code"))
                report(name + "/luhn", f.get("luhn") == "valid", f.get("luhn"))
                report(name + "/check-digit", f.get("check_digit") == iccid[-1],
                       f.get("check_digit"))
                if enc_iccid is not None:
                    report(name + "/pysim-codec", enc_iccid(iccid).lower() == ef,
                           "pysim %s ours %s" % (enc_iccid(iccid), ef))
                if verbose:
                    print("ok\t%s\t%s" % (name, iccid))

    # A check digit that does not add up is what the check is for.
    bad = icc_encode("8986000000000000002"[:-1] + "7")
    rc, f, out = run(module, "--decode-iccid", bad)
    report("iccid/bad-luhn/caught", f.get("luhn") == "INVALID", "%s" % f.get("luhn"))
    report("iccid/bad-luhn/check-digit", f.get("check_digit") == "7", f.get("check_digit"))
    # Nothing is a decode error unless the record is not BCD at all.
    rc, f, _ = run(module, "--decode-iccid", "ZZZZ")
    report("iccid/not-hex", rc == 2, "rc=%d" % rc)
    rc, f, _ = run(module, "--decode-iccid", "98")
    report("iccid/short", rc == 1, "rc=%d" % rc)
    return cases


def check_imsi(module, pysim_fns, verbose):
    enc_imsi = pysim_fns[1] if pysim_fns else None
    cases = 0
    for mcc, mnc in (("310", "26"), ("262", "01"), ("460", "00"),
                     ("234", "15"), ("404", "45"), ("208", "10")):
        for msin in ("0123456789", "012345678", "0123456", "1234567890123"):
            imsi = mcc + mnc + msin
            if len(imsi) > 15:
                continue
            ef = imsi_encode(imsi)
            ref = imsi_decode(ef)
            name = "imsi/%s-%s/%d" % (mcc, mnc, len(imsi))
            cases += 1
            report(name + "/reference", ref["imsi"] == imsi, "%s" % ref["imsi"])
            rc, f, out = run(module, "--decode-imsi", ef)
            report(name + "/digits", rc == 0 and f.get("imsi") == imsi,
                   "rc=%d %s" % (rc, out.strip()[:120]))
            report(name + "/length", f.get("length") == str(len(imsi)), f.get("length"))
            report(name + "/mcc", f.get("mcc") == mcc, f.get("mcc"))
            report(name + "/mnc", f.get("mnc_2digit") == mnc, f.get("mnc_2digit"))
            report(name + "/parity", f.get("parity") == ref["parity"],
                   "ours %s clause %s" % (f.get("parity"), ref["parity"]))
            report(name + "/parity-agrees", f.get("parity_agrees") == "yes",
                   f.get("parity_agrees"))
            report(name + "/filler", f.get("filler") == ref["filler"],
                   "ours %s clause %s" % (f.get("filler"), ref["filler"]))
            if enc_imsi is not None:
                theirs = enc_imsi(imsi).lower()
                # enc_imsi counts the parity nibble into its length, and pads
                # a lost nibble back as one extra ff octet for an even count.
                if len(imsi) % 2:
                    same = theirs[:2] == ef[:2] and theirs[2:len(ef)] == ef[2:]
                    report(name + "/pysim-codec", same,
                           "pysim %s ours %s" % (theirs, ef))
                else:
                    # enc_imsi pads an even count to a whole extra octet rather
                    # than to the filler nibble, so its octets are not the same
                    # even though its declared length is -- read by the clause
                    # rule it has to yield the same IMSI.
                    report(name + "/pysim-codec-decodes",
                           imsi_decode(theirs)["imsi"] == imsi
                           and theirs[:2] == ef[:2],
                           "pysim %s -> %s (ours %s)"
                           % (theirs, imsi_decode(theirs)["imsi"], ef))
            if verbose:
                print("ok\t%s\t%s" % (name, imsi))

    # The parity nibble read as a digit: the old shape of the defect, stated
    # as an input the module must refuse rather than misread.
    rc, f, _ = run(module, "--decode-imsi", "13200621436587F9")
    report("imsi/no-parity-refused", rc == 1, "rc=%d %s" % (rc, f.get("imsi")))
    # A length byte of nine is an even digit count at full length.
    ef9 = imsi_encode("31026012345678")
    rc, f, _ = run(module, "--decode-imsi", ef9)
    report("imsi/length-byte-nine", ef9[:2] == "08" and f.get("imsi") == "31026012345678",
           "ef %s -> %s" % (ef9, f.get("imsi")))
    rc, f, _ = run(module, "--decode-imsi", "ZZ")
    report("imsi/not-hex", rc == 2, "rc=%d" % rc)
    rc, f, _ = run(module, "--decode-imsi", "0813")
    report("imsi/short", rc == 1, "rc=%d" % rc)
    return cases


MUTANTS = [
    ("iccid-marker-octet-restored",
     '        digits+="${b:1:1}${b:0:1}"\n',
     '        if (( i == 0 )) && [[ "$b" == 98 ]]; then :; else digits+="${b:1:1}${b:0:1}"; fi\n'),
    ("iccid-filler-left-in",
     '    if [[ "$digits" == *[Ff] ]]; then filler="yes"; digits="${digits%[Ff]}"; fi',
     '    filler="no"'),
    ("iccid-luhn-not-computed",
     '    if sim_luhn_ok "$digits"; then luhn="valid"; else luhn="INVALID"; fi ;;',
     '    luhn="valid" ;;'),
    ("imsi-parity-read-as-digit",
     '    local indicator="${swapped:0:1}" rest="${swapped:1}" parity',
     '    local indicator="9" rest="${swapped}" parity'),
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
        if source.count(old) != 1:
            print("NEGCTL\tSKIP\t%s: anchor appears %d times"
                  % (name, source.count(old)))
            ok = False
            continue
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, os.path.basename(MODULE))
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(source.replace(old, new, 1))
            for link in ("tools", "loot"):
                src = os.path.join(ROOT, link)
                if os.path.isdir(src):
                    try:
                        os.symlink(src, os.path.join(td, link))
                    except OSError:
                        pass
            before = list(MISMATCHES)
            globals()["MISMATCHES"] = []
            globals()["CASES"] = 0
            pysim_fns = pysim()
            check_iccid(target, pysim_fns, verbose)
            check_imsi(target, pysim_fns, verbose)
            caught = bool(MISMATCHES)
            globals()["MISMATCHES"] = before
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

    pysim_fns = pysim()
    check_iccid(MODULE, pysim_fns, args.verbose)
    check_imsi(MODULE, pysim_fns, args.verbose)
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
