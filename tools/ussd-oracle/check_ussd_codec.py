#!/usr/bin/env python3
"""Differential check for the GSM 7-bit alphabet and the MMI/SS grammar.

Two modules read and write the same 7-bit default alphabet --
modules/38_ussd.sh (--pack/--unpack/--build) and modules/41_ota_sms.sh
(--tp-ud-build/--tp-ud-read). Both were only asserted against their own
selftest, and they disagreed: one refused 'è', '¥', '_', '€' and every
bracketed character on encode and answered '?' for 26 septets on decode, the
other encoded '\\' as its identity code 92 where the clause puts it behind ESC,
and refused a form feed. This checker states the alphabet from the clause and
makes both modules read it the same way.

TS 23.038 §6.2.1 (the default alphabet): all 128 septets are assigned, so a
decode never has to invent a character -- 0x00 is '@', 0x01 '£', 0x24 '¤',
0x40 '¡', 0x5B 'Ä', 0x7F 'à', and the rest are the identity on printable
ASCII. §6.2.1.1 (the extension table) rides behind ESC (27): '[' is 27,60,
'\\' is 27,47, '€' is 27,101, so those characters take two septets.
§6.1.2.1.1: septet i starts at bit 7*i of the octet string, low bit first --
which is why 'hellohello' packs to the published e8329bfd4697d9ec37.

TS 22.030 §5.3 (the start-string grammar): *SC# and *SC*SI# activate, #SC# and
#SC*SI# deactivate, **SC*SI# registers, ##SC# erases, *#SC# and *#SC*SI#
interrogate, and each form may carry one more *SIA after the SI. The SI-less
activate shape is legal -- *43# is how call waiting is switched on.

Usage:  python3 tools/ussd-oracle/check_ussd_codec.py [--negctl] [--verbose]
Exit:   0 all cases agree, 1 a case disagrees, 2 the environment is unusable.
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
USSD = os.environ.get("USSD_MODULE", os.path.join(ROOT, "modules", "38_ussd.sh"))
OTA = os.environ.get("OTA_MODULE", os.path.join(ROOT, "modules", "41_ota_sms.sh"))

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


# ── the clause's alphabet, stated here independently ─────────────────────
# §6.2.1, position by position. Index == septet value.
BASE = (
    "@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5"
    "\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u001b\u00c6\u00e6\u00df\u00c9"
    " !\"#\u00a4%&'()*+,-./0123456789:;<=>?"
    "\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7"
    "\u00bfabcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0"
)
# §6.2.1.1: extension code -> character, always after ESC (27).
EXT = {0x0A: "\f", 0x14: "^", 0x28: "{", 0x29: "}", 0x2F: "\\",
       0x3C: "[", 0x3D: "~", 0x3E: "]", 0x40: "|", 0x65: "\u20ac"}
EXT_REV = {v: k for k, v in EXT.items()}

assert len(BASE) == 128, len(BASE)


def septets(text):
    """Text -> septet codes, an extension character emitting ESC then its code."""
    out = []
    for ch in text:
        if ch in EXT_REV:
            out += [27, EXT_REV[ch]]
        else:
            out.append(BASE.index(ch))
    return out


def pack(codes):
    """TS 23.038 §6.1.2.1.1: septet i at bit 7*i, low bit first."""
    out = bytearray((len(codes) * 7 + 7) // 8)
    for i, s in enumerate(codes):
        bit = i * 7
        b, sh = bit // 8, bit % 8
        out[b] |= (s << sh) & 0xFF
        if sh > 1:
            out[b + 1] |= s >> (8 - sh)
    return out.hex()


def unpack(hexstr, count=None):
    """Octet string -> text, ESC consuming the next septet."""
    raw = bytes.fromhex(hexstr)
    n = len(raw) * 8 // 7
    if count is not None and count < n:
        n = count
    codes = []
    for i in range(n):
        bit = i * 7
        b, sh = bit // 8, bit % 8
        v = raw[b] >> sh
        if sh > 1:
            v |= raw[b + 1] << (8 - sh)
        codes.append(v & 0x7F)
    out = []
    esc = False
    for c in codes:
        if esc:
            out.append(EXT[c])
            esc = False
        elif c == 27:
            esc = True
        else:
            out.append(BASE[c])
    if esc:
        raise ValueError("dangling ESC")
    return "".join(out)


# ── the 7-bit alphabet, both modules ────────────────────────────────────
PUBLISHED = ("hellohello", "e8329bfd4697d9ec37")


def check_common(verbose, module=None):
    M = module or USSD
    text, want = PUBLISHED
    rc, _, out = run(M, "--pack", text)
    report("kat/ussd-pack", rc == 0 and out.strip() == want,
           "rc=%d %r want %r" % (rc, out.strip(), want))
    rc, _, out = run(OTA, "--tp-ud-build", text)
    report("kat/ota-pack", rc == 0 and out.strip() == want,
           "rc=%d %r want %r" % (rc, out.strip(), want))
    rc, f, out = run(M, "--build", "0F", text)
    report("kat/ussd-build", f.get("message") == "0f" + want, f.get("message"))
    rc, _, out = run(M, "--unpack", want)
    report("kat/ussd-unpack", out.rstrip("\n") == text, repr(out.rstrip("\n")))
    rc, _, out = run(OTA, "--tp-ud-read", want, str(len(text)))
    report("kat/ota-unpack", out.rstrip("\n") == text, repr(out.rstrip("\n")))


def check_alphabet(verbose, module=None):
    M = module or USSD
    # Every assigned septet decodes to the clause's character, in both modules.
    # The controls LF, CR and ESC are left out of the sweep: LF and CR print as
    # themselves but would split the line the check reads, ESC opens the
    # extension table and is covered by the extension cases below.
    sweep = [s for s in range(128) if s not in (0x0A, 0x0D, 0x1B)]
    h = pack(sweep)
    want = "".join(BASE[s] for s in sweep)
    rc, _, out = run(M, "--unpack", h)
    report("decode/ussd-all", rc == 0 and out.rstrip("\n") == want,
           "rc=%d %r" % (rc, out.rstrip("\n")[:80]))
    rc, _, out = run(OTA, "--tp-ud-read", h, str(len(sweep)))
    report("decode/ota-all", rc == 0 and out.rstrip("\n") == want,
           "rc=%d %r" % (rc, out.rstrip("\n")[:80]))

    for s in sweep:
        ch = BASE[s]
        rc, _, out = run(M, "--unpack", pack([s]))
        report("decode/ussd/%02x" % s, out.rstrip("\n") == ch, repr(out.rstrip("\n")))
        rc, _, out = run(M, "--pack", ch)
        report("encode/ussd/%02x" % s, rc == 0 and out.strip() == pack([s]),
               "rc=%d %r want %r" % (rc, out.strip(), pack([s])))
        rc, _, out = run(OTA, "--tp-ud-build", ch)
        report("encode/ota/%02x" % s, rc == 0 and out.strip() == pack([s]),
               "rc=%d %r want %r" % (rc, out.strip(), pack([s])))

    # §6.2.1.1: each extension character is ESC plus its code, one character
    # out, and packs back behind ESC.
    for code, ch in sorted(EXT.items()):
        h = pack([27, code])
        rc, _, out = run(M, "--unpack", h)
        report("ext/ussd-unpack/%02x" % code, out.rstrip("\n") == ch,
               "rc=%d %r" % (rc, out.rstrip("\n")))
        rc, _, out = run(OTA, "--tp-ud-read", h, "2")
        report("ext/ota-unpack/%02x" % code, out.rstrip("\n") == ch,
               "rc=%d %r" % (rc, out.rstrip("\n")))
        rc, _, out = run(M, "--pack", ch)
        report("ext/ussd-pack/%02x" % code, rc == 0 and out.strip() == h,
               "rc=%d %r want %r" % (rc, out.strip(), h))
        rc, _, out = run(OTA, "--tp-ud-build", ch)
        report("ext/ota-pack/%02x" % code, rc == 0 and out.strip() == h,
               "rc=%d %r want %r" % (rc, out.strip(), h))

    # Mixed text keeps the escape in the middle of the string.
    for text in ("a[b", "*#21#", "+15551234", "Cf \u20ac1,20", "1\u00bd"):
        if "\u00bd" in text:      # not in the alphabet: must be refused
            rc, _, _ = run(M, "--pack", text)
            report("encode/ussd-outside/%s" % text, rc == 2, "rc=%d" % rc)
            continue
        want = pack(septets(text))
        rc, _, out = run(M, "--pack", text)
        report("encode/ussd-mixed/%s" % text, rc == 0 and out.strip() == want,
               "rc=%d %r want %r" % (rc, out.strip(), want))
        rc, _, out = run(M, "--unpack", want)
        report("decode/ussd-mixed/%s" % text, out.rstrip("\n") == text,
               repr(out.rstrip("\n")))
        rc, _, out = run(OTA, "--tp-ud-build", text)
        report("encode/ota-mixed/%s" % text, rc == 0 and out.strip() == want,
               "rc=%d %r want %r" % (rc, out.strip(), want))

    # A dangling ESC is an unterminated extension, not a character.
    rc, _, _ = run(M, "--unpack", pack([27]))
    report("decode/ussd-dangling-esc", rc == 2, "rc=%d" % rc)
    rc, _, _ = run(M, "--unpack", "zz")
    report("decode/ussd-bad-hex", rc == 2, "rc=%d" % rc)

    if verbose:
        print("ok\talphabet\t%d septets, %d extension characters"
              % (len(sweep), len(EXT)))


# ── the MMI/SS start strings, TS 22.030 §5.3 ────────────────────────────
MMI = [
    # string, action, code, parameter, sia
    ("*#21#", "interrogate", "21", "", ""),
    ("*#100*1#", "interrogate", "100", "1", ""),
    ("*#06#", "interrogate", "06", "", ""),
    ("*43#", "activate", "43", "", ""),
    ("*67*+15551234#", "activate", "67", "+15551234", ""),
    ("*43*1*5#", "activate", "43", "1", "5"),
    ("**61*+15551234#", "register", "61", "+15551234", ""),
    ("**21*+4917112345678*20#", "register", "21", "+4917112345678", "20"),
    ("#21#", "deactivate", "21", "", ""),
    ("#43*1#", "deactivate", "43", "1", ""),
    ("##21#", "erase", "21", "", ""),
    ("##43*1#", "erase", "43", "1", ""),
]
MMI_BAD = ["hello", "*#abc#", "*##", "", "*#21", "*43*1*2*3#", "#", "**"]


def check_mmi(verbose, module=None):
    M = module or USSD
    for s, action, code, param, sia in MMI:
        rc, f, out = run(M, "--mmi", s)
        report("mmi/%s/rc" % s, rc == 0, "rc=%d %r" % (rc, out.strip()[:80]))
        report("mmi/%s/action" % s, f.get("action") == action, f.get("action"))
        report("mmi/%s/code" % s, f.get("code") == code, f.get("code"))
        report("mmi/%s/parameter" % s, f.get("parameter") == param,
               repr(f.get("parameter")))
        report("mmi/%s/sia" % s, (f.get("sia") or "") == sia,
               repr(f.get("sia")))
        if verbose:
            print("ok\tmmi\t%s" % s)
    # The SI-less activate is the shape that used to be refused; it is legal
    # and is flagged as also reading as a plain MMI/USSD string.
    rc, f, out = run(M, "--mmi", "*43#")
    report("mmi/no-si/note", bool(f.get("note")), repr(out.strip()[:80]))
    for s in MMI_BAD:
        rc, _, _ = run(M, "--mmi", s)
        want = 2 if s == "" else 1
        report("mmi/refused/%r" % s, rc == want, "rc=%d want %d" % (rc, want))


MUTANTS = [
    # The four defects this slice found, each put back into a scratch copy.
    ("backslash-packed-as-identity",
     "        '\\') printf 'E 47';  return 0 ;;",
     "        '\\') printf '92';  return 0 ;;"),
    ("form-feed-not-in-the-table",
     "        $'\\f') printf 'E 10'; return 0 ;;",
     ""),
    ("unpack-drops-the-last-septet",
     "    local nseptets=$(( nbytes * 8 / 7 ))",
     "    local nseptets=$(( nbytes * 8 / 7 - 1 ))"),
    ("activate-requires-an-si",
     "        '*'*)  action=activate;    body=\"${s:1}\" ;;",
     "        '*'*)  [[ \"${s:1}\" == *'*'* ]] || { printf 'ERROR\\tx\\n' >&2; return 1; }; action=activate; body=\"${s:1}\" ;;"),
    ("sia-read-as-part-of-the-parameter",
     '    sia="${f[2]:-}"',
     '    sia=""'),
]


def negctl(verbose):
    ok = True
    source = open(USSD, encoding="utf-8").read()
    for name, old, new in MUTANTS:
        if old not in source:
            print("NEGCTL\tSKIP\t%s: anchor not found in %s"
                  % (name, os.path.basename(USSD)))
            ok = False
            continue
        if source.count(old) != 1:
            print("NEGCTL\tSKIP\t%s: anchor appears %d times"
                  % (name, source.count(old)))
            ok = False
            continue
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, os.path.basename(USSD))
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
            check_common(verbose, target)
            check_alphabet(verbose, target)
            check_mmi(verbose, target)
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

    for m in (USSD, OTA):
        if not os.path.isfile(m):
            print("ERROR\tmodule not found: %s" % m)
            return 2

    check_common(args.verbose)
    check_alphabet(args.verbose)
    check_mmi(args.verbose)
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
