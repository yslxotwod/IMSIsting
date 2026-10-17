#!/usr/bin/env python3
"""Differential check for the Response Packet of modules/41_ota_sms.sh.

`--parse-resp-sms` reads the card's answer to an OTA command: TS 102 225 §5.2
(RPI, RPL, RHI, RHL, TAR, CNTR, PCNTR, status, RC/CC/DS, response data) in the
SMS form of TS 31.115 §4.2, where the packet rides in a three-octet UDH
(02 71 00) and RHI is a null field.

The parse was only asserted against the module's own selftest, which is the
one implementation it could agree with by accident. This checker states the
response packet from the clauses, assembles it with its own 3DES, and compares
what the module prints, field by field. pySim's SMS response decoder
(`pySim.ota.OtaDialectSms.decode_resp`, pySim/ota.py:681) is the second
implementation, and its three 3DES unit vectors are included as known answers.

TS 102 225 §5.2 table 3 and table 4:

    RPI    1 octet   response packet identifier ('02' in CAT-TP, the UDH IE
                     whose value is '00' in the SMS form)
    RPL    variable  from and including RHI to the end of the response data,
                     including any padding octets
    RHI    1 octet   response header identifier (null in the SMS form)
    RHL    variable  from and including TAR to the end of the RC/CC/DS
    TAR    3 octets  copy of the command's TAR
    CNTR   5 octets  copy of the command's counter
    PCNTR  1 octet   number of padding octets at the end of the data
    status 1 octet   table 5
    RC/CC/DS         as many octets as the command's SPI asked for
    data             application response, empty for a status other than '00'

Ciphering (table 4 note 1) covers CNTR..response data; the CC (note 2) is
calculated first, over the Response Packet up to the response data, and in the
SMS form the UDH is part of that input.

Usage:  python3 tools/ota-oracle/check_ota_response.py [--negctl] [--verbose]
Exit:   0 all cases agree, 1 a case disagrees, 2 the environment is unusable.
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULE = os.environ.get("OTA_MODULE", os.path.join(ROOT, "modules", "41_ota_sms.sh"))

# pySim's 3DES keyset (tests/unittests/test_ota.py, Test_SMS_3DES): its unit
# vectors below are computed with these, so a disagreement is visible.
KIC_KEY = os.environ.get("OTA_KIC_KEY", "C21DD66ACAC13CB3BC8B331B24AFB57B")
KID_KEY = os.environ.get("OTA_KID_KEY", "12110C78E678C25408233076AA033615")

UDH = "027100"

CASES = 0
MISMATCHES = []


def report(name, ok, detail=""):
    global CASES
    CASES += 1
    if not ok:
        MISMATCHES.append("%s: %s" % (name, detail))


def run(module, args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    try:
        p = subprocess.run(["bash", module] + args, capture_output=True,
                           text=True, timeout=180, env=e)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, {}, str(exc)
    fields = {}
    for line in p.stdout.splitlines():
        if "\t" in line:
            k, _, v = line.partition("\t")
            fields.setdefault(k, v)
    return p.returncode, fields, p.stdout


def pysim():
    for path in (os.environ.get("PYSIM_PATH"), "/home/ysl/.lte-oracles/pysim"):
        if path and os.path.isdir(path) and path not in sys.path:
            sys.path.append(path)
    stub = os.environ.get("PYSIM_STUB", "/home/ysl/.ota-oracles/stub")
    if stub and os.path.isdir(stub) and stub not in sys.path:
        sys.path.append(stub)
    try:
        from pySim.ota import SPI, OtaKeyset, OtaDialectSms
    except Exception as exc:
        print("SKIP\tpySim not importable: %s" % exc)
        return None
    return SPI, OtaKeyset, OtaDialectSms


def keyset(OtaKeyset, spi_dict, counter):
    return OtaKeyset("triple_des_cbc2", 1, bytes.fromhex(KIC_KEY),
                     "triple_des_cbc2", 2, bytes.fromhex(KID_KEY), counter)


def cases():
    """(SPI hex, TAR, counter, status octet, response data hex)."""
    return [
        ("0601", "B00011", 0, "00", "01612F"),
        ("0601", "B00011", 0, "00", ""),
        ("0609", "B00011", 0, "00", "01612F"),
        ("0619", "B00011", 0, "00", "01612F"),
        ("0619", "B00011", 0, "00", "0850" + "0A0B0C0D" * 4),
        ("0619", "B00011", 0, "00", ""),
        ("0619", "FFFFFF", 0xFFFFFFFFFF, "00", "01612F"),
        ("0609", "010203", 7, "00", "01" + "9000"),
        ("0619", "010203", 7, "00", "01" + "6A82"),
        ("0601", "B00011", 0, "0A", ""),
        ("0609", "B00011", 0, "01", ""),
        ("0619", "B00011", 0, "06", ""),
    ]


def clause_response(SPI, spi_hex, tar, counter, status, data_hex):
    """Assemble the Response Packet from TS 102 225 §5.2 / TS 31.115 §4.2."""
    from Cryptodome.Cipher import DES3

    spi = SPI.parse(bytes.fromhex(spi_hex))
    sig_len = {"no_rc_cc_ds": 0, "cc": 8}.get(spi["por_rc_cc_ds"])
    if sig_len is None:
        raise ValueError("RC/DS responses are not built by this module")
    data = bytes.fromhex(data_hex)
    # CNTR(5) + PCNTR(1) + status(1) + RC/CC/DS + data, all inside the cipher.
    pad = 0
    if spi["por_shall_be_ciphered"]:
        pad = (8 - (7 + sig_len + len(data)) % 8) % 8
    pt = (counter.to_bytes(5, "big") + bytes([pad])
          + bytes([int(status, 16)]))
    data = data + b"\x00" * pad
    rhl = 10 + sig_len
    rpl = 1 + rhl + len(data)
    head = rpl.to_bytes(2, "big") + bytes([rhl]) + bytes.fromhex(tar)
    if sig_len:
        signed = bytes.fromhex(UDH) + head + pt + data
        padded = signed + b"\x00" * ((8 - len(signed) % 8) % 8)
        cc = DES3.new(bytes.fromhex(KID_KEY), DES3.MODE_CBC,
                      b"\x00" * 8).encrypt(padded)[-8:]
    else:
        cc = b""
    body = pt + cc + data
    if spi["por_shall_be_ciphered"]:
        body = DES3.new(bytes.fromhex(KIC_KEY), DES3.MODE_CBC,
                        b"\x00" * 8).encrypt(body)
    return (bytes.fromhex(UDH) + head + body, rpl, rhl, pad, sig_len)


def check_parse(P, verbose, module=MODULE):
    SPI, OtaKeyset, OtaDialectSms = P
    dlg = OtaDialectSms()
    for spi_hex, tar, counter, status, data_hex in cases():
        name = "resp/%s/%s/%d/%s/%d" % (spi_hex, status, counter, tar,
                                        len(data_hex) // 2)
        spi = SPI.parse(bytes.fromhex(spi_hex))
        want, rpl, rhl, pad, sig_len = clause_response(
            SPI, spi_hex, tar, counter, status, data_hex)
        otak = keyset(OtaKeyset, spi, counter)
        env = {"OTASM_KIC_KEY": KIC_KEY, "OTASM_KID_KEY": KID_KEY}
        rc, f, out = run(module, ["--parse-resp-sms", spi_hex,
                                  want.hex().upper()], env)
        report(name + "/rc", rc == 0, "rc=%d %s" % (rc, out.strip()[:110]))
        report(name + "/transport", f.get("transport") == "sms-udh",
               "ours %s" % f.get("transport"))
        for field, value in (("rpl", str(rpl)), ("rhl", str(rhl)),
                             ("tar", tar.upper()),
                             ("cntr", "%010X" % counter),
                             ("pcntr", "%02X" % pad),
                             ("status", status)):
            report("%s/%s" % (name, field), f.get(field) == value,
                   "ours %s clause %s" % (f.get(field), value))
        report(name + "/sig_len", f.get("sig_len") == str(sig_len),
               "ours %s clause %d" % (f.get("sig_len"), sig_len))
        want_verdict = "verified" if sig_len else "not-present"
        report(name + "/cc_verdict", f.get("cc_verdict") == want_verdict,
               "ours %s clause %s" % (f.get("cc_verdict"), want_verdict))
        want_data = data_hex.upper()
        report(name + "/data",
               f.get("additional_response_data") == (want_data or "none"),
               "ours %s clause %s"
               % (f.get("additional_response_data"), want_data or "none"))
        if status == "00" and want_data:
            report(name + "/ncmd", f.get("number_of_commands") ==
                   str(int(want_data[0:2], 16)),
                   "ours %s clause %d" % (f.get("number_of_commands"),
                                          int(want_data[0:2], 16)))
            report(name + "/sw", f.get("last_status_word") == want_data[2:6],
                   "ours %s clause %s" % (f.get("last_status_word"),
                                          want_data[2:6]))
            rest = want_data[6:] or "-"
            report(name + "/last-data",
                   f.get("last_response_data") == rest,
                   "ours %s clause %s" % (f.get("last_response_data"), rest))

        # pySim's own SMS response decoder over the same bytes.
        try:
            res, dec = dlg.decode_resp(otak, spi, want.hex().upper())
            report(name + "/pysim-status",
                   str(res["response_status"]) == status_meaning_key(status),
                   "pysim %s clause %s" % (res["response_status"],
                                           status_meaning_key(status)))
            report(name + "/pysim-rpl", res["rpl"] == rpl,
                   "pysim %s clause %d" % (res["rpl"], rpl))
            report(name + "/pysim-rhl", res["rhl"] == rhl,
                   "pysim %s clause %d" % (res["rhl"], rhl))
            if status == "00" and want_data:
                report(name + "/pysim-sw",
                       dec["last_status_word"].upper() == want_data[2:6],
                       "pysim %s clause %s" % (dec["last_status_word"],
                                               want_data[2:6]))
                report(name + "/pysim-ncmd",
                       dec["number_of_commands"] == int(want_data[0:2], 16),
                       "pysim %s clause %d" % (dec["number_of_commands"],
                                               int(want_data[0:2], 16)))
            else:
                report(name + "/pysim-dec", dec is None,
                       "pysim returned %r" % (dec,))
        except Exception as exc:
            # pySim insists on parsing a CompactRemoteResp whenever the status
            # is por_ok, so an empty one makes it raise. The clause leaves the
            # response data to the application, so that is pySim's gap.
            if status == "00":
                report(name + "/pysim-empty", not want_data,
                       "pySim could not parse an empty response: %r" % exc)
            else:
                report(name + "/pysim", False, "pySim raised %r" % exc)
        if verbose:
            print("ok\t%s\t%s" % (name, want.hex().upper()))


def status_meaning_key(status):
    """pySim's ResponseStatus names, as strings, per TS 102 225 table 5."""
    return {
        "00": "por_ok", "01": "rc_cc_ds_failed", "02": "cntr_low",
        "03": "cntr_high", "04": "cntr_blocked", "05": "ciphering_error",
        "06": "undefined_security_error", "07": "insufficient_memory",
        "08": "more_time_needed", "09": "tar_unknown",
        "0A": "insufficient_security_level",
        "0B": "actual_response_sms_submit",
        "0C": "actual_response_ussd",
    }.get(status, "unknown")


def check_pysim_vectors(P, verbose, module=MODULE):
    """pySim's own 3DES response vectors, parsed by this tree instead."""
    env = {"OTASM_KIC_KEY": KIC_KEY, "OTASM_KID_KEY": KID_KEY}
    vectors = [
        # (SPI hex, TP-UD, status word expected)
        ("0601", "027100000e0ab000110000000000000001612f", "612F"),
        ("0609", "027100001612b000110000000000000055f47118381175fb01612f",
         "612F"),
        ("0619", "027100001c12b000119660ebdb81be189b5e4389e9e7ab2bc0954f963ad869ed7c",
         "612F"),
    ]
    for spi_hex, tpud, sw in vectors:
        rc, f, out = run(module, ["--parse-resp-sms", spi_hex, tpud], env)
        name = "pysim-vector/%s" % spi_hex
        report(name + "/rc", rc == 0, "rc=%d %s" % (rc, out.strip()[:110]))
        report(name + "/status", f.get("status") == "00",
               "status %s" % f.get("status"))
        report(name + "/sw", f.get("last_status_word") == sw,
               "sw %s clause %s" % (f.get("last_status_word"), sw))
        report(name + "/ncmd", f.get("number_of_commands") == "1",
               "number_of_commands %s" % f.get("number_of_commands"))
        want = "not-present" if spi_hex == "0601" else "verified"
        report(name + "/cc", f.get("cc_verdict") == want,
               "cc_verdict %s clause %s" % (f.get("cc_verdict"), want))
        if verbose:
            print("ok\t%s\t%s" % (name, tpud))


MUTANTS = [
    # The UDH is part of the CC in the SMS form (pySim's own comment says so).
    ("udh-left-out-of-the-cc",
     'signed="${udh}${head}${cntr}${pcntr}${status}${data}"',
     'signed="${head}${cntr}${pcntr}${status}${data}"'),
    ("padding-not-stripped",
     'local resp="$data" pad_ok=1\n    if (( pad_octets > 0 )); then',
     'local resp="$data" pad_ok=1\n    if (( pad_octets > 63 )); then'),
    ("rpl-counted-one-short",
     "local after=$(( ${#h} / 2 - 2 ))",
     "local after=$(( ${#h} / 2 - 1 ))"),
    ("status-read-at-the-pcntr",
     'cntr="${body:0:10}"; pcntr="${body:10:2}"; status="${body:12:2}"',
     'cntr="${body:0:10}"; pcntr="${body:10:2}"; status="${body:10:2}"'),
    # The response data starts after the RC/CC/DS, not at the status octet.
    ("data-starts-at-the-cc",
     'cc="${body:14:$(( sig_len * 2 ))}"; data="${body:$(( 14 + sig_len * 2 ))}"',
     'cc="${body:14:$(( sig_len * 2 ))}"; data="${body:14}"'),
]


def negctl(verbose, P):
    ok = True
    source = open(MODULE, encoding="utf-8").read()
    for name, old, new in MUTANTS:
        if old not in source:
            print("NEGCTL\tSKIP\t%s: anchor not found" % name)
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
            check_pysim_vectors(P, verbose, target)
            check_parse(P, verbose, target)
            caught = bool(MISMATCHES)
            if verbose and caught:
                print("negctl\tsaw\t%s" % MISMATCHES[0])
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
    P = pysim()
    if P is None:
        return 2

    check_pysim_vectors(P, args.verbose)
    check_parse(P, args.verbose)
    print("CASES\t%d" % CASES)
    for m in MISMATCHES[:40]:
        print("MISMATCH\t%s" % m)
    print("MISMATCHES\t%d" % len(MISMATCHES))
    if MISMATCHES:
        print("RESULT\tFAIL(%d)" % len(MISMATCHES))
        return 1
    print("RESULT\tPASS")
    if args.negctl:
        return 0 if negctl(args.verbose, P) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
