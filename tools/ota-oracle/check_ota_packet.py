#!/usr/bin/env python3
"""Differential check for the TS 31.115 §4.2 SMS packet of modules/41_ota_sms.sh.

`--packet-sms` builds the secured packet (CPL, CHL, SPI, KIc, KID, TAR,
CNTR, PCNTR, CC, secured data) and `--parse-packet-sms` is its inverse,
including the CC check. Both were only asserted against the module's own
selftest.

This checker states the packet layout from the clauses and compares the bytes
with pySim's own TS 31.115 encoder (`pySim.ota.OtaDialectSms.encode_cmd`,
pySim/ota.py:549), which is an independent implementation of the same clause;
pySim's `decode_cmd` is the second implementation of the inverse.

TS 102 225 §5.1.1 (SPI octet 1) and TS 31.115 §4.2 (SMS format):

    CPL  2 octets, from CPI to the end of the secured data, counting the pad
    CHL  1 octet, from SPI to the end of the CC/RC/DS field = 13 + sig_len
    SPI  2 octets   KIc 1   KID 1   TAR 3
    CNTR 5 octets   PCNTR 1 (number of padding octets)
    CC   8 octets when SPI b2b1 = 10, absent otherwise
    Secured data, padded to the cipher block size when ciphering

CC (TS 102 225 §5.1.3.1, 3DES): the DES3 CBC-MAC of CPL||CHL||SPI||KIc||KID||
TAR||CNTR||PCNTR||Secured data, taking the last eight octets. Ciphering
(§5.1.2) is 3DES CBC over CNTR||PCNTR||CC||Secured data with a zero IV.

Usage:  python3 tools/ota-oracle/check_ota_packet.py [--negctl] [--verbose]
Exit:   0 all cases agree, 1 a case disagrees, 2 the environment is unusable.
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULE = os.environ.get("OTA_MODULE", os.path.join(ROOT, "modules", "41_ota_sms.sh"))

KIC_KEY = "00112233445566778899AABBCCDDEEFF"
KID_KEY = "0102030405060708090A0B0C0D0E0F10"

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
        if path and path not in sys.path and os.path.isdir(path):
            sys.path.append(path)
    stub = os.environ.get("PYSIM_STUB", "/home/ysl/.ota-oracles/stub")
    if stub and stub not in sys.path and os.path.isdir(stub):
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


def main_cases():
    hdr = "A0A40000023F00"
    return [
        # (tar, counter, SPI hex, KIc, KID, APDU)
        ("000000", 0, "0A00", "15", "25", hdr),
        ("000000", 1, "0A00", "15", "25", "A0B00000023F00"),
        ("010203", 7, "0A00", "15", "25", "A0DA000010" + "AB" * 16),
        ("000000", 0, "0E00", "15", "25", "A0B00000023F00"),
        ("000000", 1, "0E00", "15", "25", "A0B00000023F00"),
        ("000000", 9, "0E00", "15", "25", "A0DA0000" + "CD" * 10),
        ("000000", 0, "0C00", "15", "25", "A0B000000200"),
        ("000000", 3, "1E00", "15", "25", "A0B00000023F00"),
        ("000000", 0, "0E00", "15", "25", "A0"),
        ("000000", 5, "0E00", "15", "25", "A0DA0000" + "EF" * 18),
        ("FFFFFF", 0xFFFFFFFFFF, "0A00", "15", "25", "A0A40000023F00"),
        ("000000", 0, "0800", "15", "25", "A0B00000023F00"),
    ]


def clause_packet(spi_dict, spi_hex, tar, counter, apdu, kic_octet, kid_octet):
    """Assemble the packet straight from TS 102 225 table 1 / TS 31.115 §4.2.

    No CPI and no CHI in the SMS form, so CPL counts from the CHL octet to the
    end of the secured data, and CHL counts SPI..RC/CC/DS.
    """
    from Cryptodome.Cipher import DES3

    rccds = spi_dict["rc_cc_ds"]
    ciphering = bool(spi_dict["ciphering"])
    sig_len = {"no_rc_cc_ds": 0, "cc": 8}.get(rccds)
    if sig_len is None:
        raise ValueError("RC/DS is not built by this module")
    data = apdu
    pad = 0
    if ciphering:
        pad = (8 - (14 + len(data)) % 8) % 8
        data = data + b"\x00" * pad
    chl = 13 + sig_len
    head = (bytes([chl]) + bytes.fromhex(spi_hex) + bytes([kic_octet, kid_octet])
            + bytes.fromhex(tar))
    cntr = counter.to_bytes(5, "big")
    pcntr = bytes([pad])
    cpl = 1 + chl + len(data)
    region = cntr + pcntr
    if sig_len:
        signed = cpl.to_bytes(2, "big") + head + cntr + pcntr + data
        padded = signed + b"\x00" * ((8 - len(signed) % 8) % 8)
        region += DES3.new(bytes.fromhex(KID_KEY), DES3.MODE_CBC,
                           b"\x00" * 8).encrypt(padded)[-8:]
    region += data
    if ciphering:
        region = DES3.new(bytes.fromhex(KIC_KEY), DES3.MODE_CBC,
                          b"\x00" * 8).encrypt(region)
    packet = cpl.to_bytes(2, "big") + head + region
    return packet, cpl, chl, pad, sig_len


def check_build(P, verbose, module=MODULE):
    SPI, OtaKeyset, OtaDialectSms = P
    dlg = OtaDialectSms()
    for tar, counter, spi, kic, kid, apdu in main_cases():
        name = "packet/%s/%d/%s/%d" % (spi, counter, tar, len(apdu) // 2)
        spi_dict = SPI.parse(bytes.fromhex(spi))
        otak = keyset(OtaKeyset, spi_dict, counter)
        want, cpl, chl, pad, sig_len = clause_packet(
            spi_dict, spi, tar, counter, bytes.fromhex(apdu), int(kic, 16),
            int(kid, 16))
        rc, f, out = run(module, ["--packet-sms", tar, str(counter), spi, kic,
                                  kid, apdu],
                         {"OTASM_KIC_KEY": KIC_KEY, "OTASM_KID_KEY": KID_KEY})
        ours = f.get("packet", "")
        report(name + "/hex", rc == 0 and ours == want.hex().upper(),
               "ours %s clause %s (rc=%d %s)"
               % (ours, want.hex().upper(), rc,
                  out.strip().replace("\t", " ")[:110]))
        report(name + "/cpl", f.get("cpl") == str(cpl),
               "ours %s clause %d" % (f.get("cpl"), cpl))
        report(name + "/chl", f.get("chl") == str(chl),
               "ours %s clause %d" % (f.get("chl"), chl))
        report(name + "/pcntr", f.get("pcntr") == "%02X" % pad,
               "ours %s clause %02X" % (f.get("pcntr"), pad))
        report(name + "/cntr", f.get("counter") == "%010X" % counter,
               "ours %s clause %010X" % (f.get("counter"), counter))
        want_cc = None
        if sig_len:
            signed = (cpl.to_bytes(2, "big")
                      + want[2:2 + 8]
                      + counter.to_bytes(5, "big") + bytes([pad])
                      + (bytes.fromhex(apdu)
                         + b"\x00" * ((8 - (14 + len(apdu)) % 8) % 8
                                       if spi_dict["ciphering"] else 0)))
            from Cryptodome.Cipher import DES3
            padded = signed + b"\x00" * ((8 - len(signed) % 8) % 8)
            want_cc = DES3.new(bytes.fromhex(KID_KEY), DES3.MODE_CBC,
                               b"\x00" * 8).encrypt(padded)[-8:].hex().upper()
            got_cc = f.get("cc", "").split("\t")[-1]
            report(name + "/cc", got_cc == want_cc,
                   "ours %s clause %s" % (got_cc, want_cc))
            # The same CC, computed by pySim's signer instead of by hand.
            report(name + "/pysim-cc",
                   otak.auth.sign(signed).hex().upper() == want_cc,
                   "pysim %s clause %s"
                   % (otak.auth.sign(signed).hex().upper(), want_cc))

        # pySim's own encoder. Note it omits the CPL octets when the packet is
        # not ciphered (its decode_cmd always reads them, so encoder and
        # decoder disagree there), which is why the CPL is stripped first.
        try:
            theirs = dlg.encode_cmd(otak, bytes.fromhex(tar), spi_dict,
                                    bytes.fromhex(apdu), remote_format="compact")
            if spi_dict["ciphering"]:
                report(name + "/pysim-hex", theirs.hex().upper() == ours,
                       "pysim %s ours %s" % (theirs.hex().upper(), ours))
            else:
                report(name + "/pysim-hex-no-cpl",
                       theirs.hex().upper() == want.hex().upper()[4:],
                       "pysim %s clause %s"
                       % (theirs.hex().upper(), want.hex().upper()[4:]))
        except Exception as exc:
            report(name + "/pysim-hex", False, "pySim raised %r" % exc)

        if spi_dict["ciphering"]:
            try:
                _, _, d_apdu = dlg.decode_cmd(otak, bytes.fromhex(ours))
                report(name + "/pysim-decode",
                       d_apdu.hex().upper() == apdu.upper(),
                       "pySim got %s want %s" % (d_apdu.hex().upper(),
                                                 apdu.upper()))
            except Exception as exc:
                report(name + "/pysim-decode", False,
                       "pySim decode raised %r" % exc)
        rc, p, pout = run(module, ["--parse-packet-sms", want.hex().upper()],
                          {"OTASM_KIC_KEY": KIC_KEY, "OTASM_KID_KEY": KID_KEY})
        report(name + "/parse-apdu", rc == 0 and p.get("apdu") == apdu.upper(),
               "ours %s want %s (rc=%d)" % (p.get("apdu"), apdu.upper(), rc))
        want_verdict = "verified" if sig_len else "not-present"
        report(name + "/parse-verdict", p.get("cc_verdict") == want_verdict,
               "verdict %s clause %s" % (p.get("cc_verdict"), want_verdict))
        report(name + "/parse-cpl", p.get("cpl") == str(cpl),
               "parse %s clause %d" % (p.get("cpl"), cpl))
        if verbose:
            print("ok\t%s\t%s" % (name, ours))


def check_cc_known_answer(P, verbose, module=MODULE):
    """One CC computed by hand from the clause, independent of both coders."""
    SPI, OtaKeyset, OtaDialectSms = P
    from Cryptodome.Cipher import DES3
    tar, counter, spi, apdu = "000000", 1, "0A00", "A0B00000023F00"
    spi_dict = SPI.parse(bytes.fromhex(spi))
    sig_len = 8
    chl = 13 + sig_len
    data = bytes.fromhex(apdu)
    cpl = 1 + chl + len(data)        # CPI(1) + CHL + secured data
    head = bytes([chl]) + bytes.fromhex(spi) + bytes([0x15, 0x25]) \
        + bytes.fromhex(tar)
    cntr = counter.to_bytes(5, "big")
    pcntr = b"\x00"
    signed = cpl.to_bytes(2, "big") + head + cntr + pcntr + data
    pad = signed + b"\x00" * ((8 - len(signed) % 8) % 8)
    cc = DES3.new(bytes.fromhex(KID_KEY), DES3.MODE_CBC, b"\x00" * 8) \
        .encrypt(pad)[-8:]
    want = (cpl.to_bytes(2, "big") + head + cntr + pcntr + cc + data).hex().upper()
    rc, f, out = run(module, ["--packet-sms", tar, str(counter), spi, "15", "25",
                              apdu],
                     {"OTASM_KIC_KEY": KIC_KEY, "OTASM_KID_KEY": KID_KEY})
    report("cc-vector/hex", rc == 0 and f.get("packet") == want,
           "ours %s clause %s" % (f.get("packet"), want))
    got_cc = f.get("cc", "").split("\t")[-1]
    report("cc-vector/cc", got_cc == cc.hex().upper(),
           "ours %s clause %s" % (got_cc, cc.hex().upper()))
    if verbose:
        print("ok\tcc-vector\t%s" % want)


MUTANTS = [
    ("cc-signed-over-chl",
     "cc=$(otasm_des3_cc \"$kid_key24\" \"$(printf '%04X%s%s%s' \"$cpl\" \"$head\" \"$cntr$pcntr\" \"$data\")\")",
     "cc=$(otasm_des3_cc \"$kid_key24\" \"$(printf '%04X%s%s%s' \"$chl\" \"$head\" \"$cntr$pcntr\" \"$data\")\")"),
    # 14 is CNTR(5) + PCNTR(1) + CC(8); counting from 6 instead is the same
    # modulo 8 and would be a no-op, so the plausible mistake is counting the
    # CC alone.
    ("padding-counted-from-the-cc",
     "pad_octets=$(( (8 - (14 + ${#data} / 2) % 8) % 8 ))",
     "pad_octets=$(( (8 - (8 + ${#data} / 2) % 8) % 8 ))"),
    ("pcntr-outside-cipher",
     'body="${cntr}${pcntr}${cc}${data}"',
     'body="${cntr}${cc}${data}"'),
    ("cpl-drops-the-cpi-octet",
     'local cpl=$(( 1 + chl + ${#data} / 2 ))',
     'local cpl=$(( chl + ${#data} / 2 ))'),
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
            check_build(P, verbose, target)
            check_cc_known_answer(P, verbose, target)
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

    check_cc_known_answer(P, args.verbose)
    check_build(P, args.verbose)
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
