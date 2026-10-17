#!/usr/bin/env python3
"""Differential check for the OTA security coding (SPI, KIc, KID).

The two modules that code these fields -- modules/41_ota_sms.sh (the OTA
binary-SMS module) and modules/16_sim.sh (the card side) -- each derive the
bit positions from the same standard.  Rather than trust either derivaton,
this checker states the field layout independently, from the standard's own
prose, and then compares what each module reports.

Where the layout comes from (ETSI TS 102 225 V7.4.0 and TS 31.115):

  SPI first octet, clause 5.1.1:
    b8 b7 b6  reserved, set to zero and ignored by the RE
    b5 b4     counter behaviour: 00 none | 01 informational |
              10 process iff counter > RE | 11 process iff counter is RE+1
    b3        ciphering: 0 none | 1 applied
    b2 b1     RC/CC/DS: 00 none | 01 RC | 10 CC | 11 DS
  Two prose statements pin this ordering rather than the printed table rows,
  which the PDF interleaves: "SPI1.b2b1" names the command's RC/CC/DS field,
  and "SPI2.b4b3 shall be set to the same value as SPI1.b2b1" names the PoR's.

  SPI second octet:
    b2 b1     PoR mode: 00 none | 01 required | 10 only on error | 11 reserved
    b4 b3     RC/CC/DS applied to the PoR response
    b5        PoR response shall be ciphered
    b6        SMS only (TS 31.115 clause 4.2): 0 PoR via SMS-DELIVER-REPORT,
              1 PoR via SMS-SUBMIT
    b8 b7     reserved

  KIc (clause 5.1.2) and KID for CC (clause 5.1.3.1), one octet each:
    b8..b5    key set number (which provisioned key)
    b4 b3     mode, meaningful when the family is DES: 00 DES-CBC |
              01 3DES outer-CBC two keys | 10 3DES outer-CBC three keys |
              11 DES-ECB
    b2 b1     algorithm family: 00 implicit | 01 DES | 10 reserved |
              11 proprietary

pySim (construct-based, independent implementation) is cross-checked when it
is importable, so a reading of the prose that both this file and pySim supply
still has to agree with what the modules actually print.

Usage:  python3 tools/ota-oracle/check_ota_coding.py [--negctl] [--verbose]
Exit:   0 all cases agree, 1 a case disagrees, 2 the environment is unusable.
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MOD_SMS = os.environ.get("OTA_SMS_MODULE", os.path.join(ROOT, "modules", "41_ota_sms.sh"))
MOD_SIM = os.environ.get("OTA_SIM_MODULE", os.path.join(ROOT, "modules", "16_sim.sh"))

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


# ── the independent statement of the layout ──────────────────────────────
def spi_first(counter, ciphering, rccds):
    return (counter << 3) | (ciphering << 2) | rccds


def spi_second(por, por_rccds, por_ciphering, por_submit):
    # b2b1 PoR, b4b3 PoR RC/CC/DS, b5 PoR ciphered, b6 SMS-only, b8b7 reserved
    return por | (por_rccds << 2) | (por_ciphering << 4) | (por_submit << 5)


def spi_first_fields(o1):
    return ((o1 >> 3) & 0x03, (o1 >> 2) & 0x01, o1 & 0x03)


def spi_second_fields(o2):
    return (o2 & 0x03, (o2 >> 2) & 0x03, (o2 >> 4) & 0x01, (o2 >> 5) & 0x01)


def key_fields(v):
    """(key set, mode, family) from one KIc/KID octet."""
    return ((v >> 4) & 0x0F, (v >> 2) & 0x03, v & 0x03)


# ── pySim cross-check ────────────────────────────────────────────────────
def pysim():
    for path in (os.environ.get("PYSIM_PATH"), "/home/ysl/.lte-oracles/pysim"):
        if path and path not in sys.path and os.path.isdir(path):
            sys.path.append(path)
    stub = os.environ.get("PYSIM_STUB", "/home/ysl/.ota-oracles/stub")
    if stub and stub not in sys.path and os.path.isdir(stub):
        sys.path.append(stub)
    try:
        from pySim.ota import SPI, KIC, KID_CC
        import construct
    except Exception:
        return None
    return SPI, KIC, KID_CC, construct


def pysim_spi(SPI, counter, ciphering, rccds, por=0, por_rccds=0,
              por_ciphering=0, por_submit=0):
    names = ("no_rc_cc_ds", "rc", "cc", "ds")
    counters = ("no_counter", "counter_no_replay_or_seq", "counter_must_be_higher",
                "counter_must_be_lower")
    pors = ("no_por", "por_required", "por_only_when_error")
    val = SPI.build({
        "counter": counters[counter],
        "ciphering": bool(ciphering),
        "rc_cc_ds": names[rccds],
        "por": pors[por],
        "por_rc_cc_ds": names[por_rccds],
        "por_shall_be_ciphered": bool(por_ciphering),
        "por_in_submit": bool(por_submit),
    })
    raw = val if isinstance(val, (bytes, bytearray)) else val.to_bytes()
    return raw.hex().upper()


# ── checks ───────────────────────────────────────────────────────────────
def check_spi_build(SPI):
    for counter in range(4):
        for ciphering in range(2):
            for rccds in range(4):
                want = spi_first(counter, ciphering, rccds)
                rc, f, _ = run(MOD_SMS, "--spi-build", str(rccds), str(ciphering), str(counter))
                got = f.get("spi", "")
                report("sms-spi-build counter=%d cipher=%d rc=%d" % (counter, ciphering, rccds),
                       rc == 0 and got.upper().startswith("%02X" % want),
                       "rc=%d got %r want %02X__" % (rc, got, want))
                if SPI is not None:
                    ps = pysim_spi(SPI, counter, ciphering, rccds)
                    report("sms-spi-build-vs-pysim %d/%d/%d" % (counter, ciphering, rccds),
                           ps.startswith("%02X" % want), "pysim %s spec %02X" % (ps, want))

    # the second octet, one field at a time so a failure names the field
    for por in range(3):
        rc, f, _ = run(MOD_SMS, "--spi-build", "0", "0", "0", str(por), "0", "0", "0")
        want = spi_second(por, 0, 0, 0)
        report("sms-spi2-por=%d" % por, rc == 0 and f.get("spi", "").upper().endswith("%02X" % want),
               "got %r want __%02X" % (f.get("spi"), want))
    for por_rccds in range(4):
        rc, f, _ = run(MOD_SMS, "--spi-build", "0", "0", "0", "0", str(por_rccds), "0", "0")
        want = spi_second(0, por_rccds, 0, 0)
        report("sms-spi2-por_rccds=%d" % por_rccds,
               rc == 0 and f.get("spi", "").upper().endswith("%02X" % want),
               "got %r want __%02X" % (f.get("spi"), want))
    for ciph in range(2):
        rc, f, _ = run(MOD_SMS, "--spi-build", "0", "0", "0", "0", "0", str(ciph), "0")
        want = spi_second(0, 0, ciph, 0)
        report("sms-spi2-ciphering=%d" % ciph,
               rc == 0 and f.get("spi", "").upper().endswith("%02X" % want),
               "got %r want __%02X" % (f.get("spi"), want))
    for submit in range(2):
        rc, f, _ = run(MOD_SMS, "--spi-build", "0", "0", "0", "0", "0", "0", str(submit))
        want = spi_second(0, 0, 0, submit)
        report("sms-spi2-submit=%d" % submit,
               rc == 0 and f.get("spi", "").upper().endswith("%02X" % want),
               "got %r want __%02X" % (f.get("spi"), want))


def check_spi_parse_sms():
    for o1 in range(256):
        want_c, want_ci, want_rc = spi_first_fields(o1)
        rc, f, _ = run(MOD_SMS, "--spi", "%02X00" % o1)
        report("sms-spi-parse o1=%02X" % o1,
               rc == 0 and f.get("rccds") == str(want_rc)
               and f.get("ciphering") == str(want_ci) and f.get("counter_mode") == str(want_c),
               "rc=%d rccds=%s want %d ciphering=%s want %d counter=%s want %d"
               % (rc, f.get("rccds"), want_rc, f.get("ciphering"), want_ci,
                  f.get("counter_mode"), want_c))
    for o2 in range(256):
        want_por, want_rc, want_ci, want_sms = spi_second_fields(o2)
        rc, f, _ = run(MOD_SMS, "--spi", "00%02X" % o2)
        report("sms-spi2-parse o2=%02X" % o2,
               rc == 0 and f.get("por") == str(want_por) and f.get("por_rccds") == str(want_rc)
               and f.get("por_cipher") == str(want_ci) and f.get("por_submit") == str(want_sms),
               "rc=%d por=%s por_rccds=%s por_cipher=%s por_submit=%s want %s"
               % (rc, f.get("por"), f.get("por_rccds"), f.get("por_cipher"),
                  f.get("por_submit"), (want_por, want_rc, want_ci, want_sms)))


def check_spi_parse_sim():
    for o1 in range(0, 256, 3):
        want_c, want_ci, want_rc = spi_first_fields(o1)
        # 16_sim's --spi takes the two octets as one 16-bit decimal
        rc, f, _ = run(MOD_SIM, "--spi", str(o1 << 8))
        report("sim-spi-parse o1=%02X" % o1,
               rc == 0 and f.get("spi_b2b1_rccds") == str(want_rc)
               and f.get("spi_b3_ciphering") == str(want_ci)
               and f.get("spi_b5b4_counter") == str(want_c),
               "rc=%d rccds=%s want %d ciphering=%s want %d counter=%s want %d"
               % (rc, f.get("spi_b2b1_rccds"), want_rc, f.get("spi_b3_ciphering"),
                  want_ci, f.get("spi_b5b4_counter"), want_c))
    for o2 in range(0, 256, 7):
        want_por, want_rc, want_ci, want_sms = spi_second_fields(o2)
        rc, f, _ = run(MOD_SIM, "--spi", str(o2))
        report("sim-spi2-parse o2=%02X" % o2,
               rc == 0 and f.get("spi_b2b1_por") == str(want_por)
               and f.get("spi_b4b3_por_rccds") == str(want_rc)
               and f.get("spi_b5_por_ciphering") == str(want_ci)
               and f.get("spi_b6_por_submit") == str(want_sms),
               "rc=%d por=%s rccds=%s cipher=%s submit=%s want %s"
               % (rc, f.get("spi_b2b1_por"), f.get("spi_b4b3_por_rccds"),
                  f.get("spi_b5_por_ciphering"), f.get("spi_b6_por_submit"),
                  (want_por, want_rc, want_ci, want_sms)))


def check_keys(KIC, KID_CC):
    algos = {0: "implicit", 1: "single_des", 2: "reserved3des_or_aes",
             5: "triple_des_cbc2", 9: "triple_des_cbc3"}
    for v in list(range(0, 256, 5)) + [0x02, 0x05, 0x09, 0x15, 0x41, 0xC1, 0xFF]:
        key_set, mode, family = key_fields(v)
        hexv = "%02X" % v

        rc, f, _ = run(MOD_SMS, "--key", hexv)
        report("sms-key %s" % hexv,
               rc == 0 and f.get("key_set") == str(key_set)
               and f.get("mode") == str(mode) and f.get("family") == str(family),
               "rc=%d key_set=%s want %d mode=%s want %d family=%s want %d"
               % (rc, f.get("key_set"), key_set, f.get("mode"), mode,
                  f.get("family"), family))

        rc, f, _ = run(MOD_SIM, "--ota-key", hexv)
        report("sim-key %s" % hexv,
               rc == 0 and f.get("cipher_key_set") == str(key_set)
               and f.get("cipher_mode") == str(mode)
               and f.get("cipher_family") == str(family),
               "rc=%d key_set=%s want %d mode=%s want %d family=%s want %d"
               % (rc, f.get("cipher_key_set"), key_set, f.get("cipher_mode"), mode,
                  f.get("cipher_family"), family))

        if KIC is not None:
            k = KIC.parse(bytes([v]))
            want_algo = algos.get(v & 0x0F, "unknown")
            got_algo = str(k["algo"])
            # pySim names the low nibble; DES family modes 5 and 9 are 3DES.
            ok = k["key"] == key_set
            if want_algo in ("implicit", "single_des", "triple_des_cbc2", "triple_des_cbc3"):
                ok = ok and got_algo == want_algo
            report("sms-key-vs-pysim %s" % hexv, ok,
                   "pysim key=%s algo=%s, spec key_set=%d family=%d mode=%d"
                   % (k["key"], got_algo, key_set, family, mode))


def run_env(module, args, env):
    """Run a module verb with extra environment, return (rc, fields, stderr)."""
    full = dict(os.environ)
    full.update(env or {})
    try:
        p = subprocess.run(["bash", module] + list(args), capture_output=True,
                           text=True, timeout=120, env=full)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, {}, str(exc)
    fields = {}
    for line in p.stdout.splitlines():
        if "\t" in line:
            k, _, v = line.partition("\t")
            fields.setdefault(k, v)
    return p.returncode, fields, p.stderr


def check_packet_sms(pysim_ok):
    """The secured packet itself, against pySim's encoder, byte for byte.

    A packet that reports a CC and a ciphering flag but carries neither is the
    defect this section exists to catch: the fields are read back out of the
    packet we produced, and the same packet is rebuilt by an implementation
    written by someone else.
    """
    try:
        from pySim.ota import OtaKeyset, OtaDialectSms
    except Exception as exc:
        report("packet-sms/build", False, "pySim not importable: %s" % exc)
        return
    cases = [
        ("apdu9-cc-cipher-2key", "00112233445566778899aabbccddeeff",
         "00112233445566778899aabbccddeeff", 0x0102030405, 2, 1, True, "b00001",
         "801000000c00000000"),
        ("apdu1-cc-cipher-3key", "0123456789abcdeffedcba9876543210",
         "0f1e2d3c4b5a69788796a5b4c3d2e1f0", 0, 2, 1, True, "b00001", "80"),
        ("apdu17-cc-cipher-2key", "00112233445566778899aabbccddeeff",
         "00112233445566778899aabbccddeeff", 255, 2, 1, True, "ffffff",
         "801000000c00000000010203040506070809"),
        ("apdu16-cc-clear-2key", "00112233445566778899aabbccddeeff",
         "0f1e2d3c4b5a69788796a5b4c3d2e1f0", 7, 2, 0, True, "123456",
         "801000000c0000000000000000000000ff"),
        ("apdu5-nocc-cipher-2key", "00112233445566778899aabbccddeeff",
         "0f1e2d3c4b5a69788796a5b4c3d2e1f0", 12, 2, 1, False, "010203", "8010000c00"),
    ]
    for name, kic, kid, cntr, cmode, cipher, cc, tar, apdu in cases:
        otak = OtaKeyset("triple_des_cbc2", 1, bytes.fromhex(kic),
                         "triple_des_cbc2", 1, bytes.fromhex(kid), cntr)
        spi = {"counter": cmode, "ciphering": bool(cipher),
               "rc_cc_ds": "cc" if cc else "no_rc_cc_ds", "por": "no_por",
               "por_rc_cc_ds": "no_rc_cc_ds", "por_shall_be_ciphered": False,
               "por_in_submit": False}
        ref = OtaDialectSms().encode_cmd(otak, bytes.fromhex(tar), spi,
                                         bytes.fromhex(apdu)).hex()
        o1 = (cmode << 3) | (cipher << 2) | (2 if cc else 0)
        env = {"OTASM_KIC_KEY": kic, "OTASM_KID_KEY": kid}
        rc, f, err = run_env(MOD_SMS, ("--packet-sms", tar, str(cntr),
                                       "%02X00" % o1, "15", "15", apdu), env)
        packet = (f.get("packet") or "").strip().lower()
        # pySim's unciphered branch drops the CPL prefix it has just computed
        # (a defect in pySim, not in the clause); ours keeps it, so those cases
        # are compared from the Command Header onwards. The CPL itself is
        # checked against the packet's own length below.
        ours = packet if cipher else packet[4:]
        report("packet-sms/%s" % name, rc == 0 and ours == ref,
               "ours %s pySim %s %s" % (ours or "?", ref, err.strip()))

        rc2, f2, err2 = run_env(MOD_SMS, ("--parse-packet-sms", packet), env)
        report("packet-sms/%s-roundtrip" % name,
               rc2 == 0 and f2.get("apdu") == apdu.lower()
               and f2.get("cc_verdict") in ("verified", "not-present"),
               "apdu %s verdict %s %s" % (f2.get("apdu"), f2.get("cc_verdict"),
                                          err2.strip()))
        report("packet-sms/%s-cpl" % name,
               f2.get("cpl") is not None
               and int(f2.get("cpl", -1)) == int(f2.get("packet_bytes", -2)) - 2,
               "cpl %s packet_bytes %s" % (f2.get("cpl"), f2.get("packet_bytes")))

        if cc and cipher and len(packet) > 30:
            tampered = (packet[:-30]
                        + "%02x" % (int(packet[-30:-28], 16) ^ 0x01)
                        + packet[-28:])
            rc3, f3, _ = run_env(MOD_SMS, ("--parse-packet-sms", tampered), env)
            report("packet-sms/%s-tamper-caught" % name,
                   rc3 != 0 and f3.get("cc_verdict") == "mismatch",
                   "verdict %s rc %d" % (f3.get("cc_verdict"), rc3))

    rc, f, err = run_env(MOD_SMS, ("--packet-sms", "b00001", "1", "1600", "15",
                                   "15", "8010"),
                         {"OTASM_KIC_KEY": "", "OTASM_KID_KEY": ""})
    report("packet-sms/refuses-without-key", rc == 2 and "OTASM_KIC_KEY" in err,
           "rc %d %s" % (rc, err.strip()))


def mutants():
    """Wrong readings that the checker must reject, per module.

    Each tuple is (name, which module, the fixed text, the wrong text). A
    mutant that the checker still passes means the check does not actually
    pin the bit positions.
    """
    sms, sim = "sms", "sim"
    return [
        ("first-octet-read-top-down", sms,
         "counter=$(( (o1>>3)&3 )) cipher=$(( (o1>>2)&1 )) rccds=$(( o1&3 ))",
         "counter=$(( (o1>>3)&3 )) cipher=$(( (o1>>5)&1 )) rccds=$(( (o1>>6)&3 ))"),
        ("first-octet-read-top-down", sim,
         "local rccds=$(( o1 & 0x03 ))\n    local ciphering=$(( (o1 >> 2) & 0x01 ))",
         "local rccds=$(( (o1 >> 6) & 0x03 ))\n    local ciphering=$(( (o1 >> 5) & 0x01 ))"),
        ("key-set-from-low-nibble", sms,
         "local key_set=$(( (val >> 4) & 0x0F ))",
         "local key_set=$(( val & 0x0F ))"),
        ("key-set-from-low-nibble", sim,
         "local keyset=$(( (val >> 4) & 0x0F ))",
         "local keyset=$(( val & 0x0F ))"),
        ("por-second-octet-shifted", sms,
         "local por=$(( o2&3 )) por_rccds=$(( (o2>>2)&3 ))",
         "local por=$(( (o2>>6)&3 )) por_rccds=$(( (o2>>4)&3 ))"),
    ]


def negctl(verbose):
    """Patch scratch copies of the modules and require the checks to fail."""
    ok = True
    for name, arena, old, new in mutants():
        module = MOD_SMS if arena == "sms" else MOD_SIM
        src = open(module, "r", encoding="utf-8", errors="replace").read()
        if old not in src:
            print("NEGCTL\tSKIP\t%s: anchor not found in %s" % (name, os.path.basename(module)))
            ok = False
            continue
        mutated = src.replace(old, new, 1)
        tmp = tempfile.mkdtemp(prefix="ota-negctl-")
        path = os.path.join(tmp, os.path.basename(module))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(mutated)
        env = dict(os.environ)
        env.pop("OTA_SMS_MODULE", None)
        env.pop("OTA_SIM_MODULE", None)
        env["OTA_SMS_MODULE" if arena == "sms" else "OTA_SIM_MODULE"] = path
        p = subprocess.run([sys.executable, os.path.abspath(__file__)],
                           capture_output=True, text=True, env=env)
        caught = p.returncode == 1 and "RESULT\tFAIL" in p.stdout
        print("NEGCTL\t%s\t%s\t%s" % ("CAUGHT" if caught else "MISSED", name,
                                        os.path.basename(module)))
        ok = ok and caught
        if verbose and not caught:
            print(p.stdout[-1200:])
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--negctl", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(MOD_SMS) or not os.path.isfile(MOD_SIM):
        print("ERROR\ta module is missing: %s / %s" % (MOD_SMS, MOD_SIM))
        return 2

    if args.negctl:
        return 0 if negctl(args.verbose) else 1

    py = pysim()
    SPI = KIC = KID_CC = None
    if py is None:
        print("NOTE\tpySim not importable; the spec checks still run")
    else:
        SPI, KIC, KID_CC = py[0], py[1], py[2]
        print("NOTE\tpySim cross-check enabled")
    if KID_CC is None:
        KID_CC = KIC

    check_spi_build(SPI)
    check_spi_parse_sms()
    check_spi_parse_sim()
    check_keys(KIC, KID_CC)
    check_packet_sms(py)

    print("CASES\t%d" % CASES)
    if MISMATCHES:
        for m in MISMATCHES[:40]:
            print("MISMATCH\t%s" % m)
        if len(MISMATCHES) > 40:
            print("MISMATCH\t... and %d more" % (len(MISMATCHES) - 40))
        print("MISMATCHES\t%d" % len(MISMATCHES))
        print("RESULT\tFAIL(%d)" % len(MISMATCHES))
        return 1
    print("MISMATCHES\t0")
    print("RESULT\tPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
