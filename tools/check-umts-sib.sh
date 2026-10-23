#!/bin/bash
# check-umts-sib.sh -- known-answer suite for tools/umts_sib.py
#
# What this proves, and with which referee:
#
#   1. The RRC encodings (MasterInformationBlock, SysInfoType1, SysInfoType3,
#      SysInfoType5 and the SYSTEM INFORMATION container on BCCH-FACH) are
#      compared BIT FOR BIT against pycrate's TS 25.331 ASN.1, in both
#      directions: the value is built here from the ASN.1 by hand, encoded with
#      pycrate's unaligned PER encoder, and the tool's bits must be identical;
#      then the tool's own octets are decoded by pycrate (from_uper) and the
#      decoded IE values are asserted field by field, and the re-encoding of the
#      decoded value must be the tool's bits again.  pycrate lives in
#      /home/ysl/.lte-oracles/venv/bin/python on this machine; the wrapper below
#      finds it, and exits 2 (SKIP, never PASS) when it is absent.
#
#   2. The TS 25.212 FACH transport chain is recomputed here from the clause
#      text with code that has nothing in common with the tool: the CRC by
#      polynomial long division of (block * D^16) by gCRC16, the convolutional
#      coder as a delay line over the D exponents of the octal generators, the
#      rate matching by the closed form of 4.2.7.5 (bits added/removed after
#      input bit m = ceil((m*eminus-1)/eplus)), the second interleaver by
#      filling a real 30-column matrix and reading the permuted columns, and the
#      slot split by slicing.  The 24-bit vector is also cross-checked against
#      tools/umts_bch.py, an independent implementation already in this tree.
#
#   3. tshark 4.2.2 over GSMTAP is the third referee where it can decode the
#      message: sub_type 19 (SysInfoType3), 21 (SysInfoType5), 17 (SysInfoType1),
#      16 (MasterInformationBlock) and 7 (BCCH-FACH, the SYSTEM INFORMATION
#      container).  tshark is optional; if it is missing those checks are
#      reported as skipped, not failed.
#
#   4. A NEGATION CONTROL: four copies of the tool are made with one constant
#      changed each (gCRC16, the rate 1/3 generators, SEG_FIXED_BITS, and the
#      sib-Pos width that pycrate once caught here), and the suite asserts that
#      each mutant DIVERGES from the referee.  An unmodified copy is run through
#      the same path as a no-change control, so a mutant that failed for an
#      unrelated reason (a copy that does not import, a typo in the harness)
#      cannot make the negation control pass.
#
# What it does NOT cover: nothing here exercises tools/umts_sib.py's argument
# parsing beyond the runs listed, and nothing verifies the physical layer below
# the CCTrCH (spreading, scrambling, modulation); tools/umts_bch.py covers
# P-CCPCH spreading for the BCH chain and that is out of scope here.
#
# Exit codes: 0 all checks passed, 1 at least one check failed, 2 SKIP (no
# python3 with pycrate, so the referee this suite depends on is unavailable).
#
# Usage:
#   bash tools/check-umts-sib.sh
#   PYTHON=/path/to/python bash tools/check-umts-sib.sh
#   UMTS_SIB_TOOL=/tmp/mutant.py bash tools/check-umts-sib.sh   # point at a copy

set -u

here=$(cd "$(dirname "$0")" && pwd)
tool=${UMTS_SIB_TOOL:-$here/umts_sib.py}

if [ ! -f "$tool" ]; then
    echo "FAIL t0 no tool at $tool"
    exit 1
fi

python=${PYTHON:-}
if [ -z "$python" ]; then
    for cand in /home/ysl/.lte-oracles/venv/bin/python python3 python; do
        if command -v "$cand" >/dev/null 2>&1 &&
           "$cand" -c 'import pycrate_asn1dir.RRC3G' >/dev/null 2>&1; then
            python=$cand
            break
        fi
    done
fi

if [ -z "$python" ] || ! "$python" -c 'import pycrate_asn1dir.RRC3G' >/dev/null 2>&1
then
    printf 'SKIP\tno python3 with pycrate (pycrate_asn1dir.RRC3G) on this machine\n'
    printf 'SKIP\tinstall pycrate or set PYTHON=/path/to/python; this suite has\n'
    printf 'SKIP\tno ASN.1 referee without it, so it reports SKIP (2), never PASS (0)\n'
    exit 2
fi

exec "$python" - "$tool" <<'PY'
# ---------------------------------------------------------------------------
# the suite
# ---------------------------------------------------------------------------
import binascii
import os
import re
import shutil
import subprocess
import sys
import tempfile

TOOL = os.path.abspath(sys.argv[1])
sys.path.insert(0, os.path.dirname(TOOL))
WORK = tempfile.mkdtemp(prefix="check-umts-sib-")

CHECKS = 0
FAILS = 0
SKIPS = 0
FAILED = []


def chk(name, got, want):
    """One assertion: got must equal want."""
    global CHECKS, FAILS
    CHECKS += 1
    if got == want:
        print("ok %d %s" % (CHECKS, name))
        return True
    FAILS += 1
    FAILED.append(name)
    print("FAIL %d %s -- got %r want %r" % (CHECKS, name, got, want))
    return False


def chk_true(name, cond, detail=""):
    return chk(name + (":" + detail if detail else ""), bool(cond), True)


def skip(name, why):
    global SKIPS
    SKIPS += 1
    print("skip %s -- %s" % (name, why))


def note(text):
    print("note %s" % text)


# --- running the tool ------------------------------------------------------
def run(*args, **kw):
    tool = kw.pop("tool", TOOL)
    p = subprocess.run([sys.executable, tool] + list(args),
                       capture_output=True, text=True)
    return p


def rows_of(p):
    d = {}
    for line in p.stdout.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            d.setdefault(k, []).append(v)
    return d


def one(d, key):
    if key not in d:
        raise KeyError("no %r row in %s" % (key, sorted(d)))
    return d[key][0]


STAGE_RE = re.compile(r"^([0-9a-f]*) bits=(\d+) ref=(.*)$")


def bits_of_hex(h, n):
    """The tool prints each bit string as octets: first bit in the MSB of the
    first octet, zero padding at the end.  Return (octets, bit length)."""
    by = binascii.unhexlify(h)
    return by, n


def tool_bits(d, key="hex", bitskey="bits"):
    return bits_of_hex(one(d, key), int(one(d, bitskey)))


def stage_bits(d, name):
    m = STAGE_RE.match(one(d, "stage:" + name))
    if not m:
        raise KeyError("stage %r is not '<hex> bits=<n> ref=<...>'" % name)
    return bits_of_hex(m.group(1), int(m.group(2)))


# --- pycrate referee ------------------------------------------------------
try:
    from pycrate_asn1dir import RRC3G as RRC3G
    from pycrate_asn1rt.utils import pack_val
except ImportError as exc:
    print("SKIP\tpycrate is not importable here: %s" % exc)
    print("SKIP\tthis suite's ASN.1 referee is pycrate, so it cannot pass")
    sys.exit(2)

IE = RRC3G.InformationElements
C = RRC3G.Class_definitions


def per(typ, val):
    """Encode a value with pycrate's unaligned PER encoder -> (octets, bits)."""
    typ.set_val(val)
    by, bl = pack_val(*typ._to_per())
    return by, bl


def unper(typ, by, bl):
    """Decode the tool's octets with pycrate, return (value, re-encoded bits).
    from_uper takes whole octets; the tool's hex is octet padded, so the
    trailing pad bits are decoded as part of the last component's padding and
    the re-encoding reproduces the exact bit length."""
    typ.from_uper(by)
    val = typ.get_val()
    rby, rbl = pack_val(*typ._to_per())
    return val, (rby, rbl)


def dig(val, *path):
    for p in path:
        if isinstance(p, int):
            val = val[p]
        else:
            val = val[p]
    return val


def bits_of_sib(typ, val):
    return per(typ, val)


def iv(by, bl):
    """Bit string as an integer, for BIT STRING components."""
    return int.from_bytes(by, "big") >> (8 * len(by) - bl)


# --- the ASN.1 values, written by hand from TS 25.331 10.2 ---------------
# Every value below is a translation of the ASN.1 production, not of the
# tool's source: keys in declaration order, an absent OPTIONAL simply omitted,
# a CHOICE as (alternative, value), a BIT STRING as (integer, bit length).

def sib3_a():
    return {"sib4indicator": True,
            "cellIdentity": (0x1234567, 28),
            "cellSelectReselectInfo": {
                "cellSelectQualityMeasure": ("cpich-Ec-N0", {}),
                "modeSpecificInfo": ("fdd", {"s-Intrasearch": 4,
                                             "q-QualMin": -18,
                                             "q-RxlevMin": -32}),
                "q-Hyst-l-S": 2,
                "t-Reselection-S": 1,
                "maxAllowedUL-TX-Power": 24},
            "cellAccessRestriction": {
                "cellBarred": ("notBarred", 0),
                "cellReservedForOperatorUse": "notReserved",
                "cellReservationExtension": "notReserved"}}


def sib3_b():
    return {"sib4indicator": False,
            "cellIdentity": (0x0abcdef, 28),
            "cellSelectReselectInfo": {
                "cellSelectQualityMeasure": ("cpich-Ec-N0", {"q-HYST-2-S": 20}),
                "modeSpecificInfo": ("fdd", {"s-Intrasearch": 4,
                                             "s-Intersearch": 10,
                                             "q-QualMin": -24,
                                             "q-RxlevMin": -58}),
                "q-Hyst-l-S": 20,
                "t-Reselection-S": 31,
                "maxAllowedUL-TX-Power": -50},
            "cellAccessRestriction": {
                "cellBarred": ("barred", {"intraFreqCellReselectionInd": "allowed",
                                          "t-Barred": "s80"}),
                "cellReservedForOperatorUse": "notReserved",
                "cellReservationExtension": "notReserved"}}


def sib1_a():
    return {"cn-CommonGSM-MAP-NAS-SysInfo": bytes([0x08, 0x03]),
            "cn-DomainSysInfoList": [
                {"cn-DomainIdentity": "cs-domain",
                 "cn-Type": ("gsm-MAP", bytes([0x00])),
                 "cn-DRX-CycleLengthCoeff": 6}]}


def sib1_b():
    return {"cn-CommonGSM-MAP-NAS-SysInfo": bytes([0x08, 0x03]),
            "cn-DomainSysInfoList": [
                {"cn-DomainIdentity": "cs-domain",
                 "cn-Type": ("gsm-MAP", bytes([0x00, 0x00])),
                 "cn-DRX-CycleLengthCoeff": 9}]}


def tfs(coding, rm=160, rlc=("sizeType2", 3)):
    return ("commonTransChTFS", {
        "tti": ("tti10", [{"rlc-Size": ("fdd", {"octetModeRLC-SizeInfoType2": rlc}),
                           "numberOfTbSizeList": [("one", 0)],
                           "logicalChannelList": ("allSizes", 0)}]),
        "semistaticTF-Information": {
            "channelCodingType": ("convolutional", coding),
            "rateMatchingAttribute": rm,
            "crc-Size": "crc16"}})


def sccpch(code, fach, pich, tfci=True):
    v = {"secondaryCCPCH-Info": {"modeSpecificInfo": ("fdd", {
            "dummy1": "mayBeUsed",
            "sttd-Indicator": False,
            "sf-AndCodeNumber": ("sf16", code),
            "pilotSymbolExistence": False,
            "tfci-Existence": tfci,
            "positionFixedOrFlexible": "fixed"})},
         "fach-PCH-InformationList": fach}
    if pich:
        v["pich-Info"] = ("fdd", {"channelisationCode256": 16,
                                  "pi-CountPerFrame": "e36",
                                  "sttd-Indicator": False})
    return v


def sib5(a):
    """a: dict of the differences between the two vectors."""
    rlc = a.get("rlc", ("sizeType2", 3))
    rm = a.get("rm", 160)
    coding = a.get("coding", "third")
    tfci = a.get("tfci", True)
    fach0 = [{"transportFormatSet": tfs(coding, rm, rlc),
              "transportChannelIdentity": 3, "ctch-Indicator": False},
             {"transportFormatSet": tfs("half", rm, rlc),
              "transportChannelIdentity": 4, "ctch-Indicator": False}]
    fach1 = [{"transportFormatSet": tfs(coding, rm, rlc),
              "transportChannelIdentity": 6, "ctch-Indicator": True}]
    return {"sib6indicator": a.get("sib6", False),
            "pich-PowerOffset": a.get("pich", -2),
            "modeSpecificInfo": ("fdd", {"aich-PowerOffset": a.get("aich", 0)}),
            "prach-SystemInformationList": [{
                "prach-RACH-Info": {"modeSpecificInfo": ("fdd", {
                    "availableSignatures": (0xffff, 16),
                    "availableSF": "sfpr128",
                    "preambleScramblingCodeWordNumber": 0,
                    "puncturingLimit": "pl0-44",
                    "availableSubChannelNumbers": (0xfff, 12)})},
                "transportChannelIdentity": 1,
                "modeSpecificInfo": ("fdd", {})}],
            "sCCPCH-SystemInformationList": [
                sccpch(1, fach0, True, tfci),
                sccpch(2, fach1, False, tfci)]}


def sib5_a():
    return sib5({})


def sib5_b():
    return sib5({"sib6": True, "pich": 3, "aich": -6, "rm": 200,
                 "rlc": ("sizeType1", 14), "tfci": False})


def mib_a():
    return {"mib-ValueTag": 1,
            "plmn-Type": ("gsm-MAP", {"plmn-Identity": {
                "mcc": [0, 0, 1], "mnc": [0, 1]}}),
            "sibSb-ReferenceList": [
                {"sibSb-Type": ("sysInfoType1", 1),
                 "scheduling": {"scheduling": {"sib-Pos": ("rep8", 0)}}},
                {"sibSb-Type": ("sysInfoType3", 1),
                 "scheduling": {"scheduling": {"sib-Pos": ("rep8", 0)}}},
                {"sibSb-Type": ("sysInfoType5", 1),
                 "scheduling": {"scheduling": {"sib-Pos": ("rep16", 0)}}}]}


def mib_b():
    return {"mib-ValueTag": 8,
            "plmn-Type": ("gsm-MAP", {"plmn-Identity": {
                "mcc": [3, 1, 0], "mnc": [2, 6, 0]}}),
            "sibSb-ReferenceList": [
                {"sibSb-Type": ("sysInfoType1", 2),
                 "scheduling": {"scheduling": {"sib-Pos": ("rep16", 0)}}},
                {"sibSb-Type": ("sysInfoType5", 3),
                 "scheduling": {"scheduling": {"sib-Pos": ("rep32", 0)}}}]}


# --- section 1: the ASN.1 referee ----------------------------------------

CASES = [
    ("sib3-a", ["sib3", "--cell-id", "0x1234567", "--sib4"],
     IE.SysInfoType3, sib3_a(),
     [("cellIdentity", lambda v: v[0], 0x1234567),
      ("cellSelectReselectInfo.modeSpecificInfo", lambda v: v[0], "fdd"),
      ("s-Intrasearch", lambda v: v, 4),
      ("q-QualMin", lambda v: v, -18),
      ("q-RxlevMin", lambda v: v, -32),
      ("q-Hyst-l-S", lambda v: v["q-Hyst-l-S"], 2),
      ("t-Reselection-S", lambda v: v["t-Reselection-S"], 1),
      ("maxAllowedUL-TX-Power", lambda v: v["maxAllowedUL-TX-Power"], 24),
      ("cellBarred", lambda v: v[0], "notBarred"),
      ("cellReservationExtension", lambda v: v, "notReserved")],
     "cellSelectReselectInfo"),
    ("sib3-b", ["sib3", "--cell-id", "0x0abcdef", "--s-inter", "10",
                "--q-hyst-2", "20", "--q-qualmin", "-24", "--q-rxlevmin", "-58",
                "--q-hyst", "20", "--t-resel", "31", "--max-ul", "-50",
                "--barred", "--t-barred", "3"],
     IE.SysInfoType3, sib3_b(),
     [("sib4indicator", lambda v: v, False),
      ("q-HYST-2-S", lambda v: v, 20),
      ("s-Intersearch", lambda v: v, 10),
      ("q-RxlevMin", lambda v: v, -58),
      ("cellBarred", lambda v: v[0], "barred"),
      ("intraFreqCellReselectionInd", lambda v: v, "allowed"),
      ("t-Barred", lambda v: v, "s80")],
     "cellSelectReselectInfo"),
    ("sib1-a", ["sib1"], IE.SysInfoType1, sib1_a(),
     [("cn-CommonGSM-MAP-NAS-SysInfo", lambda v: v, b"\x08\x03"),
      ("cn-DRX-CycleLengthCoeff", lambda v: v, 6)],
     "cn-DomainSysInfoList"),
    ("sib1-b", ["sib1", "--cs-nas", "0000", "--drx", "9"],
     IE.SysInfoType1, sib1_b(),
     [("cs nas", lambda v: v, b"\x00\x00"),
      ("cn-DRX-CycleLengthCoeff", lambda v: v, 9)],
     "cn-DomainSysInfoList"),
    ("sib5-a", ["sib5"], IE.SysInfoType5, sib5_a(),
     [("pich-PowerOffset", lambda v: v, -2),
      ("aich-PowerOffset", lambda v: v[1]["aich-PowerOffset"], 0),
      ("sfpr", lambda v: v, "sfpr128"),
      ("availableSignatures", lambda v: v, (0xffff, 16)),
      ("fach coding", lambda v: v, ("convolutional", "third")),
      ("fach rm", lambda v: v, 160),
      ("fach crc", lambda v: v, "crc16"),
      ("rlc", lambda v: v, ("sizeType2", 3))],
     None),
    ("sib5-b", ["sib5", "--sib6", "--pich-offset", "3", "--aich-offset", "-6",
                "--rm", "200", "--rlc-size", "20", "--tfci", "off"],
     IE.SysInfoType5, sib5_b(),
     [("sib6indicator", lambda v: v, True),
      ("pich-PowerOffset", lambda v: v, 3),
      ("aich-PowerOffset", lambda v: v[1]["aich-PowerOffset"], -6),
      ("rm 200", lambda v: v, 200),
      ("rlc 160 bits", lambda v: v, ("sizeType1", 14))],
     None),
    ("mib-a", ["mib"], IE.MasterInformationBlock, mib_a(),
     [("mib-ValueTag", lambda v: v, 1),
      ("mcc", lambda v: v, [0, 0, 1]),
      ("mnc", lambda v: v, [0, 1]),
      ("ref0", lambda v: v, ("sysInfoType1", 1)),
      ("ref2", lambda v: v, ("sysInfoType5", 1)),
      ("sib-Pos", lambda v: v, ("rep16", 0))],
     None),
    ("mib-b", ["mib", "--value-tag", "8", "--mcc", "310", "--mnc", "260",
               "--schedule", "sib1:2:16", "--schedule", "sib5:3:32"],
     IE.MasterInformationBlock, mib_b(),
     [("mib-ValueTag", lambda v: v, 8),
      ("mcc 310", lambda v: v, [3, 1, 0]),
      ("mnc 260", lambda v: v, [2, 6, 0]),
      ("rep16", lambda v: v, ("rep16", 0))],
     None),
]

# Paths into the decoded dict, per case, for the field assertions above.  The
# lambdas receive the sub-value at that path.
CASE_PATHS = {
    "sib3-a": {"cellIdentity": ("cellIdentity",),
               "cellSelectReselectInfo.modeSpecificInfo":
                   ("cellSelectReselectInfo", "modeSpecificInfo"),
               "s-Intrasearch":
                   ("cellSelectReselectInfo", "modeSpecificInfo"),
               "q-QualMin": ("cellSelectReselectInfo", "modeSpecificInfo"),
               "q-RxlevMin": ("cellSelectReselectInfo", "modeSpecificInfo"),
               "q-Hyst-l-S": ("cellSelectReselectInfo",),
               "t-Reselection-S": ("cellSelectReselectInfo",),
               "maxAllowedUL-TX-Power": ("cellSelectReselectInfo",),
               "cellBarred": ("cellAccessRestriction", "cellBarred"),
               "cellReservationExtension":
                   ("cellAccessRestriction", "cellReservationExtension")},
    "sib3-b": {"sib4indicator": ("sib4indicator",),
               "q-HYST-2-S": ("cellSelectReselectInfo",
                              "cellSelectQualityMeasure"),
               "s-Intersearch": ("cellSelectReselectInfo", "modeSpecificInfo"),
               "q-RxlevMin": ("cellSelectReselectInfo", "modeSpecificInfo"),
               "cellBarred": ("cellAccessRestriction", "cellBarred"),
               "intraFreqCellReselectionInd":
                   ("cellAccessRestriction", "cellBarred"),
               "t-Barred": ("cellAccessRestriction", "cellBarred")},
    "sib1-a": {"cn-CommonGSM-MAP-NAS-SysInfo":
                   ("cn-CommonGSM-MAP-NAS-SysInfo",),
               "cn-DRX-CycleLengthCoeff":
                   ("cn-DomainSysInfoList", 0, "cn-DRX-CycleLengthCoeff")},
    "sib1-b": {"cs nas": ("cn-DomainSysInfoList", 0, "cn-Type"),
               "cn-DRX-CycleLengthCoeff":
                   ("cn-DomainSysInfoList", 0, "cn-DRX-CycleLengthCoeff")},
    "sib5-a": {"pich-PowerOffset": ("pich-PowerOffset",),
               "aich-PowerOffset": ("modeSpecificInfo",),
               "sfpr": ("prach-SystemInformationList", 0, "prach-RACH-Info",
                        "modeSpecificInfo"),
               "availableSignatures": ("prach-SystemInformationList", 0,
                                       "prach-RACH-Info", "modeSpecificInfo"),
               "fach coding": ("sCCPCH-SystemInformationList", 0,
                               "fach-PCH-InformationList", 0,
                               "transportFormatSet"),
               "fach rm": ("sCCPCH-SystemInformationList", 0,
                           "fach-PCH-InformationList", 0, "transportFormatSet"),
               "fach crc": ("sCCPCH-SystemInformationList", 0,
                            "fach-PCH-InformationList", 0,
                            "transportFormatSet"),
               "rlc": ("sCCPCH-SystemInformationList", 0,
                       "fach-PCH-InformationList", 0, "transportFormatSet")},
    "sib5-b": {"sib6indicator": ("sib6indicator",),
               "pich-PowerOffset": ("pich-PowerOffset",),
               "aich-PowerOffset": ("modeSpecificInfo",),
               "rm 200": ("sCCPCH-SystemInformationList", 0,
                          "fach-PCH-InformationList", 0, "transportFormatSet"),
               "rlc 160 bits": ("sCCPCH-SystemInformationList", 0,
                                "fach-PCH-InformationList", 0,
                                "transportFormatSet")},
    "mib-a": {"mib-ValueTag": ("mib-ValueTag",),
              "mcc": ("plmn-Type",),
              "mnc": ("plmn-Type",),
              "ref0": ("sibSb-ReferenceList", 0, "sibSb-Type"),
              "ref2": ("sibSb-ReferenceList", 2, "sibSb-Type"),
              "sib-Pos": ("sibSb-ReferenceList", 2, "scheduling")},
    "mib-b": {"mib-ValueTag": ("mib-ValueTag",),
              "mcc 310": ("plmn-Type",),
              "mnc 260": ("plmn-Type",),
              "rep16": ("sibSb-ReferenceList", 0, "scheduling")},
}

# Sub-paths used by the assertion lambdas above, to reach the leaf value.
LEAF = {
    "sib3-a": {"s-Intrasearch": ("s-Intrasearch",),
               "q-QualMin": ("q-QualMin",),
               "q-RxlevMin": ("q-RxlevMin",),
               "cellReservationExtension": ()},
    "sib3-b": {"q-HYST-2-S": ("q-HYST-2-S",),
               "s-Intersearch": ("s-Intersearch",),
               "q-RxlevMin": ("q-RxlevMin",),
               "intraFreqCellReselectionInd":
                   ("intraFreqCellReselectionInd",),
               "t-Barred": ("t-Barred",)},
    "sib1-a": {},
    "sib1-b": {"cs nas": (1,)},
    "sib5-a": {"sfpr": ("availableSF",),
               "availableSignatures": ("availableSignatures",),
               "fach coding": (1, "semistaticTF-Information",
                               "channelCodingType"),
               "fach rm": (1, "semistaticTF-Information",
                           "rateMatchingAttribute"),
               "fach crc": (1, "semistaticTF-Information", "crc-Size"),
               "rlc": (1, "tti", 1, 0, "rlc-Size", 1,
                       "octetModeRLC-SizeInfoType2")},
    "sib5-b": {"rm 200": (1, "semistaticTF-Information",
                          "rateMatchingAttribute"),
               "rlc 160 bits": (1, "tti", 1, 0, "rlc-Size", 1,
                                "octetModeRLC-SizeInfoType2")},
    "mib-a": {"mcc": (1, "plmn-Identity", "mcc"),
              "mnc": (1, "plmn-Identity", "mnc"),
              "sib-Pos": ("scheduling", "sib-Pos")},
    "mib-b": {"mcc 310": (1, "plmn-Identity", "mcc"),
              "mnc 260": (1, "plmn-Identity", "mnc"),
              "rep16": ("scheduling", "sib-Pos")},
}

GOLD = {}          # case name -> (octets, bits) from the tool, reused later


def walk(v, *path):
    """Descend a pycrate decoded value: a SEQUENCE is a dict, a SEQUENCE OF a
    list, a CHOICE a (alternative, value) tuple.  A string key met against a
    tuple therefore means "the value of the choice's chosen alternative"."""
    for p in path:
        if isinstance(p, int):
            v = v[p]
        elif isinstance(v, tuple):
            v = v[1][p]
        else:
            v = v[p]
    return v


note("referee python %s, tool %s" % (sys.executable, TOOL))

for name, args, typ, val, asserts, _ in CASES:
    p = run(*args)
    if p.returncode != 0:
        chk("%s runs" % name, (p.returncode, p.stderr.strip()[:80]), (0, ""))
        continue
    d = rows_of(p)
    got = tool_bits(d)
    GOLD[name] = got
    want = per(typ, val)
    chk("%s: pycrate encodes the same bits" % name,
        (got[1], got[0].hex()), (want[1], want[0].hex()))
    # decode direction: pycrate decodes the tool's own octets
    val_dec, reenc = unper(typ, got[0], got[1])
    chk("%s: pycrate decodes the tool's octets and re-encodes them"
        % name, (reenc[1], reenc[0].hex()), (got[1], got[0].hex()))
    for label, fn, expect in asserts:
        path = CASE_PATHS[name][label]
        try:
            sub = walk(val_dec, *path)
            leaf = walk(sub, *LEAF[name].get(label, ()))
            gotv = fn(leaf)
        except Exception as exc:            # shape mismatch is a real failure
            chk("%s: decoded %s" % (name, label), "decode path failed: %s" % exc,
                expect)
            continue
        chk("%s: decoded %s" % (name, label), gotv, expect)

# --- section 2: the SYSTEM INFORMATION container -------------------------
def container(alt, payload_alt, payload):
    return {"message": (alt, {"payload": (payload_alt, payload)})}


def container_case(name, args, typ_expect):
    """Encode the message list with the tool and compare every message with a
    pycrate encoding of the same container built from pycrate's own SIB bits."""
    p = run(*args)
    if p.returncode != 0:
        chk("%s runs" % name, (p.returncode, p.stderr.strip()[:80]), (0, ""))
        return None
    d = rows_of(p)
    msgs = []
    for k in sorted(d):
        if re.match(r"^msg\[\d+\]$", k):
            m = re.search(r"combination=(\d+) payload=(\S+) sib=(\S+) bits=(\d+)"
                          r".*hex=([0-9a-f]*)$", d[k][0])
            if not m:
                chk("%s: msg row format" % name, d[k][0], "combination=..")
                return None
            msgs.append((int(m.group(1)), m.group(2), m.group(3),
                         bits_of_hex(m.group(5), int(m.group(4)))))
    return msgs


def sib_hex(bits):
    return bits[0].hex()


S3 = per(IE.SysInfoType3, sib3_a())
S5 = per(IE.SysInfoType5, sib5_a())
chk("pycrate SIB3 is 76 bits", S3[1], 76)
chk("pycrate SIB5 is 274 bits", S5[1], 274)

# 2a: one short SIB -> combination 8, CompleteSIB-List
msgs = container_case("si/completeSIB-List",
                      ["si", "--add", "sib3:%s:%d" % (sib_hex(S3), S3[1])],
                      None)
if msgs:
    chk("si: one message for a 76 bit SIB", len(msgs), 1)
    combo, kind, sib, (by, bl) = msgs[0]
    chk("si: combination 8 is completeSIB-List", (combo, kind, sib),
        (8, "completeSIB-List", "sib3"))
    want = per(C.BCCH_FACH_Message, container(
        "dummy", "completeSIB-List",
        [{"sib-Type": "systemInformationBlockType3",
          "sib-Data-variable": (iv(*S3), S3[1])}]))
    chk("si: completeSIB-List container is bit identical to pycrate",
        (bl, by.hex()), (want[1], want[0].hex()))
    val, reenc = unper(C.BCCH_FACH_Message, by, bl)
    chk("si: pycrate decodes the container's payload alternative",
        val["message"][1]["payload"][0], "completeSIB-List")
    chk("si: pycrate decodes the entry's sib-Type",
        val["message"][1]["payload"][1][0]["sib-Type"],
        "systemInformationBlockType3")
    chk("si: pycrate decodes the entry's SIB length",
        val["message"][1]["payload"][1][0]["sib-Data-variable"][1], 76)

# 2b: a long SIB -> First segment (222 bits) + Last segment short
msgs = container_case("si/segmented",
                      ["si", "--add",
                       "sib5:%s:%d" % (sib_hex(S5), S5[1])],
                      None)
if msgs:
    chk("si: a 274 bit SIB becomes two messages", len(msgs), 2)
    (c0, k0, s0, b0), (c1, k1, s1, b1) = msgs[0], msgs[1]
    chk("si: first message is combination 2 firstSegment",
        (c0, k0, s0), (2, "firstSegment", "sib5"))
    chk("si: second message is combination 4 lastSegmentShort",
        (c1, k1, s1), (4, "lastSegmentShort", "sib5"))
    chk("si: the first message is 237 bits (2 + 5 + 8 + 222)",
        b0[1], 237)
    chk("si: the second message is 75 bits (2 + 5 + 4 + 1 + 8 + 52)",
        b1[1], 75)
    # reassembly per TS 25.331 8.1.1.1.4: the First segment followed by the
    # segment with the next index must be the SIB pycrate encoded
    val0, _ = unper(C.BCCH_FACH_Message, b0[0], b0[1])
    val1, _ = unper(C.BCCH_FACH_Message, b1[0], b1[1])
    seg0 = val0["message"][1]["payload"][1]["sib-Data-fixed"]
    seg1 = val1["message"][1]["payload"][1]["sib-Data-variable"]
    chk("si: pycrate reads a 222 bit SIB-Data-fixed", seg0[1], 222)
    chk("si: pycrate reads a 52 bit SIB-Data-variable", seg1[1], 52)
    chk("si: the two segments reassemble to pycrate's own SIB5 bits",
        (seg0[1] + seg1[1], (seg0[0] << seg1[1]) | seg1[0]),
        (S5[1], iv(*S5)))
    want0 = per(C.BCCH_FACH_Message, container(
        "dummy", "firstSegment",
        {"sib-Type": "systemInformationBlockType5", "seg-Count": 2,
         "sib-Data-fixed": (seg0[0], 222)}))
    chk("si: firstSegment container is bit identical to pycrate",
        (b0[1], b0[0].hex()), (want0[1], want0[0].hex()))
    tail = iv(*S5) & ((1 << 52) - 1)
    want1 = per(C.BCCH_FACH_Message, container(
        "dummy", "lastSegmentShort",
        {"sib-Type": "systemInformationBlockType5", "segmentIndex": 2,
         "sib-Data-variable": (tail, 52)}))
    chk("si: lastSegmentShort container is bit identical to pycrate",
        (b1[1], b1[0].hex()), (want1[1], want1[0].hex()))
    chk("si: pycrate decodes seg-Count",
        val0["message"][1]["payload"][1]["seg-Count"], 2)

# 2c: --pack combine groups complete SIBs into one CompleteSIB-List
S1 = per(IE.SysInfoType1, sib1_a())
msgs = container_case("si/combine",
                      ["si", "--pack", "combine",
                       "--add", "sib3:%s:%d" % (sib_hex(S3), S3[1]),
                       "--add", "sib1:%s:%d" % (sib_hex(S1), S1[1])], None)
if msgs:
    chk("si --pack combine groups two SIBs into one message", len(msgs), 1)
    combo, kind, sib, (by, bl) = msgs[0]
    chk("si --pack combine emits combination 8", (combo, kind, sib),
        (8, "completeSIB-List", "sib3"))
    # 2 + 4 + 4 (and/or) + 2*(5 + 8) + 76 + 39
    chk("si --pack combine: the message is 151 bits", bl, 151)
    want = per(C.BCCH_FACH_Message, container(
        "dummy", "completeSIB-List",
        [{"sib-Type": "systemInformationBlockType3",
          "sib-Data-variable": (iv(*S3), S3[1])},
         {"sib-Type": "systemInformationBlockType1",
          "sib-Data-variable": (iv(*S1), S1[1])}]))
    chk("si --pack combine: the two entry list is bit identical to pycrate",
        (bl, by.hex()), (want[1], want[0].hex()))

# --- section 3: TS 25.212 FACH chain, recomputed from the clause ---------
GCOEF = [(0b10001000000100001 >> (16 - j)) & 1 for j in range(17)]


def get_bits(by, bl):
    """A bit string as text, truncated to the printed length: the tool pads
    each hex row to a whole octet, so hex strings of 300 bit stages differ in
    their last nibble and must be compared as bits."""
    return "".join(format(b, "08b") for b in by)[:bl]


def tb_bits(h, n):
    s = "".join(format(int(c, 16), "04b") for c in h)
    return [int(c) for c in s[:n]]


def bits_text(bs):
    """A list of ints as a bit string, the form the tool prints bits= with."""
    return "".join(str(b) for b in bs)


def crc_ldiv(tb):
    """TS 25.212 4.2.1.1: divide the block shifted left by 16 by gCRC16 with a
    plain polynomial long division over the coefficient list."""
    reg = list(tb) + [0] * 16
    for i in range(len(tb)):
        if reg[i]:
            for j in range(17):
                reg[i + j] ^= GCOEF[j]
    return reg[len(tb):]


def crc_attach_here(tb):
    """TS 25.212 4.2.1.2 appends the parity in the reverse of the remainder
    order (p1 first, ... p16 last), which is what the tree's BCH chain and the
    air captures of this tool both show."""
    return list(tb) + list(reversed(crc_ldiv(tb)))


# D exponents of the generator octals, read left to right off the octal digits:
# 561 = 101 110 001b -> D8+D6+D5+D4+1 ...
TAPS = {2: ((8, 6, 5, 4, 0), (8, 7, 6, 5, 3, 1, 0)),
        3: ((8, 6, 5, 3, 2, 1, 0), (8, 7, 5, 4, 1, 0), (8, 7, 6, 3, 0))}


def conv_here(block, rate):
    """TS 25.212 4.2.3.1 as a delay line: 8 zero tail bits, all-zero start,
    output0, output1[, output2] repeating."""
    x = list(block) + [0] * 8
    out = []
    for n in range(len(x)):
        for taps in TAPS[rate]:
            v = 0
            for k in taps:
                if n - k >= 0:
                    v ^= x[n - k]
            out.append(v)
    return out


def cum(m, eminus, eplus):
    """Number of bits added (+) or removed (-) in the first m input bits of
    TS 25.212 4.2.7.5: the loop leaves 0 < e <= eplus after each bit, so the
    cumulative count is floor((m*eminus-1)/eplus)+1 once m*eminus reaches 1."""
    num = m * eminus - 1
    return 0 if num < 0 else num // eplus + 1


def rm_here(x, ndata):
    """TS 25.212 4.2.7.5: with eini = 1 the counter fires k_m - k_{m-1} times at
    input bit m.  Repetition (Ndata,* >= Xi) copies the bit that many times
    (the repeated bit immediately after the original); puncturing (Ndata,* <
    Xi) drops the bit when the counter fires at it."""
    eplus = 2 * len(x)
    eminus = 2 * abs(ndata - len(x))
    out = []
    for m in range(1, len(x) + 1):
        k = cum(m, eminus, eplus) - cum(m - 1, eminus, eplus)
        if k:
            if ndata < len(x):
                continue               # punctured: the bit does not appear
            out.extend([x[m - 1]] * k)
        out.append(x[m - 1])
    return out


def ilv2_here(u, ndata):
    """TS 25.212 4.2.11: C2 = 30, R2 rows, Table 7 permutation, read column by
    column, the padded tail pruned."""
    P2 = (0, 20, 10, 5, 15, 25, 3, 13, 23, 8, 18, 28, 1, 11, 21, 6, 16, 26, 4,
          14, 24, 19, 9, 29, 12, 2, 7, 22, 27, 17)
    r2 = (len(u) + 29) // 30
    frame = list(u) + [0] * (r2 * 30 - len(u))
    out = []
    for col in P2:
        for row in range(r2):
            idx = row * 30 + col
            if idx < len(u):
                out.append(frame[idx])
    return out


FACH_CASES = [
    ("fach/third", ["fach", "--tb-hex", "123456", "--tb-bits", "24"], 300),
    ("fach/half", ["fach", "--tb-hex", "123456", "--tb-bits", "24",
                   "--coding", "half"], 300),
    ("fach/40bit", ["fach", "--tb-hex", "a1b2c3d4e5", "--tb-bits", "40",
                    "--ndata", "270"], 270),
    ("fach/puncture", ["fach", "--tb-hex", "123456", "--tb-bits", "24",
                       "--ndata", "120"], 120),
]

FACH_GOLD = {}
for name, args, ndata in FACH_CASES:
    rate = 2 if "half" in args else 3
    tb = tb_bits(args[2], int(args[4]))
    p = run(*args)
    if p.returncode != 0:
        chk("%s runs" % name, (p.returncode, p.stderr.strip()[:80]), (0, ""))
        continue
    d = rows_of(p)
    FACH_GOLD[name] = d
    crc = crc_attach_here(tb)
    chk("%s: CRC16 matches a long division of (block * D^16)" % name,
        get_bits(*stage_bits(d, "crc")), bits_text(crc))
    cc = conv_here(crc, rate)
    chk("%s: convolutional code matches a delay line over the D exponents"
        % name, get_bits(*stage_bits(d, "conv")), bits_text(cc))
    chk("%s: rate is 1/%d and Xi = rate*(Ki + 8)" % (name, rate),
        (one(d, "param:rate"), int(one(d, "param:xi"))),
        ("1/%d" % rate, rate * (len(crc) + 8)))
    rm = rm_here(cc, ndata)
    chk("%s: rate matching matches the 4.2.7.5 closed form" % name,
        get_bits(*stage_bits(d, "ratematch")), bits_text(rm))
    chk("%s: rate matching lands on Ndata,* = %d" % (name, ndata),
        stage_bits(d, "ratematch")[1], ndata)
    chk("%s: dN is Ndata,* - Xi" % name,
        int(one(d, "param:dn")), ndata - len(cc))
    il = ilv2_here(rm, ndata)
    chk("%s: second interleaver matches the 30 column matrix" % name,
        get_bits(*stage_bits(d, "ilv2")), bits_text(il))
    per_slot = ndata // 15
    slots_ok = all(get_bits(*stage_bits(d, "slot%02d" % k)) ==
                   bits_text(il[k * per_slot:(k + 1) * per_slot])
                   for k in range(15))
    chk("%s: the 15 slots are consecutive %d bit slices of the interleaved frame"
        % (name, per_slot), slots_ok, True)
    chk("%s: every stage is a bit string of the printed length" % name,
        all(STAGE_RE.match(v) for v in d.get("stage:ilv2", [])), True)

chk("fach: every run prints the tool's limit rows",
    all(len(v.get("limit", [])) >= 8 for v in FACH_GOLD.values()), True)

# the same 24 bit transport block through the tree's BCH chain: the CRC and a
# rate 1/2 convolutional code are the same functions of the same bits
bch = os.path.join(os.path.dirname(TOOL), "umts_bch.py")
if os.path.exists(bch):
    p = subprocess.run([sys.executable, bch, "stages", "--bch-hex", "123456"],
                       capture_output=True, text=True)
    if p.returncode == 0:
        bd = rows_of(p)
        m = STAGE_RE.match(bd["stage:crc"][0])
        chk("cross-tool: tools/umts_bch.py gives the same 40 bit CRC block",
            get_bits(*bits_of_hex(m.group(1), int(m.group(2)))),
            get_bits(*stage_bits(FACH_GOLD["fach/half"], "crc")))
        m = STAGE_RE.match(bd["stage:conv"][0])
        chk("cross-tool: tools/umts_bch.py gives the same rate 1/2 coded block",
            get_bits(*bits_of_hex(m.group(1), int(m.group(2)))),
            get_bits(*stage_bits(FACH_GOLD["fach/half"], "conv")))
    else:
        skip("cross-tool: umts_bch.py stages", "the tool exited %d" % p.returncode)
else:
    skip("cross-tool: umts_bch.py stages", "no tools/umts_bch.py in this tree")

def mstage(d, key):
    """A packer stage row: the key is already the whole row name."""
    m = STAGE_RE.match(d[key][0])
    return bits_of_hex(m.group(1), int(m.group(2)))


# --- section 3b: the packer, SIBs onto the FACH transport ---------------
# `pack` is the verb that was missing: it takes SIBs, builds the SYSTEM
# INFORMATION messages, runs each message through the FACH chain and prints
# the channel-coded frame an S-CCPCH can spread.  Every frame is recomputed
# here from the payload bits with the independent chain above.
PK = run("pack", "--add", "sib1", "--add", "sib3", "--add", "sib5")
chk("pack: exits 0", PK.returncode, 0)
pd = rows_of(PK)
chk("pack: says the transport is BCCH-FACH and not the BCH",
    any("FACH" in r and "BCH" in r for r in pd.get("transport", [])), True)
chk("pack: prints the slot format it packs for",
    one(pd, "slot_format").startswith("0 -- SF=256"), True)
chk("pack: Ndata,* is 15 slots of 20 data bits",
    one(pd, "ndata_star"), "300")
chk("pack: the transport block is an octet count",
    int(one(pd, "tb_bits")) % 8, 0)
n_msgs = int(one(pd, "frames"))
chk("pack: sib5 is segmented into two frames (one TB per TTI)",
    n_msgs, 4)
PAY_RE = re.compile(r"^combination=(\d+) kind=(\S+) sib=(\S+) bits=(\d+) "
                    r"octets=(\d+) pad=(\d+) hex=([0-9a-f]*)$")
kinds = []
for i in range(n_msgs):
    m = PAY_RE.match(one(pd, "msg[%d].payload" % i))
    if not m:
        chk("pack: message %d parses" % i, one(pd, "msg[%d].payload" % i),
            "combination=... kind=... sib=... bits=... hex=...")
        continue
    comb, kind, sib, nbits, nocts, pad, hx = m.groups()
    nbits = int(nbits)
    kinds.append((kind, sib))
    chk("pack: message %d is padded to whole octets" % i,
        (nbits + int(pad)) % 8, 0)
    chk("pack: message %d's hex is its octet count" % i,
        len(hx), 2 * int(nocts))
    tb = tb_bits(hx, nbits) + [0] * int(pad)
    chk("pack: message %d's transport block is the whole padding" % i,
        len(tb) % 8, 0)
    crc = crc_attach_here(tb)
    chk("pack: message %d CRC16 matches a long division" % i,
        get_bits(*mstage(pd, "msg[%d].stage:crc" % i)), bits_text(crc))
    cc = conv_here(crc, 3)
    chk("pack: message %d uses the 1/3 FACH code" % i,
        get_bits(*mstage(pd, "msg[%d].stage:conv" % i)), bits_text(cc))
    rm = rm_here(cc, 300)
    chk("pack: message %d rate matching matches 4.2.7.5" % i,
        get_bits(*mstage(pd, "msg[%d].stage:ratematch" % i)), bits_text(rm))
    il = ilv2_here(rm, 300)
    fh = one(pd, "msg[%d].frame_hex" % i)
    chk("pack: message %d's frame is the clause 4.2.11 output" % i,
        "".join(format(int(c, 16), "04b") for c in fh)[:300], bits_text(il))
    chk("pack: message %d's frame is %d bits" % (i, 300),
        one(pd, "msg[%d].frame_bits" % i), "300")
chk("pack: sib5 is sent as firstSegment then lastSegmentShort",
    [k for k, s2 in kinds if s2 == "sib5"],
    ["firstSegment", "lastSegmentShort"])
chk("pack: sib1 and sib3 are completeSIB-List messages",
    [k for k, s2 in kinds if s2 in ("sib1", "sib3")],
    ["completeSIB-List", "completeSIB-List"])

# the same SIBs through `si` must give the same message octets: the packer
# adds the transport, not a second encoder
SI = run("si", "--add", "sib1", "--add", "sib3", "--add", "sib5",
         "--fach-tb-bits", one(pd, "tb_bits"), "--pack", "one")
sd = rows_of(SI)
chk("pack/si: the message octets are identical",
    [one(pd, "msg[%d].payload" % i).split("hex=")[-1] for i in range(n_msgs)],
    [one(sd, "msg[%d]" % i).split("hex=")[-1] for i in range(n_msgs)])

# and the frame is what the S-CCPCH tool spreads: its referee is
# tools/check-umts-sccpch.sh, so only the argument contract is checked here
scc = os.path.join(os.path.dirname(TOOL), "umts_sccpch.py")
if os.path.exists(scc):
    sp = subprocess.run([sys.executable, scc, "stages", "--frame-hex",
                         one(pd, "msg[0].frame_hex"), "--sf", "256"],
                        capture_output=True, text=True)
    chk("pack/sccpch: a packed frame is a whole S-CCPCH frame",
        (sp.returncode, "sf\t256" in sp.stdout), (0, True))
    sp = subprocess.run([sys.executable, scc, "stages", "--frame-hex",
                         one(pd, "msg[0].frame_hex"), "--sf", "128"],
                        capture_output=True, text=True)
    chk("pack/sccpch: the SF=128 slot format refuses a 300 bit frame",
        sp.returncode, 2)
else:
    skip("pack/sccpch: cross-tool contract", "no tools/umts_sccpch.py")

for name, args in (("refuse SF=64", ["pack", "--sf", "64"]),
                   ("refuse a block that is not octets",
                    ["pack", "--tb-bits", "285"]),
                   ("refuse a block bigger than Ndata,*",
                    ["pack", "--tb-bits", "290"])):
    r = run(*args)
    chk("pack: %s" % name,
        (r.returncode, ("ERROR\t" in r.stdout or "ERROR\t" in r.stderr)),
        (2, True))

# --- section 4: the tool's own contract ---------------------------------
p = run("list")
d = rows_of(p)
chk("list: exits 0", p.returncode, 0)
chk("list: names the BCCH-FACH SYSTEM INFORMATION message",
    any("SYSTEM INFORMATION" in r for r in d.get("tool", [])), True)
chk("list: prints its limits", len(d.get("limit", [])) >= 8,
    True)
LO, HI = 8, 40
chk("list: at least %d limit rows" % LO, len(d.get("limit", [])) >= LO, True)

for verb, args, need in (
        ("sib3", ([]), ("CellIdentity", "Q-RxlevMin", "T-Reselection-S",
                        "ReservedIndicator")),
        ("sib5", ([]), ("PICH-PowerOffset", "AICH-PowerOffset", "SF-PRACH",
                        "PuncturingLimit", "RateMatchingAttribute",
                        "CRC-Size")),
        ("mib", ([]), ("MIB-ValueTag", "PLMN-Type", "MNC", "SegCount",
                       "sib-Pos")),
        ("sib1", ([]), ("NAS-SystemInformationGSM-MAP",
                        "CN-DRX-CycleLengthCoefficient")),
):
    d = rows_of(run(verb, *args))
    refs = "\n".join(d.get("ref", []))
    chk("%s: every encoded field has a ref row citing its type" % verb,
        all(t in refs for t in need), True)
    chk("%s: the ref rows are not empty" % verb,
        all(r.strip() for r in d.get("ref", [])), True)
    chk("%s: at least 10 ref rows" % verb, len(d.get("ref", [])) >= 10, True)
    chk("%s: prints its limits" % verb, len(d.get("limit", [])) >= 5, True)

d = rows_of(run("si", "--add", "sib5:%s:%d" % (sib_hex(S5), S5[1])))
refs = "\n".join(d.get("ref", []))
chk("si: cites the BCCH-FACH message type CHOICE",
    "BCCH-FACH-MessageType" in refs, True)
chk("si: cites the segment productions",
    "SIB-Data-fixed ::= BIT STRING (SIZE (222))" in refs, True)
chk("si: reports the transport block size it fits into",
    int(one(d, "fach_tb_bits")) > 0, True)

# refusals: these must fail loudly rather than emit a plausible bit string
def refuses(name, args, needle):
    p = run(*args)
    out = (p.stderr or "") + (p.stdout or "")
    chk(name, (p.returncode, needle in out), (2, True))


refuses("refuses an RLC size that is not encodable",
        ["sib5", "--rlc-size", "5"], "is below OctetModeRLC-SizeInfoType2")
refuses("refuses a Ndata,* that is not a whole number of slots",
        ["fach", "--tb-hex", "123456", "--tb-bits", "24", "--ndata", "100"],
        "not a multiple of 15 slots")
refuses("refuses a SIB it has no encoder for",
        ["si", "--add", "sib7"], "no default parameters for sib7")
refuses("refuses turbo coding for the FACH",
        ["fach", "--tb-hex", "123456", "--tb-bits", "24", "--coding", "turbo"],
        "turbo")
refuses("refuses an out of range q-RxlevMin",
        ["sib3", "--q-rxlevmin", "-100"], "is outside -58..-13")
refuses("refuses a SIB_REP that is not a power of two",
        ["mib", "--schedule", "sib1:1:3"], "is not one of")

# the tool must stay python3 stdlib only
src = open(TOOL).read()
chk("tool: no numpy import", "import numpy" in src, False)
chk("tool: no scipy import", "import scipy" in src, False)
chk("tool: cites the two specs", ("TS 25.331" in src and "TS 25.212" in src),
    True)

# --- section 5: tshark over GSMTAP (optional referee) --------------------
def pcap(bits, sub, path):
    """One UDP/GSMTAP packet carrying an RRC PDU.

    The GSMTAP header is 4 words: byte 0 version, byte 1 header length in
    words, byte 2 gsmtap.type (12 = UMTS RRC), byte 3 timeslot, bytes 4-5
    ARFCN, byte 6 signal, byte 7 SNR, bytes 8-11 frame number, and with a 4
    word header **byte 12 is gsmtap.rrc_sub_type** (byte 3 is the timeslot:
    putting the sub type there makes tshark decode 'RRC DL-DCCH').  Every sub
    type used below was found by building a one packet pcap and reading
    tshark -V, not guessed:
        7 BCCH-FACH (the SYSTEM INFORMATION container)
       16 MasterInformationBlock       17 SysInfoType1
       19 SysInfoType3                 21 SysInfoType5
    """
    by, bl = bits
    payload = list(by) + [0] * ((bl + 7) // 8 - len(by))
    g = bytearray(16)
    g[0] = 2                      # version 2
    g[1] = 4                      # header length, 32 bit words
    g[2] = 12                     # gsmtap.type = UMTS RRC
    g[3] = 0                      # timeslot
    g[4:6] = (10700).to_bytes(2, "big")   # ARFCN
    g[12] = sub                   # gsmtap.rrc_sub_type
    body = bytes(g) + bytes(payload)
    ip = (b"\x45\x00" + (20 + 8 + len(body)).to_bytes(2, "big") +
          b"\x00\x00\x40\x00\x40\x11\x00\x00" +
          bytes([127, 0, 0, 1]) + bytes([127, 0, 0, 1]))
    udp = (4729).to_bytes(2, "big") + (4729).to_bytes(2, "big") + \
        (8 + len(body)).to_bytes(2, "big") + b"\x00\x00"
    frame = (b"\xff" * 6 + b"\x00" * 6 + b"\x08\x00" + ip + udp + body)
    hdr = (0xa1b2c3d4).to_bytes(4, "big") + (2).to_bytes(2, "big") + \
        (4).to_bytes(2, "big") + b"\x00" * 8 + (65535).to_bytes(4, "big") + \
        (1).to_bytes(4, "big")
    sec = len(frame).to_bytes(4, "big")
    open(path, "wb").write(hdr + b"\x00" * 8 + sec + sec + frame)


def tshark_v(bits, sub):
    out = os.path.join(WORK, "x.pcap")
    pcap(bits, sub, out)
    p = subprocess.run(["tshark", "-r", out, "-d", "udp.port==4729,gsmtap",
                        "-V"], capture_output=True, text=True)
    return p.stdout + p.stderr


HAVE_TSHARK = shutil.which("tshark") is not None
if not HAVE_TSHARK:
    skip("tshark referee", "tshark is not installed")
else:
    ver = subprocess.run(["tshark", "-v"], capture_output=True,
                         text=True).stdout.splitlines()[0]
    note("tshark: %s" % ver)

    def tchk(name, sub, bits, want, absent=()):
        text = tshark_v(bits, sub)
        chk("tshark sub %d: %s" % (sub, name),
            [w for w in want if w not in text], [])
        for a in absent:
            chk("tshark sub %d: no %r" % (sub, a), a in text, False)

    tchk("SysInfoType3 decodes", 19, GOLD["sib3-a"],
         ["SysInfoType3", "sib4indicator: True", "cellIdentity: 12345670",
          "cellSelectQualityMeasure: cpich-Ec-N0 (0)", "modeSpecificInfo: fdd (0)",
          "s-Intrasearch: 4", "q-QualMin: -18", "q-RxlevMin: -32",
          "q-Hyst-l-S: 2", "t-Reselection-S: 1", "maxAllowedUL-TX-Power: 24",
          "cellBarred: notBarred (1)",
          "cellReservedForOperatorUse: notReserved (1)",
          "cellReservationExtension: notReserved (1)"],
         absent=("[Malformed Packet: RRC]",))
    tchk("SysInfoType5 decodes", 21, GOLD["sib5-a"],
         ["SysInfoType5", "sib6indicator: False", "pich-PowerOffset: -2",
          "aich-PowerOffset: 0", "availableSF: sfpr128 (2)",
          "puncturingLimit: pl0-44 (1)", "availableSubChannelNumbers: fff0",
          "sf-AndCodeNumber: sf16 (2)", "channelisationCode256: 16",
          "pi-CountPerFrame: e36 (1)", "rateMatchingAttribute: 160",
          "crc-Size: crc16 (3)", "convolutional: third (1)",
          "convolutional: half (0)", "ctch-Indicator: True",
          "octetModeRLC-SizeInfoType2: sizeType2 (1)"],
         absent=("[Malformed Packet: RRC]",))
    tchk("SysInfoType1 decodes", 17, GOLD["sib1-a"],
         ["SysInfoType1", "cn-CommonGSM-MAP-NAS-SysInfo: 0803",
          "Location Area Code (LAC): 0x0803 (2051)",
          "cn-DomainIdentity: cs-domain (0)", "cn-Type: gsm-MAP (0)",
          "T3212: 0"])
    # the SIB1 vector above ends in tshark's NAS dissector, not in RRC: with a
    # two octet CS domain NAS payload the RRC tree closes without a malformed
    # packet, which is what shows the RRC layout itself is correct
    p = run("sib1", "--cs-nas", "0000")
    if p.returncode == 0:
        d = rows_of(p)
        text = tshark_v(tool_bits(d), 17)
        chk("tshark sub 17: the RRC tree closes with a two octet NAS payload",
            "[Malformed Packet: RRC]" in text, False)
        chk("tshark sub 17: the two octet NAS payload is decoded",
            "cn-CommonGSM-MAP-NAS-SysInfo: 0803" in text, True)
    tchk("MasterInformationBlock decodes", 16, GOLD["mib-a"],
         ["MasterInformationBlock", "mib-ValueTag: 1",
          "plmn-Type: gsm-MAP (0)", "Mobile Country Code (MCC): Unknown (001)",
          "sibSb-ReferenceList: 3 items",
          "sibSb-Type: sysInfoType1 (0)", "sibSb-Type: sysInfoType3 (2)",
          "sibSb-Type: sysInfoType5 (4)", "sib-Pos: rep8 (1)",
          "sib-Pos: rep16 (2)"],
         absent=("[Malformed Packet: RRC]",))

    # the container: first segment and last segment short of a SIB5
    d = rows_of(run("si", "--add", "sib5:%s:%d" % (sib_hex(S5), S5[1])))
    h0 = re.search(r"hex=([0-9a-f]+)$", one(d, "msg[0]")).group(1)
    h1 = re.search(r"hex=([0-9a-f]+)$", one(d, "msg[1]")).group(1)
    b0 = int(re.search(r"bits=(\d+)", one(d, "msg[0]")).group(1))
    b1 = int(re.search(r"bits=(\d+)", one(d, "msg[1]")).group(1))
    text = tshark_v(bits_of_hex(h0, b0), 7)
    chk("tshark sub 7: the first segment decodes",
        [w for w in ("BCCH-FACH-Message", "payload: firstSegment (1)",
                     "sib-Type: systemInformationBlockType5 (5)",
                     "seg-Count: 2", "bit length 222")
         if w not in text], [])
    text = tshark_v(bits_of_hex(h1, b1), 7)
    chk("tshark sub 7: the last segment decodes",
        [w for w in ("payload: lastSegmentShort (3)",
                     "sib-Type: systemInformationBlockType5 (5)",
                     "segmentIndex: 2", "bit length 52")
         if w not in text], [])
    # documented referee limitation: tshark and pycrate both name BCCH-FACH
    # alternative 0 "dummy" (PDU-definitions.SystemInformation-FACH), while the
    # TS 25.331 v6.4.0 text calls it systemInformation.  The bits are identical.
    text = tshark_v(bits_of_hex(h0, b0), 7)
    chk("tshark sub 7: the container alternative is named dummy, not "
        "systemInformation", "message: dummy (0)" in text, True)

# --- section 6: negation control ---------------------------------------
def mutant(old, new, label):
    src = open(TOOL).read()
    if src.count(old) != 1:
        chk("negation control: the tool still contains the anchor for %r"
            % label, src.count(old), 1)
        return None
    path = os.path.join(WORK, "mutant-%s.py" % label)
    open(path, "w").write(src.replace(old, new))
    return path


def neg(name, before_args, old, new, label, gold, key=None):
    m = mutant(old, new, label)
    if m is None:
        return
    p = run(*before_args, tool=m)
    if p.returncode != 0:
        chk("negation %s: the mutant still runs" % name,
            (p.returncode, p.stderr.strip()[:80]), (0, ""))
        return
    d = rows_of(p)
    got = stage_bits(d, key)[0].hex() if key else tool_bits(d)[0].hex()
    chk("negation %s: the wrong constant makes the output diverge from the "
        "referee" % name, got != gold, True)


def gold_stage(name, stage):
    return stage_bits(FACH_GOLD[name], stage)[0].hex()


neg("gCRC16", ["fach", "--tb-hex", "123456", "--tb-bits", "24"],
    "GCRC16 = 0b10001000000100001", "GCRC16 = 0b10001000000100011", "gcrc",
    gold_stage("fach/third", "crc"), key="crc")
neg("rate 1/3 generators", ["fach", "--tb-hex", "123456", "--tb-bits", "24"],
    "3: (0o557, 0o663, 0o711)", "3: (0o561, 0o663, 0o711)", "poly",
    gold_stage("fach/third", "conv"), key="conv")
neg("sib-Pos width", ["mib"],
    "0, (rep // 2) - 1", "0, (rep // 4) - 1", "sibpos",
    GOLD["mib-a"][0].hex())
def seg_rows(tool):
    """Every message of the segmented SIB5 as (bit length, hex)."""
    p = run("si", "--add", "sib5:%s:%d" % (sib_hex(S5), S5[1]), tool=tool)
    d = rows_of(p)
    out = []
    for k in sorted(d):
        if re.match(r"^msg\[\d+\]$", k):
            m = re.search(r"bits=(\d+).*hex=([0-9a-f]+)$", d[k][0])
            out.append((int(m.group(1)), m.group(2)))
    return out


m = mutant("SEG_FIXED_BITS = 222", "SEG_FIXED_BITS = 221", "seg2")
if m is not None:
    chk("negation SEG_FIXED_BITS: a 221 bit SIB-Data-fixed diverges",
        seg_rows(m) != seg_rows(TOOL), True)

# no-change control: an untouched copy through the same path still matches, so
# the mutants above cannot be passing because "a copy of the tool" is broken
plain = os.path.join(WORK, "unmodified.py")
shutil.copyfile(TOOL, plain)
p = run("fach", "--tb-hex", "123456", "--tb-bits", "24", tool=plain)
d = rows_of(p)
chk("control: an unmodified copy of the tool still matches the CRC referee",
    stage_bits(d, "crc")[0].hex(), gold_stage("fach/third", "crc"))
p = run("mib", tool=plain)
chk("control: an unmodified copy of the tool still matches pycrate's MIB",
    tool_bits(rows_of(p))[0].hex(), GOLD["mib-a"][0].hex())
chk("control: an unmodified copy still emits the same SIB5 segments",
    seg_rows(plain), seg_rows(TOOL))

# --- summary -----------------------------------------------------------
print()
print("CHECKED %d\tFAILED %d\tSKIPPED %d" % (CHECKS, FAILS, SKIPS))
if FAILS:
    for name in FAILED:
        print("FAILED\t%s" % name)
    print("RESULT FAIL(%d)" % FAILS)
    print("WORK\t%s" % WORK)
    sys.exit(1)
print("RESULT PASS")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(0)
PY
