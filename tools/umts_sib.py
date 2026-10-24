#!/usr/bin/env python3
"""umts_sib.py -- RRC SYSTEM INFORMATION on BCCH-FACH, SIB1/SIB3/SIB5, and the FACH chain.

What this is
------------
The missing middle of this tree's 3G cell broadcast chain: the RRC
SYSTEM INFORMATION message that carries SIB1/SIB3/SIB5 on a FACH transport
channel, the SIB bodies themselves, and the TS 25.212 transport chain that
turns one such message into the bits of a FACH transport block.

Specifications and where each constant comes from
-------------------------------------------------
TS 25.331 v6.4.0 (RRC, local copy /tmp/ts331.txt), unaligned PER per X.691:
  10.2.1     ASN.1 of RRC PDUs; clause 12.1 says the basic production is
             UNALIGNED PER, so nothing in this tool is octet aligned.
  8.1.1.1.3  segmentation and concatenation: the SYSTEM INFORMATION message
             carries First/Subsequent/Last/Complete segments, one SEG_COUNT in
             the First segment header, one segment index in Subsequent/Last.
  10.2.48    the SYSTEM INFORMATION message table (segment combinations 1..11).
  10.2.1     MasterInformationBlock, SystemInformation-FACH,
             FirstSegment/SubsequentSegment/LastSegment/LastSegmentShort,
             CompleteSIB/CompleteSIBshort, and every IE used below.
  11         constants: maxSIBperMsg = 16, maxSIB = 32, maxSIB-FACH = 8,
             maxFACHPCH = 8, maxPRACH = 16, maxSCCPCH = 16, maxTF = 32,
             MaxTF = 32, maxAC = 16, maxCNdomains = 4.
  12.1       padding: the RRC PDU is padded with zero bits to the lower layer
             size constraint; a receiver accepts any padding, so a SIB payload
             may be zero padded and the rest of a fixed segment filled with
             zeros.  Every hex this tool prints is right padded with zeros to a
             whole octet ("pad" row), which is the octet string that goes on
             the air and into GSMTAP.

TS 25.212 v6.4.0 (multiplexing and channel coding, local copy /tmp/t.txt):
  4.2.1.1    gCRC16(D) = D16 + D12 + D5 + 1
  4.2.1.2    parity b_ik = p_im(Li+1-(k-Ai)), i.e. appended p16..p1
  4.2.3.1    convolutional coding, K = 9, rates 1/2 (G0=561, G1=753) and
             1/3 (G0=557, G1=663, G2=711), 8 zero tail bits, all-zero start
  4.2.3      Table 1: BCH/PCH conv 1/2; CPCH,DCH,DSCH,FACH conv 1/3 or 1/2
             and turbo 1/3 -- so the FACH rate is a TFS attribute
             (SIB5 CommonTransChTFS channelCodingType), not a constant; this
             tool therefore takes --coding third|half and refuses turbo.
  4.2.7.2    Ndata,* = P*15*(Ndata1+Ndata2); 4.2.13.7 P = 1 for FACH/PCH
  4.2.7.2.2.2 eini = 1, eplus = 2*Xi, eminus = 2*|dN| (conv, flexible)
  4.2.7.2.1.3 eini = 1, eplus = 2*Nmax, eminus = 2*|dN| (conv, fixed); with
             one transport format Nmax = Xi so both subclauses coincide
  4.2.7.5    rate matching pattern determination, verbatim loop below
  4.2.11     2nd interleaving, C2 = 30, Table 7 inter-column permutation
  4.2.12.2   bits to slots in ascending k

Usage: tools/umts_sib.py <verb> [options]   (see `list` for all verbs)
Exit:  0 built, 1 could not build, 2 usage error or refusal.
"""

import argparse
import sys

# ---------------------------------------------------------------------------
# TS 25.331 v6.4.0 clause 11 constants
# ---------------------------------------------------------------------------
MAX_SIB_PER_MSG = 16      # maxSIBperMsg: complete SIBs per SYSTEM INFORMATION
MAX_SIB = 32              # maxSIB: references in a SIB/SIBSb reference list
MAX_SIB_FACH = 8          # maxSIB-FACH: references to SIBs on the FACH
MAX_FACH_PCH = 8          # maxFACHPCH: FACHs and PCHs mapped on one S-CCPCH
MAX_PRACH = 16            # maxPRACH: PRACHs in a cell
MAX_SCCPCH = 16           # maxSCCPCH: S-CCPCHs in a cell
MAX_TF = 32               # MaxTF: transport formats in one transport format set
MAX_AC = 16               # maxAC: access classes
MAX_CN_DOMAINS = 4        # maxCNdomains: CN domains in SIB1

# ---------------------------------------------------------------------------
# TS 25.331 segment sizes (clause 10.2.1 ASN.1)
# ---------------------------------------------------------------------------
SEG_FIXED_BITS = 222      # SIB-Data-fixed ::= BIT STRING (SIZE (222))
SEG_VAR_MAX_BITS = 214    # SIB-Data-variable ::= BIT STRING (SIZE (1..214))
COMPLETE_FIXED_BITS = 226 # CompleteSIB sib-Data-fixed ::= BIT STRING (SIZE (226))
COMPLETE_MIN_LONG = 215   # clause 8.1.1.1.3 combination 10: "One Complete of
                          # size 215 to 226" -- below that a CompleteSIBshort
                          # in a CompleteSIB-List is used (combination 8)

# ---------------------------------------------------------------------------
# TS 25.212 v6.4.0 transport chain constants
# ---------------------------------------------------------------------------
CRC_BITS = 16
GCRC16 = 0b10001000000100001          # gCRC16(D) = D16 + D12 + D5 + 1
CONV_K = 9
CONV_POLY = {2: (0o561, 0o753),       # rate 1/2: G0, G1
             3: (0o557, 0o663, 0o711)}  # rate 1/3: G0, G1, G2
TAIL_BITS = 8
C2 = 30                               # 2nd interleaver columns, 4.2.11
# Table 7 of TS 25.212 4.2.11, verbatim
P2 = (0, 20, 10, 5, 15, 25, 3, 13, 23, 8, 18, 28, 1, 11, 21, 6, 16, 26, 4,
      14, 24, 19, 9, 29, 12, 2, 7, 22, 27, 17)
FACH_SLOTS = 15                       # slots per radio frame, 4.2.12.2

# ---------------------------------------------------------------------------
# Every limit this tool knows about, printed as `limit` rows by every verb.
# The tree prefers an honest refusal over a plausible fiction.
# ---------------------------------------------------------------------------
LIMITS = [
    ("tshark-referee",
     "the tool makes no claim of external verification.  Only "
     "tools/check-umts-sib.sh compares these bits with an independent decoder "
     "(tshark 4.2.2 over GSMTAP) and it reports what tshark did and did not "
     "decode; round trips through this file prove nothing."),
    ("sib5-neighbour-list",
     "SysInfoType5 (TS 25.331 10.2.1) has no frequency information and no "
     "neighbour list at all: it carries the common physical channels of the "
     "cell's own FDD carrier (PICH/AICH/PRACH/S-CCPCH + FACH/PCH transport "
     "formats).  The inter-frequency neighbour list with UARFCN lives in SIB11/"
     "SIB12 (measurement control), and SIB5bis only replaces SIB5 on Band IV. "
     "Nothing inter-frequency can be encoded here because nothing "
     "inter-frequency is in SIB5."),
    ("sib-scheduling",
     "this tool encodes SIB bodies and the SYSTEM INFORMATION message, not the "
     "MIB-to-SB1-to-SIB reference chain of clause 8.1.1.1.1: the MIB verb "
     "schedules SIBs (and optionally SB1/SB2) with SchedulingInformation, but "
     "nothing here checks that the schedule is consistent with what is sent."),
    ("fach-rate-matching-tfs",
     "one transport format per FACH.  A CCTrCH whose FACH has several "
     "transport formats needs Nmax = max_l N^TTI for TS 25.212 4.2.7.2.1.3 and "
     "the rate matching pattern would differ; with the single format this tool "
     "encodes, Nmax = Xi and the fixed (4.2.7.2.1.3) and flexible "
     "(4.2.7.2.2.2) parameter derivations give identical eini/eplus/eminus."),
    ("fach-ndata",
     "Ndata,* is not a constant: TS 25.212 4.2.7.2 says Ndata,* = "
     "P*15*(Ndata1+Ndata2) and Ndata1+Ndata2 follows from the S-CCPCH "
     "spreading factor in TS 25.211 5.3.3.1, which is a local copy this tree "
     "does not have.  --ndata is therefore an input (default 300 = 15 slots * "
     "20 bits, the SF=16 S-CCPCH this tree assumes) and the tool only checks "
     "that it is a multiple of 15."),
    ("fach-turbo",
     "turbo coding (TS 25.212 4.2.3.2, rate 1/3) is allowed for the FACH by "
     "Table 1 and is refused here: --coding only accepts third and half."),
    ("mib-on-fach",
     "TS 25.331 8.1.1.1.3 allows First/Subsequent/Last segments of a master "
     "information block, so `si` will carry MIB segments, but in a cell that "
     "broadcasts a BCH the MIB rides on the BCH (8.1.1.1.2) and the BCCH-FACH "
     "carries the SIBs (plus SB1/SB2 when the cell uses scheduling blocks)."),
    ("fixed-segment-padding",
     "a First/Subsequent/Last segment is 222 bits of data and CompleteSIB is "
     "226 bits; when the payload is shorter the tool pads with zero bits and "
     "says how many in the `pad` row.  TS 25.331 12.1 makes any padding "
     "acceptable to a receiver, so a real network may pad differently and the "
     "trailing zero bits of those segments are not a known answer."),
    ("sib-optional-ies",
     "only the IEs a camper needs are encoded.  Every OPTIONAL or DEFAULT field "
     "that is not encoded is set to its absent bit and named in a `ref` row "
     "(presence bit = 0), never silently dropped: a wrong presence bit moves "
     "every following bit.  The IEs listed in the command's `refused` rows are "
     "not reachable through the flags at all."),
]


def _die(rc, msg, why):
    sys.stderr.write("ERROR\t%s\n" % msg)
    if why:
        sys.stderr.write("WHY\t%s\n" % why)
    raise SystemExit(rc)


def _emit(rows):
    out = sys.stdout
    for k, v in rows:
        out.write("%s\t%s\n" % (k, v))


def _iw(lo, hi):
    """Bits needed for a constrained whole number lo..hi (X.691 10.5)."""
    span = hi - lo + 1
    if span < 1:
        return 0
    w = 0
    while (1 << w) < span:
        w += 1
    return w


def _bits_int(v, width):
    if width <= 0:
        return ""
    if v < 0 or v >= (1 << width):
        _die(1, "internal: %d does not fit in %d bits" % (v, width), "")
    return format(v, "0%db" % width)


def _bits_str(bits):
    """Bits as a string of '0'/'1'; accepts a bit string or a list of ints."""
    if isinstance(bits, str):
        return bits
    return "".join("1" if b else "0" for b in bits)


def _bits_hex(bits):
    """Right pad to a whole octet and print as hex (TS 25.331 12.1 padding)."""
    s = _bits_str(bits)
    pad = (-len(s)) % 8
    if not s:
        return ""
    v = int(s + "0" * pad, 2)
    return "%0*x" % ((len(s) + pad) // 4, v)


def _parse_int(s, what):
    try:
        if isinstance(s, int):
            return s
        t = s.strip()
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 10)
    except (TypeError, ValueError):
        _die(2, "not an integer: %r" % (s,), "--%s takes a decimal or 0x hex" % what)


class Enc(object):
    """Unaligned PER bit writer that records one `ref` row per field."""

    def __init__(self):
        self.parts = []
        self.n = 0
        self.refs = []

    def bits(self):
        return "".join(self.parts)

    def raw(self, name, bits, ref):
        self.parts.append(bits)
        self.n += len(bits)
        self.refs.append("%s -> %s (%d bits)  [%s]" % (name, bits or "-", len(bits), ref))
        return bits

    def field(self, name, value, lo, hi, ref, note=""):
        w = _iw(lo, hi)
        if not (lo <= value <= hi):
            _die(2, "%s = %d is outside %d..%d" % (name, value, lo, hi),
                 "%s%s" % (ref, ("; " + note) if note else ""))
        b = _bits_int(value - lo, w)
        self.parts.append(b)
        self.n += w
        self.refs.append("%s = %d -> %s (%d bit%s, constrained %d..%d)  [%s%s]"
                         % (name, value, b or "-", w, "" if w == 1 else "s", lo, hi,
                            ref, ("; " + note) if note else ""))
        return b

    def enum(self, name, index, count, ref, note=""):
        w = _iw(0, count - 1)
        b = _bits_int(index, w)
        self.parts.append(b)
        self.n += w
        self.refs.append("%s = %d -> %s (%d bit%s, %d alternatives)  [%s%s]"
                         % (name, index, b or "-", w, "" if w == 1 else "s", count,
                            ref, ("; " + note) if note else ""))
        return b

    def flag(self, name, value, ref):
        b = "1" if value else "0"
        self.parts.append(b)
        self.n += 1
        self.refs.append("%s = %s -> %s (1 bit, BOOLEAN)  [%s]"
                         % (name, "TRUE" if value else "FALSE", b, ref))
        return b

    def opt(self, name, present, ref):
        """One OPTIONAL/DEFAULT presence bit.  X.691 11.5: all of them come
        before any field value, in declaration order."""
        b = "1" if present else "0"
        self.parts.append(b)
        self.n += 1
        self.refs.append("%s presence = %d -> %s (1 bit)  [%s%s]"
                         % (name, 1 if present else 0, b, ref,
                            "" if present else ", absent"))
        return b

    def octets(self, name, data, lo, hi, ref):
        """OCTET STRING (SIZE (lo..hi)): constrained length then 8 bits each.
        No octet alignment in unaligned PER."""
        if not (lo <= len(data) <= hi):
            _die(2, "%s has %d octets, needs %d..%d" % (name, len(data), lo, hi), ref)
        b = ""
        if lo != hi:
            b += self.field(name + ".length", len(data), lo, hi, ref)
        for i, x in enumerate(data):
            b += self.raw("%s[%d]" % (name, i), _bits_int(x & 0xFF, 8), ref)
        return b

    def digits(self, name, s, lo, hi, ref):
        if not (lo <= len(s) <= hi):
            _die(2, "%s has %d digits %r, needs %d..%d" % (name, len(s), s, lo, hi), ref)
        if lo != hi:
            self.field(name + ".length", len(s), lo, hi, ref)
        for i, ch in enumerate(s):
            if not ch.isdigit():
                _die(2, "%s digit %r is not a decimal digit" % (name, ch), ref)
            self.field("%s[%d]" % (name, i), int(ch), 0, 9, "Digit ::= INTEGER (0..9)")


# ---------------------------------------------------------------------------
# SIB type enumerations, verbatim order from TS 25.331 10.2.1
# ---------------------------------------------------------------------------
# SIB-Type ::= ENUMERATED {...}  (5 bits)
SIB_TYPE = [
    "masterInformationBlock", "systemInformationBlockType1",
    "systemInformationBlockType2", "systemInformationBlockType3",
    "systemInformationBlockType4", "systemInformationBlockType5",
    "systemInformationBlockType6", "systemInformationBlockType7",
    "systemInformationBlockType8", "systemInformationBlockType9",
    "systemInformationBlockType10", "systemInformationBlockType11",
    "systemInformationBlockType12", "systemInformationBlockType13",
    "systemInformationBlockType13-1", "systemInformationBlockType13-2",
    "systemInformationBlockType13-3", "systemInformationBlockType13-4",
    "systemInformationBlockType14", "systemInformationBlockType15",
    "systemInformationBlockType15-1", "systemInformationBlockType15-2",
    "systemInformationBlockType15-3", "systemInformationBlockType16",
    "systemInformationBlockType17", "systemInformationBlockType15-4",
    "systemInformationBlockType18", "schedulingBlock1", "schedulingBlock2",
    "systemInformationBlockType15-5", "systemInformationBlockType5bis", "spare1",
]

# SIBSb-TypeAndTag ::= CHOICE {...}  (5 bits) -> (name, value tag kind)
SIBSB_TAG = [
    ("sysInfoType1", "plmn"), ("sysInfoType2", "cell"), ("sysInfoType3", "cell"),
    ("sysInfoType4", "cell"), ("sysInfoType5", "cell"), ("sysInfoType6", "cell"),
    ("sysInfoType7", None), ("sysInfoType8", "cell"), ("sysInfoType9", None),
    ("sysInfoType10", None), ("sysInfoType11", "cell"), ("sysInfoType12", "cell"),
    ("sysInfoType13", "cell"), ("sysInfoType13-1", "cell"),
    ("sysInfoType13-2", "cell"), ("sysInfoType13-3", "cell"),
    ("sysInfoType13-4", "cell"), ("sysInfoType14", None),
    ("sysInfoType15", "cell"), ("sysInfoType16", "predefined"),
    ("sysInfoType17", None), ("sysInfoTypeSB1", "cell"),
    ("sysInfoTypeSB2", "cell"), ("sysInfoType15-1", "cell"),
    ("sysInfoType15-2", "siboccur"), ("sysInfoType15-3", "siboccur"),
    ("sysInfoType15-4", "cell"), ("sysInfoType18", "cell"),
    ("sysInfoType15-5", "cell"), ("sysInfoType5bis", "cell"),
    ("spare2", None), ("spare1", None),
]

# SIB type aliases accepted on the command line, in SIB-Type index order.
SIB_ALIAS = {
    "mib": 0, "sib1": 1, "sib2": 2, "sib3": 3, "sib4": 4, "sib5": 5, "sib6": 6,
    "sib7": 7, "sib8": 8, "sib9": 9, "sib10": 10, "sib11": 11, "sib12": 12,
    "sib13": 13, "sib14": 18, "sib15": 19, "sib16": 23, "sib17": 24,
    "sib18": 26, "sib5bis": 30, "sb1": 27, "sb2": 28,
}

# SIBSb-TypeAndTag index by alias, for the MIB reference list.
SIBSB_ALIAS = {
    "mib": None, "sib1": 0, "sib2": 1, "sib3": 2, "sib4": 3, "sib5": 4,
    "sib6": 5, "sib7": 6, "sib8": 7, "sib9": 8, "sib10": 9, "sib11": 10,
    "sib12": 11, "sib13": 12, "sib14": 17, "sib15": 18, "sib16": 19,
    "sib17": 20, "sib18": 27, "sib5bis": 29, "sb1": 21, "sb2": 22,
}


# ---------------------------------------------------------------------------
# Encoders: SysInfoType1 / SysInfoType3 / SysInfoType5 / MasterInformationBlock
# ---------------------------------------------------------------------------
def enc_plmn_identity(e, p):
    """PLMN-Identity ::= SEQUENCE { mcc MCC, mnc MNC } (TS 25.331 10.3.1.11)."""
    e.digits("mcc", p["mcc"], 3, 3, "MCC ::= SEQUENCE (SIZE (3)) OF Digit")
    e.digits("mnc", p["mnc"], 2, 3, "MNC ::= SEQUENCE (SIZE (2..3)) OF Digit")


def enc_sib1(p):
    """SysInfoType1: the core network part of the broadcast (TS 25.331 10.2.1)."""
    e = Enc()
    R = "SysInfoType1"
    # preamble: three OPTIONALs, declaration order
    e.opt("ue-ConnTimersAndConstants", False, R + ": ue-ConnTimersAndConstants OPTIONAL")
    e.opt("ue-IdleTimersAndConstants", False, R + ": ue-IdleTimersAndConstants OPTIONAL")
    e.opt("v3a0NonCriticalExtensions", False, R + ": v3a0NonCriticalExtensions OPTIONAL")
    e.octets("cn-CommonGSM-MAP-NAS-SysInfo", p["nas"], 1, 8,
             "NAS-SystemInformationGSM-MAP ::= OCTET STRING (SIZE (1..8))")
    e.field("cn-DomainSysInfoList.length", len(p["domains"]), 1, MAX_CN_DOMAINS,
            "CN-DomainSysInfoList ::= SEQUENCE (SIZE (1..maxCNdomains)) OF CN-DomainSysInfo")
    for d in p["domains"]:
        e.enum("cn-DomainIdentity", 0 if d["domain"] == "cs" else 1, 2,
               "CN-DomainIdentity ::= ENUMERATED {cs-domain, ps-domain}")
        e.enum("cn-Type", 0, 2, "CN-Type ::= CHOICE {gsm-MAP, ansi-41} (gsm-MAP = 0)")
        e.octets("cn-Type.gsm-MAP", d["nas"], 1, 8,
                 "NAS-SystemInformationGSM-MAP ::= OCTET STRING (SIZE (1..8))")
        e.field("cn-DRX-CycleLengthCoeff", d["drx"], 6, 9,
                "CN-DRX-CycleLengthCoefficient ::= INTEGER (6..9)")
    return e


def enc_sib3(p):
    """SysInfoType3: cell identity, selection/reselection, access restriction."""
    e = Enc()
    R = "SysInfoType3"
    e.opt("v4b0NonCriticalExtensions", False, R + ": v4b0NonCriticalExtensions OPTIONAL")
    e.flag("sib4indicator", p["sib4"], R + ": sib4indicator BOOLEAN")
    e.raw("cellIdentity", _bits_int(p["cell_id"], 28),
          "CellIdentity ::= BIT STRING (SIZE (28)) (TS 25.331 10.3.2.3)")

    # CellSelectReselectInfoSIB-3-4 ::= SEQUENCE { mappingInfo OPTIONAL,
    #   cellSelectQualityMeasure CHOICE, modeSpecificInfo CHOICE,
    #   q-Hyst-l-S, t-Reselection-S, hcs-ServingCellInformation OPTIONAL,
    #   maxAllowedUL-TX-Power }
    R2 = "CellSelectReselectInfoSIB-3-4"
    e.opt("cellSelectReselectInfo.mappingInfo", False, R2 + ": mappingInfo OPTIONAL")
    e.opt("cellSelectReselectInfo.hcs-ServingCellInformation", False,
          R2 + ": hcs-ServingCellInformation OPTIONAL")
    ecno = p["quality"] == "ecno"
    e.enum("cellSelectQualityMeasure", 0 if ecno else 1, 2,
           R2 + ": CHOICE {cpich-Ec-N0, cpich-RSCP} (fdd quality measure)")
    if ecno:
        e.opt("cpich-Ec-N0.q-HYST-2-S", p["q_hyst_2"] is not None,
              "CellSelectQualityMeasure.cpich-Ec-N0: q-HYST-2-S OPTIONAL")
        if p["q_hyst_2"] is not None:
            e.field("q-HYST-2-S", p["q_hyst_2"], 0, 20, "Q-Hyst-S ::= INTEGER (0..20)",
                    note="actual = IE*2 = %d dB" % (p["q_hyst_2"] * 2))
    # modeSpecificInfo CHOICE {fdd, tdd}, then the fdd SEQUENCE preamble
    e.enum("cellSelectReselectInfo.modeSpecificInfo", 0, 2,
           R2 + ": modeSpecificInfo CHOICE {fdd, tdd}")
    R3 = "CellSelectReselectInfoSIB-3-4.modeSpecificInfo.fdd"
    # X.691 11.5: the fdd SEQUENCE's four presence bits form one preamble that
    # precedes every component value -- they are NOT interleaved with the values.
    for name, val in (("s-Intrasearch", p["s_intra"]),
                      ("s-Intersearch", p["s_inter"]),
                      ("s-SearchHCS", p["s_hcs"]),
                      ("rat-List", None)):
        e.opt(name, val is not None, R3 + ": %s OPTIONAL" % name)
    if p["s_intra"] is not None:
        e.field("s-Intrasearch", p["s_intra"], -16, 10,
                "S-SearchQual ::= INTEGER (-16..10)",
                note="actual = IE*2 = %d dB" % (p["s_intra"] * 2))
    if p["s_inter"] is not None:
        e.field("s-Intersearch", p["s_inter"], -16, 10,
                "S-SearchQual ::= INTEGER (-16..10)",
                note="actual = IE*2 = %d dB" % (p["s_inter"] * 2))
    if p["s_hcs"] is not None:
        e.field("s-SearchHCS", p["s_hcs"], -53, 45,
                "S-SearchRXLEV ::= INTEGER (-53..45)",
                note="actual = IE*2+1 = %d dB" % (p["s_hcs"] * 2 + 1))
    e.field("q-QualMin", p["q_qualmin"], -24, 0,
            "Q-QualMin ::= INTEGER (-24..0)", note="dB, actual = IE value")
    e.field("q-RxlevMin", p["q_rxlevmin"], -58, -13,
            "Q-RxlevMin ::= INTEGER (-58..-13)", note="actual = IE*2+1 = %d dBm"
            % (p["q_rxlevmin"] * 2 + 1))
    e.field("q-Hyst-l-S", p["q_hyst"], 0, 20, "Q-Hyst-S ::= INTEGER (0..20)",
            note="actual = IE*2 = %d dB" % (p["q_hyst"] * 2))
    e.field("t-Reselection-S", p["t_resel"], 0, 31,
            "T-Reselection-S ::= INTEGER (0..31)", note="seconds")
    e.field("maxAllowedUL-TX-Power", p["max_ul"], -50, 33,
            "MaxAllowedUL-TX-Power ::= INTEGER (-50..33)", note="dBm")

    # CellAccessRestriction ::= SEQUENCE { cellBarred, cellReservedForOperatorUse,
    #   cellReservationExtension, accessClassBarredList OPTIONAL }
    R4 = "CellAccessRestriction"
    e.opt("accessClassBarredList", p["acb_list"] is not None,
          R4 + ": AccessClassBarredList OPTIONAL")
    if p["barred"]:
        e.enum("cellBarred", 0, 2, R4 + ": CellBarred ::= CHOICE {barred, notBarred}")
        e.enum("intraFreqCellReselectionInd", 0, 2,
               "AllowedIndicator ::= ENUMERATED {allowed, notAllowed}")
        e.enum("t-Barred", p["t_barred"], 8,
               "T-Barred ::= ENUMERATED {s10,s20,s40,s80,s160,s320,s640,s1280}")
    else:
        e.enum("cellBarred", 1, 2, R4 + ": CellBarred ::= CHOICE {barred, notBarred}")
    # ReservedIndicator ::= ENUMERATED {reserved, notReserved} -- notReserved = 1
    e.enum("cellReservedForOperatorUse", 0 if p["reserved"] else 1, 2,
           "ReservedIndicator ::= ENUMERATED {reserved, notReserved}")
    e.enum("cellReservationExtension", 0 if p["reserved"] else 1, 2,
           "ReservedIndicator ::= ENUMERATED {reserved, notReserved}")
    if p["acb_list"] is not None:
        # AccessClassBarredList ::= SEQUENCE (SIZE (maxAC)) OF AccessClassBarred
        # -- fixed size, so no length determinant, maxAC bits, AC15..AC0.
        e.raw("accessClassBarredList", p["acb_list"],
              "AccessClassBarredList ::= SEQUENCE (SIZE (16)) OF AccessClassBarred "
              "(barred = 0, notBarred = 1, AC15 first)")
    return e


def enc_transport_format_set(e, tfs, ref):
    """TransportFormatSet with one common transport format (TS 25.331 10.2.1)."""
    e.enum("transportFormatSet", 1, 2,
           ref + ": TransportFormatSet ::= CHOICE {dedicatedTransChTFS, commonTransChTFS}")
    e.enum("tti", tfs["tti_index"], 5,
           "CommonTransChTFS: tti CHOICE {tti10, tti20, tti40, tti80, dynamic}")
    e.field("tf.length", 1, 1, MAX_TF,
            "CommonDynamicTF-InfoList ::= SEQUENCE (SIZE (1..maxTF)) OF CommonDynamicTF-Info",
            note="one transport format")
    e.enum("rlc-Size", 0, 2, "CommonDynamicTF-Info: rlc-Size CHOICE {fdd, tdd}")
    size_type = tfs["rlc_size_type"]
    e.enum("octetModeRLC-SizeInfoType2", size_type, 3,
           "OctetModeRLC-SizeInfoType2 ::= CHOICE {sizeType1, sizeType2, sizeType3}")
    lo, hi = ((0, 31), (0, 63), (0, 56))[size_type]
    e.field("octetModeRLC-SizeInfoType2.value", tfs["rlc_size_ie"], lo, hi,
            "OctetModeRLC-SizeInfoType2: actual = %s"
            % ("IE*8+48", "IE*16+312", "IE*64+1384")[size_type],
            note="%d bits = %d octets" % (tfs["rlc_bits"], tfs["rlc_size"]))
    e.field("numberOfTbSizeList.length", 1, 1, MAX_TF,
            "numberOfTbSizeList ::= SEQUENCE (SIZE (1..maxTF)) OF NumberOfTransportBlocks")
    e.enum("numberOfTransportBlocks", tfs["tb_choice"], 4,
           "NumberOfTransportBlocks ::= CHOICE {zero, one, small INTEGER(2..17), "
           "large INTEGER(18..512)}", note="%d blocks" % tfs["tb"])
    if tfs["tb_choice"] == 2:
        e.field("numberOfTransportBlocks.small", tfs["tb"] - 2, 0, 15,
                "NumberOfTransportBlocks.small ::= INTEGER (2..17)")
    elif tfs["tb_choice"] == 3:
        e.field("numberOfTransportBlocks.large", tfs["tb"] - 18, 0, 494,
                "NumberOfTransportBlocks.large ::= INTEGER (18..512)")
    e.enum("logicalChannelList", 0, 3,
           "LogicalChannelList ::= CHOICE {allSizes, configured, explicitList}")
    e.enum("channelCodingType", 1, 3,
           "SemistaticTF-Information: ChannelCodingType ::= CHOICE {noCoding, "
           "convolutional, turbo}")
    e.enum("codingRate", 1 if tfs["coding"] == "third" else 0, 2,
           "CodingRate ::= ENUMERATED {half, third} (TS 25.212 4.2.3 Table 1)")
    e.field("rateMatchingAttribute", tfs["rm_ie"], 1, 256,
            "RateMatchingAttribute ::= INTEGER (1..hiRM), hiRM = 256",
            note="RM = %d" % tfs["rm"])
    e.enum("crc-Size", 3, 5, "CRC-Size ::= ENUMERATED {crc0, crc8, crc12, crc16, crc24}")


def enc_sccpch(e, s):
    R = "SCCPCH-SystemInformation"
    e.opt("tfcs", False, R + ": tfcs TFCS OPTIONAL")
    e.opt("fach-PCH-InformationList", bool(s["fach"]),
          R + ": fach-PCH-InformationList OPTIONAL")
    e.opt("pich-Info", s.get("pich") is not None, R + ": pich-Info PICH-Info OPTIONAL")
    R2 = "SecondaryCCPCH-Info.fdd"
    e.enum("secondaryCCPCH-Info", 0, 2, "SecondaryCCPCH-Info ::= CHOICE {fdd, tdd}")
    # SecondaryCCPCH-Info fdd preamble: dummy2, secondaryScramblingCode, timingOffset
    e.opt("dummy2", False, R2 + ": dummy2 SecondaryCPICH-Info OPTIONAL (not used)")
    e.opt("secondaryScramblingCode", s.get("ssc") is not None,
          R2 + ": secondaryScramblingCode OPTIONAL")
    e.opt("timingOffset", s.get("timing_offset") is not None,
          R2 + ": TimingOffset DEFAULT 0")
    e.flag("dummy1", s["sttd"], R2 + ": dummy1 PCPICH-UsageForChannelEst")
    if s.get("ssc") is not None:
        e.field("secondaryScramblingCode", s["ssc"], 1, 15,
                "SecondaryScramblingCode ::= INTEGER (1..15)")
    e.flag("sttd-Indicator", s["sttd"], R2 + ": sttd-Indicator BOOLEAN")
    sf_choice = {4: 0, 8: 1, 16: 2, 32: 3, 64: 4, 128: 5, 256: 6}[s["sf"]]
    e.enum("sf-AndCodeNumber", sf_choice, 7,
           "SF256-AndCodeNumber ::= CHOICE {sf4, sf8, sf16, sf32, sf64, sf128, sf256}",
           note="SF = %d" % s["sf"])
    e.field("sf-AndCodeNumber.value", s["code"], 0, s["sf"] - 1,
            "SF256-AndCodeNumber.sf%d ::= INTEGER (0..%d)" % (s["sf"], s["sf"] - 1),
            note="channelisation code")
    e.flag("pilotSymbolExistence", s["pilot"], R2 + ": pilotSymbolExistence BOOLEAN")
    e.flag("tfci-Existence", s["tfci"], R2 + ": tfci-Existence BOOLEAN")
    e.enum("positionFixedOrFlexible", 0 if s["fixed"] else 1, 2,
           "PositionFixedOrFlexible ::= ENUMERATED {fixed, flexible}")
    if s.get("timing_offset") is not None:
        e.field("timingOffset", s["timing_offset"], 0, 149,
                "TimingOffset ::= INTEGER (0..149)", note="chips / 256")
    if s["fach"]:
        e.field("fach-PCH-InformationList.length", len(s["fach"]), 1, MAX_FACH_PCH,
                "FACH-PCH-InformationList ::= SEQUENCE (SIZE (1..maxFACHPCH)) OF "
                "FACH-PCH-Information")
        for f in s["fach"]:
            R3 = "FACH-PCH-Information"
            enc_transport_format_set(e, f["tfs"], R3)
            e.field("transportChannelIdentity", f["trch"], 1, 32,
                    "TransportChannelIdentity ::= INTEGER (1..32)")
            e.flag("ctch-Indicator", f["ctch"], R3 + ": ctch-Indicator BOOLEAN")
    if s.get("pich") is not None:
        R4 = "PICH-Info.fdd"
        e.enum("pich-Info", 0, 2, "PICH-Info ::= CHOICE {fdd, tdd}")
        e.field("channelisationCode256", s["pich"]["code"], 0, 255,
                "ChannelisationCode256 ::= INTEGER (0..255)")
        e.enum("pi-CountPerFrame", s["pich"]["pi"], 4,
               "PI-CountPerFrame ::= ENUMERATED {e18, e36, e72, e144}")
        e.flag("sttd-Indicator", s["pich"]["sttd"], R4 + ": sttd-Indicator BOOLEAN")


def enc_sib5(p):
    """SysInfoType5: the cell's PRACH and S-CCPCH common physical channels."""
    e = Enc()
    R = "SysInfoType5"
    e.opt("primaryCCPCH-Info", p["primary_ccpch"],
          R + ": primaryCCPCH-Info PrimaryCCPCH-Info OPTIONAL")
    e.opt("cbs-DRX-Level1Information", False,
          R + ": cbs-DRX-Level1Information OPTIONAL")
    e.opt("v4b0NonCriticalExtensions", False,
          R + ": v4b0NonCriticalExtensions OPTIONAL")
    e.flag("sib6indicator", p["sib6"], R + ": sib6indicator BOOLEAN")
    e.field("pich-PowerOffset", p["pich_offset"], -10, 5,
            "PICH-PowerOffset ::= INTEGER (-10..5)", note="dB")
    e.enum("modeSpecificInfo", 0, 2, R + ": modeSpecificInfo CHOICE {fdd, tdd}")
    e.field("aich-PowerOffset", p["aich_offset"], -22, 5,
            "AICH-PowerOffset ::= INTEGER (-22..5)", note="dB")
    if p["primary_ccpch"]:
        e.enum("primaryCCPCH-Info.fdd", 0, 2, "PrimaryCCPCH-Info ::= CHOICE {fdd, tdd}")
        e.flag("tx-DiversityIndicator", p["tx_div"], "PrimaryCCPCH-Info.fdd")

    e.field("prach-SystemInformationList.length", len(p["prach"]), 1, MAX_PRACH,
            "PRACH-SystemInformationList ::= SEQUENCE (SIZE (1..maxPRACH)) OF "
            "PRACH-SystemInformation")
    for pr in p["prach"]:
        R2 = "PRACH-SystemInformation"
        e.opt("rach-TransportFormatSet", pr.get("tfs") is not None,
              R2 + ": rach-TransportFormatSet OPTIONAL")
        e.opt("rach-TFCS", False, R2 + ": rach-TFCS TFCS OPTIONAL")
        e.opt("prach-Partitioning", False, R2 + ": prach-Partitioning OPTIONAL")
        e.opt("persistenceScalingFactorList", False,
              R2 + ": persistenceScalingFactorList OPTIONAL")
        e.opt("ac-To-ASC-MappingTable", False, R2 + ": ac-To-ASC-MappingTable OPTIONAL")
        R3 = "PRACH-RACH-Info.fdd"
        e.enum("prach-RACH-Info", 0, 2, "PRACH-RACH-Info ::= CHOICE {fdd, tdd}")
        e.raw("availableSignatures", pr["avail_sig"],
              "AvailableSignatures ::= BIT STRING (16 named bits signature15(0).."
              "signature0(15))")
        e.enum("availableSF", {32: 0, 64: 1, 128: 2, 256: 3}[pr["sf"]], 4,
               "SF-PRACH ::= ENUMERATED {sfpr32, sfpr64, sfpr128, sfpr256}",
               note="SF = %d" % pr["sf"])
        e.field("preambleScramblingCodeWordNumber", pr["psc"], 0, 15,
                "PreambleScramblingCodeWordNumber ::= INTEGER (0..15)")
        e.enum("puncturingLimit", PL_INDEX[pr["pl"]], 16,
               "PuncturingLimit ::= ENUMERATED {pl0-40 .. pl1}")
        e.raw("availableSubChannelNumbers", pr["avail_sub"],
              "AvailableSubChannelNumbers ::= BIT STRING (12 named bits subCh11(0).."
              "subCh0(11))")
        e.field("transportChannelIdentity", pr["trch"], 1, 32,
                "TransportChannelIdentity ::= INTEGER (1..32)")
        if pr.get("tfs") is not None:
            enc_transport_format_set(e, pr["tfs"], R3)
        e.enum("modeSpecificInfo", 0, 2, R2 + ": modeSpecificInfo CHOICE {fdd, tdd}")
        for name in ("primaryCPICH-TX-Power", "constantValue", "prach-PowerOffset",
                     "rach-TransmissionParameters", "aich-Info"):
            e.opt(name, False, R3 + ": optional FDD RACH parameter")

    e.field("sCCPCH-SystemInformationList.length", len(p["sccpch"]), 1, MAX_SCCPCH,
            "SCCPCH-SystemInformationList ::= SEQUENCE (SIZE (1..maxSCCPCH)) OF "
            "SCCPCH-SystemInformation")
    for s in p["sccpch"]:
        enc_sccpch(e, s)
    return e


def enc_mib(p):
    """MasterInformationBlock: the top of the system information tree."""
    e = Enc()
    R = "MasterInformationBlock"
    e.opt("v6xyNonCriticalExtensions", False, R + ": v6xyNonCriticalExtensions OPTIONAL")
    e.field("mib-ValueTag", p["value_tag"], 1, 8, "MIB-ValueTag ::= INTEGER (1..8)")
    e.enum("plmn-Type", 0, 4,
           "PLMN-Type ::= CHOICE {gsm-MAP, ansi-41, gsm-MAP-and-ANSI-41, spare}")
    enc_plmn_identity(e, p)
    e.field("sibSb-ReferenceList.length", len(p["refs"]), 1, MAX_SIB,
            "SIBSb-ReferenceList ::= SEQUENCE (SIZE (1..maxSIB)) OF "
            "SchedulingInformationSIBSb")
    for ref in p["refs"]:
        idx = SIBSB_ALIAS[ref["sib"]]
        name, tag = SIBSB_TAG[idx]
        e.enum("sibSb-Type", idx, 32, "SIBSb-TypeAndTag ::= CHOICE (32 alternatives)",
               note=name)
        if tag == "plmn":
            e.field("plmn-ValueTag", ref["value"], 1, 256,
                    "PLMN-ValueTag ::= INTEGER (1..256)")
        elif tag == "cell":
            e.field("cellValueTag", ref["value"], 1, 4,
                    "CellValueTag ::= INTEGER (1..4)")
        elif tag is None:
            pass
        else:
            _die(2, "cannot schedule %s in a MIB reference list" % ref["sib"],
                 "SIBSb-TypeAndTag %s needs a %s value tag, which this tool does "
                 "not encode (limit: sib-scheduling)" % (name, tag))
        R2 = "SchedulingInformation"
        e.opt("segCount", ref["seg_count"] != 1,
              R2 + ": segCount SegCount DEFAULT 1")
        e.opt("sib-PosOffsetInfo", False, R2 + ": sib-PosOffsetInfo SibOFF-List OPTIONAL")
        if ref["seg_count"] != 1:
            e.field("segCount", ref["seg_count"], 1, 16, "SegCount ::= INTEGER (1..16)")
        rep, rep_value = ref["rep"]
        e.enum("sib-Pos", SIB_POS_INDEX[rep], 11,
               "sib-Pos CHOICE {rep4, rep8, rep16, rep32, rep64, rep128, rep256, "
               "rep512, rep1024, rep2048, rep4096}", note="SIB_REP = %d" % rep)
        e.field("sib-Pos.value", rep_value, 0, (rep // 2) - 1,
                "sib-Pos.rep%d ::= INTEGER (0..%d)" % (rep, rep // 2 - 1),
                note="SIB_POS = value * 2 (the ASN.1 note: 'the value "
                     "(multiplied by two) indicates the position')")
    return e


SIB_POS_INDEX = {4: 0, 8: 1, 16: 2, 32: 3, 64: 4, 128: 5, 256: 6, 512: 7,
                 1024: 8, 2048: 9, 4096: 10}


# ---------------------------------------------------------------------------
# TS 25.212 transport chain for one FACH transport block
# ---------------------------------------------------------------------------
def crc16_parity(bits):
    """TS 25.212 4.2.1.1: remainder of the transport block times D^16, mod
    gCRC16(D) = D16 + D12 + D5 + 1, computed with a 17-bit register."""
    acc = 0
    for b in list(bits) + [0] * CRC_BITS:
        acc = (acc << 1) | b
        if acc & (1 << CRC_BITS):
            acc ^= GCRC16
    return [(acc >> (CRC_BITS - 1 - k)) & 1 for k in range(CRC_BITS)]


def crc16_attach(bits):
    """TS 25.212 4.2.1.2: b_ik = p_im(Li+1-(k-Ai)); with Li = 16 the parity
    leaves in the order p16, p15, ..., p1, the reverse of the remainder."""
    p = crc16_parity(bits)
    return list(bits) + list(reversed(p))


def _parity(reg, poly):
    return bin(reg & poly).count("1") & 1


def conv_encode(bits, rate):
    """TS 25.212 4.2.3.1: K = 9, 8 zero tail bits, all-zero start,
    output order output0, output1[, output2] repeating."""
    polys = CONV_POLY[rate]
    reg = 0
    out = []
    for b in list(bits) + [0] * TAIL_BITS:
        reg = ((reg << 1) | b) & ((1 << CONV_K) - 1)
        for poly in polys:
            out.append(_parity(reg, poly))
    return out


def rate_matching_params(xi, ndata):
    """TS 25.212 4.2.7.2.2.2 (conv, flexible) == 4.2.7.2.1.3 (conv, fixed) for
    a single transport format: a = 2, eini = 1, eplus = 2*Xi, eminus = 2*|dN|."""
    dn = ndata - xi
    return {"xi": xi, "dn": dn, "a": 2, "e_ini": 1,
            "e_plus": 2 * xi, "e_minus": 2 * abs(dn)}


def rate_match(bits, par):
    """TS 25.212 4.2.7.5 rate matching pattern determination, verbatim loop.
    A repeated bit is placed directly after the original one; a punctured bit
    is removed."""
    if par["dn"] == 0:
        return list(bits)
    out = []
    e = par["e_ini"]
    for b in bits:
        e -= par["e_minus"]
        if par["dn"] > 0:
            while e <= 0:
                out.append(b)
                e += par["e_plus"]
            out.append(b)
        else:
            if e <= 0:
                e += par["e_plus"]
            else:
                out.append(b)
    return out


def interleave2(bits):
    """TS 25.212 4.2.11: C2 = 30 columns, R2 rows, Table 7 permutation,
    read column by column, dummy padding pruned."""
    u = len(bits)
    r2 = (u + C2 - 1) // C2
    frame = list(bits) + [0] * (r2 * C2 - u)     # padding bits, any value
    out = []
    for j in range(C2):
        col = P2[j]
        for i in range(r2):
            idx = i * C2 + col
            if idx < u:                          # pruning skips the padded tail
                out.append(frame[idx])
    return out


def fach_chain(tb_bits, ndata, rate):
    """Run the whole TS 25.212 FACH chain and return [(stage, bits, ref, note)]."""
    rows = []
    rows.append(("tb", tb_bits,
                 "TS 25.212 4.2.13.6",
                 "one transport block per TTI (M1 = 1); the block size is a "
                 "higher-layer transport format attribute (TS 25.331 10.2.1 "
                 "CommonDynamicTF-Info)"))
    b = crc16_attach(tb_bits)
    rows.append(("crc", b, "TS 25.212 4.2.1.1 + 4.2.1.2",
                 "gCRC16 = D16+D12+D5+1, parity appended p16..p1"))
    b = conv_encode(b, rate)
    rows.append(("conv", b, "TS 25.212 4.2.3.1",
                 "rate 1/%d, K=9, G0=%o%s, 8 tail bits, all-zero start"
                 % (rate, CONV_POLY[rate][0],
                    "".join(", G%d=%o" % (i + 1, p)
                            for i, p in enumerate(CONV_POLY[rate][1:])))))
    rows.append(("equalise", b, "TS 25.212 4.2.4",
                 'not applied: "Radio frame size equalisation is only performed '
                 'in the UL"'))
    par = rate_matching_params(len(b), ndata)
    x = rate_match(b, par)
    delta = par["dn"]
    what = ("%d repetitions" % delta if delta > 0
            else ("%d punctures" % -delta if delta < 0 else "no change"))
    rows.append(("ratematch", x, "TS 25.212 4.2.7.2 + 4.2.7.2.1.1 + 4.2.7.2.2.2 "
                 "+ 4.2.7.5",
                 "Ndata,*=%d, Xi=%d, dN=%+d, e_ini=%d, e_plus=%d, e_minus=%d, %s"
                 % (ndata, par["xi"], delta, par["e_ini"], par["e_plus"],
                    par["e_minus"], what)))
    rows.append(("frameseg", x, "TS 25.212 4.2.6.2",
                 "Fi = 1, one segment of %d bits, transparent" % len(x)))
    rows.append(("dtx1", x, "TS 25.212 4.2.9.1",
                 "Hi = N_i,* + dN_i,* = %d = Gi, so no DTX bits are inserted"
                 % len(x)))
    rows.append(("ilv1", x, "TS 25.212 4.2.5.4",
                 "Fi = 1, the 10 ms interleaver is a single column, transparent"))
    rows.append(("mux", x, "TS 25.212 4.2.8 + 4.2.10.2",
                 "I = 1 TrCH and P = 1 PhCH, transparent"))
    x = interleave2(x)
    rows.append(("ilv2", x, "TS 25.212 4.2.11",
                 "C2 = 30, R2 = %d, Table 7 permutation, no padding for U = %d"
                 % ((ndata + C2 - 1) // C2, ndata)))
    per_slot = ndata // FACH_SLOTS
    for k in range(FACH_SLOTS):
        sl = x[k * per_slot:(k + 1) * per_slot]
        rows.append(("slot%02d" % k, sl, "TS 25.212 4.2.12.2",
                     "%d bits of slot %d" % (per_slot, k)))
    return rows, par


# ---------------------------------------------------------------------------
# SYSTEM INFORMATION message construction
# ---------------------------------------------------------------------------
SI_CHOICE = [
    ("noSegment", None), ("firstSegment", None), ("subsequentSegment", None),
    ("lastSegmentShort", None), ("lastAndFirst", None), ("lastAndComplete", None),
    ("lastAndCompleteAndFirst", None), ("completeSIB-List", None),
    ("completeAndFirst", None), ("completeSIB", None), ("lastSegment", None),
    ("spare5", None), ("spare4", None), ("spare3", None), ("spare2", None),
    ("spare1", None),
]

SI_COMBINATION = {
    "noSegment": 1, "firstSegment": 2, "subsequentSegment": 3,
    "lastSegmentShort": 4, "lastAndFirst": 5, "lastAndComplete": 6,
    "lastAndCompleteAndFirst": 7, "completeSIB-List": 8, "completeAndFirst": 9,
    "completeSIB": 10, "lastSegment": 11,
}


def si_payload_bits(kind, ent, seg=None):
    """Encode the SystemInformation-FACH payload CHOICE for one message.

    `ent` is the SIB entry; `seg` is (seg_count, seg_index, data_bits) for the
    segmented kinds, or a list of complete SIB entries for completeSIB-List."""
    e = Enc()
    e.enum("payload", [k for k, _ in SI_CHOICE].index(kind), 16,
           "SystemInformation-FACH: payload CHOICE (16 alternatives, "
           "TS 25.331 10.2.1)")
    sib_idx = SIB_ALIAS[ent["sib"]]
    if kind != "completeSIB-List":
        # CompleteSIB-List has no sib-Type before its length: the type is per entry
        e.enum("sib-Type", sib_idx, 32, "SIB-Type ::= ENUMERATED (32 alternatives)",
               note=SIB_TYPE[sib_idx])
    if kind == "completeSIB-List":
        entries = seg
        e.field("completeSIB-List.length", len(entries), 1, MAX_SIB_PER_MSG,
                "CompleteSIB-List ::= SEQUENCE (SIZE (1..maxSIBperMsg)) OF CompleteSIBshort")
        for it in entries:
            idx = SIB_ALIAS[it["sib"]]
            e.enum("sib-Type", idx, 32, "CompleteSIBshort ::= SEQUENCE {sib-Type, "
                   "sib-Data-variable}", note=SIB_TYPE[idx])
            e.field("sib-Data-variable.length", len(it["bits"]), 1, SEG_VAR_MAX_BITS,
                    "SIB-Data-variable ::= BIT STRING (SIZE (1..214))")
            e.raw("sib-Data-variable", it["bits"], "the encoded SIB")
        return e
    seg_count, seg_index, data = seg
    if kind == "firstSegment":
        e.field("seg-Count", seg_count, 1, 16, "SegCount ::= INTEGER (1..16)")
        e.raw("sib-Data-fixed", data, "SIB-Data-fixed ::= BIT STRING (SIZE (222))")
    elif kind in ("subsequentSegment", "lastSegment"):
        e.field("segmentIndex", seg_index, 1, 15, "SegmentIndex ::= INTEGER (1..15)")
        e.raw("sib-Data-fixed", data, "SIB-Data-fixed ::= BIT STRING (SIZE (222))")
    elif kind == "lastSegmentShort":
        e.field("segmentIndex", seg_index, 1, 15, "SegmentIndex ::= INTEGER (1..15)")
        e.field("sib-Data-variable.length", len(data), 1, SEG_VAR_MAX_BITS,
                "SIB-Data-variable ::= BIT STRING (SIZE (1..214))")
        e.raw("sib-Data-variable", data, "the last, short segment")
    elif kind == "completeSIB":
        e.raw("sib-Data-fixed", data,
              "CompleteSIB: sib-Data-fixed BIT STRING (SIZE (226))")
    else:
        _die(1, "internal: unsupported message payload %r" % kind, "")
    return e


def segment_sib(ent):
    """Turn one encoded SIB into a list of (kind, seg) message descriptions,
    per TS 25.331 8.1.1.1.3 combinations 2/3/4/8/10/11."""
    n = len(ent["bits"])
    if n <= SEG_VAR_MAX_BITS:
        return [("completeSIB-List", None)]           # combination 8, one entry
    if n <= COMPLETE_FIXED_BITS:
        pad = COMPLETE_FIXED_BITS - n
        if pad > COMPLETE_FIXED_BITS - COMPLETE_MIN_LONG:
            _die(2, "a %d bit SIB does not fit a segment combination" % n,
                 "clause 8.1.1.1.3: a CompleteSIBshort holds up to %d bits, a "
                 "CompleteSIB exactly 226, and 'One Complete of size 215 to 226' "
                 "needs 215..226; %d..%d is not reachable"
                 % (SEG_VAR_MAX_BITS, SEG_VAR_MAX_BITS + 1, COMPLETE_MIN_LONG - 1))
        return [("completeSIB", ("pad", pad))]        # combination 10
    seg_count = (n + SEG_FIXED_BITS - 1) // SEG_FIXED_BITS
    if seg_count > 16:
        _die(2, "a %d bit SIB needs %d segments, SEG_COUNT is 1..16"
             % (n, seg_count),
             "TS 25.331 10.2.1 SegCount ::= INTEGER (1..16); the largest SIB "
             "this message can carry is 16*222 = 3552 bits")
    out = []
    for i in range(seg_count):
        chunk = ent["bits"][i * SEG_FIXED_BITS:(i + 1) * SEG_FIXED_BITS]
        chunk = chunk + "0" * (SEG_FIXED_BITS - len(chunk))
        if i == 0:
            out.append(("firstSegment", (seg_count, 1, chunk)))
        elif i < seg_count - 1:
            out.append(("subsequentSegment", (seg_count, i + 1, chunk)))
        else:
            last = ent["bits"][i * SEG_FIXED_BITS:]
            if len(last) <= SEG_VAR_MAX_BITS:
                out.append(("lastSegmentShort", (seg_count, i + 1, last)))
            else:
                out.append(("lastSegment",
                            (seg_count, i + 1,
                             last + "0" * (SEG_FIXED_BITS - len(last)))))
    return out


def si_message_bits(kind, ent, seg=None):
    """Whole BCCH-FACH-Message: the 2-bit message type, then the payload."""
    return "00" + si_payload_bits(kind, ent, seg).bits()


def pack_si(entries, tb_bits, pack):
    """Build the list of SYSTEM INFORMATION messages for the given SIBs."""
    msgs = []
    group = []

    def flush():
        if not group:
            return
        while group:
            take = group[:MAX_SIB_PER_MSG]
            # greedy: stop before the message would overflow the transport block
            chosen = []
            for it in take:
                cand = chosen + [it]
                bits = len(si_message_bits("completeSIB-List", cand[0], cand))
                if chosen and (bits + 7) // 8 * 8 > tb_bits:
                    break
                chosen = cand
            if not chosen:
                _die(2, "SIB %r does not fit a %d bit FACH transport block"
                     % (group[0]["sib"], tb_bits),
                     "TS 25.331 8.1.1.1.3: the SYSTEM INFORMATION message shall "
                     "fit the transport block size")
            msgs.append({"kind": "completeSIB-List", "ent": chosen[0],
                         "entries": chosen})
            del group[:len(chosen)]

    for ent in entries:
        n = len(ent["bits"])
        if n <= SEG_VAR_MAX_BITS and pack == "combine":
            group.append(ent)
            continue
        flush()
        if n <= SEG_VAR_MAX_BITS:
            group.append(ent)
            flush()
        elif n <= COMPLETE_FIXED_BITS:
            msgs.append({"kind": "completeSIB", "ent": ent,
                         "seg": ("pad", COMPLETE_FIXED_BITS - n)})
        else:
            for kind, seg in segment_sib(ent):
                msgs.append({"kind": kind, "ent": ent, "seg": seg})
    flush()
    # final size check
    for m in msgs:
        bits = len(si_payload_bits(m["kind"], m["ent"],
                                   m.get("seg") if m["kind"] != "completeSIB-List"
                                   else m["entries"]).bits())
        if (bits + 7) // 8 * 8 > tb_bits:
            _die(2, "%s message of %d bits does not fit a %d bit FACH transport "
                 "block" % (m["kind"], bits, tb_bits),
                 "TS 25.331 8.1.1.1.3: the SYSTEM INFORMATION message shall fit "
                 "the transport block size")
        m["bits"] = bits
    return msgs


# ---------------------------------------------------------------------------
# option plumbing
# ---------------------------------------------------------------------------
PL_VALUES = ["pl0-40", "pl0-44", "pl0-48", "pl0-52", "pl0-56", "pl0-60",
             "pl0-64", "pl0-68", "pl0-72", "pl0-76", "pl0-80", "pl0-84",
             "pl0-88", "pl0-92", "pl0-96", "pl1"]
PL_INDEX = {v: i for i, v in enumerate(PL_VALUES)}


def _tfs(rlc_bits, tb, coding, rm, tti_index=0):
    """Build a transport format set description with one common transport
    format.  RLC size is given in bits; OctetModeRLC-SizeInfoType2 covers
    48..2712 bits in three ranges (TS 25.331 10.2.1)."""
    if rlc_bits < 48:
        _die(2, "RLC size %d bits is below OctetModeRLC-SizeInfoType2" % rlc_bits,
             "sizeType1 covers 48..296 bits (actual = IE*8+48)")
    for st, (lo, hi, base, step) in enumerate(
            ((48, 296, 48, 8), (312, 1320, 312, 16), (1384, 4968, 1384, 64))):
        if lo <= rlc_bits <= hi and (rlc_bits - base) % step == 0:
            ie = (rlc_bits - base) // step
            break
    else:
        _die(2, "RLC size %d bits is not encodable" % rlc_bits,
             "OctetModeRLC-SizeInfoType2 covers 48..296 (step 8), 312..1320 "
             "(step 16) and 1384..4968 bits (step 64)")
    if tb == 1:
        tb_choice = 1
    elif 2 <= tb <= 17:
        tb_choice = 2
    elif 18 <= tb <= 512:
        tb_choice = 3
    else:
        _die(2, "number of transport blocks %d is outside 1..512" % tb, "")
    if not (1 <= rm <= 256):
        _die(2, "rate matching attribute %d is outside 1..256" % rm,
             "RateMatchingAttribute ::= INTEGER (1..hiRM), hiRM = 256")
    return {"rlc_size": rlc_bits // 8, "rlc_bits": rlc_bits, "rlc_size_type": st,
            "rlc_size_ie": ie, "tb": tb, "tb_choice": tb_choice,
            "coding": coding, "rm": rm, "rm_ie": rm, "tti_index": tti_index}


def _sig_bits(s, default="1" * 16):
    if s is None:
        return default
    t = s.replace(" ", "").replace(",", "")
    if len(t) != 16 or any(c not in "01" for c in t):
        _die(2, "signature mask %r is not 16 bits of 0/1" % s,
             "AvailableSignatures is 16 named bits signature15(0)..signature0(15)")
    return t


def _subch_bits(s, default="1" * 12):
    if s is None:
        return default
    t = s.replace(" ", "").replace(",", "")
    if len(t) != 12 or any(c not in "01" for c in t):
        _die(2, "subchannel mask %r is not 12 bits of 0/1" % s,
             "AvailableSubChannelNumbers is 12 named bits subCh11(0)..subCh0(11)")
    return t


def sib3_defaults():
    return {"sib4": False, "cell_id": 1, "quality": "ecno", "q_hyst_2": None,
            "s_intra": 4, "s_inter": None, "s_hcs": None,
            "q_qualmin": -18, "q_rxlevmin": -32, "q_hyst": 2, "t_resel": 1,
            "max_ul": 24, "barred": False, "t_barred": 0, "reserved": False,
            "acb_list": None}


def sib5_defaults():
    tfs_fach = _tfs(360, 1, "third", 160)
    tfs_pch = _tfs(360, 1, "half", 160)
    tfs_ctch = _tfs(360, 1, "third", 160)
    return {
        "sib6": False, "pich_offset": -2, "aich_offset": 0,
        "primary_ccpch": False, "tx_div": False,
        "prach": [{"avail_sig": "1" * 16, "sf": 128, "psc": 0, "pl": "pl0-44",
                   "avail_sub": "1" * 12, "trch": 1,
                   "tfs": None}],          # --rach-tfs adds a RACH TFS
        "sccpch": [
            {"sf": 16, "code": 1, "sttd": False, "pilot": False, "tfci": True,
             "fixed": True, "ssc": None, "timing_offset": None,
             "fach": [{"tfs": tfs_fach, "trch": 3, "ctch": False},
                      {"tfs": tfs_pch, "trch": 4, "ctch": False}],
             "pich": {"code": 16, "pi": 1, "sttd": False}},
            {"sf": 16, "code": 2, "sttd": False, "pilot": False, "tfci": True,
             "fixed": True, "ssc": None, "timing_offset": None,
             "fach": [{"tfs": tfs_ctch, "trch": 6, "ctch": True}],
             "pich": None},
        ],
    }


# The repetition period a SIB gets when the schedule is derived rather than
# typed.  These are the tree's existing defaults (mib_defaults below) lifted
# into a table so one place decides: SIB1 and SIB3 are read first, SIB5 carries
# the common physical channels and is repeated less often.
SIB_REP_DEFAULT = {"sib1": 8, "sib3": 8, "sib5": 16, "sib7": 16, "sib11": 16,
                   "sib4": 16, "sib6": 16, "sib11bis": 16, "sib12": 16,
                   "sib13": 16, "sib14": 16, "sib18": 16}


def _refs_from_sibs(spec):
    """Build the MIB reference list from the SIBs a cell actually transmits."""
    names = [n.strip().lower() for n in spec.replace(",", " ").split() if n.strip()]
    if not names:
        _die(2, "--from-sibs is empty",
             "name the blocks the S-CCPCH carries, e.g. sib1,sib3,sib5")
    seen = set()
    refs = []
    for name in names:
        if name in seen:
            _die(2, "--from-sibs repeats %s" % name,
                 "one reference per block: a second entry would schedule the "
                 "same block twice in one MIB")
        seen.add(name)
        if name not in SIBSB_ALIAS or SIBSB_ALIAS[name] is None:
            _die(2, "--from-sibs: %r is not a schedulable system information "
                 "block" % name,
                 "SIBSb-TypeAndTag lists sysInfoType1..18, 5bis and "
                 "sysInfoTypeSB1/SB2; the master information block itself is "
                 "not scheduled in its own reference list")
        rep = SIB_REP_DEFAULT.get(name, 16)
        refs.append({"sib": name, "value": 1, "seg_count": 1, "rep": (rep, 0)})
    return refs


def mib_defaults():
    return {"value_tag": 1, "mcc": "001", "mnc": "01",
            "refs": [{"sib": "sib1", "value": 1, "seg_count": 1, "rep": (8, 0)},
                     {"sib": "sib3", "value": 1, "seg_count": 1, "rep": (8, 0)},
                     {"sib": "sib5", "value": 1, "seg_count": 1, "rep": (16, 0)}]}


def sib1_defaults():
    # The NAS octets are opaque to RRC (TS 25.331 10.3.1.3); the default is a
    # short 24.008 PDU so that an independent NAS dissector does not abort.
    return {"nas": [0x08, 0x03],
            "domains": [{"domain": "cs", "nas": [0x00], "drx": 6}]}


def _sib_encoder(name, params):
    if name == "mib":
        return enc_mib(params)
    if name == "sib1":
        return enc_sib1(params)
    if name == "sib3":
        return enc_sib3(params)
    if name == "sib5":
        return enc_sib5(params)
    _die(2, "no encoder for %s" % name,
         "this tool encodes the master information block and SysInfoType1, 3, 5")


def _default_params(name):
    if name == "mib":
        return mib_defaults()
    if name == "sib1":
        return sib1_defaults()
    if name == "sib3":
        return sib3_defaults()
    if name == "sib5":
        return sib5_defaults()
    _die(2, "no default parameters for %s" % name, "")


# The BCH transport block is 24 bits (tools/umts_bch.py BCH_TB_BITS; TS 25.212
# 4.2.13.6 leaves the attributes to TS 25.331).  An encoded MIB is larger than
# that -- 84 bits for the default three-block schedule -- so a cell puts it out
# in consecutive BCH transport blocks and the UE reassembles it across the MIB
# period.  This tool splits the bit string and says so; it does not invent the
# segment header of TS 25.331 8.1.1.1.3.
MIB_SEG_LIMITS = [
    ("mib-segment-header",
     "TS 25.331 8.1.1.1.3 puts a segment header (segment type, SIB type, "
     "SEG_COUNT on the first segment, segment index after it) in front of the "
     "data.  This split is a bare bit-string chunking: it reproduces the MIB "
     "bits exactly and adds no header, so it is only what a receiver that "
     "concatenates the blocks would read back"),
    ("mib-segment-count",
     "the number of segments a real cell uses is signalled by SEG_COUNT in the "
     "first segment; here it is ceil(bits / tb_bits) and nothing else"),
]


def segment_mib(bits, tb_bits):
    """Split an encoded MIB into BCH transport blocks, the last one padded."""
    if tb_bits <= 0:
        _die(2, "--segments %d is not a transport block size" % tb_bits,
             "a BCH transport block is a positive number of bits, 24 in "
             "tools/umts_bch.py [1] 4.2.13.6")
    blocks = []
    for i in range(0, len(bits), tb_bits):
        chunk = [int(b) for b in bits[i:i + tb_bits]]
        pad = tb_bits - len(chunk)
        blocks.append((chunk + [0] * pad, len(chunk), pad))
    return blocks


def _finish(e, rows, extra=None):
    bits = e.bits()
    pad = (-len(bits)) % 8
    rows.append(("bits", str(len(bits))))
    if pad:
        rows.append(("pad", "%d zero bits to a whole octet (TS 25.331 12.1)" % pad))
    rows.append(("octets", str((len(bits) + 7) // 8)))
    rows.append(("hex", _bits_hex(bits)))
    if extra:
        rows.extend(extra)
    rows.append(("bitstring", bits))
    for lim in LIMITS:
        rows.append(("limit", "%s: %s" % lim))
    return rows


# ---------------------------------------------------------------------------
# verbs
# ---------------------------------------------------------------------------
def cmd_list(args):
    rows = [
        ("tool", "umts_sib.py -- RRC SYSTEM INFORMATION on BCCH-FACH, "
                 "SIB1/SIB3/SIB5, and the TS 25.212 FACH chain"),
        ("spec", "TS 25.331 v6.4.0 (RRC, unaligned PER per X.691) / "
                 "TS 25.212 v6.4.0 (channel coding and multiplexing)"),
        ("si", "si [--add TYPE[:HEX[:BITS]] ...] [--fach-tb-bits N] "
               "[--pack one|combine]  -- SYSTEM INFORMATION message list"),
        ("mib", "mib [--value-tag N] [--mcc DDD] [--mnc DD|DDD] "
                "[--schedule SIB:VALUE:REP ...]  -- MasterInformationBlock"),
        ("sib1", "sib1 [--nas HEX] [--cs-nas HEX] [--ps-nas HEX] [--drx N]"),
        ("sib3", "sib3 [--cell-id HEX] [--sib4] [--quality ecno|rscp] "
                 "[--s-intra IE|off] [--s-inter IE|off] [--s-hcs IE|off] "
                 "[--q-qualmin IE] [--q-rxlevmin IE] [--q-hyst IE] "
                 "[--t-resel IE] [--max-ul IE] [--barred] [--t-barred IDX] "
                 "[--cell-reserved] [--acb-list BITS]"),
        ("sib5", "sib5 [--sccpch N] [--prach N] [--coding third|half] "
                 "[--rm N] [--rlc-size OCTETS] [--tb-tb N] [--sib6] "
                 "[--pich-offset N] [--aich-offset N] [--tfci on|off] "
                 "[--primary-ccpch] [--ctch-on K]"),
        ("fach", "fach --tb-hex HEX [--tb-bits N] [--coding third|half] "
                 "[--ndata N] [--sf N]  -- one FACH transport block through "
                 "TS 25.212"),
        ("conventions", "every hex is an octet string: the bit string is right "
                        "padded with zero bits (the `pad` row says how many), "
                        "first bit in the most significant bit of the first "
                        "octet -- that is exactly what GSMTAP carries"),
    ]
    for lim in LIMITS:
        rows.append(("limit", "%s: %s" % lim))
    _emit(rows)
    return 0


def cmd_mib(args):
    p = mib_defaults()
    if args.value_tag is not None:
        p["value_tag"] = args.value_tag
    if args.mcc is not None:
        p["mcc"] = args.mcc
    if args.mnc is not None:
        p["mnc"] = args.mnc
    if args.from_sibs and args.schedule:
        _die(2, "--from-sibs and --schedule name the same list",
             "drop one: --from-sibs derives the reference list from the SIBs the "
             "cell transmits, --schedule types it")
    if args.from_sibs:
        p["refs"] = _refs_from_sibs(args.from_sibs)
    if args.schedule:
        refs = []
        for spec in args.schedule:
            parts = spec.split(":")
            if len(parts) != 3:
                _die(2, "--schedule %r is not SIB:VALUE:REP" % spec, "")
            name = parts[0].lower()
            if name not in SIBSB_ALIAS or SIBSB_ALIAS[name] is None:
                _die(2, "--schedule: %r is not a schedulable system information "
                     "block" % parts[0],
                     "SIBSb-TypeAndTag lists sysInfoType1..18, 5bis and "
                     "sysInfoTypeSB1/SB2; the master information block itself "
                     "is not scheduled in its own reference list")
            rep = _parse_int(parts[2], "schedule")
            if rep not in SIB_POS_INDEX:
                _die(2, "SIB_REP %d is not one of %s" % (rep, sorted(SIB_POS_INDEX)),
                     "sib-Pos CHOICE rep4..rep4096")
            refs.append({"sib": name, "value": _parse_int(parts[1], "schedule"),
                         "seg_count": 1, "rep": (rep, 0)})
        p["refs"] = refs
    e = enc_mib(p)
    rows = [("cli", "mib")]
    rows.extend(("ref", r) for r in e.refs)
    if args.segments:
        tb_bits = _parse_int(args.segments, "segments")
        bits = e.bits()
        blocks = segment_mib(bits, tb_bits)
        rows.append(("bch_tb_bits", "%d" % tb_bits))
        rows.append(("segments", "%d" % len(blocks)))
        rows.append(("segment_frames",
                     "%d frames of 10 ms, one transport block each; a cell "
                     "repeats the whole MIB every 80 ms (8 frames), so %d "
                     "segments fit one period" % (len(blocks), len(blocks))))
        for i, (chunk, used, pad) in enumerate(blocks):
            rows.append(("seg[%d].hex" % i, _bits_hex(chunk)))
            rows.append(("seg[%d].bits" % i, "%d used, %d pad, %d total"
                         % (used, pad, tb_bits)))
        rows.append(("reassemble", "hex %s -- the segments in order, each "
                     "truncated to its used bits, are the MIB above"
                     % _bits_hex(bits)))
        rows.append(("bch_command",
                     "tools/umts_bch.py encode --bch-hex <seg[i].hex> "
                     "--frames 8 --at-start <i> --period 8 --out bch_i.cf32 "
                     "(one file per segment)"))
        _emit(_finish(e, rows, extra=list(MIB_SEG_LIMITS)))
        return 0
    _emit(_finish(e, rows))
    return 0


def cmd_sib1(args):
    p = sib1_defaults()
    if args.nas is not None:
        p["nas"] = _parse_hex_octets(args.nas, "nas")
    domains = []
    if args.cs_nas is not None:
        domains.append({"domain": "cs", "nas": _parse_hex_octets(args.cs_nas, "cs-nas"),
                        "drx": 6})
    if args.ps_nas is not None:
        domains.append({"domain": "ps", "nas": _parse_hex_octets(args.ps_nas, "ps-nas"),
                        "drx": 6})
    if domains:
        p["domains"] = domains
    if args.drx is not None:
        for d in p["domains"]:
            d["drx"] = args.drx
    e = enc_sib1(p)
    rows = [("cli", "sib1")]
    rows.extend(("ref", r) for r in e.refs)
    _emit(_finish(e, rows))
    return 0


def _parse_hex_octets(s, what):
    t = s.replace(" ", "").replace(":", "").replace("0x", "")
    if len(t) % 2 or any(c not in "0123456789abcdefABCDEF" for c in t):
        _die(2, "--%s %r is not an even number of hex digits" % (what, s), "")
    return [int(t[i:i + 2], 16) for i in range(0, len(t), 2)]


def cmd_sib3(args):
    p = sib3_defaults()
    p["sib4"] = bool(args.sib4)
    if args.cell_id is not None:
        v = _parse_int(args.cell_id, "cell-id")
        if not (0 <= v < (1 << 28)):
            _die(2, "cell identity %d does not fit 28 bits" % v,
                 "CellIdentity ::= BIT STRING (SIZE (28))")
        p["cell_id"] = v
    if args.quality is not None:
        p["quality"] = args.quality
    for key, attr in (("s_intra", "s_intra"), ("s_inter", "s_inter"),
                      ("s_hcs", "s_hcs")):
        v = getattr(args, attr)
        if v is not None:
            p[key] = None if v == "off" else _parse_int(v, attr)
    if args.q_hyst_2 is not None:
        p["q_hyst_2"] = None if args.q_hyst_2 == "off" else _parse_int(
            args.q_hyst_2, "q-hyst-2")
    for key, attr in (("q_qualmin", "q_qualmin"), ("q_rxlevmin", "q_rxlevmin"),
                      ("q_hyst", "q_hyst"), ("t_resel", "t_resel"),
                      ("max_ul", "max_ul")):
        v = getattr(args, attr)
        if v is not None:
            p[key] = _parse_int(v, attr)
    p["barred"] = bool(args.barred)
    if args.t_barred is not None:
        p["t_barred"] = _parse_int(args.t_barred, "t-barred")
    p["reserved"] = bool(args.cell_reserved)
    if args.acb_list is not None:
        t = args.acb_list.replace(",", "")
        if len(t) != MAX_AC or any(c not in "01" for c in t):
            _die(2, "--acb-list %r is not 16 bits of 0/1" % args.acb_list,
                 "AccessClassBarredList is maxAC = 16 entries, AC15 first")
        p["acb_list"] = t
    e = enc_sib3(p)
    rows = [("cli", "sib3")]
    rows.extend(("ref", r) for r in e.refs)
    rows.append(("refused", "v4b0NonCriticalExtensions / sysInfoType3-v4b0ext "
                 "(mapping-LCR-r4 is TDD only) and sysInfoType3-v590ext: not "
                 "encoded, presence bit 0"))
    rows.append(("refused", "CellSelectReselectInfoSIB-3-4.mappingInfo (GSM "
                 "cell reselection mapping), hcs-ServingCellInformation, "
                 "rat-List: not encoded, presence bit 0"))
    rows.append(("refused", "q-HYST-2-S is only defined for cpich-Ec-N0 and "
                 "only encoded when --q-hyst-2 is given"))
    rows.append(("refused", "cellBarred = barred requires t-Barred; --barred "
                 "always encodes intraFreqCellReselectionInd = allowed"))
    _emit(_finish(e, rows))
    return 0


def cmd_sib5(args):
    p = sib5_defaults()
    p["sib6"] = bool(args.sib6)
    if args.pich_offset is not None:
        p["pich_offset"] = _parse_int(args.pich_offset, "pich-offset")
    if args.aich_offset is not None:
        p["aich_offset"] = _parse_int(args.aich_offset, "aich-offset")
    p["primary_ccpch"] = bool(args.primary_ccpch)
    p["tx_div"] = bool(args.tx_div)
    coding = args.coding or "third"
    rm = _parse_int(args.rm, "rm") if args.rm is not None else 160
    rlc_octets = _parse_int(args.rlc_size, "rlc-size") if args.rlc_size else 45
    tb = _parse_int(args.tb_tb, "tb-tb") if args.tb_tb is not None else 1
    sf_sccpch = _parse_int(args.sf_sccpch, "sf-sccpch") if args.sf_sccpch else 16
    sccpch_n = _parse_int(args.sccpch, "sccpch") if args.sccpch else 2
    if not (1 <= sccpch_n <= MAX_SCCPCH):
        _die(2, "--sccpch %d is outside 1..%d" % (sccpch_n, MAX_SCCPCH),
             "SCCPCH-SystemInformationList ::= SEQUENCE (SIZE (1..maxSCCPCH))")
    tfci = True if args.tfci in (None, "on") else False
    ctch_on = _parse_int(args.ctch_on, "ctch-on") if args.ctch_on is not None else 2
    padded = rlc_octets * 8
    tfs_fach = _tfs(padded, tb, coding, rm)
    tfs_pch = _tfs(padded, tb, "half", rm)
    tfs_ctch = _tfs(padded, tb, coding, rm)
    prach = []
    for _ in range(_parse_int(args.prach, "prach") if args.prach else 1):
        prach.append({"avail_sig": _sig_bits(args.signatures),
                      "sf": _parse_int(args.sf_prach, "sf-prach") if args.sf_prach else 128,
                      "psc": 0, "pl": args.punct or "pl0-44",
                      "avail_sub": _subch_bits(args.subchannels),
                      "trch": 1,
                      "tfs": _tfs(360, 1, "half", 160) if args.rach_tfs else None})
    sccpch = []
    for i in range(1, sccpch_n + 1):
        fach = []
        if i == 1:
            fach = [{"tfs": tfs_fach, "trch": 3, "ctch": False},
                    {"tfs": tfs_pch, "trch": 4, "ctch": False}]
        if i == ctch_on:
            fach.append({"tfs": tfs_ctch, "trch": 6, "ctch": True})
        sccpch.append({"sf": sf_sccpch, "code": i, "sttd": False, "pilot": False,
                       "tfci": tfci, "fixed": True, "ssc": None,
                       "timing_offset": None, "fach": fach,
                       "pich": {"code": 16, "pi": 1, "sttd": False}
                       if i == 1 else None})
    p["prach"] = prach
    p["sccpch"] = sccpch
    p["coding"] = coding
    e = enc_sib5(p)
    rows = [("cli", "sib5")]
    rows.append(("note", "SysInfoType5 describes THIS cell's own FDD carrier: "
                 "PICH/AICH/PRACH/S-CCPCH and the transport formats of the "
                 "FACHs and PCH mapped on each S-CCPCH.  TS 25.331 10.2.1 has "
                 "no frequency information in SysInfoType5, so no "
                 "inter-frequency neighbour can appear here (that is SIB11/SIB12)"))
    rows.append(("note", "FACH coding here is %s (TS 25.212 4.2.3 Table 1 "
                 "allows conv 1/3 and 1/2 for FACH, and turbo 1/3; the PCH "
                 "entry is always conv 1/2 because Table 1 allows only that)"
                 % coding))
    rows.extend(("ref", r) for r in e.refs)
    rows.append(("refused", "TFCS (ExplicitTFCS-Configuration / "
                 "SplitTFCI-Signalling): not encoded, tfcs presence bit 0"))
    rows.append(("refused", "rach-TFCS, prach-Partitioning, "
                 "persistenceScalingFactorList, ac-To-ASC-MappingTable, "
                 "primaryCPICH-TX-Power, constantValue, prach-PowerOffset, "
                 "rach-TransmissionParameters, aich-Info: presence bit 0"))
    rows.append(("refused", "cbs-DRX-Level1Information, "
                 "v4b0NonCriticalExtensions (pNBSCH-Allocation, "
                 "openLoopPowerControl-IPDL-TDD, prach-LCR, tdd128 info, "
                 "frequencyBandIndicator): presence bit 0"))
    rows.append(("refused", "SecondaryCCPCH-Info dummy2 (SecondaryCPICH-Info, "
                 "'not used and should not be sent'), secondaryScramblingCode, "
                 "timingOffset: presence bit 0 unless set"))
    _emit(_finish(e, rows))
    return 0


def _add_entries(specs):
    """Turn repeated --add TYPE[:HEX[:BITS]] into encoded SIB entries."""
    names = specs or ["mib", "sib1", "sib3", "sib5"]
    entries = []
    for spec in names:
        parts = spec.split(":")
        name = parts[0].lower()
        if name not in SIB_ALIAS:
            _die(2, "--add: %r is not a system information block this tool can "
                 "carry" % parts[0],
                 "accepted: %s" % ", ".join(sorted(SIB_ALIAS)))
        if len(parts) >= 2 and parts[1]:
            bits = _parse_hex_bits(parts[1], parts[2] if len(parts) > 2 else None)
        else:
            bits = _sib_encoder(name, _default_params(name)).bits()
        entries.append({"sib": name, "bits": bits})
    return entries


def cmd_si(args):
    entries = _add_entries(args.add)
    tb_bits = _parse_int(args.fach_tb_bits, "fach-tb-bits") if args.fach_tb_bits else 360
    if tb_bits <= 0 or tb_bits % 8:
        _die(2, "--fach-tb-bits %d is not a positive multiple of 8" % tb_bits,
             "a FACH transport block is an integer number of octets")
    pack = args.pack or "one"
    msgs = pack_si(entries, tb_bits, pack)

    rows = [("cli", "si")]
    rows.append(("bsp", "BCCH-FACH: BCCH-FACH-Message ::= SEQUENCE { message "
                 "BCCH-FACH-MessageType }; BCCH-FACH-MessageType ::= CHOICE "
                 "{systemInformation, systemInformationChangeIndication, spare2, "
                 "spare1} -> systemInformation = 0 in the first 2 bits, then "
                 "SystemInformation-FACH"))
    rows.append(("fach_tb_bits", str(tb_bits)))
    rows.append(("pack", pack))
    for ent in entries:
        rows.append(("sib", "%s bits=%d hex=%s"
                     % (ent["sib"], len(ent["bits"]), _bits_hex(ent["bits"]))))
    for i, m in enumerate(msgs):
        seg = m.get("seg") if m["kind"] != "completeSIB-List" else m["entries"]
        e = si_payload_bits(m["kind"], m["ent"], seg)
        rows.append(("ref", "msg[%d] BCCH-FACH-MessageType = 0 -> 00 (2 bits, 4 "
                     "alternatives)  [BCCH-FACH-MessageType ::= CHOICE "
                     "{systemInformation, systemInformationChangeIndication, "
                     "spare2, spare1}]" % i))
        for r in e.refs:
            rows.append(("ref", "msg[%d] %s" % (i, r)))
        bits = si_message_bits(m["kind"], m["ent"], seg)
        pad = (-len(bits)) % 8
        combo = SI_COMBINATION.get(m["kind"], 0)
        rows.append(("msg[%d]" % i, "combination=%d payload=%s sib=%s bits=%d "
                     "octets=%d pad=%d hex=%s"
                     % (combo, m["kind"], m["ent"]["sib"], len(bits),
                        (len(bits) + 7) // 8, pad, _bits_hex(bits))))
        rows.append(("msg[%d].bits" % i, bits))
    total = sum(((len(si_message_bits(m["kind"], m["ent"],
                                      m.get("seg") if m["kind"] != "completeSIB-List"
                                      else m["entries"])) + 7) // 8) * 8
                for m in msgs)
    rows.append(("messages", str(len(msgs))))
    rows.append(("total_octets", str(total // 8)))
    rows.append(("refused", "segment combinations 5 (last+first), 6 "
                 "(last+complete), 7 (last+complete+first) and 9 "
                 "(complete+first) are not produced: --pack one sends one "
                 "segment per message and --pack combine groups only complete "
                 "SIBs, which are combinations 8 and 10/11"))
    rows.append(("refused", "noSegment (combination 1) is not emitted: it means "
                 "the network schedules nothing in that transport block"))
    for lim in LIMITS:
        rows.append(("limit", "%s: %s" % (lim[0], lim[1])))
    _emit(rows)
    return 0


def _parse_hex_bits(h, nbits):
    t = h.replace(" ", "").replace("0x", "")
    if any(c not in "0123456789abcdefABCDEF" for c in t):
        _die(2, "%r is not hex" % h, "")
    bits = "".join(format(int(c, 16), "04b") for c in t)
    if nbits is None:
        return bits
    n = _parse_int(nbits, "bits")
    if n <= 0 or n > len(bits):
        _die(2, "%d bits does not fit the %d bits of hex %r" % (n, len(bits), h), "")
    return bits[:n]


# ---------------------------------------------------------------------------
# The packer: SIBs -> SYSTEM INFORMATION messages -> a FACH transport block ->
# the channel-coded frame an S-CCPCH carries.
#
# This is the phase the catcher model called absent ("no verb packs a SIB onto
# that transport").  The transport is not the BCH -- the BCH carries the MIB
# only (TS 25.212 4.2.13.6) -- it is the BCCH mapped to a FACH, and the FACH is
# mapped to a Secondary CCPCH (TS 25.331 8.1.1.1.2/8.1.1.1.3).  The bits this
# verb prints are exactly what tools/umts_sccpch.py spreads and scrambles.
# ---------------------------------------------------------------------------
# TS 25.211 5.3.3.4 Table 18, the two rows with no pilot and no TFCI field:
# (slot format, SF, data bits per slot, Ndata,* = 15 * data bits per slot)
SCCPCH_FORMATS = {
    256: (0, 256, 20, 300),
    128: (4, 128, 40, 600),
}

PACK_LIMITS = [
    ("transport",
     "the transport is BCCH-FACH on an S-CCPCH, not the BCH: the BCH carries "
     "the MIB only, with one fixed transport format (TS 25.212 4.2.13.6), so "
     "nothing here writes to the BCH chain in tools/umts_bch.py"),
    ("slot-format",
     "only the two S-CCPCH slot formats with no pilot and no TFCI are built "
     "(TS 25.211 5.3.3.4 Table 18 formats 0 and 4).  A TFCI field would need "
     "the (32,10) Reed-Muller code of TS 25.212 4.3, which this tree does not "
     "have, and the release text does not support a pilot field at all"),
    ("transport-block",
     "the FACH transport block size is an RLC attribute carried in SIB5 "
     "(CommonTransChTFS, TS 25.331 10.2.1), so --tb-bits is an input; the "
     "default is the largest block that survives the chain with ndata >= "
     "tb+16, which is what the no-puncturing check in `fach` enforces"),
    ("one-tb-per-tti",
     "one transport block per 10 ms TTI (M1 = 1), so a SYSTEM INFORMATION "
     "message longer than one transport block is a segment (clause 8.1.1.1.3) "
     "and each segment is its own frame -- the packer emits one frame per "
     "segment and does not chain frames into a TTI"),
]


def _timeline(msgs, refs):
    """Place each SYSTEM INFORMATION message on a frame inside the rep cycle.

    One FACH transport block per TTI, so two SIBs may not share a frame: the
    UE decodes one block per 10 ms and a sum of two is neither.  The planner
    walks the blocks in transmission order and gives each the first offset that
    collides with nothing already placed, counting every repetition up to the
    cycle length.  The cycle is the longest repetition period, because every
    other period divides it (they are powers of two).
    """
    rep_of = {r["sib"]: r["rep"][0] for r in refs}
    cycle = max([rep_of.get(m["ent"]["sib"], 16) for m in msgs] or [16])
    free = [True] * cycle
    frames = [None] * cycle
    starts = [None] * len(msgs)
    i = 0
    while i < len(msgs):
        sib = msgs[i]["ent"]["sib"]
        seg = 0
        while i + seg < len(msgs) and msgs[i + seg]["ent"]["sib"] == sib:
            seg += 1
        rep = rep_of.get(sib, 16)
        if rep > cycle:
            _die(1, "internal: %s repeats every %d frames but the cycle is %d"
                 % (sib, rep, cycle))
        place = None
        for o in range(cycle):
            slots = []
            ok = True
            for k in range(0, cycle, rep):
                for j in range(seg):
                    f = (o + k + j) % cycle
                    if not free[f]:
                        ok = False
                        break
                    slots.append((f, i + j))
                if not ok:
                    break
            if ok:
                place = (o, slots)
                break
        if place is None:
            _die(2, "the SIB set does not fit in a %d frame cycle" % cycle,
                 "each block needs %s consecutive frame(s); shorten the set or "
                 "give one of them a longer repetition period" % seg)
        o, slots = place
        for f, idx in slots:
            free[f] = False
            frames[f] = idx
            # the start is the first repetition's offset, not the last frame
            # the planner happened to place: every later slot is +k*rep from it
            if starts[idx] is None:
                starts[idx] = {"start": f, "period": rep, "sib": sib}
        i += seg
    return cycle, frames, starts, rep_of


def cmd_pack(args):
    entries = _add_entries(args.add)
    sf = _parse_int(args.sf, "sf") if args.sf else 256
    if sf not in SCCPCH_FORMATS:
        _die(2, "--sf %d is not an S-CCPCH format this tool builds" % sf,
             "the built rows of TS 25.211 5.3.3.4 Table 18 are SF=256 "
             "(format 0, 20 data bits per slot) and SF=128 (format 4, 40); "
             "every other row carries a TFCI field")
    fmt, sf, per_slot, ndata = SCCPCH_FORMATS[sf]
    rate = {"third": 3, "half": 2}[args.coding or "third"]
    if args.tb_bits:
        tb_bits = _parse_int(args.tb_bits, "tb-bits")
    else:
        tb_bits = ((ndata - CRC_BITS) // 8) * 8
    if tb_bits <= 0 or tb_bits % 8:
        _die(2, "--tb-bits %d is not a positive multiple of 8" % tb_bits,
             "a transport block is an integer number of octets")
    if ndata < tb_bits + CRC_BITS:
        _die(2, "Ndata,* = %d is smaller than the %d bit block plus CRC"
             % (ndata, tb_bits),
             "the FACH chain in this tool does not puncture below its own "
             "input; pick a smaller --tb-bits or the SF=128 slot format")
    pack = args.pack or "one"
    msgs = pack_si(entries, tb_bits, pack)
    rows = [("cli", "pack")]
    timeline = None
    if args.timeline:
        refs = _refs_from_sibs(",".join(e["sib"] for e in entries))
        timeline = _timeline(msgs, refs)
        cycle, frames, starts, rep_of = timeline
    rows.append(("transport",
                 "BCCH -> FACH -> S-CCPCH (TS 25.331 8.1.1.1.2, TS 25.211 "
                 "5.3.3.4); the BCH is not involved"))
    rows.append(("slot_format", "%d -- SF=%d, %d data bits per slot, no "
                 "pilot, no TFCI (TS 25.211 5.3.3.4 Table 18)"
                 % (fmt, sf, per_slot)))
    rows.append(("sf", "%d" % sf))
    rows.append(("ndata_star", "%d" % ndata))
    rows.append(("tb_bits", "%d" % tb_bits))
    rows.append(("coding", "1/%d" % rate))
    rows.append(("pack", pack))
    if timeline:
        rows.append(("schedule.cycle",
                     "%d frames of 10 ms = %d ms (the longest repetition period "
                     "in the set)" % (cycle, cycle * 10)))
        for name in sorted(rep_of):
            rows.append(("schedule.rep", "%s rep=%d (%d frames)"
                         % (name, rep_of[name], rep_of[name])))
        rows.append(("schedule.frames",
                     "%d of %d frames carry a transport block, %d are idle"
                     % (sum(1 for f in frames if f is not None), cycle,
                        sum(1 for f in frames if f is None))))
        for f in range(cycle):
            rows.append(("schedule.frame", "%d %s" % (
                f, "msg[%d] %s" % (frames[f], msgs[frames[f]]["ent"]["sib"])
                if frames[f] is not None else "idle")))
        for idx, st in enumerate(starts):
            if st is not None:
                rows.append(("msg[%d].frame" % idx,
                             "start=%d period=%d sib=%s"
                             % (st["start"], st["period"], st["sib"])))
    for ent in entries:
        rows.append(("sib", "%s bits=%d hex=%s"
                     % (ent["sib"], len(ent["bits"]), _bits_hex(ent["bits"]))))
    for i, m in enumerate(msgs):
        seg = m.get("seg") if m["kind"] != "completeSIB-List" else m["entries"]
        bits = si_message_bits(m["kind"], m["ent"], seg)
        pad = (-len(bits)) % 8
        tb = [int(c) for c in bits] + [0] * pad
        tb_hex = _bits_hex(bits)
        rows.append(("msg[%d].payload" % i,
                     "combination=%d kind=%s sib=%s bits=%d octets=%d pad=%d "
                     "hex=%s" % (SI_COMBINATION.get(m["kind"], 0), m["kind"],
                                 m["ent"]["sib"], len(bits),
                                 (len(bits) + 7) // 8, pad, tb_hex)))
        stage_rows, par = fach_chain(tb, ndata, rate)
        frame_bits = None
        for name, sb, ref, note in stage_rows:
            if name == "ilv2":
                frame_bits = sb
            rows.append(("msg[%d].stage:%s" % (i, name),
                         "%s bits=%d ref=%s -- %s"
                         % (_bits_hex(sb), len(sb), ref, note)))
        rows.append(("msg[%d].rate_match" % i,
                     "Ndata,*=%d Xi=%d dN=%+d e_ini=%d e_plus=%d e_minus=%d"
                     % (par["xi"], par["xi"], par["dn"], par["e_ini"],
                        par["e_plus"], par["e_minus"])))
        if frame_bits is None or len(frame_bits) != ndata:
            _die(1, "internal: message %d produced %s bits, not Ndata,* = %d"
                 % (i, "no" if frame_bits is None else len(frame_bits), ndata))
        fh = _bits_hex(frame_bits)
        fpad = (-len(_bits_str(frame_bits))) % 8
        rows.append(("msg[%d].frame_hex" % i, fh))
        rows.append(("msg[%d].frame_bits" % i, "%d" % len(frame_bits)))
        rows.append(("msg[%d].frame_pad" % i, "%d" % fpad))
    rows.append(("frames", "%d" % len(msgs)))
    if timeline:
        rows.append(("next",
                     "tools/umts_sccpch.py encode --sf %d --code 3 --frames %d "
                     "--frame-hex <msg[i].frame_hex> --at-start <msg[i].frame "
                     "start> --period <msg[i].frame period> --out sccpch_<i>.cf32 "
                     "--format cf32 (one file per message; silence in the frames "
                     "it does not occupy)" % (sf, cycle)))
    else:
        rows.append(("next",
                     "tools/umts_sccpch.py encode --sf %d --code 3 --frame-hex "
                     "<msg[i].frame_hex> --out sccpch.cf32 (one file per frame)"
                     % sf))
    rows.append(("handoff",
                 "the octets and the channel-coded frame end here; the S-CCPCH "
                 "physical layer is tools/umts_sccpch.py and the transmitter is "
                 "modules/08_umts_air.sh --transmit"))
    for key, text in PACK_LIMITS:
        rows.append(("limit", "%s: %s" % (key, text)))
    _emit(rows)
    return 0


def cmd_fach(args):
    bits = _parse_hex_bits(args.tb_hex, args.tb_bits)
    if not bits:
        _die(2, "empty transport block", "")
    coding = args.coding or "third"
    rate = {"third": 3, "half": 2}[coding]
    ndata = _parse_int(args.ndata, "ndata") if args.ndata else 300
    if ndata % FACH_SLOTS:
        _die(2, "Ndata,* = %d is not a multiple of %d slots" % (ndata, FACH_SLOTS),
             "TS 25.212 4.2.7.2 Ndata,* = P*15*(Ndata1+Ndata2), so the number of "
             "data bits of a 10 ms FACH frame divides evenly into 15 slots")
    if ndata < len(bits) + CRC_BITS:
        _die(2, "Ndata,* = %d is smaller than the %d bit transport block plus "
             "CRC" % (ndata, len(bits)), "rate matching cannot puncture below "
             "the number of input bits here; check --ndata")
    rows = [("cli", "fach")]
    rows.append(("tb_hex", args.tb_hex))
    rows.append(("coding", coding))
    rows.append(("ndata_star", str(ndata)))
    rows.append(("param:e_ini_note",
                 "TS 25.212 4.2.7.2.2.2 sets eini = 1, eplus = a*Xi, "
                 "eminus = a*|dN| with a = 2 for convolutional coding"))
    stage_rows, par = fach_chain([int(c) for c in bits], ndata, rate)
    for name, sb, ref, note in stage_rows:
        rows.append(("stage:%s" % name,
                     "%s bits=%d ref=%s -- %s" % (_bits_hex(sb), len(sb), ref, note)))
    for k in ("xi", "dn", "e_ini", "e_plus", "e_minus"):
        rows.append(("param:%s" % k, str(par[k])))
    rows.append(("param:rate", "1/%d" % rate))
    rows.append(("param:tb", str(len(bits))))
    for lim in LIMITS:
        rows.append(("limit", "%s: %s" % (lim[0], lim[1])))
    _emit(rows)
    return 0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def _parser():
    ap = argparse.ArgumentParser(
        prog="umts_sib.py",
        description="RRC SYSTEM INFORMATION on BCCH-FACH (SIB1/SIB3/SIB5) and "
                    "the TS 25.212 FACH transport chain.")
    sub = ap.add_subparsers(dest="verb")

    p = sub.add_parser("list", help="list verbs, limits and conventions")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("mib", help="MasterInformationBlock")
    p.add_argument("--value-tag", type=int)
    p.add_argument("--mcc")
    p.add_argument("--mnc")
    p.add_argument("--schedule", action="append", metavar="SIB:VALUE:REP")
    p.add_argument("--segments", metavar="TB_BITS",
                   help="also split the encoded MIB into BCH transport blocks "
                        "of this size, e.g. 24")
    p.add_argument("--from-sibs", metavar="LIST",
                   help="derive the reference list from the SIBs the cell "
                        "transmits, e.g. sib1,sib3,sib5")
    p.set_defaults(func=cmd_mib)

    p = sub.add_parser("sib1", help="SysInfoType1")
    p.add_argument("--nas", help="cn-CommonGSM-MAP-NAS-SysInfo octets, hex")
    p.add_argument("--cs-nas", help="CS domain NAS octets, hex")
    p.add_argument("--ps-nas", help="PS domain NAS octets, hex")
    p.add_argument("--drx", type=int, help="cn-DRX-CycleLengthCoefficient 6..9")
    p.set_defaults(func=cmd_sib1)

    p = sub.add_parser("sib3", help="SysInfoType3")
    p.add_argument("--cell-id", help="CellIdentity, 28 bit hex or decimal")
    p.add_argument("--sib4", action="store_true")
    p.add_argument("--quality", choices=("ecno", "rscp"))
    p.add_argument("--s-intra", help="S-SearchQual IE (-16..10, actual = IE*2), "
                                     "or off")
    p.add_argument("--s-inter")
    p.add_argument("--s-hcs", help="S-SearchRXLEV IE (-53..45, actual = IE*2+1)")
    p.add_argument("--q-hyst-2", dest="q_hyst_2")
    p.add_argument("--q-qualmin", dest="q_qualmin")
    p.add_argument("--q-rxlevmin", dest="q_rxlevmin")
    p.add_argument("--q-hyst", dest="q_hyst")
    p.add_argument("--t-resel", dest="t_resel")
    p.add_argument("--max-ul", dest="max_ul")
    p.add_argument("--barred", action="store_true")
    p.add_argument("--t-barred", dest="t_barred",
                   help="T-Barred index 0..7 (s10..s1280)")
    p.add_argument("--cell-reserved", dest="cell_reserved", action="store_true")
    p.add_argument("--acb-list", dest="acb_list", help="16 bits AC15..AC0")
    p.set_defaults(func=cmd_sib3)

    p = sub.add_parser("sib5", help="SysInfoType5")
    p.add_argument("--sccpch", help="number of S-CCPCH entries (1..16)")
    p.add_argument("--prach", help="number of PRACH entries (1..16)")
    p.add_argument("--coding", choices=("third", "half"),
                   help="FACH channel coding rate (TS 25.212 4.2.3 Table 1)")
    p.add_argument("--rm", help="RateMatchingAttribute 1..256")
    p.add_argument("--rlc-size", dest="rlc_size", help="FACH RLC size in octets")
    p.add_argument("--tb-tb", dest="tb_tb", help="transport blocks per TTI")
    p.add_argument("--sib6", action="store_true")
    p.add_argument("--pich-offset", dest="pich_offset")
    p.add_argument("--aich-offset", dest="aich_offset")
    p.add_argument("--tfci", choices=("on", "off"))
    p.add_argument("--primary-ccpch", dest="primary_ccpch", action="store_true")
    p.add_argument("--tx-div", dest="tx_div", action="store_true")
    p.add_argument("--sf-sccpch", dest="sf_sccpch", help="4/8/16/.../256")
    p.add_argument("--sf-prach", dest="sf_prach", help="32/64/128/256")
    p.add_argument("--signatures", help="16 bit availableSignatures, signature15 first")
    p.add_argument("--subchannels", help="12 bit availableSubChannelNumbers")
    p.add_argument("--punct", help="PuncturingLimit, e.g. pl0-44 or pl1")
    p.add_argument("--rach-tfs", dest="rach_tfs", action="store_true",
                   help="include rach-TransportFormatSet")
    p.add_argument("--ctch-on", dest="ctch_on",
                   help="S-CCPCH index carrying the CTCH FACH (0 = none)")
    p.set_defaults(func=cmd_sib5)

    p = sub.add_parser("si", help="SYSTEM INFORMATION message(s) for BCCH-FACH")
    p.add_argument("--add", action="append", metavar="TYPE[:HEX[:BITS]]")
    p.add_argument("--fach-tb-bits", dest="fach_tb_bits")
    p.add_argument("--pack", choices=("one", "combine"))
    p.add_argument("--timeline", action="store_true",
                   help="place the messages on frames instead of stacking them "
                        "in one TTI, and print the schedule")
    p.set_defaults(func=cmd_si)

    p = sub.add_parser("pack", help="SIBs onto the FACH transport, whole chain")
    p.add_argument("--add", action="append", metavar="TYPE[:HEX[:BITS]]")
    p.add_argument("--sf", type=str, help="S-CCPCH spreading factor: 256 or 128")
    p.add_argument("--tb-bits", dest="tb_bits",
                   help="transport block size in bits (from SIB5's TFS)")
    p.add_argument("--coding", choices=("third", "half"))
    p.add_argument("--pack", choices=("one", "combine"))
    p.add_argument("--timeline", action="store_true",
                   help="place the messages on frames instead of stacking them "
                        "in one TTI, and print the schedule")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("fach", help="one FACH transport block through TS 25.212")
    p.add_argument("--tb-hex", dest="tb_hex", required=True)
    p.add_argument("--tb-bits", dest="tb_bits")
    p.add_argument("--coding", choices=("third", "half"))
    p.add_argument("--ndata")
    p.add_argument("--sf")
    p.set_defaults(func=cmd_fach)
    return ap


def main(argv):
    ap = _parser()
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
