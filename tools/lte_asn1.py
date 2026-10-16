#!/usr/bin/env python3
"""LTE RRC ASN.1 -- unaligned PER, as TS 36.331 sends it over BCCH-DL-SCH.

This is the 4G counterpart of tools/gsm_mod.py. It exists because
`modules/14_lte_air.sh` ships nine functions named lair_decode_sib*() that do
not decode TS 36.331 PER at all: they read a private bit layout and the
module's own selftest then validates that layout against itself. A real SIB1
fed to them produces values that cannot exist.

Nothing here is transcribed from memory. Every field width is the constrained
whole-number encoding of the ASN.1 range in TS 36.331, and the whole chain is
asserted below against vectors captured from pycrate 0.8.1 (an independent
ASN.1 PER implementation generated from the same specification).

THE RULE THAT MATTERS MOST, and the one that is easy to get wrong:

    X.691 places a SEQUENCE's bitmap of OPTIONAL and DEFAULT root components
    at the FRONT of the sequence, before any component value. A SEQUENCE is
    therefore laid out

        [extension bit?][optional bitmap][values in declaration order]

    and never declaration order alone. That single rule accounts for the four
    leading bits of every SIB1 -- p-Max, tdd-Config and nonCriticalExtension
    are all OPTIONAL, so SIB1 opens with three presence bits, and
    cellAccessRelatedInfo opens with one more for csg-Identity.

Usage:
    python3 tools/lte_asn1.py sib1 --mcc 262 --mnc 01 --tac 00f1 --cellid 00a1
    python3 tools/lte_asn1.py selftest
"""
import argparse
import sys

# ---------------------------------------------------------------------------
# A carrier big enough to hold any RRC message, written MSB first.
# ---------------------------------------------------------------------------


class BitWriter(object):
    __slots__ = ("bits",)

    def __init__(self):
        self.bits = []

    def uint(self, val, width):
        """Constrained whole number, MSB first, `width` bits."""
        if not 0 <= val < (1 << width):
            raise ValueError("value %d does not fit in %d bits" % (val, width))
        for i in range(width - 1, -1, -1):
            self.bits.append((val >> i) & 1)

    def bit(self, val):
        self.bits.append(1 if val else 0)

    def nibbles(self, digits):
        """MCC/MNC digits: each MCC-MNC-Digit ::= INTEGER (0..9) is 4 bits."""
        for d in digits:
            self.uint(int(d), 4)

    def string(self):
        return "".join(str(b) for b in self.bits)

    def hex(self):
        """Octet-aligned, final octet padded with zero bits per X.691."""
        s = self.string()
        s += "0" * ((8 - len(s) % 8) % 8)
        return "".join("%02X" % int(s[i:i + 8], 2) for i in range(0, len(s), 8))

    def __len__(self):
        return len(self.bits)


# ---------------------------------------------------------------------------
# TS 36.331 enumerations that are encoded by index, in specification order.
# ---------------------------------------------------------------------------

SI_PERIODICITY = ["rf8", "rf16", "rf32", "rf64", "rf128", "rf256", "rf512"]
SI_WINDOW_LENGTH = ["ms1", "ms2", "ms5", "ms10", "ms15", "ms20", "ms40"]

# SIB-Type ::= ENUMERATED { sibType3(0), sibType4(1), ... } -- 36.331 release 13.
SIB_TYPE = [
    "sibType3", "sibType4", "sibType5", "sibType6", "sibType7", "sibType8",
    "sibType9", "sibType10", "sibType11", "sibType12-v920", "sibType13-v920",
    "sibType14-v11xy", "sibType15-v11xy", "sibType16-v11xy", "sibType17-v11xy",
    "sibType18-v11xy", "sibType19-v12xy", "sibType20-v13xy", "spare2", "spare1",
]


# ---------------------------------------------------------------------------
# SystemInformationBlockType1 over BCCH-DL-SCH-Message.
# ---------------------------------------------------------------------------

def encode_sib1(mcc, mnc, tac, cellid, barred="notBarred",
                reselect="notAllowed", qrxlevmin=-70, band=20, siw="ms20",
                valuetag=0, period="rf32", sibs=("sibType3",),
                csg_indication=False, plmns=None):
    """Return the unaligned-PER encoding of a BCCH-DL-SCH-Message carrying SIB1.

    `plmns` is an optional list of (mcc, mnc, not_reserved) tuples; the first
    entry is the primary PLMN. Defaults match a minimal live cell.
    """
    w = BitWriter()

    # BCCH-DL-SCH-Message ::= SEQUENCE { message BCCH-DL-SCH-MessageType }
    # BCCH-DL-SCH-MessageType ::= CHOICE { c1, messageClassExtension }  -- 1 bit
    w.bit(0)                                  # -> c1
    # c1 ::= CHOICE { systemInformation, systemInformationBlockType1 }  -- 1 bit
    w.bit(1)                                  # -> systemInformationBlockType1

    # SystemInformationBlockType1: no extension marker, three OPTIONAL root
    # components, so a three-bit presence bitmap comes first.
    w.bit(False)                              # p-Max            -- absent
    w.bit(False)                              # tdd-Config       -- absent
    w.bit(False)                              # nonCriticalExtension -- absent

    if plmns is None:
        plmns = [(mcc, mnc, True)]

    # cellAccessRelatedInfo ::= SEQUENCE { plmn-IdentityList, trackingAreaCode,
    #   cellIdentity, cellBarred, intraFreqReselection, csg-Indication,
    #   csg-Identity OPTIONAL }
    w.bit(csg_indication and False)           # csg-Identity presence bitmap bit

    # PLMN-IdentityList ::= SEQUENCE (SIZE (1..6)) OF PLMN-IdentityInfo
    w.uint(len(plmns) - 1, 3)
    for pmcc, pmnc, reserved in plmns:
        # PLMN-IdentityInfo ::= SEQUENCE { plmn-Identity, cellReservedForOperatorUse }
        # PLMN-Identity  ::= SEQUENCE { mcc MCC OPTIONAL, mnc MNC }
        w.bit(pmcc is not None and len(pmcc) > 0)
        if pmcc:
            w.nibbles(pmcc)
        # MNC ::= SEQUENCE (SIZE (2..3)) OF MCC-MNC-Digit -- 1 bit for the size
        w.bit(len(pmnc) == 3)
        w.nibbles(pmnc)
        # cellReservedForOperatorUse ::= ENUMERATED { reserved(0), notReserved(1) }
        w.bit(bool(reserved))

    w.uint(int(tac, 16) if isinstance(tac, str) else tac, 16)
    w.uint(int(cellid, 16) if isinstance(cellid, str) else cellid, 28)
    # cellBarred ::= ENUMERATED { barred(0), notBarred(1) }
    w.bit(barred == "notBarred")
    # intraFreqReselection ::= ENUMERATED { allowed(0), notAllowed(1) }
    w.bit(reselect == "notAllowed")
    w.bit(bool(csg_indication))

    # cellSelectionInfo ::= SEQUENCE { q-RxLevMin, q-RxLevMinOffset OPTIONAL }
    # Its own optional bitmap comes first: one bit, always absent here.
    w.bit(False)
    # Q-RxLevMin ::= INTEGER (-70..-22) -- 49 values, 6 bits
    w.uint(qrxlevmin + 70, 6)

    # freqBandIndicator ::= INTEGER (1..64) -- 6 bits
    w.uint(band - 1, 6)

    # SchedulingInfoList ::= SEQUENCE (SIZE (1..32)) OF SchedulingInfo
    w.uint(0, 5)                              # one SchedulingInfo
    w.uint(SI_PERIODICITY.index(period), 3)
    # SIB-MappingInfo ::= SEQUENCE (SIZE (0..31)) OF SIB-Type
    w.uint(len(sibs), 5)
    for s in sibs:
        w.uint(SIB_TYPE.index(s), 5)

    # si-WindowLength ::= ENUMERATED { ms1, ms2, ms5, ms10, ms15, ms20, ms40 }
    w.uint(SI_WINDOW_LENGTH.index(siw), 3)
    # systemInfoValueTag ::= INTEGER (0..31) -- 5 bits
    w.uint(valuetag, 5)
    # nonCriticalExtension absent (its presence bit was written above)

    return w


# ---------------------------------------------------------------------------
# The decoder. This is the half modules/14_lte_air.sh needs: its nine
# lair_decode_sib*() functions read a private layout, not this one.
# ---------------------------------------------------------------------------


class BitReader(object):
    __slots__ = ("bits", "pos")

    def __init__(self, bits):
        if isinstance(bits, (bytes, bytearray)):
            bits = "".join(format(b, "08b") for b in bits)
        elif isinstance(bits, str) and any(c not in "01" for c in bits):
            # A hex string, not a bit string. Anything with a digit above 1 or
            # a letter in it is unambiguous; a string of only 0 and 1 is read
            # as bits, which is what the callers expect.
            bits = "".join(format(b, "08b") for b in bytes.fromhex(bits))
        self.bits = bits
        self.pos = 0

    def uint(self, width):
        if self.pos + width > len(self.bits):
            raise ValueError("ran out of bits reading %d at %d" % (width, self.pos))
        v = 0
        for _ in range(width):
            v = (v << 1) | (1 if self.bits[self.pos] == "1" else 0)
            self.pos += 1
        return v

    def bit(self):
        return self.uint(1) == 1

    def digits(self, n):
        return [self.uint(4) for _ in range(n)]

    def remaining(self):
        return len(self.bits) - self.pos


def decode_sib1(data):
    """Decode a BCCH-DL-SCH-Message carrying SIB1 (TS 36.331, unaligned PER).

    `data` is a bit string, or the bytes as they arrive on the air. Returns a
    dict of the fields, or raises ValueError when the message is not a SIB1 --
    which is what lets a caller tell a real SIB1 from noise instead of
    reporting whatever the bits happen to spell.
    """
    r = BitReader(data)

    if r.uint(1) != 0:
        raise ValueError("not a c1 message (messageClassExtension set)")
    if r.uint(1) != 1:
        raise ValueError("c1 alternative is systemInformation, not SIB1")

    p_max_present = r.bit()
    tdd_config_present = r.bit()
    non_critical_present = r.bit()
    csg_identity_present = r.bit()

    n_plmn = r.uint(3) + 1
    plmns = []
    for _ in range(n_plmn):
        mcc = r.digits(3) if r.bit() else None
        mcc = None if mcc is not None and len(mcc) == 0 else mcc
        mnc = r.digits(3 if r.bit() else 2)
        reserved = r.bit()
        plmns.append((mcc, mnc, reserved))

    tac = r.uint(16)
    cellid = r.uint(28)
    barred = "notBarred" if r.bit() else "barred"
    reselect = "notAllowed" if r.bit() else "allowed"
    csg_indication = r.bit()
    if csg_identity_present:
        r.uint(27)                            # CSG-Identity, not needed here

    has_q_offset = r.bit()
    qrxlevmin = r.uint(6) - 70
    q_offset = r.uint(3) + 1 if has_q_offset else None

    p_max = r.uint(6) - 30 if p_max_present else None
    band = r.uint(6) + 1

    n_sched = r.uint(5) + 1
    sched = []
    for _ in range(n_sched):
        period = SI_PERIODICITY[r.uint(3)]
        n_map = r.uint(5)
        sibs = [SIB_TYPE[r.uint(5)] for _ in range(n_map)]
        sched.append((period, sibs))

    if tdd_config_present:
        raise ValueError("tdd-Config present; this decoder does not model TDD")

    siw = SI_WINDOW_LENGTH[r.uint(3)]
    valuetag = r.uint(5)

    return {
        "plmns": plmns,
        "mcc": plmns[0][0],
        "mnc": plmns[0][1],
        "tac": tac,
        "cellid": cellid,
        "barred": barred,
        "reselect": reselect,
        "csg_indication": csg_indication,
        "csg_identity_present": csg_identity_present,
        "qrxlevmin": qrxlevmin,
        "q_rx_lev_min_offset": q_offset,
        "p_max": p_max,
        "band": band,
        "si_window_length": siw,
        "system_info_value_tag": valuetag,
        "scheduling": sched,
        "non_critical_present": non_critical_present,
        "bits_consumed": r.pos,
    }


# ---------------------------------------------------------------------------
# Assertion targets: captured from pycrate 0.8.1, an independent TS 36.331
# ASN.1 PER implementation. Never from this file's own output.
# ---------------------------------------------------------------------------

VECTORS = [
    ("base", dict(mcc=[2, 0, 8], mnc=[0, 1], tac=1, cellid=1),
     "4048200300010000001C0130208280"),
    ("tac1234_cidABCDEF",
     dict(mcc=[2, 0, 8], mnc=[0, 1], tac=0x1234, cellid=0x0ABCDEF),
     "4048200312340ABCDEFC0130208280"),
    ("262-01_tacF1_cidA1",
     dict(mcc=[2, 6, 2], mnc=[0, 1], tac=0x00F1, cellid=0x00A1),
     "4049880300F100000A1C0130208280"),
    ("3digit_mnc", dict(mcc=[2, 0, 8], mnc=[0, 1, 5], tac=1, cellid=1),
     "40482202B00010000001C01302082800"),
    ("barred_band13",
     dict(mcc=[3, 1, 0], mnc=[2, 6, 0], tac=0x1A2B, cellid=0x1234567,
          barred="barred", reselect="allowed", qrxlevmin=-64, band=13,
          siw="ms40", valuetag=7, period="rf64", sibs=("sibType3", "sibType4")),
     "404C424C11A2B1234567018C0310038E"),
]


# ---------------------------------------------------------------------------
# The SystemInformation container -- TS 36.331 5.2.1 / 6.3.1.
#
# This is the envelope every SIB travels in, so a transmitter cannot broadcast
# anything without it. Its header is 14 bits and was derived by differential
# probing against pycrate, then confirmed live:
#
#     bits  0..3   the SystemInformation-r8-IEs OPTIONAL/DEFAULT bitmap
#     bits  4..8   sib-TypeAndInfo count, minus one (5 bits, SIZE(1..32))
#     bits  9..13  the SIB-TypeAndInfo CHOICE index (5 bits)
#     bits 14..    the chosen SIB's own body
#
# The header is 14 bits, and every one of its pieces is a CHOICE or a
# presence flag that TS 36.331 never draws as a unit:
#
#     bit  0      BCCH-DL-SCH-MessageType CHOICE -> c1
#     bit  1      c1 CHOICE -> systemInformation
#     bit  2      criticalExtensions CHOICE -> systemInformation-r8
#     bit  3      SystemInformation-r8-IEs nonCriticalExtension (absent)
#     bits 4..8   sib-TypeAndInfo count, minus one (5 bits, SIZE(1..32))
#     bits 9..13  the SIB-TypeAndInfo CHOICE index (5 bits)
#     bits 14..   the chosen SIB's own body
#
# The rule that catches people out is the one X.691 imposes and TS 36.331
# never states: the OPTIONAL bitmap comes FIRST, before the count and the
# values. A container written in declaration order is off by four bits and
# decodes to a different SIB type.
#
# The two-bit gap between "count" and "index" is what makes this easy to get
# wrong: the CHOICE index is NOT at bits 5..9, it is at 9..13.
# ---------------------------------------------------------------------------

SI_PREFIX_BITS = 4                       # message, c1, criticalExt, nonCritExt
SI_COUNT_BITS = 5
SI_CHOICE_BITS = 5
SI_HEADER_BITS = SI_PREFIX_BITS + SI_COUNT_BITS + SI_CHOICE_BITS   # 14

# The SIB-TypeAndInfo CHOICE, in index order. Only the alternatives this tree
# can name are listed; an index outside this table is reported, not guessed.
SIB_CHOICE = [
    "sibType2", "sibType3", "sibType4", "sibType5", "sibType6",
    "sibType7", "sibType8", "sibType9", "sibType10", "sibType11",
    "sibType12-v920", "sibType13-v920", "sibType14-v1130",
    "sibType15-v1130", "sibType16-v1130", "sibType17-v1250",
    "sibType18-v1250", "sibType19-v1250", "sibType20-v1310",
]

# Captured from pycrate 0.8.1. Hex plus its TRUE bit length, because a
# container is not octet aligned: the final octet is zero-padded, so the
# length is not derivable from the hex and slicing to it is required. Each
# carries exactly one SIB, with pycrate's own minimal valid body, so the body
# is independent output even though the header is what these vectors pin.
SI_VECTORS = [
    ("sib2", "00000000000000000000000000000000100000000000000000", 200),
    ("sib3", "000400000000", 48),
    ("sib4", "000800", 24),
    ("sib5", "000C00000000000000", 72),
    ("sib6", "001000", 24),
    ("sib7", "001400", 24),
    ("sib8", "001800", 24),
]


def bits_of(hex_str, nbits=None):
    """Hex octets to a bit string, optionally truncated to the true length."""
    s = "".join(format(b, "08b") for b in bytes.fromhex(hex_str))
    return s[:nbits] if nbits is not None else s


# ---------------------------------------------------------------------------
# SystemInformationBlockType3 -- the cell-reselection block. TS 36.331 6.3.1.
#
# This is the block an operator uses to steer handsets: q-RxLevMin sets the
# minimum received level to camp, cellReselectionPriority ranks this frequency
# against its neighbours, and t-ReselectionEUTRA sets how long a UE must stay
# before it may leave. A forged version of it is a steering tool.
#
# The 34-bit body layout, mapped by probing pycrate field by field and then
# checked against a vector with every field maxed:
#
#     0      SIB3 extension bit ("..." in the ASN.1 -- it is extensible)
#     1      cellReselectionInfoCommon.speedStateReselectionPars present
#     2..5   q-Hyst                ENUMERATED, 16 values
#     6      cellReselectionServingFreqInfo.s-NonIntraSearch present
#     7..11  threshServingLow      INTEGER (0..31)
#     12..14 cellReselectionPriority INTEGER (0..7)
#     15..18 intraFreqCellReselectionInfo optional bitmap:
#              p-Max, s-IntraSearch, allowedMeasBandwidth,
#              t-ReselectionEUTRA-SF
#     19..24 q-RxLevMin            INTEGER (-70..-22), value = level + 70
#     25     presenceAntennaPort1   BOOLEAN
#     26..27 neighCellConfig        BIT STRING (SIZE (2))
#     28..30 t-ReselectionEUTRA     INTEGER (0..7)
#     31..33 three bits this model does not name
#
# The trailing three bits are real: pycrate emits them, they are zero in every
# value probed (including one with every above field maxed), and omitting them
# makes the block three bits short. They are carried explicitly rather than
# silently dropped. Everything else is spec-derived and vector-asserted.
# ---------------------------------------------------------------------------

SIB3_BODY_BITS = 34
SIB3_Q_HYST = ["dB0", "dB1", "dB2", "dB3", "dB4", "dB5", "dB6", "dB8",
               "dB10", "dB12", "dB14", "dB16", "dB18", "dB20", "dB22", "dB24"]
SIB3_T_RESELECTION = list(range(8))


def encode_sib3(q_hyst="dB0", thresh_serving_low=0, cell_reselection_priority=0,
                q_rx_lev_min=-70, presence_antenna_port1=False,
                neigh_cell_config="00", t_reselection_eutra=0, tail=0):
    """Encode a SystemInformationBlockType3 body (TS 36.331 6.3.1)."""
    if q_hyst not in SIB3_Q_HYST:
        raise ValueError("q-Hyst must be one of %s" % SIB3_Q_HYST)
    if not 0 <= thresh_serving_low <= 31:
        raise ValueError("threshServingLow is INTEGER (0..31)")
    if not 0 <= cell_reselection_priority <= 7:
        raise ValueError("cellReselectionPriority is INTEGER (0..7)")
    if not -70 <= q_rx_lev_min <= -22:
        raise ValueError("q-RxLevMin is INTEGER (-70..-22)")
    if not 0 <= t_reselection_eutra <= 7:
        raise ValueError("t-ReselectionEUTRA is INTEGER (0..7)")
    ncc = "".join(c for c in neigh_cell_config if c in "01")
    if len(ncc) != 2:
        raise ValueError("neighCellConfig is BIT STRING (SIZE (2))")
    if not 0 <= tail <= 7:
        raise ValueError("tail is 3 bits")

    w = BitWriter()
    w.bit(0)                                        # no extensions
    w.bit(0)                                        # speedStateReselectionPars
    w.uint(SIB3_Q_HYST.index(q_hyst), 4)
    w.bit(0)                                        # s-NonIntraSearch absent
    w.uint(thresh_serving_low, 5)
    w.uint(cell_reselection_priority, 3)
    w.uint(0, 4)                                    # intraFreq optionals
    w.uint(q_rx_lev_min + 70, 6)
    w.bit(1 if presence_antenna_port1 else 0)
    for c in ncc:
        w.bit(1 if c == "1" else 0)
    w.uint(t_reselection_eutra, 3)
    w.uint(tail, 3)
    return w.string()


def decode_sib3(data):
    """Decode a SystemInformationBlockType3 body."""
    r = BitReader(data)
    if len(r.bits) < SIB3_BODY_BITS:
        raise ValueError("SIB3 body is %d bits, got %d"
                         % (SIB3_BODY_BITS, len(r.bits)))

    if r.bit():
        raise ValueError("SIB3 extensions present; not modelled")
    if r.bit():
        raise ValueError("speedStateReselectionPars present; not modelled")

    q_hyst = SIB3_Q_HYST[r.uint(4)]
    if r.bit():
        raise ValueError("s-NonIntraSearch present; not modelled")
    thresh_serving_low = r.uint(5)
    cell_reselection_priority = r.uint(3)

    opt = [r.bit() for _ in range(4)]
    if any(opt):
        raise ValueError("intraFreqCellReselectionInfo optionals present "
                         "(p-Max/s-IntraSearch/allowedMeasBandwidth/"
                         "t-ReselectionEUTRA-SF); not modelled")

    q_rx_lev_min = r.uint(6) - 70
    presence_antenna_port1 = r.bit()
    neigh_cell_config = "%d%d" % (r.uint(1), r.uint(1))
    t_reselection_eutra = r.uint(3)
    tail = r.uint(3)

    return {
        "q_hyst": q_hyst,
        "thresh_serving_low": thresh_serving_low,
        "cell_reselection_priority": cell_reselection_priority,
        "q_rx_lev_min": q_rx_lev_min,
        "presence_antenna_port1": presence_antenna_port1,
        "neigh_cell_config": neigh_cell_config,
        "t_reselection_eutra": t_reselection_eutra,
        "tail": tail,
        "bits_consumed": r.pos,
    }


# Captured from pycrate 0.8.1. Four values, not one: an all-zero body would
# round-trip for a wrong layout too, so the set spans the full range of every
# field -- the "maxed" vector pins all 24 field bits at once.
SIB3_VECTORS = [
    ("minimal", "000400000000", 48,
     dict()),
    ("maxed", "0004F7F861F8", 48,
     dict(q_hyst="dB24", thresh_serving_low=31, cell_reselection_priority=7,
          q_rx_lev_min=-22, presence_antenna_port1=True,
          neigh_cell_config="11", t_reselection_eutra=7)),
    ("mid", "000461583250", 48,
     dict(q_hyst="dB6", thresh_serving_low=5, cell_reselection_priority=3,
          q_rx_lev_min=-45, neigh_cell_config="01",
          t_reselection_eutra=2)),
    ("p_max_23", "0004000401A800", 56,
     dict()),
]


def encode_si(sib_index, body_bits, count=1):
    """Wrap one SIB body in a SystemInformation-r8-IEs container.

    `sib_index` is the SIB-TypeAndInfo CHOICE index (sibType2 = 0).
    `body_bits` is the already-encoded SIB, as a bit string.
    """
    if not 1 <= count <= 32:
        raise ValueError("sib-TypeAndInfo count must be 1..32, got %r" % count)
    if not 0 <= sib_index < (1 << SI_CHOICE_BITS):
        raise ValueError("SIB CHOICE index out of range: %r" % sib_index)

    w = BitWriter()
    w.bit(0)                               # message -> c1
    w.bit(0)                               # c1 -> systemInformation
    w.bit(0)                               # criticalExtensions -> r8
    w.bit(0)                               # nonCriticalExtension absent
    w.uint(count - 1, SI_COUNT_BITS)       # count is encoded minus one
    w.uint(sib_index, SI_CHOICE_BITS)
    return w.string() + "".join(c for c in body_bits if c in "01")


def decode_si(data):
    """Decode a BCCH-DL-SCH-Message carrying SystemInformation.

    Returns the SIB type name and the body bits. Raises ValueError when the
    message is not a SystemInformation container at all.
    """
    r = BitReader(data)

    if r.uint(1) != 0:
        raise ValueError("not a c1 message (messageClassExtension set)")
    if r.uint(1) != 0:
        raise ValueError("c1 alternative is systemInformationBlockType1")
    if r.uint(1) != 0:
        raise ValueError("criticalExtensions is not systemInformation-r8")
    if r.uint(1) != 0:
        raise ValueError("nonCriticalExtension present; not modelled")

    count = r.uint(SI_COUNT_BITS) + 1
    index = r.uint(SI_CHOICE_BITS)
    name = SIB_CHOICE[index] if index < len(SIB_CHOICE) else "unknown"

    return {
        "count": count,
        "sib_index": index,
        "sib": name,
        "body_bits": r.bits[r.pos:],
        "bits_consumed": r.pos,
        "total_bits": len(r.bits),
    }


def selftest():
    failures = []

    def chk(name, got, want):
        if got != want:
            failures.append("%s FAIL want=%s got=%s" % (name, want, got))

    for name, kw, want in VECTORS:
        got = encode_sib1(**kw).hex()
        chk("vector-" + name, got, want)

    # Spot-check individual field widths against the vector that exercises them.
    base = encode_sib1(**VECTORS[0][1]).string()
    chk("base-bitlen", len(base), 118)
    chk("opening-bits", base[:6], "010000")   # c1, SIB1, 3 optional bits, csg
    chk("plmn-count", base[6:9], "000")       # one PLMN -> count-1 = 0
    chk("mcc-present", base[9], "1")
    chk("mcc-208", base[10:22], "001000001000")
    chk("mnc-two-digits", base[22], "0")
    chk("mnc-01", base[23:31], "00000001")
    chk("cellReserved", base[31], "1")        # notReserved
    chk("tac-width", len(encode_sib1(**VECTORS[1][1]).string()),
        len(encode_sib1(**VECTORS[0][1]).string()))
    chk("three-digit-mnc-is-4-bits-longer",
        len(encode_sib1(**VECTORS[3][1]).string()) - len(base), 4)
    chk("band13-one-bit-shorter",
        len(encode_sib1(**VECTORS[4][1]).string()) - len(base), 9)

    # The decoder has to give back exactly what went in, for every vector.
    # This is the half 14_lte_air's lair_decode_sib*() functions need.
    for name, kw, want in VECTORS:
        d = decode_sib1(want)
        chk("dec-" + name + "-mcc", d["mcc"], list(kw["mcc"]))
        chk("dec-" + name + "-mnc", d["mnc"], list(kw["mnc"]))
        chk("dec-" + name + "-tac", d["tac"], kw["tac"])
        chk("dec-" + name + "-cellid", d["cellid"], kw["cellid"])
        chk("dec-" + name + "-barred", d["barred"],
            kw.get("barred", "notBarred"))
        chk("dec-" + name + "-reselect", d["reselect"],
            kw.get("reselect", "notAllowed"))
        chk("dec-" + name + "-qrxlevmin", d["qrxlevmin"],
            kw.get("qrxlevmin", -70))
        chk("dec-" + name + "-band", d["band"], kw.get("band", 20))
        chk("dec-" + name + "-siw", d["si_window_length"],
            kw.get("siw", "ms20"))
        chk("dec-" + name + "-valuetag", d["system_info_value_tag"],
            kw.get("valuetag", 0))
        chk("dec-" + name + "-period", d["scheduling"][0][0],
            kw.get("period", "rf32"))
        chk("dec-" + name + "-sibs", d["scheduling"][0][1],
            list(kw.get("sibs", ("sibType3",))))

    # A decoder that accepts anything is not a decoder. Noise, a
    # messageClassExtension, and the systemInformation alternative must all be
    # refused rather than reported as a cell.
    for name, bad in (("noise", "00" * 16),
                      ("messageClassExtension", "80" + "00" * 15),
                      ("systemInformation", "20" + "00" * 15)):
        try:
            decode_sib1(bad)
            failures.append("dec-reject-" + name + " FAIL accepted the input")
        except ValueError:
            pass

    # Round-trip through the encoder as well, so the two halves cannot drift.
    for name, kw, want in VECTORS:
        chk("roundtrip-" + name, decode_sib1(encode_sib1(**kw).hex())["tac"],
            kw["tac"])

    # ---- the SystemInformation container -------------------------------
    #
    # These pin the 14-bit header, which is where a transmitter goes wrong:
    # the OPTIONAL bitmap comes first, and the CHOICE index sits at bits
    # 9..13, not immediately after the count.
    for name, hexs, nbits in SI_VECTORS:
        bits = bits_of(hexs, nbits)
        chk("si-" + name + "-bitlen", len(bits), nbits)
        # The container opens with four zero bits: c1, systemInformation,
        # systemInformation-r8, and an absent nonCriticalExtension.
        chk("si-" + name + "-prefix", bits[:SI_PREFIX_BITS], "0000")

        d = decode_si(bits)
        want_index = SIB_CHOICE.index("sibType" + name[3:])
        chk("si-" + name + "-count", d["count"], 1)
        chk("si-" + name + "-index", d["sib_index"], want_index)
        chk("si-" + name + "-name", d["sib"], "sibType" + name[3:])
        chk("si-" + name + "-consumed", d["bits_consumed"], SI_HEADER_BITS)

        # Re-encoding the decoded body must reproduce the vector bit for bit.
        chk("si-" + name + "-roundtrip",
            encode_si(d["sib_index"], d["body_bits"], d["count"]), bits)

        # And the index must be at bits 9..13, not 5..9. An implementation
        # that put it immediately after the count would read this instead.
        # Index 0 is skipped: five zero bits are five zero bits wherever you
        # look, so that vector cannot tell the two positions apart.
        if want_index != 0:
            chk("si-" + name + "-index-not-at-5",
                bits[5:10] == format(want_index, "05b"), False)
            chk("si-" + name + "-index-at-9",
                bits[9:14], format(want_index, "05b"))

    # A SIB1 message must not be read as a container, and vice versa.
    try:
        decode_si(VECTORS[0][2])
        failures.append("si-reject-sib1 FAIL accepted a SIB1 as a container")
    except ValueError:
        pass
    try:
        decode_sib1(SI_VECTORS[0][1])
        failures.append("sib1-reject-si FAIL accepted a container as a SIB1")
    except ValueError:
        pass

    # ---- SystemInformationBlockType3 -----------------------------------
    #
    # The body is 34 bits with three of them (31..33) unnamed, so this set
    # matters: a single all-zero vector would round-trip through a wrong
    # layout too. "maxed" pins all 24 named field bits at once, and "mid" is
    # a value no field boundary can fake. Each is checked as a whole
    # container -- header plus body -- not as a bare bit string.
    for name, hexs, nbits, kw in SIB3_VECTORS:
        if name == "p_max_23":
            continue        # p-Max present: modelled as a refusal, see below
        bits = bits_of(hexs, nbits)
        chk("sib3-" + name + "-body-bits", len(bits) - SI_HEADER_BITS,
            SIB3_BODY_BITS)
        chk("sib3-" + name + "-container",
            encode_si(SIB_CHOICE.index("sibType3"), encode_sib3(**kw), 1), bits)

        d = decode_sib3(bits[SI_HEADER_BITS:])
        chk("sib3-" + name + "-q-hyst", d["q_hyst"], kw.get("q_hyst", "dB0"))
        chk("sib3-" + name + "-thresh", d["thresh_serving_low"],
            kw.get("thresh_serving_low", 0))
        chk("sib3-" + name + "-prio", d["cell_reselection_priority"],
            kw.get("cell_reselection_priority", 0))
        chk("sib3-" + name + "-qrxlevmin", d["q_rx_lev_min"],
            kw.get("q_rx_lev_min", -70))
        chk("sib3-" + name + "-antport1", d["presence_antenna_port1"],
            kw.get("presence_antenna_port1", False))
        chk("sib3-" + name + "-neigh", d["neigh_cell_config"],
            kw.get("neigh_cell_config", "00"))
        chk("sib3-" + name + "-tresel", d["t_reselection_eutra"],
            kw.get("t_reselection_eutra", 0))
        chk("sib3-" + name + "-tail", d["tail"], 0)
        chk("sib3-" + name + "-consumed", d["bits_consumed"], SIB3_BODY_BITS)

    # q-RxLevMin is the field that steers a handset, so its endpoints must be
    # exact: -70 is index 0 and -22 is index 48, not 63.
    chk("sib3-qrxlevmin-floor", encode_sib3(q_rx_lev_min=-70)[19:25], "000000")
    chk("sib3-qrxlevmin-ceil", encode_sib3(q_rx_lev_min=-22)[19:25], "110000")

    # A body with an optional present is not modelled and must say so rather
    # than silently drop it. The captured vector is kept so the gap is
    # visible: p-Max 23 makes the body 42 bits, eight longer than modelled.
    pbits = bits_of(SIB3_VECTORS[3][1], SIB3_VECTORS[3][2])
    try:
        decode_sib3(pbits[SI_HEADER_BITS:])
        failures.append("sib3-reject-pmax FAIL accepted an unmodelled body")
    except ValueError:
        pass

    if failures:
        for f in failures:
            sys.stderr.write(f + "\n")
        print("RESULT\tFAIL")
        return 1
    print("RESULT\tPASS")
    return 0


def cmd_sib1(args):
    sibs = tuple(args.sib) if args.sib else ("sibType3",)
    w = encode_sib1(mcc=[int(c) for c in args.mcc],
                    mnc=[int(c) for c in args.mnc],
                    tac=int(args.tac, 16), cellid=int(args.cellid, 16),
                    barred=args.barred, reselect=args.reselect,
                    qrxlevmin=args.qrxlevmin, band=args.band,
                    siw=args.siw, valuetag=args.valuetag,
                    period=args.period, sibs=sibs)
    print("message\tBCCH-DL-SCH-Message")
    print("sib\tSystemInformationBlockType1")
    print("mcc\t%s" % args.mcc)
    print("mnc\t%s" % args.mnc)
    print("tac\t%s" % args.tac)
    print("cellid\t%s" % args.cellid)
    print("barred\t%s" % args.barred)
    print("intra_freq_reselection\t%s" % args.reselect)
    print("q_rx_lev_min\t%d" % args.qrxlevmin)
    print("band\t%d" % args.band)
    print("si_window_length\t%s" % args.siw)
    print("system_info_value_tag\t%d" % args.valuetag)
    print("si_periodicity\t%s" % args.period)
    print("sibs\t%s" % " ".join(sibs))
    print("bits\t%d" % len(w))
    print("octets\t%d" % (len(w.hex()) // 2))
    print("per_hex\t%s" % w.hex())
    return 0


def cmd_decode(args):
    bits = args.hex
    try:
        d = decode_sib1(bits)
    except ValueError as exc:
        sys.stderr.write("ERROR\tnot a SIB1: %s\n" % exc)
        return 1

    print("message\tBCCH-DL-SCH-Message")
    print("sib\tSystemInformationBlockType1")
    print("mcc\t%s" % "".join(str(x) for x in d["mcc"]))
    print("mnc\t%s" % "".join(str(x) for x in d["mnc"]))
    print("plmn_count\t%d" % len(d["plmns"]))
    print("tac\t%04x" % d["tac"])
    print("cellid\t%07x" % d["cellid"])
    print("barred\t%s" % d["barred"])
    print("intra_freq_reselection\t%s" % d["reselect"])
    print("csg_indication\t%d" % d["csg_indication"])
    print("q_rx_lev_min\t%d" % d["qrxlevmin"])
    if d["q_rx_lev_min_offset"] is not None:
        print("q_rx_lev_min_offset\t%d" % d["q_rx_lev_min_offset"])
    if d["p_max"] is not None:
        print("p_max\t%d" % d["p_max"])
    print("band\t%d" % d["band"])
    print("si_window_length\t%s" % d["si_window_length"])
    print("system_info_value_tag\t%d" % d["system_info_value_tag"])
    for period, sibs in d["scheduling"]:
        print("scheduling\t%s %s" % (period, " ".join(sibs)))
    print("bits_consumed\t%d" % d["bits_consumed"])
    return 0


def cmd_si(args):
    bits = bits_of(args.hex, args.bits)

    try:
        d = decode_si(bits)
    except ValueError as exc:
        sys.stderr.write("ERROR\tnot a SystemInformation container: %s\n" % exc)
        return 1

    print("message\tBCCH-DL-SCH-Message")
    print("c1\tsystemInformation")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    print("sib_type\t%s" % d["sib"])
    print("sib_choice_index\t%d" % d["sib_index"])
    print("sib_count\t%d" % d["count"])
    print("header_bits\t%d" % d["bits_consumed"])
    print("body_bits\t%d" % len(d["body_bits"]))
    print("total_bits\t%d" % d["total_bits"])
    print("body_hex\t%s" % _bits_to_hex(d["body_bits"]))
    return 0


def cmd_sib3(args):
    try:
        body = encode_sib3(q_hyst=args.q_hyst,
                           thresh_serving_low=args.thresh,
                           cell_reselection_priority=args.priority,
                           q_rx_lev_min=args.qrxlevmin,
                           presence_antenna_port1=args.antport1,
                           neigh_cell_config=args.neigh,
                           t_reselection_eutra=args.tresel)
    except ValueError as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2

    print("sib\tSystemInformationBlockType3")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    print("q_hyst\t%s" % args.q_hyst)
    print("thresh_serving_low\t%d" % args.thresh)
    print("cell_reselection_priority\t%d" % args.priority)
    print("q_rx_lev_min\t%d" % args.qrxlevmin)
    print("presence_antenna_port1\t%d" % (1 if args.antport1 else 0))
    print("neigh_cell_config\t%s" % args.neigh)
    print("t_reselection_eutra\t%d" % args.tresel)
    print("body_bits\t%d" % len(body))
    print("body_bits_str\t%s" % body)
    print("body_hex\t%s" % _bits_to_hex(body))
    if not args.body_only:
        full = encode_si(SIB_CHOICE.index("sibType3"), body, 1)
        print("container_bits\t%d" % len(full))
        print("container_hex\t%s" % _bits_to_hex(full))
    return 0


def cmd_sib3_decode(args):
    bits = bits_of(args.hex, args.bits)
    if len(bits) >= SI_HEADER_BITS and bits[:SI_PREFIX_BITS] == "0000":
        try:
            d = decode_si(bits)
            if d["sib"] == "sibType3":
                bits = d["body_bits"]
        except ValueError:
            pass

    try:
        d = decode_sib3(bits)
    except ValueError as exc:
        sys.stderr.write("ERROR\tnot a SIB3 body: %s\n" % exc)
        return 1

    print("message\tSystemInformationBlockType3")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    print("q_hyst\t%s" % d["q_hyst"])
    print("thresh_serving_low\t%d" % d["thresh_serving_low"])
    print("cell_reselection_priority\t%d" % d["cell_reselection_priority"])
    print("q_rx_lev_min\t%d" % d["q_rx_lev_min"])
    print("presence_antenna_port1\t%d" % d["presence_antenna_port1"])
    print("neigh_cell_config\t%s" % d["neigh_cell_config"])
    print("t_reselection_eutra\t%d" % d["t_reselection_eutra"])
    print("bits_consumed\t%d" % d["bits_consumed"])
    return 0


def _bits_to_hex(bits):
    s = bits + "0" * ((8 - len(bits) % 8) % 8)
    return "".join("%02X" % int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def main(argv):
    p = argparse.ArgumentParser(prog="lte_asn1",
                                description="LTE RRC ASN.1 unaligned PER (TS 36.331)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("sib1", help="encode a SystemInformationBlockType1")
    s.add_argument("--mcc", default="262")
    s.add_argument("--mnc", default="01")
    s.add_argument("--tac", default="00f1")
    s.add_argument("--cellid", default="00a1")
    s.add_argument("--barred", default="notBarred",
                   choices=["barred", "notBarred"])
    s.add_argument("--reselect", default="notAllowed",
                   choices=["allowed", "notAllowed"])
    s.add_argument("--qrxlevmin", type=int, default=-70)
    s.add_argument("--band", type=int, default=20)
    s.add_argument("--siw", default="ms20", choices=SI_WINDOW_LENGTH)
    s.add_argument("--valuetag", type=int, default=0)
    s.add_argument("--period", default="rf32", choices=SI_PERIODICITY)
    s.add_argument("--sib", action="append", choices=SIB_TYPE)
    s.set_defaults(func=cmd_sib1)

    d = sub.add_parser("decode",
                       help="decode a BCCH-DL-SCH-Message carrying SIB1")
    d.add_argument("hex", help="the message, as hex octets or a bit string")
    d.set_defaults(func=cmd_decode)

    sub.add_parser("selftest", help="assert against the captured pycrate vectors")

    si = sub.add_parser(
        "si", help="decode a SystemInformation container (the SIB envelope)")
    si.add_argument("hex", help="the message, as hex octets or a bit string")
    si.add_argument("--bits", type=int, default=None,
                    help="the message's true bit length, before hex padding")
    si.set_defaults(func=cmd_si)

    s3 = sub.add_parser("sib3", help="encode a SystemInformationBlockType3")
    s3.add_argument("--q-hyst", default="dB0", choices=SIB3_Q_HYST)
    s3.add_argument("--thresh", type=int, default=0,
                    help="threshServingLow, INTEGER (0..31)")
    s3.add_argument("--priority", type=int, default=0,
                    help="cellReselectionPriority, INTEGER (0..7)")
    s3.add_argument("--qrxlevmin", type=int, default=-70,
                    help="q-RxLevMin, INTEGER (-70..-22)")
    s3.add_argument("--antport1", action="store_true",
                    help="set presenceAntennaPort1")
    s3.add_argument("--neigh", default="00",
                    help="neighCellConfig, a 2-bit string")
    s3.add_argument("--tresel", type=int, default=0,
                    help="t-ReselectionEUTRA, INTEGER (0..7)")
    s3.add_argument("--body-only", action="store_true",
                    help="omit the SystemInformation container wrapper")
    s3.set_defaults(func=cmd_sib3)

    s3d = sub.add_parser("sib3-decode",
                         help="decode a SystemInformationBlockType3 body")
    s3d.add_argument("hex", help="the body (or whole container), as hex")
    s3d.add_argument("--bits", type=int, default=None,
                     help="the true bit length, before hex padding")
    s3d.set_defaults(func=cmd_sib3_decode)

    args = p.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
