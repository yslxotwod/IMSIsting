#!/usr/bin/env python3
"""LTE RRC ASN.1 -- unaligned PER, as TS 36.331 sends it over BCCH-DL-SCH.

This is the 4G counterpart of tools/gsm_mod.py. It exists because
`modules/10_lte_air.sh` ships nine functions named lair_decode_sib*() that do
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
# The decoder. This is the half modules/10_lte_air.sh needs: its nine
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
# Captured from pycrate 0.8.1, one per SIB type. The third value is the TRUE
# bit length of the container, header included. It is NOT the nibble count
# times four: pycrate's to_uper() pads to whole octets, so the hex only bounds
# the length from above, and the difference is up to seven bits. These were
# first written as the padded figures, which an assertion that the truncated
# vector is as long as the truncation length cannot detect -- each length here
# is derived from the SIB body layout instead and checked against that
# derivation in the selftest.
SI_VECTORS = [
    ("sib2", "00000000000000000000000000000000100000000000000000", 200),
    ("sib3", "000400000000", 48),
    ("sib4", "000800", 18),
    ("sib5", "000C00000000000000", 66),
    ("sib6", "001000", 18),
    ("sib7", "001400", 20),
    ("sib8", "001800", 19),
]

# The SIB5 element is 48 bits with every OPTIONAL absent: one extension bit,
# six OPTIONAL presence bits, then dl-CarrierFreq (16), q-RxLevMin (6),
# t-ReselectionEUTRA (3), threshX-High (5), threshX-Low (5),
# allowedMeasBandwidth (3), presenceAntennaPort1 (1) and neighCellConfig (2).
# The stride was confirmed by putting a different dl-CarrierFreq in the second
# element of a two-element list and watching which bit moved.
SIB5_ELEMENT_BITS = 48
SIB5_MAX_CARRIERS = 8
SIB5_NEIGH_MAX = 16
# Baseline body lengths with every OPTIONAL absent, from the ASN.1 root: one
# extension bit plus the OPTIONAL presence bits, plus SIB7's mandatory
# t-ReselectionGERAN.
SIB6_BASELINE_BITS = 1 + 3
SIB7_BASELINE_BITS = 1 + 2 + 3
SIB8_BASELINE_BITS = 1 + 4


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


# ---------------------------------------------------------------------------
# SystemInformationBlockType2 (TS 36.331 6.3.1), unaligned PER.
#
# The layout is derived from the ASN.1, not guessed. Every width comes from the
# field's own constraint: an ENUMERATED from its value count, an INTEGER from
# the span of its range, a BOOLEAN and a fixed BIT STRING by definition. The
# order is declaration order, and each SEQUENCE's OPTIONAL/DEFAULT bitmap sits
# at the FRONT of that SEQUENCE per X.691 -- which is what decides where the
# four extension bits land.
#
# It is confirmed against captured pycrate output twice over. The all-default
# value encodes to exactly SIB2_BODY_BITS body bits, and the single set bit in
# that encoding falls at body bit 117 -- precisely where this table puts the
# soundingRS-UL-ConfigCommon CHOICE index with `setup` selected. A layout that
# were four bits out would have produced 190 bits and no set bit there.
#
# Two things are deliberately not modelled, and the decoder refuses rather than
# mis-read them: ac-BarringInfo (both access-class barring records), the
# mbsfn-SubframeConfigList, and srs-MaxUpPts. All three are absent in every
# value this encoder emits and their presence bits are written as zero.
# ---------------------------------------------------------------------------

SIB2_BODY_BITS = 186

SIB2_NUMBER_OF_RA_PREAMBLES = [
    "n4", "n8", "n12", "n16", "n20", "n24", "n28", "n32",
    "n36", "n40", "n44", "n48", "n52", "n56", "n60", "n64",
]
SIB2_POWER_RAMPING_STEP = ["dB0", "dB2", "dB4", "dB6"]
SIB2_PREAMBLE_INITIAL_RECEIVED_TARGET_POWER = [
    "dBm-120", "dBm-118", "dBm-116", "dBm-114", "dBm-112", "dBm-110",
    "dBm-108", "dBm-106", "dBm-104", "dBm-102", "dBm-100", "dBm-98",
    "dBm-96", "dBm-94", "dBm-92", "dBm-90",
]
SIB2_PREAMBLE_TRANS_MAX = [
    "n3", "n4", "n5", "n6", "n7", "n8", "n10", "n20", "n50", "n100", "n200",
]
SIB2_RA_RESPONSE_WINDOW_SIZE = [
    "sf2", "sf3", "sf4", "sf5", "sf6", "sf7", "sf8", "sf10",
]
SIB2_MAC_CONTENTION_RESOLUTION_TIMER = [
    "sf8", "sf16", "sf24", "sf32", "sf40", "sf48", "sf56", "sf64",
]
SIB2_MODIFICATION_PERIOD_COEFF = ["n2", "n4", "n8", "n16"]
SIB2_DEFAULT_PAGING_CYCLE = ["rf32", "rf64", "rf128", "rf256"]
SIB2_NB = [
    "fourT", "twoT", "oneT", "halfT",
    "quarterT", "oneEighthT", "oneSixteenthT", "oneThirtySecondT",
]
SIB2_HOPPING_MODE = ["interSubFrame", "intraAndInterSubFrame"]
SIB2_DELTA_PUCCH_SHIFT = ["ds1", "ds2", "ds3"]
SIB2_SRS_BANDWIDTH_CONFIG = [
    "bw0", "bw1", "bw2", "bw3", "bw4", "bw5", "bw6", "bw7",
]
SIB2_SRS_SUBFRAME_CONFIG = ["sc%d" % i for i in range(16)]
SIB2_ALPHA = ["al0", "al04", "al05", "al06", "al07", "al08", "al09", "al1"]
SIB2_DELTA_F_PUCCH_FORMAT1 = ["deltaF-2", "deltaF0", "deltaF2"]
SIB2_DELTA_F_PUCCH_FORMAT1B = ["deltaF1", "deltaF3", "deltaF5"]
SIB2_DELTA_F_PUCCH_FORMAT2 = ["deltaF-2", "deltaF0", "deltaF1", "deltaF2"]
SIB2_DELTA_F_PUCCH_FORMAT2A = ["deltaF-2", "deltaF0", "deltaF2"]
SIB2_DELTA_F_PUCCH_FORMAT2B = ["deltaF-2", "deltaF0", "deltaF2"]
SIB2_UL_CYCLIC_PREFIX_LENGTH = ["len1", "len2"]
SIB2_T300 = ["ms100", "ms200", "ms300", "ms400", "ms600", "ms1000",
             "ms1500", "ms2000"]
SIB2_T301 = SIB2_T300
SIB2_T310 = ["ms0", "ms50", "ms100", "ms200", "ms500", "ms1000", "ms2000"]
SIB2_N310 = ["n1", "n2", "n3", "n4", "n6", "n8", "n10", "n20"]
SIB2_T311 = ["ms1000", "ms3000", "ms5000", "ms10000", "ms15000", "ms20000",
             "ms30000"]
SIB2_N311 = ["n1", "n2", "n3", "n4", "n5", "n6", "n8", "n10"]
SIB2_UL_BANDWIDTH = ["n6", "n15", "n25", "n50", "n75", "n100"]
SIB2_TIME_ALIGNMENT_TIMER = [
    "sf500", "sf750", "sf1280", "sf1920", "sf2560", "sf5120", "sf10240",
    "infinity",
]

# The layout, in bit order. `d` is the default; `r` is an inclusive INTEGER
# range, encoded offset by its lower bound the way PER encodes a constrained
# whole number; `t` is an ENUMERATED table, encoded by index.
SIB2_LAYOUT = [
    {"k": "bit", "n": "ext", "d": 0},                      # SIB2 extensible
    {"k": "bit", "n": "ac_barring_info_present", "d": 0},
    {"k": "bit", "n": "mbsfn_subframe_config_list_present", "d": 0},
    {"k": "bit", "n": "rrc_common_ext", "d": 0},           # radioResourceConfigCommon
    {"k": "bit", "n": "rach_ext", "d": 0},                 # rach-ConfigCommon
    {"k": "bit", "n": "preambles_group_a_config_present", "d": 0},
    {"k": "enum", "n": "number_of_ra_preambles",
     "t": SIB2_NUMBER_OF_RA_PREAMBLES, "d": "n4"},
    {"k": "enum", "n": "power_ramping_step",
     "t": SIB2_POWER_RAMPING_STEP, "d": "dB0"},
    {"k": "enum", "n": "preamble_initial_received_target_power",
     "t": SIB2_PREAMBLE_INITIAL_RECEIVED_TARGET_POWER, "d": "dBm-120"},
    {"k": "enum", "n": "preamble_trans_max",
     "t": SIB2_PREAMBLE_TRANS_MAX, "d": "n3"},
    {"k": "enum", "n": "ra_response_window_size",
     "t": SIB2_RA_RESPONSE_WINDOW_SIZE, "d": "sf2"},
    {"k": "enum", "n": "mac_contention_resolution_timer",
     "t": SIB2_MAC_CONTENTION_RESOLUTION_TIMER, "d": "sf8"},
    {"k": "int", "n": "max_harq_msg3_tx", "r": (1, 8), "d": 1},
    {"k": "enum", "n": "modification_period_coeff",
     "t": SIB2_MODIFICATION_PERIOD_COEFF, "d": "n2"},
    {"k": "enum", "n": "default_paging_cycle",
     "t": SIB2_DEFAULT_PAGING_CYCLE, "d": "rf32"},
    {"k": "enum", "n": "nb", "t": SIB2_NB, "d": "fourT"},
    {"k": "int", "n": "root_sequence_index", "r": (0, 837), "d": 0},
    {"k": "int", "n": "prach_config_index", "r": (0, 63), "d": 0},
    {"k": "bit", "n": "high_speed_flag", "d": 0},
    {"k": "int", "n": "zero_correlation_zone_config", "r": (0, 15), "d": 0},
    {"k": "int", "n": "prach_freq_offset", "r": (0, 94), "d": 0},
    {"k": "int", "n": "reference_signal_power", "r": (-60, 50), "d": -60},
    {"k": "int", "n": "p_b", "r": (0, 3), "d": 0},
    {"k": "int", "n": "n_sb", "r": (1, 4), "d": 1},
    {"k": "enum", "n": "hopping_mode", "t": SIB2_HOPPING_MODE,
     "d": "interSubFrame"},
    {"k": "int", "n": "pusch_hopping_offset", "r": (0, 98), "d": 0},
    {"k": "bit", "n": "enable64qam", "d": 0},
    {"k": "bit", "n": "group_hopping_enabled", "d": 0},
    {"k": "int", "n": "group_assignment_pusch", "r": (0, 29), "d": 0},
    {"k": "bit", "n": "sequence_hopping_enabled", "d": 0},
    {"k": "int", "n": "cyclic_shift", "r": (0, 7), "d": 0},
    {"k": "enum", "n": "delta_pucch_shift", "t": SIB2_DELTA_PUCCH_SHIFT,
     "d": "ds1"},
    {"k": "int", "n": "nrb_cqi", "r": (0, 98), "d": 0},
    {"k": "int", "n": "ncs_an", "r": (0, 7), "d": 0},
    {"k": "int", "n": "n1pucch_an", "r": (0, 2047), "d": 0},
    # soundingRS-UL-ConfigCommon is a CHOICE of release (NULL) and setup; the
    # one-bit index selects it, and the four setup fields follow only for setup.
    {"k": "bit", "n": "sounding_rs_setup", "d": 1},
    {"k": "optbit", "n": "srs_max_up_pts", "when": "sounding_rs_setup"},
    {"k": "enum", "n": "srs_bandwidth_config", "t": SIB2_SRS_BANDWIDTH_CONFIG,
     "d": "bw0", "when": "sounding_rs_setup"},
    {"k": "enum", "n": "srs_subframe_config", "t": SIB2_SRS_SUBFRAME_CONFIG,
     "d": "sc0", "when": "sounding_rs_setup"},
    {"k": "bit", "n": "ack_nack_srs_simultaneous_transmission", "d": 0,
     "when": "sounding_rs_setup"},
    {"k": "int", "n": "p0_nominal_pusch", "r": (-126, 24), "d": -126},
    {"k": "enum", "n": "alpha", "t": SIB2_ALPHA, "d": "al0"},
    {"k": "int", "n": "p0_nominal_pucch", "r": (-127, -96), "d": -127},
    {"k": "enum", "n": "delta_f_pucch_format1", "t": SIB2_DELTA_F_PUCCH_FORMAT1,
     "d": "deltaF-2"},
    {"k": "enum", "n": "delta_f_pucch_format1b",
     "t": SIB2_DELTA_F_PUCCH_FORMAT1B, "d": "deltaF1"},
    {"k": "enum", "n": "delta_f_pucch_format2", "t": SIB2_DELTA_F_PUCCH_FORMAT2,
     "d": "deltaF-2"},
    {"k": "enum", "n": "delta_f_pucch_format2a",
     "t": SIB2_DELTA_F_PUCCH_FORMAT2A, "d": "deltaF-2"},
    {"k": "enum", "n": "delta_f_pucch_format2b",
     "t": SIB2_DELTA_F_PUCCH_FORMAT2B, "d": "deltaF-2"},
    {"k": "int", "n": "delta_preamble_msg3", "r": (-1, 6), "d": -1},
    {"k": "enum", "n": "ul_cyclic_prefix_length",
     "t": SIB2_UL_CYCLIC_PREFIX_LENGTH, "d": "len1"},
    {"k": "bit", "n": "ue_timers_ext", "d": 0},            # ue-TimersAndConstants
    {"k": "enum", "n": "t300", "t": SIB2_T300, "d": "ms100"},
    {"k": "enum", "n": "t301", "t": SIB2_T301, "d": "ms100"},
    {"k": "enum", "n": "t310", "t": SIB2_T310, "d": "ms0"},
    {"k": "enum", "n": "n310", "t": SIB2_N310, "d": "n1"},
    {"k": "enum", "n": "t311", "t": SIB2_T311, "d": "ms1000"},
    {"k": "enum", "n": "n311", "t": SIB2_N311, "d": "n1"},
    {"k": "optbit", "n": "ul_carrier_freq"},
    {"k": "optbit", "n": "ul_bandwidth"},
    {"k": "optint", "n": "ul_carrier_freq", "r": (0, 65535)},
    {"k": "optenum", "n": "ul_bandwidth", "t": SIB2_UL_BANDWIDTH},
    {"k": "int", "n": "additional_spectrum_emission", "r": (1, 32), "d": 1},
    {"k": "enum", "n": "time_alignment_timer_common",
     "t": SIB2_TIME_ALIGNMENT_TIMER, "d": "sf500"},
]


def _bits_for(n):
    """Bits needed to carry n values, or the span of a range."""
    return max(1, (n - 1).bit_length()) if n > 1 else 1


def _range_width(lb, ub):
    return max(1, (ub - lb).bit_length())


def _is_optional(step):
    return step["k"].startswith("opt")


def _enabled(step, fields):
    """A guarded step is emitted only when its guard field selected the branch."""
    guard = step.get("when")
    return guard is None or bool(fields.get(guard, 1))


def encode_sib2(**fields):
    """Encode a SystemInformationBlockType2 body (TS 36.331 6.3.1).

    Every field of SIB2's root that this models takes its ASN.1 default unless
    passed by name; field names are the ASN.1 names lowercased with '-' and
    camelCase flattened to '_'. Returns a bit string, not a BitWriter: a SIB2
    body is a fragment of a larger message and is not octet aligned.
    """
    known = {s["n"] for s in SIB2_LAYOUT}
    unknown = set(fields) - known
    if unknown:
        raise ValueError("unknown SIB2 field(s): %s" % ", ".join(sorted(unknown)))

    for step in SIB2_LAYOUT:
        if "when" in step and not _enabled(step, fields):
            continue
        name = step["n"]
        if _is_optional(step):
            continue
        val = fields.get(name, step.get("d"))
        if step["k"] == "enum":
            if val not in step["t"]:
                raise ValueError("%s must be one of %s" % (name, step["t"]))
        elif step["k"] == "int":
            lb, ub = step["r"]
            if not lb <= val <= ub:
                raise ValueError("%s is INTEGER (%d..%d), got %s"
                                 % (name, lb, ub, val))
        elif step["k"] == "bit":
            if val not in (0, 1, True, False):
                raise ValueError("%s is a single bit" % name)

    w = BitWriter()
    for step in SIB2_LAYOUT:
        if not _enabled(step, fields):
            continue
        k, name = step["k"], step["n"]
        if k == "bit":
            w.bit(fields.get(name, step["d"]))
        elif k == "enum":
            w.uint(step["t"].index(fields.get(name, step["d"])),
                   _bits_for(len(step["t"])))
        elif k == "int":
            lb, _ub = step["r"]
            w.uint(fields.get(name, step["d"]) - lb, _range_width(*step["r"]))
        elif k == "optbit":
            w.bit(1 if fields.get(name) is not None else 0)
        elif k == "optint":
            if fields.get(name) is None:
                continue
            lb, _ub = step["r"]
            w.uint(fields[name] - lb, _range_width(*step["r"]))
        elif k == "optenum":
            if fields.get(name) is None:
                continue
            if fields[name] not in step["t"]:
                raise ValueError("%s must be one of %s" % (name, step["t"]))
            w.uint(step["t"].index(fields[name]), _bits_for(len(step["t"])))
        else:
            raise ValueError("bad layout kind %r" % k)
    return w.string()


def decode_sib2(data):
    """Decode a SystemInformationBlockType2 body.

    Raises ValueError when the bits are not a SIB2 this models -- an extension
    addition, access-class barring, an MBSFN subframe list or a `release`
    soundingRS all refuse rather than report fields read from the wrong place.
    """
    r = BitReader(data)
    if len(r.bits) < SIB2_BODY_BITS:
        raise ValueError("SIB2 body is %d bits, got %d"
                         % (SIB2_BODY_BITS, len(r.bits)))

    out = {}
    for step in SIB2_LAYOUT:
        if "when" in step and not _enabled(step, out):
            continue
        k, name = step["k"], step["n"]
        if k == "optbit":
            # An OPTIONAL or DEFAULT field costs one presence bit even when it
            # is absent, and that bit sits in the SEQUENCE's bitmap ahead of the
            # values. Not reading it does not fail loudly: it shifts every field
            # after it by one bit, and because most of SIB2's defaults are zero
            # the damage only shows up on a populated message.
            out[name] = True if r.bit() else None
            continue
        if k == "bit":
            out[name] = bool(r.bit())
            continue
        if k == "enum":
            out[name] = step["t"][r.uint(_bits_for(len(step["t"])))]
            continue
        if k == "int":
            lb, _ub = step["r"]
            out[name] = lb + r.uint(_range_width(*step["r"]))
            continue
        if k == "optint":
            if out.get(name) is None:
                continue
            lb, _ub = step["r"]
            out[name] = lb + r.uint(_range_width(*step["r"]))
            continue
        if k == "optenum":
            if out.get(name) is None:
                continue
            out[name] = step["t"][r.uint(_bits_for(len(step["t"])))]
            continue
        raise ValueError("bad layout kind %r" % k)

    if out["ext"]:
        raise ValueError("SIB2 has extension additions; not modelled")
    if out["ac_barring_info_present"]:
        raise ValueError("ac-BarringInfo present; not modelled")
    if out["mbsfn_subframe_config_list_present"]:
        raise ValueError("mbsfn-SubframeConfigList present; not modelled")
    if out["rrc_common_ext"]:
        raise ValueError("radioResourceConfigCommon has extension additions; "
                         "not modelled")
    if out["rach_ext"]:
        raise ValueError("rach-ConfigCommon has extension additions; "
                         "not modelled")
    if out["preambles_group_a_config_present"]:
        raise ValueError("preamblesGroupAConfig present; not modelled")
    if out["ue_timers_ext"]:
        raise ValueError("ue-TimersAndConstants has extension additions; "
                         "not modelled")
    if not out["sounding_rs_setup"]:
        raise ValueError("soundingRS-UL-ConfigCommon is release; no setup "
                         "fields are present")

    out["bits_consumed"] = r.pos
    return out


# Captured from pycrate 0.8.1. "default" is the all-defaults value and is the
# load-bearing one: fifty leaves encoding to zero only pin the layout because
# the single set bit -- the soundingRS CHOICE index -- lands at body bit 117.
# "prach" and "power" move bits in the first half and the second half
# respectively, so a width error anywhere shifts them into disagreement;
# "ulcarrier" is the only one that exercises the freqInfo OPTIONAL bitmap, and
# it is the only one whose body is not 186 bits.
SIB2_VECTORS = [
    ("default", "00000000000000000000000000000000100000000000000000",
     200, {}),
    ("prach", "0000000000000160F810000000000000100000000000000000",
     200, {"root_sequence_index": 22, "prach_config_index": 3,
           "high_speed_flag": True, "zero_correlation_zone_config": 12,
           "prach_freq_offset": 4}),
    ("power", "000000A80000000000025A0000000000100127780040000000",
     200, {"reference_signal_power": 15, "p_b": 1,
           "p0_nominal_pusch": -90, "alpha": "al1",
           "p0_nominal_pucch": -112, "delta_preamble_msg3": 0,
           "preamble_initial_received_target_power": "dBm-100",
           "power_ramping_step": "dB4"}),
    ("ulcarrier", "00000000000000000000000000000000100000000000000309154000",
     219, {"ul_carrier_freq": 2325, "ul_bandwidth": "n25"}),
]


# ---------------------------------------------------------------------------
# SystemInformationBlockType4 (TS 36.331 6.3.1), unaligned PER.
#
# SIB4 is the neighbour-cell list: which cells a UE may reselect to, which it
# must avoid, and the CSG range it may treat as closed. Unlike SIB2 it is
# structured -- SEQUENCE OF lists of SEQUENCEs, one of which has its own
# OPTIONAL -- so it is written out rather than driven from a flat table.
#
# THE EXTENSIBILITY RULE, which this section had to establish because no ASN.1
# dump shows it: pycrate reports `_ext = None` for a SEQUENCE with no extension
# marker, `[]` for one that is extensible but declares no extension additions,
# and a non-empty list for one that does. So an EMPTY LIST is not the same as
# None, and a SEQUENCE whose `_ext` is `[]` still emits its extension bit.
# `IntraFreqNeighCellInfo` is exactly that case -- `_ext = []` while
# `PhysCellIdRange` and `CSG-PhysCellIdRange` are None. A `len(_ext)` test
# reports both as zero; believing it puts physCellId one bit early and every
# element after that fifteen bits out.
#
# Layout, from differential probing against pycrate and then checked by hand
# against a baseline with every OPTIONAL populated:
#
#   0        extension bit
#   1        intraFreqNeighCellList present
#   2        intraFreqExcludedCellList present
#   3        csg-PhysCellIdRange present
#   4..7     intraFreqNeighCellList length - 1        (SIZE (1..16))
#   each element, IntraFreqNeighCellInfo, 15 bits:
#       +0       extension bit
#       +1..9    physCellId     INTEGER (0..503)
#       +10..14  q-OffsetCell   ENUMERATED, 31 values
#   then intraFreqExcludedCellList the same way, elements are PhysCellIdRange
#   at 1 + 9 [+ 4] bits: a range-present bit, start INTEGER (0..503), and the
#   16-value ENUMERATED when present. csg-PhysCellIdRange has that same shape.
# ---------------------------------------------------------------------------

SIB4_Q_OFFSET_CELL = [
    "dB-24", "dB-22", "dB-20", "dB-18", "dB-16", "dB-14", "dB-12", "dB-10",
    "dB-8", "dB-6", "dB-5", "dB-4", "dB-3", "dB-2", "dB-1", "dB0", "dB1",
    "dB2", "dB3", "dB4", "dB5", "dB6", "dB8", "dB10", "dB12", "dB14", "dB16",
    "dB18", "dB20", "dB22", "dB24",
]
SIB4_PHYS_CELL_ID_RANGE = [
    "n4", "n8", "n12", "n16", "n24", "n32", "n48", "n64", "n84", "n96",
    "n128", "n168", "n252", "n504", "spare2", "spare1",
]
SIB4_MAX_CELLS = 16
SIB4_PHYS_CELL_ID_MAX = 503
# The vector tables name the encoder's arguments; the decoder returns the
# ASN.1 names. One map, so a test cannot pass by comparing a value to itself
# under two spellings of the same key.
SIB4_VECTOR_KEY = {
    "neigh_cells": "intra_freq_neigh_cell_list",
    "excluded_cells": "intra_freq_excluded_cell_list",
    "csg_phys_cell_id_range": "csg_phys_cell_id_range",
}


def _sib4_check_cell_id(v, what):
    if not isinstance(v, int) or not 0 <= v <= SIB4_PHYS_CELL_ID_MAX:
        raise ValueError("%s is PhysCellId (0..%d), got %r"
                         % (what, SIB4_PHYS_CELL_ID_MAX, v))


def _sib4_write_range(w, start, rng, what):
    _sib4_check_cell_id(start, what + ".start")
    w.bit(1 if rng is not None else 0)
    w.uint(start, 9)
    if rng is not None:
        if rng not in SIB4_PHYS_CELL_ID_RANGE:
            raise ValueError("%s.range must be one of %s"
                             % (what, SIB4_PHYS_CELL_ID_RANGE))
        w.uint(SIB4_PHYS_CELL_ID_RANGE.index(rng), 4)


def encode_sib4(neigh_cells=None, excluded_cells=None,
                csg_phys_cell_id_range=None):
    """Encode a SystemInformationBlockType4 body.

    `neigh_cells` is a list of {"phys_cell_id": int, "q_offset_cell": str};
    `excluded_cells` a list of {"start": int, "range": str or None};
    `csg_phys_cell_id_range` one such dict or None. An empty or absent list
    means the OPTIONAL is absent, because TS 36.331 gives both lists a lower
    bound of 1 -- a present list always carries at least one cell.

    Returns a bit string, not a BitWriter: a SIB body is a fragment of a larger
    message and is not octet aligned.
    """
    neigh_cells = list(neigh_cells or [])
    excluded_cells = list(excluded_cells or [])

    for name, cells in (("intraFreqNeighCellList", neigh_cells),
                        ("intraFreqExcludedCellList", excluded_cells)):
        if len(cells) > SIB4_MAX_CELLS:
            raise ValueError("%s holds at most %d cells, got %d"
                             % (name, SIB4_MAX_CELLS, len(cells)))
    for c in neigh_cells:
        _sib4_check_cell_id(c.get("phys_cell_id"), "neighCell.physCellId")
        if c.get("q_offset_cell") not in SIB4_Q_OFFSET_CELL:
            raise ValueError("neighCell.qOffsetCell must be one of %s"
                             % SIB4_Q_OFFSET_CELL)

    w = BitWriter()
    w.bit(0)                                    # no extension addition
    w.bit(1 if neigh_cells else 0)
    w.bit(1 if excluded_cells else 0)
    w.bit(1 if csg_phys_cell_id_range is not None else 0)

    if neigh_cells:
        w.uint(len(neigh_cells) - 1, 4)
        for c in neigh_cells:
            w.bit(0)                            # IntraFreqNeighCellInfo ext
            w.uint(c["phys_cell_id"], 9)
            w.uint(SIB4_Q_OFFSET_CELL.index(c["q_offset_cell"]), 5)

    if excluded_cells:
        w.uint(len(excluded_cells) - 1, 4)
        for c in excluded_cells:
            _sib4_write_range(w, c.get("start"), c.get("range"),
                              "physCellIdRange")

    if csg_phys_cell_id_range is not None:
        _sib4_write_range(w, csg_phys_cell_id_range.get("start"),
                          csg_phys_cell_id_range.get("range"),
                          "csg-PhysCellIdRange")
    return w.string()


def decode_sib4(data):
    """Decode a SystemInformationBlockType4 body.

    Refuses rather than mis-reads: an extension addition in the block or in a
    neighbour cell. Returns the two lists, the CSG range, and bits_consumed.
    """
    r = BitReader(data)
    if len(r.bits) < 4:
        raise ValueError("SIB4 body is at least 4 bits, got %d" % len(r.bits))
    if r.bit():
        raise ValueError("SIB4 carries an extension addition; "
                         "this codec models the root only")

    out = {}
    neigh_present = r.bit()
    excluded_present = r.bit()
    csg_present = r.bit()

    if neigh_present:
        cells = []
        for _ in range(r.uint(4) + 1):
            if r.bit():
                raise ValueError("IntraFreqNeighCellInfo carries an "
                                 "extension addition")
            cells.append({"phys_cell_id": r.uint(9),
                          "q_offset_cell": SIB4_Q_OFFSET_CELL[r.uint(5)]})
        out["intra_freq_neigh_cell_list"] = cells
    else:
        out["intra_freq_neigh_cell_list"] = None

    def one_range():
        present = r.bit()
        start = r.uint(9)
        rng = SIB4_PHYS_CELL_ID_RANGE[r.uint(4)] if present else None
        return {"start": start, "range": rng}

    if excluded_present:
        out["intra_freq_excluded_cell_list"] = [one_range()
                                                for _ in range(r.uint(4) + 1)]
    else:
        out["intra_freq_excluded_cell_list"] = None

    out["csg_phys_cell_id_range"] = one_range() if csg_present else None
    out["bits_consumed"] = r.pos
    return out


# Captured from pycrate 0.8.1. The third value is the TRUE bit length of the
# container, including the 14-bit SystemInformation header; the hex is padded
# to whole octets, so the two differ and neither is derivable from the other.
SIB4_VECTORS = [
    ("empty", "000800", 18, {}),
    ("neigh1", "0009002AA8", 37,
     {"neigh_cells": [{"phys_cell_id": 42, "q_offset_cell": "dB6"}]}),
    ("neigh2", "000904007800F0", 52,
     {"neigh_cells": [{"phys_cell_id": 0, "q_offset_cell": "dB0"},
                      {"phys_cell_id": 0, "q_offset_cell": "dB0"}]}),
    ("neigh16",
     "00093C007802F009E01BC04780AF019E03BC087812F029E05BC0C781AF039E07BC", 262,
     {"neigh_cells": [{"phys_cell_id": i, "q_offset_cell": "dB0"}
                      for i in range(16)]}),
    ("allpresent", "0009C42AA80E0199072CDB2000", 98,
     {"neigh_cells": [{"phys_cell_id": 42, "q_offset_cell": "dB6"},
                      {"phys_cell_id": 7, "q_offset_cell": "dB-24"}],
      "excluded_cells": [{"start": 100, "range": "n8"},
                         {"start": 300, "range": "n504"}],
      "csg_phys_cell_id_range": {"start": 200, "range": "n4"}}),
]


# ---------------------------------------------------------------------------
# SystemInformationBlockType5 (TS 36.331 6.3.1), unaligned PER.
#
# SIB5 is the inter-frequency neighbour list: one InterFreqCarrierFreqInfo per
# EARFCN the UE may reselect to. It is the largest SIB here and the first with
# a MANDATORY list, which changes the preamble: SIB4's lists are OPTIONAL, so
# each carries a presence bit, while interFreqCarrierFreqList has SIZE (1..8)
# and no presence bit at all -- only its 3-bit length.
#
#   0        extension bit                                   (SIB5 root)
#   1..3     interFreqCarrierFreqList length - 1              SIZE (1..8)
#   then one InterFreqCarrierFreqInfo per carrier, 48 bits with every
#   OPTIONAL absent:
#        +0       extension bit
#        +1..+6   OPTIONAL presence bits, declaration order: p-Max,
#                 t-ReselectionEUTRA-SF, cellReselectionPriority,
#                 q-OffsetFreq, interFreqNeighCellList,
#                 interFreqExcludedCellList
#        +7..22   dl-CarrierFreq            INTEGER (0..65535)
#        +23..28  q-RxLevMin                INTEGER (-70..-22)
#        [+29..34 p-Max                     INTEGER (-30..33)]
#        +35..37  t-ReselectionEUTRA        INTEGER (0..7)
#        [+t-ReselectionEUTRA-SF            sf-Medium (2), sf-High (2)]
#        threshX-High                       INTEGER (0..31)
#        threshX-Low                        INTEGER (0..31)
#        allowedMeasBandwidth               ENUMERATED, 6 values
#        presenceAntennaPort1               BOOLEAN
#        [cellReselectionPriority           INTEGER (0..7)]
#        neighCellConfig                    BIT STRING (SIZE (2))
#        [q-OffsetFreq                      ENUMERATED, 31 values]
#        [interFreqNeighCellList            length (4) + 14 per cell]
#        [interFreqExcludedCellList         length (4) + (1 + 9 [+ 4]) per cell]
#
# The 48-bit stride was measured, not assumed: giving the second element of a
# two-element list a different dl-CarrierFreq moved exactly one bit, at
# position 88, which is that field's last bit when the element starts at body
# bit 52 -- i.e. 1 + 3 bits of preamble plus one 48-bit element.
#
# A neighbour cell here is 14 bits, NOT the 15 bits SIB4 uses. The two types
# read alike and are not:
#
#     IntraFreqNeighCellInfo  (SIB4)  ...  -- extension marker, no additions
#     InterFreqNeighCellInfo  (SIB5)       -- no extension marker at all
#
# so SIB4 writes an extension bit per cell and SIB5 does not. A cell read one
# bit long puts every following cell 1 bit out; the first one still decodes,
# which is what makes this worth a comment.
#
# Both cell lists here share SIB4's Q-OffsetRange enumeration and its
# PhysCellIdRange shape, so the value tables below are reused deliberately.
# ---------------------------------------------------------------------------

SIB5_ALLOWED_MEAS_BANDWIDTH = ["mbw6", "mbw15", "mbw25", "mbw50", "mbw75",
                               "mbw100"]
SIB5_T_RESELECTION_SF = ["oDot25", "oDot5", "oDot75", "lDot0"]
SIB5_CARRIER_KEYS = (
    "dl_carrier_freq", "q_rx_lev_min", "p_max", "t_reselection_eutra",
    "t_reselection_eutra_sf", "thresh_x_high", "thresh_x_low",
    "allowed_meas_bandwidth", "presence_antenna_port1",
    "cell_reselection_priority", "neigh_cell_config", "q_offset_freq",
    "inter_freq_neigh_cell_list", "inter_freq_excluded_cell_list",
)
SIB5_REQUIRED_KEYS = (
    "dl_carrier_freq", "q_rx_lev_min", "t_reselection_eutra",
    "thresh_x_high", "thresh_x_low", "allowed_meas_bandwidth",
)
# The default carrier: every OPTIONAL absent, all integers at their lower
# bound. It encodes to 48 zero bits, which is the baseline pycrate produces.
SIB5_DEFAULT_CARRIER = {
    "dl_carrier_freq": 0,
    "q_rx_lev_min": -70,
    "p_max": None,
    "t_reselection_eutra": 0,
    "t_reselection_eutra_sf": None,
    "thresh_x_high": 0,
    "thresh_x_low": 0,
    "allowed_meas_bandwidth": "mbw6",
    "presence_antenna_port1": False,
    "cell_reselection_priority": None,
    "neigh_cell_config": "00",
    "q_offset_freq": None,
    "inter_freq_neigh_cell_list": None,
    "inter_freq_excluded_cell_list": None,
}


def _bitstr(w, s, width, what):
    """Write a BIT STRING of a fixed size, given as '0'/'1' characters."""
    if not isinstance(s, str) or len(s) != width or set(s) - {"0", "1"}:
        raise ValueError("%s is a %d-bit string of 0 and 1, got %r"
                         % (what, width, s))
    for c in s:
        w.bit(c == "1")


def _sib5_carrier(fields):
    """Merge a caller's carrier dict over the default and validate it."""
    unknown = set(fields) - set(SIB5_CARRIER_KEYS)
    if unknown:
        raise ValueError("unknown SIB5 carrier field(s): %s"
                         % ", ".join(sorted(unknown)))
    c = dict(SIB5_DEFAULT_CARRIER)
    c.update(fields)

    _bitstr(BitWriter(), c["neigh_cell_config"], 2, "neighCellConfig")
    if not isinstance(c["dl_carrier_freq"], int) or not 0 <= c["dl_carrier_freq"] <= 65535:
        raise ValueError("dl-CarrierFreq is INTEGER (0..65535), got %r"
                         % (c["dl_carrier_freq"],))
    for name, lo, hi in (("q_rx_lev_min", -70, -22), ("p_max", -30, 33),
                         ("thresh_x_high", 0, 31), ("thresh_x_low", 0, 31)):
        v = c[name]
        if v is None:
            if name == "p_max":
                continue
            raise ValueError("%s is required" % name)
        if not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError("%s is INTEGER (%d..%d), got %r"
                             % (name, lo, hi, v))
    for name, lo, hi in (("t_reselection_eutra", 0, 7),
                         ("cell_reselection_priority", 0, 7)):
        v = c[name]
        if v is None:
            continue
        if not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError("%s is INTEGER (%d..%d), got %r"
                             % (name, lo, hi, v))
    if c["allowed_meas_bandwidth"] not in SIB5_ALLOWED_MEAS_BANDWIDTH:
        raise ValueError("allowedMeasBandwidth must be one of %s"
                         % SIB5_ALLOWED_MEAS_BANDWIDTH)
    if c["q_offset_freq"] is not None and c["q_offset_freq"] not in SIB4_Q_OFFSET_CELL:
        raise ValueError("q-OffsetFreq must be one of %s" % SIB4_Q_OFFSET_CELL)
    sf = c["t_reselection_eutra_sf"]
    if sf is not None:
        if set(sf) != {"sf_medium", "sf_high"}:
            raise ValueError("t-ReselectionEUTRA-SF needs sf_medium and "
                             "sf_high, got %r" % (sf,))
        for k, v in sf.items():
            if v not in SIB5_T_RESELECTION_SF:
                raise ValueError("t-ReselectionEUTRA-SF.%s must be one of %s"
                                 % (k, SIB5_T_RESELECTION_SF))
    for name in ("inter_freq_neigh_cell_list", "inter_freq_excluded_cell_list"):
        cells = c[name]
        if cells is not None and len(cells) > SIB5_NEIGH_MAX:
            raise ValueError("%s holds at most %d cells, got %d"
                             % (name, SIB5_NEIGH_MAX, len(cells)))
    for cell in c["inter_freq_neigh_cell_list"] or []:
        _sib4_check_cell_id(cell.get("phys_cell_id"),
                            "interFreqNeighCell.physCellId")
        if cell.get("q_offset_cell") not in SIB4_Q_OFFSET_CELL:
            raise ValueError("interFreqNeighCell.qOffsetCell must be one of %s"
                             % SIB4_Q_OFFSET_CELL)
    return c


def _sib5_write_carrier(w, c):
    w.bit(0)                                        # no extension addition
    w.bit(1 if c["p_max"] is not None else 0)
    w.bit(1 if c["t_reselection_eutra_sf"] is not None else 0)
    w.bit(1 if c["cell_reselection_priority"] is not None else 0)
    w.bit(1 if c["q_offset_freq"] is not None else 0)
    w.bit(1 if c["inter_freq_neigh_cell_list"] else 0)
    w.bit(1 if c["inter_freq_excluded_cell_list"] else 0)

    w.uint(c["dl_carrier_freq"], 16)
    w.uint(c["q_rx_lev_min"] + 70, 6)
    if c["p_max"] is not None:
        w.uint(c["p_max"] + 30, 6)
    w.uint(c["t_reselection_eutra"], 3)
    if c["t_reselection_eutra_sf"] is not None:
        w.uint(SIB5_T_RESELECTION_SF.index(c["t_reselection_eutra_sf"]["sf_medium"]), 2)
        w.uint(SIB5_T_RESELECTION_SF.index(c["t_reselection_eutra_sf"]["sf_high"]), 2)
    w.uint(c["thresh_x_high"], 5)
    w.uint(c["thresh_x_low"], 5)
    w.uint(SIB5_ALLOWED_MEAS_BANDWIDTH.index(c["allowed_meas_bandwidth"]), 3)
    w.bit(1 if c["presence_antenna_port1"] else 0)
    if c["cell_reselection_priority"] is not None:
        w.uint(c["cell_reselection_priority"], 3)
    _bitstr(w, c["neigh_cell_config"], 2, "neighCellConfig")
    if c["q_offset_freq"] is not None:
        w.uint(SIB4_Q_OFFSET_CELL.index(c["q_offset_freq"]), 5)
    if c["inter_freq_neigh_cell_list"]:
        cells = c["inter_freq_neigh_cell_list"]
        w.uint(len(cells) - 1, 4)
        for cell in cells:
            # No extension bit here, and that is not an oversight: SIB5's
            # InterFreqNeighCellInfo has no extension marker at all, while
            # SIB4's IntraFreqNeighCellInfo is extensible with no additions.
            # The two look like the same type and are not -- one bit per cell
            # separates them, and reading the wrong one shifts every cell
            # after the first.
            w.uint(cell["phys_cell_id"], 9)
            w.uint(SIB4_Q_OFFSET_CELL.index(cell["q_offset_cell"]), 5)
    if c["inter_freq_excluded_cell_list"]:
        cells = c["inter_freq_excluded_cell_list"]
        w.uint(len(cells) - 1, 4)
        for cell in cells:
            _sib4_write_range(w, cell.get("start"), cell.get("range"),
                              "interFreqExcludedCell.physCellIdRange")


def encode_sib5(carriers=None):
    """Encode a SystemInformationBlockType5 body.

    `carriers` is a list of dicts with the SIB5_CARRIER_KEYS; anything omitted
    takes SIB5_DEFAULT_CARRIER's value, and a key set to None means the
    OPTIONAL is absent. The list has SIZE (1..8) and is mandatory, so an empty
    or absent list encodes the one-element default -- a SIB5 with no carriers
    is not a message TS 36.331 can express.

    Returns a bit string, not a BitWriter.
    """
    if carriers is None:
        carriers = [{}]
    if not carriers:
        carriers = [{}]
    if len(carriers) > SIB5_MAX_CARRIERS:
        raise ValueError("interFreqCarrierFreqList holds at most %d carriers, "
                         "got %d" % (SIB5_MAX_CARRIERS, len(carriers)))

    merged = [_sib5_carrier(c) for c in carriers]
    w = BitWriter()
    w.bit(0)                                        # no extension addition
    w.uint(len(merged) - 1, 3)
    for c in merged:
        _sib5_write_carrier(w, c)
    return w.string()


def decode_sib5(data):
    """Decode a SystemInformationBlockType5 body.

    Refuses rather than mis-reads: an extension addition in the block or in a
    carrier. The carrier dicts it returns use the encoder's key names, so the
    round trip is a comparison of like with like.
    """
    r = BitReader(data)
    if len(r.bits) < 1 + 3:
        raise ValueError("SIB5 body is at least 4 bits, got %d" % len(r.bits))
    if r.bit():
        raise ValueError("SIB5 carries an extension addition; "
                         "this codec models the root only")

    out = {"carriers": []}
    for _ in range(r.uint(3) + 1):
        if r.bit():
            raise ValueError("InterFreqCarrierFreqInfo carries an extension "
                             "addition")
        has_pmax = r.bit()
        has_sf = r.bit()
        has_prio = r.bit()
        has_qoff = r.bit()
        has_neigh = r.bit()
        has_excl = r.bit()

        c = dict(SIB5_DEFAULT_CARRIER)
        c["dl_carrier_freq"] = r.uint(16)
        c["q_rx_lev_min"] = r.uint(6) - 70
        c["p_max"] = (r.uint(6) - 30) if has_pmax else None
        c["t_reselection_eutra"] = r.uint(3)
        if has_sf:
            c["t_reselection_eutra_sf"] = {
                "sf_medium": SIB5_T_RESELECTION_SF[r.uint(2)],
                "sf_high": SIB5_T_RESELECTION_SF[r.uint(2)],
            }
        c["thresh_x_high"] = r.uint(5)
        c["thresh_x_low"] = r.uint(5)
        c["allowed_meas_bandwidth"] = SIB5_ALLOWED_MEAS_BANDWIDTH[r.uint(3)]
        c["presence_antenna_port1"] = bool(r.bit())
        c["cell_reselection_priority"] = r.uint(3) if has_prio else None
        c["neigh_cell_config"] = "".join("1" if r.bit() else "0"
                                         for _ in range(2))
        c["q_offset_freq"] = (SIB4_Q_OFFSET_CELL[r.uint(5)] if has_qoff
                              else None)

        if has_neigh:
            cells = []
            for _ in range(r.uint(4) + 1):
                cells.append({"phys_cell_id": r.uint(9),
                              "q_offset_cell": SIB4_Q_OFFSET_CELL[r.uint(5)]})
            c["inter_freq_neigh_cell_list"] = cells
        if has_excl:
            cells = []
            for _ in range(r.uint(4) + 1):
                present = r.bit()
                start = r.uint(9)
                cells.append({"start": start,
                              "range": (SIB4_PHYS_CELL_ID_RANGE[r.uint(4)]
                                        if present else None)})
            c["inter_freq_excluded_cell_list"] = cells
        out["carriers"].append(c)

    out["bits_consumed"] = r.pos
    return out


# Captured from pycrate 0.8.1. As with SIB4_VECTORS the third value is the TRUE
# bit length of the container, of which the body is that minus the 14-bit
# SystemInformation header; the hex is padded to whole octets.
#
# Each vector's carriers are PARTIAL dicts merged over SIB5_DEFAULT_CARRIER, so
# a row lists only what it changes. The "empty" row is the whole codec at its
# floor: one carrier, every OPTIONAL absent, 52 body bits.
SIB5_VECTORS = [
    ("empty", "000C00000000000000", 66, [{}]),
    ("dlfreq", "000C00026900000000", 66, [{"dl_carrier_freq": 1234}]),
    ("alloptions", "000C1F826961FF7FFEED311557EE0199052C", 144, [{
        "dl_carrier_freq": 1234, "q_rx_lev_min": -22, "p_max": 33,
        "t_reselection_eutra": 7,
        "t_reselection_eutra_sf": {"sf_medium": "oDot5", "sf_high": "lDot0"},
        "thresh_x_high": 31, "thresh_x_low": 31,
        "allowed_meas_bandwidth": "mbw100", "presence_antenna_port1": True,
        "cell_reselection_priority": 5, "neigh_cell_config": "10",
        "q_offset_freq": "dB4",
        "inter_freq_neigh_cell_list": [
            {"phys_cell_id": 42, "q_offset_cell": "dB6"},
            {"phys_cell_id": 503, "q_offset_cell": "dB-24"}],
        "inter_freq_excluded_cell_list": [{"start": 100, "range": "n8"},
                                          {"start": 300, "range": None}],
    }]),
    ("neigh16",
     "000C0100000000003C00F00BC04F01BC08F02BC0CF03BC10F04BC14F05BC18F06BC1CF07BC", 294,
     [{"inter_freq_neigh_cell_list": [{"phys_cell_id": i,
                                       "q_offset_cell": "dB0"}
                                      for i in range(16)]}]),
    ("eightcarriers",
     "000DC0009600000000009680000000009700000000009780000000009800000000009880000000009900000000009980000000",
     402,
     [{"dl_carrier_freq": 300 + i} for i in range(8)]),
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
    # This is the half 10_lte_air's lair_decode_sib*() functions need.
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
    # Each container's true length, derived from the SIB body layout rather
    # than read off the hex. Without this the loop below can only assert that
    # a vector is as long as the length it was truncated to, which is true of
    # any number at all.
    si_true = {
        "sib2": SI_HEADER_BITS + SIB2_BODY_BITS,
        "sib3": SI_HEADER_BITS + SIB3_BODY_BITS,
        "sib4": SI_HEADER_BITS + 4,                      # every OPTIONAL absent
        "sib5": SI_HEADER_BITS + 1 + 3 + SIB5_ELEMENT_BITS,
        "sib6": SI_HEADER_BITS + SIB6_BASELINE_BITS,
        "sib7": SI_HEADER_BITS + SIB7_BASELINE_BITS,
        "sib8": SI_HEADER_BITS + SIB8_BASELINE_BITS,
    }
    for name, hexs, nbits in SI_VECTORS:
        bits = bits_of(hexs, nbits)
        chk("si-" + name + "-bitlen", len(bits), nbits)
        chk("si-" + name + "-bitlen-derived", nbits, si_true[name])
        # The hex is the true bits followed by the zero padding that brings it
        # to a whole octet, so the padding is present, empty of information,
        # and shorter than eight bits. A padded length stored as a true one
        # makes the first of these zero and the third still pass.
        padded = bits_of(hexs)
        chk("si-" + name + "-padding-under-8", 0 <= len(padded) - nbits < 8, True)
        chk("si-" + name + "-padding-zeros",
            set(padded[nbits:]) - {"0"}, set())
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

    # ---- SystemInformationBlockType2 -----------------------------------
    #
    # Each vector is checked as a whole container -- header plus body -- so a
    # header change cannot be cancelled out by a body change. The fifty leaves
    # of the default value are then checked individually for the two things a
    # round-trip cannot see: that the OPTIONAL bitmap sits at the front of the
    # SEQUENCE where X.691 puts it, and that an absent OPTIONAL still costs its
    # presence bit.
    for name, hexs, nbits, kw in SIB2_VECTORS:
        bits = bits_of(hexs, nbits)
        chk("sib2-" + name + "-container",
            encode_si(SIB_CHOICE.index("sibType2"), encode_sib2(**kw), 1), bits)
        d = decode_sib2(bits[SI_HEADER_BITS:])
        chk("sib2-" + name + "-consumed", d["bits_consumed"],
            nbits - SI_HEADER_BITS)
        for k, want in kw.items():
            chk("sib2-%s-%s" % (name, k), d[k], want)

    body = encode_sib2()
    chk("sib2-default-body-bits", len(body), SIB2_BODY_BITS)
    chk("sib2-default-only-set-bit",
        [i for i, c in enumerate(body) if c == "1"], [117])
    # The three presence bits exist even though nothing follows two of them on
    # the default message; a decoder that skips them is one bit out from here.
    chk("sib2-default-sounding-rs-setup", body[117], "1")
    chk("sib2-default-srs-max-up-pts-absent", body[118], "0")
    # Asserting these two are "0" would be vacuous -- that whole stretch of the
    # default body is zero, so the check would pass at any position. Setting
    # each OPTIONAL pins the presence bit, the value's offset and its width.
    # The comparison is against the first 176 bits only: past the first
    # presence bit the two layouts sit at different offsets by construction, so
    # a whole-body diff would be comparing unrelated fields.
    cf = encode_sib2(ul_carrier_freq=1)
    chk("sib2-ul-carrier-freq-presence-bit", cf[176], "1")
    chk("sib2-ul-carrier-freq-prefix-unmoved",
        [i for i in range(176) if cf[i] != body[i]], [])
    chk("sib2-ul-carrier-freq-value-bits", cf[178:194], "0000000000000001")
    chk("sib2-ul-carrier-freq-body-bits", len(cf), SIB2_BODY_BITS + 16)
    bw = encode_sib2(ul_bandwidth="n100")
    chk("sib2-ul-bandwidth-presence-bit", bw[177], "1")
    chk("sib2-ul-bandwidth-prefix-unmoved",
        [i for i in range(176) if bw[i] != body[i]], [])
    chk("sib2-ul-bandwidth-value-bits", bw[178:181], "101")
    chk("sib2-ul-bandwidth-body-bits", len(bw), SIB2_BODY_BITS + 3)
    chk("sib2-optional-costs-value-bits-only",
        len(encode_sib2(ul_carrier_freq=0, ul_bandwidth="n6")) - SIB2_BODY_BITS,
        16 + 3)

    def _flip(s, i):
        return s[:i] + ("1" if s[i] == "0" else "0") + s[i + 1:]

    # Every one of these is a message this codec does not model. Refusing is
    # the only honest answer: each would move every field after it.
    for label, pos in [("ext", 0), ("ac-barring", 1), ("mbsfn", 2),
                       ("rrc-ext", 3), ("rach-ext", 4), ("group-a", 5)]:
        try:
            decode_sib2(_flip(body, pos))
            failures.append("sib2-reject-%s FAIL accepted an unmodelled body"
                            % label)
        except ValueError:
            pass
    try:
        decode_sib2(_flip(body, 117))
        failures.append("sib2-reject-release FAIL accepted a release "
                        "soundingRS as setup fields")
    except ValueError:
        pass
    try:
        decode_sib2(body[:100])
        failures.append("sib2-reject-short FAIL accepted a 100-bit body")
    except ValueError:
        pass

    # ── SIB4 ────────────────────────────────────────────────────────────
    # SIB4 is the first SIB here with nested structure, so these check the
    # shape as well as the values. The per-cell extension bit is the one an
    # extensibility test written as `len(_ext)` hides, and losing it moves
    # every neighbour cell after the first.
    for name, hexs, nbits, f in SIB4_VECTORS:
        bits = bits_of(hexs, nbits)
        body = encode_sib4(neigh_cells=f.get("neigh_cells"),
                           excluded_cells=f.get("excluded_cells"),
                           csg_phys_cell_id_range=f.get("csg_phys_cell_id_range"))
        chk("sib4-" + name + "-container",
            encode_si(SIB_CHOICE.index("sibType4"), body, 1), bits)
        d = decode_sib4(bits[SI_HEADER_BITS:])
        chk("sib4-" + name + "-consumed", d["bits_consumed"],
            nbits - SI_HEADER_BITS)
        for k, want in f.items():
            chk("sib4-%s-%s" % (name, k), d[SIB4_VECTOR_KEY[k]], want)
        chk("sib4-" + name + "-roundtrip",
            encode_sib4(neigh_cells=d["intra_freq_neigh_cell_list"],
                        excluded_cells=d["intra_freq_excluded_cell_list"],
                        csg_phys_cell_id_range=d["csg_phys_cell_id_range"]), body)

    # The stride is what catches the missing extension bit: 15 bits per
    # neighbour cell, not 14, so sixteen cells is 240 bits and not 224.
    zero = {"phys_cell_id": 0, "q_offset_cell": "dB0"}
    chk("sib4-empty-body-bits", len(encode_sib4()), 4)
    one = encode_sib4(neigh_cells=[zero])
    two = encode_sib4(neigh_cells=[zero, zero])
    chk("sib4-one-body-bits", len(one), 4 + 4 + 15)
    chk("sib4-cell-stride", len(two) - len(one), 15)
    chk("sib4-16-cells-body-bits", len(encode_sib4(neigh_cells=[zero] * 16)), 248)
    # An excluded entry is the other element shape: no extension bit, but a
    # range-present bit, and no length field of its own beyond the list's.
    chk("sib4-excluded-body-bits",
        len(encode_sib4(excluded_cells=[{"start": 0, "range": None}])),
        4 + 4 + 1 + 9)
    chk("sib4-excluded-range-costs-4",
        len(encode_sib4(excluded_cells=[{"start": 0, "range": "n4"}]))
        - len(encode_sib4(excluded_cells=[{"start": 0, "range": None}])), 4)

    # Refusals. Each of these would move every field after it.
    for label, bad in [("ext", "1" + "0" * 40),
                       ("cell-ext", "0100" + "0000" + "1" + "0" * 40),
                       ("short", "01")]:
        try:
            decode_sib4(bad)
            failures.append("sib4-reject-%s FAIL accepted an unmodelled body"
                            % label)
        except ValueError:
            pass

    # SIB5. A neighbour cell here is 14 bits, not SIB4's 15 -- the SIB5 type has
    # no extension marker at all. A test reusing SIB4's stride would still pass
    # on a one-cell list and go wrong from the second cell on, which is exactly
    # the shape of the bug this table was written to catch.
    for name, hexs, nbits, partials in SIB5_VECTORS:
        bits = bits_of(hexs, nbits)
        carriers = [dict(SIB5_DEFAULT_CARRIER, **p) for p in partials]
        body = encode_sib5(carriers=carriers)
        chk("sib5-" + name + "-container",
            encode_si(SIB_CHOICE.index("sibType5"), body, 1), bits)
        d = decode_sib5(bits[SI_HEADER_BITS:])
        chk("sib5-" + name + "-consumed", d["bits_consumed"],
            nbits - SI_HEADER_BITS)
        chk("sib5-" + name + "-fields", d["carriers"], carriers)
        chk("sib5-" + name + "-roundtrip", encode_sib5(carriers=d["carriers"]),
            body)

    chk("sib5-empty-body-bits", len(encode_sib5()), 52)
    zero5 = {"phys_cell_id": 0, "q_offset_cell": "dB0"}
    one5 = encode_sib5(carriers=[dict(SIB5_DEFAULT_CARRIER,
                                      inter_freq_neigh_cell_list=[zero5])])
    two5 = encode_sib5(carriers=[dict(SIB5_DEFAULT_CARRIER,
                                      inter_freq_neigh_cell_list=[zero5, zero5])])
    chk("sib5-neigh-one-body-bits", len(one5), 4 + 48 + 4 + 14)
    chk("sib5-cell-stride", len(two5) - len(one5), 14)
    chk("sib5-cell-past-first-stride",
        len(encode_sib5(carriers=[dict(SIB5_DEFAULT_CARRIER,
            inter_freq_neigh_cell_list=[zero5] * 16)]))
        - len(encode_sib5(carriers=[dict(SIB5_DEFAULT_CARRIER,
            inter_freq_neigh_cell_list=[zero5] * 15)])), 14)
    # The carrier stride is the element's baseline size, and the preamble does
    # not grow with the list, so eight carriers add 7 x 48 to the one-carrier
    # floor.
    chk("sib5-carrier-stride",
        len(encode_sib5(carriers=[{}, {}])) - len(encode_sib5()), 48)
    chk("sib5-8-carriers-body-bits", len(encode_sib5(carriers=[{}] * 8)),
        4 + 8 * 48)

    # Refusals.
    for label, bad in [("ext", "1" + "0" * 60),
                       ("carrier-ext", "0" + "000" + "1" + "0" * 60),
                       ("short", "01")]:
        try:
            decode_sib5(bad)
            failures.append("sib5-reject-%s FAIL accepted an unmodelled body"
                            % label)
        except ValueError:
            pass
    # 503 is physCellId's ceiling; 504 must be refused, not truncated to 0.
    try:
        encode_sib5(carriers=[dict(SIB5_DEFAULT_CARRIER,
                                   inter_freq_neigh_cell_list=[
                                       {"phys_cell_id": 504,
                                        "q_offset_cell": "dB0"}])])
        failures.append("sib5-reject-cell-id FAIL accepted physCellId 504")
    except ValueError:
        pass
    # An unknown carrier key must be refused: a typo would otherwise take the
    # default silently and encode a carrier the caller never asked for.
    try:
        encode_sib5(carriers=[{"dl_carrier_frequency": 1}])
        failures.append("sib5-reject-unknown-key FAIL accepted a typo'd key")
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
    # Same guard as sib2-decode: a container must be long enough to leave a
    # whole body after its 14-bit header, or a bare body gets mistaken for one.
    if (len(bits) - SI_HEADER_BITS >= SIB3_BODY_BITS
            and bits[:SI_PREFIX_BITS] == "0000"):
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


def _sib4_parse_range(text, what):
    """Parse START or START:RANGE into a PhysCellIdRange."""
    head, _, tail = text.partition(":")
    if not head:
        raise ValueError("%s wants START[:RANGE], got %r" % (what, text))
    try:
        start = int(head, 0)
    except ValueError:
        raise ValueError("%s start must be an integer, got %r" % (what, head))
    if not tail:
        return {"start": start, "range": None}
    if tail not in SIB4_PHYS_CELL_ID_RANGE:
        raise ValueError("%s range must be one of %s, got %r"
                         % (what, SIB4_PHYS_CELL_ID_RANGE, tail))
    return {"start": start, "range": tail}


def cmd_sib4(args):
    try:
        neigh = []
        for spec in args.neigh or []:
            pid, sep, off = spec.partition(":")
            if not sep:
                raise ValueError("--neigh wants PHYS:OFFSET, got %r" % spec)
            neigh.append({"phys_cell_id": int(pid, 0), "q_offset_cell": off})
        excluded = [_sib4_parse_range(s, "--excluded")
                    for s in (args.excluded or [])]
        csg = _sib4_parse_range(args.csg, "--csg") if args.csg else None
        body = encode_sib4(neigh_cells=neigh, excluded_cells=excluded,
                           csg_phys_cell_id_range=csg)
    except (ValueError, IndexError) as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2

    print("sib\tSystemInformationBlockType4")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    print("neigh_count\t%d" % len(neigh))
    for c in neigh:
        print("neigh\t%d\t%s" % (c["phys_cell_id"], c["q_offset_cell"]))
    print("excluded_count\t%d" % len(excluded))
    for c in excluded:
        print("excluded\t%d\t%s" % (c["start"], c["range"] or "-"))
    print("csg_phys_cell_id_range\t%s"
          % ("%d:%s" % (csg["start"], csg["range"] or "-") if csg else "-"))
    print("body_bits\t%d" % len(body))
    print("body_bits_str\t%s" % body)
    print("body_hex\t%s" % _bits_to_hex(body))
    if not args.body_only:
        full = encode_si(SIB_CHOICE.index("sibType4"), body, 1)
        print("container_bits\t%d" % len(full))
        print("container_hex\t%s" % _bits_to_hex(full))
    return 0


def cmd_sib4_decode(args):
    bits = bits_of(args.hex, args.bits)
    # Same guard as sib2-decode and sib3-decode. A bare SIB4 body is at least
    # four bits and starts with the extension bit, so the only four-zero prefix
    # it can have is the four-bit empty body, which is too short to be confused
    # for a container once the header is subtracted.
    if len(bits) - SI_HEADER_BITS >= 4 and bits[:SI_PREFIX_BITS] == "0000":
        try:
            d = decode_si(bits)
            if d["sib"] == "sibType4":
                bits = d["body_bits"]
        except ValueError:
            pass

    try:
        d = decode_sib4(bits)
    except ValueError as exc:
        sys.stderr.write("ERROR\tnot a SIB4 body: %s\n" % exc)
        return 1

    print("message\tSystemInformationBlockType4")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    neigh = d["intra_freq_neigh_cell_list"]
    print("neigh_count\t%d" % (len(neigh) if neigh else 0))
    for c in neigh or []:
        print("neigh\t%d\t%s" % (c["phys_cell_id"], c["q_offset_cell"]))
    excluded = d["intra_freq_excluded_cell_list"]
    print("excluded_count\t%d" % (len(excluded) if excluded else 0))
    for c in excluded or []:
        print("excluded\t%d\t%s" % (c["start"], c["range"] or "-"))
    csg = d["csg_phys_cell_id_range"]
    print("csg_phys_cell_id_range\t%s"
          % ("%d:%s" % (csg["start"], csg["range"] or "-") if csg else "-"))
    print("bits_consumed\t%d" % d["bits_consumed"])
    return 0


def _sib5_parse_carrier(spec):
    """Parse one --carrier value into a SIB5 carrier dict.

    The form is comma-separated key=value pairs, with two keys that hold more
    than one item spelled as a pipe-separated list:

        --carrier dl_carrier_freq=1234,q_rx_lev_min=-100,p_max=23
        --carrier dl_carrier_freq=0,neigh=42:dB6|7:dB-24
        --carrier dl_carrier_freq=0,excluded=100:n8|300:
        --carrier dl_carrier_freq=0,tresel_sf=oDot5:lDot0,prio=5

    A bare `key=` yields None, which is how an OPTIONAL is left absent when the
    carrier is merged over SIB5_DEFAULT_CARRIER.
    """
    out = {}
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        key, sep, val = item.partition("=")
        if not sep:
            raise ValueError("--carrier wants key=value, got %r" % item)
        key = key.strip()
        if key in ("neigh", "neigh_cell_list", "inter_freq_neigh_cell_list"):
            cells = []
            for one in val.split("|"):
                if not one:
                    continue
                pid, colon, off = one.partition(":")
                if not colon:
                    raise ValueError("neigh wants PHYS:OFFSET, got %r" % one)
                cells.append({"phys_cell_id": int(pid, 0), "q_offset_cell": off})
            out["inter_freq_neigh_cell_list"] = cells or None
        elif key in ("excluded", "excluded_cell_list",
                     "inter_freq_excluded_cell_list"):
            cells = []
            for one in val.split("|"):
                if not one:
                    continue
                cells.append(_sib4_parse_range(one, "excluded"))
            out["inter_freq_excluded_cell_list"] = cells or None
        elif key in ("tresel_sf", "t_reselection_eutra_sf"):
            if not val:
                out["t_reselection_eutra_sf"] = None
            else:
                med, colon, high = val.partition(":")
                if not colon:
                    raise ValueError("tresel_sf wants SF-MEDIUM:SF-HIGH, got %r"
                                     % val)
                out["t_reselection_eutra_sf"] = {"sf_medium": med,
                                                 "sf_high": high}
        elif key in ("neigh_cfg", "neigh_cell_config"):
            out["neigh_cell_config"] = val
        elif key in ("antport1", "presence_antenna_port1"):
            out["presence_antenna_port1"] = val.lower() in ("1", "true", "yes")
        elif key == "prio":
            out["cell_reselection_priority"] = None if not val else int(val, 0)
        elif key == "ambw":
            out["allowed_meas_bandwidth"] = val
        elif key in ("qoff", "q_offset_freq"):
            out["q_offset_freq"] = val or None
        else:
            if key not in SIB5_CARRIER_KEYS:
                raise ValueError("unknown --carrier key %r; the keys are %s"
                                 % (key, ", ".join(SIB5_CARRIER_KEYS)))
            out[key] = None if not val else int(val, 0)
    return out


def cmd_sib5(args):
    try:
        carriers = [_sib5_parse_carrier(s) for s in (args.carrier or [])] or None
        body = encode_sib5(carriers=carriers)
        merged = [dict(SIB5_DEFAULT_CARRIER, **_sib5_parse_carrier(s))
                  for s in (args.carrier or [])] or [dict(SIB5_DEFAULT_CARRIER)]
    except (ValueError, IndexError) as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2

    print("sib\tSystemInformationBlockType5")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    print("carrier_count\t%d" % len(merged))
    for i, c in enumerate(merged):
        neigh = c["inter_freq_neigh_cell_list"] or []
        excl = c["inter_freq_excluded_cell_list"] or []
        print("carrier\t%d\tdl_carrier_freq=%d\tq_rx_lev_min=%d\tp_max=%s"
              "\tthresh_x_high=%d\tthresh_x_low=%d\tambw=%s\tantport1=%s"
              "\tneigh_cell_config=%s\tt_reselection_eutra=%d\tprio=%s"
              "\tq_offset_freq=%s\tneigh=%s\texcluded=%s"
              % (i, c["dl_carrier_freq"], c["q_rx_lev_min"],
                 c["p_max"] if c["p_max"] is not None else "-",
                 c["thresh_x_high"], c["thresh_x_low"],
                 c["allowed_meas_bandwidth"],
                 "1" if c["presence_antenna_port1"] else "0",
                 c["neigh_cell_config"], c["t_reselection_eutra"],
                 c["cell_reselection_priority"]
                 if c["cell_reselection_priority"] is not None else "-",
                 c["q_offset_freq"] or "-",
                 "|".join("%d:%s" % (x["phys_cell_id"], x["q_offset_cell"])
                          for x in neigh) or "-",
                 "|".join("%d:%s" % (x["start"], x["range"] or "-")
                          for x in excl) or "-"))
    print("body_bits\t%d" % len(body))
    print("body_bits_str\t%s" % body)
    print("body_hex\t%s" % _bits_to_hex(body))
    if not args.body_only:
        full = encode_si(SIB_CHOICE.index("sibType5"), body, 1)
        print("container_bits\t%d" % len(full))
        print("container_hex\t%s" % _bits_to_hex(full))
    return 0


def cmd_sib5_decode(args):
    bits = bits_of(args.hex, args.bits)
    # No auto-detection here, unlike sib2/3/4-decode. A SIB5 body opens with
    # the extension bit followed by a 3-bit length, so its first four bits are
    # "0000" for the ordinary one-carrier case -- exactly what a
    # SystemInformation header looks like. Guessing would sometimes decode a
    # body as a container, so the caller says which with --container.
    if args.container:
        try:
            d = decode_si(bits)
        except ValueError as exc:
            sys.stderr.write("ERROR\tnot a SystemInformation container: %s\n"
                             % exc)
            return 1
        if d["sib"] != "sibType5":
            sys.stderr.write("ERROR\tcontainer carries %s, not sibType5\n"
                             % d["sib"])
            return 1
        bits = d["body_bits"]

    try:
        d = decode_sib5(bits)
    except ValueError as exc:
        sys.stderr.write("ERROR\tnot a SIB5 body: %s\n" % exc)
        return 1

    print("message\tSystemInformationBlockType5")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    print("carrier_count\t%d" % len(d["carriers"]))
    for i, c in enumerate(d["carriers"]):
        print("carrier\t%d\tdl_carrier_freq=%d\tq_rx_lev_min=%d\tp_max=%s"
              "\tthresh_x_high=%d\tthresh_x_low=%d\tambw=%s\tantport1=%s"
              "\tneigh_cell_config=%s\tt_reselection_eutra=%d\tprio=%s"
              "\tq_offset_freq=%s"
              % (i, c["dl_carrier_freq"], c["q_rx_lev_min"],
                 c["p_max"] if c["p_max"] is not None else "-",
                 c["thresh_x_high"], c["thresh_x_low"],
                 c["allowed_meas_bandwidth"],
                 "1" if c["presence_antenna_port1"] else "0",
                 c["neigh_cell_config"], c["t_reselection_eutra"],
                 c["cell_reselection_priority"]
                 if c["cell_reselection_priority"] is not None else "-",
                 c["q_offset_freq"] or "-"))
        for cell in c["inter_freq_neigh_cell_list"] or []:
            print("neigh\t%d\t%d\t%s" % (i, cell["phys_cell_id"],
                                         cell["q_offset_cell"]))
        for cell in c["inter_freq_excluded_cell_list"] or []:
            print("excluded\t%d\t%d\t%s" % (i, cell["start"],
                                            cell["range"] or "-"))
    print("bits_consumed\t%d" % d["bits_consumed"])
    return 0


def _sib2_step(name):
    for step in SIB2_LAYOUT:
        if step["n"] == name:
            return step
    return None


def cmd_sib2(args):
    if args.fields:
        for step in SIB2_LAYOUT:
            if step["k"] == "optbit":
                continue        # derived from whether its value is set
            default = step.get("d")
            if step["k"] in ("optint", "optenum"):
                default = "(absent)"
            print("%s\t%s\t%s" % (step["n"], step["k"], default))
        return 0

    kw = {}
    for spec in args.set:
        if "=" not in spec:
            sys.stderr.write("ERROR\t--set wants NAME=VALUE, got %r\n" % spec)
            return 2
        name, raw = spec.split("=", 1)
        step = _sib2_step(name)
        if step is None:
            sys.stderr.write("ERROR\tno SIB2 field named %r; "
                             "`lte_asn1.py sib2 --fields` lists them\n" % name)
            return 2
        if step["k"] == "optbit":
            sys.stderr.write("ERROR\t%s is set by giving its value, not by "
                             "naming it\n" % name)
            return 2
        try:
            if step["k"] == "bit":
                if raw in ("0", "false", "False", "no"):
                    kw[name] = 0
                elif raw in ("1", "true", "True", "yes"):
                    kw[name] = 1
                else:
                    raise ValueError("%s is a single bit (0 or 1)" % name)
            elif step["k"] in ("int", "optint"):
                kw[name] = int(raw, 0)
            else:
                kw[name] = raw
        except ValueError as exc:
            sys.stderr.write("ERROR\t%s\n" % exc)
            return 2

    try:
        body = encode_sib2(**kw)
    except ValueError as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2

    print("sib\tSystemInformationBlockType2")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    print("fields_set\t%d" % len(kw))
    for k in sorted(kw):
        print("%s\t%s" % (k, kw[k]))
    print("body_bits\t%d" % len(body))
    print("body_bits_str\t%s" % body)
    print("body_hex\t%s" % _bits_to_hex(body))
    if not args.body_only:
        full = encode_si(SIB_CHOICE.index("sibType2"), body, 1)
        print("container_bits\t%d" % len(full))
        print("container_hex\t%s" % _bits_to_hex(full))
    return 0


def cmd_sib2_decode(args):
    bits = bits_of(args.hex, args.bits)
    # Only treat the input as a container when a 14-bit header would still
    # leave a whole body behind. Without that test a bare body whose first ten
    # bits happen to be zero -- which the all-defaults body's are -- would be
    # read as a container and silently lose its first 14 bits.
    if (len(bits) - SI_HEADER_BITS >= SIB2_BODY_BITS
            and bits[:SI_PREFIX_BITS] == "0000"):
        try:
            d = decode_si(bits)
            if d["sib"] == "sibType2":
                bits = d["body_bits"]
        except ValueError:
            pass

    try:
        d = decode_sib2(bits)
    except ValueError as exc:
        sys.stderr.write("ERROR\tnot a SIB2 body this codec models: %s\n" % exc)
        return 1

    print("message\tSystemInformationBlockType2")
    print("layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)")
    for k, v in d.items():
        if k == "bits_consumed":
            continue
        if k == "srs_max_up_pts":
            print("%s\t%s" % (k, "present" if v else "absent"))
        elif isinstance(v, bool):
            print("%s\t%d" % (k, 1 if v else 0))
        elif v is None:
            print("%s\tabsent" % k)
        else:
            print("%s\t%s" % (k, v))
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

    s2 = sub.add_parser("sib2", help="encode a SystemInformationBlockType2")
    s2.add_argument("--set", action="append", default=[], metavar="NAME=VALUE",
                    help="set a field; repeatable. --fields lists the names")
    s2.add_argument("--fields", action="store_true",
                    help="list the settable fields and their defaults")
    s2.add_argument("--body-only", action="store_true",
                    help="omit the SystemInformation container wrapper")
    s2.set_defaults(func=cmd_sib2)

    s2d = sub.add_parser("sib2-decode",
                         help="decode a SystemInformationBlockType2 body")
    s2d.add_argument("hex", help="the body (or whole container), as hex")
    s2d.add_argument("--bits", type=int, default=None,
                     help="the true bit length, before hex padding")
    s2d.set_defaults(func=cmd_sib2_decode)

    s4 = sub.add_parser("sib4", help="encode a SystemInformationBlockType4")
    s4.add_argument("--neigh", action="append", default=[], metavar="PHYS:OFFSET",
                    help="add a neighbour cell, e.g. 42:dB6; repeatable")
    s4.add_argument("--excluded", action="append", default=[],
                    metavar="START[:RANGE]",
                    help="add an excluded PhysCellIdRange; repeatable")
    s4.add_argument("--csg", metavar="START[:RANGE]", default=None,
                    help="the csg-PhysCellIdRange")
    s4.add_argument("--body-only", action="store_true",
                    help="omit the SystemInformation container wrapper")
    s4.set_defaults(func=cmd_sib4)

    s4d = sub.add_parser("sib4-decode",
                         help="decode a SystemInformationBlockType4 body")
    s4d.add_argument("hex", help="the body (or whole container), as hex")
    s4d.add_argument("--bits", type=int, default=None,
                     help="the true bit length, before hex padding")
    s4d.set_defaults(func=cmd_sib4_decode)

    s5 = sub.add_parser("sib5", help="encode a SystemInformationBlockType5")
    s5.add_argument("--carrier", action="append", default=[], metavar="K=V,...",
                    help="one InterFreqCarrierFreqInfo as comma-separated "
                         "key=value pairs; repeatable, one per carrier. "
                         "neigh=PHYS:OFFSET|... and excluded=START[:RANGE]|... "
                         "hold lists, tresel_sf=SF-MEDIUM:SF-HIGH, "
                         "prio=N, ambw=mbw6..mbw100, antport1=0|1, "
                         "neigh_cfg=00..11; a bare key= leaves an OPTIONAL out")
    s5.add_argument("--body-only", action="store_true",
                    help="omit the SystemInformation container wrapper")
    s5.set_defaults(func=cmd_sib5)

    s5d = sub.add_parser("sib5-decode",
                         help="decode a SystemInformationBlockType5 body")
    s5d.add_argument("hex", help="the body, as hex")
    s5d.add_argument("--bits", type=int, default=None,
                     help="the true bit length, before hex padding")
    s5d.add_argument("--container", action="store_true",
                     help="the hex is a whole SystemInformation container; "
                          "required because a SIB5 body also starts with four "
                          "zero bits, so this cannot be auto-detected")
    s5d.set_defaults(func=cmd_sib5_decode)

    args = p.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
