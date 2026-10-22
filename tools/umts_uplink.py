#!/usr/bin/env python3
"""tools/umts_uplink.py -- the uplink side of a UMTS catcher.

Everything modules/08_umts_air.sh builds is what the *network* sends: DL-CCCH,
PCCH, the downlink RRC messages and the downlink physical channels in
tools/umts_phy.py.  This file is the other direction -- what a *handset* sends:

    request       RRC CONNECTION REQUEST, UL-CCCH, TS 25.331 clause 10.2.39
    prach         the PRACH preamble, TS 25.213 4.3.3.2/4.3.3.3 + TS 25.211 5.2.2.1.2
    message-part  the DPCCH/DPDCH slot structure of the RACH message part,
                  TS 25.211 5.2.2.1.3, as a bit structure (not as chips)
    list          the verbs and their flags

Output is one row per fact, tab separated: the same shape as tools/umts_sib.py,
tools/umts_phy.py and the `uair_rrc_emit` rows of modules/08_umts_air.sh.  Every
row carries a `ref` that cites the clause the value came from, and everything
this file does NOT build is named in a `limit` row rather than approximated.

Specifications and where each constant comes from
-------------------------------------------------
TS 25.331 v6.4.0 (RRC protocol) -- /tmp/ts331.txt, `pdftotext -layout`
    10.2.39      RRC CONNECTION REQUEST message contents      (p.427, ts331.txt:876)
    10.3.3.15    Initial UE identity: the InitialUE-Identity CHOICE, 8 alternatives,
                 written down as ASN.1 in 11.3                   (ts331.txt:55021)
    10.3.1.17    TMSI (GSM-MAP), BIT STRING (SIZE (32))
    10.3.1.5     IMSI (GSM-MAP), SIZE (6..21) OF Digit
    10.3.1.7     Location Area Identification (plmn-Identity then lac)
    11.3         Information element definitions, where MCC (SIZE (3)), MNC
                 (SIZE (2..3)), Digit (0..9) and TMSI-and-LAI-GSM-MAP itself live
    10.3.3.11    Establishment cause, 32 values, no extension marker
    10.3.3.27    Protocol error indicator, 2 values
    11.2         UL-CCCH-Message ASN.1: integrityCheckInfo OPTIONAL, absent here
    12.1         the message is a bit string padded with zero bits to a whole octet
    X.691        ITU-T X.691 (PER) for the bit-level rules named in each `ref`
TS 25.213 v6.4.0 (spreading and modulation) -- /tmp/ts125213.txt
    4.2.2.2      binary "0" -> +1, "1" -> -1 (real/complex chip mapping)
    4.3.1.2.1    downlink/inner channelisation: DPDCH1 = C_ch,SF,SF/4
    4.3.2.2      c_long,1,n / c_long,2,n: degree 25 Gold sequences
    4.3.2.5      S_r-msg,n(i) = C_long,n(i+4096) (message part scrambling)
    4.3.3.2      S_r-pre,n(i) = c_long,1,n(i), i = 0..4095; n = 16*m + k
    4.3.3.3      Table 3: 16 signatures of length 16 (Hadamard), and
                 C_pre,n,s(k) = S_r-pre,n(k) . C_sig,s(k) . exp(j(pi/4 + k pi/2))
TS 25.211 v6.4.0 (physical channels) -- /tmp/ts125211.txt
    5.2.2.1.1    15 access slots per 2 frames, 5120 chips apart
    5.2.2.1.2    preamble = 4096 chips = 256 repetitions of a 16-chip signature
    5.2.2.1.3    message part = 15 slots x 2560 chips = 38400 chips = 10 ms;
                 Table 6 (slot formats: N_data 10/20/40/80, SF 256/128/64/32),
                 Table 7 (N_pilot = 8, N_TFCI = 2), Table 8 (pilot bit patterns);
                 2 TFCI bits per slot -> 30 TFCI bits per message part frame
TS 25.212 v6.4.0 (multiplexing and channel coding) -- /tmp/t.txt, cited only in
    `limit` rows 4.2/4.3, for the transport chain and TFCI coding this file
    does not build.
"""

import argparse
import hashlib
import math
import os
import sys
from array import array

# ── constants, with the clause that fixes each one ──────────────────────
CHIP_RATE = 3840000          # TS 25.213 4.4.1: "The modulating chip rate is
                             # 3.84 Mcps" (and 5.3.1 for the downlink)
PREAMBLE_CHIPS = 4096        # TS 25.211 5.2.2.1.1: preamble of length 4096 chips
SIGNATURE_CHIPS = 16         # TS 25.211 5.2.2.1.2: 16-chip signature
PREAMBLE_REPS = 256          # 4096 / 16
ACCESS_SLOTS = 15            # TS 25.211 5.2.2.1.1: 15 access slots per two frames
ACCESS_SLOT_CHIPS = 5120     # TS 25.211 5.2.2.1.1: 5120 chips between access slots
CHIPS_PER_SLOT = 2560        # TS 25.211 5.2.1.1: 10 ms = 15 slots at 2560 chips
SLOTS_PER_FRAME = 15
CHIPS_PER_FRAME = CHIPS_PER_SLOT * SLOTS_PER_FRAME          # 38400
ACCESS_WINDOW_CHIPS = 2 * CHIPS_PER_FRAME                   # 76800 = 15 * 5120

# TS 25.211 5.2.2.1.3 Table 6: slot format k -> (spreading factor, N_data).
SLOT_FORMATS = {
    0: (256, 10),
    1: (128, 20),
    2: (64, 40),
    3: (32, 80),
}

# TS 25.211 5.2.2.1.3 Table 7: control part of the RACH message part, DPCCH.
N_PILOT = 8
N_TFCI = 2

# TS 25.211 5.2.2.1.3 Table 8: pilot bit patterns for N_pilot = 8, slots 0..14.
PILOT_PATTERNS = (
    "11111110",
    "10101110",
    "10111011",
    "10101010",
    "11101011",
    "11111110",
    "11111010",
    "11101010",
    "10111110",
    "11111111",
    "10111011",
    "11101111",
    "11101010",
    "10101111",
    "10101111",
)

# TS 25.213 4.3.3.3 Table 3: the 16 signature codes P_s, s = 0..15, i = 0..15.
# '1' means +1 and '0' means -1, in the order printed in the clause.  The table
# is exactly the Sylvester Hadamard matrix, P_s(i) = (-1)**popcount(s AND i) --
# tools/check-umts-uplink.sh generates that matrix independently and requires
# this transcription to equal it, so a typo here cannot pass the checker.
SIGNATURES = (
    "1111111111111111",   #  0
    "1010101010101010",   #  1
    "1100110011001100",   #  2
    "1001100110011001",   #  3
    "1111000011110000",   #  4
    "1010010110100101",   #  5
    "1100001111000011",   #  6
    "1001011010010110",   #  7
    "1111111100000000",   #  8
    "1010101001010101",   #  9
    "1100110000110011",   # 10
    "1001100101100110",   # 11
    "1111000000001111",   # 12
    "1010010101011010",   # 13
    "1100001100111100",   # 14
    "1001011001101001",   # 15
)

# TS 25.213 4.3.3.3: exp(j(pi/4 + k pi/2)) for k mod 4 = 0,1,2,3.  Every preamble
# chip is one of these four values times +1 or -1, so it is exactly +-(1+-j)/sqrt2.
_PHASE = (
    complex(1.0, 1.0) / math.sqrt(2.0),
    complex(-1.0, 1.0) / math.sqrt(2.0),
    complex(-1.0, -1.0) / math.sqrt(2.0),
    complex(1.0, -1.0) / math.sqrt(2.0),
)

# TS 25.331 10.3.3.11: EstablishmentCause.  v6.4.0 has 32 values and no extension
# marker, so the index is five bits (X.691 23.1).  Values 21..31 are spare11..spare1
# in this release; later releases gave 21..23 names (mbms-PTP-RB-Request,
# delayTolerantAccess, spare9), which is why the checker asserts causes by index
# and only uses names for 0..20, where every release agrees.
ESTABLISHMENT_CAUSES = (
    "originatingConversationalCall",
    "originatingStreamingCall",
    "originatingInteractiveCall",
    "originatingBackgroundCall",
    "originatingSubscribedTrafficCall",
    "terminatingConversationalCall",
    "terminatingStreamingCall",
    "terminatingInteractiveCall",
    "terminatingBackgroundCall",
    "emergencyCall",
    "interRAT-CellReselection",
    "interRAT-CellChangeOrder",
    "registration",
    "detach",
    "originatingHighPrioritySignalling",
    "originatingLowPrioritySignalling",
    "callRe-establishment",
    "terminatingHighPrioritySignalling",
    "terminatingLowPrioritySignalling",
    "terminatingCauseUnknown",
    "mbms-Reception",
    "spare11",
    "spare10",
    "spare9",
    "spare8",
    "spare7",
    "spare6",
    "spare5",
    "spare4",
    "spare3",
    "spare2",
    "spare1",
)

# TS 25.331 10.3.3.15: InitialUE-Identity, eight alternatives, no extension marker.
INITIAL_UE_IDENTITIES = (
    "imsi",
    "tmsi-and-LAI",
    "p-TMSI-and-RAI",
    "imei",
    "esn-DS-41",
    "imsi-DS-41",
    "imsi-and-ESN-DS-41",
    "tmsi-DS-41",
)

# Every verb prints every limit: what this file refuses to build and why.
LIMITS = (
    (
        "no-uplink-transmission",
        "nothing is transmitted and nothing is keyed to a radio: this file produces "
        "the octets and the samples, and tools/umts_phy.py produces downlink "
        "baseband.  An uplink transmitter needs the frame timing of the cell it "
        "answers (TS 25.211 5.2.2.1.1: access slots are 5120 chips apart with an "
        "offset the network signals in the SIB5 PRACH system information), and "
        "that timing is not built here.",
    ),
    (
        "message-part-spreading",
        "message-part names the channelisation codes but does not spread and does "
        "not apply beta gains: TS 25.213 4.3.1.3 gives the control part "
        "cc = Cch,256,16*s+15 and the data part cd = Cch,SF,SF*s/16 for preamble "
        "signature s, TS 25.213 4.2.2.2 puts the data part on the I branch and the "
        "control part on the Q branch multiplied by beta_d and beta_c, and "
        "beta_c/beta_d are signalled by the network in the PRACH message-part "
        "gains.  Without them any chip stream would be a shape, not a signal.",
    ),
    (
        "message-part-scrambling",
        "message-part does not scramble: TS 25.213 4.3.2.5 needs S_r-msg,n(i) = "
        "C_long,n(i + 4096) for i = 0..38399, and C_long,n(i) depends on "
        "c_long,2,n(2*floor(i/2)) = Z_n((2*floor(i/2) + 16777232) mod (2^25-1)).  "
        "The Gold sequence would therefore have to be run to symbol index about "
        "16.8 million in a pure Python loop for every message part.  prach needs "
        "only indices 0..4095, which is why the preamble is generated as chips and "
        "the message part is not.",
    ),
    (
        "message-part-tfci-coding",
        "message-part takes the 30 TFCI bits as an input codeword and does not "
        "encode a TFCI value: TS 25.212 4.3 (coding of the TFCI) turns a set of "
        "transport format combinations into those 30 bits, and that coding is "
        "built nowhere in this tree for the uplink direction.",
    ),
    (
        "message-part-transport-chain",
        "message-part takes the data bits as an input bit string and does not run "
        "the RACH transport channel: TS 25.212 4.2 (the uplink transport chain: "
        "CRC attachment, transport block concatenation, channel coding, rate "
        "matching, interleaving) is not built for the uplink here.",
    ),
    (
        "message-part-samples",
        "message-part writes no samples file: without spreading, gains and "
        "scrambling (see the three limits above) the only honest output is the bit "
        "structure, so this verb has no --out.",
    ),
    (
        "prach-no-pulse-shaping",
        "prach repeats each chip for the whole number of samples per chip (zero "
        "order hold) and applies no pulse shaping filter: TS 25.213 4.2.2.2 gives "
        "the spread signal at chip rate, and the transmit filter and the "
        "modulation to a carrier are a radio's business, not this file's.",
    ),
    (
        "prach-decomposition-switches",
        "--no-scrambling and --no-signature exist so the checker can show the two "
        "multiplications are separable; the samples they write are NOT the "
        "physical PRACH preamble and carry no information.",
    ),
    (
        "request-optional-ies",
        "request encodes the two OPTIONAL components of RRCConnectionRequest "
        "(measuredResultsOnRACH, v3d0NonCriticalExtensions) as absent and offers "
        "no way to make them present: each would pull in a whole measured-results "
        "or later-release IE, so --measured and --v3d0 refuse with exit 2 instead "
        "of inventing a presence bit and leaving the IE body unwritten.",
    ),
    (
        "request-identity-choices",
        "request builds only two of the eight InitialUE-Identity alternatives: imsi "
        "(IMSI-GSM-MAP) and tmsi-and-LAI (TMSI-and-LAI-GSM-MAP), which are the two a "
        "handset opening a connection sends, and it refuses the rest.  p-TMSI-and-RAI "
        "would be the GPRS form of the same thing; imei, esn-DS-41, imsi-DS-41, "
        "imsi-and-ESN-DS-41 and tmsi-DS-41 exist for the USIM/ME identity procedures "
        "and no catcher sends them.  There is no imsi-and-LAI alternative in the "
        "ASN.1 at all: TS 25.331 10.3.3.15 sends the IMSI bare, because the LAI is "
        "not part of an IMSI identity.",
    ),
    (
        "ciphering-and-integrity",
        "no row of this file carries a MAC-I and nothing is ciphered: an RRC "
        "CONNECTION REQUEST is sent before security activation, so "
        "integrityCheckInfo is absent (TS 25.331 11.2) and no ciphering is in "
        "force.",
    ),
    (
        "pycrate-referee",
        "this tool makes no claim of external verification.  Only "
        "tools/check-umts-uplink.sh holds the rows it prints against an independent "
        "decoder (pycrate's transcription of TS 25.331 for the request, tshark 4.2.2 "
        "over GSMTAP for the same octets, and a from-the-clause recomputation for "
        "the PRACH chips); round trips through this file prove nothing.",
    ),
)

# The limit rows a given verb still owes (the rest are general).
VERB_LIMITS = {
    "request": ("no-uplink-transmission", "request-optional-ies",
                "request-identity-choices", "ciphering-and-integrity",
                "pycrate-referee"),
    "prach": ("no-uplink-transmission", "prach-no-pulse-shaping",
              "prach-decomposition-switches", "pycrate-referee"),
    "message-part": ("message-part-spreading", "message-part-scrambling",
                     "message-part-tfci-coding", "message-part-transport-chain",
                     "message-part-samples", "pycrate-referee"),
}


# ── output, in the row style of tools/umts_sib.py ───────────────────────
def _emit(rows):
    out = sys.stdout
    for k, v in rows:
        out.write("%s\t%s\n" % (k, v))


def _die(rc, msg, why=None):
    sys.stderr.write("ERROR\t%s\n" % msg)
    if why:
        sys.stderr.write("WHY\t%s\n" % why)
    raise SystemExit(rc)


def _limits(verb):
    for key in VERB_LIMITS[verb]:
        for k, text in LIMITS:
            if k == key:
                _emit([("limit", "%s: %s" % (k, text))])
                break


def _iw(lo, hi):
    """Bits for a constrained whole number, X.691 10.5."""
    n = hi - lo + 1
    if n <= 1:
        return 0
    return (n - 1).bit_length()


def _bits_int(value, width):
    if value < 0 or value >= (1 << width):
        raise ValueError("value does not fit")
    return format(value, "0%db" % width)


def _bits_hex(bits):
    """Right-pad to a whole octet, then hex: TS 25.331 12.1 (zero padding)."""
    pad = (-len(bits)) % 8
    bits = bits + "0" * pad
    return "%0*x" % (len(bits) // 4, int(bits, 2))


def _pad_bits(bits):
    return (-len(bits)) % 8


def _parse_int(text, what):
    t = text.strip()
    if not t:
        _die(2, "%s is empty" % what)
    try:
        if t.lower().startswith(("0x", "0b")):
            return int(t, 0)
        if t.isdigit():
            return int(t, 10)
        return int(t, 0)
    except ValueError:
        _die(2, "%s %r is not a number" % (what, text),
             "hexadecimal takes a 0x prefix; decimal is plain digits")


def _parse_hex(text, what, width):
    """A hex field in this tree's convention: bare hex digits, optional 0x, left padded."""
    t = text.strip()
    if t.lower().startswith("0x"):
        t = t[2:]
    if not t or any(c not in "0123456789abcdefABCDEF" for c in t):
        _die(2, "%s %r is not hexadecimal" % (what, text),
             "hex fields in this tree are bare hex digits, optionally 0x-prefixed; "
             "decimal is not accepted for a BIT STRING")
    if len(t) > width:
        _die(2, "%s has %d hex digits, the field holds %d" % (what, len(t), width))
    return int(t, 16), t.rjust(width, "0").lower()


def _parse_digits(text, what, lo, hi):
    if not text or not text.isdigit():
        _die(2, "%s %r must be decimal digits" % (what, text),
             "TS 25.331 11.3: each Digit is an INTEGER (0..9), not hex")
    out = [int(c) for c in text]
    if not (lo <= len(out) <= hi):
        _die(2, "%s has %d digits, needs %d..%d" % (what, len(out), lo, hi),
             "the ASN.1 of TS 25.331 11.3 fixes MCC at 3 digits and MNC at 2..3")
    return out


class Enc:
    """A bit writer that also keeps one `ref` row per field it writes."""

    def __init__(self):
        self.parts = []
        self.n = 0
        self.refs = []

    def _add(self, name, bits, ref, note):
        self.parts.append(bits)
        self.n += len(bits)
        unit = "bit" if len(bits) == 1 else "bits"
        tail = "" if not note else "; " + note
        self.refs.append("%s -> %s (%d %s)  [%s%s]" % (name, bits, len(bits), unit, ref, tail))

    def raw(self, name, bits, ref, note=None):
        if not bits:
            raise ValueError("empty field")
        self._add(name, bits, ref, note)

    def field(self, name, value, lo, hi, ref, note=None):
        w = _iw(lo, hi)
        if not (lo <= value <= hi):
            _die(2, "%s = %d is outside %d..%d" % (name, value, lo, hi))
        self._add(name, _bits_int(value - lo, w),
                  "%s; %d value%s from %d, X.691 10.5" % (ref, w, "" if w == 1 else "s", lo),
                  note)

    def enum(self, name, index, width, count, ref, note=None):
        if not (0 <= index < count):
            _die(2, "%s index %d is outside 0..%d" % (name, index, count - 1))
        self._add(name, _bits_int(index, width),
                  "%s; %d alternatives, X.691 23.1" % (ref, count), note)

    def flag(self, name, value, ref, note=None):
        self._add(name, "1" if value else "0", ref, note)

    def opt(self, name, present, ref, note=None):
        state = "present" if present else "absent"
        tail = "%s, %s" % (ref, state)
        if note:
            tail += "; " + note
        self._add(name, "1" if present else "0", tail, None)

    def bits(self):
        return "".join(self.parts)


# ── RRC CONNECTION REQUEST, UL-CCCH (TS 25.331 10.2.39) ─────────────────
def _cause_index(text):
    t = text.strip()
    if t in ESTABLISHMENT_CAUSES:
        return ESTABLISHMENT_CAUSES.index(t)
    v = _parse_int(t, "--cause")
    if not (0 <= v < len(ESTABLISHMENT_CAUSES)):
        _die(2, "--cause %d is outside 0..31" % v,
             "EstablishmentCause has 32 values in TS 25.331 v6.4.0 10.3.3.11")
    return v


def cmd_request(a):
    if a.measured:
        _die(2, "--measured asks for measuredResultsOnRACH to be present",
             "this tool does not encode a MeasuredResultsOnRACH, and inventing the "
             "presence bit without its body would produce a message no handset sends "
             "and no decoder accepts (TS 25.331 10.2.39: the component is OPTIONAL, "
             "so absent is both legal and what a real request carries)")
    if a.v3d0:
        _die(2, "--v3d0 asks for v3d0NonCriticalExtensions to be present",
             "the v3d0 extension is a later-release IE group; this tool writes only "
             "the r3 body of RRCConnectionRequest and refuses to set a presence bit "
             "for a group whose IEs it does not encode (TS 25.331 10.2.39)")
    if a.imsi and a.tmsi:
        _die(2, "--imsi and --tmsi are alternative initialUE-Identity choices",
             "InitialUE-Identity is a CHOICE of eight alternatives (TS 25.331 "
             "10.3.3.15); a request carries exactly one of them")
    if a.tmsi is None and a.imsi is None:
        a.tmsi = "12345678"        # the identity modules/08_umts_air.sh defaults to
    mcc = _parse_digits(a.mcc, "--mcc", 3, 3)
    mnc = _parse_digits(a.mnc, "--mnc", 2, 3)
    cause = _cause_index(a.cause)
    e = Enc()

    # UL-CCCH-Message ::= SEQUENCE { integrityCheckInfo IntegrityCheckInfo OPTIONAL,
    #                                message UL-CCCH-MessageType }
    e.opt("integrityCheckInfo", 0,
          "UL-CCCH-Message ::= SEQUENCE {integrityCheckInfo IntegrityCheckInfo "
          "OPTIONAL, message UL-CCCH-MessageType} (TS 25.331 11.2)",
          "an RRC CONNECTION REQUEST is sent before security activation so it "
          "carries no MAC-I")

    # UL-CCCH-MessageType ::= CHOICE { cellUpdate, rrcConnectionRequest, uraUpdate, ... }
    e.enum("message", 1, 2, 4,
           "UL-CCCH-MessageType ::= CHOICE {cellUpdate, rrcConnectionRequest, "
           "uraUpdate, extension} (TS 25.331 11.2)",
           "three root alternatives plus the extension marker")

    # RRCConnectionRequest ::= SEQUENCE { initialUE-Identity, establishmentCause,
    #     protocolErrorIndicator, measuredResultsOnRACH OPTIONAL,
    #     v3d0NonCriticalExtensions OPTIONAL }
    e.opt("measuredResultsOnRACH", 0,
          "RRCConnectionRequest: measuredResultsOnRACH MeasuredResultsOnRACH "
          "OPTIONAL (TS 25.331 10.2.39)")
    e.opt("v3d0NonCriticalExtensions", 0,
          "RRCConnectionRequest: v3d0NonCriticalExtensions SEQUENCE OPTIONAL "
          "(TS 25.331 10.2.39)")

    if a.imsi is not None:
        digits = _parse_digits(a.imsi, "--imsi", 6, 21)
        e.enum("initialUE-Identity", 0, 3, 8,
               "InitialUE-Identity ::= CHOICE {imsi, tmsi-and-LAI, p-TMSI-and-RAI, "
               "imei, esn-DS-41, imsi-DS-41, imsi-and-ESN-DS-41, tmsi-DS-41} "
               "(TS 25.331 10.3.3.15)",
               "imsi IMSI-GSM-MAP: the IMSI is sent bare, with no LAI")
        e.field("imsi.length", len(digits), 6, 21,
                "IMSI-GSM-MAP ::= SEQUENCE (SIZE (6..21)) OF Digit (TS 25.331 10.3.1.5)",
                "the length determinant carries the digit count")
        for i, d in enumerate(digits):
            e.field("imsi[%d]" % i, d, 0, 9,
                    "Digit ::= INTEGER (0..9) (TS 25.331 11.3)")
        ident = "imsi"
    else:
        tmsi, tmsi_hex = _parse_hex(a.tmsi, "--tmsi", 8)
        lac, lac_hex = _parse_hex(a.lac, "--lac", 4)
        if not (0 <= tmsi < (1 << 32)):
            _die(2, "--tmsi does not fit 32 bits",
                 "TMSI-GSM-MAP ::= BIT STRING (SIZE (32)) (TS 25.331 10.3.1.17)")
        if not (0 <= lac < (1 << 16)):
            _die(2, "--lac does not fit 16 bits",
                 "LAI ::= SEQUENCE {plmn-Identity PLMN-Identity, lac BIT STRING "
                 "(SIZE (16))} (TS 25.331 10.3.1.7)")
        e.enum("initialUE-Identity", 1, 3, 8,
               "InitialUE-Identity ::= CHOICE {imsi, tmsi-and-LAI, p-TMSI-and-RAI, "
               "imei, esn-DS-41, imsi-DS-41, imsi-and-ESN-DS-41, tmsi-DS-41} "
               "(TS 25.331 10.3.3.15)")
        e.raw("tmsi", _bits_int(tmsi, 32),
              "TMSI-and-LAI-GSM-MAP ::= SEQUENCE {tmsi TMSI-GSM-MAP, lai LAI}; "
              "TMSI-GSM-MAP ::= BIT STRING (SIZE (32)) (TS 25.331 10.3.1.17)",
              "0x%s; the tmsi comes before the lai, so its four octets lead" % tmsi_hex)
        for i, d in enumerate(mcc):
            e.field("mcc[%d]" % i, d, 0, 9,
                    "PLMN-Identity ::= SEQUENCE {mcc MCC, mnc MNC}; MCC ::= "
                    "SEQUENCE (SIZE (3)) OF Digit (TS 25.331 11.3)",
                    "MCC has no optional and no length determinant, three digits always")
        e.field("mnc.length", len(mnc), 2, 3,
                "MNC ::= SEQUENCE (SIZE (2..3)) OF Digit (TS 25.331 11.3)",
                "one bit: the digit count less the lower bound 2")
        for i, d in enumerate(mnc):
            e.field("mnc[%d]" % i, d, 0, 9,
                    "Digit ::= INTEGER (0..9) (TS 25.331 11.3)")
        e.raw("lac", _bits_int(lac, 16),
              "LAI ::= SEQUENCE {plmn-Identity PLMN-Identity, lac BIT STRING "
              "(SIZE (16))} (TS 25.331 10.3.1.7)",
              "0x%s; the lai follows the plmn-Identity" % lac_hex)
        ident = "tmsi-and-LAI"

    e.enum("establishmentCause", cause, 5, 32,
           "EstablishmentCause ::= ENUMERATED {...} (TS 25.331 10.3.3.11)",
           "32 values in v6.4.0, no extension marker")
    e.flag("protocolErrorIndicator", bool(a.error),
           "ProtocolErrorIndicator ::= ENUMERATED {noError, errorOccurred} "
           "(TS 25.331 10.3.3.27)")

    bits = e.bits()
    pad = _pad_bits(bits)
    rows = [
        ("cli", "request"),
        ("message_type", "rrcConnectionRequest"),
        ("channel", "ul-ccch"),
        ("gsmtap_sub_type", "3"),
        ("initial_ue_identity", ident),
        ("establishment_cause", "%d %s" % (cause, ESTABLISHMENT_CAUSES[cause])),
        ("protocol_error_indicator", "1 errorOccurred" if a.error else "0 noError"),
    ]
    rows.extend(("ref", r) for r in e.refs)
    rows.extend([
        ("bits", str(e.n)),
        ("pad", "%d zero bits to a whole octet (TS 25.331 12.1)" % pad),
        ("octets", str((e.n + 7) // 8)),
        ("hex", _bits_hex(bits)),
        ("bitstring", bits),
    ])
    _emit(rows)
    _limits("request")
    return 0


# ── PRACH preamble (TS 25.213 4.3.3, TS 25.211 5.2.2.1.2) ──────────────
def _gold_signs(n, count):
    """Z_n(i) for i = 0..count-1, TS 25.213 4.3.2.2 (degree 25 Gold sequence)."""
    if not (0 <= n < (1 << 25)):
        _die(2, "scrambling code number %d is outside 0..2^25-2" % n)
    x = [(n >> i) & 1 for i in range(25)]
    x[24] = 1                                  # x_n(24) = 1 by definition
    y = [1] * 25
    out = []
    for i in range(count + 25):
        if i >= 25:
            # x_n(i+25) = x_n(i+3) + x_n(i) mod 2 ; y(i+25) = y(i+3)+y(i+2)+y(i+1)+y(i)
            x.append(x[i - 25 + 3] ^ x[i - 25])
            y.append(y[i - 25 + 3] ^ y[i - 25 + 2] ^ y[i - 25 + 1] ^ y[i - 25])
        if i < count:
            out.append(1 if (x[i] ^ y[i]) == 0 else -1)
    return out


def _preamble_chips(signature, code_number, no_scrambling=False, no_signature=False):
    """C_pre,n,s(k) = S_r-pre,n(k) . C_sig,s(k) . exp(j(pi/4 + k pi/2)), TS 25.213 4.3.3.3."""
    signs = _gold_signs(code_number, PREAMBLE_CHIPS)
    pat = SIGNATURES[signature]
    chips = []
    for k in range(PREAMBLE_CHIPS):
        csig = 1 if no_signature else (1 if pat[k % SIGNATURE_CHIPS] == "1" else -1)
        spr = 1 if no_scrambling else signs[k]
        chips.append((csig * spr) * _PHASE[k % 4])
    return chips


def _quantise(samples, fmt):
    if fmt == "cf32":
        flat = []
        ext = flat.extend
        for v in samples:
            ext((v.real, v.imag))
        buf = array("f", flat)
        if sys.byteorder != "little":
            buf.byteswap()
        return buf.tobytes()
    if fmt == "ci16":
        vals = []
        ap = vals.append
        for v in samples:
            r = int(round(v.real * 32767.0))
            i = int(round(v.imag * 32767.0))
            ap(-32768 if r < -32768 else (32767 if r > 32767 else r))
            ap(-32768 if i < -32768 else (32767 if i > 32767 else i))
        buf = array("h", vals)
        if sys.byteorder != "little":
            buf.byteswap()
        return buf.tobytes()
    if fmt == "cu8":
        vals = array("B")
        for v in samples:
            r = int(round(v.real * 127.0 + 127.5))
            i = int(round(v.imag * 127.0 + 127.5))
            vals.append(0 if r < 0 else (255 if r > 255 else r))
            vals.append(0 if i < 0 else (255 if i > 255 else i))
        return vals.tobytes()
    _die(2, "unknown format %r" % fmt)


def _chip_sign_bits(samples):
    out = []
    for v in samples:
        out.append("1" if v.real < 0 else "0")
        out.append("1" if v.imag < 0 else "0")
    return "".join(out)


def _rate_chip_samples(rate):
    """samples per chip, or a sample rate in Hz that is a whole multiple of the chip rate."""
    if 1 <= rate <= 64:
        return rate
    if rate > 64 and rate % CHIP_RATE == 0:
        spc = rate // CHIP_RATE
        if spc > 64:
            _die(2, "--rate %d is %d samples per chip, the cap is 64" % (rate, spc),
                 "a preamble of 4096 chips at 64 samples per chip is already 262144 "
                 "samples; a higher rate is a recording, not a generator")
        return spc
    _die(2, "--rate must be 1..64 samples per chip or a whole multiple of %d Hz" % CHIP_RATE)


def cmd_prach(a):
    if not (0 <= a.signature < len(SIGNATURES)):
        _die(2, "--signature %d is outside 0..15" % a.signature,
             "TS 25.211 5.2.2.1.2: there are 16 signatures, 0..15")
    if not (0 <= a.slot < ACCESS_SLOTS):
        _die(2, "--slot %d is outside 0..14" % a.slot,
             "TS 25.211 5.2.2.1.1: 15 access slots, 0..14, per two frames")
    if not (0 <= a.psc < 512):
        _die(2, "--psc %d is outside 0..511" % a.psc,
             "TS 25.213 5.2.2: the codes are 512 sets of a primary scrambling code "
             "n = 16*i, i = 0..511, plus 15 secondaries")
    if not (0 <= a.code < 16):
        _die(2, "--code %d is outside 0..15" % a.code,
             "TS 25.213 4.3.3.2: n = 16*m + k with k = 0..15 the PRACH code index")
    code_number = 16 * a.psc + a.code
    if a.format not in ("cf32", "ci16", "cu8"):
        _die(2, "--format %r is not cf32, ci16 or cu8" % a.format)
    if a.out == "-":
        _die(2, "--out - is refused",
             "stdout carries the TSV summary of this file, the same convention as "
             "tools/umts_phy.py, so the samples go to a path or nowhere at all")
    spc = _rate_chip_samples(a.rate)

    chips = _preamble_chips(a.signature, code_number, a.no_scrambling, a.no_signature)
    ms = PREAMBLE_CHIPS * 1000.0 / CHIP_RATE
    if abs(ms - (4096.0 * 1000.0 / 3840000.0)) > 1e-12:
        raise AssertionError("preamble duration")

    if a.bare:
        window = list(chips)
        offset = 0
    else:
        offset = a.slot * ACCESS_SLOT_CHIPS
        if offset + PREAMBLE_CHIPS > ACCESS_WINDOW_CHIPS:
            _die(2, "the preamble does not fit the access slot window")
        window = [0j] * offset + list(chips)
        window.extend([0j] * (ACCESS_WINDOW_CHIPS - len(window)))

    samples = []
    for c in window:
        samples.extend([c] * spc)

    rows = [
        ("cli", "prach"),
        ("signature", str(a.signature)),
        ("sequence", "P%d" % a.signature),
        ("access_slot", "%d of 0..14" % a.slot),
        ("access_slot_offset_chips", str(offset)),
        ("code_number", str(code_number)),
        ("psc", str(a.psc)),
        ("preamble_code_index", str(a.code)),
        ("preamble_chips", str(PREAMBLE_CHIPS)),
        ("preamble_signature_reps", str(PREAMBLE_REPS)),
        ("preamble_ms", "%.16f" % ms),
        ("chip_rate", str(CHIP_RATE)),
        ("chip_samples", str(spc)),
        ("rate", str(spc * CHIP_RATE)),
        ("format", a.format),
        ("window_chips", str(len(window))),
        ("samples", str(len(samples))),
        ("bytes", str(len(samples) * {"cf32": 8, "ci16": 4, "cu8": 2}[a.format])),
        ("chips_head", _bits_hex(_chip_sign_bits(chips[:32]))),
        ("chips_sha256", hashlib.sha256(
            bytes.fromhex(_bits_hex(_chip_sign_bits(chips)))).hexdigest()),
    ]
    refs = [
        ("ref", "preamble = 4096 chips = 256 repetitions of the 16-chip signature "
                "P%d (TS 25.211 5.2.2.1.1/5.2.2.1.2)" % a.signature),
        ("ref", "S_r-pre,n(i) = c_long,1,n(i), i = 0..4095 (TS 25.213 4.3.3.2): the "
                "preamble scrambling code is the Gold sequence c_long,1 alone, not "
                "the complex C_long,n of TS 25.213 4.3.2.2 that dedicated channels "
                "and the PRACH message part (4.3.2.5) use"),
        ("ref", "n = 16*m + k = 16*%d + %d = %d (TS 25.213 4.3.3.2): m is the "
                "downlink primary scrambling code, k the PRACH code index"
                % (a.psc, a.code, code_number)),
        ("ref", "C_pre,n,s(k) = S_r-pre,n(k) . C_sig,s(k) . exp(j(pi/4 + k pi/2)), "
                "k = 0..4095 (TS 25.213 4.3.3.3)"),
        ("ref", "C_sig,s(i) = P_s(i mod 16) with P_s from Table 3 of TS 25.213 4.3.3.3"),
        ("ref", "preamble duration = 4096 / 3840000 s = %.16f ms at the 3.84 Mcps "
                "chip rate of TS 25.213 4.4.1" % ms),
        ("ref", "access slot %d starts at %d chips = %d * 5120 (TS 25.211 5.2.2.1.1: "
                "15 access slots per two frames, 5120 chips apart)"
                % (a.slot, offset, a.slot)),
    ]
    if a.bare:
        refs.append(("ref", "the file holds the 4096 preamble chips alone, one chip "
                            "per --rate samples"))
    else:
        refs.append(("ref", "the file holds the two frames of the access slot grid "
                            "(76800 chips = 15 * 5120) with the preamble at chip %d "
                            "of the window and zeros elsewhere; the zeros are not "
                            "transmitted, they mark where in the grid the preamble "
                            "sits" % offset))
    if a.no_scrambling:
        refs.append(("ref", "DIAGNOSTIC: S_r-pre was forced to +1, so these chips are "
                            "not a PRACH preamble"))
    if a.no_signature:
        refs.append(("ref", "DIAGNOSTIC: C_sig was forced to +1, so these chips are "
                            "not a PRACH preamble"))
    if a.out:
        data = _quantise(samples, a.format)
        try:
            with open(a.out, "wb") as fh:
                fh.write(data)
        except OSError as exc:
            _die(2, "cannot write %s" % a.out, "%s" % exc)
        rows.append(("path", os.path.abspath(a.out)))
    rows.extend(refs)
    _emit(rows)
    _limits("prach")
    return 0


# ── RACH message part slot structure (TS 25.211 5.2.2.1.3) ──────────────
def _hex_field(text, what):
    """A hex field: an optional 0x prefix and hex digits only, nothing else."""
    t = text.strip()
    if t.lower().startswith("0x"):
        t = t[2:]
    if not t or any(c not in "0123456789abcdefABCDEF" for c in t):
        _die(2, "%s %r is not hexadecimal" % (what, text),
             "a bit string is written as hex digits here, optionally 0x-prefixed, "
             "with no sign and no separators")
    return t


def cmd_message_part(a):
    if not (0 <= a.signature < len(SIGNATURES)):
        _die(2, "--signature %d is outside 0..15" % a.signature,
             "TS 25.213 4.3.1.3: the preamble signature s, 0..15, picks the "
             "sub-tree the message part spreads in")
    if a.sf is not None and a.k is not None:
        _die(2, "--sf and --k name the same thing",
             "TS 25.211 5.2.2.1.3 Table 6 fixes one from the other")
    if a.sf is not None:
        fmt = None
        for k, (sf, _nd) in SLOT_FORMATS.items():
            if sf == a.sf:
                fmt = k
        if fmt is None:
            _die(2, "--sf %d is not 256, 128, 64 or 32" % a.sf,
                 "TS 25.211 5.2.2.1.3 Table 6: the data part is 10*2^k bits, k = 0..3, "
                 "spread at SF 256, 128, 64 or 32")
    else:
        fmt = a.k
        if not (0 <= fmt <= 3):
            _die(2, "--k %d is outside 0..3" % fmt,
                 "TS 25.211 5.2.2.1.3: data part = 10*2^k bits with k = 0..3")
    sf, ndata = SLOT_FORMATS[fmt]
    data_bits = ndata * SLOTS_PER_FRAME
    data_text = a.data or ""
    data_pad = 0
    if data_text:
        data_text = _hex_field(a.data, "--data")
        iv = int(data_text, 16)
        given = len(data_text) * 4
        if given > data_bits:
            _die(2, "--data has %d bits, slot format %d carries %d data bits per "
                    "10 ms" % (given, fmt, data_bits),
                 "TS 25.211 5.2.2.1.3 Table 6: N_data bits per slot times 15 slots, "
                 "and a hex digit is four bits, so a longer string is not this field")
        # hex gives multiples of four bits and N_data is not always a multiple of
        # four (slot format 0 carries 150 data bits), so a short string is taken
        # as a value and padded with zero bits at the front.
        data_pad = data_bits - given
        data = _bits_int(iv, data_bits)
    else:
        data = "0" * data_bits

    tfci_iv = int(_hex_field(a.tfci or "0", "--tfci"), 16)
    if tfci_iv >= (1 << 30):
        _die(2, "--tfci needs 30 bits",
             "TS 25.211 5.2.2.1.3 Table 7: N_TFCI = 2 bits per slot, 15 slots = 30 "
             "TFCI bits per 10 ms message part")
    tfci = _bits_int(tfci_iv, 30)

    # TS 25.213 4.3.1.3: signature s picks channelisation-code node 16, and the
    # message part spreads in the sub-tree below it -- control at
    # cc = Cch,256,m with m = 16*s + 15, data at cd = Cch,SF,m with m = SF*s/16.
    cc_m = 16 * a.signature + 15
    cd_m = sf * a.signature // 16
    rows = [
        ("cli", "message-part"),
        ("signature", "%d of 0..15" % a.signature),
        ("cc_code", "Cch,256,%d" % cc_m),
        ("cc_code_number", str(cc_m)),
        ("cd_code", "Cch,%d,%d" % (sf, cd_m)),
        ("cd_code_number", str(cd_m)),
        ("slot_format", "%d of 0..3" % fmt),
        ("spreading_factor", str(sf)),
        ("ndata", "%d bits per slot" % ndata),
        ("ndata_frame", str(data_bits)),
        ("npilot", str(N_PILOT)),
        ("ntfci", str(N_TFCI)),
        ("control_bits_slot", str(N_PILOT + N_TFCI)),
        ("slots", str(SLOTS_PER_FRAME)),
        ("chips_slot", str(CHIPS_PER_SLOT)),
        ("chips_frame", str(CHIPS_PER_FRAME)),
        ("ms_frame", "%.1f" % (CHIPS_PER_FRAME * 1000.0 / CHIP_RATE)),
        ("tfci_bits", str(len(tfci))),
        ("tfci", tfci),
        ("data_bits", str(len(data))),
        ("data_pad", "%d zero bits at the front of the data part" % data_pad),
        ("data", _bits_hex(data)),
    ]
    rows.extend(("pilot[%d]" % s, PILOT_PATTERNS[s]) for s in range(SLOTS_PER_FRAME))
    rows.extend(("tfci_slot[%d]" % s, tfci[2 * s:2 * s + 2]) for s in range(SLOTS_PER_FRAME))
    # data_slot[i] rows are not printed: 15 rows of 10..80 bits are noise, and
    # `data` above already carries the same bits as one hex string.
    refs = [
        ("ref", "message part = 15 slots x 2560 chips = 38400 chips = 10 ms "
                "(TS 25.211 5.2.2.1.3)"),
        ("ref", "data part = 10 * 2^k bits, k = %d, spread at SF %d: %d bits per "
                "slot, %d per 10 ms (TS 25.211 5.2.2.1.3 Table 6)"
                % (fmt, sf, ndata, data_bits)),
        ("ref", "control part = %d pilot + %d TFCI bits per slot, spread at SF 256 "
                "(TS 25.211 5.2.2.1.3 Table 7)" % (N_PILOT, N_TFCI)),
        ("ref", "pilot bit patterns per slot (TS 25.211 5.2.2.1.3 Table 8, "
                "N_pilot = 8)"),
        ("ref", "TFCI: %d bits = %d per slot x %d slots, slot s carrying bits 2s and "
                "2s+1 (TS 25.211 5.2.2.1.3)" % (len(tfci), N_TFCI, SLOTS_PER_FRAME)),
        ("ref", "spreading: data on the I branch at cd = Cch,%d,%d and control on "
                "the Q branch at cc = Cch,256,%d (TS 25.213 4.3.1.3: m = SF*s/16 and "
                "m = 16*s+15 for signature s = %d; 4.2.2.2 for the I/Q split) -- the "
                "codes are named here, not applied"
                % (sf, cd_m, cc_m, a.signature)),
        ("ref", "binary to real: '0' -> +1, '1' -> -1 (TS 25.213 4.2.2.2)"),
    ]
    rows.extend(refs)
    _emit(rows)
    _limits("message-part")
    return 0


# ── verb list and the command line ─────────────────────────────────────
VERBS = (
    ("request",
     "--tmsi HEX | --imsi DIGITS [--mcc DDD] [--mnc DD] [--lac HEX] "
     "[--cause NAME|0..31] [--error]",
     "RRC CONNECTION REQUEST, UL-CCCH (TS 25.331 10.2.39)"),
    ("prach",
     "[--signature 0..15] [--slot 0..14] [--psc 0..511] [--code 0..15] "
     "[--rate N|Hz] [--format cf32|ci16|cu8] [--out PATH] [--bare] "
     "[--no-scrambling] [--no-signature]",
     "PRACH preamble chips, TS 25.213 4.3.3.3"),
    ("message-part",
     "[--sf 256|128|64|32 | --k 0..3] [--signature 0..15] [--tfci HEX30] "
     "[--data HEX]",
     "RACH message part slot structure as bits, TS 25.211 5.2.2.1.3"),
    ("list", "", "this table"),
)


def cmd_list(a):
    rows = [("cli", "list")]
    for name, flags, text in VERBS:
        rows.append(("verb", "%s\t%s\t%s" % (name, flags, text)))
    for name, flags, text in VERBS:
        rows.append(("ref", "%s -- %s" % (name, text)))
    _emit(rows)
    # list is the whole table, so it carries every limit this file owes
    for k, text in LIMITS:
        _emit([("limit", "%s: %s" % (k, text))])
    return 0


def main(argv):
    ap = argparse.ArgumentParser(
        prog="umts_uplink.py",
        description="Uplink side of a UMTS catcher: RRC CONNECTION REQUEST and the "
                    "PRACH preamble.  Tab separated rows; see --help of each verb.")
    sub = ap.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("request", help="RRC CONNECTION REQUEST (UL-CCCH)")
    p.add_argument("--tmsi", default=None, help="TMSI, hex (default 12345678)")
    p.add_argument("--imsi", default=None, help="IMSI digits, 6..21 of them")
    p.add_argument("--mcc", default="001", help="MCC, three digits (default 001)")
    p.add_argument("--mnc", default="01", help="MNC, two or three digits (default 01)")
    p.add_argument("--lac", default="1", help="LAC, hex (default 1)")
    p.add_argument("--cause", default="registration",
                   help="EstablishmentCause name or index (default registration)")
    p.add_argument("--error", action="store_true",
                   help="protocolErrorIndicator = errorOccurred")
    p.add_argument("--measured", action="store_true",
                   help="refused: measuredResultsOnRACH is not encoded")
    p.add_argument("--v3d0", action="store_true",
                   help="refused: v3d0NonCriticalExtensions is not encoded")
    p.set_defaults(fn=cmd_request)

    p = sub.add_parser("prach", help="PRACH preamble chips and samples")
    p.add_argument("--signature", type=int, default=0,
                   help="signature s, 0..15 (TS 25.211 5.2.2.1.2)")
    p.add_argument("--slot", type=int, default=0,
                   help="access slot 0..14, 5120 chips apart (TS 25.211 5.2.2.1.1)")
    p.add_argument("--psc", type=int, default=0, help="downlink PSC m, 0..511")
    p.add_argument("--code", type=int, default=0, help="PRACH code index k, 0..15")
    p.add_argument("--rate", type=int, default=1,
                   help="samples per chip 1..64, or a sample rate in Hz")
    p.add_argument("--format", default="cf32")
    p.add_argument("--out", default=None)
    p.add_argument("--bare", action="store_true",
                   help="write the 4096 preamble chips without the access slot window")
    p.add_argument("--no-scrambling", action="store_true",
                   help="DIAGNOSTIC: force the scrambling sequence to +1")
    p.add_argument("--no-signature", action="store_true",
                   help="DIAGNOSTIC: force the signature code to +1")
    p.set_defaults(fn=cmd_prach)

    p = sub.add_parser("message-part", help="RACH message part slot structure (bits)")
    p.add_argument("--sf", type=int, default=None)
    p.add_argument("--k", type=int, default=None)
    p.add_argument("--signature", type=int, default=0,
                   help="preamble signature 0..15 (TS 25.213 4.3.1.3)")
    p.add_argument("--tfci", default=None, help="30 TFCI bits, hex")
    p.add_argument("--data", default=None, help="15*N_data data bits, hex")
    p.set_defaults(fn=cmd_message_part)

    p = sub.add_parser("list", help="the verbs and their flags")
    p.set_defaults(fn=cmd_list)

    a = ap.parse_args(argv)
    if getattr(a, "verb", None) == "message-part" and a.sf is None and a.k is None:
        a.k = 0
    return a.fn(a) or 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(0)
