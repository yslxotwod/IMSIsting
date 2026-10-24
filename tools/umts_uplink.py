#!/usr/bin/env python3
"""tools/umts_uplink.py -- the uplink side of a UMTS catcher.

Everything modules/08_umts_air.sh builds is what the *network* sends: DL-CCCH,
PCCH, the downlink RRC messages and the downlink physical channels in
tools/umts_phy.py.  This file is the other direction -- what a *handset* sends:

    request       RRC CONNECTION REQUEST, UL-CCCH, TS 25.331 clause 10.2.39
    prach         the PRACH preamble, TS 25.213 4.3.3.2/4.3.3.3 + TS 25.211 5.2.2.1.2
    message-part  the DPCCH/DPDCH slot structure of the RACH message part,
                  TS 25.211 5.2.2.1.3, spread with the signature's codes,
                  weighted by beta_c/beta_d and scrambled (TS 25.213 4.2.2.2,
                  4.3.1.3, 4.3.2.5) -- as chips and, with --out, as samples
    burst         the whole random-access transmission: N preambles, a gap, and
                  the message part, TS 25.211 5.2.2.1.1 figure 4
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
        "message-part-gain-quantisation",
        "the gain factors are the 4-bit signalled words of TS 25.331 "
        "GainFactor ::= INTEGER (0..15), mapped here to word/15 with 15 -> 1.0.  "
        "The word-to-amplitude table itself is TS 25.214 5.1.2.2, which this tree "
        "does not carry; the ratio between beta_c and beta_d is what the samples "
        "preserve either way, and a caller who needs the exact amplitudes from "
        "that table has to supply them.",
    ),
    (
        "message-part-gap",
        "burst puts the message part straight after the last preamble, which is "
        "what TS 25.211 5.2.2.1.1 figure 4 draws.  The gap a real network uses is "
        "signalled by higher layers and is an input here (--gap-chips), not "
        "derived.",
    ),
    (
        "message-part-tfci-coding",
        "message-part takes the 30 TFCI bits as an input codeword and does not "
        "encode one: TS 25.212 4.3.3 (coding of the TFCI) is what turns a 10-bit "
        "TFC index into the 32-bit Reed-Muller word and 4.3.5.1 punctures it to "
        "the 30 bits a slot carries, and that encoder is the `tfci` verb of this "
        "same file -- so the honest statement here is that message-part does not "
        "call it, not that it does not exist.",
    ),
    (
        "message-part-transport-chain",
        "message-part takes the data bits as an input bit string and does not run "
        "the RACH transport channel: TS 25.212 4.2 in uplink order (CRC, channel "
        "coding, radio frame size equalisation, 1st interleaving, radio frame "
        "segmentation, per-frame rate matching, 2nd interleaving) is the `chain` "
        "verb, and message-part is where its output lands.",
    ),
    (
        "message-part-samples",
        "message-part without --out writes no samples file: the bit structure is "
        "the whole of what that call asks for.  With --out it writes the spread, "
        "weighted and scrambled chips of one or two 10 ms frames, normalised by a "
        "single linear factor that the beta ratio does not change.",
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
    (
        "chain-turbo-coding",
        "the `chain` verb codes with the convolutional code of TS 25.212 4.2.3.1 "
        "(rate 1/2 or 1/3) or not at all.  Turbo coding (4.2.3.2, rate 1/3 with "
        "the 1st and 2nd parity streams and the Trellis termination of 4.2.3.2.2) "
        "is not built, so a transport format that names it is not this verb's to "
        "produce.",
    ),
    (
        "chain-code-block-segmentation",
        "no code block segmentation (TS 25.212 4.2.2) is applied: the block goes in "
        "whole.  A convolutional code's maximum block size is 504 bits, so a "
        "transport block longer than that is a format this verb prints without "
        "splitting rather than one it refuses, and the row says so.",
    ),
    (
        "chain-compressed-mode",
        "compressed mode (TS 25.212 4.4) is not built: there is no transmission gap, "
        "no N_first/TGL, no p-bits inserted before the 1st interleaver (4.2.5.1) "
        "and no compressed N_data,cm in the rate matching parameters.  Every frame "
        "this verb produces is a normal frame.",
    ),
    (
        "chain-no-transmission",
        "`chain` produces the frame bits a message part would carry, not chips and "
        "not a transmission: feed `data_hex` to message-part (or burst) for the "
        "spreading, and see no-uplink-transmission for what is missing above that.",
    ),
    (
        "tfci-hard-split",
        "`tfci` encodes a single 10-bit TFC index in normal mode (TS 25.212 4.3.3 "
        "+ 4.3.5.1).  Hard split mode (4.3.4, where the code word is split between "
        "a DCH and a DSCH CCTrCH through the pi1/pi2 permutations of 4.3.4) is a "
        "DSCH feature and is not built.",
    ),
)

# The limit rows a given verb still owes (the rest are general).
VERB_LIMITS = {
    "request": ("no-uplink-transmission", "request-optional-ies",
                "request-identity-choices", "ciphering-and-integrity",
                "pycrate-referee"),
    "prach": ("no-uplink-transmission", "prach-no-pulse-shaping",
              "prach-decomposition-switches", "pycrate-referee"),
    "message-part": ("message-part-gain-quantisation", "message-part-tfci-coding",
                     "message-part-transport-chain", "message-part-samples",
                     "pycrate-referee"),
    "burst": ("no-uplink-transmission", "message-part-gain-quantisation",
              "message-part-gap", "message-part-tfci-coding",
              "message-part-transport-chain"),
    "chain": ("chain-turbo-coding", "chain-code-block-segmentation",
              "chain-compressed-mode", "chain-no-transmission"),
    "tfci": ("tfci-hard-split",),
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


def _fit_hex_bits(text, width, what, lead_note=""):
    """A hex string whose value must fit `width` bits.

    Hex is a whole number of nibbles, so a bit field whose width is not a
    multiple of four arrives as "%04d" style padding: TS 25.331 12.1 zero-pads
    the last octet.  The padding is therefore allowed and trimmed here, but
    only if those trailing bits really are zero -- a hex string that carries
    information past the field width is still refused.
    """
    given = len(text) * 4
    iv = int(text, 16)
    trimmed = 0
    if given > width:
        extra = given - width
        if iv & ((1 << extra) - 1):
            _die(2, "%s has %d bits, the field holds %d%s"
                 % (what, given, width, lead_note),
                 "the bits past the field are not zero, so this is not "
                 "TS 25.331 12.1 octet padding")
        iv >>= extra
        trimmed = extra
    return _bits_int(iv, width), width - given if given < width else 0, trimmed


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
# The x and y m-sequences of TS 25.213 4.3.2.2 are linear recurrences of degree
# 25, so the state 25 chips ahead is a fixed GF(2) matrix applied 25 times.  A
# message part needs Z_n at index 16777232 + 2*q, about 16.8 million -- running
# the shift register forward would be 16.8 million Python steps per call, so the
# matrix is raised to the needed power instead and the run starts there.  The
# sequence is identical either way; tools/check-umts-uplink.sh checks the jump
# against a plain forward run over a window it can afford.
_GF2_MASK = (1 << 25) - 1


def _gf2_companion(taps):
    """The 25x25 companion matrix of a recurrence, rows as bit masks."""
    rows = [1 << (j + 1) for j in range(24)]
    rows.append(sum(1 << t for t in taps))
    return rows


def _gf2_parity(x):
    return bin(x).count("1") & 1


def _gf2_matvec(m, v):
    """m is 25 rows as bit masks over the input vector; the product is a vector
    whose bit j is the parity of row j restricted to the set bits of v."""
    return sum(_gf2_parity(m[j] & v) << j for j in range(25))


def _gf2_matmul(a, b):
    """Row j of a*b is the XOR of the rows of b that row j of a selects."""
    out = []
    for row in a:
        acc = 0
        i = 0
        r = row
        while r:
            if r & 1:
                acc ^= b[i]
            r >>= 1
            i += 1
        out.append(acc)
    return out


def _advance(state, steps, taps):
    """Run a 25-tap linear recurrence `steps` chips forward in O(log steps)."""
    m = _gf2_companion(taps)
    while steps:
        if steps & 1:
            state = _gf2_matvec(m, state)
        steps >>= 1
        if steps:
            m = _gf2_matmul(m, m)
    return state


_X_TAPS = (0, 3)          # x_n(i+25) = x_n(i+3) + x_n(i)     modulo 2
_Y_TAPS = (0, 1, 2, 3)    # y(i+25)   = y(i+3)+y(i+2)+y(i+1)+y(i) modulo 2


def _gold_signs_at(n, start, count):
    """Z_n(i) for i = start .. start+count-1, TS 25.213 4.3.2.2."""
    if not (0 <= n < (1 << 25)):
        _die(2, "scrambling code number %d is outside 0..2^25-2" % n)
    if start < 0:
        _die(2, "the Gold sequence index %d is negative" % start)
    xs = (n & 0xFFFFFF) | (1 << 24)      # x_n(0..23) = bits of n, x_n(24) = 1
    ys = _GF2_MASK                       # y(0..24) = 1
    if start:
        xs = _advance(xs, start, _X_TAPS)
        ys = _advance(ys, start, _Y_TAPS)
    out = []
    ap = out.append
    for _ in range(count):
        ap(1 if ((xs & 1) ^ (ys & 1)) == 0 else -1)
        xb = ((xs >> 3) ^ xs) & 1
        xs = (xs >> 1) | (xb << 24)
        yb = ((ys >> 3) ^ (ys >> 2) ^ (ys >> 1) ^ ys) & 1
        ys = (ys >> 1) | (yb << 24)
    return out


def _gold_signs(n, count):
    """Z_n(i) for i = 0..count-1, TS 25.213 4.3.2.2 (degree 25 Gold sequence)."""
    return _gold_signs_at(n, 0, count)


# ── channelisation codes and the message-part scrambling ─────────────────
_OVSF_CACHE = {}


def _ovsf(sf, k):
    """Cch,sf,k, TS 25.213 4.3.1.1: Cch,sf,k = Cch,sf/2,floor(k/2) followed by
    itself (k even) or by its negation (k odd)."""
    if not (0 <= k < sf):
        _die(2, "channelisation code Cch,%d,%d is outside the code tree" % (sf, k))
    key = (sf, k)
    if key in _OVSF_CACHE:
        return _OVSF_CACHE[key]
    if sf == 1:
        out = (1,)
    else:
        parent = _ovsf(sf // 2, k // 2)
        out = parent + parent if k % 2 == 0 else parent + tuple(-v for v in parent)
    _OVSF_CACHE[key] = out
    return out


_C_LONG_PERIOD = (1 << 25) - 1
_C_LONG_SHIFT = 16777232       # 4.3.2.2: c_long,2,n(i) = Z_n(i + 16777232)


def _long_scrambling(n, start, count):
    """C_long,n(i) for i = start .. start+count-1, TS 25.213 4.3.2.2:

        C_long,n(i) = c_long,1,n(i) * (1 + j*(-1)**i * c_long,2,n(2*floor(i/2)))

    with c_long,1,n(i) = Z_n(i) and c_long,2,n(i) = Z_n(i + 16777232 mod 2^25-1).
    The two indices are jumped to in one pass each: the first is `start`, the
    second is 2*floor(i/2) + 16777232, which moves one step per two chips.
    """
    c1 = _gold_signs_at(n, start, count)
    q0 = start // 2
    nq = (start + count - 1) // 2 - q0 + 1
    m0 = (2 * q0 + _C_LONG_SHIFT) % _C_LONG_PERIOD
    # the c_long,2 index is 2*floor(i/2) + 16777232, so it steps by TWO per q:
    # both chips of a pair share one value, and the next pair is two indices on.
    c2 = _gold_signs_at(n, m0, 2 * nq)[0::2]
    out = []
    ap = out.append
    for t in range(count):
        i = start + t
        alt = 1 if (i & 1) == 0 else -1
        # c2 advances every two chips: chip i uses index q = floor(i/2) - q0
        ap(complex(c1[t], alt * c2[(i // 2) - q0]))
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


# ── the message part as chips (TS 25.213 4.2.2.2, 4.3.1.3, 4.3.2.5) ────
DATA_CODE_MIN_SF = 32
DATA_CODE_MAX_SF = 256
CONTROL_SF = 256


def _spread(bits, code):
    """Binary to real (+1 for '0', -1 for '1') then channelise: one symbol per
    SF chips, TS 25.213 4.2.2.2."""
    out = []
    for b in bits:
        sign = 1 if b == "0" else -1
        out.extend(sign * c for c in code)
    return out


def _gain_from_word(word, name):
    """A 4-bit signalled gain factor to an amplitude.

    TS 25.331 10.3.6.xx GainFactor ::= INTEGER (0..15) is the signalled word;
    TS 25.213 4.2.2.2 quantises the two amplitudes into 4-bit words and requires
    "at least one of the values beta_c and beta_d has the amplitude 1.0".  The
    word-to-amplitude table itself lives in TS 25.214 5.1.2.2, which this tree
    does not carry, so the mapping used here is word/15 with 15 -> 1.0 and the
    limit row says so.
    """
    if not (0 <= word <= 15):
        _die(2, "%s %d is outside the 4-bit signalled range 0..15" % (name, word),
             "TS 25.331 GainFactor ::= INTEGER (0..15)")
    return 1.0 if word == 15 else word / 15.0


def _message_part_chips(signature, fmt, data, tfci, beta_c, beta_d,
                        scramble=True, code_number=0, frames=1):
    """The 38400*chips_per_frame chips of a RACH message part.

    Data part on the I branch spread by cd = Cch,SF,SF*s/16, control part on the
    Q branch spread by cc = Cch,256,16*s+15, weighted by beta_d and beta_c, then
    scrambled by S_r-msg,n(i) = C_long,n(i + 4096) aligned to each 10 ms frame.
    """
    sf, ndata = SLOT_FORMATS[fmt]
    cd = _ovsf(sf, sf * signature // 16)
    cc = _ovsf(CONTROL_SF, 16 * signature + 15)
    chips = []
    for frame in range(frames):
        frame_chips = []
        for slot in range(SLOTS_PER_FRAME):
            # one data field per slot across the whole message part: a 20 ms
            # part carries 2 x 15 x N_data distinct data bits, so the frame is
            # part of the index and not a repeat of the first frame
            k = (frame * SLOTS_PER_FRAME + slot) * ndata
            dbits = data[k:k + ndata]
            cbits = PILOT_PATTERNS[slot] + tfci[2 * slot:2 * slot + 2]
            dsp = _spread(dbits, cd)
            csp = _spread(cbits, cc)
            if len(dsp) != CHIPS_PER_SLOT or len(csp) != CHIPS_PER_SLOT:
                raise AssertionError("slot does not fill 2560 chips")
            frame_chips.extend(complex(beta_d * dsp[c], beta_c * csp[c])
                               for c in range(CHIPS_PER_SLOT))
        if scramble:
            # 4.3.2.5: the code is 10 ms long and restarts at each message part
            # radio frame, offset by 4096 chips into the long sequence.
            scr = _long_scrambling(code_number, _MSG_SCRAMBLE_OFFSET,
                                   CHIPS_PER_FRAME)
            frame_chips = [frame_chips[i] * scr[i] for i in range(CHIPS_PER_FRAME)]
        chips.extend(frame_chips)
    return chips


_MSG_SCRAMBLE_OFFSET = 4096      # 4.3.2.5: S_r-msg,n(i) = C_long,n(i + 4096)


def cmd_burst(a):
    """Preamble repetitions and the message part joined into one transmission.

    TS 25.211 5.2.2.1.1: "The random-access transmission consists of one or
    several preambles of length 4096 chips and a message of length 10 ms or
    20 ms", and 5.2.2.1.2/5.2.2.1.3 give the two parts.  Figure 4 draws them
    adjacent.  The gap a real cell uses between the last preamble and the
    message part is not fixed by that figure, so it is an input here.
    """
    if a.out is None:
        _die(2, "burst needs --out",
             "the verb joins two chip-level parts and writes them; the bit "
             "structure of the preamble is what prach prints and of the message "
             "part what message-part prints")
    if not (1 <= a.preambles <= 64):
        _die(2, "--preambles %d is outside 1..64" % a.preambles,
             "a random-access attempt is one or several preambles; more than 64 "
             "is a retry loop, not one transmission")
    if a.gap_chips < 0:
        _die(2, "--gap-chips %d is negative" % a.gap_chips,
             "the gap between the last preamble and the message part is silence")
    if a.gap_chips % CHIPS_PER_SLOT:
        _die(2, "--gap-chips %d is not a whole number of slots" % a.gap_chips,
             "TS 25.211 5.2.2.1.1: the transmission starts on access-slot "
             "boundaries, which are 5120 chips apart, so a gap the network "
             "signals is a slot multiple")
    if not (0 <= a.signature < len(SIGNATURES)):
        _die(2, "--signature %d is outside 0..15" % a.signature)
    if not (0 <= a.psc < 512):
        _die(2, "--psc %d is outside 0..511" % a.psc)
    if not (0 <= a.code < 16):
        _die(2, "--code %d is outside 0..15" % a.code)
    if a.frames not in (1, 2):
        _die(2, "--frames %d is not a message part length" % a.frames)
    if a.format not in ("cf32", "ci16", "cu8"):
        _die(2, "--format %r is not cf32, ci16 or cu8" % a.format)
    if a.out == "-":
        _die(2, "--out - is refused", "stdout carries the TSV summary")
    beta_c = _gain_from_word(a.beta_c, "--beta-c")
    beta_d = _gain_from_word(a.beta_d, "--beta-d")
    if a.beta_c != 15 and a.beta_d != 15:
        _die(2, "--beta-c %d and --beta-d %d both leave amplitude 1.0"
             % (a.beta_c, a.beta_d),
             "TS 25.213 4.2.2.2: one of the two gain factors is 1.0")
    code_number = 16 * a.psc + a.code
    spc = _rate_chip_samples(a.rate)

    pre = _preamble_chips(a.signature, code_number, a.no_scrambling, False)
    if a.frames == 1:
        fmt = 3 if a.sf is None else None
        if fmt is None:
            for k, (sf, _n) in SLOT_FORMATS.items():
                if sf == a.sf:
                    fmt = k
            if fmt is None:
                _die(2, "--sf %d is not 256, 128, 64 or 32" % a.sf)
    else:
        if a.sf is None:
            _die(2, "--frames 2 needs --sf",
                 "a 20 ms message part carries 2 x 15 x N_data data bits, so the "
                 "slot format has to be named rather than defaulted")
        fmt = None
        for k, (sf, _n) in SLOT_FORMATS.items():
            if sf == a.sf:
                fmt = k
        if fmt is None:
            _die(2, "--sf %d is not 256, 128, 64 or 32" % a.sf)
    sf, ndata = SLOT_FORMATS[fmt]
    data_bits = ndata * SLOTS_PER_FRAME * a.frames
    data_text = _hex_field(a.data, "--data") if a.data else ""
    if data_text:
        data, _dp, _dt = _fit_hex_bits(
            data_text, data_bits, "--data",
            " over %d frame(s) of slot format %d" % (a.frames, fmt))
    else:
        data = "0" * data_bits
    tfci = _bits_int(int(_hex_field(a.tfci or "0", "--tfci"), 16), 30)

    msg = _message_part_chips(a.signature, fmt, data, tfci, beta_c, beta_d,
                              scramble=not a.no_scrambling,
                              code_number=code_number, frames=a.frames)
    parts = []
    for _ in range(a.preambles):
        parts.extend(pre)
    pre_chips = a.preambles * PREAMBLE_CHIPS
    parts.extend([0j] * a.gap_chips)
    parts.extend(msg)
    peak = max(max(abs(v.real), abs(v.imag)) for v in parts)
    scale = 1.0 / peak if peak > 0 else 1.0
    samples = []
    for v in parts:
        z = v * scale
        samples.extend([z] * spc)
    with open(a.out, "wb") as fh:
        fh.write(_quantise(samples, a.format))
    rows = [
        ("cli", "burst"),
        ("signature", "%d of 0..15 (TS 25.213 4.3.3.3)" % a.signature),
        ("preamble_code", "%d (n = 16*%d + %d)"
         % (code_number, a.psc, a.code)),
        ("preambles", str(a.preambles)),
        ("preamble_chips", str(pre_chips)),
        ("gap_chips", str(a.gap_chips)),
        ("message_chips", str(len(msg))),
        ("message_frames", str(a.frames)),
        ("slot_format", "%d of 0..3, SF %d" % (fmt, sf)),
        ("beta_c", "%d -> %.6f" % (a.beta_c, beta_c)),
        ("beta_d", "%d -> %.6f" % (a.beta_d, beta_d)),
        ("chips", str(len(parts))),
        ("ms", "%.1f" % (len(parts) * 1000.0 / CHIP_RATE)),
        ("samples_per_chip", str(spc)),
        ("samples", str(len(samples))),
        ("bytes", str(len(samples) * {"cf32": 8, "ci16": 4, "cu8": 2}[a.format])),
        ("format", a.format),
        ("out", a.out),
        ("peak_chip", "%.6f" % peak),
        ("scale", "%.6f -- one linear factor over the whole burst" % scale),
        ("scrambling_code", "%d (n = 16*%d + %d, TS 25.213 4.3.3.2)"
         % (code_number, a.psc, a.code)),
        ("scrambling_start", "%d chips into C_long,n, reset at each 10 ms "
         "message part frame (TS 25.213 4.3.2.5)" % _MSG_SCRAMBLE_OFFSET),
        ("scrambling", "off -- the message part is unscrambled" if a.no_scrambling
         else "S_r-msg,n(i) = C_long,n(i + %d) on the message part"
              % _MSG_SCRAMBLE_OFFSET),
        ("part[0]", "preamble x %d: chips 0..%d" % (a.preambles, pre_chips - 1)),
        ("part[1]", "gap: chips %d..%d" % (pre_chips, pre_chips + a.gap_chips - 1)
         if a.gap_chips else "gap: none"),
        ("part[2]", "message part: chips %d..%d"
         % (pre_chips + a.gap_chips, len(parts) - 1)),
        ("ref", "TS 25.211 5.2.2.1.1: one or several preambles of 4096 chips and "
                "a message of 10 or 20 ms"),
        ("ref", "TS 25.211 5.2.2.1.3: the message part is 15 slots of 2560 chips "
                "per 10 ms frame, data on I at SF %d, control on Q at SF 256"
                % sf),
        ("ref", "TS 25.213 4.3.2.5: the message part is scrambled by "
                "S_r-msg,n(i) = C_long,n(i + 4096), restarting at each 10 ms "
                "message part frame"),
        ("ref", "TS 25.213 4.3.3.1: the preamble is C_pre,n,s(k) = "
                "S_r-pre,n(k) x C_sig,s(k) x exp(j(pi/4 + k pi/2))"),
    ]
    _emit(rows)
    _limits("burst")
    return 0


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
    data_bits = ndata * SLOTS_PER_FRAME * a.frames
    data_text = a.data or ""
    data_pad = 0
    data_trim = 0
    if data_text:
        data_text = _hex_field(a.data, "--data")
        iv = int(data_text, 16)
        # hex gives multiples of four bits and N_data is not always a multiple of
        # four (slot format 0 carries 150 data bits), so the string arrives
        # either short by up to three bits -- padded at the front -- or long by
        # the octet padding TS 25.331 12.1 adds, which _fit_hex_bits trims.
        data, data_pad, data_trim = _fit_hex_bits(
            data_text, data_bits, "--data",
            " per 10 ms of slot format %d" % fmt)
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
        ("data_tail_pad", "%d zero bits trimmed from the last octet (TS 25.331 "
                          "12.1 octet padding)" % data_trim),
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

    # The chips, when a file was asked for.  Without --out the verb stays what
    # it was: the bit structure and the codes, no samples.
    if a.out:
        if a.format not in ("cf32", "ci16", "cu8"):
            _die(2, "--format %r is not cf32, ci16 or cu8" % a.format)
        if a.out == "-":
            _die(2, "--out - is refused",
                 "stdout carries the TSV summary, so the samples go to a path")
        if a.frames not in (1, 2):
            _die(2, "--frames %d is not a message part length" % a.frames,
                 "TS 25.211 5.2.2.1.3: a message part is 10 ms (one radio frame) "
                 "or 20 ms (two), the TTI of the RACH transport channel")
        beta_c = _gain_from_word(a.beta_c, "--beta-c")
        beta_d = _gain_from_word(a.beta_d, "--beta-d")
        if a.beta_c != 15 and a.beta_d != 15:
            _die(2, "--beta-c %d and --beta-d %d both leave amplitude 1.0"
                 % (a.beta_c, a.beta_d),
                 "TS 25.213 4.2.2.2: at least one of beta_c and beta_d has the "
                 "amplitude 1.0 at every instant, so one of the two words is 15")
        if not (0 <= a.psc < 512):
            _die(2, "--psc %d is outside 0..511" % a.psc,
                 "TS 25.213 4.3.3.2: 512 groups of 16 PRACH codes")
        if not (0 <= a.code < 16):
            _die(2, "--code %d is outside 0..15" % a.code,
                 "TS 25.213 4.3.3.2: n = 16*m + k, k = 0..15")
        code_number = 16 * a.psc + a.code
        spc = _rate_chip_samples(a.rate)
        chips = _message_part_chips(a.signature, fmt, data, tfci, beta_c, beta_d,
                                    scramble=not a.no_scrambling,
                                    code_number=code_number, frames=a.frames)
        peak = max(max(abs(v.real), abs(v.imag)) for v in chips)
        scale = 1.0 / peak if peak > 0 else 1.0
        samples = []
        for v in chips:
            z = v * scale
            samples.extend([z] * spc)
        with open(a.out, "wb") as fh:
            fh.write(_quantise(samples, a.format))
        rows.extend([
            ("chips", str(len(chips))),
            ("frames", str(a.frames)),
            ("ms", "%.1f" % (len(chips) * 1000.0 / CHIP_RATE)),
            ("samples_per_chip", str(spc)),
            ("samples", str(len(samples))),
            ("bytes", str(len(samples) * {"cf32": 8, "ci16": 4, "cu8": 2}[a.format])),
            ("format", a.format),
            ("out", a.out),
            ("beta_c", "%d -> %.6f (TS 25.213 4.2.2.2: control part, Q branch)"
             % (a.beta_c, beta_c)),
            ("beta_d", "%d -> %.6f (data part, I branch)" % (a.beta_d, beta_d)),
            ("peak_chip", "%.6f -- largest of |I| and |Q| before normalisation"
             % peak),
            ("scale", "%.6f -- one linear factor, the beta ratio is untouched"
             % scale),
            ("scrambling_code", "%d (n = 16*%d + %d, TS 25.213 4.3.3.2)"
             % (code_number, a.psc, a.code)),
            ("scrambling_start", "%d chips into C_long,n, reset at each 10 ms "
             "message part frame (TS 25.213 4.3.2.5)" % _MSG_SCRAMBLE_OFFSET),
            ("scrambling", "off -- the chips are unscrambled" if a.no_scrambling
             else "S_r-msg,n(i) = C_long,n(i + %d), applied as a complex multiply"
                  % _MSG_SCRAMBLE_OFFSET),
        ])

    _emit(rows)
    _limits("message-part")
    return 0


# ── the RACH transport channel, TS 25.212 4.2 ──────────────────────────
# The uplink chain is NOT the downlink chain with different constants.  In the
# uplink the order is CRC, channel coding, radio frame size equalisation
# (4.2.4 -- "only performed in the UL"), 1st interleaving, radio frame
# segmentation, and only THEN rate matching, which therefore runs per radio
# frame on one segment instead of once over the whole TTI.  That is why
# tools/umts_sib.py's FACH chain cannot be called from here, and why this file
# carries its own copy of the pieces both directions share.
CRC_EXPONENTS = {
    24: (24, 23, 6, 5, 0),                 # gCRC24(D) = D24+D23+D6+D5+D+1
    16: (16, 12, 5, 0),                    # gCRC16(D) = D16+D12+D5+1
    12: (12, 11, 3, 2, 1, 0),              # gCRC12(D) = D12+D11+D3+D2+D+1
    8: (8, 7, 4, 3, 1, 0),                 # gCRC8(D)  = D8+D7+D4+D3+D+1
}
CONV_POLY_UP = {2: (0o561, 0o753),         # rate 1/2: G0, G1
                3: (0o557, 0o663, 0o711)}  # rate 1/3: G0, G1, G2
CONV_K = 9                                 # constraint length, 4.2.3.1
UP_TAIL = 8                                # tail bits, 4.2.3.1
C2_UP = 30                                 # 2nd interleaver columns, 4.2.11
# Table 7 of TS 25.212 4.2.11, C2 = 30, verbatim
P2_UP = (0, 20, 10, 5, 15, 25, 3, 13, 23, 8, 18, 28, 1, 11, 21, 6, 16, 26, 4,
         14, 24, 19, 9, 29, 12, 2, 7, 22, 27, 17)
# Table 4 of TS 25.212 4.2.5.2, the inter-column permutation of the 1st
# interleaver, which is the bit reversal of the column index on log2(C1) bits
P1_UP = {1: (0,), 2: (0, 1), 4: (0, 2, 1, 3), 8: (0, 4, 2, 6, 1, 5, 3, 7)}
# Table 8 of TS 25.212 4.3.3: the (32,10) sub-code basis, row i is Mi,0..Mi,9
TFCI_BASIS = (
    "1000010000", "0100011000", "1100010001", "0010011011", "1010010001",
    "0110010010", "1110010100", "0001010110", "1001011110", "0101011011",
    "1101010011", "0011010110", "1011010101", "0111011001", "1111011111",
    "1000111100", "0100111101", "1100111010", "0010110111", "1010110101",
    "0110110011", "1110110111", "0001110100", "1001111101", "0101111010",
    "1101111001", "0011110010", "1011111100", "0111111110", "1111111111",
    "0000010000", "0000111000",
)


def crc_poly(size):
    """The generator polynomial as a bit mask, from its exponents."""
    p = 0
    for e in CRC_EXPONENTS[size]:
        p |= 1 << e
    return p


def crc_parity(bits, size):
    """TS 25.212 4.2.1: the remainder of the block times D**size, mod gCRC."""
    poly = crc_poly(size)
    acc = 0
    for b in list(bits) + [0] * size:
        acc = (acc << 1) | b
        if acc & (1 << size):
            acc ^= poly
    return acc


def crc_attach(bits, size):
    """TS 25.212 4.2.1.2: p_im(Li+1-(k-Ai)), i.e. the parity appended in the
    order p_L, p_(L-1), ..., p_1 -- the reverse of the division remainder."""
    if size == 0:
        return list(bits)
    p = crc_parity(bits, size)
    return list(bits) + [(p >> k) & 1 for k in range(size - 1, -1, -1)]


def _parity_of(reg, poly):
    return bin(reg & poly).count("1") & 1


def conv_encode_up(bits, rate):
    """TS 25.212 4.2.3.1: K = 9, start state all zeros, 8 tail bits, output
    G0, G1[, G2] repeating per input bit."""
    polys = CONV_POLY_UP[rate]
    reg = 0
    out = []
    for b in list(bits) + [0] * UP_TAIL:
        reg = ((reg << 1) | b) & ((1 << CONV_K) - 1)
        for poly in polys:
            out.append(_parity_of(reg, poly))
    return out


def equalise(bits, frames):
    """TS 25.212 4.2.4: Ni = ceil(Ei/Fi), Ti = Fi*Ni, pad Ti-Ei bits.

    "tik = {0, 1} for k = Ei+1 .. Ti" leaves the padding value open; zeros are
    used here and the row says so.  Only the uplink performs this block.
    """
    n = -(-len(bits) // frames)
    return list(bits) + [0] * (frames * n - len(bits)), n


def interleave1(bits, frames):
    """TS 25.212 4.2.5.2/4.2.5.3: write R1 x C1 row by row with C1 = Fi,
    permute the columns by Table 4, read column by column."""
    c1 = frames
    if c1 not in P1_UP:
        raise ValueError("C1 = %d is not 1, 2, 4 or 8" % c1)
    r1 = len(bits) // c1
    perm = P1_UP[c1]
    out = []
    for j in range(c1):
        col = perm[j]
        for i in range(r1):
            out.append(bits[i * c1 + col])
    return out


def segment(bits, frames):
    """TS 25.212 4.2.6: Yi = Xi/Fi, consecutive chunks of Yi bits."""
    yi = len(bits) // frames
    return [bits[i * yi:(i + 1) * yi] for i in range(frames)]


def rm_offsets(dn, xi, frames):
    """TS 25.212 4.2.7.1.2.1: the per-frame offset S the uplink initialises
    e_ini from.  q is signed, q' carries the gcd correction when q is even."""
    r = dn % xi if xi else 0
    if r != 0 and 2 * r <= xi:
        q = xi // r
    else:
        q = xi // (r - xi) if (r - xi) else 0
    if q % 2 == 0:
        from math import gcd
        # q' is q + gcd(q, Fi)/Fi, a multiple of 1/8 rather than an integer, so
        # it is kept as a numerator/denominator pair
        g = gcd(abs(q), frames) if q else frames
        qn, qd = q * frames + g, frames
    else:
        qn, qd = q, 1
    s = [0] * frames
    for x in range(frames):
        col = ((x * qn) // qd) % frames
        s[col] = (x * qn) // qd // frames
    return s, q, (qn, qd)


def uplink_rate_params(xi, ndata, frames):
    """TS 25.212 4.2.7.1.2 (I = 1 for a RACH CCTrCH): dN = Ndata - Ni, and the
    per-frame e_ini = (a S[P1(ni)] |dN| + 1) mod (a Ni), a = 2."""
    dn = ndata - xi
    s, q, qq = rm_offsets(dn, xi, frames)
    p1 = P1_UP[frames]
    return {"xi": xi, "dn": dn, "a": 2, "s": s, "q": q, "q_prime": qq,
            "e_plus": 2 * xi, "e_minus": 2 * abs(dn),
            "e_ini": [(2 * s[p1[ni]] * abs(dn) + 1) % (2 * xi)
                      for ni in range(frames)]}


def rate_match_frame(bits, par, frame_index):
    """TS 25.212 4.2.7.5, applied to one radio frame's segment."""
    if par["dn"] == 0:
        return list(bits)
    out = []
    e = par["e_ini"][frame_index]
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


def interleave2_up(bits):
    """TS 25.212 4.2.11: C2 = 30 columns, R2 rows, Table 7, read column by
    column, padding pruned."""
    u = len(bits)
    r2 = -(-u // C2_UP)
    padded = list(bits) + [0] * (r2 * C2_UP - u)
    out = []
    for j in range(C2_UP):
        col = P2_UP[j]
        for i in range(r2):
            idx = i * C2_UP + col
            if idx < u:
                out.append(padded[idx])
    return out


def tfci_encode(index):
    """TS 25.212 4.3.3: bi = sum_n a_n M_i,n mod 2 over the Table 8 basis, with
    a0 the LSB of the TFC index.  Returns the 32-bit code word."""
    if not (0 <= index <= 1023):
        raise ValueError("a TFCI is 10 bits, so the index is 0..1023")
    a = [(index >> n) & 1 for n in range(10)]
    word = []
    for row in TFCI_BASIS:
        acc = 0
        for n in range(10):
            acc ^= a[n] & (1 if row[n] == "1" else 0)
        word.append(acc)
    return word


def tfci_30(index):
    """TS 25.212 4.3.5.1: for uplink physical channels k = 0..29 and dk =
    b(k mod 32), so the first 30 bits of the 32-bit word are the field."""
    return tfci_encode(index)[:30]


def _bits_str(bits):
    """The int list a stage carries, as the '0'/'1' string the rest of this file
    (and _bits_hex) uses."""
    return "".join(str(b) for b in bits)


def rach_chain(tb_bits, crc_size, coding, frames, ndata):
    """The whole TS 25.212 4.2 transport chain for a RACH, in uplink order.

    `tb_bits` is a '0'/'1' string; every stage row carries an int list and is
    stringified at the edge by cmd_chain.
    """
    rows = []
    b = [int(c) for c in tb_bits]
    rows.append(("tb", b, "TS 25.212 4.2.13.2",
                 "one transport block of a RACH TrCH; the TTI is 10 or 20 ms "
                 "and there is exactly one TrCH in the CCTrCH (I = 1)"))
    b = crc_attach(b, crc_size) if crc_size else list(b)
    rows.append(("crc", b, "TS 25.212 4.2.1.1 + 4.2.1.2",
                 ("gCRC%d attached, parity appended p%d..p1" % (crc_size, crc_size))
                 if crc_size else "no CRC: gCRC0, a transport format attribute"))
    rows.append(("codeblock", b, "TS 25.212 4.2.2",
                 "not applied: one code block, so B = %d is not split" % len(b)))
    if coding:
        b = conv_encode_up(b, coding)
        rows.append(("conv", b, "TS 25.212 4.2.3.1",
                     "rate 1/%d, K=9, G=%s, 8 tail bits, all-zero start"
                     % (coding, ", ".join("%o" % q for q in CONV_POLY_UP[coding]))))
    else:
        rows.append(("conv", b, "TS 25.212 4.2.3",
                     "no channel coding, a transport format attribute"))
    ei = len(b)
    b, ni = equalise(b, frames)
    rows.append(("equalise", b, "TS 25.212 4.2.4",
                 "Fi = %d, Ni = ceil(%d/%d) = %d, padded with %d zero bits -- "
                 "this block exists in the UL only"
                 % (frames, ei, frames, ni, frames * ni - ei)))
    b = interleave1(b, frames)
    rows.append(("ilv1", b, "TS 25.212 4.2.5.2 + 4.2.5.3 + Table 4",
                 "C1 = %d, R1 = %d, permutation %s, read column by column"
                 % (frames, len(b) // frames, list(P1_UP[frames]))))
    segs = segment(b, frames)
    for i, seg in enumerate(segs):
        rows.append(("frameseg%d" % i, seg, "TS 25.212 4.2.6",
                     "radio frame %d of %d, Yi = %d bits" % (i, frames, len(seg))))
    par = uplink_rate_params(ni, ndata, frames)
    matched = []
    for i, seg in enumerate(segs):
        m = rate_match_frame(seg, par, i)
        matched.append(m)
        what = ("%d repetitions" % par["dn"] if par["dn"] > 0
                else ("%d punctures" % -par["dn"] if par["dn"] < 0 else "no change"))
        rows.append(("ratematch%d" % i, m, "TS 25.212 4.2.7.1.2 + 4.2.7.1.3 + 4.2.7.5",
                     "frame %d: Xi=%d, dN=%+d, e_ini=%d, e_plus=%d, e_minus=%d, %s, "
                     "output %d bits = Ndata"
                     % (i, par["xi"], par["dn"], par["e_ini"][i], par["e_plus"],
                        par["e_minus"], what, len(m))))
    x = [bit for seg in matched for bit in seg]
    rows.append(("mux", x, "TS 25.212 4.2.8",
                 "I = 1, so TrCH multiplexing is the identity"))
    rows.append(("physseg", x, "TS 25.212 4.2.10.1",
                 "P = 1, one PRACH, so physical channel segmentation is the "
                 "identity"))
    v = interleave2_up(x)
    rows.append(("ilv2", v, "TS 25.212 4.2.11 + Table 7",
                 "C2 = 30, R2 = %d, no padding for U = %d" % (len(v) // 30, len(v))))
    per_slot = len(v) // (15 * frames)
    for k in range(15 * frames):
        rows.append(("slot%02d" % k, v[k * per_slot:(k + 1) * per_slot],
                     "TS 25.211 5.2.2.1.3",
                     "%d data bits of slot %d" % (per_slot, k % 15)))
    return rows, v, par


def cmd_tfci(a):
    """TS 25.212 4.3.3 and 4.3.5.1: a TFC index to the 30 TFCI bits of a slot."""
    if not (0 <= a.index <= 1023):
        _die(2, "--index %d is outside 0..1023" % a.index,
             "TS 25.212 4.3.3: the TFCI is 10 bits, so a TFC index is 0..1023")
    word = tfci_encode(a.index)
    bits30 = word[:30]
    rows = [
        ("cli", "tfci"),
        ("index", "%d (10-bit TFC index, a0 = LSB)" % a.index),
        ("word32", "%032x" % int("".join(str(b) for b in word), 2)),
        ("word32_weight", str(sum(word))),
        ("tfci30", "%030x" % int("".join(str(b) for b in bits30), 2)),
        ("tfci30_bits", "".join(str(b) for b in bits30)),
        ("next", "message-part --tfci %030x" % int("".join(str(b) for b in bits30), 2)),
        ("ref", "TS 25.212 4.3.3: the (32,10) sub-code of the second order "
                "Reed-Muller code, basis sequences Table 8"),
        ("ref", "TS 25.212 4.3.5.1: uplink, k = 0..29 and dk = b(k mod 32), so "
                "b30 and b31 are not transmitted"),
    ]
    _emit(rows)
    _limits("tfci")
    return 0


def cmd_chain(a):
    """The RACH transport channel: a transport block to the frame bits the
    message part carries, by every stage of TS 25.212 4.2 in uplink order."""
    if a.crc not in (0, 8, 12, 16, 24):
        _die(2, "--crc %d is not a CRC this chain can attach" % a.crc,
             "TS 25.212 4.2.1.1: gCRC24, gCRC16, gCRC12, gCRC8 or gCRC0")
    if a.coding not in ("third", "half", "none"):
        _die(2, "--coding %r is not third, half or none" % a.coding,
             "TS 25.212 4.2.3: a RACH transport format codes with a "
             "convolutional code rate 1/3 or 1/2, or with no coding")
    if a.frames not in (1, 2):
        _die(2, "--frames %d is not a RACH TTI" % a.frames,
             "TS 25.212 4.2.13.2: the transmission time interval of a RACH is "
             "either 10 ms or 20 ms")
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
                 "TS 25.211 5.2.2.1.3 Table 6: the data part is 10*2^k bits, "
                 "k = 0..3, spread at SF 256, 128, 64 or 32")
    else:
        fmt = a.k if a.k is not None else 0
        if not (0 <= fmt <= 3):
            _die(2, "--k %d is outside 0..3" % fmt,
                 "TS 25.211 5.2.2.1.3: data part = 10*2^k bits with k = 0..3")
    sf, ndata = SLOT_FORMATS[fmt]
    ndata_frame = ndata * SLOTS_PER_FRAME
    tb = _hex_field(a.tb, "--tb") if a.tb else ""
    tb_bits = _bits_int(int(tb, 16), len(tb) * 4) if tb else ""
    coding = {"third": 3, "half": 2, "none": None}[a.coding]
    rows, v, par = rach_chain(tb_bits or "", a.crc, coding, a.frames, ndata_frame)
    parts = []
    for name, bits, ref, note in rows:
        parts.append(("stage:" + name, "%s bits=%d ref=%s -- %s"
                      % (_bits_hex(_bits_str(bits)), len(bits), ref, note)))
    per_frame = len(v) // a.frames
    for i in range(a.frames):
        fr = v[i * per_frame:(i + 1) * per_frame]
        parts.append(("frame%d.hex" % i, _bits_hex(_bits_str(fr))))
        parts.append(("frame%d.bits" % i, str(len(fr))))
    parts.extend([
        ("frames", str(a.frames)),
        ("tti_ms", str(10 * a.frames)),
        ("slot_format", "%d of 0..3, SF %d, %d data bits per slot" % (fmt, sf, ndata)),
        ("ndata", "%d bits per radio frame" % ndata_frame),
        ("tb_bits", str(len(tb_bits))),
        ("crc", str(a.crc)),
        ("coding", a.coding),
        ("dN", "%+d" % par["dn"]),
        ("rate_match", "Xi=%d, e_plus=%d, e_minus=%d, S=%s, e_ini=%s"
         % (par["xi"], par["e_plus"], par["e_minus"], par["s"],
            par["e_ini"])),
        ("data_hex", _bits_hex(_bits_str(v))),
        ("data_bits", str(len(v))),
    ])
    tfci_note = ""
    if a.tfci_index is not None:
        bits30 = tfci_30(a.tfci_index)
        tfci_note = " --tfci %030x" % int("".join(str(b) for b in bits30), 2)
        parts.append(("tfci_index", str(a.tfci_index)))
        parts.append(("tfci30", "%030x" % int("".join(str(b) for b in bits30), 2)))
    parts.append(("next", "message-part --sf %d --frames %d --data %s%s"
                  % (sf, a.frames, _bits_hex(_bits_str(v)), tfci_note)))
    parts.append(("ref", "TS 25.212 4.2: the uplink chain in uplink order, with "
                         "radio frame size equalisation (4.2.4) before the 1st "
                         "interleaver (4.2.5) and rate matching per radio frame"))
    _emit(parts)
    _limits("chain")
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
     "[--data HEX] [--psc 0..511] [--code 0..15] [--beta-c 0..15] "
     "[--beta-d 0..15] [--frames 1|2] [--rate N|Hz] [--format cf32|ci16|cu8] "
     "[--out PATH] [--no-scrambling]",
     "RACH message part: slot structure as bits, and with --out the spread, "
     "weighted and scrambled chips (TS 25.211 5.2.2.1.3, TS 25.213 4.2.2.2)"),
    ("burst",
     "[--signature 0..15] [--psc 0..511] [--code 0..15] [--preambles 1..64] "
     "[--gap-chips N] [--sf 256|128|64|32] [--frames 1|2] [--data HEX] "
     "[--tfci HEX30] [--beta-c 0..15] [--beta-d 0..15] [--rate N|Hz] "
     "[--format cf32|ci16|cu8] [--out PATH] [--no-scrambling]",
     "a whole random-access transmission: preambles then the message part "
     "(TS 25.211 5.2.2.1.1)"),
    ("chain",
     "--tb HEX [--crc 0|8|12|16|24] [--coding third|half|none] "
     "[--frames 1|2] [--sf 256|128|64|32 | --k 0..3] [--tfci-index 0..1023]",
     "the RACH transport channel: a transport block through the whole "
     "TS 25.212 4.2 uplink chain to the frame bits the message part carries"),
    ("tfci",
     "--index 0..1023",
     "a TFC index to the 30 TFCI bits of a slot (TS 25.212 4.3.3 + 4.3.5.1)"),
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
    p.add_argument("--psc", type=int, default=0,
                   help="downlink primary scrambling code the PRACH code group "
                        "comes from, 0..511 (TS 25.213 4.3.3.2)")
    p.add_argument("--code", type=int, default=0,
                   help="PRACH code index within the group, 0..15")
    p.add_argument("--beta-c", dest="beta_c", type=int, default=15,
                   help="signalled gain factor for the control part, 0..15")
    p.add_argument("--beta-d", dest="beta_d", type=int, default=15,
                   help="signalled gain factor for the data part, 0..15")
    p.add_argument("--frames", type=int, default=1,
                   help="message part length: 1 frame (10 ms) or 2 (20 ms)")
    p.add_argument("--rate", type=int, default=1,
                   help="samples per chip (1..64) or a sample rate in Hz")
    p.add_argument("--format", default="cf32", help="cf32, ci16 or cu8")
    p.add_argument("--out", default=None, help="samples file")
    p.add_argument("--no-scrambling", dest="no_scrambling", action="store_true",
                   help="leave the chips unscrambled")
    p.set_defaults(fn=cmd_message_part)

    p = sub.add_parser("burst", help="a whole random-access transmission")
    p.add_argument("--signature", type=int, default=0)
    p.add_argument("--psc", type=int, default=0)
    p.add_argument("--code", type=int, default=0)
    p.add_argument("--preambles", type=int, default=1)
    p.add_argument("--gap-chips", dest="gap_chips", type=int, default=0)
    p.add_argument("--sf", type=int, default=None)
    p.add_argument("--frames", type=int, default=1)
    p.add_argument("--data", default=None)
    p.add_argument("--tfci", default=None)
    p.add_argument("--beta-c", dest="beta_c", type=int, default=15)
    p.add_argument("--beta-d", dest="beta_d", type=int, default=15)
    p.add_argument("--rate", type=int, default=1)
    p.add_argument("--format", default="cf32")
    p.add_argument("--out", default=None)
    p.add_argument("--no-scrambling", dest="no_scrambling", action="store_true")
    p.set_defaults(fn=cmd_burst)

    p = sub.add_parser("chain",
                       help="the RACH transport channel, TS 25.212 4.2 uplink")
    p.add_argument("--tb", default=None, help="the transport block as hex bits")
    p.add_argument("--crc", type=int, default=16,
                   help="CRC size: 24, 16, 12, 8 or 0")
    p.add_argument("--coding", default="third",
                   help="channel coding: third (rate 1/3), half (rate 1/2), none")
    p.add_argument("--frames", type=int, default=1,
                   help="TTI: 1 frame (10 ms) or 2 (20 ms)")
    p.add_argument("--sf", type=int, default=None, help="256, 128, 64 or 32")
    p.add_argument("--k", type=int, default=None, help="slot format 0..3")
    p.add_argument("--tfci-index", dest="tfci_index", type=int, default=None,
                   help="also encode this TFC index into the 30 TFCI bits")
    p.set_defaults(fn=cmd_chain)

    p = sub.add_parser("tfci", help="TFC index to the 30 TFCI bits")
    p.add_argument("--index", type=int, default=0, help="the 10-bit TFC index")
    p.set_defaults(fn=cmd_tfci)

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
