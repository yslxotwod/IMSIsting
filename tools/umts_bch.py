#!/usr/bin/env python3
"""UMTS BCH transport-channel coding chain and P-CCPCH chip generator.

Every constant used below is read out of the clause printed next to it.  The
texts are the Release 6 versions, matching the supplied TS 25.212:

  [1] ETSI TS 125 212 V6.4.0 (3GPP TS 25.212 v6.4.0), "Multiplexing and
      channel coding (FDD)"
      https://www.etsi.org/deliver/etsi_ts/125200_125299/125212/06.04.00_60/ts_125212v060400p.pdf
  [2] ETSI TS 125 211 V6.4.0 (3GPP TS 25.211 v6.4.0), "Physical channels and
      mapping of transport channels onto physical channels (FDD)"
      https://www.etsi.org/deliver/etsi_ts/125200_125299/125211/06.04.00_60/ts_125211v060400p.pdf
  [3] ETSI TS 125 213 V6.4.0 (3GPP TS 25.213 v6.4.0), "Spreading and
      modulation (FDD)"
      https://www.etsi.org/deliver/etsi_ts/125200_125299/125213/06.04.00_60/ts_125213v060400p.pdf

The chain, in the order of [1] clause 4.2:

  4.2.1.1 + 4.2.1.2   CRC attachment        24 -> 40 bits  (gCRC16)
  4.2.3.1             convolutional coding  40 -> 96 bits  (1/2, K=9,
                                                            G0=561, G1=753,
                                                            8 tail bits)
  4.2.4               radio frame size equalisation
                      "only performed in the UL" -> not applied to the BCH
  4.2.7.2 + 4.2.7.2.1 rate matching parameters
                      Ndata,* = P*15*(Ndata1+Ndata2) = 270
  4.2.7.5             rate matching pattern  96 -> 270 bits (174 repeats)
  4.2.6.2             radio frame segmentation   Fi = 1 -> transparent
  4.2.9.1             1st DTX insertion         Hi = Di = 270 -> no DTX bits
  4.2.5.4             1st interleaving          Fi = 1 -> transparent
  4.2.8               TrCH multiplexing         I = 1 -> transparent
  4.2.10.2            physical channel segmentation  P = 1 -> transparent
  4.2.11              2nd interleaving          270 bits, C2 = 30, R2 = 9
  4.2.12.2            physical channel mapping  18 bits per slot, 15 slots

The physical channel is the P-CCPCH of [2] clause 5.3.3.3: fixed rate
30 kbps, SF = 256, Ndata1 = 18 bits per slot, and the first 256 chips of
every slot are Tx OFF because P-SCH/S-SCH live there.  Spreading is
Cch,256,1 ([3] 5.2.1), the modulation is QPSK ([3] 5.1.1.1) and the
scrambling code is Sdl,n with n = 16*i for primary code i ([3] 5.2.2),
applied aligned with the P-CCPCH frame boundary ([3] 5.1.4).

Two things are not in [1]-[3] and are therefore inputs or documented gaps,
never guessed constants: the transport block content and size (the BCH
transport format is a predefined higher-layer attribute, [1] 4.2.13.6 points
at [11] = TS 25.331), and the pulse shape ([3] 5.3.2 defers it to [4] =
TS 25.104).  See the `limit` rows below and `umts_bch.py list`.

Usage:
  umts_bch.py encode --bch-hex <hex> --out <path> [--format cf32|ci16|cu8]
                     [--rate <samples/chip>] [--psc <0-511>] [--frames <n>]
  umts_bch.py stages --bch-hex <hex> [--psc <0-511>]
  umts_bch.py list

Exit codes: 0 built, 1 could not build, 2 usage error or refused.
"""

import math
import sys

try:
    import numpy as np
except ImportError:  # stages/list do not need it; encode refuses without it
    np = None


# ---------------------------------------------------------------------------
# Constants, each with the clause it comes from.
# ---------------------------------------------------------------------------

# [2] 5.3.3.3: the P-CCPCH slot is 2560 chips, fifteen of them per 10 ms frame,
# and the P-CCPCH row of the channel table is the 30 kbps, SF = 256 one.
CHIPS_PER_SLOT = 2560
SLOTS_PER_FRAME = 15
CHIPS_PER_FRAME = CHIPS_PER_SLOT * SLOTS_PER_FRAME  # 38400
SF = 256                       # [2] 5.3.3.3 "fixed rate (30 kbps, SF=256)"
OFF_CHIPS = 256                # [2] 5.3.3.3 Figure 15: first 256 chips Tx OFF
NDATA1 = 18                    # [2] 5.3.3.3 Figure 15: "Data Ndata1 bits"
NDATA2 = 0                     # [2] 5.3.3.3 Figure 15: no Ndata2 field
BITS_PER_SLOT = NDATA1 + NDATA2                     # 18
BITS_PER_FRAME = BITS_PER_SLOT * SLOTS_PER_FRAME    # 270
DATA_CHIPS_PER_SLOT = CHIPS_PER_SLOT - OFF_CHIPS    # 2304
SYMBOLS_PER_SLOT = BITS_PER_SLOT // 2               # 9, QPSK
CHIP_RATE = 3840000            # [3] 5.3.1 chip rate 3.84 Mcps

# [1] 4.2.1.1: gCRC16(D) = D16 + D12 + D5 + 1
CRC_BITS = 16
GCRC16 = 0b10001000000100001   # coefficients of D16 .. D0

# [1] 4.2.3.1: rate 1/2, constraint length 9, G0 = 561 octal, G1 = 753 octal,
# 8 tail bits of binary 0, shift register starts all-zero.  The figures are
# not extractable from the text, so the tap sets are the octal numbers as
# 9-bit binary with the most significant bit being the current input bit;
# that is the reading under which they are the published generating functions
# 1 + D4 + D5 + D6 + D8 and 1 + D + D3 + D5 + D6 + D7 + D8.
CONV_K = 9
G0 = 0o561                     # 0b101110001
G1 = 0o753                     # 0b111101011
TAIL_BITS = 8

# [1] 4.2.13.6: one TrCH, one transport block per TTI, one P-CCPCH; every
# transport format attribute except RM1 is predefined by higher layers.
BCH_TB_BITS = 24
N_PHYS = 1                     # P = 1  ([1] 4.2.13.6 "Only one primary CCPCH")
                               # I = 1 and M1 = 1 per the same clause
TTI_FRAMES = 1                 # Fi = 1: one BCH block per 10 ms frame
# [1] 4.2.13.6: "The Static rate matching parameter RM1 is not provided by
# higher layer signalling neither fixed. Any value may be used as there is one
# transport channel in the CCTrCH and no need to do any balancing between
# multiple transport channels."  With I = 1, [1] 4.2.7 formula (1) gives
# Z1,j = Ndata,j exactly, so the pattern does not depend on RM1; RM1 = 1 is
# used here and both values are computed to show the equality.
RM1 = 1

# [1] 4.2.3.1 / 4.2.7.2 / 4.2.7.2.1.3, evaluated for the single BCH
# transport format.  The arithmetic is redone in rate_match_params().
E_I = (BCH_TB_BITS + CRC_BITS + TAIL_BITS) * 2   # 96, [1] 4.2.3.1
NDATA_STAR = N_PHYS * 15 * (NDATA1 + NDATA2)    # 270, [1] 4.2.7.2
G_I = NDATA_STAR                                # 270, [1] 4.2.7.4.4

# [1] 4.2.11 Table 7, C2 = 30
C2 = 30
P2 = [0, 20, 10, 5, 15, 25, 3, 13, 23, 8, 18, 28, 1, 11, 21,
      6, 16, 26, 4, 14, 24, 19, 9, 29, 12, 2, 7, 22, 27, 17]
R2 = int(math.ceil(BITS_PER_FRAME / float(C2)))  # 9

# [3] 5.2.1: "The channelisation code for the Primary CCPCH is fixed to
# Cch,256,1".
CODE_NUMBER = 1

# [3] 5.2.2: n = 16*i for primary scrambling code i, i = 0..511.
PSC_STRIDE = 16
PSC_MAX = 511
GOLD_PERIOD = (1 << 18) - 1                     # 262143
SCRAMBLE_Q_OFFSET = 131072                      # [3] 5.2.2 Sdl,n definition


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _die(rc, msg, why=None):
    sys.stderr.write("ERROR\t%s\n" % msg)
    if why is not None:
        sys.stderr.write("WHY\t%s\n" % why)
    raise SystemExit(rc)


def _bits_hex(bits):
    """Hex string for a bit vector, left-padded to a whole nibble."""
    v = 0
    for b in bits:
        v = (v << 1) | (b & 1)
    return "%0*x" % ((len(bits) + 3) // 4, v)


def _parse_bch_hex(text):
    t = text.strip().lower()
    if t.startswith("0x"):
        t = t[2:]
    if not t or any(c not in "0123456789abcdef" for c in t):
        _die(2, "--bch-hex %r is not hexadecimal" % (text,),
             "the transport block is given as hex digits, one nibble per "
             "4 bits; the BCH block is 24 bits = 6 hex digits")
    if len(t) * 4 != BCH_TB_BITS:
        _die(2, "--bch-hex %r is %d bits, BCH transport blocks are %d bits"
             % (text, len(t) * 4, BCH_TB_BITS),
             "the BCH transport block size is a transport format attribute "
             "predefined by higher layers ([11] = TS 25.331; [1] 4.2.13.6 "
             "says all such attributes are predefined apart from RM1), so "
             "this tool refuses to pad or truncate a block to fit")
    v = int(t, 16)
    return [(v >> (BCH_TB_BITS - 1 - k)) & 1 for k in range(BCH_TB_BITS)]


def _parity(reg, poly):
    s = 0
    for j in range(CONV_K):
        if (poly >> j) & 1:
            s ^= (reg >> j) & 1
    return s & 1


# ---------------------------------------------------------------------------
# [1] 4.2.1 CRC attachment
# ---------------------------------------------------------------------------

def crc16_parity(tb):
    """Parity bits p1..p16 of [1] 4.2.1.1.

    Systematic form: a(D)*D^16 + p1*D^15 + ... + p16*D^0 is divisible by
    gCRC16(D) = D16 + D12 + D5 + 1, i.e. p1..p16 are the coefficients, MSB
    first, of the remainder of a(D)*D^16 divided by gCRC16.  Computed here by
    running the whole dividend (block followed by 16 zeros) through the
    17-coefficient divisor.
    """
    acc = 0
    for b in list(tb) + [0] * CRC_BITS:
        acc = (acc << 1) | b
        if acc & (1 << CRC_BITS):
            acc ^= GCRC16
    return [(acc >> (CRC_BITS - 1 - k)) & 1 for k in range(CRC_BITS)]


def crc16_attach(tb):
    """[1] 4.2.1.2: b_im,k = a_im,k for k <= Ai, and

        b_im,k = p_im,(Li+1-(k-Ai))    for k = Ai+1 .. Ai+Li.

    With Li = 16 the parity bits leave in the order p16, p15, ..., p1, i.e.
    the reverse of the coefficient order that 4.2.1.1's divisibility property
    fixes.  The two clauses say what they say; the mapping is applied
    literally, which is why the CRC bytes are bit-reversed relative to a
    "append the remainder MSB first" encoder.
    """
    p = crc16_parity(tb)
    return list(tb) + list(reversed(p))


# ---------------------------------------------------------------------------
# [1] 4.2.3.1 convolutional coding
# ---------------------------------------------------------------------------

def conv_encode(bits):
    """Rate 1/2, K = 9, G0 = 561, G1 = 753, 8 zero tail bits, all-zero start.

    [1] 4.2.3.1: eight tail bits of binary 0 are appended and the two outputs
    of one input bit are emitted in the order output0, output1.  The register
    holds the current input bit in bit 0 and older bits upwards, so bit j of
    a generator polynomial taps the input j steps earlier.
    """
    reg = 0
    out = []
    for b in list(bits) + [0] * TAIL_BITS:
        reg = ((reg << 1) | b) & ((1 << CONV_K) - 1)
        out.append(_parity(reg, G0))
        out.append(_parity(reg, G1))
    return out


# ---------------------------------------------------------------------------
# [1] 4.2.7 rate matching
# ---------------------------------------------------------------------------

def rate_match_params(rm1=RM1):
    """[1] 4.2.7 formula (1)/(2), 4.2.7.2, 4.2.7.2.1.1, 4.2.7.2.1.3."""
    # 4.2.7.2.1.1: N_i,* = (1/Fi) * max over the TFS of N^TTI, and the BCH
    # has a single transport format, so N_i,* = E_i / Fi = 96.
    n_i_star = E_I // TTI_FRAMES
    # 4.2.7.2: Ndata,* = P * 15 * (Ndata1 + Ndata2); on the downlink Ndata,j
    # does not depend on j.
    ndata = N_PHYS * 15 * (NDATA1 + NDATA2)
    # 4.2.7 formula (1): Z_0,j = 0 and
    #   Z_i,j = floor( (sum_m RM_m N_m,j) * Ndata,j / (sum_m RM_m N_m,j) ).
    # With I = 1 the fraction is Ndata,j exactly, so RM1 cancels.
    z1 = (rm1 * n_i_star * ndata) // (rm1 * n_i_star)
    # 4.2.7 formula (2): dN_i,j = Z_i,j - Z_(i-1),j - N_i,j
    dn = z1 - 0 - n_i_star
    # 4.2.7.2.1.1: dN_i,max = Fi * dN_i,*
    dn_max = TTI_FRAMES * dn
    if z1 != ndata or dn_max != dn:
        _die(1, "rate matching arithmetic does not close: Z=%d Ndata=%d "
             "dN_max=%d" % (z1, ndata, dn_max),
             "TS 25.212 4.2.7 formula (1)/(2)")
    # 4.2.7.2.1.3, convolutionally coded TrCH with fixed positions.
    n_max = E_I
    return {
        "rm1": rm1,
        "N_i_star": n_i_star,
        "Ndata_star": ndata,
        "Z_1": z1,
        "delta_N": dn,
        "delta_N_max": dn_max,
        "a": 2,
        "N_max": n_max,
        "X_i": n_max,
        "e_ini": 1,
        "e_plus": 2 * n_max,
        "e_minus": 2 * dn,
        "delta_N_TTI": (dn * n_max) // n_max * (1 if dn >= 0 else -1),
    }


def rate_match(bits, prm=None):
    """[1] 4.2.7.5 repetition branch (dN > 0), bit for bit.

    e = e_ini; for every input bit: e -= e_minus; do while e <= 0 { repeat the
    bit; e += e_plus }.  "A repeated bit is placed directly after the
    original one."
    """
    prm = prm or rate_match_params()
    e = prm["e_ini"]
    out = []
    for b in bits:
        out.append(b)                      # the bit itself
        e -= prm["e_minus"]
        while e <= 0:                      # ... and its repeats
            out.append(b)
            e += prm["e_plus"]
    if len(out) != len(bits) + prm["delta_N"]:
        _die(1, "rate matching produced %d bits, the parameters demand %d"
             % (len(out), len(bits) + prm["delta_N"]),
             "TS 25.212 4.2.7.2.1.3: G_i = N_i,* + dN_i,*")
    return out


# ---------------------------------------------------------------------------
# [1] 4.2.11 2nd interleaving
# ---------------------------------------------------------------------------

def ilv2(bits):
    """[1] 4.2.11 block interleaver, C2 = 30, R2 = ceil(U/C2).

    Write row by row, permute the columns with Table 7 (P2(j) is the original
    position of permuted column j), read column by column, prune padding.
    """
    u = list(bits)
    rows = int(math.ceil(len(u) / float(C2)))
    padded = u + [0] * (rows * C2 - len(u))
    out = []
    for j in range(C2):
        for r in range(rows):
            k = r * C2 + P2[j]
            if k < len(u):
                out.append(padded[k])
    return out


# ---------------------------------------------------------------------------
# [1] 4.2.12 / [2] 5.3.3.3 / [3] 5.1.1.1, 5.2: P-CCPCH
# ---------------------------------------------------------------------------

def slot_map(bits):
    """[1] 4.2.12.2: v_p,k go on the air in ascending k; 18 bits per slot."""
    if len(bits) != BITS_PER_FRAME:
        _die(1, "%d bits do not fill %d slots of %d bits"
             % (len(bits), SLOTS_PER_FRAME, BITS_PER_SLOT),
             "TS 25.211 5.3.3.3 Figure 15 fixes Ndata1 = 18")
    return [list(bits[s * BITS_PER_SLOT:(s + 1) * BITS_PER_SLOT])
            for s in range(SLOTS_PER_FRAME)]


def qpsk(bits):
    """[3] 5.1.1.1: 0 -> +1, 1 -> -1; even symbol -> I, odd symbol -> Q."""
    syms = []
    for k in range(0, len(bits) - 1, 2):
        syms.append((1.0 if bits[k] == 0 else -1.0,
                     1.0 if bits[k + 1] == 0 else -1.0))
    return syms


def ovsf(sf, index):
    """[3] 4.3.1.1: Cch,2n',2k = (C, C), Cch,2n',2k+1 = (C, -C)."""
    if sf == 1:
        return [1]
    half = ovsf(sf // 2, index // 2)
    if index % 2 == 0:
        return half + half
    return half + [-c for c in half]


def scrambling_sequence(psc):
    """[3] 5.2.2: primary code n = 16*i and

        Sdl,n(i) = Zn(i) + j Zn((i + 131072) mod (2^18 - 1)),  i = 0..38399

    with x(i+18) = x(i+7) + x(i), y(i+18) = y(i+10) + y(i+7) + y(i+5) + y(i),
    x(0) = 1, x(1..17) = 0, y(0..17) = 1, zn(i) = x((i+n) mod (2^18-1)) + y(i)
    and Zn = +1 for zn = 0, -1 for zn = 1.
    """
    n = PSC_STRIDE * psc
    L = GOLD_PERIOD
    x = [0] * L
    y = [1] * L
    x[0] = 1
    for i in range(L - 18):
        x[i + 18] = (x[i + 7] + x[i]) & 1
        y[i + 18] = (y[i + 10] + y[i + 7] + y[i + 5] + y[i]) & 1
    seq = []
    for i in range(CHIPS_PER_FRAME):
        z1 = (x[(i + n) % L] + y[i]) & 1
        z2 = (x[(i + SCRAMBLE_Q_OFFSET + n) % L]
              + y[(i + SCRAMBLE_Q_OFFSET) % L]) & 1
        seq.append(complex(1.0 if z1 == 0 else -1.0,
                           1.0 if z2 == 0 else -1.0))
    return seq


def frame_chips(bits, psc):
    """Spread, scramble and place the 270 frame bits on the P-CCPCH.

    The channelisation code is aligned with the symbol boundary ([3] 5.1.2)
    and the scrambling code is aligned with the P-CCPCH frame boundary, so the
    P-CCPCH frame position selects the scrambling chip; the 256 chips per slot
    that belong to P-SCH/S-SCH stay unmodulated, they only advance the frame
    position ([3] 5.1.4: "aligned with the P-CCPCH frame boundary, i.e. the
    first complex chip of the spread P-CCPCH frame is multiplied with chip
    number zero of the scrambling code").
    """
    code = ovsf(SF, CODE_NUMBER)
    s = scrambling_sequence(psc)
    spread = []
    for (i, q) in qpsk(bits):
        for c in code:
            spread.append(complex(i * c, q * c))
    if len(spread) != SLOTS_PER_FRAME * DATA_CHIPS_PER_SLOT:
        _die(1, "spread %d chips, the slot structure holds %d"
             % (len(spread), SLOTS_PER_FRAME * DATA_CHIPS_PER_SLOT),
             "TS 25.211 5.3.3.3 Figure 15: 9 symbols of 256 chips per slot")
    frame = [0j] * CHIPS_PER_FRAME
    scram = []
    k = 0
    for slot in range(SLOTS_PER_FRAME):
        base = slot * CHIPS_PER_SLOT + OFF_CHIPS
        for c in range(DATA_CHIPS_PER_SLOT):
            v = spread[k] * s[base + c]
            frame[base + c] = v
            scram.append(v)
            k += 1
    return frame, spread, scram


# ---------------------------------------------------------------------------
# Chain driver
# ---------------------------------------------------------------------------

def build(bch_bits, psc=0):
    """Run the whole chain in [1] 4.2 order; return (stages, params, ilv2).

    Each stage is a dict with name, bits and ref (the clause).  The stages
    that are transparent for the BCH are kept as rows so `stages` shows the
    clause was read and why it is a no-op.
    """
    tb = list(bch_bits)
    st = []

    def add(name, bits, ref, note):
        st.append({"name": name, "bits": list(bits), "ref": ref,
                   "note": note})

    add("tb", tb, "TS 25.212 4.2.13.6",
        "one transport block per TTI (M1 = 1); the block size is a "
        "higher-layer transport format attribute ([11] = TS 25.331)")
    crc = crc16_attach(tb)
    add("crc", crc, "TS 25.212 4.2.1.1 + 4.2.1.2",
        "gCRC16 = D16+D12+D5+1, parity appended p16..p1")
    conv = conv_encode(crc)
    add("conv", conv, "TS 25.212 4.2.3.1",
        "rate 1/2, K=9, G0=561, G1=753, 8 tail bits, all-zero start")
    add("equalise", conv, "TS 25.212 4.2.4",
        "not applied: \"Radio frame size equalisation is only performed in "
        "the UL\"")
    prm = rate_match_params()
    rm = rate_match(conv, prm)
    add("ratematch", rm, "TS 25.212 4.2.7.2 + 4.2.7.2.1.1 + 4.2.7.2.1.3 + "
        "4.2.7.5",
        "Ndata,*=270, Z=270, dN=174, e_ini=1, e_plus=192, e_minus=348, "
        "174 repetitions")
    add("frameseg", rm, "TS 25.212 4.2.6.2",
        "Fi = 1, one segment of 270 bits, transparent")
    add("dtx1", rm, "TS 25.212 4.2.9.1",
        "Hi = N_i,* + dN_i,* = 270 = Gi, so no DTX bits are inserted")
    add("ilv1", rm, "TS 25.212 4.2.5.4",
        "Fi = 1, the 10 ms interleaver is a single column, transparent")
    add("mux", rm, "TS 25.212 4.2.8 + 4.2.10.2",
        "I = 1 TrCH and P = 1 PhCH, transparent")
    ilv = ilv2(rm)
    add("ilv2", ilv, "TS 25.212 4.2.11",
        "C2 = 30, R2 = 9, Table 7 permutation, no padding for U = 270")
    for s, slotbits in enumerate(slot_map(ilv)):
        add("slot%02d" % s, slotbits, "TS 25.212 4.2.12.2",
            "18 bits of slot %d" % s)
    syms = qpsk(ilv)
    add("qpsk_i", [0 if i > 0 else 1 for (i, q) in syms],
        "TS 25.213 5.1.1.1", "135 symbols, 0 -> +1, 1 -> -1 on I")
    add("qpsk_q", [0 if q > 0 else 1 for (i, q) in syms],
        "TS 25.213 5.1.1.1", "135 symbols, odd symbol of each pair -> Q")
    frame, spread, scram = frame_chips(ilv, psc)
    add("spread_i", [0 if c.real > 0 else 1 for c in spread],
        "TS 25.213 5.1.2 + 5.2.1",
        "34560 chips, Cch,256,1, I rail, 0 -> +1, 1 -> -1")
    add("spread_q", [0 if c.imag > 0 else 1 for c in spread],
        "TS 25.213 5.1.2 + 5.2.1",
        "34560 chips, Cch,256,1, Q rail, 0 -> +1, 1 -> -1")
    scr = scrambling_sequence(psc)
    add("scrambling_i", [0 if c.real > 0 else 1 for c in scr],
        "TS 25.213 5.2.2",
        "38400 chips of the frame-aligned code, Zn(i) rail, 0 -> +1, 1 -> -1")
    add("scrambling_q", [0 if c.imag > 0 else 1 for c in scr],
        "TS 25.213 5.2.2",
        "38400 chips of the frame-aligned code, Zn(i+131072) rail")
    params = {
        "N_i_star": prm["N_i_star"], "Ndata_star": prm["Ndata_star"],
        "Z_1": prm["Z_1"], "delta_N": prm["delta_N"],
        "delta_N_max": prm["delta_N_max"], "N_max": prm["N_max"],
        "X_i": prm["X_i"], "e_ini": prm["e_ini"],
        "e_plus": prm["e_plus"], "e_minus": prm["e_minus"],
        "delta_N_TTI": prm["delta_N_TTI"],
        "C2": C2, "R2": R2, "U": BITS_PER_FRAME,
        "sf": SF, "code": "Cch,%d,%d" % (SF, CODE_NUMBER),
        "bits_per_slot": BITS_PER_SLOT, "slots": SLOTS_PER_FRAME,
        "symbols_per_slot": SYMBOLS_PER_SLOT,
        "chips_on": SLOTS_PER_FRAME * DATA_CHIPS_PER_SLOT,
        "chips_off": SLOTS_PER_FRAME * OFF_CHIPS,
        "chips_frame": CHIPS_PER_FRAME,
        "psc": psc, "scrambling_code": PSC_STRIDE * psc,
    }
    return st, params, ilv


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

FORMATS = {"cf32": 8, "ci16": 4, "cu8": 2}
FULL_SCALE = {"cf32": 1.0, "ci16": 32767.0, "cu8": 127.5}


def _quantise(x, fmt):
    """Sample container: cf32 = little-endian float32 I,Q; ci16 = int16 I,Q
    at 32767 full scale; cu8 = uint8 I,Q with a 127.5 offset."""
    if fmt == "cf32":
        return np.asarray(x, dtype="<c8").tobytes()
    if fmt == "ci16":
        q = np.empty(x.size * 2, dtype="<i2")
        q[0::2] = np.clip(np.rint(x.real * 32767.0), -32768, 32767)
        q[1::2] = np.clip(np.rint(x.imag * 32767.0), -32768, 32767)
        return q.tobytes()
    q = np.empty(x.size * 2, dtype=np.uint8)
    q[0::2] = np.clip(np.rint(x.real * 127.0 + 127.5), 0, 255)
    q[1::2] = np.clip(np.rint(x.imag * 127.0 + 127.5), 0, 255)
    return q.tobytes()


def _emit(rows):
    out = []
    for k, v in rows:
        out.append("%s\t%s\n" % (k, v))
    sys.stdout.write("".join(out))


LIMITS = [
    ("amplitude",
     "the scattered chips of TS 25.213 5.1.4/5.2.2 have components in "
     "{-2, 0, +2} (|spread| = sqrt(2), |Sdl,n| = sqrt(2)); the sample file "
     "applies a fixed 0.5 so the peak component is 1.0 = full scale. No "
     "cell power, CPICH power offset or channel weight is applied, none of "
     "which is in the supplied texts"),
    ("pulse-shaping",
     "TS 25.213 5.3.2 defers the pulse shape to [4] = TS 25.104, which is "
     "not supplied; --rate > 1 therefore holds each chip flat (rectangular "
     "per-chip hold) and no RRC filter is applied"),
    ("tx-mask",
     "no spectrum emission mask is in the supplied texts; the flat-hold "
     "samples are not shaped to a mask"),
    ("sttd",
     "TS 25.211 5.3.3.3.1: whether or not STTD is applied is signalled by "
     "higher layers; this tool emits the non-STTD P-CCPCH only"),
    ("code-phase",
     "frame 0 starts at scrambling-code phase 0; TS 25.213 5.2.2 repeats "
     "the phase 0..38399 pattern every 10 ms, so every frame of the output "
     "carries the same 38400-chip pattern"),
    ("crc-order",
     "TS 25.212 4.2.1.1 puts p1 at D^15 while 4.2.1.2 transmits p16 first; "
     "the two orders differ, and the transmission mapping of 4.2.1.2 is "
     "applied literally here"),
]


def _chain_rows(st, params):
    rows = []
    for s in st:
        rows.append(("stage:" + s["name"],
                     "%s bits=%d ref=%s -- %s"
                     % (_bits_hex(s["bits"]), len(s["bits"]), s["ref"],
                        s["note"])))
    for k in ("N_i_star", "Ndata_star", "Z_1", "delta_N", "delta_N_max",
              "N_max", "X_i", "e_ini", "e_plus", "e_minus", "delta_N_TTI",
              "C2", "R2", "U", "sf", "bits_per_slot", "slots",
              "symbols_per_slot", "chips_on", "chips_off", "chips_frame",
              "psc", "scrambling_code"):
        rows.append(("param:" + k, "%d" % params[k]))
    rows.append(("param:code", params["code"]))
    rows.append(("param:table7", ", ".join("%d" % x for x in P2)))
    rows.append(("param:rm1",
                 "%d (arbitrary, TS 25.212 4.2.13.6: with I = 1 clause 4.2.7 "
                 "gives Z_1,j = Ndata,j, so the pattern does not depend on "
                 "it)" % RM1))
    return rows


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list(args):
    rows = [
        ("chain",
         "1 CRC attachment 24 -> 40 bits, gCRC16 = D16+D12+D5+1, parity "
         "appended in the order p16..p1 [TS 25.212 4.2.1.1, 4.2.1.2]"),
        ("chain",
         "2 convolutional coding 40 -> 96 bits, rate 1/2, K = 9, "
         "G0 = 561 octal, G1 = 753 octal, 8 tail bits of 0 [TS 25.212 4.2.3.1]"),
        ("chain",
         "3 radio frame size equalisation: not applied, TS 25.212 4.2.4 is "
         "uplink-only [TS 25.212 4.2.4]"),
        ("chain",
         "4 rate matching 96 -> 270 bits: Ndata,* = P*15*(Ndata1+Ndata2) = "
         "270, Z = 270, dN = 174, e_ini = 1, e_plus = 192, e_minus = 348, "
         "174 repetitions [TS 25.212 4.2.7, 4.2.7.2, 4.2.7.2.1.1, 4.2.7.2.1.3, "
         "4.2.7.5]"),
        ("chain",
         "5 radio frame segmentation + 1st DTX insertion + 1st interleaving: "
         "transparent, Fi = 1 [TS 25.212 4.2.5.4, 4.2.6, 4.2.9.1]"),
        ("chain",
         "6 TrCH multiplexing + physical channel segmentation: transparent, "
         "I = 1 and P = 1 [TS 25.212 4.2.10, 4.2.10.2]"),
        ("chain",
         "7 2nd interleaving 270 -> 270 bits, C2 = 30, R2 = 9, Table 7 "
         "permutation, no padding [TS 25.212 4.2.11]"),
        ("chain",
         "8 physical channel mapping + P-CCPCH: 15 slots of 18 data bits "
         "after a 256-chip Tx OFF gap, SF = 256, Cch,256,1, QPSK, "
         "Sdl,16*PSC aligned to the frame boundary [TS 25.212 4.2.12.2, TS 25.211 "
         "5.3.3.3, TS 25.213 5.1.1.1, 5.1.2, 5.1.4, 5.2.1, 5.2.2]"),
        ("output",
         "cf32 | ci16 | cu8 at --rate samples per chip, --frames frames of "
         "38400 chips, peak component 1.0"),
        ("note",
         "clause numbering of TS 25.211 v6.4.0: 5.3.3.2 is \"Downlink phase "
         "reference\" (Table 17); the P-CCPCH structure is 5.3.3.3 of the "
         "same document version as the supplied TS 25.212, and the P-CCPCH "
         "constants are taken from there"),
        ("note",
         "TS 25.212 4.2.13.6: \"There can only be one TrCH in the BCH "
         "CCTrCH, i.e. I=1\"; \"There can only be one transport block in "
         "each transmission time interval, i.e. M1 = 1\"; \"The Static rate "
         "matching parameter RM1 is not provided by higher layer signalling "
         "neither fixed. Any value may be used as there is one transport "
         "channel in the CCTrCH\"; \"Only one primary CCPCH is used, i.e. "
         "P=1\""),
        ("refused",
         "compressed mode (puncturing or spreading-factor reduction): the "
         "Np^TTI, TGL, Nfirst and Nlast parameters of TS 25.212 4.2.7.2.1.2 "
         "are signalled from higher layers (TS 25.331) and are not in the "
         "supplied texts"),
        ("refused",
         "STTD transmit diversity: signalled per cell by higher layers, no "
         "value is fixed by TS 25.211 5.3.3.3.1"),
        ("refused",
         "transport blocks other than 24 bits, more than one transport "
         "block, more than one TrCH, more than one P-CCPCH: the transport "
         "format attributes are predefined by [11] = TS 25.331 (not "
         "supplied), and 4.2.13.6 fixes M1 = 1, I = 1, P = 1"),
        ("refused",
         "secondary scrambling codes: a cell's P-CCPCH always uses the "
         "primary code Sdl,16*i of TS 25.213 5.2.2, the secondary codes are "
         "not part of this channel"),
        ("refused",
         "pulse shaping and the TX mask: TS 25.213 5.3.2 points at "
         "[4] = TS 25.104, which is not supplied, so no filter is applied "
         "and no mask is claimed"),
    ]
    for key, text in LIMITS:
        rows.append(("limit", "%s: %s" % (key, text)))
    _emit(rows)
    return 0


def cmd_stages(args):
    tb = _parse_bch_hex(args.bch_hex)
    st, params, _ = build(tb, args.psc)
    rows = [
        ("cli", "stages"),
        ("bch_hex", "%06x" % int("".join(str(b) for b in tb), 2)),
        ("tb_bits", "%d" % BCH_TB_BITS),
        ("frames", "1"),
    ]
    rows.extend(_chain_rows(st, params))
    for key, text in LIMITS:
        rows.append(("limit", "%s: %s" % (key, text)))
    _emit(rows)
    return 0


def cmd_encode(args):
    if np is None:
        _die(1, "numpy is not installed",
             "the sample writer needs numpy; `stages` and `list` do not")
    tb = _parse_bch_hex(args.bch_hex)
    fmt = args.format
    if fmt not in FORMATS:
        _die(2, "--format %r is not one of cf32, ci16, cu8" % (fmt,),
             "the sample container must be one this tool can write")
    sps = args.rate
    if sps < 1 or sps > 64:
        _die(2, "--rate %d samples per chip is outside 1..64" % sps,
             "the carrier is 3.84 Mcps, so %d samples per chip is out of "
             "range" % sps)
    if args.psc < 0 or args.psc > PSC_MAX:
        _die(2, "--psc %d is outside 0..511" % args.psc,
             "TS 25.213 5.2.2 defines 512 primary scrambling codes")
    if args.at_start < 0 or args.at_start >= args.frames:
        _die(2, "--at-start %d is outside the %d frame file"
             % (args.at_start, args.frames),
             "the first frame the BCH occupies has to be one of the frames the "
             "file holds")
    if args.period < 1:
        _die(2, "--period %d is not a frame count" % args.period,
             "a period of one means every frame; zero would mean no frame at all")
    if args.frames < 1 or args.frames > 100:
        _die(2, "--frames %d is outside 1..100" % args.frames,
             "one frame is 38400 chips")
    if args.out in ("-", "/dev/stdout", "/dev/fd/1"):
        _die(2, "--out must be a file path; stdout carries the TSV summary",
             "the TSV summary is the tool's output channel; the sample "
             "file is binary and would interleave with it")

    st, params, ilv = build(tb, args.psc)
    frame, spread, scram = frame_chips(ilv, args.psc)
    # The complex product of a +-1 +-1j spread chip with Sdl,n (whose rails are
    # +-1 each, so |Sdl,n| = sqrt(2), TS 25.213 5.2.2) lands on one axis with
    # a component of +-2 or 0.  A factor of 1/2 puts the peak component at
    # full scale without changing anything about the channel.
    # A channel that does not occupy every frame is silent in the others: the
    # BCH repeats once per MIB period (80 ms = 8 frames), so a file built for a
    # whole SIB cycle must not carry the MIB in every frame of it.
    used = [1 if (f >= args.at_start and
                  (f - args.at_start) % args.period == 0) else 0
            for f in range(args.frames)]
    frames_written = int(sum(used))
    plan = np.concatenate([np.asarray(frame, dtype=np.complex128) * u
                           for u in used])
    x = plan * 0.5
    if sps > 1:
        x = np.repeat(x, sps)
    payload = _quantise(x, fmt)
    if len(payload) != x.size * FORMATS[fmt]:
        _die(1, "internal: %d bytes for %d %s samples"
             % (len(payload), x.size, fmt))
    try:
        with open(args.out, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        _die(1, "cannot write %s: %s" % (args.out, exc))

    peak = float(max(abs(x.real).max(), abs(x.imag).max()))
    rows = [
        ("path", args.out),
        ("hex", _bits_hex(ilv)),
        ("bch_hex", "%06x" % int("".join(str(b) for b in tb), 2)),
        ("tb_bits", "%d" % BCH_TB_BITS),
        ("crc_bits", "%d" % CRC_BITS),
        ("coded_bits", "%d" % E_I),
        ("rate_matched_bits", "%d" % G_I),
        ("delta_N", "%d" % params["delta_N"]),
        ("format", fmt),
        ("rate", "%d" % (sps * CHIP_RATE)),
        ("chip_rate", "%d" % CHIP_RATE),
        ("chip_samples", "%d" % sps),
        ("seconds", "%.9f" % (x.size / float(sps * CHIP_RATE))),
        ("frames", "%d" % args.frames),
        ("at_start", "%d" % args.at_start),
        ("period", "%d" % args.period),
        ("frames_written", "%d" % frames_written),
        ("slots", "%d" % (args.frames * SLOTS_PER_FRAME)),
        ("chips", "%d" % (args.frames * CHIPS_PER_FRAME)),
        ("chips_on", "%d" % (args.frames * SLOTS_PER_FRAME
                             * DATA_CHIPS_PER_SLOT)),
        ("chips_off", "%d" % (args.frames * SLOTS_PER_FRAME * OFF_CHIPS)),
        ("chips_per_slot", "%d" % CHIPS_PER_SLOT),
        ("chips_per_frame", "%d" % CHIPS_PER_FRAME),
        ("samples", "%d" % x.size),
        ("bytes", "%d" % len(payload)),
        ("psc", "%d" % args.psc),
        ("scrambling_code", "%d" % params["scrambling_code"]),
        ("sf", "%d" % SF),
        ("code", params["code"]),
        ("bits_per_slot", "%d" % BITS_PER_SLOT),
        ("symbols_per_slot", "%d" % SYMBOLS_PER_SLOT),
        ("peak_full_scale", "%.4f" % FULL_SCALE[fmt]),
        ("peak_written", "%.6f" % peak),
        ("scale", "0.5"),
        ("chip_constellation",
         "I,Q in {-2, 0, +2} before the 0.5 scale: |Sdl,n| = sqrt(2) "
         "(TS 25.213 5.2.2 rails are +-1) times the sqrt(2) QPSK symbol"),
        ("dtx_chips", "%d" % (args.frames * SLOTS_PER_FRAME * OFF_CHIPS)),
        ("formula_ref",
         "TS 25.212 4.2.1.1+4.2.1.2 (gCRC16), 4.2.3.1 (1/2, K=9, 561/753, "
         "8 tail bits), 4.2.7.2+4.2.7.2.1.1+4.2.7.2.1.3+4.2.7.5 "
         "(Ndata,*=270, dN=174), 4.2.11 (C2=30, R2=9, Table 7), 4.2.12.2; "
         "TS 25.211 5.3.3.3 (30 kbps, SF=256, Ndata1=18, 256-chip Tx OFF); "
         "TS 25.213 5.1.1.1 (QPSK), 5.2.1 (Cch,256,1), 5.2.2 (Sdl,16*PSC), "
         "5.1.4 (frame-aligned scrambling)"),
    ]
    for key, text in LIMITS:
        rows.append(("limit", "%s: %s" % (key, text)))
    _emit(rows)
    return 0


def _parser():
    import argparse

    def sps(text):
        v = int(text, 0)
        if v >= CHIP_RATE and v % CHIP_RATE == 0:
            v //= CHIP_RATE
        return v

    p = argparse.ArgumentParser(
        prog="umts_bch.py",
        description="UMTS BCH coding chain (TS 25.212) and P-CCPCH "
                    "(TS 25.211/25.213) chip generator")
    sub = p.add_subparsers(dest="cmd")
    e = sub.add_parser("encode", help="write P-CCPCH samples")
    e.add_argument("--bch-hex", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--format", default="cf32")
    e.add_argument("--rate", type=sps, default=1)
    e.add_argument("--psc", type=int, default=0)
    e.add_argument("--frames", type=int, default=1)
    e.add_argument("--at-start", type=int, default=0,
                   help="first frame the BCH occupies, 0-based")
    e.add_argument("--period", type=int, default=1,
                   help="repeat every N frames; the MIB period is 8 frames "
                        "(80 ms, TS 25.331 8.1.1.1.1)")
    s = sub.add_parser("stages", help="print every intermediate bit vector")
    s.add_argument("--bch-hex", required=True)
    s.add_argument("--psc", type=int, default=0)
    sub.add_parser("list", help="what is built and what is refused")
    return p


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "stages":
        return cmd_stages(args)
    if args.cmd == "encode":
        return cmd_encode(args)
    _parser().print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
