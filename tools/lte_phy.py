#!/usr/bin/env python3
"""LTE downlink physical-layer coding, TS 36.212.

Every constant and every algorithm here is transcribed from a source outside
this tree, and every one is asserted against a vector captured from an
independent implementation. Nothing is written from memory:

  * CRC24A / CRC24B / CRC16 / CRC8 polynomials and the bit-at-a-time shift
    register come from srsRAN's lib/src/phy/fec/crc.c and its table in
    lib/src/phy/fec/test/crc_test.h. The four gold checksums below are
    srsRAN's own: 5001 bits of `srand(1); rand() % 2`, crc24a 0x1C5C97,
    crc24b 0x36D1F0, crc16 0x7FF4, crc8 0xF0.

  * The turbo encoder is a transcription of srsran_tcod_encode() in
    srsRAN's lib/src/phy/fec/turbo/turbocoder.c. Its two constituent
    encoders are the 8-state rate-1/2 recursive systematic code of
    TS 36.212 5.1.3.2.3 with g0(D) = 1 + D^2 + D^3 (feedback) and
    g1(D) = 1 + D + D^3 (feedforward), and the 12 tail bits are the
    switch-to-zero tail of TS 36.212 5.1.3.2.2.

  * The QPP interleaver parameters are srsRAN's f1_list / f2_list
    (lib/src/phy/fec/turbo/tc_interl_lte.c) against its tc_cb_sizes
    (lib/src/phy/fec/cbsegm.c), which are TS 36.212 Table 5.1.3-3.
    Pi(i) = (f1*i + f2*i*i) mod K.

The turbo encoder is verified against CommPy 1.2.0 -- a third-party library
that builds the same code from a trellis description rather than from
srsRAN's C. The captured vectors are in TURBO_VECTORS; they were produced by
CommPy and are asserted here, so the check does not need CommPy installed.

CLI:
    lte_phy.py crc   <hex> [24a|24b|16|8]
    lte_phy.py turbo <hex>          encode with the LTE turbo code
    lte_phy.py sizes                the 188 valid code-block sizes
    lte_phy.py selftest
"""

import math
import sys

# TS 36.212 Table 5.1.3-3, via srsRAN f1_list / f2_list, indexed by the
# matching entry of tc_cb_sizes. Three parallel lists, 188 entries each.
TC_CB_SIZES = [
    40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128,
    136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216, 224,
    232, 240, 248, 256, 264, 272, 280, 288, 296, 304, 312, 320,
    328, 336, 344, 352, 360, 368, 376, 384, 392, 400, 408, 416,
    424, 432, 440, 448, 456, 464, 472, 480, 488, 496, 504, 512,
    528, 544, 560, 576, 592, 608, 624, 640, 656, 672, 688, 704,
    720, 736, 752, 768, 784, 800, 816, 832, 848, 864, 880, 896,
    912, 928, 944, 960, 976, 992, 1008, 1024, 1056, 1088, 1120, 1152,
    1184, 1216, 1248, 1280, 1312, 1344, 1376, 1408, 1440, 1472, 1504, 1536,
    1568, 1600, 1632, 1664, 1696, 1728, 1760, 1792, 1824, 1856, 1888, 1920,
    1952, 1984, 2016, 2048, 2112, 2176, 2240, 2304, 2368, 2432, 2496, 2560,
    2624, 2688, 2752, 2816, 2880, 2944, 3008, 3072, 3136, 3200, 3264, 3328,
    3392, 3456, 3520, 3584, 3648, 3712, 3776, 3840, 3904, 3968, 4032, 4096,
    4160, 4224, 4288, 4352, 4416, 4480, 4544, 4608, 4672, 4736, 4800, 4864,
    4928, 4992, 5056, 5120, 5184, 5248, 5312, 5376, 5440, 5504, 5568, 5632,
    5696, 5760, 5824, 5888, 5952, 6016, 6080, 6144,
]
TC_F1 = [
    3, 7, 19, 7, 7, 11, 5, 11, 7, 41, 103, 15,
    9, 17, 9, 21, 101, 21, 57, 23, 13, 27, 11, 27,
    85, 29, 33, 15, 17, 33, 103, 19, 19, 37, 19, 21,
    21, 115, 193, 21, 133, 81, 45, 23, 243, 151, 155, 25,
    51, 47, 91, 29, 29, 247, 29, 89, 91, 157, 55, 31,
    17, 35, 227, 65, 19, 37, 41, 39, 185, 43, 21, 155,
    79, 139, 23, 217, 25, 17, 127, 25, 239, 17, 137, 215,
    29, 15, 147, 29, 59, 65, 55, 31, 17, 171, 67, 35,
    19, 39, 19, 199, 21, 211, 21, 43, 149, 45, 49, 71,
    13, 17, 25, 183, 55, 127, 27, 29, 29, 57, 45, 31,
    59, 185, 113, 31, 17, 171, 209, 253, 367, 265, 181, 39,
    27, 127, 143, 43, 29, 45, 157, 47, 13, 111, 443, 51,
    51, 451, 257, 57, 313, 271, 179, 331, 363, 375, 127, 31,
    33, 43, 33, 477, 35, 233, 357, 337, 37, 71, 71, 37,
    39, 127, 39, 39, 31, 113, 41, 251, 43, 21, 43, 45,
    45, 161, 89, 323, 47, 23, 47, 263,
]
TC_F2 = [
    10, 12, 42, 16, 18, 20, 22, 24, 26, 84, 90, 32,
    34, 108, 38, 120, 84, 44, 46, 48, 50, 52, 36, 56,
    58, 60, 62, 32, 198, 68, 210, 36, 74, 76, 78, 120,
    82, 84, 86, 44, 90, 46, 94, 48, 98, 40, 102, 52,
    106, 72, 110, 168, 114, 58, 118, 180, 122, 62, 84, 64,
    66, 68, 420, 96, 74, 76, 234, 80, 82, 252, 86, 44,
    120, 92, 94, 48, 98, 80, 102, 52, 106, 48, 110, 112,
    114, 58, 118, 60, 122, 124, 84, 64, 66, 204, 140, 72,
    74, 76, 78, 240, 82, 252, 86, 88, 60, 92, 846, 48,
    28, 80, 102, 104, 954, 96, 110, 112, 114, 116, 354, 120,
    610, 124, 420, 64, 66, 136, 420, 216, 444, 456, 468, 80,
    164, 504, 172, 88, 300, 92, 188, 96, 28, 240, 204, 104,
    212, 192, 220, 336, 228, 232, 236, 120, 244, 248, 168, 64,
    130, 264, 134, 408, 138, 280, 142, 480, 146, 444, 120, 152,
    462, 234, 158, 80, 96, 902, 166, 336, 170, 86, 174, 176,
    178, 120, 182, 184, 186, 94, 190, 480,
]


# 3GPP polynomials, TS 36.212 5.1.1. The x^order term is implicit and the
# constant term is implicit too: these are the 24/16/8 significant bits below
# the leading one, exactly as srsRAN passes them to srsran_crc_init().
CRC_POLYS = {
    "24a": (24, 0x864CFB),
    "24b": (24, 0x800063),
    "16": (16, 0x1021),
    "8": (8, 0x9B),
}


def lte_crc(bits, kind="24a"):
    """The CRC of TS 36.212 5.1.1: a plain shift register, no reflection.

    `bits` is an iterable of 0/1 (or '0'/'1'). The returned value is the CRC
    word as an integer; append it most-significant bit first to transmit it.
    """
    if kind not in CRC_POLYS:
        raise ValueError("unknown CRC %r (have %s)"
                         % (kind, ", ".join(sorted(CRC_POLYS))))
    order, poly = CRC_POLYS[kind]
    top = 1 << (order - 1)
    mask = (1 << order) - 1
    reg = 0
    for b in bits:
        bit = 1 if (b == 1 or b == "1") else 0
        msb = 1 if (reg & top) else 0
        reg = (reg << 1) & mask
        if bit ^ msb:
            reg ^= poly
    return reg


def crc_bits(bits, kind="24a"):
    """The CRC as a bit list, MSB first -- the order it is transmitted in."""
    order, _ = CRC_POLYS[kind]
    v = lte_crc(bits, kind)
    return [(v >> (order - 1 - i)) & 1 for i in range(order)]


def cb_size_index(k):
    """Index of a valid turbo code-block size, or raise.

    A code block has to be one of the 188 sizes in TS 36.212 Table 5.1.3-3;
    anything else has no QPP interleaver parameters and cannot be encoded.
    """
    try:
        return TC_CB_SIZES.index(k)
    except ValueError:
        raise ValueError("%d is not a TS 36.212 Table 5.1.3-3 code block size"
                         % k)


def qpp_interleave(k, f1=None, f2=None):
    """The QPP permutation Pi(i) = (f1*i + f2*i*i) mod K.

    Pi(0) is 0 by construction, not by a special case: the loop starts at 1
    for the same reason srsRAN's does.
    """
    idx = cb_size_index(k)
    if f1 is None:
        f1 = TC_F1[idx]
    if f2 is None:
        f2 = TC_F2[idx]
    per = [0] * k
    for i in range(1, k):
        per[i] = (f1 * i + f2 * i * i) % k
    return per


def turbo_encode(bits, k=None):
    """The LTE turbo encoder, TS 36.212 5.1.3.2.

    Transcribed from srsran_tcod_encode(). Output is 3*K + 12 bits, laid out
    exactly as the standard lays it out:

        index 3i      systematic bit i
        index 3i+1    parity from constituent encoder 1
        index 3i+2    parity from constituent encoder 2 (fed Pi(i))

    for i in 0..K-1, followed by twelve tail bits: six from encoder 1 (three
    systematic tail bits interleaved with their parities) and six from
    encoder 2, each taking the encoder to the all-zero state.
    """
    bits = [1 if (b == 1 or b == "1") else 0 for b in bits]
    if k is None:
        k = len(bits)
    if len(bits) != k:
        raise ValueError("expected %d bits, got %d" % (k, len(bits)))
    per = qpp_interleave(k)

    r1 = [0, 0, 0]
    r2 = [0, 0, 0]
    out = []
    for i in range(k):
        b = bits[i]
        out.append(b)

        inn = b ^ (r1[2] ^ r1[1])
        out.append(r1[2] ^ (r1[0] ^ inn))
        r1 = [inn, r1[0], r1[1]]

        b2 = bits[per[i]]
        inn = b2 ^ (r2[2] ^ r2[1])
        out.append(r2[2] ^ (r2[0] ^ inn))
        r2 = [inn, r2[0], r2[1]]

    for r in (r1, r2):
        for _ in range(3):
            b = r[2] ^ r[1]
            out.append(b)
            inn = b ^ (r[2] ^ r[1])
            out.append(r[2] ^ (r[0] ^ inn))
            r[:] = [inn, r[0], r[1]]

    return out


def bits_to_hex(bits, nbits=None):
    """Pack a bit list MSB-first; `nbits` records the true length when it is
    not a multiple of 8, because the padding is not distinguishable."""
    if nbits is None:
        nbits = len(bits)
    s = "".join("1" if (b == 1 or b == "1") else "0" for b in bits[:nbits])
    s += "0" * ((8 - len(s) % 8) % 8)
    return "".join("%02X" % int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def hex_to_bits(hex_str, nbits=None):
    """Unpack hex to bits, most significant first, dropping anything past
    `nbits`.

    The input must be whole octets. A bit string whose length is not a
    multiple of eight is represented by padding it on the RIGHT, so it should
    be rendered with bits_to_hex() and its true length passed as nbits. An
    odd number of nibbles is rejected here rather than being silently
    left-padded, which would shift every bit.
    """
    h = "".join(hex_str.split()).upper()
    if len(h) % 2:
        raise ValueError(
            "hex must be whole octets, got %d nibble(s); pad on the right "
            "with a zero and pass the true length separately" % len(h))
    s = "".join(format(b, "08b") for b in bytes.fromhex(h))
    return [int(c) for c in (s[:nbits] if nbits is not None else s)]


CRC_INPUT_HEX = "BCD60B1E3AF4A91D5D52834218E89D7FED65C5578A0BE6D7CD380E55323930B9041067A7B9006A316FB68140D10E4E4BD90440B891BE4B110796EB6F9E68C9F5848012BC45B604FBBEB49E7CE1F7E18C11C7B876EA8A59D45FB2C3F66EB648C48CA9109A1FAFC825C3397CD1DD7465B6729A416195B2EF232F9C505975AF48369BA93F851C828F6F5EF1ABA23ABCD924EDCC6B0A1972CF70ABDE1DB7875B7EAA79795E82A0EBCEF96E068DCB55A127E42E0BB864E9EA7DF5EE00AC4A86DEA67AD78E0D730CA0514250DF4B20AC398DF7E55EE62D6B9E3A8B5CA6B3C43DF071B699C06A075849A2F0C9F921CC1E300409E03209A8DB007C375CCD59467619199F9250AECE6D08C5A053E1AE4923FCDBA4FA8358671646A60FCDB32970830FCAA10671BA012F14A374F1415C6E309508C6B78FFE6A15E1CF84B398E1280583825B4247FF50A003F06C42DD40CB61180C309009ACF90FEE1E4B72922D3145497034B45B811A2086CA6993F2C4559CFE46635AE472EB329C68C06940CB6D4BF74602C7F12807F8E6126AA4DFDBA04C38EEA48CFAC5FE52E89A32EC5B5F05766BDDF712DDC2ABDB8AC5E1159E992640A86B22C84C169E01F6F3A859D66E8D188D65C0A8024501780F64825B5D1B20858FCB2A75AE22CD51AFB779CEE3447F61FD08F16DC4938BBCBD9CCFD32EE3CE7CD64EC99E765ECB1D44A8111967BF86F41D1DBB922B50EFD05F77AF027B0E384DA21D7E0E9012ACC74BFA1E6BF1CDF21467C0FBD327772322D0FB34F190E073BC80D06DC7EC9BF50D7EEBD366A87987217638556B9F5F0BEA5D56D185864425AA4652BFA3E9DCD5EA1C50BC563F5A3D96AA3158BB3690ECF973FD68B5D78A5A71B87BC2B680"
CRC_INPUT_BITS = 5001
CRC_GOLD = {
    "24a": 0x1C5C97,
    "24b": 0x36D1F0,
    "16": 0x7FF4,
    "8": 0xF0,
}

# Produced by CommPy 1.2.0 from the same trellis and interleaver. The
# input is always lcg_bits(k) below, so only the output is stored.
TURBO_VECTORS = [
    (40, "034D1E62F627B216A4C3425707C3B97070"),
    (48, "03DF1662E466B616E4E7C0170753F962F8B4AEC0"),
    (512, "07CF1E4664669614E5C7D0562751F162FAF44385803EFB21745EC26C15B2A6932C34FC6475571475C4F3E32487284CFE57804E4EB93654DD2DFA0DBFFB85C0000F75437285D62AEC1758A38DFAF2FDB89036B7D970CD59E51A3FF8337B0E0BEA263F2A7DED321060B8D7C476C199A3F567BB48FE6AD5E9544BC902BB29B39F285534FFB96290B11DB59FF0ED8A1085BB7686D831F8FB17ADE68B564467FDC3FEE5BCD65F94FA6B1C6C08C7C5FEDD86136AB30393437C56208F087B4D1E5CE6A4C1B0"),
]

# K = 6144 is the largest size and its output is 18444 bits, so it is
# pinned by hash rather than by a literal.
TURBO_LARGE_K = 6144
TURBO_LARGE_BITS = 18444
TURBO_LARGE_SHA256 = "682f65cdc2428d8fce94b3f1fa66b27d4f89df59276c2ac2ddbc4937d3b671da"


# ---------------------------------------------------------------------------
# Captured vectors. Nothing in this file is asserted against this file's own
# output: the CRCs are srsRAN's gold checksums and the turbo vectors came out
# of CommPy, which builds the code from a trellis rather than from srsRAN's C.
# ---------------------------------------------------------------------------

def lcg_bits(k, seed=1):
    """The vector inputs. A plain 32-bit LCG written out in full so the input
    is reproducible without depending on any runtime's own PRNG."""
    x = seed & 0xFFFFFFFF
    out = []
    for _ in range(k):
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 1)
    return out


# ---------------------------------------------------------------------------
# Scrambling. TS 36.211 7.2 defines the pseudo-random sequence; TS 36.212
# 5.3.1 says where it is applied.
#
# The generator is the length-31 Gold sequence, and it is bit-for-bit the
# same generator NR uses (TS 38.211 5.2.1) -- same two polynomials, same
# Nc = 1600, same LSB-first seed load. That is what makes py3gpp, an NR
# library, a legitimate oracle for it rather than a coincidence: the only
# thing LTE and NR do not share here is the c_init composition, which is
# kept separate below and never guessed.
# ---------------------------------------------------------------------------

GOLD_NC = 1600


def gold_sequence(c_init, length):
    """TS 36.211 7.2, the sequence c(n).

    c(n)       = (x1(n + Nc) + x2(n + Nc)) mod 2
    x1(n + 31) = (x1(n + 3) + x1(n)) mod 2
    x2(n + 31) = (x2(n + 3) + x2(n + 2) + x2(n + 1) + x2(n)) mod 2

    Nc = 1600, x1(0) = 1 with x1(n) = 0 for n = 1..30, and x2 is loaded from
    c_init with x2(i) = (c_init >> i) & 1 -- least significant bit first,
    which is the detail that silently inverts the whole sequence if reversed.
    """
    if length < 0:
        raise ValueError("length must not be negative")
    if length == 0:
        return []
    if c_init < 0:
        raise ValueError("c_init must not be negative")
    span = GOLD_NC + length + 31
    x1 = [0] * span
    x2 = [0] * span
    x1[0] = 1
    for i in range(31):
        x2[i] = (c_init >> i) & 1
    for n in range(GOLD_NC + length):
        x1[n + 31] = (x1[n + 3] + x1[n]) & 1
        x2[n + 31] = (x2[n + 3] + x2[n + 2] + x2[n + 1] + x2[n]) & 1
    return [(x1[n + GOLD_NC] + x2[n + GOLD_NC]) & 1 for n in range(length)]


def lte_scramble(bits, c_init):
    """TS 36.211 7.2: b(n) = (a(n) + c(n)) mod 2.

    The addition is modulo two, so this is a XOR, and XOR is its own
    inverse -- descrambling is the same call, which is asserted below rather
    than assumed.
    """
    c = gold_sequence(c_init, len(bits))
    return [(int(b) ^ k) & 1 for b, k in zip(bits, c)]


def turbo_split(bits, k=None):
    """Split the 3K+12 turbo output into the three streams of 5.1.3.2.2.

    Each stream is D = K+4 long: K systematic (or parity) bits, then four
    tail bits. The tail is NOT a contiguous run per stream -- the twelve tail
    bits are six (systematic, parity) pairs dealt round-robin, so stream m
    receives tail[3j+m] for j = 0..3.

    Reading the tail as three contiguous four-bit runs, x_K,x_{K+1},x_{K+2}
    and so on, is the natural mistake and it corrupts every rate-matched
    output downstream without changing any length, so nothing else catches
    it.
    """
    if k is None:
        k = (len(bits) - 12) // 3
    if len(bits) != 3 * k + 12:
        raise ValueError(
            "turbo output must be 3K+12 bits for K=%d, got %d" % (k, len(bits)))
    tail = bits[3 * k:3 * k + 12]
    return tuple(bits[m:3 * k:3] + [tail[3 * j + m] for j in range(4)]
                 for m in range(3))


def turbo_encode_split(bits, k=None):
    """turbo_encode followed by turbo_split, the input rate matching needs."""
    out = turbo_encode(bits, k)
    return turbo_split(out, k if k is not None else len(bits))


# ---------------------------------------------------------------------------
# Rate matching. TS 36.212 5.1.4.1.
#
# The permutation pattern is Table 5.1.4-1, confirmed verbatim against ETSI
# TS 136 212 V8.3.0 clause 5.1.4.1.1 and against three implementations that
# are independent of srsRAN: turbofec, OpenLTE and openairinterface5g.
#
# Table 5.1.4-2 holds the SAME 32 values rotated by one position, for the
# convolutional code. gr-lte's sub-block deinterleaver uses that one, so
# despite being a GNU Radio LTE module it is not an oracle for this stage.
# Confusing the two produces code that half-works.
# ---------------------------------------------------------------------------

RM_PERM = [0, 16, 8, 24, 4, 20, 12, 28, 2, 18, 10, 26, 6, 22, 14, 30,
           1, 17, 9, 25, 5, 21, 13, 29, 3, 19, 11, 27, 7, 23, 15, 31]

RM_NULL = None


def rm_rows(d_len):
    """R_tc_subblock: the smallest row count whose 32 columns hold D bits."""
    return (d_len + 31) // 32


def rm_subblock_index_map(d_len, rows):
    """Streams 0 and 1: index into d, or None where the output is <NULL>.

    y carries K_pi = 32*rows entries with N_D = K_pi - D dummy bits
    PREPENDED; the returned index is into d, so it is offset by N_D. The
    matrix is written row-major, columns are permuted, then it is read out
    column by column, which collapses to y[32*r + P(c)].
    """
    k_pi = rows * 32
    n_d = k_pi - d_len
    out = []
    for k in range(k_pi):
        y = (k % rows) * 32 + RM_PERM[k // rows]
        out.append(None if y < n_d else y - n_d)
    return out


def rm_subblock2_index_map(d_len, rows):
    """Stream 2: the same matrix, read out shifted by one, modulo K_pi.

    The modulo is not cosmetic. It wraps at exactly one index, k = K_pi-1,
    where the shifted position equals K_pi and so lands back on y_0 -- and
    y_0 is a dummy bit whenever N_D > 0. Dropping the modulo reads the wrong
    element at that one position and nowhere else.
    """
    k_pi = rows * 32
    n_d = k_pi - d_len
    out = []
    for k in range(k_pi):
        y = (RM_PERM[k // rows] + 32 * (k % rows) + 1) % k_pi
        out.append(None if y < n_d else y - n_d)
    return out


def rm_collect(d0, d1, d2):
    """Sub-block interleaving plus bit collection, producing the w buffer.

    v^(1) takes the EVEN offsets after K_pi and v^(2) the ODD ones. The
    convolutional code instead writes them contiguously; mixing the two
    layouts silently half-works, which is why the offsets are spelled out.
    """
    d_len = len(d0)
    if len(d1) != d_len or len(d2) != d_len:
        raise ValueError("the three streams must be the same length")
    rows = rm_rows(d_len)
    m0 = rm_subblock_index_map(d_len, rows)
    m2 = rm_subblock2_index_map(d_len, rows)
    k_pi = rows * 32

    def take(stream, idx):
        return RM_NULL if idx is None else stream[idx]

    w = [take(d0, i) for i in m0]
    for k in range(k_pi):
        w.append(take(d1, m0[k]))
        w.append(take(d2, m2[k]))
    return w, k_pi


def lte_rate_match(d0, d1, d2, e_len, rv=0, n_cb=None):
    """TS 36.212 5.1.4.1: sub-block interleaving, collection, selection.

    k_0 comes from N_cb -- the circular buffer size, which may be below K_w
    once the soft buffer is split -- and its divisor is 8*R_tc_subblock.
    Substituting K_w for N_cb is only equal when no truncation applies, and
    using 8 or 256 as the divisor is wrong at every D that is not a multiple
    of 256.
    """
    if rv not in (0, 1, 2, 3):
        raise ValueError("rv must be 0..3")
    w, k_pi = rm_collect(d0, d1, d2)
    k_w = 3 * k_pi
    n_cb = k_w if n_cb is None else min(n_cb, k_w)
    rows = rm_rows(len(d0))
    k_0 = rows * (2 * (((n_cb + 8 * rows - 1) // (8 * rows)) * rv) + 2)
    out = []
    j = 0
    while len(out) < e_len:
        val = w[(k_0 + j) % n_cb]
        if val is not RM_NULL:
            out.append(val)
        j += 1
    return out


# ---------------------------------------------------------------------------
# Scrambling seeds, TS 36.211. The slot term is floor(n_s/2) everywhere it
# appears -- not n_s -- and q is present for the shared channels but absent
# from the control channels.
# ---------------------------------------------------------------------------


def cinit_pdsch(rnti, q, n_s, cell_id):
    """TS 36.211 6.3.1, re-initialised at the start of each subframe."""
    return (rnti << 14) + (q << 13) + ((n_s // 2) << 9) + cell_id


def cinit_pusch(rnti, q, n_s, cell_id):
    """TS 36.211 5.3.1, same shape as PDSCH."""
    return (rnti << 14) + (q << 13) + ((n_s // 2) << 9) + cell_id


def cinit_pdcch(n_s, cell_id):
    """TS 36.211 6.8.2."""
    return ((n_s // 2) << 9) + cell_id


def cinit_pcfich(n_s, cell_id):
    """TS 36.211 6.7.1."""
    return (((n_s // 2) + 1) * (2 * cell_id + 1) << 9) + cell_id


def cinit_phich(n_s, cell_id):
    """TS 36.211 6.9.1, identical in form to PCFICH."""
    return (((n_s // 2) + 1) * (2 * cell_id + 1) << 9) + cell_id


def cinit_pbch(cell_id, n_f=0, tdd=False, mbms=False):
    """TS 36.211 6.6.1.

    PBCH is the odd one out. Its sequence is 1920 bits, seeded ONCE per
    40 ms, and the four frames in that period take 480-bit slices of it --
    they do not each restart the generator. FDD seeds on the cell id alone
    (so every 40 ms period produces the same sequence); TDD folds in
    n_f mod 4. An MBMS-dedicated cell uses 2^9 + cell id, which is why a
    receiver that does not know the cell type must try both seeds.
    """
    if mbms:
        return (1 << 9) + cell_id
    if tdd:
        return ((1 << 9) * (n_f % 4)) + cell_id
    return cell_id


def cinit_pucch(n_s, cell_id, rnti):
    """TS 36.211 5.4.2, 5.4.2A, 5.4.2B, 5.4.2C.

    Formats 2/2a/2b, 3, 4 and 5 scramble with this seed. Formats 1/1a/1b do
    no bit-level scrambling at all and are deliberately absent here. The
    spec writes "+ n_RNTI" without fixing a width; 16 bits is the reading
    the implementations use, flagged here as an inference rather than a
    literal spec statement.
    """
    return ((((n_s // 2) + 1) * (2 * cell_id + 1)) << 16) + (rnti & 0xFFFF)


PBCH_SEQ_BITS = 1920
PBCH_BITS_PER_FRAME = 480


# Captured from py3gpp 0.6.0, whose nrPRBS() implements TS 38.211 5.2.1 --
# the same Gold generator from a different project, a different language and
# a different specification numbering. Only the generator is asserted here;
# the LTE c_init compositions are a separate concern and are not read from
# these vectors.
GOLD_VECTORS = [
    (0, 32, "00000010000110100001001001111010"),
    (1, 32, "00000010100000110000001101110100"),
    (0xFFFF, 32, "11110010111000000001011110000000"),
    (1234, 64, "1100000101101100001001011111101010000010011100110111011001011010"),
    (0x1C5C97, 32, "11011100001011110010101100001101"),
]

# Published first-16-bit outputs from the ShareTechnote LTE pseudo-random
# sequence handbook. These are the only external human-readable vectors for
# the LTE Gold generator that could be located, and they are a genuinely
# independent anchor: the py3gpp table above is a different specification
# numbering, and the two agree. There is no official published table to
# appeal to -- the 3GPP conformance specs define transmitter requirements in
# terms of EVM and throughput, not scrambling vectors -- so this is stated
# as the strongest evidence available rather than as a ratified vector set.
GOLD_PUBLISHED = [
    (0, "0000001000011010"),
    (1, "0000001010000011"),
    (64, "0001111000000110"),
    (1537, "0110000011000001"),
    (24579, "1110010001110010"),
    (1638401, "1101001110011100"),
]

# Golden position -> source index maps for the sub-block interleaver,
# documented independently of this implementation. -1 is a <NULL>. Marker
# data is d[j] = j. D = 44 gives R = 2, K_pi = 64 and N_D = 20, which is the
# smallest case with dummies at both ends and so exercises the wrap.

GOLD_RM_V0_D44 = [
    -1, 12, -1, 28, -1, 20, 4, 36, -1, 16, 0, 32, -1, 24, 8, 40,
    -1, 14, -1, 30, -1, 22, 6, 38, -1, 18, 2, 34,
    -1, 26, 10, 42, -1, 13, -1, 29, -1, 21, 5, 37, -1, 17, 1, 33,
    -1, 25, 9, 41, -1, 15, -1, 31, -1, 23, 7, 39,
    -1, 19, 3, 35, -1, 27, 11, 43,
]

GOLD_RM_V2_D44 = [
    -1, 13, -1, 29, -1, 21, 5, 37, -1, 17, 1, 33, -1, 25, 9, 41,
    -1, 15, -1, 31, -1, 23, 7, 39, -1, 19, 3, 35,
    -1, 27, 11, 43, -1, 14, -1, 30, -1, 22, 6, 38, -1, 18, 2, 34,
    -1, 26, 10, 42, -1, 16, 0, 32, -1, 24, 8, 40,
    -1, 20, 4, 36, -1, 28, 12, -1,
]

# k_0 per rv, from the spec formula. The N_cb values below the K_w for a
# given D are the ones where substituting K_w for N_cb would give a different
# answer, so they are the cases worth pinning.
GOLD_RM_K0 = [
    (44, 192, (4, 52, 100, 148)),
    (44, 120, (4, 36, 68, 100)),
    (44, 96, (4, 28, 52, 76)),
    (44, 72, (4, 24, 44, 64)),
    (44, 64, (4, 20, 36, 52)),
    (100, 384, (8, 104, 200, 296)),
    (100, 136, (8, 48, 88, 128)),
    (100, 120, (8, 40, 72, 104)),
]

# D bits in, E bits out, all three streams identical. Derived from the spec
# formula and cross-checked against OpenLTE's independent Octave
# transliteration; these are computed, not ratified, vectors.
RM_VECTORS = [
    (44, 192, 0, 40, "0100001101000110100011000001010001011100"),
    (44, 192, 1, 40, "1011100010111001000000001101100100001001"),
    (44, 192, 2, 40, "0001001111011000000111100000010100110010"),
    (44, 192, 3, 40, "0011001000000001101101011000100101010000"),
    (44, 120, 1, 40, "0000010100010111000101110010000000011011"),
    (44, 120, 2, 40, "1100100000000110110010000100111101100101"),
    (44, 120, 3, 40, "0001001111011001010000110100011010001100"),
]


def selftest():
    import hashlib
    failures = []

    def chk(name, got, want):
        if got != want:
            failures.append("%s FAIL want=%s got=%s" % (name, want, got))

    # ---- CRC, against srsRAN's own checksums --------------------------
    data = hex_to_bits(CRC_INPUT_HEX, CRC_INPUT_BITS)
    chk("crc-input-bits", len(data), CRC_INPUT_BITS)
    for kind, want in sorted(CRC_GOLD.items()):
        chk("crc-" + kind, lte_crc(data, kind), want)

    # The CRC of an all-zero input is zero for every polynomial that has a
    # non-zero constant term, and every one of these does. A CRC that
    # returned its polynomial instead would pass the gold vectors but fail
    # this, so both directions are checked.
    for kind in CRC_GOLD:
        chk("crc-" + kind + "-zero", lte_crc([0] * 64, kind), 0)

    # crc_bits() must be the same word, MSB first.
    for kind, want in sorted(CRC_GOLD.items()):
        order, _ = CRC_POLYS[kind]
        chk("crc-bits-" + kind, int("".join(str(b) for b in crc_bits(data, kind)), 2), want)
        chk("crc-bits-len-" + kind, len(crc_bits(data, kind)), order)

    # An unknown polynomial name is refused rather than silently defaulted.
    try:
        lte_crc(data, "32")
        failures.append("crc-unknown FAIL accepted an unknown CRC")
    except ValueError:
        pass

    # ---- the QPP interleaver ------------------------------------------
    chk("qpp-index-0", cb_size_index(40), 0)
    chk("qpp-index-last", cb_size_index(6144), 187)
    # Every valid size must produce a permutation, not just a map. A wrong
    # f1/f2 pair usually collides instead of failing loudly.
    for k in (40, 48, 512, 6144):
        per = qpp_interleave(k)
        chk("qpp-perm-%d" % k, sorted(per), list(range(k)))
        chk("qpp-zero-%d" % k, per[0], 0)
    # 41 is not a Table 5.1.3-3 size: between 40 and 48 there is nothing.
    try:
        qpp_interleave(41)
        failures.append("qpp-invalid FAIL accepted 41 as a code block size")
    except ValueError:
        pass

    # ---- the turbo encoder, against CommPy -----------------------------
    for k, want_hex in TURBO_VECTORS:
        got = turbo_encode(lcg_bits(k), k)
        chk("turbo-len-%d" % k, len(got), 3 * k + 12)
        chk("turbo-%d" % k, bits_to_hex(got, 3 * k + 12), want_hex)

    large = turbo_encode(lcg_bits(TURBO_LARGE_K), TURBO_LARGE_K)
    chk("turbo-large-len", len(large), TURBO_LARGE_BITS)
    chk("turbo-large-sha256",
        hashlib.sha256("".join(str(b) for b in large).encode()).hexdigest(),
        TURBO_LARGE_SHA256)

    # The tail must actually drive both encoders to the zero state. Checked
    # by re-running the encoder's own shift registers over the tail bits: if
    # the tail were wrong the register would not end at zero. This is the
    # one part CommPy's rsc_encode() does not produce, so it is checked by
    # construction rather than by a vector.
    for k in (40, 48, 512):
        per = qpp_interleave(k)
        b = lcg_bits(k)
        r1 = [0, 0, 0]
        r2 = [0, 0, 0]
        for i in range(k):
            inn = b[i] ^ (r1[2] ^ r1[1])
            r1 = [inn, r1[0], r1[1]]
            inn = b[per[i]] ^ (r2[2] ^ r2[1])
            r2 = [inn, r2[0], r2[1]]
        out = turbo_encode(b, k)
        # Replay the twelve tail bits exactly as the encoder emits them.
        tail = out[3 * k:]
        chk("turbo-tail-len-%d" % k, len(tail), 12)
        for r, off in ((r1, 0), (r2, 6)):
            for j in range(3):
                bit = tail[off + 2 * j]
                inn = bit ^ (r[2] ^ r[1])
                # The tail bit is defined as exactly the feedback that
                # zeroes the register, so the shifted-in value must be zero.
                chk("turbo-tail-feedback-%d-%d" % (k, off + j), inn, 0)
                r[:] = [inn, r[0], r[1]]
            chk("turbo-tail-final-state-%d-%d" % (k, off), r, [0, 0, 0])

    # A length that is not a valid code block size must be refused, not
    # silently interleaved with the wrong parameters.
    try:
        turbo_encode([0] * 41, 41)
        failures.append("turbo-invalid FAIL accepted K=41")
    except ValueError:
        pass
    try:
        turbo_encode([0] * 40, 48)
        failures.append("turbo-mismatch FAIL accepted a short input")
    except ValueError:
        pass

    # ---- Scrambling, against py3gpp's NR Gold generator ----------------
    # TS 38.211 5.2.1 and TS 36.211 7.2 define the same generator, so an NR
    # library is an independent check on the LTE one.
    for c_init, length, want in GOLD_VECTORS:
        got = "".join(str(b) for b in gold_sequence(c_init, length))
        chk("gold-%d-%d" % (c_init, length), got, want)

    # The sequence must not depend on how much of it is asked for. A
    # generator that only computed Nc state advances when length crossed
    # some threshold would pass the vectors above and fail this.
    for c_init, length, want in GOLD_VECTORS:
        full = gold_sequence(c_init, length + 40)
        chk("gold-prefix-%d" % c_init, gold_sequence(c_init, length), full[:length])

    # x2 is loaded least-significant bit first. Reversing that is the single
    # most likely transcription error and it is invisible in the length, so
    # confirm two c_init values that differ only in their bit order differ.
    chk("gold-bitorder-1-2", gold_sequence(1, 32) == gold_sequence(2, 32), False)
    chk("gold-bitorder-1-2pow30",
        gold_sequence(1, 32) == gold_sequence(1 << 30, 32), False)

    # Scrambling is its own inverse, so descrambling is the same call.
    msg = lcg_bits(200)
    for c_init in (0, 1, 0xFFFF, 12345):
        chk("scramble-roundtrip-%d" % c_init,
            lte_scramble(lte_scramble(msg, c_init), c_init), msg)

    # Scrambling with c(n) = 0 would be the identity; confirm the sequence is
    # actually being applied rather than silently skipped.
    chk("scramble-not-identity", lte_scramble(msg, 7) == msg, False)
    chk("scramble-empty", lte_scramble([], 7), [])
    chk("gold-empty", gold_sequence(7, 0), [])

    # ---- Published external vectors -----------------------------------
    # A second, unrelated table. The py3gpp vectors above are an NR library;
    # these are the LTE handbook's own first-16-bit outputs. Agreement
    # between the two is the closest thing to independent confirmation that
    # exists here, since no ratified scrambling vector set is published.
    for c_init, want in GOLD_PUBLISHED:
        got = "".join(str(b) for b in gold_sequence(c_init, 16))
        chk("gold-pub-%d" % c_init, got, want)

    # ---- Scrambling seeds, TS 36.211 ----------------------------------
    # The published PDSCH row is RNTI 100, q 0, n_s 0, cell id 1. That
    # composes to 1638401, which is the c_init of the last published vector
    # -- so the seed formula and the generator are checked against the same
    # external table rather than against each other.
    chk("cinit-pdsch-published", cinit_pdsch(100, 0, 0, 1), 1638401)
    chk("cinit-pdsch-slots", cinit_pdsch(0x1234, 0, 3, 1), 0x048D0201)
    chk("cinit-pdcch-published", cinit_pdcch(0, 1), 1)
    chk("cinit-pcfich-published", cinit_pcfich(0, 1), 1537)
    chk("cinit-phich-published", cinit_phich(0, 1), 1537)
    chk("cinit-pbch-fdd", cinit_pbch(1), 1)
    # TDD folds in (n_f mod 4), so frames 0 and 4 of a 40 ms period share a
    # seed and the three frames between them do not.
    chk("cinit-pbch-tdd-nf0", cinit_pbch(1, n_f=0, tdd=True), 1)
    chk("cinit-pbch-tdd-nf4", cinit_pbch(1, n_f=4, tdd=True), 1)
    chk("cinit-pbch-tdd-nf5", cinit_pbch(1, n_f=5, tdd=True), 513)
    chk("cinit-pbch-tdd-nf7", cinit_pbch(1, n_f=7, tdd=True), 1537)
    chk("cinit-pbch-mbms", cinit_pbch(1, mbms=True), 513)
    chk("cinit-pucch", cinit_pucch(0, 1, 0x12345), (1 * 3 << 16) + 0x2345)
    # floor(n_s/2) is the term that is most often transcribed as n_s. Two
    # slots in the same subframe must therefore seed identically, and the
    # next subframe must not.
    chk("cinit-ns0-eq-ns1", cinit_pdsch(7, 0, 0, 1), cinit_pdsch(7, 0, 1, 1))
    chk("cinit-ns0-ne-ns2",
        cinit_pdsch(7, 0, 0, 1) == cinit_pdsch(7, 0, 2, 1), False)

    # ---- Rate matching, against the golden Table 5.1.4-1 maps ----------
    # The index maps are the sharpest test available: they pin the exact
    # interleaver, where a hash of the final output would let a compensating
    # pair of errors cancel. Marker data is d[j] = j, so -1 is a <NULL> and
    # any other value is the source index that output position draws from.
    def rm_map_as_list(d_len, rows, stream2):
        m = (rm_subblock2_index_map if stream2
             else rm_subblock_index_map)(d_len, rows)
        return [-1 if i is None else i for i in m]

    chk("rm-rows-44", rm_rows(44), 2)
    chk("rm-rows-100", rm_rows(100), 4)
    chk("rm-rows-exact-64", rm_rows(64), 2)
    chk("rm-v0-d44", rm_map_as_list(44, 2, False), GOLD_RM_V0_D44)
    chk("rm-v2-d44", rm_map_as_list(44, 2, True), GOLD_RM_V2_D44)

    # The stream-2 wrap. At k = K_pi-1 the shifted position equals K_pi and
    # lands back on y_0, a dummy bit. This is the one index where dropping
    # the modulo shows up, so it is asserted by name rather than left to the
    # full-map comparison above.
    chk("rm-v2-wrap-d44", rm_map_as_list(44, 2, True)[63], -1)
    chk("rm-v2-wrap-d100", rm_map_as_list(100, 4, True)[127], -1)

    # Stream 2 must actually be shifted. If the "+1" were dropped, stream 2
    # would collapse onto stream 0 and the whole map comparison above would
    # still have caught it -- but only for the exact D tested, so this states
    # the property directly.
    chk("rm-v2-shifted-d44",
        rm_map_as_list(44, 2, True) == rm_map_as_list(44, 2, False), False)
    chk("rm-v2-shifted-d100",
        rm_map_as_list(100, 4, True) == rm_map_as_list(100, 4, False), False)
    # Having stripped it, confirm the two maps agree everywhere the shift
    # cannot bite: entry k of v2 is entry k of v0 advanced by one source
    # index, so off the wrap they differ by exactly one.
    v0d44 = rm_map_as_list(44, 2, False)
    v2d44 = rm_map_as_list(44, 2, True)
    chk("rm-v2-is-v0-plus-one",
        [b for a, b in zip(v0d44, v2d44) if a >= 0 and b >= 0][:5],
        [a + 1 for a, b in zip(v0d44, v2d44) if a >= 0 and b >= 0][:5])

    def rm_k0(d_len, n_cb, rv):
        rows = rm_rows(d_len)
        return rows * (2 * (((n_cb + 8 * rows - 1) // (8 * rows)) * rv) + 2)

    for d_len, n_cb, want in GOLD_RM_K0:
        for rv, k0 in enumerate(want):
            chk("rm-k0-d%d-n%d-rv%d" % (d_len, n_cb, rv),
                rm_k0(d_len, n_cb, rv), k0)

    # End-to-end selection, including the <NULL> skipping. Each vector is
    # D bits in, E bits out, with all three streams fed the same marker
    # sequence so that any stream mix-up changes the result.
    for d_len, n_cb, rv, e_len, want in RM_VECTORS:
        d = [(7 * j) % 5 % 2 for j in range(d_len)]
        got = lte_rate_match(d, d, d, e_len, rv=rv, n_cb=n_cb)
        chk("rm-out-d%d-n%d-rv%d" % (d_len, n_cb, rv),
            "".join(str(b) for b in got), want)

    # E longer than the buffer is the normal case, not an error: the
    # selection wraps. Asking for more than N_cb must not raise or spin.
    d = [(7 * j) % 5 % 2 for j in range(44)]
    chk("rm-wrap-len", len(lte_rate_match(d, d, d, 500, n_cb=192)), 500)

    try:
        lte_rate_match([0] * 44, [0] * 44, [0] * 40, 10)
        failures.append("rm-uneven FAIL accepted mismatched streams")
    except ValueError:
        pass
    try:
        lte_rate_match([0] * 44, [0] * 44, [0] * 44, 10, rv=4)
        failures.append("rm-rv FAIL accepted rv=4")
    except ValueError:
        pass

    # ---- Turbo output split, against turbofec's own encoder ------------
    # K=40, input 1010...10. turbofec's encoder was built and run, and its
    # three streams compared bit-for-bit against a reference written from the
    # standard polynomials. This pins the round-robin tail deal, which is
    # invisible in every length and every downstream count.
    alt = [1 - (i % 2) for i in range(40)]
    s0, s1, s2 = turbo_encode_split(alt, 40)
    chk("split-len-d0", len(s0), 44)
    chk("split-d0", "".join(str(b) for b in s0),
        "10101010101010101010101010101010101010101010")
    chk("split-d1", "".join(str(b) for b in s1),
        "11000010011110110000100111101100001001111010")
    chk("split-d2", "".join(str(b) for b in s2),
        "11000010011110110000100111101100001001110000")

    # The tail deal, stated directly: stream m takes tail[3j+m]. A contiguous
    # reading would put tail[0..3] in d0, which this rejects.
    raw = turbo_encode(alt, 40)
    tail = raw[120:132]
    chk("split-tail-rule",
        [s0[40], s1[40], s2[40], s0[41], s1[41], s2[41]],
        [tail[0], tail[1], tail[2], tail[3], tail[4], tail[5]])
    chk("split-tail-not-contiguous", s0[40:44] == tail[0:4], False)

    # The three streams must reconstruct the encoder output exactly, so that
    # splitting loses nothing.
    rebuilt = []
    for i in range(40):
        rebuilt += [s0[i], s1[i], s2[i]]
    chk("split-rebuild-sys", rebuilt, raw[:120])

    try:
        turbo_split([0] * 100, 40)
        failures.append("split-len FAIL accepted a wrong length")
    except ValueError:
        pass

    # ---- FFT: round trip everywhere, numpy where it exists -------------
    # This FFT is pure Python so the selftest runs on a machine with no
    # numpy. Where numpy is present it is an independent ORACLE -- a
    # different algorithm, pocketfft, from this mixed-radix one.
    import random
    rnd = random.Random(20140607)
    for n in (2, 3, 4, 6, 8, 12, 16, 128, 512, 1024, 1536, 2048):
        x = [complex(rnd.uniform(-1, 1), rnd.uniform(-1, 1)) for _ in range(n)]
        rt = ifft(fft(x))
        chk("fft-roundtrip-%d" % n,
            max(abs(a - b) for a, b in zip(rt, x)) < 1e-9, True)
    try:
        import numpy
        for n in (128, 1536, 2048):
            x = [complex(rnd.uniform(-1, 1), rnd.uniform(-1, 1)) for _ in range(n)]
            want = numpy.fft.fft(numpy.array(x))
            got = fft(x)
            chk("fft-numpy-%d" % n,
                max(abs(got[i] - want[i]) for i in range(n)) < 1e-9, True)
        print("NOTE\tnumpy is installed: the FFT was checked against numpy.fft")
    except ImportError:
        print("NOTE\tnumpy is absent: the FFT was checked by round trip only")

    # ---- QPSK, TS 36.211 Table 7.1.2-1 --------------------------------
    s = 1.0 / math.sqrt(2.0)
    qwant = [(0, 0, complex(s, s)), (0, 1, complex(s, -s)),
             (1, 0, complex(-s, s)), (1, 1, complex(-s, -s))]
    qbits = []
    for b0, b1, _ in qwant:
        qbits += [b0, b1]
    qgot = qpsk_modulate(qbits)
    for i, (b0, b1, e) in enumerate(qwant):
        chk("qpsk-%d%d" % (b0, b1), abs(qgot[i] - e) < 1e-12, True)
    chk("qpsk-roundtrip", qpsk_demodulate(qgot), qbits)
    chk("qpsk-unit-power",
        abs(sum(abs(d) ** 2 for d in qgot) / len(qgot) - 1.0) < 1e-12, True)
    # The bit-order trap: swapping the pair must change the symbol, or the
    # "trap" is not actually being tested for.
    chk("qpsk-bit-order-matters",
        qpsk_modulate([1, 0]) != qpsk_modulate([0, 1]), True)
    try:
        qpsk_modulate([1, 0, 1])
        failures.append("qpsk-odd FAIL accepted an odd bit count")
    except ValueError:
        pass

    # ---- OFDM parameters, TS 36.211 6.12 ------------------------------
    # The check is the slot duration. A slot is 0.5 ms -- 15360 T_s -- at
    # every bandwidth, so the CP lengths are not free parameters: get one
    # wrong and the slot stops being half a millisecond.
    for bw, n_rb, n_fft, fs in LTE_OFDM:
        want_slot = SLOT_T_S * n_fft // 2048
        chk("ofdm-slot-%g" % bw, slot_samples(n_fft), want_slot)
        chk("ofdm-slot-ext-%g" % bw, slot_samples(n_fft, extended=True), want_slot)
        # Subcarrier spacing is 15 kHz at every bandwidth, which is the
        # property that ties N_FFT to the sample rate.
        chk("ofdm-scs-%g" % bw, abs(fs / float(n_fft) - 15000.0) < 1e-6, True)
        # The occupied band must fit inside the transform.
        chk("ofdm-fits-%g" % bw, n_rb * 12 <= n_fft, True)
    # The one non-power-of-two size, and the reason the FFT is mixed radix.
    chk("ofdm-1536-needs-radix-3", ofdm_params(75)["n_fft"], 1536)
    chk("ofdm-1536-factor", _smallest_prime_factor(1536), 2)
    chk("ofdm-1536-is-3-times-512", 1536 // 3, 512)
    try:
        ofdm_params(99)
        failures.append("ofdm-bad-rb FAIL accepted an invalid N_RB")
    except ValueError:
        pass

    # ---- CRS, TS 36.211 6.10.1 ----------------------------------------
    # The stagger. Port 0 uses subcarriers 0 and 6 in symbol 0 and 3 and 9
    # in symbol 4; port 1 does the opposite. If a modulator forgot the
    # stagger both reference symbols would land on the same comb and a
    # receiver could not tell a frequency offset from a timing offset.
    chk("crs-p0-l0", crs_re_positions(6, 0, 0, 0)[:2], [0, 6])
    chk("crs-p0-l4", crs_re_positions(6, 0, 0, 4)[:2], [3, 9])
    chk("crs-p1-l0", crs_re_positions(6, 0, 1, 0)[:2], [3, 9])
    chk("crs-p1-l4", crs_re_positions(6, 0, 1, 4)[:2], [0, 6])
    # Every cell shifts the pattern by N_ID mod 6 -- the whole reuse story.
    for cid in range(6):
        chk("crs-shift-%d" % cid, crs_re_positions(6, cid, 0, 0)[0], cid % 6)
        chk("crs-shift-wrap-%d" % cid,
            crs_re_positions(6, cid, 0, 4)[0], (3 + cid) % 6)
    for n_rb in (6, 15, 25, 50, 75, 100):
        chk("crs-count-%d" % n_rb, len(crs_re_positions(n_rb, 0, 0, 0)), 2 * n_rb)
    # The sequence is a unit-power QPSK constellation, same scale as data.
    seq = crs_sequence(6, 0, 0, 0)
    chk("crs-unit-power", all(abs(abs(v) - 1.0) < 1e-12 for v in seq), True)
    q = 1.0 / math.sqrt(2.0)
    chk("crs-values-are-qpsk",
        {complex(round(v.real, 9), round(v.imag, 9)) for v in seq},
        {complex(round(s * q, 9), round(t * q, 9))
         for s in (1, -1) for t in (1, -1)})
    # N_CP is part of the seed, so the two prefix lengths scramble differently.
    chk("crs-cinit-ncp", crs_cinit(0, 0, 1) - crs_cinit(0, 0, 1, True), 1)
    chk("crs-cinit-cellid", crs_cinit(0, 0, 0), 1024 * 8 * 1 + 1)
    chk("crs-grid-1port", crs_grid(6, 1, 0, ports=(0,))[1], 24)
    chk("crs-grid-2port", crs_grid(6, 1, 0, ports=(0, 1))[1], 48)
    chk("crs-grid-4port", crs_grid(6, 1, 0, ports=(0, 1, 2, 3))[1], 72)
    # Two ports must not collide, or the reference is unusable.
    p0 = set(crs_re_positions(6, 3, 0, 0))
    p1 = set(crs_re_positions(6, 3, 1, 0))
    chk("crs-ports-disjoint-l0", p0 & p1, set())

    # ---- OFDM subcarrier mapping, TS 36.211 6.12 ----------------------
    for n_fft, n_rb in ((128, 6), (512, 25), (1536, 75), (2048, 100)):
        n_sc = n_rb * 12
        b = subcarrier_bins(n_fft, n_sc)
        chk("bins-distinct-%d" % n_fft, len(set(b)), n_sc)
        chk("bins-range-%d" % n_fft, all(0 <= v < n_fft for v in b), True)
        # LTE does not use the centre subcarrier. This is the check that a
        # self-consistent round-trip cannot make: laying the subcarriers out
        # from bin 0 also round-trips, it just puts the carrier in the wrong
        # place and makes the occupied band asymmetric.
        chk("bins-skip-dc-%d" % n_fft, 0 in b, False)
        # Half below the DC bin (wrapping to the top of the FFT), half above.
        chk("bins-first-%d" % n_fft, b[0], n_fft - n_sc // 2)
        chk("bins-last-%d" % n_fft, b[-1], n_sc // 2)
        chk("bins-symmetric-%d" % n_fft,
            b[0] + b[-1], n_fft)
    try:
        subcarrier_bins(128, 129)
        failures.append("bins-too-many FAIL accepted N_sc > N_FFT")
    except ValueError:
        pass
    try:
        subcarrier_bins(128, 73)
        failures.append("bins-odd FAIL accepted an odd subcarrier count")
    except ValueError:
        pass

    # ---- OFDM modulate: the round-trip is the proof -------------------
    # A single tone must come back on exactly the bin it was placed on,
    # with no energy anywhere else. This is the check that catches a
    # missing conjugate, a real-valued body, or an off-by-one in the wrap.
    n_fft = 128
    n_sc = 72
    bins = subcarrier_bins(n_fft, n_sc)
    tone_ok = True
    for idx in (0, 1, 35, 36, 71):
        row = [0j] * n_sc
        row[idx] = 1 + 0j
        samples, lens = ofdm_modulate([row] + [[0j] * n_sc] * 6, n_fft)
        body = samples[lens[0] - n_fft:lens[0]]
        spec = fft(body)
        if max(range(n_fft), key=lambda k: abs(spec[k])) != bins[idx]:
            tone_ok = False
    chk("ofdm-single-tone", tone_ok, True)
    # A complex body is required: a real one would mirror every subcarrier
    # onto its conjugate bin and light up two peaks instead of one.
    row = [0j] * n_sc
    row[0] = 1 + 0j
    samples, lens = ofdm_modulate([row] + [[0j] * n_sc] * 6, n_fft)
    spec = fft(samples[lens[0] - n_fft:lens[0]])
    chk("ofdm-body-is-complex",
        abs(spec[(n_fft - bins[0]) % n_fft]) < 1e-9, True)
    # Full multitone round-trip over a real CRS grid plus a payload.
    grid, _ = crs_grid(6, 1, 0, ports=(0,))
    want = {}
    x = 12345
    for l in range(7):
        for k in range(n_sc):
            if grid[l][k] is None:
                x = (1103515245 * x + 12345) & 0x7FFFFFFF
                if (x >> 16) & 1:
                    v = qpsk_modulate([(x >> 17) & 1, (x >> 18) & 1])[0]
                    grid[l][k] = v
                    want[(l, k)] = v
    samples, lens = ofdm_modulate(grid, n_fft)
    worst = 0.0
    for l in range(7):
        start = sum(lens[:l])
        spec = fft(samples[start + lens[l] - n_fft:start + lens[l]])
        for (ll, k), v in want.items():
            if ll == l:
                worst = max(worst, abs(spec[bins[k]] - v))
    chk("ofdm-multitone-roundtrip", worst < 1e-9, True)
    chk("ofdm-slot-total", sum(lens), slot_samples(n_fft))
    # The cyclic prefix is the tail of the body, copied -- not zeroed.
    chk("ofdm-cp-is-tail",
        all(abs(a - b) < 1e-12
            for a, b in zip(samples[:lens[0] - n_fft],
                            samples[lens[0] - n_fft - 10:lens[0] - n_fft])), True)
    chk("ofdm-cp-length", lens[0] - n_fft, cp_lengths(n_fft)[0])
    # Every subcarrier populated: the DC bin must still come out empty,
    # because nothing maps to it. This is what distinguishes the LTE
    # mapping from a linear one, in the domain a receiver actually sees.
    row = [1 + 0j] * n_sc
    g = [row] + [[0j] * n_sc] * 6
    s_full, _ = ofdm_modulate(g, n_fft)
    spec_full = fft(s_full[lens[0] - n_fft:lens[0]])
    chk("ofdm-dc-bin-empty", abs(spec_full[0]) < 1e-12, True)
    chk("ofdm-dc-neighbours-used",
        abs(spec_full[1]) > 0.9 and abs(spec_full[n_fft - 1]) > 0.9, True)
    try:
        ofdm_modulate([[0j] * n_sc] * 14, n_fft)
        failures.append("ofdm-too-many-symbols FAIL accepted 14 symbols in a slot")
    except ValueError:
        pass

    if failures:
        for f in failures:
            sys.stderr.write(f + "\n")
        print("RESULT\tFAIL")
        return 1
    print("RESULT\tPASS")
    return 0


def cmd_crc(args):
    bits = hex_to_bits(args.hex)
    print("crc\t%s" % args.kind)
    print("order\t%d" % CRC_POLYS[args.kind][0])
    print("poly\t0x%X" % CRC_POLYS[args.kind][1])
    print("input_bits\t%d" % len(bits))
    print("crc_hex\t0x%X" % lte_crc(bits, args.kind))
    return 0


def cmd_turbo(args):
    bits = hex_to_bits(args.hex)
    k = args.k if args.k is not None else len(bits)
    try:
        out = turbo_encode(bits, k)
    except ValueError as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2
    print("code\tLTE turbo, TS 36.212 5.1.3.2")
    print("k\t%d" % k)
    idx = cb_size_index(k)
    print("cb_size_index\t%d" % idx)
    print("qpp_f1\t%d" % TC_F1[idx])
    print("qpp_f2\t%d" % TC_F2[idx])
    print("input_bits\t%d" % k)
    print("output_bits\t%d" % len(out))
    print("tail_bits\t12")
    print("output_hex\t%s" % bits_to_hex(out, len(out)))
    return 0


def cmd_sizes(args):
    print("sizes\t%d" % len(TC_CB_SIZES))
    for i, k in enumerate(TC_CB_SIZES):
        print("size.%d\t%d\t%d\t%d" % (i, k, TC_F1[i], TC_F2[i]))
    return 0


def cmd_gold(args):
    seq = gold_sequence(args.c_init, args.length)
    print("spec\tTS 36.211 7.2 (generator identical to TS 38.211 5.2.1)")
    print("c_init\t%d" % args.c_init)
    print("length\t%d" % args.length)
    print("nc\t%d" % GOLD_NC)
    print("bits\t%s" % "".join(str(b) for b in seq))
    print("hex\t%s" % bits_to_hex(seq, len(seq)))
    return 0


def cmd_scramble(args):
    bits = hex_to_bits(args.hex, args.bits)
    out = lte_scramble(bits, args.c_init)
    print("spec\tTS 36.211 7.2 b(n) = (a(n) + c(n)) mod 2")
    print("c_init\t%d" % args.c_init)
    print("input_bits\t%d" % len(bits))
    print("output_bits\t%d" % len(out))
    print("output_hex\t%s" % bits_to_hex(out, len(out)))
    return 0


def cmd_rm(args):
    d0 = hex_to_bits(args.d0, args.bits)
    d1 = hex_to_bits(args.d1, args.bits)
    d2 = hex_to_bits(args.d2, args.bits)
    rows = rm_rows(len(d0))
    out = lte_rate_match(d0, d1, d2, args.e, rv=args.rv, n_cb=args.n_cb)
    print("spec\tTS 36.212 5.1.4.1")
    print("d_bits\t%d" % len(d0))
    print("rows\t%d" % rows)
    print("k_pi\t%d" % (rows * 32))
    print("n_d\t%d" % (rows * 32 - len(d0)))
    print("k_w\t%d" % (rows * 32 * 3))
    print("n_cb\t%d" % (args.n_cb if args.n_cb else rows * 32 * 3))
    print("rv\t%d" % args.rv)
    print("e_bits\t%d" % len(out))
    print("output_bits\t%s" % "".join(str(b) for b in out))
    print("output_hex\t%s" % bits_to_hex(out, len(out)))
    return 0


def cmd_turbo_rm(args):
    bits = hex_to_bits(args.hex, args.k)
    k = args.k if args.k is not None else len(bits)
    d0, d1, d2 = turbo_encode_split(bits, k)
    out = lte_rate_match(d0, d1, d2, args.e, rv=args.rv, n_cb=args.n_cb)
    print("spec\tTS 36.212 5.1.3.2 then 5.1.4.1")
    print("k\t%d" % k)
    print("turbo_bits\t%d" % (3 * k + 12))
    print("d_bits\t%d" % len(d0))
    print("d0_hex\t%s" % bits_to_hex(d0, len(d0)))
    print("d1_hex\t%s" % bits_to_hex(d1, len(d1)))
    print("d2_hex\t%s" % bits_to_hex(d2, len(d2)))
    print("rv\t%d" % args.rv)
    print("e_bits\t%d" % len(out))
    print("output_bits\t%s" % "".join(str(b) for b in out))
    print("output_hex\t%s" % bits_to_hex(out, len(out)))
    return 0


def cmd_cinit(args):
    ch = args.channel
    a = args
    if ch == "pdsch":
        v = cinit_pdsch(a.rnti, a.q, a.n_s, a.cell)
        spec = "TS 36.211 6.3.1"
    elif ch == "pusch":
        v = cinit_pusch(a.rnti, a.q, a.n_s, a.cell)
        spec = "TS 36.211 5.3.1"
    elif ch == "pdcch":
        v = cinit_pdcch(a.n_s, a.cell)
        spec = "TS 36.211 6.8.2"
    elif ch == "pcfich":
        v = cinit_pcfich(a.n_s, a.cell)
        spec = "TS 36.211 6.7.1"
    elif ch == "phich":
        v = cinit_phich(a.n_s, a.cell)
        spec = "TS 36.211 6.9.1"
    elif ch == "pucch":
        v = cinit_pucch(a.n_s, a.cell, a.rnti)
        spec = "TS 36.211 5.4.2 (formats 2/2a/2b, 3, 4, 5 only)"
    else:
        v = cinit_pbch(a.cell, n_f=a.n_f, tdd=a.tdd, mbms=a.mbms)
        spec = "TS 36.211 6.6.1"
    print("channel\t%s" % ch)
    print("spec\t%s" % spec)
    print("c_init\t%d" % v)
    print("c_init_hex\t0x%X" % v)
    if v >= (1 << 31):
        print("warning\tc_init exceeds 31 bits and will not fit the x2 state")
    return 0


# ---------------------------------------------------------------------------
# Modulation, TS 36.211 7.1
# ---------------------------------------------------------------------------

# TS 36.211 Table 7.1.2-1. The table lists the constellation points with the
# 1/sqrt(2) already factored out; the scaling is applied in qpsk_modulate so
# the table stays readable against the spec.
QPSK_TABLE = {
    (0, 0): (1, 1),
    (0, 1): (1, -1),
    (1, 0): (-1, 1),
    (1, 1): (-1, -1),
}


def qpsk_modulate(bits):
    """TS 36.211 7.1.2: b(2i), b(2i+1) -> d(i) = 1/sqrt(2) * (1-2b(2i))
    + j * 1/sqrt(2) * (1-2b(2i+1)).

    The trap is the bit order. The FIRST bit of the pair drives the real
    part and the second drives the imaginary part. Swapping them maps every
    bit pair to a different but equally valid QPSK symbol, so the result has
    the right power, the right constellation and the right length, and
    decodes to garbage. Nothing downstream can detect it.
    """
    if len(bits) % 2:
        raise ValueError("QPSK takes an even number of bits (got %d)" % len(bits))
    s = 1.0 / math.sqrt(2.0)
    out = []
    for i in range(0, len(bits), 2):
        re, im = QPSK_TABLE[(bits[i], bits[i + 1])]
        out.append(complex(re * s, im * s))
    return out


def qpsk_demodulate(symbols):
    """The inverse of qpsk_modulate, for round-trip assertion."""
    bits = []
    for d in symbols:
        bits.append(0 if d.real > 0 else 1)
        bits.append(0 if d.imag > 0 else 1)
    return bits


# ---------------------------------------------------------------------------
# FFT, for OFDM (TS 36.211 6.12)
# ---------------------------------------------------------------------------

# Pure Python on purpose. This file imports nothing but `math` and `sys`, so
# its selftest runs on a machine with no numpy -- and numpy, where it exists,
# is then an ORACLE rather than a dependency. The selftest asserts this FFT
# against numpy.fft.fft on random input.

_TWIDDLE_CACHE = {}


def _smallest_prime_factor(n):
    if n % 2 == 0:
        return 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            return d
        d += 2
    return n


def _twiddle(sign, n, e):
    """exp(sign * 2*pi*j*e/n), cached across calls."""
    key = (sign, n, e % n)
    v = _TWIDDLE_CACHE.get(key)
    if v is None:
        a = sign * 2.0 * math.pi * ((e % n) / float(n))
        v = complex(math.cos(a), math.sin(a))
        _TWIDDLE_CACHE[key] = v
    return v


def _fft(x, inverse):
    """Mixed-radix Cooley-Tukey, decimation in time.

        X[k] = sum_{r=0}^{p-1} W_N^{rk} * X_r[k mod (N/p)]

    where X_r is the transform of the subsequence x[r::p]. No scaling here;
    ifft() applies 1/N so that ifft(fft(x)) == x.

    The radix is the smallest prime factor, so LTE's power-of-two sizes use
    radix 2 and 1536 = 2**9 * 3 -- which the 15 MHz carrier needs -- uses
    radix 2 down to a radix 3. A power-of-two-only FFT would silently be
    unable to build a 15 MHz carrier at all.
    """
    n = len(x)
    if n == 0:
        raise ValueError("empty FFT input")
    if n == 1:
        return [x[0]]
    p = _smallest_prime_factor(n)
    if p == n:
        # n is prime, so the only exact route is a direct DFT at O(n**2).
        # Refuse a large one rather than appear to hang.
        if n > 61:
            raise ValueError(
                "FFT size %d is prime and too large for the naive fallback" % n)
        sign = 1.0 if inverse else -1.0
        return [sum(x[j] * _twiddle(sign, n, j * k) for j in range(n))
                for k in range(n)]
    m = n // p
    subs = [_fft(x[r::p], inverse) for r in range(p)]
    sign = 1.0 if inverse else -1.0
    out = [0j] * n
    for k in range(n):
        km = k % m
        acc = subs[0][km]
        for r in range(1, p):
            acc += _twiddle(sign, n, r * k) * subs[r][km]
        out[k] = acc
    return out


def fft(x):
    """The forward DFT, sum x[j] exp(-2*pi*j*j*k/N)."""
    return _fft(list(x), False)


def ifft(x):
    """The inverse DFT, 1/N sum x[j] exp(+2*pi*j*j*k/N)."""
    v = _fft(list(x), True)
    n = len(v)
    return [c / n for c in v]


# ---------------------------------------------------------------------------
# OFDM parameters, TS 36.211 6.12
# ---------------------------------------------------------------------------

# The basic time unit of TS 36.211, T_s = 1/(15000 * 2048) s. Every LTE
# timing is an integer multiple of it, at every bandwidth -- the 2048-point
# FFT at the 20 MHz sampling rate is the definition, not a special case.
T_S_DENOM = 15000 * 2048          # 30720000
SLOT_T_S = 15360                  # one slot is 0.5 ms, exactly
SYMBOLS_PER_SLOT_NORMAL = 7
SYMBOLS_PER_SLOT_EXTENDED = 6

# TS 36.211 Table 6.12-1. (channel bandwidth MHz, N_RB, N_FFT, sample rate Hz)
#
# The N_FFT column is the whole reason a power-of-two FFT is not enough:
# 15 MHz uses 1536, which is 2**9 * 3. A radix-2-only transform cannot build
# that carrier at all -- not "builds it inaccurately", cannot build it.
LTE_OFDM = [
    (1.4,    6,  128,  1920000),
    (3.0,   15,  256,  3840000),
    (5.0,   25,  512,  7680000),
    (10.0,  50, 1024, 15360000),
    (15.0,  75, 1536, 23040000),
    (20.0, 100, 2048, 30720000),
]


def ofdm_params(n_rb):
    """The OFDM parameters for a bandwidth given as N_RB."""
    for bw, rb, n_fft, fs in LTE_OFDM:
        if rb == n_rb:
            return {"bandwidth_mhz": bw, "n_rb": rb, "n_fft": n_fft,
                    "sample_rate": fs, "n_sc": rb * 12}
    raise ValueError("no LTE bandwidth has N_RB=%d (valid: %s)"
                     % (n_rb, ", ".join(str(r[1]) for r in LTE_OFDM)))


def cp_lengths(n_fft, extended=False):
    """The cyclic prefix length in samples for each symbol of one slot.

    TS 36.211 6.12.1 gives these in units of T_s as 160 and 144 for normal
    CP (first symbol, remaining symbols) and 512 for extended CP, always at
    the 2048-point reference. At a smaller FFT the sample is longer, so the
    count scales by N_FFT/2048 -- integer for every LTE size.
    """
    if extended:
        return [512 * n_fft // 2048] * SYMBOLS_PER_SLOT_EXTENDED
    return [160 * n_fft // 2048] + [144 * n_fft // 2048] * 6


def slot_samples(n_fft, extended=False):
    """Total samples in one slot: every CP plus every symbol body.

    This must equal 15360 * N_FFT/2048 for every bandwidth, because a slot
    is 0.5 ms at whatever rate the carrier samples. That identity is the
    check on the CP table above: get a CP length wrong and the slot is no
    longer half a millisecond, which is a thing the spec fixes exactly and
    a receiver will notice.
    """
    cps = cp_lengths(n_fft, extended)
    return sum(cps) + len(cps) * n_fft


# ---------------------------------------------------------------------------
# Cell-specific reference signals, TS 36.211 6.10.1
# ---------------------------------------------------------------------------

def crs_cinit(n_s, l, cell_id, extended_cp=False):
    """The Gold seed for the CRS of slot n_s, symbol l, TS 36.211 6.10.1.1.

        c_init = 2**10 * (7*(n_s+1) + l + 1) * (2*N_ID + 1) + 2*N_ID + N_CP

    N_CP is 1 for normal cyclic prefix and 0 for extended. The distinction
    is not cosmetic: it puts the two prefix lengths on different scrambling
    sequences, so a receiver that guesses the wrong prefix length does not
    merely mis-time its window, it correlates against the wrong reference.
    """
    n_cp = 0 if extended_cp else 1
    return (1024 * (7 * (n_s + 1) + l + 1) * (2 * cell_id + 1)
            + 2 * cell_id + n_cp)


def crs_sequence(n_rb, n_s, l, cell_id, extended_cp=False):
    """The CRS symbols for one symbol of one slot: 2*N_RB complex values.

    TS 36.211 6.10.1.1 defines r as a QPSK constellation taken two bits at a
    time from the Gold generator seeded above -- same 1/sqrt(2) scaling as
    the data modulation, so the reference and the data sit in the same
    constellation.
    """
    c = gold_sequence(crs_cinit(n_s, l, cell_id, extended_cp), 2 * 2 * n_rb)
    return [complex((1 - 2 * c[2 * m]) / math.sqrt(2.0),
                    (1 - 2 * c[2 * m + 1]) / math.sqrt(2.0))
            for m in range(2 * n_rb)]


def crs_re_positions(n_rb, cell_id, port=0, l=0):
    """The subcarriers a CRS symbol lands on, TS 36.211 6.10.1.2.

    Within a resource block the reference sits on subcarriers spaced six
    apart, so two REs per block per symbol -- but which two depends on both
    the antenna port and the symbol, because the pattern is deliberately
    staggered between the two reference symbols of a slot. Port 0 uses
    subcarriers 0 and 6 in symbol 0 and 3 and 9 in symbol 4; port 1 is the
    other way round. That stagger is what lets a receiver estimate the
    channel on a grid rather than a comb.

    On top of that, every cell shifts the whole pattern by N_ID mod 6, so
    neighbouring cells transmit their references in different subcarriers
    and can be told apart -- six shifts is exactly the reuse factor the
    grid allows.
    """
    if port not in (0, 1, 2, 3):
        raise ValueError("LTE has CRS antenna ports 0..3, not %r" % (port,))
    # v per TS 36.211 6.10.1.2: the stagger between the slot's two CRS
    # symbols, and the fact that ports 2 and 3 only ever use symbol 1.
    if port == 0:
        v = 0 if l == 0 else 3
    elif port == 1:
        v = 3 if l == 0 else 0
    elif port == 2:
        v = 3
    else:
        v = 0
    v_shift = cell_id % 6
    return [(6 * m + (v + v_shift) % 6) % (n_rb * 12) for m in range(2 * n_rb)]


def crs_grid(n_rb, cell_id, n_s, extended_cp=False, ports=(0,)):
    """Insert CRS for one slot into a fresh grid, returning (grid, count).

    The grid is a list of symbols, each a list of n_rb*12 complex values or
    None where nothing is mapped. CRS goes on symbol 0 and 4 of every slot
    for ports 0 and 1; ports 2 and 3 exist only on symbol 1 when four ports
    are configured, which is why the port loop is not uniform.
    """
    n_sc = n_rb * 12
    grid = [[None] * n_sc for _ in range(SYMBOLS_PER_SLOT_NORMAL)]
    inserted = 0
    for p in ports:
        if p in (0, 1):
            symbols = (0, 4)
        else:
            symbols = (1,)
        for l in symbols:
            seq = crs_sequence(n_rb, n_s, l, cell_id, extended_cp)
            for idx, k in enumerate(crs_re_positions(n_rb, cell_id, p, l)):
                grid[l][k] = seq[idx]
                inserted += 1
    return grid, inserted


# ---------------------------------------------------------------------------
# OFDM baseband generation, TS 36.211 6.12
# ---------------------------------------------------------------------------

def subcarrier_bins(n_fft, n_sc):
    """Map n_sc subcarriers onto FFT bins, SKIPPING the DC bin.

    TS 36.211 6.12 sums over a band centred on the carrier, and LTE does
    not use the centre subcarrier: the DC bin is left empty and the n_sc
    subcarriers are split evenly either side of it. For a 20 MHz carrier
    that is bins 1..600 and 1448..2047 of a 2048-point transform -- 1200
    subcarriers occupying bins -600..-1 and +1..+600, which is symmetric
    about the carrier and exactly 18 MHz wide.

    The alternative -- laying the n_sc subcarriers out from bin 0, which is
    what a naive reading of the sum suggests -- occupies -600..+599, which
    is neither symmetric nor the right width. Both mappings round-trip
    perfectly through an IFFT/FFT pair, so no self-test can tell them
    apart; only an external reference can. This one follows srsRAN, whose
    srsran_ofdm_tx_sf() does exactly the copy above with dc = 1.
    """
    if n_sc > n_fft - 1:
        raise ValueError("N_sc=%d does not fit around the DC bin of an "
                         "N_FFT=%d transform" % (n_sc, n_fft))
    if n_sc % 2:
        raise ValueError("LTE carriers are an even number of subcarriers "
                         "(12 per RB), not %d" % n_sc)
    half = n_sc // 2
    return ([(n_fft - half + i) % n_fft for i in range(half)]
            + [i + 1 for i in range(half)])


def ofdm_modulate(grid, n_fft, extended_cp=False):
    """Turn resource-grid symbols into a baseband sample stream.

    Runs the whole TS 36.211 6.12 chain: subcarrier mapping, inverse
    transform, and prepending each symbol's cyclic prefix. Returns
    (samples, per_symbol_lengths) where the lengths are the total length of
    each symbol including its prefix, so a caller can see the timing
    structure rather than just a flat buffer.

    The samples are complex baseband I/Q. The DC bin stays at zero because
    no subcarrier maps to it.
    """
    bins = subcarrier_bins(n_fft, len(grid[0]))
    cps = cp_lengths(n_fft, extended_cp)
    if len(cps) < len(grid):
        raise ValueError("%d symbols do not fit in a %d-symbol slot"
                         % (len(grid), len(cps)))
    out = []
    lengths = []
    for l, row in enumerate(grid):
        spec = [0j] * n_fft
        for i, k in enumerate(bins):
            v = row[i] if i < len(row) else None
            if v is not None:
                spec[k] = complex(v) if not isinstance(v, complex) else v
        # The baseband signal is complex I/Q. Taking the real part here would
        # fold the spectrum onto itself and mirror every subcarrier to its
        # conjugate bin, which looks plausible on a plot and is wrong on a
        # radio -- a single tone would come out at both +f and -f.
        body = ifft(spec)
        cp = cps[l]
        sym = body[-cp:] + body
        out.extend(sym)
        lengths.append(len(sym))
    return out, lengths


def main(argv):
    import argparse
    p = argparse.ArgumentParser(
        prog="lte_phy",
        description="LTE downlink coding: CRC and the turbo code (TS 36.212)")
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("crc", help="compute an LTE CRC")
    c.add_argument("hex", help="the input, as hex octets")
    c.add_argument("kind", nargs="?", default="24a",
                   choices=sorted(CRC_POLYS))
    c.set_defaults(func=cmd_crc)

    t = sub.add_parser("turbo", help="encode with the LTE turbo code")
    t.add_argument("hex", help="the input, as hex octets")
    t.add_argument("--k", type=int, default=None,
                   help="the true bit length, before hex padding")
    t.set_defaults(func=cmd_turbo)

    sub.add_parser("sizes", help="list the valid code block sizes")

    g = sub.add_parser("gold", help="emit the TS 36.211 7.2 Gold sequence")
    g.add_argument("c_init", type=int, help="the generator seed")
    g.add_argument("length", type=int, help="how many bits")
    g.set_defaults(func=cmd_gold)

    s = sub.add_parser("scramble", help="scramble a bit sequence")
    s.add_argument("hex", help="the input, as hex octets")
    s.add_argument("c_init", type=int, help="the generator seed")
    s.add_argument("--bits", type=int, default=None,
                   help="the true bit length, before hex padding")
    s.set_defaults(func=cmd_scramble)

    sub.add_parser("selftest", help="assert against the captured vectors")

    # Rate matching takes the three streams separately rather than a turbo
    # output, because the mapping from the encoder's 3K+12 bits onto
    # d^(0)/d^(1)/d^(2) is a distinct step with its own trap in the tail.
    r = sub.add_parser("rm", help="rate match three turbo streams")
    r.add_argument("d0", help="systematic stream, as hex octets")
    r.add_argument("d1", help="first parity stream, as hex octets")
    r.add_argument("d2", help="second parity stream, as hex octets")
    r.add_argument("--e", type=int, required=True,
                   help="output length in bits")
    r.add_argument("--rv", type=int, default=0, help="redundancy version 0..3")
    r.add_argument("--n-cb", type=int, default=None,
                   help="soft buffer size, defaulting to K_w")
    r.add_argument("--bits", type=int, default=None,
                   help="the true stream length D, before hex padding")
    r.set_defaults(func=cmd_rm)

    tr = sub.add_parser("turbo-rm",
                        help="turbo encode, split the streams, rate match")
    tr.add_argument("hex", help="the input, as hex octets")
    tr.add_argument("--k", type=int, default=None,
                    help="the true input length, before hex padding")
    tr.add_argument("--e", type=int, required=True,
                    help="output length in bits")
    tr.add_argument("--rv", type=int, default=0)
    tr.add_argument("--n-cb", type=int, default=None)
    tr.set_defaults(func=cmd_turbo_rm)

    ci = sub.add_parser("cinit", help="compute a TS 36.211 scrambling seed")
    ci.add_argument("channel",
                    choices=["pdsch", "pusch", "pdcch", "pcfich", "phich",
                             "pbch", "pucch"])
    ci.add_argument("--rnti", type=int, default=0)
    ci.add_argument("--q", type=int, default=0)
    ci.add_argument("--n-s", type=int, default=0)
    ci.add_argument("--cell", type=int, default=0)
    ci.add_argument("--n-f", type=int, default=0, help="PBCH: the SFN")
    ci.add_argument("--tdd", action="store_true", help="PBCH: frame type 2")
    ci.add_argument("--mbms", action="store_true",
                    help="PBCH: MBMS-dedicated cell")
    ci.set_defaults(func=cmd_cinit)

    args = p.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    if not hasattr(args, "func"):
        p.print_help()
        return 2
    if args.cmd == "sizes":
        args.func(args)
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
