#!/usr/bin/env python3
"""GSM/UMTS authentication and ciphering primitives for IMSIsting.

Implements, as known-answer-tested functions:

  * COMP128-1  -- the classic GSM A3/A8 (SRES + Kc)
  * COMP128-2  -- the v2 variant (Kc's low 10 bits forced to zero)
  * COMP128-3  -- the v3 variant
  * AES-128    -- the block cipher Milenage is built on
  * Milenage   -- the TS 35.206 UMTS/GSM authentication functions
                  f1/f1*/f2/f3/f4/f5/f5*, taking OP or OPC
  * Keccak-f[1600] -- the permutation under TUAK
  * TUAK       -- the TS 35.231 Keccak-based function set, including its
                  key-length-dependent instance encoding and Keccak iteration
                  count
  * A5/1       -- the GSM cipher: the 64-bit state machine and its frame
                  keystream
  * A51Table   -- an A5/1 time-memory-tradeoff table (rainbow table) with a
                  working build-and-lookup interface
  * DPA model  -- the COMP128-1 round-0 level-0 leakage point, per-key-byte
                  Pearson correlation, and key recovery from synthetic traces,
                  proved by running COMP128-1 forward on held-out challenges

Run `--selftest` to check every one against published vectors.

HONEST LIMIT ON THE DPA MODEL. `dpa_run` synthesises its traces from the
leakage model with a seeded RNG; there is no oscilloscope, no probe and no card
in this path, so nothing here is a measurement of a real device. What it does
establish is what the attack needs: a correct leakage model and clean traces.
The `--dpa-sweep` control makes that concrete -- when the model targets the
wrong quantity, all 16 key bytes come back wrong. A masked card would break the
Hamming-weight assumption the same way, and masking is what COMP128-2/-3 do.

HONEST LIMIT ON A5/1 TMTO. `A51Table` implements the real algorithm -- chain
generation, table sort, online lookup at every column, and hit verification by
regenerating the observed keystream -- but it is exercised at a reduced index
width so a lookup can be checked exhaustively in seconds. The 2^54 table the
literature describes (Golic 1997; Nohl 2009) is a precomputed-table or cluster
job and is NOT what runs here; `--a51-tmto-demo` says so on every run.

PROVENANCE. The compression tables and the structure of the v2/v3 inner
function are ported from libosmocore's src/gsm/comp128.c and
src/gsm/comp128v23.c -- (C) 2009 Sylvain Munaut, GPL-2.0-or-later -- which are
themselves reimplementations of the leaked "Technical Information: GSM System
Security Study" (Racal Research, 10-1617-01, 1988), with the three documented
typos corrected, cross-checked against the Briceno/Goldberg/Wagner
reverse-engineering. The known-answer vectors are libosmocore's own test suite
(tests/comp128/comp128_test.c) plus the published examples from the `comp128`
PyPI package.

A5/1 is written from the published algorithm description and is pinned by the
two independent vectors already used by `modules/06_gsm_air.sh` and
`modules/20_gsm_cve.sh` -- Briceno/Goldberg/Wagner and libosmocore -- asserting
the downlink and uplink row of each, so a transposed state or a wrong clocking
order cannot pass.

The Milenage, Keccak and TUAK halves are written from the 3GPP specifications
themselves -- TS 35.206 (Milenage), TS 35.231 (TUAK) and the TS 35.208 /
TS 35.232 clauses that publish their test sets. Every vector below is a value
printed in those documents. TUAK is covered twice over: the raw 200-byte
Keccak-f[1600] input/output pairs pin the permutation and the byte-to-lane
mapping on their own, and the instance in-blocks printed in TS 35.232 clause 6
and 7 pin the key-length-dependent framing.

Inputs are checked strictly, and a wrong-length or non-hex value is an error
rather than a zero-filled result: a silently wrong SRES/Kc is worse than none.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import random
import sys

# COMP128-1 compression tables (libosmocore src/gsm/comp128.c)
COMP128_T0 = (
    102, 177, 186, 162,   2, 156, 112,  75,  55,  25,   8,  12, 251, 193, 246, 188,
    109, 213, 151,  53,  42,  79, 191, 115, 233, 242, 164, 223, 209, 148, 108, 161,
    252,  37, 244,  47,  64, 211,   6, 237, 185, 160, 139, 113,  76, 138,  59,  70,
     67,  26,  13, 157,  63, 179, 221,  30, 214,  36, 166,  69, 152, 124, 207, 116,
    247, 194,  41,  84,  71,   1,  49,  14,  95,  35, 169,  21,  96,  78, 215, 225,
    182, 243,  28,  92, 201, 118,   4,  74, 248, 128,  17,  11, 146, 132, 245,  48,
    149,  90, 120,  39,  87, 230, 106, 232, 175,  19, 126, 190, 202, 141, 137, 176,
    250,  27, 101,  40, 219, 227,  58,  20,  51, 178,  98, 216, 140,  22,  32, 121,
     61, 103, 203,  72,  29, 110,  85, 212, 180, 204, 150, 183,  15,  66, 172, 196,
     56, 197, 158,   0, 100,  45, 153,   7, 144, 222, 163, 167,  60, 135, 210, 231,
    174, 165,  38, 249, 224,  34, 220, 229, 217, 208, 241,  68, 206, 189, 125, 255,
    239,  54, 168,  89, 123, 122,  73, 145, 117, 234, 143,  99, 129, 200, 192,  82,
    104, 170, 136, 235,  93,  81, 205, 173, 236,  94, 105,  52,  46, 228, 198,   5,
     57, 254,  97, 155, 142, 133, 199, 171, 187,  50,  65, 181, 127, 107, 147, 226,
    184, 218, 131,  33,  77,  86,  31,  44,  88,  62, 238,  18,  24,  43, 154,  23,
     80, 159, 134, 111,   9, 114,   3,  91,  16, 130,  83,  10, 195, 240, 253, 119,
    177, 102, 162, 186, 156,   2,  75, 112,  25,  55,  12,   8, 193, 251, 188, 246,
    213, 109,  53, 151,  79,  42, 115, 191, 242, 233, 223, 164, 148, 209, 161, 108,
     37, 252,  47, 244, 211,  64, 237,   6, 160, 185, 113, 139, 138,  76,  70,  59,
     26,  67, 157,  13, 179,  63,  30, 221,  36, 214,  69, 166, 124, 152, 116, 207,
    194, 247,  84,  41,   1,  71,  14,  49,  35,  95,  21, 169,  78,  96, 225, 215,
    243, 182,  92,  28, 118, 201,  74,   4, 128, 248,  11,  17, 132, 146,  48, 245,
     90, 149,  39, 120, 230,  87, 232, 106,  19, 175, 190, 126, 141, 202, 176, 137,
     27, 250,  40, 101, 227, 219,  20,  58, 178,  51, 216,  98,  22, 140, 121,  32,
    103,  61,  72, 203, 110,  29, 212,  85, 204, 180, 183, 150,  66,  15, 196, 172,
    197,  56,   0, 158,  45, 100,   7, 153, 222, 144, 167, 163, 135,  60, 231, 210,
    165, 174, 249,  38,  34, 224, 229, 220, 208, 217,  68, 241, 189, 206, 255, 125,
     54, 239,  89, 168, 122, 123, 145,  73, 234, 117,  99, 143, 200, 129,  82, 192,
    170, 104, 235, 136,  81,  93, 173, 205,  94, 236,  52, 105, 228,  46,   5, 198,
    254,  57, 155,  97, 133, 142, 171, 199,  50, 187, 181,  65, 107, 127, 226, 147,
    218, 184,  33, 131,  86,  77,  44,  31,  62,  88,  18, 238,  43,  24,  23, 154,
    159,  80, 111, 134, 114,   9,  91,   3, 130,  16,  10,  83, 240, 195, 119, 253,
)
COMP128_T1 = (
     19,  11,  80, 114,  43,   1,  69,  94,  39,  18, 127, 117,  97,   3,  85,  43,
     27, 124,  70,  83,  47,  71,  63,  10,  47,  89,  79,   4,  14,  59,  11,   5,
     35, 107, 103,  68,  21,  86,  36,  91,  85, 126,  32,  50, 109,  94, 120,   6,
     53,  79,  28,  45,  99,  95,  41,  34,  88,  68,  93,  55, 110, 125, 105,  20,
     90,  80,  76,  96,  23,  60,  89,  64, 121,  56,  14,  74, 101,   8,  19,  78,
     76,  66, 104,  46, 111,  50,  32,   3,  39,   0,  58,  25,  92,  22,  18,  51,
     57,  65, 119, 116,  22, 109,   7,  86,  59,  93,  62, 110,  78,  99,  77,  67,
     12, 113,  87,  98, 102,   5,  88,  33,  38,  56,  23,   8,  75,  45,  13,  75,
     95,  63,  28,  49, 123, 120,  20, 112,  44,  30,  15,  98, 106,   2, 103,  29,
     82, 107,  42, 124,  24,  30,  41,  16, 108, 100, 117,  40,  73,  40,   7, 114,
     82, 115,  36, 112,  12, 102, 100,  84,  92,  48,  72,  97,   9,  54,  55,  74,
    113, 123,  17,  26,  53,  58,   4,   9,  69, 122,  21, 118,  42,  60,  27,  73,
    118, 125,  34,  15,  65, 115,  84,  64,  62,  81,  70,   1,  24, 111, 121,  83,
    104,  81,  49, 127,  48, 105,  31,  10,   6,  91,  87,  37,  16,  54, 116, 126,
     31,  38,  13,   0,  72, 106,  77,  61,  26,  67,  46,  29,  96,  37,  61,  52,
    101,  17,  44, 108,  71,  52,  66,  57,  33,  51,  25,  90,   2, 119, 122,  35,
)
COMP128_T2 = (
     52,  50,  44,   6,  21,  49,  41,  59,  39,  51,  25,  32,  51,  47,  52,  43,
     37,   4,  40,  34,  61,  12,  28,   4,  58,  23,   8,  15,  12,  22,   9,  18,
     55,  10,  33,  35,  50,   1,  43,   3,  57,  13,  62,  14,   7,  42,  44,  59,
     62,  57,  27,   6,   8,  31,  26,  54,  41,  22,  45,  20,  39,   3,  16,  56,
     48,   2,  21,  28,  36,  42,  60,  33,  34,  18,   0,  11,  24,  10,  17,  61,
     29,  14,  45,  26,  55,  46,  11,  17,  54,  46,   9,  24,  30,  60,  32,   0,
     20,  38,   2,  30,  58,  35,   1,  16,  56,  40,  23,  48,  13,  19,  19,  27,
     31,  53,  47,  38,  63,  15,  49,   5,  37,  53,  25,  36,  63,  29,   5,   7,
)
COMP128_T3 = (
      1,   5,  29,   6,  25,   1,  18,  23,  17,  19,   0,   9,  24,  25,   6,  31,
     28,  20,  24,  30,   4,  27,   3,  13,  15,  16,  14,  18,   4,   3,   8,   9,
     20,   0,  12,  26,  21,   8,  28,   2,  29,   2,  15,   7,  11,  22,  14,  10,
     17,  21,  12,  30,  26,  27,  16,  31,  11,   7,  13,  23,  10,   5,  22,  19,
)
COMP128_T4 = (
     15,  12,  10,   4,   1,  14,  11,   7,   5,   0,  14,   7,   1,   2,  13,   8,
     10,   3,   4,   9,   6,   0,   3,   2,   5,   6,   8,   9,  11,  13,  15,  12,
)
COMP128_TABLES = (COMP128_T0, COMP128_T1, COMP128_T2, COMP128_T3, COMP128_T4)
# COMP128-2/3 tables (libosmocore src/gsm/comp128v23.c)
V23_TABLE0 = (
    197, 235,  60, 151,  98,  96,   3, 100, 248, 118,  42, 117, 172, 211, 181, 203,
     61, 126, 156,  87, 149, 224,  55, 132, 186,  63, 238, 255,  85,  83, 152,  33,
    160, 184, 210, 219, 159,  11, 180, 194, 130, 212, 147,   5, 215,  92,  27,  46,
    113, 187,  52,  25, 185,  79, 221,  48,  70,  31, 101,  15, 195, 201,  50, 222,
    137, 233, 229, 106, 122, 183, 178, 177, 144, 207, 234, 182,  37, 254, 227, 231,
     54, 209, 133,  65, 202,  69, 237, 220, 189, 146, 120,  68,  21, 125,  38,  30,
      2, 155,  53, 196, 174, 176,  51, 246, 167,  76, 110,  20,  82, 121, 103, 112,
     56, 173,  49, 217, 252,   0, 114, 228, 123,  12,  93, 161, 253, 232, 240, 175,
     67, 128,  22, 158,  89,  18,  77, 109, 190,  17,  62,   4, 153, 163,  59, 145,
    138,   7,  74, 205,  10, 162,  80,  45, 104, 111, 150, 214, 154,  28, 191, 169,
    213,  88, 193, 198, 200, 245,  39, 164, 124,  84,  78,   1, 188, 170,  23,  86,
    226, 141,  32,   6, 131, 127, 199,  40, 135,  16,  57,  71,  91, 225, 168, 242,
    206,  97, 166,  44,  14,  90, 236, 239, 230, 244, 223, 108, 102, 119, 148, 251,
     29, 216,   8,   9, 249, 208,  24, 105,  94,  34,  64,  95, 115,  72, 134, 204,
     43, 247, 243, 218,  47,  58,  73, 107, 241, 179, 116,  66,  36, 143,  81, 250,
    139,  19,  13, 142, 140, 129, 192,  99, 171, 157, 136,  41,  75,  35, 165,  26,
)
V23_TABLE1 = (
    170,  42,  95, 141, 109,  30,  71,  89,  26, 147, 231, 205, 239, 212, 124, 129,
    216,  79,  15, 185, 153,  14, 251, 162,   0, 241, 172, 197,  43,  10, 194, 235,
      6,  20,  72,  45, 143, 104, 161, 119,  41, 136,  38, 189, 135,  25,  93,  18,
    224, 171, 252, 195,  63,  19,  58, 165,  23,  55, 133, 254, 214, 144, 220, 178,
    156,  52, 110, 225,  97, 183, 140,  39,  53,  88, 219, 167,  16, 198,  62, 222,
     76, 139, 175,  94,  51, 134, 115,  22,  67,   1, 249, 217,   3,   5, 232, 138,
     31,  56, 116, 163,  70, 128, 234, 132, 229, 184, 244,  13,  34,  73, 233, 154,
    179, 131, 215, 236, 142, 223,  27,  57, 246, 108, 211,   8, 253,  85,  66, 245,
    193,  78, 190,   4,  17,   7, 150, 127, 152, 213,  37, 186,   2, 243,  46, 169,
     68, 101,  60, 174, 208, 158, 176,  69, 238, 191,  90,  83, 166, 125,  77,  59,
     21,  92,  49, 151, 168,  99,   9,  50, 146, 113, 117, 228,  65, 230,  40,  82,
     54, 237, 227, 102,  28,  36, 107,  24,  44, 126, 206, 201,  61, 114, 164, 207,
    181,  29,  91,  64, 221, 255,  48, 155, 192, 111, 180, 210, 182, 247, 203, 148,
    209,  98, 173,  11,  75, 123, 250, 118,  32,  47, 240, 202,  74, 177, 100,  80,
    196,  33, 248,  86, 157, 137, 120, 130,  84, 204, 122,  81, 242, 188, 200, 149,
    226, 218, 160, 187, 106,  35,  87, 105,  96, 145, 199, 159,  12, 121, 103, 112,
)

# ---------------------------------------------------------------------------
# COMP128-1 (A3/A8)
# ---------------------------------------------------------------------------

# --- known-answer vectors ---------------------------------------------------
COMP128_V1_VECTORS = (
    ("00112233445566778899AABBCCDDEEFF", "00112233445566778899AABBCCDDEEFF", "04A66BA8", "F87EB8222CEA3400"),
    ("112233445566778899AABBCCDDEEFF00", "2233445566778899AABBCCDDEEFF0011", "3C0DCFBD", "F84A72DC312F6000"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "2EB9F582", "59A9CF45911C3400"),
)
COMP128_V2_VECTORS = (
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "00000000000000000000000000000000", "34B4225B", "F16B96E118A85800"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "00102030405060708090A0B0C0D0E0F0", "A892A8EF", "D6D33E3650372C00"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "F699F0BA", "BA87114F0350BC00"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "000102030405060708090A0B0C0D0E0F", "A5B4C7CA", "0514C4E1B25CBC00"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "A926134D19884E0C5DFDFED7E5D43926", "315E8EF1", "9510592D48DE8C00"),
)
COMP128_V3_VECTORS = (
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "00000000000000000000000000000000", "34B4225B", "F16B96E118A85986"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "00102030405060708090A0B0C0D0E0F0", "A892A8EF", "D6D33E3650372F78"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "F699F0BA", "BA87114F0350BD8B"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "000102030405060708090A0B0C0D0E0F", "A5B4C7CA", "0514C4E1B25CBFED"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "A6D10F7561451F50B85255AD5BD912D3", "66862241", "4C3922D25727F3C7"),
)
COMP128_V2_VECTORS = COMP128_V2_VECTORS + (
    ("00112233445566778899AABBCCDDEEFF", "00112233445566778899AABBCCDDEEFF", "6FB9EB06", "605D954FFDEFE800"),
)
COMP128_V3_VECTORS = COMP128_V3_VECTORS + (
    ("00112233445566778899AABBCCDDEEFF", "00112233445566778899AABBCCDDEEFF", "6FB9EB06", "605D954FFDEFEA7F"),
)


def _round(x, n, tbl):
    m = 4 - n
    for i in range(1 << n):
        for j in range(1 << m):
            a = j + i * (2 << m)
            b = a + (1 << m)
            y = (x[a] + (x[b] << 1)) & ((32 << m) - 1)
            z = ((x[a] << 1) + x[b]) & ((32 << m) - 1)
            x[a] = tbl[y]
            x[b] = tbl[z]


def _compress(x):
    for n in range(5):
        _round(x, n, COMP128_TABLES[n])


def _bits_from_bytes(x):
    return [1 if (x[i >> 2] & (1 << (3 - (i & 3)))) else 0 for i in range(128)]


def _permute(x, bits):
    for i in range(16, 32):
        x[i] = 0
    for i in range(128):
        x[(i >> 3) + 16] |= bits[(i * 17) & 127] << (7 - (i & 7))


def comp128v1(ki: bytes, rand: bytes) -> tuple[bytes, bytes]:
    """Return (SRES 4 bytes, Kc 8 bytes)."""
    x = [0] * 32
    x[16:32] = list(rand)
    for _ in range(7):
        x[0:16] = list(ki)
        _compress(x)
        _permute(x, _bits_from_bytes(x))
    x[0:16] = list(ki)
    _compress(x)
    sres = bytes(((x[i] << 4) | x[i + 1]) & 0xFF for i in range(0, 8, 2))
    kc = bytearray(8)
    for i in range(0, 12, 2):
        kc[i >> 1] = ((x[i + 18] << 6) | (x[i + 19] << 2) | (x[i + 20] >> 2)) & 0xFF
    kc[6] = ((x[30] << 6) | (x[31] << 2)) & 0xFF
    return sres, bytes(kc)


# ---------------------------------------------------------------------------
# COMP128-2 / COMP128-3
# ---------------------------------------------------------------------------

def _v23_internal(output, kxor, rand):
    temp = [0] * 16
    km = list(rand) + list(kxor)
    for i in range(5):
        for z in range(16):
            temp[z] = V23_TABLE0[V23_TABLE1[km[16 + z]] ^ km[z]]
        j = 0
        while (1 << i) > j:
            k = 0
            while (1 << (4 - i)) > k:
                km[((2 * k + 1) << i) + j] = \
                    V23_TABLE0[V23_TABLE1[temp[(k << i) + j]] ^ km[(k << i) + 16 + j]]
                km[(k << (i + 1)) + j] = temp[(k << i) + j]
                k += 1
            j += 1
    for i in range(16):
        output[i] = 0
        for j in range(8):
            output[i] ^= (((km[((19 * (j + 8 * i) + 19) % 256) // 8] >> ((3 * j + 3) % 8)) & 1) << j)


def comp128v3(ki: bytes, rand: bytes) -> tuple[bytes, bytes]:
    k_mix = [0] * 16
    rand_mix = [0] * 16
    for i in range(8):
        k_mix[i] = ki[15 - i]
        k_mix[15 - i] = ki[i]
        rand_mix[i] = rand[15 - i]
        rand_mix[15 - i] = rand[i]
    katyvasz = [k_mix[i] ^ rand_mix[i] for i in range(16)]
    for _ in range(8):
        _v23_internal(rand_mix, katyvasz, rand_mix)
    out = [rand_mix[15 - i] for i in range(16)]
    out[4:12] = out[8:16]          # bytes 4..7 are discarded by the algorithm
    return bytes(out[0:4]), bytes(out[4:12])


def comp128v2(ki: bytes, rand: bytes) -> tuple[bytes, bytes]:
    sres, kc = comp128v3(ki, rand)
    kc = bytearray(kc)
    kc[7] = 0                      # the low 10 bits of Kc are forced to zero
    kc[6] &= 0xFC
    return sres, bytes(kc)


COMP128 = {"v1": comp128v1, "v2": comp128v2, "v3": comp128v3}

COMP128_KNOWN_ANSWERS = {
    "v1": COMP128_V1_VECTORS,
    "v2": COMP128_V2_VECTORS,
    "v3": COMP128_V3_VECTORS,
}


def parse_hex(value: str, nbytes: int, what: str) -> bytes:
    if len(value) != nbytes * 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError("%s must be exactly %d hex digits, got %r" % (what, nbytes * 2, value))
    return bytes.fromhex(value)


def auth_vector(algo: str, ki_hex: str, rand_hex: str) -> tuple[bytes, bytes]:
    fn = COMP128.get(algo)
    if fn is None:
        raise ValueError("unknown algorithm %r (expected v1, v2 or v3)" % algo)
    return fn(parse_hex(ki_hex, 16, "KI"), parse_hex(rand_hex, 16, "RAND"))


# ----------------------------------------------------------------- AES-128
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _aes_expand(key):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r + c][j] << (24 - 8 * j) for j in range(4)) for r in range(11) for c in range(4)]


def _aes_encrypt_block(rk, block):
    s = [list(block[i * 4:i * 4 + 4]) for i in range(4)]  # s[col][row] -> state[row][col]
    st = [[s[c][r] for c in range(4)] for r in range(4)]
    k = [rk[i].to_bytes(4, 'big') for i in range(44)]

    def arks(round_):
        for c in range(4):
            kb = k[4 * round_ + c]
            for r in range(4):
                st[r][c] ^= kb[r]

    arks(0)
    for rnd in range(1, 11):
        for r in range(4):
            for c in range(4):
                st[r][c] = SBOX[st[r][c]]
        for r in range(1, 4):
            st[r] = st[r][r:] + st[r][:r]
        if rnd != 10:
            for c in range(4):
                a = [st[r][c] for r in range(4)]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                st[0][c] = a[0] ^ t ^ _xtime(a[0] ^ a[1])
                st[1][c] = a[1] ^ t ^ _xtime(a[1] ^ a[2])
                st[2][c] = a[2] ^ t ^ _xtime(a[2] ^ a[3])
                st[3][c] = a[3] ^ t ^ _xtime(a[3] ^ a[0])
        arks(rnd)
    return bytes(st[r][c] for c in range(4) for r in range(4))


def aes128_enc(key, block):
    return _aes_encrypt_block(_aes_expand(key), block)


# --------------------------------------------------------------- Milenage
def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _rotl(b, n):
    n %= 128
    v = int.from_bytes(b, 'big')
    v = ((v << n) | (v >> (128 - n))) & ((1 << 128) - 1)
    return v.to_bytes(16, 'big')


C1 = bytes(16)
C2 = (1).to_bytes(16, 'big')
C3 = (2).to_bytes(16, 'big')
C4 = (4).to_bytes(16, 'big')
C5 = (8).to_bytes(16, 'big')


def milenage_opc(k, op):
    return _xor(op, aes128_enc(k, op))


def milenage(k, opc, rand, sqn=None, amf=None):
    temp = aes128_enc(k, _xor(rand, opc))
    out2 = _xor(aes128_enc(k, _xor(_rotl(_xor(temp, opc), 0), C2)), opc)
    out3 = _xor(aes128_enc(k, _xor(_rotl(_xor(temp, opc), 32), C3)), opc)
    out4 = _xor(aes128_enc(k, _xor(_rotl(_xor(temp, opc), 64), C4)), opc)
    out5 = _xor(aes128_enc(k, _xor(_rotl(_xor(temp, opc), 96), C5)), opc)
    res = {'f2': out2[8:16], 'f3': out3, 'f4': out4,
           'f5': out2[0:6], 'f5*': out5[0:6]}
    if sqn is not None:
        in1 = sqn + amf + sqn + amf
        out1 = _xor(aes128_enc(k, _xor(_xor(temp, _rotl(_xor(in1, opc), 64)), C1)), opc)
        res['f1'] = out1[0:8]
        res['f1*'] = out1[8:16]
    return res


# --------------------------------------------------------- Keccak-f[1600]
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18],
       [1, 44, 10, 45, 2],
       [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56],
       [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64


def keccak_f1600(a):
    """a is a flat list of 25 lanes; lane index i == x + 5*y."""
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y] & M64) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= RC[rnd]
    return a


def _bytes_to_lanes(b):
    assert len(b) == 200
    return [int.from_bytes(b[8 * i:8 * i + 8], 'little') for i in range(25)]


def _lanes_to_bytes(a):
    return b''.join(x.to_bytes(8, 'little') for x in a)


def tuk_perm(inb, iterations=1):
    a = _bytes_to_lanes(inb)
    for _ in range(iterations):
        a = keccak_f1600(a)
    return _lanes_to_bytes(a)


# ------------------------------------------------------------------- TUAK
ALGONAME = b"TUAK1.0"


def _instance_bits(func, out_bits, ck256=0, ik256=0, k256=0):
    if func == 'topc':
        bits = [0, 0, 0, 0, 0, 0, 0, k256]
    elif func in ('f1', 'f1*'):
        f = [0, 0] if func == 'f1' else [1, 0]
        bits = f + {64: [0, 0, 1], 128: [0, 1, 0], 256: [1, 0, 0]}[out_bits] + [0, 0, k256]
    elif func == 'f2f5':
        bits = [0, 1] + {32: [0, 0, 0], 64: [0, 0, 1], 128: [0, 1, 0], 256: [1, 0, 0]}[out_bits] \
            + [ck256, ik256, k256]
    elif func == 'f5*':
        bits = [1, 1, 0, 0, 0, 0, 0, k256]
    else:
        raise ValueError(func)
    return int(''.join(str(x) for x in bits), 2)


def _tuk_in(topc, instance, rand, k, klength, amf=None, sqn=None):
    buf = bytearray(200)
    buf[0:32] = topc[::-1]
    buf[32] = instance
    buf[33:40] = ALGONAME[::-1]
    buf[40:56] = rand[::-1]
    if amf is not None:
        buf[56:58] = amf[::-1]
        buf[58:64] = sqn[::-1]
    kk = k[::-1]
    buf[64:64 + len(kk)] = kk
    buf[96] = 0x1F
    buf[135] = 0x80
    return bytes(buf)


def tuak_topc(top, k, klength, iterations=1):
    inst = _instance_bits('topc', 0, k256=1 if klength == 256 else 0)
    inb = _tuk_in(top, inst, bytes(16), k, klength)
    return tuk_perm(inb, iterations)[0:32][::-1]


def tuak_f1(k, topc, rand, sqn, amf, klength, maclength, iterations=1, f1star=False):
    inst = _instance_bits('f1*' if f1star else 'f1', maclength,
                          k256=1 if klength == 256 else 0)
    inb = _tuk_in(topc, inst, rand, k, klength, amf, sqn)
    out = tuk_perm(inb, iterations)
    return out[0:maclength // 8][::-1]


def tuak_f2f5(k, topc, rand, klength, reslength, cklength, iklength, iterations=1):
    inst = _instance_bits('f2f5', reslength,
                          ck256=1 if cklength == 256 else 0,
                          ik256=1 if iklength == 256 else 0,
                          k256=1 if klength == 256 else 0)
    inb = _tuk_in(topc, inst, rand, k, klength)
    out = tuk_perm(inb, iterations)
    return {
        'f2': out[0:reslength // 8][::-1],
        'f3': out[32:32 + cklength // 8][::-1],
        'f4': out[64:64 + iklength // 8][::-1],
        'f5': out[96:102][::-1],
    }


def tuak_f5star(k, topc, rand, klength, iterations=1):
    inst = _instance_bits('f5*', 0, k256=1 if klength == 256 else 0)
    inb = _tuk_in(topc, inst, rand, k, klength)
    return tuk_perm(inb, iterations)[96:102][::-1]


# TS 35.208 clause 4.3 -- the twenty published Milenage test sets.
# Fields: K, OP, RAND, SQN, AMF, OPC, f1, f1*, f2, f3, f4, f5, f5*.
MILENAGE_VECTORS = [
    ("465b5ce8b199b49faa5f0a2ee238a6bc", "cdc202d5123e20f62b6d676ac72cb318", "23553cbe9637a89d218ae64dae47bf35", "ff9bb4d0b607", "b9b9", "cd63cb71954a9f4e48a5994e37a02baf",
     "4a9ffac354dfafb3", "01cfaf9ec4e871e9", "a54211d5e3ba50bf", "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f769bcd751044604127672711c6d3441", "aa689c648370", "451e8beca43b"),
    ("465b5ce8b199b49faa5f0a2ee238a6bc", "cdc202d5123e20f62b6d676ac72cb318", "23553cbe9637a89d218ae64dae47bf35", "ff9bb4d0b607", "b9b9", "cd63cb71954a9f4e48a5994e37a02baf",
     "4a9ffac354dfafb3", "01cfaf9ec4e871e9", "a54211d5e3ba50bf", "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f769bcd751044604127672711c6d3441", "aa689c648370", "451e8beca43b"),
    ("fec86ba6eb707ed08905757b1bb44b8f", "dbc59adcb6f9a0ef735477b7fadf8374", "9f7c8d021accf4db213ccff0c7f71a6a", "9d0277595ffc", "725c", "1006020f0a478bf6b699f15c062e42b3",
     "9cabc3e99baf7281", "95814ba2b3044324", "8011c48c0c214ed2", "5dbdbb2954e8f3cde665b046179a5098", "59a92d3b476a0443487055cf88b2307b", "33484dc2136b", "deacdd848cc6"),
    ("9e5944aea94b81165c82fbf9f32db751", "223014c5806694c007ca1eeef57f004f", "ce83dbc54ac0274a157c17f80d017bd6", "0b604a81eca8", "9e09", "a64a507ae1a2a98bb88eb4210135dc87",
     "74a58220cba84c49", "ac2cc74a96871837", "f365cd683cd92e96", "e203edb3971574f5a94b0d61b816345d", "0c4524adeac041c4dd830d20854fc46b", "f0b9c08ad02e", "6085a86c6f63"),
    ("4ab1deb05ca6ceb051fc98e77d026a84", "2d16c5cd1fdf6b22383584e3bef2a8d8", "74b0cd6031a1c8339b2b6ce2b8c4a186", "e880a1b580b6", "9f07", "dcf07cbd51855290b92a07a9891e523e",
     "49e785dd12626ef2", "9e85790336bb3fa2", "5860fc1bce351e7e", "7657766b373d1c2138f307e3de9242f9", "1c42e960d89b8fa99f2744e0708ccb53", "31e11a609118", "fe2555e54aa9"),
    ("6c38a116ac280c454f59332ee35c8c4f", "1ba00a1a7c6700ac8c3ff3e96ad08725", "ee6466bc96202c5a557abbeff8babf63", "414b98222181", "4464", "3803ef5363b947c6aaa225e58fae3934",
     "078adfb488241a57", "80246b8d0186bcf1", "16c8233f05a0ac28", "3f8c7587fe8e4b233af676aede30ba3b", "a7466cc1e6b2a1337d49d3b66e95d7b4", "45b0f69ab06c", "1f53cd2b1113"),
    ("2d609d4db0ac5bf0d2c0de267014de0d", "460a48385427aa39264aac8efc9e73e8", "194aa756013896b74b4a2a3b0af4539e", "6bf69438c2e4", "5f67", "c35a0ab0bcbfc9252caff15f24efbde0",
     "bd07d3003b9e5cc3", "bcb6c2fcad152250", "8c25a16cd918a1df", "4cd0846020f8fa0731dd47cbdc6be411", "88ab80a415f15c73711254a1d388f696", "7e6455f34cf3", "dc6dd01e8f15"),
    ("a530a7fe428fad1082c45eddfce13884", "511c6c4e83e38c89b1c5d8dde62426fa", "3a4c2b3245c50eb5c71d08639395764d", "f63f5d768784", "b90e", "27953e49bc8af6dcc6e730eb80286be3",
     "53761fbd679b0bad", "21adfd334a10e7ce", "a63241e1ffc3e5ab", "10f05bab75a99a5fbb98a9c287679c3b", "f9ec0865eb32f22369cade40c59c3a44", "88196c47986f", "c987a3d23115"),
    ("d9151cf04896e25830bf2e08267b8360", "75fc2233a44294ee8e6de25c4353d26b", "f761e5e93d603feb730e27556cb8a2ca", "47ee0199820a", "9113", "c4c93effe8a08138c203d4c27ce4e3d9",
     "66cc4be44862af1f", "7a4b8d7a8753f246", "4a90b2171ac83a76", "71236b7129f9b22ab77ea7a54c96da22", "90527ebaa5588968db41727325a04d9e", "82a0f5287a71", "527dbf41f35f"),
    ("a0e2971b6822e8d354a18cc235624ecb", "323792faca21fb4d5d6f13c145a9d2c1", "08eff828b13fdb562722c65c7f30a9b2", "db5c066481e0", "716b", "82a26f22bba9e9488f949a10d98e9cc4",
     "9485fe24621cb9f6", "bce325ce03e2e9b9", "4bc2212d8624910a", "08cef6d004ec61471a3c3cda048137fa", "ed0318ca5deb9206272f6e8fa64ba411", "a2f858aa9e5d", "74e76fbbec38"),
    ("0da6f7ba86d5eac8a19cf563ac58642d", "4b9a26fa459e3acbff36f4015de3bdc1", "679ac4dbacd7d233ff9d6806f4149ce3", "6e2331d692ad", "224a", "0db1071f8767562ca43a0a64c41e8d08",
     "2831d7ae9088e492", "9b2e16951135d523", "6fc30fee6d123523", "69b1cae7c7429d975e245cacb05a517c", "74f24e8c26df58e1b38d7dcd4f1b7fbd", "4c539a26e1fa", "07861e126928"),
    ("77b45843c88e58c10d202684515ed430", "bf3286c7a51409ce95724d503bfe6e70", "4c47eb3076dc55fe5106cb2034b8cd78", "fe1a8731005d", "ad25", "d483afae562409a326b5bb0b20c4d762",
     "08332d7e9f484570", "ed41b734489d5207", "aefa357beac2a87a", "908c43f0569cb8f74bc971e706c36c5f", "c251df0d888dd9329bcf46655b226e40", "30ff25cdadf6", "e84ed0d4677e"),
    ("729b17729270dd87ccdf1bfe29b4e9bb", "d04c9c35bd2262fa810d2924d036fd13", "311c4c929744d675b720f3b7e9b1cbd0", "c85c4cf65916", "5bb2", "228c2f2f06ac3268a9e616ee16db4ba1",
     "ff794fe2f827ebf8", "24fe4dc61e874b52", "98dbbd099b3b408d", "44c0f23c5493cfd241e48f197e1d1012", "0c9fb81613884c2535dd0eabf3b440d8", "5380d158cfe3", "87ac3b559fb6"),
    ("d32dd23e89dc662354ca12eb79dd32fa", "fe75905b9da47d356236d0314e09c32e", "cf7d0ab1d94306950bf12018fbd46887", "484107e56a43", "b5e6", "d22a4b4180a5325708a5ff70d9f67ec7",
     "cf19d62b6a809866", "5d269537e45e2ce6", "af4a411e1139f2c2", "5af86b80edb70df5292cc1121cbad50c", "7f4d6ae7440e18789a8b75ad3f42f03a", "217af49272ad", "900e101c677e"),
    ("af7c65e1927221de591187a2c5987a53", "0c7acb8d95b7d4a31c5aca6d26345a88", "1f0f8578464fd59b64bed2d09436b57a", "3d627b01418d", "84f6", "a4cf5c8155c08a7eff418e5443b98e55",
     "c37cae7805642032", "68cd09a452d8db7c", "7bffa5c2f41fbc05", "3f8c3f3ccf7625bf77fc94bcfd22fd26", "abcbae8fd46115e9961a55d0da5f2078", "837fd7b74419", "56e97a6090b1"),
    ("5bd7ecd3d3127a41d12539bed4e7cf71", "f967f76038b920a9cd25e10c08b49924", "59b75f14251c75031d0bcbac1c2c04c7", "a298ae8929dc", "d056", "76089d3c0ff3efdc6e36721d4fceb747",
     "c3f25cd94309107e", "b0c8ba343665afcc", "7e3f44c7591f6f45", "d42b2d615e49a03ac275a5aef97af892", "0b3f8d024fe6bfafaa982b8f82e319c2", "5be11495525d", "4d6a34a1e4eb"),
    ("6cd1c6ceb1e01e14f1b82316a90b7f3d", "078bfca9564659ecd8851e84e6c59b48", "f69b78f300a0568bce9f0cb93c4be4c9", "b4fce5feb059", "e4bb", "a219dc37f1dc7d66738b5843c799f206",
     "69a90869c268cb7b", "2e0fdcf9fd1cfa6a", "70f6bdb9ad21525f", "6edaf99e5bd9f85d5f36d91c1272fb4b", "d61c853c280dd9c46f297baec386de17", "1c408a858b3e", "aa4ae52daa30"),
    ("b73a90cbcf3afb622dba83c58a8415df", "b672047e003bb952dca6cb8af0e5b779", "b120f1c1a0102a2f507dd543de68281f", "f1e8a523a36d", "471b", "df0c67868fa25f748b7044c6e7c245b8",
     "ebd70341bcd415b0", "12359f5d82220c14", "479dd25c20792d63", "66195dbed0313274c5ca7766615fa25e", "66bec707eb2afc476d7408a8f2927b36", "aefdaa5ddd99", "12ec2b87fbb1"),
    ("5122250214c33e723a5dd523fc145fc0", "c9e8763286b5b9ffbdf56e1297d0887b", "81e92b6c0ee0e12ebceba8d92a99dfa5", "16f3b3f70fc2", "c3ab", "981d464c7c52eb6e5036234984ad0bcf",
     "2a5c23d15ee351d5", "62dae3853f3af9d2", "28d7b0f2a2ec3de5", "5349fbe098649f948f5d2e973a81c00f", "9744871ad32bf9bbd1dd5ce54e3e2e5a", "ada15aeb7bb8", "d461bc15475d"),
    ("90dca4eda45b53cf0f12d7c9c3bc6a89", "3ffcfe5b7b1111589920d3528e84e655", "9fddc72092c6ad036b6e464789315b78", "20f813bd4141", "61df", "cb9cccc4b9258e6dca4760379fb82581",
     "09db94eab4f8149e", "a29468aa9775b527", "a95100e2760952cd", "b5f2da03883b69f96bf52e029ed9ac45", "b4721368bc16ea67875c5598688bb0ef", "83cfd54db913", "4f2039392ddc"),
]

# TS 35.232 clause 5 -- raw Keccak-f[1600] permutation pairs (200 bytes in,
# 200 bytes out). These pin the permutation and the byte<->lane mapping on
# their own, before any TUAK framing is involved.
KECCAK_VECTORS = [
    # clause 5.3
    ("2476d2dac59e2e9349df3255a9dab1b69eb5c208f151c7309e8c8f17db456d0b5eb0afb6c73e37ce8ccccf20b79d8a67294149174809e429709330c4ad231d3e5211ae0bd80520c43ad4b436625792a76c52089d0f739271151a37594df66de4429f3c970a3456b6ce2c78cd1128717f4bdb731a4c97dbe5eb7353fe81e37c33ac60b82122eac611a98e0e7442b99964752293e4f9c696ba05f07a21451f90730c9678c645ad4be44c4d2d981a3412081c9c6b05c993ff1c561a0d242b4706d501c34765b37a0b50",
     "2fdc58d4d94a884c1cb03a8e63acab8375e856b561ba3a0625e830acdb55734286646f87189b435425b5d6654e228228b697b81cbead655b71aaccc25e3d7e51b5cb5ac227f67f2ad8a062976782b08a7ec3f1b538d6008c0babef83da64366b62a53f88a3dc0629bded795f3220f3c65c76bdd01243e88f63d6912e5fb5cda167b71f9baaa742dc193ff78c1767a38a1c96408cce169239b077f2903a07b8c46a048d66318e595ea4bb92992c7c2d3dcd381975b6e05f85ba18152096cc30ed22140ff3b6711ea7"),
    # clause 5.4
    ("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
     "44e0e58ca968975c4c2592a157f53f2124519b010b89e15e301ef58f76501db59cde067f1fde09c0a4b5c210a6a19f06ba4c8f0c6fc868f0fc80a63b2553791e41c82278ad115efc70f71d641ff0774aa5d547b6d9914914022c514c45fceca61cb66b0f0313e34988ae0d36737e2c0529907fe653fc4e185d07f3961f826bb88031af844d9e7d9876170363fde76786c58ccbcf5c3a01bb914c1b0208a27c7be3bbbbbb9976e040317afc2afbfadc7ba7fc237235c65551aa3139641fa8db2e6483f28740b31b61"),
    # clause 5.5
    ("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8",
     "5dd0e3dd9e46db2187a9e1a444427d7a832fef29913990e015ea8d1f3f1fa6413ffbbc586f5a4d694dd60668fbf3b4bbda4945c9ea0cbee211735ebfa8399b613aff34d1dd47fa398c78f48a91a6657d29036c87f7735f43e2abb76a135045b70e42c59d809214a4cd301f1857300a55d01d32365b6abda51ead7541db7beddc46e485727c3b2b5d83b59e5a7a62e0131614ba0d7bfacd4eba716232808859f003855f5c47010a50e1262f9e9e812e6cb3dd52d9adb7be1910427634025231968de0b43fa24b4b3e"),
    # clause 5.6
    ("abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab",
     "0052f00eb409b5ce5f78e95320ee6a715f5b1a0a7e5bed0343d6911330abe2fc57b66fb5ba9ef2880b0575ed0a9870c50c6657838a1d32f388fdc3a4e73246ddd956587477c4c8d41ad419140452cc171323ae1ff0910ce1c3278b62c64875912b7f7c21cfa052e0b040214c5f3b81c320758792cea0c8d1e42e92e1ef3cf066be16c61ee44ddd69db729a825d4dbbfd9f97da46c6103d5a5f8c8d21bd427d58af4b411178bede5a1986a0c91d38c485ee2d5472bdd0a5b9faabf7077313caf9f30a1e46ac8e1258"),
    # clause 5.7
    ("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
     "c16ca06def3add45b20ccfd67aa8f91215c2e8751edd02a5103f61ba6f7bf3bbb2595f411baf6aab1653f17e951e2dc88dfbf76867940a6338608218f8dff1417bdb3c6f45226487a9a6078b656a37ff861dfa793077c08803a8b962da6724ddc86d1093ffd00588a28e6c1b801f735463bc05581ed597bdbf37a459297f650539989efc4a7a9c8b2233c020dea30034c1f2c6cf5e0ccccc535540871803ed3d20b0c51013a3024ac56b33af5a2611233d537d11804ef02eb55978ffd43d9a7e48844264dece8fa8"),
    # clause 5.8
    ("0000000000000000010000000000000002000000000000000300000000000000040000000000000000000000000000000100000000000000020000000000000003000000000000000400000000000000000000000000000001000000000000000200000000000000030000000000000004000000000000000000000000000000010000000000000002000000000000000300000000000000040000000000000000000000000000000100000000000000020000000000000003000000000000000400000000000000",
     "560dbe41f6a75a7d33e15d6bfe0bdc647de554341ce0d061bbbdf1be757649dee741b1fd37418da6f35ab70e1587cc368c1b89adccce1d07ad920d4d9d08a043946c2f6fe1a517a249ce3c8a5f834eecfa2faaaddee832e6db24d42a2b04a78463a9b2df6d2f02fc5c29732a126514fb15eb7abe7fbf5718916691c7c2f8434600da7e2f9b7665a59c6141115505c9d9e9f805af6f9e6bc4f19c65c60ea972a6e4fa01857d298a09268390d574f63d4f76fb6d6dfcd13738c49848acd51e4ed783afa1ba520fa337"),
]

# TS 35.232 clause 6 -- TUAK f1 / f1*. Fields: K, TOP, RAND, SQN, AMF,
# KEY_sz(bits), MAC_sz(bits), KeccakIterations, TOPc, f1, f1*.
TUAK_F1_VECTORS = [
    ("abababababababababababababababab", "5555555555555555555555555555555555555555555555555555555555555555", "42424242424242424242424242424242", "111111111111", "ffff",
     128, 64, 1, "bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff",
     "f9a54e6aeaa8618d", "e94b4dc6c7297df3"),
    ("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "0123456789abcdef0123456789abcdef", "0123456789ab", "abcd",
     256, 128, 1, "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524",
     "c0b8c2d4148ec7aa5f1d78a97e4d1d58", "ef81af7290f7842c6ceafa537fa0745b"),
    ("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "0123456789abcdef0123456789abcdef", "0123456789ab", "abcd",
     256, 256, 1, "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524",
     "d97b75a1776065271b1e212bc3b1bf173f438b21e6c64a55a96c372e085e5cc5", "427bbf07c6e3a86c54f8c5216499f3909a6fd4a164c9fe235b1550258111b821"),
    ("b8da837a50652d6ac7c97da14f6acc61", "0952be13556c32ebc58195d9dd930493e12a9003669988ffde5fa1f0fe35cc01", "6887e55425a966bd86c9661a5fa72be8", "0dea2ee2c5af", "df1e",
     128, 128, 1, "2bc16eb657a68e1f446f08f57c0efb1d493527a2e652ce281eb6ca0e4487760a",
     "749214087958dd8f58bfcdf869d8ae3f", "619e865afe80e382aee13063f9dfb56d"),
    ("1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5", "e59f6eb10ea406813f4991b0b9e02f181edf4c7e17b480f66d34da35ee88c95e", "c570aac68cde651fb1e3088322498bef", "c89bb71f3a41", "297d",
     256, 64, 1, "3c6052e41532a28a47aa3cbb89f223e8f3aaa976aecd48bc3e7d6165a55eff62",
     "d7340dad02b4cb01", "c6021e2e66accb15"),
    ("1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5", "e59f6eb10ea406813f4991b0b9e02f181edf4c7e17b480f66d34da35ee88c95e", "c570aac68cde651fb1e3088322498bef", "c89bb71f3a41", "297d",
     256, 256, 2, "b04a66f26c62fcd6c82de22a179ab65506ecf47f56245cd149966cfa9cec7a51",
     "90d2289ed1ca1c3dbc2247bb480d431ac71d2e4a7677f6e997cfddb0cbad88b7", "427355dbac30e825063aba61b556e87583abac638e3ab01c4c884ad9d458dc2f"),
]

# TS 35.232 clause 7 -- TUAK f2/f3/f4/f5/f5*. Fields: K, TOP, RAND,
# KEY_sz, CK_sz, IK_sz, RES_sz (bits), KeccakIterations, TOPc,
# f2, f3, f4, f5, f5*.
TUAK_F2F5_VECTORS = [
    ("abababababababababababababababab", "5555555555555555555555555555555555555555555555555555555555555555", "42424242424242424242424242424242",
     128, 128, 128, 32, 1, "bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff",
     "657acd64", "d71a1e5c6caffe986a26f783e5c78be1", "be849fa2564f869aecee6f62d4337e72", "719f1e9b9054", "e7af6b3d0e38"),
    ("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "0123456789abcdef0123456789abcdef",
     256, 128, 128, 64, 1, "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524",
     "e9d749dc4eea0035", "a4cb6f6529ab17f8337f27baa8234d47", "2274155ccf4199d5e2abcbf621907f90", "480a9345cc1e", "f84eb338848c"),
    ("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "0123456789abcdef0123456789abcdef",
     256, 128, 256, 64, 1, "305425427e18c503c8a4b294ea72c95d0c36c6c6b29d0c65de5974d5977f8524",
     "07021c73e7635c7d", "4d59ac796834eb85d11fa148a5058c3c", "126d47500136fdc5ddfd14f19ebf16749ce4b6435323fbb5715a3a796a6082bd", "1d6622c4e59a", "f84eb338848c"),
    ("b8da837a50652d6ac7c97da14f6acc61", "0952be13556c32ebc58195d9dd930493e12a9003669988ffde5fa1f0fe35cc01", "6887e55425a966bd86c9661a5fa72be8",
     128, 128, 128, 128, 1, "2bc16eb657a68e1f446f08f57c0efb1d493527a2e652ce281eb6ca0e4487760a",
     "4041ce438e3e38e8aa96562eed83ac43", "3e3bc01bea0cd914c4c2c83ce2d92757", "666a8e6f577b1aa77b7fd53cebb8a3d6", "1f880d005119", "45e617d77fe5"),
    ("1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5", "e59f6eb10ea406813f4991b0b9e02f181edf4c7e17b480f66d34da35ee88c95e", "c570aac68cde651fb1e3088322498bef",
     256, 256, 128, 256, 1, "3c6052e41532a28a47aa3cbb89f223e8f3aaa976aecd48bc3e7d6165a55eff62",
     "84d89b41db1867ffd4c7ba1d82163f4d526a20fbae5418fbb526940b1eeb905c", "d419676afe5ab58c1d8bee0d43523a4d2f52ef0b31a4676a0c334427a988fe65", "205533e505661b61d05cc0eac87818f4", "d7b3d2d4980a", "ca9655264986"),
    ("1574ca56881d05c189c82880f789c9cd4244955f4426aa2b69c29f15770e5aa5", "e59f6eb10ea406813f4991b0b9e02f181edf4c7e17b480f66d34da35ee88c95e", "c570aac68cde651fb1e3088322498bef",
     256, 256, 256, 256, 2, "b04a66f26c62fcd6c82de22a179ab65506ecf47f56245cd149966cfa9cec7a51",
     "d67e6e64590d22eecba7324afa4af4460c93f01b24506d6e12047d789a94c867", "ede57edfc57cdffe1aae75066a1b7479bbc3837438e88d37a801cccc9f972b89", "48ed9299126e5057402fe01f9201cf25249f9c5c0ed2afcf084755daff1d3999", "6aae8d18c448", "8c5f33b61f4e"),
]


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def milenage_vector(ki_hex: str, op_hex: str, rand_hex: str,
                    sqn_hex: str = "", amf_hex: str = "") -> dict:
    """Full Milenage run from OP: returns OPC plus f1..f5* as bytes.

    SQN and AMF are only needed for f1/f1*, which are omitted when they are not
    supplied.  OP is supplied as an operator constant and OPC is derived.
    """
    k = parse_hex(ki_hex, 16, "KI")
    op = parse_hex(op_hex, 16, "OP")
    rand = parse_hex(rand_hex, 16, "RAND")
    opc = milenage_opc(k, op)
    out = {"OPC": opc}
    if sqn_hex and amf_hex:
        out.update(milenage(k, opc, rand, parse_hex(sqn_hex, 6, "SQN"),
                            parse_hex(amf_hex, 2, "AMF")))
    else:
        out.update(milenage(k, opc, rand))
    return out


def tuak_vector(ki_hex: str, top_hex: str, rand_hex: str,
                sqn_hex: str = "", amf_hex: str = "",
                klength: int = 128, maclength: int = 64,
                reslength: int = 64, cklength: int = 128, iklength: int = 128,
                iterations: int = 1) -> dict:
    """Full TUAK run from TOP: returns TOPc plus f1..f5* as bytes."""
    k = parse_hex(ki_hex, klength // 8, "KI")
    top = parse_hex(top_hex, 32, "TOP")
    rand = parse_hex(rand_hex, 16, "RAND")
    topc = tuak_topc(top, k, klength, iterations)
    out = {"TOPC": topc}
    if sqn_hex and amf_hex:
        sqn = parse_hex(sqn_hex, 6, "SQN")
        amf = parse_hex(amf_hex, 2, "AMF")
        out["f1"] = tuak_f1(k, topc, rand, sqn, amf, klength, maclength, iterations)
        out["f1*"] = tuak_f1(k, topc, rand, sqn, amf, klength, maclength,
                             iterations, f1star=True)
    out.update(tuak_f2f5(k, topc, rand, klength, reslength, cklength, iklength,
                         iterations))
    out["f5*"] = tuak_f5star(k, topc, rand, klength, iterations)
    return out


# FIPS-197 appendix C.1: key, plaintext, ciphertext.
AES128_VECTORS = [
    ("000102030405060708090a0b0c0d0e0f",
     "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"),
]


# ── 5G key derivation (TS 33.220 Annex B.2, as used by TS 33.501 A.2) ──────
# S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln, each Li a 2-byte
# big-endian BIT length; output = HMAC-SHA-256(key, S) truncated to the
# capability the caller asks for.  FC values this tree uses:
#   0x6A KAUSF  (AUSF key,      P0 = SN name, P1 = SQN xor AK)
#   0x6B RES*   (resync-proof RES, P0 = SN name, P1 = RAND, P2 = RES)
#   0x6C KSEAF  (SEAF key,      P0 = SN name)                -- 13_nr_core
# The function is deliberately unaware of which FC means what: the caller
# passes the inputs, and the caller is the module that names the clause.

KDF_FC = {
    0x6A: ("KAUSF", "AUSF key (TS 33.501 A.4.1): P0 = SN name, P1 = SQN xor AK"),
    0x6B: ("RES*", "5G RES star (TS 33.501 A.4.1): P0 = SN name, P1 = RAND, P2 = RES"),
    0x6C: ("KSEAF", "SEAF key (TS 33.501 A.5): P0 = SN name"),
    # AKMA (TS 33.535). The FC space is allocated per document: 33.535 claims
    # the range 0x80-0x82 (A.1.2), and each annex fixes the parameters.
    0x80: ("KAKMA", "AKMA anchor key (TS 33.535 A.2): KEY = KAUSF, P0 = \"AKMA\", P1 = SUPI"),
    0x81: ("A-TID", "AKMA temporary UE id (TS 33.535 A.3): KEY = KAUSF, P0 = \"A-TID\", P1 = SUPI"),
    0x82: ("KAF", "AKMA application key (TS 33.535 A.4): KEY = KAKMA, P0 = AF_ID"),
}


def kdf_parts(fc: int, params, out_bits: int = 256):
    """Return (message_bytes, description_rows) for one KDF invocation.

    Lengths are BIT lengths in two bytes, so a parameter longer than 8191
    bytes cannot be expressed; that is a property of the scheme, not of this
    code, and it is refused rather than wrapped.
    """
    if not 0 <= fc <= 0xFF:
        raise ValueError("FC must fit in one octet, got %d" % fc)
    parts = [bytes([fc])]
    rows = []
    for i, raw in enumerate(params):
        p = bytes(raw)
        bits = len(p) * 8
        if bits > 0xFFFF:
            raise ValueError("P%d is %d bytes; the scheme caps a parameter at "
                             "65535 bits (8191 bytes)" % (i, len(p)))
        parts.append(p)
        parts.append(bits.to_bytes(2, "big"))
        rows.append((i, p, bits))
    msg = b"".join(parts)
    return msg, rows, (out_bits + 7) // 8


def kdf(key: bytes, fc: int, params) -> bytes:
    """HMAC-SHA-256(key, FC || P0 || L0 || ...) truncated to 256 bits."""
    msg, _rows, nbytes = kdf_parts(fc, params)
    return hmac.new(key, msg, hashlib.sha256).digest()[:nbytes]


def kausf(key: bytes, sn_name: bytes, sqn_ak: bytes) -> bytes:
    """AUSF key: KDF(KEY, FC=0x6A, SN name, SQN xor AK), 256 bits.

    KEY is CK||IK, not K (TS 33.501 A.4.1): the 256-bit concatenation of the
    two 128-bit keys the authentication produced. Using K here is the mistake
    that produces a KAUSF no core will agree with.
    """
    return kdf(key, 0x6A, (sn_name, sqn_ak))


def res_star(key: bytes, sn_name: bytes, rand: bytes, res: bytes) -> bytes:
    """5G RES*/XRES*: the RIGHTMOST 128 bits of the 256-bit KDF output.

    TS 33.501 Annex A.4 derives a 256-bit block and takes its second half,
    which is why the output here is 16 bytes and not 32.
    """
    return kdf(key, 0x6B, (sn_name, rand, res))[16:32]


def kseaf(kausf_key: bytes, sn_name: bytes) -> bytes:
    """SEAF key: KDF(KAUSF, FC=0x6C, SN name)."""
    return kdf(kausf_key, 0x6C, (sn_name,))


def hxres_star(rand: bytes, res_star_bytes: bytes) -> bytes:
    """HXRES*: the rightmost 128 bits of SHA-256(RAND || RES*) (TS 33.501 A.5).

    RAND comes first and the second half of the digest is taken. This is the
    value the serving network sees: it compares it against the HRES* the UE
    derives, so it can conclude the UE holds the card without learning RES*.
    """
    if len(rand) != 16:
        raise ValueError("RAND must be 16 bytes, got %d" % len(rand))
    if len(res_star_bytes) != 16:
        raise ValueError("RES* must be 16 bytes, got %d" % len(res_star_bytes))
    return hashlib.sha256(rand + res_star_bytes).digest()[16:32]


def _cli_kdf(a) -> int:
    """--kdf <fc> --key <hex> --p0 <hex> [--p1 <hex>] [--p2 <hex>]."""
    try:
        fc = int(a.kdf, 16)
    except (TypeError, ValueError):
        print("ERROR\t--kdf wants one octet of hex, e.g. 6A", file=sys.stderr)
        return 2
    if not a.key or not a.p0:
        print("ERROR\t--kdf needs --key and --p0", file=sys.stderr)
        return 2
    try:
        key = bytes.fromhex(a.key)
    except ValueError:
        print("ERROR\t--key must be hex", file=sys.stderr)
        return 1
    if not key:
        print("ERROR\t--key is empty", file=sys.stderr)
        return 1
    params = []
    for i, v in enumerate((a.p0, a.p1, a.p2)):
        if v is None:
            continue
        if i != len(params):
            print("ERROR\tgive the KDF parameters in order starting at --p0",
                  file=sys.stderr)
            return 2
        try:
            params.append(bytes.fromhex(v))
        except ValueError:
            print("ERROR\t--p%d must be hex" % i, file=sys.stderr)
            return 1
    try:
        msg, rows, nbytes = kdf_parts(fc, params)
        out = hmac.new(key, msg, hashlib.sha256).digest()[:nbytes]
    except ValueError as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 1
    name, why = KDF_FC.get(fc, ("FC 0x%02X" % fc, "no clause is named for this FC here"))
    print("fc\t%02X" % fc)
    print("derived\t%s" % name)
    print("key_bits\t%d" % (len(key) * 8))
    print("message_bits\t%d" % (len(msg) * 8))
    for i, p, bits in rows:
        print("p%d\t%s\tp%d_bits\t%d" % (i, p.hex().upper(), i, bits))
    print("out\t%s" % out.hex().upper())
    print("source\tTS 33.220 Annex B.2: HMAC-SHA-256(key, FC || P0 || L0 || ...), Li = bit length")
    print("clause\t%s" % why)
    return 0


def _cli_derive(a) -> int:
    """--derive <res-star|hxres|kausf|kseaf> with the inputs that derivation needs.

    Named derivations, because the truncation and the parameter order are part
    of each clause and are exactly what a raw --kdf call gets wrong.
    """
    kind = (a.derive or "").lower()

    def hx(v, name, nbytes=None):
        if v is None:
            raise ValueError("%s is required" % name)
        try:
            b = bytes.fromhex(v)
        except ValueError:
            raise ValueError("%s must be hex" % name)
        if nbytes is not None and len(b) != nbytes:
            raise ValueError("%s must be %d bytes, got %d" % (name, nbytes, len(b)))
        return b

    try:
        if kind in ("res-star", "xres-star"):
            ck, ik = hx(a.ck, "--ck", 16), hx(a.ik, "--ik", 16)
            sn, rand, res = hx(a.sn, "--sn"), hx(a.rand, "--rand", 16), hx(a.res, "--res")
            out = res_star(ck + ik, sn, rand, res)
            rows = [("res_star", out.hex().upper()),
                    ("key", "CK||IK, %d bytes" % (len(ck) + len(ik))),
                    ("rand", rand.hex().upper()),
                    ("res", res.hex().upper()),
                    ("source", "TS 33.501 Annex A.4: rightmost 128 bits of "
                               "KDF(CK||IK, FC=0x6B, SN || RAND || RES)")]
        elif kind == "hxres":
            rand = hx(a.rand, "--rand", 16)
            rs = hx(a.xres_star or a.res_star, "--xres-star", 16)
            out = hxres_star(rand, rs)
            rows = [("hxres_star", out.hex().upper()),
                    ("rand", rand.hex().upper()),
                    ("res_star", rs.hex().upper()),
                    ("source", "TS 33.501 Annex A.5: rightmost 128 bits of "
                               "SHA-256(RAND || RES*)")]
        elif kind == "kausf":
            ck, ik = hx(a.ck, "--ck", 16), hx(a.ik, "--ik", 16)
            sn, sqn_ak = hx(a.sn, "--sn"), hx(a.sqn_ak, "--sqn-ak", 6)
            out = kausf(ck + ik, sn, sqn_ak)
            rows = [("kausf", out.hex().upper()),
                    ("key", "CK||IK, %d bytes" % (len(ck) + len(ik))),
                    ("sqn_ak", sqn_ak.hex().upper()),
                    ("source", "TS 33.501 Annex A.4.1: KDF(CK||IK, FC=0x6A, "
                               "SN || SQN xor AK), 256 bits")]
        elif kind == "kseaf":
            sn = hx(a.sn, "--sn")
            k = hx(a.key, "--key", 32)
            out = kseaf(k, sn)
            rows = [("kseaf", out.hex().upper()),
                    ("source", "TS 33.501 Annex A.6: KDF(KAUSF, FC=0x6C, SN), 256 bits")]
        else:
            print("ERROR\t--derive wants res-star, hxres, kausf or kseaf",
                  file=sys.stderr)
            return 2
    except ValueError as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 1
    print("derived\t%s" % kind)
    for k, v in rows:
        print("%s\t%s" % (k, v))
    return 0


def _cli_hxres(a) -> int:
    """--hxres --res-star <hex> --rand <hex>."""
    if not a.res_star or not a.rand:
        print("ERROR\t--hxres needs --res-star and --rand", file=sys.stderr)
        return 2
    try:
        res_star_b = bytes.fromhex(a.res_star)
        rand_b = bytes.fromhex(a.rand)
    except ValueError:
        print("ERROR\t--res-star and --rand must be hex", file=sys.stderr)
        return 1
    try:
        out = hxres_star(rand_b, res_star_b)
    except ValueError as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 1
    print("res_star\t%s" % res_star_b.hex().upper())
    print("rand\t%s" % rand_b.hex().upper())
    print("hxres_star\t%s" % out.hex().upper())
    print("source\tTS 33.501 Annex A.5: HXRES* = rightmost 128 bits of SHA-256(RAND || RES*)")
    return 0


# ============================================================ 128-EEA/EIA
#
# EEA0/EIA0 (null) need no code. EEA1/EIA1 are SNOW 3G (TS 35.201/35.202),
# EEA2/EIA2 are AES (TS 33.401 annex B), EEA3/EIA3 are ZUC (TS 35.221).
# Every suite below is checked by --selftest against its published vectors;
# none of them is derived from another suite here.

_ZUC_S0 = bytes.fromhex(
    "3e725b47cae0003304d1549809b96dcb7b1bf932af9d6aa5b82dfc1d08530390"
    "4d4e8499e4ced991ddb685488b296eaccdc1f81e734369c6b5bdfd396320d438"
    "767db2a7cfed57c5f32cbb142106559be3ef5e314f7f5aa40d8251495fba581c"
    "4a16d517a892241f8cffd8ae2e01d3ad3b4bda46ebc9de9a8f87d73a806f2fc8"
    "b1b437f70a2213287ccc3c89c7c3965607bf7ef00b2b975235417961a64c10fe"
    "bc2695888ab0a3fbc01894f2e1e5e95dd0dc1166645cec59427512f5749caa23"
    "0e86abbe2a02e767e644a26cc2939ff1f6fa36d250689e6271153dd640c4e20f"
    "8e83776b25053f0c30ea70b7a1e8a9658d271adb81b3a0f4457a19dfee783460")

_ZUC_S1 = bytes.fromhex(
    "55c263713bc847869f3cda5b29aafd778cc5940ca61a1300e3a8167240f9f842"
    "4426689681d9453e1076c6a78b3943e13ab5562ac06db3052266bfdc0bfa6248"
    "dd20110636c9c1cff62752bb69f5d4877f844cd29c57a4bc4f9adffed68d7aeb"
    "2b53d85ca11417fb23d57d3067730809eeb7703f61b2198e4ee54b938f5ddba9"
    "adf1ae2ecb0dfcf42d466e1d97e8d1e94d37a5755e839eab829db91ce0cd4989"
    "01b6bd5824a25f387899159050b895e4d091c7ceed0fb46fa0ccf0024a79c3de"
    "a3efea51e66b18ec1b2c80f774e7ff215a6a541e41319235c433070aba7e0e34"
    "88b1987cf33d606c7bcad31f3265042864be859b2f598ad7b025acaf1203e2f2")

_SNOW_SQ = bytes.fromhex(
    "25247367d7ae5c30a4ee6ecb7db582dbe48e48494f5d6a787088e85f5e8465e2"
    "d8e9cced402f112857d2ace34a151bb9b28085a62e024729074b0ec151aa89d4"
    "ca0146b3efdd447bc27fbec39f204c6483a2684213b441cdbac6bb6d4d7121f4"
    "8db0e593fe8fe6cf43453122373696fabc0f08521d551ac54e23697a92ff5b5a"
    "eb9a1ca9d17e0dfc508ab662f50af8dc033c0c39f1b8f33df2d597668132a000"
    "06cef6eab717f78c79d6a7bf8b3f1f536375352c60fd27d394a57ca105582dbd"
    "d9c7af6b540be03804c89de714b1879cdf6ff9da2ac459167491ab266176342b"
    "ad99fb72ec3312de983bc09b3e18103a56e177c91e9e95a39019a86c09d0f086")

_M32 = 0xFFFFFFFF
_ZUC_M31 = 0x7FFFFFFF
_ZUC_KD = (0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
           0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC)


# ------------------------------------------------------------- SNOW 3G
def _mulx(v, c):
    return (((v << 1) & 0xFF) ^ c) if (v & 0x80) else ((v << 1) & 0xFF)


def _mulxpow(v, i, c):
    for _ in range(i):
        v = _mulx(v, c)
    return v


_MULA = tuple((_mulxpow(c, 23, 0xA9) << 24) | (_mulxpow(c, 245, 0xA9) << 16)
              | (_mulxpow(c, 48, 0xA9) << 8) | _mulxpow(c, 239, 0xA9) for c in range(256))
_DIVA = tuple((_mulxpow(c, 16, 0xA9) << 24) | (_mulxpow(c, 39, 0xA9) << 16)
              | (_mulxpow(c, 6, 0xA9) << 8) | _mulxpow(c, 64, 0xA9) for c in range(256))


def _snow_sbox(w, box, cte):
    """S1 (box = AES S-box, cte = 0x1B) and S2 (box = SQ, cte = 0x69)."""
    s0 = box[(w >> 24) & 0xFF]
    s1 = box[(w >> 16) & 0xFF]
    s2 = box[(w >> 8) & 0xFF]
    s3 = box[w & 0xFF]
    return (((_mulx(s0, cte) ^ s1 ^ s2 ^ _mulx(s3, cte) ^ s3) & 0xFF) << 24
            | ((_mulx(s0, cte) ^ s0 ^ _mulx(s1, cte) ^ s2 ^ s3) & 0xFF) << 16
            | ((s0 ^ _mulx(s1, cte) ^ s1 ^ _mulx(s2, cte) ^ s3) & 0xFF) << 8
            | ((s0 ^ s1 ^ _mulx(s2, cte) ^ s2 ^ _mulx(s3, cte)) & 0xFF))


class Snow3G:
    """SNOW 3G LFSR + FSM keystream generator (TS 35.201 section 4)."""

    __slots__ = ("s", "r")

    def __init__(self, key, iv):
        k0, k1, k2, k3 = key
        i0, i1, i2, i3 = iv
        n0, n1, n2, n3 = (~k0) & _M32, (~k1) & _M32, (~k2) & _M32, (~k3) & _M32
        self.s = [n0, n1, n2, n3, k0, k1, k2, k3,
                  n0, n1 ^ i3, n2 ^ i2, n3, k0 ^ i1, k1, k2, k3 ^ i0]
        self.r = [0, 0, 0]
        for _ in range(32):
            self._init_mode(self._fsm())

    def _fsm(self):
        s, r = self.s, self.r
        f = ((s[15] + r[0]) & _M32) ^ r[1]
        rr = (r[1] + (r[2] ^ s[5])) & _M32
        r[2] = _snow_sbox(r[1], _SNOW_SQ, 0x69)
        r[1] = _snow_sbox(r[0], SBOX, 0x1B)
        r[0] = rr
        return f

    def _step(self, feed):
        s = self.s
        v = ((s[0] << 8) & _M32) ^ _MULA[(s[0] >> 24) & 0xFF] ^ s[2] ^ (s[11] >> 8) ^ _DIVA[s[11] & 0xFF]
        if feed is not None:
            v ^= feed
        s.pop(0)
        s.append(v & _M32)

    def _init_mode(self, feed):
        self._step(feed)

    def words(self, n):
        self._fsm()                         # the two warm-up clocks
        self._step(None)
        out = []
        for _ in range(n):
            out.append(self._fsm() ^ self.s[0])
            self._step(None)
        return out


def _snow_iv(count, bearer, direction, integrity):
    """TS 35.202 section 4.4; the f9 variant swaps FRESH for BEARER||0^27.

    The integrity IV carries DIRECTION in the top bits of IV[8] and IV[14]
    (TS 33.401 annex B.2.2), which is why the two halves differ.
    """
    fresh = (bearer << 27) & _M32
    if integrity:
        return [fresh ^ ((direction << 15) & _M32), (count ^ (direction << 31)) & _M32, fresh, count]
    conf = fresh | ((direction << 26) & _M32)
    return [conf, count, conf, count]


def _snow_keys(key16):
    return [int.from_bytes(key16[i * 4:i * 4 + 4], 'big') for i in (3, 2, 1, 0)]


def _mask_tail(buf, length):
    """Clear the bits past LENGTH in the final octet a caller gave us."""
    n = length >> 3
    rem = length & 7
    if not rem:
        return bytes(buf[:n])
    tail = buf[n:n + 1] or b'\x00'
    return bytes(buf[:n]) + bytes([tail[0] & ((0xFF << (8 - rem)) & 0xFF)])


def _keystream_bytes(words, nbytes):
    return b''.join(w.to_bytes(4, 'big') for w in words)[:nbytes]


def eea1(ck, count, bearer, direction, data, length):
    """128-EEA1 — SNOW 3G keystream XORed with the message."""
    st = Snow3G(_snow_keys(ck), _snow_iv(count, bearer, direction, False))
    nbytes = (length + 7) >> 3
    ks = _keystream_bytes(st.words((nbytes + 3) // 4), nbytes)
    return _mask_tail(bytes(a ^ b for a, b in zip(ks, data)), length)


def _gf64(v, p, c):
    r = 0
    for i in range(64):
        if (p >> i) & 1:
            x = v
            for _ in range(i):
                x = (((x << 1) ^ c) & 0xFFFFFFFFFFFFFFFF) if (x >> 63) & 1 else ((x << 1) & 0xFFFFFFFFFFFFFFFF)
            r ^= x
    return r


def eia1(ik, count, bearer, direction, data, length):
    """128-EIA1 — SNOW 3G f9 over the message, 32-bit MAC."""
    st = Snow3G(_snow_keys(ik), _snow_iv(count, bearer, direction, True))
    z = _keystream_bytes(st.words(5), 20)
    p = int.from_bytes(z[0:8], 'big')
    q = int.from_bytes(z[8:16], 'big')
    otp = int.from_bytes(z[16:20], 'big')
    blocks = ((length + 0x3F) >> 6) + 1
    ev = 0
    for i in range(blocks - 2):
        ev = _gf64(ev ^ int.from_bytes(data[i * 8:i * 8 + 8], 'big'), p, 0x1B)
    rem = bytes(data[8 * (blocks - 2):8 * (blocks - 1)]).ljust(8, b'\x00')
    ev = _gf64(ev ^ int.from_bytes(rem, 'big'), p, 0x1B)
    ev = _gf64(ev ^ length, q, 0x1B)
    return ((ev >> 32) ^ otp).to_bytes(4, 'big')


# ----------------------------------------------------------------- ZUC
def _rot32(a, k):
    return ((a << k) | (a >> (32 - k))) & _M32


def _add31(a, b):
    s = a + b
    return (s & _ZUC_M31) + (s >> 31)


def _rot31(a, k):
    a &= _ZUC_M31
    return ((a << k) | (a >> (31 - k))) & _ZUC_M31


def _zuc_l1(x):
    return (x ^ _rot32(x, 2) ^ _rot32(x, 10) ^ _rot32(x, 18) ^ _rot32(x, 24)) & _M32


def _zuc_l2(x):
    return (x ^ _rot32(x, 8) ^ _rot32(x, 14) ^ _rot32(x, 22) ^ _rot32(x, 30)) & _M32


def _zuc_s(x):
    return ((_ZUC_S0[x >> 24] << 24) | (_ZUC_S1[(x >> 16) & 0xFF] << 16)
            | (_ZUC_S0[(x >> 8) & 0xFF] << 8) | _ZUC_S1[x & 0xFF]) & _M32


class Zuc:
    """ZUC keystream generator (TS 35.221 sections 3.2-3.4)."""

    __slots__ = ("s", "r1", "r2")

    def __init__(self, key, iv):
        self.s = [((key[i] << 23) | (_ZUC_KD[i] << 8) | iv[i]) & _M32 for i in range(16)]
        self.r1 = self.r2 = 0
        for _ in range(32):
            x0, x1, x2 = self._br3()
            f = ((x0 ^ self.r1) + self.r2) & _M32
            self.r1, self.r2 = self._fsm(x1, x2)
            self._lfsr(f >> 1)
        x1, x2 = self._br2()
        self.r1, self.r2 = self._fsm(x1, x2)
        self._lfsr(None)

    def _br3(self):
        s = self.s
        return ((((s[15] & 0x7FFF8000) << 1) | (s[14] & 0xFFFF)) & _M32,
                (((s[11] & 0xFFFF) << 16) | (s[9] >> 15)) & _M32,
                (((s[7] & 0xFFFF) << 16) | (s[5] >> 15)) & _M32)

    def _br2(self):
        s = self.s
        return ((((s[11] & 0xFFFF) << 16) | (s[9] >> 15)) & _M32,
                (((s[7] & 0xFFFF) << 16) | (s[5] >> 15)) & _M32)

    def _fsm(self, x1, x2):
        w1 = (self.r1 + x1) & _M32
        w2 = (self.r2 ^ x2) & _M32
        u = _zuc_l1(((w1 << 16) & _M32) | (w2 >> 16))
        v = _zuc_l2(((w2 << 16) & _M32) | (w1 >> 16))
        return _zuc_s(u), _zuc_s(v)

    def _lfsr(self, u):
        s = self.s
        v = s[0]
        v = _add31(v, _rot31(s[0], 8))
        v = _add31(v, _rot31(s[4], 20))
        v = _add31(v, _rot31(s[10], 21))
        v = _add31(v, _rot31(s[13], 17))
        v = _add31(v, _rot31(s[15], 15))
        if u is not None:
            v = _add31(v, u)
        elif v == 0:
            v = _ZUC_M31                  # the LFSR state may never be zero
        s.pop(0)
        s.append(v & _ZUC_M31)

    def words(self, n):
        out = []
        for _ in range(n):
            x0, x1, x2 = self._br3()
            x3 = (((self.s[2] & 0xFFFF) << 16) | (self.s[0] >> 15)) & _M32
            f = ((x0 ^ self.r1) + self.r2) & _M32
            out.append((f ^ x3) & _M32)
            self.r1, self.r2 = self._fsm(x1, x2)
            self._lfsr(None)
        return out


def _zuc_iv(count, bearer, direction, integrity):
    """TS 35.221 section 3.3; EIA3 also injects DIRECTION into IV[8] and IV[14]."""
    iv = [(count >> 24) & 0xFF, (count >> 16) & 0xFF, (count >> 8) & 0xFF, count & 0xFF]
    if integrity:
        iv.append((bearer << 3) & 0xF8)
        d = (direction << 7) & 0x80
        iv += [0, 0, 0]
        iv += [iv[0] ^ d, iv[1], iv[2], iv[3]]
        iv += [iv[4], iv[5], iv[6] ^ d, iv[7]]
    else:
        iv.append(((bearer << 3) | (direction << 2)) & 0xFC)
        iv += [0, 0, 0]
        iv += [iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]]
    return iv


def eea3(ck, count, bearer, direction, data, length):
    """128-EEA3 — ZUC keystream XORed with the message."""
    st = Zuc(ck, _zuc_iv(count, bearer, direction, False))
    nbytes = (length + 7) >> 3
    ks = _keystream_bytes(st.words((nbytes + 3) // 4), nbytes)
    return _mask_tail(bytes(a ^ b for a, b in zip(ks, data)), length)


def eia3(ik, count, bearer, direction, data, length):
    """128-EIA3 — ZUC MAC over a bit stream, 32-bit output."""
    st = Zuc(ik, _zuc_iv(count, bearer, direction, True))
    bits = ''.join(format(b, '08b') for b in data)[:length]
    nwords = ((length + 31) >> 5) + 2
    words = st.words(nwords)
    zbits = ''.join(format(w, '032b') for w in words)
    t = 0
    for i in range(length):
        if bits[i] == '1':
            t ^= int(zbits[i:i + 32], 2)
    return ((t ^ int(zbits[length:length + 32], 2)) ^ words[nwords - 1]).to_bytes(4, 'big')


# ------------------------------------------------------- AES: EEA2 / EIA2
def _ctr_block(count, bearer, direction, index):
    """TS 33.401 annex B.1.3: COUNT || BEARER || DIRECTION || 0^26 || index."""
    return (count.to_bytes(4, 'big')
            + bytes([((bearer << 3) | (direction << 2)) & 0xFC]) + b'\x00\x00\x00'
            + index.to_bytes(8, 'big'))


def eea2(ck, count, bearer, direction, data, length):
    """128-EEA2 — AES-128 in counter mode."""
    rk = _aes_expand(ck)
    nbytes = (length + 7) >> 3
    ks = b''.join(_aes_encrypt_block(rk, _ctr_block(count, bearer, direction, i))
                  for i in range((nbytes + 15) >> 4))[:nbytes]
    return _mask_tail(bytes(a ^ b for a, b in zip(ks, data)), length)


def _cmac_subkeys(rk):
    l = int.from_bytes(_aes_encrypt_block(rk, b'\x00' * 16), 'big')
    k1 = ((l << 1) & ((1 << 128) - 1)) ^ (0x87 if (l >> 127) & 1 else 0)
    k2 = ((k1 << 1) & ((1 << 128) - 1)) ^ (0x87 if (k1 >> 127) & 1 else 0)
    return k1.to_bytes(16, 'big'), k2.to_bytes(16, 'big')


def _bits_to_block(bits):
    return bytes(int(bits[i:i + 8], 2) for i in range(0, 128, 8))


def eia2(ik, count, bearer, direction, data, length):
    """128-EIA2 — AES-128-CMAC over COUNT||BEARER||DIR||0^26||MESSAGE, 32-bit MAC.

    CMAC is defined on bit strings (TS 33.401 annex B.2.3), so the digest is
    assembled as bits and only converted back to octets per 128-bit block: a
    3GPP message whose bit length is not a multiple of 8 leaves the low bits of
    its final octet undefined and they must not be invented.
    """
    rk = _aes_expand(ik)
    k1, k2 = _cmac_subkeys(rk)
    head = (count.to_bytes(4, 'big')
            + bytes([((bearer << 3) | (direction << 2)) & 0xFC]) + b'\x00\x00\x00')
    bits = (''.join(format(b, '08b') for b in head)
            + ''.join(format(b, '08b') for b in data)[:length])
    nfull = (len(bits) + 127) // 128
    body = bits[:128 * (nfull - 1)]
    tail = bits[128 * (nfull - 1):]
    if len(tail) == 128:
        last = _xor(_bits_to_block(tail), k1)
    else:
        last = _xor(_bits_to_block(tail + '1' + '0' * (127 - len(tail))), k2)
    x = bytes(16)
    for i in range(0, len(body), 128):
        x = _aes_encrypt_block(rk, _xor(x, _bits_to_block(body[i:i + 128])))
    return _aes_encrypt_block(rk, _xor(x, last))[:4]


EEA = {1: eea1, 2: eea2, 3: eea3}
EIA = {1: eia1, 2: eia2, 3: eia3}
EEA_NAMES = {0: "128-EEA0 null", 1: "128-EEA1 SNOW 3G", 2: "128-EEA2 AES-CTR", 3: "128-EEA3 ZUC"}
EIA_NAMES = {0: "128-EIA0 null", 1: "128-EIA1 SNOW 3G", 2: "128-EIA2 AES-CMAC", 3: "128-EIA3 ZUC"}


def _crypto_kat_checks():
    """Yield (name, ok, detail) for every Milenage/TUAK known-answer test."""
    for n, (key_h, pt_h, ct_h) in enumerate(AES128_VECTORS, 1):
        got = aes128_enc(bytes.fromhex(key_h), bytes.fromhex(pt_h))
        yield ("aes128-%d" % n, got.hex() == ct_h,
               "want=%s got=%s" % (ct_h, got.hex()))
    for n, v in enumerate(KECCAK_VECTORS, 1):
        (k_in, k_out) = v
        got = tuk_perm(bytes.fromhex(k_in), 1)
        yield ("keccak-%d" % n, got.hex() == k_out,
               "want=%s got=%s" % (k_out, got.hex()))
    for n, v in enumerate(MILENAGE_VECTORS, 1):
        (k_h, op_h, rand_h, sqn_h, amf_h, opc_h) = v[:6]
        want = v[6:]
        try:
            k = parse_hex(k_h, 16, "K")
            op = parse_hex(op_h, 16, "OP")
            rand = parse_hex(rand_h, 16, "RAND")
            sqn = parse_hex(sqn_h, 6, "SQN")
            amf = parse_hex(amf_h, 2, "AMF")
        except ValueError as exc:
            yield ("milenage-%d" % n, False, str(exc))
            continue
        opc = milenage_opc(k, op)
        if opc.hex() != opc_h:
            yield ("milenage-%d-opc" % n, False, "want=%s got=%s" % (opc_h, opc.hex()))
            continue
        got = milenage(k, opc, rand, sqn, amf)
        for lab, w in zip(("f1", "f1*", "f2", "f3", "f4", "f5", "f5*"), want):
            yield ("milenage-%d-%s" % (n, lab), got[lab].hex() == w,
                   "want=%s got=%s" % (w, got[lab].hex()))
    for n, v in enumerate(TUAK_F1_VECTORS, 1):
        (k_h, top_h, rand_h, sqn_h, amf_h, kl, ml, it, topc_h, f1_h, f1s_h) = v
        try:
            k = parse_hex(k_h, kl // 8, "K")
            top = parse_hex(top_h, 32, "TOP")
            rand = parse_hex(rand_h, 16, "RAND")
            sqn = parse_hex(sqn_h, 6, "SQN")
            amf = parse_hex(amf_h, 2, "AMF")
        except ValueError as exc:
            yield ("tuak-f1-%d" % n, False, str(exc))
            continue
        topc = tuak_topc(top, k, kl, it)
        if topc.hex() != topc_h:
            yield ("tuak-f1-%d-topc" % n, False, "want=%s got=%s" % (topc_h, topc.hex()))
            continue
        got1 = tuak_f1(k, topc, rand, sqn, amf, kl, ml, it)
        got1s = tuak_f1(k, topc, rand, sqn, amf, kl, ml, it, f1star=True)
        yield ("tuak-f1-%d-f1" % n, got1.hex() == f1_h,
               "want=%s got=%s" % (f1_h, got1.hex()))
        yield ("tuak-f1-%d-f1*" % n, got1s.hex() == f1s_h,
               "want=%s got=%s" % (f1s_h, got1s.hex()))
    for n, v in enumerate(TUAK_F2F5_VECTORS, 1):
        (k_h, top_h, rand_h, kl, ckl, ikl, rl, it, topc_h,
         f2_h, f3_h, f4_h, f5_h, f5s_h) = v
        try:
            k = parse_hex(k_h, kl // 8, "K")
            top = parse_hex(top_h, 32, "TOP")
            rand = parse_hex(rand_h, 16, "RAND")
        except ValueError as exc:
            yield ("tuak-f2345-%d" % n, False, str(exc))
            continue
        topc = tuak_topc(top, k, kl, it)
        if topc.hex() != topc_h:
            yield ("tuak-f2345-%d-topc" % n, False, "want=%s got=%s" % (topc_h, topc.hex()))
            continue
        got = tuak_f2f5(k, topc, rand, kl, rl, ckl, ikl, it)
        got5s = tuak_f5star(k, topc, rand, kl, it)
        for lab, w, g in (("f2", f2_h, got["f2"]), ("f3", f3_h, got["f3"]),
                          ("f4", f4_h, got["f4"]), ("f5", f5_h, got["f5"]),
                          ("f5*", f5s_h, got5s)):
            yield ("tuak-f2345-%d-%s" % (n, lab), g.hex() == w,
                   "want=%s got=%s" % (w, g.hex()))


# --------------------------------------------------------------------- A5/1
# Three LFSRs of 19, 22 and 23 bits, the middle bit of each voting on which
# registers clock, output the parity of the three top bits. The published
# reference reverse-engineering (Briceno/Goldberg/Wagner 1998) is why A5/1 is
# the one GSM cipher with an agreed vector.
_R1MASK, _R2MASK, _R3MASK = 0x07FFFF, 0x3FFFFF, 0x7FFFFF
_R1MID, _R2MID, _R3MID = 0x000100, 0x000400, 0x000400
_R1TAPS, _R2TAPS, _R3TAPS = 0x072000, 0x300000, 0x700080
_R1OUT, _R2OUT, _R3OUT = 0x040000, 0x200000, 0x400000


if hasattr(int, "bit_count"):           # Python 3.10+, and 6x faster
    def _par(value: int) -> int:
        return value.bit_count() & 1
else:                                   # older interpreters still work
    def _par(value: int) -> int:
        return bin(value).count("1") & 1


def _clkone(reg: int, mask: int, taps: int) -> int:
    return ((reg << 1) & mask) | _par(reg & taps)


class A51:
    """GSM A5/1. `kc` is the key as a little-endian integer (see
    a51_kc_int), `count` the 22-bit frame count (see a51_count_from_fn)."""

    def __init__(self, kc: int, count: int):
        self.r1 = self.r2 = self.r3 = 0
        for i in range(64):
            self.clock_all()
            bit = (kc >> i) & 1
            self.r1 ^= bit
            self.r2 ^= bit
            self.r3 ^= bit
        for i in range(22):
            self.clock_all()
            bit = (count >> i) & 1
            self.r1 ^= bit
            self.r2 ^= bit
            self.r3 ^= bit
        for _ in range(100):          # the specified warm-up
            self.step()

    def clock_all(self) -> None:
        self.r1 = _clkone(self.r1, _R1MASK, _R1TAPS)
        self.r2 = _clkone(self.r2, _R2MASK, _R2TAPS)
        self.r3 = _clkone(self.r3, _R3MASK, _R3TAPS)

    def step(self) -> None:
        maj = (((self.r1 & _R1MID) != 0) + ((self.r2 & _R2MID) != 0)
               + ((self.r3 & _R3MID) != 0)) >= 2
        if ((self.r1 & _R1MID) != 0) == maj:
            self.r1 = _clkone(self.r1, _R1MASK, _R1TAPS)
        if ((self.r2 & _R2MID) != 0) == maj:
            self.r2 = _clkone(self.r2, _R2MASK, _R2TAPS)
        if ((self.r3 & _R3MID) != 0) == maj:
            self.r3 = _clkone(self.r3, _R3MASK, _R3TAPS)

    def bit(self) -> int:
        return (_par(self.r1 & _R1OUT) ^ _par(self.r2 & _R2OUT)
                ^ _par(self.r3 & _R3OUT))

    def bits(self, n: int) -> list:
        # Registers are held in locals for the whole run: this is the inner
        # loop of the tradeoff table, where the attribute traffic dominates.
        r1, r2, r3 = self.r1, self.r2, self.r3
        m1, m2, m3 = _R1MID, _R2MID, _R3MID
        out = []
        append = out.append
        for _ in range(n):
            maj = (((r1 & m1) != 0) + ((r2 & m2) != 0) + ((r3 & m3) != 0)) >= 2
            if ((r1 & m1) != 0) == maj:
                r1 = ((r1 << 1) & _R1MASK) | _par(r1 & _R1TAPS)
            if ((r2 & m2) != 0) == maj:
                r2 = ((r2 << 1) & _R2MASK) | _par(r2 & _R2TAPS)
            if ((r3 & m3) != 0) == maj:
                r3 = ((r3 << 1) & _R3MASK) | _par(r3 & _R3TAPS)
            append(_par(r1 & _R1OUT) ^ _par(r2 & _R2OUT) ^ _par(r3 & _R3OUT))
        self.r1, self.r2, self.r3 = r1, r2, r3
        return out

    def keystream(self, n: int) -> str:
        return "".join(str(b) for b in self.bits(n))


def a51_kc_int(kc_hex: str) -> int:
    """Key octets arrive in transmission order and the loader consumes the
    first octet LSB-first, so the hex string is a little-endian integer: the
    official vector's {12,23,45,67,89,AB,CD,EF} loads as 0xEFCDAB8967452312."""
    if len(kc_hex) % 2:
        kc_hex = "0" + kc_hex
    octets = [kc_hex[i:i + 2] for i in range(0, len(kc_hex), 2)]
    return int("".join(reversed(octets)) or "0", 16)


def a51_count_from_fn(fn: int) -> int:
    """GSM frame number to the 22-bit COUNT, i.e. osmo_a5_fn_count():
    T1 = fn / (26*51), T2 = fn % 26, T3 = fn % 51, COUNT = T1<<11 | T3<<5 | T2.
    The 22 bits are therefore T1(11) | T3(6) | T2(5), not the raw frame
    number -- using the raw frame number is the classic way to get a
    keystream that matches nothing."""
    return ((fn // (26 * 51)) << 11) | ((fn % 51) << 5) | (fn % 26)


def a51_keystream(kc_hex: str, count, nbits: int = 228) -> str:
    """`nbits` keystream bits as a 0/1 string."""
    kc_hex = kc_hex.strip().lower()
    if len(kc_hex) != 16 or any(c not in "0123456789abcdef" for c in kc_hex):
        raise ValueError("Kc must be exactly 16 hex digits, got %r" % kc_hex)
    if nbits < 1 or nbits > 11400:
        raise ValueError("bit count must be 1..11400, got %r" % nbits)
    return A51(a51_kc_int(kc_hex),
               int(count, 0) if isinstance(count, str) else count).keystream(nbits)


def a51_hex(kc_hex: str, count, nbits: int = 228) -> str:
    """The keystream packed MSB-first into hex, for comparison against the
    published tables. Note 114-bit GSM blocks are not a whole nibble count,
    so the last nibble of a published 29-nibble row is padding: compare
    bit-for-bit with a51_keystream, never as hex."""
    bits = a51_keystream(kc_hex, count, nbits)
    out = ""
    for i in range(0, len(bits), 4):
        nib = bits[i:i + 4]
        nib = nib + "0" * (4 - len(nib))
        out += "%x" % int(nib, 2)
    return out


# Two independent published A5/1 vectors. One alone cannot catch a wrong tap
# or a wrong COUNT convention: a bug in reading the vector passes exactly as
# happily as a bug in the core. These differ in codebase, key, count and byte
# order. Both also carry an uplink row, and in both it is bits 114..227 of the
# SAME run -- A5/1 is one 228-bit generator per frame, downlink first, not two
# generators. That is asserted, because getting it wrong halves the keystream.
#   downlink/uplink are the published 29-nibble rows (last nibble padding).
A51_VECTORS = [
    # Briceno/Goldberg/Wagner pedagogical implementation, test() in
    # https://cryptome.org/jya/a51-pi.htm . Key bytes 12 23 45 67 89 AB CD EF,
    # COUNT 0x134.
    ("1223456789abcdef", 0x134,
     "534EAA582FE8151AB6E1855A728C00", "24FD35A35D5FB6526D32F906DF1AC0"),
    # libosmocore tests/a5/a5_test.c. Frame number 123456 (COUNT 0x2EC88 via
    # osmo_a5_fn_count); its loader reads the key bytes in reverse, so the
    # identical 64-bit key is written here reversed.
    ("efcdab8967452301", 0x2ec88,
     "CBA25576175D3B1C7B2F29A8C1B600", "D9035E0F2AEC139A05D4A87BB16480"),
]

# The COUNT conversion itself is a published value, checked separately because
# a wrong T1/T2/T3 packing produces a self-consistent keystream that no key
# vector would ever flag.
A51_COUNT_VECTORS = [
    (123456, 191624),        # osmo_a5_fn_count(123456), i.e. 0x2EC88
]


# ------------------------------------------------- A5/1 time-memory tradeoff
#
# THE HONEST SCOPE. Recovering Kc from an observed keystream is a search over
# a 2^64 key space -- 2^54 once COMP128's ten forced-zero key bits are
# discounted. That search is a rainbow-table or cluster job and is NOT run
# here, and nothing below claims otherwise. What is implemented and tested is
# the *table* half: the build and lookup interface such an attack needs, run
# at a width the caller names, so the whole method is exhaustively checkable.
# `--a51-tmto-demo` additionally cross-checks every hit against a direct
# keystream recomputation, which is what separates a real recovery from the
# false alarm a reduction function inevitably produces.
#
# The table is a rainbow table: the reduction carries the column index, so
# chains do not merge the way plain Hellman chains do. The build/lookup shape
# is identical to Hellman's.

class A51Table:
    """A rainbow table over `width` low bits of the A5/1 key integer.

    The key integer is masked to `width` bits for the demo: that is the
    analogue of the real attack's reduction from 2^54, and it is what makes
    the method checkable. `base` supplies the known high key bits.

    Cost, stated honestly: the table costs `chains * length` keystream
    evaluations to build, and a lookup costs up to `length^2 / 2` because
    every column alignment has to be tried. That is the textbook rainbow
    online phase -- `length` table probes, each behind a walk of up to
    `length` steps. It is fine at demo width and is exactly why the real
    2^54 table is a precomputed artifact rather than something built here.
    """

    def __init__(self, width=12, chains=256, length=64, ks_bits=32,
                 base=0, count=0, seed=1):
        if not 8 <= width <= 32:
            raise ValueError("width must be 8..32 (a wider table is a handoff, not a test)")
        if chains < 1 or length < 1:
            raise ValueError("chains and length must be positive")
        if ks_bits < width:
            raise ValueError("ks_bits must be at least the index width")
        self.width = width
        self.chains = chains
        self.length = length
        self.ks_bits = ks_bits
        self.base = base
        self.count = count
        self.seed = seed
        self.mask = (1 << width) - 1
        self.table = {}                # endpoint -> (start point, chain index)
        self.evaluations = 0
        self.collisions = 0
        self.false_alarms = 0

    def reduce(self, bits) -> int:
        """Fold a keystream bit string down to the index width."""
        v = 0
        for b in bits:
            v = ((v << 1) | b) & self.mask
        return v

    def column_value(self, x: int, column: int) -> int:
        """f_column(x): keystream of key x, reduced, salted by the column."""
        self.evaluations += 1
        ks = A51(self.base | (x & self.mask), self.count).bits(self.ks_bits)
        return (self.reduce(ks) ^ (column * 0x9E3779B1)) & self.mask

    def reduce_column(self, ks_bits, column: int) -> int:
        """R_column(keystream): the value f_column maps *from*."""
        return (self.reduce(ks_bits) ^ (column * 0x9E3779B1)) & self.mask

    def build(self) -> "A51Table":
        rnd = random.Random(self.seed)
        for idx in range(self.chains):
            start = rnd.getrandbits(self.width)
            x = start
            for column in range(self.length):
                x = self.column_value(x, column)
            if x in self.table:
                self.collisions += 1
                continue
            self.table[x] = (start, idx)
        return self

    def lookup(self, observed_bits):
        """Given the observed keystream bits, return a key that generates
        them, or None.

        For each column i we take R_i(observed) and push it through columns
        i+1..L-1.  If that lands on a stored endpoint, the chain may hold a
        key whose keystream is the observed one, so the chain is walked and
        every key on it is tested against the keystream directly.  The direct
        test is what makes a reduction collision (a "false alarm") cost time
        rather than a wrong answer.
        """
        for i in range(self.length - 1, -1, -1):
            v = self.reduce_column(observed_bits, i)
            for column in range(i + 1, self.length):
                v = self.column_value(v, column)
            hit = self.table.get(v)
            if hit is None:
                continue
            x = hit[0]
            for column in range(self.length):
                if A51(self.base | x, self.count).bits(self.ks_bits) == observed_bits:
                    return x
                x = self.column_value(x, column)
            self.false_alarms += 1       # endpoint matched, no key on the chain
        return None


def a51_tmto_demo(width=10, chains=48, length=24, ks_bits=24, trials=8,
                  seed=1, base=0, count=0):
    """Build a table and try to recover `trials` random keys from keystream
    alone. Returns a statistics dict. This is the self-contained proof that
    the build/lookup interface works; it is not the 2^54 attack."""
    t = A51Table(width=width, chains=chains, length=length, ks_bits=ks_bits,
                 base=base, count=count, seed=seed).build()
    rnd = random.Random(seed ^ 0x5EED)
    stats = {"width": width, "chains": chains, "length": length,
             "ks_bits": ks_bits, "table_entries": len(t.table),
             "build_evaluations": t.evaluations, "chain_collisions": t.collisions,
             "trials": trials, "chains_walked": 0, "recovered": 0,
             "false_alarms": 0, "keystream_collisions": 0, "missed": 0}
    mask = (1 << width) - 1
    for _ in range(trials):
        target_key = rnd.getrandbits(width) & mask
        observed = A51(base | target_key, count).bits(ks_bits)
        before = t.evaluations
        cand = t.lookup(observed)
        stats["chains_walked"] += t.evaluations - before
        if cand is None:
            stats["missed"] += 1
            continue
        # lookup() already confirmed cand regenerates the observed keystream;
        # equalling the original key as well is the end-to-end result.
        if cand == target_key:
            stats["recovered"] += 1
        else:
            stats["keystream_collisions"] += 1
    stats["lookup_evaluations"] = t.evaluations - stats["build_evaluations"]
    stats["recovery_rate"] = (stats["recovered"] / trials) if trials else 0.0
    return stats


def _a51_tmto_check():
    """Deterministic proof that the lookup works at every column alignment.

    Picking a random key and hoping the table contains it makes a flaky test.
    Instead one chain is walked to a start point that the table really holds,
    and then several of that chain's own values are used as targets: by
    construction each one is recoverable, and each exercises a different
    column offset in the online phase.
    """
    t = A51Table(width=8, chains=8, length=16, ks_bits=16, seed=7).build()
    rnd = random.Random(99)
    start = None
    for _ in range(500):
        s = rnd.getrandbits(8)
        x = s
        for column in range(t.length):
            x = t.column_value(x, column)
        if t.table.get(x, (None,))[0] == s:
            start = s
            break
    if start is None:
        return [("a51-tmto", False, "no chain survived the build")]
    chain = [start]
    x = start
    for column in range(t.length):
        x = t.column_value(x, column)
        chain.append(x)
    results = []
    for position in (1, t.length // 3, (2 * t.length) // 3, t.length - 1):
        target = chain[position]
        observed = A51(t.base | target, t.count).bits(t.ks_bits)
        got = t.lookup(observed)
        results.append(("a51-tmto-column-%d" % position, got == target,
                        "want=%d got=%s" % (target, got)))
    return results


# ---------------------------------------------------------------------------
# DPA / side-channel model for COMP128-1
# ---------------------------------------------------------------------------
#
# COMP128-1's compression function is a five-level butterfly of table lookups
# (Tables T0..T4, of 512/256/128/64/32 entries). Level 0 of the first round
# sees exactly one key byte and one challenge byte per position:
#
#     y = (x[a] + (x[b] << 1)) & 0x1FF,   x[a] = ki[j],  x[b] = rand[j]
#     x[a] = T0[y]
#
# so the ADDRESS of a level-0 lookup is (ki[j] + 2*rand[j]) & 511 — a function
# of one key byte and a value the attacker chooses. That is the classic target:
# guess the key byte, predict a power proxy for the lookup, and correlate the
# prediction against measured traces. The published proxy is the Hamming weight
# of the byte the lookup produces.
#
# WHAT THIS IS, AND WHAT IT IS NOT
#   * It IS a real correlation power analysis. The leakage model, the Pearson
#     correlation over all 256 hypotheses and the recovery decision are the
#     standard ones. The attack is validated by using the recovered key to
#     reproduce COMP128-1 on a challenge the trace set never contained — a
#     correlation peak on its own would prove nothing, reproducing the cipher
#     is what proves the key.
#   * It is NOT a measurement of any card. Traces are SYNTHETIC: generated
#     from the leakage model plus a controlled amount of Gaussian noise. The
#     point is to establish the trace count and signal-to-noise ratio the
#     attack needs before a capture rig is worth building, and to exercise the
#     analysis half end to end against a known ground truth.
#   * It is why COMP128-2 and COMP128-3 exist. Both were introduced to remove
#     the table-lookup leakage this attack depends on, so a v2/v3 card is not
#     covered by it. A key recovered here is a COMP128-1 key or nothing.
#
# The noise parameter is a standard deviation in the same units as the
# Hamming-weight leak (0..8). sigma=1.0 is roughly "one bit of the sbox output
# is lost in noise"; sigma=4.0 drowns the signal almost completely.

_DPA_MODEL = None
DPA_SIGMA_DEFAULT = 1.0
DPA_TRACES_DEFAULT = 512


def dpa_hw(value):
    """Hamming weight of a byte — the standard power proxy for a table lookup."""
    return bin(value & 0xFF).count("1")


def dpa_addr(ki_byte, rand_byte):
    """The level-0 T0 address: (ki[j] + 2*rand[j]) & 511."""
    return (ki_byte + 2 * rand_byte) & 0x1FF


def dpa_leak(ki_byte, rand_byte):
    """Modelled power for one level-0 lookup, before noise."""
    return dpa_hw(COMP128_T0[dpa_addr(ki_byte, rand_byte)])


def dpa_leak_weighted(ki_byte, rand_byte, weights):
    """A leak with unequal per-bit cost — the realistic deviation from Hamming
    weight. Each set bit of the T0 output contributes weights[bit] instead of
    1.0, so weights of all 1.0 reproduces dpa_leak exactly."""
    v = COMP128_T0[dpa_addr(ki_byte, rand_byte)]
    return sum(weights[b] for b in range(8) if v & (1 << b))


def dpa_leak_addr(ki_byte, rand_byte):
    """A deliberately WRONG model: leaks the lookup address instead of the
    value it produces. Kept so the attack's dependence on the correct model can
    be demonstrated rather than asserted."""
    return float(dpa_hw(dpa_addr(ki_byte, rand_byte)))


def dpa_weights(spread=0.0, seed=7):
    """Eight per-bit costs with mean 1.0 and standard deviation `spread`."""
    rng = random.Random(seed)
    return [1.0 + (rng.gauss(0.0, spread) if spread else 0.0) for _ in range(8)]


def dpa_synth(ki, rands, sigma=DPA_SIGMA_DEFAULT, seed=1, gain=1.0,
              model="hw", spread=0.0, model_seed=7):
    """Synthetic traces: one row per RAND, one column per key byte.

    Row t, column j is the leak of the level-0 lookup for key byte j under
    challenge rands[t], scaled by `gain` and perturbed by Gaussian noise of
    standard deviation `sigma`.

    `model` selects the leak the traces are BUILT from — the attack always
    assumes Hamming weight, so anything other than "hw" measures what happens
    when the attacker's model is wrong:
      "hw"       Hamming weight of the T0 output (the published proxy)
      "weighted" Hamming weight with unequal per-bit costs (`spread`)
      "addr"     Hamming weight of the address, not the data
    """
    if len(ki) != 16:
        raise ValueError("ki must be 16 bytes")
    weights = dpa_weights(spread, model_seed) if model == "weighted" else None
    rng = random.Random(seed)
    traces = []
    for r in rands:
        if len(r) != 16:
            raise ValueError("every RAND must be 16 bytes")
        row = []
        for j in range(16):
            if model == "hw":
                v = float(dpa_leak(ki[j], r[j]))
            elif model == "weighted":
                v = dpa_leak_weighted(ki[j], r[j], weights)
            elif model == "addr":
                v = dpa_leak_addr(ki[j], r[j])
            else:
                raise ValueError("unknown leak model: %r" % (model,))
            v *= gain
            if sigma:
                v += rng.gauss(0.0, sigma)
            row.append(v)
        traces.append(row)
    return traces


def _dpa_model_table():
    """MODEL[guess][rand_byte] = predicted leak. Built once, 65536 entries."""
    global _DPA_MODEL
    if _DPA_MODEL is None:
        _DPA_MODEL = [bytes(dpa_hw(COMP128_T0[(g + 2 * rb) & 0x1FF])
                            for rb in range(256)) for g in range(256)]
    return _DPA_MODEL


def dpa_pearson(xs, ys):
    """Pearson correlation coefficient, 0.0 when either side is constant."""
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    sxy = sxx = syy = 0.0
    for a, b in zip(xs, ys):
        da = a - mx
        db = b - my
        sxy += da * db
        sxx += da * da
        syy += db * db
    if sxx <= 0.0 or syy <= 0.0:
        return 0.0
    return sxy / ((sxx ** 0.5) * (syy ** 0.5))


def dpa_rank(rand_column, samples):
    """Score all 256 key-byte hypotheses, best first. Returns [(r, guess)]."""
    model = _dpa_model_table()
    scored = []
    for g in range(256):
        row = model[g]
        scored.append((dpa_pearson([row[rb] for rb in rand_column], samples), g))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return scored


def dpa_recover(rands, traces):
    """Recover all 16 key bytes independently. Returns (ki, per_byte_report)."""
    if len(rands) != len(traces):
        raise ValueError("rands and traces must be the same length")
    ki = bytearray(16)
    report = []
    for j in range(16):
        column = [r[j] for r in rands]
        samples = [t[j] for t in traces]
        scored = dpa_rank(column, samples)
        best_r, best_g = scored[0]
        runner_r = scored[1][0]
        ki[j] = best_g
        report.append({
            "position": j,
            "guess": best_g,
            "r": best_r,
            "runner_up_guess": scored[1][1],
            "runner_up_r": runner_r,
            "margin": best_r - runner_r,
        })
    return bytes(ki), report


def dpa_run(ki, n_traces=DPA_TRACES_DEFAULT, sigma=DPA_SIGMA_DEFAULT, seed=1,
            model="hw", spread=0.0, model_seed=7):
    """End-to-end: synthesise, attack, then verify on held-out challenges."""
    rng = random.Random((seed * 2654435761) & 0xFFFFFFFF)
    rands = [bytes(rng.randrange(256) for _ in range(16)) for _ in range(n_traces)]
    traces = dpa_synth(ki, rands, sigma=sigma, seed=seed, model=model,
                       spread=spread, model_seed=model_seed)
    recovered, report = dpa_recover(rands, traces)
    holdout = [bytes(rng.randrange(256) for _ in range(16)) for _ in range(4)]
    mismatches = sum(1 for h in holdout
                     if comp128v1(recovered, h) != comp128v1(ki, h))
    mean_margin = sum(p["margin"] for p in report) / 16.0
    return {
        "true_ki": ki,
        "recovered_ki": recovered,
        "exact": recovered == ki,
        "bytes_wrong": sum(1 for a, b in zip(recovered, ki) if a != b),
        "holdout_checked": len(holdout),
        "holdout_mismatches": mismatches,
        "verified": mismatches == 0,
        "traces": n_traces,
        "sigma": sigma,
        "seed": seed,
        "model": model,
        "spread": spread,
        "per_byte": report,
        "mean_margin": mean_margin,
    }


def dpa_noise_sweep(ki, sigmas, n_traces=DPA_TRACES_DEFAULT, seed=1):
    """How much noise the attack survives at a fixed trace count."""
    out = []
    for s in sigmas:
        r = dpa_run(ki, n_traces=n_traces, sigma=s, seed=seed)
        out.append((s, r["exact"], r["verified"], r["mean_margin"]))
    return out


def dpa_trace_sweep(ki, counts, sigma=DPA_SIGMA_DEFAULT, seed=1):
    """How many traces the attack needs at a fixed noise level."""
    out = []
    for n in counts:
        r = dpa_run(ki, n_traces=n, sigma=sigma, seed=seed)
        out.append((n, r["exact"], r["verified"], r["mean_margin"]))
    return out


def dpa_mismatch_sweep(ki, spreads, n_traces=DPA_TRACES_DEFAULT, seed=1,
                       sigma=0.0):
    """What the attack does when its leakage model is WRONG.

    Traces are built with unequal per-bit costs (`spread`); the attack still
    assumes plain Hamming weight. This is the failure mode that matters in
    practice — a real card's leak is never exactly the textbook proxy — and it
    is the one experiment here that cannot come out perfect by construction.
    """
    out = []
    for s in spreads:
        r = dpa_run(ki, n_traces=n_traces, sigma=sigma, seed=seed,
                    model="weighted", spread=s)
        out.append((s, r["bytes_wrong"], r["exact"], r["verified"],
                    r["mean_margin"]))
    r = dpa_run(ki, n_traces=n_traces, sigma=sigma, seed=seed, model="addr")
    out.append(("addr", r["bytes_wrong"], r["exact"], r["verified"],
                r["mean_margin"]))
    return out


# ---------------------------------------------------------------------------
# selftest / CLI
# ---------------------------------------------------------------------------

DPA_TEST_KI = "465b5ce8b199b49faa5f0a2ee238a6bc"


def _dpa_checks():
    """Checks for the DPA model.

    The load-bearing one is `dpa-recovers-comp128v1-ki`: the recovered key has
    to reproduce COMP128-1 on a challenge the trace set never contained. A
    correlation peak would prove nothing, so `dpa-wrong-model-fails` is its
    companion — it confirms the attack fails when the leakage model targets the
    wrong quantity, which is what stops the first check passing by accident.
    """
    results = []
    # Correlations are compared with a tolerance: the arithmetic is exact for
    # these inputs but the comparison must not depend on the last bit.
    def near(x, want):
        return abs(x - want) < 1e-9
    got = dpa_pearson([1.0, 2.0, 3.0], [2.0, 4.0, 6.0])
    results.append(("dpa-pearson-linear", near(got, 1.0),
                    "want=1.0 got=%.17g" % got))
    got = dpa_pearson([1.0, 2.0, 3.0], [6.0, 4.0, 2.0])
    results.append(("dpa-pearson-anti", near(got, -1.0),
                    "want=-1.0 got=%.17g" % got))
    got = dpa_pearson([1.0, 2.0, 3.0], [5.0, 5.0, 5.0])
    results.append(("dpa-pearson-constant", got == 0.0,
                    "a constant column has no correlation, got=%.17g" % got))
    # By hand: ki[0]=0x46=70, rand[0]=0x23=35 -> 70 + 2*35 = 140.
    got = dpa_addr(0x46, 0x23)
    results.append(("dpa-level0-address", got == 140, "want=140 got=%d" % got))

    ki = bytes.fromhex(DPA_TEST_KI)
    r = dpa_run(ki, n_traces=128, sigma=0.0, seed=1)
    results.append(("dpa-recovers-comp128v1-ki", r["verified"],
                    "recovered=%s wrong=%d" % (r["recovered_ki"].hex(), r["bytes_wrong"])))
    r2 = dpa_run(ki, n_traces=128, sigma=0.0, seed=1, model="addr")
    results.append(("dpa-wrong-model-fails", not r2["exact"],
                    "the address model recovered the key, so the model is not being tested"))
    r3 = dpa_run(ki, n_traces=256, sigma=2.0, seed=3)
    results.append(("dpa-survives-sigma-2", r3["verified"],
                    "wrong=%d recovered=%s" % (r3["bytes_wrong"], r3["recovered_ki"].hex())))
    return results


def _eea_eia_kat_checks():
    """Yield (name, ok, detail) for every EEA/EIA published test vector."""
    h = bytes.fromhex
    f8 = (
        (1, "2bd6459f82c5b300952c49104881ff48", 0x72a4f20f, 0x0c, 1, 798,
         "7ec61272743bf1614726446a6c38ced166f6ca76eb5430044286346cef130f9292"
         "2b03450d3a9975e5bd2ea0eb55ad8e1b199e3ec4316020e9a1b285e762795359b7"
         "bdfd39bef4b2484583d5afe082aee638bf5fd5a606193901a08f4ab41aab9b134880",
         "8ceba62943dced3a0990b06ea1b0a2c4fb3cedc71b369f42ba64c1eb6665e72a"
         "a1c9bb0deaa20fe86058b8baee2c2e7f0becce48b52932a53c9d5f931a3a7c53"
         "2259af4325e2a65e3084ad5f6a513b7bddc1b65f0aa0d97a053db55a88c4c4f9"
         "605e4140"),
        (3, "5acb1d644c0d51204ea5f1451010d852", 4199901990, 0x03, 1, 120,
         "ad9c441f890b38c457a49d421407e8", "ba0f31300334c56b52a7497cbac046"),
    )
    for n, ck, count, bearer, direction, length, pt, ct in f8:
        got = eea1(h(ck), count, bearer, direction, h(pt), length)
        yield ("eea1-set%d" % n, got.hex() == ct, "want=%s got=%s" % (ct, got.hex()))
    f9 = (
        (1, "2bd6459f82c5b300952c49104881ff48", 0x38a6f056, 0x1f, 0, 88,
         "3332346263393861373479", "731f1165"),
        (3, "d3419be821087acd02123a9248033359", 0xc7590ea9, 0x17, 0, 511,
         "bbb057038809496bcff86d6fbc8ce5b135a06b166054f2d565be8ace75dc851e0b"
         "cdd8f07141c495872fb5d8c0c66a8b6da556663e4e461205d84580bee5bc7e",
         "9a16c77d"),
    )
    for n, ik, count, bearer, direction, length, msg, mac in f9:
        got = eia1(h(ik), count, bearer, direction, h(msg), length)
        yield ("eia1-set%d" % n, got.hex() == mac, "want=%s got=%s" % (mac, got.hex()))
    got = eea2(h("d3c5d592327fb11c4035c6680af8c6d1"), 0x398a59b4, 0x15, 1,
               h("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0"), 253)
    want = "e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78"
    yield ("eea2-set1", got.hex() == want, "want=%s got=%s" % (want, got.hex()))
    got = eia2(h("2bd6459f82c5b300952c49104881ff48"), 0x38a6f056, 0x18, 0,
               h("3332346263393840"), 58)
    yield ("eia2-set1", got.hex() == "118c6eb8", "want=118c6eb8 got=%s" % got.hex())
    # TS 35.222 test vector 1 and 2 exercise ZUC with a zero key and IV, which
    # is the only published keystream KAT for the generator itself.
    w = Zuc(bytes(16), bytes(16)).words(2)
    got = "%08X%08X" % (w[0], w[1])
    yield ("zuc-tv1", got == "27BEDE74018082DA", "want=27BEDE74018082DA got=%s" % got)
    w = Zuc(bytes([0xFF] * 16), bytes([0xFF] * 16)).words(2)
    got = "%08X%08X" % (w[0], w[1])
    yield ("zuc-tv2", got == "0657CFA07096398B", "want=0657CFA07096398B got=%s" % got)
    eia3_sets = (
        (1, "c9e6cec4607c72db000aefa88385ab0a", 0xa94059da, 0x0a, 1, 577,
         "983b41d47d780c9e1ad11d7eb70391b1de0b35da2dc62f83e7b78d6306ca0ea0"
         "7e941b7be91348f9fcb170e2217fecd97f9f68adb16e5d7d21e569d280ed775c"
         "ebde3f4093c5388100000000", "fae8ff0b"),
        (2, "47054125561eb2dda94059da05097850", 0x561eb2dd, 0x14, 0, 90,
         "000000000000000000000000", "6719a088"),
    )
    for n, ik, count, bearer, direction, length, msg, mac in eia3_sets:
        got = eia3(h(ik), count, bearer, direction, h(msg), length)
        yield ("eia3-set%d" % n, got.hex() == mac, "want=%s got=%s" % (mac, got.hex()))


def _cli_eea_eia(a) -> int:
    if a.message is None:
        print("ERROR\t--eea/--eia need --message", file=sys.stderr)
        return 2
    if a.count is None:
        print("ERROR\t--eea/--eia need --count", file=sys.stderr)
        return 2
    key_hex = a.ck if a.eea is not None else a.ik
    if not key_hex:
        print("ERROR\t--eea needs --ck, --eia needs --ik", file=sys.stderr)
        return 2
    if not 0 <= a.bearer <= 31:
        print("ERROR\t--bearer is 5 bits, 0..31", file=sys.stderr)
        return 2
    try:
        key = parse_hex(key_hex, 16, "CK" if a.eea is not None else "IK")
        msg = parse_hex(a.message, len(a.message) // 2, "MESSAGE")
        count = int(a.count, 16) if a.count.lower().startswith("0x") else int(a.count)
    except ValueError as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 1
    length = a.bit_length if a.bit_length is not None else len(msg) * 8
    if length > len(msg) * 8:
        print("ERROR\t--bit-length %d exceeds the %d bits of --message"
              % (length, len(msg) * 8), file=sys.stderr)
        return 2
    if count >> 32:
        print("ERROR\t--count is 32 bits", file=sys.stderr)
        return 2
    if a.eea is not None:
        algo = a.eea
        print("algorithm\t%s" % EEA_NAMES[algo])
        fn = EEA.get(algo)
    else:
        algo = a.eia
        print("algorithm\t%s" % EIA_NAMES[algo])
        fn = EIA.get(algo)
    print("count\t0x%08X" % count)
    print("bearer\t%d" % a.bearer)
    print("direction\t%d (%s)" % (a.direction,
                                   "downlink" if a.direction else "uplink"))
    print("bit_length\t%d" % length)
    print("message\t%s" % msg[:length // 8 + (1 if length % 8 else 0)].hex().upper())
    if fn is None:
        # EEA0/EIA0 is the null algorithm: nothing is computed and nothing is
        # claimed to have been computed.
        print("output\t%s" % msg[:length // 8 + (1 if length % 8 else 0)].hex().upper())
        print("note\tnull algorithm: no ciphering or integrity applied")
        return 0
    out = fn(key, count, a.bearer, a.direction, msg, length)
    print("%s\t%s" % ("keystream_output" if a.eea is not None else "mac",
                       out.hex().upper()))
    return 0


def selftest() -> int:
    bad = 0
    for algo, vectors in COMP128_KNOWN_ANSWERS.items():
        for ki_hex, rand_hex, sres_hex, kc_hex in vectors:
            try:
                sres, kc = auth_vector(algo, ki_hex, rand_hex)
            except ValueError as exc:
                print("%s-%-40s FAIL %s" % (algo, ki_hex[:32], exc))
                bad += 1
                continue
            got = (sres + kc).hex().upper()
            want = (sres_hex + kc_hex).upper()
            name = "%s-%s-%s" % (algo, ki_hex[:8], rand_hex[:8])
            if got == want:
                print("%-40s PASS" % name)
            else:
                print("%-40s FAIL want=%s got=%s" % (name, want, got))
                bad += 1
    # Milenage / Keccak / TUAK, one summary line per published test set.
    order, groups = [], {}
    for name, ok, detail in _crypto_kat_checks():
        key = name if name.startswith("keccak-") else "-".join(name.split("-")[:2])
        if key not in groups:
            groups[key] = [0, 0, []]
            order.append(key)
        groups[key][0 if ok else 1] += 1
        if not ok:
            groups[key][2].append("%s %s" % (name, detail))
    for key in order:
        npass, nfail, fails = groups[key]
        if nfail:
            print("%-40s FAIL %d of %d: %s"
                  % (key, nfail, npass + nfail, "; ".join(fails[:3])))
            bad += nfail
        else:
            print("%-40s PASS %d checks" % (key, npass))
    # EEA1/EEA2/EEA3 and EIA1/EIA2/EIA3, one summary line per published set.
    for name, ok, detail in _eea_eia_kat_checks():
        print("%-40s %s" % (name, "PASS" if ok else "FAIL " + detail))
        bad += 0 if ok else 1
    # A5/1 against its two independent published vectors, both rows of each.
    for n, (kc, count, down, up) in enumerate(A51_VECTORS, 1):
        try:
            ks = a51_keystream(kc, count, 228)
        except ValueError as exc:
            print("%-40s FAIL %s" % ("a5-1-vector-%d" % n, exc))
            bad += 1
            continue
        for lab, want, got in (
                ("downlink", down, ks[:114]),
                ("uplink", up, ks[114:228])):
            wantbits = "".join(format(int(c, 16), "04b") for c in want)[:114]
            if got == wantbits:
                print("%-40s PASS" % ("a5-1-vector-%d-%s" % (n, lab)))
            else:
                print("%-40s FAIL want=%s got=%s"
                      % ("a5-1-vector-%d-%s" % (n, lab), wantbits, got))
                bad += 1
    for fn, want in A51_COUNT_VECTORS:
        got = a51_count_from_fn(fn)
        if got == want:
            print("%-40s PASS" % ("a5-1-count-fn%d" % fn))
        else:
            print("%-40s FAIL want=%#x got=%#x" % ("a5-1-count-fn%d" % fn, want, got))
            bad += 1
    # The tradeoff table, deterministically: recover keys that are known to be
    # on a stored chain, at four different online-phase column alignments.
    for name, ok, detail in _a51_tmto_check():
        if ok:
            print("%-40s PASS" % name)
        else:
            print("%-40s FAIL %s" % (name, detail))
            bad += 1
    # The DPA model. Checked against a held-out COMP128-1 challenge, not
    # against its own correlation output.
    for name, ok, detail in _dpa_checks():
        if ok:
            print("%-40s PASS" % name)
        else:
            print("%-40s FAIL %s" % (name, detail))
            bad += 1
    # A wrong length must be refused, not zero-filled.
    for algo in COMP128:
        try:
            auth_vector(algo, "00", "00")
            print("%-40s FAIL short input was accepted" % (algo + "-rejects-short"))
            bad += 1
        except ValueError:
            print("%-40s PASS" % (algo + "-rejects-short"))
    print("RESULT\t%s" % ("PASS" if bad == 0 else "FAIL(%d)" % bad))
    return 1 if bad else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="IMSIsting GSM/UMTS crypto primitives")
    p.add_argument("--selftest", action="store_true", help="run known-answer tests")
    p.add_argument("--comp128", metavar="ALGO", choices=sorted(COMP128),
                   help="derive SRES and Kc with COMP128 v1/v2/v3")
    p.add_argument("--ki", help="KI, 32 hex digits (16 for a 128-bit TUAK key)")
    p.add_argument("--rand", help="RAND, 32 hex digits")
    p.add_argument("--milenage", action="store_true",
                   help="Milenage f1..f5* from --ki, --rand and --op or --opc")
    p.add_argument("--op", help="Milenage OP, 32 hex digits (OPC is derived)")
    p.add_argument("--opc", help="Milenage OPC, 32 hex digits (instead of --op)")
    p.add_argument("--tuak", action="store_true",
                   help="TUAK f1..f5* from --ki, --rand and --top")
    p.add_argument("--top", help="TUAK TOP, 64 hex digits (TOPC is derived)")
    p.add_argument("--sqn", help="SQN, 12 hex digits (needed for f1/f1*)")
    p.add_argument("--amf", help="AMF, 4 hex digits (needed for f1/f1*)")
    p.add_argument("--klength", type=int, default=128, choices=(128, 256),
                   help="TUAK key length in bits (default 128)")
    p.add_argument("--iterations", type=int, default=1, choices=(1, 2),
                   help="Keccak iterations (TUAK default 1)")
    # TUAK output lengths are per-vector, not fixed by the algorithm: a TS 35.232
    # test set names MAC_sz, RES_sz, CK_sz and IK_sz for each row, and the same
    # inputs produce different f2..f5 for different RES_sz. The defaults below are
    # the ones this CLI has always used, so the output of an existing command is
    # unchanged; the flags exist because without them a standard vector whose row
    # says RES_sz=32 could never be reproduced from the command line at all, and
    # the TSV now states the sizes it actually used.
    p.add_argument("--mac-sz", type=int, default=64, choices=(64, 128),
                   help="TUAK MAC_sz in bits (default 64)")
    p.add_argument("--res-sz", type=int, default=64, choices=(32, 64, 128, 256),
                   help="TUAK RES_sz in bits (default 64)")
    p.add_argument("--ck-sz", type=int, default=128, choices=(128, 256),
                   help="TUAK CK_sz in bits (default 128)")
    p.add_argument("--ik-sz", type=int, default=128, choices=(128, 256),
                   help="TUAK IK_sz in bits (default 128)")
    p.add_argument("--kdf", metavar="FC",
                   help="5G KDF (TS 33.220 B.2): octet FC in hex, with --key and "
                        "--p0/--p1/--p2")
    p.add_argument("--key", help="KDF key, hex (K for 0x6A/0x6B, KAUSF for 0x6C)")
    p.add_argument("--p0", help="KDF parameter P0, hex (SN name for every FC here)")
    p.add_argument("--p1", help="KDF parameter P1, hex (SQN xor AK, or RAND)")
    p.add_argument("--p2", help="KDF parameter P2, hex (RES, for RES*)")
    p.add_argument("--derive", metavar="WHAT",
                   help="named 5G derivation: res-star, hxres, kausf or kseaf")
    p.add_argument("--ck", help="CK, hex, 16 bytes (KDF key is CK||IK)")
    p.add_argument("--ik", help="IK, hex, 16 bytes")
    p.add_argument("--sn", help="serving network name, hex (UTF-8 bytes)")
    p.add_argument("--sqn-ak", help="SQN xor AK, hex, 6 bytes")
    p.add_argument("--res", help="RES, hex, 8 or 16 bytes")
    p.add_argument("--xres-star", help="XRES*, hex, 16 bytes")
    p.add_argument("--hxres", action="store_true",
                   help="HXRES* from --res-star and --rand (TS 33.501 A.9)")
    p.add_argument("--res-star", help="RES* (or XRES*), hex, 16 bytes")
    p.add_argument("--keccak", metavar="HEX",
                   help="raw Keccak-f[1600] on exactly 200 bytes of hex")
    p.add_argument("--eea", type=int, choices=(0, 1, 2, 3), metavar="ALGO",
                   help="128-EEA ciphering of --message under --ck, --count, "
                        "--bearer, --direction and --bit-length")
    p.add_argument("--eia", type=int, choices=(0, 1, 2, 3), metavar="ALGO",
                   help="128-EIA integrity MAC of --message under --ik, --count, "
                        "--bearer, --direction and --bit-length")
    p.add_argument("--bearer", type=int, default=0,
                   help="5-bit radio bearer identity 0..31 (default 0)")
    p.add_argument("--direction", type=int, default=0, choices=(0, 1),
                   help="0 = uplink, 1 = downlink (default 0)")
    p.add_argument("--message", help="message to protect, hex")
    p.add_argument("--bit-length", type=int,
                   help="length of --message in bits (default: every bit given)")
    p.add_argument("--a51", action="store_true",
                   help="A5/1 keystream from --kc and --count")
    p.add_argument("--kc", help="Kc, 16 hex digits in transmission order")
    p.add_argument("--count", help="22-bit COUNT (or use --a51-count with a frame number)")
    p.add_argument("--bits", type=int, default=228,
                   help="keystream bits to produce (default 228, one frame)")
    p.add_argument("--a51-count", metavar="FRAME_NUMBER",
                   help="convert a GSM frame number to its 22-bit COUNT")
    p.add_argument("--a51-tmto-demo", action="store_true",
                   help="build a reduced-width A5/1 TMTO table and attack it")
    p.add_argument("--chains", type=int, help="TMTO chains (default 48)")
    p.add_argument("--length", type=int, help="TMTO chain length (default 24)")
    p.add_argument("--width", type=int, help="TMTO index width in bits (default 10)")
    p.add_argument("--trials", type=int, help="TMTO random targets to try (default 8)")
    p.add_argument("--dpa-leak", action="store_true",
                   help="show the COMP128-1 level-0 DPA leakage point for --ki and --rand")
    p.add_argument("--dpa-sim", action="store_true",
                   help="synthetic-trace DPA against --ki, verified on held-out challenges")
    p.add_argument("--dpa-sweep", action="store_true",
                   help="DPA noise, trace-count and leakage-model-mismatch sweeps")
    p.add_argument("--traces", type=int, help="DPA traces to synthesise (default 512)")
    p.add_argument("--sigma", type=float, help="DPA trace noise, std dev (default 1.0)")
    p.add_argument("--seed", type=int, help="DPA RNG seed (default 1)")
    p.add_argument("--model", choices=("hw", "weighted", "addr"),
                   help="leakage model the TRACES are built from (default hw)")
    p.add_argument("--spread", type=float, help="per-bit cost spread for --model weighted")
    a = p.parse_args(argv)

    if a.selftest:
        return selftest()
    if a.eea is not None or a.eia is not None:
        return _cli_eea_eia(a)
    if a.derive:
        return _cli_derive(a)
    if a.hxres:
        return _cli_hxres(a)
    if a.kdf is not None:
        return _cli_kdf(a)
    if a.keccak:
        try:
            inb = parse_hex(a.keccak, 200, "KECCAK input")
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        print(tuk_perm(inb, a.iterations).hex().upper())
        return 0
    if a.a51_count:
        if not a.a51_count.isdigit():
            print("ERROR\t--a51-count needs a frame number 0..2715647", file=sys.stderr)
            return 2
        fn = int(a.a51_count)
        if fn > 2715647:
            print("ERROR\tframe number out of range 0..2715647", file=sys.stderr)
            return 1
        count = a51_count_from_fn(fn)
        print("frame_number\t%d" % fn)
        print("count\t%d" % count)
        print("count_hex\t0x%X" % count)
        return 0
    if a.a51:
        if not a.kc or a.count is None:
            print("ERROR\t--a51 needs --kc and --count", file=sys.stderr)
            return 2
        try:
            ks = a51_keystream(a.kc, a.count, a.bits)
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        print("kc\t%s" % a.kc.upper())
        print("count\t%s" % a.count)
        print("bits\t%d" % a.bits)
        print("keystream\t%s" % ks)
        print("keystream_hex\t%s"
              % "".join("%x" % int((ks[i:i + 4] + "0000")[:4], 2)
                        for i in range(0, len(ks), 4)))
        return 0
    if a.a51_tmto_demo:
        try:
            stats = a51_tmto_demo(
                width=a.width or 10, chains=a.chains or 48,
                length=a.length or 24, ks_bits=max(24, a.width or 10),
                trials=a.trials or 8)
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        print("scope\treduced-width demonstration, NOT the 2^54 attack")
        for key in ("width", "chains", "length", "ks_bits", "table_entries",
                    "chain_collisions", "build_evaluations", "trials",
                    "recovered", "missed", "false_alarms",
                    "keystream_collisions", "lookup_evaluations"):
            print("%s\t%s" % (key, stats[key]))
        print("recovery_rate\t%.3f" % stats["recovery_rate"])
        if stats["recovered"] == 0:
            print("verdict\tno key recovered at this table size; widen the table", file=sys.stderr)
            return 1
        print("verdict\ttable interface works: %d of %d keys recovered from keystream alone"
              % (stats["recovered"], stats["trials"]))
        return 0
    if a.dpa_leak:
        if not a.ki or not a.rand:
            print("ERROR\t--dpa-leak needs --ki and --rand", file=sys.stderr)
            return 2
        try:
            k = parse_hex(a.ki, 16, "KI")
            rand = parse_hex(a.rand, 16, "RAND")
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        print("implementation\tcomp128v1")
        print("leak_point\tround 0, level 0: x[a] = T0[(ki[j] + 2*rand[j]) & 511]")
        print("power_proxy\tHamming weight of the byte T0 returns")
        print("table\tCOMP128_T0, %d entries of one byte" % len(COMP128_T0))
        print("ki\t%s" % a.ki.upper())
        print("rand\t%s" % a.rand.upper())
        for j in range(16):
            addr = dpa_addr(k[j], rand[j])
            v = COMP128_T0[addr]
            print("pos_%02d\tki=%02X rand=%02X addr=%d t0=%02X hw=%d"
                  % (j, k[j], rand[j], addr, v, dpa_hw(v)))
        print("positions\t16")
        print("note\tone key byte per position, and RAND is attacker-chosen, "
              "which is what makes each position independently attackable")
        return 0
    if a.dpa_sim or a.dpa_sweep:
        if not a.ki:
            print("ERROR\t--dpa-sim/--dpa-sweep need --ki", file=sys.stderr)
            return 2
        try:
            k = parse_hex(a.ki, 16, "KI")
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        traces = a.traces or DPA_TRACES_DEFAULT
        sigma = DPA_SIGMA_DEFAULT if a.sigma is None else a.sigma
        seed = a.seed or 1
        if a.dpa_sweep:
            print("scope\tsynthetic traces, leakage model assumed, not a measured card")
            print("ki\t%s" % k.hex().upper())
            print("sweep\tnoise (sigma, 512 traces, hw model)")
            for s, exact, verified, margin in dpa_noise_sweep(
                    k, (0.0, 0.5, 1.0, 2.0, 3.0, 5.0), n_traces=traces, seed=seed):
                print("noise_sigma_%.1f\texact=%s verified=%s margin=%.4f"
                      % (s, exact, verified, margin))
            print("sweep\ttrace count (sigma=1.0, hw model)")
            for n, exact, verified, margin in dpa_trace_sweep(
                    k, (16, 32, 64, 128, 256, 512), sigma=1.0, seed=seed):
                print("traces_%03d\texact=%s verified=%s margin=%.4f"
                      % (n, exact, verified, margin))
            print("sweep\tleakage-model mismatch (sigma=0, %d traces); the attack "
                  "always assumes Hamming weight" % traces)
            for s, wrong, exact, verified, margin in dpa_mismatch_sweep(
                    k, (0.0, 0.25, 0.5, 1.0, 2.0), n_traces=traces, seed=seed):
                print("model_spread_%s\tbytes_wrong=%d exact=%s verified=%s margin=%.4f"
                      % (s, wrong, exact, verified, margin))
            print("note\tthe 'addr' row leaks the wrong quantity and is expected "
                  "to fail; a sweep where it succeeds is not testing the model")
            return 0
        r = dpa_run(k, n_traces=traces, sigma=sigma, seed=seed,
                    model=a.model or "hw", spread=a.spread or 0.0)
        print("scope\tsynthetic traces from a leakage model, not a measured card")
        print("true_ki\t%s" % r["true_ki"].hex().upper())
        print("recovered_ki\t%s" % r["recovered_ki"].hex().upper())
        print("traces\t%d" % r["traces"])
        print("sigma\t%s" % r["sigma"])
        print("leak_model\t%s" % r["model"])
        print("leak_spread\t%s" % r["spread"])
        print("bytes_wrong\t%d" % r["bytes_wrong"])
        print("mean_peak_r\t%.4f"
              % (sum(p["r"] for p in r["per_byte"]) / 16.0))
        print("mean_margin\t%.4f" % r["mean_margin"])
        print("holdout_challenges\t%d" % r["holdout_checked"])
        print("holdout_mismatches\t%d" % r["holdout_mismatches"])
        for p in r["per_byte"]:
            print("byte_%02d\tguess=%02X r=%.4f runner_up=%02X r=%.4f margin=%.4f"
                  % (p["position"], p["guess"], p["r"], p["runner_up_guess"],
                     p["runner_up_r"], p["margin"]))
        if not r["verified"]:
            print("verdict\tcharacterised failure: recovered key does NOT reproduce "
                  "COMP128-1 on the held-out challenges", file=sys.stderr)
            return 1
        print("verdict\trecovered key reproduces COMP128-1 on %d challenges the "
              "trace set never contained" % r["holdout_checked"])
        return 0
    if a.milenage:
        if not a.ki or not a.rand or not (a.op or a.opc):
            print("ERROR\t--milenage needs --ki, --rand and --op or --opc",
                  file=sys.stderr)
            return 2
        try:
            k = parse_hex(a.ki, 16, "KI")
            rand = parse_hex(a.rand, 16, "RAND")
            opc = (parse_hex(a.opc, 16, "OPC") if a.opc
                   else milenage_opc(k, parse_hex(a.op, 16, "OP")))
            sqn = parse_hex(a.sqn, 6, "SQN") if a.sqn else None
            amf = parse_hex(a.amf, 2, "AMF") if a.amf else None
            out = milenage(k, opc, rand, sqn, amf)
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        print("algorithm\tmilenage")
        print("ki\t%s" % a.ki.upper())
        print("opc\t%s" % opc.hex().upper())
        for name in ("f1", "f1*", "f2", "f3", "f4", "f5", "f5*"):
            if name in out:
                print("%s\t%s" % (name, out[name].hex().upper()))
        return 0
    if a.tuak:
        if not a.ki or not a.rand or not a.top:
            print("ERROR\t--tuak needs --ki, --rand and --top", file=sys.stderr)
            return 2
        try:
            k = parse_hex(a.ki, a.klength // 8, "KI")
            top = parse_hex(a.top, 32, "TOP")
            rand = parse_hex(a.rand, 16, "RAND")
            sqn = parse_hex(a.sqn, 6, "SQN") if a.sqn else None
            amf = parse_hex(a.amf, 2, "AMF") if a.amf else None
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        it, kl = a.iterations, a.klength
        mac, res, ck, ik = a.mac_sz, a.res_sz, a.ck_sz, a.ik_sz
        topc = tuak_topc(top, k, kl, it)
        print("algorithm\ttuak")
        print("ki\t%s" % a.ki.upper())
        print("topc\t%s" % topc.hex().upper())
        print("keccak_iterations\t%d" % it)
        # Stated because these are per-vector parameters: a reader comparing
        # against a TS 35.232 row has to know which row's sizes produced these
        # values, and RES_sz in particular changes f2..f5.
        print("mac_sz\t%d" % mac)
        print("res_sz\t%d" % res)
        print("ck_sz\t%d" % ck)
        print("ik_sz\t%d" % ik)
        if sqn is not None and amf is not None:
            print("f1\t%s"
                  % tuak_f1(k, topc, rand, sqn, amf, kl, mac, it).hex().upper())
            print("f1*\t%s"
                  % tuak_f1(k, topc, rand, sqn, amf, kl, mac, it,
                            f1star=True).hex().upper())
        got = tuak_f2f5(k, topc, rand, kl, res, ck, ik, it)
        for name in ("f2", "f3", "f4", "f5"):
            print("%s\t%s" % (name, got[name].hex().upper()))
        print("f5*\t%s" % tuak_f5star(k, topc, rand, kl, it).hex().upper())
        return 0
    if a.comp128:
        if not a.ki or not a.rand:
            print("ERROR\t--comp128 needs --ki and --rand", file=sys.stderr)
            return 2
        try:
            sres, kc = auth_vector(a.comp128, a.ki, a.rand)
        except ValueError as exc:
            print("ERROR\t%s" % exc, file=sys.stderr)
            return 1
        print("algorithm\tcomp128%s" % a.comp128)
        print("ki\t%s" % a.ki.upper())
        print("rand\t%s" % a.rand.upper())
        print("sres\t%s" % sres.hex().upper())
        print("kc\t%s" % kc.hex().upper())
        return 0
    p.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
