#!/usr/bin/env python3
"""GSM/UMTS authentication and ciphering primitives for IMSIsting.

Implements, as known-answer-tested functions:

  * COMP128-1  -- the classic GSM A3/A8 (SRES + Kc)
  * COMP128-2  -- the v2 variant (Kc's low 10 bits forced to zero)
  * COMP128-3  -- the v3 variant

Run `--selftest` to check every one against published vectors.

PROVENANCE. The compression tables and the structure of the v2/v3 inner
function are ported from libosmocore's src/gsm/comp128.c and
src/gsm/comp128v23.c -- (C) 2009 Sylvain Munaut, GPL-2.0-or-later -- which are
themselves reimplementations of the leaked "Technical Information: GSM System
Security Study" (Racal Research, 10-1617-01, 1988), with the three documented
typos corrected, cross-checked against the Briceno/Goldberg/Wagner
reverse-engineering. The known-answer vectors are libosmocore's own test suite
(tests/comp128/comp128_test.c) plus the published examples from the `comp128`
PyPI package.

Inputs are checked strictly, and a wrong-length or non-hex value is an error
rather than a zero-filled result: a silently wrong SRES/Kc is worse than none.
"""
from __future__ import annotations

import argparse
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


# ---------------------------------------------------------------------------
# selftest / CLI
# ---------------------------------------------------------------------------

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
    p.add_argument("--ki", help="KI, 32 hex digits")
    p.add_argument("--rand", help="RAND, 32 hex digits")
    a = p.parse_args(argv)

    if a.selftest:
        return selftest()
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
