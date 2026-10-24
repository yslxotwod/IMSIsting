#!/usr/bin/env python3
"""KASUMI and the GPRS ciphering algorithms GEA3 and GEA4.

Standard library only. GEA3 and GEA4 are the two GEA variants 3GPP published in
full together with public test data, so they are the two that can be
implemented here and proved:

  GEA3  TS 55.216 V6.2.0, test data TS 55.217 V6.1.0 / TS 55.218 V6.1.0
  GEA4  TS 55.226 V9.0.0, test data in the same clause
  KASUMI TS 35.202 (the block cipher both are built on)

GEA1 and GEA2 were never published by 3GPP; they were recovered by
reverse engineering and published in the cryptanalysis literature (Beierle et
al., EUROCRYPT 2021; Amzaleg and Dinur, IACR ePrint 2022/424), which is also
where the attacks on them live. GEA5 is specified in TS 55.251 and tested in
TS 55.252, but every substantive clause of both is licence-gated, so its
algorithm body is not something this file can implement from public text.

Both GEA3 and GEA4 are KASUMI in an OFB-like keystream mode over a 64-bit
register built from the 32-bit frame input, the frame type byte, the direction
bit and a constant, with the session key XORed by 0x55 for a preliminary round.
The whole construction is TS 55.216 section 3.2 / TS 55.226 and is reproduced
from the specification, not from another implementation.
"""

import sys

# ── KASUMI S-boxes (TS 35.202 section 4.2) ───────────────────────────────────
S7 = [
        54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33,
        55, 113, 39, 114, 21, 67, 65, 12, 47, 73, 46, 27, 25, 111, 124, 81,
        53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40, 120, 104, 70, 71, 43,
        20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
        117, 116, 76, 11, 89, 106, 0, 125, 118, 99, 86, 69, 30, 57, 126, 87,
        112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35, 103, 32, 97, 28, 66,
        102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29, 115, 44,
        64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3,
]

S9 = [
        167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
        183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
        175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
        95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
        165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
        501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421, 350, 163,
        232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
        344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,
        487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
        475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
        363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
        439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
        465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61, 244, 282,
        173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330,
        280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
        132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,
        35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
        50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
        72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
        185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
        1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
        336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
        47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
        414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
        266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
        311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
        485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
        312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
        284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
        97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
        438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
        43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461,
]

M32 = 0xFFFFFFFF
M16 = 0xFFFF

# ── bit helpers ──────────────────────────────────────────────────────────────


def lsl(x, s, width):
    """s-bit left shift inside a width-bit register."""
    mask = (1 << width) - 1
    return ((x << s) | (x >> (width - s))) & mask


def lsl_zeros(x, s, width):
    """s-bit left shift with no wraparound (the <<n form in the spec)."""
    return (x << s) & ((1 << width) - 1)


# ── KASUMI primitives ────────────────────────────────────────────────────────


def fi(i, skey):
    """FI: 16-bit nonlinear function with a 16-bit subkey."""
    left = (i >> 7) & 0x1FF
    right = i & 0x7F
    left = S9[left] ^ right
    right = S7[right] ^ (left & 0x7F)
    left ^= skey & 0x1FF
    right ^= (skey >> 9) & 0x7F
    left = S9[left] ^ right
    right = S7[right] ^ (left & 0x7F)
    return ((right << 9) | left) & M16


def fo(i, ko, ki, rnd):
    """FO: 32-bit function, three FI rounds with its own subkeys."""
    left = (i >> 16) & M16
    right = i & M16

    left ^= ko[0][rnd]
    left = fi(left, ki[0][rnd])
    left ^= right

    right ^= ko[1][rnd]
    right = fi(right, ki[1][rnd])
    right ^= left

    left ^= ko[2][rnd]
    left = fi(left, ki[2][rnd])
    left ^= right

    return ((right << 16) | left) & M32


def fl(i, kl, rnd):
    """FL: 32-bit function that keeps the round keys in the data path."""
    left = (i >> 16) & M16
    right = i & M16
    tmp = left & kl[0][rnd]
    right ^= lsl(tmp, 1, 16)
    tmp = right | kl[1][rnd]
    left ^= lsl(tmp, 1, 16)
    return ((left << 16) | right) & M32


# ── key schedule (TS 35.202 section 4.4) ─────────────────────────────────────

C = [0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210]


def be16(key, i):
    return (key[2 * i] << 8) | key[2 * i + 1]


def key_expand(key):
    """Eighteen 16-bit round subkeys from a 16-octet key."""
    kprime = [C[i] ^ be16(key, i) for i in range(8)]
    kl = ([0] * 8, [0] * 8)
    ko = ([0] * 8, [0] * 8, [0] * 8)
    ki = ([0] * 8, [0] * 8, [0] * 8)
    for i in range(8):
        kl[0][i] = lsl(be16(key, i), 1, 16)
        kl[1][i] = kprime[(i + 2) & 7]
        ko[0][i] = lsl(be16(key, (i + 1) & 7), 5, 16)
        ko[1][i] = lsl(be16(key, (i + 5) & 7), 8, 16)
        ko[2][i] = lsl(be16(key, (i + 6) & 7), 13, 16)
        ki[0][i] = kprime[(i + 4) & 7]
        ki[1][i] = kprime[(i + 3) & 7]
        ki[2][i] = kprime[(i + 7) & 7]
    return kl, ko, ki


def kasumi(block, sk):
    """One 64-bit KASUMI encipherment."""
    kl, ko, ki = sk
    left = (block >> 32) & M32
    right = block & M32
    for i in range(0, 8, 2):
        right ^= fo(fl(left, kl, i), ko, ki, i)
        left ^= fl(fo(right, ko, ki, i + 1), kl, i + 1)
    return ((left << 32) | right) & 0xFFFFFFFFFFFFFFFF


# ── keystream generator (TR 55.919 section 8.2, TS 55.216 section 3.2) ──────


def keystream(ck, iv, direction, nbytes, frame_type=0xFF):
    """Gamma in `nbytes` octets, big-endian, for a 16-octet ck."""
    ca = frame_type
    cb = 0
    cc = iv & M32
    cd = direction & 1

    a = ((cc & M32) << 32) | ((cb << 3 | cd << 2) << 24) | (ca << 16)
    a &= 0xFFFFFFFFFFFFFFFF

    mod_key = bytes(b ^ 0x55 for b in ck)
    a = kasumi(a, key_expand(mod_key))
    sk = key_expand(ck)

    out = bytearray()
    blk = 0
    full = nbytes // 8
    for i in range(full):
        blk = kasumi(a ^ i ^ blk, sk)
        out += blk.to_bytes(8, "big")
    rest = nbytes - full * 8
    if rest:
        blk = kasumi(a ^ full ^ blk, sk)
        out += blk.to_bytes(8, "big")[:rest]
    return bytes(out)


def gea4(kc, iv, direction, nbytes):
    """GEA4: the 128-bit key is used as it stands (TS 55.226)."""
    if len(kc) != 16:
        raise ValueError("GEA4 needs a 16-octet key")
    return keystream(kc, iv, direction, nbytes, frame_type=0xFF)


def gea3(kc, iv, direction, nbytes):
    """GEA3: the 64-bit Kc is doubled to 128 bits, then the GEA4 core.

    TS 55.216 takes the GSM cipher key Kc and derives the 128-bit input as
    Kc||Kc (the C4 function, TS 33.102 section 6.8.2.3).
    """
    if len(kc) != 8:
        raise ValueError("GEA3 needs an 8-octet key")
    return keystream(kc + kc, iv, direction, nbytes, frame_type=0xFF)


# ── published test data ─────────────────────────────────────────────────────
# GEA3: 3GPP TS 55.217 V6.1.0 / TS 55.218 V6.1.0
# GEA4: 3GPP TS 55.226 V9.0.0
KAT = [
    ("GEA3", "2BD6459F82C5BC00", 0x8E9421A3, 0, 59,
     "5F359709DE950D0105B17B6C90194280F880B48DCCDC2AFEED415DBEF4354EEBB21D073CCBBFB2D706BD7AFFD371FC96E3970D143DCB2624054826"),
    ("GEA3", "952C49104881FF48", 0x5064DB71, 0, 59,
     "FDC03D738C8E14FF0320E59AAF75760799E9DA78DD8F888471C4AEAAC1849633A26CD84F459D265B83D7D9B9A0B1E54F4D75E331640DF19E0DB0E0"),
    ("GEA3", "EFA8B2229E720C2A", 0x4BDBD5E5, 1, 59,
     "4718A2ADFC90590949DDADAB406EC3B925F1AF1214673909DAAB96BB4C18B1374BB1E99445A81CC856E47C6E49E9DBB9873D0831B2175CA1E109BA"),
    ("GEA3", "3451F23A43BD2C87", 0x893FE14F, 0, 59,
     "B46B1E284E3F8B63B86D9DF0915CFCEDDF2F061895BF9F82BF2593AE4847E94A4626C393CF8941CE15EA7812690D8415B88C5730FE1F5D410E16A2"),
    ("GEA3", "CAA2639BE82435CF", 0x8FE17885, 1, 59,
     "9FEFAF155A26CF35603E727CDAA87BA067FD84FF98A50B7FF0EC8E95A0FB70E79CB93DEE2B7E9AB59D050E1262401571F349C68229DDF0DECC4E85"),
    ("GEA3", "1ACA8B448B767B39", 0x4F7BC3B5, 0, 59,
     "514F6C3A3B5A55CA190092F7BB6E80EF3EDB738FCDCE2FF90BB387DDE75BBC32A04A67B898A3DFB8198FFFC37D437CF69E7F9C13B51A868720E750"),
    ("GEA4", "D3C5D592327FB11C4035C6680AF8C6D1", 0x0A3A59B4, 0, 51,
     "6E217CE41EBEFB5EC8094C15974290065E42BABC9AE35654A53085CE68DFA4426A2FF0AD4AF3341006A3F84B7613ACB4FBDC34"),
    ("GEA4", "3D43C388C9581E337FF1F97EB5C1F85E", 0x48571AB9, 0, 59,
     "FC7314EF00A63ED0116F236C5D25C54EEC56A5B71F9F18B4D7941F84E422ACBDE5EEA9A204679002D14F312F3DEE2A1AC917C3FBDC3696143C0F5D"),
    ("GEA4", "A4496A64DF4F399F3B4506814A3E07A1", 0xEB04ADE2, 1, 59,
     "2AEB5970FB06B718027D048488AAF24FB3B74EA4A6B1242FF85B108FF816A303C72757D9AAD862B835D1D287DBC141D0A28D79D87BB137CD1198CD"),
]


def run_kat(verbose=False):
    """Every published vector, checked and reported row by row."""
    bad = 0
    for algo, kc_hex, iv, direction, nbytes, want in KAT:
        kc = bytes.fromhex(kc_hex)
        got = (gea3 if algo == "GEA3" else gea4)(kc, iv, direction, nbytes).hex().upper()
        ok = got == want.upper()
        if not ok:
            bad += 1
        if verbose or not ok:
            print("%s\t%s\tiv=%08X dir=%d len=%d\t%s"
                  % (algo, kc_hex, iv, direction, nbytes, "PASS" if ok else "FAIL"))
            if not ok:
                print("  want " + want.upper())
                print("  got  " + got)
    print("vectors\t%d" % len(KAT))
    print("failed\t%d" % bad)
    print("result\t%s" % ("kat-pass" if bad == 0 else "kat-fail"))
    return 0 if bad == 0 else 1


def main(argv):
    if not argv or argv[0] in ("--help", "-h"):
        print("usage: gsm_gea.py --kat | --gea3 <kc> <iv> <dir> <len> "
              "| --gea4 <kc> <iv> <dir> <len>")
        return 0 if not argv else 2
    cmd = argv[0]
    if cmd == "--kat":
        return run_kat(verbose="-v" in argv)
    if cmd in ("--gea3", "--gea4"):
        kc_hex, iv_hex, direction, nbytes = argv[1:5]
        kc = bytes.fromhex(kc_hex)
        out = (gea3 if cmd == "--gea3" else gea4)(
            kc, int(iv_hex, 16), int(direction), int(nbytes))
        print("algo\t%s" % cmd[2:].upper())
        print("gamma\t%s" % out.hex())
        return 0
    print("unknown command: " + cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
