#!/usr/bin/env python3
"""Check 12_nr_air's BCH chain, its CP lengths and its slot geometry against
the clauses, stage by stage.

WHY THIS EXISTS

modules/12_nr_air.sh builds a real BCH: TS 38.212 7.1.1 payload, 7.1.2 payload
scrambling, 5.1 CRC24C, 7.1.4 polar coding, 7.1.5 rate matching, then
TS 38.211 7.3.3.1 coded-bit scrambling. It pins the result for one vector,
which is the strongest check in the module. But a pin is one vector, and the
pin is compared against a constant that lives in the same file as the chain
that produces it. A chain that is wrong in the same way its pin is wrong
passes. That is not hypothetical here: the CRC24C attachment was wrong at BOTH
ends -- the generator and the decoder shared the same wrong expression -- and
the module's own CRC check agreed with itself for as long as the pin was not
consulted. The pin caught it. This file makes sure a wrong chain is caught by
something that is not the module too.

WHAT IT CHECKS, AND WHAT IT DOES NOT

It re-derives, from the clause, the chain that turns a 24-bit MIB plus a 10-bit
SFN into the 864 rate-matched bits and then into the 864 scrambled bits, and it
compares every intermediate the module publishes: bch_payload_hex (32),
bch_k_hex (56), bch_codeword_hex (864), bch_scrambled_hex (864). It also
re-derives the CP lengths (TS 38.211 5.3.1) and the samples in a slot, and it
re-checks the DMRS and PBCH resource-element counts (TS 38.211 7.4.3.1).

It does NOT check: the PSS/SSS/DMRS chip values (pinned in the module against
an independent implementation, and checked by --stage=sync), the SSB
resource-element POSITIONS (which k carries what), the PBCH payload's MIB field
encoding beyond the SFN, or anything above the BCH. Those are named gaps, not
covered ground.

HOW IT READS THE MODULE

It regenerates the module's own generator with `nair_write_bb_gen` and then
runs it. Regenerating first matters: /tmp/imsisting/nr_air/nr_ssb_bb.py
persists between runs, so a generator left over from an older module would
otherwise be read as if it were the current one. That happened once already.

TWO CONVENTIONS THE MODULE USES, SO THE REFERENCE MATCHES THEM

  - The generator's `sf` argument is the FULL 10-bit SFN. The MIB carries the
    six MSBs (38.331 6.2.2) and the four LSBs ride in the PBCH payload
    (38.212 7.1.1).
  - L_max is 8 in FR1. With L_max in {4, 8} the A+6 and A+7 bits are the
    reserved branch, so the codeword is identical for L_max 4 and 8.

The reliability sequence of TS 38.212 Table 5.3.1.2-1 is carried in this file
as data (RELIABILITY), read out of an installed reference once and checked to be
a permutation of 0..1023, so this stage needs no third-party package and no
network -- the same property the MIB and numerology stages have. Everything
else here is derived from the clause.

Licence note: py3gpp is AGPL-3.0. It was installed outside this tree, used to
obtain that one published table, and nothing of its source is copied in.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The module under test. The negative control points this at a mutated COPY in
# a scratch tree, so no control ever writes the repository's own module -- the
# last time a harness mutated a module in place, modules/15_downgrade.sh was
# left empty and had to be rebuilt from a session store.
MODULE = os.environ.get("NR_BCH_MODULE", os.path.join(ROOT, "modules", "12_nr_air.sh"))
# Where the module writes its regenerated generator. Discovered by asking the
# module itself, because it derives its temp directory from its own root: a
# copy in a scratch tree does NOT write to the same path as the repo's copy,
# and assuming the default silently reads the wrong module's generator.
BB_PY = os.environ.get("NR_BCH_BB")

# ---------------------------------------------------------------------------
# TS 38.212 Table 7.1.1-1: the PBCH payload interleaver. Published table, so it
# is the same numbers any implementation carries; the code that consumes it is
# written here.
PBCH_G = [16, 23, 18, 17, 8, 30, 10, 6, 24, 7, 0, 5, 3, 2, 1, 4,
          9, 11, 12, 13, 14, 15, 19, 20, 21, 22, 25, 26, 27, 28, 29, 31]

# TS 38.212 Table 5.4.1.1-1: the rate-matching sub-block interleaver.
P_SUBBLOCK = [0, 1, 2, 4, 3, 5, 6, 7, 8, 16, 9, 17, 10, 18, 11, 19,
              12, 20, 13, 21, 14, 22, 15, 23, 24, 25, 26, 28, 27, 29, 30, 31]

# TS 38.212 Table 5.3.1.1-1: the pre-code interleaver pattern for I_IL = 1.
P_IL_MAX = [0, 2, 4, 7, 9, 14, 19, 20, 24, 25, 26, 28, 31, 34, 42, 45, 49,
            50, 51, 53, 54, 56, 58, 59, 61, 62, 65, 66, 67, 69, 70, 71, 72,
            76, 77, 81, 82, 83, 87, 88, 89, 91, 93, 95, 98, 101, 104, 106,
            108, 110, 111, 113, 115, 118, 119, 120, 122, 123, 126, 127, 129,
            132, 134, 138, 139, 140, 1, 3, 5, 8, 10, 15, 21, 27, 29, 32, 35,
            43, 46, 52, 55, 57, 60, 63, 68, 73, 78, 84, 90, 92, 94, 96, 99,
            102, 105, 107, 109, 112, 114, 116, 121, 124, 128, 130, 133, 135,
            141, 6, 11, 16, 22, 30, 33, 36, 44, 47, 64, 74, 79, 85, 97, 100,
            103, 117, 125, 131, 136, 142, 12, 17, 23, 37, 48, 75, 80, 86, 137,
            143, 13, 18, 38, 144, 39, 145, 40, 146, 41, 147, 148, 149, 150,
            151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163]
K_IL_MAX = 164

E = 864          # the PBCH rate-matched length, TS 38.212 7.1.5
NMAX = 9         # TS 38.212 7.1.4
K_BCH = 56       # 32 payload bits + 24 CRC bits


# ---------------------------------------------------------------------------
# TS 38.211 5.2.1, the length-31 Gold sequence. x1 has taps (3, 0); x2 is
# seeded with c_init, which is what makes this reusable for DMRS and PBCH
# scrambling as well as the payload scrambling.
def gold(c_init, length):
    nc = 1600
    total = 31 + nc + length
    x1 = [0] * total
    x2 = [0] * total
    x1[0] = 1                                  # x1(0) = 1, x1(1..30) = 0
    for i in range(31):
        x2[i] = (c_init >> i) & 1              # x2 is the seed, LSB first
    for i in range(total - 31):
        # TS 38.211 5.2.1 gives the two recurrences DIFFERENT taps:
        #   x1(n+31) = (x1(n+3) + x1(n)) mod 2
        #   x2(n+31) = (x2(n+3) + x2(n+2) + x2(n+1) + x2(n)) mod 2
        # x2's extra taps are what make this the NR Gold sequence. Giving both
        # sequences x1's taps is the LTE sequence (TS 36.211 7.2), and it
        # disagrees with a correct implementation on every bit.
        x1[i + 31] = (x1[i + 3] + x1[i]) % 2
        x2[i + 31] = (x2[i + 3] + x2[i + 2] + x2[i + 1] + x2[i]) % 2
    return [(x1[i + nc] + x2[i + nc]) % 2 for i in range(length)]


# ---------------------------------------------------------------------------
# TS 38.212 5.1, the CRC24C parity. The clause defines the parity as the
# remainder of a(D)*D^24 + p(D) over g(D), so the message bits go through a
# register initialised to ZERO and the register's final contents ARE the
# parity. Appending 24 zeros and starting from 0xFFFFFF is the *LTE* reading
# and does not give this polynomial's parity.
CRC24C_POLY = 0xB2B117      # g(D) = D^24 + D^23 + D^21 + D^20 + D^17 + D^15
                            #        + D^13 + D^12 + D^8 + D^4 + D^2 + D + 1
                            # (the D^24 term is implicit, as the register width)
# The neighbouring polynomials are close enough to be a trap: gCRC24A is
# 0x864CFB and gCRC24B is 0x800063. A wrong constant still produces 24 bits of
# plausible-looking parity, so the only thing that catches it is an outside
# vector -- which is how this file's first draft got it wrong.


def crc24c(bits):
    """TS 38.212 5.1: the parity p(D) is the remainder of a(D)*D^24 over g(D).

    Implemented as the long division the clause describes, on the whole
    message at once: append 24 zeros, then cancel the leading term d times at
    each exponent >= 24. A shift-register form computes the same thing but
    hides which convention it is using (message bits into the register, or a
    register initialised to all ones and 24 zeros appended), and those
    variants give different answers -- getting that choice wrong is exactly the
    defect that sat in modules/12_nr_air.sh until the pinned codeword caught
    it. Long division leaves no convention to get wrong.
    """
    val = 0
    for b in bits:
        val = (val << 1) | (b & 1)
    val <<= 24
    top = val.bit_length() - 1
    gen = (1 << 24) | CRC24C_POLY          # the full g(D), D^24 included
    for shift in range(top, 23, -1):
        if (val >> shift) & 1:
            val ^= gen << (shift - 24)
    return [(val >> i) & 1 for i in range(23, -1, -1)]


# ---------------------------------------------------------------------------
# TS 38.212 7.1.4 / 5.3.1: polar encoding.
# TS 38.212 Table 5.3.1.2-1, the reliability sequence, as a map from channel
# index to its rank: RELIABILITY[ch] is the position of channel `ch` in the
# published ordering, which runs from the least to the most reliable, so the
# channels with the LARGEST rank are the information bits. Carried here rather
# than imported so this stage needs no py3gpp and no network, like the MIB and
# numerology stages. It was read out of the installed transcription once and
# checked to be a permutation of 0..1023; the stage's own negative control is
# what proves the encoding that consumes it can fail.
RELIABILITY = [
    0, 1, 2, 4, 8, 16, 32, 3, 5, 64, 9, 6, 17, 10, 18, 128,
    12, 33, 65, 20, 256, 34, 24, 36, 7, 129, 66, 512, 11, 40, 68, 130,
    19, 13, 48, 14, 72, 257, 21, 132, 35, 258, 26, 513, 80, 37, 25, 22,
    136, 260, 264, 38, 514, 96, 67, 41, 144, 28, 69, 42, 516, 49, 74, 272,
    160, 520, 288, 528, 192, 544, 70, 44, 131, 81, 50, 73, 15, 320, 133, 52,
    23, 134, 384, 76, 137, 82, 56, 27, 97, 39, 259, 84, 138, 145, 261, 29,
    43, 98, 515, 88, 140, 30, 146, 71, 262, 265, 161, 576, 45, 100, 640, 51,
    148, 46, 75, 266, 273, 517, 104, 162, 53, 193, 152, 77, 164, 768, 268, 274,
    518, 54, 83, 57, 521, 112, 135, 78, 289, 194, 85, 276, 522, 58, 168, 139,
    99, 86, 60, 280, 89, 290, 529, 524, 196, 141, 101, 147, 176, 142, 530, 321,
    31, 200, 90, 545, 292, 322, 532, 263, 149, 102, 105, 304, 296, 163, 92, 47,
    267, 385, 546, 324, 208, 386, 150, 153, 165, 106, 55, 328, 536, 577, 548, 113,
    154, 79, 269, 108, 578, 224, 166, 519, 552, 195, 270, 641, 523, 275, 580, 291,
    59, 169, 560, 114, 277, 156, 87, 197, 116, 170, 61, 531, 525, 642, 281, 278,
    526, 177, 293, 388, 91, 584, 769, 198, 172, 120, 201, 336, 62, 282, 143, 103,
    178, 294, 93, 644, 202, 592, 323, 392, 297, 770, 107, 180, 151, 209, 284, 648,
    94, 204, 298, 400, 608, 352, 325, 533, 155, 210, 305, 547, 300, 109, 184, 534,
    537, 115, 167, 225, 326, 306, 772, 157, 656, 329, 110, 117, 212, 171, 776, 330,
    226, 549, 538, 387, 308, 216, 416, 271, 279, 158, 337, 550, 672, 118, 332, 579,
    540, 389, 173, 121, 553, 199, 784, 179, 228, 338, 312, 704, 390, 174, 554, 581,
    393, 283, 122, 448, 353, 561, 203, 63, 340, 394, 527, 582, 556, 181, 295, 285,
    232, 124, 205, 182, 643, 562, 286, 585, 299, 354, 211, 401, 185, 396, 344, 586,
    645, 593, 535, 240, 206, 95, 327, 564, 800, 402, 356, 307, 301, 417, 213, 568,
    832, 588, 186, 646, 404, 227, 896, 594, 418, 302, 649, 771, 360, 539, 111, 331,
    214, 309, 188, 449, 217, 408, 609, 596, 551, 650, 229, 159, 420, 310, 541, 773,
    610, 657, 333, 119, 600, 339, 218, 368, 652, 230, 391, 313, 450, 542, 334, 233,
    555, 774, 175, 123, 658, 612, 341, 777, 220, 314, 424, 395, 673, 583, 355, 287,
    183, 234, 125, 557, 660, 616, 342, 316, 241, 778, 563, 345, 452, 397, 403, 207,
    674, 558, 785, 432, 357, 187, 236, 664, 624, 587, 780, 705, 126, 242, 565, 398,
    346, 456, 358, 405, 303, 569, 244, 595, 189, 566, 676, 361, 706, 589, 215, 786,
    647, 348, 419, 406, 464, 680, 801, 362, 590, 409, 570, 788, 597, 572, 219, 311,
    708, 598, 601, 651, 421, 792, 802, 611, 602, 410, 231, 688, 653, 248, 369, 190,
    364, 654, 659, 335, 480, 315, 221, 370, 613, 422, 425, 451, 614, 543, 235, 412,
    343, 372, 775, 317, 222, 426, 453, 237, 559, 833, 804, 712, 834, 661, 808, 779,
    617, 604, 433, 720, 816, 836, 347, 897, 243, 662, 454, 318, 675, 618, 898, 781,
    376, 428, 665, 736, 567, 840, 625, 238, 359, 457, 399, 787, 591, 678, 434, 677,
    349, 245, 458, 666, 620, 363, 127, 191, 782, 407, 436, 626, 571, 465, 681, 246,
    707, 350, 599, 668, 790, 460, 249, 682, 573, 411, 803, 789, 709, 365, 440, 628,
    689, 374, 423, 466, 793, 250, 371, 481, 574, 413, 603, 366, 468, 655, 900, 805,
    615, 684, 710, 429, 794, 252, 373, 605, 848, 690, 713, 632, 482, 806, 427, 904,
    414, 223, 663, 692, 835, 619, 472, 455, 796, 809, 714, 721, 837, 716, 864, 810,
    606, 912, 722, 696, 377, 435, 817, 319, 621, 812, 484, 430, 838, 667, 488, 239,
    378, 459, 622, 627, 437, 380, 818, 461, 496, 669, 679, 724, 841, 629, 351, 467,
    438, 737, 251, 462, 442, 441, 469, 247, 683, 842, 738, 899, 670, 783, 849, 820,
    728, 928, 791, 367, 901, 630, 685, 844, 633, 711, 253, 691, 824, 902, 686, 740,
    850, 375, 444, 470, 483, 415, 485, 905, 795, 473, 634, 744, 852, 960, 865, 693,
    797, 906, 715, 807, 474, 636, 694, 254, 717, 575, 913, 798, 811, 379, 697, 431,
    607, 489, 866, 723, 486, 908, 718, 813, 476, 856, 839, 725, 698, 914, 752, 868,
    819, 814, 439, 929, 490, 623, 671, 739, 916, 463, 843, 381, 497, 930, 821, 726,
    961, 872, 492, 631, 729, 700, 443, 741, 845, 920, 382, 822, 851, 730, 498, 880,
    742, 445, 471, 635, 932, 687, 903, 825, 500, 846, 745, 826, 732, 446, 962, 936,
    475, 853, 867, 637, 907, 487, 695, 746, 828, 753, 854, 857, 504, 799, 255, 964,
    909, 719, 477, 915, 638, 748, 944, 869, 491, 699, 754, 858, 478, 968, 383, 910,
    815, 976, 870, 917, 727, 493, 873, 701, 931, 756, 860, 499, 731, 823, 922, 874,
    918, 502, 933, 743, 760, 881, 494, 702, 921, 501, 876, 847, 992, 447, 733, 827,
    934, 882, 937, 963, 747, 505, 855, 924, 734, 829, 965, 938, 884, 506, 749, 945,
    966, 755, 859, 940, 830, 911, 871, 639, 888, 479, 946, 750, 969, 508, 861, 757,
    970, 919, 875, 862, 758, 948, 977, 923, 972, 761, 877, 952, 495, 703, 935, 978,
    883, 762, 503, 925, 878, 735, 993, 885, 939, 994, 980, 926, 764, 941, 967, 886,
    831, 947, 507, 889, 984, 751, 942, 996, 971, 890, 509, 949, 973, 1000, 892, 950,
    863, 759, 1008, 510, 979, 953, 763, 974, 954, 879, 981, 982, 927, 995, 765, 956,
    887, 985, 997, 986, 943, 891, 998, 766, 511, 988, 1001, 951, 1002, 893, 975, 894,
    1009, 955, 1004, 1010, 957, 983, 958, 987, 1012, 999, 1016, 767, 989, 1003, 990, 1005,
    959, 1011, 1013, 895, 1006, 1014, 1017, 1018, 991, 1020, 1007, 1015, 1019, 1021, 1022, 1023,
]


def info_positions(k, n):
    """The k information-bit positions, TS 38.212 5.3.1.2.

    The sequence is used exactly as the clause and the reference use it: sort
    the 1024 channel indices by their entry in the table, keep the n that sort
    first, put those back into channel order, and the last k of THAT are the
    information positions. Written out rather than paraphrased because the two
    reorderings are what make it work, and the tempting "take the n channels
    with the largest entries" reading of the same table gives a different --
    wrong -- answer. Verified against the reference for seven (k, n) pairs."""
    order = sorted(range(1024), key=lambda c: RELIABILITY[c])
    sel = order[0:n]
    by_channel = sorted(range(n), key=lambda p: sel[p])
    ranking = [RELIABILITY[sel[p]] for p in by_channel]
    return sorted(ranking[n - k:])


def polar_precode_interleave(k):
    """TS 38.212 5.3.1.1: p_IL(i) for I_IL = 1, derived from the table by the
    rule the clause gives (keep the entries >= K_IL_max - K, shift them down)."""
    p = []
    for v in P_IL_MAX:
        if v >= (K_IL_MAX - k):
            p.append(v - (K_IL_MAX - k))
    return p


def polar_encode(payload, iil=True):
    """TS 38.212 5.3.1 + 7.1.4. G_N is the nmax-fold Kronecker product of
    [[1,0],[1,1]]; the codeword is u * G_N mod 2."""
    import numpy as np
    n = 2 ** NMAX
    k = len(payload)
    src = [payload[polar_precode_interleave(k)[i]] for i in range(k)] if iil else list(payload)
    info = info_positions(k, n)
    assert len(info) == k, (len(info), k)
    u = np.zeros(n, dtype=np.int64)
    for i, pos in enumerate(info):
        u[pos] = src[i] & 1
    g = np.array([[1]], dtype=np.int64)
    f = np.array([[1, 0], [1, 1]], dtype=np.int64)
    for _ in range(NMAX):
        g = np.kron(g, f)
    return ((u @ g) % 2).tolist()


def rate_match(codeword, e):
    """TS 38.212 5.4.1: sub-block interleaving then bit selection.

    5.4.1.1 writes the sequence into 32 columns and permutes the columns with
    the pattern P of Table 5.4.1.1-1, reading row-wise. With N = 512 that makes
    the row length N/32 = 16, so P permutes 32 chunks of 16 elements -- NOT 32
    elements at a time inside each chunk, which is the same trap the table's
    shape invites and which this file's first draft fell into.

    5.4.1.2 is the bit selection; for the PBCH N = 512 and E = 864, so E > N
    and the branch taken is repetition (W = d[(k mod N)]).
    """
    n = len(codeword)
    row = n // 32
    interleaved = [0] * n
    for i in range(32):
        for r in range(row):
            interleaved[i * row + r] = codeword[P_SUBBLOCK[i] * row + r]
    if e <= n:
        return interleaved[:e]
    return interleaved[:n] + [interleaved[k % n] for k in range(n, e)]


# ---------------------------------------------------------------------------
# TS 38.212 7.1.1 + 7.1.2
def payload_generate(mib, sfn, hrf, l_max, kssb_msb, ssb_idx):
    a = [0] * 32
    for k in range(6):
        a[PBCH_G[k]] = mib[1 + k]
    a[PBCH_G[6]] = (sfn >> 3) & 1
    a[PBCH_G[7]] = (sfn >> 2) & 1
    a[PBCH_G[8]] = (sfn >> 1) & 1
    a[PBCH_G[9]] = sfn & 1
    a[PBCH_G[10]] = hrf & 1
    if l_max == 10:
        a[PBCH_G[11]] = kssb_msb & 1
        a[PBCH_G[13]] = (ssb_idx >> 3) & 1
    elif l_max == 20:
        a[PBCH_G[11]] = kssb_msb & 1
        a[PBCH_G[12]] = (ssb_idx >> 4) & 1
        a[PBCH_G[13]] = (ssb_idx >> 3) & 1
    elif l_max == 64:
        a[PBCH_G[11]] = (ssb_idx >> 5) & 1
        a[PBCH_G[12]] = (ssb_idx >> 4) & 1
        a[PBCH_G[13]] = (ssb_idx >> 3) & 1
    else:
        a[PBCH_G[11]] = kssb_msb & 1
    j = 14
    for i in range(24):
        if 1 <= i <= 6:
            continue
        a[PBCH_G[j]] = mib[i]
        j += 1
    assert j == 32, j
    return a


def payload_scramble(a, sfn, l_max, ncellid):
    m = {4: 29, 8: 29, 10: 28, 20: 27, 64: 26}[l_max]
    v = 2 * ((sfn >> 2) & 1) + ((sfn >> 1) & 1)
    excl = {PBCH_G[7], PBCH_G[8], PBCH_G[10]}
    if l_max == 10:
        excl.add(PBCH_G[13])
    elif l_max == 20:
        excl |= {PBCH_G[12], PBCH_G[13]}
    elif l_max == 64:
        excl |= {PBCH_G[11], PBCH_G[12], PBCH_G[13]}
    c = gold(ncellid, (v + 1) * m)
    out = list(a)
    j = 0
    for i in range(32):
        if i in excl:
            continue
        out[i] = a[i] ^ c[j + v * m]
        j += 1
    assert j == m, (j, m)
    return out


def coded_scramble(codeword, pci, i_ssb, l_max):
    """TS 38.211 7.3.3.1. nu = i_SSB mod 8 for L_max = 4, i_SSB mod 4 for
    L_max = 8 or 64; the sequence is initialised with N_ID^cell."""
    nu = i_ssb % (8 if l_max == 4 else 4)
    c = gold(pci, 864 + nu * 864)
    return [codeword[i] ^ c[i + nu * 864] for i in range(864)]


# ---------------------------------------------------------------------------
# TS 38.211 5.3.1, the cyclic prefix lengths, derived from the sample-count
# definition rather than from any implementation's constant.
def cp_lengths(mu, nslot, nfft):
    short = 144 * nfft // 2048
    extra = 16 * nfft * (2 ** mu) // 2048
    l0 = nslot * 14
    return [short + extra if (l0 + l) in (0, 7 * (2 ** mu)) else short
            for l in range(14)]


# ---------------------------------------------------------------------------
def bits_from_hex(h, width):
    n = len(h) * 4
    bits = []
    for ch in h:
        v = int(ch, 16)
        bits += [(v >> i) & 1 for i in range(3, -1, -1)]
    return bits[:width]


def run_generator(pci, sfn):
    proc = subprocess.run(
        ["python3", BB_PY, "/tmp/nr_bch_oracle.bin", str(pci), "30", "2048", str(sfn)],
        capture_output=True, text=True, timeout=110)
    if proc.returncode != 0:
        return None, proc.stderr.strip() or proc.stdout.strip()
    out = {}
    for line in proc.stdout.splitlines():
        if "\t" in line:
            k, _, v = line.partition("\t")
            out[k] = v
    return out, None


CASES = [(0, 37), (42, 37), (42, 0), (1, 1023), (777, 511), (1007, 8)]


def main():
    global BB_PY, MODULE
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == "--module" and i + 1 < len(argv):
            MODULE = argv[i + 1]
        elif a.startswith("--module="):
            MODULE = a.partition("=")[2]
    print("== NR BCH chain vs TS 38.212 7.1 / TS 38.211 7.3.3.1 ==")

    reg = subprocess.run(
        ["bash", "-c", 'source "%s" >/dev/null 2>&1; nair_write_bb_gen; '
                       'printf "MOD_TMP=%%s\\n" "$MOD_TMP"' % MODULE],
        cwd=os.path.dirname(os.path.dirname(MODULE)), capture_output=True,
        text=True, timeout=110)
    mod_tmp = ""
    for line in reg.stdout.splitlines():
        if line.startswith("MOD_TMP="):
            mod_tmp = line.partition("=")[2]
    if not BB_PY:
        if not mod_tmp:
            print("ERROR\tthe module did not report MOD_TMP (rc=%d): %s"
                  % (reg.returncode, reg.stderr.strip()))
            return 2
        BB_PY = os.path.join(mod_tmp, "nr_ssb_bb.py")
    if not os.path.exists(BB_PY):
        print("ERROR\tthe module did not write %s (rc=%d)" % (BB_PY, reg.returncode))
        return 2
    print("module\t\t%s" % MODULE)
    print("generator\t%s (regenerated from it)" % BB_PY)

    bad = 0
    checked = 0
    for pci, sfn in CASES:
        got, err = run_generator(pci, sfn)
        if got is None:
            print("case pci=%d sfn=%d: GENERATOR FAILED: %s" % (pci, sfn, err))
            bad += 1
            continue
        l_max = int(got["bch_l_max"])
        mib = bits_from_hex(got["mib_hex"], 24)
        # The MIB must carry sfn >> 4 in bits 1..6, per 38.331 6.2.2.
        want_sfn_field = [(sfn >> 4 >> i) & 1 for i in range(5, -1, -1)]
        if mib[1:7] != want_sfn_field:
            print("case pci=%d sfn=%d: MIB SFN field %s, clause says %s"
                  % (pci, sfn, mib[1:7], want_sfn_field))
            bad += 1
        # And the module's own published field must agree with the same value.
        if int(got["mib_sfn_field"]) != sfn >> 4:
            print("case pci=%d sfn=%d: mib_sfn_field %s != %d"
                  % (pci, sfn, got["mib_sfn_field"], sfn >> 4))
            bad += 1

        a = payload_scramble(payload_generate(mib, sfn, 0, l_max, 0, 0),
                             sfn, l_max, pci)
        want_payload = "".join("%x" % int("".join(str(b) for b in a[i:i + 4]), 2)
                               for i in range(0, 32, 4))
        k_bits = a + crc24c(a)
        want_k = "".join("%x" % int("".join(str(b) for b in k_bits[i:i + 4]), 2)
                         for i in range(0, 56, 4))
        cw = rate_match(polar_encode(k_bits), E)
        want_cw = "".join("%x" % int("".join(str(b) for b in cw[i:i + 4]), 2)
                          for i in range(0, 864, 4))
        scr = coded_scramble(cw, pci, 0, l_max)
        want_scr = "".join("%x" % int("".join(str(b) for b in scr[i:i + 4]), 2)
                           for i in range(0, 864, 4))

        # The module publishes the payload unscrambled-scrambled under
        # bch_payload_hex only after 7.1.2, so compare field by field and name
        # any that differs.
        for field, want in (("bch_payload_hex", want_payload),
                            ("bch_k_hex", want_k),
                            ("bch_codeword_hex", want_cw),
                            ("bch_scrambled_hex", want_scr)):
            checked += 1
            if got.get(field) != want:
                print("MISMATCH\tpci=%d sfn=%d %s\n  we:  %s\n  ref: %s"
                      % (pci, sfn, field, got.get(field, "(absent)"), want))
                bad += 1

        # CP lengths and slot geometry, re-derived from TS 38.211 5.3.1.
        mu = 1
        cps = cp_lengths(mu, 0, 2048)
        if int(got["cp_long"]) != cps[0] or int(got["cp_short"]) != cps[1]:
            print("MISMATCH\tpci=%d sfn=%d cp_long/cp_short %s/%s, clause says %d/%d"
                  % (pci, sfn, got["cp_long"], got["cp_short"], cps[0], cps[1]))
            bad += 1
        want_slot = 14 * 2048 + sum(cps)
        if int(got["slot_samples"]) != want_slot:
            print("MISMATCH\tpci=%d sfn=%d slot_samples %s, clause says %d"
                  % (pci, sfn, got["slot_samples"], want_slot))
            bad += 1
        if int(got["dmrs_re"]) != 144 or int(got["pbch_re"]) != 432:
            print("MISMATCH\tpci=%d sfn=%d dmrs_re/pbch_re %s/%s, 38.211 7.4.3.1 says 144/432"
                  % (pci, sfn, got["dmrs_re"], got["pbch_re"]))
            bad += 1

    print("cases\t%d" % len(CASES))
    print("fields checked\t%d" % checked)
    print("MISMATCHES: %d" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
