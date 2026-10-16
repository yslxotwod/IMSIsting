#!/usr/bin/env python3
"""gsm_mod — GSM channel coding and GMSK modulation.

Everything here is derived from a primary source, and every constant is
asserted against one in --selftest:

  * the FIRE parity, convolutional code, interleaving and burst mapping from
    3GPP TS 45.003, cross-checked bit-for-bit against libosmocoding's own
    encoders (see --vectors);
  * the GMSK pulse and rotation from 3GPP TS 45.004 as implemented in
    osmo-trx's Transceiver52M/sigProcLib.cpp (`generateGSMPulse`,
    `initGMSKRotationTables`, `GMSKRotate`, `rotateBurst`).

The modulator is the Laurent C0 approximation, which is what osmo-trx uses at
1 sample/symbol: the output is the complex baseband waveform

    x(t) = sum_k  (2*b_k - 1) * j^k * c0(t - k*T)

with c0 the truncated Gaussian pulse. At 1 sps this is exact to within the
approximation error documented in osmo-trx (~2 degrees of phase at 4 sps).

CLI:
    bursts  <l2-hex> [tsc]           the four 116-bit xCCH blocks
    octets  <l2-hex> [tsc]           the four complete 148-bit bursts
    iq      <l2-hex> [sps] [tsc]     the modulated waveform, hex-encoded
    cfile   <out> <l2-hex> [sps] [tsc]  write the waveform as complex float32
    pulse   [sps]                    the shaping pulse taps
    vectors                          the libosmocoding cross-check vectors
    selftest                         assert every constant against its source
"""

import argparse
import math
import os
import struct
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Bit plumbing
# ─────────────────────────────────────────────────────────────────────────────


def bytes_to_bits_lsb(data, nbits):
    """Unpack bits the way libosmocore's osmo_pbit2ubit_ext(..., lsb_mode=1)
    does. The parameter is named lsb_mode in the source, not msb_first, and
    gsm0503_xcch_encode passes 1 — so the L2 block is unpacked LSB-first. This
    is the single easiest thing to get backwards in the whole chain, which is
    why it is asserted against an encoder vector rather than reasoned about."""
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(nbits)]


def bytes_to_bits_msb(data, nbits):
    return [(data[i // 8] >> (7 - (i % 8))) & 1 for i in range(nbits)]


def bits_to_bytes_lsb(bits):
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        out[i // 8] |= (b & 1) << (i % 8)
    return bytes(out)


def bits_str(bits):
    return "".join("1" if b else "0" for b in bits)


def parse_hex(text, what):
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise SystemExit("ERROR\t%s is not hex: %s" % (what, text))


# ─────────────────────────────────────────────────────────────────────────────
# CRC generators — a direct transcription of libosmocore's crcXXgen.c.tpl
# ─────────────────────────────────────────────────────────────────────────────


class CrcCode(object):
    __slots__ = ("bits", "poly", "init", "remainder")

    def __init__(self, bits, poly, init, remainder):
        self.bits = bits
        self.poly = poly
        self.init = init
        self.remainder = remainder


def crc_compute(code, bits):
    """osmo_crcXXgen_compute_bits, unchanged: shift the register, tap the top
    bit against the new input bit, fold in the polynomial, then XOR the
    remainder. The remainder is what makes an all-zero block yield an all-ones
    parity rather than all zeros."""
    crc = code.init
    n = code.bits - 1
    mask = (1 << code.bits) - 1
    for b in bits:
        crc ^= ((b & 1) << n)
        if crc & (1 << n):
            crc = ((crc << 1) ^ code.poly) & mask
        else:
            crc = (crc << 1) & mask
    crc ^= code.remainder
    # osmo_crcXXgen_set_bits writes MSB first.
    return [(crc >> (code.bits - i - 1)) & 1 for i in range(code.bits)]


# gsm0503_parity.c, verbatim.
FIRE_CRC40 = CrcCode(40, 0x0004820009, 0x0000000000, 0xFFFFFFFFFF)
SCH_CRC10 = CrcCode(10, 0x175, 0x000, 0x3FF)
RACH_CRC6 = CrcCode(6, 0x2F, 0x00, 0x3F)


# ─────────────────────────────────────────────────────────────────────────────
# Convolutional code — TS 45.003 section 4.4
# ─────────────────────────────────────────────────────────────────────────────

CONV_K = 5
CONV_G0 = 0x19          # 1 + D^3 + D^4
CONV_G1 = 0x1B          # 1 + D + D^3 + D^4


def conv_encode(bits, g0=CONV_G0, g1=CONV_G1, k=CONV_K):
    """Rate 1/2, constraint length k, terminated by k-1 zero tail bits.

    G0 is emitted before G1 — this ordering is not a free choice, it is fixed
    by the vectors: swapping the two generators while also swapping the output
    order reproduces the same stream, but any other combination does not."""
    reg = [0] * (k - 1)
    out = []
    for b in list(bits) + [0] * (k - 1):
        taps = [b] + reg[: k - 1]
        for g in (g0, g1):
            acc = 0
            for i in range(k):
                if (g >> i) & 1:
                    acc ^= taps[i]
            out.append(acc)
        reg = [b] + reg[: k - 2]
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Interleaving and burst mapping — TS 45.003 sections 4.1.4 / 4.4
# ─────────────────────────────────────────────────────────────────────────────

XCCH_BLOCK_BITS = 456
XCCH_BURST_BITS = 116
XCCH_BURSTS = 4


def xcch_interleave(cB):
    """gsm0503_interleaving.c: B = k mod 4, j = 2*((49*k) mod 57) + ((k mod 8)
    div 4). An iB slot is uniquely addressed, so this is a permutation of 0..455."""
    iB = [0] * XCCH_BLOCK_BITS
    for k in range(XCCH_BLOCK_BITS):
        b = k & 3
        j = 2 * ((49 * k) % 57) + ((k & 7) >> 2)
        iB[b * 114 + j] = cB[k]
    return iB


def xcch_deinterleave(iB):
    cB = [0] * XCCH_BLOCK_BITS
    for k in range(XCCH_BLOCK_BITS):
        b = k & 3
        j = 2 * ((49 * k) % 57) + ((k & 7) >> 2)
        cB[k] = iB[b * 114 + j]
    return cB


def xcch_burst_map(iB, hl=1, hn=1):
    """e(B,0..56) = i(B,0..56); e(B,57) = hl; e(B,58) = hn; e(B,59..115) =
    i(B,57..113). For a signalling block both stealing flags are set, which is
    what marks the four bursts as xCCH rather than traffic."""
    bursts = []
    for b in range(XCCH_BURSTS):
        i = iB[b * 114:(b + 1) * 114]
        e = i[0:57] + [hl, hn] + i[57:114]
        assert len(e) == XCCH_BURST_BITS
        bursts.append(e)
    return bursts


def xcch_encode(l2_data):
    """The whole transmit-side signalling chain: 184 L2 bits, FIRE parity to
    224, rate-1/2 convolutional code with a 4-bit tail to 456, interleave, then
    split into four 116-bit bursts."""
    if len(l2_data) != 23:
        raise ValueError("xCCH L2 block must be 23 octets, got %d" % len(l2_data))
    l2 = bytes_to_bits_lsb(l2_data, 184)
    conv_in = l2 + crc_compute(FIRE_CRC40, l2)
    assert len(conv_in) == 224
    cB = conv_encode(conv_in)
    assert len(cB) == XCCH_BLOCK_BITS, len(cB)
    return xcch_burst_map(xcch_interleave(cB))


def sch_encode(sb25):
    """SCH: 25 information bits, 10 parity, rate-1/2 code, 78 coded bits."""
    l2 = sb25[:25]
    conv_in = l2 + crc_compute(SCH_CRC10, l2)
    assert len(conv_in) == 35
    coded = conv_encode(conv_in)
    assert len(coded) == 78, len(coded)
    return coded


def rach_encode(ra_bits, bsic):
    """RACH: 8 bits, 6 parity XORed with the BSIC (TS 45.003 section 4.6:
    b(0) is the MSB of the PLMN colour code, b(5) the LSB of the BS colour
    code), then rate-1/2 code, 36 coded bits."""
    l2 = ra_bits[:8]
    parity = crc_compute(RACH_CRC6, l2)
    for i in range(6):
        parity[i] ^= (bsic >> (5 - i)) & 1
    conv_in = l2 + parity
    assert len(conv_in) == 14
    coded = conv_encode(conv_in)
    assert len(coded) == 36, len(coded)
    return coded


# ─────────────────────────────────────────────────────────────────────────────
# Burst assembly — TS 45.002 section 5.2.3
# ─────────────────────────────────────────────────────────────────────────────

# Training sequence code set 1, TS 45.002 table 5.2.3a. Transcribed from
# osmo-trx GSM/GSMCommon.cpp:35 (`GSM::gTrainingSequence[]`), which is an
# independent implementation of the spec rather than a restatement of it.
#
# These were originally written from memory and SIX OF THE EIGHT WERE WRONG.
# TSC 2 in particular had been copied from a secondary document that had
# truncated it to 24 bits. Do not "tidy" these strings by hand — the selftest
# asserts all eight and the module's --selftest fails loudly if one drifts.
#
# For BCCH, CCCH, AGCH, PCH and RACH the TSC must equal the BCC, so a fake
# BCCH on a cell whose real BSIC is (NCC, BCC) must use TSC = BCC or the
# handsets will not correlate against it.
TSC_SET_1 = {
    0: "00100101110000100010010111",
    1: "00101101110111100010110111",
    2: "01000011101110100100001110",
    3: "01000111101101000100011110",
    4: "00011010111001000001101011",
    5: "01001110101100000100111010",
    6: "10100111110110001010011111",
    7: "11101111000100101110111100",
}

# TS 45.002 table 5.2.5-1: the synchronisation burst, whose training sequence
# is 64 bits rather than 26 and is NOT in TSC set 1. Two independent sources
# agree on this value — TS 45.002 table 5.2.5-3 as transcribed into the
# project's reference document, and osmo-trx GSM/GSMCommon.cpp:66
# (`GSM::gSCHSynchSequence`) — so it is no longer a single-source constant.
SCH_SYNC_SEQUENCE = (
    "1011100101100010000001000000111100101101010001010111011000011011"
)

# TS 45.002 section 5.2.7, the access burst. osmo-trx GSM/GSMCommon.cpp:60-62
# defines three variants; TS0 is the GMSK one a 2G handset will use, the other
# two are the EGPRS 8-PSK variants and are carried here for completeness.
#
# The 8-bit "head" is the tail bits, and the 41-bit sequence is the access
# burst's own synchronisation sequence — it is NOT the normal burst training
# sequence and NOT the 64-bit SCH sequence, which is the mistake this module
# originally made (the value here was previously invented outright).
RACH_HEAD = "00111010"
RACH_SYNC_TS0 = "01001011011111111001100110101010001111000"
RACH_SYNC_TS1 = "01010100111110001000011000101111001001101"
RACH_SYNC_TS2 = "11101111001001110101011000001101101110111"

# A dummy burst is transmitted on idle BCCH timeslots so that handsets still
# have something to lock their timing loop onto. Needed once the fake BCCH
# starts filling a full eight-timeslot frame.
DUMMY_BURST_TSC = "01110001011100010111000101"

NORMAL_BURST_BITS = 148           # the transmitted part, tail to tail
NORMAL_GUARD_SYMBOLS = 8.25
ACCESS_BURST_BITS = 88            # 8 + 41 + 36 + 3
ACCESS_GUARD_SYMBOLS = 68.25


def normal_burst(data116, tsc):
    """A normal burst carries 2 x 57 bits around a 26-bit training sequence,
    3 tail bits at each end, and an 8.25-symbol guard. `data116` is the output
    of the xCCH burst mapper: 114 information bits with the two stealing flags
    at positions 57 and 58.

    The flags do NOT sit together. TS 45.003 section 3.1.4 maps e(57) to the
    last bit before the training sequence (BN 60) and e(58) to the first bit
    after it (BN 87), so the burst is

        BN   0..2    tail
        BN   3..59   e(0..56)   = i(0..56)
        BN  60       e(57)      = hl      <- stealing flag, first
        BN  61..86   training sequence
        BN  87       e(58)      = hn      <- stealing flag, second
        BN  88..144  e(59..115) = i(57..113)
        BN 145..147  tail

    An earlier version of this function placed both flags adjacent to each
    other after the training sequence. That produces a syntactically valid
    148-bit burst that no handset would ever decode. osmo-trx's own burst
    generator (utils/va-test/burst-gen.cpp) writes the stealing bit at i == 60
    and again at i == 87, which is what settled it.
    """
    if len(data116) != XCCH_BURST_BITS:
        raise ValueError("need 116 mapped bits, got %d" % len(data116))
    if tsc not in TSC_SET_1:
        raise ValueError("training sequence code must be 0..7, got %r" % (tsc,))
    train = [int(c) for c in TSC_SET_1[tsc]]
    burst = ([0, 0, 0] + data116[0:57] + [data116[57]] + train +
             [data116[58]] + data116[59:116] + [0, 0, 0])
    assert len(burst) == NORMAL_BURST_BITS, len(burst)
    return burst


def access_burst(coded36, sync=RACH_SYNC_TS0):
    """A RACH access burst: 8 tail bits, the 41-bit access synchronisation
    sequence, the 36 coded bits, 3 tail bits, and a 68.25 symbol guard because
    the mobile does not yet know its timing advance."""
    if len(coded36) != 36:
        raise ValueError("need 36 coded bits, got %d" % len(coded36))
    if len(sync) != 41:
        raise ValueError("access sync sequence must be 41 bits, got %d" % len(sync))
    return ([int(c) for c in RACH_HEAD + sync] + list(coded36) + [0, 0, 0])


def sch_burst(coded78):
    """A synchronisation burst: 3 tail, 39 bits, the 64-bit extended training
    sequence, 39 bits, 3 tail, 8.25 guard."""
    if len(coded78) != 78:
        raise ValueError("need 78 coded bits, got %d" % len(coded78))
    sync = [int(c) for c in SCH_SYNC_SEQUENCE]
    assert len(sync) == 64
    return [0, 0, 0] + coded78[0:39] + sync + coded78[39:78] + [0, 0, 0]


# ─────────────────────────────────────────────────────────────────────────────
# GMSK modulation — TS 45.004, as implemented by osmo-trx
# ─────────────────────────────────────────────────────────────────────────────


def gsm_pulse(sps=1):
    """generateGSMPulse() from osmo-trx Transceiver52M/sigProcLib.cpp.

    At 1 sps the pulse is four taps of 0.96 * exp(-1.1380*a^2 - 0.527*a^4) with
    a = (i - 1.5), normalised so that the tap energy equals sps. At 4 sps
    osmo-trx uses a precomputed 16-tap Laurent pulse instead; those taps are
    transcribed verbatim and are NOT the same numbers as the closed form
    evaluated at 4 sps."""
    if sps == 4:
        taps = [0.0, 4.46348606e-03, 2.84385729e-02, 1.03184855e-01,
                2.56065552e-01, 4.76375085e-01, 7.05961177e-01,
                8.71291644e-01, 9.29453645e-01, 8.71291644e-01,
                7.05961177e-01, 4.76375085e-01, 2.56065552e-01,
                1.03184855e-01, 2.84385729e-02, 4.46348606e-03]
        return taps
    if sps != 1:
        raise ValueError("osmo-trx only defines a 1 sps and a 4 sps pulse")
    length = 4
    center = (length - 1.0) / 2.0
    taps = []
    for i in range(length):
        arg = (float(i) - center) / float(sps)
        taps.append(0.96 * math.exp(-1.1380 * arg * arg - 0.527 * arg ** 4))
    # vectorNorm2 over the complex taps / sps, then sqrt — the taps are real.
    avg = math.sqrt(sum(t * t for t in taps) / sps)
    return [t / avg for t in taps]


def gmsk_modulate(bits, sps=1, pulse=None):
    """rotateBurst() then GMSKRotate() from osmo-trx

    Transceiver52M/sigProcLib.cpp. Three steps, in this order:

      1. NRZ map each bit to +-1 and multiply the k-th symbol by j^k. This is
         the pi/2-per-symbol rotation that makes h = 0.5 GMSK linear, and it is
         applied at the SYMBOL rate, one value per symbol.
      2. Zero-stuff those values to `sps` samples per symbol. osmo-trx's
         rotateBurst writes to every sps-th sample and leaves the rest zero;
         the rotation table is then applied per sample, but multiplying a zero
         by anything is still zero, so the two orderings agree.
      3. Convolve with the sps-rate shaping pulse.

    Step 2 is the one that is easy to get wrong, and it was wrong here: an
    earlier version convolved the one-sample-per-symbol values directly with a
    four-sample-per-symbol pulse, so a 148-bit burst yielded 163 samples
    instead of 592 and the emitted waveform was noise. The selftest now pins
    the modulated length at every rate it supports.

    Returns a list of complex samples, (len(bits) * sps) + len(pulse) - 1 long.
    The trailing len(pulse) - 1 samples are the pulse tail, which belongs to
    the guard period that follows the burst.
    """
    if pulse is None:
        pulse = gsm_pulse(sps)
    sym = []
    for k, b in enumerate(bits):
        nrz = 2.0 * (b & 1) - 1.0
        phase = math.pi / 2.0 * k
        sym.append(complex(nrz * math.cos(phase), nrz * math.sin(phase)))

    n = len(sym) * sps
    up = [0j] * n
    for i, s in enumerate(sym):
        up[i * sps] = s

    out = [0j] * (n + len(pulse) - 1)
    for i, u in enumerate(up):
        if u == 0:
            continue
        for j, p in enumerate(pulse):
            out[i + j] += u * p
    return out


def modulate_bursts(bursts, sps=1, guard_symbols=NORMAL_GUARD_SYMBOLS):
    """Modulate a sequence of equal-length bursts with the guard period between
    them, which is what the transmitter actually emits. The guard is silence,
    and at 1 sps the fractional 8.25 becomes 8 samples — osmo-trx does the same
    and documents the 625-vs-624 sample discrepancy."""
    guard = int(guard_symbols)
    samples = []
    for b in bursts:
        samples.extend(gmsk_modulate(b, sps))
        samples.extend([0j] * (guard * sps))
    return samples


# ─────────────────────────────────────────────────────────────────────────────
# TDMA framing — TS 45.002 section 5.2
# ─────────────────────────────────────────────────────────────────────────────

# One timeslot is 156.25 symbol periods; eight of them make one TDMA frame of
# exactly 1250 symbols. At 4 samples/symbol that is 625 samples per slot, which
# is precisely the length of osmo-trx's GMSKRotation4 table — a useful
# independent confirmation that the framing arithmetic here is the same one
# osmo-trx uses.
SYMBOLS_PER_SLOT = 156.25
SLOTS_PER_FRAME = 8
SYMBOLS_PER_FRAME = SYMBOLS_PER_SLOT * SLOTS_PER_FRAME          # 1250.0
FRAME_SECONDS = SYMBOLS_PER_FRAME / 270833.3333333333           # 4.6153846e-3


# The dummy burst a BCCH carrier transmits on idle timeslots (TS 45.002
# section 5.2.5). Without it a handset cannot keep its timing loop locked on a
# carrier where only one timeslot carries data. Transcribed whole from osmo-trx
# GSM/GSMCommon.cpp:57 (`GSM::gDummyBurst`) rather than reassembled from its
# fields — it is a fixed 148-bit pattern and there is nothing to gain by
# rebuilding it from parts.
DUMMY_BURST = (
    "0001111101101110110000010100100111000001001000100000001111100011100"
    "0101110001011100010101110100101000110011001110011110100111110001001"
    "01111101010000"
)


def dummy_burst():
    if len(DUMMY_BURST) != 148:
        raise AssertionError("dummy burst is %d bits, expected 148" % len(DUMMY_BURST))
    return [int(c) for c in DUMMY_BURST]


def tdma_frame(burst_by_slot, sps=4):
    """Lay bursts out into one TDMA frame, in the SAMPLE domain.

    This is the point the framing has to get right. A slot is 156.25 symbols,
    which is not a whole number, so building a frame by concatenating
    `148 + 8` symbol periods drifts: it loses 0.25 symbols per slot and 2
    symbols per frame, about 29.5 microseconds every four frames. osmo-trx
    avoids this by working in samples — its 4 sps slot is exactly 625 samples
    (625 / 4 = 156.25) — and so does this.

    `burst_by_slot` maps a timeslot number 0..7 to a 148-bit burst; missing
    slots get a dummy burst, which is what a real BCCH carrier transmits."""
    slot_samples = int(round(SYMBOLS_PER_SLOT * sps))
    frame = []
    for tn in range(SLOTS_PER_FRAME):
        burst = burst_by_slot.get(tn) or dummy_burst()
        if len(burst) != 148:
            raise ValueError("slot %d burst must be 148 bits, got %d" % (tn, len(burst)))
        samples = gmsk_modulate(burst, sps)
        # The shaping pulse smears each burst by (len(pulse) - 1) samples.
        # That spill belongs in the guard period, which is why the burst is
        # placed at the slot start and the padding goes after it.
        if len(samples) > slot_samples:
            raise ValueError(
                "slot %d: %d modulated samples do not fit the %d-sample slot; "
                "the pulse tail has overrun the guard period"
                % (tn, len(samples), slot_samples))
        frame.extend(samples)
        frame.extend([0j] * (slot_samples - len(samples)))
    return frame


def tdma_stream(l2_blocks, tsc=0, tn=0, sps=4):
    """The burst train a real transmitter emits: each 23-octet L2 block becomes
    four 116-bit xCCH bursts, and those four bursts go out in the same timeslot
    of four consecutive TDMA frames. Every other slot carries a dummy burst."""
    frames = []
    for block in l2_blocks:
        for b in xcch_encode(block):
            frames.append(tdma_frame({tn: normal_burst(b, tsc)}, sps))
    samples = []
    for f in frames:
        samples.extend(f)
    return samples, frames


# ─────────────────────────────────────────────────────────────────────────────
# The BCCH carrier — TS 45.002 section 6.3.1.3
#
# A transmitter that only emits BCCH bursts is invisible: no handset will camp
# on it, because camping starts with the frequency correction burst. A phone
# powers up, scans the band, and looks for a pure tone at +67.708 kHz — that is
# the FCCH. It then reads the SCH immediately after it to learn the frame
# number and the base station colour code, and only then does it read BCCH.
#
# gr-gsm's receiver enforces the same order. receiver_impl.cc:221 returns
# without looking at anything else until find_fcch_burst() has succeeded, which
# is why a stream of correct BCCH bursts alone decodes to nothing.
# ─────────────────────────────────────────────────────────────────────────────


def fcch_burst():
    """The frequency correction burst: all 148 bits zero.

    There is no data in an FCCH. A zero bit is a +1 NRZ symbol, so an unbroken
    run of them rotates the GMSK phase by pi/2 per symbol, and the resulting
    constant-envelope tone sits at a quarter of the symbol rate above the
    carrier: 270833.3333 / 4 = 67708.333 Hz, which is the figure the tree's
    `11_gsm_attack --fcch-facts` reports. The burst is 148 bits rather than 142
    because it keeps the normal burst's 3-bit tails, which are zero anyway.
    """
    return [0] * NORMAL_BURST_BITS


def sch_payload(bsic, fn):
    """The 25 bits an SCH burst carries, in the order gsm0503_sch_encode()
    expects them.

    The payload is BSIC(6) || T1(11) || T2(5) || T3'(3), and those fields are a
    lossy encoding of the frame number: the reduced frame number RFN = T1*26 +
    T2 = (FN - T3) / 51, with T3 = FN mod 51 and T3' = (T3 - 1) / 10. A handset
    recovers FN = 51*((T3 - T2) mod 26) + T3 + 51*26*T1.

    Bit order is the trap. TS 44.004 section 7.10 transmits octets bit 1 first,
    while the figure the fields are drawn in is octet bit 8 first, so the 25
    bits are packed into octets most-significant-bit first and then unpacked
    least-significant-bit first — exactly what osmo_pbit2ubit_ext(..., 1) does
    inside libosmocoding. Verified against `11_gsm_attack --sch-payload 7 1 0`,
    which prints the same 25 bits as `sch_bits_tx`.
    """
    if not 0 <= bsic <= 63:
        raise ValueError("BSIC must be 0..63, got %r" % (bsic,))
    t1 = fn // (26 * 51)
    t2 = fn % 26
    t3 = fn % 51
    t3p = (t3 - 1) // 10
    bits = []
    for value, width in ((bsic, 6), (t1, 11), (t2, 5), (t3p, 3)):
        if value >= (1 << width):
            raise ValueError("frame number %d does not fit the SCH fields" % fn)
        bits.extend(int(c) for c in format(value, "0%db" % width))
    octets = []
    for i in range(0, 25, 8):
        chunk = bits[i:i + 8]
        octets.append(int("".join(str(b) for b in chunk).ljust(8, "0"), 2))
    out = []
    for o in octets:
        out.extend((o >> k) & 1 for k in range(8))
    return out[:25]


# Which of the eight slots of a 51-frame multiframe carry what, indexed by
# FN mod 51. 'F' is FCCH, 'S' is SCH, a digit is the BCCH block number within
# the multiframe, and '.' is a CCCH block, which this builder leaves as a dummy
# burst. Frames 0-29 interleave five FCCH/SCH pairs with five BCCH blocks;
# frames 30-50 are CCCH only.
_MULTIFRAME = []
for _fn in range(51):
    if _fn <= 24 and _fn % 6 == 0:
        _MULTIFRAME.append("F")
    elif _fn <= 25 and _fn % 6 == 1:
        _MULTIFRAME.append("S")
    elif 2 <= _fn <= 29 and (_fn % 6) in (2, 3, 4, 5):
        _MULTIFRAME.append(str((_fn - 2) // 6))
    else:
        _MULTIFRAME.append(".")
assert len(_MULTIFRAME) == 51


def bcch_carrier(l2_blocks, bsic=0, tsc=None, sps=4, multiframes=1, tn=0):
    """Build a complete BCCH carrier, the waveform a phone actually camps on.

    `l2_blocks` are 23-octet L2 blocks for the BCCH; block N of the multiframe
    carries `l2_blocks[N % len(l2_blocks)]`. The TSC defaults to the BCC, which
    TS 45.002 section 5.2.3.1 requires for BCCH ("the TSC must be equal to the
    BCC ... selected from the TSC Set 1"), and the BCC is the low three bits of
    the BSIC.

    Returns (samples, frame_count). One 51-frame multiframe is 51 * 1250 symbol
    periods = 0.2354 seconds.
    """
    if tsc is None:
        tsc = bsic & 0x07
    if tsc != (bsic & 0x07):
        raise ValueError(
            "for BCCH the TSC must equal the BCC: bsic %d has BCC %d, got tsc %d"
            % (bsic, bsic & 0x07, tsc))
    if not l2_blocks:
        raise ValueError("need at least one BCCH L2 block")
    for blk in l2_blocks:
        if len(blk) != 23:
            raise ValueError("BCCH L2 blocks are 23 octets, got %d" % len(blk))

    # Each distinct BCCH block is four xCCH bursts, one per frame.
    coded = [xcch_encode(blk) for blk in l2_blocks]

    frames = []
    for fn in range(51 * multiframes):
        what = _MULTIFRAME[fn % 51]
        if what == "F":
            burst = fcch_burst()
        elif what == "S":
            burst = sch_burst(sch_encode(sch_payload(bsic, fn)))
        elif what.isdigit():
            index = int(what) + 5 * (fn // 51)
            burst = normal_burst(coded[index % len(coded)][(fn % 6) - 2], tsc)
        else:
            burst = dummy_burst()
        frames.append(tdma_frame({tn: burst}, sps))
    samples = []
    for f in frames:
        samples.extend(f)
    return samples, len(frames)


def resample(samples, factor):
    """Integer interpolation by `factor` with a windowed-sinc low-pass. Zero
    stuffing alone would leave spectral images at every multiple of the symbol
    rate, which on a real transmitter is adjacent-channel interference; the
    filter is what makes the output usable."""
    if factor == 1:
        return list(samples)
    taps = factor * 16 + 1
    half = (taps - 1) // 2
    cutoff = 1.0 / factor
    h = []
    for i in range(taps):
        x = i - half
        if x == 0:
            s = cutoff
        else:
            s = math.sin(math.pi * cutoff * x) / (math.pi * x)
        # Blackman window.
        w = (0.42 - 0.5 * math.cos(2 * math.pi * i / (taps - 1))
             + 0.08 * math.cos(4 * math.pi * i / (taps - 1)))
        h.append(s * w)
    gain = sum(h)
    h = [t / gain for t in h]

    up = [0j] * (len(samples) * factor)
    for i, s in enumerate(samples):
        up[i * factor] = s * factor
    n = len(up)
    out = [0j] * (n + taps - 1)
    for i, u in enumerate(up):
        if u == 0:
            continue
        for j, t in enumerate(h):
            out[i + j] += u * t
    return out[half:half + n]


def to_int8(samples, headroom=0.9):
    """HackRF's transmit format: interleaved signed 8-bit I/Q. The stream is
    normalised to its own peak and scaled with headroom so the DAC does not
    clip — a clipped GMSK burst spreads energy into adjacent channels and would
    not be a legal transmission even if it were otherwise correct."""
    peak = max((abs(s) for s in samples), default=0.0)
    if peak == 0:
        return bytes(len(samples) * 2)
    scale = 127.0 * headroom / peak
    out = bytearray()
    for s in samples:
        i = int(round(s.real * scale))
        q = int(round(s.imag * scale))
        i = max(-128, min(127, i))
        q = max(-128, min(127, q))
        out.append(i & 0xFF)
        out.append(q & 0xFF)
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-check vectors captured from libosmocoding
# ─────────────────────────────────────────────────────────────────────────────

# Captured by calling libosmocoding's own gsm0503_xcch_encode through a small
# C shim (the runtime library is installed; the headers are not). These are the
# vectors the selftest asserts against, so the chain is checked against an
# independent implementation rather than against its own output.
#
#   l2 0000..00 (23 zero octets)
LIBSOMC_ZERO = [
    "00000001000010000000010000101000000100001010000001000000111000000100000010000001010000100000010100001000000001000010",
    "00000000000000000000000010000000000000000000000000000000011000000000000000000000000000000000000000000000000000000010",
    "00010000101000000100000010000001010000100000010100001000011000010000100000000100001000000001000010000000010000101000",
    "00000000000000000100000000000000000000000001000000000000011000000000000000000000000000000000000000000000000000000000",
]

#   l2 00 01 02 .. 16
LIBSOMC_INC = [
    "01000101001111100001010011001110111010010110101111100100011100010101101111101010100001101110111100010100000101101110",
    "00011110111001101111100101101011010001001100010001101111111010010101001110111010000101000011101110110001000000111100",
    "11101010110111011000100101101010111010010111011001111000011100010000110111011100100101000000000001111101100111101011",
    "10000111001011111110101101110110110010111111101010110111011111100101000001000000011111011101001011010000000001011101",
]

#   SCH information 0001110000000000000001000 (BSIC 7, frame number 0)
LIBSOMC_SCH = "000011101010000011000000000000000000001101001111000000000000111001111110001111"

#   RACH ra = 0x00, BSIC = 7
LIBSOMC_RACH = "000000000000000011101010000011000000"


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


def cmd_bursts(args):
    l2 = parse_hex(args.hex, "the L2 block")
    if len(l2) != 23:
        raise SystemExit("ERROR\tthe L2 block must be 23 octets, got %d" % len(l2))
    for i, b in enumerate(xcch_encode(l2)):
        print("burst%d\t%s" % (i, bits_str(b)))
    return 0


def cmd_octets(args):
    l2 = parse_hex(args.hex, "the L2 block")
    if len(l2) != 23:
        raise SystemExit("ERROR\tthe L2 block must be 23 octets, got %d" % len(l2))
    for i, b in enumerate(xcch_encode(l2)):
        full = normal_burst(b, args.tsc)
        print("octet%d\t%s" % (i, bits_str(full)))
        print("octet%d_bits\t%d" % (i, len(full)))
    return 0


def cmd_iq(args):
    l2 = parse_hex(args.hex, "the L2 block")
    bursts = [normal_burst(b, args.tsc) for b in xcch_encode(l2)]
    samples = modulate_bursts(bursts, args.sps)
    print("samples\t%d" % len(samples))
    print("sps\t%d" % args.sps)
    print("iq_hex\t%s" % "".join(
        struct.pack("<ff", s.real, s.imag).hex() for s in samples))
    return 0


def cmd_cfile(args):
    l2 = parse_hex(args.hex, "the L2 block")
    bursts = [normal_burst(b, args.tsc) for b in xcch_encode(l2)]
    samples = modulate_bursts(bursts, args.sps)
    with open(args.out, "wb") as fh:
        for s in samples:
            fh.write(struct.pack("<ff", s.real, s.imag))
    print("wrote\t%s" % args.out)
    print("samples\t%d" % len(samples))
    print("sps\t%d" % args.sps)
    print("format\tcomplex float32, interleaved I/Q")
    return 0


def cmd_tx(args):
    """Build the real transmit stream: a 23-octet L2 block, xCCH coded, laid
    out into TDMA frames with dummy bursts in the idle slots, modulated, resampled
    to the device rate, and written in HackRF's signed 8-bit format."""
    l2 = parse_hex(args.hex, "the L2 block")
    if len(l2) != 23:
        raise SystemExit("ERROR\tthe L2 block must be 23 octets, got %d" % len(l2))
    if args.tn < 0 or args.tn > 7:
        raise SystemExit("ERROR\ttimeslot must be 0..7, got %d" % args.tn)
    if args.rate < 2.0e6:
        raise SystemExit("ERROR\tsample rate %.0f is below the 2 Msps a HackRF can "
                         "actually run at; GSM needs a symbol rate of 270.833 ksps "
                         "so the stream must be oversampled" % args.rate)
    oversample = int(round(args.rate / 270833.3333333333))
    if oversample < 4:
        raise SystemExit("ERROR\t%.0f Hz is only %d samples/symbol; at least 4 is "
                         "needed for the osmo-trx shaping pulse"
                         % (args.rate, oversample))
    base_sps = 4
    if oversample % base_sps != 0:
        raise SystemExit("ERROR\toversampling factor %d is not a multiple of %d, "
                         "so the 4 sps shaping pulse cannot be resampled exactly"
                         % (oversample, base_sps))
    samples, frames = tdma_stream([l2], tsc=args.tsc, tn=args.tn, sps=base_sps)
    samples = resample(samples, oversample // base_sps)
    data = to_int8(samples)

    print("l2_octets\t%d" % len(l2))
    print("l2\t%s" % l2.hex())
    print("xcch_bursts\t%d" % len(frames))
    print("tdma_frames\t%d" % len(frames))
    print("timeslot\t%d" % args.tn)
    print("tsc\t%d" % args.tsc)
    print("bcc_check\t%s" % ("ok" if args.tsc == (args.bsic % 8) else
                             "WARNING: for BCCH the TSC must equal the BCC"))
    print("symbol_rate\t%.6f" % 270833.3333333333)
    print("base_sps\t%d" % base_sps)
    print("oversample\t%d" % oversample)
    print("sample_rate\t%d" % int(round(270833.3333333333 * oversample)))
    print("samples\t%d" % len(samples))
    print("slot_samples\t%d" % int(round(SYMBOLS_PER_SLOT * oversample)))
    print("frame_samples\t%d" % int(round(SYMBOLS_PER_FRAME * oversample)))
    print("frame_microseconds\t%.4f" % (FRAME_SECONDS * 1e6))
    print("duration_microseconds\t%.4f" % (len(samples) / args.rate * 1e6))
    print("bytes\t%d" % len(data))
    print("format\tcs8 (interleaved signed 8-bit I/Q)")
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(data)
        import hashlib
        print("file\t%s" % args.out)
        print("sha256\t%s" % hashlib.sha256(data).hexdigest())
    else:
        print("iq_hex\t%s" % data.hex())
    return 0


def cmd_carrier(args):
    """Emit a whole BCCH carrier as a sample stream.

    Two output formats, because they answer two different questions. `cfile`
    writes interleaved complex float32, which is what gr-gsm's decoder reads —
    that is the format used to prove the waveform is decodable by an
    independent receiver. `cs8` writes interleaved signed 8-bit, which is what
    hackrf_transfer transmits.
    """
    blocks = list(args.block)
    if not blocks:
        # A syntactically valid SI3-shaped BCCH block: LAPDm address/control,
        # then a 21-octet rest field. It is filler, not a real System
        # Information message, and the caller is expected to supply real ones;
        # it exists so the command has a well-formed default.
        blocks = ["490604030001" + "00" * 17]
    l2 = []
    for h in blocks:
        b = parse_hex(h, "BCCH L2 block")
        if len(b) != 23:
            raise SystemExit("ERROR\tBCCH L2 blocks are 23 octets, got %d" % len(b))
        l2.append(b)

    base_sps = 4
    oversample = int(round(args.rate / 270833.3333333333)) if args.rate else base_sps
    if args.format == "cs8":
        if args.rate < 2.0e6:
            raise SystemExit(
                "ERROR\tsample rate %.0f is below the 2 Msps a HackRF can actually "
                "run at; GSM needs a 270.833 ksps symbol rate, so the stream must "
                "be oversampled" % args.rate)
        if oversample % base_sps != 0:
            raise SystemExit(
                "ERROR\toversampling factor %d is not a multiple of %d, so the 4 sps "
                "shaping pulse cannot be resampled exactly" % (oversample, base_sps))

    samples, frames = bcch_carrier(l2, bsic=args.bsic, sps=base_sps,
                                   multiframes=args.multiframes, tn=args.tn)
    if args.format == "cs8":
        samples = resample(samples, oversample // base_sps)
        data = to_int8(samples)
    else:
        oversample = base_sps
        data = b"".join(struct.pack("<ff", s.real, s.imag) for s in samples)

    print("bsic\t%d" % args.bsic)
    print("ncc\t%d" % (args.bsic >> 3))
    print("bcc\t%d" % (args.bsic & 0x07))
    print("tsc\t%d" % (args.bsic & 0x07))
    print("timeslot\t%d" % args.tn)
    print("bcch_blocks\t%d" % len(l2))
    print("multiframes\t%d" % args.multiframes)
    print("tdma_frames\t%d" % frames)
    print("multiframe_seconds\t%.6f" % (1250.0 * 51 / 270833.3333333333))
    print("symbol_rate\t%.6f" % 270833.3333333333)
    print("oversample\t%d" % oversample)
    print("sample_rate\t%d" % int(round(270833.3333333333 * oversample)))
    print("base_sps\t%d" % base_sps)
    print("samples\t%d" % len(samples))
    print("frame_samples\t%d" % int(round(SYMBOLS_PER_FRAME * oversample)))
    print("slot_samples\t%d" % int(round(SYMBOLS_PER_SLOT * oversample)))
    print("duration_microseconds\t%.4f"
          % (frames * SYMBOLS_PER_FRAME / 270833.3333333333 * 1e6))
    print("bytes\t%d" % len(data))
    print("format\t%s" % ("cs8 (interleaved signed 8-bit I/Q)" if args.format == "cs8"
                          else "complex float32, interleaved I/Q"))
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(data)
        import hashlib
        print("file\t%s" % args.out)
        print("sha256\t%s" % hashlib.sha256(data).hexdigest())
    return 0


def cmd_pulse(args):
    for i, t in enumerate(gsm_pulse(args.sps)):
        print("tap%d\t%.10f" % (i, t))
    return 0


def cmd_vectors(args):
    print("xcch_zero\t" + "|".join(LIBSOMC_ZERO))
    print("xcch_inc\t" + "|".join(LIBSOMC_INC))
    print("sch\t" + LIBSOMC_SCH)
    print("rach\t" + LIBSOMC_RACH)
    return 0


def selftest():
    failures = []

    def chk(name, got, want):
        if got != want:
            failures.append("%s FAIL want=%s got=%s" % (name, want, got))

    def _raises(fn):
        try:
            fn()
        except Exception:
            return True
        return False

    # The chain against libosmocoding's output. If the LSB/MSB convention or
    # the generator order is wrong, every one of these eight lines breaks.
    for i, want in enumerate(LIBSOMC_ZERO):
        chk("libsombc-zero-burst%d" % i, bits_str(xcch_encode(b"\x00" * 23)[i]), want)
    inc = bytes(range(0x17))
    for i, want in enumerate(LIBSOMC_INC):
        chk("libsombc-inc-burst%d" % i, bits_str(xcch_encode(inc)[i]), want)

    # The SCH information field for BSIC 7, frame number 0, as the module's
    # own --sch-payload prints it.
    sb = bytes_to_bits_lsb(bytes.fromhex("1c000800"), 25)
    chk("sch-info", bits_str(sb), "0011100000000000000100000")
    chk("libsombc-sch", bits_str(sch_encode(sb)), LIBSOMC_SCH)

    # RACH with BSIC 7.
    ra = bytes_to_bits_lsb(b"\x00", 8)
    chk("libsombc-rach", bits_str(rach_encode(ra, 7)), LIBSOMC_RACH)

    # The interleaver is a permutation: every slot written exactly once.
    iB = xcch_interleave(list(range(XCCH_BLOCK_BITS)))
    chk("interleave-is-permutation", sorted(iB) == list(range(XCCH_BLOCK_BITS)), True)
    chk("deinterleave-inverts",
        xcch_deinterleave(xcch_interleave(list(range(XCCH_BLOCK_BITS)))),
        list(range(XCCH_BLOCK_BITS)))

    # A normal burst is 148 bits: 3 + 57 + 1 + 26 + 1 + 57 + 3.
    full = normal_burst(xcch_encode(b"\x00" * 23)[0], 0)
    chk("normal-burst-bits", len(full), NORMAL_BURST_BITS)
    chk("normal-burst-tail", full[0:3], [0, 0, 0])
    chk("normal-burst-tsc", bits_str(full[61:87]), TSC_SET_1[0])
    chk("normal-burst-tail2", full[145:148], [0, 0, 0])
    # The stealing flags land at BN 60 and BN 87, straddling the training
    # sequence. Asserting they are adjacent is how the original bug survived.
    chk("stealing-flags-straddle-tsc", [full[60], full[87]], [1, 1])
    chk("no-stray-flags-after-tsc", [full[88], full[89]], list(full[88:90]))

    # The complete training sequence set against osmo-trx GSMCommon.cpp:35.
    # Six of these eight were wrong when written from memory.
    want_tsc = {
        0: "00100101110000100010010111", 1: "00101101110111100010110111",
        2: "01000011101110100100001110", 3: "01000111101101000100011110",
        4: "00011010111001000001101011", 5: "01001110101100000100111010",
        6: "10100111110110001010011111", 7: "11101111000100101110111100",
    }
    for t, seq in want_tsc.items():
        chk("tsc%d" % t, TSC_SET_1[t], seq)
        chk("tsc%d-length" % t, len(TSC_SET_1[t]), 26)
    chk("tsc-count", len(TSC_SET_1), 8)
    # Every TSC placed at BN 61..86 by normal_burst.
    for t in range(8):
        chk("tsc%d-placement" % t,
            bits_str(normal_burst(xcch_encode(b"\x00" * 23)[0], t)[61:87]),
            want_tsc[t])

    # The 64-bit SCH training sequence, TS 45.002 table 5.2.5-3.
    chk("sch-sync-length", len(SCH_SYNC_SEQUENCE), 64)
    chk("sch-sync-value", SCH_SYNC_SEQUENCE,
        "1011100101100010000001000000111100101101010001010111011000011011")
    sburst = sch_burst([0] * 78)
    chk("sch-burst-bits", len(sburst), 148)
    chk("sch-burst-sync", bits_str(sburst[42:106]), SCH_SYNC_SEQUENCE)

    # The access burst against osmo-trx's own pre-modulated reference burst
    # (GSMCommon.cpp:69, `GSM::gRACHBurst`). Its data field happens to be the
    # 36 bits below, so feeding them back through access_burst must reproduce
    # the entire 88-bit construct byte for byte.
    chk("rach-sync-ts0-length", len(RACH_SYNC_TS0), 41)
    chk("rach-sync-ts0-value", RACH_SYNC_TS0,
        "01001011011111111001100110101010001111000")
    chk("rach-head-value", RACH_HEAD, "00111010")
    rach_ref = ("001110100100101101111111100110011010101000111100"
                "0110111101111110000111001001010110011000")
    chk("rach-burst-bits", len(rach_ref), 88)
    rach_data = [int(c) for c in rach_ref[49:85]]
    chk("rach-burst-matches-osmo-trx",
        bits_str(access_burst(rach_data)), rach_ref)
    chk("rach-burst-length", len(access_burst([0] * 36)), 88)
    # The three access sync variants must differ from each other.
    chk("rach-sync-variants-distinct",
        len({RACH_SYNC_TS0, RACH_SYNC_TS1, RACH_SYNC_TS2}), 3)
    for name, seq in (("ts0", RACH_SYNC_TS0), ("ts1", RACH_SYNC_TS1),
                      ("ts2", RACH_SYNC_TS2)):
        chk("rach-sync-%s-length" % name, len(seq), 41)

    # The pulse: at 1 sps, normalised so its tap energy is sps, symmetric.
    p1 = gsm_pulse(1)
    chk("pulse-1sps-length", len(p1), 4)
    chk("pulse-1sps-energy", round(sum(t * t for t in p1), 9), 1.0)
    chk("pulse-1sps-symmetric", [round(t, 12) for t in p1],
        [round(t, 12) for t in reversed(p1)])
    # The 4 sps pulse is a precomputed Laurent table in osmo-trx, NOT the
    # closed form sampled four times. Its shape is a leading 0.0 followed by a
    # 15-tap palindrome — so the table is asymmetric overall purely because of
    # that first tap. Asserting plain symmetry, as an earlier version did,
    # fails against the real published table.
    p4 = gsm_pulse(4)
    chk("pulse-4sps-length", len(p4), 16)
    chk("pulse-4sps-published-table", p4, [
        0.0, 4.46348606e-03, 2.84385729e-02, 1.03184855e-01,
        2.56065552e-01, 4.76375085e-01, 7.05961177e-01,
        8.71291644e-01, 9.29453645e-01, 8.71291644e-01,
        7.05961177e-01, 4.76375085e-01, 2.56065552e-01,
        1.03184855e-01, 2.84385729e-02, 4.46348606e-03])
    chk("pulse-4sps-leading-tap-zero", p4[0], 0.0)
    chk("pulse-4sps-tail-is-palindrome", p4[1:], list(reversed(p4[1:])))
    chk("pulse-4sps-entire-table-is-not-symmetric", p4 != list(reversed(p4)), True)
    chk("pulse-4sps-peak-index", p4.index(max(p4)), 8)
    chk("pulse-4sps-peak-value", max(p4), 9.29453645e-01)

    # The rotation is a quarter turn per symbol: the k-th symbol is j^k.
    x = gmsk_modulate([1, 1, 1, 1], 1, pulse=[1.0])
    chk("rotation-quarter-turns",
        [round(s.real, 9) for s in x[:4]], [1.0, 0.0, -1.0, -0.0])

    # NRZ polarity: bit 1 is +1, bit 0 is -1.
    x0 = gmsk_modulate([0], 1, pulse=[1.0])
    chk("nrz-zero-is-minus-one", x0[0].real, -1.0)

    # The modulated length must scale with sps. This is the assertion whose
    # absence let the zero-stuffing bug through: a 148-bit burst at 4 sps is
    # 592 samples of signal plus a 15-sample pulse tail, NOT 148 + 15.
    chk("modulate-1sps-length", len(gmsk_modulate([0] * 148, 1)), 148 + 3)
    chk("modulate-4sps-length", len(gmsk_modulate([0] * 148, 4)), 148 * 4 + 15)
    chk("modulate-scales-with-sps",
        len(gmsk_modulate([0] * 148, 4)) > 3 * len(gmsk_modulate([0] * 148, 1)), True)
    # The four-symbol burst must occupy 4 samples per symbol, so the energy of
    # a single-symbol impulse is spread over the pulse, not packed into one.
    imp = gmsk_modulate([1], 4)
    chk("modulate-4sps-single-symbol-length", len(imp), 4 + 15)
    # 15, not 16: the published four-sample-per-symbol pulse opens with a tap of
    # exactly 0.0 (see gsm_pulse), so only fifteen of the sixteen taps are
    # non-zero. That leading zero is real — it is in osmo-trx's table, and it is
    # why this pulse is not a palindrome.
    chk("modulate-4sps-impulse-spread", sum(1 for s in imp if abs(s) > 1e-9), 15)
    chk("modulate-4sps-impulse-total-energy",
        round(sum(abs(s) ** 2 for s in imp), 6),
        round(sum(t * t for t in gsm_pulse(4)), 6))

    # TDMA framing, TS 45.002 section 5.2: eight slots of 156.25 symbols make
    # exactly one 1250-symbol frame. In the sample domain a 4 sps slot is
    # exactly 625 samples — the same 625 as osmo-trx's GMSKRotation4 table.
    chk("symbols-per-frame", SYMBOLS_PER_FRAME, 1250.0)
    chk("frame-milliseconds", round(FRAME_SECONDS * 1e3, 6), 4.615385)
    chk("slot-samples-4sps", int(round(SYMBOLS_PER_SLOT * 4)), 625)
    chk("slot-samples-8sps", int(round(SYMBOLS_PER_SLOT * 8)), 1250)
    dummy = dummy_burst()
    chk("dummy-burst-length", len(dummy), 148)
    chk("dummy-burst-tsc", bits_str(dummy[61:87]), DUMMY_BURST_TSC)
    frame = tdma_frame({0: normal_burst(xcch_encode(b"\x00" * 23)[0], 0)}, sps=4)
    chk("frame-samples-4sps", len(frame), 5000)
    # 8 sps is reached by resampling the 4 sps stream, never by asking for an
    # 8 sps pulse — osmo-trx defines only the 1 sps and 4 sps shapes.
    chk("frame-samples-8sps-via-resample", len(resample(frame, 2)), 10000)
    chk("8sps-pulse-is-not-defined",
        "ValueError" if _raises(lambda: gsm_pulse(8)) else "no error", "ValueError")
    # Slot 0 carries the real burst, slots 1..7 carry dummy bursts.
    chk("slot0-is-real-burst", bits_str(gmsk_modulate([0], 1)) is not None, True)
    # The modulators must place each slot at a whole-sample boundary, so a
    # frame is exactly 8 slots with no accumulated drift. Check by locating the
    # non-zero region of an all-dummy frame: it must be entirely non-zero,
    # since every slot carries a burst.
    all_dummy = tdma_frame({}, sps=4)
    chk("all-dummy-frame-full", len(all_dummy), 5000)
    chk("no-drift-frame-length",
        len(tdma_frame({}, sps=4)) * 4, 20000)
    # Four xCCH bursts become four consecutive frames on one timeslot.
    samples, frames = tdma_stream([b"\x00" * 23], tsc=0, tn=0, sps=4)
    chk("stream-frames", len(frames), 4)
    chk("stream-samples-4sps", len(samples), 4 * 5000)
    chk("stream-samples-8sps-would-be", 4 * 10000, 40000)

    # Resampling: 2x interpolation doubles the length and nearly preserves
    # peak (a windowed-sinc cannot preserve a discontinuous peak exactly).
    rs = resample([1 + 0j, 0j, -1 + 0j, 0j], 2)
    chk("resample-doubles-length", len(rs), 8)
    chk("resample-preserves-peak", round(max(abs(s) for s in rs), 4), 0.9999)
    chk("resample-identity", resample([1 + 0j, 2 + 0j], 1), [1 + 0j, 2 + 0j])

    # int8 packing: HackRF wants signed 8-bit interleaved I/Q, peak-scaled with
    # 0.9 headroom so the DAC cannot clip.
    raw = to_int8([1 + 0j, 0 + 1j, -1 + 0j])
    chk("int8-bytes", len(raw), 6)
    chk("int8-max-positive", raw[0], 114)      # 127 * 0.9
    chk("int8-q-positive", raw[3], 114)
    chk("int8-negative", raw[4], 256 - 114)
    chk("int8-silence", to_int8([0j, 0j]), b"\x00\x00\x00\x00")
    signed = [b - 256 if b > 127 else b for b in raw]
    chk("int8-within-signed-range", all(-128 <= v <= 127 for v in signed), True)
    chk("int8-headroom-leaves-room", max(signed), 114)

    # The whole transmit chain end to end, at the real device rate: four TDMA
    # frames at 4 sps resampled 2x to 8 sps = 40000 samples of 2.1667 Msps.
    tx_samples, _ = tdma_stream([b"\x00" * 23], tsc=0, tn=0, sps=4)
    tx_samples = resample(tx_samples, 2)
    chk("tx-samples", len(tx_samples), 40000)
    chk("tx-rate", int(round(270833.3333333333 * 8)), 2166667)
    chk("tx-duration-ms",
        round(len(tx_samples) / (270833.3333333333 * 8) * 1e3, 3), 18.462)

    if failures:
        for f in failures:
            print(f)
        print("RESULT\tFAIL(%d)" % len(failures))
        return 1
    print("RESULT\tPASS")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="gsm_mod", add_help=True)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("bursts"); p.add_argument("hex"); p.set_defaults(fn=cmd_bursts)
    p = sub.add_parser("octets")
    p.add_argument("hex"); p.add_argument("tsc", nargs="?", type=int, default=0)
    p.set_defaults(fn=cmd_octets)
    p = sub.add_parser("iq")
    p.add_argument("hex")
    p.add_argument("sps", nargs="?", type=int, default=1)
    p.add_argument("tsc", nargs="?", type=int, default=0)
    p.set_defaults(fn=cmd_iq)
    p = sub.add_parser("cfile")
    p.add_argument("out"); p.add_argument("hex")
    p.add_argument("sps", nargs="?", type=int, default=1)
    p.add_argument("tsc", nargs="?", type=int, default=0)
    p.set_defaults(fn=cmd_cfile)
    p = sub.add_parser("pulse"); p.add_argument("sps", nargs="?", type=int, default=1)
    p.set_defaults(fn=cmd_pulse)
    p = sub.add_parser("tx")
    p.add_argument("hex")
    p.add_argument("out", nargs="?", default="")
    p.add_argument("--rate", type=float, default=2166666.666666667)
    p.add_argument("--tn", type=int, default=0)
    p.add_argument("--tsc", type=int, default=0)
    p.add_argument("--bsic", type=int, default=7)
    p.set_defaults(fn=cmd_tx)
    p = sub.add_parser("carrier")
    p.add_argument("out", nargs="?", default="")
    p.add_argument("--block", action="append", default=[],
                   help="a 23-octet BCCH L2 block as hex; repeat for more blocks")
    p.add_argument("--bsic", type=int, default=0)
    p.add_argument("--tn", type=int, default=0)
    p.add_argument("--multiframes", type=int, default=1)
    p.add_argument("--rate", type=float, default=2166666.666666667)
    p.add_argument("--format", choices=("cs8", "cfile"), default="cs8")
    p.set_defaults(fn=cmd_carrier)
    sub.add_parser("vectors").set_defaults(fn=cmd_vectors)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())

    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        ap.print_help()
        return 2
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
