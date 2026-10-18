#!/usr/bin/env python3
"""phy_seqs.py -- turn a reference signal into IQ samples at a requested rate.

The tree already has LTE *downlink* PHY stages in `tools/lte_phy.py` (PSS,
SSS, PBCH, CRS, PDSCH, OFDM -- cross-checked against srsRAN_4G) and its own
NR SSB generator in `modules/12_nr_air.sh`. What it had no place for is the
step between "a clause defines a sequence" and "here are samples a baseband
emitter can play". This tool is that place, for the three signals nobody had
implemented yet:

    gps-ca   GPS L1 C/A spreading code, IS-GPS-200 (ICD-GPS-200) 3.2.2
    prach    LTE PRACH preamble, TS 36.211 5.7.1 / 5.7.2
    prs      LTE positioning reference signal, TS 36.211 6.10.4

It writes a flat interleaved-IQ file and prints the parameters it used as TSV
on stdout, one `key<TAB>value` per line, so the caller never has to trust that
the numbers in its own command line are the numbers that were used. The
consumer is `modules/33_jamming_detect.sh`, which builds baseband waveforms.

    tools/phy_seqs.py list
    tools/phy_seqs.py gen --seq gps-ca --out X.cf32 [--prn N] [--rate SPS]
                          [--secs S] [--format cf32|ci16|cu8]

Exit codes: 0 success, 1 I/O failure (cannot write, no numpy, no lte_phy.py
next to this file), 2 bad argument (unknown sequence, bad format, bad rate,
out-of-range PRN / PCI / preamble / N_CS zone / v, invalid PRS bandwidth).

== What each sequence is, and what it is NOT ==

gps-ca -- the C/A code, data-less.
    Generated as IS-GPS-200 Figure 3-9 defines it: two 10-stage maximal
    length shift registers, G1 with x^10 + x^3 + 1 (stages 3 and 10 XORed into
    the input) and G2 with x^10 + x^9 + x^8 + x^6 + x^3 + x^2 + 1 (stages
    2,3,6,8,9,10), both loaded with all ones at the start of each 1023-chip
    period. Chip i of PRN n is

        ca(i) = G1(i) XOR G2((i - d_n) mod 1023)

    where d_n is the "Code Delay Chips (C/A)" column of Table 3-Ia -- G2 is
    delayed by d_n chips. Because G2 has period 1023 this is the same as
    advancing it by 1023 - d_n, which is the form many implementations use;
    the table's number is the delay, not the advance. Getting that backwards
    produces a code that is still 1023 chips, still +-1, still 32 distinct
    codes, still three-valued in autocorrelation -- and wrong for every PRN.
    The check pins it against the published first-ten-chips octal vector for
    all 32 PRNs, which is what catches a sign error here.

    Samples: BPSK, chip -> sample by zero-order hold at --rate, and the
    1023-chip period is simply repeated to fill --secs. No navigation data
    (all-zero nav message: this is the pure C/A carrier, not a GPS signal),
    no carrier frequency, no Doppler, no PRN-dependent power. Q is zero: this
    is a real baseband, not a complex envelope on an intermediate frequency.

prach -- the LTE PRACH preamble, format 0.
    x_u(n) = exp(-j*pi*u*n*(n+1)/N_ZC), N_ZC = 839, followed by the cyclic
    shift x_u,v(n) = x_u((n + C_v) mod N_ZC) with the unrestricted-set
    C_v = v*N_CS (TS 36.211 5.7.2). N_CS comes from zeroCorrelationZoneConfig
    0..15 via Table 5.7.2-2 (unrestricted set, formats 0-3):
    --ncs selects that config index, not the N_CS value itself, and the TSV
    prints both (`ncs_zone` and `ncs`) so the choice is never ambiguous after
    the fact.

    The emitted block is the whole format-0 occasion: CP of 3168*Ts =
    103.125 us (the tail of the CAZAC copied to the front), the 800 us
    sequence (839 samples at N_RA = 1.04875 MHz), then 2976*Ts = 96.875 us of
    guard -- exactly 1 ms, tiled to fill --secs. The resample from 839 samples
    to --rate*0.8 ms is a circular FFT zero-pad, i.e. band-limited
    interpolation: it places the 839-tone spectrum at baseband without
    inventing an image or a carrier. It is still an approximation: the
    continuous-time preamble the eNB correlates against is not band-limited
    to 839 bins, so the interpolated waveform is not bit-exact to any
    transmitter, and the CP is taken from the interpolated sequence so it
    lines up with it.

    Deliberately absent, because it would be a guess dressed as a transcript:
    Table 5.7.3-1 (preamble sequence index -> logical root) and Table 5.7.2-4
    (logical -> physical root, an 838-row permutation) are NOT applied.
    --preamble is therefore the *physical* root u (1..838), not a preamble
    sequence index; taking a logical root as if it were physical yields a
    valid-looking ZC of the wrong root for most indices, which no structural
    check can see. The restricted sets (high-speed flag) are not implemented.

prs -- the LTE positioning reference signal sequence and its RE map.
    TS 36.211 6.10.4.1: r_{l,ns}(m) = (1 - 2c(2m))/sqrt(2) +
    j(1 - 2c(2m+1))/sqrt(2) for m = 0..2*N_RB_max,DL - 1 = 0..219, with the
    length-31 Gold generator of 7.2 initialised at the start of each OFDM
    symbol,

        c_init = 2^28 * floor(N_ID_PRS/512)
               + 2^10 * (7*(ns+1) + l + 1) * (2*(N_ID_PRS mod 512) + 1)
               + 2*(N_ID_PRS mod 512) + N_CP

    with N_CP = 1 for normal CP. That per-OFDM-symbol form is what R9 V9.1.0,
    R10 V10.6.0 and R14 V14.5.0 all print (rounded up: the clause says
    N_CP = 1 normal / 0 extended). No 36.211 revision read for this tool
    defines a per-subframe `c_init = N_ID_PRS` -- a form that would drop the
    (7*(ns+1)+l+1) factor entirely -- so this tool does not implement one and
    no check claims it.

    The Gold generator is not reimplemented here: `gold_sequence` is imported
    from lte_phy.py, the tree's existing TS 36.211 7.2 stage, so there cannot
    be a second convention. The PRS c_init differs from that file's CRS c_init
    (lte_phy.crs_cinit) only by the 2^28*floor(N_ID_PRS/512) term -- identical
    for N_ID_PRS < 512 -- and the check asserts that equality directly, which
    is what pins both.

    The emitted samples are the QPSK sequence values for every PRS OFDM
    symbol of one 10 ms radio frame (l = 3,5,6 for even n_s; 1,2,3,5,6 for odd
    n_s with 1 or 2 PBCH ports -- the 4-port set is not modelled), 80 symbols
    x 220 values = 17600 values per frame, concatenated in (n_s, l) order and
    tiled to fill --secs. They are NOT an OFDM waveform: no IFFT, no CP, no
    grid, no carrier. That is why --rate is ignored for prs and reported as
    `requested_rate`: 15 kHz spacing does not divide 20 Msps, so no grid
    exists at that rate to be honest about. The mapping table is emitted as
    data in a sidecar file, `<out>.remap.tsv`, and the stdout rows say which
    key is which (`samples_are`, `mapping_is`).

    The map is the no-hopping normal-CP case of 6.10.4.2:
    k = 6m + (N_RB_DL - N_RB_PRS) + (6 - l + v_shift) mod 6, m' = m +
    N_RB_max,DL - N_RB_PRS, v_shift = N_ID_PRS mod 6, port p = 6. The
    frequency-hopping variant (n_iRB) and extended CP are not implemented, and
    no PRS scheduling (I_PRS periodicity/offset from 36.331) is modelled:
    every PRS symbol of the frame is emitted, which is a dense PRS, not a
    configured one.

== Formats (byte-compatible with modules/33_jamming_detect.sh) ==

    cf32  8 bytes/sample  complex64, interleaved float32 I,Q
    ci16  4 bytes/sample  interleaved int16, round(x*32767), clipped
    cu8   2 bytes/sample  interleaved uint8, round(x*127+127.5), clipped,
                          centred such that (d - 127.5)/127.5 recovers x

`peak_full_scale` is the full scale of the container (1.0, 32767.0, 127.5),
not the measured peak, so a reader can undo the quantiser without being told
the signal again. cu8 cannot represent 0.0 exactly (127.5 is a tie); the
rounding follows the consumer's numpy convention rather than inventing one.

Style: Python 3 stdlib + numpy, no other dependency. Nothing in this file is
gated on an authorisation flag; where a capability is absent it is absent.
"""

import argparse
import os
import sys


def _die(rc, msg):
    """Print one TSV-shaped error line to stderr and exit."""
    sys.stderr.write("ERROR\t%s\n" % msg)
    raise SystemExit(rc)


try:
    import numpy as np
except ImportError:  # pragma: no cover - environment, not logic
    _die(1, "numpy is not importable: %s" % sys.exc_info()[1])
    raise

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
try:
    import lte_phy
except ImportError:  # pragma: no cover - environment, not logic
    _die(1, "cannot import tools/lte_phy.py from %s: the TS 36.211 7.2 Gold "
            "generator is taken from there, not reimplemented" % _HERE)
    raise


# ---------------------------------------------------------------------------
# container formats
# ---------------------------------------------------------------------------

FORMAT_ITEM_BYTES = {"cf32": 8, "ci16": 4, "cu8": 2}
FORMAT_FULL_SCALE = {"cf32": 1.0, "ci16": 32767.0, "cu8": 127.5}


def quantise(x, fmt):
    """Serialise complex samples; the formulas are the consumer's, verbatim.

    `modules/33_jamming_detect.sh` writes cf32 as np.asarray(x, '<c8') and
    reads cu8 back as (d - 127.5)/127.5, so these three paths have to agree
    with it byte for byte, including the rounding of a .5 tie.
    """
    x = np.asarray(x)
    if fmt == "cf32":
        return np.asarray(x, "<c8").tobytes()
    if fmt == "ci16":
        q = np.empty(2 * x.size, dtype="<i2")
        q[0::2] = np.clip(np.round(x.real * 32767.0), -32768, 32767)
        q[1::2] = np.clip(np.round(x.imag * 32767.0), -32768, 32767)
        return q.tobytes()
    if fmt == "cu8":
        q = np.empty(2 * x.size, dtype=np.uint8)
        q[0::2] = np.clip(np.round(x.real * 127.0 + 127.5), 0, 255)
        q[1::2] = np.clip(np.round(x.imag * 127.0 + 127.5), 0, 255)
        return q.tobytes()
    raise ValueError("unknown format %r" % (fmt,))


def write_samples(path, payload):
    try:
        with open(path, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        _die(1, "cannot write %s: %s" % (path, exc))


# ---------------------------------------------------------------------------
# GPS L1 C/A -- IS-GPS-200 (ICD-GPS-200) 3.2.2, Figure 3-9, Table 3-Ia
# ---------------------------------------------------------------------------

GPS_CA_CHIP_RATE = 1023000          # chips/s
GPS_CA_CHIPS = 1023                 # chips per code period
GPS_G1_TAPS = (3, 10)               # x^10 + x^3 + 1
GPS_G2_TAPS = (2, 3, 6, 8, 9, 10)   # x^10+x^9+x^8+x^6+x^3+x^2+1

# Table 3-Ia, "Code Delay Chips (C/A)", PRN 1..32. This is the delay applied
# to G2, so the code is G1(i) XOR G2(i - d); see gps_ca_chips().
GPS_CA_G2_DELAY = [
    5, 6, 7, 8, 17, 18, 139, 140, 141, 251, 252, 254, 255, 256, 257, 258,
    469, 470, 471, 472, 473, 474, 509, 512, 513, 514, 515, 516,
    859, 860, 861, 862,
]


def _lfsr_bits(taps, length):
    """One 10-stage maximal-length register, all-ones seed, one bit per chip.

    IS-GPS-200 Figure 3-9: the tapped stages are XORed together and the sum is
    clocked into stage 1 while stages 1..9 shift into 2..10; the sequence is
    taken from stage 10. `taps` are 1-based stage numbers, as the ICD prints
    them.
    """
    state = [1] * 10
    out = []
    for _ in range(length):
        out.append(state[9])
        fb = 0
        for t in taps:
            fb ^= state[t - 1]
        state = [fb] + state[:9]
    return out


def gps_ca_chips(prn):
    """The 1023 C/A chips of one PRN, as 0/1 bits.

    ca(i) = G1(i) XOR G2((i - d) mod 1023) with d from Table 3-Ia. The
    published first-ten-chips octal vector for PRN 1 (1440, i.e.
    1100100000) is reproduced by d = 5 in this form and by no other reading
    of the table; PRN 23 (d = 509, octal 1063) is the one where the widely
    copied delay lists disagree with the current ICD, so it is the vector that
    tells the two apart.
    """
    if not 1 <= prn <= len(GPS_CA_G2_DELAY):
        raise ValueError("PRN must be 1..%d" % len(GPS_CA_G2_DELAY))
    g1 = _lfsr_bits(GPS_G1_TAPS, GPS_CA_CHIPS)
    g2 = _lfsr_bits(GPS_G2_TAPS, GPS_CA_CHIPS)
    d = GPS_CA_G2_DELAY[prn - 1]
    return [g1[i] ^ g2[(i - d) % GPS_CA_CHIPS] for i in range(GPS_CA_CHIPS)]


def gps_ca_samples(prn, rate, secs):
    """Sign of the C/A code held at --rate, repeated to fill --secs.

    Sample i carries chip floor(i * 1023000 / rate) mod 1023: a zero-order
    hold of the chip train, which is what "BPSK chip -> sample" means when the
    requested rate is not a multiple of 1.023 MHz. The chip edge therefore
    lands on the nearest sample, within one sample of its true time; nothing
    interpolates, so no chip is ever shorter than a sample and no filter is
    silently invented.
    """
    n = int(round(secs * rate))
    if n < 1:
        raise ValueError("--secs * --rate must be at least one sample")
    sign = 1.0 - 2.0 * np.asarray(gps_ca_chips(prn), dtype=np.float64)
    # floor(i*1023000/rate) mod 1023, kept in int64 by reducing modulo the
    # number of chips' worth of samples first (i*rate would overflow for
    # multi-second captures at 30 Msps).
    period = GPS_CA_CHIPS * rate
    idx = ((np.arange(n, dtype=np.int64) * GPS_CA_CHIP_RATE) % period) // rate
    return sign[idx].astype(np.complex64)


# ---------------------------------------------------------------------------
# LTE PRACH -- TS 36.211 5.7.2 (sequence), 5.7.1 Table 5.7.1-1 (format 0)
# ---------------------------------------------------------------------------

PRACH_N_ZC = 839
PRACH_RA_RATE_HZ = 1048750          # 839 samples / 800 us, exactly
PRACH_TCP_US = 103.125              # 3168*Ts
PRACH_TSEQ_US = 800.0               # 24576*Ts
PRACH_TOTAL_US = 1000.0             # one format-0 subframe
PRACH_TS_HZ = 30720000.0            # Ts = 1/30.72 MHz

# Table 5.7.2-2, N_CS for preamble formats 0-3, unrestricted set, indexed by
# zeroCorrelationZoneConfig 0..15. (The restricted-set A/B columns are not
# implemented; this tool never emits a restricted set.)
PRACH_NCS_UNRESTRICTED = [0, 13, 15, 18, 22, 26, 32, 38,
                          46, 59, 76, 93, 119, 167, 279, 419]


def prach_zc(u, n_zc=PRACH_N_ZC):
    """x_u(n) = exp(-j*pi*u*n*(n+1)/N_ZC), TS 36.211 5.7.2.

    N_ZC is prime for format 0 (839), so every u in 1..838 is a valid root:
    the sequence is constant-modulus and its periodic autocorrelation is zero
    at every non-zero shift. u = 0 would give a constant sequence and is
    refused upstream.
    """
    n = np.arange(n_zc, dtype=np.float64)
    return np.exp(-1j * np.pi * u * n * (n + 1.0) / n_zc)


def prach_cv(ncs, v, n_zc=PRACH_N_ZC):
    """The cyclic shift C_v of the unrestricted set, TS 36.211 5.7.2.

    N_CS != 0: C_v = v*N_CS for v = 0..floor(N_ZC/N_CS) - 1.
    N_CS == 0: the root is the sequence, C_v = 0, and only v = 0 exists.
    """
    if ncs == 0:
        if v != 0:
            raise ValueError("N_CS = 0 has one preamble per root: v must be 0")
        return 0
    vmax = n_zc // ncs - 1
    if not 0 <= v <= vmax:
        raise ValueError("v must be 0..%d for N_CS = %d" % (vmax, ncs))
    return v * ncs


def prach_preamble(u, cv, n_zc=PRACH_N_ZC):
    """x_u,v(n) = x_u((n + C_v) mod N_ZC), TS 36.211 5.7.2."""
    base = prach_zc(u, n_zc)
    n = np.arange(n_zc)
    return base[(n + cv) % n_zc]


def prach_resample(x, n_out):
    """Band-limited (FFT zero-pad) resample of one period of x to n_out.

    N_ZC is odd, so the transform has (N_ZC-1)/2 positive frequencies and
    (N_ZC-1)/2 negative ones with no Nyquist bin to split; the high-frequency
    bins stay empty, which places the 839-tone preamble exactly at baseband
    instead of folding images down like a zero-order hold would.
    """
    m = len(x)
    if n_out == m:
        return np.array(x, dtype=np.complex128)
    if n_out < 1:
        raise ValueError("resample target must be positive")
    half = (m - 1) // 2
    neg = m - half - 1
    spec = np.fft.fft(x)
    out = np.zeros(n_out, dtype=np.complex128)
    out[:half + 1] = spec[:half + 1]
    if neg:
        out[n_out - neg:] = spec[m - neg:]
    return np.fft.ifft(out) * (n_out / float(m))


def prach_samples(u, ncs_zone, v, rate, secs):
    """One format-0 occasion (CP + 800 us sequence + guard) tiled over --secs.

    The timing constants are the clause's own: 3168*Ts and 24576*Ts at
    Ts = 1/30.72 MHz, with the remaining 2976*Ts of the 1 ms subframe left as
    guard. Sample counts are rounded once per block and the guard absorbs the
    rounding, so a 1 ms block is always exactly round(rate/1000) samples and
    blocks never drift against each other.
    """
    ms_n = int(round(rate / 1000.0))
    if ms_n < 1:
        raise ValueError("--rate must be at least 1000 sps to hold a 1 ms "
                         "PRACH occasion")
    cp_n = int(round(PRACH_TCP_US * 1e-6 * rate))
    seq_n = int(round(PRACH_TSEQ_US * 1e-6 * rate))
    if cp_n + seq_n > ms_n:
        raise ValueError("--rate %d sps cannot hold a %0.3f us CP and a %0.3f "
                         "us sequence inside 1 ms" % (rate, PRACH_TCP_US,
                                                      PRACH_TSEQ_US))
    guard_n = ms_n - cp_n - seq_n
    cv = prach_cv(PRACH_NCS_UNRESTRICTED[ncs_zone], v)
    seq = prach_resample(prach_preamble(u, cv), seq_n)
    block = np.concatenate((seq[seq_n - cp_n:], seq, np.zeros(guard_n)))
    n_ms = int(round(secs * 1000.0))
    if n_ms < 1:
        n_ms = 1
    x = np.tile(block, n_ms).astype(np.complex64)
    meta = {
        "ncs": PRACH_NCS_UNRESTRICTED[ncs_zone],
        "cv": cv,
        "cp_samples": cp_n,
        "seq_samples": seq_n,
        "guard_samples": guard_n,
        "subframe_samples": ms_n,
        "subframes": n_ms,
    }
    return x, meta


# ---------------------------------------------------------------------------
# LTE PRS -- TS 36.211 6.10.4.1 (sequence), 6.10.4.2 (mapping)
# ---------------------------------------------------------------------------

PRS_N_RB_MAX_DL = 110
PRS_RE_PER_SYMBOL = 2 * PRS_N_RB_MAX_DL
PRS_SCS_HZ = 15000
PRS_VALID_N_RB = (6, 15, 25, 50, 75, 100)
PRS_N_SLOTS_PER_FRAME = 20
PRS_FRAME_S = 0.010


def prs_cinit(ns, l, n_id_prs, extended_cp=False):
    """The per-OFDM-symbol Gold seed, TS 36.211 6.10.4.1.

        c_init = 2^28 * floor(N_ID_PRS/512)
               + 2^10 * (7*(ns+1) + l + 1) * (2*(N_ID_PRS mod 512) + 1)
               + 2*(N_ID_PRS mod 512) + N_CP

    N_CP is 1 for normal CP and 0 for extended. The leading 2^28 term only
    matters when N_ID_PRS >= 512 (N_ID_PRS runs 0..4095 when configured,
    otherwise it is N_ID_cell, 0..503); it is implemented for completeness
    even though --pci restricts the generated signal to the PCI range.
    """
    n_cp = 0 if extended_cp else 1
    lo = n_id_prs % 512
    return (2 ** 28 * (n_id_prs // 512)
            + 1024 * (7 * (ns + 1) + l + 1) * (2 * lo + 1)
            + 2 * lo + n_cp)


def prs_sequence(c_init):
    """The 220 QPSK symbols r(m) of one PRS OFDM symbol, TS 36.211 6.10.4.1.

    Two Gold bits per symbol, bit 2m into the real part and 2m+1 into the
    imaginary, both (1 - 2c)/sqrt(2) -- the same QPSK constellation as the CRS
    and the data in lte_phy.py. The Gold generator is lte_phy.gold_sequence:
    reimplementing it here would create a second convention to keep in step,
    which is exactly the failure this tree has already paid for twice.
    """
    c = lte_phy.gold_sequence(c_init, 2 * PRS_RE_PER_SYMBOL)
    k = 1.0 / np.sqrt(2.0)
    re = (1.0 - 2.0 * np.asarray(c[0::2], dtype=np.float64)) * k
    im = (1.0 - 2.0 * np.asarray(c[1::2], dtype=np.float64)) * k
    return (re + 1j * im).astype(np.complex64)


def prs_l_set(ns_mod_two, pbch_ports=2):
    """PRS OFDM symbols in one slot, TS 36.211 6.10.4.2, normal CP.

    even n_s: {3,5,6}; odd n_s with 1 or 2 PBCH ports: {1,2,3,5,6}; odd n_s
    with 4 ports: {2,3,5,6}. Only the 1-or-2-port case is modelled; the
    four-port cell is refused rather than silently mis-symbolised.
    """
    if ns_mod_two == 0:
        return (3, 5, 6)
    if pbch_ports in (1, 2):
        return (1, 2, 3, 5, 6)
    if pbch_ports == 4:
        return (2, 3, 5, 6)
    raise ValueError("PBCH ports must be 1, 2 or 4")


def prs_k(n_rb_dl, n_rb_prs, l, m, v_shift):
    """k = 6m + (N_RB_DL - N_RB_PRS) + (6 - l + v_shift) mod 6.

    Note the minus on l and the bandwidth-offset term: both are in the clause
    (6.10.4.2, normal CP) and both are easy to drop. The sequence index is the
    translated m' = m + N_RB_max,DL - N_RB_PRS -- the same 110-offset window
    as the CRS, so a 100-RB cell reads its PRS from r(10) onwards.
    """
    return (6 * m + (n_rb_dl - n_rb_prs) + (6 - l + v_shift) % 6)


def prs_m_prime(m, n_rb_prs):
    return m + PRS_N_RB_MAX_DL - n_rb_prs


def prs_frame(n_id_prs):
    """The PRS sequence values of one 10 ms radio frame, in (n_s, l) order.

    80 symbols x 220 values: even slots carry l = 3,5,6 and odd slots
    1,2,3,5,6, so a frame is 10*3 + 10*5 symbols. Values depend on n_s and l
    only through c_init, so this is every PRS symbol of the frame exactly
    once; repeating the frame is what --secs does.
    """
    chunks = []
    for ns in range(PRS_N_SLOTS_PER_FRAME):
        for l in prs_l_set(ns % 2):
            chunks.append(prs_sequence(prs_cinit(ns, l, n_id_prs)))
    return np.concatenate(chunks)


def prs_remap_rows(n_rb_dl, n_rb_prs, v_shift):
    """(n_s mod 2, l, m, m', k) for every mapped RE, as data.

    k depends on l and v_shift only, not on n_s, so five l values are enough
    to describe the map; the n_s parity column says which of them occur in
    which slot.
    """
    rows = []
    for ns_parity in (0, 1):
        for l in prs_l_set(ns_parity):
            for m in range(2 * n_rb_prs):
                rows.append((ns_parity, l, m, prs_m_prime(m, n_rb_prs),
                             prs_k(n_rb_dl, n_rb_prs, l, m, v_shift)))
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SEQUENCES = ("gps-ca", "prach", "prs")

LIST_LINES = (
    ("gps-ca",
     "prn=1..32; rate=any sps>=1; chip_rate=1023000 Hz; chips=1023; "
     "data-less (all-zero nav); format=cf32|ci16|cu8",
     "IS-GPS-200 3.2.2 + Figure 3-9 + Table 3-Ia"),
    ("prach",
     "preamble=physical root u=1..838; ncs_zone=0..15 (Table 5.7.2-2 "
     "unrestricted); v=0..floor(839/N_CS)-1; format 0 (1 ms, 800 us "
     "sequence); rate>=1000 sps; format=cf32|ci16|cu8",
     "TS 36.211 5.7.2 + Table 5.7.1-1 (format 0) + Table 5.7.2-2 (N_CS)"),
    ("prs",
     "pci=N_ID_PRS=0..503; n_rb_prs and n_rb_dl in 6,15,25,50,75,100; "
     "220 QPSK values per PRS OFDM symbol; --rate is requested, not used "
     "(RE-domain samples, no OFDM grid)",
     "TS 36.211 6.10.4.1 (sequence) + 6.10.4.2 (mapping, normal CP)"),
)


class _Parser(argparse.ArgumentParser):
    """argparse, but every usage error is one `ERROR<TAB>...` stderr line.

    Exit status stays 2, which is what the module contract and
    modules/33_jamming_detect.sh already use for a bad argument.
    """

    def error(self, message):
        sys.stderr.write("ERROR\t%s\n" % message)
        raise SystemExit(2)


def _parser():
    ap = _Parser(
        prog="phy_seqs.py",
        description="Reference-signal sequences as IQ samples "
                    "(GPS C/A, LTE PRACH, LTE PRS).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="one line per sequence, with its parameters "
                                "and the clause the maths came from")
    gen = sub.add_parser("gen", help="write samples and print the parameters "
                                     "used as TSV")
    gen.add_argument("--seq", required=True,
                     help="gps-ca | prach | prs")
    gen.add_argument("--out", required=True,
                     help="output path (binary, interleaved I/Q)")
    gen.add_argument("--format", default="cf32",
                     help="cf32 (default) | ci16 | cu8")
    gen.add_argument("--rate", default="20000000",
                     help="sample rate in samples/s (default 20000000); "
                          "ignored for prs, which is RE-domain")
    gen.add_argument("--secs", default="1.0",
                     help="duration in seconds (default 1.0)")
    gen.add_argument("--prn", default="1",
                     help="gps-ca: PRN 1..32 (default 1)")
    gen.add_argument("--pci", default="1",
                     help="prs: N_ID_PRS / physical cell id 0..503 "
                          "(default 1)")
    gen.add_argument("--preamble", default="1",
                     help="prach: physical root sequence index u, 1..838 "
                          "(default 1)")
    gen.add_argument("--ncs", default="0",
                     help="prach: zeroCorrelationZoneConfig 0..15 (default "
                          "0), which selects N_CS from Table 5.7.2-2")
    gen.add_argument("--v", default="0",
                     help="prach: cyclic shift index v for the chosen N_CS "
                          "(default 0)")
    gen.add_argument("--n-rb-prs", default="100",
                     help="prs: N_RB_PRS bandwidth in 6,15,25,50,75,100 "
                          "(default 100)")
    gen.add_argument("--n-rb-dl", default="100",
                     help="prs: N_RB_DL in 6,15,25,50,75,100 (default 100)")
    return ap


def _int_arg(name, text, lo=None, hi=None):
    try:
        val = int(text, 10)
    except (TypeError, ValueError):
        _die(2, "--%s must be an integer, got %r" % (name, text))
    if lo is not None and val < lo:
        _die(2, "--%s must be >= %d, got %d" % (name, lo, val))
    if hi is not None and val > hi:
        _die(2, "--%s must be <= %d, got %d" % (name, hi, val))
    return val


def _rate_arg(text):
    try:
        rate = int(text, 10)
    except (TypeError, ValueError):
        _die(2, "--rate must be an integer sample rate in samples/s, got %r"
             % (text,))
    if rate < 1:
        _die(2, "--rate must be positive, got %d" % rate)
    if rate > 1000000000:
        _die(2, "--rate must be at most 1000000000 sps, got %d" % rate)
    return rate


def _secs_arg(text):
    try:
        secs = float(text)
    except (TypeError, ValueError):
        _die(2, "--secs must be a number of seconds, got %r" % (text,))
    if not (secs > 0.0):
        _die(2, "--secs must be positive, got %r" % (text,))
    if secs > 3600.0:
        _die(2, "--secs must be at most 3600, got %r" % (text,))
    return secs


def _format_arg(text):
    if text not in FORMAT_ITEM_BYTES:
        _die(2, "unknown --format %r (want one of %s)"
             % (text, ", ".join(sorted(FORMAT_ITEM_BYTES))))
    return text


def _emit(pairs):
    for key, value in pairs:
        sys.stdout.write("%s\t%s\n" % (key, value))


def _common_rows(out, fmt, rate, samples):
    return [
        ("format", fmt),
        ("rate", "%d" % rate),
        ("samples", "%d" % samples),
        ("seconds", "%.6f" % (samples / float(rate))),
        ("bytes", "%d" % (samples * FORMAT_ITEM_BYTES[fmt])),
        ("peak_full_scale", "%.4f" % FORMAT_FULL_SCALE[fmt]),
    ]


def cmd_list(_args):
    for name, params, ref in LIST_LINES:
        sys.stdout.write("%s\t%s\t%s\n" % (name, params, ref))
    return 0


def cmd_gen(args):
    seq = args.seq
    if seq not in SEQUENCES:
        _die(2, "unknown --seq %r (want %s)" % (seq, ", ".join(SEQUENCES)))
    fmt = _format_arg(args.format)
    rate = _rate_arg(args.rate)
    secs = _secs_arg(args.secs)
    if args.out in ("-", "/dev/stdout", "/dev/fd/1"):
        _die(2, "--out must be a file path; stdout carries the TSV summary")

    if seq == "gps-ca":
        prn = _int_arg("prn", args.prn, 1, 32)
        x = gps_ca_samples(prn, rate, secs)
        rows = [("seq", "gps-ca"), ("out", args.out), ("prn", "%d" % prn),
                ("g2_delay_chips", "%d" % GPS_CA_G2_DELAY[prn - 1]),
                ("chip_rate_hz", "%d" % GPS_CA_CHIP_RATE),
                ("chips_per_period", "%d" % GPS_CA_CHIPS)]
        rows += _common_rows(args.out, fmt, rate, len(x))
        rows += [
            ("formula_ref", "IS-GPS-200 (ICD-GPS-200) 3.2.2, Figure 3-9, "
                            "Table 3-Ia (C/A code phase assignments)"),
            ("repeat",
             "sample i holds chip floor(i*1023000/rate) mod 1023 (zero-order "
             "hold of the 1023-chip code); the period repeats every "
             "1023*rate/1023000 nominal samples"),
            ("nav_data", "none: data-less all-zero navigation message, so "
                         "this is the pure C/A spreading code, not a GPS "
                         "signal (no carrier, no Doppler, no nav bits)"),
            ("quadrature", "Q = 0 (real BPSK baseband, no carrier)"),
            ("contains", "samples only; no mapping table"),
        ]
        meta = None
    elif seq == "prach":
        u = _int_arg("preamble", args.preamble, 1, 838)
        zone = _int_arg("ncs", args.ncs, 0, 15)
        v = _int_arg("v", args.v, 0, 838)
        try:
            x, meta = prach_samples(u, zone, v, rate, secs)
        except ValueError as exc:
            _die(2, str(exc))
        rows = [("seq", "prach"), ("out", args.out),
                ("preamble_format", "0"),
                ("preamble_root_u", "%d" % u),
                ("ncs_zone", "%d" % zone),
                ("ncs", "%d" % meta["ncs"]),
                ("v", "%d" % v),
                ("cv", "%d" % meta["cv"]),
                ("n_ra_hz", "%d" % PRACH_RA_RATE_HZ),
                ("cp_samples", "%d" % meta["cp_samples"]),
                ("seq_samples", "%d" % meta["seq_samples"]),
                ("guard_samples", "%d" % meta["guard_samples"]),
                ("subframe_samples", "%d" % meta["subframe_samples"]),
                ("subframes", "%d" % meta["subframes"])]
        rows += _common_rows(args.out, fmt, rate, len(x))
        rows += [
            ("formula_ref", "TS 36.211 5.7.2 (Zadoff-Chu preamble and C_v), "
                            "5.7.1 Table 5.7.1-1 (format 0: TCP=3168*Ts, "
                            "TSEQ=24576*Ts), Table 5.7.2-2 (N_CS)"),
            ("structure",
             "format-0 occasion tiled to --secs: CP 3168*Ts (tail of the "
             "sequence), 24576*Ts (800 us) CAZAC, 2976*Ts guard of zeros, "
             "= exactly 1 ms per block"),
            ("contains",
             "samples only: the CP is samples[0:cp_samples], the sequence is "
             "samples[cp_samples:cp_samples+seq_samples], then guard zeros"),
            ("baseband",
             "CAZAC at N_RA=1048750 Hz resampled by circular FFT zero-pad to "
             "--rate: no SC-FDMA DFT precoding, no OFDM grid, no uplink "
             "carrier, no path loss or timing advance"),
            ("root_convention",
             "--preamble is the physical root u, not a preamble sequence "
             "index: 5.7.3-1 (sequence index -> logical root) and 5.7.2-4 "
             "(logical -> physical) are deliberately not transcribed"),
        ]
    else:  # prs
        pci = _int_arg("pci", args.pci, 0, 503)
        n_rb_dl = _int_arg("n-rb-dl", args.n_rb_dl)
        n_rb_prs = _int_arg("n-rb-prs", args.n_rb_prs)
        for name, val in (("n-rb-dl", n_rb_dl), ("n-rb-prs", n_rb_prs)):
            if val not in PRS_VALID_N_RB:
                _die(2, "--%s must be one of %s, got %d"
                     % (name, ", ".join(str(r) for r in PRS_VALID_N_RB), val))
        if n_rb_prs > n_rb_dl:
            _die(2, "--n-rb-prs (%d) cannot exceed --n-rb-dl (%d)"
                 % (n_rb_prs, n_rb_dl))
        v_shift = pci % 6
        frame = prs_frame(pci)
        n_frames = int(round(secs / PRS_FRAME_S))
        if n_frames < 1:
            n_frames = 1
        x = np.tile(frame, n_frames)
        seq_rate = int(round(len(frame) / PRS_FRAME_S))
        rows = [("seq", "prs"), ("out", args.out),
                ("pci", "%d" % pci),
                ("n_id_prs", "%d" % pci),
                ("n_rb_max_dl", "%d" % PRS_N_RB_MAX_DL),
                ("n_rb_dl", "%d" % n_rb_dl),
                ("n_rb_prs", "%d" % n_rb_prs),
                ("v_shift", "%d" % v_shift),
                ("k_offset", "%d" % (n_rb_dl - n_rb_prs)),
                ("m_prime_offset", "%d" % (PRS_N_RB_MAX_DL - n_rb_prs)),
                ("scs_hz", "%d" % PRS_SCS_HZ),
                ("ns_set", "0..19"),
                ("l_even_ns", "3,5,6"),
                ("l_odd_ns", "1,2,3,5,6 (1 or 2 PBCH ports)"),
                ("symbols_per_frame", "%d" % (len(frame)
                                              // PRS_RE_PER_SYMBOL)),
                ("re_per_symbol", "%d" % PRS_RE_PER_SYMBOL),
                ("samples_per_frame", "%d" % len(frame)),
                ("frames", "%d" % n_frames),
                ("cinit_ns0_l3", "%d" % prs_cinit(0, 3, pci)),
                ("requested_rate", "%d" % rate)]
        rows += _common_rows(args.out, fmt, seq_rate, len(x))
        remap_path = args.out + ".remap.tsv"
        remap_rows = prs_remap_rows(n_rb_dl, n_rb_prs, v_shift)
        lines = ["# phy_seqs prs RE map, TS 36.211 6.10.4.2 normal CP",
                 "# k = 6m + (n_rb_dl - n_rb_prs) + (6 - l + v_shift) mod 6",
                 "# m' = m + 110 - n_rb_prs; v_shift = N_ID_PRS mod 6",
                 "ns_parity\tl\tm\tm_prime\tk"]
        for ns_parity, l, m, mprime, k in remap_rows:
            lines.append("%d\t%d\t%d\t%d\t%d" % (ns_parity, l, m, mprime, k))
        try:
            with open(remap_path, "w") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError as exc:
            _die(1, "cannot write %s: %s" % (remap_path, exc))
        rows += [
            ("formula_ref", "TS 36.211 6.10.4.1 (Gold-seeded QPSK sequence, "
                            "c_init per OFDM symbol) and 6.10.4.2 (RE "
                            "mapping, normal CP, no frequency hopping)"),
            ("structure",
             "one 10 ms radio frame of dense-PRS symbols (%d OFDM symbols x "
             "%d QPSK values) concatenated in (n_s, l) order and tiled to "
             "fill --secs" % (len(frame) // PRS_RE_PER_SYMBOL,
                              PRS_RE_PER_SYMBOL)),
            ("samples_are", "the QPSK sequence values r_{l,ns}(m), m = "
                            "0..219, one per PRS resource element; NOT an "
                            "OFDM waveform (no IFFT, no CP, no grid, no "
                            "carrier)"),
            ("mapping_is", "the resource-element map k(n_s, l, m) is not "
                           "baked into the samples; it is the data in "
                           "mapping_file (ns_parity, l, m, m_prime, k)"),
            ("mapping_file", remap_path),
            ("mapping_rows", "%d" % (len(remap_rows))),
            ("rate_basis", "one sample per PRS resource element; rate = "
                           "samples per second of radio time (1760000 for a "
                           "dense-PRS frame), not a waveform sample rate"),
            ("rate_note", "--rate is ignored for prs: 15 kHz subcarrier "
                          "spacing does not divide 20 Msps, so no OFDM grid "
                          "exists at the requested rate to be honest about"),
            ("cinit_note", "c_init is the per-OFDM-symbol form of 6.10.4.1, "
                           "identical to lte_phy.crs_cinit(ns, l, pci) for "
                           "N_ID_PRS < 512; no per-subframe "
                           "c_init = N_ID_PRS form is defined by any 36.211 "
                           "revision read for this tool, so none is emitted"),
        ]
        meta = None

    samples = len(x)
    payload = quantise(x, fmt)
    if len(payload) != samples * FORMAT_ITEM_BYTES[fmt]:
        _die(1, "internal: %d bytes for %d %s samples"
             % (len(payload), samples, fmt))
    write_samples(args.out, payload)
    _emit(rows)
    return 0


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "gen":
        return cmd_gen(args)
    _parser().print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
