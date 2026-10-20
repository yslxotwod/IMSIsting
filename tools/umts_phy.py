#!/usr/bin/env python3
"""umts_phy.py -- WCDMA (UMTS Uu) downlink baseband: P-CPICH and SCH.

The tree has an LTE downlink PHY stage (`tools/lte_phy.py`, cross-checked
against srsRAN_4G) and an LTE reference-signal emitter (`tools/phy_seqs.py`),
but no WCDMA baseband: `modules/08_umts_air.sh` reads UMTS air-interface
signalling (UARFCN, SIBs, RRC, AKA) rather than generating a waveform. This
tool generates that waveform for the two channels a cell cannot omit: the
primary common pilot (P-CPICH, the phase and power reference) and the
synchronisation channel (SCH, what a UE searches for before it knows anything
about the cell).

    tools/umts_phy.py list
    tools/umts_phy.py gen --carrier <p-cpich|sch|both> --out PATH
                          [--format cf32|ci16|cu8] [--rate SPS]
                          [--seconds S] [--psc 0-511]

`gen` writes a flat interleaved-IQ file and prints the parameters it actually
used as TSV on stdout, one `key<TAB>value` per line, so the caller never has
to trust that its own command line is what reached the file.

Exit codes: 0 built and written, 1 could not build or write, 2 usage error or
a refused component (a component this tool will not synthesise, named in the
`WHY` line). Errors are `ERROR<TAB>...` on stderr; a refusal also carries
`WHY<TAB>...` naming what is missing.

== Chip rate and the frame (TS 25.213 5.2, TS 25.211 5) ==

The FDD chip rate is 3.84 Mcps. A slot is Tslot = 2560 chips, a radio frame is
15 slots = 38400 chips = 10 ms exactly, so one frame is 38400/3840000 s =
0.01 s with no residue. `--rate` is the *output* sample rate and this tool
only emits integer multiples of the chip rate: an integer 1..64 is read as
samples per chip (sps), anything larger must be a sample rate in Hz that
divides exactly by 3840000. There is no fractional resampler here, so nothing
is interpolated and `chip_samples` in the TSV is the sps actually used.
`--chip-rate` exists only to be refused politely: no other chip rate is
defined for this mode.

== Scrambling code (TS 25.213 5.2.2, 5.2.3) ==

Two degree-18 generators, from the clause verbatim:

    x(i+18) = x(i+7) + x(i)                             mod 2
    y(i+18) = y(i+10) + y(i+7) + y(i+5) + y(i)          mod 2

with x(0) = 1 and x(1..17) = 0, and y(0..17) all ones. The primitive
polynomial behind the x recursion is 1 + X^7 + X^18 and behind the y recursion
1 + X^5 + X^7 + X^10 + X^18, which is what makes the taps above the clause's
and not a guess. Then

    z_n(i) = x((i + n) mod (2^18 - 1)) + y(i)           mod 2,  i = 0..2^18-2
    Z_n(i) = +1 if z_n(i) = 0, -1 if z_n(i) = 1
    S_dl,n(i) = Z_n(i) + j * Z_n((i + 131072) mod (2^18 - 1)),  i = 0..38399

and "the pattern from phase 0 up to the phase of 38399 is repeated". The code
is complex with symbols from {+1+j, +1-j, -1+j, -1-j}, the I and Q halves are
*different phases of the same Gold sequence* (131072 apart), and the repeat
period is the frame (38400 chips), not the Gold period (262143). All three of
those are properties the clause fixes, and the checker tests them where they
are visible in the samples.

Only primary scrambling codes are emitted: the i:th primary code is n = 16*i,
i = 0..511, which is what `--psc` selects. The 15 secondary codes per set and
the compressed-mode left/right alternatives (also 5.2.2) are not implemented
and say so in `list`.

== P-CPICH (TS 25.213 5.2.1, TS 25.211 5.3.3.1) ==

"It is the primary CPICH that is transmitted with the fixed channelisation
code Cch,256,0" (TS 25.213 5.2.1). The pre-defined bit sequence is all zeros
for antenna 1 with no transmit diversity (TS 25.211 5.3.3.1, Figure 14), and
the QPSK mapper of TS 25.213 5.1.1.1 maps binary 0 to +1, so every symbol is
+1 on I and +1 on Q: the pilot is a constant (1 + j) symbol stream at
SF = 256, i.e. 10 symbols per slot, 20 bits per slot, 2560 chips per slot.
Spread by Cch,256,0 (all ones) and scrambled, the emitted chips are

    chip(i) = W_cpich * (1 + j) * S_dl,psc(i)

and descrambling them recovers the constant symbol, which is exactly what a
receiver uses the pilot for.

== SCH (TS 25.211 5.3.3.5, TS 25.213 5.2.3) ==

P-SCH is one modulated code of 256 chips per slot, identical in every cell:

    Cpsc = (1 + j) * <a, a, a, -a, -a, a, -a, -a, a, a, a, -a, a, -a, a, a>

S-SCH carries 15 SSCs per frame, one per slot, each 256 chips, chosen by the
cell's scrambling code group i = 0..63 (TS 25.213 5.2.3.2, Table 4). The SSC
set is built from the printed sequences, not from a table of chips:

    z = <b, b, b, -b, b, b, -b, -b, b, -b, b, -b, -b, -b, -b, -b>
    b = <a_1..a_8, -a_9..-a_16>
    Cssc,k = (1 + j) * <h_m(i) * z(i)>,  m = 16*(k-1),  h_m = row m of H8

with H8 built by the printed recursion H_k = [[H_{k-1}, H_{k-1}],
[H_{k-1}, -H_{k-1}]] from H_0 = (1). Both sync codes are modulated by the
symbol a of Figure 18, which is +1 when the P-CCPCH is STTD encoded and -1
when it is not; this tool emits the no-transmit-diversity case, a = -1, and
says so in the `sch_sign` row rather than leaving it implicit.

The SCH starts at the first chip of each slot and is *not* scrambled: TS
25.213 5.2.2 lists the channels that "shall always be transmitted using the
primary scrambling code" (P-CCPCH, P-CPICH, PICH, MICH, AICH, S-CCPCH) and the
SCH is not among them, so the 256 SCH chips are added on top of the scrambled
channels in the Figure 9 combining point without a scrambling multiplication.

The code group is derived, not guessed: TS 25.213 5.2.2 defines group j as
primary codes 16*8*j + 16*k, j = 0..63, k = 0..7, so a primary code psc = 16*i
belongs to group i // 8 = psc // 128. That is the value in the `group` row.

== Amplitude, and what is not modelled ==

No 3GPP clause fixes the absolute transmit amplitude of these channels, and
the SCH weights Gp/Gs of the TS 25.213 5.1.5 combining point are signalled,
not fixed. This tool therefore states its own weights instead of pretending
to a standard: W_cpich = 0.5, W_psch = W_ssch = 0.5 (equal voltage), so a cell
emitting the P-CPICH alone peaks at exactly 1.0 of full scale. `--carrier
both` can sum above 1.0, in which case every sample is scaled once by
(1 - 1e-6)/peak before quantisation so the container cannot clip, and both
`peak_scale` and `peak_written` report what happened.

Every honest limit is printed as a `limit` row, one per clause or component
that is not implemented, so a caller can see them without reading this file.

== Formats (byte-compatible with modules/33_jamming_detect.sh) ==

    cf32  8 bytes/sample  complex64, interleaved float32 I,Q
    ci16  4 bytes/sample  interleaved int16, round(x*32767), clipped
    cu8   2 bytes/sample  interleaved uint8, round(x*127+127.5), clipped,
                          centred such that (d - 127.5)/127.5 recovers x

`peak_full_scale` is the full scale of the container (1.0, 32767.0, 127.5),
not the measured peak, so a reader can undo the quantiser without being told
the signal again; `peak_written` is the measured peak in those same units.
cu8 cannot represent 0.0 exactly (127.5 is a tie) and the rounding follows
the consumer's numpy convention rather than inventing one.

== Sources ==

Every constant in this file is transcribed from, and cited against, the
3GPP release-12 text: TS 25.213 V12.0.0 (spreading and modulation, FDD) for
the OVSF tree (4.3.1.1, Figure 4), the scrambling code (5.2.2, 5.2.3), the
sync codes (5.2.3.1) and the SSC allocation (5.2.3.2, Table 4); TS 25.211
V12.0.0 (physical channels, FDD) for the CPICH frame structure (5.3.3.1) and
the SCH structure (5.3.3.5). Where a value could not be confirmed from that
text it would be refused in code rather than approximated; see REFUSED below.

Style: Python 3 stdlib + numpy, no other dependency. Nothing here is gated on
an authorisation flag; where a capability is absent it is absent.
"""

import argparse
import functools
import os
import sys


def _die(rc, msg, why=None):
    """One ERROR line on stderr, plus WHY when a person needs the reason."""
    sys.stderr.write("ERROR\t%s\n" % msg)
    if why:
        sys.stderr.write("WHY\t%s\n" % why)
    raise SystemExit(rc)


try:
    import numpy as np
except ImportError:  # pragma: no cover - environment, not logic
    _die(1, "numpy is not importable: %s" % sys.exc_info()[1])
    raise


# ---------------------------------------------------------------------------
# chip rate, slot and frame arithmetic -- TS 25.211 5, TS 25.213 5.2
# ---------------------------------------------------------------------------

CHIP_RATE = 3840000          # chips/s, the FDD chip rate; no other is defined
CHIPS_PER_SLOT = 2560        # Tslot = 2560 chips (25.211 5.3.3.1, Figure 13)
SLOTS_PER_FRAME = 15         # 25.211 5, Figure 13
CHIPS_PER_FRAME = CHIPS_PER_SLOT * SLOTS_PER_FRAME      # 38400, exactly
FRAME_SECONDS = 0.01         # 10 ms frame, and 38400/3840000 s == 0.01 s

PILOT_SF = 256               # P-CPICH spreading factor is fixed at 256
PILOT_CODE_NUMBER = 0        # ... and its code is Cch,256,0 (25.213 5.2.1)
SCH_CHIPS = 256              # PSC and SSC are 256 chips (25.213 5.2.3.1)
PSC_MAX = 511                # primary codes n = 16*i, i = 0..511 (25.213 5.2.2)
PSC_STRIDE = 16
CODE_GROUPS = 64             # 25.213 5.2.2: 64 groups of 8 primary codes
CODES_PER_GROUP = 8

# TS 25.211 5.3.3.5, Figure 18: the SCH is modulated by the symbol a, which is
# +1 when the P-CCPCH is STTD encoded and -1 when it is not. No transmit
# diversity is the case this tool emits, and it is reported as `sch_sign`.
SCH_SIGN = -1

# Modelled weights, not standard values: no clause fixes absolute amplitude and
# Gp/Gs of the 25.213 5.1.5 combining point are signalled. Equal voltage, with
# W_cpich chosen so the pilot alone peaks at exactly 1.0 of full scale.
W_CPICH = 0.5
W_PSCH = 0.5
W_SSCH = 0.5

# ---------------------------------------------------------------------------
# container formats -- the formulas are modules/33_jamming_detect.sh's, verbatim
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


# ---------------------------------------------------------------------------
# OVSF code tree -- TS 25.213 4.3.1.1, the recursion printed under Figure 4
# ---------------------------------------------------------------------------

def ovsf(sf, k):
    """Cch,sf,k as +1/-1 integers, from the code tree, never a stored pattern.

    Figure 4 of TS 25.213 prints the tree and, under it, the recurrence

        Cch,1,0        = (1)
        Cch,2,0        = (Cch,1,0,  Cch,1,0)
        Cch,2,1        = (Cch,1,0, -Cch,1,0)
        Cch,2(n+1),2r  = (Cch,2n,r,  Cch,2n,r)
        Cch,2(n+1),2r+1= (Cch,2n,r, -Cch,2n,r)

    so a code is its parent's chips doubled with the second half either
    repeated (even child) or negated (odd child). Which half a code number
    falls in is read from the most significant bit of k first, because the
    recursion doubles the spreading factor on the left of the tree.
    """
    if sf < 1 or (sf & (sf - 1)) != 0:
        raise ValueError("spreading factor must be a power of two, got %r"
                         % (sf,))
    if not 0 <= k < sf:
        raise ValueError("code number %r out of range for SF %d" % (k, sf))
    bits = []
    n = k
    levels = sf.bit_length() - 1
    for _ in range(levels):
        bits.append(n & 1)
        n >>= 1
    bits.reverse()                       # most significant level first
    code = [1]
    for bit in bits:
        if bit == 0:
            code = code + code
        else:
            code = code + [-c for c in code]
    return code


# ---------------------------------------------------------------------------
# scrambling codes -- TS 25.213 5.2.2 (generators), 5.2.3 (complex code)
# ---------------------------------------------------------------------------

GOLD_DEGREE = 18
GOLD_PERIOD = (1 << GOLD_DEGREE) - 1        # 2^18 - 1 = 262143
GOLD_Q_OFFSET = 1 << 17                     # 131072, the I/Q phase offset


@functools.lru_cache(maxsize=1)
def gold_sequences():
    """x and y as the clause computes them: bit recursions, both mod 2.

    x is the m-sequence of the primitive polynomial 1 + X^7 + X^18, so
    x(i+18) = x(i+7) + x(i); y uses 1 + X^5 + X^7 + X^10 + X^18, so
    y(i+18) = y(i+10) + y(i+7) + y(i+5) + y(i). The initial conditions are
    x(0) = 1 with x(1..17) = 0 and y(0..17) = 1 (TS 25.213 5.2.2).
    """
    n = GOLD_PERIOD
    x = np.zeros(n, dtype=np.int8)
    y = np.ones(n, dtype=np.int8)
    x[0] = 1
    # i runs to 2^18 - 20, so the last index written is 2^18 - 2.
    for i in range(n - GOLD_DEGREE):
        x[i + GOLD_DEGREE] = x[i + 7] ^ x[i]
        y[i + GOLD_DEGREE] = (y[i + 10] ^ y[i + 7] ^ y[i + 5] ^ y[i])
    return x, y


def scrambling_code(psc, chips=CHIPS_PER_FRAME):
    """S_dl,n for the primary code n = 16*psc, chips 0..chips-1 of the pattern.

    One frame is 38400 chips and "the pattern from phase 0 up to the phase of
    38399 is repeated", so the caller tiles this slice per frame; the Gold
    period (262143) is *not* the repeat period of the emitted code.
    """
    if not 0 <= psc <= PSC_MAX:
        raise ValueError("primary scrambling code %r out of range 0..511"
                         % (psc,))
    n = PSC_STRIDE * psc
    x, y = gold_sequences()
    i = np.arange(chips)
    z_i = x[(i + n) % GOLD_PERIOD] ^ y[:chips]
    z_q = x[(i + n + GOLD_Q_OFFSET) % GOLD_PERIOD] ^ y[:chips]
    # Z_n(i) = +1 for a 0 bit and -1 for a 1 bit, then S = Z_i + j Z_q.
    return (1 - 2 * z_i).astype(np.float64) + 1j * (1 - 2 * z_q).astype(
        np.float64)


# ---------------------------------------------------------------------------
# synchronisation codes -- TS 25.213 5.2.3.1, verbatim sequences
# ---------------------------------------------------------------------------

# "a = <x1, x2, x3, ..., x16> = <1, 1, 1, 1, 1, 1, -1, -1, 1, -1, 1, -1, 1,
# -1, -1, 1>" -- printed in full in 5.2.3.1, so it is transcribed, not derived.
PSC_A = (1, 1, 1, 1, 1, 1, -1, -1, 1, -1, 1, -1, 1, -1, -1, 1)

# The 16 block signs of Cpsc: <a, a, a, -a, -a, a, -a, -a, a, a, a, -a, a,
# -a, a, a> (5.2.3.1) written as the modulation applied to each copy of a.
PSC_BLOCKS = (1, 1, 1, -1, -1, 1, -1, -1, 1, 1, 1, -1, 1, -1, 1, 1)

# b = <a_1..a_8, -a_9..-a_16> (5.2.3.1), the Golay sequence the SSC set uses.
SSC_B = tuple(PSC_A[:8]) + tuple(-v for v in PSC_A[8:])

# z = <b, b, b, -b, b, b, -b, -b, b, -b, b, -b, -b, -b, -b, -b> (5.2.3.1),
# again as the per-block modulation so the 256-chip z is generated, not stored.
SSC_BLOCKS = (1, 1, 1, -1, 1, 1, -1, -1, 1, -1, 1, -1, -1, -1, -1, -1)


def _blockwise(seq, blocks):
    """Place each block sign in front of the whole 16-chip sequence."""
    n = len(seq) * len(blocks)
    return np.array([seq[i % len(seq)] * blocks[i // len(seq)]
                     for i in range(n)], dtype=np.float64)


def psc_code():
    """Cpsc, 256 chips: (1 + j) times the printed block sequence."""
    return (1 + 1j) * _blockwise(PSC_A, PSC_BLOCKS)


@functools.lru_cache(maxsize=1)
def hadamard8():
    """H8 by the recursion printed in 5.2.3.1: H_k, each quadrant +-H_{k-1}.

    H_0 = (1), so the rows are numbered from row 0 = all ones, and the SSC for
    k uses row m = 16*(k-1); no Hadamard row is stored, the matrix is built.
    """
    h = np.array([[1]], dtype=np.int8)
    while h.shape[0] < 256:
        h = np.block([[h, h], [h, -h]])
    return h


@functools.lru_cache(maxsize=1)
def ssc_codes():
    """The 16 SSCs, Cssc,1..Cssc,16, indexed 0..15.

    Cssc,k = (1 + j) * <h_m(i) * z(i)> with m = 16*(k-1) (5.2.3.1). z is
    generated from b and its block signs, h_m is a row of H8, so the only
    transcription here is the printed sequences themselves.
    """
    z = _blockwise(SSC_B, SSC_BLOCKS)
    h = hadamard8()
    out = []
    for k in range(1, 17):
        out.append((1 + 1j) * (h[16 * (k - 1)].astype(np.float64) * z))
    return tuple(out)


# TS 25.213 5.2.3.2, Table 4: the SSC used in slots #0..#14 for each of the 64
# scrambling code groups. Entries are SSC numbers 1..16. Transcribed from the
# table as printed; the group for a given --psc follows from 5.2.2, which says
# the j:th group is the primary scrambling codes 16*8*j + 16*k (j = 0..63,
# k = 0..7). The i:th primary code is n = 16*i, so 8*j + k = i and the group is
# i // 8 = psc // 8 -- not psc // 128, which would only ever reach group 3.
SSC_ALLOCATION = (
    (1, 1, 2, 8, 9, 10, 15, 8, 10, 16, 2, 7, 15, 7, 16),
    (1, 1, 5, 16, 7, 3, 14, 16, 3, 10, 5, 12, 14, 12, 10),
    (1, 2, 1, 15, 5, 5, 12, 16, 6, 11, 2, 16, 11, 15, 12),
    (1, 2, 3, 1, 8, 6, 5, 2, 5, 8, 4, 4, 6, 3, 7),
    (1, 2, 16, 6, 6, 11, 15, 5, 12, 1, 15, 12, 16, 11, 2),
    (1, 3, 4, 7, 4, 1, 5, 5, 3, 6, 2, 8, 7, 6, 8),
    (1, 4, 11, 3, 4, 10, 9, 2, 11, 2, 10, 12, 12, 9, 3),
    (1, 5, 6, 6, 14, 9, 10, 2, 13, 9, 2, 5, 14, 1, 13),
    (1, 6, 10, 10, 4, 11, 7, 13, 16, 11, 13, 6, 4, 1, 16),
    (1, 6, 13, 2, 14, 2, 6, 5, 5, 13, 10, 9, 1, 14, 10),
    (1, 7, 8, 5, 7, 2, 4, 3, 8, 3, 2, 6, 6, 4, 5),
    (1, 7, 10, 9, 16, 7, 9, 15, 1, 8, 16, 8, 15, 2, 2),
    (1, 8, 12, 9, 9, 4, 13, 16, 5, 1, 13, 5, 12, 4, 8),
    (1, 8, 14, 10, 14, 1, 15, 15, 8, 5, 11, 4, 10, 5, 4),
    (1, 9, 2, 15, 15, 16, 10, 7, 8, 1, 10, 8, 2, 16, 9),
    (1, 9, 15, 6, 16, 2, 13, 14, 10, 11, 7, 4, 5, 12, 3),
    (1, 10, 9, 11, 15, 7, 6, 4, 16, 5, 2, 12, 13, 3, 14),
    (1, 11, 14, 4, 13, 2, 9, 10, 12, 16, 8, 5, 3, 15, 6),
    (1, 12, 12, 13, 14, 7, 2, 8, 14, 2, 1, 13, 11, 8, 11),
    (1, 12, 15, 5, 4, 14, 3, 16, 7, 8, 6, 2, 10, 11, 13),
    (1, 15, 4, 3, 7, 6, 10, 13, 12, 5, 14, 16, 8, 2, 11),
    (1, 16, 3, 12, 11, 9, 13, 5, 8, 2, 14, 7, 4, 10, 15),
    (2, 2, 5, 10, 16, 11, 3, 10, 11, 8, 5, 13, 3, 13, 8),
    (2, 2, 12, 3, 15, 5, 8, 3, 5, 14, 12, 9, 8, 9, 14),
    (2, 3, 6, 16, 12, 16, 3, 13, 13, 6, 7, 9, 2, 12, 7),
    (2, 3, 8, 2, 9, 15, 14, 3, 14, 9, 5, 5, 15, 8, 12),
    (2, 4, 7, 9, 5, 4, 9, 11, 2, 14, 5, 14, 11, 16, 16),
    (2, 4, 13, 12, 12, 7, 15, 10, 5, 2, 15, 5, 13, 7, 4),
    (2, 5, 9, 9, 3, 12, 8, 14, 15, 12, 14, 5, 3, 2, 15),
    (2, 5, 11, 7, 2, 11, 9, 4, 16, 7, 16, 9, 14, 14, 4),
    (2, 6, 2, 13, 3, 3, 12, 9, 7, 16, 6, 9, 16, 13, 12),
    (2, 6, 9, 7, 7, 16, 13, 3, 12, 2, 13, 12, 9, 16, 6),
    (2, 7, 12, 15, 2, 12, 4, 10, 13, 15, 13, 4, 5, 5, 10),
    (2, 7, 14, 16, 5, 9, 2, 9, 16, 11, 11, 5, 7, 4, 14),
    (2, 8, 5, 12, 5, 2, 14, 14, 8, 15, 3, 9, 12, 15, 9),
    (2, 9, 13, 4, 2, 13, 8, 11, 6, 4, 6, 8, 15, 15, 11),
    (2, 10, 3, 2, 13, 16, 8, 10, 8, 13, 11, 11, 16, 3, 5),
    (2, 11, 15, 3, 11, 6, 14, 10, 15, 10, 6, 7, 7, 14, 3),
    (2, 16, 4, 5, 16, 14, 7, 11, 4, 11, 14, 9, 9, 7, 5),
    (3, 3, 4, 6, 11, 12, 13, 6, 12, 14, 4, 5, 13, 5, 14),
    (3, 3, 6, 5, 16, 9, 15, 5, 9, 10, 6, 4, 15, 4, 10),
    (3, 4, 5, 14, 4, 6, 12, 13, 5, 13, 6, 11, 11, 12, 14),
    (3, 4, 9, 16, 10, 4, 16, 15, 3, 5, 10, 5, 15, 6, 6),
    (3, 4, 16, 10, 5, 10, 4, 9, 9, 16, 15, 6, 3, 5, 15),
    (3, 5, 12, 11, 14, 5, 11, 13, 3, 6, 14, 6, 13, 4, 4),
    (3, 6, 4, 10, 6, 5, 9, 15, 4, 15, 5, 16, 16, 9, 10),
    (3, 7, 8, 8, 16, 11, 12, 4, 15, 11, 4, 7, 16, 3, 15),
    (3, 7, 16, 11, 4, 15, 3, 15, 11, 12, 12, 4, 7, 8, 16),
    (3, 8, 7, 15, 4, 8, 15, 12, 3, 16, 4, 16, 12, 11, 11),
    (3, 8, 15, 4, 16, 4, 8, 7, 7, 15, 12, 11, 3, 16, 12),
    (3, 10, 10, 15, 16, 5, 4, 6, 16, 4, 3, 15, 9, 6, 9),
    (3, 13, 11, 5, 4, 12, 4, 11, 6, 6, 5, 3, 14, 13, 12),
    (3, 14, 7, 9, 14, 10, 13, 8, 7, 8, 10, 4, 4, 13, 9),
    (5, 5, 8, 14, 16, 13, 6, 14, 13, 7, 8, 15, 6, 15, 7),
    (5, 6, 11, 7, 10, 8, 5, 8, 7, 12, 12, 10, 6, 9, 11),
    (5, 6, 13, 8, 13, 5, 7, 7, 6, 16, 14, 15, 8, 16, 15),
    (5, 7, 9, 10, 7, 11, 6, 12, 9, 12, 11, 8, 8, 6, 10),
    (5, 9, 6, 8, 10, 9, 8, 12, 5, 11, 10, 11, 12, 7, 7),
    (5, 10, 10, 12, 8, 11, 9, 7, 8, 9, 5, 12, 6, 7, 6),
    (5, 10, 12, 6, 5, 12, 8, 9, 7, 6, 7, 8, 11, 11, 9),
    (5, 13, 15, 15, 14, 8, 6, 7, 16, 8, 7, 13, 14, 5, 16),
    (9, 10, 13, 10, 11, 15, 15, 9, 16, 12, 14, 13, 16, 14, 11),
    (9, 11, 12, 15, 12, 9, 13, 13, 11, 14, 10, 16, 15, 14, 16),
    (9, 12, 10, 15, 13, 14, 9, 14, 15, 11, 11, 13, 12, 16, 10),
)


def code_group(psc):
    """The scrambling code group j that primary code psc (n = 16*i) is in.

    TS 25.213 5.2.2: the j:th group is primary scrambling codes 16*8*j + 16*k
    for j = 0..63 and k = 0..7, and the i:th primary code is n = 16*i with
    i = 0..511. So 8*j + k = i and the group is i // 8 = psc // 8: eight
    consecutive primary codes share a group, and all 64 groups are reachable.
    """
    if not 0 <= psc <= PSC_MAX:
        raise ValueError("primary scrambling code %r out of range 0..511"
                         % (psc,))
    return psc // CODES_PER_GROUP


# ---------------------------------------------------------------------------
# carrier synthesis
# ---------------------------------------------------------------------------

def build_frame(carrier, psc):
    """One 10 ms radio frame of complex chips, 38400 of them.

    The channels are spread, then scrambled, then summed (TS 25.213 5.1.5
    Figure 9). P-CPICH is the constant (1 + j) symbol spread by Cch,256,0 --
    all ones, so spreading leaves the symbol in every chip -- and multiplied
    chip-wise by the scrambling code. The SCH is added afterwards and is not
    scrambled: 5.2.2's list of channels that use the primary scrambling code
    does not include it, and 5.3.3.5 defines it as its own 256-chip codes.
    """
    frame = np.zeros(CHIPS_PER_FRAME, dtype=np.complex128)
    if carrier in ("p-cpich", "both"):
        # 20 bits per slot = 10 QPSK symbols of (1 + j) at SF 256 (25.211
        # 5.3.3.1 Figure 13, all-zero Antenna 1 pattern), spread by the fixed
        # Cch,256,0 and scrambled.
        pilot = np.asarray(ovsf(PILOT_SF, PILOT_CODE_NUMBER), dtype=np.float64)
        assert pilot.size == PILOT_SF and (pilot == 1).all()
        symbol = np.repeat(pilot, CHIPS_PER_FRAME // pilot.size)
        frame += W_CPICH * (1 + 1j) * symbol * scrambling_code(psc)
    if carrier in ("sch", "both"):
        cp = psc_code()
        ssc = ssc_codes()
        row = SSC_ALLOCATION[code_group(psc)]
        for slot in range(SLOTS_PER_FRAME):
            start = slot * CHIPS_PER_SLOT
            # Figure 18: the SCH occupies the first 256 chips of every slot.
            frame[start:start + SCH_CHIPS] += W_PSCH * SCH_SIGN * cp
            frame[start:start + SCH_CHIPS] += (
                W_SSCH * SCH_SIGN * ssc[row[slot] - 1])
    return frame


def build_chips(carrier, psc, chips):
    """`chips` chips of the requested carrier, tiling whole frames."""
    frame = build_frame(carrier, psc)
    frames = (chips + CHIPS_PER_FRAME - 1) // CHIPS_PER_FRAME
    return np.tile(frame, frames)[:chips]


def headroom(x):
    """Scale down to full scale if the sum can clip; report the factor.

    A single scale is enough because scaling is linear, so there is nothing to
    iterate (unlike a waveform whose own construction is nonlinear). 1 - 1e-6
    keeps the peak strictly below full scale after float32 rounding.
    """
    peak = float(np.max(np.abs(x))) if x.size else 0.0
    if peak <= 1.0:
        return x, 1.0, peak
    scale = (1.0 - 1e-6) / peak
    x = x * scale
    return x, scale, float(np.max(np.abs(x)))


# ---------------------------------------------------------------------------
# what the tool will not synthesise (refusals), and what it does not model
# ---------------------------------------------------------------------------

REFUSED = {
    "s-cpich": (
        "the secondary CPICH",
        "TS 25.211 5.3.3.1 / TS 25.213 5.2.1 leave an S-CPICH's "
        "channelisation code and power offset to UTRAN signalling "
        "(the fixed Cch,256,0 belongs to the *primary* CPICH), so there is "
        "no standard-fixed 256-chip code to emit for it"),
    "p-ccpch": (
        "the P-CCPCH (BCH)",
        "its chips are the BCH transport block through the TS 25.212 4.6 "
        "coding chain (CRC, convolutional code, rate matching, 2-frame "
        "interleaving); this tool has no transport-channel stage, and a "
        "P-CCPCH emitted without BCH content would be a plausible-looking "
        "sequence, not the standard's"),
    "dpch": (
        "the DPCH family (DPCCH/DPDCH, PICH, AICH, S-CCPCH)",
        "every one of these needs a transport-channel or acquisition-"
        "indicator input (TS 25.211 5.3.3.6-5.3.3.9, TS 25.212) and a "
        "UTRAN-assigned channelisation code (TS 25.213 5.2.1); none of them "
        "is fixed by the standard alone"),
    "hs-dsch": (
        "HS-DSCH/HS-SCCH/HS-PDSCH",
        "the HS-PDSCH requires the TS 25.212 4.6 coding chain, 16/64QAM "
        "mapping and UE-specific codes; the purely standard-fixed part of "
        "the HS-DSCH does not exist"),
}

COMPARISON = (
    ("amplitude",
     "no clause fixes absolute transmit amplitude and the SCH weights Gp/Gs "
     "of TS 25.213 5.1.5 are signalled; W_cpich=%.1f, W_psch=%.1f, "
     "W_ssch=%.1f volts, then one headroom scale if the sum would clip"
     % (W_CPICH, W_PSCH, W_SSCH)),
    ("pulse-shaping",
     "chips are zero-order held at chip_samples > 1; the RRC filter of "
     "TS 25.104 6.8.1 (roll-off 0.22) and the TS 25.141 transmit mask are "
     "not applied"),
    ("scrambling-scope",
     "primary scrambling codes n = 16*i only (TS 25.213 5.2.2); the 15 "
     "secondary codes per set and the compressed-mode left/right "
     "alternatives are not implemented"),
    ("transport-channels",
     "no P-CCPCH, PICH, AICH, S-CCPCH or DPCH: those need TS 25.212 coding "
     "or UTRAN-assigned codes, so only the pilot and the SCH are emitted"),
    ("cpich-antenna",
     "the Antenna 1 all-zero pre-defined sequence of TS 25.211 5.3.3.1 "
     "Figure 14 only; the Antenna 2 STTD pattern is not emitted"),
    ("sch-sign",
     "a = -1, i.e. P-CCPCH not STTD encoded (TS 25.211 5.3.3.5); the "
     "a = +1 variant is selected by this row, not by a flag"),
    ("timing",
     "slot 0 / frame 0 begins at output sample 0 and the scrambling code "
     "starts at phase 0 there; no cell timing offset (TS 25.211 7) is "
     "modelled"),
    ("carrier",
     "complex baseband envelope only: no RF carrier, no path loss, no "
     "multipath channel, no noise"),
)


# ---------------------------------------------------------------------------
# argument handling
# ---------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    """argparse, but every usage error is one `ERROR<TAB>...` stderr line."""

    def error(self, message):
        sys.stderr.write("ERROR\t%s\n" % message)
        raise SystemExit(2)


def _parser():
    ap = _Parser(
        prog="umts_phy.py",
        description="WCDMA/UMTS Uu downlink baseband generator: primary "
                    "CPICH and synchronisation channel, with a real TS "
                    "25.213 scrambling code and OVSF spreading.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="one line per thing this tool can and "
                                "cannot generate, with the clause")
    gen = sub.add_parser("gen", help="write chips as IQ samples and print "
                                     "the parameters used as TSV")
    gen.add_argument("--carrier", required=True,
                     help="p-cpich | sch | both")
    gen.add_argument("--out", required=True,
                     help="output path (binary, interleaved I/Q)")
    gen.add_argument("--format", default="cf32",
                     help="cf32 (default) | ci16 | cu8")
    gen.add_argument("--rate", default="1",
                     help="output samples per chip, 1..64 (default 1), or a "
                          "sample rate in Hz that is an exact multiple of "
                          "3840000")
    gen.add_argument("--seconds", default="0.01",
                     help="duration in seconds (default 0.01 = one 10 ms "
                          "frame)")
    gen.add_argument("--psc", default="0",
                     help="primary scrambling code number i, 0..511 "
                          "(default 0); the code itself is n = 16*i")
    gen.add_argument("--chip-rate", default=str(CHIP_RATE),
                     help="chips/s; only 3840000 exists (default)")
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


def _chip_rate_arg(text):
    try:
        rate = int(text, 10)
    except (TypeError, ValueError):
        _die(2, "--chip-rate must be an integer in chips/s, got %r" % (text,))
    if rate != CHIP_RATE:
        _die(2, "unsupported --chip-rate %d" % rate,
             "TS 25.213 5.2 defines exactly one chip rate for the FDD mode, "
             "3.84 Mcps; there is no second chip rate to generate and "
             "scaling a 3.84 Mcps code to %d is not defined by any clause"
             % rate)
    return rate


def _rate_arg(text):
    """sps 1..64, or an Hz sample rate that is an exact multiple of 3.84 MHz."""
    try:
        val = int(text, 10)
    except (TypeError, ValueError):
        _die(2, "--rate must be an integer, got %r" % (text,),
             "the rate is either samples per chip (1..64) or a sample rate "
             "in Hz; a fractional rate would need a resampler, and this "
             "tool does not have one")
    if 1 <= val <= 64:
        return val
    if val >= CHIP_RATE and val % CHIP_RATE == 0:
        sps = val // CHIP_RATE
        if sps > 64:
            _die(2, "--rate %d is %d samples per chip, more than 64"
                 % (val, sps))
        return sps
    _die(2, "--rate %d is neither 1..64 samples per chip nor an integer "
            "multiple of the %d Hz chip rate" % (val, CHIP_RATE),
         "--rate is the output sample rate; this tool emits integer "
         "multiples of the chip rate only and has no fractional resampler, "
         "so %d Hz cannot be produced without inventing one" % val)


def _seconds_arg(text):
    try:
        val = float(text)
    except (TypeError, ValueError):
        _die(2, "--seconds must be a number of seconds, got %r" % (text,))
    if not (val > 0.0):
        _die(2, "--seconds must be positive, got %r" % (text,))
    if val > 3600.0:
        _die(2, "--seconds must be at most 3600, got %r" % (text,))
    return val


def _format_arg(text):
    if text not in FORMAT_ITEM_BYTES:
        _die(2, "unknown --format %r (want one of %s)"
             % (text, ", ".join(sorted(FORMAT_ITEM_BYTES))))
    return text


def _emit(pairs):
    for key, value in pairs:
        sys.stdout.write("%s\t%s\n" % (key, value))


def cmd_list(_args):
    for name, params, ref in LIST_LINES:
        sys.stdout.write("%s\t%s\t%s\n" % (name, params, ref))
    return 0


LIST_LINES = (
    ("carrier:p-cpich",
     "psc=0..511; SF=256 fixed to Cch,256,0; symbol=(1+j) from the all-zero "
     "Antenna 1 bit pattern; 38400 chips per 10 ms frame; "
     "format=cf32|ci16|cu8",
     "TS 25.213 4.3.1.1 (tree) + 5.2.1 (fixed code) + 5.2.2/5.2.3 "
     "(scrambling) + TS 25.211 5.3.3.1 (structure)"),
    ("carrier:sch",
     "psc=0..511 selects the code group psc//8 (eight primary codes per "
     "group, 5.2.2); P-SCH = 256-chip Cpsc in "
     "every slot; S-SCH = 15 x 256-chips from TS 25.213 5.2.3.2 Table 4; "
     "sign a=-1 (P-CCPCH not STTD encoded); not scrambled",
     "TS 25.213 5.2.3.1 (codes) + 5.2.3.2 Table 4 (allocation) + "
     "TS 25.211 5.3.3.5 (structure)"),
    ("carrier:both",
     "p-cpich + p-sch + s-sch summed at the TS 25.213 5.1.5 combining "
     "point; weights are modelled (see list row limit:amplitude), and one "
     "headroom scale is applied if the sum would exceed full scale",
     "TS 25.213 5.1.5 Figure 9 (combining)"),
    ("limit:amplitude",
     "W_cpich=0.5, W_psch=0.5, W_ssch=0.5 volts: no clause fixes absolute "
     "amplitude and Gp/Gs are signalled, so these are this tool's numbers",
     "assumption, stated; not a standard value"),
    ("limit:pulse-shaping",
     "chips are zero-order held above 1 sample per chip; no RRC "
     "(roll-off 0.22), no transmit mask",
     "TS 25.104 6.8.1 / TS 25.141, deliberately not implemented"),
    ("limit:scrambling-scope",
     "primary scrambling codes n=16*i only; no secondary codes, no "
     "compressed-mode left/right alternatives",
     "TS 25.213 5.2.2, partially implemented"),
    ("limit:cpich-antenna",
     "Antenna 1 (all-zero) pre-defined pattern only; no STTD Antenna 2 "
     "pattern, no S-CPICH",
     "TS 25.211 5.3.3.1 Figure 14, partially implemented"),
    ("refused:s-cpich",
     "rc 2 with ERROR and WHY: an S-CPICH's code and power offset are "
     "signalled, not standard-fixed",
     "TS 25.211 5.3.3.1 / TS 25.213 5.2.1 -- refused, see WHY line"),
    ("refused:p-ccpch",
     "rc 2 with ERROR and WHY: BCH content needs the TS 25.212 4.6 coding "
     "chain, which this tool does not have",
     "TS 25.212 4.6 -- refused"),
    ("refused:dpch",
     "rc 2 with ERROR and WHY: DPCCH/DPDCH/PICH/AICH/S-CCPCH need "
     "transport-channel input or UTRAN-assigned codes",
     "TS 25.211 5.3.3.6-5.3.3.9 -- refused"),
    ("refused:hs-dsch",
     "rc 2 with ERROR and WHY: HS-PDSCH/HS-SCCH/HS-DSCH need the "
     "transport-channel chain and UE-specific codes",
     "TS 25.212 4.6 / TS 25.213 5.2.1 -- refused"),
    ("rate", "1..64 samples per chip, or a sample rate in Hz that is an "
             "exact integer multiple of 3840000; no resampler exists",
     "TS 25.213 5.2 (3.84 Mcps)"),
    ("format", "cf32 (default, complex64) | ci16 (int16, x32767) | cu8 "
               "(uint8, x127+127.5); byte-compatible with "
               "modules/33_jamming_detect.sh",
     "tools/phy_seqs.py quantise() / modules/33_jamming_detect.sh"),
)


# ---------------------------------------------------------------------------
# gen
# ---------------------------------------------------------------------------

def cmd_gen(args):
    carrier = args.carrier
    if carrier in REFUSED:
        what, why = REFUSED[carrier]
        _die(2, "--carrier %s is not generated by this tool" % carrier,
             "%s cannot be synthesised here: %s" % (what, why))
    if carrier not in ("p-cpich", "sch", "both"):
        _die(2, "unknown --carrier %r (want p-cpich | sch | both)"
             % (carrier,),
             "the carriers this tool emits are p-cpich, sch and both; the "
             "ones it refuses are named in the `refused:` rows of "
             "`umts_phy.py list`")
    fmt = _format_arg(args.format)
    sps = _rate_arg(args.rate)
    seconds = _seconds_arg(args.seconds)
    chip_rate = _chip_rate_arg(args.chip_rate)
    psc = _int_arg("psc", args.psc, 0, PSC_MAX)
    if args.out in ("-", "/dev/stdout", "/dev/fd/1"):
        _die(2, "--out must be a file path; stdout carries the TSV summary")

    rate = sps * chip_rate
    samples = int(round(seconds * rate))
    if samples < sps:
        _die(2, "--seconds %r is shorter than one chip at %d sps"
             % (args.seconds, sps))
    if samples % sps:
        _die(2, "--seconds %r does not give a whole number of chips"
             % (args.seconds,),
             "%d samples at %d samples per chip leaves %d samples of a "
             "part-chipped symbol; the tool emits whole chips only, so pick "
             "a duration that is a multiple of %.9f s"
             % (samples, sps, samples % sps, sps * 1.0 / rate))
    chips = samples // sps

    x = build_chips(carrier, psc, chips)
    x, scale, peak = headroom(x)
    samples_out = np.repeat(x, sps) if sps > 1 else x
    payload = quantise(samples_out, fmt)
    if len(payload) != samples_out.size * FORMAT_ITEM_BYTES[fmt]:
        _die(1, "internal: %d bytes for %d %s samples"
             % (len(payload), samples_out.size, fmt))
    try:
        with open(args.out, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        _die(1, "cannot write %s: %s" % (args.out, exc))

    frames = chips / float(CHIPS_PER_FRAME)
    slots = chips / float(CHIPS_PER_SLOT)
    rows = [
        ("path", args.out),
        ("carrier", carrier),
        ("format", fmt),
        ("rate", "%d" % rate),
        ("chip_rate", "%d" % chip_rate),
        ("chip_samples", "%d" % sps),
        ("seconds", "%.9f" % (samples_out.size / float(rate))),
        ("samples", "%d" % samples_out.size),
        ("bytes", "%d" % len(payload)),
        ("psc", "%d" % psc),
        ("scrambling_code", "%d" % (PSC_STRIDE * psc)),
        ("chips", "%d" % chips),
        ("chips_per_slot", "%d" % CHIPS_PER_SLOT),
        ("chips_per_frame", "%d" % CHIPS_PER_FRAME),
        ("slots", "%.6f" % slots),
        ("frames", "%.6f" % frames),
        ("frame_seconds", "%.6f" % FRAME_SECONDS),
        ("pilot_sf", "%d" % PILOT_SF),
        ("pilot_code", "Cch,%d,%d" % (PILOT_SF, PILOT_CODE_NUMBER)),
        ("pilot_symbol", "1+1j"),
        ("code_group", "%d" % code_group(psc)),
        ("sch_sign", "%d" % SCH_SIGN),
        ("peak_full_scale", "%.4f" % FORMAT_FULL_SCALE[fmt]),
        ("peak_written", "%.6f" % peak),
        ("peak_scale", "%.9f" % scale),
        ("formula_ref",
         "TS 25.213 5.2.2+5.2.3 (x/y generators, Gold, complex code), "
         "4.3.1.1 (OVSF tree), 5.2.3.1+5.2.3.2 Table 4 (PSC/SSC), "
         "TS 25.211 5.3.3.1 and 5.3.3.5 (frame and SCH structure)"),
        ("code_phase",
         "frame 0 starts at scrambling-code phase 0; 5.2.3 repeats the "
         "phase-0..38399 pattern every 10 ms frame, so every frame of this "
         "file carries the same 38400-chip pattern"),
    ]
    for key, text in COMPARISON:
        rows.append(("limit", "%s: %s" % (key, text)))
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
