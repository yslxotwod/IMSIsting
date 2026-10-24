#!/usr/bin/env python3
"""umts_sccpch.py -- the S-CCPCH: the physical channel a SIB actually rides.

What this is
------------
The last hop of this tree's 3G broadcast chain.  `umts_sib.py` builds the RRC
SYSTEM INFORMATION messages and runs a FACH transport block through TS 25.212;
`umts_bch.py` puts the MIB on the P-CCPCH.  This tool takes the channel-coded
FACH frame that comes out of the TS 25.212 chain and does the physical layer
under it: slot structure, QPSK, spreading, the frame offset, scrambling, and
the sample file a transmitter can key.

Why it is not the BCH
---------------------
SIB1/SIB3/SIB5 do not ride the BCH.  The BCH carries the MasterInformationBlock
only, with one fixed transport format (TS 25.212 4.2.13.6, "Only one primary
CCPCH"); the SIBs ride the BCCH mapped to a FACH, and the FACH is mapped to a
Secondary CCPCH (TS 25.331 8.1.1.1.2/8.1.1.1.3, TS 25.211 5.3.3.4).  So the
missing piece was never a different BCH payload: it is the S-CCPCH under the
FACH, which is what this tool builds.  The MIB schedules the SIBs; this file
carries them.

Specifications and where each constant comes from
-------------------------------------------------
TS 25.211 v6.4.0 (local copy /tmp/ts125211.txt):
  5.3.3.4    Secondary CCPCH frame structure (Figure 17) and Table 18: slot
             formats 0..17, "Tslot = 2560 chips, 20*2^k bits (k=0..6)",
             "SF = 256/2^k", spreading factor range 256 down to 4,
             Bits/Frame, Bits/Slot, Ndata1, Npilot, NTFCI per format.
             Only the two formats with no pilot and no TFCI field are built
             here: format 0 (SF=256, 20 data bits per slot, 300 per frame) and
             format 4 (SF=128, 40 data bits per slot, 600 per frame).  The
             release text says "The slot formats with pilot bits are not
             supported in this release", and a TFCI field needs the (32,10)
             RM code of TS 25.212 4.3 that this tool does not implement, so
             formats 1-3 and 5-17 are refused rather than half-built.
  7.1        "the offset from the P-CCPCH frame timing is a multiple of 256
             chips, i.e. tau_S-CCPCH,k = Tk * 256 chip, Tk in {0..149}".
TS 25.213 v6.4.0 (local copy /tmp/ts125213.txt):
  4.3.1.1    OVSF recursion Cch,2n',2k = (C, C), Cch,2n',2k+1 = (C, -C)
  5.1.1.1    QPSK: bit pair to I/Q, 0 -> +1, 1 -> -1
  5.2.1      the channelisation code is assigned by UTRAN; Cch,256,0 is the
             Primary CPICH and Cch,256,1 is the Primary CCPCH, so neither is
             available to an S-CCPCH, and a code whose subtree contains them
             (Cch,SF,0 for any SF) is refused for the same reason.
  5.2.2      primary scrambling code n = 16*i, Sdl,n(i) = Zn(i) +
             j*Zn((i+131072) mod (2^18-1))
  5.1.4      "the scrambling code is aligned with the P-CCPCH frame boundary",
             which is why the frame offset is applied in chips and not in
             symbols: the S-CCPCH frame starts Tk*256 chips after the P-CCPCH
             frame boundary, mid-scrambling-sequence.

Usage: tools/umts_sccpch.py <verb> [options]   (see `list`)
Exit:  0 built, 1 could not build, 2 usage error or refusal.
"""

import argparse
import os
import sys

# The Gold generator, the OVSF recursion and the QPSK mapping are the ones
# umts_bch.py already holds and check-umts-bch.sh already referees; importing
# them is how this tree keeps one implementation of a published sequence
# instead of two that can drift.  The referee for this file recomputes them
# from the clause text again, so the import is not trusted either.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
try:
    from umts_bch import (CHIPS_PER_FRAME, CHIPS_PER_SLOT, SLOTS_PER_FRAME,
                          CHIP_RATE, PSC_MAX, ovsf, qpsk,
                          scrambling_sequence)
except ImportError:  # a copy tested outside the tree still gets its limits
    CHIPS_PER_SLOT = 2560
    SLOTS_PER_FRAME = 15
    CHIPS_PER_FRAME = CHIPS_PER_SLOT * SLOTS_PER_FRAME
    CHIP_RATE = 3840000
    PSC_MAX = 511
    ovsf = None

try:
    import numpy as np
except ImportError:  # stages/list do not need it; encode/mix refuse without it
    np = None


# ---------------------------------------------------------------------------
# TS 25.211 5.3.3.4 Table 18, the whole table so a refusal can quote a row.
# ---------------------------------------------------------------------------
# (slot format, channel bit rate kbps, symbol rate ksps, SF, bits/frame,
#  bits/slot, Ndata1, Npilot, NTFCI)
TABLE18 = [
    (0, 30, 15, 256, 300, 20, 20, 0, 0),
    (1, 30, 15, 256, 300, 20, 12, 8, 0),
    (2, 30, 15, 256, 300, 20, 18, 0, 2),
    (3, 30, 15, 256, 300, 20, 10, 8, 2),
    (4, 60, 30, 128, 600, 40, 40, 0, 0),
    (5, 60, 30, 128, 600, 40, 32, 8, 0),
    (6, 60, 30, 128, 600, 40, 38, 0, 2),
    (7, 60, 30, 128, 600, 40, 30, 8, 2),
    (8, 120, 60, 64, 1200, 80, 72, 0, 8),
    (9, 120, 60, 64, 1200, 80, 64, 8, 8),
    (10, 240, 120, 32, 2400, 160, 152, 0, 8),
    (11, 240, 120, 32, 2400, 160, 144, 8, 8),
    (12, 480, 240, 16, 4800, 320, 312, 0, 8),
    (13, 480, 240, 16, 4800, 320, 296, 16, 8),
    (14, 960, 480, 8, 9600, 640, 632, 0, 8),
    (15, 960, 480, 8, 9600, 640, 616, 16, 8),
    (16, 1920, 960, 4, 19200, 1280, 1272, 0, 8),
    (17, 1920, 960, 4, 19200, 1280, 1256, 16, 8),
]
BY_ID = {row[0]: row for row in TABLE18}

# The formats this tool builds: no pilot field, no TFCI field.
BUILT = {0: "SF=256, 20 data bits per slot, no pilot, no TFCI",
         4: "SF=128, 40 data bits per slot, no pilot, no TFCI"}
SF_TO_FORMAT = {256: 0, 128: 4}

OFFSET_MAX = 149          # TS 25.211 7.1: Tk in {0..149}, 256 chips each
OFFSET_CHIPS = 256

# Sample containers, same conventions as umts_bch.py and umts_phy.py.
FORMATS = {"cf32": 8, "ci16": 4, "cu8": 2}
FULL_SCALE = {"cf32": 1.0, "ci16": 32767.0, "cu8": 127.0}

LIMITS = [
    ("slot-formats",
     "only Table 18 formats 0 and 4 are built: they are the two with Npilot=0 "
     "and NTFCI=0.  A pilot field is refused because the release text does "
     "not support it, and a TFCI field is refused because the (32,10) Reed-"
     "Muller code of TS 25.212 4.3 is not implemented here"),
    ("spreading-code",
     "the code is an input (Cch,SF,k with SF 256 or 128).  Cch,256,0 and "
     "Cch,256,1 are refused because they are the Primary CPICH and the "
     "Primary CCPCH (TS 25.213 5.2.1), and Cch,SF,0 is refused for any SF "
     "because its subtree contains those two codes"),
    ("scrambling",
     "the primary scrambling code of the cell is used; TS 25.213 5.2.3 also "
     "allows a secondary scrambling code for an S-CCPCH, which is not built "
     "here because a camping UE does not look for it"),
    ("one-channel",
     "one S-CCPCH at a time.  A cell may carry up to maxSCCPCH=16 (TS 25.331 "
     "11) and this tool writes one of them; summing is the caller's job "
     "(`mix` does it for sample files)"),
    ("frame-offset",
     "tau_S-CCPCH is applied as leading zero chips on this channel's own "
     "timeline, so the file starts at the P-CCPCH frame boundary and the "
     "S-CCPCH frame starts `offset` chips later.  `mix` sums two such files "
     "sample for sample, which is what puts the broadcast channels on one "
     "carrier"),
    ("no-transmitter",
     "this tool writes samples and nothing else.  Nothing here keys a radio; "
     "modules/08_umts_air.sh --transmit is the only path that does, and it "
     "prints its own refusal when no device answers"),
    ("referee",
     "there is no external decoder for this chain on this machine.  The "
     "checks that hold it live in tools/check-umts-sccpch.sh, which "
     "recomputes the slot structure, the OVSF code, the spreading, the frame "
     "offset and the Gold scrambling sequence from the clause text with code "
     "that has nothing in common with this file"),
]


def _die(rc, msg, why=None):
    print("ERROR\t%s" % msg)
    if why:
        print("WHY\t%s" % why)
    return rc


def _emit(rows):
    for row in rows:
        print("%s\t%s" % row)


def _bits_hex(bits):
    b = list(bits)
    pad = (-len(b)) % 4
    b += [0] * pad
    return "".join("%x" % int("".join(str(x) for x in b[i:i + 4]), 2)
                   for i in range(0, len(b), 4)), pad


def _hex_bits(text, width=None):
    t = text.replace(" ", "").replace("0x", "").lower()
    if not t or any(c not in "0123456789abcdef" for c in t):
        raise ValueError("%r is not hex" % text)
    bits = [int(c, 16) >> (3 - i) & 1 for c in t for i in range(4)]
    if width is not None:
        if width > len(bits):
            raise ValueError("%r carries %d bits, not %d" % (text, len(bits), width))
        bits = bits[:width]
    return bits


def _int(text, what):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        raise ValueError("%s: %r is not an integer" % (what, text))


def slot_format(sf):
    """Look the slot format up from the spreading factor, or refuse."""
    fmt = SF_TO_FORMAT.get(sf)
    if fmt is None:
        raise ValueError(
            "SF=%d is not an S-CCPCH format this tool builds (%s); Table 18 "
            "also has SF=64,32,16,8,4, but every one of those rows carries a "
            "TFCI field and formats 1,3,5,7,9,11,13,15,17 also carry a pilot"
            % (sf, "0 (SF=256) and 4 (SF=128)"))
    return BY_ID[fmt]


def check_code(fmt_row, code):
    """Refuse a channelisation code another channel already owns."""
    sf = fmt_row[3]
    if code < 0 or code >= sf:
        raise ValueError("Cch,%d,%d does not exist: k is 0..%d" % (sf, code, sf - 1))
    if code == 0:
        raise ValueError(
            "Cch,%d,0 is refused: its subtree holds Cch,256,0 (Primary CPICH) "
            "and Cch,256,1 (Primary CCPCH), so no other channel may use it "
            "(TS 25.213 5.2.1)" % sf)
    if sf == 256 and code == 1:
        raise ValueError(
            "Cch,256,1 is the Primary CCPCH (TS 25.213 5.2.1); the S-CCPCH "
            "needs a different code")


# ---------------------------------------------------------------------------
# The physical chain
# ---------------------------------------------------------------------------
def frame_symbols(bits, fmt_row):
    """Bits -> QPSK symbols, slot by slot (TS 25.213 5.1.1.1)."""
    data1 = fmt_row[6]
    if len(bits) != fmt_row[4]:
        raise ValueError("%d channel-coded bits, slot format %d holds %d"
                         % (len(bits), fmt_row[0], fmt_row[4]))
    out = []
    for slot in range(SLOTS_PER_FRAME):
        chunk = bits[slot * data1:(slot + 1) * data1]
        out.append(qpsk(chunk))
    return out


def spread_symbols(symbols, code):
    """Spread one slot: each QPSK symbol over SF chips (TS 25.213 4.3.1.1)."""
    return [complex(i * c, q * c) for (i, q) in symbols for c in code]


def frame_chips(bits, fmt_row, code, psc, offset_chips=0):
    """Return (frame, spread, scram) for one 10 ms S-CCPCH frame.

    The frame list is CHIPS_PER_FRAME long and starts at the *S-CCPCH* frame
    boundary.  The offset is not applied here: a channel's own frame is built
    from its own start, and the offset places the frame on the carrier
    timeline, which is why `encode` prefixes `offset_chips` zeros instead of
    rotating the scrambling sequence.
    """
    sf = fmt_row[3]
    chip_code = ovsf(sf, code)
    scram = scrambling_sequence(psc)
    spread = []
    for sym in frame_symbols(bits, fmt_row):
        slot = spread_symbols(sym, chip_code)
        if len(slot) != CHIPS_PER_SLOT:
            raise ValueError("a spread slot is %d chips, the slot is %d"
                             % (len(slot), CHIPS_PER_SLOT))
        spread.extend(slot)
    frame = [0j] * CHIPS_PER_FRAME
    on = []
    for c in range(CHIPS_PER_FRAME):
        v = spread[c] * scram[c]
        frame[c] = v
        on.append(v)
    return frame, spread, on


# ---------------------------------------------------------------------------
# Sample containers
# ---------------------------------------------------------------------------
def quantise(x, fmt):
    """Sample container, byte for byte the one umts_bch.py writes: cf32 is
    little-endian float32 I,Q interleaved; ci16 is int16 pairs at 32767 full
    scale; cu8 is unsigned pairs with a 127.5 offset at 127.0 scale.  The
    interleaving matters -- `mix` reads the same files, and a carrier built by
    two tools has to mean the same thing in both."""
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


def _read_samples(path, fmt, nbytes):
    with open(path, "rb") as fh:
        data = fh.read()
    width = FORMATS[fmt]
    if len(data) < nbytes:
        raise ValueError("%s carries %d bytes, %d are needed for %d samples"
                         % (path, len(data), nbytes, nbytes // width))
    data = data[:nbytes]
    if fmt == "cf32":
        f = np.frombuffer(data, dtype="<f4")
        return f[0::2].astype(np.float64) + 1j * f[1::2]
    if fmt == "ci16":
        v = np.frombuffer(data, dtype="<i2")
        return (v[0::2].astype(np.float64) + 1j * v[1::2]) / 32767.0
    v = np.frombuffer(data, dtype="u1").astype(np.float64)
    return ((v[0::2] - 127.5) + 1j * (v[1::2] - 127.5)) / 127.0


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------
def cmd_list(_args):
    rows = [
        ("tool", "umts_sccpch.py -- the Secondary CCPCH under the FACH: slot "
                 "structure, QPSK, spreading, frame offset, scrambling"),
        ("spec", "TS 25.211 v6.4.0 5.3.3.4 (Table 18) and 7.1; TS 25.213 "
                 "v6.4.0 4.3.1.1, 5.1.1.1, 5.1.4, 5.2.1, 5.2.2"),
        ("list", "list  -- this page"),
        ("stages", "stages --frame-hex HEX [--sf 256|128] [--code K] [--offset N] "
                   "[--psc I]  -- slot, QPSK, spreading and scrambling bit rows"),
        ("encode", "encode --frame-hex HEX [--sf 256|128] [--code K] "
                   "[--offset N] [--psc I] [--frames N] [--rate SPS] "
                   "[--format cf32|ci16|cu8] --out FILE  -- the sample file"),
        ("mix", "mix --out FILE --format F --in A --in B [...]  -- sum sample "
                "files on one carrier (the caller's channel summing)"),
        ("channel", "one S-CCPCH frame is %d chips = %d slots of %d chips = "
                    "10 ms at %d chips/s" % (CHIPS_PER_FRAME, SLOTS_PER_FRAME,
                                             CHIPS_PER_SLOT, CHIP_RATE)),
        ("built", "; ".join("format %d: %s" % (k, v)
                            for k, v in sorted(BUILT.items()))),
        ("convention", "every hex is an octet string, right padded with zero "
                       "bits, first bit in the most significant bit of the "
                       "first octet -- the same convention as umts_sib.py and "
                       "umts_bch.py"),
    ]
    for key, text in LIMITS:
        rows.append(("limit", "%s: %s" % (key, text)))
    _emit(rows)
    return 0


def _common(args):
    """Parse the physical arguments every building verb shares."""
    sf = 256 if args.sf is None else _int(args.sf, "--sf")
    fmt_row = slot_format(sf)
    code = 3 if args.code is None else _int(args.code, "--code")
    check_code(fmt_row, code)
    offset = 0 if args.offset is None else _int(args.offset, "--offset")
    if offset < 0 or offset > OFFSET_MAX:
        raise ValueError("--offset %d is outside 0..%d: tau_S-CCPCH = Tk * "
                         "256 chips with Tk in {0..%d} (TS 25.211 7.1)"
                         % (offset, OFFSET_MAX, OFFSET_MAX))
    psc = 0 if args.psc is None else _int(args.psc, "--psc")
    if psc < 0 or psc > PSC_MAX:
        raise ValueError("--psc %d is outside 0..%d: TS 25.213 5.2.2 defines "
                         "512 primary scrambling codes" % (psc, PSC_MAX))
    bits = _hex_bits(args.frame_hex, width=fmt_row[4])
    return fmt_row, code, offset, psc, bits


def cmd_stages(args):
    try:
        fmt_row, code, offset, psc, bits = _common(args)
    except ValueError as exc:
        return _die(2, str(exc), "the frame is the channel-coded FACH frame "
                    "from umts_sib.py pack, one slot format's worth of bits")
    frame, spread, scram = frame_chips(bits, fmt_row, code, psc)
    rows = [
        ("cli", "stages"),
        ("slot_format", "%d -- %s" % (fmt_row[0], BUILT[fmt_row[0]])),
        ("sf", "%d" % fmt_row[3]),
        ("code", "Cch,%d,%d" % (fmt_row[3], code)),
        ("bits_per_slot", "%d" % fmt_row[6]),
        ("bits_frame", "%d" % fmt_row[4]),
        ("offset_chips", "%d (= %d * %d)" % (offset * OFFSET_CHIPS, offset,
                                             OFFSET_CHIPS)),
        ("psc", "%d, scrambling code %d" % (psc, 16 * psc)),
    ]
    for slot in range(SLOTS_PER_FRAME):
        chunk = bits[slot * fmt_row[6]:(slot + 1) * fmt_row[6]]
        h, pad = _bits_hex(chunk)
        rows.append(("slot%02d" % slot,
                     "bits=%s symbols=%d hex=%s pad=%d ref=TS 25.211 5.3.3.4 "
                     "Figure 17"
                     % ("".join(str(b) for b in chunk), fmt_row[7] and
                        len(chunk) // 2 or len(chunk) // 2, h, pad)))
    for s in range(SLOTS_PER_FRAME):
        sl = spread[s * CHIPS_PER_SLOT:(s + 1) * CHIPS_PER_SLOT]
        rows.append(("chips%02d" % s,
                     "first4=%s ref=TS 25.213 4.3.1.1 + 5.2.2; the S-CCPCH "
                     "frame starts at chip %d of the carrier frame"
                     % (", ".join("%+.0f%+.0fj" % (c.real, c.imag) for c in sl[:4]),
                        offset * OFFSET_CHIPS)))
    rows.append(("chips_frame", "%d" % CHIPS_PER_FRAME))
    rows.append(("energy_first_frame",
                 "%.3f" % sum(abs(c) for c in frame)))
    for key, text in LIMITS:
        rows.append(("limit", "%s: %s" % (key, text)))
    _emit(rows)
    return 0


def cmd_encode(args):
    if np is None:
        return _die(1, "numpy is not installed",
                    "the sample writer needs numpy; `stages` and `list` do not")
    try:
        fmt_row, code, offset, psc, bits = _common(args)
    except ValueError as exc:
        return _die(2, str(exc), "see --help for the arguments a frame needs")
    fmt = args.format
    if fmt not in FORMATS:
        return _die(2, "--format %r is not one of cf32, ci16, cu8" % (fmt,))
    sps = args.rate
    if sps < 1 or sps > 64:
        return _die(2, "--rate %d samples per chip is outside 1..64" % sps,
                    "the chip rate is 3.84 Mcps, so %d samples per chip is out "
                    "of range" % sps)
    if args.frames < 1 or args.frames > 100:
        return _die(2, "--frames %d is outside 1..100" % args.frames,
                    "one frame is %d chips" % CHIPS_PER_FRAME)
    if args.at_start < 0 or args.at_start >= args.frames:
        return _die(2, "--at-start %d is outside the %d frame file"
                    % (args.at_start, args.frames),
                    "the first frame a channel occupies has to be one of the "
                    "frames the file holds")
    if args.period < 1:
        return _die(2, "--period %d is not a frame count" % args.period,
                    "a repetition period of one means every frame, and zero "
                    "means the channel never appears")
    if args.out in ("-", "/dev/stdout", "/dev/fd/1"):
        return _die(2, "--out must be a file path; stdout carries the TSV summary",
                    "the TSV summary is the output channel and the sample file "
                    "is binary")
    try:
        frame, spread, scram = frame_chips(bits, fmt_row, code, psc)
    except ValueError as exc:
        return _die(1, str(exc))

    # The frame offset is applied on the carrier timeline: the file starts at
    # the P-CCPCH frame boundary, the S-CCPCH frame starts offset*256 chips in.
    #
    # A channel that repeats every N frames is silent in the frames it does not
    # occupy.  That is what keeps two SIBs from being summed into the same TTI:
    # the UE decodes one FACH transport block per frame, so a sum of two is
    # neither of them.  Silence, not a low amplitude, for the same reason.
    used = [1 if (f >= args.at_start and
                  (f - args.at_start) % args.period == 0) else 0
            for f in range(args.frames)]
    frames = int(sum(used))
    plan = np.concatenate([np.asarray(frame, dtype=np.complex128) * u
                           for u in used])
    body = np.repeat(plan, sps)
    pad = np.zeros(offset * OFFSET_CHIPS * sps, dtype=np.complex128)
    x = np.concatenate([pad, body]) * 0.5
    payload = quantise(x, fmt)
    expect = x.size * FORMATS[fmt]
    if len(payload) != expect:
        return _die(1, "internal: %d bytes for %d %s samples"
                    % (len(payload), x.size, fmt))
    try:
        with open(args.out, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        return _die(1, "cannot write %s: %s" % (args.out, exc))

    peak = float(max(abs(x.real).max(), abs(x.imag).max()))
    h, padbits = _bits_hex(bits)
    rows = [
        ("path", args.out),
        ("frame_hex", h),
        ("frame_bits", "%d" % len(bits)),
        ("frame_pad", "%d" % padbits),
        ("slot_format", "%d" % fmt_row[0]),
        ("sf", "%d" % fmt_row[3]),
        ("code", "Cch,%d,%d" % (fmt_row[3], code)),
        ("offset", "%d" % offset),
        ("offset_chips", "%d" % (offset * OFFSET_CHIPS)),
        ("at_start", "%d" % args.at_start),
        ("period", "%d" % args.period),
        ("frames_written", "%d" % frames),
        ("frames_silent", "%d" % (args.frames - frames)),
        ("psc", "%d" % psc),
        ("scrambling_code", "%d" % (16 * psc)),
        ("format", fmt),
        ("rate", "%d" % (sps * CHIP_RATE)),
        ("chip_samples", "%d" % sps),
        ("chip_rate", "%d" % CHIP_RATE),
        ("frames", "%d" % args.frames),
        ("slots", "%d" % (args.frames * SLOTS_PER_FRAME)),
        ("chips", "%d" % (args.frames * CHIPS_PER_FRAME + offset * OFFSET_CHIPS)),
        ("chips_channel", "%d" % (args.frames * CHIPS_PER_FRAME)),
        ("samples", "%d" % x.size),
        ("bytes", "%d" % len(payload)),
        ("seconds", "%.9f" % (x.size / float(sps * CHIP_RATE))),
        ("peak_full_scale", "%.4f" % FULL_SCALE[fmt]),
        ("peak_written", "%.6f" % peak),
        ("scale", "0.5"),
        ("chip_constellation",
         "I,Q in {-2, 0, +2} before the 0.5 scale: |Sdl,n| = sqrt(2) "
         "(TS 25.213 5.2.2 rails are +-1) times the sqrt(2) QPSK symbol"),
        ("next", "tools/umts_sccpch.py mix --format %s --in %s "
                 "[--in carrier] [--in bch] --out cell.%s"
                 % (fmt, args.out, fmt)),
        ("handoff", "these are samples.  Keying a radio is --transmit's job, "
                    "and it says so itself when no device answers"),
        ("formula_ref",
         "TS 25.211 5.3.3.4 Table 18 (format %d: SF=%d, %d data bits per "
         "slot, no pilot, no TFCI) and 7.1 (tau = Tk*256 chips); "
         "TS 25.213 5.1.1.1 (QPSK), 4.3.1.1 (Cch,%d,%d), 5.2.2 (Sdl,%d), "
         "5.1.4 (frame-aligned scrambling)"
         % (fmt_row[0], fmt_row[3], fmt_row[6], fmt_row[3], code, 16 * psc)),
    ]
    for key, text in LIMITS:
        rows.append(("limit", "%s: %s" % (key, text)))
    _emit(rows)
    return 0


def cmd_mix(args):
    """Sum sample files onto one carrier.

    The first --in is the reference: it sets the length of the output, and
    every other file is summed sample for sample as far as it goes.  A channel
    that is shorter than the carrier contributes silence past its end, and
    that is named in the output rather than padded away silently -- a BCH
    written for one frame on a one second carrier is a real thing to see.
    """
    if np is None:
        return _die(1, "numpy is not installed", "mixing needs numpy")
    fmt = args.format
    if fmt not in FORMATS:
        return _die(2, "--format %r is not one of cf32, ci16, cu8" % (fmt,))
    if len(args.inputs) < 2:
        return _die(2, "mix needs at least two --in files (%d given)"
                    % len(args.inputs),
                    "one file is already a carrier; mixing is how two channels "
                    "become one waveform")
    counts = []
    for path in args.inputs:
        if not os.path.isfile(path):
            return _die(2, "no such sample file: %s" % path)
        size = os.path.getsize(path)
        if size % FORMATS[fmt]:
            return _die(2, "%s is %d bytes, not a whole number of %s samples"
                        % (path, size, fmt))
        counts.append(size // FORMATS[fmt])
    n = counts[0]
    acc = np.zeros(n, dtype=np.complex128)
    coverage = []
    for i, path in enumerate(args.inputs):
        used = min(counts[i], n)
        acc[:used] += _read_samples(path, fmt, used * FORMATS[fmt])
        coverage.append("%s:%d/%d" % (os.path.basename(path), used, n))
    peak = float(max(abs(acc.real).max(), abs(acc.imag).max()))
    factor = 1.0
    if not args.no_scale and peak > 1.0:
        # The same rule umts_phy.py applies to its own carrier: one linear
        # scale for the whole file, so the channels keep their relative power
        # and the sum lands just under full scale instead of clipping in the
        # radio's DAC.  A cell whose S-CCPCH is louder than its pilot is not a
        # cell a handset will keep; amplifying it into a wall does not fix that.
        factor = (1.0 - 1e-6) / peak
        acc = acc * factor
    payload = quantise(acc, fmt)
    try:
        with open(args.out, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        return _die(1, "cannot write %s: %s" % (args.out, exc))
    written = float(max(abs(acc.real).max(), abs(acc.imag).max()))
    short = [c for c, cnt in zip(coverage, counts) if cnt < n]
    rows = [
        ("path", args.out),
        ("inputs", "%d" % len(args.inputs)),
        ("reference", args.inputs[0]),
        ("samples", "%d" % n),
        ("format", fmt),
        ("peak_sum", "%.6f" % peak),
        ("peak_scale", "%.9f" % factor),
        ("peak_written", "%.6f" % written),
        ("full_scale", "%.4f" % FULL_SCALE[fmt]),
        ("clip_risk", "no -- scaled to full scale" if factor < 1.0
         else ("yes -- --no-scale was given" if peak > 1.0 else "no")),
        ("coverage", "; ".join(coverage)),
        ("short_inputs", ", ".join(short) if short else "none"),
        ("note", "sample for sample addition: every channel keeps its own "
                 "spreading, scrambling and frame offset, and only the sum is "
                 "written; the first --in sets the length, and a file shorter "
                 "than it contributes silence past its end (named above)"),
    ]
    _emit(rows)
    return 0


def _rate_arg(text):
    v = int(text, 0)
    if v >= CHIP_RATE and v % CHIP_RATE == 0:
        v //= CHIP_RATE
    return v


def _parser():
    ap = argparse.ArgumentParser(
        prog="umts_sccpch.py",
        description="The Secondary CCPCH under a FACH: TS 25.211 5.3.3.4 slot "
                    "structure, TS 25.213 spreading and scrambling, samples.")
    sub = ap.add_subparsers(dest="verb")

    p = sub.add_parser("list", help="verbs, limits and conventions")
    p.set_defaults(func=cmd_list)

    for name, func, helptext in (
            ("stages", cmd_stages, "print the slot, QPSK and chip rows"),
            ("encode", cmd_encode, "write the S-CCPCH sample file")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--frame-hex", dest="frame_hex", required=True)
        p.add_argument("--sf", type=str, help="spreading factor: 256 or 128")
        p.add_argument("--code", type=str, help="channelisation code number k")
        p.add_argument("--offset", type=str,
                       help="tau_S-CCPCH in units of 256 chips, 0..149")
        p.add_argument("--psc", type=str, help="primary scrambling code, 0..511")
        if name == "encode":
            p.add_argument("--frames", type=int, default=1)
            p.add_argument("--at-start", type=int, default=0,
                           help="first frame this channel occupies, 0-based")
            p.add_argument("--period", type=int, default=1,
                           help="repeat every N frames; frames in between are "
                                "silent, so two channels never share a TTI")
            p.add_argument("--rate", type=_rate_arg, default=1)
            p.add_argument("--format", default="cf32",
                           help="cf32, ci16 or cu8")
            p.add_argument("--out", required=True)
        p.set_defaults(func=func)

    p = sub.add_parser("mix", help="sum sample files onto one carrier")
    p.add_argument("--in", dest="inputs", action="append", default=[],
                   metavar="FILE")
    p.add_argument("--out", required=True)
    p.add_argument("--format", default="cf32")
    p.add_argument("--no-scale", action="store_true",
                   help="keep the raw sum even if it exceeds full scale")
    p.set_defaults(func=cmd_mix)
    return ap


def main(argv):
    ap = _parser()
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
