#!/usr/bin/env python3
"""Cross-check modules/12_nr_air.sh's MIB decoder against the ASN.1 layout.

Why this exists
---------------
nair_decode_mib() reads its field offsets from a comment that lists the MIB
ASN.1 fields in order. That comment omits the CHOICE selector bit that
BCCH-BCH-MessageType carries, so every field sits one bit early and a
"spare" bit appears at position 23 where the standard has none. The module's
own selftest pins numbers derived from the same comment, so the decoder and
its expected values share one misreading and the selftest passes. This is the
same failure mode as the SSS seeding bug, in a different stage.

The layout below is written out from the clause text and the published
ASN.1, not transcribed from the module.

The clause
----------
TS 38.331 6.2.1:

    BCCH-BCH-Message ::= SEQUENCE { message BCCH-BCH-MessageType }
    BCCH-BCH-MessageType ::= CHOICE {
        mib                     MIB,
        messageClassExtension   SEQUENCE {}
    }
    MIB ::= SEQUENCE {
        systemFrameNumber       BIT STRING (SIZE (6)),
        subCarrierSpacingCommon ENUMERATED {scs15or60, scs30or120},
        ssb-SubcarrierOffset    INTEGER (0..15),
        dmrs-TypeA-Position     ENUMERATED {pos2, pos3},
        pdcch-ConfigSIB1        PDCCH-ConfigSIB1,
        cellBarred              ENUMERATED {barred, notBarred},
        intraFreqReselection    ENUMERATED {allowed, notAllowed},
        spare                   BIT STRING (SIZE (1))
    }
    PDCCH-ConfigSIB1 ::= SEQUENCE {
        controlResourceSetZero  ControlResourceSetZero,   -- INTEGER (0..15)
        searchSpaceZero         SearchSpaceZero           -- INTEGER (0..15)
    }

The CHOICE selector is 1 bit and is encoded FIRST, before any MIB field.
That makes the 24-bit BCCH-BCH-Message exactly:

    1 (CHOICE) + 6 + 1 + 4 + 1 + 8 + 1 + 1 + 1 = 24 bits

with no padding bit. A layout that needs a padding bit to reach 24 has
dropped the CHOICE selector.

Independence
------------
Three sources that do not share our reading, and do not share each other's:

 1. The ASN.1 above, encoded here from scratch.
 2. py3gpp's TS 38.212 7.1.1 interleaver (nrBCH.py: SFN_PAYLOAD_BEGIN = 1),
    which takes trblk[1..6] as the six SFN MSBs and trblk[0] as "other".
 3. A published decode of a real srsRAN gNB recording, made with asn1tools
    against the TS 38.331 ASN.1 by Daniel Estevez:
        https://destevez.net/2024/12/5g-nr-pbch/
    He states the first bit of the BCCH-BCH-Message UPER encoding is the
    message type and the remaining 23 bits are the MIB, and that the six SFN
    MSBs sit at MIB bits 1..6 with the first bit counted as 0. The MIB he
    decoded is carried below as VECTOR_ESTEVEZ.

Tolerance
---------
None. Every field is an integer slice of a fixed bit string.

Negative control
----------------
tools/check-nr-phy-oracle.sh runs this after the sync check. A --layout
option exists so the negative control can feed the OLD (CHOICE-less) layout
back in and require this comparator to reject it.

Usage:  cmp_nr_mib.py [--module PATH] [--layout choice|legacy] [--quiet]
"""

import argparse
import os
import subprocess
import sys

L = 24

# (name, offset, width) -- offset counts from the MSB of the 24-bit word.
# TS 38.331 6.2.1 field order with the BCCH-BCH-MessageType CHOICE selector
# as bit 0. This is the layout the standard describes.
LAYOUT_CHOICE = [
    ("bcch-bch-messagetype",   0, 1),
    ("systemFrameNumber",      1, 6),
    ("subCarrierSpacingCommon", 7, 1),
    ("ssb-SubcarrierOffset",   8, 4),
    ("dmrs-TypeA-Position",   12, 1),
    ("pdcch-ConfigSIB1",      13, 8),
    ("cellBarred",            21, 1),
    ("intraFreqReselection",  22, 1),
    ("spare",                 23, 1),
]

# The module's layout: no CHOICE selector, SFN at bit 0, and a padding bit
# invented at 23 to reach 24. Kept here so the negative control can prove
# this comparator is able to tell the two apart.
LAYOUT_LEGACY = [
    ("bcch-bch-messagetype", None, 0),
    ("systemFrameNumber",      0, 6),
    ("subCarrierSpacingCommon", 6, 1),
    ("ssb-SubcarrierOffset",   7, 4),
    ("dmrs-TypeA-Position",   11, 1),
    ("pdcch-ConfigSIB1",      12, 8),
    ("cellBarred",            20, 1),
    ("intraFreqReselection",  21, 1),
    ("spare",                 22, 1),
]

# A real MIB from a published decoding of an srsRAN 5G NR downlink recording.
# Estevez reports, for the first decoded MIB:
#   systemFrameNumber (b'\xdc', 6) = 0b110111 = 55
#   subCarrierSpacingCommon 'scs15or60'            -> 0
#   ssb-SubcarrierOffset 8
#   dmrs-TypeA-Position 'pos2'                     -> 0
#   pdcch-ConfigSIB1 {controlResourceSetZero: 0, searchSpaceZero: 0} -> 0
#   cellBarred 'notBarred'                         -> 1
#   intraFreqReselection 'notAllowed'              -> 1
#   spare (b'\x00', 1)                             -> 0
VECTOR_ESTEVEZ = {
    "bcch-bch-messagetype": 0,
    "systemFrameNumber": 55,
    "subCarrierSpacingCommon": 0,
    "ssb-SubcarrierOffset": 8,
    "dmrs-TypeA-Position": 0,
    "pdcch-ConfigSIB1": 0,
    "cellBarred": 1,
    "intraFreqReselection": 1,
    "spare": 0,
}


def bits_to_int(bits, off, width):
    return int(bits[off:off + width], 2) if width else 0


def int_to_bits(value, width):
    return format(value & ((1 << width) - 1), "0%db" % width)


def pack(fields, values, layout):
    """Build the 24-bit word from named field values under a layout."""
    out = ["0"] * L
    for name, off, width in layout:
        if off is None or width == 0:
            continue
        bs = int_to_bits(values[name], width)
        for i, b in enumerate(bs):
            out[off + i] = b
    return "".join(out)


def ref_decode(word_bits, layout):
    return {name: bits_to_int(word_bits, off, width) if off is not None else 0
            for name, off, width in layout}


# ── the module under test ───────────────────────────────────────────────

class Module:
    """Calls nair_decode_mib() by sourcing 12_nr_air.sh in one bash process."""

    SEP = "\x1e"

    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            sys.exit("cmp_nr_mib: module not found: %s" % path)

    def decode_many(self, hexes):
        if not hexes:
            return []
        cases = "\n".join(hexes) + "\n"
        script = (
            'source "$1" </dev/null >/dev/null 2>&1 || exit 9\n'
            'shift\n'
            'while IFS= read -r c; do\n'
            '  [ -z "$c" ] && continue\n'
            '  out=$(nair_decode_mib "$c" 2>/dev/null); rc=$?\n'
            '  printf "%s\\n" "$out"\n'
            '  printf "rc\\t%s\\n" "$rc"\n'
            '  printf "\\036"\n'
            'done\n'
        )
        p = subprocess.run(
            ["bash", "-c", script, "bash", self.path],
            input=cases, capture_output=True, text=True,
        )
        if p.returncode != 0:
            raise RuntimeError(
                "sourcing %s failed (exit %d): %s"
                % (self.path, p.returncode, (p.stderr or "").strip()[:300])
            )
        results = []
        for rec in p.stdout.split(self.SEP):
            if not rec.strip():
                continue
            d = {}
            for line in rec.splitlines():
                if "\t" in line:
                    k, v = line.split("\t", 1)
                    d[k.strip()] = v.strip()
            results.append(d if d else None)
        if len(results) != len(hexes):
            raise RuntimeError(
                "decoder returned %d records for %d payloads"
                % (len(results), len(hexes))
            )
        return results


# Fields the module reports, and how to read a comparable integer out of
# its output. Kept explicit rather than guessed: a field the module does not
# report is a failure to compare, not a pass.
MODULE_FIELD = {
    "systemFrameNumber": ("sfn", None),
    # The module reports this field in kHz, not as the ASN.1 enumeration
    # index. scs15or60 (index 0) and scs30or120 (index 1) each cover two
    # kHz values, so the map is many-to-one and the choice between the two
    # members of a pair is not decidable from the MIB alone.
    "subCarrierSpacingCommon": ("subcarrier_spacing_common",
                                {15: 0, 60: 0, 30: 1, 120: 1}),
    "ssb-SubcarrierOffset": ("ssb_subcarrier_offset", None),
    "dmrs-TypeA-Position": ("dmrs_type_a_position", {"pos2": 0, "pos3": 1}),
    "pdcch-ConfigSIB1": ("pdcch_config_sib1", None),
    "cellBarred": ("cell_barred", {"barred": 0, "notBarred": 1}),
    "intraFreqReselection": ("intra_freq_reselection",
                             {"allowed": 0, "notAllowed": 1}),
    "spare": ("spare", None),
}


def compare(ours, expected, label, quiet):
    """Return a list of human-readable mismatches for one payload."""
    bad = []
    if ours is None:
        return ["%s: the decoder refused a payload the layout says is a MIB"
                % label]
    for name, (key, enum) in MODULE_FIELD.items():
        if key not in ours:
            bad.append("%s %s: the decoder did not report '%s'" % (label, name, key))
            continue
        raw = ours[key]
        if enum is not None:
            # Enum maps here are keyed by the module's own rendering, which
            # may be a name or a number, while the ASN.1 is an index. Accept
            # either spelling of a key.
            key_v = raw
            if key_v not in enum:
                try:
                    key_v = int(raw)
                except ValueError:
                    pass
            if key_v not in enum:
                bad.append("%s %s: decoder said '%s', layout expects %s"
                           % (label, name, raw, expected[name]))
                continue
            got = enum[key_v]
        else:
            try:
                got = int(raw)
            except ValueError:
                bad.append("%s %s: decoder said '%s', not an integer"
                           % (label, name, raw))
                continue
        if got != expected[name]:
            bad.append("%s %s: ours=%d layout=%d" % (label, name, got, expected[name]))
    return bad


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--module", default=None)
    ap.add_argument("--layout", default="choice", choices=("choice", "legacy"),
                    help="reference layout; 'legacy' is the module's own "
                         "CHOICE-less reading and exists for the negative control")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    module_path = args.module or os.path.join(root, "modules", "12_nr_air.sh")
    layout = LAYOUT_CHOICE if args.layout == "choice" else LAYOUT_LEGACY

    mod = Module(module_path)

    print("== NR MIB field offsets vs TS 38.331 6.2.1")
    print("   module : %s" % module_path)
    print("   layout : %s (CHOICE selector %s)"
          % (args.layout,
             "included, bit 0" if args.layout == "choice"
             else "OMITTED -- this is the module's own reading, not the standard"))

    # Payloads to check. Every one is built from a field-value dict and the
    # reference layout, so the payload is derived from the layout rather than
    # from the module's output. The module's output is only ever compared to
    # the layout, never used to generate the expectation.
    vectors = []

    # 1. The published real-world MIB.
    word = pack(layout, VECTOR_ESTEVEZ, layout)
    vectors.append(("published srsRAN MIB (Estevez 2024)", word, VECTOR_ESTEVEZ))

    # 2. A spread of synthetic values, including every field boundary.
    def variant(**over):
        v = dict(VECTOR_ESTEVEZ)
        v.update(over)
        return v

    synth = [
        ("sfn=0", variant(**{"systemFrameNumber": 0})),
        ("sfn=63", variant(**{"systemFrameNumber": 63})),
        ("scs=scs30or120", variant(**{"subCarrierSpacingCommon": 1})),
        ("offset=15", variant(**{"ssb-SubcarrierOffset": 15})),
        ("dmrs=pos3", variant(**{"dmrs-TypeA-Position": 1})),
        ("corset0=15,ss0=15", variant(**{"pdcch-ConfigSIB1": 0xFF})),
        ("cellBarred=barred", variant(**{"cellBarred": 0})),
        ("reselection=allowed", variant(**{"intraFreqReselection": 0})),
        ("spare=1", variant(**{"spare": 1})),
        ("all zero", {k: 0 for k in VECTOR_ESTEVEZ}),
        ("all one", {k: (63 if k == "systemFrameNumber" else 1)
                     for k in VECTOR_ESTEVEZ}),
    ]
    for name, s in synth:
        word = pack(layout, s, layout)
        vectors.append(("synthetic %s" % name, word, s))

    # 3. The CHOICE selector set to 1 -- messageClassExtension, not a MIB.
    #    A correct decoder must not report a systemFrameNumber for it.
    ext = dict(VECTOR_ESTEVEZ)
    ext["bcch-bch-messagetype"] = 1
    if args.layout == "choice":
        vectors.append(("CHOICE=messageClassExtension", pack(layout, ext, layout), ext))

    hexes = ["%06X" % int(word, 2) for _, word, _ in vectors]
    ours_all = mod.decode_many(hexes)

    checks = 0
    mismatches = 0
    for (label, word, expected), ours in zip(vectors, ours_all):
        expected = dict(expected)
        expected.setdefault("bcch-bch-messagetype", 0)
        ours = dict(ours or {})
        rc = 0
        if "rc" in ours:
            try:
                rc = int(ours.pop("rc"))
            except ValueError:
                rc = 0

        if expected["bcch-bch-messagetype"] != 0:
            # Selector 1 is messageClassExtension: an empty SEQUENCE with no
            # systemFrameNumber. The ONLY correct behaviour is to refuse, so
            # a refusal here is agreement, not a mismatch. Requiring the
            # decoder to report fields for it would be requiring it to
            # misread a different message as a MIB.
            if rc == 0:
                bad = ["%s: CHOICE=1 means messageClassExtension, but the "
                       "decoder accepted the payload as a MIB (rc=0, sfn=%s)"
                       % (label, ours.get("sfn"))]
            else:
                bad = []
        elif rc != 0:
            bad = ["%s: the decoder refused a payload that IS a MIB "
                   "(rc=%d, message_type=%s)"
                   % (label, rc, ours.get("message_type", "nothing printed"))]
        else:
            bad = compare(ours, expected, label, args.quiet)

        checks += 1
        if bad:
            mismatches += 1
            print("\n  MISMATCH  %s  payload=%s" % (label, "%06X" % int(word, 2)))
            for b in bad[:10]:
                print("    %s" % b)
            if len(bad) > 10:
                print("    ... and %d more" % (len(bad) - 10))
        elif not args.quiet:
            print("  ok        %s  payload=%s  sfn=%s"
                  % (label, "%06X" % int(word, 2), ours.get("sfn")))

    print("\n  payloads checked: %d" % checks)
    if mismatches:
        print("  MISMATCHES: %d" % mismatches)
        print("\n== the MIB decoder does NOT match TS 38.331 6.2.1")
        return 1
    print("  MISMATCHES: 0")
    print("\n== the MIB decoder matches TS 38.331 6.2.1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
