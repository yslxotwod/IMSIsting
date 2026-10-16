#!/usr/bin/env python3
"""Hand-built differential check for SIB9 to SIB13.

`tools/lte-per-oracle/verify_per.py` generates values at random from pycrate's
object graph, which is the right default: random values reach corners -- a list
at its maximum size, an integer on its bound, an extension present on its own --
that nobody writes by hand. But its generator cannot yet build a value pycrate
will accept for every type, and for those types it silently reports zero cases.
A type with zero cases is unverified, and reading that as a pass is the failure
mode this tree keeps re-learning.

This script covers that gap for SIB9 to SIB13 by constructing the values
explicitly and making the same assertion: our bits must equal pycrate's bits for
the identical value, and decoding our bits must re-encode to the same bits.

Explicit values are weaker than random ones in exactly one way -- they cannot
find a corner nobody thought of -- so this is a supplement to the random harness
and not a replacement for it. It states how many cases it skipped rather than
quietly counting them as passes.

Run it with the oracle interpreter, which is the only Python here with pycrate:

    /home/ysl/.lte-oracles/venv/bin/python \\
        tools/lte-sib-oracle/handcheck_sib913.py --table <generated layout>

Exit 0 when every case agrees, 1 on any disagreement, 2 if it could not set up.
"""

import argparse
import copy
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

# (pycrate attribute, root name in the generated table, value)
#
# The pycrate attribute and the table's root name differ for SIB12 and SIB13:
# pycrate carries them only under their Rel-9 names, and the generator
# normalises the hyphen to an underscore for a Python identifier. Inside a
# value, though, the keys keep pycrate's own spelling with the hyphen, because
# that spelling is what the ASN.1 says.
CASES = [
    # SIB9 -- the home eNodeB name, TS 36.331 6.3.1. 64 bits is an 8-byte name,
    # 392 bits the maximum.
    ("SystemInformationBlockType9", "SystemInformationBlockType9", {
        "hnb-Name": b"\x01\x02\x03\x04\x05\x06\x07"}),
    ("SystemInformationBlockType9", "SystemInformationBlockType9", {
        "hnb-Name": bytes(range(48))}),

    # SIB10 -- ETWS primary notification. warningType is a fixed two octets.
    ("SystemInformationBlockType10", "SystemInformationBlockType10", {
        "messageIdentifier": (0xBEEF, 16),
        "serialNumber": (0x1234, 16),
        "warningType": b"\x11\x22"}),
    ("SystemInformationBlockType10", "SystemInformationBlockType10", {
        "messageIdentifier": (0xFFFF, 16),
        "serialNumber": (0xFFFF, 16),
        "warningType": b"\xFF\xFF",
        "dummy": bytes(range(50))}),

    # SIB11 -- ETWS secondary notification, segmented.
    ("SystemInformationBlockType11", "SystemInformationBlockType11", {
        "messageIdentifier": (0x1234, 16),
        "serialNumber": (0x5678, 16),
        "warningMessageSegmentType": "notLastSegment",
        "warningMessageSegmentNumber": 0,
        "warningMessageSegment": b"\xDE\xAD\xBE\xEF"}),
    ("SystemInformationBlockType11", "SystemInformationBlockType11", {
        "messageIdentifier": (0xABCD, 16),
        "serialNumber": (0x0001, 16),
        "warningMessageSegmentType": "lastSegment",
        "warningMessageSegmentNumber": 63,
        "warningMessageSegment": b"\x00",
        "dataCodingScheme": b"\x01"}),

    # SIB12-r9 -- CMAS. This is the message whose fields SIB8's decoder used to
    # print under SIB8's name, so it is worth having real vectors for.
    ("SystemInformationBlockType12_r9", "SystemInformationBlockType12_r9", {
        "messageIdentifier-r9": (0x4370, 16),
        "serialNumber-r9": (0x1111, 16),
        "warningMessageSegmentType-r9": "notLastSegment",
        "warningMessageSegmentNumber-r9": 0,
        "warningMessageSegment-r9": b"\x90\x00\x3C"}),
    ("SystemInformationBlockType12_r9", "SystemInformationBlockType12_r9", {
        "messageIdentifier-r9": (0x1112, 16),
        "serialNumber-r9": (0x2222, 16),
        "warningMessageSegmentType-r9": "lastSegment",
        "warningMessageSegmentNumber-r9": 63,
        "warningMessageSegment-r9": b"\xFF\x00\x01\x02\x03",
        "dataCodingScheme-r9": b"\x01"}),

    # SIB13-r9 -- MBSFN. The list is constrained to 1..8, so the second case
    # carries two entries rather than one: a codec that mishandles the list
    # count agrees on a single-element list.
    ("SystemInformationBlockType13_r9", "SystemInformationBlockType13_r9", {
        "mbsfn-AreaInfoList-r9": [{
            "mbsfn-AreaId-r9": 0,
            "non-MBSFNregionLength": "s1",
            "notificationIndicator-r9": 0,
            "mcch-Config-r9": {
                "mcch-RepetitionPeriod-r9": "rf32",
                "mcch-Offset-r9": 0,
                "mcch-ModificationPeriod-r9": "rf512",
                "sf-AllocInfo-r9": (0b100000, 6),
                "signallingMCS-r9": "n2"}}],
        "notificationConfig-r9": {
            "notificationRepetitionCoeff-r9": "n2",
            "notificationOffset-r9": 0,
            "notificationSF-Index-r9": 1}}),
    ("SystemInformationBlockType13_r9", "SystemInformationBlockType13_r9", {
        "mbsfn-AreaInfoList-r9": [
            {"mbsfn-AreaId-r9": 255,
             "non-MBSFNregionLength": "s2",
             "notificationIndicator-r9": 7,
             "mcch-Config-r9": {
                 "mcch-RepetitionPeriod-r9": "rf256",
                 "mcch-Offset-r9": 10,
                 "mcch-ModificationPeriod-r9": "rf1024",
                 "sf-AllocInfo-r9": (0b111111, 6),
                 "signallingMCS-r9": "n19"}},
            {"mbsfn-AreaId-r9": 1,
             "non-MBSFNregionLength": "s1",
             "notificationIndicator-r9": 3,
             "mcch-Config-r9": {
                 "mcch-RepetitionPeriod-r9": "rf64",
                 "mcch-Offset-r9": 5,
                 "mcch-ModificationPeriod-r9": "rf512",
                 "sf-AllocInfo-r9": (0b000001, 6),
                 "signallingMCS-r9": "n7"}}],
        "notificationConfig-r9": {
            "notificationRepetitionCoeff-r9": "n4",
            "notificationOffset-r9": 10,
            "notificationSF-Index-r9": 6}}),
]


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pycrate_bits(obj):
    """The oracle's own bit string, built from its unaligned-PER encoder."""
    out = ""
    n = 0
    for _t, v, bl in obj._to_per():
        if isinstance(v, int):
            out += format(v, "0%db" % bl)
        elif isinstance(v, bytes):
            out += "".join(format(b, "08b") for b in v)[:bl]
        else:
            out += str(v)
        n += bl
    return out, n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--table", required=True,
                    help="generated layout table (tools/asn1gen.py --out ...)")
    ap.add_argument("--per", default=os.path.join(REPO, "tools", "lte_per.py"),
                    help="the PER engine to test")
    args = ap.parse_args(argv)

    try:
        from pycrate_asn1dir import RRCLTE
    except ImportError:
        sys.stderr.write(
            "this check needs pycrate; run it with the oracle interpreter:\n"
            "  /home/ysl/.lte-oracles/venv/bin/python %s --table ...\n"
            % os.path.relpath(__file__))
        return 2

    per = load_module(os.path.abspath(args.per), "lte_per")
    tbl = load_module(os.path.abspath(args.table), "lte_rrc_layout")
    codec = per.codec_from_module(tbl)
    M = RRCLTE.EUTRA_RRC_Definitions

    ok = bad = skip = 0
    for attr, root, val in CASES:
        obj = copy.deepcopy(getattr(M, attr))
        try:
            obj.set_val(val)
        except Exception as exc:
            print("  SKIP  %-28s pycrate rejected the value: %s" % (attr, exc))
            skip += 1
            continue
        want, wbits = pycrate_bits(obj)
        try:
            got = codec.encode_bits(root, val)
        except Exception as exc:
            print("  FAIL  %-28s encode raised %s" % (attr, exc))
            bad += 1
            continue
        if got != want:
            first = next((i for i in range(min(len(got), len(want)))
                          if got[i] != want[i]), min(len(got), len(want)))
            print("  FAIL  %-28s bit %d of %d\n        pycrate %s\n        ours    %s"
                  % (attr, first, wbits, want, got))
            bad += 1
            continue
        try:
            back = codec.decode_bits(root, want)
            again = codec.encode_bits(root, back)
        except Exception as exc:
            print("  FAIL  %-28s decode raised %s" % (attr, exc))
            bad += 1
            continue
        if again != want:
            print("  FAIL  %-28s round-trip differs\n        want  %s\n        again %s"
                  % (attr, want, again))
            bad += 1
            continue
        print("  ok    %-28s %4d bits" % (attr, wbits))
        ok += 1

    print()
    print("agree %d  disagree %d  skipped %d" % (ok, bad, skip))
    if skip:
        # A skipped case is a case that was not checked. Say so loudly rather
        # than letting the summary read as full coverage.
        print("(%d case(s) were not checked at all -- fix the value above, "
              "do not read this as a pass)" % skip)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
