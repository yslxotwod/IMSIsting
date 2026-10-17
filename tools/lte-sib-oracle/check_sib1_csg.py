#!/usr/bin/env python3
"""Assert our SIB1 cellAccessRelatedInfo against pycrate, CSG fields included.

WHY THIS EXISTS
---------------
`tools/lte_asn1.py`'s SIB1 encoder used to write its csg-Identity presence bit
as `csg_indication and False`, which is a constant: a CSG identity could never
be emitted, and the decoder threw the 27 bits away, so no dump this tree
produced could distinguish "closed cell that names its group" from "closed cell
that only sets the flag". The module's own selftest did not catch it because it
asserted against a layout and a vector derived from the same reading.

So the assertion here is against pycrate 0.8.1 -- an independent TS 36.331
PER implementation -- and the cases are chosen to separate the two CSG fields,
which the ASN.1 makes independent (csg-Indication mandatory, csg-Identity
OPTIONAL).

TWO-SIDED ON PURPOSE
--------------------
A check that passes on a correct implementation is only half a check: the other
half is proving it CAN fail. Before any result is reported, each reintroduced
defect is applied to a scratch copy of the module (never the repository's file)
and the comparator must reject it. If a mutant passes, this script exits 2 and
reports nothing about our code -- a green result under a broken control is the
exact failure this tree keeps re-learning.

Run with the oracle interpreter, the only Python here with pycrate:

    /home/ysl/.lte-oracles/venv/bin/python tools/lte-sib-oracle/check_sib1_csg.py

Exit 0 when every case agrees and every mutant is caught, 1 on a disagreement,
2 when the control itself failed or pycrate is missing.
"""

import copy
import importlib.util
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
MODULE = os.path.join(REPO, "tools", "lte_asn1.py")

# (label, csg-Indication, csg-Identity or None)
CASES = [
    ("plain",                    False, None),
    ("flag only",                True,  None),
    ("identity, flag clear",     False, 0x1234567),
    ("identity, flag set",       True,  0x1234567),
    ("identity zero",            True,  0),
    ("identity max",             True,  (1 << 27) - 1),
]

# (label, old text, new text). Each is a defect this file exists to catch.
MUTANTS = [
    ("presence bit forced off",
     "w.bit(csg_identity is not None)",
     "w.bit(False)"),
    ("presence bit forced on",
     "w.bit(csg_identity is not None)",
     "w.bit(True)"),
    ("identity width 26 not 27",
     "w.uint(csg_identity, 27)",
     "w.uint(csg_identity, 26)"),
]


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pycrate_bits(obj):
    out, n = "", 0
    for _t, v, bl in obj._to_per():
        if isinstance(v, int):
            out += format(v, "0%db" % bl)
        elif isinstance(v, bytes):
            out += "".join(format(b, "08b") for b in v)[:bl]
        else:
            out += str(v)
        n += bl
    return out, n


def pycrate_value(indication, identity):
    car = {
        "plmn-IdentityList": [
            {"plmn-Identity": {"mcc": [0, 0, 1], "mnc": [0, 1]},
             "cellReservedForOperatorUse": "notReserved"},
        ],
        "trackingAreaCode": (0x00F1, 16),
        "cellIdentity": (0x00A1, 28),
        "cellBarred": "notBarred",
        "intraFreqReselection": "notAllowed",
        "csg-Indication": bool(indication),
    }
    if identity is not None:
        car["csg-Identity"] = (identity, 27)
    return {
        "message": ("c1", ("systemInformationBlockType1", {
            "cellAccessRelatedInfo": car,
            "cellSelectionInfo": {"q-RxLevMin": -70},
            "freqBandIndicator": 20,
            "schedulingInfoList": [
                {"si-Periodicity": "rf32",
                 "sib-MappingInfo": ["sibType3"]},
            ],
            "si-WindowLength": "ms20",
            "systemInfoValueTag": 0,
        })),
    }


def mismatches(mod, M):
    """Return [(label, detail)] for every case where our bits differ."""
    out = []
    for label, ind, cid in CASES:
        obj = copy.deepcopy(getattr(M, "BCCH_DL_SCH_Message"))
        obj.set_val(pycrate_value(ind, cid))
        want, wbits = pycrate_bits(obj)
        try:
            got = mod.encode_sib1([0, 0, 1], [0, 1], 0x00F1, 0x00A1,
                                  barred="notBarred", reselect="notAllowed",
                                  qrxlevmin=-70, band=20, siw="ms20",
                                  valuetag=0, period="rf32",
                                  sibs=("sibType3",),
                                  csg_indication=ind, csg_identity=cid).string()
        except Exception as exc:
            out.append((label, "encode raised %s: %s"
                        % (type(exc).__name__, exc)))
            continue
        if got != want:
            first = next((i for i in range(min(len(got), len(want)))
                          if got[i] != want[i]), min(len(got), len(want)))
            out.append((label, "bit %d of %d (ours %d bits, pycrate %d)"
                        % (first, wbits, len(got), len(want))))
    return out


def main():
    try:
        from pycrate_asn1dir import RRCLTE
    except ImportError:
        sys.stderr.write(
            "this check needs pycrate; run it with the oracle interpreter:\n"
            "  /home/ysl/.lte-oracles/venv/bin/python %s\n"
            % os.path.relpath(__file__))
        return 2
    M = RRCLTE.EUTRA_RRC_Definitions

    # ---- control: the unmutated module must PASS -------------------------
    bad = mismatches(load_module(MODULE, "sib1_true"), M)
    if bad:
        sys.stderr.write(
            "NEGCTL-SIB1CSG: the comparator rejects the TRUE module, so a\n"
            "failure below would say nothing about our code:\n")
        for label, detail in bad:
            sys.stderr.write("  %-24s %s\n" % (label, detail))
        return 2
    print("PRECHECK ok: the comparator passes the module unmodified")

    # ---- control: each reintroduced defect must FAIL ---------------------
    source = open(MODULE, "r", encoding="utf-8").read()
    caught = 0
    for label, old, new in MUTANTS:
        if old not in source:
            sys.stderr.write(
                "NEGCTL-SIB1CSG: mutation anchor %r is not in %s -- the\n"
                "control cannot run, so no result is reported\n"
                % (old, os.path.relpath(MODULE, REPO)))
            return 2
        tmpdir = tempfile.mkdtemp(prefix="sib1csg-")
        try:
            path = os.path.join(tmpdir, "lte_asn1_mut.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(source.replace(old, new, 1))
            got = mismatches(load_module(path, "sib1_mut"), M)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        if not got:
            sys.stderr.write(
                "NEGCTL-SIB1CSG: mutation %r was NOT caught -- the\n"
                "comparator cannot detect it, so its green result means\n"
                "nothing. No result reported.\n" % label)
            return 2
        print("  caught  %-26s %d case(s) disagree, first: %s"
              % (label, len(got), got[0][1]))
        caught += 1

    if caught != len(MUTANTS):
        sys.stderr.write("NEGCTL-SIB1CSG: %d of %d mutations ran\n"
                         % (caught, len(MUTANTS)))
        return 2
    print("NEGCTL-SIB1CSG: the comparator passes the true module and "
          "rejects all %d reintroduced defects" % len(MUTANTS))

    print("cases checked: %d   MISMATCHES: 0" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
