#!/usr/bin/env python3
"""Independent verification of tools/lte_rrc.py against pycrate 0.8.1.

Why this file exists
--------------------
`tools/lte_rrc.py` claims two things that this tree's own output cannot
corroborate: that the messages it builds encode the same bits as the
specification does, and that the value an operator writes down survives into the
built message unchanged.  The second claim is the interesting one -- the generic
engine underneath was already shown to agree with pycrate bit for bit on random
values (`tools/lte-per-oracle/verify_per.py`), so what is left to prove is that
this builder's *field-level semantics* are right: that the target cell id an
operator typed is the target cell id on the air, in the field it belongs in.

So every check here feeds one intended message to two independent encoders --
`tools/lte_rrc.py` and pycrate -- and compares:

  1. bits   -- both encoders produce identical bits for the same input value;
  2. read   -- pycrate *decodes* our bits and reports exactly the value we meant
               (a whole-message structural comparison, then named fields);
  3. keep   -- the component names present in the built value are exactly those
               the operator set, so nothing was silently dropped or invented;
  4. turn   -- encode -> decode -> re-encode is bit-identical, on both codecs;
  5. box    -- the HandoverCommand container's DL-DCCH envelope and its
               unconstrained OCTET STRING length determinant agree with pycrate;
  6. refuse -- the CLI exits non-zero, with a REFUSED line, for values this tree
               will not encode.

Two of the messages are fully populated (every modelled OPTIONAL present) and one
is minimal, because the maximally-populated case is where a PER codec breaks.

What this does NOT cover, stated plainly:
  * any message field `tools/lte_rrc.py` refuses (the v890/v920/v1020
    nonCriticalExtension chain, every extension addition, the RLC UM bearers,
    physicalConfigDedicated, drx-Config, phr-Config, the UTRA/GERAN/CDMA2000
    measurement objects) -- those are never built, so they are never compared;
  * the ON-AIR behaviour of the message: this compares encoders, not a UE;
  * pycrate's own correctness against TS 36.331.  pycrate is the independent
    implementation here; if it is wrong, both encoders are wrong together.

Run with the oracle interpreter, which is the only Python here with pycrate:
    /home/ysl/.lte-oracles/venv/bin/python tools/lte-rrc-oracle/verify_rrc.py

Exit codes: 0 every check agreed; 1 at least one disagreed; 2 could not set up.
"""

import argparse
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
REPO = os.path.dirname(TOOLS)
ORACLE_PY = "/home/ysl/.lte-oracles/venv/bin/python"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod          # so lte_rrc's own imports find these files
    spec.loader.exec_module(mod)
    return mod


try:
    from pycrate_asn1dir import RRCLTE
except ImportError:                                       # pragma: no cover
    sys.stderr.write(
        "pycrate is not importable here, so there is no independent "
        "implementation to compare against.\nRun this with the oracle "
        "interpreter:\n  %s %s\n" % (ORACLE_PY, os.path.relpath(__file__)))
    sys.exit(2)

RRC = RRCLTE.EUTRA_RRC_Definitions
INTER = RRCLTE.EUTRA_InterNodeDefinitions


# --------------------------------------------------------------------------
# The two encoders, side by side.
# --------------------------------------------------------------------------

def pycrate_bits(module, typename, value):
    """(bits, bit length) pycrate produces for `value`, at the true bit length.

    The copy matters: pycrate's unaligned-PER encoder deletes a component whose
    value equals its DEFAULT straight out of the dict it was handed
    (asnobj_construct.py:1020, `del self._val[ident]`, on the caller's own
    object), so handing it a case's value would leave that case quietly missing
    a field for every later check.
    """
    obj = copy.deepcopy(getattr(module, typename))
    obj.set_val(copy.deepcopy(value))
    out = ""
    for _t, v, bl in obj._to_per():
        if isinstance(v, int):
            out += format(v, "0%db" % bl)
        elif isinstance(v, bytes):
            out += "".join(format(b, "08b") for b in v)[:bl]
        else:
            out += str(v)
    return out, len(out)


def pycrate_decode(module, typename, bits):
    """pycrate's reading of `bits`, in the same value shapes lte_per uses."""
    obj = copy.deepcopy(getattr(module, typename))
    padded = bits + "0" * (-len(bits) % 8)
    obj.from_uper(bytes(int(padded[i:i + 8], 2) for i in range(0, len(padded), 8)))
    return obj.get_val()


def dig(value, path):
    """Follow a dotted path through a built or decoded value."""
    for part in path.split("."):
        if isinstance(value, dict):
            if part not in value:
                raise KeyError("no component %r in %s" % (part, sorted(value)))
            value = value[part]
        elif isinstance(value, (tuple, list)) and len(value) == 2 and \
                isinstance(value[0], str):
            if value[0] != part:
                raise KeyError("alternative is %r, not %r" % (value[0], part))
            value = value[1]
        elif isinstance(value, (tuple, list)):
            value = value[int(part)]
        else:
            raise KeyError("cannot descend into %r looking for %r" % (value, part))
    return value


def flat(value):
    """Values as JSON-comparable atoms (bytes as hex, tuples as lists)."""
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [flat(v) for v in value]
    if isinstance(value, dict):
        return dict((k, flat(v)) for k, v in value.items())
    return value


def keys_at(value, path):
    """The component names present at a path, so a silent drop cannot hide."""
    if path:
        value = dig(value, path)
    if isinstance(value, dict):
        return set(value)
    raise AssertionError("%s is not a SEQUENCE (%r)" % (path or "<root>", type(value)))


def missing_optionals(lte_rrc, spec, node, value, path, out):
    """Every modelled OPTIONAL/DEFAULT a value left unset, walked through views."""
    if spec[0] == "ref":
        return missing_optionals(lte_rrc, lte_rrc.VIEWS[spec[1]],
                                 lte_rrc.TYPES[spec[1]], value, path, out)
    while node["k"] == "ref":
        node = lte_rrc.TYPES[node["t"]]
    if node["k"] == "seq" and spec[0] == "seq":
        for name, cnode, optional, default in node["comp"]:
            if name not in spec[1]:
                continue
            if (optional or default is not None) and name not in value:
                out.append("%s.%s" % (path, name))
            if name in value:
                missing_optionals(lte_rrc, spec[1][name], cnode, value[name],
                                  "%s.%s" % (path, name), out)
    elif node["k"] == "choice" and spec[0] == "choice":
        alts = dict((a[0], a[1]) for a in node["alts"])
        missing_optionals(lte_rrc, spec[1][value[0]], alts[value[0]], value[1],
                          "%s.%s" % (path, value[0]), out)
    elif node["k"] == "seqof" and spec[0] == "seqof":
        for i, item in enumerate(value):
            missing_optionals(lte_rrc, spec[1], node["of"], item,
                              "%s[%d]" % (path, i), out)


# --------------------------------------------------------------------------
# The messages under test.
#
# The `minimal` and `full` fixtures come from tools/lte_rrc.py on purpose: the
# point of the comparison is the *encoding* of an identical input value.  The
# third case is written out here instead, so at least one message is stated
# entirely outside the tool it tests.
# --------------------------------------------------------------------------

NAMED_IES = {
    "transaction_identifier": 2,
    "mobilityControlInfo": {
        "targetPhysCellId": 7,
        "carrierFreq": {"dl-CarrierFreq": 6300},
        "t304": "ms200",
        "newUE-Identity": "0x1234",
        "radioResourceConfigCommon": {
            "prach-Config": {"rootSequenceIndex": 1},
            "pusch-ConfigCommon": {
                "pusch-ConfigBasic": {
                    "n-SB": 2,
                    "hoppingMode": "intraAndInterSubFrame",
                    "pusch-HoppingOffset": 4,
                    "enable64QAM": True,
                },
                "ul-ReferenceSignalsPUSCH": {
                    "groupHoppingEnabled": True,
                    "groupAssignmentPUSCH": 3,
                    "sequenceHoppingEnabled": False,
                    "cyclicShift": 5,
                },
            },
            "ul-CyclicPrefixLength": "len2",
        },
        "rach-ConfigDedicated": {"ra-PreambleIndex": 3, "ra-PRACH-MaskIndex": 1},
    },
    "securityConfigHO": {"handoverType": {"intraLTE": {
        "keyChangeIndicator": False,
        "nextHopChainingCount": 1,
    }}},
}

# What each message must say once pycrate has read our bits back.  These are the
# fields an operator actually sets for a handover, spelled as ASN.1 paths.
EXPECT = {
    "reconfiguration/minimal": [
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.targetPhysCellId", 42),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.t304", "ms500"),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.newUE-Identity", [60, 16]),
        ("rrc-TransactionIdentifier", 1),
    ],
    "reconfiguration/full": [
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.targetPhysCellId", 42),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.carrierFreq.dl-CarrierFreq", 1650),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.carrierBandwidth.ul-Bandwidth", "n100"),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.additionalSpectrumEmission", 1),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.rach-ConfigDedicated.ra-PreambleIndex", 12),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "securityConfigHO.handoverType.intraLTE.nextHopChainingCount", 3),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "securityConfigHO.handoverType.intraLTE.keyChangeIndicator", True),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "measConfig.measObjectToRemoveList.0", 2),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "measConfig.measObjectToAddModList.0.measObject.measObjectEUTRA."
         "cellsToRemoveList.0", 2),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "measConfig.reportConfigToRemoveList.0", 2),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "measConfig.measIdToRemoveList.0", 2),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "measConfig.measIdToAddModList.0.measId", 1),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "measConfig.reportConfigToAddModList.0.reportConfig.reportConfigEUTRA."
         "triggerType.event.eventId.eventA3.a3-Offset", 4),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "radioResourceConfigDedicated.srb-ToAddModList.0.rlc-Config."
         "explicitValue.am.ul-AM-RLC.pollPDU", "p8"),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "radioResourceConfigDedicated.drb-ToReleaseList.0", 3),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "dedicatedInfoNASList.0", "0x0102030405"),
    ],
    "reconfiguration/named": [
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.targetPhysCellId", 7),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.t304", "ms200"),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.newUE-Identity", [0x1234, 16]),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.radioResourceConfigCommon.prach-Config."
         "rootSequenceIndex", 1),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "mobilityControlInfo.radioResourceConfigCommon.pusch-ConfigCommon."
         "pusch-ConfigBasic.n-SB", 2),
        ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
         "securityConfigHO.handoverType.intraLTE.keyChangeIndicator", False),
        ("rrc-TransactionIdentifier", 2),
    ],
}

# The component names each case's operator wrote, so "nothing was dropped" is
# checked against the operator's own words rather than against the encoder.
KEEP = {
    "minimal": [("", {"rrc-TransactionIdentifier", "criticalExtensions"}),
                ("criticalExtensions.c1.rrcConnectionReconfiguration-r8",
                 {"mobilityControlInfo"}),
                ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
                 "mobilityControlInfo",
                 {"targetPhysCellId", "t304", "newUE-Identity",
                  "radioResourceConfigCommon"})],
    "full": [("criticalExtensions.c1.rrcConnectionReconfiguration-r8",
              {"measConfig", "mobilityControlInfo", "dedicatedInfoNASList",
               "radioResourceConfigDedicated", "securityConfigHO"}),
             ("criticalExtensions.c1.rrcConnectionReconfiguration-r8.measConfig",
              {"measObjectToRemoveList", "measObjectToAddModList",
               "reportConfigToRemoveList", "reportConfigToAddModList",
               "measIdToRemoveList", "measIdToAddModList", "quantityConfig",
               "measGapConfig", "s-Measure"}),
             ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
              "mobilityControlInfo",
              {"targetPhysCellId", "carrierFreq", "carrierBandwidth",
               "additionalSpectrumEmission", "t304", "newUE-Identity",
               "radioResourceConfigCommon", "rach-ConfigDedicated"}),
             ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
              "radioResourceConfigDedicated",
              {"srb-ToAddModList", "drb-ToReleaseList", "mac-MainConfig"})],
    "named": [("criticalExtensions.c1.rrcConnectionReconfiguration-r8",
               {"mobilityControlInfo", "securityConfigHO"}),
              ("criticalExtensions.c1.rrcConnectionReconfiguration-r8."
               "mobilityControlInfo",
               {"targetPhysCellId", "carrierFreq", "t304", "newUE-Identity",
                "radioResourceConfigCommon", "rach-ConfigDedicated"})],
}


def build_cases(lte_rrc):
    """[(name, parts, built reconfiguration value)] in the order they run."""
    out = []
    for case in lte_rrc.CASES:
        ies = lte_rrc.case_ies(case)
        out.append(("reconfiguration/%s" % case, case,
                    lte_rrc.reconfiguration(**ies)))
    out.append(("reconfiguration/named", "named",
                lte_rrc.reconfiguration(**copy.deepcopy(NAMED_IES))))
    return out


# --------------------------------------------------------------------------
# Checks.
# --------------------------------------------------------------------------

class Report(object):
    def __init__(self):
        self.failures = []
        self.n = 0

    def check(self, name, fn):
        self.n += 1
        try:
            detail = fn()
        except Exception as exc:                           # noqa: BLE001
            message = "%s: %s" % (type(exc).__name__, exc)
            self.failures.append("%s: %s" % (name, message))
            print("MISMATCH %s\n         %s" % (name, message))
            return
        print("ok       %-44s %s" % (name, detail or ""))
        return detail


def run_checks(lte_rrc, report, verbose):
    cases = build_cases(lte_rrc)

    def bits_agree(name, built, typename, module, py_name=None):
        def fn():
            mine = lte_rrc.CODEC.encode_bits(typename, built)
            want, n = pycrate_bits(module, py_name or typename, built)
            if mine != want:
                first = next((i for i in range(min(len(mine), len(want)))
                              if mine[i] != want[i]), min(len(mine), len(want)))
                raise AssertionError(
                    "bits differ at %d (pycrate %d bits, ours %d)\n"
                    "    want=%s\n    got =%s"
                    % (first, len(want), len(mine), want, mine))
            return "%d bits, identical" % len(mine)
        return fn

    def reads_back(name, built, typename, module, py_name=None):
        def fn():
            mine = lte_rrc.CODEC.encode_bits(typename, built)
            got = pycrate_decode(module, py_name or typename, mine)
            diffs = lte_rrc.compare_message(typename, built, got)
            if diffs:
                raise AssertionError("pycrate read back a different message: %s"
                                     % "; ".join(diffs))
            return "pycrate re-reads it identically"
        return fn

    def named_fields(name, built, typename, module, py_name=None):
        def fn():
            mine = lte_rrc.CODEC.encode_bits(typename, built)
            got = pycrate_decode(module, py_name or typename, mine)
            bad = []
            for path, want in EXPECT[name]:
                try:
                    have = flat(dig(got, path))
                except Exception as exc:                   # noqa: BLE001
                    bad.append("%s: %s" % (path, exc))
                    continue
                if have != flat(want):
                    bad.append("%s: sent %r, pycrate read %r" % (path, want, have))
            if bad:
                raise AssertionError("; ".join(bad))
            return "%d operator fields verified" % len(EXPECT[name])
        return fn

    def keeps(name, part, built, typename, module, py_name=None):
        def fn():
            for path, want in KEEP[part]:
                have = keys_at(built, path)
                if have != want:
                    raise AssertionError(
                        "%s present %s, operator wrote %s"
                        % (path or "<root>", sorted(have), sorted(want)))
            return "no component dropped or invented"
        return fn

    def round_trips(name, built, typename, module, py_name=None):
        def fn():
            mine = lte_rrc.CODEC.encode_bits(typename, built)
            back, n = lte_rrc.decode_bits(typename, mine)
            if n != len(mine):
                raise AssertionError("our decode used %d of %d bits" % (n, len(mine)))
            again = lte_rrc.CODEC.encode_bits(typename, back)
            if again != mine:
                raise AssertionError("re-encoding our decode moved a bit")
            obj = copy.deepcopy(getattr(module, py_name or typename))
            padded = mine + "0" * (-len(mine) % 8)
            obj.from_uper(bytes(int(padded[i:i + 8], 2)
                                for i in range(0, len(padded), 8)))
            if obj.to_uper().hex().upper() != lte_rrc.CODEC.encode_hex(typename, built):
                raise AssertionError("pycrate re-encoding our bits differs")
            return "ours and pycrate's both re-encode to the same bits"
        return fn

    # ---- the "full" case must really be maximal ---------------------------
    def full_is_maximal():
        value = lte_rrc.reconfiguration_case("full")
        out = []
        missing_optionals(lte_rrc, lte_rrc.VIEWS["RRCConnectionReconfiguration"],
                          lte_rrc.TYPES["RRCConnectionReconfiguration"],
                          value, "", out)
        if out:
            raise AssertionError(
                "the fully-populated case leaves %d modelled OPTIONAL(s) unset, "
                "so it is not the maximal case: %s" % (len(out), ", ".join(out)))
        return "every modelled OPTIONAL and DEFAULT is present"
    report.check("full case is maximal", full_is_maximal)

    # ---- the reconfigurations ------------------------------------------
    for name, part, built in cases:
        report.check("%s bits" % name,
                     bits_agree(name, built, "RRCConnectionReconfiguration", RRC))
        report.check("%s pycrate reads it back" % name,
                     reads_back(name, built, "RRCConnectionReconfiguration", RRC))
        report.check("%s operator fields" % name,
                     named_fields(name, built, "RRCConnectionReconfiguration", RRC))
        report.check("%s nothing dropped" % name,
                     keeps(name, part, built, "RRCConnectionReconfiguration", RRC))
        report.check("%s round trip" % name,
                     round_trips(name, built, "RRCConnectionReconfiguration", RRC))

    # ---- the same reconfigurations, inside a HandoverCommand -------------
    for name, part, built in cases:
        cmd = lte_rrc.handover_command(built)
        report.check("%s handover bits" % name,
                     bits_agree(name, cmd, "HandoverCommand", INTER))
        report.check("%s handover round trip" % name,
                     round_trips(name, cmd, "HandoverCommand", INTER))

        def container(name=name, built=built):
            inner = lte_rrc.CODEC.encode_bits("RRCConnectionReconfiguration", built)
            cmd = lte_rrc.handover_command(built)
            box = cmd["criticalExtensions"][1][1]["handoverCommandMessage"]
            bits = "".join(format(b, "08b") for b in box)
            if not bits.startswith(lte_rrc.DL_DCCH_PREFIX):
                raise AssertionError("container lacks the DL-DCCH envelope")
            body = bits[len(lte_rrc.DL_DCCH_PREFIX):]
            if body[:len(inner)] != inner:
                raise AssertionError("container does not carry our reconfiguration")
            if set(body[len(inner):]) - {"0"}:
                raise AssertionError("container padding is not zero")

            # The envelope itself, straight from pycrate's DL-DCCH-Message.
            dl = {"message": ("c1", ("rrcConnectionReconfiguration", built))}
            want, n = pycrate_bits(RRC, "DL_DCCH_Message", dl)
            mine = bits[:n]
            if mine != want:
                raise AssertionError(
                    "DL-DCCH envelope differs (pycrate %d bits, ours %d)\n"
                    "    want=%s\n    got =%s" % (len(want), n, want, mine))
            if n != 5 + len(inner):
                raise AssertionError("pycrate's DL-DCCH body is %d bits, ours %d"
                                     % (n - 5, len(inner)))
            # And pycrate must accept our container bytes as a DL-DCCH-Message.
            back = pycrate_decode(RRC, "DL_DCCH_Message", mine)
            if flat(dig(back, "message.c1.rrcConnectionReconfiguration")) != flat(built):
                raise AssertionError("pycrate read a different body out of the "
                                     "container")
            return "envelope %s + %d bits, pycrate-identical, box %d bytes" % (
                lte_rrc.DL_DCCH_PREFIX, len(inner), len(box))
        report.check("%s DL-DCCH container" % name, container)

    # ---- the CLI must refuse, and say so ---------------------------------
    def cli_refusals():
        cases = [
            ("transaction identifier out of range",
             ["reconfiguration", "--tx", "4"]),
            ("phys cell id out of range",
             ["reconfiguration", "--tx", "1", "--set",
              "mobilityControlInfo.targetPhysCellId=999",
              "--set", "mobilityControlInfo.t304=ms500",
              "--set", "mobilityControlInfo.newUE-Identity=1",
              "--set", "mobilityControlInfo.radioResourceConfigCommon.prach-Config."
                       "rootSequenceIndex=1",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.pusch-ConfigBasic.n-SB=1",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.pusch-ConfigBasic.hoppingMode=interSubFrame",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.pusch-ConfigBasic.pusch-HoppingOffset=0",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.pusch-ConfigBasic.enable64QAM=false",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.ul-ReferenceSignalsPUSCH."
                       "groupHoppingEnabled=false",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.ul-ReferenceSignalsPUSCH."
                       "groupAssignmentPUSCH=0",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.ul-ReferenceSignalsPUSCH."
                       "sequenceHoppingEnabled=false",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "pusch-ConfigCommon.ul-ReferenceSignalsPUSCH.cyclicShift=0",
              "--set", "mobilityControlInfo.radioResourceConfigCommon."
                       "ul-CyclicPrefixLength=len1"]),
            ("enum name the table does not have",
             ["reconfiguration", "--tx", "1", "--set",
              "mobilityControlInfo.t304=ms501"]),
            ("component this tree does not model",
             ["reconfiguration", "--tx", "1", "--set",
              "nonCriticalExtension.lateNonCriticalExtension=0011"]),
        ]
        bad = []
        for why, argv in cases:
            proc = subprocess.run([sys.executable, os.path.join(TOOLS, "lte_rrc.py")]
                                  + argv, capture_output=True, text=True)
            if proc.returncode == 0:
                bad.append("%s: exit 0 (should refuse)" % why)
            elif "REFUSED" not in proc.stderr:
                bad.append("%s: exit %d without a REFUSED line (%r)"
                           % (why, proc.returncode, proc.stderr.strip()[:80]))
        if bad:
            raise AssertionError("; ".join(bad))
        return "%d refusals exit non-zero with a REFUSED line" % len(cases)
    report.check("CLI refusals", cli_refusals)

    # ---- unmapped paths: the JSON path into an extension addition --------
    def extension_addition_refused():
        payload = {"criticalExtensions": {"c1": {"rrcConnectionReconfiguration-r8": {
            "measConfig": {"measObjectToAddModList": [{
                "measObjectId": 1,
                "measObject": {"measObjectEUTRA": {
                    "carrierFreq": 1650,
                    "allowedMeasBandwidth": "mbw100",
                    "presenceAntennaPort1": True,
                    "neighCellConfig": "00",
                    "measCycleSCell-r13": "sf160",
                }},
            }]},
        }}}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(payload, handle)
            path = handle.name
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(TOOLS, "lte_rrc.py"), "reconfiguration",
                 "--json", path], capture_output=True, text=True)
        finally:
            os.unlink(path)
        if proc.returncode == 0:
            raise AssertionError("an r13 extension addition encoded without complaint")
        if "REFUSED" not in proc.stderr:
            raise AssertionError("exit %d without a REFUSED line: %r"
                                 % (proc.returncode, proc.stderr.strip()[:120]))
        if "measCycleSCell-r13" not in proc.stderr:
            raise AssertionError("the refusal does not name the field: %r"
                                 % proc.stderr.strip()[:160])
        return "named in the refusal: %s" % proc.stderr.strip().split(": ", 1)[1][:60]
    report.check("unmodelled extension addition refused",
                 extension_addition_refused)

    # ---- the vectors lte_rrc.py pins must really be pycrate's output -------
    def pins_are_pycrate():
        bad = []
        for (what, case), (want_len, want_hex) in sorted(lte_rrc.PINNED.items()):
            value = lte_rrc.reconfiguration_case(case)
            typename, module = "RRCConnectionReconfiguration", RRC
            if what == "handover-command":
                value = lte_rrc.handover_command(value)
                typename, module = "HandoverCommand", INTER
            bits, n = pycrate_bits(module, typename, value)
            padded = bits + "0" * (-len(bits) % 8)
            got_hex = "".join(format(int(padded[i:i + 8], 2), "02X")
                              for i in range(0, len(padded), 8))
            if n != want_len or got_hex != want_hex:
                bad.append("%s/%s: pinned (%d, %s), pycrate says (%d, %s)"
                           % (what, case, want_len, want_hex, n, got_hex))
        if bad:
            raise AssertionError("; ".join(bad))
        return "%d pinned vectors are pycrate's own output" % len(lte_rrc.PINNED)
    report.check("pinned vectors", pins_are_pycrate)

    # ---- `build` must go through the view too, not straight to the engine ---
    def build_path():
        # The engine alone would happily encode INTEGER 4 of RRC-TransactionIdentifier
        # (0..3) as two bits, because an ext=False INTEGER carries no range check.
        # The view is the only thing standing between that and the air.
        def run(payload):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
                handle.write(payload)
                path = handle.name
            try:
                return subprocess.run(
                    [sys.executable, os.path.join(TOOLS, "lte_rrc.py"), "build",
                     "RRC_TransactionIdentifier", "--json", path, "--hex"],
                    capture_output=True, text=True)
            finally:
                os.unlink(path)

        out_of_range = run("4")
        if out_of_range.returncode == 0:
            raise AssertionError("build accepted 4 for a 0..3 INTEGER and encoded %r"
                                 % out_of_range.stdout.strip())
        if "REFUSED" not in out_of_range.stderr:
            raise AssertionError("build exited %d without a REFUSED line: %r"
                                 % (out_of_range.returncode,
                                    out_of_range.stderr.strip()[:120]))
        in_range = run("3")
        if in_range.returncode != 0 or in_range.stdout.strip() != "C0":
            raise AssertionError("build refused a legal value: exit %d, %r"
                                 % (in_range.returncode, in_range.stdout.strip()))
        unmodelled = subprocess.run(
            [sys.executable, os.path.join(TOOLS, "lte_rrc.py"), "build",
             "DL_DCCH_Message", "--json", "/dev/null"],
            capture_output=True, text=True)
        if unmodelled.returncode == 0:
            raise AssertionError("build claimed a view of DL_DCCH_Message")
        return "range-checked via the view; legal value still encodes"
    report.check("CLI build path", build_path)

    # ---- decode side: our own decoder reads our own hex -------------------
    def cli_decode():
        built = lte_rrc.reconfiguration_case("full")
        bits = lte_rrc.CODEC.encode_bits("RRCConnectionReconfiguration", built)
        hexstr = lte_rrc.CODEC.encode_hex("RRCConnectionReconfiguration", built)
        proc = subprocess.run(
            [sys.executable, os.path.join(TOOLS, "lte_rrc.py"), "decode",
             "--type", "reconfiguration", "--hex", hexstr],
            capture_output=True, text=True)
        if proc.returncode != 0:
            raise AssertionError("decode exited %d: %s" % (proc.returncode,
                                                           proc.stderr.strip()))
        want = "bitlen    %d" % len(bits)
        if want not in proc.stdout:
            raise AssertionError("decode did not report %r:\n%s"
                                 % (want, proc.stdout[:200]))
        return "decode reports %d bits and a value" % len(bits)
    report.check("CLI decode", cli_decode)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare tools/lte_rrc.py with pycrate on handover messages")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    for name, path in (("lte_per", "lte_per.py"),
                       ("lte_rrc_layout", "lte_rrc_layout.py"),
                       ("lte_rrc", "lte_rrc.py")):
        if not os.path.exists(os.path.join(TOOLS, path)):
            sys.stderr.write("could not set up: %s is missing\n"
                             % os.path.join(TOOLS, path))
            return 2
    lte_rrc = load_module("lte_rrc", os.path.join(TOOLS, "lte_rrc.py"))

    report = Report()
    run_checks(lte_rrc, report, args.verbose)
    print("compared %d checks against pycrate 0.8.1: %d mismatches"
          % (report.n, len(report.failures)))
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main())
