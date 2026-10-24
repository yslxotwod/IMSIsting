#!/usr/bin/env python3
"""lte_rrc.py -- build the LTE handover RRC messages this field kit transmits.

Why this file exists
--------------------
`RRCConnectionReconfiguration` and the inter-node `HandoverCommand` (TS 36.331,
carried in TS 36.413 HANDOVER REQUEST) are far too large to transcribe leaf by
leaf, so the encoding here comes from the generated layout table
(`lte_rrc_layout`) driven by the generic unaligned-PER engine (`lte_per`).  That
pair already agrees with pycrate bit for bit on arbitrary values
(`tools/lte-per-oracle/verify_per.py`).  What the pair does *not* do is tell an
operator which fields they may set, or notice when they set one the tree cannot
encode: `lte_per` will encode an out-of-range INTEGER by truncating it and will
happily skip a component nobody modelled, and the resulting message still looks
exactly like a message on the bench.

This module is the layer that closes that gap.  It carries one hand-written
*view* per message type: the ASN.1 component names, spelled verbatim as in
TS 36.331, that this tree models, each with the shape an operator may write.
Anything outside a view -- an unmodelled component, an extension addition, an
out-of-range value, a hand-rolled octet string where a decoded message belongs
-- is REFUSED, never silently dropped, because a dropped field produces a
message that is wrong on the air and indistinguishable from a right one off it.

A view never restates an encoding rule.  Naming a field `INT`, `ENUM`, `BITS`
or `BOOL` makes the builder read that field's bounds, allowed names and length
straight out of the generated table, so there is no second copy of X.691 here
to drift out of date.

What is deliberately *not* modelled (all refused, see `describe`):
  * every extension addition of every sequence and choice in the view;
  * `RRCConnectionReconfiguration.nonCriticalExtension` (the v890/v920/v1020
    chain) -- a handover needs none of it, and half-encoding it is worse than
    not encoding it;
  * the RLC UM bearers, the SPS configuration, `physicalConfigDedicated`,
    `drx-Config`, `phr-Config` and the CDMA2000/UTRA/GERAN measurement objects.

Usage
-----
    # the two messages, from named options
    python3 tools/lte_rrc.py reconfiguration --tx 1 \
        --set mobilityControlInfo.targetPhysCellId=42 \
        --set mobilityControlInfo.t304=ms500 \
        --set mobilityControlInfo.newUE-Identity=0x003c
    python3 tools/lte_rrc.py handover-command --tx 1 --set ...

    # a known-good starting point, minimal or fully populated
    python3 tools/lte_rrc.py template --case full

    # decode / report the size
    python3 tools/lte_rrc.py decode --type handover-command --hex 7C1A...
    python3 tools/lte_rrc.py bitlen --type reconfiguration --set ...

    # what is modelled, and what is refused
    python3 tools/lte_rrc.py describe RRCConnectionReconfiguration_r8_IEs

`--set PATH=VALUE` addresses components by their ASN.1 names (dotted), relative
to the r8-IEs of the message being built; for `handover-command` the path is
relative to the reconfiguration carried inside the container.  VALUE is JSON,
falling back to a plain string (`--set ...t304=ms500`), or `@FILE` to read JSON
from a file.  A CHOICE is written either as a one-key object
(`--set securityConfigHO.handoverType.intraLTE.keyChangeIndicator=true`) or, for
an alternative that carries nothing, as its bare name
(`--set srb-ToAddModList[0].rlc-Config=defaultValue` is not supported -- put
lists and choices in JSON with `--set path=<json>`).

Exit codes: 0 built/decoded; 1 selftest failed; 2 refused (or bad usage).
"""

import argparse
import copy
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import lte_per  # noqa: E402  (path fix-up has to come first)
import lte_rrc_layout  # noqa: E402

CODEC = lte_per.codec_from_module(lte_rrc_layout)
TYPES = lte_rrc_layout.TYPES

# The one thing the layout table cannot give us.  TS 36.331 10.5 constrains
# HandoverCommand-r8-IEs.handoverCommandMessage to DL-DCCH-Message, but
# DL-DCCH-Message is not a root of the generated table (the constraint survives
# only as a `containing` comment), so the five-bit envelope below is written out
# by hand: DL-DCCH-MessageType is a non-extensible 2-alternative CHOICE, we want
# `c1` (bit 0); c1 is a non-extensible 16-alternative CHOICE whose fifth
# alternative is rrcConnectionReconfiguration (bits 0100).
# tools/lte-rrc-oracle/verify_rrc.py asserts these five bits against pycrate.
DL_DCCH_C1_INDEX = 4
DL_DCCH_PREFIX = "0" + format(DL_DCCH_C1_INDEX, "04b")

# The UE's answer to RRCConnectionSetup travels on UL-DCCH, whose c1 CHOICE has
# rrcConnectionSetupComplete-r8 as its fifth alternative (index 4) in the
# generated table (tools/lte_rrc_layout.py:71811).  The envelope is the same
# shape as DL-DCCH's: one extension bit, then the four-bit index.
UL_DCCH_SETUP_COMPLETE_INDEX = 4
UL_DCCH_SETUP_COMPLETE_PREFIX = "0" + format(UL_DCCH_SETUP_COMPLETE_INDEX, "04b")


class Refused(ValueError):
    """A value this builder will not encode, because encoding it would lie."""


# --------------------------------------------------------------------------
# The view language.
#
# A view is written with the ASN.1 component names of the table, so it can be
# diffed against that table mechanically (`_check_views` and `describe` do
# exactly that).  Leave a field out of a view and it is refused; leave a
# *mandatory* field out of a view and the builder refuses to start at all,
# because then it could never emit a legal message.
# --------------------------------------------------------------------------

INT = ("int",)
ENUM = ("enum",)
BOOL = ("bool",)
NULL = ("null",)
OCTETS = ("octets", None, None)  # unconstrained OCTET STRING
BITS = ("bits",)
CRNTI = ("crnti",)
DL_DCCH = ("dl-dcch",)


def REF(t):
    """Delegate to the view of the named type; the table must really say `ref`."""
    return ("ref", t)


def SEQ(fields):
    return ("seq", fields)


def CH(alts):
    return ("choice", alts)


def LIST(of):
    return ("seqof", of)


def OCTETS_OF(lo, hi):
    return ("octets", lo, hi)


def _deref(node, path):
    while node["k"] == "ref":
        try:
            node = TYPES[node["t"]]
        except KeyError:
            raise Refused("%s: table references unknown type %r" % (path, node["t"]))
    return node


def _comp_names(node):
    return [c[0] for c in node["comp"]]


def _extadd_names(node):
    """Names an extension addition could use, whichever shape the table kept."""
    out = []
    for entry in node.get("extadd") or ():
        if isinstance(entry, dict):
            if entry.get("names"):
                out.extend(entry["names"])
            elif entry.get("name"):
                out.append(entry["name"])
        else:
            out.append(entry[0])
    return out


def _resolve_name(node, key, path):
    """Map an operator's spelling onto the table's, without guessing.

    ASN.1 component names are hyphenated; Python keyword arguments and some
    shells are not, so `_` is accepted as a stand-in for `-`.  An exact match
    always wins.
    """
    names = _comp_names(node) + _extadd_names(node) if node["k"] == "seq" else \
        [a[0] for a in node["alts"]] + _extadd_names(node)
    if key in names:
        return key
    swapped = key.replace("_", "-")
    if swapped in names:
        return swapped
    return None


# --------------------------------------------------------------------------
# The views.
# --------------------------------------------------------------------------

SECURITY_ALGORITHM_CONFIG = SEQ({
    "cipheringAlgorithm": ENUM,
    "integrityProtAlgorithm": ENUM,
})


VIEWS = {
    # -- the two messages, and the wrapper TS 36.331 puts around their body --
    "RRCConnectionReconfiguration": SEQ({
        "rrc-TransactionIdentifier": REF("RRC_TransactionIdentifier"),
        "criticalExtensions": CH({
            "c1": CH({
                "rrcConnectionReconfiguration-r8": REF("RRCConnectionReconfiguration_r8_IEs"),
            }),
        }),
    }),
    "RRC_TransactionIdentifier": INT,

    "RRCConnectionReconfiguration_r8_IEs": SEQ({
        "measConfig": REF("MeasConfig"),
        "mobilityControlInfo": REF("MobilityControlInfo"),
        "dedicatedInfoNASList": LIST(OCTETS),
        "radioResourceConfigDedicated": REF("RadioResourceConfigDedicated"),
        "securityConfigHO": REF("SecurityConfigHO"),
    }),

    # -- the first message a UE ever sends on the RRC connection: the identity
    #    it selected and, inside dedicatedInfoNAS, the first NAS PDU.  This is
    #    the door the rest of the attach walks through --
    "RRCConnectionSetupComplete": SEQ({
        "rrc-TransactionIdentifier": REF("RRC_TransactionIdentifier"),
        "criticalExtensions": CH({
            "c1": CH({
                "rrcConnectionSetupComplete-r8": REF("RRCConnectionSetupComplete_r8_IEs"),
            }),
        }),
    }),
    "RRCConnectionSetupComplete_r8_IEs": SEQ({
        "selectedPLMN-Identity": INT,
        "registeredMME": REF("RegisteredMME"),
        "dedicatedInfoNAS": REF("DedicatedInfoNAS"),
        "nonCriticalExtension": REF("RRCConnectionSetupComplete_v8a0_IEs"),
    }),
    "RegisteredMME": SEQ({
        "plmn-Identity": REF("PLMN_Identity"),
        "mmegi": BITS,
        "mmec": REF("MMEC"),
    }),
    "PLMN_Identity": SEQ({
        "mcc": LIST(INT),
        "mnc": LIST(INT),
    }),
    "DedicatedInfoNAS": OCTETS,
    "MMEC": BITS,
    "HandoverCommand": SEQ({
        "criticalExtensions": CH({
            "c1": CH({
                "handoverCommand-r8": REF("HandoverCommand_r8_IEs"),
            }),
        }),
    }),
    "HandoverCommand_r8_IEs": SEQ({
        "handoverCommandMessage": DL_DCCH,
    }),

    # -- mobility control: who and where to hand over to, and how to reach it --
    "MobilityControlInfo": SEQ({
        "targetPhysCellId": INT,
        "carrierFreq": REF("CarrierFreqEUTRA"),
        "carrierBandwidth": REF("CarrierBandwidthEUTRA"),
        "additionalSpectrumEmission": INT,
        "t304": ENUM,
        "newUE-Identity": CRNTI,
        "radioResourceConfigCommon": REF("RadioResourceConfigCommon"),
        "rach-ConfigDedicated": REF("RACH_ConfigDedicated"),
    }),
    "CarrierFreqEUTRA": SEQ({
        "dl-CarrierFreq": INT,
        "ul-CarrierFreq": INT,
    }),
    "CarrierBandwidthEUTRA": SEQ({
        "dl-Bandwidth": ENUM,
        "ul-Bandwidth": ENUM,
    }),
    "RACH_ConfigDedicated": SEQ({
        "ra-PreambleIndex": INT,
        "ra-PRACH-MaskIndex": INT,
    }),

    # -- security: the key change the UE must make before it talks to the target
    "SecurityConfigHO": SEQ({
        "handoverType": CH({
            "intraLTE": SEQ({
                "securityAlgorithmConfig": REF("SecurityAlgorithmConfig"),
                "keyChangeIndicator": BOOL,
                "nextHopChainingCount": INT,
            }),
            "interRAT": SEQ({
                "securityAlgorithmConfig": REF("SecurityAlgorithmConfig"),
                "nas-SecurityParamToEUTRA": OCTETS_OF(6, 6),
            }),
        }),
    }),
    "SecurityAlgorithmConfig": SECURITY_ALGORITHM_CONFIG,

    # -- the target cell's broadcast configuration, as the UE must use it now --
    "RadioResourceConfigCommon": SEQ({
        "rach-ConfigCommon": REF("RACH_ConfigCommon"),
        "prach-Config": REF("PRACH_Config"),
        "pdsch-ConfigCommon": REF("PDSCH_ConfigCommon"),
        "pusch-ConfigCommon": REF("PUSCH_ConfigCommon"),
        "phich-Config": REF("PHICH_Config"),
        "pucch-ConfigCommon": REF("PUCCH_ConfigCommon"),
        "soundingRS-UL-ConfigCommon": REF("SoundingRS_UL_ConfigCommon"),
        "uplinkPowerControlCommon": REF("UplinkPowerControlCommon"),
        "antennaInfoCommon": REF("AntennaInfoCommon"),
        "p-Max": INT,
        "tdd-Config": REF("TDD_Config"),
        "ul-CyclicPrefixLength": ENUM,
    }),
    "RACH_ConfigCommon": SEQ({
        "preambleInfo": SEQ({
            "numberOfRA-Preambles": ENUM,
            "preamblesGroupAConfig": SEQ({
                "sizeOfRA-PreamblesGroupA": ENUM,
                "messageSizeGroupA": ENUM,
                "messagePowerOffsetGroupB": ENUM,
            }),
        }),
        "powerRampingParameters": REF("PowerRampingParameters"),
        "ra-SupervisionInfo": SEQ({
            "preambleTransMax": ENUM,
            "ra-ResponseWindowSize": ENUM,
            "mac-ContentionResolutionTimer": ENUM,
        }),
        "maxHARQ-Msg3Tx": INT,
    }),
    "PowerRampingParameters": SEQ({
        "powerRampingStep": ENUM,
        "preambleInitialReceivedTargetPower": ENUM,
    }),
    "PRACH_Config": SEQ({
        "rootSequenceIndex": INT,
        "prach-ConfigInfo": REF("PRACH_ConfigInfo"),
    }),
    "PRACH_ConfigInfo": SEQ({
        "prach-ConfigIndex": INT,
        "highSpeedFlag": BOOL,
        "zeroCorrelationZoneConfig": INT,
        "prach-FreqOffset": INT,
    }),
    "PDSCH_ConfigCommon": SEQ({
        "referenceSignalPower": INT,
        "p-b": INT,
    }),
    "PUSCH_ConfigCommon": SEQ({
        "pusch-ConfigBasic": SEQ({
            "n-SB": INT,
            "hoppingMode": ENUM,
            "pusch-HoppingOffset": INT,
            "enable64QAM": BOOL,
        }),
        "ul-ReferenceSignalsPUSCH": SEQ({
            "groupHoppingEnabled": BOOL,
            "groupAssignmentPUSCH": INT,
            "sequenceHoppingEnabled": BOOL,
            "cyclicShift": INT,
        }),
    }),
    "PHICH_Config": SEQ({
        "phich-Duration": ENUM,
        "phich-Resource": ENUM,
    }),
    "PUCCH_ConfigCommon": SEQ({
        "deltaPUCCH-Shift": ENUM,
        "nRB-CQI": INT,
        "nCS-AN": INT,
        "n1PUCCH-AN": INT,
    }),
    # The table keeps SoundingRS-UL-ConfigCommon.setup as an inline SEQUENCE,
    # reachable only through the CHOICE below.
    "SoundingRS_UL_ConfigCommon": CH({
        "release": NULL,
        "setup": SEQ({
            "srs-BandwidthConfig": ENUM,
            "srs-SubframeConfig": ENUM,
            "ackNackSRS-SimultaneousTransmission": BOOL,
            "srs-MaxUpPts": ENUM,
        }),
    }),
    "UplinkPowerControlCommon": SEQ({
        "p0-NominalPUSCH": INT,
        "alpha": ENUM,
        "p0-NominalPUCCH": INT,
        "deltaFList-PUCCH": SEQ({
            "deltaF-PUCCH-Format1": ENUM,
            "deltaF-PUCCH-Format1b": ENUM,
            "deltaF-PUCCH-Format2": ENUM,
            "deltaF-PUCCH-Format2a": ENUM,
            "deltaF-PUCCH-Format2b": ENUM,
        }),
        "deltaPreambleMsg3": INT,
    }),
    "AntennaInfoCommon": SEQ({
        "antennaPortsCount": ENUM,
    }),
    "TDD_Config": SEQ({
        "subframeAssignment": ENUM,
        "specialSubframePatterns": ENUM,
    }),

    # -- measurements: what the UE measures and when it reports --------------
    "MeasConfig": SEQ({
        "measObjectToRemoveList": LIST(INT),
        "measObjectToAddModList": LIST(REF("MeasObjectToAddMod")),
        "reportConfigToRemoveList": LIST(INT),
        "reportConfigToAddModList": LIST(REF("ReportConfigToAddMod")),
        "measIdToRemoveList": LIST(INT),
        "measIdToAddModList": LIST(REF("MeasIdToAddMod")),
        "quantityConfig": REF("QuantityConfig"),
        "measGapConfig": REF("MeasGapConfig"),
        "s-Measure": INT,
    }),
    "QuantityConfig": SEQ({
        "quantityConfigEUTRA": SEQ({
            "filterCoefficientRSRP": ENUM,
            "filterCoefficientRSRQ": ENUM,
        }),
    }),
    "MeasObjectToAddMod": SEQ({
        "measObjectId": INT,
        "measObject": CH({
            "measObjectEUTRA": REF("MeasObjectEUTRA"),
        }),
    }),
    "MeasObjectEUTRA": SEQ({
        "carrierFreq": INT,
        "allowedMeasBandwidth": ENUM,
        "presenceAntennaPort1": BOOL,
        "neighCellConfig": ("bits", 2),
        "offsetFreq": ENUM,
        "cellsToRemoveList": LIST(INT),
        "cellsToAddModList": LIST(REF("CellsToAddMod")),
        "cellForWhichToReportCGI": INT,
    }),
    "CellsToAddMod": SEQ({
        "cellIndex": INT,
        "physCellId": INT,
        "cellIndividualOffset": ENUM,
    }),
    "ReportConfigToAddMod": SEQ({
        "reportConfigId": INT,
        "reportConfig": CH({
            "reportConfigEUTRA": REF("ReportConfigEUTRA"),
        }),
    }),
    "ReportConfigEUTRA": SEQ({
        "triggerType": CH({
            "event": SEQ({
                "eventId": CH({
                    "eventA1": SEQ({"a1-Threshold": REF("ThresholdEUTRA")}),
                    "eventA2": SEQ({"a2-Threshold": REF("ThresholdEUTRA")}),
                    "eventA3": SEQ({
                        "a3-Offset": INT,
                        "reportOnLeave": BOOL,
                    }),
                    "eventA4": SEQ({"a4-Threshold": REF("ThresholdEUTRA")}),
                    "eventA5": SEQ({
                        "a5-Threshold1": REF("ThresholdEUTRA"),
                        "a5-Threshold2": REF("ThresholdEUTRA"),
                    }),
                }),
                "hysteresis": INT,
                "timeToTrigger": ENUM,
            }),
            "periodical": SEQ({
                "purpose": ENUM,
            }),
        }),
        "triggerQuantity": ENUM,
        "reportQuantity": ENUM,
        "maxReportCells": INT,
        "reportInterval": ENUM,
        "reportAmount": ENUM,
    }),
    "ThresholdEUTRA": CH({
        "threshold-RSRP": INT,
        "threshold-RSRQ": INT,
    }),
    "MeasIdToAddMod": SEQ({
        "measId": INT,
        "measObjectId": INT,
        "reportConfigId": INT,
    }),
    "MeasGapConfig": CH({
        "release": NULL,
        "setup": SEQ({
            "gapOffset": CH({
                "gp0": INT,
                "gp1": INT,
            }),
        }),
    }),

    # -- the dedicated side: bearers the UE keeps, releases and configures ----
    "RadioResourceConfigDedicated": SEQ({
        "srb-ToAddModList": LIST(REF("SRB_ToAddMod")),
        "drb-ToReleaseList": REF("DRB_ToReleaseList"),
        "mac-MainConfig": CH({
            "explicitValue": REF("MAC_MainConfig"),
            "defaultValue": NULL,
        }),
    }),
    "SRB_ToAddMod": SEQ({
        "srb-Identity": INT,
        "rlc-Config": CH({
            "explicitValue": REF("RLC_Config"),
            "defaultValue": NULL,
        }),
        "logicalChannelConfig": CH({
            "explicitValue": REF("LogicalChannelConfig"),
            "defaultValue": NULL,
        }),
    }),
    "RLC_Config": CH({
        "am": SEQ({
            "ul-AM-RLC": REF("UL_AM_RLC"),
            "dl-AM-RLC": REF("DL_AM_RLC"),
        }),
    }),
    "UL_AM_RLC": SEQ({
        "t-PollRetransmit": ENUM,
        "pollPDU": ENUM,
        "pollByte": ENUM,
        "maxRetxThreshold": ENUM,
    }),
    "DL_AM_RLC": SEQ({
        "t-Reordering": ENUM,
        "t-StatusProhibit": ENUM,
    }),
    "LogicalChannelConfig": SEQ({
        "ul-SpecificParameters": SEQ({
            "priority": INT,
            "prioritisedBitRate": ENUM,
            "bucketSizeDuration": ENUM,
            "logicalChannelGroup": INT,
        }),
    }),
    "MAC_MainConfig": SEQ({
        "ul-SCH-Config": SEQ({
            "maxHARQ-Tx": ENUM,
            "periodicBSR-Timer": ENUM,
            "retxBSR-Timer": ENUM,
            "ttiBundling": BOOL,
        }),
        "timeAlignmentTimerDedicated": ENUM,
    }),
    "DRB_ToReleaseList": LIST(INT),
}


# --------------------------------------------------------------------------
# Building.
# --------------------------------------------------------------------------

def _as_int(value, path):
    if isinstance(value, bool) or not isinstance(value, int):
        raise Refused("%s: expected an integer, got %r" % (path, value))
    return value


def _as_enum(value, node, path):
    if not isinstance(value, str):
        raise Refused("%s: expected one of %s, got %r"
                      % (path, "/".join(node["names"][:4]) + "/...", value))
    allowed = list(node["names"]) + list(node.get("ext") or ())
    if value not in allowed:
        raise Refused("%s: %r is not a value of this ENUMERATED (%s)"
                      % (path, value, ", ".join(allowed[:8]) + ("..." if len(allowed) > 8 else "")))
    return value


def _as_bits(value, size, path, what="BIT STRING"):
    if len(size) == 1:
        size = (size[0], size[0])
    lo, hi = size
    nbits = lo if lo == hi else None
    if nbits is None:
        raise Refused("%s: variable-length %s is not modelled" % (path, what))
    if isinstance(value, str):
        text = value
        if text.lower().startswith("0x"):
            hextext = text[2:]
            if not hextext or any(c not in "0123456789abcdefABCDEF" for c in hextext):
                raise Refused("%s: expected %d bits as hex, got %r" % (path, nbits, value))
            raw, width = int(hextext, 16), len(hextext) * 4
        else:
            bittext = text[2:] if text.lower().startswith("0b") else text
            if not bittext or any(c not in "01" for c in bittext):
                raise Refused("%s: expected %d bits as 0/1 or hex, got %r"
                              % (path, nbits, value))
            raw, width = int(bittext, 2), len(bittext)
        if width != nbits:
            raise Refused("%s: expected exactly %d bits, got %d" % (path, nbits, width))
        return raw, nbits
    if isinstance(value, (tuple, list)) and len(value) == 2:
        # The engine's own shape, so a decoded message can be rebuilt as-is.
        raw, width = value
        if isinstance(raw, bool) or not isinstance(raw, int) or width != nbits:
            raise Refused("%s: %r is not a %d-bit value" % (path, value, nbits))
        if not 0 <= raw < (1 << nbits):
            raise Refused("%s: %d does not fit in %d bits" % (path, raw, nbits))
        return raw, nbits
    if isinstance(value, bool) or not isinstance(value, int):
        raise Refused("%s: expected a %d-bit integer, a hex string or a %d-character "
                      "bit string, got %r" % (path, nbits, nbits, value))
    if not 0 <= value < (1 << nbits):
        raise Refused("%s: %d does not fit in %d bits" % (path, value, nbits))
    return value, nbits


def _as_octets(value, node, path):
    if isinstance(value, str):
        text = value[2:] if value.lower().startswith("0x") else value
        if len(text) % 2 or any(c not in "0123456789abcdefABCDEF" for c in text):
            raise Refused("%s: expected an even-length hex string, got %r" % (path, value))
        raw = bytes.fromhex(text)
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise Refused("%s: expected bytes or a hex string, got %r" % (path, value))
    size = node.get("size")
    if size:
        lo, hi = size[0], size[1] if size[1] is not None else size[0]
        if not lo <= len(raw) <= hi:
            raise Refused("%s: OCTET STRING is %d bytes, the table allows %d..%d"
                          % (path, len(raw), lo, hi))
    return raw


def _wrap_dl_dcch(reconfig_value, path):
    """Put a reconfiguration where TS 36.331 10.5 wants it: inside a DL-DCCH."""
    bits = CODEC.encode_bits("RRCConnectionReconfiguration", reconfig_value)
    body = DL_DCCH_PREFIX + bits
    body += "0" * (-len(body) % 8)
    return bytes(int(body[i:i + 8], 2) for i in range(0, len(body), 8))


def _build(spec, node, value, path):
    kind = spec[0]

    if kind == "ref":
        want = spec[1]
        if node["k"] != "ref" or node["t"] != want:
            raise Refused("%s: internal view error, the table does not reference %s here"
                          % (path, want))
        if want not in VIEWS:
            raise Refused("%s: %s has no view in this builder" % (path, want))
        return _build(VIEWS[want], TYPES[want], value, path)

    node = _deref(node, path)

    if kind == "int":
        if node["k"] != "int":
            raise Refused("%s: internal view error, table says %s not INTEGER"
                          % (path, node["k"]))
        v = _as_int(value, path)
        lb, ub = node["lb"], node["ub"]
        if not node["ext"]:
            if lb is not None and v < lb:
                raise Refused("%s: %d is below the allowed minimum %d" % (path, v, lb))
            if ub is not None and v > ub:
                # lte_per would truncate this to fit the root range.
                raise Refused("%s: %d is above the allowed maximum %d" % (path, v, ub))
        return v

    if kind == "enum":
        if node["k"] != "enum":
            raise Refused("%s: internal view error, table says %s not ENUMERATED"
                          % (path, node["k"]))
        return _as_enum(value, node, path)

    if kind == "bool":
        if node["k"] != "bool":
            raise Refused("%s: internal view error, table says %s not BOOLEAN"
                          % (path, node["k"]))
        if not isinstance(value, bool):
            raise Refused("%s: expected true or false, got %r" % (path, value))
        return value

    if kind == "null":
        if node["k"] != "null":
            raise Refused("%s: internal view error, table says %s not NULL"
                          % (path, node["k"]))
        if value not in (None, 0, True):
            raise Refused("%s: this alternative carries nothing, got %r" % (path, value))
        return 0

    if kind == "bits":
        if node["k"] != "bits":
            raise Refused("%s: internal view error, table says %s not BIT STRING"
                          % (path, node["k"]))
        size = spec[1:] if len(spec) > 1 else node["size"]
        return _as_bits(value, size, path)

    if kind == "crnti":
        if node["k"] != "bits":
            raise Refused("%s: internal view error, table says %s not BIT STRING"
                          % (path, node["k"]))
        return _as_bits(value, node["size"], path, what="BIT STRING (C-RNTI)")

    if kind == "octets":
        if node["k"] != "octets":
            raise Refused("%s: internal view error, table says %s not OCTET STRING"
                          % (path, node["k"]))
        raw = _as_octets(value, node, path)
        lo, hi = spec[1], spec[2]
        if lo is not None and not lo <= len(raw) <= hi:
            raise Refused("%s: %d bytes, this field is fixed at %d..%d"
                          % (path, len(raw), lo, hi))
        return raw

    if kind == "dl-dcch":
        if node["k"] != "octets":
            raise Refused("%s: internal view error, table says %s not OCTET STRING"
                          % (path, node["k"]))
        if not isinstance(value, dict):
            raise Refused("%s: expected a built RRCConnectionReconfiguration value "
                          "(the container is decoded, not hand-written); got %r"
                          % (path, value))
        inner = _build(VIEWS["RRCConnectionReconfiguration"],
                       TYPES["RRCConnectionReconfiguration"], value,
                       path + ":RRCConnectionReconfiguration")
        return _wrap_dl_dcch(inner, path)

    if kind == "seq":
        if node["k"] != "seq":
            raise Refused("%s: internal view error, table says %s not SEQUENCE"
                          % (path, node["k"]))
        if not isinstance(value, dict):
            raise Refused("%s: expected an object of ASN.1 component names, got %r"
                          % (path, value))
        fields = spec[1]
        out = {}
        for key, item in value.items():
            name = _resolve_name(node, key, path) if key not in fields else key
            if name is None:
                if key in _comp_names(node) or key in _extadd_names(node):
                    raise Refused("%s.%s is not modelled by this builder; `describe` "
                                  "lists what is" % (path, key))
                raise Refused("%s: unknown component %r (modelled: %s)"
                              % (path, key, ", ".join(sorted(fields))))
            if name not in fields:
                if key in _extadd_names(node) or name in _extadd_names(node):
                    raise Refused("%s.%s is an extension addition and is not modelled "
                                  "by this builder" % (path, name))
                raise Refused("%s.%s is not modelled by this builder; `describe` lists "
                              "what is" % (path, name))
            out[name] = _build(fields[name], _comp_node(node, name), item,
                               "%s.%s" % (path, name))
        for cname, cnode, optional, default in node["comp"]:
            # A DEFAULT component is omittable even though the generated table
            # records optional=False for it; the engine reads it the same way
            # (lte_per.py:354 tests `opt or dflt is not None`), so a default the
            # operator leaves out still encodes as the default.
            if not optional and default is None and cname not in out:
                raise Refused("%s: mandatory component %s is missing" % (path, cname))
        return out

    if kind == "choice":
        if node["k"] != "choice":
            raise Refused("%s: internal view error, table says %s not CHOICE"
                          % (path, node["k"]))
        alts = spec[1]
        name, item = _split_choice(value, node, path)
        if name not in alts:
            if name in [a[0] for a in node["alts"]] or name in _extadd_names(node):
                raise Refused("%s: alternative %s is not modelled by this builder "
                              "(modelled: %s)" % (path, name, ", ".join(sorted(alts))))
            raise Refused("%s: unknown alternative %r (modelled: %s)"
                          % (path, name, ", ".join(sorted(alts))))
        alt_node = dict((a[0], a[1]) for a in node["alts"])[name]
        return (name, _build(alts[name], alt_node, item, "%s.%s" % (path, name)))

    if kind == "seqof":
        if node["k"] != "seqof":
            raise Refused("%s: internal view error, table says %s not SEQUENCE OF"
                          % (path, node["k"]))
        if not isinstance(value, list):
            raise Refused("%s: expected a list, got %r" % (path, value))
        size = node.get("size")
        if size:
            lo, hi = size[0], size[1] if size[1] is not None else size[0]
            if not node["ext"] and not lo <= len(value) <= hi:
                raise Refused("%s: %d entries, the table allows %d..%d"
                              % (path, len(value), lo, hi))
        return [_build(spec[1], node["of"], item, "%s[%d]" % (path, i))
                for i, item in enumerate(value)]

    raise Refused("%s: internal view error, unknown spec kind %r" % (path, kind))


def _comp_node(node, name):
    for cname, cnode, _opt, _default in node["comp"]:
        if cname == name:
            return cnode
    raise Refused("internal view error: %s has no component %s" % (node.get("name", "?"), name))


def _split_choice(value, node, path):
    """A CHOICE is written as a one-key object, a [name, value] pair, or a bare name."""
    if isinstance(value, str):
        for alt in node["alts"]:
            if alt[0] == value and alt[1]["k"] == "null":
                return value, None
        raise Refused("%s: %r names no alternative that carries nothing; write the "
                      "alternative and its value" % (path, value))
    if isinstance(value, dict):
        if len(value) != 1:
            raise Refused("%s: a CHOICE takes exactly one alternative, got %d keys"
                          % (path, len(value)))
        key = next(iter(value))
        name = _resolve_name(node, key, path) or key
        return name, value[key]
    if isinstance(value, (list, tuple)) and len(value) == 2:
        name = _resolve_name(node, value[0], path) or value[0]
        return name, value[1]
    raise Refused("%s: expected an object like {\"%s\": value}, got %r"
                  % (path, node["alts"][0][0], value))


def build(typename, value):
    """Validate `value` against this tree's view of `typename`.

    Returns the engine-shaped value (what `lte_per` calls a SEQUENCE: a dict of
    exactly the components that are present).  Raises `Refused` otherwise.
    """
    if typename not in VIEWS:
        raise Refused("this builder has no view of %s" % typename)
    if typename not in TYPES:
        raise Refused("the generated table has no type %s" % typename)
    return _build(VIEWS[typename], TYPES[typename], value, typename)


# --------------------------------------------------------------------------
# The two messages, by name.
# --------------------------------------------------------------------------

def _ie_kwargs(node, kwargs, path):
    """Keyword arguments use `_` where ASN.1 uses `-`; nothing else is accepted."""
    out = {}
    for key, item in kwargs.items():
        if item is None:
            continue
        name = _resolve_name(node, key, path)
        if name is None:
            raise Refused("%s: unknown component %r" % (path, key))
        out[name] = item
    return out


def reconfiguration(transaction_identifier=0, **ies):
    """Build an RRCConnectionReconfiguration.

    `ies` are the components of RRCConnectionReconfiguration-r8-IEs, spelled with
    `_` for `-`: measConfig, mobilityControlInfo, dedicatedInfoNASList,
    radioResourceConfigDedicated, securityConfigHO.
    """
    node = TYPES["RRCConnectionReconfiguration_r8_IEs"]
    body = _ie_kwargs(node, ies, "RRCConnectionReconfiguration-r8-IEs")
    return build("RRCConnectionReconfiguration", {
        "rrc-TransactionIdentifier": transaction_identifier,
        "criticalExtensions": {"c1": {"rrcConnectionReconfiguration-r8": body}},
    })


def handover_command(reconfiguration_value):
    """Wrap a built reconfiguration in the inter-node HandoverCommand."""
    return build("HandoverCommand", {
        "criticalExtensions": {"c1": {"handoverCommand-r8": {
            "handoverCommandMessage": reconfiguration_value,
        }}},
    })


def encode(typename, value):
    """(bits, bit length) for a built value of `typename`."""
    value = build(typename, value)
    bits = CODEC.encode_bits(typename, value)
    return bits, len(bits)


def encode_hex(typename, value):
    return CODEC.encode_hex(typename, build(typename, value))


# --------------------------------------------------------------------------
# Decoding.
# --------------------------------------------------------------------------

def _decode_longest(typename, bits):
    """Decode the longest prefix that is a complete, self-consistent message."""
    for n in range(len(bits), 0, -1):
        if bits[n:] and set(bits[n:]) != {"0"}:
            continue
        try:
            value = CODEC.decode_bits(typename, bits[:n], exact=True)
        except lte_per.PerError:
            continue
        if CODEC.encode_bits(typename, value) == bits[:n]:
            return value, n
    raise Refused("no prefix of these %d bits decodes as a complete %s"
                  % (len(bits), typename))


def _bits_of_hex(text, path):
    text = text.strip().replace(" ", "").replace(":", "")
    text = text[2:] if text.lower().startswith("0x") else text
    if not text or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise Refused("%s: expected hex, got %r" % (path, text))
    return "".join(format(b, "08b") for b in bytes.fromhex(text if len(text) % 2 == 0
                                                         else "0" + text))


def decode_bits(typename, bits):
    value, n = _decode_longest(typename, bits)
    return value, n


def decode_hex(typename, hexstr):
    return decode_bits(typename, _bits_of_hex(hexstr, "hex"))


def _render(value):
    """JSON, with the opaque strings written the way an operator reads them."""
    if isinstance(value, bytes):
        return {"octets-hex": value.hex().upper()}
    if isinstance(value, dict):
        return dict((k, _render(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        # A CHOICE is the 2-tuple the engine documents; JSON has no tuple, so it
        # reads back as [alternative, value].
        return [_render(v) for v in value]
    return value


def _compare(spec, node, sent, got, path, out):
    kind = spec[0]
    if kind == "ref":
        _compare(VIEWS[spec[1]], TYPES[spec[1]], sent, got, path, out)
        return
    node = _deref(node, path)

    if kind == "seq":
        if not isinstance(got, dict):
            out.append("%s: expected an object, got %r" % (path, got))
            return
        comps = dict((c[0], c) for c in node["comp"])
        for name, item in sent.items():
            if name not in got:
                # Canonical PER does not spend a bit on a component equal to its
                # DEFAULT, so a decoder cannot give it back.  That is not a loss.
                comp = comps.get(name)
                if comp is not None and comp[3] is not None and comp[3] == item:
                    continue
                out.append("%s.%s: lost" % (path, name))
                continue
            sub = spec[1].get(name)
            if sub is None:
                out.append("%s.%s: not in the view, cannot compare" % (path, name))
                continue
            _compare(sub, comps[name][1], item, got[name], "%s.%s" % (path, name), out)
        for name in got:
            if name in sent:
                continue
            # The mirror image of the case above: a component left out because
            # its value was the DEFAULT comes back as the DEFAULT, so a decoder
            # legitimately reports a component the message never spent a bit on.
            comp = comps.get(name)
            if comp is not None and comp[3] is not None and comp[3] == got[name]:
                continue
            out.append("%s.%s: appeared" % (path, name))
        return

    if kind == "choice":
        if not isinstance(got, (tuple, list)) or len(got) != 2:
            out.append("%s: expected a CHOICE, got %r" % (path, got))
            return
        if sent[0] != got[0]:
            out.append("%s: alternative %s became %s" % (path, sent[0], got[0]))
            return
        alts = dict((a[0], a[1]) for a in node["alts"])
        _compare(spec[1][sent[0]], alts[sent[0]], sent[1], got[1],
                 "%s.%s" % (path, sent[0]), out)
        return

    if kind == "seqof":
        if not isinstance(got, list) or len(got) != len(sent):
            out.append("%s: %d entries became %r" % (path, len(sent), got))
            return
        for i, (a, b) in enumerate(zip(sent, got)):
            _compare(spec[1], node["of"], a, b, "%s[%d]" % (path, i), out)
        return

    want = _build(spec, node, sent, path)
    if isinstance(want, bytes):
        got = bytes(got) if isinstance(got, (bytes, bytearray)) else got
    if want != got:
        out.append("%s: %r became %r" % (path, sent, got))


def compare_message(typename, sent, got):
    """Differences between the value an operator meant and the value that decoded.

    DEFAULT-valued components are allowed to be missing from `got`, because
    canonical PER does not encode them.  Returns a list of human-readable
    differences; empty means the two describe the same message.
    """
    out = []
    _compare(VIEWS[typename], TYPES[typename], sent, got, typename, out)
    return out


# --------------------------------------------------------------------------
# Templates: a minimal and a fully populated handover.
# --------------------------------------------------------------------------

_RRC_COMMON_FULL = {
    "rach-ConfigCommon": {
        "preambleInfo": {
            "numberOfRA-Preambles": "n52",
            "preamblesGroupAConfig": {
                "sizeOfRA-PreamblesGroupA": "n48",
                "messageSizeGroupA": "b56",
                "messagePowerOffsetGroupB": "dB10",
            },
        },
        "powerRampingParameters": {
            "powerRampingStep": "dB2",
            "preambleInitialReceivedTargetPower": "dBm-104",
        },
        "ra-SupervisionInfo": {
            "preambleTransMax": "n10",
            "ra-ResponseWindowSize": "sf4",
            "mac-ContentionResolutionTimer": "sf32",
        },
        "maxHARQ-Msg3Tx": 4,
    },
    "prach-Config": {
        "rootSequenceIndex": 22,
        "prach-ConfigInfo": {
            "prach-ConfigIndex": 12,
            "highSpeedFlag": False,
            "zeroCorrelationZoneConfig": 4,
            "prach-FreqOffset": 2,
        },
    },
    "pdsch-ConfigCommon": {"referenceSignalPower": 18, "p-b": 1},
    "pusch-ConfigCommon": {
        "pusch-ConfigBasic": {
            "n-SB": 1,
            "hoppingMode": "interSubFrame",
            "pusch-HoppingOffset": 0,
            "enable64QAM": False,
        },
        "ul-ReferenceSignalsPUSCH": {
            "groupHoppingEnabled": False,
            "groupAssignmentPUSCH": 0,
            "sequenceHoppingEnabled": False,
            "cyclicShift": 0,
        },
    },
    "phich-Config": {"phich-Duration": "normal", "phich-Resource": "one"},
    "pucch-ConfigCommon": {
        "deltaPUCCH-Shift": "ds1",
        "nRB-CQI": 4,
        "nCS-AN": 0,
        "n1PUCCH-AN": 10,
    },
    "soundingRS-UL-ConfigCommon": {"setup": {
        "srs-BandwidthConfig": "bw2",
        "srs-SubframeConfig": "sc2",
        "ackNackSRS-SimultaneousTransmission": True,
        "srs-MaxUpPts": "true",
    }},
    "uplinkPowerControlCommon": {
        "p0-NominalPUSCH": -70,
        "alpha": "al1",
        "p0-NominalPUCCH": -100,
        "deltaFList-PUCCH": {
            "deltaF-PUCCH-Format1": "deltaF0",
            "deltaF-PUCCH-Format1b": "deltaF3",
            "deltaF-PUCCH-Format2": "deltaF0",
            "deltaF-PUCCH-Format2a": "deltaF0",
            "deltaF-PUCCH-Format2b": "deltaF0",
        },
        "deltaPreambleMsg3": 2,
    },
    "antennaInfoCommon": {"antennaPortsCount": "an1"},
    "p-Max": 23,
    "tdd-Config": {"subframeAssignment": "sa1", "specialSubframePatterns": "ssp4"},
    "ul-CyclicPrefixLength": "len1",
}

_RRC_COMMON_MINIMAL = {
    "prach-Config": {"rootSequenceIndex": 22},
    "pusch-ConfigCommon": {
        "pusch-ConfigBasic": {
            "n-SB": 1,
            "hoppingMode": "interSubFrame",
            "pusch-HoppingOffset": 0,
            "enable64QAM": False,
        },
        "ul-ReferenceSignalsPUSCH": {
            "groupHoppingEnabled": False,
            "groupAssignmentPUSCH": 0,
            "sequenceHoppingEnabled": False,
            "cyclicShift": 0,
        },
    },
    "ul-CyclicPrefixLength": "len1",
}

_MEAS_FULL = {
    # The "to remove" lists are what a real reconfiguration carries when it
    # replaces a measurement configuration; leaving them out would leave the
    # "full" case with four modelled OPTIONALs unset, and the whole point of
    # that case is to set every bit of the optional bitmap PER spends.
    "measObjectToRemoveList": [2],
    "measObjectToAddModList": [
        {
            "measObjectId": 1,
            "measObject": {"measObjectEUTRA": {
                "carrierFreq": 1650,
                "allowedMeasBandwidth": "mbw100",
                "presenceAntennaPort1": True,
                "neighCellConfig": "00",
                "offsetFreq": "dB0",
                "cellsToRemoveList": [2],
                "cellsToAddModList": [
                    {"cellIndex": 1, "physCellId": 42, "cellIndividualOffset": "dB0"},
                ],
                "cellForWhichToReportCGI": 42,
            }},
        },
    ],
    "reportConfigToRemoveList": [2],
    "reportConfigToAddModList": [
        {
            "reportConfigId": 1,
            "reportConfig": {"reportConfigEUTRA": {
                "triggerType": {"event": {
                    "eventId": {"eventA3": {"a3-Offset": 4, "reportOnLeave": False}},
                    "hysteresis": 2,
                    "timeToTrigger": "ms320",
                }},
                "triggerQuantity": "rsrp",
                "reportQuantity": "sameAsTriggerQuantity",
                "maxReportCells": 4,
                "reportInterval": "ms480",
                "reportAmount": "r1",
            }},
        },
    ],
    "measIdToRemoveList": [2],
    "measIdToAddModList": [
        {"measId": 1, "measObjectId": 1, "reportConfigId": 1},
    ],
    "quantityConfig": {"quantityConfigEUTRA": {
        "filterCoefficientRSRP": "fc4",
        "filterCoefficientRSRQ": "fc4",
    }},
    "measGapConfig": {"setup": {"gapOffset": {"gp0": 3}}},
    "s-Measure": 20,
}

_RRC_DEDICATED_FULL = {
    "srb-ToAddModList": [
        {
            "srb-Identity": 1,
            "rlc-Config": {"explicitValue": {"am": {
                "ul-AM-RLC": {
                    "t-PollRetransmit": "ms100",
                    "pollPDU": "p8",
                    "pollByte": "kB1000",
                    "maxRetxThreshold": "t8",
                },
                "dl-AM-RLC": {"t-Reordering": "ms100", "t-StatusProhibit": "ms25"},
            }}},
            "logicalChannelConfig": {"explicitValue": {"ul-SpecificParameters": {
                "priority": 1,
                "prioritisedBitRate": "kBps8",
                "bucketSizeDuration": "ms100",
                "logicalChannelGroup": 0,
            }}},
        },
    ],
    "drb-ToReleaseList": [3],
    "mac-MainConfig": {"explicitValue": {
        "ul-SCH-Config": {
            "maxHARQ-Tx": "n4",
            "periodicBSR-Timer": "sf20",
            "retxBSR-Timer": "sf640",
            "ttiBundling": False,
        },
        "timeAlignmentTimerDedicated": "sf1280",
    }},
}

_MOBILITY_FULL = {
    "targetPhysCellId": 42,
    "carrierFreq": {"dl-CarrierFreq": 1650, "ul-CarrierFreq": 17650},
    "carrierBandwidth": {"dl-Bandwidth": "n100", "ul-Bandwidth": "n100"},
    "additionalSpectrumEmission": 1,
    "t304": "ms500",
    "newUE-Identity": "0x003c",
    "radioResourceConfigCommon": _RRC_COMMON_FULL,
    "rach-ConfigDedicated": {"ra-PreambleIndex": 12, "ra-PRACH-MaskIndex": 0},
}

_MOBILITY_MINIMAL = {
    "targetPhysCellId": 42,
    "t304": "ms500",
    "newUE-Identity": "0x003c",
    "radioResourceConfigCommon": _RRC_COMMON_MINIMAL,
}


def case_ies(case):
    """The operator-level input behind `reconfiguration_case`, as written.

    Kept separate so the oracle can feed the same intended message to this
    builder and to pycrate, and then check the two agree field by field.
    """
    if case == "minimal":
        ies = {"mobilityControlInfo": dict(_MOBILITY_MINIMAL)}
    elif case == "full":
        ies = {
            "measConfig": dict(_MEAS_FULL),
            "mobilityControlInfo": dict(_MOBILITY_FULL),
            "dedicatedInfoNASList": ["0102030405"],
            "radioResourceConfigDedicated": dict(_RRC_DEDICATED_FULL),
            "securityConfigHO": {"handoverType": {"intraLTE": {
                "securityAlgorithmConfig": {
                    "cipheringAlgorithm": "eea2",
                    "integrityProtAlgorithm": "eia2",
                },
                "keyChangeIndicator": True,
                "nextHopChainingCount": 3,
            }}},
        }
    else:
        raise Refused("unknown case %r (minimal, full)" % case)
    ies["transaction_identifier"] = 1
    return copy.deepcopy(ies)


def reconfiguration_case(case):
    """A named, known-good reconfiguration: `minimal` or `full`."""
    return reconfiguration(**case_ies(case))


CASES = ("minimal", "full")


# --------------------------------------------------------------------------
# describe: what a view models, and what it refuses.
# --------------------------------------------------------------------------

def describe(typename):
    node = TYPES.get(typename)
    if node is None:
        raise Refused("the generated table has no type %s" % typename)
    node = _deref(node, typename)
    if node["k"] == "choice":
        print("%s: CHOICE, %d alternatives in the table" % (typename, len(node["alts"])))
        spec = VIEWS.get(typename)
        modelled = spec[1] if spec else {}
        for name, alt in node["alts"]:
            mark = "modelled" if name in modelled else "NOT MODELLED (refused)"
            print("  %-40s %s" % (name, mark))
        for name in _extadd_names(node):
            print("  %-40s NOT MODELLED (extension addition, refused)" % name)
        return
    if node["k"] != "seq":
        print("%s: %s%s" % (typename, node["k"],
                            "" if typename not in VIEWS else " (modelled)"))
        return
    spec = VIEWS.get(typename)
    fields = dict(spec[1]) if spec and spec[0] == "seq" else {}
    print("%s: SEQUENCE, extensible=%s, %d root components in the table"
          % (typename, node["ext"], len(node["comp"])))
    for cname, _cnode, optional, default in node["comp"]:
        mark = "modelled" if cname in fields else \
            ("NOT MODELLED (refused)" + (" -- MANDATORY, so nothing builds" if not optional else ""))
        print("  %-40s %-4s %s" % (cname, "OPT" if optional else "MAND", mark))
    for name in _extadd_names(node):
        print("  %-40s %s" % (name, "NOT MODELLED (extension addition, refused)"))
    if node["ext"]:
        print("  (the extension bit is emitted as not-present)")


def _check_views():
    """Prove every view is a subset of the table it claims to describe.

    A view that names a component the table does not have, or omits a mandatory
    one, is a bug in this file and is reported as such -- never papered over.
    """
    problems = []
    kind_ok = {"int": ("int",), "enum": ("enum",), "bool": ("bool",), "null": ("null",),
               "bits": ("bits",), "crnti": ("bits",), "octets": ("octets",),
               "dl-dcch": ("octets",), "seq": ("seq",), "choice": ("choice",),
               "seqof": ("seqof",)}

    def walk(spec, node, path):
        kind = spec[0]
        if kind == "ref":
            if node["k"] != "ref" or node["t"] != spec[1]:
                problems.append("%s: table does not reference %s here" % (path, spec[1]))
                return
            if spec[1] not in VIEWS:
                problems.append("%s: view of %s is missing" % (path, spec[1]))
                return
            walk(VIEWS[spec[1]], TYPES[spec[1]], "%s:%s" % (path, spec[1]))
            return
        node = _deref(node, path)
        if node["k"] not in kind_ok.get(kind, ()):
            problems.append("%s: view says %s, table says %s" % (path, kind, node["k"]))
            return
        if kind == "seq":
            fields = spec[1]
            comps = dict((c[0], c) for c in node["comp"])
            for cname, _cn, optional, _d in node["comp"]:
                if cname not in fields and not optional:
                    problems.append("%s.%s: mandatory component is not in the view"
                                    % (path, cname))
            for fname, fspec in fields.items():
                if fname not in comps:
                    problems.append("%s.%s: the table has no such component (%s)"
                                    % (path, fname, ", ".join(comps)))
                    continue
                walk(fspec, comps[fname][1], "%s.%s" % (path, fname))
        elif kind == "choice":
            alts = dict((a[0], a[1]) for a in node["alts"])
            for aname, aspec in spec[1].items():
                if aname not in alts:
                    problems.append("%s.%s: the table has no such alternative (%s)"
                                    % (path, aname, ", ".join(alts)))
                    continue
                walk(aspec, alts[aname], "%s.%s" % (path, aname))
        elif kind == "seqof":
            walk(spec[1], node["of"], path + "[]")

    for typename, spec in VIEWS.items():
        if typename not in TYPES:
            problems.append("%s: not a type in the generated table" % typename)
            continue
        walk(spec, TYPES[typename], typename)

    if len(DL_DCCH_PREFIX) != 5 or DL_DCCH_PREFIX != "00100":
        problems.append("DL-DCCH envelope prefix changed: %r" % DL_DCCH_PREFIX)
    return problems


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

# Captured from pycrate 0.8.1 by tools/lte-rrc-oracle/verify_rrc.py, which
# re-derives them from pycrate on every run.  They are pinned here so a change
# in this tree that moves a bit is caught without the oracle venv.
PINNED = {
    ("reconfiguration", "minimal"): (88, "41000AA001E00005800000"),
    ("reconfiguration", "full"): (
        660,
        "43E7FC0040006419CAC00400153C54008000A20A06400100000410328F15419C913CAAA0"
        "80078FFB8B230C9B82C61014E40000080800568A71F6AAB352830001404080C101561813"
        "3368298090044CCC9122B0"),
    ("handover-command", "minimal"): (109, "0061104002A80078000160000000"),
    ("handover-command", "full"): (
        685,
        "02A110F9FF001000190672B00100054F150020002882819000400001040CA3C55067244F2"
        "AA82001E3FEE2C8C326E0B1840539000002020015A29C7DAAACD4A0C00050102030405586"
        "04CCDA0A60240113332448AC00"),
}


def selftest():
    failures = []
    ran = []

    def check(name, fn):
        ran.append(name)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 -- selftest must report everything
            failures.append("%s: %s: %s" % (name, type(exc).__name__, exc))

    check("views match the table", lambda: (_ for _ in ()).throw(
        AssertionError("; ".join(_check_views()))) if _check_views() else None)

    def template_round_trip():
        for case in CASES:
            value = reconfiguration_case(case)
            bits = CODEC.encode_bits("RRCConnectionReconfiguration", value)
            back, n = decode_bits("RRCConnectionReconfiguration", bits)
            assert n == len(bits), "case %s: decoded %d of %d bits" % (case, n, len(bits))
            assert CODEC.encode_bits("RRCConnectionReconfiguration", back) == bits, \
                "case %s: re-encoding the decoded value moved a bit" % case
            diffs = compare_message("RRCConnectionReconfiguration", value, back)
            assert not diffs, "case %s: %s" % (case, "; ".join(diffs))
            cmd = handover_command(value)
            cbits = CODEC.encode_bits("HandoverCommand", cmd)
            cback, cn = decode_bits("HandoverCommand", cbits)
            assert cn == len(cbits), "case %s: handover decoded %d of %d" % (
                case, cn, len(cbits))
            assert CODEC.encode_bits("HandoverCommand", cback) == cbits, \
                "case %s: re-encoding the decoded handover command moved a bit" % case

    def handover_container_matches():
        # The container must be the same reconfiguration, byte for byte, and the
        # DL-DCCH envelope must be the five bits this file hard-codes.
        value = reconfiguration_case("full")
        cmd = handover_command(value)
        inner_bits = CODEC.encode_bits("RRCConnectionReconfiguration", value)
        container = cmd["criticalExtensions"][1][1]["handoverCommandMessage"]
        bits = "".join(format(b, "08b") for b in container)
        assert bits.startswith(DL_DCCH_PREFIX), "container has no DL-DCCH envelope"
        assert bits[len(DL_DCCH_PREFIX):len(DL_DCCH_PREFIX) + len(inner_bits)] == inner_bits, \
            "container does not carry the reconfiguration it was built from"
        assert set(bits[len(DL_DCCH_PREFIX) + len(inner_bits):]) <= {"0"}, \
            "container padding is not zero"
    check("template round trips", template_round_trip)
    check("handover container", handover_container_matches)

    def refusals():
        bomb = [
            ("unknown component",
             lambda: build("RRCConnectionReconfiguration_r8_IEs", {"nonCriticalExtension": {}})),
            ("unknown name",
             lambda: build("RRCConnectionReconfiguration_r8_IEs", {"nosuchfield": 1})),
            ("extension addition",
             lambda: build("MeasObjectEUTRA", {"carrierFreq": 1, "allowedMeasBandwidth": "mbw6",
                                               "presenceAntennaPort1": True,
                                               "neighCellConfig": 0, "measCycleSCell-r13": 1})),
            ("integer above the root range",
             lambda: build("RRC_TransactionIdentifier", 4)),
            ("integer below the root range",
             lambda: build("PhysCellId", -1)),
            ("c-rnti too wide",
             lambda: build("MobilityControlInfo", {
                 "targetPhysCellId": 1, "t304": "ms500", "newUE-Identity": "0x10000",
                 "radioResourceConfigCommon": dict(_RRC_COMMON_MINIMAL)})),
            ("enum name not in the table",
             lambda: build("MobilityControlInfo", {
                 "targetPhysCellId": 1, "t304": "ms501", "newUE-Identity": 1,
                 "radioResourceConfigCommon": dict(_RRC_COMMON_MINIMAL)})),
            ("empty SEQUENCE OF that is not extensible",
             lambda: build("MeasConfig", {"measObjectToRemoveList": []})),
            ("unmodelled CHOICE alternative",
             lambda: build("RLC_Config", {"um-Bi-Directional": {"ul-UM-RLC": {}}})),
            ("raw octets where a built message belongs",
             lambda: build("HandoverCommand_r8_IEs", {"handoverCommandMessage": "0011"})),
            ("missing mandatory component",
             lambda: build("CellsToAddMod", {"cellIndex": 1})),
            ("boolean given an integer",
             lambda: build("MeasObjectEUTRA", {"carrierFreq": 1, "allowedMeasBandwidth": "mbw6",
                                               "presenceAntennaPort1": 1,
                                               "neighCellConfig": 0})),
        ]
        for name, fn in bomb:
            try:
                fn()
            except Refused:
                continue
            raise AssertionError("REFUSED expected for: %s" % name)
    check("refusals", refusals)

    def pins():
        for (what, case), (want_len, want_hex) in PINNED.items():
            value = reconfiguration_case(case)
            typename = ("RRCConnectionReconfiguration" if what == "reconfiguration"
                        else "HandoverCommand")
            if what == "handover-command":
                value = handover_command(value)
            bits = CODEC.encode_bits(typename, value)
            got_hex = CODEC.encode_hex(typename, value)
            assert want_len is not None, "%s/%s is not pinned yet" % (what, case)
            assert len(bits) == want_len, "%s/%s: %d bits, pinned %d" % (
                what, case, len(bits), want_len)
            assert got_hex == want_hex, "%s/%s: hex moved\n want %s\n got  %s" % (
                what, case, want_hex, got_hex)
    check("pinned vectors", pins)

    for line in failures:
        print("FAIL %s" % line)
    if failures:
        print("selftest: %d of %d checks failed" % (len(failures), len(ran)))
        return 1
    print("selftest: %d checks passed" % len(ran))
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _parse_set(items, path):
    """--set PATH=VALUE, with VALUE as JSON, as a plain string, or @FILE."""
    out = {}
    for item in items or ():
        if "=" not in item:
            raise Refused("--set wants PATH=VALUE, got %r" % item)
        key, raw = item.split("=", 1)
        if raw.startswith("@"):
            with open(raw[1:], "r") as handle:
                value = json.load(handle)
        else:
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw
        node = out
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise Refused("--set %s: %s is already set to a value" % (key, part))
        node[parts[-1]] = value
    return out


def _body_from_args(args):
    """The r8-IEs body, from either --json (whole message) or --set (relative)."""
    if args.json:
        with open(args.json, "r") as handle:
            return json.load(handle), True
    return _parse_set(args.set, "r8-IEs"), False


def _emit(args, typename, value):
    bits = CODEC.encode_bits(typename, value)
    hexstr = CODEC.encode_hex(typename, value)
    if args.bits:
        print(bits)
    if args.hex:
        print(hexstr)
    if args.bitlen:
        print(len(bits))
    if args.value:
        print(json.dumps(_render(value), indent=2, sort_keys=True))
    if args.bits or args.hex or args.bitlen or args.value:
        return 0
    print("type      %s" % typename)
    print("bitlen    %d" % len(bits))
    print("hex       %s" % hexstr)
    return 0


def cmd_reconfiguration(args):
    body, whole = _body_from_args(args)
    if whole:
        value = build("RRCConnectionReconfiguration", body)
    else:
        value = reconfiguration(transaction_identifier=args.tx, **body)
    return _emit(args, "RRCConnectionReconfiguration", value)


def cmd_handover_command(args):
    body, whole = _body_from_args(args)
    if whole:
        inner = build("RRCConnectionReconfiguration", body)
    else:
        inner = reconfiguration(transaction_identifier=args.tx, **body)
    return _emit(args, "HandoverCommand", handover_command(inner))


def _ul_dcch_setup_complete(value):
    """Put a Setup Complete where TS 36.331 10.5 wants it: inside a UL-DCCH.

    Same shape as `_wrap_dl_dcch`: the true bit string is envelope + body, and
    only the transport pads it to octets, so the padding is reported rather
    than hidden.
    """
    bits = CODEC.encode_bits("RRCConnectionSetupComplete", value)
    return UL_DCCH_SETUP_COMPLETE_PREFIX, bits


def cmd_setup_complete(args):
    nas = args.nas
    value = build("RRCConnectionSetupComplete", {
        "rrc-TransactionIdentifier": args.tx,
        "criticalExtensions": {"c1": {"rrcConnectionSetupComplete-r8": {
            "selectedPLMN-Identity": args.plmn,
            "dedicatedInfoNAS": nas,
        }}},
    })
    prefix, body = _ul_dcch_setup_complete(value)
    whole = prefix + body
    padded = whole + "0" * (-len(whole) % 8)
    octets = bytes(int(padded[i:i + 8], 2) for i in range(0, len(padded), 8))
    if args.bits:
        print(whole)
    if args.hex:
        print(octets.hex())
    if args.bitlen:
        print(len(whole))
    if args.value:
        print(json.dumps(_render(value), indent=2, sort_keys=True))
    if args.bits or args.hex or args.bitlen or args.value:
        return 0
    print("type      RRCConnectionSetupComplete")
    print("envelope  UL-DCCH-Message/c1/rrcConnectionSetupComplete-r8 (%s)"
          % UL_DCCH_SETUP_COMPLETE_PREFIX)
    print("bitlen    %d%s" % (len(whole), "" if len(padded) == len(whole)
                              else "  (%d pad bits to octets)" % (len(padded) - len(whole))))
    print("octets    %d" % len(octets))
    print("hex       %s" % octets.hex())
    return 0


def cmd_template(args):
    inner = reconfiguration_case(args.case)
    if args.message == "handover-command":
        return _emit(args, "HandoverCommand", handover_command(inner))
    return _emit(args, "RRCConnectionReconfiguration", inner)


def cmd_bitlen(args):
    if args.case:
        inner = reconfiguration_case(args.case)
    else:
        body, whole = _body_from_args(args)
        if args.type == "handover-command":
            inner = build("RRCConnectionReconfiguration", body) if whole else \
                reconfiguration(transaction_identifier=args.tx, **body)
            bits = CODEC.encode_bits("HandoverCommand", handover_command(inner))
            print(len(bits))
            return 0
        inner = build("RRCConnectionReconfiguration", body) if whole else \
            reconfiguration(transaction_identifier=args.tx, **body)
    if args.type == "handover-command":
        bits = CODEC.encode_bits("HandoverCommand", handover_command(inner))
    else:
        bits = CODEC.encode_bits("RRCConnectionReconfiguration", inner)
    print(len(bits))
    return 0


def cmd_decode(args):
    bits = _bits_of_hex(args.hex, "--hex")
    if args.bits is not None:
        if args.bits > len(bits):
            raise Refused("--bits %d is more than the %d bits given" % (args.bits, len(bits)))
        bits = bits[:args.bits]
    if args.type == "reconfiguration":
        value, n = decode_bits("RRCConnectionReconfiguration", bits)
        print("type      RRCConnectionReconfiguration")
        print("bitlen    %d%s" % (n, "" if n == len(bits) else
                                  "  (of %d bits given)" % len(bits)))
        print(json.dumps(_render(value), indent=2, sort_keys=True))
        return 0

    if args.type == "setup-complete":
        if not bits.startswith(UL_DCCH_SETUP_COMPLETE_PREFIX):
            raise Refused("the container is not a UL-DCCH-Message carrying "
                          "rrcConnectionSetupComplete (prefix %s, got %s)"
                          % (UL_DCCH_SETUP_COMPLETE_PREFIX, bits[:5]))
        value, n = decode_bits("RRCConnectionSetupComplete",
                               bits[len(UL_DCCH_SETUP_COMPLETE_PREFIX):])
        print("type      RRCConnectionSetupComplete")
        print("envelope  UL-DCCH-Message/c1/rrcConnectionSetupComplete-r8 (%s)"
              % UL_DCCH_SETUP_COMPLETE_PREFIX)
        print("bitlen    %d%s" % (n + len(UL_DCCH_SETUP_COMPLETE_PREFIX),
                                  "" if n + len(UL_DCCH_SETUP_COMPLETE_PREFIX) == len(bits)
                                  else "  (of %d bits given)" % len(bits)))
        nas = value["criticalExtensions"][1][1].get("dedicatedInfoNAS", b"")
        print("plmn      %s" % value["criticalExtensions"][1][1]
              .get("selectedPLMN-Identity"))
        print("nas_octets %d" % len(nas))
        print("nas_hex   %s" % bytes(nas).hex())
        print(json.dumps(_render(value), indent=2, sort_keys=True))
        return 0

    cmd, n = decode_bits("HandoverCommand", bits)
    print("type      HandoverCommand")
    print("bitlen    %d%s" % (n, "" if n == len(bits) else "  (of %d bits given)" % len(bits)))
    container = cmd["criticalExtensions"][1][1]["handoverCommandMessage"]
    print("container %d bytes" % len(container))
    cbits = "".join(format(b, "08b") for b in container)
    if not cbits.startswith(DL_DCCH_PREFIX):
        raise Refused("the container is not a DL-DCCH-Message carrying "
                      "rrcConnectionReconfiguration (prefix %s, got %s)"
                      % (DL_DCCH_PREFIX, cbits[:5]))
    print("envelope  DL-DCCH-Message/c1/rrcConnectionReconfiguration (%s)"
          % DL_DCCH_PREFIX)
    value, inner_n = decode_bits("RRCConnectionReconfiguration",
                                 cbits[len(DL_DCCH_PREFIX):])
    print("inner     RRCConnectionReconfiguration, %d bits, %d pad bits"
          % (inner_n, len(cbits) - len(DL_DCCH_PREFIX) - inner_n))
    print(json.dumps(_render(value), indent=2, sort_keys=True))
    return 0


def cmd_describe(args):
    describe(args.type)
    return 0


def cmd_build(args):
    body, whole = _body_from_args(args)
    if not whole:
        raise Refused("build wants --json (the whole value)")
    # Through build(), not straight to the engine: the view is what range-checks
    # an INTEGER and refuses a component this tree does not model.  Encoding the
    # raw dict would send an out-of-range value that looks fine in hex.
    return _emit(args, args.type, build(args.type, body))


def _add_emit_flags(p):
    p.add_argument("--bits", action="store_true",
                   help="print the encoded bit string (the true length, unpadded)")
    p.add_argument("--hex", action="store_true",
                   help="print the encoding as hex, padded to whole octets")
    p.add_argument("--bitlen", action="store_true", help="print the bit length")
    p.add_argument("--value", action="store_true",
                   help="print the built value as JSON (octet strings as hex)")


def _add_source_flags(p, message):
    p.add_argument("--json", metavar="FILE",
                   help="read the whole %s value from a JSON file" % message)
    p.add_argument("--set", action="append", metavar="PATH=VALUE", default=[],
                   help="set a component by its ASN.1 name, relative to the r8-IEs "
                        "(repeatable; VALUE is JSON or a plain string)")
    p.add_argument("--tx", type=int, default=0, metavar="N",
                   help="rrc-TransactionIdentifier (0..3); ignored with --json")


def main(argv):
    p = argparse.ArgumentParser(
        prog="lte_rrc.py",
        description="Build, inspect and decode the LTE handover RRC messages "
                    "(TS 36.331 RRCConnectionReconfiguration and the inter-node "
                    "HandoverCommand). Fields this tree does not model are refused, "
                    "never silently dropped.")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("reconfiguration", help="build an RRCConnectionReconfiguration")
    _add_source_flags(r, "RRCConnectionReconfiguration")
    _add_emit_flags(r)
    r.set_defaults(func=cmd_reconfiguration)

    h = sub.add_parser("handover-command",
                       help="build an inter-node HandoverCommand carrying a "
                            "reconfiguration in its DL-DCCH container")
    _add_source_flags(h, "HandoverCommand")
    _add_emit_flags(h)
    h.set_defaults(func=cmd_handover_command)

    t = sub.add_parser("template",
                       help="emit a known-good handover template: `minimal` (only "
                            "what a handover must carry) or `full` (every modelled "
                            "optional present)")
    t.add_argument("--case", choices=CASES, default="full")
    t.add_argument("--message", choices=("reconfiguration", "handover-command"),
                   default="reconfiguration")
    _add_emit_flags(t)
    t.set_defaults(func=cmd_template)

    b = sub.add_parser("bitlen", help="report the bit length of a message")
    b.add_argument("--type", choices=("reconfiguration", "handover-command"),
                   default="reconfiguration")
    b.add_argument("--case", choices=CASES, default=None,
                   help="use a template instead of --set/--json")
    _add_source_flags(b, "message")
    b.set_defaults(func=cmd_bitlen)

    d = sub.add_parser("decode", help="decode a message, and for a handover command "
                                      "the reconfiguration in its container")
    s2 = sub.add_parser("setup-complete",
                        help="build the UE's RRCConnectionSetupComplete on UL-DCCH, "
                             "carrying the first NAS PDU")
    s2.add_argument("--nas", required=True, metavar="HEX",
                    help="the NAS PDU as hex (dedicatedInfoNAS)")
    s2.add_argument("--plmn", type=int, default=1, metavar="N",
                    help="selectedPLMN-Identity, 1..maxPLMN (default 1)")
    s2.add_argument("--tx", type=int, default=0, metavar="N",
                    help="rrc-TransactionIdentifier (0..3)")
    _add_emit_flags(s2)
    s2.set_defaults(func=cmd_setup_complete)

    d.add_argument("--type", choices=("reconfiguration", "handover-command", "setup-complete"),
                   required=True)
    d.add_argument("--hex", required=True, help="the encoding, as hex")
    d.add_argument("--bits", type=int, default=None,
                   help="the true bit length, if the hex was padded")
    d.set_defaults(func=cmd_decode)

    s = sub.add_parser("describe",
                       help="list the components of a type, marking each as modelled "
                            "or refused")
    s.add_argument("type")
    s.set_defaults(func=cmd_describe)

    g = sub.add_parser("build", help="build any type this tool has a view of, from --json")
    g.add_argument("type")
    _add_source_flags(g, "value")
    _add_emit_flags(g)
    g.set_defaults(func=cmd_build)

    sub.add_parser("selftest", help="check the views against the table, the pinned "
                                    "vectors, refusals and round trips")

    args = p.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    if args.cmd is None:
        p.print_help()
        return 2
    if not hasattr(args, "func"):
        p.print_help()
        return 2
    try:
        return args.func(args)
    except Refused as exc:
        sys.stderr.write("REFUSED: %s\n" % exc)
        return 2
    except lte_per.PerError as exc:
        sys.stderr.write("REFUSED (PER engine): %s\n" % exc)
        return 2
    except json.JSONDecodeError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except OSError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
