#!/usr/bin/env python3
"""Differential check of the SS7/MAP codec in modules/26_ss7_map.sh.

The statement of the clauses, written out here as code:

* ITU-T Q.704 2.2 -- the MTP3 routing label is four octets: the destination
  point code in fourteen bits, the originating point code in fourteen bits and
  a four-bit signalling link selection, low octet first, with bit 7 and 8 of
  the last octet carrying the top of the OPC and the SLS.
* ITU-T Q.713 3.4.1 -- address indicator: bit 1 point code present, bit 2 SSN
  present, bits 3-6 the global title indicator, bit 7 routing (1 = on SSN).
* ITU-T Q.713 3.4.2 -- the address elements occur in the order point code,
  subsystem number, global title; the point code is two octets with the top
  two bits of the second octet zero.
* ITU-T Q.713 3.4.2.2 -- the subsystem number registry (0-15 assigned by
  ITU-T, 16-254 national, 255 expansion).
* ITU-T Q.713 Table 11 and 1.4 -- UDT: message type 9, protocol class, three
  pointers, then CDPA, CGPA and data, each as a length octet and its contents.
  A pointer is the distance from its own octet to the parameter's length
  octet, so the first is 3, the second 3 + 1 + len(CDPA), and the third one
  further.
* ITU-T Q.773 3.1 -- TCAP tags: 0x61 unidirectional, 0x62 begin, 0x64 end,
  0x65 continue, 0x67 abort; the component portion is 0x6C and its components
  are 0xA1 invoke, 0xA2 returnResult, 0xA3 returnError, 0xA4 reject, each
  starting with an invoke identifier as a universal INTEGER.
* TS 29.002 17.5 -- the assigned MAP operation codes (`CODE local:N`), the
  operations the clause names as withdrawn, and the older ones the dissector
  still names.
* TS 29.002 17.7.5 -- the assigned SS-Codes, 72 of them.
* TS 29.002 17.7.1 -- RegisterSS-Arg: ss-Code is a plain SS-Code (no context
  tag), forwardedToNumber is [4].
* TS 23.003 3.3 -- TBCD: two digits per octet, the lower digit first; an odd
  number of digits is padded with F as the high nibble of the last octet.

Nothing here is taken from the module. The tables come from the clause text,
the encoders are written from the clause text, and the module is driven
through its own command line. Where the dissector (Wireshark 4.2.2) is the
second implementation, the section is skipped when it is not installed.

Run:  python3 tools/ss7-oracle/check_ss7_codec.py [--module PATH] [--negctl]
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

MODULE = "modules/26_ss7_map.sh"
BASH = os.environ.get("BASH", "bash")

CASES = 0
MISMATCHES = 0
NOTES = 0


def _table(block):
    out = {}
    for line in block.strip().splitlines():
        if not line.strip():
            continue
        code, name = line.split(":", 1)
        out[int(code)] = name
    return out


# TS 29.002 17.5: every operation the clause assigns with CODE local:N.
OPS = _table("""
2:updateLocation
3:cancelLocation
4:provideRoamingNumber
5:noteSubscriberDataModified
6:resumeCallHandling
7:insertSubscriberData
8:deleteSubscriberData
10:registerSS
11:eraseSS
12:activateSS
13:deactivateSS
14:interrogateSS
15:authenticationFailureReport
17:registerPassword
18:getPassword
20:releaseResources
21:mt-ForwardSM-VGCS
22:sendRoutingInfo
23:updateGprsLocation
24:sendRoutingInfoForGprs
25:failureReport
26:noteMsPresentForGprs
29:sendEndSignal
33:processAccessSignalling
34:forwardAccessSignalling
36:cancelVcsgLocation
37:reset
38:forwardCheckSS-Indication
39:prepareGroupCall
40:sendGroupCallEndSignal
41:processGroupCallSignalling
42:forwardGroupCallSignalling
43:checkIMEI
44:mt-ForwardSM
45:sendRoutingInfoForSM
46:mo-ForwardSM
47:reportSM-DeliveryStatus
50:activateTraceMode
51:deactivateTraceMode
53:updateVcsgLocation
55:sendIdentification
56:sendAuthenticationInfo
57:restoreData
58:sendIMSI
59:processUnstructuredSS-Request
60:unstructuredSS-Request
61:unstructuredSS-Notify
62:anyTimeSubscriptionInterrogation
63:informServiceCentre
64:alertServiceCentre
65:anyTimeModification
66:readyForSM
67:purgeMS
68:prepareHandover
69:prepareSubsequentHandover
70:provideSubscriberInfo
71:anyTimeInterrogation
72:ss-InvocationNotification
73:setReportingState
74:statusReport
75:remoteUserFree
76:registerCC-Entry
77:eraseCC-Entry
83:provideSubscriberLocation
84:sendGroupCallInfo
85:sendRoutingInfoForLCS
86:subscriberLocationReport
87:ist-Alert
88:ist-Command
89:noteMM-Event
""")

# TS 29.002 17.5: the operations the clause lists in its "reserved for older
# versions of this specification" comment -- real on live networks, withdrawn
# from the current module body.
WITHDRAWN = _table("""
9:sendParameters
19:processUnstructuredSS-Data
28:performHandover
30:performSubsequentHandover
31:provideSIWFSNumber
32:siwfs-SignallingModify
35:noteInternalHandover
48:noteSubscriberPresent
49:alertServiceCentreWithoutResult
52:traceSubscriberActivity
54:beginSubscriberActivity
""")

# Operations that the clause no longer defines and the dissector still names:
# the 1999 secure transport classes, the LCS work items and the CC-entry
# operands. Kept so a capture of an old network still decodes.
HISTORIC = _table("""
16:notifySS
78:secureTransportClass1
79:secureTransportClass2
80:secureTransportClass3
81:secureTransportClass4
109:lcs-PeriodicLocationCancellation
110:lcs-LocationUpdate
111:lcs-PeriodicLocationRequest
112:lcs-AreaEventCancellation
113:lcs-AreaEventReport
114:lcs-AreaEventRequest
115:lcs-MOLR
116:lcs-LocationNotification
117:callDeflection
118:userUserService
119:accessRegisterCCEntry
120:forwardCUG-Info
121:splitMPTY
122:retrieveMPTY
123:holdMPTY
124:buildMPTY
125:forwardChargeAdvice
126:explicitCT
""")

# The dissector's own spelling for the ITU values (Wireshark 4.2.2), which is
# what the module's table says it read back. The module may add a gloss after
# the short name, so the check looks for containment.
SSN_DISSECTOR = {
    1: "SCCP management",
    2: "Reserved for ITU-T allocation",
    3: "ISDN User Part",
    4: "OMAP (Operation, Maintenance, and Administration Part)",
    5: "MAP (Mobile Application Part)",
    6: "HLR (Home Location Register)",
    7: "VLR (Visitor Location Register)",
    8: "MSC (Mobile Switching Center)",
    9: "EIC/EIR (Equipment Identifier Center/Equipment Identification Register)",
    10: "AUC/AC (Authentication Center)",
    11: "ISDN supplementary services (ITU only)",
    12: "Reserved for international use (ITU only)",
    13: "Broadband ISDN edge-to-edge applications (ITU only)",
    14: "TC test responder (ITU only)",
}

# TS 29.002 17.7.5: every SS-Code the clause assigns.
SS = _table("""
0:allSS
16:allLineIdentificationSS
17:clip
18:clir
19:colp
20:colr
21:mci
24:allNameIdentificationSS
25:cnap
32:allForwardingSS
33:cfu
36:cd
40:allCondForwardingSS
41:cfb
42:cfnry
43:cfnrc
48:allCallOfferingSS
49:ect
50:mah
64:allCallCompletionSS
65:cw
66:hold
67:ccbs-A
68:ccbs-B
69:mc
80:allMultiPartySS
81:multiPTY
96:allCommunityOfInterest-SS
97:cug
112:allChargingSS
113:aoci
114:aocc
128:allAdditionalInfoTransferSS
129:uus1
130:uus2
131:uus3
144:allBarringSS
145:barringOfOutgoingCalls
146:baoc
147:boic
148:boicExHC
153:barringOfIncomingCalls
154:baic
155:bicRoam
160:allCallPrioritySS
161:emlpp
176:allLCSPrivacyException
177:universal
178:callSessionRelated
179:callSessionUnrelated
180:plmnoperator
181:serviceType
192:allMOLR-SS
193:basicSelfLocation
194:autonomousSelfLocation
195:transferToThirdParty
240:allPLMN-specificSS
241:plmn-specificSS-1
242:plmn-specificSS-2
243:plmn-specificSS-3
244:plmn-specificSS-4
245:plmn-specificSS-5
246:plmn-specificSS-6
247:plmn-specificSS-7
248:plmn-specificSS-8
249:plmn-specificSS-9
250:plmn-specificSS-A
251:plmn-specificSS-B
252:plmn-specificSS-C
253:plmn-specificSS-D
254:plmn-specificSS-E
255:plmn-specificSS-F
""")

# ITU-T Q.713 3.4.2.2, 0-15. 15 and above are left unnamed by the module
# unless a national value is assigned, so only these are named here.
SSN_ITU = {
    0: "SSN not known/not used",
    1: "SCCP management",
    2: "Reserved for ITU-T allocation",
    3: "ISDN user part",
    4: "operation, maintenance and administration part (OMAP)",
    5: "mobile application part (MAP)",
    6: "home location register (HLR)",
    7: "visitor location register (VLR)",
    8: "mobile switching centre (MSC)",
    9: "equipment identifier centre (EIC)",
    10: "authentication centre (AUC)",
    11: "ISDN supplementary services",
    12: "reserved for international use",
    13: "broadband ISDN edge-to-edge applications",
    14: "TC test responder",
}

# The national values 3GPP assigns (TS 23.003 8.5 / the MAP subsystem table the
# dissector carries). The module must name exactly these and nothing else.
SSN_NATIONAL = {142, 143, 145, 146, 147, 148, 149, 150, 248, 249, 250, 251,
                252, 253, 254}

SSN_3GPP = {
    142: "RANAP", 143: "RNSAP", 145: "GMLC(MAP)", 146: "CAP",
    147: "gsmSCF (MAP) or IM-SSF (MAP) or Presence Network Agent",
    148: "SIWF (MAP)", 149: "SGSN (MAP)", 150: "GGSN (MAP)",
    248: "CSS (MAP)", 249: "PCAP", 250: "BSC (BSSAP-LE)",
    251: "MSC (BSSAP-LE)", 252: "IOS or SMLC (BSSAP-LE)",
    253: "BSS O&M (A interface)", 254: "BSSAP/BSAP",
}

# ── helpers ────────────────────────────────────────────────────────────────
import struct

TSHARK = os.environ.get("TSHARK", "tshark")

QUIET = False
CASES = []
SECTIONS = {}


def short_name(name):
    """The dissector's distinctive name without its gloss."""
    import re
    return re.sub(r"\s*\(.*", "", name).strip()


def section(key):
    def wrap(fn):
        SECTIONS[key] = fn
        return fn
    return wrap


def show(v):
    if isinstance(v, bytes):
        return v.hex().upper()
    return str(v).replace("\n", "\\n").replace("\t", "\\t")


def add(case, want, got):
    CASES.append((case, want, got))
    if want != got and not QUIET:
        print("MISMATCH\t" + case + "\twant=" + show(want) + "\tgot=" + show(got))


def run(module, *args):
    p = subprocess.run([BASH, module] + list(args), capture_output=True)
    return (p.returncode,
            p.stdout.decode("latin-1"),
            p.stderr.decode("latin-1"))


def rows(out):
    return [line.split("\t") for line in out.split("\n") if line]


def get(out, key, default=""):
    for parts in rows(out):
        if parts[0] == key:
            return parts[1] if len(parts) > 1 else ""
    return default


def get_all(out, key):
    return [parts[1] if len(parts) > 1 else "" for parts in rows(out)
            if parts[0] == key]


def full_rows(out, key):
    """Every row whose first field is `key`, as tab-joined text."""
    return ["\t".join(parts) for parts in rows(out) if parts[0] == key]


def batch_scan(module, func):
    """Call a module function for 0..255 inside one bash process.

    The registries are the module's tables; reading them 256 times through
    the CLI would cost 256 processes, so the sourced form is used for the
    coverage sweep and the CLI form for the authority rows.
    """
    code = ('source "$1" >/dev/null 2>&1; '
            'for i in $(seq 0 255); do '
            'printf "%d\\t%s\\n" "$i" "$( ' + func + ' "$i" )"; done')
    p = subprocess.run([BASH, "-c", code, "scan", module], capture_output=True)
    text = p.stdout.decode("latin-1")
    out = {}
    for line in text.split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            out[int(parts[0])] = parts[1]
    return out


# ── ASN.1 / SS7 encoders written from the clauses ──────────────────────────
def blen(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + blen(len(body)) + body


def int_tlv(v):
    if v == 0:
        b = b"\x00"
    else:
        b = v.to_bytes((v.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
    return tlv(0x02, b)


def parse_tlv(b, i=0):
    tag = b[i]
    i += 1
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > len(b):
        raise ValueError("length runs past the buffer")
    return tag, b[i:i + n], i + n


def tbcd(digits):
    """TS 29.002 TBCD: two digits per octet, the FIRST digit in the low
    nibble, an odd trailing digit padded with F in the high nibble."""
    d = digits.strip()
    if len(d) % 2:
        d += "F"
    return bytes(int(d[i + 1] + d[i], 16) for i in range(0, len(d), 2))


def tbcd_digits(octets):
    out = []
    for octet in octets:
        out.append("%X" % (octet & 0x0F))
        out.append("%X" % (octet >> 4))
    return "".join(out).rstrip("F")


def isdn_addr(digits):
    return b"\x91" + tbcd(digits)


def label(dpc, opc, sls):
    return bytes([dpc & 0xFF,
                  ((dpc >> 8) & 0x3F) | ((opc & 0x03) << 6),
                  (opc >> 2) & 0xFF,
                  ((opc >> 10) & 0x0F) | ((sls & 0x0F) << 4)])


def sio_octet(si=3, ni=2, spare=0):
    return (ni << 6) | (spare << 4) | si


def sccp_addr(pc=None, ssn=None, ri=0, gt=None):
    """Q.713 3.4.2.2: bit 7 routeing indicator, bit 0 PC, bit 1 SSN,
    bits 2-5 global title indicator."""
    ai = (ri & 1) << 6
    body = b""
    if pc is not None:
        ai |= 0x01
        body += bytes([pc & 0xFF, (pc >> 8) & 0xFF])
    if ssn is not None:
        ai |= 0x02
        body += bytes([ssn])
    if gt is not None:
        ai |= 0x10          # global title indicator 0100
        body += gt
    return bytes([ai]) + body


def parse_addr(a):
    ai = a[0]
    i = 1
    pc = ssn = None
    if ai & 0x01:
        pc = a[i] | ((a[i + 1] & 0x3F) << 8)
        i += 2
    if ai & 0x02:
        ssn = a[i]
        i += 1
    return {"ai": ai, "pc": pc, "ssn": ssn, "rest": a[i:]}


def udt(cdpa, cgpa, data, mt=0x09, cls=0):
    """Q.713 §4.2 UDT; the pointers are distances from the octet that holds
    them (indexes 2, 3, 4) to the length octet of their parameter."""
    # Each pointer is the distance from its own octet (indexes 2, 3, 4) to
    # the length octet of its parameter: the called-party length octet is at
    # 5, the calling-party one at 6 + len(cdpa) and the data one after that.
    p1 = 3
    p2 = 3 + len(cdpa)
    p3 = p2 + len(cgpa)
    return (bytes([mt, (cls & 0x0F) << 4, p1, p2, p3])
            + bytes([len(cdpa)]) + cdpa
            + bytes([len(cgpa)]) + cgpa
            + bytes([len(data)]) + data)


def parse_udt(b):
    if b[0] != 0x09:
        raise ValueError("not a UDT")
    def param(ptr_index):
        off = ptr_index + b[ptr_index]
        n = b[off]
        return b[off + 1:off + 1 + n]
    return {"class": (b[1] >> 4) & 0x0F,
            "cdpa": parse_addr(param(2)),
            "cgpa": parse_addr(param(3)),
            "data": param(4)}


def msu(sccp, dpc=1, opc=2, sls=0, si=3, ni=2, spare=0):
    return bytes([sio_octet(si, ni, spare)]) + label(dpc, opc, sls) + sccp


def tcap(tag, otid=None, dtid=None, comps=b""):
    body = b""
    if otid is not None:
        body += tlv(0x48, otid.to_bytes(4, "big"))
    if dtid is not None:
        body += tlv(0x49, dtid.to_bytes(4, "big"))
    if comps:
        body += tlv(0x6C, comps)
    return tlv(tag, body)


def comp_invoke(iid, op, arg=b""):
    return tlv(0xA1, int_tlv(iid) + int_tlv(op) + arg)


def comp_return_last(iid, op, res=b""):
    return tlv(0xA2, int_tlv(iid) + tlv(0x30, int_tlv(op) + res))


def comp_return_not_last(iid, op, res=b""):
    return tlv(0xA7, int_tlv(iid) + tlv(0x30, int_tlv(op) + res))


def comp_error(iid, code):
    return tlv(0xA3, int_tlv(iid) + int_tlv(code))


def comp_reject(iid, ptag, value):
    """Q.773 3.3.4: the problem is a CHOICE tagged [0] general, [1] invoke,
    [2] returnResult, [3] returnError -- a context tag, not an INTEGER."""
    return tlv(0xA4, int_tlv(iid) + tlv(ptag, bytes([value])))


def parse_tcap(b):
    tag, body, _ = parse_tlv(b, 0)
    out = {"tag": tag, "otid": None, "dtid": None, "comps": []}
    i = 0
    while i < len(body):
        t, v, i = parse_tlv(body, i)
        if t == 0x48:
            out["otid"] = int.from_bytes(v, "big")
        elif t == 0x49:
            out["dtid"] = int.from_bytes(v, "big")
        elif t == 0x6C:
            out["comps"] = parse_comps(v)
    return out


def parse_comps(b):
    out = []
    i = 0
    while i < len(b):
        t, v, i = parse_tlv(b, i)
        comp = {"tag": t, "iid": None, "op": None, "arg": b""}
        j = 0
        if j < len(v):
            t2, v2, j = parse_tlv(v, j)
            if t2 == 0x02:
                comp["iid"] = int.from_bytes(v2, "big")
        if t in (0xA2, 0xA7):
            if j < len(v):
                t3, v3, j = parse_tlv(v, j)
                if t3 == 0x30:
                    k = 0
                    if v3:
                        t4, v4, k = parse_tlv(v3, 0)
                        if t4 == 0x02:
                            comp["op"] = int.from_bytes(v4, "big")
                    comp["arg"] = v3[k:]
        elif t == 0xA1:
            if j < len(v):
                t3, v3, j = parse_tlv(v, j)
                if t3 == 0x02:
                    comp["op"] = int.from_bytes(v3, "big")
                comp["arg"] = v[j:]
        else:
            comp["arg"] = v[j:]
        out.append(comp)
    return out


def sctp_data(payload, ppid=3, sport=2905, dport=2905, tsn=1, sid=0, ssn=0):
    chunk = (bytes([0x00, 0x03]) + struct.pack(">H", 16 + len(payload))
             + struct.pack(">IHHI", tsn, sid, ssn, ppid) + payload)
    return struct.pack(">HHII", sport, dport, 0, 0) + chunk


def m3ua_data(msu_bytes):
    param = struct.pack(">HH", 0x0210, 4 + len(msu_bytes)) + msu_bytes
    return bytes([1, 0, 1, 1]) + struct.pack(">I", 8 + len(param)) + param


# ── checks ─────────────────────────────────────────────────────────────────
@section("opcodes")
def check_opcodes(module):
    """TS 29.002 17.5 Table: every CODE local:N, read back through the CLI."""
    for code in sorted(OPS):
        rc, out, err = run(module, "--opcode", str(code))
        add("opcode-%d-rc" % code, 0, rc)
        add("opcode-%d-name" % code, OPS[code], get(out, "name"))
        add("opcode-%d-assigned" % code, "yes", get(out, "assigned"))
        add("opcode-%d-status" % code, "active", get(out, "status"))
    for code in sorted(WITHDRAWN):
        out = run(module, "--opcode", str(code))[1]
        add("opcode-%d-withdrawn" % code, WITHDRAWN[code], get(out, "name"))
        add("opcode-%d-withdrawn-assigned" % code, "no", get(out, "assigned"))
        add("opcode-%d-withdrawn-status" % code, "withdrawn", get(out, "status"))
    for code in sorted(HISTORIC):
        out = run(module, "--opcode", str(code))[1]
        add("opcode-%d-historic" % code, HISTORIC[code], get(out, "name"))
        add("opcode-%d-historic-assigned" % code, "no", get(out, "assigned"))
        add("opcode-%d-historic-status" % code, "dissector-only", get(out, "status"))
    for code in (1, 127, 128, 200, 255):
        out = run(module, "--opcode", str(code))[1]
        add("opcode-%d-unassigned-name" % code, "unassigned/unknown", get(out, "name"))
        add("opcode-%d-unassigned" % code, "no", get(out, "assigned"))
        add("opcode-%d-unassigned-status" % code, "unassigned", get(out, "status"))
    scan = batch_scan(module, "ss7_map_opcode_name")
    known = {c: n for c, n in scan.items()
             if n not in ("unassigned/unknown", "unknown", "")}
    want = dict(OPS)
    want.update(WITHDRAWN)
    want.update(HISTORIC)
    add("opcode-coverage-size", 104, len(want))
    add("opcode-coverage-count", len(want), len(known))
    add("opcode-coverage-codes", sorted(want), sorted(known))


@section("sscodes")
def check_sscodes(module):
    """TS 29.002 17.7.2 SS-Code: all 72 values, read back through a builder."""
    for code in sorted(SS):
        rc, out, err = run(module, "--build-register-ss", str(code), "33690000000")
        add("ss-%d-rc" % code, 0, rc)
        add("ss-%d-name" % code, SS[code], get(out, "ss_name"))
        add("ss-%d-code" % code, str(code), get(out, "ss_code"))
        frame = bytes.fromhex(get(out, "hex"))
        arg = parse_udt(frame[5:])
        comp = parse_tcap(arg["data"])["comps"][0]
        _, body, _ = parse_tlv(comp["arg"], 0)
        tag, value, _ = parse_tlv(body, 0)
        add("ss-%d-on-wire-tag" % code, 0x04, tag)
        add("ss-%d-on-wire" % code, "%02X" % code, value.hex().upper())
    for code in (1, 15, 22, 60, 200):
        out = run(module, "--build-register-ss", str(code), "33690000000")[1]
        add("ss-%d-unassigned" % code, "unknown", get(out, "ss_name"))
    scan = batch_scan(module, "ss7_ss_code_name")
    known = {c: n for c, n in scan.items() if n not in ("unknown", "")}
    add("ss-coverage-count", len(SS), len(known))
    add("ss-coverage-codes", sorted(SS), sorted(known))


@section("ssn")
def check_ssn(module):
    """Q.713 3.4.2.2 Table 3 for the ITU values, TS 23.003 8.5 for the
    national ones. The module's table is documented as read back from the
    dissector, so the check is that the dissector's short name still appears
    in the module's name, and that nothing outside the assigned set is named.
    """
    scan = batch_scan(module, "ss7_ssn_name")
    named = 0
    for code in range(256):
        got = scan.get(code, "<missing>")
        if code in SSN_NATIONAL:
            want = SSN_3GPP[code]
        elif code in SSN_DISSECTOR:
            want = SSN_DISSECTOR[code]
        elif code == 0:
            # Q.713: 0 is "SSN not used"; it must be named, not "unknown".
            add("ssn-0-named", True, got not in ("unknown", ""))
            named += 1
            continue
        else:
            add("ssn-%d" % code, "unknown", got)
            continue
        named += 1
        add("ssn-%d-clause" % code, True,
            short_name(want).lower() in got.lower())
    add("ssn-named-count", len(SSN_NATIONAL) + len(SSN_DISSECTOR) + 1, named)
    # The 145/146 split is the trap: 145 is GMLC, 146 is CAP.
    add("ssn-145-gmlc", True, "GMLC" in scan.get(145, ""))
    add("ssn-146-cap", True,
        "CAP" in scan.get(146, "") and "GMLC" not in scan.get(146, ""))
    for code in (6, 8, 145, 149, 142, 200):
        out = run(module, "--ssn", str(code))[1]
        add("ssn-%d-cli" % code, scan.get(code, "<missing>"), get(out, "name"))


@section("mtp3")
def check_mtp3(module):
    """Q.704 2.2: the four-octet label (DPC 8/6, OPC 2/8/4, SLS in the top
    nibble of the last octet) and the service information octet."""
    for dpc, opc, sls in ((1, 2, 0), (16383, 16383, 15), (0, 0, 0),
                          (1, 16383, 7), (12345, 6789, 3)):
        frame = msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), b"\x41"),
                    dpc, opc, sls)
        rc, out, err = run(module, "--decode-msu", frame.hex())
        add("mtp3-%d-%d-%d-rc" % (dpc, opc, sls), 0, rc)
        add("mtp3-%d-%d-%d-dpc" % (dpc, opc, sls), str(dpc), get(out, "dpc"))
        add("mtp3-%d-%d-%d-opc" % (dpc, opc, sls), str(opc), get(out, "opc"))
        add("mtp3-%d-%d-%d-sls" % (dpc, opc, sls), str(sls), get(out, "sls"))
        add("mtp3-%d-%d-%d-pc-roundtrip" % (dpc, opc, sls), str(dpc),
            get(run(module, "--pc-format", str(dpc))[1], "roundtrip"))
    for ni in range(4):
        for si in (0, 3, 5, 7):
            for spare in (0, 3):
                frame = msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), b"\x41"),
                            si=si, ni=ni, spare=spare)
                out = run(module, "--decode-msu", frame.hex())[1]
                tag = "%d-%d-%d" % (ni, si, spare)
                add("sio-" + tag + "-ni", str(ni), get(out, "ni"))
                add("sio-" + tag + "-spare", str(spare), get(out, "spare"))
                add("sio-" + tag + "-si", str(si), get(out, "si"))


@section("sccp")
def check_sccp(module):
    """Q.713 1.4/3.4/4.2: the address indicator, the three pointers, the class.
    Wireshark 4.2.2 reads an address indicator of 0x03 as route on GT and 0x43
    as route on SSN, which is what the module prints."""
    for pc, ssn, ri in ((6, 6, 0), (6, 6, 1), (6, None, 0), (None, 6, 0),
                        (16383, 8, 0), (1, 1, 0)):
        frame = msu(udt(sccp_addr(pc, ssn, ri=ri), sccp_addr(8, 8, ri=1), b"\x41"))
        out = run(module, "--decode-msu", frame.hex())[1]
        tag = "%s-%s-%s" % (pc, ssn, ri)
        add("sccp-called-pc-" + tag, "" if pc is None else str(pc),
            get(out, "called_pc"))
        add("sccp-called-ssn-" + tag, "" if ssn is None else str(ssn),
            get(out, "called_ssn"))
        add("sccp-route-on-" + tag, "SSN+PC" if ri else "GT",
            get(out, "called_routing_on"))
        add("sccp-calling-route-on-" + tag, "SSN+PC", get(out, "calling_routing_on"))
    for n in (0, 1, 5, 40, 255):
        data = bytes(range(0x41, 0x41 + n)) if n < 200 else b"\x41" * n
        frame = msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), data))
        out = run(module, "--decode-msu", frame.hex())[1]
        add("sccp-data-len-%d" % n, data.hex().upper(), get(out, "sccp_data"))
    for cls in (0, 1, 15):
        frame = msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), b"\x41", cls=cls))
        out = run(module, "--decode-msu", frame.hex())[1]
        add("sccp-class-%d" % cls, str(cls), get(out, "sccp_class"))
    # A GT-routed address: the fixture the module's selftest pins, which
    # Wireshark 4.2.2 decodes as the digits 33163254768.
    cdpa = bytes.fromhex("12040011913361234567F8")
    frame = msu(udt(cdpa, sccp_addr(8, 8), b"\x41\x42"))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("sccp-gt-route", "GT", get(out, "called_routing_on"))
    add("sccp-gt-digits", "33163254768", get(out, "called_gt_digits"))
    add("sccp-gt-indicator", "4", get(out, "called_gt_indicator"))
    # A length octet that promises more octets than the frame carries is
    # refused, not decoded short.
    good = bytearray(msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), b"\x41\x42")))
    add("sccp-good-frame-rc", 0, run(module, "--decode-msu", bytes(good).hex())[0])
    msu_off = 5
    data_len_at = msu_off + 5 + 1 + 4 + 1 + 4     # sio+label, then the SCCP
    good[data_len_at] = 11
    rc, out, err = run(module, "--decode-msu", bytes(good).hex())
    add("sccp-length-refused", 1, rc)
    add("sccp-length-reason", True, "user data length 11 runs past" in err)
    bad = bytearray(msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), b"\x41")))
    bad[msu_off + 3] = 1         # calling-party pointer before the called one
    rc, out, err = run(module, "--decode-msu", bytes(bad).hex())
    add("sccp-pointer-order-refused", 1, rc)
    add("sccp-pointer-order-reason", True, "pointers are out of order" in err)
    # A UDT whose data is not TCAP: the MSU decoder must stop at SCCP.
    frame = msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), b"\xde\xad"))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("sccp-no-tcap-layer", "", get(out, "tcap_message_type"))


@section("tcap")
def check_tcap(module):
    """Q.773 3.3: five component types, and a returnResult whose opcode lives
    one SEQUENCE deeper than an invoke's. Component rows are
    index, type, invokeID, opcode, operation name, parameter."""
    def frame_for(tag, comps, otid=None, dtid=None):
        return msu(udt(sccp_addr(6, 6), sccp_addr(8, 8),
                       tcap(tag, otid=otid, dtid=dtid, comps=comps)))

    for tag, name in ((0x61, "unidirectional"), (0x62, "begin"),
                      (0x64, "end"), (0x65, "continue"), (0x67, "abort")):
        frame = frame_for(tag, comp_invoke(1, 22, tlv(0x30, b"\x80\x07\x91\x33")),
                          otid=7 if tag in (0x62, 0x65) else None)
        rc, out, err = run(module, "--decode-msu", frame.hex())
        add("tcap-%02X-rc" % tag, 0, rc)
        add("tcap-%02X-type" % tag, name, get(out, "tcap_message_type"))
        add("tcap-%02X-tag" % tag, "%02X" % tag, get(out, "tcap_tag"))
    frame = frame_for(0x62, comp_invoke(1, 22, tlv(0x30, b"\x80\x07\x91\x33")), otid=7)
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-otid", "00000007", get(out, "otid"))
    add("tcap-ndt", 0, len(get_all(out, "dtid")))
    add("tcap-layers", "mtp3,sccp,tcap", ",".join(get_all(out, "layer")))
    row = full_rows(out, "component")
    add("tcap-invoke-rows", 1, len(row))
    add("tcap-invoke-row",
        "component\t0\tinvoke\t1\t22\tsendRoutingInfo\t300480079133", row[0])
    # A returnResultLast carries its opcode inside a nested SEQUENCE.
    frame = frame_for(0x64, comp_return_last(1, 22, b"\x80\x07\x91\x33"), dtid=7)
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-dtid", "00000007", get(out, "dtid"))
    add("tcap-return-last",
        "component\t0\treturnResultLast\t1\t22\tsendRoutingInfo\t80079133",
        full_rows(out, "component")[0])
    frame = frame_for(0x65, comp_return_not_last(1, 22, b"\x41"))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-return-not-last",
        "component\t0\treturnResultNotLast\t1\t22\tsendRoutingInfo\t41",
        full_rows(out, "component")[0])
    # A returnError names an ERROR code, not an operation: code 34 is
    # systemFailure while operation 34 is sendRoutingInfoForLCS, and code 4 is
    # an operation (provideRoamingNumber) but no error at all.
    frame = frame_for(0x64, comp_error(1, 34))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-error-row",
        "component\t0\treturnError\t1\t34\tsystemFailure\t",
        full_rows(out, "component")[0])
    frame = frame_for(0x64, comp_error(1, 4))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-error-4-unassigned",
        "component\t0\treturnError\t1\t4\tunassigned/unknown\t",
        full_rows(out, "component")[0])
    # The reject problem is a CHOICE: [1] is invokeProblem.
    frame = frame_for(0x64, comp_reject(1, 0x81, 1))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-reject-row",
        "component\t0\treject\t1\t129\tinvokeProblem\t01",
        full_rows(out, "component")[0])
    frame = frame_for(0x64, comp_reject(1, 0x82, 1))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-reject-return-result",
        "component\t0\treject\t1\t130\treturnResultProblem\t01",
        full_rows(out, "component")[0])
    frame = frame_for(0x62, comp_invoke(1, 22, b"\x41") + comp_invoke(2, 70, b"\x42"),
                      otid=1)
    out = run(module, "--decode-msu", frame.hex())[1]
    add("tcap-two-components", 2, len(full_rows(out, "component")))
    # --decode-tcap on the component portion alone must agree with the MSU
    # decoder, which now reaches TCAP itself.
    tcap_hex = tcap(0x62, otid=9, comps=comp_invoke(3, 56, b"\x41"))
    out = run(module, "--decode-tcap", tcap_hex.hex())[1]
    add("tcap-verb-type", "begin", get(out, "tcap_message_type"))
    add("tcap-verb-row",
        "component\t0\tinvoke\t3\t56\tsendAuthenticationInfo\t41",
        full_rows(out, "component")[0])


@section("tbcd")
def check_tbcd(module):
    """TS 29.002 TBCD: low nibble first, a trailing digit padded with F."""
    for digits in ("1", "12", "123", "1234567", "33689000000", "123456789012345"):
        rc, out, err = run(module, "--build-sri", digits)
        add("tbcd-%s-rc" % digits, 0, rc)
        frame = bytes.fromhex(get(out, "hex"))
        arg = parse_udt(frame[5:])
        comp = parse_tcap(arg["data"])["comps"][0]
        _, body, _ = parse_tlv(comp["arg"], 0)
        tag, addr, _ = parse_tlv(body, 0)
        add("tbcd-%s-nai" % digits, "91", "%02X" % addr[0])
        add("tbcd-%s-digits" % digits, digits, tbcd_digits(addr[1:]))
    for digits in ("1234567890123456", "abc", "", "12x4"):
        rc, out, err = run(module, "--build-sri", digits)
        add("tbcd-invalid-%r-refused" % digits, True, rc != 0)
    rc, out, err = run(module, "--build-ati", "310150123456789")
    frame = bytes.fromhex(get(out, "hex"))
    arg = parse_udt(frame[5:])
    comp = parse_tcap(arg["data"])["comps"][0]
    add("tbcd-imsi-in-arg", True,
        tbcd("310150123456789").hex().upper() in comp["arg"].hex().upper())


@section("builders")
def check_builders(module):
    """Every builder: operation code, MTP3 label, SCCP addresses, TCAP shape
    and the argument the module claims to have encoded. The SSNs and the label
    are the module's documented reference pair (HLR/VLR, dpc 1 / opc 2); the
    builder's own decoder has to agree with the oracle's parse of the same
    octets."""
    LBL = label(1, 2, 0).hex().upper()
    cases = [
        # verb, args, opcode, operation, field, value, called SSN, calling SSN
        ("--build-sri", ["33689000000"], 22, "sendRoutingInfo", "msisdn",
         "33689000000", 6, 8),
        ("--build-sri-sm", ["33689000000", "33690000000"], 45,
         "sendRoutingInfoForSM", "msisdn", "33689000000", 6, 8),
        ("--build-ati", ["310150123456789"], 71, "anyTimeInterrogation",
         "imsi", "310150123456789", 6, 145),
        ("--build-sai", ["310150123456789", "2"], 56, "sendAuthenticationInfo",
         "imsi", "310150123456789", 6, 7),
        ("--build-psi", ["310150123456789"], 70, "provideSubscriberInfo",
         "imsi", "310150123456789", 7, 6),
        ("--build-ulr", ["310150123456789"], 2, "updateLocation",
         "imsi", "310150123456789", 6, 7),
        ("--build-isd", ["310150123456789"], 7, "insertSubscriberData",
         "imsi", "310150123456789", 6, 7),
        ("--build-register-ss", ["33", "33690000000"], 10, "registerSS",
         "ss_code", "33", 6, 7),
        ("--build-activate-ss", ["33"], 12, "activateSS", "ss_code", "33", 6, 7),
    ]
    for verb, args, op, name, field, value, cssn, ossn in cases:
        tag = verb.lstrip("-")
        rc, out, err = run(module, verb, *args)
        add(tag + "-rc", 0, rc)
        add(tag + "-opcode", str(op), get(out, "opcode"))
        add(tag + "-opcode-name", name, get(out, "opcode_name"))
        add(tag + "-roundtrip", str(op), get(out, "roundtrip_opcode"))
        add(tag + "-field", value, get(out, field))
        hexs = get(out, "hex")
        add(tag + "-octets", len(hexs) // 2, int(get(out, "octets") or 0))
        frame = bytes.fromhex(hexs)
        add(tag + "-sio-si", "3", "%d" % (frame[0] & 0x0F))
        add(tag + "-sio-ni", "2", "%d" % ((frame[0] >> 6) & 0x03))
        add(tag + "-label", LBL, frame[1:5].hex().upper())
        u = parse_udt(frame[5:])
        add(tag + "-udt", 0x09, frame[5])
        add(tag + "-class", 0, u["class"])
        add(tag + "-called-pc", 1, u["cdpa"]["pc"])
        add(tag + "-called-ssn", cssn, u["cdpa"]["ssn"])
        add(tag + "-calling-pc", 2, u["cgpa"]["pc"])
        add(tag + "-calling-ssn", ossn, u["cgpa"]["ssn"])
        t = parse_tcap(u["data"])
        add(tag + "-tcap", 0x62, t["tag"])
        add(tag + "-comps", 1, len(t["comps"]))
        add(tag + "-component", 0xA1, t["comps"][0]["tag"])
        add(tag + "-iid", 1, t["comps"][0]["iid"])
        add(tag + "-wire-opcode", op, t["comps"][0]["op"])
    # The builder's own decoder must read the frame back to the same values.
    frame = bytes.fromhex(get(run(module, "--build-sri", "33689000000")[1], "hex"))
    out = run(module, "--decode-msu", frame.hex())[1]
    add("build-sri-decode-ssn", "6", get(out, "called_ssn"))
    add("build-sri-decode-op", "22", full_rows(out, "component")[0].split("\t")[4])
    # A number with a non-digit octet must be refused, not stripped: "12x4"
    # silently became 124 before this check existed.
    add("build-sri-mangled-refused", True,
        run(module, "--build-sri", "12x4")[0] != 0)
    add("build-sri-plus-accepted", 0, run(module, "--build-sri", "+33612345678")[0])
    add("build-ati-imsi-letters-refused", True,
        run(module, "--build-ati", "31015X123456789")[0] != 0)
    add("build-ati-imsi-short-refused", True,
        run(module, "--build-ati", "1234")[0] != 0)


@section("flows")
def check_flows(module):
    """The four flows: each step has to be a frame the oracle can read, and
    the operation it claims has to be the operation on the wire."""
    for flow, seq in (("intercept", [22, 70]), ("locate", [22, 71]),
                      ("sms-intercept", [45, 44]), ("forward-hijack", [10, 12])):
        rc, out, err = run(module, "--flow", flow)
        add("flow-" + flow + "-rc", 0, rc)
        steps = [r for r in rows(out) if r[0] == "step"]
        adds = [r for r in rows(out) if r[0] == "step_hex"]
        add("flow-" + flow + "-steps", len(seq), len(steps))
        add("flow-" + flow + "-hexes", len(seq), len(adds))
        for i, want_op in enumerate(seq):
            frame = bytes.fromhex(adds[i][2])
            u = parse_udt(frame[5:])
            t = parse_tcap(u["data"])
            add("flow-" + flow + "-step%d-opcode" % (i + 1), want_op,
                t["comps"][0]["op"])
            add("flow-" + flow + "-step%d-claim" % (i + 1), str(want_op),
                steps[i][3] if len(steps[i]) > 3 else "")
            add("flow-" + flow + "-step%d-named" % (i + 1), True,
                get(out, "step") != "" and steps[i][4] != "unassigned/unknown"
                if len(steps[i]) > 4 else True)


@section("sigtran")
def check_sigtran(module):
    """RFC 4666 over RFC 4960: the DATA chunk, the M3UA DATA message, and the
    MTP3 message carried inside it."""
    inner = msu(udt(sccp_addr(6, 6), sccp_addr(8, 8), b"\x41\x42"))
    frame = sctp_data(m3ua_data(inner))
    rc, out, err = run(module, "--decode-sigtran", frame.hex())
    add("sigtran-rc", 0, rc)
    add("sigtran-sport", "2905", get(out, "sctp_sport"))
    add("sigtran-chunk", "DATA", get(out, "chunk_name"))
    add("sigtran-ppid", "3", get(out, "data_ppid"))
    add("sigtran-class", "Transfer", get(out, "m3ua_class_name"))
    add("sigtran-type", "DATA", get(out, "m3ua_type_name"))
    add("sigtran-param", "0x0210", get(out, "param_tag"))
    add("sigtran-msu", inner.hex().upper(), get(out, "msu_hex"))
    add("sigtran-sccp-data", "4142", get(out, "sccp_data"))
    # A chunk length past the datagram is a refusal, not a truncated decode.
    bad = bytearray(frame)
    bad[14] = 0x00
    bad[15] = 0xFF
    rc, out, err = run(module, "--decode-sigtran", bytes(bad).hex())
    add("sigtran-chunk-refused", 1, rc)
    add("sigtran-chunk-reason", True, "runs past the datagram" in err)


@section("tshark")
def check_tshark(module):
    """The independent implementation: Wireshark's GSM MAP dissector reads the
    module's own frames without a malformation, and names the same operation."""
    if shutil.which(TSHARK) is None:
        return
    rc, out, err = run(module, "--build-sri", "33689000000")
    frame = bytes.fromhex(get(out, "hex"))
    pcap = os.path.join(tempfile.mkdtemp(prefix="ss7oracle"), "f.pcap")
    with open(pcap, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 141))
        fh.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
        fh.write(frame)
    p = subprocess.run([TSHARK, "-r", pcap, "-V"], capture_output=True)
    text = p.stdout.decode("latin-1")
    add("tshark-rc", 0, p.returncode)
    add("tshark-sri-opcode", True, "sendRoutingInfo (22)" in text)
    add("tshark-no-malformed", False, "BER Error" in text)


# ── mutants ────────────────────────────────────────────────────────────────
# Each anchor is a line that carries a clause fact. Flipping it must move a
# case above, otherwise the suite is not reading the thing it claims to read.
MUTANTS = [
    ("ss-144-name-dropped",
     '        144) echo "allBarringSS" ;;',
     '        144) echo "allCallRestrictionSS" ;;',
     ["sscodes"]),
    ("opcode-38-shortened",
     '        38)  echo "forwardCheckSS-Indication" ;;',
     '        38)  echo "forwardCheckSS" ;;',
     ["opcodes"]),
    ("sls-read-from-the-low-nibble",
     '    local sls=$(( (o4 >> 4) & 0x0F ))',
     '    local sls=$(( o4 & 0x0F ))',
     ["mtp3"]),
    ("builder-called-pointer-off-by-one",
     '        "$(ss7_byte $(( p2_off - 3 )))" \\',
     '        "$(ss7_byte $(( p2_off - 2 )))" \\',
     ["builders"]),
    ("decoder-calling-pointer-off-by-one",
     '        coff=$(( p2 + 3 )); xoff=$(( p3 + 4 ))',
     '        coff=$(( p2 + 2 )); xoff=$(( p3 + 4 ))',
     ["sccp"]),
    ("tbcd-odd-digit-padded-with-zero",
     '    (( ${#d} % 2 )) && d+="F"',
     '    (( ${#d} % 2 )) && d+="0"',
     ["tbcd"]),
    ("tcap-abort-renamed",
     '        67) echo "abort" ;;',
     '        67) echo "continue" ;;',
     ["tcap"]),
]


def run_mutant(module, anchor, repl, sections):
    with open(module, encoding="utf-8") as fh:
        src = fh.read()
    if src.count(anchor) < 1:
        return "ANCHOR-MISSING", []
    tmp = os.path.join(tempfile.mkdtemp(prefix="ss7mut"), "mutant.sh")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(src.replace(anchor, repl, 1))
    os.chmod(tmp, 0o755)
    start = len(CASES)
    global QUIET
    QUIET = True
    try:
        check_all(tmp, only=sections)
    finally:
        QUIET = False
    fails = [c[0] for c in CASES[start:] if c[1] != c[2]]
    return ("CAUGHT" if fails else "SURVIVED"), fails


def negctl(module):
    caught = 0
    for name, anchor, repl, sections in MUTANTS:
        verdict, fails = run_mutant(module, anchor, repl, sections)
        print("NEGCTL\t" + name + "\t" + verdict)
        if verdict == "CAUGHT":
            caught += 1
            print("NEGCTL-CASE\t" + name + "\t" + fails[0])
        else:
            print("NEGCTL-MISS\t" + name + "\tevery case in "
                  + ",".join(sections) + " still passed")
    print("NEGCTL-CAUGHT\t%d of %d" % (caught, len(MUTANTS)))
    return 0 if caught == len(MUTANTS) else 1


# ── main ───────────────────────────────────────────────────────────────────
def check_all(module, only=None):
    for key, fn in SECTIONS.items():
        if only is not None and key not in only:
            continue
        fn(module)


def report():
    bad = [c for c in CASES if c[1] != c[2]]
    print("CASES\t%d" % len(CASES))
    print("MISMATCHES\t%d" % len(bad))
    for case, want, got in bad:
        print("FAIL\t" + case + "\twant=" + show(want) + "\tgot=" + show(got))
    print("RESULT\t" + ("PASS" if not bad else "FAIL"))
    return 0 if not bad else 1


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default=MODULE)
    ap.add_argument("--negctl", action="store_true")
    args = ap.parse_args(argv)
    module = args.module
    if not os.path.isabs(module):
        module = os.path.join(os.getcwd(), module)
    if not os.path.exists(module):
        here = os.path.dirname(os.path.abspath(__file__))
        module = os.path.normpath(os.path.join(here, "..", "..", args.module))
    if not os.path.exists(module):
        print("ERROR\tno module at " + module)
        return 2
    check_all(module)
    rc = report()
    if args.negctl:
        rc = max(rc, negctl(module))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
