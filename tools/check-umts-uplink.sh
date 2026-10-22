#!/usr/bin/env bash
# tools/check-umts-uplink.sh -- known-answer suite for tools/umts_uplink.py.
#
# The uplink side of the catcher is held against five independent referees, and
# the expected value in every check is derived from the clause or from an
# independent implementation BEFORE the tool is asked:
#
#   1. a HAND-DERIVED bit string for each RRC CONNECTION REQUEST vector: the
#      layout is written out field by field in the comment above each vector,
#      straight from the ASN.1 of TS 25.331 v6.4.0 clauses 10.2.39 and 10.3.3,
#      and the bit count is added up by hand.
#   2. pycrate's transcription of TS 25.331 (from pycrate_asn1dir import RRC3G),
#      BOTH ways: its PER encoder is given the expected value tree and its
#      octets must equal the tool's bit for bit; and its PER decoder is given
#      the tool's own octets and every field is then asserted individually.
#   3. tshark 4.2.2 over a one-packet GSMTAP pcap.  The sub_type that dissects
#      as UL-CCCH is found BY EXPERIMENT here (all 31 values are dissected and
#      exactly one of them must produce a UL-CCCH-Message) and the request
#      fields are then read out of the dissector's own words.
#   4. a RECOMPUTATION OF THE PRACH CHIPS FROM THE CLAUSE, in this file, sharing
#      no code with the tool: TS 25.213 4.3.2.2 (the degree 25 Gold sequence),
#      4.3.3.2 (S_r-pre,n(i) = c_long,1,n(i), n = 16m+k) and 4.3.3.3 (Table 3,
#      generated here as the Sylvester Hadamard matrix P_s(i) = (-1)**popcount,
#      which is what the printed table is, plus exp(j(pi/4 + k pi/2))).  Two
#      hand-computed Gold symbols are asserted first, so the recomputation is
#      itself held to a known answer and not merely to the tool.
#   5. the clause tables themselves for the RACH message part: TS 25.211
#      5.2.2.1.3 Table 6 (N_data and SF), Table 7 (N_pilot/N_TFCI) and Table 8
#      (the 15 pilot patterns), transcribed in this file from the clause text.
#
# NEGATION CONTROL.  Three copies of the tool are made inside the suite, each
# with ONE constant changed: the UL-CCCH-MessageType alternative, one chip phase
# of the PRACH preamble, and one pilot pattern of the message part.  Each mutant
# must still run (exit 0) and must DIVERGE from the value the referee derived --
# that is what proves these checks can fail at all.  An UNMODIFIED copy then
# goes through the same comparison path and must still match, so a mutant that
# failed for an unrelated reason (a copy that does not import, a typo in this
# harness) cannot make the negation control pass.
#
# There are no round trips in the evidence: the tool's bits are never decoded by
# the tool and re-encoded by the tool to "confirm" itself.  Every comparison is
# tool output against one of the five referees above.
#
# Usage:
#   bash tools/check-umts-uplink.sh
#   PYTHON=/path/to/python bash tools/check-umts-uplink.sh
#   UMTS_UPLINK_TOOL=/tmp/mutant.py bash tools/check-umts-uplink.sh
#   (UMTS_UPLINK_TOOL points the suite at another copy of the tool -- the same
#    switch the negation control uses.)
#
# Exit: 0 PASS, 1 FAILED, 2 SKIP (pycrate or tshark missing -- never PASS).

set -u

here=$(cd "$(dirname "$0")" && pwd)
tool=${UMTS_UPLINK_TOOL:-$here/umts_uplink.py}

if [ ! -f "$tool" ]; then
    printf 'FAIL\tt0 no tool at %s\n' "$tool"
    exit 1
fi

python=${PYTHON:-}
if [ -z "$python" ]; then
    for cand in /home/ysl/.lte-oracles/venv/bin/python python3 python; do
        if command -v "$cand" >/dev/null 2>&1 &&
           "$cand" -c 'import pycrate_asn1dir.RRC3G' >/dev/null 2>&1; then
            python=$cand
            break
        fi
    done
fi
if [ -z "$python" ] || ! "$python" -c 'import pycrate_asn1dir.RRC3G' >/dev/null 2>&1; then
    printf 'SKIP\tt1 the referee is absent: no python with pycrate_asn1dir.RRC3G\n'
    printf 'SKIP\tt1 tried: %s\n' "${PYTHON:-/home/ysl/.lte-oracles/venv/bin/python python3 python}"
    printf 'SKIP\tt1 this suite holds the uplink tool against pycrate and tshark; without pycrate there is nothing to hold it against, so this is a SKIP and not a PASS.  Install pycrate (pip install pycrate in a venv) or point PYTHON at one.\n'
    exit 2
fi

tshark=$(command -v tshark 2>/dev/null || true)

exec "$python" - "$tool" "$tshark" "$here" <<'PY'
# -*- coding: utf-8 -*-
"""The suite proper.  argv: tool path, tshark path (may be empty)."""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

TOOL = os.path.abspath(sys.argv[1])
TSHARK = sys.argv[2] if len(sys.argv) > 2 else ""
HERE = sys.argv[3] if len(sys.argv) > 3 else os.path.dirname(TOOL)
sys.path.insert(0, os.path.dirname(TOOL))
WORK = tempfile.mkdtemp(prefix="check-umts-uplink.")

CHECKS = 0
FAILS = 0
SKIPS = 0
FAILED = []


def chk(name, got, want):
    global CHECKS, FAILS
    CHECKS += 1
    if got == want:
        print("ok %d %s" % (CHECKS, name))
    else:
        FAILS += 1
        FAILED.append(name)
        print("FAIL %d %s -- got %r want %r" % (CHECKS, name, got, want))


def chk_true(name, cond, detail=""):
    global CHECKS, FAILS
    CHECKS += 1
    if cond:
        print("ok %d %s" % (CHECKS, name))
    else:
        FAILS += 1
        FAILED.append(name)
        print("FAIL %d %s%s" % (CHECKS, name, (" -- " + detail) if detail else ""))


def skip(name, why):
    global SKIPS
    SKIPS += 1
    print("skip %s -- %s" % (name, why))


def note(text):
    print("note %s" % text)


def run(*args, **kw):
    tool = kw.get("tool", TOOL)
    env = kw.get("env") or os.environ.copy()
    return subprocess.run([sys.executable, tool] + list(args),
                          capture_output=True, text=True, env=env)


def rows_of(p):
    d = {}
    for line in p.stdout.splitlines():
        if "\t" not in line:
            continue
        k, v = line.split("\t", 1)
        d.setdefault(k, []).append(v)
    return d


def one(d, key):
    try:
        return d[key][0]
    except (KeyError, IndexError):
        print("FAIL 0 one(%r) -- rows present: %s" % (key, sorted(d)))
        raise


# ── 0. the tool lists what it does ─────────────────────────────────────────
p = run("list")
chk("t0 list exits 0", p.returncode, 0)
verbs = " ".join(v.split("\t")[0] for v in rows_of(p).get("verb", []))
for want in ("request", "prach", "message-part"):
    chk_true("t0 list names %s" % want, want in verbs, "verbs: %r" % verbs)

try:
    from pycrate_asn1dir import RRC3G as R
    from pycrate_asn1rt.utils import pack_val
except ImportError as exc:                        # the wrapper already checked
    print("SKIP t1 pycrate import failed inside the suite: %s" % exc)
    sys.exit(2)

C = R.Class_definitions


def py_encode(val):
    """Our expected value tree -> pycrate's PER octets and bit length."""
    t = C.UL_CCCH_Message
    t.set_val(val)
    return pack_val(*t._to_per())


def py_decode(octets):
    t = C.UL_CCCH_Message
    t.from_uper(octets)
    return t.get_val()


# ── 1. the RRC CONNECTION REQUEST vectors ──────────────────────────────────
# Each vector carries its own hand derivation.  The shared layout, from the
# ASN.1 of TS 25.331 v6.4.0:
#
#   bits  field                                             clause
#      1  integrityCheckInfo absent                         25.331 11.2
#      2  UL-CCCH-MessageType = 1 rrcConnectionRequest      25.331 11.2 (3 alts + ext)
#      1  measuredResultsOnRACH absent                      25.331 10.2.39
#      1  v3d0NonCriticalExtensions absent                  25.331 10.2.39
#      3  InitialUE-Identity alternative                    25.331 10.3.3.15 (8 alts)
#     32  tmsi (or 4 + 4n for the IMSI length and digits)   25.331 10.3.1.17/10.3.1.5
#     12  mcc, three Digits of 4 bits                       25.331 11.3
#      1  mnc length determinant, digit count - 2           25.331 11.3
#   8/12  mnc, two or three Digits of 4 bits                25.331 11.3
#     16  lac                                               25.331 10.3.1.7
#      5  establishmentCause, 32 values                      25.331 10.3.3.11
#      1  protocolErrorIndicator                             25.331 10.3.3.27
#
# The presence ladder (the two OPTIONAL components) sits before the first field
# value of the SEQUENCE, X.691 11.5, and there is no SEQUENCE extension marker.
VECTORS = []


def vec(label, args, hexstr, bits, ident, tmsi, digits, lac, cause, pei):
    VECTORS.append(dict(label=label, args=args, hex=hexstr, bits=bits,
                        ident=ident, tmsi=tmsi, digits=digits, lac=lac,
                        cause=cause, pei=pei))


# (1) defaults: 1+2+1+1+3+32+12+1+8+16+5+1 = 83 bits = 10 octets + 3 bits, so
#     five zero bits of padding (TS 25.331 12.1).  Bits in order:
#       0 | 01 | 0 | 0 | 001 | 0001 0010 0011 0100 0101 0110 0111 1000
#       (tmsi 0x12345678) | 0000 0000 0001 (mcc 0,0,1) | 0 (mnc length)
#       | 0000 0001 (mnc 0,1) | 0000 0000 0000 0001 (lac 0x0001) | 01100 (12)
#       | 0 (noError)   ->  21 12 34 56 78 00 10 08 00 0b 00
#     That is also the vector the tree already carries at
#     modules/08_umts_air.sh:1714 ("2112345678001008000b00"), an independent
#     transcription of the same message and therefore a sixth witness: the tool's
#     defaults reproduce it octet for octet.
vec("default", [], "2112345678001008000b00", 83,
    "tmsi-and-LAI", 0x12345678, [0, 0, 1, 0, 1], 0x0001, "registration", "noError")

# (2) tmsi 0xC0FFEE01, mcc 460, mnc 00, lac 0x1234; same 83-bit layout:
#       0|01|0|0|001|11000000111111111110111000000001|010001100000 (4,6,0)
#       |0|00000000 (0,0)|0001001000110100 (lac 0x1234)|01100|0
#     -> 21 c0 ff ee 01 46 00 00 91 a3 00
vec("catcher", ["--tmsi", "c0ffee01", "--mcc", "460", "--mnc", "00",
                "--lac", "1234"],
    "21c0ffee0146000091a300", 83,
    "tmsi-and-LAI", 0xC0FFEE01, [4, 6, 0, 0, 0], 0x1234, "registration", "noError")

# (3) IMSI 234015678901234: ...|000 (imsi)|1001 (digit count 15-6 = 9)|
#     fifteen 4-bit digits |01100|0 -> 1+2+1+1+3+4+60+5+1 = 78 bits, two zero
#     bits of padding:
#       0|01|0|0|000|1001|0010 0011 0100 0000 0001 0101 0110 0111 1000 1001
#       0000 0001 0010 0011 0100|01100|0   ->  20 92 34 01 56 78 90 12 34 60
vec("imsi", ["--imsi", "234015678901234"],
    "20923401567890123460", 78,
    "imsi", None, [2, 3, 4, 0, 1, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4], None,
    "registration", "noError")

# (4) a THREE-digit MNC: the length determinant is n-2 = 1, and the digits are
#     0,0,1, so the LAI grows by four bits: 83 + 4 = 87 bits, one bit of
#     padding.  establishmentCause 9 is emergencyCall, index 9 of 10.3.3.11:
#       0|01|0|0|001|0x12345678|000000000001 (0,0,1)|1|000000000001 (0,0,1)
#       |0x0001|01001 (9)|0   ->  21 12 34 56 78 00 18 00 80 00 a4
vec("mnc3", ["--mnc", "001", "--cause", "emergencyCall"],
    "21123456780018008000a4", 87,
    "tmsi-and-LAI", 0x12345678, [0, 0, 1, 0, 0, 1], 0x0001, "emergencyCall",
    "noError")

# (5) the same message with protocolErrorIndicator = errorOccurred, so the last
#     data bit is 1:  0|01|0|0|001|0x12345678|mcc 0,0,1|0|mnc 0,1|0x0001|
#     01001 (9)|1  ->  21 12 34 56 78 00 10 08 00 0a 60
vec("pei", ["--cause", "9", "--error"],
    "2112345678001008000a60", 83,
    "tmsi-and-LAI", 0x12345678, [0, 0, 1, 0, 1], 0x0001, "emergencyCall",
    "errorOccurred")


def value_tree(v):
    """The value tree pycrate must produce, written out from the clause."""
    if v["ident"] == "imsi":
        ident = ("imsi", [int(c) for c in v["digits"]])
    else:
        d = v["digits"]
        ident = ("tmsi-and-LAI", {
            "tmsi": (v["tmsi"], 32),
            "lai": {
                "plmn-Identity": {"mcc": d[0:3], "mnc": d[3:]},
                "lac": (v["lac"], 16),
            },
        })
    return {"message": ("rrcConnectionRequest", {
        "initialUE-Identity": ident,
        "establishmentCause": v["cause"],
        "protocolErrorIndicator": v["pei"],
    })}


def digits_of(tree):
    alt, val = tree["message"][1]["initialUE-Identity"]
    if alt == "imsi":
        return [int(x) for x in val]
    plmn = val["lai"]["plmn-Identity"]
    return list(plmn["mcc"]) + list(plmn["mnc"])


for v in VECTORS:
    label = v["label"]
    p = run("request", *v["args"])
    chk("request/%s: exits 0" % label, p.returncode, 0)
    d = rows_of(p)
    got_hex = one(d, "hex")
    got_bits = int(one(d, "bits"))
    # (a) against the hand-derived bit string
    chk("request/%s: bits against the hand-derived layout" % label,
        got_bits, v["bits"])
    chk("request/%s: octets against the hand-derived layout" % label,
        got_hex, v["hex"])
    # internal consistency of the rows (not a known answer)
    chk("request/%s: octets = ceil(bits/8)" % label,
        int(one(d, "octets")), (got_bits + 7) // 8)
    chk("request/%s: padding = (-bits) mod 8" % label,
        int(one(d, "pad").split(" ")[0]), (-got_bits) % 8)
    # (b) pycrate's PER encoder, given the EXPECTED tree, must produce the
    #     tool's bits: the encode direction, against an independent encoder.
    buf, n = py_encode(value_tree(v))
    chk("request/%s: pycrate PER encoder bit count" % label, n, got_bits)
    chk_true("request/%s: pycrate encoder and the tool agree bit for bit" % label,
             buf.hex() == got_hex and n == got_bits,
             "pycrate %s/%d, tool %s/%d" % (buf.hex(), n, got_hex, got_bits))
    # (c) pycrate's decoder, given the TOOL's octets, field by field
    try:
        tree = py_decode(bytes.fromhex(got_hex))
    except Exception as exc:                  # a mutant can put anything here
        chk_true("request/%s: pycrate decodes the tool's octets" % label, False,
                 repr(exc))
        continue
    chk("request/%s: integrityCheckInfo is absent" % label,
        "integrityCheckInfo" in tree, False)
    chk("request/%s: message is rrcConnectionRequest" % label,
        tree["message"][0], "rrcConnectionRequest")
    if tree["message"][0] != "rrcConnectionRequest":
        continue                      # a mutant can decode as another alternative
    body = tree["message"][1]
    chk("request/%s: initialUE-Identity alternative" % label,
        body["initialUE-Identity"][0], v["ident"])
    chk("request/%s: measuredResultsOnRACH is absent" % label,
        "measuredResultsOnRACH" in body, False)
    chk("request/%s: v3d0NonCriticalExtensions is absent" % label,
        "v3d0NonCriticalExtensions" in body, False)
    chk("request/%s: PLMN and IMSI digits" % label, digits_of(tree), v["digits"])
    if v["ident"] == "tmsi-and-LAI":
        chk("request/%s: tmsi" % label,
            body["initialUE-Identity"][1]["tmsi"][0], v["tmsi"])
        chk("request/%s: lac" % label,
            body["initialUE-Identity"][1]["lai"]["lac"][0], v["lac"])
    chk("request/%s: establishmentCause" % label,
        body["establishmentCause"], v["cause"])
    chk("request/%s: protocolErrorIndicator" % label,
        body["protocolErrorIndicator"], v["pei"])
    # the tool's own summary rows must agree with the referee too
    chk("request/%s: reported establishment_cause" % label,
        one(d, "establishment_cause").split(" ", 1)[1], v["cause"])
    chk("request/%s: reported initial_ue_identity" % label,
        one(d, "initial_ue_identity"), v["ident"])
    chk("request/%s: channel" % label, one(d, "channel"), "ul-ccch")
    chk("request/%s: every ref row cites TS 25.331" % label,
        all("TS 25.331" in r for r in d.get("ref", [])), True)

# every establishmentCause name the tool knows, at its own index, through
# pycrate's decoder: indices 0..20 are the values v6.4.0 and later releases agree
# on (21..23 were reassigned after v6.4.0, which is why the table stops here).
CAUSES = re.split(r"[,\s]+", """originatingConversationalCall, originatingStreamingCall,
originatingInteractiveCall, originatingBackgroundCall,
originatingSubscribedTrafficCall, terminatingConversationalCall,
terminatingStreamingCall, terminatingInteractiveCall, terminatingBackgroundCall,
emergencyCall, interRAT-CellReselection, interRAT-CellChangeOrder, registration,
detach, originatingHighPrioritySignalling, originatingLowPrioritySignalling,
callRe-establishment, terminatingHighPrioritySignalling,
terminatingLowPrioritySignalling, terminatingCauseUnknown, mbms-Reception""".strip())
bad = []
for i, name in enumerate(CAUSES):
    d = rows_of(run("request", "--cause", str(i)))
    try:
        got = py_decode(bytes.fromhex(one(d, "hex")))["message"][1][
            "establishmentCause"]
    except (KeyError, TypeError, IndexError):
        got = "<not an rrcConnectionRequest>"     # what a mutant would give
    if got != name:
        bad.append((i, name, got))
chk("request: establishmentCause indices 0..%d are the names of the clause"
    % (len(CAUSES) - 1), bad, [])
chk("request: the cause table starts with the 21 agreed values", len(CAUSES), 21)

# ── 2. tshark over GSMTAP ─────────────────────────────────────────────────
# The one-packet pcap is Ethernet + IPv4 + UDP 4729 + a 16-byte GSMTAP header:
# version 2, hdr_len 4 words, type 12 (UMTS RRC), and BYTE 12 of the header is
# the RRC sub type -- the byte this section has to find by experiment.


def pcap(octets, subtype):
    gsmtap = bytes([2, 4, 12, 0,                 # version, hdr_len, type 12, timeslot
                    0, 100,                      # arfcn 100
                    0x40, 0,                     # signal, snr
                    0, 0, 0, 1,                  # frame number
                    subtype, 0, 0, 0])           # byte 12 = rrc sub type
    payload = gsmtap + octets
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), 0, 0, 64,
                     17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    udp = struct.pack(">HHHH", 4729, 4729, 8 + len(payload), 0)
    frame = eth + ip + udp + payload
    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    ph = struct.pack("<IIII", 0, 0, len(frame), len(frame))
    return gh + ph + frame


def dissect(octets, subtype):
    path = os.path.join(WORK, "gsmtap.pcap")
    with open(path, "wb") as fh:
        fh.write(pcap(octets, subtype))
    p = subprocess.run([TSHARK, "-r", path, "-d", "udp.port==4729,gsmtap", "-V"],
                       capture_output=True, text=True)
    return p.stdout


def field(text, name):
    """The value after '<indent>name: ' on the first matching line."""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(name + ": "):
            return s[len(name) + 2:]
    return None


if not TSHARK:
    skip("gsmtap: sub type experiment",
         "tshark is not on PATH, so no independent dissector is available")
    skip("gsmtap: request field dissection", "tshark is not on PATH")
else:
    # Find the sub type by experiment: dissect the first vector under every value
    # 0..30 and record which one yields a UL-CCCH-Message.  Nothing here trusts a
    # constant on its own -- the assertion is that exactly one value works.
    octets = bytes.fromhex(VECTORS[0]["hex"])
    found = {}
    for subtype in range(0, 31):
        text = dissect(octets, subtype)
        label = field(text, "Message Type")
        pdus = [l.strip() for l in text.splitlines() if l.strip().endswith("-Message")]
        found[subtype] = (label, pdus[0] if pdus else "")
    ul = [s for s, (lab, pdu) in found.items() if "UL-CCCH" in (lab or "")]
    chk("gsmtap: exactly one sub type 0..30 dissects as UL-CCCH", ul, [3])
    chk("gsmtap: sub type 3 is RRC UL-CCCH", found[3][0], "RRC UL-CCCH (3)")
    chk("gsmtap: sub type 3 yields UL-CCCH-Message", found[3][1], "UL-CCCH-Message")
    chk("gsmtap: the tool reports the same sub type",
        one(rows_of(run("request")), "gsmtap_sub_type"), "3")
    note("gsmtap sub types dissected by this tshark: %s"
         % " ".join("%d=%s" % (s, found[s][0] or "?") for s in range(0, 31)))
    for s, want in ((0, "RRC DL-DCCH"), (1, "RRC UL-DCCH"), (2, "RRC DL-CCCH"),
                    (4, "RRC PCCH"), (7, "RRC BCCH-FACH"), (8, "RRC BCCH-BCH"),
                    (16, "RRC Master Information Block"),
                    (19, "RRC System Information Type 3"),
                    (21, "RRC System Information Type 5")):
        chk_true("gsmtap: sub type %d is %s" % (s, want),
                 (found[s][0] or "").startswith(want), found[s][0])
    # the request fields, out of the dissector's words
    for v in VECTORS:
        label = v["label"]
        text = dissect(bytes.fromhex(v["hex"]), 3)
        chk("gsmtap/%s: UL-CCCH-Message" % label,
            "UL-CCCH-Message" in text, True)
        chk("gsmtap/%s: message" % label,
            field(text, "message"), "rrcConnectionRequest (1)")
        chk("gsmtap/%s: initialUE-Identity" % label,
            field(text, "initialUE-Identity"),
            "%s (%d)" % (v["ident"], 0 if v["ident"] == "imsi" else 1))
        digs = [int(x) for x in re.findall(r"^\s*Digit: (\d+)$", text, re.M)]
        chk("gsmtap/%s: MCC/MNC digits" % label, digs, v["digits"])
        if v["ident"] == "tmsi-and-LAI":
            chk("gsmtap/%s: tmsi" % label,
                (field(text, "tmsi") or "").split(" ")[0], "%08x" % v["tmsi"])
            chk("gsmtap/%s: lac" % label,
                (field(text, "lac") or "").split(" ")[0], "%04x" % v["lac"])
        chk("gsmtap/%s: establishmentCause" % label,
            field(text, "establishmentCause"),
            "%s (%d)" % (v["cause"], CAUSES.index(v["cause"])))
        chk("gsmtap/%s: protocolErrorIndicator" % label,
            field(text, "protocolErrorIndicator"),
            "%s (%d)" % (v["pei"], 0 if v["pei"] == "noError" else 1))

# ── 3. the PRACH preamble, recomputed from the clause ─────────────────────
# Everything in this section is written from the text of TS 25.213/25.211 and
# shares no code with tools/umts_uplink.py.
SQ2 = 0.7071067811865476


def gold(n, count):
    """Z_n(i), TS 25.213 4.3.2.2.  Two degree 25 m-sequences: x seeded with the
    bits of n (LSB = n0) and x(24) = 1, y(0..24) = 1; z = x + y mod 2."""
    x = [(n >> i) & 1 for i in range(24)]
    x.append(1)
    y = [1] * 25
    out = []
    for i in range(count + 25):
        if i >= 25:
            x.append(x[i - 22] ^ x[i - 25])                        # x(i+3) + x(i)
            y.append(y[i - 22] ^ y[i - 23] ^ y[i - 24] ^ y[i - 25])
        if i < count:
            out.append(-1 if (x[i] ^ y[i]) else 1)
    return out


def sig_sign(s, i):
    """P_s(i) of Table 3, TS 25.213 4.3.3.3.  The 16 codes of length 16 in the
    clause are the Sylvester Hadamard matrix, P_s(i) = (-1)**popcount(s AND i):
    row 0 is sixteen +1, row 1 alternates, row 8 is +1 for i < 8 and -1 after."""
    return -1 if bin(s & i).count("1") & 1 else 1


PHASE = ((1, 1), (-1, 1), (-1, -1), (1, -1))    # exp(j(pi/4 + k pi/2)) * sqrt2


def preamble(s, n):
    """C_pre,n,s(k) = S_r-pre,n(k) . C_sig,s(k) . exp(j(pi/4 + k pi/2))."""
    g = gold(n, 4096)
    return [complex(sig_sign(s, k % 16) * g[k] * PHASE[k % 4][0] * SQ2,
                    sig_sign(s, k % 16) * g[k] * PHASE[k % 4][1] * SQ2)
            for k in range(4096)]


# Hold the Gold generator to hand computations first, so the recomputation is
# itself checked against something derived by hand.  For n = 0: x(0..23) = 0,
# x(24) = 1, so x(i) = 0 for i <= 45 except x(24) = 1 and x(46) = x(24) + x(21)
# = 1; y(0..24) = 1 makes y(25..45) = 0 (four ones per window) and y(46) =
# y(24) + y(23) + y(22) + y(21) = 0.  So z = x + y is 1 for i = 0..23, 0 for
# i = 24..45, and 1 again at i = 46:
g0 = gold(0, 64)
chk("prach: Gold n=0, symbols 0..23 are -1", [g0[i] for i in range(24)], [-1] * 24)
chk("prach: Gold n=0, symbols 24..45 are +1", [g0[i] for i in range(24, 46)], [1] * 22)
chk("prach: Gold n=0, symbol 46 is -1", g0[46], -1)
# For n = 1: x(0) = 1 only, so z(0) = 1 + 1 = 0 and z(1..23) = 1:
chk("prach: Gold n=1 starts +1 then -1 through symbol 23",
    [gold(1, 24)[i] for i in range(24)], [1] + [-1] * 23)
# The Hadamard matrix generated here is orthogonal by construction; the tool's
# own Table 3 transcription is compared to it through the chips below.
had = [[sig_sign(s, i) for i in range(16)] for s in range(16)]
chk("prach: the generated Table 3 rows are orthogonal",
    all(sum(had[a][i] * had[b][i] for i in range(16)) == (16 if a == b else 0)
        for a in range(16) for b in range(16)), True)


def read_cf32(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    n = len(raw) // 8
    vals = struct.unpack("<%df" % (2 * n), raw)
    return [complex(vals[2 * i], vals[2 * i + 1]) for i in range(n)], len(raw)


def prach_file(*args, **kw):
    name = kw.pop("name", "p.cf32")
    path = os.path.join(WORK, name)
    p = run("prach", "--out", path, *args)
    chk("prach %s: exits 0" % " ".join(args), p.returncode, 0)
    if p.returncode != 0:
        print(p.stderr)
    return path, rows_of(p)


def close(a, b, tol=1e-6):
    return abs(a.real - b.real) <= tol and abs(a.imag - b.imag) <= tol


# (a) the length and the rate: the structural known answers of the clause
path, d = prach_file("--bare", "--rate", "1")
chips, nbytes = read_cf32(path)
chk("prach: the preamble is exactly 4096 chips", len(chips), 4096)
chk("prach: 4096 cf32 chips are 32768 octets", nbytes, 4096 * 8)
chk("prach: reported preamble_chips", int(one(d, "preamble_chips")), 4096)
chk("prach: 4096 chips = 256 signatures of 16",
    int(one(d, "preamble_signature_reps")), 256)
chk("prach: 4096 chips at 3.84 Mcps is 1.0666... ms",
    round(float(one(d, "preamble_ms")), 12), round(4096.0 / 3.84e6 * 1e3, 12))
chk("prach: chip rate", int(one(d, "chip_rate")), 3840000)
chk("prach: one chip per sample at --rate 1", int(one(d, "chip_samples")), 1)

# (b) every chip against the from-the-clause recomputation
bad = [k for k in range(4096) if not close(chips[k], preamble(0, 0)[k])]
chk("prach: all 4096 chips equal the clause recomputation (signature 0, n 0)",
    bad[:8], [])
# the hand-derived chip 0: S_r-pre,0(0) = Z_0(0) = -1 (see the n = 0 derivation
# above), C_sig,0(0) = +1, exp(j pi/4) = (1+j)/sqrt2, so chip 0 = -(1+j)/sqrt2.
chk("prach: chip 0 is -(1+j)/sqrt2",
    (round(chips[0].real, 6), round(chips[0].imag, 6)), (-0.707107, -0.707107))

# (c) n = 16*psc + code: other codes change the chips and match the clause
path2, d2 = prach_file("--bare", "--code", "3", "--rate", "1", name="p2.cf32")
chips2, _ = read_cf32(path2)
# n = 16*m + k, TS 25.213 4.3.3.2, so --psc 0 --code 3 is n = 16*0 + 3 = 3
bad = [k for k in range(4096) if not close(chips2[k], preamble(0, 3)[k])]
chk("prach: all 4096 chips for code n = 16*0+3 = 3", bad[:8], [])
chk("prach: a different code index changes the chips", chips2 == chips, False)
chk("prach: reported code_number for --code 3", int(one(d2, "code_number")), 3)
chk("prach: reported preamble code index", int(one(d2, "preamble_code_index")), 3)
path3, d3 = prach_file("--bare", "--psc", "7", "--rate", "1", name="p3.cf32")
chips3, _ = read_cf32(path3)
chk("prach: n = 16*psc + code = 112", int(one(d3, "code_number")), 112)
chk("prach: reported primary scrambling code", int(one(d3, "psc")), 7)
bad = [k for k in range(4096) if not close(chips3[k], preamble(0, 112)[k])]
chk("prach: all 4096 chips for n = 16*7+0", bad[:8], [])

# (d) every signature against the generated Hadamard matrix
bad_sig = []
for s in range(16):
    path_s, _ = prach_file("--bare", "--signature", str(s), "--rate", "1",
                           name="sig%d.cf32" % s)
    cs, _ = read_cf32(path_s)
    w = preamble(s, 0)
    if [k for k in range(4096) if not close(cs[k], w[k])][:1]:
        bad_sig.append(s)
chk("prach: all 16 signatures equal the generated Table 3", bad_sig, [])
# P0 and P1 differ in 8 of 16 positions, so exactly 2048 of 4096 chips differ.
path0, _ = prach_file("--bare", "--signature", "0", "--rate", "1", name="s0.cf32")
path1, _ = prach_file("--bare", "--signature", "1", "--rate", "1", name="s1.cf32")
c0, _ = read_cf32(path0)
c1, _ = read_cf32(path1)
chk("prach: a wrong signature changes 2048 of 4096 chips",
    sum(1 for k in range(4096) if c0[k] != c1[k]), 2048)

# (e) separability of the two multiplications.  --no-scrambling forces S_r-pre
#     to +1 and --no-signature forces C_sig to +1; both are diagnostic
#     switches, not physical signals.  If the two steps really are separable
#     then full / no-signature is exactly C_sig (a 16-chip period) and
#     full / no-scrambling is exactly the Gold sequence.
path_f, _ = prach_file("--bare", "--signature", "5", "--rate", "1", name="f.cf32")
path_ns, _ = prach_file("--bare", "--signature", "5", "--rate", "1",
                        "--no-scrambling", name="ns.cf32")
path_ng, _ = prach_file("--bare", "--signature", "5", "--rate", "1",
                        "--no-signature", name="ng.cf32")
cf, _ = read_cf32(path_f)
cs, _ = read_cf32(path_ns)
cg, _ = read_cf32(path_ng)
chk("prach: with the scrambling zeroed the chips repeat every 16 chips",
    sum(1 for k in range(4096 - 16) if cs[k] != cs[k + 16]), 0)
chk("prach: with the signature zeroed the 16-chip period is gone (about half of "
    "the positions differ)", sum(1 for k in range(4096 - 16) if cg[k] != cg[k + 16]) > 1500,
    True)
ratio_sig = [cf[k] / cg[k] for k in range(4096)]
chk("prach: full / no-signature is exactly C_sig of signature 5",
    all(abs(ratio_sig[k].real - sig_sign(5, k % 16)) < 1e-5 and
        abs(ratio_sig[k].imag) < 1e-5 for k in range(4096)), True)
chk("prach: full / no-signature takes two values (a 16-chip period)",
    len({round(ratio_sig[k].real, 5) for k in range(4096)}), 2)
g_full = gold(0, 4096)          # signature 5 with --psc 0 --code 0 uses n = 0
ratio_scr = [cf[k] / cs[k] for k in range(4096)]
chk("prach: full / no-scrambling is exactly S_r-pre, the Gold sequence",
    all(abs(ratio_scr[k].real - g_full[k]) < 1e-5 and
        abs(ratio_scr[k].imag) < 1e-5 for k in range(4096)), True)

# (f) access slot placement.  STRUCTURAL INVARIANT, NOT A KNOWN ANSWER: it says
#     the preamble sits at slot*5120 chips of a two-frame window (TS 25.211
#     5.2.2.1.1, 15 slots at 5120 chips), which is what 15 * 5120 = 76800 buys;
#     it says nothing about the samples themselves being correct.
path_w, dw = prach_file("--slot", "14", "--rate", "1", name="w.cf32")
cw, _ = read_cf32(path_w)
chk("prach: the access slot window is two frames, 15 * 5120 = 76800 chips",
    int(one(dw, "window_chips")), 76800)
chk("prach: slot 14 starts at 71680 chips of the window",
    int(one(dw, "access_slot_offset_chips")), 71680)
nonzero = [k for k in range(len(cw)) if cw[k] != 0]
chk("prach: structurally, slot 14 holds exactly 4096 non-zero chips", len(nonzero), 4096)
chk("prach: structurally, they start at chip 71680", nonzero[0], 71680)
chk("prach: structurally, the window has no energy before the preamble",
    sum(1 for k in range(71680) if cw[k] != 0), 0)

# (g) byte compatibility with the writer of tools/umts_phy.py.  Its item sizes
#     are read out of ITS source (never restated here), and its three formulas
#     -- cf32 as float32 pairs, ci16 as clip(round(x*32767), -32768, 32767) and
#     cu8 as clip(round(x*127 + 127.5), 0, 255), tools/umts_phy.py quantise() --
#     are applied to the cf32 chips that (b) already held against the clause.
#     So a file this tool writes and a file that tool writes carry the same
#     numbers for the same chips, which is what "byte compatible" means here.
# the tree's own writer is the reference, so it is looked for beside this suite
# first: UMTS_UPLINK_TOOL may point at a copy somewhere else entirely
phy = ""
for cand in (os.path.join(HERE, "umts_phy.py"),
             os.path.join(os.path.dirname(TOOL), "umts_phy.py")):
    if os.path.isfile(cand):
        phy = cand
        break
chk_true("prach: tools/umts_phy.py found for the byte comparison", bool(phy), phy)
psrc = open(phy).read() if phy else ""


def phy_dict(name):
    m = re.search(r"^%s = \{(.*?)\}" % name, psrc, re.M | re.S)
    return dict(re.findall(r'"(\w+)":\s*([0-9.]+)', m.group(1))) if m else {}


items = dict((k, int(float(v))) for k, v in phy_dict("FORMAT_ITEM_BYTES").items())
if items:
    chk("prach: umts_phy FORMAT_ITEM_BYTES read out of its source",
        (items.get("cf32"), items.get("ci16"), items.get("cu8")), (8, 4, 2))
else:
    # its source could not be parsed here: SKIP the comparison, never guess
    skip("prach: umts_phy byte compatibility",
         "FORMAT_ITEM_BYTES not found in %r" % phy)


def clip(v, lo, hi):
    return lo if v < lo else (hi if v > hi else v)


for fmt in ("ci16", "cu8") if items else ():
    path_fmt, d_fmt = prach_file("--bare", "--format", fmt, "--rate", "1",
                                 name="p.%s" % fmt)
    with open(path_fmt, "rb") as fh:
        raw = fh.read()
    chk("prach: %s is %d octets per chip" % (fmt, items[fmt]), len(raw),
        4096 * items[fmt])
    chk("prach: %s bytes row" % fmt, int(one(d_fmt, "bytes")), 4096 * items[fmt])
    if fmt == "ci16":
        vals = struct.unpack("<%dh" % (2 * 4096), raw)
        want = []
        for c in chips:
            want.append(clip(int(round(c.real * 32767.0)), -32768, 32767))
            want.append(clip(int(round(c.imag * 32767.0)), -32768, 32767))
    else:
        vals = struct.unpack("<%dB" % (2 * 4096), raw)
        want = []
        for c in chips:
            want.append(clip(int(round(c.real * 127.0 + 127.5)), 0, 255))
            want.append(clip(int(round(c.imag * 127.0 + 127.5)), 0, 255))
    chk("prach: %s holds the umts_phy quantisation of the clause chips" % fmt,
        list(vals) == want, True)

# (h) --rate: 4 samples per chip is the same chip repeated four times
path_r, dr = prach_file("--bare", "--rate", "4", name="r.cf32")
cr, _ = read_cf32(path_r)
chk("prach: --rate 4 writes 4096 * 4 samples", len(cr), 4096 * 4)
chk("prach: --rate 4 repeats each chip (zero order hold)",
    all(cr[4 * k + j] == chips[k] for k in range(0, 4096, 97) for j in range(4)), True)
chk("prach: --rate 4 reports 15360000 Hz", int(one(dr, "rate")), 4 * 3840000)

# ── 4. the RACH message part, against the clause tables ───────────────────
# TS 25.211 5.2.2.1.3 Table 6: the data part is 10 * 2**k bits with k = 0..3,
# spread at SF 256, 128, 64, 32; a frame is 15 slots, so the data part carries
# 150, 300, 600 and 1200 bits per 10 ms.  Table 7: N_pilot = 8, N_TFCI = 2.
# Table 8: the pilot patterns below, transcribed from the clause text.
TABLE6 = ((0, 256, 10, 150), (1, 128, 20, 300), (2, 64, 40, 600), (3, 32, 80, 1200))
TABLE8 = ("11111110", "10101110", "10111011", "10101010", "11101011",
          "11111110", "11111010", "11101010", "10111110", "11111111",
          "10111011", "11101111", "11101010", "10101111", "10101111")

for k, sf, ndata, bits in TABLE6:
    p = run("message-part", "--k", str(k))
    d = rows_of(p)
    chk("message-part/k%d: exits 0" % k, p.returncode, 0)
    chk("message-part/k%d: spreading factor" % k, int(one(d, "spreading_factor")), sf)
    chk("message-part/k%d: N_data per slot" % k, int(one(d, "ndata").split(" ")[0]), ndata)
    chk("message-part/k%d: N_data per 10 ms" % k, int(one(d, "ndata_frame")), bits)
    chk("message-part/k%d: data bits = N_data * 15 slots" % k, bits, ndata * 15)
    chk("message-part/k%d: 15 slots" % k, int(one(d, "slots")), 15)
    chk("message-part/k%d: 2560 chips per slot" % k, int(one(d, "chips_slot")), 2560)
    chk("message-part/k%d: 38400 chips per 10 ms" % k, int(one(d, "chips_frame")), 38400)
    chk("message-part/k%d: 8 pilot + 2 TFCI control bits" % k,
        int(one(d, "control_bits_slot")), 10)
    chk("message-part/k%d: 30 TFCI bits per frame" % k, int(one(d, "tfci_bits")), 30)
    chk("message-part/k%d: the pilot patterns are Table 8" % k,
        tuple(one(d, "pilot[%d]" % s) for s in range(15)), TABLE8)
    p2 = run("message-part", "--sf", str(sf))
    d2 = rows_of(p2)
    chk("message-part/k%d: --sf %d names the same slot format" % (k, sf),
        (int(one(d2, "spreading_factor")), int(one(d2, "slot_format").split(" ")[0])),
        (sf, k))

# the channelisation codes follow TS 25.213 4.3.1.3: for preamble signature s the
# control part is cc = Cch,256,m with m = 16*s + 15 and the data part is
# cd = Cch,SF,m with m = SF*s/16.  Derived from the clause, not from the tool:
#   s=0, SF=256 -> m = 15   and m = 256*0/16  = 0
#   s=5, SF=64  -> m = 95   and m = 64*5/16   = 20
#   s=15, SF=32 -> m = 255  and m = 32*15/16  = 30
for sig, sf, cc_want, cd_want in ((0, 256, 15, 0), (5, 64, 95, 20),
                                  (15, 32, 255, 30)):
    d = rows_of(run("message-part", "--sf", str(sf), "--signature", str(sig)))
    chk("message-part/sig%d SF%d: control code Cch,256,%d" % (sig, sf, cc_want),
        one(d, "cc_code"), "Cch,256,%d" % cc_want)
    chk("message-part/sig%d SF%d: data code Cch,%d,%d" % (sig, sf, sf, cd_want),
        one(d, "cd_code"), "Cch,%d,%d" % (sf, cd_want))
    chk("message-part/sig%d SF%d: code numbers as reported" % (sig, sf),
        (int(one(d, "cc_code_number")), int(one(d, "cd_code_number"))),
        (cc_want, cd_want))

# the TFCI codeword is split two bits per slot, slot s carrying bits 2s and 2s+1
tfci_iv = 0x15555555
d = rows_of(run("message-part", "--tfci", "0x%x" % tfci_iv))
want_tfci = format(tfci_iv, "030b")
chk("message-part: the TFCI codeword is the 30 bits given", one(d, "tfci"), want_tfci)
chk("message-part: slot s carries TFCI bits 2s and 2s+1",
    tuple(one(d, "tfci_slot[%d]" % s) for s in range(15)),
    tuple(want_tfci[2 * s:2 * s + 2] for s in range(15)))

# the data bit string is taken as given (600 bits = 150 hex digits, exact)
data_hex = "3" * 150
d = rows_of(run("message-part", "--k", "2", "--data", data_hex))
chk("message-part: the data bits are the bits given", one(d, "data"), data_hex)
chk("message-part: data_bits row", int(one(d, "data_bits")), 600)
# Slot format 0 carries 150 data bits, which no hex string can express exactly
# (a hex digit is four bits), so a shorter string is a value and is padded with
# zero bits at the front.  The 148-bit value 0x333..3 (37 digits) shifted up by
# two zero bits is 0xCCCC..C over 150 bits, and the tool's hex rendering pads the
# tail to a whole nibble (TS 25.331 12.1), so the row reads one zero nibble and
# 37 c nibbles.
d = rows_of(run("message-part", "--k", "0", "--data", "3" * 37))
chk("message-part: a 150-bit data field from 148 bits of hex",
    one(d, "data"), "0" + "c" * 37)
chk("message-part: data_pad row names the two zero bits",
    int(one(d, "data_pad").split(" ")[0]), 2)

# ── 5. refusals: rc 2, the clause that justifies them, no output ──────────
REFUSALS = (
    (("request", "--measured"), "10.2.39"),
    (("request", "--v3d0"), "10.2.39"),
    (("request", "--imsi", "234015678901234", "--tmsi", "1"), "10.3.3.15"),
    (("request", "--mcc", "46"), "11.3"),
    (("request", "--cause", "detach-now"), "cause"),
    (("prach", "--signature", "16"), "5.2.2.1.2"),
    (("prach", "--slot", "15"), "5.2.2.1.1"),
    (("prach", "--format", "f32"), "cf32"),
    (("prach", "--out", "-"), "stdout"),
    (("prach", "--out", "/"), "cannot write"),
    (("prach", "--rate", "100"), "3840000"),
    (("message-part", "--tfci", "0x40000000"), "30"),
    (("message-part", "--sf", "512"), "Table 6"),
    (("message-part", "--signature", "16"), "4.3.1.3"),
    # 152 bits of hex cannot fit the 150-bit data part of slot format 0
    (("message-part", "--data", "f" * 38), "Table 6"),
)
for args, clause in REFUSALS:
    p = run(*args)
    name = " ".join(args)
    chk_true("%s refuses with exit 2" % name, p.returncode == 2,
             "exit %d" % p.returncode)
    chk_true("%s names %s in WHY" % (name, clause), clause in p.stderr,
             "stderr: %r" % p.stderr[:200])
    chk_true("%s writes nothing to stdout" % name, p.stdout == "", p.stdout[:120])

# every verb names what it does not build, in a limit row that cites a clause
for args, key in ((("request",), "request-optional-ies"),
                  (("prach",), "prach-no-pulse-shaping"),
                  (("message-part",), "message-part-scrambling"),
                  (("message-part",), "message-part-tfci-coding")):
    lim = " ".join(rows_of(run(*args)).get("limit", []))
    chk_true("%s prints a limit row for %s" % (" ".join(args), key), key in lim,
             "limits: %r" % lim[:160])
    chk_true("%s cites a TS 25 clause in its limit rows" % " ".join(args),
             "TS 25." in lim, lim[:160])

# ── 6. the tool runs without numpy ────────────────────────────────────────
blockdir = os.path.join(WORK, "nonumpy")
os.makedirs(blockdir, exist_ok=True)
with open(os.path.join(blockdir, "numpy.py"), "w") as fh:
    fh.write("raise ImportError('numpy is blocked by tools/check-umts-uplink.sh')\n")
env = os.environ.copy()
env["PYTHONPATH"] = blockdir
# the control for the control: with that block in place numpy cannot be imported
p = subprocess.run([sys.executable, "-c", "import numpy"], capture_output=True,
                   text=True, env=env)
chk_true("no-numpy: the blocker really blocks numpy", p.returncode != 0,
         "exit %d" % p.returncode)
p = run("prach", "--bare", "--out", os.path.join(WORK, "nb.cf32"), env=env)
chk("no-numpy: prach still runs", p.returncode, 0)
chk_true("no-numpy: prach still writes its rows", "preamble_chips" in p.stdout,
         p.stdout[:120])
p = run("request", env=env)
chk("no-numpy: request still runs", p.returncode, 0)
chk("no-numpy: request still produces the hand-derived octets",
    one(rows_of(p), "hex"), VECTORS[0]["hex"])
src = open(TOOL).read()
chk("no-numpy: the tool does not import numpy at all",
    [l.strip() for l in src.splitlines()
     if l.strip().startswith(("import numpy", "from numpy"))], [])

# ── 7. negation controls ─────────────────────────────────────────────────
# Three mutants, one constant each, plus one unchanged copy through the same
# comparison path.  A mutant must still run and must DIVERGE from what the
# referee derived; the unchanged copy must still MATCH, so a mutant that failed
# for an unrelated reason (a copy that does not import, a typo in the harness)
# cannot make the negation control pass.


def mutant(old, new, label):
    src = open(TOOL).read()
    if src.count(old) != 1:
        chk_true("negation %s: the anchor appears exactly once in the tool" % label,
                 False, "count = %d for %r" % (src.count(old), old))
        return None
    path = os.path.join(WORK, "mutant-%s.py" % label)
    with open(path, "w") as fh:
        fh.write(src.replace(old, new))
    return path


# (1) the UL-CCCH-MessageType alternative: 1 (rrcConnectionRequest) -> 0
m = mutant('e.enum("message", 1, 2, 4,', 'e.enum("message", 0, 2, 4,', "choice")
if m:
    p = run("request", tool=m)
    chk("negation/choice: the mutant still runs", p.returncode, 0)
    got = one(rows_of(p), "hex")
    chk_true("negation/choice: the mutant's bits diverge from the hand-derived vector",
             got != VECTORS[0]["hex"], "still %s" % got)
    try:
        same = py_decode(bytes.fromhex(got))["message"][0] == "rrcConnectionRequest"
    except Exception:
        same = False
    chk_true("negation/choice: pycrate no longer reads rrcConnectionRequest",
             not same, "pycrate still reads rrcConnectionRequest")

# (2) one chip phase of the PRACH preamble: exp(j pi/4) -> exp(-j pi/4), which
#     must change exactly the 1 in 4 chips with k mod 4 == 0.
m = mutant("    complex(1.0, 1.0) / math.sqrt(2.0),",
           "    complex(1.0, -1.0) / math.sqrt(2.0),", "phase")
if m:
    path = os.path.join(WORK, "mut.cf32")
    p = run("prach", "--bare", "--rate", "1", "--out", path, tool=m)
    chk("negation/phase: the mutant still runs", p.returncode, 0)
    cm, _ = read_cf32(path)
    w = preamble(0, 0)
    diff = sum(1 for k in range(4096) if not close(cm[k], w[k]))
    chk("negation/phase: the mutant's chips diverge from the clause at 1024 chips",
        diff, 1024)

# (3) one pilot pattern of the message part: Table 8 slot 1 '10101110' -> '10101111'
m = mutant('    "10101110",\n', '    "10101111",\n', "pilot")
if m:
    p = run("message-part", "--k", "1", tool=m)
    chk("negation/pilot: the mutant still runs", p.returncode, 0)
    got = one(rows_of(p), "pilot[1]")
    chk_true("negation/pilot: the mutant's slot 1 diverges from Table 8",
             got != TABLE8[1], "slot 1 = %r, Table 8 = %r" % (got, TABLE8[1]))

# the no-change control: an unmodified copy, through the same three paths
same = os.path.join(WORK, "unmodified.py")
shutil.copyfile(TOOL, same)
p = run("request", tool=same)
chk("no-change: the unmodified copy still runs request", p.returncode, 0)
chk("no-change: the unmodified copy still matches the hand-derived vector",
    one(rows_of(p), "hex"), VECTORS[0]["hex"])
path = os.path.join(WORK, "same.cf32")
p = run("prach", "--bare", "--rate", "1", "--out", path, tool=same)
chk("no-change: the unmodified copy still runs prach", p.returncode, 0)
csame, _ = read_cf32(path)
chk("no-change: the unmodified copy still matches the clause recomputation",
    sum(1 for k in range(4096) if not close(csame[k], preamble(0, 0)[k])), 0)
p = run("message-part", "--k", "1", tool=same)
chk("no-change: the unmodified copy still has Table 8 in slot 1",
    one(rows_of(p), "pilot[1]"), TABLE8[1])

# ── footer ───────────────────────────────────────────────────────────────
print()
print("CHECKED\t%d\tFAILED\t%d\tSKIPPED\t%d" % (CHECKS, FAILS, SKIPS))
if FAILS:
    for name in FAILED:
        print("FAILED\t%s" % name)
    print("RESULT FAIL(%d)" % FAILS)
    print("WORK\t%s" % WORK)
    sys.exit(1)
if SKIPS:
    print("RESULT SKIP(%d)" % SKIPS)
    print("WORK\t%s" % WORK)
    sys.exit(2)
shutil.rmtree(WORK, ignore_errors=True)
print("RESULT PASS")
sys.exit(0)
PY
