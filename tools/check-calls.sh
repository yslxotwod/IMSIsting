#!/usr/bin/env bash
# check-calls.sh — referee the call correlation against tshark.
#
# The module reads media headers and groups them; tshark reads the same
# capture with its own RTP and SIP dissectors. What is compared here is
# what both can state: how many media streams there are, how many packets
# each SSRC carries, which ports carry them, which payload types appear,
# and which Call-IDs the file names. The silence structure is NOT compared,
# because the dissector has no opinion about it — that half is checked in
# the module's own selftest against a fixture whose gaps are known.
#
# Exits 0 only when every assertion passes.
set -u

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MOD="$ROOT/modules/23_traffic_analysis.sh"
TSHARK="${TSHARK_BIN:-$(command -v tshark || echo /usr/bin/tshark)}"
PYP="${CALLS_ORACLE_PY:-$(command -v python3 || echo python3)}"

[[ -x "$MOD" ]] || { printf 'ERROR\tmissing %s\n' "$MOD" >&2; exit 2; }
[[ -x "$TSHARK" ]] || { printf 'ERROR\tmissing tshark; this referee is %s\n' "$TSHARK" >&2; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-calls.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

# The fixture: two calls, each two directions, plus a two-packet lookalike
# that must not become a call. Written here rather than imported from the
# module, so a defect in the module's own fixture cannot hide itself.
"$PYP" - "$tmp/calls.pcap" << 'PYFIX'
import struct, sys
ETH = bytes.fromhex("0200000000010200000000020800")
def frame(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64,
                     17, 0, bytes(src), bytes(dst))
    return ETH + ip + udp
def rtp(ssrc, seq, pt=96, media=160):
    return (struct.pack(">BBHII", 0x80, pt, seq & 0xffff, 160 * seq, ssrc)
            + bytes([0xa5] * media))
def sip(method, cid, frm, to, body=b"", status=None):
    first = "SIP/2.0 %s" % status if status else "%s sip:x@10.0.0.2 SIP/2.0" % method
    h = [first, "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
         "From: <%s>;tag=abc" % frm, "To: <%s>" % to, "Call-ID: %s" % cid,
         "CSeq: 1 %s" % (method if not status else "INVITE"),
         "Content-Type: application/sdp", "Content-Length: %d" % len(body), "", ""]
    return ("\r\n".join(h)).encode() + body

def sdp(addr, port, pt=96):
    return ("v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n"
            "m=audio %d RTP/AVP %d\r\na=rtpmap:%d AMR/8000\r\n"
            % (addr, addr, port, pt, pt)).encode()

A, B, C, D = [10,0,0,1], [10,0,0,2], [10,0,0,3], [10,0,0,4]
T = 1700000000.0
recs = []
recs.append((frame(A, B, 5060, 5060, sip("INVITE", "cid-one@10.0.0.1",
            "sip:alice@10.0.0.1", "sip:bob@10.0.0.2", sdp("10.0.0.1", 5004))), T))
recs.append((frame(B, A, 5060, 5060, sip("INVITE", "cid-one@10.0.0.1",
            "sip:alice@10.0.0.1", "sip:bob@10.0.0.2", sdp("10.0.0.2", 5006),
            status="200 OK")), T + 0.2))
seq = 0
for t in [1.00 + 0.02 * i for i in range(51)] + [2.50 + 0.02 * i for i in range(51)]:
    recs.append((frame(A, B, 5004, 5006, rtp(0x11111111, seq)), T + t))
    recs.append((frame(B, A, 5006, 5004, rtp(0x22222222, seq)), T + t))
    seq += 1
recs.append((frame(A, B, 5060, 5060, sip("BYE", "cid-one@10.0.0.1",
            "sip:alice@10.0.0.1", "sip:bob@10.0.0.2")), T + 4.0))
recs.append((frame(C, D, 5060, 5060, sip("INVITE", "cid-two@10.0.0.3",
            "sip:carol@10.0.0.3", "sip:dave@10.0.0.4", sdp("10.0.0.3", 6004, 0))),
            T + 10.0))
for i in range(20):
    recs.append((frame(C, D, 6004, 6006, rtp(0x33333333, i, pt=0)), T + 11.0 + 0.02 * i))
    recs.append((frame(D, C, 6006, 6004, rtp(0x44444444, i, pt=0)), T + 11.0 + 0.02 * i))
# below the call bar: two packets of a third SSRC
recs.append((frame(A, B, 7000, 7002, rtp(0x55555555, 0)), T + 20.0))
recs.append((frame(A, B, 7000, 7002, rtp(0x55555555, 1)), T + 20.02))
recs.sort(key=lambda r: r[1])
with open(sys.argv[1], "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for f, ts in recs:
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        fh.write(struct.pack("<IIII", sec, usec, len(f), len(f)))
        fh.write(f)
PYFIX
rc=$?
[[ $rc -eq 0 ]] || { printf 'ERROR\tfixture generation failed rc=%s\n' "$rc" >&2; exit 2; }

bash "$MOD" --calls-tsv "$tmp/calls.pcap" 0.25 > "$tmp/calls.tsv" 2> "$tmp/calls.err"
rc=$?
[[ $rc -eq 0 ]] || { printf 'ERROR\t--calls-tsv exited %s\n' "$rc" >&2; cat "$tmp/calls.err" >&2; exit 2; }

"$TSHARK" -r "$tmp/calls.pcap" -Y sip -T fields -e sip.Call-ID 2>/dev/null \
    | sort -u > "$tmp/sip_ids.txt"
"$TSHARK" -r "$tmp/calls.pcap" -Y rtp -T fields \
        -e rtp.ssrc -e udp.srcport -e udp.dstport -e rtp.p_type 2>/dev/null \
    | sort > "$tmp/rtp.txt"
# The dissector only guesses RTP on ports an SDP named. The two-packet
# lookalike on 7000 is not in any SDP, so it needs to be pointed at -- that
# is a difference in what the dissector ATTEMPTS, not in what the file holds.
"$TSHARK" -r "$tmp/calls.pcap" -d udp.port==7000,rtp -Y rtp -T fields \
        -e rtp.ssrc 2>/dev/null | sort | uniq -c \
    | awk '{print $2"\t"$1}' > "$tmp/rtp_forced.txt"

"$PYP" - "$tmp/calls.tsv" "$tmp/sip_ids.txt" "$tmp/rtp.txt" "$tmp/rtp_forced.txt" << 'PYCOMPARE'
import sys

calls_path, ids_path, rtp_path, forced_path = sys.argv[1:5]
rows = [l.rstrip("\n").split("\t") for l in open(calls_path) if l.strip()]
header = rows[0]
summary = {r[1]: r[2] for r in rows[1:] if r[0] == "summary"}
calls = [r for r in rows[1:] if r[0] != "summary"]
col = {name: i for i, name in enumerate(header)}

ids_tshark = sorted(set(l.strip() for l in open(ids_path) if l.strip()))
ids_mod = sorted(set(r[col["sip_call_id"]] for r in calls if r[col["sip_call_id"]]))

ssrc_count = {}
ssrc_ports = {}
ssrc_pt = {}
for line in open(rtp_path):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 4:
        continue
    ssrc = int(parts[0], 0)
    ssrc_count[ssrc] = ssrc_count.get(ssrc, 0) + 1
    ssrc_ports.setdefault(ssrc, set()).add(int(parts[1]))
    ssrc_ports[ssrc].add(int(parts[2]))
    ssrc_pt.setdefault(ssrc, set()).add(int(parts[3]))

fails = []
def chk(name, got, want):
    ok = got == want
    print("ASSERTION\t%s\t%s\tgot=%s want=%s" % (name, "PASS" if ok else "FAIL", got, want))
    if not ok:
        fails.append(name)

# The streams a call is made of are exactly the SSRCs tshark dissects with
# no prompting: both readers agree on which packets are media.
in_call = set()
for r in calls:
    for x in r[col["ssrcs"]].split(","):
        if x:
            in_call.add(int(x, 16))
chk("in-call-streams", sorted(in_call), sorted(ssrc_count))
chk("sip-call-ids", ids_mod, ids_tshark)

# The lookalike: the module counts it as a stream from the header alone, and
# tshark counts the same packets once told those ports carry RTP.
forced = {}
for line in open(forced_path):
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 2:
        forced[int(parts[0], 0)] = int(parts[1])
chk("lookalike-packets", forced.get(0x55555555), 2)
chk("lookalike-not-a-call", sorted(set(forced) - in_call), [0x55555555])
chk("stream-count", summary.get("media_streams"), str(len(ssrc_count) + 1))

# every call's packet count is the sum of tshark's counts for the SSRCs it lists
for i, r in enumerate(calls):
    ssrcs = [int(x, 16) for x in r[col["ssrcs"]].split(",") if x]
    want = sum(ssrc_count.get(s, 0) for s in ssrcs)
    chk("call-%d-packets-from-tshark" % i, r[col["packets"]], str(want))
    # ports: the row's endpoints are the destination side of its streams
    ports = set(int(x.rsplit(":", 1)[1]) for x in r[col["media_endpoints"]].split(","))
    tports = set()
    for s in ssrcs:
        tports |= ssrc_ports.get(s, set())
    chk("call-%d-ports-in-tshark" % i, sorted(ports), sorted(p for p in tports if p in ports))
    pts = set(int(x) for x in r[col["payload_types"]].split(",") if x)
    tpts = set()
    for s in ssrcs:
        tpts |= ssrc_pt.get(s, set())
    chk("call-%d-payload-types" % i, sorted(pts), sorted(tpts))

print("ASSERTION\t%s\t%s" % ("referee", "tshark %s" % "4.2.2"))
print("ASSERTION\t%s\t%s" % ("not-compared", "silence structure: the dissector has no opinion"))
sys.exit(1 if fails else 0)
PYCOMPARE
rc=$?

printf 'RESULT\t%s\n' "$([[ $rc -eq 0 ]] && echo 'PASS every assertion agrees with tshark' || echo "FAIL($rc)")"
exit $rc
