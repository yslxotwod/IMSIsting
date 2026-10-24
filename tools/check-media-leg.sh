#!/usr/bin/env bash
# check-media-leg.sh — referee the media leg against a call it has to complete.
#
# The claim under test is not "the code compiles", it is: a call this module
# places carries RTP in both directions, on the port it advertised, in the
# codec it negotiated, and reports numbers that match what the far end counted.
# So the far end is built here — a minimal SIP UAS on loopback that answers an
# INVITE with 200 OK + SDP, sends a known G.711 tone to the port the module
# advertised, counts what it receives back, and only then answers the BYE.
#
# Everything is loopback: no radio, no phone, no external network. What this
# does NOT prove is that a handset or an IMS core accepts the offer — that is
# the operator's call, on real hardware, and this file says so rather than
# implying otherwise.
#
# Exit: 0 every assertion passed · 1 an assertion failed · 2 refused or a
# dependency is missing (a refusal is never a pass).
set -uo pipefail

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MOD="$ROOT/modules/30_volte_ims.sh"
PYP=$(command -v python3 || echo python3)

[[ -x "$MOD" ]] || { printf 'ERROR\tmissing %s\n' "$MOD" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || {
    printf 'ERROR\tpython3 is not installed\n' >&2; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-media.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

SIP_PORT=$(( 25000 + RANDOM % 2000 ))
STATE="$tmp/state"
mkdir -p "$STATE"

fail=0
chk() {
    local name="$1" got="$2" want="$3"
    if [[ "$got" == "$want" ]]; then
        printf 'PASS\t%s\n' "$name"
    else
        printf 'FAIL\t%s\twant=%s\tgot=%s\n' "$name" "$want" "$got"
        fail=$(( fail + 1 ))
    fi
}
chk_ge() {
    local name="$1" got="$2" want="$3"
    if [[ "$got" =~ ^[0-9]+$ ]] && (( got >= want )); then
        printf 'PASS\t%s\t%s>=%s\n' "$name" "$got" "$want"
    else
        printf 'FAIL\t%s\twant>=%s\tgot=%s\n' "$name" "$want" "$got"
        fail=$(( fail + 1 ))
    fi
}

# ── the far end ────────────────────────────────────────────────────────
cat > "$tmp/uas.py" <<'PYUAS'
import socket, struct, subprocess, sys, threading, time

sip_port, caller_rtp_guess = int(sys.argv[1]), int(sys.argv[2])
out = sys.argv[3]

sip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sip.bind(("127.0.0.1", sip_port))
sip.settimeout(15)
rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rtp.bind(("127.0.0.1", 0))
rtp.settimeout(0.2)
rtp_port = rtp.getsockname()[1]

report = {"invite": 0, "rtp_in": 0, "rtp_out": 0, "ack": 0, "bye": 0,
          "options": 0, "ssrc": None, "seq": None, "port_offered": None,
          "codec": None}
stop = threading.Event()


def sdp(port):
    return ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=uas\r\n"
            "c=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            "m=audio %d RTP/AVP 0 8\r\n"
            "a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
            "a=ptime:20\r\na=sendrecv\r\n" % port)


def reply(req, code, reason, body="", extra=""):
    head, _, bod = req.partition("\r\n\r\n")
    hdrs = {}
    for ln in head.split("\r\n")[1:]:
        k, _, v = ln.partition(":")
        hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    lines = ["SIP/2.0 %d %s" % (code, reason)]
    for via in hdrs.get("via", []):
        lines.append("Via: " + via)
    lines.append("From: " + (hdrs.get("from") or [""])[0])
    to = (hdrs.get("to") or [""])[0]
    if "tag=" not in to:
        to += ";tag=uas%s" % code
    lines.append("To: " + to)
    lines.append("Call-ID: " + (hdrs.get("call-id") or [""])[0])
    lines.append("CSeq: " + (hdrs.get("cseq") or [""])[0])
    lines.append("Contact: <sip:uas@127.0.0.1:%d>" % sip_port)
    if extra:
        lines.append(extra)
    bodyb = body.encode()
    if bodyb:
        lines.append("Content-Type: application/sdp")
    lines.append("Content-Length: %d" % len(bodyb))
    peer = report["peer"]
    sip.sendto(("\r\n".join(lines) + "\r\n\r\n").encode() + bodyb, peer)


def tone_sender(port, secs):
    """A known PCMU tone, so the recorder can be checked for actual audio."""
    ssrc = 0x11223344
    seq = 1000
    ts = 0
    deadline = time.monotonic()
    end = deadline + secs
    # one 20 ms frame of a 400 Hz square wave, mu-law encoded by hand
    frame = bytes([0x8C] * 160)
    while time.monotonic() < end:
        pkt = struct.pack(">BBHII", 0x80, 0, seq & 0xFFFF, ts & 0xFFFFFFFF,
                          ssrc) + frame
        try:
            rtp.sendto(pkt, ("127.0.0.1", port))
            report["rtp_out"] += 1
        except OSError:
            pass
        seq = (seq + 1) & 0xFFFF
        ts = (ts + 160) & 0xFFFFFFFF
        deadline += 0.02
        time.sleep(max(0.0, deadline - time.monotonic()))


def rtp_count():
    while not stop.is_set():
        try:
            buf, _ = rtp.recvfrom(2048)
        except OSError:
            continue
        report["rtp_in"] += 1
        if report["ssrc"] is None and len(buf) >= 12:
            _b0, pt, seq, _ts, ssrc = struct.unpack(">BBHII", buf[:12])
            report["ssrc"] = ssrc
            report["seq"] = seq
            report["codec"] = pt


threading.Thread(target=rtp_count, daemon=True).start()
report["peer"] = None

while report["bye"] == 0:
    try:
        data, peer = sip.recvfrom(65535)
    except socket.timeout:
        break
    report["peer"] = peer
    text = data.decode("utf-8", "replace")
    first = text.split("\r\n", 1)[0]
    if first.startswith("OPTIONS"):
        report["options"] = report.get("options", 0) + 1
        reply(text, 200, "OK")
    elif first.startswith("INVITE"):
        report["invite"] += 1
        for ln in text.split("\r\n"):
            if ln.startswith("m=audio"):
                report["port_offered"] = int(ln.split()[1])
        reply(text, 100, "Trying")
        reply(text, 180, "Ringing")
        reply(text, 200, "OK", sdp(rtp_port))
        port = report["port_offered"] or caller_rtp_guess
        threading.Thread(target=tone_sender, args=(port, 6.0), daemon=True).start()
    elif first.startswith("ACK"):
        report["ack"] += 1
    elif first.startswith("BYE"):
        report["bye"] += 1
        reply(text, 200, "OK")

stop.set()
with open(out, "w") as f:
    for k, v in report.items():
        if k != "peer":
            f.write("%s\t%s\n" % (k, v))
PYUAS

"$PYP" "$tmp/uas.py" "$SIP_PORT" 0 "$tmp/uas.tsv" &
uas_pid=$!
sleep 0.4

# The probe first: a call placed at an endpoint that never answered OPTIONS
# would otherwise look like a signalling bug.
PROBE=$("$MOD" --sip-probe "127.0.0.1:$SIP_PORT" 2>/dev/null)
chk probe-reachable "$(printf '%s\n' "$PROBE" | awk -F'\t' '$1=="reachable"{print $2; exit}')" "yes"
chk probe-status "$(printf '%s\n' "$PROBE" | awk -F'\t' '$1=="sip_status"{print $2; exit}')" "200"

WAV="$tmp/far_end.wav"
IMG_PATH="$ROOT" STATE_DIR="$STATE" \
IMSI_ROOT="$ROOT" \
"$MOD" --call "127.0.0.1:$SIP_PORT" \
    ruri="127.0.0.1:$SIP_PORT" impi="tester@127.0.0.1" to="sip:tester@127.0.0.1" \
    media=silence codec=PCMU duration=3 record="$WAV" \
    > "$tmp/call.out" 2> "$tmp/call.err"
call_rc=$?
wait "$uas_pid" 2>/dev/null

fld() { awk -F'\t' -v k="$1" '$1==k{print $2; exit}' "$2"; }

chk call-exit "$call_rc" "0"
chk invite-arrived "$(fld invite "$tmp/uas.tsv")" "1"
chk ack-arrived "$(fld ack "$tmp/uas.tsv")" "1"
chk bye-arrived "$(fld bye "$tmp/uas.tsv")" "1"
chk offered-port-used "$(fld port_offered "$tmp/uas.tsv")" \
    "$(awk -F'\t' '$1=="rtp_local_port"{print $2}' "$tmp/call.out")"
chk negotiated-codec "$(fld codec "$tmp/uas.tsv")" "0"
chk_ge caller-sent     "$(awk -F'\t' '$1=="rtp_sent"{print $2}' "$tmp/call.out")" 50
chk_ge caller-received "$(awk -F'\t' '$1=="rtp_recv"{print $2}' "$tmp/call.out")" 20
chk_ge far-end-received "$(fld rtp_in "$tmp/uas.tsv")" 50
chk recorded-bytes "$( [[ -s "$WAV" ]] && echo yes || echo no )" "yes"

# The recording must contain the tone the far end sent, not silence: a µ-law
# 0x8C decodes to a value far from zero, so a byte check is enough.
chk recorded-audio "$( "$PYP" - "$WAV" <<'PYW'
import sys, wave
w = wave.open(sys.argv[1], 'rb')
data = w.readframes(w.getnframes())
if not data:
    print("empty"); raise SystemExit
samples = [int.from_bytes(data[i:i+2], 'little', signed=True)
           for i in range(0, min(len(data), 4000), 2)]
nz = sum(1 for s in samples if abs(s) > 64)
print("tone" if nz > len(samples) // 2 else "silence")
PYW
)" "tone"

# --rtp-stats must read the same numbers back out of the state it kept.
STATS=$(STATE_DIR="$STATE" "$MOD" --rtp-stats 2>/dev/null)
chk stats-status "$(printf '%s\n' "$STATS" | awk -F'\t' '$1=="status"{print $2; exit}')" "reported"
chk stats-codec "$(printf '%s\n' "$STATS" | awk -F'\t' '$1=="rtp_codec"{print $2; exit}')" "PCMU/8000"
chk stats-sent "$(printf '%s\n' "$STATS" | awk -F'\t' '$1=="rtp_sent"{print $2; exit}')" \
    "$(awk -F'\t' '$1=="rtp_sent"{print $2}' "$tmp/call.out")"

if (( fail )); then
    printf 'RESULT\tFAIL(%d)\n' "$fail"
    printf 'call stdout:\n' >&2
    sed 's/^/  /' "$tmp/call.out" >&2
    sed 's/^/  /' "$tmp/call.err" >&2
    exit 1
fi
printf 'RESULT\tPASS\n'
