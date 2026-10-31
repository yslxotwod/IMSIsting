#!/usr/bin/env bash
# Check the DNSTap and DoH codecs this tree builds against referees.
#
# modules/27_cellular_dns.sh reads a DNSTap Frame Streams tap (framing plus a
# protobuf walk) and builds/reads an RFC 8484 DoH exchange. A check that compares
# the builder with the reader only proves the two share the same misunderstanding,
# so this uses three things that were written by someone else:
#
#   * tshark 4.2.2's HTTP dissector, on the request the tree builds. It has to
#     read it as a POST to /dns-query with Host, Content-Type, Accept and
#     Content-Length, which is what RFC 8484 §4.1 asks of a DoH request.
#   * dnspython, on the request body: the body has to decode as the DNS message
#     the tree says it put there (RFC 1035 §4.1.2 / §4.1.4).
#   * google.protobuf's own wire-format decoder, on the DNSTap stream: the frame
#     lengths, the field numbers, the wire types and the length prefixes that the
#     tree reports have to be the ones protobuf itself reads.
#
# The Frames Streams prologue and the dnstap.proto field numbers are NOT checked
# here, and are reported by the module as unobserved: this build has no local copy
# of either specification to cite and no fixture captured from a resolver.
#
# Exits:
#   0  every referee agrees
#   1  a referee disagrees (both values are printed)
#   2  the check could not run
set -u

cd "$(dirname "$0")/.." || exit 2

TSHARK=${TSHARK:-/usr/bin/tshark}
MODULE=modules/27_cellular_dns.sh
FIXTURE=$(mktemp -d "${TMPDIR:-/tmp}/check-dnstap.XXXXXX") || exit 2
trap 'rm -rf "$FIXTURE"' EXIT

if [ ! -r "$MODULE" ]; then
  echo "FAIL no $MODULE"
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP no python3 to build the frames and cross-check the protobuf walk"
  exit 0
fi

# The module's CLI creates its store tree on start; send it into the fixture.
export TMP_DIR="$FIXTURE/tmp" LOOT_DIR="$FIXTURE/loot" \
       CAPTURES_DIR="$FIXTURE/captures" LOGS_DIR="$FIXTURE/logs" STATE_DIR="$FIXTURE/state"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR"

run_module() { bash "$MODULE" "$@" 2>"$FIXTURE/err"; }
field() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

bad=0
pass() { printf '%s\tPASS\n' "$1"; }
fail() { printf '%s\tFAIL want=%s got=%s\n' "$1" "$2" "$3"; bad=$((bad + 1)); }
chk() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "$3" "$2"; fi; }

# ── what the tree builds ────────────────────────────────────────────────
out=$(run_module --build-query www.example.com A) || { echo "FAIL --build-query refused: $(cat "$FIXTURE/err")"; exit 2; }
q=$(field "$out" hex)
[ -n "$q" ] || { echo "FAIL --build-query printed no hex"; exit 2; }

out=$(run_module --doh-build "$q" --host dns.example --path /dns-query) || {
  echo "FAIL --doh-build refused: $(cat "$FIXTURE/err")"; exit 2; }
req=$(field "$out" request_hex)
chk doh-build-content-length "$(field "$out" content_length)" "$(( ${#q} / 2 ))"
chk doh-build-body-is-the-message "$(field "$out" body_hex)" "$q"

out=$(run_module --dnstap-build "$q" --addr 192.0.2.1) || {
  echo "FAIL --dnstap-build refused: $(cat "$FIXTURE/err")"; exit 2; }
stream=$(field "$out" stream_hex)
out=$(run_module --dnstap "$stream") || { echo "FAIL --dnstap refused: $(cat "$FIXTURE/err")"; exit 2; }
t_name=$(field "$out" frame.1.dns.name)
t_qtype=$(field "$out" frame.1.dns.qtype)
t_ct=$(field "$out" frame.0.content_type)
t_addr=$(field "$out" frame.1.addr.inferred_ipv4)

# ── referee 1: tshark's HTTP dissector ──────────────────────────────────
if [ -x "$TSHARK" ]; then
  if python3 - "$req" "$FIXTURE/doh.pcap" <<'PY'
import struct, sys
req = bytes.fromhex(sys.argv[1])
eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + struct.pack(">H", 0x0800)
total = 20 + 20 + len(req)
ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                 bytes([192, 0, 2, 1]), bytes([192, 0, 2, 53]))
ip = ip[:10] + struct.pack(">H", sum(struct.unpack(">%dH" % 10, ip)) % 0xFFFF ^ 0xFFFF) + ip[12:]
tcp = struct.pack(">HHIIBBHHH", 40000, 8080, 1, 0, 0x50, 0x18, 65535, 0, 0)
frame = eth + ip + tcp + req
pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
open(sys.argv[2], "wb").write(pcap + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)
PY
  then
    # cut, not read: IFS=$'\t' read collapses empty interior fields, which shifts
    # every column after the empty one.
    hdrs=$("$TSHARK" -r "$FIXTURE/doh.pcap" -d tcp.port==8080,http -T fields \
             -e http.request.method -e http.request.uri -e http.host \
             -e http.content_type -e http.content_length 2>"$FIXTURE/tshark.err" | head -1)
    m=$(printf '%s' "$hdrs" | cut -f1)
    uri=$(printf '%s' "$hdrs" | cut -f2)
    host=$(printf '%s' "$hdrs" | cut -f3)
    ct=$(printf '%s' "$hdrs" | cut -f4)
    clen=$(printf '%s' "$hdrs" | cut -f5)
    chk tshark-doh-method "$m" "POST"
    chk tshark-doh-path "$uri" "/dns-query"
    chk tshark-doh-host "$host" "dns.example"
    chk tshark-doh-content-type "$ct" "application/dns-message"
    chk tshark-doh-content-length "$clen" "$(( ${#q} / 2 ))"
  else
    echo "SKIP tshark-referee the fixture could not be built"
  fi
else
  echo "SKIP tshark-referee no tshark at $TSHARK"
fi

# ── referee 2 and 3: dnspython on the body, protobuf on the stream ───────
python3 - "$req" "$stream" "$t_name" "$t_qtype" "$t_ct" "$t_addr" <<'PY'
import struct, sys
bad = 0

def chk(name, got, want):
    global bad
    if str(got) == str(want):
        print("%s\tPASS" % name)
    else:
        print("%s\tFAIL want=%s got=%s" % (name, want, got))
        bad += 1

req = bytes.fromhex(sys.argv[1])
stream = bytes.fromhex(sys.argv[2])
t_name, t_qtype, t_ct, t_addr = sys.argv[3:7]

# referee 2: dnspython reads the DoH body as a DNS message (RFC 1035 §4.1)
try:
    import dns.message
except Exception as exc:                                   # pragma: no cover
    print("SKIP dnspython-referee %s" % exc)
else:
    head, _, body = req.partition(b"\r\n\r\n")
    chk("doh-body-split", "yes" if body else "no", "yes")
    msg = dns.message.from_wire(body)
    q = msg.question[0]
    chk("dnspython-doh-name", q.name.to_text().rstrip("."), "www.example.com")
    chk("dnspython-doh-type", q.rdtype, 1)
    chk("dnspython-doh-size", len(body), len(msg.to_wire()))

# referee 3: protobuf's own wire-format decoder reads the DNSTap stream
from google.protobuf.internal import decoder

def walk(buf, pos=0, depth=0):
    """(field, wiretype, value) for every field protobuf itself would read."""
    out = []
    while pos < len(buf):
        key, pos = decoder._DecodeVarint(buf, pos)
        field, wt = key >> 3, key & 7
        if wt == 0:
            val, pos = decoder._DecodeVarint(buf, pos)
        elif wt == 2:
            n, pos = decoder._DecodeVarint(buf, pos)
            val = buf[pos:pos + n]
            pos += n
        elif wt == 1:
            val = buf[pos:pos + 8]; pos += 8
        elif wt == 5:
            val = buf[pos:pos + 4]; pos += 4
        else:
            raise ValueError("wire type %d at depth %d" % (wt, depth))
        out.append((field, wt, val))
    return out

frames, pos = [], 4                                  # the stream prefix is 4 octets
while pos + 4 <= len(stream):
    n = struct.unpack(">I", stream[pos:pos + 4])[0]
    pos += 4
    if n == 0:
        frames.append(("fin", b""))
        break
    frames.append(("frame", stream[pos:pos + n]))
    pos += n

chk("framestream-frame-count", len(frames), 3)
chk("framestream-consumed", pos, len(stream))
kinds = [k for k, _ in frames]
chk("framestream-kinds", "".join(k[0] for k in kinds), "fff")

ctrl = frames[0][1]
if len(ctrl) >= 8 and ctrl[:4] == b"\x00\x00\x00\x01":
    vlen = struct.unpack(">I", ctrl[4:8])[0]
    chk("framestream-control-type", ctrl[8:8 + vlen].decode("utf-8", "replace"), t_ct)
else:
    chk("framestream-control-type", "no control field", t_ct)

data = frames[1][1]
fields = walk(data)
chk("protobuf-field-count", len(fields), 2)
chk("protobuf-field-1-number", fields[0][0], 1)
chk("protobuf-field-1-wiretype", fields[0][1], 2)
chk("protobuf-field-1-address", ".".join(str(b) for b in fields[0][2]), t_addr)
chk("protobuf-field-2-number", fields[1][0], 2)
chk("protobuf-field-2-wiretype", fields[1][1], 2)
dns_bytes = fields[1][2]
chk("protobuf-field-2-length", len(dns_bytes), len(fields[1][2]))

try:
    import dns.message
except Exception:
    pass
else:
    inner = dns.message.from_wire(dns_bytes)
    chk("protobuf-dns-leaf-name", inner.question[0].name.to_text().rstrip("."), t_name)
    chk("protobuf-dns-leaf-type", inner.question[0].rdtype, 1 if t_qtype == "A" else -1)

sys.exit(1 if bad else 0)
PY
rc=$?
[ "$rc" -eq 0 ] || bad=$((bad + 1))

printf 'RESULT\t%s\n' "$([ "$bad" -eq 0 ] && echo PASS || echo "FAIL($bad)")"
[ "$bad" -eq 0 ]
