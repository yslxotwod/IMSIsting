#!/usr/bin/env bash
# Offline framing checks for the UMTS GSMTAP capture reader.
set -euo pipefail
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/umts_catcher.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PCAP="$TMP/umts.pcap"

python3 - "$PCAP" <<'PY'
import struct
import sys

path = sys.argv[1]

def packet(payload, subtype=4, port=4729, gsmtap_type=12):
    gsmtap = bytes([2, 4, gsmtap_type, 0, 0, 1, 0, 0, 0, 0, 0, 0, subtype, 0, 0, 0]) + payload
    udp = struct.pack('!HHHH', 40000, port, 8 + len(gsmtap), 0) + gsmtap
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack('!H', 20 + len(udp))
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = bytes([192, 0, 2, 1])
    ip[16:20] = bytes([192, 0, 2, 2])
    return bytes(ip) + udp

# Synthetic non-identifying payloads exercise only packet framing and redaction.
frames = [
    (1, 250000, packet(bytes.fromhex('4800000000'), subtype=4)),
    (2, 500000, packet(bytes.fromhex('6c00602800c8404109a2b3c48091a2b0'), subtype=8)),
    (3, 0, packet(b'ignored', port=9999)),
]
with open(path, 'wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
    for sec, usec, data in frames:
        f.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
        f.write(data)
PY

out=$(python3 "$TOOL" pcap-analyze "$PCAP")
line_count=$(printf '%s\n' "$out" | awk -F '\t' '$1 == "frame" {n++} END {print n+0}')
[[ "$line_count" == 2 ]]
printf '%s\n' "$out" | grep -F $'frame\t1\t1.250000\t4\tDCCH\t5' >/dev/null
printf '%s\n' "$out" | grep -F $'frame\t2\t2.500000\t8\tDCH\t16' >/dev/null
! printf '%s\n' "$out" | grep -Eiq '6c006028|c8404109|4800000000|imsi|identity'
# Truncated record data must fail closed and produce no frame summaries.
cp "$PCAP" "$TMP/truncated.pcap"
python3 - "$TMP/truncated.pcap" <<'PY'
import sys
path = sys.argv[1]
data = open(path, 'rb').read()
open(path, 'wb').write(data[:-1])
PY
if python3 "$TOOL" pcap-analyze "$TMP/truncated.pcap" >"$TMP/out" 2>"$TMP/err"; then
    echo 'truncated pcap unexpectedly succeeded' >&2
    exit 1
fi
grep -F $'ERROR\ttruncated pcap packet' "$TMP/err" >/dev/null
printf 'RESULT\tPASS\n'
