#!/usr/bin/env bash
# diaprobe-selftest — proves the probe kit can talk Diameter without a network.
#
# Runs a loopback SCTP peer in the background, fires every message type at it,
# and asserts the answers come back decoded. No radio, no root, no internet,
# per AGENTS.md §4.
#
#   tools/diameter-probe/selftest.sh
#
# Prints ASSERTION rows then RESULT PASS|FAIL.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$ROOT/tools/diameter-probe/diaprobe.py"
PY="${PYTHON:-python3}"
PYCRATE_SITE="$HOME/.local/lib/python3.12/site-packages"
PORT="${PORT:-39971}"

fail=0
assert() {
    local name="$1" want="$2" got="$3"
    if [ "$want" = "$got" ]; then
        echo "ASSERTION $name PASS"
    else
        echo "ASSERTION $name FAIL (want '$want' got '$got')"
        fail=1
    fi
}

cleanup() {
    [ -n "${PEER_PID:-}" ] && kill "$PEER_PID" 2>/dev/null
    wait "${PEER_PID:-}" 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$ROOT/tmp"

# --- a loopback peer that answers every request with success -----------------
cat > "$ROOT/tmp/diaprobe-selftest-peer.py" <<'PYEOF'
import socket, struct, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import diaprobe as D

port = int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
print("ready", flush=True)
while True:
    c, _ = s.accept()
    try:
        hdr = D._recv_exact(c, 20, "sctp")
        if hdr is None:
            continue
        ln = (hdr[1] << 16) | (hdr[2] << 8) | hdr[3]
        body = D._recv_exact(c, ln - 20, "sctp")
        req = D.decode(hdr + body)
        avps = [
            D._mk_avp(264, b"peer.selftest"),
            D._mk_avp(296, b"selftest.realm"),
            D._mk_avp(268, struct.pack("!I", 2001)),
            D._mk_avp(269, b"selftest"),
            D._mk_avp(258, struct.pack("!I", 16777251)),
        ]
        c.sendall(D._build(257, 0x80, 0, "peer.selftest", avps).to_bytes())
    except Exception:
        pass
    finally:
        c.close()
PYEOF

"$PY" "$ROOT/tmp/diaprobe-selftest-peer.py" "$ROOT/tools/diameter-probe" "$PYCRATE_SITE" "$PORT" \
    >"$ROOT/tmp/diaprobe-selftest-peer.log" 2>&1 &
PEER_PID=$!

for _ in $(seq 1 30); do
    grep -q ready "$ROOT/tmp/diaprobe-selftest-peer.log" 2>/dev/null && break
    sleep 0.2
done

if ! grep -q ready "$ROOT/tmp/diaprobe-selftest-peer.log" 2>/dev/null; then
    echo "ASSERTION peer_started FAIL"
    cat "$ROOT/tmp/diaprobe-selftest-peer.log"
    echo "RESULT FAIL"
    exit 1
fi
echo "ASSERTION peer_started PASS"

# --- offline: every message type builds and round-trips ----------------------
build=$("$PY" - "$PROBE" "$PYCRATE_SITE" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[2])
import importlib.util
spec = importlib.util.spec_from_file_location("diaprobe", sys.argv[1])
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

msgs = {
    "cer": D.build_cer("probe.selftest", "selftest.realm", "127.0.0.1"),
    "dwr": D.build_dwr("probe.selftest", "selftest.realm"),
    "ulr": D.build_ulr("probe.selftest", "selftest.realm", "hss.selftest", "470010000000001"),
    "air": D.build_air("probe.selftest", "selftest.realm", "hss.selftest", "470010000000001", "470", "01"),
    "slr": D.build_slr("probe.selftest", "selftest.realm", "hss.selftest", "470010000000001"),
}
bad = []
for name, m in msgs.items():
    b = m.to_bytes()
    o = D.decode(b)
    if o["cmd"] != int(m[0]["Cmd"].get_val()) or not o["avps"]:
        bad.append(name)
print("OK" if not bad else "BAD:" + ",".join(bad))
PYEOF
)
assert "messages_build_and_decode" "OK" "$build"

# --- over the wire: each verb gets a decoded answer ---------------------------
for verb in cer dwr; do
    out=$("$PY" "$PROBE" "$verb" --host 127.0.0.1 --port "$PORT" --transport sctp --timeout 5 2>/dev/null | tail -1)
    # column 10 is Origin-Realm: the CEA's realm is what a peer advertises
    cols=$(printf '%s' "$out" | awk -F'\t' '{print $7"|"$10}')
    assert "${verb}_over_sctp" "2001|selftest.realm" "$cols"
done

for verb in ulr air slr; do
    extra=""
    [ "$verb" = "air" ] && extra="--mcc 470 --mnc 01"
    out=$("$PY" "$PROBE" "$verb" --host 127.0.0.1 --port "$PORT" --transport sctp \
        --timeout 5 --imsi 470010000000001 --dest-realm hss.selftest $extra 2>/dev/null | tail -1)
    cols=$(printf '%s' "$out" | awk -F'\t' '{print $7"|"$11}')
    assert "${verb}_over_sctp" "2001|MEASURED" "$cols"
done

# --- an unreachable peer is UNOBSERVED, never "clean" ------------------------
out=$("$PY" "$PROBE" cer --host 127.0.0.1 --port 39972 --transport sctp --timeout 2 2>/dev/null | tail -1)
cols=$(printf '%s' "$out" | awk -F'\t' '{print $11}')
assert "unreachable_is_unobserved" "UNOBSERVED" "$cols"

# --- the store got a header and at least one row ----------------------------
store="${LOOT_DIR:-$ROOT/loot}/diameter-probe/probes.tsv"
if [ -f "$store" ]; then
    hdr=$(head -1 "$store" | cut -f1)
    rows=$(wc -l < "$store")
    assert "store_header" "utc" "$hdr"
    [ "$rows" -ge 2 ] && echo "ASSERTION store_has_rows PASS" || { echo "ASSERTION store_has_rows FAIL"; fail=1; }
else
    echo "ASSERTION store_created FAIL"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "RESULT PASS"
    exit 0
else
    echo "RESULT FAIL"
    exit 1
fi
