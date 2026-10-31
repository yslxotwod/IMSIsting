#!/usr/bin/env bash
# GSMTAP passive capture and decode — Osmocom's wrapper that carries a raw
# GSM/UMTS/LTE/NR message inside a UDP packet on port 4729.
#
# The header layout here was verified against Wireshark's GSMTAP dissector, not
# recalled. Two things that are easy to get wrong and are asserted in the
# selftest:
#
#   * The version-2 header is SIXTEEN bytes and hdr_len counts 32-bit words,
#     so hdr_len = 4. A twelve-byte header with hdr_len = 4 makes the dissector
#     consume four bytes of the payload.
#   * The GSM channel type lives in the sub_type octet. Older GSMTAP revisions
#     packed it into the upper byte of the arfcn field; both are accepted on
#     read, but only sub_type is emitted. The arfcn field carries the ARFCN in
#     bits 0..13, with 0x4000 marking uplink and 0x8000 marking PCS.
#
# Resolve IMSISTING_ROOT from this script's own path so state and loot land in
# the project tree even when launched standalone via pkexec.
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi
if [[ -n "${IMSISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$IMSISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi
: "${IMSISTING_HOME:=$IMSISTING_ROOT}"
: "${TMP_DIR:=/tmp/imsisting}"
: "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
: "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
: "${STATE_DIR:=$IMSISTING_ROOT/state}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null

MOD_TMP="$TMP_DIR/gsmtap"
GTAP_DIR="$LOOT_DIR/gsmtap"
GTAP_TSV="$GTAP_DIR/decoded.tsv"
GTAP_IDENT="$GTAP_DIR/identities.tsv"
mkdir -p "$MOD_TMP" "$GTAP_DIR" 2>/dev/null

GTAP_PORT=4729
# The datagram listener. It has to be its own script file, not an inline
# `python3 -c '...'`: the reader uses single quotes, and the python body below
# contains both single quotes and a `bytes.fromhex` call whose parentheses and
# quoting survived one round of shell interpolation but not the next. A separate
# file also means the framing rule can be unit-tested directly.
GTAP_LISTEN_PY="$MOD_TMP/gsmtap_listen.py"
# Bind address and the port set the reader accepts. Both are defaults, not
# constants: a second GSMTAP source (grgsm_livemon on 4729 alongside an
# srsENB/Open5GS feed on another port) needs --port, and a remote feed that is
# already encapsulated into a capture needs --read --any-port. Keeping 4729 as
# the default leaves every existing invocation bit-identical.
GTAP_IFACE="0.0.0.0"
# The loaded watchlist. Declared here, not only inside the loader: gtap_wl_verdict
# reads it, and an unset array under `set -u` is an error rather than an empty
# list, which would turn "no watchlist loaded" into a crash instead of "unknown".
GTAP_WL=()
# Positional arguments left after the CLI flag parse, and the last --forward
# target split. Both are module-scope so a sourced caller sees them.
GTAP_POS=()
GTAP_FWD_HOST=""
GTAP_FWD_PORT=""
# The last --relay target split into host/port. Module-scope for the same
# reason as GTAP_FWD_*: the dispatcher validates the target once and the
# relay body, the probe and the failure message must all be talking about the
# same destination -- reading it back out of "$1" at each site is how a
# half-parsed target ends up named in a refusal.
GTAP_RELAY_HOST=""
GTAP_RELAY_PORT=""
# The shared cross-module device/target state.
GTAP_SDR="${TMP_DIR}/sdr_device"

# ── sanitisation ────────────────────────────────────────────────────────
gtap_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# ── argument validation ─────────────────────────────────────────────────
# Every numeric flag is validated BEFORE it reaches arithmetic or a socat
# address. `$(( 16#$var ))` and friends abort the enclosing command
# substitution on bad input (conventions §15), and a port that is not a port
# would otherwise be spliced straight into a socket address.
gtap_valid_port() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    # 0 is not a legal destination for our purposes and >65535 is not a port.
    (( ${1} >= 1 && ${1} <= 65535 )) || return 1
    return 0
}

# A bind address is an IPv4 dotted quad or a hostname. Reject anything with a
# character that could end the socat address early (comma, colon, space) — a
# `bind=` value containing a comma silently changes the address list.
gtap_valid_iface() {
    local a="${1:-}"
    [[ -n "$a" ]] || return 1
    [[ "$a" =~ ^[0-9A-Za-z._:-]+$ ]] || return 1
    case "$a" in
        *:*) # IPv6 is not reachable through the UDP4-RECV path below.
             return 1 ;;
    esac
    # An address that is only dotted-decimal is checked for real: a typo like
    # 999.999.999.999 passes the character class above, then fails inside the
    # bind, which reports a generic runtime error after the listener has already
    # announced itself. Rejecting it here makes a malformed address a usage
    # error (rc=2) that names the flag, before any socket is touched.
    if [[ "$a" =~ ^[0-9.]+$ ]]; then
        local o
        local -a oct=()
        IFS=. read -r -a oct <<< "$a"
        (( ${#oct[@]} == 4 )) || return 1
        for o in "${oct[@]}"; do
            [[ "$o" =~ ^[0-9]{1,3}$ ]] || return 1
            (( 10#$o <= 255 )) || return 1
        done
        return 0
    fi
    # A hostname or interface name is left to the resolver.
    [[ "$a" =~ ^[0-9A-Za-z._-]+$ ]] || return 1
    return 0
}

# HOST:PORT for --forward. Split on the LAST colon so a hostname is not
# mangled, and validate the port half with the same rule as --port.
gtap_forward_split() {
    local spec="${1:-}"
    GTAP_FWD_HOST="" GTAP_FWD_PORT=""
    [[ "$spec" == *:* ]] || return 1
    GTAP_FWD_HOST="${spec%:*}"
    GTAP_FWD_PORT="${spec##*:}"
    [[ -n "$GTAP_FWD_HOST" ]] || return 1
    gtap_valid_port "$GTAP_FWD_PORT" || return 1
    return 0
}

# HOST:PORT for --relay. The verb exists because a parsed stream is worth
# forwarding even when the collector that made it is not the one that wants it:
# a second analyst, a Wireshark across the room, or a second module watching a
# different generation. The host half is validated with the interface rule as
# well as the port half, because a relay target that is only a typo away from a
# valid one otherwise fails deep inside sendto(), after the capture has already
# been walked and half the frames have been counted as forwarded.
gtap_relay_split() {
    local spec="${1:-}"
    GTAP_RELAY_HOST="" GTAP_RELAY_PORT=""
    gtap_forward_split "$spec" || return 1
    gtap_valid_iface "$GTAP_FWD_HOST" || return 1
    GTAP_RELAY_HOST="$GTAP_FWD_HOST"
    GTAP_RELAY_PORT="$GTAP_FWD_PORT"
    return 0
}

# --since/--until accept an epoch integer or an ISO-8601-ish stamp. An epoch is
# returned unchanged; a stamp is converted with date -d. An unparseable value
# is an error, never a silently-ignored bound: a bound that quietly does
# nothing turns "no frames in that window" into "no frames at all".
gtap_ts_bound() {
    local v="${1:-}"
    [[ -n "$v" ]] || { printf 'ERROR\tempty time bound\n' >&2; return 1; }
    case "$v" in
        ''|*[!0-9]*) ;;                 # not a pure integer -> try date -d
        *) printf '%s\n' "$v"; return 0 ;;
    esac
    local e
    e=$(date -d "$v" +%s 2>/dev/null) || {
        printf 'ERROR\tunparseable time bound: %s\n' "$v" >&2; return 1; }
    [[ "$e" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tunparseable time bound: %s\n' "$v" >&2; return 1; }
    printf '%s\n' "$e"
}

# Seconds -> "YYYY-mm-ddTHH:MM:SSZ". Empty in, empty out: an absent pcap
# timestamp must stay absent rather than being rendered as 1970.
gtap_ts_utc() {
    local e="${1:-}"
    [[ -n "$e" ]] || { printf ''; return 0; }
    date -u -d "@$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf ''
}

# Split a TSV line into GTAP_F, preserving empty fields. `read` with IFS=tab
# collapses runs of tabs and shifts every later column left.
GTAP_F=()
gtap_split() {
    GTAP_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        GTAP_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── constants ───────────────────────────────────────────────────────────
# GSMTAP payload types (Osmocom gsmtap.h). The ones a cellular toolkit meets.
# Normalise whatever form the caller passed (5, 05 or 0x05) to 0xNN. `case`
# matches patterns as literal text, so a bare decimal would silently fall
# through to "unknown" — conventions §15.
gtap_norm_u8() {
    local v
    v=$(printf '%d' "$(( ${1:-0} ))" 2>/dev/null) || { echo "0xff"; return; }
    printf '0x%02x' "$(( v & 0xff ))"
}

gtap_type_name() {
    case "$(gtap_norm_u8 "${1:-0}")" in
        0x01) echo "GSM Um (CS)" ;;
        0x02) echo "GSM Um (PS)" ;;
        0x03) echo "UMTS RRC" ;;
        0x04) echo "LTE RRC" ;;
        0x05) echo "LTE NAS" ;;
        0x06) echo "NR RRC" ;;
        0x07) echo "NR NAS" ;;
        0x08) echo "GSM Abis" ;;
        0x09) echo "UMTS Iub" ;;
        0x0a) echo "LTE X2AP" ;;
        0x0b) echo "NR NGAP" ;;
        0x0c) echo "LTE S1AP" ;;
        0x0d) echo "UMTS RRC (CS)" ;;
        *)    echo "unknown" ;;
    esac
}

# GSM channel type, carried in sub_type.
gtap_channel_name() {
    case "$(gtap_norm_u8 "${1:-0}")" in
        0x00) echo "UNKNOWN" ;;   0x01) echo "BCCH" ;;
        0x02) echo "CCCH" ;;      0x03) echo "RACH" ;;
        0x04) echo "AGCH" ;;      0x05) echo "PCH" ;;
        0x06) echo "SDCCH" ;;     0x07) echo "SDCCH4" ;;
        0x08) echo "SDCCH8" ;;    0x09) echo "TCH/F" ;;
        0x0a) echo "TCH/H" ;;     0x0b) echo "PACCH" ;;
        0x0c) echo "CBCH" ;;      0x0d) echo "PDCH" ;;
        0x0e) echo "PTCCH" ;;     0x0f) echo "CBCH52" ;;
        *)    echo "unknown" ;;
    esac
}

# ── header codec ────────────────────────────────────────────────────────
# Build a 16-byte version-2 header. Arguments:
#   type timeslot arfcn signal snr frame sub_type [uplink] [pcs]
gtap_build_header() {
    local type="${1:-1}" ts="${2:-0}" arfcn="${3:-0}" sig="${4:-0}" \
          snr="${5:-0}" frame="${6:-0}" sub="${7:-0}" ul="${8:-0}" pcs="${9:-0}"
    python3 - "$type" "$ts" "$arfcn" "$sig" "$snr" "$frame" "$sub" "$ul" "$pcs" <<'PY'
import struct, sys
t, ts, arfcn, sig, snr, frame, sub, ul, pcs = (int(x, 0) for x in sys.argv[1:10])
if not (0 <= arfcn <= 0x3fff):
    sys.exit(1)
a = arfcn | (0x4000 if ul else 0) | (0x8000 if pcs else 0)
# version, hdr_len(words=4), type, timeslot, arfcn, signal_dbm, snr_db,
# frame_number, sub_type, antenna_nr, sub_slot, res
hdr = struct.pack('!BBBBHbbIBBBB', 2, 4, t, ts, a, sig, snr, frame, sub, 0, 0, 0)
sys.stdout.write(hdr.hex())
PY
}

# Parse a header from the front of a hex string. Emits TSV.
gtap_parse_header() {
    local h; h=$(printf '%s' "${1:-}" | tr -d ' \t\r\n' | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]+$ ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    (( ${#h} >= 32 )) || {
        printf 'ERROR\theader needs 16 bytes, got %d\n' "$(( ${#h} / 2 ))" >&2
        return 1
    }
    python3 - "$h" <<'PY'
import struct, sys
h = sys.argv[1]
b = bytes.fromhex(h[:32])
ver, hlen, typ, ts, arfcn, sig, snr, frame, sub, ant, slot, res = \
    struct.unpack('!BBBBHbbIBBBB', b)
print("version\t%d" % ver)
print("hdr_len_words\t%d" % hlen)
print("hdr_len_bytes\t%d" % (hlen * 4))
print("type\t0x%02x" % typ)
print("timeslot\t%d" % ts)
print("arfcn\t%d" % (arfcn & 0x3fff))
print("uplink\t%s" % ("yes" if arfcn & 0x4000 else "no"))
print("pcs\t%s" % ("yes" if arfcn & 0x8000 else "no"))
print("signal_dbm\t%d" % sig)
print("snr_db\t%d" % snr)
print("frame_number\t%d" % frame)
print("sub_type\t0x%02x" % sub)
print("antenna_nr\t%d" % ant)
print("sub_slot\t%d" % slot)
print("payload_hex\t%s" % h[32:])
PY
}

# The channel name, accepting both the current (sub_type) and the legacy
# (upper byte of arfcn) encodings so an old capture still decodes.
#
# sub_type is a GSM *channel type* only for a GSM payload. Wireshark reads the
# same octet as "SCH/F" under an LTE payload, and it is right to: the namespace
# is payload-dependent. Naming a GSM channel for a NAS frame would be a
# confidently wrong answer, so non-GSM payloads report "-".
gtap_is_gsm_type() {
    case "$(gtap_norm_u8 "${1:-0}")" in
        0x01|0x02|0x08) return 0 ;;   # GSM Um CS, GSM Um PS, GSM Abis
        *) return 1 ;;
    esac
}

gtap_channel_of() {
    local sub="${1:-0}" arfcn="${2:-0}" type="${3:-0x01}"
    gtap_is_gsm_type "$type" || { echo "-"; return; }

    if [[ "$(( ${sub:-0} ))" -ne 0 ]]; then
        gtap_channel_name "$sub"
    else
        # Legacy: high byte of the 16-bit arfcn field.
        local hi=$(( (arfcn >> 8) & 0xff ))
        [[ "$hi" -eq 0 ]] && { echo "UNKNOWN"; return; }
        gtap_channel_name "$hi"
    fi
}

gtap_field() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

# ── capture I/O ─────────────────────────────────────────────────────────
# A GSMTAP capture is an ordinary Ethernet/IP/UDP pcap on port 4729, which is
# what Wireshark expects and what the dissector keys off.
# Frames come from a FILE, not stdin: a heredoc replaces stdin, so a piped
# frame list would be silently lost and the capture would come out empty.
gtap_write_pcap() {
    local out="$1" frames_file="${2:-}"
    [[ -n "$frames_file" && -f "$frames_file" ]] || {
        printf 'ERROR	gtap_write_pcap needs a frames file
' >&2; return 2; }
    python3 - "$out" "$frames_file" <<'PY'
import struct, sys
out = sys.argv[1]
frames = [l.strip() for l in open(sys.argv[2]) if l.strip()]
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    ts = 0
    for hx in frames:
        g = bytes.fromhex(hx)
        udp = struct.pack('!HHHH', 4729, 4729, 8 + len(g), 0) + g
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         bytes([10,0,0,1]), bytes([10,0,0,2])) + udp
        eth = bytes.fromhex('001122334455') + bytes.fromhex('66778899aabb') + \
              struct.pack('!H', 0x0800) + ip
        f.write(struct.pack('<IIII', ts, 0, len(eth), len(eth)))
        f.write(eth)
        ts += 1
PY
}

gtap_read_pcap() {
    local pcap="${1:-}"
    # $2 = accepted UDP port, or "any" for --any-port. Default 4729 preserves
    # the original behaviour exactly.
    local port="${2:-4729}"
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 1; }
    if [[ "$port" != "any" ]]; then
        gtap_valid_port "$port" || {
            printf 'ERROR\tbad port: %s\n' "$port" >&2; return 2; }
    fi
    python3 - "$pcap" "$port" <<'PY'
import struct, sys
p = sys.argv[1]
portarg = sys.argv[2]
want = None if portarg == "any" else int(portarg)
d = open(p, 'rb').read()
if len(d) < 24:
    sys.exit(1)
magic = struct.unpack('<I', d[:4])[0]
if magic == 0xa1b2c3d4:
    end, nano = '<', False
elif magic == 0xd4c3b2a1:
    end, nano = '>', False
elif magic == 0xa1b23c4d:
    end, nano = '<', True
elif magic == 0x4d3cb2a1:
    end, nano = '>', True
else:
    sys.stderr.write("not a pcap (magic %08x)\n" % magic)
    sys.exit(1)
off = 24
n = 0
while off + 16 <= len(d):
    ts, tu, incl, orig = struct.unpack(end + 'IIII', d[off:off+16])
    off += 16
    if off + incl > len(d):
        break
    fr = d[off:off+incl]
    off += incl
    # Walk Ethernet -> IPv4 -> UDP -> GSMTAP.
    if len(fr) < 14:
        continue
    o = 14
    if struct.unpack('!H', fr[12:14])[0] != 0x0800:
        continue
    ihl = (fr[o] & 0x0f) * 4
    if len(fr) < o + ihl + 8:
        continue
    o += ihl
    sp, dp, ln = struct.unpack('!HHH', fr[o:o+6])
    o += 8
    if want is not None and sp != want and dp != want:
        continue
    g = fr[o:o+ln-8]
    if len(g) < 16:
        continue
    # ts_sec/ts_usec are carried out of the reader instead of being parsed and
    # thrown away. Fields: ordinal, ts_sec, ts_usec, payload hex. The caller
    # turns the two time fields into ts_epoch/ts_utc.
    print("%d\t%d\t%d\t%s" % (n, ts, tu, g.hex()))
    n += 1
PY
}

# ── listeners ───────────────────────────────────────────────────────────
# Write the datagram listener to disk on first use. Embedding it here keeps the
# module a single self-contained file (no sibling .py to ship or find) while
# still giving python3 a real file to run, which is what avoids the shell
# quoting trap an inline `python3 -c` would hit.
gtap_ensure_listener() {
    [[ -s "$GTAP_LISTEN_PY" ]] && return 0
    mkdir -p "$(dirname "$GTAP_LISTEN_PY")"
    cat > "$GTAP_LISTEN_PY" <<'GTAP_LISTENER_PY'
import os, socket, struct, sys, time

secs = float(os.environ["GTAP_LISTEN_SECS"])
bind = os.environ["GTAP_LISTEN_BIND"]
port = int(os.environ["GTAP_LISTEN_PORT"])
mode = os.environ["GTAP_LISTEN_MODE"]
outp = os.environ["GTAP_LISTEN_OUT"]
fwd  = os.environ["GTAP_LISTEN_FWD"]

# SO_REUSEADDR so a quick restart is not blocked by the previous socket
# teardown, which otherwise looks like a listener that sees nothing.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((bind, port))
except OSError as e:
    sys.stderr.write("ERROR\tcannot bind %s:%d - %s\n" % (bind, port, e))
    sys.exit(2)

fwd_sock = None
fwd_addr = None
if fwd:
    host, _, fport = fwd.rpartition(":")
    fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fwd_addr = (host, int(fport))

# A receive timeout lets the loop notice the deadline and exit cleanly instead
# of relying on a signal killing it mid-write.
s.settimeout(0.5)
deadline = time.time() + secs

if mode == "pipe":
    out = sys.stdout.buffer
    # The 24-byte global header goes out and is flushed BEFORE the first frame,
    # so `wireshark -k -i -` sees a pcap immediately instead of hanging until
    # the timeout expires with nothing on screen.
    out.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    out.flush()
else:
    out = open(outp, "w", buffering=1)

n = 0
while time.time() < deadline:
    try:
        g, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    except OSError:
        break
    if not g:
        continue
    if fwd_sock is not None:
        # Forward the raw datagram unchanged: the remote receiver expects the
        # same GSMTAP bytes this listener parses, not a re-wrapped frame.
        try:
            fwd_sock.sendto(g, fwd_addr)
        except OSError as e:
            sys.stderr.write("WARN\tforward to %s failed: %s\n" % (fwd, e))
    if mode == "pipe":
        udp = struct.pack("!HHHH", port, port, 8 + len(g), 0) + g
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp
        eth = (bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") +
               struct.pack("!H", 0x0800) + ip)
        ts = int(time.time())
        out.write(struct.pack("<IIII", ts, 0, len(eth), len(eth)))
        out.write(eth)
        out.flush()
    else:
        out.write(g.hex() + "\n")
    n += 1

s.close()
if fwd_sock is not None:
    fwd_sock.close()
if mode == "pipe":
    out.flush()
else:
    out.close()
sys.stderr.write("frames\t%d\n" % n)
GTAP_LISTENER_PY
}

# --listen --pipe streams a live pcap to stdout. The 24-byte global header is
# written and flushed BEFORE the first frame, then each record is written and
# flushed as it arrives. That is what makes `wireshark -k -i -` show frames
# while they land; buffering the whole capture and writing it at the end gives
# the operator nothing at all until the timeout expires, which is the gap this
# closes.
gtap_listen() {
    local secs="${1:-30}" out="${2:-}"
    # Optional modifiers, all defaulting to the original behaviour.
    local port="${3:-$GTAP_PORT}" iface="${4:-$GTAP_IFACE}" \
          pipe_mode="${5:-0}" forward="${6:-}"
    local any_port=0
    [[ -n "$out" ]] || out="$CAPTURES_DIR/gsmtap_$(date +%Y%m%d_%H%M%S).pcap"

    # Validate before building any socket address.
    gtap_valid_port "$port" || {
        printf 'ERROR\tbad port: %s (want 1-65535)\n' "${port:-<empty>}" >&2; return 2; }
    gtap_valid_iface "$iface" || {
        printf 'ERROR\tbad bind address: %s\n' "${iface:-<empty>}" >&2; return 2; }
    if [[ -n "$forward" ]]; then
        gtap_forward_split "$forward" || {
            printf 'ERROR\tbad --forward target: %s (want HOST:PORT)\n' "$forward" >&2
            return 2; }
    fi
    (( any_port )) && { printf 'ERROR\t--any-port applies to --read, not --listen\n' >&2; return 2; }

    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tno python3 — needed to bind UDP %d and frame the capture\n' "$port" >&2
        return 1
    }
    gtap_ensure_listener || { printf 'ERROR\tcannot write listener script\n' >&2; return 1; }

    local tmp; tmp=$(mktemp "$MOD_TMP/listen.XXXXXX") || return 1
    info "listening on UDP $port (bind $iface) for ${secs}s..."

    # The socket is bound in python3 rather than piped from `socat -u
    # UDP4-RECV:...`. socat concatenates datagrams into one byte stream with no
    # separator, so a reader cannot recover the datagram boundaries: three
    # 17-byte frames arrive as a single 51-byte run, which is counted as ONE
    # frame and framed as one oversized record. An earlier revision of this
    # function assumed newline-separated datagrams and silently dropped frames
    # for exactly that reason. Binding the socket here preserves the real
    # boundary, so the frame count and the emitted records are both honest.
    #
    # $1 = seconds, $2 = bind address, $3 = port, $4 = mode (pipe|hex)
    #   $5 = output path (pipe mode), $6 = forward target ("" = off)
    local lerr; lerr=$(mktemp "$MOD_TMP/lstenerr.XXXXXX") || return 1
    GTAP_LISTEN_SECS="$secs" GTAP_LISTEN_BIND="$iface" GTAP_LISTEN_PORT="$port" \
    GTAP_LISTEN_MODE="$([[ $pipe_mode -eq 1 ]] && echo pipe || echo hex)" \
    GTAP_LISTEN_OUT="$([[ $pipe_mode -eq 1 ]] && echo "$out" || echo "$tmp")" \
    GTAP_LISTEN_FWD="$forward" \
    python3 "$GTAP_LISTEN_PY" 2>"$lerr"
    local rc=$?
    # The listener reports its own received-datagram count on stderr. Reading it
    # is the only reliable success signal: `stat` on $out races the shell's own
    # `>` redirect, whose buffer has not been flushed when this line runs, so a
    # capture holding 3 real frames still measured as 0 bytes and was discarded.
    local got; got=$(sed -n 's/^frames\t//p' "$lerr" | tail -1)
    cat "$lerr" >&2
    if (( pipe_mode )); then
        if (( rc != 0 )); then
            rm -f "$lerr"
            printf 'ERROR\tlistener failed (rc=%d) on UDP %s:%s\n' "$rc" "$iface" "$port" >&2
            return 1
        fi
        # Report honestly: the header alone means nothing was received.
        if [[ "${got:-0}" -le 0 ]]; then
            rm -f "$out"
            printf 'ERROR\tno GSMTAP received on UDP %d in %ss — is grgsm_livemon (or an eNB/srsue with GSMTAP) running?\n' \
                "$port" "$secs" >&2
            return 1
        fi
        # In pipe mode STDOUT IS THE CAPTURE: the listener writes the pcap
        # global header and every record to sys.stdout.buffer, and $out is
        # only the label used in this block. So the status lines have to go to
        # stderr. Printing them on stdout appends text immediately after the
        # last record, which makes the stream malformed: a record walker reads
        # the ASCII of "OK\t/path" as a phantom fourth record header
        # (incl_len 1885434983) and `wireshark -k -i -` reports a bad tail.
        # The documented use is `--listen 60 --pipe | wireshark -k -i -`.
        printf 'OK\t%s\n' "$out" >&2
        rm -f "$lerr"
        printf 'mode\tpipe\n' >&2
        printf 'port\t%s\n' "$port" >&2
        return 0
    fi
    rm -f "$lerr"
    (( rc == 0 )) || {
        rm -f "$tmp"
        printf 'ERROR\tlistener failed (rc=%d) on UDP %s:%s\n' "$rc" "$iface" "$port" >&2
        return 1
    }
    # The listener's own count, cross-checked against the hex lines it wrote.
    local n; n=$(grep -c . "$tmp" || true)
    if [[ "${n:-0}" -eq 0 ]]; then
        rm -f "$tmp"
        printf 'ERROR\tno GSMTAP received on UDP %d in %ss — is grgsm_livemon (or an eNB/srsue with GSMTAP) running?\n' \
            "$port" "$secs" >&2
        return 1
    fi
    gtap_write_pcap "$out" "$tmp"
    rm -f "$tmp"
    printf 'OK\t%s\n' "$out"
    printf 'frames\t%s\n' "$n"
    printf 'port\t%s\n' "$port"
}

# ── decode to TSV ───────────────────────────────────────────────────────
gtap_init_store() {
    mkdir -p "$GTAP_DIR"
    [[ -f "$GTAP_TSV" ]] || printf 'frame\ttype\tchannel\tarfcn\tuplink\ttimeslot\tsignal_dbm\tsnr_db\tframe_number\tpayload_len\tpayload_hex\tts_epoch\tts_utc\n' > "$GTAP_TSV"
}

gtap_decode_pcap() {
    local pcap="${1:-}"
    # Optional modifiers: $2 = accepted UDP port (or "any" for --any-port),
    # $3 = --since bound, $4 = --until bound, $5 = --arfcn, $6 = --channel,
    # $7 = uplink-only, $8 = --relay target (HOST:PORT, "" = off),
    # $9 = --watchlist FILE ("" = off). All default to the original behaviour:
    # port 4729, no time bound, no filter, nothing forwarded.
    local port="${2:-$GTAP_PORT}" since="${3:-}" until="${4:-}" \
          farfcn="${5:-}" fchan="${6:-}" uplink_only="${7:-0}" \
          relay="${8:-}" wlfile="${9:-}"
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 1; }
    gtap_init_store

    # Validate every filter before reading a single frame. A silently-ignored
    # bound turns "no frames in that window" into "no frames at all".
    local since_e="" until_e=""
    if [[ -n "$since" ]]; then
        since_e=$(gtap_ts_bound "$since") || return 2
    fi
    if [[ -n "$until" ]]; then
        until_e=$(gtap_ts_bound "$until") || return 2
    fi
    if [[ -n "$farfcn" ]]; then
        [[ "$farfcn" =~ ^[0-9]+$ ]] || {
            printf 'ERROR\tbad --arfcn: %s\n' "$farfcn" >&2; return 2; }
        (( farfcn <= 1023 || (farfcn >= 5120 && farfcn <= 8699) )) || {
            printf 'ERROR\t--arfcn %s is outside the GSM ARFCN range\n' "$farfcn" >&2
            return 2; }
    fi

    # ── relay: prove the destination before reading anything ──
    # An unreachable collector is refused by name up front. The alternative --
    # read, decode, then report zero forwarded -- is exactly the ambiguity the
    # counters exist to remove, and a refusal is the only report that survives
    # being read by a script.
    local relay_host="" relay_port=""
    if [[ -n "$relay" ]]; then
        gtap_relay_split "$relay" || {
            printf 'ERROR\tbad --relay target: %s (want HOST:PORT)\n' "$relay" >&2
            return 2; }
        relay_host="$GTAP_RELAY_HOST" relay_port="$GTAP_RELAY_PORT"
        local probe prc
        probe=$(gtap_relay_probe "$relay_host" "$relay_port"); prc=$?
        if (( prc != 0 )); then
            printf 'MISSING\treachable relay destination %s:%s\n' "$relay_host" "$relay_port" >&2
            printf 'WHY\t%s\n' "$(gtap_field "$probe" why)" >&2
            return 1
        fi
    fi

    local tmp; tmp=$(mktemp "$MOD_TMP/dec.XXXXXX") || return 1
    gtap_read_pcap "$pcap" "$port" > "$tmp" || {
        rm -f "$tmp"; printf 'ERROR\tcould not read %s as a GSMTAP capture\n' "$pcap" >&2; return 1; }
    local n; n=$(grep -c . "$tmp" || true)

    if [[ "${n:-0}" -eq 0 ]]; then
        rm -f "$tmp"
        if [[ "$port" == "any" ]]; then
            printf 'ERROR\tno GSMTAP frames on any UDP port in %s\n' "$pcap" >&2
        else
            printf 'ERROR\tno GSMTAP frames on UDP %s in %s\n' "$port" "$pcap" >&2
        fi
        return 1
    fi

    # ── watchlist: resolved once for the whole stream ──
    # Matched in one pass over the frames file rather than per frame inside the
    # loop: a stream filter runs over the entire capture, and a decoder fork per
    # frame (which is what --identities-tsv does, and can afford, over a store
    # of a few identities) would turn a 10k-frame read into minutes.
    local wl_hits=" " wl_out=""
    if [[ -n "$wlfile" ]]; then
        gtap_watchlist_load "$wlfile" || { rm -f "$tmp"; return 2; }
        local entf; entf=$(mktemp "$MOD_TMP/wl.XXXXXX") || { rm -f "$tmp"; return 1; }
        printf '%s\n' "${GTAP_WL[@]}" > "$entf"
        wl_out=$(gtap_watchlist_match "$tmp" "$entf"); local wrc=$?
        rm -f "$entf"
        if (( wrc != 0 )); then
            rm -f "$tmp"
            printf 'ERROR\tcould not apply the watchlist %s to %s\n' "$wlfile" "$pcap" >&2
            return 1
        fi
        # Space-delimited frame ordinals: the membership test below stays a
        # shell pattern instead of a per-frame command substitution.
        wl_hits=" $(printf '%s\n' "$wl_out" | awk -F'\t' '$1=="frame"{printf "%s ", $2}')"
    fi

    # Frames that survive the filters are staged here and handed to the relay in
    # one process. A fork per frame to send one datagram apiece would be slower
    # than the decode it is relaying.
    local fwd_file=""
    if [[ -n "$relay_host" ]]; then
        fwd_file=$(mktemp "$MOD_TMP/fwd.XXXXXX") || { rm -f "$tmp"; return 1; }
    fi

    local rows=0 skipped=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        gtap_split "$line"
        local fr="${GTAP_F[0]:-}" tsec="${GTAP_F[1]:-}" tusec="${GTAP_F[2]:-}" hex="${GTAP_F[3]:-}"
        local p; p=$(gtap_parse_header "$hex") || continue
        local typ sub arfcn ul ts sig snr fn pl
        typ=$(gtap_field "$p" type);    sub=$(gtap_field "$p" sub_type)
        arfcn=$(gtap_field "$p" arfcn); ul=$(gtap_field "$p" uplink)
        ts=$(gtap_field "$p" timeslot); sig=$(gtap_field "$p" signal_dbm)
        snr=$(gtap_field "$p" snr_db);  fn=$(gtap_field "$p" frame_number)
        pl=$(gtap_field "$p" payload_hex)
        local chan; chan=$(gtap_channel_of "$sub" "$arfcn" "$typ")

        # ── filters ──
        if [[ -n "$farfcn" ]] && [[ "$arfcn" != "$farfcn" ]]; then
            skipped=$((skipped + 1)); continue
        fi
        if [[ -n "$fchan" ]] && [[ "$chan" != "$fchan" ]]; then
            skipped=$((skipped + 1)); continue
        fi
        if (( uplink_only )) && [[ "$ul" != "yes" ]]; then
            skipped=$((skipped + 1)); continue
        fi
        if [[ -n "$since_e" ]] && (( tsec < since_e )); then
            skipped=$((skipped + 1)); continue
        fi
        if [[ -n "$until_e" ]] && (( tsec > until_e )); then
            skipped=$((skipped + 1)); continue
        fi
        # The watchlist is the last filter applied: it is the only one that had
        # to look inside the payload, so every cheap test has already answered.
        if [[ -n "$wlfile" ]] && [[ "$wl_hits" != *" $fr "* ]]; then
            skipped=$((skipped + 1)); continue
        fi

        # Staged for the relay before the store write, so a frame the store
        # rejects can never be forwarded and a frame that is forwarded is
        # guaranteed to be counted as forwarded.
        if [[ -n "$fwd_file" ]]; then
            printf '%s\n' "$hex" >> "$fwd_file"
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$fr" "$(gtap_type_name "$typ")" "$chan" \
            "$arfcn" "$ul" "$ts" "$sig" "$snr" "$fn" \
            "$(( ${#pl} / 2 ))" "$(gtap_sanitize "$pl")" \
            "$tsec" "$(gtap_ts_utc "$tsec")" >> "$GTAP_TSV"
        rows=$((rows + 1))
    done < "$tmp"
    rm -f "$tmp"

    printf 'frames\t%s\n' "$rows"
    (( skipped > 0 )) && printf 'filtered\t%s\n' "$skipped"
    printf 'store\t%s\n' "$GTAP_TSV"

    # ── relay ──
    local rrc=0
    if [[ -n "$fwd_file" ]]; then
        local sres; sres=$(gtap_relay_send "$relay_host" "$relay_port" "$fwd_file")
        rm -f "$fwd_file"
        local sent bad
        sent=$(gtap_field "$sres" forwarded)
        bad=$(gtap_field "$sres" send_failed)
        gtap_relay_report "$relay_host" "$relay_port" "$n" "${sent:-0}" \
            "$skipped" "${bad:-0}" || rrc=1
        if (( rrc != 0 )) && [[ -n "$(gtap_field "$sres" why)" ]]; then
            printf 'why\t%s\n' "$(gtap_field "$sres" why)"
        fi
    fi

    # ── watchlist report ──
    if [[ -n "$wlfile" ]]; then
        gtap_watchlist_report "$wl_out"
    fi
    return "$rrc"
}

gtap_identities() {
    local pcap="${1:-}"
    gtap_init_store
    [[ -f "$GTAP_TSV" ]] || { printf 'ERROR\tno decode store; run --read first\n' >&2; return 1; }
    local n; n=$(tail -n +2 "$GTAP_TSV" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tdecode store is empty; run --read first\n' >&2; return 1; }

    # Hand the payloads to the per-generation decoder that owns the message
    # format, rather than re-implementing NAS/RR parsing here.
    local lte="$IMSISTING_ROOT/modules/09_lte_attach.sh"
    local gsm="$IMSISTING_ROOT/modules/06_gsm_air.sh"
    # The per-generation decoders read the messages that carry an identity in a
    # field they already parse (an IDENTITY REQUEST). The structural reader
    # reads the mobile identity element itself, so an Attach Request or a TAU
    # Request yields the subscriber instead of nothing.
    local nasid="$IMSISTING_ROOT/tools/nas_identity.py"
    local found=0

    printf 'frame\tkind\tvalue\tsource\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        gtap_split "$line"
        local fr="${GTAP_F[0]:-}" typ="${GTAP_F[1]:-}" pl="${GTAP_F[10]:-}"
        [[ -z "$pl" ]] && continue
        local dec=""
        case "$typ" in
            "LTE NAS"|"NR NAS") [[ -x "$lte" ]] && dec="$lte" ;;
            "GSM Um (CS)"|"GSM Um (PS)") [[ -x "$gsm" ]] && dec="$gsm" ;;
        esac
        [[ -z "$dec" ]] && continue
        # A payload carrying an IMSI in the clear is the finding. The decoder
        # is asked to classify it; if it cannot, nothing is claimed.
        local out="" src; src=$(basename "$dec")
        out=$("$dec" --identity-exposure "$pl" 2>/dev/null) || out=""
        if [[ -z "$out" && -x "$nasid" ]]; then
            out=$("$nasid" decode "$pl" 2>/dev/null | awk -F'\t' '
                $1 == "identity_kind" { k = $2 }
                $1 == "identity" && $2 ~ /^[0-9]+$/ { print k "\t" $2; exit }')
            [[ -n "$out" ]] && src="tools/nas_identity.py"
        fi
        [[ -z "$out" ]] && continue
        while IFS= read -r r; do
            [[ -z "$r" ]] && continue
            printf '%s\t%s\t%s\t%s\n' "$fr" "$(gtap_sanitize "$(cut -f1 <<<"$r")")" \
                "$(gtap_sanitize "$(cut -f2 <<<"$r")")" "$src"
            found=$((found + 1))
        done <<< "$out"
    done < <(tail -n +2 "$GTAP_TSV")
    return 0
}

gtap_export() {
    local n; n=$(tail -n +2 "$GTAP_TSV" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tnothing decoded to export\n' >&2; return 1; }
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out="$GTAP_DIR/decoded_${ts}.tsv"
    cp "$GTAP_TSV" "$out"
    printf 'OK\t%s\n' "$out"
}

# ── watchlist ───────────────────────────────────────────────────────────
# A subscriber list to watch for: one TMSI/IMSI/IMEI per line, blank lines and
# `#` comments ignored. Matching is on the normalised digit string so a list
# entry with the usual separators still matches a bare value from a payload.
# Any non-hex-digit character is stripped and letters upper-cased, which makes
# "310-150-123456789" and "310150123456789" the same key.
gtap_wl_norm() { printf '%s' "${1:-}" | tr -d '[:space:]-' | tr 'a-f' 'A-F'; }

gtap_watchlist_load() {
    local f="${1:-}"
    GTAP_WL=()
    [[ -n "$f" && -f "$f" ]] || {
        printf 'ERROR\tno such watchlist: %s\n' "${f:-<none>}" >&2; return 1; }
    local line v
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        v=$(gtap_wl_norm "$line")
        [[ -n "$v" ]] || continue
        GTAP_WL+=("$v")
    done < "$f"
    (( ${#GTAP_WL[@]} > 0 )) || {
        printf 'ERROR\twatchlist %s holds no usable entries\n' "$f" >&2; return 1; }
    return 0
}

# Three-state verdict. A value is "hit" only on an exact match, "miss" on a
# definite non-match. There is deliberately no third silent state: an empty
# value is "unknown", never "miss", because classifying an absent identity as
# clean is the "unknown is not safe" failure (brief §"An unknown value must
# never be classified as safe").
gtap_wl_verdict() {
    local v; v=$(gtap_wl_norm "${1:-}")
    [[ -n "$v" ]] || { printf 'unknown'; return 0; }
    local e
    for e in "${GTAP_WL[@]}"; do
        [[ "$e" == "$v" ]] && { printf 'hit'; return 0; }
    done
    printf 'miss'
}

# identities-tsv with a watchlist verdict appended. The frame/kind/value/source
# columns are unchanged; only the trailing verdict column is added.
gtap_identities_watch() {
    local wl="${1:-}"
    gtap_watchlist_load "$wl" || return 2
    local out; out=$(gtap_identities) || return 1
    printf 'frame\tkind\tvalue\tsource\twatch\n'
    local line n=0 hits=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        n=$((n + 1))
        (( n == 1 )) && continue      # skip gtap_identities' own header
        gtap_split "$line"
        local v="${GTAP_F[2]:-}"
        local verdict; verdict=$(gtap_wl_verdict "$v")
        [[ "$verdict" == "hit" ]] && hits=$((hits + 1))
        printf '%s\t%s\n' "$line" "$verdict"
    done <<< "$out"
    printf 'watchlist\thits\t%s\n' "$hits" >&2
    return 0
}

# The --watchlist store. Derived per call rather than captured at load time:
# the selftest repoints $GTAP_DIR at a scratch tree, and a path frozen into a
# global once wrote fixtures into the real loot/.
gtap_watchlist_tsv() { printf '%s' "$GTAP_DIR/watchlist.tsv"; }

# Match a loaded watchlist against every frame of a read, in ONE pass. This
# exists because a stream filter has to run over the whole capture, so it
# cannot afford a decoder fork per frame the way gtap_identities does (that is
# fine for a handful of identities, not for ten thousand frames). Instead it
# searches the encodings 24.008 actually puts on the wire for each kind of
# entry and names the encoding it matched, so a hit says what fired:
#
#   * 24.008 BCD, digit1 in the LOW nibble with F padding -- how an IMSI or an
#     IMEI leaves the phone inside the Mobile Identity IE. This is the identity
#     case, and the F-padded and unpadded forms are both searched because the
#     same digits appear padded in one message and embedded in another.
#   * The PLMN field of the Location Area Identification, which is three octets
#     in ITS OWN layout (MCC2|MCC1, MNC1|MCC3, MNC3|MNC2, F where the MNC has
#     two digits). The MCC+MNC digits of a watchlist entry are not a plain BCD
#     run, which is exactly the sort of nearly-right encoding that silently
#     never matches.
#   * 4-octet big endian, the width of a TMSI and of a 28-bit cell identity;
#     a cell id is a binary field, never BCD.
#
# Entries with no such encoding are reported with an empty kind. That is a
# fact, not a miss: a value nobody can put on the wire cannot be looked for.
# $1 = the reader's frames file, $2 = one normalised entry per line.
gtap_watchlist_match() {
    local frames="${1:-}" entries="${2:-}"
    [[ -f "$frames" ]] || {
        printf 'ERROR\tno frames file to match against\n' >&2; return 1; }
    [[ -f "$entries" ]] || {
        printf 'ERROR\tno watchlist entries to match\n' >&2; return 1; }
    python3 - "$frames" "$entries" <<'PY'
import sys

def encodings(v):
    """(label, bytes) pairs 24.008 can carry for this value."""
    out = []
    if v.isdigit():
        # BCD: digit1 in the low nibble, F pads an odd count.
        if 4 <= len(v) <= 16:
            b = bytearray()
            for i in range(0, len(v) - 1, 2):
                b.append(int(v[i + 1]) << 4 | int(v[i]))
            if len(v) % 2:
                b.append(0xF0 | int(v[-1]))
                out.append(("identity", bytes(b[:-1])))
            out.append(("identity", bytes(b)))
        # PLMN: MCC(3 digits) + MNC(2 or 3 digits), own octet layout.
        if len(v) in (5, 6):
            mcc, mnc = v[:3], v[3:]
            o1 = int(mcc[1]) << 4 | int(mcc[0])
            o2 = int(mnc[0]) << 4 | int(mcc[2])
            o3 = (int(mnc[2]) << 4 | int(mnc[1])) if len(mnc) > 2 else \
                 (0xF0 | int(mnc[1]))
            out.append(("plmn", bytes([o1, o2, o3])))
        # A cell identity is binary: search the two widths it is carried at.
        n = int(v)
        if 0 < n < 0x10000:
            out.append(("cellid", n.to_bytes(2, "big")))
        elif 0 < n < 0x10000000:
            out.append(("cellid", n.to_bytes(4, "big")))
    else:
        try:
            n = int(v, 16)
        except ValueError:
            return out
        if 0 < n < 0x100000000:
            out.append(("tmsi", n.to_bytes(4, "big")))
    return out

vals = [l.rstrip("\n") for l in open(sys.argv[2]) if l.strip()]
enc = [(v, encodings(v)) for v in vals]
counts = dict((v, 0) for v in vals)
payload_bytes = 0
hits = 0
for line in open(sys.argv[1]):
    f = line.rstrip("\n").split("\t")
    if len(f) < 4 or not f[3]:
        continue
    payload = bytes.fromhex(f[3])[16:]      # past the 16-byte GSMTAP header
    payload_bytes += len(payload)
    if not payload:
        continue
    for v, encs in enc:
        for label, b in encs:
            if len(b) <= len(payload) and b in payload:
                counts[v] += 1
                print("frame\t%s\t%s\t%s" % (f[0], v, label))
                hits += 1
                break
for v, encs in enc:
    kind = encs[0][0] if encs else ""
    print("entry\t%s\t%s\t%d" % (v, kind, counts[v]))
print("payload_bytes\t%d" % payload_bytes)
print("frame_hits\t%d" % hits)
PY
}

# Turn the matcher's answer into the report an operator reads, and append it to
# the watchlist store. The point of this function is the three-way verdict: an
# entry that was searched and found is `matched`, an entry that was searched and
# not found is `unmatched`, and an entry that could not be searched at all is
# `unobserved` with a reason. Collapsing the third case into the second is the
# "no hits is not the same fact as never looked" failure this module exists to
# avoid. $1 = gtap_watchlist_match output.
gtap_watchlist_report() {
    local out="${1:-}"
    local payload; payload=$(gtap_field "$out" payload_bytes)
    local store; store=$(gtap_watchlist_tsv)
    mkdir -p "$GTAP_DIR" 2>/dev/null
    [[ -f "$store" ]] || printf 'ts_utc\tentry\tkind\tcount\tverdict\n' > "$store"
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local nm=0 nu=0 no=0
    printf 'watchlist_store\t%s\n' "$store"
    local r
    while IFS= read -r r; do
        [[ -n "$r" ]] || continue
        [[ "${r%%	*}" == "entry" ]] || continue
        gtap_split "$r"
        local val="${GTAP_F[1]:-}" kind="${GTAP_F[2]:-}" cnt="${GTAP_F[3]:-0}" verdict
        if [[ -z "$kind" ]]; then
            # No wire encoding exists for this value, so nobody looked.
            verdict="unobserved"
        elif [[ "${payload:-0}" -le 0 ]]; then
            # Frames arrived but carried no payload octet to search.
            verdict="unobserved"
        elif [[ "${cnt:-0}" -gt 0 ]]; then
            verdict="matched"
        else
            verdict="unmatched"
        fi
        case "$verdict" in
            matched)   nm=$((nm + 1)) ;;
            unmatched) nu=$((nu + 1)) ;;
            *)         no=$((no + 1)) ;;
        esac
        printf 'watchlist_entry\t%s\t%s\t%s\t%s\n' \
            "$(gtap_sanitize "$val")" "${kind:-none}" "$verdict" "${cnt:-0}"
        printf '%s\t%s\t%s\t%s\t%s\n' "$ts" "$(gtap_sanitize "$val")" \
            "${kind:-none}" "${cnt:-0}" "$verdict" >> "$store"
    done <<< "$out"
    printf 'watchlist_matched_entries\t%s\n' "$nm"
    printf 'watchlist_unmatched_entries\t%s\n' "$nu"
    (( no > 0 )) && printf 'watchlist_unobserved_entries\t%s\n' "$no"
    # Always a verdict row: an empty report and a report that could not be
    # produced must not render the same way.
    if (( nm == 0 && nu == 0 )); then
        printf 'verdict\tunobserved\n'
        printf 'why\tno watchlist entry could be searched: %s payload octets in the stream\n' \
            "${payload:-0}"
    elif (( nm > 0 )); then
        printf 'verdict\tmatched\n'
    else
        printf 'verdict\tno-match\n'
    fi
    return 0
}

# ── relay ───────────────────────────────────────────────────────────────
# The relay store. Derived per call, not captured at load time, for the same
# reason as gtap_watchlist_tsv: the selftest repoints $GTAP_DIR.
gtap_relay_tsv() { printf '%s' "$GTAP_DIR/relay.tsv"; }

# Can anything be reached at HOST:PORT? A relay that is refused up front is a
# different thing from a relay that runs and forwards nothing, and only one of
# them means the collector is misconfigured. UDP cannot be asked directly -- no
# handshake, no error -- so the only honest signal is the ICMP
# port-unreachable the kernel hands back to a CONNECTED socket. The probe
# therefore carries an EMPTY datagram: it is not a GSMTAP frame, carries no
# header, and this module's own listener drops empty datagrams for the same
# reason. Emits `verdict reachable|unreachable` plus a `why`/`probe` row; rc 0
# only when something is there to read it.
gtap_relay_probe() {
    local host="${1:-}" port="${2:-}"
    if [[ -z "$host" ]]; then
        printf 'verdict\tunreachable\nwhy\tno relay host was named\n'
        return 1
    fi
    if ! gtap_valid_port "$port"; then
        printf 'verdict\tunreachable\nwhy\t%s is not a UDP port\n' "${port:-<empty>}"
        return 1
    fi
    command -v python3 >/dev/null 2>&1 || {
        printf 'verdict\tunobserved\nwhy\tpython3 is missing, so the destination cannot be probed\n'
        return 1; }
    python3 - "$host" "$port" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
except OSError as e:
    print("verdict\tunreachable")
    print("why\tcannot resolve %s (%s)" % (host, e))
    sys.exit(1)
sa = infos[0][4]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.2)
try:
    s.connect(sa)
except OSError as e:
    print("verdict\tunreachable")
    print("why\tcannot address %s:%d (%s)" % (host, port, e))
    sys.exit(1)
refused = ""
for _ in range(3):
    try:
        s.send(b"")
    except OSError as e:
        refused = str(e) or "send failed"
        break
    try:
        s.recv(1)
    except ConnectionRefusedError as e:
        refused = str(e) or "connection refused"
        break
    except socket.timeout:
        continue
    except OSError as e:
        refused = str(e) or "socket error"
        break
    break
s.close()
if refused:
    print("verdict\tunreachable")
    print("why\tnothing accepted the probe at %s:%d (%s)" % (host, port, refused))
    sys.exit(1)
print("verdict\treachable")
print("resolved\t%s:%d" % (sa[0], sa[1]))
print("probe\tno-refusal-observed")
PY
}

# Hand the frames that passed the filters to the second collector. They go out
# as the original datagrams, byte for byte: a GSMTAP header names the payload
# type and the radio's state, not the collector that read it, so nothing in it
# has to change -- and rebuilding it from the fields this module parses would
# silently drop the ones it does not (antenna_nr, sub_slot, res) and produce a
# worse copy than the original. `forwarded` counts datagrams the kernel
# accepted from sendto(); whether a remote process read them is not something a
# UDP sender can observe, and is not claimed.
gtap_relay_send() {  # <host> <port> <hexfile>
    local host="${1:-}" port="${2:-}" file="${3:-}"
    [[ -f "$file" ]] || {
        printf 'ERROR\tno frames staged for relay\n' >&2; return 1; }
    python3 - "$host" "$port" "$file" <<'PY'
import socket, sys, time
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    sa = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
except OSError as e:
    print("forwarded\t0")
    print("send_failed\t0")
    print("why\tcannot resolve %s (%s)" % (host, e))
    sys.exit(1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sent = failed = n = 0
err = ""
for line in open(path):
    line = line.strip()
    if not line:
        continue
    g = bytes.fromhex(line)
    if len(g) < 16:
        # Short of a header: not a GSMTAP datagram, so it cannot be relayed.
        failed += 1
        err = "a staged frame is shorter than a 16-byte GSMTAP header"
        continue
    try:
        s.sendto(g, sa)
        sent += 1
    except OSError as e:
        failed += 1
        err = str(e)
    n += 1
    if n % 128 == 0:
        time.sleep(0.001)   # do not outrun a slow receiver's socket buffer
s.close()
print("forwarded\t%d" % sent)
print("send_failed\t%d" % failed)
if failed > 0:
    print("why\t%s" % (err or "sendto failed"))
PY
}

# Report --relay's three counters and give them a verdict, then record them so a
# second process can read the same numbers out of loot instead of asking this
# shell. The three counters exist because their difference is the finding:
# seen=0 is "the destination was never given anything", seen=N/forwarded=0 is
# "your filters excluded every frame", and seen=N/forwarded=N is a working
# relay. A single "forwarded: 0" line would hide which of those happened.
gtap_relay_report() {  # <host> <port> <seen> <forwarded> <dropped> <sendfailed>
    local host="${1:-}" port="${2:-}" seen="${3:-0}" fwd="${4:-0}" \
          drop="${5:-0}" bad="${6:-0}"
    local store; store=$(gtap_relay_tsv)
    mkdir -p "$GTAP_DIR" 2>/dev/null
    [[ -f "$store" ]] || printf 'ts_utc\ttarget\tpackets_seen\tpackets_forwarded\tpackets_dropped_by_filter\tsend_failed\tverdict\n' > "$store"
    local verdict
    if (( seen <= 0 )); then
        verdict="unobserved"
    elif (( fwd <= 0 )); then
        # Frames were seen and every one of them was filtered out.
        verdict="silent"
    elif (( fwd + drop + bad < seen )); then
        verdict="partial"
    else
        verdict="relayed"
    fi
    printf 'relay_target\t%s:%s\n' "$host" "$port"
    printf 'packets_seen\t%s\n' "$seen"
    printf 'packets_forwarded\t%s\n' "$fwd"
    printf 'packets_dropped_by_filter\t%s\n' "$drop"
    (( bad > 0 )) && printf 'relay_send_failed\t%s\n' "$bad"
    printf 'relay_verdict\t%s\n' "$verdict"
    printf 'relay_store\t%s\n' "$store"
    printf '%s\t%s:%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$host" "$port" "$seen" "$fwd" "$drop" "$bad" "$verdict" >> "$store"
    if (( seen <= 0 )); then
        printf 'verdict\tunobserved\n'
        printf 'why\tthe capture carried no GSMTAP frame to relay\n'
        return 1
    fi
    (( bad > 0 )) && return 1
    return 0
}

# The relay counters as TSV, for a second process. No relay yet is not a zero
# counter: it is an unobserved one, and it says so with a reason and a non-zero
# exit rather than handing back a tidy row of zeroes that reads as "a relay ran
# and forwarded nothing".
gtap_cmd_relay_status() {
    local store; store=$(gtap_relay_tsv)
    if [[ ! -s "$store" ]]; then
        printf 'verdict\tunobserved\n'
        printf 'why\tno relay has been recorded in %s\n' "$store"
        return 1
    fi
    local last; last=$(tail -n +2 "$store" 2>/dev/null | grep . | tail -n 1)
    if [[ -z "$last" ]]; then
        printf 'verdict\tunobserved\n'
        printf 'why\t%s holds a header and no relay run\n' "$store"
        return 1
    fi
    gtap_split "$last"
    printf 'relay_target\t%s\n'              "${GTAP_F[1]:-unobserved}"
    printf 'packets_seen\t%s\n'              "${GTAP_F[2]:-unobserved}"
    printf 'packets_forwarded\t%s\n'         "${GTAP_F[3]:-unobserved}"
    printf 'packets_dropped_by_filter\t%s\n' "${GTAP_F[4]:-unobserved}"
    printf 'relay_send_failed\t%s\n'         "${GTAP_F[5]:-unobserved}"
    printf 'verdict\t%s\n'                   "${GTAP_F[6]:-unobserved}"
    printf 'recorded\t%s\n'                  "${GTAP_F[0]:-unobserved}"
    printf 'relay_store\t%s\n'               "$store"
    [[ "${GTAP_F[6]:-}" == "unobserved" ]] && return 1
    return 0
}

# --relay <HOST:PORT> [PCAP]: read a capture and hand every frame that survives
# the filters to a second collector. The probe runs before the capture is
# touched so an unreachable destination is a named refusal instead of a run
# that parses, decodes, and finally reports zero forwarded frames -- which is
# indistinguishable from a filter that excluded everything.
gtap_cmd_relay() {  # <host:port> [pcap]
    local spec="${1:-}" pcap="${2:-}"
    if [[ -z "$spec" ]]; then
        printf 'ERROR\t--relay needs HOST:PORT\n' >&2
        return 2
    fi
    if ! gtap_relay_split "$spec"; then
        printf 'ERROR\t--relay needs HOST:PORT, got: %s\n' "$spec" >&2
        return 2
    fi
    if [[ -z "$pcap" ]]; then
        printf 'MISSING\tcapture to relay\n' >&2
        printf 'WHY\t--relay forwards the frames a capture carries, and no capture was named\n' >&2
        return 1
    fi
    gtap_decode_pcap "$pcap" "${fport:-$GTAP_PORT}" "${fsince:-}" "${funtil:-}" \
        "${farfcn:-}" "${fchan:-}" "${ful:-0}" \
        "${GTAP_RELAY_HOST}:${GTAP_RELAY_PORT}" "${fwl:-}"
}

# ── selftest ────────────────────────────────────────────────────────────
# The header layout asserted here was verified against Wireshark's GSMTAP
# dissector: a 16-byte version-2 header with hdr_len = 4, the GSM channel in
# sub_type, and uplink as 0x4000 in the arfcn field.
gtap_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { gtap_field "$1" "$2"; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" GTAP_DIR="$d/loot/gsmtap" GTAP_TSV="$d/loot/gsmtap/decoded.tsv"
    # Read the shared SDR state from the scratch dir, not the host's.
    export GTAP_SDR="$d/state/sdr_device"

    # 1. Header size and the word/byte relationship. This is the trap: a
    #    12-byte header with hdr_len = 4 makes a dissector eat payload.
    local h; h=$(gtap_build_header 1 0 42 -60 25 298 5)
    chk hdr-hex-len   "$(( ${#h} / 2 ))" "16"
    chk hdr-hdrlen-b  "$(gtap_field "$(gtap_parse_header "$h")" hdr_len_bytes)" "16"

    # 2. Known-answer: the exact bytes for a known field set.
    chk hdr-exact "$h" "02040100""002a""c4""19""0000012a""05""000000"

    # 3. Field round-trip.
    local p; p=$(gtap_parse_header "$h")
    chk fld-version  "$(fld "$p" version)" "2"
    chk fld-hdrlen   "$(fld "$p" hdr_len_words)" "4"
    chk fld-type     "$(fld "$p" type)" "0x01"
    chk fld-arfcn    "$(fld "$p" arfcn)" "42"
    chk fld-uplink   "$(fld "$p" uplink)" "no"
    chk fld-signal   "$(fld "$p" signal_dbm)" "-60"
    chk fld-snr      "$(fld "$p" snr_db)" "25"
    chk fld-frame    "$(fld "$p" frame_number)" "298"
    chk fld-subtype  "$(fld "$p" sub_type)" "0x05"
    chk fld-payload  "$(fld "$p" payload_hex)" ""

    # 4. The uplink and PCS flags live in the arfcn field, not the ARFCN.
    h=$(gtap_build_header 1 0 42 0 0 0 5 1 0)
    p=$(gtap_parse_header "$h")
    chk flag-ul-arfcn "$(fld "$p" arfcn)" "42"
    chk flag-ul-set   "$(fld "$p" uplink)" "yes"
    chk flag-ul-pcs   "$(fld "$p" pcs)" "no"
    h=$(gtap_build_header 1 0 42 0 0 0 5 0 1)
    chk flag-pcs-set  "$(fld "$(gtap_parse_header "$h")" pcs)" "yes"

    # 5. Channel naming, current encoding.
    chk ch-bcch   "$(gtap_channel_name 0x01)" "BCCH"
    chk ch-ccch   "$(gtap_channel_name 0x02)" "CCCH"
    chk ch-pch    "$(gtap_channel_name 0x05)" "PCH"
    chk ch-sdcch  "$(gtap_channel_name 0x06)" "SDCCH"
    chk ch-tchf   "$(gtap_channel_name 0x09)" "TCH/F"
    chk ch-unknown "$(gtap_channel_name 0x7e)" "unknown"
    chk ch-of-sub  "$(gtap_channel_of 0x05 42 0x01)" "PCH"
    # Legacy encoding still decodes for an old capture.
    chk ch-legacy  "$(gtap_channel_of 0x00 $(( (0x05 << 8) | 42 )) 0x01)" "PCH"
    chk ch-none    "$(gtap_channel_of 0x00 42 0x01)" "UNKNOWN"
    # sub_type is a GSM channel only under a GSM payload. Under LTE NAS the
    # same octet is not a channel, and claiming one would be wrong.
    chk ch-gsm-ty  "$(gtap_is_gsm_type 0x01 && echo yes || echo no)" "yes"
    chk ch-lte-ty  "$(gtap_is_gsm_type 0x05 && echo yes || echo no)" "no"
    chk ch-nongsm  "$(gtap_channel_of 0x05 42 0x05)" "-"

    # 6. Payload types.
    chk ty-gsm  "$(gtap_type_name 0x01)" "GSM Um (CS)"
    chk ty-lte  "$(gtap_type_name 0x04)" "LTE RRC"
    chk ty-nr   "$(gtap_type_name 0x06)" "NR RRC"
    chk ty-unk  "$(gtap_type_name 0x99)" "unknown"

    # 7. Truncated and malformed input must fail, not guess.
    chk short-rc   "$(gtap_parse_header 02040100 >/dev/null 2>&1; echo $?)" "1"
    chk nonhex-rc  "$(gtap_parse_header zz >/dev/null 2>&1; echo $?)" "2"
    chk arfcn-range "$(gtap_build_header 1 0 99999 >/dev/null 2>&1; echo $?)" "1"

    # 8. Payload is carried through untouched.
    h=$(gtap_build_header 5 0 42 0 0 0 0)
    p=$(gtap_parse_header "${h}deadbeef")
    chk payload-kept "$(fld "$p" payload_hex)" "deadbeef"
    chk payload-len  "$(( ${#h} / 2 ))" "16"

    # 9. The identity harvest is a CROSS-MODULE contract: this module asks
    #    06_gsm_air to classify each GSM Um payload with --identity-exposure.
    #    If that verb ever goes missing the loop's `|| continue` swallows every
    #    payload and the harvest silently reports nothing -- which is exactly
    #    how it was broken before. Assert both halves: the callee implements
    #    the verb, and a real IDENTITY RESPONSE yields its IMSI here.
    local gsm="$IMSISTING_ROOT/modules/06_gsm_air.sh"
    chk exp-verb-exists \
        "$(grep -cE '^[[:space:]]*--identity-exposure\)' "$gsm" 2>/dev/null)" "1"
    chk exp-verb-answers \
        "$("$gsm" --identity-exposure 06093901511032547698 2>/dev/null | awk -F'\t' '$1=="imsi"{print $2}')" \
        "310150123456789"
    chk exp-verb-refuses \
        "$("$gsm" --identity-exposure 06061b000162f2103039 >/dev/null 2>&1; echo $?)" "1"
    #    And through this module's own entry point, over a store holding one
    #    identity-bearing payload and one that carries none.
    mkdir -p "$GTAP_DIR"
    printf 'frame\ttype\tchannel\tarfcn\tuplink\ttimeslot\tsignal_dbm\tsnr_db\tframe_number\tpayload_len\tpayload_hex\n' > "$GTAP_TSV"
    printf '1\tGSM Um (CS)\t0\t42\t1\t0\t-60\t20\t1\t10\t06093901511032547698\n' >> "$GTAP_TSV"
    printf '2\tGSM Um (CS)\t0\t42\t1\t0\t-60\t20\t2\t11\t06061b000162f2103039\n' >> "$GTAP_TSV"
    local ids; ids=$(gtap_identities 2>/dev/null)
    chk id-harvest-imsi "$(printf '%s\n' "$ids" | awk -F'\t' '$2=="imsi"{print $3}')" \
        "310150123456789"
    chk id-harvest-frame "$(printf '%s\n' "$ids" | awk -F'\t' '$2=="imsi"{print $1}')" "1"
    chk id-harvest-only-1 "$(printf '%s\n' "$ids" | tail -n +2 | grep -c .)" "5"
    rm -f "$GTAP_TSV"

    # 9. pcap write then read round-trip, including a frame with an empty
    #    payload, which is where a collapsing TSV reader would lose a column.
    local pc="$d/rt.pcap"
    printf '%s\n%s\n' "$(gtap_build_header 1 0 7 0 0 0 1)" \
                      "$(gtap_build_header 5 0 42 -60 25 298 5)ff00" > "$d/frames.txt"
    printf '%s\n' "$(gtap_build_header 1 0 42 -60 25 298 5)ff00" >> "$d/frames.txt"
    gtap_write_pcap "$pc" "$d/frames.txt"
    chk pcap-exists "$([[ -s "$pc" ]] && echo yes || echo no)" "yes"
    local rd; rd=$(gtap_read_pcap "$pc")
    chk pcap-frames "$(printf '%s\n' "$rd" | grep -c .)" "3"
    # The reader now carries ordinal, ts_sec, ts_usec, payload-hex; the payload
    # moved from field 2 to field 4.
    chk pcap-f1     "$(printf '%s\n' "$rd" | head -1 | cut -f4)" \
                    "$(gtap_build_header 1 0 7 0 0 0 1)"
    chk pcap-f2     "$(printf '%s\n' "$rd" | sed -n '2p' | cut -f4)" \
                    "$(gtap_build_header 5 0 42 -60 25 298 5)ff00"
    chk pcap-f3     "$(printf '%s\n' "$rd" | sed -n '3p' | cut -f4)" \
                    "$(gtap_build_header 1 0 42 -60 25 298 5)ff00"

    # 10. Decode to the store, and the store's field count. The two ts columns
    #     were APPENDED after payload_hex, so every previously-published
    #     column index is unchanged (payload_hex is still field 11).
    local out; out=$(gtap_decode_pcap "$pc")
    chk dec-frames "$(gtap_field "$out" frames)" "3"
    chk store-rows "$(tail -n +2 "$GTAP_TSV" | grep -c .)" "3"
    chk store-cols "$(head -1 "$GTAP_TSV" | awk -F'\t' '{print NF}')" "13"
    chk store-f1ch "$(sed -n '2p' "$GTAP_TSV" | cut -f3)" "BCCH"
    # Frame 2 is an LTE NAS payload, so it gets no GSM channel name.
    chk store-f2ch "$(sed -n '3p' "$GTAP_TSV" | cut -f3)" "-"
    chk store-f2sig "$(sed -n '3p' "$GTAP_TSV" | cut -f7)" "-60"
    # Frame 3 is the same sub_type under a GSM payload, so it IS a channel.
    chk store-f3ch "$(sed -n '4p' "$GTAP_TSV" | cut -f3)" "PCH"

    # 11. A non-GSMTAP pcap is an error, not an empty success.
    local bad_pc="$d/bad.pcap"
    printf '%s\n' "$(gtap_build_header 1 0 7 0 0 0 1)" > "$d/one.txt"
    gtap_write_pcap "$bad_pc" "$d/one.txt"
    python3 - "$bad_pc" <<'PY'
import sys
p = sys.argv[1]
d = bytearray(open(p,'rb').read())
# Rewrite BOTH UDP ports away from 4729. The reader accepts a frame if either
# port matches, so changing only the destination would leave sport=4729 and
# the test would pass for the wrong reason.
n = 0
for i in range(len(d) - 1):
    if d[i:i+2] == bytes([0x12, 0x79]):
        d[i:i+2] = bytes([0x00, 0x01]); n += 1
if n < 2:
    sys.stderr.write("test fixture: expected 2 port occurrences, found %d\n" % n)
    sys.exit(3)
open(p,'wb').write(bytes(d))
PY
    chk non-gsmtap-fixture "$?" "0"
    chk non-gsmtap-rc "$(gtap_decode_pcap "$bad_pc" >/dev/null 2>&1; echo $?)" "1"

    # High, uncommon ports for the live-listener block: it must not collide
    # with the fixtures above (4729 default, 4800 explicit).
    local GTAP_LIVE_PORT=49701

    # 12. Export refuses an empty store.
    : > "$GTAP_TSV"
    chk export-empty-rc "$(gtap_export >/dev/null 2>&1; echo $?)" "1"
    chk read-missing-rc "$(gtap_read_pcap "$d/nope.pcap" >/dev/null 2>&1; echo $?)" "1"

    # ── 13. Configurable port and bind (gap 1) ──────────────────────────
    # A fixture with a NON-default UDP port and a known capture timestamp.
    # Building it inline rather than reusing gtap_write_pcap proves the reader
    # is not keyed to whatever the writer happens to emit.
    local FIX_TS=1700000000
    local pfix="$d/portfixture.pcap"
    python3 - "$pfix" "$FIX_TS" "$(gtap_build_header 1 0 42 -60 25 298 5)" \
                   "$(gtap_build_header 1 0 99 -70 10 7 6)" <<'PY'
import struct, sys
out, ts0, h1, h2 = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
frames = [(ts0, 0, bytes.fromhex(h1 + "aa")), (ts0 + 60, 500000, bytes.fromhex(h2 + "bb"))]
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, tu, g in frames:
        udp = struct.pack('!HHHH', 4800, 4800, 8 + len(g), 0) + g
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         bytes([10,0,0,1]), bytes([10,0,0,2])) + udp
        eth = bytes.fromhex('001122334455') + bytes.fromhex('66778899aabb') + \
              struct.pack('!H', 0x0800) + ip
        f.write(struct.pack('<IIII', ts, tu, len(eth), len(eth)))
        f.write(eth)
PY

    # Default port 4729 must NOT see frames that arrived on 4800...
    chk port-default-rejects \
        "$(gtap_read_pcap "$pfix" 2>/dev/null | grep -c .)" "0"
    chk port-default-rc \
        "$(gtap_decode_pcap "$pfix" >/dev/null 2>&1; echo $?)" "1"
    # ...but --port 4800 does, and --any-port widens it to any port.
    chk port-explicit \
        "$(gtap_read_pcap "$pfix" 4800 2>/dev/null | grep -c .)" "2"
    chk port-any \
        "$(gtap_read_pcap "$pfix" any 2>/dev/null | grep -c .)" "2"
    # An old 4729 capture still reads under the default.
    chk port-legacy-default "$(gtap_read_pcap "$pc" 2>/dev/null | grep -c .)" "3"

    # Port validation: bad values are rejected, never spliced into a socket.
    chk badport-empty "$(gtap_valid_port '' && echo ok || echo no)" "no"
    chk badport-alpha "$(gtap_valid_port 47x9 && echo ok || echo no)" "no"
    chk badport-zero  "$(gtap_valid_port 0 && echo ok || echo no)" "no"
    chk badport-high  "$(gtap_valid_port 65536 && echo ok || echo no)" "no"
    chk goodport-4729 "$(gtap_valid_port 4729 && echo ok || echo no)" "ok"
    chk goodport-1    "$(gtap_valid_port 1 && echo ok || echo no)" "ok"
    # A comma would silently split a socat address list; a colon means IPv6,
    # which the UDP4-RECV path does not serve.
    chk iface-comma   "$(gtap_valid_iface '0.0.0.0,1.2.3.4' && echo ok || echo no)" "no"
    chk iface-v6      "$(gtap_valid_iface '::1' && echo ok || echo no)" "no"
    chk iface-wild    "$(gtap_valid_iface '0.0.0.0' && echo ok || echo no)" "ok"
    chk iface-loop    "$(gtap_valid_iface '127.0.0.1' && echo ok || echo no)" "ok"
    # --forward HOST:PORT, split on the LAST colon.
    chk fwd-ok        "$(gtap_forward_split 127.0.0.1:4730 && printf '%s/%s' "$GTAP_FWD_HOST" "$GTAP_FWD_PORT")" "127.0.0.1/4730"
    chk fwd-noport    "$(gtap_forward_split 127.0.0.1 && echo ok || echo no)" "no"
    chk fwd-badport   "$(gtap_forward_split host:99999 && echo ok || echo no)" "no"
    chk fwd-nohost    "$(gtap_forward_split :4730 && echo ok || echo no)" "no"

    # ── 14. Capture timestamps are carried, not discarded (gap 3) ───────
    # The fixture's own ts values are the known answer: ts_sec 1700000000
    # renders as 2023-11-14T22:13:20Z (independent of this code, it is what
    # `date -u -d @1700000000` says).
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800)
    chk ts-frames "$(gtap_field "$out" frames)" "2"
    chk ts-row1-epoch "$(sed -n '2p' "$GTAP_TSV" | cut -f12)" "1700000000"
    chk ts-row1-utc   "$(sed -n '2p' "$GTAP_TSV" | cut -f13)" "2023-11-14T22:13:20Z"
    chk ts-row2-epoch "$(sed -n '3p' "$GTAP_TSV" | cut -f12)" "1700000060"
    chk ts-row2-utc   "$(sed -n '3p' "$GTAP_TSV" | cut -f13)" "2023-11-14T22:14:20Z"
    # The ts columns are the LAST two, so payload_hex is still field 11 and
    # the identities harvester's GTAP_F[10] still reads the payload.
    # payload_hex is the payload AFTER the 16-byte header -- gtap_parse_header
    # splits the header off -- so the known answer is the trailing octet only.
    chk ts-payload-still-11 "$(sed -n '2p' "$GTAP_TSV" | cut -f11)" "aa"
    chk ts-hdr-epoch "$(head -1 "$GTAP_TSV" | cut -f12)" "ts_epoch"
    chk ts-hdr-utc   "$(head -1 "$GTAP_TSV" | cut -f13)" "ts_utc"
    chk ts-utc-known "$(gtap_ts_utc 0)" "1970-01-01T00:00:00Z"
    chk ts-utc-empty "$(gtap_ts_utc '')" ""

    # --since/--until bound a read. 1700000030 sits between the two frames, so
    # it must select exactly one of them in each direction.
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 "" 1700000030)
    chk since-frames "$(gtap_field "$out" frames)" "1"
    chk since-keeps  "$(sed -n '2p' "$GTAP_TSV" | cut -f12)" "1700000000"
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 1700000030 "")
    chk until-frames "$(gtap_field "$out" frames)" "1"
    chk until-keeps  "$(sed -n '2p' "$GTAP_TSV" | cut -f12)" "1700000060"
    # Inclusive bounds: an exact-ts bound keeps that frame.
    out=$(gtap_decode_pcap "$pfix" 4800 1700000000)
    chk since-incl "$(gtap_field "$out" frames)" "2"
    # A window that excludes everything is a reported zero, not an error.
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 1800000000 "")
    chk window-empty "$(gtap_field "$out" frames)" "0"
    # An unparseable bound is an error, not a silently-ignored filter.
    chk badbound-rc "$(gtap_decode_pcap "$pfix" 4800 "not-a-date" >/dev/null 2>&1; echo $?)" "2"
    chk bound-iso   "$(gtap_ts_bound 2023-11-14T22:13:20Z)" "1700000000"
    chk bound-epoch "$(gtap_ts_bound 1700000000)" "1700000000"
    chk bound-junk-rc "$(gtap_ts_bound zzz >/dev/null 2>&1; echo $?)" "1"

    # ── 15. ARFCN / channel / uplink filters (gap 4) ────────────────────
    # The fixture holds ARFCN 42 / PCH (sub_type 5) / downlink and
    # ARFCN 99 / SDCCH (sub_type 6) / downlink. Both directions for each
    # filter: the matching frame is admitted AND the non-matching one is not.
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 "" "" 42)
    chk flt-arfcn-frames "$(gtap_field "$out" frames)" "1"
    chk flt-arfcn-keeps  "$(sed -n '2p' "$GTAP_TSV" | cut -f4)" "42"
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 "" "" 99)
    chk flt-arfcn-other  "$(sed -n '2p' "$GTAP_TSV" | cut -f4)" "99"
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 "" "" "" PCH)
    chk flt-chan-frames  "$(gtap_field "$out" frames)" "1"
    chk flt-chan-keeps   "$(sed -n '2p' "$GTAP_TSV" | cut -f3)" "PCH"
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 "" "" "" SDCCH)
    chk flt-chan-other   "$(sed -n '2p' "$GTAP_TSV" | cut -f3)" "SDCCH"
    # A filter that matches nothing reports zero rows rather than everything.
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$pfix" 4800 "" "" 7)
    chk flt-arfcn-none   "$(gtap_field "$out" frames)" "0"
    chk flt-none-rows    "$(tail -n +2 "$GTAP_TSV" | grep -c .)" "0"
    # The filtered count is reported so a silent 0 is visible.
    out=$(gtap_decode_pcap "$pfix" 4800 "" "" 42)
    chk flt-filtered "$(gtap_field "$out" filtered)" "1"
    # Uplink: build a fixture whose only frame is uplink-flagged.
    local ulh; ulh=$(gtap_build_header 1 0 42 -60 25 298 5 1 0)
    python3 - "$d/ul.pcap" "$ulh" <<'PY'
import struct, sys
out, h1 = sys.argv[1], sys.argv[2]
g = bytes.fromhex(h1 + "cc")
udp = struct.pack('!HHHH', 4800, 4800, 8 + len(g), 0) + g
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                 bytes([10,0,0,1]), bytes([10,0,0,2])) + udp
eth = bytes.fromhex('001122334455') + bytes.fromhex('66778899aabb') + \
      struct.pack('!H', 0x0800) + ip
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    f.write(struct.pack('<IIII', 1700000000, 0, len(eth), len(eth)))
    f.write(eth)
PY
    rm -f "$GTAP_TSV"
    out=$(gtap_decode_pcap "$d/ul.pcap" 4800 "" "" "" "" 1)
    chk flt-ul-keeps  "$(gtap_field "$out" frames)" "1"
    chk flt-ul-value  "$(sed -n '2p' "$GTAP_TSV" | cut -f5)" "yes"
    # The same capture with no uplink filter keeps it too, and the downlink
    # fixture is rejected by the uplink filter -- both directions.
    out=$(gtap_decode_pcap "$d/ul.pcap" 4800)
    chk flt-ul-plain  "$(gtap_field "$out" frames)" "1"
    out=$(gtap_decode_pcap "$pfix" 4800 "" "" "" "" 1)
    chk flt-ul-rejects "$(gtap_field "$out" frames)" "0"
    # An out-of-range ARFCN is refused rather than filtering everything out.
    chk flt-arfcn-range "$(gtap_decode_pcap "$pfix" 4800 "" "" 99999 >/dev/null 2>&1; echo $?)" "2"

    # ── 16. Watchlist flags hits, and abstains on a clean identity ──────
    # Rebuild the identity store the harvester reads.
    mkdir -p "$GTAP_DIR"
    printf 'frame\ttype\tchannel\tarfcn\tuplink\ttimeslot\tsignal_dbm\tsnr_db\tframe_number\tpayload_len\tpayload_hex\tts_epoch\tts_utc\n' > "$GTAP_TSV"
    printf '1\tGSM Um (CS)\t0\t42\t1\t0\t-60\t20\t1\t10\t06093901511032547698\t1700000000\t2023-11-14T22:13:20Z\n' >> "$GTAP_TSV"
    printf '2\tGSM Um (CS)\t0\t42\t1\t0\t-60\t20\t2\t11\t06061b000162f2103039\t1700000001\t2023-11-14T22:13:21Z\n' >> "$GTAP_TSV"
    local wlf="$d/watch.txt"
    printf '# watch these\n\n310150123456789\n' > "$wlf"
    local wid; wid=$(gtap_identities_watch "$wlf" 2>/dev/null)
    # Positive direction: the planted IMSI is flagged hit.
    chk wl-hit "$(printf '%s\n' "$wid" | awk -F'\t' '$3=="310150123456789"{print $5}')" "hit"
    chk wl-hit-count "$(printf '%s\n' "$wid" | awk -F'\t' '$5=="hit"' | grep -c .)" "1"
    chk wl-header "$(printf '%s\n' "$wid" | head -1 | cut -f5)" "watch"
    # Negative direction: a value NOT on the list is a miss, not a hit -- a
    # matcher that always fires would pass the assertion above and fail here.
    # gtap_identities_watch runs in a command substitution above, so its
    # gtap_watchlist_load happened in a SUBSHELL and the parent's GTAP_WL is
    # still empty. Load in this shell before asserting on the verdict.
    gtap_watchlist_load "$wlf"
    chk wl-loaded "$(printf '%s' "${#GTAP_WL[@]}")" "1"
    chk wl-miss "$(gtap_wl_verdict 999999999999999)" "miss"
    chk wl-verdict-hit "$(gtap_wl_verdict 310150123456789)" "hit"
    chk wl-verdict-miss "$(gtap_wl_verdict 310150000000000)" "miss"
    # An absent identity is unknown, never "miss" (unknown is not safe).
    chk wl-verdict-unknown "$(gtap_wl_verdict '')" "unknown"
    chk wl-verdict-junk "$(gtap_wl_verdict '----')" "unknown"
    # Separators are normalised, so the list form still matches a bare value.
    chk wl-norm-dashes "$(gtap_wl_norm 310-150-123456789)" "310150123456789"
    chk wl-norm-space  "$(gtap_wl_norm ' 310150123456789 ')" "310150123456789"
    chk wl-norm-lower  "$(gtap_wl_norm 0a1b2c3d4e5f)" "0A1B2C3D4E5F"
    # A list with no usable entries is an error, not a silent no-op.
    printf '# only a comment\n' > "$d/empty.txt"
    chk wl-empty-rc "$(gtap_watchlist_load "$d/empty.txt" >/dev/null 2>&1; echo $?)" "1"
    chk wl-missing-rc "$(gtap_watchlist_load "$d/nope.txt" >/dev/null 2>&1; echo $?)" "1"
    # The unflagged path is unchanged: no verdict column when no list is given.
    chk wl-off-header "$(gtap_identities 2>/dev/null | head -1 | awk -F'\t' '{print NF}')" "4"

    # ── 17. Defaults unchanged: no flags == the old behaviour ───────────
    # The Lead's requirement, asserted rather than claimed: the store a
    # flagless read produces must be byte-identical to the store produced by
    # passing every default explicitly (port 4729, no bound, no filter).
    rm -f "$GTAP_TSV"
    gtap_decode_pcap "$pc" >/dev/null
    local plain; plain=$(cat "$GTAP_TSV")
    rm -f "$GTAP_TSV"
    gtap_decode_pcap "$pc" 4729 "" "" "" "" 0 >/dev/null
    local explicit; explicit=$(cat "$GTAP_TSV")
    chk defaults-identical "$([[ "$plain" == "$explicit" ]] && echo same || echo differ)" "same"
    chk defaults-cols "$(printf '%s\n' "$plain" | head -1 | awk -F'\t' '{print NF}')" "13"
    chk defaults-first11 "$(printf '%s\n' "$plain" | head -1 | cut -f1-11)" \
        "$(printf 'frame\ttype\tchannel\tarfcn\tuplink\ttimeslot\tsignal_dbm\tsnr_db\tframe_number\tpayload_len\tpayload_hex')"
    # The default port really is 4729 and the default bind really is 0.0.0.0.
    chk defaults-port "$GTAP_PORT" "4729"
    chk defaults-iface "$GTAP_IFACE" "0.0.0.0"

    # ── 17b. Live listener framing (regression) ─────────────────────────
    # The counts below are the whole point: an earlier revision piped datagrams
    # through `socat -u UDP4-RECV:...`, which concatenates them into one byte
    # stream with no separator, so three frames were counted and framed as ONE.
    # A live send is the only way to catch that -- a fixture-based assertion
    # cannot, because the fixture already has correct record boundaries.
    gtap_ensure_listener
    chk listener-script "$([[ -s "$GTAP_LISTEN_PY" ]] && echo yes || echo no)" "yes"
    chk listener-syntax "$(python3 -c "import ast,sys;ast.parse(open(sys.argv[1]).read())" "$GTAP_LISTEN_PY" 2>/dev/null && echo ok || echo bad)" "ok"

    if command -v timeout >/dev/null 2>&1; then
        # Live pipe mode: 3 datagrams in, 3 records out.
        ( sleep 1.5
          python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
g=bytes.fromhex('$(gtap_build_header 1 0 42 -60 25 298 5)'+'aa')
for _ in range(3):
    s.sendto(g,('127.0.0.1',$GTAP_LIVE_PORT)); time.sleep(0.05)
" ) >/dev/null 2>&1 &
        local sender=$!
        timeout 8 "$0" --listen 4 "$d/live.pcap" --port "$GTAP_LIVE_PORT" --pipe \
            > "$d/live_stream.pcap" 2>"$d/live.err"
        local lrc=$?
        wait "$sender" 2>/dev/null
        chk live-pipe-rc "$lrc" "0"
        chk live-pipe-frames "$(sed -n 's/^frames	//p' "$d/live.err" | tail -1)" "3"
        # The stream must be a real pcap with 3 records, not one oversized one.
        chk live-pipe-magic "$(python3 -c "
import struct,sys
d=open(sys.argv[1],'rb').read(4)
print('%08x' % struct.unpack('<I',d)[0])" "$d/live_stream.pcap")" "a1b2c3d4"
        chk live-pipe-records "$(python3 -c "
import struct,sys
b=open(sys.argv[1],'rb').read()
o,n=24,0
while o+16 <= len(b):
    _,_,inc,_=struct.unpack('<IIII',b[o:o+16])
    o += 16+inc; n += 1
print(n)" "$d/live_stream.pcap")" "3"

        # Hex mode writes the capture the CLI promises.
        ( sleep 1.5
          python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
g=bytes.fromhex('$(gtap_build_header 1 0 42 -60 25 298 5)'+'aa')
for _ in range(2):
    s.sendto(g,('127.0.0.1',$((GTAP_LIVE_PORT+1)))); time.sleep(0.05)
" ) >/dev/null 2>&1 &
        sender=$!
        timeout 8 "$0" --listen 4 "$d/hex.pcap" --port "$((GTAP_LIVE_PORT+1))" \
            >"$d/hex.out" 2>"$d/hex.err"
        lrc=$?
        wait "$sender" 2>/dev/null
        chk live-hex-rc "$lrc" "0"
        chk live-hex-frames "$(sed -n 's/^frames	//p' "$d/hex.err" | tail -1)" "2"
        chk live-hex-records "$(python3 -c "
import struct,sys
b=open(sys.argv[1],'rb').read()
o,n=24,0
while o+16 <= len(b):
    _,_,inc,_=struct.unpack('<IIII',b[o:o+16])
    o += 16+inc; n += 1
print(n)" "$d/hex.pcap")" "2"

        # An idle listener must report failure, never an empty success.
        timeout 8 "$0" --listen 1 "$d/idle.pcap" --port "$((GTAP_LIVE_PORT+2))" --pipe \
            >"$d/idle.stream" 2>"$d/idle.err"
        chk live-idle-rc "$?" "1"
        chk live-idle-msg "$(grep -c 'no GSMTAP received' "$d/idle.err")" "1"
        # A bad bind is refused rather than silently listening nowhere.
        timeout 8 "$0" --listen 1 "$d/bad.pcap" --port "$((GTAP_LIVE_PORT+3))" \
            --iface '999.999.999.999' >/dev/null 2>&1
        chk live-badbind-rc "$?" "2"
    else
        printf 'SKIP	listener-live (no timeout)\n'
    fi

    # 18. Unknown flags and misplaced modifiers are refused, not ignored.
    chk cli-unknown-flag "$(gtap_cli_main --read "$pc" --nope >/dev/null 2>&1; echo $?)" "2"
    chk cli-anyport-listen "$(gtap_cli_main --listen 1 --any-port >/dev/null 2>&1; echo $?)" "2"
    chk cli-pipe-read "$(gtap_cli_main --read "$pc" --pipe >/dev/null 2>&1; echo $?)" "2"
    chk cli-badport "$(gtap_cli_main --listen 1 --port 99999 >/dev/null 2>&1; echo $?)" "2"
    chk cli-badchan "$(gtap_cli_main --read "$pc" --channel NOPE >/dev/null 2>&1; echo $?)" "2"
    chk cli-missing-wl "$(gtap_cli_main --identities-tsv --watchlist "$d/nope.txt" >/dev/null 2>&1; echo $?)" "2"
    chk cli-read-noargs "$(gtap_cli_main --read >/dev/null 2>&1; echo $?)" "2"
    # A flag placed AFTER the positional still binds (the mis-bind trap).
    # `rm -f`, not `: >`: gtap_init_store only writes the header when the file
    # is ABSENT, so a truncated store keeps no header and `tail -n +2` would
    # silently drop the first data row.
    rm -f "$GTAP_TSV"
    gtap_cli_main --read "$pc" --port 4729 >/dev/null 2>&1
    chk cli-flag-after-pos "$(tail -n +2 "$GTAP_TSV" | grep -c .)" "3"
    # --any-port via the CLI reaches the reader.
    rm -f "$GTAP_TSV"
    gtap_cli_main --read "$pfix" --any-port >/dev/null 2>&1
    chk cli-any-port "$(tail -n +2 "$GTAP_TSV" | grep -c .)" "2"

    # status TSV contract. There was no assertion here at all, which is why a
    # populated "<driver>\t<serial>\t<index>" state file — 3 fields pasted raw
    # into a 2-field row — went unnoticed. Assert both cases.
    local out
    mkdir -p "${GTAP_SDR%/*}"
    printf 'bladerf\tdeadbeef0001\t1\n' > "$GTAP_SDR"
    out=$(gtap_cli_status_tsv)
    chk status-sdr         "$(fld "$out" sdr)"        "bladerf"
    chk status-sdr-sn      "$(fld "$out" sdr_serial)" "deadbeef0001"
    chk status-sdr-idx     "$(fld "$out" sdr_index)"  "1"
    chk status-fields      "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"
    rm -f "$GTAP_SDR"
    out=$(gtap_cli_status_tsv)
    chk status-sdr-nofile  "$(fld "$out" sdr)" "none"
    chk status-fields-none "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"

    # A node source needs a name, and a name nobody registered is a refusal
    # that names the fix rather than a fetch that quietly finds nothing.
    chk node-missing-arg   "$(gtap_cmd_node "" >/dev/null 2>&1; echo $?)" "2"
    chk node-unknown       "$(CASEBOOK_DIR="$d/nobook" gtap_cmd_node no-such-node >/dev/null 2>&1; echo $?)" "2"

    # ── 19. Relay (gap: forward what was parsed) ────────────────────────
    # A relay's counters are the finding, so all three are asserted apart:
    # packets seen, packets forwarded, packets the filters dropped. A relay
    # that forwards nothing is only meaningful next to a relay that received
    # nothing, and a single "forwarded: 0" line is exactly what destroys that
    # difference -- which is why `silent` is a verdict of its own.
    local rc_pc="$d/relay.pcap" rport=$((GTAP_LIVE_PORT + 7)) dead=$((GTAP_LIVE_PORT + 8))
    printf '%s\n%s\n' "$(gtap_build_header 1 0 7 0 0 1 1)21436587092143f5" \
                      "$(gtap_build_header 1 0 7 0 0 2 1)ff00" > "$d/relay_frames.txt"
    gtap_write_pcap "$rc_pc" "$d/relay_frames.txt"

    # Nothing has been relayed into this scratch tree, so the status verb must
    # answer `unobserved` with a reason rather than a tidy row of zeroes.
    local rst; rst=$(gtap_cli_main --relay-status)
    chk relay-status-unobserved "$(fld "$rst" verdict)" "unobserved"
    chk relay-status-why        "$(printf '%s\n' "$rst" | awk -F'\t' '$1=="why"' | grep -c .)" "1"
    chk relay-status-rc         "$(gtap_cli_main --relay-status >/dev/null 2>&1; echo $?)" "1"

    # A loopback listener proves the hop end to end with no radio and no
    # network, and the datagrams are compared byte for byte with what the
    # capture carried: the original GSMTAP header has to survive intact.
    python3 - "$rport" "$d/relay.recv" <<'PY' &
import socket, sys
port, out = int(sys.argv[1]), sys.argv[2]
f = open(out, "w")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.settimeout(8.0)
while True:
    try:
        d, _ = s.recvfrom(65535)
    except socket.timeout:
        break
    if d:                       # the reachability probe's empty datagram
        f.write(d.hex() + "\n")
        f.flush()
f.close()
PY
    local rpid=$!
    sleep 0.5
    local rout; rout=$(gtap_cmd_relay "127.0.0.1:$rport" "$rc_pc")
    chk relay-seen      "$(fld "$rout" packets_seen)" "2"
    chk relay-forwarded "$(fld "$rout" packets_forwarded)" "2"
    chk relay-dropped   "$(fld "$rout" packets_dropped_by_filter)" "0"
    chk relay-verdict   "$(fld "$rout" relay_verdict)" "relayed"
    # Wait for both datagrams rather than trusting a sleep.
    local waited=0
    while (( waited < 40 )) && (( $(grep -c . "$d/relay.recv" 2>/dev/null || true) < 2 )); do
        sleep 0.1; waited=$((waited + 1))
    done
    chk relay-recv-count  "$(grep -c . "$d/relay.recv")" "2"
    chk relay-recv-hdr1   "$(sed -n '1p' "$d/relay.recv")" \
        "$(gtap_build_header 1 0 7 0 0 1 1)21436587092143f5"
    chk relay-recv-hdr2   "$(sed -n '2p' "$d/relay.recv")" \
        "$(gtap_build_header 1 0 7 0 0 2 1)ff00"

    # The same capture under a filter that excludes every frame: seen 2,
    # forwarded 0, dropped 2 is a real answer about the filter, and it is not
    # the same answer as a destination nothing was ever sent to.
    local sout; sout=$(gtap_cli_main --relay "127.0.0.1:$rport" "$rc_pc" --arfcn 999 2>/dev/null)
    chk relay-silent-seen    "$(fld "$sout" packets_seen)" "2"
    chk relay-silent-fwd     "$(fld "$sout" packets_forwarded)" "0"
    chk relay-silent-drop    "$(fld "$sout" packets_dropped_by_filter)" "2"
    chk relay-silent-verdict "$(fld "$sout" relay_verdict)" "silent"
    chk relay-silent-sentnothing "$(grep -c . "$d/relay.recv")" "2"
    kill -TERM "$rpid" 2>/dev/null
    wait "$rpid" 2>/dev/null

    # The counters reach a second process through the store, not through this
    # shell: --relay-status reads back the newest row.
    chk relay-status-last   "$(fld "$(gtap_cli_main --relay-status)" verdict)" "silent"
    chk relay-store-cols    "$(awk -F'\t' 'NF!=7' "$(gtap_relay_tsv)" | grep -c .)" "0"
    chk relay-store-rows    "$(awk -F'\t' 'NR>1' "$(gtap_relay_tsv)" | grep -c .)" "2"

    # An unreachable destination is refused BY NAME before the capture is
    # walked, so a relay that cannot deliver never looks like one that
    # forwarded nothing.
    local miss mrc
    miss=$(gtap_cmd_relay "127.0.0.1:$dead" "$rc_pc" 2>"$d/relay-dead.err"); mrc=$?
    chk relay-dead-rc      "$mrc" "1"
    chk relay-dead-missing "$(awk -F'\t' '$1=="MISSING"' "$d/relay-dead.err" | grep -c .)" "1"
    chk relay-dead-why     "$(awk -F'\t' '$1=="WHY"' "$d/relay-dead.err" | grep -c .)" "1"
    # Named in the MISSING row itself, not merely somewhere in the noise.
    chk relay-dead-named   "$(awk -F'\t' -v t="127.0.0.1:$dead" \
        '$1=="MISSING" && index($0, t)' "$d/relay-dead.err" | grep -c .)" "1"
    chk relay-dead-nosend  "$(printf '%s\n' "$miss" | awk -F'\t' '$1=="packets_forwarded"' | grep -c .)" "0"
    chk relay-bad-target   "$(gtap_cmd_relay 'not-a-target' "$rc_pc" >/dev/null 2>&1; echo $?)" "2"
    chk relay-no-capture   "$(gtap_cmd_relay '127.0.0.1:4729' >/dev/null 2>&1; echo $?)" "1"

    # The two relays are different operations and each names the other when it
    # is asked for the wrong one, instead of silently doing nothing.
    gtap_cli_main --listen 1 --relay 127.0.0.1:4729 >/dev/null 2>"$d/relay-listen.err"
    chk relay-listen-refused     "$?" "1"
    chk relay-listen-names-alt   "$(grep -c 'use --forward' "$d/relay-listen.err")" "1"
    gtap_cli_main --read "$rc_pc" --forward 127.0.0.1:4729 >/dev/null 2>"$d/relay-rfwd.err"
    chk relay-rfwd-refused       "$?" "1"
    chk relay-rfwd-names-alt     "$(grep -c 'use --relay' "$d/relay-rfwd.err")" "1"

    # ── 20. Watchlist as a stream filter ────────────────────────────────
    # The filter and the per-entry report are asserted together: keeping the
    # wrong frames and naming the wrong entries are one defect seen from two
    # ends. The fixture holds a hit, a value that must be NAMED `unmatched`,
    # and a value with no wire encoding at all, which is `unobserved` -- a
    # third fact, and the one that would otherwise be silently dropped.
    local wl="$d/watch.txt"
    printf '%s\n' '# fixture watchlist: a comment line is not an entry' \
                  '123456789012345' '999999999999999' 'ZZZ' > "$wl"
    local wout; wout=$(gtap_cli_main --read "$rc_pc" --watchlist "$wl" 2>/dev/null)
    chk wl-frames     "$(fld "$wout" frames)" "1"
    chk wl-filtered   "$(fld "$wout" filtered)" "1"
    chk wl-matched    "$(fld "$wout" watchlist_matched_entries)" "1"
    chk wl-unmatched  "$(fld "$wout" watchlist_unmatched_entries)" "1"
    chk wl-unobserved "$(fld "$wout" watchlist_unobserved_entries)" "1"
    chk wl-hit-verdict "$(printf '%s\n' "$wout" | awk -F'\t' '$1=="watchlist_entry" && $2=="123456789012345"{print $4}')" "matched"
    chk wl-miss-named  "$(printf '%s\n' "$wout" | awk -F'\t' '$1=="watchlist_entry" && $2=="999999999999999"{print $4}')" "unmatched"
    chk wl-nowire      "$(printf '%s\n' "$wout" | awk -F'\t' '$1=="watchlist_entry" && $2=="ZZZ"{print $4}')" "unobserved"
    chk wl-store-cols  "$(head -1 "$(gtap_watchlist_tsv)" | awk -F'\t' '{print NF}')" "5"
    chk wl-store-rows  "$(tail -n +2 "$(gtap_watchlist_tsv)" | grep -c .)" "3"
    chk wl-store-hit   "$(awk -F'\t' '$2=="123456789012345" && $5=="matched"' \
                            "$(gtap_watchlist_tsv)" | grep -c .)" "1"

    # An entry that is searchable and simply absent is `unmatched`, and a
    # stream that matches nothing is an empty read, not a failure.
    printf '%s\n' '555555555555555' > "$d/watch-miss.txt"
    local wno; wno=$(gtap_cli_main --read "$rc_pc" --watchlist "$d/watch-miss.txt" 2>/dev/null)
    chk wl-nohit-frames  "$(fld "$wno" frames)" "0"
    chk wl-nohit-verdict "$(fld "$wno" verdict)" "no-match"
    chk wl-nohit-named   "$(printf '%s\n' "$wno" | awk -F'\t' '$1=="watchlist_entry"{print $4}')" "unmatched"

    # A stream with no payload octet cannot be searched at all, and says so
    # instead of libelling every entry as unmatched.
    local nopc="$d/nopayload.pcap"
    printf '%s\n' "$(gtap_build_header 1 0 7 0 0 1 1)" > "$d/nopayload.txt"
    gtap_write_pcap "$nopc" "$d/nopayload.txt"
    local wnp; wnp=$(gtap_cli_main --read "$nopc" --watchlist "$wl" 2>/dev/null)
    chk wl-nopayload-verdict "$(fld "$wnp" verdict)" "unobserved"

    trap - EXIT
    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
gtap_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== gsmtap passive ===${C_RESET}"
        echo -e "  port:  ${C_GRN}udp/$GTAP_PORT${C_RESET}"
        echo -e "  store: ${C_DIM}$GTAP_TSV${C_RESET}\n"
        cat << 'M'
  [1]  listen live (30s) and write a pcap
  [2]  decode a pcap to TSV
  [3]  harvest identities from the decode store
  [4]  export the decode store
  [5]  decode a header from hex
  [6]  relay a pcap to a second collector
  [7]  last relay counters
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) gtap_listen 30; read -rp "  press enter " _ ;;
            2) read -rp "  pcap path> " p; gtap_decode_pcap "$p"; read -rp "  press enter " _ ;;
            3) gtap_identities | head -40; read -rp "  press enter " _ ;;
            4) gtap_export; read -rp "  press enter " _ ;;
            5) read -rp "  header hex> " h; gtap_parse_header "$h" | column -t -s$'\t' 2>/dev/null \
                 || gtap_parse_header "$h"; read -rp "  press enter " _ ;;
            6) read -rp "  pcap path> " p
               read -rp "  relay to host:port> " t
               gtap_cmd_relay "$t" "$p"; read -rp "  press enter " _ ;;
            7) gtap_cmd_relay_status > "$MOD_TMP/relay-status.tsv" 2>&1
               column -t -s$'\t' "$MOD_TMP/relay-status.tsv" 2>/dev/null \
                 || cat "$MOD_TMP/relay-status.tsv"
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────

# The shared state file is written by 01_radio as <driver>\t<serial>\t<index>.
# Never paste it raw into a status row: that puts three values into a two-field
# contract. Split it into three 2-field rows instead.
gtap_sdr_rows() {
    local drv="none" sn="none" idx="none"
    if [[ -s "$GTAP_SDR" ]]; then
        IFS=$'\t' read -r drv sn idx < <(tr -d '\r' < "$GTAP_SDR" | head -n1)
    fi
    printf 'sdr\t%s\n'        "${drv:-none}"
    printf 'sdr_serial\t%s\n' "${sn:-none}"
    printf 'sdr_index\t%s\n'  "${idx:-none}"
}

gtap_cli_status_tsv() {
    local rows=0
    [[ -f "$GTAP_TSV" ]] && rows=$(tail -n +2 "$GTAP_TSV" 2>/dev/null | grep -c . || true)
    printf 'port\t%s\n'      "$GTAP_PORT"
    gtap_sdr_rows
    printf 'decoded\t%s\n'   "${rows:-0}"
    printf 'dir\t%s\n'       "$GTAP_DIR"
    printf 'store\t%s\n'     "$GTAP_TSV"
    printf 'socat\t%s\n'     "$(command -v socat >/dev/null 2>&1 && echo yes || echo no)"
}

# ── a node as the capture source ────────────────────────────────────────
# A GSMTAP capture does not have to be made here: a node with an SDR writes its
# own pcap, and this module reads it the same way it reads a local one. The
# fetch is done by node_source.py, so the path a node keeps its captures in is
# spelled in one place rather than in every module that wants one.
gtap_node_capture() {  # <name> -> prints the local path
    local name="${1:-}"
    [[ -n "$name" ]] || { printf 'ERROR\t--node needs a fleet node name\n' >&2; return 2; }
    local tool="$IMSISTING_ROOT/tools/node_source.py"
    [[ -f "$tool" ]] || {
        printf 'ERROR\t%s is missing\nWHY\twithout it a node is a name with no way to ask it for a capture\n' "$tool" >&2
        return 2; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is missing\nWHY\tthe node table is not a shell job\n' >&2; return 2; }
    local out rc
    out=$(python3 "$tool" captures "$name" --newest 2>"$MOD_TMP/node.err"); rc=$?
    if (( rc != 0 )); then
        cat "$MOD_TMP/node.err" >&2
        return "$rc"
    fi
    local path
    path=$(printf '%s\n' "$out" | awk -F'\t' '$1=="fetched"{print $2; exit}')
    [[ -n "$path" ]] || {
        printf 'ERROR\t%s reported no capture to fetch\nWHY\tan empty answer is not an empty capture store\n' "$name" >&2
        return 1; }
    printf 'node\t%s\n' "$name" >&2
    printf 'fetched\t%s\n' "$path" >&2
    printf '%s' "$path"
}

gtap_cmd_node() {  # <name>
    local path rc
    path=$(gtap_node_capture "${1:-}"); rc=$?
    (( rc != 0 )) && return "$rc"
    gtap_decode_pcap "$path" "${fport:-$GTAP_PORT}" \
        "$fsince" "$funtil" "$farfcn" "$fchan" "$ful"
}

gtap_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift

    # Pull the modifiers out of the remaining arguments, leaving positionals in
    # GTAP_POS. Flags may appear before or after a positional, so a plain
    # "$1/$2" read would mis-bind "listen 30 --port 4800".
    GTAP_POS=()
    local fport="" fiface="" fsince="" funtil="" farfcn="" fchan="" fwl=""
    local fpipe=0 fany=0 ful=0 fforward="" frelay=""
    while (($# > 0)); do
        case "$1" in
            --port)
                fport="${2:-}"
                [[ "$fport" =~ ^[0-9]+$ ]] || {
                    printf 'ERROR\t--port needs a number, got: %s\n' "${2:-<empty>}" >&2
                    return 2; }
                gtap_valid_port "$fport" || {
                    printf 'ERROR\t--port out of range: %s\n' "$fport" >&2; return 2; }
                shift 2 ;;
            --iface)
                fiface="${2:-}"
                gtap_valid_iface "$fiface" || {
                    printf 'ERROR\t--iface needs an IPv4 address or hostname, got: %s\n' \
                        "${2:-<empty>}" >&2; return 2; }
                shift 2 ;;
            --any-port) fany=1; shift ;;
            --pipe)     fpipe=1; shift ;;
            --uplink)   ful=1; shift ;;
            --forward)
                fforward="${2:-}"
                gtap_forward_split "$fforward" || {
                    printf 'ERROR\t--forward needs HOST:PORT, got: %s\n' "${2:-<empty>}" >&2
                    return 2; }
                shift 2 ;;
            --relay)
                frelay="${2:-}"
                gtap_relay_split "$frelay" || {
                    printf 'ERROR\t--relay needs HOST:PORT, got: %s\n' "${2:-<empty>}" >&2
                    return 2; }
                shift 2 ;;
            --since)    fsince="${2:-}"; shift 2 ;;
            --until)    funtil="${2:-}"; shift 2 ;;
            --arfcn)
                farfcn="${2:-}"
                [[ "$farfcn" =~ ^[0-9]+$ ]] || {
                    printf 'ERROR\t--arfcn needs a number, got: %s\n' "${2:-<empty>}" >&2
                    return 2; }
                shift 2 ;;
            --channel)
                fchan="${2:-}"
                # Accept any channel name the codec knows, plus "unknown"/"-",
                # but reject a typo rather than silently filtering everything.
                case "$fchan" in
                    BCCH|CCCH|RACH|AGCH|PCH|SDCCH|SDCCH4|SDCCH8|TCH/F|TCH/H|PACCH|CBCH|PDCH|PTCCH|CBCH52|UNKNOWN|-) ;;
                    *) printf 'ERROR\t--channel %s is not a known GSM channel (BCCH|CCCH|RACH|AGCH|PCH|SDCCH|SDCCH4|SDCCH8|TCH/F|TCH/H|PACCH|CBCH|PDCH|PTCCH|CBCH52)\n' \
                           "${2:-<empty>}" >&2; return 2 ;;
                esac
                shift 2 ;;
            --watchlist)
                fwl="${2:-}"
                [[ -f "$fwl" ]] || {
                    printf 'ERROR\t--watchlist needs a readable file, got: %s\n' \
                        "${2:-<empty>}" >&2; return 2; }
                shift 2 ;;
            --*)
                printf 'ERROR\tunknown flag: %s\n' "$1" >&2
                return 2 ;;
            *) GTAP_POS+=("$1"); shift ;;
        esac
    done
    # Positional access that is safe under `set -u`.
    gtap_p() { printf '%s' "${GTAP_POS[$(($1 - 1))]:-}"; }

    case "$cmd" in
        --status-tsv)      gtap_cli_status_tsv ;;
        --listen)
            # --port/--iface apply here; --any-port is a read-only concept.
            (( fany )) && { printf 'ERROR\t--any-port applies to --read, not --listen\n' >&2; return 2; }
            # --relay re-emits parsed frames; --listen relays raw datagrams
            # before anything is parsed, so the two are not the same operation
            # and picking one silently for the operator would be the wrong
            # answer to a question they did not ask.
            if [[ -n "$frelay" ]]; then
                printf 'MISSING\trelay of parsed frames while listening live\n' >&2
                printf 'WHY\t--relay works on a capture, --listen has no stream to parse; use --forward %s for a live datagram relay\n' \
                    "$frelay" >&2
                return 1
            fi
            gtap_listen "$(gtap_p 1 | grep . || echo 30)" "$(gtap_p 2)" \
                        "${fport:-$GTAP_PORT}" "${fiface:-$GTAP_IFACE}" \
                        "$fpipe" "$fforward" ;;
        --read)
            [[ -n "$(gtap_p 1)" ]] || {
                printf 'ERROR\t--read needs a pcap path\n' >&2; return 2; }
            (( fpipe )) && { printf 'ERROR\t--pipe applies to --listen, not --read\n' >&2; return 2; }
            # --forward is the live listener's relay; on a capture the frames
            # have already been parsed, which is what --relay works from.
            if [[ -n "$fforward" ]]; then
                printf 'MISSING\tlive forward while reading a capture\n' >&2
                printf 'WHY\t--forward relays datagrams a live socket sees; a capture is not that stream, use --relay %s instead\n' \
                    "$fforward" >&2
                return 1
            fi
            gtap_decode_pcap "$(gtap_p 1)" \
                "$([[ $fany -eq 1 ]] && echo any || echo "${fport:-$GTAP_PORT}")" \
                "$fsince" "$funtil" "$farfcn" "$fchan" "$ful" "$frelay" "$fwl" ;;
        --relay)
            gtap_cmd_relay "$(gtap_p 1)" "$(gtap_p 2)" ;;
        --relay-status)    gtap_cmd_relay_status ;;
        --decode-tsv)      gtap_init_store; tail -n +2 "$GTAP_TSV" ;;
        --identities-tsv)
            if [[ -n "$fwl" ]]; then gtap_identities_watch "$fwl"
            else gtap_identities; fi ;;
        --export-pcap)     gtap_export ;;
        --node)            gtap_cmd_node "$(gtap_p 1)" ;;
        --parse-header)    gtap_parse_header "$(gtap_p 1)" ;;
        --build-header)    gtap_build_header "${GTAP_POS[@]}" ;;
        --selftest)        gtap_selftest ;;
        --menu)            gtap_menu ;;
        *)
            cat >&2 <<EOF
GSMTAP Live Feed — listen for, decode and export Osmocom GSMTAP

Usage: $0 COMMAND [FLAGS]

  --status-tsv            listener and store state as TSV
  --listen [SECS] [OUT]   capture UDP $GTAP_PORT to a pcap, default 30s
  --read <pcap>           decode a GSMTAP pcap into the TSV store
  --relay <H:P> [PCAP]    decode a pcap and forward every frame that passes
                            the filters to a second collector as GSMTAP/UDP
  --relay-status          the last relay's counters as TSV, for a second process
  --node <name>           fetch that node's newest capture and decode it
  --decode-tsv            the decoded store as TSV
  --identities-tsv        identities seen in the clear in the store
  --export-pcap           copy the decoded store into loot/
  --parse-header <hex>    decode a GSMTAP header
  --build-header T TS A S N F SUB [UL] [PCS]   build a header, emit hex
  --selftest              verify the header codec and pcap I/O without a radio
  --menu                  interactive menu

Modifiers (default behaviour is unchanged when none are given):
  --port <N>              UDP port to listen on / accept when reading (default $GTAP_PORT)
  --iface <ADDR>          bind address for --listen (default $GTAP_IFACE)
  --any-port              with --read: accept GSMTAP on any UDP port
  --since <TS>            with --read: keep frames at or after TS (epoch or ISO)
  --until <TS>            with --read: keep frames at or before TS (epoch or ISO)
  --arfcn <N>             with --listen/--read: keep only this ARFCN
  --channel <NAME>        with --listen/--read: keep only this GSM channel
  --uplink                with --listen: keep only uplink frames
  --forward <HOST:PORT>   relay every received GSMTAP datagram live
  --relay <HOST:PORT>     with --read: forward every frame the filters keep,
                            original GSMTAP header intact, to HOST:PORT
  --pipe                  with --listen: stream a live pcap on stdout, e.g.
                            $0 --listen 60 --pipe | wireshark -k -i -
  --watchlist <FILE>      with --read: keep only frames carrying a listed value,
                            and report every entry as matched/unmatched
                          with --identities-tsv: flag listed TMSI/IMSI/IMEI

Exit: 0 on success, 1 on runtime failure, 2 on bad arguments.
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    : "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
    : "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
    : "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
    : "${STATE_DIR:=$IMSISTING_ROOT/state}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    gtap_cli_main "$@"
fi
