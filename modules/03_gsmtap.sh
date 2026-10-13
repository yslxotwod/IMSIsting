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
# The shared cross-module device/target state.
GTAP_SDR="${TMP_DIR}/sdr_device"

# ── sanitisation ────────────────────────────────────────────────────────
gtap_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

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
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 1; }
    python3 - "$pcap" <<'PY'
import struct, sys
p = sys.argv[1]
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
    if sp != 4729 and dp != 4729:
        continue
    g = fr[o:o+ln-8]
    if len(g) < 16:
        continue
    print("%d\t%s" % (n, g.hex()))
    n += 1
PY
}

# ── listeners ───────────────────────────────────────────────────────────
gtap_listen() {
    local secs="${1:-30}" out="${2:-}"
    [[ -n "$out" ]] || out="$CAPTURES_DIR/gsmtap_$(date +%Y%m%d_%H%M%S).pcap"
    mkdir -p "$(dirname "$out")"

    command -v socat >/dev/null 2>&1 || {
        printf 'ERROR\tno socat — install socat to listen on UDP %d\n' "$GTAP_PORT" >&2
        return 1
    }

    local tmp; tmp=$(mktemp "$MOD_TMP/listen.XXXXXX") || return 1
    info "listening on UDP $GTAP_PORT for ${secs}s..."
    # Stream the raw UDP payloads as hex, one per line.
    timeout "$secs" socat -u "UDP4-RECV:$GTAP_PORT,bind=0.0.0.0" - 2>/dev/null | \
        python3 -c '
import sys
for line in sys.stdin.buffer:
    if line.strip():
        sys.stdout.write(line.strip().hex() + "\n")
' > "$tmp"
    local n; n=$(grep -c . "$tmp" || true)
    if [[ "${n:-0}" -eq 0 ]]; then
        rm -f "$tmp"
        printf 'ERROR\tno GSMTAP received on UDP %d in %ss — is grgsm_livemon (or an eNB/srsue with GSMTAP) running?\n' \
            "$GTAP_PORT" "$secs" >&2
        return 1
    fi
    gtap_write_pcap "$out" "$tmp"
    rm -f "$tmp"
    printf 'OK\t%s\n' "$out"
    printf 'frames\t%s\n' "$n"
}

# ── decode to TSV ───────────────────────────────────────────────────────
gtap_init_store() {
    mkdir -p "$GTAP_DIR"
    [[ -f "$GTAP_TSV" ]] || printf 'frame\ttype\tchannel\tarfcn\tuplink\ttimeslot\tsignal_dbm\tsnr_db\tframe_number\tpayload_len\tpayload_hex\n' > "$GTAP_TSV"
}

gtap_decode_pcap() {
    local pcap="${1:-}"
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 1; }
    gtap_init_store

    local tmp; tmp=$(mktemp "$MOD_TMP/dec.XXXXXX") || return 1
    gtap_read_pcap "$pcap" > "$tmp" || {
        rm -f "$tmp"; printf 'ERROR\tcould not read %s as a GSMTAP capture\n' "$pcap" >&2; return 1; }
    local n; n=$(grep -c . "$tmp" || true)

    if [[ "${n:-0}" -eq 0 ]]; then
        rm -f "$tmp"
        printf 'ERROR\tno GSMTAP frames on UDP %d in %s\n' "$GTAP_PORT" "$pcap" >&2
        return 1
    fi

    local rows=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        gtap_split "$line"
        local fr="${GTAP_F[0]:-}" hex="${GTAP_F[1]:-}"
        local p; p=$(gtap_parse_header "$hex") || continue
        local typ sub arfcn ul ts sig snr fn pl
        typ=$(gtap_field "$p" type);    sub=$(gtap_field "$p" sub_type)
        arfcn=$(gtap_field "$p" arfcn); ul=$(gtap_field "$p" uplink)
        ts=$(gtap_field "$p" timeslot); sig=$(gtap_field "$p" signal_dbm)
        snr=$(gtap_field "$p" snr_db);  fn=$(gtap_field "$p" frame_number)
        pl=$(gtap_field "$p" payload_hex)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$fr" "$(gtap_type_name "$typ")" "$(gtap_channel_of "$sub" "$arfcn" "$typ")" \
            "$arfcn" "$ul" "$ts" "$sig" "$snr" "$fn" \
            "$(( ${#pl} / 2 ))" "$(gtap_sanitize "$pl")" >> "$GTAP_TSV"
        rows=$((rows + 1))
    done < "$tmp"
    rm -f "$tmp"

    printf 'frames\t%s\n' "$rows"
    printf 'store\t%s\n' "$GTAP_TSV"
}

gtap_identities() {
    local pcap="${1:-}"
    gtap_init_store
    [[ -f "$GTAP_TSV" ]] || { printf 'ERROR\tno decode store; run --read first\n' >&2; return 1; }
    local n; n=$(tail -n +2 "$GTAP_TSV" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tdecode store is empty; run --read first\n' >&2; return 1; }

    # Hand the payloads to the per-generation decoder that owns the message
    # format, rather than re-implementing NAS/RR parsing here.
    local lte="$IMSISTING_ROOT/modules/13_lte_attach.sh"
    local gsm="$IMSISTING_ROOT/modules/10_gsm_air.sh"
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
        local out
        out=$("$dec" --identity-exposure "$pl" 2>/dev/null) || continue
        while IFS= read -r r; do
            [[ -z "$r" ]] && continue
            printf '%s\t%s\t%s\t%s\n' "$fr" "$(gtap_sanitize "$(cut -f1 <<<"$r")")" \
                "$(gtap_sanitize "$(cut -f2 <<<"$r")")" "$(basename "$dec")"
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
    chk pcap-f1     "$(printf '%s\n' "$rd" | head -1 | cut -f2)" \
                    "$(gtap_build_header 1 0 7 0 0 0 1)"
    chk pcap-f2     "$(printf '%s\n' "$rd" | sed -n '2p' | cut -f2)" \
                    "$(gtap_build_header 5 0 42 -60 25 298 5)ff00"
    chk pcap-f3     "$(printf '%s\n' "$rd" | sed -n '3p' | cut -f2)" \
                    "$(gtap_build_header 1 0 42 -60 25 298 5)ff00"

    # 10. Decode to the store, and the store's field count.
    local out; out=$(gtap_decode_pcap "$pc")
    chk dec-frames "$(gtap_field "$out" frames)" "3"
    chk store-rows "$(tail -n +2 "$GTAP_TSV" | grep -c .)" "3"
    chk store-cols "$(head -1 "$GTAP_TSV" | awk -F'\t' '{print NF}')" "11"
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

    # 12. Export refuses an empty store.
    : > "$GTAP_TSV"
    chk export-empty-rc "$(gtap_export >/dev/null 2>&1; echo $?)" "1"
    chk read-missing-rc "$(gtap_read_pcap "$d/nope.pcap" >/dev/null 2>&1; echo $?)" "1"

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
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
gtap_cli_status_tsv() {
    local sdr; sdr=$(cat "$GTAP_SDR" 2>/dev/null || echo none)
    local rows=0
    [[ -f "$GTAP_TSV" ]] && rows=$(tail -n +2 "$GTAP_TSV" 2>/dev/null | grep -c . || true)
    printf 'port\t%s\n'      "$GTAP_PORT"
    printf 'sdr\t%s\n'       "$sdr"
    printf 'decoded\t%s\n'   "${rows:-0}"
    printf 'dir\t%s\n'       "$GTAP_DIR"
    printf 'store\t%s\n'     "$GTAP_TSV"
    printf 'socat\t%s\n'     "$(command -v socat >/dev/null 2>&1 && echo yes || echo no)"
}

gtap_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      gtap_cli_status_tsv ;;
        --listen)          gtap_listen "${1:-30}" "${2:-}" ;;
        --read)            gtap_decode_pcap "${1:-}" ;;
        --decode-tsv)      gtap_init_store; tail -n +2 "$GTAP_TSV" ;;
        --identities-tsv)  gtap_identities ;;
        --export-pcap)     gtap_export ;;
        --parse-header)    gtap_parse_header "${1:-}" ;;
        --build-header)    gtap_build_header "$@" ;;
        --sealftest|--selftest) gtap_selftest ;;
        --menu)            gtap_menu ;;
        *)
            cat >&2 <<EOF
GSMTAP Passive — listen for, decode and export Osmocom GSMTAP

Usage: $0 COMMAND
  --status-tsv            listener and store state as TSV
  --listen [SECS] [OUT]   capture UDP $GTAP_PORT to a pcap, default 30s
  --read <pcap>           decode a GSMTAP pcap into the TSV store
  --decode-tsv            the decoded store as TSV
  --identities-tsv        identities seen in the clear in the store
  --export-pcap           copy the decoded store into loot/
  --parse-header <hex>    decode a GSMTAP header
  --build-header T TS A S N F SUB [UL] [PCS]   build a header, emit hex
  --selftest              verify the header codec and pcap I/O without a radio
  --menu                  interactive menu
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
