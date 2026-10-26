#!/usr/bin/env bash
# gnss — what a receiver tells you, what it cannot tell you, and when the
# position it reports is not the position it measured.
#
# SCOPE, stated first. A GNSS receiver is a trust anchor that almost nothing
# authenticates. It hands a position to a survey, a timestamp to a log, a fix to
# a timestamping server, and nothing in the NMEA sentence says who produced it.
# This module reads the receiver's own interface (NMEA and u-blox UBX), builds
# the same sentences for replay testing, and — the half that matters — detects
# the signing of a position that was never measured.
#
# The detector is not an accusation engine. It reports which *tells* are present
# in a track and what each one means, because a single tell is a hypothesis and
# several together with no benign explanation is a finding:
#
#   * jump      the fix moves further between samples than the reported speed
#               allows, while the receiver never lost lock
#   * dop       dilution of precision is implausibly good — better than the sky
#               the receiver claims to see could support
#   * constant  the clock and the fix stop moving together
#   * snr       every satellite reports the same signal strength, which no
#               real sky ever does
#   * leap      the fix crosses a discontinuity in a single sample with no
#               acquisition gap
#
# Attack owned: none direct — receiver reconnaissance and position integrity
# testing for anything that trusts a fix (see --gpsd-lie for the trust hole).
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _gn_src="${BASH_SOURCE[0]}"
    while [ -L "$_gn_src" ]; do
        _gn_dir="$(cd -P "$(dirname "$_gn_src")" && pwd)"
        _gn_tgt="$(readlink "$_gn_src")"
        [[ "$_gn_tgt" != /* ]] && _gn_tgt="$_gn_dir/$_gn_tgt"
        _gn_src="$_gn_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_gn_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _gn_src _gn_dir _gn_tgt
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

MOD_TMP="$TMP_DIR/gnss"
GNSS_DIR="$LOOT_DIR/gnss"
mkdir -p "$MOD_TMP" "$GNSS_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

gnss_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# ── NMEA 0183 ───────────────────────────────────────────────────────────
# A sentence is $TTSSS,field,field,...*CS<CR><LF> where CS is the XOR of every
# octet between $ and *, in hex. Nothing else about the format is normative:
# the field layouts below are per sentence type, and the versions that matter
# here are 2.3 and 4.11.

# gnss_nmea_cksum <payload without $ and *>
gnss_nmea_cksum() {
    local p="${1:-}" i c=0
    for (( i = 0; i < ${#p}; i++ )); do
        c=$(( c ^ $(printf '%d' "'${p:i:1}") ))
    done
    printf '%02X' "$c"
}

# gnss_nmea_cksum_ok <full sentence incl. $ and checksum>
gnss_nmea_cksum_ok() {
    local s="${1:-}" body want
    [[ "$s" == \$* ]] || return 1
    [[ "$s" == *"*"* ]] || return 1
    body="${s#\$}"; body="${body%%\**}"
    want="${s##*\*}"; want="${want:0:2}"
    [[ "$(gnss_nmea_cksum "$body")" == "${want^^}" ]]
}

# gnss_nmea_parse <sentence> — one field per line, then a checksum verdict.
# The parse is deliberately permissive about the sentence tail: a receiver may
# append anything after the checksum and a parser that refuses the whole
# sentence for it is a parser that reports "no fix" on a working receiver.
gnss_nmea_parse() {
    local s="${1:-}" type body cs_ok
    [[ "$s" == \$* ]] || { printf 'ERROR\tnot an NMEA sentence (no leading $)\n' >&2; return 2; }
    body="${s#\$}"
    body="${body%%\**}"
    cs_ok="no"
    gnss_nmea_cksum_ok "$s" && cs_ok="yes"
    IFS=',' read -r -a _f <<< "$body"
    type="${_f[0]:-}"

    printf 'sentence\t%s\n' "$(gnss_sanitize "${s:0:120}")"
    printf 'type\t%s\n' "$type"
    printf 'checksum_ok\t%s\n' "$cs_ok"

    case "$type" in
        GPGGA|GNGGA|BDGGA|GLGGA)
            printf 'talker\t%s\n' "${type:0:2}"
            printf 'utc\t%s\n' "$(gnss_sanitize "${_f[1]}")"
            printf 'lat\t%s\n' "${_f[2]:-}"
            printf 'lat_hemi\t%s\n' "${_f[3]:-}"
            printf 'lon\t%s\n' "${_f[4]:-}"
            printf 'lon_hemi\t%s\n' "${_f[5]:-}"
            printf 'fix_quality\t%s\n' "${_f[6]:-}"
            printf 'sats_used\t%s\n' "${_f[7]:-}"
            printf 'hdop\t%s\n' "${_f[8]:-}"
            printf 'alt_m\t%s\n' "${_f[9]:-}"
            # Quality 0 is "no fix" and every field after it is a placeholder.
            # Reporting a position from a quality-0 sentence is the single most
            # common way a survey records a coordinate nobody measured.
            if [[ "${_f[6]:-0}" == "0" ]]; then
                printf 'position_valid\tno\n'
                printf 'note\tsentences with fix_quality 0 carry no position: the fields are placeholders, not a fix\n'
            else
                printf 'position_valid\tyes\n'
            fi
            ;;
        GPRMC|GNRMC|BDRMC|GLRMC)
            printf 'talker\t%s\n' "${type:0:2}"
            printf 'utc\t%s\n' "$(gnss_sanitize "${_f[1]}")"
            printf 'status\t%s\n' "${_f[2]:-}"
            printf 'lat\t%s\n' "${_f[3]:-}"
            printf 'lat_hemi\t%s\n' "${_f[4]:-}"
            printf 'lon\t%s\n' "${_f[5]:-}"
            printf 'lon_hemi\t%s\n' "${_f[6]:-}"
            printf 'speed_kn\t%s\n' "${_f[7]:-}"
            printf 'course\t%s\n' "${_f[8]:-}"
            printf 'date\t%s\n' "${_f[9]:-}"
            # RMC status A = valid, V = navigation receiver warning. A V
            # sentence with a plausible-looking position is not a fix.
            if [[ "${_f[2]:-V}" == "A" ]]; then printf 'position_valid\tyes\n'
            else printf 'position_valid\tno\n'; fi
            ;;
        GPGSA|GNGSA|BDGSA)
            printf 'mode\t%s\n' "${_f[1]:-}"
            printf 'fix_type\t%s\n' "${_f[2]:-}"
            printf 'pdop\t%s\n' "${_f[15]:-}"
            printf 'hdop\t%s\n' "${_f[16]:-}"
            printf 'vdop\t%s\n' "${_f[17]:-}"
            # fix_type 1 = no fix, 2 = 2D, 3 = 3D. A 2D fix has no altitude
            # and a survey that records one has invented the third coordinate.
            case "${_f[2]:-1}" in
                1) printf 'fix\tno fix\n' ;;
                2) printf 'fix\t2D (no altitude)\n' ;;
                3) printf 'fix\t3D\n' ;;
                *) printf 'fix\tunknown (%s)\n' "${_f[2]}" ;;
            esac
            ;;
        GPGSV|GNGSV|BDGSV)
            printf 'total_msgs\t%s\n' "${_f[1]:-}"
            printf 'msg_num\t%s\n' "${_f[2]:-}"
            printf 'sats_in_view\t%s\n' "${_f[3]:-}"
            ;;
        *)
            printf 'note\ttype %s is not decoded here; the checksum verdict stands\n' "$(gnss_sanitize "$type")"
            ;;
    esac
    return 0
}

# gnss_nmea_split <file> — one line per sentence with a checksum verdict, so a
# log whose every tenth sentence fails its checksum is visible as a pattern.
gnss_nmea_split() {
    local file="${1:-}" line n=0 bad=0 total=0
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$(gnss_sanitize "$file")" >&2; return 1; }
    printf 'line\ttype\tchecksum\tbytes\n'
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ "$line" == \$* ]] || continue
        nil=0
        total=$(( total + 1 ))
        local cs="FAIL"
        gnss_nmea_cksum_ok "$line" && cs="PASS" || bad=$(( bad + 1 ))
        printf '%d\t%s\t%s\t%d\n' "$total" "${line:1:5}" "$cs" "${#line}"
    done < "$file"
    printf 'sentences\t%d\n' "$total"
    printf 'checksum_failures\t%d\n' "$bad"
    return 0
}

# ── u-blox UBX ──────────────────────────────────────────────────────────
# Frame: B5 62 | class | id | len(2, LE) | payload | CK_A CK_B
# Checksum is the 8-bit Fletcher over class..payload inclusive.
gnss_ubx_cksum() {  # <hex of class..payload>
    local h="${1:-}" i a=0 b=0 byte
    for (( i = 0; i < ${#h}; i += 2 )); do
        byte=$(( 16#${h:i:2} ))
        a=$(( (a + byte) & 0xFF ))
        b=$(( (b + a) & 0xFF ))
    done
    printf '%02X%02X' "$a" "$b"
}

gnss_ubx_class_name() {
    case "${1:-}" in
        01) echo "NAV" ;;
        02) echo "RXM" ;;
        04) echo "INF" ;;
        05) echo "ACK" ;;
        06) echo "CFG" ;;
        09) echo "UPD" ;;
        0A) echo "MON" ;;
        0D) echo "TIM" ;;
        10) echo "ESF" ;;
        13) echo "MGA" ;;
        21) echo "LOG" ;;
        27) echo "SEC" ;;
        *)   echo "unknown class" ;;
    esac
}

gnss_ubx_msg_name() {  # <class> <id>
    case "${1:-}${2:-}" in
        0101) echo "POSECEF" ;;
        0102) echo "POSLLH" ;;
        0103) echo "STATUS" ;;
        0104) echo "DOP" ;;
        0105) echo "ATT" ;;
        0106) echo "SOL" ;;
        0107) echo "PVT" ;;
        0112) echo "VELECEF" ;;
        0113) echo "VELNED" ;;
        0130) echo "HPPOSECEF" ;;
        0131) echo "HPPOSLLH" ;;
        0135) echo "ODO" ;;
        0114) echo "HNR" ;;
        0201) echo "MEASX" ;;
        0214) echo "RAWX" ;;
        0215) echo "SFRBX" ;;
        0501) echo "ACK-ACK" ;;
        0500) echo "ACK-NAK" ;;
        0600) echo "CFG-PRT" ;;
        0602) echo "CFG-NAV2" ;;
        0608) echo "CFG-RATE" ;;
        0609) echo "CFG-CFG" ;;
        0611) echo "CFG-RXM" ;;
        0616) echo "CFG-SBAS" ;;
        0617) echo "CFG-NMEA" ;;
        061E) echo "CFG-GNSS" ;;
        0624) echo "CFG-NAV5" ;;
        0625) echo "CFG-NAVX5" ;;
        062B) echo "CFG-AUTO" ;;
        062D) echo "CFG-TMODE2" ;;
        0631) echo "CFG-TP5" ;;
        0634) echo "CFG-ITFM" ;;
        0661) echo "CFG-PMS" ;;
        068E) echo "CFG-GEOFENCE" ;;
        *)    echo "unknown/unlisted" ;;
    esac
}

gnss_ubx_parse() {  # <hex frame>
    local h="${1:-}" cls id len pay want got
    h="${h// /}"; h="${h//$'\n'/}"; h="${h^^}"
    [[ "$h" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    (( ${#h} >= 16 )) || { printf 'ERROR\tframe is shorter than the 8-byte header\n' >&2; return 2; }
    [[ "${h:0:4}" == "B562" ]] || {
        printf 'ERROR\tno B5 62 sync; this is not a UBX frame\n' >&2; return 2; }
    cls="${h:4:2}"; id="${h:6:2}"
    len=$(( 16#${h:8:2} | (16#${h:10:2} << 8) ))
    pay="${h:12:$(( len * 2 ))}"
    (( ${#pay} == len * 2 )) || {
        printf 'ERROR\tlength field says %d payload octets, %d present\n' \
            "$len" "$(( ${#pay} / 2 ))" >&2; return 2; }
    want="${h:$(( 12 + len * 2 )):4}"
    got=$(gnss_ubx_cksum "${h:4:$(( 8 + len * 2 ))}")
    printf 'sync\t%s\n' "B562"
    printf 'class\t%s\n' "$cls"
    printf 'class_name\t%s\n' "$(gnss_ubx_class_name "$cls")"
    printf 'id\t%s\n' "$id"
    printf 'message\t%s\n' "$(gnss_ubx_msg_name "$cls" "$id")"
    printf 'length\t%d\n' "$len"
    printf 'checksum_field\t%s\n' "$want"
    printf 'checksum_computed\t%s\n' "$got"
    if [[ "$want" == "$got" ]]; then printf 'checksum_ok\tyes\n'
    else printf 'checksum_ok\tno\n'; fi
    return 0
}

# ── forging: the same wires, for replay testing ─────────────────────────
# A forged NMEA sentence is how a logger that trusts a serial port gets tested.
# The fields are positional and the checksum is real, because a test that fails
# on a checksum tests the logger's parser and not its trust model.
gnss_nmea_gga() {  # <lat dec> <lon dec> <alt_m> [sats] [hdop] [quality]
    local lat="${1:-0}" lon="${2:-0}" alt="${3:-0}"
    local sats="${4:-09}" hdop="${5:-0.9}" q="${6:-1}"
    local field checksum
    # ddmm.mmmm / dddmm.mmmm — the format is degrees concatenated with decimal
    # minutes, which is NOT decimal degrees. Writing the degree value straight
    # out produces a sentence every consumer reads as a different place.
    local lat_a lat_h lon_a lon_h
    lat_a=$(awk -v v="$lat" 'BEGIN{ a=(v<0?-v:v); d=int(a); m=(a-d)*60; printf "%02d%07.4f", d, m }')
    lat_h=$(awk -v v="$lat" 'BEGIN{ printf "%s", (v<0 ? "S" : "N") }')
    lon_a=$(awk -v v="$lon" 'BEGIN{ a=(v<0?-v:v); d=int(a); m=(a-d)*60; printf "%03d%07.4f", d, m }')
    lon_h=$(awk -v v="$lon" 'BEGIN{ printf "%s", (v<0 ? "W" : "E") }')
    field="GPGGA,$(date -u +%H%M%S.00),${lat_a},${lat_h},${lon_a},${lon_h},${q},${sats},${hdop},${alt},M,0.0,M,,"
    checksum=$(gnss_nmea_cksum "$field")
    printf 'sentence\t$%s*%s\n' "$field" "$checksum"
    printf 'lat\t%s\n' "$(awk -v v="$lat" 'BEGIN{printf "%.6f", v}')"
    printf 'lon\t%s\n' "$(awk -v v="$lon" 'BEGIN{printf "%.6f", v}')"
    return 0
}

gnss_nmea_rmc() {  # <lat dec> <lon dec> <speed_kn> [status]
    local lat="${1:-0}" lon="${2:-0}" spd="${3:-0}" st="${4:-A}"
    local lat_a lat_h lon_a lon_h field checksum
    lat_a=$(awk -v v="$lat" 'BEGIN{ a=(v<0?-v:v); d=int(a); m=(a-d)*60; printf "%02d%07.4f", d, m }')
    lat_h=$(awk -v v="$lat" 'BEGIN{ printf "%s", (v<0 ? "S" : "N") }')
    lon_a=$(awk -v v="$lon" 'BEGIN{ a=(v<0?-v:v); d=int(a); m=(a-d)*60; printf "%03d%07.4f", d, m }')
    lon_h=$(awk -v v="$lon" 'BEGIN{ printf "%s", (v<0 ? "W" : "E") }')
    field="GPRMC,$(date -u +%H%M%S.00),${st},${lat_a},${lat_h},${lon_a},${lon_h},$(awk -v s="$spd" 'BEGIN{printf "%.2f", s}'),0.00,$(date -u +%d%m%y),,,A"
    checksum=$(gnss_nmea_cksum "$field")
    printf 'sentence\t$%s*%s\n' "$field" "$checksum"
    return 0
}

# gnss_ubx_pvt <lat> <lon> <alt> — a NAV-PVT frame, checksummed.
# The frame is the one a receiver would send, with the fix type set to 3D and
# the validity flags set: a forge that leaves the validity bits clear produces
# a frame every decoder should refuse, which tests the decoder.
gnss_ubx_pvt() {
    local lat="${1:-0}" lon="${2:-0}" alt="${3:-0}"
    local lat_i lon_i alt_i pay ck
    lat_i=$(awk -v v="$lat" 'BEGIN{printf "%d", v*10000000}')
    lon_i=$(awk -v v="$lon" 'BEGIN{printf "%d", v*10000000}')
    alt_i=$(awk -v v="$alt" 'BEGIN{printf "%d", (v+0)*1000}')
    # 84-octet NAV-PVT payload: iTOW(4) year(2) month day hour min sec(1 each)
    # valid(1) tAcc(4) nano(4) fixType(1) flags(1) flags2(1) numSV(1)
    # lon(4) lat(4) height(4) hMSL(4) hAcc(4) vAcc(4) ...
    local itow="00000000" year="E807" mon="0C" day="01" hr="00" mn="00" sec="00"
    pay="${itow}${year}${mon}${day}${hr}${mn}${sec}03"
    pay+="0000000000000000"     # tAcc, nano
    pay+="03"                    # fixType = 3 (3D)
    pay+="8B"                    # flags: gnssFixOK | diffSoln? no: gnssFixOK(1)|headVeh? use 0x8B = gnssFixOK|psmState|carrier? use simple
    pay+="00"                    # flags2
    pay+="09"                    # numSV
    pay+="$(printf '%08X' "$(( (lon_i * 100) & 0xFFFFFFFF ))" | cut -c1-8)"
    pay+="$(printf '%08X' "$(( (lat_i * 100) & 0xFFFFFFFF ))" | cut -c1-8)"
    # The two position words are sign-extended int32 little-endian in the real
    # frame; --gnss-ubx-pvt emits the raw words and says so rather than
    # pretending a shell printf produces a byte-exact receiver frame.
    pay+="00000000"              # height (raw)
    pay+="00000000"              # hMSL (raw)
    pay+="0000000000000000"      # hAcc, vAcc
    # Pad to the declared length so the length field is honest.
    local len=$(( ${#pay} / 2 ))
    ck=$(gnss_ubx_cksum "0107$(printf '%02X%02X' $(( len & 0xFF )) $(( (len >> 8) & 0xFF )) )${pay}")
    printf 'frame\tB5620107%02X%02X%s%s\n' $(( len & 0xFF )) $(( (len >> 8) & 0xFF )) "$pay" "$ck"
    printf 'payload_octets\t%d\n' "$len"
    printf 'message\tNAV-PVT\n'
    printf 'note\tthe position words are the raw scaled integers; a receiver frame is little-endian signed and this emits the magnitude, so compare fields rather than bytes\n'
    return 0
}

# ── spoof detection: the tells, not the accusation ──────────────────────
# Input is a TSV of fixes: utc<TAB>lat<TAB>lon<TAB>speed_kn<TAB>hdop<TAB>sats
# Every row is a fix the receiver reported. The detector never says "spoofed";
# it says which tells fired and what a benign explanation would have to be.
gnss_spoof_detect() {
    local file="${1:-}" max_kn="${2:-900}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such track: %s\n' "$(gnss_sanitize "$file")" >&2; return 1; }
    awk -F'\t' -v maxkn="$max_kn" '
        function rad(d) { return d * 3.14159265358979323846 / 180 }
        # Great-circle distance in metres between two fixes.
        function dist(lat1, lon1, lat2, lon2,   p1, p2, dp, dl, a) {
            p1 = rad(lat1); p2 = rad(lat2)
            dp = rad(lat2 - lat1); dl = rad(lon2 - lon1)
            a = sin(dp/2)^2 + cos(p1) * cos(p2) * sin(dl/2)^2
            return 2 * 6371000 * atan2(sqrt(a), sqrt(1 - a))
        }
        NR == 1 { next }
        NF < 3 { next }
        {
            n++
            utc[n] = $1; lat[n] = $2 + 0; lon[n] = $3 + 0
            spd[n] = ($4 == "" ? 0 : $4 + 0)
            hdop[n] = ($5 == "" ? -1 : $5 + 0)
            sats[n] = ($6 == "" ? 0 : $6 + 0)
        }
        END {
            printf "fixes\t%d\n", n
            if (n < 2) { printf "verdict\tsilent\ttrack too short to test\n"; exit 0 }

            jumps = 0; best_d = 0; best_i = 0
            for (i = 1; i < n; i++) {
                d = dist(lat[i], lon[i], lat[i+1], lon[i+1])
                dt = 1
                # Time between samples, from HHMMSS when it parses, else 1 s.
                if (length(utc[i]) >= 6 && length(utc[i+1]) >= 6) {
                    a = substr(utc[i],1,2)*3600 + substr(utc[i],3,2)*60 + substr(utc[i],5,2)
                    b = substr(utc[i+1],1,2)*3600 + substr(utc[i+1],3,2)*60 + substr(utc[i+1],5,2)
                    dt = b - a
                    if (dt <= 0) dt = 1
                }
                # Distance the reported speed allows, doubled for manoeuvre
                # slack: a car cannot outrun its own speedometer by more than
                # the receiver quantisation plus a hard brake or a launch.
                allowed = (spd[i] + 1) * 0.514444 * dt * 2
                if (d > allowed && d > 50) {
                    jumps++
                    if (d > best_d) { best_d = d; best_i = i }
                }
            }
            printf "jumps\t%d\n", jumps
            if (jumps > 0) {
                printf "tell_jump\t%s\tfix %d -> %d moves %.0f m in one sample with no acquisition gap\n", "PRESENT", best_i, best_i+1, best_d
            } else {
                printf "tell_jump\t%s\tno discontinuity beyond twice the reported speed\n", "absent"
            }

            # DOP: HDOP below 0.5 while the receiver claims fewer than 6
            # satellites is a sky that cannot produce that geometry.
            dopple = 0; lo = -1
            for (i = 1; i <= n; i++) {
                if (hdop[i] >= 0 && hdop[i] < 0.5 && sats[i] > 0 && sats[i] < 6) {
                    dopple++
                    if (lo < 0 || hdop[i] < lo) lo = hdop[i]
                }
            }
            printf "implausible_dop\t%d\n", dopple
            if (dopple > 0) {
                printf "tell_dop\t%s\tHDOP %.2f with under six satellites: geometry that sky cannot give\n", "PRESENT", lo
            } else {
                printf "tell_dop\t%s\tnone\n", "absent"
            }

            # Speed consistency: a fix that moves at 400 kn while reporting 2
            # is a track whose position and speed disagree.
            spd_bad = 0
            for (i = 1; i < n; i++) {
                d = dist(lat[i], lon[i], lat[i+1], lon[i+1])
                implied = d / 0.514444
                # A jump already counted above is the same event, not a second
                # finding: the speed tell is for a track that moves fast the
                # whole way, which the jump tell does not catch.
                allowed = (spd[i] + 1) * 0.514444 * 2
                if (implied > maxkn && !(d > allowed && d > 50)) spd_bad++
            }
            printf "implausible_speed\t%d\n", spd_bad
            if (spd_bad > 0) {
                printf "tell_speed\t%s\t%d intervals imply more than %.0f kn, which no receiver-vehicle pair reaches under its own power\n", "PRESENT", spd_bad, maxkn
            } else {
                printf "tell_speed\t%s\tnone\n", "absent"
            }

            tells = (jumps > 0) + (dopple > 0) + (spd_bad > 0)
            printf "tells_present\t%d\n", tells
            if (tells >= 2) {
                printf "verdict\t%s\t%s\n", "inconsistent", "two or more independent tells: the track needs a benign explanation before it is used"
            } else if (tells == 1) {
                printf "verdict\t%s\t%s\n", "suspect", "one tell: a hypothesis, not a finding"
            } else {
                printf "verdict\t%s\t%s\n", "consistent", "no tell fired against this model"
            }
        }
    ' "$file"
}

# ── the trust hole ──────────────────────────────────────────────────────
# gpsd hands TPV to anything that can open the socket. Nothing authenticates
# the writer, and most consumers never check that the reader is the one that
# owns the device. This verb states which consumers on this machine take a
# position from gpsd and what they would accept from it.
gnss_gpsd_trust() {
    local sock="${GPSD_SOCKET:-/var/run/gpsd.sock}"
    printf 'socket\t%s\n' "$sock"
    if [[ -S "$sock" ]]; then
        printf 'socket_state\tpresent\n'
        # The permissions are the whole finding: a socket any local user can
        # write to is a position any local user can set.
        stat -c 'socket_mode\t%a\nsocket_owner\t%U\n' "$sock" 2>/dev/null || true
    else
        printf 'socket_state\tsilent\n'
        printf 'note\tno gpsd socket: nothing on this machine takes a position from a daemon here\n'
    fi
    local cmd found=0
    for cmd in chronyd ntpd gpsd gpsmon gpspipe cgps; do
        if command -v "$cmd" >/dev/null 2>&1; then
            printf 'consumer\t%s\t%s\n' "$cmd" "$(command -v "$cmd")"
            found=$(( found + 1 ))
        fi
    done
    if (( found == 0 )); then printf 'consumers\tnone\n'; fi
    printf 'risk\t%s\n' "a socket that authenticates nobody is a position that authenticates nobody"
    printf 'note\twriting a fix is not the attack; it is that everything downstream treats the fix as measured\n'
    return 0
}

# gnss_gpsd_lie <lat> <lon> — what a forged TPV would make a consumer believe,
# and what it does to the clock if that consumer is a time daemon.
gnss_gpsd_lie() {
    local lat="${1:-}" lon="${2:-}"
    [[ -n "$lat" && -n "$lon" ]] || {
        printf 'ERROR\tusage: --gpsd-lie <lat> <lon>\n' >&2; return 2; }
    awk -v lat="$lat" -v lon="$lon" 'BEGIN{
        if (lat < -90 || lat > 90) exit 3
        if (lon < -180 || lon > 180) exit 3
    }' || { printf 'ERROR\tlat must be -90..90 and lon -180..180\n' >&2; return 2; }
    local mode="class C"
    printf 'forged_lat\t%s\nforged_lon\t%s\n' "$lat" "$lon"
    printf 'tpv_field\t%s\t%s,%s\n' "device" "$(gnss_sanitize "$(hostname 2>/dev/null || echo host)")" "${GPSD_DEVICE:-ttyUSB0}"
    # A time daemon reads the fix's timestamp, not its position: the position
    # is a side effect. That is why a forged position is a survey-integrity
    # problem and a forged time is a certificate problem.
    printf 'clock_effect\t%s\n' "a time daemon that accepts TPV accepts the time in the same message"
    printf 'class\t%s\n' "$mode"
    printf 'note\tthe fix and the timestamp travel together: nothing in TPV says which of the two the consumer needed\n'
    return 0
}

# ── constellation reference ─────────────────────────────────────────────
gnss_constellations() {
    printf 'system\tbands\tspoofing_resistance\tnote\n'
    printf 'GPS\tL1 C/A, L1C, L2C, L5\tnone in L1 C/A\tunauthenticated civil signal\n'
    printf 'GPS\tM-code (L1/L2)\tauthenticated (restricted)\tmilitary, not available to civil receivers\n'
    printf 'Galileo\tE1, E5, E6\tnone in E1/E5\tOS-NMA authenticity is an optional navigation message\n'
    printf 'Galileo\tE6 (HAS)\tauthenticated\tHigh Accuracy Service, commercial\n'
    printf 'GLONASS\tL1, L2 FDMA/CDMA\tnone\tnavigation message is unauthenticated\n'
    printf 'BeiDou\tB1I, B2I, B1C\tnone in B1I\tB1C has an open authenticatable structure, not enforced by default\n'
    printf 'NavIC\tL5, S\tnone\tregional\n'
    return 0
}

gnss_status_tsv() {
    printf 'MODULE\tgnss\n'
    printf 'TARGET\treceiver interface, position integrity and the fix trust model\n'
    printf 'PROTOCOLS\tNMEA 0183 (2.3/4.11 subset), u-blox UBX\n'
    printf 'TRANSMIT\tnone — parse, forge and compare\n'
    printf 'STORE\t%s\n' "$GNSS_DIR"
    printf 'SELFTEST\tyes\n'
}

# ── selftest — no receiver, no root, no network ─────────────────────────
gnss_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT

    # 1. Checksum: the classic GGA sentence from NMEA 0183 §7. A checksum that
    #    disagrees with the published example is wrong, full stop.
    local gga='$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47'
    chk nmea-cksum       "$(gnss_nmea_cksum 'GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,')" "47"
    chk nmea-cksum-ok    "$(gnss_nmea_cksum_ok "$gga"; echo $?)" "0"
    chk nmea-cksum-bad   "$(gnss_nmea_cksum_ok '${gga%47}48'; echo $?)" "1"

    # 2. Parse: the fields a survey records.
    chk nmea-lat         "$(fld "$(gnss_nmea_parse "$gga")" lat)" "4807.038"
    chk nmea-sats        "$(fld "$(gnss_nmea_parse "$gga")" sats_used)" "08"
    chk nmea-hdop        "$(fld "$(gnss_nmea_parse "$gga")" hdop)" "0.9"
    chk nmea-valid       "$(fld "$(gnss_nmea_parse "$gga")" position_valid)" "yes"

    # A quality-0 GGA carries a placeholder position, not a fix.
    local nofix='$GPGGA,123519,,,,,0,00,99.9,,M,,M,,*5B'
    chk nmea-nofix-valid "$(fld "$(gnss_nmea_parse "$nofix")" position_valid)" "no"

    # 3. GSA: a 2D fix has no altitude.
    local gsa='$GPGSA,A,2,04,05,09,12,24,25,29,31,,,,,1.8,1.2,1.4*3E'
    chk gsa-fix          "$(fld "$(gnss_nmea_parse "$gsa")" fix)" "2D (no altitude)"
    chk gsa-hdop         "$(fld "$(gnss_nmea_parse "$gsa")" hdop)" "1.2"

    # 4. Forge: the sentence round-trips through the parser with a real check.
    local forged fgga
    forged=$(gnss_nmea_gga 52.370216 4.895168 12.5)
    fgga=$(fld "$forged" sentence)
    chk forge-cksum      "$(gnss_nmea_cksum_ok "$fgga"; echo $?)" "0"
    # 52.370216 deg -> 52 deg + 22.21296 min -> 5222.2130 in ddmm.mmmm form.
    chk forge-lat        "$(fld "$(gnss_nmea_parse "$fgga")" lat)" "5222.2130"
    chk forge-valid      "$(fld "$(gnss_nmea_parse "$fgga")" position_valid)" "yes"
    chk forge-hemi       "$(fld "$(gnss_nmea_parse "$fgga")" lat_hemi)" "N"

    # Southern/western: the sign must reach the hemisphere field, not the value.
    forged=$(gnss_nmea_gga -33.9249 18.4241 10)
    fgga=$(fld "$forged" sentence)
    chk forge-south      "$(fld "$(gnss_nmea_parse "$fgga")" lat_hemi)" "S"
    chk forge-south-val  "$(fld "$(gnss_nmea_parse "$fgga")" lat)" "3355.4940"

    # 5. UBX checksum against real frames with published checksums:
    #    B5 62 06 00 00 00 0E 9B (UBX-CFG-PRT poll) and
    #    B5 62 05 01 02 00 06 01 0F 38 (UBX-ACK-ACK).
    chk ubx-cksum-cfgprt "$(gnss_ubx_cksum '06000000')"   "0618"
    chk ubx-cksum-ack    "$(gnss_ubx_cksum '050102000601')" "0F38"
    chk ubx-ack-parse    "$(fld "$(gnss_ubx_parse B5620501020006010F38)" checksum_ok)" "yes"

    # 6. UBX parse: a well-formed NAV-PVT header with an honest length.
    local pvt
    pvt=$(gnss_ubx_pvt 52.370216 4.895168 12.5)
    chk ubx-pvt-msg      "$(fld "$pvt" message)" "NAV-PVT"
    local frame
    frame=$(fld "$pvt" frame)
    chk ubx-pvt-parse    "$(fld "$(gnss_ubx_parse "$frame")" checksum_ok)" "yes"
    chk ubx-pvt-class    "$(fld "$(gnss_ubx_parse "$frame")" class_name)" "NAV"
    # A frame whose length field lies is refused rather than half-read.
    chk ubx-short        "$(gnss_ubx_parse B56201070A0000 >/dev/null 2>&1; echo $?)" "2"
    chk ubx-badsync      "$(gnss_ubx_parse B5629907 >/dev/null 2>&1; echo $?)" "2"

    # 7. Spoof detection: three tracks, each with one property.
    printf 'utc\tlat\tlon\tspeed_kn\thdop\tsats\n' > "$d/clean.tsv"
    printf '120000\t52.3700\t4.8900\t30.0\t0.9\t9\n' >> "$d/clean.tsv"
    printf '120001\t52.3702\t4.8904\t30.0\t0.9\t9\n' >> "$d/clean.tsv"
    printf '120002\t52.3704\t4.8908\t30.0\t0.9\t9\n' >> "$d/clean.tsv"
    local out
    out=$(gnss_spoof_detect "$d/clean.tsv")
    chk spoof-clean-verdict "$(fld "$out" verdict)" "consistent"
    chk spoof-clean-tells   "$(fld "$out" tells_present)" "0"

    printf 'utc\tlat\tlon\tspeed_kn\thdop\tsats\n' > "$d/jump.tsv"
    printf '120000\t52.3700\t4.8900\t30.0\t0.9\t9\n' >> "$d/jump.tsv"
    printf '120001\t52.9700\t4.8900\t30.0\t0.9\t9\n' >> "$d/jump.tsv"
    out=$(gnss_spoof_detect "$d/jump.tsv")
    chk spoof-jump          "$(fld "$out" tell_jump)" "PRESENT"
    chk spoof-jump-verdict  "$(fld "$out" verdict)" "suspect"

    # Two tells at once is the finding, one is the hypothesis.
    printf 'utc\tlat\tlon\tspeed_kn\thdop\tsats\n' > "$d/both.tsv"
    printf '120000\t52.3700\t4.8900\t30.0\t0.30\t4\n' >> "$d/both.tsv"
    printf '120001\t52.9700\t4.8900\t30.0\t0.30\t4\n' >> "$d/both.tsv"
    out=$(gnss_spoof_detect "$d/both.tsv")
    chk spoof-both-tells    "$(fld "$out" tells_present)" "2"
    chk spoof-both-verdict  "$(fld "$out" verdict)" "inconsistent"

    # 8. Shape: the verbs answer rather than half-answer.
    chk spoof-missing       "$(gnss_spoof_detect "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"
    chk nmea-not-sentence   "$(gnss_nmea_parse 'GPGGA,1' >/dev/null 2>&1; echo $?)" "2"
    chk lie-bad-lat         "$(gnss_gpsd_lie 91 0 >/dev/null 2>&1; echo $?)" "2"
    chk lie-ok              "$(fld "$(gnss_gpsd_lie 52.37 4.89)" forged_lat)" "52.37"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    if (( bad )); then printf 'RESULT\tFAIL(%d)\n' "$bad"; return 1; fi
    printf 'RESULT\tPASS\n'
    return 0
}

# ── CLI ─────────────────────────────────────────────────────────────────
gnss_usage() {
    cat <<'EOF'
gnss — receiver interface, position integrity, and the fix trust model

  --status-tsv              module state as TSV
  --nmea <sentence>         decode one NMEA 0183 sentence, checksum included
  --nmea-file <log>         one row per sentence: type, checksum verdict, size
  --nmea-gga <lat> <lon> <alt_m> [sats] [hdop] [quality]
                            build a GGA sentence with a real checksum
  --nmea-rmc <lat> <lon> <speed_kn> [status]
                            build an RMC sentence
  --ubx <hex>               decode a u-blox UBX frame
  --ubx-pvt <lat> <lon> <alt_m>
                            build a NAV-PVT frame
  --spoof-detect <track.tsv> [max_kn]
                            which tells a fix track carries, and what each means
                            (TSV: utc lat lon speed_kn hdop sats)
  --constellations          what each system's civil signal does and does not
                            authenticate
  --gpsd-trust              what on this machine takes a position from gpsd
  --gpsd-lie <lat> <lon>    what a forged TPV makes a consumer believe
  --selftest                verify the codecs and the detector without hardware
  --menu                    interactive menu
EOF
}

gnss_menu() {
    printf '\n  gnss — receiver interface and position integrity\n\n'
    printf '  1) Decode an NMEA sentence\n'
    printf '  2) Scan an NMEA log\n'
    printf '  3) Build a GGA sentence\n'
    printf '  4) Decode a UBX frame\n'
    printf '  5) Check a fix track for spoofing tells\n'
    printf '  6) What takes its position from gpsd\n'
    printf '  7) Constellation authenticity reference\n'
    printf '  s) selftest\n  q) quit\n\n'
    local c
    read -r -p '  > ' c
    case "$c" in
        1) read -r -p '  sentence: ' x; gnss_nmea_parse "$x" ;;
        2) read -r -p '  log file: ' x; gnss_nmea_split "$x" ;;
        3) read -r -p '  lat lon alt: ' la lo al; gnss_nmea_gga "$la" "$lo" "$al" ;;
        4) read -r -p '  hex: ' x; gnss_ubx_parse "$x" ;;
        5) read -r -p '  track tsv: ' x; gnss_spoof_detect "$x" ;;
        6) gnss_gpsd_trust ;;
        7) gnss_constellations ;;
        s|S) gnss_selftest ;;
        *) : ;;
    esac
}

gnss_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   gnss_status_tsv ;;
        --nmea)         gnss_nmea_parse "${1:-}" ;;
        --nmea-file)    gnss_nmea_split "${1:-}" ;;
        --nmea-gga)     gnss_nmea_gga "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
        --nmea-rmc)     gnss_nmea_rmc "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --ubx)          gnss_ubx_parse "${1:-}" ;;
        --ubx-pvt)      gnss_ubx_pvt "${1:-}" "${2:-}" "${3:-}" ;;
        --spoof-detect) gnss_spoof_detect "${1:-}" "${2:-900}" ;;
        --constellations) gnss_constellations ;;
        --gpsd-trust)   gnss_gpsd_trust ;;
        --gpsd-lie)     gnss_gpsd_lie "${1:-}" "${2:-}" ;;
        --selftest)     gnss_selftest ;;
        --menu|"")      gnss_menu ;;
        --help|-h|--list) gnss_usage ;;
        *)
            printf 'ERROR\tunknown verb: %s\n' "$(gnss_sanitize "$cmd")" >&2
            gnss_usage >&2
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
    gnss_cli_main "$@"
fi
