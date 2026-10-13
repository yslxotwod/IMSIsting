#!/usr/bin/env bash
# tower survey / war-drive — GPS-tagged cell survey with map export
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

MOD_TMP="$TMP_DIR/tower_map"
TMAP_DIR="$LOOT_DIR/tower_map"
TMAP_POINTS="$TMAP_DIR/points.tsv"
mkdir -p "$MOD_TMP" "$TMAP_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
tmap_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Split a TSV line into the global array TMAP_F, preserving empty fields.
# `read` with IFS=tab collapses runs of separators, so a row with an empty
# column shifts every field after it. `cut -f` does not, so the line is split
# that way and read into the array one field at a time.
TMAP_F=()
tmap_split() {
    TMAP_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        TMAP_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── GPS ─────────────────────────────────────────────────────────────────
# gpsd is the normal source. Without it the survey still runs, but every point
# is recorded with an empty position and the export says so rather than
# inventing coordinates.
tmap_gps_available() {
    command -v gpspipe >/dev/null 2>&1 || return 1
    command -v gpsd    >/dev/null 2>&1 || return 1
    return 0
}

tmap_gps_running() {
    pgrep -x gpsd >/dev/null 2>&1
}

tmap_gps_read() {
    # Emits "lat\tlon\talt\tspeed\ttime" or nothing.
    command -v gpspipe >/dev/null 2>&1 || return 1

    local out
    out=$(timeout 3 gpspipe -w -n 8 2>/dev/null | grep '"class":"TPV"' | tail -1)
    [[ -z "$out" ]] && return 1

    local lat lon alt spd
    lat=$(sed -n 's/.*"lat":\([-0-9.]*\).*/\1/p' <<<"$out")
    lon=$(sed -n 's/.*"lon":\([-0-9.]*\).*/\1/p' <<<"$out")
    alt=$(sed -n 's/.*"alt":\([-0-9.]*\).*/\1/p' <<<"$out")
    spd=$(sed -n 's/.*"speed":\([-0-9.]*\).*/\1/p' <<<"$out")

    [[ -z "$lat" || -z "$lon" ]] && return 1
    printf '%s\t%s\t%s\t%s\n' "$lat" "$lon" "${alt:-}" "${spd:-}"
}

tmap_start_gpsd() {
    command -v gpsd >/dev/null 2>&1 || {
        printf 'ERROR\tgpsd not installed — install gpsd and gpsd-clients\n' >&2
        return 1
    }
    tmap_gps_running && { info "gpsd already running"; return 0; }

    # The device is whatever the user names; the common USB receivers are
    # /dev/ttyUSB0 and /dev/ttyACM0.
    local dev="${1:-/dev/ttyUSB0}"
    [[ -e "$dev" ]] || {
        printf 'ERROR\tno GPS device at %s — pass a device path\n' "$dev" >&2
        return 1
    }
    gpsd "$dev" >/dev/null 2>&1 &
    sleep 1
    tmap_gps_running || { printf 'ERROR\tgpsd failed to start on %s\n' "$dev" >&2; return 1; }
    info "gpsd started on $dev"
}

# ── store ───────────────────────────────────────────────────────────────
tmap_header() {
    printf 'ts\tlat\tlon\talt_m\tspeed_mps\trat\tgen\tarfcn\tplmn\tcell_id\trsrp_dbm\toperator\n'
}

tmap_init_store() {
    mkdir -p "$TMAP_DIR"
    [[ -f "$TMAP_POINTS" ]] || tmap_header > "$TMAP_POINTS"
}

tmap_point_count() {
    [[ -f "$TMAP_POINTS" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$TMAP_POINTS" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# Record one observation. A point with no fix is still recorded — with empty
# coordinates — because losing the observation is worse than losing the
# position, and the export can then say which points had no fix.
tmap_record() {
    local rat="$1" gen="$2" arfcn="$3" plmn="$4" cell="$5" rsrp="$6" op="$7"
    tmap_init_store

    local ts; ts=$(date -Is)
    local fix lat="" lon="" alt="" spd=""
    if fix=$(tmap_gps_read); then
        # tmap_split, not `read`: alt and speed are commonly absent from a
        # gpsd TPV record, and IFS=tab would collapse the empty field and
        # shift speed into alt.
        tmap_split "$fix"
        lat="${TMAP_F[0]:-}"; lon="${TMAP_F[1]:-}"
        alt="${TMAP_F[2]:-}"; spd="${TMAP_F[3]:-}"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$ts" "$lat" "$lon" "$alt" "$spd" \
        "$(tmap_sanitize "$rat")" "$(tmap_sanitize "$gen")" \
        "$(tmap_sanitize "$arfcn")" "$(tmap_sanitize "$plmn")" \
        "$(tmap_sanitize "$cell")" "$(tmap_sanitize "$rsrp")" \
        "$(tmap_sanitize "$op")" >> "$TMAP_POINTS"
}

# ── survey loop ─────────────────────────────────────────────────────────
# One pass: ask 02_cell_recon for a survey, then stamp each cell with the
# current fix. This reuses the recon module rather than duplicating its
# parsing — the two cannot disagree about what a cell looks like.
tmap_run_survey() {
    local rat="${1:-gsm}" band="${2:-GSM900}"
    local recon="$IMSISTING_ROOT/modules/02_cell_recon.sh"

    [[ -x "$recon" ]] || {
        printf 'ERROR\t02_cell_recon.sh not found or not executable at %s\n' "$recon" >&2
        return 1
    }

    if tmap_gps_available && tmap_gps_running; then
        info "GPS fix available"
    elif tmap_gps_available; then
        warn "gpsd is not running — points will be recorded without a position"
    else
        warn "gpsd/gpspipe not installed — points will be recorded without a position"
    fi

    info "survey pass: $rat ${band:-}"
    local rows
    rows=$("$recon" --scan "$rat" "$band" >/dev/null 2>&1; "$recon" --list-tsv 2>/dev/null)
    if [[ -z "$rows" ]]; then
        printf 'ERROR\trecon returned no cells — is the radio attached and in range?\n' >&2
        return 1
    fi

    local n=0
    # Same empty-field hazard: recon rows carry empty columns for fields a
    # given RAT does not have, so split with awk rather than `read`.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == rat$'\t'* ]] && continue
        tmap_split "$line"
        r="${TMAP_F[0]:-}"; gen="${TMAP_F[1]:-}"; arfcn="${TMAP_F[2]:-}"
        freq="${TMAP_F[3]:-}"; plmn="${TMAP_F[4]:-}"; mcc="${TMAP_F[5]:-}"
        mnc="${TMAP_F[6]:-}"; op="${TMAP_F[7]:-}"; ctry="${TMAP_F[8]:-}"
        cid="${TMAP_F[9]:-}"; lac="${TMAP_F[10]:-}"; bandc="${TMAP_F[11]:-}"
        rsrp="${TMAP_F[12]:-}"; cipher="${TMAP_F[13]:-}"; src="${TMAP_F[14]:-}"
        tmap_record "$r" "$gen" "$arfcn" "$plmn" "$cid" "$rsrp" "$op"
        n=$((n + 1))
    done <<< "$rows"

    ok "recorded $n point(s)"
    return 0
}

tmap_list() {
    local n; n=$(tmap_point_count)
    (( n > 0 )) || { warn "no survey points yet"; return 1; }
    tmap_header
    tail -n +2 "$TMAP_POINTS"
}

tmap_history() {
    local n; n=$(tmap_point_count)
    (( n > 0 )) || { warn "no survey points yet"; return 1; }
    printf 'points\ttotal\n'
    printf 'with_fix\t%s\n' "$(tail -n +2 "$TMAP_POINTS" | awk -F'\t' '$2!=""' | grep -c . || true)"
    printf 'without_fix\t%s\n' "$(tail -n +2 "$TMAP_POINTS" | awk -F'\t' '$2==""' | grep -c . || true)"
    printf 'distinct_cells\t%s\n' "$(tail -n +2 "$TMAP_POINTS" | cut -f8,9,10 | sort -u | grep -c . || true)"
    printf 'all\t%s\n' "$n"
}

tmap_clear() {
    tmap_init_store
    tmap_header > "$TMAP_POINTS"
    ok "survey store cleared"
}

# ── exports ─────────────────────────────────────────────────────────────
# KML for a map, CSV for a spreadsheet. Both refuse on an empty store rather
# than writing an empty file that looks like a successful export.
tmap_export_csv() {
    local n; n=$(tmap_point_count)
    (( n > 0 )) || { printf 'ERROR\tno survey points to export\n' >&2; return 1; }

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out="$TMAP_DIR/survey_${ts}.csv"
    cp "$TMAP_POINTS" "$out"
    printf 'OK\t%s\n' "$out"
}

tmap_export_kml() {
    local n; n=$(tmap_point_count)
    (( n > 0 )) || { printf 'ERROR\tno survey points to export\n' >&2; return 1; }

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out="$TMAP_DIR/survey_${ts}.kml"

    # Count the placeable points first. The KML body is written inside a
    # redirected brace group, which is a subshell — a counter incremented in
    # there would be lost, and the "no fix" note would silently never fire.
    local placed=0
    placed=$(tail -n +2 "$TMAP_POINTS" 2>/dev/null |
             awk -F'\t' '$2 != "" && $3 != ""' | grep -c . || true)
    [[ -z "$placed" ]] && placed=0

    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n'
        printf '<kml xmlns="http://www.opengis.net/kml/2.2">\n'
        printf '  <Document>\n'
        printf '    <name>IMSIsting cell survey</name>\n'
        printf '    <description>%s points, %s placeable, generated %s</description>\n' \
            "$n" "$placed" "$(date -Is)"
        printf '    <Style id="cell"><IconStyle><color>ffd9b34f</color>'
        printf '<scale>0.8</scale><Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon>'
        printf '</IconStyle></Style>\n'

        # Only points with a fix can be placed on a map. The rest are counted
        # in the description so the omission is visible, not silent.
        # Read the line whole and split with awk: `read` with IFS=tab
        # collapses runs of separators, so a point with empty lat/lon would
        # shift every later field. awk -F'\t' preserves the empty fields.
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" == ts$'\t'* ]] && continue
            tmap_split "$line"
            ts_f="${TMAP_F[0]:-}"; lat="${TMAP_F[1]:-}"; lon="${TMAP_F[2]:-}"
            alt="${TMAP_F[3]:-}";  spd="${TMAP_F[4]:-}"; rat="${TMAP_F[5]:-}"
            gen="${TMAP_F[6]:-}";  arfcn="${TMAP_F[7]:-}"; plmn="${TMAP_F[8]:-}"
            cell="${TMAP_F[9]:-}"; rsrp="${TMAP_F[10]:-}"; op="${TMAP_F[11]:-}"
            [[ -z "$lat" || -z "$lon" ]] && continue
            printf '    <Placemark>\n'
            printf '      <name>%s %s</name>\n' "$(tmap_kml_escape "$rat")" "$(tmap_kml_escape "$cell")"
            printf '      <description>%s</description>\n' \
                "$(tmap_kml_escape "gen=$gen arfcn=$arfcn plmn=$plmn rsrp=$rsrp op=$op ts=$ts_f")"
            printf '      <styleUrl>#cell</styleUrl>\n'
            printf '      <Point><coordinates>%s,%s,%s</coordinates></Point>\n' \
                "$lon" "$lat" "${alt:-0}"
            printf '    </Placemark>\n'
        done < "$TMAP_POINTS"

        printf '  </Document>\n'
        printf '</kml>\n'
    } > "$out"

    local missing=$(( n - placed ))
    printf 'OK\t%s\n' "$out"
    if (( missing > 0 )); then
        printf 'NOTE\t%d of %d points had no GPS fix and are not on the map\n' \
            "$missing" "$n"
    fi
}

tmap_kml_escape() {
    printf '%s' "${1:-}" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

tmap_export_geojson() {
    local n; n=$(tmap_point_count)
    (( n > 0 )) || { printf 'ERROR\tno survey points to export\n' >&2; return 1; }

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out="$TMAP_DIR/survey_${ts}.geojson"

    {
        printf '{"type":"FeatureCollection","features":[\n'
        local first=1
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" == ts$'\t'* ]] && continue
            tmap_split "$line"
            ts_f="${TMAP_F[0]:-}"; lat="${TMAP_F[1]:-}"; lon="${TMAP_F[2]:-}"
            alt="${TMAP_F[3]:-}";  spd="${TMAP_F[4]:-}"; rat="${TMAP_F[5]:-}"
            gen="${TMAP_F[6]:-}";  arfcn="${TMAP_F[7]:-}"; plmn="${TMAP_F[8]:-}"
            cell="${TMAP_F[9]:-}"; rsrp="${TMAP_F[10]:-}"; op="${TMAP_F[11]:-}"
            [[ -z "$lat" || -z "$lon" ]] && continue
            (( first )) || printf ',\n'
            first=0
            printf '{"type":"Feature","geometry":{"type":"Point","coordinates":[%s,%s]},' "$lon" "$lat"
            printf '"properties":{"ts":"%s","rat":"%s","gen":"%s","arfcn":"%s","plmn":"%s","cell":"%s","rsrp":"%s","operator":"%s"}}' \
                "$ts_f" "$rat" "$gen" "$arfcn" "$plmn" "$cell" "$rsrp" "$(tmap_json_escape "$op")"
        done < "$TMAP_POINTS"
        printf '\n]}\n'
    } > "$out"

    printf 'OK\t%s\n' "$out"
}

tmap_json_escape() {
    printf '%s' "${1:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# ── selftest ────────────────────────────────────────────────────────────
tmap_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot" TMAP_DIR="$d/loot/tower_map" TMAP_POINTS="$d/loot/tower_map/points.tsv"

    # 1. Empty store: every export must refuse rather than write an empty file.
    tmap_init_store
    chk init-header    "$(head -1 "$TMAP_POINTS" | awk -F'\t' '{print NF}')" "12"
    chk count-empty    "$(tmap_point_count)" "0"
    chk csv-empty-rc   "$(tmap_export_csv  >/dev/null 2>&1; echo $?)" "1"
    chk kml-empty-rc   "$(tmap_export_kml  >/dev/null 2>&1; echo $?)" "1"
    chk geo-empty-rc   "$(tmap_export_geojson >/dev/null 2>&1; echo $?)" "1"
    chk list-empty-rc  "$(tmap_list >/dev/null 2>&1; echo $?)" "1"
    chk hist-empty-rc  "$(tmap_history >/dev/null 2>&1; echo $?)" "1"

    # 2. A recorded point has the full field count. GPS is absent in a test
    #    environment, so the position fields are legitimately empty — the
    #    point is still recorded, which is the behaviour under test.
    tmap_record "LTE" "4G" "6300" "208-01" "12345" "-85" "Orange FR"
    chk count-one      "$(tmap_point_count)" "1"
    chk point-fields   "$(tail -1 "$TMAP_POINTS" | awk -F'\t' '{print NF}')" "12"
    chk point-rat      "$(tail -1 "$TMAP_POINTS" | cut -f6)" "LTE"
    chk point-arfcn    "$(tail -1 "$TMAP_POINTS" | cut -f8)" "6300"
    chk point-cell     "$(tail -1 "$TMAP_POINTS" | cut -f10)" "12345"
    chk point-op       "$(tail -1 "$TMAP_POINTS" | cut -f12)" "Orange FR"

    # 3. A hostile operator name must not forge a row.
    tmap_record "GSM" "2G" "42" "208-01" $'99\tEVIL\tROW' "-70" $'Evil\tOp'
    chk inject-fields  "$(tail -1 "$TMAP_POINTS" | awk -F'\t' '{print NF}')" "12"
    chk count-two      "$(tmap_point_count)" "2"

    # 4. CSV export writes a real file with the header plus every point.
    local csv; csv=$(tmap_export_csv | cut -f2)
    chk csv-exists     "$([[ -f "$csv" ]] && echo yes || echo no)" "yes"
    chk csv-lines      "$(grep -c . "$csv")" "3"

    # 5. KML: a point with no fix is not placed, and the omission is reported.
    local kmlout kml
    kmlout=$(tmap_export_kml)
    kml=$(printf '%s\n' "$kmlout" | awk -F'\t' '$1=="OK"{print $2}')
    chk kml-exists     "$([[ -f "$kml" ]] && echo yes || echo no)" "yes"
    chk kml-placemarks "$(grep -c '<Placemark>' "$kml")" "0"
    chk kml-note       "$(printf '%s\n' "$kmlout" | grep -c '^NOTE')" "1"
    chk kml-note-count "$(printf '%s\n' "$kmlout" | awk -F'\t' '$1=="NOTE"{print $2}' | cut -d' ' -f1)" "2"

    # 6. KML escaping: a cell name with XML metacharacters must be escaped.
    printf '%s\n' "$(tmap_header)" > "$TMAP_POINTS"
    printf '2026-01-01T00:00:00Z\t48.85\t2.35\t35\t0\tLTE\t4G\t6300\t208-01\t<a&b>c\t-80\tOrange FR\n' >> "$TMAP_POINTS"
    kmlout=$(tmap_export_kml)
    kml=$(printf '%s\n' "$kmlout" | awk -F'\t' '$1=="OK"{print $2}')
    chk kml-placed     "$(grep -c '<Placemark>' "$kml")" "1"
    chk kml-escaped    "$(grep -c 'a&amp;b' "$kml")" "1"
    chk kml-no-raw     "$(grep -c '<a&b>' "$kml")" "0"

    # 7. GeoJSON with a fix.
    local geo; geo=$(tmap_export_geojson | cut -f2)
    chk geo-exists     "$([[ -f "$geo" ]] && echo yes || echo no)" "yes"
    chk geo-features   "$(grep -c '"type":"Feature"' "$geo")" "1"
    chk geo-coords     "$(grep -c '"coordinates":\[2.35,48.85\]' "$geo")" "1"

    # 8. History accounting: one point with a fix.
    local hist; hist=$(tmap_history)
    chk hist-with-fix    "$(fld "$hist" with_fix)" "1"
    chk hist-without-fix "$(fld "$hist" without_fix)" "0"
    chk hist-all         "$(fld "$hist" all)" "1"

    # 9. Clear empties the store but keeps the header.
    tmap_clear >/dev/null 2>&1
    chk clear-count    "$(tmap_point_count)" "0"
    chk clear-header   "$(grep -c '^ts' "$TMAP_POINTS")" "1"

    # 10. Survey without the recon module must fail loudly, not silently.
    local saved="$IMSISTING_ROOT"
    IMSISTING_ROOT="$d/nonexistent"
    chk survey-missing-recon "$(tmap_run_survey gsm GSM900 >/dev/null 2>&1; echo $?)" "1"
    IMSISTING_ROOT="$saved"

    # 11. GPS helpers must report absence rather than blocking.
    chk gps-avail-is-bool "$([[ "$(tmap_gps_available && echo 1 || echo 0)" =~ ^[01]$ ]] && echo yes || echo no)" "yes"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
tmap_menu() {
    while true; do
        banner
        local gps="absent"
        tmap_gps_available && { tmap_gps_running && gps="fixing" || gps="present, not running"; }
        echo -e "  ${C_MAG}=== tower survey ===${C_RESET}"
        echo -e "  gps:    ${C_GRN}$gps${C_RESET}"
        echo -e "  points: ${C_GRN}$(tmap_point_count)${C_RESET}"
        echo -e "  store:  ${C_DIM}$TMAP_POINTS${C_RESET}\n"
        cat << 'M'
  [1]  GPS survey pass (GSM 900)
  [2]  GPS survey pass (LTE)
  [3]  start gpsd
  [4]  show GPS quality
  [5]  list points
  [6]  export CSV
  [7]  export KML
  [8]  export GeoJSON
  [9]  clear survey
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) tmap_run_survey gsm GSM900; read -rp "  press enter " _ ;;
            2) tmap_run_survey lte; read -rp "  press enter " _ ;;
            3) read -rp "  gps device [/dev/ttyUSB0]> " dev
               tmap_start_gpsd "${dev:-/dev/ttyUSB0}"; sleep 1 ;;
            4)
               if tmap_gps_read; then ok "fix acquired"; else warn "no fix"; fi
               read -rp "  press enter " _ ;;
            5) tmap_list | column -t -s$'\t' 2>/dev/null || tmap_list
               read -rp "  press enter " _ ;;
            6) tmap_export_csv; read -rp "  press enter " _ ;;
            7) tmap_export_kml; read -rp "  press enter " _ ;;
            8) tmap_export_geojson; read -rp "  press enter " _ ;;
            9) tmap_clear; sleep 1 ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
tmap_cli_status_tsv() {
    local gps="absent"
    if tmap_gps_available; then
        tmap_gps_running && gps="running" || gps="stopped"
    fi
    printf 'gps\t%s\n'     "$gps"
    printf 'points\t%s\n'  "$(tmap_point_count)"
    printf 'dir\t%s\n'     "$TMAP_DIR"
    printf 'store\t%s\n'   "$TMAP_POINTS"
}

tmap_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   tmap_cli_status_tsv ;;
        --survey)       tmap_run_survey "${1:-gsm}" "${2:-}" ;;
        --list)         tmap_list ;;
        --list-tsv)     tmap_list ;;
        --history)      tmap_history ;;
        --export-csv)   tmap_export_csv ;;
        --export-kml)   tmap_export_kml ;;
        --export-geojson) tmap_export_geojson ;;
        --clear)        tmap_clear ;;
        --start-gpsd)   tmap_start_gpsd "${1:-/dev/ttyUSB0}" ;;
        --gps-quality-tsv)
            local fix
            if fix=$(tmap_gps_read); then
                printf 'fix\tyes\nlat\t%s\nlon\t%s\nalt\t%s\nspeed\t%s\n' \
                    "$(cut -f1 <<<"$fix")" "$(cut -f2 <<<"$fix")" \
                    "$(cut -f3 <<<"$fix")" "$(cut -f4 <<<"$fix")"
            else
                printf 'fix\tno\n'
            fi ;;
        --selftest)     tmap_selftest ;;
        --menu)         tmap_menu ;;
        *)
            cat >&2 <<EOF
Tower Survey — GPS-tagged cell survey with map export

Usage: $0 COMMAND
  --status-tsv              GPS and store state as TSV
  --survey <gsm|lte> [BAND]  one survey pass, one point per cell
  --list-tsv                recorded points as TSV
  --history                 point accounting (with fix, without, distinct cells)
  --gps-quality-tsv         current fix, or fix\tno
  --start-gpsd [DEVICE]     start gpsd on DEVICE (default /dev/ttyUSB0)
  --export-csv              write the survey as CSV
  --export-kml              write the survey as KML (points with a fix only)
  --export-geojson          write the survey as GeoJSON
  --clear                   empty the survey store
  --selftest                verify the store and exporters without GPS
  --menu                    interactive menu
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
    tmap_cli_main "$@"
fi
