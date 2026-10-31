#!/usr/bin/env bash
# tower survey / war-drive — GPS-tagged cell survey with map export
#
# Two things this module can say that a survey alone cannot: where the towers
# that were never heard are (imported from a published database), and how dense
# they are without reading four hundred coordinates (a coarse grid).
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
# Imported towers live beside the survey points, not in them: a published
# position was advertised by a third party and a survey point was measured
# here, and the two stores are what keeps that difference visible.
TMAP_TOWERS="$TMAP_DIR/towers.tsv"
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

# ── imported tower database ─────────────────────────────────────────────
#
# A survey only knows what its own receiver heard. On the first drive through a
# city that is a handful of cells and a blank map, and a blank map reads as
# "there are no towers here" when the truth is "nobody has looked here yet".
# OpenCellID and the Mozilla Location Service both publish cell positions, so
# an operator's existing coverage can be seen before a single point is taken.
#
# Nothing is downloaded: these verbs read a CSV that is already on disk, so the
# answer never depends on a network this module cannot see or check.
#
# The imports write to a tower store of their own rather than into points.tsv.
# The survey store is measured, the imported store is advertised, and merging
# them at rest would erase the one distinction the whole toolkit is built on.
# --store-tsv is the single place where the two are joined, and every row that
# comes out of it says which kind of fact it is.

# The tower store's columns are the fields the importers can actually fill.
# There is no operator name because neither format carries one (mcc/mnc is an
# identity, not a brand) and no generation column because it is derivable from
# the radio name -- a stored copy is a second answer that can disagree later.
tmap_towers_header() {
    printf 'source\trat\tmcc\tmnc\tlac\tcell_id\tlat\tlon\trange_m\tsamples\tavg_signal\timported_ts\n'
}

# An import that created its store only after a successful parse would leave a
# real export merged into an unheaded file; creating the header first means the
# store is readable by another verb even when every row of the file is rejected.
tmap_towers_init() {
    mkdir -p "$TMAP_DIR"
    [[ -f "$TMAP_TOWERS" ]] || tmap_towers_header > "$TMAP_TOWERS"
}

# Counting the store is how every other verb decides whether it has anything to
# work with, so it answers 0 for an absent file instead of failing: absence and
# emptiness are the same refusal, one level up.
tmap_tower_count() {
    [[ -f "$TMAP_TOWERS" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$TMAP_TOWERS" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# Both stores, reduced to the only two columns a grid needs, with the numeric
# test in place: a coordinate that is not a number would otherwise be read by
# awk arithmetic as zero and land a tower in the Gulf of Guinea.
tmap_positioned() {
    local re='^[-+]?[0-9]+([.][0-9]+)?$'
    if [[ -f "$TMAP_TOWERS" ]]; then
        tail -n +2 "$TMAP_TOWERS" 2>/dev/null |
            awk -F'\t' -v re="$re" '$7 ~ re && $8 ~ re { printf "%s\t%s\n", $7, $8 }'
    fi
    if [[ -f "$TMAP_POINTS" ]]; then
        tail -n +2 "$TMAP_POINTS" 2>/dev/null |
            awk -F'\t' -v re="$re" '$2 ~ re && $3 ~ re { printf "%s\t%s\n", $2, $3 }'
    fi
}

# Import one published tower export and say exactly what happened to every row.
#
# The report exists because an import that silently drops half a file is worse
# than no import: the map then shows the half that parsed and looks complete.
# Rows are therefore counted into named reasons -- a row with no coordinates, a
# latitude of 500, a non-numeric mcc and the rest -- and read == imported +
# rejected is the property the selftest holds this to.
#
# Deduplication is per source. The same cell in OpenCellID and in MLS is two
# independent claims about one tower, so both are kept; the same cell twice in
# one file is one claim written twice, so the second copy is refused.
tmap_import() {  # <opencellid|mls> <file.csv> [--help]
    local fmt="${1:-}" file=""
    case "$fmt" in
        opencellid|mls) ;;
        *)
            printf 'ERROR\tthe importer reads opencellid and mls exports, not %s\n' \
                "$(tmap_sanitize "$fmt")" >&2
            printf 'WHY\teach format has its own column order, and guessing which one a file is would put a longitude in a latitude field\n' >&2
            return 2 ;;
    esac
    (($# > 0)) && shift
    while (($#)); do
        case "$1" in
            --help|-h) printf 'usage: --import-%s <file.csv>\n' "$fmt"; return 0 ;;
            -*)
                printf 'ERROR\t--import-%s does not take %s\n' "$fmt" "$(tmap_sanitize "$1")" >&2
                return 2 ;;
            *)
                if [[ -n "$file" ]]; then
                    printf 'ERROR\t--import-%s takes one file, not %s and %s\n' \
                        "$fmt" "$(tmap_sanitize "$file")" "$(tmap_sanitize "$1")" >&2
                    return 2
                fi
                file="$1"; shift ;;
        esac
    done
    [[ -n "$file" ]] || {
        printf 'ERROR\t--import-%s needs a CSV file\n' "$fmt" >&2
        printf 'WHY\tthere is nothing to import without a file, and an empty tower list would look like a successful import of nothing\n' >&2
        return 2; }
    [[ -r "$file" ]] || {
        printf 'MISSING\t%s\n' "$(tmap_sanitize "$file")" >&2
        printf 'WHY\tthis verb reads an export that is already on disk; it never fetches one, so an absent file cannot be substituted for\n' >&2
        printf 'verdict\tunobserved\n'
        printf 'reason\tno-file: no CSV at that path, so no row was read and no tower was placed\n'
        return 1; }

    tmap_towers_init
    local rep
    # The reasons are checked in a fixed order so a row with two problems lands
    # in the same bucket on every run: a file counted twice must agree with
    # itself, or the numbers are not a measurement.
    rep=$(awk -v fmt="$fmt" -v existing="$TMAP_TOWERS" -v store="$TMAP_TOWERS" \
              -v stage="$(date -Is)" -v bom="$(printf '\357\273\277')" '
        function tf(s) { gsub(/^[ \t]+/, "", s); gsub(/[ \t]+$/, "", s); return s }
        function saf(s) { gsub(/[\t\r\n]/, " ", s); return s }
        function isnum(s) { return s ~ /^[-+]?[0-9]+([.][0-9]+)?$/ }
        function isint(s) { return s ~ /^[0-9]+$/ }
        function rej(r) { rejected++; hits[r] = hits[r] + 1 }
        BEGIN {
            FS = ","
            need = (fmt == "opencellid") ? 13 : 11
            nb = split("field-count no-coordinates lat-not-a-number lon-not-a-number lat-out-of-range lon-out-of-range plmn-not-numeric cell-id-not-numeric null-island duplicate", bucket, " ")
            if (existing != "") {
                keep = FS
                FS = "\t"
                while ((getline ln < existing) > 0) {
                    n = split(ln, f, "\t")
                    if (n >= 6) seen[f[1] SUBSEP f[2] SUBSEP f[3] "-" f[4] SUBSEP f[5] SUBSEP f[6]] = 1
                }
                close(existing)
                FS = keep
            }
        }
        {
            gsub(/\r/, "")
            # A byte-order mark in front of the first line would otherwise turn
            # the header into a data row and be counted as a rejection.
            if (!bomdone) { sub(bom, ""); bomdone = 1 }
            if ($0 ~ /^[ \t]*$/) next
            if ($0 ~ /^[ \t]*#/) next
            if (!data_seen) {
                data_seen = 1
                h = tolower(tf($1))
                if (h == "radio" || h == "mcc") { nheader = 1; next }
            }
            nread++
            if (fmt == "opencellid") {
                radio = $1; mcc = $2; mnc = $3; lac = $4; cid = $5
                lon = $6; lat = $7; rng = $8; smp = $9; avg = $13
            } else {
                radio = ""; mcc = $1; mnc = $2; lac = $3; cid = $4
                lon = $5; lat = $6; rng = $7; smp = $8; avg = ""
            }
            if (NF < need) { rej("field-count"); next }
            radio = tf(radio); mcc = tf(mcc); mnc = tf(mnc); lac = tf(lac); cid = tf(cid)
            lon = tf(lon); lat = tf(lat); rng = tf(rng); smp = tf(smp); avg = tf(avg)
            if (lat == "" || lon == "") { rej("no-coordinates"); next }
            if (!isnum(lat)) { rej("lat-not-a-number"); next }
            if (!isnum(lon)) { rej("lon-not-a-number"); next }
            if (lat + 0 > 90 || lat + 0 < -90) { rej("lat-out-of-range"); next }
            if (lon + 0 > 180 || lon + 0 < -180) { rej("lon-out-of-range"); next }
            if (!isint(mcc) || length(mcc) != 3) { rej("plmn-not-numeric"); next }
            if (!isint(mnc) || length(mnc) > 3) { rej("plmn-not-numeric"); next }
            if (!isint(lac) || !isint(cid)) { rej("cell-id-not-numeric"); next }
            if (lat + 0 == 0 && lon + 0 == 0) { rej("null-island"); next }
            key = fmt SUBSEP radio SUBSEP mcc "-" mnc SUBSEP lac SUBSEP cid
            if (key in seen) { rej("duplicate"); next }
            seen[key] = 1
            print fmt "\t" saf(radio) "\t" mcc "\t" mnc "\t" lac "\t" cid "\t" lat "\t" lon \
                  "\t" saf(rng) "\t" saf(smp) "\t" saf(avg) "\t" stage >> store
            imported++
        }
        END {
            printf "rows_read\t%d\n", nread
            printf "header_skipped\t%d\n", nheader
            printf "rows_imported\t%d\n", imported
            printf "rows_rejected\t%d\n", rejected
            for (i = 1; i <= nb; i++)
                printf "reject_reason\t%s\t%d\n", bucket[i], (bucket[i] in hits) ? hits[bucket[i]] : 0
        }' "$file") || {
        printf 'ERROR\treading %s failed\n' "$(tmap_sanitize "$file")" >&2
        return 1; }

    local nimp nrej
    nimp=$(fldk "$rep" rows_imported)
    nrej=$(fldk "$rep" rows_rejected)
    printf 'source\t%s\n' "$fmt"
    printf 'file\t%s\n' "$(tmap_sanitize "$file")"
    printf '%s\n' "$rep"
    printf 'towers_total\t%s\n' "$(tmap_tower_count)"
    printf 'store\t%s\n' "$TMAP_TOWERS"

    (( ${nimp:-0} > 0 )) || {
        printf 'MISSING\timportable-towers\n' >&2
        printf 'WHY\t%s row(s) were read and %s could not be placed, so nothing was merged and an unchanged store must not be reported as a finished import\n' \
            "$(fldk "$rep" rows_read)" "${nrej:-0}" >&2
        printf 'verdict\tunobserved\n'
        printf 'reason\tno-importable-rows: every row failed one of the reasons counted above\n'
        return 1; }
    return 0
}

# One field out of a key/value report, with the empty field tolerated.
# `read` would collapse a missing field; this is only ever used on two- and
# three-column numeric reports, where an absent key means 0.
fldk() {
    printf '%s\n' "${1:-}" | awk -F'\t' -v k="$2" '$1 == k { print $2; exit }'
}

# A coarse density grid over everything that knows where it is.
#
# A list of coordinates answers "is this tower known" and says nothing about
# shape: whether one drive crossed one cell or forty, whether the imported
# database is dense where this receiver is thin. A terminal is not a map, so
# this is deliberately coarse -- and every count is printed next to the cell
# size and the approximate metres it covers, because a density without its
# resolution is a picture of the font rather than of the towers.
tmap_heatmap() {  # [--cell-deg N] [--help]
    local cell_deg="0.05"
    while (($#)); do
        case "$1" in
            --cell-deg)
                cell_deg="${2:-}"
                [[ -n "$cell_deg" ]] || {
                    printf 'ERROR\t--cell-deg needs a number of degrees\n' >&2
                    printf 'WHY\tthe cell size is the resolution of every count drawn below it; a blank one leaves the grid with no meaning to state\n' >&2
                    return 2; }
                shift 2 ;;
            --help|-h) printf 'usage: --heatmap [--cell-deg 0.05]\n'; return 0 ;;
            *)
                printf 'ERROR\t--heatmap does not take %s\n' "$(tmap_sanitize "$1")" >&2
                return 2 ;;
        esac
    done
    awk -v d="$cell_deg" 'BEGIN { exit !(d ~ /^[0-9]+([.][0-9]+)?$/ && d + 0 > 0) }' || {
        printf 'ERROR\t--cell-deg must be degrees as a positive number, not %s\n' \
            "$(tmap_sanitize "$cell_deg")" >&2
        printf 'WHY\ta zero cell would divide the grid by nothing\n' >&2
        return 2; }

    local pos="$MOD_TMP/heat.$$.tsv"
    tmap_positioned > "$pos" 2>/dev/null
    local npos nall nunpos
    npos=$(grep -c . "$pos" 2>/dev/null || true); [[ -z "$npos" ]] && npos=0
    nall=$(( $(tmap_point_count) + $(tmap_tower_count) ))
    nunpos=$(( nall - npos )); (( nunpos < 0 )) && nunpos=0

    (( npos > 0 )) || {
        rm -f "$pos"
        printf 'MISSING\tpositioned-towers\n'
        printf 'WHY\ta grid of towers needs coordinates and %s known row(s) carry none, so an empty grid would claim this area has no towers when the truth is that nothing here has been placed\n' \
            "$nall"
        printf 'verdict\tunobserved\n'
        printf 'reason\tno-positioned-towers: an empty map is not an empty world\n'
        return 1; }

    local bb mnla mxla mnlo mxlo dims cols rows_
    bb=$(awk -F'\t' 'NR == 1 { mnla = $1 + 0; mxla = $1 + 0; mnlo = $2 + 0; mxlo = $2 + 0 }
                     { if ($1 + 0 < mnla) mnla = $1 + 0; if ($1 + 0 > mxla) mxla = $1 + 0
                       if ($2 + 0 < mnlo) mnlo = $2 + 0; if ($2 + 0 > mxlo) mxlo = $2 + 0 }
                     END { printf "%s\t%s\t%s\t%s\n", mnla, mxla, mnlo, mxlo }' "$pos")
    mnla=$(cut -f1 <<< "$bb"); mxla=$(cut -f2 <<< "$bb")
    mnlo=$(cut -f3 <<< "$bb"); mxlo=$(cut -f4 <<< "$bb")

    # 1e-9 before the truncation: 2.35 - 2.30 is 0.04999999999999982 in binary
    # floating point, and a tower exactly on a cell edge would otherwise be
    # counted in the cell below it.
    dims=$(awk -v mnla="$mnla" -v mxla="$mxla" -v mnlo="$mnlo" -v mxlo="$mxlo" -v d="$cell_deg" \
        'BEGIN { c = int((mxlo - mnlo) / d + 1e-9) + 1; r = int((mxla - mnla) / d + 1e-9) + 1
                 printf "%d\t%d\n", c, r }')
    cols=$(cut -f1 <<< "$dims"); rows_=$(cut -f2 <<< "$dims")

    if (( cols * rows_ > 4096 )); then
        rm -f "$pos"
        printf 'ERROR\t--cell-deg %s draws a %sx%s grid (over 4096 cells) over this bounding box\n' \
            "$cell_deg" "$cols" "$rows_" >&2
        printf 'WHY\tthis verb is a coarse look at density in a terminal; a finer cell needs a drawing tool, and %s already writes one for it\n' \
            '--export-geojson' >&2
        return 2
    fi

    local mns mew stats
    mns=$(awk -v d="$cell_deg" 'BEGIN { printf "%d", 111320 * d + 0.5 }')
    mew=$(awk -v mnla="$mnla" -v mxla="$mxla" -v d="$cell_deg" \
        'BEGIN { c = (mnla + mxla) / 2; printf "%d", 111320 * d * cos(c * 3.14159265358979 / 180) + 0.5 }')
    stats=$(awk -F'\t' -v mnla="$mnla" -v mnlo="$mnlo" -v d="$cell_deg" '
        BEGIN { cols = 0 }
        { r = int(($1 - mnla) / d + 1e-9); c = int(($2 - mnlo) / d + 1e-9)
          if (!((r SUBSEP c) in g)) used++
          g[r SUBSEP c]++ }
        END { max = 0; for (k in g) if (g[k] > max) max = g[k]
              printf "%d\t%d\n", used, max }' "$pos")

    printf 'heatmap\n'
    printf 'cell_deg\t%.6f\n' "$cell_deg"
    printf 'grid_cols\t%s\n' "$cols"
    printf 'grid_rows\t%s\n' "$rows_"
    printf 'positioned\t%s\n' "$npos"
    printf 'unpositioned\t%s\n' "$nunpos"
    printf 'bbox_min_lat\t%s\n' "$mnla"
    printf 'bbox_max_lat\t%s\n' "$mxla"
    printf 'bbox_min_lon\t%s\n' "$mnlo"
    printf 'bbox_max_lon\t%s\n' "$mxlo"
    printf 'cell_m_north_south\t%s\n' "$mns"
    printf 'cell_m_east_west\t%s\n' "$mew"
    printf 'cells_used\t%s\n' "$(cut -f1 <<< "$stats")"
    printf 'max_cell\t%s\n' "$(cut -f2 <<< "$stats")"
    printf 'legend\t. = no tower | 1-9 = that many towers | # = 10 or more | first row is the north edge, first column the west edge\n'
    printf 'grid\tbegin\n'
    awk -F'\t' -v mnla="$mnla" -v mnlo="$mnlo" -v d="$cell_deg" -v cols="$cols" -v rows="$rows_" '
        BEGIN { cols = cols + 0; rows = rows + 0 }
        { r = int(($1 - mnla) / d + 1e-9); c = int(($2 - mnlo) / d + 1e-9)
          if (c < 0) c = 0; if (c > cols - 1) c = cols - 1
          if (r < 0) r = 0; if (r > rows - 1) r = rows - 1
          g[r, c]++ }
        END {
            for (r = rows - 1; r >= 0; r--) {
                line = ""
                for (c = 0; c < cols; c++) {
                    n = g[r, c] + 0
                    if (n == 0) line = line "."
                    else if (n < 10) line = line n
                    else line = line "#"
                }
                print line
            }
        }' "$pos"
    printf 'grid\tend\n'
    rm -f "$pos"
    return 0
}

# The merged store: survey points and imported towers, one header, one row per
# tower, because every consumer -- this module's exporters, the GUI, another
# module reading the loot directory -- would otherwise have to know which of
# two files a tower came from and how that file orders its columns.
#
# The last column carries the difference instead of hiding it: `measured` is a
# position this machine derived from a fix, `advertised` is a position a third
# party published. They are not the same kind of fact and a consumer that
# treats them as one will eventually report a database as a survey.
#
# plmn is mcc-mnc exactly as the source wrote it, unpadded: an MNC of "1" is
# printed "1" and not "01", because padding it is a claim about how many digits
# that network uses.
tmap_store_tsv() {
    # This verb has no modifiers, and silently ignoring one would let a caller
    # believe it filtered the table when it did not.
    while (($#)); do
        case "$1" in
            --help|-h) printf 'usage: --store-tsv\t(no arguments)\n'; return 0 ;;
            *) printf 'ERROR\t--store-tsv does not take %s\n' "$1"; return 2 ;;
        esac
    done
    printf 'origin\tlat\tlon\talt_m\tspeed_mps\trat\tgen\tarfcn\tplmn\tcell_id\trsrp_dbm\toperator\tevidence\n'
    if [[ -f "$TMAP_POINTS" ]]; then
        tail -n +2 "$TMAP_POINTS" 2>/dev/null |
            awk -F'\t' 'NF >= 12 { printf "survey\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tmeasured\n", $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 }'
    fi
    if [[ -f "$TMAP_TOWERS" ]]; then
        # The generation is derived here rather than stored: CDMA and iDEN also
        # appear in published exports and neither maps onto one generation, so
        # an unknown radio leaves the column empty instead of guessing.
        tail -n +2 "$TMAP_TOWERS" 2>/dev/null |
            awk -F'\t' 'NF >= 12 {
                r = toupper($2)
                if (r == "GSM") g = "2G"
                else if (r == "UMTS") g = "3G"
                else if (r == "LTE") g = "4G"
                else if (r == "NR") g = "5G"
                else g = ""
                printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tadvertised\n", $1, $7, $8, "", "", $2, g, "", $3 "-" $4, $6, $11, ""
            }'
    fi
    local n
    n=$(( $(tmap_point_count) + $(tmap_tower_count) ))
    (( n > 0 )) || {
        # Every word of the refusal goes to stderr: stdout is the table other
        # verbs and the GUI parse, and a verdict line in the middle of it would
        # be a row with two columns that no reader expects.
        printf 'MISSING\ttowers\n' >&2
        printf 'WHY\tneither a survey point nor an imported tower has been recorded, so the store holds a header and no rows, and a consumer must not read that as an area surveyed and found empty\n' >&2
        printf 'verdict\tunobserved\n' >&2
        printf 'reason\tempty-store: nothing has been measured and nothing has been imported\n' >&2
        return 1; }
    return 0
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
    # The import report breaks rejections out as reject_reason<TAB>name<TAB>n.
    rz()  { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1=="reject_reason" && $2==k {print $3; exit}'; }
    # The grid is delimited by grid<TAB>begin / grid<TAB>end so its shape can
    # be asserted as a shape rather than by eye.
    grid() {
        printf '%s\n' "$1" | awk -F'\t' '
            $1 == "grid" && $2 == "begin" { on = 1; next }
            $1 == "grid" && $2 == "end"   { on = 0; next }
            on { printf "%s%s", (n++ ? "," : ""), $0 }'
    }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot" TMAP_DIR="$d/loot/tower_map" TMAP_POINTS="$d/loot/tower_map/points.tsv" \
           TMAP_TOWERS="$d/loot/tower_map/towers.tsv"

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

    # 12. Import an OpenCellID export. The fixture writes one row for every way
    #     a tower can fail to be placeable -- no coordinates, a latitude of
    #     500, a non-numeric mcc, a longitude that is not a number, 0/0, a
    #     truncated row, and the same cell twice -- so each bucket has to be
    #     counted, not just the total.
    local ocid="$d/opencellid.csv"
    {
        printf 'radio,mcc,mnc,lac,cid,lon,lat,range,samples,changeable,created,updated,averageSignal\n'
        printf 'GSM,208,1,9001,11111,2.3500,48.8500,1000,7,1,1600000000,1600000100,-85\n'
        printf 'LTE,208,1,9002,11112,2.4000,48.9000,500,3,1,1600000000,1600000100,-95\n'
        printf 'UMTS,208,10,9003,11113,2.3000,48.8000,300,1,1,1600000000,1600000100,-101\n'
        printf 'LTE,208,1,9004,11114,,48.9000,500,3,1,1600000000,1600000100,-95\n'
        printf 'GSM,208,1,9005,11115,2.3000,500,500,3,1,1600000000,1600000100,-85\n'
        printf 'GSM,20X,1,9006,11116,2.3000,48.8000,500,3,1,1600000000,1600000100,-85\n'
        printf 'GSM,208,1,9007,11117,0,0,500,3,1,1600000000,1600000100,-85\n'
        printf 'GSM,208,1,9001,11111,2.3500,48.8500,1000,7,1,1600000000,1600000100,-85\n'
        printf 'LTE,208,1,9008,11118,2.5\n'
        printf 'GSM,208,1,9009,11119,abc,48.8000,500,3,1,1600000000,1600000100,-85\n'
    } > "$ocid"
    local rep; rep=$(tmap_import opencellid "$ocid")
    chk ocid-rc          "$?" "0"
    chk ocid-header      "$(fld "$rep" header_skipped)" "1"
    chk ocid-read        "$(fld "$rep" rows_read)" "10"
    chk ocid-imported    "$(fld "$rep" rows_imported)" "3"
    chk ocid-rejected    "$(fld "$rep" rows_rejected)" "7"
    chk ocid-accounting  "$(( $(fld "$rep" rows_imported) + $(fld "$rep" rows_rejected) ))" "10"
    chk ocid-rej-fields  "$(rz "$rep" field-count)" "1"
    chk ocid-rej-coord   "$(rz "$rep" no-coordinates)" "1"
    chk ocid-rej-latnum  "$(rz "$rep" lat-not-a-number)" "0"
    chk ocid-rej-lonnum  "$(rz "$rep" lon-not-a-number)" "1"
    chk ocid-rej-latrng  "$(rz "$rep" lat-out-of-range)" "1"
    chk ocid-rej-lonrng  "$(rz "$rep" lon-out-of-range)" "0"
    chk ocid-rej-plmn    "$(rz "$rep" plmn-not-numeric)" "1"
    chk ocid-rej-cellid  "$(rz "$rep" cell-id-not-numeric)" "0"
    chk ocid-rej-null    "$(rz "$rep" null-island)" "1"
    chk ocid-rej-dup     "$(rz "$rep" duplicate)" "1"
    chk ocid-store-rows  "$(tmap_tower_count)" "3"
    chk ocid-store-cols  "$(head -1 "$TMAP_TOWERS" | awk -F'\t' '{print NF}')" "12"
    chk ocid-source      "$(cut -f1 "$TMAP_TOWERS" | tail -n +2 | sort -u)" "opencellid"

    # 13. The MLS export has its own column order, and the same cell as an
    #     OpenCellID row is kept rather than de-duplicated: two sources that
    #     agree are two claims about one tower, not one claim written twice.
    local mls="$d/mls.csv"
    {
        printf 'mcc,mnc,lac,cellid,lon,lat,range,samples,changeable,created,updated\n'
        printf '208,1,9101,22221,2.3600,48.8600,800,5,1,1600000000,1600000100\n'
        printf '208,1,9102,22222,2.3700,48.8700,800,5,1,1600000000,1600000100\n'
        printf '208,1,9101,22221,2.3600,48.8600,800,5,1,1600000000,1600000100\n'
        printf '208,1,9103,22223,200.0000,48.0000,800,5,1,1600000000,1600000100\n'
        printf '208,10,9003,11113,2.3000,48.8000,300,1,1,1600000000,1600000100\n'
        printf '208,1,9106,22226,,48.8000,800,5,1,1600000000,1600000100\n'
    } > "$mls"
    local mrep; mrep=$(tmap_import mls "$mls")
    chk mls-rc           "$?" "0"
    chk mls-read         "$(fld "$mrep" rows_read)" "6"
    chk mls-imported     "$(fld "$mrep" rows_imported)" "3"
    chk mls-rejected     "$(fld "$mrep" rows_rejected)" "3"
    chk mls-rej-dup      "$(rz "$mrep" duplicate)" "1"
    chk mls-rej-lonrng   "$(rz "$mrep" lon-out-of-range)" "1"
    chk mls-rej-coord    "$(rz "$mrep" no-coordinates)" "1"
    chk mls-store-rows   "$(tmap_tower_count)" "6"
    chk mls-store-rat    "$(awk -F'\t' '$1=="mls"{print $2}' "$TMAP_TOWERS" | sort -u)" ""

    # 14. Re-importing the same file must import nothing: the store already
    #     holds every placeable row, and a second copy would double the map.
    local rep2; rep2=$(tmap_import opencellid "$ocid" 2>/dev/null)
    chk reimport-rc       "$?" "1"
    chk reimport-imported "$(fld "$rep2" rows_imported)" "0"
    chk reimport-dup      "$(rz "$rep2" duplicate)" "4"
    chk reimport-store    "$(tmap_tower_count)" "6"

    # 15. An import of a file where nothing can be placed is a refusal with the
    #     reasons attached, not a quiet success that changed nothing.
    local badcsv="$d/bad.csv"
    printf 'GSM,208,1,9001,11111,,48.85,1000,7,1,1,1,-85\n' > "$badcsv"
    local brep brc
    brep=$(tmap_import opencellid "$badcsv" 2>&1); brc=$?
    chk badimport-rc     "$brc" "1"
    chk badimport-read   "$(fld "$brep" rows_read)" "1"
    chk badimport-msg    "$(printf '%s\n' "$brep" | grep -c '^MISSING')" "1"
    chk badimport-why    "$(printf '%s\n' "$brep" | grep -c '^WHY')" "1"
    chk badimport-store  "$(tmap_tower_count)" "6"

    # 16. Import argument errors are usage errors, not refusals.
    chk import-noarg-rc  "$(tmap_import opencellid >/dev/null 2>&1; echo $?)" "2"
    chk import-nofile-rc "$(tmap_import opencellid "$d/absent.csv" >/dev/null 2>&1; echo $?)" "1"
    chk import-nofile-msg "$(tmap_import opencellid "$d/absent.csv" 2>&1 | grep -c '^MISSING')" "1"
    chk import-badfmt-rc "$(tmap_import csv "$badcsv" >/dev/null 2>&1; echo $?)" "2"
    chk import-twofile-rc "$(tmap_import mls "$mls" "$ocid" >/dev/null 2>&1; echo $?)" "2"

    # 17. The heatmap reads both stores: one measured point with a fix is added
    #     next to the imported towers, and one without a fix must be counted as
    #     unplaced rather than dropped in silence.
    printf '%s\n' "$(tmap_header)" > "$TMAP_POINTS"
    printf '2026-01-01T00:00:00Z\t48.85\t2.35\t35\t0\tLTE\t4G\t6300\t208-01\t11111\t-80\tOrange FR\n' >> "$TMAP_POINTS"
    printf '2026-01-01T00:10:00Z\t\t\t\t\tGSM\t2G\t42\t208-01\t99\t-70\tOrange FR\n' >> "$TMAP_POINTS"
    local hmap hrc
    hmap=$(tmap_heatmap); hrc=$?
    chk heat-rc        "$hrc" "0"
    chk heat-deg       "$(fld "$hmap" cell_deg)" "0.050000"
    chk heat-cols      "$(fld "$hmap" grid_cols)" "3"
    chk heat-rows      "$(fld "$hmap" grid_rows)" "3"
    chk heat-positioned "$(fld "$hmap" positioned)" "7"
    chk heat-unpositioned "$(fld "$hmap" unpositioned)" "1"
    chk heat-cells-used "$(fld "$hmap" cells_used)" "3"
    chk heat-max-cell  "$(fld "$hmap" max_cell)" "4"
    chk heat-legend    "$(printf '%s\n' "$hmap" | grep -c '^legend')" "1"
    chk heat-res-ns    "$([[ "$(fld "$hmap" cell_m_north_south)" =~ ^[0-9]+$ ]] && echo yes || echo no)" "yes"
    # Four towers around 48.85/2.35 (three imported, one measured), one in the
    # north-east cell, two in the south-west cell.
    chk heat-grid      "$(grid "$hmap")" "..1,.4.,2.."
    chk heat-grid-shape "$(printf '%s\n' "$hmap" | awk -F'\t' '
            $1=="grid"&&$2=="begin"{on=1;next} $1=="grid"&&$2=="end"{on=0} on{print length($0)}' |
            sort -u | tr '\n' ',')" "3,"

    # 18. With nothing positioned the heatmap refuses by name, and says why an
    #     empty grid is not evidence about the world.
    local sp="$TMAP_POINTS" st="$TMAP_TOWERS"
    mkdir -p "$d/empty/loot/tower_map"
    TMAP_POINTS="$d/empty/loot/tower_map/points.tsv"
    TMAP_TOWERS="$d/empty/loot/tower_map/towers.tsv"
    tmap_init_store
    local href2 hrc2
    href2=$(tmap_heatmap 2>&1); hrc2=$?
    chk heat-none-rc   "$hrc2" "1"
    chk heat-none-msg  "$(printf '%s\n' "$href2" | grep -c '^MISSING')" "1"
    chk heat-none-name "$(printf '%s\n' "$href2" | awk -F'\t' '$1=="MISSING"{print $2}')" "positioned-towers"
    chk heat-none-why  "$(printf '%s\n' "$href2" | grep -c '^WHY')" "1"
    chk heat-none-verdict "$(printf '%s\n' "$href2" | awk -F'\t' '$1=="verdict"{print $2}')" "unobserved"
    chk store-empty-rc "$(tmap_store_tsv >/dev/null 2>&1; echo $?)" "1"
    chk store-empty-hdr "$(tmap_store_tsv 2>/dev/null | awk -F'\t' '{print NF}')" "13"
    TMAP_POINTS="$sp"; TMAP_TOWERS="$st"

    # 19. The merged store carries both kinds of fact and says which is which.
    local stv
    stv=$(tmap_store_tsv)
    chk store-cols     "$(printf '%s\n' "$stv" | head -1 | awk -F'\t' '{print NF}')" "13"
    chk store-rows     "$(printf '%s\n' "$stv" | tail -n +2 | grep -c .)" "8"
    chk store-measured "$(printf '%s\n' "$stv" | awk -F'\t' '$13=="measured"' | grep -c .)" "2"
    chk store-advertised "$(printf '%s\n' "$stv" | awk -F'\t' '$13=="advertised"' | grep -c .)" "6"
    chk store-gen-2g   "$(printf '%s\n' "$stv" | awk -F'\t' '$2=="48.8500" && $7=="2G" && $13=="advertised"' | grep -c .)" "1"
    chk store-gen-4g   "$(printf '%s\n' "$stv" | awk -F'\t' '$7=="4G" && $13=="advertised" && $11=="-95"' | grep -c .)" "1"
    chk store-plmn     "$(printf '%s\n' "$stv" | awk -F'\t' '$13=="advertised" && $9=="208-10"' | grep -c .)" "2"
    chk store-unplaced "$(printf '%s\n' "$stv" | awk -F'\t' '$13=="measured" && $2==""' | grep -c .)" "1"
    chk store-arg-rc "$(tmap_store_tsv extra >/dev/null 2>&1; echo $?)" "2"

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
        echo -e "  towers: ${C_GRN}$(tmap_tower_count)${C_RESET}"
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
  [10] import OpenCellID CSV
  [11] import MLS CSV
  [12] tower heatmap
  [13] merged store (TSV)
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
            10) read -rp "  OpenCellID CSV path> " f
                [[ -n "$f" ]] && tmap_import opencellid "$f"
                read -rp "  press enter " _ ;;
            11) read -rp "  MLS CSV path> " f
                [[ -n "$f" ]] && tmap_import mls "$f"
                read -rp "  press enter " _ ;;
            12) read -rp "  cell size in degrees [0.05]> " cdeg
                if [[ -n "$cdeg" ]]; then tmap_heatmap --cell-deg "$cdeg"; else tmap_heatmap; fi
                read -rp "  press enter " _ ;;
            13) tmap_store_tsv | column -t -s$'\t' 2>/dev/null || tmap_store_tsv
                read -rp "  press enter " _ ;;
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
    printf 'towers\t%s\n'  "$(tmap_tower_count)"
    printf 'dir\t%s\n'     "$TMAP_DIR"
    printf 'store\t%s\n'   "$TMAP_POINTS"
    printf 'towers_store\t%s\n' "$TMAP_TOWERS"
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
        --import-opencellid) tmap_import opencellid "$@" ;;
        --import-mls)   tmap_import mls "$@" ;;
        --heatmap)      tmap_heatmap "$@" ;;
        --store-tsv)    tmap_store_tsv "$@" ;;
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
  --import-opencellid <csv>  merge an OpenCellID export into the tower store
  --import-mls <csv>        merge a Mozilla Location Service export
  --heatmap [--cell-deg N]  tower density grid over the store bounding box
  --store-tsv               survey points and imported towers as one TSV
  --clear                   empty the survey store
  --selftest                verify the store, the importers, the heatmap and the exporters without GPS
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
