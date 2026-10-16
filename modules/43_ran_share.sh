#!/usr/bin/env bash
# ran_share — RAN sharing: MOCN/MORAN/GWCN boundaries and cross-operator leakage.
#
# When operators share radio access (MOCN broadcasts several PLMNs from one
# carrier; MORAN shares the RAN but keeps separate carriers; GWCN also shares the
# core), a cell advertises a set of PLMNs, and only those. A PLMN seen from a
# cell that does not broadcast it is a boundary leak — the thing a sharing audit
# is looking for. This module encodes/decodes PLMNs per TS 24.008, classifies
# the sharing mode, and checks the broadcast set.
#
# Attack owned: O18/O20 adjacency (slicing/roaming boundary) — analysis half.
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
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

MOD_TMP="$TMP_DIR/ran_share"
RANS_DIR="$LOOT_DIR/ran_share"
mkdir -p "$MOD_TMP" "$RANS_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

rans_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
RANS_F=()
rans_split() {
    RANS_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        RANS_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

rans_status_tsv() {
    printf 'MODULE\tran_share\n'
    printf 'TARGET\tPLMN coding, MOCN/MORAN/GWCN, cross-operator leakage\n'
    printf 'TRANSMIT\tnone — encoding and boundary analysis\n'
    printf 'SELFTEST\tyes\n'
}

# ── PLMN coding (TS 24.008 §10.5.1.3) ───────────────────────────────────
#   octet 1: MCC digit 2 | MCC digit 1
#   octet 2: MNC digit 3 | MCC digit 3   (MNC digit 3 = F for a 2-digit MNC)
#   octet 3: MNC digit 2 | MNC digit 1
# Worked anchor: MCC 001 / MNC 01 -> 00 F1 10.
rans_plmn_encode() {
    local mcc="${1:-}" mnc="${2:-}"
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || { printf 'ERROR\tMCC must be 3 digits\n' >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || { printf 'ERROR\tMNC must be 2 or 3 digits\n' >&2; return 2; }
    local o1 o2 o3
    o1=$(( (10#${mcc:1:1} << 4) | 10#${mcc:0:1} ))
    if (( ${#mnc} == 3 )); then
        o2=$(( (10#${mnc:2:1} << 4) | 10#${mcc:2:1} ))
    else
        o2=$(( (0xF << 4) | 10#${mcc:2:1} ))
    fi
    o3=$(( (10#${mnc:1:1} << 4) | 10#${mnc:0:1} ))
    printf '%02X%02X%02X\n' "$o1" "$o2" "$o3"
}
rans_plmn_decode() {
    local h="${1:-}"
    h=$(printf '%s' "$h" | tr -d ' \t\r\n:.-' | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]{6}$ ]] || { printf 'ERROR\tPLMN must be 3 octets of hex\n' >&2; return 2; }
    local o1=$(( 16#${h:0:2} )) o2=$(( 16#${h:2:2} )) o3=$(( 16#${h:4:2} ))
    local mcc1=$(( o1 & 0xF )) mcc2=$(( (o1 >> 4) & 0xF )) mcc3=$(( o2 & 0xF ))
    local mnc1=$(( o3 & 0xF )) mnc2=$(( (o3 >> 4) & 0xF )) mnc3=$(( (o2 >> 4) & 0xF ))
    local mcc="${mcc1}${mcc2}${mcc3}" mnc
    if (( mnc3 == 0xF )); then mnc="${mnc1}${mnc2}"; else mnc="${mnc1}${mnc2}${mnc3}"; fi
    printf 'mcc\t%s\nmnc\t%s\nplmn\t%s-%s\n' "$mcc" "$mnc" "$mcc" "$mnc"
}

# ── equivalent-PLMN list (TS 24.008 §10.5.1.13: at most 15) ─────────────
rans_eplmn_check() {
    local list="${1:-}"
    [[ -n "$list" ]] || { printf 'ERROR\tempty PLMN list\n' >&2; return 2; }
    local count=0 plmn
    local IFS=','
    for plmn in $list; do
        [[ "$plmn" =~ ^[0-9]{3}-?[0-9]{2,3}$ ]] || { printf 'ERROR\tnot a PLMN: %s\n' "$plmn" >&2; return 2; }
        count=$(( count + 1 ))
    done
    printf 'count\t%d\nmax\t15\n' "$count"
    if (( count > 15 )); then printf 'verdict\tINVALID — the equivalent-PLMN list is capped at 15 (TS 24.008 §10.5.1.13)\n'
    else printf 'verdict\tok\n'; fi
}

# ── sharing-mode classification ─────────────────────────────────────────
rans_mode_classify() {
    local mode="${1:-}"
    case "${mode,,}" in
        mocn) printf 'mode\tMOCN\nran\tshared (one carrier broadcasts several PLMNs)\ncore\tseparate per operator\n' ;;
        moran) printf 'mode\tMORAN\nran\tshared infrastructure, one carrier per operator\ncore\tseparate per operator\n' ;;
        gwcn) printf 'mode\tGWCN\nran\tshared (one carrier)\ncore\tshared core network\n' ;;
        *) printf 'mode\tunknown\nran\tunknown\ncore\tunknown\nverdict\tunknown — never classified as a sharing mode\n' ;;
    esac
}

# ── cross-operator leakage ──────────────────────────────────────────────
# TSV: cell_id<TAB>broadcast_plmns (comma list)<TAB>observed_plmn<TAB>source.
# A PLMN observed on a cell that does not broadcast it is a boundary leak.
rans_leak_check() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such cell file: %s\n' "$file" >&2; return 1; }
    printf 'cell_id\tobserved_plmn\tverdict\tdetail\n'
    local leaks=0 line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == cell_id* || "$line" == \#* ]] && continue
        rans_split "$line"
        local cid="${RANS_F[0]:-}" bcast="${RANS_F[1]:-}" obs="${RANS_F[2]:-}"
        [[ -n "$obs" ]] || continue
        if [[ ",$bcast," == *",$obs,"* ]]; then
            printf '%s\t%s\tok\tbroadcast set includes the observed PLMN\n' "$(rans_sanitize "$cid")" "$(rans_sanitize "$obs")"
        else
            printf '%s\t%s\tLEAK\tobserved PLMN is not in the cell'"'"'s broadcast set {%s}\n' \
                "$(rans_sanitize "$cid")" "$(rans_sanitize "$obs")" "$(rans_sanitize "$bcast")"
            leaks=$(( leaks + 1 ))
        fi
    done < "$file"
    printf 'summary\tleaks\t%d\n' "$leaks"
    (( leaks == 0 )) || return 0
    return 0
}

rans_plan() {
    cat <<'EOF'
status	handoff
what	auditing a shared-RAN deployment end to end
hardware	a lab with two cores (Open5GS instances), one shared eNB/gNB, and UEs holding each operator's SIM
software	Open5GS MOCN support, a multi-PLMN SIB1 configuration, and the UE-side PLMN selection log
flow	1. encode the expected broadcast PLMN set here  2. capture the cell's SIB1  3. run --leak-check over the observed set
note	confirming a leak across two carriers needs both carriers' authorisation; this module analyses captures you hold
EOF
}

rans_selftest() {
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
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export RANS_DIR="$d/loot/ran_share"
    mkdir -p "$RANS_DIR"

    # 1. PLMN coding (TS 24.008 §10.5.1.3). 001-01 is the canonical test PLMN.
    chk plmn-00101 "$(rans_plmn_encode 001 01)" "00F110"
    chk plmn-dec-mcc "$(fld "$(rans_plmn_decode 00F110)" mcc)" "001"
    chk plmn-dec-mnc "$(fld "$(rans_plmn_decode 00F110)" mnc)" "01"
    # a 3-digit MNC takes the high nibble of octet 2.
    local e310; e310=$(rans_plmn_encode 310 260)
    chk plmn-310260 "$(fld "$(rans_plmn_decode "$e310")" plmn)" "310-260"
    chk plmn-3digit-len "$(( ${#e310} ))" "6"
    chk plmn-badmcc "$(rans_plmn_encode 31 260 >/dev/null 2>&1; echo $?)" "2"
    chk plmn-badmnc "$(rans_plmn_encode 310 2 >/dev/null 2>&1; echo $?)" "2"
    chk plmn-dec-bad "$(rans_plmn_decode 00 >/dev/null 2>&1; echo $?)" "2"

    # 2. Equivalent-PLMN cap.
    chk eplmn-ok "$(fld "$(rans_eplmn_check 310-260,310-410,312-530)" verdict)" "ok"
    chk eplmn-count "$(fld "$(rans_eplmn_check 310-260,310-410,312-530)" count)" "3"
    local big=""; local i
    for (( i=1; i<=16; i++ )); do big+="${big:+,}$(( 200 + i ))-01"; done
    chk eplmn-over "$(rans_eplmn_check "$big" | awk -F'\t' '$1=="verdict"{print ($2 ~ /INVALID/)?"invalid":"ok"}')" "invalid"
    chk eplmn-bad "$(rans_eplmn_check abc >/dev/null 2>&1; echo $?)" "2"
    chk eplmn-empty "$(rans_eplmn_check '' >/dev/null 2>&1; echo $?)" "2"

    # 3. Sharing-mode classification; unknown is never a mode.
    chk mode-mocn  "$(fld "$(rans_mode_classify mocn)" mode)" "MOCN"
    chk mode-moran "$(fld "$(rans_mode_classify MORAN)" mode)" "MORAN"
    chk mode-gwcn  "$(fld "$(rans_mode_classify gwcn)" mode)" "GWCN"
    chk mode-unknown "$(fld "$(rans_mode_classify wimax)" verdict)" "unknown — never classified as a sharing mode"

    # 4. Leak check: a PLMN outside the broadcast set is flagged, one inside abstains.
    printf 'cell_id\tbroadcast_plmns\tobserved_plmn\tsource\n' > "$d/cells.tsv"
    printf 'cellA\t310-260,310-410\t310-260\tSIB1\n' >> "$d/cells.tsv"
    printf 'cellA\t310-260,310-410\t312-530\tSIB1\n' >> "$d/cells.tsv"
    local out; out=$(rans_leak_check "$d/cells.tsv")
    chk leak-count "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary"{print $3}')" "1"
    chk leak-row   "$(printf '%s\n' "$out" | awk -F'\t' '$3=="LEAK"{print $2}')" "312-530"
    chk leak-ok-row "$(printf '%s\n' "$out" | awk -F'\t' '$3=="ok"{print $2}')" "310-260"
    chk leak-missing "$(rans_leak_check "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

rans_menu() {
    while true; do
        banner
        echo "  === RAN Sharing ==="
        echo
        cat <<'M'
  [1]  Encode a PLMN
  [2]  Decode a PLMN
  [3]  Equivalent-PLMN list check
  [4]  Classify a sharing mode
  [5]  Cross-operator leak check
  [6]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  mcc> " m; read -rp "  mnc> " n; rans_plmn_encode "$m" "$n"; read -rp "  enter " _ ;;
            2) read -rp "  plmn hex> " h; rans_plmn_decode "$h"; read -rp "  enter " _ ;;
            3) read -rp "  plmn list> " l; rans_eplmn_check "$l"; read -rp "  enter " _ ;;
            4) read -rp "  mode [mocn|moran|gwcn]> " m; rans_mode_classify "$m"; read -rp "  enter " _ ;;
            5) read -rp "  cell tsv> " p; rans_leak_check "$p"; read -rp "  enter " _ ;;
            6) rans_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

rans_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  rans_status_tsv ;;
        --plmn-encode) rans_plmn_encode "${1:-}" "${2:-}" ;;
        --plmn-decode) rans_plmn_decode "${1:-}" ;;
        --eplmn)       rans_eplmn_check "${1:-}" ;;
        --mode)        rans_mode_classify "${1:-}" ;;
        --leak-check)  rans_leak_check "${1:-}" ;;
        --plan)        rans_plan ;;
        --selftest)    rans_selftest ;;
        --menu)        rans_menu ;;
        *)
            cat >&2 <<EOF
RAN Sharing — PLMN coding, MOCN/MORAN/GWCN and cross-operator leakage

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --plmn-encode <mcc> <mnc>    TS 24.008 §10.5.1.3 PLMN coding
  --plmn-decode <hex>          decode a 3-octet PLMN
  --eplmn <list>               equivalent-PLMN list check (cap 15)
  --mode <mocn|moran|gwcn>     sharing-mode classification
  --leak-check <tsv>           PLMN-outside-broadcast-set detection
  --plan                       two-core lab handoff plan
  --selftest                   verify the codec and the detectors
  --menu                       interactive menu
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
    rans_cli_main "$@"
fi
