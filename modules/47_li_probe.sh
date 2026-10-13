#!/usr/bin/env bash
# li_probe — lawful-interception discovery: the interfaces, and what a capture
# can and cannot tell you about an intercept in progress.
#
# SCOPE, stated first: this module is detection-only. It models the 3GPP LI
# architecture (TS 33.107, TS 33.108, TS 33.128 for 5G), names the handover
# interfaces, and scores signalling patterns that a lawful intercept or an
# IMSI catcher tends to leave behind. It does not activate, provision or operate
# interception, and no such verb is dispatchable. The selftest asserts that.
#
# Attack owned: O12/O13 adjacency (tracking via the core) — detection half only.
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

MOD_TMP="$TMP_DIR/li_probe"
LIPR_DIR="$LOOT_DIR/li_probe"
mkdir -p "$MOD_TMP" "$LIPR_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

lipr_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
LIPR_F=()
lipr_split() {
    LIPR_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        LIPR_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

lipr_status_tsv() {
    printf 'MODULE\tli_probe\n'
    printf 'TARGET\t3GPP lawful-interception interfaces and interception-posture signals\n'
    printf 'SCOPE\tdetection-only — no activation, provisioning or interception verb\n'
    printf 'SELFTEST\tyes\n'
}

# ── LI interfaces (TS 33.107 / TS 33.108; 5G in TS 33.128) ──────────────
lipr_interfaces() {
    cat <<'EOF'
interface	handover	name	endpoints
X1	HI1	administration	ADMF -> DF2/DF3 (provisioning, target activation/deactivation)
X2	HI2	IRI	DF2 -> LEMF (intercept-related information: signalling events, not content)
X3	HI3	CC	DF3 -> LEMF (content of communication)
EOF
}
lipr_name_of() {
    case "$1" in
        X1|HI1) echo "administration (ADMF to DF2/DF3)" ;;
        X2|HI2) echo "IRI (DF2 to LEMF, signalling events)" ;;
        X3|HI3) echo "CC (DF3 to LEMF, content)" ;;
        *) echo "unknown interface — never classified as a handover interface" ;;
    esac
}
lipr_architecture() {
    cat <<'EOF'
node	role
ADMF	Administration Function — provisions intercepts; the only node that may activate a target
POI	Point of Interception — inside the network element (MME/AMF/UPF/HLR), not on the wire
DF2	Delivery Function 2 — mediates IRI (X2) toward the LEMF
DF3	Delivery Function 3 — mediates CC (X3) toward the LEMF
LEMF	Law Enforcement Monitoring Facility — the collection endpoint
EOF
}

# ── interception-posture scoring ────────────────────────────────────────
# A capture cannot prove an intercept is active; it can only show signalling
# that a lawful intercept or an IMSI catcher tends to produce. These are the
# signals, weighted, per TS 33.107 §6 and IMSI-catcher behaviour. Input TSV:
#   ts<TAB>imsi<TAB>event<TAB>cell<TAB>silent
# event in {identity_request, auth_request, location_update, sms, detach}.
lipr_score() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such signalling file: %s\n' "$file" >&2; return 1; }
    awk -F'\t' '
        NR==1 && $1 ~ /^ts/ { next }
        NF>=3 {
            imsi=$2; ev=$3; cell=$4
            cnt[imsi SUBSEP ev]++
            if (cell != "" && !(imsi SUBSEP "c" SUBSEP cell in seen)) { seen[imsi SUBSEP "c" SUBSEP cell]=1; nc[imsi]++ }
            if (imsi != "" && !(imsi in any)) any[imsi]=1
        }
        END {
            printf "finding\tseverity\timsi\tdetail\n"
            total=0
            for (imsi in any) {
                ir=cnt[imsi SUBSEP "identity_request"]+0
                ar=cnt[imsi SUBSEP "auth_request"]+0
                lu=cnt[imsi SUBSEP "location_update"]+0
                sm=cnt[imsi SUBSEP "silent_sms"]+0
                cells=nc[imsi]+0
                sc=0
                if (ir>=3) { printf "forced_identity_burst\tHIGH\t%s\t%d identity requests for one subscriber; repeated forced-identity is an LI/IMSI-catcher signature\n", imsi, ir; sc+=3 }
                if (sm>=1) { printf "silent_sms\tHIGH\t%s\t%d silent/undelivered SMS; used to verify a target is on the network\n", imsi, sm; sc+=2 }
                if (ar>=5) { printf "auth_storm\tMEDIUM\t%s\t%d authentication requests; a re-authentication burst\n", imsi, ar; sc+=1 }
                if (lu>=5) { printf "location_update_burst\tMEDIUM\t%s\t%d location updates\n", imsi, lu; sc+=1 }
                if (cells>=5) { printf "wide_cell_spread\tMEDIUM\t%s\tsubscriber seen across %d cells\n", imsi, cells; sc+=1 }
                total+=sc
                if (sc>=3) risk[imsi]="high"; else if (sc>=1) risk[imsi]="medium"; else risk[imsi]="low"
            }
            printf "summary\tscore\t%d\n", total
            band="low"; for (i in risk) { if (risk[i]=="high") band="high"; else if (risk[i]=="medium" && band!="high") band="medium" }
            printf "summary\trisk\t%s\n", band
        }' "$file"
}

lipr_report() {
    cat <<'EOF'
section	content
provenance	which capture, which interface point, timestamps in UTC, clock source
signals	the per-subscriber findings from --score, with the raw event counts
limits	the air interface does not carry an LI flag; these are heuristics, not proof
escalation	a carrier's own mediation/ADMF logs and the DF2 IRI feed are the admissible record
regulator	notify the national regulator with the measurement log; keep the capture chain of custody
EOF
}

lipr_plan() {
    cat <<'EOF'
status	handoff
what	confirming an intercept from the network side rather than inferring it
hardware	a lab core (Open5GS/Osmocom) with its ADMF/DF mediation, or an operator's lawful-authorisation audit
software	the mediation function's own logs, the X1 provisioning record, and the operator's LI-management audit trail
flow	1. collect signalling into the TSV this module scores  2. --score for the posture  3. --report for the handling
note	only the operator (or its national authority) can confirm an active intercept; this module never performs one
EOF
}

lipr_selftest() {
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
    export LIPR_DIR="$d/loot/li_probe"
    mkdir -p "$LIPR_DIR"

    # 1. Interface naming (TS 33.108): X1=HI1=admin, X2=HI2=IRI, X3=HI3=CC.
    chk if-x1 "$(lipr_name_of X1)" "administration (ADMF to DF2/DF3)"
    chk if-x2 "$(lipr_name_of X2)" "IRI (DF2 to LEMF, signalling events)"
    chk if-x3 "$(lipr_name_of X3)" "CC (DF3 to LEMF, content)"
    chk if-hi2 "$(lipr_name_of HI2)" "IRI (DF2 to LEMF, signalling events)"
    chk if-unknown "$(lipr_name_of X9)" "unknown interface — never classified as a handover interface"
    chk if-table-x2 "$(lipr_interfaces | awk -F'\t' '$1=="X2"{print $3}')" "IRI"

    # 2. A quiet subscriber scores low; a surveilled-looking one scores high.
    printf 'ts\timsi\tevent\tcell\tsilent\n' > "$d/quiet.tsv"
    printf '2026-01-01T00:00:00Z\t310150000000001\tlocation_update\tcellA\t\n' >> "$d/quiet.tsv"
    printf '2026-01-01T00:01:00Z\t310150000000001\tauth_request\tcellA\t\n' >> "$d/quiet.tsv"
    local out; out=$(lipr_score "$d/quiet.tsv")
    chk quiet-score "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="score"{print $3}')" "0"
    chk quiet-risk  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="risk"{print $3}')" "low"

    { printf 'ts\timsi\tevent\tcell\tsilent\n'
      for i in 1 2 3 4; do printf '2026-01-01T00:0%d:00Z\t310150000000002\tidentity_request\tcellA\t\n' "$i"; done
      printf '2026-01-01T00:05:00Z\t310150000000002\tsilent_sms\tcellA\tyes\n'
      for c in A B C D E F; do printf '2026-01-01T00:1%s:00Z\t310150000000002\tlocation_update\tcell%s\t\n' "$(printf '%d' $(( $(printf '%d' "'$c") - 65 )))" "$c"; done
    } > "$d/noisy.tsv"
    out=$(lipr_score "$d/noisy.tsv")
    chk noisy-forced "$(printf '%s\n' "$out" | awk -F'\t' '$1=="forced_identity_burst"{print $2}')" "HIGH"
    chk noisy-silent "$(printf '%s\n' "$out" | awk -F'\t' '$1=="silent_sms"{print $2}')" "HIGH"
    chk noisy-spread "$(printf '%s\n' "$out" | awk -F'\t' '$1=="wide_cell_spread"{print $2}')" "MEDIUM"
    chk noisy-risk   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="risk"{print $3}')" "high"
    chk noisy-score-pos "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="score"{print ($3>0)?"yes":"no"}')" "yes"
    chk score-missing "$(lipr_score "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 3. Report and plan are present and name the admissible record.
    chk report-escalation "$(lipr_report | awk -F'\t' '$1=="escalation"{print ($2 ~ /ADMF/)?"yes":"no"}')" "yes"
    chk plan-status "$(fld "$(lipr_plan)" status)" "handoff"

    # 4. Scope, behavioural: no activation/interception verb is dispatchable.
    chk scope-no-activate  "$(lipr_cli_main --activate >/dev/null 2>&1; echo $?)" "2"
    chk scope-no-intercept "$(lipr_cli_main --intercept >/dev/null 2>&1; echo $?)" "2"
    chk scope-no-provision "$(lipr_cli_main --provision-target >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

lipr_menu() {
    while true; do
        banner
        echo "  === LI Discovery (detection only) ==="
        echo
        cat <<'M'
  [1]  LI interface reference
  [2]  LI architecture reference
  [3]  Score interception-posture signals
  [4]  Reporting guidance
  [5]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) lipr_interfaces; read -rp "  enter " _ ;;
            2) lipr_architecture; read -rp "  enter " _ ;;
            3) read -rp "  signalling tsv> " p; lipr_score "$p"; read -rp "  enter " _ ;;
            4) lipr_report; read -rp "  enter " _ ;;
            5) lipr_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

lipr_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  lipr_status_tsv ;;
        --interfaces)  lipr_interfaces ;;
        --iface)       lipr_name_of "${1:-}" ;;
        --architecture) lipr_architecture ;;
        --score|--detect) lipr_score "${1:-}" ;;
        --report)      lipr_report ;;
        --plan)        lipr_plan ;;
        --selftest)    lipr_selftest ;;
        --menu)        lipr_menu ;;
        *)
            cat >&2 <<EOF
LI Discovery — 3GPP lawful-interception interfaces and posture signals (detection only)

Usage: $0 COMMAND
  --status-tsv         module state as TSV
  --interfaces         X1/HI1, X2/HI2, X3/HI3 reference (TS 33.108)
  --iface <X1|X2|X3>   name one interface
  --architecture       ADMF/POI/DF2/DF3/LEMF roles
  --score <tsv>        interception-posture score over signalling events
  --report             what to record and where to escalate
  --plan               network-side confirmation handoff
  --selftest           verify the model and the scorer, no capture needed
  --menu               interactive menu

Scope: this module detects and reports. It does not perform, activate or
provision lawful interception, and the selftest asserts no such verb exists.
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
    lipr_cli_main "$@"
fi
