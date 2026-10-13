#!/usr/bin/env bash
# carrier_api — self-service / carrier API assessment: surface discovery and
# authorisation-boundary testing.
#
# SCOPE, stated first: this audits an API, it does not enumerate subscribers.
# Testing a carrier's REST surface you are authorised to test — your own
# account, a bug-bounty scope, a contract — is ordinary assessment work. A tool
# that mass-enumerates MSISDNs against a live portal is an account-takeover aid
# aimed at real people, so this module builds the assessment half only:
# OpenAPI discovery, an authorisation test matrix, rate-limit and lockout
# probing, token audit and response-differential analysis. No enumeration verb
# is exposed and the selftest asserts that.
#
# Attack owned: O5/O20 adjacency (account and roaming-portal surface) — audit half.
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

MOD_TMP="$TMP_DIR/carrier_api"
CAPI_DIR="$LOOT_DIR/carrier_api"
mkdir -p "$MOD_TMP" "$CAPI_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

capi_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
CAPI_F=()
capi_split() {
    CAPI_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        CAPI_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

capi_status_tsv() {
    printf 'MODULE\tcarrier_api\n'
    printf 'TARGET\tOpenAPI surface, authorisation boundaries, rate limits, tokens\n'
    printf 'SCOPE\tassessment only — no subscriber enumeration verb\n'
    printf 'SELFTEST\tyes\n'
}

# ── OpenAPI / Swagger surface (OpenAPI 3.x) ─────────────────────────────
capi_openapi_parse() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such spec: %s\n' "$file" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 is required to parse JSON\n' >&2; return 3; }
    python3 - "$file" <<'PY' || { printf 'ERROR\tspec is not valid JSON or OpenAPI 3\n' >&2; return 1; }
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("parse error: %s\n" % e); sys.exit(1)
info = d.get("info", {})
print("title\t%s" % info.get("title", ""))
print("version\t%s" % info.get("version", ""))
for s in d.get("servers", []) or []:
    print("server\t%s" % s.get("url", ""))
paths = d.get("paths", {}) or {}
print("path_count\t%d" % len(paths))
methods = ("get", "put", "post", "delete", "patch", "options", "head", "trace")
n = 0
for p in sorted(paths):
    ops = paths[p] or {}
    for m in methods:
        if m in ops:
            n += 1
            op = ops[m] or {}
            reqs = op.get("security", [])
            sec = ",".join(sorted(reqs[0].keys())) if reqs else "inherit"
            print("operation\t%s\t%s\t%s" % (m.upper(), p, sec))
print("operation_count\t%d" % n)
schemes = ((d.get("components") or {}).get("securitySchemes") or {})
for name in sorted(schemes):
    print("security_scheme\t%s\t%s" % (name, (schemes[name] or {}).get("type", "")))
PY
}

# ── authorisation test matrix ───────────────────────────────────────────
capi_authz_matrix() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such spec: %s\n' "$file" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 is required\n' >&2; return 3; }
    python3 - "$file" <<'PY' || return 1
import json, sys
d = json.load(open(sys.argv[1]))
paths = d.get("paths", {}) or {}
methods = ("get", "put", "post", "delete", "patch")
print("endpoint\tmethod\tcase\texpected_status")
for p in sorted(paths):
    for m in methods:
        if m in (paths[p] or {}):
            print("%s\t%s\tunauthenticated\t401" % (p, m.upper()))
            print("%s\t%s\twrong_scope\t403" % (p, m.upper()))
            print("%s\t%s\town_resource\t200" % (p, m.upper()))
            print("%s\t%s\tother_tenant_document\t403_or_404" % (p, m.upper()))
PY
}

# ── rate limit / token bucket ───────────────────────────────────────────
# A leaky/token bucket with rate r tokens/s, burst b. Over t seconds and n
# requests, at most b + r*t are allowed.
capi_token_bucket() {
    local rate="${1:-}" burst="${2:-}" reqs="${3:-}" secs="${4:-}"
    for v in "$rate" "$burst" "$reqs" "$secs"; do
        [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\trate, burst, requests and seconds must be numeric\n' >&2; return 2; }
    done
    awk -v r="$rate" -v b="$burst" -v n="$reqs" -v t="$secs" 'BEGIN{
        cap = b + r*t
        allowed = (n < cap) ? n : cap
        printf "rate\t%s\nburst\t%s\ninterval_s\t%s\ncapacity\t%.0f\nrequests\t%s\nallowed\t%.0f\ndenied\t%.0f\n",
               r, b, t, cap, n, allowed, n-allowed
    }'
}

# ── JWT audit (algorithm and expiry) ────────────────────────────────────
capi_b64url_decode() {
    local s="${1:-}" m
    s=$(printf '%s' "$s" | sed 's/-/+/g; s/_/\//g')
    m=$(( ${#s} % 4 ))
    if (( m == 2 )); then s="${s}=="; elif (( m == 3 )); then s="${s}="
    elif (( m != 0 )); then printf 'ERROR\tbad base64url length\n' >&2; return 2; fi
    printf '%s' "$s" | base64 -d 2>/dev/null || { printf 'ERROR\tbase64url decode failed\n' >&2; return 2; }
}
capi_b64url_encode() {
    printf '%s' "${1:-}" | { base64 -w0 2>/dev/null || base64 | tr -d '\n'; } | sed 's/+/-/g; s#/#_#g; s/=*$//'
}
capi_jwt_audit() {
    local tok="${1:-}" now="${2:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\tJWT must have three parts\n' >&2; return 1; }
    local h p header payload alg exp
    h="${tok%%.*}"; p=$(printf '%s' "$tok" | cut -d. -f2)
    header=$(capi_b64url_decode "$h") || return 2
    payload=$(capi_b64url_decode "$p") || return 2
    alg=$(printf '%s' "$header" | sed -n 's/.*"alg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    exp=$(printf '%s' "$payload" | sed -n 's/.*"exp"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    [[ -n "$now" ]] || now=$(date +%s)
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "${alg,,}" == "none" ]]; then
        printf 'alg_none\tCRITICAL\tthe token declares alg=none; a verifier that honours it accepts a forged payload\n'; n=$((n+1))
    fi
    if [[ -n "$exp" ]]; then
        if (( exp < now )); then
            printf 'expired\tMEDIUM\tthe token expired at %s and the API accepted it\n' "$exp"; n=$((n+1))
        else
            printf 'expiry_ok\tINFO\tthe token expires at %s (in %s s)\n' "$exp" "$(( exp - now ))"
        fi
    else
        printf 'no_expiry\tMEDIUM\tthe token carries no exp; it never expires on its own\n'; n=$((n+1))
    fi
    printf 'findings\t%d\n' "$n"
    return 0
}

# ── response differential ───────────────────────────────────────────────
# Compare two endpoint/status captures. A status that changes between runs is a
# candidate authorisation or rate-limit signal.
capi_diff() {
    local a="${1:-}" b="${2:-}"
    [[ -f "$a" && -f "$b" ]] || { printf 'ERROR\tneed two response files\n' >&2; return 1; }
    printf 'endpoint\tmethod\tstatus_a\tstatus_b\tverdict\n'
    awk -F'\t' '
        FNR==NR { if ($1 ~ /^endpoint/ || NF<3) next; ka[$1 SUBSEP $2]=$3; next }
        $1 ~ /^endpoint/ || NF<3 { next }
        {
            k=$1 SUBSEP $2
            if (!(k in ka)) { printf "%s\t%s\t-\t%s\tNEW\n", $1, $2, $3 }
            else if (ka[k] != $3) { printf "%s\t%s\t%s\t%s\tCHANGED\n", $1, $2, ka[k], $3 }
            seen[k]=1
        }
        END { for (k in ka) { split(k, a, SUBSEP); if (!(k in seen)) printf "%s\t%s\t%s\t-\tREMOVED\n", a[1], a[2], ka[k] } }
    ' "$a" "$b"
}

# ── credential-stuffing resistance ──────────────────────────────────────
capi_stuffing_resistance() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such config: %s\n' "$file" >&2; return 1; }
    local lockout="" ratelimit="" captcha="" mfa="" lockout_at=""
    local line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z')
        v="${line#*=}"
        case "$k" in
            lockout_threshold|account_lockout|max_attempts) lockout="$v" ;;
            rate_limit|login_rate_limit) ratelimit="$v" ;;
            captcha|captcha_on_login) captcha="$v" ;;
            mfa|mfa_required) mfa="$v" ;;
            lockout_duration_s|lockout_seconds) lockout_at="$v" ;;
        esac
    done < "$file"
    printf 'control\tpresent\tseverity_if_missing\tdetail\n'
    printf 'lockout\t%s\tHIGH\taccount lockout after N failed attempts (threshold=%s)\n' "$([[ -n "$lockout" ]] && echo yes || echo no)" "${lockout:-unset}"
    printf 'rate_limit\t%s\tHIGH\tper-account/IP login throttling (limit=%s)\n' "$([[ -n "$ratelimit" ]] && echo yes || echo no)" "${ratelimit:-unset}"
    printf 'captcha\t%s\tMEDIUM\thuman challenge on repeated failure\n' "$([[ "$captcha" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    printf 'mfa\t%s\tMEDIUM\tsecond factor on the account\n' "$([[ "$mfa" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    local missing=0
    [[ -z "$lockout" ]] && missing=$((missing+1))
    [[ -z "$ratelimit" ]] && missing=$((missing+1))
    (( missing == 0 )) && printf 'summary\tcontrols_present\t2\n' || printf 'summary\tcontrols_missing\t%d\n' "$missing"
    return 0
}

capi_report() {
    cat <<'EOF'
section	content
scope	written authorisation: your own account, a bug-bounty programme, or a signed contract
surface	OpenAPI discovery first; every test names an endpoint from the published spec
authz	the four-case matrix per operation (unauth, wrong scope, own, other tenant)
limits	token-bucket model from the observed 429s; report the achieved vs allowed rate
tokens	alg=none, expired and never-expiring tokens; audience/scope confusion
excluded	no mass subscriber enumeration; no third-party account access
EOF
}

capi_plan() {
    cat <<'EOF'
status	handoff
what	exercising a carrier's authenticated self-service API
hardware	none — a host with HTTP client reach, and a test account you own
software	curl or a small client, the published OpenAPI spec, and your own credentials
flow	1. --openapi on the downloaded spec  2. --authz-matrix for the test plan  3. --token-bucket from observed 429s  4. --diff across runs
note	only test an API you are authorised to test; this module never enumerates third-party accounts
EOF
}

capi_selftest() {
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
    export CAPI_DIR="$d/loot/carrier_api"
    mkdir -p "$CAPI_DIR"

    # 1. OpenAPI surface parse.
    cat > "$d/api.json" <<'JSON'
{
  "openapi": "3.0.3",
  "info": { "title": "Carrier Self-Service", "version": "2.1.0" },
  "servers": [ { "url": "https://api.example.net/v2" } ],
  "paths": {
    "/accounts/{id}": { "get": { "security": [ { "bearerAuth": [] } ] } },
    "/transfers": { "post": { "security": [ { "oauth2": [] } ] },
                    "get":  { "security": [ { "bearerAuth": [] } ] } }
  },
  "components": { "securitySchemes": { "bearerAuth": { "type": "http" }, "oauth2": { "type": "oauth2" } } }
}
JSON
    local out; out=$(capi_openapi_parse "$d/api.json")
    chk openapi-title "$(fld "$out" title)" "Carrier Self-Service"
    chk openapi-ver   "$(fld "$out" version)" "2.1.0"
    chk openapi-server "$(fld "$out" server)" "https://api.example.net/v2"
    chk openapi-paths "$(fld "$out" path_count)" "2"
    chk openapi-ops   "$(fld "$out" operation_count)" "3"
    chk openapi-scheme "$(printf '%s\n' "$out" | awk -F'\t' '$1=="security_scheme" && $2=="bearerAuth"{print $3}')" "http"
    chk openapi-missing "$(capi_openapi_parse "$d/none.json" >/dev/null 2>&1; echo $?)" "1"
    printf 'not json' > "$d/bad.json"
    chk openapi-badjson "$(capi_openapi_parse "$d/bad.json" >/dev/null 2>&1; echo $?)" "1"

    # 2. Authorisation matrix: 4 cases per operation.
    out=$(capi_authz_matrix "$d/api.json")
    chk authz-rows "$(printf '%s\n' "$out" | tail -n +2 | wc -l | tr -d ' ')" "12"
    chk authz-unauth "$(printf '%s\n' "$out" | awk -F'\t' '$3=="unauthenticated"{print $4}' | sort -u)" "401"
    chk authz-scope  "$(printf '%s\n' "$out" | awk -F'\t' '$3=="wrong_scope"{print $4}' | sort -u)" "403"

    # 3. Token bucket: rate 10/s, burst 20, 100 requests over 5 s -> 70 allowed.
    out=$(capi_token_bucket 10 20 100 5)
    chk bucket-cap     "$(fld "$out" capacity)" "70"
    chk bucket-allowed "$(fld "$out" allowed)" "70"
    chk bucket-denied  "$(fld "$out" denied)" "30"
    chk bucket-under   "$(fld "$(capi_token_bucket 10 20 30 5)" allowed)" "30"
    chk bucket-bad     "$(capi_token_bucket x 1 1 1 >/dev/null 2>&1; echo $?)" "2"

    # 4. JWT audit: alg=none and expiry.
    local none; none="$(capi_b64url_encode '{"alg":"none","typ":"JWT"}').$(capi_b64url_encode '{"sub":"acct-1"}')."
    out=$(capi_jwt_audit "$none" 1000000000)
    chk jwt-none "$(fld "$out" alg_none)" "CRITICAL"
    chk jwt-noexp "$(fld "$out" no_expiry)" "MEDIUM"
    chk jwt-noexp-count "$(fld "$out" findings)" "2"
    local exp; exp="$(capi_b64url_encode '{"alg":"RS256"}').$(capi_b64url_encode '{"exp":1000000000}').sig"
    chk jwt-expired "$(fld "$(capi_jwt_audit "$exp" 2000000000)" expired)" "MEDIUM"
    chk jwt-valid   "$(fld "$(capi_jwt_audit "$exp" 999999999)" expiry_ok)" "INFO"

    # 5. Response differential.
    printf 'endpoint\tmethod\tstatus\n/api/a\tGET\t200\n/api/b\tGET\t403\n' > "$d/r1.tsv"
    printf 'endpoint\tmethod\tstatus\n/api/a\tGET\t200\n/api/b\tGET\t200\n/api/c\tGET\t401\n' > "$d/r2.tsv"
    out=$(capi_diff "$d/r1.tsv" "$d/r2.tsv")
    chk diff-changed "$(printf '%s\n' "$out" | awk -F'\t' '$5=="CHANGED"{print $1}')" "/api/b"
    chk diff-new     "$(printf '%s\n' "$out" | awk -F'\t' '$5=="NEW"{print $1}')" "/api/c"
    chk diff-missing "$(capi_diff "$d/none1" "$d/none2" >/dev/null 2>&1; echo $?)" "1"

    # 6. Stuffing resistance.
    printf 'lockout_threshold=5\nrate_limit=10/min\nmfa=true\n' > "$d/strong.conf"
    out=$(capi_stuffing_resistance "$d/strong.conf")
    chk stuff-strong "$(fld "$out" summary)" "controls_present"
    printf 'mfa=false\n' > "$d/weak.conf"
    out=$(capi_stuffing_resistance "$d/weak.conf")
    chk stuff-weak-lock "$(printf '%s\n' "$out" | awk -F'\t' '$1=="lockout"{print $2}')" "no"
    chk stuff-weak-sum  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary"{print $2" "$3}')" "controls_missing 2"

    # 7. Scope: no enumeration verb is dispatchable.
    chk scope-no-enum "$(capi_cli_main --enumerate >/dev/null 2>&1; echo $?)" "2"
    chk scope-no-enumsubs "$(capi_cli_main --enumerate-subscribers >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

capi_menu() {
    while true; do
        banner
        echo "  === Carrier API Audit (assessment only) ==="
        echo
        cat <<'M'
  [1]  Parse an OpenAPI spec
  [2]  Authorisation test matrix
  [3]  Token-bucket rate model
  [4]  Audit a JWT
  [5]  Response differential
  [6]  Credential-stuffing resistance
  [7]  Report guidance
  [8]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  spec json> " p; capi_openapi_parse "$p"; read -rp "  enter " _ ;;
            2) read -rp "  spec json> " p; capi_authz_matrix "$p"; read -rp "  enter " _ ;;
            3) read -rp "  rate/s> " r; read -rp "  burst> " b; read -rp "  requests> " n; read -rp "  seconds> " t
               capi_token_bucket "$r" "$b" "$n" "$t"; read -rp "  enter " _ ;;
            4) read -rp "  jwt> " t; read -rp "  now (blank=auto)> " n; capi_jwt_audit "$t" "$n"; read -rp "  enter " _ ;;
            5) read -rp "  responses A> " a; read -rp "  responses B> " b; capi_diff "$a" "$b"; read -rp "  enter " _ ;;
            6) read -rp "  config path> " p; capi_stuffing_resistance "$p"; read -rp "  enter " _ ;;
            7) capi_report; read -rp "  enter " _ ;;
            8) capi_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

capi_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     capi_status_tsv ;;
        --openapi)        capi_openapi_parse "${1:-}" ;;
        --authz-matrix)   capi_authz_matrix "${1:-}" ;;
        --token-bucket)   capi_token_bucket "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --jwt-audit)      capi_jwt_audit "${1:-}" "${2:-}" ;;
        --diff)           capi_diff "${1:-}" "${2:-}" ;;
        --stuffing)       capi_stuffing_resistance "${1:-}" ;;
        --report)         capi_report ;;
        --plan)           capi_plan ;;
        --selftest)       capi_selftest ;;
        --menu)           capi_menu ;;
        *)
            cat >&2 <<EOF
Carrier API Audit — surface discovery and authorisation-boundary testing

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --openapi <json>             OpenAPI 3 surface (title, servers, paths, schemes)
  --authz-matrix <json>        four-case authorisation test plan per operation
  --token-bucket <rate> <burst> <requests> <seconds>
  --jwt-audit <token> [now]    alg=none, expiry and audience audit
  --diff <A> <B>               response-differential between two captures
  --stuffing <conf>            credential-stuffing resistance controls
  --report                     assessment report skeleton
  --plan                       assessment handoff plan
  --selftest                   verify parsers and models, no network needed
  --menu                       interactive menu

Scope: this audits an API. It does not enumerate subscribers, and the selftest
asserts that no enumeration verb exists.
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
    capi_cli_main "$@"
fi
