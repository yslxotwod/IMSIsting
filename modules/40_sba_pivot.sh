#!/usr/bin/env bash
# sba_pivot — 5G Service Based Architecture: HTTP/2 framing and NRF/OAuth surface.
#
# The 5G core is a mesh of HTTP/2 JSON micro-services (NRF discovery, AUSF, UDM,
# SMF) authorised by OAuth2 access tokens. This module builds and decodes the
# HTTP/2 frames those services speak (RFC 7540), constructs NRF discovery
# requests (TS 29.510), and audits the tokens — including the alg=none and
# audience-confusion classes that turn a service mesh into a pivot. It reads and
# encodes; it does not authenticate to a core it does not own.
#
# Attack owned: O19 adjacency (core SBA) and the 5G half of O4 — assessment half.
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

MOD_TMP="$TMP_DIR/sba_pivot"
SBAP_DIR="$LOOT_DIR/sba_pivot"
mkdir -p "$MOD_TMP" "$SBAP_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

sbap_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
SBAP_F=()
sbap_split() {
    SBAP_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        SBAP_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
sbap_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
sbap_is_hex() {
    local h; h=$(sbap_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
sbap_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }

sbap_status_tsv() {
    printf 'MODULE\tsba_pivot\n'
    printf 'TARGET\tHTTP/2 SBI framing, NRF discovery, OAuth2 token audit\n'
    printf 'TRANSPORT\tHTTP/2 over TCP (or SCTP for N2/N4 interworking)\n'
    printf 'TRANSMIT\tnone — encode, decode and audit only\n'
    printf 'SELFTEST\tyes\n'
}

# ── HTTP/2 frames (RFC 7540 §4.1, §6) ───────────────────────────────────
#   length 3 | type 1 | flags 1 | R+stream id 4  => 9-octet header
sbap_h2_types() {
    cat <<'EOF'
type	frame
0	DATA
1	HEADERS
2	PRIORITY
3	RST_STREAM
4	SETTINGS
5	PUSH_PROMISE
6	PING
7	GOAWAY
8	WINDOW_UPDATE
9	CONTINUATION
EOF
}
sbap_h2_name() {
    case "$1" in
        0) echo DATA ;; 1) echo HEADERS ;; 2) echo PRIORITY ;; 3) echo RST_STREAM ;;
        4) echo SETTINGS ;; 5) echo PUSH_PROMISE ;; 6) echo PING ;; 7) echo GOAWAY ;;
        8) echo WINDOW_UPDATE ;; 9) echo CONTINUATION ;; *) echo unknown ;;
    esac
}
sbap_h2_build() {
    local type="${1:-0}" flags="${2:-0}" sid="${3:-0}" payload
    payload=$(sbap_norm_hex "${4:-}")
    [[ -z "$payload" ]] || sbap_is_hex "$payload" || {
        printf 'ERROR\tpayload must be hex\n' >&2; return 2; }
    local plen=$(( ${#payload} / 2 ))
    printf '%06X%s%s%08X%s' "$(( plen & 0xFFFFFF ))" "$(sbap_byte "$type")" \
        "$(sbap_byte "$flags")" "$(( sid & 0x7FFFFFFF ))" "$payload"
}
sbap_h2_parse() {
    local h; h=$(sbap_norm_hex "${1:-}")
    sbap_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 18 )) || { printf 'ERROR\tHTTP/2 header is 9 octets\n' >&2; return 1; }
    local len=$(( 16#${h:0:6} )) type=$(( 16#${h:6:2} )) flags=$(( 16#${h:8:2} ))
    local sid=$(( 16#${h:10:8} & 0x7FFFFFFF ))
    printf 'length\t%d\ntype\t%d\ntype_name\t%s\nflags\t0x%02X\nstream_id\t%d\n' \
        "$len" "$type" "$(sbap_h2_name "$type")" "$flags" "$sid"
    (( ${#h} - 18 >= len * 2 )) || printf 'truncated\ttrue (payload shorter than the declared length)\n'
}

# ── SETTINGS parameters (RFC 7540 §6.5.2) ───────────────────────────────
sbap_settings_parse() {
    local h; h=$(sbap_norm_hex "${1:-}")
    sbap_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} % 12 == 0 )) || { printf 'ERROR\tSETTINGS payload must be a multiple of 6 octets\n' >&2; return 1; }
    printf 'id\tname\tvalue\n'
    local off=0
    while (( off*2 < ${#h} )); do
        local id=$(( 16#${h:$((off*2)):4} ))
        local val=$(( 16#${h:$((off*2+4)):8} ))
        local name
        case "$id" in
            1) name=HEADER_TABLE_SIZE ;; 2) name=ENABLE_PUSH ;; 3) name=MAX_CONCURRENT_STREAMS ;;
            4) name=INITIAL_WINDOW_SIZE ;; 5) name=MAX_FRAME_SIZE ;; 6) name=MAX_HEADER_LIST_SIZE ;;
            *) name=unknown ;;
        esac
        printf '%d\t%s\t%d\n' "$id" "$name" "$val"
        off=$(( off + 6 ))
    done
}

# ── NRF discovery (TS 29.510 §5.3 / §6.2.3) ─────────────────────────────
sbap_nf_paths() {
    cat <<'EOF'
service	path
nnrf-disc	/nnrf-disc/v1/nf-instances
nnrf-nfm	/nnrf-nfm/v1/nf-instances
nausf-auth	/nausf-auth/v1/ue-authentications
nudm-sdm	/nudm-sdm/v1/imsi-{imsi}/sm-data
nudm-uecm	/nudm-uecm/v1/imsi-{imsi}/registrations
nsmf-pdusession	/nsmf-pdusession/v1/sm-contexts
nbsf-management	/nbsf-management/v1/pcfBindings
EOF
}
sbap_nrf_discovery() {
    local target="${1:-UDM}" requester="${2:-AMF}"
    printf 'method\tGET\npath\t/nnrf-disc/v1/nf-instances\n'
    printf 'query\ttarget-nf-type=%s&requester-nf-type=%s\n' "$target" "$requester"
    printf 'header\taccept: application/3gppHal+json\n'
    printf 'url\t/nnrf-disc/v1/nf-instances?target-nf-type=%s&requester-nf-type=%s\n' "$target" "$requester"
}

# ── JWT / JOSE (RFC 7515, RFC 7519) ─────────────────────────────────────
sbap_b64url_decode() {
    local s="${1:-}" m
    s=$(printf '%s' "$s" | sed 's/-/+/g; s/_/\//g')
    m=$(( ${#s} % 4 ))
    if (( m == 2 )); then s="${s}=="; elif (( m == 3 )); then s="${s}="
    elif (( m != 0 )); then printf 'ERROR\tbad base64url length\n' >&2; return 2; fi
    printf '%s' "$s" | base64 -d 2>/dev/null || { printf 'ERROR\tbase64url decode failed\n' >&2; return 2; }
}
sbap_b64url_encode() {
    printf '%s' "${1:-}" | { base64 -w0 2>/dev/null || base64 | tr -d '\n'; } | sed 's/+/-/g; s#/#_#g; s/=*$//'
}
sbap_jwt_parts() {
    local tok="${1:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\tJWT must have three dot-separated parts\n' >&2; return 1; }
    printf '%s' "${tok%%.*}"
    printf '\t%s' "$(printf '%s' "$tok" | cut -d. -f2)"
    printf '\t%s' "$(printf '%s' "$tok" | cut -d. -f3-)"
}
sbap_jwt_decode() {
    local tok="${1:-}"
    local h p s
    h="${tok%%.*}"
    p=$(printf '%s' "$tok" | cut -d. -f2)
    s=$(printf '%s' "$tok" | cut -d. -f3-)
    local header payload
    header=$(sbap_b64url_decode "$h") || return 2
    payload=$(sbap_b64url_decode "$p") || return 2
    local alg
    alg=$(printf '%s' "$header" | sed -n 's/.*"alg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [[ -n "$alg" ]] || alg="<none-declared>"
    printf 'alg\t%s\nalg_none\t%s\nheader\t%s\npayload\t%s\nsignature_len\t%d\n' \
        "$alg" "$([[ "${alg,,}" == "none" ]] && echo yes || echo no)" \
        "$(sbap_sanitize "$header")" "$(sbap_sanitize "$payload")" "$(( ${#s} ))"
}
sbap_jwt_audit() {
    local tok="${1:-}" expected="${2:-}"
    local h p
    h="${tok%%.*}"; p=$(printf '%s' "$tok" | cut -d. -f2)
    local header payload alg
    header=$(sbap_b64url_decode "$h") || return 2
    payload=$(sbap_b64url_decode "$p") || return 2
    alg=$(printf '%s' "$header" | sed -n 's/.*"alg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "${alg,,}" == "none" ]]; then
        printf 'alg_none\tCRITICAL\tthe token declares alg=none; a verifier that honours it accepts any payload\n'; n=$((n+1))
    fi
    local aud
    aud=$(printf '%s' "$payload" | sed -n 's/.*"aud"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [[ -z "$aud" ]]; then
        printf 'no_audience\tHIGH\tthe token carries no aud claim; audience confusion lets it be replayed at another NF\n'; n=$((n+1))
    elif [[ -n "$expected" && "$aud" != "$expected" ]]; then
        printf 'audience_mismatch\tHIGH\ttoken aud=%s but the service expected %s\n' "$(sbap_sanitize "$aud")" "$(sbap_sanitize "$expected")"; n=$((n+1))
    fi
    (( n == 0 )) && printf 'none\tINFO\tno alg=none and the audience matched\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

sbap_plan() {
    cat <<'EOF'
status	handoff
what	querying a live SBA mesh or registering a rogue NF
hardware	a 5G SA testbed: Open5GS or free5GC on a host, optionally with srsRAN gNB and a UE
software	Open5GS (NRF/AMF/AUSF/UDM/SMF), curl or grpcurl, a TLS key for the SBI if mTLS is on
flow	1. build a discovery request here  2. send it from an authorised client  3. audit any token the NRF returns with --jwt-audit
note	registering an NF or minting tokens against a production core needs that operator's authorisation; nothing is sent by this module
EOF
}

# ── cross-service token abuse (arXiv 2509.08992) ────────────────────────
# A token minted for one NF is only safe at another if the consumer pins the
# audience and scope. This reports exactly which claim is missing.
sbap_token_pivot() {
    local tok="${1:-}" target="${2:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\ta JWT is required\n' >&2; return 1; }
    [[ -n "$target" ]] || { printf 'ERROR\ttarget NF required\n' >&2; return 2; }
    local p payload aud sub iss scope
    p=$(printf '%s' "$tok" | cut -d. -f2)
    payload=$(sbap_b64url_decode "$p") || return 2
    aud=$(printf '%s' "$payload"   | sed -n 's/.*"aud"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    sub=$(printf '%s' "$payload"   | sed -n 's/.*"sub"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    iss=$(printf '%s' "$payload"   | sed -n 's/.*"iss"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    scope=$(printf '%s' "$payload" | sed -n 's/.*"scope"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    printf 'target_nf\t%s\naud\t%s\nsub\t%s\niss\t%s\nscope\t%s\n' \
        "$target" "$aud" "$sub" "$iss" "$scope"
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ -z "$aud" ]]; then
        printf 'no_audience\tHIGH\tno aud claim — any NF that does not pin the audience accepts this token\n'; n=$(( n + 1 ))
    elif [[ "$aud" != *"$target"* ]]; then
        printf 'audience_mismatch\tHIGH\taud=%s does not name %s — cross-service replay if the target does not enforce aud\n' \
            "$(sbap_sanitize "$aud")" "$(sbap_sanitize "$target")"; n=$(( n + 1 ))
    fi
    if [[ -n "$sub" && "$sub" != "$target" ]]; then
        printf 'subject_confusion\tMEDIUM\ttoken subject is %s; presenting it to %s relies on audience pinning\n' \
            "$(sbap_sanitize "$sub")" "$(sbap_sanitize "$target")"; n=$(( n + 1 ))
    fi
    (( n == 0 )) && printf 'none\tINFO\taudience and subject are consistent with the target NF\n'
    printf 'findings\t%d\n' "$n"
    return 0
}
sbap_scope_confusion() {
    local tok="${1:-}" expect="${2:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\ta JWT is required\n' >&2; return 1; }
    [[ -n "$expect" ]] || { printf 'ERROR\texpected scope required\n' >&2; return 2; }
    local payload scope
    payload=$(sbap_b64url_decode "$(printf '%s' "$tok" | cut -d. -f2)") || return 2
    scope=$(printf '%s' "$payload" | sed -n 's/.*"scope"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    printf 'expected_scope\t%s\nscope\t%s\n' "$expect" "$scope"
    if [[ -z "$scope" ]]; then
        printf 'finding\tHIGH\tno scope claim — an unconstrained token can be used far beyond its mint purpose\n'
    elif [[ " $scope " != *" $expect "* ]]; then
        printf 'finding\tHIGH\tscope "%s" does not grant "%s" — a consumer that trusts the subject rather than the scope is exploitable\n' \
            "$(sbap_sanitize "$scope")" "$(sbap_sanitize "$expect")"
    else
        printf 'finding\tINFO\tscope grants the requested operation\n'
    fi
    return 0
}

# ── HTTP/2 Rapid Reset (CVE-2023-44487) ─────────────────────────────────
# Open a stream, then RST it immediately; the server does O(streams) work for
# O(1) bytes on the wire. On the SBI this is a core-plane DoS.
sbap_rapid_reset() {
    local n="${1:-5}"
    [[ "$n" =~ ^[1-9][0-9]*$ ]] && (( n <= 1000 )) || { printf 'ERROR\tstream count 1..1000\n' >&2; return 2; }
    printf 'frame\tstream\ttype\thex\n'
    local i sid
    for (( i = 0; i < n; i++ )); do
        sid=$(( 2 * i + 1 ))
        printf 'open\t%d\tHEADERS\t%s\n' "$sid" "$(sbap_h2_build 1 4 "$sid" "")"
        printf 'reset\t%d\tRST_STREAM\t%s\n' "$sid" "$(sbap_h2_build 3 0 "$sid" "00000008")"
    done
    printf 'streams\t%d\nframes\t%d\nattack\tHTTP/2 Rapid Reset (CVE-2023-44487): open-then-RST each stream; the peer does per-stream work for one small frame each\n' \
        "$n" "$(( 2 * n ))"
}

sbap_selftest() {
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
    export SBAP_DIR="$d/loot/sba_pivot"
    mkdir -p "$SBAP_DIR"

    # 1. HTTP/2 frame types are the RFC 7540 §11.2 registry.
    chk h2-data    "$(sbap_h2_name 0)" "DATA"
    chk h2-headers "$(sbap_h2_name 1)" "HEADERS"
    chk h2-settings "$(sbap_h2_name 4)" "SETTINGS"
    chk h2-goaway  "$(sbap_h2_name 7)" "GOAWAY"
    chk h2-ping    "$(sbap_h2_name 6)" "PING"
    chk h2-unknown "$(sbap_h2_name 42)" "unknown"

    # 2. Frame build/parse round-trips; header is 9 octets.
    local f; f=$(sbap_h2_build 4 0 0 000300000064)
    chk h2-len "$(fld "$(sbap_h2_parse "$f")" length)" "6"
    chk h2-type "$(fld "$(sbap_h2_parse "$f")" type_name)" "SETTINGS"
    chk h2-sid "$(fld "$(sbap_h2_parse "$f")" stream_id)" "0"
    # a DATA frame on stream 1.
    local f2; f2=$(sbap_h2_build 0 1 1 deadbeef)
    chk h2-data-len "$(fld "$(sbap_h2_parse "$f2")" length)" "4"
    chk h2-data-sid "$(fld "$(sbap_h2_parse "$f2")" stream_id)" "1"
    chk h2-short "$(sbap_h2_parse 0000 >/dev/null 2>&1; echo $?)" "1"
    chk h2-badhex "$(sbap_h2_parse zz >/dev/null 2>&1; echo $?)" "2"

    # 3. SETTINGS parameters (RFC 7540 §6.5.2).
    local s; s=$(sbap_settings_parse 000300000064000400100000)
    chk set-maxstreams "$(printf '%s\n' "$s" | awk -F'\t' '$1==3{print $2}')" "MAX_CONCURRENT_STREAMS"
    chk set-maxstreams-v "$(printf '%s\n' "$s" | awk -F'\t' '$1==3{print $3}')" "100"
    chk set-initwin  "$(printf '%s\n' "$s" | awk -F'\t' '$1==4{print $2}')" "INITIAL_WINDOW_SIZE"
    chk set-initwin-v "$(printf '%s\n' "$s" | awk -F'\t' '$1==4{print $3}')" "1048576"
    chk set-bad "$(sbap_settings_parse 0003 >/dev/null 2>&1; echo $?)" "1"

    # 4. NRF discovery path (TS 29.510 §6.2.3).
    local nrf; nrf=$(sbap_nrf_discovery UDM AMF)
    chk nrf-path "$(fld "$nrf" path)" "/nnrf-disc/v1/nf-instances"
    chk nrf-query "$(fld "$nrf" query)" "target-nf-type=UDM&requester-nf-type=AMF"
    chk nrf-paths "$(sbap_nf_paths | awk -F'\t' '$1=="nausf-auth"{print $2}')" "/nausf-auth/v1/ue-authentications"

    # 5. JWT: the canonical jwt.io token is the external anchor.
    local tok="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    local out; out=$(sbap_jwt_decode "$tok")
    chk jwt-alg    "$(fld "$out" alg)" "RS256"
    chk jwt-none   "$(fld "$out" alg_none)" "no"
    chk jwt-sub    "$([[ "$(fld "$out" payload)" == *'"sub":"1234567890"'* ]] && echo yes || echo no)" "yes"
    # build an alg=none token and confirm it is caught.
    local hdr payload none
    hdr=$(sbap_b64url_encode '{"alg":"none","typ":"JWT"}')
    payload=$(sbap_b64url_encode '{"sub":"AUSF"}')
    none="${hdr}.${payload}."
    out=$(sbap_jwt_audit "$none" NRF)
    chk jwt-none-flag "$(fld "$out" alg_none)" "CRITICAL"
    chk jwt-none-aud  "$(fld "$out" no_audience)" "HIGH"
    chk jwt-none-count "$(fld "$out" findings)" "2"
    # a well-formed token with the right audience abstains.
    local good
    good=$(sbap_b64url_encode '{"alg":"RS256","typ":"JWT"}')
    good="${good}.$(sbap_b64url_encode '{"aud":"NRF","sub":"AUSF"}').sig"
    out=$(sbap_jwt_audit "$good" NRF)
    chk jwt-good "$(fld "$out" none)" "INFO"
    chk jwt-good-count "$(fld "$out" findings)" "0"
    # wrong audience is flagged.
    out=$(sbap_jwt_audit "$good" UDM)
    chk jwt-mismatch "$(fld "$out" audience_mismatch)" "HIGH"
    chk jwt-bad "$(sbap_jwt_decode 'not.a.jwt!' >/dev/null 2>&1; echo $?)" "2"

    # 6. Cross-service token abuse: audience and scope.
    local tok_amf tok_ok
    tok_amf="$(sbap_b64url_encode '{"alg":"RS256"}').$(sbap_b64url_encode '{"sub":"AMF"}').sig"
    tok_ok="$(sbap_b64url_encode '{"alg":"RS256"}').$(sbap_b64url_encode '{"aud":"NRF","sub":"NRF"}').sig"
    out=$(sbap_token_pivot "$tok_amf" NRF)
    chk pivot-noaud "$(printf '%s\n' "$out" | awk -F'\t' '$1=="no_audience"{print $2}')" "HIGH"
    chk pivot-subj  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="subject_confusion"{print $2}')" "MEDIUM"
    out=$(sbap_token_pivot "$tok_ok" NRF)
    chk pivot-ok "$(printf '%s\n' "$out" | awk -F'\t' '$1=="none"{print $2}')" "INFO"
    local tok_scope
    tok_scope="$(sbap_b64url_encode '{"alg":"RS256"}').$(sbap_b64url_encode '{"scope":"nnrf-disc"}').sig"
    chk scope-bad "$(sbap_scope_confusion "$tok_scope" nausf-auth | awk -F'\t' '$1=="finding"{print ($2=="HIGH")?"hi":"no"}')" "hi"
    chk scope-ok  "$(sbap_scope_confusion "$tok_scope" nnrf-disc | awk -F'\t' '$1=="finding"{print ($2=="INFO")?"ok":"no"}')" "ok"

    # 7. HTTP/2 Rapid Reset: n streams -> 2n frames, n of them RST_STREAM.
    out=$(sbap_rapid_reset 3)
    chk rapid-streams "$(printf '%s\n' "$out" | awk -F'\t' '$1=="streams"{print $2}')" "3"
    chk rapid-frames  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="frames"{print $2}')" "6"
    chk rapid-rst     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="reset"{n++} END{print n+0}')" "3"
    chk rapid-bad     "$(sbap_rapid_reset 0 >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

sbap_menu() {
    while true; do
        banner
        echo "  === 5G SBA Pivot ==="
        echo
        cat <<'M'
  [1]  HTTP/2 frame type reference
  [2]  Build an HTTP/2 frame
  [3]  Parse an HTTP/2 frame
  [4]  Parse a SETTINGS payload
  [5]  NRF discovery request
  [6]  SBI path reference
  [7]  Decode a JWT
  [8]  Audit a JWT
  [9]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) sbap_h2_types; read -rp "  enter " _ ;;
            2) read -rp "  type> " t; read -rp "  flags> " fl; read -rp "  sid> " s; read -rp "  payload hex> " p
               sbap_h2_build "$t" "$fl" "$s" "$p"; echo; read -rp "  enter " _ ;;
            3) read -rp "  hex> " h; sbap_h2_parse "$h"; read -rp "  enter " _ ;;
            4) read -rp "  hex> " h; sbap_settings_parse "$h"; read -rp "  enter " _ ;;
            5) read -rp "  target NF type> " t; read -rp "  requester NF type> " r
               sbap_nrf_discovery "$t" "$r"; read -rp "  enter " _ ;;
            6) sbap_nf_paths; read -rp "  enter " _ ;;
            7) read -rp "  jwt> " t; sbap_jwt_decode "$t"; read -rp "  enter " _ ;;
            8) read -rp "  jwt> " t; read -rp "  expected aud> " a; sbap_jwt_audit "$t" "$a"; read -rp "  enter " _ ;;
            9) sbap_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

sbap_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  sbap_status_tsv ;;
        --h2-types)    sbap_h2_types ;;
        --h2-build)    sbap_h2_build "${1:-0}" "${2:-0}" "${3:-0}" "${4:-}" ;;
        --h2-parse)    sbap_h2_parse "${1:-}" ;;
        --settings)    sbap_settings_parse "${1:-}" ;;
        --nrf)         sbap_nrf_discovery "${1:-UDM}" "${2:-AMF}" ;;
        --nf-paths)    sbap_nf_paths ;;
        --jwt)         sbap_jwt_decode "${1:-}" ;;
        --jwt-audit)   sbap_jwt_audit "${1:-}" "${2:-}" ;;
        --token-pivot) sbap_token_pivot "${1:-}" "${2:-}" ;;
        --scope)       sbap_scope_confusion "${1:-}" "${2:-}" ;;
        --rapid-reset) sbap_rapid_reset "${1:-5}" ;;
        --plan)        sbap_plan ;;
        --selftest)    sbap_selftest ;;
        --menu)        sbap_menu ;;
        *)
            cat >&2 <<EOF
5G SBA Pivot — HTTP/2 SBI framing, NRF discovery, OAuth2 token audit

Usage: $0 COMMAND
  --status-tsv          module state as TSV
  --h2-types            HTTP/2 frame type reference
  --h2-build <t> <flags> <sid> <payload_hex>
  --h2-parse <hex>      decode a 9-octet HTTP/2 header and length
  --settings <hex>      decode a SETTINGS payload
  --nrf <target> [requester]   NRF discovery request (TS 29.510)
  --nf-paths            SBI service path reference
  --jwt <token>         decode a JWT header and payload
  --jwt-audit <token> [expected_aud]
  --token-pivot <token> <target_nf>   cross-service token replay check
  --scope <token> <expected_scope>    scope-confusion check
  --rapid-reset <n>          HTTP/2 Rapid Reset frame sequence (CVE-2023-44487)
  --plan                SBA lab handoff plan
  --selftest            verify framing and token audit, no core needed
  --menu                interactive menu
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
    sbap_cli_main "$@"
fi
