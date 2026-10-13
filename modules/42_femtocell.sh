#!/usr/bin/env bash
# femtocell — HeNB and Iuh: local device assessment and PCI/CSG conflict work.
#
# A femtocell (HeNB) exposes three surfaces a researcher owns or is authorised
# to test: the local management console (TR-069/CWMP, often left at defaults),
# the Iuh backhaul to the HeNB-GW (HNBAP/RUA/RANAP over SCTP), and the air
# interface's CSG and PCI allocation. This module works all three from a config
# or a captured cell list. It does not attack a core network it does not own.
#
# Attack owned: O1 adjacency (residential/small-cell access) — assessment half.
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

MOD_TMP="$TMP_DIR/femtocell"
FEMT_DIR="$LOOT_DIR/femtocell"
mkdir -p "$MOD_TMP" "$FEMT_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

femt_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
FEMT_F=()
femt_split() {
    FEMT_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        FEMT_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
femt_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }

femt_status_tsv() {
    printf 'MODULE\tfemtocell\n'
    printf 'TARGET\tHeNB local management, Iuh backhaul, CSG/PCI allocation\n'
    printf 'TRANSMIT\tnone — assessment and conflict detection only\n'
    printf 'SELFTEST\tyes\n'
}

# ── CSG identity (TS 36.413 / TS 25.469: CSG-Id is 27 bits) ─────────────
FEMT_CSG_MAX=134217727
femt_csg_encode() {
    local id="${1:-}"
    [[ "$id" =~ ^[0-9]+$ ]] || { printf 'ERROR\tCSG id must be numeric\n' >&2; return 2; }
    (( id >= 0 && id <= FEMT_CSG_MAX )) || {
        printf 'ERROR\tCSG id %s out of range 0..%d (27 bits)\n' "$id" "$FEMT_CSG_MAX" >&2; return 2; }
    printf '%08X\n' "$id"
}
femt_csg_decode() {
    local h; h=$(femt_norm_hex "${1:-}")
    [[ "$h" =~ ^[0-9a-f]{1,8}$ ]] || { printf 'ERROR\tCSG id must be 1..8 hex digits\n' >&2; return 2; }
    local v=$(( 16#$h ))
    (( v <= FEMT_CSG_MAX )) || {
        printf 'ERROR\t0x%s exceeds the 27-bit CSG-Id space\n' "$h" >&2; return 1; }
    printf 'csg_id\t%d\nhex\t%08X\nbits\t27\n' "$v" "$v"
}

# ── PCI conflict / confusion over a cell list ───────────────────────────
# A PCI is only unique within one carrier. Two distinct cells advertising the
# same PCI on the same EARFCN cause PCI confusion: the UE cannot tell them
# apart, and a handover can be directed at the wrong cell. Input TSV columns:
#   pci  earfcn  cell_id  [plmn]
femt_pci_conflict() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such cell list: %s\n' "$file" >&2; return 1; }
    printf 'pci\tearfcn\tcells\tverdict\n'
    local found=0
    awk -F'\t' 'NR>1 && NF>=3 { key=$1"|"$2; n[key]++; ex[key]=ex[key]" "$3 }
                END { for (k in n) if (n[k]>1) { split(k,a,"|"); print a[1]"\t"a[2]"\t"substr(ex[k],2)"\tCONFLICT" } }' \
        "$file" | sort -n
    found=$(awk -F'\t' 'NR>1 && NF>=3 { key=$1"|"$2; n[key]++ } END { c=0; for (k in n) if (n[k]>1) c++; print c }' "$file")
    printf 'summary\tconflicts\t%d\n' "$found"
    return 0
}

# ── Iuh backhaul reference ──────────────────────────────────────────────
femt_iuh_stack() {
    cat <<'EOF'
layer	protocol	spec	transport
HNBAP	Home NodeB Application Part	TS 25.469	SCTP, Iuh
RUA	RANAP User Adaptation	TS 25.468	SCTP, Iuh
RANAP	Radio Access Network Application Part	TS 25.413	SCTP, Iuh
UEA/CS	HNB-GW registration, UE registration	TS 25.467	Iuh
EOF
}

# ── TR-069 / CWMP local management audit ────────────────────────────────
# Reads a KEY=VALUE config (an ACS profile, a HeNB management dump, or a
# TR-196 FAP data-model extract) and reports concrete misconfigurations. No
# network request is made.
femt_tr069_audit() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such config: %s\n' "$file" >&2; return 1; }
    local cwmp_url="" user="" pass="" wan="" port="" tls=""
    local line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k="${line%%=*}"; v="${line#*=}"
        k=$(printf '%s' "$k" | tr -d ' ' | tr 'A-Z' 'a-z')
        case "$k" in
            cwmp_url|acs_url|acsurl) cwmp_url="$v" ;;
            cwmp_username|acs_username|username|user) user="$v" ;;
            cwmp_password|acs_password|password|pass) pass="$v" ;;
            wan_management|remote_management|wan_http) wan="$v" ;;
            tr069_port|acs_port|management_port) port="$v" ;;
            require_tls|cwmp_tls|https_only) tls="$v" ;;
        esac
    done < "$file"
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "$user" =~ ^(admin|root|support|cusadmin)$ && "$pass" =~ ^(admin|password|root|1234|support|cusadmin|)$ ]]; then
        printf 'default_credentials\tHIGH\tdevice management accepted a vendor default username/password pair\n'; n=$((n+1))
    fi
    if [[ "$cwmp_url" == http://* ]]; then
        printf 'plaintext_cwmp\tHIGH\tACS URL is HTTP; TR-069 SOAP rides in the clear and carries credentials and config\n'; n=$((n+1))
    fi
    if [[ "${wan:-false}" =~ ^(true|yes|1|enabled)$ ]]; then
        printf 'wan_management_exposed\tHIGH\tmanagement reachable from the WAN side; TR-069 belongs on the operator backhaul\n'; n=$((n+1))
    fi
    if [[ -n "$tls" && ! "$tls" =~ ^(true|yes|1|required)$ ]]; then
        printf 'tls_optional\tMEDIUM\tTLS is configured but not required; a downgrade to plaintext is possible\n'; n=$((n+1))
    fi
    if [[ -n "$port" && "$port" != "7547" && "$port" =~ ^[0-9]+$ ]]; then
        printf 'nonstandard_port\tLOW\tmanagement port %s (TR-069 default is 7547); not a defect by itself\n' "$port"; n=$((n+1))
    fi
    (( n == 0 )) && printf 'none\tINFO\tno default credentials, plaintext ACS or WAN exposure found in this config\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

femt_plan() {
    cat <<'EOF'
status	handoff
what	exercising the Iuh backhaul or the local management plane
hardware	an HeNB you own (a commercial unit or an srsRAN/srsLTE small-cell on an SDR) and a test HNB-GW
software	osmo-hnbgw, an SCTP stack, a packet capture point on the Iuh
flow	1. capture the Iuh SCTP association here  2. decode HNBAP/RUA/RANAP  3. audit the local config with --tr069-audit
note	for a device you own or a lab; attaching to a carrier's HeNB-GW is out of scope
EOF
}

femt_selftest() {
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
    export FEMT_DIR="$d/loot/femtocell"
    mkdir -p "$FEMT_DIR"

    # 1. CSG-Id is 27 bits (TS 36.413).
    chk csg-max    "$(femt_csg_decode 07FFFFFF | awk -F'\t' '$1=="csg_id"{print $2}')" "134217727"
    chk csg-zero   "$(femt_csg_encode 0)"    "00000000"
    chk csg-one    "$(femt_csg_encode 1)"    "00000001"
    chk csg-maxenc "$(femt_csg_encode 134217727)" "07FFFFFF"
    chk csg-round  "$(femt_csg_decode "$(femt_csg_encode 1234567)" | awk -F'\t' '$1=="csg_id"{print $2}')" "1234567"
    chk csg-over   "$(femt_csg_encode 134217728 >/dev/null 2>&1; echo $?)" "2"
    chk csg-neg    "$(femt_csg_encode -1 >/dev/null 2>&1; echo $?)" "2"
    chk csg-decover "$(femt_csg_decode 08000000 >/dev/null 2>&1; echo $?)" "1"

    # 2. PCI conflict detection: positive on same PCI+freq, abstains otherwise.
    printf 'pci\tearfcn\tcell_id\n' > "$d/pci.tsv"
    printf '100\t6300\tAAAAAA\n' >> "$d/pci.tsv"
    printf '100\t6300\tBBBBBB\n' >> "$d/pci.tsv"
    printf '100\t6400\tCCCCCC\n' >> "$d/pci.tsv"
    printf '200\t6300\tDDDDDD\n' >> "$d/pci.tsv"
    local out
    out=$(femt_pci_conflict "$d/pci.tsv")
    chk pci-conflict-count "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary"{print $3}')" "1"
    chk pci-conflict-key   "$(printf '%s\n' "$out" | awk -F'\t' '$4=="CONFLICT"{print $1"|"$2}')" "100|6300"
    chk pci-negative-count "$(printf '%s\n' "$out" | awk -F'\t' '$4=="CONFLICT"' | wc -l | tr -d ' ')" "1"
    chk pci-missing "$(femt_pci_conflict "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 3. TR-069 audit: a bad config is flagged, a good one abstains.
    cat > "$d/bad.conf" <<'CFG'
cwmp_url=http://acs.example.net:7547/acs
cwmp_username=admin
cwmp_password=admin
wan_management=true
CFG
    out=$(femt_tr069_audit "$d/bad.conf")
    chk tr069-defaults "$(printf '%s\n' "$out" | awk -F'\t' '$1=="default_credentials"{print $2}')" "HIGH"
    chk tr069-http     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="plaintext_cwmp"{print $2}')" "HIGH"
    chk tr069-wan      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="wan_management_exposed"{print $2}')" "HIGH"
    chk tr069-count    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="findings"{print $2}')" "3"
    cat > "$d/good.conf" <<'CFG'
cwmp_url=https://acs.example.net:7547/acs
cwmp_username=support-bot
cwmp_password=Zq7-control-plane
wan_management=false
require_tls=true
CFG
    out=$(femt_tr069_audit "$d/good.conf")
    chk tr069-clean "$(printf '%s\n' "$out" | awk -F'\t' '$1=="none"{print $2}')" "INFO"
    chk tr069-clean-count "$(printf '%s\n' "$out" | awk -F'\t' '$1=="findings"{print $2}')" "0"
    chk tr069-missing "$(femt_tr069_audit "$d/none.conf" >/dev/null 2>&1; echo $?)" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

femt_menu() {
    while true; do
        banner
        echo "  === Femtocell / HeNB ==="
        echo
        cat <<'M'
  [1]  CSG id encode
  [2]  CSG id decode
  [3]  PCI conflict check
  [4]  Iuh stack reference
  [5]  TR-069 config audit
  [6]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  csg id> " i; femt_csg_encode "$i"; read -rp "  enter " _ ;;
            2) read -rp "  csg hex> " h; femt_csg_decode "$h"; read -rp "  enter " _ ;;
            3) read -rp "  cell-list tsv> " p; femt_pci_conflict "$p"; read -rp "  enter " _ ;;
            4) femt_iuh_stack; read -rp "  enter " _ ;;
            5) read -rp "  config path> " p; femt_tr069_audit "$p"; read -rp "  enter " _ ;;
            6) femt_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

femt_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  femt_status_tsv ;;
        --csg-encode)  femt_csg_encode "${1:-}" ;;
        --csg-decode)  femt_csg_decode "${1:-}" ;;
        --pci-conflict) femt_pci_conflict "${1:-}" ;;
        --iuh)         femt_iuh_stack ;;
        --tr069-audit) femt_tr069_audit "${1:-}" ;;
        --plan)        femt_plan ;;
        --selftest)    femt_selftest ;;
        --menu)        femt_menu ;;
        *)
            cat >&2 <<EOF
Femtocell / HeNB — local management audit and PCI/CSG conflict work

Usage: $0 COMMAND
  --status-tsv          module state as TSV
  --csg-encode <id>     27-bit CSG-Id to hex
  --csg-decode <hex>    hex to CSG-Id
  --pci-conflict <tsv>  PCI confusion over a cell list
  --iuh                 Iuh (HNBAP/RUA/RANAP) reference
  --tr069-audit <conf>  TR-069/CWMP local management findings
  --plan                lab HeNB handoff plan
  --selftest            verify the codec and detectors, no radio needed
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
    femt_cli_main "$@"
fi
