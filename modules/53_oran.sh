#!/usr/bin/env bash
# oran — O-RAN / Open RAN: the RIC interfaces and the assessment of a deployment.
#
# Open RAN splits a base station into a CU, a DU, an O-RU and two RICs (near-RT
# and non-RT), wired by a set of standard interfaces: E2, A1, O1, O2, F1, E1 and
# the Open Fronthaul. Each is a trust boundary, and the early specs left several
# unauthenticated by default. This module names the interfaces, models an xApp's
# effective authority, and assesses a deployment configuration against the
# O-RAN security control set. It analyses; it does not deploy a rogue xApp.
#
# Complements 31_ss7_map/15_lte_core: those cover the core, this covers the RAN.
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

MOD_TMP="$TMP_DIR/oran"
ORAN_DIR="$LOOT_DIR/oran"
mkdir -p "$MOD_TMP" "$ORAN_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

oran_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
ORAN_F=()
oran_split() {
    ORAN_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        ORAN_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

oran_status_tsv() {
    printf 'MODULE\toran\n'
    printf 'TARGET\tO-RAN interfaces (E2/A1/O1/O2/F1/E1/fronthaul) and xApp authority\n'
    printf 'SCOPE\tassessment of a deployment you operate; no rogue-xApp deployment\n'
    printf 'SELFTEST\tyes\n'
}

# ── the interface set ───────────────────────────────────────────────────
oran_interfaces() {
    cat <<'EOF'
interface	endpoints	transport	spec_wg
A1	non-RT RIC <-> near-RT RIC	HTTP/JSON over TCP	O-RAN.WG2
E2	near-RT RIC <-> E2 node (CU/DU)	E2AP over SCTP	O-RAN.WG3
O1	OAM <-> managed element	NETCONF/YANG over SSH	O-RAN.WG10
O2	O-Cloud <-> SMO	REST (Redfish/K8s)	O-RAN.WG5
F1	CU <-> DU	F1AP over SCTP (F1-C), GTP-U (F1-U)	3GPP
E1	CU-CP <-> CU-UP	E1AP over SCTP	3GPP
fronthaul	DU <-> O-RU	eCPRI / RoE over Ethernet	O-RAN.WG4
EOF
}
oran_e2sm() {
    cat <<'EOF'
service_model	purpose	authority
ORAN-E2SM-KPM	key performance measurements	read (subscription reports)
ORAN-E2SM-RC	RAN control	write (RIC Control: handover, slicing, beam)
ORAN-E2SM-NI	network interface	read/control of per-interface data
EOF
}

# ── deployment risk assessment ──────────────────────────────────────────
# Reads KEY=VALUE. Absent or negative security controls become findings. An
# unknown value is never read as "enabled".
oran_assess() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such config: %s\n' "$file" >&2; return 1; }
    local a1_tls="" e2_ipsec="" ingress="" xapp_signed="" o1_auth="" macsec=""
    local line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z')
        v="${line#*=}"
        case "$k" in
            a1_tls) a1_tls="$v" ;;
            e2_ipsec|e2_sec) e2_ipsec="$v" ;;
            ric_ingress|e2_ingress|a1_ingress) ingress="$v" ;;
            xapp_signed|xapp_signature) xapp_signed="$v" ;;
            o1_auth|o1_authentication) o1_auth="$v" ;;
            fronthaul_macsec|macsec) macsec="$v" ;;
        esac
    done < "$file"
    printf 'finding\tseverity\tdetail\n'
    local n=0
    [[ "$a1_tls" =~ ^(true|yes|1|on)$ ]] || { printf 'a1_not_tls\tHIGH\tA1 carries JSON policy over an unauthenticated channel; enable TLS and mTLS between the RICs\n'; n=$((n+1)); }
    [[ "$e2_ipsec" =~ ^(true|yes|1|on)$ ]] || { printf 'e2_no_ipsec\tHIGH\tE2AP over SCTP is unauthenticated at the application layer; IPsec on the E2 transport is the control\n'; n=$((n+1)); }
    [[ "$ingress" == "0.0.0.0/0" || "$ingress" == "any" || -z "$ingress" ]] && { printf 'ric_ingress_open\tHIGH\tthe near-RT RIC accepts E2/A1 from any address; restrict to known E2 nodes and the SMO\n'; n=$((n+1)); }
    [[ "$xapp_signed" =~ ^(true|yes|1|on)$ ]] || { printf 'xapp_unsigned\tHIGH\txApps are not signature-verified before load; an unsigned xApp can request RAN control\n'; n=$((n+1)); }
    [[ "$o1_auth" =~ ^(true|yes|1|on)$ ]] || { printf 'o1_weak_auth\tMEDIUM\tO1 management authentication is not enforced; NETCONF write access reconfigures the RAN\n'; n=$((n+1)); }
    [[ "$macsec" =~ ^(true|yes|1|on)$ ]] || { printf 'fronthaul_no_macsec\tMEDIUM\tthe Open Fronthaul carries IQ in the clear; MACsec protects the DU-RU link\n'; n=$((n+1)); }
    (( n == 0 )) && printf 'none\tINFO\tA1 TLS, E2 IPsec, xApp signing, O1 auth and fronthaul MACsec are all configured\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

# ── xApp authority model ────────────────────────────────────────────────
# An xApp is only as safe as the authority the RIC grants it. Input TSV:
#   name<TAB>e2sm<TAB>control<TAB>signed
oran_xapp_authority() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such xApp list: %s\n' "$file" >&2; return 1; }
    printf 'xapp\te2sm\tcontrol\tsigned\tverdict\n'
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == name* || "$line" == \#* ]] && continue
        oran_split "$line"
        local name="${ORAN_F[0]:-}" e2sm="${ORAN_F[1]:-}" ctl="${ORAN_F[2]:-}" sig="${ORAN_F[3]:-}"
        local verdict="ok"
        if [[ "$ctl" =~ ^(true|yes|1)$ && ! "$sig" =~ ^(true|yes|1)$ ]]; then
            verdict="OVERBROAD — an unsigned xApp holds RAN control"
        elif [[ "$e2sm" == *RC* && "$ctl" =~ ^(true|yes|1)$ && "$sig" =~ ^(true|yes|1)$ ]]; then
            verdict="control granted (signed) — verify scope and rate limits"
        elif [[ "$e2sm" == *RC* ]]; then
            verdict="RC subscription without control — read only"
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$(oran_sanitize "$name")" "$(oran_sanitize "$e2sm")" \
            "$(oran_sanitize "$ctl")" "$(oran_sanitize "$sig")" "$verdict"
    done < "$file"
}

oran_plan() {
    cat <<'EOF'
status	handoff
what	exercising E2/A1 against a RIC, or loading an xApp
hardware	an O-RAN testbed: a near-RT RIC (the O-RAN SC RIC), one E2 node (srsRAN gNB with the E2 agent), and one O-RU or a simulated fronthaul
software	O-RAN Software Community near-RT RIC, srsRAN with the E2 interface, an xApp you wrote
flow	1. --interfaces for the map  2. --assess your deployment config  3. --xapp-authority over the loaded xApp list
note	loading an xApp into a carrier RIC needs that carrier's authorisation; this module assesses a deployment you control
EOF
}

oran_selftest() {
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
    export ORAN_DIR="$d/loot/oran"
    mkdir -p "$ORAN_DIR"

    # 1. Interface set: the transport each one actually rides.
    chk if-e2 "$(oran_interfaces | awk -F'\t' '$1=="E2"{print $2}')" "near-RT RIC <-> E2 node (CU/DU)"
    chk if-e2-tp "$(oran_interfaces | awk -F'\t' '$1=="E2"{print $3}')" "E2AP over SCTP"
    chk if-fh "$(oran_interfaces | awk -F'\t' '$1=="fronthaul"{print $3}')" "eCPRI / RoE over Ethernet"
    chk if-a1-wg "$(oran_interfaces | awk -F'\t' '$1=="A1"{print $4}')" "O-RAN.WG2"
    chk e2sm-rc "$(oran_e2sm | awk -F'\t' '$1=="ORAN-E2SM-RC"{print $2}')" "RAN control"

    # 2. Deployment assessment: an open config is flagged, a hardened one abstains.
    printf 'a1_tls=false\ne2_ipsec=false\nric_ingress=0.0.0.0/0\nxapp_signed=false\no1_auth=false\nfronthaul_macsec=false\n' > "$d/open.conf"
    local out; out=$(oran_assess "$d/open.conf")
    chk assess-a1 "$(printf '%s\n' "$out" | awk -F'\t' '$1=="a1_not_tls"{print $2}')" "HIGH"
    chk assess-ric "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ric_ingress_open"{print $2}')" "HIGH"
    chk assess-count "$(fld "$out" findings)" "6"
    printf 'a1_tls=true\ne2_ipsec=true\nric_ingress=10.0.0.0/24\nxapp_signed=true\no1_auth=true\nfronthaul_macsec=true\n' > "$d/hard.conf"
    out=$(oran_assess "$d/hard.conf")
    chk assess-clean "$(fld "$out" none)" "INFO"
    chk assess-clean-count "$(fld "$out" findings)" "0"
    chk assess-missing "$(oran_assess "$d/none.conf" >/dev/null 2>&1; echo $?)" "1"

    # 3. xApp authority: an unsigned control xApp is overbroad.
    printf 'name\te2sm\tcontrol\tsigned\nwatchdog\tORAN-E2SM-KPM\tfalse\tfalse\nrotor\tORAN-E2SM-RC\ttrue\tfalse\ntuner\tORAN-E2SM-RC\ttrue\ttrue\n' > "$d/xapps.tsv"
    out=$(oran_xapp_authority "$d/xapps.tsv")
    chk xapp-overbroad "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rotor"{print $5}')" "OVERBROAD — an unsigned xApp holds RAN control"
    chk xapp-signed "$(printf '%s\n' "$out" | awk -F'\t' '$1=="tuner" && $5 ~ /control granted/{print "yes"}')" "yes"
    chk xapp-read "$(printf '%s\n' "$out" | awk -F'\t' '$1=="watchdog"{print $5}')" "ok"
    chk xapp-missing "$(oran_xapp_authority "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 4. A1 policy poisoning and RIC Control.
    out=$(oran_a1_put 20000 1 global)
    chk a1-path "$(fld "$out" path)" "/A1-P/v2/policytypes/20000/policies/1"
    chk a1-method "$(fld "$out" method)" "PUT"
    chk a1-attack "$([[ "$(fld "$out" attack)" == forged* ]] && echo yes || echo no)" "yes"
    chk a1-bad "$(oran_a1_put x 1 >/dev/null 2>&1; echo $?)" "2"
    out=$(oran_e2_control 2 1 0)
    chk e2-proc "$(fld "$out" e2ap_procedure_code)" "6"
    chk e2-sm "$(fld "$out" ran_function)" "ORAN-E2SM-RC"
    chk e2-bad "$(oran_e2_control x 1 >/dev/null 2>&1; echo $?)" "2"
    chk xapp-sub "$(oran_xapp_attack rogue | awk -F'\t' '$1=="subscription" && $2 ~ /KPM/{print "yes"}')" "yes"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

oran_menu() {
    while true; do
        banner
        echo "  === O-RAN / Open RAN ==="
        echo
        cat <<'M'
  [1]  Interface reference
  [2]  E2 service-model reference
  [3]  Assess a deployment config
  [4]  xApp authority model
  [5]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) oran_interfaces; read -rp "  enter " _ ;;
            2) oran_e2sm; read -rp "  enter " _ ;;
            3) read -rp "  config path> " p; oran_assess "$p"; read -rp "  enter " _ ;;
            4) read -rp "  xapp tsv> " p; oran_xapp_authority "$p"; read -rp "  enter " _ ;;
            5) oran_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── A1 policy poisoning and RIC Control construction ────────────────────
# A1 carries policy from the non-RT RIC to the near-RT RIC as JSON. A forged
# PUT installs an attacker policy if the near-RT RIC does not authenticate the
# non-RT RIC. Shape: PUT /A1-P/v2/policytypes/{id}/policies/{instance}.
oran_a1_put() {
    local policy_type="${1:-20000}" instance="${2:-1}" scope="${3:-global}" json="${4:-}"
    [[ "$policy_type" =~ ^[0-9]+$ && "$instance" =~ ^[0-9]+$ ]] || { printf 'ERROR\tpolicy type and instance are numeric\n' >&2; return 2; }
    [[ -n "$json" ]] || json='{"scope":{"ueId":"ALL"},"statement":{"action":"modify","value":0}}'
    printf 'method\tPUT\npath\t/A1-P/v2/policytypes/%s/policies/%s\nscope\t%s\n' "$policy_type" "$instance" "$scope"
    printf 'body\t%s\n' "$(oran_sanitize "$json")"
    printf 'attack\tforged A1 policy PUT — a near-RT RIC that does not authenticate the non-RT RIC installs an attacker policy (slicing, handover, beam control)\n'
}
# RIC Control is E2AP procedure 6; the RAN function and action are looked up
# from the E2 service model. This builds the control shape an xApp sends.
oran_e2_control() {
    local ranfunc="${1:-2}" action="${2:-1}" ue="${3:-0}"
    [[ "$ranfunc" =~ ^[0-9]+$ && "$action" =~ ^[0-9]+$ ]] || { printf 'ERROR\tRAN function id and RIC action id are numeric\n' >&2; return 2; }
    local rn; case "$ranfunc" in 2) rn="ORAN-E2SM-RC" ;; 3) rn="ORAN-E2SM-KPM" ;; *) rn="custom" ;; esac
    printf 'procedure\tRIC Control Request\ne2ap_procedure_code\t6\nran_function_id\t%s\nran_function\t%s\nric_action_id\t%s\ntarget_ue\t%s\n' \
        "$ranfunc" "$rn" "$action" "$ue"
    printf 'attack\tRIC Control — a compromised or unsigned xApp drives handover, slicing or beam decisions through this message\n'
}
# The over-broad xApp: subscribe to KPM everywhere and hold RC control.
oran_xapp_attack() {
    local name="${1:-rogue-xapp}"
    printf 'xapp\t%s\nsubscription\tORAN-E2SM-KPM (all E2 nodes)\ncontrol\tORAN-E2SM-RC (all E2 nodes)\n' "$(oran_sanitize "$name")"
    printf 'attack\tan xApp that both reads the whole KPM surface and holds RAN Control can profile every UE and steer the network; if it is unsigned the RIC accepted it without proof of origin\n'
}

oran_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      oran_status_tsv ;;
        --interfaces)      oran_interfaces ;;
        --e2sm)            oran_e2sm ;;
        --assess)          oran_assess "${1:-}" ;;
        --xapp-authority)  oran_xapp_authority "${1:-}" ;;
        --a1-put)          oran_a1_put "${1:-20000}" "${2:-1}" "${3:-global}" "${4:-}" ;;
        --e2-control)      oran_e2_control "${1:-2}" "${2:-1}" "${3:-0}" ;;
        --xapp-attack)     oran_xapp_attack "${1:-rogue-xapp}" ;;
        --plan)            oran_plan ;;
        --selftest)        oran_selftest ;;
        --menu)            oran_menu ;;
        *)
            cat >&2 <<EOF
O-RAN / Open RAN — RIC interfaces and deployment assessment

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --interfaces              E2/A1/O1/O2/F1/E1/fronthaul map
  --e2sm                    E2 service-model reference
  --assess <conf>           deployment security findings (KEY=VALUE)
  --xapp-authority <tsv>    effective authority per loaded xApp
  --a1-put [type] [inst] [scope] [json]   forged A1 policy PUT (policy poisoning)
  --e2-control [ranfunc] [action] [ue]    RIC Control (E2AP procedure 6) shape
  --xapp-attack [name]      the over-broad xApp model
  --plan                    O-RAN testbed handoff plan
  --selftest                verify the tables and the assessor
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
    oran_cli_main "$@"
fi
