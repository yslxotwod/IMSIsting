#!/usr/bin/env bash
# oran — O-RAN / xApp Attacks: the RIC interfaces and the assessment of a deployment.
#
# Open RAN splits a base station into a CU, a DU, an O-RU and two RICs (near-RT
# and non-RT), wired by a set of standard interfaces: E2, A1, O1, O2, F1, E1 and
# the Open Fronthaul. Each is a trust boundary, and the early specs left several
# unauthenticated by default. This module names the interfaces, models an xApp's
# effective authority, and assesses a deployment configuration against the
# O-RAN security control set. It analyses; it does not deploy a rogue xApp.
#
# A1 policy is where the radio is actually divided: a policy body carries the
# per-slice PRB shares, quotas and the 5QIs a slice may use. --qos-policy builds
# that body in the shape --a1-put targets ({"scope":..,"statement":..} under
# PUT /A1-P/v2/policytypes/{id}/policies/{instance}) and writes it locally;
# --qos-policy-check validates a body against exactly the fields this module
# documents, refusing unknown keys rather than ignoring them. Nothing is sent.
#
# Complements 26_ss7_map/11_lte_core: those cover the core, this covers the RAN.
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
    printf 'A1_POLICY_TYPE\t20000 (the --a1-put default; a near-RT RIC documents its own policy type IDs)\n'
    printf 'A1_QOS_VERBS\t--qos-policy, --qos-policy-check\n'
    printf 'A1_QOS_BODY\t{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[per-slice snssai/prb/quota/allowed5qi]}}\n'
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


    # 5. A1 QoS policy body: consistent with --a1-put, and checked.
    out=$(oran_qos_policy); rc=$?
    chk qos-rc          "$rc" "0"
    chk qos-put-path    "$(fld "$out" path)" "$(oran_a1_put 20000 1 global | awk -F'\t' '$1=="path"{print $2}')"
    chk qos-put-shape   "$(fld "$out" method)" "PUT"
    chk qos-ranfunc     "$([[ "$(fld "$out" ran_function)" == ORAN-E2SM-RC* ]] && echo yes || echo no)" "yes"
    chk qos-type-id     "$(fld "$out" policy_type_id)" "20000"
    chk qos-body-scope  "$([[ "$(fld "$out" body)" == '{"scope":{"ueId":"ALL"}'* ]] && echo yes || echo no)" "yes"
    chk qos-body-action "$([[ "$(fld "$out" body)" == *'"action":"slice-qos"'* ]] && echo yes || echo no)" "yes"
    chk qos-body-prb    "$([[ "$(fld "$out" body)" == *'"prb":{"minPct":30,"maxPct":50}'* ]] && echo yes || echo no)" "yes"
    chk qos-body-5qi    "$([[ "$(fld "$out" body)" == *'"allowed5qi":[82,85]'* ]] && echo yes || echo no)" "yes"
    local qfile; qfile=$(fld "$out" file)
    chk qos-file        "$([[ -s "$qfile" ]] && echo written || echo missing)" "written"
    chk qos-bad-type    "$(oran_qos_policy x 1 >/dev/null 2>&1; echo $?)" "2"
    # --qos-policy passes its own checker, so the generator and the validator
    # agree on the fields this module documents.
    if command -v python3 >/dev/null 2>&1; then
        out=$(oran_qos_policy_check "$qfile"); rc=$?
        chk qos-check-rc      "$rc" "0"
        chk qos-check-verdict "$(fld "$out" verdict)" "consistent"
        chk qos-check-slices  "$(fld "$out" slices)" "3"
        chk qos-check-action  "$(fld "$out" action)" "slice-qos"
        chk qos-check-prbsum  "$(fld "$out" prb_min_sum)" "45"
        chk qos-check-slice2  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="slice" && $2=="2"{print $9}')" "82,85"
        chk qos-check-tsn     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="slice" && $2=="2"{print $10}')" "1000/500 us"
        chk qos-check-dup-sst "$(printf '%s\n' "$out" | awk -F'\t' '$1=="slice"{print $3}' | sort -u | wc -l)" "3"
        # Unknown keys are refused, at every level.
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[{"snssai":{"sst":1,"sd":"000001"},"prb":{"minPct":30,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[1]}]},"bandwidth":5}' > "$d/top.json"
        chk qos-unknown-top   "$(oran_qos_policy_check "$d/top.json" >/dev/null 2>&1; echo $?)" "2"
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[{"snssai":{"sst":1,"sd":"000001"},"prb":{"minPct":30,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[1],"bandwidth":5}]}}' > "$d/slicekey.json"
        chk qos-unknown-slice "$(oran_qos_policy_check "$d/slicekey.json" >/dev/null 2>&1; echo $?)" "2"
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[{"snssai":{"sst":1},"prb":{"minPct":70,"maxPct":90},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[1]},{"snssai":{"sst":2},"prb":{"minPct":40,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[82]}]}}' > "$d/over.json"
        chk qos-prb-over      "$(oran_qos_policy_check "$d/over.json" >/dev/null 2>&1; echo $?)" "2"
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[{"snssai":{"sst":1},"prb":{"minPct":60,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[1]}]}}' > "$d/minmax.json"
        chk qos-min-max       "$(oran_qos_policy_check "$d/minmax.json" >/dev/null 2>&1; echo $?)" "2"
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[{"snssai":{"sst":1},"prb":{"minPct":1,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[1]},{"snssai":{"sst":1},"prb":{"minPct":1,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[5]}]}}' > "$d/dup.json"
        chk qos-dup-slice     "$(oran_qos_policy_check "$d/dup.json" >/dev/null 2>&1; echo $?)" "2"
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[{"snssai":{"sst":1},"prb":{"minPct":1,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[256]}]}}' > "$d/five.json"
        chk qos-5qi-range     "$(oran_qos_policy_check "$d/five.json" >/dev/null 2>&1; echo $?)" "2"
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","slices":[{"snssai":{"sst":2},"prb":{"minPct":1,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[82],"tsn":{"periodicityUs":1000,"burstArrivalTimeUs":1000}}]}}' > "$d/tsn.json"
        chk qos-tsn-period    "$(oran_qos_policy_check "$d/tsn.json" >/dev/null 2>&1; echo $?)" "2"
        printf '%s\n' '{"scope":{"ueId":"ALL"},"statement":{"action":"modify","slices":[{"snssai":{"sst":1},"prb":{"minPct":1,"maxPct":50},"quota":{"ulGbrKbps":1,"dlGbrKbps":1},"allowed5qi":[1]}]}}' > "$d/action.json"
        chk qos-action        "$(oran_qos_policy_check "$d/action.json" >/dev/null 2>&1; echo $?)" "2"
        printf 'not json\n' > "$d/broken.json"
        chk qos-broken-json   "$(oran_qos_policy_check "$d/broken.json" >/dev/null 2>&1; echo $?)" "2"
        chk qos-nofile        "$(oran_qos_policy_check "$d/none.json" >/dev/null 2>&1; echo $?)" "1"
        chk qos-none          "$(oran_qos_policy_check >/dev/null 2>&1; echo $?)" "2"
        # The ERROR line names the offending key, so the author can find it.
        chk qos-unknown-named "$(oran_qos_policy_check "$d/top.json" 2>&1 >/dev/null | grep -c 'unknown key(s): bandwidth')" "1"
    else
        printf 'qos-suite\tSKIP python3 not present\n'
    fi

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

oran_menu() {
    while true; do
        banner
        echo "  === O-RAN / xApp Attacks ==="
        echo
        cat <<'M'
  [1]  Interface reference
  [2]  E2 service-model reference
  [3]  Assess a deployment config
  [4]  xApp authority model
  [5]  Plan (handoff)
  [6]  A1 QoS policy body (per-slice PRB/quota/5QI)
  [7]  Validate an A1 QoS policy body
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) oran_interfaces; read -rp "  enter " _ ;;
            2) oran_e2sm; read -rp "  enter " _ ;;
            3) read -rp "  config path> " p; oran_assess "$p"; read -rp "  enter " _ ;;
            4) read -rp "  xapp tsv> " p; oran_xapp_authority "$p"; read -rp "  enter " _ ;;
            5) oran_plan; read -rp "  enter " _ ;;
            6) oran_qos_policy | column -t -s$'\t' 2>/dev/null || oran_qos_policy
               read -rp "  enter " _ ;;
            7) read -rp "  json path> " p; oran_qos_policy_check "$p" | column -t -s$'\t' 2>/dev/null || oran_qos_policy_check "$p"
               read -rp "  enter " _ ;;
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
# ── A1 QoS policy: a complete body for the PUT, and a checker for it ────
# --a1-put takes hand-written JSON; this is the body that PUT was always
# missing: per-slice PRB sharing, per-slice quota and the 5QIs the slice may
# carry, in the A1-P v2 shape {"scope":..,"statement":{..}} the module already
# targets. Nothing is sent: the body is written under $ORAN_DIR for an
# operator to hand to --a1-put against a testbed they own.
oran_qos_policy_body() {
    local policy_type="${1:-20000}" instance="${2:-1}"
    printf '{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","policyTypeId":%s,"policyInstanceId":%s,"slices":[' \
        "$policy_type" "$instance"
    printf '{"snssai":{"sst":1,"sd":"000001"},"prb":{"minPct":30,"maxPct":50},"quota":{"ulGbrKbps":20000,"dlGbrKbps":40000},"allowed5qi":[1,5,6,9]}'
    printf ',{"snssai":{"sst":2,"sd":"000002"},"prb":{"minPct":10,"maxPct":20},"quota":{"ulGbrKbps":5000,"dlGbrKbps":10000},"allowed5qi":[82,85],"tsn":{"periodicityUs":1000,"burstArrivalTimeUs":500}}'
    printf ',{"snssai":{"sst":3,"sd":"000003"},"prb":{"minPct":5,"maxPct":10},"quota":{"ulGbrKbps":1000,"dlGbrKbps":1000},"allowed5qi":[9]}'
    printf ']}}\n'
}

# oran_qos_policy [policy-type] [instance] [scope]
oran_qos_policy() {
    local policy_type="${1:-20000}" instance="${2:-1}" scope="${3:-global}"
    [[ "$policy_type" =~ ^[0-9]+$ && "$instance" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tpolicy type and instance are numeric\n' >&2
        printf 'WHY\tthe A1 path is /A1-P/v2/policytypes/{policytype_id}/policies/{policy_instance_id} (O-RAN.WG2.A1AP); both segments are numeric\n' >&2
        return 2; }
    local body out_file verdict
    body=$(oran_qos_policy_body "$policy_type" "$instance")
    out_file="$ORAN_DIR/a1-qos-policy-${policy_type}-${instance}.json"
    mkdir -p "$ORAN_DIR" 2>/dev/null
    if ! printf '%s\n' "$body" > "$out_file" 2>/dev/null; then
        printf 'ERROR\tcannot write %s\n' "$(oran_sanitize "$out_file")" >&2
        return 1
    fi
    printf 'ran_function\tORAN-E2SM-RC (RAN control: slicing, handover, beam)\n'
    printf 'ran_function_note\t%s\n' "the body is not bound to a RAN function on the wire: the non-RT RIC registers the policy type and the near-RT RIC maps it to its RAN function, so the policy type ID must match that registration"
    printf 'policy_type_id\t%s\n' "$policy_type"
    printf 'policy_instance_id\t%s\n' "$instance"
    printf 'method\tPUT\n'
    printf 'path\t/A1-P/v2/policytypes/%s/policies/%s\n' "$policy_type" "$instance"
    printf 'content_type\tapplication/json\n'
    printf 'scope\t%s\n' "$(oran_sanitize "$scope")"
    printf 'body\t%s\n' "$body"
    printf 'file\t%s\n' "$(oran_sanitize "$out_file")"
    printf 'slices\t3\n'
    printf 'slice_1\tSST 1 / SD 000001\tPRB 30-50%%\tquota 20000/40000 kbit/s\t5QI 1,5,6,9\n'
    printf 'slice_2\tSST 2 / SD 000002\tPRB 10-20%%\tquota 5000/10000 kbit/s\t5QI 82,85 + TSC periodicity 1000 us\n'
    printf 'slice_3\tSST 3 / SD 000003\tPRB 5-10%%\tquota 1000/1000 kbit/s\t5QI 9\n'
    if [[ -n "$(command -v python3 2>/dev/null)" ]]; then
        verdict=$(oran_qos_policy_check "$out_file" 2>/dev/null | awk -F'\t' '$1=="verdict"{print $2; exit}')
        printf 'verdict\t%s\n' "${verdict:-unknown}"
    else
        printf 'verdict\tunknown\n'
        printf 'limit\t%s\n' "python3 is absent, so the body was not validated against --qos-policy-check in this build"
    fi
    printf 'put_with\t--a1-put %s %s %s "$(cat %s)"\n' "$policy_type" "$instance" "$(oran_sanitize "$scope")" "$(oran_sanitize "$out_file")"
    printf 'attack\t%s\n' "a near-RT RIC that does not authenticate the non-RT RIC installs this body from anyone who can reach the A1 endpoint: PRB shares and the per-slice 5QI set decide who gets the radio"
    printf 'note\tnothing is sent; the body is written locally for a testbed you own\n'
}

# --qos-policy-check <json> — validate an A1 QoS body against the fields this
# module documents. Unknown keys are refused, never ignored: a key the near-RT
# RIC does not know is a policy that does not say what its author thinks.
oran_qos_policy_check() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --qos-policy-check <json>\n' >&2; return 2; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read %s\n' "$(oran_sanitize "$file")" >&2
        printf 'WHY\tthe checker needs the policy body as a JSON file\n' >&2; return 1; }
    if [[ -z "$(command -v python3 2>/dev/null)" ]]; then
        printf 'ERROR\tpython3 is not installed, so JSON cannot be validated\n' >&2
        printf 'WHY\tthe A1 body is JSON (O-RAN.WG2.A1AP); a shell-only parser would accept some malformed bodies and refuse others, which is worse than declining\n' >&2
        return 1
    fi
    python3 - "$file" <<'PY'
import json, sys

path = sys.argv[1]

def fail(msg, why):
    print("ERROR\t" + msg, file=sys.stderr)
    print("WHY\t" + why, file=sys.stderr)
    sys.exit(2)

def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)

def keys_ok(obj, allowed, where):
    unknown = sorted(k for k in obj if k not in allowed)
    if unknown:
        fail("%s carries unknown key(s): %s" % (where, ", ".join(unknown)),
             "%s accepts only: %s (O-RAN.WG2.A1AP policy body as this module targets it). An unknown key would be ignored by the near-RT RIC, so the policy would not do what it says" % (where, ", ".join(sorted(allowed))))

try:
    with open(path, "r", encoding="utf-8") as fh:
        body = json.load(fh)
except Exception as exc:
    fail("body is not valid JSON: %s" % exc,
         "an A1 policy body is a JSON object (O-RAN.WG2.A1AP); a body that does not parse cannot be PUT")

if not isinstance(body, dict):
    fail("the body is a %s, not a JSON object" % type(body).__name__,
         "the A1-P policy body is a JSON object with scope and statement")

keys_ok(body, {"scope", "statement"}, "the policy body")
for req in ("scope", "statement"):
    if req not in body:
        fail("the policy body has no %s object" % req,
             'the PUT body this module targets is {"scope":..,"statement":..}; without %s the near-RT RIC has no policy to install' % req)

scope = body["scope"]
if not isinstance(scope, dict):
    fail("scope is a %s, not a JSON object" % type(scope).__name__, "scope selects the UEs the policy applies to")
keys_ok(scope, {"ueId"}, "scope")
if not isinstance(scope.get("ueId"), str) or not scope["ueId"]:
    fail("scope.ueId is absent or not a non-empty string",
         'scope.ueId is a UE identity or "ALL" (the default body of --a1-put uses {"ueId":"ALL"})')

stmt = body["statement"]
if not isinstance(stmt, dict):
    fail("statement is a %s, not a JSON object" % type(stmt).__name__, "statement carries the policy action and its payload")
keys_ok(stmt, {"action", "policyTypeId", "policyInstanceId", "slices"}, "statement")
if not isinstance(stmt.get("action"), str) or not stmt["action"]:
    fail("statement.action is absent or not a non-empty string", 'the statement says what the policy does; this module targets "slice-qos"')
if stmt["action"] != "slice-qos":
    fail('statement.action is "%s", not "slice-qos"' % stmt["action"],
         'the QoS body this module generates and checks has action "slice-qos"; another action would be a different policy shape and its slices would not be read')
for key in ("policyTypeId", "policyInstanceId"):
    if key in stmt and not (is_int(stmt[key]) and stmt[key] >= 0):
        fail("statement.%s is not a non-negative integer" % key, "the policy type and instance are numeric segments of the A1 path")
slices = stmt.get("slices")
if not isinstance(slices, list) or not slices:
    fail("statement.slices is absent or not a non-empty array", "the QoS body is per-slice; a policy with no slice constrains nothing")

allowed_slice = {"snssai", "prb", "quota", "allowed5qi", "tsn"}
seen = []
rows = []
total_min = 0
total_max = 0
for idx, sl in enumerate(slices, 1):
    where = "statement.slices[%d]" % idx
    if not isinstance(sl, dict):
        fail("%s is a %s, not a JSON object" % (where, type(sl).__name__), "each slice is an object of snssai, prb, quota and allowed5qi")
    keys_ok(sl, allowed_slice, where)
    for req in ("snssai", "prb", "quota", "allowed5qi"):
        if req not in sl:
            fail("%s has no %s" % (where, req), "a slice without %s is a constraint the near-RT RIC cannot apply (PRB share, quota and 5QI set are what the policy is for)" % req)

    sn = sl["snssai"]
    if not isinstance(sn, dict):
        fail("%s.snssai is a %s, not a JSON object" % (where, type(sn).__name__), "the slice is identified by its S-NSSAI")
    keys_ok(sn, {"sst", "sd"}, where + ".snssai")
    if not is_int(sn.get("sst")) or not (0 <= sn["sst"] <= 255):
        fail("%s.snssai.sst is not an integer 0-255" % where, "the SST is one octet (TS 23.501 5.15.2.2)")
    sd = sn.get("sd")
    if sd is not None:
        if not isinstance(sd, str) or len(sd) != 6 or any(c not in "0123456789abcdefABCDEF" for c in sd):
            fail("%s.snssai.sd is %r, not 6 hex digits" % (where, sd), "the SD is 3 octets written as 6 hex digits (TS 23.003 28.4.2); 'none'/0xFFFFFF means no SD")
        sd = sd.upper()
    key = (sn["sst"], sd)
    if key in seen:
        fail("%s.snssai duplicates SST %d / SD %s of an earlier slice" % (where, sn["sst"], sd or "none"),
             "two slices with the same S-NSSAI in one policy are two conflicting PRB/quota rules for the same slice")
    seen.append(key)

    prb = sl["prb"]
    if not isinstance(prb, dict):
        fail("%s.prb is a %s, not a JSON object" % (where, type(prb).__name__), "prb carries the PRB share of the slice")
    keys_ok(prb, {"minPct", "maxPct"}, where + ".prb")
    for k in ("minPct", "maxPct"):
        if not is_int(prb.get(k)) or not (0 <= prb[k] <= 100):
            fail("%s.prb.%s is not an integer 0-100" % (where, k), "a PRB share is a percentage of the radio's physical resource blocks")
    if prb["minPct"] > prb["maxPct"]:
        fail("%s.prb has minPct %d > maxPct %d" % (where, prb["minPct"], prb["maxPct"]), "the guaranteed share cannot exceed the maximum share")
    total_min += prb["minPct"]
    total_max += prb["maxPct"]

    q = sl["quota"]
    if not isinstance(q, dict):
        fail("%s.quota is a %s, not a JSON object" % (where, type(q).__name__), "quota carries the guaranteed rate of the slice")
    keys_ok(q, {"ulGbrKbps", "dlGbrKbps"}, where + ".quota")
    for k in ("ulGbrKbps", "dlGbrKbps"):
        if not is_int(q.get(k)) or q[k] < 0:
            fail("%s.quota.%s is not a non-negative integer" % (where, k), "a guaranteed rate is kbit/s per direction and cannot be negative")

    five = sl["allowed5qi"]
    if not isinstance(five, list) or not five:
        fail("%s.allowed5qi is absent or not a non-empty array" % where, "the 5QI set is the slice's QoS; an empty set allows nothing")
    for v in five:
        if not is_int(v) or not (0 <= v <= 255):
            fail("%s.allowed5qi contains %r, not an integer 0-255" % (where, v), "the 5QI is a one-octet identifier (TS 23.501 5.7.4)")
    if len(set(five)) != len(five):
        fail("%s.allowed5qi repeats a 5QI" % where, "a repeated 5QI is a duplicated constraint, which means the list was edited without reading it")

    tsn = sl.get("tsn")
    if tsn is not None:
        if not isinstance(tsn, dict):
            fail("%s.tsn is a %s, not a JSON object" % (where, type(tsn).__name__), "the TSC assistance information is an object")
        keys_ok(tsn, {"periodicityUs", "burstArrivalTimeUs"}, where + ".tsn")
        for k in ("periodicityUs", "burstArrivalTimeUs"):
            if k in tsn and (not is_int(tsn[k]) or tsn[k] <= 0):
                fail("%s.tsn.%s is not a positive integer" % (where, k), "TS 38.413 carries the TSC periodicity and burst arrival time in microseconds")
        if "periodicityUs" in tsn and "burstArrivalTimeUs" in tsn and tsn["burstArrivalTimeUs"] >= tsn["periodicityUs"]:
            fail("%s.tsn.burstArrivalTimeUs (%d) is not inside the period (%d us)" % (where, tsn["burstArrivalTimeUs"], tsn["periodicityUs"]),
                 "the burst arrival time is an offset within the periodicity (TS 23.501 5.7.4.3 TSC assistance information); an offset that does not fit is not a schedule the RAN can follow")

    rows.append((idx, sn["sst"], sd or "none", prb["minPct"], prb["maxPct"],
                 q["ulGbrKbps"], q["dlGbrKbps"], ",".join(str(v) for v in five),
                 ("%d/%d us" % (tsn["periodicityUs"], tsn["burstArrivalTimeUs"])) if isinstance(tsn, dict) and "periodicityUs" in tsn and "burstArrivalTimeUs" in tsn else "-"))

if total_min > 100:
    fail("the guaranteed PRB shares sum to %d%% (> 100%%)" % total_min,
         "the per-slice minimum PRB shares are reservations on the same radio: they cannot add up to more than the radio (O-RAN.WG2 QoS/PRB policy)")

out = sys.stdout
out.write("input\t%s\n" % path)
out.write("action\t%s\n" % stmt["action"])
if "policyTypeId" in stmt:
    out.write("policy_type_id\t%d\n" % stmt["policyTypeId"])
if "policyInstanceId" in stmt:
    out.write("policy_instance_id\t%d\n" % stmt["policyInstanceId"])
out.write("scope_ueid\t%s\n" % scope["ueId"])
out.write("slices\t%d\n" % len(rows))
for r in rows:
    out.write("slice\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n" % r)
out.write("prb_min_sum\t%d\n" % total_min)
out.write("prb_max_sum\t%d\n" % total_max)
out.write("verdict\tconsistent\n")
PY
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
        --qos-policy)      oran_qos_policy "${1:-20000}" "${2:-1}" "${3:-global}" ;;
        --qos-policy-check) oran_qos_policy_check "${1:-}" ;;
        --e2-control)      oran_e2_control "${1:-2}" "${2:-1}" "${3:-0}" ;;
        --xapp-attack)     oran_xapp_attack "${1:-rogue-xapp}" ;;
        --plan)            oran_plan ;;
        --selftest)        oran_selftest ;;
        --menu)            oran_menu ;;
        *)
            cat >&2 <<EOF
O-RAN / xApp Attacks — RIC interfaces and deployment assessment

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --interfaces              E2/A1/O1/O2/F1/E1/fronthaul map
  --e2sm                    E2 service-model reference
  --assess <conf>           deployment security findings (KEY=VALUE)
  --xapp-authority <tsv>    effective authority per loaded xApp
  --a1-put [type] [inst] [scope] [json]   forged A1 policy PUT (policy poisoning)
  --qos-policy [type] [inst] [scope]      a complete A1 QoS policy body: per-slice
                                          PRB share, quota and 5QI set, written
                                          locally for --a1-put (nothing is sent)
  --qos-policy-check <json>               validate that body; unknown keys are
                                          refused, not ignored
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
