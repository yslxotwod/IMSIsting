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

    # D1 -- the redistribution the totals cannot see.
    local pz
    pz=$(oran_a1_poison 1 2 20)
    chk a1-poison-vmin  "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="slice" && $2=="SST 1"{print $5}')" "10"
    chk a1-poison-amax  "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="slice" && $2=="SST 2"{print $6}')" "40"
    chk a1-poison-ssum  "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="sum" && $2=="min"{print $4}')" "45"
    chk a1-poison-body  "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="body"{print $2}' | grep -c '"minPct":10,"maxPct":30')" "1"
    chk a1-poison-json  "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="body"{print $2}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["statement"]["slices"]))' 2>/dev/null)" "3"
    chk a1-poison-blind "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="audit_naive"{print ($2 ~ /a redistribution moves nothing/)?"yes":"no"}')" "yes"
    chk a1-poison-diff  "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="audit_honest"{print ($2 ~ /SST 1 fell 30 -> 10/)?"yes":"no"}')" "yes"
    chk a1-poison-find  "$(printf '%s\n' "$pz" | awk -F'\t' '$1=="finding" && $2=="no_cross_policy_accounting"{print $3}')" "HIGH"
    chk a1-poison-same  "$(oran_a1_poison 1 1 >/dev/null 2>&1; echo $?)" "2"
    chk a1-poison-range "$(oran_a1_poison 1 2 200 >/dev/null 2>&1; echo $?)" "2"

    # D2 -- the KPM subscription: per-UE measurements, empty scope, a join key.
    local ks; ks=$(oran_e2_subscribe 500)
    chk kpm-code      "$(fld "$ks" e2ap_procedure_code)" "8"
    chk kpm-period    "$(fld "$ks" event_trigger)"       "format 1: periodic report every 500 ms"
    chk kpm-meas      "$(printf '%s\n' "$ks" | awk -F'\t' '$1=="measurement"{n++} END{print n+0}')" "8"
    chk kpm-ue        "$(printf '%s\n' "$ks" | awk -F'\t' '$1=="measurement" && $2=="DRB.UEThpDl"{print $3}')" "per DRB / UE"
    chk kpm-nodes     "$(fld "$ks" scope_node_list | grep -c 'every E2 node')" "1"
    chk kpm-uempty    "$(fld "$ks" scope_ue_list | grep -c 'no UE filter')" "1"
    chk kpm-gran      "$(printf '%s\n' "$ks" | awk -F'\t' '$1=="finding" && $2=="ue_granularity"{print $3}')" "HIGH"
    chk kpm-join      "$(printf '%s\n' "$ks" | awk -F'\t' '$1=="finding" && $2=="join_key"{print $3}')" "MEDIUM"
    chk kpm-period-bad "$(oran_e2_subscribe 50 >/dev/null 2>&1; echo $?)" "2"
    chk kpm-style-bad "$(oran_e2_subscribe 1000 0 >/dev/null 2>&1; echo $?)" "2"
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
# ── D2 -- the KPM subscription: per-UE telemetry by design ──────────────
# E2SM-KPM style 1 reports measurements on a period. Most of what it can
# report is per-DRB or per-slice, and DRBs belong to UEs: a subscriber that is
# accepted once can pull a live, labelled stream of what every handset in the
# cell is doing. Nothing about the subscription is per-target: the xApp asks
# for all nodes, all UEs, and gets them.
oran_e2_subscribe() {
    local period="${1:-1000}" style="${2:-1}"
    [[ "$period" =~ ^[0-9]+$ ]] && (( period >= 100 && period <= 600000 )) || {
        printf 'ERROR\tthe report period is milliseconds, 100..600000\n' >&2; return 2; }
    [[ "$style" =~ ^[1-9]$ ]] || { printf 'ERROR\tE2SM-KPM has styles 1..2 in this build\n' >&2; return 2; }
    printf 'e2ap_procedure\tRIC Subscription Request\n'
    printf 'e2ap_procedure_code\t8\n'
    printf 'ran_function\tORAN-E2SM-KPM\n'
    printf 'ran_function_id\t3\n'
    printf 'event_trigger\tformat 1: periodic report every %s ms\n' "$period"
    printf 'action\tstyle %s, action 1, no filter\n' "$style"
    printf 'scope_node_list\tempty -- an empty list is every E2 node the RIC holds\n'
    printf 'scope_ue_list\tempty -- no UE filter, so every UE the node reports on is included\n'
    printf 'header\tmeasurement\tgranularity\treveals\n'
    printf 'measurement\tDRB.UEThpDl\tper DRB / UE\tthe downlink throughput each handset actually got, sample by sample\n'
    printf 'measurement\tDRB.UEThpUl\tper DRB / UE\tthe uplink each handset got, which distinguishes streaming, bulk upload and idle\n'
    printf 'measurement\tDRB.RlcSduDelayDl\tper DRB / UE\tqueue delay: what the scheduler is doing to this subscriber relative to the others\n'
    printf 'measurement\tDRB.PdcpSduVolumeDl_Filter\tper DRB / UE\tvolumes per bearer, which map onto the QoS class the UE asked for\n'
    printf 'measurement\tRRU.PrbUsedDl\tper cell / slice\tthe cell share in use, the denominator behind the per-UE numbers\n'
    printf 'measurement\tDRB.UEBufferedTrafficDl\tper DRB / UE\tbuffer occupancy: whether the UE is saturated, stalling, or thin\n'
    printf 'measurement\tCQI.Report\tper UE\tthe channel the handset reports -- a cheap radio-fingerprint of one device\n'
    printf 'measurement\tDRB.MeanActiveUeDl\tper slice\tactive UE count, so a per-UE stream can be placed in the cell load\n'
    printf 'identity\tthe indication carries the RAN UE NGAP ID and, in E2SM format 3, the UE ID: correlating that with the NGAP id on N2 names the subscriber\n'
    printf 'correlate\tone RAN UE NGAP ID from the E2 indication plus one NGAP message from the capture is a join key that survives encryption of the user plane\n'
    printf 'finding\tue_granularity\tHIGH\tthe measurements are per DRB and DRBs belong to UEs: this is not aggregate KPI, it is per-subscriber behaviour, labelled, every %s ms\n' "$period"
    printf 'finding\tall_nodes\tHIGH\tan empty node list subscribes to every E2 node; no scope is needed to start, and none is required afterwards\n'
    printf 'finding\tno_consumer_auth\tMEDIUM\tE2 setup establishes an xApp identity, and the near-RT RIC then treats subscriptions as that identity: the granularity of the authorisation is the RIC ACL, not the KPM action\n'
    printf 'finding\tjoin_key\tMEDIUM\tthe RAN UE NGAP ID in the indication joins to N2 signalling; a KPM stream plus an NGAP capture identifies which handset is doing what, without decrypting anything\n'
    printf 'finding\tpersistence\tMEDIUM\tthe subscription keeps reporting until it is deleted or the node deregisters; an expired xApp leaves an orphan that keeps collecting\n'
    printf 'detect\tinventory RIC subscriptions against approved xApp ids, alert on any subscription with an empty node or UE list, and on a KPM subscription whose event trigger period changed\n'
    printf 'verdict\tKPM is the quietest interface in this module: it needs no control, produces no packets to the UE, and returns a per-UE profile of the cell\n'
    return 0
}

oran_e2_control() {
    local ranfunc="${1:-2}" action="${2:-1}" ue="${3:-0}"
    [[ "$ranfunc" =~ ^[0-9]+$ && "$action" =~ ^[0-9]+$ ]] || { printf 'ERROR\tRAN function id and RIC action id are numeric\n' >&2; return 2; }
    local rn; case "$ranfunc" in 2) rn="ORAN-E2SM-RC" ;; 3) rn="ORAN-E2SM-KPM" ;; *) rn="custom" ;; esac
    printf 'procedure\tRIC Control Request\ne2ap_procedure_code\t6\nran_function_id\t%s\nran_function\t%s\nric_action_id\t%s\ntarget_ue\t%s\n' \
        "$ranfunc" "$rn" "$action" "$ue"
    printf 'attack\tRIC Control — a compromised or unsigned xApp drives handover, slicing or beam decisions through this message\n'
}
# The over-broad xApp: subscribe to KPM everywhere and hold RC control.
# ── D1 -- the policy that quietly moves the radio ───────────────────────
# A1 policies are per-slice statements of PRB share and 5QI set. The near-RT
# RIC applies each policy it holds; it does not add them up. So a policy that
# looks reasonable slice by slice can over-commit the cell, and the slice that
# loses is the one whose minimum was quietly lowered -- while the sum of the
# minimums still reads under 100 and passes a naive audit.
oran_a1_poison() {
    local victim="${1:-1}" attacker="${2:-2}" shift_pct="${3:-2}"
    [[ "$victim" =~ ^[1-3]$ && "$attacker" =~ ^[1-3]$ && "$victim" != "$attacker" ]] || {
        printf 'ERROR\t--a1-poison takes two different slice numbers 1..3\n' >&2; return 2; }
    [[ "$shift_pct" =~ ^[0-9]+$ ]] && (( shift_pct >= 1 && shift_pct <= 90 )) || {
        printf 'ERROR\tthe shift is a percentage 1..90\n' >&2; return 2; }
    # before: SST1 30-50, SST2 10-20, SST3 5-10 (oran_qos_policy_body defaults)
    local -a bn=(30 10 5) bx=(50 20 10)
    local -a an=("${bn[@]}") ax=("${bx[@]}")
    local keep=$shift_pct
    an[$((victim-1))]=$(( bn[$((victim-1))] - keep ))
    ax[$((victim-1))]=$(( bx[$((victim-1))] - keep ))
    (( an[$((victim-1))] < 1 )) && an[$((victim-1))]=1
    an[$((attacker-1))]=$(( bn[$((attacker-1))] + keep ))
    ax[$((attacker-1))]=$(( bx[$((attacker-1))] + keep ))
    (( ax[$((attacker-1))] > 99 )) && ax[$((attacker-1))]=99
    local i
    local bmin=0 bmax=0 amin=0 amax=0
    for i in 0 1 2; do
        bmin=$(( bmin + bn[i] )); bmax=$(( bmax + bx[i] ))
        amin=$(( amin + an[i] )); amax=$(( amax + ax[i] ))
    done
    printf 'policy_type_id\t20000\npolicy_instance_id\t1\nscope\tALL\n'
    printf 'method\tPUT\npath\t/A1-P/v2/policytypes/20000/policies/1\n'
    printf 'ledger\tslice\tprb_min_before\tprb_max_before\tprb_min_after\tprb_max_after\n'
    local sst
    for i in 0 1 2; do
        sst="SST $(( i + 1 ))"
        printf 'slice\t%s\t%s\t%s\t%s\t%s\n' "$sst" "${bn[i]}" "${bx[i]}" "${an[i]}" "${ax[i]}"
    done
    printf 'sum\tmin\t%s\t%s\n' "$bmin" "$amin"
    printf 'sum\tmax\t%s\t%s\n' "$bmax" "$amax"
    printf 'victim\t%s\tloses %s%% of its PRB floor\n' "SST $victim" "$keep"
    printf 'attacker_gain\t%s\tgains %s%%\n' "SST $attacker" "$keep"
    # the body, in the same shape the module already builds
    printf 'body\t{"scope":{"ueId":"ALL"},"statement":{"action":"slice-qos","policyTypeId":20000,"policyInstanceId":1,"slices":['
    for i in 0 1 2; do
        (( i > 0 )) && printf ','
        local q5; case "$i" in
            0) q5="1,5,6,9"; local ug=20000 dg=40000 ;;
            1) q5="82,85";   local ug=5000  dg=10000 ;;
            *) q5="9";       local ug=1000  dg=1000 ;;
        esac
        printf '{"snssai":{"sst":%d,"sd":"00000%d"},"prb":{"minPct":%d,"maxPct":%d},"quota":{"ulGbrKbps":%d,"dlGbrKbps":%d},"allowed5qi":[%s]}' \
            $(( i + 1 )) $(( i + 1 )) "${an[i]}" "${ax[i]}" "$ug" "$dg" "$q5"
    done
    printf ']}}\n'
    printf 'audit_naive\tmin-sum %s -> %s, max-sum %s -> %s: a redistribution moves nothing in the totals, so a check that adds slices cannot see it\n' \
        "$bmin" "$amin" "$bmax" "$amax"
    printf 'audit_honest\tcompare each slice against its previous body: SST %s fell %s -> %s while SST %s rose %s -> %s in the same PUT\n' \
        "$victim" "${bn[$((victim-1))]}" "${an[$((victim-1))]}" "$attacker" "${bn[$((attacker-1))]}" "${an[$((attacker-1))]}"
    printf 'overcommit\tif a policy instead raised a slice above the cell headroom (max-sum over 100), the scheduler decides per TTI who actually gets PRB and the over-committed slice is not the one that loses\n'
    printf 'finding\tquiet_shift\tHIGH\tthe change is %s percentage points on two slices and the totals do not move: small enough to read as retuning, large enough to move the victim below the level its 5QI set needs\n' "$keep"
    printf 'finding\tno_cross_policy_accounting\tHIGH\tthe near-RT RIC enforces each policy as written; nothing sums the slices, so an over-commit is invisible at the point of enforcement\n'
    printf 'finding\tfiveqi_carries_it\tMEDIUM\tthe 5QI set is what the scheduler weighs: leaving [1,5,6,9] on an under-fed slice does not restore the GFBR its bearers think they have\n'
    printf 'detect\taudit the policy store by max-sum per cell rather than per policy, and diff policy_instance bodies against the previous revision on every PUT\n'
    printf 'verdict\tA1 poisoning is arithmetic the RIC does not do: the poisoned policy is valid JSON, valid A1, and only the ledger for the whole cell shows it\n'
    return 0
}

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
        --e2-subscribe)    oran_e2_subscribe "${1:-1000}" "${2:-1}" ;;
        --xapp-attack)     oran_xapp_attack "${1:-rogue-xapp}" ;;
        --a1-poison)       oran_a1_poison "${1:-1}" "${2:-2}" "${3:-2}" ;;
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
  --e2-subscribe [period_ms] [style]   D2: the KPM subscription that returns
                          per-UE telemetry to any accepted xApp
  --xapp-attack [name]      the over-broad xApp model
  --a1-poison [victim] [attacker] [pct]
                            D1: a policy PUT that moves PRB from one
                            slice to another without changing the totals
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
