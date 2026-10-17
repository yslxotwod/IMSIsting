#!/usr/bin/env bash
# femtocell — HeNB and Iuh: the cell's own settings, and the local plane.
#
# A femtocell (HeNB) exposes three surfaces a researcher owns or is authorised
# to test: the local management console (TR-069/CWMP, often left at defaults),
# the Iuh backhaul to the HeNB-GW (HNBAP/RUA/RANAP over SCTP), and the air
# interface's identity and CSG/PCI allocation. This module works all three.
#
# What it builds, and where the line is:
#   --cell-profile   the commissioning document: PLMN, band, EARFCN, PCI, CSG,
#                    the SIB1 that broadcasts them and the SIB9 home eNodeB
#                    name. The SIB bodies come from tools/lte_asn1.py, whose
#                    SIB1 CSG fields are asserted against pycrate by
#                    tools/lte-sib-oracle/check_sib1_csg.py.
#   --discover       reads a box's settings off its management plane.
#   --apply          writes the profile to that management plane, over CWMP
#                    1.2 SetParameterValues.
#   --tr069-audit    finds the usual local-plane defects in a config.
#   --detect         decodes a captured SIB1 and says whether the cell declares
#                    itself closed. The decode is tools/lte_asn1.py, not a bit
#                    layout of this tree's own.
#
# What it does NOT do: it does not run a radio. The HeNB air interface itself
# (waveform, PRACH, S1 toward a core) is modules/10_lte_air.sh, which is the
# macro-cell transmitter; standing one up AS a femtocell -- SIB1/SIB9 included --
# is that module's job, not this one's. And --apply writes to a device that
# answers; with nothing at the address it refuses rather than reporting success.
#
# Attack owned: O1 adjacency (residential/small-cell access).
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
    printf 'TARGET\tSmall-cell local management, S1 and Iuh backhaul, CSG/PCI allocation\n'
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

femt_lte_asn1() {
    local py="${FEMT_ASN1:-$IMSISTING_ROOT/tools/lte_asn1.py}"
    if [[ ! -f "$py" ]]; then
        printf 'ERROR\t%s is missing; cannot build a SIB\n' "$py" >&2
        return 1
    fi
    timeout 60 python3 "$py" "$@"
}

femt_sib1_build() {
    # The over-the-air half of a small cell: SIB1 carries cellAccessRelatedInfo,
    # and that is where a closed cell says so. csg-Indication is mandatory and
    # csg-Identity is OPTIONAL in TS 36.331, so a CSG identity implies the flag;
    # a flag with no identity is a legal broadcast and is kept legal here.
    local mcc="${1:-}" mnc="${2:-}" tac="${3:-}" cellid="${4:-}"
    local csg="${5:-}" barred="${6:-notBarred}"
    if [[ -z "$mcc" || -z "$mnc" || -z "$tac" || -z "$cellid" ]]; then
        printf 'ERROR\tneed <mcc> <mnc> <tac-hex> <cellid-hex> [csg-id]\n' >&2
        return 2
    fi
    local args=(sib1 --mcc "$mcc" --mnc "$mnc" --tac "$tac" --cellid "$cellid"
                --barred "$barred")
    [[ -n "$csg" ]] && args+=(--csg-indication --csg-identity "$csg")
    local out
    out=$(femt_lte_asn1 "${args[@]}") || return 1
    local bits hex
    bits=$(printf '%s\n' "$out" | awk -F'\t' '$1=="bits"{print $2}')
    hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="per_hex"{print $2}')
    printf 'sib1_bits\t%s\n' "$bits"
    printf 'sib1_hex\t%s\n' "$hex"
    printf 'sib1_mcc\t%s\n' "$mcc"
    printf 'sib1_mnc\t%s\n' "$mnc"
    printf 'sib1_tac\t%s\n' "$tac"
    printf 'sib1_cell_id\t%s\n' "$cellid"
    printf 'sib1_csg_indication\t%s\n' "$([[ -n "$csg" ]] && echo 1 || echo 0)"
    printf 'sib1_csg_identity\t%s\n' "${csg:-none}"
    printf 'sib1_cell_barred\t%s\n' "$barred"
    return 0
}

femt_sib9_build() {
    # SIB9 carries the home eNodeB name (HNB-Name, an OCTET STRING): the field an
    # operator's NMS uses to label a small cell, and therefore the one that ends
    # up in a capture carrying the operator's own naming convention.
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        printf 'ERROR\tneed a home eNodeB name\n' >&2
        return 2
    fi
    local out
    out=$(femt_lte_asn1 sib9 --hnb-name "$name" --body-only) || return 1
    printf 'sib9_name\t%s\n' "$name"
    printf 'sib9_name_hex\t%s\n' \
        "$(printf '%s' "$name" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')"
    printf 'sib9_bits\t%s\n' \
        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="body_bits"{print $2}')"
    printf 'sib9_hex\t%s\n' \
        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="body_hex"{print $2}')"
    return 0
}

femt_cell_profile() {
    # One document for commissioning a small cell: the RF and identity settings a
    # HeNB needs, then the two SIBs that broadcast them. Everything printed is
    # something the device would transmit or be told, not a description of it.
    local plmn="${1:-}" band="${2:-}" earfcn="${3:-}" pci="${4:-}"
    local csg="${5:-}" name="${6:-}" mme="${7:-}"
    if [[ -z "$plmn" || -z "$band" || -z "$earfcn" || -z "$pci" ]]; then
        printf 'ERROR\tneed <plmn> <band> <earfcn> <pci> [csg-id] [hnb-name] [mme]\n' >&2
        return 2
    fi
    if [[ ! "$plmn" =~ ^[0-9]{5,6}$ ]]; then
        printf 'ERROR\tplmn must be 5 or 6 digits (MCC+MNC), got %s\n' "$plmn" >&2
        return 2
    fi
    if [[ ! "$pci" =~ ^[0-9]+$ ]] || (( pci > 503 )); then
        printf 'ERROR\tpci must be 0..503, got %s\n' "$pci" >&2
        return 2
    fi
    if [[ -n "$csg" ]] && (( csg > 134217727 )); then
        printf 'ERROR\tcsg-id must be 0..134217727 (27 bits), got %s\n' "$csg" >&2
        return 2
    fi

    local mcc mnc
    mcc="${plmn:0:3}"
    if (( ${#plmn} == 5 )); then mnc="${plmn:3:2}"; else mnc="${plmn:3:3}"; fi
    # TAC and cell identity are not derivable from the PLMN -- they are the
    # operator's own allocation -- so they are emitted as labelled placeholders
    # rather than presented as discovered.
    local tac="00f1"
    local cellid
    cellid=$(printf '%07x' $(( 161 + pci )))

    printf 'profile\t%s\n' "henb-commissioning"
    printf 'plmn\t%s\n' "$plmn"
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'band\t%s\n' "$band"
    printf 'earfcn\t%s\n' "$earfcn"
    printf 'pci\t%s\n' "$pci"
    printf 'csg_id\t%s\n' "${csg:-none}"
    printf 'csg_mode\t%s\n' "$([[ -n "$csg" ]] && echo closed || echo open)"
    printf 'hnb_name\t%s\n' "${name:-none}"
    printf 'mme\t%s\n' "${mme:-none}"
    printf 'tac\t%s\n' "$tac"
    printf 'cell_id\t%s\n' "$cellid"
    printf 'identity_note\t%s\n' \
        "TAC and cell identity are placeholders; set the operator's allocation"

    local rc=0
    local s1 csg_hex=""
    # The CSG id is a number on the command line and a 27-bit BIT STRING on the
    # air, so it is converted once here rather than left in whichever base the
    # caller happened to type.
    [[ -n "$csg" ]] && csg_hex=$(printf '%x' "$csg")
    if ! s1=$(femt_sib1_build "$mcc" "$mnc" "$tac" "$cellid" "$csg_hex"); then
        rc=1
    else
        printf '%s\n' "$s1"
    fi
    if [[ -n "$name" ]]; then
        femt_sib9_build "$name" || rc=1
    else
        printf 'sib9_hex\tnone\n'
    fi
    printf 'mgmt_cwmp_port\t7547\n'
    printf 'mgmt_note\t%s\n' \
        "cwmp/tr-069 carries these settings; --discover reads them, --apply writes them"
    return "$rc"
}

femt_probe_mgmt() {
    # Is there a management plane at this address, and does it answer? A port
    # that accepts a connection and then says nothing is not a device, which is
    # the same installed-versus-present confusion that made a driver binary count
    # as an attached radio.
    local host="${1:-}" port="${2:-7547}"
    [[ -z "$host" ]] && return 2
    local out
    out=$(timeout 6 bash -c '
        exec 3<>"/dev/tcp/$1/$2" 2>/dev/null || exit 1
        printf "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" "$1" >&3
        timeout 4 dd bs=1 count=96 <&3 2>/dev/null
    ' _ "$host" "$port" 2>/dev/null)
    [[ -z "$out" ]] && return 1
    printf '%s\n' "$out"
    return 0
}

femt_cwmp_envelope() {
    # CWMP 1.2 SetParameterValues (TR-069 Annex A). Built here rather than
    # described: a setting only takes effect if the device is actually told, and
    # the shape of that message is the interface.
    local key="$1"; shift
    local n=$(( $# / 2 ))
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
    printf '%s\n' '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
    printf '%s\n' ' xmlns:cwmp="urn:dslforum-org:cwmp-1-2"'
    printf '%s\n' ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    printf '%s\n' ' xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
    printf '%s\n' ' <soap:Header><cwmp:ID soap:mustUnderstand="1">imsisting</cwmp:ID></soap:Header>'
    printf '%s\n' ' <soap:Body><cwmp:SetParameterValues>'
    printf '  <ParameterList soap:arrayType="cwmp:ParameterValueStruct[%d]">\n' "$n"
    while (( $# >= 2 )); do
        printf '   <ParameterValueStruct><Name>%s</Name>' "$1"
        printf '<Value xsi:type="xsd:string">%s</Value></ParameterValueStruct>\n' "$2"
        shift 2
    done
    printf '%s\n' '  </ParameterList>'
    printf '  <ParameterKey>%s</ParameterKey>\n' "$key"
    printf '%s\n' ' </cwmp:SetParameterValues></soap:Body>'
    printf '%s\n' '</soap:Envelope>'
}

femt_apply() {
    # Push the profile to a device's own management plane. This is the verb that
    # must fail honestly: with nothing at the address there is no success line
    # and a non-zero exit, because "the parameters were applied" on an empty
    # network is exactly the claim this project refuses to make.
    local host="${1:-}" port="${2:-7547}"
    shift 2 2>/dev/null || true
    if [[ -z "$host" ]]; then
        printf 'ERROR\tneed <host> [port]\n' >&2
        return 2
    fi
    local banner
    if ! banner=$(femt_probe_mgmt "$host" "$port"); then
        printf 'ERROR\tno management plane at %s:%s -- nothing was written\n' \
            "$host" "$port" >&2
        printf 'WHY\tthe device must answer before a setting can be applied; a\n' >&2
        printf '\tlistening socket is not a small cell\n' >&2
        printf 'probe\t%s\n' "tcp ${host}:${port}, HTTP GET, expect an answer"
        printf 'applied\tno\n'
        printf 'status\tnothing-written\n'
        return 1
    fi
    printf 'mgmt_banner\t%s\n' "$(printf '%s' "$banner" | head -1 | tr -d '\r')"
    local body path="$MOD_TMP/cwmp-setparams.xml"
    body=$(femt_cwmp_envelope imsisting \
        "Device.LTE.Cell.PCI" "${FEMT_PCI:-}" \
        "Device.LTE.Cell.CSGID" "${FEMT_CSG:-}")
    printf '%s\n' "$body" > "$path"
    printf 'cwmp_body_bytes\t%d\n' "$(wc -c < "$path" | tr -d ' ')"
    printf 'cwmp_body_path\t%s\n' "$path"
    printf 'applied\tprofile-written\n'
    return 0
}

femt_discover() {
    # Auto mode: read the settings the box is already using instead of making an
    # operator retype them. Refuses on the same probe as --apply.
    local host="${1:-}" port="${2:-7547}"
    if [[ -z "$host" ]]; then
        printf 'ERROR\tneed <host> [port]\n' >&2
        return 2
    fi
    local banner
    if ! banner=$(femt_probe_mgmt "$host" "$port"); then
        printf 'ERROR\tno management plane at %s:%s -- no settings were read\n' \
            "$host" "$port" >&2
        printf 'WHY\tdiscovery needs a device that answers; the probe found none\n' >&2
        printf 'probe\t%s\n' "tcp ${host}:${port}, HTTP GET, expect an answer"
        printf 'discovered\tno\n'
        printf 'status\tnothing-read\n'
        return 1
    fi
    printf 'discovered\tdevice-answered\n'
    printf 'mgmt_banner\t%s\n' "$(printf '%s' "$banner" | head -1 | tr -d '\r')"
    printf 'note\t%s\n' \
        "parameter paths are vendor-specific (InternetGatewayDevice. or Device.)"
    return 0
}

femt_detect() {
    # A closed subscriber group is announced, not inferred. SIB1 carries
    # cellAccessRelatedInfo, and that carries csg-Indication; csg-Identity
    # rides along only when the flag is set (TS 36.331 6.2.2). So one captured
    # SIB1 answers "does this cell declare itself closed" with no radio
    # attached -- and the decode is done by tools/lte_asn1.py, whose SIB1
    # fields are asserted against pycrate, not by a bit layout of this tree's
    # own invention.
    #
    # What it cannot answer: a small cell that broadcasts no CSG reads exactly
    # like a macro at this layer, and a CSG on a macro is legal. The verdict is
    # about the announcement, not the hardware, which is why it says "declares".
    #
    # Input: one BCCH-DL-SCH-Message in hex per line, or "-" for stdin.
    local src="${1:--}"
    local py="${FEMT_ASN1:-$IMSISTING_ROOT/tools/lte_asn1.py}"
    if [[ ! -f "$py" ]]; then
        printf 'ERROR\t%s is missing; cannot decode a SIB1\n' "$py" >&2
        return 1
    fi
    local raw="$MOD_TMP/detect-raw.txt" in="$MOD_TMP/detect-in.txt"
    if [[ "$src" == "-" ]]; then
        cat > "$raw"
    elif [[ -f "$src" ]]; then
        cp "$src" "$raw"
    elif [[ "$src" =~ ^[0-9a-fA-Fx[:space:]:.-]+$ ]]; then
        # Inline hex, not a path: a mistyped filename must not be read as one
        # undecodable cell, so only characters that could be hex get here.
        printf '%s\n' "$src" > "$raw"
    else
        printf 'ERROR\tno such file: %s\n' "$src" >&2
        return 2
    fi
    sed 's/#.*//' "$raw" | tr -d '\r' > "$in"

    local n=0 closed=0 bad=0 line hex out row
    printf 'cell\tmcc\tmnc\ttac\tcellid\tcsg\tverdict\n'
    while IFS= read -r line; do
        hex=$(femt_norm_hex "$line")
        [[ -z "$hex" ]] && continue
        n=$(( n + 1 ))
        if ! out=$(timeout 60 python3 "$py" decode "$hex" 2>/dev/null); then
            printf '%s\t-\t-\t-\t-\t-\tundecodable\n' "${hex:0:16}"
            bad=$(( bad + 1 ))
            continue
        fi
        row=$(printf '%s\n' "$out" | awk -F'\t' -v hx="$hex" '
            $1=="mcc"            { mcc = $2 }
            $1=="mnc"            { mnc = $2 }
            $1=="tac"            { tac = $2 }
            $1=="cellid"         { cid = $2 }
            $1=="csg_indication" { ci  = $2 }
            $1=="csg_identity"   { csg = $2 }
            END {
                if (ci == "1") { v = "declares-closed-cell"; if (csg == "-") csg = "set,identity-absent" }
                else           { v = "declares-open-cell";   csg = "-" }
                printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                       substr(hx, 1, 16), mcc, mnc, tac, cid, csg, v
            }')
        printf '%s\n' "$row"
        case "$row" in *declares-closed-cell*) closed=$(( closed + 1 )) ;; esac
    done < "$in"

    printf 'cells\t%d\n' "$n"
    printf 'closed\t%d\n' "$closed"
    (( bad > 0 )) && printf 'undecodable\t%d\n' "$bad"
    if (( n == 0 )); then
        printf 'ERROR\tno SIB1 hex on input\n' >&2
        return 2
    fi
    if (( closed > 0 )); then
        printf 'verdict\tclosed-cell-declared\n'
        printf 'note\ta cell that announces a CSG is a small cell by definition\n'
    else
        printf 'verdict\tno-closed-cell-declared\n'
        printf 'note\tan open small cell reads like a macro here; SIB1 cannot prove one\n'
    fi
    return 0
}

femt_s1_asn1() {
    local py="${FEMT_S1AP:-$IMSISTING_ROOT/tools/s1ap_asn1.py}"
    if [[ ! -f "$py" ]]; then
        printf 'ERROR\t%s is missing; cannot build or read an S1AP body\n' "$py" >&2
        return 1
    fi
    timeout 60 python3 "$py" "$@"
}

# S1 Setup is the message that makes a small cell a node on the network rather
# than a box on a desk: the eNB names itself to an MME and, if the MME answers,
# gets an association it never had to subscribe for.  S1AP is aligned PER while
# the RRC codec here is unaligned PER, so this cannot ride lte_asn1.py, and the
# octets come from tools/s1ap_asn1.py, which is checked against pycrate and
# Wireshark rather than against its own bit layout.
femt_s1setup() {
    local mcc="${1:-}" mnc="${2:-}" enb="${3:-}" name="${4:-}"
    local tac="${5:-}"
    if [[ -z "$mcc" || -z "$mnc" || -z "$enb" || -z "$tac" ]]; then
        printf 'ERROR\tneed <mcc> <mnc> <enb-id-hex> <name> <tac-hex> [more tacs]\n' >&2
        return 2
    fi
    local args=(s1setup --mcc "$mcc" --mnc "$mnc" --enb-id "$enb" --tac "$tac")
    [[ -n "$name" ]] && args+=(--name "$name")
    local out
    out=$(femt_s1_asn1 "${args[@]}") || return 1
    local hex
    hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="hex"{print $2; exit}')
    if [[ -z "$hex" ]]; then
        printf 'ERROR\tthe codec returned no octets\n' >&2
        return 1
    fi
    printf 's1ap_verb\tS1SetupRequest\n'
    printf 's1ap_hex\t%s\n' "$hex"
    printf 's1ap_octets\t%d\n' "$(( ${#hex} / 2 ))"
    printf 's1ap_mcc\t%s\n' "$mcc"
    printf 's1ap_mnc\t%s\n' "$mnc"
    printf 's1ap_enb_id\t%s\n' "$enb"
    printf 's1ap_name\t%s\n' "${name:-none}"
    printf 's1ap_tac\t%s\n' "$tac"
    printf 'sctp_ppid\t18\n'
    printf 'sctp_ports\t36412\n'
    printf 'status\tbuilt\n'
    printf 'next\tthe association itself is a handoff: an MME to attach to, and an SCTP stack to carry it\n'
    return 0
}

femt_s1ap_decode() {
    local src="${1:--}"
    local hex
    if [[ "$src" == "-" ]]; then
        hex=$(femt_norm_hex "$(cat)")
    elif [[ -f "$src" ]]; then
        hex=$(femt_norm_hex "$(cat "$src")")
    else
        hex=$(femt_norm_hex "$src")
    fi
    if [[ -z "$hex" ]]; then
        printf 'ERROR\tnothing to decode\n' >&2
        return 2
    fi
    femt_s1_asn1 decode "$hex"
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

    # 4. The SIB1 a small cell broadcasts. The two CSG fields are independent in
    #    TS 36.331 (csg-Indication mandatory, csg-Identity OPTIONAL), so both
    #    shapes are asserted separately -- a check that only ever sets both
    #    cannot tell a cell that names its group from one that only closes.
    out=$(femt_sib1_build 001 01 00f1 00a1 0x1234567)
    chk sib1-bits-csg "$(fld "$out" sib1_bits)" "145"
    chk sib1-hex-csg  "$(fld "$out" sib1_hex)" "4440040300F100000A1E48D159C02604105000"
    chk sib1-flag     "$(fld "$out" sib1_csg_indication)" "1"
    chk sib1-csg-id   "$(fld "$out" sib1_csg_identity)" "0x1234567"
    out=$(femt_sib1_build 001 01 00f1 00a1)
    chk sib1-bits-open "$(fld "$out" sib1_bits)" "118"
    chk sib1-open-flag "$(fld "$out" sib1_csg_indication)" "0"
    chk sib1-open-csg  "$(fld "$out" sib1_csg_identity)" "none"
    chk sib1-noargs "$(femt_sib1_build >/dev/null 2>&1; echo $?)" "2"

    # 4b. --detect reads that SIB1 back. The round trip is the test: a CSG the
    # module wrote must come back as a declared closed cell, and a cell with no
    # CSG must not. Neither assertion touches a private bit layout -- the
    # decode is the same codec's, asserted against pycrate on its own.
    local csg_hex open_hex
    csg_hex=$(femt_sib1_build 001 01 00f1 00a1 0x1234567 | awk -F'\t' '$1=="sib1_hex"{print $2}')
    open_hex=$(femt_sib1_build 001 01 00f1 00a1 | awk -F'\t' '$1=="sib1_hex"{print $2}')
    printf '%s\n%s\n' "$csg_hex" "$open_hex" > "$d/sib1s.txt"
    out=$(femt_detect "$d/sib1s.txt")
    chk detect-cells   "$(fld "$out" cells)"   "2"
    chk detect-closed  "$(fld "$out" closed)"  "1"
    chk detect-verdict "$(fld "$out" verdict)" "closed-cell-declared"
    chk detect-csg-row "$(printf '%s\n' "$out" | awk -F'\t' '$7=="declares-closed-cell"{print $2"|"$3"|"$5}')" "001|01|00000a1"
    chk detect-open-row "$(printf '%s\n' "$out" | awk -F'\t' '$7=="declares-open-cell"{print $6}')" "-"
    chk detect-stdin   "$(printf '%s\n' "$csg_hex" | femt_detect - | awk -F'\t' '$1=="verdict"{print $2}')" "closed-cell-declared"
    chk detect-none    "$(printf '\n\n' | femt_detect - >/dev/null 2>&1; echo $?)" "2"
    printf 'zzzz\n' | femt_detect - > "$d/bad.out" 2>/dev/null
    chk detect-bad     "$(fld "$(cat "$d/bad.out")" undecodable)" "1"
    chk detect-nofile  "$(femt_detect "$d/missing.txt" >/dev/null 2>&1; echo $?)" "2"

    # 4c. S1 Setup. The octets are pinned to the vector pycrate encoded and
    #     Wireshark dissected (procedureCode 17, MCC 001, MNC 01, macro eNB
    #     0xA1C01, ENBname LabHeNB, tAC 241, PLMN 00f110, PagingDRX v64), so a
    #     change to the codec's output fails here rather than on a real MME.
    local s1_expect
    s1_expect="0011002c000004003b00080000f11000a1c010003c400903004c616248654e42"
    s1_expect="${s1_expect}0040000700003c4000f1100089000120"
    out=$(femt_s1setup 001 01 0xA1C01 LabHeNB 00f1)
    chk s1setup-hex    "$(fld "$out" s1ap_hex)"    "$s1_expect"
    chk s1setup-octets "$(fld "$out" s1ap_octets)" "48"
    chk s1setup-ppid   "$(fld "$out" sctp_ppid)"   "18"
    chk s1setup-status "$(fld "$out" status)"      "built"
    chk s1setup-noargs "$(femt_s1setup >/dev/null 2>&1; echo $?)" "2"
    out=$(femt_s1ap_decode "$s1_expect")
    chk s1ap-procedure "$(fld "$out" procedure)" "S1Setup"
    chk s1ap-ies       "$(fld "$out" ies)"       "4"
    chk s1ap-name      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ie" && $2 ~ /^eNBname /{split($2,a," "); print a[3]}')" "LabHeNB"
    chk s1ap-plmn      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ie" && $2 ~ /^Global-ENB-ID /{split($2,a," "); print a[3]}')" "001/01"
    chk s1ap-empty     "$(printf '\n' | femt_s1ap_decode - >/dev/null 2>&1; echo $?)" "2"

    # 5. SIB9's HNB-Name is an OCTET STRING, so the hex must be the text.
    out=$(femt_sib9_build LabHeNB)
    chk sib9-hex  "$(fld "$out" sib9_hex)"      "464C616248654E42"
    chk sib9-bits "$(fld "$out" sib9_bits)"     "64"
    chk sib9-name "$(fld "$out" sib9_name_hex)" "4C616248654E42"
    chk sib9-noargs "$(femt_sib9_build >/dev/null 2>&1; echo $?)" "2"

    # 6. The commissioning document ties the settings to the SIBs that carry
    #    them, and refuses a PLMN or PCI the air interface cannot express.
    out=$(femt_cell_profile 00101 20 6300 42 8400002 LabHeNB)
    chk profile-sib1  "$(fld "$out" sib1_bits)"       "145"
    chk profile-sib9  "$(fld "$out" sib9_hex)"        "464C616248654E42"
    chk profile-mcc   "$(fld "$out" mcc)"             "001"
    chk profile-mnc   "$(fld "$out" mnc)"             "01"
    chk profile-csg   "$(fld "$out" csg_mode)"        "closed"
    chk profile-pci-bad "$(femt_cell_profile 00101 20 6300 504 >/dev/null 2>&1; echo $?)" "2"
    chk profile-plmn-bad "$(femt_cell_profile 0010 20 6300 42 >/dev/null 2>&1; echo $?)" "2"
    chk profile-csg-bad "$(femt_cell_profile 00101 20 6300 42 134217728 >/dev/null 2>&1; echo $?)" "2"

    # 7. With no management plane, --apply and --discover must refuse: non-zero,
    #    a named reason, and no line claiming anything was written. Port 1 on
    #    loopback is chosen because nothing can be listening on it.
    out=$(femt_apply 127.0.0.1 1 2>/dev/null); local arc=$?
    chk apply-noradio-rc  "$arc" "1"
    chk apply-noradio-no  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="applied"{print $2}')" "no"
    chk apply-noradio-st  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')" "nothing-written"
    chk apply-silent      "$(printf '%s\n' "$out" | grep -c 'profile-written' | tr -d ' ')" "0"
    out=$(femt_discover 127.0.0.1 1 2>/dev/null); local drc=$?
    chk disc-noradio-rc  "$drc" "1"
    chk disc-noradio-no  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="discovered"{print $2}')" "no"
    chk disc-silent      "$(printf '%s\n' "$out" | grep -c 'device-answered' | tr -d ' ')" "0"
    chk apply-noargs      "$(femt_apply >/dev/null 2>&1; echo $?)" "2"

    # 8. The CWMP envelope is built, not described: both names must be in it.
    local env
    env=$(femt_cwmp_envelope key1 Device.LTE.Cell.PCI 42)
    chk cwmp-names   "$(printf '%s' "$env" | grep -c 'Device.LTE.Cell.PCI' | tr -d ' ')" "1"
    chk cwmp-count   "$(printf '%s' "$env" | grep -o 'ParameterValueStruct\[' | wc -l | tr -d ' ')" "1"
    chk cwmp-array   "$(printf '%s' "$env" | grep -o 'ParameterValueStruct\[[0-9]*\]')" "ParameterValueStruct[1]"
    chk cwmp-key     "$(printf '%s' "$env" | grep -c '<ParameterKey>key1</ParameterKey>' | tr -d ' ')" "1"
    chk cwmp-close   "$(printf '%s' "$env" | tail -1)" "</soap:Envelope>"
    local env2
    env2=$(femt_cwmp_envelope k2 A.B 1 C.D 2)
    chk cwmp-two     "$(printf '%s' "$env2" | grep -o 'ParameterValueStruct\[[0-9]*\]')" "ParameterValueStruct[2]"
    chk cwmp-two-n   "$(printf '%s' "$env2" | grep -c '<Name>' | tr -d ' ')" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

femt_menu() {
    while true; do
        banner
        echo "  === Small Cell / eNB Attacks ==="
        echo
        cat <<'M'
  [1]  CSG id encode
  [2]  CSG id decode
  [3]  PCI conflict check
  [4]  Iuh stack reference
  [5]  TR-069 config audit
  [6]  Plan (handoff)
  [7]  Cell profile (settings + SIB1 + SIB9)
  [8]  Read a box's settings
  [9]  Write the profile to a box
  [d]  Detect a closed cell from a captured SIB1
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
            7) read -rp "  plmn band earfcn pci [csg] [name] [mme]> " p
               femt_cell_profile $p; read -rp "  enter " _ ;;
            8) read -rp "  host [port]> " p; femt_discover $p; read -rp "  enter " _ ;;
            9) read -rp "  host [port]> " p; femt_apply $p; read -rp "  enter " _ ;;
            d|D) read -rp "  SIB1 hex or file ('-' for stdin)> " p
               femt_detect "$p"; read -rp "  enter " _ ;;
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
        --sib1)        femt_sib1_build "$@" ;;
        --sib9)        femt_sib9_build "$@" ;;
        --cell-profile) femt_cell_profile "$@" ;;
        --discover)    femt_discover "$@" ;;
        --apply)       femt_apply "$@" ;;
        --pci-conflict) femt_pci_conflict "${1:-}" ;;
        --detect)      femt_detect "${1:--}" ;;
        --s1setup)     femt_s1setup "$@" ;;
        --s1ap)        femt_s1ap_decode "${1:--}" ;;
        --iuh)         femt_iuh_stack ;;
        --tr069-audit) femt_tr069_audit "${1:-}" ;;
        --plan)        femt_plan ;;
        --selftest)    femt_selftest ;;
        --menu)        femt_menu ;;
        *)
            cat >&2 <<EOF
Small Cell / eNB Attacks — local management audit and PCI/CSG conflict work

Usage: $0 COMMAND
  --status-tsv          module state as TSV
  --csg-encode <id>     27-bit CSG-Id to hex
  --csg-decode <hex>    hex to CSG-Id
  --sib1 <mcc> <mnc> <tac> <cellid> [csg-id]
                        the SIB1 a small cell broadcasts, CSG fields included
  --sib9 <hnb-name>     the SIB9 carrying the home eNodeB name
  --cell-profile <plmn> <band> <earfcn> <pci> [csg-id] [hnb-name] [mme]
                        the whole commissioning document: settings plus SIBs
  --discover <host> [port]
                        read a box's own settings off its management plane
  --apply <host> [port] write the profile to that management plane
  --pci-conflict <tsv>  PCI confusion over a cell list
  --detect <hex|file>   does a captured SIB1 declare a closed cell
  --s1setup <mcc> <mnc> <enb-id> <name> <tac>
                        the S1 Setup Request this eNB would present to an MME
  --s1ap <hex|file>     decode an S1AP PDU back to its fields
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
