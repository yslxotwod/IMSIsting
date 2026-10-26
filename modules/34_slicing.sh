#!/usr/bin/env bash
# Slicing Escape — S-NSSAI codec, slice selection, isolation testing,
#                  5QI/TSN QoS descriptions and slice/QoS consistency
#                                                                   (tag: slic)
#
# Capability split, per MODULE_CONVENTIONS.md §9:
#
#   * Everything encodable is encoded for real. The S-NSSAI (SST/SD), the NSSAI
#     container, the registration-time selection outcome, and the isolation
#     evaluation over observed N3 transport endpoints are all computed here.
#   * The isolation evaluation is deliberately conservative: an isolation
#     conclusion is only reached when the capture (or an explicit mapping)
#     actually binds slices to transport endpoints. When a needed field is
#     absent the module says "not determinable from this capture" and names
#     the missing field. A false "isolated" is the one answer that must never
#     be produced.
#   * The QoS side is a table, not a guess: TS 23.501 Table 5.7.4-1 is
#     carried once and every 5QI verb reads it. A 5QI that is neither a row of
#     the table nor operator-specific (128-254) is refused, and a TSN/QoS
#     description whose GFBR/MFBR contradicts its resource type is refused
#     too, because a non-GBR flow has no GBR QoS information. Where the table
#     does not give a cell (5QI 75 is reserved in the carried copy) the module
#     prints `unknown`, never a plausible number.
#   * --tsn-config emits the field set of QosFlowLevelQosParameters but no
#     NGAP octets: tools/ngap_asn1.py has no encoder for that type, and the
#     module says so in a `limit` row instead of inventing PER bits.
#   * A slice-escape run needs a 5G SA testbed with two slices and a
#     subscription that is authorised for only one of them. That is a
#     `status: handoff` plan naming the testbed.
#
# Reference clause map (values asserted in --selftest are marked):
#   TS 23.003 §28.4.2      S-NSSAI: SST (1 octet) + SD (3 octets); SD
#                          0xFFFFFF means "no SD"
#   TS 23.501 §5.15.2.2    network slicing; Table 5.15.2.2-1 SST values
#   TS 23.501 §5.15.5.2.1  NSSF role in slice selection
#   TS 23.501 §5.15.5.3    S-NSSAI mapping between the HPLMN and the VPLMN
#   TS 23.501 §5.7.3       QoS flow / GBR vs non-GBR; gBR-QosInformation
#   TS 23.501 §5.7.4       the three 5QI resource types and the 5QI value
#                          ranges: 1-127 standardized, 128-254 operator-specific
#   TS 23.501 Table 5.7.4-1  standardized 5QI to QoS characteristics
#   TS 23.501 §5.7.4.3     TSC assistance information (periodicity, burst
#                          arrival time, N6 jitter range)
#   TS 24.501 §9.11.3.37   NSSAI / S-NSSAI information elements
#   TS 24.501 §9.11.3.46   rejected NSSAI and its cause values
#   TS 24.501 §8.2.6       Registration procedure (requested -> allowed NSSAI)
#   TS 23.502 §4.2.3       slice-specific authorisation and the NSSF
#   TS 29.244              PFCP: F-TEID, Node ID (for the isolation evidence)
#   TS 38.413              NGAP: PDU Session Resource Setup carries the S-NSSAI;
#                          QosFlowLevelQosParameters, GBR-QosInformation and
#                          PacketDelayBudget ::= INTEGER (0..1023) in 0.5 ms
#                          units — the pdb_0_5ms_units column
#   GSMA IR.88 / 5G SA     visited-network slice mapping enforcement
#
# Known-answer authorities used by --selftest:
#   * TS 23.003 §28.4.2 for the byte layout, and TS 23.501 Table 5.15.2.2-1
#     for the SST assignments (1 eMBB, 2 URLLC, 3 MIoT, 4 V2X, 5 HMTC).
#   * TS 23.501 Table 5.7.4-1 for every 5QI row --selftest asserts: the
#     resource type, priority level, PDB, PER, MDBV and averaging window are
#     literals from the table, so a mistyped row fails. Cells the carried table
#     does not give are printed `unknown` and asserted as such; the module does
#     not fill them from a plausible-looking default.
#   * Wireshark 4.2.2 `tshark`: the 5GS NAS framing used by --selection
#     ([extended protocol discriminator 0x7E][spare half octet | security
#     header type][message type][IEs]) was confirmed by exporting a PDU to the
#     `nas-5gs` dissector (`text2pcap -l 252 -P nas-5gs`); 7E 00 44 16 decodes
#     as Registration reject with 5GMM cause "Congestion (22)" and 7E 00 44 3E
#     as cause "No network slices available (62)", which --selftest asserts.
#
# Resolve IMSISTING_ROOT from this script's own path so state and loot land in
# the project tree even when launched standalone via pkexec (no launcher env).
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

MOD_TMP="$TMP_DIR/slicing"
SLIC_DIR="$LOOT_DIR/slicing"
SLIC_PLANS="$SLIC_DIR/plans"
mkdir -p "$MOD_TMP" "$SLIC_DIR" "$SLIC_PLANS" 2>/dev/null

# ── sanitisation and TSV splitting ──────────────────────────────────────
slic_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Split a TSV line into SLIC_F, preserving empty fields. Parameter expansion,
# never `IFS=$'\t' read` (MODULE_CONVENTIONS §12): a tab is whitespace to
# `read`, so a run of tabs collapses and every later field shifts.
SLIC_F=()
slic_split() {
    SLIC_F=()
    local line="${1:-}"
    while :; do
        if [[ "$line" == *$'\t'* ]]; then
            SLIC_F+=( "${line%%$'\t'*}" )
            line="${line#*$'\t'}"
        else
            SLIC_F+=( "$line" )
            break
        fi
    done
}

slic_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
slic_nfc() {
    local s="${1:-}"; s="${s^^}"; s="${s//[[:space:]]/}"; s="${s//:/}"; s="${s//-/}"
    printf '%s' "$s"
}
slic_is_hex() { [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 )); }

# ── SST table — TS 23.501 Table 5.15.2.2-1 ──────────────────────────────
# SST 0 is not assigned in the table; 1..5 are the standardised service types.
# An unknown SST is reported as unknown and is NEVER folded onto eMBB: a
# report that silently maps an unassigned value to eMBB would hide exactly the
# case an operator-specific slice is being used without authorisation.
slic_sst_name() {
    case "${1:-}" in
        1) echo "eMBB (enhanced Mobile Broadband)" ;;
        2) echo "URLLC (ultra-Reliable Low-Latency Communications)" ;;
        3) echo "MIoT (massive IoT / mMTC)" ;;
        4) echo "V2X (Vehicle-to-Everything)" ;;
        5) echo "HMTC (High-Performance Machine-Type Communications)" ;;
        *) echo "unknown" ;;
    esac
}

slic_sst_known() { [[ "$(slic_sst_name "${1:-}")" != "unknown" ]]; }

slic_sst_table() {
    cat <<'EOF'
sst	name	standard	source
1	eMBB (enhanced Mobile Broadband)	3GPP	TS 23.501 Table 5.15.2.2-1
2	URLLC (ultra-Reliable Low-Latency Communications)	3GPP	TS 23.501 Table 5.15.2.2-1
3	MIoT (massive IoT / mMTC)	3GPP	TS 23.501 Table 5.15.2.2-1
4	V2X (Vehicle-to-Everything)	3GPP	TS 23.501 Table 5.15.2.2-1
5	HMTC (High-Performance Machine-Type Communications)	3GPP	TS 23.501 Table 5.15.2.2-1
128-255	operator-specific	operator	TS 23.501 5.15.2.2: SST values 128-255 are operator-specific
note	0 is not assigned by the table; an unassigned value is reported as unknown and never mapped to eMBB		
EOF
}

# ── 5QI — TS 23.501 Table 5.7.4-1 ───────────────────────────────────────
# The standardized-5QI table is carried once, `|`-separated, and every 5QI verb
# reads it, so --five-qi, --five-qi-table, --tsn-config and --slice-qos-check
# cannot drift apart. Fields:
#   5qi|resource_type|priority|pdb_ms|per|mdbv|averaging_window|report_status|service
# "N/A" is the table's own cell value: the column does not apply to that 5QI (a
# non-GBR flow has no MDBV and no averaging window). The module writes
# "unknown" only where it cannot state a cell, and never puts a plausible
# number in its place. 5QI 75 is carried as "reserved": the copy of the table
# this module was taken from lists it as reserved for future use in that
# release (NOTE 14) and gives no characteristics, so all its cells are unknown.
slic_5qi_table_raw() {
    cat <<'EOF'
1|GBR|20|100|10^-2|N/A|2000|standardized|Conversational Voice
2|GBR|40|150|10^-3|N/A|2000|standardized|Conversational Video (Live Streaming)
3|GBR|30|50|10^-3|N/A|2000|standardized|Real Time Gaming, V2X messages, electricity distribution (medium voltage), process automation (monitoring)
4|GBR|50|300|10^-6|N/A|2000|standardized|Non-Conversational Video (Buffered Streaming)
5|non-GBR|10|100|10^-6|N/A|N/A|standardized|IMS Signalling
6|non-GBR|60|300|10^-6|N/A|N/A|standardized|Video (Buffered Streaming), TCP-based
7|non-GBR|70|100|10^-3|N/A|N/A|standardized|Voice, Video (Live Streaming), Interactive Gaming
8|non-GBR|80|300|10^-6|N/A|N/A|standardized|Video (Buffered Streaming), TCP-based
9|non-GBR|90|300|10^-6|N/A|N/A|standardized|Video (Buffered Streaming), TCP-based
65|GBR|7|75|10^-2|N/A|2000|standardized|Mission Critical user plane Push To Talk voice (MCPTT)
66|GBR|20|100|10^-2|N/A|2000|standardized|Non-Mission-Critical user plane Push To Talk voice
67|GBR|15|100|10^-3|N/A|2000|standardized|Mission Critical Video user plane
69|non-GBR|5|60|10^-6|N/A|N/A|standardized|Mission Critical delay sensitive signalling (MC-PTT signalling)
70|non-GBR|55|200|10^-6|N/A|N/A|standardized|Mission Critical Data
71|GBR|56|150|10^-6|N/A|2000|standardized|"Live" Uplink Streaming
72|GBR|56|300|10^-4|N/A|2000|standardized|"Live" Uplink Streaming
73|GBR|56|300|10^-8|N/A|2000|standardized|"Live" Uplink Streaming
74|GBR|56|500|10^-8|N/A|2000|standardized|"Live" Uplink Streaming
75|unknown|unknown|unknown|unknown|unknown|unknown|reserved|not given by the carried copy of the table (NOTE 14)
76|GBR|56|500|10^-4|N/A|2000|standardized|"Live" Uplink Streaming
79|non-GBR|65|50|10^-2|N/A|N/A|standardized|V2X messages
80|non-GBR|68|10|10^-6|N/A|N/A|standardized|Low Latency eMBB applications, Augmented Reality
82|delay-critical GBR|19|10|10^-4|255|2000|standardized|Discrete Automation
83|delay-critical GBR|22|10|10^-4|1354|2000|standardized|Discrete Automation, V2X messages (platooning)
84|delay-critical GBR|24|30|10^-5|1354|2000|standardized|Intelligent transport systems
85|delay-critical GBR|21|5|10^-5|255|2000|standardized|Electricity distribution (high voltage), V2X messages (remote driving)
86|delay-critical GBR|18|5|10^-4|1354|2000|standardized|V2X messages (advanced driving, collision avoidance)
87|delay-critical GBR|25|5|10^-3|500|2000|standardized|Interactive service (motion tracking data)
88|delay-critical GBR|25|10|10^-3|1125|2000|standardized|Interactive service (motion tracking data)
89|delay-critical GBR|25|15|10^-4|17000|2000|standardized|Visual content for cloud/edge/split rendering
90|delay-critical GBR|25|20|10^-4|63000|2000|standardized|Visual content for cloud/edge/split rendering
EOF
}

# slic_5qi_row <5qi> — the raw table row for an assigned 5QI, nothing if the
# value is not a row of the table.
slic_5qi_row() {
    local q="${1:-}"
    [[ "$q" =~ ^[0-9]{1,3}$ ]] || return 1
    slic_5qi_table_raw | awk -F'|' -v q="$q" '$1==q{print; exit}'
}

# slic_5qi_get <5qi> <field> — one cell of the table, empty when the row or the
# field does not exist (the caller distinguishes absent from "N/A").
slic_5qi_get() {
    local q="${1:-}" f="${2:-}" row
    row=$(slic_5qi_row "$q") || return 1
    [[ -n "$row" ]] || return 1
    case "$f" in
        resource_type) awk -F'|' '{print $2}' <<<"$row" ;;
        priority)      awk -F'|' '{print $3}' <<<"$row" ;;
        pdb_ms)        awk -F'|' '{print $4}' <<<"$row" ;;
        per)           awk -F'|' '{print $5}' <<<"$row" ;;
        mdbv)          awk -F'|' '{print $6}' <<<"$row" ;;
        avg_window)    awk -F'|' '{print $7}' <<<"$row" ;;
        status)        awk -F'|' '{print $8}' <<<"$row" ;;
        service)       awk -F'|' '{print $9}' <<<"$row" ;;
        *) return 1 ;;
    esac
}

slic_5qi_reserved() { [[ "${1:-}" == "75" ]]; }

# standardized | reserved | operator-specific | unassigned | invalid
slic_5qi_status() {
    local q="${1:-}"
    [[ "$q" =~ ^[0-9]{1,3}$ ]] || { printf 'invalid'; return 0; }
    (( q <= 255 )) || { printf 'invalid'; return 0; }
    if slic_5qi_reserved "$q"; then printf 'reserved'; return 0; fi
    [[ -n "$(slic_5qi_row "$q")" ]] && { printf 'standardized'; return 0; }
    if (( q >= 128 && q <= 254 )); then printf 'operator-specific'; return 0; fi
    printf 'unassigned'
}

# The PDB is signalled in TS 38.413 as PacketDelayBudget ::= INTEGER (0..1023)
# in units of 0.5 ms, so a 30 ms budget is 60 units.
slic_5qi_pdb_units() {
    local ms="${1:-}"
    [[ "$ms" =~ ^[0-9]+$ ]] || { printf 'unknown'; return 0; }
    printf '%d' "$(( ms * 2 ))"
}

# slic_5qi_desc <5qi> — the characteristics of one 5QI.
#   rc 0  the 5QI was decoded (standardized, reserved or operator-specific)
#   rc 1  a valid 5QI value that the table does not assign and that is not in
#         the operator-specific range: refused rather than guessed
#   rc 2  not a 5QI value at all
slic_5qi_desc() {
    local q="${1:-}"
    [[ -n "$q" ]] || { printf 'ERROR\tusage: --five-qi <5qi>\n' >&2; return 2; }
    if [[ ! "$q" =~ ^[0-9]{1,3}$ ]] || (( q > 255 )); then
        printf 'ERROR\t5QI must be a decimal value 0-255; got "%s"\n' "$(slic_sanitize "$q")" >&2
        printf 'WHY\tthe 5QI is a one-octet identifier (TS 23.501 5.7.4); "%s" is not one\n' "$(slic_sanitize "$q")" >&2
        return 2
    fi
    local st; st=$(slic_5qi_status "$q")
    case "$st" in
        unassigned)
            printf 'ERROR\t5QI %s is not in TS 23.501 Table 5.7.4-1 and is not operator-specific\n' "$q" >&2
            printf 'WHY\tthe carried table assigns 1-9, 65-67, 69-74, 76, 79-80 and 82-90; 75 is reserved in it and 128-254 are operator-specific. A value in neither set has no characteristics this module can state, and a plausible-looking row would be a guess\n' >&2
            return 1 ;;
        reserved)
            printf '5qi\t%s\n' "$q"
            printf 'status\treserved\n'
            printf 'resource_type\tunknown\n'
            printf 'priority_level\tunknown\n'
            printf 'pdb_ms\tunknown\n'
            printf 'pdb_0_5ms_units\tunknown\n'
            printf 'per\tunknown\n'
            printf 'mdbv_bytes\tunknown\n'
            printf 'averaging_window_ms\tunknown\n'
            printf 'service\tunknown\n'
            printf 'table\tTS 23.501 Table 5.7.4-1\n'
            printf 'note\t%s\n' "the carried copy of Table 5.7.4-1 lists 5QI 75 as reserved for future use and not supported in the release it was taken from (NOTE 14), so every characteristic is unknown here; a later release may assign it and this module does not guess the values"
            return 0 ;;
        operator-specific)
            printf '5qi\t%s\n' "$q"
            printf 'status\toperator-specific\n'
            printf 'resource_type\tunknown\n'
            printf 'priority_level\tunknown\n'
            printf 'pdb_ms\tunknown\n'
            printf 'pdb_0_5ms_units\tunknown\n'
            printf 'per\tunknown\n'
            printf 'mdbv_bytes\tunknown\n'
            printf 'averaging_window_ms\tunknown\n'
            printf 'service\tunknown\n'
            printf 'range\t128-254 operator-specific (TS 23.501 5.7.4)\n'
            printf 'note\t%s\n' "Table 5.7.4-1 gives no characteristics for 128-254: such a 5QI is pre-configured in the RAN, or signalled with the 5QI as a dynamically assigned 5QI inside QosFlowLevelQosParameters (TS 38.413). A default printed here would invent a QoS contract"
            return 0 ;;
    esac
    local rt pri pdb per mdbv avg svc
    rt=$(slic_5qi_get "$q" resource_type)
    pri=$(slic_5qi_get "$q" priority)
    pdb=$(slic_5qi_get "$q" pdb_ms)
    per=$(slic_5qi_get "$q" per)
    mdbv=$(slic_5qi_get "$q" mdbv)
    avg=$(slic_5qi_get "$q" avg_window)
    svc=$(slic_5qi_get "$q" service)
    printf '5qi\t%s\n' "$q"
    printf 'status\tstandardized\n'
    printf 'resource_type\t%s\n' "$rt"
    printf 'priority_level\t%s\n' "$pri"
    printf 'pdb_ms\t%s\n' "$pdb"
    printf 'pdb_0_5ms_units\t%s\n' "$(slic_5qi_pdb_units "$pdb")"
    printf 'per\t%s\n' "$per"
    printf 'mdbv_bytes\t%s\n' "$mdbv"
    printf 'averaging_window_ms\t%s\n' "$avg"
    printf 'service\t%s\n' "$svc"
    printf 'standardized\t%s\n' "yes"
    printf 'table\tTS 23.501 Table 5.7.4-1\n'
    case "$rt" in
        GBR) printf 'gbr_info_required\t%s\n' "yes: GFBR/MFBR in each direction (TS 23.501 5.7.3.3, gBR-QosInformation in TS 38.413)" ;;
        "delay-critical GBR") printf 'gbr_info_required\t%s\n' "yes: GFBR/MFBR plus the MDBV above (TS 23.501 5.7.4, delay-critical GBR)" ;;
        *) printf 'gbr_info_required\t%s\n' "no: a non-GBR flow carries no GBR QoS information" ;;
    esac
    [[ "$mdbv" == "N/A" ]] || printf 'mdbv_note\t%s\n' "the MDBV applies only to delay-critical GBR: (PDB - CN PDB) is the window it must fit in"
    return 0
}

slic_cmd_five_qi() {
    local q="${1:-}"
    [[ -n "$q" ]] || { printf 'ERROR\tusage: --five-qi <5qi>\n' >&2; return 2; }
    slic_5qi_desc "$q"
}

# --five-qi-table [resource-type] — the whole table, clause cited once.
slic_cmd_five_qi_table() {
    local want="${1:-}" field=2 value="" label=""
    case "${want,,}" in
        ""|all) ;;
        gbr) value="GBR"; label="GBR" ;;
        non-gbr|nongbr) value="non-GBR"; label="non-GBR" ;;
        delay-critical-gbr|dc-gbr|delay-critical|dcgbr) value="delay-critical GBR"; label="delay-critical GBR" ;;
        reserved) field=8; value="reserved"; label="reserved" ;;
        *)
            printf 'ERROR\tunknown resource type "%s"\n' "$(slic_sanitize "$want")" >&2
            printf 'WHY\twant gbr, non-gbr, delay-critical-gbr, reserved or all\n' >&2
            return 2 ;;
    esac
    printf '5qi\tresource_type\tpriority\tpdb_ms\tpdb_0_5ms_units\tper\tmdbv_bytes\taveraging_window_ms\tstatus\tservice\n'
    slic_5qi_table_raw | awk -F'|' -v f="$field" -v v="$value" '
        (v == "" || $f == v) {
            u = ($4 == "unknown") ? "unknown" : $4 * 2
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, u, $5, $6, $7, $8, $9
        }'
    printf 'source\tTS 23.501 Table 5.7.4-1 (Standardized 5QI to QoS characteristics mapping), clause 5.7.4\n'
    printf 'note\t%s\n' "N/A is the table's own cell (the column does not apply to that 5QI); unknown is a cell the carried table does not give (5QI 75 is reserved, NOTE 14). 5QI 128-254 are operator-specific and are listed here as a range row below"
    printf 'operator_specific\t128-254\tunknown\tunknown\tunknown\tunknown\tunknown\tunknown\toperator-specific\tcharacteristics pre-configured in the RAN or signalled dynamically in QosFlowLevelQosParameters (TS 38.413)\n'
    printf 'pdb_units\t%s\n' "pdb_0_5ms_units is the PDB in the 0.5 ms granularity of TS 38.413 PacketDelayBudget ::= INTEGER (0..1023)"
}

# ── TSN / QoS configuration — TS 23.501 §5.7.4.3, TS 38.413 ─────────────
# A TSN/QoS description as KEY=VALUE. Bits rates are bit/s with an optional
# k/M/G suffix; the TSC assistance information is in microseconds, which is the
# unit TS 38.413 carries (periodicity, burst arrival time, N6 jitter range).
slic_tsn_bps() {
    local v="${1:-}" n u e
    v="${v//[[:space:]]/}"
    [[ "$v" =~ ^([0-9]+)([kKmMgG]?)$ ]] || return 1
    n="${BASH_REMATCH[1]}"; u="${BASH_REMATCH[2],,}"
    case "$u" in
        "") e=1 ;;
        k)  e=1000 ;;
        m)  e=1000000 ;;
        g)  e=1000000000 ;;
    esac
    # The NGAP GBR QoS information field is 32 bits wide, in bit/s.
    (( n > 4000000000 / e )) && return 1
    printf '%d' "$(( n * e ))"
}

slic_bps_display() {
    local b="${1:-}"
    [[ "$b" =~ ^[0-9]+$ ]] || { printf 'unknown'; return 0; }
    if (( b >= 1000000000 && b % 1000000000 == 0 )); then printf '%d Gbit/s' "$(( b / 1000000000 ))"
    elif (( b >= 1000000 && b % 1000000 == 0 )); then printf '%d Mbit/s' "$(( b / 1000000 ))"
    elif (( b >= 1000 && b % 1000 == 0 )); then printf '%d kbit/s' "$(( b / 1000 ))"
    else printf '%d bit/s' "$b"; fi
}

# Can tools/ngap_asn1.py carry a QosFlowLevelQosParameters? Probed, never
# assumed: the module emits NGAP octets only from an encoder that exists.
slic_ngap_qos_encoder() {
    local t="$IMSISTING_ROOT/tools/ngap_asn1.py"
    [[ -r "$t" ]] || { printf 'missing'; return 0; }
    if grep -qi 'qos_flow_level_qos_parameters' "$t" 2>/dev/null; then
        printf 'present'
    else
        printf 'absent'
    fi
}

# slic_tsn_config <conf>
slic_tsn_config() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --tsn-config <conf>\n' >&2; return 2; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read %s\n' "$(slic_sanitize "$file")" >&2; return 1; }
    local fq="" gfbr_ul="" gfbr_dl="" mfbr_ul="" mfbr_dl="" avg="" qfi=""
    local tsc_per="" tsc_burst="" tsc_jit=""
    local line k v
    while IFS= read -r line; do
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || {
            printf 'ERROR\t%s is not KEY=VALUE\n' "$(slic_sanitize "$line")" >&2; return 2; }
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z')
        v=$(printf '%s' "${line#*=}" | tr -d ' ')
        case "$k" in
            5qi|five-qi|five_qi)  fq="$v" ;;
            gfbr_ul|gfbr-up)        gfbr_ul="$v" ;;
            gfbr_dl|gfbr-down)      gfbr_dl="$v" ;;
            mfbr_ul|mfbr-up)        mfbr_ul="$v" ;;
            mfbr_dl|mfbr-down)      mfbr_dl="$v" ;;
            averaging_window)       avg="$v" ;;
            qfi)                    qfi="$v" ;;
            tsc_periodicity)        tsc_per="$v" ;;
            tsc_burst_arrival_time) tsc_burst="$v" ;;
            tsc_jitter_range|tsc_jitter) tsc_jit="$v" ;;
            *)
                printf 'ERROR\tunknown key "%s" in %s\n' "$(slic_sanitize "$k")" "$(slic_sanitize "$file")" >&2
                printf 'WHY\taccepted keys: 5qi, qfi, gfbr_ul, gfbr_dl, mfbr_ul, mfbr_dl, averaging_window, tsc_periodicity, tsc_burst_arrival_time, tsc_jitter_range. An ignored key would silently drop part of the QoS description\n' >&2
                return 2 ;;
        esac
    done < "$file"

    [[ -n "$fq" ]] || {
        printf 'ERROR\t%s carries no 5qi= line\n' "$(slic_sanitize "$file")" >&2
        printf 'WHY\tthe 5QI is what every other characteristic hangs from; without it there is no QoS flow to describe\n' >&2
        return 2; }

    local st; st=$(slic_5qi_status "$fq")
    [[ "$st" == "unassigned" ]] && {
        printf 'ERROR\t5QI %s is not in TS 23.501 Table 5.7.4-1\n' "$(slic_sanitize "$fq")" >&2
        printf 'WHY\tuse --five-qi-table for the assigned values; a TSN/QoS description needs a 5QI whose resource type is known, because that decides whether GFBR/MFBR may appear at all\n' >&2
        return 1; }

    local rt; rt=$(slic_5qi_get "$fq" resource_type)
    [[ -n "$rt" ]] || rt="unknown"   # operator-specific / reserved
    local is_gbr=0
    case "$rt" in GBR|"delay-critical GBR") is_gbr=1 ;; esac

    local b
    if (( is_gbr == 0 )); then
        if [[ -n "$gfbr_ul" || -n "$gfbr_dl" || -n "$mfbr_ul" || -n "$mfbr_dl" || -n "$avg" ]]; then
            printf 'ERROR\t5QI %s is %s, which carries no GBR QoS information\n' "$fq" "$rt" >&2
            printf 'WHY\tonly a GBR or delay-critical GBR flow has GFBR/MFBR and an averaging window (TS 23.501 5.7.3.3); a non-GBR flow with a guaranteed bitrate is a description the core cannot honour\n' >&2
            return 2
        fi
    else
        [[ -n "$gfbr_ul" && -n "$gfbr_dl" && -n "$mfbr_ul" && -n "$mfbr_dl" ]] || {
            printf 'ERROR\t5QI %s is %s: gfbr_ul, gfbr_dl, mfbr_ul and mfbr_dl are all required\n' "$fq" "$rt" >&2
            printf 'WHY\ta GBR flow carries GFBR and MFBR in each direction in gBR-QosInformation (TS 38.413); 0 is a legal value, an absent direction is not describable\n' >&2
            return 2; }
    fi

    local g_ul=0 g_dl=0 m_ul=0 m_dl=0
    if (( is_gbr == 1 )); then
        g_ul=$(slic_tsn_bps "$gfbr_ul") || { printf 'ERROR\tgfbr_ul "%s" is not a bit rate\n' "$(slic_sanitize "$gfbr_ul")" >&2; printf 'WHY\tgive bit/s, or a value with a k/M/G suffix\n' >&2; return 2; }
        g_dl=$(slic_tsn_bps "$gfbr_dl") || { printf 'ERROR\tgfbr_dl "%s" is not a bit rate\n' "$(slic_sanitize "$gfbr_dl")" >&2; return 2; }
        m_ul=$(slic_tsn_bps "$mfbr_ul") || { printf 'ERROR\tmfbr_ul "%s" is not a bit rate\n' "$(slic_sanitize "$mfbr_ul")" >&2; return 2; }
        m_dl=$(slic_tsn_bps "$mfbr_dl") || { printf 'ERROR\tmfbr_dl "%s" is not a bit rate\n' "$(slic_sanitize "$mfbr_dl")" >&2; return 2; }
        (( g_ul <= m_ul )) || { printf 'ERROR\tgfbr_ul %s exceeds mfbr_ul %s\n' "$g_ul" "$m_ul" >&2; printf 'WHY\tthe guaranteed rate must not exceed the maximum (TS 23.501 5.7.3.3)\n' >&2; return 2; }
        (( g_dl <= m_dl )) || { printf 'ERROR\tgfbr_dl %s exceeds mfbr_dl %s\n' "$g_dl" "$m_dl" >&2; return 2; }
        [[ -n "$avg" ]] || avg=$(slic_5qi_get "$fq" avg_window)
        [[ "$avg" == "N/A" ]] && avg=2000
        [[ "$avg" =~ ^[0-9]+$ ]] && (( avg > 0 )) || { printf 'ERROR\taveraging_window "%s" must be a positive number of milliseconds\n' "$(slic_sanitize "$avg")" >&2; return 2; }
    fi

    [[ -z "$qfi" ]] || { [[ "$qfi" =~ ^[0-9]+$ ]] && (( qfi <= 63 )) || {
        printf 'ERROR\tqfi "%s" is not 0-63\n' "$(slic_sanitize "$qfi")" >&2
        printf 'WHY\tthe QFI is 6 bits in TS 24.501/38.413\n' >&2
        return 2; }; }

    # TSC assistance information: all three fields are optional, but the
    # periodicity is what the other two are relative to.
    if [[ -n "$tsc_burst" || -n "$tsc_jit" ]]; then
        [[ -n "$tsc_per" ]] || {
            printf 'ERROR\ttsc_burst_arrival_time/tsc_jitter_range given without tsc_periodicity\n' >&2
            printf 'WHY\tthe burst arrival time and the N6 jitter range are relative to the traffic periodicity (TS 23.501 5.7.4.3 TSC assistance information)\n' >&2
            return 2; }
    fi
    local t
    for t in "$tsc_per" "$tsc_burst"; do
        [[ -z "$t" ]] && continue
        [[ "$t" =~ ^[0-9]+$ ]] && (( t > 0 )) || {
            printf 'ERROR\tTSC value "%s" must be a positive number of microseconds\n' "$(slic_sanitize "$t")" >&2
            printf 'WHY\tTS 38.413 carries the TSC assistance information (periodicity, burst arrival time) in microseconds\n' >&2
            return 2; }
    done
    local jmin="" jmax=""
    if [[ -n "$tsc_jit" ]]; then
        if [[ "$tsc_jit" == *-* ]]; then
            jmin="${tsc_jit%%-*}"; jmax="${tsc_jit#*-}"
            [[ "$jmin" =~ ^[0-9]+$ && "$jmax" =~ ^[0-9]+$ ]] || {
                printf 'ERROR\ttsc_jitter_range "%s" must be min-max in microseconds\n' "$(slic_sanitize "$tsc_jit")" >&2; return 2; }
            (( jmin <= jmax )) || {
                printf 'ERROR\ttsc_jitter_range "%s" has min above max\n' "$(slic_sanitize "$tsc_jit")" >&2; return 2; }
        else
            [[ "$tsc_jit" =~ ^[0-9]+$ ]] || {
                printf 'ERROR\ttsc_jitter_range "%s" must be a number or min-max in microseconds\n' "$(slic_sanitize "$tsc_jit")" >&2; return 2; }
            jmin="$tsc_jit"; jmax="$tsc_jit"
        fi
    fi

    # The description itself. Field order follows QosFlowLevelQosParameters so
    # it can be read next to the NGAP message it would become.
    printf 'input\t%s\n' "$(slic_sanitize "$file")"
    # The 5QI's own default averaging window is kept apart from the effective
    # one below: two rows with the same key would make the value depend on
    # which row a reader happened to hit first.
    slic_5qi_desc "$fq" | awk -F'\t' 'BEGIN{OFS="\t"} $1=="averaging_window_ms"{$1="fiveqi_default_averaging_window_ms"}1'
    [[ -n "$qfi" ]] && printf 'qfi\t%s\n' "$qfi"
    if (( is_gbr == 1 )); then
        printf 'gfbr_ul_bps\t%d\n' "$g_ul"
        printf 'gfbr_dl_bps\t%d\n' "$g_dl"
        printf 'mfbr_ul_bps\t%d\n' "$m_ul"
        printf 'mfbr_dl_bps\t%d\n' "$m_dl"
        printf 'gfbr_ul_display\t%s\n' "$(slic_bps_display "$g_ul")"
        printf 'gfbr_dl_display\t%s\n' "$(slic_bps_display "$g_dl")"
        printf 'averaging_window_ms\t%s\n' "$avg"
    else
        printf 'gfbr_ul_bps\t%s\n' "N/A"
        printf 'gfbr_dl_bps\t%s\n' "N/A"
        printf 'mfbr_ul_bps\t%s\n' "N/A"
        printf 'mfbr_dl_bps\t%s\n' "N/A"
        printf 'averaging_window_ms\t%s\n' "N/A"
    fi
    if [[ -n "$tsc_per" ]]; then
        printf 'tsc_assistance\tpresent\n'
        printf 'tsc_periodicity_us\t%s\n' "$tsc_per"
        [[ -n "$tsc_burst" ]] && printf 'tsc_burst_arrival_time_us\t%s\n' "$tsc_burst"
        [[ -n "$jmin" ]] && printf 'tsc_n6_jitter_range_us\t%s-%s\n' "$jmin" "$jmax"
    else
        printf 'tsc_assistance\tabsent\n'
    fi

    # NGAP octets only from an encoder that exists.
    local enc; enc=$(slic_ngap_qos_encoder)
    if [[ "$enc" == "present" ]]; then
        printf 'ngap_qos_level_parameters\tnot-emitted\n'
        printf 'limit\t%s\n' "tools/ngap_asn1.py now greps for qos_flow_level_qos_parameters, but this module has no verified entry point to call, so no octets are emitted; inventing the ASN.1 PER bits would be worse than omitting them"
    else
        printf 'ngap_qos_level_parameters\tnot-emitted\n'
        printf 'limit\t%s\n' "tools/ngap_asn1.py carries no QosFlowLevelQosParameters encoder (grep -i qos_flow_level_qos_parameters: $enc), so no NGAP octets are emitted; the rows above are the field set such a message would carry, and hand-building the ASN.1 PER bits would produce octets nobody can verify"
    fi
    printf 'refs\tTS 23.501 5.7.3, 5.7.4 (Table 5.7.4-1), 5.7.4.3 TSC assistance information; TS 38.413 QosFlowLevelQosParameters, GBR-QosInformation, TSCAssistanceInformation\n'
    printf 'note\t%s\n' "nothing is transmitted: this is the description an N2 QoS profile would be built from"
    return 0
}

slic_cmd_tsn_config() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --tsn-config <conf>\n' >&2; return 2; }
    slic_tsn_config "$file"
}

# ── slice/flow QoS consistency — SST against the 5QI resource type ──────
# Each rule is a sentence, and the sentence is printed on the finding line: a
# verdict whose rule is hidden cannot be argued with or corrected.
slic_sst_expected_rt() {
    case "${1:-}" in
        1) printf 'non-GBR GBR' ;;
        2) printf 'GBR delay-critical GBR' ;;
        3) printf 'non-GBR GBR' ;;
        4) printf 'non-GBR GBR delay-critical GBR' ;;
        5) printf 'GBR delay-critical GBR' ;;
        *) printf '' ;;
    esac
}

# Per-row evaluation of one slice/flow. Arguments: slice sst fiveqi gfbr_ul gfbr_dl mfbr_ul mfbr_dl
# Emits `check` rows and `finding` rows; returns the number of conflicting rows
# through SLIC_QOS_BAD.
SLIC_QOS_BAD=0
slic_qos_row() {
    local slice="${1:-}" sst="${2:-}" fiveqi="${3:-}"
    local gu="${4:-}" gd="${5:-}" mu="${6:-}" md="${7:-}"
    local st rt name verdict="ok" rule="-"
    local -a findings=()
    st=$(slic_5qi_status "$fiveqi")
    rt=$(slic_5qi_get "$fiveqi" resource_type); [[ -n "$rt" ]] || rt="unknown"
    name=$(slic_sst_name "$sst")
    local known=1; slic_sst_known "$sst" || known=0

    local sev="HIGH"
    case "$st" in
        unassigned|invalid)
            findings+=( "HIGH" "5qi_not_in_table" "the 5QI is not a row of TS 23.501 Table 5.7.4-1 and is not operator-specific, so its resource type is unknown and the SST/5QI consistency cannot be judged (5QI $fiveqi)" )
            verdict="not-determinable"; rule="5qi_not_in_table" ;;
    esac

    if [[ "$verdict" == "ok" && "$st" == "standardized" ]]; then
        if (( known == 0 )) && (( sst >= 128 && sst <= 255 )); then
            verdict="not-determinable"; rule="sst_operator_specific"
            findings+=( "INFO" "sst_operator_specific" "an operator-specific SST ($sst) declares no 3GPP service type, so the 5QI/resource-type consistency cannot be checked without the operator's SST map" )
        elif (( known == 0 )); then
            verdict="not-determinable"; rule="sst_not_in_table"
            findings+=( "INFO" "sst_not_in_table" "SST $sst is not one of 1-5 in TS 23.501 Table 5.15.2.2-1, so no expected resource type exists for it" )
        else
            case "$sst:$rt" in
                1:"delay-critical GBR")
                    verdict="conflict"; rule="sst1_no_delay_critical"
                    findings+=( "HIGH" "sst1_no_delay_critical" "an SST 1 (eMBB) slice must not carry a delay-critical GBR flow: that resource type is the URLLC class (TS 23.501 5.7.4), so the SST and the 5QI disagree about the service — declared SST 1 (eMBB) with 5QI $fiveqi ($rt)" ) ;;
                2:"non-GBR")
                    verdict="conflict"; rule="sst2_requires_guarantee"
                    findings+=( "HIGH" "sst2_requires_guarantee" "an SST 2 (URLLC) slice carrying a non-GBR 5QI has no guaranteed bitrate and no delay-critical handling: URLLC needs GBR or delay-critical GBR (TS 23.501 5.7.4) — declared SST 2 (URLLC) with 5QI $fiveqi (non-GBR)" ) ;;
                3:"delay-critical GBR")
                    verdict="conflict"; rule="sst3_no_delay_critical"
                    findings+=( "HIGH" "sst3_no_delay_critical" "an SST 3 (MIoT/mMTC) slice must not carry a delay-critical GBR flow: mMTC is the non-GBR mass class (TS 23.501 5.15.2.2-1), and a delay-critical flow reserves resources mMTC does not need — declared SST 3 (MIoT) with 5QI $fiveqi ($rt)" ) ;;
                5:"non-GBR")
                    verdict="conflict"; rule="sst5_requires_guarantee"
                    findings+=( "MEDIUM" "sst5_requires_guarantee" "an SST 5 (HMTC) slice carrying a non-GBR 5QI has no resource guarantee: HMTC flows are ordered as GBR or delay-critical GBR (TS 23.501 5.7.4) — declared SST 5 (HMTC) with 5QI $fiveqi (non-GBR)" ) ;;
            esac
        fi
    fi

    # GBR bookkeeping, independent of the SST rule.
    if [[ "$verdict" != "not-determinable" && "$st" == "standardized" ]]; then
        case "$rt" in
            GBR|"delay-critical GBR")
                if [[ -z "$gu" || -z "$gd" || -z "$mu" || -z "$md" ]]; then
                    [[ "$verdict" == "ok" ]] && { verdict="conflict"; rule="gbr_requires_bitrate"; }
                    local have=""
                    [[ -n "$gu" ]] && have+=" ul_gfbr=$gu"
                    [[ -n "$gd" ]] && have+=" dl_gfbr=$gd"
                    [[ -n "$mu" ]] && have+=" ul_mfbr=$mu"
                    [[ -n "$md" ]] && have+=" dl_mfbr=$md"
                    [[ -n "$have" ]] || have=" none"
                    findings+=( "HIGH" "gbr_requires_bitrate" "a $rt flow must carry GFBR and MFBR in each direction (TS 23.501 5.7.3.3, gBR-QosInformation in TS 38.413); this row declares${have}, and a missing direction is a profile the core cannot honour" )
                else
                    (( gu <= mu )) || { [[ "$verdict" == "ok" ]] && { verdict="conflict"; rule="mfbr_lt_gfbr"; }
                        findings+=( "HIGH" "mfbr_lt_gfbr" "MFBR must be >= GFBR in the same direction; this row has gfbr_ul=$gu > mfbr_ul=$mu" ); }
                    (( gd <= md )) || { [[ "$verdict" == "ok" ]] && { verdict="conflict"; rule="mfbr_lt_gfbr"; }
                        findings+=( "HIGH" "mfbr_lt_gfbr" "MFBR must be >= GFBR in the same direction; this row has gfbr_dl=$gd > mfbr_dl=$md" ); }
                fi ;;
            non-GBR)
                if [[ -n "$gu$gd$mu$md" ]]; then
                    [[ "$verdict" == "ok" ]] && { verdict="conflict"; rule="non_gbr_has_bitrate"; }
                    findings+=( "HIGH" "non_gbr_has_bitrate" "a non-GBR flow has no GBR QoS information, so a GFBR/MFBR on it is either a mis-mapped flow or a profile the core will not honour (TS 23.501 5.7.3.3)" )
                fi ;;
        esac
    fi

    printf 'check\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(slic_sanitize "$slice")" "$(slic_sanitize "$sst")" "$(slic_sanitize "$name")" \
        "$(slic_sanitize "$fiveqi")" "$(slic_sanitize "$rt")" "$verdict" "$rule"
    local i
    for (( i = 0; i + 2 < ${#findings[@]}; i += 3 )); do
        [[ -n "${findings[$i]:-}" ]] || continue
        printf 'finding\t%s\t%s\t%s\t%s\n' "$(slic_sanitize "$slice")" \
            "${findings[$i]}" "${findings[$i+1]}" "${findings[$((i+2))]}"
        [[ "${findings[$i]}" == "HIGH" ]] && SLIC_QOS_BAD=$(( SLIC_QOS_BAD + 1 ))
    done
    return 0
}

# slic_slice_qos_check <tsv>
#   slice  sst  5qi  [gfbr_ul_bps gfbr_dl_bps mfbr_ul_bps mfbr_dl_bps]
# The header names the columns; an unknown column is refused, never ignored.
slic_slice_qos_check() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --slice-qos-check <tsv>\n' >&2; return 2; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read %s\n' "$(slic_sanitize "$file")" >&2; return 1; }
    local header="" line
    while IFS= read -r line; do
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        header="$line"; break
    done < "$file"
    [[ -n "$header" ]] || { printf 'ERROR\t%s has no header row\n' "$(slic_sanitize "$file")" >&2; return 2; }
    slic_split "$header"
    local -A col=()
    local i
    for (( i = 0; i < ${#SLIC_F[@]}; i++ )); do
        case "${SLIC_F[$i],,}" in
            slice|name)          col[slice]=$i ;;
            sst)                 col[sst]=$i ;;
            5qi|fiveqi|five_qi)  col[fiveqi]=$i ;;
            gfbr_ul_bps)         col[gu]=$i ;;
            gfbr_dl_bps)         col[gd]=$i ;;
            mfbr_ul_bps)         col[mu]=$i ;;
            mfbr_dl_bps)         col[md]=$i ;;
            *)
                printf 'ERROR\tunknown column "%s" in the header of %s\n' "$(slic_sanitize "${SLIC_F[$i]}")" "$(slic_sanitize "$file")" >&2
                printf 'WHY\taccepted columns: slice, sst, 5qi, gfbr_ul_bps, gfbr_dl_bps, mfbr_ul_bps, mfbr_dl_bps. Ignoring a column would drop the fact it was meant to contribute\n' >&2
                return 2 ;;
        esac
    done
    local need
    for need in slice sst fiveqi; do
        [[ -n "${col[$need]:-}" ]] || {
            printf 'ERROR\tthe header of %s has no %s column\n' "$(slic_sanitize "$file")" "$need" >&2
            printf 'WHY\tthe check needs the slice name, its declared S-NSSAI SST and its 5QI for every row\n' >&2
            return 2; }
    done
    SLIC_QOS_BAD=0
    printf 'input\t%s\n' "$(slic_sanitize "$file")"
    printf 'header\tslice\tsst\tsst_name\t5qi\tresource_type\tverdict\trule\n'
    local n=0 bad=0
    while IFS= read -r line; do
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == "$header" ]] && continue
        slic_split "$line"
        local slice="${SLIC_F[${col[slice]}]:-}"
        local sst="${SLIC_F[${col[sst]}]:-}"
        local fiveqi="${SLIC_F[${col[fiveqi]}]:-}"
        local gu="" gd="" mu="" md=""
        [[ -n "${col[gu]:-}" ]] && gu="${SLIC_F[${col[gu]}]:-}"
        [[ -n "${col[gd]:-}" ]] && gd="${SLIC_F[${col[gd]}]:-}"
        [[ -n "${col[mu]:-}" ]] && mu="${SLIC_F[${col[mu]}]:-}"
        [[ -n "${col[md]:-}" ]] && md="${SLIC_F[${col[md]}]:-}"
        if [[ ! "$sst" =~ ^[0-9]{1,3}$ ]] || (( sst > 255 )); then
            printf 'ERROR\tSST "%s" on slice "%s" is not 0-255\n' "$(slic_sanitize "$sst")" "$(slic_sanitize "$slice")" >&2
            printf 'WHY\tSST is one octet (TS 23.501 5.15.2.2)\n' >&2
            return 2
        fi
        local v
        for v in "$gu" "$gd" "$mu" "$md"; do
            [[ -z "$v" ]] && continue
            [[ "$v" =~ ^[0-9]+$ ]] || {
                printf 'ERROR\tbit rate "%s" on slice "%s" is not a number of bit/s\n' "$(slic_sanitize "$v")" "$(slic_sanitize "$slice")" >&2
                return 2; }
        done
        local before=$SLIC_QOS_BAD
        slic_qos_row "$slice" "$sst" "$fiveqi" "$gu" "$gd" "$mu" "$md"
        (( SLIC_QOS_BAD > before )) && bad=$(( bad + 1 ))
        n=$(( n + 1 ))
    done < "$file"
    (( n > 0 )) || { printf 'ERROR\t%s has no data rows\n' "$(slic_sanitize "$file")" >&2; return 1; }
    printf 'rows\t%d\n' "$n"
    printf 'conflicts\t%d\n' "$bad"
    printf 'verdict\t%s\n' "$([[ $bad -gt 0 ]] && echo conflicts || echo consistent)"
    return 0
}

slic_cmd_slice_qos_check() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --slice-qos-check <tsv>\n' >&2; return 2; }
    slic_slice_qos_check "$file"
}

# ── S-NSSAI codec — TS 23.003 §28.4.2 ───────────────────────────────────
# S-NSSAI = SST (1 octet) + SD (3 octets). The SD is 0xFFFFFF when the slice
# has no differentiator, and the "no SD" form is transmitted as SST only.
slic_encode_s_nssai() {
    local sst="${1:-}" sd="${2:-}"
    [[ "$sst" =~ ^[0-9]+$ ]] && (( sst <= 255 )) || {
        printf 'ERROR\tSST must be 1-3 decimal digits (0-255)\n' >&2; return 1; }
    case "${sd,,}" in
        ""|none|ffffff|no-sd|nosd) sd="FFFFFF" ;;
        *) sd=$(slic_nfc "$sd")
           [[ "$sd" =~ ^[0-9A-Fa-f]{6}$ ]] || {
               printf 'ERROR\tSD must be 3 octets of hex (e.g. 000001) or "none"\n' >&2; return 1; } ;;
    esac
    printf '%s%s' "$(slic_byte "$sst")" "${sd^^}"
}

slic_decode_s_nssai() {
    local hex; hex=$(slic_nfc "${1:-}")
    slic_is_hex "$hex" || { printf 'ERROR\tS-NSSAI needs hex\n' >&2; return 1; }
    local n=$(( ${#hex} / 2 ))
    case "$n" in
        1)  printf 's_nssai\t%s\n' "$hex"
            printf 'length\t1\n'
            printf 'sst\t%s\n' "$(( 16#$hex ))"
            printf 'sst_name\t%s\n' "$(slic_sst_name $(( 16#$hex )))"
            printf 'sd\tffffff\n'
            printf 'sd_present\t0\n'
            printf 'note\t%s\n' "SST only: the slice has no slice differentiator on the wire (TS 24.501 9.11.3.37)"
            return 0 ;;
        4)  local sst=$(( 16#${hex:0:2} )) sd="${hex:2:6}"
            printf 's_nssai\t%s\n' "$hex"
            printf 'length\t4\n'
            printf 'sst\t%s\n' "$sst"
            printf 'sst_name\t%s\n' "$(slic_sst_name "$sst")"
            printf 'sst_known\t%s\n' "$(slic_sst_known "$sst" && echo yes || echo no)"
            printf 'sd\t%s\n' "${sd,,}"
            printf 'sd_present\t%s\n' "$([[ "${sd^^}" == "FFFFFF" ]] && echo 0 || echo 1)"
            printf 'sd_decimal\t%s\n' "$(( 16#$sd ))"
            return 0 ;;
        *)  printf 'ERROR\tS-NSSAI is 1 octet (SST) or 4 octets (SST+SD); got %s octets\n' "$n" >&2
            return 1 ;;
    esac
}

# ── NSSAI container — TS 24.501 §9.11.3.37 ──────────────────────────────
# An NSSAI is a sequence of S-NSSAIs, each itself length-prefixed:
#   [len=1][SST] | [len=4][SST][SD][SD][SD] ...
# A full NSSAI IE prepends an IEI octet and a length octet. slic_nssai_parse
# accepts either the container value or the full IE (it detects the leading
# IEI by checking whether the first octet matches the remaining length).
slic_nssai_parse() {
    local hex; hex=$(slic_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --nssai-parse <hex>\n' >&2; return 2; }
    slic_is_hex "$hex" && (( ${#hex} >= 4 )) || { printf 'ERROR\tNSSAI needs hex (a container value or a full IE)\n' >&2; return 1; }
    local off=0 iei=""
    # Full-IE form: [IEI][len][content...]. If the length fits the remainder
    # exactly and the first octet is not itself a plausible S-NSSAI length
    # header that consumes the whole thing, treat it as an IE.
    local first=$(( 16#${hex:0:2} ))
    local len2=$(( 16#${hex:2:2} ))
    if (( (off + 2 + len2) * 2 == ${#hex} )) && (( first != 1 && first != 4 )); then
        iei=$(slic_byte "$first")
        off=2
        printf 'iei\t%s\n' "$iei"
    fi
    printf 'container\t%s\n' "${hex:$((off*2))}"
    printf 'header\ts_nssai\tsst\tsst_name\tsd\tsd_present\n'
    local idx=0
    while (( off * 2 < ${#hex} )); do
        (( ${#hex} >= (off + 1) * 2 )) || { printf 'ERROR\tNSSAI is truncated at S-NSSAI %s\n' "$idx" >&2; return 1; }
        local l=$(( 16#${hex:$((off*2)):2} ))
        (( l == 1 || l == 4 )) || {
            printf 'ERROR\tS-NSSAI %s declares length %s; TS 24.501 allows 1 or 4\n' "$idx" "$l" >&2; return 1; }
        (( ${#hex} >= (off + 1 + l) * 2 )) || {
            printf 'ERROR\tS-NSSAI %s is truncated\n' "$idx" >&2; return 1; }
        local v="${hex:$(((off+1)*2)):$((l*2))}"
        local sst=$(( 16#${v:0:2} ))
        local sd="ffffff" present=0
        if (( l == 4 )); then sd="${v:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; fi
        printf 'entry\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$idx" "$v" "$sst" "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present"
        idx=$(( idx + 1 ))
        off=$(( off + 1 + l ))
    done
    printf 'count\t%s\n' "$idx"
    return 0
}

# ── slice selection ─────────────────────────────────────────────────────
# slic_selection <requested-nssai> [allowed-nssai] [rejected-nssai]
#
# The outcome classes are the ones that matter for security:
#   allowed            requested and in the allowed NSSAI
#   rejected           requested and in the rejected NSSAI (with its cause)
#   dropped            requested, neither allowed nor rejected — silently
#                      discarded, which is the case an operator cannot see
#   unrequested-allowed  in the allowed NSSAI but never requested: the network
#                      granted a slice the UE did not ask for, which is the
#                      "honoured without authorisation" class
# With only the requested NSSAI the outcome is not determinable; the function
# says so rather than assuming.
slic_selection() {
    local req="${1:-}" allow="${2:-}" rej="${3:-}"
    [[ -n "$req" ]] || { printf 'ERROR\tusage: --selection <requested-nssai-hex> [allowed-hex] [rejected-hex]\n' >&2; return 2; }
    local rp; rp=$(slic_nssai_parse "$req") || return 1
    local -a req_list=()
    local line
    while IFS= read -r line; do
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "entry" ]] && req_list+=( "${SLIC_F[2]}" )
    done <<<"$rp"
    printf 'requested_count\t%s\n' "${#req_list[@]}"
    printf 'header\tclass\ts_nssai\tsst\tsst_name\tsd\tsd_present\tdetail\n'
    if [[ -z "$allow" && -z "$rej" ]]; then
        local v idx=0
        for v in "${req_list[@]}"; do
            local sst=$(( 16#${v:0:2} ))
            local sd="ffffff" present=0
            (( ${#v} == 8 )) && { sd="${v:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; }
            printf 'selection\trequested\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$v" "$sst" "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" \
                "outcome not determinable from this input: no allowed or rejected NSSAI supplied"
            idx=$(( idx + 1 ))
        done
        printf 'outcome\tnot-determinable\n'
        printf 'missing\t%s\n' "the allowed NSSAI (and the rejected NSSAI with its cause) from the Registration Accept"
        return 0
    fi
    local -A allow_set rej_set rej_cause
    local ap rjp
    if [[ -n "$allow" ]]; then
        ap=$(slic_nssai_parse "$allow") || return 1
        while IFS= read -r line; do
            slic_split "$line"
            [[ "${SLIC_F[0]:-}" == "entry" ]] && allow_set["${SLIC_F[2]}"]=1
        done <<<"$ap"
    fi
    if [[ -n "$rej" ]]; then
        rjp=$(slic_nssai_parse "$rej") || return 1
        while IFS= read -r line; do
            slic_split "$line"
            [[ "${SLIC_F[0]:-}" == "entry" ]] && rej_set["${SLIC_F[2]}"]=1
        done <<<"$rjp"
    fi
    local v sst sd present nallow=0 nrej=0 ndrop=0 nbad=0
    for v in "${req_list[@]}"; do
        sst=$(( 16#${v:0:2} )); sd="ffffff"; present=0
        (( ${#v} == 8 )) && { sd="${v:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; }
        if [[ -n "${allow_set[$v]:-}" ]]; then
            nallow=$(( nallow + 1 ))
            printf 'selection\tallowed\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$sst" \
                "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" "granted"
        elif [[ -n "${rej_set[$v]:-}" ]]; then
            nrej=$(( nrej + 1 ))
            printf 'selection\trejected\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$sst" \
                "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" "rejected NSSAI"
        else
            ndrop=$(( ndrop + 1 ))
            printf 'selection\tdropped\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$sst" \
                "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" \
                "neither allowed nor rejected: the UE has no signal about why"
        fi
    done
    # Allowed but never requested: the grant the UE did not ask for.
    local k
    for k in "${!allow_set[@]}"; do
        local found=0 r
        for r in "${req_list[@]}"; do [[ "$r" == "$k" ]] && found=1; done
        (( found )) && continue
        nbad=$(( nbad + 1 ))
        sst=$(( 16#${k:0:2} )); sd="ffffff"; present=0
        (( ${#k} == 8 )) && { sd="${k:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; }
        printf 'selection\tunrequested-allowed\t%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "$sst" \
            "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" \
            "the allowed NSSAI grants a slice the UE never requested"
    done
    printf 'outcome\t%s\n' "$([[ $nbad -gt 0 || $ndrop -gt 0 ]] && echo anomalous || echo consistent)"
    printf 'allowed\t%s\n' "$nallow"
    printf 'rejected\t%s\n' "$nrej"
    printf 'dropped\t%s\n' "$ndrop"
    printf 'unrequested_allowed\t%s\n' "$nbad"
    if (( nbad > 0 )); then
        printf 'finding\tHIGH\tunrequested-allowed-slice\tthe network granted a slice outside the requested set\n'
    fi
    if (( ndrop > 0 )); then
        printf 'finding\tMEDIUM\tsilently-dropped-request\ta requested slice was neither allowed nor rejected\n'
    fi
    return 0
}

# ── 5GS NAS slice extraction (for --selection on a captured PDU) ────────
# 5GS plain NAS framing (verified with Wireshark 4.2.2 via
# `text2pcap -l 252 -P nas-5gs`): octet 1 extended protocol discriminator
# (0x7E for 5GMM), octet 2 spare half octet | security header type, octet 3
# message type, then the information elements.
slic_nas_5gs_type() {
    local hex; hex=$(slic_nfc "${1:-}")
    slic_is_hex "$hex" && (( ${#hex} >= 6 )) || return 1
    [[ "${hex:0:2}" == "7E" ]] || return 1
    printf '%d' "$(( 16#${hex:4:2} ))"
}

slic_nas_5gs_message_name() {
    case "${1:-}" in
        65) echo "Registration request" ;;
        66) echo "Registration accept" ;;
        67) echo "Registration complete" ;;
        68) echo "Registration reject" ;;
        76) echo "Service request" ;;
        77) echo "Service reject" ;;
        78) echo "Service accept" ;;
        193) echo "PDU session establishment request" ;;
        194) echo "PDU session establishment accept" ;;
        195) echo "PDU session establishment reject" ;;
        *) echo "unknown" ;;
    esac
}

# The 5GMM cause of a Registration reject / Service reject, which is the octet
# immediately after the 3-octet 5GS plain-NAS header. Verified: 7E 00 44 16 is
# "Congestion (22)" and 7E 00 44 3E is "No network slices available (62)".
slic_nas_5gs_cause() {
    local hex; hex=$(slic_nfc "${1:-}")
    local t; t=$(slic_nas_5gs_type "$hex") || return 1
    case "$t" in
        68|77) (( ${#hex} >= 8 )) && printf '%d' "$(( 16#${hex:6:2} ))" ;;
        *) printf '' ;;
    esac
}

slic_5gmm_cause_name() {
    case "${1:-}" in
        22)  echo "Congestion" ;;
        62)  echo "No network slices available" ;;
        65)  echo "Maximum number of PDU sessions reached" ;;
        67)  echo "Insufficient resources for specific slice and DNN" ;;
        69)  echo "Insufficient resources for specific slice" ;;
        73)  echo "Serving network not authorized" ;;
        91)  echo "DNN not supported or not subscribed in the slice" ;;
        92)  echo "Insufficient user-plane resources for the PDU session" ;;
        *)   echo "unknown" ;;
    esac
}

# ── isolation evidence ──────────────────────────────────────────────────
# A pcap alone can show the N3 transport (GTP-U endpoints and TEIDs) but not
# which slice a TEID belongs to: the S-NSSAI lives in the NAS/NGAP signalling.
# The module therefore accepts an explicit slice->TEID mapping and compares:
#   * dedicated UPF      distinct N3 endpoints per slice
#   * shared-transport   different S-NSSAIs on the same N3 endpoint
#   * shared-upf-shared-teid-space  same endpoint AND overlapping TEIDs
# Anything it cannot establish is reported as not-determinable.
slic_pcap_py() {
    cat <<'PYEOF'
import sys, struct

def _u16(b, o, e): return struct.unpack_from(e + 'H', b, o)[0]
def _u32(b, o, e): return struct.unpack_from(e + 'I', b, o)[0]

def classic(data):
    magic = data[:4]
    if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): e = '>'
    elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): e = '<'
    else: return None, None
    if len(data) < 24: return None, None
    lt = _u32(data, 20, e); off, out = 24, []
    while off + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack_from(e + 'IIII', data, off)
        off += 16
        if incl > len(data) - off: break
        out.append((data[off:off + incl],))
        off += incl
    return lt, out

def pcapng(data):
    off, e, seen, lts, out = 0, '<', False, [], []
    while off + 12 <= len(data):
        probe = struct.unpack_from('<I', data, off)[0]
        if probe == 0x0A0D0D0A or (not seen and data[off:off + 4] == b'\x0a\x0d\x0d\x0a'):
            bom = struct.unpack_from('<I', data, off + 8)[0]
            e = '<' if bom == 0x1A2B3C4D else '>'; seen = True
        btype = _u32(data, off, e); blen = _u32(data, off + 4, e)
        if blen < 12 or off + blen > len(data): break
        body = data[off + 8:off + blen - 4]
        if btype == 1: lts.append(_u16(body, 0, e))
        elif btype == 6:
            iface = _u32(body, 0, e); cap = _u32(body, 12, e)
            out.append(((lts[iface] if iface < len(lts) else 1), body[20:20 + cap]))
        elif btype == 3:
            orig = _u32(body, 0, e); out.append(((lts[0] if lts else 1), body[4:4 + orig]))
        off += blen
    return out

def ipv4(t):
    if len(t) < 20: return None
    ihl = (t[0] & 0x0F) * 4
    if ihl < 20 or len(t) < ihl: return None
    if struct.unpack_from('>H', t, 6)[0] & 0x1FFF: return None
    return t[9], '.'.join(str(x) for x in t[12:16]), '.'.join(str(x) for x in t[16:20]), t[ihl:]

def l3(t, lt):
    if lt == 1:
        if len(t) < 14: return None
        et = struct.unpack_from('>H', t, 12)[0]; off = 14
        while et in (0x8100, 0x88A8) and len(t) >= off + 4:
            et = struct.unpack_from('>H', t, off + 2)[0]; off += 4
        return ipv4(t[off:]) if et == 0x0800 else None
    if lt in (101, 12, 14, 228): return ipv4(t)
    if lt == 113: return ipv4(t[16:]) if len(t) >= 16 and _u16(t, 14, '>') == 0x0800 else None
    if lt == 276: return ipv4(t[20:]) if len(t) >= 20 and _u16(t, 0, '>') == 0x0800 else None
    return None

def pfcp_ies(hexs):
    # TS 29.244: IE = type (2) + length (2) + value, 4-octet aligned.
    out, b, off = [], bytes.fromhex(hexs), 0
    while off + 4 <= len(b):
        t = struct.unpack_from('>H', b, off)[0]
        ln = struct.unpack_from('>H', b, off + 2)[0]
        if off + 4 + ln > len(b): break
        out.append((t, b[off + 4:off + 4 + ln]))
        off += 4 + ln + ((4 - ln % 4) % 4)
    return out

def main():
    path = sys.argv[1]
    with open(path, 'rb') as f: data = f.read()
    lt, pkts = classic(data)
    if lt is not None:
        frames = [(1, p[0]) for p in pkts]
    else:
        frames = [(lt2, p) for lt2, p in pcapng(data)]
    for linktype, pkt in frames:
        parsed = l3(pkt, linktype)
        if not parsed: continue
        proto, src, dst, payload = parsed
        if proto != 17 or len(payload) < 8: continue
        sp, dp = struct.unpack_from('>HH', payload, 0)
        up = payload[8:]
        if 2152 in (sp, dp) and len(up) >= 8:
            flags = up[0]
            if (flags >> 5) & 0x07 == 1:
                teid = struct.unpack_from('>I', up, 4)[0]
                print('gtpu\t%s\t%s\t%d' % (src, dst, teid))
        elif 8805 in (sp, dp) and len(up) >= 8:
            mtype = up[1]
            body = up[4:]
            nodeid = ''
            fteid = ''
            for t, v in pfcp_ies(body.hex()):
                if t == 60 and len(v) >= 5:   # Node ID (IPv4)
                    nodeid = '.'.join(str(x) for x in v[1:5])
                elif t == 21 and len(v) >= 9: # F-TEID
                    fteid = str(struct.unpack_from('>I', v, 1)[0])
            if nodeid or fteid:
                print('pfcp\t%s\t%s\t%d\t%s\t%s' % (src, dst, mtype, nodeid or '-', fteid or '-'))
    return 0

sys.exit(main())
PYEOF
}

slic_gtpu_flows() {
    local pcap="${1:-}"
    [[ -r "$pcap" ]] || { printf 'ERROR\tcannot read capture: %s\n' "$(slic_sanitize "$pcap")" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'MISSING\tpython3 is required to read a capture\n' >&2; return 1; }
    python3 <(slic_pcap_py) "$pcap"
}

# slic_isolation_check <pcap> [slice=teid[,teid];slice=teid...]
#
# Without a slice->TEID mapping the capture cannot bind a slice to transport,
# and the answer is "not-determinable" naming the missing binding. With a
# mapping, the transport endpoints per slice are compared.
slic_isolation_check() {
    local pcap="${1:-}" map="${2:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --isolation-check <pcap> [slice=teid[,teid];...]\n' >&2; return 2; }
    local obs; obs=$(slic_gtpu_flows "$pcap") || return 1
    local gtpu_lines pfcp_lines
    gtpu_lines=$(printf '%s\n' "$obs" | awk -F'\t' '$1=="gtpu"')
    pfcp_lines=$(printf '%s\n' "$obs" | awk -F'\t' '$1=="pfcp"')
    printf 'capture\t%s\n' "$(slic_sanitize "$pcap")"
    printf 'gtpu_flows\t%s\n' "$(printf '%s\n' "$gtpu_lines" | grep -c .)"
    printf 'pfcp_messages\t%s\n' "$(printf '%s\n' "$pfcp_lines" | grep -c .)"
    printf 'header\tobservation\tsrc\tdst\tdetail\n'
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "gtpu" ]] && printf 'gtpu\tflow\t%s\t%s\tteid=%s\n' \
            "$(slic_sanitize "${SLIC_F[1]}")" "$(slic_sanitize "${SLIC_F[2]}")" "$(slic_sanitize "${SLIC_F[3]}")"
    done <<<"$gtpu_lines"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "pfcp" ]] && printf 'pfcp\tmessage\t%s\t%s\ttype=%s node=%s f-teid=%s\n' \
            "$(slic_sanitize "${SLIC_F[1]}")" "$(slic_sanitize "${SLIC_F[2]}")" \
            "$(slic_sanitize "${SLIC_F[3]}")" "$(slic_sanitize "${SLIC_F[4]}")" "$(slic_sanitize "${SLIC_F[5]}")"
    done <<<"$pfcp_lines"

    if [[ -z "$map" ]]; then
        printf 'isolation\tnot-determinable\n'
        printf 'missing\t%s\n' "the S-NSSAI to TEID/N3 binding, which lives in the NAS/NGAP signalling, and a cross-slice reachability observation (a pcap cannot show whether slice A's user plane can reach slice B's service)"
        printf 'finding\tINFO\tnot-determinable-from-capture\tthe capture shows the transport but not which slice owns it; supply slice=teid[,...];... to evaluate\n'
        return 0
    fi

    # Parse the mapping: "slice=teid[,teid];slice=teid"
    local -A slice_teids slice_endpoints
    local part
    local IFS=';'
    for part in $map; do
        local name="${part%%=*}" teids="${part#*=}"
        [[ "$name" != "$part" && -n "$teids" ]] || {
            printf 'ERROR\tslice map entries must be slice=teid[,teid]; got "%s"\n' "$(slic_sanitize "$part")" >&2
            unset IFS; return 2; }
        local t
        local IFS=','
        for t in $teids; do
            [[ "$t" =~ ^[0-9]+$ ]] || { printf 'ERROR\tTEID must be decimal: "%s"\n' "$(slic_sanitize "$t")" >&2; unset IFS; return 2; }
            slice_teids["$name"]+="${slice_teids[$name]:+,}${t}"
            local ep
            ep=$(printf '%s\n' "$gtpu_lines" | awk -F'\t' -v t="$t" '$3==t || $4==t {print $2"->"$3; exit}')
            [[ -n "$ep" ]] && slice_endpoints["$name"]+="${slice_endpoints[$name]:+,}${ep}"
        done
        unset IFS
    done
    unset IFS

    local -a names=()
    local k
    for k in "${!slice_teids[@]}"; do names+=( "$k" ); done
    if (( ${#names[@]} < 2 )); then
        printf 'isolation\tnot-determinable\n'
        printf 'missing\t%s\n' "fewer than two slices were mapped; cross-slice isolation needs at least two"
        return 0
    fi
    printf 'header2\tslice\tslice\tevaluated\tshared_endpoints\n'
    local i j a b ea eb shared
    for (( i = 0; i < ${#names[@]}; i++ )); do
        for (( j = i + 1; j < ${#names[@]}; j++ )); do
            a="${names[$i]}"; b="${names[$j]}"
            ea="${slice_endpoints[$a]:-}"; eb="${slice_endpoints[$b]:-}"
            if [[ -z "$ea" || -z "$eb" ]]; then
                printf 'pair\t%s\t%s\tnot-determinable\tno observed GTP-U flow for the mapped TEID(s)\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")"
                continue
            fi
            shared=""
            local e
            local IFS=','
            for e in $ea; do
                local f
                for f in $eb; do [[ "$e" == "$f" ]] && shared="$e"; done
            done
            unset IFS
            if [[ -n "$shared" ]]; then
                printf 'pair\t%s\t%s\tshared-transport\t%s\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")" "$(slic_sanitize "$shared")"
                printf 'finding\tHIGH\tslice-isolation-failure\tslices %s and %s share the N3 endpoint %s, so any transport-level enforcement of the slice boundary is absent\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")" "$(slic_sanitize "$shared")"
            else
                printf 'pair\t%s\t%s\tdistinct-transport\t%s vs %s\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")" "$(slic_sanitize "$ea")" "$(slic_sanitize "$eb")"
            fi
        done
    done
    printf 'isolation\t%s\n' "distinct-transport-is-not-isolation: different N3 endpoints are necessary but not sufficient; a user-plane reachability test between the slices is still required"
    return 0
}

# ── detection rules for slice events ────────────────────────────────────
# Row: event frame ts ue slice kind cause
#   kind = register | session-establish | session-modify | reject
slic_detect_stream() {
    local line
    local -A seen_slice_by_ue last_slice_by_ue
    local n=0
    local frame ts ue slice kind cause
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "event" ]] || continue
        n=$(( n + 1 ))
        frame="${SLIC_F[1]:-}"; ts="${SLIC_F[2]:-}"; ue="${SLIC_F[3]:-}"
        slice="${SLIC_F[4]:-}"; kind="${SLIC_F[5]:-}"; cause="${SLIC_F[6]:-}"
        # 1. an unexpected S-NSSAI in a session establishment: a slice this UE
        #    has never registered on.
        if [[ "$kind" == "session-establish" ]]; then
            if [[ -n "${last_slice_by_ue[$ue]:-}" && "${last_slice_by_ue[$ue]}" != "$slice" ]]; then
                printf 'FINDING\tHIGH\tslice-change-mid-session\t%s\tue %s established a session on %s while its registration slice was %s\n' \
                    "$(slic_sanitize "$frame")" "$(slic_sanitize "$ue")" "$(slic_sanitize "$slice")" "$(slic_sanitize "${last_slice_by_ue[$ue]}")"
            fi
            if [[ -z "${seen_slice_by_ue[$ue|$slice]:-}" ]]; then
                printf 'FINDING\tMEDIUM\tunexpected-s-nssai-in-session\t%s\tue %s requested a session on %s with no prior registration on it\n' \
                    "$(slic_sanitize "$frame")" "$(slic_sanitize "$ue")" "$(slic_sanitize "$slice")"
            fi
        fi
        if [[ "$kind" == "register" ]]; then
            seen_slice_by_ue["$ue|$slice"]=1
            last_slice_by_ue["$ue"]="$slice"
        fi
        if [[ "$kind" == "reject" && -n "$cause" ]]; then
            # A rejection cause tells an observer which slices the
            # subscription has and which the network will not serve.
            case "$cause" in
                62|69|91|67)
                    printf 'FINDING\tMEDIUM\trejection-cause-reveals-slice-config\t%s\tue %s got cause %s (%s), which names the slice configuration\n' \
                        "$(slic_sanitize "$frame")" "$(slic_sanitize "$ue")" "$(slic_sanitize "$cause")" \
                        "$(slic_sanitize "$(slic_5gmm_cause_name "$cause")")" ;;
            esac
        fi
    done
    (( n > 0 )) || { printf 'ERROR\tno slice events to inspect\n' >&2; return 1; }
    return 0
}

slic_cmd_detect() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --detect <slice-events.tsv>\n' >&2; return 2; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read %s\n' "$(slic_sanitize "$file")" >&2; return 1; }
    printf 'input\t%s\n' "$(slic_sanitize "$file")"
    printf 'header\tseverity\trule\tframe\tdetail\n'
    slic_detect_stream < "$file"
}

# ── attack surface and vulnerability classes ────────────────────────────
# ── D3 -- the cross-slice reachability matrix ───────────────────────────
# A slice is an S-NSSAI in the signalling plus a forwarding instance in the
# UPF. The tests below are the ones that decide whether the second half
# exists: addressing first (can the two slices even see each other), then
# authorisation (is a session in one slice entitled to reach the other), then
# the resource half (does the 5QI carry the PRB the slice was promised).
slic_cmd_cross_slice() {
    local a="${1:-1}" b="${2:-2}" sub_a="${3:-10.45.0.0/16}" sub_b="${4:-10.46.0.0/16}"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$a" != "$b" ]] || {
        printf 'ERROR\t--cross-slice takes two different slice identifiers\n' >&2; return 2; }
    printf 'slice_a\tSST %s\nslice_b\tSST %s\nsubnet_a\t%s\nsubnet_b\t%s\n' "$a" "$b" "$(slic_sanitize "$sub_a")" "$(slic_sanitize "$sub_b")"
    printf 'test\tT1\tdirection\tA -> B\n'
    printf 'test_artefact\tT1\tping -c3 -W2 <b-host-in-%s>\n' "$(slic_sanitize "$sub_b")"
    printf 'test_expected\tT1\tunreachable\n'
    printf 'test_why\tT1\tif each slice has its own UPF network instance, the PDU session in A has no route to a %s address; reachability means the two slices share a forwarding instance\n' "$(slic_sanitize "$sub_b")"
    printf 'test\tT2\tdirection\tB -> A\n'
    printf 'test_artefact\tT2\tping -c3 -W2 <a-host-in-%s>\n' "$(slic_sanitize "$sub_a")"
    printf 'test_expected\tT2\tunreachable\n'
    printf 'test_why\tT2\tasymmetric separation is a finding in itself: one direction open is a misconfigured ACL, not a policy\n'
    printf 'test\tT3\tdirection\tA -> B service port\n'
    printf 'test_artefact\tT3\tcurl -m3 http://<b-service-in-%s>/\n' "$(slic_sanitize "$sub_b")"
    printf 'test_expected\tT3\tno route or connection refused\n'
    printf 'test_why\tT3\tthe user plane has no slice field in the GTP-U header: what stops A reaching B is the UPF network instance plus an ACL, never the S-NSSAI in the NAS\n'
    printf 'test\tT4\tdirection\tA -> B with a second session\n'
    printf 'test_artefact\tT4\topen two PDU sessions from the same UE (S-NSSAIs %s and %s) and repeat T1\n' "$a" "$b"
    printf 'test_expected\tT4\tunreachable\n'
    printf 'test_why\tT4\ttwo sessions is the standard way a UE gets two addresses; a UE with both sees the crossing as a routing decision, so the UPF must not route between its own slices\n'
    printf 'test\tT5\tdirection\tauthorisation\n'
    printf 'test_artefact\tT5\tregister with an Allowed NSSAI of {%s} and request a PDU session for %s\n' "$a" "$b"
    printf 'test_expected\tT5\treject (5GMM cause 62 or 69)\n'
    printf 'test_why\tT5\tTS 23.501 5.15.5.2.1 puts the check at the AMF/NSSF: a session for a slice outside the subscription must never be established, however the NSSAI was requested\n'
    printf 'test\tT6\tdirection\t5QI inside the slice\n'
    printf 'test_artefact\tT6\trequest a QFI/5QI from slice B within a session in slice A (--slice-qos-check the body first)\n'
    printf 'test_expected\tT6\t5QI outside the slice ARP/5QI set is rejected; unknown 5QI must not silently take the default\n'
    printf 'test_why\tT6\tthe 5QI selects the scheduler weight, so a low-priority slice that can ask for 5QI 1 takes the PRB the other slice was promised\n'
    printf 'test\tT7\tdirection\tresource half\n'
    printf 'test_artefact\tT7\trun N parallel sessions in slice %s and measure slice %s PRB\n' "$a" "$b"
    printf 'test_expected\tT7\tno change in slice %s once its guaranteed share is met\n' "$b"
    printf 'test_why\tT7\tRAN slice share is per-slice RRM policy: if N sessions in A move the PRB that B sees, the share is enforced per UE or per bearer, not per slice\n'
    printf 'finding\tshared_instance\t%s\tthe deciding fact is whether the two slices terminate on one UPF network instance; a shared one makes every test above a routing question\n' \
        "$( [[ "$(printf '%s' "$sub_a" | cut -d. -f1-2)" == "$(printf '%s' "$sub_b" | cut -d. -f1-2)" ]] && echo HIGH || echo INFO )"
    printf 'finding\tlabel_not_boundary\tHIGH\tthe S-NSSAI is carried in NAS/NGAP and never in GTP-U; a network that signals isolation and shares forwarding has only the label\n'
    printf 'finding\tno_recheck\tMEDIUM\tslice selection at registration is not re-run for every session: T5 is the test that catches an AMF that only consults the NSSF once\n'
    printf 'detect\tat the UPF record per-slice network instance on every GTP-U flow; at the AMF count PDU sessions whose S-NSSAI is outside the Allowed NSSAI; in the RAN alert when a slice share drifts while its own session count is flat\n'
    printf 'verdict\tisolation is a forwarding fact and a share fact: the tests above are cheap, and a slice that passes T1-T4 but fails T6/T7 is isolated on paper only\n'
    return 0
}

slic_surface_notes() {
    cat <<'EOF'
class	mechanism	precondition	impact	note
slice-honoured-without-authorisation	a requested S-NSSAI that the subscription does not include is granted anyway	the NSSF/AMF does not check the requested S-NSSAI against the UE's subscribed S-NSSAIs	the UE reaches a slice it is not entitled to	the requested NSSAI is UE-controlled; the allowed NSSAI must be derived from the subscription, not echoed back
no-subscription-slice	a slice the subscriber has no subscription for, reached via a PDU session with that S-NSSAI	no per-slice authorisation at session establishment	unauthorised service access	TS 23.501 5.15.5.2.1 places the check at the AMF/NSSF; a PDU session that reaches a slice the UE is not subscribed to means the check is absent
shared-upf-no-vrf	isolation is signalled (distinct S-NSSAI) but the UPF is shared without a VRF or a network-instance separation	one UPF instance serving several slices	cross-slice reachability and traffic mixing	the slice boundary is then a label, not a boundary: the S-NSSAI exists in the signalling and nowhere in the forwarding path
roaming-mapping-not-enforced	the visited network maps the UE's S-NSSAI to a VPLMN value and the mapping is not enforced	roaming with a slice that the VPLMN maps	the UE reaches a VPLMN slice it should not, or the wrong slice	isolation must hold for the mapped S-NSSAI, not just the HPLMN one (TS 23.501 5.15.5.3)
slice-id-enumeration	distinct rejection causes reveal which slices exist and which are refused	rejections carry specific causes to an unauthorised UE	slice inventory from outside	cause 62 (no network slices available), 69 (insufficient resources for specific slice), 91 (DNN not supported in the slice) discriminate the configuration
nssf-bypass	signalling a requested NSSAI after registration, or a modified requested NSSAI in a new registration, hoping the NSSF is only consulted once	the AMF does not re-run slice selection	slice change without re-authorisation	the requested NSSAI is an input to selection, never a grant; a slice change must go back through the NSSF
n2-n3-signalled-not-enforced	the S-NSSAI appears in NGAP and NAS but not in the N3 encapsulation	no per-slice network instance at the N3 boundary	a misconfigured UPF routes across slices	check whether the N3 endpoint is per-slice or shared; the S-NSSAI has no place in the GTP-U header, so enforcement must be at the UPF network instance
EOF
}

# ── plans — status: handoff ─────────────────────────────────────────────
slic_plan_write() {
    local name="$1" title="$2" needs="$3" body="$4"
    mkdir -p "$SLIC_PLANS" || { printf 'ERROR\tcannot create %s\n' "$SLIC_PLANS" >&2; return 1; }
    local out="$SLIC_PLANS/${name}.plan"
    {
        printf 'status: handoff\n'
        printf 'plan: %s\n' "$title"
        printf 'module: 34_slicing.sh (slic)\n'
        printf 'requires: %s\n' "$needs"
        printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        printf '%s\n' "$body"
    } > "$out" || { printf 'ERROR\tcould not write %s\n' "$out" >&2; return 1; }
    [[ -s "$out" ]] || { printf 'ERROR\t%s is empty\n' "$out" >&2; return 1; }
    printf '%s' "$out"
}

slic_plan_escape_lab() {
    local body
    body=$(cat <<'EOF'
# Slice escape lab — 5G SA with two slices (handoff)

## What the handoff needs
1. A 5G SA testbed with at least two slices: Open5GS or free5GC with a gNB
   (srsRAN or OpenAirInterface) and two S-NSSAIs configured, e.g.
   1/000001 (eMBB) and 2/000002 (URLLC), each with its own SMF/UPF or one UPF
   with two network instances.
2. A subscriber whose subscription includes only ONE of the two slices, so the
   other slice is the unauthorised one.
3. A second UPF configuration with a SHARED UPF and no per-slice network
   instance/VRF, to reproduce the shared-UPF isolation failure.
4. A UE with a programmable test SIM and a way to set the requested NSSAI.
5. An N3 capture point (GTP-U) and an N2 capture point (NGAP), plus a
   reachability target inside each slice (a service address) to test whether
   slice A's user plane can reach slice B's service.

## What is already implemented in software
- S-NSSAI SST/SD encode and decode, the NSSAI container parse, and the
  selection outcome (`--selection`) including the "granted but never
  requested" and "silently dropped" classes.
- The isolation evaluation (`--isolation-check`) over observed GTP-U endpoints
  with an explicit slice->TEID map, which reports shared-transport and
  refuses to claim isolation from a capture alone.
- The detection rules for an unexpected S-NSSAI, a mid-session slice change
  and a rejection cause that names the slice configuration.

## Steps
1. Bring the testbed up; register the UE and capture the requested and allowed
   NSSAI. Run `--selection <requested> <allowed> <rejected>` and confirm the
   outcome matches the subscription.
2. Set the requested NSSAI to the slice the subscriber is NOT subscribed to
   and re-register. If the allowed NSSAI contains it, that is the
   honoured-without-authorisation class.
3. Establish a PDU session on the unauthorised slice and confirm user-plane
   reachability.
4. Capture N3 and run `--isolation-check <pcap> <sliceA=teid,...;sliceB=teid,...>`
   to show whether the two slices share an N3 endpoint.
5. From a host in slice A, attempt to reach the service address in slice B.
   Record the result — this is the observation the capture cannot make.
6. Repeat with the shared-UPF configuration and with the visited-network
   mapping in a roaming setup.

## Safety
A 5G SA testbed with two network instances is core-network equipment; this is
a lab topology on spectrum you are licensed for. Nothing here transmits.
EOF
)
    slic_plan_write "slice-escape-lab" "5G SA two-slice escape and isolation lab" \
        "a 5G SA testbed (Open5GS or free5GC + srsRAN/OAI gNB) with two S-NSSAIs on either separate or shared UPFs, a test SIM subscribed to only one slice, a UE that can set the requested NSSAI, and N2/N3 capture plus an in-slice reachability target" \
        "$body"
}

slic_cmd_plan() {
    local which="${1:-}" pf rc
    case "$which" in
        slice-escape-lab) pf=$(slic_plan_escape_lab); rc=$? ;;
        *)
            printf 'ERROR\tunknown plan: %s (want slice-escape-lab)\n' "$(slic_sanitize "${which:-<none>}")" >&2
            return 2 ;;
    esac
    [[ "$rc" -eq 0 && -n "$pf" ]] || return "${rc:-1}"
    printf 'plan_file\t%s\n' "$pf"
    printf 'status\thandoff\n'
    printf 'note\t%s\n' "this vector needs the testbed named in the plan; no traffic was sent"
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
slic_cli_status_tsv() {
    local plans=0
    [[ -d "$SLIC_PLANS" ]] && plans=$(find "$SLIC_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)
    printf 'module\tslicing\n'
    printf 'tag\tslic\n'
    printf 'dir\t%s\n' "$SLIC_DIR"
    printf 'plans_dir\t%s\n' "$SLIC_PLANS"
    printf 'plans\t%s\n' "$plans"
    printf 'sst_assigned\t1,2,3,4,5\n'
    printf 'five_qi_rows\t%s\n' "$(slic_5qi_table_raw | grep -c .)"
    printf 'five_qi_id_range\t%s\n' "1-127 standardized, 128-254 operator-specific, 255 unused by the table"
    printf 'five_qi_table\tTS 23.501 Table 5.7.4-1\n'
    printf 'five_qi_unknown_cells\t%s\n' "5QI 75: reserved in the carried table (NOTE 14), all characteristics unknown"
    printf 'qos_verbs\t--five-qi, --five-qi-table, --tsn-config, --slice-qos-check\n'
    printf 'tsn_ngap_encoder\t%s\n' "$(slic_ngap_qos_encoder)"
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
    printf 'isolation_verdict\t%s\n' "not-determinable without a slice-to-TEID binding"
    printf 'refs\tTS 23.003, TS 23.501 (5.7.3, 5.7.4, Table 5.7.4-1, 5.7.4.3, 5.15), TS 23.502, TS 24.501, TS 29.244, TS 38.413\n'
}

slic_cmd_encode() {
    local sst="${1:-}" sd="${2:-}"
    [[ -n "$sst" ]] || { printf 'ERROR\tusage: --encode-s-nssai <sst> [sd]\n' >&2; return 2; }
    local hex; hex=$(slic_encode_s_nssai "$sst" "$sd") || return 1
    printf 'sst\t%s\n' "$(slic_sanitize "$sst")"
    printf 'sst_name\t%s\n' "$(slic_sst_name "$sst")"
    printf 'sd\t%s\n' "$(slic_sanitize "${sd:-none}")"
    printf 'octets\t%s\n' "$(( ${#hex} / 2 ))"
    printf 'hex\t%s\n' "$hex"
    printf 'roundtrip_sst\t%s\n' "$(slic_decode_s_nssai "$hex" | awk -F'\t' '$1=="sst"{print $2}')"
    printf 'roundtrip_sd\t%s\n' "$(slic_decode_s_nssai "$hex" | awk -F'\t' '$1=="sd"{print $2}')"
}

slic_cmd_decode() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-s-nssai <hex>\n' >&2; return 2; }
    slic_decode_s_nssai "$hex"
}

slic_cmd_nssai() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --nssai-parse <hex>\n' >&2; return 2; }
    slic_nssai_parse "$hex"
}

slic_cmd_selection() {
    local req="${1:-}" allow="${2:-}" rej="${3:-}"
    [[ -n "$req" ]] || { printf 'ERROR\tusage: --selection <requested-hex> [allowed-hex] [rejected-hex]\n' >&2; return 2; }
    slic_selection "$req" "$allow" "$rej"
}

slic_cmd_isolation() {
    local pcap="${1:-}" map="${2:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --isolation-check <pcap> [slice=teid,...;...]\n' >&2; return 2; }
    slic_isolation_check "$pcap" "$map"
}

# ── selftest — no radio, no root, no network ────────────────────────────
# ── URSP — TS 24.526 §5.2 (the assignment leg of slicing) ───────────────
# A slice is only useful to a UE that is told which traffic belongs to it. That
# statement is a URSP rule: a traffic descriptor (what the traffic is), a rule
# precedence, and a list of route selection descriptors (which S-NSSAI and DNN
# it should use, on which access). The rules are not negotiated -- the network
# states them in a UE policy container inside a 5GMM MANAGE UE POLICY COMMAND,
# and the UE applies them. So this is a policy document, and the interesting
# questions are about precedence and about what the document steers traffic to.
#
# The encoding is the octet layout of TS 24.526 Figure 5.2.1-5.2.4:
#   rule = Len(2) Precedence(1) LenTrafficDesc(2) <components>
#          LenRouteSelectDescList(2) <descriptors>
#   descriptor = Len(2) Precedence(1) LenCont(2) <components>
#   traffic component  = Type(1) <value, self-delimiting>
#   route component    = Type(1) <value, self-delimiting>
# The S-NSSAI value is emitted as 4 octets (SST + SD) and never as SST alone:
# inside a descriptor there is no length octet in front of it, so the 1-octet
# form cannot be delimited from the component that follows. The walker accepts
# the 1-octet form only where the descriptor content ends exactly there.

slic_ursp_td_type_name() {
    case "${1:-}" in
        1)   echo "match-all" ;;
        2)   echo "OS Id" ;;
        8)   echo "OS Id + OS App Id" ;;
        16)  echo "IPv4 remote address" ;;
        17)  echo "IPv4 local address" ;;
        33)  echo "IPv6 remote address/prefix" ;;
        35)  echo "IPv6 local address/prefix" ;;
        48)  echo "protocol identifier / next header" ;;
        64)  echo "single local port" ;;
        65)  echo "local port range" ;;
        80)  echo "single remote port" ;;
        81)  echo "remote port range" ;;
        96)  echo "security parameter index" ;;
        112) echo "type of service / traffic class" ;;
        128) echo "flow label" ;;
        129) echo "destination MAC address" ;;
        130) echo "source MAC address" ;;
        131) echo "802.1Q C-TAG VID" ;;
        132) echo "802.1Q S-TAG VID" ;;
        133) echo "802.1Q C-TAG PCP/DEI" ;;
        134) echo "802.1Q S-TAG PCP/DEI" ;;
        135) echo "EtherType" ;;
        136) echo "DNN" ;;
        144) echo "connection capabilities" ;;
        145) echo "destination FQDN" ;;
        160) echo "OS App Id" ;;
        *)   echo "unknown" ;;
    esac
}

slic_ursp_rsd_type_name() {
    case "${1:-}" in
        1)   echo "SSC mode" ;;
        2)   echo "S-NSSAI" ;;
        4)   echo "DNN" ;;
        8)   echo "PDU session type" ;;
        16)  echo "preferred access type" ;;
        17)  echo "multi-access preference" ;;
        32)  echo "non-seamless non-3GPP offload" ;;
        64)  echo "location criteria" ;;
        128) echo "time window" ;;
        *)   echo "unknown" ;;
    esac
}

slic_ursp_pdu_name() {
    case "${1:-}" in
        1) echo "ipv4" ;;
        2) echo "ipv6" ;;
        3) echo "ipv4v6" ;;
        4) echo "ethernet" ;;
        5) echo "unstructured" ;;
        *) echo "unknown" ;;
    esac
}

slic_ursp_access_name() {
    case "${1:-}" in
        1) echo "3gpp" ;;
        2) echo "non-3gpp" ;;
        *) echo "unset" ;;
    esac
}

# DNN -> APN octets (TS 23.003 §9.1): each label is length-prefixed.
slic_apn_encode() {
    local dnn="${1:-}" out="" label
    [[ -n "$dnn" ]] || { printf 'ERROR\tDNN is empty\n' >&2; return 2; }
    local IFS='.'
    local -a labels
    read -r -a labels <<< "$dnn"
    ((${#labels[@]} > 0)) || { printf 'ERROR\tDNN "%s" has no labels\n' "$dnn" >&2; return 2; }
    for label in "${labels[@]}"; do
        ((${#label} >= 1 && ${#label} <= 63)) || {
            printf 'ERROR\tDNN label "%s" is %s octets; TS 23.003 allows 1-63\n' \
                "$label" "${#label}" >&2; return 2; }
        out+=$(slic_byte "${#label}")
        out+=$(printf '%s' "$label" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')
    done
    printf '%s' "$out"
}

slic_apn_decode() {
    local hex; hex=$(slic_nfc "${1:-}")
    local off=0 out="" n
    while ((off * 2 < ${#hex})); do
        n=$((16#${hex:$((off * 2)):2}))
        ((n >= 1 && n <= 63)) || {
            printf 'ERROR\tAPN label length %s is outside 1-63\n' "$n" >&2; return 1; }
        out+="${out:+$'\x2e'}"
        out+=$(slic_hex_utf8 "${hex:$(((off + 1) * 2)):$((n * 2))}")
        off=$((off + 1 + n))
    done
    printf '%s' "$out"
}

slic_hex_utf8() {
    local hex="${1:-}" out="" i
    for ((i = 0; i * 2 < ${#hex}; i++)); do
        out+=$(printf "\\$(printf '%03o' "$((16#${hex:$((i * 2)):2}))")")
    done
    printf '%s' "$out"
}

slic_ursp_td_comp() {
    local kind="${1:-}" val="${2:-}" hex
    case "${kind,,}" in
        match-all|matchall)
            printf '01' ;;
        domain|fqdn)
            [[ -n "$val" ]] || { printf 'ERROR\t--domain needs a hostname\n' >&2; return 2; }
            hex=$(printf '%s' "$val" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')
            printf '91%s%s' "$(slic_byte $((${#hex} / 2)))" "$hex" ;;
        app-id|appid)
            [[ -n "$val" ]] || { printf 'ERROR\t--app-id needs an identifier\n' >&2; return 2; }
            hex=$(printf '%s' "$val" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')
            printf 'A0%s%s' "$(slic_byte $((${#hex} / 2)))" "$hex" ;;
        dnn-match|dnn)
            local apn
            apn=$(slic_apn_encode "$val") || return 2
            printf '88%s%s' "$(slic_byte $((${#apn} / 2)))" "$apn" ;;
        *)
            printf 'ERROR\tunknown traffic descriptor kind "%s" (match-all, domain, app-id, dnn-match)\n' \
                "$kind" >&2
            return 2 ;;
    esac
}

slic_ursp_rsd_comp() {
    local kind="${1:-}" val="${2:-}" sst sd pdu access
    case "${kind,,}" in
        ssc)
            [[ "$val" =~ ^[1-3]$ ]] || {
                printf 'ERROR\t--ssc takes 1, 2 or 3 (TS 23.501 5.15.6)\n' >&2; return 2; }
            printf '01%s' "$(slic_byte "$val")" ;;
        snssai)
            sst="${val%%:*}"
            sd="${val#*:}"
            [[ "$sd" == "$val" ]] && sd=""
            local nssai
            nssai=$(slic_encode_s_nssai "$sst" "$sd") || return 2
            ((${#nssai} == 8)) || {
                printf 'ERROR\t--snssai needs SST:SD (4 octets) inside a descriptor; "%s" encoded to %s octets and an S-NSSAI without SD cannot be delimited from the next component\n' \
                    "$val" "$((${#nssai} / 2))" >&2
                return 2; }
            printf '02%s' "$nssai" ;;
        dnn)
            local apn
            apn=$(slic_apn_encode "$val") || return 2
            printf '04%s%s' "$(slic_byte $((${#apn} / 2)))" "$apn" ;;
        pdu)
            case "${val,,}" in
                ipv4) pdu=1 ;; ipv6) pdu=2 ;; ipv4v6) pdu=3 ;;
                ethernet) pdu=4 ;; unstructured) pdu=5 ;;
                *) printf 'ERROR\t--pdu takes ipv4, ipv6, ipv4v6, ethernet or unstructured\n' >&2
                   return 2 ;;
            esac
            printf '08%s' "$(slic_byte "$pdu")" ;;
        access)
            case "${val,,}" in
                3gpp) access=1 ;; non-3gpp|non3gpp) access=2 ;;
                *) printf 'ERROR\t--access takes 3gpp or non-3gpp\n' >&2; return 2 ;;
            esac
            printf '10%s' "$(slic_byte "$access")" ;;
        multi-access|multiacess|multiaccess)
            printf '11' ;;
        offload)
            printf '20' ;;
        *)
            printf 'ERROR\tunknown route selection kind "%s" (snssai, dnn, ssc, pdu, access, multi-access, offload)\n' \
                "$kind" >&2
            return 2 ;;
    esac
}

# Wrap a rule in a UE policy part: Len(2) spare(4)+Type(4)=1 (URSP) content.
slic_ursp_wrap() {
    local rule="${1:-}"
    # The part length counts the rule list only; the spare/type octet follows it.
    printf '%04X01%s' $((${#rule} / 2)) "$rule"
}

slic_ursp_td_component_rows() {
    local ridx="${1:-0}" hex="${2:-}" off=0 type name len vhex
    while ((off * 2 < ${#hex})); do
        type=$((16#${hex:$((off * 2)):2}))
        name=$(slic_ursp_td_type_name "$type")
        off=$((off + 1))
        case "$type" in
            1)
                printf 'td\t%s\t%s\t%s\t%s\n' "$ridx" "$(slic_byte "$type")" "$name" "any traffic"
                ;;
            136)
                len=$((16#${hex:$((off * 2)):2}))
                off=$((off + 1))
                vhex="${hex:$((off * 2)):$((len * 2))}"
                printf 'td\t%s\t%s\t%s\t%s\n' "$ridx" "$(slic_byte "$type")" "$name" \
                    "$(slic_apn_decode "$vhex" 2>/dev/null || printf '%s' "$vhex")"
                off=$((off + len))
                ;;
            2|145|160)
                len=$((16#${hex:$((off * 2)):2}))
                off=$((off + 1))
                vhex="${hex:$((off * 2)):$((len * 2))}"
                printf 'td\t%s\t%s\t%s\t%s\n' "$ridx" "$(slic_byte "$type")" "$name" \
                    "$(slic_hex_utf8 "$vhex")"
                off=$((off + len))
                ;;
            *)
                printf 'td\t%s\t%s\t%s\t%s\n' "$ridx" "$(slic_byte "$type")" "$name" \
                    "not walked here: this component type has no builder in this module"
                return 0
                ;;
        esac
    done
}

slic_ursp_rsd_component_rows() {
    local ridx="${1:-0}" rds="${2:-0}" hex="${3:-}" off=0 end type name vhex len
    end=$((${#hex} / 2))
    while ((off < end)); do
        type=$((16#${hex:$((off * 2)):2}))
        name=$(slic_ursp_rsd_type_name "$type")
        off=$((off + 1))
        case "$type" in
            1)
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" \
                    "SSC mode $((16#${hex:$((off * 2)):2} & 0x07))"
                off=$((off + 1))
                ;;
            2)
                if ((end - off >= 4)); then len=4; else len=$((end - off)); fi
                vhex="${hex:$((off * 2)):$((len * 2))}"
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" \
                    "$(slic_decode_s_nssai "$vhex" 2>/dev/null |
                        awk -F'\t' '$1=="sst"{s=$2} $1=="sst_name"{n=$2} $1=="sd"{d=$2}
                                    END{if (s=="") printf "sst+sd %s", d; else printf "%s %s sd=%s", s, n, d}')"
                off=$((off + len))
                ;;
            4)
                len=$((16#${hex:$((off * 2)):2}))
                off=$((off + 1))
                vhex="${hex:$((off * 2)):$((len * 2))}"
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" \
                    "$(slic_apn_decode "$vhex" 2>/dev/null || printf '%s' "$vhex")"
                off=$((off + len))
                ;;
            8)
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" \
                    "$(slic_ursp_pdu_name "$((16#${hex:$((off * 2)):2} & 0x07))")"
                off=$((off + 1))
                ;;
            16)
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" \
                    "$(slic_ursp_access_name "$((16#${hex:$((off * 2)):2} & 0x03))")"
                off=$((off + 1))
                ;;
            17)
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" "preferred"
                ;;
            32)
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" "indicated"
                ;;
            *)
                printf 'rsd\t%s\t%s\t%s\t%s\t%s\n' "$ridx" "$rds" "$(slic_byte "$type")" "$name" \
                    "not walked here: this component type has no builder in this module"
                return 0
                ;;
        esac
    done
}

# Walk a URSP rule, a rule list, or a UE policy part. Prints rules as rows:
#   rule <n> precedent <p> td_octets <n> rds <n>
# and one td / rsd row per component.
slic_ursp_walk() {
    local hex; hex=$(slic_nfc "${1:-}")
    slic_is_hex "$hex" || { printf 'ERROR\tURSP needs hex\n' >&2; return 1; }
    local off=0 total=$((${#hex} / 2)) wrap=no
    # A UE policy part starts with a 2-octet length that covers the remainder
    # and a spare/type octet whose low nibble is 1 (URSP).
    if ((${#hex} >= 8)); then
        local len2=$((16#${hex:0:4}))
        local t2=$((16#${hex:4:2} & 0x0F))
        if ((len2 + 3 == total && t2 == 1)); then
            printf 'layer\tue_policy_part\n'
            printf 'policy_part_len\t%s\n' "$len2"
            printf 'policy_part_type\t%s\n' "$(slic_byte "$t2")"
            off=3
            wrap=yes
        fi
    fi
    local idx=0 precedence tdlen tdlist rsdlistlen rdlen rdprec contlen rulelen
    while ((off + 5 <= total)); do
        idx=$((idx + 1))
        rulelen=$((16#${hex:$((off * 2)):4}))
        precedence=$((16#${hex:$(((off + 2) * 2)):2}))
        tdlen=$((16#${hex:$(((off + 3) * 2)):4}))
        off=$((off + 5))
        printf 'rule\t%s\t%s\n' "$idx" "$precedence"
        printf 'rule_len_field\t%s\n' "$rulelen"
        printf 'td_octets\t%s\n' "$tdlen"
        tdlist="${hex:$((off * 2)):$((tdlen * 2))}"
        slic_ursp_td_component_rows "$idx" "$tdlist"
        off=$((off + tdlen))
        rsdlistlen=$((16#${hex:$((off * 2)):4}))
        off=$((off + 2))
        rsdlist="${hex:$((off * 2)):$((rsdlistlen * 2))}"
        local roff=0 ridx=0
        while ((roff * 2 < ${#rsdlist})); do
            ridx=$((ridx + 1))
            rdlen=$((16#${rsdlist:$((roff * 2)):4}))
            rdprec=$((16#${rsdlist:$(((roff + 2) * 2)):2}))
            contlen=$((16#${rsdlist:$(((roff + 3) * 2)):4}))
            printf 'rsd_rule\t%s\t%s\t%s\n' "$idx" "$ridx" "$rdprec"
            printf 'rsd_octets\t%s\n' "$rdlen"
            slic_ursp_rsd_component_rows "$idx" "$ridx" "${rsdlist:$(((roff + 5) * 2)):$((contlen * 2))}"
            roff=$((roff + 5 + contlen))
        done
        off=$((off + rsdlistlen))
        printf 'rule_end\t%s\n' "$off"
    done
    printf 'rules\t%s\n' "$idx"
    printf 'walked\t%s\t%s\n' "$off" "$total"
    printf 'wrapped\t%s\n' "$wrap"
}

slic_cmd_ursp_rule() {
    local precedence=1 rsd_precedence="" td_hex="" rsd_hex="" wrap=0 oracle=0 out="" snssai="" dnn=""
    local have_td=0 have_rsd=0
    while (($# > 0)); do
        case "$1" in
            --precedence)     precedence="${2:-1}"; shift 2 ;;
            --rsd-precedence) rsd_precedence="${2:-}"; shift 2 ;;
            --match-all)      td_hex+=$(slic_ursp_td_comp match-all "") || return 2
                              have_td=1; shift ;;
            --domain)         td_hex+=$(slic_ursp_td_comp domain "${2:-}") || return 2
                              have_td=1; shift 2 ;;
            --app-id)         td_hex+=$(slic_ursp_td_comp app-id "${2:-}") || return 2
                              have_td=1; shift 2 ;;
            --dnn-match)      td_hex+=$(slic_ursp_td_comp dnn-match "${2:-}") || return 2
                              have_td=1; shift 2 ;;
            --snssai)         snssai="${2:-}"; shift 2 ;;
            --dnn)            dnn="${2:-}"; shift 2 ;;
            --ssc)            rsd_hex+=$(slic_ursp_rsd_comp ssc "${2:-}") || return 2
                              have_rsd=1; shift 2 ;;
            --pdu)            rsd_hex+=$(slic_ursp_rsd_comp pdu "${2:-}") || return 2
                              have_rsd=1; shift 2 ;;
            --access)         rsd_hex+=$(slic_ursp_rsd_comp access "${2:-}") || return 2
                              have_rsd=1; shift 2 ;;
            --multi-access)   rsd_hex+=$(slic_ursp_rsd_comp multi-access "") || return 2
                              have_rsd=1; shift ;;
            --offload)        rsd_hex+=$(slic_ursp_rsd_comp offload "") || return 2
                              have_rsd=1; shift ;;
            --wrap)           wrap=1; shift ;;
            --oracle)         oracle=1; shift ;;
            --out)            out="${2:-}"; shift 2 ;;
            *) printf 'ERROR\tunknown option %s\n' "$1" >&2; return 2 ;;
        esac
    done
    [[ "$precedence" =~ ^[0-9]+$ ]] && ((precedence <= 255)) || {
        printf 'ERROR\t--precedence takes 0-255\n' >&2; return 2; }
    # The route selection components arrive as flags, so they are appended in a
    # fixed order after the loop: S-NSSAI, DNN, then whatever else was asked
    # for. Order inside the descriptor is not significant to the encoder; it is
    # fixed here so the same request always produces the same octets.
    local ordered=""
    [[ -n "$snssai" ]] && { ordered+=$(slic_ursp_rsd_comp snssai "$snssai") || return 2; have_rsd=1; }
    local sd_defaulted=0
    [[ -n "$snssai" && "$snssai" != *:* ]] && sd_defaulted=1
    [[ -n "$dnn" ]] && { ordered+=$(slic_ursp_rsd_comp dnn "$dnn") || return 2; have_rsd=1; }
    rsd_hex="${ordered}${rsd_hex}"
    ((have_td == 1)) || {
        printf 'ERROR\ta URSP rule needs a traffic descriptor (--match-all, --domain, --app-id, --dnn-match)\n' >&2
        return 2; }
    ((have_rsd == 1)) || {
        printf 'ERROR\ta URSP rule needs a route selection descriptor (--snssai, --dnn, --ssc, --pdu, --access, --offload)\n' >&2
        return 2; }
    local tdlen=$((${#td_hex} / 2)) rsdlen=$((${#rsd_hex} / 2))
    [[ -n "$rsd_precedence" ]] || rsd_precedence="$precedence"
    local rsd_cont
    rsd_cont=$(printf '%04X%02X%04X%s' $((3 + rsdlen)) "$rsd_precedence" "$rsdlen" "$rsd_hex")
    local rsdlistlen=$((${#rsd_cont} / 2))
    local rule
    rule=$(printf '%04X%02X%04X%s%04X%s' \
        $((5 + tdlen + rsdlistlen)) "$precedence" "$tdlen" "$td_hex" "$rsdlistlen" "$rsd_cont")
    printf 'spec\tTS 24.526 5.2 (URSP rule, traffic descriptor, route selection descriptor)\n'
    printf 'rule_precedence\t%s\n' "$precedence"
    printf 'rsd_precedence\t%s\n' "$rsd_precedence"
    printf 'hex\t%s\n' "$rule"
    printf 'octets\t%s\n' "$((${#rule} / 2))"
    printf 'rule_len_field\t%s\n' $((5 + tdlen + rsdlistlen))
    printf 'td_octets\t%s\n' "$tdlen"
    printf 'rsd_octets\t%s\n' "$rsdlistlen"
    printf 'traffic_descriptor\t%s\n' \
        "$(slic_ursp_walk "$rule" | awk -F'\t' '$1=="td"{printf "%s%s", (n++?" + ":""), $4}')"
    printf 'route_selection\t%s\n' \
        "$(slic_ursp_walk "$rule" | awk -F'\t' '$1=="rsd"{if (!seen[$5]++) printf "%s%s", (n++?" + ":""), $5}')"
    if ((sd_defaulted == 1)); then
        printf 'sd_emitted\tffffff\tthe SST-only S-NSSAI has no length octet inside a descriptor, so the 4-octet form with SD=FFFFFF is emitted and it means the slice has no differentiator\n'
    fi
    printf 'decoded_back\tyes\n'
    slic_ursp_walk "$rule" | sed 's/^/back_/'
    if ((wrap == 1)); then
        printf 'policy_part_hex\t%s\n' "$(slic_ursp_wrap "$rule")"
        printf 'policy_part_octets\t%s\n' $(((${#rule} / 2) + 3))
        printf 'carried_in\t5GMM MANAGE UE POLICY COMMAND, UE policy container\n'
    fi
    if ((oracle == 1)); then
        local py="${IMSI_URSP_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}"
        if [[ -x "$py" ]]; then
            local dec
            dec=$("$py" - "$(slic_ursp_wrap "$rule")" <<'PYORACLE' 2>&1
import sys
from pycrate_mobile.TS24501_UEPOL import UEPolPart
part = UEPolPart()
try:
    part.from_bytes(bytes.fromhex(sys.argv[1]))
except Exception as exc:
    print('oracle_decode_ok\tno')
    print('oracle_error\t%s' % str(exc).replace('\n', ' ')[:120])
    raise SystemExit(1)
print('oracle_decode_ok\tyes')
rules = part[3].get_alt()
items = getattr(rules, '_content', [])
print('oracle_rules\t%d' % len(items))
if items:
    r = items[0]
    print('oracle_rule_precedence\t%d' % r[1].get_val())
    print('oracle_rule_len\t%d' % r[0].get_val())
    td = getattr(r[3], '_content', [])
    if td:
        t = td[0]
        print('oracle_td_type\t%d' % t[0].get_val())
        if t[0].get_val() == 145:
            print('oracle_td_fqdn\t%s' % t[1].get_alt()[1].get_val().decode('ascii', 'replace'))
print('oracle_note\tpycrate decodes the rule framing and the traffic descriptor; its S-NSSAI decoder reads the mapped-HPLMN fields unconditionally, so a descriptor that carries an S-NSSAI followed by another component is misread from that point on')
PYORACLE
)
            [[ -n "$dec" ]] && printf '%s\n' "$dec"
        else
            printf 'oracle\tskipped\t%s is not executable\n' "$py"
        fi
    fi
    printf 'ref\tTS 24.526 5.2, TS 24.501 9.11.2.1B (DNN) and 9.11.2.8 (S-NSSAI)\n'
    printf 'limit\tthis builds one rule; a real policy part carries a rule list, and the precedence the UE applies is the number in the rule, not the order\n'
    printf 'verdict\tursp_rule_built\n'
    if [[ -n "$out" ]]; then
        printf 'hex\t%s\n' "$rule" > "$out"
        printf 'written\t%s\n' "$out"
    fi
}

slic_cmd_ursp_parse() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --ursp-parse <hex>\n' >&2; return 2; }
    slic_ursp_walk "$hex" || return 1
    printf 'ref\tTS 24.526 5.2; the S-NSSAI inside a descriptor is read as 4 octets because the 1-octet form cannot be delimited there\n'
    printf 'verdict\tursp_parsed\n'
}

slic_cmd_ursp_audit() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --ursp-audit <hex>\n' >&2; return 2; }
    local walk; walk=$(slic_ursp_walk "$hex") || return 1
    local rules; rules=$(printf '%s\n' "$walk" | awk -F'\t' '$1=="rules"{print $2}')
    printf 'rules\t%s\n' "${rules:-0}"
    ((${rules:-0} > 0)) || { printf 'ERROR\tno URSP rule decoded\n' >&2; return 1; }
    # precedence of every rule and whether its descriptor is match-all
    local map; map=$(printf '%s\n' "$walk" | awk -F'\t' '
        $1=="rule"{prec[$2]=$3; td[$2]=""}
        $1=="td"{td[$2]=td[$2] (td[$2]==""?"":"+") $4}
        $1=="rsd"{key=$2; comp[key]=comp[key] (comp[key]==""?"":"+") $5 "=" $6}
        END{ for (k in prec) printf "rule\t%s\t%s\t%s\t%s\n", k, prec[k], td[k], comp[k] }')
    local findings=0
    # match-all rule that outranks (lower number) a rule with a real descriptor
    shadow=$(printf '%s\n' "$map" | awk -F'\t' '
        $4=="match-all"{ma=$3}
        END{ if (ma != "") print ma }')
    if [[ -n "$shadow" ]]; then
        local outranked
        outranked=$(printf '%s\n' "$map" | awk -F'\t' -v ma="$shadow" '$4!="match-all" && $3>ma' | wc -l)
        if ((outranked > 0)); then
            printf 'finding\tmatch_all_shadows_targeted\tHIGH\ta match-all rule at precedence %s is applied before %s rule(s) with a specific descriptor, so their traffic never reaches them\n' \
                "$shadow" "$outranked"
            findings=$((findings + 1))
        else
            printf 'note\tmatch_all_at_precedence\t%s\tthis rule catches everything that no earlier rule matched, which is the intended use\n' "$shadow"
        fi
    fi
    # descriptors that steer traffic somewhere other than the 3GPP slice
    local off3gpp
    off3gpp=$(printf '%s\n' "$map" | awk -F'\t' '$5 ~ /non-3gpp/{print $2}')
    if [[ -n "$off3gpp" ]]; then
        printf 'finding\tsteered_off_3gpp\tHIGH\trule(s) %s prefer non-3GPP access: the traffic is handed to a network the operator does not carry\n' \
            "$(printf '%s' "$off3gpp" | tr '\n' ' ')"
        findings=$((findings + 1))
    fi
    local offload
    offload=$(printf '%s\n' "$map" | awk -F'\t' '$5 ~ /offload/{print $2}')
    if [[ -n "$offload" ]]; then
        printf 'finding\toffload_bypasses_the_core\tHIGH\trule(s) %s carry the non-seamless offload indication: that traffic never enters the 5G core, so no slice applies to it and no core-side policy can see it\n' \
            "$(printf '%s' "$offload" | tr '\n' ' ')"
        findings=$((findings + 1))
    fi
    local noslice
    noslice=$(printf '%s\n' "$map" | awk -F'\t' '($5 !~ /S-NSSAI/){print $2}')
    if [[ -n "$noslice" ]]; then
        printf 'finding\tdescriptor_without_snssai\tMEDIUM\trule(s) %s select a route with no S-NSSAI, so the matching traffic stays on the default session and the slice the rule was written for is never used\n' \
            "$(printf '%s' "$noslice" | tr '\n' ' ')"
        findings=$((findings + 1))
    fi
    local dup
    dup=$(printf '%s\n' "$map" | awk -F'\t' '{c[$3]++} END{for (p in c) if (c[p] > 1) print p}' | sort -n | tr '\n' ' ')
    if [[ -n "$dup" ]]; then
        printf 'finding\tduplicate_precedence\tMEDIUM\tprecedence value(s) %s are used by more than one rule; the UE resolution order for equal precedence is not defined by the policy\n' \
            "$dup"
        findings=$((findings + 1))
    fi
    printf 'findings\t%s\n' "$findings"
    printf 'ref\tTS 24.526 5.2 and 5.4 (the UE applies the rule with the lowest precedence value first)\n'
    printf 'limit\tthe audit reads the policy the network wrote; it cannot tell whether a rule is malicious, only whether it steers traffic somewhere the slice does not cover\n'
    if ((findings > 0)); then
        printf 'verdict\tpolicy_steers_traffic_outside_the_slice\n'
    else
        printf 'verdict\tpolicy_consistent_with_the_slice\n'
    fi
}

slic_ursp_types() {
    cat <<'EOF'
layer	kind	value	name	note
component	traffic_descriptor	1	match-all	no value
component	traffic_descriptor	8	OS Id + OS App Id	length-prefixed
component	traffic_descriptor	136	DNN	length-prefixed APN
component	traffic_descriptor	144	connection capabilities	one octet
component	traffic_descriptor	145	destination FQDN	length-prefixed
component	traffic_descriptor	160	OS App Id	length-prefixed
component	route_selection	1	SSC mode	one octet, 3 bits used
component	route_selection	2	S-NSSAI	SST + SD, 4 octets here
component	route_selection	4	DNN	length-prefixed APN
component	route_selection	8	PDU session type	one octet, 3 bits used
component	route_selection	16	preferred access type	one octet, 2 bits used
component	route_selection	17	multi-access preference	no value
component	route_selection	32	non-seamless non-3GPP offload	no value
component	route_selection	64	location criteria	not built here
component	route_selection	128	time window	not built here
source		ts	24.526	Table 5.2.1 and Figures 5.2.1-5.2.4	
source		ts	24.501	9.11.2.1B DNN, 9.11.2.8 S-NSSAI	
EOF
}

slic_cmd_ursp_types() { slic_ursp_types; }

slic_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    local _prev_trap; _prev_trap=$(trap -p EXIT)
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export SLIC_DIR="$d/loot/slicing"
    export SLIC_PLANS="$SLIC_DIR/plans"
    mkdir -p "$SLIC_PLANS"

    # ── 1. SST table, known answers from TS 23.501 Table 5.15.2.2-1 ─────
    chk sst-1 "$(slic_sst_name 1)" "eMBB (enhanced Mobile Broadband)"
    chk sst-2 "$(slic_sst_name 2)" "URLLC (ultra-Reliable Low-Latency Communications)"
    chk sst-3 "$(slic_sst_name 3)" "MIoT (massive IoT / mMTC)"
    chk sst-4 "$(slic_sst_name 4)" "V2X (Vehicle-to-Everything)"
    chk sst-5 "$(slic_sst_name 5)" "HMTC (High-Performance Machine-Type Communications)"
    # An unassigned SST must be reported as unknown, never folded onto eMBB.
    chk sst-0-unknown  "$(slic_sst_name 0)" "unknown"
    chk sst-6-unknown  "$(slic_sst_name 6)" "unknown"
    chk sst-200-unknown "$(slic_sst_name 200)" "unknown"
    chk sst-unknown-not-embb "$(slic_sst_name 99 | grep -c 'eMBB')" "0"
    chk sst-known-1  "$(slic_sst_known 1 && echo yes || echo no)" "yes"
    chk sst-known-99 "$(slic_sst_known 99 && echo yes || echo no)" "no"
    chk sst-table-rows "$(slic_sst_table | grep -c '^[0-9]')" "6"
    chk sst-table-source "$(slic_sst_table | grep -c 'TS 23.501 Table 5.15.2.2-1')" "5"

    # ── 2. S-NSSAI encode/decode, byte-exact ────────────────────────────
    chk enc-embb      "$(slic_encode_s_nssai 1 000001)" "01000001"
    chk enc-urllc     "$(slic_encode_s_nssai 2 000002)" "02000002"
    chk enc-miot      "$(slic_encode_s_nssai 3 000003)" "03000003"
    chk enc-v2x       "$(slic_encode_s_nssai 4 000004)" "04000004"
    chk enc-hmtc      "$(slic_encode_s_nssai 5 000005)" "05000005"
    chk enc-no-sd     "$(slic_encode_s_nssai 1)" "01FFFFFF"
    chk enc-sd-none   "$(slic_encode_s_nssai 1 none)" "01FFFFFF"
    chk enc-sd-case   "$(slic_encode_s_nssai 1 abcdef)" "01ABCDEF"
    chk enc-oob       "$(slic_encode_s_nssai 256 000001 >/dev/null 2>&1; echo $?)" "1"
    chk enc-bad-sd    "$(slic_encode_s_nssai 1 zzz >/dev/null 2>&1; echo $?)" "1"
    chk enc-empty     "$(slic_encode_s_nssai '' >/dev/null 2>&1; echo $?)" "1"
    out=$(slic_decode_s_nssai 01000001); rc=$?
    chk dec-rc        "$rc" "0"
    chk dec-len       "$(fld "$out" length)" "4"
    chk dec-sst       "$(fld "$out" sst)" "1"
    chk dec-sst-name  "$(fld "$out" sst_name)" "eMBB (enhanced Mobile Broadband)"
    chk dec-sst-known "$(fld "$out" sst_known)" "yes"
    chk dec-sd        "$(fld "$out" sd)" "000001"
    chk dec-sd-present "$(fld "$out" sd_present)" "1"
    # SST-only form.
    out=$(slic_decode_s_nssai 02)
    chk dec1-len    "$(fld "$out" length)" "1"
    chk dec1-sst    "$(fld "$out" sst)" "2"
    chk dec1-sst-name "$(fld "$out" sst_name)" "URLLC (ultra-Reliable Low-Latency Communications)"
    chk dec1-sd     "$(fld "$out" sd)" "ffffff"
    chk dec1-nopresent "$(fld "$out" sd_present)" "0"
    # The 0xFFFFFF differentiator means "no SD" even in the 4-octet form.
    out=$(slic_decode_s_nssai 01FFFFFF)
    chk dec-nosd-present "$(fld "$out" sd_present)" "0"
    # Unknown SST is reported as unknown through the decoder too.
    out=$(slic_decode_s_nssai 63000001)
    chk dec-unknown-sst "$(fld "$out" sst_name)" "unknown"
    chk dec-unknown-known "$(fld "$out" sst_known)" "no"
    chk dec-bad-len   "$(slic_decode_s_nssai 0102 >/dev/null 2>&1; echo $?)" "1"
    chk dec-nonhex    "$(slic_decode_s_nssai zz >/dev/null 2>&1; echo $?)" "1"
    # Round-trip every assigned SST.
    local s
    for s in 1 2 3 4 5; do
        chk "roundtrip-$s" "$(slic_decode_s_nssai "$(slic_encode_s_nssai "$s" 123456)" | awk -F'\t' '$1=="sst"{print $2}')" "$s"
    done

    # ── 3. NSSAI container parse, including a multi-slice hex ───────────
    # eMBB(1/000001) + URLLC(2/000002): each S-NSSAI is length-prefixed.
    out=$(slic_nssai_parse "0401000001"; echo) 2>/dev/null
    # full container: [4][01 00 00 01] is a single 4-octet S-NSSAI
    out=$(slic_nssai_parse "0401000001"); rc=$?
    chk nssai-rc     "$rc" "0"
    chk nssai-count  "$(fld "$out" count)" "1"
    chk nssai-e0     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry"{print $3}')" "01000001"
    chk nssai-sst    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry"{print $4}')" "1"
    # Multi-slice: [4]01000001 [1]02  -> two entries, 5 octets
    out=$(slic_nssai_parse "04010000010102"); rc=$?
    chk nssai2-rc    "$rc" "0"
    chk nssai2-count "$(fld "$out" count)" "2"
    chk nssai2-e0sst "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==0{print $4}')" "1"
    chk nssai2-e1sst "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==1{print $4}')" "2"
    chk nssai2-e1sd  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==1{print $6}')" "ffffff"
    # Three slices, mixed 1-octet and 4-octet forms.
    out=$(slic_nssai_parse "040100000101020404000004")
    chk nssai3-count "$(fld "$out" count)" "3"
    chk nssai3-e2sst "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==2{print $4}')" "4"
    # A full NSSAI IE (IEI + length + container) is accepted and the IEI reported.
    out=$(slic_nssai_parse "2a050401000001")
    chk nssai-iei    "$(fld "$out" iei)" "2A"
    chk nssai-iei-cnt "$(fld "$out" count)" "1"
    # Malformed containers fail rather than silently truncating.
    chk nssai-bad-len  "$(slic_nssai_parse "0301000001" >/dev/null 2>&1; echo $?)" "1"
    chk nssai-trunc    "$(slic_nssai_parse "04010000" >/dev/null 2>&1; echo $?)" "1"
    chk nssai-none     "$(slic_nssai_parse >/dev/null 2>&1; echo $?)" "2"

    # ── 4. Selection outcomes ───────────────────────────────────────────
    # requested eMBB+URLLC, allowed eMBB only, rejected URLLC with a cause:
    # the dropped/unrequested classes must not appear.
    out=$(slic_selection "04010000010402000002" "0401000001" "0402000002"); rc=$?
    chk sel-rc        "$rc" "0"
    chk sel-outcome   "$(fld "$out" outcome)" "consistent"
    chk sel-allowed   "$(fld "$out" allowed)" "1"
    chk sel-rejected  "$(fld "$out" rejected)" "1"
    chk sel-dropped   "$(fld "$out" dropped)" "0"
    chk sel-unreq     "$(fld "$out" unrequested_allowed)" "0"
    chk sel-no-finding "$(printf '%s\n' "$out" | grep -c '^finding')" "0"
    # The network grants a slice that was never requested.
    out=$(slic_selection "0401000001" "04010000010402000002" "")
    chk sel-unreq-bad "$(fld "$out" unrequested_allowed)" "1"
    chk sel-unreq-outcome "$(fld "$out" outcome)" "anomalous"
    chk sel-unreq-finding "$(printf '%s\n' "$out" | grep -c 'unrequested-allowed-slice')" "1"
    # A requested slice the network neither allows nor rejects.
    out=$(slic_selection "04010000010402000002" "0401000001" "")
    chk sel-drop-count "$(fld "$out" dropped)" "1"
    chk sel-drop-finding "$(printf '%s\n' "$out" | grep -c 'silently-dropped-request')" "1"
    # With only the requested NSSAI the outcome is explicitly not determinable.
    out=$(slic_selection "0401000001")
    chk sel-1arg-outcome "$(fld "$out" outcome)" "not-determinable"
    chk sel-1arg-missing "$(fld "$out" missing)" "the allowed NSSAI (and the rejected NSSAI with its cause) from the Registration Accept"
    chk sel-1arg-none    "$(printf '%s\n' "$out" | grep -c '^selection	allowed')" "0"
    chk sel-none         "$(slic_selection >/dev/null 2>&1; echo $?)" "2"
    chk sel-bad-req      "$(slic_selection zz >/dev/null 2>&1; echo $?)" "1"

    # ── 5. 5GS NAS framing, known answers from tshark ───────────────────
    # 7E 00 44 16 is Registration reject with 5GMM cause 22; tshark 4.2.2
    # decodes it as "Congestion (22)" via the nas-5gs dissector.
    chk nas-type     "$(slic_nas_5gs_type "7E004416")" "68"
    chk nas-name     "$(slic_nas_5gs_message_name 68)" "Registration reject"
    chk nas-cause    "$(slic_nas_5gs_cause "7E004416")" "22"
    chk nas-cause-nm "$(slic_5gmm_cause_name 22)" "Congestion"
    chk nas-cause62  "$(slic_nas_5gs_cause "7E00443E")" "62"
    chk nas-cause62n "$(slic_5gmm_cause_name 62)" "No network slices available"
    chk nas-causename62 "$(slic_5gmm_cause_name 62)" "No network slices available"
    chk nas-not5gs   "$(slic_nas_5gs_type "07440F" >/dev/null 2>&1; echo $?)" "1"
    chk nas-short    "$(slic_nas_5gs_type "7E00" >/dev/null 2>&1; echo $?)" "1"
    chk nas-msg-names "$(slic_nas_5gs_message_name 65)" "Registration request"
    chk nas-session  "$(slic_nas_5gs_message_name 193)" "PDU session establishment request"

    # ── 6. Detection rules ──────────────────────────────────────────────
    # A clean sequence: register on slice A, then a session on slice A.
    out=$(printf 'event\t1\t1\tue1\t01000001\tregister\t\nevent\t2\t2\tue1\t01000001\tsession-establish\t\n' | slic_detect_stream)
    chk detect-clean "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    # A session on a slice the UE never registered on.
    out=$(printf 'event\t3\t3\tue1\t01000001\tregister\t\nevent\t4\t4\tue1\t02000002\tsession-establish\t\n' | slic_detect_stream)
    chk detect-unexpected "$(printf '%s' "$out" | grep -c 'unexpected-s-nssai-in-session')" "1"
    chk detect-change     "$(printf '%s' "$out" | grep -c 'slice-change-mid-session')" "1"
    # A rejection cause that names the slice configuration.
    out=$(printf 'event\t5\t5\tue1\t01000001\treject\t62\n' | slic_detect_stream)
    chk detect-cause "$(printf '%s' "$out" | grep -c 'rejection-cause-reveals-slice-config')" "1"
    # A benign cause must not fire that rule.
    out=$(printf 'event\t6\t6\tue1\t01000001\treject\t22\n' | slic_detect_stream)
    chk detect-cause-quiet "$(printf '%s' "$out" | grep -c 'rejection-cause-reveals-slice-config')" "0"
    chk detect-empty "$(printf '' | slic_detect_stream >/dev/null 2>&1; echo $?)" "1"

    # ── 7. Isolation: never claim isolation it cannot establish ─────────
    local pcap="$d/n3.pcap"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$pcap" <<'PY'
import struct, sys
path = sys.argv[1]
def eth(p): return bytes.fromhex('00112233445566778899aabb') + struct.pack('>H', 0x0800) + p
def ip(s, d, p):
    return struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(p), 1, 0, 64, 17, 0) + s + d + p
def udp(sp, dp, p): return struct.pack('>HHHH', sp, dp, 8 + len(p), 0) + p
def gtpu(teid):
    # GTPv1-U G-PDU: flags 0x30 (version 1, PT=1), type 0xFF, length, TEID
    return struct.pack('>BBHI', 0x30, 0xFF, 4, teid) + b'\x45\x00\x00\x14' + b'\x00' * 16
UPF1 = bytes([10, 20, 0, 1]); UPF2 = bytes([10, 20, 0, 2]); GNB = bytes([10, 10, 0, 1])
frames = []
for teid in (1001, 1002):          # both slices on the same UPF endpoint
    frames.append(eth(ip(UPF1, GNB, udp(2152, 2152, gtpu(teid)))))
frames.append(eth(ip(UPF2, GNB, udp(2152, 2152, gtpu(2001)))))
with open(path, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, fr in enumerate(frames):
        f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
        f.write(fr)
PY
        # No slice mapping: the answer must be "not determinable", and it must
        # NOT claim isolation.
        out=$(slic_cmd_isolation "$pcap"); rc=$?
        chk iso-rc        "$rc" "0"
        chk iso-verdict   "$(fld "$out" isolation)" "not-determinable"
        chk iso-missing   "$(printf '%s\n' "$out" | grep -c 'S-NSSAI to TEID')" "1"
        chk iso-no-claim  "$(printf '%s\n' "$out" | grep -ci 'isolated')" "0"
        chk iso-flows     "$(fld "$out" gtpu_flows)" "3"
        # With a mapping: slices A(1001) and B(1002) both land on 10.20.0.1,
        # so the transport is shared.
        out=$(slic_cmd_isolation "$pcap" "A=1001;B=1002")
        chk iso-shared    "$(printf '%s\n' "$out" | grep -c 'shared-transport')" "1"
        chk iso-finding   "$(printf '%s\n' "$out" | grep -c 'slice-isolation-failure')" "1"
        # A(1001) on UPF1 and C(2001) on UPF2: distinct endpoints, which is
        # necessary but explicitly not sufficient.
        out=$(slic_cmd_isolation "$pcap" "A=1001;C=2001")
        chk iso-distinct  "$(printf '%s\n' "$out" | grep -c '^pair.*distinct-transport')" "1"
        chk iso-notclaim  "$(fld "$out" isolation | grep -c 'not-isolation')" "1"
        # A mapping whose TEIDs never appear is not determinable either.
        out=$(slic_cmd_isolation "$pcap" "A=9999;B=8888")
        chk iso-nomatch   "$(printf '%s\n' "$out" | grep -c 'not-determinable')" "1"
        chk iso-bad-map   "$(slic_cmd_isolation "$pcap" "A" >/dev/null 2>&1; echo $?)" "2"
        chk iso-bad-teid  "$(slic_cmd_isolation "$pcap" "A=abc;B=1" >/dev/null 2>&1; echo $?)" "2"
    else
        printf 'isolation-suite\tSKIP python3 not present\n'
    fi

    # ── 8. Plans carry status: handoff ──────────────────────────────────
    local pf file
    pf=$(slic_cmd_plan slice-escape-lab); rc=$?
    chk plan-rc     "$rc" "0"
    chk plan-status "$(printf '%s\n' "$pf" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    file=$(printf '%s\n' "$pf" | awk -F'\t' '$1=="plan_file"{print $2}')
    chk plan-file-status "$(grep -c '^status: handoff' "$file")" "1"
    chk plan-file-slices "$(grep -q 'two S-NSSAIs' "$file" && echo yes || echo no)" "yes"
    chk plan-file-upf    "$(grep -q 'SHARED UPF' "$file" && echo yes || echo no)" "yes"
    chk plan-unknown     "$(slic_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"

    # ── 9. Status TSV, surface notes, sanitisation ──────────────────────
    out=$(slic_cli_status_tsv)
    chk status-module "$(fld "$out" module)" "slicing"
    chk status-tag    "$(fld "$out" tag)" "slic"
    chk status-dir    "$(fld "$out" dir)" "$SLIC_DIR"
    chk status-sst    "$(fld "$out" sst_assigned)" "1,2,3,4,5"
    out=$(slic_surface_notes)
    chk surface-auth   "$(printf '%s\n' "$out" | grep -c 'slice-honoured-without-authorisation')" "1"
    chk surface-vrf    "$(printf '%s\n' "$out" | grep -c 'shared-upf-no-vrf')" "1"
    chk surface-roam   "$(printf '%s\n' "$out" | grep -c 'roaming-mapping-not-enforced')" "1"
    chk surface-enum   "$(printf '%s\n' "$out" | grep -c 'slice-id-enumeration')" "1"

    # D3 -- the cross-slice matrix: seven tests, and what a different
    # answer proves.
    local cs; cs=$(slic_cmd_cross_slice 1 2)
    chk cross-tests    "$(printf '%s\n' "$cs" | awk -F'\t' '$1=="test"{n++} END{print n+0}')" "7"
    chk cross-a        "$(fld "$cs" slice_a)" "SST 1"
    chk cross-b        "$(fld "$cs" slice_b)" "SST 2"
    chk cross-sub-a    "$(fld "$cs" subnet_a)" "10.45.0.0/16"
    chk cross-t5-cause "$(printf '%s\n' "$cs" | awk -F'\t' '$1=="test_expected" && $2=="T5"{print ($3 ~ /cause 62 or 69/)?"yes":"no"}')" "yes"
    chk cross-art-t3   "$(printf '%s\n' "$cs" | awk -F'\t' '$1=="test_artefact" && $2=="T3"{print ($3 ~ /^curl -m3/)?"yes":"no"}')" "yes"
    chk cross-finding  "$(printf '%s\n' "$cs" | awk -F'\t' '$1=="finding" && $2=="label_not_boundary"{print $3}')" "HIGH"
    chk cross-shared   "$(printf '%s\n' "$cs" | awk -F'\t' '$1=="finding" && $2=="shared_instance"{print $3}')" "INFO"
    chk cross-shared-h "$(slic_cmd_cross_slice 1 2 10.45.0.0/16 10.45.1.0/24 | awk -F'\t' '$1=="finding" && $2=="shared_instance"{print $3}')" "HIGH"
    chk cross-same     "$(slic_cmd_cross_slice 2 2 >/dev/null 2>&1; echo $?)" "2"
    local evil
    evil=$(slic_sanitize $'a\tb\nc')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c)" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | wc -l)" "0"
    SLIC_F=()
    slic_split $'x\t\ty\tz'
    chk split-len   "${#SLIC_F[@]}" "4"
    chk split-empty "${SLIC_F[1]}" ""
    chk split-third "${SLIC_F[2]}" "y"

    # ── 10. 5QI, TSN/QoS and slice/QoS consistency ──────────────────────
    # Table 5.7.4-1 rows as literals: resource type, priority, PDB, PER,
    # MDBV and averaging window. A mistyped row fails here.
    out=$(slic_5qi_desc 1); rc=$?
    chk fiveqi-1-rc      "$rc" "0"
    chk fiveqi-1-status  "$(fld "$out" status)" "standardized"
    chk fiveqi-1-rt      "$(fld "$out" resource_type)" "GBR"
    chk fiveqi-1-prio    "$(fld "$out" priority_level)" "20"
    chk fiveqi-1-pdb     "$(fld "$out" pdb_ms)" "100"
    chk fiveqi-1-units   "$(fld "$out" pdb_0_5ms_units)" "200"
    chk fiveqi-1-per     "$(fld "$out" per)" "10^-2"
    chk fiveqi-1-mdbv    "$(fld "$out" mdbv_bytes)" "N/A"
    chk fiveqi-1-avg     "$(fld "$out" averaging_window_ms)" "2000"
    out=$(slic_5qi_desc 5)
    chk fiveqi-5-rt      "$(fld "$out" resource_type)" "non-GBR"
    chk fiveqi-5-prio    "$(fld "$out" priority_level)" "10"
    chk fiveqi-5-pdb     "$(fld "$out" pdb_ms)" "100"
    chk fiveqi-5-per     "$(fld "$out" per)" "10^-6"
    chk fiveqi-5-avg     "$(fld "$out" averaging_window_ms)" "N/A"
    out=$(slic_5qi_desc 65)
    chk fiveqi-65-rt     "$(fld "$out" resource_type)" "GBR"
    chk fiveqi-65-prio   "$(fld "$out" priority_level)" "7"
    chk fiveqi-65-pdb    "$(fld "$out" pdb_ms)" "75"
    chk fiveqi-65-per    "$(fld "$out" per)" "10^-2"
    out=$(slic_5qi_desc 66)
    chk fiveqi-66-prio   "$(fld "$out" priority_level)" "20"
    chk fiveqi-66-pdb    "$(fld "$out" pdb_ms)" "100"
    chk fiveqi-66-per    "$(fld "$out" per)" "10^-2"
    out=$(slic_5qi_desc 67)
    chk fiveqi-67-prio   "$(fld "$out" priority_level)" "15"
    chk fiveqi-67-pdb    "$(fld "$out" pdb_ms)" "100"
    chk fiveqi-67-per    "$(fld "$out" per)" "10^-3"
    out=$(slic_5qi_desc 82)
    chk fiveqi-82-rt     "$(fld "$out" resource_type)" "delay-critical GBR"
    chk fiveqi-82-prio   "$(fld "$out" priority_level)" "19"
    chk fiveqi-82-pdb    "$(fld "$out" pdb_ms)" "10"
    chk fiveqi-82-units  "$(fld "$out" pdb_0_5ms_units)" "20"
    chk fiveqi-82-per    "$(fld "$out" per)" "10^-4"
    chk fiveqi-82-mdbv   "$(fld "$out" mdbv_bytes)" "255"
    out=$(slic_5qi_desc 84)
    chk fiveqi-84-rt     "$(fld "$out" resource_type)" "delay-critical GBR"
    chk fiveqi-84-prio   "$(fld "$out" priority_level)" "24"
    chk fiveqi-84-pdb    "$(fld "$out" pdb_ms)" "30"
    chk fiveqi-84-units  "$(fld "$out" pdb_0_5ms_units)" "60"
    chk fiveqi-84-per    "$(fld "$out" per)" "10^-5"
    chk fiveqi-84-mdbv   "$(fld "$out" mdbv_bytes)" "1354"
    out=$(slic_5qi_desc 85)
    chk fiveqi-85-rt     "$(fld "$out" resource_type)" "delay-critical GBR"
    chk fiveqi-85-prio   "$(fld "$out" priority_level)" "21"
    chk fiveqi-85-pdb    "$(fld "$out" pdb_ms)" "5"
    chk fiveqi-85-units  "$(fld "$out" pdb_0_5ms_units)" "10"
    chk fiveqi-85-per    "$(fld "$out" per)" "10^-5"
    chk fiveqi-85-mdbv   "$(fld "$out" mdbv_bytes)" "255"
    chk fiveqi-85-avg    "$(fld "$out" averaging_window_ms)" "2000"
    # A dynamic (operator-specific) value: the characteristics are unknown, and
    # the module says so instead of inventing a default row.
    out=$(slic_5qi_desc 137); rc=$?
    chk fiveqi-137-rc     "$rc" "0"
    chk fiveqi-137-status "$(fld "$out" status)" "operator-specific"
    chk fiveqi-137-rt     "$(fld "$out" resource_type)" "unknown"
    chk fiveqi-137-prio   "$(fld "$out" priority_level)" "unknown"
    chk fiveqi-137-pdb    "$(fld "$out" pdb_ms)" "unknown"
    chk fiveqi-137-nodefault "$(fld "$out" averaging_window_ms)" "unknown"
    chk fiveqi-200-status "$(slic_5qi_desc 200 | awk -F'\t' '$1=="status"{print $2}')" "operator-specific"
    # 5QI 75 is reserved in the carried copy: every cell unknown, not N/A.
    out=$(slic_5qi_desc 75); rc=$?
    chk fiveqi-75-rc     "$rc" "0"
    chk fiveqi-75-status "$(fld "$out" status)" "reserved"
    chk fiveqi-75-rt     "$(fld "$out" resource_type)" "unknown"
    chk fiveqi-75-prio   "$(fld "$out" priority_level)" "unknown"
    chk fiveqi-75-service "$(fld "$out" service)" "unknown"
    # Values the table does not assign are refused, not guessed.
    chk fiveqi-rc-unassigned "$(slic_5qi_desc 12 >/dev/null 2>&1; echo $?)" "1"
    chk fiveqi-rc-255        "$(slic_5qi_desc 255 >/dev/null 2>&1; echo $?)" "1"
    chk fiveqi-rc-68         "$(slic_5qi_desc 68 >/dev/null 2>&1; echo $?)" "1"
    chk fiveqi-rc-oob        "$(slic_5qi_desc 300 >/dev/null 2>&1; echo $?)" "2"
    chk fiveqi-rc-nan        "$(slic_5qi_desc abc >/dev/null 2>&1; echo $?)" "2"
    chk fiveqi-rc-empty      "$(slic_5qi_desc >/dev/null 2>&1; echo $?)" "2"
    # The table prints 30 standardized rows plus the one reserved row, and the
    # clause is cited once.
    out=$(slic_cmd_five_qi_table)
    chk fiveqi-table-rows     "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^[0-9]+$/ && ($2=="GBR" || $2=="non-GBR" || $2=="delay-critical GBR" || $2=="unknown")' | wc -l)" "31"
    chk fiveqi-table-gbr      "$(slic_cmd_five_qi_table gbr | awk -F'\t' '$1 ~ /^[0-9]+$/' | wc -l)" "12"
    chk fiveqi-table-nongbr   "$(slic_cmd_five_qi_table non-gbr | awk -F'\t' '$1 ~ /^[0-9]+$/' | wc -l)" "9"
    chk fiveqi-table-dcgbr    "$(slic_cmd_five_qi_table delay-critical-gbr | awk -F'\t' '$1 ~ /^[0-9]+$/' | wc -l)" "9"
    chk fiveqi-table-reserved "$(slic_cmd_five_qi_table reserved | awk -F'\t' '$1 ~ /^[0-9]+$/' | wc -l)" "1"
    chk fiveqi-table-cite     "$(printf '%s\n' "$out" | grep -c 'Table 5.7.4-1')" "1"
    chk fiveqi-table-85units  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="85"{print $5}')" "10"
    chk fiveqi-table-badrt    "$(slic_cmd_five_qi_table bogus >/dev/null 2>&1; echo $?)" "2"

    # --tsn-config: a TSC flow, and the refusals that keep it honest.
    cat > "$d/tsn.conf" <<'CONF'
5qi=82
qfi=1
gfbr_ul=2M
gfbr_dl=2M
mfbr_ul=10M
mfbr_dl=10M
averaging_window=2000
tsc_periodicity=1000
tsc_burst_arrival_time=500
tsc_jitter_range=100-200
CONF
    out=$(slic_cmd_tsn_config "$d/tsn.conf"); rc=$?
    chk tsn-rc        "$rc" "0"
    chk tsn-gfbr-ul   "$(fld "$out" gfbr_ul_bps)" "2000000"
    chk tsn-mfbr-dl   "$(fld "$out" mfbr_dl_bps)" "10000000"
    chk tsn-display   "$(fld "$out" gfbr_ul_display)" "2 Mbit/s"
    chk tsn-avg       "$(fld "$out" averaging_window_ms)" "2000"
    chk tsn-avg-unique "$(printf '%s\n' "$out" | awk -F'\t' '$1=="averaging_window_ms"' | wc -l)" "1"
    chk tsn-avg-fiqi   "$(fld "$out" fiveqi_default_averaging_window_ms)" "2000"
    chk tsn-qfi       "$(fld "$out" qfi)" "1"
    chk tsn-period    "$(fld "$out" tsc_periodicity_us)" "1000"
    chk tsn-burst     "$(fld "$out" tsc_burst_arrival_time_us)" "500"
    chk tsn-jitter    "$(fld "$out" tsc_n6_jitter_range_us)" "100-200"
    # No encoder for QosFlowLevelQosParameters: say so in a limit row.
    chk tsn-no-octets "$(fld "$out" ngap_qos_level_parameters)" "not-emitted"
    chk tsn-limit-row "$(printf '%s\n' "$out" | awk -F'\t' '$1=="limit"' | wc -l)" "1"
    chk tsn-limit-names-encoder "$(printf '%s\n' "$out" | awk -F'\t' '$1=="limit"{print $2}' | grep -c 'QosFlowLevelQosParameters')" "1"
    # A non-GBR 5QI carries no GBR QoS information.
    printf '5qi=9\ngfbr_ul=1M\n' > "$d/ngbr.conf"
    chk tsn-ngbr-rc   "$(slic_cmd_tsn_config "$d/ngbr.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'qfi=1\n' > "$d/no5qi.conf"
    chk tsn-no5qi-rc  "$(slic_cmd_tsn_config "$d/no5qi.conf" >/dev/null 2>&1; echo $?)" "2"
    printf '5qi=82\nfoo=bar\n' > "$d/badkey.conf"
    chk tsn-badkey-rc "$(slic_cmd_tsn_config "$d/badkey.conf" >/dev/null 2>&1; echo $?)" "2"
    printf '5qi=1\ngfbr_ul=1M\ngfbr_dl=1M\nmfbr_ul=1M\nmfbr_dl=1M\ntsc_periodicity=1000\ntsc_jitter_range=300-100\n' > "$d/jit.conf"
    chk tsn-jitter-rc "$(slic_cmd_tsn_config "$d/jit.conf" >/dev/null 2>&1; echo $?)" "2"
    printf '5qi=1\ngfbr_ul=1M\ngfbr_dl=1M\nmfbr_ul=1M\nmfbr_dl=1M\ntsc_burst_arrival_time=5\n' > "$d/noper.conf"
    chk tsn-noper-rc  "$(slic_cmd_tsn_config "$d/noper.conf" >/dev/null 2>&1; echo $?)" "2"
    printf '5qi=1\ngfbr_ul=1M\ngfbr_dl=1M\nmfbr_ul=1M\nmfbr_dl=1M\n' > "$d/gbr-noavg.conf"
    out=$(slic_cmd_tsn_config "$d/gbr-noavg.conf"); rc=$?
    chk tsn-avg-default "$rc/$(fld "$out" averaging_window_ms)" "0/2000"
    chk tsn-missing     "$(slic_cmd_tsn_config /nonexistent.conf >/dev/null 2>&1; echo $?)" "1"
    chk tsn-none        "$(slic_cmd_tsn_config >/dev/null 2>&1; echo $?)" "2"
    chk tsn-gfbr-gt-mfbr "$(printf '5qi=1\ngfbr_ul=9M\ngfbr_dl=1M\nmfbr_ul=1M\nmfbr_dl=1M\n' > "$d/gt.conf"; slic_cmd_tsn_config "$d/gt.conf" >/dev/null 2>&1; echo $?)" "2"

    # --slice-qos-check: SST against the 5QI resource type, rule printed.
    printf 'slice\tsst\t5qi\tgfbr_ul_bps\tgfbr_dl_bps\tmfbr_ul_bps\tmfbr_dl_bps\nembb-voice\t1\t1\t1000000\t1000000\t2000000\t2000000\nembb-ar\t1\t82\t2000000\t2000000\t10000000\t10000000\nurllc-ctrl\t2\t69\t\t\t\t\nmiot-meters\t3\t85\t1000\t1000\t5000\t5000\nv2x-car\t4\t83\t5000000\t5000000\t20000000\t20000000\nhmtc-cam\t5\t6\t\t\t\t\nop-slice\t200\t9\t\t\t\t\n' > "$d/slices.tsv"
    out=$(slic_cmd_slice_qos_check "$d/slices.tsv"); rc=$?
    chk qos-rc          "$rc" "0"
    chk qos-rows        "$(fld "$out" rows)" "7"
    chk qos-conflicts   "$(fld "$out" conflicts)" "3"
    chk qos-verdict     "$(fld "$out" verdict)" "conflicts"
    chk qos-sst1        "$(printf '%s\n' "$out" | grep -c '^finding	embb-ar	HIGH	sst1_no_delay_critical')" "1"
    chk qos-sst2        "$(printf '%s\n' "$out" | grep -c '^finding	urllc-ctrl	HIGH	sst2_requires_guarantee')" "1"
    chk qos-sst3        "$(printf '%s\n' "$out" | grep -c '^finding	miot-meters	HIGH	sst3_no_delay_critical')" "1"
    chk qos-sst5-medium "$(printf '%s\n' "$out" | grep -c '^finding	hmtc-cam	MEDIUM	sst5_requires_guarantee')" "1"
    # The rule sentence travels with the finding, not somewhere else.
    chk qos-rule-text   "$(printf '%s\n' "$out" | grep -c '^finding	embb-ar	HIGH	sst1_no_delay_critical	an SST 1 (eMBB) slice must not carry a delay-critical GBR flow')" "1"
    chk qos-check-ok    "$(printf '%s\n' "$out" | grep -c '^check	v2x-car	4	.*	ok	-')" "1"
    chk qos-operatorsst "$(printf '%s\n' "$out" | grep -c '^check	op-slice	200	unknown	9	non-GBR	not-determinable	sst_operator_specific')" "1"
    # A clean configuration is consistent and silent.
    printf 'slice\tsst\t5qi\tgfbr_ul_bps\tgfbr_dl_bps\tmfbr_ul_bps\tmfbr_dl_bps\nembb\t1\t1\t1\t1\t2\t2\nurllc\t2\t85\t1\t1\t9\t9\n' > "$d/clean.tsv"
    out=$(slic_cmd_slice_qos_check "$d/clean.tsv")
    chk qos-clean-conflicts "$(fld "$out" conflicts)" "0"
    chk qos-clean-verdict   "$(fld "$out" verdict)" "consistent"
    chk qos-clean-nofind    "$(printf '%s\n' "$out" | grep -c '^finding')" "0"
    # GBR bookkeeping rules fire independently of the SST rule.
    printf 'slice\tsst\t5qi\tgfbr_ul_bps\tgfbr_dl_bps\tmfbr_ul_bps\tmfbr_dl_bps\ngbr-nobit\t4\t1\t\t\t\t\nngbr-bit\t4\t9\t1\t1\t2\t2\nmfbr-low\t4\t1\t9\t1\t1\t1\n' > "$d/book.tsv"
    out=$(slic_cmd_slice_qos_check "$d/book.tsv")
    chk qos-gbr-nobit   "$(printf '%s\n' "$out" | grep -c '^finding	gbr-nobit	HIGH	gbr_requires_bitrate')" "1"
    chk qos-ngbr-bit    "$(printf '%s\n' "$out" | grep -c '^finding	ngbr-bit	HIGH	non_gbr_has_bitrate')" "1"
    chk qos-mfbr-low    "$(printf '%s\n' "$out" | grep -c '^finding	mfbr-low	HIGH	mfbr_lt_gfbr')" "1"
    chk qos-conflicts2  "$(fld "$out" conflicts)" "3"
    # Refusals: an unknown column is named, never ignored.
    printf 'slice\tsst\t5qi\tbandwidth\nembb\t1\t1\t5\n' > "$d/badcol.tsv"
    chk qos-badcol-rc   "$(slic_cmd_slice_qos_check "$d/badcol.tsv" >/dev/null 2>&1; echo $?)" "2"
    printf 'slice\tsst\nembb\t1\n' > "$d/nocol.tsv"
    chk qos-nocol-rc    "$(slic_cmd_slice_qos_check "$d/nocol.tsv" >/dev/null 2>&1; echo $?)" "2"
    printf 'slice\tsst\t5qi\nembb\t999\t1\n' > "$d/badsst.tsv"
    chk qos-badsst-rc   "$(slic_cmd_slice_qos_check "$d/badsst.tsv" >/dev/null 2>&1; echo $?)" "2"
    chk qos-nofile-rc   "$(slic_cmd_slice_qos_check /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"
    chk qos-none-rc     "$(slic_cmd_slice_qos_check >/dev/null 2>&1; echo $?)" "2"
    # A 5QI outside the table is a finding, not a silent "ok".
    printf 'slice\tsst\t5qi\nweird\t1\t12\n' > "$d/unassigned.tsv"
    out=$(slic_cmd_slice_qos_check "$d/unassigned.tsv")
    chk qos-unassigned  "$(printf '%s\n' "$out" | grep -c '^finding	weird	HIGH	5qi_not_in_table')" "1"
    chk qos-unassigned-verdict "$(fld "$out" verdict)" "conflicts"
    chk qos-unassigned-conflicts "$(fld "$out" conflicts)" "1"

    # ── 11. Argument validation returns non-zero ────────────────────────
    chk val-encode-none  "$(slic_cmd_encode >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-none  "$(slic_cmd_decode >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-bad   "$(slic_cmd_decode 0102 >/dev/null 2>&1; echo $?)" "1"
    chk val-nssai-none   "$(slic_cmd_nssai >/dev/null 2>&1; echo $?)" "2"
    chk val-sel-none     "$(slic_cmd_selection >/dev/null 2>&1; echo $?)" "2"
    chk val-iso-none     "$(slic_cmd_isolation >/dev/null 2>&1; echo $?)" "2"
    chk val-iso-nofile   "$(slic_cmd_isolation /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk val-detect-none  "$(slic_cmd_detect >/dev/null 2>&1; echo $?)" "2"
    chk val-detect-nofile "$(slic_cmd_detect /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"

    # ── 12. URSP — TS 24.526 5.2 ────────────────────────────────────────
    # The hex expectations are the octet layout of Figures 5.2.1-5.2.4, and
    # pycrate TS24526_UEPOL is asked to decode the same bytes when it is
    # installed: an independent implementation agreeing on the framing and the
    # traffic descriptor is worth more than the same author twice.
    out=$(slic_cmd_ursp_rule --match-all --snssai 1:000001 --dnn internet)
    chk ursp-matchall-hex  "$(fld "$out" hex)" "001B01000101001500130100100201000001040908696E7465726E6574"
    chk ursp-matchall-td   "$(fld "$out" traffic_descriptor)" "match-all"
    chk ursp-matchall-rsd  "$(fld "$out" route_selection)" "S-NSSAI + DNN"
    chk ursp-matchall-len  "$(fld "$out" rule_len_field)" "27"
    chk ursp-matchall-rt   "$(printf '%s\n' "$out" | grep -c '^back_rsd	1	1	04	DNN	internet$')" "1"
    chk ursp-matchall-nssai "$(printf '%s\n' "$out" | awk -F'\t' '$1=="back_rsd" && $5=="S-NSSAI"{print $6}' | grep -c 'sd=000001')" "1"

    out=$(slic_cmd_ursp_rule --app-id com.example.app --ssc 1 --pdu ipv4 --access 3gpp --precedence 7)
    chk ursp-appid-hex     "$(fld "$out" hex)" "0021070011A00F636F6D2E6578616D706C652E617070000B0009070006010108011001"
    chk ursp-appid-preced  "$(fld "$out" rule_precedence)" "7"
    chk ursp-appid-ssc     "$(printf '%s\n' "$out" | grep -c 'back_rsd	1	1	01	SSC mode	SSC mode 1')" "1"
    chk ursp-appid-pdu     "$(printf '%s\n' "$out" | grep -c 'back_rsd	1	1	08	PDU session type	ipv4')" "1"
    chk ursp-appid-access  "$(printf '%s\n' "$out" | grep -c 'back_rsd	1	1	10	preferred access type	3gpp')" "1"

    # A DNN with several labels is a length-prefixed APN (TS 23.003 9.1).
    out=$(slic_cmd_ursp_rule --dnn-match internet.mnc001.mcc001.gprs --snssai 3:000003)
    chk ursp-apn-hex       "$(fld "$out" hex)" "002D01001E881C08696E7465726E6574066D6E63303031066D63633030310467707273000A00080100050203000003"
    chk ursp-apn-decoded   "$(printf '%s\n' "$out" | grep -c 'back_td	1	88	DNN	internet.mnc001.mcc001.gprs')" "1"

    # The SST-only S-NSSAI is emitted as 4 octets with SD=FFFFFF and says so.
    out=$(slic_cmd_ursp_rule --match-all --snssai 2)
    chk ursp-sd-defaulted  "$(fld "$out" sd_emitted)" "ffffff"
    chk ursp-sd-hex        "$(fld "$out" hex)" "001001000101000A00080100050202FFFFFF"

    # The UE policy part length counts the rule list, not the type octet.
    out=$(slic_cmd_ursp_rule --domain netflix.com --snssai 2:000002 --precedence 5 --wrap)
    chk ursp-wrap-len      "$(fld "$out" policy_part_hex | cut -c1-4)" "001E"
    chk ursp-wrap-octets   "$(fld "$out" policy_part_octets)" "33"
    chk ursp-wrap-type     "$(fld "$out" policy_part_hex | cut -c5-6)" "01"
    chk ursp-wrap-carried  "$(fld "$out" carried_in)" "5GMM MANAGE UE POLICY COMMAND, UE policy container"

    # The walker reads the wrapped part back to the same rule.
    out=$(slic_cmd_ursp_parse "$(fld "$(slic_cmd_ursp_rule --domain netflix.com --snssai 2:000002 --precedence 5 --wrap)" policy_part_hex)")
    chk ursp-parse-layer   "$(fld "$out" layer)" "ue_policy_part"
    chk ursp-parse-rules   "$(fld "$out" rules)" "1"
    chk ursp-parse-fqdn    "$(printf '%s\n' "$out" | grep -c '^td	1	91	destination FQDN	netflix.com')" "1"

    # Oracle: an independent decoder agrees on framing, precedence, FQDN.
    local py="${IMSI_URSP_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}"
    if [[ -x "$py" ]]; then
        out=$(slic_cmd_ursp_rule --domain netflix.com --snssai 2:000002 --precedence 5 --wrap --oracle)
        chk ursp-oracle-ok    "$(fld "$out" oracle_decode_ok)" "yes"
        chk ursp-oracle-rules "$(fld "$out" oracle_rules)" "1"
        chk ursp-oracle-preced "$(fld "$out" oracle_rule_precedence)" "5"
        chk ursp-oracle-fqdn  "$(fld "$out" oracle_td_fqdn)" "netflix.com"
        chk ursp-oracle-same-len "$(fld "$out" oracle_rule_len)" "$(fld "$out" rule_len_field)"
    else
        printf 'ursp-oracle	SKIP	%s is not executable\n' "$py"
    fi

    # Audit: a match-all rule at a lower precedence number shadows the rules
    # behind it, a descriptor can steer traffic off 3GPP, and offload bypasses
    # the core entirely.
    local r1 r2 r3
    r1=$(fld "$(slic_cmd_ursp_rule --match-all --snssai 1:000001 --precedence 1)" hex)
    r2=$(fld "$(slic_cmd_ursp_rule --domain bank.example --snssai 2:000002 --access non-3gpp --precedence 40)" hex)
    r3=$(fld "$(slic_cmd_ursp_rule --app-id com.example.app --snssai 1:000001 --access 3gpp --offload --precedence 10)" hex)
    out=$(slic_cmd_ursp_audit "${r1}${r2}")
    chk ursp-audit-rules   "$(fld "$out" rules)" "2"
    chk ursp-audit-shadow  "$(printf '%s\n' "$out" | grep -c '^finding	match_all_shadows_targeted	HIGH')" "1"
    chk ursp-audit-off3gpp "$(printf '%s\n' "$out" | grep -c '^finding	steered_off_3gpp	HIGH')" "1"
    chk ursp-audit-verdict "$(fld "$out" verdict)" "policy_steers_traffic_outside_the_slice"
    out=$(slic_cmd_ursp_audit "$r3")
    chk ursp-audit-offload "$(printf '%s\n' "$out" | grep -c '^finding	offload_bypasses_the_core	HIGH')" "1"
    out=$(slic_cmd_ursp_audit "$(fld "$(slic_cmd_ursp_rule --match-all --snssai 1:000001 --access 3gpp)" hex)")
    chk ursp-audit-clean   "$(fld "$out" findings)" "0"
    chk ursp-audit-clean-verdict "$(fld "$out" verdict)" "policy_consistent_with_the_slice"

    chk ursp-types-rows    "$(slic_cmd_ursp_types | grep -c '^component')" "15"
    chk ursp-no-td-rc      "$(slic_cmd_ursp_rule --snssai 1:000001 >/dev/null 2>&1; echo $?)" "2"
    chk ursp-no-rsd-rc     "$(slic_cmd_ursp_rule --match-all >/dev/null 2>&1; echo $?)" "2"
    chk ursp-bad-kind-rc   "$(slic_cmd_ursp_rule --bogus >/dev/null 2>&1; echo $?)" "2"
    chk ursp-parse-none    "$(slic_cmd_ursp_parse >/dev/null 2>&1; echo $?)" "2"
    chk ursp-audit-none    "$(slic_cmd_ursp_audit >/dev/null 2>&1; echo $?)" "2"
    chk ursp-apn-bad-rc    "$(slic_apn_encode 'a..b' >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d"
    trap - EXIT
    [[ -n "$_prev_trap" ]] && eval "$_prev_trap"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
slic_menu() {
    local c p h
    while true; do
        banner
        echo -e "  ${C_MAG}=== Slicing Escape ===${C_RESET}"
        echo -e "  SST:  ${C_GRN}1 eMBB  2 URLLC  3 MIoT  4 V2X  5 HMTC${C_RESET}"
        echo -e "  dir:  ${C_DIM}$SLIC_PLANS${C_RESET}\n"
        cat << 'M'
  [1]  SST table
  [2]  encode an S-NSSAI
  [3]  decode an S-NSSAI
  [4]  parse an NSSAI container
  [5]  slice selection (requested / allowed / rejected)
  [6]  isolation check from a capture
  [7]  decode a 5GS NAS slice message
  [8]  vulnerability classes
  [9]  plan: slice escape lab
  [10] 5QI characteristics (TS 23.501 Table 5.7.4-1)
  [11] 5QI table (filter by resource type)
  [12] TSN/QoS configuration description
  [13] slice/QoS consistency check
  [14] status
  [0]  back

M
        # EOF leaves the menu. Without the '|| return 0' a piped or closed stdin
        # spins forever: read fails, c stays empty, the case matches nothing and
        # the loop comes straight back. Every other menu in the tree does this.
        read -rp "  choice> " c || return 0
        case "$c" in
            1) slic_sst_table | column -t -s$'\t' 2>/dev/null || slic_sst_table
               read -rp "  press enter " _ ;;
            2) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an SST; cannot prompt in CLI mode" >&2
               else read -rp "  SST (1-255)> " p; read -rp "  SD (6 hex or none)> " s
                    slic_cmd_encode "$p" "${s:-none}"; read -rp "  press enter " _; fi ;;
            3) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  S-NSSAI hex> " h; slic_cmd_decode "$h" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            4) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  NSSAI hex> " h; slic_cmd_nssai "$h" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            5) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  requested NSSAI hex> " r; read -rp "  allowed NSSAI hex (blank)> " a; read -rp "  rejected NSSAI hex (blank)> " j
                    slic_cmd_selection "$r" "$a" "$j" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            6) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; read -rp "  slice map (blank, e.g. A=1001;B=1002)> " m
                    slic_cmd_isolation "$p" "$m" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            7) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  5GS NAS hex> " h
                    printf 'message_type\t%s\nmessage_name\t%s\ncause\t%s\ncause_name\t%s\n' \
                        "$(slic_nas_5gs_type "$h")" "$(slic_nas_5gs_message_name "$(slic_nas_5gs_type "$h")")" \
                        "$(slic_nas_5gs_cause "$h")" "$(slic_5gmm_cause_name "$(slic_nas_5gs_cause "$h")")"
                    read -rp "  press enter " _; fi ;;
            8) slic_surface_notes | column -t -s$'\t' 2>/dev/null || slic_surface_notes
               read -rp "  press enter " _ ;;
            9) slic_cmd_plan slice-escape-lab; read -rp "  press enter " _ ;;
            10) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a 5QI; cannot prompt in CLI mode" >&2
               else read -rp "  5QI> " p; slic_cmd_five_qi "$p" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _; fi ;;
            11) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a resource type; cannot prompt in CLI mode" >&2
               else read -rp "  resource type (blank = all: gbr|non-gbr|delay-critical-gbr|reserved)> " p
                    slic_cmd_five_qi_table "$p" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _; fi ;;
            12) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a conf file; cannot prompt in CLI mode" >&2
               else read -rp "  tsn conf path> " p
                    slic_cmd_tsn_config "$p" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _; fi ;;
            13) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a tsv; cannot prompt in CLI mode" >&2
               else read -rp "  slice/flow tsv path> " p
                    slic_cmd_slice_qos_check "$p" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _; fi ;;
            14) slic_cli_status_tsv | column -t -s$'\t' 2>/dev/null || slic_cli_status_tsv
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
slic_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        slic_cli_status_tsv ;;
        --sst-table)         slic_sst_table ;;
        --encode-s-nssai)    slic_cmd_encode "${1:-}" "${2:-}" ;;
        --decode-s-nssai)    slic_cmd_decode "${1:-}" ;;
        --nssai-parse)       slic_cmd_nssai "${1:-}" ;;
        --selection)         slic_cmd_selection "${1:-}" "${2:-}" "${3:-}" ;;
        --isolation-check)   slic_cmd_isolation "${1:-}" "${2:-}" ;;
        --cross-slice)       slic_cmd_cross_slice "${1:-1}" "${2:-2}" "${3:-}" "${4:-}" ;;
        --detect)            slic_cmd_detect "${1:-}" ;;
        --nas5gs)            {
                                 local h="${1:-}"
                                 [[ -n "$h" ]] || { printf 'ERROR\tusage: --nas5gs <hex>\n' >&2; return 2; }
                                 local t; t=$(slic_nas_5gs_type "$h") || { printf 'ERROR\tnot a 5GS plain NAS message (no 0x7E extended protocol discriminator)\n' >&2; return 1; }
                                 local cz; cz=$(slic_nas_5gs_cause "$h")
                                 printf 'message_type\t%s\n' "$t"
                                 printf 'message_name\t%s\n' "$(slic_nas_5gs_message_name "$t")"
                                 printf 'cause\t%s\n' "$cz"
                                 printf 'cause_name\t%s\n' "$([[ -n "$cz" ]] && slic_5gmm_cause_name "$cz" || printf '')"
                             } ;;
        --five-qi)           slic_cmd_five_qi "${1:-}" ;;
        --five-qi-table)     slic_cmd_five_qi_table "${1:-}" ;;
        --tsn-config)        slic_cmd_tsn_config "${1:-}" ;;
        --slice-qos-check)   slic_cmd_slice_qos_check "${1:-}" ;;
        --ursp-rule)         slic_cmd_ursp_rule "$@" ;;
        --ursp-parse)        slic_cmd_ursp_parse "${1:-}" ;;
        --ursp-audit)        slic_cmd_ursp_audit "${1:-}" ;;
        --ursp-types)        slic_cmd_ursp_types ;;
        --surface)           slic_surface_notes ;;
        --plan)              slic_cmd_plan "${1:-}" ;;
        --selftest)          slic_selftest ;;
        --menu)              slic_menu ;;
        *)
            cat >&2 <<EOF
Slicing Escape — S-NSSAI codec, slice selection, isolation, 5QI/TSN QoS

Usage: $0 COMMAND
  --status-tsv                        module state as TSV
  --sst-table                         the standardised SST values with sources
  --encode-s-nssai <sst> [sd]         S-NSSAI hex (SST + 3-octet SD)
  --decode-s-nssai <hex>              S-NSSAI hex -> SST/SD and the SST name
  --nssai-parse <hex>                 NSSAI container (or full IE) -> slices
  --selection <req> [allow] [reject]  the selection outcome, including
                                      granted-but-unrequested and dropped
  --isolation-check <pcap> [map]      isolation evidence; never claims
                                      isolation it cannot establish
  --detect <slice-events.tsv>         session-level slice anomaly rules
  --cross-slice [a] [b] [subnet-a] [subnet-b]
                                      D3: the reachability matrix between two
                                      slices -- addressing, authorisation,
                                      5QI and the resource half
  --nas5gs <hex>                      decode a 5GS plain NAS slice message
  --five-qi <5qi>                     decode one 5QI to its TS 23.501
                                      Table 5.7.4-1 characteristics
  --five-qi-table [resource-type]     the whole table as TSV; filter by
                                      gbr | non-gbr | delay-critical-gbr |
                                      reserved
  --tsn-config <conf>                 a TSN/QoS description (5qi=, gfbr_*,
                                      mfbr_*, averaging_window=, tsc_*) as TSV.
                                      No NGAP octets: the encoder does not
                                      exist, and a limit row says so
  --slice-qos-check <tsv>             flag a slice whose 5QI resource type
                                      contradicts its S-NSSAI SST; each
                                      finding carries the rule it broke
  --ursp-rule --match-all|--domain F |--app-id ID|--dnn-match DNN
                                      one URSP rule: traffic descriptor flags
                                      plus --snssai SST:SD, --dnn, --ssc, --pdu,
                                      --access, --multi-access, --offload,
                                      --precedence and --wrap for the policy part
  --ursp-parse <hex>                  walk a URSP rule, rule list or UE policy part
  --ursp-audit <hex>                  what the policy steers traffic to, and what
                                      it steers it out of
  --ursp-types                        the component types this module builds
  --surface                           the vulnerability classes
  --plan slice-escape-lab             write the handed-off lab plan
  --selftest                          verify the codec and rules
  --menu                              interactive menu
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
    slic_cli_main "$@"
fi
