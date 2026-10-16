#!/usr/bin/env bash
# sidelink — NR sidelink / V2X (PC5): resource pool maths and ITS security.
#
# Sidelink lets UEs talk directly on PC5 without the network, which is what V2X
# uses. It brings its own physical layer (SCI, resource pools, PSFCH), its own
# identity (24-bit Layer-2 IDs) and a certificate-based security layer (ETSI
# TS 102 940 / IEEE 1609.2 pseudonym certificates). This module works the
# resource-pool arithmetic, the SCI-1A field layout and the ITS certificate
# model, and checks a relay configuration. It transmits nothing.
#
# Attack owned: V2X/sidelink adjacency (O17 beam/resource surface) — analysis half.
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

MOD_TMP="$TMP_DIR/sidelink"
SLNK_DIR="$LOOT_DIR/sidelink"
mkdir -p "$MOD_TMP" "$SLNK_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

slnk_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
SLNK_F=()
slnk_split() {
    SLNK_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        SLNK_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

slnk_status_tsv() {
    printf 'MODULE\tsidelink\n'
    printf 'TARGET\tPC5 resource pools, SCI-1A layout, ITS certificate model, relay checks\n'
    printf 'TRANSMIT\tnone — resource arithmetic and configuration analysis\n'
    printf 'SELFTEST\tyes\n'
}

# ── resource pool: number of subchannels ────────────────────────────────
slnk_subchannels() {
    local bwp="${1:-}" sub="${2:-}"
    [[ "$bwp" =~ ^[0-9]+$ && "$sub" =~ ^[0-9]+$ ]] || { printf 'ERROR\tbandwidth and subchannel size must be integers\n' >&2; return 2; }
    (( sub > 0 )) || { printf 'ERROR\tsubchannel size must be positive\n' >&2; return 2; }
    printf 'bwp_prb\t%d\nsubchannel_prb\t%d\nsubchannels\t%d\nremainder_prb\t%d\n' \
        "$bwp" "$sub" "$(( bwp / sub ))" "$(( bwp % sub ))"
}

# ── SCI-1A frequency resource indicator width (TS 38.212 §8.3.1.1) ──────
# Start-and-length is encoded over N*(N+1)/2 states, so the field is
# ceil(log2(N*(N+1)/2)) bits.
slnk_freq_bits() {
    local n="${1:-}"
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || { printf 'ERROR\tsubchannel count must be positive\n' >&2; return 2; }
    local states=$(( n * (n + 1) / 2 )) bits=0 p=1
    while (( p < states )); do p=$(( p * 2 )); bits=$(( bits + 1 )); done
    printf 'subchannels\t%d\nstates\t%d\nfreq_field_bits\t%d\n' "$n" "$states" "$bits"
}

# ── PFI and Layer-2 IDs ─────────────────────────────────────────────────
slnk_pfi() {
    local v="${1:-}"
    [[ "$v" =~ ^[0-9]+$ ]] || { printf 'ERROR\tPFI must be numeric\n' >&2; return 2; }
    (( v >= 1 && v <= 64 )) || { printf 'ERROR\tPFI is a 6-bit value in 1..64 (0 is not usable)\n' >&2; return 2; }
    printf 'pfi\t%d\nbits\t6\n' "$v"
}
slnk_l2id() {
    local h="${1:-}"
    h=$(printf '%s' "$h" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]{1,6}$ ]] || { printf 'ERROR\tLayer-2 ID must be 1..6 hex digits (24 bits)\n' >&2; return 2; }
    printf 'l2_id\t%s\nvalue\t%d\nbits\t24\n' "$h" "$(( 16#$h ))"
}

slnk_sci_1a() {
    cat <<'EOF'
field	bits	meaning
priority	3	PPPP (1..8)
freq_resource_assignment	var	start subchannel + number of subchannels
time_resource_assignment	5	up to three resources
resource_reservation_period	5	periodic reservation
dmrs_pattern	2	DMRS pattern
sci_format_2a	1	whether a second-stage SCI follows
beta_offset	2	SCI-2A beta offset
num_dmrs	1	number of DMRS symbols
mcs	5	modulation and coding scheme
psfch_overhead	2	PSFCH symbol overhead
EOF
}

slnk_its() {
    cat <<'EOF'
certificate	type	purpose
enrollment	ETSI TS 102 941	long-term; proves the ITS station to the authority
authorization	ETSI TS 102 941	short-term pseudonym; signs CAM/DENM, rotated frequently
application	ETSI TS 102 940	scoped to an application (e.g., platooning)
EOF
}

# ── relay configuration check ───────────────────────────────────────────
# A UE-to-NW relay extends coverage; an open relay without an ACL lets any
# remote UE route through the relay's credentials.
slnk_relay_check() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such config: %s\n' "$file" >&2; return 1; }
    local remote="" acl="" filter="" signed=""
    local line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z'); v="${line#*=}"
        case "$k" in
            remote_ue_allowed) remote="$v" ;;
            relay_acl|acl) acl="$v" ;;
            l2id_filter|relay_l2id_filter) filter="$v" ;;
            relay_authorized|authorized) signed="$v" ;;
        esac
    done < "$file"
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "$remote" =~ ^(true|yes|1|on)$ ]]; then
        if [[ -z "$acl" && -z "$filter" ]]; then
            printf 'open_relay\tHIGH\tremote-UE relaying is enabled with no ACL and no Layer-2 ID filter; any remote UE can route through this relay\n'; n=$((n+1))
        else
            printf 'relay_filtered\tINFO\tremote-UE relaying is enabled but bounded by an ACL or Layer-2 ID filter\n'
        fi
    fi
    [[ "$signed" =~ ^(true|yes|1|on)$ ]] || { printf 'relay_unauthorized\tMEDIUM\trelaying is not tied to an authorisation; a rogue relay can impersonate a node\n'; n=$((n+1)); }
    (( n == 0 )) && printf 'none\tINFO\trelaying is off or fully bounded and authorised\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

slnk_plan() {
    cat <<'EOF'
status	handoff
what	observing or emulating PC5 sidelink
hardware	an SDR with transmit for a UE-side sidelink (USRP/BladeRF), or two UEs with V2X enabled
software	srsRAN with sidelink support, or a UE test bench with the PC5 stack; an ITS PKI for the certificate layer
flow	1. --subchannels and --freq-bits for a pool  2. --sci1a for the field layout  3. --relay-check on a relay config
note	transmitting PC5 into the V2X band needs a licence and an ITS credential; this module analyses pools and configs
EOF
}

slnk_selftest() {
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
    export SLNK_DIR="$d/loot/sidelink"
    mkdir -p "$SLNK_DIR"

    # 1. Resource pool: subchannels and remainder.
    chk sub-100-10 "$(fld "$(slnk_subchannels 100 10)" subchannels)" "10"
    chk sub-100-12 "$(fld "$(slnk_subchannels 100 12)" subchannels)" "8"
    chk sub-rem    "$(fld "$(slnk_subchannels 100 12)" remainder_prb)" "4"
    chk sub-bad    "$(slnk_subchannels 100 0 >/dev/null 2>&1; echo $?)" "2"

    # 2. SCI-1A frequency field width: N=10 -> 55 states -> 6 bits.
    chk freq-10 "$(fld "$(slnk_freq_bits 10)" freq_field_bits)" "6"
    chk freq-8  "$(fld "$(slnk_freq_bits 8)" freq_field_bits)" "6"
    chk freq-25 "$(fld "$(slnk_freq_bits 25)" freq_field_bits)" "9"
    chk freq-1  "$(fld "$(slnk_freq_bits 1)" freq_field_bits)" "0"
    chk freq-bad "$(slnk_freq_bits 0 >/dev/null 2>&1; echo $?)" "2"

    # 3. PFI and Layer-2 ID ranges.
    chk pfi-1  "$(fld "$(slnk_pfi 1)" bits)" "6"
    chk pfi-64 "$(fld "$(slnk_pfi 64)" pfi)" "64"
    chk pfi-0  "$(slnk_pfi 0 >/dev/null 2>&1; echo $?)" "2"
    chk pfi-65 "$(slnk_pfi 65 >/dev/null 2>&1; echo $?)" "2"
    chk l2id   "$(fld "$(slnk_l2id ffffff)" value)" "16777215"
    chk l2id-bad "$(slnk_l2id 1234567 >/dev/null 2>&1; echo $?)" "2"

    # 4. Layout and certificate tables.
    chk sci-mcs "$(slnk_sci_1a | awk -F'\t' '$1=="mcs"{print $2}')" "5"
    chk sci-prio "$(slnk_sci_1a | awk -F'\t' '$1=="priority"{print $2}')" "3"
    chk its-pseudo "$(slnk_its | awk -F'\t' '$1=="authorization"{print ($3 ~ /pseudonym/)?"ok":"no"}')" "ok"

    # 5. Relay check: open relay flagged, bounded relay abstains.
    printf 'remote_ue_allowed=true\nrelay_authorized=false\n' > "$d/open.conf"
    local out; out=$(slnk_relay_check "$d/open.conf")
    chk relay-open "$(fld "$out" open_relay)" "HIGH"
    chk relay-open-count "$(fld "$out" findings)" "2"
    printf 'remote_ue_allowed=true\nrelay_acl=allowed-l2ids\nrelay_authorized=true\n' > "$d/bounded.conf"
    out=$(slnk_relay_check "$d/bounded.conf")
    chk relay-bounded "$(fld "$out" relay_filtered)" "INFO"
    chk relay-bounded-count "$(fld "$out" findings)" "0"
    chk relay-missing "$(slnk_relay_check "$d/none.conf" >/dev/null 2>&1; echo $?)" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

slnk_menu() {
    while true; do
        banner
        echo "  === NR Sidelink / V2X ==="
        echo
        cat <<'M'
  [1]  Subchannel count
  [2]  SCI-1A frequency field width
  [3]  PFI range
  [4]  Layer-2 ID
  [5]  SCI-1A field reference
  [6]  ITS certificate reference
  [7]  Relay configuration check
  [8]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  bwp PRB> " b; read -rp "  subchannel PRB> " s; slnk_subchannels "$b" "$s"; read -rp "  enter " _ ;;
            2) read -rp "  subchannels> " n; slnk_freq_bits "$n"; read -rp "  enter " _ ;;
            3) read -rp "  pfi> " p; slnk_pfi "$p"; read -rp "  enter " _ ;;
            4) read -rp "  l2 id (hex)> " h; slnk_l2id "$h"; read -rp "  enter " _ ;;
            5) slnk_sci_1a; read -rp "  enter " _ ;;
            6) slnk_its; read -rp "  enter " _ ;;
            7) read -rp "  relay config> " p; slnk_relay_check "$p"; read -rp "  enter " _ ;;
            8) slnk_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

slnk_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  slnk_status_tsv ;;
        --subchannels) slnk_subchannels "${1:-}" "${2:-}" ;;
        --freq-bits)   slnk_freq_bits "${1:-}" ;;
        --pfi)         slnk_pfi "${1:-}" ;;
        --l2id)        slnk_l2id "${1:-}" ;;
        --sci1a)       slnk_sci_1a ;;
        --its)         slnk_its ;;
        --relay-check) slnk_relay_check "${1:-}" ;;
        --plan)        slnk_plan ;;
        --selftest)    slnk_selftest ;;
        --menu)        slnk_menu ;;
        *)
            cat >&2 <<EOF
NR Sidelink / V2X — PC5 resource pools, SCI-1A and ITS security

Usage: $0 COMMAND
  --status-tsv               module state as TSV
  --subchannels <bwp_prb> <subchannel_prb>
  --freq-bits <n_subchannels>   SCI-1A frequency resource field width
  --pfi <1..64>              PC5 QoS flow identifier
  --l2id <hex>               24-bit Layer-2 ID
  --sci1a                    SCI format 1-A field reference
  --its                      ETSI/1609.2 certificate reference
  --relay-check <conf>       UE-to-NW relay configuration findings
  --plan                     V2X handoff plan
  --selftest                 verify the arithmetic and detectors
  --menu                     interactive menu
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
    slnk_cli_main "$@"
fi
