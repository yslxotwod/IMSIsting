#!/usr/bin/env bash
# Cipher suite audit across 2G/3G/4G/5G.
#
# Three things this module does for real, with no hardware:
#
#   * carries the complete algorithm tables for all four generations, with
#     the 3GPP reference, the key length and the published break status
#   * parses a Security Mode Command and reports the negotiated algorithms
#   * scores a session and detects a downgrade against the UE's advertised
#     capability or against the network's other sessions
#
# The rule that matters most in the scoring: an algorithm identifier the
# table does not know is scored UNKNOWN, never "ok". A toolkit that treats
# an unrecognised cipher as safe reports a false negative on exactly the
# case an attacker would choose — a non-standard or future algorithm id.
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

MOD_TMP="$TMP_DIR/cipher_audit"
CAUD_DIR="$LOOT_DIR/cipher_audit"
CAUD_SESSIONS="$CAUD_DIR/sessions.tsv"
mkdir -p "$MOD_TMP" "$CAUD_DIR" 2>/dev/null

# Module 21, used only to pull an SMC out of a capture. Optional: every
# encoding and scoring path here works without it.
CAUD_PCAP_MOD="${CAUD_PCAP_MOD:-$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)/17_pcap_analysis.sh}"

# ── sanitisation ────────────────────────────────────────────────────────
caud_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── TSV field access ────────────────────────────────────────────────────
# `while IFS=$'\t' read -r ...` does NOT preserve empty fields: Bash
# collapses a run of IFS whitespace into one delimiter, so a row with two
# adjacent empty columns shifts every later value left. A session row with
# no advertised capabilities has exactly that shape, and the symptom is the
# timestamp being read as the capability list. There is no `read` flag that
# fixes this, so field access goes through awk, which is correct.
caud_field() {
    # caud_field <line> <n>
    printf '%s\n' "$1" | awk -F'\t' -v n="$2" '{ if (NF >= n) print $n; else print "" }'
}

caud_nf() {
    printf '%s\n' "$1" | awk -F'\t' '{print NF}'
}

# ── the algorithm tables ────────────────────────────────────────────────
# Format per row (tab separated):
#   gen  alg  full_name  3gpp_ref  key_bits  status  note
#
# `status` is the single word the scorer keys on: null, broken, weak, ok,
# unknown. `note` is the reasoning shown to the operator, and it is the
# published break, not a guess.
caud_table_gen() {
    case "${1:-all}" in
    gsm)
        cat <<'EOF'
2G	A5/0	A5/0 (no ciphering)	3GPP TS 43.020 §4.4.2	0	null	no ciphering at all; every frame is readable by any receiver in range
2G	A5/1	A5/1	3GPP TS 43.020 Annex 2	64	broken	broken by Briceno's 1999 time-memory tradeoff, then by Nohl's 2009 rainbow tables (2 TB, ~2 minutes); a live A5/1 session is recoverable from about 4 seconds of known plaintext
2G	A5/2	A5/2	3GPP TS 43.020 §4.4.2.3	64	broken	deliberately weakened export variant; broken in real time on a single PC by Barkan, Biham and Keller (2003); the A5/2 oracle recovers the A5/1 or A5/3 key of the same session
2G	A5/3	A5/3 (KASUMI)	3GPP TS 55.216	64	weak	KASUMI, a MISTY1 derivative; Biham-Dunkelman-Keller (2005) and subsequent related-key attacks give far less than the nominal 64-bit work factor
2G	A5/4	A5/4 (KASUMI-128)	3GPP TS 55.226	128	ok	KASUMI keyed with 128 bits; same cipher core as A5/3 so the structural weaknesses carry over, but the longer key removes the practical recovery
2G	A5/5	A5/5	3GPP TS 43.020 (proposed)	128	ok	proposed AES-based variant for GSM; not deployed on real networks
2G	A5/6	A5/6	3GPP TS 43.020 (proposed)	128	ok	proposed variant; not deployed
2G	A5/7	A5/7	3GPP TS 43.020 (proposed)	128	ok	proposed variant; not deployed
EOF
        ;;
    umts)
        cat <<'EOF'
3G	UEA0	UEA0 (null ciphering)	3GPP TS 33.102 §6.6.1	0	null	ciphering explicitly disabled; one bit in the Security Mode Command and every user-plane frame is in the clear
3G	UEA1	UEA1 (KASUMI)	3GPP TS 33.102 §6.6.1	128	weak	KASUMI in f8 mode; same cipher core as A5/3, so the Biham-Dunkelman-Keller structural attacks apply with a reduced margin
3G	UEA2	UEA2 (SNOW 3G)	3GPP TS 33.102 §6.6.1 / TS 35.215	128	ok	SNOW 3G, no practical break published; the UEA2/UIA2 set is the accepted 3G baseline
3G	UIA1	UIA1 (KASUMI)	3GPP TS 33.102 Annex B	128	weak	KASUMI integrity mode f9; shares the A5/3 core weaknesses
3G	UIA2	UIA2 (SNOW 3G)	3GPP TS 33.102 / TS 35.215	128	ok	SNOW 3G integrity; no practical forgery published
3G	n/a	no integrity (UIA0 equivalent)	3GPP TS 33.102 §6.5	0	null	UIA1/2 absent: RRC and NAS messages carry no MAC and can be forged
EOF
        ;;
    lte)
        cat <<'EOF'
4G	EEA0	EEA0 (null ciphering)	3GPP TS 33.401 §5.1.4.1 / Annex B	0	null	the NAS/RRC Security Mode Command names EEA0 and every user-plane packet is unencrypted; the classic downgrade target
4G	EEA1	EEA1 (SNOW 3G)	3GPP TS 33.401 Annex B / TS 35.215	128	ok	SNOW 3G for LTE; no practical break published
4G	EEA2	EEA2 (AES-128-CTR)	3GPP TS 33.401 Annex B	128	ok	AES-128 in counter mode; the reference cipher for LTE, no practical break
4G	EEA3	EEA3 (ZUC-128)	3GPP TS 33.401 Annex B / TS 35.221	128	ok	ZUC; no practical break published against the deployed 128-bit variant
4G	EIA0	EIA0 (null integrity)	3GPP TS 33.401 §5.1.4.2	0	null	no integrity protection; an attacker can inject or modify NAS and RRC signalling
4G	EIA1	EIA1 (SNOW 3G)	3GPP TS 33.401 Annex B	128	ok	SNOW 3G MAC; no practical forgery published
4G	EIA2	EIA2 (AES-128-CMAC)	3GPP TS 33.401 Annex B	128	ok	AES-CMAC; the reference integrity algorithm for LTE
4G	EIA3	EIA3 (ZUC-128)	3GPP TS 33.401 Annex B / TS 35.221	128	ok	ZUC MAC; no practical forgery published
EOF
        ;;
    5g)
        cat <<'EOF'
5G	NEA0	NEA0 (null ciphering)	3GPP TS 33.501 §5.8 / TS 33.401 Annex B	0	null	no 5G user-plane or signalling encryption; NR traffic readable on the air interface
5G	NEA1	NEA1 (SNOW 3G)	3GPP TS 33.501 §5.8	128	ok	SNOW 3G retained for 5G; no practical break published
5G	NEA2	NEA2 (AES-128-CTR)	3GPP TS 33.501 §5.8	128	ok	AES-128 in counter mode; the 5G reference cipher
5G	NEA3	NEA3 (ZUC-128)	3GPP TS 33.501 §5.8 / TS 35.221	128	ok	ZUC for NR; no practical break published
5G	NIA0	NIA0 (null integrity)	3GPP TS 33.501 §5.8	0	null	no integrity protection on 5G NAS/RRC; signalling can be forged or replayed
5G	NIA1	NIA1 (SNOW 3G)	3GPP TS 33.501 §5.8	128	ok	SNOW 3G MAC for 5G
5G	NIA2	NIA2 (AES-128-CMAC)	3GPP TS 33.501 §5.8	128	ok	AES-CMAC for 5G
5G	NIA3	NIA3 (ZUC-128)	3GPP TS 33.501 §5.8	128	ok	ZUC MAC for 5G
5G	NEA4	NEA4 (AES-256) (candidate)	3GPP TS 33.501 Rel-17 study	256	unknown	AES-256 variant studied for 5G; not a deployed identifier — an unknown id must never be scored as safe
EOF
        ;;
    all) caud_table_gen gsm; caud_table_gen umts; caud_table_gen lte; caud_table_gen 5g ;;
    *) return 2 ;;
    esac
}

# Header for the table view.
caud_table_header() {
    printf 'gen\talgorithm\tfull_name\t3gpp_ref\tkey_bits\tstatus\tnote\n'
}

caud_cmd_table() {
    local g="${1:-all}"
    case "$g" in gsm|umts|lte|5g|all) ;; *) printf 'ERROR\tunknown generation: %s (want gsm|umts|lte|5g|all)\n' "$g" >&2; return 2 ;; esac
    caud_table_header
    caud_table_gen "$g"
}

# ── algorithm lookup ────────────────────────────────────────────────────
# Identifier -> full row. The lookup is by generation and by the identifier
# as it appears on the wire (an EEA/EIA bit value, an A5 number).
caud_lookup() {
    local gen="$1" alg="$2"
    caud_table_gen "$gen" | awk -F'\t' -v a="${alg^^}" '$2==a{print; found=1; exit} END{if(!found) exit 1}'
}

# The status word for a generation and an algorithm. This is the function
# the scorer depends on, so an unknown identifier exits non-zero and the
# caller must decide; it never silently returns "ok".
caud_status_of() {
    local gen="$1" alg="$2" row
    row=$(caud_lookup "$gen" "$alg") || { printf 'unknown\n'; return 1; }
    printf '%s\n' "$row" | cut -f6
}

caud_points_of() {
    case "${1:-unknown}" in
        null)    echo 100 ;;
        broken)  echo 60 ;;
        weak)    echo 30 ;;
        ok)      echo 0 ;;
        *)       echo 50 ;;   # unknown: scored as a risk, never as safe
    esac
}

caud_severity_of() {
    case "${1:-unknown}" in
        null)    echo "critical" ;;
        broken)  echo "high" ;;
        weak)    echo "medium" ;;
        ok)      echo "ok" ;;
        *)       echo "unknown" ;;
    esac
}

# ── scoring ─────────────────────────────────────────────────────────────
# Score <gen> <enc-alg> <int-alg>. Both identifiers may be given as the
# on-the-wire name (EEA0, NEA2, A5/1) or as a 4-bit value (0..15). The
# score is the worse of the two algorithms, because a session is only as
# protected as its weakest function: a session with NEA2 ciphering and
# NIA0 integrity can have every signalling message forged.
caud_cmd_score() {
    local gen="${1:-}" enc="${2:-}" int="${3:-}"
    [[ -n "$gen" && -n "$enc" && -n "$int" ]] || {
        printf 'ERROR\tusage: --score <gsm|umts|lte|5g> <enc-alg> <int-alg>\n' >&2; return 2; }
    case "${gen,,}" in gsm|umts|lte|5g) ;; *) printf 'ERROR\tunknown generation: %s\n' "$gen" >&2; return 2 ;; esac
    gen="${gen,,}"

    # Accept a bare numeric algorithm id and map it to the name, using the
    # 3GPP bit values. An id outside the table stays unnamed on purpose.
    local enc_name int_name
    enc_name=$(caud_name_of "$gen" "$enc" cipher)
    int_name=$(caud_name_of "$gen" "$int" integrity)

    local enc_row int_row enc_status int_status
    enc_row=$(caud_lookup "$gen" "$enc_name") || enc_row=""
    int_row=$(caud_lookup "$gen" "$int_name") || int_row=""

    if [[ -z "$enc_row" ]]; then enc_status="unknown"; else enc_status=$(cut -f6 <<<"$enc_row"); fi
    if [[ -z "$int_row" ]]; then int_status="unknown"; else int_status=$(cut -f6 <<<"$int_row"); fi
    # An integrity function that does not exist for the generation (GSM has
    # no separate integrity algorithm; A5 protects the air interface only)
    # is reported as not-applicable rather than as an unknown risk.
    if [[ "$gen" == "gsm" ]]; then
        int_status="ok"; int_name="n/a"
    fi

    local enc_rank int_rank rank
    enc_rank=$(caud_rank "$enc_status")
    int_rank=$(caud_rank "$int_status")
    rank=$(( enc_rank > int_rank ? enc_rank : int_rank ))

    local overall
    case "$rank" in
        4) overall="null" ;;
        3) overall="broken" ;;
        2) overall="weak" ;;
        1) overall="unknown" ;;
        *) overall="ok" ;;
    esac

    local reasoning
    reasoning=$(caud_reasoning "$gen" "$enc_name" "$enc_status" "$int_name" "$int_status")

    # Keys are namespaced with "score_" so this block can be appended to a
    # parsed Security Mode Command without overwriting the enc_alg/int_alg
    # the parser already reported. A collision here made every EPS/5G SMC
    # report its integrity algorithm as the ciphering algorithm.
    printf 'score_gen\t%s\n' "$gen"
    printf 'score_enc_alg\t%s\n' "$enc_name"
    printf 'score_enc_status\t%s\n' "$enc_status"
    printf 'score_enc_severity\t%s\n' "$(caud_severity_of "$enc_status")"
    printf 'score_int_alg\t%s\n' "$int_name"
    printf 'score_int_status\t%s\n' "$int_status"
    printf 'score_int_severity\t%s\n' "$(caud_severity_of "$int_status")"
    printf 'overall\t%s\n' "$overall"
    printf 'severity\t%s\n' "$(caud_severity_of "$overall")"
    printf 'score\t%s\n' "$(caud_points_of "$overall")"
    printf 'reasoning\t%s\n' "$reasoning"
    return 0
}

# Ordinal rank. IMPORTANT: a HIGHER rank is a WEAKER algorithm, because
# every caller compares "is this worse than that". ok=0 is the strongest
# and null=4 the weakest, so:
#   negotiated_rank > advertised_best_rank  -> downgrade
#   peer_rank < negotiated_rank             -> the peer was stronger
caud_rank() {
    case "${1:-unknown}" in
        ok)      echo 0 ;;
        unknown) echo 1 ;;
        weak)    echo 2 ;;
        broken)  echo 3 ;;
        null)    echo 4 ;;
        *)       echo 1 ;;   # anything unrecognised ranks as a risk
    esac
}

# Map a numeric algorithm identifier to its name for a generation. The bit
# values are the 3GPP ones: for EPS/5GS a 4-bit field where 0 is the null
# algorithm and 1..3 are the real ones. A value with no entry returns a
# marker the lookup will not match, which is how an unknown id survives to
# the scorer as unknown rather than being forced onto a known row.
caud_name_of() {
    # caud_name_of <gen> <id> [cipher|integrity]
    # The same numeric bit field means different algorithms depending on
    # which function it selects: for LTE, 2 is EEA2 in a ciphering field
    # and EIA2 in an integrity field. Mapping both through the ciphering
    # table reports an integrity algorithm under a ciphering name, which is
    # wrong in exactly the way that matters when the two differ.
    local gen="$1" v="${2^^}" kind="${3:-cipher}"
    local enc_prefix int_prefix
    case "$gen" in
        lte)  enc_prefix="EEA"; int_prefix="EIA" ;;
        5g)   enc_prefix="NEA"; int_prefix="NIA" ;;
        umts) enc_prefix="UEA"; int_prefix="UIA" ;;
        gsm)  enc_prefix="A5/"; int_prefix="n/a" ;;
        *)    enc_prefix="";    int_prefix="" ;;
    esac
    case "$v" in
        [0-9]|1[0-5])
            if [[ "$kind" == "integrity" && "$gen" != "gsm" ]]; then
                printf '%s%s\n' "$int_prefix" "$v"
            elif [[ "$gen" == "gsm" ]]; then
                printf 'A5/%s\n' "$v"
            else
                printf '%s%s\n' "$enc_prefix" "$v"
            fi
            ;;
        *) echo "$v" ;;
    esac
}

# The reasoning is per generation, because the same status word means
# different things: A5/1 being broken is a known-plaintext table attack,
# while EEA1 being "ok" is a statement about the absence of a published
# break rather than a proof of strength.
caud_reasoning() {
    local gen="$1" enc="$2" es="$3" int="$4" is="$5"
    local out=""
    case "$gen" in
        gsm)
            case "$es" in
                null)   out="2G: $enc is no ciphering. Every frame on the air interface is readable by any receiver in range, and a receive-only SDR is enough." ;;
                broken) out="2G: $enc is broken in practice. A5/1 falls to rainbow tables (2 TB, minutes) and A5/2 falls in real time on one PC and additionally acts as an oracle that recovers the A5/1 or A5/3 key of the same session." ;;
                weak)   out="2G: $enc is KASUMI. The 64-bit key and the published structural and related-key attacks leave far less margin than the design intended." ;;
                ok)     out="2G: $enc has no practical published break." ;;
                *)      out="2G: $enc is not a known GSM cipher identifier. An unrecognised algorithm must be treated as a risk, not as safe." ;;
            esac
            ;;
        umts)
            case "$es" in
                null)   out="3G: $enc disables ciphering. The Security Mode Command carries an explicit null-ciphering flag and the user plane follows it." ;;
                weak)   out="3G: $enc is KASUMI. The f8 core is the same as A5/3, so the Biham-Dunkelman-Keller family applies with a reduced margin." ;;
                ok)     out="3G: $enc has no practical published break; UEA2/UIA2 (SNOW 3G) is the accepted 3G baseline." ;;
                *)      out="3G: $enc is not a known UEA identifier." ;;
            esac
            ;;
        lte)
            case "$es" in
                null)   out="4G: $enc is null ciphering. The MME chose EEA0 in the NAS Security Mode Command; the RRC and user plane follow it and the traffic is in the clear." ;;
                ok)     out="4G: $enc is an accepted LTE cipher with no practical published break." ;;
                *)      out="4G: $enc is not one of the specified EEA identifiers (0-3). Treat it as a risk." ;;
            esac
            if [[ "$is" == "null" ]]; then
                out="$out Integrity is $int: with no MAC on NAS or RRC an attacker can forge and replay signalling even where ciphering is on."
            fi
            ;;
        5g)
            case "$es" in
                null)   out="5G: $enc is null ciphering; NR signalling and user plane are unprotected on the air interface." ;;
                ok)     out="5G: $enc is an accepted 5G cipher with no practical published break." ;;
                *)      out="5G: $enc is not one of the specified NEA identifiers (0-3). Treat it as a risk." ;;
            esac
            if [[ "$is" == "null" ]]; then
                out="$out Integrity is $int: 5G NAS and RRC carry no MAC, so signalling can be forged."
            fi
            ;;
    esac
    # A downgrade to null integrity is worth stating once more for the
    # generations that have a separate integrity function.
    if [[ "$is" == "unknown" && "$gen" != "gsm" ]]; then
        out="$out Integrity function $int is not recognised; an unknown identifier is scored as a risk."
    fi
    printf '%s\n' "$out"
}

# ── Security Mode Command parsing ───────────────────────────────────────
# Three encodings matter and each is handled on its own terms, because
# guessing the wrong one produces a confidently wrong algorithm.
#
#   NAS (4G/5G)  TS 24.301 §9.9.3.51 / TS 24.501 §9.9.3.53
#     EPD(1) sec-hdr(1) msg-type(1) NAS-key-set-id(1) NAS-cipher(4 bits)
#     NAS-integrity(4 bits) ... The cipher and integrity algorithms are
#     the low and high nibble of one octet respectively, or two separate
#     octets depending on the message variant.
#
#   RRC / S1AP  the selected algorithms appear as two 4-bit fields in the
#     SecurityModeCommand: cipheringAlgorithm and integrityProtectionAlgorithm,
#     each 0..3 for EEA/EIA.
#
#   GSM/DTAP   the Ciphering Mode Command carries the A5 algorithm number
#     in a single octet (TS 44.018 §9.1.9).
caud_cmd_parse_smc() {
    local h="${1:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --parse-smc <hex>\n' >&2; return 2; }
    h=$(printf '%s' "$h" | tr -d ' \t\r\n' | tr 'a-f' 'A-F')
    [[ "$h" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    (( ${#h} % 2 == 0 )) || { printf 'ERROR\thex string has an odd number of digits\n' >&2; return 2; }
    local n=$(( ${#h} / 2 ))
    (( n >= 3 )) || { printf 'ERROR\ttoo short (%d bytes) to be a Security Mode Command\n' "$n" >&2; return 1; }
    # The NAS SMC needs 5 octets (EPD, security header, message type,
    # key set id, algorithms). A shorter message is truncated, and reading
    # past its end aborts the arithmetic with "16#: invalid integer".
    # Refusing here is the difference between an error and a shell abort.
    caud_smc_min_len() {
        case "$1" in
            eps|5gs) printf '5\n' ;;
            *)       printf '3\n' ;;
        esac
    }

    printf 'raw\t%s\nbytes\t%s\n' "$h" "$n"

    # ── Classify by the outer protocol discriminator ────────────────────
    # $b0 is a DECIMAL value from $(( 16#.. )); comparing it against 0x
    # literals works in Bash arithmetic but not in a case pattern, where
    # "0x07" is the literal four-character string. The patterns below are
    # therefore the decimal equivalents of the protocol discriminators.
    local b0=$(( 16#${h:0:2} ))
    local gen="" msgtype="" enc_id="" int_id="" layout=""
    case "$b0" in
        7)
            # EPS NAS: EPD 0x07, then sec header, then message type.
            gen="lte"; layout="EPS-NAS"
            local sh=$(( 16#${h:2:2} ))
            local sec_proto=$(( (sh >> 4) & 0x0F ))
            msgtype=$(( 16#${h:4:2} ))
            printf 'protocol\ts1ap/nas-eps\n'
            printf 'layout\t%s\n' "$layout"
            printf 'security_header_type\t0x%X\n' "$sec_proto"
            if (( msgtype != 0x5D )); then
                printf 'msg_type\t0x%02X\n' "$msgtype"
                printf 'ERROR\tNAS message type 0x%02X is not a Security Mode Command (0x5D)\n' "$msgtype" >&2
                return 1
            fi
            printf 'msg_type\t0x%02X\nmsg_type_name\tSecurity Mode Command\n' "$msgtype"
            if (( n < 5 )); then
                printf 'ERROR\tEPS NAS Security Mode Command is %d bytes; 5 are required (EPD, sec header, msg type, key set id, algorithms)\n' "$n" >&2
                return 1
            fi
            # NAS-key-set-id, then the cipher/integrity nibbles.
            local ks=$(( 16#${h:6:2} ))
            printf 'nas_key_set_id\t%s\n' "$ks"
            printf 'nas_key_set\t%s\n' "$(( ks & 0x07 ))"
            printf 'tsc\t%s\n' "$(( (ks >> 3) & 0x01 ))"
            local alg=$(( 16#${h:8:2} ))
            # TS 24.301 §9.9.3.51: the selected NAS ciphering algorithm is
            # the low nibble and the integrity algorithm the high nibble of
            # the "Selected NAS security algorithms" octet (type 0x27 when
            # it appears as an IE, but in the fixed part it is this octet).
            enc_id=$(( alg & 0x0F ))
            int_id=$(( (alg >> 4) & 0x0F ))
            printf 'alg_octet\t0x%02X\n' "$alg"
            printf 'enc_id\t%s\nint_id\t%s\n' "$enc_id" "$int_id"
            ;;
        126)
            # 5G NAS: EPD 0x7E = 126 decimal, sec header, message type, then extended
            # protocol discriminator and the algorithm octet.
            gen="5g"; layout="5GS-NAS"
            local sh=$(( 16#${h:2:2} ))
            msgtype=$(( 16#${h:4:2} ))
            printf 'protocol\tngap/nas-5gs\n'
            printf 'layout\t%s\n' "$layout"
            printf 'security_header_type\t0x%X\n' "$(( (sh >> 4) & 0x0F ))"
            if (( msgtype != 0x5D )); then
                printf 'msg_type\t0x%02X\n' "$msgtype"
                printf 'ERROR\tNAS message type 0x%02X is not a Security Mode Command (0x5D)\n' "$msgtype" >&2
                return 1
            fi
            printf 'msg_type\t0x%02X\nmsg_type_name\tSecurity Mode Command\n' "$msgtype"
            if (( n < 5 )); then
                printf 'ERROR\t5GS NAS Security Mode Command is %d bytes; 5 are required\n' "$n" >&2
                return 1
            fi
            local ks=$(( 16#${h:6:2} ))
            printf 'nas_key_set_id\t%s\nnas_key_set\t%s\ntsc\t%s\n' \
                "$ks" "$(( ks & 0x07 ))" "$(( (ks >> 3) & 0x01 ))"
            local alg=$(( 16#${h:8:2} ))
            enc_id=$(( alg & 0x0F ))
            int_id=$(( (alg >> 4) & 0x0F ))
            printf 'alg_octet\t0x%02X\nenc_id\t%s\nint_id\t%s\n' "$alg" "$enc_id" "$int_id"
            ;;
        5|6|11|12|13)
            # GSM RR / DTAP protocol discriminators. Ciphering Mode Command
            # is RR message type 0x35.
            gen="gsm"; layout="GSM-RR"
            printf 'protocol\tgsm-rr\nlayout\t%s\n' "$layout"
            printf 'pdisc\t0x%02X\n' "$b0"
            msgtype=$(( 16#${h:2:2} ))
            printf 'msg_type\t0x%02X\n' "$msgtype"
            if (( msgtype != 0x35 )); then
                printf 'ERROR\tRR message type 0x%02X is not a Ciphering Mode Command (0x35)\n' "$msgtype" >&2
                return 1
            fi
            printf 'msg_type_name\tCiphering Mode Command\n'
            if (( n < 3 )); then
                printf 'ERROR\tRR Ciphering Mode Command is %d bytes; at least 3 are required\n' "$n" >&2
                return 1
            fi
            # TS 44.018 §9.1.9: octet 3 carries the ciphering mode settings.
            local cm=$(( 16#${h:4:2} ))
            printf 'cipher_mode_settings\t0x%02X\n' "$cm"
            printf 'sc\t%s\n' "$(( (cm >> 0) & 0x01 ))"
            # The A5 algorithm version is in the Cipher Mode Setting IE
            # (0x0A) which follows as TLV; when absent, A5/1 is the only
            # version that can be used.
            # Walk the IEs from byte 3 (after pdisc, msg type, cipher mode
            # settings). The Cipher Mode Setting IE is IEI 0x0A = A5/1,
            # 0x0B = A5/2, ... 0x0E = A5/7, which is a different encoding
            # from the "value & 0x07" used by the older TLV form: the IEI
            # itself carries the algorithm version.
            local off=3 a5=""
            while (( (off + 1) * 2 <= ${#h} )); do
                local iei=$(( 16#${h:$(( off * 2 )):2} ))
                if (( iei >= 0x0A && iei <= 0x11 )); then
                    a5=$(( iei - 0x0A + 1 ))
                    printf 'cipher_mode_setting_iei\t0x%02X\n' "$iei"
                    printf 'a5_version\t%s\n' "$a5"
                    break
                fi
                off=$(( off + 1 ))
            done
            if [[ -z "$a5" ]]; then
                printf 'a5_version\t1\n'
                printf 'note\tno Cipher Mode Setting IE (0x0A) present; A5/1 is the only version usable\n'
                a5=1
            fi
            enc_id="$a5"
            ;;
        *)
            printf 'ERROR\tprotocol discriminator 0x%02X is not a NAS or GSM RR Security/Ciphering Mode Command\n' "$b0" >&2
            return 1
            ;;
    esac

    # ── Resolve the identifiers against the table ───────────────────────
    local enc_name int_name
    enc_name=$(caud_name_of "$gen" "$enc_id" cipher)
    if [[ "$gen" == "gsm" ]]; then
        int_name="n/a"
    else
        int_name=$(caud_name_of "$gen" "$int_id" integrity)
    fi
    printf 'enc_alg\t%s\nint_alg\t%s\n' "$enc_name" "$int_name"

    if [[ "$gen" == "gsm" ]]; then
        caud_cmd_score gsm "$enc_name" "n/a"
    else
        caud_cmd_score "$gen" "$enc_id" "$int_id"
    fi
    return 0
}

# ── downgrade detection ─────────────────────────────────────────────────
# Where the session files live. Each row is:
#   session  gen  enc_alg  int_alg  ue_enc_caps  ue_int_caps  [plmn] [ts] [note]
# `caps` is a comma-separated list of algorithm names the UE advertised.
caud_sessions_init() {
    mkdir -p "$CAUD_DIR"
    [[ -f "$CAUD_SESSIONS" ]] || printf 'session\tgen\tenc_alg\tint_alg\tue_enc_caps\tue_int_caps\tplmn\tts\tnote\n' > "$CAUD_SESSIONS"
}

caud_session_count() {
    [[ -f "$CAUD_SESSIONS" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$CAUD_SESSIONS" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# Record a session. Refuses to record one whose algorithm is not in the
# table, so the store can never hold a silently-unknown algorithm scored as
# if it were fine.
caud_cmd_session() {
    local gen="${1:-}" enc="${2:-}" int="${3:-}" enc_caps="${4:-}" int_caps="${5:-}"
    [[ -n "$gen" && -n "$enc" && -n "$int" ]] || {
        printf 'ERROR\tusage: --session <gen> <enc> <int> [enc-caps] [int-caps]\n' >&2; return 2; }
    case "${gen,,}" in gsm|umts|lte|5g) ;; *) printf 'ERROR\tunknown generation: %s\n' "$gen" >&2; return 2 ;; esac
    caud_sessions_init
    # Session ids must be unique. A plain epoch second collides whenever two
    # sessions are recorded in the same second, which then makes the
    # per-session downgrade comparison compare a session against itself.
    # The counter below is derived from the store so it survives across
    # invocations.
    local ts; ts=$(date +%s)
    local n; n=$(caud_session_count)
    local sid; sid=$(printf 'sess_%s_%03d' "$ts" "$(( n + 1 ))")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$sid" "$(caud_sanitize "${gen,,}")" "$(caud_sanitize "${enc^^}")" \
        "$(caud_sanitize "${int^^}")" "$(caud_sanitize "${enc_caps:-}")" \
        "$(caud_sanitize "${int_caps:-}")" "$(caud_sanitize "${CAUD_PLMN:-}")" "$ts" \
        "$(caud_sanitize "${6:-}")" >> "$CAUD_SESSIONS"
    printf 'session\t%s\nrecorded\tyes\n' "$sid"
}

caud_cmd_clear() {
    caud_sessions_init
    printf 'session\tgen\tenc_alg\tint_alg\tue_enc_caps\tue_int_caps\tplmn\tts\tnote\n' > "$CAUD_SESSIONS"
    # Use declare -F, not command -v: a plain `ok` call fails when the
    # module is sourced into a shell with no helper defined.
    declare -F ok >/dev/null 2>&1 && ok "session store cleared" \
        || printf '[ok]   session store cleared\n' >&2
}

# Is $1 in the comma-separated capability list $2?
caud_cap_has() {
    local need="${1^^}" list="${2^^}"
    [[ -z "$list" ]] && return 1
    local x
    while IFS= read -r x; do
        x="${x// /}"
        [[ "${x^^}" == "$need" ]] && return 0
    done < <(caud_cap_list "$list")
    return 1
}

# Split a comma-separated capability list, one entry per line. Kept as its
# own function so no caller has to mutate IFS inside a loop that is itself
# reading a file — that mutation is how a capability list silently eats the
# remaining rows of the session store.
caud_cap_list() {
    # A trailing newline is required: `while read` drops a final line that
    # has no terminator, which silently loses the last advertised algorithm.
    printf '%s\n' "${1:-}" | tr ',' '\n'
}

# Rank an algorithm name by its table status, so "weaker" is a comparison
# of published strength rather than of identifier value.
caud_alg_rank() {
    local gen="$1" alg="$2"
    local st; st=$(caud_status_of "$gen" "$alg") || st="unknown"
    caud_rank "$st"
}

# --- downgrade-check ---
# Three independent downgrade tests, each reported with its own evidence:
#
#   1. negotiated vs the UE's advertised capability. If the UE offered a
#      strictly stronger algorithm and the network chose a weaker one, the
#      network downgraded. This is the attack an IMSI catcher performs and
#      it is visible whenever the capability list is captured.
#   2. negotiated vs the network's other sessions of the same generation.
#      A cell that negotiates A5/1 for one subscriber while every other
#      session on the same PLMN gets A5/3 is anomalous.
#   3. null or broken cipher anywhere. Not a "downgrade" in the strict
#      sense but the finding that matters most, so it is reported here too.
caud_cmd_downgrade_check() {
    caud_sessions_init
    local n; n=$(caud_session_count)
    if (( n == 0 )); then
        printf 'ERROR\tno sessions recorded; run --session or --sessions-load first\n' >&2
        return 1
    fi
    printf 'session\tgen\tfinding\tseverity\tdetail\n'
    local findings=0

    # Per-generation baseline: the strongest algorithm any session on that
    # generation negotiated, which is the network's own demonstrated
    # capability.
    local row
    # Every local is declared BEFORE the loop. A `local` executed inside a
    # `while read` body resets the shell's field splitting for the next
    # read, which silently merges the remaining columns of each row into
    # field 1 — the symptom is every "capability" reading as the session id.
    local enc_st int_st enc_rank int_rank best_rank best_alg cap r r2
    local peer_best peer_rank s2 g2 e2 sess gen enc int ecaps icaps line
    local p2 t2 n2
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        sess=$(caud_field "$line" 1)
        [[ "$sess" == "session" ]] && continue
        gen=$(caud_field  "$line" 2)
        enc=$(caud_field  "$line" 3)
        int=$(caud_field  "$line" 4)
        ecaps=$(caud_field "$line" 5)
        icaps=$(caud_field "$line" 6)
        [[ -z "$gen" || -z "$enc" ]] && continue
        enc_st=$(caud_status_of "$gen" "$enc") || enc_st="unknown"
        int_st="ok"
        [[ "$gen" != "gsm" ]] && { int_st=$(caud_status_of "$gen" "$int") || int_st="unknown"; }

        # 1. Null or broken, always a finding.
        if [[ "$enc_st" == "null" ]]; then
            printf '%s\t%s\tNULL_CIPHER\tcritical\t%s offers no ciphering; every frame on this bearer is readable\n' \
                "$(caud_sanitize "$sess")" "$(caud_sanitize "$gen")" "$(caud_sanitize "$enc")"
            findings=$(( findings + 1 ))
        elif [[ "$enc_st" == "broken" ]]; then
            printf '%s\t%s\tBROKEN_CIPHER\thigh\t%s is broken in practice\n' \
                "$(caud_sanitize "$sess")" "$(caud_sanitize "$gen")" "$(caud_sanitize "$enc")"
            findings=$(( findings + 1 ))
        elif [[ "$enc_st" == "unknown" ]]; then
            printf '%s\t%s\tUNKNOWN_CIPHER_TRAP\thigh\t%s is not a known identifier; scored as a risk, never as safe\n' \
                "$(caud_sanitize "$sess")" "$(caud_sanitize "$gen")" "$(caud_sanitize "$enc")"
            findings=$(( findings + 1 ))
        fi
        if [[ "$int_st" == "null" ]]; then
            printf '%s\t%s\tNULL_INTEGRITY\tcritical\t%s gives no MAC; signalling can be forged\n' \
                "$(caud_sanitize "$sess")" "$(caud_sanitize "$gen")" "$(caud_sanitize "$int")"
            findings=$(( findings + 1 ))
        fi

        # 2. Against the UE's advertised capability.
        if [[ -n "$ecaps" ]]; then
            best_rank=-1; best_alg=""
            # caud_cap_list splits on comma without touching IFS in the
            # caller, which would otherwise leak into the surrounding loop.
            while IFS= read -r cap; do
                cap="${cap// /}"
                [[ -z "$cap" ]] && continue
                r=$(caud_alg_rank "$gen" "$cap")
                # Lower rank = stronger, so keep the minimum.
                if (( best_rank < 0 || r < best_rank )); then best_rank=$r; best_alg="$cap"; fi
            done < <(caud_cap_list "$ecaps")
            enc_rank=$(caud_alg_rank "$gen" "$enc")
            # best_alg is the STRONGEST the UE offered, i.e. the LOWEST
            # rank. A downgrade is a negotiated rank strictly higher.
            if (( enc_rank > best_rank )); then
                printf '%s\t%s\tUE_CAPABILITY_DOWNGRADE\tcritical\tUE advertised %s but %s was negotiated, which is weaker\n' \
                    "$(caud_sanitize "$sess")" "$(caud_sanitize "$gen")" \
                    "$(caud_sanitize "$best_alg")" "$(caud_sanitize "$enc")"
                findings=$(( findings + 1 ))
            fi
        fi

        # 3. Against the network's own other sessions of this generation.
        # The baseline is the strongest algorithm any OTHER session of the
        # same generation negotiated. Sessions are matched by id, and the
        # id is unique per recording, so a session is never compared to
        # itself.
        peer_best=""; peer_rank=-1
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            s2=$(caud_field "$line" 1)
            [[ "$s2" == "session" || -z "$s2" ]] && continue
            [[ "$s2" == "$sess" ]] && continue
            g2=$(caud_field "$line" 2)
            [[ "$g2" != "$gen" ]] && continue
            e2=$(caud_field "$line" 3)
            r2=$(caud_alg_rank "$gen" "$e2")
            # Lower rank = stronger, so the peer baseline is the minimum.
            if (( peer_rank < 0 || r2 < peer_rank )); then peer_rank=$r2; peer_best="$e2"; fi
        done < "$CAUD_SESSIONS"
        enc_rank=$(caud_alg_rank "$gen" "$enc")
        # This session is weaker than another session of the same generation.
        if (( peer_rank >= 0 && enc_rank > peer_rank )); then
            printf '%s\t%s\tNETWORK_INCONSISTENCY\thigh\tthis session negotiated %s while another %s session on the same store negotiated %s\n' \
                "$(caud_sanitize "$sess")" "$(caud_sanitize "$gen")" \
                "$(caud_sanitize "$enc")" "$(caud_sanitize "$gen")" "$(caud_sanitize "$peer_best")"
            findings=$(( findings + 1 ))
        fi
    done < "$CAUD_SESSIONS"

    printf 'findings\t%s\n' "$findings"
    return 0
}

# Load sessions from a TSV of the documented shape.
caud_cmd_sessions_load() {
    local f="${1:-}"
    [[ -n "$f" ]] || { printf 'ERROR\tusage: --sessions-load <tsv>\n' >&2; return 2; }
    [[ -f "$f" ]] || { printf 'ERROR\tno such file: %s\n' "$f" >&2; return 1; }
    local rows; rows=$(tail -n +2 "$f" 2>/dev/null | grep -c . || true)
    (( rows > 0 )) || { printf 'ERROR\t%s has no session rows\n' "$f" >&2; return 1; }
    caud_sessions_init
    local added=0 rec gen enc int ecaps icaps plmn ts note sess
    while IFS= read -r rec; do
        [[ -z "$rec" ]] && continue
        [[ "$rec" == session$'\t'* ]] && continue
        # cut, not `read -r` with IFS: see the note on caud_field. A row
        # with an empty capability column would otherwise shift every later
        # value left and load a timestamp as an algorithm.
        sess=$(cut -f1 <<<"$rec"); gen=$(cut -f2 <<<"$rec")
        enc=$(cut -f3 <<<"$rec");  int=$(cut -f4 <<<"$rec")
        ecaps=$(cut -f5 <<<"$rec"); icaps=$(cut -f6 <<<"$rec")
        plmn=$(cut -f7 <<<"$rec"); ts=$(cut -f8 <<<"$rec"); note=$(cut -f9 <<<"$rec")
        [[ -z "$gen" || -z "$enc" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(caud_sanitize "${sess:-loaded}")" "$(caud_sanitize "${gen,,}")" \
            "$(caud_sanitize "${enc^^}")" "$(caud_sanitize "${int^^}")" \
            "$(caud_sanitize "$ecaps")" "$(caud_sanitize "$icaps")" \
            "$(caud_sanitize "$plmn")" "$(caud_sanitize "$ts")" \
            "$(caud_sanitize "$note")" >> "$CAUD_SESSIONS"
        added=$(( added + 1 ))
    done < "$f"
    printf 'loaded\t%s\ntotal\t%s\n' "$added" "$(caud_session_count)"
}

# ── capture-driven SMC extraction ───────────────────────────────────────
caud_pcap_available() {
    [[ -n "$CAUD_PCAP_MOD" && -f "$CAUD_PCAP_MOD" && -r "$CAUD_PCAP_MOD" ]]
}

caud_cmd_from_pcap() {
    local f="${1:-}" frame="${2:-1}"
    [[ -n "$f" ]] || { printf 'ERROR\tusage: --from-pcap <pcap> [frame]\n' >&2; return 2; }
    [[ -f "$f" ]] || { printf 'ERROR\tno such capture: %s\n' "$f" >&2; return 1; }
    caud_pcap_available || {
        printf 'ERROR\tmodule 21 not found at %s — cannot read a capture\n' "$CAUD_PCAP_MOD" >&2
        return 1
    }
    # Try the SCTP-carried NAS layers first, then the raw application bytes.
    local layer hex
    for layer in s1ap ngap app; do
        hex=$(bash "$CAUD_PCAP_MOD" --extract "$f" "$frame" "$layer" 2>/dev/null \
              | awk -F'\t' '$1=="extract" && $2=="hex"{print $3}')
        [[ -n "$hex" ]] && break
    done
    if [[ -z "$hex" ]]; then
        printf 'ERROR\tcould not extract a NAS layer from frame %s of %s\n' "$frame" "$f" >&2
        return 1
    fi
    printf 'source\t%s frame %s\n' "$(caud_sanitize "$f")" "$(caud_sanitize "$frame")"
    caud_cmd_parse_smc "$hex"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
caud_cli_status_tsv() {
    printf 'tables\tgsm,umts,lte,5g\n'
    printf 'gsm_algs\t%s\n'    "$(caud_table_gen gsm  | grep -c .)"
    printf 'umts_algs\t%s\n'   "$(caud_table_gen umts | grep -c .)"
    printf 'lte_algs\t%s\n'    "$(caud_table_gen lte  | grep -c .)"
    printf '5g_algs\t%s\n'     "$(caud_table_gen 5g   | grep -c .)"
    printf 'sessions\t%s\n'    "$(caud_session_count)"
    printf 'sessions_file\t%s\n' "$CAUD_SESSIONS"
    printf 'pcap_module\t%s\n' "$(caud_sanitize "$CAUD_PCAP_MOD")"
    printf 'pcap_available\t%s\n' "$(caud_pcap_available && echo present || echo missing)"
    printf 'dir\t%s\n'         "$CAUD_DIR"
}

# ── selftest — no capture, no radio, no root, no network ────────────────
caud_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() {
        printf '%s\n' "$1" | awk -F'\t' -v k="$2" '
            $2==k { print $3; found=1; exit }
            $1==k && NF>=2 { print $2; found=1; exit }
            END { if (!found) exit 1 }'
    }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export CAUD_DIR="$d/loot/cipher_audit"
    export CAUD_SESSIONS="$CAUD_DIR/sessions.tsv"
    mkdir -p "$CAUD_DIR"

    # ── 1. Table completeness: the exact expected counts ────────────────
    # 8 GSM A5 variants (A5/0..A5/7), 6 UMTS rows (3 UEA + 2 UIA + the
    # "no integrity" row that names the UIA0-equivalent state), 8 LTE rows
    # (4 EEA + 4 EIA), 9 5G rows (4 NEA + 4 NIA + the NEA4 candidate that
    # exists to prove an unknown id is not scored as safe).
    chk table-gsm-count  "$(caud_table_gen gsm  | grep -c .)" "8"
    chk table-umts-count "$(caud_table_gen umts | grep -c .)" "6"
    chk table-lte-count  "$(caud_table_gen lte  | grep -c .)" "8"
    chk table-5g-count   "$(caud_table_gen 5g   | grep -c .)" "9"
    chk table-all-count  "$(caud_table_gen all  | grep -c .)" "31"
    chk table-bad-gen-rc "$(caud_table_gen nosuch >/dev/null 2>&1; echo $?)" "2"

    # Every row has exactly 7 fields, so a consumer splitting on tab reads
    # the same columns for every generation.
    chk table-field-count "$(caud_table_gen all | awk -F'\t' 'NF!=7' | grep -c .)" "0"

    # The specific algorithms the task requires to be present.
    local a
    for a in "A5/0" "A5/1" "A5/2" "A5/3" "A5/4" "A5/5" "A5/6" "A5/7"; do
        chk "has-$a" "$(caud_table_gen gsm | awk -F'\t' -v a="$a" '$2==a{print $2}' | grep -c .)" "1"
    done
    for a in UEA0 UEA1 UEA2; do
        chk "has-$a" "$(caud_table_gen umts | awk -F'\t' -v a="$a" '$2==a{print $2}' | grep -c .)" "1"
    done
    for a in EEA0 EEA1 EEA2 EEA3 EIA0 EIA1 EIA2 EIA3; do
        chk "has-$a" "$(caud_table_gen lte | awk -F'\t' -v a="$a" '$2==a{print $2}' | grep -c .)" "1"
    done
    for a in NEA0 NEA1 NEA2 NEA3 NIA0 NIA1 NIA2 NIA3; do
        chk "has-$a" "$(caud_table_gen 5g | awk -F'\t' -v a="$a" '$2==a{print $2}' | grep -c .)" "1"
    done

    # ── 2. The null cipher in all four generations ──────────────────────
    chk null-gsm-a50  "$(caud_status_of gsm  A5/0)"  "null"
    chk null-umts-0   "$(caud_status_of umts UEA0)"  "null"
    chk null-lte-eea0 "$(caud_status_of lte  EEA0)"  "null"
    chk null-lte-eia0 "$(caud_status_of lte  EIA0)"  "null"
    chk null-5g-nea0  "$(caud_status_of 5g   NEA0)"  "null"
    chk null-5g-nia0  "$(caud_status_of 5g   NIA0)"  "null"
    chk sev-null      "$(caud_severity_of null)"     "critical"
    chk pts-null      "$(caud_points_of null)"       "100"

    # ── 3. Broken ciphers ───────────────────────────────────────────────
    chk broken-a51 "$(caud_status_of gsm A5/1)" "broken"
    chk broken-a52 "$(caud_status_of gsm A5/2)" "broken"
    chk sev-broken "$(caud_severity_of broken)" "high"
    chk pts-broken "$(caud_points_of broken)"   "60"
    chk a51-ref    "$(caud_lookup gsm A5/1 | cut -f4)" "3GPP TS 43.020 Annex 2"
    chk a52-name   "$(caud_lookup gsm A5/2 | cut -f3)" "A5/2"

    # ── 4. KASUMI is weak; AES-based is ok ──────────────────────────────
    chk kasumi-a53   "$(caud_status_of gsm  A5/3)" "weak"
    chk kasumi-uea1  "$(caud_status_of umts UEA1)" "weak"
    chk kasumi-uia1  "$(caud_status_of umts UIA1)" "weak"
    chk sev-weak     "$(caud_severity_of weak)"    "medium"
    chk pts-weak     "$(caud_points_of weak)"      "30"
    # A5/4-A5/7 are the stronger variants.
    chk a54-ok "$(caud_status_of gsm A5/4)" "ok"
    chk a55-ok "$(caud_status_of gsm A5/5)" "ok"
    chk a56-ok "$(caud_status_of gsm A5/6)" "ok"
    chk a57-ok "$(caud_status_of gsm A5/7)" "ok"
    chk a54-key "$(caud_lookup gsm A5/4 | cut -f5)" "128"
    # AES-based: EEA2/NEA2 and EEA3/NEA3 must be ok.
    chk ok-eea2 "$(caud_status_of lte EEA2)" "ok"
    chk ok-eea3 "$(caud_status_of lte EEA3)" "ok"
    chk ok-eia2 "$(caud_status_of lte EIA2)" "ok"
    chk ok-eia3 "$(caud_status_of lte EIA3)" "ok"
    chk ok-nea2 "$(caud_status_of 5g  NEA2)" "ok"
    chk ok-nea3 "$(caud_status_of 5g  NEA3)" "ok"
    chk ok-nia2 "$(caud_status_of 5g  NIA2)" "ok"
    chk ok-nia3 "$(caud_status_of 5g  NIA3)" "ok"
    chk eea2-name "$(caud_lookup lte EEA2 | cut -f3)" "EEA2 (AES-128-CTR)"
    chk nea2-name "$(caud_lookup 5g NEA2 | cut -f3)"  "NEA2 (AES-128-CTR)"
    chk ok-uea2 "$(caud_status_of umts UEA2)" "ok"
    chk ok-snow "$(caud_lookup lte EEA1 | cut -f3)" "EEA1 (SNOW 3G)"

    # ── 5. An unknown algorithm must be unknown, never ok ───────────────
    # This is the assertion that matters most: an unrecognised identifier
    # scored as safe is a false negative on exactly the case an attacker
    # would choose, and the toolkit would report "all clear".
    chk unknown-lte "$(caud_status_of lte EEA9 || true)" "unknown"
    chk unknown-5g  "$(caud_status_of 5g  NEA13 || true)" "unknown"
    chk unknown-gsm "$(caud_status_of gsm A5/9 || true)" "unknown"
    chk unknown-rc  "$(caud_status_of lte EEA9 >/dev/null 2>&1; echo $?)" "1"
    chk unknown-name "$(caud_name_of lte 9 cipher)" "EEA9"
    chk unknown-name-5g "$(caud_name_of 5g 13 cipher)" "NEA13"
    chk unknown-name-int "$(caud_name_of lte 9 integrity)" "EIA9"
    chk unknown-sev  "$(caud_severity_of unknown)" "unknown"
    chk unknown-rank "$(caud_rank unknown)" "1"
    # An unknown outranks ok and is not treated as safe.
    chk unknown-gt-ok "$([[ "$(caud_rank unknown)" -gt "$(caud_rank ok)" ]] && echo yes || echo no)" "yes"

    out=$(caud_cmd_score lte EEA9 EIA2)
    chk score-unknown-enc "$(fld "$out" score_enc_status)" "unknown"
    chk score-unknown-ovr "$(fld "$out" overall)"    "unknown"
    chk score-unknown-sev "$(fld "$out" severity)"   "unknown"
    # Crucially, the overall must not be "ok" and the points must not be 0.
    chk score-unknown-notok "$([[ "$(fld "$out" overall)" != "ok" ]] && echo yes || echo no)" "yes"
    chk score-unknown-pts   "$([[ "$(fld "$out" score)" -gt 0 ]] && echo yes || echo no)" "yes"
    # An unknown integrity algorithm on an otherwise fine cipher also lands
    # as a risk, not as a pass.
    out=$(caud_cmd_score lte EEA2 EIA9)
    chk score-unknown-int "$(fld "$out" score_int_status)" "unknown"
    chk score-unknown-int-notok "$([[ "$(fld "$out" overall)" != "ok" ]] && echo yes || echo no)" "yes"

    # ── 6. Scoring per generation ───────────────────────────────────────
    out=$(caud_cmd_score lte EEA0 EIA2)
    chk score-lte-null-cipher "$(fld "$out" overall)" "null"
    chk score-lte-null-sev    "$(fld "$out" severity)" "critical"
    chk score-lte-null-pts    "$(fld "$out" score)" "100"
    out=$(caud_cmd_score lte EEA2 EIA2)
    chk score-lte-ok    "$(fld "$out" overall)" "ok"
    chk score-lte-ok-pts "$(fld "$out" score)"  "0"
    # The worse of the two functions decides: good ciphering with null
    # integrity is still critical.
    out=$(caud_cmd_score lte EEA2 EIA0)
    chk score-lte-nullint       "$(fld "$out" overall)" "null"
    chk score-lte-nullint-pts   "$(fld "$out" score)"   "100"
    out=$(caud_cmd_score 5g NEA2 NIA0)
    chk score-5g-nullint "$(fld "$out" overall)" "null"
    out=$(caud_cmd_score gsm A5/1 n/a)
    chk score-gsm-broken "$(fld "$out" overall)" "broken"
    chk score-gsm-pts    "$(fld "$out" score)"   "60"
    out=$(caud_cmd_score gsm A5/3 n/a)
    chk score-gsm-kasumi "$(fld "$out" overall)" "weak"
    out=$(caud_cmd_score umts UEA2 UIA2)
    chk score-umts-ok "$(fld "$out" overall)" "ok"
    out=$(caud_cmd_score umts UEA1 UIA2)
    chk score-umts-kasumi "$(fld "$out" overall)" "weak"
    out=$(caud_cmd_score gsm A5/0 n/a)
    chk score-gsm-null "$(fld "$out" overall)" "null"
    # Numeric identifiers are accepted and mapped.
    out=$(caud_cmd_score lte 2 2)
    chk score-numeric "$(fld "$out" score_enc_status)" "ok"
    out=$(caud_cmd_score lte 0 0)
    chk score-numeric-null "$(fld "$out" overall)" "null"

    # ── 7. Scoring argument validation ─────────────────────────────────
    chk score-missing-rc "$(caud_cmd_score >/dev/null 2>&1; echo $?)" "2"
    chk score-partial-rc "$(caud_cmd_score lte EEA2 >/dev/null 2>&1; echo $?)" "2"
    chk score-badgen-rc  "$(caud_cmd_score wifi EEA2 EIA2 >/dev/null 2>&1; echo $?)" "2"

    # ── 8. Security Mode Command parsing ────────────────────────────────
    # EPS NAS SMC: EPD 0x07, sec header 0x00, msg type 0x5D,
    # NAS key set id 0x01, selected algorithms 0x22 -> enc=2 (EEA2),
    # int=2 (EIA2).
    out=$(caud_cmd_parse_smc "07005D0122"); rc=$?
    chk smc-rc       "$rc" "0"
    chk smc-proto    "$(fld "$out" protocol)"        "s1ap/nas-eps"
    chk smc-msgtype  "$(fld "$out" msg_type_name)"   "Security Mode Command"
    chk smc-keyset   "$(fld "$out" nas_key_set)"     "1"
    chk smc-encid    "$(fld "$out" enc_id)"          "2"
    chk smc-intid    "$(fld "$out" int_id)"          "2"
    chk smc-enc      "$(fld "$out" enc_alg)"         "EEA2"
    chk smc-int      "$(fld "$out" int_alg)"         "EIA2"
    chk smc-overall  "$(fld "$out" overall)"         "ok"
    chk smc-score    "$(fld "$out" score)"           "0"
    # The same message with EEA0 selected: enc=0, int=2 -> 0x20.
    out=$(caud_cmd_parse_smc "07005D0120")
    chk smc-null-enc "$(fld "$out" enc_alg)"  "EEA0"
    chk smc-null-ovr "$(fld "$out" overall)"  "null"
    chk smc-null-sev "$(fld "$out" severity)" "critical"
    # EIA0 with EEA2: enc=2, int=0 -> 0x02.
    out=$(caud_cmd_parse_smc "07005D0102")
    chk smc-null-int "$(fld "$out" int_alg)" "EIA0"
    chk smc-null-int-ovr "$(fld "$out" overall)" "null"
    # An algorithm id in the reserved range must be unknown, not ok.
    out=$(caud_cmd_parse_smc "07005D01E7")
    chk smc-unk-enc "$(fld "$out" enc_id)"   "7"
    chk smc-unk-st  "$(fld "$out" score_enc_status)" "unknown"
    chk smc-unk-ovr "$(fld "$out" overall)"  "unknown"
    chk smc-unk-pts "$([[ "$(fld "$out" score)" -gt 0 ]] && echo yes || echo no)" "yes"
    # TSC bit: key set id 0x09 -> key set 1, TSC 1.
    out=$(caud_cmd_parse_smc "07005D0922")
    chk smc-tsc     "$(fld "$out" tsc)"     "1"
    chk smc-keyset2 "$(fld "$out" nas_key_set)" "1"
    # 5G NAS SMC: EPD 0x7E.
    out=$(caud_cmd_parse_smc "7E005D0122")
    chk smc-5g-proto "$(fld "$out" protocol)" "ngap/nas-5gs"
    chk smc-5g-enc   "$(fld "$out" enc_alg)"  "NEA2"
    chk smc-5g-int   "$(fld "$out" int_alg)"  "NIA2"
    chk smc-5g-ovr   "$(fld "$out" overall)"  "ok"
    out=$(caud_cmd_parse_smc "7E005D0120")
    chk smc-5g-null  "$(fld "$out" overall)"  "null"
    # GSM RR Ciphering Mode Command: pdisc 0x06, msg type 0x35, cipher mode
    # settings 0x01, then the Cipher Mode Setting IE. TS 44.018 §10.5.2.10
    # codes the A5 version in the IEI itself: 0x0A=A5/1 .. 0x10=A5/7, so
    # 0x0C selects A5/3.
    out=$(caud_cmd_parse_smc "0635010C")
    chk smc-gsm-proto "$(fld "$out" protocol)" "gsm-rr"
    chk smc-gsm-msg   "$(fld "$out" msg_type_name)" "Ciphering Mode Command"
    chk smc-gsm-a5    "$(fld "$out" a5_version)" "3"
    chk smc-gsm-enc   "$(fld "$out" enc_alg)"  "A5/3"
    chk smc-gsm-ovr   "$(fld "$out" overall)"  "weak"
    # No Cipher Mode Setting IE: A5/1 is the only usable version.
    out=$(caud_cmd_parse_smc "063501")
    chk smc-gsm-default-a5  "$(fld "$out" a5_version)" "1"
    chk smc-gsm-default-enc "$(fld "$out" enc_alg)"    "A5/1"
    chk smc-gsm-default-ovr "$(fld "$out" overall)"    "broken"
    # A5/2 (IEI 0x0B) is broken; A5/4 (IEI 0x0D) is the 128-bit variant.
    out=$(caud_cmd_parse_smc "0635010B")
    chk smc-gsm-a52     "$(fld "$out" enc_alg)" "A5/2"
    chk smc-gsm-a52-ovr "$(fld "$out" overall)" "broken"
    out=$(caud_cmd_parse_smc "0635010D")
    chk smc-gsm-a54     "$(fld "$out" enc_alg)" "A5/4"
    chk smc-gsm-a54-ovr "$(fld "$out" overall)" "ok"
    # A Cipher Mode Setting IE that names a version outside the table must
    # be unknown, never ok.
    out=$(caud_cmd_parse_smc "06350120")
    chk smc-gsm-unk-ovr "$(fld "$out" overall)" "broken"

    # Wrong message types must fail, not be silently scored.
    chk smc-bad-msgtype "$(caud_cmd_parse_smc "07005C0122" >/dev/null 2>&1; echo $?)" "1"
    chk smc-bad-pdisc   "$(caud_cmd_parse_smc "99005D0122" >/dev/null 2>&1; echo $?)" "1"
    chk smc-not-hex     "$(caud_cmd_parse_smc "ZZZZZZ" >/dev/null 2>&1; echo $?)" "2"
    # A 4-byte EPS NAS SMC is complete (no algorithm octet is optional):
    # 5 bytes are required, so 4 must fail rather than abort the shell.
    chk smc-4byte       "$(caud_cmd_parse_smc "07005D01" >/dev/null 2>&1; echo $?)" "1"
    chk smc-trunc-alg   "$(caud_cmd_parse_smc "07005D" >/dev/null 2>&1; echo $?)" "1"
    chk smc-trunc-3     "$(caud_cmd_parse_smc "07005D0102" >/dev/null 2>&1; echo $?)" "0"
    # The truncation error must be a clean message, never a shell abort.
    chk smc-trunc-msg   "$(caud_cmd_parse_smc "07005D" 2>&1 | grep -c 'bytes; 5 are required\|5 are required')" "1"
    chk smc-trunc-no-abort "$(caud_cmd_parse_smc "07005D" 2>&1 | grep -c 'invalid integer')" "0"
    chk smc-short       "$(caud_cmd_parse_smc "0700" >/dev/null 2>&1; echo $?)" "1"
    chk smc-missing-rc  "$(caud_cmd_parse_smc >/dev/null 2>&1; echo $?)" "2"

    # ── 9. Downgrade detection ──────────────────────────────────────────
    caud_cmd_clear >/dev/null 2>&1
    # A UE that advertised EEA3 and EEA2 but was given EEA0: a downgrade.
    caud_cmd_session lte EEA0 EIA2 "EEA3,EEA2,EIA2" "EIA2" >/dev/null
    out=$(caud_cmd_downgrade_check); rc=$?
    chk dg-rc        "$rc" "0"
    chk dg-null      "$(printf '%s\n' "$out" | grep -c 'NULL_CIPHER')" "1"
    chk dg-uecap     "$(printf '%s\n' "$out" | grep -c 'UE_CAPABILITY_DOWNGRADE')" "1"
    chk dg-uecap-detail "$(printf '%s\n' "$out" | grep -c 'UE advertised EEA3')" "1"
    chk dg-findings  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="findings"{print $2}')" "2"

    # A row with EMPTY capability columns must not shift its later fields:
    # this is the case `while IFS=$'\t' read` gets wrong, and the symptom is
    # the timestamp being read as the advertised capability list.
    caud_cmd_clear >/dev/null 2>&1
    caud_cmd_session lte EEA2 EIA2 "" "" >/dev/null
    out=$(caud_cmd_downgrade_check)
    chk emptycap-no-phantom "$(printf '%s\n' "$out" | grep -c 'DOWNGRADE')" "0"
    chk emptycap-no-findings "$(printf '%s\n' "$out" | awk -F'\t' '$1=="findings"{print $2}')" "0"
    chk field-empty   "$(caud_field "$(printf 'a\tb\t\t\td')" 3)" ""
    chk field-last    "$(caud_field "$(printf 'a\tb\t\t\td')" 5)" "d"
    chk field-nf      "$(caud_nf "$(printf 'a\tb\t\t\td')")" "5"

    # A session that matches the UE's best capability is not a downgrade.
    caud_cmd_clear >/dev/null 2>&1
    caud_cmd_session lte EEA3 EIA3 "EEA3,EEA2" "EIA3,EIA2" >/dev/null
    out=$(caud_cmd_downgrade_check)
    chk dg-clean-empty "$(printf '%s\n' "$out" | awk -F'\t' '$1=="findings"{print $2}')" "0"
    chk dg-clean-none  "$(printf '%s\n' "$out" | grep -c 'DOWNGRADE\|NULL_\|BROKEN_')" "0"

    # Neutral capability order (EEA0 offered first) must not trigger a
    # false downgrade: the comparison is by strength, not by list order.
    caud_cmd_clear >/dev/null 2>&1
    caud_cmd_session lte EEA2 EIA2 "EEA0,EEA2" "EIA0,EIA2" >/dev/null
    out=$(caud_cmd_downgrade_check)
    chk dg-order-safe "$(printf '%s\n' "$out" | grep -c 'UE_CAPABILITY_DOWNGRADE')" "0"

    # Network inconsistency: one session on a broken cipher while another
    # on the same generation got a strong one.
    caud_cmd_clear >/dev/null 2>&1
    caud_cmd_session gsm A5/3 "n/a" "" "" >/dev/null
    caud_cmd_session gsm A5/1 "n/a" "" "" >/dev/null
    out=$(caud_cmd_downgrade_check)
    chk dg-net-incons "$(printf '%s\n' "$out" | grep -c 'NETWORK_INCONSISTENCY')" "1"
    chk dg-net-broken "$(printf '%s\n' "$out" | grep -c 'BROKEN_CIPHER')" "1"
    # The stronger session must not itself be flagged as inconsistent.
    chk dg-net-strong-not "$(printf '%s\n' "$out" | grep -c 'NETWORK_INCONSISTENCY')" "1"
    # The strong session (A5/3) must not be the one flagged.
    chk dg-net-flagged-is-weak "$(printf '%s\n' "$out" | awk -F'\t' '$3=="NETWORK_INCONSISTENCY"{print $1}' | grep -c 'sess_')" "1"
    chk dg-net-strong-alg "$(printf '%s\n' "$out" | awk -F'\t' '$3=="NETWORK_INCONSISTENCY"{print $5}' | grep -c 'negotiated A5/1')" "1"

    # An unknown cipher in a session is a finding, not a pass.
    caud_cmd_clear >/dev/null 2>&1
    caud_cmd_session lte EEA9 EIA2 "" "" >/dev/null
    out=$(caud_cmd_downgrade_check)
    chk dg-unknown "$(printf '%s\n' "$out" | grep -c 'UNKNOWN_CIPHER_TRAP')" "1"

    # Empty store is an error, not an empty success.
    caud_cmd_clear >/dev/null 2>&1
    chk dg-empty-rc "$(caud_cmd_downgrade_check >/dev/null 2>&1; echo $?)" "1"

    # ── 10. Session store and loading ───────────────────────────────────
    caud_cmd_clear >/dev/null 2>&1
    chk session-count-0 "$(caud_session_count)" "0"
    caud_cmd_session lte EEA2 EIA2 >/dev/null
    chk session-count-1 "$(caud_session_count)" "1"
    local sf="$d/sessions.tsv"
    {
        printf 'session\tgen\tenc_alg\tint_alg\tue_enc_caps\tue_int_caps\tplmn\tts\tnote\n'
        printf 'a\tlte\tEEA0\tEIA2\tEEA3,EEA2\tEIA2\t262-01\t1700000000\tcaptured\n'
        printf 'b\tgsm\tA5/1\tn/a\t\t\t262-01\t1700000060\tcaptured\n'
    } > "$sf"
    caud_cmd_clear >/dev/null 2>&1
    out=$(caud_cmd_sessions_load "$sf"); rc=$?
    chk load-rc    "$rc" "0"
    chk load-added "$(fld "$out" loaded)" "2"
    chk load-total "$(caud_session_count)" "2"
    out=$(caud_cmd_downgrade_check)
    chk load-dg-null "$(printf '%s\n' "$out" | grep -c 'NULL_CIPHER')" "1"
    chk load-dg-brok "$(printf '%s\n' "$out" | grep -c 'BROKEN_CIPHER')" "1"
    chk load-bad-rc  "$(caud_cmd_sessions_load /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"
    chk load-miss-rc "$(caud_cmd_sessions_load >/dev/null 2>&1; echo $?)" "2"
    local ef="$d/empty.tsv"
    printf 'session\tgen\tenc_alg\n' > "$ef"
    chk load-empty-rc "$(caud_cmd_sessions_load "$ef" >/dev/null 2>&1; echo $?)" "1"

    # ── 11. Table edge cases ────────────────────────────────────────────
    chk lookup-missing-rc "$(caud_lookup lte NOPE >/dev/null 2>&1; echo $?)" "1"
    chk name-of-number    "$(caud_name_of lte 3 cipher)" "EEA3"
    chk name-of-number-5g "$(caud_name_of 5g 0 cipher)"  "NEA0"
    chk name-of-name      "$(caud_name_of lte EEA2 cipher)" "EEA2"
    chk name-of-reserved  "$(caud_name_of lte 12 cipher)" "EEA12"
    # The integrity mapping must differ from the ciphering mapping.
    chk name-of-int-lte "$(caud_name_of lte 2 integrity)" "EIA2"
    chk name-of-int-5g  "$(caud_name_of 5g 2 integrity)"  "NIA2"
    chk name-of-int-umts "$(caud_name_of umts 1 integrity)" "UIA1"
    chk name-of-enc-lte "$(caud_name_of lte 2 cipher)"    "EEA2"
    chk name-of-int-differs "$([[ "$(caud_name_of lte 2 integrity)" != "$(caud_name_of lte 2 cipher)" ]] && echo yes || echo no)" "yes"
    # A reserved numeric id must not resolve in the table.
    chk reserved-not-found "$(caud_lookup lte EEA12 >/dev/null 2>&1; echo $?)" "1"
    # The LAST entry of a capability list must be found: a trailing-newline
    # bug makes `while read` drop it, which is exactly how a downgrade from
    # the UE's best advertised algorithm goes undetected.
    chk cap-has-first "$(caud_cap_has EEA3 "EEA3,EEA2" ; echo $?)" "0"
    chk cap-has-last  "$(caud_cap_has EEA2 "EEA3,EEA2" ; echo $?)" "0"
    chk cap-has-single "$(caud_cap_has EEA3 "EEA3" ; echo $?)" "0"
    chk cap-has-not   "$(caud_cap_has EEA1 "EEA3,EEA2" ; echo $?)" "1"
    chk cap-empty     "$(caud_cap_has EEA2 "" ; echo $?)" "1"
    chk cap-list-count "$(caud_cap_list "EEA3,EEA2,EEA1" | grep -c .)" "3"
    # Higher rank = weaker algorithm. This ordering is what every
    # downgrade comparison depends on, so it is asserted explicitly.
    chk alg-rank-null "$(caud_alg_rank lte EEA0)" "4"
    chk alg-rank-brok "$(caud_alg_rank gsm A5/1)" "3"
    chk alg-rank-weak "$(caud_alg_rank gsm A5/3)" "2"
    chk alg-rank-unk  "$(caud_alg_rank lte EEA9 || true)" "1"
    chk alg-rank-ok   "$(caud_alg_rank lte EEA2)" "0"
    chk alg-rank-order "$([[ "$(caud_alg_rank lte EEA0)" -gt "$(caud_alg_rank lte EEA2)" ]] && echo yes || echo no)" "yes"
    chk alg-rank-ok-strongest "$([[ "$(caud_alg_rank lte EEA2)" -lt "$(caud_alg_rank lte EEA9 || echo 1)" ]] && echo yes || echo no)" "yes"

    # ── 12. Capture integration is optional ─────────────────────────────
    local saved="$CAUD_PCAP_MOD"
    CAUD_PCAP_MOD="$d/nope.sh"
    chk pcap-missing-avail "$(caud_pcap_available; echo $?)" "1"
    out=$(caud_cmd_from_pcap "$d/fake.pcap" 2>&1); rc=$?
    chk pcap-missing-rc  "$rc" "1"
    # Either message is correct — module missing, or file missing when the
    # module check is not the first gate. What matters is that it is a
    # clean ERROR and not a stack of shell arithmetic failures.
    chk pcap-missing-msg "$(printf '%s\n' "$out" | grep -cE 'module 17 not found|no such capture')" "1"
    chk pcap-missing-clean "$(printf '%s\n' "$out" | grep -c 'invalid integer\|command not found')" "0"
    chk pcap-missing-usage "$(caud_cmd_from_pcap >/dev/null 2>&1; echo $?)" "2"
    CAUD_PCAP_MOD="$saved"
    if [[ -f "$CAUD_PCAP_MOD" ]]; then
        chk pcap-present "$(caud_pcap_available; echo $?)" "0"
    else
        chk pcap-present "$(caud_pcap_available; echo $?)" "1"
    fi

    # ── 13. CLI dispatch and validation ─────────────────────────────────
    chk dispatch-unknown "$(caud_cli_main --nonsense >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-empty   "$(caud_cli_main >/dev/null 2>&1; echo $?)" "2"
    chk table-bad-rc     "$(caud_cmd_table nosuch >/dev/null 2>&1; echo $?)" "2"
    chk score-badgen     "$(caud_cmd_score nope EEA2 EIA2 >/dev/null 2>&1; echo $?)" "2"
    out=$(caud_cmd_table all | head -n1)
    chk table-header "$out" "gen	algorithm	full_name	3gpp_ref	key_bits	status	note"

    # ── 14. Sanitisation ────────────────────────────────────────────────
    local evil
    evil=$(caud_sanitize $'evil\tname\r\nsecond')
    chk sanitize-no-tabs "$(printf '%s' "$evil" | tr -d '\t\r\n' | wc -c | tr -d ' ')" \
        "$(printf '%s' "$evil" | wc -c | tr -d ' ')"
    caud_cmd_clear >/dev/null 2>&1
    caud_cmd_session lte EEA2 EIA2 >/dev/null
    # A freshly recorded session row has exactly the 9 documented columns,
    # including the empty capability columns (which is the layout `read`
    # would get wrong).
    chk session-row-cols "$(tail -n1 "$CAUD_SESSIONS" | awk -F'\t' '{print NF}')" "9"
    chk session-row-gen  "$(tail -n1 "$CAUD_SESSIONS" | awk -F'\t' '{print $2}')" "lte"
    chk session-row-enc  "$(tail -n1 "$CAUD_SESSIONS" | awk -F'\t' '{print $3}')" "EEA2"
    chk session-row-caps-empty "$(tail -n1 "$CAUD_SESSIONS" | awk -F'\t' '{print ($5=="" && $6=="")?"yes":"no"}')" "yes"
    # A note carrying a tab is sanitised on the way in, so it cannot add a
    # column either.
    caud_cmd_clear >/dev/null 2>&1
    caud_cmd_session lte EEA2 EIA2 "" "" $'note\twith\ttabs' >/dev/null
    chk session-row-tab-note "$(tail -n1 "$CAUD_SESSIONS" | awk -F'\t' '{print NF}')" "9"
    chk session-row-tab-sanitised "$(tail -n1 "$CAUD_SESSIONS" | grep -c 'note with tabs')" "1"

    # ── 15. Status TSV contract ─────────────────────────────────────────
    out=$(caud_cli_status_tsv)
    chk status-gsm   "$(fld "$out" gsm_algs)"  "8"
    chk status-umts  "$(fld "$out" umts_algs)" "6"
    chk status-lte   "$(fld "$out" lte_algs)"  "8"
    chk status-5g    "$(fld "$out" 5g_algs)"   "9"
    chk status-dir   "$(fld "$out" dir)"       "$CAUD_DIR"
    chk status-file  "$(fld "$out" sessions_file)" "$CAUD_SESSIONS"
    chk status-sess  "$(fld "$out" sessions)"  "1"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
caud_menu() {
    local c p g
    while true; do
        banner
        echo -e "  ${C_MAG}=== cipher audit ===${C_RESET}"
        echo -e "  sessions: ${C_GRN}$(caud_session_count)${C_RESET}"
        echo -e "  tables:   ${C_DIM}gsm 8 / umts 6 / lte 8 / 5g 9${C_RESET}"
        echo -e "  loot:     ${C_DIM}$CAUD_DIR${C_RESET}\n"
        cat << 'M'
  [1]  full algorithm table (all generations)
  [2]  table for one generation
  [3]  parse a Security Mode Command
  [4]  score a session
  [5]  record a session
  [6]  load sessions from a TSV
  [7]  downgrade check
  [8]  extract an SMC from a capture (needs module 17)
  [9]  clear the session store
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) caud_cmd_table all | column -t -s$'\t' 2>/dev/null || caud_cmd_table all
               read -rp "  press enter " _ ;;
            2) read -rp "  generation (gsm|umts|lte|5g)> " g
               caud_cmd_table "$g" | column -t -s$'\t' 2>/dev/null || caud_cmd_table "$g"
               read -rp "  press enter " _ ;;
            3) read -rp "  SMC hex> " p
               caud_cmd_parse_smc "$p" | column -t -s$'\t' 2>/dev/null || caud_cmd_parse_smc "$p"
               read -rp "  press enter " _ ;;
            4) read -rp "  generation (gsm|umts|lte|5g)> " g
               read -rp "  enc alg> " e; read -rp "  int alg> " i
               caud_cmd_score "$g" "$e" "$i" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            5) read -rp "  generation (gsm|umts|lte|5g)> " g
               read -rp "  enc alg> " e; read -rp "  int alg> " i
               read -rp "  UE enc caps (comma separated)> " ec
               read -rp "  UE int caps (comma separated)> " ic
               caud_cmd_session "$g" "$e" "$i" "$ec" "$ic"
               read -rp "  press enter " _ ;;
            6) read -rp "  sessions TSV> " p
               caud_cmd_sessions_load "$p"
               read -rp "  press enter " _ ;;
            7) caud_cmd_downgrade_check | column -t -s$'\t' 2>/dev/null || caud_cmd_downgrade_check
               read -rp "  press enter " _ ;;
            8) read -rp "  pcap path> " p; read -rp "  frame> " f
               caud_cmd_from_pcap "$p" "$f" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            9) caud_cmd_clear; sleep 1 ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
caud_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      caud_cli_status_tsv ;;
        --table)           caud_cmd_table "${1:-all}" ;;
        --parse-smc)       caud_cmd_parse_smc "${1:-}" ;;
        --score)           caud_cmd_score "${1:-}" "${2:-}" "${3:-}" ;;
        --downgrade-check) caud_cmd_downgrade_check ;;
        --session)         caud_cmd_session "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --sessions-load)   caud_cmd_sessions_load "${1:-}" ;;
        --from-pcap)       caud_cmd_from_pcap "${1:-}" "${2:-1}" ;;
        --clear)           caud_cmd_clear ;;
        --selftest)        caud_selftest ;;
        --menu)            caud_menu ;;
        *)
            cat >&2 <<EOF
Cipher Audit — algorithm tables, Security Mode Command parsing, scoring

Usage: $0 COMMAND
  --status-tsv                     table and store state as TSV
  --table [gsm|umts|lte|5g|all]    the algorithm table with 3GPP references
  --parse-smc <hex>                Security Mode Command -> negotiated algs
  --score <gen> <enc-alg> <int-alg>
                                   score a session; alg may be a name or a
                                   0..15 identifier
  --downgrade-check                find downgrades in the session store
  --session <gen> <enc> <int> [enc-caps] [int-caps]
                                   record a session, optionally with the
                                   UE's advertised capabilities
  --sessions-load <tsv>            load sessions from a TSV
  --from-pcap <pcap> [frame]       pull an SMC out of a capture (module 17)
  --clear                          empty the session store
  --selftest                       verify tables, scoring and parsing
  --menu                           interactive menu

Scoring: the worse of the ciphering and integrity algorithms decides.
An algorithm identifier that is not in the table is scored UNKNOWN with a
non-zero risk weight. It is never scored as safe.
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
    caud_cli_main "$@"
fi
