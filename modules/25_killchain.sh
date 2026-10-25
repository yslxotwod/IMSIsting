#!/usr/bin/env bash
# Cellular killchain — chain the other modules into an ordered, recorded run.
#
# A chain is an ordered list of steps. Each step names a module, a verb and
# that verb's arguments, plus whether it needs hardware. Steps run in order;
# the run is recorded to loot/killchain/ with a per-step result.
#
# Execution rules this module enforces:
#   * a step whose module is missing is SKIP, never PASS
#   * a step whose hardware is absent is SKIP with the reason, never PASS
#   * a failed step stops the chain unless --keep-going, and the overall exit
#     is non-zero
#   * --dry-run resolves and prints the steps and writes no run report
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
: "${MODULES_DIR:=$IMSISTING_ROOT/modules}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null

MOD_TMP="$TMP_DIR/killchain"
KCHN_DIR="$LOOT_DIR/killchain"
KCHN_RUNS_DIR="$KCHN_DIR/runs"
KCHN_CHAINS_DIR="$KCHN_DIR/chains"
KCHN_STATE_DIR="${KCHN_STATE_DIR:-$STATE_DIR/killchain}"
KCHN_ACTIVE_STATE="$KCHN_STATE_DIR/active.tsv"
KCHN_PAUSE_FILE="$KCHN_STATE_DIR/pause.request"
KCHN_PROGRESS_FILE="$KCHN_STATE_DIR/progress.tsv"
mkdir -p "$MOD_TMP" "$KCHN_DIR" "$KCHN_RUNS_DIR" "$KCHN_CHAINS_DIR" "$KCHN_STATE_DIR" 2>/dev/null

KCHN_VERSION="1.1"

# The logging helpers live in the launcher, but this module must run
# standalone (and be sourceable by a test harness) without them. The
# `declare -F` form is mandatory: /usr/bin/info exists on most systems, so
# `command -v info` would find texinfo instead of the shim.
declare -F banner >/dev/null 2>&1 || banner() { :; }
declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }

# ── sanitisation ────────────────────────────────────────────────────────
kchn_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# Split a shell-ish argument string into words. The chain format stores a
# verb's arguments as one field, so quoting has to survive the round trip.
kchn_split_args() {
    local s="${1:-}"
    # shellcheck disable=SC2206
    KCHN_ARGV=()
    [[ -z "$s" || "$s" == "-" ]] && return 0
    eval "KCHN_ARGV=($s)" 2>/dev/null || KCHN_ARGV=()
    return 0
}

# ── chain file format ───────────────────────────────────────────────────
# A chain is a TSV:  step  module  verb  args  hardware  description
#   step        integer, ascending from 1
#   module      the module id, e.g. 02_cell_recon (no .sh suffix required)
#   verb        the module verb, e.g. --scan
#   args        the verb's arguments, shell-quoted; "-" for none
#   hardware    yes | no — does this step need a radio or a testbed
#   description free text, sanitised on every write
# Lines starting with # are comments and are dropped on parse.
kchn_chain_header() {
    printf 'step\tmodule\tverb\targs\thardware\tdescription\n'
}

# ── built-in chains ─────────────────────────────────────────────────────
kchn_builtin_chain() {
    case "${1:-}" in
        survey)
            kchn_chain_header
            printf '1\t02_cell_recon\t--scan\tgsm GSM900\tyes\tGSM survey on 900 MHz\n'
            printf '2\t02_cell_recon\t--list-tsv\t-\tno\tread the surveyed cells back\n'
            printf '3\t02_cell_recon\t--export\t-\tno\twrite the survey into loot\n'
            ;;
        passive-audit)
            kchn_chain_header
            printf '1\t17_pcap_analysis\t--hierarchy\t-\tno\tprotocol hierarchy of the capture\n'
            printf '2\t17_pcap_analysis\t--identities\t-\tno\tharvest identities from the capture\n'
            printf '3\t18_imsi_exposure\t--audit\t-\tno\tcorrelate identities across the capture\n'
            printf '4\t19_cipher_audit\t--score\t-\tno\tscore the negotiated ciphers\n'
            printf '5\t18_imsi_exposure\t--report\t-\tno\twrite the exposure report\n'
            ;;
        gsm-assessment)
            kchn_chain_header
            printf '1\t02_cell_recon\t--scan\tgsm GSM900\tyes\tfind the GSM cells in range\n'
            printf '2\t06_gsm_air\t--decode-pcap\t-\tno\tdecode the GSM air interface capture\n'
            printf '3\t06_gsm_air\t--cipher-audit\t-\tno\taudit the A5 cipher per session\n'
            printf '4\t19_cipher_audit\t--table\t-\tno\tshow the cipher table\n'
            printf '5\t07_gsm_attack\t--plan\t-\tno\twrite the GSM attack plans\n'
            printf '6\t20_gsm_cve\t--list-cves\t-\tno\tlist the 2G/3G CVE probes and handoffs\n'
            ;;
        lte-core-audit)
            kchn_chain_header
            printf '1\t17_pcap_analysis\t--hierarchy\t-\tno\tprotocol hierarchy of the EPC capture\n'
            printf '2\t11_lte_core\t--decode-diameter\t-\tno\tparse the Diameter S6a exchange\n'
            printf '3\t11_lte_core\t--decode-gtp-c\t-\tno\tparse the GTP-C exchange\n'
            printf '4\t11_lte_core\t--surface\t-\tno\treport the EPC surface\n'
            printf '5\t21_lte_cve\t--list-cves\t-\tno\tlist the LTE core plans\n'
            ;;
        5g-privacy)
            kchn_chain_header
            printf '1\t14_suci\t--parse-suci\t-\tno\tparse the captured SUCI\n'
            printf '2\t14_suci\t--audit\t-\tno\taudit the SUCI concealment\n'
            printf '3\t19_cipher_audit\t--downgrade-check\t-\tno\tcheck the null-cipher downgrade path\n'
            printf '4\t22_nr_cve\t--list-cves\t-\tno\tlist the 5G CVE probes and handoffs\n'
            ;;
        rf-effect)
            # The receive path, end to end, with no radio and no pre-existing
            # capture: the module writes a fixture whose verdict is fixed by
            # construction and then has to reach that verdict through its real
            # analyser. The transmit half is deliberately NOT a step. Arming the
            # lab gate is an operator's act with a disclaimer attached, not
            # something a chain should be able to do on its behalf, so the last
            # step reports the gate state instead of opening it.
            #
            # --discriminate is also absent, for a different reason: it decides
            # between jamming, congestion and a coverage hole from the feature
            # record, and a synthetic capture carries none of the receiver
            # counters (decode failures, RSRP/RSRQ deltas) that decision needs.
            # On a fixture it correctly answers "indeterminate" and exits 1, so
            # a chain step would report a failure the operator did not cause.
            kchn_chain_header
            printf '1\t33_jamming_detect\t--fixture\tclean /tmp/imsisting/jamming_detect/chain_clean.cf32\tno\twrite a known-clean capture\n'
            printf '2\t33_jamming_detect\t--characterise\t/tmp/imsisting/jamming_detect/chain_clean.cf32 cf32 20000000\tno\ta clean capture must characterise as clean\n'
            printf '3\t33_jamming_detect\t--fixture\tnarrow /tmp/imsisting/jamming_detect/chain_narrow.cf32\tno\twrite a known-narrowband capture\n'
            printf '4\t33_jamming_detect\t--characterise\t/tmp/imsisting/jamming_detect/chain_narrow.cf32 cf32 20000000\tno\ta 25 kHz offset carrier must characterise as narrowband\n'
            printf '5\t33_jamming_detect\t--analyse\t/tmp/imsisting/jamming_detect/chain_narrow.cf32 cf32 20000000\tno\tthe features, saved as the record\n'
            printf '6\t33_jamming_detect\t--noise-floor\t/tmp/imsisting/jamming_detect/chain_narrow.cf32 cf32 20000000\tno\tthe noise floor over time\n'
            printf '7\t33_jamming_detect\t--tx-status\t-\tno\tthe disclaimer and the gate state, keys nothing\n'
            ;;
        nbiot-audit)
            # Every step is a worked vector, so this chain runs identically on a
            # machine that has never seen a capture. The two decoders are given
            # real messages rather than being asked for a usage line.
            kchn_chain_header
            printf '1\t45_iot\t--decode-sib1\tc30a8246815d5e6d058606e53b5073a801008008\tno\tdecode a real SystemInformationBlockType1-NB\n'
            printf '2\t45_iot\t--decode-mib\taccac00000\tno\tdecode a real MasterInformationBlock-NB\n'
            printf '3\t45_iot\t--npss-nss\t503\tno\tthe PCI 503 decomposition (NPSS is fixed, NSSS carries the PCI)\n'
            printf '4\t45_iot\t--selftest\t-\tno\tthe codec known answers and the refusals\n'
            ;;
        lmr-survey)
            # Non-3GPP land mobile radio: the frame arithmetic is derived from the
            # air interface and checked against the published durations, so an
            # operator can see whether the two still agree before trusting a
            # survey. No radio and no capture.
            kchn_chain_header
            printf '1\t53_non3gpp\t--classify\t25\tno\ta 25 kHz channel is TETRA\n'
            printf '2\t53_non3gpp\t--classify\t12.5\tno\ta 12.5 kHz channel is DMR\n'
            printf '3\t53_non3gpp\t--frame-math\t255 2 4 36000\tno\tderive the TETRA frame from 2040 bits at 36 kbit/s\n'
            printf '4\t53_non3gpp\t--frame-math\t132 2 2 9600 2.5\tno\tderive the DMR frame from 528 bits plus two guards\n'
            printf '5\t53_non3gpp\t--detect-note\t-\tno\tthe cipher posture per technology\n'
            printf '6\t51_sidelink\t--subchannels\t100 10\tno\tsidelink resource pool split\n'
            printf '7\t51_sidelink\t--freq-bits\t10\tno\tSCI-1A frequency field width for 10 subchannels\n'
            ;;
        slice-oran-assess)
            # The 5G control-plane surface that Phases 11 names: slice selection
            # on the NAS side, then the RIC side that owns the policies.
            kchn_chain_header
            printf '1\t34_slicing\t--sst-table\t-\tno\tthe standardised slice types\n'
            printf '2\t34_slicing\t--encode-s-nssai\t1 000001\tno\tencode a known S-NSSAI\n'
            printf '3\t34_slicing\t--decode-s-nssai\t01000001\tno\tdecode it back\n'
            printf '4\t48_oran\t--interfaces\t-\tno\tthe RIC interface map\n'
            printf '5\t48_oran\t--e2sm\t-\tno\tthe E2 service models an xApp can drive\n'
            printf '6\t48_oran\t--xapp-attack\t-\tno\tthe over-broad xApp model\n'
            ;;
        nr-core-exposure)
            # The 5G core's own protocols, from the messages that make the
            # exposure concrete: a PFCP session-modification that re-points a
            # user plane N3 endpoint, a NGAP setup that answers, a NAS COUNT
            # that goes backwards, and two procedures whose interleaving breaks
            # the state machine. No core required: every step builds octets or
            # compares numbers.
            kchn_chain_header
            printf '1\t13_nr_core\t--pfcp-hijack\t123456789 4242 203.0.113.9\tno\tbuild a Session Modification that re-points the N3 FAR\n'
            printf '2\t13_nr_core\t--ngap-probe\t10.0.0.1\tno\twhat a NGSetup and an InitialUEMessage ask an AMF\n'
            printf '3\t13_nr_core\t--nas-count-check\t500 500\tno\ta NAS COUNT that repeats is a keystream that repeats\n'
            printf '4\t13_nr_core\t--rekey-walk\t-\tno\tthe re-key and NCC checks a walk would make\n'
            printf '5\t13_nr_core\t--kairos\tpdu-release pdu-establish\tno\ttwo procedures, one state machine, and a schedule that breaks it\n'
            ;;
        sba-exposure)
            # The 5G service-based boundary: a roaming N32 hop, the NRF
            # inventory answered to any requester, and the metadata endpoint a
            # callback URI can be pointed at.
            kchn_chain_header
            printf '1\t40_sba_pivot\t--n32-bridge\thttp://10.0.0.1 AMF 001-01\tno\twhat crosses the home/visiting boundary, and what only appears to\n'
            printf '2\t40_sba_pivot\t--nrf-walk\tnrf.5gc.mnc001.mcc001.3gppnetwork.org AMF\tno\tthirteen target types asked of one discovery service\n'
            printf '3\t40_sba_pivot\t--imds-pivot\tAMF\tno\tan NFRegister whose notification URI points at the metadata service\n'
            ;;
        ntn-timing)
            # A satellite cell is arithmetic before it is radio: Doppler at the
            # carrier, range at the elevation, the K_offset that converts one to
            # the other, and the SIB19 that tells a UE to believe all three.
            kchn_chain_header
            printf '1\t49_ntn\t--doppler\t2100 7.5 30\tno\tDoppler on a 2100 MHz carrier at 7.5 km/s\n'
            printf '2\t49_ntn\t--range\t600 45\tno\tslant range from a 600 km altitude at 45 degrees\n'
            printf '3\t49_ntn\t--ta\t12000\tno\tthe timing advance that range implies\n'
            printf '4\t49_ntn\t--sib19-build\t--koffset 20 --epoch-sfn 3 --epoch-sub 5 --validity s30 --ref-hex AABBCC\tno\tthe element a satellite cell broadcasts\n'
            printf '5\t49_ntn\t--sib19-carrier\t--ref-hex AABBCC\tno\tthe same block inside the BCCH-DL-SCH envelope it travels in\n'
            printf '6\t49_ntn\t--ephemeris-hijack\t--true-range 1200 --forged-range 600 --koffset 20\tno\tthe timing a UE derives from an ephemeris nobody binds\n'
            printf '7\t49_ntn\t--timing-geoloc\t--ta 12000 --sat-lat 0 --sat-lon 0 --sat-alt 600\tno\tone range is a circle, and the circle is where the UE is not\n'
            ;;
        sim-resync)
            # The counter exchange behind a synchronisation failure, from both
            # ends: the token the card would send, then the network deciding
            # whether the counter it carries is ahead of its own.
            kchn_chain_header
            printf '1\t16_sim\t--auts-build\t465B5CE8B199B49FAA5F0A2EE238A6BC CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 FF9BB4D0B607\tno\tthe AUTS a stale card sends (TS 35.208 set 1)\n'
            printf '2\t16_sim\t--auts-verify\t465B5CE8B199B49FAA5F0A2EE238A6BC CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 55F328B43577CF44E93596E355C6\tno\tcheck one token in isolation\n'
            printf '3\t16_sim\t--auts-responder\t465B5CE8B199B49FAA5F0A2EE238A6BC CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 55F328B43577CF44E93596E355C6 --sqn-he FF9BB4D0B600\tno\tthe network accepts, moves its counter and issues a new AUTN\n'
            printf '4\t16_sim\t--auts-responder\t465B5CE8B199B49FAA5F0A2EE238A6BC CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 55F328B43577CF44E93596E355C6 --sqn-he FF9BB4D0B607\tno\tthe same token again, against the counter the first answer set\n'
            ;;
        gea-posture)
            # GEA is where 2G ciphering is decided: which algorithms exist, which
            # this tree can compute against published vectors, and what the two
            # that were never published cost to break.
            kchn_chain_header
            printf '1\t50_gprs\t--gea-table\t-\tno\tevery GEA with its clause, key size and whether it is implemented here\n'
            printf '2\t50_gprs\t--gea\t1\tno\tthe standing of GEA1, by name\n'
            printf '3\t50_gprs\t--gea-crypt\t3 2BD6459F82C5BC00 8E9421A3 0001020304\tno\tGEA3 keystream against the published vector\n'
            printf '4\t50_gprs\t--gea-kat\t-\tno\tthe nine published GEA3/GEA4 vectors\n'
            printf '5\t50_gprs\t--gea-recovery\t--algo 1\tno\twhat recovering GEA1 costs, in octets, guesses and hours\n'
            ;;
        *)
            return 1 ;;
    esac
}

# Every built-in chain must appear here. The selftest asserts this list and
# the menu agree, so a new chain cannot ship unlisted.
kchn_builtin_names() {
    printf '%s\n' survey passive-audit gsm-assessment lte-core-audit 5g-privacy \
        rf-effect nbiot-audit lmr-survey slice-oran-assess \
        nr-core-exposure sba-exposure ntn-timing sim-resync gea-posture
}

kchn_builtin_count() {
    kchn_builtin_names | grep -c . || true
}

kchn_is_builtin() {
    kchn_builtin_names | grep -qxF -- "${1:-}"
}

# ── chain storage: built-ins plus anything added with --add-chain ───────
kchn_chain_path() {
    printf '%s/%s.tsv\n' "$KCHN_CHAINS_DIR" "$(printf '%s' "${1:-}" | tr -c 'A-Za-z0-9._-' '_')"
}

kchn_chain_exists() {
    kchn_is_builtin "${1:-}" && return 0
    [[ -f "$(kchn_chain_path "${1:-}")" ]]
}

kchn_chain_names() {
    kchn_builtin_names
    local f
    for f in "$KCHN_CHAINS_DIR"/*.tsv; do
        [[ -f "$f" ]] || continue
        basename "$f" .tsv
    done
}

# Emit the resolved chain: comments dropped, blanks dropped, steps ordered.
kchn_chain_body() {
    local name="${1:-}"
    if kchn_is_builtin "$name"; then
        kchn_builtin_chain "$name"
    elif [[ -f "$(kchn_chain_path "$name")" ]]; then
        cat "$(kchn_chain_path "$name")"
    else
        printf 'ERROR\tno such chain: %s\n' "$(kchn_sanitize "$name")" >&2
        return 1
    fi
}

kchn_chain_steps() {
    local name="${1:-}" body
    body="$(kchn_chain_body "$name")" || return 1
    printf '%s\n' "$body" | grep -v '^#' | grep -v '^[[:space:]]*$'
}

kchn_step_count() {
    local name="${1:-}" n
    n=$(kchn_chain_steps "$name" 2>/dev/null | tail -n +2 | grep -c . || true)
    printf '%s\n' "${n:-0}"
}

kchn_chain_modules() {
    kchn_chain_steps "${1:-}" 2>/dev/null | tail -n +2 | cut -f2
}

kchn_needs_hardware() {
    local name="${1:-}"
    kchn_chain_steps "$name" 2>/dev/null | tail -n +2 | awk -F'\t' '$5=="yes"' | grep -c . || true
}

# ── hardware and module resolution ──────────────────────────────────────
kchn_module_path() {
    local id="${1:-}"
    id="${id%.sh}"
    if [[ -f "$MODULES_DIR/$id.sh" ]]; then
        printf '%s\n' "$MODULES_DIR/$id.sh"
        return 0
    fi
    return 1
}

# Does this host have the radio the step needs? The check names what is
# missing; an absent radio is a SKIP reason, never a pass.
kchn_hardware_reason() {
    local have=""
    command -v hackrf_info   >/dev/null 2>&1 && have="$have hackrf"
    command -v bladeRF-cli   >/dev/null 2>&1 && have="$have bladerf"
    command -v uhd_find_devices >/dev/null 2>&1 && have="$have usrp"
    command -v LimeUtil      >/dev/null 2>&1 && have="$have limesdr"
    command -v rtl_test      >/dev/null 2>&1 && have="$have rtlsdr"
    if [[ -z "$have" ]]; then
        printf 'no SDR toolchain on this host (need hackrf/bladerf/usrp/limesdr/rtlsdr)\n'
        return 1
    fi
    # A tool being installed is not the same as a radio being attached; the
    # device file is the honest test.
    local d
    for d in /dev/hackrf* /dev/bladerf* /dev/bus/usb/*/* /dev/ttyUSB*; do
        [[ -e "$d" ]] && return 0
    done
    printf 'SDR tools present (%s) but no radio device node found\n' "$(printf '%s' "$have" | sed 's/^ //')"
    return 1
}

# ── run report ──────────────────────────────────────────────────────────
# One row per step:  step  module  verb  status  exit  seconds  detail
KCHN_REPORT_HDR='step	module	verb	status	exit	seconds	detail'
kchn_report_header() { printf '%s\n' "$KCHN_REPORT_HDR"; }

kchn_write_report() {
    local file="$1" row
    {
        kchn_report_header
        for row in "${KCHN_ROWS[@]}"; do
            printf '%s\n' "$row"
        done
    } > "$file" || {
        printf 'ERROR\tcannot write run report %s\n' "$file" >&2
        return 1
    }
    return 0
}

kchn_row() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(kchn_sanitize "${1:-}")" "$(kchn_sanitize "${2:-}")" \
        "$(kchn_sanitize "${3:-}")" "$(kchn_sanitize "${4:-}")" \
        "$(kchn_sanitize "${5:-}")" "$(kchn_sanitize "${6:-}")" \
        "$(kchn_sanitize "${7:-}")"
}

# ── execution checkpoints ──────────────────────────────────────────────
# Checkpoints are written atomically after each step. Pause is cooperative:
# the current module is allowed to finish before the chain enters PAUSED.
kchn_checkpoint_write() {
    local chain="$1" next="$2" keep="$3" target="${4:-}" report="${5:-}"
    local tmp="$KCHN_ACTIVE_STATE.$$"
    mkdir -p "$KCHN_STATE_DIR" || return 1
    printf 'chain\t%s\nnext_step\t%s\nkeep_going\t%s\ntarget\t%s\nreport\t%s\nupdated\t%s\n' \
        "$(kchn_sanitize "$chain")" "$(kchn_sanitize "$next")" "$keep" \
        "$(kchn_sanitize "$target")" "$(kchn_sanitize "$report")" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$tmp" && mv "$tmp" "$KCHN_ACTIVE_STATE"
}

kchn_progress_init() {
    kchn_report_header > "$KCHN_PROGRESS_FILE"
}

kchn_progress_load() {
    KCHN_ROWS=()
    [[ -f "$KCHN_PROGRESS_FILE" ]] || return 0
    mapfile -t KCHN_ROWS < <(tail -n +2 "$KCHN_PROGRESS_FILE")
}

kchn_progress_append() {
    local row="$1"
    printf '%s\n' "$row" >> "$KCHN_PROGRESS_FILE"
}

kchn_checkpoint_field() {
    [[ -f "$KCHN_ACTIVE_STATE" ]] || return 1
    awk -F'\t' -v k="$1" '$1==k{print $2; exit}' "$KCHN_ACTIVE_STATE"
}

kchn_pause() {
    mkdir -p "$KCHN_STATE_DIR" || return 1
    : > "$KCHN_PAUSE_FILE"
    printf 'pause\trequested\n'
}

kchn_run_status_tsv() {
    if [[ ! -f "$KCHN_ACTIVE_STATE" ]]; then
        printf 'state\tidle\nchain\t-\nnext_step\t-\ntarget\t-\nupdated\t-\n'
        return 0
    fi
    printf 'state\t%s\n' "$([[ -f "$KCHN_PAUSE_FILE" ]] && echo paused || echo resumable)"
    cat "$KCHN_ACTIVE_STATE"
}

kchn_resume() {
    [[ -f "$KCHN_ACTIVE_STATE" ]] || { printf 'ERROR\tno interrupted or paused run\n' >&2; return 1; }
    local chain next keep target
    chain=$(kchn_checkpoint_field chain); next=$(kchn_checkpoint_field next_step)
    keep=$(kchn_checkpoint_field keep_going); target=$(kchn_checkpoint_field target)
    rm -f "$KCHN_PAUSE_FILE"
    IMSISTING_TARGET_ID="$target" kchn_run_chain "$chain" 0 "$keep" "$next" "$target"
}

kchn_run_multi() {
    local chain="${1:-}" file="${2:-}"
    [[ -n "$chain" && -f "$file" ]] || {
        printf 'ERROR\tusage: --run-multi CHAIN TARGETS.tsv\n' >&2; return 2; }
    local target rest n=0 bad=0
    while IFS=$'\t' read -r target rest; do
        [[ -z "$target" || "$target" == target || "$target" == id || "$target" == \#* ]] && continue
        [[ "$target" =~ ^[A-Za-z0-9._:-]+$ ]] || {
            printf 'ERROR\tinvalid target id: %s\n' "$(kchn_sanitize "$target")" >&2; bad=1; continue; }
        n=$((n + 1))
        printf 'TARGET\t%s\n' "$target"
        IMSISTING_TARGET_ID="$target" kchn_run_chain "$chain" 0 0 1 "$target" || bad=1
    done < "$file"
    [[ "$n" -gt 0 ]] || { printf 'ERROR\tno targets in %s\n' "$file" >&2; return 1; }
    return "$bad"
}

# Statuses: PASS (verb exited 0), FAIL (verb exited non-zero),
#           SKIP (module missing or hardware absent), ERROR (bad step line).
kchn_run_chain() {
    local name="${1:-}" dry="${2:-0}" keep="${3:-0}" start="${4:-1}" target="${5:-${IMSISTING_TARGET_ID:-}}"
    if [[ -z "$name" ]]; then
        printf 'ERROR\tusage: --run <chain>\n' >&2
        return 2
    fi
    if ! kchn_chain_exists "$name"; then
        printf 'ERROR\tunknown chain: %s (see --list-chains)\n' "$(kchn_sanitize "$name")" >&2
        return 2
    fi

    local steps hw
    steps=$(kchn_step_count "$name")
    hw=$(kchn_needs_hardware "$name")
    if [[ "$steps" -eq 0 ]]; then
        printf 'ERROR\tchain %s has no steps\n' "$(kchn_sanitize "$name")" >&2
        return 1
    fi

    # A chain that needs hardware says so before it starts.
    local hw_reason="" hw_ok=1
    if [[ "$hw" -gt 0 ]]; then
        if ! hw_reason="$(kchn_hardware_reason)"; then
            hw_ok=0
        fi
        if [[ "$hw_ok" -eq 1 ]]; then
            info "chain $name needs hardware on $hw step(s); a radio is present"
        else
            warn "chain $name needs hardware on $hw step(s) — $hw_reason"
        fi
    fi

    KCHN_ROWS=()
    local line n=0 overall=0 report=""
    if [[ "$dry" != "1" ]]; then
        rm -f "$KCHN_PAUSE_FILE"
        if (( start <= 1 )); then kchn_progress_init; else kchn_progress_load; fi
        kchn_checkpoint_write "$name" "$start" "$keep" "$target" "" || return 1
    fi
    while IFS=$'\t' read -r step module verb args hard desc; do
        [[ -z "$step" || "$step" == "step" ]] && continue
        [[ "$step" =~ ^[0-9]+$ ]] || {
            KCHN_ROWS+=("$(kchn_row "$step" "$module" "$verb" ERROR 2 0 "non-numeric step")")
            overall=1; continue; }
        (( step < start )) && continue
        n=$((n + 1))
        if [[ "$dry" != "1" && -f "$KCHN_PAUSE_FILE" ]]; then
            kchn_checkpoint_write "$name" "$step" "$keep" "$target" "$report"
            printf 'PAUSED\t%s\tnext step %s\n' "$(kchn_sanitize "$name")" "$step"
            return 3
        fi

        # Dry run comes first and short-circuits both gates below. A dry run
        # resolves the chain as written — it does not evaluate whether this
        # host has the module or the radio, because that is execution-time
        # feasibility and reporting it as SKIP here would misrepresent a
        # chain the operator has not asked to run yet. Nothing is executed
        # and no run report is written on this path.
        if [[ "$dry" == "1" ]]; then
            printf 'DRY\t%s\t%s\t%s\t%s\t%s\n' \
                "$(kchn_sanitize "$step")" "$(kchn_sanitize "$module")" \
                "$(kchn_sanitize "$verb")" "$(kchn_sanitize "$args")" \
                "$(kchn_sanitize "$desc")"
            continue
        fi

        # Resolve the module.
        local mpath=""
        if ! mpath="$(kchn_module_path "$module")"; then
            local skip_row
            skip_row=$(kchn_row "$step" "$module" "$verb" SKIP "-" "0" "module not found: $module")
            KCHN_ROWS+=("$skip_row")
            kchn_progress_append "$skip_row"
            kchn_checkpoint_write "$name" "$((step + 1))" "$keep" "$target" "$report"
            printf 'SKIP\t%s\t%s\tmodule not found\n' "$(kchn_sanitize "$module")" "$(kchn_sanitize "$verb")"
            continue
        fi

        # Hardware gate: absent hardware is a SKIP with a reason.
        if [[ "$hard" == "yes" && "$hw_ok" -eq 0 ]]; then
            local skip_row
            skip_row=$(kchn_row "$step" "$module" "$verb" SKIP "-" "0" "hardware absent: $hw_reason")
            KCHN_ROWS+=("$skip_row")
            kchn_progress_append "$skip_row"
            kchn_checkpoint_write "$name" "$((step + 1))" "$keep" "$target" "$report"
            printf 'SKIP\t%s\t%s\thardware absent\n' "$(kchn_sanitize "$module")" "$(kchn_sanitize "$verb")"
            continue
        fi

        if [[ -n "$target" ]]; then
            args=${args//\{\{target\}\}/$target}
            desc=${desc//\{\{target\}\}/$target}
            export IMSISTING_TARGET_ID="$target"
        fi
        kchn_split_args "$args"
        local t0 t1 secs rc
        t0=$(date +%s)
        info "step $step: $module $verb ${args:--}"
        bash "$mpath" "$verb" "${KCHN_ARGV[@]}" </dev/null
        rc=$?
        t1=$(date +%s)
        secs=$((t1 - t0))

        if [[ "$rc" -eq 0 ]]; then
            local completed_row
            completed_row=$(kchn_row "$step" "$module" "$verb" PASS "$rc" "$secs" "$desc")
            KCHN_ROWS+=("$completed_row")
            kchn_progress_append "$completed_row"
            printf 'PASS\t%s\t%s\t%s\n' "$(kchn_sanitize "$module")" "$(kchn_sanitize "$verb")" "$rc"
            kchn_checkpoint_write "$name" "$((step + 1))" "$keep" "$target" "$report"
        else
            local failed_row
            failed_row=$(kchn_row "$step" "$module" "$verb" FAIL "$rc" "$secs" "$desc")
            KCHN_ROWS+=("$failed_row")
            kchn_progress_append "$failed_row"
            printf 'FAIL\t%s\t%s\t%s\n' "$(kchn_sanitize "$module")" "$(kchn_sanitize "$verb")" "$rc"
            overall=1
            kchn_checkpoint_write "$name" "$step" "$keep" "$target" "$report"
            if [[ "$keep" != "1" ]]; then
                warn "step $step failed (rc=$rc) — stopping; use --keep-going to continue"
                break
            fi
        fi
    done < <(kchn_chain_steps "$name" | tail -n +2)

    if [[ "$dry" == "1" ]]; then
        # A dry run writes no run report and reports success.
        printf 'DRY-RUN\t%s\t%s step(s)\n' "$(kchn_sanitize "$name")" "$n"
        return 0
    fi
    if [[ "$n" -eq 0 ]]; then
        printf 'ERROR\tchain %s resolved to zero steps\n' "$(kchn_sanitize "$name")" >&2
        return 1
    fi

    local ts report
    ts=$(date +%Y%m%d_%H%M%S)
    report="$KCHN_RUNS_DIR/${name}${target:+_${target}}_${ts}.tsv"
    mkdir -p "$KCHN_RUNS_DIR" 2>/dev/null
    kchn_write_report "$report" || return 1
    ok "run report: $report"
    if [[ "$overall" -eq 0 ]]; then
        rm -f "$KCHN_ACTIVE_STATE" "$KCHN_PAUSE_FILE" "$KCHN_PROGRESS_FILE"
    fi
    if [[ "$overall" -ne 0 ]]; then
        printf 'RESULT\tFAIL\n' >&2
        return 1
    fi
    printf 'RESULT\tPASS\n'
    return 0
}

# ── chain management ────────────────────────────────────────────────────
kchn_add_chain() {
    local name="${1:-}"
    [[ -n "$name" ]] || { printf 'ERROR\tusage: --add-chain <name>\n' >&2; return 2; }
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || {
        printf 'ERROR\tchain name must be alphanumeric with . _ -\n' >&2; return 2; }
    if kchn_is_builtin "$name"; then
        printf 'ERROR\t%s is a built-in chain and cannot be replaced\n' "$(kchn_sanitize "$name")" >&2
        return 2
    fi
    local f; f="$(kchn_chain_path "$name")"
    if [[ -e "$f" ]]; then
        printf 'ERROR\tchain %s already exists at %s\n' "$(kchn_sanitize "$name")" "$(kchn_sanitize "$f")" >&2
        return 2
    fi
    mkdir -p "$KCHN_CHAINS_DIR" 2>/dev/null || {
        printf 'ERROR\tcannot create %s\n' "$KCHN_CHAINS_DIR" >&2; return 1; }
    {
        kchn_chain_header
        printf '# %s — edit this file; one step per line, tab separated:\n' "$(kchn_sanitize "$name")"
        printf '# step <TAB> module <TAB> verb <TAB> args <TAB> hardware <TAB> description\n'
        printf '# args may be "-" for none; hardware is yes or no.\n'
    } > "$f" || {
        printf 'ERROR\tcannot write %s\n' "$f" >&2; return 1; }
    printf 'chain\t%s\npath\t%s\nstatus\tcreated\n' \
        "$(kchn_sanitize "$name")" "$(kchn_sanitize "$f")"
    return 0
}

kchn_show_chain() {
    local name="${1:-}"
    [[ -n "$name" ]] || { printf 'ERROR\tusage: --show-chain <name>\n' >&2; return 2; }
    if ! kchn_chain_exists "$name"; then
        printf 'ERROR\tunknown chain: %s (see --list-chains)\n' "$(kchn_sanitize "$name")" >&2
        return 2
    fi
    local steps hw
    steps=$(kchn_step_count "$name")
    hw=$(kchn_needs_hardware "$name")
    printf 'chain\t%s\nsteps\t%s\nhardware_steps\t%s\n' \
        "$(kchn_sanitize "$name")" "$steps" "$hw"
    kchn_chain_steps "$name"
    return 0
}

kchn_list_chains() {
    printf 'chain\tsteps\thardware_steps\tsource\n'
    local n steps hw src
    while IFS= read -r n; do
        [[ -z "$n" ]] && continue
        steps=$(kchn_step_count "$n")
        hw=$(kchn_needs_hardware "$n")
        if kchn_is_builtin "$n"; then src="builtin"; else src="file"; fi
        printf '%s\t%s\t%s\t%s\n' \
            "$(kchn_sanitize "$n")" "$steps" "$hw" "$src"
    done < <(kchn_chain_names)
}

kchn_runs_tsv() {
    local f n=0
    printf 'run\tchain\tsteps\n'
    for f in "$KCHN_RUNS_DIR"/*.tsv; do
        [[ -f "$f" ]] || continue
        n=$((n + 1))
        printf '%s\t%s\t%s\n' \
            "$(kchn_sanitize "$(basename "$f")")" \
            "$(kchn_sanitize "$(basename "$f" | sed 's/_[0-9]\{8\}_[0-9]\{6\}\.tsv$//')")" \
            "$(tail -n +2 "$f" | grep -c . || true)"
    done
    [[ "$n" -gt 0 ]] || {
        printf 'ERROR\tno chain runs recorded yet\n' >&2
        return 1
    }
    return 0
}

kchn_cli_status_tsv() {
    local runs chains
    runs=$(find "$KCHN_RUNS_DIR" -type f -name '*.tsv' 2>/dev/null | wc -l | tr -d ' ')
    chains=$(kchn_chain_names | grep -c . || true)
    printf 'module\tkillchain\nversion\t%s\n' "$KCHN_VERSION"
    printf 'chains\t%s\n'        "$chains"
    printf 'builtin_chains\t%s\n' "$(kchn_builtin_count)"
    printf 'runs\t%s\n'          "$runs"
    printf 'modules_dir\t%s\n'   "$MODULES_DIR"
    printf 'dir\t%s\n'           "$KCHN_DIR"
    printf 'runs_dir\t%s\n'      "$KCHN_RUNS_DIR"
    printf 'chains_dir\t%s\n'    "$KCHN_CHAINS_DIR"
    if kchn_hardware_reason >/dev/null 2>&1; then
        printf 'hardware\tpresent\n'
    else
        printf 'hardware\tabsent\n'
    fi
}

# ── selftest — no radio, no root, no network ────────────────────────────
kchn_selftest() {
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
    mkdir -p "$d/loot" "$d/modules"
    export LOOT_DIR="$d/loot" MODULES_DIR="$d/modules"
    export KCHN_DIR="$d/loot/killchain" KCHN_RUNS_DIR="$d/loot/killchain/runs"
    export KCHN_CHAINS_DIR="$d/loot/killchain/chains"
    export KCHN_STATE_DIR="$d/state/killchain"
    export KCHN_ACTIVE_STATE="$KCHN_STATE_DIR/active.tsv"
    export KCHN_PAUSE_FILE="$KCHN_STATE_DIR/pause.request"
    export KCHN_PROGRESS_FILE="$KCHN_STATE_DIR/progress.tsv"
    mkdir -p "$KCHN_RUNS_DIR" "$KCHN_CHAINS_DIR" "$KCHN_STATE_DIR"

    # A stub module that always succeeds, and one that always fails.
    cat > "$d/modules/02_cell_recon.sh" <<'STUB'
#!/usr/bin/env bash
echo "stub ok: $*"
exit 0
STUB
    cat > "$d/modules/99_failing.sh" <<'STUB'
#!/usr/bin/env bash
echo "stub fail: $*" >&2
exit 3
STUB
    chmod +x "$d/modules"/*.sh

    # ── 1. every built-in chain is listed ──────────────────────────────
    local n chk_names=0
    for n in $(kchn_builtin_names); do
        kchn_chain_exists "$n" && chk_names=$((chk_names + 1))
    done
    chk builtin-count        "$(kchn_builtin_count)" "14"
    chk builtin-all-exist    "$chk_names" "14"
    chk builtin-names        "$(kchn_builtin_names | sort | tr '\n' ' ')" "5g-privacy gea-posture gsm-assessment lmr-survey lte-core-audit nbiot-audit nr-core-exposure ntn-timing passive-audit rf-effect sba-exposure sim-resync slice-oran-assess survey "
    chk builtin-listed       "$(kchn_list_chains | tail -n +2 | grep -c .)" "14"
    chk builtin-listed-src   "$(kchn_list_chains | awk -F'\t' '$4=="builtin"' | grep -c .)" "14"

    # Every chain's steps parse into the six documented fields, with a
    # positive step number and a hardware flag of yes or no.
    local steps_bad=0
    for n in $(kchn_builtin_names); do
        kchn_chain_steps "$n" | tail -n +2 | awk -F'\t' '
            NF!=6 || $1 !~ /^[0-9]+$/ || $5 !~ /^(yes|no)$/ { exit 1 }' || steps_bad=$((steps_bad + 1))
    done
    chk builtin-step-shape "$steps_bad" "0"

    # Every built-in step must name a verb its module actually implements.
    # This is the check that catches chain/module drift: a chain that calls
    # a verb nobody wrote is a button that does nothing. It runs against the
    # real modules tree, and skips a module that is not installed rather than
    # inventing a verdict.
    local drift=0 checked=0
    for n in $(kchn_builtin_names); do
        while IFS=$'\t' read -r stp mod verb rest; do
            [[ "$stp" == "step" || -z "$stp" ]] && continue
            local rp
            rp="$IMSISTING_ROOT/modules/${mod%.sh}.sh"
            [[ -f "$rp" ]] || continue
            checked=$((checked + 1))
            # The verb is present in the module's dispatch when it appears as
            # a case arm there.
            # Match a case arm exactly: leading whitespace, the verb, then ")".
            # -F is used on a constructed fixed string so the leading dashes
            # and any regex metacharacters in the verb cannot misfire.
            grep -qF -- "$(printf '%s)' "$verb")" "$rp" || drift=$((drift + 1))
        done < <(kchn_chain_steps "$n" | tail -n +2)
    done
    chk builtin-verbs-exist "$drift" "0"
    printf 'builtin-verbs-checked\t%s\n' "$checked"

    # ── 2. --show-chain resolves the right count and module ids ────────
    out=$(kchn_show_chain survey); rc=$?
    chk show-survey-rc     "$rc" "0"
    chk show-survey-steps  "$(fld "$out" steps)" "3"
    chk show-survey-hw     "$(fld "$out" hardware_steps)" "1"
    chk show-survey-mods   "$(printf '%s\n' "$out" | tail -n +5 | cut -f2 | tr '\n' ' ')" \
                           "02_cell_recon 02_cell_recon 02_cell_recon "
    chk show-survey-verbs  "$(printf '%s\n' "$out" | tail -n +5 | cut -f3 | tr '\n' ' ')" \
                           "--scan --list-tsv --export "

    out=$(kchn_show_chain passive-audit)
    chk show-passive-steps "$(fld "$out" steps)" "5"
    chk show-passive-hw    "$(fld "$out" hardware_steps)" "0"
    chk show-passive-mods  "$(printf '%s\n' "$out" | tail -n +5 | cut -f2 | tr '\n' ' ')" \
                           "17_pcap_analysis 17_pcap_analysis 18_imsi_exposure 19_cipher_audit 18_imsi_exposure "

    out=$(kchn_show_chain gsm-assessment)
    chk show-gsm-steps "$(fld "$out" steps)" "6"
    chk show-gsm-hw    "$(fld "$out" hardware_steps)" "1"

    out=$(kchn_show_chain lte-core-audit)
    chk show-lte-steps "$(fld "$out" steps)" "5"
    chk show-lte-mods  "$(printf '%s\n' "$out" | tail -n +5 | cut -f2 | tr '\n' ' ')" \
                       "17_pcap_analysis 11_lte_core 11_lte_core 11_lte_core 21_lte_cve "

    out=$(kchn_show_chain 5g-privacy)
    chk show-5g-steps "$(fld "$out" steps)" "4"
    chk show-5g-mods  "$(printf '%s\n' "$out" | tail -n +5 | cut -f2 | tr '\n' ' ')" \
                      "14_suci 14_suci 19_cipher_audit 22_nr_cve "

    # ── 3. argument validation for an unknown chain ────────────────────
    chk show-unknown-rc "$(kchn_show_chain nope >/dev/null 2>&1; echo $?)" "2"
    chk run-unknown-rc  "$(kchn_run_chain nope >/dev/null 2>&1; echo $?)" "2"
    chk run-noarg-rc    "$(kchn_run_chain >/dev/null 2>&1; echo $?)" "2"
    chk show-noarg-rc   "$(kchn_show_chain >/dev/null 2>&1; echo $?)" "2"
    chk add-noarg-rc    "$(kchn_add_chain >/dev/null 2>&1; echo $?)" "2"
    chk add-badname-rc  "$(kchn_add_chain 'bad/name' >/dev/null 2>&1; echo $?)" "2"
    chk add-builtin-rc  "$(kchn_add_chain survey >/dev/null 2>&1; echo $?)" "2"

    # ── 4. --dry-run executes nothing and writes no run report ─────────
    local before after
    before=$(find "$KCHN_RUNS_DIR" -type f | wc -l | tr -d ' ')
    out=$(kchn_run_chain survey 1 0); rc=$?
    after=$(find "$KCHN_RUNS_DIR" -type f | wc -l | tr -d ' ')
    chk dry-rc        "$rc" "0"
    chk dry-no-report "$after" "$before"
    chk dry-lines     "$(printf '%s\n' "$out" | grep -c '^DRY	')" "3"
    chk dry-summary   "$(printf '%s\n' "$out" | grep -c '^DRY-RUN	survey	3 step')" "1"
    chk dry-no-pass   "$(printf '%s\n' "$out" | grep -c '^PASS')" "0"
    chk dry-no-stub   "$(printf '%s\n' "$out" | grep -c 'stub ok')" "0"

    # A dry run of a hardware chain still resolves without touching a radio.
    out=$(kchn_run_chain gsm-assessment 1 0); rc=$?
    chk dry-hw-rc     "$rc" "0"
    chk dry-hw-lines  "$(printf '%s\n' "$out" | grep -c '^DRY	')" "6"
    chk dry-hw-report "$(find "$KCHN_RUNS_DIR" -type f | wc -l | tr -d ' ')" "$before"

    # ── 5. a chain referencing a missing module records SKIP, not PASS ─
    cat > "$KCHN_CHAINS_DIR/missing.tsv" <<'CHAIN'
step	module	verb	args	hardware	description
1	02_cell_recon	--scan	gsm	no	stub step that should run
2	42_does_not_exist	--run	-	no	step whose module is absent
3	02_cell_recon	--list-tsv	-	no	trailing step
CHAIN
    # Force the hardware gate open by pointing the module dir at the stubs
    # and giving the chain a non-hardware first step for this assertion.
    out=$(kchn_run_chain missing 0 1 2>&1); rc=$?
    chk skip-run-rc     "$rc" "0"
    chk skip-line       "$(printf '%s\n' "$out" | grep -c '^SKIP	42_does_not_exist')" "1"
    chk skip-not-pass   "$(printf '%s\n' "$out" | grep -c '^PASS	42_does_not_exist')" "0"
    local rep
    rep=$(find "$KCHN_RUNS_DIR" -name 'missing_*.tsv' | head -1)
    chk skip-report-exists "$([[ -f "$rep" ]] && echo yes || echo no)" "yes"
    chk skip-report-status "$(awk -F'\t' '$2=="42_does_not_exist"{print $4}' "$rep")" "SKIP"
    chk skip-report-exit   "$(awk -F'\t' '$2=="42_does_not_exist"{print $5}' "$rep")" "-"
    chk skip-report-reason "$(awk -F'\t' '$2=="42_does_not_exist"{print $7}' "$rep" | grep -c 'module not found')" "1"

    # ── 6. the run report TSV shape and exit codes ─────────────────────
    chk report-hdr     "$(head -1 "$rep")" "$(printf 'step\tmodule\tverb\tstatus\texit\tseconds\tdetail')"
    chk report-fields  "$(awk -F'\t' 'NF!=7' "$rep" | grep -c . || true)" "0"
    chk report-rows    "$(tail -n +2 "$rep" | grep -c .)" "3"
    chk report-exits   "$(awk -F'\t' 'NR>1{print $5}' "$rep" | tr '\n' ' ')" "0 - 0 "
    chk report-statuses "$(awk -F'\t' 'NR>1{print $4}' "$rep" | tr '\n' ' ')" "PASS SKIP PASS "

    # ── 7. a failing step fails the chain unless --keep-going ──────────
    cat > "$KCHN_CHAINS_DIR/failfast.tsv" <<'CHAIN'
step	module	verb	args	hardware	description
1	02_cell_recon	--ok	-	no	first step passes
2	99_failing	--boom	-	no	second step fails
3	02_cell_recon	--after	-	no	third step must not run without --keep-going
CHAIN
    before=$(find "$KCHN_RUNS_DIR" -type f | wc -l | tr -d ' ')
    out=$(kchn_run_chain failfast 0 0 2>&1); rc=$?
    chk failfast-rc      "$rc" "1"
    chk failfast-fail    "$(printf '%s\n' "$out" | grep -c '^FAIL	99_failing')" "1"
    chk failfast-stop    "$(printf '%s\n' "$out" | grep -c '^PASS	02_cell_recon')" "1"
    chk failfast-stopped "$(printf '%s\n' "$out" | grep -c 'stopping')" "1"
    local rep2
    rep2=$(find "$KCHN_RUNS_DIR" -name 'failfast_*.tsv' | head -1)
    chk failfast-report-rows "$(tail -n +2 "$rep2" | grep -c .)" "2"
    chk failfast-report-fail "$(awk -F'\t' '$2=="99_failing"{print $4}' "$rep2")" "FAIL"
    chk failfast-report-exit "$(awk -F'\t' '$2=="99_failing"{print $5}' "$rep2")" "3"

    out=$(kchn_run_chain failfast 0 1 2>&1); rc=$?
    chk keepgoing-rc     "$rc" "1"
    chk keepgoing-runs   "$(printf '%s\n' "$out" | grep -c '^PASS	02_cell_recon')" "2"
    rep2=$(ls -t "$KCHN_RUNS_DIR"/failfast_*.tsv | head -1)
    chk keepgoing-rows   "$(tail -n +2 "$rep2" | grep -c .)" "3"
    chk keepgoing-status "$(awk -F'\t' 'NR>1{print $4}' "$rep2" | tr '\n' ' ')" "PASS FAIL PASS "
    chk keepgoing-nonzero "$(tail -n +2 "$rep2" | awk -F'\t' '$4=="FAIL"' | grep -c .)" "1"

    # ── 8. hardware-absent steps are SKIP with a reason ────────────────
    # The stub module dir has no radio, so the "yes" step must SKIP even
    # though its module exists and would have succeeded.
    cat > "$KCHN_CHAINS_DIR/hwonly.tsv" <<'CHAIN'
step	module	verb	args	hardware	description
1	02_cell_recon	--tx	-	yes	needs a radio that is not here
2	02_cell_recon	--rx	-	no	no radio needed
CHAIN
    # Only run this branch when the host really has no radio, otherwise the
    # first step would legitimately pass.
    if kchn_hardware_reason >/dev/null 2>&1; then
        printf 'skip-no-radio\tPASS (radio present, branch not applicable)\n'
    else
        out=$(kchn_run_chain hwonly 0 1 2>&1); rc=$?
        chk hw-skip-rc     "$rc" "0"
        chk hw-skip-line   "$(printf '%s\n' "$out" | grep -c '^SKIP	02_cell_recon	--tx	hardware absent')" "1"
        chk hw-skip-nopass "$(printf '%s\n' "$out" | grep -c '^PASS	02_cell_recon	--tx')" "0"
        local reph
        reph=$(find "$KCHN_RUNS_DIR" -name 'hwonly_*.tsv' | head -1)
        chk hw-report-status "$(awk -F'\t' '$3=="--tx"{print $4}' "$reph")" "SKIP"
        chk hw-report-reason "$(awk -F'\t' '$3=="--tx"{print $7}' "$reph" | grep -c 'hardware absent')" "1"
        chk hw-report-pass   "$(awk -F'\t' '$3=="--rx"{print $4}' "$reph")" "PASS"
    fi

    # The chain that needs hardware announces it before it starts.
    out=$(kchn_run_chain hwonly 0 1 2>&1)
    chk hw-announce "$(printf '%s\n' "$out" | grep -cE 'needs hardware on [0-9]+ step')" "1"

    # ── 9. --add-chain and the file-backed chain path ──────────────────
    out=$(kchn_add_chain custom); rc=$?
    chk add-rc         "$rc" "0"
    chk add-status     "$(printf '%s\n' "$out" | grep -c '^status	created$')" "1"
    chk add-file       "$([[ -f "$KCHN_CHAINS_DIR/custom.tsv" ]] && echo yes || echo no)" "yes"
    chk add-exists-rc  "$(kchn_add_chain custom >/dev/null 2>&1; echo $?)" "2"
    chk add-listed     "$(kchn_chain_names | grep -cx custom)" "1"
    chk add-step-count "$(kchn_step_count custom)" "0"
    chk add-listed-row "$(kchn_list_chains | awk -F'\t' '$1=="custom"{print $4}')" "file"

    # A file-backed chain runs like any other.
    cat > "$KCHN_CHAINS_DIR/custom.tsv" <<'CHAIN'
step	module	verb	args	hardware	description
1	02_cell_recon	--one	-	no	first
2	02_cell_recon	--two	ARGS with spaces	no	second, quoted args
CHAIN
    chk custom-steps "$(kchn_step_count custom)" "2"
    out=$(kchn_run_chain custom 0 0 2>&1); rc=$?
    chk custom-rc      "$rc" "0"
    chk custom-pass    "$(printf '%s\n' "$out" | grep -c '^PASS')" "2"
    chk custom-args    "$(printf '%s\n' "$out" | grep -c 'stub ok: --two ARGS with spaces')" "1"

    # ── 10. listing and TSV contracts ──────────────────────────────────
    out=$(kchn_list_chains)
    chk list-hdr    "$(printf '%s\n' "$out" | head -1)" "$(printf 'chain\tsteps\thardware_steps\tsource')"
    chk list-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=4' | grep -c . || true)" "0"
    chk list-rows   "$(printf '%s\n' "$out" | tail -n +2 | grep -c .)" "$(kchn_chain_names | grep -c .)"

    out=$(kchn_runs_tsv); rc=$?
    chk runs-rc     "$rc" "0"
    chk runs-hdr    "$(printf '%s\n' "$out" | head -1)" "$(printf 'run\tchain\tsteps')"
    chk runs-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3' | grep -c . || true)" "0"
    chk runs-chain  "$(printf '%s\n' "$out" | awk -F'\t' '$2=="surveys" || $2=="survey"' | grep -c .)" "0"

    out=$(kchn_cli_status_tsv)
    chk status-module  "$(fld "$out" module)"           "killchain"
    chk status-builtin "$(fld "$out" builtin_chains)"   "14"
    chk status-dir     "$(fld "$out" dir)"              "$KCHN_DIR"
    chk status-runsdir "$(fld "$out" runs_dir)"         "$KCHN_RUNS_DIR"
    chk status-fields  "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"

    # An empty runs dir is an error, not an empty success.
    rm -rf "$KCHN_RUNS_DIR"; mkdir -p "$KCHN_RUNS_DIR"
    chk runs-empty-rc "$(kchn_runs_tsv >/dev/null 2>&1; echo $?)" "1"

    # ── 11. TSV injection on the report writer ─────────────────────────
    KCHN_ROWS=()
    KCHN_ROWS+=("$(kchn_row "1" $'mod\tule' "verb" "PASS" "0" "0" $'desc\nhere')")
    local rf="$KCHN_RUNS_DIR/inject.tsv"
    kchn_write_report "$rf"
    chk report-inject-fields "$(awk -F'\t' 'NF!=7' "$rf" | grep -c . || true)" "0"
    chk report-inject-rows   "$(tail -n +2 "$rf" | grep -c .)" "1"
    chk report-unwritable-rc "$(kchn_write_report /proc/imsisting-nope/r.tsv >/dev/null 2>&1; echo $?)" "1"

    # Checkpoint/status and multi-target substitution are offline-testable.
    rm -f "$KCHN_ACTIVE_STATE" "$KCHN_PAUSE_FILE"
    chk run-status-idle "$(kchn_run_status_tsv | awk -F'\t' '$1=="state"{print $2}')" idle
    kchn_checkpoint_write smoke 2 1 ue-a report.tsv
    chk run-status-chain "$(kchn_run_status_tsv | awk -F'\t' '$1=="chain"{print $2}')" smoke
    chk run-status-next "$(kchn_run_status_tsv | awk -F'\t' '$1=="next_step"{print $2}')" 2
    chk pause-rc "$(kchn_pause >/dev/null 2>&1; echo $?)" 0
    chk pause-state "$(kchn_run_status_tsv | awk -F'\t' '$1=="state"{print $2}')" paused
    rm -f "$KCHN_ACTIVE_STATE" "$KCHN_PAUSE_FILE"
    cat > "$KCHN_CHAINS_DIR/multi.tsv" <<'CHAIN'
step	module	verb	args	hardware	description
1	02_cell_recon	--ok	{{target}}	no	target {{target}}
CHAIN
    printf 'target\tlabel\nue-a\tfirst\nue-b\tsecond\n' > "$d/targets.tsv"
    chk multi-rc "$(kchn_run_multi multi "$d/targets.tsv" >/dev/null 2>&1; echo $?)" 0
    chk multi-reports "$(find "$KCHN_RUNS_DIR" -name 'multi_ue-*.tsv' | wc -l | tr -d ' ')" 2
    chk multi-invalid "$(printf 'bad target\tx\n' > "$d/badtargets.tsv"; kchn_run_multi multi "$d/badtargets.tsv" >/dev/null 2>&1; echo $?)" 1

    # A chain file with a malformed hardware flag is a bad step line, and a
    # bad step must not silently become a pass.
    cat > "$KCHN_CHAINS_DIR/badflag.tsv" <<'CHAIN'
step	module	verb	args	hardware	description
1	02_cell_recon	--ok	-	maybe	malformed hardware flag
CHAIN
    chk badflag-shape "$(kchn_chain_steps badflag | tail -n +2 | awk -F'\t' '$5 !~ /^(yes|no)$/' | grep -c .)" "1"

    # R69: evidence. A manifest that verifies, and the same manifest after one
    # byte moves -- because a hash check that cannot fail is not a check.
    mkdir -p "$d/ev"
    printf 'alpha\n' > "$d/ev/one.txt"
    printf 'beta\n'  > "$d/ev/two.txt"
    local evman="$d/ev/manifest.tsv" evout evver
    evout=$(kchn_evidence_build --out "$evman" --note 'selftest' "$d/ev/one.txt" "$d/ev/two.txt")
    chk ev-rc "$?" "0"
    chk ev-artifacts "$(fld "$evout" artifacts)" "2"
    chk ev-verdict "$(fld "$evout" verdict)" "evidence_manifest_written"
    chk ev-version "$(fld "$evout" tool_version | grep -cE '^[0-9]+\.[0-9]+')" "1"
    chk ev-header "$(grep -c '^# body_sha256' "$evman")" "1"
    chk ev-utc "$(awk -F'\t' '$1=="# produced_at" && $2 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T.*Z$/{n++} END{print n+0}' "$evman")" "1"
    chk ev-note "$(awk -F'\t' '$1=="# note" && $2=="selftest"{n++} END{print n+0}' "$evman")" "1"
    evver=$(kchn_evidence_verify "$evman")
    chk ev-verify-rc "$?" "0"
    chk ev-verify-verdict "$(fld "$evver" verdict)" "evidence_intact"
    chk ev-verify-body "$(fld "$evver" body_verdict)" "matches"
    chk ev-verify-unchanged "$(fld "$evver" unchanged)" "2"
    printf 'alphabet\n' > "$d/ev/one.txt"
    evver=$(kchn_evidence_verify "$evman")
    chk ev-tamper-rc "$?" "1"
    chk ev-tamper-verdict "$(fld "$evver" verdict)" "evidence_broken"
    chk ev-tamper-changed "$(fld "$evver" changed)" "1"
    chk ev-tamper-finding "$(printf '%s\n' "$evver" | grep -c 'evidence_altered HIGH')" "1"
    rm -f "$d/ev/two.txt"
    chk ev-missing "$(kchn_evidence_verify "$evman" 2>/dev/null | awk -F'\t' '$1=="missing" && $2 ~ /^[0-9]+$/{print $2}')" "1"
    chk ev-noargs "$(kchn_evidence_build >/dev/null 2>&1; echo $?)" "2"
    chk ev-badfile "$(kchn_evidence_build "$d/ev/nope.txt" >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
# ── R69 (I7): evidence, so a finding survives the report ────────────────
# Every verb in this tree prints observations. An observation becomes evidence
# when someone else can re-derive it: the bytes it came from are named by hash,
# the moment is stamped in UTC, and the tool that produced it is identified by
# version and commit. Three things die in a hand-written report and these verbs
# are about those three: the file that was "the capture" is edited afterwards,
# the timestamp is off by a timezone, and nobody knows which build printed the
# verdict.
#
# The manifest is deliberately plain text with a '#' header, because the point
# is that a reader can check it without this tool. The body hash covers the
# artefact rows only, so the header can gain fields without invalidating it.
kchn_evidence_build() {
    local out="${KCHN_EVIDENCE_OUT:-}" note=""
    local -a files=()
    while (( $# )); do
        case "$1" in
            --out)  out="${2:-}";  shift 2 || { kchn_evidence_usage; return 2; } ;;
            --note) note="${2:-}"; shift 2 || { kchn_evidence_usage; return 2; } ;;
            --) shift; while (( $# )); do files+=("$1"); shift; done ;;
            *) files+=("$1"); shift ;;
        esac
    done
    (( ${#files[@]} )) || { printf 'ERROR\t--evidence-build wants at least one file\n' >&2; return 2; }
    local f
    for f in "${files[@]}"; do
        [[ -r "$f" ]] || { printf 'ERROR\tnot readable: %s\n' "$f" >&2; return 2; }
    done
    local ver commit host now body_body
    ver="$(cat "$IMSISTING_ROOT/VERSION" 2>/dev/null || echo unknown)"
    commit="$(git -C "$IMSISTING_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    host="$(hostname 2>/dev/null || echo unknown)"
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    local tmp; tmp=$(mktemp)
    for f in "${files[@]}"; do
        local size sum mtime
        size=$(stat -c '%s' -- "$f" 2>/dev/null || echo 0)
        sum=$(sha256sum -- "$f" | awk '{print $1}')
        mtime=$(date -u -r "$f" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
        printf 'artifact\t%s\t%s\t%s\t%s\n' "$size" "$sum" "$mtime" "$f" >> "$tmp"
    done
    body_body=$(sha256sum -- "$tmp" | awk '{print $1}')

    local path="${out:-"$IMSISTING_ROOT/evidence/evidence_$(date -u +%Y%m%dT%H%M%SZ).tsv"}"
    mkdir -p -- "$(dirname -- "$path")" || { rm -f "$tmp"; return 1; }
    {
        printf '# evidence manifest, IMSIsting\n'
        printf '# produced_at\t%s\n' "$now"
        printf '# tool_version\t%s\n' "$ver"
        printf '# tool_commit\t%s\n' "$commit"
        printf '# host\t%s\n' "$host"
        printf '# clock\tUTC, from this host clock: a report that needs a traceable clock says so, and this line is the claim\n'
        printf '# body_sha256\t%s\n' "$body_body"
        [[ -n "$note" ]] && printf '# note\t%s\n' "$(kchn_sanitize "$note")"
        printf '# columns\tsize\tsha256\tmtime_utc\tpath\n'
        cat "$tmp"
    } > "$path" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"

    printf 'manifest\t%s\n' "$path"
    printf 'produced_at\t%s\n' "$now"
    printf 'tool_version\t%s\n' "$ver"
    printf 'tool_commit\t%s\n' "$commit"
    printf 'host\t%s\n' "$host"
    printf 'artifacts\t%d\n' "${#files[@]}"
    printf 'body_sha256\t%s\n' "$body_body"
    local row
    while IFS=$'\t' read -r tag size sum mtime rel; do
        printf 'artifact\t%s\t%s\t%s\t%s\n' "$rel" "$size" "$sum" "$mtime"
    done < <(grep -v '^#' "$path")
    printf 'limit\ta hash proves the bytes did not change after they were hashed; it says nothing about whether they were the bytes the radio produced\n'
    printf 'ref\tNIST SP 800-86 (hashes and timestamps as part of the record), ISO 8601 UTC timestamps\n'
    printf 'verdict\tevidence_manifest_written\n'
    return 0
}

kchn_evidence_verify() {
    local manifest="${1:-}"
    [[ -n "$manifest" ]] || { kchn_evidence_usage; return 2; }
    [[ -r "$manifest" ]] || { printf 'ERROR\tnot readable: %s\n' "$manifest" >&2; return 2; }
    local claimed
    claimed=$(awk -F'\t' '$1=="# body_sha256"{print $2}' "$manifest")
    local body; body=$(mktemp)
    grep -v '^#' "$manifest" > "$body"
    local actual; actual=$(sha256sum -- "$body" | awk '{print $1}')
    local rows=0 unchanged=0 changed=0 missing=0
    local out_list=""
    while IFS=$'\t' read -r tag size sum mtime rel; do
        [[ "$tag" == artifact ]] || continue
        rows=$(( rows + 1 ))
        if [[ ! -r "$rel" ]]; then
            missing=$(( missing + 1 )); out_list+="missing\t$rel\n"; continue
        fi
        local now_sum; now_sum=$(sha256sum -- "$rel" | awk '{print $1}')
        if [[ "$now_sum" == "$sum" ]]; then
            unchanged=$(( unchanged + 1 ))
        else
            changed=$(( changed + 1 )); out_list+="changed\t$rel\t$sum\t$now_sum\n"
        fi
    done < "$body"
    rm -f "$body"
    printf 'manifest\t%s\n' "$manifest"
    printf 'body_claims\t%s\n' "${claimed:-absent}"
    printf 'body_actual\t%s\n' "$actual"
    printf 'body_verdict\t%s\n' "$( [[ -n "$claimed" && "$claimed" == "$actual" ]] && echo matches || echo differs )"
    printf 'artifacts\t%d\n' "$rows"
    printf 'unchanged\t%d\n' "$unchanged"
    printf 'changed\t%d\n' "$changed"
    printf 'missing\t%d\n' "$missing"
    [[ -n "$out_list" ]] && printf "$out_list"
    if (( changed > 0 || missing > 0 )); then
        printf 'finding\tevidence_altered HIGH\tthe manifest no longer describes the tree it described when it was written, so any finding that cites these paths has to be re-derived before it is reported\n'
        printf 'verdict\tevidence_broken\n'
        return 1
    fi
    printf 'finding\tevidence_intact INFO\tevery hashed artifact still hashes to what the manifest recorded\n'
    printf 'limit\tthis check cannot tell whether the file it hashes now is the file the radio produced, and an empty manifest verifies as intact\n'
    printf 'verdict\tevidence_intact\n'
    return 0
}

kchn_evidence_usage() {
    cat >&2 <<'EOF'
USAGE	--evidence-build [--out PATH] [--note TEXT] FILE...
USAGE	--evidence-verify MANIFEST
EOF
    return 2
}


kchn_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== cellular killchain ===${C_RESET}"
        echo -e "  chains: ${C_GRN}$(kchn_chain_names | grep -c .)${C_RESET}"
        echo -e "  runs:   ${C_GRN}$(find "$KCHN_RUNS_DIR" -type f -name '*.tsv' 2>/dev/null | wc -l | tr -d ' ')${C_RESET}"
        if kchn_hardware_reason >/dev/null 2>&1; then
            echo -e "  radio:  ${C_GRN}present${C_RESET}"
        else
            echo -e "  radio:  ${C_YEL}absent${C_RESET}"
        fi
        echo -e "  dir:    ${C_DIM}$KCHN_DIR${C_RESET}\n"
        cat << 'M'
  [1]  list chains
  [2]  show a chain
  [3]  dry-run a chain (resolve steps, execute nothing)
  [4]  run a chain
  [5]  run a chain, keep going after a failure
  [6]  create a new chain file
  [7]  show run history
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) kchn_list_chains | column -t -s$'\t' 2>/dev/null || kchn_list_chains
               read -rp "  press enter " _ ;;
            2) read -rp "  chain> " n; kchn_show_chain "$n" | column -t -s$'\t' 2>/dev/null || kchn_show_chain "$n"
               read -rp "  press enter " _ ;;
            3) read -rp "  chain> " n; kchn_run_chain "$n" 1 0; read -rp "  press enter " _ ;;
            4) read -rp "  chain> " n; kchn_run_chain "$n" 0 0; read -rp "  press enter " _ ;;
            5) read -rp "  chain> " n; kchn_run_chain "$n" 0 1; read -rp "  press enter " _ ;;
            6) read -rp "  new chain name> " n; kchn_add_chain "$n"; sleep 1 ;;
            7) kchn_runs_tsv | column -t -s$'\t' 2>/dev/null || kchn_runs_tsv
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
kchn_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  kchn_cli_status_tsv ;;
        --list-chains) kchn_list_chains ;;
        --show-chain)  kchn_show_chain "${1:-}" ;;
        --run)         kchn_run_chain "${1:-}" 0 0 ;;
        --dry-run)     kchn_run_chain "${1:-}" 1 0 ;;
        --add-chain)   kchn_add_chain "${1:-}" ;;
        --runs-tsv)    kchn_runs_tsv ;;
        --pause)       kchn_pause ;;
        --resume)      kchn_resume ;;
        --run-multi)   kchn_run_multi "${1:-}" "${2:-}" ;;
        --run-status-tsv) kchn_run_status_tsv ;;
        --evidence-build)  kchn_evidence_build "$@" ;;
        --evidence-verify) kchn_evidence_verify "${1:-}" ;;
        --selftest)    kchn_selftest ;;
        --menu)        kchn_menu ;;
        *)
            cat >&2 <<EOF
Cellular Killchain — chain the modules into an ordered, recorded run

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --list-chains             every chain, with step and hardware counts
  --show-chain <name>       resolve a chain's steps without running them
  --run <name> [--dry-run] [--keep-going]
                            run a chain; --dry-run prints the resolved steps
                            and writes no report; --keep-going continues after
                            a failed step (the overall exit is still non-zero)
  --add-chain <name>        create an empty chain file to edit
  --runs-tsv                recorded runs as TSV
  --pause                   request a cooperative pause between steps
  --resume                  resume the active run from its checkpoint
  --run-multi CHAIN FILE    run once per first-column target; {{target}} expands
  --run-status-tsv          active checkpoint and pause state
  --selftest                verify chaining and reporting without a radio
  --menu                    interactive menu

Chain file format (TSV, one step per line):
  step <TAB> module <TAB> verb <TAB> args <TAB> hardware <TAB> description
EOF
            return 2 ;;
    esac
}

# The verb list above documents --run <name> [--dry-run] [--keep-going]; the
# dispatcher also accepts the flags inline after the chain name.
kchn_cli_run_args() {
    local name="${1:-}"; shift || true
    local dry=0 keep=0 a
    for a in "$@"; do
        case "$a" in
            --dry-run)    dry=1 ;;
            --keep-going) keep=1 ;;
            *) printf 'ERROR\tunknown run flag: %s\n' "$(kchn_sanitize "$a")" >&2; return 2 ;;
        esac
    done
    kchn_run_chain "$name" "$dry" "$keep"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    : "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
    : "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
    : "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
    : "${STATE_DIR:=$IMSISTING_ROOT/state}"
    : "${MODULES_DIR:=$IMSISTING_ROOT/modules}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    # `--run <name> [flags]` is routed through the flag parser so both
    # `--run x --dry-run` and `--dry-run x` behave the same way.
    if [[ "${1:-}" == "--run" ]]; then
        shift
        kchn_cli_run_args "$@"
    else
        kchn_cli_main "$@"
    fi
fi
