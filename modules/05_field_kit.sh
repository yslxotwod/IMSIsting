#!/usr/bin/env bash
# field kit — RF pre-flight, honesty verification, and a synthetic signal source
#
# Two jobs, both aimed at a session where you have limited time and possibly no
# radio at all.
#
# 1. HONESTY. This toolkit's whole claim is that it tells you when it did not
#    work. A shielded room is the one place where "there is nothing on the air"
#    is a fact rather than an assumption, so it is the right place to check that
#    every radio-gated verb fails *honestly*: non-zero, naming the missing
#    hardware, and never a fabricated result. `--guard-check` runs exactly that
#    across the tree.
#
# 2. A KNOWN SIGNAL. With no SDR you cannot put real cellular traffic on the air,
#    but every consumer in this tree reads GSMTAP — the same format gr-gsm,
#    srsRAN and Open5GS emit. `--emit` generates a deterministic, spec-shaped
#    GSMTAP stream (GSM BCCH/paging, LTE NAS attach, NR RRC) and sends it to the
#    Live Traffic view or to a pcap. That drives the whole receive-and-decode
#    chain end to end from a signal whose every byte you know.
#
# Resolve IMSISTING_ROOT from this script's own path so state and loot land in
# the project tree even when launched standalone via pkexec.
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

MOD_TMP="$TMP_DIR/field_kit"
FK_DIR="$LOOT_DIR/field_kit"
FK_GUARDS="$FK_DIR/guard-check.tsv"
mkdir -p "$MOD_TMP" "$FK_DIR" 2>/dev/null

FK_PORT=4729

# ── sanitisation ────────────────────────────────────────────────────────
fk_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

FK_F=()
fk_split() {
    FK_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        FK_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── hardware inventory ──────────────────────────────────────────────────
# Two questions that look like one, and answering the first while asking both
# is what made this report claim a radio on a machine with none:
#
#   fk_probe_sdr_tools  which vendor TOOLS are installed. `command -v` is the
#                       right test for that and proves nothing else.
#   fk_probe_radio      which DRIVERS answer a presence probe. A driver on
#                       PATH says the software is installed; `hackrf_info`
#                       exits 1 and prints "No HackRF boards found." with
#                       nothing plugged in, so the probe has to be run.
#
# SoapySDRUtil is deliberately not a presence probe: with no radio attached
# it still reports "Found device 0", because its own audio driver matches any
# machine with a sound card. It stays in the tool inventory, where it is true.
fk_probe_sdr_tools() {
    local d
    for d in hackrf bladeRF LimeUtil uhd_find_devices rtl_test SoapySDRUtil; do
        if command -v "$d" >/dev/null 2>&1; then
            printf '%s\n' "$d"
        fi
    done
}

# One driver, one probe. Returns 0 only when a device answers.
fk_radio_probe() {
    local drv="$1" out
    case "$drv" in
        hackrf)
            command -v hackrf_info >/dev/null 2>&1 || return 1
            out=$(timeout 10 hackrf_info 2>&1) || return 1
            grep -qi 'no hackrf boards found' <<< "$out" && return 1
            return 0 ;;
        bladerf)
            command -v bladeRF-cli >/dev/null 2>&1 || return 1
            out=$(timeout 10 bladeRF-cli -p 2>&1) || return 1
            grep -qi 'no devices are available' <<< "$out" && return 1
            return 0 ;;
        limesdr)
            # LimeUtil --find exits 0 whether or not a board is present, so
            # its exit code carries no information and only its output does.
            command -v LimeUtil >/dev/null 2>&1 || return 1
            out=$(timeout 15 LimeUtil --find 2>&1)
            [[ -n "${out//[[:space:]]/}" ]] ;;
        usrp)
            command -v uhd_find_devices >/dev/null 2>&1 || return 1
            out=$(timeout 15 uhd_find_devices 2>&1)
            grep -qi 'device address' <<< "$out" ;;
        rtl)
            command -v rtl_test >/dev/null 2>&1 || return 1
            out=$(timeout 15 rtl_test 2>&1)
            grep -qiE 'found[[:space:]]+[0-9]+[[:space:]]+device' <<< "$out" ;;
        *) return 1 ;;
    esac
}

# Every driver that actually answered.
fk_probe_radio() {
    local drv
    # Defined but empty is an instruction, not an unset variable: it is how
    # the selftest asserts the no-radio path on a box that has a radio.
    if [[ -n "${FK_SDR_DEVICE+set}" ]]; then
        [[ -n "$FK_SDR_DEVICE" ]] || return 1
        printf '%s\n' "$FK_SDR_DEVICE"; return 0
    fi
    for drv in hackrf bladerf limesdr usrp rtl; do
        fk_radio_probe "$drv" && printf '%s\n' "$drv"
    done
}

fk_probe_tty() {
    local t
    for t in /dev/ttyUSB0 /dev/ttyACM0 /dev/ttyUSB1 /dev/ttyACM1; do
        [[ -e "$t" ]] && printf '%s\n' "$t"
    done
}

# The installed tools, for reports about what is installed.
fk_sdr_label() {
    local l; l=$(fk_probe_sdr_tools | tr '\n' ' ')
    printf '%s' "${l% }"
    [[ -n "${l// /}" ]] || printf 'none'
}

# The radios that answered, for reports about what can be used.
fk_radio_label() {
    local l; l=$(fk_probe_radio | tr '\n' ' ')
    printf '%s' "${l% }"
    [[ -n "${l// /}" ]] || printf 'none'
}

fk_has_sdr() {
    [[ -n "$(fk_probe_radio)" ]]
}

# ── synthetic GSMTAP source ─────────────────────────────────────────────
# Scenarios are built from real message shapes. Every byte is known, which is
# what makes this usable as a signal: you can assert on what comes out the far
# end because you know exactly what went in.
#
#   gsm-idle     BCCH SI3 + paging request
#   gsm-attach   paging + RACH + identity exchange
#   lte-attach   LTE NAS attach request + RRC
#   mixed        all of the above, interleaved
fk_scenario_frames() {
    local scenario="${1:-mixed}"
    local T=$'\t'
    case "$scenario" in
        gsm-idle)
            printf '0x01%s0%s42%s-62%s28%s0x01%s06201b00016202f13039\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s0%s42%s-64%s26%s0x05%s062103310150123456789f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            ;;
        gsm-attach)
            printf '0x01%s0%s42%s-64%s26%s0x05%s062103310150123456789f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s2%s51%s-70%s18%s0x03%s0102030405\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s0%s42%s-68%s24%s0x06%s05310150123456789f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            ;;
        lte-attach)
            printf '0x05%s0%s6300%s-85%s12%s0x00%s0741010bf600f110000000000000\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x04%s0%s6300%s-85%s12%s0x00%saabbccdd\n' "$T" "$T" "$T" "$T" "$T" "$T"
            ;;
        mixed)
            printf '0x01%s0%s42%s-62%s28%s0x01%s06201b00016202f13039\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x05%s0%s6300%s-85%s12%s0x00%s0741010bf600f110000000000000\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s0%s42%s-64%s26%s0x05%s062103310150123456789f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x04%s0%s6300%s-87%s11%s0x00%saabbccdd\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s2%s51%s-70%s18%s0x03%s0102030405\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x05%s0%s6300%s-88%s14%s0x00%s0742010f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            ;;
        imsi-catcher)
            # A high identity-exposure burst: a cell that keeps forcing permanent
            # identities. GSM: a paging-by-IMSI, then repeated RR Identity
            # Requests (msg type 0x15) and CM Service Rejects; LTE: an EMM
            # Identity Request and an Attach Reject with a re-attach cause.
            printf '0x01%s0%s42%s-40%s30%s0x05%s062103310150123456789f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s0%s42%s-41%s29%s0x06%s1510\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s0%s42%s-41%s29%s0x06%s1520\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s0%s42%s-42%s28%s0x06%s1520\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x01%s0%s42%s-42%s28%s0x06%s253f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x05%s0%s6300%s-55%s20%s0x00%s075b01\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x05%s0%s6300%s-55%s20%s0x00%s07440f\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x05%s0%s6300%s-56%s19%s0x00%s075b01\n' "$T" "$T" "$T" "$T" "$T" "$T"
            printf '0x05%s0%s6300%s-56%s19%s0x00%s07440b\n' "$T" "$T" "$T" "$T" "$T" "$T"
            ;;
        *)  printf 'ERROR\tunknown scenario: %s\n' "$scenario" >&2; return 2 ;;
    esac
}

fk_build_gsmtap() {
    python3 - "$@" <<'PY'
import struct, sys
typ, ts, arfcn, sig, snr, sub, payload = sys.argv[1:8]
typ = int(typ, 0); ts = int(ts, 0); arfcn = int(arfcn, 0)
sig = int(sig, 0); snr = int(snr, 0); sub = int(sub, 0)
# Verified against Wireshark's GSMTAP dissector: 16-byte version-2 header,
# hdr_len in 32-bit words, GSM channel in sub_type, uplink as 0x4000 in arfcn.
hdr = struct.pack('!BBBBHbbIBBBB', 2, 4, typ, ts, arfcn, sig, snr, 0, sub, 0, 0, 0)
sys.stdout.write((hdr + bytes.fromhex(payload)).hex())
PY
}

# Emit a scenario. Target is either "udp" (default, to the Live Traffic view) or
# a file path ending in .pcap.
fk_emit() {
    local scenario="${1:-mixed}" count="${2:-1}" delay="${3:-0.15}" target="${4:-udp}"
    [[ "$count" =~ ^[0-9]+$ ]] || count=1
    local frames; frames=$(fk_scenario_frames "$scenario") || return $?
    local n; n=$(printf '%s\n' "$frames" | grep -c .)
    (( n > 0 )) || { printf 'ERROR\tscenario produced no frames\n' >&2; return 1; }

    local hexes=() i
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        fk_split "$line"
        hexes+=("$(fk_build_gsmtap "${FK_F[0]}" "${FK_F[1]}" "${FK_F[2]}" \
                                 "${FK_F[3]}" "${FK_F[4]}" "${FK_F[5]}" "${FK_F[6]}")")
    done <<< "$frames"

    if [[ "$target" == "udp" ]]; then
        python3 - "${delay}" "${count}" "${hexes[@]}" <<'PY'
import socket, sys, time
delay = float(sys.argv[1]); count = int(sys.argv[2]); frames = sys.argv[3:]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sent = 0
for rep in range(count):
    for hx in frames:
        s.sendto(bytes.fromhex(hx), ('127.0.0.1', 4729))
        sent += 1
        time.sleep(delay)
print("sent\t%d" % sent)
PY
    else
        local out="$target"
        mkdir -p "$(dirname "$out")"
        printf '%s\n' "${hexes[@]}" > "$MOD_TMP/frames.txt"
        # A GSMTAP capture is Ethernet/IP/UDP on 4729, which is what Wireshark
        # and 03_gsmtap both expect.
        python3 - "$out" "$MOD_TMP/frames.txt" "$count" "$delay" <<'PY'
import struct, sys
out, ff = sys.argv[1], sys.argv[2]
count = int(sys.argv[3])
# The delay is the gap between frames, exactly as on the udp path: a capture
# that stamped one second per frame whatever was asked for would be a
# different emission from the one the live view just watched.
delay = float(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else 1.0
frames = [l.strip() for l in open(ff) if l.strip()]
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    ts = 0.0
    for rep in range(count):
        for hx in frames:
            g = bytes.fromhex(hx)
            udp = struct.pack('!HHHH', 4729, 4729, 8 + len(g), 0) + g
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                             bytes([10,0,0,1]), bytes([10,0,0,2])) + udp
            eth = bytes.fromhex('001122334455') + bytes.fromhex('66778899aabb') + \
                  struct.pack('!H', 0x0800) + ip
            sec = int(ts)
            f.write(struct.pack('<IIII', sec, int(round((ts - sec) * 1000000)),
                                len(eth), len(eth)))
            f.write(eth)
            ts += delay
print("wrote\t%s" % out)
PY
    fi
}

# ── honesty verification ────────────────────────────────────────────────
# The claim under test: with no radio attached, every radio-gated verb FAILS,
# says why, and returns non-zero. A verb that prints a success line, or that
# returns 0 having done nothing, is the exact bug this toolkit exists to avoid.
#
# Each row: module | verb | args
#
# The matrix contains only verbs that CANNOT legitimately succeed without a
# radio. A verb that is pure computation - --earfcn, --arfcn, --pci - returns 0
# on a machine with no SDR and that is correct behaviour, not fabrication.
# Putting one here would report the module as broken for doing its job.
fk_guard_matrix() {
    cat <<'MATRIX'
01_radio|--record|
02_cell_recon|--scan|gsm||45
06_gsm_air|--decode-pcap|/nonexistent.pcap
07_gsm_attack|--transmit|62||60
10_lte_air|--start|
10_lte_air|--rrc-tx|reconfiguration|LAIR_SDR_DEVICE= LAIR_TX_IQ=|60
10_lte_air|--rrc-tx|reconfiguration|LAIR_SDR_DEVICE=hackrf LAIR_TX_IQ=|60
12_nr_air|--start|
12_nr_air|--gen-gnb-conf|00101 n78 640000 0 --tx||60
12_nr_air|--build-meas-report|measId=1 --tx||60
13_nr_core|--decode-ngap|00
15_downgrade|--detect|/nonexistent.pcap
15_downgrade|--tx-reject|EMM 15 attach|DWN_SDR_DEVICE=|30
20_gsm_cve|--run-cve|CVE-2017-1000250
21_lte_cve|--probe|CVE-2017-6975
22_nr_cve|--run-cve|CVE-2019-1234
26_ss7_map|--decode-msu|00
27_cellular_dns|--detect|/nonexistent.pcap
28_paging_track|--detect|/nonexistent.pcap
28_paging_track|--paging-tx||PGT_SDR_DEVICE=|60
28_paging_track|--paging-storm||PGT_SDR_DEVICE= PGT_STORM_CYCLES=1|120
29_mac_layer|--rnti-track|/nonexistent.pcap
30_volte_ims|--sip-build|||60
30_volte_ims|--sip-send|||60
30_volte_ims|--register-aka|k=465b5ce8b199b49faa5f0a2ee238a6bc op=cdc202d5123e20f62b6d676ac72cb318 rand=23553cbe9637a89d218ae64dae47bf35||30
30_volte_ims|--call|127.0.0.1:9||20
32_nas_signaling|--rate|/nonexistent.pcap
33_jamming_detect|--analyse|/nonexistent.iq
39_ta_geoloc|--trilaterate|/nonexistent.tsv
41_ota_sms|--parse-packet|00
41_ota_sms|--packet-sms||OTASM_KIC_KEY= OTASM_KID_KEY=|60
16_sim|--parse-ota|||60
46_lpp|--forge-position|91,0||30
42_li_probe|--score|/nonexistent.pcap
43_ran_share|--leak-check|/nonexistent.pcap
54_baseband_exploit|--inject|7E0044001F|BEXP_TX_ARMED=1 BEXP_TX_CMD=
55_nr_inject|--inject|7E0044001F|NRJ_TX_ARMED=1 NRJ_TX_CMD=
MATRIX
}

# Decide whether an invocation failed honestly. Honest = non-zero exit OR an
# explicit ERROR/MISSING line. Dishonest = exit 0 AND no error line, i.e. it
# claimed to work.
fk_classify_run() {
    local rc="$1" out="$2"
    if (( rc != 0 )); then
        if printf '%s' "$out" | grep -qE '(^|\t)(ERROR|MISSING|SKIP)|no (SDR|such|capture|radio)|not (found|present|available)'; then
            printf 'honest-fail'
        else
            printf 'silent-fail'      # non-zero but says nothing
        fi
    else
        if printf '%s' "$out" | grep -qE '^ERROR'; then
            printf 'honest-fail'
        else
            printf 'FABRICATED'       # returned 0 - it claims success
        fi
    fi
}

fk_guard_check() {
    local quiet=0
    [[ "${1:-}" == "--quiet" ]] && quiet=1

    printf 'module\tverb\tstatus\tdetail\n' > "$FK_GUARDS"
    local honest=0 silent=0 fabricated=0 missing=0 timedout=0
    local mod verb args envset tmo line

    while IFS='|' read -r mod verb args envset tmo; do
        [[ -z "$mod" ]] && continue

        if [[ ! -x "$IMSISTING_ROOT/modules/$mod.sh" ]]; then
            printf '%s\t%s\tmodule-missing\t-\n' "$mod" "$verb" >> "$FK_GUARDS"
            missing=$((missing + 1))
            (( quiet )) || printf '%-20s %-16s %s\n' "$mod" "$verb" "module missing"
            continue
        fi

        # Fields: mod|verb|args|env|timeout.  The optional 4th field pins the
        # environment for this probe. A TX module is checked with its TX command
        # explicitly empty and its guard armed: that exercises the real "no
        # hardware" branch and makes it impossible for --guard-check to radiate
        # by accident.  The 5th field must exceed the module's OWN internal
        # timeout, otherwise we kill it before it can report honestly and
        # mislabel a slow-but-honest module as silent.  Default 25s.
        tmo="${tmo:-25}"

        # </dev/null is not tidiness. The loop's own stdin is the matrix
        # process substitution, so a probe that calls `read` -- every module
        # with an interactive prompt does -- steals the NEXT ROWS of the
        # matrix. Those rows then never run and the probe is judged on a
        # prompt it received instead of on what it does with no input.
        local out rc
        out=$(timeout "$tmo" env $envset "$IMSISTING_ROOT/modules/$mod.sh" "$verb" $args 2>&1 </dev/null); rc=$?

        # A killed probe is not a verdict about the module. Surface it as its
        # own status rather than folding it into honest/silent.
        local status
        if (( rc == 124 )); then
            status='timeout'
        else
            status=$(fk_classify_run "$rc" "$out")
        fi
        local detail; detail=$(printf '%s' "$out" | grep -oE 'ERROR[[:space:]][^\n]*|no [A-Za-z0-9 /_-]*(SDR|radio|capture)[^\n]*' | head -1)

        case "$status" in
            honest-fail) honest=$((honest + 1)) ;;
            silent-fail) silent=$((silent + 1)) ;;
            FABRICATED)  fabricated=$((fabricated + 1)) ;;
            timeout)     timedout=$((timedout + 1)) ;;
        esac

        printf '%s\t%s\t%s\t%s\n' "$mod" "$verb" "$status" "$(fk_sanitize "$detail")" >> "$FK_GUARDS"

        if (( ! quiet )) || [[ "$status" != "honest-fail" ]]; then
            case "$status" in
                honest-fail) printf '%-20s %-16s \033[38;5;46m%s\033[0m\n' "$mod" "$verb" "$status" ;;
                timeout)     printf '%-20s %-16s \033[38;5;226m%s\033[0m  exceeded %ss\n' "$mod" "$verb" "$status" "$tmo" ;;
                *)           printf '%-20s %-16s \033[38;5;196m%s\033[0m  %s\n' "$mod" "$verb" "$status" "$(fk_sanitize "$detail")" ;;
            esac
        fi
    done < <(fk_guard_matrix)

    printf '\nhonest %d   silent %d   fabricated %d   timeout %d   missing %d\n' \
        "$honest" "$silent" "$fabricated" "$timedout" "$missing"
    printf 'report\t%s\n' "$FK_GUARDS"

    # A fabricated result is the cardinal sin: it returned success with no
    # radio attached. A silent failure is a lesser bug but still a bug.
    (( fabricated == 0 && silent == 0 ))
}

# ── capability ──────────────────────────────────────────────────────────
fk_capability() {
    local sdrs; sdrs=$(fk_sdr_label)
    local radios; radios=$(fk_radio_label)
    local have_radio=no
    fk_has_sdr && have_radio=yes
    local ttys; ttys=$(fk_probe_tty | tr '\n' ' ')
    local pkexec=no
    command -v pkexec >/dev/null 2>&1 && pkexec=yes

    printf 'sdr_tools\t%s\n'   "$sdrs"
    printf 'sdr_devices\t%s\n' "$radios"
    printf 'serial_radios\t%s\n' "${ttys:-none}"
    printf 'can_transmit\t%s\n' "$([[ "$have_radio" == yes ]] && echo unknown || echo no)"
    printf 'pkexec\t%s\n'      "$pkexec"
    printf 'gsmtap_port\t%s\n' "$FK_PORT"
    printf 'gsmtap_consumers\t%s\n' \
        "$(for m in 03_gsmtap 17_pcap_analysis 18_imsi_exposure 28_paging_track; do
             [[ -x "$IMSISTING_ROOT/modules/$m.sh" ]] && printf '%s ' "$m"; done)"
    printf 'software_emitters\t%s\n' \
        "$(for e in grgsm_livemon srsenb gnb srsepc open5gs; do
             command -v "$e" >/dev/null 2>&1 && printf '%s ' "$e"; done)"
    printf 'honest_baseline\t%s\n' "$([[ "$have_radio" == no ]] && echo 'no radio - guards must fail honestly' || echo 'radio present')"
}

# ── selftest ────────────────────────────────────────────────────────────
fk_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" FK_DIR="$d/loot/field_kit" FK_GUARDS="$d/loot/field_kit/guard-check.tsv"

    # 1. The GSMTAP header is the one verified against Wireshark: 16 bytes,
    #    hdr_len 4, GSM channel in sub_type.
    local h h2
    h=$(fk_build_gsmtap 0x01 0 42 -62 28 0x05 "")
    h2=$(fk_build_gsmtap 0x01 0 42 -62 28 0x05 0621)
    chk header-bytes   "$(( ${#h}  / 2 ))" "16"   # 16-byte header, no payload
    chk framing-bytes  "$(( ${#h2} / 2 ))" "18"   # header + 2-byte payload
    # Hand-derivable from the GSMTAP header layout:
    #   02 version | 04 hdr_len(words) | 01 type GSM | 00 timeslot
    #   002a arfcn 42 | c2 signal -62 | 1c snr 28 | 00000000 frame
    #   05 sub_type PCH | 00 00 00 pad
    chk header-exact  "${h:0:32}" "02040100002ac21c0000000005000000"

    # 2. Scenarios produce the frames they claim.
    chk scen-gsm-idle   "$(fk_scenario_frames gsm-idle   | grep -c .)" "2"
    chk scen-gsm-attach "$(fk_scenario_frames gsm-attach | grep -c .)" "3"
    chk scen-lte-attach "$(fk_scenario_frames lte-attach | grep -c .)" "2"
    chk scen-mixed      "$(fk_scenario_frames mixed      | grep -c .)" "6"
    chk scen-bad-rc     "$(fk_scenario_frames nonsense >/dev/null 2>&1; echo $?)" "2"
    # The IMSI-catcher scenario is a high-exposure burst: more identity-bearing
    # frames than the idle baseline, so the Marlin detector has a positive.
    chk scen-catcher    "$(fk_scenario_frames imsi-catcher | grep -c .)" "9"
    chk scen-catcher-gt "$([[ $(fk_scenario_frames imsi-catcher | grep -c .) -gt $(fk_scenario_frames gsm-idle | grep -c .) ]] && echo yes || echo no)" "yes"

    # 3. Emission is deterministic: same scenario, same bytes.
    local a b
    a=$(fk_scenario_frames mixed | while IFS= read -r l; do
            [[ -z "$l" ]] && continue; fk_split "$l"
            fk_build_gsmtap "${FK_F[0]}" "${FK_F[1]}" "${FK_F[2]}" "${FK_F[3]}" "${FK_F[4]}" "${FK_F[5]}" "${FK_F[6]}"
        done | md5sum)
    b=$(fk_scenario_frames mixed | while IFS= read -r l; do
            [[ -z "$l" ]] && continue; fk_split "$l"
            fk_build_gsmtap "${FK_F[0]}" "${FK_F[1]}" "${FK_F[2]}" "${FK_F[3]}" "${FK_F[4]}" "${FK_F[5]}" "${FK_F[6]}"
        done | md5sum)
    chk emit-deterministic "$a" "$b"

    # 4. Emit to a pcap, then decode with 03_gsmtap and assert the round trip.
    #    This is the known-signal test: every byte in is known, so every frame
    #    out is checkable.
    local pc="$d/mixed.pcap"
    local w; w=$(fk_emit mixed 1 0 "$pc")
    chk emit-wrote "$(fld "$w" wrote)" "$pc"
    chk pcap-exists "$([[ -s "$pc" ]] && echo yes || echo no)" "yes"

    local gtap="$IMSISTING_ROOT/modules/03_gsmtap.sh"
    if [[ -x "$gtap" ]]; then
        local dec store rows
        dec=$(timeout 90 "$gtap" --read "$pc" 2>&1)
        store=$(printf '%s\n' "$dec" | awk -F'\t' '$1=="store"{print $2; exit}')
        chk decode-store "$([[ -n "$store" && -s "$store" ]] && echo yes || echo no)" "yes"
        if [[ -n "$store" && -s "$store" ]]; then
            rows=$(tail -n +2 "$store" | grep -c . || true)
            chk decode-rows "$rows" "6"
            # Channel names must survive the round trip: three GSM frames carry
            # a real channel, three LTE frames carry none.
            chk decode-bcch  "$(awk -F'\t' '$3=="BCCH"' "$store" | grep -c . || true)" "1"
            chk decode-pch   "$(awk -F'\t' '$3=="PCH"'  "$store" | grep -c . || true)" "1"
            chk decode-rach  "$(awk -F'\t' '$3=="RACH"' "$store" | grep -c . || true)" "1"
            chk decode-nogsm "$(awk -F'\t' '$3=="-"'    "$store" | grep -c . || true)" "3"
            # Byte fidelity: every payload emitted must appear in the store.
            local missing=0 pay
            while IFS= read -r pay; do
                [[ -z "$pay" ]] && continue
                awk -F'\t' -v p="$pay" 'NR>1 && $11==p{f=1} END{exit !f}' "$store" \
                    || { missing=$((missing + 1)); printf '  payload missing: %s\n' "$pay"; }
            done < <(fk_scenario_frames mixed | cut -f7)
            chk decode-payloads "$missing" "0"
        fi
    else
        printf 'decode-roundtrip\tSKIP (03_gsmtap not executable)\n'
    fi

    # 5. The classifier must separate an honest failure from a fabricated one.
    #    Both directions - a classifier that always says "honest" is useless.
    chk cls-nonzero-says   "$(fk_classify_run 1 'ERROR\tno SDR found')" "honest-fail"
    chk cls-nonzero-silent "$(fk_classify_run 1 '')" "silent-fail"
    chk cls-zero-error     "$(fk_classify_run 0 'ERROR\tstopped')" "honest-fail"
    chk cls-zero-silent    "$(fk_classify_run 0 'OK\tall good')" "FABRICATED"

    # 6. Guard check over a synthetic matrix, not the live tree: build a fake
    #    module dir so the assertion does not depend on what hardware exists.
    local fake="$d/modules"; mkdir -p "$fake"
    printf '#!/bin/sh\necho "ERROR\tno SDR - hackrf_info not found" >&2\nexit 1\n' > "$fake/aa_honest.sh"
    printf '#!/bin/sh\necho "OK\tall good"\nexit 0\n'                                > "$fake/bb_fabricated.sh"
    printf '#!/bin/sh\nexit 3\n'                                                       > "$fake/cc_silent.sh"
    chmod +x "$fake"/*.sh
    local rc_a out_a rc_b out_b rc_c out_c
    out_a=$("$fake/aa_honest.sh"     2>&1); rc_a=$?
    out_b=$("$fake/bb_fabricated.sh" 2>&1); rc_b=$?
    out_c=$("$fake/cc_silent.sh"     2>&1); rc_c=$?
    chk guard-honest     "$(fk_classify_run $rc_a "$out_a")" "honest-fail"
    chk guard-fabricated "$(fk_classify_run $rc_b "$out_b")" "FABRICATED"
    chk guard-silent     "$(fk_classify_run $rc_c "$out_c")" "silent-fail"

    # 7. Capability report shape.
    local cap; cap=$(fk_capability)
    chk cap-sdr    "$(fld "$cap" sdr_tools)"    "$(fk_sdr_label)"
    chk cap-radio  "$(fld "$cap" sdr_devices)"  "$(fk_radio_label)"
    chk cap-port   "$(fld "$cap" gsmtap_port)"  "4729"
    chk cap-base   "$(printf '%s' "$cap" | grep -c '^honest_baseline')" "1"

    # 7b. The presence probe must answer "is a radio attached", not "is the
    #     tool installed" -- that conflation is what made this report claim a
    #     radio on a machine with none. Both directions, because a probe that
    #     can only refuse is not a probe.
    local fbin="$d/bin"; mkdir -p "$fbin"
    : > "$fbin/hackrf"; chmod +x "$fbin/hackrf"
    printf '#!/bin/sh\necho "No HackRF boards found."\nexit 1\n' > "$fbin/hackrf_info"
    chmod +x "$fbin/hackrf_info"
    chk probe-tools-noradio \
        "$(PATH="$fbin:$PATH" fk_probe_sdr_tools | grep -c '^hackrf$')" "1"
    chk probe-noradio \
        "$(PATH="$fbin:$PATH" fk_radio_probe hackrf >/dev/null 2>&1; echo $?)" "1"
    printf '#!/bin/sh\necho "Found HackRF"\necho "Board ID Number: 2 (HackRF One)"\nexit 0\n' \
        > "$fbin/hackrf_info"
    chmod +x "$fbin/hackrf_info"
    chk probe-radio \
        "$(PATH="$fbin:$PATH" fk_radio_probe hackrf >/dev/null 2>&1; echo $?)" "0"
    # The override is how a test asserts the no-radio path on a box that has
    # a radio, and defined-but-empty is an instruction rather than unset.
    chk probe-override-on  "$(FK_SDR_DEVICE=hackrf fk_radio_label)" "hackrf"
    chk probe-override-off "$(FK_SDR_DEVICE= fk_radio_label)"       "none"
    chk probe-override-rc  "$(FK_SDR_DEVICE= fk_has_sdr; echo $?)"  "1"

    # 8. Argument validation.
    chk emit-bad-scenario "$(fk_emit nonsense 1 0 "$d/x.pcap" >/dev/null 2>&1; echo $?)" "2"

    trap - EXIT
    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
fk_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== field kit ===${C_RESET}"
        echo -e "  sdr:   ${C_GRN}$(fk_probe_sdr_tools | tr '\n' ' ' | sed 's/^$/none/')${C_RESET}"
        echo -e "  radio: ${C_GRN}$(fk_radio_label)${C_RESET}\n"
        cat << 'M'
  [1]  capability report
  [2]  guard check — do radio verbs fail honestly?
  [3]  emit synthetic GSMTAP (mixed) to the Live Traffic view
  [4]  emit synthetic GSMTAP (lte-attach)
  [5]  write a synthetic GSMTAP pcap
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) fk_capability | column -t -s$'\t' 2>/dev/null || fk_capability
               read -rp "  press enter " _ ;;
            2) fk_guard_check; read -rp "  press enter " _ ;;
            3) fk_emit mixed 1 0.2 udp; read -rp "  press enter " _ ;;
            4) fk_emit lte-attach 1 0.2 udp; read -rp "  press enter " _ ;;
            5) fk_emit mixed 1 0 "$CAPTURES_DIR/fieldkit_$(date +%Y%m%d_%H%M%S).pcap"
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
fk_cli_status_tsv() {
    printf 'sdr\t%s\n'      "$(fk_sdr_label)"
    printf 'radio\t%s\n'    "$(fk_radio_label)"
    printf 'serial\t%s\n'   "$(fk_probe_tty | tr '\n' ' ' | sed 's/^$/none/')"
    printf 'guards\t%s\n'   "$FK_GUARDS"
    printf 'port\t%s\n'     "$FK_PORT"
}

fk_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    fk_cli_status_tsv ;;
        --capability)    fk_capability ;;
        --guard-check)   fk_guard_check "$@" ;;
        --emit)          fk_emit "${1:-mixed}" "${2:-1}" "${3:-0.2}" "${4:-udp}" ;;
        --scenarios)     fk_scenario_frames gsm-idle >/dev/null && \
                         printf 'gsm-idle\ngsm-attach\nlte-attach\nimsi-catcher\nmixed\n' ;;
        --selftest)      fk_selftest ;;
        --menu)          fk_menu ;;
        *)
            cat >&2 <<EOF
Field Kit — RF pre-flight, honesty check, and a synthetic signal source

Usage: $0 COMMAND
  --capability            what radio hardware is present, and what it means
  --guard-check [--quiet] run every radio-gated verb and verify it fails
                          honestly (non-zero, naming the missing hardware)
                          rather than fabricating a result
  --emit [SCENARIO] [N] [DELAY] [udp|FILE.pcap]
                          generate a deterministic GSMTAP stream
  --scenarios             list the built-in scenarios
  --status-tsv            capability state as TSV
  --selftest              verify the codec, the scenarios and the classifier
  --menu                  interactive menu

Scenarios: gsm-idle, gsm-attach, lte-attach, imsi-catcher, mixed
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
    fk_cli_main "$@"
fi
