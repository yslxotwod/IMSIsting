#!/usr/bin/env bash
# SDR / radio device manager — the cellular equivalent of an interface manager.
#
# Enumerates attached software defined radios through each vendor's own probe
# tool, reports what each device can actually do (frequency range, sample
# rate, gain, direction), arbitrates band coverage, writes the selected
# device to the shared $TMP_DIR/sdr_device, and records IQ.
#
# Direction matters more here than anywhere else in the toolkit: an RTL-SDR
# receives and cannot transmit, so an attack vector built on one fails at the
# first transmit. Every row says which it is, and every verb that needs TX
# refuses by name rather than dying quietly inside a vendor CLI.
#
# Resolve IMSISTING_ROOT from this script's own path so state and captures
# land in the project tree even when launched standalone via pkexec.
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

RADIO_DIR="$LOOT_DIR/radio"
RADIO_TMP="$TMP_DIR/radio"
mkdir -p "$RADIO_DIR" "$RADIO_TMP" 2>/dev/null

# ── shared cross-module state (see MODULE_CONVENTIONS.md §2) ────────────
RADIO_SDR_STATE="$TMP_DIR/sdr_device"       # <driver>\t<serial>\t<index>
RADIO_GAIN_STATE="$TMP_DIR/sdr_gain"
RADIO_FREQ_STATE="$TMP_DIR/sdr_freq"
RADIO_RATE_STATE="$TMP_DIR/sdr_rate"
RADIO_CACHE="$RADIO_TMP/roster.tsv"         # last successful enumeration
RADIO_LOCK_DIR="${RADIO_LOCK_DIR:-$TMP_DIR/radio.lock}"

# ── radio ownership ─────────────────────────────────────────────────────
# A vendor utility generally opens an SDR exclusively. Claiming ownership
# here prevents two modules from producing confusing "device busy" failures.
radio_lock_read() {
    [[ -f "$RADIO_LOCK_DIR/owner.tsv" ]] || return 1
    cat "$RADIO_LOCK_DIR/owner.tsv"
}

radio_lock_field() {
    radio_lock_read 2>/dev/null | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'
}

radio_lock_pid_alive() {
    local pid="${1:-}"
    [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

radio_lock_claim() {
    local owner="${1:-}" pid="${2:-$$}" started device existing_owner existing_pid
    [[ -n "$owner" ]] || { printf 'ERROR\tusage: --lock-claim OWNER [PID]\n' >&2; return 2; }
    [[ "$pid" =~ ^[0-9]+$ ]] || { printf 'ERROR\tPID must be numeric\n' >&2; return 2; }
    owner=$(radio_sanitize "$owner")

    if mkdir "$RADIO_LOCK_DIR" 2>/dev/null; then
        started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        device=$(radio_selected 2>/dev/null || echo none)
        printf 'owner\t%s\npid\t%s\nstarted\t%s\ndevice\t%s\n' \
            "$owner" "$pid" "$started" "$(radio_sanitize "$device")" > "$RADIO_LOCK_DIR/owner.tsv" || {
            rm -rf "$RADIO_LOCK_DIR"; printf 'ERROR\tcannot write radio lock\n' >&2; return 1; }
        printf 'lock\tclaimed\nowner\t%s\npid\t%s\n' "$owner" "$pid"
        return 0
    fi

    existing_owner=$(radio_lock_field owner)
    existing_pid=$(radio_lock_field pid)
    if ! radio_lock_pid_alive "$existing_pid"; then
        rm -rf "$RADIO_LOCK_DIR" 2>/dev/null || {
            printf 'ERROR\tstale radio lock cannot be removed\n' >&2; return 1; }
        radio_lock_claim "$owner" "$pid"
        return $?
    fi
    if [[ "$existing_owner" == "$owner" && "$existing_pid" == "$pid" ]]; then
        printf 'lock\talready-owned\nowner\t%s\npid\t%s\n' "$owner" "$pid"
        return 0
    fi
    printf 'ERROR\tradio owned by %s (pid %s)\n' \
        "$(radio_sanitize "$existing_owner")" "$(radio_sanitize "$existing_pid")" >&2
    return 1
}

radio_lock_release() {
    local owner="${1:-}" existing
    [[ -n "$owner" ]] || { printf 'ERROR\tusage: --lock-release OWNER\n' >&2; return 2; }
    [[ -d "$RADIO_LOCK_DIR" ]] || { printf 'lock\tnone\n'; return 0; }
    existing=$(radio_lock_field owner)
    if [[ "$existing" != "$(radio_sanitize "$owner")" ]]; then
        printf 'ERROR\tlock belongs to %s, not %s\n' \
            "$(radio_sanitize "$existing")" "$(radio_sanitize "$owner")" >&2
        return 1
    fi
    rm -rf "$RADIO_LOCK_DIR" || return 1
    printf 'lock\treleased\nowner\t%s\n' "$(radio_sanitize "$owner")"
}

radio_lock_recover() {
    local pid
    [[ -d "$RADIO_LOCK_DIR" ]] || { printf 'lock\tnone\n'; return 0; }
    pid=$(radio_lock_field pid)
    if radio_lock_pid_alive "$pid"; then
        printf 'ERROR\tlock is live (pid %s)\n' "$pid" >&2; return 1
    fi
    rm -rf "$RADIO_LOCK_DIR" || return 1
    printf 'lock\trecovered\n'
}

radio_lock_status_tsv() {
    local owner pid started device state
    if [[ ! -d "$RADIO_LOCK_DIR" ]]; then
        printf 'state\tfree\nowner\tnone\npid\t-\nstarted\t-\ndevice\t-\n'
        return 0
    fi
    owner=$(radio_lock_field owner); pid=$(radio_lock_field pid)
    started=$(radio_lock_field started); device=$(radio_lock_field device)
    if radio_lock_pid_alive "$pid"; then state=locked; else state=stale; fi
    printf 'state\t%s\nowner\t%s\npid\t%s\nstarted\t%s\ndevice\t%s\n' \
        "$state" "$(radio_sanitize "$owner")" "$(radio_sanitize "$pid")" \
        "$(radio_sanitize "$started")" "$(radio_sanitize "$device")"
}

radio_processes_tsv() {
    printf 'pid\tcommand\n'
    ps -eo pid=,args= 2>/dev/null | awk '
        /hackrf_transfer|rtl_sdr|bladeRF-cli|LimeUtil|uhd_rx|SoapySDRUtil|rx_samples_to_file/ && $0 !~ /awk/ {
            pid=$1; sub(/^[[:space:]]*[0-9]+[[:space:]]+/, ""); gsub(/[\t\r\n]/, " "); print pid "\t" $0
        }'
}

# ── sanitisation ────────────────────────────────────────────────────────
# Device serial numbers come from the hardware itself. A malformed EEPROM or
# a hostile device can carry a tab and forge a row in every consumer that
# splits on tab.
radio_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ═══════════════════════════════════════════════════════════════════
#  vendor probe table
#
#  Driver     | probe command                | direction | TX-capable
#  The commands are the real vendor CLIs; each is run with a short timeout
#  because a wedged USB device otherwise hangs the whole module.
# ═══════════════════════════════════════════════════════════════════

# pluto is listed before soapy because it is a specific device with its own
# control surface (iio over USB or Ethernet); soapy is the catch-all.
RADIO_DRIVERS=(hackrf bladerf limesdr usrp rtlsdr pluto soapy)

radio_probe_cmd() {
    case "$1" in
        hackrf)  echo "hackrf_info" ;;
        bladerf) echo "bladeRF-cli" ;;
        limesdr) echo "LimeUtil" ;;
        usrp)    echo "uhd_find_devices" ;;
        rtlsdr)  echo "rtl_test" ;;
        pluto*)  echo "iio_info" ;;
        soapy)   echo "SoapySDRUtil" ;;
        *)       echo "" ;;
    esac
}

radio_direction() {
    case "$1" in
        rtlsdr) echo "RX" ;;
        # AD9361/AD9363 boards transmit on the second chain: ADALM-PLUTO has
        # one RX and one TX, the Pluto+/LibreSDR boards have two of each.
        pluto*) echo "RX/TX" ;;
        *)      echo "RX/TX" ;;
    esac
}

radio_can_tx() {
    [[ "$(radio_direction "$1")" == "RX/TX" ]]
}

# Vendor probe arguments. `hackrf_info` needs none, `bladeRF-cli` needs
# `-p` (probe) because a bare invocation opens an interactive shell.
radio_probe_args() {
    case "$1" in
        hackrf)  printf '%s\n' "" ;;
        bladerf) printf '%s\n' "-p" ;;
        limesdr) printf '%s\n' "--find" ;;
        usrp)    printf '%s\n' "" ;;
        rtlsdr)  printf '%s\n' "-t" ;;
        pluto*)  printf '%s\n' "-s" ;;
        soapy)   printf '%s\n' "--find" ;;
        *)       printf '%s\n' "" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  enumeration
#
#  One TSV row per attached device:
#    driver serial freq_min freq_max rate_min rate_max gain_min gain_max dir
#  Empty range cells mean "the probe does not report it", which is a real
#  answer for several vendors; it is never filled in with a guess.
# ═══════════════════════════════════════════════════════════════════

radio_header() {
    printf 'driver\tserial\tfreq_min_mhz\tfreq_max_mhz\trate_min_msps\trate_max_msps\tgain_min_db\tgain_max_db\tdirection\n'
}

# Each vendor tool prints its own shape. These parsers are written against
# the real output of each tool, not against an idealised one.

# hackrf_info:      "Serial number: 0000000000000000a06063dc2b1e5e8f"
radio_parse_hackrf() {
    local txt="$1"
    local sn fmin fmax rmin rmax gmin gmax
    sn=$(printf '%s\n' "$txt"    | sed -n 's/^Serial number:[[:space:]]*//p' | head -1 | tr -d '\r')
    fmin=$(printf '%s\n' "$txt"  | sed -n 's/^.*[Ff]req.*[Mm]in.*:[[:space:]]*//p' | head -1)
    rmax=$(printf '%s\n' "$txt"  | sed -n 's/^.*[Ss]ample.*[Rr]ate.*:[[:space:]]*//p'    | head -1)
    # HackRF One is 1 MHz - 6 GHz, up to 20 Msps, 0-40 dB (14-bit) / 0-62 dB.
    fmin=$(printf '%s' "${fmin:-1}");       fmin="${fmin%% *}"
    fmax=$(printf '%s' "6000")
    rmin="2"; rmax="${rmax%% *}"; [[ -z "$rmax" || ! "$rmax" =~ ^[0-9] ]] && rmax="20"
    gmin="0"; gmax="62"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "hackrf" "$(radio_sanitize "${sn:-unknown}")" "$fmin" "$fmax" \
        "$rmin" "$rmax" "$gmin" "$gmax" "$(radio_direction hackrf)"
}

# bladeRF-cli -p:   "  Serial:        a1b2c3..." plus a "Frequency Range:" block
radio_parse_bladerf() {
    local txt="$1"
    local sn
    sn=$(printf '%s\n' "$txt" | sed -n 's/^[[:space:]]*Serial:[[:space:]]*//p' | head -1 | tr -d '\r')
    # bladeRF x40/x115 cover 300 MHz - 3.8 GHz, 0.52 - 61.44 Msps, -15..60 dB
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "bladerf" "$(radio_sanitize "${sn:-unknown}")" "300" "3800" \
        "0.52" "61.44" "-15" "60" "$(radio_direction bladerf)"
}

# LimeUtil --find:  "  * [LimeSDR-USB, media=USB 3.0, module=FX3, serial=0009..., addr=1d50:6108]"
radio_parse_limesdr() {
    local txt="$1" line sn
    line=$(printf '%s\n' "$txt" | grep -m1 -E '^\s*\*' )
    sn=$(printf '%s\n' "$line" | sed -n 's/.*serial=\([^,]*\).*/\1/p' | tr -d ' ')
    # LimeSDR-USB: 100 kHz - 3.8 GHz, up to 61.44 Msps, -12..61 dB
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "limesdr" "$(radio_sanitize "${sn:-unknown}")" "0.1" "3800" \
        "0.1" "61.44" "-12" "61" "$(radio_direction limesdr)"
}

# uhd_find_devices: "  serial: 30A3D42" and "  type: b200"
radio_parse_usrp() {
    local txt="$1" sn
    sn=$(printf '%s\n' "$txt" | sed -n 's/^[[:space:]]*serial:[[:space:]]*//p' | head -1 | tr -d '\r')
    # B200/B210: 70 MHz - 6 GHz, 200 - 61.44e6 Msps, 0..76 dB
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "usrp" "$(radio_sanitize "${sn:-unknown}")" "70" "6000" \
        "0.2" "61.44" "0" "76" "$(radio_direction usrp)"
}

# rtl_test -t: "Found 1 device(s):  0:  Realtek, RTL2838UHIDIR, SN: 00000001"
radio_parse_rtlsdr() {
    local txt="$1" sn n
    sn=$(printf '%s\n' "$txt" | sed -n 's/.*SN:[[:space:]]*\([A-Za-z0-9]*\).*/\1/p' | head -1 | tr -d '\r')
    n=$(printf '%s\n' "$txt" | grep -cE '^[[:space:]]*[0-9]+:[[:space:]]')
    (( n == 0 )) && n=1
    # RTL2832U: 24 - 1766 MHz, 0.225 - 2.4 Msps, 0 - 49.6 dB, RECEIVE ONLY.
    local i
    for (( i = 0; i < n; i++ )); do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "rtlsdr" "$(radio_sanitize "${sn:-$i}")" "24" "1766" \
            "0.225" "2.4" "0" "49.6" "RX"
    done
}

# SoapySDRUtil --find: "  Found device 0" / "    driver = rtlsdr" /
#                      "    serial = 00000001"
radio_parse_soapy() {
    local txt="$1" idx=0 line drv="" sn="" first=1
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*Found\ device ]]; then
            if (( first == 0 )); then
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "soapy:${drv:-unknown}" "$(radio_sanitize "${sn:-unknown}")" \
                    "0" "0" "0" "0" "0" "0" "$(radio_direction "${drv:-soapy}")"
            fi
            first=0; drv=""; sn=""; idx=$((idx + 1))
            continue
        fi
        [[ "$first" -eq 1 ]] && continue
        if [[ "$line" =~ ^[[:space:]]*driver[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            drv="${BASH_REMATCH[1]}"; drv="${drv%"${drv##*[![:space:]]}"}"
        elif [[ "$line" =~ ^[[:space:]]*serial[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            sn="${BASH_REMATCH[1]}"; sn="${sn%"${sn##*[![:space:]]}"}"
        fi
    done < <(printf '%s\n' "$txt")
    if (( first == 0 )); then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "soapy:${drv:-unknown}" "$(radio_sanitize "${sn:-unknown}")" \
            "0" "0" "0" "0" "0" "0" "$(radio_direction "${drv:-soapy}")"
    fi
}

# iio_info -s:        "  0: 0456:b673 (Analog Devices Inc. PlutoSDR ...), serial=..."
#                     "  1: ip:192.168.2.1 (Analog Devices Inc. PlutoSDR ...)"
#
# The context URI IS the address, so it goes into the driver field the way
# soapy puts its backend driver there: `pluto:ip:192.168.2.1` is reachable over
# Ethernet, `pluto:usb:1.9.5` over USB, and the two are the same board with two
# doors. A board that reports no serial is identified by its URI, which is
# still unique per context.
radio_parse_pluto() {
    local txt="$1" line uri rest sn
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*[0-9]+:[[:space:]]+([^[:space:]]+)[[:space:]]+ ]] || continue
        uri="${BASH_REMATCH[1]}"
        rest="${line#*"$uri"}"
        [[ -n "$uri" ]] || continue
        # serial=<value> when the firmware reports one; a context with none is
        # identified by its URI, which is unique per context on the bus.
        sn=$(printf '%s' "$rest" | sed -n 's/.*serial=\([^][, ]*\).*/\1/p')
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "pluto:${uri}" \
            "$(radio_sanitize "${sn:-$uri}")" \
            "" "" "" "" "" "" \
            "$(radio_direction pluto)"
    done < <(printf '%s\n' "$txt")
}

radio_parse() {
    # radio_parse DRIVER "<probe output>" -> zero or more TSV rows
    case "$1" in
        hackrf)  radio_parse_hackrf  "$2" ;;
        bladerf) radio_parse_bladerf "$2" ;;
        limesdr) radio_parse_limesdr "$2" ;;
        usrp)    radio_parse_usrp    "$2" ;;
        rtlsdr)  radio_parse_rtlsdr  "$2" ;;
        pluto)   radio_parse_pluto   "$2" ;;
        soapy)   radio_parse_soapy   "$2" ;;
        *)       return 1 ;;
    esac
}

# Run one vendor probe. Prints the raw tool output. Returns non-zero when
# the tool is absent (naming it) or when the probe failed.
radio_probe() {
    local drv="$1" tool args out
    tool=$(radio_probe_cmd "$drv")
    [[ -z "$tool" ]] && { printf 'ERROR\tunknown driver %s\n' "$(radio_sanitize "$drv")" >&2; return 2; }
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'MISSING\t%s\t%s probe not installed\n' "$(radio_sanitize "$drv")" "$tool" >&2
        return 1
    fi
    args=$(radio_probe_args "$drv")
    # shellcheck disable=SC2086
    out=$(timeout 20 "$tool" $args 2>&1)
    local rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'ERROR\t%s returned rc=%s with no output\n' "$tool" "$rc" >&2
        return 1
    fi
    printf '%s\n' "$out"
    # A probe that exits non-zero but printed a device list still counts.
    (( rc == 0 )) && return 0
    printf '%s\n' "$out" | grep -qiE 'serial|found|device' && return 0
    return 1
}

# Full roster. Never guesses: a driver whose tool is absent simply produces
# no rows, and --status-tsv records why.
radio_enumerate() {
    local drv out rows
    for drv in "${RADIO_DRIVERS[@]}"; do
        out=$(radio_probe "$drv" 2>/dev/null) || continue
        [[ -z "$out" ]] && continue
        rows=$(radio_parse "$drv" "$out") || continue
        [[ -z "$rows" ]] && continue
        printf '%s\n' "$rows"
    done
}

# Cached enumeration: a probe costs up to 20 s per vendor when a device is
# wedged, so the roster is cached briefly for GUI refreshes.
radio_roster() {
    local max_age="${1:-10}"
    if [[ -f "$RADIO_CACHE" ]]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$RADIO_CACHE" 2>/dev/null || echo 0) ))
        if (( age < max_age )); then cat "$RADIO_CACHE"; return 0; fi
    fi
    local rows; rows=$(radio_enumerate)
    if [[ -n "$rows" ]]; then
        printf '%s\n' "$rows" > "$RADIO_CACHE"
    else
        : > "$RADIO_CACHE"
    fi
    printf '%s\n' "$rows"
}

radio_count() {
    radio_roster | grep -c . || true
}

# hmm: grep -c on empty input prints 0 and exits 1, so guard with || true.
radio_device_row() {
    # radio_device_row <index|driver|serial>
    local want="$1" i=0 row
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        local drv sn
        drv=$(printf '%s\n' "$row" | cut -f1)
        sn=$(printf '%s\n' "$row" | cut -f2)
        if [[ "$want" == "$i" || "$want" == "$drv" || "$want" == "$sn" ]]; then
            printf '%s\n' "$row"; return 0
        fi
        i=$((i + 1))
    done < <(radio_roster)
    return 1
}

radio_selected() {
    [[ -s "$RADIO_SDR_STATE" ]] || return 1
    head -n1 "$RADIO_SDR_STATE"
}

radio_selected_driver() {
    local s; s=$(radio_selected) || return 1
    printf '%s\n' "$s" | cut -f1
}

# ═══════════════════════════════════════════════════════════════════
#  band classification
#
#  Downlink frequencies, from 3GPP. An unknown frequency is reported as
#  "unsupported" rather than being bent into the nearest band: a survey
#  that invents a band is worse than one that admits it does not know.
# ═══════════════════════════════════════════════════════════════════

RADIO_BANDS=(
    "GSM850|869|894|2G"
    "GSM900|925|960|2G"
    # Order is load-bearing throughout this table: the first band whose edges
    # contain the frequency wins, so where two bands overlap the narrower one
    # is listed first (n78 inside n77, n261 inside n257) and where two names
    # describe the same spectrum the more specific generation is listed first
    # (LTE-B3 before GSM1800 for 1805-1880).
    "GSM1900|1930|1990|2G"
    "UMTS-B1|2110|2170|3G"
    "LTE-B1|2110|2170|4G"
    "LTE-B3|1805|1880|4G"
    "GSM1800|1805|1880|2G"
    "LTE-B7|2620|2690|4G"
    "LTE-B8|925|960|4G"
    "LTE-B20|791|821|4G"
    "LTE-B28|758|803|4G"
    "LTE-B38|2570|2620|4G"
    "LTE-B40|2300|2400|4G"
    "LTE-B41|2496|2690|4G"
    "NR-n1|2110|2170|5G"
    "NR-n3|1805|1880|5G"
    "NR-n28|758|803|5G"
    "NR-n41|2496|2690|5G"
    "NR-n78|3300|3800|5G"
    "NR-n77|3300|4200|5G"
    "NR-n79|4400|5000|5G"
    "NR-FR2-n261|27500|28350|5G-FR2"
    "NR-FR2-n257|26500|29500|5G-FR2"
    "NR-FR2-n258|24250|27500|5G-FR2"
    "NR-FR2-n260|37000|40000|5G-FR2"
)

# radio_band_of MHZ -> "name gen" or "unsupported unknown"
radio_band_of() {
    local mhz="$1" e
    [[ "$mhz" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'unsupported unknown'; return 1; }
    # awk does the float compare so "0.925" and "925" both work.
    e=$(awk -v f="$mhz" 'BEGIN{
        # Same order as RADIO_BANDS above; first match wins.
        n = split("GSM850 869 894 2G|GSM900 925 960 2G|GSM1900 1930 1990 2G|" \
                  "UMTS-B1 2110 2170 3G|LTE-B1 2110 2170 4G|" \
                  "LTE-B3 1805 1880 4G|GSM1800 1805 1880 2G|LTE-B7 2620 2690 4G|LTE-B8 925 960 4G|" \
                  "LTE-B20 791 821 4G|LTE-B28 758 803 4G|LTE-B38 2570 2620 4G|" \
                  "LTE-B40 2300 2400 4G|LTE-B41 2496 2690 4G|NR-n1 2110 2170 5G|" \
                  "NR-n3 1805 1880 5G|NR-n28 758 803 5G|NR-n41 2496 2690 5G|" \
                  "NR-n78 3300 3800 5G|NR-n77 3300 4200 5G|NR-n79 4400 5000 5G|" \
                  "NR-FR2-n261 27500 28350 5G-FR2|NR-FR2-n257 26500 29500 5G-FR2|" \
                  "NR-FR2-n258 24250 27500 5G-FR2|NR-FR2-n260 37000 40000 5G-FR2",
                  arr, "|")
        for (i = 1; i <= n; i++) {
            split(arr[i], b, " ")
            if (f+0 >= b[2]+0 && f+0 <= b[3]+0) { printf "%s %s", b[1], b[4]; exit 0 }
        }
        exit 1
    }') || { printf 'unsupported unknown'; return 1; }
    printf '%s' "$e"
    return 0
}

radio_band_name() { radio_band_of "$1" | cut -d' ' -f1; }
radio_band_gen()  { radio_band_of "$1" | cut -d' ' -f2; }

# FR2 needs mmWave hardware and an external mixer on almost every SDR in
# this toolkit's roster. Saying so by name is the whole point.
radio_needs_mmwave() {
    [[ "$(radio_band_gen "$1")" == "5G-FR2" ]]
}

# ── coverage ────────────────────────────────────────────────────────────
radio_covers() {
    # radio_covers "<roster row>" <mhz>
    local row="$1" mhz="$2" fmin fmax
    fmin=$(printf '%s\n' "$row" | cut -f3)
    fmax=$(printf '%s\n' "$row" | cut -f4)
    [[ -z "$fmin" || -z "$fmax" ]] && return 1
    awk -v f="$mhz" -v a="$fmin" -v b="$fmax" 'BEGIN{ exit !(f+0 >= a+0 && f+0 <= b+0) }'
}

radio_any_covers() {
    local mhz="$1" row
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        radio_covers "$row" "$mhz" && return 0
    done < <(radio_roster)
    return 1
}

# ═══════════════════════════════════════════════════════════════════
#  control commands
#
#  The vendor-specific spelling for setting centre frequency, sample rate
#  and gain. Printed for the selected device (or a named driver) so another
#  module can run it, and used directly by --set-* when hardware is present.
# ═══════════════════════════════════════════════════════════════════

radio_freq_cmd() {
    # radio_freq_cmd DRIVER HZ|MHZ_VALUE_FMT(Hz)
    case "$1" in
        hackrf)  printf 'hackrf_transfer -f %s -a 1 -l 40 -g 40 -s 20000000 -n 0 (or: hackrf_sweep / gr-fosphor tuned with -f %s)' "$2" "$2" ;;
        bladerf) printf 'bladeRF-cli -e "set frequency rx %s; set frequency tx %s"' "$2" "$2" ;;
        limesdr) printf 'LimeUtil --set-frequency=%s (or: SoapySDRUtil --args="driver=lime" --frequency=%s)' "$2" "$2" ;;
        usrp)    printf 'uhd_find_devices; set via uhd: rx_freq=%s (use tx_freq=%s to transmit)' "$2" "$2" ;;
        rtlsdr)  printf 'rtl_sdr -f %s -s 2048000 -g 40 capture.iq  # RX ONLY' "$2" ;;
        pluto*)  printf 'iio_attr -u %s -c ad9361-phy altvoltage0 frequency %s   # RX LO; TX LO is altvoltage1' \
                     "${1#pluto:}" "$2" ;;
        soapy*)  printf 'SoapySDRUtil --args="driver=%s" --frequency=%s' "${1#soapy:}" "$2" ;;
        *)       printf '' ;;
    esac
}

radio_rate_cmd() {
    case "$1" in
        hackrf)  printf 'hackrf_transfer -s %s' "$2" ;;
        bladerf) printf 'bladeRF-cli -e "set samplerate rx %s; set samplerate tx %s"' "$2" "$2" ;;
        limesdr) printf 'LimeUtil --set-sample-rate=%s' "$2" ;;
        usrp)    printf 'uhd: master_clock_rate=%s, samp_rate=%s' "$2" "$2" ;;
        rtlsdr)  printf 'rtl_sdr -s %s   # max 2.4 Msps, RX ONLY' "$2" ;;
        pluto*)  printf 'iio_attr -u %s -c ad9361-phy -i voltage0 sampling_frequency %s   # 0.52..61.44 Msps' \
                     "${1#pluto:}" "$2" ;;
        soapy*)  printf 'SoapySDRUtil --args="driver=%s" --rate=%s' "${1#soapy:}" "$2" ;;
        *)       printf '' ;;
    esac
}

radio_gain_cmd() {
    case "$1" in
        hackrf)  printf 'hackrf_transfer -l %s -g %s   # IF gain + RF gain, each 0..40' "$2" "$2" ;;
        bladerf) printf 'bladeRF-cli -e "set gain rx %s; set gain tx %s"   # -15..60 dB' "$2" "$2" ;;
        limesdr) printf 'LimeUtil --set-gain=%s   # -12..61 dB' "$2" ;;
        usrp)    printf 'uhd: gain=%s   # B200/B210: 0..76 dB' "$2" ;;
        rtlsdr)  printf 'rtl_sdr -g %s   # 0..49.6 dB, RX ONLY' "$2" ;;
        pluto*)  printf 'iio_attr -u %s -c ad9361-phy -i voltage0 hardwaregain %s   # 0..76 dB, manual gain mode' \
                     "${1#pluto:}" "$2" ;;
        soapy*)  printf 'SoapySDRUtil --args="driver=%s" --gain=%s' "${1#soapy:}" "$2" ;;
        *)       printf '' ;;
    esac
}

# The three control commands for whichever device is selected, plus the
# device's own TX verdict.
radio_control_plan() {
    local drv="$1" f="$2" g="$3" r="$4"
    printf 'driver\t%s\n' "$(radio_sanitize "$drv")"
    printf 'frequency\t%s\n' "$(radio_sanitize "$f")"
    printf 'sample_rate\t%s\n' "$(radio_sanitize "$r")"
    printf 'gain\t%s\n' "$(radio_sanitize "$g")"
    printf 'set_frequency_cmd\t%s\n' "$(radio_sanitize "$(radio_freq_cmd "$drv" "$f")")"
    printf 'set_rate_cmd\t%s\n' "$(radio_sanitize "$(radio_rate_cmd "$drv" "$r")")"
    printf 'set_gain_cmd\t%s\n' "$(radio_sanitize "$(radio_gain_cmd "$drv" "$g")")"
    printf 'direction\t%s\n' "$(radio_direction "$drv")"
    printf 'can_tx\t%s\n' "$(radio_can_tx "$drv" && echo yes || echo no)"
}

# ── shared state ────────────────────────────────────────────────────────
radio_write_state() {
    local drv="$1" sn="$2" idx="$3"
    mkdir -p "$TMP_DIR" 2>/dev/null || {
        printf 'ERROR\tcannot create %s\n' "$TMP_DIR" >&2; return 1; }
    if ! printf '%s\t%s\t%s\n' "$(radio_sanitize "$drv")" "$(radio_sanitize "$sn")" "$idx" > "$RADIO_SDR_STATE"; then
        printf 'ERROR\tcould not write %s (permission denied)\n' "$RADIO_SDR_STATE" >&2
        return 1
    fi
    printf 'OK\t%s\n' "$RADIO_SDR_STATE"
}

radio_record_state() {
    # radio_record_state TYPE VALUE
    local f
    case "$1" in
        freq) f="$RADIO_FREQ_STATE" ;;
        gain) f="$RADIO_GAIN_STATE" ;;
        rate) f="$RADIO_RATE_STATE" ;;
        *) printf 'ERROR\tunknown state %s\n' "$(radio_sanitize "$1")" >&2; return 2 ;;
    esac
    printf '%s\n' "$(radio_sanitize "$2")" > "$f" 2>/dev/null || {
        printf 'ERROR\tcould not write %s\n' "$f" >&2; return 1; }
}

radio_read_state() {
    local f
    case "$1" in
        freq) f="$RADIO_FREQ_STATE" ;;
        gain) f="$RADIO_GAIN_STATE" ;;
        rate) f="$RADIO_RATE_STATE" ;;
        *) return 1 ;;
    esac
    [[ -s "$f" ]] && head -n1 "$f"
    return 0
}

# ═══════════════════════════════════════════════════════════════════
#  IQ capture
# ═══════════════════════════════════════════════════════════════════

# The sample format a driver's capture command actually writes. Every reader in
# the tree takes this as an argument rather than guessing from a filename, and a
# wrong guess silently halves or doubles the sample rate.
radio_capture_format() {
    case "$1" in
        hackrf)  echo "cs8"  ;;
        rtlsdr)  echo "cu8"  ;;
        bladerf) echo "sc16" ;;
        limesdr) echo "cs16" ;;
        usrp)    echo "sc16" ;;
        pluto*)  echo "ci16" ;;
        soapy*)  echo "cf32" ;;
        *)       echo "" ;;
    esac
}

# A driver token that is safe in a filename. `pluto:ip:192.168.2.1` is a driver
# and an address at once, and a colon in a path is not.
radio_slug() {
    printf '%s' "$1" | tr ':/ ' '___' | tr -cd 'A-Za-z0-9._-'
}

# Vendor capture command. Where the vendor CLI cannot capture raw IQ at all
# the function returns non-zero, and the caller writes a plan instead of
# pretending. GNU Radio is the universal fallback and is named in the plan.
# The binaries a driver's capture command runs. A plan is only honest when the
# tools it names are the tools that exist: Pluto needs three, not one.
radio_capture_needs() {
    case "$1" in
        hackrf)  echo "hackrf_transfer" ;;
        rtlsdr)  echo "rtl_sdr" ;;
        bladerf) echo "bladeRF-cli" ;;
        limesdr) echo "LimeUtil" ;;
        usrp)    echo "uhd_find_devices" ;;
        pluto*)  echo "iio_attr iio_readdev" ;;
        soapy*)  echo "SoapySDRUtil" ;;
        *)       echo "" ;;
    esac
}

radio_capture_cmd() {
    local drv="$1" secs="$2" out="$3" hz="$4" rate="$5" gain="$6"
    case "$drv" in
        hackrf)
            printf 'hackrf_transfer -r %s -f %s -s %s -l %s -g %s -n %s' \
                "$out" "$hz" "$rate" "$gain" "$gain" "$(( secs * rate ))" ;;
        bladerf)
            printf 'bladeRF-cli -e "set frequency rx %s; set samplerate rx %s; set gain rx %s; rx config file=%s format=bin n=%s"' \
                "$hz" "$rate" "$gain" "$out" "$(( secs * rate ))" ;;
        limesdr)
            printf 'LimeUtil --capture=%s --freq=%s --rate=%s --gain=%s --duration=%s' \
                "$out" "$hz" "$rate" "$gain" "$secs" ;;
        rtlsdr)
            printf 'rtl_sdr -f %s -s %s -g %s -n %s %s' \
                "$hz" "$rate" "$gain" "$(( secs * rate ))" "$out" ;;
        usrp)
            printf 'uhd: rx_samples_to_file --freq %s --rate %s --gain %s --duration %s --file %s' \
                "$hz" "$rate" "$gain" "$secs" "$out" ;;
        pluto*)
            # iio_readdev streams the two IQ channels as signed 16-bit pairs:
            # the AD9361 is a 12-bit converter, so samples arrive shifted left
            # by four, not scaled to full range. -s is a sample count, -b the
            # kernel buffer, -T a timeout so a dead link cannot hang the caller.
            #
            # The control writes come first and in the same command: iio_attr
            # is libiio's only control surface, gain_control_mode must be
            # manual before hardwaregain means anything, and a capture at the
            # wrong local oscillator is worse than a failed one.
            local uri="${drv#pluto:}"
            printf 'iio_attr -u %s -c ad9361-phy altvoltage0 frequency %s && \
iio_attr -u %s -c ad9361-phy -i voltage0 sampling_frequency %s && \
iio_attr -u %s -c ad9361-phy -i voltage0 gain_control_mode manual && \
iio_attr -u %s -c ad9361-phy -i voltage0 hardwaregain %s && \
iio_readdev -u %s -b 262144 -s %s -T 30 cf-ad9361-lpc voltage0 voltage1 > %s' \
                "$uri" "$hz" "$uri" "$rate" "$uri" "$uri" "$gain" \
                "$uri" "$(( secs * rate ))" "$out" ;;
        soapy*)
            printf 'SoapySDRUtil --args="driver=%s" --rate=%s --frequency=%s --gain=%s --duration=%s --direction=RX --file=%s' \
                "${drv#soapy:}" "$rate" "$hz" "$gain" "$secs" "$out" ;;
        *) return 1 ;;
    esac
}

# The GNU Radio path, for any device soapty/gnuradio supports. Printed as a
# plan when the vendor CLI is missing, because it is genuinely the fallback.
radio_gnuradio_plan() {
    local drv="$1" hz="$2" rate="$3" gain="$4" secs="$5" out="$6"
    cat <<EOF
# GNU Radio alternative (requires gnuradio + gr-osmosdr):
#   gnuradio-companion, or headless:
#   python3 - <<'PY'
#   from gnuradio import gr, blocks
#   from gnuradio import osmosdr
#   tb = gr.top_block()
#   src = osmosdr.source(args="driver=${drv}")
#   src.set_sample_rate(${rate})
#   src.set_center_freq(${hz})
#   src.set_gain(${gain})
#   snk = blocks.file_sink(gr.sizeof_gr_complex, "${out}")
#   tb.connect(src, snk)
#   tb.start(); tb.wait()      # add a head block for a fixed ${secs}s run
#   PY
EOF
}

radio_record_unlocked() {
    local secs="${1:-}" drv hz rate gain
    # `[[ ok ]] && (( n>0 )) || {...}` is NOT an if. It happened to work on a
    # valid argument, but a *missing* one fell through into the no-SDR path and
    # returned 1 where the contract says 2.
    if [[ ! "$secs" =~ ^[0-9]+$ ]] || (( secs <= 0 )); then
        printf 'ERROR\tusage: --record SECONDS (positive integer)\n' >&2
        return 2
    fi
    drv=$(radio_selected_driver) || {
        printf 'ERROR\tno SDR selected — run --select <device> first\n' >&2; return 1; }
    hz=$(radio_read_state freq); hz="${hz:-0}"
    rate=$(radio_read_state rate); rate="${rate:-2000000}"
    gain=$(radio_read_state gain); gain="${gain:-40}"

    local ts out plan
    ts=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$CAPTURES_DIR" 2>/dev/null || {
        printf 'ERROR\tcannot create %s\n' "$CAPTURES_DIR" >&2; return 1; }
    local slug
    slug=$(radio_slug "$drv")
    out="$CAPTURES_DIR/iq_${slug}_${ts}.iq"
    plan="$CAPTURES_DIR/iq_${slug}_${ts}.plan.txt"

    local cmd
    if ! cmd=$(radio_capture_cmd "$drv" "$secs" "$out" "$hz" "$rate" "$gain"); then
        printf 'HANDOFF\t%s\tno capture path for driver\n' "$(radio_sanitize "$drv")"
        {
            printf '# IQ capture plan — driver %s\n' "$(radio_sanitize "$drv")"
            printf '# status: handoff — this driver has no raw-IQ CLI in the roster\n'
            printf '# centre %s Hz, rate %s sps, gain %s dB, %s s -> %s\n' "$hz" "$rate" "$gain" "$secs" "$out"
            radio_gnuradio_plan "$drv" "$hz" "$rate" "$gain" "$secs" "$out"
        } > "$plan"
        printf 'status: handoff\t%s\n' "$plan"
        return 1
    fi

    local need missing=""
    for need in $(radio_capture_needs "$drv"); do
        command -v "$need" >/dev/null 2>&1 || missing="$missing $need"
    done
    if [[ -n "$missing" ]]; then
        printf 'HANDOFF\t%s\t%s not installed\n' \
            "$(radio_sanitize "$drv")" "${missing# }"
        {
            printf '# IQ capture plan — driver %s\n' "$(radio_sanitize "$drv")"
            printf '# status: handoff — missing: %s\n' "${missing# }"
            printf '# install it with: 00_deps.sh --install-package %s\n' "${missing# }"
            printf '# centre %s Hz, rate %s sps, gain %s dB, %s s -> %s\n' "$hz" "$rate" "$gain" "$secs" "$out"
            printf '# vendor command: %s\n' "$(radio_sanitize "$cmd")"
            radio_gnuradio_plan "$drv" "$hz" "$rate" "$gain" "$secs" "$out"
        } > "$plan"
        printf 'status: handoff\t%s\n' "$plan"
        return 1
    fi

    if command -v "$(radio_probe_cmd "$drv")" >/dev/null 2>&1; then
        info "recording ${secs}s of IQ from $drv to $out"
        # The vendor command is run through bash -c so quoted -e strings work.
        if bash -c "$cmd" >/dev/null 2>&1; then
            if [[ -s "$out" ]]; then
                printf 'OK\t%s\t%s\n' "$out" "$(stat -c %s "$out" 2>/dev/null || echo 0)"
                printf 'format\t%s\n' "$(radio_capture_format "$drv")"
                return 0
            fi
            printf 'ERROR\t%s produced no data (radio busy or not streaming)\n' "$out" >&2
            return 1
        fi
        printf 'ERROR\tcapture command failed: %s\n' "$(radio_sanitize "$cmd")" >&2
        return 1
    fi

    printf 'HANDOFF\t%s\t%s not installed\n' "$(radio_sanitize "$drv")" "$(radio_probe_cmd "$drv")"
    {
        printf '# IQ capture plan — driver %s\n' "$(radio_sanitize "$drv")"
        printf '# status: handoff — %s is not installed\n' "$(radio_probe_cmd "$drv")"
        printf '# install it with: 00_deps.sh --install-package %s\n' "$(radio_probe_cmd "$drv")"
        printf '# centre %s Hz, rate %s sps, gain %s dB, %s s -> %s\n' "$hz" "$rate" "$gain" "$secs" "$out"
        printf '# vendor command: %s\n' "$(radio_sanitize "$cmd")"
        radio_gnuradio_plan "$drv" "$hz" "$rate" "$gain" "$secs" "$out"
    } > "$plan"
    printf 'status: handoff\t%s\n' "$plan"
    return 1
}

radio_record() {
    local owner="radio-record-$$" rc
    radio_lock_claim "$owner" "$$" >/dev/null || return $?
    radio_record_unlocked "$@"; rc=$?
    radio_lock_release "$owner" >/dev/null 2>&1 || true
    return "$rc"
}

# ═══════════════════════════════════════════════════════════════════
#  CLI verbs
# ═══════════════════════════════════════════════════════════════════

radio_cli_status_tsv() {
    local n sel probe_missing=""
    n=$(radio_count)
    sel=$(radio_selected 2>/dev/null) || sel=""
    local drv tool
    for drv in "${RADIO_DRIVERS[@]}"; do
        tool=$(radio_probe_cmd "$drv")
        command -v "$tool" >/dev/null 2>&1 || probe_missing="$probe_missing $tool"
    done
    printf 'devices\t%s\n' "$n"
    printf 'selected\t%s\n' "$(radio_sanitize "$sel")"
    printf 'selected_driver\t%s\n' "$(radio_sanitize "$(radio_selected_driver 2>/dev/null || echo none)")"
    printf 'can_tx\t%s\n' "$(local d; d=$(radio_selected_driver 2>/dev/null) && radio_can_tx "$d" && echo yes || echo no)"
    printf 'freq_hz\t%s\n' "$(radio_read_state freq)"
    printf 'gain_db\t%s\n' "$(radio_read_state gain)"
    printf 'rate_sps\t%s\n' "$(radio_read_state rate)"
    printf 'probe_tools_missing\t%s\n' "$(radio_sanitize "${probe_missing# }")"
    printf 'state_file\t%s\n' "$RADIO_SDR_STATE"
    printf 'captures_dir\t%s\n' "$CAPTURES_DIR"
    printf 'lock_state\t%s\n' "$(radio_lock_status_tsv | awk -F'\t' '$1=="state"{print $2}')"
    printf 'lock_owner\t%s\n' "$(radio_lock_status_tsv | awk -F'\t' '$1=="owner"{print $2}')"
}

radio_cmd_list_tsv() {
    radio_header
    radio_roster
}

radio_cmd_caps_tsv() {
    local want="${1:-}" row found=0 idx=0
    if [[ -z "$want" ]]; then
        # selected device, else the first one attached
        if row=$(radio_selected 2>/dev/null); then
            radio_caps_row "$row"
            return $?
        fi
        row=$(radio_roster | head -1)
        [[ -z "$row" ]] && {
            printf 'ERROR\tno SDR attached — none of %s responded\n' \
                "$(printf '%s ' "${RADIO_DRIVERS[@]}")" >&2
            return 1
        }
        radio_caps_row "$row"
        return $?
    fi
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        local drv sn
        drv=$(printf '%s\n' "$row" | cut -f1); sn=$(printf '%s\n' "$row" | cut -f2)
        if [[ "$want" == "$idx" || "$want" == "$drv" || "$want" == "$sn" ]]; then
            radio_caps_row "$row"; return $?
        fi
        idx=$((idx + 1))
    done < <(radio_roster)
    printf 'ERROR\tno such device: %s\n' "$(radio_sanitize "$want")" >&2
    return 1
}

radio_caps_row() {
    local row="$1"
    local drv sn fmin fmax rmin rmax gmin gmax dir bands=""
    drv=$(printf '%s\n' "$row" | cut -f1)
    sn=$(printf '%s\n' "$row" | cut -f2)
    fmin=$(printf '%s\n' "$row" | cut -f3); fmax=$(printf '%s\n' "$row" | cut -f4)
    rmin=$(printf '%s\n' "$row" | cut -f5); rmax=$(printf '%s\n' "$row" | cut -f6)
    gmin=$(printf '%s\n' "$row" | cut -f7); gmax=$(printf '%s\n' "$row" | cut -f8)
    dir=$(printf '%s\n' "$row" | cut -f9)
    # Which cellular bands this device can reach, evaluated against the real
    # band edges rather than the centre.
    local b name lo hi hits=""
    for b in "${RADIO_BANDS[@]}"; do
        name=$(printf '%s\n' "$b" | cut -d'|' -f1)
        lo=$(printf '%s\n' "$b" | cut -d'|' -f2)
        hi=$(printf '%s\n' "$b" | cut -d'|' -f3)
        awk -v a="$fmin" -v z="$fmax" -v l="$lo" -v h="$hi" \
            'BEGIN{ exit !(a+0 <= h+0 && z+0 >= l+0) }' && hits="$hits $name"
    done
    bands="${hits# }"
    printf 'driver\t%s\n' "$(radio_sanitize "$drv")"
    printf 'serial\t%s\n' "$(radio_sanitize "$sn")"
    printf 'freq_min_mhz\t%s\nfreq_max_mhz\t%s\n' "$fmin" "$fmax"
    printf 'rate_min_msps\t%s\nrate_max_msps\t%s\n' "$rmin" "$rmax"
    printf 'gain_min_db\t%s\ngain_max_db\t%s\n' "$gmin" "$gmax"
    printf 'direction\t%s\n' "$dir"
    printf 'can_tx\t%s\n' "$(radio_can_tx "$drv" && echo yes || echo no)"
    printf 'tx_note\t%s\n' "$(radio_can_tx "$drv" && echo "transmit capable" || echo "RECEIVE ONLY — attack verbs requiring TX will refuse")"
    printf 'bands\t%s\n' "$(radio_sanitize "$bands")"
    [[ "$drv" == soapy* ]] && printf 'note\t%s\n' "SoapySDR wrapper: range cells are empty because SoapySDRUtil --find does not report them; query the backend driver directly"
    return 0
}

radio_cmd_band_check() {
    local mhz="${1:-}"
    [[ -n "$mhz" ]] || { printf 'ERROR\tusage: --band-check <mhz>\n' >&2; return 2; }
    [[ "$mhz" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tnot a frequency in MHz: %s\n' "$(radio_sanitize "$mhz")" >&2; return 2; }
    local band gen
    band=$(radio_band_name "$mhz"); gen=$(radio_band_gen "$mhz")
    printf 'freq_mhz\t%s\n' "$mhz"
    printf 'band\t%s\n' "$(radio_sanitize "$band")"
    printf 'generation\t%s\n' "$(radio_sanitize "$gen")"
    if [[ "$band" == "unsupported" ]]; then
        printf 'supported\tno\n'
        printf 'reason\t%s\n' "no cellular band in the table covers ${mhz} MHz"
        return 1
    fi
    local row n=0
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        if radio_covers "$row" "$mhz"; then
            printf 'device\t%s\t%s\n' "$(printf '%s\n' "$row" | cut -f1)" \
                                          "$(radio_sanitize "$(printf '%s\n' "$row" | cut -f2)")"
            n=$((n + 1))
        fi
    done < <(radio_roster)
    printf 'devices_covering\t%s\n' "$n"
    if radio_needs_mmwave "$mhz"; then
        printf 'supported\tno\n'
        printf 'needs\tmmWave hardware (NR FR2 24-40 GHz)\n'
        printf 'reason\t%s\n' "FR2 requires a mmWave front end plus an IF/mixer chain; no SDR in this roster tunes 24-40 GHz directly"
        return 1
    fi
    if (( n == 0 )); then
        printf 'supported\tno\n'
        printf 'reason\t%s\n' "no attached SDR covers ${mhz} MHz (probe tools: $(printf '%s ' "${RADIO_DRIVERS[@]}"))"
        return 1
    fi
    printf 'supported\tyes\n'
    return 0
}

radio_cmd_select() {
    local want="${1:-}"
    [[ -n "$want" ]] || { printf 'ERROR\tusage: --select <index|driver|serial>\n' >&2; return 2; }
    local idx=0 row
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        local drv sn
        drv=$(printf '%s\n' "$row" | cut -f1); sn=$(printf '%s\n' "$row" | cut -f2)
        if [[ "$want" == "$idx" || "$want" == "$drv" || "$want" == "$sn" ]]; then
            radio_write_state "$drv" "$sn" "$idx" >/dev/null || return 1
            printf 'OK\t%s\t%s\t%s\n' "$(radio_sanitize "$drv")" "$(radio_sanitize "$sn")" "$idx"
            printf 'direction\t%s\n' "$(radio_direction "$drv")"
            radio_can_tx "$drv" || printf 'WARN\t%s is receive-only; transmit verbs will refuse\n' "$(radio_sanitize "$drv")"
            return 0
        fi
        idx=$((idx + 1))
    done < <(radio_roster)
    printf 'ERROR\tno such device: %s (attach an SDR, or run --list-tsv)\n' "$(radio_sanitize "$want")" >&2
    return 1
}

radio_selected_or_fail() {
    local want="${1:-}"
    if [[ -n "$want" ]]; then radio_cmd_select "$want" >/dev/null || return 1; fi
    local sel; sel=$(radio_selected) || {
        printf 'ERROR\tno SDR selected — attach a radio and run --select <device>\n' >&2
        printf 'MISSING\t%s\n' "$(printf '%s ' "${RADIO_DRIVERS[@]}")" >&2
        return 1
    }
    printf '%s\n' "$sel"
}

radio_cmd_set_freq() {
    local mhz="${1:-}"
    [[ -n "$mhz" ]] || { printf 'ERROR\tusage: --set-freq <mhz>\n' >&2; return 2; }
    [[ "$mhz" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tnot a frequency in MHz: %s\n' "$(radio_sanitize "$mhz")" >&2; return 2; }
    local sel drv hz
    sel=$(radio_selected_or_fail) || return 1
    drv=$(printf '%s\n' "$sel" | cut -f1)
    hz=$(awk -v f="$mhz" 'BEGIN{printf "%d", f*1000000}')
    radio_record_state freq "$hz" || return 1
    printf 'OK\t%s\n' "$(radio_sanitize "$drv")"
    printf 'freq_hz\t%s\n' "$hz"
    printf 'command\t%s\n' "$(radio_sanitize "$(radio_freq_cmd "$drv" "$hz")")"
}

radio_cmd_set_gain() {
    local db="${1:-}"
    [[ -n "$db" ]] || { printf 'ERROR\tusage: --set-gain <db>\n' >&2; return 2; }
    [[ "$db" =~ ^-?[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tnot a gain in dB: %s\n' "$(radio_sanitize "$db")" >&2; return 2; }
    local sel drv
    sel=$(radio_selected_or_fail) || return 1
    drv=$(printf '%s\n' "$sel" | cut -f1)
    radio_record_state gain "$db" || return 1
    printf 'OK\t%s\n' "$(radio_sanitize "$drv")"
    printf 'gain_db\t%s\n' "$db"
    printf 'command\t%s\n' "$(radio_sanitize "$(radio_gain_cmd "$drv" "$db")")"
}

radio_cmd_set_rate() {
    local sps="${1:-}"
    [[ -n "$sps" ]] || { printf 'ERROR\tusage: --set-rate <sps>\n' >&2; return 2; }
    [[ "$sps" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tnot a sample rate: %s\n' "$(radio_sanitize "$sps")" >&2; return 2; }
    local sel drv
    sel=$(radio_selected_or_fail) || return 1
    drv=$(printf '%s\n' "$sel" | cut -f1)
    radio_record_state rate "$sps" || return 1
    printf 'OK\t%s\n' "$(radio_sanitize "$drv")"
    printf 'rate_sps\t%s\n' "$sps"
    printf 'command\t%s\n' "$(radio_sanitize "$(radio_rate_cmd "$drv" "$sps")")"
}

radio_cmd_plan() {
    local drv="${1:-}"
    [[ -n "$drv" ]] || drv=$(radio_selected_driver) || drv="hackrf"
    radio_control_plan "$drv" \
        "$(radio_read_state freq || echo 0)" \
        "$(radio_read_state gain || echo 40)" \
        "$(radio_read_state rate || echo 2000000)"
}

# ═══════════════════════════════════════════════════════════════════
#  selftest — no radio, no root, no network
# ═══════════════════════════════════════════════════════════════════
radio_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$RADIO_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$RADIO_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state" TMP_DIR="$d/tmp"
    export RADIO_DIR="$LOOT_DIR/radio" RADIO_TMP="$TMP_DIR/radio"
    mkdir -p "$RADIO_DIR" "$RADIO_TMP" "$CAPTURES_DIR"
    export RADIO_SDR_STATE="$TMP_DIR/sdr_device"
    export RADIO_GAIN_STATE="$TMP_DIR/sdr_gain"
    export RADIO_FREQ_STATE="$TMP_DIR/sdr_freq"
    export RADIO_RATE_STATE="$TMP_DIR/sdr_rate"
    export RADIO_CACHE="$RADIO_TMP/roster.tsv"
    export RADIO_LOCK_DIR="$TMP_DIR/radio.lock"

    local out rc row

    # 1. Probe table is well-formed: every driver has a tool, args, direction.
    chk probe-table-nonempty "$(( ${#RADIO_DRIVERS[@]} > 0 ? 1 : 0 ))" 1
    local drv miss=0
    for drv in "${RADIO_DRIVERS[@]}"; do
        [[ -n "$(radio_probe_cmd "$drv")" ]] || miss=$((miss + 1))
        [[ -n "$(radio_direction "$drv")" ]] || miss=$((miss + 1))
    done
    chk probe-table-complete "$miss" 0
    chk probe-hackrf-tool   "$(radio_probe_cmd hackrf)"  hackrf_info
    chk probe-bladerf-tool  "$(radio_probe_cmd bladerf)" bladeRF-cli
    chk probe-bladerf-args  "$(radio_probe_args bladerf)" "-p"
    chk probe-limesdr-tool  "$(radio_probe_cmd limesdr)" LimeUtil
    chk probe-usrp-tool     "$(radio_probe_cmd usrp)"    uhd_find_devices
    chk probe-rtlsdr-tool   "$(radio_probe_cmd rtlsdr)"  rtl_test
    chk probe-pluto-tool    "$(radio_probe_cmd pluto)"   iio_info
    chk probe-pluto-args    "$(radio_probe_args pluto)"  "-s"
    chk probe-soapy-tool    "$(radio_probe_cmd soapy)"   SoapySDRUtil
    chk probe-unknown-empty "$(radio_probe_cmd nonsense)" ""
    chk missing-tool-rc     "$(radio_probe definitely_not_a_driver >/dev/null 2>&1; echo $?)" 2
    chk missing-tool-named  "$(radio_probe definitely_not_a_driver 2>&1 >/dev/null | grep -c 'unknown driver')" 1
    # A vendor tool that is genuinely absent must be named, not silently skipped.
    if ! command -v hackrf_info >/dev/null 2>&1; then
        chk probe-absent-named "$(radio_probe hackrf 2>&1 >/dev/null | grep -c 'hackrf_info')" 1
    fi

    # 2. Direction: receive-only hardware is flagged, TX hardware is not.
    chk dir-rtlsdr-rx    "$(radio_direction rtlsdr)" "RX"
    chk dir-hackrf-tx    "$(radio_direction hackrf)" "RX/TX"
    chk cantx-rtlsdr     "$(radio_can_tx rtlsdr && echo yes || echo no)"  no
    chk cantx-hackrf     "$(radio_can_tx hackrf && echo yes || echo no)"  yes
    chk cantx-bladerf    "$(radio_can_tx bladerf && echo yes || echo no)" yes
    chk dir-pluto-tx     "$(radio_direction pluto)"            "RX/TX"
    chk dir-pluto-uri-tx "$(radio_direction pluto:ip:10.0.0.2)" "RX/TX"
    chk cantx-pluto      "$(radio_can_tx pluto && echo yes || echo no)" yes

    # 3. Parsers against the real output shape of each vendor tool.
    out=$(radio_parse hackrf 'Found HackRF
Index: 0
Serial number: 0000000000000000a06063dc2b1e5e8f
Board ID Number: 2 (HackRF One)
Firmware Version: 2018.01.1')
    chk parse-hackrf-fields "$(printf '%s\n' "$out" | awk -F'\t' '{print NF}')" 9
    chk parse-hackrf-driver "$(printf '%s\n' "$out" | cut -f1)" hackrf
    chk parse-hackrf-serial "$(printf '%s\n' "$out" | cut -f2)" 0000000000000000a06063dc2b1e5e8f
    chk parse-hackrf-dir    "$(printf '%s\n' "$out" | cut -f9)" "RX/TX"

    out=$(radio_parse rtlsdr 'Found 1 device(s):
  0:  Realtek, RTL2838UHIDIR, SN: 00000001

Using device 0: Generic RTL2832U OEM
Found Rafael Micro R820T tuner')
    chk parse-rtlsdr-fields "$(printf '%s\n' "$out" | awk -F'\t' '{print NF}')" 9
    chk parse-rtlsdr-driver "$(printf '%s\n' "$out" | cut -f1)" rtlsdr
    chk parse-rtlsdr-serial "$(printf '%s\n' "$out" | cut -f2)" 00000001
    chk parse-rtlsdr-dir    "$(printf '%s\n' "$out" | cut -f9)" "RX"
    chk parse-rtlsdr-fmax   "$(printf '%s\n' "$out" | cut -f4)" 1766
    chk parse-rtlsdr-count  "$(printf '%s\n' "$out" | grep -c .)" 1

    # iio_info -s: the context URI is the address, and a board reachable two
    # ways is two rows because the two doors behave differently.
    out=$(radio_parse pluto 'Library version: 0.24 (git tag: v0.24)
Compiled with backends: local xml ip usb serial
IIO context scan:
	0: usb:1.9.5 (Analog Devices Inc. PlutoSDR (ADALM-PLUTO)), serial=0000000000000001 [usb]
	1: ip:192.168.2.1 (Analog Devices Inc. PlutoSDR (ADALM-PLUTO)), serial=0000000000000001 [ip]')
    chk parse-pluto-count   "$(printf '%s\n' "$out" | grep -c .)" 2
    chk parse-pluto-fields  "$(printf '%s\n' "$out" | awk -F'\t' '{print NF}' | sort -u)" 9
    chk parse-pluto-usb     "$(printf '%s\n' "$out" | cut -f1 | head -1)" "pluto:usb:1.9.5"
    chk parse-pluto-ip      "$(printf '%s\n' "$out" | cut -f1 | tail -1)" "pluto:ip:192.168.2.1"
    chk parse-pluto-serial  "$(printf '%s\n' "$out" | cut -f2 | head -1)" "0000000000000001"
    chk parse-pluto-dir     "$(printf '%s\n' "$out" | cut -f9 | head -1)" "RX/TX"
    # Nothing iio_info -s prints is a range, so the range cells stay empty
    # rather than being filled with a datasheet number nobody measured.
    chk parse-pluto-empty-ranges "$(printf '%s\n' "$out" | cut -f3,4,5,6,7,8 | head -1)" $'\t\t\t\t\t'
    out=$(radio_parse pluto 'Library version: 0.24
IIO context scan:
	0: local: (Analog Devices Inc. PlutoSDR (ADALM-PLUTO))')
    chk parse-pluto-noserial "$(printf '%s\n' "$out" | cut -f2)" "local:"
    chk parse-pluto-emptytxt  "$(radio_parse pluto '' | grep -c .)" 0

    out=$(radio_parse bladerf 'bladeRF-cli version: 2023.02
  Backend:        libusb
  Serial:         a1b2c3d4e5f6
  USB Bus:        3')
    chk parse-bladerf-serial "$(printf '%s\n' "$out" | cut -f2)" a1b2c3d4e5f6
    chk parse-bladerf-driver "$(printf '%s\n' "$out" | cut -f1)" bladerf

    out=$(radio_parse usrp 'linux; GNU C++ version 11; Boost_107400; UHD_4.3.0

-- UHD Device 0
Device Address:
    serial: 30A3D42
    product: B210')
    chk parse-usrp-serial "$(printf '%s\n' "$out" | cut -f2)" 30A3D42
    chk parse-usrp-fmax   "$(printf '%s\n' "$out" | cut -f4)" 6000

    out=$(radio_parse limesdr 'Find devices:
  * [LimeSDR-USB, media=USB 3.0, module=FX3, serial=0009060C24F1D3A3, addr=1d50:6108]')
    chk parse-lime-serial "$(printf '%s\n' "$out" | cut -f2)" 0009060C24F1D3A3
    chk parse-lime-driver "$(printf '%s\n' "$out" | cut -f1)" limesdr

    out=$(radio_parse soapy 'SoapySDRUtil --find
######################################################
## Soapy SDR -- the SDR abstraction library
######################################################

Found device 0
  driver = rtlsdr
  serial = 00000001

Found device 1
  driver = hackrf
  serial = 0000000000000000a06063dc2b1e5e8f
')
    chk parse-soapy-count  "$(printf '%s\n' "$out" | grep -c .)" 2
    chk parse-soapy-drv1   "$(printf '%s\n' "$out" | sed -n 1p | cut -f1)" "soapy:rtlsdr"
    chk parse-soapy-drv2   "$(printf '%s\n' "$out" | sed -n 2p | cut -f1)" "soapy:hackrf"
    chk parse-soapy-dir2   "$(printf '%s\n' "$out" | sed -n 2p | cut -f9)" "RX/TX"
    chk parse-unknown-drv  "$(radio_parse nonsense x >/dev/null 2>&1; echo $?)" 1
    # Untrusted serial text cannot forge a row.
    out=$(radio_parse hackrf "$(printf 'Serial number: evil\tserial\there\n')")
    chk parse-hackrf-injection "$(printf '%s\n' "$out" | awk -F'\t' '{print NF}' | sort -u | tr '\n' ',')" "9,"

    # 4. Band classification against real cellular downlink frequencies.
    chk band-gsm900   "$(radio_band_name 942)"    GSM900
    chk band-gsm900lo "$(radio_band_name 925)"    GSM900
    chk band-gsm900hi "$(radio_band_name 960)"    GSM900
    # 1805-1880 is both GSM1800 downlink and LTE band 3 downlink - the same
    # spectrum with two names. It is reported once, as LTE-B3; --band-check
    # prints the generation so a 2G-only survey is not misled.
    chk band-1805-1880  "$(radio_band_name 1842.5)" LTE-B3
    chk band-1805-gen   "$(radio_band_gen 1842.5)"  4G
    chk band-gsm1800-unaliased "$(radio_band_name 1805)" LTE-B3
    chk band-umts     "$(radio_band_name 2140)"   UMTS-B1
    chk band-lte-b20  "$(radio_band_name 806)"    LTE-B20
    chk band-lte-b3   "$(radio_band_name 1815)"   LTE-B3
    chk band-n78      "$(radio_band_name 3500)"   NR-n78
    chk band-gen-2g   "$(radio_band_gen 942)"     2G
    chk band-gen-4g   "$(radio_band_gen 806)"     4G
    chk band-gen-5g   "$(radio_band_gen 3500)"    5G
    # Out of range must be "unsupported", never the nearest band.
    chk band-out-of-range       "$(radio_band_name 100)"    unsupported
    chk band-out-of-range-gen   "$(radio_band_gen 100)"     unknown
    chk band-out-of-range-rc    "$(radio_band_of 100 >/dev/null 2>&1; echo $?)" 1
    chk band-microwave-range    "$(radio_band_name 5800)"   unsupported
    chk band-nonnum             "$(radio_band_of abcd >/dev/null 2>&1; echo $?)" 1
    chk band-empty              "$(radio_band_name '')"     unsupported
    # FR2 at 28 GHz is FR2 and needs mmWave hardware.
    chk band-fr2-28ghz      "$(radio_band_name 28000)"     NR-FR2-n261
    chk band-fr2-gen        "$(radio_band_gen 28000)"      5G-FR2
    chk band-fr2-mmwave     "$(radio_needs_mmwave 28000 && echo yes || echo no)" yes
    chk band-sub6-no-mmwave "$(radio_needs_mmwave 3500 && echo yes || echo no)"  no
    chk band-fr2-26ghz      "$(radio_band_name 26500)"     NR-FR2-n257
    chk band-fr2-39ghz      "$(radio_band_name 39000)"     NR-FR2-n260
    # The band table itself must stay well-formed.
    chk band-table-fields "$(printf '%s\n' "${RADIO_BANDS[@]}" | awk -F'|' 'NF!=4{c++} END{print c+0}')" 0
    chk band-table-order "$(printf '%s\n' "${RADIO_BANDS[@]}" | awk -F'|' '$2+0>$3+0{c++} END{print c+0}')" 0
    # Overlapping bands must stay in narrow-first order, and the awk table
    # inside radio_band_of must agree with the display table.
    chk band-table-awk-agrees "$(radio_band_name 3500)$(radio_band_name 28000)$(radio_band_name 1842.5)" "NR-n78NR-FR2-n261LTE-B3"
    chk band-table-awklast "$(radio_band_name 4150)"   NR-n77
    chk band-table-awklast2 "$(radio_band_name 29000)" NR-FR2-n257

    # 5. Band check with no radio attached must fail honestly and name FR2.
    out=$(radio_cmd_band_check 942 2>&1); rc=$?
    chk bandcheck-nonum-rc  "$(radio_cmd_band_check abc >/dev/null 2>&1; echo $?)" 2
    chk bandcheck-noarg-rc  "$(radio_cmd_band_check >/dev/null 2>&1; echo $?)" 2
    chk bandcheck-noarg-msg "$(radio_cmd_band_check 2>&1 >/dev/null | grep -c 'usage: --band-check')" 1
    chk bandcheck-nonnum-msg "$(radio_cmd_band_check 12x 2>&1 >/dev/null | grep -c 'not a frequency')" 1
    out=$(radio_cmd_band_check 28000 2>&1); rc=$?
    chk bandcheck-fr2-rc     "$rc" 1
    chk bandcheck-fr2-band   "$(fld "$out" band)" NR-FR2-n261
    chk bandcheck-fr2-needs "$(awk -F'\t' '$1=="needs"{print ($2 ~ /mmWave/) ? 1 : 0}' <<<"$out")" 1
    chk bandcheck-fr2-needs-named "$(fld "$out" needs)" "mmWave hardware (NR FR2 24-40 GHz)"
    chk bandcheck-fr2-nosup  "$(fld "$out" supported)" no
    #    "No radio attached" is an environment fact, not a code path. A host
    #    with a HackRF on the bus legitimately answers `supported yes`, so
    #    force an empty roster to test the branch this assertion names, and
    #    keep the live answer as a second assertion only when it applies.
    local empty_roster="$d/empty-roster.tsv"
    : > "$empty_roster"
    out=$(RADIO_CACHE="$empty_roster" radio_cmd_band_check 942 2>&1); rc=$?
    chk bandcheck-noradio-rc "$rc" 1
    chk bandcheck-noradio-sup "$(fld "$out" supported)" no
    chk bandcheck-noradio-why "$(printf '%s\n' "$out" | grep -c 'no attached SDR')" 1
    if (( $(radio_count) == 0 )); then
        out=$(radio_cmd_band_check 942 2>&1); rc=$?
        chk bandcheck-live-noradio-rc  "$rc" 1
        chk bandcheck-live-noradio-sup "$(fld "$out" supported)" no
    fi
    out=$(radio_cmd_band_check 100 2>&1); rc=$?
    chk bandcheck-unsupported-rc "$rc" 1
    chk bandcheck-unsupported    "$(fld "$out" supported)" no

    # 6. Device selection. Nothing is attached here, so every name fails —
    #    but the failure must name the device and return non-zero.
    chk select-noarg-rc   "$(radio_cmd_select >/dev/null 2>&1; echo $?)" 2
    chk select-noarg-msg  "$(radio_cmd_select 2>&1 >/dev/null | grep -c 'usage: --select')" 1
    out=$(radio_cmd_select definitely_not_a_device 2>&1); rc=$?
    chk select-unknown-rc  "$rc" 1
    chk select-unknown-msg "$(printf '%s\n' "$out" | grep -c 'no such device')" 1
    chk select-unknown-named "$(printf '%s\n' "$out" | grep -c 'definitely_not_a_device')" 1
    chk select-did-not-write "$([[ -e "$RADIO_SDR_STATE" ]] && echo yes || echo no)" no

    # 7. Shared state. Selection is exercised through the writer directly
    #    (no radio), then read back the way another module would.
    rm -f "$RADIO_SDR_STATE"
    out=$(radio_write_state hackrf 0000000000000000a06063dc2b1e5e8f 0); rc=$?
    chk state-write-rc     "$rc" 0
    chk state-file-exists  "$([[ -f "$RADIO_SDR_STATE" ]] && echo yes || echo no)" yes
    chk state-file-fields  "$(awk -F'\t' '{print NF}' "$RADIO_SDR_STATE")" 3
    chk state-file-driver  "$(cut -f1 "$RADIO_SDR_STATE")" hackrf
    chk state-file-serial  "$(cut -f2 "$RADIO_SDR_STATE")" 0000000000000000a06063dc2b1e5e8f
    chk selected-driver    "$(radio_selected_driver)" hackrf
    chk selected-raw       "$(radio_selected)" "$(cat "$RADIO_SDR_STATE")"
    chk state-says-ok      "$(printf '%s\n' "$out" | cut -f1)" OK
    # An unwritable state path must be an error, not a silent success.
    local saved="$RADIO_SDR_STATE"
    RADIO_SDR_STATE="$d/nodir/deeper/sdr_device"
    out=$(radio_write_state hackrf X 0 2>&1); rc=$?
    chk state-unwritable-rc   "$rc" 1
    chk state-unwritable-says "$(printf '%s\n' "$out" | grep -c '^ERROR')" 1
    chk state-unwritable-no-ok "$(printf '%s\n' "$out" | grep -c '^OK')" 0
    RADIO_SDR_STATE="$saved"
    # The state file must be shared: it lives directly under TMP_DIR, not in
    # a per-module subdirectory, or no other module can see it.
    chk state-shared-path "$(dirname "$RADIO_SDR_STATE")" "$TMP_DIR"
    chk state-basename    "$(basename "$RADIO_SDR_STATE")" sdr_device

    # 8. Control state and the per-vendor command spelling.
    radio_record_state freq 942000000; chk set-freq-state "$(radio_read_state freq)" 942000000
    radio_record_state gain 40;        chk set-gain-state "$(radio_read_state gain)" 40
    radio_record_state rate 2000000;   chk set-rate-state "$(radio_read_state rate)" 2000000
    chk set-freq-nonum-rc  "$(radio_cmd_set_freq abc >/dev/null 2>&1; echo $?)" 2
    chk set-freq-noarg-rc  "$(radio_cmd_set_freq >/dev/null 2>&1; echo $?)" 2
    chk set-gain-nonum-rc  "$(radio_cmd_set_gain abc >/dev/null 2>&1; echo $?)" 2
    chk set-freq-nonum-b   "$(radio_cmd_set_freq 9x9 >/dev/null 2>&1; echo $?)" 2
    chk set-rate-nonum-rc  "$(radio_cmd_set_rate abc >/dev/null 2>&1; echo $?)" 2
    chk set-gain-noarg-rc  "$(radio_cmd_set_gain >/dev/null 2>&1; echo $?)" 2
    chk set-rate-noarg-rc  "$(radio_cmd_set_rate >/dev/null 2>&1; echo $?)" 2
    # A negative gain is legal for bladeRF/Lime; it must be accepted, and it
    # is set LAST so the status assertions below see a known value.
    chk set-gain-negative-rc "$(radio_cmd_set_gain -12 >/dev/null 2>&1; echo $?)" 0
    chk set-gain-negative-val "$(radio_read_state gain)" -12
    chk set-gain-negative-cmd "$(radio_gain_cmd bladerf -12 | grep -c -- '-12')" 1
    radio_record_state gain 40; radio_record_state freq 942000000; radio_record_state rate 2000000
    # With hackrf selected, the plan must quote hackrf's own CLI, not a
    # generic one.
    out=$(radio_control_plan hackrf 942000000 40 2000000)
    chk plan-hackrf-freq "$(printf '%s\n' "$out" | awk -F'\t' '$1=="set_frequency_cmd"{print $2}' | grep -c 'hackrf_transfer')" 1
    chk plan-hackrf-rate "$(printf '%s\n' "$out" | awk -F'\t' '$1=="set_rate_cmd"{print $2}' | grep -c 'hackrf_transfer')" 1
    chk plan-hackrf-gain "$(printf '%s\n' "$out" | awk -F'\t' '$1=="set_gain_cmd"{print $2}' | grep -c 'hackrf_transfer')" 1
    chk plan-hackrf-cantx "$(fld "$out" can_tx)" yes
    out=$(radio_control_plan rtlsdr 942000000 40 2048000)
    chk plan-rtlsdr-freq "$(printf '%s\n' "$out" | awk -F'\t' '$1=="set_frequency_cmd"{print $2}' | grep -c 'rtl_sdr')" 1
    chk plan-rtlsdr-cantx "$(fld "$out" can_tx)" no
    chk plan-rtlsdr-txflag "$(printf '%s\n' "$out" | awk -F'\t' '$1=="set_frequency_cmd"{print $2}' | grep -c 'RX ONLY')" 1
    out=$(radio_control_plan bladerf 1842500000 30 40000000)
    chk plan-bladerf "$(printf '%s\n' "$out" | awk -F'\t' '$1=="set_frequency_cmd"{print $2}' | grep -c 'bladeRF-cli')" 1
    out=$(radio_control_plan soapy:hackrf 942000000 40 2000000)
    chk plan-soapy "$(printf '%s\n' "$out" | awk -F'\t' '$1=="set_frequency_cmd"{print $2}' | grep -c 'SoapySDRUtil')" 1
    chk plan-unknown-empty "$(radio_freq_cmd nonsense 1)" ""
    chk plan-fields "$(radio_control_plan hackrf 1 1 1 | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0

    # 9. Capture: hardware-free, so it must hand off with a plan file rather
    #    than claim a recording happened.
    chk record-badarg-rc "$(radio_record abc >/dev/null 2>&1; echo $?)" 2
    chk record-noarg-rc  "$(radio_record >/dev/null 2>&1; echo $?)" 2
    out=$(radio_record 1 2>&1); rc=$?
    if command -v hackrf_transfer >/dev/null 2>&1; then
        chk record-hwpresent-rc "$([[ $rc -eq 0 || $rc -eq 1 ]] && echo ok || echo bad)" ok
    else
        chk record-handoff-rc  "$rc" 1
        chk record-handoff-says "$(printf '%s\n' "$out" | grep -c '^HANDOFF')" 1
        chk record-no-ok-claim "$(printf '%s\n' "$out" | grep -c '^OK')" 0
        chk record-plan-written "$(printf '%s\n' "$out" | grep -c 'plan.txt')" 1
        chk record-plan-is-plan "$(ls "$CAPTURES_DIR"/*.plan.txt 2>/dev/null | wc -l)" 1
        chk record-plan-names-tool "$(grep -h -c 'hackrf_transfer' "$CAPTURES_DIR"/*.plan.txt 2>/dev/null | head -1)" 1
        chk record-plan-mentions-gnuradio "$(grep -q 'gnuradio' "$CAPTURES_DIR"/*.plan.txt 2>/dev/null && echo yes || echo no)" yes
    fi
    chk capture-cmd-hackrf  "$(radio_capture_cmd hackrf 2 /tmp/x.iq 942000000 20000000 40 | grep -c 'hackrf_transfer -r')" 1
    chk capture-cmd-rtlsdr  "$(radio_capture_cmd rtlsdr 2 /tmp/x.iq 942000000 2048000 40 | grep -c 'rtl_sdr')" 1
    chk capture-cmd-unknown "$(radio_capture_cmd nonsense 2 /tmp/x.iq 1 1 1 >/dev/null 2>&1; echo $?)" 1
    # Pluto: the tune, the rate, the manual gain mode and the stream are one
    # command, because iio_attr has no state of its own to set up first.
    out=$(radio_capture_cmd pluto:ip:192.168.2.1 2 /tmp/x.iq 942000000 2083000 40)
    chk capture-cmd-pluto-stream  "$(printf '%s\n' "$out" | grep -c 'iio_readdev -u ip:192.168.2.1')" 1
    chk capture-cmd-pluto-tune    "$(printf '%s\n' "$out" | grep -c 'altvoltage0 frequency 942000000')" 1
    chk capture-cmd-pluto-rate    "$(printf '%s\n' "$out" | grep -c 'sampling_frequency 2083000')" 1
    chk capture-cmd-pluto-gain    "$(printf '%s\n' "$out" | grep -c 'gain_control_mode manual')" 1
    chk capture-cmd-pluto-samples "$(printf '%s\n' "$out" | grep -c -- '-s 4166000')" 1
    chk capture-cmd-pluto-chans   "$(printf '%s\n' "$out" | grep -c 'cf-ad9361-lpc voltage0 voltage1')" 1
    chk capture-needs-pluto       "$(radio_capture_needs pluto:ip:192.168.2.1)" "iio_attr iio_readdev"
    chk capture-needs-hackrf      "$(radio_capture_needs hackrf)" "hackrf_transfer"
    chk capture-needs-unknown     "$(radio_capture_needs nonsense)" ""
    chk capture-format-pluto      "$(radio_capture_format pluto:usb:1.9.5)" ci16
    chk capture-format-hackrf     "$(radio_capture_format hackrf)" cs8
    chk capture-format-rtlsdr     "$(radio_capture_format rtlsdr)" cu8
    chk capture-format-unknown    "$(radio_capture_format nonsense)" ""
    chk slug-pluto "$(radio_slug pluto:ip:192.168.2.1)" "pluto_ip_192.168.2.1"
    chk slug-hackrf "$(radio_slug hackrf)" hackrf
    chk gnuradio-plan-names-driver "$(radio_gnuradio_plan rtlsdr 942000000 2048000 40 2 /tmp/x.iq | grep -c 'driver=rtlsdr')" 1

    # 10. Coverage arithmetic against the parser's own rows.
    row=$(printf 'hackrf\tsn\t1\t6000\t2\t20\t0\t62\tRX/TX')
    chk covers-inside   "$(radio_covers "$row" 942 && echo yes || echo no)"       yes
    chk covers-edge-lo  "$(radio_covers "$row" 1 && echo yes || echo no)"         yes
    chk covers-edge-hi  "$(radio_covers "$row" 6000 && echo yes || echo no)"      yes
    chk covers-outside  "$(radio_covers "$row" 24000 && echo yes || echo no)"     no
    row=$(printf 'rtlsdr\tsn\t24\t1766\t0.225\t2.4\t0\t49.6\tRX')
    chk covers-rtl-gsm  "$(radio_covers "$row" 942 && echo yes || echo no)"       yes
    chk covers-rtl-fr2  "$(radio_covers "$row" 28000 && echo yes || echo no)"     no
    chk covers-empty    "$(radio_covers "$(printf 'soapy:x\tsn\t\t\t\t\t\t\tRX/TX')" 942 && echo yes || echo no)" no
    #    Another live-host assertion: an empty roster covers nothing. Forced
    #    empty rather than assumed empty, then the live case when it applies.
    chk any-covers-none "$(RADIO_CACHE="$empty_roster" radio_any_covers 942 && echo yes || echo no)" no
    if (( $(radio_count) == 0 )); then
        chk any-covers-none-live "$(radio_any_covers 942 && echo yes || echo no)" no
    fi

    # 11. TSV contracts.
    out=$(radio_cmd_list_tsv)
    chk list-header-fields "$(printf '%s\n' "$out" | head -1 | awk -F'\t' '{print NF}')" 9
    chk list-header-first  "$(printf '%s\n' "$out" | head -1 | cut -f1)" driver
    #    One row means header-only: the live roster is empty. The header is
    #    asserted above regardless; this asserts the row count only when the
    #    bus really is empty.
    if (( $(radio_count) == 0 )); then
        chk list-rows-no-radio "$(printf '%s\n' "$out" | grep -c .)" 1
    else
        chk list-rows-with-radio \
            "$(printf '%s\n' "$out" | tail -n +2 | awk -F'\t' 'NF==9' | grep -c .)" \
            "$(radio_count)"
    fi
    chk header-fields      "$(radio_header | awk -F'\t' '{print NF}')" 9

    out=$(radio_cli_status_tsv)
    #    The contract: `devices` equals the live roster count and the two never
    #    disagree. Pinning it to 0 only held on a host with nothing attached.
    chk status-devices   "$(fld "$out" devices)" "$(radio_count)"
    chk status-selected-driver "$(fld "$out" selected_driver)" hackrf
    chk status-selected-fields "$(awk -F'\t' '$1=="selected"{print NF}' <<<"$out")" 2
    chk status-cantx     "$(fld "$out" can_tx)" yes
    chk status-freq      "$(fld "$out" freq_hz)" 942000000
    chk status-gain      "$(fld "$out" gain_db)" 40   # -12 was set by the set-gain usage test just above
    chk status-rate      "$(fld "$out" rate_sps)" 2000000
    chk status-statefile "$(fld "$out" state_file)" "$RADIO_SDR_STATE"
    chk status-fields    "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk status-keys      "$(printf '%s\n' "$out" | cut -f1 | tr '\n' ' ')" \
        "devices selected selected_driver can_tx freq_hz gain_db rate_sps probe_tools_missing state_file captures_dir lock_state lock_owner "
    chk status-probe-missing-names " $(printf '%s\n' "$out" | awk -F'\t' '$1=="probe_tools_missing"{print $2}') " \
        "$( for t in hackrf_info bladeRF-cli LimeUtil uhd_find_devices rtl_test iio_info SoapySDRUtil; do
                command -v "$t" >/dev/null 2>&1 || printf '%s ' "$t"
            done | sed 's/^/ /' )"

    # 12. Verb validation and dispatch.
    chk caps-unknown-rc "$(radio_cmd_caps_tsv definitely_not_a_device >/dev/null 2>&1; echo $?)" 1
    chk probe-unknown-rc "$(radio_probe nonsense >/dev/null 2>&1; echo $?)" 2
    chk plan-nonzero-rc "$(radio_cmd_plan hackrf >/dev/null 2>&1; echo $?)" 0
    chk main-status-rc  "$(radio_cli_main --status-tsv >/dev/null 2>&1; echo $?)" 0
    chk main-list-rc    "$(radio_cli_main --list-tsv >/dev/null 2>&1; echo $?)" 0
    chk main-unknown-rc "$(radio_cli_main definitely-not-a-verb >/dev/null 2>&1; echo $?)" 2
    chk main-noargs-rc  "$(radio_cli_main >/dev/null 2>&1; echo $?)" 2
    chk main-menu-rc    "$(radio_cli_main --menu </dev/null >/dev/null 2>&1; echo $?)" 0
    chk menu-fn-defined "$(declare -F radio_menu >/dev/null && echo yes || echo no)" yes

    # 13. Exclusive ownership: live conflicts fail, owners cannot release
    # each other's claim, and a dead PID is recoverable.
    rm -rf "$RADIO_LOCK_DIR"
    chk lock-free "$(radio_lock_status_tsv | awk -F'\t' '$1=="state"{print $2}')" free
    chk lock-claim-rc "$(radio_lock_claim alpha $$ >/dev/null 2>&1; echo $?)" 0
    chk lock-owner "$(radio_lock_status_tsv | awk -F'\t' '$1=="owner"{print $2}')" alpha
    chk lock-conflict-rc "$(radio_lock_claim beta $$ >/dev/null 2>&1; echo $?)" 1
    chk lock-wrong-release "$(radio_lock_release beta >/dev/null 2>&1; echo $?)" 1
    chk lock-release-rc "$(radio_lock_release alpha >/dev/null 2>&1; echo $?)" 0
    mkdir -p "$RADIO_LOCK_DIR"
    printf 'owner\tdead\npid\t99999999\nstarted\t-\ndevice\t-\n' > "$RADIO_LOCK_DIR/owner.tsv"
    chk lock-stale "$(radio_lock_status_tsv | awk -F'\t' '$1=="state"{print $2}')" stale
    chk lock-recover-rc "$(radio_lock_recover >/dev/null 2>&1; echo $?)" 0
    chk lock-after-recover "$(radio_lock_status_tsv | awk -F'\t' '$1=="state"{print $2}')" free
    chk processes-header "$(radio_processes_tsv | head -1)" $'pid\tcommand'

    # 14. Sanitisation.
    chk sanitize-tab "$(radio_sanitize $'a\tb')" "a b"
    chk sanitize-nl  "$(radio_sanitize $'a\nb')" "a b"
    chk sanitize-cr  "$(radio_sanitize $'a\rb')" "a b"

    # ── the estimator: a known clock error, recovered from a synthesised tone ──
    if radio_calib_available; then
        local iq="$d/cal.cf32"
        python3 "$(RADIO_CALIB_PY)" synth "$iq" cf32 2048000 1900000000 12.5 \
            --samples 65536 --snr-db 30 >/dev/null 2>&1
        local out
        out=$(radio_calibrate 1900 "$iq")
        chk calib-verdict "$(fld "$out" verdict)" "measured"
        chk calib-ppm-near "$(awk -v p="$(fld "$out" ppm)" 'BEGIN{d=p-12.5; if(d<0)d=-d; print (d<0.1)?"yes":"no"}')" "yes"
        chk calib-offset-hz "$(awk -v o="$(fld "$out" offset_hz)" 'BEGIN{d=o-23750; if(d<0)d=-d; print (d<200)?"yes":"no"}')" "yes"
        chk calib-resolution-stated "$(fld "$out" resolution_hz)" "15.625000"

        # A capture with no carrier in it: the refusal has to be named, because
        # a peak found in noise is a number with nothing behind it.
        python3 "$(RADIO_CALIB_PY)" synth "$d/noise.cf32" cf32 2048000 1900000000 0 \
            --samples 65536 --noise-only --snr-db 0 >/dev/null 2>&1
        chk calib-noise-refused "$(radio_calibrate 1900 "$d/noise.cf32" >/dev/null 2>&1; echo $?)" "1"
        chk calib-noise-reason "$(radio_calibrate 1900 "$d/noise.cf32" 2>/dev/null | grep -c 'no-peak-above-noise')" "1"

        # A capture too short to resolve anything.
        : > "$d/tiny.ci16"
        head -c 2048 /dev/zero >> "$d/tiny.ci16"
        chk calib-short-refused "$(radio_calibrate 1900 "$d/tiny.ci16" --fmt ci16 >/dev/null 2>&1; echo $?)" "1"
        chk calib-short-reason "$(radio_calibrate 1900 "$d/tiny.ci16" --fmt ci16 2>/dev/null | grep -c too-few-samples)" "1"

        # A carrier 40 ppm out is outside a 20 kHz window: the answer is that
        # the window could not hold it, never a number from the window edge.
        python3 "$(RADIO_CALIB_PY)" synth "$d/far.cf32" cf32 2048000 1900000000 40 \
            --samples 65536 --snr-db 40 >/dev/null 2>&1
        chk calib-edge-refused "$(radio_calibrate 1900 "$d/far.cf32" --window 20000 >/dev/null 2>&1; echo $?)" "1"

        chk calib-needs-carrier "$(radio_calibrate '' "$iq" >/dev/null 2>&1; echo $?)" "2"
        chk calib-rejects-flag "$(radio_calibrate 1900 "$iq" --nonsense >/dev/null 2>&1; echo $?)" "2"
    else
        chk calib-skipped "$(radio_calibrate 1900 /nonexistent 2>/dev/null | grep -c no-estimator)" "1"
    fi

    # ── the compression point: the gain at which the output stops tracking ──
    # 30 dB is 3 dB below the straight line, so the knee is unambiguous; a row
    # exactly ON the threshold would test the comparison, not the instrument.
    printf '# gain_db,out_db\n0,-60\n10,-50\n20,-40\n30,-33\n40,-42\n' > "$d/knee.csv"
    local kn
    kn=$(radio_gain_knee "$d/knee.csv")
    chk knee-verdict "$(fld "$kn" verdict)" "measured"
    chk knee-gain "$(fld "$kn" compression_gain_db)" "30.00"
    chk knee-slope "$(fld "$kn" linear_slope)" "1.0000"
    printf '# gain_db,out_db\n0,-60\n10,-50\n20,-40\n' > "$d/linear.csv"
    chk knee-never "$(radio_gain_knee "$d/linear.csv" >/dev/null 2>&1; echo $?)" "1"
    chk knee-never-why "$(radio_gain_knee "$d/linear.csv" 2>/dev/null | grep -c never-compresses)" "1"
    chk knee-noargs "$(radio_gain_knee >/dev/null 2>&1; echo $?)" "2"

    # ── the reference check names what is absent rather than failing ──
    local rc
    rc=$(radio_ref_check 2>/dev/null) || true
    chk ref-verdict "$(printf '%s\n' "$rc" | awk -F'\t' '$1=="verdict"{print $2}')" \
        "$(printf '%s\n' "$rc" | awk -F'\t' '$1=="verdict"{print $2}')"
    # How many references exist is a fact about this machine (a VM has no PPS,
    # a laptop with a u-blox may), so the assertion is about the shape of the
    # answer: the GPSDO row is always absent, and every absent row says why.
    chk ref-names-gap "$(printf '%s\n' "$rc" | awk -F'\t' '$1=="absent" && $2=="gpsdo-serial"{print "named"}')" "named"
    chk ref-absent-have-detail "$(printf '%s\n' "$rc" | awk -F'\t' '$1=="absent" && $4!=""{n++} END{print n+0}')" \
        "$(printf '%s\n' "$rc" | grep -c '^absent')"
    chk ref-pps-row "$(printf '%s\n' "$rc" | awk -F'\t' '$1=="absent" && $2=="pps"{print "named"}')" "named"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ═══════════════════════════════════════════════════════════════════
#  menu
# ═══════════════════════════════════════════════════════════════════
radio_menu() {
    local c
    while true; do
        banner
        local n sel
        n=$(radio_count)
        sel=$(radio_selected 2>/dev/null | cut -f1) || sel="none"
        echo -e "  ${C_MAG}=== SDR / radio manager ===${C_RESET}"
        echo -e "  devices: ${C_GRN}${n}${C_RESET}   selected: ${C_GRN}${sel:-none}${C_RESET}"
        echo -e "  freq: ${C_DIM}$(radio_read_state freq)${C_RESET}  gain: ${C_DIM}$(radio_read_state gain)${C_RESET}  rate: ${C_DIM}$(radio_read_state rate)${C_RESET}\n"
        cat << 'M'
  [1]  list attached SDRs
  [2]  select a device
  [3]  capability report for selected device
  [4]  band check (is a frequency covered?)
  [5]  set centre frequency
  [6]  set gain
  [7]  set sample rate
  [8]  show vendor control commands for selection
  [9]  record raw IQ
  [10] calibrate the clock against a known carrier
  [11] compression point from a gain sweep
  [12] is there a frequency reference here?
  [0]  back

M
        if [[ -n "${IMSISTING_CLI:-}" ]]; then
            echo "  (menu unavailable in CLI mode)" >&2
            return 0
        fi
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) radio_cmd_list_tsv | column -t -s$'\t' 2>/dev/null || radio_cmd_list_tsv
               read -rp "  press enter " _ ;;
            2) radio_cmd_list_tsv | column -t -s$'\t' 2>/dev/null
               read -rp "  index, driver or serial> " w
               radio_cmd_select "$w"; read -rp "  press enter " _ ;;
            3) radio_cmd_caps_tsv | column -t -s$'\t' 2>/dev/null || radio_cmd_caps_tsv
               read -rp "  press enter " _ ;;
            4) read -rp "  frequency MHz> " f
               radio_cmd_band_check "$f"; read -rp "  press enter " _ ;;
            5) read -rp "  frequency MHz> " f
               radio_cmd_set_freq "$f"; read -rp "  press enter " _ ;;
            6) read -rp "  gain dB> " g
               radio_cmd_set_gain "$g"; read -rp "  press enter " _ ;;
            7) read -rp "  sample rate sps> " r
               radio_cmd_set_rate "$r"; read -rp "  press enter " _ ;;
            8) radio_cmd_plan | column -t -s$'\t' 2>/dev/null || radio_cmd_plan
               read -rp "  press enter " _ ;;
            9) read -rp "  seconds> " s
               radio_record "$s"; read -rp "  press enter " _ ;;
            10) read -rp "  carrier MHz> " cf; read -rp "  capture file> " fp
                radio_calibrate "$cf" "$fp"; read -rp "  press enter " _ ;;
            11) read -rp "  gain/out CSV> " gp; radio_gain_knee "$gp"; read -rp "  enter " _ ;;
            12) radio_ref_check; read -rp "  press enter " _ ;;
            0) return 0 ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── calibration: the error the radio adds to every number above ────────
#
# An SDR's sample clock is a crystal, and every frequency the radio is tuned to
# inherits its error. One part per million on a 1.9 GHz carrier is 1.9 kHz --
# wider than an LTE subcarrier -- so a capture that "looks wrong" is often
# tuned wrong rather than decoded wrong. These verbs measure that error instead
# of assuming it, and each one states the resolution it achieved, because a
# number without its own error bar is a guess.

RADIO_CALIB_PY() { printf '%s' "${IMSISTING_ROOT}/tools/sdr_calib.py"; }

# The estimator needs numpy. Saying so by name is the difference between a
# missing dependency and a broken measurement.
radio_calib_available() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c 'import numpy' 2>/dev/null || return 1
    [[ -r "$(RADIO_CALIB_PY)" ]] || return 1
    return 0
}

radio_calibrate() {  # <carrier_mhz> <file> [--rate sps] [--window hz] [--fmt f]
    local mhz="${1:-}" file="${2:-}"
    (($# >= 2)) && shift 2
    local rate="2048000" window="50000" fmt="cf32"
    while (($#)); do
        case "$1" in
            --rate)   rate="${2:-}"; shift 2 ;;
            --window) window="${2:-}"; shift 2 ;;
            --fmt)    fmt="${2:-}"; shift 2 ;;
            --help|-h) printf 'usage: --calibrate <carrier_mhz> <file> [--rate sps] [--window hz] [--fmt cf32|ci16|cu8]\n'; return 0 ;;
            *) printf 'ERROR\t--calibrate does not take %s\n' "$(radio_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ -n "$mhz" && -n "$file" ]] || {
        printf 'ERROR\t--calibrate needs a carrier in MHz and a capture file\n' >&2
        printf 'WHY\tthe clock error is a ratio: without the carrier there is nothing to divide by, and without the capture there is nothing to measure\n' >&2
        return 2; }
    [[ "$mhz" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tcarrier must be MHz as a number, not %s\n' "$(radio_sanitize "$mhz")" >&2; return 2; }
    if ! radio_calib_available; then
        printf 'MISSING\tpython3 with numpy, or %s\n' "$(RADIO_CALIB_PY)" >&2
        printf 'verdict\tunobserved\n'
        printf 'reason\tno-estimator: the frequency estimate needs numpy, and a fallback that guesses would be worse than no answer\n'
        return 1
    fi
    local hz
    hz=$(awk -v m="$mhz" 'BEGIN{printf "%.6f", m*1000000}')
    printf 'carrier_mhz\t%s\n' "$mhz"
    python3 "$(RADIO_CALIB_PY)" tone "$file" "$fmt" "$rate" "$hz" --window-hz "$window"
}

radio_gain_knee() {  # <csv> [--ref-db db]
    local csv="${1:-}"
    (($# >= 1)) && shift
    local ref="1.0"
    while (($#)); do
        case "$1" in
            --ref-db) ref="${2:-}"; shift 2 ;;
            --help|-h) printf 'usage: --gain-knee <gain_db,out_db csv> [--ref-db db]\n'; return 0 ;;
            *) printf 'ERROR\t--gain-knee does not take %s\n' "$(radio_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ -n "$csv" ]] || { printf 'ERROR\t--gain-knee needs a CSV of gain_db,out_db\n' >&2; return 2; }
    if ! radio_calib_available; then
        printf 'verdict\tunobserved\nreason\tno-estimator: numpy or %s is missing\n' "$(RADIO_CALIB_PY)"
        return 1
    fi
    python3 "$(RADIO_CALIB_PY)" gain "$csv" --ref-db "$ref"
}

# Is there anything in this machine that could serve as a frequency reference?
# A clock can only be calibrated against something more accurate than itself,
# so the honest answer is a list of what exists and, when nothing does, that
# the ppm figure is a measurement against the network rather than a traceable
# one.
radio_ref_check() {
    local found=0
    if command -v gpspipe >/dev/null 2>&1 && pgrep -x gpsd >/dev/null 2>&1; then
        printf 'reference\tgpsd\tdetail\t%s\n' \
            "$(gpspipe -w -n 3 2>/dev/null | grep -c '"mode":[23]') fixes seen in 3 sentences"
        found=1
    else
        printf 'absent\tgpsd\tdetail\tno gpsd speaking NMEA, so no GPS-disciplined clock to compare against\n'
    fi
    if [[ -e /dev/pps0 ]]; then
        printf 'reference\tpps\tdetail\t/dev/pps0 exists: a pulse-per-second this radio can be steered by\n'
        found=1
    else
        printf 'absent\tpps\tdetail\tno /dev/pps0: no 1PPS to measure the sample clock against\n'
    fi
    if [[ -d /sys/class/pps ]]; then
        printf 'reference\tpps-sysfs\tdetail\t%s PPS device(s) in /sys/class/pps\n' "$(ls -1 /sys/class/pps 2>/dev/null | wc -l)"
        found=1
    else
        printf 'absent\tpps-sysfs\tdetail\tno /sys/class/pps\n'
    fi
    # A GPSDO on a serial port is the other common arrangement, and there is no
    # way to know which port without asking, so the check states the gap rather
    # than scanning every device.
    printf 'absent\tgpsdo-serial\tdetail\tnot probed: a GPSDO can sit on any serial port, and guessing one would be a fabricated answer\n'
    if (( found )); then
        printf 'verdict\treference-present\n'
        return 0
    fi
    printf 'verdict\tno-reference\n'
    printf 'reason\tnothing here is more accurate than the radio itself, so --calibrate measures against the network (a known carrier) rather than against a traceable standard\n'
    return 1
}

# ═══════════════════════════════════════════════════════════════════
#  CLI dispatch
# ═══════════════════════════════════════════════════════════════════
radio_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   radio_cli_status_tsv ;;
        --list-tsv)     radio_cmd_list_tsv ;;
        --select)       radio_cmd_select "${1:-}" ;;
        --caps-tsv)     radio_cmd_caps_tsv "${1:-}" ;;
        --band-check)   radio_cmd_band_check "${1:-}" ;;
        --set-freq)     radio_cmd_set_freq "${1:-}" ;;
        --set-gain)     radio_cmd_set_gain "${1:-}" ;;
        --set-rate)     radio_cmd_set_rate "${1:-}" ;;
        --plan)         radio_cmd_plan "${1:-}" ;;
        --record)       radio_record "${1:-}" ;;
        --lock-claim)   radio_lock_claim "${1:-}" "${2:-$$}" ;;
        --lock-release) radio_lock_release "${1:-}" ;;
        --lock-status-tsv) radio_lock_status_tsv ;;
        --lock-recover) radio_lock_recover ;;
        --processes-tsv) radio_processes_tsv ;;
        --calibrate)    radio_calibrate "$@" ;;
        --gain-knee)    radio_gain_knee "$@" ;;
        --ref-check)    radio_ref_check ;;
        --selftest)     radio_selftest ;;
        --menu)         radio_menu ;;
        *)
            cat >&2 <<EOF
SDR / Radio Manager — detect, characterise and steer software defined radios

Usage: $0 COMMAND
  --status-tsv               selected device, gain/freq/rate and probe state
  --list-tsv                 every attached SDR, one row each
  --select <index|driver|serial>   select a device (written to \$TMP_DIR/sdr_device)
  --caps-tsv [device]        capability report for one or all devices
  --band-check <mhz>         which band covers this frequency, and can we reach it
  --set-freq <mhz>           set centre frequency for the selection
  --set-gain <db>            set gain for the selection
  --set-rate <sps>           set sample rate for the selection
  --plan [driver]            print the vendor control commands
  --record <seconds>         record raw IQ into captures/ with exclusive ownership
  --lock-claim <owner> [pid] claim the selected SDR for one operation
  --lock-release <owner>     release only that owner's claim
  --lock-status-tsv          owner, PID, device and stale/live state
  --lock-recover             remove a stale claim; refuses a live owner
  --processes-tsv            vendor processes that may hold an SDR open
  --calibrate <carrier_mhz> <file> [--rate sps] [--window hz] [--fmt fmt]
                             the radio's clock error, recovered from a carrier
                             of known frequency, with its own resolution stated
  --gain-knee <gain_db,out_db csv> [--ref-db db]
                             the 1 dB compression point: above it a power
                             reading is the amplifier, not the signal
  --ref-check                is anything here more accurate than the radio
  --selftest                 verify parsers, band tables and the estimator, no radio needed
  --menu                     interactive menu

A receive-only device (rtl-sdr) is flagged on every row. Verbs that need
transmit capability refuse by name instead of failing inside a vendor CLI.
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
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    radio_cli_main "$@"
fi
