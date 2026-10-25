#!/usr/bin/env bash
# ue_agent.sh — the handset as a node on this bench.
#
# Why a phone and not a piece of hardware
# --------------------------------------
# Every other node class in `tools/casebook.py` is something this bench owns:
# a sensor, a local box, a remote shell. A handset is the first node class the
# bench does *not* own and cannot build, and it is the only one that answers
# the questions the radio modules can only infer -- what the network actually
# pushed, what the modem actually negotiated, whether a SIB was decoded.  Phase
# 13 of docs/OFFENSIVE_ROADMAP.md, deferred there by request until now.
#
# What this speaks
# ----------------
# `adb` only.  No root is assumed, no exploit is attempted, and nothing here
# writes to the device: every verb is a read.  The consequence is that the
# answers are the ones a stock handset is willing to give -- a modern Android
# redacts the IMEI and IMSI through most paths, so those two are reported with
# the source that produced them and a plain `unavailable` when the path is
# closed.  The point of the tool is not to defeat that; it is to stop guessing.
#
# Verified without a phone
# ------------------------
# `--selftest` puts a stub `adb` on PATH and runs the parsers against it, so
# the shape of every answer is checked on any host, phone or not.  A parser
# that only runs when hardware is attached is a parser nobody ever tested.
#
# Node integration: `tools/casebook.py node-add <name> <serial> --transport
# adb --role ue`, then `node-probe` and `node-collect` drive this file.
#
# Attack position: authorised use only.  Nothing here transmits.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The adb binary is overridable so the selftest can point at a stub, and so a
# caller with several adb builds can name one.
ue_adb() { printf '%s' "${UE_ADB:-adb}"; }

ue_serial() { printf '%s' "${UE_SERIAL:-}"; }

ue_emit() { printf '%s\t%s\n' "$1" "$2"; }

ue_have_adb() { command -v "$(ue_adb)" >/dev/null 2>&1; }

# Every adb call goes through one place, so the "-s <serial>" threading is
# decided once instead of at twenty call sites.
ue_adbcmd() {
    local bin; bin=$(ue_adb)
    local serial; serial=$(ue_serial)
    if [[ -n "$serial" ]]; then
        "$bin" -s "$serial" "$@"
    else
        "$bin" "$@"
    fi
}

# A phone answers `getprop` and nothing at all answers `dumpsys` on a device
# that is not there, so an empty reply is a state and not an error.
ue_shell() {
    ue_adbcmd shell "$1" 2>/dev/null
}

# `service call` prints a Parcel as 32-bit words.  A string arrives as
# UTF-16LE, two characters per word, each followed by a zero octet; reading
# the words back as bytes and keeping the printable ones recovers it without
# depending on where the length word sits or how the version padded it.
ue_parcel_string() {
    local line="${1:-}"
    if [[ -z "$line" && ! -t 0 ]]; then line=$(cat); fi
    [[ -n "$line" ]] || return 1
    printf '%s\n' "$line" | grep -oE '0x[0-9a-fA-F]{8}' | while read -r word; do
        local hex="${word#0x}" b0 b1 b2 b3
        b0="${hex:6:2}"; b1="${hex:4:2}"; b2="${hex:2:2}"; b3="${hex:0:2}"
        local ch
        for ch in "$b0" "$b1" "$b2" "$b3"; do
            if [[ "$ch" =~ ^[3-7][0-9a-fA-F]$ ]]; then
                printf "\\x$ch"
            fi
        done
    done
}

ue_prop() { ue_shell "getprop $1" | tr -d '\r' | head -1; }

# ── Verbs ───────────────────────────────────────────────────────────────

ue_cmd_probe() {
    if ! ue_have_adb; then
        ue_emit adb "$(ue_adb)"
        ue_emit state absent
        ue_emit status absent
        ue_emit note "no adb on PATH: install platform-tools or set UE_ADB to its path"
        return 3
    fi
    ue_emit adb "$(ue_adb)"
    ue_emit version "$(ue_adbcmd version 2>/dev/null | head -1 | tr -d '\r')"
    local devices
    devices=$(ue_adbcmd devices -l 2>/dev/null | tr -d '\r' | sed -n '2,$p' | grep -v '^$')
    if [[ -z "$devices" ]]; then
        ue_emit state no-device
        ue_emit status no-device
        ue_emit note "the adb server is up; no handset is presenting an adb interface"
        ue_emit how "set the phone's USB option to file transfer or PTP; 'no data transfer' and MIDI present no adb interface"
        ue_emit how "accept the 'Allow USB debugging?' prompt after replugging"
        return 3
    fi
    ue_emit devices "$(printf '%s\n' "$devices" | grep -c '[^[:space:]]')"
    # The first usable line is the device, unless UE_SERIAL names one.
    local line serial state
    line=$(printf '%s\n' "$devices" | awk '$2 != "offline" {print; exit}')
    serial=$(printf '%s' "$line" | awk '{print $1}')
    state=$(printf '%s' "$line" | awk '{print $2}')
    ue_emit serial "$serial"
    ue_emit state "$state"
    ue_emit status "$([[ "$state" == "device" ]] && echo online || echo "$state")"
    if [[ "$state" != "device" ]]; then
        case "$state" in
            unauthorized)
                ue_emit note "the handset is attached and has not authorised this computer"
                ue_emit how "unlock the phone and accept the 'Allow USB debugging?' prompt"
                ue_emit how "tick 'Always allow from this computer' so it stops asking on every replug"
                ue_emit how "no prompt appears: Developer options - revoke USB debugging authorisations, then replug"
                ue_emit how "a stale authorisation looks the same: adb kill-server, then adb start-server" ;;
            offline)
                ue_emit note "the handset is listed offline: the adb server's view of it is stale"
                ue_emit how "adb kill-server; adb start-server; replug the cable" ;;
            *)
                ue_emit note "the handset is in state $state"
                ue_emit how "adb devices -l names the state; authorise it on the phone, then replug" ;;
        esac
        return 3
    fi
}

# What this handset can do, in the same vocabulary `tools/node_agent.sh` uses.
#
# One vocabulary matters: a fleet table that spells a phone's abilities
# differently from a router's cannot be sorted, and the reader ends up comparing
# words instead of capabilities.  Everything named here is a read the handset
# already allows over adb -- no root, no AT parser, no diag interface.  A phone
# that claimed `at` or `diag` would sit in the fleet looking like a modem.
ue_cmd_caps() {
    ue_cmd_probe >/dev/null 2>&1
    local rc=$?
    (( rc == 3 )) && { ue_unavailable; return 3; }
    ue_emit status online
    ue_emit serial "$(ue_serial_line)"
    ue_emit model "$(ue_prop ro.product.model)"
    ue_emit android "$(ue_prop ro.build.version.release)"
    ue_emit cap cells
    ue_emit via-cells "dumpsys telephony.registry"
    ue_emit cap radio-log
    ue_emit via-radio-log "logcat -b radio"
    ue_emit cap identity
    ue_emit via-identity "getprop"
    ue_emit cap network-ue
    ue_emit via-network-ue "attached to the network as a subscriber"
    ue_emit cap battery
    ue_emit via-battery "sysfs"
    if [[ "$(ue_prop gsm.sim.state)" == "READY" ]]; then
        ue_emit cap sim
        ue_emit via-sim "gsm.sim.state"
    fi
    # Root is the difference between reading what Android exposes and reading
    # what the modem exposes; the presence of `su` is the only honest test
    # available over adb, and it is a statement about the build, not the sandbox.
    if [[ -n "$(ue_shell 'command -v su' 2>/dev/null | tr -d '\r')" ]]; then
        ue_emit cap root
        ue_emit via-root "su on PATH"
        ue_emit class phone-rooted
    else
        ue_emit class phone
    fi
}

# The one reason a verb cannot read anything, in the handset's own words.  Every
# verb asks this rather than inventing its own shrug, so "unauthorized" is never
# reported as "absent" — the two need different things from a human.
ue_unavailable() {
    local line state
    line=$(ue_adbcmd devices -l 2>/dev/null | tr -d '\r' | sed -n '2,$p' \
           | awk '$2 != "offline" {print; exit}')
    state=$(printf '%s' "$line" | awk '{print $2}')
    ue_emit status unavailable
    case "$state" in
        unauthorized)
            ue_emit reason "the handset is attached but has not authorised this computer"
            ue_emit how "accept the 'Allow USB debugging?' prompt on the phone"
            ue_emit how "tick 'Always allow from this computer', or revoke authorisations and replug"
            ue_emit usb_mode "file transfer or PTP; 'no data transfer' and MIDI present no adb interface" ;;
        offline)
            ue_emit reason "the handset is listed offline: the server's view of it is stale"
            ue_emit how "adb kill-server; adb start-server; replug" ;;
        *)
            ue_emit reason "no handset is presenting an adb interface"
            ue_emit how "choose file transfer (or PTP) in the USB options; 'no data transfer' and MIDI present none"
            ue_emit how "accept the 'Allow USB debugging?' prompt after replugging" ;;
    esac
    return 3
}

ue_cmd_identity() {
    ue_cmd_probe >/dev/null 2>&1
    local rc=$?
    (( rc == 3 )) && { ue_unavailable; return 3; }
    ue_emit status online
    ue_emit serial "$(ue_serial_line)"
    ue_emit model "$(ue_prop ro.product.model)"
    ue_emit manufacturer "$(ue_prop ro.product.manufacturer)"
    ue_emit device "$(ue_prop ro.product.device)"
    ue_emit android "$(ue_prop ro.build.version.release)"
    ue_emit sdk "$(ue_prop ro.build.version.sdk)"
    ue_emit build "$(ue_prop ro.build.id)"
    ue_emit fingerprint "$(ue_prop ro.build.fingerprint)"

    # IMEI: `dumpsys iphonesubinfo` carried it in cleartext through Android 9
    # and redacts it from 10 onward, where the field reads "Device ID = <null>"
    # or the service refuses.  Report which happened rather than a guess.
    local sub imei src imei_raw=""
    sub=$(ue_shell 'dumpsys iphonesubinfo' | tr -d '\r')
    imei=$(printf '%s\n' "$sub" | sed -n 's/.*Device ID *= *//p' | head -1 | tr -d ' ')
    src='dumpsys iphonesubinfo'
    if [[ -z "$imei" || ! "$imei" =~ ^[0-9]{14,16}$ ]]; then
        imei_raw=$(ue_shell 'service call iphonesubinfo 1' | tr -d '\r')
        imei=$(printf '%s\n' "$imei_raw" | ue_parcel_string | tr -dc '0-9')
        src='service call iphonesubinfo 1 (transaction ids vary by release)'
    fi
    if [[ "$imei" =~ ^[0-9]{14,16}$ ]]; then
        ue_emit imei "$imei"
        ue_emit imei_source "$src"
        ue_emit imei_luhn "$(ue_luhn "$imei" >/dev/null 2>&1 && echo ok || echo fail)"
    else
        # The reason is evidence, not a story: a hardened build (GrapheneOS,
        # a redacting OEM, an MDM) answers with a null field, a permission
        # denial and a refusal to run the service at all, and those are three
        # different facts about the handset.
        local why
        why=$(printf '%s\n' "$sub" | grep -iE 'device id|permission|denial|error|null|exception' \
              | head -1 | sed 's/^[[:space:]]*//')
        if printf '%s' "$imei_raw" | grep -qi 'ffffffff'; then
            # The OS's own null is the fact; the empty parcel says WHY it is a
            # null rather than a number.  Both belong in the one row.
            if [[ -n "$why" ]]; then
                why="$why (the binder call returned an empty string: withheld on this build, not absent from it)"
            else
                why="the binder call succeeded and returned an empty string -- withheld on this build, not absent from it"
            fi
        fi
        ue_emit imei unavailable
        ue_emit imei_evidence "${why:-the service answered, and it named no Device ID at all}"
        ue_emit imei_note "both paths are closed on this handset without root; an IMEI is not a secret the radio needs, it is a secret the OS hides"
    fi

    # IMSI: same story, one more indirection -- the subscriber id is behind a
    # per-subscription call and needs READ_PHONE_STATE even where it is not
    # redacted.
    local imsi imsi_raw
    imsi_raw=$(ue_shell 'service call iphonesubinfo 7' | tr -d '\r')
    imsi=$(printf '%s' "$imsi_raw" | ue_parcel_string | tr -dc '0-9')
    if (( ${#imsi} >= 14 && ${#imsi} <= 16 )); then
        ue_emit imsi "$imsi"
        ue_emit imsi_mcc_mnc "$(printf '%s' "$imsi" | cut -c1-5)"
        ue_emit imsi_source "service call iphonesubinfo 7"
    else
        local ireason
        ireason=$(printf '%s\n' "$imsi_raw" | grep -vE '^[[:space:]]*$' \
                  | grep -iE 'permission|denial|error|null|exception|unknown' | head -1 \
                  | sed 's/^[[:space:]]*//')
        if [[ -z "$ireason" ]] && printf '%s' "$imsi_raw" | grep -qi 'ffffffff'; then
            ireason="the binder call succeeded and returned an empty string -- withheld on this build, not absent from it"
        fi
        ue_emit imsi unavailable
        ue_emit imsi_evidence "${ireason:-the per-subscription call answered with no digits}"
        ue_emit imsi_note "closed without READ_PHONE_STATE; the radio modules can still read it off the wire"
    fi

    # Some builds publish a LIST here ("20825,20825") and some a single value.
    # The row is the network the SIM is registered to, so take the first entry
    # and name the two halves of it rather than printing a comma.
    local numeric
    numeric=$(ue_numeric)
    ue_emit sim_state "$(ue_sim_state)"
    ue_emit sim_operator "$numeric"
    ue_emit sim_operator_name "$(ue_prop gsm.sim.operator.alpha)"
    if [[ "$numeric" =~ ^[0-9]{5,6}$ ]]; then
        ue_emit sim_mcc "$(printf '%s' "$numeric" | cut -c1-3)"
        ue_emit sim_mnc "$(printf '%s' "$numeric" | cut -c4-)"
    fi
}

ue_sim_state() {
    local s
    s=$(ue_shell 'getprop gsm.sim.state' | tr -d '\r' | head -1)
    printf '%s' "${s:-unknown}"
}

# The serial of the handset this run is talking to, resolved the same way
# probe resolves it.
ue_serial_line() {
    if [[ -n "$(ue_serial)" ]]; then
        printf '%s' "$(ue_serial)"; return
    fi
    ue_adbcmd devices -l 2>/dev/null | tr -d '\r' | sed -n '2,$p' \
        | awk '$2 == "device" {print $1; exit}'
}

# Luhn is the checksum the IMEI's last digit carries; a spoofed or transcribed
# IMEI usually fails it, so the report says which.
ue_luhn() {
    local digits="${1:-}" i d sum=0 double=0
    [[ "$digits" =~ ^[0-9]{14,16}$ ]] || return 1
    local rev="" n=${#digits}
    for (( i = n - 1; i >= 0; i-- )); do rev+="${digits:i:1}"; done
    for (( i = 0; i < n - 1; i++ )); do
        d=${rev:i:1}
        if (( double )); then
            d=$(( d * 2 ))
            (( d > 9 )) && d=$(( d - 9 ))
        fi
        sum=$(( sum + d ))
        double=$(( 1 - double ))
    done
    (( (sum + ${rev:n-1:1}) % 10 == 0 ))
}

# `gsm.sim.operator.numeric` is a LIST on some builds ("20825,20825") and a
# single value on others.  The first entry is the registration; the comma is
# not part of an MCC/MNC.
ue_numeric() {
    ue_prop "${1:-gsm.sim.operator.numeric}" | tr ',' '\n' | head -1 | tr -d '[:space:]'
}

ue_cmd_radio() {
    ue_cmd_probe >/dev/null 2>&1
    local rc=$?; (( rc == 3 )) && { ue_unavailable; return 3; }
    ue_emit status online
    ue_emit sim_state "$(ue_sim_state)"
    ue_emit sim_operator "$(ue_numeric)"
    ue_emit network_operator "$(ue_numeric gsm.operator.numeric)"
    ue_emit network_type "$(ue_prop gsm.network.type)"
    ue_emit roaming "$(ue_prop gsm.roaming.state)"
    ue_emit data_state "$(ue_prop gsm.data.state)"
    local reg
    reg=$(ue_shell 'dumpsys telephony.registry' | tr -d '\r')
    ue_emit service_state "$(printf '%s\n' "$reg" | sed -n 's/.*mServiceState=.* mVoiceRegState=\([0-9]*\).*/\1/p' | head -1)"
    ue_emit signal_rsrp "$(printf '%s\n' "$reg" | sed -n 's/.*mRsrp *= *\(-\{0,1\}[0-9]*\).*/\1/p' | head -1)"
    ue_emit signal_rsrq "$(printf '%s\n' "$reg" | sed -n 's/.*mRsrq *= *\(-\{0,1\}[0-9]*\).*/\1/p' | head -1)"
    ue_emit signal_db "$(printf '%s\n' "$reg" | sed -n 's/.*mSignalStrength=.*mGsmSignalStrength = \([0-9]*\).*/\1/p' | head -1)"
}

# The serving cell is the one observation that cannot be inferred from the
# bench's own radio: this is what the phone was actually camped on.  The dump
# is parsed by tools/ue_cells.py rather than by an awk here, because the shapes
# that broke it are not grep-shaped: the same cell printed several times, the
# identity nested inside a CellInfo wrapper that also carries its signal
# strength, band lists that contain commas, and a hardened build that writes
# "[****]" where a number belongs.  That parser has its own fixtures.
ue_cmd_cells() {
    local file=""
    while (( $# )); do
        case "$1" in
            --file) file="${2:-}"; shift 2 ;;
            *)      shift ;;
        esac
    done
    local parser="$ROOT/tools/ue_cells.py"
    if [[ ! -f "$parser" ]]; then
        printf 'ERROR\t%s is missing\nWHY\tthe registry layout is not a shell job\n' "$parser"
        return 1
    fi
    local text=""
    if [[ -n "$file" ]]; then
        if [[ ! -f "$file" ]]; then
            printf 'ERROR\tno such file: %s\n' "$file"
            return 2
        fi
        text="$file"
    else
        ue_cmd_probe >/dev/null 2>&1
        local rc=$?; (( rc == 3 )) && { ue_unavailable; return 3; }
        local reg
        reg=$(ue_shell 'dumpsys telephony.registry' | tr -d '\r')
        printf '%s\n' "$reg" | python3 "$parser" rows
        return $?
    fi
    python3 "$parser" rows --file "$text"
}

# The modem's own account of what it did: `adb logcat -b radio`, sorted into
# PDUs and text.  The parsing lives in tools/radio_logcat.py because reading a
# log is not a shell job, and because the fixtures have to run on a host with no
# handset.  This verb is the fetch and the row shape; nothing here guesses at
# the octets.
ue_cmd_radio_log() {
    local file="" lines=400 commands=0 decode=0
    while (( $# )); do
        case "$1" in
            --file)     file="${2:-}"; shift 2 ;;
            --lines)    lines="${2:-400}"; shift 2 ;;
            --commands) commands=1; shift ;;
            --decode)   decode=1; shift ;;
            *)          shift ;;
        esac
    done
    local parser="$ROOT/tools/radio_logcat.py"
    [[ -f "$parser" ]] || { printf 'ERROR\tno %s\n' "$parser" >&2; return 1; }
    local args=() log="" source="file"
    (( commands )) && args+=(--commands)
    (( decode )) && args+=(--decode)
    if [[ -n "$file" ]]; then
        [[ -f "$file" ]] || { ue_emit status no-such-file; ue_emit path "$file"; return 2; }
        log="$file"
    else
        ue_cmd_probe >/dev/null 2>&1
        local rc=$?; (( rc == 3 )) && {
            ue_emit status unavailable
            ue_emit reason "no handset is attached and no --file was given; the parser runs on a saved log"
            return 3
        }
        source="adb"
        log="$(mktemp)"
        # -d prints what is buffered and exits, -t bounds it so a chatty modem
        # cannot fill the disk, and threadtime is the layout the parser reads.
        ue_adbcmd logcat -b radio -d -v threadtime -t "$lines" > "$log" 2>/dev/null
        ue_emit fetched_lines "$(wc -l < "$log" | tr -d ' ')"
        ue_emit buffer_lines "$lines"
    fi
    local rows
    rows=$(python3 "$parser" parse "$log" --rows "${args[@]}" 2>&1)
    local rc2=$?
    [[ "$source" == "adb" ]] && rm -f "$log"
    if (( rc2 != 0 )); then
        ue_emit status parse-failed
        printf '%s\n' "$rows" >&2
        return 1
    fi
    printf '%s\n' "$rows" | sed "s/^source\t.*/source\t$source/"
}

# A file the operator asks for by name; adb pull, then casebook indexes it.
ue_cmd_collect() {
    local remote="${1:-}" local_dir="${2:-}"
    if [[ -z "$remote" ]]; then
        printf 'ERROR\tneed <device-path> [local-dir]\n' >&2
        return 2
    fi
    ue_cmd_probe >/dev/null 2>&1
    local rc=$?; (( rc == 3 )) && { ue_unavailable; return 3; }
    [[ -n "$local_dir" ]] || local_dir="${TMP_DIR:-/tmp/imsisting}/ue-pull"
    mkdir -p "$local_dir" || return 1
    ue_emit status pulling
    ue_emit remote "$remote"
    ue_emit local "$local_dir"
    if ue_adbcmd pull "$remote" "$local_dir" 2>&1 | tr -d '\r'; then
        ue_emit result pulled
        return 0
    fi
    ue_emit result failed
    return 1
}

ue_cmd_plan() {
    cat << 'EOF'
step	what it needs	why it is not automatic
pair	USB debugging enabled, the host key accepted on the handset	nothing here can accept the prompt for you; that is a human at the glass
probe	adb devices shows "device"	"unauthorized" means the prompt is still up, "offline" means the server is stale
read	no permission beyond what adb already holds	every verb here is a read; a write is not part of this tool
usb mode	file transfer or PTP in the phone's USB options	"no data transfer" and MIDI present no adb interface at all, so no verb here can see the handset
identify	READ_PHONE_STATE for IMSI, nothing for IMEI on a modern build	the OS hides both; report the source, do not pretend
cells	dumpsys telephony.registry	a stock build answers; a locked-down MDM build may not
collect	the path named explicitly	adb pull takes a path, and a path is a decision the caller makes
EOF
}

# ── Selftest ────────────────────────────────────────────────────────────
#
# A stub adb, because the parsers are the part that can be wrong.  The stub
# answers the exact commands the verbs issue and nothing else, so a verb that
# starts calling a new command fails loudly instead of silently reading "".
ue_selftest() {
    local pass=0 fail=0
    local stub_dir; stub_dir=$(mktemp -d)
    local saved_path="$PATH" saved_serial="${UE_SERIAL:-}"

    # UTF-16LE "310150123456789" as Parcel words: each word carries two
    # characters, first character in the low 16 bits.
    cat > "$stub_dir/adb" <<'EOF'
#!/usr/bin/env bash
serial=""
if [[ "${1:-}" == "-s" ]]; then serial="$2"; shift 2; fi
case "$*" in
    version) printf 'Android Debug Bridge version 1.0.41\n' ;;
    "devices -l") printf 'List of devices attached\nR58M12345\tdevice product:beyond1 model:SM_G973F device:beyond1 transport_id:1\n' ;;
    "shell getprop ro.product.model") printf 'SM-G973F\r\n' ;;
    "shell getprop ro.product.manufacturer") printf 'samsung\r\n' ;;
    "shell getprop ro.product.device") printf 'beyond1\r\n' ;;
    "shell getprop ro.build.version.release") printf '13\r\n' ;;
    "shell getprop ro.build.version.sdk") printf '33\r\n' ;;
    "shell getprop ro.build.id") printf 'TP1A.220624.014\r\n' ;;
    "shell getprop ro.build.fingerprint") printf 'samsung/beyond1/beyond1:13/TP1A.220624.014/x:user/release-keys\r\n' ;;
    "shell getprop gsm.sim.state") printf 'READY\r\n' ;;
    "shell getprop gsm.sim.operator.numeric") printf '310260,310260\r\n' ;;
    "shell getprop gsm.sim.operator.alpha") printf 'T-Mobile\r\n' ;;
    "shell getprop gsm.operator.numeric") printf '310260\r\n' ;;
    "shell getprop gsm.network.type") printf 'LTE\r\n' ;;
    "shell getprop gsm.roaming.state") printf 'false\r\n' ;;
    "shell getprop gsm.data.state") printf 'CONNECTED\r\n' ;;
    "shell dumpsys iphonesubinfo") printf 'Phone Subscriber Info:\n  Service Info: Device ID = 356938035643809\n' ;;
    "shell service call iphonesubinfo 1") printf 'Result: Parcel(\n  0x00000000 0x00330033 0x00390036 0x00380033 0x00300033 0x00350033 0x00340036 0x00330033 0x00390038 0x00000000 '"'"'.'"'"')\n' ;;
    "shell service call iphonesubinfo 7") printf 'Result: Parcel(0x0000000f 0x00310033 0x00310030 0x00300035 0x00320031 0x00340033 0x00360035 0x00380037 0x00000039 '"'"'.'"'"')\n' ;;
    "shell dumpsys telephony.registry")
        printf '  mServiceState=ServiceState{ mVoiceRegState=0 mDataRegState=0 }\n  mSignalStrength=SignalStrength: 20 -1 -1 -1 -1 mGsmSignalStrength = 20 mRsrp = -95 mRsrq = -11\n'
        # The modern layout puts spaces around "=" and prints a neighbour block
        # after the serving one; the withheld variant is what a handset that
        # refuses to publish its identity looks like.
        if [[ "${UE_STUB_CELLS:-}" == "withheld" ]]; then
            printf '  mCellIdentity=CellIdentityLte:{ mCi = 12345678 mPci = Unknown mTac = 26011 mMcc = 310 mMnc = 260 }\n'
        else
            # The shape a hardened build actually prints: identifiers redacted,
            # band lists that contain commas, and the serving cell repeated bare
            # and then inside CellInfo carrying its signal strength.
            printf '  mCellIdentity=CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [3] mBandwidth = 20000 mMcc = 208 mMnc = 20 mAlphaLong = LycaMobile mAlphaShort = LycaMobile mAdditionalPlmns = {} mCsgInfo = null }\n'
            printf '  mCellInfo=[CellInfoLte:{ mRegistered=YES mTimeStamp=1 mCellIdentityLte=CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [3] mBandwidth = 20000 mMcc = 208 mMnc = 20 } mCellSignalStrengthLte = { rsrp = -97 rsrq = -12 } }, CellInfoLte:{ mRegistered=NO mTimeStamp=2 mCellIdentityLte=CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [20,3] mBandwidth = 10000 mMcc = null mMnc = null } mCellSignalStrengthLte = { rsrp = -111 } }]\n'
        fi ;;
    # The radio buffer: prose, an AT trace, a proven APDU and a proven NAS PDU.
    "logcat -b radio -d -v threadtime -t 400") printf '01-02 03:04:05.678  1234  5678 D RILJ    : [UNSL]< UNSOL_RESPONSE_NETWORK_STATE\n01-02 03:04:05.679  1234  5678 D AT      : AT> AT+CSQ\n01-02 03:04:05.681  1234  5678 D RIL     : AT< +CRSM: 144,0,\"002F0A0B0C\"\n01-02 03:04:05.682  1234  5678 D RILC    : NAS: 07 41 0b f1 10\n' ;;
    *) printf 'stub: unhandled command: %s\n' "$*" >&2; exit 127 ;;
esac
EOF
    chmod +x "$stub_dir/adb"

    ue_check() {
        local name="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf 'PASS\t%s\n' "$name"; pass=$((pass+1))
        else printf 'FAIL\t%s\twant=%s got=%s\n' "$name" "$want" "$got"; fail=$((fail+1)); fi
    }

    # 1. Without adb, every verb says so and exits 3 rather than inventing a
    #    device.  This is the path a fresh host takes.
    local out rc
    out=$(UE_ADB=definitely-not-adb bash "${BASH_SOURCE[0]}" --probe 2>/dev/null); rc=$?
    ue_check probe-absent-rc    "$rc"  "3"
    ue_check probe-absent-state "$(printf '%s\n' "$out" | awk -F'\t' '$1=="state"{print $2}')" "absent"
    out=$(UE_ADB=definitely-not-adb bash "${BASH_SOURCE[0]}" --identity 2>/dev/null); rc=$?
    ue_check identity-absent-rc "$rc" "3"

    # 2. The parsers against the stub.
    PATH="$stub_dir:$saved_path"
    export UE_ADB="$stub_dir/adb"
    out=$(bash "${BASH_SOURCE[0]}" --probe 2>/dev/null)
    ue_check probe-serial  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="serial"{print $2}')" "R58M12345"
    ue_check probe-state   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="state"{print $2}')"  "device"
    ue_check probe-devices "$(printf '%s\n' "$out" | awk -F'\t' '$1=="devices"{print $2}')" "1"
    ue_check probe-online  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')" "online"

    # 2b. The caps verb speaks the node_agent vocabulary, so a phone and a
    #     router can sit in one fleet table.  A handset must never claim an AT
    #     parser or a diag interface: it has neither without root.
    out=$(bash "${BASH_SOURCE[0]}" --caps 2>/dev/null)
    ue_check caps-status    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')" "online"
    ue_check caps-class     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="class"{print $2}')"  "phone"
    ue_check caps-cells     "$(printf '%s\n' "$out" | grep -c '^cap	cells$')"               "1"
    ue_check caps-radio-log "$(printf '%s\n' "$out" | grep -c '^cap	radio-log$')"           "1"
    ue_check caps-sim       "$(printf '%s\n' "$out" | grep -c '^cap	sim$')"                 "1"
    ue_check caps-no-at     "$(printf '%s\n' "$out" | grep -c '^cap	at$')"                  "0"
    ue_check caps-no-diag   "$(printf '%s\n' "$out" | grep -c '^cap	diag$')"                "0"
    ue_check caps-no-root   "$(printf '%s\n' "$out" | grep -c '^cap	root$')"                "0"
    out=$(UE_ADB=definitely-not-adb bash "${BASH_SOURCE[0]}" --caps 2>/dev/null); rc=$?
    ue_check caps-absent-rc "$rc" "3"
    ue_check caps-absent-class "$(printf '%s\n' "$out" | grep -c '^class')" "0"

    out=$(bash "${BASH_SOURCE[0]}" --identity 2>/dev/null)
    ue_check ident-model   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="model"{print $2}')"        "SM-G973F"
    ue_check ident-android "$(printf '%s\n' "$out" | awk -F'\t' '$1=="android"{print $2}')"      "13"
    ue_check ident-imei    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="imei"{print $2}')"         "356938035643809"
    ue_check ident-luhn    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="imei_luhn"{print $2}')"    "ok"
    ue_check ident-imsi    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="imsi"{print $2}')"         "310150123456789"
    ue_check ident-mccmnc  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="imsi_mcc_mnc"{print $2}')" "31015"
    ue_check ident-sim     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sim_state"{print $2}')"    "READY"

    # 3. The Parcel decoder on its own: zeros are padding, not characters.
    ue_check parcel-imsi "$(ue_parcel_string 'Result: Parcel(0x0000000f 0x00310033 0x00310030)' | tr -dc '0-9')" "3101"
    ue_check parcel-empty "$(ue_parcel_string '' >/dev/null 2>&1; echo $?)" "1"
    # 4. Luhn: the IMEI's check digit, which a spoofed or mistyped one fails.
    ue_check luhn-good "$(ue_luhn 356938035643809 >/dev/null 2>&1; echo $?)" "0"
    ue_check luhn-bad  "$(ue_luhn 356938035643808 >/dev/null 2>&1; echo $?)" "1"
    ue_check luhn-short "$(ue_luhn 12345 >/dev/null 2>&1; echo $?)" "1"

    out=$(bash "${BASH_SOURCE[0]}" --radio 2>/dev/null)
    ue_check radio-rat     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="network_type"{print $2}')"  "LTE"
    ue_check radio-rsrp    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="signal_rsrp"{print $2}')"   "-95"
    ue_check radio-rsrq    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="signal_rsrq"{print $2}')"   "-11"

    out=$(bash "${BASH_SOURCE[0]}" --cells 2>/dev/null)
    ue_check cell-rat      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rat"{print $2}')"           "Lte"
    # A redacted identifier is a value the handset HAS and will not print.  It
    # reaches the reader as the token the handset used, never as empty and never
    # as a number the parser guessed.
    ue_check cell-ci       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="cell.Ci"{print $2}')"       "[****]"
    ue_check cell-mcc      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="cell.Mcc"{print $2}')"      "208"
    ue_check cell-bw       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="cell.Bandwidth"{print $2}')" "20000"
    # Three printed blocks, two cells: the serving cell is printed bare and then
    # inside CellInfo, and reading both as separate cells invents a neighbour.
    ue_check cell-blocks   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="blocks"{print $2}')"       "2"
    ue_check cell-deduped  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="duplicates"{print $2}')"   "1"
    ue_check cell-withheld "$(printf '%s\n' "$out" | awk -F'\t' '$1=="withheld"{print $2}')"     "Ci Pci Tac Earfcn"
    ue_check cell-nb-bands "$(printf '%s\n' "$out" | awk -F'\t' '$1=="cells.2.Bands"{print $2}')" "[20,3]"
    ue_check cell-nb-null  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="cells.2.Mcc"{print $2}')"  "null"
    ue_check cell-rsrp     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="signal_rsrp"{print $2}')"  "-97"
    out=$(UE_STUB_CELLS=withheld PATH="$stub_dir:$saved_path" UE_ADB="$stub_dir/adb" bash "${BASH_SOURCE[0]}" --cells 2>/dev/null)
    ue_check cell-withheld-w "$(printf '%s\n' "$out" | awk -F'\t' '$1=="withheld"{print $2}')"   "Pci"
    ue_check cell-missing   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="missing"{print $2}')"     "Earfcn"
    ue_check cell-status   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')"        "cell-seen"

    # The saved-dump path: the same parser with no handset in the room.  This is
    # how a live layout gets pinned, and it must not need a device to work.
    local dump="$stub_dir/registry.txt"
    printf '  mCellInfo=[CellInfoLte:{ mRegistered=YES mCellConnectionStatus=1 CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [20, 3] mBandwidth = 10000 mMcc = 208 mMnc = 20 } CellSignalStrengthLte:{ rsrp = -75 cqi = 15 level = 4 }}]\n' > "$dump"
    out=$(UE_ADB=definitely-not-adb bash "${BASH_SOURCE[0]}" --cells --file "$dump" 2>/dev/null)
    ue_check cell-file-blocks   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="blocks"{print $2}')"      "1"
    ue_check cell-file-scalar   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="cell.CellConnectionStatus"{print $2}')" "1"
    ue_check cell-file-withheld "$(printf '%s\n' "$out" | awk -F'\t' '$1=="withheld"{print $2}')" "Ci Pci Tac Earfcn"

    # 4b. The radio log: a saved log parses without a handset, a live one comes
    #     through adb, and the parser is never asked to invent octets.
    local log_file="$stub_dir/radio.log"
    printf '%s\n' \
        '01-02 03:04:05.678  1234  5678 D RILJ    : [UNSL]< UNSOL_RESPONSE_NETWORK_STATE' \
        '01-02 03:04:05.681  1234  5678 D RIL     : AT< +CRSM: 144,0,"002F0A0B0C"' \
        '01-02 03:04:05.682  1234  5678 D RILC    : NAS: 07 41 0b f1 10' > "$log_file"
    out=$(bash "${BASH_SOURCE[0]}" --radio-log --file "$log_file" 2>/dev/null)
    ue_check radio-log-file-status "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')" "parsed"
    ue_check radio-log-file-pdus   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="pdus"{print $2}')"   "2"
    ue_check radio-log-file-proven "$(printf '%s\n' "$out" | awk -F'\t' '$1=="proven"{print $2}')" "2"
    ue_check radio-log-prose       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="prose"{print $2}')"  "1"
    ue_check radio-log-layer       "$(printf '%s\n' "$out" | awk -F'\t' '$1~/^layer\.nas-eps$/{print $2}')" "1"
    out=$(bash "${BASH_SOURCE[0]}" --radio-log 2>/dev/null)
    ue_check radio-log-adb-source "$(printf '%s\n' "$out" | awk -F'\t' '$1=="source"{print $2}')" "adb"
    ue_check radio-log-adb-pdus   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="pdus"{print $2}')"   "2"
    ue_check radio-log-missing-rc "$(bash "${BASH_SOURCE[0]}" --radio-log --file "$stub_dir/nope.log" >/dev/null 2>&1; echo $?)" "2"
    ue_check radio-log-nohandset-rc "$(UE_ADB=definitely-not-adb bash "${BASH_SOURCE[0]}" --radio-log >/dev/null 2>&1; echo $?)" "3"
    # The decode step runs the verbs it names: the NAS line comes back with a
    # message name from 32_nas_signaling, not with this file's own guess.
    out=$(bash "${BASH_SOURCE[0]}" --radio-log --file "$log_file" --decode 2>/dev/null)
    ue_check radio-log-decoded-count "$(printf '%s\n' "$out" | awk -F'\t' '$1~/^decoded\.[0-9]+\.status$/{n++} END{print n+0}')" "2"
    ue_check radio-log-decoded-nas "$(printf '%s\n' "$out" | awk -F'\t' '$1~/^decoded\.[0-9]+\.field\.message_name$/{print $2}')" "Attach request"

    # 5. Argument handling and the disarmed-by-default surface: no verb here
    #    writes to the handset, and collect without a path is a usage error.
    ue_check collect-nopath "$(bash "${BASH_SOURCE[0]}" --collect >/dev/null 2>&1; echo $?)" "2"
    ue_check collect-online "$(PATH="$stub_dir:$saved_path" bash "${BASH_SOURCE[0]}" --collect /sdcard/Download/trace.pcap "$stub_dir" 2>/dev/null | awk -F'\t' '$1=="status"{print $2}')" "pulling"

    # 6. The plan names the human steps and nothing pretends to be automatic.
    out=$(bash "${BASH_SOURCE[0]}" --plan 2>/dev/null)
    ue_check plan-rows  "$(printf '%s\n' "$out" | grep -c '^step')" "1"
    ue_check plan-pair  "$(printf '%s\n' "$out" | grep -c '^pair')" "1"

    # 7. A handset that is plugged in and has not been authorised is NOT the
    #    same as one that is absent: it is a prompt waiting on a human, and a
    #    verb that called it "no handset to ask" sent the reader looking for a
    #    cable.  Both verbs must name the state and the step that clears it.
    local unauth_dir; unauth_dir=$(mktemp -d)
    cat > "$unauth_dir/adb" <<'STUB'
#!/usr/bin/env bash
case "$*" in
    version) printf 'Android Debug Bridge version 1.0.41\n' ;;
    "devices -l") printf 'List of devices attached\n33201FDH2004W1\tunauthorized usb:1-2 transport_id:3\n' ;;
    *) printf 'stub: unhandled command: %s\n' "$*" >&2; exit 127 ;;
esac
STUB
    chmod +x "$unauth_dir/adb"

    out=$(UE_ADB="$unauth_dir/adb" PATH="$unauth_dir:$saved_path" bash "${BASH_SOURCE[0]}" --probe 2>/dev/null); rc=$?
    ue_check unauth-probe-rc     "$rc" "3"
    ue_check unauth-probe-serial "$(printf '%s\n' "$out" | awk -F'\t' '$1=="serial"{print $2}')" "33201FDH2004W1"
    ue_check unauth-probe-state  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="state"{print $2}')"  "unauthorized"
    ue_check unauth-probe-count  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="devices"{print $2}')" "1"

    ue_check unauth-probe-note   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="note"{print $2}')" \
                                 "the handset is attached and has not authorised this computer"
    ue_check unauth-probe-how    "$(printf '%s\n' "$out" | grep -c '^how')" "4"

    out=$(UE_ADB="$unauth_dir/adb" PATH="$unauth_dir:$saved_path" bash "${BASH_SOURCE[0]}" --identity 2>/dev/null); rc=$?
    ue_check unauth-identity-rc     "$rc" "3"
    ue_check unauth-identity-reason "$(printf '%s\n' "$out" | awk -F'\t' '$1=="reason"{print $2}')" \
                                    "the handset is attached but has not authorised this computer"
    ue_check unauth-identity-usb    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="usb_mode"{print $2}')" \
                                    "file transfer or PTP; 'no data transfer' and MIDI present no adb interface"
    # 8. The operator code arrives as a list on a real handset.  The comma is
    #    not part of an MCC/MNC, so the row and its two halves must be the
    #    first entry only.
    out=$(PATH="$stub_dir:$saved_path" UE_ADB="$stub_dir/adb" bash "${BASH_SOURCE[0]}" --radio 2>/dev/null)
    ue_check radio-sim-operator   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sim_operator"{print $2}')" "310260"
    ue_check radio-network-op     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="network_operator"{print $2}')" "310260"
    out=$(PATH="$stub_dir:$saved_path" UE_ADB="$stub_dir/adb" bash "${BASH_SOURCE[0]}" --identity 2>/dev/null)
    ue_check identity-sim-mcc     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sim_mcc"{print $2}')" "310"
    ue_check identity-sim-mnc     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sim_mnc"{print $2}')" "260"
    # 9. A hardened OS that REDACTES answers the binder call successfully with an
    #    empty string.  That is not the same as a missing field, a permission
    #    denial, or a service that will not run, and the evidence row says which.
    local redact_dir; redact_dir=$(mktemp -d)
    cat > "$redact_dir/adb" <<'STUB'
#!/usr/bin/env bash
case "$*" in
    version) printf 'Android Debug Bridge version 1.0.41\n' ;;
    "devices -l") printf 'List of devices attached\n33201FDH2004W1\tdevice usb:1-2 transport_id:3\n' ;;
    shell\ getprop\ *) printf '\r\n' ;;
    "shell dumpsys iphonesubinfo") printf 'Phone Subscriber Info:\n  Service Info: Device ID = <null>\n' ;;
    "shell service call iphonesubinfo 1"|"shell service call iphonesubinfo 7") printf "Result: Parcel( 00000000 ffffffff '........')\n" ;;
    *) printf 'stub: unhandled command: %s\n' "$*" >&2; exit 127 ;;
esac
STUB
    chmod +x "$redact_dir/adb"
    out=$(UE_ADB="$redact_dir/adb" PATH="$redact_dir:$saved_path" bash "${BASH_SOURCE[0]}" --identity 2>/dev/null)
    ue_check redacted-imei "$(printf '%s\n' "$out" | awk -F'\t' '$1=="imei"{print $2}')" "unavailable"
    ue_check redacted-imei-evidence \
        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="imei_evidence"{print $2}' | grep -c 'withheld on this build')" "1"
    ue_check redacted-imsi-evidence \
        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="imsi_evidence"{print $2}' | grep -c 'withheld on this build')" "1"
    rm -rf "$redact_dir"

    rm -rf "$unauth_dir"

    UE_SERIAL="$saved_serial"
    export PATH="$saved_path"
    rm -rf "$stub_dir"
    printf 'ASSERTIONS\t%s\n' "$((pass + fail))"
    if (( fail == 0 )); then printf 'RESULT\tPASS\n'; else printf 'RESULT\tFAIL(%s)\n' "$fail"; fi
    (( fail == 0 ))
}

# ── Dispatch ────────────────────────────────────────────────────────────
ue_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --probe)     ue_cmd_probe ;;
        --caps)      ue_cmd_caps ;;
        --identity)  ue_cmd_identity ;;
        --radio)     ue_cmd_radio ;;
        --cells)     ue_cmd_cells "$@" ;;
        --radio-log) ue_cmd_radio_log "$@" ;;
        --collect)   ue_cmd_collect "${1:-}" "${2:-}" ;;
        --plan)      ue_cmd_plan ;;
        --selftest)  ue_selftest ;;
        *)
            cat >&2 <<EOF
ue_agent — the handset as a node (Phase 13)

Usage: $0 COMMAND
  --probe       adb present, device present, serial and state
  --caps        what this handset can do, in the node_agent vocabulary
  --identity    model, build, IMEI, IMSI, SIM -- each with its source
  --radio       SIM state, operator, network type, signal
  --cells       the serving cell as the handset sees it [--file dump.txt]
  --radio-log [--file PATH] [--lines N] [--commands] [--decode]
                the modems own radio buffer, sorted into PDUs and text
                (no handset? give it a saved log with --file)
  --collect <device-path> [local-dir]
                adb pull one named file; nothing is dispatched blind
  --plan        the human steps this tool cannot do for you
  --selftest    run the parsers against a stub adb, no phone needed

Env: UE_ADB (adb binary), UE_SERIAL (pick one device)
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    ue_main "$@"
fi
