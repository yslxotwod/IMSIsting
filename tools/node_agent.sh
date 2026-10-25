#!/bin/sh
# node_agent.sh — the far side of a remote node, as one file you can pipe.
#
# Why a file on stdin and not an install
# --------------------------------------
#     ssh host 'sh -s -- --caps' < tools/node_agent.sh
#
# runs this without copying anything to the node, without a writable /tmp, and
# without leaving a file behind.  A router with four megabytes of free flash and
# a dongle in a van are both reachable that way, and `sh -s` is the one thing
# every one of them has.  `tools/casebook.py` does exactly this; nothing else
# pushes this file anywhere.
#
# What a capability means here
# ----------------------------
# A cap is reported because a tool that can do the job answers on PATH, or
# because the device node a modem would appear as exists.  That is the same
# standard `31_remote_node` in wifisting uses (`command -v`), and it is the
# honest one: this file does not open the device, so it cannot claim the device
# works.  Two consequences are stated in the output rather than hidden:
#
#   * `sdr-tx` says a transmitter's tooling is installed, not that an antenna
#     will radiate.  The `note` row says so in words.
#   * a node with no caps at all is classed `relay`, not `sensor`, because a box
#     that cannot hear anything is a place to keep files, not a place to listen.
#
# What it does not do
# -------------------
# No identity, no key material, no traffic.  Serials, IMEIs and IMSIs belong in
# `ue_agent.sh --identity` and the loot stores that index them; a capability
# probe that quietly collected identifiers would put them in a node table that
# gets copied into case exports.  Everything here is about *what the box can do*.
#
# Node prefix
# -----------
# Every /dev, /sys, /proc and /etc lookup goes through `$NODE_PREFIX`, which is
# empty in real use.  That is not decoration: it is what lets `--selftest`
# prove the class inference on a laptop with no modem attached, instead of
# shipping a parser nobody ever ran.
#
# Output is strict TSV, key<TAB>value, one row per fact.
# Exit 0 reported, 2 refused (nothing to ask), 3 handoff (asked, cannot answer).

set -u

NODE_PREFIX=${NODE_PREFIX:-}

na_emit() { printf '%s\t%s\n' "$1" "$2"; }

na_have() { command -v "$1" >/dev/null 2>&1; }

# First tool from a list that answers on PATH; prints its name.
na_first_cmd() {
    for tool in "$@"; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '%s' "$tool"
            return 0
        fi
    done
    return 1
}

# First existing path from a list of globs, prefix-aware; prints the path.
na_first_path() {
    for pattern in "$@"; do
        set -- $NODE_PREFIX$pattern
        if [ -e "$1" ]; then
            printf '%s' "$1"
            return 0
        fi
    done
    return 1
}

na_read() {
    [ -r "$NODE_PREFIX$1" ] && head -n 1 "$NODE_PREFIX$1" 2>/dev/null | tr -d '\r'
}

na_os_name() {
    if [ -r "$NODE_PREFIX/etc/os-release" ]; then
        sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$NODE_PREFIX/etc/os-release" | head -n 1
        return 0
    fi
    if [ -r "$NODE_PREFIX/etc/openwrt_release" ]; then
        sed -n "s/^DISTRIB_DESCRIPTION='\{0,1\}\([^']*\)'\{0,1\}$/\1/p" "$NODE_PREFIX/etc/openwrt_release" | head -n 1
        return 0
    fi
    uname -s 2>/dev/null
}

na_board_model() {
    na_read /proc/device-tree/model 2>/dev/null || na_read /sys/firmware/devicetree/base/model 2>/dev/null
}

# ── Verbs ───────────────────────────────────────────────────────────────

na_cmd_probe() {
    na_emit host "$(hostname 2>/dev/null || uname -n 2>/dev/null)"
    na_emit kernel "$(uname -r 2>/dev/null)"
    na_emit arch "$(uname -m 2>/dev/null)"
    os=$(na_os_name)
    [ -n "$os" ] && na_emit os "$os"
    board=$(na_board_model | tr -d '\000')
    [ -n "$board" ] && na_emit board "$board"
    [ -r "$NODE_PREFIX/proc/uptime" ] && na_emit uptime_s "$(cut -d' ' -f1 "$NODE_PREFIX/proc/uptime" 2>/dev/null)"
    [ -r "$NODE_PREFIX/proc/meminfo" ] && na_emit mem_kb "$(awk '/^MemTotal:/ {print $2; exit}' "$NODE_PREFIX/proc/meminfo" 2>/dev/null)"
    [ -r "$NODE_PREFIX/proc/loadavg" ] && na_emit load "$(cut -d' ' -f1-3 "$NODE_PREFIX/proc/loadavg" 2>/dev/null)"
    if df -Pk "$NODE_PREFIX/" >/dev/null 2>&1; then
        na_emit disk_free_kb "$(df -Pk "$NODE_PREFIX/" 2>/dev/null | awk 'NR==2 {print $4; exit}')"
    fi
    if na_have getprop; then
        na_emit android "$(getprop ro.build.version.release 2>/dev/null | tr -d '\r' | head -n 1)"
    fi
    if na_have nproc; then
        na_emit cpu "$(nproc 2>/dev/null)"
    else
        na_emit cpu "$(awk '/^processor:/ {n++} END {print n+0}' "$NODE_PREFIX/proc/cpuinfo" 2>/dev/null)"
    fi
    return 0
}

# One cap, one row, plus where it came from.  Two functions so the caller never
# has to remember the row order.
na_cap_from_path() {
    na_emit cap "$1"
    na_emit "via-$1" "$2"
}

na_cap_from_cmd() {
    na_emit cap "$1"
    na_emit "via-$1" "cmd:$2"
}

na_cmd_caps() {
    na_emit shell "$(uname -s 2>/dev/null | tr 'A-Z' 'a-z')"

    if [ "$(id -u 2>/dev/null)" = "0" ]; then
        na_emit cap root
        na_emit via-root "uid:0"
    fi

    # Modem paths.  A tty that a modem answers on is the dongle; the AT tooling
    # only matters when there is no device node for it to talk to.
    if path=$(na_first_path '/dev/ttyUSB*' '/dev/ttyACM*' '/dev/ttyHS*' '/dev/smd*' '/dev/wwan*'); then
        na_cap_from_path at "$path"
    elif tool=$(na_first_cmd atinout socat); then
        na_cap_from_cmd at "$tool"
    fi

    if path=$(na_first_path '/dev/cdc-wdm*'); then
        na_cap_from_path qmi "$path"
    elif tool=$(na_first_cmd uqmi qmicli); then
        na_cap_from_cmd qmi "$tool"
    fi

    tool=$(na_first_cmd mbimcli mbim-network) && na_cap_from_cmd mbim "$tool"
    tool=$(na_first_cmd mmcli) && na_cap_from_cmd modem "$tool"
    path=$(na_first_path '/dev/diag' '/dev/Diag') && na_cap_from_path diag "$path"

    if path=$(na_first_path '/dev/ttyGPS*' '/dev/ttyAMA0'); then
        na_cap_from_path gps "$path"
    elif tool=$(na_first_cmd gpspipe gpsd); then
        na_cap_from_cmd gps "$tool"
    fi

    tool=$(na_first_cmd pcsc_scan opensc-tool pcscd) && na_cap_from_cmd pcsc "$tool"
    tool=$(na_first_cmd simtrace2-list simtrace) && na_cap_from_cmd simtrace "$tool"

    # SDR: receive and transmit are separate claims because the hardware is.
    # iio_readdev/iio_info are libiio: a Pluto responds to those and to nothing
    # else, so leaving them out would call a node with a Pluto "not an SDR".
    if tool=$(na_first_cmd rtl_sdr rx_sdr airspy_rx hackrf_transfer SoapySDRUtil uhd_find_devices iio_info); then
        na_cap_from_cmd sdr-rx "$tool"
    fi
    if tool=$(na_first_cmd hackrf_transfer SoapySDRUtil uhd_find_devices LimeUtil iio_info); then
        na_cap_from_cmd sdr-tx "$tool"
        na_emit note "sdr-tx means a transmitter's tooling is installed, not that an antenna will radiate"
    fi

    tool=$(na_first_cmd tcpdump) && na_cap_from_cmd tcpdump "$tool"
    tool=$(na_first_cmd tshark) && na_cap_from_cmd tshark "$tool"
    tool=$(na_first_cmd grgsm_livemon grgsm_scanner srsran) && na_cap_from_cmd gsmtap "$tool"
    tool=$(na_first_cmd open5gs-mmed srsepc magma) && na_cap_from_cmd core "$tool"
    tool=$(na_first_cmd srsue ofono) && na_cap_from_cmd ue "$tool"
    tool=$(na_first_cmd iw) && na_cap_from_cmd wifi "$tool"

    if na_first_path '/sys/class/power_supply/BAT*' >/dev/null; then
        na_emit cap battery
        na_emit via-battery "sysfs:BAT"
    else
        na_emit cap always-on
        na_emit via-always-on "no-battery"
    fi

    na_emit class "$(na_class)"
    return 0
}

# The class follows from what the node can do, and from what board it is on.
# Order matters: the first rule that fits wins, because a Raspberry Pi with an
# SDR on it is an SDR node that happens to be a Pi -- the radio is the point.
na_class() {
    if na_have getprop || [ -e "$NODE_PREFIX/system/build.prop" ]; then
        if [ "$(id -u 2>/dev/null)" = "0" ]; then printf 'phone-rooted'; else printf 'phone'; fi
        return 0
    fi
    if [ -e "$NODE_PREFIX/etc/openwrt_release" ] || [ -e "$NODE_PREFIX/etc/routeros" ]; then
        printf 'router'
        return 0
    fi
    board=$(na_board_model | tr -d '\000')
    case "$board" in
        *Raspberry*|*Rock*|*Orange*|*Beagle*|*Banana*|*NanoPi*) printf 'sbc'; return 0 ;;
    esac
    if na_first_cmd rtl_sdr rx_sdr airspy_rx hackrf_transfer SoapySDRUtil uhd_find_devices iio_info >/dev/null; then
        printf 'sdr'
        return 0
    fi
    if na_first_cmd open5gs-mmed srsepc magma >/dev/null; then
        printf 'core'
        return 0
    fi
    if na_first_cmd pcsc_scan opensc-tool pcscd simtrace2-list simtrace >/dev/null; then
        printf 'sim-kit'
        return 0
    fi
    if na_first_path '/dev/ttyUSB*' '/dev/ttyACM*' '/dev/ttyHS*' '/dev/wwan*' '/dev/cdc-wdm*' >/dev/null \
        || na_first_cmd uqmi qmicli mbimcli mmcli >/dev/null; then
        # A modem with Wi-Fi beside it is a router; a modem on its own is a
        # dongle, whether it is a stick or an IoT module on a breakout board.
        if na_first_cmd iw >/dev/null; then printf 'router'; else printf 'dongle'; fi
        return 0
    fi
    if [ -e "$NODE_PREFIX/etc/imsisting" ]; then
        printf 'workstation'
        return 0
    fi
    printf 'relay'
}

# ── Stream ──────────────────────────────────────────────────────────────
#
# A node keeps its own spool and the client drains it from a byte offset.  That
# is the whole difference from piping into `nohup ssh ... >> client.tsv`: when
# the link drops, a client-side spool has a hole in it, and a node-side spool
# has the events waiting.  The cursor lives with the client (`--since`), so a
# reconnect costs the round trip, not the traffic.
#
# What the node collects with is named, because three different things are
# behind one stream verb and they are not equally good evidence:
#
#   tshark    GSMTAP frames dissected: type and length, timed by the capture
#   tcpdump   the same packets undissected: source and length, no GSMTAP type
#   heartbeat nothing to hear with, so a beat row and no pretending
#
# The spool is a table with a header, not key/value rows: a stream is many
# small records of the same shape, and a header is what lets a client that
# reconnects read the columns it read before.

na_stream_spool() {
    if [ -n "${NODE_SPOOL:-}" ]; then
        printf '%s' "$NODE_SPOOL"
        return 0
    fi
    printf '%s/imsisting.node/stream.tsv' "${TMPDIR:-/tmp}"
}

na_stream_header() { printf 'kind\tepoch\tsrc\ttype\tlen\tdetail\n'; }

# What this node can collect with.  Named so the client can tell a dissected
# GSMTAP capture from a heartbeat that only says the box is alive.
na_stream_source() {
    if na_first_cmd tshark >/dev/null; then printf 'tshark'; return 0; fi
    if na_first_cmd tcpdump >/dev/null; then printf 'tcpdump'; return 0; fi
    printf 'heartbeat'
}

# One collection window into the spool.  Bounded on purpose: an agent that
# never returns cannot be piped over ssh without holding a session open, and a
# node in a field kit should survive its client disappearing.
na_stream_collect() {
    window=$1
    spool=$2
    source=$(na_stream_source)
    iface=${NODE_STREAM_IFACE:-any}
    case "$source" in
    tshark)
        na_first_cmd timeout >/dev/null || return 0
        timeout "$window" tshark -i "$iface" -f 'udp port 4729' -l -T fields \
            -e frame.time_epoch -e gsmtap.type -e udp.length 2>/dev/null |
        awk -F'\t' -v iface="$iface" 'NF >= 3 && $1 != "" {
            printf "gsmtap\t%s\t-\t%s\t%s\tvia=tshark iface=%s\n", $1, ($2 == "" ? "-" : $2), $3, iface
        }' >> "$spool"
        ;;
    tcpdump)
        na_first_cmd timeout >/dev/null || return 0
        timeout "$window" tcpdump -i "$iface" -n -l 'udp port 4729' 2>/dev/null |
        while IFS= read -r line; do
            case "$line" in *'length '*) ;; *) continue ;; esac
            len=$(printf '%s' "$line" | sed -n 's/.*length \([0-9][0-9]*\).*/\1/p')
            [ -n "$len" ] || continue
            src=$(printf '%s' "$line" | awk '{for (i = 1; i < NF; i++) if ($i == "IP") {print $(i + 1); exit}}' |
                  sed 's/\.[0-9][0-9]*$//')
            printf 'gsmtap\t%s\t%s\t-\t%s\tvia=tcpdump iface=%s epoch=collection\n' \
                "$(date +%s 2>/dev/null || echo 0)" "${src:--}" "$len" "$iface" >> "$spool"
        done
        ;;
    *)
        beat_now=$(date +%s 2>/dev/null || echo 0)
        beat_last=$(awk -F'\t' '$1 == "beat" {t = $2} END {printf "%d", t + 0}' "$spool" 2>/dev/null)
        if [ "$((beat_now - ${beat_last:-0}))" -ge "${NODE_STREAM_INTERVAL:-5}" ]; then
            printf 'beat\t%s\t%s\t-\t-\tuptime=%s load=%s source=heartbeat\n' \
                "$beat_now" "$(hostname 2>/dev/null || echo node)" \
                "$(na_read /proc/uptime | cut -d' ' -f1 || echo '?')" \
                "$(na_read /proc/loadavg | cut -d' ' -f1 || echo '?')" >> "$spool"
        fi
        ;;
    esac
    return 0
}

na_cmd_stream() {
    spool=$(na_stream_spool)
    if ! mkdir -p "$(dirname "$spool")" 2>/dev/null || ! : >> "$spool" 2>/dev/null; then
        na_emit ERROR "the node has no writable spool"
        na_emit WHY "NODE_SPOOL=$spool is not writable; a stream with nowhere to spool loses every event that happens while the link is down"
        return 2
    fi
    [ -s "$spool" ] || na_stream_header > "$spool"
    since=${NODE_SINCE:-0}
    case "$since" in '' | *[!0-9]*) since=0 ;; esac
    na_stream_collect "${NODE_STREAM_WINDOW:-2}" "$spool"
    size=$(wc -c < "$spool" | tr -d ' ')
    na_emit spool "$spool"
    na_emit source "$(na_stream_source)"
    na_emit size "$size"
    # `tail -c +N` is one-based, so offset 0 means "from the first byte", which
    # is the header: a client that starts from nothing must be able to learn the
    # column order from the stream itself.
    if [ "$since" -lt "$size" ]; then
        tail -c "+$((since + 1))" "$spool"
    fi
    return 0
}

# ── Exec ────────────────────────────────────────────────────────────────
#
# The dispatch transport: run what the client asked for, and hand its status
# back unchanged.  127 is left alone on purpose -- "the toolkit is not on this
# node" is a fact the client turns into a handoff, and swallowing it here would
# turn a missing install into a silent success.

na_cmd_exec() {
    if [ "$#" -eq 0 ]; then
        na_emit ERROR "no command to run"
        na_emit WHY "usage: --exec COMMAND [ARG ...]"
        return 2
    fi
    "$@"
}

# ── Selftest ────────────────────────────────────────────────────────────
#
# Each case builds a fake root and a fake PATH, then asserts the rows.  A
# capability probe that only runs when a modem is plugged in is a probe nobody
# tested, so every branch below is reachable on any host.

na_selftest() {
    pass=0
    fail=0
    base=$(mktemp -d) || return 1
    saved_prefix="$NODE_PREFIX"
    saved_path="$PATH"

    na_check() {
        if [ "$2" = "$3" ]; then
            printf 'PASS\t%s\n' "$1"
            pass=$((pass + 1))
        else
            printf 'FAIL\t%s\tgot=%s want=%s\n' "$1" "$2" "$3"
            fail=$((fail + 1))
        fi
    }

    # A stub PATH that answers `command -v` for exactly the names asked for.
    #
    # It has to be a complete PATH to be deterministic -- a relay case that
    # passes because this laptop happens to have tcpdump is not a test.  So the
    # core utilities are symlinked back in (tr, head, sed ... are plumbing, not
    # capabilities) and only the names passed here are fabricated.  `rm -f`
    # before writing matters: writing through a symlink would clobber /usr/bin/id.
    na_stub_path() {
        dir="$base/bin-$1"
        shift
        mkdir -p "$dir"
        for keep in sh tr head sed awk grep cut uname hostname id df cat ls printf rm chmod mktemp nproc; do
            real=$(command -v "$keep" 2>/dev/null) || continue
            ln -sf "$real" "$dir/$keep"
        done
        for name in "$@"; do
            rm -f "$dir/$name"
            printf '#!/bin/sh\nexit 0\n' > "$dir/$name"
            chmod +x "$dir/$name"
        done
        printf '%s' "$dir"
    }

    na_field() {   # first value for a key in captured output
        printf '%s\n' "$2" | awk -F'\t' -v k="$1" '$1 == k {print $2; exit}'
    }

    # 1. An SDR box: the radio is the point, even before the class rules run.
    p=$(na_stub_path sdr rtl_sdr hackrf_transfer)
    mkdir -p "$base/sdr"
    out=$(PATH="$p" NODE_PREFIX="$base/sdr" na_cmd_caps)
    na_check "class-sdr" "$(na_field class "$out")" "sdr"
    na_check "cap-sdr-rx" "$(na_field via-sdr-rx "$out")" "cmd:rtl_sdr"
    na_check "cap-sdr-tx" "$(printf '%s\n' "$out" | grep -c '^cap	sdr-tx$')" "1"
    na_check "note-sdr-tx" "$(printf '%s\n' "$out" | grep -c 'transmitter.s tooling is installed')" "1"

    # 2. A router: OpenWrt, a modem on ttyUSB, Wi-Fi beside it.
    p=$(na_stub_path router uqmi iw)
    mkdir -p "$base/router/etc" "$base/router/dev"
    : > "$base/router/etc/openwrt_release"
    : > "$base/router/dev/ttyUSB0"
    out=$(PATH="$p" NODE_PREFIX="$base/router" na_cmd_caps)
    na_check "class-router" "$(na_field class "$out")" "router"
    na_check "cap-at-usb" "$(na_field via-at "$out")" "$base/router/dev/ttyUSB0"
    na_check "cap-qmi" "$(na_field via-qmi "$out")" "cmd:uqmi"

    # 3. A bare dongle: one tty, no shell tooling, no Wi-Fi.
    p=$(na_stub_path dongle)
    mkdir -p "$base/dongle/dev"
    : > "$base/dongle/dev/ttyUSB2"
    out=$(PATH="$p" NODE_PREFIX="$base/dongle" na_cmd_caps)
    na_check "class-dongle" "$(na_field class "$out")" "dongle"
    na_check "cap-at-dongle" "$(na_field via-at "$out")" "$base/dongle/dev/ttyUSB2"

    # 4. A relay: nothing to hear with, so it is not called a sensor.
    p=$(na_stub_path relay)
    mkdir -p "$base/relay"
    out=$(PATH="$p" NODE_PREFIX="$base/relay" na_cmd_caps)
    na_check "class-relay" "$(na_field class "$out")" "relay"
    na_check "cap-alone" "$(printf '%s\n' "$out" | grep -c '^cap	')" "1"
    na_check "cap-shell-only" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="cap"{print $2}')" "always-on"

    # 5. A diag interface is its own cap: the modem's internal log.
    p=$(na_stub_path diag)
    mkdir -p "$base/diag/dev"
    : > "$base/diag/dev/diag"
    out=$(PATH="$p" NODE_PREFIX="$base/diag" na_cmd_caps)
    na_check "cap-diag" "$(na_field via-diag "$out")" "$base/diag/dev/diag"

    # 6. Root is a capability like any other.
    p=$(na_stub_path root id)
    mkdir -p "$base/root"
    printf '#!/bin/sh\n[ "$1" = "-u" ] && { echo 0; exit 0; }\nexit 1\n' > "$p/id"
    chmod +x "$p/id"
    out=$(PATH="$p" NODE_PREFIX="$base/root" na_cmd_caps)
    na_check "cap-root" "$(printf '%s\n' "$out" | grep -c '^cap	root$')" "1"

    # 7. Battery decides always-on, and a battery box is not always-on.
    p=$(na_stub_path batt)
    mkdir -p "$base/batt/sys/class/power_supply/BAT0"
    out=$(PATH="$p" NODE_PREFIX="$base/batt" na_cmd_caps)
    na_check "cap-battery" "$(printf '%s\n' "$out" | grep -c '^cap	battery$')" "1"
    na_check "cap-always-on-absent" "$(printf '%s\n' "$out" | grep -c '^cap	always-on$')" "0"

    # 8. Board model names an SBC; the board row is what a human recognises.
    p=$(na_stub_path sbc)
    mkdir -p "$base/sbc/proc/device-tree"
    printf 'Raspberry Pi 4 Model B Rev 1.4\000' > "$base/sbc/proc/device-tree/model"
    out=$(PATH="$p" NODE_PREFIX="$base/sbc" na_cmd_caps)
    na_check "class-sbc" "$(na_field class "$out")" "sbc"

    # 9. Probe rows are populated, not blank keys.
    out=$(PATH="$saved_path" NODE_PREFIX="$base/sbc" na_cmd_probe)
    na_check "probe-board" "$(na_field board "$out")" "Raspberry Pi 4 Model B Rev 1.4"
    na_check "probe-host-nonempty" "$([ -n "$(na_field host "$out")" ] && echo yes || echo no)" "yes"
    na_check "probe-kernel-nonempty" "$([ -n "$(na_field kernel "$out")" ] && echo yes || echo no)" "yes"

    # 10. A modem tool alone is a dongle, and the tool is named as the reason.
    p=$(na_stub_path mbim mbimcli)
    mkdir -p "$base/mbim"
    out=$(PATH="$p" NODE_PREFIX="$base/mbim" na_cmd_caps)
    na_check "class-dongle-by-tool" "$(na_field class "$out")" "dongle"
    na_check "cap-mbim" "$(na_field via-mbim "$out")" "cmd:mbimcli"

    NODE_PREFIX="$saved_prefix"
    rm -rf "$base"
    printf 'ASSERTIONS\t%s\n' "$((pass + fail))"
    if [ "$fail" -eq 0 ]; then printf 'RESULT\tPASS\n'; else printf 'RESULT\tFAIL(%s)\n' "$fail"; fi
    [ "$fail" -eq 0 ]
}

# ── Stream selftest ─────────────────────────────────────────────────────
#
# The spool is a file and a cursor, so it can be proved without a radio: a
# seeded spool drained twice must emit its rows once and then nothing, which is
# exactly what a reconnecting client depends on.

na_selftest_stream() {
    pass=0
    fail=0
    base=$(mktemp -d) || return 1
    saved_spool="${NODE_SPOOL:-}"
    saved_window="${NODE_STREAM_WINDOW:-}"
    saved_since="${NODE_SINCE:-}"
    unset NODE_SINCE

    na_scheck() {
        if [ "$2" = "$3" ]; then
            printf 'PASS\t%s\n' "$1"
            pass=$((pass + 1))
        else
            printf 'FAIL\t%s\tgot=%s want=%s\n' "$1" "$2" "$3"
            fail=$((fail + 1))
        fi
    }

    # A PATH with the plumbing and no capture tool, so the heartbeat branch is
    # the one under test on any host.
    empty=$(mktemp -d)
    for keep in sh tr head sed awk grep cut uname hostname id df cat ls printf rm chmod mkdir mktemp nproc wc date dirname tail; do
        real=$(command -v "$keep" 2>/dev/null) || continue
        ln -sf "$real" "$empty/$keep"
    done

    NODE_SPOOL="$base/stream.tsv"
    NODE_STREAM_WINDOW=0
    # 1. Nothing collected and nothing spooled: a header, a source, no rows.
    out=$(PATH="$empty" NODE_SPOOL="$NODE_SPOOL" NODE_STREAM_WINDOW=0 sh "$0" --stream)
    na_scheck "stream-source-heartbeat" "$(na_field source "$out")" "heartbeat"
    na_scheck "stream-header-first" "$(head -n 1 "$NODE_SPOOL")" "kind	epoch	src	type	len	detail"
    na_scheck "stream-no-rows-yet" "$(printf '%s\n' "$out" | grep -c '^gsmtap	')" "0"
    na_scheck "stream-size-is-header" "$(na_field size "$out")" "$(wc -c < "$NODE_SPOOL" | tr -d ' ')"

    # 2. A seeded spool is drained from the cursor, header included.
    printf 'gsmtap\t1700000000.5\t-\t1\t84\tvia=tshark iface=any\n' >> "$NODE_SPOOL"
    out=$(PATH="$empty" NODE_SPOOL="$NODE_SPOOL" NODE_STREAM_WINDOW=0 sh "$0" --stream)
    na_scheck "stream-row-drained" "$(printf '%s\n' "$out" | grep -c '^gsmtap	')" "1"
    na_scheck "stream-header-and-row" "$(printf '%s\n' "$out" | grep -c '^kind	')" "1"

    # 3. From the byte offset the client already has, the same spool is silent.
    size=$(na_field size "$out")
    out=$(PATH="$empty" NODE_SPOOL="$NODE_SPOOL" NODE_STREAM_WINDOW=0 NODE_SINCE="$size" sh "$0" --stream)
    na_scheck "stream-resume-quiet" "$(printf '%s\n' "$out" | grep -c '^gsmtap	')" "0"
    na_scheck "stream-resume-size" "$(na_field size "$out")" "$size"
    na_scheck "stream-meta-still-there" "$(na_field source "$out")" "heartbeat"

    # 4. A spool nobody can write is refused, and says what to set.  /proc takes
    #    no new directories on any Linux, so this is unwritable even as root.
    refused=$(PATH="$empty" NODE_SPOOL=/proc/imsisting-selftest/stream.tsv NODE_STREAM_WINDOW=0 sh "$0" --stream 2>/dev/null)
    rc=$?
    na_scheck "stream-unwritable-rc" "$rc" "2"
    na_scheck "stream-unwritable-why" "$(printf '%s\n' "$refused" | grep -c 'Writable\|is not writable')" "1"

    # 5. A tcpdump-only node reports the undissected source, so the client can
    #    tell it from a real GSMTAP dissection.
    stub=$(mktemp -d)
    for keep in sh tr head sed awk grep cut uname hostname id df cat ls printf rm chmod mkdir mktemp nproc timeout wc date dirname tail; do
        real=$(command -v "$keep" 2>/dev/null) || continue
        ln -sf "$real" "$stub/$keep"
    done
    printf '#!/bin/sh\nexit 0\n' > "$stub/tcpdump"
    chmod +x "$stub/tcpdump"
    out=$(PATH="$stub" NODE_SPOOL="$base/tcp.tsv" NODE_STREAM_WINDOW=0 sh "$0" --stream)
    na_scheck "stream-source-tcpdump" "$(na_field source "$out")" "tcpdump"

    # 6. --exec hands back the command's own status, and 127 is not swallowed.
    out=$(sh "$0" --exec sh -c 'printf "hello\tworld\n"; exit 0')
    na_scheck "exec-stdout" "$out" "hello	world"
    sh "$0" --exec sh -c 'exit 7'
    na_scheck "exec-rc" "$?" "7"
    sh "$0" --exec definitely-not-a-command-xyz >/dev/null 2>&1
    na_scheck "exec-127" "$?" "127"
    out=$(sh "$0" --exec)
    na_scheck "exec-empty-refused" "$(printf '%s\n' "$out" | grep -c '^ERROR	no command to run')" "1"

    NODE_SPOOL="$saved_spool"
    [ -n "$saved_window" ] && NODE_STREAM_WINDOW="$saved_window"
    [ -n "$saved_since" ] && NODE_SINCE="$saved_since"
    rm -rf "$base" "$stub" "$empty"
    printf 'ASSERTIONS\t%s\n' "$((pass + fail))"
    if [ "$fail" -eq 0 ]; then printf 'RESULT\tPASS\n'; else printf 'RESULT\tFAIL(%s)\n' "$fail"; fi
    [ "$fail" -eq 0 ]
}

# ── Long runs on the node ───────────────────────────────────────────────
#
# A module dispatched to a node may run for longer than a connection lasts, so
# the node owns the run: a pid file, a log, and a tag the client can use to stop
# it.  Nothing here needs a daemon of our own -- the pid file IS the control
# channel, which is the one piece of state a stranded ssh session cannot lose.

na_runs_dir() {
    printf '%s' "${NODE_RUNS:-${TMPDIR:-/tmp}/imsisting.node/runs}"
}

na_runs_ready() {
    dir=$(na_runs_dir)
    mkdir -p "$dir" 2>/dev/null || {
        na_emit ERROR "cannot write the run directory $dir"
        na_emit WHY "a run nobody can find again is worse than a run that was refused"
        return 2
    }
    return 0
}

na_run_alive() {
    pid=$(cat "$1" 2>/dev/null)
    [ -n "$pid" ] || return 1
    if kill -0 "$pid" 2>/dev/null; then return 0; fi
    return 1
}

na_cmd_run() {
    tag=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --tag)
                shift
                tag="${1:-}"
                shift || true ;;
            --)
                shift
                break ;;
            *)
                break ;;
        esac
    done
    if [ -z "$tag" ]; then
        na_emit ERROR "a run needs a tag"
        na_emit WHY "usage: --run --tag TAG -- COMMAND [ARG...]"
        return 2
    fi
    if [ "$#" -eq 0 ]; then
        na_emit ERROR "no command to run"
        na_emit WHY "usage: --run --tag TAG -- COMMAND [ARG...]"
        return 2
    fi
    na_runs_ready || return $?
    dir=$(na_runs_dir)
    # The child keeps its own log and its own pid: the client may never come
    # back, and the node still has to be able to say what happened.
    ( "$@" >"$dir/$tag.log" 2>&1 & echo $! >"$dir/$tag.pid" )
    pid=$(cat "$dir/$tag.pid" 2>/dev/null)
    na_emit run "$tag"
    na_emit pid "$pid"
    na_emit log "$dir/$tag.log"
    printf 'started\n'
    return 0
}

na_cmd_run_stop() {
    tag=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --tag) shift; tag="${1:-}"; shift || true ;;
            *) break ;;
        esac
    done
    [ -n "$tag" ] || { na_emit ERROR "which run?"; na_emit WHY "usage: --run-stop --tag TAG"; return 2; }
    dir=$(na_runs_dir)
    pidfile="$dir/$tag.pid"
    [ -f "$pidfile" ] || {
        na_emit ERROR "no run tagged $tag on this node"
        na_emit WHY "the pid file is $pidfile; a run that never started cannot be stopped"
        return 1
    }
    if na_run_alive "$pidfile"; then
        pid=$(cat "$pidfile" 2>/dev/null)
        kill "$pid" 2>/dev/null
        # A module that ignores TERM keeps running; say so instead of claiming it
        # stopped.
        n=0
        while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 20 ]; do
            sleep 0.1
            n=$((n + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
            na_emit signal TERM+KILL
        else
            na_emit signal TERM
        fi
        na_emit stopped "$tag"
        rm -f "$pidfile"
    else
        na_emit stopped "$tag"
        na_emit note "it had already exited"
        rm -f "$pidfile"
    fi
    return 0
}

na_cmd_run_status() {
    dir=$(na_runs_dir)
    na_emit runs_dir "$dir"
    [ -d "$dir" ] || return 0
    for pidfile in "$dir"/*.pid; do
        [ -f "$pidfile" ] || continue
        tag=$(basename "$pidfile" .pid)
        pid=$(cat "$pidfile" 2>/dev/null)
        if na_run_alive "$pidfile"; then
            state=running
        else
            state=exited
        fi
        log="$dir/$tag.log"
        bytes=0
        [ -f "$log" ] && bytes=$(wc -c <"$log" 2>/dev/null | tr -d ' ')
        na_emit run "$tag"
        na_emit pid "$pid"
        na_emit state "$state"
        na_emit log_bytes "$bytes"
    done
    return 0
}

# ── Health ──────────────────────────────────────────────────────────────
# Five numbers a person actually uses to decide whether to send work to a node.
# Kept apart from --probe because --probe describes what the box IS, and this
# describes what it is doing right now.
na_cmd_health() {
    [ -r "$NODE_PREFIX/proc/loadavg" ] && na_emit load1 "$(cut -d' ' -f1 "$NODE_PREFIX/proc/loadavg" 2>/dev/null)"
    [ -r "$NODE_PREFIX/proc/uptime" ] && na_emit uptime_s "$(cut -d' ' -f1 "$NODE_PREFIX/proc/uptime" 2>/dev/null)"
    if [ -r "$NODE_PREFIX/proc/meminfo" ]; then
        total=$(awk '/^MemTotal:/ {print $2; exit}' "$NODE_PREFIX/proc/meminfo" 2>/dev/null)
        avail=$(awk '/^MemAvailable:/ {print $2; exit}' "$NODE_PREFIX/proc/meminfo" 2>/dev/null)
        [ -n "$total" ] && na_emit mem_total_kb "$total"
        if [ -n "$total" ] && [ -n "$avail" ]; then
            na_emit mem_used_pct "$(awk -v t="$total" -v a="$avail" 'BEGIN {printf "%.0f", (t-a)*100/t}')"
        fi
    fi
    if df -Pk "$NODE_PREFIX/" >/dev/null 2>&1; then
        df -Pk "$NODE_PREFIX/" 2>/dev/null | awk 'NR==2 {printf "disk_free_kb\t%s\ndisk_used_pct\t%s\n", $4, $5}' | tr -d '%'
    fi
    na_emit run_count "$(na_cmd_run_status 2>/dev/null | grep -c '^state\trunning$')"
    return 0
}

# ── Run control selftest ────────────────────────────────────────────────
na_selftest_runs() {
    pass=0
    fail=0
    base=$(mktemp -d) || return 1
    NODE_RUNS="$base/runs"
    export NODE_RUNS

    srcheck() {
        if [ "$2" = "$3" ]; then
            printf 'PASS\t%s\n' "$1"
            pass=$((pass + 1))
        else
            printf 'FAIL\t%s\tgot=%s want=%s\n' "$1" "$2" "$3"
            fail=$((fail + 1))
        fi
    }

    # 1. A tagged background run leaves a pid, a log and a word the client can
    #    act on.
    out=$("$0" --run --tag work -- sh -c 'sleep 5' 2>&1)
    srcheck "run-emits-tag" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="run"{print $2; exit}')" "work"
    srcheck "run-started" "$(printf '%s\n' "$out" | grep -c '^started$')" "1"
    pid=$(printf '%s\n' "$out" | awk -F'\t' '$1=="pid"{print $2; exit}')
    srcheck "run-pidfile" "$([ -s "$NODE_RUNS/work.pid" ] && echo yes || echo no)" "yes"

    # 2. Status sees it alive, and says so with the word the client greps for.
    out=$("$0" --run-status 2>&1)
    srcheck "status-running" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="state"{print $2; exit}')" "running"
    srcheck "status-logfile" "$(printf '%s\n' "$out" | grep -c "^log_bytes[[:space:]]")" "1"

    # 3. Stop is a real stop: TERM, the pid goes, and the pid file is gone so a
    #    second stop cannot pretend to have stopped something.
    out=$("$0" --run-stop --tag work 2>&1)
    srcheck "stop-said" "$(printf '%s\n' "$out" | grep -c '^stopped')" "1"
    srcheck "stop-signal" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="signal"{print $2; exit}')" "TERM"
    sleep 0.3
    srcheck "stop-pidfile-gone" "$([ -f "$NODE_RUNS/work.pid" ] && echo yes || echo no)" "no"
    if [ -n "$pid" ]; then
        srcheck "stop-process-gone" "$(kill -0 "$pid" 2>/dev/null && echo alive || echo gone)" "gone"
    fi

    # 4. A run that has finished reads as exited, not as running.
    "$0" --run --tag quick -- true >/dev/null 2>&1
    sleep 0.3
    out=$("$0" --run-status 2>&1)
    srcheck "status-exited" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="state"{print $2; exit}')" "exited"

    # 5. Stopping what never started is an error naming the file it looked for.
    out=$("$0" --run-stop --tag ghost 2>&1); rc=$?
    srcheck "stop-unknown-rc" "$rc" "1"
    srcheck "stop-unknown-names-path" "$(printf '%s\n' "$out" | grep -c 'ghost.pid')" "1"

    # 6. Refusals: no tag, no command, unwritable run directory.
    out=$("$0" --run -- sh -c 'true' 2>&1); srcheck "run-needs-tag-rc" "$?" "2"
    out=$("$0" --run --tag x -- 2>&1); srcheck "run-needs-command-rc" "$?" "2"
    out=$(NODE_RUNS=/proc/imsisting-node-selftest/runs "$0" --run --tag x -- true 2>&1)
    srcheck "run-refuses-unwritable" "$(printf '%s\n' "$out" | grep -c '^ERROR')" "1"

    # 7. Health answers with the four numbers a person routes work by.
    out=$("$0" --health 2>&1)
    srcheck "health-load" "$(printf '%s\n' "$out" | grep -c '^load1[[:space:]]')" "1"
    srcheck "health-disk" "$(printf '%s\n' "$out" | grep -c '^disk_free_kb[[:space:]]')" "1"
    srcheck "health-runs" "$(printf '%s\n' "$out" | grep -c '^run_count[[:space:]]')" "1"

    rm -rf -- "$base"
    printf 'ASSERTIONS\t%s\n' "$((pass + fail))"
    if [ "$fail" -eq 0 ]; then
        printf 'RESULT\tPASS\n'
        unset NODE_RUNS
        return 0
    fi
    printf 'RESULT\tFAIL\n'
    unset NODE_RUNS
    return 1
}

# ── Dispatch ────────────────────────────────────────────────────────────

na_main() {
    [ "$#" -eq 0 ] && set -- --help
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --probe)    shift; na_cmd_probe ;;
            --caps)     shift; na_cmd_caps ;;
            --since)
                shift
                case "${1:-}" in
                    '' | *[!0-9]*)
                        na_emit ERROR "--since wants a byte offset"
                        na_emit WHY "usage: --since N --stream, where N is the size the client already drained"
                        return 2 ;;
                esac
                NODE_SINCE=$1
                shift ;;
            --stream)   shift; na_cmd_stream || return $? ;;
            --exec)     shift; na_cmd_exec "$@"; return $? ;;
            --run)      shift; na_cmd_run "$@"; return $? ;;
            --run-stop) shift; na_cmd_run_stop "$@"; return $? ;;
            --run-status) shift; na_cmd_run_status "$@"; return $? ;;
            --health)   shift; na_cmd_health ;;
            --selftest-runs) shift; na_selftest_runs; return $? ;;
            --selftest)
                shift
                na_selftest || return 1
                na_selftest_stream || return 1 ;;
            --help | *)
                na_usage
                return 2 ;;
        esac
    done
    return 0
}

na_usage() {
            cat >&2 <<EOF
node_agent — what a remote node can do, measured (remote node)

Usage: $0 COMMAND
  --probe            host facts: host, os, kernel, arch, board, uptime, cpu, mem, disk
  --caps             one row per capability, the reason for it, and the node class
  --since N --stream drain the node's event spool from byte offset N
  --exec CMD [ARG...] run a command on the node and hand back its status
  --run --tag T -- CMD [ARG...]   start it in the background under a tag
  --run-stop --tag T              stop the run by tag
  --run-status                    every tagged run, its pid and whether it lives
  --health                        load, memory, disk and how many runs are going
  --selftest         every class rule, the spool cursor and exec, faked

Run it on the node, or pipe it there with no install:
  ssh host 'sh -s -- --caps' < tools/node_agent.sh
  ssh host 'sh -s -- --since 0 --stream' < tools/node_agent.sh

Verbs may be combined: --probe --caps is one round trip, which is why the
casebook probe asks for both at once.  --since comes before --stream.

The stream spools on the node, not on the client: a dropped link then costs a
round trip instead of the events that happened while it was down.

Env: NODE_PREFIX (test hook: read /dev, /sys, /proc and /etc under this root)
     NODE_SPOOL (where the event spool lives; default \$TMPDIR/imsisting.node/stream.tsv)
     NODE_STREAM_WINDOW (seconds collected per call; default 2)
     NODE_STREAM_INTERVAL (seconds between heartbeat rows; default 5)
     NODE_STREAM_IFACE (capture interface; default any)
EOF
}

na_main "$@"
