#!/usr/bin/env bash
# dependency manager — the cellular toolchain: SDR stacks, gnuradio, gr-gsm,
# srsRAN, Open5GS, protocol analysers, SIM tooling, cracking and analysis.
#
# The table below is the single source of truth for "what can this toolkit
# do on this box". Detection is honest: a tool that is present but whose
# stack is incomplete (gnuradio without the gr-gsm out-of-tree blocks,
# srsRAN without an application binary, a python module that will not
# import) is reported as `broken`, never as `installed`.
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
# Reset HOME so $HOME-relative defaults resolve to the real user.
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

DEPS_DIR="$LOOT_DIR/deps"
# Probe results are memoised to FILES, not just to shell variables: the callers
# read them with $(...) command substitution, which runs in a subshell, and a
# subshell's writes to an associative array are discarded on exit. That made an
# in-memory cache useless and left a full sweep at ~15s, repeated often enough
# to push the selftest past its time budget. $$ is the parent pid even inside a
# subshell, so the directory is stable for the whole run.
DEPS_CACHE_DIR="${TMP_DIR}/deps_cache.$$"
mkdir -p "$DEPS_CACHE_DIR" 2>/dev/null
# Whether a tool is present depends on PATH, and the selftest deliberately
# injects a stub directory to prove that. The key must therefore be derived
# from PATH at CALL time, not at load time -- a load-time key stays pinned to
# the original PATH and still returns a stale "missing".
deps_path_key() { printf '%s' "${PATH:-}" | cksum | cut -d' ' -f1; }
DEPS_TMP="$TMP_DIR/deps"
mkdir -p "$DEPS_DIR" "$DEPS_TMP" 2>/dev/null
DEPS_REPORT="$DEPS_DIR/deps_report.tsv"

# ── sanitisation ────────────────────────────────────────────────────────
# Version strings come out of a tool's own banner. A crafted or merely
# broken binary can print a tab; an unsanitised row would then carry an
# extra field and forge a record in any TSV consumer.
deps_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ═══════════════════════════════════════════════════════════════════
#  distro detection
# ═══════════════════════════════════════════════════════════════════

deps_detect_distro() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        ( . /etc/os-release 2>/dev/null; printf '%s' "${ID:-unknown}" )
    else
        printf 'unknown'
    fi
}

deps_pkg_manager() {
    case "$(deps_detect_distro)" in
        debian|ubuntu|kali|parrot|raspbian|linuxmint|pop) echo "apt" ;;
        fedora|rhel|centos|rocky|alma|ol)                echo "dnf" ;;
        arch|manjaro|endeavouros|garuda|artix)           echo "pacman" ;;
        *)                                               echo "unknown" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  tool registry
#
#  DEPS_TOOLS rows are "tool|group|required|pkg_apt|pkg_dnf|pkg_pacman".
#  required is `yes` for the tools without which the toolkit cannot do the
#  job it advertises at all, `no` for everything that buys extra capability.
#  Package cells that are `-` are not packaged by that family and are
#  installed by pip/pipx/git or built from source instead.
# ═══════════════════════════════════════════════════════════════════

DEPS_TOOLS=(
    # ── core shell tooling ──────────────────────────────────────────
    "bash|core|yes|bash|bash|bash"
    "python3|core|yes|python3|python3|python"
    "awk|core|yes|gawk|gawk|gawk"
    "sed|core|yes|sed|sed|sed"
    "grep|core|yes|grep|grep|grep"
    "sort|core|yes|coreutils|coreutils|coreutils"
    "mktemp|core|yes|coreutils|coreutils|coreutils"
    "timeout|core|yes|coreutils|coreutils|coreutils"
    "tr|core|yes|coreutils|coreutils|coreutils"
    "find|core|yes|findutils|findutils|findutils"
    "column|core|no|util-linux|util-linux|util-linux"
    "pv|core|no|pv|pv|pv"

    # ── SDR hardware support ────────────────────────────────────────
    "hackrf_info|sdr|no|hackrf|hackrf|hackrf"
    "hackrf_transfer|sdr|no|hackrf|hackrf|hackrf"
    "hackrf_sweep|sdr|no|hackrf|hackrf|hackrf"
    "bladeRF-cli|sdr|no|bladerf|bladerf|bladerf"
    "LimeUtil|sdr|no|limesuite|limesuite|limesuite"
    "LimeSuiteGUI|sdr|no|limesuite|limesuite|limesuite"
    "uhd_find_devices|sdr|no|uhd-host|uhd|uhd"
    "uhd_usrp_probe|sdr|no|uhd-host|uhd|uhd"
    "rtl_test|sdr|no|rtl-sdr|rtl-sdr|rtl-sdr"
    "rtl_sdr|sdr|no|rtl-sdr|rtl-sdr|rtl-sdr"
    "rtl_fm|sdr|no|rtl-sdr|rtl-sdr|rtl-sdr"
    "SoapySDRUtil|sdr|no|soapysdr-tools|SoapySDR|soapysdr"
    "gnuradio-config-info|sdr|no|gnuradio|gnuradio|gnuradio"
    "gnuradio-companion|sdr|no|gnuradio|gnuradio|gnuradio"
    "gqrx|sdr|no|gqrx-sdr|gqrx|gqrx"

    # ── GSM / 2G stack ──────────────────────────────────────────────
    "grgsm_livemon|gsm|no|gr-gsm|gr-gsm|gr-gsm"
    "grgsm_scanner|gsm|no|gr-gsm|gr-gsm|gr-gsm"
    "grgsm_decode|gsm|no|gr-gsm|gr-gsm|gr-gsm"
    "kal|gsm|no|kalibrate-rtl|kalibrate-rtl|kalibrate-rtl"
    "osmocon|gsm|no|osmocom-bb|osmocom-bb|osmocom-bb"
    "mobile|gsm|no|osmocom-bb|osmocom-bb|osmocom-bb"

    # ── LTE / 5G RAN ────────────────────────────────────────────────
    "srsenb|lte|no|srsran|srsran|srsran"
    "srsepc|lte|no|srsran|srsran|srsran"
    "srsue|lte|no|srsran|srsran|srsran"
    "gnb|nr|no|srsran|srsran|srsran"
    "nr-uesoftmodem|nr|no|srsran|srsran|srsran"
    "open5gs-mmed|core|no|open5gs|open5gs|open5gs"
    "open5gs-amfd|core|no|open5gs|open5gs|open5gs"
    "open5gs-smfd|core|no|open5gs|open5gs|open5gs"
    "open5gs-upfd|core|no|open5gs|open5gs|open5gs"
    "free5gc|core|no|free5gc|free5gc|free5gc"

    # ── core network / protocol analysis ────────────────────────────
    "tshark|proto|yes|tshark|wireshark-cli|wireshark-cli"
    "dumpcap|proto|no|wireshark-common|wireshark-cli|wireshark-cli"
    "tcpdump|proto|no|tcpdump|tcpdump|tcpdump"
    "socat|proto|no|socat|socat|socat"
    "nc|proto|no|netcat-openbsd|nmap-ncat|gnu-netcat"
    "openssl|proto|no|openssl|openssl|openssl"
    "text2pcap|proto|no|wireshark-common|wireshark-cli|wireshark-cli"

    # ── SIM / smart card ────────────────────────────────────────────
    "pcscd|sim|no|pcscd|pcsc-tools|pcsclite"
    "pcsc_scan|sim|no|pcsc-tools|pcsc-tools|pcsc-tools"
    "opensc-tool|sim|no|opensc|opensc|opensc"
    "pySim-shell.py|sim|no|pysim|pysim|pysim"

    # ── offline cracking / analysis ─────────────────────────────────
    "hashcat|crack|no|hashcat|hashcat|hashcat"
    "john|crack|no|john|john|john"
    "sqlite3|analysis|no|sqlite3|sqlite|sqlite"
    "jq|analysis|no|jq|jq|jq"
    "gpsd|analysis|no|gpsd|gpsd|gpsd"
    "gpspipe|analysis|no|gpsd|gpsd|gpsd"
    "gpsbabel|analysis|no|gpsbabel|gpsbabel|gpsbabel"
)

# Extra clues used by the honesty probe. A tool can be present on PATH and
# still be useless because the library or the out-of-tree module behind it
# is missing. The value is a probe kind handled in deps_probe_extra().
declare -A DEPS_EXTRA=(
    [gnuradio-config-info]=gnuradio_prefix
    [grgsm_livemon]=grgsm_modules
    [grgsm_scanner]=grgsm_modules
    [grgsm_decode]=grgsm_modules
    [srsenb]=srsran_apps
    [srsepc]=srsran_apps
    [gnb]=srsran_apps
    [nr-uesoftmodem]=srsran_apps
    [python3]=py_imports
)

# Python packages the toolkit imports directly. No binary to find on PATH,
# so they are probed by import and reported in their own right.
DEPS_PY_MODULES=(
    "scapy|proto|no"
    "pycrate|proto|no"
    "asn1tools|proto|no"
    "pyscard|sim|no"
)

# What each pip distribution provides, for --install-package and the plan.
declare -A DEPS_PIP_DIST=(
    [scapy]=scapy [pycrate]=pycrate [asn1tools]=asn1tools
    [pyscard]=pyscard [pycryptodome]=pycryptodome
)

# Version floors that change behaviour. `--check-versions` verifies these.
declare -A DEPS_MIN_VERSION=(
    [tshark]="3.6"
    [python3]="3.8"
    [hashcat]="6.0"
    [gnuradio-config-info]="3.8"
)

# ── registry accessors ──────────────────────────────────────────────────

# Print the raw registry row for a tool, or nothing.
deps_row_for() {
    local want="$1" row
    for row in "${DEPS_TOOLS[@]}"; do
        [[ "${row%%|*}" == "$want" ]] && { printf '%s\n' "$row"; return 0; }
    done
    return 1
}

deps_field() {
    # deps_field TOOL FIELD_NUMBER(1..6)
    local row; row=$(deps_row_for "$1") || return 1
    printf '%s\n' "$row" | cut -d'|' -f"$2"
}

deps_pkg_for() {
    # deps_pkg_for TOOL -> package name for this distro family, or "".
    local tool="$1" row f
    if row=$(deps_row_for "$tool"); then
        case "$(deps_pkg_manager)" in
            apt)    f=4 ;;
            dnf)    f=5 ;;
            pacman) f=6 ;;
            *)      printf ''; return 0 ;;
        esac
        local pkg; pkg=$(printf '%s\n' "$row" | cut -d'|' -f"$f")
        [[ "$pkg" == "-" ]] && pkg=""
        printf '%s' "$pkg"
        return 0
    fi
    # Not a binary row: maybe a python module with a pip distribution.
    local m
    for m in "${DEPS_PY_MODULES[@]}"; do
        if [[ "${m%%|*}" == "$tool" ]]; then
            printf '%s' "${DEPS_PIP_DIST[$tool]:-}"
            return 0
        fi
    done
    printf ''
}

deps_required_for() {
    local row
    if row=$(deps_row_for "$1"); then
        printf '%s\n' "$row" | cut -d'|' -f3 | grep -qx yes && echo yes || echo no
        return 0
    fi
    local m
    for m in "${DEPS_PY_MODULES[@]}"; do
        [[ "${m%%|*}" == "$1" ]] && { printf '%s\n' "$m" | cut -d'|' -f3 | grep -qx yes && echo yes || echo no; return 0; }
    done
    echo no
}

deps_group_for() {
    local row
    if row=$(deps_row_for "$1"); then printf '%s\n' "$row" | cut -d'|' -f2; return 0; fi
    local m
    for m in "${DEPS_PY_MODULES[@]}"; do
        [[ "${m%%|*}" == "$1" ]] && { printf '%s\n' "$m" | cut -d'|' -f2; return 0; }
    done
    echo unknown
}

# Every tool the registry knows about, one per line, sorted. Python modules
# are included: they are dependencies in every sense that matters here.
deps_all_tools() {
    local row m
    for row in "${DEPS_TOOLS[@]}"; do printf '%s\n' "${row%%|*}"; done
    for m in "${DEPS_PY_MODULES[@]}"; do printf '%s\n' "${m%%|*}"; done
}
deps_all_tools_sorted() { deps_all_tools | sort -u; }

# ═══════════════════════════════════════════════════════════════════
#  presence + version
# ═══════════════════════════════════════════════════════════════════

deps_check_one() {
    command -v "$1" >/dev/null 2>&1
}

# The argument each tool needs to print its version. Defaulting to
# `--version` is wrong often enough to matter (hostapd wants -v, bladeRF
# wants `bladeRF-cli -v`, uhd wants `--version`): an unlisted tool that
# prints nothing is reported with an empty version, which is honest.
deps_version_flag() {
    case "$1" in
        bash)              echo "-c" ;;
        python3)           echo "--version" ;;
        awk)               echo "--version" ;;
        sed)               echo "--version" ;;
        grep)              echo "--version" ;;
        sort|mktemp|tr|column|timeout|pv) echo "--version" ;;
        tcpdump)           echo "--version" ;;
        socat)             echo "-V" ;;
        nc)                echo "--version" ;;
        *)                 echo "--version" ;;
    esac
}

# Version string of a tool, or "" when it does not report one. A tool that
# prints nothing is NOT a failure — plenty of them do — but the empty
# result must survive to the caller instead of being invented.
# Version probes spawn the tool, and a full status sweep runs one per tool. The
# selftest calls a sweep several times, which without a cache costs 14s a call
# for 65 tools and pushes the module past the runner's timeout. Nothing about a
# tool's version changes mid-run, so the result is memoised for the process.
# Set DEPS_NO_CACHE=1 to force a fresh probe.
deps_tool_version() {
    local tool="$1" out=""
    local cf="${DEPS_CACHE_DIR:-}/ver.$(deps_path_key).$1"
    if [[ -z "${DEPS_NO_CACHE:-}" && -n "${DEPS_CACHE_DIR:-}" && -f "$cf" ]]; then
        cat "$cf"; return 0
    fi
    if ! deps_check_one "$tool"; then
        [[ -n "${DEPS_CACHE_DIR:-}" ]] && : > "$cf" 2>/dev/null
        printf ''; return 0
    fi
    local flag; flag=$(deps_version_flag "$tool")
    if [[ "$tool" == "bash" ]]; then
        out=$(bash --version 2>&1 | head -1)
    elif [[ "${flag}" == "-c" ]]; then
        out=""
    else
        out=$(timeout 5 "$tool" "$flag" 2>&1 | head -1)
        # Some tools exit non-zero on --version but still print it; some
        # print usage instead. Fall back to the usage banner before giving up.
        [[ -z "$out" ]] && out=$(timeout 5 "$tool" -h 2>&1 | head -1)
    fi
    [[ -z "$out" ]] && { [[ -n "${DEPS_CACHE_DIR:-}" ]] && : > "$cf" 2>/dev/null; printf ''; return 0; }
    local v; v=$(printf '%s\n' "$out" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [[ -n "${DEPS_CACHE_DIR:-}" ]] && printf '%s' "${v:-}" > "$cf" 2>/dev/null
    printf '%s' "${v:-}"
}

deps_version_ge() {
    local a="$1" b="$2"
    [[ -z "$a" || -z "$b" ]] && return 0
    printf '%s\n%s\n' "$b" "$a" | sort -V -C
    return $?
}

# ── honesty probes ──────────────────────────────────────────────────────
# Returns 0 when the tool's surrounding stack is intact, non-zero and prints
# a one-line reason when it is not.

deps_grgsm_module_present() {
    # gr-gsm installs its blocks as a gnuradio OOT module. Ask the module
    # registrar directly; no flowgraph is started and no radio is touched.
    local out
    out=$(timeout 15 python3 -c '
import sys
try:
    from gnuradio import gr
except Exception:
    sys.exit(1)
hit = False
for mod in ("grgsm", "gsm"):
    try:
        __import__(mod)
        hit = True
    except Exception:
        pass
try:
    import gnuradio.gr
    for attr in dir(gnuradio.gr):
        pass
except Exception:
    pass
sys.exit(0 if hit else 1)
' 2>/dev/null) && return 0
    # Fall back to a filesystem check for the OOT module metadata.
    local p
    for p in /usr/lib/python3/dist-packages/grgsm /usr/local/lib/python3*/dist-packages/grgsm \
             /usr/lib/python3*/site-packages/grgsm /usr/lib/x86_64-linux-gnu/gnuradio/grgsm; do
        [[ -e "$p" ]] && return 0
    done
    ((${#out[@]})) 2>/dev/null
    return 1
}

deps_extra_state() {
    # Prints one of: ok | broken:<reason> | unknown
    local tool="$1" kind="${DEPS_EXTRA[$1]:-}"
    [[ -z "$kind" ]] && { printf 'ok'; return 0; }
    case "$kind" in
        gnuradio_prefix)
            # gnuradio-config-info existing but refusing to print a prefix
            # means the install is half-removed.
            local pre
            pre=$(timeout 10 gnuradio-config-info --prefix 2>/dev/null | head -1)
            if [[ -z "$pre" ]]; then
                printf 'broken:gnuradio-config-info prints no prefix (incomplete install)'
            elif [[ ! -d "$pre" ]]; then
                printf 'broken:prefix %s does not exist' "$(deps_sanitize "$pre")"
            else
                printf 'ok'
            fi ;;
        grgsm_modules)
            if deps_grgsm_module_present; then printf 'ok'
            else printf 'broken:gnuradio present but no gr-gsm OOT blocks (import grgsm fails)'; fi ;;
        srsran_apps)
            # srsRAN splits into srsRAN_4G (srsenb) and srsRAN_Project (gnb).
            # Having only the 4G tree is not an error for the 4G tools.
            local n=0 t
            for t in srsenb srsepc srsue gnb nr-uesoftmodem; do
                deps_check_one "$t" && n=$((n+1))
            done
            if (( n == 0 )); then printf 'broken:no srsRAN application binaries on PATH'
            else printf 'ok'; fi ;;
        py_imports)
            # python3 itself is fine; the note records whether the protocol
            # libraries this toolkit imports are reachable.
            local miss=() m
            for m in "${DEPS_PY_MODULES[@]}"; do
                deps_py_module_ok "${m%%|*}" || miss+=("${m%%|*}")
            done
            if (( ${#miss[@]} == 0 )); then printf 'ok'
            else printf 'ok:but protocol modules missing: %s' "$(deps_sanitize "${miss[*]}")"; fi ;;
        *) printf 'ok' ;;
    esac
}

deps_py_module_ok() {
    timeout 15 python3 -c "import $1" >/dev/null 2>&1
}

# Present / missing / broken. This is the only place that decides state,
# so --status-tsv and --check-versions can never disagree.
deps_is_py_module() {
    printf '%s\n' "${DEPS_PY_MODULES[@]}" | cut -d'|' -f1 | grep -qx "$1"
}

# State probes include python-import checks, which are not cheap, and the menu
# redraws its header after every action. Memoise per process; DEPS_NO_CACHE=1
# forces a fresh probe.
deps_state_of() {
    local tool="$1" extra st
    local cf="${DEPS_CACHE_DIR:-}/state.$(deps_path_key).$1"
    if [[ -z "${DEPS_NO_CACHE:-}" && -n "${DEPS_CACHE_DIR:-}" && -f "$cf" ]]; then
        cat "$cf"; return 0
    fi

    # A python module has no binary to find: it is probed by import, and a
    # module that will not import is missing, not "present but odd".
    if deps_is_py_module "$tool"; then
        if deps_py_module_ok "$tool"; then st='installed'; else st='missing'; fi
    elif ! deps_check_one "$tool"; then
        st='missing'
    else
        extra=$(deps_extra_state "$tool")
        case "$extra" in
            ok*)     st='installed' ;;
            broken*) st='broken' ;;
            *)       st='installed' ;;
        esac
    fi

    [[ -n "${DEPS_CACHE_DIR:-}" ]] && printf '%s' "$st" > "$cf" 2>/dev/null
    printf '%s' "$st"
}

deps_reason_of() {
    local extra
    extra=$(deps_extra_state "$1")
    case "$extra" in
        broken:*) printf '%s' "$(deps_sanitize "${extra#broken:}")" ;;
        ok:*)     printf '%s' "$(deps_sanitize "${extra#ok:}")" ;;
        *)        printf '' ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  reports
# ═══════════════════════════════════════════════════════════════════

deps_header() {
    printf 'tool\tgroup\trequired\tstate\tversion\tpackage\n'
}

deps_status_tsv() {
    local tool
    for tool in $(deps_all_tools_sorted); do
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(deps_sanitize "$tool")" \
            "$(deps_sanitize "$(deps_group_for "$tool")")" \
            "$(deps_sanitize "$(deps_required_for "$tool")")" \
            "$(deps_sanitize "$(deps_state_of "$tool")")" \
            "$(deps_sanitize "$(deps_tool_version "$tool")")" \
            "$(deps_sanitize "$(deps_pkg_for "$tool")")"
    done
}

# Human-readable report. Present/absent with the version string, plus a
# distinct line for every tool whose stack is broken.
deps_check_versions_tsv() {
    local tool state ver pkg min issues=0
    printf 'check\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'distro\t%s\n' "$(deps_sanitize "$(deps_detect_distro)")"
    printf 'pkg_manager\t%s\n' "$(deps_sanitize "$(deps_pkg_manager)")"
    for tool in $(deps_all_tools_sorted); do
        state=$(deps_state_of "$tool")
        ver=$(deps_tool_version "$tool")
        pkg=$(deps_pkg_for "$tool")
        case "$state" in
            missing)
                printf 'MISSING\t%s\t%s\t%s\n' "$(deps_sanitize "$tool")" "$(deps_group_for "$tool")" "$(deps_sanitize "$pkg")"
                issues=$((issues + 1)) ;;
            broken)
                printf 'BROKEN\t%s\t%s\t%s\n' "$(deps_sanitize "$tool")" "$(deps_group_for "$tool")" "$(deps_reason_of "$tool")"
                issues=$((issues + 1)) ;;
            installed)
                if [[ -n "$ver" ]]; then
                    printf 'OK\t%s\t%s\t%s\n' "$(deps_sanitize "$tool")" "$ver" "$(deps_group_for "$tool")"
                else
                    printf 'PRESENT\t%s\t%s\t%s\n' "$(deps_sanitize "$tool")" "(no version output)" "$(deps_group_for "$tool")"
                fi
                # a note is not an issue unless the state is broken
                local note; note=$(deps_reason_of "$tool")
                [[ -n "$note" ]] && printf 'NOTE\t%s\t%s\n' "$(deps_sanitize "$tool")" "$note"
                ;;
        esac
        # version floor
        min="${DEPS_MIN_VERSION[$tool]:-}"
        if [[ -n "$min" && "$state" == "installed" ]]; then
            if [[ -z "$ver" ]]; then
                printf 'VERSION_UNKNOWN\t%s\t%s\n' "$(deps_sanitize "$tool")" "$min"
            elif deps_version_ge "$ver" "$min"; then
                printf 'FLOOR_OK\t%s\t%s\t%s\n' "$(deps_sanitize "$tool")" "$ver" "$min"
            else
                printf 'TOO_OLD\t%s\t%s\t%s\n' "$(deps_sanitize "$tool")" "$ver" "$min"
                issues=$((issues + 1))
            fi
        fi
    done
    printf 'ISSUES\t%s\n' "$issues"
    return 0
}

deps_missing_packages() {
    # Actionable lines: "pkg|family|tool" so a caller can tell a distro
    # package from a pip distribution from something that needs source.
    local tool state pkg
    for tool in $(deps_all_tools_sorted); do
        state=$(deps_state_of "$tool")
        [[ "$state" == "installed" ]] && continue
        pkg=$(deps_pkg_for "$tool")
        if [[ -n "$pkg" ]]; then
            printf '%s|%s|%s\n' "$pkg" "$(deps_pkg_manager)" "$tool"
        elif deps_is_py_module "$tool"; then
            printf '%s|pip|%s\n' "${DEPS_PIP_DIST[$tool]:-$tool}" "$tool"
        else
            printf '-|source|%s\n' "$tool"
        fi
    done
}

deps_cmd_missing_only() {
    local n=0 tool state
    for tool in $(deps_all_tools_sorted); do
        state=$(deps_state_of "$tool")
        [[ "$state" == "installed" ]] && continue
        printf '%s\t%s\t%s\t%s\n' "$(deps_sanitize "$tool")" "$state" \
            "$(deps_sanitize "$(deps_group_for "$tool")")" \
            "$(deps_sanitize "$(deps_pkg_for "$tool")")"
        n=$((n + 1))
    done
    printf 'MISSING_COUNT\t%s\n' "$n"
    [[ "$n" -eq 0 ]]
}

deps_distro_info() {
    printf 'distro\t%s\n' "$(deps_sanitize "$(deps_detect_distro)")"
    printf 'pkg_manager\t%s\n' "$(deps_sanitize "$(deps_pkg_manager)")"
    printf 'kernel\t%s\n' "$(deps_sanitize "$(uname -r 2>/dev/null)")"
    printf 'tools_registered\t%s\n' "$(deps_all_tools_sorted | grep -c .)"
    printf 'tools_missing\t%s\n' "$(deps_status_tsv | awk -F'\t' '$4!="installed"' | grep -c .)"
    printf 'tools_broken\t%s\n' "$(deps_status_tsv | awk -F'\t' '$4=="broken"' | grep -c .)"
    printf 'can_install\t%s\n' "$(case "$(deps_pkg_manager)" in unknown) echo no ;; *) echo yes ;; esac)"
}

deps_write_report() {
    # Fail loudly. A bare `return 1` here meant an unwritable destination
    # reported nothing at all — the caller saw a non-zero status with no
    # reason, which is indistinguishable from a crash.
    if ! mkdir -p "$DEPS_DIR" 2>/dev/null; then
        printf 'ERROR	could not create %s\n' "$DEPS_DIR" >&2
        return 1
    fi
    local tmp="$DEPS_REPORT.tmp.$$"
    if ! { deps_header; deps_status_tsv; } > "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        printf 'ERROR\tcould not write %s (permission denied)\n' "$DEPS_REPORT" >&2
        return 1
    fi
    if ! mv "$tmp" "$DEPS_REPORT" 2>/dev/null; then
        rm -f "$tmp"
        printf 'ERROR\tcould not replace %s\n' "$DEPS_REPORT" >&2
        return 1
    fi
    printf 'OK\t%s\n' "$DEPS_REPORT"
}

# ═══════════════════════════════════════════════════════════════════
#  install
#
#  Installing packages changes the machine, so nothing here acts without an
#  explicit flag. In CLI mode a bare `--install-all` prints the plan and
#  refuses; the interactive menu asks, and the answer is the consent.
# ═══════════════════════════════════════════════════════════════════

deps_install_plan() {
    local tool state pkg mgr
    mgr=$(deps_pkg_manager)
    printf 'plan\t%s\n' "install every registered tool that is not already installed"
    printf 'pkg_manager\t%s\n' "$(deps_sanitize "$mgr")"
    printf 'distro\t%s\n' "$(deps_sanitize "$(deps_detect_distro)")"
    [[ "$mgr" == "unknown" ]] && printf 'WARN\tno supported package manager for this distro; only pip/source steps would run\n'
    for tool in $(deps_all_tools_sorted); do
        state=$(deps_state_of "$tool")
        [[ "$state" == "installed" ]] && continue
        pkg=$(deps_pkg_for "$tool")
        if [[ -n "$pkg" ]]; then
            printf 'install\t%s\t%s\t%s\n' "$tool" "$(deps_sanitize "$pkg")" "$mgr"
        elif deps_is_py_module "$tool"; then
            printf 'install\t%s\t%s\tpip\n' "$tool" "$(deps_sanitize "${DEPS_PIP_DIST[$tool]:-$tool}")"
        else
            printf 'PLAN\t%s\t%s\n' "$tool" "no package in $mgr; build from source (see docs)"
        fi
    done
}

# Refuse in CLI mode; ask only in a real terminal.
deps_confirm() {
    local prompt="$1"
    if [[ -n "${IMSISTING_CLI:-}" ]]; then
        printf 'REFUSED\t%s\n' "$prompt" >&2
        printf 'ERROR\tCLI mode does not install without an explicit flag; re-run with --yes\n' >&2
        return 1
    fi
    [[ -t 0 ]] || {
        printf 'REFUSED\t%s\n' "$prompt" >&2
        printf 'ERROR\tstdin is not a terminal; cannot ask for consent\n' >&2
        return 1
    }
    local a
    read -rp "  $prompt [y/N] " a
    [[ "$a" == "y" || "$a" == "Y" ]] || { printf 'ABORTED\tdeclined\n' >&2; return 1; }
    return 0
}

deps_run_privileged() {
    local packages=("$@")
    local mgr script
    if (( ${#packages[@]} == 0 )); then
        printf 'OK\tnothing to install\n'
        return 0
    fi
    mgr=$(deps_pkg_manager)
    if [[ "$mgr" == "unknown" ]]; then
        printf 'ERROR\tunsupported distro — install manually: %s\n' "$(deps_sanitize "${packages[*]}")" >&2
        return 1
    fi
    if (( EUID == 0 )); then
        deps_privileged_install "${packages[@]}"
        return $?
    fi
    script=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")
    if command -v pkexec >/dev/null 2>&1; then
        # pkexec drops the environment; pass the tree through explicitly or
        # the re-exec'd module resolves IMSISTING_ROOT from /usr/bin.
        pkexec env IMSISTING_ROOT="$IMSISTING_ROOT" \
                   TMP_DIR="$TMP_DIR" LOOT_DIR="$LOOT_DIR" \
                   CAPTURES_DIR="$CAPTURES_DIR" LOGS_DIR="$LOGS_DIR" \
                   STATE_DIR="$STATE_DIR" \
                   "$script" --privileged-install "${packages[@]}"
        return $?
    fi
    printf 'ERROR\tpkexec not found — re-run as root to install packages\n' >&2
    return 1
}

deps_privileged_install() {
    local packages=("$@")
    local mgr pkg
    local -a failed=()
    (( EUID == 0 )) || { printf 'ERROR\troot required\n' >&2; return 1; }
    (( ${#packages[@]} > 0 )) || return 0

    mgr=$(deps_pkg_manager)
    case "$mgr" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update || return 1
            for pkg in "${packages[@]}"; do
                printf 'INSTALLING\t%s\n' "$(deps_sanitize "$pkg")"
                apt-get install -y -- "$pkg" || failed+=("$pkg")
            done ;;
        dnf)
            for pkg in "${packages[@]}"; do
                printf 'INSTALLING\t%s\n' "$(deps_sanitize "$pkg")"
                dnf install -y "$pkg" || failed+=("$pkg")
            done ;;
        pacman)
            pacman -Sy --noconfirm || true
            for pkg in "${packages[@]}"; do
                printf 'INSTALLING\t%s\n' "$(deps_sanitize "$pkg")"
                pacman -S --noconfirm --needed "$pkg" || failed+=("$pkg")
            done ;;
        *) printf 'ERROR\tunsupported package manager\n' >&2; return 1 ;;
    esac

    if (( ${#failed[@]} > 0 )); then
        printf 'FAILED\t%s\n' "$(deps_sanitize "${failed[*]}")" >&2
        return 1
    fi
    printf 'OK\tinstalled %s package(s)\n' "${#packages[@]}"
    return 0
}

# pip path for the python protocol libraries. Runs unprivileged on purpose:
# these belong in the invoking user's environment, not the system one.
deps_install_pip() {
    local -a dists=("$@")
    local -a failed=()
    (( ${#dists[@]} > 0 )) || { printf 'ERROR\tno distributions named\n' >&2; return 2; }
    local py="" d
    for py in python3 python; do command -v "$py" >/dev/null 2>&1 && break; py=""; done
    [[ -z "$py" ]] && { printf 'ERROR\tpython3 not found\n' >&2; return 1; }
    if ! "$py" -m pip --version >/dev/null 2>&1; then
        printf 'ERROR\tpython3-pip is not installed — install it first (apt: python3-pip)\n' >&2
        return 1
    fi
    for d in "${dists[@]}"; do
        printf 'INSTALLING\t%s\n' "$(deps_sanitize "$d")"
        "$py" -m pip install --user -- "$d" 2>&1 | tail -3 || failed+=("$d")
    done
    if (( ${#failed[@]} > 0 )); then
        printf 'FAILED\t%s\n' "$(deps_sanitize "${failed[*]}")" >&2
        return 1
    fi
    printf 'OK\tpip install complete\n'
    return 0
}

deps_dedupe() {
    local x seen=""
    for x in "$@"; do
        [[ -z "$x" ]] && continue
        case " $seen " in *" $x "*) continue ;; esac
        seen="$seen $x"
        printf '%s\n' "$x"
    done
}

# Distro packages for everything missing (pip/source rows are reported, not
# silently dropped: a plan that omits them lies about coverage).
deps_install_missing_cmd() {
    local yes="${1:-}"
    local -a pkgs=() pips=() srcs=()
    local line family pkg
    while IFS='|' read -r pkg family _tool; do
        case "$family" in
            pip)    pips+=("$pkg") ;;
            source) srcs+=("$pkg") ;;
            unknown) ;;
            *)      pkgs+=("$pkg") ;;
        esac
    done < <(deps_missing_packages)
    local -a upkgs=()
    while IFS= read -r pkg; do upkgs+=("$pkg"); done < <(deps_dedupe "${pkgs[@]}")

    printf 'PLAN\tdistro packages\t%s\n' "${#upkgs[@]}"
    local p
    for p in "${upkgs[@]}"; do printf 'will-install\t%s\n' "$(deps_sanitize "$p")"; done
    if (( ${#pips[@]} > 0 )); then
        printf 'PLAN\tpip distributions\t%s\t%s\n' "${#pips[@]}" "$(deps_sanitize "${pips[*]}")"
    fi
    if (( ${#srcs[@]} > 0 )); then
        printf 'PLAN\tsource builds\t%s\t%s\n' "${#srcs[@]}" "$(deps_sanitize "${srcs[*]}")"
    fi

    (( ${#upkgs[@]} + ${#pips[@]} + ${#srcs[@]} > 0 )) || { printf 'OK\tnothing missing\n'; return 0; }

    if [[ "$yes" != "--yes" ]]; then
        deps_confirm "install the packages listed above?" || return 1
    fi
    local rc=0
    if (( ${#upkgs[@]} > 0 )); then
        deps_run_privileged "${upkgs[@]}" || rc=1
    fi
    if (( ${#pips[@]} > 0 )); then
        deps_install_pip "${pips[@]}" || rc=1
    fi
    if (( ${#srcs[@]} > 0 )); then
        printf 'HANDOFF\tsource|%s\n' "$(deps_sanitize "${srcs[*]}")"
        printf 'status: handoff — these have no package in %s; build them from source\n' "$(deps_pkg_manager)" >&2
    fi
    return $rc
}

deps_install_all_cmd() {
    local yes="${1:-}"
    local -a pkgs=() pips=() srcs=()
    local tool pkg
    for tool in $(deps_all_tools_sorted); do
        [[ "$(deps_state_of "$tool")" == "installed" ]] && continue
        pkg=$(deps_pkg_for "$tool")
        if [[ -n "$pkg" ]]; then
            if deps_is_py_module "$tool"; then
                pips+=("$pkg")
            else
                pkgs+=("$pkg")
            fi
        else
            srcs+=("$tool")
        fi
    done
    local -a upkgs=() upips=()
    while IFS= read -r p; do upkgs+=("$p"); done < <(deps_dedupe "${pkgs[@]}")
    while IFS= read -r p; do upips+=("$p"); done < <(deps_dedupe "${pips[@]}")

    printf 'PLAN\tdistro packages\t%s\n' "${#upkgs[@]}"
    local p
    for p in "${upkgs[@]}"; do printf 'will-install\t%s\n' "$(deps_sanitize "$p")"; done
    printf 'PLAN\tpip distributions\t%s\n' "${#upips[@]}"
    for p in "${upips[@]}"; do printf 'will-pip-install\t%s\n' "$(deps_sanitize "$p")"; done
    printf 'PLAN\tsource builds\t%s\n' "${#srcs[@]}"
    for p in "${srcs[@]}"; do printf 'will-build-from-source\t%s\n' "$(deps_sanitize "$p")"; done

    (( ${#upkgs[@]} + ${#upips[@]} > 0 )) || {
        printf 'OK\tno installable packages missing (%s need source)\n' "${#srcs[@]}"
        return 0
    }

    if [[ "$yes" != "--yes" ]]; then
        deps_confirm "install everything listed above?" || return 1
    fi
    local rc=0
    if (( ${#upkgs[@]} > 0 )); then
        deps_run_privileged "${upkgs[@]}" || rc=1
    fi
    if (( ${#upips[@]} > 0 )); then
        deps_install_pip "${upips[@]}" || rc=1
    fi
    (( ${#srcs[@]} > 0 )) && printf 'status: handoff — %s need a source build\n' "${#srcs[@]}" >&2
    return $rc
}

deps_install_package_cmd() {
    local -a req=("$@")
    (( ${#req[@]} > 0 )) || { printf 'ERROR\tusage: --install-package PACKAGE [PACKAGE...]\n' >&2; return 2; }
    # Accept either a tool name or a raw package name; a tool name is
    # translated through the registry so the user can say `grgsm_livemon`.
    local -a resolved=()
    local a p
    for a in "${req[@]}"; do
        [[ -z "$a" ]] && continue
        p=$(deps_pkg_for "$a")
        if [[ -n "$p" ]]; then
            resolved+=("$p")
        else
            resolved+=("$a")
        fi
    done
    local -a uniq=()
    while IFS= read -r p; do uniq+=("$p"); done < <(deps_dedupe "${resolved[@]}")
    (( ${#uniq[@]} > 0 )) || { printf 'ERROR\tno package named\n' >&2; return 2; }

    local -a distro=() pip=()
    for p in "${uniq[@]}"; do
        if printf '%s\n' "${DEPS_PIP_DIST[@]}" | grep -qx "$p"; then pip+=("$p"); else distro+=("$p"); fi
    done
    local rc=0
    if (( ${#distro[@]} > 0 )); then deps_run_privileged "${distro[@]}" || rc=1; fi
    if (( ${#pip[@]} > 0 )); then deps_install_pip "${pip[@]}" || rc=1; fi
    return $rc
}

# ═══════════════════════════════════════════════════════════════════
#  hardware-facing summaries (used by the menu header)
# ═══════════════════════════════════════════════════════════════════

deps_sdr_tools_present() {
    local t
    for t in hackrf_info bladeRF-cli LimeUtil uhd_find_devices rtl_test SoapySDRUtil; do
        deps_check_one "$t" && { printf '%s\n' "$t"; return 0; }
    done
    return 1
}

deps_summary_line() {
    # State only — no version probes. The menu draws this on every redraw, and
    # running the full status sweep here made the menu take 57 seconds to show
    # its first prompt. It also ran the sweep twice. Ask the cheap state probe
    # once per tool instead.
    local total=0 installed=0 broken=0 missing=0 t st
    while read -r t; do
        [[ -z "$t" ]] && continue
        total=$(( total + 1 ))
        st=$(deps_state_of "$t")
        case "$st" in
            installed) installed=$(( installed + 1 )) ;;
            broken)    broken=$(( broken + 1 )) ;;
            *)         missing=$(( missing + 1 )) ;;
        esac
    done < <(deps_all_tools_sorted)
    printf '%s\n' "deps: ${installed}/${total} installed, ${broken} broken, ${missing} missing"
}

# ═══════════════════════════════════════════════════════════════════
#  selftest — no radio, no root, no network
# ═══════════════════════════════════════════════════════════════════
deps_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    local d out rc
    d=$(mktemp -d "$DEPS_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$DEPS_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export DEPS_DIR="$LOOT_DIR/deps"
    export DEPS_TMP="$d/tmp"
    export DEPS_REPORT="$DEPS_DIR/deps_report.tsv"
    mkdir -p "$DEPS_DIR" "$DEPS_TMP"

    # 1. The table is non-empty and every row has exactly six fields.
    chk table-nonempty "$(( ${#DEPS_TOOLS[@]} > 0 ? 1 : 0 ))" 1
    local nrows=${#DEPS_TOOLS[@]}
    chk table-count "$nrows" "$nrows"
    chk table-field-count "$(printf '%s\n' "${DEPS_TOOLS[@]}" | awk -F'|' 'NF!=6{c++} END{print c+0}')" 0
    # name, group, required are never empty; family cells are never empty
    chk table-no-empty "$(printf '%s\n' "${DEPS_TOOLS[@]}" | awk -F'|' '$1==""||$2==""||$3==""||$4==""||$5==""||$6==""{c++} END{print c+0}')" 0
    chk table-required-domain "$(printf '%s\n' "${DEPS_TOOLS[@]}" | awk -F'|' '$3!="yes"&&$3!="no"{c++} END{print c+0}')" 0
    chk table-unique "$(printf '%s\n' "${DEPS_TOOLS[@]}" | cut -d'|' -f1 | sort -u | grep -c .)" "$nrows"
    chk table-py-count "$(printf '%s\n' "${DEPS_PY_MODULES[@]}" | awk -F'|' 'NF!=3{c++} END{print c+0}')" 0
    chk table-extra-registered \
        "$(for t in "${!DEPS_EXTRA[@]}"; do deps_row_for "$t" >/dev/null 2>&1 || echo "$t"; done | grep -c .)" 0
    chk table-minversion-registered \
        "$(for t in "${!DEPS_MIN_VERSION[@]}"; do deps_row_for "$t" >/dev/null 2>&1 || echo "$t"; done | grep -c .)" 0

    # 2. Coverage of the groups the roster promises.
    local g
    for g in sdr gsm lte nr core proto sim crack analysis; do
        chk "group-$g" "$(printf '%s\n' "${DEPS_TOOLS[@]}" | awk -F'|' -v g="$g" '$2==g' | grep -c .)" \
            "$(printf '%s\n' "${DEPS_TOOLS[@]}" | awk -F'|' -v g="$g" '$2==g' | grep -c .)"
        chk "group-$g-nonempty" "$(( $(printf '%s\n' "${DEPS_TOOLS[@]}" | awk -F'|' -v g="$g" '$2==g' | grep -c .) > 0 ? 1 : 0 ))" 1
    done

    # 3. Named tools the task requires are actually in the table.
    local t
    for t in hackrf_info hackrf_transfer bladeRF-cli LimeUtil uhd_find_devices rtl_test \
             SoapySDRUtil gnuradio-companion gqrx grgsm_livemon grgsm_scanner kal \
             srsenb srsepc gnb nr-uesoftmodem open5gs-mmed free5gc tshark tcpdump \
             socat pcscd pcsc_scan opensc-tool hashcat john gpsd gpsbabel sqlite3 jq column pv; do
        chk "registered-$t" "$(deps_row_for "$t" >/dev/null 2>&1 && echo yes || echo no)" yes
    done
    chk registered-scapy "$(printf '%s\n' "${DEPS_PY_MODULES[@]}" | cut -d'|' -f1 | grep -cx scapy)" 1
    chk registered-pycrate "$(printf '%s\n' "${DEPS_PY_MODULES[@]}" | cut -d'|' -f1 | grep -cx pycrate)" 1
    chk registered-asn1tools "$(printf '%s\n' "${DEPS_PY_MODULES[@]}" | cut -d'|' -f1 | grep -cx asn1tools)" 1
    chk registered-pyscard "$(printf '%s\n' "${DEPS_PY_MODULES[@]}" | cut -d'|' -f1 | grep -cx pyscard)" 1

    # 4. Honest detection: a known-present tool, and a name that cannot exist.
    chk detect-bash-present "$(deps_check_one bash && echo yes || echo no)" yes
    chk detect-absent-tool  "$(deps_check_one definitely_not_a_tool_xyz && echo yes || echo no)" no
    chk state-bash          "$(deps_state_of bash)" installed
    chk state-absent        "$(deps_state_of definitely_not_a_tool_xyz)" missing
    chk version-absent-empty "$(deps_tool_version definitely_not_a_tool_xyz)" ""

    # 5. Version parse. A tool that prints NOTHING must yield an empty
    #    version, not a fabricated one and not a crash. Do NOT use `true`:
    #    on GNU coreutils it prints "true (GNU coreutils) 9.4", so it is not
    #    silent and the assertion would be testing the wrong thing. Build a
    #    binary that is silent by construction.
    printf '#!/bin/sh\nexit 0\n' > "$d/silent"; chmod +x "$d/silent"
    chk version-silent-tool "$(deps_tool_version "$d/silent")" ""
    chk version-absent-tool "$(deps_tool_version "$d/no_such_tool")" ""
    chk version-bash-shape "$(deps_tool_version bash | grep -cE '^[0-9]+\.[0-9]+')" 1
    chk version-bash-exact "$(deps_tool_version bash)" "$(bash --version | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
    chk version-flag-bash    "$(deps_version_flag bash)" "-c"
    chk version-flag-default "$(deps_version_flag some-unlisted-tool)" "--version"
    if command -v python3 >/dev/null 2>&1; then
        chk version-python3-shape "$(deps_tool_version python3 | grep -cE '^[0-9]+\.[0-9]+')" 1
    fi

    # 6. Version comparison is numeric, not lexicographic.
    chk vge-equal     "$(deps_version_ge 6.0 6.0; echo $?)" 0
    chk vge-newer     "$(deps_version_ge 6.1 6.0; echo $?)" 0
    chk vge-older     "$(deps_version_ge 5.9 6.0; echo $?)" 1
    chk vge-numeric   "$(deps_version_ge 1.10 1.9; echo $?)" 0
    chk vge-numeric-b "$(deps_version_ge 1.9 1.10; echo $?)" 1
    chk vge-empty-cur "$(deps_version_ge "" 6.0; echo $?)" 0
    chk vge-empty-min "$(deps_version_ge 6.0 ""; echo $?)" 0

    # 7. Distro detection is sane and maps to a known package manager.
    local id mgr
    id=$(deps_detect_distro)
    mgr=$(deps_pkg_manager)
    chk distro-shape "$(printf '%s' "$id" | grep -cE '^[a-z0-9._-]+$')" 1
    chk distro-matches-os-release "$id" \
        "$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -1)"
    case "$id" in
        debian|ubuntu|kali|parrot|raspbian|linuxmint|pop) want_mgr=apt ;;
        fedora|rhel|centos|rocky|alma|ol)                want_mgr=dnf ;;
        arch|manjaro|endeavouros|garuda|artix)           want_mgr=pacman ;;
        *)                                               want_mgr=unknown ;;
    esac
    chk pkg-manager-mapping "$mgr" "$want_mgr"
    chk pkg-manager-known   "$(printf '%s' "$mgr" | grep -cE '^(apt|dnf|pacman|unknown)$')" 1

    # 8. Package mapping per distro family, exercised directly rather than
    #    through whatever this box happens to run.
    chk pkg-apt-hackrf      "$(DEPS_APT_PROBE=$(deps_row_for hackrf_info | cut -d'|' -f4); echo "$DEPS_APT_PROBE")" hackrf
    chk pkg-dnf-bladerf     "$(deps_row_for bladeRF-cli | cut -d'|' -f5)" bladerf
    chk pkg-pacman-limesuite "$(deps_row_for LimeUtil | cut -d'|' -f6)" limesuite
    chk pkg-apt-uhd         "$(deps_row_for uhd_find_devices | cut -d'|' -f4)" uhd-host
    chk pkg-apt-rtlsdr      "$(deps_row_for rtl_test | cut -d'|' -f4)" rtl-sdr
    chk pkg-apt-soapy       "$(deps_row_for SoapySDRUtil | cut -d'|' -f4)" soapysdr-tools
    chk pkg-apt-grgsm       "$(deps_row_for grgsm_livemon | cut -d'|' -f4)" gr-gsm
    chk pkg-apt-srsran-apps "$(deps_row_for srsenb | cut -d'|' -f4)" srsran
    chk pkg-apt-open5gs     "$(deps_row_for open5gs-mmed | cut -d'|' -f4)" open5gs
    chk pkg-dnf-tshark      "$(deps_row_for tshark | cut -d'|' -f5)" wireshark-cli
    chk pkg-pacman-tshark   "$(deps_row_for tshark | cut -d'|' -f6)" wireshark-cli
    chk pkg-apt-column      "$(deps_row_for column | cut -d'|' -f4)" util-linux
    chk pkg-apt-pyscard     "$(deps_pkg_for pyscard)" pyscard
    chk pkg-unknown-tool    "$(deps_pkg_for definitely_not_a_tool_xyz)" ""
    chk row-missing-tool    "$(deps_row_for definitely_not_a_tool_xyz >/dev/null 2>&1; echo $?)" 1
    chk required-bash       "$(deps_required_for bash)" yes
    chk required-hackrf     "$(deps_required_for hackrf_info)" no
    chk group-hackrf        "$(deps_group_for hackrf_info)" sdr
    chk group-grgsm         "$(deps_group_for grgsm_livemon)" gsm
    chk group-unknown       "$(deps_group_for definitely_not_a_tool_xyz)" unknown

    # 9. Every required tool must be installable, or --install-missing lies.
    local no_pkg=""
    local row
    for row in "${DEPS_TOOLS[@]}"; do
        [[ "$(printf '%s\n' "$row" | cut -d'|' -f3)" == "yes" ]] || continue
        for f in 4 5 6; do
            [[ "$(printf '%s\n' "$row" | cut -d'|' -f$f)" == "-" ]] && no_pkg="$no_pkg $(printf '%s\n' "$row" | cut -d'|' -f1)"
        done
    done
    chk pkg-required-mapped "$(printf '%s' "$no_pkg" | tr -s ' ' '\n' | grep -c .)" 0

    # 10. Honesty: a present-with-broken-stack tool is not "installed".
    #     Simulated with a stub so the result does not depend on this box.
    local stub="$d/bin"
    mkdir -p "$stub"
    printf '#!/bin/sh\nexit 0\n' > "$stub/gnuradio-config-info"
    chmod +x "$stub/gnuradio-config-info"
    out=$(PATH="$stub:$PATH" deps_state_of gnuradio-config-info)
    chk broken-state-distinct "$out" broken
    out=$(PATH="$stub:$PATH" deps_extra_state gnuradio-config-info)
    chk broken-state-reason "$(printf '%s' "$out" | grep -c '^broken:')" 1
    # The state domain is closed: nothing else may appear.
    chk state-domain "$(deps_status_tsv | awk -F'\t' '$4!="installed"&&$4!="missing"&&$4!="broken"{c++} END{print c+0}')" 0
    # A present tool with no extra probe is installed, not unknown.
    printf '#!/bin/sh\necho "pv 1.8.5"\n' > "$stub/pv"
    chmod +x "$stub/pv"
    chk plain-present-is-installed "$(PATH="$stub:$PATH" deps_state_of pv)" installed

    # 11. status-tsv shape: one row per registered tool, six fields each.
    out=$(deps_status_tsv)
    chk status-rows    "$(rcount "$out")" "$(deps_all_tools_sorted | grep -c .)"
    chk status-fields  "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=6{c++} END{print c+0}')" 0
    chk status-nonempty "$(printf '%s\n' "$out" | awk -F'\t' '$1==""||$2==""||$3==""||$4==""{c++} END{print c+0}')" 0
    chk status-sorted  "$(printf '%s\n' "$out" | cut -f1 | sort -c 2>/dev/null; echo $?)" 0
    chk status-bash-row "$(printf '%s\n' "$out" | awk -F'\t' '$1=="bash"{print $4}')" installed
    chk status-absent-row "$(printf '%s\n' "$out" | awk -F'\t' '$1=="definitely_not_a_tool_xyz"{print $4}')" ""
    chk header-fields  "$(deps_header | awk -F'\t' '{print NF}')" 6
    chk header-first   "$(deps_header | cut -f1)" tool

    # 12. Untrusted text cannot forge a TSV row.
    chk sanitize-tab  "$(deps_sanitize $'a\tb')" "a b"
    chk sanitize-nl   "$(deps_sanitize $'a\nb')" "a b"
    chk sanitize-cr   "$(deps_sanitize $'a\rb')" "a b"
    chk sanitize-fields "$(printf '%s\n' "$(deps_sanitize $'x\ty\tz')" | awk -F'\t' '{print NF}')" 1

    # 13. --missing-only reports the absent tool by name and returns non-zero.
    out=$(deps_cmd_missing_only); rc=$?
    chk missing-only-rc      "$rc" 1
    # The sentinel name is used elsewhere as a probe target; it is not a row in
    # the dependency table, so --missing-only cannot list it. Assert the
    # invariant that actually holds: every name reported missing really is
    # missing, checked against this same run's own state.
    chk missing-only-names   "$(printf '%s\n' "$out" | awk -F'\t' '$1!="MISSING_COUNT"{print $1}' | while read -r t; do
        [[ "$(deps_state_of "$t")" =~ ^(missing|broken)$ ]] || echo bad
    done | grep -c .)" 0
    chk missing-only-nonempty "$(printf '%s\n' "$out" | awk -F'\t' '$1!="MISSING_COUNT"' | grep -c .)" \
                              "$(fld "$out" MISSING_COUNT)"
    chk missing-only-fields  "$(printf '%s\n' "$out" | awk -F'\t' '$1!="MISSING_COUNT" && NF!=4{c++} END{print c+0}')" 0
    chk missing-only-count   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="MISSING_COUNT"' | grep -c .)" 1
    # MISSING_COUNT counts everything not installed — missing AND broken. The
    # literal-state-word sum that used to be asserted here only agreed on a
    # host where nothing was present-but-broken. Count both states, and assert
    # that no third state can appear in the output at all.
    chk missing-only-tally   "$(fld "$out" MISSING_COUNT)" "$(printf '%s\n' "$out" | grep -cE $'\t(missing|broken)\t')"
    chk missing-only-tally2  "$(fld "$out" MISSING_COUNT)" "$(printf '%s\n' "$out" | awk -F'\t' '$2=="missing"||$2=="broken"' | grep -c .)"
    chk missing-only-states  "$(printf '%s\n' "$out" | awk -F'\t' '$1!="MISSING_COUNT" && $2!="missing" && $2!="broken"{c++} END{print c+0}')" 0
    # present tools must NOT appear
    chk missing-only-omits-present "$(printf '%s\n' "$out" | awk -F'\t' '$1=="bash"' | grep -c .)" 0

    # 14. plan/install paths never act without consent.
    out=$(deps_install_package_cmd 2>&1); rc=$?
    chk install-package-noarg-rc  "$rc" 2
    chk install-package-noarg-msg "$(printf '%s\n' "$out" | grep -c 'usage: --install-package')" 1
    out=$(deps_run_privileged); rc=$?
    chk privileged-nopkgs-rc  "$rc" 0
    chk privileged-nopkgs-says "$(printf '%s\n' "$out" | grep -c 'nothing to install')" 1
    out=$(IMSISTING_CLI=1 deps_install_all_cmd 2>&1); rc=$?
    chk install-all-cli-refuses-msg "$(printf '%s\n' "$out" | grep -c 'REFUSED')" 1
    chk install-all-cli-plan      "$(printf '%s\n' "$out" | grep -c '^PLAN')" 3
    chk install-all-cli-plan-distro "$(printf '%s\n' "$out" | grep -cE '^PLAN[[:space:]]+distro packages')" 1
    chk install-all-cli-plan-pip    "$(printf '%s\n' "$out" | grep -cE '^PLAN[[:space:]]+pip distributions')" 1
    chk install-all-cli-plan-src    "$(printf '%s\n' "$out" | grep -cE '^PLAN[[:space:]]+source builds')" 1
    # It must not have escalated: no pkexec, no package manager ran. The
    # observable proof is that the run produced no INSTALLING line.
    chk install-all-cli-no-act    "$(printf '%s\n' "$out" | grep -c '^INSTALLING')" 0
    out=$(deps_install_pip 2>&1); rc=$?
    chk install-pip-noarg-rc "$rc" 2

    # 15. install plan is complete and truthful about coverage.
    out=$(deps_install_plan)
    chk plan-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF<2{c++} END{print c+0}')" 0
    chk plan-pkg-mgr  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="pkg_manager"{print $2}')" "$(deps_pkg_manager)"
    # an absent tool with a package must be listed, an installed one must not
    if ! command -v hackrf_info >/dev/null 2>&1; then
        chk plan-lists-absent "$(printf '%s\n' "$out" | awk -F'\t' '$1=="install" && $2=="hackrf_info"' | grep -c .)" 1
    fi
    if command -v bash >/dev/null 2>&1; then
        chk plan-omits-present "$(printf '%s\n' "$out" | awk -F'\t' '$2=="bash"' | grep -c .)" 0
    fi

    # 16. check-versions report is internally consistent.
    out=$(deps_check_versions_tsv)
    chk cv-issues-match "$(fld "$out" ISSUES)" \
        "$(printf '%s\n' "$out" | awk -F'\t' '$1=="MISSING"||$1=="BROKEN"||$1=="TOO_OLD"' | grep -c .)"
    chk cv-last-is-issues "$(printf '%s\n' "$out" | tail -1 | cut -f1)" ISSUES
    chk cv-invariants "$(printf '%s\n' "$out" | awk -F'\t' '
            $1=="OK"||$1=="PRESENT"||$1=="MISSING"{if(NF!=4)c++}
            $1=="BROKEN"{if(NF!=4)c++}
            $1=="NOTE"||$1=="VERSION_UNKNOWN"{if(NF!=3)c++}
            $1=="FLOOR_OK"||$1=="TOO_OLD"{if(NF!=4)c++}
            $1=="ISSUES"||$1=="check"||$1=="distro"||$1=="pkg_manager"{if(NF!=2)c++}
            $1!="OK"&&$1!="PRESENT"&&$1!="MISSING"&&$1!="BROKEN"&&$1!="NOTE"&&$1!="VERSION_UNKNOWN"&&$1!="FLOOR_OK"&&$1!="TOO_OLD"&&$1!="ISSUES"&&$1!="check"&&$1!="distro"&&$1!="pkg_manager"{c++}
            END{print c+0}')" 0
    chk cv-known-tools "$(printf '%s\n' "$out" | awk -F'\t' '$1=="FLOOR_OK"||$1=="TOO_OLD"||$1=="VERSION_UNKNOWN"{print $2}' | while read -r t; do [[ -n "${DEPS_MIN_VERSION[$t]:-}" ]] || echo bad; done | grep -c .)" 0
    chk cv-bash-ok "$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK" && $2=="bash"' | grep -c .)" 1
    chk cv-floor-row "$(printf '%s\n' "$out" | awk -F'\t' '$1=="FLOOR_OK"||$1=="TOO_OLD"||$1=="VERSION_UNKNOWN"' | grep -c .)" \
        "$(for t in "${!DEPS_MIN_VERSION[@]}"; do [[ "$(deps_state_of "$t")" == installed ]] && echo "$t"; done | grep -c .)"
    chk cv-absent-named "$(printf '%s\n' "$out" | awk -F'\t' '$1=="MISSING" && $2=="definitely_not_a_tool_xyz"' | grep -c .)" 0

    # 17. report writing: works, and does not claim success on failure.
    unset IMSISTING_CLI
    out=$(deps_write_report); rc=$?
    chk report-rc     "$rc" 0
    chk report-exists "$([[ -f "$DEPS_REPORT" ]] && echo yes || echo no)" yes
    chk report-says   "$(printf '%s\n' "$out" | cut -f1)" OK
    chk report-header "$(head -1 "$DEPS_REPORT" | cut -f1)" tool
    chk report-rows   "$(tail -n +2 "$DEPS_REPORT" | grep -c .)" "$(deps_all_tools_sorted | grep -c .)"
    # A report destination that cannot be written must be reported as a
    # failure, never as success. Redirect DEPS_DIR at a path whose parent is
    # a plain FILE, so mkdir -p fails for real on every filesystem.
    local blocker="$d/blocker"
    printf 'not a directory\n' > "$blocker"
    local saved_report="$DEPS_REPORT" saved_dir="$DEPS_DIR"
    DEPS_DIR="$blocker/deps"
    DEPS_REPORT="$DEPS_DIR/deps_report.tsv"
    out=$(deps_write_report 2>&1); rc=$?
    chk report-failure-rc   "$rc" 1
    chk report-failure-says "$(printf '%s\n' "$out" | grep -c '^ERROR')" 1
    chk report-no-ok-line   "$(printf '%s\n' "$out" | grep -c '^OK')" 0
    DEPS_DIR="$saved_dir"; DEPS_REPORT="$saved_report"

    # 18. distro-info keys and dispatch.
    out=$(deps_distro_info)
    chk distro-info-keys "$(printf '%s\n' "$out" | cut -f1 | tr '\n' ' ')" \
        "distro pkg_manager kernel tools_registered tools_missing tools_broken can_install "
    chk distro-info-installable "$(fld "$out" can_install)" \
        "$(case "$(deps_pkg_manager)" in unknown) echo no ;; *) echo yes ;; esac)"
    chk main-distroinfo-rc "$(deps_cli_main --distro-info >/dev/null 2>&1; echo $?)" 0
    chk main-status-rc     "$(deps_cli_main --status-tsv >/dev/null 2>&1; echo $?)" 0
    chk main-unknown-rc    "$(deps_cli_main definitely-not-a-verb >/dev/null 2>&1; echo $?)" 2
    chk main-noargs-rc     "$(deps_cli_main >/dev/null 2>&1; echo $?)" 2
    chk main-selftest-helper "$(declare -F deps_selftest >/dev/null && echo yes || echo no)" yes
    chk menu-helper          "$(declare -F deps_menu >/dev/null && echo yes || echo no)" yes
    chk cli-menu-rc          "$(deps_cli_main --menu < /dev/null >/dev/null 2>&1; echo $?)" 0

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ═══════════════════════════════════════════════════════════════════
#  menu
# ═══════════════════════════════════════════════════════════════════
deps_menu() {
    local c
    while true; do
        banner
        echo -e "  ${C_MAG}=== dependency manager ===${C_RESET}"
        echo -e "  distro: ${C_GRN}$(deps_detect_distro)${C_RESET}  pkg: ${C_GRN}$(deps_pkg_manager)${C_RESET}"
        echo -e "  ${C_DIM}$(deps_summary_line)${C_RESET}"
        echo -e "  sdr tools: ${C_GRN}$(deps_sdr_tools_present | tr '\n' ' ' || echo none)${C_RESET}\n"
        cat << 'M'
  [1]  check versions (full report)
  [2]  show missing tools only
  [3]  install what is missing
  [4]  install ALL registered packages
  [5]  install one package
  [6]  distro info
  [7]  write status report to loot/
  [0]  back

M
        if [[ -n "${IMSISTING_CLI:-}" ]]; then
            echo "  (menu unavailable in CLI mode)" >&2
            return 0
        fi
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) deps_check_versions_tsv | column -t -s$'\t' 2>/dev/null || deps_check_versions_tsv
               read -rp "  press enter " _ ;;
            2) deps_cmd_missing_only | column -t -s$'\t' 2>/dev/null || deps_cmd_missing_only
               read -rp "  press enter " _ ;;
            3) deps_install_missing_cmd; read -rp "  press enter " _ ;;
            4) deps_install_all_cmd; read -rp "  press enter " _ ;;
            5) read -rp "  package or tool name> " p
               deps_install_package_cmd "$p"; read -rp "  press enter " _ ;;
            6) deps_distro_info | column -t -s$'\t' 2>/dev/null || deps_distro_info
               read -rp "  press enter " _ ;;
            7) deps_write_report; sleep 1 ;;
            0) return 0 ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════
#  CLI dispatch
# ═══════════════════════════════════════════════════════════════════
deps_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)       deps_status_tsv ;;
        --check-versions)   deps_check_versions_tsv ;;
        --missing-only)     deps_cmd_missing_only ;;
        --install-missing)  deps_install_missing_cmd "${1:-}" ;;
        --install-package)  deps_install_package_cmd "$@" ;;
        --install-all)      deps_install_all_cmd "${1:-}" ;;
        --install-pip)      deps_install_pip "$@" ;;
        --distro-info)      deps_distro_info ;;
        --report)           deps_write_report ;;
        --privileged-install) deps_privileged_install "$@" ;;
        --selftest)         deps_selftest ;;
        --menu)             deps_menu ;;
        help|--help|-h)
            cat <<EOF
Dependency Manager — the cellular toolchain

Usage: $0 COMMAND
  --status-tsv                 one row per registered tool, 6 TSV fields
  --check-versions             present/absent/broken with version strings
  --missing-only               only the tools that are not usable
  --install-missing [--yes]    install what is missing (asks first)
  --install-package PKG...     install named packages or tool names
  --install-all [--yes]        install every registered package
  --install-pip DIST...        pip-install protocol libraries
  --distro-info                distro, package manager, counts
  --report                     write loot/deps/deps_report.tsv
  --selftest                   verify the registry and parsers, no radio
  --menu                       interactive menu

Installs never run without consent: in CLI mode a bare --install-all or
--install-missing prints the plan and refuses unless --yes is given.
EOF
            ;;
        *) cat >&2 <<EOF
Usage: $0 --status-tsv | --check-versions | --missing-only
       $0 --install-missing [--yes] | --install-package PKG... | --install-all [--yes]
       $0 --install-pip DIST... | --distro-info | --report
       $0 --selftest | --menu
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
    deps_cli_main "$@"
fi
