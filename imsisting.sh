#!/usr/bin/env bash
# IMSIsting main launcher — cellular security research toolkit
#
# Standalone CLI:   sudo bash imsisting.sh
# Sourced by GUI:   IMSISTING_GUI=1 source imsisting.sh

# ── sourced-vs-executed detection ───────────────────────────
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    IMSISTING_SOURCED=1
else
    IMSISTING_SOURCED=0
fi
export IMSISTING_SOURCED

# ── resolve script location, following symlinks ─────────────
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

export IMSISTING_ROOT="$SCRIPT_DIR"
export MODULES_DIR="$SCRIPT_DIR/modules"

# ── version ─────────────────────────────────────────────────
# VERSION has no second copy: native/meson.build reads this same file at
# configure time, so the GUI label and `--version` cannot drift apart the way
# they had (the CLI said v0.4 while meson.build still said 0.1.0). If the file
# is unreadable, say so rather than print a plausible stale number.
if [[ -r "$SCRIPT_DIR/VERSION" ]]; then
    IMSISTING_VERSION="$(cat "$SCRIPT_DIR/VERSION")"
else
    IMSISTING_VERSION="unknown"
fi
export IMSISTING_VERSION

# ── declared settings ───────────────────────────────────────
# state/settings.tsv holds what the operator declared: key<TAB>value, one per
# line, '#' starts a comment, and a missing key means "the default". Plain
# TSV for the same reason state/ui.tsv is: no parser to get wrong, and a file
# that survives being read by hand.
#
# Precedence is environment > file > default, so a one-off
# `LOOT_DIR=/mnt/usb bash imsisting.sh` still means what it says.
SETTINGS_FILE="$SCRIPT_DIR/state/settings.tsv"
declare -A IMSISTING_SETTINGS=()
imsisting_settings_load() {
    local k v line
    IMSISTING_SETTINGS=()
    [[ -r "$SETTINGS_FILE" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        k="${line%%$'\t'*}"
        v="${line#*$'\t'}"
        [[ -z "$k" || "$k" == "$line" ]] && continue   # no tab: not a pair
        IMSISTING_SETTINGS["$k"]="$v"
    done < "$SETTINGS_FILE"
    return 0
}
# Value of a setting, or the default when it was never declared.
imsisting_setting() {
    local k="$1" d="${2:-}"
    [[ -n "${IMSISTING_SETTINGS[$k]+set}" ]] && printf '%s' "${IMSISTING_SETTINGS[$k]}" || printf '%s' "$d"
}
# True when the key is in the file (so the UI can say "default" honestly).
imsisting_setting_set() { [[ -n "${IMSISTING_SETTINGS[$1]+set}" ]]; }
imsisting_settings_load

export TMP_DIR="${TMP_DIR:-$(imsisting_setting paths.tmp "$SCRIPT_DIR/tmp")}"
export LOOT_DIR="${LOOT_DIR:-$(imsisting_setting paths.loot "$SCRIPT_DIR/loot")}"
export LOG_DIR="${LOG_DIR:-$(imsisting_setting paths.logs "$SCRIPT_DIR/logs")}"
export CAPTURES_DIR="${CAPTURES_DIR:-$(imsisting_setting paths.captures "$SCRIPT_DIR/captures")}"
export STATE_DIR="${STATE_DIR:-$(imsisting_setting paths.state "$SCRIPT_DIR/state")}"
export CASES_DIR="${CASES_DIR:-$(imsisting_setting paths.cases "$SCRIPT_DIR/cases")}"
export SESSION_LOG="${SESSION_LOG:-$LOG_DIR/session_$(date +%Y%m%d_%H%M%S)_$$.log}"

for d in "$TMP_DIR" "$LOOT_DIR" "$LOG_DIR" "$CAPTURES_DIR" "$STATE_DIR" "$CASES_DIR"; do
    if ! mkdir -p "$d"; then
        printf 'imsisting: cannot create %s\n' "$d" >&2
        (( IMSISTING_SOURCED )) && return 1 || exit 1
    fi
done

# ---------------------------------------------------------------------
#  Module icons. GTK resolves them by name from the hicolor theme, so the
#  symbolic SVGs are copied there and the cache refreshed. Without this a
#  tarball unzipped elsewhere shows grey placeholder boxes with no
#  indication why.
#  The theme is kept in step with the tree, not merely seeded: files that are
#  missing or whose content differs are (re)copied, and imsisting-* files this
#  toolkit no longer ships are pruned. Copy-if-missing alone meant an edited
#  or renamed icon never reached the theme — the old drawing stayed installed
#  with nothing to show it was stale. The cache rebuild is skipped when
#  nothing changed.
# ---------------------------------------------------------------------
ICON_SRC="$SCRIPT_DIR/native/resources/icons/symbolic"
ICON_DST="$HOME/.local/share/icons/hicolor/scalable/actions"

if [ -d "$ICON_SRC" ]; then
    installed=0
    pruned=0
    mkdir -p "$ICON_DST" 2>/dev/null
    for src in "$ICON_SRC"/imsisting-*.svg; do
        [ -e "$src" ] || continue
        name=$(basename "$src")
        if [ ! -e "$ICON_DST/$name" ] || ! cmp -s "$src" "$ICON_DST/$name"; then
            cp -f "$src" "$ICON_DST/$name" 2>/dev/null && installed=$((installed + 1))
        fi
    done
    # Only imsisting-* names are considered here, so nothing else in the
    # user's icon theme is ever touched.
    for dst in "$ICON_DST"/imsisting-*.svg; do
        [ -e "$dst" ] || continue
        name=$(basename "$dst")
        if [ ! -e "$ICON_SRC/$name" ]; then
            rm -f "$dst" 2>/dev/null && pruned=$((pruned + 1))
        fi
    done
    if [ "$installed" -gt 0 ] || [ "$pruned" -gt 0 ]; then
        printf '  module icons: %d updated, %d pruned in the hicolor theme\n' \
               "$installed" "$pruned"
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -t -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
        fi
    fi
fi

# ---------------------------------------------------------------------
#  Application icon and desktop entry.
#
#  The icon has to be findable by name. A menu, a dock, a window list and a
#  file manager all resolve the entry's Icon= key through GtkIconTheme, and a
#  theme only knows the names inside its own directories: an absolute path
#  into the tree is the desktop spec's fallback and GIO-based readers accept
#  it, but a theme-based reader treats the value as a name, finds nothing and
#  draws a blank page. So the logo is copied into the user's own hicolor theme
#  under the application id. That is a per-user file, needs no root and no
#  distro theme, and it follows this tree around because it is rewritten
#  whenever the source is newer.
#
#  Sizes are generated when ImageMagick is around, because a 500 px PNG
#  scaled down looks better than one blit at 48 px; without it the full-size
#  file goes into the 512 slot and a theme scales it itself.
#
#  The entry is written beside it, named after the application id the GTK
#  side registers, and rewritten only when its content differs — which is
#  also how a checkout that moved stops pointing at where it used to be.
#
#  $XDG_DATA_HOME is the standard location with its own default as the
#  fallback, so a system that never set the variable still gets the files.
# ---------------------------------------------------------------------
DESKTOP_ID="com.imsisting.native"
DESKTOP_SRC="$SCRIPT_DIR/native/resources/imsisting.desktop.in"
DESKTOP_LOGO="$SCRIPT_DIR/native/resources/imsisting_logo.png"

if [ -r "$DESKTOP_LOGO" ]; then
    DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}"
    ICON_THEME="$DATA_DIR/icons/hicolor"

    if command -v convert >/dev/null 2>&1; then
        icon_sizes="48 64 128 256 512"
    else
        icon_sizes="512"
    fi

    desktop_icons=0
    for size in $icon_sizes; do
        icon_dir="$ICON_THEME/${size}x${size}/apps"
        icon_dst="$icon_dir/$DESKTOP_ID.png"
        if [ -e "$icon_dst" ] && [ ! "$DESKTOP_LOGO" -nt "$icon_dst" ]; then
            continue
        fi
        if ! mkdir -p "$icon_dir" 2>/dev/null; then
            continue
        fi
        if [ "$size" = "512" ]; then
            cp -f "$DESKTOP_LOGO" "$icon_dst" 2>/dev/null &&
                desktop_icons=$((desktop_icons + 1))
        else
            convert "$DESKTOP_LOGO" -resize "${size}x${size}" -strip "$icon_dst" 2>/dev/null &&
                desktop_icons=$((desktop_icons + 1))
        fi
    done

    if [ "$desktop_icons" -gt 0 ]; then
        printf '  installed %s application icon(s) into the hicolor theme\n' "$desktop_icons"
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -t -f "$ICON_THEME" 2>/dev/null || true
        fi
    fi
fi

if [ -r "$DESKTOP_SRC" ]; then
    DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    DESKTOP_DST="$DESKTOP_DIR/$DESKTOP_ID.desktop"
    if mkdir -p "$DESKTOP_DIR" 2>/dev/null; then
        desktop_exec="\"$SCRIPT_DIR/imsisting.sh\" --gui"
        desktop_tmp="$(mktemp "$DESKTOP_DIR/.imsisting.XXXXXX" 2>/dev/null)" || desktop_tmp=""
        if [ -n "$desktop_tmp" ]; then
            # Literal substitution: a path is never a pattern, so & and | in
            # it stay what they are.
            while IFS= read -r line || [ -n "$line" ]; do
                line="${line//@EXEC@/$desktop_exec}"
                printf '%s\n' "$line"
            done < "$DESKTOP_SRC" > "$desktop_tmp"
            if [ ! -e "$DESKTOP_DST" ] || ! cmp -s "$desktop_tmp" "$DESKTOP_DST"; then
                chmod 644 "$desktop_tmp"
                if mv -f "$desktop_tmp" "$DESKTOP_DST"; then
                    printf '  desktop entry: %s\n' "$DESKTOP_DST"
                else
                    rm -f "$desktop_tmp"
                fi
            else
                rm -f "$desktop_tmp"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------
#  The GUI binary's own icon, for a file manager.
#
#  A file manager reads a file's icon from its content type, and an ELF
#  executable is sniffed as application/x-executable whatever it is named, so
#  browsing to the binary shows a generic executable. The package installed
#  here declares a content type of our own, keyed on the file name, and
#  points it at the same icon the desktop entry uses.
#
#  It adds a type rather than restating application/x-executable, because that
#  one is global and another toolkit on the same machine may already have its
#  own mapping for it - rewriting it would put this logo on every executable.
#
#  update-mime-database compiles the package into the mime cache, and is
#  skipped when the file did not change, since that rebuild is the expensive
#  half of this.
# ---------------------------------------------------------------------
MIME_SRC="$SCRIPT_DIR/native/resources/imsisting-gui-mime.xml"

if [ -r "$MIME_SRC" ]; then
    MIME_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/mime"
    MIME_DST="$MIME_DIR/packages/imsisting-gui.xml"
    mime_changed=0
    if [ ! -e "$MIME_DST" ] || ! cmp -s "$MIME_SRC" "$MIME_DST"; then
        if mkdir -p "$MIME_DIR/packages" 2>/dev/null && cp -f "$MIME_SRC" "$MIME_DST" 2>/dev/null; then
            mime_changed=1
            printf '  file-type icon: %s\n' "$MIME_DST"
        fi
    fi
    if [ "$mime_changed" = 1 ] && command -v update-mime-database >/dev/null 2>&1; then
        update-mime-database "$MIME_DIR" 2>/dev/null || true
    fi
fi

# ── CLI flags (standalone only) ─────────────────────────────
IMSISTING_LIST=0

# One key, one line, rewritten in place. `drop` is a full key, never a prefix,
# so paths.tmp can never take paths.tmp2 with it.
imsisting_settings_rewrite() {
    local drop="$1" append="${2:-}" line tmp
    mkdir -p "$(dirname "$SETTINGS_FILE")" 2>/dev/null
    tmp="$(mktemp "$SETTINGS_FILE.XXXXXX")" || return 1
    if [[ -f "$SETTINGS_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" == "$drop"$'\t'* ]] && continue
            printf '%s\n' "$line"
        done < "$SETTINGS_FILE" > "$tmp"
    fi
    [[ -n "$append" ]] && printf '%s\n' "$append" >> "$tmp"
    mv -f "$tmp" "$SETTINGS_FILE"
}

imsisting_settings_cli() {
    local cmd="${1:-list}" k v
    case "$cmd" in
        path) printf '%s\n' "$SETTINGS_FILE" ;;
        list)
            imsisting_settings_load
            for k in $(printf '%s\n' "${!IMSISTING_SETTINGS[@]}" | sort); do
                printf '%s\t%s\n' "$k" "${IMSISTING_SETTINGS[$k]}"
            done ;;
        get)
            k="${2:-}"
            [[ -n "$k" ]] || { printf 'usage: imsisting --settings get KEY\n' >&2; return 2; }
            imsisting_settings_load
            imsisting_setting "$k" ""
            printf '\n' ;;
        set)
            k="${2:-}"; v="${3:-}"
            [[ -n "$k" && $# -ge 3 ]] || { printf 'usage: imsisting --settings set KEY VALUE\n' >&2; return 2; }
            imsisting_settings_rewrite "$k" "$k"$'\t'"$v" || return 1
            printf '%s\t%s\n' "$k" "$v" ;;
        unset)
            k="${2:-}"
            [[ -n "$k" ]] || { printf 'usage: imsisting --settings unset KEY\n' >&2; return 2; }
            imsisting_settings_rewrite "$k" || return 1 ;;
        reset)
            : > "$SETTINGS_FILE"
            printf 'imsisting: %s cleared — every setting is back to its default\n' "$SETTINGS_FILE" ;;
        *)
            printf 'usage: imsisting --settings [list|get KEY|set KEY VALUE|unset KEY|reset|path]\n' >&2
            return 2 ;;
    esac
}

if (( ! IMSISTING_SOURCED )); then
    case "${1:-}" in
        -h|--help)
            cat << 'USAGE'
imsisting — cellular security research toolkit
            2G/GSM · 3G/UMTS · 4G/LTE · 5G/NR

Usage:
  sudo bash imsisting.sh           Interactive module browser (requires root)
  sudo bash imsisting.sh --tui     Full-screen module browser (explicit selection)
  bash imsisting.sh --list         List all modules and availability
  bash imsisting.sh --index        Print the module index (TSV)
  bash imsisting.sh --gui          Launch the GTK GUI
  bash imsisting.sh --settings list        Declared settings (TSV)
  bash imsisting.sh --settings set K V     Declare a setting
  bash imsisting.sh --settings unset K     Back to the default
  bash imsisting.sh --settings reset       Back to every default
  bash imsisting.sh --version      Print version
  bash imsisting.sh --help         This message
USAGE
            exit 0 ;;
        -V|--version)
            # Count the modules rather than hardcode: a stale number here is
            # the first thing a user sees and the easiest thing to forget.
            # The version itself is never written here -- it is read from
            # VERSION above, so this line cannot drift from the GUI.
            _n=$(ls -1 "$SCRIPT_DIR"/modules/*.sh 2>/dev/null | wc -l)
            echo "imsisting v${IMSISTING_VERSION} — ${_n} modules, 2G/3G/4G/5G"
            unset _n
            exit 0 ;;
        --index)
            cat "$SCRIPT_DIR/module_index.tsv" 2>/dev/null || {
                printf 'imsisting: no module_index.tsv — run tools/gen-module-index.sh\n' >&2
                exit 1
            }
            exit 0 ;;
        --settings)
            shift
            imsisting_settings_cli "$@"
            exit $? ;;
        --list)
            IMSISTING_LIST=1 ;;
        --tui)
            IMSISTING_TUI=1
            IMSISTING_LIST=0 ;;
        --gui)
            IMSISTING_GUI=1
            IMSISTING_LIST=0 ;;
        "")
            ;;
        *)
            printf 'imsisting: unknown flag: %s\n' "$1" >&2
            exit 2 ;;
    esac
fi

# ── palette ─────────────────────────────────────────────────
C_RED=$'\e[38;5;196m'; C_GRN=$'\e[38;5;46m';   C_YEL=$'\e[38;5;226m'
C_CYN=$'\e[38;5;51m';  C_MAG=$'\e[38;5;201m';  C_BLU=$'\e[38;5;39m'
C_ORG=$'\e[38;5;208m'; C_PUR=$'\e[38;5;135m';  C_DIM=$'\e[38;5;240m'
C_WHT=$'\e[38;5;255m'; C_BOLD=$'\e[1m';        C_RESET=$'\e[0m'
export C_RED C_GRN C_YEL C_CYN C_MAG C_BLU C_ORG C_PUR C_DIM C_WHT C_BOLD C_RESET

# ── logging ─────────────────────────────────────────────────
info() { echo -e "${C_CYN}[${C_BOLD}*${C_RESET}${C_CYN}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }
ok()   { echo -e "${C_GRN}[${C_BOLD}+${C_RESET}${C_GRN}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }
warn() { echo -e "${C_YEL}[${C_BOLD}!${C_RESET}${C_YEL}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }
err()  { echo -e "${C_RED}[${C_BOLD}-${C_RESET}${C_RED}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }

# ── cursor + width ──────────────────────────────────────────
show_cursor() { printf '\e[?25h'; }
hide_cursor() { printf '\e[?25l'; }
term_width() {
    local w
    w=$(tput cols 2>/dev/null) || w=80
    [[ -z "$w" || "$w" -lt 40 ]] && w=80
    echo "$w"
}

if (( ! IMSISTING_SOURCED )); then
    trap 'show_cursor; tput cnorm 2>/dev/null; echo' EXIT INT TERM
fi

# ── module table ────────────────────────────────────────────
# CATEGORY|KEY|LABEL|MENU_FUNCTION|MODULE_ID
#
# KEY is the menu selection key (a sequential position, as in wifisting);
# MODULE_ID is the module file the row drives. They are NOT the same number
# and are not meant to be — the fifth field exists so the mapping is stated
# rather than inferred. tools/check-paths.sh verifies every module file
# appears here exactly once.
IMSISTING_MODULE_TABLE=(
    # SYSTEM
    "SYSTEM|01|Dependency Manager|deps_menu|00_deps"
    "SYSTEM|02|SDR / Radio Manager|radio_menu|01_radio"
    "SYSTEM|03|Field Kit|fkit_menu|05_field_kit"
    "SYSTEM|04|Cellular Killchain|kchn_menu|25_killchain"

    # RECON
    "RECON|05|Cell Recon|crec_menu|02_cell_recon"
    "RECON|06|GSMTAP Live Feed|gtap_menu|03_gsmtap"
    "RECON|07|Tower Survey|tmap_menu|04_tower_map"

    # RADIO
    "RADIO|08|GSM Air Interface|gair_menu|06_gsm_air"
    "RADIO|09|GSM Catcher|gatk_menu|07_gsm_attack"
    "RADIO|10|UMTS Air Interface|uair_menu|08_umts_air"
    "RADIO|11|LTE Air Interface|lair_menu|10_lte_air"
    "RADIO|12|5G NR Air Interface|nair_menu|12_nr_air"
    "RADIO|13|Downgrade Attacks|dwn_menu|15_downgrade"
    "RADIO|14|NB-IoT / Cat-M1|iot_menu|45_iot"
    "RADIO|15|GPRS / EDGE|gprs_menu|50_gprs"
    "RADIO|16|NR Sidelink / V2X|slnk_menu|51_sidelink"
    "RADIO|17|5G NTN / Satellite|ntn_menu|49_ntn"
    "RADIO|18|TETRA / DMR / GSM-R|n3g_menu|53_non3gpp"
    "RADIO|19|Jamming Detection|jamd_menu|33_jamming_detect"
    "RADIO|20|LTE Evil Twin|et_menu|57_evil_twin"

    # ACCESS
    "ACCESS|20|LTE Attach Forge|latt_menu|09_lte_attach"
    "ACCESS|21|Slicing Escape|slic_menu|34_slicing"
    "ACCESS|22|VoWiFi / ePDG Attacks|vowi_menu|36_vowifi"
    "ACCESS|23|Small Cell / eNB Attacks|femt_menu|37_femtocell"
    "ACCESS|24|USSD Forge|ussd_menu|38_ussd"
    "ACCESS|25|RAN Sharing|rans_menu|43_ran_share"
    "ACCESS|26|Wi-Fi Offload / LWA|wifioff_menu|47_wifioff"

    # CORE NETWORK
    "CORE NETWORK|27|LTE Core (EPC)|lcore_menu|11_lte_core"
    "CORE NETWORK|28|5G Core (SBA)|ncore_menu|13_nr_core"
    "CORE NETWORK|29|SS7 / MAP Attacks|ss7_menu|26_ss7_map"
    "CORE NETWORK|30|Cellular DNS Spoof|cdns_menu|27_cellular_dns"
    "CORE NETWORK|31|VoLTE / IMS Attacks|vims_menu|30_volte_ims"
    "CORE NETWORK|32|NAS Signalling|nasf_menu|32_nas_signaling"
    "CORE NETWORK|33|5G SBA Pivot|sbap_menu|40_sba_pivot"
    "CORE NETWORK|34|O-RAN / xApp Attacks|oran_menu|48_oran"

    # SIM / IDENTITY
    "SIM / IDENTITY|35|SUCI Deconcealment|suci_menu|14_suci"
    "SIM / IDENTITY|36|SIM / eSIM / OTA Attacks|sim_menu|16_sim"
    "SIM / IDENTITY|37|IMSI Harvest|imsi_menu|18_imsi_exposure"
    "SIM / IDENTITY|38|SIM Swap Attack/Defence|simd_menu|31_sim_defense"
    "SIM / IDENTITY|39|OTA Binary SMS Attacks|otasm_menu|41_ota_sms"
    "SIM / IDENTITY|40|STK Attacks|stk_menu|52_stk"

    # BASEBAND / DEVICE
    "BASEBAND / DEVICE|41|Baseband Fuzzing|bbnd_menu|35_baseband"
    "BASEBAND / DEVICE|42|Baseband Exploits|bexp_menu|54_baseband_exploit"
    "BASEBAND / DEVICE|43|5G NR Injection|nrj_menu|55_nr_inject"
    "BASEBAND / DEVICE|44|Baseband NV/EFS|bbdg_menu|56_baseband_diag"
    "SIM / IDENTITY|58|5G SUCI Catcher|suci_catcher_menu|58_suci_catcher"

    # TRACKING
    "TRACKING|45|RF Fingerprint / CSI|rff_menu|24_rf_fingerprint"
    "TRACKING|46|Paging / Torpedo|pgt_menu|28_paging_track"
    "TRACKING|47|TA Geolocation|tgeo_menu|39_ta_geoloc"
    "TRACKING|48|LPP Position Forgery|lpp_menu|46_lpp"

    # ANALYSIS
    "ANALYSIS|49|Capture Analysis|pcap_menu|17_pcap_analysis"
    "ANALYSIS|50|Cipher Audit|caud_menu|19_cipher_audit"
    "ANALYSIS|51|Traffic Analysis|tana_menu|23_traffic_analysis"
    "ANALYSIS|52|MAC / RLC Analysis|macl_menu|29_mac_layer"

    # EXPLOIT KITS
    "EXPLOIT KITS|53|GSM/UMTS CVE Kit|gcve_menu|20_gsm_cve"
    "EXPLOIT KITS|54|LTE CVE Kit|lcve_menu|21_lte_cve"
    "EXPLOIT KITS|55|5G CVE Kit|ncve_menu|22_nr_cve"

    # INTERCEPT / CARRIER
    "INTERCEPT / CARRIER|56|LI Interception|lipr_menu|42_li_probe"
    "INTERCEPT / CARRIER|57|Carrier API Abuse|capi_menu|44_carrier_api"

)

# ── banner ──────────────────────────────────────────────────
# Wordmark on the left, illustration on the right, after a modern terminal
# splash. The illustration is a baked terminal-art asset (assets/banner.ans,
# produced by tools/gen-banner.sh from any image) when present; otherwise a
# built-in line-art fallback. A terminal too narrow for both stacks them.
banner() {
    clear
    local w; w=$(term_width)

    local -a _LOGO=(
        '████ █   █ █████ ████       █   █'
        '  █  ██ ██ █       █        █            ███'
        '  █  █ █ █ █████   █  ████ ███  █  █ ██ █  █'
        '  █  █   █     █   █  █     █   █  ██ █ ████'
        '  █  █   █ █████   █   ███  █   █  █  █    █'
        '████ █   █ █████ ████ ████  ██  █  █  █ ███'
    )
    # wordmark gradient: blue -> violet -> magenta, one shade per line.
    local -a _GC=( "$C_BLU" $'\e[38;5;63m' $'\e[38;5;69m' $'\e[38;5;105m' "$C_PUR" "$C_MAG" )
    local _i _l _lw=0
    for _l in "${_LOGO[@]}"; do (( ${#_l} > _lw )) && _lw=${#_l}; done

    # The illustration: baked asset if present, else the built-in fallback.
    local _asset="${IMSISTING_BANNER_ART:-$IMSISTING_ROOT/assets/banner.ans}"
    local -a _ART=()
    if [[ -r "$_asset" ]]; then
        while IFS= read -r _l || [[ -n "$_l" ]]; do _ART+=("$_l"); done < "$_asset"
    else
        _ART=(
            '          \|      |/'
            '           \      /'
            '            \    /'
            '         ____\__/____'
            '        /            \'
            '       /   ________   \'
            '      /   /        \   \'
            '     /   /  > scan  \   \'
            '    /   /____________\   \'
            '   /______________________\'
            '  |  []  []  []  []  []  []|'
            '  |________________________|'
            '  |  |                  |  |'
            '  |__|__________________|__|'
        )
    fi
    # visible width of the art (strip SGR sequences so colour is not counted)
    local _aw=0 _bare
    for _l in "${_ART[@]}"; do
        _bare=$(printf '%s' "$_l" | sed 's/\x1b\[[0-9;]*m//g')
        (( ${#_bare} > _aw )) && _aw=${#_bare}
    done

    if (( w >= _lw + _aw + 4 )); then
        local _rows=${#_LOGO[@]} _pad
        (( ${#_ART[@]} > _rows )) && _rows=${#_ART[@]}
        for (( _i = 0; _i < _rows; _i++ )); do
            _l="${_LOGO[_i]:-}"
            printf -v _pad '%*s' "$(( _lw - ${#_l} ))" ""
            printf '  %s%s%s%s  %s\n' \
                "${_GC[_i % ${#_GC[@]}]}" "$_l" "$_pad" "$C_RESET" "${_ART[_i]:-}"
        done
    else
        for (( _i = 0; _i < ${#_LOGO[@]}; _i++ )); do
            printf '  %s%s%s\n' "${_GC[_i % ${#_GC[@]}]}" "${_LOGO[_i]}" "$C_RESET"
        done
        printf '\n'
        for (( _i = 0; _i < ${#_ART[@]}; _i++ )); do
            printf '  %s\n' "${_ART[_i]}"
        done
    fi

    printf '\n'
    printf '%s' "$C_PUR"
    printf '═%.0s' $(seq 1 "$w")
    printf '%s\n' "$C_RESET"

    printf '  %s%s» %scellular offensive toolkit %s// 2g · 3g · 4g · 5g %s// v%s %s// ysl%s\n' \
        "$C_CYN" "$C_BOLD" "$C_WHT" "$C_DIM" "$C_MAG" "$IMSISTING_VERSION" "$C_RESET"

    printf '%s' "$C_PUR"
    printf '─%.0s' $(seq 1 "$w")
    printf '%s\n' "$C_RESET"
}

# ── framed input prompt ─────────────────────────────────────
# A rounded input field drawn closed, like a modern CLI splash. The box is
# printed, the cursor is parked on the field, read() takes the line, and the
# field is then redrawn with the value and its closing border. It only ever
# moves the cursor within the three rows the box owns.
menu_prompt() {
    local _var="$1" _hint="${2:-}"
    local w; w=$(term_width)
    local inner=$(( w - 8 ))
    (( inner < ${#_hint} + 4 )) && inner=$(( ${#_hint} + 4 ))
    (( inner < 30 )) && inner=30
    local bar; bar=$(printf '─%.0s' $(seq 1 "$inner"))

    printf '  %s╭%s╮%s\n' "$C_PUR" "$bar" "$C_RESET"
    printf '  %s│%s > %s%-*s%s%s│%s\n' \
        "$C_PUR" "$C_RESET" "$C_DIM" "$(( inner - 3 ))" "$_hint" "$C_RESET" "$C_PUR" "$C_RESET"
    printf '  %s╰%s╯%s\n' "$C_PUR" "$bar" "$C_RESET"

    # park the cursor on the field and clear the placeholder
    printf '\e[2A\e[1G\e[2K'
    printf '  %s│%s > ' "$C_PUR" "$C_RESET"
    IFS= read -r "$_var"

    # redraw the field with the entered value and the closing border
    printf '\e[1A\e[1G\e[2K'
    local _val; printf -v _val '%s' "${!_var}"
    local _len=${#_val}
    local _rem=$(( inner - 3 - _len )); (( _rem < 0 )) && _rem=0
    printf '  %s│%s > %s%s%s%*s%s│%s' \
        "$C_PUR" "$C_RESET" "$C_BOLD$C_WHT" "$_val" "$C_RESET" \
        "$_rem" "" "$C_PUR" "$C_RESET"
    printf '\n\e[1B'
}

# ── menu primitives ─────────────────────────────────────────
menu_row() {
    local key="$1" label="$2" state="$3"
    local kcol="$C_ORG" lcol="$C_WHT" tag=""
    case "$state" in
        missing)
            kcol="$C_DIM"; lcol="$C_DIM"; tag=" ${C_YEL}[offline]${C_RESET}" ;;
    esac
    printf '   %s│%s %s[%s]%s  %s%s%s%s\n' \
        "$C_DIM" "$C_RESET" \
        "$kcol$C_BOLD" "$key" "$C_RESET" \
        "$lcol" "$label" "$C_RESET" "$tag"
}

section_header() {
    local title="$1"
    printf '\n   %s── %s%s%s %s───────────────────────────────%s\n' \
        "$C_PUR$C_BOLD" "$C_MAG" "$title" "$C_PUR$C_BOLD" "$C_DIM" "$C_RESET"
}

row_state() {
    declare -F "$1" >/dev/null 2>&1 && echo present || echo missing
}

fn_for_key() {
    local key="$1" row
    for row in "${IMSISTING_MODULE_TABLE[@]}"; do
        # Trailing _ absorbs the MODULE_ID field: `read` gives the LAST
        # variable the whole remainder, so without it f becomes
        # "fn_menu|00_mod" and declare -F never matches.
        IFS='|' read -r _ k _ f _ <<< "$row"
        [[ "$k" == "$key" ]] && { echo "$f"; return; }
    done
}

# ── root + module dir checks ────────────────────────────────
if [[ $EUID -ne 0 && "${IMSISTING_LIST:-0}" != "1" && "${IMSISTING_GUI:-0}" != "1" && "${IMSISTING_TUI:-0}" != "1" ]]; then
    if [[ ! -t 0 || ! -t 1 || "${TERM:-dumb}" == "dumb" ]]; then
        printf 'IMSIsting: interactive mode needs a terminal; try --list, --help, or --gui.\n' >&2
    else
        err "must run as root — try: sudo bash $0"
    fi
    exit 1
fi
if [[ $EUID -ne 0 && "${IMSISTING_GUI:-0}" == "1" ]]; then
    warn "GUI backend is not root; privileged module operations may fail"
fi

if [[ ! -d "$MODULES_DIR" ]]; then
    err "modules dir not found: $MODULES_DIR"
    (( IMSISTING_SOURCED )) && return 1 || exit 1
fi

info "loading modules from $MODULES_DIR"
shopt -s nullglob
MODULE_FILES=("$MODULES_DIR"/*.sh)
shopt -u nullglob

if [[ ${#MODULE_FILES[@]} -eq 0 ]]; then
    err "no .sh files in $MODULES_DIR"
    (( IMSISTING_SOURCED )) && return 1 || exit 1
fi

for mod in "${MODULE_FILES[@]}"; do
    if ! bash -n "$mod" 2>/dev/null; then
        err "syntax error in $(basename "$mod") — skipping"
        continue
    fi

    # Some modules call `exit` at top level. Sourcing such a file would
    # kill this shell mid-loop. Shadow the exit builtin for the duration
    # of the source, then unshadow.
    _prev_exit_fn=$(declare -f exit 2>/dev/null || true)
    exit() { return "${1:-0}"; }

    if source "$mod" 2>>"$SESSION_LOG"; then
        ok "loaded: $(basename "$mod")"
    else
        err "runtime error in $(basename "$mod")"
    fi

    unset -f exit
    if [[ -n "$_prev_exit_fn" ]]; then
        eval "$_prev_exit_fn"
        unset _prev_exit_fn
    fi
done

# ── --list ──────────────────────────────────────────────────
if (( IMSISTING_LIST )) && (( ! IMSISTING_SOURCED )) && [[ "${IMSISTING_TUI:-0}" != "1" ]]; then
    printf '\nimsisting — installed modules\n\n'
    local_cat=""
    for row in "${IMSISTING_MODULE_TABLE[@]}"; do
        IFS='|' read -r cat key label fn _ <<< "$row"
        if [[ "$cat" != "$local_cat" ]]; then
            printf '  %s%s%s\n' "$C_MAG" "$cat" "$C_RESET"
            local_cat="$cat"
        fi
        if declare -F "$fn" >/dev/null 2>&1; then
            printf '    [%s] %-28s %s✓%s\n' "$key" "$label" "$C_GRN" "$C_RESET"
        else
            printf '    [%s] %-28s %s✗%s\n' "$key" "$label" "$C_DIM" "$C_RESET"
        fi
    done
    echo
    exit 0
fi

# ── cleanup (standalone only) ──────────────────────────────
cleanup() {
    show_cursor
    info "cleaning up radio state..."
    for daemon in grgsm_livemon srsenb srsepc gnb nr-uesoftmodem; do
        pkill -f "$daemon" 2>/dev/null
    done
    ok "system restored. goodbye."
}
if (( ! IMSISTING_SOURCED )) && [[ "${IMSISTING_GUI:-0}" != "1" ]]; then
    trap cleanup EXIT TERM
fi

# ── main menu ───────────────────────────────────────────────
# Is a GUI already up ON THIS DISPLAY?
#
# The plain `pgrep -x imsisting-gui` test that used to live here was blind to
# the display, so any instance anywhere - a screenshot run on a virtual X
# server, a second session, a window left open on another monitor's DISPLAY -
# made every later launch print "already running" and do nothing. The symptom
# the operator sees is a GUI that will not start, with no error to explain it.
gui_running_here() {
    local pid d want="${DISPLAY:-}"

    for pid in $(pgrep -x imsisting-gui 2>/dev/null); do
        d=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null |
            sed -n 's/^DISPLAY=//p' | head -1)
        [[ -z "$d" ]] && d="$want"
        if [[ "$d" == "$want" ]]; then
            printf '%s' "$pid"
            return 0
        fi
    done
    return 1
}

launch_gui() {
    local running
    if ! running=$(gui_running_here); then
        local bin="$IMSISTING_ROOT/native/builddir/imsisting-gui"
        [[ -x "$bin" ]] || bin="$IMSISTING_ROOT/native/build/imsisting-gui"
        if [[ ! -x "$bin" ]]; then
            err "GUI not built — run: meson setup native/builddir native && ninja -C native/builddir"
            sleep 2
            return 1
        fi
        info "launching imsisting-gui..."
        nohup "$bin" >/dev/null 2>&1 &
        sleep 1
    else
        info "imsisting-gui is already running on this display (pid $running)"
        sleep 1
    fi
}

main_menu() {
    while true; do
        banner
        echo

        local_cat=""
        for row in "${IMSISTING_MODULE_TABLE[@]}"; do
            IFS='|' read -r cat key label fn _ <<< "$row"
            if [[ "$cat" != "$local_cat" ]]; then
                section_header "$cat"
                local_cat="$cat"
            fi
            menu_row "$key" "$label" "$(row_state "$fn")"
        done

        echo
        printf '   %s│%s\n' "$C_DIM" "$C_RESET"
        printf '   %s│%s  %s[h]%s help   %s[c]%s clear   %s[g]%s gui   %s[q]%s quit\n' \
            "$C_DIM" "$C_RESET" \
            "$C_ORG$C_BOLD" "$C_RESET" \
            "$C_ORG$C_BOLD" "$C_RESET" \
            "$C_ORG$C_BOLD" "$C_RESET" \
            "$C_RED$C_BOLD" "$C_RESET"

        echo
        printf '   %s└─%s▶%s %s · %ssession:%s %s\n' \
            "$C_PUR" "$C_MAG" "$C_RESET" \
            "$(date +%H:%M:%S)" "$C_DIM" "$C_RESET" \
            "$(basename "$SESSION_LOG")"
        echo

        show_cursor
        local choice
        menu_prompt choice 'enter a module key · [h]elp · [c]lear · [g]ui · [q]uit'
        hide_cursor

        local norm="${choice#0}"
        [[ -z "$norm" ]] && norm="$choice"

        case "$choice" in
            q|Q) show_cursor; info "bye"; exit 0 ;;
            h|H)
                clear
                cat << HELP
imsisting CLI — help
────────────────────

  Modules are grouped by generation. Type the two-digit key to launch.
  Modules marked [offline] failed to load — check logs/session_*.log.

  Keys:
    [01]-[23]   launch module
    [h]         this help
    [c]         clear screen
    [g]         launch the GUI (native/builddir/imsisting-gui)
    [q]         quit

  Every module has its own menu. Type '0' inside to return here.

  Session log:  logs/session_<date>_<pid>.log
  Project root: ${IMSISTING_ROOT:-\$HOME/IMSIsting}
  Press enter to return.
HELP
                read -r _
                ;;
            c|C) : ;;
            g|G) launch_gui ;;
            *)
                local fn
                fn=$(fn_for_key "$choice")
                [[ -z "$fn" ]] && fn=$(fn_for_key "$norm")

                if [[ -n "$fn" ]] && declare -F "$fn" >/dev/null 2>&1; then
                    "$fn"
                elif [[ -n "$fn" ]]; then
                    warn "module $choice failed to load — check $SESSION_LOG"
                    sleep 1
                else
                    warn "invalid selection: $choice"
                    sleep 0.5
                fi
                ;;
        esac
    done
}

# ── entry ───────────────────────────────────────────────────
# Don't leave a false conditional as the final sourced command — the
# GUI sources this file then invokes a module function; a status of 1
# here would prevent the caller's `&&` from firing.
if (( ! IMSISTING_SOURCED )) && [[ "${IMSISTING_GUI:-0}" != "1" && "${IMSISTING_TUI:-0}" != "1" ]]; then
    main_menu
fi
if (( ! IMSISTING_SOURCED )) && [[ "${IMSISTING_GUI:-0}" == "1" ]]; then
    launch_gui
fi
if (( ! IMSISTING_SOURCED )) && [[ "${IMSISTING_TUI:-0}" == "1" ]]; then
    exec python3 "$SCRIPT_DIR/tools/imsisting_tui.py" --root "$SCRIPT_DIR"
fi

true
