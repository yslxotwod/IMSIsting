#!/usr/bin/env bash
# stk — SIM Toolkit proactive commands (TS 31.111).
#
# The SIM Toolkit lets a SIM drive the handset: show a menu, send an SMS, set up
# a call, launch a browser, open a data channel. Each instruction is a proactive
# command built from COMPREHENSION-TLVs and wrapped in a tag-0xD0 envelope. That
# authority is why an STK command with no user confirmation is a security event.
# This module builds, decodes and audits proactive commands. 16_sim handles the
# APDU and OTA layers; this is the command layer above them.
#
# Attack owned: O5/O12 adjacency (SIM-driven actions) — codec and audit half.
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
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

MOD_TMP="$TMP_DIR/stk"
STK_DIR="$LOOT_DIR/stk"
mkdir -p "$MOD_TMP" "$STK_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

stk_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
STK_F=()
stk_split() {
    STK_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        STK_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
stk_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
stk_is_hex() {
    local h; h=$(stk_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
stk_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }

stk_status_tsv() {
    printf 'MODULE\tstk\n'
    printf 'TARGET\tTS 31.111 proactive commands (D0 envelope, COMPREHENSION-TLVs)\n'
    printf 'TRANSMIT\tnone — construction, decode and audit; delivery is a handoff\n'
    printf 'SELFTEST\tyes\n'
}

# ── command and device tables (TS 31.111 §9.4, §8.7) ────────────────────
stk_cmd_name() {
    case "$1" in
        01) echo "REFRESH" ;;
        02) echo "MORE TIME" ;;
        03) echo "POLL INTERVAL" ;;
        04) echo "POLLING OFF" ;;
        05) echo "PROVIDE LOCAL INFORMATION" ;;
        10) echo "SET UP CALL" ;;
        11) echo "SEND SS" ;;
        12) echo "SEND USSD" ;;
        13) echo "SEND SHORT MESSAGE" ;;
        14) echo "SEND DTMF" ;;
        15) echo "LAUNCH BROWSER" ;;
        16) echo "GEOGRAPHICAL LOCATION REQUEST" ;;
        20) echo "PLAY TONE" ;;
        21) echo "DISPLAY TEXT" ;;
        22) echo "GET INKEY" ;;
        23) echo "GET INPUT" ;;
        24) echo "SELECT ITEM" ;;
        25) echo "SET UP MENU" ;;
        27) echo "TIMER MANAGEMENT" ;;
        28) echo "SET UP IDLE MODE TEXT" ;;
        30) echo "PERFORM CARD APDU" ;;
        31) echo "POWER OFF CARD" ;;
        32) echo "POWER ON CARD" ;;
        33) echo "GET READER STATUS" ;;
        34) echo "RUN AT" ;;
        40) echo "OPEN CHANNEL" ;;
        41) echo "CLOSE CHANNEL" ;;
        42) echo "RECEIVE DATA" ;;
        43) echo "SEND DATA" ;;
        44) echo "GET CHANNEL STATUS" ;;
        45) echo "SERVICE SEARCH" ;;
        46) echo "GET SERVICE INFORMATION" ;;
        47) echo "DECLARE SERVICE" ;;
        50) echo "SET FRAMING" ;;
        51) echo "GET FRAMING" ;;
        60) echo "RETRIEVE MULTIMEDIA MESSAGE" ;;
        61) echo "SUBMIT MULTIMEDIA MESSAGE" ;;
        *) echo "unknown proactive command" ;;
    esac
}
stk_device_name() {
    case "$1" in
        01) echo "KEYPAD" ;;
        02) echo "DISPLAY" ;;
        03) echo "EARPIECE" ;;
        04) echo "CARD READER" ;;
        05) echo "TERMINAL" ;;
        06) echo "NETWORK" ;;
        81) echo "UICC/SIM" ;;
        82) echo "ME/terminal" ;;
        *) echo "unknown device" ;;
    esac
}
stk_result_name() {
    case "$1" in
        00) echo "command performed successfully" ;;
        20) echo "user did not accept" ;;
        21) echo "user cleared" ;;
        23) echo "no response from the user" ;;
        24) echo "help information required" ;;
        30) echo "SS/USSD transaction terminated by the user" ;;
        35) echo "command beyond the ME's capability" ;;
        36) echo "command type not understood" ;;
        37) echo "command data not understood" ;;
        38) echo "command number not known" ;;
        39) echo "SS return error" ;;
        3A) echo "SMS RP-ERROR" ;;
        *) echo "unknown result code" ;;
    esac
}

# ── COMPREHENSION-TLV codec ─────────────────────────────────────────────
stk_tlv_len() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be numeric\n' >&2; return 2; }
    (( n <= 127 )) && { printf '%02X' "$(( n & 0xFF ))"; return 0; }
    if (( n <= 0xFF )); then printf '81%02X' "$(( n & 0xFF ))"
    else printf '82%04X' "$(( n & 0xFFFF ))"; fi
}
stk_tlv() {
    local tag="${1:-}" value; value=$(stk_norm_hex "${2:-}")
    stk_is_hex "$value" || { printf 'ERROR\tTLV value must be hex\n' >&2; return 2; }
    printf '%s%s%s' "$tag" "$(stk_tlv_len "$(( ${#value}/2 ))")" "$value"
}

# ── proactive command build / parse (tag 0xD0) ──────────────────────────
# TS 31.111 6.4.4 (Command Details, TS 102 223 8.6): the value is three octets
# -- command number, type of command, command qualifier. This used to write the
# type, the qualifier and a zero, which put the type where the command number
# belongs: a card reading it saw the command number as the type and the type as
# the qualifier, so a SET UP CALL arrived as whatever 0x10 means to the card and
# an 0x00 qualifier. The command number is the last argument so existing calls
# still build the command they name.
stk_proactive_build() {
    local type="${1:-21}" qualifier="${2:-00}" src="${3:-81}" dst="${4:-82}" number="${5:-01}"
    [[ "$type" =~ ^[0-9A-Fa-f]{2}$ && "$qualifier" =~ ^[0-9A-Fa-f]{2}$ ]] || {
        printf 'ERROR\tcommand type and qualifier must be one octet each\n' >&2; return 2; }
    [[ "$number" =~ ^[0-9A-Fa-f]{2}$ && "$number" != "00" ]] || {
        printf 'ERROR\tcommand number must be one non-zero octet of hex\n' >&2; return 2; }
    local cd di
    cd=$(stk_tlv 01 "${number}${type}${qualifier}")
    di=$(stk_tlv 02 "${src}${dst}")
    local body="${cd}${di}"
    printf 'D0%s%s\n' "$(stk_tlv_len "$(( ${#body}/2 ))")" "$body"
}
stk_proactive_parse() {
    local h; h=$(stk_norm_hex "${1:-}")
    stk_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    [[ "${h:0:2}" == "d0" ]] || { printf 'ERROR\tnot a proactive command (first tag must be D0)\n' >&2; return 1; }
    local len=$(( 16#${h:2:2} )) off=2
    if (( len > 127 )); then
        local n=$(( len & 0x7F ))
        len=$(( 16#${h:4:$((n*2))} )); off=$(( 2 + n ))
    fi
    printf 'envelope\tD0\nbody_len\t%d\n' "$len"
    local number="" cmd_type="" qualifier="" src="" dst=""
    printf 'tag\tlength\tvalue\n'
    local guard=0
    while (( off*2 < ${#h} )); do
        (( guard++ > 64 )) && { printf 'ERROR\ttoo many sub-TLVs\n' >&2; return 1; }
        local tag="${h:$((off*2)):2}"; off=$(( off + 1 ))
        local l=$(( 16#${h:$((off*2)):2} )); off=$(( off + 1 ))
        if (( l > 127 )); then
            local k=$(( l & 0x7F )); l=$(( 16#${h:$((off*2)):$((k*2))} )); off=$(( off + k ))
        fi
        local val="${h:$((off*2)):$((l*2))}"; off=$(( off + l ))
        printf '%s\t%d\t%s\n' "$tag" "$l" "$val"
        # 0x81/0x82 are the same information elements with the comprehension-
        # required bit set (TS 102 223 8.1), which is the form cards normally
        # send, so both are read.
        if [[ "$tag" == "01" || "$tag" == "81" ]]; then
            number="${val:0:2}"; cmd_type="${val:2:2}"; qualifier="${val:4:2}"
        elif [[ "$tag" == "02" || "$tag" == "82" ]]; then
            src="${val:0:2}"; dst="${val:2:2}"
        fi
    done
    printf 'command_number\t%s\ncmd_type\t%s\ncmd_name\t%s\nqualifier\t%s\n' \
        "$number" "$cmd_type" "$(stk_cmd_name "$cmd_type")" "$qualifier"
    printf 'source\t%s\nsource_name\t%s\ndestination\t%s\ndestination_name\t%s\n' \
        "$src" "$(stk_device_name "$src")" "$dst" "$(stk_device_name "$dst")"
}

# ── audit: proactive commands that act without the user ─────────────────
# Input TSV: type<TAB>qualifier<TAB>user_confirm. High-risk commands that the
# SIM issues are the ones that leave the handset (SMS, SS, USSD, call, browser,
# open channel). When user_confirm is false the action is silent.
stk_audit() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such command log: %s\n' "$file" >&2; return 1; }
    printf 'type\tname\tuser_confirm\tverdict\n'
    local line risky=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == type* || "$line" == \#* ]] && continue
        stk_split "$line"
        local t="${STK_F[0]:-}" q="${STK_F[1]:-}" uc="${STK_F[2]:-}"
        local name verdict="ok"
        name=$(stk_cmd_name "$t")
        case "$t" in
            10|11|12|13|15|30|40|43|60|61)
                if [[ "$uc" =~ ^(false|no|0)$ ]]; then
                    verdict="HIGH — acts off-device with no user confirmation"
                    risky=$(( risky + 1 ))
                else
                    verdict="off-device action, user-confirmed"
                fi ;;
            21|22|23|24|25)
                verdict="UI command" ;;
            *) verdict="other" ;;
        esac
        printf '%s\t%s\t%s\t%s\n' "$(stk_sanitize "$t")" "$(stk_sanitize "$name")" "$(stk_sanitize "$uc")" "$verdict"
    done < "$file"
    printf 'summary\tsilent_offdevice\t%d\n' "$risky"
}

stk_plan() {
    cat <<'EOF'
status	handoff
what	delivering a proactive command, or capturing the SIM-ME interface
hardware	a programmable SIM you own (sysmoISIM-SJA2), plus a SIMtrace2 or a rooted handset to observe the T=0 link
software	pySim with STK support, SIMtrace2 firmware, and the TS 31.111 command set
flow	1. build a command here with --build  2. capture the SIM-ME APDU exchange  3. --audit the command log
note	a live subscriber's SIM needs their keys and authorisation; this module works on your own SIM and on captures
EOF
}

# ── S@T / WIB / Simjacker (AdaptiveMobile, 2019) ────────────────────────
stk_sat_cmds() {
    cat <<'EOF'
command	effect	risk
provideLocalInformation	returns cell id and location	location tracking
sendShortMessage	sends an SMS from the SIM	premium SMS and fraud
setupCall	places a voice call	call fraud and eavesdrop setup
sendDTMF	sends DTMF tones	IVR and interactive abuse
sendUSSD	sends a USSD string	subscriber steering
launchBrowser	opens a URL	drive-by and phishing
EOF
}
# Detect the S@T / WIB applet from a SIM application identifier (AID hex) or a
# name. S@T carries the ASCII bytes 53 40 54; WIB carries 57 49 42.
stk_sat_audit() {
    local in="${1:-}"
    [[ -n "$in" ]] || { printf 'ERROR\tusage: --sat-audit <aid_hex|name>\n' >&2; return 2; }
    local h lower sat=no wib=no
    h=$(printf '%s' "$in" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
    lower=$(printf '%s' "$in" | tr 'A-Z' 'a-z')
    if [[ "$h" =~ ^[0-9a-f]+$ ]]; then
        [[ "$h" == *534054* ]] && sat=yes     # "S@T"
        [[ "$h" == *574942* ]] && wib=yes     # "WIB"
    fi
    [[ "$lower" == *"s@t"* ]] && sat=yes
    [[ "$lower" == *wib* ]] && wib=yes
    printf 'sat_present\t%s\nwib_present\t%s\n' "$sat" "$wib"
    [[ "$sat" == yes ]] && {
        printf 'finding\tHIGH\tS@T browser applet present — a binary SMS invokes its command set with no user interaction (Simjacker)\n'
        printf 'surface\tthe S@T command set is reachable over the air; see --sat-cmds\n'
    }
    [[ "$wib" == yes ]] && printf 'finding\tHIGH\tWIB applet present — the same class of over-the-air command dispatch\n'
    [[ "$sat" == no && "$wib" == no ]] && printf 'finding\tINFO\tno S@T or WIB applet marker in the input\n'
    return 0
}
# Simjacker fingerprint: a binary (8-bit) SMS carrying the SIM data-download
# TP-PID (0x7F) — the transport the S@T/WIB command rides. An optional payload
# opening with D0 is a proactive envelope.
stk_simjacker_detect() {
    local pid="${1:-}" dcs="${2:-}" payload
    payload=$(printf '%s' "${3:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
    [[ "$pid" =~ ^[0-9A-Fa-f]{1,2}$ && "$dcs" =~ ^[0-9A-Fa-f]{1,2}$ ]] || {
        printf 'ERROR\tusage: --simjacker-detect <pid_hex> <dcs_hex> [payload_hex]\n' >&2; return 2; }
    local p=$(( 16#$pid )) d=$(( 16#$dcs )) binary=no
    case "$(( d & 0xF0 ))" in
        0|4|8|12|16|20|24|28|192) binary=yes ;;
    esac
    printf 'pid\t0x%02X\npid_meaning\t%s\ndcs\t0x%02X\nbinary\t%s\n' \
        "$p" "$([[ $p -eq 0x7f ]] && echo "SIM data download (toolkit)" || echo "non-toolkit")" "$d" "$binary"
    local n=0
    if (( p == 0x7f )); then
        printf 'finding\tHIGH\tTP-PID 0x7F: a SIM data-download SMS — the transport a Simjacker/WIB payload rides\n'; n=$(( n + 1 ))
    fi
    if (( p == 0x7f )) && [[ "$binary" == yes ]]; then
        printf 'finding\tCRITICAL\tbinary toolkit SMS with a SIM data-download PID — Simjacker/WIB fingerprint\n'; n=$(( n + 1 ))
    fi
    [[ -n "$payload" && "$payload" == d0* ]] && printf 'note\tINFO\tpayload opens a D0 proactive envelope; decode it with --parse\n'
    (( n == 0 )) && printf 'finding\tINFO\tno toolkit-SMS fingerprint\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

# ── RUN AT: the proactive command that hands the modem a string ─────────
# TS 31.111 6.4.12 defines a proactive command whose payload is not data the
# card composes but a command the card asks the terminal to execute in its own
# AT parser: RUN AT, type of command 0x34. The tree carried the whole SAT
# envelope and forty command types and not this one, so `stk_cmd_name 34`
# printed "unknown proactive command" and nothing could carry an AT string.
#
# What the terminal does with it is a property of the terminal. The published
# CATANA work (CVE-2025-48618, CVE-2026-57550) found compliant implementations
# that hand a modem a chain of AT commands, and the consequences are the ones
# this verb classifies rather than performs: a radio-access-technology change
# that drops a device to 2G, an identifier readout, a shutdown, and on recent
# Android a browser launch with no user interaction. The root cause is
# delegation of trust, which is why the useful artefact is the envelope plus
# an acceptance harness, not an exploit.
stk_run_at_build() {   # <at-command-string> | --raw-hex HEX
    local value="${1:-}"
    [[ -n "$value" ]] || {
        printf 'ERROR\tusage: --run-at-build "<AT command>" | --run-at-build --raw-hex HEX\n' >&2
        printf 'WHY\tthe AT command travels as an octet string in the command, and an empty one is a command with no payload\n' >&2
        return 2; }
    local arg_hex="" qualifier="00" number="${STK_AT_NUMBER:-01}" text=""
    if [[ "$value" == "--raw-hex" ]]; then
        arg_hex=$(stk_norm_hex "${2:-}")
        [[ "$arg_hex" =~ ^[0-9a-f]+$ ]] && (( ${#arg_hex} % 2 == 0 )) && [[ -n "$arg_hex" ]] || {
            printf 'ERROR\t--raw-hex wants an even, non-empty run of hex digits\n' >&2; return 2; }
    else
        text="$value"
        arg_hex=$(printf '%s' "$value" | od -An -tx1 | tr -d ' \n')
    fi
    (( ${#arg_hex} / 2 <= 239 )) || {
        printf 'ERROR\tthe AT command is %d octets; a short TLV carries at most 239\n' "$(( ${#arg_hex} / 2 ))" >&2; return 2; }
    # Command Details: command number, type 0x34, qualifier (0 = the terminal
    # decides how to run it, which is the whole complaint).
    local cd di at body
    cd=$(stk_tlv 01 "${number}34${qualifier}")
    di=$(stk_tlv 02 "${STK_AT_SRC:-81}${STK_AT_DST:-82}")
    # TS 31.111 8.7: the AT command is carried in a TLV whose tag is 0x30.
    at=$(stk_tlv 30 "$arg_hex")
    body="${cd}${di}${at}"
    local cmd="D0$(stk_tlv_len "$(( ${#body}/2 ))")${body}"
    printf 'command\t%s\n' "$cmd"
    printf 'command_type\t34\n'
    printf 'command_name\tRUN AT\n'
    printf 'command_number\t%s\n' "$number"
    printf 'qualifier\t%s\n' "$qualifier"
    printf 'at_octets\t%d\n' "$(( ${#arg_hex} / 2 ))"
    printf 'at_hex\t%s\n' "$(printf '%s' "$arg_hex" | tr 'a-f' 'A-F')"
    printf 'at_text\t%s\n' "$(stk_sanitize "$text")"
    printf 'envelope\tD0 (proactive command), terminal response is R9 (Terminal Response) after the modem acts\n'
    printf 'ref\tTS 31.111 6.4.12 (RUN AT), 8.7 (AT command TLV 0x30), TS 102 223 8.6 (Command Details)\n'
    printf 'limit\tthe command is a request: what the terminal does with the string is the terminal behaviour the audit below classifies, and no modem is driven here\n'
    printf 'verdict\trun_at_built\n'
}

stk_run_at_audit() {   # <at-command-string> [--rat 5g|4g|3g|2g]
    local cmdline="${1:-}" rat="5g"
    [[ -n "$cmdline" ]] || {
        printf 'ERROR\tusage: --run-at-audit "AT+..." [--rat 5g|4g|3g|2g]\n' >&2; return 2; }
    shift
    while (($#)); do
        case "$1" in
            --rat) rat="${2:-5g}"; shift 2 ;;
            *) printf 'ERROR\tunknown option %s\n' "$(stk_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    case "$rat" in 5g|4g|3g|2g) ;; *)
        printf 'ERROR\t--rat is 5g, 4g, 3g or 2g\n' >&2; return 2 ;; esac
    local lower; lower=$(printf '%s' "$cmdline" | tr 'A-Z' 'a-z')
    local cls="none" effect="nothing this module models" severity="INFO" why=""
    local chained="no"; case "$cmdline" in *";"*) chained="yes" ;; esac
    case "$lower" in
        *cops*|*creg*|*ctzu*|*cgdcont*|*cesq*|*ws46*)
            cls="rat_or_service_change"; severity="HIGH"
            effect="the modem is told which radio or which bearer to use: a 5G device can be walked down to 2G, which needs no memory bug to break confidentiality"
            why="the AT surface exposes the same radio controls the card asks for, and a downgrade is a legitimate command" ;;
        *cgsn*|*cimi*|*cgmi*|*cgmm*|*csim*|*crsm*|*iced*)
            cls="identifier_or_file_readout"; severity="HIGH"
            effect="serial, model, IMSI or the card's own files are read out through the modem, so the card can learn the handset it is in"
            why="the card is allowed to ask for local information, and a modem answers the same identifiers the handset prints" ;;
        *cfun*0*|*cfun=1,1*|*cpwroff*|*poweroff*)
            cls="shutdown_or_reset"; severity="MEDIUM"
            effect="the modem is switched off or reset: a cellular kill, and on a device it is reachable from, a reboot loop"
            why="power control is a normal AT command and the card may not distinguish asking from acting" ;;
        *action=android.intent.action.view*|*http*|*ucmd*)
            cls="browser_launch_or_uri"; severity="HIGH"
            effect="the terminal is asked to open a URI; published implementations have launched a browser with no user interaction"
            why="the chain of commands that reaches the application processor is spec-compliant" ;;
        *)
            if [[ "$chained" == "yes" ]]; then
                cls="at_chain"; severity="MEDIUM"
                effect="a second AT command follows the first in the same string: a chain is the primitive every one of the above needs"
                why="one proactive command carries one string, and the modem parser treats the separators as them"
            fi ;;
    esac
    printf 'at_text\t%s\n' "$(stk_sanitize "$cmdline")"
    printf 'at_class\t%s\n' "$cls"
    printf 'rat\t%s\n' "$rat"
    printf 'device_effect\t%s\n' "$effect"
    printf 'why_compliant\t%s\n' "$why"
    printf 'severity\t%s\n' "$severity"
    # A chain carries the specific classes: it is reported as the shape that
    # makes them composable, after the class the first command in it names.
    if [[ "$chained" == "yes" && "$cls" != "at_chain" && "$cls" != "none" ]]; then
        printf 'chained\t%s\toctets\t%s\n' "$cls" "$(( ${#cmdline} ))"
    fi
    if [[ "$cls" != "none" ]]; then
        printf 'finding\t%s\t%s\t%s\n' "$cls" "$severity" "the modem executes what the card asks, which is what the specification requires"
    fi
    printf 'acceptance\ta harness: send the envelope, read the Terminal Response and the modem-side effect, and record both; without a device the class above is what can be stated\n'
    printf 'detect\t%s\n' "eDRX/paging anomalies, an unexpected RAT change while the card session is active, an AT-initiated reboot in the modem log"
    printf 'ref\tTS 31.111 6.4.12; published CATANA work (CVE-2025-48618, CVE-2026-57550)\n'
    printf 'verdict\t%s\n' "$([[ "$cls" == "none" ]] && echo at_command_not_modelled || echo at_command_classified)"
}

stk_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export STK_DIR="$d/loot/stk"
    mkdir -p "$STK_DIR"

    # 1. Command types (TS 31.111 §9.4).
    chk cmd-refresh "$(stk_cmd_name 01)" "REFRESH"
    chk cmd-setupcall "$(stk_cmd_name 10)" "SET UP CALL"
    chk cmd-ussd "$(stk_cmd_name 12)" "SEND USSD"
    chk cmd-sms "$(stk_cmd_name 13)" "SEND SHORT MESSAGE"
    chk cmd-browser "$(stk_cmd_name 15)" "LAUNCH BROWSER"
    chk cmd-display "$(stk_cmd_name 21)" "DISPLAY TEXT"
    chk cmd-opench "$(stk_cmd_name 40)" "OPEN CHANNEL"
    chk cmd-unknown "$(stk_cmd_name 99)" "unknown proactive command"

    # 2. Device identities (TS 31.111 §8.7).
    chk dev-keypad "$(stk_device_name 01)" "KEYPAD"
    chk dev-display "$(stk_device_name 02)" "DISPLAY"
    chk dev-terminal "$(stk_device_name 05)" "TERMINAL"
    chk dev-unknown "$(stk_device_name AA)" "unknown device"

    # 3. Result codes.
    chk res-ok "$(stk_result_name 00)" "command performed successfully"
    chk res-reject "$(stk_result_name 20)" "user did not accept"
    chk res-ussd "$(stk_result_name 30)" "SS/USSD transaction terminated by the user"

    # 4. Proactive command build/parse round-trip.
    local pkt; pkt=$(stk_proactive_build 21 00 81 82)
    chk build-envelope "${pkt:0:2}" "D0"
    local out; out=$(stk_proactive_parse "$pkt")
    chk parse-type "$(fld "$out" cmd_type)" "21"
    chk parse-name "$(fld "$out" cmd_name)" "DISPLAY TEXT"
    chk parse-src  "$(fld "$out" source)" "81"
    chk parse-dst  "$(fld "$out" destination)" "82"
    chk parse-alt  "$(fld "$(stk_proactive_parse "$(stk_proactive_build 13 00 81 82)")" cmd_name)" "SEND SHORT MESSAGE"
    # The Command Details value is command number, type, qualifier -- the order
    # pySim's CommandDetails struct declares (TS 102 223 8.6) -- so the built
    # octets after the tag and length are 01 21 00, not 21 00 00.
    chk build-cd-value "$(stk_proactive_build 21 00 81 82 | cut -c9-14)" "012100"
    chk build-cd-number "$(stk_proactive_build 10 00 81 82 07 | cut -c9-14)" "071000"
    chk parse-number "$(fld "$out" command_number)" "01"
    chk parse-cr-tag "$(fld "$(stk_proactive_parse D009810301100002028182)" cmd_name)" "SET UP CALL"
    chk parse-cr-number "$(fld "$(stk_proactive_parse D009810301100002028182)" command_number)" "01"
    chk build-bad-number "$(stk_proactive_build 21 00 81 82 00 >/dev/null 2>&1; echo $?)" "2"
    chk parse-badtag "$(stk_proactive_parse 9900 >/dev/null 2>&1; echo $?)" "1"
    chk parse-badhex "$(stk_proactive_parse zz >/dev/null 2>&1; echo $?)" "2"
    # TLV length helper: 127 -> one octet, 128 -> 81 80.
    chk tlv-len-127 "$(stk_tlv_len 127)" "7F"
    chk tlv-len-128 "$(stk_tlv_len 128)" "8180"

    # 5. Audit: a silent off-device action is flagged, UI and confirmed ones are not.
    printf 'type\tqualifier\tuser_confirm\n' > "$d/log.tsv"
    printf '13\t00\tfalse\n' >> "$d/log.tsv"
    printf '11\t00\ttrue\n' >> "$d/log.tsv"
    printf '21\t00\tfalse\n' >> "$d/log.tsv"
    out=$(stk_audit "$d/log.tsv")
    chk audit-silent "$(printf '%s\n' "$out" | awk -F'\t' '$1=="13"{print ($4 ~ /HIGH/)?"high":"no"}')" "high"
    chk audit-confirmed "$(printf '%s\n' "$out" | awk -F'\t' '$1=="11"{print ($4 ~ /user-confirmed/)?"yes":"no"}')" "yes"
    chk audit-ui "$(printf '%s\n' "$out" | awk -F'\t' '$1=="21"{print $4}')" "UI command"
    chk audit-count "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary"{print $3}')" "1"
    chk audit-missing "$(stk_audit "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 6. S@T / WIB / Simjacker (AdaptiveMobile, 2019).
    chk sat-cmds-count "$(stk_sat_cmds | tail -n +2 | wc -l | tr -d ' ')" "6"
    chk sat-cmd-loc "$(stk_sat_cmds | awk -F'\t' '$1=="provideLocalInformation"{print $3}')" "location tracking"
    out=$(stk_sat_audit a0000000534054ff)
    chk sat-present "$(fld "$out" sat_present)" "yes"
    chk sat-finding "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding"{print $2}')" "HIGH"
    out=$(stk_sat_audit a0000000112233)
    chk sat-absent "$(fld "$out" sat_present)" "no"
    out=$(stk_simjacker_detect 7f 04)
    chk simj-critical "$(printf '%s\n' "$out" | awk -F'\t' '$2=="CRITICAL"{print $2}')" "CRITICAL"
    chk simj-findings "$(fld "$out" findings)" "2"
    out=$(stk_simjacker_detect 00 00)
    chk simj-clean "$(fld "$out" findings)" "0"
    chk simj-bad "$(stk_simjacker_detect zz 00 >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    # ── RUN AT: the proactive command that was missing ─────────────────
    local ra rab raa
    chk runat-name        "$(stk_cmd_name 34)" "RUN AT"
    rab=$(stk_run_at_build "AT+COPS=0" 2>/dev/null)
    chk runat-hex         "$(printf '%s\n' "$rab" | awk -F'\t' '$1=="command"{print $2}')" "D014010301340002028182300941542b434f50533d30"
    chk runat-type        "$(printf '%s\n' "$rab" | awk -F'\t' '$1=="command_type"{print $2}')" "34"
    chk runat-name-row    "$(printf '%s\n' "$rab" | awk -F'\t' '$1=="command_name"{print $2}')" "RUN AT"
    chk runat-octets      "$(printf '%s\n' "$rab" | awk -F'\t' '$1=="at_octets"{print $2}')" "9"
    chk runat-text        "$(printf '%s\n' "$rab" | awk -F'\t' '$1=="at_text"{print $2}')" "AT+COPS=0"
    chk runat-tlv30       "$(printf '%s\n' "$rab" | awk -F'\t' '$1=="command" && $2 ~ /^D0[0-9A-F]*300941542b434f50533d30$/{print "has"}')" "has"
    chk runat-verdict     "$(printf '%s\n' "$rab" | awk -F'\t' '$1=="verdict"{print $2}')" "run_at_built"
    chk runat-raw         "$(stk_run_at_build --raw-hex 0d0a | awk -F'\t' '$1=="at_hex"{print $2}')" "0D0A"
    chk runat-raw-odd     "$(stk_run_at_build --raw-hex ABC >/dev/null 2>&1; echo $?)" "2"
    chk runat-noargs      "$(stk_run_at_build >/dev/null 2>&1; echo $?)" "2"
    raa=$(stk_run_at_audit "AT+COPS=1,2,26201" 2>/dev/null)
    chk runat-class-rat   "$(printf '%s\n' "$raa" | awk -F'\t' '$1=="at_class"{print $2}')" "rat_or_service_change"
    chk runat-sev         "$(printf '%s\n' "$raa" | awk -F'\t' '$1=="severity"{print $2}')" "HIGH"
    chk runat-finding     "$(printf '%s\n' "$raa" | awk -F'\t' '$1=="finding"{print $2}')" "rat_or_service_change"
    chk runat-class-id    "$(stk_run_at_audit "AT+CGSN" | awk -F'\t' '$1=="at_class"{print $2}')" "identifier_or_file_readout"
    chk runat-class-off   "$(stk_run_at_audit "AT+CFUN=0" | awk -F'\t' '$1=="at_class"{print $2}')" "shutdown_or_reset"
    chk runat-class-uri   "$(stk_run_at_audit "AT+UCMD=action=android.intent.action.VIEW" | awk -F'\t' '$1=="at_class"{print $2}')" "browser_launch_or_uri"
    chk runat-class-chain "$(stk_run_at_audit "AT+CGSN;AT+COPS=0" | awk -F'\t' '$1=="chained"{print "chained"}')" "chained"
    chk runat-none        "$(stk_run_at_audit "AT+IUNKNOWN" | awk -F'\t' '$1=="verdict"{print $2}')" "at_command_not_modelled"
    chk runat-bad-rat     "$(stk_run_at_audit "AT+CGSN" --rat 6g >/dev/null 2>&1; echo $?)" "2"
    chk runat-noargs-audit "$(stk_run_at_audit >/dev/null 2>&1; echo $?)" "2"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

stk_menu() {
    while true; do
        banner
        echo "  === SIM Toolkit (proactive commands) ==="
        echo
        cat <<'M'
  [1]  Command type reference
  [2]  Device identity reference
  [3]  Result code reference
  [4]  Build a proactive command
  [5]  Parse a proactive command
  [6]  Audit a command log
  [7]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) for t in 01 03 05 10 11 12 13 14 15 16 20 21 22 23 24 25 30 40 41 42 43 44; do printf '  %s\t%s\n' "$t" "$(stk_cmd_name "$t")"; done; read -rp "  enter " _ ;;
            2) for i in 01 02 03 04 05 06 81 82; do printf '  %s\t%s\n' "$i" "$(stk_device_name "$i")"; done; read -rp "  enter " _ ;;
            3) for r in 00 20 21 23 24 30 35 36 37; do printf '  %s\t%s\n' "$r" "$(stk_result_name "$r")"; done; read -rp "  enter " _ ;;
            4) read -rp "  type (hex)> " t; read -rp "  qualifier (hex)> " q; read -rp "  src (hex)> " s; read -rp "  dst (hex)> " dd
               stk_proactive_build "$t" "$q" "$s" "$dd"; read -rp "  enter " _ ;;
            5) read -rp "  hex> " h; stk_proactive_parse "$h"; read -rp "  enter " _ ;;
            6) read -rp "  command log> " p; stk_audit "$p"; read -rp "  enter " _ ;;
            7) stk_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

stk_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  stk_status_tsv ;;
        --cmd)         stk_cmd_name "${1:-}" ;;
        --device)      stk_device_name "${1:-}" ;;
        --result)      stk_result_name "${1:-}" ;;
        --build)       stk_proactive_build "${1:-21}" "${2:-00}" "${3:-81}" "${4:-82}" "${5:-01}" ;;
        --parse)       stk_proactive_parse "${1:-}" ;;
        --audit)       stk_audit "${1:-}" ;;
        --run-at-build) stk_run_at_build "$@" ;;
        --run-at-audit) stk_run_at_audit "$@" ;;
        --sat-cmds)    stk_sat_cmds ;;
        --sat-audit)   stk_sat_audit "${1:-}" ;;
        --simjacker-detect) stk_simjacker_detect "${1:-}" "${2:-}" "${3:-}" ;;
        --plan)        stk_plan ;;
        --selftest)    stk_selftest ;;
        --menu)        stk_menu ;;
        *)
            cat >&2 <<EOF
STK Attacks — TS 31.111 proactive command construction and audit

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --cmd <hex>               proactive command type name
  --device <hex>            device identity name
  --result <hex>            result code name
  --build <type> <qualifier> [src] [dst] [number]
                                     build a D0 proactive command; the number
                                     defaults to 01 and is the first octet of
                                     the Command Details value (TS 31.111 6.4.4)
  --parse <hex>             decode a proactive command
  --audit <log>             flag silent off-device commands
  --sat-cmds                the S@T command surface
  --sat-audit <aid|name>    S@T / WIB applet detection
  --simjacker-detect <pid> <dcs> [payload]   toolkit-SMS (Simjacker/WIB) fingerprint
  --plan                    SIM-ME handoff plan
  --selftest                verify codecs and the audit
  --menu                    interactive menu
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
    stk_cli_main "$@"
fi
