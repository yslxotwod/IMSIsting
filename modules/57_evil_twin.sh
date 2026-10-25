#!/usr/bin/env bash
# LTE/NR evil twin: a cell built from a recon row, a phone that attaches to it,
# and the record of what that phone handed over.
#
# The twin is a real base station (srsRAN 4G for LTE, srsRAN Project for NR)
# plus a real core (srsEPC, or Open5GS for NR). What makes it an evil twin is
# not the software: it is that the PLMN, the channel and the cell identity come
# from a cell somebody actually observed, so a phone that is camped there has
# no reason to look twice.
#
# Two ways to run it, and they do not produce the same thing:
#
#   contained  every peer address is 127.0.0.x, the radio is srsRAN's own
#              loopback device, and the UE is an srsue you own. This proves the
#              chain works and produces no air evidence at all, because
#              nothing went on the air.
#
#   --radiate  the radio section is rewritten to a real SDR that 01_radio
#              enumerated and reports as transmit-capable. The UE is then
#              whatever phone walks past. Evidence comes from two places: the
#              S1/N1 signalling on loopback (S1AP to the EPC or NGAP to the
#              AMF, which carries the NAS the phone sent us) and the eNB/gNB
#              log (which carries the RRC-level facts the NAS does not).
#
# Radiating is a licensed act and the responsibility is the operator's. This
# module therefore refuses to radiate by accident (a prepared twin records
# which radio it was prepared for, and a run refuses when the two disagree)
# but it does not ask for an approval flag to do what it was told to do.
#
# Exit codes follow the tree: 0 measured/built, 1 could not, 2 refused, 3 handoff.
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _et_src="${BASH_SOURCE[0]}"
    while [ -L "$_et_src" ]; do
        _et_dir="$(cd -P "$(dirname "$_et_src")" && pwd)"
        _et_tgt="$(readlink "$_et_src")"; [[ "$_et_tgt" != /* ]] && _et_tgt="$_et_dir/$_et_tgt"
        _et_src="$_et_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_et_src")/.." && pwd)"
fi
export IMSISTING_ROOT
ET_TWIN="${ET_TWIN_DIR:-${LOOT_DIR:-$IMSISTING_ROOT/loot}/evil-twin}"
# The store is resolved per call, not per load: ET_TWIN_DIR is how a caller
# (or the selftest) points the evidence somewhere other than the real loot.
et_store_dir() { printf '%s\n' "${ET_TWIN_DIR:-${LOOT_DIR:-$IMSISTING_ROOT/loot}/evil-twin}"; }
et_evidence_path() { printf '%s/evidence.tsv\n' "$(et_store_dir)"; }
et_error() { printf 'ERROR\t%s\n' "$*" >&2; }
et_why() { printf 'WHY\t%s\n' "$*" >&2; }
et_safe_path() {
    local p="${1:-}" real root
    [[ -n "$p" && "$p" != / && "$p" != "$HOME" ]] || return 1
    real=$(realpath -m -- "$p" 2>/dev/null) || return 1
    root=$(realpath -m -- "$IMSISTING_ROOT" 2>/dev/null) || return 1
    [[ "$real" != "$root" && "$real" != "$root/" && "$real" != "$root/.." ]]
}
et_load_lte() {
    [[ -r "$IMSISTING_ROOT/modules/10_lte_air.sh" ]] || { et_error 'missing LTE config generator'; return 1; }
    # shellcheck disable=SC1091
    source "$IMSISTING_ROOT/modules/10_lte_air.sh"
}
et_load_nr() {
    [[ -r "$IMSISTING_ROOT/modules/12_nr_air.sh" ]] || { et_error 'missing NR config generator'; return 1; }
    # shellcheck disable=SC1091
    source "$IMSISTING_ROOT/modules/12_nr_air.sh"
}
et_load_radio() {
    [[ -r "$IMSISTING_ROOT/modules/01_radio.sh" ]] || {
        et_error 'missing 01_radio.sh; without it the twin has no antenna to point at'
        return 1
    }
    # shellcheck disable=SC1091
    source "$IMSISTING_ROOT/modules/01_radio.sh"
}

# ── the antenna ─────────────────────────────────────────────────────────
# A roster row is driver, serial, range, rates, gains, direction. Only rows the
# radio module calls transmit-capable are eligible: a receive-only stick
# prepared as a twin produces a config that radiates nothing, which is the
# fabricated-success shape this tree refuses.
et_radio_rows() {
    if [[ -n "${ET_RADIO_ROWS:-}" && -r "${ET_RADIO_ROWS}" ]]; then
        cat "$ET_RADIO_ROWS"            # test hook: a roster without hardware
        return 0
    fi
    et_load_radio || return 1
    radio_roster 5
}
et_radio_pick() {
    local want="${1:-}" row drv sn dir seen=0
    et_radio_rows > /tmp/.et_roster.$$ 2>/dev/null || { et_error 'cannot enumerate radios'; return 2; }
    while IFS= read -r row; do
        [[ -n "$row" ]] || continue
        drv="$(printf '%s\n' "$row" | cut -f1)"
        sn="$(printf '%s\n' "$row" | cut -f2)"
        dir="$(printf '%s\n' "$row" | cut -f9)"
        [[ "$dir" == *TX* ]] || continue
        seen=$((seen + 1))
        if [[ -z "$want" || "$want" == "$drv" || "$want" == "$sn" ]]; then
            printf '%s\n' "$row"; rm -f "/tmp/.et_roster.$$"; return 0
        fi
    done < "/tmp/.et_roster.$$"
    if (( seen == 0 )); then
        et_error 'no transmit-capable radio'
        et_why 'an evil twin is a transmitter: a receive-only stick, or no stick at all, cannot be one. Attach a radio 01_radio reports as TX, or stay contained without --radiate.'
        rm -f "/tmp/.et_roster.$$"
        return 2
    fi
    et_error "no radio matches $want"
    et_why "the radios attached are the ones this refused to substitute from; pick one of the drivers or serials that 01_radio enumerated."
    rm -f "/tmp/.et_roster.$$"
    return 2
}

# srsRAN names the radio in its config, and each vendor has one name. The
# mapping is not a preference: srsRAN 4G speaks UHD natively and everything
# else through SoapySDR, so a HackRF is device_name soapy with driver hackrf,
# not device_name hackrf.
et_rf_map() {  # <driver> -> device_name<TAB>device_args
    local drv="${1:-}"
    case "$drv" in
        uhd|usrp*)          printf 'uhd\t\n' ;;
        hackrf*)            printf 'soapy\tdriver=hackrf\n' ;;
        bladerf*)           printf 'soapy\tdriver=bladerf\n' ;;
        limesdr*|lime*)     printf 'soapy\tdriver=lime\n' ;;
        pluto:*)            printf 'soapy\tdriver=plutosdr\n' ;;
        pluto*)             printf 'soapy\tdriver=plutosdr\n' ;;
        soapy:*)            printf 'soapy\tdriver=%s\n' "${drv#soapy:}" ;;
        rtlsdr*)            return 1 ;;   # receive only: never a twin
        *)                  return 1 ;;
    esac
}

et_rf_patch_lte() {  # <enb.conf> <device_name> <device_args>
    local conf="$1" name="$2" args="$3"
    [[ -r "$conf" ]] || { et_error "cannot read $conf"; return 1; }
    grep -q '^\[rf\]' "$conf" || { et_error "$conf has no [rf] section; regenerate it with --prepare-lte"; return 1; }
    sed -i "s|^device_name *=.*|device_name = ${name}|" "$conf"
    sed -i "s|^device_args *=.*|device_args = ${args}|" "$conf"
    grep -q "^device_name = ${name}$" "$conf" || { et_error "could not set device_name in $conf"; return 1; }
    return 0
}

et_rf_patch_nr() {  # <gnb.conf> <device_driver> <device_args> <tx_gain> <rx_gain>
    local conf="$1" driver="$2" args="$3" tx="$4" rx="$5" tmp
    [[ -r "$conf" ]] || { et_error "cannot read $conf"; return 1; }
    grep -q '^rf:' "$conf" && { et_error "$conf already carries an rf block; regenerate it"; return 1; }
    tmp="$(mktemp)" || return 1
    awk -v d="$driver" -v a="$args" -v tx="$tx" -v rx="$rx" '
        !done && /^cell_cfg:/ {
            print "rf:"
            print "  device_driver: " d
            if (a != "") print "  device_args: \"" a "\""
            print "  tx_gain: " tx
            print "  rx_gain: " rx
            done = 1
        }
        { print }
    ' "$conf" > "$tmp" || { rm -f "$tmp"; return 1; }
    grep -q '^rf:' "$tmp" || { rm -f "$tmp"; et_error "$conf has no cell_cfg anchor for the rf block"; return 1; }
    mv "$tmp" "$conf"
}

# ── the evidence ────────────────────────────────────────────────────────
et_evidence_init() {
    local dir store
    dir="$(et_store_dir)"; store="$(et_evidence_path)"
    mkdir -p "$dir" || { et_error "cannot create $dir"; return 1; }
    [[ -s "$store" ]] || printf 'ts\trun\tkind\tvalue\tsource\tconfidence\n' > "$store"
}
# One row per fact. Confidence is not decoration: "observed" means the value
# came out of a capture or a log line, "advertised" means the twin sent it and
# nobody has confirmed a phone read it.
et_evidence_add() {  # <run> <kind> <value> <source> <confidence>
    local run="$1" kind="$2" value="$3" source="$4" confidence="$5" store
    et_evidence_init || return 1
    store="$(et_evidence_path)"
    [[ -n "$value" ]] || return 1
    awk -F'\t' -v r="$run" -v k="$kind" -v v="$value" -v s="$source" \
        'NR>1 && $2==r && $3==k && $4==v && $5==s {found=1} END{exit !found}' "$store" \
        && return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run" "$kind" "$value" "$source" "$confidence" >> "$store"
    printf 'evidence\t%s\t%s\t%s\t%s\n' "$kind" "$value" "$source" "$confidence"
}

# Identities from the twin's own capture. Module 17 owns pcap decoding in this
# tree, including the fallback parser when tshark is absent; reusing it means
# one decoder to trust instead of a second regex.
et_evidence_from_capture() {  # <run> <pcap>
    local run="$1" pcap="$2" tool rows rc
    [[ -s "$pcap" ]] || return 0
    tool="$IMSISTING_ROOT/modules/17_pcap_analysis.sh"
    [[ -r "$tool" ]] || { printf 'note\tno pcap decoder at %s; capture kept, not decoded\n' "$tool"; return 0; }
    rows="$(bash "$tool" --identities "$pcap" 2>/dev/null)"; rc=$?
    if (( rc != 0 )) || [[ -z "$rows" ]]; then
        printf 'note\tcapture kept at %s; module 17 decoded nothing from it\n' "$pcap"
        return 0
    fi
    local kind value proto where n=0
    while IFS=$'\t' read -r _f _frame kind value proto _src _dst where; do
        [[ "$kind" == "kind" || -z "$kind" ]] && continue
        [[ "$kind" == "file" ]] && continue
        et_evidence_add "$run" "$kind" "$value" "capture:${pcap##*/}" observed >/dev/null
        ((n++))
    done <<< "$rows"
    (( n > 0 )) && printf 'evidence\tidentity\t%s\t%s\tobserved\n' "$n" "capture:${pcap##*/}"
    return 0
}

# Facts only the RAN side knows: which cell the phone chose, what it asked for,
# which cipher it was willing to take. A log greps cheaply and honestly; every
# row says which file it came from.
et_evidence_from_logs() {  # <run> <dir>
    local run="$1" dir="$2" f name val src n=0
    for f in "$dir"/logs/*.log; do
        [[ -s "$f" ]] || continue
        name="${f##*/}"
        src="log:$name"
        while IFS= read -r val; do
            [[ -n "$val" ]] || continue
            et_evidence_add "$run" imsi "$val" "$src" observed >/dev/null; ((n++))
        done < <(grep -Eo 'IMSI[[:space:]]*[=:][[:space:]]*[0-9]{6,15}' "$f" 2>/dev/null |
                 sed -E 's/.*[=:][[:space:]]*//' | sort -u | head -20)
        while IFS= read -r val; do
            [[ -n "$val" ]] || continue
            et_evidence_add "$run" tmsi "$val" "$src" observed >/dev/null; ((n++))
        done < <(grep -Eoi '(m-)?tmsi[[:space:]]*[=:][[:space:]]*(0x)?[0-9a-f]{4,8}' "$f" 2>/dev/null |
                 sed -E 's/.*[=:][[:space:]]*//' | sort -u | head -10)
        while IFS= read -r val; do
            [[ -n "$val" ]] || continue
            et_evidence_add "$run" cipher "$val" "$src" advertised >/dev/null; ((n++))
        done < <(grep -Eo '\b(EEA|EIA|NEA|NIA)[0-9]\b' "$f" 2>/dev/null | sort -u | head -10)
        for val in "attach accept:attach-accept" "attach reject:attach-reject" \
                   "registration accept:registration-accept" "pdu session established:pdu-session" \
                   "PDU Session Establishment Accept:pdu-session"; do
            grep -qi "${val%%:*}" "$f" 2>/dev/null || continue
            et_evidence_add "$run" procedure "${val##*:}" "$src" observed >/dev/null; ((n++))
        done
        grep -Eqi 'rrc connection setup complete|rrc connected' "$f" 2>/dev/null &&
            { et_evidence_add "$run" procedure rrc-connected "$src" observed >/dev/null; ((n++)); }
    done
    (( n > 0 )) || return 0
    printf 'evidence\tevents\t%s\tlogs\tobserved\n' "$n"
    return 0
}

# What the twin itself put out. This is the only side that is knowable before
# anyone answers, so it is recorded as advertised rather than observed.
et_evidence_from_config() {  # <run> <dir> <rat> <radio-row|->
    local run="$1" dir="$2" rat="$3" row="$4" v
    if [[ "$rat" == LTE && -r "$dir/enb.conf" ]]; then
        v=$(awk -F' *= *' '/^dl_earfcn/{print $2; exit}' "$dir/enb.conf")
        [[ -n "$v" ]] && et_evidence_add "$run" earfcn "$v" "config:enb.conf" advertised >/dev/null
        v=$(awk -F' *= *' '/^mcc/{print $2; exit}' "$dir/enb.conf")
        [[ -n "$v" ]] && et_evidence_add "$run" plmn "$v" "config:enb.conf" advertised >/dev/null
        while IFS= read -r v; do
            [[ -n "$v" ]] || continue
            et_evidence_add "$run" cipher "$v" "config:enb.conf" advertised >/dev/null
        done < <(grep -Eo '\b(EEA|EIA)[0-9]\b' "$dir/enb.conf" 2>/dev/null | sort -u)
    fi
    if [[ "$rat" == NR && -r "$dir/gnb.conf" ]]; then
        v=$(awk -F': *' '/^ *dl_arfcn:/{print $2; exit}' "$dir/gnb.conf")
        [[ -n "$v" ]] && et_evidence_add "$run" arfcn "$v" "config:gnb.conf" advertised >/dev/null
    fi
    [[ "$row" == "-" ]] && return 0
    et_evidence_add "$run" radio "$(printf '%s' "$row" | cut -f1)" "radio:roster" advertised >/dev/null
    et_evidence_add "$run" rail "$(printf '%s' "$row" | cut -f9)" "radio:roster" advertised >/dev/null
    return 0
}

et_capture_start() {  # <dir> <iface>  -> writes pid to <dir>/capture.pid
    local dir="$1" iface="$2"
    command -v tcpdump >/dev/null 2>&1 || {
        et_error 'tcpdump is not installed'
        et_why 'a run asked for evidence cannot be recorded without it; install tcpdump or drop --with-capture and read only the logs.'
        return 1
    }
    mkdir -p "$dir/logs" || return 1
    # Both seams, one file: S1AP and NGAP carry the NAS a phone sent us, and
    # GTP-U/PFCP prove a bearer was actually established.
    tcpdump -i "$iface" -U -s 0 -w "$dir/evidence.pcap" \
        'sctp port 36412 or sctp port 38412 or udp port 2152 or udp port 8805' \
        >"$dir/logs/capture.log" 2>&1 &
    printf '%s\n' "$!" > "$dir/capture.pid"
    sleep 1
    kill -0 "$(cat "$dir/capture.pid")" 2>/dev/null || {
        et_error "capture did not start on $iface; see $dir/logs/capture.log"
        return 1
    }
    return 0
}
et_capture_stop() {  # <dir>
    local dir="$1" pid
    [[ -f "$dir/capture.pid" ]] || return 0
    pid=$(cat "$dir/capture.pid" 2>/dev/null)
    [[ -n "$pid" ]] && kill -INT "$pid" 2>/dev/null
    sleep 1
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && kill -TERM "$pid" 2>/dev/null
    rm -f "$dir/capture.pid"
    return 0
}

et_evidence_tsv() {  # [--run NAME]
    local want=""
    while (($#)); do
        case "$1" in
            --run) want="${2:-}"; shift 2 ;;
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    local store; store="$(et_evidence_path)"
    [[ -s "$store" ]] || { et_error "no evidence recorded yet ($store)"; et_why 'evidence is written when a twin run finishes; run --run-lte or --run-nr first.'; return 1; }
    printf 'ts\trun\tkind\tvalue\tsource\tconfidence\n'
    if [[ -n "$want" ]]; then
        awk -F'\t' -v r="$want" 'NR>1 && $2==r' "$store"
    else
        tail -n +2 "$store"
    fi
}

et_cmd_evidence_collect() {  # <dir> [--rat lte|nr] [--run NAME]
    local dir="${1:-}" rat=lte run=""
    shift || true
    while (($#)); do
        case "$1" in
            --rat) rat="${2:-}"; shift 2 ;;
            --run) run="${2:-}"; shift 2 ;;
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    [[ -n "$dir" ]] || { et_error 'usage: --evidence-collect <twin-dir> [--rat lte|nr] [--run NAME]'; return 2; }
    [[ -d "$dir" ]] || { et_error "no such twin directory: $dir"; return 1; }
    [[ "$rat" == lte || "$rat" == nr ]] || { et_error 'rat must be lte or nr'; return 2; }
    [[ -n "$run" ]] || run="${rat}-${dir##*/}"
    et_evidence_from_config "$run" "$dir" "$(printf '%s' "$rat" | tr '[:lower:]' '[:upper:]')" "-"
    et_evidence_from_logs "$run" "$dir"
    et_evidence_from_capture "$run" "$dir/evidence.pcap"
    printf 'run\t%s\nstore\t%s\n' "$run" "$(et_evidence_path)"
}

et_read_nr_row() {
    local input="$1" row="$2" line mcc mnc plmn
    line=$(awk -F'\t' -v n="$row" 'NR==n+1 {print; found=1; exit} END {if (!found) exit 1}' "$input") || { et_error 'row does not exist in recon TSV'; return 2; }
    [[ "$(awk -F'\t' '{print NF}' <<<"$line")" == 16 ]] || { et_error 'recon TSV row must have 16 columns'; return 2; }
    [[ "$(cut -f1 <<<"$line")" == NR && "$(cut -f2 <<<"$line")" == 5G ]] || { et_error 'selected recon row is not NR/5G'; return 2; }
    [[ "$line" != *'$('* && "$line" != *'`'* && "$line" != *'\\'* ]] || { et_error 'NR row contains unsupported control syntax'; return 2; }
    local field
    for field in 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
        [[ "$(cut -f"$field" <<<"$line")" != *[\$\`\\]* ]] || { et_error 'NR row contains unsafe field characters'; return 2; }
    done
    mcc="$(cut -f6 <<<"$line")"; mnc="$(cut -f7 <<<"$line")"; plmn="$(cut -f5 <<<"$line" | tr -d '-')"
    [[ "$(cut -f12 <<<"$line")" =~ ^(n[0-9]{1,4})(,n[0-9]{1,4})*$ && "$(cut -f3 <<<"$line")" =~ ^[0-9]{1,7}$ ]] || { et_error 'NR band/ARFCN fields are invalid'; return 2; }
    [[ "$mcc" =~ ^[0-9]{3}$ && "$mnc" =~ ^[0-9]{2,3}$ && "$plmn" == "$mcc$mnc" ]] || { et_error 'NR PLMN must match 3-digit MCC and 2/3-digit MNC'; return 2; }
    local arfcn="$(cut -f3 <<<"$line")" band="$(cut -f12 <<<"$line")" expected_band expected_freq row_freq
    [[ "$arfcn" =~ ^[0-9]{1,7}$ ]] || { et_error 'NR ARFCN out of range'; return 2; }
    (( 10#$arfcn <= 3279165 )) || { et_error 'NR ARFCN out of range'; return 2; }
    et_load_nr >/dev/null 2>&1 || { et_error 'cannot load NR frequency helpers'; return 1; }
    expected_band="$(nair_band_of_arfcn "$arfcn")"
    [[ ",$expected_band," == *",$band,"* ]] || { et_error 'NR ARFCN is outside selected band'; return 2; }
    [[ "$band" =~ ^n[0-9]{1,4}$ ]] || { et_error 'NR band is invalid'; return 2; }
    if [[ "$expected_band" == *,* && "${ET_NR_BAND_OVERRIDE:-0}" != 1 ]]; then
        et_error 'overlapping NR bands require an explicit --band selection'; return 2
    fi
    expected_freq="$(nair_arfcn_to_mhz "$arfcn")"; row_freq="$(cut -f4 <<<"$line")"
    [[ "$row_freq" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { et_error 'NR frequency must be numeric'; return 2; }
    [[ "$(awk -v a="$row_freq" -v b="$expected_freq" 'BEGIN{d=a-b; if(d<0)d=-d; print (d<0.001)?"yes":"no"}')" == yes ]] || { et_error 'NR frequency does not match ARFCN'; return 2; }
    [[ "$(cut -f11 <<<"$line")" =~ ^[0-9]{1,8}$ ]] || { et_error 'NR TAC must be numeric and 0..16777215'; return 2; }
    (( 10#$(cut -f11 <<<"$line") <= 16777215 )) || { et_error 'NR TAC must be numeric and 0..16777215'; return 2; }
    printf '%s\n' "$line"
}

# A prepared twin records which radio it was built for, so a later run cannot
# quietly radiate through a different one.
et_write_radio_stamp() {  # <dir> <row>
    printf '%s\n' "$2" > "$1/radio.tsv"
}
et_read_radio_stamp() {  # <dir> -> row or nothing
    [[ -s "$1/radio.tsv" ]] || return 0
    head -n1 "$1/radio.tsv"
}

et_prepare_lte() {
    local input="${1:-}" row="${2:-}" pci=1 out="$ET_TWIN" radiate=0 want="" tx_gain=70
    shift 2 2>/dev/null || true
    while (($#)); do
        case "$1" in
            --pci) [[ -n "${2:-}" ]] || { et_error '--pci needs a value'; return 2; }; pci="$2"; shift 2 ;;
            --out) [[ -n "${2:-}" ]] || { et_error '--out needs a directory'; return 2; }; out="$2"; shift 2 ;;
            --radiate) radiate=1; shift ;;
            --radio) [[ -n "${2:-}" ]] || { et_error '--radio needs a driver or serial'; return 2; }; want="$2"; shift 2 ;;
            --tx-gain) [[ -n "${2:-}" ]] || { et_error '--tx-gain needs a dB value'; return 2; }; tx_gain="$2"; shift 2 ;;
            --ack-isolated-lab) shift ;;   # retired: accepted and ignored
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    [[ -f "$input" && -r "$input" ]] || { et_error 'provide a readable recon TSV'; return 2; }
    [[ "$row" =~ ^[0-9]+$ ]] && (( ${#row} <= 9 && 10#$row > 0 )) || { et_error 'row must be a positive data-row number'; return 2; }
    [[ "$pci" =~ ^[0-9]+$ ]] && (( ${#pci} <= 3 && 10#$pci <= 503 )) || { et_error 'LTE PCI must be 0..503'; return 2; }
    [[ "$tx_gain" =~ ^-?[0-9]+$ ]] && (( tx_gain >= -30 && tx_gain <= 100 )) || { et_error 'tx gain must be -30..100 dB'; return 2; }
    (( ${#input} <= 4096 && ${#out} <= 4096 )) || { et_error 'input/output path is too long'; return 2; }
    et_safe_path "$out" || { et_error 'output must be a dedicated twin directory'; return 2; }
    [[ ! -e "$out" || -d "$out" ]] || { et_error 'output path exists and is not a directory'; return 2; }
    local line
    line=$(awk -F'\t' -v n="$row" 'NR==n+1 {print; found=1; exit} END {if (!found) exit 1}' "$input") || { et_error 'row does not exist in recon TSV'; return 2; }
    [[ "$(awk -F'\t' '{print NF}' <<<"$line")" == 16 ]] || { et_error 'recon TSV row must have 16 columns'; return 2; }
    [[ "$(cut -f1 <<<"$line")" == LTE && "$(cut -f2 <<<"$line")" == 4G ]] || { et_error 'selected recon row is not LTE/4G'; return 2; }
    [[ "$line" != *'$('* && "$line" != *'`'* && "$line" != *'\\'* ]] || { et_error 'LTE row contains unsupported control syntax'; return 2; }
    ET_TWIN="$out"; et_load_lte || return 1
    set +o pipefail
    LAIR_CONF="$ET_TWIN/enb.conf"; LAIR_RRC="$ET_TWIN/rr.conf"
    lair_cmd_clone_recon "$input" "$row" --pci "$pci" || return $?
    printf 'OK\ttwin_dir=%s\nOK\tradio=LTE\n' "$ET_TWIN"
    if (( radiate )); then
        local rrow dname dargs
        rrow="$(et_radio_pick "$want")" || return $?
        IFS=$'\t' read -r dname dargs <<< "$(et_rf_map "$(printf '%s' "$rrow" | cut -f1)")" || {
            et_error "radio $(printf '%s' "$rrow" | cut -f1) cannot be driven by srsRAN"
            et_why 'srsRAN 4G speaks UHD natively and every other vendor through SoapySDR; this radio is receive only or has no driver there.'
            return 2
        }
        et_rf_patch_lte "$ET_TWIN/enb.conf" "$dname" "$dargs" || return 1
        sed -i "s|^tx_gain *=.*|tx_gain = ${tx_gain}|" "$ET_TWIN/enb.conf"
        et_write_radio_stamp "$ET_TWIN" "$rrow"
        printf 'OK\tmode=radiate\nOK\tdevice=%s %s\nOK\ttx_gain=%s\n' "$dname" "$dargs" "$tx_gain"
        printf 'note\tradiating is a licensed act; the operator carries that responsibility, and this twin was pointed at %s from the recon row.\n' "$(cut -f5 <<<"$line")"
    else
        : > "$ET_TWIN/radio.tsv"
        printf 'OK\tmode=contained\nnote\tcontained runs prove the chain and produce no air evidence: every peer is loopback and the radio is srsRAN its own device.\n'
    fi
    return 0
}

et_prepare_nr() {
    local input="${1:-}" row="${2:-}" pci=1 out="$ET_TWIN" format=srsran nrband arfcn plmn band_override="" radiate=0 want="" tx_gain=70
    shift 2 2>/dev/null || true
    while (($#)); do
        case "$1" in
            --pci) [[ -n "${2:-}" ]] || { et_error '--pci needs a value'; return 2; }; pci="$2"; shift 2 ;;
            --out) [[ -n "${2:-}" ]] || { et_error '--out needs a directory'; return 2; }; out="$2"; shift 2 ;;
            --format) [[ -n "${2:-}" ]] || { et_error '--format needs srsran or open5gs'; return 2; }; format="$2"; shift 2 ;;
            --band) [[ -n "${2:-}" ]] || { et_error '--band needs n<number>'; return 2; }; band_override="$2"; shift 2 ;;
            --radiate) radiate=1; shift ;;
            --radio) [[ -n "${2:-}" ]] || { et_error '--radio needs a driver or serial'; return 2; }; want="$2"; shift 2 ;;
            --tx-gain) [[ -n "${2:-}" ]] || { et_error '--tx-gain needs a dB value'; return 2; }; tx_gain="$2"; shift 2 ;;
            --ack-isolated-lab) shift ;;   # retired: accepted and ignored
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    [[ -f "$input" && -r "$input" ]] || { et_error 'provide a readable recon TSV'; return 2; }
    [[ "$row" =~ ^[0-9]+$ ]] && (( ${#row} <= 9 && 10#$row > 0 )) || { et_error 'row must be a positive data-row number'; return 2; }
    [[ "$pci" =~ ^[0-9]+$ ]] && (( ${#pci} <= 4 && 10#$pci <= 1007 )) || { et_error 'NR PCI must be 0..1007'; return 2; }
    (( ${#row} <= 9 && ${#pci} <= 4 && ${#input} <= 4096 && ${#out} <= 4096 )) || { et_error 'input/output value is too long'; return 2; }
    [[ "$format" == srsran || "$format" == open5gs ]] || { et_error 'format must be srsran or open5gs'; return 2; }
    [[ "$tx_gain" =~ ^-?[0-9]+$ ]] && (( tx_gain >= -30 && tx_gain <= 100 )) || { et_error 'tx gain must be -30..100 dB'; return 2; }
    et_safe_path "$out" || { et_error 'output must be a dedicated twin directory'; return 2; }
    [[ ! -e "$out" || -d "$out" ]] || { et_error 'output path exists and is not a directory'; return 2; }
    local line
    [[ -z "$band_override" || "$band_override" =~ ^n[0-9]{1,4}$ ]] || { et_error 'NR band must look like n78'; return 2; }
    local band_was_set=0
    [[ -z "$band_override" ]] || band_was_set=1
    line=$(ET_NR_BAND_OVERRIDE="$band_was_set" et_read_nr_row "$input" "$row") || return $?
    nrband="$(cut -f12 <<<"$line")"; arfcn="$(cut -f3 <<<"$line")"; plmn="$(cut -f6 <<<"$line")$(cut -f7 <<<"$line")"
    if [[ -n "$band_override" ]]; then
        [[ ",${nrband}," == *",${band_override},"* ]] || { et_error 'selected band must appear in recon row'; return 2; }
        nrband="$band_override"
    else
        [[ "$nrband" != *,* ]] || { et_error 'overlapping NR bands require --band n<number>'; return 2; }
    fi
    [[ "$(cut -f5 <<<"$line" | tr -d '-')" == "$plmn" ]] || { et_error 'PLMN does not match MCC/MNC fields'; return 2; }
    local tac="$(cut -f11 <<<"$line")"
    [[ "$tac" =~ ^[0-9]{1,8}$ ]] && (( 10#$tac <= 16777215 )) || { et_error 'NR TAC must be numeric and 0..16777215'; return 2; }
    mkdir -p "$out" || { et_error "cannot create $out"; return 1; }
    ET_TWIN="$out"; et_load_nr || return 1
    NAIR_DIR="$out"; NAIR_CONF="$out/gnb.conf"; NAIR_LOG="$out/logs/gnb.log"
    nair_gen_gnb_conf "$plmn" "$nrband" "$arfcn" "$pci" "$out/gnb.conf" || return $?
    if [[ "$format" == open5gs ]]; then
        nair_gen_open5gs_conf "$plmn" "$tac" "$out/amf.yaml" || return $?
    fi
    printf 'OK\ttwin_dir=%s\nOK\tradio=NR\nOK\tformat=%s\n' "$ET_TWIN" "$format"
    if (( radiate )); then
        local rrow dname dargs
        rrow="$(et_radio_pick "$want")" || return $?
        IFS=$'\t' read -r dname dargs <<< "$(et_rf_map "$(printf '%s' "$rrow" | cut -f1)")" || {
            et_error "radio $(printf '%s' "$rrow" | cut -f1) cannot be driven by srsRAN Project"
            et_why 'the gNB speaks UHD and SoapySDR; this radio is receive only or has no driver there.'
            return 2
        }
        et_rf_patch_nr "$out/gnb.conf" "$dname" "$dargs" "$tx_gain" 40 || return 1
        et_write_radio_stamp "$out" "$rrow"
        printf 'OK\tmode=radiate\nOK\tdevice=%s %s\nOK\ttx_gain=%s\n' "$dname" "$dargs" "$tx_gain"
        printf 'note\tradiating is a licensed act; the operator carries that responsibility, and this twin was pointed at %s from the recon row.\n' "$(cut -f5 <<<"$line")"
    else
        : > "$out/radio.tsv"
        printf 'OK\tmode=contained\nnote\tcontained runs prove the chain and produce no air evidence: every peer is loopback and the radio is the gNB its own device.\n'
    fi
    return 0
}

# What a twin needs depends on who the UE is. A contained twin needs its own
# UE file; a radiating twin has no UE file at all, because the UE is somebody
# else's phone. Demanding one would be asking for a config nobody uses.
et_configs() {  # <dir> <LTE|NR> [radiate]
    local dir="$1" kind="$2" radiate="${3:-0}" name miss=0 required
    if [[ "$kind" == LTE ]]; then
        required="epc.conf enb.conf rr.conf"
        (( radiate )) || required="$required srsue.conf"
    else
        required="amf.yaml gnb.conf"
        (( radiate )) || required="$required ue.yaml"
    fi
    for name in $required; do
        [[ -s "$dir/$name" ]] || { et_error "missing or empty config: $dir/$name"; miss=1; }
    done
    return "$miss"
}
et_preflight_lte() {
    local dir="${1:-$ET_TWIN}" miss=0 t row
    et_safe_path "$dir" || { et_error 'provide a dedicated twin directory'; return 2; }
    [[ -d "$dir" ]] || { et_error "twin directory not found: $dir"; return 2; }
    row="$(et_read_radio_stamp "$dir")"
    if [[ -n "$row" ]]; then et_configs "$dir" LTE 1 || return 1; else et_configs "$dir" LTE 0 || return 1; fi
    if [[ -n "$row" ]]; then
        printf 'mode\tradiate\nradio\t%s\nrail\t%s\n' "$(printf '%s' "$row" | cut -f1)" "$(printf '%s' "$row" | cut -f9)"
        printf 'device\t%s\n' "$(awk '/^device_name/{sub(/^device_name *= */,""); n=$0} /^device_args/{sub(/^device_args *= */,""); a=$0} END{print n (a=="" ? "" : " " a)}' "$dir/enb.conf")"
    else
        printf 'mode\tcontained\n'
        et_loopback_configs "$dir/epc.conf" "$dir/enb.conf" "$dir/rr.conf" "$dir/srsue.conf" || { et_error 'contained configs must bind/connect only to loopback'; return 2; }
    fi
    for t in srsepc srsenb timeout; do
        if command -v "$t" >/dev/null 2>&1; then printf 'tool\t%s\t%s\n' "$t" "$(command -v "$t")"; else printf 'missing_tool\t%s\n' "$t"; miss=1; fi
    done
    if ! command -v srsue >/dev/null 2>&1; then
        printf 'missing_tool\tsrsue\n'
        [[ -n "$row" ]] || miss=1
    fi
    (( miss == 0 )) || { et_error 'preflight incomplete; install reported RAN tools'; return 1; }
    if [[ -n "$row" ]]; then printf 'result\tready-lte-twin-radiating\n'; else printf 'result\tready-lte-twin-contained\n'; fi
}
et_preflight_nr() {
    local dir="${1:-$ET_TWIN}" miss=0 t row
    et_safe_path "$dir" || { et_error 'provide a dedicated twin directory'; return 2; }
    [[ -d "$dir" ]] || { et_error "twin directory not found: $dir"; return 2; }
    row="$(et_read_radio_stamp "$dir")"
    if [[ -n "$row" ]]; then et_configs "$dir" NR 1 || return 1; else et_configs "$dir" NR 0 || return 1; fi
    if [[ -n "$row" ]]; then
        printf 'mode\tradiate\nradio\t%s\nrail\t%s\n' "$(printf '%s' "$row" | cut -f1)" "$(printf '%s' "$row" | cut -f9)"
        printf 'device\t%s\n' "$(awk -F': *' '/^ *device_driver:/{print $2; exit}' "$dir/gnb.conf")"
    else
        printf 'mode\tcontained\n'
        et_loopback_nr_configs "$dir/amf.yaml" "$dir/gnb.conf" "$dir/ue.yaml" || { et_error 'contained configs must bind/connect only to loopback'; return 2; }
    fi
    for t in open5gs-amfd open5gs-upfd gnb; do
        if command -v "$t" >/dev/null 2>&1; then printf 'tool\t%s\t%s\n' "$t" "$(command -v "$t")"; else printf 'missing_tool\t%s\n' "$t"; miss=1; fi
    done
    if ! command -v nr-ue >/dev/null 2>&1; then
        printf 'missing_tool\tnr-ue\n'
        [[ -n "$row" ]] || miss=1
    fi
    (( miss == 0 )) || { et_error 'preflight incomplete; install reported RAN tools'; return 1; }
    if [[ -n "$row" ]]; then printf 'result\tready-nr-twin-radiating\n'; else printf 'result\tready-nr-twin-contained\n'; fi
}

# A wait that can be interrupted: `sleep N` in a trap-bearing shell leaves the
# children running for N seconds after Ctrl-C.
et_wait_window() {
    local seconds="$1" waited=0
    while (( waited < seconds )); do
        sleep 1 || break
        waited=$((waited + 1))
        local alive=0 p
        for p in "${ET_PIDS[@]:-}"; do kill -0 "$p" 2>/dev/null && alive=$((alive + 1)); done
        (( alive > 0 )) || break
    done
}

et_run_lte() {
    local dir="${1:-$ET_TWIN}" seconds="${2:-120}" name; shift 2 2>/dev/null || true
    local radiate=0 capture=0 iface=lo
    while (($#)); do
        case "$1" in
            --radiate) radiate=1; shift ;;
            --with-capture|capture) capture=1; shift ;;   # --capture kept as an alias
            --iface) [[ -n "${2:-}" ]] || { et_error '--iface needs an interface'; return 2; }; iface="$2"; shift 2 ;;
            --ack-isolated-lab) shift ;;   # retired: accepted and ignored
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    et_safe_path "$dir" || { et_error 'provide a dedicated twin directory'; return 2; }
    [[ -d "$dir" ]] || { et_error 'twin directory not found'; return 2; }
    [[ "$seconds" =~ ^[0-9]+$ ]] && (( seconds >= 5 && seconds <= 3600 )) || { et_error 'duration must be 5..3600 seconds'; return 2; }
    local stamp radiorow
    radiorow="$(et_read_radio_stamp "$dir")"
    if (( radiate )); then
        [[ -n "$radiorow" ]] || {
            et_error 'this twin was prepared contained, so there is nothing to radiate with'
            et_why 'run --prepare-lte <recon.tsv> <row> --radiate to write the radio section, then run it again.'
            return 2
        }
        local dev; dev="$(awk -F' *= *' '/^device_name/{print $2; exit}' "$dir/enb.conf")"
        [[ "$dev" != auto && -n "$dev" ]] || {
            et_error "the twin's radio section is still auto, so it would pick a device nobody chose"
            et_why 're-run --prepare-lte with --radiate so the device_name is written explicitly.'
            return 2
        }
    else
        if [[ -n "$radiorow" ]]; then
            et_error 'this twin is prepared to radiate; say --radiate to run it, or prepare a contained one'
            et_why 'the radio section was written for a specific SDR and the record of that is in radio.tsv; running it as a loopback twin would change what was asked for without saying so.'
            return 2
        fi
        et_loopback_configs "$dir/epc.conf" "$dir/enb.conf" "$dir/rr.conf" "$dir/srsue.conf" || {
            et_error 'the configs point at peers that are not loopback, so this run would reach a network it does not own'
            et_why 'prepare the twin again with --radiate for an on-air run, or regenerate the configs for a contained one.'
            return 2
        }
    fi
    et_configs "$dir" LTE "$radiate" || return 2
    for name in srsepc srsenb timeout; do command -v "$name" >/dev/null 2>&1 || { et_error "$name is required"; return 1; }; done
    if (( ! radiate )); then
        command -v srsue >/dev/null 2>&1 || { et_error 'srsue is required for a contained run'; et_why 'a contained twin has no phone walking past, so the UE has to be one you own.'; return 1; }
    fi
    local epc enb ue="" p st rc=0 bounded=0
    epc=$(command -v srsepc); enb=$(command -v srsenb)
    (( radiate )) || ue=$(command -v srsue)
    mkdir -p "$dir/logs" || return 1
    stamp="lte-$(date -u +%Y%m%dT%H%M%SZ)"
    rm -f "$dir/evidence.pcap"
    (( capture )) && { et_capture_start "$dir" "$iface" || return 1; }
    ET_PIDS=(); trap 'et_stop_all' INT TERM HUP
    if (( radiate )); then
        printf 'mode\tradiate\nradio\t%s\n' "$(printf '%s' "$radiorow" | cut -f1)"
        printf 'note\tthe twin is transmitting as %s; a phone that camps here is not yours and its attach is the evidence.\n' "$(cut -f5 <<<"$radiorow" >/dev/null 2>&1; printf '%s' "$(printf '%s' "$radiorow" | cut -f1)")"
    else
        printf 'mode\tcontained\n'
        printf 'note\tloopback peers only, so nothing is radiated and no air evidence can exist from this run.\n'
    fi
    (cd "$dir" && timeout --signal=INT "$seconds" "$epc" "$dir/epc.conf") >"$dir/logs/epc.log" 2>&1 & ET_PIDS+=("$!")
    sleep 2; kill -0 "${ET_PIDS[0]}" 2>/dev/null || { et_stop_all; (( capture )) && et_capture_stop "$dir"; et_error 'EPC exited early; see logs/epc.log'; return 1; }
    (cd "$dir" && timeout --signal=INT "$seconds" "$enb" "$dir/enb.conf") >"$dir/logs/enb.log" 2>&1 & ET_PIDS+=("$!")
    sleep 3; kill -0 "${ET_PIDS[1]}" 2>/dev/null || { et_stop_all; (( capture )) && et_capture_stop "$dir"; et_error 'eNB exited early; see logs/enb.log'; return 1; }
    if [[ -n "$ue" ]]; then
        (cd "$dir" && timeout --signal=INT "$seconds" "$ue" "$dir/srsue.conf") >"$dir/logs/ue.log" 2>&1 & ET_PIDS+=("$!")
    fi
    et_wait_window "$seconds"
    for p in "${ET_PIDS[@]}"; do kill -INT "$p" 2>/dev/null || :; done
    for p in "${ET_PIDS[@]}"; do
        wait "$p" 2>/dev/null
        st=$?
        case "$st" in
            0) ;;
            124|130) bounded=$((bounded + 1)) ;;
            *) rc=1 ;;
        esac
    done
    ET_PIDS=(); trap - INT TERM HUP
    (( capture )) && et_capture_stop "$dir"
    printf 'log\tepc\t%s/logs/epc.log\nlog\tenb\t%s/logs/enb.log\n' "$dir" "$dir"
    [[ -n "$ue" ]] && printf 'log\tue\t%s/logs/ue.log\n' "$dir"
    (( capture )) && printf 'capture\t%s\n' "$dir/evidence.pcap"

    et_evidence_from_config "$stamp" "$dir" LTE "$radiorow"
    et_evidence_from_logs "$stamp" "$dir"
    (( capture )) && et_evidence_from_capture "$stamp" "$dir/evidence.pcap"
    local ids attaches
    local ev; ev="$(et_evidence_path)"
    ids=$(awk -F'\t' -v r="$stamp" 'NR>1 && $2==r && ($3=="imsi"||$3=="suci")' "$ev" 2>/dev/null | wc -l)
    attaches=$(awk -F'\t' -v r="$stamp" 'NR>1 && $2==r && $3=="procedure" && ($4=="attach-accept"||$4=="registration-accept")' "$ev" 2>/dev/null | wc -l)
    printf 'run\t%s\nstore\t%s\nidentities\t%s\nattaches\t%s\n' "$stamp" "$ev" "$ids" "$attaches"
    (( bounded == 0 )) || printf 'note\t%d service(s) stopped by the timer, not by a crash.\n' "$bounded"
    (( rc == 0 )) || printf 'note\tA service exited nonzero at bounded shutdown; inspect its log.\n'
    if (( radiate )); then
        if (( ids > 0 )); then
            printf 'result\ttwin-received-identity\n'
        elif (( attaches > 0 )); then
            printf 'result\ttwin-accepted-attach\n'
        elif grep -Eqi 'rrc connection request|initial ue message|preamble' "$dir/logs/enb.log" 2>/dev/null; then
            printf 'result\ttwin-saw-attempt\n'
        else
            printf 'result\ttwin-radiated-unanswered\n'
            et_why 'the twin transmitted and nothing attached. Check that the recon channel is still live, that its PLMN is real in this area, and that the radio actually reached the antenna.'
            return 1
        fi
    else
        if grep -Eiq 'attach accept|attached|pdn connectivity accept|RRC connected' "$dir/logs/ue.log" 2>/dev/null; then
            printf 'result\tLTE-attach-marker-found\n'
        else
            printf 'result\tLTE-run-finished-no-attach-marker\n'
            et_why 'Inspect logs, matching SIM credentials in srsue.conf, the recon channel plan, and the loopback peers.'
            return 1
        fi
    fi
    return 0
}

et_stop_all() {
    local p
    for p in "${ET_PIDS[@]:-}"; do kill -INT "$p" 2>/dev/null || :; done
    for p in "${ET_PIDS[@]:-}"; do wait "$p" 2>/dev/null || :; done
    ET_PIDS=()
}
# One file. A file that names no peer address at all is not suspicious — the
# generated rr.conf is a cell list and carries none — so this only rejects a
# file that names a peer which is not loopback. The caller decides whether the
# set as a whole named anything.
et_loopback_scan() {
    local file="$1" line key value
    [[ -r "$file" ]] || return 1
    while IFS= read -r line; do
            line="${line%%#*}"
            [[ "$line" =~ ^[[:space:]]*([[:alnum:]_-]*(addr|address|bind|host|server|client|peer)[[:alnum:]_-]*)[[:space:]]*[:=][[:space:]]*[\"\']?([^[:space:]\"\']+) ]] || continue
            key="${BASH_REMATCH[1],,}"
            value="${BASH_REMATCH[3]%%,*}"
            value="${value#tcp://}"; value="${value#udp://}"
            case "$key" in *port*|*domain*|*interface*|*path*|*plmn*|*mcc*|*mnc*|*device*) continue ;; esac
            [[ "$value" == *:* && "$value" != *://* ]] && value="${value%%:*}"
            if [[ "$value" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
                [[ "$value" == 127.* ]] || return 1
            elif [[ "$value" =~ ^(localhost|.*\.localhost)$ ]]; then
                :
            else
                return 1
            fi
    done < "$file"
    return 0
}
et_loopback_configs() {
    local file line total=0
    for file in "$@"; do
        et_loopback_scan "$file" || return 1
        while IFS= read -r line; do
            line="${line%%#*}"
            [[ "$line" =~ ^[[:space:]]*[[:alnum:]_-]*(addr|address|bind|host|server|client|peer)[[:alnum:]_-]*[[:space:]]*[:=] ]] && total=$((total + 1))
        done < "$file"
    done
    (( total > 0 ))
}
et_loopback_nr_configs() {
    et_loopback_configs "$@" || return 1
    grep -Eiq '127\.|localhost' "$1" && grep -Eiq '127\.|localhost' "$2" && grep -Eiq '127\.|localhost' "$3"
}

et_run_nr() {
    local dir="${1:-$ET_TWIN}" seconds="${2:-120}" name; shift 2 2>/dev/null || true
    local radiate=0 capture=0 iface=lo
    while (($#)); do
        case "$1" in
            --radiate) radiate=1; shift ;;
            --with-capture|capture) capture=1; shift ;;   # --capture kept as an alias
            --iface) [[ -n "${2:-}" ]] || { et_error '--iface needs an interface'; return 2; }; iface="$2"; shift 2 ;;
            --ack-isolated-lab) shift ;;   # retired: accepted and ignored
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    et_safe_path "$dir" || { et_error 'provide a dedicated twin directory'; return 2; }
    [[ -d "$dir" ]] || { et_error 'twin directory not found'; return 2; }
    [[ "$seconds" =~ ^[0-9]+$ ]] && (( seconds >= 5 && seconds <= 3600 )) || { et_error 'duration must be 5..3600 seconds'; return 2; }
    local stamp radiorow
    radiorow="$(et_read_radio_stamp "$dir")"
    if (( radiate )); then
        [[ -n "$radiorow" ]] || {
            et_error 'this twin was prepared contained, so there is nothing to radiate with'
            et_why 'run --prepare-nr <recon.tsv> <row> --radiate to write the rf block, then run it again.'
            return 2
        }
        grep -q '^rf:' "$dir/gnb.conf" || {
            et_error "the gNB config has no rf block, so the gNB would pick a device nobody chose"
            et_why 're-run --prepare-nr with --radiate so the rf block is written explicitly.'
            return 2
        }
    else
        if [[ -n "$radiorow" ]]; then
            et_error 'this twin is prepared to radiate; say --radiate to run it, or prepare a contained one'
            et_why 'the rf block was written for a specific SDR and the record of that is in radio.tsv; running it as a loopback twin would change what was asked for without saying so.'
            return 2
        fi
        et_loopback_nr_configs "$dir/amf.yaml" "$dir/gnb.conf" "$dir/ue.yaml" || {
            et_error 'the configs point at peers that are not loopback, so this run would reach a network it does not own'
            et_why 'prepare the twin again with --radiate for an on-air run, or regenerate the configs for a contained one.'
            return 2
        }
    fi
    et_configs "$dir" NR "$radiate" || return 2
    for name in open5gs-amfd open5gs-upfd gnb timeout; do command -v "$name" >/dev/null 2>&1 || { et_error "$name is required"; return 1; }; done
    if (( ! radiate )); then
        command -v nr-ue >/dev/null 2>&1 || { et_error 'nr-ue is required for a contained run'; et_why 'a contained twin has no phone walking past, so the UE has to be one you own.'; return 1; }
    fi
    local amf upf gnb ue="" p st rc=0 bounded=0
    amf=$(command -v open5gs-amfd); upf=$(command -v open5gs-upfd); gnb=$(command -v gnb)
    (( radiate )) || ue=$(command -v nr-ue)
    mkdir -p "$dir/logs" || return 1
    stamp="nr-$(date -u +%Y%m%dT%H%M%SZ)"
    rm -f "$dir/evidence.pcap"
    (( capture )) && { et_capture_start "$dir" "$iface" || return 1; }
    ET_PIDS=(); trap 'et_stop_all' INT TERM HUP
    printf 'conf\tamf=%s gnb=%s ue=%s\n' "$dir/amf.yaml" "$dir/gnb.conf" "${ue:+$dir/ue.yaml}"
    if (( radiate )); then
        printf 'mode\tradiate\nradio\t%s\n' "$(printf '%s' "$radiorow" | cut -f1)"
        printf 'note\tthe gNB is transmitting as %s; a phone that registers here is not yours and its registration is the evidence.\n' "$(printf '%s' "$radiorow" | cut -f1)"
    else
        printf 'mode\tcontained\n'
        printf 'note\tloopback peers only, so nothing is radiated and no air evidence can exist from this run.\n'
    fi
    # Open5GS and srsRAN Project both take their file with -c; a positional
    # path is ignored and the process falls back to its installed config,
    # which is how a "test" reaches the host's real network. The switch moves
    # to the system config: -c here, and the file is the twin's own.
    local amf_pid upf_pid gnb_pid ue_pid
    (cd "$dir" && timeout --signal=INT "$seconds" "$amf" -c "$dir/amf.yaml") >"$dir/logs/amf.log" 2>&1 & amf_pid=$!
    ET_PIDS+=("$amf_pid")
    sleep 2; kill -0 "$amf_pid" 2>/dev/null || { et_stop_all; (( capture )) && et_capture_stop "$dir"; et_error 'AMF exited early; see logs/amf.log'; return 1; }
    if [[ -r "$dir/upf.yaml" ]]; then
        (cd "$dir" && timeout --signal=INT "$seconds" "$upf" -c "$dir/upf.yaml") >"$dir/logs/upf.log" 2>&1 & upf_pid=$!
        ET_PIDS+=("$upf_pid")
        sleep 2; kill -0 "$upf_pid" 2>/dev/null || { et_stop_all; (( capture )) && et_capture_stop "$dir"; et_error 'UPF exited early; see logs/upf.log'; return 1; }
    else
        # A UPF with no local config is not a UPF on this twin: it would read
        # the installed one. Refusing the start is better than a PDU session
        # that routes wherever the host happens to point.
        printf 'upf\tskipped (no upf.yaml here; a PDU session needs a local UPF slice)\n'
    fi
    (cd "$dir" && timeout --signal=INT "$seconds" "$gnb" -c "$dir/gnb.conf") >"$dir/logs/gnb.log" 2>&1 & gnb_pid=$!
    ET_PIDS+=("$gnb_pid")
    sleep 3; kill -0 "$gnb_pid" 2>/dev/null || { et_stop_all; (( capture )) && et_capture_stop "$dir"; et_error 'gNB exited early; see logs/gnb.log'; return 1; }
    if [[ -n "$ue" ]]; then
        (cd "$dir" && timeout --signal=INT "$seconds" "$ue" -c "$dir/ue.yaml") >"$dir/logs/ue.log" 2>&1 & ue_pid=$!
        ET_PIDS+=("$ue_pid")
    fi
    et_wait_window "$seconds"
    for p in "${ET_PIDS[@]}"; do kill -INT "$p" 2>/dev/null || :; done
    for p in "${ET_PIDS[@]}"; do
        wait "$p" 2>/dev/null
        st=$?
        case "$st" in
            0) ;;
            124|130) bounded=$((bounded + 1)) ;;
            *) rc=1 ;;
        esac
    done
    ET_PIDS=(); trap - INT TERM HUP
    (( capture )) && et_capture_stop "$dir"
    printf 'log\tamf\t%s/logs/amf.log\nlog\tgnb\t%s/logs/gnb.log\n' "$dir" "$dir"
    [[ -r "$dir/upf.yaml" ]] && printf 'log\tupf\t%s/logs/upf.log\n' "$dir"
    [[ -n "$ue" ]] && printf 'log\tue\t%s/logs/ue.log\n' "$dir"
    (( capture )) && printf 'capture\t%s\n' "$dir/evidence.pcap"

    et_evidence_from_config "$stamp" "$dir" NR "$radiorow"
    et_evidence_from_logs "$stamp" "$dir"
    (( capture )) && et_evidence_from_capture "$stamp" "$dir/evidence.pcap"
    local ids attaches
    local ev; ev="$(et_evidence_path)"
    ids=$(awk -F'\t' -v r="$stamp" 'NR>1 && $2==r && ($3=="imsi"||$3=="suci")' "$ev" 2>/dev/null | wc -l)
    attaches=$(awk -F'\t' -v r="$stamp" 'NR>1 && $2==r && $3=="procedure" && ($4=="registration-accept"||$4=="pdu-session")' "$ev" 2>/dev/null | wc -l)
    printf 'run\t%s\nstore\t%s\nidentities\t%s\nattaches\t%s\n' "$stamp" "$ev" "$ids" "$attaches"
    (( bounded == 0 )) || printf 'note\t%d service(s) stopped by the timer, not by a crash.\n' "$bounded"
    (( rc == 0 )) || printf 'note\tA service exited nonzero at bounded shutdown; inspect its log.\n'
    if (( radiate )); then
        if (( ids > 0 )); then
            printf 'result\ttwin-received-identity\n'
        elif (( attaches > 0 )); then
            printf 'result\ttwin-accepted-registration\n'
        elif grep -Eqi 'rrc setup request|preamble|initial ue|registration request' "$dir/logs/gnb.log" 2>/dev/null; then
            printf 'result\ttwin-saw-attempt\n'
        else
            printf 'result\ttwin-radiated-unanswered\n'
            et_why 'the gNB transmitted and nothing registered. Check that the recon channel is still live, that its PLMN and slice are real in this area, and that the radio reached the antenna.'
            return 1
        fi
    else
        if grep -Eiq 'Registration accept|registration complete|PDU Session Establishment Accept|PDU session established' "$dir/logs/ue.log" 2>/dev/null; then
            printf 'result\tNR-registration-marker-found\n'
        else
            printf 'result\tNR-run-finished-no-registration-marker\n'
            et_why 'Inspect configs, subscriber profile, PLMN/slice, and ZMQ channel setup.'
            return 1
        fi
    fi
    return 0
}

et_stub_bin() {  # <dir> <name> <marker>
    mkdir -p "$1" || return 1
    cat > "$1/$2" <<'STUB'
#!/bin/sh
printf '%s %s\n' "$0" "$*" >> "${ET_ARGV_LOG:-/dev/null}"
printf 'MARKER_GOES_HERE\n'
trap 'exit 0' INT TERM
while :; do sleep 0.2; done
STUB
    sed -i "s|MARKER_GOES_HERE|$3|" "$1/$2"
    chmod +x "$1/$2"
}

et_selftest() {
    local d rc=0 twin out
    d=$(mktemp -d) || return 1
    twin="$d/twin"
    mkdir -p "$twin/logs"
    et_safe_path "$d" || rc=1; et_safe_path / && rc=1

    # ── the antenna mapping, without hardware ──────────────────────────────
    [[ "$(et_rf_map hackrf | tr '\t' ' ')" == "soapy driver=hackrf" ]] || { printf 'selftest\thackrf map\n' >&2; rc=1; }
    [[ "$(et_rf_map bladerf | tr '\t' ' ')" == "soapy driver=bladerf" ]] || { printf 'selftest\tbladerf map\n' >&2; rc=1; }
    [[ "$(et_rf_map 'pluto:ip:192.168.2.1' | tr '\t' ' ')" == "soapy driver=plutosdr" ]] || { printf 'selftest\tpluto map\n' >&2; rc=1; }
    [[ "$(et_rf_map usrp | tr '\t' ' ')" == "uhd " ]] || { printf 'selftest\tuhd map\n' >&2; rc=1; }
    et_rf_map rtlsdr >/dev/null 2>&1 && { printf 'selftest\trtlsdr accepted as a twin\n' >&2; rc=1; }
    et_rf_map frobnicate >/dev/null 2>&1 && { printf 'selftest\tunknown driver accepted\n' >&2; rc=1; }

    # A roster with no TX row must refuse: a receive-only twin radiates nothing.
    printf 'rtlsdr\t1\t24\t1766\t0.9\t3.2\t0\t40\tRX\n' > "$d/roster-rx.tsv"
    printf 'hackrf\tabc\t1\t6000\t2\t20\t0\t62\tRX/TX\n' > "$d/roster-tx.tsv"
    ET_RADIO_ROWS="$d/roster-rx.tsv" et_radio_pick >/dev/null 2>&1
    [[ $? == 2 ]] || { printf 'selftest\treceive-only roster did not refuse\n' >&2; rc=1; }
    out="$(ET_RADIO_ROWS="$d/roster-tx.tsv" et_radio_pick)"
    [[ "$(printf '%s' "$out" | cut -f1)" == hackrf ]] || { printf 'selftest\tTX roster not picked\n' >&2; rc=1; }
    out="$(ET_RADIO_ROWS="$d/roster-tx.tsv" et_radio_pick nosuch)"
    [[ $? == 2 ]] || { printf 'selftest\tunmatched --radio did not refuse\n' >&2; rc=1; }

    # ── the config patch ───────────────────────────────────────────────────
    printf '[enb]\nmme_addr = 127.0.1.100\n\n[rf]\ndevice_name = auto\ndevice_args = auto\ntx_gain = 70\nrx_gain = 40\ndl_earfcn = 6300\n\n[expert]\nlte_sample_rate = 1.92e6\n' > "$twin/enb.conf"
    et_rf_patch_lte "$twin/enb.conf" soapy 'driver=hackrf' || rc=1
    grep -q '^device_name = soapy$' "$twin/enb.conf" || { printf 'selftest\tdevice_name not patched\n' >&2; rc=1; }
    grep -q '^device_args = driver=hackrf$' "$twin/enb.conf" || { printf 'selftest\tdevice_args not patched\n' >&2; rc=1; }
    printf 'gnb_id: 1\namf:\n  addr: 127.0.0.5\ncell_cfg:\n  band: n78\n  dl_arfcn: 632628\nlog:\n  filename: x.log\n' > "$twin/gnb.conf"
    et_rf_patch_nr "$twin/gnb.conf" uhd '' 60 40 || rc=1
    grep -q '^rf:$' "$twin/gnb.conf" || { printf 'selftest\trf block not inserted\n' >&2; rc=1; }
    [[ "$(grep -n '^rf:$' "$twin/gnb.conf" | cut -d: -f1)" -lt "$(grep -n '^cell_cfg:$' "$twin/gnb.conf" | cut -d: -f1)" ]] || { printf 'selftest\trf block placed after cell_cfg\n' >&2; rc=1; }
    grep -q '^  device_driver: uhd$' "$twin/gnb.conf" || { printf 'selftest\trf driver not written\n' >&2; rc=1; }

    # ── contained twins refuse to radiate and vice versa ───────────────────
    et_prepare_lte '' 1 --out / >/dev/null 2>&1; [[ $? == 2 ]] || { printf 'selftest\tprepare-lte accepted / as output\n' >&2; rc=1; }
    et_prepare_nr '' 1 --out / >/dev/null 2>&1; [[ $? == 2 ]] || { printf 'selftest\tprepare-nr accepted / as output\n' >&2; rc=1; }
    [[ "$(et_preflight_lte "$d" >/dev/null 2>&1; echo $?)" == 1 ]] || { printf 'selftest\tempty preflight-lte did not fail\n' >&2; rc=1; }
    [[ "$(et_preflight_nr "$d" >/dev/null 2>&1; echo $?)" == 1 ]] || { printf 'selftest\tempty preflight-nr did not fail\n' >&2; rc=1; }

    # ── the run, against stubs ─────────────────────────────────────────────
    # srsRAN Project and Open5GS take their file with -c; a positional path is
    # silently ignored and the process reads its installed config instead —
    # which on this host is the outside network. The stubs record argv so a
    # regression to positional makes the test fail instead of a twin that runs
    # against someone else's core.
    et_stub_bin "$d/bin" open5gs-amfd 'AMF started' || rc=1
    et_stub_bin "$d/bin" open5gs-upfd 'UPF started' || rc=1
    et_stub_bin "$d/bin" gnb 'gNB started' || rc=1
    et_stub_bin "$d/bin" nr-ue 'Registration accept' || rc=1
    et_stub_bin "$d/bin" srsepc 'EPC started' || rc=1
    et_stub_bin "$d/bin" srsenb 'eNB started' || rc=1
    et_stub_bin "$d/bin" srsue 'Attach accept IMSI=001010000000001' || rc=1
    printf 'amf:\n  ngap:\n    server_addr: 127.0.0.5\n' > "$twin/amf.yaml"
    printf 'upf:\n  gtpu_addr: 127.0.0.5\n' > "$twin/upf.yaml"
    printf 'gnb:\n  amf:\n    addr: 127.0.0.5\n' > "$twin/gnb.conf"
    printf 'ue:\n  gnb:\n    addr: 127.0.0.5\n' > "$twin/ue.yaml"
    printf 'epc:\n  mme:\n    addr: 127.0.0.1\n' > "$twin/epc.conf"
    printf 'enb:\n  mme_addr: 127.0.0.1\n' > "$twin/enb.conf"
    printf 'ue:\n  epc:\n    addr: 127.0.0.1\n' > "$twin/srsue.conf"
    printf 'cell_list:\n  - cell:\n      mme_addr: 127.0.0.1\n' > "$twin/rr.conf"
    : > "$twin/radio.tsv"

    out=$(ET_ARGV_LOG="$d/argv.log" ET_TWIN_DIR="$d/store" PATH="$d/bin:$PATH" et_run_nr "$twin" 5 2>&1)
    [[ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="result"{print $2; exit}')" == NR-registration-marker-found ]] || { printf 'selftest\tNR run did not report its marker\n' >&2; rc=1; }
    for cfg in "$twin/amf.yaml" "$twin/upf.yaml" "$twin/gnb.conf" "$twin/ue.yaml"; do
        grep -q " -c $cfg\b" "$d/argv.log" || { printf 'selftest\tNR process not launched with -c %s\n' "$cfg" >&2; rc=1; }
    done
    printf '%s\n' "$out" | grep -q '^mode[[:space:]]*contained' || { printf 'selftest\tcontained run did not say so\n' >&2; rc=1; }

    # No upf.yaml: the UPF is named as skipped, and nothing reads a config the
    # twin does not own.
    rm -f "$twin/upf.yaml" "$d/argv.log" "$twin"/logs/*.log
    out=$(ET_ARGV_LOG="$d/argv.log" ET_TWIN_DIR="$d/store" PATH="$d/bin:$PATH" et_run_nr "$twin" 5 2>&1)
    printf '%s\n' "$out" | grep -q '^upf[[:space:]]*skipped' || { printf 'selftest\tmissing UPF not reported as skipped\n' >&2; rc=1; }
    grep -q open5gs-upfd "$d/argv.log" && { printf 'selftest\tUPF started without a local slice\n' >&2; rc=1; }

    # srsRAN 4G takes its configs positionally and still finds its marker, and
    # the evidence table gets the IMSI the UE log printed.
    rm -f "$d/argv.log" "$twin"/logs/*.log
    out=$(ET_ARGV_LOG="$d/argv.log" ET_TWIN_DIR="$d/store" PATH="$d/bin:$PATH" et_run_lte "$twin" 5 2>&1)
    [[ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="result"{print $2; exit}')" == LTE-attach-marker-found ]] || { printf 'selftest\tLTE run did not report its marker\n' >&2; rc=1; }
    grep -q "^$d/bin/srsepc $twin/epc.conf$" "$d/argv.log" || { printf 'selftest\tLTE EPC not given the twin config\n' >&2; rc=1; }
    [[ -s "$d/store/evidence.tsv" ]] || { printf 'selftest\tevidence store not written\n' >&2; rc=1; }
    awk -F'\t' '$3=="imsi"{found=1} END{exit !found}' "$d/store/evidence.tsv" 2>/dev/null ||
        { printf 'selftest\tno identity evidence harvested\n' >&2; rc=1; }
    awk -F'\t' '$3=="imsi" && $4=="001010000000001"{found=1} END{exit !found}' "$d/store/evidence.tsv" 2>/dev/null ||
        { printf 'selftest\tevidence value not the one the log printed\n' >&2; rc=1; }
    head -n1 "$d/store/evidence.tsv" | grep -q '^ts.*run.*kind.*value.*source.*confidence' || { printf 'selftest\tevidence header\n' >&2; rc=1; }

    # A contained twin must refuse --radiate: nothing was prepared to radiate.
    out=$(ET_TWIN_DIR="$d/store" PATH="$d/bin:$PATH" et_run_lte "$twin" 5 --radiate 2>&1)
    [[ $? == 2 ]] || { printf 'selftest\tcontained twin radiated anyway\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q 'nothing to radiate with' || { printf 'selftest\tradiate refusal did not say why\n' >&2; rc=1; }

    # A twin prepared to radiate refuses a contained run: the config no longer
    # points at loopback, and pretending otherwise would be a silent change of
    # what the operator asked for.
    printf 'hackrf\tabc\t1\t6000\t2\t20\t0\t62\tRX/TX\n' > "$d/roster-tx.tsv"
    mkdir -p "$d/rad"
    cp "$twin/epc.conf" "$twin/rr.conf" "$twin/srsue.conf" "$d/rad/"
    printf '[enb]\nmme_addr = 127.0.1.100\n\n[rf]\ndevice_name = auto\ndevice_args = auto\ntx_gain = 70\nrx_gain = 40\ndl_earfcn = 6300\n' > "$d/rad/enb.conf"
    ET_RADIO_ROWS="$d/roster-tx.tsv" et_rf_patch_lte "$d/rad/enb.conf" soapy 'driver=hackrf' || rc=1
    printf 'hackrf\tabc\t1\t6000\t2\t20\t0\t62\tRX/TX\n' > "$d/rad/radio.tsv"
    out=$(ET_TWIN_DIR="$d/store" PATH="$d/bin:$PATH" et_run_lte "$d/rad" 5 2>&1)
    [[ $? == 2 ]] || { printf 'selftest\tradiating twin ran contained\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q 'prepared to radiate' || { printf 'selftest\tradiate/contained mismatch not named\n' >&2; rc=1; }

    # A radiating run with no phone in range must say so, not invent a success:
    # the srsue stub is not started in this mode at all.
    rm -f "$d/argv.log" "$d/rad"/logs/*.log
    out=$(ET_ARGV_LOG="$d/argv.log" ET_TWIN_DIR="$d/store" PATH="$d/bin:$PATH" et_run_lte "$d/rad" 5 --radiate 2>&1)
    [[ $? == 1 ]] || { printf 'selftest\tunanswered radiating run did not fail\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q '^mode[[:space:]]*radiate' || { printf 'selftest\tradiating run did not say its mode\n' >&2; rc=1; }
    [[ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="result"{print $2; exit}')" == twin-radiated-unanswered ]] ||
        { printf 'selftest\tunanswered radiating run claimed something else\n' >&2; rc=1; }
    grep -q "srsue" "$d/argv.log" && { printf 'selftest\ta radiating run started its own UE\n' >&2; rc=1; }

    # A service that dies on start is an error that names it, not a run.
    printf '#!/bin/sh\nexit 1\n' > "$d/bin/open5gs-amfd"
    out=$(ET_TWIN_DIR="$d/store" PATH="$d/bin:$PATH" et_run_nr "$twin" 5 2>&1); local amf_rc=$?
    [[ "$amf_rc" == 1 ]] || { printf 'selftest\tdead AMF did not fail the run\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q 'AMF exited early' || { printf 'selftest\tdead AMF did not name itself\n' >&2; rc=1; }

    # ── evidence store reads back ──────────────────────────────────────────
    out=$(ET_TWIN_DIR="$d/store" et_evidence_tsv)
    head -n1 <<< "$out" | grep -q '^ts' || { printf 'selftest\tevidence-tsv header\n' >&2; rc=1; }
    out=$(ET_TWIN_DIR="$d/nowhere" et_evidence_tsv 2>&1)
    [[ $? == 1 ]] || { printf 'selftest\tempty evidence store did not refuse politely\n' >&2; rc=1; }
    out=$(ET_TWIN_DIR="$d/store" et_cmd_evidence_collect "$twin" --rat lte 2>&1)
    printf '%s\n' "$out" | grep -q '^run[[:space:]]' || { printf 'selftest\tevidence-collect reported no run\n' >&2; rc=1; }

    rm -rf -- "$d"
    if (( rc == 0 )); then builtin printf 'selftest\tPASS\nRESULT\tPASS\n'; else builtin printf 'selftest\tFAIL\nRESULT\tFAIL\n'; return 1; fi
}

et_menu() { cat <<'EOF'
LTE / NR Evil Twin
  --prepare-lte <recon.tsv> <row> [--pci N] [--out DIR] [--radiate] [--radio DRIVER|SERIAL] [--tx-gain dB]
  --prepare-nr  <recon.tsv> <row> [--pci N] [--band n78] [--format srsran|open5gs]
                [--out DIR] [--radiate] [--radio DRIVER|SERIAL] [--tx-gain dB]
  --preflight-lte [DIR]      what the twin still needs before it can start
  --preflight-nr [DIR]
  --run-lte <DIR> [seconds] [--radiate] [--with-capture] [--iface lo]
  --run-nr  <DIR> [seconds] [--radiate] [--with-capture] [--iface lo]
  --evidence-collect <DIR> [--rat lte|nr] [--run NAME]
  --evidence-tsv [--run NAME]
  --selftest
EOF
}
et_cli() {
    local cmd="${1:-}"; (($#)) && shift
    case "$cmd" in
        --prepare-lte|--prepare) et_prepare_lte "$@" ;;
        --prepare-nr) et_prepare_nr "$@" ;;
        --preflight-lte|--preflight) et_preflight_lte "$@" ;;
        --preflight-nr) et_preflight_nr "$@" ;;
        --run-lte|--lte-test|--ota-test) et_run_lte "$@" ;;
        --run-nr|--nr-test) et_run_nr "$@" ;;
        --evidence-collect) et_cmd_evidence_collect "$@" ;;
        --evidence-tsv) et_evidence_tsv "$@" ;;
        --selftest) et_selftest ;;
        --help|-h|help|--__index_probe__|'') et_menu ;;
        *) et_error "unknown command: $cmd"; return 2 ;;
    esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then et_cli "$@"; fi
