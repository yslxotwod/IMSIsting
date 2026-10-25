#!/usr/bin/env bash
# Isolated LTE/NR simulator lab: recon-derived configs and bounded UE tests.
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
ET_LAB="${ET_LAB_DIR:-${LOOT_DIR:-$IMSISTING_ROOT/loot}/evil-twin-lab}"
et_error() { printf 'ERROR\t%s\n' "$*" >&2; }
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
et_prepare_lte() {
    local input="${1:-}" row="${2:-}" pci=1 out="$ET_LAB"
    shift 2 2>/dev/null || true
    while (($#)); do
        case "$1" in
            --pci) [[ -n "${2:-}" ]] || { et_error '--pci needs a value'; return 2; }; pci="$2"; shift 2 ;;
            --out) [[ -n "${2:-}" ]] || { et_error '--out needs a directory'; return 2; }; out="$2"; shift 2 ;;
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    [[ -f "$input" && -r "$input" ]] || { et_error 'provide a readable recon TSV'; return 2; }
    [[ "$row" =~ ^[0-9]+$ ]] && (( ${#row} <= 9 && 10#$row > 0 )) || { et_error 'row must be a positive data-row number'; return 2; }
    [[ "$pci" =~ ^[0-9]+$ ]] && (( ${#pci} <= 3 && 10#$pci <= 503 )) || { et_error 'LTE PCI must be 0..503'; return 2; }
    (( ${#input} <= 4096 && ${#out} <= 4096 )) || { et_error 'input/output path is too long'; return 2; }
    et_safe_path "$out" || { et_error 'output must be a dedicated lab directory'; return 2; }
    [[ ! -e "$out" || -d "$out" ]] || { et_error 'output path exists and is not a directory'; return 2; }
    local line
    line=$(awk -F'\t' -v n="$row" 'NR==n+1 {print; found=1; exit} END {if (!found) exit 1}' "$input") || { et_error 'row does not exist in recon TSV'; return 2; }
    [[ "$(awk -F'\t' '{print NF}' <<<"$line")" == 16 ]] || { et_error 'recon TSV row must have 16 columns'; return 2; }
    [[ "$(cut -f1 <<<"$line")" == LTE && "$(cut -f2 <<<"$line")" == 4G ]] || { et_error 'selected recon row is not LTE/4G'; return 2; }
    [[ "$line" != *'$('* && "$line" != *'`'* && "$line" != *'\\'* ]] || { et_error 'LTE row contains unsupported control syntax'; return 2; }
    ET_LAB="$out"; et_load_lte || return 1
    set +o pipefail
    LAIR_CONF="$ET_LAB/enb.conf"; LAIR_RRC="$ET_LAB/rr.conf"
    lair_cmd_clone_recon "$input" "$row" --pci "$pci" || return $?
    printf 'OK\tlab_dir=%s\nOK\tradio=LTE\nOK\tmode=config-only\n' "$ET_LAB"
}
et_prepare_nr() {
    local input="${1:-}" row="${2:-}" pci=1 out="$ET_LAB" format=srsran nrband arfcn plmn band_override=""
    shift 2 2>/dev/null || true
    while (($#)); do
        case "$1" in
            --pci) [[ -n "${2:-}" ]] || { et_error '--pci needs a value'; return 2; }; pci="$2"; shift 2 ;;
            --out) [[ -n "${2:-}" ]] || { et_error '--out needs a directory'; return 2; }; out="$2"; shift 2 ;;
            --format) [[ -n "${2:-}" ]] || { et_error '--format needs srsran or open5gs'; return 2; }; format="$2"; shift 2 ;;
            --band) [[ -n "${2:-}" ]] || { et_error '--band needs n<number>'; return 2; }; band_override="$2"; shift 2 ;;
            *) et_error "unknown option: $1"; return 2 ;;
        esac
    done
    [[ -f "$input" && -r "$input" ]] || { et_error 'provide a readable recon TSV'; return 2; }
    [[ "$row" =~ ^[0-9]+$ ]] && (( ${#row} <= 9 && 10#$row > 0 )) || { et_error 'row must be a positive data-row number'; return 2; }
    [[ "$pci" =~ ^[0-9]+$ ]] && (( ${#pci} <= 4 && 10#$pci <= 1007 )) || { et_error 'NR PCI must be 0..1007'; return 2; }
    (( ${#row} <= 9 && ${#pci} <= 4 && ${#input} <= 4096 && ${#out} <= 4096 )) || { et_error 'input/output value is too long'; return 2; } || { et_error 'input/output path is too long'; return 2; }
    [[ "$format" == srsran || "$format" == open5gs ]] || { et_error 'format must be srsran or open5gs'; return 2; }
    et_safe_path "$out" || { et_error 'output must be a dedicated lab directory'; return 2; }
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
    ET_LAB="$out"; et_load_nr || return 1
    NAIR_DIR="$out"; NAIR_CONF="$out/gnb.conf"; NAIR_LOG="$out/logs/gnb.log"
    nair_gen_gnb_conf "$plmn" "$nrband" "$arfcn" "$pci" "$out/gnb.conf" || return $?
    if [[ "$format" == open5gs ]]; then
        nair_gen_open5gs_conf "$plmn" "$tac" "$out/amf.yaml" || return $?
    fi
    printf 'OK\tlab_dir=%s\nOK\tradio=NR\nOK\tformat=%s\nOK\tmode=config-only\n' "$ET_LAB" "$format"
}
et_configs() {
    local dir="$1" kind="$2" name miss=0
    if [[ "$kind" == LTE ]]; then
        for name in epc.conf enb.conf srsue.conf; do [[ -s "$dir/$name" ]] || { et_error "missing or empty config: $dir/$name"; miss=1; }; done
        [[ -s "$dir/rr.conf" ]] || { et_error "missing or empty config: $dir/rr.conf"; miss=1; }
    else
        for name in amf.yaml gnb.conf ue.yaml; do [[ -s "$dir/$name" ]] || { et_error "missing or empty config: $dir/$name"; miss=1; }; done
    fi
    return "$miss"
}
et_preflight_lte() {
    local dir="${1:-$ET_LAB}" miss=0 t
    et_safe_path "$dir" || { et_error 'provide a dedicated lab directory'; return 2; }
    [[ -d "$dir" ]] || { et_error "lab directory not found: $dir"; return 2; }
    et_configs "$dir" LTE || { printf 'WHY\tProvide local EPC/UE configs and run --prepare-lte for RAN configs\n' >&2; return 1; }
    et_loopback_configs "$dir/epc.conf" "$dir/enb.conf" "$dir/rr.conf" "$dir/srsue.conf" || { et_error 'LTE configs must bind/connect only to loopback'; return 2; }
    for t in srsepc srsenb srsue timeout; do
        if command -v "$t" >/dev/null 2>&1; then printf 'tool\t%s\t%s\n' "$t" "$(command -v "$t")"; else printf 'missing_tool\t%s\n' "$t"; miss=1; fi
    done
    printf 'boundary\tLocal EPC/eNB and owned test UE only; preflight starts no services.\n'
    (( miss == 0 )) || { et_error 'preflight incomplete; install reported local lab tools'; return 1; }
    printf 'result\tready-for-contained-isolated-LTE-lab\n'
}
et_preflight_nr() {
    local dir="${1:-$ET_LAB}" miss=0 t
    et_safe_path "$dir" || { et_error 'provide a dedicated lab directory'; return 2; }
    [[ -d "$dir" ]] || { et_error "lab directory not found: $dir"; return 2; }
    et_configs "$dir" NR || { printf 'WHY\tProvide locally administered Open5GS AMF plus gNB and UE configs\n' >&2; return 1; }
    et_loopback_nr_configs "$dir/amf.yaml" "$dir/gnb.conf" "$dir/ue.yaml" || { et_error 'NR configs must bind/connect only to loopback'; return 2; }
    for t in open5gs-amfd open5gs-upfd gnb nr-ue; do
        if command -v "$t" >/dev/null 2>&1; then printf 'tool\t%s\t%s\n' "$t" "$(command -v "$t")"; else printf 'missing_tool\t%s\n' "$t"; miss=1; fi
    done
    printf 'boundary\tLocal 5GC/gNB and owned simulator UE only; preflight starts no services.\n'
    (( miss == 0 )) || { et_error 'preflight incomplete; install reported local simulator tools'; return 1; }
    printf 'result\tready-for-contained-isolated-NR-lab\n'
}
et_run_lte() {
    local dir="${1:-$ET_LAB}" seconds="${2:-120}" name; shift 2 2>/dev/null || true
    while (($#)); do
        case "$1" in --ack-isolated-lab) shift ;; *) et_error "unexpected LTE OTA argument: $1"; return 2 ;; esac
    done
    et_safe_path "$dir" || { et_error 'provide a dedicated lab directory'; return 2; }
    [[ -d "$dir" ]] || { et_error 'lab directory not found'; return 2; }
    et_configs "$dir" LTE || return 2
    [[ "$seconds" =~ ^[0-9]+$ ]] && (( seconds >= 5 && seconds <= 3600 )) || { et_error 'duration must be 5..3600 seconds'; return 2; }
    for name in srsepc srsenb srsue timeout; do command -v "$name" >/dev/null 2>&1 || { et_error "$name is required"; return 1; }; done
    et_loopback_configs "$dir/epc.conf" "$dir/enb.conf" "$dir/rr.conf" "$dir/srsue.conf" || { et_error 'LTE configs must bind/connect only to loopback'; return 2; }
    local epc enb ue p w st rc=0 bounded=0
    epc=$(command -v srsepc); enb=$(command -v srsenb); ue=$(command -v srsue)
    mkdir -p "$dir/logs" || return 1
    ET_PIDS=(); trap 'et_stop_all' INT TERM HUP
    printf 'boundary\tLocal test EPC/eNB and owned test UE only; use a channel emulator or RF-contained cabled setup. Config guard requires loopback peers.\n'
    (cd "$dir" && timeout --signal=INT "$seconds" "$epc" "$dir/epc.conf") >"$dir/logs/epc.log" 2>&1 & ET_PIDS+=("$!")
    sleep 2; kill -0 "${ET_PIDS[0]}" 2>/dev/null || { et_stop_all; et_error 'EPC exited early; see logs/epc.log'; return 1; }
    (cd "$dir" && timeout --signal=INT "$seconds" "$enb" "$dir/enb.conf") >"$dir/logs/enb.log" 2>&1 & ET_PIDS+=("$!")
    sleep 3; kill -0 "${ET_PIDS[1]}" 2>/dev/null || { et_stop_all; et_error 'eNB exited early; see logs/enb.log'; return 1; }
    (cd "$dir" && timeout --signal=INT "$seconds" "$ue" "$dir/srsue.conf") >"$dir/logs/ue.log" 2>&1 & ET_PIDS+=("$!")
    sleep "$seconds"
    for p in "${ET_PIDS[@]}"; do kill -INT "$p" 2>/dev/null || :; done
    for p in "${ET_PIDS[@]}"; do
        wait "$p" 2>/dev/null
        st=$?
        case "$st" in
            0) ;;
            124|130) bounded=$((bounded + 1)) ;;   # timeout's own INT, normal
            *) rc=1 ;;
        esac
    done
    ET_PIDS=(); trap - INT TERM HUP
    printf 'log\tepc\t%s/logs/epc.log\nlog\tenb\t%s/logs/enb.log\nlog\tue\t%s/logs/ue.log\n' "$dir" "$dir" "$dir"
    if grep -Eiq 'attach accept|attached|pdn connectivity accept|RRC connected' "$dir/logs/ue.log"; then printf 'result\tLTE-attach-marker-found\n'; else printf 'result\tLTE-test-finished-no-attach-marker\nWHY\tInspect logs, matching test-SIM credentials, channel plan, and containment.\n'; return 1; fi
    (( bounded == 0 )) || printf 'note\t%d service(s) stopped by the timer, not by a crash.\n' "$bounded"
    (( rc == 0 )) || printf 'note\tA service exited nonzero at bounded shutdown; inspect its log.\n'
}
et_stop_all() {
    local p
    for p in "${ET_PIDS[@]:-}"; do kill -INT "$p" 2>/dev/null || :; done
    for p in "${ET_PIDS[@]:-}"; do wait "$p" 2>/dev/null || :; done
    ET_PIDS=()
}
et_loopback_configs() {
    local file line key value found total=0
    for file in "$@"; do
        [[ -r "$file" ]] || return 1
        found=0
        while IFS= read -r line; do
            line="${line%%#*}"
            [[ "$line" =~ ^[[:space:]]*([[:alnum:]_-]*(addr|address|bind|host|server|client|peer)[[:alnum:]_-]*)[[:space:]]*[:=][[:space:]]*[\"\']?([^[:space:]\"\']+) ]] || continue
            key="${BASH_REMATCH[1],,}"
            value="${BASH_REMATCH[3]%%,*}"
            value="${value#tcp://}"; value="${value#udp://}"
            case "$key" in *port*|*domain*|*interface*|*path*|*plmn*|*mcc*|*mnc*) continue ;; esac
            [[ "$value" == *:* && "$value" != *://* ]] && value="${value%%:*}"
            found=1; ((total++))
            if [[ "$value" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
                [[ "$value" == 127.* ]] || return 1
            elif [[ "$value" =~ ^(localhost|.*\.localhost)$ ]]; then
                :
            else
                return 1
            fi
        done < "$file"
        (( found == 1 )) || return 1
    done
    (( total > 0 ))
}
et_loopback_nr_configs() {
    et_loopback_configs "$@" || return 1
    grep -Eiq '127\.|localhost' "$1" && grep -Eiq '127\.|localhost' "$2" && grep -Eiq '127\.|localhost' "$3"
}
et_run_nr() {
    local dir="${1:-$ET_LAB}" seconds="${2:-120}" name; shift 2 2>/dev/null || true
    while (($#)); do
        case "$1" in --ack-isolated-lab) shift ;; *) et_error "unexpected NR test argument: $1"; return 2 ;; esac
    done
    et_safe_path "$dir" || { et_error 'provide a dedicated lab directory'; return 2; }
    [[ -d "$dir" ]] || { et_error 'lab directory not found'; return 2; }
    et_configs "$dir" NR || return 2
    [[ -r "$dir/gnb.conf" && -r "$dir/ue.yaml" ]] || { et_error 'NR gNB/UE configs must be readable'; return 2; }
    [[ "$seconds" =~ ^[0-9]+$ ]] && (( seconds >= 5 && seconds <= 3600 )) || { et_error 'duration must be 5..3600 seconds'; return 2; }
    for name in open5gs-amfd open5gs-upfd gnb nr-ue timeout; do command -v "$name" >/dev/null 2>&1 || { et_error "$name is required"; return 1; }; done
    et_loopback_nr_configs "$dir/amf.yaml" "$dir/gnb.conf" "$dir/ue.yaml" || { et_error 'NR configs must bind/connect only to loopback'; return 2; }
    et_loopback_nr_configs "$dir/amf.yaml" "$dir/gnb.conf" "$dir/ue.yaml" || { et_error 'NR configs must bind/connect only to loopback'; return 2; }
    local amf upf gnb ue p w st rc=0 bounded=0
    amf=$(command -v open5gs-amfd); upf=$(command -v open5gs-upfd); gnb=$(command -v gnb); ue=$(command -v nr-ue)
    mkdir -p "$dir/logs" || return 1
    ET_PIDS=(); trap 'et_stop_all' INT TERM HUP
    printf 'conf\tamf=%s gnb=%s ue=%s\n' "$dir/amf.yaml" "$dir/gnb.conf" "$dir/ue.yaml"
    # Open5GS and srsRAN Project both take their file with -c; a positional
    # path is ignored and the process falls back to its installed config,
    # which is how a "lab" run reaches the host's real network. The switch
    # moves to the system config: -c here, and the file is the lab's own.
    local amf_pid upf_pid gnb_pid ue_pid
    (cd "$dir" && timeout --signal=INT "$seconds" "$amf" -c "$dir/amf.yaml") >"$dir/logs/amf.log" 2>&1 & amf_pid=$!
    ET_PIDS+=("$amf_pid")
    sleep 2; kill -0 "$amf_pid" 2>/dev/null || { et_stop_all; et_error 'AMF exited early; see logs/amf.log'; return 1; }
    if [[ -r "$dir/upf.yaml" ]]; then
        (cd "$dir" && timeout --signal=INT "$seconds" "$upf" -c "$dir/upf.yaml") >"$dir/logs/upf.log" 2>&1 & upf_pid=$!
        ET_PIDS+=("$upf_pid")
        sleep 2; kill -0 "$upf_pid" 2>/dev/null || { et_stop_all; et_error 'UPF exited early; see logs/upf.log'; return 1; }
    else
        # A UPF with no lab config is not a UPF on the lab network: it would
        # read the installed one. Refusing the start is better than a PDU
        # session that routes wherever the host happens to point.
        printf 'upf\tskipped (no upf.yaml in the lab; a PDU session needs a local UPF slice)\n'
    fi
    (cd "$dir" && timeout --signal=INT "$seconds" "$gnb" -c "$dir/gnb.conf") >"$dir/logs/gnb.log" 2>&1 & gnb_pid=$!
    ET_PIDS+=("$gnb_pid")
    sleep 3; kill -0 "$gnb_pid" 2>/dev/null || { et_stop_all; et_error 'gNB exited early; see logs/gnb.log'; return 1; }
    (cd "$dir" && timeout --signal=INT "$seconds" "$ue" -c "$dir/ue.yaml") >"$dir/logs/ue.log" 2>&1 & ue_pid=$!
    ET_PIDS+=("$ue_pid")
    sleep "$seconds"
    for p in "${ET_PIDS[@]}"; do kill -INT "$p" 2>/dev/null || :; done
    for p in "${ET_PIDS[@]}"; do
        wait "$p" 2>/dev/null
        st=$?
        case "$st" in
            0) ;;
            124|130) bounded=$((bounded + 1)) ;;   # timeout's own INT, normal
            *) rc=1 ;;
        esac
    done
    ET_PIDS=(); trap - INT TERM HUP
    printf 'log\tamf\t%s/logs/amf.log\nlog\tupf\t%s/logs/upf.log\nlog\tgnb\t%s/logs/gnb.log\nlog\tue\t%s/logs/ue.log\n' "$dir" "$dir" "$dir" "$dir"
    if grep -Eiq 'Registration accept|registration complete|PDU Session Establishment Accept|PDU session established' "$dir/logs/ue.log"; then printf 'result\tNR-registration-marker-found\n'; else printf 'result\tNR-test-finished-no-registration-marker\nWHY\tInspect configs, subscriber profile, PLMN/slice, and ZMQ channel setup.\n'; return 1; fi
    (( bounded == 0 )) || printf 'note\t%d service(s) stopped by the timer, not by a crash.\n' "$bounded"
    (( rc == 0 )) || printf 'note\tA service exited nonzero at bounded shutdown; inspect its log.\n'
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
    local d rc=0 lab out
    d=$(mktemp -d) || return 1
    lab="$d/lab"
    mkdir -p "$lab/logs"
    et_safe_path "$d" || rc=1; et_safe_path / && rc=1
    et_prepare_lte '' 1 --out / >/dev/null 2>&1; [[ $? == 2 ]] || rc=1
    et_prepare_nr '' 1 --out / >/dev/null 2>&1; [[ $? == 2 ]] || rc=1
    [[ "$(et_preflight_lte "$d" >/dev/null 2>&1; echo $?)" == 1 ]] || rc=1
    [[ "$(et_preflight_nr "$d" >/dev/null 2>&1; echo $?)" == 1 ]] || rc=1

    # ── the transmit half, against stubs ────────────────────────────────────
    # srsRAN Project and Open5GS take their file with -c; a positional path is
    # silently ignored and the process reads its installed config instead —
    # which on this host is the outside network. The stubs record argv so a
    # regression to positional makes the test fail instead of a lab that runs
    # against someone else's core.
    et_stub_bin "$d/bin" open5gs-amfd 'AMF started' || rc=1
    et_stub_bin "$d/bin" open5gs-upfd 'UPF started' || rc=1
    et_stub_bin "$d/bin" gnb 'gNB started' || rc=1
    et_stub_bin "$d/bin" nr-ue 'Registration accept' || rc=1
    et_stub_bin "$d/bin" srsepc 'EPC started' || rc=1
    et_stub_bin "$d/bin" srsenb 'eNB started' || rc=1
    et_stub_bin "$d/bin" srsue 'Attach accept' || rc=1
    printf 'amf:\n  ngap:\n    server_addr: 127.0.0.5\n' > "$lab/amf.yaml"
    printf 'upf:\n  gtpu_addr: 127.0.0.5\n' > "$lab/upf.yaml"
    printf 'gnb:\n  amf:\n    addr: 127.0.0.5\n' > "$lab/gnb.conf"
    printf 'ue:\n  gnb:\n    addr: 127.0.0.5\n' > "$lab/ue.yaml"
    printf 'epc:\n  mme:\n    addr: 127.0.0.1\n' > "$lab/epc.conf"
    printf 'enb:\n  mme_addr: 127.0.0.1\n' > "$lab/enb.conf"
    printf 'ue:\n  epc:\n    addr: 127.0.0.1\n' > "$lab/srsue.conf"
    printf 'cell_list:\n  - cell:\n      mme_addr: 127.0.0.1\n' > "$lab/rr.conf"

    out=$(ET_ARGV_LOG="$d/argv.log" PATH="$d/bin:$PATH" et_run_nr "$lab" 5 2>&1)
    [[ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="result"{print $2; exit}')" == NR-registration-marker-found ]] || { printf 'selftest\tNR run did not report its marker\n' >&2; rc=1; }
    for cfg in "$lab/amf.yaml" "$lab/upf.yaml" "$lab/gnb.conf" "$lab/ue.yaml"; do
        grep -q " -c $cfg\b" "$d/argv.log" || { printf 'selftest\tNR process not launched with -c %s\n' "$cfg" >&2; rc=1; }
    done

    # No upf.yaml: the UPF is named as skipped, and nothing reads a config the
    # lab does not own.
    rm -f "$lab/upf.yaml" "$d/argv.log" "$lab"/logs/*.log
    out=$(ET_ARGV_LOG="$d/argv.log" PATH="$d/bin:$PATH" et_run_nr "$lab" 5 2>&1)
    printf '%s\n' "$out" | grep -q '^upf[[:space:]]*skipped' || { printf 'selftest\tmissing UPF not reported as skipped\n' >&2; rc=1; }
    [[ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="result"{print $2; exit}')" == NR-registration-marker-found ]] || rc=1
    grep -q open5gs-upfd "$d/argv.log" && { printf 'selftest\tUPF started without a lab slice\n' >&2; rc=1; }

    # The LTE lab passes its configs positionally, which is what srsRAN 4G
    # reads, and still finds its own attach marker.
    rm -f "$d/argv.log" "$lab"/logs/*.log
    out=$(ET_ARGV_LOG="$d/argv.log" PATH="$d/bin:$PATH" et_run_lte "$lab" 5 2>&1)
    [[ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="result"{print $2; exit}')" == LTE-attach-marker-found ]] || { printf 'selftest\tLTE run did not report its marker\n' >&2; rc=1; }
    grep -q "^$d/bin/srsepc $lab/epc.conf$" "$d/argv.log" || { printf 'selftest\tLTE EPC not given its lab config\n' >&2; rc=1; }

    # A service that dies on start is an error that names it, not a run.
    printf '#!/bin/sh\nexit 1\n' > "$d/bin/open5gs-amfd"
    out=$(PATH="$d/bin:$PATH" et_run_nr "$lab" 5 2>&1); local amf_rc=$?
    [[ "$amf_rc" == 1 ]] || { printf 'selftest\tdead AMF did not fail the run\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q 'AMF exited early' || { printf 'selftest\tdead AMF did not name itself\n' >&2; rc=1; }

    rm -rf -- "$d"
    if (( rc == 0 )); then builtin printf 'selftest\tPASS\nRESULT\tPASS\n'; else builtin printf 'selftest\tFAIL\nRESULT\tFAIL\n'; return 1; fi
}
et_menu() { cat <<'EOF'
Isolated LTE/NR Lab
  --prepare-lte <recon.tsv> <row> [--pci N] [--out DIR]
  --prepare-nr <recon.tsv> <row> [--pci N] [--band n78] [--format srsran|open5gs] [--out DIR]
  --preflight-lte [DIR]  (local srsEPC/eNB/test-UE prerequisites)
  --preflight-nr [DIR]   (local Open5GS/gNB/simulator-UE prerequisites)
  --lte-test <DIR> [seconds] (bounded local LTE attach; no flag needed)
  --nr-test <DIR> [seconds] (bounded local 5G registration; no flag needed)
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
        --lte-test|--ota-test) et_run_lte "$@" ;;
        --nr-test) et_run_nr "$@" ;;
        --selftest) et_selftest ;;
        --help|-h|help|--__index_probe__|'') et_menu ;;
        *) et_error "unknown command: $cmd"; return 2 ;;
    esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then et_cli "$@"; fi
