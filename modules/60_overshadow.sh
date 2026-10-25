#!/usr/bin/env bash
# overshadow — the attack that is not a fake base station.
#
# AdaptOver (arXiv 2106.05039, MobiCom 2022) does not imitate a tower. It
# listens to the live link, works out which subframe carries the message it
# wants to change, and transmits on that resource at that instant with slightly
# more power than the genuine transmitter. The victim stays camped on the real
# cell, so every rogue-base-station detector has nothing to look at: neither
# CellularPrivacy nor SnoopSnitch saw it (paper section 5.6).
#
# WHAT IS HERE, AND WHAT IS NOT. Everything in this module is analysis and
# planning: subframe maps, a timing budget, a power budget, a detector and a
# schedule. Nothing here keys a transmitter — this tree has no PHY transmit
# path, and `--transmit` refuses by name rather than pretending otherwise. The
# published implementation is srsUE with fourteen lines changed (paper section
# 4.2), which is a real-time software stack, not a bash module.
#
# The hardware is smaller than folklore says. Paper section 5.1.2: one USRP
# B210 over USB 3.0, two Qorvo TQP9111-PCB2600 amplifier boards on 5 V, a
# dielectric duplexer for the uplink attacker, a Mikrotik mANT LTE 5o 5 dBi
# antenna, and no external amplification at all inside a shielded lab. Power
# measured on the air: 29 dBm per port for 50 m of downlink, 28.5 dBm per port
# with a 5.73 us timing advance for 398 m of uplink in urban NLOS, 14.2 dBm per
# port still working over a lake. That is a low-power attack, and the point of
# it is that it cannot be found by looking for a loud one.
#
# The distinction that matters for authorisation: uplink overshadowing hits the
# resource blocks of one victim, so only that victim degrades. Downlink
# overshadowing is on the same frequency it receives on, so all reference
# signals of the cell are overshadowed and every user in the cell degrades —
# the paper only ran it in a shielded box or on an empty field. `--plan
# --mode dl` says so on every row it prints, and `--collateral` states it again.
#
# Read-only: no radio, no root, no network. Tier 0 analysis, Tier 3/4 delivery.
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _osh_src="${BASH_SOURCE[0]}"
    while [ -L "$_osh_src" ]; do
        _osh_dir="$(cd -P "$(dirname "$_osh_src")" && pwd)"
        _osh_tgt="$(readlink "$_osh_src")"
        [[ "$_osh_tgt" != /* ]] && _osh_tgt="$_osh_dir/$_osh_tgt"
        _osh_src="$_osh_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_osh_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _osh_src _osh_dir _osh_tgt
fi
if [[ -n "${IMSISTING_ROOT:-}" ]]; then
    _osh_home="$(dirname "$IMSISTING_ROOT")"
    if [[ -n "$_osh_home" && -d "$_osh_home" && "$HOME" != "$_osh_home" ]]; then
        export HOME="$_osh_home"
    fi
    unset _osh_home
fi
: "${IMSISTING_HOME:=$IMSISTING_ROOT}"
: "${TMP_DIR:=/tmp/imsisting}"
: "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
: "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
: "${STATE_DIR:=$IMSISTING_ROOT/state}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null

MOD_TMP="$TMP_DIR/overshadow"
OSH_DIR="$LOOT_DIR/overshadow"
mkdir -p "$MOD_TMP" "$OSH_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

# ── constants ────────────────────────────────────────────────────────────
# LTE: 30720 Ts per subframe, Ts = 1/30720000 s. Everything below is derived
# from those two numbers plus the FDD frame structure (TS 36.211 4).
readonly OSH_TS_PER_SUBFRAME=30720
readonly OSH_TS_HZ=30720000
readonly OSH_SUBFRAMES_PER_FRAME=10
# Normal cyclic prefix (TS 36.211 Table 5.2.1-1): the first symbol of a slot is
# 5.21 us, the other six are 4.69 us. The longer one is the alignment budget
# that matters, because a receiver tolerates an echo inside its own prefix.
readonly OSH_CP_FIRST_US=5.21
readonly OSH_CP_US=4.69
readonly OSH_SYMBOL_US=71.43
readonly OSH_SLOT_US=500.0
readonly OSH_SUBFRAME_US=1000.0

# The published attacker queues a message for transmission no earlier than 2 ms
# before the instant it must go out (paper section 4.2), which is the window
# this module budgets against.
readonly OSH_QUEUE_US=2000

osh_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

osh_isnum() {
    [[ -n "${1:-}" ]] || return 1
    printf '%s' "$1" | grep -Eq '^-?[0-9]+(\.[0-9]+)?$'
}

osh_need_num() {
    osh_isnum "${2:-}" && return 0
    printf 'ERROR\t%s is not a number: %s\n' "$1" "$(osh_sanitize "${2:-}")" >&2
    return 2
}

# Decimal formatting without depending on bc: awk does the arithmetic.
osh_fmt() {
    local val="$1" dec="${2:-2}"
    awk -v v="$val" -v d="$dec" 'BEGIN{ if (d == 0) printf "%d", v; else printf "%.*f", d, v }'
}

# ── status / info ────────────────────────────────────────────────────────
osh_status_tsv() {
    printf 'MODULE\tovershadow\n'
    printf 'TARGET\tovershadowing (AdaptOver): subframe map, timing, power, detection, plan\n'
    printf 'TRANSMIT\tnone — analysis and planning only; --transmit refuses by name\n'
    printf 'SELFTEST\tyes\n'
}

osh_info() {
    cat <<'EOF'
overshadow — the attack that is not a fake base station.

AdaptOver does not transmit like a tower. It receives the live downlink, learns
which subframe carries the message it wants to replace, and is louder than the
genuine transmitter for exactly that subframe. The victim stays camped on the
real cell, so a rogue-base-station detector has nothing to see.

What this module does (all Tier 0, no radio):
  --needs [radio]      the published bill of materials and what each SDR can do
  --timing-budget      receive instant to transmit instant, against 2 ms and CP
  --power-budget       the two cases that make downlink loud and uplink surgical
  --subframe-map FILE  which subframe and RBs carry which message, from a map
  --detect FILE        four detectors, none of which is a loud-signal detector
  --plan TARGET        a sample-indexed schedule; it plans, it does not key
  --collateral         why downlink mode degrades every user in the cell

What it does not do: key a radio. There is no PHY transmit path in this tree,
and the published implementation is srsUE with fourteen lines changed behind a
real-time downlink decoder — a software integration job on srsRAN.

Ref: AdaptOver, arXiv 2106.05039 / MobiCom 2022 10.1145/3495243.3560525.
EOF
}

# ── the bill of materials ────────────────────────────────────────────────
# Paper section 5.1.2 is the authority for every row here; the radio matrix is
# the capability that decides whether one box can both listen and transmit.
osh_needs() {
    local radio="${1:-b210}" kind ch dpx iso note
    case "$radio" in
        b210)      kind="USRP B210"; ch="2 TX / 2 RX shared LO"; dpx="full duplex"; iso="needs a duplexer when TX and RX are on different bands, which is the uplink case"; note="the radio the paper used, over USB 3.0 to an i7-11800H laptop" ;;
        b205mini)  kind="USRP B205mini-i"; ch="1 TX / 1 RX"; dpx="full duplex"; iso="one port each, so a duplexer is mandatory for the uplink case"; note="enough for a single-victim uplink overshadow, loses the multi-UE-on-one-PHY trick" ;;
        x310)      kind="USRP X310 + UBX/LWB"; ch="2 TX / 2 RX"; dpx="full duplex"; iso="best isolation of the three, which is what the same-frequency downlink case needs"; note="five to ten times the cost for a case that also degrades a whole cell" ;;
        pluto)     kind="ADALM-PLUTO"; ch="1 TX / 1 RX"; dpx="full duplex (AD9363)"; iso="USB 2 streaming jitter fights a 2 ms scheduling window"; note="cheapest, and nobody has published this attack running on it; treat as an experiment" ;;
        *) printf 'ERROR\tunknown radio: %s\n' "$(osh_sanitize "$radio")" >&2
           printf 'WHY\tthis module knows the radios the attack has actually been run on\n' >&2
           printf 'FIX\t--needs b210 | b205mini | x310 | pluto\n' >&2
           return 2 ;;
    esac
    printf 'radio\t%s\n' "$kind"
    printf 'channels\t%s\n' "$ch"
    printf 'duplex\t%s\n' "$dpx"
    printf 'isolation\t%s\n' "$iso"
    printf 'radio_note\t%s\n' "$note"
    printf 'amplifier\t2 x Qorvo TQP9111-PCB2600 evaluation board, 5 V supply\n'
    printf 'filter\tone dielectric duplexer (open-cells design) for the uplink attacker; none for downlink, which is the same frequency both ways\n'
    printf 'antenna\tMikrotik mANT LTE 5o, 5 dBi; the downlink attacker puts a second 2x2 antenna on the receive port\n'
    printf 'host\tlaptop, USB 3.0, one core per attack UE stack\n'
    printf 'lab\tAmarisoft Callbox in a shielded box needs no external amplification at all\n'
    printf 'power_envelope\t14.2 dBm to 29 dBm per port across every measurement in the paper\n'
    printf 'reference_ue_power\t23 dBm (a handset)\n'
    printf 'reference_cell_power\t47 dBm and up: the paper notes base stations run on the order of 50 watts\n'
    printf 'specialized_hardware\tnone: section 3.1 states COTS only, no low latency processing beyond it\n'
    printf 'software\treal-time downlink decoder plus several UE stacks on one PHY (srsUE, 14 lines changed for the published proof of concept)\n'
    printf 'missing_here\tthe PHY transmit path: --transmit refuses rather than pretending a plan is a signal\n'
    printf 'detection\tpublished: CellularPrivacy (Huawei P40) and SnoopSnitch (rooted Nexus 5X) both missed it\n'
    printf 'ref\tarXiv 2106.05039 sections 3.1, 4.2, 5.1.2, 5.6\n'
}

# ── timing budget ────────────────────────────────────────────────────────
# A plan is not a transmission: this is the arithmetic that decides whether a
# given stack could ever hit the instant. Two budgets matter and they are not
# the same one — the 2 ms queue window is how far ahead the message must be
# ready, and the cyclic prefix is how far off the transmitted instant may be
# before the receiver simply sees interference.
osh_timing_budget() {
    local encode=200 usb=400 pa=50 jitter=300 queue=$OSH_QUEUE_US cp=$OSH_CP_US
    while (($#)); do
        case "$1" in
            --encode-us) osh_need_num --encode-us "${2:-}" || return 2; encode="$2"; shift 2 ;;
            --usb-us)    osh_need_num --usb-us "${2:-}"    || return 2; usb="$2";    shift 2 ;;
            --pa-rise-us) osh_need_num --pa-rise-us "${2:-}" || return 2; pa="$2";   shift 2 ;;
            --jitter-us) osh_need_num --jitter-us "${2:-}" || return 2; jitter="$2"; shift 2 ;;
            --queue-us)  osh_need_num --queue-us "${2:-}"  || return 2; queue="$2";  shift 2 ;;
            --cp-us)     osh_need_num --cp-us "${2:-}"     || return 2; cp="$2";     shift 2 ;;
            *) printf 'ERROR\tunknown option: %s\n' "$(osh_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    local spent margin verdict binding
    spent=$(awk -v a="$encode" -v b="$usb" -v c="$pa" -v d="$jitter" 'BEGIN{printf "%.1f", a+b+c+d}')
    margin=$(awk -v q="$queue" -v s="$spent" 'BEGIN{printf "%.1f", q-s}')
    printf 'queue_window_us\t%s\n' "$(osh_fmt "$queue" 1)"
    printf 'encode_us\t%s\n' "$(osh_fmt "$encode" 1)"
    printf 'host_to_sdr_us\t%s\n' "$(osh_fmt "$usb" 1)"
    printf 'pa_rise_us\t%s\n' "$(osh_fmt "$pa" 1)"
    printf 'scheduler_jitter_us\t%s\n' "$(osh_fmt "$jitter" 1)"
    printf 'spent_us\t%s\n' "$spent"
    printf 'margin_us\t%s\n' "$margin"
    printf 'cp_us\t%s\n' "$(osh_fmt "$cp" 2)"
    printf 'cp_first_symbol_us\t%s\n' "$(osh_fmt "$OSH_CP_FIRST_US" 2)"
    printf 'alignment_tolerance_us\t%s\n' "$(awk -v c="$cp" 'BEGIN{printf "%.2f", c/2}')"
    printf 'ta_unit_us\t%s\n' "$(awk -v h="$OSH_TS_HZ" 'BEGIN{printf "%.4f", 16*1000000/h}')"
    printf 'ta_unit_note\t16 Ts is 0.52 us, so a network TA command cannot steer the attacker: it sets a static advance and ignores them\n'
    # The binding constraint is the tighter of the two budgets, and saying
    # which one is binding is the whole point of printing both.
    binding=$(awk -v m="$margin" -v c="$cp" 'BEGIN{ if (m < c) print "queue" ; else print "cp" }')
    verdict="fits"
    awk -v m="$margin" 'BEGIN{ exit !(m > 0) }' || verdict="does_not_fit_the_queue_window"
    printf 'binding_constraint\t%s\n' "$binding"
    printf 'verdict\t%s\n' "$verdict"
    printf 'limit\tthis is a budget, not a measurement: the numbers are the stack you would build, not a latency anyone measured here\n'
}

# ── power budget ─────────────────────────────────────────────────────────
# Log-distance path loss, PL = 32.44 + 20 log10(f MHz) + 10 n log10(d km).
# The two cases are asymmetric and that asymmetry is the finding:
#   uplink   — the attacker has to beat one handset at the base station, and
#              power control keeps that handset quiet, so the required power is
#              small and roughly independent of where the attacker stands;
#   downlink — the attacker has to beat a 50 W base station at the victim, so
#              the required power is set by the cell, not by the attacker, and
#              the range collapses to tens of metres.
osh_power_budget() {
    local mode="dl" freq=2100 n=2.7 gain=5 ue=23 cell=47 margin=6
    local cell_km=0.5 range_km="" max_dbm=29 att_km="" vic_km="" 
    while (($#)); do
        case "$1" in
            --mode)   mode="${2:-}"; shift 2 ;;
            --freq-mhz) osh_need_num --freq-mhz "${2:-}" || return 2; freq="$2"; shift 2 ;;
            --path-loss-exponent) osh_need_num --path-loss-exponent "${2:-}" || return 2; n="$2"; shift 2 ;;
            --attacker-gain-dbi) osh_need_num --attacker-gain-dbi "${2:-}" || return 2; gain="$2"; shift 2 ;;
            --ue-power-dbm) osh_need_num --ue-power-dbm "${2:-}" || return 2; ue="$2"; shift 2 ;;
            --cell-power-dbm) osh_need_num --cell-power-dbm "${2:-}" || return 2; cell="$2"; shift 2 ;;
            --margin-db) osh_need_num --margin-db "${2:-}" || return 2; margin="$2"; shift 2 ;;
            --cell-km) osh_need_num --cell-km "${2:-}" || return 2; cell_km="$2"; shift 2 ;;
            --range-km) osh_need_num --range-km "${2:-}" || return 2; range_km="$2"; shift 2 ;;
            --attacker-km) osh_need_num --attacker-km "${2:-}" || return 2; att_km="$2"; shift 2 ;;
            --victim-km)   osh_need_num --victim-km "${2:-}"   || return 2; vic_km="$2"; shift 2 ;;
            --max-power-dbm) osh_need_num --max-power-dbm "${2:-}" || return 2; max_dbm="$2"; shift 2 ;;
            *) printf 'ERROR\tunknown option: %s\n' "$(osh_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    case "$mode" in ul|dl) ;; *) printf 'ERROR\t--mode takes ul or dl\n' >&2; return 2 ;; esac
    printf 'mode\t%s\n' "$mode"
    printf 'model\tlog-distance: PL = 32.44 + 20 log10(f_MHz) + 10 n log10(d_km)\n'
    printf 'freq_mhz\t%s\n' "$(osh_fmt "$freq" 0)"
    printf 'path_loss_exponent\t%s\n' "$(osh_fmt "$n" 2)"
    printf 'attacker_gain_dbi\t%s\n' "$(osh_fmt "$gain" 1)"
    printf 'margin_db\t%s\n' "$(osh_fmt "$margin" 1)"

    local pl1 required eirp_att d_km att_tx
    pl1=$(awk -v f="$freq" 'BEGIN{printf "%.2f", 32.44 + 20*log(f)/log(10)}')
    printf 'free_space_1km_plus_freq_db\t%s\n' "$pl1"

    if [[ "$mode" == "ul" ]]; then
        # Beat the victim handset AT THE BASE STATION. The receiver power does
        # not matter on its own: what matters is the difference between the two
        # paths, which is why an attacker standing next to the victim needs
        # about a handset power and an attacker standing far away does not.
        local delta
        if [[ -n "$att_km" && -n "$vic_km" ]]; then
            delta=$(awk -v p="$pl1" -v n="$n" -v a="$att_km" -v v="$vic_km" '
                BEGIN{ printf "%.2f", 10*n*(log(a)-log(v))/log(10) }')
        else
            delta="0.00"
        fi
        required=$(awk -v u="$ue" -v m="$margin" -v d="$delta" 'BEGIN{printf "%.2f", u+m+d}')
        printf 'victim_ue_power_dbm	%s
' "$(osh_fmt "$ue" 1)"
        printf 'path_loss_delta_db	%s
' "$delta"
        printf 'required_attacker_tx_dbm	%s
' "$required"
        printf 'required_note	the differential term is PL(attacker to cell) minus PL(victim to cell): stand next to the victim and it vanishes
'
        printf 'why	power control keeps a nearby handset quiet, so this number stays small wherever the attacker stands
'
        printf 'attacker_eirp_dbm	%s
' "$(awk -v r="$required" -v g="$gain" 'BEGIN{printf "%.2f", r+g}')"
        printf 'paper_measured_dbm	28.5 per port at 398 m urban NLOS; 14.2 per port at long range over a lake
'
        printf 'paper_delta_db	%s
' "$(awk -v r="$required" -v p=28.5 'BEGIN{printf "%+.2f", r-p}')"
        printf 'verdict	uplink_overshadow_is_low_power
'
    else
        # Beat the cell at the victim: the cell sets the required power.
        local pl_cell rx_at_victim
        pl_cell=$(awk -v p="$pl1" -v n="$n" -v d="$cell_km" 'BEGIN{printf "%.2f", p + 10*n*log(d)/log(10)}')
        rx_at_victim=$(awk -v c="$cell" -v p="$pl_cell" 'BEGIN{printf "%.2f", c-p}')
        required=$(awk -v r="$rx_at_victim" -v m="$margin" 'BEGIN{printf "%.2f", r+m}')
        printf 'cell_power_dbm\t%s\n' "$(osh_fmt "$cell" 1)"
        printf 'cell_to_victim_km\t%s\n' "$(osh_fmt "$cell_km" 3)"
        printf 'cell_to_victim_pl_db\t%s\n' "$pl_cell"
        printf 'cell_at_victim_dbm\t%s\n' "$rx_at_victim"
        printf 'required_at_victim_dbm\t%s\n' "$required"
        printf 'why\tthe receiver is the phone and the competitor is the tower, so the power needed is set by the cell and not by the attacker\n'
        # Range the attacker achieves with a given transmit power.
        d_km=$(awk -v mx="$max_dbm" -v g="$gain" -v r="$required" -v p="$pl1" -v n="$n" '
            BEGIN{
                pl = mx + g - r;
                if (pl <= 0) { print "0.000"; exit }
                printf "%.3f", exp((pl - p)/(10*n)*log(10))
            }')
        printf 'attacker_max_power_dbm\t%s\n' "$(osh_fmt "$max_dbm" 1)"
        printf 'attacker_eirp_dbm\t%s\n' "$(awk -v mx="$max_dbm" -v g="$gain" 'BEGIN{printf "%.2f", mx+g}')"
        printf 'attacker_range_km\t%s\n' "$d_km"
        printf 'attacker_range_m\t%s\n' "$(awk -v d="$d_km" 'BEGIN{printf "%.0f", d*1000}')"
        printf 'paper_measured_dbm\t29 per port reaching 50 m in an urban open field\n'
        printf 'paper_model_check_m\t%s\n' "$(awk -v mx=29 -v g=5 -v r="$required" -v p="$pl1" -v n="$n" '
            BEGIN{ pl = mx + g - r; if (pl <= 0) { print 0; exit } printf "%.0f", 1000*exp((pl-p)/(10*n)*log(10)) }')"
        printf 'verdict\tdownlink_overshadow_collapses_with_range\n'
    fi
    printf 'limit\tthe model is log-distance, not a ray trace: the paper measured in specific streets and over a lake, and the delta rows say how far the model sits from those points\n'
}

# ── subframe map ─────────────────────────────────────────────────────────
# A capture cannot be turned into a map here: this tree has no LTE PHY decoder.
# What it does have is modules that decode MAC allocations, so the map is a TSV
# they can write. The columns are the ones a DCI gives you.
osh_subframe_map() {
    local f="${1:-}"
    if [[ -z "$f" ]]; then
        printf 'ERROR\t--subframe-map needs a TSV of decoded allocations\n' >&2
        printf 'WHY\tthe map is per-subframe scheduling, which only a decoder can produce\n' >&2
        printf 'FIX\tcolumns: sfn sf rnti rb_start rb_count mcs tbs channel\n' >&2
        return 2
    fi
    if [[ ! -r "$f" ]]; then
        printf 'ERROR\tcannot read %s\n' "$(osh_sanitize "$f")" >&2
        case "${f##*.}" in
            pcap|pcapng|cap) printf 'WHY\tthis module reads decoded allocations, not a capture: there is no LTE PHY decoder in this tree\n' >&2
                             printf 'FIX\tdecode first with 29_mac_layer or 17_pcap_analysis, then pass the TSV here\n' >&2 ;;
            *) printf 'WHY\tthe file does not exist or is not readable\n' >&2 ;;
        esac
        return 1
    fi
    printf 'map\t%s\n' "$(osh_sanitize "$f")"
    awk -F'\t' '
        NR == 1 && $1 ~ /^sfn$/ { next }
        NF < 8 { next }
        {
            key = $1 "." $2;
            alloc[key] = 1;
            total++;
            rnti[$3]++;
            chan[$8]++;
            if (first[$8] == "") first[$8] = key;
            # A message is overshadowable where integrity does not apply. That
            # is the user plane and everything before AS security, which is
            # exactly the window the IMSI variant lives in.
            sec = "yes";
            if ($8 == "sib" || $8 == "paging" || $8 == "msg4" || $8 == "msg3" || $8 == "rar" || $8 == "pdcch" || $8 == "pcch") sec = "no";
            if (sec == "no") { tgt += 0; tgts[key " /" $8] = $3 "\t" $4 "\t" $5 }
        }
        END {
            printf "allocations\t%d\n", total;
            printf "subframes\t%d\n", length(alloc);
            for (c in chan) printf "channel\t%s\t%d\n", c, chan[c];
            for (r in rnti) printf "rnti\t%s\t%d\n", r, rnti[r];
            for (k in tgts) {
                split(tgts[k], a, "\t");
                printf "target\t%s\t%s\trb %s+%s\t%s\n", k, "", a[2], a[3], "no AS security: a transport block here is accepted without an integrity check";
            }
        }' "$f"
    printf 'ref\tTS 36.213 8.6 (DCI carries the allocation), TS 36.331 5.3 (which messages precede AS security)\n'
    printf 'limit\tthe map says where a transport block sits; whether overshadowing it works is a radio question this tree cannot answer\n'
}

# ── detection ────────────────────────────────────────────────────────────
# Overshadowing is invisible to the detectors that look for a loud long-lived
# signal, so every detector here looks at structure instead. Input is a TSV of
# observations, one per line: t_s, kind, cell, rnti, value. Kinds are
# scheduled, received, sib, paging, rsrp, handover, sync.
osh_detect() {
    local f="${1:-}" rsrp_thresh=6 drift_thresh=0.5
    shift || true
    while (($#)); do
        case "$1" in
            --rsrp-db)   osh_need_num --rsrp-db "${2:-}"   || return 2; rsrp_thresh="$2"; shift 2 ;;
            --drift-us)  osh_need_num --drift-us "${2:-}"  || return 2; drift_thresh="$2"; shift 2 ;;
            *) printf 'ERROR\tunknown option: %s\n' "$(osh_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    if [[ -z "$f" ]]; then
        printf 'ERROR\t--detect needs an observations TSV\n' >&2
        printf 'FIX\tcolumns: t_s kind cell rnti value  (kinds: scheduled received sib paging rsrp handover sync)\n' >&2
        return 2
    fi
    if [[ ! -r "$f" ]]; then
        printf 'ERROR\tcannot read %s\n' "$(osh_sanitize "$f")" >&2
        return 1
    fi
    awk -F'\t' -v th="$rsrp_thresh" -v dr="$drift_thresh" '
        NR == 1 && $2 == "kind" { next }
        NF < 5 { next }
        { rows++ }
        $2 == "scheduled" { sched[$3 "/" $5] = 1; next }
        $2 == "received"  { rx_key = $3 "/" $5; if (rx[$3 "/" $5] == "") rx_order[++nrx] = $3 "/" $5; rx[$3 "/" $5] = $1; next }
        $2 == "sib"       { sib_cell[$3] = $4; sib_val[$3 "/" $4] = (sib_val[$3 "/" $4] == "") ? $5 : sib_val[$3 "/" $4] " " $5; next }
        $2 == "paging"    { paged[$3]++; next }
        $2 == "rsrp"      {
            if ($3 in last_rsrp) {
                d = $5 - last_rsrp[$3]; if (d < 0) d = -d;
                if (d > th && !($3 in ho)) { printf "detector\trsrp_discontinuity\tMEDIUM\t%s\t%+.1f dB in one step with no handover between\t%s\n", $3, $5-last_rsrp[$3], $1 }
            }
            last_rsrp[$3] = $5; next }
        $2 == "handover"  { ho[$3] = 1; next }
        $2 == "sync"      {
            if ($3 in last_sync) {
                d = $5 - last_sync[$3]; if (d < 0) d = -d;
                if (d > dr) printf "detector\ttiming_drift\tMEDIUM\t%s\t%.2f us change across subframes, no handover\t%s\n", $3, $5-last_sync[$3], $1
            }
            last_sync[$3] = $5; next }
        END {
            # D1: a CRC-passing transport block the cell never scheduled.
            for (i = 1; i <= nrx; i++) {
                k = rx_order[i];
                if (!(k in sched))
                    printf "detector\tunscheduled_crc_passing_tb\tHIGH\t%s\treceived at %s and never scheduled for that subframe\t%s\n", k, rx[k], rx[k]
            }
            # D2: a SIB whose value changed with no paging to announce it.
            for (j in sib_val) {
                split(j, p, "/");
                if (split(sib_val[j], vals, " ") > 1 && !(p[1] in paged))
                    printf "detector\tsib_change_without_paging\tHIGH\t%s\tSIB %s changed with no paging record for the cell\t%s\n", p[1], p[2], p[1]
            }
            printf "observations\t%d\n", rows
            printf "scheduled_keys\t%d\n", length(sched)
            printf "received_keys\t%d\n", length(rx)
        }' "$f"
    printf 'ref\tpaper section 5.6: published IMSI-catcher apps test for a loud cell and do not test for any of this\n'
    printf 'verdict\tsee the detector rows: any HIGH row is a transport block or a SIB that does not fit the cell own schedule\n'
    printf 'limit\tevery detector needs a capture of the scheduling and the received blocks together; a downlink-only capture cannot separate the two\n'
}

# ── plan ─────────────────────────────────────────────────────────────────
# The plan is a schedule of sample offsets and a gain envelope, which is what a
# transmit stack would consume. It is not a transmission, and the rows say so.
osh_plan() {
    local target="" mode="ul" rate=3840000 dur=1 sfn=0 sf=5 out="" rb="0-49"
    while (($#)); do
        case "$1" in
            --mode) mode="${2:-}"; shift 2 ;;
            --rate) osh_need_num --rate "${2:-}" || return 2; rate="$2"; shift 2 ;;
            --duration) osh_need_num --duration "${2:-}" || return 2; dur="$2"; shift 2 ;;
            --sfn) osh_need_num --sfn "${2:-}" || return 2; sfn="$2"; shift 2 ;;
            --sf) osh_need_num --sf "${2:-}" || return 2; sf="$2"; shift 2 ;;
            --rb) rb="${2:-}"; shift 2 ;;
            --out) out="${2:-}"; shift 2 ;;
            -*) printf 'ERROR\tunknown option: %s\n' "$(osh_sanitize "$1")" >&2; return 2 ;;
            *) target="$1"; shift ;;
        esac
    done
    case "$mode" in ul|dl) ;; *) printf 'ERROR\t--mode takes ul or dl\n' >&2; printf 'WHY\tuplink overshadows one victim grant; downlink overshadows the frequency it receives on\n' >&2; return 2 ;; esac
    if [[ -z "$target" ]]; then
        printf 'ERROR\t--plan needs a target: the message or the C-RNTI to overshadow\n' >&2
        printf 'FIX\t--plan rnti:0x4a2b | --plan msg4 | --plan sib1\n' >&2
        return 2
    fi
    local per_ms=$(( rate / 1000 ))
    if (( per_ms <= 0 )); then
        printf 'ERROR\trate %s is below one sample per millisecond\n' "$(osh_sanitize "$rate")" >&2
        return 2
    fi
    local sf_abs=$(( sfn * OSH_SUBFRAMES_PER_FRAME + sf ))
    local start=$(( sf_abs * per_ms ))
    local len=$per_ms
    printf 'target\t%s\n' "$(osh_sanitize "$target")"
    printf 'mode\t%s\n' "$mode"
    printf 'rate\t%s\n' "$rate"
    printf 'samples_per_ms\t%s\n' "$per_ms"
    printf 'sfn\t%s\n' "$sfn"
    printf 'subframe\t%s\n' "$sf"
    printf 'rb_window\t%s\n' "$(osh_sanitize "$rb")"
    printf 'subframe_us\t%s\n' "$(osh_fmt "$OSH_SUBFRAME_US" 1)"
    printf 'cp_us\t%s\n' "$(osh_fmt "$OSH_CP_US" 2)"
    printf 'step\treceive_sync\t0\tduration_us\t-\tnote\tPSS/SSS gives frame and slot; the plan is meaningless without it\n'
    printf 'step\tdecode_dci\t500\tduration_us\t-\tnote\tcontinuous PDCCH decode gives the allocation: which RBs carry the target transport block\n'
    printf 'step\tqueue_message\t1000\tnote\tframed and in the send buffer 2 ms before the transmit instant (paper section 4.2)\n'
    printf 'step\ttransmit\t%s\tnote\t%s\n' "$start" "$( [[ "$mode" == "ul" ]] && echo "on the uplink grant the victim was given, at the advance the attacker chose" || echo "on the downlink subframe, on top of the cell own transmission" )"
    printf 'wake\tsample_start\t%s\tsample_len\t%s\ttime_us\t%s\n' "$start" "$len" "$(awk -v s="$sf_abs" 'BEGIN{printf "%.0f", s*1000}')"
    printf 'gain_envelope\tramp_up_us\t%s\thold_us\t%s\tramp_down_us\t%s\n' 5 "$(osh_fmt "$OSH_SUBFRAME_US" 0)" 5
    printf 'keys\tnone for the messages before AS security; the IMSI variant lives exactly there\n'
    printf 'waveform\tnot produced here: this plan would be consumed by a real-time PHY transmitter, which this tree does not have\n'
    if [[ "$mode" == "dl" ]]; then
        printf 'collateral\tevery user in the cell: the attacker transmits on the frequency it listens to, so the cell reference signals are overshadowed too\n'
        printf 'where_it_was_run\tshielded box or open field with nobody else present (paper section 5.1.1)\n'
        printf 'loud\tas loud as the cell at the victim, which is why the published downlink range is 50 m\n'
    else
        printf 'collateral\tthe victim own grant only: uplink is a scheduling problem in one set of resource blocks\n'
        printf 'loud\tslightly above one handset at the base station, which is why the published uplink range is hundreds of metres to kilometres\n'
    fi
    printf 'needs\tone SDR with simultaneous receive and transmit, an amplifier board, and a real-time stack (see --needs)\n'
    if [[ -n "$out" ]]; then
        printf 'time_us\tkind\tsample_start\tsample_len\tnote\n' > "$out"
        printf '%s\ttransmit\t%s\t%s\t%s\n' "$(awk -v s="$sf_abs" 'BEGIN{printf "%.0f", s*1000}')" "$start" "$len" "$(osh_sanitize "$target")" >> "$out"
        printf 'schedule_file\t%s\n' "$(osh_sanitize "$out")"
    fi
    printf 'verdict\tplan_only\n'
    printf 'ref\tarXiv 2106.05039 sections 4.1, 4.2, 5.3, 5.5\n'
}

osh_collateral() {
    cat <<'EOF'
mode	downlink	uplink
what_is_overshadowed	the subframe on the frequency the attacker receives	the resource blocks of one victim grant
who_degrades	every user in the cell, because the cell reference signals go too	the victim, and only while that grant is active
why	transmit and receive are on the same frequency, so there is no filtering that separates them	transmit and receive are on different frequencies, so a duplexer separates them
published_range	50 m in an urban open field at 29 dBm per port	398 m urban NLOS at 28.5 dBm per port; 1.3 km rural; above 3.8 km claimed
where_it_was_run	shielded box or empty field, nobody else present	on a live network, one subscriber at a time
authorisation	everyone in the cell is a third party: this needs a shielded enclosure	only the target has to consent
ref	arXiv 2106.05039 sections 5.1.1, 5.3, 5.5
EOF
}

osh_usage() {
    cat <<'EOF'
overshadow — overshadowing (AdaptOver): analysis and planning, never a transmitter

  --info                    what this module is and what it refuses to do
  --status-tsv              machine-readable status
  --needs [radio]           published bill of materials; b210 b205mini x310 pluto
  --timing-budget           receive instant to transmit instant against 2 ms and CP
  --power-budget            required power and range for --mode ul or dl
  --subframe-map <tsv>      which subframe and RBs carry which message
  --detect <tsv>            unscheduled TB, SIB change without paging, RSRP, drift
  --plan <target>           sample-indexed schedule; plans, does not key
  --collateral              downlink degrades the cell, uplink degrades one grant
  --selftest                arithmetic checks against the published numbers
  --menu                    interactive menu

Options:
  --mode ul|dl              which direction is being planned or budgeted
  --rate <sps>              sample rate for the schedule (default 3840000)
  --sfn <n> --sf <n>        which subframe the plan targets
  --freq-mhz <n>            band for the power model (default 2100)
  --path-loss-exponent <n>  log-distance exponent (default 2.7 urban)
  --cell-power-dbm <n>      cell power for the downlink case (default 47)
  --ue-power-dbm <n>        victim handset power for the uplink case (default 23)
  --margin-db <n>           how far above the competitor the attacker aims (default 6)
  --range-km <n>            attacker to receiver hop, for the uplink arithmetic
  --out <path>              write the schedule as TSV

--transmit is not implemented and refuses by name: the published attack needs a
real-time srsUE-derived stack, and this tree has no PHY transmit path.
EOF
}

osh_transmit_refusal() {
    printf 'ERROR\t--transmit is not implemented in this module\n' >&2
    printf 'WHY\tovershadowing needs a real-time downlink decoder and a transmitter aligned to the subframe boundary; the published proof of concept is srsUE with fourteen lines changed (paper section 4.2), and this tree has no PHY transmit path\n' >&2
    printf 'FIX\tuse --plan to produce the schedule a transmit stack would consume, and --subframe-map plus --timing-budget to check the assumptions it rests on\n' >&2
    return 3
}

# ── selftest ─────────────────────────────────────────────────────────────
osh_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT

    # 1. Frame arithmetic derived from 30720 Ts, not quoted constants.
    chk ts-subframe "$(awk -v h="$OSH_TS_HZ" 'BEGIN{printf "%.0f", 1000000/h*30720}')" "1000"
    chk subframe-us "$(osh_fmt "$OSH_SUBFRAME_US" 1)" "1000.0"
    chk slot-us "$(osh_fmt "$OSH_SLOT_US" 1)" "500.0"
    chk cp-us "$(osh_fmt "$OSH_CP_US" 2)" "4.69"

    # 2. The bill of materials names the radio the paper used and the amplifier
    # it used, so a reader cannot mistake this for a laboratory build.
    out=$(osh_needs b210)
    chk needs-radio "$(fld "$out" radio)" "USRP B210"
    chk needs-amp "$(fld "$out" amplifier | grep -c TQP9111)" "1"
    chk needs-cots "$(fld "$out" specialized_hardware | grep -c 'none')" "1"
    chk needs-missing "$(fld "$out" missing_here | grep -c 'PHY transmit path')" "1"
    chk needs-bad "$(osh_needs pluto9 >/dev/null 2>&1; echo $?)" "2"

    # 3. Timing budget: the two budgets are different and the binding one is
    # named. A 3 ms encode cannot fit a 2 ms queue window.
    out=$(osh_timing_budget)
    chk timing-spent "$(fld "$out" spent_us)" "950.0"
    chk timing-margin "$(fld "$out" margin_us)" "1050.0"
    chk timing-binding "$(fld "$out" binding_constraint)" "cp"
    chk timing-verdict "$(fld "$out" verdict)" "fits"
    chk timing-ta-unit "$(fld "$out" ta_unit_us)" "0.5208"
    out=$(osh_timing_budget --encode-us 3000)
    chk timing-slow-verdict "$(fld "$out" verdict)" "does_not_fit_the_queue_window"
    chk timing-slow-binding "$(fld "$out" binding_constraint)" "queue"

    # 4. Power: uplink is a handset-class number and downlink collapses. The
    # downlink model is checked against the paper's measured point rather than
    # against itself: 29 dBm per port reached 50 m, and the model should land
    # in the same order of magnitude, not twenty metres or two kilometres.
    out=$(osh_power_budget --mode ul)
    chk ul-required "$(fld "$out" required_attacker_tx_dbm)" "29.00"
    chk ul-delta "$(fld "$(osh_power_budget --mode ul --attacker-km 1 --victim-km 0.1)" required_attacker_tx_dbm)" "56.00"
    chk ul-verdict "$(fld "$out" verdict)" "uplink_overshadow_is_low_power"
    out=$(osh_power_budget --mode dl)
    chk dl-required "$(fld "$out" required_at_victim_dbm | cut -d. -f1)" "-37"
    local model_m
    model_m=$(fld "$out" paper_model_check_m)
    chk dl-model-order "$(awk -v m="$model_m" 'BEGIN{ print (m > 10 && m < 300) ? "same_order" : "wrong_order" }')" "same_order"
    chk dl-range-shorter "$(awk -v a="$(fld "$out" attacker_range_m)" -v b="500" 'BEGIN{ print (a < b) ? "yes" : "no" }')" "yes"
    chk dl-verdict "$(fld "$out" verdict)" "downlink_overshadow_collapses_with_range"
    chk power-bad-mode "$(osh_power_budget --mode sideways >/dev/null 2>&1; echo $?)" "2"

    # 5. Subframe map: a target is a message that arrives before AS security,
    # and the scheduling keys are counted, not guessed.
    printf 'sfn\tsf\trnti\trb_start\trb_count\tmcs\ttbs\tchannel\n' > "$d/map.tsv"
    printf '0\t5\t0x4a2b\t0\t49\t9\t120\tpdcch\n' >> "$d/map.tsv"
    printf '0\t5\t0x4a2b\t0\t49\t9\t120\tsib\n' >> "$d/map.tsv"
    printf '1\t5\t0x4a2b\t10\t20\t9\t80\tdrb\n' >> "$d/map.tsv"
    out=$(osh_subframe_map "$d/map.tsv")
    chk map-alloc "$(fld "$out" allocations)" "3"
    chk map-subframes "$(fld "$out" subframes)" "2"
    chk map-targets "$(printf '%s\n' "$out" | grep -c '^target')" "2"
    chk map-pcap-refused "$(osh_subframe_map /tmp/nope.pcap >/dev/null 2>&1; echo $?)" "1"
    chk map-noarg "$(osh_subframe_map >/dev/null 2>&1; echo $?)" "2"

    # 6. Detectors: each one fires on a fixture built to trip it and stays quiet
    # on a clean file, so a detector that fires on everything cannot pass.
    printf 't_s\tkind\tcell\trnti\tvalue\n' > "$d/bad.tsv"
    printf '1.0\tscheduled\t1\t0x4a2b\t0.5\n' >> "$d/bad.tsv"
    printf '1.0\treceived\t1\t0x4a2b\t0.5\n' >> "$d/bad.tsv"
    printf '1.1\treceived\t1\t0x4a2b\t0.6\n' >> "$d/bad.tsv"
    printf '1.2\tsib\t1\tsib1\ttagA\n' >> "$d/bad.tsv"
    printf '1.3\tsib\t1\tsib1\ttagB\n' >> "$d/bad.tsv"
    printf '2.0\trsrp\t1\t-\t-70\n' >> "$d/bad.tsv"
    printf '2.1\trsrp\t1\t-\t-58\n' >> "$d/bad.tsv"
    printf '3.0\tsync\t1\t-\t0.10\n' >> "$d/bad.tsv"
    printf '3.1\tsync\t1\t-\t1.90\n' >> "$d/bad.tsv"
    out=$(osh_detect "$d/bad.tsv")
    chk detect-unscheduled "$(printf '%s\n' "$out" | grep -c unscheduled_crc_passing_tb)" "1"
    chk detect-sib "$(printf '%s\n' "$out" | grep -c sib_change_without_paging)" "1"
    chk detect-rsrp "$(printf '%s\n' "$out" | grep -c rsrp_discontinuity)" "1"
    chk detect-drift "$(printf '%s\n' "$out" | grep -c timing_drift)" "1"
    chk detect-observations "$(fld "$out" observations)" "9"

    printf 't_s\tkind\tcell\trnti\tvalue\n' > "$d/clean.tsv"
    printf '1.0\tscheduled\t1\t0x4a2b\t0.5\n' >> "$d/clean.tsv"
    printf '1.0\treceived\t1\t0x4a2b\t0.5\n' >> "$d/clean.tsv"
    printf '1.2\tpaging\t1\tue1\t-\n' >> "$d/clean.tsv"
    printf '1.3\tsib\t1\tsib1\ttagA\n' >> "$d/clean.tsv"
    printf '1.4\tsib\t1\tsib1\ttagB\n' >> "$d/clean.tsv"
    printf '2.0\trsrp\t1\t-\t-70\n' >> "$d/clean.tsv"
    printf '2.1\trsrp\t1\t-\t-69\n' >> "$d/clean.tsv"
    printf '3.0\tsync\t1\t-\t0.10\n' >> "$d/clean.tsv"
    printf '3.1\tsync\t1\t-\t0.20\n' >> "$d/clean.tsv"
    out=$(osh_detect "$d/clean.tsv")
    chk detect-clean "$(printf '%s\n' "$out" | grep -c '^detector')" "0"
    chk detect-noarg "$(osh_detect >/dev/null 2>&1; echo $?)" "2"

    # 7. Plan: the sample start has to agree with the subframe arithmetic, and
    # the two modes have to say different things about who pays.
    out=$(osh_plan msg4 --mode ul --rate 1920000 --sfn 0 --sf 9)
    chk plan-samples-per-ms "$(fld "$out" samples_per_ms)" "1920"
    chk plan-start "$(printf '%s\n' "$out" | awk -F'\t' '$1=="wake"{print $3}')" "17280"
    chk plan-verdict "$(fld "$out" verdict)" "plan_only"
    chk plan-ul-collateral "$(fld "$out" collateral | grep -c 'victim own grant')" "1"
    out=$(osh_plan msg4 --mode dl --rate 1920000)
    chk plan-dl-loud "$(fld "$out" loud | grep -c '50 m')" "1"
    chk plan-dl-collateral "$(fld "$out" collateral | grep -c 'every user in the cell')" "1"
    chk plan-bad-mode "$(osh_plan msg4 --mode both >/dev/null 2>&1; echo $?)" "2"
    chk plan-noarg "$(osh_plan >/dev/null 2>&1; echo $?)" "2"

    # 8. The refusal that keeps this module honest.
    chk transmit-refused "$(osh_transmit_refusal >/dev/null 2>&1; echo $?)" "3"
    chk collateral-rows "$(osh_collateral | wc -l)" "8"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

osh_menu() {
    while true; do
        banner
        echo "  === Overshadowing / AdaptOver ==="
        echo
        cat <<'M'
  [1]  Bill of materials (and which SDR)
  [2]  Timing budget
  [3]  Power budget (uplink or downlink)
  [4]  Subframe map from a decoded TSV
  [5]  Detect from observations
  [6]  Plan a schedule
  [7]  What each mode costs other users
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) osh_needs b210; read -rp "  enter " _ ;;
            2) osh_timing_budget; read -rp "  enter " _ ;;
            3) read -rp "  mode ul|dl> " m; osh_power_budget --mode "${m:-dl}"; read -rp "  enter " _ ;;
            4) read -rp "  map tsv> " f; osh_subframe_map "$f"; read -rp "  enter " _ ;;
            5) read -rp "  observations tsv> " f; osh_detect "$f"; read -rp "  enter " _ ;;
            6) read -rp "  target> " t; read -rp "  mode ul|dl> " m; osh_plan "${t:-msg4}" --mode "${m:-ul}"; read -rp "  enter " _ ;;
            7) osh_collateral; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

osh_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   osh_status_tsv ;;
        --info)         osh_info ;;
        --needs)        osh_needs "${1:-b210}" ;;
        --timing-budget) osh_timing_budget "$@" ;;
        --power-budget) osh_power_budget "$@" ;;
        --subframe-map) osh_subframe_map "${1:-}" ;;
        --detect)       osh_detect "$@" ;;
        --plan)         osh_plan "$@" ;;
        --collateral)   osh_collateral ;;
        --transmit)     osh_transmit_refusal ;;
        --selftest)     osh_selftest ;;
        --menu)         osh_menu ;;
        --help|--usage|-h) osh_usage ;;
        "")             osh_usage; return 2 ;;
        *)              printf 'ERROR\tunknown verb: %s\n' "$(osh_sanitize "$cmd")" >&2
                        osh_usage
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
    osh_cli_main "$@"
fi
