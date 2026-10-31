#!/usr/bin/env bash
# sidelink — NR sidelink / V2X (PC5): resource pool maths and ITS security.
#
# Sidelink lets UEs talk directly on PC5 without the network, which is what V2X
# uses. It brings its own physical layer (SCI, resource pools, PSFCH), its own
# identity (24-bit Layer-2 IDs) and a certificate-based security layer (ETSI
# TS 102 940 / IEEE 1609.2 pseudonym certificates). This module works the
# resource-pool arithmetic, the SCI-1A field layout and the ITS certificate
# model, and checks a relay configuration. It transmits nothing.
#
# Attack owned: V2X/sidelink adjacency (O17 beam/resource surface) — analysis half.
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

MOD_TMP="$TMP_DIR/sidelink"
SLNK_DIR="$LOOT_DIR/sidelink"
mkdir -p "$MOD_TMP" "$SLNK_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

slnk_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
SLNK_F=()
slnk_split() {
    SLNK_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        SLNK_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

slnk_status_tsv() {
    printf 'MODULE\tsidelink\n'
    printf 'TARGET\tPC5 resource pools, SCI-1A layout, ITS certificate model, relay checks\n'
    printf 'TRANSMIT\tnone — resource arithmetic and configuration analysis\n'
    printf 'SELFTEST\tyes\n'
}

# ── resource pool: number of subchannels ────────────────────────────────
slnk_subchannels() {
    local bwp="${1:-}" sub="${2:-}"
    [[ "$bwp" =~ ^[0-9]+$ && "$sub" =~ ^[0-9]+$ ]] || { printf 'ERROR\tbandwidth and subchannel size must be integers\n' >&2; return 2; }
    (( sub > 0 )) || { printf 'ERROR\tsubchannel size must be positive\n' >&2; return 2; }
    printf 'bwp_prb\t%d\nsubchannel_prb\t%d\nsubchannels\t%d\nremainder_prb\t%d\n' \
        "$bwp" "$sub" "$(( bwp / sub ))" "$(( bwp % sub ))"
}

# ── SCI-1A frequency resource indicator width (TS 38.212 §7.3.1.1) ──────
# Start-and-length is encoded over N*(N+1)/2 states, so the field is
# ceil(log2(N*(N+1)/2)) bits, and it is absent (0 bits) when N=1 because the
# only legal assignment is the single subchannel. The clause is 7.3.1.1, the
# SCI format 1-A payload; earlier revisions of this comment cited 8.3.1.1,
# which is the CRC and channel-coding clause, not the payload layout.
slnk_freq_bits() {
    local n="${1:-}"
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || { printf 'ERROR\tsubchannel count must be positive\n' >&2; return 2; }
    local states=$(( n * (n + 1) / 2 )) bits=0 p=1
    while (( p < states )); do p=$(( p * 2 )); bits=$(( bits + 1 )); done
    printf 'subchannels\t%d\nstates\t%d\nfreq_field_bits\t%d\n' "$n" "$states" "$bits"
}

# ── PFI and Layer-2 IDs ─────────────────────────────────────────────────
slnk_pfi() {
    local v="${1:-}"
    [[ "$v" =~ ^[0-9]+$ ]] || { printf 'ERROR\tPFI must be numeric\n' >&2; return 2; }
    (( v >= 1 && v <= 64 )) || { printf 'ERROR\tPFI is a 6-bit value in 1..64 (0 is not usable)\n' >&2; return 2; }
    printf 'pfi\t%d\nbits\t6\n' "$v"
}
slnk_l2id() {
    local h="${1:-}"
    h=$(printf '%s' "$h" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]{1,6}$ ]] || { printf 'ERROR\tLayer-2 ID must be 1..6 hex digits (24 bits)\n' >&2; return 2; }
    printf 'l2_id\t%s\nvalue\t%d\nbits\t24\n' "$h" "$(( 16#$h ))"
}

slnk_sci_1a() {
    # This used to print a ten-row table of bit widths. Several were not the
    # widths in TS 38.212 Table 7.3.1.1.1-1: it said 5 bits for the resource
    # reservation period (the table has 4), 2 for the DMRS pattern (1), 1 for
    # the second-stage SCI format (2) and 2 for the PSFCH overhead (0 or 1).
    # A table of numbers that reads like a decoder and is wrong is worse than
    # no table, because a reader sizes a parser from it.
    #
    # The widths are not recoverable from anything in this tree. SCI format 1-A
    # is a bit-packed PSCCH payload defined by TS 38.212 clause 7.3.1.1, not an
    # ASN.1 IE, so there is no pycrate module to generate a layout table from
    # and no oracle here to certify one against -- the generators cover ASN.1
    # families only (tools/asn1gen.py: rrc, lpp, nbiot).
    #
    # What this module CAN prove is the one field whose width is arithmetic:
    # the frequency resource assignment, encoded start-and-length over
    # N(N+1)/2 states, which is why --freq-bits exists and is checked.
    printf 'ERROR\tSCI format 1-A field widths are not decoded here\n' >&2
    printf 'WHY\tSCI-1A is a bit-packed payload defined by TS 38.212 clause 7.3.1.1, not an ASN.1 IE, so no layout table in this tree can describe it and no oracle here can certify one. The table this verb used to print carried widths that did not match Table 7.3.1.1.1-1.\n' >&2
    printf 'WHAT IS REAL\t--freq-bits <subchannels> computes the frequency resource assignment width from the start-and-length encoding: ceil(log2(N(N+1)/2)) bits.\n' >&2
    printf 'NEXT\tadd a hand-written, clause-cited SCI-1A field table with a known-answer check against one captured PSCCH payload before any verb claims to parse one\n' >&2
    return 2
}

slnk_its() {
    cat <<'EOF'
certificate	type	purpose
enrollment	ETSI TS 102 941	long-term; proves the ITS station to the authority
authorization	ETSI TS 102 941	short-term pseudonym; signs CAM/DENM, rotated frequently
application	ETSI TS 102 940	scoped to an application (e.g., platooning)
note	reference	these are the certificate roles as the cited clauses define them; this module builds no certificate and validates none
EOF
}

# ── relay configuration check ───────────────────────────────────────────
# A UE-to-NW relay extends coverage; an open relay without an ACL lets any
# remote UE route through the relay's credentials.
slnk_relay_check() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such config: %s\n' "$file" >&2; return 1; }
    local remote="" acl="" filter="" signed=""
    local line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z'); v="${line#*=}"
        case "$k" in
            remote_ue_allowed) remote="$v" ;;
            relay_acl|acl) acl="$v" ;;
            l2id_filter|relay_l2id_filter) filter="$v" ;;
            relay_authorized|authorized) signed="$v" ;;
        esac
    done < "$file"
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "$remote" =~ ^(true|yes|1|on)$ ]]; then
        if [[ -z "$acl" && -z "$filter" ]]; then
            printf 'open_relay\tHIGH\tremote-UE relaying is enabled with no ACL and no Layer-2 ID filter; any remote UE can route through this relay\n'; n=$((n+1))
        else
            printf 'relay_filtered\tINFO\tremote-UE relaying is enabled but bounded by an ACL or Layer-2 ID filter\n'
        fi
    fi
    [[ "$signed" =~ ^(true|yes|1|on)$ ]] || { printf 'relay_unauthorized\tMEDIUM\trelaying is not tied to an authorisation; a rogue relay can impersonate a node\n'; n=$((n+1)); }
    (( n == 0 )) && printf 'none\tINFO\trelaying is off or fully bounded and authorised\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

slnk_plan() {
    cat <<'EOF'
status	handoff
what	observing or emulating PC5 sidelink
hardware	an SDR with transmit for a UE-side sidelink (USRP/BladeRF), or two UEs with V2X enabled
software	srsRAN with sidelink support, or a UE test bench with the PC5 stack; an ITS PKI for the certificate layer
flow	1. --subchannels and --freq-bits for a pool  2. --its for the certificate roles  3. --relay-check on a relay config
note	transmitting PC5 into the V2X band needs a licence and an ITS credential; this module analyses pools and configs
EOF
}

# ── pseudonym rotation audit (TS 102 941) ────────────────────────────────
# A pseudonym that rotates is only unlinkable if the rotation is actually
# happening: one certificate signing everything for twenty minutes links the
# whole journey, and two certificates that appear at the same place at the same
# moment link to each other even though neither is reused. The audit reads a
# trace (time, certificate id) and counts both.
SLNK_BUCKET=${SLNK_BUCKET:-300}   # seconds per rotation bucket (5 min)
slnk_pau_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --pseudonym-audit <trace.tsv> [bucket-seconds]
	trace.tsv has one row per signed message: <epoch-seconds> <certificate-id> [latitude] [longitude]
EOF
}
slnk_cmd_pseudonym_audit() {
    local f="${1:-}" bucket="${2:-$SLNK_BUCKET}"
    if [[ -z "$f" ]]; then slnk_pau_usage; return 2; fi
    if [[ ! -r "$f" ]]; then
        printf 'WHY\tthe audit reads a trace of what was signed, so an absent trace is an absent capture\n' >&2
        printf 'ERROR\tcannot read %s\n' "$(slnk_sanitize "$f")" >&2
        return 1
    fi
    [[ "$bucket" =~ ^[0-9]+$ && "$bucket" -gt 0 ]] || {
        printf 'ERROR\tbucket-seconds must be a positive whole number\n' >&2; return 2; }
    awk -F'\t' -v bucket="$bucket" '
        NF < 2 { next }
        $1 !~ /^[0-9]+$/ { next }
        {
            t = $1 + 0; cert = $2
            if (cert == "") next
            n++
            if (!(cert in first) || t < first[cert]) first[cert] = t
            if (!(cert in last) || t > last[cert]) last[cert] = t
            uses[cert]++
            b = int(t / bucket)
            buckets[cert] = buckets[cert] (cert in buckets && index(buckets[cert] " ", b " ") ? "" : (buckets[cert] == "" ? b : " " b))
            seen[b] = seen[b] " " cert
        }
        END {
            if (n == 0) { print "ERROR\tno usable rows (want epoch-seconds and a certificate id)"; exit 2 }
            nc = 0; reuse = 0; span_max = 0
            for (c in uses) {
                nc++
                span = last[c] - first[c]
                if (span > span_max) span_max = span
                k = split(buckets[c], arr, " ")
                if (k > 1) reuse++
                printf "pseudonym\t%s\tuses=%d\tbuckets=%d\tspan_s=%d\n", c, uses[c], k, span
            }
            linkable = 0
            for (bx in seen) {
                m = split(seen[bx], cs, " ")
                delete u
                uniq = 0
                for (i = 1; i <= m; i++) { if (cs[i] != "" && !(cs[i] in u)) { u[cs[i]] = 1; uniq++ } }
                if (uniq > 1) { linkable += uniq * (uniq - 1) / 2; pairs++ }
            }
            printf "messages\t%d\n", n
            printf "pseudonyms\t%d\n", nc
            printf "rotation_bucket_s\t%d\n", bucket
            printf "longest_span_s\t%d\n", span_max
            printf "reused_pseudonyms\t%d\n", reuse
            printf "linkable_pairs\t%d\n", linkable
            printf "clusters_with_two\t%d\n", pairs + 0
            if (nc == 1 && n > 1)
                print "finding\tno_rotation\tHIGH\tevery message was signed with one certificate, so the whole trace is one vehicle"
            if (reuse > 0)
                printf "finding\tpseudonym_reuse\tHIGH\t%d certificate(s) live across more than one %d-second bucket\n", reuse, bucket
            if (linkable > 0)
                printf "finding\tco_temporal_linkage\tMEDIUM\t%d pair(s) of certificates appear in the same bucket, which links them to each other\n", linkable
            if (nc > 1 && reuse == 0 && linkable == 0)
                print "finding\trotation_consistent\tINFO\tevery certificate stays inside its bucket and no two share one"
            verdict = (nc == 1 && n > 1) || linkable > 0 || reuse > 0 ? "pseudonyms_linkable" : "pseudonyms_rotating"
            printf "verdict\t%s\n", verdict
            printf "note\tTS 102 941 rotates pseudonyms on a schedule; the bucket is the audit window and a shorter one that still shows reuse is the stronger finding\n"
            printf "ref\tETSI TS 102 941 (pseudonym provisioning), TS 103 097 (signing)\n"
        }' "$f"
}

# ── the rogue UE-to-network relay (TS 23.303 / 33.303) ───────────────────
# A UE-to-network relay is a phone that forwards a remote UE's traffic. Any
# relay that carries the traffic can read what is not encrypted above it and can
# rewrite what is not integrity-protected above it; the interesting question is
# therefore not whether the relay can see something but which layer a defence
# would have to protect to stop it. The interposition is a model: the config
# names the relay's layer and the trace layer names the protocols.
slnk_relay_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --relay-interpose <config>
	config keys: relay_layer=layer2|layer3, traffic=http|dns|https|quic|all
EOF
}
slnk_cmd_relay_interpose() {
    local file="${1:-}"
    if [[ -z "$file" ]]; then slnk_relay_usage; return 2; fi
    [[ -f "$file" ]] || {
        printf 'WHY\ta relay interposition is a claim about traffic, so an absent config names no traffic\n' >&2
        printf 'ERROR\tno such config: %s\n' "$(slnk_sanitize "$file")" >&2
        return 1
    }
    local layer="" traffic="all" line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z'); v="${line#*=}"
        case "$k" in
            relay_layer|layer) layer="$v" ;;
            traffic|traffic_kind) traffic="$v" ;;
        esac
    done < "$file"
    case "$layer" in
        layer2|l2|'' ) layer="layer2" ;;
        layer3|l3 )    layer="layer3" ;;
        * ) printf 'ERROR\trelay_layer must be layer2 or layer3\n' >&2; return 2 ;;
    esac
    case "$traffic" in
        http|dns|https|quic|all) ;;
        * ) printf 'ERROR\ttraffic must be http, dns, https, quic or all\n' >&2; return 2 ;;
    esac
    local n=0
    printf 'relay_layer\t%s\n' "$layer"
    printf 'traffic\t%s\n' "$traffic"
    if [[ "$layer" == "layer2" ]]; then
        printf 'sees\tLayer-2 frames of the remote UE: every IP packet, because the relay carries them\n'
        printf 'sees\tDNS queries in the clear unless the remote UE uses a resolver the relay cannot see (DoH/DoT)\n'
        printf 'sees\tTLS and QUIC handshakes: server names, certificate chains and packet timing\n'
        printf 'sees\tIP addresses and ports, which is the remote UE traffic pattern even with no plaintext\n'
        printf 'can_do\tdrop, delay, reorder or duplicate any packet, and the remote UE has no way to tell a relay loss from a radio loss\n'
        printf 'can_do\trewrite plaintext DNS answers when the query is not protected\n'
        printf 'can_do\treset a TCP association or redirect a plaintext HTTP request\n'
        printf 'cannot\bread or forge an end-to-end TLS or QUIC payload, which is what a VPN or DoH would give the remote UE\n'
    else
        printf 'sees\tthe remote UE traffic only as far as the relay terminates the tunnel, which is the Layer-3 design\n'
        printf 'can_do\tsubstitute its own endpoint and terminate TLS, if the remote UE does not pin the server certificate\n'
        printf 'cannot\tskip a certificate the remote UE validates, which is the reason to pin at the application layer\n'
    fi
    printf 'finding\trelay_position\tHIGH\tthe relay is on the path for every packet the remote UE sends, before any protection the remote UE applies above it\n'; n=$((n+1))
    if [[ "$traffic" == "http" || "$traffic" == "dns" || "$traffic" == "all" ]]; then
        printf 'finding\tplaintext_visible\tHIGH\t%s traffic crosses the relay in clear text, so the relay reads it and can change it\n' "$traffic"; n=$((n+1))
    else
        printf 'finding\tmetadata_only\tMEDIUM\t%s traffic keeps its payload, but the relay still learns destinations and timing\n' "$traffic"; n=$((n+1))
    fi
    printf 'finding\tdetection_hard\tHIGH\tnothing in the remote UE protocol stack names the relay, so a defence has to come from the above layers (VPN, DoH, pinned certificates) or from a network-side relay audit\n'; n=$((n+1))
    printf 'detect\tlatency\tone extra PC5 hop inflates round-trip time by the relay processing time, which a consistent baseline can show\n'
    printf 'detect\tl2id\tthe relay Layer-2 ID is visible in the PC5 scheduling the remote UE sees\n'
    printf 'detect\tpath\tthe remote UE network path ends where the relay is, so a traceroute stops at the relay subnet\n'
    printf 'verdict\trelay_sees_traffic\n'
    printf 'findings\t%d\n' "$n"
    printf 'ref\t3GPP TS 23.303 (proximity services), TS 33.303 (security for proximity services)\n'
    printf 'note\tthe relay is not a break of the radio; it is a break of the trust chain the remote UE walked into when it picked the relay\n'
}

# ── kinematic linkage across pseudonyms (H2) ─────────────────────────────
# Pseudonym rotation is supposed to break the link between a vehicle and its
# history. It does not break physics: when one certificate stops transmitting
# and another starts, at the same place, at the same speed, in the same
# direction, a few seconds later, the two are one vehicle. The analysis reads a
# trace where each message carries a certificate id, a time and a position, and
# links certificates whose trajectories continue each other.
slnk_link_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --linkage <trace.tsv> [--gap seconds] [--radius metres]
	trace.tsv rows: <certificate-id> <t_seconds> <latitude> <longitude> <speed_mps> <heading_deg>
EOF
}
slnk_cmd_linkage() {
    local f="" gap=10 radius=100
    while (( $# )); do
        case "$1" in
            --gap)    gap="${2:-}"; shift 2 || { slnk_link_usage; return 2; } ;;
            --radius) radius="${2:-}"; shift 2 || { slnk_link_usage; return 2; } ;;
            -*)       slnk_link_usage; return 2 ;;
            *)        f="$1"; shift ;;
        esac
    done
    if [[ -z "$f" ]]; then slnk_link_usage; return 2; fi
    [[ -r "$f" ]] || {
        printf 'WHY\tthe linkage is a claim about a capture, so an absent capture supports no claim\n' >&2
        printf 'ERROR\tcannot read %s\n' "$(slnk_sanitize "$f")" >&2
        return 1
    }
    [[ "$gap" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--gap wants whole seconds\n' >&2; return 2; }
    [[ "$radius" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--radius wants whole metres\n' >&2; return 2; }
    awk -F'\t' -v gap="$gap" -v radius="$radius" '
        function dist(la1, lo1, la2, lo2) {
            # equirectangular on a sphere of radius 6371000 m: good to a few
            # metres at the scales a vehicle trace spans
            return 6371000 * 3.14159265358979 / 180 \
                 * sqrt((la2 - la1)^2 + (cos((la1 + la2) / 2 * 3.14159265358979 / 180) * (lo2 - lo1))^2)
        }
        function adiff(a, b) { d = (a - b) % 360; if (d < 0) d += 360; return d > 180 ? 360 - d : d }
        NF < 4 { next }
        $2 !~ /^-?[0-9.]+$/ || $3 !~ /^-?[0-9.]+$/ || $4 !~ /^-?[0-9.]+$/ { next }
        {
            id = $1; t = $2 + 0; la = $3 + 0; lo = $4 + 0
            sp = (NF >= 5 && $5 ~ /^-?[0-9.]+$/) ? $5 + 0 : -1
            hd = (NF >= 6 && $6 ~ /^-?[0-9.]+$/) ? $6 + 0 : -1
            n++
            if (!(id in cnt)) { order[++nc] = id }
            cnt[id]++
            if (!(id in first_t) || t < first_t[id]) { first_t[id] = t; first_la[id] = la; first_lo[id] = lo; first_sp[id] = sp; first_hd[id] = hd }
            if (!(id in last_t) || t > last_t[id]) { last_t[id] = t; last_la[id] = la; last_lo[id] = lo; last_sp[id] = sp; last_hd[id] = hd }
        }
        END {
            if (n == 0) { print "ERROR\tno usable rows (want id, t, lat, lon)"; exit 2 }
            links = 0; chains = 0
            for (i = 1; i <= nc; i++) {
                best = ""; bestscore = 999
                for (j = 1; j <= nc; j++) {
                    if (i == j) continue
                    g = first_t[order[j]] - last_t[order[i]]
                    if (g < 0 || g > gap) continue
                    d = dist(last_la[order[i]], last_lo[order[i]], first_la[order[j]], first_lo[order[j]])
                    # how far the vehicle could have travelled in the gap, with
                    # a third again on top for acceleration and position noise
                    reach = (last_sp[order[i]] >= 0 ? last_sp[order[i]] : 15) * g * 1.34 + radius
                    if (d > reach) continue
                    score = d + g
                    if (score < bestscore) { bestscore = score; best = order[j]; best_g = g; best_d = d }
                }
                if (best != "") {
                    links++
                    printf "link\t%s\t%s\tgap_s=%d\tstep_m=%d\tconsistent=yes\n", order[i], best, best_g, best_d
                }
            }
            printf "messages\t%d\n", n
            printf "pseudonyms\t%d\n", nc
            printf "linkable_successors\t%d\n", links
            if (links > 0) {
                printf "finding\tkinematic_linkage\tHIGH\t%d certificate change(s) are continuous in place, time and speed, so the rotation did not break the vehicle\n", links
                printf "finding\trotation_insufficient\tHIGH\tthe pseudonyms change but the trajectory does not, so a passive observer joins them\n"
            } else {
                printf "finding\tno_kinematic_linkage\tINFO\tno certificate change in this capture continues a trajectory within %d s and %d m\n", gap, radius
            }
            verdict = links > 0 ? "pseudonyms_linkable" : "pseudonyms_unlinked_in_this_capture"
            printf "verdict\t%s\n", verdict
            printf "note\tthe linkage uses only what a receiver sees: where and when each certificate transmitted\n"
            printf "ref\tETSI TS 102 941 (pseudonym rotation), TS 103 097\n"
        }' "$f"
}

slnk_selftest() {
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
    export SLNK_DIR="$d/loot/sidelink"
    mkdir -p "$SLNK_DIR"

    # 1. Resource pool: subchannels and remainder.
    chk sub-100-10 "$(fld "$(slnk_subchannels 100 10)" subchannels)" "10"
    chk sub-100-12 "$(fld "$(slnk_subchannels 100 12)" subchannels)" "8"
    chk sub-rem    "$(fld "$(slnk_subchannels 100 12)" remainder_prb)" "4"
    chk sub-bad    "$(slnk_subchannels 100 0 >/dev/null 2>&1; echo $?)" "2"

    # 2. SCI-1A frequency field width: N=10 -> 55 states -> 6 bits.
    chk freq-10 "$(fld "$(slnk_freq_bits 10)" freq_field_bits)" "6"
    chk freq-8  "$(fld "$(slnk_freq_bits 8)" freq_field_bits)" "6"
    chk freq-25 "$(fld "$(slnk_freq_bits 25)" freq_field_bits)" "9"
    chk freq-1  "$(fld "$(slnk_freq_bits 1)" freq_field_bits)" "0"
    chk freq-bad "$(slnk_freq_bits 0 >/dev/null 2>&1; echo $?)" "2"

    # 3. PFI and Layer-2 ID ranges.
    chk pfi-1  "$(fld "$(slnk_pfi 1)" bits)" "6"
    chk pfi-64 "$(fld "$(slnk_pfi 64)" pfi)" "64"
    chk pfi-0  "$(slnk_pfi 0 >/dev/null 2>&1; echo $?)" "2"
    chk pfi-65 "$(slnk_pfi 65 >/dev/null 2>&1; echo $?)" "2"
    chk l2id   "$(fld "$(slnk_l2id ffffff)" value)" "16777215"
    chk l2id-bad "$(slnk_l2id 1234567 >/dev/null 2>&1; echo $?)" "2"

    # 4. The SCI-1A reference refuses, and the certificate table cites its
    #    clauses without pretending to validate anything.
    chk sci1a-refuses "$(slnk_sci_1a >/dev/null 2>&1; echo $?)" "2"
    chk sci1a-no-widths "$(slnk_sci_1a 2>/dev/null | grep -c '^mcs')" "0"
    chk its-pseudo "$(slnk_its | awk -F'\t' '$1=="authorization"{print ($3 ~ /pseudonym/)?"ok":"no"}')" "ok"
    chk its-not-a-validator "$(slnk_its | awk -F'\t' '$1=="note"{print ($3 ~ /validates none/)?"ok":"no"}')" "ok"

    # 5. Relay check: open relay flagged, bounded relay abstains.
    printf 'remote_ue_allowed=true\nrelay_authorized=false\n' > "$d/open.conf"
    local out; out=$(slnk_relay_check "$d/open.conf")
    chk relay-open "$(fld "$out" open_relay)" "HIGH"
    chk relay-open-count "$(fld "$out" findings)" "2"
    printf 'remote_ue_allowed=true\nrelay_acl=allowed-l2ids\nrelay_authorized=true\n' > "$d/bounded.conf"
    out=$(slnk_relay_check "$d/bounded.conf")
    chk relay-bounded "$(fld "$out" relay_filtered)" "INFO"
    chk relay-bounded-count "$(fld "$out" findings)" "0"
    chk relay-missing "$(slnk_relay_check "$d/none.conf" >/dev/null 2>&1; echo $?)" "1"

    # 8. The ghost vehicle: plan rows, and arithmetic that catches a teleport.
    chk bsm-plan-signing "$(slnk_bsm_plan | awk -F'\t' '$1=="signing"{print ($2 ~ /1609.2/)?"ok":"no"}')" "ok"
    chk bsm-plan-limit   "$(slnk_bsm_plan | awk -F'\t' '$1=="limit"{print ($2 ~ /handoff/)?"ok":"no"}')" "ok"
    printf 'v1\t0\t52.5200\t13.4050\t15\nv1\t1\t52.5200\t13.4050\t15\nv1\t2\t52.5300\t13.4050\t15\n' > "$d/ghost.tsv"
    chk bsm-ghost-verdict "$(slnk_bsm_audit "$d/ghost.tsv" | awk -F'\t' '$1=="verdict"{print $2}')" "ghost_in_traffic"
    chk bsm-ghost-finding "$(slnk_bsm_audit "$d/ghost.tsv" | awk -F'\t' '$1=="finding" && $2=="ghost_vehicle"{print "yes"}')" "yes"
    printf 'v1\t0\t52.5200\t13.4050\t15\nv1\t1\t52.5201\t13.4050\t15\n' > "$d/real.tsv"
    chk bsm-real-verdict "$(slnk_bsm_audit "$d/real.tsv" | awk -F'\t' '$1=="verdict"{print $2}')" "no_ghost_in_this_capture"
    chk bsm-audit-missing "$(slnk_bsm_audit "$d/nope.tsv" >/dev/null 2>&1; echo $?)" "1"
    chk bsm-audit-noargs "$(slnk_bsm_audit >/dev/null 2>&1; echo $?)" "2"
    # 9. Pseudonym rotation audit: reuse, linkage, and a single certificate.
    printf '1700000000\taa\n1700000010\taa\n1700000400\tbb\n1700000410\tbb\n1700000405\tcc\n' > "$d/trace.tsv"
    chk pau-pseudonyms "$(slnk_cmd_pseudonym_audit "$d/trace.tsv" 300 | awk -F'\t' '$1=="pseudonyms"{print $2}')" "3"
    chk pau-linkage "$(slnk_cmd_pseudonym_audit "$d/trace.tsv" 300 | awk -F'\t' '$1=="linkable_pairs"{print $2}')" "1"
    chk pau-linkable-verdict "$(slnk_cmd_pseudonym_audit "$d/trace.tsv" 300 | awk -F'\t' '$1=="verdict"{print $2}')" "pseudonyms_linkable"
    chk pau-reuse "$(slnk_cmd_pseudonym_audit "$d/trace.tsv" 10 | awk -F'\t' '$1=="reused_pseudonyms"{print $2}')" "2"
    printf '1700000000\taa\n1700000010\taa\n' > "$d/one.tsv"
    chk pau-single-verdict "$(slnk_cmd_pseudonym_audit "$d/one.tsv" 300 | awk -F'\t' '$1=="verdict"{print $2}')" "pseudonyms_linkable"
    chk pau-no-rotation "$(slnk_cmd_pseudonym_audit "$d/one.tsv" 300 | awk -F'\t' '$1=="finding" && $2=="no_rotation"{print $3}')" "HIGH"
    chk pau-missing "$(slnk_cmd_pseudonym_audit "$d/nope.tsv" 300 >/dev/null 2>&1; echo $?)" "1"
    chk pau-noargs "$(slnk_cmd_pseudonym_audit >/dev/null 2>&1; echo $?)" "2"
    chk pau-bad-bucket "$(slnk_cmd_pseudonym_audit "$d/trace.tsv" zero >/dev/null 2>&1; echo $?)" "2"
    # 10. The rogue relay: position, plaintext, and the refusal paths.
    printf 'relay_layer=layer2\ntraffic=dns\n' > "$d/rel.conf"
    local ro; ro=$(slnk_cmd_relay_interpose "$d/rel.conf")
    chk ri-layer      "$(awk -F'\t' '$1=="relay_layer"{print $2}' <<<"$ro")" "layer2"
    chk ri-position   "$(awk -F'\t' '$1=="finding" && $2=="relay_position"{print $3}' <<<"$ro")" "HIGH"
    chk ri-plaintext  "$(awk -F'\t' '$1=="finding" && $2=="plaintext_visible"{print $3}' <<<"$ro")" "HIGH"
    chk ri-verdict    "$(awk -F'\t' '$1=="verdict"{print $2}' <<<"$ro")" "relay_sees_traffic"
    printf 'relay_layer=layer3\ntraffic=https\n' > "$d/rel3.conf"
    chk ri-meta       "$(slnk_cmd_relay_interpose "$d/rel3.conf" | awk -F'\t' '$1=="finding" && $2=="metadata_only"{print $3}')" "MEDIUM"
    chk ri-bad-layer  "$(printf 'relay_layer=layer9\n' > "$d/bad.conf"; slnk_cmd_relay_interpose "$d/bad.conf" >/dev/null 2>&1; echo $?)" "2"
    chk ri-missing    "$(slnk_cmd_relay_interpose "$d/none.conf" >/dev/null 2>&1; echo $?)" "1"
    chk ri-noargs     "$(slnk_cmd_relay_interpose >/dev/null 2>&1; echo $?)" "2"
    # 11. Kinematic linkage across a rotated certificate.
    printf 'aa\t0\t52.52000\t13.40500\t15\t90\naa\t5\t52.52000\t13.40550\t15\t90\nbb\t9\t52.52000\t13.40620\t15\t90\nbb\t14\t52.52000\t13.40670\t15\t90\n' > "$d/link.tsv"
    local lo; lo=$(slnk_cmd_linkage "$d/link.tsv")
    chk link-successors "$(awk -F'\t' '$1=="linkable_successors"{print $2}' <<<"$lo")" "1"
    chk link-gap       "$(awk -F'\t' '$2=="aa" && $3=="bb"{print $4}' <<<"$lo")" "gap_s=4"
    chk link-verdict   "$(awk -F'\t' '$1=="verdict"{print $2}' <<<"$lo")" "pseudonyms_linkable"
    chk link-finding   "$(awk -F'\t' '$1=="finding" && $2=="kinematic_linkage"{print $3}' <<<"$lo")" "HIGH"
    printf 'aa\t0\t0.00000\t0.00000\t10\t0\naa\t5\t0.00000\t0.00000\t10\t0\nbb\t9\t0.50000\t0.50000\t10\t0\n' > "$d/far.tsv"
    chk link-far       "$(slnk_cmd_linkage "$d/far.tsv" --gap 10 --radius 50 | awk -F'\t' '$1=="verdict"{print $2}')" "pseudonyms_unlinked_in_this_capture"
    chk link-bad-gap   "$(slnk_cmd_linkage "$d/link.tsv" --gap abc >/dev/null 2>&1; echo $?)" "2"
    chk link-missing   "$(slnk_cmd_linkage "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"
    chk link-noargs    "$(slnk_cmd_linkage >/dev/null 2>&1; echo $?)" "2"
    # 12. The V2X service advertisement: a container this module defines, a
    #     round trip through it, and a refusal for octets it does not own. The
    #     gossip rows name the TS 24.587 header as unobserved on every run.
    local adv advhex
    adv=$(slnk_cmd_pc5_advert build 0x00008001 --l2id a1b2c3 --pqi 8 --pdb-ms 20 --gfbr-kbps 500 --repeat-ms 100)
    advhex=$(fld "$adv" hex)
    chk adv-psid      "$(fld "$adv" psid_dec)" "32769"
    chk adv-l2id      "$(fld "$adv" l2_id)" "a1b2c3"
    chk adv-octets    "$(fld "$adv" container_octets)" "19"
    chk adv-hex-len   "${#advhex}" "38"
    chk adv-repeats   "$(fld "$adv" repeats_per_min)" "600"
    chk adv-beacons   "$(fld "$adv" beacons_per_hour)" "36000"
    chk adv-fixed-id  "$(printf '%s\n' "$adv" | awk -F'\t' '$1=="finding" && $2=="fixed_l2id"{print $3}')" "MEDIUM"
    chk adv-roundtrip-psid "$(fld "$(slnk_cmd_pc5_advert parse "$advhex")" psid_dec)" "32769"
    chk adv-roundtrip-rep  "$(fld "$(slnk_cmd_pc5_advert parse "$advhex")" repeat_ms)" "100"
    chk adv-roundtrip-pqi  "$(fld "$(slnk_cmd_pc5_advert parse "$advhex")" pqi)" "8"
    chk adv-foreign-refused "$(slnk_cmd_pc5_advert parse deadbeef >/dev/null 2>&1; echo $?)" "1"
    chk adv-short-refused   "$(slnk_cmd_pc5_advert parse 5632583100 >/dev/null 2>&1; echo $?)" "1"
    chk adv-bad-psid  "$(slnk_cmd_pc5_advert build 4294967296 >/dev/null 2>&1; echo $?)" "2"
    chk adv-bad-pqi   "$(slnk_cmd_pc5_advert build 1 --pqi 256 >/dev/null 2>&1; echo $?)" "2"
    chk adv-no-psid   "$(slnk_cmd_pc5_advert build >/dev/null 2>&1; echo $?)" "2"
    chk adv-no-sub    "$(slnk_cmd_pc5_advert >/dev/null 2>&1; echo $?)" "2"
    chk adv-not-wire  "$(slnk_adv_doctrine | awk -F'\t' '$1=="format"{print ($2 ~ /NOT the TS 24.587/)?"yes":"no"}')" "yes"
    chk adv-unobserved-v5 "$(slnk_adv_doctrine | awk -F'\t' '$1=="unobserved" && $2=="v5_message_header"' | wc -l)" "1"
    chk adv-unobserved-pqi "$(slnk_adv_doctrine | awk -F'\t' '$1=="unobserved" && $2=="pqi_characteristics"' | wc -l)" "1"
    # 13. PC5 QoS: the invariant, the slot arithmetic, and the honest blanks.
    local q
    chk qos-blank-pqi "$(fld "$(slnk_cmd_pc5_qos)" pqi)" "unobserved"
    chk qos-blank-reason "$(slnk_cmd_pc5_qos | awk -F'\t' '$1=="note"{print ($2 ~ /unobserved/)?"yes":"no"}')" "yes"
    q=$(slnk_cmd_pc5_qos --pqi 8 --resource-type gbr --gfbr-kbps 500 --mfbr-kbps 400 --pdb-ms 20 --scs-khz 30) && qrc=0 || qrc=$?
    chk qos-inconsistent-rc "$qrc" "1"
    chk qos-inconsistent "$(printf '%s\n' "$q" | awk -F'\t' '$1=="finding" && $2=="qos_inconsistent"{print $3}')" "HIGH"
    q=$(slnk_cmd_pc5_qos --gfbr-kbps 500 --mfbr-kbps 1000 --pdb-ms 20 --scs-khz 30)
    chk qos-consistent "$(fld "$q" verdict)" "qos_consistent"
    chk qos-slot "$(fld "$q" slot_ms)" "0.5000"
    chk qos-slots "$(fld "$q" pdb_slots)" "40.0000"
    chk qos-inflight "$(fld "$q" in_flight_bits)" "10000"
    chk qos-mu15 "$(fld "$(slnk_cmd_pc5_qos --scs-khz 15 --pdb-ms 10)" slot_ms)" "1.0000"
    chk qos-bad-rtype "$(slnk_cmd_pc5_qos --resource-type maybe >/dev/null 2>&1; echo $?)" "2"
    chk qos-bad-scs   "$(slnk_cmd_pc5_qos --scs-khz 7 >/dev/null 2>&1; echo $?)" "2"
    chk qos-bad-per   "$(slnk_cmd_pc5_qos --per 2 >/dev/null 2>&1; echo $?)" "2"
    chk qos-store-header "$(grep -c '^ts' "$SLNK_DIR/pc5-qos.tsv")" "1"
    chk qos-store-row "$(awk -F'\t' '$10=="qos_inconsistent"' "$SLNK_DIR/pc5-qos.tsv" | wc -l)" "1"
    chk advert-store-header "$(grep -c '^ts' "$SLNK_DIR/v2x_adverts.tsv")" "1"
    chk advert-store-row "$(awk -F'\t' '$2=="pc5-advert" && $3=="32769" && $4=="a1b2c3"' "$SLNK_DIR/v2x_adverts.tsv" | wc -l)" "1"
    # 14. The advertisement plan is a handoff, not a failure.
    chk v2x-plan-status "$(slnk_v2x_plan | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk v2x-plan-exit   "$(slnk_v2x_plan >/dev/null 2>&1; echo $?)" "3"
    chk v2x-plan-gap    "$(slnk_v2x_plan | awk -F'\t' '$1=="not_implemented"{print ($2 ~ /TS 24.587/)?"yes":"no"}')" "yes"
    chk v2x-plan-needs  "$(slnk_v2x_plan | awk -F'\t' '$1=="needs_2"{print ($2 ~ /102 941/)?"yes":"no"}')" "yes"
    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── the ghost vehicle ───────────────────────────────────────────────────
# A BSM says where a car is. Nothing in the message proves a car is there.
# The plan half lists what a ghost needs to be believed; the audit half is
# the arithmetic a receiver can run to catch one, and it needs no key: a
# vehicle that teleports, accelerates past what a tyre can do, or reports a
# speed that disagrees with its own positions is not a vehicle.
slnk_bsm_plan() {
    cat <<'EOF'
role	the ghost broadcasts the same message a real vehicle does, for a vehicle that is not there
message	SAE J2735 BasicSafetyMessage: msgCnt, id (4 octets), secMark, lat/lon (1/10 microdegree), elevation, accuracy, transmission state, speed (0.02 m/s units), heading (0.0125 degree units), acceleration, brake status, vehicle size
signing	a real BSM is signed under an IEEE 1609.2 pseudonym certificate; a receiver that only checks the signature accepts a ghost that holds any valid certificate, which is why the certificate proves who signed and not who is there
needs	1. a certificate chain a receiver accepts  2. a position on a road a receiver believes  3. a speed and heading consistent with the road's own flow  4. an id that is either new (a fresh vehicle, plausible) or continuing (a vehicle that was there)
harder	a ghost that follows a real vehicle's trajectory at a fixed offset is the shape that survives plausibility checks; a stationary ghost in a live road is caught in seconds by the flow model
catch	1. kinematics: positions that disagree with the reported speed, or acceleration beyond grip (kinematic_fault)  2. an id that stops and restarts at a distant position (teleport)  3. two ids that move as one (cloning)  4. a vehicle that never yields to anything (no interaction) -- all of them arithmetic over a capture, none of them needs the key
limit	the transmit half needs a PC5 sidelink PHY at 5.9 GHz and a certificate a receiver accepts; this tree builds the message model and the audit, and states the transmit as a handoff rather than pretending to a radio it does not have
EOF
}

slnk_bsm_audit() {  # <log.tsv>
    local log="${1:-}"
    [[ -n "$log" ]] || { printf 'ERROR\tusage: --bsm-audit <log.tsv> (id, t_s, lat_deg, lon_deg, speed_mps)\n' >&2; return 2; }
    [[ -r "$log" ]] || { printf 'ERROR\tcannot read %s\n' "$(slnk_sanitize "$log")" >&2; return 1; }
    local rows n
    rows=$(grep -v '^#' "$log" | grep . | awk -F'\t' 'NF>=5{print $1"\t"$2"\t"$3"\t"$4"\t"$5}')
    n=$(printf '%s\n' "$rows" | grep -c . || true)
    (( n >= 2 )) || { printf 'ERROR\tneed at least two messages to have a gap; %d read\n' "$n" >&2; return 1; }
    printf '%s\n' "$rows" | awk -F'\t' '
        function rad(x) { return x * 3.14159265358979 / 180 }
        function dist(a1,o1,a2,o2,   dlat,dlon,x,y) {
            dlat = rad(a2-a1); dlon = rad(o2-o1)
            x = dlon * cos(rad((a1+a2)/2)); y = dlat
            return 6371000 * sqrt(x*x + y*y)
        }
        {
            id[NR]=$1; t[NR]=$2+0; la[NR]=$3+0; lo[NR]=$4+0; sp[NR]=$5+0; order[NR]=$1
        }
        END {
            # per-id kinematic checks over consecutive samples
            printf "messages\t%d\n", NR
            ids = 0
            for (i = 1; i <= NR; i++) if (!(id[i] in seen)) { seen[id[i]]=1; ids++ }
            printf "vehicles\t%d\n", ids
            tele = 0; accel = 0; imps = 0
            for (i = 2; i <= NR; i++) {
                if (id[i] != id[i-1]) continue
                dt = t[i] - t[i-1]
                if (dt <= 0) { printf "sample\t%d\tclock\tnon-monotonic timestamp for %s\n", i, id[i]; bad++; continue }
                d = dist(la[i-1], lo[i-1], la[i], lo[i])
                v = d / dt
                dv = v - sp[i-1]
                # 9 m/s^2 is past what a road tyre sustains; 15 m/s per step
                a = dv / dt
                if (v > 80 || a > 15) {
                    printf "impossible\t%s\t%d\t%.1f m in %.1f s = %.1f m/s, reported %.1f\n", id[i], i, d, dt, v, sp[i-1]
                    imps++
                } else if (v - sp[i-1] > 12 || sp[i-1] - v > 12) {
                    printf "inconsistent\t%s\t%d\tmoved %.1f m/s while reporting %.1f m/s\n", id[i], i, v, sp[i-1]
                    imps++
                }
            }
            printf "impossible^%d\n", imps
            printf "findings\t%d\n", imps + 0
            if (imps > 0) {
                printf "finding\tghost_vehicle\tMEDIUM\t%d message(s) describe motion a road vehicle cannot perform; the signature over each one was fine, which is the point: a certificate proves who signed, not who is there\n", imps
                printf "verdict\tghost_in_traffic\n"
            } else {
                printf "finding\tkinematics_consistent\tINFO\tevery consecutive pair of positions agrees with the speed the message reported\n"
                printf "verdict\tno_ghost_in_this_capture\n"
                printf "note\t%s\n", "a ghost that follows a real trajectory at an offset passes this check; a receiver with road topology does better, and the arithmetic above is the free half"
            }
        }' | grep -v '^impossible^'
}

# ── the V2X service advertisement on PC5 (TS 23.287 / TS 24.587) ─────────
# Two different things get called "the advertisement": what a UE announces —
# a V2X service identified by a PSID (an ITS-AID), with a PC5 QoS profile
# attached to it — and the octets that carry it. The first is citable field by
# field. The second is not: the TS 24.587 V5 message header layout is not in
# this tree (the SCI-1A refusal above is the same gap, one layer down), so
# this module builds its OWN container, says so on every row, and refuses
# foreign octets by name instead of guessing an offset. A round trip through
# that container is a property this module can prove; a claim to speak the
# standard's wire format is not.
SLNK_ADV_MAGIC="56325831"          # 'V2X1' — this module's container tag
slnk_adv_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --pc5-advert build <psid> [--l2id <hex>] [--pqi N] [--pdb-ms N] [--gfbr-kbps N] [--repeat-ms N]
	       --pc5-advert parse <hex>
EOF
}
slnk_adv_doctrine() {
    printf 'format\t%s\n' "this module's own 19-octet container tagged V2X1; it is NOT the TS 24.587 V5 wire format and no row here claims to be"
    printf 'container\tmagic 4 o (V2X1) | psid 4 o BE | l2_id 3 o | pqi 1 o | pdb_ms 2 o BE | gfbr_kbps 3 o BE | repeat_ms 2 o BE = 19 octets\n'
    printf 'psid_width\t32 bits\tIEEE 1609.2 / SAE J2735: a PSID (ITS-AID) is a 32-bit identifier, and TS 23.287 identifies a V2X service by one\n'
    printf 'l2id_width\t24 bits\tTS 23.287 5.6: PC5 addresses a station by a 24-bit Layer-2 ID, not by an IMSI or a phone number\n'
    printf 'unobserved\tv5_message_header\tthe TS 24.587 V5 message header field order is not in this tree, so these octets are a container this module defines and not a message it can claim to send\n'
    printf 'unobserved\tpqi_characteristics\tthe PQI to (resource type, priority, PDB, PER) binding lives in TS 23.287 Table 5.4.4-1, which is not in this tree: a PQI number alone yields no characteristics here\n'
    printf 'ref\tTS 23.287 (V2X architecture and PC5 QoS), TS 24.587 (V5 protocol aspects), IEEE 1609.2 (PSID/ITS-AID)\n'
}
slnk_adv_hex() {  # build|parse helper: print the field rows for a container
    local hex="$1"
    local psid_hex="${hex:8:8}" l2_hex="${hex:16:6}" pqi_hex="${hex:22:2}"
    local pdb_hex="${hex:24:4}" gfbr_hex="${hex:28:6}" rep_hex="${hex:34:4}"
    printf 'container_octets\t%d\n' "$(( ${#hex} / 2 ))"
    printf 'psid\t%s\n' "$psid_hex"
    printf 'psid_dec\t%d\n' "$(( 16#$psid_hex ))"
    printf 'l2_id\t%s\n' "$l2_hex"
    printf 'pqi\t%d\n' "$(( 16#$pqi_hex ))"
    printf 'pdb_ms\t%d\n' "$(( 16#$pdb_hex ))"
    printf 'gfbr_kbps\t%d\n' "$(( 16#$gfbr_hex ))"
    printf 'repeat_ms\t%d\n' "$(( 16#$rep_hex ))"
}
slnk_cmd_pc5_advert() {
    local sub="${1:-}"
    (($#)) && shift || true
    case "$sub" in
        build|parse) ;;
        *) slnk_adv_usage; return 2 ;;
    esac
    if [[ "$sub" == "parse" ]]; then
        local in="${1:-}"
        [[ -n "$in" ]] || { slnk_adv_usage; return 2; }
        local hex
        hex=$(printf '%s' "$in" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
        [[ "$hex" =~ ^[0-9a-f]+$ ]] || { printf 'ERROR\toctets must be hex: %s\n' "$(slnk_sanitize "$in")" >&2; return 2; }
        if [[ "${hex:0:8}" != "$SLNK_ADV_MAGIC" ]]; then
            printf 'WHY\tthe first four octets are not V2X1, so this is not the container --pc5-advert build writes, and the TS 24.587 V5 header layout that would tell a parser where a PSID starts is not in this tree\n' >&2
            printf 'ERROR\trefusing to guess a field offset for foreign octets\n' >&2
            return 1
        fi
        (( ${#hex} == 38 )) || {
            printf 'ERROR\tthe V2X1 container is 38 hex digits (19 octets); %d were given, so the tail is not attributable to a field\n' "${#hex}" >&2
            return 1; }
        slnk_adv_hex "$hex"
        printf 'hex\t%s\n' "$hex"
        local rep; rep=$(( 16#${hex:34:4} ))
        if (( rep > 0 )); then
            printf 'repeats_per_min\t%d\n' "$(( 60000 / rep ))"
            printf 'beacons_per_hour\t%d\n' "$(( 3600000 / rep ))"
        else
            printf 'repeats_per_min\tunobserved\tthe repeat interval is zero, so no advertisement rate follows from it\n'
        fi
        printf 'verdict\tdecoded_from_this_module_container\n'
        slnk_adv_doctrine
        return 0
    fi

    local psid="${1:-}"
    [[ -n "$psid" ]] || { slnk_adv_usage; return 2; }
    shift || true
    local l2id="000000" pqi=0 pdb=0 gfbr=0 repeat=100
    while (($#)); do
        case "${1:-}" in
            --l2id)       l2id="${2:-}";  shift $(( $# >= 2 ? 2 : 1 )) ;;
            --pqi)        pqi="${2:-}";   shift $(( $# >= 2 ? 2 : 1 )) ;;
            --pdb-ms)     pdb="${2:-}";   shift $(( $# >= 2 ? 2 : 1 )) ;;
            --gfbr-kbps)  gfbr="${2:-}";  shift $(( $# >= 2 ? 2 : 1 )) ;;
            --repeat-ms)  repeat="${2:-}";shift $(( $# >= 2 ? 2 : 1 )) ;;
            "")           shift ;;
            *) printf 'ERROR\tunknown option for --pc5-advert: %s\n' "$(slnk_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    local psid_hex
    if [[ "$psid" =~ ^[0-9]+$ ]]; then
        (( psid <= 4294967295 )) || { printf 'ERROR\tpsid must fit 32 bits (0..4294967295), which is the width IEEE 1609.2 gives a PSID\n' >&2; return 2; }
        psid_hex=$(printf '%08x' "$psid")
    elif [[ "$psid" =~ ^(0[xX])?([0-9a-fA-F]{1,8})$ ]]; then
        psid_hex=$(printf '%08x' "$(( 16#${BASH_REMATCH[2]} ))")
    else
        printf 'ERROR\tpsid must be decimal or 1..8 hex digits\n' >&2; return 2
    fi
    local l2_hex
    l2_hex=$(printf '%s' "$l2id" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
    [[ "$l2_hex" =~ ^[0-9a-f]{1,6}$ ]] || { printf 'ERROR\t--l2id must be 1..6 hex digits (24 bits, TS 23.287 5.6)\n' >&2; return 2; }
    l2_hex=$(printf '%06x' "$(( 16#$l2_hex ))")
    local ok=1
    [[ "$pqi"   =~ ^[0-9]+$ ]] && (( pqi <= 255 ))      || ok=0
    [[ "$pdb"   =~ ^[0-9]+$ ]] && (( pdb <= 65535 ))    || ok=0
    [[ "$gfbr"  =~ ^[0-9]+$ ]] && (( gfbr <= 16777215 ))|| ok=0
    [[ "$repeat" =~ ^[0-9]+$ ]] && (( repeat >= 1 && repeat <= 65535 )) || ok=0
    (( ok == 1 )) || {
        printf 'ERROR\t--pqi 0..255, --pdb-ms 0..65535, --gfbr-kbps 0..16777215, --repeat-ms 1..65535 (the container widths)\n' >&2
        return 2; }
    local hex
    hex="${SLNK_ADV_MAGIC}$(printf '%s%06x%02x%04x%06x%04x' "$psid_hex" "$(( 16#$l2_hex ))" "$pqi" "$pdb" "$gfbr" "$repeat")"
    slnk_adv_hex "$hex"
    printf 'hex\t%s\n' "$hex"
    printf 'repeats_per_min\t%d\n' "$(( 60000 / repeat ))"
    printf 'beacons_per_hour\t%d\n' "$(( 3600000 / repeat ))"
    printf 'finding\tfixed_l2id\tMEDIUM\tthe advertisement carries one Layer-2 ID for the whole repetition period, so %d announcements an hour are joinable into one station without any key\n' "$(( 3600000 / repeat ))"
    printf 'verdict\tcontainer_built\n'
    local store="${SLNK_DIR:-$LOOT_DIR/sidelink}/v2x_adverts.tsv"
    mkdir -p "${store%/*}"
    [[ -s "$store" ]] || printf 'ts\tverb\tpsid\tl2_id\tpqi\thex\trepeats_per_min\n' > "$store"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        pc5-advert "$(( 16#$psid_hex ))" "$l2_hex" "$pqi" "$hex" "$(( 60000 / repeat ))" >> "$store"
    slnk_adv_doctrine
}

# ── PC5 QoS parameters (TS 23.287 5.4.4) ─────────────────────────────────
# A PC5 QoS profile is a PQI, a PFI per flow, and — for a GBR flow — a
# guaranteed and a maximum bit rate. Three of the checks below are arithmetic
# rather than quotation: MFBR must not sit below GFBR, a packet delay budget
# converts to a slot count at a stated numerology, and PDB x rate is how many
# bits the flow may have in flight. The PQI's own characteristics are a table
# this tree does not hold, so a PQI number alone yields `unobserved`.
slnk_qos_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --pc5-qos [--pqi N] [--resource-type gbr|non-gbr] [--gfbr-kbps N]
	      [--mfbr-kbps N] [--pdb-ms N] [--per P] [--priority N] [--scs-khz 15|30|60|120]
EOF
}
slnk_cmd_pc5_qos() {
    local pqi="" rtype="" gfbr="" mfbr="" pdb="" per="" prio="" scs=""
    while (($#)); do
        case "${1:-}" in
            --pqi)           pqi="${2:-}";   shift $(( $# >= 2 ? 2 : 1 )) ;;
            --resource-type) rtype="${2:-}"; shift $(( $# >= 2 ? 2 : 1 )) ;;
            --gfbr-kbps)     gfbr="${2:-}";  shift $(( $# >= 2 ? 2 : 1 )) ;;
            --mfbr-kbps)     mfbr="${2:-}";  shift $(( $# >= 2 ? 2 : 1 )) ;;
            --pdb-ms)        pdb="${2:-}";   shift $(( $# >= 2 ? 2 : 1 )) ;;
            --per)           per="${2:-}";   shift $(( $# >= 2 ? 2 : 1 )) ;;
            --priority)      prio="${2:-}";  shift $(( $# >= 2 ? 2 : 1 )) ;;
            --scs-khz)       scs="${2:-}";   shift $(( $# >= 2 ? 2 : 1 )) ;;
            "")              shift ;;
            *) slnk_qos_usage; return 2 ;;
        esac
    done
    [[ -z "$pqi" || "$pqi" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--pqi must be numeric\n' >&2; return 2; }
    [[ -z "$rtype" || "$rtype" =~ ^(gbr|non-gbr)$ ]] || { printf 'ERROR\t--resource-type must be gbr or non-gbr\n' >&2; return 2; }
    local v
    for v in "$gfbr" "$mfbr"; do
        [[ -z "$v" || "$v" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--gfbr-kbps and --mfbr-kbps want whole kbit/s\n' >&2; return 2; }
    done
    [[ -z "$pdb" || "$pdb" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--pdb-ms wants whole milliseconds\n' >&2; return 2; }
    [[ -z "$per" || "$per" =~ ^(0([.][0-9]+)?|1([.]0+)?|[.][0-9]+)$ ]] || { printf 'ERROR\t--per wants a probability in (0,1]\n' >&2; return 2; }
    [[ -z "$prio" || "$prio" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--priority must be numeric\n' >&2; return 2; }
    [[ -z "$scs" || "$scs" =~ ^(15|30|60|120)$ ]] || { printf 'ERROR\t--scs-khz must be 15, 30, 60 or 120\n' >&2; return 2; }

    local store="${SLNK_DIR:-$LOOT_DIR/sidelink}/pc5-qos.tsv"
    mkdir -p "${store%/*}" 2>/dev/null
    [[ -s "$store" ]] || printf 'ts\tpqi\tresource_type\tgfbr_kbps\tmfbr_kbps\tpdb_ms\tper\tpriority\tscs_khz\tverdict\n' >> "$store"

    local u="unobserved"
    printf 'pqi\t%s\n' "${pqi:-$u}"
    printf 'resource_type\t%s\n' "${rtype:-$u}"
    printf 'gfbr_kbps\t%s\n' "${gfbr:-$u}"
    printf 'mfbr_kbps\t%s\n' "${mfbr:-$u}"
    printf 'pdb_ms\t%s\n' "${pdb:-$u}"
    printf 'per\t%s\n' "${per:-$u}"
    printf 'priority\t%s\n' "${prio:-$u}"
    printf 'scs_khz\t%s\n' "${scs:-$u}"
    local verdict="parameters_incomplete" rc=0
    if [[ -n "$scs" ]]; then
        local mu=0 t="$scs" slot
        while (( t > 15 )); do t=$(( t / 2 )); mu=$(( mu + 1 )); done
        slot=$(awk -v m="$mu" 'BEGIN{ printf "%.4f", 1.0 / (2 ^ m) }')
        printf 'numerology_mu\t%d\n' "$mu"
        printf 'slot_ms\t%s\n' "$slot"
        if [[ -n "$pdb" ]]; then
            printf 'pdb_slots\t%s\n' "$(awk -v p="$pdb" -v s="$slot" 'BEGIN{ printf "%.4f", p / s }')"
        else
            printf 'pdb_slots\tunobserved\tthe packet delay budget was not supplied\n'
        fi
    fi
    if [[ -n "$pdb" && -n "$gfbr" ]]; then
        printf 'in_flight_bits\t%s\n' "$(awk -v p="$pdb" -v r="$gfbr" 'BEGIN{ printf "%.0f", r * 1000 * p / 1000 }')"
    else
        printf 'in_flight_bits\tunobserved\tPDB x GFBR needs both a delay budget and a rate\n'
    fi
    if [[ -n "$gfbr" && -n "$mfbr" ]]; then
        if (( mfbr < gfbr )); then
            printf 'finding\tqos_inconsistent\tHIGH\tMFBR %s kbit/s sits below GFBR %s kbit/s, which no flow can honour: the guaranteed rate would exceed the maximum the flow is allowed\n' "$mfbr" "$gfbr"
            printf 'verdict\tqos_inconsistent\n'
            printf 'ref\tTS 23.287 5.4.4 (PC5 QoS parameters), TS 24.587 (V5 signalling)\n'
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "${pqi:-}" "${rtype:-}" "$gfbr" "$mfbr" "${pdb:-}" "${per:-}" "${prio:-}" "${scs:-}" "qos_inconsistent" >> "$store"
            return 1
        fi
        printf 'finding\tqos_consistent\tINFO\tMFBR %s kbit/s is at or above GFBR %s kbit/s, which is the invariant a GBR flow has to satisfy\n' "$mfbr" "$gfbr"
        verdict="qos_consistent"
    else
        printf 'mfbr_gfbr_check\tunobserved\tboth --gfbr-kbps and --mfbr-kbps are needed to test the invariant\n'
    fi
    if [[ -z "$pqi" && -z "$rtype" && -z "$pdb" && -z "$per" && -z "$prio" ]]; then
        printf 'note\tthis verb reports the parameter set: supply a value for any row you know and the rest stay unobserved rather than being filled in from the PQI table this tree does not hold\n'
    fi
    printf 'verdict\t%s\n' "$verdict"
    printf 'ref\tTS 23.287 5.4.4 (PC5 QoS parameters), TS 24.587 (V5 signalling)\n'
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "${pqi:-}" "${rtype:-}" "${gfbr:-}" "${mfbr:-}" "${pdb:-}" "${per:-}" "${prio:-}" "${scs:-}" "$verdict" >> "$store"
    return $rc
}

# ── what forging that advertisement would still need ────────────────────
slnk_v2x_plan() {
    cat <<'EOF'
status	handoff
what	advertising a V2X service on PC5 that a receiver believes
built_here	the advertisement model (--pc5-advert build/parse, its container and its round trip) and the PC5 QoS arithmetic (--pc5-qos: MFBR/GFBR invariant, PDB to slots, bits in flight)
not_implemented	the TS 24.587 V5 message header and its field order, which are not in this tree, so no octet here is claimed to be a wire-format V5 message
needs_1	a PC5 sidelink PHY at 5.9 GHz with transmit, which this module does not have and will not pretend to have
needs_2	an ITS credential chain a receiver accepts (TS 102 941): the advertisement is signed, and a receiver that validates rejects an unsigned one
needs_3	a PQI the receiver's own QoS mapping accepts, with GFBR/MFBR it believes — the numbers, not the octets, are what a receiver enforces
detect_by	a PSID advertising a service no operator offers, one Layer-2 ID repeating far more often than road traffic requires, or GFBR/PDB values that no real flow of that service uses
honest_verdict	the service advertisement is analysable here and the Qos arithmetic is exact; emitting one needs a radio, a credential and a header layout this tree does not hold
ref	TS 23.287 (V2X architecture, PC5 QoS), TS 24.587 (V5 protocol aspects), ETSI TS 102 941 (ITS credential provisioning)
EOF
    return 3
}


slnk_menu() {
    while true; do
        banner
        echo "  === NR Sidelink / V2X ==="
        echo
        cat <<'M'
  [1]  Subchannel count
  [2]  SCI-1A frequency field width
  [3]  PFI range
  [4]  Layer-2 ID
  [5]  SCI-1A field reference
  [6]  ITS certificate reference
  [7]  Relay configuration check
  [8]  Plan (handoff)
  [9]  Build a V2X advertisement (V2X1 container)
  [10] Parse an advertisement container
  [11] PC5 QoS parameters
  [12] V2X advertisement plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  bwp PRB> " b; read -rp "  subchannel PRB> " s; slnk_subchannels "$b" "$s"; read -rp "  enter " _ ;;
            2) read -rp "  subchannels> " n; slnk_freq_bits "$n"; read -rp "  enter " _ ;;
            3) read -rp "  pfi> " p; slnk_pfi "$p"; read -rp "  enter " _ ;;
            4) read -rp "  l2 id (hex)> " h; slnk_l2id "$h"; read -rp "  enter " _ ;;
            5) slnk_sci_1a; read -rp "  enter " _ ;;
            6) slnk_its; read -rp "  enter " _ ;;
            7) read -rp "  relay config> " p; slnk_relay_check "$p"; read -rp "  enter " _ ;;
            8) slnk_plan; read -rp "  enter " _ ;;
            9) read -rp "  psid (dec or hex)> " ps
               read -rp "  l2 id (hex, blank=000000)> " l2
               read -rp "  pqi (blank=0)> " pq
               read -rp "  repeat ms (blank=100)> " rp
               slnk_cmd_pc5_advert build "$ps" ${l2:+--l2id "$l2"} ${pq:+--pqi "$pq"} ${rp:+--repeat-ms "$rp"}
               read -rp "  enter " _ ;;
            10) read -rp "  container hex> " hx; slnk_cmd_pc5_advert parse "$hx"; read -rp "  enter " _ ;;
            11) read -rp "  pqi (blank=unobserved)> " pq
                read -rp "  gfbr kbit/s (blank=unobserved)> " gb
                read -rp "  mfbr kbit/s (blank=unobserved)> " mb
                read -rp "  pdb ms (blank=unobserved)> " pb
                read -rp "  scs kHz [15|30|60|120] (blank=unobserved)> " sc
                slnk_cmd_pc5_qos ${pq:+--pqi "$pq"} ${gb:+--gfbr-kbps "$gb"} ${mb:+--mfbr-kbps "$mb"} ${pb:+--pdb-ms "$pb"} ${sc:+--scs-khz "$sc"}
                read -rp "  enter " _ ;;
            12) slnk_v2x_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

slnk_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  slnk_status_tsv ;;
        --subchannels) slnk_subchannels "${1:-}" "${2:-}" ;;
        --freq-bits)   slnk_freq_bits "${1:-}" ;;
        --pfi)         slnk_pfi "${1:-}" ;;
        --l2id)        slnk_l2id "${1:-}" ;;
        --sci1a)       slnk_sci_1a ;;
        --its)         slnk_its ;;
        --relay-check) slnk_relay_check "${1:-}" ;;
        --bsm-plan)    slnk_bsm_plan ;;
        --bsm-audit)   slnk_bsm_audit "${1:-}" ;;
        --pseudonym-audit) slnk_cmd_pseudonym_audit "${1:-}" "${2:-}" ;;
        --relay-interpose) slnk_cmd_relay_interpose "${1:-}" ;;
        --linkage)       slnk_cmd_linkage "$@" ;;
        --pc5-advert)  slnk_cmd_pc5_advert "$@" ;;
        --pc5-qos)     slnk_cmd_pc5_qos "$@" ;;
        --v2x-plan)    slnk_v2x_plan ;;
        --plan)        slnk_plan ;;
        --selftest)    slnk_selftest ;;
        --menu)        slnk_menu ;;
        *)
            cat >&2 <<EOF
NR Sidelink / V2X — PC5 resource pools, SCI-1A and ITS security

Usage: $0 COMMAND
  --status-tsv               module state as TSV
  --subchannels <bwp_prb> <subchannel_prb>
  --freq-bits <n_subchannels>   SCI-1A frequency resource field width
  --pfi <1..64>              PC5 QoS flow identifier
  --l2id <hex>               24-bit Layer-2 ID
  --sci1a                    SCI format 1-A: refuses, the widths are not in this tree
  --its                      ETSI/1609.2 certificate roles (reference, no validator)
  --relay-check <conf>       UE-to-NW relay configuration findings
  --bsm-plan                 what a ghost vehicle needs, and what a receiver
                             can check without any key
  --bsm-audit <log.tsv>      kinematics over a BSM log (id, t_s, lat, lon,
                             speed_mps): teleports, impossible acceleration and
                             speed/position disagreements
  --linkage <trace.tsv> [--gap S] [--radius M]
                            kinematic linkage: certificates whose trajectories continue each other
  --relay-interpose <config>  what a UE-to-network relay sees and can change
  --pseudonym-audit <trace.tsv> [bucket-s]
                            pseudonym rotation audit: reuse and co-temporal linkage
  --pc5-advert build <psid> [--l2id <hex>] [--pqi N] [--pdb-ms N]
                            [--gfbr-kbps N] [--repeat-ms N]
                            a V2X service advertisement, built into this
                            module's own V2X1 container (PSID 32 bits, L2 ID
                            24 bits); says on every row that the TS 24.587
                            header is not what these octets are
  --pc5-advert parse <hex>  read that container back, field by field; refuses
                            foreign octets by name rather than guessing offsets
  --pc5-qos [--pqi N] [--resource-type gbr|non-gbr] [--gfbr-kbps N]
            [--mfbr-kbps N] [--pdb-ms N] [--per P] [--priority N] [--scs-khz N]
                            PC5 QoS parameters: the MFBR >= GFBR invariant, PDB
                            in slots at a numerology, bits in flight; unsupplied
                            rows read unobserved, not zero
  --v2x-plan                 what forging an advertisement still needs (handoff)
  --plan                     V2X handoff plan
  --selftest                 verify the arithmetic and detectors
  --menu                     interactive menu
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
    slnk_cli_main "$@"
fi
