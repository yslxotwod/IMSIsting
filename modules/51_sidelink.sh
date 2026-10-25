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
  --relay-interpose <config>  what a UE-to-network relay sees and can change
  --pseudonym-audit <trace.tsv> [bucket-s]
                            pseudonym rotation audit: reuse and co-temporal linkage
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
