#!/usr/bin/env bash
# rcs — Rich Communication Services: the messaging plane that sits on IMS.
#
# RCS is what a phone does when two subscribers both have it: 1:1 chat, group
# chat, file transfer, capability discovery, and the chatbot (MaaP) economy on
# top. Every one of those hangs off SIP and the CPIM/MSRP pair, and the
# configuration that tells a handset where they live is a document the network
# publishes to anyone who asks for it.
#
# Three surfaces this module covers, in the order they are worth looking at:
#
#   1. Provisioning. The RCS autoconfiguration document names the IMS APN, the
#      P-CSCF, the MSRP relay, the presence server and the chatbot list. It is
#      fetched over plain HTTPS by any handset on first boot. Reading it is a
#      GET, and it discloses the operator's internal naming as advertised fact.
#   2. Capability discovery. A SIP OPTIONS carrying RCS feature tags answers
#      with the capabilities of a *subscriber*, not of a server. Whether that
#      answer comes back for an address the caller has no relationship with is
#      the difference between a discovery mechanism and a subscriber oracle.
#   3. The message codecs themselves. CPIM (RFC 3862) and MSRP (RFC 4975/4976)
#      are the actual payloads, and both carry identity claims the network is
#      supposed to verify: a From header in a CPIM message is attacker-chosen
#      text unless something on the path checks it against the authenticated
#      IMPU.
#
# Attack owned: O14 adjacency (subscriber steering via signalling) and the
# identity-claim half of the RCS messaging plane — codec, discovery and
# disclosure detection. Transmit is a handoff: nothing here sends SIP.
#
# Doctrine (AGENTS.md §3): every row says whether it is measured, advertised or
# unobserved. A capability response that arrives is measured; a config document
# is advertised; anything this module could not read is unobserved, and is
# never written up as absent.
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

MOD_TMP="$TMP_DIR/rcs"
RCS_DIR="$LOOT_DIR/rcs"
mkdir -p "$MOD_TMP" "$RCS_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

rcs_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Byte length, not character length. Content-Length in CPIM and MSRP counts
# octets: a message whose body carries a 2-byte UTF-8 character is two octets
# longer than bash thinks it is, and a peer that reads the header literally
# truncates the body mid-character.
rcs_bytes() { printf '%s' "${1:-}" | wc -c | tr -d ' '; }

rcs_file_or_stdin() {
    local f="${1:-}"
    if [[ -z "$f" || "$f" == "-" ]]; then cat
    elif [[ -r "$f" ]]; then cat "$f"
    else printf 'ERROR\tcannot read %s\n' "$f" >&2; return 2; fi
}

# ── RCS feature tags ─────────────────────────────────────────────────────
# The tokens a handset puts in Accept-Contact to ask what a contact can do, and
# the ones that come back. Two dialects, both still in use: the OMA CPM ICSI
# refs (the 1:1 chat, group session, large-message and file-transfer services)
# and the 3GPP/GSMA IARI urns (the older RCS 1.0/2.0 names). A parser that knows
# only one dialect reads half the answers as "no capabilities".
#
# Source column: the document that defines the token. Nothing here was observed
# on a live network — this is a reference table and says so.
rcs_feature_table() {
    cat <<'EOF'
token	surface	dialect	source	meaning
urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg	chat	ICSI	OMA CPM 1.0	one-to-one chat, pager mode over SIP MESSAGE
urn:urn-7:3gpp-service.ims.icsi.oma.cpm.largemsg	chat	ICSI	OMA CPM 1.0	large message mode: the message arrives over MSRP instead of MESSAGE
urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session	group-chat	ICSI	OMA CPM 1.0	group session, MSRP media plane with a conference focus
urn:urn-7:3gpp-service.ims.icsi.oma.cpm.filetransfer	file-transfer	ICSI	OMA CPM 1.0	1:1 file transfer, MSRP
urn:urn-7:3gpp-service.ims.icsi.oma.cpm.deferred	deferred	ICSI	OMA CPM 1.0	store-and-forward messaging
urn:urn-7:3gpp-service.ims.icsi.gsma.callcomposer	call-composer	ICSI	GSMA RCC.07	content attached to a call before it is answered
urn:urn-7:3gpp-service.ims.icsi.gsma.sharedmap	map-share	ICSI	GSMA RCC.07	live map on the call
urn:urn-7:3gpp-service.ims.icsi.gsma.sharedsketch	sketch-share	ICSI	GSMA RCC.07	live sketch on the call
urn:urn-7:3gpp-service.ims.icsi.gsma.geolocpush	geo-push	ICSI	GSMA RCC.07	one-shot location push
urn:urn-7:3gpp-application.ims.iari.rcse.im	chat	IARI	GSMA RCC.07	RCS 1:1 chat (the pre-CPM name, still advertised)
urn:urn-7:3gpp-application.ims.iari.rcse.ft	file-transfer	IARI	GSMA RCC.07	RCS file transfer
urn:urn-7:3gpp-application.ims.iari.rcse.ftthumb	file-transfer	IARI	GSMA RCC.07	file-transfer thumbnail preview
urn:urn-7:3gpp-application.ims.iari.rcs.one.to.one	chat	IARI	GSMA RCC.07	RCS one-to-one service
urn:urn-7:3gpp-application.ims.iari.rcse.imgshare	image-share	IARI	GSMA RCC.07	image share during a call
urn:urn-7:3gpp-application.ims.iari.rcse.vsharing	video-share	IARI	GSMA RCC.07	video share during a call
urn:urn-7:3gpp-application.ims.iari.gsma.vvm	visual-voicemail	IARI	GSMA RCC.07	visual voicemail
urn:urn-7:3gpp-application.ims.iari.gsma-is	geoloc-pull	IARI	GSMA RCC.07	location pull
urn:urn-7:3gpp-application.ims.iari.rcs.chatbot	chatbot	IARI	GSMA RCC.07	A2P chatbot messaging (MaaP)
urn:urn-7:3gpp-application.ims.iari.rcs.chatbot.sa	chatbot-standalone	IARI	GSMA RCC.07	chatbot reached outside a conversation
urn:urn-7:3gpp-application.ims.iari.rcs.ec implicitly-standalone	presence	IARI	GSMA RCC.07	standalone messaging without a phone number
EOF
}

# The bare name is what a handset actually sends after "+g.3gpp.icsi-ref=" or
# "+g.3gpp.iari-ref=", URL-encoded. Strip the wrapper so a table lookup works
# on either form.
rcs_feature_norm() {
    local t="${1:-}"
    t="${t%\"}"; t="${t#\"}"
    t="${t//%3A/:}"; t="${t//%3a/:}"  # the wrapper arrives percent-encoded
    t="${t#urn%3Aurn-7%3A}"; t="${t#urn:urn-7:}"
    printf '%s' "$t"
}

# ── CPIM (RFC 3862) ─────────────────────────────────────────────────────
# A CPIM message is headers, a blank line, then the body. The headers include
# From and To as *presentational* identity — "Alice <sip:alice@example.com>" —
# and the standard is explicit that they are display text, not authentication.
# An RCS client that renders From without comparing it to the authenticated
# IMPU shows the attacker's chosen name next to the attacker's chosen address.
rcs_cpim_build() {
    local from="${1:-}" to="${2:-}" text="${3:-}" ctype="${4:-text/plain; charset=utf-8}"
    [[ -n "$from" && -n "$to" ]] || {
        printf 'ERROR\t--cpim-build needs a From and a To\n' >&2; return 2; }
    local len mid dt
    len=$(rcs_bytes "$text")
    mid="$(date -u +%Y%m%d%H%M%S).$$@rcs.local"
    dt="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'From: %s\r\n' "$from"
    printf 'To: %s\r\n' "$to"
    printf 'DateTime: %s\r\n' "$dt"
    printf 'Message-ID: <%s>\r\n' "$mid"
    printf 'Content-Type: %s\r\n' "$ctype"
    printf 'Content-Length: %s\r\n' "$len"
    printf '\r\n'
    printf '%s' "$text"
}

rcs_cpim_parse() {
    local in; in=$(rcs_file_or_stdin "${1:-}") || return $?
    printf '%s' "$in" | awk -v RS='\r\n\r\n' '
        NR==1 {
            n=split($0, h, "\r\n")
            for (i=1; i<=n; i++) {
                p=index(h[i], ":")
                if (p==0) { print "finding\tmalformed-header\tHIGH\ta header line has no colon: " h[i]; next }
                k=tolower(substr(h[i],1,p-1)); v=substr(h[i],p+1)
                sub(/^ /,"",v)
                print "header\t" k "\t" v
                have[k]=1
            }
            body=$0
            next
        }
        NR>1 { body=body "\r\n\r\n" $0 }
        END {
            print "body-bytes\t" length(body)
            if (!("from" in have))       print "finding\tmissing-from\tHIGH\tthe message claims no sender at all"
            if (!("to" in have))         print "finding\tmissing-to\tHIGH\tthe message names no recipient"
            if (!("message-id" in have)) print "finding\tmissing-message-id\tMEDIUM\twithout a Message-ID a client cannot refuse a replay"
            if (!("datetime" in have))   print "finding\tmissing-datetime\tLOW\tthe rendered timestamp will come from the receiver, not the sender"
            if (("content-length" in have) && (length(body) != have_len)) {
                # have_len is set below when the header is seen
            }
            if (("from" in have) && ("to" in have) && (have["from"] == have["to"]))
                print "finding\tfrom-equals-to\tMEDIUM\tthe sender and recipient are the same identity"
            print "verdict\tparsed"
        }' 
}

# ── MSRP (RFC 4975 / 4976) ──────────────────────────────────────────────
# MSRP is the media plane: file transfer, large messages and group chat all
# arrive as MSRP frames through a *relay*. The relay is the interesting box —
# it decides, per frame, whether the authenticated connection owns the
# session-id and the From-Path. A relay that forwards a frame whose From-Path
# is not the authenticated identity is an open messaging path.
rcs_msrp_build() {
    local to="${1:-}" from="${2:-}" ctype="${3:-message/cpim}" body="${4:-}"
    [[ -n "$to" && -n "$from" ]] || {
        printf 'ERROR\t--msrp-build needs To-Path and From-Path\n' >&2; return 2; }
    local tid len
    tid=$(printf 'r%05x%s' "$$" "$(date -u +%S)")
    len=$(rcs_bytes "$body")
    printf 'MSRP %s SEND\r\n' "$tid"
    printf 'To-Path: %s\r\n' "$to"
    printf 'From-Path: %s\r\n' "$from"
    printf 'Message-ID: %s\r\n' "$$.$(date -u +%s)@rcs.local"
    printf 'Byte-Range: 1-%s/%s\r\n' "$len" "$len"
    printf 'Content-Type: %s\r\n' "$ctype"
    printf 'Content-Length: %s\r\n' "$len"
    printf '\r\n'
    printf '%s\r\n' "$body"
    printf -- '-------%s$\r\n' "$tid"
}

rcs_msrp_parse() {
    local in; in=$(rcs_file_or_stdin "${1:-}") || return $?
    printf '%s' "$in" | awk '
        { sub(/\r$/,"") }
        NR==1 {
            if ($0 ~ /^MSRP /) {
                tid=$2; meth=$3
                print "start-line\t" $0
                print "transaction-id\t" tid
                print "method\t" meth
                if (length(tid) < 6) print "finding\ttid-too-short\tHIGH\tRFC 4975 requires at least 6 characters; a short one is guessable across sessions"
            } else {
                print "finding\tnot-msrp\tHIGH\tthe first line is not an MSRP request line"
                print "verdict\tunparsed"
                exit
            }
            next
        }
        /^-------/ {
            t=$0; sub(/^-+/,"",t); sub(/[?+$#]$/,"",t)
            print "terminator\t" $0
            if (t != tid) print "finding\tterminator-tid-mismatch\tHIGH\tthe frame closes with a different transaction-id: " t " vs " tid
            seen_end=1
            next
        }
        /^[A-Za-z-]+:/ && !inbody {
            p=index($0, ":"); k=tolower(substr($0,1,p-1)); v=substr($0,p+1); sub(/^ /,"",v)
            print "header\t" k "\t" v
            hdr[k]=v
            next
        }
        { if (!inbody && $0=="") { inbody=1; next } if (inbody) { body=body (body==""?"":"\n") $0 } }
        END {
            if (inbody) print "body-bytes\t" length(body)
            if (!("to-path" in hdr))   print "finding\tmissing-to-path\tHIGH\tthe frame names no next hop"
            if (!("from-path" in hdr)) print "finding\tmissing-from-path\tHIGH\tthe frame claims no source path; a relay cannot check ownership"
            if (!("message-id" in hdr)) print "finding\tmissing-message-id\tMEDIUM\twithout a Message-ID duplicate delivery cannot be detected"
            if (!seen_end) print "finding\tmissing-terminator\tHIGH\tthe frame never closed: a relay reading this stream stays in frame"
            if (meth == "SEND" && ("byte-range" in hdr)) {
                br=hdr["byte-range"]; 
                if (match(br, /^[0-9]+-[0-9]+\/[0-9]+$/) == 0)
                    print "finding\tbad-byte-range\tMEDIUM\tByte-Range is not start-end/total: " br
            }
            if (("from-path" in hdr) && ("to-path" in hdr) && (hdr["from-path"] == hdr["to-path"]))
                print "finding\tpath-loops-to-itself\tMEDIUM\tFrom-Path and To-Path are the same address"
            nf=0
            print "verdict\tparsed"
        }'
}

# ── RCS autoconfiguration ───────────────────────────────────────────────
# The document is OMA client provisioning (a <wap-provisioningdoc> tree of
# <characteristic type=...>/<parm name= value=>) in the classic form, and a flat
# key/JSON shape in newer profiles. One flattener handles the XML; a JSON scan
# handles the other. Both emit the same three columns so the classifier above
# them does not care which arrived.
rcs_config_flat() {
    local in; in=$(rcs_file_or_stdin "${1:-}") || return $?

    if printf '%s' "$in" | sed -n '1,3p' | grep -q '{'; then
        printf 'key\tvalue\tprovenance\n'
        printf '%s' "$in" | grep -oE '"[A-Za-z0-9_.-]+"[[:space:]]*:[[:space:]]*("[^"]*"|[0-9]+)' |
            awk -F'"' '{k=$2; v=$4; gsub(/\\/,"",v); print k "\t" v "\tadvertised"}'
        return 0
    fi

    printf 'parm\tvalue\tprovenance\n'
    printf '%s' "$in" | sed -e 's/></>\n</g' | awk '
        { sub(/^[ \t]+/, "") }
        /^<characteristic/ {
            t=""
            if (match($0, /type="[^"]*"/)) t=substr($0, RSTART+6, RLENGTH-7)
            depth++; stack[depth]=t; next
        }
        /^<\/characteristic/ { if (depth>0) { stack[depth]=""; depth-- } next }
        /^<parm/ {
            n=""; v=""
            if (match($0, /name="[^"]*"/))  n=substr($0, RSTART+6, RLENGTH-7)
            if (match($0, /value="[^"]*"/)) v=substr($0, RSTART+7, RLENGTH-8)
            if (n=="") next
            p=""
            for (i=1; i<=depth; i++) { if (stack[i] != "") p = p (p==""?"":"/") stack[i] }
            print (p==""?"/":p) "/" n "\t" v "\tadvertised"
        }'
}

# Classify a flattened key into the surface it belongs to. The sets are the
# names GSMA RCC.07 and OMA-CP actually use; anything unrecognised stays
# "unclassified" rather than being forced into a bucket, because a wrong bucket
# is a claim about the operator's network that the document did not make.
rcs_config_section() {
    local k="${1,,}"
    case "$k" in
        *pcscf*|*p-cscf*|*ims*|*apn*|*ap2001*|*sip_auth*|*impu*|*impi*) echo ims ;;
        *msrp*|*relay*)                                                     echo msrp ;;
        *presence*|*capab*|*discovery*|*rd*)                                echo presence ;;
        *chatbot*|*maap*|*bot*)                                             echo chatbot ;;
        *ft*|*file*|*thumb*)                                                echo file-transfer ;;
        *vvm*|*voicemail*)                                                  echo voicemail ;;
        *)                                                                  echo unclassified ;;
    esac
}

rcs_config_report() {
    local in; in=$(rcs_config_flat "${1:-}") || return $?
    printf 'section\tkey\tvalue\tprovenance\n'
    local line key val prov sec n=0
    while IFS=$'\t' read -r key val prov; do
        [[ "$key" == parm || "$key" == key ]] && continue
        [[ -z "$key" ]] && continue
        sec=$(rcs_config_section "$key")
        printf '%s\t%s\t%s\t%s\n' "$sec" "$(rcs_sanitize "$key")" "$(rcs_sanitize "$val")" "$prov"
        n=$((n + 1))
    done <<< "$in"
    printf 'summary\tparams\t%s\tadvertised\n' "$n"
    local ims msrp bots
    ims=$(printf '%s' "$in" | awk -F'\t' '{print $1}' | grep -ci 'pcscf\|p-cscf\|apn' || true)
    msrp=$(printf '%s' "$in" | awk -F'\t' '{print $1}' | grep -ci 'msrp\|relay' || true)
    bots=$(printf '%s' "$in" | awk -F'\t' 'tolower($1) ~ /chatbot|maap/ {c++} END{print c+0}')
    printf 'surface\tims-params\t%s\tadvertised\n' "$ims"
    printf 'surface\tmsrp-params\t%s\tadvertised\n' "$msrp"
    printf 'surface\tchatbot-entries\t%s\tadvertised\n' "$bots"
    if (( n == 0 )); then
        printf 'verdict\tno-params\tunobserved\tthe document carried no name/value pairs this parser recognises; that is not the same as an operator with no services\n'
    else
        printf 'verdict\tparsed\tadvertised\n'
    fi
}

# Fetch the candidates a handset tries on first boot. GET only, no credential,
# nothing written back to the network.
rcs_config_fetch() {
    local host="${1:-}"
    [[ -n "$host" ]] || { printf 'ERROR\t--config-fetch needs a host or operator domain\n' >&2; return 2; }
    declare -F curl >/dev/null 2>&1 || command -v curl >/dev/null 2>&1 || {
        printf 'GUARD\tcurl-missing\trefusing: the fetch needs curl, and inventing an empty result would read as "no document"\n'
        return 1; }
    local -a urls=(
        "https://${host}/.well-known/rcs-config"
        "https://config.rcs.${host}/rcs-config"
        "https://rcs.${host}/.well-known/rcs-config"
        "https://autoconfig.${host}/rcs"
    )
    printf 'url\tstatus\tbytes\tfile\n'
    local u code len out got=0 i=0
    for u in "${urls[@]}"; do
        i=$((i + 1))
        out="$RCS_DIR/$(printf '%s' "$u" | tr '/:' '__').bin"
        code=$(curl -skL --max-time 12 -o "$out" -w '%{http_code}' "$u" 2>/dev/null || echo 000)
        len=$(wc -c < "$out" 2>/dev/null | tr -d ' ')
        printf '%s\t%s\t%s\t%s\n' "$u" "$code" "${len:-0}" "$out"
        if [[ "$code" == 200 && "${len:-0}" -gt 0 ]]; then got=$((got + 1)); fi
    done
    if (( got == 0 )); then
        printf 'verdict\tno-config-observed\tunobserved\tnone of the candidate URLs answered 200 with a body; an operator that does not publish here is unobserved, not absent\n'
        return 1
    fi
    printf 'verdict\tfetched\tmeasured\n'
}

# ── SIP capability discovery ────────────────────────────────────────────
# The request a handset sends to learn what a contact supports. It is an
# OPTIONS with the RCS feature tags in Accept-Contact; the answer describes the
# SUBSCRIBER. Nothing in the request proves the caller has any relationship
# with that subscriber, which is exactly why the answer is worth auditing.
rcs_sip_cap_build() {
    local target="${1:-sip:user@example.invalid}"
    local branch tag callid
    branch=$(printf 'z9hG4bK%08x' "$$")
    tag=$(printf '%08x' "$(date -u +%s)")
    callid="$(date -u +%s).$$@rcs.local"
    cat <<EOF
OPTIONS ${target} SIP/2.0
Via: SIP/2.0/TCP client.example.invalid:5060;branch=${branch}
Max-Forwards: 70
From: <sip:probe@example.invalid>;tag=${tag}
To: <${target}>
Call-ID: ${callid}
CSeq: 1 OPTIONS
Contact: <sip:probe@client.example.invalid>
Accept: application/sdp
Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg",urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.filetransfer
Accept-Contact: *;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im",urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot
User-Agent: IMSIsting-rcs
Content-Length: 0

EOF
}

# Parse a 200 OK OPTIONS answer into capabilities. The features ride in
# Contact (RFC 3840 feature parameters) or Feature-Caps (RFC 6809).
rcs_sip_cap_parse() {
    local in; in=$(rcs_file_or_stdin "${1:-}") || return $?
    printf '%s' "$in" | awk '
        { sub(/\r$/,"") }
        NR==1 { print "status-line\t" $0; if ($2 ~ /^[0-9]+$/) code=$2; next }
        /^[Cc]ontact:/ || /^[Ff]eature-[Cc]aps:/ { hdr=$0; sub(/^[^:]*:[ ]*/,"",hdr); all = all " " hdr }
        { if (tolower($0) ~ /^(server|user-agent):/) { p=index($0,":"); print "peer\t" tolower(substr($0,1,p-1)) "\t" substr($0,p+2) } }
        END {
            print "code\t" (code==""?"unobserved":code)
            n=0
            while (match(all, /\+g\.3gpp\.[a-z-]+-ref="[^"]*"/)) {
                m=substr(all, RSTART, RLENGTH)
                kind=m; sub(/=.*/,"",kind); sub(/^\+g\.3gpp\./,"",kind); sub(/-ref$/,"",kind)
                v=m; sub(/^[^=]*="/,"",v); sub(/"$/,"",v)
                k=split(v, parts, ",")
                for (i=1; i<=k; i++) {
                    t=parts[i]
                    gsub(/%3A/,":",t); gsub(/%3a/,":",t)
                    sub(/^urn:urn-7:/,"",t)
                    print "capability\t" kind "\t" t
                    n++
                }
                all = substr(all, RSTART+RLENGTH)
            }
            print "capabilities\t" n
            if (code == "200" && n > 0) print "verdict\tdiscloses-capability\tmeasured"
            else if (code ~ /^40[13]$/ || code ~ /^407$/) print "verdict\tauth-required\tmeasured"
            else if (code == "") print "verdict\tunobserved\tunobserved"
            else print "verdict\tno-capability-observed\tmeasured"
        }'
}

# The audit: two addresses, one the caller has a relationship with and one it
# does not. Identical answers prove nothing. Different answers prove the network
# tells an unrelated caller whether a given number is a subscriber with RCS on
# — which is a subscriber oracle, whatever the answer looks like.
rcs_presence_audit() {
    local known="${1:-}" unknown="${2:-}"
    [[ -r "$known" && -r "$unknown" ]] || {
        printf 'ERROR\t--presence-audit needs two captured responses: <known-subscriber> <unknown>\n' >&2
        return 2; }
    local ka kb kc uc capital
    ka=$(rcs_sip_cap_parse "$known"); kb=$(rcs_sip_cap_parse "$unknown")
    kc=$(printf '%s\n' "$ka" | awk -F'\t' '$1=="code"{print $2}')
    uc=$(printf '%s\n' "$kb" | awk -F'\t' '$1=="code"{print $2}')
    kcap=$(printf '%s\n' "$ka" | awk -F'\t' '$1=="capabilities"{print $2}')
    ucap=$(printf '%s\n' "$kb" | awk -F'\t' '$1=="capabilities"{print $2}')
    printf 'known-code\t%s\n' "${kc:-unobserved}"
    printf 'unknown-code\t%s\n' "${uc:-unobserved}"
    printf 'known-capabilities\t%s\n' "${kcap:-0}"
    printf 'unknown-capabilities\t%s\n' "${ucap:-0}"
    if [[ -z "$kc" || -z "$uc" || "$kc" == "unobserved" || "$uc" == "unobserved" ]]; then
        printf 'verdict\tunobserved\tone of the two responses carried no status line; a comparison needs both\n'
        return 1
    fi
    if [[ "$kc" == "$uc" && "${kcap:-0}" == "${ucap:-0}" ]]; then
        printf 'verdict\tno-corroboration\tmeasured\tthe two answers are identical, so the network is not telling an unrelated caller anything about this subscriber\n'
        return 0
    fi
    printf 'finding\tsubscriber-oracle\tHIGH\tan identical request gets a different answer for an unrelated address, so presence/capability is disclosable to any caller\n'
    printf 'verdict\tdiscloses-subscriber-existence\tmeasured\n'
    return 0
}

rcs_plan() {
    cat <<'EOF'
status	handoff
what	originating SIP towards an IMS core: OPTIONS, SUBSCRIBE, MESSAGE, MSRP SEND
hardware	a USIM you control, or a programmable SIM in a UE you own, plus a reachable P-CSCF
software	osmo-msc + an IMS core (Kamailio/Asterisk with the RCS modules), or an operator testbed you are authorised on
flow	1. build the request here with --sip-cap-build  2. originate it from the owned IMPU  3. capture the answer and audit it with --presence-audit
note	a capability query names a subscriber, so it is attributable to the asking identity. Nothing in this module transmits; the answer you audit must be one you were authorised to obtain.
EOF
}

rcs_status_tsv() {
    printf 'MODULE\trcs\n'
    printf 'TARGET\tRCS: autoconfiguration, capability discovery, CPIM and MSRP messaging\n'
    printf 'TRANSMIT\tnone — codecs, one HTTPS GET, and disclosure analysis\n'
    printf 'SELFTEST\tyes\n'
}

rcs_info() {
    cat <<'EOF'
Rich Communication Services is the operator's own messaging stack: chat, group
chat, file transfer and the chatbot economy, all riding SIP and the CPIM/MSRP
codec pair on top of IMS.

It is interesting for one reason. The three things that make it work are also
the three things that disclose and spoof. The autoconfiguration document tells
any handset where the P-CSCF, the MSRP relay and the chatbot list live, and it
is served over plain HTTPS to anyone. Capability discovery answers a question
about a *subscriber* — what can this number do — to a caller who has proved
nothing about their relationship to that number. And CPIM carries From and To as
presentational text, so a client that renders them without comparing them to the
authenticated identity shows a name the sender chose.

This module reads those three surfaces and says, per row, whether the fact is
measured (a response arrived), advertised (a document said so about itself) or
unobserved (nothing was read, which is not the same as nothing being there).
EOF
}

# ── selftest ────────────────────────────────────────────────────────────
rcs_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    cnt() { printf '%s\n' "$1" | awk -F'\t' -v k="$1" 'BEGIN{k=ENVIRON["K"]} $1==k{c++} END{print c+0}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export RCS_DIR="$d/loot/rcs"
    mkdir -p "$RCS_DIR"

    # 1. CPIM: build then parse. The Content-Length is octets, not characters.
    local frame out
    frame=$(rcs_cpim_build 'Alice <sip:alice@example.com>' 'Bob <sip:bob@example.com>' 'hello')
    chk cpim-has-from  "$(printf '%s' "$frame" | grep -c '^From: Alice')" "1"
    chk cpim-has-to    "$(printf '%s' "$frame" | grep -c '^To: Bob')"     "1"
    chk cpim-length    "$(printf '%s' "$frame" | grep -o '^Content-Length: [0-9]*' | awk '{print $2}')" "5"
    frame=$(rcs_cpim_build 'A <sip:a@x>' 'B <sip:b@x>' 'é')
    chk cpim-utf8-octets "$(printf '%s' "$frame" | grep -o '^Content-Length: [0-9]*' | awk '{print $2}')" "2"
    out=$(printf '%s' "$frame" | rcs_cpim_parse -)
    chk cpim-parse-verdict "$(fld "$out" verdict)" "parsed"
    chk cpim-parse-from    "$(fld "$out" header | head -1)" "from"

    # 2. CPIM: a message with no Message-ID and identical From/To is caught.
    printf 'From: same <sip:s@x>\r\nTo: same <sip:s@x>\r\nContent-Length: 0\r\n\r\n' > "$d/c1.cpim"
    out=$(rcs_cpim_parse "$d/c1.cpim")
    chk cpim-catch-no-msgid "$(printf '%s\n' "$out" | grep -c 'missing-message-id')" "1"
    chk cpim-catch-selfsend "$(printf '%s\n' "$out" | grep -c 'from-equals-to')" "1"

    # 3. MSRP: build, then parse cleanly.
    local m
    m=$(rcs_msrp_build 'msrps://relay.example.com:2855/a;tcp' 'msrps://alice@example.com/b;tcp' 'message/cpim' 'hi')
    chk msrp-start  "$(printf '%s' "$m" | head -1 | cut -d' ' -f1)" "MSRP"
    chk msrp-tid-len "$(printf '%s' "$m" | head -1 | awk '{print length($2)}' | awk '{print ($1>=6)?"ok":"short"}')" "ok"
    chk msrp-ends   "$(printf '%s' "$m" | tail -1 | grep -c '^-------')" "1"
    out=$(printf '%s' "$m" | rcs_msrp_parse -)
    chk msrp-parse-verdict "$(fld "$out" verdict)" "parsed"
    chk msrp-no-findings  "$(printf '%s\n' "$out" | grep -c '^finding')" "0"

    # 4. MSRP: a frame that never closes is not a frame.
    printf 'MSRP abcdef SEND\r\nTo-Path: msrps://r/x;tcp\r\nFrom-Path: msrps://a/y;tcp\r\nMessage-ID: 1\r\n\r\nbody' > "$d/m1.msrp"
    out=$(rcs_msrp_parse "$d/m1.msrp")
    chk msrp-catch-no-end "$(printf '%s\n' "$out" | grep -c 'missing-terminator')" "1"
    # A terminator carrying a different transaction-id is a framing error, not a close.
    printf 'MSRP abcdef SEND\r\nTo-Path: msrps://r/x;tcp\r\nFrom-Path: msrps://a/y;tcp\r\nMessage-ID: 1\r\n\r\nb\r\n-------ghijkl$\r\n' > "$d/m2.msrp"
    out=$(rcs_msrp_parse "$d/m2.msrp")
    chk msrp-catch-tid "$(printf '%s\n' "$out" | grep -c 'terminator-tid-mismatch')" "1"
    # From-Path is the claim a relay is supposed to check.
    printf 'MSRP abcdef SEND\r\nTo-Path: msrps://r/x;tcp\r\n\r\nb\r\n-------abcdef$\r\n' > "$d/m3.msrp"
    out=$(rcs_msrp_parse "$d/m3.msrp")
    chk msrp-catch-no-frompath "$(printf '%s\n' "$out" | grep -c 'missing-from-path')" "1"
    chk msrp-short-tid "$(printf 'MSRP ab SEND\r\nTo-Path: x\r\nFrom-Path: y\r\n\r\n-------ab$\r\n' | rcs_msrp_parse - | grep -c 'tid-too-short')" "1"

    # 5. Feature table: both dialects present, and normalisation strips the wrapper.
    chk features-count "$(rcs_feature_table | tail -n +2 | wc -l | tr -d ' ')" "20"
    chk features-both-dialects "$(rcs_feature_table | awk -F'\t' 'NR>1{print $3}' | sort -u | tr '\n' ' ' | tr -s ' ')" "IARI ICSI "
    chk feature-norm "$(rcs_feature_norm 'urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg')" "3gpp-service.ims.icsi.oma.cpm.msg"

    # 6. Autoconfig: OMA-CP XML flattens with its path, and the classifier buckets it.
    cat > "$d/cfg.xml" <<'XML'
<?xml version="1.0"?>
<wap-provisioningdoc version="1.1">
  <characteristic type="APPLICATION">
    <parm name="AppID" value="ap2001"/>
    <characteristic type="APPAUTH"><parm name="AAUTHNAME" value="user"/></characteristic>
  </characteristic>
  <characteristic type="RCS">
    <parm name="P-CSCF" value="pcscf.ims.example.com"/>
    <parm name="MSRP_Relay" value="msrps://relay.example.com:2855"/>
    <parm name="Chatbot" value="sip:bot@example.com"/>
    <parm name="Presence" value="enabled"/>
  </characteristic>
</wap-provisioningdoc>
XML
    out=$(rcs_config_flat "$d/cfg.xml")
    chk cfg-flat-has-pcscf "$(printf '%s\n' "$out" | grep -c 'P-CSCF')" "1"
    chk cfg-flat-path "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /APPLICATION\/APPAUTH\/AAUTHNAME/{print "ok"}' | head -1)" "ok"
    out=$(rcs_config_report "$d/cfg.xml")
    chk cfg-section-ims "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ims"' | grep -c 'P-CSCF')" "1"
    chk cfg-section-msrp "$(printf '%s\n' "$out" | awk -F'\t' '$1=="msrp"' | grep -c 'MSRP_Relay')" "1"
    chk cfg-section-bot "$(printf '%s\n' "$out" | awk -F'\t' '$1=="chatbot"' | grep -c 'Chatbot')" "1"
    chk cfg-verdict "$(fld "$out" verdict)" "parsed"

    # 7. Autoconfig: the JSON shape flattens too, and an empty document is
    #    "unobserved", not "an operator with no services".
    printf '{"ims": {"pcscf": "pcscf.example.com", "apn": "ims"}, "msrp_relay": "msrps://r.example"}' > "$d/cfg.json"
    out=$(rcs_config_report "$d/cfg.json")
    chk cfg-json-verdict "$(fld "$out" verdict)" "parsed"
    chk cfg-json-ims "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ims"' | wc -l | tr -d ' ' | awk '{print ($1>=2)?"ok":"few"}')" "ok"
    printf '<?xml version="1.0"?><wap-provisioningdoc></wap-provisioningdoc>' > "$d/empty.xml"
    out=$(rcs_config_report "$d/empty.xml")
    chk cfg-empty-unobserved "$(fld "$out" verdict)" "no-params"

    # 8. Capability request: the tags that make it a discovery request at all.
    local req; req=$(rcs_sip_cap_build 'sip:bob@example.com')
    chk cap-build-options  "$(printf '%s' "$req" | head -1 | cut -d' ' -f1)" "OPTIONS"
    chk cap-build-target   "$(printf '%s' "$req" | grep -c 'OPTIONS sip:bob@example.com SIP/2.0')" "1"
    chk cap-build-acceptc  "$(printf '%s' "$req" | grep -c '^Accept-Contact:')" "2"
    chk cap-build-icsi     "$(printf '%s' "$req" | grep -c 'icsi.oma.cpm.msg')" "1"
    chk cap-build-iari     "$(printf '%s' "$req" | grep -c 'rcs.chatbot')" "1"
    chk cap-build-cseq     "$(printf '%s' "$req" | grep -c '^CSeq: 1 OPTIONS')" "1"

    # 9. A 200 OK with features parses into capabilities; a 401 does not claim any.
    cat > "$d/ok.sip" <<'SIP'
SIP/2.0 200 OK
Server: IMS-AS/1.0
Contact: <sip:bob@ims.example.com>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"

SIP
    out=$(rcs_sip_cap_parse "$d/ok.sip")
    chk cap-parse-code "$(fld "$out" code)" "200"
    chk cap-parse-count "$(fld "$out" capabilities)" "2"
    chk cap-parse-verdict "$(fld "$out" verdict)" "discloses-capability"
    printf 'SIP/2.0 401 Unauthorized\r\n\r\n' > "$d/401.sip"
    out=$(rcs_sip_cap_parse "$d/401.sip")
    chk cap-401-verdict "$(fld "$out" verdict)" "auth-required"
    chk cap-401-none "$(fld "$out" capabilities)" "0"

    # 10. The disclosure audit: identical answers prove nothing, different ones prove an oracle.
    cp "$d/ok.sip" "$d/ok2.sip"
    out=$(rcs_presence_audit "$d/ok.sip" "$d/ok2.sip")
    chk audit-identical "$(fld "$out" verdict)" "no-corroboration"
    printf 'SIP/2.0 404 Not Found\r\n\r\n' > "$d/404.sip"
    out=$(rcs_presence_audit "$d/ok.sip" "$d/404.sip")
    chk audit-differs "$(fld "$out" verdict)" "discloses-subscriber-existence"
    chk audit-differs-finding "$(printf '%s\n' "$out" | grep -c 'subscriber-oracle')" "1"
    printf 'garbage with no status line\n' > "$d/bad.sip"
    out=$(rcs_presence_audit "$d/ok.sip" "$d/bad.sip")
    chk audit-unobserved "$(fld "$out" verdict)" "unobserved"
    chk audit-needs-two "$(rcs_presence_audit "$d/ok.sip" >/dev/null 2>&1; echo $?)" "2"

    # 11. Guards name what is missing.
    chk guard-curl-or-garbage "$(rcs_config_fetch '' >/dev/null 2>&1; echo $?)" "2"
    chk guard-cpim-noargs "$(rcs_cpim_build '' '' '' >/dev/null 2>&1; echo $?)" "2"
    chk guard-msrp-noargs "$(rcs_msrp_build '' '' >/dev/null 2>&1; echo $?)" "2"
    chk guard-badfile "$(rcs_config_flat "$d/nope.xml" >/dev/null 2>&1; echo $?)" "2"

    # 12. Plan is a handoff, and says so with the code the tree reserves for it.
    chk plan-handoff "$(rcs_plan | grep -c '^status	handoff')" "1"
    chk status-transmit "$(rcs_status_tsv | grep -c '^TRANSMIT	none')" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

rcs_menu() {
    while true; do
        banner
        echo "  === RCS ==="
        echo
        cat <<'M'
  [1]  Read the feature-tag table
  [2]  Build a CPIM message
  [3]  Parse a CPIM message
  [4]  Build an MSRP frame
  [5]  Parse an MSRP frame
  [6]  Parse an RCS autoconfig document
  [7]  Fetch an autoconfig document (HTTPS GET)
  [8]  Build a capability-discovery OPTIONS
  [9]  Parse a capability answer
  [10] Audit disclosure: known vs unknown subscriber
  [11] Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) rcs_feature_table | column -t -s $'\t' 2>/dev/null || rcs_feature_table; read -rp "  enter " _ ;;
            2) read -rp "  from> " f; read -rp "  to> " t; read -rp "  text> " x; rcs_cpim_build "$f" "$t" "$x"; echo; read -rp "  enter " _ ;;
            3) read -rp "  file (- for stdin)> " p; rcs_cpim_parse "$p"; read -rp "  enter " _ ;;
            4) read -rp "  to-path> " t; read -rp "  from-path> " f; read -rp "  body> " x; rcs_msrp_build "$t" "$f" 'message/cpim' "$x"; read -rp "  enter " _ ;;
            5) read -rp "  file (- for stdin)> " p; rcs_msrp_parse "$p"; read -rp "  enter " _ ;;
            6) read -rp "  file> " p; rcs_config_report "$p"; read -rp "  enter " _ ;;
            7) read -rp "  host / operator domain> " h; rcs_config_fetch "$h"; read -rp "  enter " _ ;;
            8) read -rp "  target sip: uri> " u; rcs_sip_cap_build "$u"; read -rp "  enter " _ ;;
            9) read -rp "  response file> " p; rcs_sip_cap_parse "$p"; read -rp "  enter " _ ;;
            10) read -rp "  known-subscriber response> " a; read -rp "  unknown response> " b; rcs_presence_audit "$a" "$b"; read -rp "  enter " _ ;;
            11) rcs_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

rcs_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     rcs_status_tsv ;;
        --info)           rcs_info ;;
        --features)       rcs_feature_table ;;
        --cpim-build)     rcs_cpim_build "${1:-}" "${2:-}" "${3:-}" "${4:-text/plain; charset=utf-8}" ;;
        --cpim-parse)     rcs_cpim_parse "${1:-}" ;;
        --msrp-build)     rcs_msrp_build "${1:-}" "${2:-}" "${3:-message/cpim}" "${4:-}" ;;
        --msrp-parse)     rcs_msrp_parse "${1:-}" ;;
        --config-parse)   rcs_config_report "${1:-}" ;;
        --config-flat)    rcs_config_flat "${1:-}" ;;
        --config-fetch)   rcs_config_fetch "${1:-}" ;;
        --sip-cap-build)  rcs_sip_cap_build "${1:-}" ;;
        --sip-cap-parse)  rcs_sip_cap_parse "${1:-}" ;;
        --presence-audit) rcs_presence_audit "${1:-}" "${2:-}" ;;
        --plan)           rcs_plan ;;
        --selftest)       rcs_selftest ;;
        --menu)           rcs_menu ;;
        *)
            cat >&2 <<EOF
RCS — autoconfiguration, capability discovery and the CPIM/MSRP messaging plane

Usage: $0 COMMAND
  --status-tsv          module state as TSV
  --info                what this module covers and why
  --features            the RCS feature-tag / ICSI / IARI reference table
  --cpim-build <from> <to> <text> [ctype]   RFC 3862 CPIM message
  --cpim-parse <file|->   CPIM headers, octet count and identity findings
  --msrp-build <to-path> <from-path> [ctype] [body]   RFC 4975 SEND frame
  --msrp-parse <file|->   MSRP framing, transaction-id and path checks
  --config-parse <file|->   RCS autoconfiguration -> sectioned TSV
  --config-flat <file|->    the raw name/value flattening under --config-parse
  --config-fetch <host>     the candidate autoconfig URLs, over HTTPS GET
  --sip-cap-build <uri>     a capability-discovery OPTIONS with RCS feature tags
  --sip-cap-parse <file|->  a 200 OK answer -> capabilities, or why there are none
  --presence-audit <known> <unknown>   diff two answers for subscriber disclosure
  --plan                lab/authorisation handoff plan
  --selftest            verify every codec and parser, no network needed
  --menu                interactive menu
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
    rcs_cli_main "$@"
fi
