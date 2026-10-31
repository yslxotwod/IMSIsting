#!/usr/bin/env bash
# Check the NSSAI-family information elements modules/34_slicing.sh builds
# against TS 24.501 §9.11.3.37 / §9.11.3.46 and against Wireshark.
#
# The interesting failure mode here is a builder that agrees with itself. The
# module can print an IE, parse its own octets back, and be wrong about the
# layout the whole way: the length adds up, the S-NSSAIs come back, and the
# reject cause is read from the wrong nibble. So every case below states the
# octets the clause gives and the values tshark must read out of them, and the
# module is compared with those, not with its own round trip.
#
# Two layouts exist and only one of them is the rejected NSSAI's: the plain
# NSSAI prefixes each S-NSSAI with its length in a whole octet, while the
# rejected NSSAI packs the length into the high nibble and the reject cause into
# the low nibble of one octet. The last two cases exist to prove that difference
# rather than assert it: the nibble spelling has to decode clean, and the
# byte-length spelling of the same three S-NSSAI octets has to make tshark
# complain, because only then is the choice of layout evidence and not opinion.
#
# Exits 0 when every case agrees, 1 on a disagreement, 2 when the check cannot
# run (no tshark, no text2pcap, no python3).
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TSHARK=${TSHARK:-/usr/bin/tshark}
TEXT2PCAP=${TEXT2PCAP:-/usr/bin/text2pcap}
MODULE="$ROOT/modules/34_slicing.sh"

for t in "$TSHARK" "$TEXT2PCAP"; do
    if [[ ! -x "$t" ]]; then
        echo "SKIP	no $t"
        exit 2
    fi
done
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP	no python3"
    exit 2
fi
[[ -r "$MODULE" ]] || { echo "FAIL	no $MODULE" >&2; exit 2; }

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
export LOOT_DIR="$tmp/loot" STATE_DIR="$tmp/state" TMP_DIR="$tmp/tmp"

rc=0
say() { printf '%s\n' "$*"; }

# The 5GS plain-NAS headers these IEs travel in, from TS 24.501 §8.2 and
# confirmed with tshark: the Registration request needs its three mandatory
# IEs (registration type, ngKSI, 5GS mobile identity) before any optional IE
# can be reached, and the Registration accept needs the 5GS registration
# result. Without them tshark stops at the mandatory IE and calls the rest of
# the message malformed, which would look like a defect in the NSSAI IE.
hdr_req="7e004179000100"       # Registration request, initial, no identity
hdr_acc="7e00420100"           # Registration accept, 3GPP access, result 1

# name|kind|list|header|expected IE octets|what tshark must read
#   sst=<comma list>  sd=<n entries carrying a differentiator>
#   rejlen=<n> rejcause=<n>   (rejected NSSAI only)
cases=(
  "requested-plain|requested|1|$hdr_req|2F020101|sst=1 sd=0"
  "requested-sst-sd|requested|1,2:0000AB|$hdr_req|2F07010104020000AB|sst=1,2 sd=1"
  "allowed|allowed|1|$hdr_acc|15020101|sst=1 sd=0"
  "configured|configured|3|$hdr_acc|31020103|sst=3 sd=0"
  "pending|pending|4|$hdr_acc|39020104|sst=4 sd=0"
  "mapped|mapped|1|$hdr_req|35020101|sst=1 sd=0"
  "rejected-cause|rejected|2:0000AB=1|$hdr_acc|110541020000AB|sst=2 sd=1 rejlen=4 rejcause=1"
)

pcap_add() {  # <header-hex> <ie-hex>  -> appends one exported-PDU frame's text
    local h="$1$2" i
    printf '000000  '
    for (( i = 0; i < ${#h}; i += 2 )); do printf '%s ' "${h:i:2}"; done
    printf '\n\n'
}

ok=0
bad=0

# ── cases the module builds ─────────────────────────────────────────────
n=0
for c in "${cases[@]}"; do
    IFS='|' read -r name kind list hdr want_ie want_tsh <<<"$c"
    n=$(( n + 1 ))
    out=$(bash "$MODULE" --nssai-ie "$kind" "$list" 2>&1)
    got_ie=$(printf '%s\n' "$out" | awk -F'\t' '$1=="ie"{print $2; exit}')
    if [[ "$got_ie" != "$want_ie" ]]; then
        say "FAIL	$name	module built '$got_ie', TS 24.501 9.11.3.37/9.11.3.46 gives '$want_ie'"
        bad=$(( bad + 1 ))
        continue
    fi
    say "ok	$name	$got_ie (as the clause gives it)"
    ok=$(( ok + 1 ))
    { pcap_add "$hdr" "$got_ie"; } >> "$tmp/$name.txt"
done

if (( bad > 0 )); then
    say "FAIL	a builder that disagrees with the clause is not worth dissecting"
    exit 1
fi

# ── frames, one pcap per case, dissected by tshark ──────────────────────
for c in "${cases[@]}"; do
    IFS='|' read -r name kind list hdr want_ie want_tsh <<<"$c"
    "$TEXT2PCAP" -l 252 -P nas-5gs "$tmp/$name.txt" "$tmp/$name.pcap" >/dev/null 2>&1
    if [[ ! -s "$tmp/$name.pcap" ]]; then
        say "FAIL	$name	text2pcap framed nothing (the exported-PDU link type is the only way to reach the nas-5gs dissector without NGAP)"
        bad=$(( bad + 1 ))
        continue
    fi
    got=$("$TSHARK" -r "$tmp/$name.pcap" -T fields \
            -e nas-5gs.mm.sst -e nas-5gs.mm.mm_sd \
            -e nas-5gs.mm.len_of_rej_s_nssai -e nas-5gs.mm.rej_s_nssai.cause \
            -e _ws.expert.message -E separator='|' 2>/dev/null | head -1)
    IFS='|' read -r g_sst g_sd g_len g_cause g_exp <<<"$got"
    fail=""
    for pair in $want_tsh; do
        k="${pair%%=*}"; v="${pair#*=}"
        case "$k" in
            sst)      [[ "$g_sst" == "$v" ]] || fail+=" sst(want $v got ${g_sst:-none})" ;;
            sd)       n_sd=$(printf '%s\n' "$g_sd" | tr ',' '\n' | sed '/^$/d' | wc -l)
                      [[ "$n_sd" == "$v" ]] || fail+=" sd-count(want $v got $n_sd)" ;;
            rejlen)   [[ "$g_len" == "$v" ]] || fail+=" rejected-length(want $v got ${g_len:-none})" ;;
            rejcause) [[ "$g_cause" == "$v" ]] || fail+=" reject-cause(want $v got ${g_cause:-none})" ;;
        esac
    done
    if [[ -n "$g_exp" ]]; then
        fail+=" expert($g_exp)"
    fi
    if [[ -n "$fail" ]]; then
        say "FAIL	$name	tshark disagrees:$fail"
        bad=$(( bad + 1 ))
    else
        say "ok	$name	tshark reads $got"
        ok=$(( ok + 1 ))
    fi
done

# ── the layout is evidence, not opinion: the wrong spelling must break ──
# Same three S-NSSAI octets (SST 1, cause 3) under the byte-length spelling.
pcap_add "$hdr_acc" "1103010103" > "$tmp/bytelength.txt"
"$TEXT2PCAP" -l 252 -P nas-5gs "$tmp/bytelength.txt" "$tmp/bytelength.pcap" >/dev/null 2>&1
if [[ -s "$tmp/bytelength.pcap" ]]; then
    exp=$("$TSHARK" -r "$tmp/bytelength.pcap" -T fields -e _ws.expert.message 2>/dev/null | head -1)
    if [[ -n "$exp" ]]; then
        ok=$(( ok + 1 ))
        say "ok	rejected-bytelength	tshark rejects the byte-length spelling of the rejected NSSAI ($exp)"
    else
        bad=$(( bad + 1 ))
        say "FAIL	rejected-bytelength	tshark accepted 11 03 01 01 03 as a Rejected NSSAI, so the nibble layout is not confirmed"
    fi
fi
# And the module must not silently accept it either.
out=$(bash "$MODULE" --nssai-ie-parse 1103010103 2>&1); crc=$?
if (( crc != 0 )); then
    ok=$(( ok + 1 ))
    say "ok	rejected-bytelength-parse	the module refuses it with a reason (exit $crc)"
else
    bad=$(( bad + 1 ))
    say "FAIL	rejected-bytelength-parse	the module parsed 11 03 01 01 03 without complaining"
fi

# ── a layout this module does not implement must be unobserved, not empty ─
out=$(bash "$MODULE" --nssai-ie-parse 68020101 2>&1); crc=$?
if [[ "$crc" == "1" ]] && printf '%s\n' "$out" | grep -q $'^status\tunobserved'; then
    ok=$(( ok + 1 ))
    say "ok	extended-rejected	the extended rejected NSSAI is reported unobserved with its reason"
else
    bad=$(( bad + 1 ))
    say "FAIL	extended-rejected	expected exit 1 with status\tunobserved; got exit $crc:"
    printf '%s\n' "$out" | sed 's/^/     /'
fi

# ── the IEI table must be per message, not one global list ─────────────
# 0x2F is the Requested NSSAI in a Registration request and is not an
# NSSAI-family IE of a Registration accept; if the module hands back a name for
# it there, the table is being read without the message it came from.
out=$(bash "$MODULE" --nssai-ie-parse 2F020101 reg-accept 2>&1); crc=$?
if (( crc != 0 )); then
    ok=$(( ok + 1 ))
    say "ok	iei-per-message	0x2F is refused in a Registration accept"
else
    bad=$(( bad + 1 ))
    say "FAIL	iei-per-message	0x2F was accepted as an NSSAI-family IE of a Registration accept"
fi

say ""
say "CASES	$(( ok + bad ))	OK	$ok	MISMATCHES	$bad"
if (( bad == 0 )); then
    say "RESULT	PASS"
    say "the NSSAI-family IEs agree with TS 24.501 and with tshark 4.2.2"
    exit 0
fi
say "RESULT	FAIL($bad)"
exit 1
