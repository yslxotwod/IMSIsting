#!/usr/bin/env bash
# check-grx-screening — the interconnect screening model behaves as specified
#
# The two real-world interconnect exposures this toolkit models (GTP-C over an
# over-provisioned GRX peer, Diameter over a flat roaming interconnect) reduce
# to one question a border either answers or does not: *may this peer originate
# this message?*  This gate proves the model answers it in the same three
# states the rest of the toolkit uses (allow / deny / unknown), and that a peer
# which passes the address check but uses a message or an interface it was
# never granted is caught rather than waved through.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LC="$ROOT/modules/11_lte_core.sh"

bad=0
asserts=0
chk() {
    local name="$1" got="$2" want="$3"
    asserts=$((asserts + 1))
    if [[ "$got" == "$want" ]]; then
        printf 'ASSERTION\t%s\tPASS\n' "$name"
    else
        printf 'ASSERTION\t%s\tFAIL\twant=%s\tgot=%s\n' "$name" "$want" "$got"
        bad=$((bad + 1))
    fi
}

d=$(mktemp -d "${TMPDIR:-/tmp}/check-grx.XXXXXX") || exit 1
trap 'rm -rf "$d"' EXIT
mkdir -p "$d/opops"
printf 'plmn\tcidr\trole\tnote\n' > "$d/opops/iprange.tsv"
printf '310-260\t198.51.100.0/26\tgrx-peer\tcontracted roaming partner\n' >> "$d/opops/iprange.tsv"
printf '262-01\t203.0.113.0/28\tipx-stp\tDX exchange signalling peer\n' >> "$d/opops/iprange.tsv"

fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

screen() { REFDATA_OPOPS="$d/opops" bash "$LC" --gtp-screen-peer "$@" 2>&1; }
dscreen() { bash "$LC" --diameter-screen "$@" 2>&1; }

# ── GTP-C peer screening ────────────────────────────────────────────────
out=$(screen 198.51.100.5 32)
chk gtp-screen-contracted "$(fld "$out" verdict)" "allow"
chk gtp-screen-role       "$(fld "$out" role)"    "grx-peer"
chk gtp-screen-plmn       "$(fld "$out" plmn)"    "310-260"

out=$(screen 8.8.8.8 32)
chk gtp-screen-stranger   "$(fld "$out" verdict)" "deny"
chk gtp-screen-stranger-why "$(fld "$out" note)"  "address is not inside any contracted peer prefix"

# A /26 must not contain a /24 neighbour: 198.51.101.0 is outside.
chk gtp-screen-boundary   "$(fld "$(screen 198.51.101.0 32)" verdict)" "deny"

# Right address, allowed message.
chk gtp-screen-echo       "$(fld "$(screen 198.51.100.5 2)" verdict)" "allow"
chk gtp-screen-echo-note  "$(fld "$(screen 198.51.100.5 2)" note)"  "echo reply to a request this node sent"
chk gtp-screen-create     "$(fld "$(screen 198.51.100.5 32)" verdict)" "allow"

# Right address, message a peer may not originate: MBMS Session Start (231)
# is prepared by the operator's own core.
out=$(screen 198.51.100.5 231)
chk gtp-screen-initiate   "$(fld "$out" verdict)" "deny"
chk gtp-screen-init-note  "$(fld "$out" note)"    "message may not be sent by a peer: it is a node-initiated procedure"

# No message type at all: the answer is about the peer, not about a message.
out=$(screen 198.51.100.5)
chk gtp-screen-peer-only  "$(fld "$out" verdict)" "allow"

# No operator table on the machine: unobserved, never "deny", because a
# missing file must not manufacture a blocked-peer finding.
out=$(REFDATA_OPOPS="$d/none" bash "$LC" --gtp-screen-peer 1.1.1.1 1 2>&1)
chk gtp-screen-silent     "$(fld "$out" verdict)" "unknown"
chk gtp-screen-silent-why "$(fld "$out" note)"    "no operator address table (data/opops/iprange.tsv)"

# ── Diameter interconnect screening ─────────────────────────────────────
# S6a ULR (316) arriving from a roaming peer is the identity-theft shape:
# the interface is PLMN-internal, so the home network is its only origin.
out=$(dscreen 16777251 316)
chk dh-s6a-ulr        "$(fld "$out" verdict)" "deny"
chk dh-s6a-scope      "$(fld "$out" scope)"   "plmn-internal"
chk dh-s6a-why        "$(fld "$out" note)"    "interface is PLMN-internal: only the home network may originate it"
chk dh-s6a-appname    "$(fld "$out" application_name)" "3GPP S6a/S6d"
chk dh-s6a-cmdname    "$(fld "$out" command_name)" "Update-Location (ULR/ULA)  [S6a/S6d]"

# AIR (318) is the authentication-vector harvest; same verdict, different code.
chk dh-s6a-air        "$(fld "$(dscreen 16777251 318)" verdict)" "deny"

# Cx is different: the I-CSCF asks the HSS (UAR 300, LIR 302) from outside
# the MME/HSS pair, so those are legitimately originated across the boundary.
chk dh-cx-uar         "$(fld "$(dscreen 16777216 300)" verdict)" "allow"
chk dh-cx-lir         "$(fld "$(dscreen 16777216 302)" verdict)" "allow"
# ...but SAR (301) and MAR (303) are MME/network-initiated, not peer-initiated.
chk dh-cx-sar         "$(fld "$(dscreen 16777216 301)" verdict)" "deny"

# An interconnect application is carried by peers by definition.
chk dh-interconnect   "$(fld "$(dscreen 16777238 258)" verdict)" "allow"
chk dh-interconnect-scope "$(fld "$(dscreen 16777238 258)" scope)" "interconnect"

# ── shape ──────────────────────────────────────────────────────────────
chk gtp-screen-usage   "$(bash "$LC" --gtp-screen-peer >/dev/null 2>&1; echo $?)" "2"
chk gtp-screen-badtype "$(bash "$LC" --gtp-screen-peer 1.2.3.4 notatype >/dev/null 2>&1; echo $?)" "2"
chk gtp-screen-badip   "$(bash "$LC" --gtp-screen-peer 999.1.1.1 32 >/dev/null 2>&1; echo $?)" "2"
chk dh-screen-usage    "$(bash "$LC" --diameter-screen 16777251 >/dev/null 2>&1; echo $?)" "2"
chk dh-screen-badapp   "$(bash "$LC" --diameter-screen abc 316 >/dev/null 2>&1; echo $?)" "2"

# Both verbs must be offered by the module, or nobody can find them.
help=$(bash "$LC" --help 2>&1)
case "$help" in *--gtp-screen-peer*) chk help-gtp-screen PASS PASS ;; *) chk help-gtp-screen PASS MISSING ;; esac
case "$help" in *--diameter-screen*)  chk help-dh-screen  PASS PASS ;; *) chk help-dh-screen  PASS MISSING ;; esac
case "$(bash "$LC" --status-tsv 2>&1)" in
    *gtp-screen-peer*) chk status-gtp-screen PASS PASS ;;
    *) chk status-gtp-screen PASS MISSING ;;
esac

printf 'ASSERTIONS\t%d\n' "$asserts"
if (( bad )); then
    printf 'RESULT\tFAIL(%d)\n' "$bad"
    exit 1
fi
printf 'RESULT\tPASS\n'
