#!/usr/bin/env bash
# tools/check-ikev2-chain.sh — let tshark referee the IKEv2 messages that
# modules/36_vowifi.sh assembles.
#
# The module builds an IKE_SA_INIT (SAi, KEi, Ni) and two IKE_AUTH chains (an
# EAP-AKA'-less one with IDi/AUTH/SA/TSi/TSr, and the ePDG one with IDi/EAP).
# This checker wraps each of them in Ethernet/IPv4/UDP 500 by hand — text2pcap
# cannot frame an IKEv2 message either — and asks tshark to dissect it. If
# tshark reads the same exchange, the same payload chain, the same transforms
# and the same traffic selectors, the octets are the RFC's and not this tree's
# opinion. A negative control (a truncated message) proves the checker would
# have caught a wrong one.
#
# Exit: 0 all cases agree, 1 a mismatch, 2 a tool is missing (SKIP).
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
TSHARK=${TSHARK:-/usr/bin/tshark}
PY=${PYTHON:-python3}
MOD="$root/modules/36_vowifi.sh"

command -v "$TSHARK" >/dev/null 2>&1 || { printf 'SKIP\t%s is not installed\n' "$TSHARK"; exit 2; }
command -v "$PY" >/dev/null 2>&1 || { printf 'SKIP\t%s is not installed\n' "$PY"; exit 2; }
[[ -f "$MOD" ]] || { printf 'SKIP\t%s is not present\n' "$MOD"; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-ikev2.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT
export LOOT_DIR="$tmp/loot" STATE_DIR="$tmp/state" TMP_DIR="$tmp/tmp"
export CAPTURES_DIR="$tmp/captures" LOGS_DIR="$tmp/logs"
mkdir -p "$LOOT_DIR" "$STATE_DIR" "$TMP_DIR" "$CAPTURES_DIR" "$LOGS_DIR"

n=0 ok=0 bad=0
chk() {  # <name> <got> <want>
    local name="$1" got="$2" want="$3"
    n=$(( n + 1 ))
    if [[ "$got" == "$want" ]]; then
        ok=$(( ok + 1 )); printf 'ASSERTION\t%s\tPASS\n' "$name"
    else
        bad=$(( bad + 1 ))
        printf 'ASSERTION\t%s\tFAIL\twant[%s] got[%s]\n' "$name" "$want" "$got"
    fi
}

# ── ask the module for the message, then frame it by hand ───────────────────
build() {  # <name> <module args...>
    local name="$1"; shift
    local hex
    # one invocation: the module appends a store row per call, and this
    # checker must not inflate the store it is auditing.
    bash "$MOD" "$@" > "$tmp/$name.rows" 2>/dev/null
    hex=$(awk -F'\t' '$1=="hex"{print $2}' "$tmp/$name.rows")
    [[ -n "$hex" ]] || { printf 'ERROR\t%s produced no hex\n' "$name" >&2; return 1; }
    printf '%s' "$hex" > "$tmp/$name.hex"
    return 0
}

build sa-init   --ike-chain ike-sa-init plain || exit 1
build auth      --ike-chain ike-auth plain     || exit 1
build auth-eap  --ike-chain ike-auth epdg      || exit 1
# negative control: the same message with its tail cut, which no reader may
# accept as a whole one.
head -c $(( $(wc -c < "$tmp/sa-init.hex") - 16 )) < "$tmp/sa-init.hex" > "$tmp/sa-trunc.hex"

"$PY" - "$tmp" <<'PY'
import struct, sys, os
tmp = sys.argv[1]
def csum(b):
    if len(b) % 2: b += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def frame(ike):
    src, dst = bytes([10,0,0,1]), bytes([10,0,0,2])
    udp = struct.pack('!HHHH', 500, 500, 8 + len(ike), 0) + ike
    ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0) + src + dst
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('00112233445566778899aabb0800') + ip + udp
names = ['sa-init', 'auth', 'auth-eap', 'sa-trunc']
frames = []
for nm in names:
    hexs = open(os.path.join(tmp, nm + '.hex')).read().strip()
    frames.append(frame(bytes.fromhex(hexs)))
with open(os.path.join(tmp, 'chain.pcap'), 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for fr in frames:
        f.write(struct.pack('<IIII', 0, 0, len(fr), len(fr)))
        f.write(fr)
PY
[[ -s "$tmp/chain.pcap" ]] || { printf 'SKIP\tcould not write a pcap fixture\n'; exit 2; }

dissect() { "$TSHARK" -r "$tmp/chain.pcap" -Y "frame.number==$1" -V 2>/dev/null; }
# The dissector's own field extraction is steadier than its prose: a field that
# holds several values comes back comma separated, in wire order.
tf() { "$TSHARK" -r "$tmp/chain.pcap" -Y "frame.number==$1" -T fields \
        -E 'separator=,' -E 'occurrence=a' -e "$2" 2>/dev/null; }
row() { awk -F'\t' -v k="$2" '$1==k{print $2; exit}' "$tmp/$1.rows"; }

# ── case 1: IKE_SA_INIT — SAi, KEi, Ni (RFC 7296 §1.2) ────────────────────
chk 'sa-init/exchange'      "$(tf 1 isakmp.exchangetype)" '34'
chk 'sa-init/exchange-name' "$(printf '%s\n' "$(dissect 1)" | sed -n 's/^    Exchange type: \(.*\) ([0-9]*)$/\1/p' | head -1)" \
                            "$(awk -F'\t' '$1=="exchange_type"{print $3; exit}' "$tmp/sa-init.rows")"
t=$(dissect 1)
chk 'sa-init/next-payload'  "$(printf '%s\n' "$t" | sed -n 's/^    Next payload: \(.*\) ([0-9]*)$/\1/p' | head -1)" 'Security Association'
chk 'sa-init/version'       "$(printf '%s\n' "$t" | sed -n 's/^    Version: \(.*\)$/\1/p' | head -1)" '2.0'
chk 'sa-init/length'        "$(tf 1 isakmp.length)" "$(row sa-init length_field)"
chk 'sa-init/payload-chain' "$(printf '%s\n' "$t" | sed -n 's/^    Payload: \(.*\) ([0-9]*)$/\1/p' | tr '\n' ',' | sed 's/,$//')" \
                            'Security Association,Key Exchange,Nonce'
chk 'sa-init/encr-name'     "$(printf '%s\n' "$t" | sed -n 's/.*Transform ID (ENCR): \(.*\) ([0-9]*)$/\1/p' | head -1)" 'ENCR_AES_CBC'
chk 'sa-init/key-length'    "$(printf '%s\n' "$t" | sed -n 's/.*Key Length: \([0-9]*\)$/\1/p' | head -1)" '128'
chk 'sa-init/prf-name'      "$(printf '%s\n' "$t" | sed -n 's/.*Transform ID (PRF): \(.*\) ([0-9]*)$/\1/p' | head -1)" 'PRF_HMAC_SHA2_256'
chk 'sa-init/integ-name'    "$(printf '%s\n' "$t" | sed -n 's/.*Transform ID (INTEG): \(.*\) ([0-9]*)$/\1/p' | head -1)" 'AUTH_HMAC_SHA2_256_128'
chk 'sa-init/dh-group'      "$(printf '%s\n' "$t" | sed -n 's/^        DH Group #: \(.*\)$/\1/p' | head -1)" '2048 bit MODP group (14)'
chk 'sa-init/nonce-octets'  "$(( $(tf 1 isakmp.nonce | tr -d ',' | wc -c) / 2 ))" "$(row sa-init nonce_octets)"
chk 'sa-init/clean'         "$(printf '%s\n' "$t" | grep -c 'Malformed Packet')" '0'

# ── case 2: IKE_AUTH with IDi/AUTH/SA/TSi/TSr ─────────────────────────────
t=$(dissect 2)
chk 'auth/exchange'         "$(tf 2 isakmp.exchangetype)" '35'
chk 'auth/payload-chain'    "$(printf '%s\n' "$t" | sed -n 's/^    Payload: \(.*\) ([0-9]*).*$/\1/p' | sed 's/ # [0-9]*$//' | tr '\n' ',' | sed 's/,$//')" \
                            'Identification - Initiator,Authentication,Security Association,Traffic Selector - Initiator,Traffic Selector - Responder'
chk 'auth/id-type'          "$(tf 2 isakmp.id.type)" '2'
chk 'auth/id-value'         "$(printf '%s\n' "$t" | sed -n 's/^            ID_FQDN: \(.*\)$/\1/p' | head -1)" 'ue.example.org'
chk 'auth/auth-method'      "$(tf 2 isakmp.auth.method)" '2'
chk 'auth/child-sa-proto'   "$(tf 2 isakmp.prop.protoid)" '3'
chk 'auth/child-sa-encr'    "$(printf '%s\n' "$t" | sed -n 's/.*Transform ID (ENCR): \(.*\) ([0-9]*)$/\1/p' | head -1)" 'ENCR_AES_CBC'
chk 'auth/tsi-addr'         "$(tf 2 isakmp.ts.start_ipv4 | cut -d, -f1)" '10.0.0.1'
chk 'auth/tsr-range'        "$(tf 2 isakmp.ts.start_ipv4 | cut -d, -f2)-$(tf 2 isakmp.ts.end_ipv4 | cut -d, -f2)" \
                            '0.0.0.0-255.255.255.255'
chk 'auth/ts-ports'         "$(tf 2 isakmp.ts.start_port | cut -d, -f1)-$(tf 2 isakmp.ts.end_port | cut -d, -f1)" \
                            '0-65535'
chk 'auth/clean'            "$(printf '%s\n' "$t" | grep -c 'Malformed Packet')" '0'

# ── case 3: IKE_AUTH toward an ePDG — IDi holding the NAI, then EAP ───────
t=$(dissect 3)
chk 'epdg/exchange'         "$(tf 3 isakmp.exchangetype)" '35'
chk 'epdg/payload-chain'    "$(tf 3 isakmp.typepayload)" '35,48'
chk 'epdg/id-type'          "$(tf 3 isakmp.id.type)" '3'
chk 'epdg/nai-in-idi'       "$(printf '%s\n' "$t" | sed -n 's/^        Identification Data:\(.*\)$/\1/p' | head -1)" \
                            '0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org'
chk 'epdg/nai-user'         "$(printf '%s\n' "$t" | sed -n 's/^        Identification Data:\(.*\)$/\1/p' | head -1 | cut -d@ -f1)" '0001010123456789'
chk 'epdg/nai-realm'        "$(printf '%s\n' "$t" | sed -n 's/^        Identification Data:\(.*\)$/\1/p' | head -1 | cut -d@ -f2)" \
                            "$(bash "$MOD" --nai 001010123456789 001 01 | sed -n 's/^0[0-9]*@//p')"
chk 'epdg/gateway-name'     "$(bash "$MOD" --epdg 001 01)" 'epdg.epc.mnc001.mcc001.pub.3gppnetwork.org'
chk 'epdg/eap-code'         "$(tf 3 eap.code)" '2'
chk 'epdg/eap-id'           "$(tf 3 eap.id)" '1'
chk 'epdg/eap-type'         "$(tf 3 eap.type)" '50'
chk 'epdg/eap-subtype'      "$(tf 3 eap.aka.subtype)" '1'
chk 'epdg/at-rand-type'     "$(tf 3 eap.aka.subtype.type)" '1'
chk 'epdg/at-rand-length'   "$(tf 3 eap.aka.subtype.len)" '5'
chk 'epdg/eap-type-name'    "$(printf '%s\n' "$t" | sed -n "s/^            Type: .*EAP (EAP-AKA') (\([0-9]*\))$/\1/p" | head -1)" '50'
chk 'epdg/clean'            "$(printf '%s\n' "$t" | grep -c 'Malformed Packet')" '0'

# ── negative control: a truncated message must be refused by both readers ──
t=$(dissect 4)
chk 'trunc/tshark-notices'  "$(printf '%s\n' "$t" | grep -cE 'Malformed Packet|Expert Info' | awk '{print ($1>0)?"yes":"no"}')" 'yes'
bash "$MOD" --chain-parse "$(cat "$tmp/sa-trunc.hex")" >/dev/null 2>&1
chk 'trunc/module-refuses'  "$?" '1'
chk 'trunc/reason-named'    "$(bash "$MOD" --chain-parse "$(cat "$tmp/sa-trunc.hex")" 2>&1 >/dev/null | grep -c 'truncated')" '1'

# ── the store is append-only and carries what was built ────────────────────
chk 'store/header'          "$(head -1 "$LOOT_DIR/vowifi/ike-chains.tsv" 2>/dev/null)" \
                            "$(printf 'ts\tverb\texchange\tprofile\tpayloads\toctets\tverdict\tdetail')"
chk 'store/sa-init-row'     "$(awk -F'\t' '$2=="ike-chain" && $3=="ike-sa-init"{c++} END{print c+0}' "$LOOT_DIR/vowifi/ike-chains.tsv")" '1'
chk 'store/auth-row'        "$(awk -F'\t' '$2=="ike-chain" && $3=="ike-auth" && $4=="epdg"{c++} END{print c+0}' "$LOOT_DIR/vowifi/ike-chains.tsv")" '1'

printf 'CASES\t%d\tOK\t%d\tMISMATCHES\t%d\n' "$n" "$ok" "$bad"
if (( bad == 0 )); then
    printf 'RESULT\tPASS\n'; exit 0
fi
printf 'RESULT\tFAIL(%d)\n' "$bad"; exit 1
