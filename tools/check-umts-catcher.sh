#!/usr/bin/env bash
# Known-answer checks for tools/umts_catcher.py.
#
# Every expected value below is worked out by hand from the clause before the
# tool is asked, so the check fails if the tool drifts:
#
#   MM IDENTITY REQUEST, TS 24.008 9.2.5
#     protocol discriminator 0x05 | skip indicator 0x00 | message type 0x18 |
#     identity type, a TYPE-1 IE, so one octet holding the value in its low half
#     and no IEI in front of it. IMSI = 1 -> 05001801
#       05 00 18 02 -> IMEI, 05 00 18 03 -> IMEISV, 05 00 18 04 -> TMSI
#
#   MM AUTHENTICATION REQUEST, TS 24.008 9.2.1
#     05 00 12 | 21 10 <rand> | 20 10 <autn>
#
#   AUTHENTICATION RESPONSE, TS 24.008 9.2.2
#     05 00 13 | 22 <len> <res> | 27 10 <ck> | 28 10 <ik>
set -uo pipefail
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/umts_catcher.py"
n=0; bad=0
chk() {
    n=$((n + 1))
    if [[ "$2" == "$3" ]]; then printf 'ok   %-28s %s\n' "$1" "$2"
    else printf 'FAIL %-28s want=%s got=%s\n' "$1" "$3" "$2"; bad=$((bad + 1)); fi
}
fld() { "$TOOL" "${@:2}" 2>/dev/null | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
# Read a field out of a string the script already captured, rather than running
# the tool again: kfld <key> <captured-tsv>.
kfld() { printf '%s\n' "$2" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }

chk imsi "$(fld mm_hex identity)" "05001801"
chk imei "$(fld mm_hex identity --identity imei)" "05001802"
chk imeisv "$(fld mm_hex identity --identity imeisv)" "05001803"
chk tmsi "$(fld mm_hex identity --identity tmsi)" "05001804"
chk mm_len "$(fld mm_bytes identity)" "4"
chk txid_refused "$(python3 "$TOOL" identity --txid 4 >/dev/null 2>&1; echo $?)" "2"
chk domain_refused "$(python3 "$TOOL" identity --domain xx >/dev/null 2>&1; echo $?)" "2"

RAND=00112233445566778899aabbccddeeff
AUTN=ffeeddccbbaa99887766554433221100
chk auth_req "$(fld mm_hex auth --rand $RAND --autn $AUTN)" \
    "0500122110${RAND}2010${AUTN}"
chk auth_rand_refused "$(python3 "$TOOL" auth --rand 0011 --autn $AUTN >/dev/null 2>&1; echo $?)" "2"
chk auth_nonhex "$(python3 "$TOOL" auth --rand zz --autn $AUTN >/dev/null 2>&1; echo $?)" "2"

resp_hex="050013"                  # PD 05, skip 00, AUTHENTICATION RESPONSE 13
resp_hex+="2204""12345678"          # RES, 4 octets
resp_hex+="2710""00112233445566778899aabbccddeeff"   # CK
resp_hex+="2810""ffeeddccbbaa99887766554433221100"   # IK
chk resp_type "$(fld message_type auth-response "$resp_hex")" "13"
chk resp_res  "$(fld res auth-response "$resp_hex")" "12345678"
chk resp_ck   "$(fld ck auth-response "$resp_hex")" "00112233445566778899aabbccddeeff"
chk resp_ik   "$(fld ik auth-response "$resp_hex")" "ffeeddccbbaa99887766554433221100"
chk resp_nonmm "$(python3 "$TOOL" auth-response 06001300 >/dev/null 2>&1; echo $?)" "2"
chk resp_wrongtype "$(python3 "$TOOL" auth-response 05001200 >/dev/null 2>&1; echo $?)" "2"

# The RRC wrapper has no referee on this machine and the tool says so in its own
# output. The check asserts the statement is present, not that the bytes are
# verified: claiming the second without a decoder would be the lie.
# The wrapper is pinned to the pycrate transcription of TS 25.331, which
# tools/umts_rrc_oracle.py runs as an independent encoder AND decoder. The
# first version of this tool got the layout wrong (a stray presence bit and an
# 8-bit length where the ASN.1 wants a 12-bit n-1) and pycrate rejected it with
# "bitlen overflow"; this check is what would catch that again.
chk wrapper_hex   "$(fld rrc_hex identity)" "1400060a003002"
chk wrapper_bits  "$(fld rrc_bits identity)" "55"
chk wrapper_named "$(fld type_name identity)" "downlinkDirectTransfer"
chk wrapper_txid  "$(fld rrc_transaction_identifier identity)" "0"
chk wrapper_says_verified "$(fld verified identity | grep -c 'bit for bit against the pycrate')" "1"
chk wrapper_bare_still_works "$(fld mm_hex identity)" "05001801"

# 9. The other way to get an AUTN: compute it, which needs the subscriber key.
#    The expected value is TS 35.208 test set 1's AUTN -- (SQN xor f5)||AMF||f1
#    with f5 AA689C648370 and f1 4A9FFAC354DFAFB3, i.e. 55F328B43577 || B9B9 ||
#    4A9FFAC354DFAFB3. It is the same value modules/16_sim.sh --sim-auth-check
#    pins, so this asserts that the catcher's fresh path and the SIM path agree.
keyauth=$("$TOOL" auth --ki 465B5CE8B199B49FAA5F0A2EE238A6BC \
    --op CDC202D5123E20F62B6D676AC72CB318 --sqn FF9BB4D0B607 --amf B9B9 \
    --rand 23553CBE9637A89D218AE64DAE47BF35 2>/dev/null)
chk keyauth_autn   "$(kfld autn "$keyauth")" "55f328b43577b9b94a9ffac354dfafb3"
chk keyauth_f1     "$(kfld milenage_f1 "$keyauth")" "4A9FFAC354DFAFB3"
chk keyauth_label  "$(kfld what_it_is "$keyauth" | grep -c "fresh AUTHENTICATION REQUEST")" "1"
chk keyauth_no_key "$(kfld what_it_is_not "$keyauth" | grep -c "without a key")" "1"
# A wrong key must not silently produce the same MAC.
badauth=$("$TOOL" auth --ki 00000000000000000000000000000000 \
    --op CDC202D5123E20F62B6D676AC72CB318 --sqn FF9BB4D0B607 --amf B9B9 \
    --rand 23553CBE9637A89D218AE64DAE47BF35 2>/dev/null)
chk keyauth_negctl "$(kfld autn "$badauth" | grep -c "55f328b43577")" "0"
chk keyauth_needs_op "$("$TOOL" auth --ki 465B5CE8B199B49FAA5F0A2EE238A6BC --sqn FF9BB4D0B607 >/dev/null 2>&1; echo $?)" "2"

printf '\nCHECKS\t%d\nPASSED\t%d\nFAILED\t%d\n' "$n" "$((n - bad))" "$bad"
(( bad > 0 )) && { printf 'RESULT\tFAIL(%d)\n' "$bad"; exit 1; }
printf 'RESULT\tPASS\n'
