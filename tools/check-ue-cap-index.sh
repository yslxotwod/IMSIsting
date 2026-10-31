#!/usr/bin/env bash
# check-ue-cap-index.sh — referee for modules/09_lte_attach.sh --ue-cap-index.
#
# The octets --ue-cap-index decodes are a TS 24.301 §9.9.3.34 UE network
# capability, the same IE a real Attach Request carries. The strongest offline
# referee for those bits is therefore the dissector that decodes that IE, and
# tshark publishes its own bit table for the eight EEA bits and the eight EIA
# bits (nas-eps.emm.eea0 … eia7: one boolean field per bit, each with its mask
# in hex). This script reads that table out of `tshark -G fields`, derives the
# expected algorithm names for a given octet from it, and requires the module
# to print the same set. No packet has to be framed for that: the table is the
# dissector's own statement of where each bit lives.
#
# It also checks that the module's own NAS decoder puts the same octets in
# IE 0x33 of an Attach Request it built, and it exercises the unobserved paths
# on purpose — a dump with no capability column, an identity that is not an
# IMSI, and a value too long to be this IE — because a verb that answers those
# with a zero instead of a reason is the bug this file exists to catch.
#
# Exit: 0 all cases ok, 1 mismatches, 2 cannot run (no tshark, no module).
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TSHARK=${TSHARK:-/usr/bin/tshark}
MOD="$ROOT/modules/09_lte_attach.sh"

[[ -x "$TSHARK" ]] || { printf 'SKIP\t%s is not installed, so the bit table cannot be read\n' "$TSHARK"; exit 2; }
[[ -f "$MOD" ]]    || { printf 'ERROR\tno %s\n' "$MOD" >&2; exit 2; }

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
export LOOT_DIR="$tmp/loot" STATE_DIR="$tmp/state" TMP_DIR="$tmp/tmp" \
       CAPTURES_DIR="$tmp/captures" LOGS_DIR="$tmp/logs"

ok=0 bad=0 ncase=0
chk() { # <name> <got> <want>
    ncase=$(( ncase + 1 ))
    if [[ "$2" == "$3" ]]; then
        ok=$(( ok + 1 )); printf 'OK\t%s\t%s\n' "$1" "$2"
    else
        bad=$(( bad + 1 )); printf 'MISMATCH\t%s\tgot=%s\twant=%s\n' "$1" "$2" "$3"
    fi
}
has() { # <name> <text> <fixed string that must be in it>
    ncase=$(( ncase + 1 ))
    if [[ "$2" == *"$3"* ]]; then
        ok=$(( ok + 1 )); printf 'OK\t%s\t%s\n' "$1" "contains: $3"
    else
        bad=$(( bad + 1 )); printf 'MISMATCH\t%s\tno: %s\n' "$1" "$3"
    fi
}

# ── tshark's own table for the EEA / EIA bits ───────────────────────────
"$TSHARK" -G fields 2>/dev/null \
    | awk -F'\t' '$3 ~ /^nas-eps\.emm\.(128)?(eea|eia)[0-9]$/ { print $2 "|" $3 "|" $7 }' \
    > "$tmp/bits"
n_bits=$(grep -c . "$tmp/bits" 2>/dev/null || true)
if [[ "${n_bits:-0}" -lt 14 ]]; then
    printf 'SKIP\tthis tshark has no nas-eps EEA/EIA bit table (%s rows)\n' "${n_bits:-0}"
    exit 2
fi

# tshark_labels <eea|eia> <one octet, decimal> -> comma list of that octet's
# algorithm names, taken from the dissector's masks. Masks are powers of two,
# so bit n of the octet is int(v / mask) % 2 without any bitwise operator.
tshark_labels() {
    awk -F'|' -v fam="$1" -v v="$2" '
        {
            tail = $2; sub(/^nas-eps\.emm\./, "", tail)
            if (fam == "eea" && tail !~ /eea/) next
            if (fam == "eia" && tail !~ /eia/) next
            m = $3; sub(/^0x/, "", m); val = 0
            for (i = 1; i <= length(m); i++)
                val = val * 16 + index("0123456789ABCDEF", toupper(substr(m, i, 1))) - 1
            if (val > 0 && int(v / val) % 2 == 1)
                out = out (out == "" ? "" : ",") $1
        }
        END { print (out == "" ? "-" : out) }' "$tmp/bits"
}
canon() { tr ',' '\n' | sed '/^$/d' | sort | paste -sd, -; }

# compare_family <name> <eea|eia> <octet-decimal> <module list>
# The module must name exactly what the dissector names for this octet. A bit
# the dissector publishes no field for at all (tshark 4.2.2 has no
# nas-eps.emm.eia7) is dropped from the module side with a NOTE rather than
# counted as agreement — the name there comes from TS 24.301 §9.9.3.34, not
# from tshark, and pretending otherwise would be the referee lying.
compare_family() {
    local name="$1" fam="$2" oct="$3" got="$4" exp filtered="" lbl
    exp=$(tshark_labels "$fam" "$oct")
    while IFS= read -r lbl; do
        [[ -z "$lbl" || "$lbl" == "-" ]] && continue
        if awk -F'|' -v l="$lbl" '$1 == l { found = 1 } END { exit !found }' "$tmp/bits"; then
            filtered+="${filtered:+,}$lbl"
        else
            printf 'NOTE\t%s\t%s\t%s\n' "$name" "$lbl" \
                "tshark publishes no field for this bit; the name is from TS 24.301 9.9.3.34"
        fi
    done < <(printf '%s\n' "$got" | tr ',' '\n')
    chk "$name" "$(printf '%s\n' "${filtered:--}" | canon)" "$(printf '%s\n' "$exp" | canon)"
}

# ── a dump with capability octets, one row per shape worth testing ──────
cat > "$tmp/dump.csv" <<'CSV'
imsi,ue_network_capability,msisdn
001010000000001,E0E0,491700000001
001010000000002,8080,491700000002
001010000000003,FFFF,491700000003
001010000000004,0000,491700000004
001010000000005,,"+491700000005"
CSV

bash "$MOD" --ue-cap-index "$tmp/dump.csv" > "$tmp/out.tsv" 2> "$tmp/out.err"
rc=$?
chk dump-rc "$rc" 0
chk dump-records "$(awk -F'\t' '$1=="records"{print $2}' "$tmp/out.tsv")" 5
chk dump-with-cap "$(awk -F'\t' '$1=="with_capability"{print $2}' "$tmp/out.tsv")" 4
chk dump-without-cap "$(awk -F'\t' '$1=="without_capability"{print $2}' "$tmp/out.tsv")" 1
chk dump-verdict "$(awk -F'\t' '$1=="verdict"{print $2}' "$tmp/out.tsv")" indexed

# every octet pair, against the dissector's own masks
while IFS=',' read -r imsi cap _rest; do
    [[ -n "$imsi" && -n "$cap" ]] || continue
    cap="${cap//\"/}"
    o1=$(( 16#${cap:0:2} ))
    o2=$(( 16#${cap:2:2} ))
    # index row: index | imsi | octets | fingerprint | eea | eia | verdict | detail
    got_eea=$(awk -F'\t' -v k="$imsi" '$1=="index" && $2==k{print $5}' "$tmp/out.tsv")
    got_eia=$(awk -F'\t' -v k="$imsi" '$1=="index" && $2==k{print $6}' "$tmp/out.tsv")
    compare_family "eea-for-$cap" eea "$o1" "$got_eea"
    compare_family "eia-for-$cap" eia "$o2" "$got_eia"
done < <(tail -n +2 "$tmp/dump.csv")

# the same octets, seen by the module's own NAS decoder inside IE 0x33 of an
# Attach Request — the IE the dissector above decodes in a capture
attach=$(bash "$MOD" --encode-attach 001010000000001 E0E0 2>/dev/null \
    | awk -F'\t' '$1=="nas_hex"{print $2}')
has attach-built "$attach" "3302E0E0"
dec=$(bash "$MOD" --decode-nas "$attach" 2>/dev/null)
has attach-ie-type "$dec" "type=0x33"
has attach-ie-value "$dec" "value=E0E0"
has attach-ie-name "$dec" "UE network capability"

# an unobserved dump is a normal answer, not a zero: no capability column at all
cat > "$tmp/nocap.csv" <<'CSV'
imsi,msisdn
001010000000001,491700000001
CSV
bash "$MOD" --ue-cap-index "$tmp/nocap.csv" > "$tmp/nocap.tsv" 2>&1
chk nocap-rc "$?" 1
chk nocap-verdict "$(awk -F'\t' '$1=="verdict"{print $2}' "$tmp/nocap.tsv")" unobserved
chk nocap-row "$(awk -F'\t' '$1=="index"{print $7}' "$tmp/nocap.tsv")" unobserved
chk nocap-note "$(awk -F'\t' '$1=="note"{print $2}' "$tmp/nocap.tsv" | cut -c1-25)" \
    "the CSV has no capability"
has nocap-searched "$(cat "$tmp/nocap.tsv")" "ue_network_capability"

# an identity that is not an IMSI is unobserved, never indexed as one
printf 'supi,capability\n001,E0E0\n' > "$tmp/supi.csv"
bash "$MOD" --ue-cap-index "$tmp/supi.csv" > "$tmp/supi.tsv" 2>&1
chk supi-rc "$?" 1
has supi-reason "$(cat "$tmp/supi.tsv")" "not a 14-15 digit IMSI"

# a value too long to be this IE: it is somebody else's capability
printf 'imsi,ue_network_capability\n001010000000001,000102030405060708090A0B0C0D0E0F10\n' > "$tmp/big.csv"
bash "$MOD" --ue-cap-index "$tmp/big.csv" > "$tmp/big.tsv" 2>&1
chk big-rc "$?" 1
has big-reason "$(cat "$tmp/big.tsv")" "1..15 octets"

# a column named only "capability" is not this IE: unobserved, with the reason
printf 'imsi,capability\n001010000000001,E0E0\n' > "$tmp/vague.csv"
bash "$MOD" --ue-cap-index "$tmp/vague.csv" > "$tmp/vague.tsv" 2>&1
chk vague-rc "$?" 1
has vague-reason "$(cat "$tmp/vague.tsv")" "does not say it is the NAS UE network capability"
chk vague-no-class "$(grep -c 'nas-caps' "$tmp/vague.tsv")" 0

# a look-up that misses says so, and names what the dump does hold
bash "$MOD" --ue-cap-index "$tmp/dump.csv" 001010000000099 > "$tmp/miss.tsv" 2>&1
chk miss-rc "$?" 1
chk miss-status "$(awk -F'\t' '$1=="status"{print $2}' "$tmp/miss.tsv")" unobserved
has miss-known "$(cat "$tmp/miss.tsv")" "001010000000001"

# a look-up that hits answers one IMSI only
bash "$MOD" --ue-cap-index "$tmp/dump.csv" 001010000000002 > "$tmp/hit.tsv" 2>&1
chk hit-rc "$?" 0
chk hit-rows "$(grep -c '^index' "$tmp/hit.tsv")" 1
chk hit-imsi "$(awk -F'\t' '$1=="index"{print $2}' "$tmp/hit.tsv")" 001010000000002

# refusals
bash "$MOD" --ue-cap-index >/dev/null 2>&1;            chk usage-noarg "$?" 2
bash "$MOD" --ue-cap-index /nonexistent.csv >/dev/null 2>&1; chk usage-nofile "$?" 1
bash "$MOD" --ue-cap-index "$tmp/dump.csv" abc >/dev/null 2>&1; chk usage-badimsi "$?" 2

# the store: append-only TSV under loot/lte_attach
store="$tmp/loot/lte_attach/ue-cap-index.tsv"
chk store-header "$(head -1 "$store")" \
    "$(printf 'ts\tfile\timsi\tsource\tkind\toctets\tclass\tverdict\tdetail')"
chk store-measured "$(awk -F'\t' '$1!="ts" && $8=="measured"{c++} END{print (c>0)?"yes":"no"}' "$store")" yes
before=$(grep -c . "$store")
bash "$MOD" --ue-cap-index "$tmp/dump.csv" 001010000000001 >/dev/null 2>&1
after=$(grep -c . "$store")
chk store-append "$(( after - before ))" 1

printf 'CASES\t%d\tOK\t%d\tMISMATCHES\t%d\n' "$ncase" "$ok" "$bad"
[[ $bad -eq 0 ]] && { printf 'RESULT\tPASS\n'; exit 0; }
printf 'RESULT\tFAIL(%d)\n' "$bad"
exit 1
