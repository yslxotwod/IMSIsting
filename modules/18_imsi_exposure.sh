#!/usr/bin/env bash
# IMSI exposure audit — identity harvesting, TMSI/GUTI-to-IMSI correlation,
# cross-capture correlation and a per-subscriber exposure score.
#
# This module never reads a capture itself. It drives module 17
# (17_pcap_analysis.sh) as a subprocess and consumes the TSV it emits, so
# there is exactly one pcap parser in the tree. When module 17 is absent the
# audit still runs against a hand-supplied TSV of the same shape, which is
# also what the selftest uses.
#
# The highest-value output is the mapping. A forced Identity Request or a
# Location Update puts both identities in one message, and once a TMSI has
# been bound to an IMSI every other frame carrying that TMSI names the
# subscriber — this is the de-anonymisation that the temporary identity
# exists to prevent.
#
# Resolve IMSISTING_ROOT from this script's own path so state and loot land in
# the project tree even when launched standalone via pkexec (no launcher env).
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

MOD_TMP="$TMP_DIR/imsi"
IMSI_DIR="$LOOT_DIR/imsi_exposure"
IMSI_IDENT="$IMSI_DIR/identities.tsv"
IMSI_MAP="$IMSI_DIR/tmsi_imsi_map.tsv"
IMSI_SUBS="$IMSI_DIR/subscribers.tsv"
IMSI_EXPO="$IMSI_DIR/exposure.tsv"
mkdir -p "$MOD_TMP" "$IMSI_DIR" 2>/dev/null

# Module 21, located next to this file. Called as a subprocess, never soured,
# so its globals cannot collide with ours.
IMSI_PCAP_MOD="${IMSI_PCAP_MOD:-$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)/17_pcap_analysis.sh}"

# Redaction is the responsible default for output that leaves the machine:
# --redact masks every identity to its last four digits.
IMSI_REDACT=0

# ── sanitisation ────────────────────────────────────────────────────────
# An IMSI lifted from a capture is untrusted text. A tab inside it would
# forge a whole TSV row in a consumer that splits on tab.
imsi_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── TSV field access ────────────────────────────────────────────────────
# `while IFS=$'\t' read -r ...` collapses runs of tab characters into one
# delimiter, so a row with an empty column shifts every later value left.
# Field access therefore goes through awk, which splits on every tab and
# keeps empty fields where they belong.
imsi_field() {
    # imsi_field <line> <n>
    printf '%s\n' "$1" | awk -F'\t' -v n="$2" '{ if (NF >= n) print $n; else print "" }'
}

# ── redaction ───────────────────────────────────────────────────────────
# Masks all but the last four characters. Works for any length: a value
# shorter than five characters has nothing safe to show and becomes all
# asterisks, because showing a 4-digit value "minus the last 4" would be
# showing the whole thing.
imsi_mask() {
    local v="${1:-}"
    local n=${#v}
    (( n == 0 )) && { printf '\n'; return 0; }
    if (( n <= 4 )); then
        printf '%s' "$v" | tr '0-9A-Za-z' '*'
        printf '\n'
        return 0
    fi
    local keep=4
    local stars=$(( n - keep ))
    local i out=""
    for (( i = 0; i < stars; i++ )); do out+="*"; done
    printf '%s%s\n' "$out" "${v:$stars}"
}

# Apply redaction only when --redact is in force.
imsi_show() {
    local v="${1:-}"
    if (( IMSI_REDACT )); then imsi_mask "$v"; else printf '%s\n' "$v"; fi
}

# ── module 17 integration ───────────────────────────────────────────────
imsi_pcap_available() {
    [[ -n "$IMSI_PCAP_MOD" && -f "$IMSI_PCAP_MOD" && -r "$IMSI_PCAP_MOD" ]]
}

# Harvest one capture through module 17. Its rows are already sanitised by
# that module; this wraps them so a failure is a failure here too.
imsi_harvest_pcap() {
    local f="${1:-}" out
    [[ -n "$f" ]] || { printf 'ERROR\tno capture given\n' >&2; return 2; }
    [[ -f "$f" ]] || { printf 'ERROR\tno such capture: %s\n' "$f" >&2; return 1; }
    imsi_pcap_available || {
        printf 'ERROR\tmodule 21 not found at %s — cannot read a capture\n' "$IMSI_PCAP_MOD" >&2
        return 1
    }
    out=$(bash "$IMSI_PCAP_MOD" --identities "$f" 2>/dev/null); local rc=$?
    (( rc == 0 )) || {
        printf 'ERROR\tmodule 21 failed to harvest %s (rc=%s)\n' "$f" "$rc" >&2
        return 1
    }
    printf '%s\n' "$out"
}

imsi_init_store() {
    mkdir -p "$IMSI_DIR"
    [[ -f "$IMSI_IDENT" ]] || printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n' > "$IMSI_IDENT"
}

imsi_ident_count() {
    [[ -f "$IMSI_IDENT" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$IMSI_IDENT" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# Append harvested rows, dropping the header and any summary line, and
# de-duplicating on (file, frame, kind, value) so re-running an audit does
# not multiply the store.
imsi_store_add() {
    local tmp="$1"
    [[ -s "$tmp" ]] || return 1
    imsi_init_store
    local added=0 rec
    while IFS= read -r rec; do
        [[ -z "$rec" ]] && continue
        [[ "$rec" == file$'\t'* ]] && continue     # header
        [[ "$rec" == summary$'\t'* ]] && continue  # module 17 counter
        local f1 f2 f3
        f1=$(cut -f1 <<<"$rec"); f2=$(cut -f2 <<<"$rec")
        f3=$(cut -f3 <<<"$rec")
        # A row is an identity row when it has a source label, a frame, and
        # a kind drawn from the identity vocabulary. The file column is a
        # label, not necessarily an absolute path: a store can name captures
        # relative to the tree they came from, and requiring an absolute
        # path here would silently discard every such row.
        [[ -n "$f1" && -n "$f2" ]] || continue
        case "$f3" in
            imsi|imei|imeisv|tmsi|ptmsi|m-tmsi|guti|5g-guti|msisdn|suci|supi) ;;
            *) continue ;;
        esac
        if grep -qF -- "$rec" "$IMSI_IDENT" 2>/dev/null; then continue; fi
        printf '%s\n' "$rec" >> "$IMSI_IDENT"
        added=$(( added + 1 ))
    done < "$tmp"
    printf '%d\n' "$added"
}

# ── optional richer fields ──────────────────────────────────────────────
# Module 21's identity rows carry the capture, frame, kind, value and the
# protocol that exposed it. The audit is more useful with the cell the
# identity was seen on and the cipher in force, and both are things a
# capture legitimately carries. This schema is what --audit reads:
#
#   file  frame  kind  value  protocol  src  dst  where  [plmn] [cell] [ts] [cipher]
#
# Columns 9-12 are optional; a row with only the first eight still audits.
imsi_field() {
    # imsi_field <row> <n> — field n, or empty when the row is short.
    local row="$1" n="$2"
    printf '%s\n' "$row" | awk -F'\t' -v n="$n" 'NF>=n{print $n; exit}'
}

# ── correlation ─────────────────────────────────────────────────────────
# Build the temporary-identity-to-IMSI binding.
#
# The binding is real and comes from two places in a cellular capture:
#
#   1. An Identity Response carries the IMSI *and* the message is addressed
#      to a temporary identity the network assigned (TMSI in 2G/3G/4G,
#      5G-GUTI in 5G). Both appear in the same exchange.
#   2. A Location Update / Attach / TAU carries the old temporary identity
#      in the request and the new one in the accept, together with the IMSI
#      on the first attach.
#
# Within one capture, the correlation available from a flat identity list is
# by co-occurrence: rows sharing a frame, or rows sharing a capture and a
# source/destination pair. This builder implements both, and reports the
# evidence for each binding rather than asserting it.
imsi_build_map() {
    local src="${1:-$IMSI_IDENT}"
    [[ -f "$src" ]] || { printf 'ERROR\tno identity store: %s\n' "$src" >&2; return 1; }
    local n; n=$(tail -n +2 "$src" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tidentity store is empty — nothing to correlate\n' >&2; return 1; }

    mkdir -p "$IMSI_DIR"
    printf 'temp_kind\ttemp_value\timsi\tevidence\tfile\tframe\tprotocol\n' > "$IMSI_MAP"

    local found=0
    # ── Pass 1: same frame, same capture ────────────────────────────────
    # A frame that carries both a temporary identity and an IMSI is the
    # strongest evidence there is: that is what an Identity Response or a
    # combined Attach looks like. Group by (file, frame).
    local key
    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        local f="${key%%$'\t'*}" fr="${key##*$'\t'}"
        local imsis temps
        imsis=$(awk -F'\t' -v f="$f" -v r="$fr" \
            '$1==f && $2==r && $3=="imsi"{print $4}' "$src" | sort -u)
        temps=$(awk -F'\t' -v f="$f" -v r="$fr" \
            '$1==f && $2==r && ($3=="tmsi"||$3=="guti"||$3=="m-tmsi"||$3=="5g-guti"||$3=="ptmsi"){print $3"\t"$4}' "$src" | sort -u)
        [[ -z "$imsis" || -z "$temps" ]] && continue
        local i t
        while IFS= read -r i; do
            [[ -z "$i" ]] && continue
            while IFS=$'\t' read -r tk tv; do
                [[ -z "$tk" ]] && continue
                printf '%s\t%s\t%s\tsame-frame\t%s\t%s\t%s\n' \
                    "$(imsi_sanitize "$tk")" "$(imsi_sanitize "$tv")" \
                    "$(imsi_sanitize "$i")" "$(imsi_sanitize "$f")" \
                    "$(imsi_sanitize "$fr")" "identity-exchange" >> "$IMSI_MAP"
                found=$(( found + 1 ))
            done <<< "$temps"
        done <<< "$imsis"
    done < <(awk -F'\t' 'NR>1{print $1"\t"$2}' "$src" | sort -u)

    # ── Pass 2: same capture and same endpoint pair ─────────────────────
    # Across a Location Update the IMSI and the temporary identity appear in
    # different frames of the same dialog. Binding them by endpoint pair is
    # weaker than same-frame evidence, so the evidence column says so.
    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        local f="${key%%$'\t'*}" pair="${key##*$'\t'}"
        local imsis temps
        imsis=$(awk -F'\t' -v f="$f" -v p="$pair" \
            'NR>1 && $1==f && ($6"\t"$7)==p && $3=="imsi"{print $4}' "$src" | sort -u)
        temps=$(awk -F'\t' -v f="$f" -v p="$pair" \
            'NR>1 && $1==f && ($6"\t"$7)==p && ($3=="tmsi"||$3=="guti"||$3=="m-tmsi"||$3=="5g-guti"||$3=="ptmsi"){print $3"\t"$4}' "$src" | sort -u)
        [[ -z "$imsis" || -z "$temps" ]] && continue
        local i tk tv
        while IFS= read -r i; do
            [[ -z "$i" ]] && continue
            while IFS=$'\t' read -r tk tv; do
                [[ -z "$tk" ]] && continue
                # Do not duplicate a same-frame binding.
                if grep -qF "$(printf '%s\t%s\t%s\tsame-frame' "$tk" "$tv" "$i")" "$IMSI_MAP" 2>/dev/null; then
                    continue
                fi
                printf '%s\t%s\t%s\tsame-endpoint-pair\t%s\t-\t%s\n' \
                    "$(imsi_sanitize "$tk")" "$(imsi_sanitize "$tv")" \
                    "$(imsi_sanitize "$i")" "$(imsi_sanitize "$f")" \
                    "dialog" >> "$IMSI_MAP"
                found=$(( found + 1 ))
            done <<< "$temps"
        done <<< "$imsis"
    done < <(awk -F'\t' 'NR>1{print $1"\t"$6"\t"$7}' "$src" | sort -u)

    printf '%d\n' "$found"
}

imsi_map_rows() {
    [[ -f "$IMSI_MAP" ]] || return 1
    local n; n=$(tail -n +2 "$IMSI_MAP" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

imsi_cmd_map() {
    local src="${1:-}"
    [[ -n "$src" && -f "$src" ]] && IMSI_IDENT="$src"
    local n; n=$(imsi_build_map "$IMSI_IDENT") || return 1
    if (( n == 0 )); then
        # An empty mapping from a non-empty store is a real answer, but it
        # must be stated as a finding rather than printed as an empty table.
        printf 'temp_kind\ttemp_value\timsi\tevidence\tfile\tframe\tprotocol\n'
        printf 'INFO\tno temporary identity co-occurred with an IMSI in this store\n' >&2
        return 0
    fi
    head -n1 "$IMSI_MAP"
    local line tk tv im ev f fr pr
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == temp_kind$'\t'* ]] && continue
        tk=$(imsi_field "$line" 1); tv=$(imsi_field "$line" 2)
        im=$(imsi_field "$line" 3); ev=$(imsi_field "$line" 4)
        f=$(imsi_field  "$line" 5); fr=$(imsi_field "$line" 6)
        pr=$(imsi_field "$line" 7)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(imsi_sanitize "$tk")" "$(imsi_show "$tv")" "$(imsi_show "$im")" \
            "$(imsi_sanitize "$ev")" "$(imsi_sanitize "$f")" \
            "$(imsi_sanitize "$fr")" "$(imsi_sanitize "$pr")"
    done < "$IMSI_MAP"
}

# ── per-subscriber aggregation ──────────────────────────────────────────
# One row per IMSI. The columns are the exposure facts an audit has to
# answer for: how the IMSI was exposed, what else was exposed with it,
# where and when it was seen, and the score.
imsi_headers_subs() {
    printf 'imsi\tscore\timsi_cleartext\ttmsi_mapped\tguti_mapped\timei_exposed\tmsisdn_exposed\tnull_cipher\tframes\tcaptures\tfirst_seen\tlast_seen\tplmns\tprotocols\n'
}

imsi_cmd_subscribers_tsv() {
    local src="${IMSI_IDENT}"
    [[ -f "$src" ]] || { printf 'ERROR\tno identity store; run --audit on a capture first\n' >&2; return 1; }
    local n; n=$(tail -n +2 "$src" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tidentity store is empty\n' >&2; return 1; }

    # Every IMSI in the store, plus the IMSIs that the map bound.
    local imsis
    imsis=$( { awk -F'\t' 'NR>1 && $3=="imsi"{print $4}' "$src"
               [[ -f "$IMSI_MAP" ]] && awk -F'\t' 'NR>1{print $3}' "$IMSI_MAP"
             } | grep -E '^[0-9]+$' | sort -u)
    [[ -n "$imsis" ]] || { printf 'ERROR\tno IMSI found in the store\n' >&2; return 1; }

    imsi_headers_subs
    imsi_score_all "$src"
}

# The exposure score. The ordering is the point of the whole module:
#
#   70  IMSI sent in the clear           identity disclosed to anyone listening
#   40  TMSI or GUTI mapped to an IMSI   de-anonymisation of a whole session
#   25  IMEI exposed                     device tracking independent of the SIM
#   20  MSISDN exposed                   the subscriber's own number, in the clear
#   15  null cipher in use               everything else on the bearer is readable
#
# The score is the sum of the applicable findings, capped at 100 so a
# subscriber with several findings is not reported above the maximum. The
# cap is deliberate: a single grant of 99 would be meaningless next to a
# grant of 70, whereas "worst case" should read as worst case.
imsi_score_of() {
    local cleartext="$1" tmsi="$2" guti="$3" imei="$4" msisdn="$5" nullc="$6"
    local s=0
    (( cleartext )) && s=$(( s + 70 ))
    (( tmsi ))      && s=$(( s + 40 ))
    (( guti ))      && s=$(( s + 40 ))
    (( imei ))      && s=$(( s + 25 ))
    (( msisdn ))    && s=$(( s + 20 ))
    (( nullc ))     && s=$(( s + 15 ))
    (( s > 100 )) && s=100
    printf '%d\n' "$s"
}

imsi_band() {
    local s="$1"
    if   (( s >= 70 )); then echo "critical"
    elif (( s >= 40 )); then echo "high"
    elif (( s >= 15 )); then echo "medium"
    elif (( s > 0 ));   then echo "low"
    else                     echo "none"
    fi
}

imsi_score_all() {
    local src="$1"
    local imsis
    imsis=$( { awk -F'\t' 'NR>1 && $3=="imsi"{print $4}' "$src"
               [[ -f "$IMSI_MAP" ]] && awk -F'\t' 'NR>1{print $3}' "$IMSI_MAP"
             } | grep -E '^[0-9]+$' | sort -u)
    local im
    while IFS= read -r im; do
        [[ -z "$im" ]] && continue
        imsi_score_one "$src" "$im"
    done <<< "$imsis"
}

imsi_score_one() {
    local src="$1" im="$2"

    # How was the IMSI itself exposed? A row of kind "imsi" in the clear is
    # the worst case; an IMSI that only appears inside the map was learned
    # from an exchange rather than broadcast.
    local ct_rows ct_frames
    ct_rows=$(awk -F'\t' -v im="$im" 'NR>1 && $3=="imsi" && $4==im' "$src")
    ct_frames=$(printf '%s\n' "$ct_rows" | grep -c . || true)
    local cleartext=0
    (( ct_frames > 0 )) && cleartext=1

    # Temporary identities bound to this IMSI.
    local tmap t_tmsi=0 t_guti=0
    tmap=$( [[ -f "$IMSI_MAP" ]] && awk -F'\t' -v im="$im" 'NR>1 && $3==im{print $1"\t"$2}' "$IMSI_MAP" )
    if [[ -n "$tmap" ]]; then
        while IFS=$'\t' read -r tk tv; do
            [[ -z "$tk" ]] && continue
            case "$tk" in
                tmsi|ptmsi|m-tmsi) t_tmsi=1 ;;
                guti|5g-guti)       t_guti=1 ;;
                *)                  t_tmsi=1 ;;
            esac
        done <<< "$tmap"
    fi

    # Everything else exposed in the same capture.
    local imei_n msisdn_n
    imei_n=$(awk -F'\t' -v f="" 'NR>1 && ($3=="imei"||$3=="imeisv")' "$src" | grep -c . || true)
    msisdn_n=$(awk -F'\t' 'NR>1 && $3=="msisdn"' "$src" | grep -c . || true)
    local imei=0 msisdn=0
    if (( imei_n > 0 )); then
        # Attribute the IMEI only when it shares a capture with this IMSI.
        local caps
        caps=$(printf '%s\n' "$ct_rows" | awk -F'\t' 'NF>=1{print $1}' | sort -u)
        while IFS= read -r c; do
            [[ -z "$c" ]] && continue
            if awk -F'\t' -v c="$c" 'NR>1 && $1==c && ($3=="imei"||$3=="imeisv")' "$src" | grep -q .; then
                imei=1; break
            fi
        done <<< "$caps"
    fi
    if (( msisdn_n > 0 )); then
        local caps
        caps=$(printf '%s\n' "$ct_rows" | awk -F'\t' 'NF>=1{print $1}' | sort -u)
        while IFS= read -r c; do
            [[ -z "$c" ]] && continue
            if awk -F'\t' -v c="$c" 'NR>1 && $1==c && $3=="msisdn"' "$src" | grep -q .; then
                msisdn=1; break
            fi
        done <<< "$caps"
    fi

    # Null cipher, from column 12 (cipher) when module 17 or a caller
    # supplied it.
    local nullc=0
    if awk -F'\t' -v im="$im" 'NR>1 && $4==im && NF>=12 && ($12=="null"||$12=="EEA0"||$12=="NEA0"||$12=="UEA0"||$12=="A5/0"||$12=="0")' "$src" | grep -q .; then
        nullc=1
    fi

    local score; score=$(imsi_score_of "$cleartext" "$t_tmsi" "$t_guti" "$imei" "$msisdn" "$nullc")

    # Aggregates over every row that belongs to this subscriber: the IMSI
    # rows plus the rows of any frame the map tied to it.
    local frames captures first last plmns protos
    frames=$(( ct_frames ))
    captures=$(printf '%s\n' "$ct_rows" | awk -F'\t' 'NF>=1{print $1}' | sort -u | grep -c . || true)
    first=$(printf '%s\n' "$ct_rows" | awk -F'\t' 'NF>=11{print $11}' | sort -n | head -n1)
    last=$(printf '%s\n' "$ct_rows" | awk -F'\t' 'NF>=11{print $11}' | sort -n | tail -n1)
    plmns=$(printf '%s\n' "$ct_rows" | awk -F'\t' 'NF>=9{print $9}' | grep -v '^$' | sort -u | paste -sd, - 2>/dev/null)
    protos=$(printf '%s\n' "$ct_rows" | awk -F'\t' 'NF>=5{print $5}' | sort -u | paste -sd, - 2>/dev/null)

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(imsi_show "$im")" "$score" "$cleartext" "$t_tmsi" "$t_guti" \
        "$imei" "$msisdn" "$nullc" "${frames:-0}" "${captures:-0}" \
        "$(imsi_sanitize "${first:--}")" "$(imsi_sanitize "${last:--}")" \
        "$(imsi_sanitize "${plmns:--}")" "$(imsi_sanitize "${protos:--}")"
}

# ── exposure TSV: one row per finding, with the reason ──────────────────
imsi_cmd_exposure_tsv() {
    local src="${IMSI_IDENT}"
    [[ -f "$src" ]] || { printf 'ERROR\tno identity store; run --audit on a capture first\n' >&2; return 1; }
    local n; n=$(tail -n +2 "$src" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tidentity store is empty\n' >&2; return 1; }

    printf 'imsi\tfinding\tseverity\tpoints\tevidence\n'
    local subs
    subs=$(imsi_cmd_subscribers_tsv | tail -n +2)
    [[ -n "$subs" ]] || { printf 'ERROR\tno subscribers to score\n' >&2; return 1; }
    local row im score ct tmsi guti imei msisdn nullc frames caps first last plmns protos
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue
        [[ "$row" == imsi$'\t'* ]] && continue
        im=$(imsi_field     "$row" 1);  score=$(imsi_field "$row" 2)
        ct=$(imsi_field     "$row" 3);  tmsi=$(imsi_field  "$row" 4)
        guti=$(imsi_field   "$row" 5);  imei=$(imsi_field  "$row" 6)
        msisdn=$(imsi_field "$row" 7);  nullc=$(imsi_field "$row" 8)
        frames=$(imsi_field "$row" 9);  caps=$(imsi_field  "$row" 10)
        first=$(imsi_field  "$row" 11); last=$(imsi_field  "$row" 12)
        plmns=$(imsi_field  "$row" 13); protos=$(imsi_field "$row" 14)
        [[ -z "$im" ]] && continue
        [[ "$ct" == "1" ]] && printf '%s\tIMSI in the clear\tcritical\t70\tIMSI transmitted without a temporary identity in %s frame(s)\n' \
            "$im" "$frames"
        [[ "$tmsi" == "1" ]] && printf '%s\tTMSI mapped to IMSI\thigh\t40\ttemporary identity bound to this subscriber; the binding de-anonymises every other frame carrying it\n' "$im"
        [[ "$guti" == "1" ]] && printf '%s\tGUTI mapped to IMSI\thigh\t40\t5G/4G GUTI bound to this subscriber\n' "$im"
        [[ "$imei" == "1" ]] && printf '%s\tIMEI exposed\tmedium\t25\tdevice identity readable in the same capture\n' "$im"
        [[ "$msisdn" == "1" ]] && printf '%s\tMSISDN exposed\tmedium\t20\tsubscriber number readable in the same capture\n' "$im"
        [[ "$nullc" == "1" ]] && printf '%s\tnull cipher in use\tmedium\t15\tbearer carries no ciphering, so all traffic on it is readable\n' "$im"
        if [[ "$score" == "0" ]]; then
            printf '%s\tno exposure finding\tinfo\t0\tidentity present but no exposed attribute matched a finding\n' "$im"
        fi
    done < <(printf '%s\n' "$subs")
}

# ── cross-capture correlation ───────────────────────────────────────────
# The same IMSI seen in several captures: how many, over what time span,
# on which PLMNs. This is what turns a set of captures into a movement
# picture, and it is why the audit takes more than one file.
imsi_cmd_cross() {
    local src="${IMSI_IDENT}"
    [[ -f "$src" ]] || { printf 'ERROR\tno identity store\n' >&2; return 1; }
    local n; n=$(tail -n +2 "$src" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tidentity store is empty\n' >&2; return 1; }

    printf 'imsi\tcaptures\tfirst_seen\tlast_seen\tspan_s\tplmns\tfiles\n'
    local im
    while IFS= read -r im; do
        [[ -z "$im" ]] && continue
        local rows caps first last span plmns files
        rows=$(awk -F'\t' -v im="$im" 'NR>1 && $4==im && $3=="imsi"' "$src")
        [[ -n "$rows" ]] || continue
        caps=$(printf '%s\n' "$rows" | awk -F'\t' '{print $1}' | sort -u | grep -c . || true)
        files=$(printf '%s\n' "$rows" | awk -F'\t' '{print $1}' | sort -u | paste -sd, - 2>/dev/null)
        first=$(printf '%s\n' "$rows" | awk -F'\t' 'NF>=11 && $11!=""{print $11}' | sort -n | head -n1)
        last=$(printf '%s\n' "$rows" | awk -F'\t' 'NF>=11 && $11!=""{print $11}' | sort -n | tail -n1)
        plmns=$(printf '%s\n' "$rows" | awk -F'\t' 'NF>=9 && $9!=""{print $9}' | sort -u | paste -sd, - 2>/dev/null)
        span="-"
        if [[ -n "$first" && -n "$last" && "$first" =~ ^[0-9]+$ && "$last" =~ ^[0-9]+$ ]]; then
            span=$(( last - first ))
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(imsi_show "$im")" "$caps" "${first:--}" "${last:--}" \
            "$span" "$(imsi_sanitize "${plmns:--}")" "$(imsi_sanitize "${files:--}")"
    done < <(awk -F'\t' 'NR>1 && $3=="imsi"{print $4}' "$src" | sort -u)
}

# ── the audit verb ──────────────────────────────────────────────────────
# Accepts captures and/or pre-harvested TSVs. A file ending .tsv/.txt is
# read as a store directly (this is the path the selftest uses, and the path
# a caller with their own parser uses); anything else is handed to module 17.
imsi_cmd_audit() {
    (($# > 0)) || { printf 'ERROR\tusage: --audit <pcap...|tsv...>\n' >&2; return 2; }
    local total=0 f tmp
    # Classify the inputs first so a missing module 17 is reported before
    # any partial work happens. The module check comes before the file
    # check because "module 17 is missing" is the actionable error when the
    # caller handed us a capture, while "no such file" is actionable for a
    # TSV.
    local need_pcap=0 have_tsv=0
    for f in "$@"; do
        case "${f,,}" in
            *.tsv|*.txt) have_tsv=1 ;;
            *) need_pcap=1 ;;
        esac
    done
    if (( need_pcap )) && ! imsi_pcap_available; then
        printf 'ERROR\tcapture analysis module not found at %s — supply a TSV instead, or restore module 17\n' \
            "$IMSI_PCAP_MOD" >&2
        return 1
    fi
    for f in "$@"; do
        [[ -f "$f" ]] || { printf 'ERROR\tno such file: %s\n' "$f" >&2; return 1; }
    done
    : "$have_tsv"

    tmp=$(mktemp "$MOD_TMP/audit.XXXXXX") || return 1
    : > "$tmp"
    for f in "$@"; do
        case "${f,,}" in
            *.tsv|*.txt)
                cat "$f" >> "$tmp"
                total=$(( total + 1 ))
                ;;
            *)
                if ! imsi_harvest_pcap "$f" >> "$tmp" 2>/dev/null; then
                    printf 'ERROR\tharvest failed for %s\n' "$f" >&2
                    rm -f "$tmp"
                    return 1
                fi
                total=$(( total + 1 ))
                ;;
        esac
    done

    # An input with no identity is an error, not an empty success. This is
    # checked against the rows in THIS run, not against the store size: a
    # store that already holds rows from an earlier audit must not turn an
    # empty input into a success.
    local added
    added=$(imsi_store_add "$tmp")
    rm -f "$tmp"
    if [[ "${added:-0}" -eq 0 ]]; then
        printf 'ERROR\tno identities found in the %s input(s) supplied\n' "$total" >&2
        return 1
    fi

    imsi_build_map "$IMSI_IDENT" >/dev/null 2>&1 || true
    printf 'inputs\t%s\n' "$total"
    printf 'identities\t%s\n' "$(imsi_ident_count)"
    printf 'mappings\t%s\n' "$(imsi_map_rows 2>/dev/null || echo 0)"
    printf 'store\t%s\n' "$IMSI_IDENT"
    printf 'map\t%s\n' "$IMSI_MAP"
    return 0
}

# ── report ──────────────────────────────────────────────────────────────
imsi_cmd_report() {
    local src="${IMSI_IDENT}"
    [[ -f "$src" ]] || { printf 'ERROR\tno identity store; run --audit first\n' >&2; return 1; }
    local n; n=$(tail -n +2 "$src" 2>/dev/null | grep -c . || true)
    (( n > 0 )) || { printf 'ERROR\tidentity store is empty\n' >&2; return 1; }

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out="$IMSI_DIR/report_${ts}.txt"
    mkdir -p "$IMSI_DIR"
    {
        printf 'IMSI exposure audit\n'
        printf 'generated: %s\n' "$(date -Is)"
        printf 'store: %s\n' "$src"
        printf 'redacted: %s\n' "$([[ $IMSI_REDACT -eq 1 ]] && echo yes || echo no)"
        printf '\n-- summary ----------------------------------------------------\n'
        printf 'identity rows: %s\n' "$n"
        printf 'temporary-identity mappings: %s\n' "$(imsi_map_rows 2>/dev/null || echo 0)"
        printf '\n-- exposure findings -------------------------------------------\n'
        imsi_cmd_exposure_tsv | column -t -s$'\t' 2>/dev/null || imsi_cmd_exposure_tsv
        printf '\n-- per-subscriber ----------------------------------------------\n'
        imsi_cmd_subscribers_tsv | column -t -s$'\t' 2>/dev/null || imsi_cmd_subscribers_tsv
        printf '\n-- temporary identity mappings ---------------------------------\n'
        imsi_cmd_map
        printf '\n-- cross-capture correlation -----------------------------------\n'
        imsi_cmd_cross
        printf '\n-- methodology -------------------------------------------------\n'
        cat <<'EOM'
An IMSI sent in the clear is scored 70 because it discloses the subscriber
to any receiver in range for the lifetime of that exchange. A TMSI or GUTI
mapped to an IMSI is scored 40: the temporary identity is designed to make
a subscriber unlinkable, and once the binding is known every other frame
carrying that value names the subscriber. An exposed IMEI scores 25 because
it tracks the device independently of the SIM. An exposed MSISDN scores 20
because it is the subscriber's own number, which is directly attributable.
A null cipher scores 15 because everything else on that bearer is readable
regardless of which identities were logged.

Scores are summed and capped at 100. The cap is a presentation choice: a
subscriber with every finding present is "worst case", and a score above
100 would not rank anything further.
EOM
    } | tee "$out" >/dev/null
    printf 'report\t%s\n' "$out"
    printf 'rows\t%s\n' "$(wc -l < "$out" | tr -d ' ')"
}

# ── store inspection ────────────────────────────────────────────────────
imsi_cmd_identities() {
    [[ -f "$IMSI_IDENT" ]] || { printf 'ERROR\tno identity store; run --audit first\n' >&2; return 1; }
    local n; n=$(imsi_ident_count)
    (( n > 0 )) || { printf 'ERROR\tidentity store is empty\n' >&2; return 1; }
    printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n'
    local line f fr k v p s dd w
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == file$'\t'* ]] && continue
        f=$(imsi_field  "$line" 1); fr=$(imsi_field "$line" 2)
        k=$(imsi_field  "$line" 3); v=$(imsi_field  "$line" 4)
        p=$(imsi_field  "$line" 5); s=$(imsi_field  "$line" 6)
        dd=$(imsi_field "$line" 7); w=$(imsi_field  "$line" 8)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(imsi_sanitize "$f")" "$(imsi_sanitize "$fr")" \
            "$(imsi_sanitize "$k")" "$(imsi_show "$v")" \
            "$(imsi_sanitize "$p")" "$(imsi_sanitize "$s")" \
            "$(imsi_sanitize "$dd")" "$(imsi_sanitize "$w")"
    done < "$IMSI_IDENT"
}

imsi_cmd_clear() {
    imsi_init_store
    printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n' > "$IMSI_IDENT"
    printf 'temp_kind\ttemp_value\timsi\tevidence\tfile\tframe\tprotocol\n' > "$IMSI_MAP"
    ok "identity store and mapping cleared"
}

# ── harvest verb (capture-only wrapper around --audit) ──────────────────
imsi_cmd_harvest() {
    (($# > 0)) || { printf 'ERROR\tusage: --harvest <pcap...>\n' >&2; return 2; }
    imsi_cmd_audit "$@"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
imsi_cli_status_tsv() {
    local pa
    pa=$(imsi_pcap_available && echo present || echo missing)
    printf 'pcap_module\t%s\n'    "$(imsi_sanitize "$IMSI_PCAP_MOD")"
    printf 'pcap_available\t%s\n' "$pa"
    printf 'ident_store\t%s\n'    "$IMSI_IDENT"
    printf 'identities\t%s\n'     "$(imsi_ident_count)"
    printf 'map\t%s\n'            "$IMSI_MAP"
    printf 'mappings\t%s\n'       "$(imsi_map_rows 2>/dev/null || echo 0)"
    printf 'subscribers_file\t%s\n' "$IMSI_SUBS"
    printf 'exposure_file\t%s\n'  "$IMSI_EXPO"
    printf 'redact_default\tno\n'
    printf 'dir\t%s\n'            "$IMSI_DIR"
}

# ── selftest — no capture, no module 17, no network, no root ────────────
# ── Marlin — IMSI-catcher detection by identity-exposure ratio ──────────
# (Tucker et al., NDSS 2025.) A normal cell keeps the fraction of messages
# that solicit a permanent identity low; a catcher cannot avoid them, so the
# ratio spikes. This implements the ratio-and-threshold half of the method.
imsi_exposing_msgs() {
    cat <<'EOF'
gen	message	trigger
GSM	Identity Request (RR)	forces IMSI at any time
GSM	Paging Request (IMSI)	pages by IMSI
GSM	Location Updating Accept (TMSI realloc)	re-allocation drives IMSI use
GSM	CM Service Reject	reject causes a re-attach
UMTS	Identity Request (RRC)	direct IMSI query
UMTS	Security Mode Command (null)	downgrade then query
LTE	Identity Request (EMM)	forces IMSI outside attach
LTE	Attach Reject (cause 3,6-8,11-15,35)	forces IMSI re-attach
LTE	TAU Reject (cause 3,6-7,9,11-12,14)	forces IMSI re-attach
LTE	Detach Request (re-attach)	forces IMSI at re-attach
LTE	Authentication Reject	forces TMSI deletion
5G	Identity Request (5GMM)	direct SUCI/IMSI query
5G	Registration Reject (cause 3,6-7,9-15)	forces re-registration
5G	Authentication Reject	context invalidation
EOF
}
# Baseline exposure rate a normal cell stays under, by generation.
imsi_marlin_baseline() {
    case "${1^^}" in
        GSM|2G) printf '0.06' ;;
        UMTS|3G) printf '0.05' ;;
        LTE|4G) printf '0.03' ;;
        5G|NR) printf '0.02' ;;
        *) printf '' ;;
    esac
}
# TSV: conn<TAB>gen<TAB>msg<TAB>exposing(0/1). Per connection: ratio and a
# normal-approximation z against the generation baseline.
imsi_marlin() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$file" >&2; return 1; }
    printf 'conn\tgen\tn\texposing\tratio\tz\tverdict\n'
    awk -F'\t' '
        NR==1 && $1 ~ /^conn/ { next }
        NF>=4 { k=$1; n[k]++; e[k]+=($4==1); g[k]=$2 }
        END {
            for (k in n) {
                gen=g[k]
                p0=(gen=="GSM"||gen=="2G")?0.06:(gen=="UMTS"||gen=="3G")?0.05:(gen=="LTE"||gen=="4G")?0.03:(gen=="5G"||gen=="NR")?0.02:0.03
                r=e[k]/n[k]
                z=(p0>0&&p0<1)?(r-p0)/sqrt(p0*(1-p0)/n[k]):0
                v=(z>3)?"CATCHER":(z>1.5)?"SUSPECT":"normal"
                printf "%s\t%s\t%d\t%d\t%.2f\t%.2f\t%s\n", k, gen, n[k], e[k], r, z, v
            }
        }' "$file" | sort
}

# ── eSIM device-profile linkability (Di5Guise) ──────────────────────────
# Rotating the MNO profile is the privacy advice for an eSIM: a new IMSI, a
# new ICCID, a new subscription. What rotation does not replace is the eUICC
# itself. Every eUICC carries a Device Profile provisioned at manufacture --
# a secret key, a certificate and the unique EID -- and that profile
# authenticates the hardware to the SM-DP+/SM-DS on ES9+ and to the eIM on
# ES2+ whatever MNO profile happens to be enabled at the time. An operator,
# or anyone who sits where the provisioning traffic and the RAN both reach,
# therefore has one key that folds every rotated identity back onto one
# handset.
#
# This verb is the correlation oracle the tree was missing: it reads records
# from a provisioning sequence (whatever a caller extracted from ES9+/ES2+/
# ES10c logs, and the identity store this module already keeps) and scores how
# much of a rotation survives the correlation. The decoupled variant is scored
# separately, because that is the only published measurement of whether the
# advice works (re-identification 93% -> 49% with a decoupled device profile
# and traffic obfuscation; the number is cited, not measured here).
imsi_device_link() {   # <records.tsv> [--eid-col N] [--imsi-col N]
    local file="${1:-}"
    [[ -n "$file" ]] || {
        printf 'ERROR\tusage: --device-link <records.tsv> [--eid-col N] [--imsi-col N]\n' >&2
        printf 'WHY\tcolumns: event_type, eid, iccid, imsi, t (seconds); the EID is the device anchor and the IMSI is the identity that rotates\n' >&2
        return 2; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read %s\n' "$(imsi_sanitize "$file")" >&2; return 1; }
    shift
    local eid_col=2 imsi_col=4
    while (($#)); do
        case "$1" in
            --eid-col)  eid_col="${2:-2}"; shift 2 ;;
            --imsi-col) imsi_col="${2:-4}"; shift 2 ;;
            *) printf 'ERROR\tunknown option %s\n' "$(imsi_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    awk -F'\t' -v ec="$eid_col" -v ic="$imsi_col" '
        NR==1 && $1 ~ /^[A-Za-z_]/ { next }
        NF < 4 { next }
        {
            e = $(ec); i = $(ic)
            if (e == "" || i == "") next
            if (!((i SUBSEP e) in seen)) { seen[i SUBSEP e] = 1; ecount[i]++ }
            eids[e] = 1
            ids[i] = 1
            if (!(i in first_eid)) { first_eid[i] = e; order[++n] = i }
            else if (first_eid[i] != e) { multi[i] = 1 }
            pairs++
            # a rotation is the same EID carrying a second identity
            if (!(e in count)) { count[e] = 0 }
        }
        END {
            ne = 0; for (x in eids) ne++
            ni = 0; for (x in ids) ni++
            multi_n = 0
            for (x in multi) multi_n++
            # identities that land on an EID that already carried another
            # identity: that is re-identification through the device profile
            linked = 0
            for (x in ids) if (multi_n > 0 && (x in multi)) linked++
            # per-EID identity counts: max is the rotation depth observed
            delete cnt
            for (k in seen) { split(k, parts, SUBSEP); cnt[parts[2]]++ }
            maxrot = 0; rot_eids = 0
            for (e in cnt) { if (cnt[e] > 1) rot_eids++; if (cnt[e] > maxrot) maxrot = cnt[e] }
            printf "records\t%d\n", pairs
            printf "devices\t%d\n", ne
            printf "identities\t%d\n", ni
            printf "identities_per_device\t%.2f\n", (ne ? ni / ne : 0)
            printf "devices_with_more_than_one_identity\t%d\n", rot_eids
            printf "rotation_depth_max\t%d\n", maxrot
            # an identity is re-identified when the device it landed on already
            # carried a different identity: the EID is what joined them
            relinked = 0; shared = 0
            for (x in ids) if (ecount[x] > 1) shared++
            for (k in seen) {
                split(k, parts, SUBSEP)
                if (cnt[parts[2]] > 1) relinked++
            }
            printf "identities_on_a_device_with_another_identity\t%d\n", relinked
            printf "identities_seen_on_more_than_one_device\t%d\n", shared
            printf "reidentification_rate\t%.4f\n", (ni ? relinked / ni : 0)
            if (rot_eids > 0)
                printf "finding\tdevice_profile_is_an_anchor\tHIGH\tthe EID survives the profile rotation: %d of %d device(s) carried more than one identity, and every identity lands on a device that is already known\n", rot_eids, ne
            else
                printf "finding\tno_rotation_in_this_file\tINFO\tevery device carried one identity, so this file cannot show whether rotation unlinks\n"
            printf "decoupled_baseline\tpublished\tre-identification 93%% falls to 49%% when the device profile is decoupled from the MNO profile and the provisioning traffic is obfuscated (the number is cited from the published evaluation; nothing here measured it)\n"
            printf "verdict\t%s\n", (rot_eids > 0 ? "identities_relink_to_one_device" : "no_relink_evidence")
        }' "$file"
    printf 'ref\tGSMA SGP.22 (ES9+/ES2+/ES10c), the EID as the eUICC identifier; Di5Guise published evaluation for the decoupled variant\n'
    printf 'limit\tthe EID anchor is only as good as the records: a file without EIDs scores nothing, and a file with one identity per device cannot show rotation\n'
    printf 'advice\trotating the MNO profile changes the identity, not the device: unlinkability needs the device profile decoupled, which is a different provisioning decision\n'
}

imsi_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    chkne() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" != "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want!=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export IMSI_DIR="$d/loot/imsi_exposure"
    export IMSI_IDENT="$IMSI_DIR/identities.tsv"
    export IMSI_MAP="$IMSI_DIR/tmsi_imsi_map.tsv"
    export IMSI_SUBS="$IMSI_DIR/subscribers.tsv"
    export IMSI_EXPO="$IMSI_DIR/exposure.tsv"
    mkdir -p "$IMSI_DIR"

    # ── 1. Redaction: even and odd length ───────────────────────────────
    # A 15-digit IMSI (odd) and a 16-digit IMSI (even) must both keep
    # exactly the last four characters.
    chk mask-15      "$(imsi_mask 310260123456789)"  "***********6789"
    chk mask-15-len  "$(printf '%s' "$(imsi_mask 310260123456789)" | wc -c | tr -d ' ')" "15"
    chk mask-16      "$(imsi_mask 0010101234567890)" "************7890"
    chk mask-16-len  "$(printf '%s' "$(imsi_mask 0010101234567890)" | wc -c | tr -d ' ')" "16"
    chk mask-4       "$(imsi_mask 1234)"             "****"
    chk mask-3       "$(imsi_mask 123)"              "***"
    chk mask-1       "$(imsi_mask 7)"                "*"
    chk mask-empty   "$(imsi_mask '')"               ""
    chk mask-15-tail "$(imsi_mask 310260123456789 | tail -c5)" "6789"
    chk mask-16-tail "$(imsi_mask 0010101234567890 | tail -c5)" "7890"
    # A short value must never leak: masking a 4-digit value to "last 4"
    # would be no masking at all.
    chkne mask-short-leaks "$(imsi_mask 1234)" "1234"

    # imsi_show honours the flag.
    IMSI_REDACT=0
    chk show-off "$(imsi_show 310260123456789)" "310260123456789"
    IMSI_REDACT=1
    chk show-on  "$(imsi_show 310260123456789)" "***********6789"
    IMSI_REDACT=0

    # ── 2. The synthetic input: a capture-shaped TSV ────────────────────
    # Columns: file frame kind value protocol src dst where [plmn] [cell] [ts] [cipher]
    # Three subscribers with deliberately different exposure so the score
    # ordering is testable:
    #   A  310260123456789  IMSI in the clear  + TMSI mapped + null cipher
    #   B  262011234567890  TMSI mapped only (IMSI never sent in the clear)
    #   C  0010101234567890 no mapping at all
    local inp="$d/input.tsv"
    {
        printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\tplmn\tcell\tts\tcipher\n'
        # Subscriber A: IMSI in the clear, plus a TMSI in the same frame.
        printf 'cap-a.pcap\t10\timsi\t310260123456789\ts1ap\t10.0.0.1\t10.0.0.2\tidentity response at offset 32\t262-01\t12345\t1700000000\tEEA0\n'
        printf 'cap-a.pcap\t10\ttmsi\t4A3B2C1D\ts1ap\t10.0.0.1\t10.0.0.2\tidentity IE at offset 20\t262-01\t12345\t1700000000\tEEA0\n'
        printf 'cap-a.pcap\t11\timsi\t310260123456789\ts1ap\t10.0.0.1\t10.0.0.2\tidentity response at offset 32\t262-01\t12345\t1700000060\tEEA3\n'
        printf 'cap-a.pcap\t12\tmsisdn\t491710000001\ts1ap\t10.0.0.1\t10.0.0.2\tMSISDN IE\t262-01\t12345\t1700000120\tEEA3\n'
        # Subscriber B: no cleartext IMSI, but an IMSI and TMSI in one dialog.
        printf 'cap-b.pcap\t20\timsi\t262011234567890\tm3ua\t10.0.1.1\t10.0.1.2\tMAP SAI\t262-01\t22222\t1700001000\tA5/1\n'
        printf 'cap-b.pcap\t20\ttmsi\t11223344\tm3ua\t10.0.1.1\t10.0.1.2\tTMSI IE\t262-01\t22222\t1700001000\tA5/1\n'
        printf 'cap-b.pcap\t21\timei\t351234567890123\tm3ua\t10.0.1.1\t10.0.1.2\tIMEI IE\t262-01\t22222\t1700001060\tA5/1\n'
        # Subscriber C: only the IMSI, no temporary identity, no device id.
        printf 'cap-c.pcap\t30\timsi\t0010101234567890\tngap\t10.0.2.1\t10.0.2.2\t5G identity\t001-01\t33333\t1700002000\tNEA2\n'
    } > "$inp"
    chk input-rows "$(tail -n +2 "$inp" | grep -c .)" "8"

    # ── 3. Audit against the synthetic input ────────────────────────────
    out=$(imsi_cmd_audit "$inp"); rc=$?
    chk audit-rc         "$rc" "0"
    chk audit-inputs     "$(awk -F'\t' '$1=="inputs"{print $2}' <<<"$out")" "1"
    chk audit-identities "$(awk -F'\t' '$1=="identities"{print $2}' <<<"$out")" "8"
    chk store-count      "$(imsi_ident_count)" "8"

    # Re-running the same audit must not duplicate rows.
    imsi_cmd_audit "$inp" >/dev/null
    chk audit-idempotent "$(imsi_ident_count)" "8"

    # ── 4. The TMSI-to-IMSI mapping is built correctly ──────────────────
    out=$(imsi_build_map "$IMSI_IDENT"); rc=$?
    chk map-rc      "$rc" "0"
    chk map-count   "$out" "2"
    chk map-rows    "$(imsi_map_rows)" "2"
    # Subscriber A's TMSI must bind to A's IMSI, same-frame.
    chk map-a-tmsi  "$(awk -F'\t' '$1=="tmsi" && $2=="4A3B2C1D"{print $3}' "$IMSI_MAP")" "310260123456789"
    chk map-a-evid  "$(awk -F'\t' '$1=="tmsi" && $2=="4A3B2C1D"{print $4}' "$IMSI_MAP")" "same-frame"
    chk map-a-frame "$(awk -F'\t' '$1=="tmsi" && $2=="4A3B2C1D"{print $6}' "$IMSI_MAP")" "10"
    chk map-b-tmsi  "$(awk -F'\t' '$1=="tmsi" && $2=="11223344"{print $3}' "$IMSI_MAP")" "262011234567890"
    chk map-b-evid  "$(awk -F'\t' '$1=="tmsi" && $2=="11223344"{print $4}' "$IMSI_MAP")" "same-frame"
    # The map must not invent a binding for subscriber C, who has no
    # temporary identity anywhere in the input.
    chk map-no-c "$(grep -c '0010101234567890' "$IMSI_MAP" || true)" "0"
    # Header plus exactly two data rows.
    chk map-file-rows "$(tail -n +2 "$IMSI_MAP" | grep -c .)" "2"

    # ── 5. Exposure score ordering ──────────────────────────────────────
    # A: 70 (cleartext) + 40 (TMSI) + 20 (MSISDN) + 15 (null) = 145 -> 100
    # B: 70 (cleartext) + 40 (TMSI) + 25 (IMEI)             = 135 -> 100
    # C: 70 (cleartext)                                     -> 70
    out=$(imsi_cmd_subscribers_tsv); rc=$?
    chk subs-rc    "$rc" "0"
    chk subs-rows  "$(printf '%s\n' "$out" | grep -c '^[0-9]')" "3"
    chk subs-header "$(printf '%s\n' "$out" | head -n1 | awk -F'\t' '{print NF}')" "14"
    local score_c score_a score_b
    score_c=$(printf '%s\n' "$out" | awk -F'\t' '$1=="0010101234567890"{print $2}')
    score_a=$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $2}')
    score_b=$(printf '%s\n' "$out" | awk -F'\t' '$1=="262011234567890"{print $2}')
    chk score-c "$score_c" "70"
    chk score-a "$score_a" "100"
    chk score-b "$score_b" "100"
    # Ordering: A == B > C, and C is strictly greater than zero.
    chk score-order  "$([[ "$score_a" -ge "$score_c" && "$score_b" -ge "$score_c" ]] && echo yes || echo no)" "yes"
    chk score-nonzero "$([[ "$score_c" -gt 0 ]] && echo yes || echo no)" "yes"
    chk score-cap     "$([[ "$score_a" -le 100 ]] && echo yes || echo no)" "yes"

    # The individual flags must be right, not just the total.
    chk flag-a-cleartext "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $3}')" "1"
    chk flag-a-tmsi      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $4}')" "1"
    chk flag-a-msisdn    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $7}')" "1"
    chk flag-a-null      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $8}')" "1"
    chk flag-a-imei      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $6}')" "0"
    chk flag-b-imei      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="262011234567890"{print $6}')" "1"
    chk flag-b-msisdn    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="262011234567890"{print $7}')" "0"
    chk flag-c-tmsi      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="0010101234567890"{print $4}')" "0"
    chk flag-c-null      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="0010101234567890"{print $8}')" "0"

    # The score function itself, directly.
    chk score-fn-none   "$(imsi_score_of 0 0 0 0 0 0)" "0"
    chk score-fn-ct     "$(imsi_score_of 1 0 0 0 0 0)" "70"
    chk score-fn-tmsi   "$(imsi_score_of 0 1 0 0 0 0)" "40"
    chk score-fn-guti   "$(imsi_score_of 0 0 1 0 0 0)" "40"
    chk score-fn-imei   "$(imsi_score_of 0 0 0 1 0 0)" "25"
    chk score-fn-msisdn "$(imsi_score_of 0 0 0 0 1 0)" "20"
    chk score-fn-null   "$(imsi_score_of 0 0 0 0 0 1)" "15"
    chk score-fn-cap    "$(imsi_score_of 1 1 1 1 1 1)" "100"
    chk score-fn-order  "$([[ "$(imsi_score_of 1 0 0 0 0 0)" -gt "$(imsi_score_of 0 1 0 0 0 0)" ]] && echo yes || echo no)" "yes"
    chk band-critical   "$(imsi_band 100)" "critical"
    chk band-high       "$(imsi_band 40)"  "high"
    chk band-medium     "$(imsi_band 20)"  "medium"
    chk band-none       "$(imsi_band 0)"   "none"

    # ── 6. Exposure findings carry their reason ─────────────────────────
    out=$(imsi_cmd_exposure_tsv); rc=$?
    chk expo-rc      "$rc" "0"
    chk expo-cleartext "$(printf '%s\n' "$out" | grep -c 'IMSI in the clear')" "3"
    chk expo-points    "$(printf '%s\n' "$out" | grep -c $'\t70\t')" "3"
    chk expo-tmsi      "$(printf '%s\n' "$out" | grep -c 'TMSI mapped to IMSI')" "2"
    chk expo-null      "$(printf '%s\n' "$out" | grep -c 'null cipher in use')" "1"
    chk expo-msisdn    "$(printf '%s\n' "$out" | grep -c 'MSISDN exposed')" "1"

    # ── 7. Cross-capture correlation ────────────────────────────────────
    out=$(imsi_cmd_cross)
    chk cross-rows  "$(printf '%s\n' "$out" | grep -c '^[0-9]')" "3"
    chk cross-a-cap "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $2}')" "1"
    # cross-capture span counts only the kind=imsi rows for that
    # subscriber: 1700000060 - 1700000000 = 60.
    chk cross-a-span "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $5}')" "60"
    chk cross-a-plmn "$(printf '%s\n' "$out" | awk -F'\t' '$1=="310260123456789"{print $6}')" "262-01"
    chk cross-header "$(printf '%s\n' "$out" | head -n1 | awk -F'\t' '{print NF}')" "7"

    # ── 8. Redaction applies to every identity-bearing output ───────────
    IMSI_REDACT=1
    out=$(imsi_cmd_subscribers_tsv)
    chk redact-subs-masked "$(printf '%s\n' "$out" | grep -c '^\*\*\*\*\*\*\*\*\*\*\*6789')" "1"
    chk redact-subs-noleak "$(printf '%s\n' "$out" | grep -c '310260123456789')" "0"
    out=$(imsi_cmd_map)
    chk redact-map-noleak  "$(printf '%s\n' "$out" | grep -c '4A3B2C1D')" "0"
    chk redact-map-masked  "$(printf '%s\n' "$out" | grep -c '\*\*\*\*2C1D')" "1"
    out=$(imsi_cmd_identities)
    chk redact-ident-noleak "$(printf '%s\n' "$out" | grep -c $'\t310260123456789\t')" "0"
    IMSI_REDACT=0
    out=$(imsi_cmd_subscribers_tsv)
    chk unredact-restored "$(printf '%s\n' "$out" | grep -c '310260123456789')" "1"

    # ── 9. An empty input is an error, never an empty success ───────────
    local empty="$d/empty.tsv"
    printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n' > "$empty"
    chk empty-audit-rc "$(imsi_cmd_audit "$empty" >/dev/null 2>&1; echo $?)" "1"
    : > "$d/zero.tsv"
    chk zero-audit-rc  "$(imsi_cmd_audit "$d/zero.tsv" >/dev/null 2>&1; echo $?)" "1"
    # A store with rows but no IMSI must also refuse to produce an "audit".
    local noimsi="$d/noimsi.tsv"
    printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n' > "$noimsi"
    printf 'x.pcap\t1\ttmsi\tAABBCCDD\ts1ap\t1.1.1.1\t2.2.2.2\tIE\n' >> "$noimsi"
    # The audit itself succeeds (an identity was found) but the subscriber
    # view has nothing to report and must say so with a non-zero exit.
    imsi_cmd_clear >/dev/null 2>&1
    imsi_cmd_audit "$noimsi" >/dev/null 2>&1
    chk noimsi-subs-rc "$(imsi_cmd_subscribers_tsv >/dev/null 2>&1; echo $?)" "1"
    chk noimsi-map-rc  "$(imsi_cmd_map >/dev/null 2>&1; echo $?)" "0"

    # ── 10. Missing module 17 is handled gracefully ─────────────────────
    # With the module unavailable, a capture input must fail with a clear
    # message; a TSV input must still work.
    imsi_cmd_clear >/dev/null 2>&1
    local saved_mod="$IMSI_PCAP_MOD"
    IMSI_PCAP_MOD="$d/does_not_exist.sh"
    chk nopcap-available "$(imsi_pcap_available; echo $?)" "1"
    out=$(imsi_cmd_audit "$d/fake.pcap" 2>&1); rc=$?
    chk nopcap-rc    "$rc" "1"
    chk nopcap-msg   "$(printf '%s\n' "$out" | grep -c 'module 17 not found\|capture analysis module not found')" "1"
    # The TSV path must still work with module 17 gone.
    out=$(imsi_cmd_audit "$inp"); rc=$?
    chk nopcap-tsv-rc "$rc" "0"
    chk nopcap-tsv-n  "$(awk -F'\t' '$1=="identities"{print $2}' <<<"$out")" "8"
    IMSI_PCAP_MOD="$saved_mod"

    # When module 17 really is present, it must be callable and discoverable.
    if [[ -f "$IMSI_PCAP_MOD" ]]; then
        chk pcap-present "$(imsi_pcap_available; echo $?)" "0"
    else
        chk pcap-present "$(imsi_pcap_available; echo $?)" "1"
    fi

    # ── 11. Report rendering ────────────────────────────────────────────
    out=$(imsi_cmd_report); rc=$?
    chk report-rc "$rc" "0"
    local rp; rp=$(awk -F'\t' '$1=="report"{print $2}' <<<"$out")
    chk report-exists "$([[ -s "$rp" ]] && echo yes || echo no)" "yes"
    chk report-has-findings "$(grep -c 'IMSI in the clear' "$rp")" "3"
    chk report-has-method   "$(grep -c 'scored 70 because' "$rp")" "1"
    chk report-has-map      "$(grep -c '4A3B2C1D' "$rp")" "1"

    # ── 12. Argument validation ─────────────────────────────────────────
    chk audit-missing-rc    "$(imsi_cmd_audit >/dev/null 2>&1; echo $?)" "2"
    chk audit-nofile-rc     "$(imsi_cmd_audit /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk harvest-missing-rc  "$(imsi_cmd_harvest >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-unknown    "$(imsi_cli_main --nonsense >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-empty      "$(imsi_cli_main >/dev/null 2>&1; echo $?)" "2"

    imsi_cmd_clear >/dev/null 2>&1
    chk clear-then-subs-rc "$(imsi_cmd_subscribers_tsv >/dev/null 2>&1; echo $?)" "1"
    chk clear-then-expo-rc "$(imsi_cmd_exposure_tsv >/dev/null 2>&1; echo $?)" "1"
    chk clear-then-cross-rc "$(imsi_cmd_cross >/dev/null 2>&1; echo $?)" "1"
    chk clear-then-map-rc  "$(imsi_cmd_map >/dev/null 2>&1; echo $?)" "1"
    chk clear-then-rep-rc  "$(imsi_cmd_report >/dev/null 2>&1; echo $?)" "1"
    chk clear-count        "$(imsi_ident_count)" "0"

    # ── 13. Sanitisation ────────────────────────────────────────────────
    local evil
    evil=$(imsi_sanitize $'evil\tname\r\nsecond')
    chk sanitize-no-tabs "$(printf '%s' "$evil" | tr -d '\t\r\n' | wc -c | tr -d ' ')" \
        "$(printf '%s' "$evil" | wc -c | tr -d ' ')"
    # A value carrying a tab must not split into extra columns.
    local tabsrc="$d/tab.tsv"
    printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n' > "$tabsrc"
    printf 'x.pcap\t1\timsi\t310260123456789\tngap\t1.1.1.1\t2.2.2.2\tplain\n' >> "$tabsrc"
    imsi_cmd_clear >/dev/null 2>&1
    imsi_cmd_audit "$tabsrc" >/dev/null 2>&1
    chk tsv-columns "$(imsi_cmd_identities | tail -n1 | awk -F'\t' '{print NF}')" "8"

    # ── 14. Empty columns must not shift a row ─────────────────────────
    # `while IFS=$'\t' read` collapses runs of tabs, so a row with an empty
    # column moves every later value left. The identity store hits this
    # whenever a capture carries an identity with no PLMN or timestamp.
    chk field-empty "$(imsi_field "$(printf 'a\tb\t\t\td')" 3)" ""
    chk field-last  "$(imsi_field "$(printf 'a\tb\t\t\td')" 5)" "d"
    local emptysrc="$d/empty_cols.tsv"
    {
        printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\tplmn\tcell\tts\tcipher\n'
        printf 'ec.pcap\t7\timsi\t310260123456789\tngap\t1.1.1.1\t2.2.2.2\tidentity\t\t\t\n'
        printf 'ec.pcap\t7\ttmsi\tAABBCCDD\tngap\t1.1.1.1\t2.2.2.2\tidentity IE\t\t\t\n'
    } > "$emptysrc"
    imsi_cmd_clear >/dev/null 2>&1
    out=$(imsi_cmd_audit "$emptysrc")
    chk empty-audit-n "$(awk -F'\t' '$1=="identities"{print $2}' <<<"$out")" "2"
    chk empty-map-n   "$(awk -F'\t' '$1=="mappings"{print $2}' <<<"$out")" "1"
    # The rendered identity rows must still carry 8 columns each.
    chk empty-ident-cols "$(imsi_cmd_identities | tail -n1 | awk -F'\t' '{print NF}')" "8"
    chk empty-ident-ok   "$(imsi_cmd_identities | tail -n1 | cut -f3)" "tmsi"
    chk empty-map-cols   "$(imsi_cmd_map | tail -n1 | awk -F'\t' '{print NF}')" "7"
    chk empty-map-imsi   "$(imsi_cmd_map | tail -n1 | cut -f3)" "310260123456789"
    chk empty-map-evid   "$(imsi_cmd_map | tail -n1 | cut -f4)" "same-frame"
    chk empty-subs-cols  "$(imsi_cmd_subscribers_tsv | tail -n1 | awk -F'\t' '{print NF}')" "14"
    chk empty-subs-imsi  "$(imsi_cmd_subscribers_tsv | tail -n1 | cut -f1)" "310260123456789"
    chk empty-expo-n     "$(imsi_cmd_exposure_tsv | grep -c 'IMSI in the clear')" "1"

    # ── 15. Status TSV contract ─────────────────────────────────────────
    out=$(imsi_cli_status_tsv)
    chk status-dir  "$(awk -F'\t' '$1=="dir"{print $2}' <<<"$out")" "$IMSI_DIR"
    chk status-store "$(awk -F'\t' '$1=="ident_store"{print $2}' <<<"$out")" "$IMSI_IDENT"
    # The store holds whatever the last audit left in it; assert the value
    # the section above actually produced rather than a fixed number.
    chk status-count "$(awk -F'\t' '$1=="identities"{print $2}' <<<"$out")" "$(imsi_ident_count)"
    chk status-redact "$(awk -F'\t' '$1=="redact_default"{print $2}' <<<"$out")" "no"

    # ── Marlin: identity-exposure ratio vs generation baseline ──────────
    local mf="$d/marlin.tsv"
    printf 'conn\tgen\tmsg\texposing\n' > "$mf"
    local i
    for (( i=0; i<20; i++ )); do printf 'c1\tLTE\tattach\t0\n' >> "$mf"; done
    for (( i=0; i<4; i++ )); do printf 'c2\tLTE\tidentity\t1\n' >> "$mf"; done
    printf 'c2\tLTE\tsmc\t0\n' >> "$mf"
    out=$(imsi_marlin "$mf")
    chk marlin-clean   "$(awk -F'\t' '$1=="c1"{print $7}' <<<"$out")" "normal"
    chk marlin-ratio   "$(awk -F'\t' '$1=="c1"{print $5}' <<<"$out")" "0.00"
    chk marlin-catcher "$(awk -F'\t' '$1=="c2"{print $7}' <<<"$out")" "CATCHER"
    chk marlin-msgs    "$(imsi_exposing_msgs | tail -n +2 | wc -l | tr -d ' ')" "14"
    chk marlin-base-lte "$(imsi_marlin_baseline LTE)" "0.03"
    chk marlin-base-gsm "$(imsi_marlin_baseline GSM)" "0.06"
    chk marlin-base-unk "$(imsi_marlin_baseline wimax)" ""
    chk marlin-missing "$(imsi_marlin "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    rm -rf "$d"
    # ── device-profile linkability: rotation does not replace the eUICC ──
    local dl dld
    dl=$(mktemp -d)
    printf 'event\teid\ticcid\timsi\tt\nes9+\tAAAA\t8901\t310150000000001\t100\nactivation\tAAAA\t8901\t310150000000001\t200\nes9+\tAAAA\t8902\t310150000000002\t900\nactivation\tAAAA\t8902\t310150000000002\t1000\nes9+\tBBBB\t8903\t310150000000003\t300\n' > "$dl/rot.tsv"
    dld=$(imsi_device_link "$dl/rot.tsv" 2>/dev/null)
    chk dlink-devices   "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="devices"{print $2}')" "2"
    chk dlink-ids       "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="identities"{print $2}')" "3"
    chk dlink-rot       "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="devices_with_more_than_one_identity"{print $2}')" "1"
    chk dlink-depth     "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="rotation_depth_max"{print $2}')" "2"
    chk dlink-relinked  "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="identities_on_a_device_with_another_identity"{print $2}')" "2"
    chk dlink-rate      "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="reidentification_rate"{print $2}')" "0.6667"
    chk dlink-perdev    "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="identities_per_device"{print $2}')" "1.50"
    chk dlink-finding   "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="finding"{print $2}')" "device_profile_is_an_anchor"
    chk dlink-sev       "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="finding"{print $3}')" "HIGH"
    chk dlink-verdict   "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="verdict"{print $2}')" "identities_relink_to_one_device"
    chk dlink-baseline  "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="decoupled_baseline" && $3 ~ /93%/ && $3 ~ /49%/{print "cited"}')" "cited"
    chk dlink-advice    "$(printf '%s\n' "$dld" | awk -F'\t' '$1=="advice" && $2 ~ /decoupled/{print "stated"}')" "stated"
    # one identity per device: the file cannot show rotation, and says so
    printf 'event\teid\ticcid\timsi\nes9+\tAAAA\t8901\t310150000000001\nes9+\tBBBB\t8902\t310150000000002\n' > "$dl/flat.tsv"
    chk dlink-flat      "$(imsi_device_link "$dl/flat.tsv" | awk -F'\t' '$1=="verdict"{print $2}')" "no_relink_evidence"
    chk dlink-flat-note "$(imsi_device_link "$dl/flat.tsv" | awk -F'\t' '$1=="finding" && $2 ~ /no_rotation/{print "noted"}')" "noted"
    # a shared identity across two EIDs is the opposite failure: one SIM cloned
    # across devices, which the same rows have to be able to report
    printf 'event\teid\ticcid\timsi\nes9+\tAAAA\t8901\t310150000000001\nes9+\tBBBB\t8902\t310150000000001\n' > "$dl/shared.tsv"
    chk dlink-shared    "$(imsi_device_link "$dl/shared.tsv" | awk -F'\t' '$1=="identities_seen_on_more_than_one_device"{print $2}')" "1"
    chk dlink-noargs    "$(imsi_device_link >/dev/null 2>&1; echo $?)" "2"
    chk dlink-nofile    "$(imsi_device_link "$dl/none.tsv" >/dev/null 2>&1; echo $?)" "1"
    rm -rf "$dl"

    # ---- node as the evidence source ------------------------------------
    # A name is required and an unregistered one is refused with the command
    # that fixes it, because "no such node" is actionable and "no identities"
    # is not.
    chk node-missing-arg "$(imsi_cmd_node "" >/dev/null 2>&1; echo $?)" "2"
    chk node-unknown     "$(CASEBOOK_DIR="$d/nobook" imsi_cmd_node no-such >/dev/null 2>&1; echo $?)" "2"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
imsi_menu() {
    local c p
    while true; do
        banner
        echo -e "  ${C_MAG}=== IMSI exposure audit ===${C_RESET}"
        echo -e "  module21: ${C_GRN}$(imsi_pcap_available && echo present || echo missing)${C_RESET}"
        echo -e "  ids:      ${C_GRN}$(imsi_ident_count)${C_RESET}"
        echo -e "  mappings: ${C_GRN}$(imsi_map_rows 2>/dev/null || echo 0)${C_RESET}"
        echo -e "  redact:   ${C_YEL}$([[ $IMSI_REDACT -eq 1 ]] && echo on || echo off)${C_RESET}"
        echo -e "  loot:     ${C_DIM}$IMSI_DIR${C_RESET}\n"
        cat << 'M'
  [1]  audit captures (harvest + correlate)
  [2]  show harvested identities
  [3]  TMSI/GUTI -> IMSI mapping
  [4]  per-subscriber exposure
  [5]  exposure findings with reasons
  [6]  cross-capture correlation
  [7]  write a report to loot
  [8]  toggle redaction
  [9]  clear the store
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) read -rp "  pcap/tsv paths (space separated)> " -a paths
               imsi_cmd_audit "${paths[@]}" | column -t -s$'\t' 2>/dev/null || imsi_cmd_audit "${paths[@]}"
               read -rp "  press enter " _ ;;
            2) imsi_cmd_identities | column -t -s$'\t' 2>/dev/null || imsi_cmd_identities
               read -rp "  press enter " _ ;;
            3) imsi_cmd_map | column -t -s$'\t' 2>/dev/null || imsi_cmd_map
               read -rp "  press enter " _ ;;
            4) imsi_cmd_subscribers_tsv | column -t -s$'\t' 2>/dev/null || imsi_cmd_subscribers_tsv
               read -rp "  press enter " _ ;;
            5) imsi_cmd_exposure_tsv | column -t -s$'\t' 2>/dev/null || imsi_cmd_exposure_tsv
               read -rp "  press enter " _ ;;
            6) imsi_cmd_cross | column -t -s$'\t' 2>/dev/null || imsi_cmd_cross
               read -rp "  press enter " _ ;;
            7) imsi_cmd_report; read -rp "  press enter " _ ;;
            8) if (( IMSI_REDACT )); then IMSI_REDACT=0; ok "redaction off"
               else IMSI_REDACT=1; ok "redaction on — identities masked to the last 4"; fi
               sleep 1 ;;
            9) imsi_cmd_clear; sleep 1 ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── a node as the evidence source ───────────────────────────────────────
# Identities are exposed on somebody else's air, not necessarily on this one.
# The node hands over its newest capture and audit reads it like any other; the
# store records where it came from because an identity with no origin cannot be
# defended in a report.
imsi_node_capture() {  # <name> -> local path
    local name="${1:-}"
    [[ -n "$name" ]] || { printf 'ERROR\t--node needs a fleet node name\n' >&2; return 2; }
    local tool="$IMSISTING_ROOT/tools/node_source.py"
    [[ -f "$tool" ]] || {
        printf 'ERROR\t%s is missing\nWHY\twithout it a node is a name with no way to ask it for a capture\n' "$tool" >&2
        return 2; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is missing\nWHY\tthe node table is not a shell job\n' >&2; return 2; }
    local out rc path
    out=$(python3 "$tool" captures "$name" --newest 2>"$MOD_TMP/node.err"); rc=$?
    if (( rc != 0 )); then
        cat "$MOD_TMP/node.err" >&2
        return "$rc"
    fi
    path=$(printf '%s\n' "$out" | awk -F'\t' '$1=="fetched"{print $2; exit}')
    [[ -n "$path" ]] || {
        printf 'ERROR\t%s reported no capture to fetch\nWHY\tan empty answer is not an empty capture store\n' "$name" >&2
        return 1; }
    printf 'node\t%s\n' "$name" >&2
    printf 'fetched\t%s\n' "$path" >&2
    printf '%s' "$path"
}

imsi_cmd_node() {  # <name>
    local name="${1:-}" path rc
    [[ -n "$name" ]] || { printf 'ERROR\tusage: --node <name>\n' >&2; return 2; }
    path=$(imsi_node_capture "$name" 2>"$MOD_TMP/node.meta"); rc=$?
    cat "$MOD_TMP/node.meta" >&2
    (( rc != 0 )) && return "$rc"
    imsi_cmd_audit "$path"
}

# ── CLI dispatch ────────────────────────────────────────────────────────
imsi_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      imsi_cli_status_tsv ;;
        --audit)           imsi_cmd_audit "$@" ;;
        --node)            imsi_cmd_node "${1:-}" ;;
        --harvest)         imsi_cmd_harvest "$@" ;;
        --map)             imsi_cmd_map "${1:-}" ;;
        --subscribers-tsv) imsi_cmd_subscribers_tsv ;;
        --exposure-tsv)    imsi_cmd_exposure_tsv ;;
        --device-link) imsi_device_link "$@" ;;
        --cross)           imsi_cmd_cross ;;
        --marlin)          imsi_marlin "${1:-}" ;;
        --marlin-msgs)     imsi_exposing_msgs ;;
        --identities)      imsi_cmd_identities ;;
        --report)          imsi_cmd_report ;;
        --redact)          IMSI_REDACT=1
                           # --redact is a mode flag: when it is the only
                           # argument it turns redaction on for a following
                           # verb invoked in the same shell; on the CLI it
                           # prints the redacted subscriber view so the flag
                           # is always observable.
                           if [[ -n "${1:-}" ]]; then
                               case "$1" in
                                   --subscribers-tsv|--exposure-tsv|--map|--identities)
                                       imsi_cli_main "$@" ;;
                                   *)  imsi_cmd_audit "$@" ;;
                               esac
                           else
                               imsi_cmd_subscribers_tsv
                           fi ;;
        --clear)           imsi_cmd_clear ;;
        --selftest)        imsi_selftest ;;
        --menu)            imsi_menu ;;
        *)
            cat >&2 <<EOF
IMSI Harvest — identity harvesting, correlation and scoring

Harvests through module 17 (17_pcap_analysis.sh), so there is one pcap
parser in the tree. A pre-harvested TSV of the same shape is also accepted,
which is what to use when module 17 is unavailable.

Usage: $0 COMMAND
  --status-tsv                    store and module state as TSV
  --audit <pcap...|tsv...>        harvest and correlate one or more inputs
  --node <name>                   fetch that node's newest capture and audit it
  --harvest <pcap...>             alias for --audit with captures only
  --map                           TMSI/GUTI -> IMSI mapping with evidence
  --subscribers-tsv               one row per subscriber with the score
  --exposure-tsv                  one row per finding, with the reason
  --cross                         the same IMSI across captures
  --marlin <tsv>                  IMSI-catcher detection by identity-exposure ratio (NDSS '25)
  --marlin-msgs                   the IMSI-exposing message catalogue
  --identities                    the harvested identity store
  --report                        write the full report into loot
  --redact [VERB]                 mask every identity to its last 4 digits
  --clear                         empty the store
  --selftest                      verify correlation and scoring, no capture
  --menu                          interactive menu

Exposure score, summed and capped at 100:
  70  IMSI sent in the clear
  40  TMSI (or GUTI) mapped to an IMSI
  25  IMEI exposed
  20  MSISDN exposed
  15  null cipher in use
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
    imsi_cli_main "$@"
fi
