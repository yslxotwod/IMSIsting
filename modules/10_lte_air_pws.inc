# ───────────────────────────────────────────────────────────────────────
# PWS / ETWS / CMAS — SIB10, SIB11, SIB12 builders
#
# SOURCED, NOT EXECUTED. `modules/10_lte_air.sh` sources this file right
# after lair_decode_sib(); every line below is a function definition, so
# sourcing it prints nothing, runs nothing and touches no state.
#
# TS 36.331 §6.3.1 defines the three public-warning system information
# blocks, and this module already decoded them (lair_decode_sib10/11/12
# use the generated unaligned-PER table in tools/lte_rrc_layout.py). The
# encode side is the same table, so these verbs delegate to
# `tools/lte_asn1.py sib10|sib11|sib12` instead of hand-rolling bits. A
# second copy of the layout in shell is exactly the drift that made the old
# "SIB6 / SIB7 / SIB8 — ETWS and CMAS" block in this file wrong once
# already, and the delegation is differential-tested against pycrate by
# tools/lte-sib-oracle/handcheck_sib913.py.
#
# What each block carries (TS 36.331 §6.3.1):
#
#   SystemInformationBlockType10 — ETWS primary notification
#       messageIdentifier           BIT STRING (SIZE (16))
#       serialNumber                BIT STRING (SIZE (16))
#       warningType                 OCTET STRING (SIZE (2))
#       dummy                       OCTET STRING (SIZE (50)) OPTIONAL
#
#   SystemInformationBlockType11 — ETWS secondary notification
#       messageIdentifier, serialNumber
#       warningMessageSegmentType    ENUMERATED {notLastSegment, lastSegment}
#       warningMessageSegmentNumber  INTEGER (0..63)
#       warningMessageSegment        OCTET STRING
#       dataCodingScheme             OCTET STRING (SIZE (1)) OPTIONAL
#
#   SystemInformationBlockType12-r9 — CMAS notification: the same fields
#   with the -r9 suffixes Rel-9 gave them, plus the Rel-15 extension-group
#   field warningAreaCoordinatesSegment-r15 (OCTET STRING, OPTIONAL).
#
#   All three blocks carry lateNonCriticalExtension (OCTET STRING,
#   OPTIONAL) in their extension group: --late-non-critical sets it.
#
# Three things the verbs make visible instead of papering over:
#
#   * There is no warningSecurityInfo in SIB10. The 50-octet OPTIONAL field
#     is spelled `dummy` in the ASN.1, and that is the field a security
#     information blob would ride in — 50 octets is 400 bits, not the 48
#     bits the other spelling suggests. --security-info is refused by name
#     and --dummy takes the real field.
#
#   * The warning message segment count is not an RRC field. TS 36.331 has
#     a segment number and a last-segment flag and nothing else, so --count
#     is accepted for consistency checking only and the `fields` row says
#     count_encoded=no.
#
#   * The segment type has no `first`. A one-segment message is a
#     lastSegment and the opening segment of a longer one is a
#     notLastSegment, so the word is refused rather than mapped onto
#     whichever of the two looks closer.
#
#   * --segment is the segment CONTENTS and --segment-number is the segment
#     NUMBER. The ASN.1 names are warningMessageSegment (OCTET STRING) and
#     warningMessageSegmentNumber (INTEGER (0..63)); a --segment that took a
#     number would read like the contents it did not carry. --payload and
#     --payload-text remain as aliases for --segment.
#
#   * The Rel-9 SIB12 has no warning area field. The warning area coordinates
#     are an OCTET STRING segment that Rel-15 added to SIB12's extension group
#     (warningAreaCoordinatesSegment-r15), so --warning-area sets that
#     extension field and is refused by name on SIB11, which has no extension
#     group entry for it. The codec drops a key the type does not have, so
#     accepting the flag there would build a message that silently does not
#     carry it.
#
# A fourth verb, --enb-sib-schedule, answers "can this tree put a warning on
# air". It takes the body a --build-sib verb produced, writes the message
# octets next to enb.conf, and either emits the srsRAN sib.conf fragment that
# would broadcast it or refuses with what srsRAN is missing. It writes
# configuration; it does not transmit.
#
# The warning message contents themselves are TS 23.041 octets the caller
# supplies. These verbs build the RRC message that carries them; they do
# not synthesize a CMAS/ETWS body, and they transmit nothing.
# ───────────────────────────────────────────────────────────────────────

# ERROR<TAB>… plus an optional WHY<TAB>… on stderr. Returns 0 on purpose:
# call sites pick their own exit status, so a caller can never mistake a
# printed message for a failed verb.
lair_pws_err() {
    printf 'ERROR\t%s\n' "$1" >&2
    if [[ -n "${2:-}" ]]; then printf 'WHY\t%s\n' "$2" >&2; fi
    return 0
}

# The standing note every builder prints, in one place. It is the legal
# position this tree states for its emitters, and the reason `sent` is 0.
lair_pws_note() {
    printf 'note\tpublic-warning message octets for analysis and detection; transmitting a forged alert is illegal. nothing here transmits, which is why sent is 0\n'
}

# Decimal 0..65535, normalised without leading zeros for the JSON.
lair_pws_u16() {
    local v="${1:-}"
    [[ "$v" =~ ^[0-9]+$ ]] || return 1
    while [[ "$v" == 0?* ]]; do v="${v#0}"; done
    (( ${#v} <= 5 )) || return 1
    (( 10#$v <= 65535 )) || return 1
    printf '%s' "$v"
}

# Decimal 0..63: warningMessageSegmentNumber's own bound.
lair_pws_seg() {
    local v="${1:-}"
    [[ "$v" =~ ^[0-9]+$ ]] || return 1
    while [[ "$v" == 0?* ]]; do v="${v#0}"; done
    (( ${#v} <= 2 )) || return 1
    (( 10#$v <= 63 )) || return 1
    printf '%s' "$v"
}

# Uppercase hex, even digit count, at least one octet. Echoes the
# normalised form; returns 1 otherwise. An empty segment is refused here
# rather than encoded as a zero-length octet string: a warning message with
# no contents carries no warning.
lair_pws_hexoct() {
    local v="${1:-}"
    [[ "$v" =~ ^[0-9A-Fa-f]+$ ]] || return 1
    (( ${#v} % 2 == 0 )) || return 1
    printf '%s' "${v^^}"
}

# TS 36.331 §6.3.1: WarningMessageSegmentType ::= ENUMERATED
# {notLastSegment, lastSegment}. The last two spellings are the module's
# convenience aliases; nothing here invents a third state.
lair_pws_segtype() {
    case "${1:-}" in
        notLastSegment|notLast|0) printf '%s' notLastSegment ;;
        lastSegment|last|1)       printf '%s' lastSegment ;;
        *) return 1 ;;
    esac
}

# Build one body through the generated codec, print the contract rows, and
# optionally write the message octets to a file.
#   $1 SIB name (SIB10 / SIB11 / SIB12)
#   $2 codec subcommand (sib10 / sib11 / sib12)
#   $3 the value, as JSON for `lte_asn1.py --json`
#   $4 fields row body
#   $5 ref row body
#   $6 limit row body
#   $7 --out path, or empty
lair_pws_emit() {
    local sib="$1" stem="$2" json="$3" fields="$4" ref="$5" limit="$6"
    local out="${7:-}"
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"

    if [[ ! -r "$tool" ]]; then
        lair_pws_err "missing $tool" \
            "the PWS builders delegate to the generated TS 36.331 PER codec; a hand-rolled bit writer here would be a second copy of the layout"
        return 1
    fi
    command -v python3 >/dev/null 2>&1 || {
        lair_pws_err "python3 is not on PATH" "the PER codec runs on python3"
        return 1
    }

    local res rc bits hex
    res=$(python3 "$tool" "$stem" --json "$json" --body-only 2>&1)
    rc=$?
    if (( rc != 0 )); then
        # The codec owns the layout: its refusal is the verb's refusal, and
        # its own ERROR/WHY text is the one worth printing.
        printf '%s\n' "$res" >&2
        return 2
    fi
    bits=$(printf '%s\n' "$res" | awk -F'\t' '$1=="body_bits"{print $2; exit}')
    hex=$(printf '%s\n'  "$res" | awk -F'\t' '$1=="body_hex"{print $2; exit}')
    if [[ ! "$bits" =~ ^[0-9]+$ || -z "$hex" ]]; then
        lair_pws_err "the codec printed no body for $sib"
        return 1
    fi

    if [[ -n "$out" ]]; then
        command -v xxd >/dev/null 2>&1 || {
            lair_pws_err "--out needs xxd, which is not on PATH"
            return 1
        }
        mkdir -p "$(dirname -- "$out")" 2>/dev/null
        printf '%s' "$hex" | xxd -r -p > "$out" 2>/dev/null || {
            lair_pws_err "could not write $(lair_sanitize "$out")"
            return 1
        }
        out=$(lair_sanitize "$out")
    fi

    printf 'message\t%s\n' "$sib"
    printf 'fields\t%s\n' "$fields"
    printf 'bytes\t%d\n' "$(( (bits + 7) / 8 ))"
    printf 'hex\t%s\n' "$hex"
    if [[ -n "$out" ]]; then printf 'out\t%s\n' "$out"; fi
    # A body is not always a whole number of octets — SIB10 without --dummy
    # is 50 bits — so body_hex carries zero padding and bits_consumed is the
    # only length that separates padding from data.
    printf 'bits_consumed\t%s\n' "$bits"
    printf 'built\tyes\n'
    printf 'sent\t0\n'
    printf 'ref\t%s\n' "$ref"
    printf 'limit\t%s\n' "$limit"
    lair_pws_note
    return 0
}

# ── --build-sib10 — ETWS primary notification ───────────────────────────
lair_cmd_build_sib10() {
    local mid="" serial="" wt="" dummy="" late="" out=""
    local k v
    while (( $# )); do
        k="$1" v="${2:-}"
        case "$k" in
            --message-id|--serial|--warning-type|--dummy|--late-non-critical|--out)
                if (( $# < 2 )); then
                    lair_pws_err "$k needs a value"
                    return 2
                fi
                case "$k" in
                    --message-id)   mid="$v" ;;
                    --serial)       serial="$v" ;;
                    --warning-type) wt="$v" ;;
                    --dummy)        dummy="$v" ;;
                    --late-non-critical) late="$v" ;;
                    --out)          out="$v" ;;
                esac
                # A flag that was given an empty value is bad input, not an
                # absent flag: --dummy '' would otherwise silently build the
                # 50-bit short form and --out '' would silently write nothing.
                if [[ -z "$v" ]]; then
                    lair_pws_err "$k needs a non-empty value"
                    return 2
                fi
                shift 2 ;;
            --security-info)
                lair_pws_err "--security-info is not a field of SystemInformationBlockType10" \
                    "TS 36.331 §6.3.1 spells the 50-octet OPTIONAL field 'dummy'; SIB10 carries no warningSecurityInfo, and 50 octets is 400 bits, not the 48 the flag name suggests. --dummy takes the real field"
                return 2 ;;
            *)
                lair_pws_err "unknown option for --build-sib10: $(lair_sanitize "$k")" \
                    "options are --message-id, --serial, --warning-type, --dummy, --late-non-critical, --out"
                return 2 ;;
        esac
    done

    if [[ -z "$mid" ]]; then
        lair_pws_err "--build-sib10 needs --message-id <0..65535>" \
            "TS 36.331 §6.3.1 messageIdentifier is a 16-bit BIT STRING and is mandatory in the type; TS 23.041 §9.4.2.2.2 carries the same 16-bit message identifier"
        return 2
    fi
    local midv
    midv=$(lair_pws_u16 "$mid") || {
        lair_pws_err "--message-id must be decimal 0..65535: $(lair_sanitize "$mid")" \
            "TS 36.331 §6.3.1 messageIdentifier is a 16-bit BIT STRING and is mandatory in the type; TS 23.041 §9.4.2.2.2 carries the same 16-bit message identifier"
        return 2
    }
    mid="$midv"
    if [[ -z "$serial" ]]; then
        lair_pws_err "--build-sib10 needs --serial <0..65535>" \
            "TS 36.331 §6.3.1 serialNumber is a 16-bit BIT STRING and is mandatory; roll it per retransmission (TS 23.041 §9.4.2.2.3) so a receiver does not discard a changed message as a duplicate"
        return 2
    fi
    local serialv
    serialv=$(lair_pws_u16 "$serial") || {
        lair_pws_err "--serial must be decimal 0..65535: $(lair_sanitize "$serial")" \
            "TS 36.331 §6.3.1 serialNumber is a 16-bit BIT STRING and is mandatory; roll it per retransmission (TS 23.041 §9.4.2.2.3) so a receiver does not discard a changed message as a duplicate"
        return 2
    }
    serial="$serialv"
    if [[ -z "$wt" ]]; then
        lair_pws_err "--build-sib10 needs --warning-type <4 hex digits>" \
            "TS 36.331 §6.3.1 warningType is OCTET STRING (SIZE (2)) and is mandatory; TS 23.041 §9.4.2.2.4 puts the warning class in the top two bits and the category in the low six"
        return 2
    fi
    local wtv
    wtv=$(lair_pws_hexoct "$wt") || {
        lair_pws_err "--warning-type must be 2 octets of hex: $(lair_sanitize "$wt")" \
            "TS 36.331 §6.3.1 warningType is OCTET STRING (SIZE (2)), so give 4 hex digits: class in the top two bits, category in the low six (TS 23.041 §9.4.2.2.4)"
        return 2
    }
    wt="$wtv"
    if (( ${#wt} != 4 )); then
        lair_pws_err "--warning-type is OCTET STRING (SIZE (2)) in TS 36.331 §6.3.1, so it is exactly 4 hex digits; got $(( ${#wt} / 2 )) octets"
        return 2
    fi
    if [[ -n "$dummy" ]]; then
        local dummyv
        dummyv=$(lair_pws_hexoct "$dummy") || {
            lair_pws_err "--dummy must be hex octets: $(lair_sanitize "$dummy")" \
                "TS 36.331 §6.3.1 dummy is OCTET STRING (SIZE (50)), 100 hex digits; it is the backwards-compatibility filler, not warningSecurityInfo"
            return 2
        }
        dummy="$dummyv"
        if (( ${#dummy} != 100 )); then
            lair_pws_err "--dummy is OCTET STRING (SIZE (50)) in TS 36.331 §6.3.1, so it is exactly 50 octets (100 hex digits); got $(( ${#dummy} / 2 )) octets"
            return 2
        fi
    fi

    if [[ -n "$late" ]]; then
        local latev
        latev=$(lair_pws_hexoct "$late") || {
            lair_pws_err "--late-non-critical must be whole octets of hex: $(lair_sanitize "$late")"
            return 2
        }
        late="$latev"
    fi

    local json="{\"messageIdentifier\":{\"\$bits\":[$mid,16]},\"serialNumber\":{\"\$bits\":[$serial,16]},\"warningType\":{\"\$octets\":\"$wt\"}"
    [[ -n "$dummy" ]] && json+=",\"dummy\":{\"\$octets\":\"$dummy\"}"
    [[ -n "$late" ]] && json+=",\"lateNonCriticalExtension\":{\"\$octets\":\"$late\"}"
    json+="}"

    # warningType is not opaque to this module: lair_warning_type already
    # reads its warning class and category, so the fields row shows what the
    # two octets mean as well as what they are.
    local wtinfo=""
    wtinfo=$(lair_warning_type "$wt" 2>/dev/null) || wtinfo=""
    local fields="message_identifier=$mid serial=$serial warning_type=$wt dummy_octets=$(( ${#dummy} / 2 ))"
    if [[ -n "$late" ]]; then fields+=" late_noncritical_octets=$(( ${#late} / 2 ))"; fi
    if [[ -n "$wtinfo" ]]; then fields+=" ($wtinfo)"; fi

    local ref limit
    ref="3GPP TS 36.331 6.3.1 SystemInformationBlockType10 (unaligned PER, generated codec tools/lte_asn1.py)"
    limit="message octets only: no BCCH-DL-SCH wrapper, no PDCCH scheduling, no PWS delivery; body_hex is zero-padded to whole octets and bits_consumed is the true length"
    lair_pws_emit SIB10 sib10 "$json" "$fields" "$ref" "$limit" "$out"
}

# ── --build-sib11 / --build-sib12 — ETWS secondary and CMAS ─────────────
#
# The two blocks differ only in the -r9 suffixes Rel-9 gave the CMAS one, so
# one runner builds both and the dispatch verbs stay thin.
lair_cmd_build_sib11() { lair_cmd_build_sib_segmented SIB11 "$@"; }
lair_cmd_build_sib12() { lair_cmd_build_sib_segmented SIB12 "$@"; }

# ── Warning-area targeting (TS 23.041 §9.4.2.2.5, TS 36.331 SIB10/11/12) ─
# The codec above builds the segments. This is the arithmetic nobody does
# before pressing send, and it decides whether a warning reaches one cell or
# a country.
#
# The scope is NOT in the Set-of CBS IDs as a wide field. Each warning message
# carries a Serial Number whose top 2 bits are the Geographical Scope:
#
#   GS 00  immediate  cell wide          (operators use this for base station IDs)
#   GS 01  normal     PLMN wide
#   GS 10  normal     Location Area wide (GSM) / Service Area wide (UMTS)
#   GS 11  normal     cell wide
#
# (TS 23.041 v8.11.0 §9.4.2.2.5, the coding table.) The rest of the Serial
# Number is a 10-bit Message Code and a 4-bit Update Number.
#
# Two consequences that matter before a forged warning goes out:
#   * "cell wide" is about identity, not delivery — the TS says outright that
#     a message with GS=cell is treated as new in the next cell, so the same
#     broadcast re-displays at every cell boundary it crosses.
#   * PLMN wide means the UE treats identical Message Code + Update Number as
#     the same message across the whole network, which is what makes one
#     forged body survive a drive across cells instead of being re-shown.
#
# The Set-of CBS IDs in SIB11/12 is a *list of target cells/areas*, a separate
# field from the scope. Reading one and claiming it answers the other is the
# mistake this verb exists to avoid making.

# lair_warning_scope <serial 4-hex>
#   Serial Number is 2 octets: GS in octet 1 bits 7-6, Message Code spanning
#   the remaining bits, Update Number in octet 2 bits 3-0.
lair_warning_scope() {  # <serial 4-hex> -> scope|mode|message_code|update
    local h="${1:-}"; h="${h^^}"
    [[ "$h" =~ ^[0-9A-F]{4}$ ]] || { printf 'invalid'; return 1; }
    local v=$(( 16#$h ))
    local gs=$(( (v >> 14) & 0x3 ))
    local up=$(( v & 0xF ))
    local mc=$(( (v >> 4) & 0x3FF ))
    local scope mode
    case $gs in
        0) scope=cell-wide;          mode=immediate ;;
        1) scope=plmn-wide;          mode=normal ;;
        2) scope=location-area-wide; mode=normal ;;
        3) scope=cell-wide;          mode=normal ;;
    esac
    printf '%s|%s|%d|%d' "$scope" "$mode" "$mc" "$up"
}

lair_warning_area_usage() {
    printf 'usage: --warning-area <serial-hex>[,<serial-hex>,...]\n' >&2
    printf '       each argument is a 2-octet Serial Number (GS + Message Code + Update Number)\n' >&2
}

# lair_cmd_warning_area <serial hex list>
#   Decode one or more Serial Numbers and report the reach the scope implies.
lair_cmd_warning_area() {
    local list="${1:-}"
    [[ -n "$list" ]] || { lair_warning_area_usage; return 2; }
    list="${list// /}"; list="${list//,/ }"
    local -a ids; read -r -a ids <<< "$list"
    printf 'field\tvalue\n'
    printf 'serial_count\t%d\n' "${#ids[@]}"
    local widest='' widest_rank=0 rank id dec scope mode mc up
    for id in "${ids[@]}"; do
        id="${id^^}"
        [[ "$id" =~ ^[0-9A-F]{4}$ ]] || {
            printf 'ERROR\t%s is not a 2-octet Serial Number (4 hex digits)\n' \
                "$(printf '%s' "$id" | tr -cd '0-9A-Fa-f')" >&2; return 2; }
        dec=$(lair_warning_scope "$id") || return 2
        scope="${dec%%|*}"; local rest="${dec#*|}"
        mode="${rest%%|*}"; rest="${rest#*|}"
        mc="${rest%%|*}"; up="${rest##*|}"
        case "$scope" in
            plmn-wide)          rank=3 ;;
            location-area-wide) rank=2 ;;
            cell-wide)          rank=1 ;;
            *)                  rank=0 ;;
        esac
        printf 'serial\t%s\tscope=%s\tmode=%s\tmessage_code=%s\tupdate=%s\n' \
            "$id" "$scope" "$mode" "$mc" "$up"
        if (( rank > widest_rank )); then widest_rank=$rank; widest="$id"; fi
    done
    printf 'widest_serial\t%s\n' "$widest"
    case $widest_rank in
        3) printf 'effective_reach\tevery cell in the PLMN treats identical Message Code + Update Number as one message\n'
           printf 'targeting_verdict\tnetwork-wide identity: one forged body survives a drive across cells\n' ;;
        2) printf 'effective_reach\tone Location Area (GSM) or Service Area (UMTS)\n'
           printf 'targeting_verdict\tbounded by the area the UE is registered in\n' ;;
        1) printf 'effective_reach\tone cell of identity, re-displayed at every cell boundary it crosses\n'
           printf 'targeting_verdict\tnarrow by identity, NOT narrow by delivery: GS=cell is treated as new in the next cell\n' ;;
        *) printf 'effective_reach\tunclassified\n'
           printf 'targeting_verdict\tunknown, and unknown is not the same answer as narrow\n' ;;
    esac
    if (( ${#ids[@]} > 1 )) && (( widest_rank >= 2 )); then
        printf 'set_note\tthe widest scope in the set decides; a cell-wide entry does not shrink a PLMN-wide one\n'
    fi
    printf 'cbsid_separate\tthe Set-of CBS IDs in SIB11/12 names target areas and is a different field from the scope; reading it does not answer this\n'
    printf 'spec\tTS 23.041 9.4.2.2.5 (Geographical Scope coding), TS 36.331 SIB10/11/12\n'
    return 0
}

lair_cmd_build_sib_segmented() {
    local sib="${1:-}"; (($# > 0)) && shift
    local stem sfx
    case "$sib" in
        SIB11) stem=sib11; sfx="" ;;
        SIB12) stem=sib12; sfx="-r9" ;;
        *) lair_pws_err "internal: unknown segmented SIB '$sib'"; return 1 ;;
    esac

    local mid="" serial="" segt="" seg="" count="" payload="" dcs="" warea="" late="" out=""
    local k v
    while (( $# )); do
        k="$1" v="${2:-}"
        case "$k" in
            --message-id|--serial|--segment-type|--segment-number|--segment|--count|--payload|--data-coding|--warning-area|--late-non-critical|--out)
                if (( $# < 2 )); then
                    lair_pws_err "$k needs a value"
                    return 2
                fi
                case "$k" in
                    --message-id)      mid="$v" ;;
                    --serial)          serial="$v" ;;
                    --segment-type)    segt="$v" ;;
                    # ASN.1: warningMessageSegment is the OCTET STRING,
                    # warningMessageSegmentNumber the INTEGER (0..63).
                    --segment-number)  seg="$v" ;;
                    --segment|--payload) payload="$v" ;;
                    --count)           count="$v" ;;
                    --data-coding)     dcs="$v" ;;
                    --warning-area)    warea="$v" ;;
                    --late-non-critical) late="$v" ;;
                    --out)             out="$v" ;;
                esac
                if [[ -z "$v" ]]; then
                    lair_pws_err "$k needs a non-empty value"
                    return 2
                fi
                if [[ "$k" == --warning-area && "$sib" == SIB11 ]]; then
                    # The codec drops a key the type does not have, so an
                    # accepted flag here would build a message that silently
                    # does not carry it.
                    lair_pws_err "--warning-area is not a field of SystemInformationBlockType11" \
                        "TS 36.331 §6.3.1 puts warningAreaCoordinatesSegment-r15 in SystemInformationBlockType12-r9's extension group only (Rel-15); SIB11 has no warning area segment"
                    return 2
                fi
                shift 2 ;;
            --payload-text)
                if (( $# < 2 )); then
                    lair_pws_err "--payload-text needs a value"
                    return 2
                fi
                command -v od >/dev/null 2>&1 || {
                    lair_pws_err "--payload-text needs od, which is not on PATH"
                    return 1
                }
                if [[ -z "$v" ]]; then
                    lair_pws_err "--payload-text is empty" \
                        "an empty warning segment carries no warning message; give the text the segment carries"
                    return 2
                fi
                payload=$(printf '%s' "$v" | od -An -tx1 | tr -d ' \n')
                shift 2 ;;
            *)
                lair_pws_err "unknown option for --build-${stem}: $(lair_sanitize "$k")" \
                    "options are --message-id, --serial, --segment-type, --segment (contents), --segment-number, --count, --payload, --payload-text, --data-coding, --warning-area (SIB12 only), --late-non-critical, --out"
                return 2 ;;
        esac
    done

    if [[ -z "$mid" ]]; then
        lair_pws_err "--build-${stem} needs --message-id <0..65535>" \
            "TS 36.331 §6.3.1 messageIdentifier is a 16-bit BIT STRING and is mandatory in the type; TS 23.041 §9.4.2.2.2 carries the same 16-bit message identifier"
        return 2
    fi
    local midv
    midv=$(lair_pws_u16 "$mid") || {
        lair_pws_err "--message-id must be decimal 0..65535: $(lair_sanitize "$mid")" \
            "TS 36.331 §6.3.1 messageIdentifier is a 16-bit BIT STRING and is mandatory in the type; TS 23.041 §9.4.2.2.2 carries the same 16-bit message identifier"
        return 2
    }
    mid="$midv"
    if [[ -z "$serial" ]]; then
        lair_pws_err "--build-${stem} needs --serial <0..65535>" \
            "TS 36.331 §6.3.1 serialNumber is a 16-bit BIT STRING and is mandatory; roll it per retransmission (TS 23.041 §9.4.2.2.3) so a receiver does not discard a changed message as a duplicate"
        return 2
    fi
    local serialv
    serialv=$(lair_pws_u16 "$serial") || {
        lair_pws_err "--serial must be decimal 0..65535: $(lair_sanitize "$serial")" \
            "TS 36.331 §6.3.1 serialNumber is a 16-bit BIT STRING and is mandatory; roll it per retransmission (TS 23.041 §9.4.2.2.3) so a receiver does not discard a changed message as a duplicate"
        return 2
    }
    serial="$serialv"
    if [[ -z "$segt" ]]; then
        lair_pws_err "--build-${stem} needs --segment-type <notLastSegment|lastSegment>" \
            "TS 36.331 §6.3.1 requires warningMessageSegmentType in every SIB11/SIB12: a receiver holds an incomplete message until the last segment arrives"
        return 2
    fi
    if [[ "$segt" == first ]]; then
        lair_pws_err "--segment-type first is not in the enumeration" \
            "TS 36.331 §6.3.1: WarningMessageSegmentType ::= ENUMERATED {notLastSegment, lastSegment}. A one-segment message is a lastSegment and the opening segment of a longer one is a notLastSegment"
        return 2
    fi
    local segtv
    segtv=$(lair_pws_segtype "$segt") || {
        lair_pws_err "--segment-type takes notLastSegment or lastSegment: $(lair_sanitize "$segt")" \
            "the ASN.1 enumeration has two states, not three"
        return 2
    }
    segt="$segtv"
    if [[ -z "$seg" ]]; then
        lair_pws_err "--build-${stem} needs --segment-number <0..63>" \
            "TS 36.331 §6.3.1 warningMessageSegmentNumber is INTEGER (0..63): a warning message has at most 64 segments"
        return 2
    fi
    local segv
    segv=$(lair_pws_seg "$seg") || {
        lair_pws_err "--segment-number is warningMessageSegmentNumber, INTEGER (0..63): $(lair_sanitize "$seg")" \
            "TS 36.331 §6.3.1 warningMessageSegmentNumber is INTEGER (0..63): a warning message has at most 64 segments"
        return 2
    }
    seg="$segv"
    if [[ -n "$count" ]]; then
        # Not lair_pws_seg: that one stops at 63 because it validates the
        # segment number, and a 64-segment message has a count of 64.
        local countv
        countv=$(lair_pws_u16 "$count") || {
            lair_pws_err "--count must be decimal 1..64: $(lair_sanitize "$count")"
            return 2
        }
        count="$countv"
        if (( count < 1 || count > 64 )); then
            lair_pws_err "--count must be 1..64 (segment numbers run 0..63); got $(lair_sanitize "$count")"
            return 2
        fi
        if (( seg >= count )); then
            lair_pws_err "--segment-number $seg is outside --count $count" \
            "a message of $count segments numbers them 0..$(( count - 1 )); the count itself is not encoded in the message (count_encoded=no)"
            return 2
        fi
        if [[ "$segt" == lastSegment ]] && (( seg != count - 1 )); then
            lair_pws_err "--segment-number $seg of $count is not the last segment, but --segment-type is lastSegment"
            return 2
        fi
        if [[ "$segt" == notLastSegment ]] && (( seg == count - 1 )); then
            lair_pws_err "--segment-number $seg is the last of $count, but --segment-type is notLastSegment" \
                "a receiver waiting for the last segment never completes the warning message"
            return 2
        fi
    fi
    if [[ -z "$payload" ]]; then
        lair_pws_err "--build-${stem} needs --segment <hex octets>, --payload, or --payload-text <utf8 text>" \
            "warningMessageSegment is the OCTET STRING that carries the TS 23.041 CB-Data IE; an empty segment carries no warning message"
        return 2
    fi
    local payloadv
    payloadv=$(lair_pws_hexoct "$payload") || {
        lair_pws_err "--segment must be whole octets of hex: $(lair_sanitize "$payload")" \
            "warningMessageSegment is an unconstrained OCTET STRING: give it as whole octets of hex, or pass text with --payload-text"
        return 2
    }
    payload="$payloadv"
    if [[ -n "$dcs" ]]; then
        local dcsv
        dcsv=$(lair_pws_hexoct "$dcs") || {
            lair_pws_err "--data-coding must be one octet of hex: $(lair_sanitize "$dcs")" \
                "TS 36.331 §6.3.1 dataCodingScheme is OCTET STRING (SIZE (1)); its value is TS 23.041 §9.4.2.2.5 encoding, not free text"
            return 2
        }
        dcs="$dcsv"
        if (( ${#dcs} != 2 )); then
            lair_pws_err "--data-coding is OCTET STRING (SIZE (1)), so it is exactly 2 hex digits; got $(lair_sanitize "$dcs")" \
                "one octet only: TS 23.041 §9.4.2.2.5 data coding scheme, e.g. 01 for GSM 7 bit"
            return 2
        fi
    fi

    if [[ -n "$warea" ]]; then
        local wareav
        wareav=$(lair_pws_hexoct "$warea") || {
            lair_pws_err "--warning-area must be whole octets of hex: $(lair_sanitize "$warea")" \
                "warningAreaCoordinatesSegment-r15 is an OCTET STRING carrying one segment of the warning area polygon (TS 36.331 §6.3.1, SystemInformationBlockType12-r9 extension group, Rel-15)"
            return 2
        }
        warea="$wareav"
    fi
    if [[ -n "$late" ]]; then
        local latev2
        latev2=$(lair_pws_hexoct "$late") || {
            lair_pws_err "--late-non-critical must be whole octets of hex: $(lair_sanitize "$late")"
            return 2
        }
        late="$latev2"
    fi

    local json="{\"messageIdentifier$sfx\":{\"\$bits\":[$mid,16]},\"serialNumber$sfx\":{\"\$bits\":[$serial,16]},\"warningMessageSegmentType$sfx\":\"$segt\",\"warningMessageSegmentNumber$sfx\":$seg,\"warningMessageSegment$sfx\":{\"\$octets\":\"$payload\"}"
    [[ -n "$dcs" ]] && json+=",\"dataCodingScheme$sfx\":{\"\$octets\":\"$dcs\"}"
    [[ -n "$late" ]] && json+=",\"lateNonCriticalExtension\":{\"\$octets\":\"$late\"}"
    [[ -n "$warea" ]] && json+=",\"warningAreaCoordinatesSegment-r15\":{\"\$octets\":\"$warea\"}"
    json+="}"

    local fields="message_identifier=$mid serial=$serial segment_type=$segt segment_number=$seg segment_octets=$(( ${#payload} / 2 ))"
    if [[ -n "$count" ]]; then fields+=" count=$count"; fi
    # count_encoded=no is not decoration: a reader who assumes the count is
    # in the message will look for it in a field that does not exist.
    fields+=" count_encoded=no"
    if [[ -n "$dcs" ]]; then fields+=" data_coding=$dcs"; else fields+=" data_coding=none"; fi
    if [[ -n "$warea" ]]; then fields+=" warning_area_octets=$(( ${#warea} / 2 ))"; fi
    if [[ -n "$late" ]]; then fields+=" late_noncritical_octets=$(( ${#late} / 2 ))"; fi

    local ref limit
    if [[ "$sib" == SIB11 ]]; then
        ref="3GPP TS 36.331 6.3.1 SystemInformationBlockType11 (unaligned PER, generated codec tools/lte_asn1.py; contents TS 23.041)"
        limit="message octets only: no BCCH-DL-SCH wrapper, no PDCCH scheduling, no PWS delivery; the warning message contents are the caller's TS 23.041 octets and nothing here splits a message into segments"
        lair_pws_emit SIB11 "$stem" "$json" "$fields" "$ref" "$limit" "$out"
    else
        ref="3GPP TS 36.331 6.3.1 SystemInformationBlockType12-r9 (unaligned PER, generated codec tools/lte_asn1.py; contents TS 23.041)"
        limit="message octets only: no BCCH-DL-SCH wrapper, no PDCCH scheduling, no PWS delivery; the CMAS message body is the caller's TS 23.041 octets and nothing here builds it"
        lair_pws_emit SIB12 "$stem" "$json" "$fields" "$ref" "$limit" "$out"
    fi
}

# ── Field read-back ───────────────────────────────────────────────────
# The decoder prints a bit-string as "0x1100 (16 bits)"; the width is the
# decoder's answer to "how big was this field", not part of the value, so
# the read-back keeps the value and drops the suffix.
lair_pws_dfield() {
    printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}' | awk '{print $1}'
}

# ── The eNB side: what srsRAN would need to broadcast the body ─────────
#
# This is the honest answer to "can this tree put a warning on air". The
# module can now build the SIB10/11/12 octets; broadcasting one needs an
# eNB whose RRC carries PWS encoding, a sib.conf that declares the message,
# a sib1 scheduler entry naming it, and a cell the operator is licensed to
# transmit on. This verb writes the configuration for the first three and
# refuses to write it for an srsRAN that would reject it rather than ignore
# it silently.
#
# Verified against the two versions that matter here, both read in full:
#
#   srsRAN_4G release_23_11 (the tag this tree pins at
#   tools/check-lte-phy-oracle.sh:68) registers sib.conf sections sib1,
#   sib2, sib3, sib4, sib5, sib6, sib7, sib9 and sib13 only. There is no
#   sib10/sib11/sib12 section, rrc_cfg_->sibs[9..11] is never filled, and
#   sib_info_item_c::pack() returns SRSASN_ERROR_ENCODE_FAIL for the unset
#   choice (lib/src/asn1/rrc/bcch_msg.cc:12145), so a sib1 scheduler entry
#   naming 10, 11 or 12 makes srsenb fail to start. It does NOT accept them.
#
#   srsRAN_4G master implements it: srsenb/src/enb_cfg_parser.cc has
#   parse_sib10() (section "sib10": message_id, serial_num, warning_type),
#   parse_sib11() and parse_sib12() (sections "sib11"/"sib12":
#   message_id, serial_num, data_coding_scheme, warning_message), and
#   parse_sibs() fills rrc_cfg_->sibs[9].set_sib10() plus
#   rrc_cfg_->sib11_segments / sib12_segments, and the sched_info entry
#   itself sets rrc_cfg_->etws_present (SIB10/SIB11) or cmas_present
#   (SIB12) — the PDCCH ETWS/CMAS paging indication (P-RNTI) is driven by
#   the same line, so nothing here has to emit it separately. For SIB11 and SIB12 the
#   config carries the warning MESSAGE TEXT, not segment octets: srsRAN
#   builds the CB-Data IE from it (TS 23.041 §9.4.2.2.5), encodes it with
#   the scheme data_coding_scheme selects, and cuts it into 100-octet
#   segments itself.
#
# There is no [sib] section and no sib_sched_list key in either version:
# the scheduler entry is sib1's sched_info inside the sib.conf file that
# enb.conf's [enb_files] sib_config names. This module's --gen-enb-conf
# writes no [enb_files] block, so srsenb falls back to ./sib.conf
# (srsenb/src/main.cc:97) and exits if it is missing (main.cc:485).
lair_cmd_enb_sib_schedule() {
    local sib="" hex="" wmsg="" out="" ver=""
    local k v
    while (( $# )); do
        k="$1" v="${2:-}"
        case "$k" in
            --sib|--hex|--warning-message|--out|--srsran-version)
                if (( $# < 2 )); then
                    lair_pws_err "$k needs a value"
                    return 2
                fi
                case "$k" in
                    --sib)             sib="$v" ;;
                    --hex)             hex="$v" ;;
                    --warning-message) wmsg="$v" ;;
                    --out)             out="$v" ;;
                    --srsran-version)  ver="$v" ;;
                esac
                shift 2 ;;
            *)
                lair_pws_err "unknown option for --enb-sib-schedule: $(lair_sanitize "$k")" \
                    "options are --sib, --hex, --warning-message, --out, --srsran-version"
                return 2 ;;
        esac
    done

    case "$sib" in
        10|sib10) sib=10 ;;
        11|sib11) sib=11 ;;
        12|sib12) sib=12 ;;
        "")
            lair_pws_err "--enb-sib-schedule needs --sib 10|11|12" \
                "SIB10 is ETWS primary, SIB11 ETWS secondary and SIB12 CMAS; SIB6/7/8 are not warning message containers and SIB9/13 are scheduled by other means"
            return 2 ;;
        *)
            lair_pws_err "--sib takes 10, 11 or 12: $(lair_sanitize "$sib")"
            return 2 ;;
    esac

    if [[ -z "$hex" ]]; then
        lair_pws_err "--enb-sib-schedule needs --hex <body>" \
            "take the hex row --build-sib$sib printed: this verb reads the config fields back out of the bits so they cannot disagree with the message"
        return 2
    fi
    local hexv
    hexv=$(lair_pws_hexoct "$hex") || {
        lair_pws_err "--hex must be whole octets of hex: $(lair_sanitize "$hex")"
        return 2
    }
    hex="$hexv"

    local decoded rc
    decoded=$(lair_decode_sib "$hex" "$sib" 2>/dev/null)
    rc=$?
    if (( rc != 0 )) || [[ -z "$decoded" ]]; then
        lair_pws_err "--hex is not a SIB$sib body: it does not decode as one" \
            "pass the body --build-sib$sib emitted; another SIB, a BCCH-DL-SCH container or a trailing extra octet will not read as SIB$sib"
        return 2
    fi

    local sfx="" mid serial dcs wt bits
    [[ "$sib" == 12 ]] && sfx=-r9
    mid=$(lair_pws_dfield "$decoded" "messageIdentifier$sfx")
    serial=$(lair_pws_dfield "$decoded" "serialNumber$sfx")
    bits=$(lair_pws_dfield "$decoded" bits)
    if (( sib == 10 )); then
        wt=$(lair_pws_dfield "$decoded" warningType)
    else
        dcs=$(lair_pws_dfield "$decoded" "dataCodingScheme$sfx")
        if [[ -z "$dcs" ]]; then
            lair_pws_err "SIB$sib without dataCodingScheme cannot be scheduled through srsRAN" \
                "srsRAN's parse_sib$sib sets data_coding_scheme_present = true and calls select_cbs_encoding() on it, so the section needs data_coding_scheme; rebuild with --data-coding <one octet of hex> (TS 23.041 §9.4.2.2.5 data coding scheme)"
            return 2
        fi
        if [[ -z "$wmsg" ]]; then
            lair_pws_err "SIB$sib needs --warning-message <text> for the srsRAN section" \
                "the sib.conf field is warning_message, a string: srsRAN builds the CB-Data IE from the text (TS 23.041 §9.4.2.2.5), encodes it with the data_coding_scheme and splits it into segments itself, so the segment octets in the RRC body are not the config input"
            return 2
        fi
        case "$wmsg" in
            *$'\n'*)
                lair_pws_err "--warning-message cannot contain a newline" \
                    "the srsRAN config value is one quoted string; spaces are fine"
                return 2 ;;
        esac
    fi
    if [[ -z "$mid" || -z "$serial" ]]; then
        lair_pws_err "the decoded SIB$sib body carries no messageIdentifier/serialNumber" \
            "both are mandatory in the ASN.1 type; a body without them is not a SIB$sib"
        return 2
    fi

    local section="sib$sib"
    local octets="${out:-${LAIR_DIR:-.}}/sib$sib.octets"
    local frag="${out:-${LAIR_DIR:-.}}/sib.conf.fragment"

    # The refusal is the default on purpose: no srsRAN is installed on this
    # machine, and the version this tree pins cannot carry these SIBs. An
    # operator who has a master build opts in by naming it.
    if [[ "$ver" != master ]]; then
        printf 'sib\t%d\n'             "$sib"
        printf 'hex\t%s\n'             "$hex"
        printf 'bits\t%s\n'            "$bits"
        printf 'bytes\t%d\n'           "$(( ${#hex} / 2 ))"
        printf 'sib_conf_section\t%s\n' "$section"
        printf 'sched_info_key\tsib1.sched_info[].si_mapping_info\n'
        printf 'sched_info_value\t%d\n' "$sib"
        printf 'version_refused\t%s\n' "${ver:-srsRAN_4G release_23_11 (default; nothing newer is installed)}"
        printf 'built\tno\n'
        printf 'sent\t0\n'
        printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType%d; srsRAN_4G sib.conf sib1.sched_info / enb.conf [enb_files] sib_config\n' "$sib"
        printf 'limit\ta warning SIB broadcast needs the operator\x27s own cell and a lawful basis; this verb writes configuration and message octets and transmits nothing (sent 0)\n'
        lair_pws_note
        if [[ -n "$ver" && "$ver" != "release_23_11" && "$ver" != "23.11" && "$ver" != "23_11" ]]; then
            lair_pws_err "srsRAN version $(lair_sanitize "$ver") is not one this verb verified" \
                "the two it knows are release_23_11 (refused: no PWS encoding) and master (emitted)"
        fi
        lair_pws_err "srsRAN_4G release_23_11 cannot broadcast SIB$sib" \
            "release_23_11 registers sib.conf sections sib1, sib2, sib3, sib4, sib5, sib6, sib7, sib9, sib13 only; it has no sib$sib parse function, rrc_cfg_->sibs[$(( sib - 1 ))] is never filled, and sib_info_item_c::pack() returns SRSASN_ERROR_ENCODE_FAIL for the unset choice (lib/src/asn1/rrc/bcch_msg.cc:12145), so si_mapping_info = [ $sib ] makes srsenb fail to start instead of transmitting. the missing link is PWS encoding in srsenb itself. srsRAN_4G master implements it (srsenb/src/enb_cfg_parser.cc parse_sib10/parse_sib11/parse_sib12): pass --srsran-version master to write that fragment; no config was written"
        return 2
    fi

    command -v xxd >/dev/null 2>&1 || {
        lair_pws_err "--enb-sib-schedule needs xxd to write the octets file"
        return 1
    }
    mkdir -p "${out:-${LAIR_DIR:-.}}" || {
        lair_pws_err "cannot create $octets"
        return 1
    }
    printf '%s' "$hex" | xxd -r -p > "$octets" || {
        lair_pws_err "cannot write $octets"
        return 1
    }

    case "$sib" in
        10)
            {
                printf '# IMSIsting modules/10_lte_air.sh --enb-sib-schedule -> srsRAN_4G sib.conf fragment\n'
                printf '#\n'
                printf '# Verified against srsRAN_4G master, srsenb/src/enb_cfg_parser.cc:\n'
                printf '#   parse_sib10(): section "sib10"; fields message_id, serial_num, warning_type\n'
                printf '#\n'
                printf '# 1. Merge this section into the sib.conf that enb.conf [enb_files] sib_config names.\n'
                printf '#    srsenb defaults to ./sib.conf (srsenb/src/main.cc:97) and exits without it (main.cc:485).\n'
                printf '# 2. Schedule it from sib1 sched_info, one SIB per SI message:\n'
                printf '#       sched_info = ( { si_periodicity = 16; si_mapping_info = [ 10 ]; } );\n'
                printf '# 3. The [enb] block --gen-enb-conf writes has no [enb_files] section; add\n'
                printf '#       sib_config = "sib.conf";\n'
                printf '#    there, or start srsenb from the directory holding this file.\n'
                printf '# 4. srsRAN sets rrc_cfg_->etws_present from this sched_info entry, so the\n'
                printf '#    PDCCH ETWS paging indication (P-RNTI) follows from the same line.\n'
                printf '#\n'
                printf '# The message octets are in sib10.octets. srsRAN re-encodes the body from this\n'
                printf '# config, so that file is the reference body for another stack, not an input.\n'
                printf '\n'
                printf 'sib10 =\n{\n'
                printf '    message_id = %s;\n'   "$mid"
                printf '    serial_num = %s;\n'   "$serial"
                printf '    warning_type = 0x%s;\n' "$wt"
                printf '};\n'
            } > "$frag" || {
                lair_pws_err "cannot write $frag"
                return 1
            } ;;
        *)
            # libconfig string: escape the backslash and the quote, leave the
            # rest alone; a newline was refused above.
            local etxt="${wmsg//\\/\\\\}"
            etxt="${etxt//\"/\\\"}"
            {
                printf '# IMSIsting modules/10_lte_air.sh --enb-sib-schedule -> srsRAN_4G sib.conf fragment\n'
                printf '#\n'
                printf '# Verified against srsRAN_4G master, srsenb/src/enb_cfg_parser.cc:\n'
                printf '#   parse_sib%s(): section "sib%s"; fields message_id, serial_num,\n' "$sib" "$sib"
                printf '#   data_coding_scheme, warning_message. srsRAN builds the CB-Data IE from\n'
                printf '#   warning_message (TS 23.041 9.4.2.2.5), encodes it with the scheme\n'
                printf '#   data_coding_scheme selects (GSM7 or UCS2) and splits it into 100-octet\n'
                printf '#   segments itself, so no segment fields go in this config.\n'
                printf '#\n'
                printf '# 1. Merge this section into the sib.conf that enb.conf [enb_files] sib_config names.\n'
                printf '# 2. Schedule it from sib1 sched_info, one SIB per SI message:\n'
                printf '#       sched_info = ( { si_periodicity = 16; si_mapping_info = [ %s ]; } );\n' "$sib"
                printf '# 3. srsRAN sets %s from this sched_info entry, so the\n' "$([[ "$sib" == 12 ]] && echo 'rrc_cfg_->cmas_present' || echo 'rrc_cfg_->etws_present')"
                printf '#    PDCCH %s paging indication (P-RNTI) follows from the same line.\n' "$([[ "$sib" == 12 ]] && echo CMAS || echo ETWS)"
                printf '#\n'
                printf '# The message octets are in sib%s.octets. They carry THIS segment as built by\n' "$sib"
                printf '# --build-sib%s; srsRAN cuts its own segments from warning_message, so that file\n' "$sib"
                printf '# is the reference body for another stack, not an input to srsenb.\n'
                printf '\n'
                printf 'sib%s =\n{\n' "$sib"
                printf '    message_id = %s;\n'        "$mid"
                printf '    serial_num = %s;\n'        "$serial"
                printf '    data_coding_scheme = 0x%s;\n' "$dcs"
                printf '    warning_message = "%s";\n' "$etxt"
                printf '};\n'
            } > "$frag" || {
                lair_pws_err "cannot write $frag"
                return 1
            } ;;
    esac

    printf 'sib\t%d\n'              "$sib"
    printf 'hex\t%s\n'              "$hex"
    printf 'bits\t%s\n'             "$bits"
    printf 'bytes\t%d\n'            "$(( ${#hex} / 2 ))"
    if (( sib == 10 )); then
        printf 'fields\tmessage_identifier=%s serial=%s warning_type=0x%s\n' "$mid" "$serial" "$wt"
        printf 'version_verified\tsrsRAN_4G master (srsenb/src/enb_cfg_parser.cc parse_sib10)\n'
    else
        printf 'fields\tmessage_identifier=%s serial=%s data_coding=0x%s warning_message_chars=%d\n' \
            "$mid" "$serial" "$dcs" "${#wmsg}"
        printf 'version_verified\tsrsRAN_4G master (srsenb/src/enb_cfg_parser.cc parse_sib%s)\n' "$sib"
    fi
    printf 'sib_conf_section\t%s\n'                     "$section"
    printf 'sched_info_key\tsib1.sched_info[].si_mapping_info\n'
    printf 'sched_info_value\t%d\n'                     "$sib"
    printf 'sib_conf_file\t%s\n'                        "$frag"
    printf 'octets_file\t%s\n'                          "$octets"
    printf 'built\tyes\n'
    printf 'sent\t0\n'
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType%d; srsRAN_4G sib.conf sib1.sched_info / enb.conf [enb_files] sib_config\n' "$sib"
    printf 'limit\ta warning SIB broadcast needs the operator\x27s own cell and a lawful basis; this verb writes configuration and message octets and transmits nothing (sent 0); srsRAN re-encodes SIB10/11/12 from sib.conf, so the .octets file is a reference body, not an input to srsenb\n'
    lair_pws_note
    printf 'OK\t%s\n' "$frag"
    return 0
}

# ── Selftest ──────────────────────────────────────────────────────────
# Called from the module's lair_selftest, which defines chk/fld/fline and
# has already pointed LOOT_DIR/LAIR_DIR at a throwaway directory. The
# expected hex values are known answers from pycrate's own encoder
# (pycrate_asn1dir.RRCLTE, to_uper()), not from running this builder twice.
lair_pws_selftest() {
    local out rc d1 d2

    # ── Warning-area scope (TS 23.041 9.4.2.2.5) ───────────────────────
    # GS is octet 1 bits 7-6, NOT a low-12-bit field. These four values are the
    # whole coding table, so they get pinned one at a time.
    chk warn-scope-gs00 "$(lair_warning_scope 0000 | cut -d'|' -f1)" "cell-wide"
    chk warn-scope-gs01 "$(lair_warning_scope 4000 | cut -d'|' -f1)" "plmn-wide"
    chk warn-scope-gs10 "$(lair_warning_scope 8000 | cut -d'|' -f1)" "location-area-wide"
    chk warn-scope-gs11 "$(lair_warning_scope C000 | cut -d'|' -f1)" "cell-wide"
    chk warn-mode-gs00-immediate "$(lair_warning_scope 0000 | cut -d'|' -f2)" "immediate"
    chk warn-mode-gs01-normal    "$(lair_warning_scope 4000 | cut -d'|' -f2)" "normal"
    # GS=PLMN must NOT decode as cell-wide, or a wide forgery reads as narrow.
    chk warn-gs-not-cell "$([ "$(lair_warning_scope 4000 | cut -d'|' -f1)" != "cell-wide" ] && echo yes)" "yes"

    # The widest entry decides; a narrow entry must not shrink it.
    out=$(lair_cmd_warning_area "C000,4000" 2>/dev/null)
    chk warn-widest-plmn "$(fld "$out" widest_serial)" "4000"
    chk warn-widest-is-plmn "$(fld "$out" targeting_verdict | grep -c 'network-wide')" "1"
    out=$(lair_cmd_warning_area "C000,0000" 2>/dev/null)
    chk warn-all-narrow "$(fld "$out" targeting_verdict | grep -c 'narrow by identity')" "1"
    # GS=cell must be described as re-displayed, never as a delivery bound.
    chk warn-cell-not-delivery-bound "$(fld "$(lair_cmd_warning_area 0000 2>/dev/null)" targeting_verdict | grep -c 'NOT narrow by delivery')" "1"
    chk warn-bad-hex "$(lair_cmd_warning_area "40" 2>&1 >/dev/null | grep -c 'not a 2-octet Serial Number')" "1"
    # The CBS ID set is a different field and the verb has to say so.
    chk warn-cbsid-separate "$(fld "$(lair_cmd_warning_area 4000 2>/dev/null)" cbsid_separate | grep -c 'different field from the scope')" "1"

    # ── SIB10: exact octets, pinned from pycrate ──────────────────────
    out=$(lair_cmd_build_sib10 --message-id 4352 --serial 0 --warning-type 0001 2>/dev/null)
    chk pws10-hex    "$(fld "$out" hex)"            "04400000000040"
    chk pws10-bits   "$(fld "$out" bits_consumed)"  "50"
    chk pws10-sent   "$(fld "$out" sent)"           "0"
    chk pws10-ref    "$(printf '%s\n' "$out" | grep -c '^ref	3GPP TS 36.331 6.3.1 SystemInformationBlockType10')" "1"
    # pycrate: messageIdentifier 0x1102, serialNumber 0x1234, warningType
    # 0B02, dummy 50 octets 00..31 -> 450 bits.
    out=$(lair_cmd_build_sib10 --message-id 4354 --serial 4660 --warning-type 0B02 \
        --dummy 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031 2>/dev/null)
    chk pws10-dummy-hex  "$(fld "$out" hex)"           "4440848D02C080004080C1014181C2024282C3034383C4044484C5054585C6064686C7074787C8084888C9094989CA0A4A8ACB0B4B8BCC0C40"
    chk pws10-dummy-bits "$(fld "$out" bits_consumed)" "450"

    # ── SIB11: exact octets, pinned from pycrate ──────────────────────
    out=$(lair_cmd_build_sib11 --message-id 4660 --serial 22136 \
        --segment-type notLastSegment --segment-number 0 --segment DEADBEEF 2>/dev/null)
    chk pws11-hex  "$(fld "$out" hex)"            "048D159E00026F56DF7780"
    chk pws11-bits "$(fld "$out" bits_consumed)"  "81"
    chk pws11-seg  "$(printf '%s\n' "$out" | grep -c 'segment_number=0 segment_octets=4')" "1"
    out=$(lair_cmd_build_sib11 --message-id 4660 --serial 22136 \
        --segment-type lastSegment --segment-number 63 --segment 00 --data-coding 01 2>/dev/null)
    chk pws11-dcs-hex  "$(fld "$out" hex)"            "448D159E3F80800080"
    chk pws11-dcs-bits "$(fld "$out" bits_consumed)"  "65"

    # ── SIB12: exact octets, pinned from pycrate ──────────────────────
    out=$(lair_cmd_build_sib12 --message-id 17264 --serial 4369 \
        --segment-type notLastSegment --segment-number 0 --segment 90003C 2>/dev/null)
    chk pws12-hex  "$(fld "$out" hex)"            "086E02222000E4000F00"
    chk pws12-bits "$(fld "$out" bits_consumed)"  "74"
    out=$(lair_cmd_build_sib12 --message-id 17264 --serial 4369 \
        --segment-type lastSegment --segment-number 63 --segment FF0001 --data-coding 01 2>/dev/null)
    chk pws12-dcs-hex  "$(fld "$out" hex)"            "486E02223FC0FFC0004040"
    chk pws12-dcs-bits "$(fld "$out" bits_consumed)"  "82"

    # ── Extension group: lateNonCriticalExtension, Rel-15 warning area ──
    # pycrate: the optional lateNonCriticalExtension sits in the extension
    # group, so each of these is the bare-body pin above plus the extension
    # bit, the field bitmap and a length-prefixed octet string.
    out=$(lair_cmd_build_sib10 --message-id 4352 --serial 0 --warning-type 0001         --late-non-critical BB 2>/dev/null)
    chk pws10-late-hex  "$(fld "$out" hex)"           "8440000000004040806EC0"
    chk pws10-late-bits "$(fld "$out" bits_consumed)" "82"
    out=$(lair_cmd_build_sib11 --message-id 4660 --serial 22136 \
        --segment-type notLastSegment --segment-number 0 --segment DEADBEEF \
        --late-non-critical AA 2>/dev/null)
    chk pws11-late-hex  "$(fld "$out" hex)"           "848D159E00026F56DF77808100D500"
    chk pws11-late-bits "$(fld "$out" bits_consumed)" "113"
    out=$(lair_cmd_build_sib12 --message-id 17264 --serial 4369 \
        --segment-type lastSegment --segment-number 63 --segment FF0001 \
        --warning-area 0102 2>/dev/null)
    chk pws12-warea-hex  "$(fld "$out" hex)"           "886E02223FC0FFC00040412040204000"
    chk pws12-warea-bits "$(fld "$out" bits_consumed)" "122"
    chk pws12-warea-field "$(printf '%s\n' "$out" | grep -c 'warning_area_octets=2')" "1"

    # ── Round trip: the module's own decoder reads back what it wrote ──
    out=$(lair_decode_sib 04400000000040 10 2>/dev/null); rc=$?
    chk pws10-rt-rc     "$rc" "0"
    chk pws10-rt-mid    "$(fld "$out" messageIdentifier)" "0x1100 (16 bits)"
    chk pws10-rt-serial "$(fld "$out" serialNumber)"      "0x0000 (16 bits)"
    chk pws10-rt-wt     "$(fld "$out" warningType)"       "0001"
    out=$(lair_decode_sib 4440848D02C080004080C1014181C2024282C3034383C4044484C5054585C6064686C7074787C8084888C9094989CA0A4A8ACB0B4B8BCC0C40 10 2>/dev/null)
    chk pws10-dummy-rt-wt  "$(fld "$out" warningType)"  "0B02"
    chk pws10-dummy-rt-len "$(printf '%s\n' "$out" | awk -F'\t' '$1=="dummy"{print length($2)/2}')" "50"

    out=$(lair_decode_sib 048D159E00026F56DF7780 11 2>/dev/null); rc=$?
    chk pws11-rt-rc     "$rc" "0"
    chk pws11-rt-mid    "$(fld "$out" messageIdentifier)"           "0x1234 (16 bits)"
    chk pws11-rt-serial "$(fld "$out" serialNumber)"                "0x5678 (16 bits)"
    chk pws11-rt-type   "$(fld "$out" warningMessageSegmentType)"   "notLastSegment"
    chk pws11-rt-num    "$(fld "$out" warningMessageSegmentNumber)" "0"
    chk pws11-rt-seg    "$(fld "$out" warningMessageSegment)"       "DEADBEEF"
    out=$(lair_decode_sib 448D159E3F80800080 11 2>/dev/null)
    chk pws11-dcs-rt-type "$(fld "$out" warningMessageSegmentType)" "lastSegment"
    chk pws11-dcs-rt-num  "$(fld "$out" warningMessageSegmentNumber)" "63"
    chk pws11-dcs-rt-dcs  "$(fld "$out" dataCodingScheme)"          "01"

    out=$(lair_decode_sib 086E02222000E4000F00 12 2>/dev/null); rc=$?
    chk pws12-rt-rc     "$rc" "0"
    chk pws12-rt-mid    "$(fld "$out" messageIdentifier-r9)"          "0x4370 (16 bits)"
    chk pws12-rt-serial "$(fld "$out" serialNumber-r9)"               "0x1111 (16 bits)"
    chk pws12-rt-type   "$(fld "$out" warningMessageSegmentType-r9)"  "notLastSegment"
    chk pws12-rt-num    "$(fld "$out" warningMessageSegmentNumber-r9)" "0"
    chk pws12-rt-seg    "$(fld "$out" warningMessageSegment-r9)"      "90003C"
    out=$(lair_decode_sib 486E02223FC0FFC0004040 12 2>/dev/null)
    chk pws12-dcs-rt-type "$(fld "$out" warningMessageSegmentType-r9)"  "lastSegment"
    chk pws12-dcs-rt-num  "$(fld "$out" warningMessageSegmentNumber-r9)" "63"
    chk pws12-dcs-rt-dcs  "$(fld "$out" dataCodingScheme-r9)"           "01"

    out=$(lair_decode_sib 848D159E00026F56DF77808100D500 11 2>/dev/null)
    chk pws11-late-rt "$(fld "$out" lateNonCriticalExtension)" "AA"
    out=$(lair_decode_sib 886E02223FC0FFC00040412040204000 12 2>/dev/null)
    chk pws12-warea-rt "$(fld "$out" warningAreaCoordinatesSegment-r15)" "0102"

    # ── Rejected inputs ───────────────────────────────────────────────
    chk pws10-bad-hex  "$(lair_cmd_build_sib10 --message-id 4352 --serial 0 --warning-type 0001 --dummy 00 >/dev/null 2>&1; echo $?)" "2"
    chk pws11-bad-num  "$(lair_cmd_build_sib11 --message-id 1 --serial 1 --segment-type lastSegment --segment-number 64 --segment 00 >/dev/null 2>&1; echo $?)" "2"
    chk pws11-no-seg   "$(lair_cmd_build_sib11 --message-id 1 --serial 1 --segment-type lastSegment --segment-number 0 --payload XY >/dev/null 2>&1; echo $?)" "2"
    # The codec drops a key the type does not have, so the flag has to be
    # refused here or the message would silently not carry it.
    chk pws11-warea-refused "$(lair_cmd_build_sib11 --message-id 1 --serial 1 --segment-type lastSegment --segment-number 0 --segment 00 --warning-area 0102 >/dev/null 2>&1; echo $?)" "2"

    # ── The eNB side: refuse release_23_11, emit for master ───────────
    d1=$(mktemp -d "$MOD_TMP/pws.XXXXXX") || { chk pws-sched-mktemp 1 0; return 1; }

    out=$(lair_cmd_enb_sib_schedule --sib 10 --hex 04400000000040 --out "$d1" 2>"$d1/err"); rc=$?
    chk sched-default-rc      "$rc" "2"
    chk sched-default-error   "$(grep -c '^ERROR' "$d1/err")" "1"
    chk sched-default-version "$(grep -c 'release_23_11 registers sib.conf sections' "$d1/err")" "1"
    chk sched-default-missing "$(grep -c 'the missing link is' "$d1/err")" "1"
    chk sched-default-accepts "$(grep -c 'sib1, sib2, sib3, sib4, sib5, sib6, sib7, sib9, sib13 only' "$d1/err")" "1"
    chk sched-default-noconf  "$(ls "$d1" | grep -c 'sib.conf.fragment')" "0"
    chk sched-default-sent    "$(fld "$out" sent)" "0"
    chk sched-default-limit   "$(printf '%s\n' "$out" | grep -c 'lawful basis')" "1"

    d2=$(mktemp -d "$MOD_TMP/pws.XXXXXX") || { chk pws-sched-mktemp2 1 0; rm -rf "$d1"; return 1; }
    out=$(lair_cmd_enb_sib_schedule --sib 10 --hex 04400000000040 --out "$d2" --srsran-version master 2>/dev/null); rc=$?
    chk sched10-rc        "$rc" "0"
    chk sched10-section   "$(grep -c '^sib10 =$' "$d2/sib.conf.fragment")" "1"
    chk sched10-mid       "$(grep -c '^    message_id = 0x1100;$' "$d2/sib.conf.fragment")" "1"
    chk sched10-serial    "$(grep -c '^    serial_num = 0x0000;$' "$d2/sib.conf.fragment")" "1"
    chk sched10-wt        "$(grep -c '^    warning_type = 0x0001;$' "$d2/sib.conf.fragment")" "1"
    chk sched10-sched-key "$(grep -c 'si_mapping_info = \[ 10 \]' "$d2/sib.conf.fragment")" "1"
    chk sched10-verified  "$(printf '%s\n' "$out" | grep -c '^version_verified	srsRAN_4G master')" "1"
    chk sched10-octets    "$(xxd -p "$d2/sib10.octets" | tr -d '\n')" "04400000000040"

    out=$(lair_cmd_enb_sib_schedule --sib 11 --hex 448D159E3F80800080 \
        --warning-message 'mayday test' --out "$d2" --srsran-version master 2>/dev/null); rc=$?
    chk sched11-rc      "$rc" "0"
    chk sched11-section "$(grep -c '^sib11 =$' "$d2/sib.conf.fragment")" "1"
    chk sched11-dcs     "$(grep -c '^    data_coding_scheme = 0x01;$' "$d2/sib.conf.fragment")" "1"
    chk sched11-wmsg    "$(grep -c '^    warning_message = "mayday test";$' "$d2/sib.conf.fragment")" "1"
    chk sched11-sched   "$(grep -c 'si_mapping_info = \[ 11 \]' "$d2/sib.conf.fragment")" "1"

    out=$(lair_cmd_enb_sib_schedule --sib 12 --hex 486E02223FC0FFC0004040 \
        --warning-message 'test alert' --out "$d2" --srsran-version master 2>/dev/null); rc=$?
    chk sched12-rc      "$rc" "0"
    chk sched12-section "$(grep -c '^sib12 =$' "$d2/sib.conf.fragment")" "1"
    chk sched12-sched   "$(grep -c 'si_mapping_info = \[ 12 \]' "$d2/sib.conf.fragment")" "1"

    # SIB11 without a data coding scheme cannot be scheduled: srsRAN's
    # parser marks data_coding_scheme present and encodes with it.
    chk sched11-nodcs "$(lair_cmd_enb_sib_schedule --sib 11 --hex 048D159E00026F56DF7780 \
        --warning-message x --out "$d2" --srsran-version master >/dev/null 2>&1; echo $?)" "2"
    chk sched11-nodcs-why "$(lair_cmd_enb_sib_schedule --sib 11 --hex 048D159E00026F56DF7780 \
        --warning-message x --out "$d2" --srsran-version master 2>&1 >/dev/null | grep -c 'data-coding')" "1"
    chk sched12-nowmsg "$(lair_cmd_enb_sib_schedule --sib 12 --hex 486E02223FC0FFC0004040 \
        --out "$d2" --srsran-version master 2>&1 >/dev/null | grep -c 'warning_message')" "1"
    chk sched-bad-sib "$(lair_cmd_enb_sib_schedule --sib 9 --hex 00 --srsran-version master >/dev/null 2>&1; echo $?)" "2"
    chk sched-bad-hex "$(lair_cmd_enb_sib_schedule --sib 10 --hex 044 >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d1" "$d2"
    return 0
}
