#!/usr/bin/env bash
# Referee for the UTRAN RRC forging verbs in modules/08_umts_air.sh.
#
# The module can state that its bits are placed per TS 25.331, but it cannot
# prove it: an encoder and its own length table agree with each other by
# construction. The one independent reader on this machine is Wireshark's RRC
# dissector, so this runner takes the module's octets, wraps them in a GSMTAP
# datagram (measurement plane type 12, UMTS RRC) inside a UDP/4729 packet, and
# asks tshark what it sees. A message that dissects to the intended type with
# the intended field values is proven; one that tshark calls
# [Malformed Packet: RRC] is a failure, not a warning.
#
# The runner also holds itself to the same standard: for every message it
# corrupts the top-level CHOICE index and requires tshark either to reject the
# octets or to name a different message. Without that control the pass lines
# above would prove only that tshark reads octets, not that this checker can
# fail.

set -u

# Paths are resolved with shell builtins only, so that a thin PATH cannot make
# this runner fail in a confusing way before it has decided whether the referee
# is even present.
src=${BASH_SOURCE[0]}
case "$src" in
    */*) srcdir=${src%/*} ;;
    *)   srcdir=. ;;
esac
here=$(cd -- "$srcdir" && pwd) || exit 1
root=${here%/*}
mod="$root/modules/08_umts_air.sh"

# tshark 4.2.2 carries the RRC dissector; without it these octets cannot be
# proven, and printing PASS on no evidence is the failure mode this whole
# runner exists to avoid. This decision comes before any temporary file, so a
# machine without tshark gets SKIP and exit 2 rather than a broken run.
tshark=$(type -P tshark || true)
if [[ -z "$tshark" ]]; then
    printf 'SKIP\tno tshark: the UMTS RRC dissector is the referee, so nothing is claimed\n'
    exit 2
fi

if [[ ! -f "$mod" ]]; then
    printf 'ERROR\t%s is missing\n' "$mod" >&2
    printf 'WHY\tthere is nothing to referee\n' >&2
    exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/umts-rrc-check.XXXXXX" 2>/dev/null) || tmp=""
if [[ -z "$tmp" ]]; then
    tmp="${TMPDIR:-/tmp}/umts-rrc-check.$$"
    mkdir -p "$tmp" || exit 1
fi
trap 'rm -rf "$tmp"' EXIT

checks=0
fails=0

pass() { checks=$(( checks + 1 )); printf 'check\t%s\tPASS\n' "$1"; }
fail() { checks=$(( checks + 1 )); fails=$(( fails + 1 )); printf 'check\t%s\tFAIL\n' "$1"; }

# One pcap with one packet: pcap magic little endian, linktype 101 raw IP (no
# ethernet header to get wrong), IPv4/UDP 4729 loopback, then the 16-octet
# GSMTAP header. Octet 12 of that header is gsmtap.rrc_sub_type and selects
# which top-level RRC SEQUENCE the dissector assumes, which is exactly the
# distinction a receiver makes from the logical channel it is listening to.
pb() { printf '%b' "\\x$(printf '%02x' "$1")"; }
pcap_make() {  # outfile sub_type hex
    local out="$1" st="$2" hex="$3" i ulen tot
    ulen=$(( 8 + 16 + ${#hex} / 2 ))
    tot=$(( 20 + ulen ))
    {
        pb 0xd4; pb 0xc3; pb 0xb2; pb 0xa1; pb 0x02; pb 0x00; pb 0x04; pb 0x00
        pb 0; pb 0; pb 0; pb 0; pb 0; pb 0; pb 0; pb 0
        pb 0xff; pb 0xff; pb 0x00; pb 0x00
        pb 0x65; pb 0; pb 0; pb 0
        pb 0; pb 0; pb 0; pb 0
        pb 0; pb 0; pb 0; pb 0
        pb $(( tot & 255 )); pb $(( tot >> 8 )); pb 0; pb 0
        pb $(( tot & 255 )); pb $(( tot >> 8 )); pb 0; pb 0
        pb 0x45; pb 0x00; pb $(( tot >> 8 )); pb $(( tot & 255 ))
        pb 0; pb 0; pb 0; pb 0; pb 64; pb 17; pb 0; pb 0
        pb 127; pb 0; pb 0; pb 1; pb 127; pb 0; pb 0; pb 1
        pb 0x12; pb 0x79; pb 0x12; pb 0x79
        pb $(( ulen >> 8 )); pb $(( ulen & 255 )); pb 0; pb 0
        pb 0x02; pb 0x04; pb 0x0c; pb 0x00; pb 0; pb 0; pb 0; pb 0
        pb 0; pb 0; pb 0; pb 0; pb "$st"; pb 0; pb 0; pb 0
        for (( i = 0; i < ${#hex}; i += 2 )); do pb $(( 16#${hex:i:2} )); done
    } > "$out"
}

dissect() { "$tshark" -r "$1" -V 2>&1; }

has() {  # text, literal
    case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac
}

# The configurations are explicit rather than the module's defaults, so that a
# change of default cannot silently move what this runner asserts.
setup_conf="$tmp/setup.conf"
reject_conf="$tmp/reject.conf"
paging_conf="$tmp/paging.conf"
cat > "$setup_conf" <<'CONF'
tmsi=12345678
lac=0001
mcc=001
mnc=01
txid=0
srnc=123
srnti=12345
drx=6
state=cell-DCH
CONF
cat > "$reject_conf" <<'CONF'
tmsi=12345678
lac=0001
mcc=001
mnc=01
txid=0
cause=congestion
wait=8
CONF
cat > "$paging_conf" <<'CONF'
tmsi=12345678
cause=terminatingConversationalCall
domain=cs
mib=1
CONF

# Known answers, produced independently from pycrate's transcription of the
# TS 25.331 ASN.1 and then dissected here. They are repeated so that a change in
# the module's bit placement cannot pass by agreeing with itself.
kat_setup=300022468acf0002010001048c48d147818c2e41b01a00108008601a00528018a01a00948028e01a00d680300020800618663600008200186198d8
kat_reject=10448d159e000402000220
kat_paging=60022468acf000

# build name conf sub_type hex_row
build() {  # name -> sets built_hex, built_bits
    local name="$1" conf="$2"
    local out
    out=$(bash "$mod" "$name" "$conf" 2>"$tmp/$name.err")
    built_rc=$?
    built_hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="hex"{print $2}')
    built_bits=$(printf '%s\n' "$out" | awk -F'\t' '$1=="bits"{print $2}')
    built_type=$(printf '%s\n' "$out" | awk -F'\t' '$1=="message_type"{print $2}')
    built_sent=$(printf '%s\n' "$out" | awk -F'\t' '$1=="sent"{print $2}')
    built_limits=$(printf '%s\n' "$out" | awk -F'\t' '$1=="limit"' | grep -c .)
}

referee() {  # label sub_type hex expected_message_type expected_subtype_label
    local label="$1" st="$2" hex="$3" want_type="$4" want_chan="$5"
    local pcap="$tmp/$label.pcap" out
    pcap_make "$pcap" "$st" "$hex"
    out=$(dissect "$pcap")
    if has "$out" "Message Type: $want_chan"; then
        pass "$label-channel"
    else
        fail "$label-channel"
    fi
    if has "$out" "message: $want_type ("; then
        pass "$label-type"
    else
        fail "$label-type"
    fi
    if has "$out" '[Malformed Packet: RRC]'; then
        fail "$label-not-malformed"
    else
        pass "$label-not-malformed"
    fi
}

# ── RRC CONNECTION SETUP, DL-CCCH ────────────────────────────────────────────
# TS 25.331 10.2.43: RRCConnectionSetup is versioned, r3 carrying the IEs. A UE
# in the state this message describes has a U-RNTI, an SRB list and one DCH.
build --build-rrc-setup "$setup_conf"
if (( built_rc == 0 )) && [[ -n "$built_hex" ]]; then
    pass setup-builds
else
    fail setup-builds
fi
if [[ "$built_hex" == "$kat_setup" ]]; then
    pass setup-known-answer
else
    fail setup-known-answer
fi
if [[ "$built_sent" == "0" ]]; then pass setup-sent-0; else fail setup-sent-0; fi
if (( built_limits >= 1 )); then pass setup-limit-row; else fail setup-limit-row; fi
if [[ "$built_type" == "rrcConnectionSetup" ]]; then
    pass setup-module-type
else
    fail setup-module-type
fi
referee setup 2 "$built_hex" rrcConnectionSetup "RRC DL-CCCH (2)"
out=$(dissect "$tmp/setup.pcap")
for want in "tmsi: 12345678" "lac: 0001" "rrc-StateIndicator: cell-DCH (0)" \
            "utran-DRX-CycleLengthCoeff: 6" "srb-InformationSetupList: 4 items" \
            "rateMatchingAttribute: 100" "tti: tti20 (1)"; do
    if has "$out" "$want"; then pass "setup-field[$want]"; else fail "setup-field[$want]"; fi
done
# The module's own parser must read back what tshark reads, or the two
# directions of this module disagree about the same octets.
mod_view=$(bash "$mod" --parse-rrc "dl-ccch:$built_hex" 2>/dev/null)
if has "$mod_view" "tmsi-and-LAI"; then pass setup-parse-identity; else fail setup-parse-identity; fi
if has "$mod_view" "srb_information_setup_list	4"; then pass setup-parse-srb; else fail setup-parse-srb; fi

# ── RRC CONNECTION REJECT, DL-CCCH ──────────────────────────────────────────
# The wait time is why this message exists: rejectionCause plus WaitTime
# INTEGER(0..15), TS 25.331 10.2.42.
build --build-rrc-reject "$reject_conf"
if (( built_rc == 0 )) && [[ -n "$built_hex" ]]; then
    pass reject-builds
else
    fail reject-builds
fi
if [[ "$built_hex" == "$kat_reject" ]]; then
    pass reject-known-answer
else
    fail reject-known-answer
fi
referee reject 2 "$built_hex" rrcConnectionReject "RRC DL-CCCH (2)"
out=$(dissect "$tmp/reject.pcap")
for want in "rejectionCause: congestion (0)" "waitTime: 8" "tmsi: 12345678"; do
    if has "$out" "$want"; then pass "reject-field[$want]"; else fail "reject-field[$want]"; fi
done

# ── PAGING TYPE 1, PCCH ─────────────────────────────────────────────────────
build --build-paging "$paging_conf"
if (( built_rc == 0 )) && [[ -n "$built_hex" ]]; then
    pass paging-builds
else
    fail paging-builds
fi
if [[ "$built_hex" == "$kat_paging" ]]; then
    pass paging-known-answer
else
    fail paging-known-answer
fi
referee paging 4 "$built_hex" pagingType1 "RRC PCCH (4)"
out=$(dissect "$tmp/paging.pcap")
for want in "pagingCause: terminatingConversationalCall (0)" \
            "cn-pagedUE-Identity: tmsi-GSM-MAP (1)" "tmsi-GSM-MAP: 12345678" \
            "pagingRecordList: 1 item"; do
    if has "$out" "$want"; then pass "paging-field[$want]"; else fail "paging-field[$want]"; fi
done

# ── UPLINK, parsed rather than built, still refereed ────────────────────────
# A measurement report with a present integrityCheckInfo (TS 25.331 10.3.2.4)
# is the case where the channel envelope's presence bit comes BEFORE the type
# index; misordering them yields a plausible, wrong message type.
kat_ic=ef56df779a0000
pcap_make "$tmp/ic.pcap" 1 "$kat_ic"
out=$(dissect "$tmp/ic.pcap")
if has "$out" "message: measurementReport (8)"; then pass ic-type; else fail ic-type; fi
if has "$out" "rrc-MessageSequenceNumber: 3"; then pass ic-sequence; else fail ic-sequence; fi
mod_view=$(bash "$mod" --parse-rrc "ul-dcch:$kat_ic" 2>/dev/null)
if has "$mod_view" "message_authentication_code	deadbeef"; then
    pass ic-module-mac
else
    fail ic-module-mac
fi
kat_req=2112345678001008000b00
pcap_make "$tmp/req.pcap" 3 "$kat_req"
out=$(dissect "$tmp/req.pcap")
if has "$out" "message: rrcConnectionRequest (1)"; then pass req-type; else fail req-type; fi
if has "$out" "establishmentCause: registration (12)"; then pass req-cause; else fail req-cause; fi

# ── Negation controls ───────────────────────────────────────────────────────
# Each control moves exactly the top-level CHOICE index and nothing else. If
# the checks above were vacuous, these would pass too; they must not.
# Setup: index 3 (rrcConnectionSetup) -> 5 (dummy). First octet 0x30 -> 0x50.
neg_setup="50${kat_setup:2}"
pcap_make "$tmp/neg_setup.pcap" 2 "$neg_setup"
out=$(dissect "$tmp/neg_setup.pcap")
if has "$out" "message: rrcConnectionSetup ("; then
    fail neg-setup-reclassified
else
    pass neg-setup-reclassified
fi
if has "$out" "message: dummy (5)" || has "$out" '[Malformed Packet: RRC]'; then
    pass neg-setup-honest
else
    fail neg-setup-honest
fi
# Reject: index 1 -> 3 (rrcConnectionSetup), first octet 0x10 -> 0x30. The same
# octets must now be called a different message, which shows the index is what
# carries the type.
neg_reject="30${kat_reject:2}"
pcap_make "$tmp/neg_reject.pcap" 2 "$neg_reject"
out=$(dissect "$tmp/neg_reject.pcap")
if has "$out" "message: rrcConnectionReject ("; then
    fail neg-reject-reclassified
else
    pass neg-reject-reclassified
fi
if has "$out" "message: rrcConnectionSetup (3)" || has "$out" '[Malformed Packet: RRC]'; then
    pass neg-reject-honest
else
    fail neg-reject-honest
fi
# Paging: index 0 (pagingType1) -> 1 (spare), first octet 0x60 -> 0xe0.
neg_paging="e0${kat_paging:2}"
pcap_make "$tmp/neg_paging.pcap" 4 "$neg_paging"
out=$(dissect "$tmp/neg_paging.pcap")
if has "$out" "message: pagingType1 ("; then
    fail neg-paging-reclassified
else
    pass neg-paging-reclassified
fi
if has "$out" "[Malformed Packet: RRC]" || has "$out" "spare (1)"; then
    pass neg-paging-honest
else
    fail neg-paging-honest
fi

# ── Verdict ────────────────────────────────────────────────────────────────
if (( fails > 0 )); then
    printf 'FAILED\t%s of %s checks\n' "$fails" "$checks"
    exit 1
fi
printf 'CHECKS\t%s\tPASS\n' "$checks"
exit 0
