#!/usr/bin/env bash
# Cellular layer-2 observation — the LTE MAC/RLC/PDCP chain and what its
# addressing reveals.
#
# Owns ATTACK_COVERAGE.md P9 (MAC-layer passive) alongside 21_pcap_analysis.
# Everything here is offline: a hex MAC PDU from stdin, or a pcap on disk.
# No radio, no root, no network.
#
# Field width, because this is the constant an implementation gets wrong:
# the LTE MAC subheader's LCID field is SIX bits (bits 7..2 of the first
# octet), R is bit 1 and E is bit 0, so the LCID space is 0..63. The UL-SCH
# table assigns 52..63, which no five-bit field can hold; a decoder that
# masks five bits reports those entries as 20..31 and looks correct while
# naming the wrong logical channel. Encoding is
# octet0 = (LCID << 2) | (R << 1) | E.
#
# ---------------------------------------------------------------------------
# The integrity gap, stated exactly
#
#   In LTE, the USER PLANE has no integrity protection. The PDCP layer
#   applies ciphering only to DRBs; there is no MAC-I over the payload, so a
#   bit-flipped ciphertext decrypts to a bit-flipped plaintext with no
#   detection at the receiver. That is the whole precondition for aLTEr
#   (ATTACK_COVERAGE.md O10, owned by 32_cellular_dns): an on-path attacker
#   can rewrite the plaintext of a DNS response inside the user plane and
#   neither the UE nor the network notices.
#
#   The CONTROL PLANE is different. RRC signalling and NAS messages carry
#   integrity protection (the PDCP MAC-I for SRBs, and NAS integrity for NAS
#   messages), so a forged control message is rejected.
#
#   Saying "LTE has no integrity" without that qualifier is wrong, and this
#   module's --integrity-gap output must state both halves. The selftest
#   fails if a report ever claims the gap applies to the control plane too.
#
#   This module documents and DETECTS the gap. It does not perform the
#   redirection — that is module 32.
# ---------------------------------------------------------------------------
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

# Under pkexec HOME=/root even though we write to the invoking user's tree.
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

MOD_TMP="$TMP_DIR/mac_layer"
MACL_DIR="$LOOT_DIR/mac_layer"
MACL_RNTI="$MACL_DIR/rnti.tsv"
MACL_SCHED="$MACL_DIR/schedule.tsv"
mkdir -p "$MOD_TMP" "$MACL_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
# A capture is attacker-controlled by definition: a hex dump or a cell
# identity can carry a tab and forge a whole row in a consumer that splits
# on tab. Tabs, CR and LF become spaces.
macl_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# Split a TSV line into the global array MACL_F, preserving empty fields.
# `read` with IFS=tab treats tab as whitespace and collapses runs of it, so
# a row with an empty column shifts every field after it. cut -f does not.
MACL_F=()
macl_split() {
    MACL_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        MACL_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── LTE MAC LCID tables ─────────────────────────────────────────────────
# 3GPP TS 36.321 Table 6.2.1-1 (DL-SCH) and Table 6.2.1-2 (UL-SCH). These
# values are the spec's, not this module's: a wrong LCID here would name
# the wrong logical channel on every capture, so the selftest asserts them
# individually rather than trusting the table's own lookup.
#
# Field width: the LCID field is SIX bits (bits 7..2 of the first octet),
# so the space is 0..63. The UL-SCH table is why this matters: it assigns
# 52..63, which a five-bit field cannot hold. Decoding with a five-bit mask
# silently reports those entries as 20..31 instead - a plausible wrong
# answer, which is exactly the failure mode this tree writes tests about.
# Encoding: first_octet = (LCID << 2) | (R << 1) | E, with R = 0.
#
# DL-SCH (Table 6.2.1-1):
#   0        CCCH
#   1-10     Identity of the logical channel (LCID 1..10)
#   11-14    Reserved
#   15       Padding
# UL-SCH (Table 6.2.1-2):
#   0        CCCH
#   1-10     Identity of the logical channel
#   11       CCCH (again: LCID 11 is a second CCCH entry in the UL table
#            when the UE has no C-RNTI; note it rather than hiding it)
#   12-14    Reserved
#   15       Padding
#   52       CCCH
#   53       Contention Resolution Identity
#   54       Timing Advance Command
#   55       DRX Command
#   56       UE Contention Resolution Identity
#   57       Recommended bit rate (see note below)
#   58       Recommended bit rate query
#   59       Configured grant confirmation
#   60       C-RNTI / (SC-PTM)
#   61       C-RNTI / (SC-PTM)
#   62       C-RNTI / (SC-PTM)
#   63       Padding
#
# The module supports both directions explicitly: the caller passes --ul or
# --dl, because LCID 15 and 63 both mean padding and 11 means reserved in
# one table and CCCH in the other. Guessing a direction produces a
# confidently wrong channel name, which is exactly the failure this tree
# writes comments about.
macl_lcid_name() {
    local lcid="${1:-}" dir="${2:-dl}"
    [[ "$lcid" =~ ^[0-9]+$ ]] || { echo "unknown"; return 1; }
    # The LCID field is six bits wide, so 0..63 is the whole space. A value
    # above 63 is not an LCID at all and must not be coerced into one.
    if (( lcid < 0 || lcid > 63 )); then
        echo "unknown"
        return 1
    fi
    if [[ "$dir" == "ul" ]]; then
        case "$lcid" in
            0)  echo "CCCH" ;;
            1|2|3|4|5|6|7|8|9|10) echo "Logical channel $lcid" ;;
            11) echo "CCCH" ;;
            12|13|14) echo "Reserved" ;;
            15) echo "Padding" ;;
            52) echo "CCCH" ;;
            53) echo "Contention Resolution Identity" ;;
            54) echo "Timing Advance Command" ;;
            55) echo "DRX Command" ;;
            56) echo "UE Contention Resolution Identity" ;;
            57) echo "Recommended bit rate" ;;
            58) echo "Recommended bit rate query" ;;
            59) echo "Configured grant confirmation" ;;
            60|61|62) echo "C-RNTI/SC-PTM" ;;
            63) echo "Padding" ;;
            *)  echo "unknown" ;;
        esac
    else
        case "$lcid" in
            0)  echo "CCCH" ;;
            1|2|3|4|5|6|7|8|9|10) echo "Logical channel $lcid" ;;
            11|12|13|14) echo "Reserved" ;;
            15) echo "Padding" ;;
            *)  echo "unknown" ;;
        esac
    fi
}

# MAC CE payload lengths in bytes, where the spec fixes them. A CE with a
# fixed length must be checked against it: a length that disagrees means
# the subheader chain has desynchronised and every later SDU boundary in
# the PDU is wrong.
macl_ce_len() {
    local lcid="${1:-}"
    case "$lcid" in
        53|56) echo 6 ;;     # contention resolution identity, 48 bits
        54)    echo 1 ;;     # timing advance command, 6 bits used
        55)    echo 1 ;;     # DRX command
        59)    echo 1 ;;     # configured grant confirmation
        57|58) echo 1 ;;     # recommended bit rate (1 byte)
        *)     echo "" ;;
    esac
}

# Timing Advance Command MAC CE (TS 36.321 §6.1.3.4): a 1-byte CE whose
# top 2 bits are the CE tag and whose low 6 bits are the TA index. The
# index maps to a timing adjustment by TS 36.213 Table 4.2.3-1; the
# mapping depends on the TA group's current value, so this module reports
# the index and its 2-bit tag, not a fabricated nanosecond figure.
macl_ta_fields() {
    local byte="${1:-}"
    [[ "$byte" =~ ^[0-9A-Fa-f]{1,2}$ ]] || { return 1; }
    local v=$(( 16#$byte ))
    printf 'tag\t%d\nindex\t%d\n' "$(( (v >> 6) & 0x3 ))" "$(( v & 0x3F ))"
}

# ── RNTI tables ─────────────────────────────────────────────────────────
# TS 36.321 §7.1 and TS 36.211 §6.11 / TS 36.212. The fixed values are the
# spec's; the ranges are the assignment rules. 0 is reserved and is not a
# valid RNTI: a decoder that maps 0 to "C-RNTI" is reporting a parse
# failure as a device.
macl_rnti_class() {
    local rnti="${1:-}"
    [[ "$rnti" =~ ^(0[xX])?[0-9A-Fa-f]{1,4}$ ]] || { echo "invalid"; return 1; }
    local v
    if [[ "$rnti" == 0x* || "$rnti" == 0X* ]]; then
        v=$(( rnti ))
    else
        v=$(( 16#$rnti ))
    fi
    if (( v == 0 )); then
        echo "reserved"
    elif (( v == 0xFFFF )); then
        echo "SI-RNTI"
    elif (( v == 0xFFFE )); then
        echo "P-RNTI"
    elif (( v >= 0xFFF0 && v <= 0xFFFD )); then
        echo "reserved"
    elif (( v >= 0x0001 && v <= 0x003C )); then
        echo "RA-RNTI"
    elif (( v >= 0x003D && v <= 0x3FFF )); then
        echo "C-RNTI"
    elif (( v >= 0x4000 && v <= 0xFFEF )); then
        echo "C-RNTI"
    else
        echo "reserved"
    fi
}

macl_rnti_value() {
    local rnti="${1:-}"
    [[ "$rnti" =~ ^(0[xX])?[0-9A-Fa-f]{1,4}$ ]] || { return 1; }
    if [[ "$rnti" == 0x* || "$rnti" == 0X* ]]; then
        printf '%d' "$(( rnti ))"
    else
        printf '%d' "$(( 16#$rnti ))"
    fi
}

macl_rnti_meaning() {
    case "$(macl_rnti_class "${1:-}")" in
        reserved)  echo "reserved by TS 36.321 - not an assigned device" ;;
        SI-RNTI)   echo "system information broadcast (SIB1/SI), fixed 0xFFFF" ;;
        P-RNTI)    echo "paging and system information change notification, fixed 0xFFFE" ;;
        RA-RNTI)   echo "random-access response, derived from the PRACH occasion and temporary" ;;
        C-RNTI)    echo "assigned by the eNB in the random-access response or an RRC reconfiguration; persists for the RRC connection" ;;
        invalid)   echo "not a 16-bit RNTI" ;;
        *)         echo "unknown" ;;
    esac
}

# ── MAC PDU decode (python) ─────────────────────────────────────────────
# The subheader chain is walked in python because the parse is
# length-driven and byte-exact, and a bash loop over hex substrings is the
# wrong tool. The walker is strict: any inconsistency is an error, never a
# partially decoded PDU presented as complete.
macl_engine_py() {
    cat << 'PYEOF'
#!/usr/bin/env python3
"""LTE MAC PDU decoder and RNTI/scheduling helpers.

Implements TS 36.321 §6.1.2 (MAC PDU) and §6.2.1 (subheaders). The
direction (DL-SCH / UL-SCH) is an explicit argument because LCID 11 and
LCID 15 mean different things in the two tables.

Emits TSV with a leading record-type column. Every failure is an error to
stderr with a reason, and the exit status is non-zero.
"""
import sys
import os
import math
import struct

# TS 36.321 Table 6.2.1-1 (DL-SCH) and Table 6.2.1-2 (UL-SCH).
# Values are the spec's; see the shell-side copies for the prose.
DL_LCID = {0: "CCCH", 15: "Padding"}
UL_LCID = {0: "CCCH", 11: "CCCH", 15: "Padding", 52: "CCCH",
           53: "Contention Resolution Identity",
           54: "Timing Advance Command", 55: "DRX Command",
           56: "UE Contention Resolution Identity",
           57: "Recommended bit rate", 58: "Recommended bit rate query",
           59: "Configured grant confirmation",
           60: "C-RNTI/SC-PTM", 61: "C-RNTI/SC-PTM", 62: "C-RNTI/SC-PTM",
           63: "Padding"}
DL_RESERVED = set(range(11, 15))
UL_RESERVED = set(range(12, 15))
# Fixed CE payload lengths in bytes (TS 36.321 §6.1.3).
CE_LEN = {53: 6, 56: 6, 54: 1, 55: 1, 59: 1, 57: 1, 58: 1}


def out(*fields):
    sys.stdout.write("\t".join("" if f is None else str(f) for f in fields) + "\n")


def err(msg):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.stderr.flush()


def lcid_name(lcid, direction):
    if direction == "ul":
        if lcid in UL_LCID:
            return UL_LCID[lcid]
        if 1 <= lcid <= 10:
            return "Logical channel %d" % lcid
        if lcid in UL_RESERVED:
            return "Reserved"
        return "unknown"
    if lcid in DL_LCID:
        return DL_LCID[lcid]
    if 1 <= lcid <= 10:
        return "Logical channel %d" % lcid
    if lcid in DL_RESERVED:
        return "Reserved"
    return "unknown"


def decode_mac(hexstr, direction):
    """Decode a MAC PDU into subheaders and payload segments.

    Subheader layout (TS 36.321 6.1.2). Two layouts, both encoded in the
    first two octets, MSB-first within each octet:

        octet0: LCID(6) R E          bits 7..2 LCID, bit 1 R, bit 0 E
        octet1: L(7)    F            bits 7..1 the seven high bits of L,
                                     bit 0 F
        octet2: L(8)                 the eight low bits of L, only if F=1

    So: E is bit 0 of the first octet; F is bit 0 of the second octet; the
    7-bit length lives in bits 1..7 of the second octet; when F=1 the third
    octet carries the remaining eight length bits, MSB first, giving a
    15-bit L. The final subheader of a PDU has E=0. A padding subheader
    (LCID 15 on DL-SCH, 63 on UL-SCH) has no length field and is one octet.

    The payload segments then follow the whole header chain, in the order
    the subheaders appear. A subheader octet is NOT a payload byte: walking
    the chain and consuming payload as you go desynchronises the moment a
    payload byte has E=0, which is half of them.
    """
    h = hexstr.strip().replace(":", "").replace(" ", "").replace("-", "")
    if not h:
        raise ValueError("empty MAC PDU")
    if len(h) % 2 != 0:
        raise ValueError("MAC PDU hex has an odd number of nibbles (%d) - "
                         "a PDU is an octet string" % len(h))
    try:
        b = bytes.fromhex(h)
    except ValueError as e:
        raise ValueError("MAC PDU is not valid hex: %s" % e)
    if len(b) < 1:
        raise ValueError("MAC PDU is empty")
    pad_lcid = 15 if direction == "dl" else 63
    pos = 0
    subs = []
    while True:
        if pos >= len(b):
            raise ValueError("subheader chain runs to the end of the PDU "
                             "without an E=0 terminator - the PDU is "
                             "truncated or not a MAC PDU")
        octet0 = b[pos]
        # LCID is the upper six bits; E is bit 0 and R is bit 1. A 5-bit
        # mask ((octet0 >> 3) & 0x1F) cannot represent the UL-SCH table's
        # 52..63 entries at all, so it is not a narrower reading of the same
        # field - it is the wrong field width.
        lcid = (octet0 >> 2) & 0x3F
        e = octet0 & 0x01
        if lcid == pad_lcid:
            # Padding subheader: one octet, no length field. It ends the
            # chain only when its own E bit is 0; a padding octet in the
            # middle of a chain is legal and must not truncate the decode.
            subs.append({"lcid": lcid, "f": 0, "len": None, "e": e,
                         "header_bytes": 1, "offset": pos})
            pos += 1
            if not e:
                break
            continue
        if pos + 1 >= len(b):
            raise ValueError("subheader at byte %d is truncated: the LCID "
                             "octet needs a following F/L octet" % pos)
        octet1 = b[pos + 1]
        f = octet1 & 0x01
        if f:
            if pos + 2 >= len(b):
                raise ValueError("subheader at byte %d declares a 16-bit "
                                 "length (F=1) but the PDU ends first" % pos)
            length = (octet1 >> 1) | (b[pos + 2] << 7)
            hbytes = 3
        else:
            length = (octet1 >> 1) & 0x7F
            hbytes = 2
        if length == 0 and lcid != pad_lcid:
            raise ValueError("subheader at byte %d (LCID %d) declares a zero "
                             "payload length - the chain is not a valid MAC "
                             "PDU header" % (pos, lcid))
        subs.append({"lcid": lcid, "f": f, "len": length,
                     "header_bytes": hbytes, "offset": pos, "e": e})
        pos += hbytes
        if not e:
            break
    if not subs:
        raise ValueError("no subheaders decoded - not a MAC PDU")
    # Payload segments are consecutive from the end of the header chain.
    head_end = pos
    cur = head_end
    for s in subs:
        if s["len"] is None:
            s["payload_offset"] = None
            s["payload"] = ""
            continue
        if cur + s["len"] > len(b):
            raise ValueError("subheader LCID %d at byte %d claims %d payload "
                             "bytes but only %d remain - the PDU is truncated "
                             "or the subheader chain has desynchronised"
                             % (s["lcid"], s["offset"], s["len"],
                                len(b) - cur))
        seg = b[cur:cur + s["len"]]
        s["payload_offset"] = cur
        s["payload"] = seg.hex().upper()
        cur += s["len"]
    return {"pdu": b, "subheaders": subs, "header_bytes": head_end,
            "payload_end": cur, "direction": direction}


def mac_ce_report(sub):
    """Report a MAC CE whose payload length the spec fixes, and flag a
    mismatch. A fixed-length CE with the wrong length means the chain is
    wrong: every boundary after it is garbage."""
    lcid = sub["lcid"]
    if lcid not in CE_LEN:
        return None
    want = CE_LEN[lcid]
    got = sub["len"]
    rep = {"lcid": lcid, "name": lcid_name(lcid, "ul"),
           "payload_bytes": got, "expected_bytes": want,
           "consistent": (got == want)}
    payload = sub["payload"]
    if lcid == 54 and len(payload) >= 2:
        v = int(payload[:2], 16)
        rep["ta_tag"] = (v >> 6) & 0x3
        rep["ta_index"] = v & 0x3F
    return rep


def mode_decode(hexstr, direction):
    p = decode_mac(hexstr, direction)
    out("pdu", "direction", direction)
    out("pdu", "bytes", len(p["pdu"]))
    out("pdu", "header_bytes", p["header_bytes"])
    out("pdu", "subheaders", len(p["subheaders"]))
    out("sub", "index", "lcid", "lcid_name", "f", "e", "len", "header_bytes",
        "payload_offset", "payload_hex")
    for i, s in enumerate(p["subheaders"]):
        name = lcid_name(s["lcid"], direction)
        # Every data row carries the same leading record-type column as the
        # header and the summary rows. Emitting a bare index here would make
        # the row indistinguishable from a key/value record for any consumer
        # that splits on the first column.
        out("sub", i, s["lcid"], name, s["f"], s.get("e", ""),
            "" if s["len"] is None else s["len"], s["header_bytes"],
            "" if s["payload_offset"] is None else s["payload_offset"],
            s["payload"])
        rep = mac_ce_report(s)
        if rep is not None:
            out("ce", i, rep["name"], rep["payload_bytes"],
                rep["expected_bytes"], "yes" if rep["consistent"] else "no")
            if not rep["consistent"]:
                err("MAC CE %s at subheader %d carries %d bytes, the spec "
                    "fixes %d - subheader chain desynchronised"
                    % (rep["name"], i, rep["payload_bytes"],
                       rep["expected_bytes"]))
                return 1
            if "ta_index" in rep:
                out("ce_ta", "tag", rep["ta_tag"], "index", rep["ta_index"])
    out("pdu_summary", "subheaders", len(p["subheaders"]),
        "payload_bytes", p["payload_end"] - p["header_bytes"],
        "consumed_bytes", p["payload_end"])
    if p["payload_end"] != len(p["pdu"]):
        err("%d trailing bytes after the last subheader payload - the chain "
            "does not cover the PDU"
            % (len(p["pdu"]) - p["payload_end"]))
        return 1
    return 0


def mode_rnti(rnti):
    try:
        v = int(rnti, 16) if not rnti.lower().startswith("0x") else int(rnti, 16)
    except ValueError:
        err("RNTI %r is not hex" % rnti)
        return 1
    if v < 0 or v > 0xFFFF:
        err("RNTI 0x%X is outside the 16-bit space" % v)
        return 1
    if v == 0:
        cls = "reserved"
    elif v == 0xFFFF:
        cls = "SI-RNTI"
    elif v == 0xFFFE:
        cls = "P-RNTI"
    elif 0xFFF0 <= v <= 0xFFFD:
        cls = "reserved"
    elif 1 <= v <= 0x3C:
        cls = "RA-RNTI"
    else:
        cls = "C-RNTI"
    out("rnti", "value", "0x%04X" % v)
    out("rnti", "decimal", v)
    out("rnti", "class", cls)
    return 0


# ─────────────────────────────────────────────────────────────────────────
# DCI (TS 36.212 §5.3.3.1.3, format 1 / 1A) and scheduling pattern
# ─────────────────────────────────────────────────────────────────────────
def mode_dci(hexstr, fmt):
    h = hexstr.strip().replace(":", "").replace(" ", "")
    if not h or len(h) % 2 != 0:
        err("DCI is not a whole octet string")
        return 1
    try:
        b = bytes.fromhex(h)
    except ValueError as e:
        err("DCI is not valid hex: %s" % e)
        return 1
    if fmt not in ("1", "1a", "1A"):
        err("unsupported DCI format %r (implemented: 1, 1A)" % fmt)
        return 1
    # Format 1 fields, in order (TS 36.212 Table 5.3.3.1.3-3), on a
    # bit string read MSB first:
    #   resource allocation header (1)  - format 1 only, absent in 1A
    #   resource block assignment (variable by bandwidth; this decoder
    #     reports the raw bits and the field width it assumed)
    #   MCS (5)
    #   HARQ process number (3)
    #   redundancy version (2)
    #   TPC (1) / DAI (2) / HARQ-ACK (2)
    # The exact widths of the RB assignment and the trailing fields depend
    # on the system bandwidth and the TDD/FDD mode, neither of which is in
    # the DCI. This decoder therefore reports the bit string, the fields
    # whose position is bandwidth-independent, and NAMES the two values it
    # would need rather than inventing them. That is the honest decode.
    # python3 has no %b format code; the bit string is built with the
    # string format method, which does.
    bits = "".join(format(x, "08b") for x in b)
    if len(bits) < 11:
        err("DCI bit string is %d bits; at least 11 are needed before the "
            "bandwidth-dependent fields it carries can be located" % len(bits))
        return 1
    mcs = int(bits[-11:-6], 2)
    harq = int(bits[-6:-3], 2) if len(bits) >= 6 else None
    rv = int(bits[-3:-1], 2) if len(bits) >= 3 else None
    out("dci", "format", fmt)
    out("dci", "bytes", len(b))
    out("dci", "bits", len(bits))
    out("dci", "bitstring", bits)
    out("dci", "trailing_mcs", "" if mcs is None else mcs)
    out("dci", "trailing_harq_process", "" if harq is None else harq)
    out("dci", "trailing_rv", "" if rv is None else rv)
    out("dci", "needs", "system bandwidth (RB assignment width) and FDD/TDD "
        "(trailing field widths) to decode the leading fields; neither is "
        "carried in the DCI itself")
    out("dci", "source", "TS 36.212 Table 5.3.3.1.3-3")
    return 0


# MCS index -> (modulation order, TBS index) per TS 36.213 Table 7.1.7.1-1.
MCS_TABLE = {}
for _i in range(0, 10):
    MCS_TABLE[_i] = (2, _i)         # QPSK
for _i in range(10, 17):
    MCS_TABLE[_i] = (4, _i)         # 16QAM
for _i in range(17, 28):
    MCS_TABLE[_i] = (6, _i)         # 64QAM
MCS_TABLE[28] = (6, 27)
MCS_TABLE[29] = (2, 0)              # QPSK, reserved use
MCS_TABLE[30] = (4, 0)
MCS_TABLE[31] = (6, 0)


def mcs_modulation(mcs):
    """TS 36.213 Table 7.1.7.1-1 modulation order: 2 = QPSK, 4 = 16QAM,
    6 = 64QAM. Indices 29-31 are the reserved triples."""
    if mcs not in MCS_TABLE:
        return None
    order = MCS_TABLE[mcs][0]
    return {2: "QPSK", 4: "16QAM", 6: "64QAM"}.get(order)


def mode_sched(grants):
    """Scheduling-pattern inference from a grant list.

    Each grant is "ts_ms:rnti:mcs:prbs". The output reports the per-RNTI
    inter-grant interval distribution, the periodicity if one dominates,
    and the allocation statistics. The periodicity and the allocation size
    together are the layer-2 side channel: a 1 ms cadence with 2 PRBs is a
    keepalive, a 100 ms cadence with 50 PRBs is a video segment fetch, and
    an observer sees both without decrypting a byte.
    """
    by = {}
    for g in grants:
        parts = g.split(":")
        if len(parts) != 4:
            err("grant %r is not ts:rnti:mcs:prbs" % g)
            return 1
        try:
            ts = float(parts[0]); rnti = int(parts[1], 16)
            mcs = int(parts[2]); prbs = int(parts[3])
        except ValueError:
            err("grant %r has a non-numeric field" % g)
            return 1
        by.setdefault(rnti, []).append((ts, mcs, prbs))
    if not by:
        err("no grants")
        return 1
    out("sched", "rntis", len(by))
    out("rnti_sched", "rnti", "class", "grants", "first_ms", "last_ms",
        "period_ms", "period_count", "median_interval_ms", "mcs_median",
        "prbs_median", "prbs_total")
    for rnti in sorted(by):
        rows = sorted(by[rnti], key=lambda r: r[0])
        ts = [r[0] for r in rows]
        iv = [round((ts[i + 1] - ts[i]) * 1000.0, 6) for i in range(len(ts) - 1)]
        counts = {}
        for v in iv:
            key = round(v, 3)
            counts[key] = counts.get(key, 0) + 1
        period = None
        pcount = 0
        for k, c in counts.items():
            if c > pcount or (c == pcount and period is not None and k < period):
                period, pcount = k, c
        med_iv = sorted(iv)[len(iv) // 2] if iv else 0.0
        mcs_sorted = sorted(r[1] for r in rows)
        prb_sorted = sorted(r[2] for r in rows)
        out("rnti_sched", "0x%04X" % rnti, rnti_class(rnti), len(rows),
            "%.3f" % (ts[0] * 1000.0), "%.3f" % (ts[-1] * 1000.0),
            "" if period is None else "%.3f" % period, pcount,
            "%.3f" % med_iv, mcs_sorted[len(mcs_sorted) // 2],
            prb_sorted[len(prb_sorted) // 2], sum(r[2] for r in rows))
        mod = mcs_modulation(mcs_sorted[len(mcs_sorted) // 2])
        out("rnti_app", "0x%04X" % rnti, "mcs_median", mcs_sorted[len(mcs_sorted) // 2],
            "modulation", mod or "unknown",
            "note", "cadence and allocation size are visible without "
            "decrypting the bearer; they characterise the application")
    return 0


def rnti_class(v):
    if v == 0:
        return "reserved"
    if v == 0xFFFF:
        return "SI-RNTI"
    if v == 0xFFFE:
        return "P-RNTI"
    if 0xFFF0 <= v <= 0xFFFD:
        return "reserved"
    if 1 <= v <= 0x3C:
        return "RA-RNTI"
    return "C-RNTI"


# ─────────────────────────────────────────────────────────────────────────
# pcap-driven verbs: RNTI track and scheduling pattern
# ─────────────────────────────────────────────────────────────────────────
def read_pcap(path):
    """Yield (ts, frame) from a classic pcap. Only the classic format is
    needed here: the MAC PDUs this module tracks arrive over a capture that
    module 21 or an SDR bridge wrote. pcapng is rejected with a reason
    rather than misparsed."""
    if not os.path.isfile(path):
        raise ValueError("no such capture: %s" % path)
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            raise ValueError("file is %d bytes - too short to be a capture"
                             % len(head))
        magic = struct.unpack("<I", head)[0]
        if magic == 0x0a0d0d0a:
            raise ValueError("this verb reads classic pcap; %s is pcapng - "
                             "convert it with editcap -F pcap" % path)
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            endian = "<"; nsec = (magic == 0xa1b23c4d)
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
            endian = ">"; nsec = (magic == 0x4d3cb2a1)
        else:
            raise ValueError("not a pcap capture (magic 0x%08x)" % magic)
        # The magic has already been consumed, so the REST of the 24-byte
        # global header is 20 bytes. Reading 24 here leaves the file
        # position 4 bytes past the first record header and every record
        # then reads its incl_len from the middle of the previous record -
        # which surfaces as a bogus "record truncated" on the second frame.
        hdr = fh.read(20)
        if len(hdr) < 20:
            raise ValueError("pcap global header truncated")
        # vmaj vmin thiszone sigfigs snaplen network = 2+2+4+4+4+4 = 20 bytes
        (vmaj, vmin, tz, sig, snap, net) = struct.unpack(endian + "HHiIII", hdr)
        while True:
            rh = fh.read(16)
            if len(rh) == 0:
                return
            if len(rh) < 16:
                raise ValueError("record header truncated at the end of %s" % path)
            sec, frac, incl, orig = struct.unpack(endian + "IIII", rh)
            data = fh.read(incl)
            if len(data) < incl:
                raise ValueError("record truncated: wanted %d bytes, got %d"
                                 % (incl, len(data)))
            ts = sec + (frac / 1e9 if nsec else frac / 1e6)
            yield ts, data, net


def mac_pdus_in_pcap(path):
    """Extract candidate MAC PDUs from a pcap.

    A MAC PDU is not a network-layer object, so there is no port or
    ethertype that identifies it. What a capture from an SDR bridge or a
    GSMTAP feed carries is the PDU as an opaque payload. This function
    therefore takes a stated convention: every UDP datagram whose payload
    is longer than 3 bytes is offered to the decoder, and the decoder's
    success or failure is reported per frame. A caller that knows its
    capture's encapsulation can filter with --filter-port.
    """
    pdus = []
    for ts, frame, net in read_pcap(path):
        payload = None
        if net == 1 and len(frame) >= 14:
            et = struct.unpack(">H", frame[12:14])[0]
            if et == 0x0800:
                payload = frame[14:]
        elif net in (101, 12, 228):
            payload = frame
        if payload is None or len(payload) < 20:
            continue
        ihl = (payload[0] & 0xF) * 4
        if payload[0] >> 4 != 4 or len(payload) < ihl + 8:
            continue
        if payload[9] != 17:
            continue
        udp = payload[ihl:]
        sport, dport, ulen = struct.unpack(">HHH", udp[0:6])
        body = udp[8:8 + max(0, ulen - 8)]
        if len(body) < 3:
            continue
        pdus.append((ts, sport, dport, body))
    return pdus


def mode_rnti_track(path, direction):
    """Track RNTIs across a capture.

    The capture this module can actually track without a full L1/L2
    dissector is one where each frame's payload is a MAC PDU; the RNTI is
    not inside the PDU, it is the CRC mask that addressed it. This verb
    therefore does what it can prove: it decodes every candidate PDU,
    records which LCIDs appear and when, and reports the per-flow RNTI
    evidence the capture carries. Where an RNTI is not recoverable it says
    so instead of inventing one.
    """
    pdus = mac_pdus_in_pcap(path)
    if not pdus:
        err("no candidate MAC PDUs in %s (no UDP payloads longer than 3 bytes)"
            % path)
        return 1
    out("track", "file", path)
    out("track", "candidate_pdus", len(pdus))
    out("track", "direction", direction)
    out("rnti_flow", "index", "ts_ms", "src_port", "dst_port", "bytes",
        "decoded", "subheaders", "lcids")
    ok_n = 0
    for i, (ts, sp, dp, body) in enumerate(pdus):
        try:
            p = decode_mac(body.hex(), direction)
            lcids = ",".join(str(s["lcid"]) for s in p["subheaders"])
            out("rnti_flow", i, "%.3f" % (ts * 1000.0), sp, dp, len(body),
                "yes", len(p["subheaders"]), lcids)
            ok_n += 1
        except ValueError as e:
            out("rnti_flow", i, "%.3f" % (ts * 1000.0), sp, dp, len(body),
                "no", 0, "")
    out("track", "decoded_pdus", ok_n)
    out("track", "undecoded_pdus", len(pdus) - ok_n)
    out("track", "note", "the RNTI is the CRC mask that addressed a PDU, "
        "not a field inside it: a PDU payload alone cannot prove which "
        "RNTI it belonged to. Tracking an RNTI to a device needs the "
        "DCI/CRC layer, which is marked handoff in --integrity-gap's "
        "sibling verbs rather than guessed here")
    return 0


def mode_sched_pcap(path, idle, direction):
    """Infer a grant cadence from decoded MAC PDUs in a capture.

    The observable cadence is the arrival time of PDUs whose LCID chain
    shows a data-bearing subheader (LCID 1-10). That is a lower bound on
    the grant cadence: it counts served grants, not every grant.
    """
    pdus = mac_pdus_in_pcap(path)
    if not pdus:
        err("no candidate MAC PDUs in %s" % path)
        return 1
    events = []
    for ts, sp, dp, body in pdus:
        try:
            p = decode_mac(body.hex(), direction)
        except ValueError:
            continue
        data_subs = [s for s in p["subheaders"] if 1 <= s["lcid"] <= 10]
        if not data_subs:
            continue
        events.append((ts, sp, dp, sum(s["len"] or 0 for s in data_subs),
                       len(data_subs)))
    if not events:
        err("no data-bearing MAC PDUs in %s" % path)
        return 1
    events.sort(key=lambda e: e[0])
    out("sched_pcap", "file", path)
    out("sched_pcap", "data_pdus", len(events))
    out("sched_pcap", "first_ms", "%.3f" % (events[0][0] * 1000.0))
    out("sched_pcap", "last_ms", "%.3f" % (events[-1][0] * 1000.0))
    iv = [(events[i + 1][0] - events[i][0]) * 1000.0
          for i in range(len(events) - 1)]
    bursts = 0
    prev = None
    for t in [e[0] for e in events]:
        if prev is None or (t - prev) * 1000.0 > idle * 1000.0:
            bursts += 1
        prev = t
    out("sched_pcap", "bursts", bursts)
    if iv:
        s = sorted(iv)
        out("sched_pcap", "interval_p50_ms", "%.3f" % s[len(s) // 2])
        out("sched_pcap", "interval_min_ms", "%.3f" % s[0])
        out("sched_pcap", "interval_max_ms", "%.3f" % s[-1])
        counts = {}
        for v in iv:
            counts[round(v, 3)] = counts.get(round(v, 3), 0) + 1
        best = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
        out("sched_pcap", "dominant_interval_ms", "%.3f" % best[0])
        out("sched_pcap", "dominant_count", best[1])
    out("sched_pcap", "cadence_note", "this is the arrival cadence of PDUs "
        "that carry data; it is a lower bound on the grant rate, because a "
        "grant that serves no data leaves no PDU here")
    out("sched_pcap", "direction", direction)
    return 0


def mode_integrity_gap():
    """The aLTEr precondition, stated with both halves.

    TS 33.401 §5.4 and TS 36.323 §6.2: ciphering applies to DRBs and SRBs;
    integrity protection (the PDCP MAC-I) applies to SRBs. NAS integrity
    (TS 24.301) covers NAS messages. The user plane therefore has
    confidentiality but not integrity, which is the gap.
    """
    rows = [
        ("user_plane", "DRB", "ciphering", "yes",
         "PDCP applies the negotiated cipher (EEA1/EEA2/EEA3)",
         "TS 36.323 6.2 / TS 33.401 5.4"),
        ("user_plane", "DRB", "integrity", "no",
         "no MAC-I over DRB payloads; a flipped ciphertext bit decrypts to "
         "a flipped plaintext bit with no detection at the receiver",
         "TS 36.323 6.2 - DRB integrity is not part of the LTE profile"),
        ("control_plane", "SRB", "ciphering", "yes",
         "PDCP applies the same cipher to signalling radio bearers",
         "TS 36.323 6.2"),
        ("control_plane", "SRB", "integrity", "yes",
         "the PDCP MAC-I protects RRC signalling; a forged RRC message "
         "fails the integrity check at the UE",
         "TS 36.323 6.2 / TS 33.401 6.3.1"),
        ("control_plane", "NAS", "integrity", "yes",
         "NAS integrity (NIA) protects NAS messages independently of RRC",
         "TS 24.301 / TS 33.401 5.4"),
    ]
    out("integrity", "plane", "bearer", "property", "present", "detail",
        "source")
    for r in rows:
        out("integrity", *r)
    out("integrity_gap", "conclusion",
        "the LTE USER plane has no integrity protection; the CONTROL plane "
        "(RRC over SRB and NAS) is integrity protected")
    out("integrity_gap", "user_plane_integrity", "absent")
    out("integrity_gap", "control_plane_integrity", "present")
    out("integrity_gap", "alte_precondition", "satisfied")
    out("integrity_gap", "owner_of_the_attack", "32_cellular_dns (O10)")
    out("integrity_gap", "this_module", "documents and detects the gap; it "
        "does not perform the redirection")
    out("integrity_gap", "detection", "an unexplained change in a device's "
        "scheduling pattern, an RNTI that was never assigned in this "
        "capture, and a MAC CE that should not appear (a contention "
        "resolution after the random-access procedure completed, or a "
        "timing advance command from a direction that cannot send one)")
    return 0


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    a = argv[2:]
    try:
        if mode == "decode":
            if len(a) < 1:
                err("usage: --decode-mac <hex> [dl|ul]")
                return 2
            direction = a[1] if len(a) > 1 else "dl"
            if direction not in ("dl", "ul"):
                err("direction must be dl or ul")
                return 2
            return mode_decode(a[0], direction)
        if mode == "rnti":
            if len(a) < 1:
                err("usage: --rnti <hex>")
                return 2
            return mode_rnti(a[0])
        if mode == "dci":
            if len(a) < 1:
                err("usage: --dci <hex> [1|1A]")
                return 2
            return mode_dci(a[0], a[1] if len(a) > 1 else "1")
        if mode == "sched":
            return mode_sched(a)
        if mode == "rnti-track":
            if len(a) < 1:
                err("usage: --rnti-track <pcap> [dl|ul]")
                return 2
            return mode_rnti_track(a[0], a[1] if len(a) > 1 else "dl")
        if mode == "sched-pcap":
            if len(a) < 1:
                err("usage: --sched-pattern <pcap> [idle-s] [dl|ul]")
                return 2
            idle = float(a[1]) if len(a) > 1 else 1.0
            return mode_sched_pcap(a[0], idle, a[2] if len(a) > 2 else "dl")
        if mode == "integrity-gap":
            return mode_integrity_gap()
    except ValueError as e:
        err(str(e))
        return 1
    err("unknown mode %r" % mode)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except ValueError as e:
        err(str(e))
        sys.exit(1)
    except BrokenPipeError:
        sys.exit(0)
PYEOF
}

macl_ensure_engine() {
    mkdir -p "$MOD_TMP" 2>/dev/null
    local tmp="$MOD_TMP/.macl_engine.py.new"
    macl_engine_py > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    [[ -s "$tmp" ]] || { rm -f "$tmp"; return 1; }
    if [[ ! -f "$MOD_TMP/macl_engine.py" ]] || ! cmp -s "$tmp" "$MOD_TMP/macl_engine.py"; then
        mv -f "$tmp" "$MOD_TMP/macl_engine.py" || { rm -f "$tmp"; return 1; }
    else
        rm -f "$tmp"
    fi
    [[ -s "$MOD_TMP/macl_engine.py" ]]
}

macl_run() {
    local mode="$1"; shift
    macl_ensure_engine || {
        printf 'ERROR\tcannot write the MAC decoder to %s\n' "$MOD_TMP/macl_engine.py" >&2
        return 1
    }
    python3 "$MOD_TMP/macl_engine.py" "$mode" "$@"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
macl_cli_status_tsv() {
    local py eng
    py=$(command -v python3 >/dev/null 2>&1 && echo present || echo missing)
    eng=$([[ -s "$MOD_TMP/macl_engine.py" ]] && echo ready || echo not-staged)
    printf 'python3\t%s\n'        "$py"
    printf 'engine\t%s\n'         "$eng"
    printf 'engine_path\t%s\n'    "$MOD_TMP/macl_engine.py"
    printf 'lcid_source\t%s\n'    'TS 36.321 Table 6.2.1-1 (DL) / 6.2.1-2 (UL)'
    printf 'rnti_source\t%s\n'    'TS 36.321 7.1, TS 36.211 6.11'
    printf 'directions\t%s\n'     'dl,ul'
    printf 'rnti_store\t%s\n'     "$MACL_RNTI"
    printf 'sched_store\t%s\n'    "$MACL_SCHED"
    printf 'loot_dir\t%s\n'       "$MACL_DIR"
    printf 'captures_dir\t%s\n'   "$CAPTURES_DIR"
    printf 'capture_count\t%s\n'  "$(find "$CAPTURES_DIR" -maxdepth 1 -type f \
        \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) 2>/dev/null | wc -l | tr -d ' ')"
    printf 'user_plane_integrity\t%s\n' 'absent'
    printf 'control_plane_integrity\t%s\n' 'present'
    printf 'attack_coverage\t%s\n' 'P9'
    printf 'radio_required\t%s\n' 'no'
}

macl_cmd_decode() {
    local hex="${1:-}" dir="${2:-dl}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-mac <hex> [dl|ul]\n' >&2; return 2; }
    case "$dir" in
        dl|ul) ;;
        *) printf 'ERROR\tdirection must be dl or ul\n' >&2; return 2 ;;
    esac
    if ! printf '%s' "$hex" | grep -qE '^[0-9A-Fa-f]+$'; then
        printf 'ERROR\tMAC PDU is not a hex string\n' >&2; return 1
    fi
    [[ $(( ${#hex} % 2 )) -eq 0 ]] || {
        printf 'ERROR\tMAC PDU hex has an odd number of nibbles (%d)\n' "${#hex}" >&2
        return 1; }
    macl_run decode "$hex" "$dir"
}

macl_cmd_lcid_table() {
    # The table is the module's contract with the spec, so it prints from
    # the same function the decoder uses rather than from a second copy.
    printf 'direction\tlcid\tname\n'
    local i
    for (( i = 0; i <= 63; i++ )); do
        local n
        n=$(macl_lcid_name "$i" dl)
        # Only print the DL table's real entries plus every UL-only entry.
        if [[ "$n" != "unknown" ]]; then
            printf 'dl\t%s\t%s\n' "$i" "$n"
        fi
    done
    for (( i = 52; i <= 63; i++ )); do
        printf 'ul\t%s\t%s\n' "$i" "$(macl_lcid_name "$i" ul)"
    done
    # A reserved LCID must read as Reserved, not as unknown or as 0.
    printf 'dl\t11\t%s\n' "$(macl_lcid_name 11 dl)"
    printf 'ul\t11\t%s\n' "$(macl_lcid_name 11 ul)"
    printf 'note\t-\tLCID 11 is Reserved in DL-SCH (Table 6.2.1-1) and CCCH in UL-SCH (Table 6.2.1-2), which is why the direction is an explicit argument\n'
}

macl_cmd_rnti_table() {
    printf 'rnti\tclass\tmeaning\n'
    printf '0x0000\treserved\t%s\n' "$(macl_rnti_meaning 0000)"
    printf '0x0001\tRA-RNTI\t%s\n' "$(macl_rnti_meaning 0001)"
    printf '0x003C\tRA-RNTI\t%s\n' "$(macl_rnti_meaning 003C)"
    printf '0x003D\tC-RNTI\t%s\n' "$(macl_rnti_meaning 003D)"
    printf '0x0100\tC-RNTI\t%s\n' "$(macl_rnti_meaning 0100)"
    printf '0xFFEF\tC-RNTI\t%s\n' "$(macl_rnti_meaning FFEF)"
    printf '0xFFFE\tP-RNTI\t%s\n' "$(macl_rnti_meaning FFFE)"
    printf '0xFFFF\tSI-RNTI\t%s\n' "$(macl_rnti_meaning FFFF)"
    printf '0xFFF0\treserved\t%s\n' "$(macl_rnti_meaning FFF0)"
}

macl_cmd_rnti_track() {
    local f="${1:-}" dir="${2:-dl}"
    [[ -n "$f" ]] || { printf 'ERROR\tusage: --rnti-track <pcap> [dl|ul]\n' >&2; return 2; }
    [[ -f "$f" ]] || { printf 'ERROR\tno such capture: %s\n' "$f" >&2; return 1; }
    case "$dir" in dl|ul) ;; *) printf 'ERROR\tdirection must be dl or ul\n' >&2; return 2 ;; esac
    macl_run rnti-track "$f" "$dir"
}

macl_cmd_sched_pattern() {
    local f="${1:-}" idle="${2:-1.0}" dir="${3:-dl}"
    [[ -n "$f" ]] || { printf 'ERROR\tusage: --sched-pattern <pcap|grants...>\n' >&2; return 2; }
    if [[ -f "$f" ]]; then
        [[ "$idle" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
            printf 'ERROR\tidle threshold must be a number of seconds\n' >&2; return 2; }
        case "$dir" in dl|ul) ;; *) printf 'ERROR\tdirection must be dl or ul\n' >&2; return 2 ;; esac
        macl_run sched-pcap "$f" "$idle" "$dir"
    else
        # No such file: treat the arguments as a grant list and say so, so a
        # mistyped path is never silently read as grants.
        printf 'ERROR\tno such capture: %s (grant-list mode takes ts:rnti:mcs:prbs arguments)\n' "$f" >&2
        return 1
    fi
}

macl_cmd_sched_grants() {
    (($# > 0)) || { printf 'ERROR\tusage: --sched-parse <ts_ms:rnti:mcs:prbs>...\n' >&2; return 2; }
    macl_run sched "$@"
}

macl_cmd_integrity_gap() {
    macl_run integrity-gap
}

macl_cmd_dci() {
    local hex="${1:-}" fmt="${2:-1}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --dci <hex> [1|1A]\n' >&2; return 2; }
    printf '%s' "$hex" | grep -qE '^[0-9A-Fa-f]+$' || {
        printf 'ERROR\tDCI is not a hex string\n' >&2; return 1; }
    [[ $(( ${#hex} % 2 )) -eq 0 ]] || {
        printf 'ERROR\tDCI hex has an odd number of nibbles\n' >&2; return 1; }
    macl_run dci "$hex" "$fmt"
}

# ── selftest — no radio, no root, no network ────────────────────────────
macl_selftest() {
    local bad=0 npass=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"; npass=$((npass + 1))
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    # Field n of the first row whose field 1 equals the record type.
    rowf() { printf '%s\n' "$1" | awk -F'\t' -v r="$2" -v n="$3" '$1==r{print $n; exit}'; }
    # Field n of the row whose field 1 equals r and field 2 equals k.
    # Field accessor for a three-column key/value record:
    #   rkf "$out" <record-type> <key> <field>   -> field of that row
    rkf() { printf '%s\n' "$1" | awk -F'\t' -v r="$2" -v k="$3" -v n="$4"         '$1==r && $2==k{print $n; exit}'; }
    # Count data rows (the header row for that record type is excluded by
    # requiring the second field to be a number).
    nsub() { printf '%s\n' "$1" | awk -F'\t' -v r="$2" '$1==r && $2 ~ /^[0-9]+$/{n++} END{print n+0}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export MACL_DIR="$d/loot/mac_layer"
    export MACL_RNTI="$MACL_DIR/rnti.tsv"
    export MACL_SCHED="$MACL_DIR/schedule.tsv"
    export MOD_TMP="$d/tmp"
    mkdir -p "$MOD_TMP" "$MACL_DIR" "$CAPTURES_DIR" "$STATE_DIR"
    macl_cleanup() { rm -rf "$d"; }
    trap macl_cleanup EXIT

    macl_ensure_engine || { printf 'ERROR\tengine staging failed\n' >&2; return 1; }

    # ── LCID table against TS 36.321 ────────────────────────────────────
    # Each value is asserted individually against the spec table. The table
    # in the code is not the source of truth here; the spec is.
    chk lcid-dl-0     "$(macl_lcid_name 0 dl)"   "CCCH"
    chk lcid-dl-1     "$(macl_lcid_name 1 dl)"   "Logical channel 1"
    chk lcid-dl-10    "$(macl_lcid_name 10 dl)"  "Logical channel 10"
    chk lcid-dl-11    "$(macl_lcid_name 11 dl)"  "Reserved"
    chk lcid-dl-14    "$(macl_lcid_name 14 dl)"  "Reserved"
    chk lcid-dl-15    "$(macl_lcid_name 15 dl)"  "Padding"
    chk lcid-ul-0     "$(macl_lcid_name 0 ul)"   "CCCH"
    chk lcid-ul-52    "$(macl_lcid_name 52 ul)"  "CCCH"
    chk lcid-ul-53    "$(macl_lcid_name 53 ul)"  "Contention Resolution Identity"
    chk lcid-ul-54    "$(macl_lcid_name 54 ul)"  "Timing Advance Command"
    chk lcid-ul-55    "$(macl_lcid_name 55 ul)"  "DRX Command"
    chk lcid-ul-63    "$(macl_lcid_name 63 ul)"  "Padding"
    # LCID 11 is the table trap: Reserved in DL, CCCH in UL.
    chk lcid-direction-split "$(macl_lcid_name 11 dl)/$(macl_lcid_name 11 ul)" "Reserved/CCCH"
    # An LCID that is not in the table reports unknown, NOT 0 and NOT a
    # silent empty string.
    chk lcid-unknown-dl "$(macl_lcid_name 20 dl)" "unknown"
    chk lcid-unknown-ul "$(macl_lcid_name 40 ul)" "unknown"
    chk lcid-oor-rc     "$(macl_lcid_name 99 dl >/dev/null 2>&1; echo $?)" "1"
    chk lcid-nonnum-rc  "$(macl_lcid_name abc dl >/dev/null 2>&1; echo $?)" "1"
    # A CE with a spec-fixed length must be checked, not assumed.
    chk ce-len-cr  "$(macl_ce_len 53)" "6"
    chk ce-len-ta  "$(macl_ce_len 54)" "1"
    chk ce-len-none "$(macl_ce_len 1)" ""

    out=$(macl_cmd_lcid_table)
    chk lcid-table-hd   "$(printf '%s\n' "$out" | head -n1 | awk -F'\t' '{print NF}')" "3"
    chk lcid-table-dl11 "$(printf '%s\n' "$out" | awk -F'\t' '$1=="dl" && $2=="11" && NF>=3{print $3; exit}')" "Reserved"
    chk lcid-table-ul11 "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ul" && $2=="11"{print $3}')" "CCCH"

    # ── RNTI classification against the reserved values ─────────────────
    chk rnti-si         "$(macl_rnti_class FFFF)"   "SI-RNTI"
    chk rnti-p          "$(macl_rnti_class FFFE)"   "P-RNTI"
    chk rnti-zero       "$(macl_rnti_class 0000)"   "reserved"
    chk rnti-ra-low     "$(macl_rnti_class 0001)"   "RA-RNTI"
    chk rnti-ra-high    "$(macl_rnti_class 003C)"   "RA-RNTI"
    chk rnti-cr-low     "$(macl_rnti_class 003D)"   "C-RNTI"
    chk rnti-cr-high    "$(macl_rnti_class FFEF)"   "C-RNTI"
    chk rnti-resv-hi    "$(macl_rnti_class FFF0)"   "reserved"
    chk rnti-0x-prefix  "$(macl_rnti_class 0xFFFE)" "P-RNTI"
    chk rnti-value-ffff "$(macl_rnti_value FFFF)"   "65535"
    chk rnti-value-0x   "$(macl_rnti_value 0x0001)" "1"
    chk rnti-junk-rc    "$(macl_rnti_class zzzz >/dev/null 2>&1; echo $?)" "1"
    chk rnti-invalid    "$(macl_rnti_class zzzz 2>/dev/null)" "invalid"

    # ── a hand-built MAC PDU, byte-exact boundaries ─────────────────────
    # TS 36.321 §6.1.2. Built by hand so every boundary is a value this test
    # chose. A MAC PDU payload is a byte string with no internal boundaries,
    # so the only byte-exact fixture that can exist is one where the header
    # chain ends exactly where the payload begins - the chain is walked by
    # the E bits, and the first octet with E=0 ends it. Here that octet is
    # the padding subheader 0x3C placed immediately after the two real
    # subheaders:
    #
    #   Encoding: octet0 = (LCID << 2) | (R << 1) | E, R = 0.
    #   subheader 0: octet0 = 0x11  -> LCID = (0x11 >> 2) & 0x3F = 4,
    #                E = 0x11 & 1 = 1 (more subheaders follow)
    #                octet1 = 0x0A  -> F = 0, L = (0x0A >> 1) & 0x7F = 5
    #                so this subheader is 2 bytes (offset 0) and its SDU is
    #                the first 5 payload bytes.
    #   subheader 1: octet0 = 0x0D  -> LCID = (0x0D >> 2) & 0x3F = 3, E = 1
    #                octet1 = 0x05  -> F = 1 (16-bit length), L bits 7..1
    #                                  = 0b0000010
    #                octet2 = 0x00  -> L bits 15..8 = 0   => L = 2
    #                so this subheader is 3 bytes (offset 2) and its SDU is
    #                the next 2 payload bytes.
    #   subheader 2: octet0 = 0x3C  -> LCID = (0x3C >> 2) & 0x3F = 15, E = 0
    #                one octet (offset 5), no length field, and the octet
    #                that ends the chain.
    #   header chain = 6 bytes (offsets 0..5). The padding octet ends the
    #   chain because its bit 0 is 0 (E=0); the earlier version of this
    #   fixture used a padding octet whose bit 0 was 1, and the walker then
    #   correctly read the next payload byte as a subheader and rejected the
    #   PDU.
    #   payload      = 7 bytes (offsets 6..12): five for SDU 0, two for SDU 1
    #   PDU = 11 0A 0D 05 00 3C 45 x8   (13 bytes total)
    #
    # 0x45 as the payload filler matters: it is odd, so if the walker
    # wrongly continued into the payload it would not stop there, and the
    # consumed-bytes assertion below would fail. A filler whose low bit is
    # clear would let a broken walker terminate by accident and pass.
    local pdu="110A0D05003C45454545454545"
    out=$(macl_cmd_decode "$pdu" dl); rc=$?
    chk decode-rc        "$rc" "0"
    chk decode-bytes     "$(rkf "$out" pdu bytes 3)" "13"
    chk decode-subs      "$(rkf "$out" pdu subheaders 3)" "3"
    chk decode-headerlen "$(rkf "$out" pdu header_bytes 3)" "6"
    chk decode-sub-rows  "$(nsub "$out" sub)" "3"
    # Byte-exact assertions on the chain.
    chk decode-s0-lcid   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $3}')" "4"
    chk decode-s0-name   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $4}')" "Logical channel 4"
    chk decode-s0-len    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $7}')" "5"
    chk decode-s0-off    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $9}')" "6"
    chk decode-s0-payload "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $10}')" "4545454545"
    chk decode-s1-lcid   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="1"{print $3}')" "3"
    chk decode-s1-f      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="1"{print $5}')" "1"
    chk decode-s1-len    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="1"{print $7}')" "2"
    chk decode-s1-off    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="1"{print $9}')" "11"
    chk decode-s1-payload "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="1"{print $10}')" "4545"
    chk decode-s2-lcid   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="2"{print $3}')" "15"
    chk decode-s2-name   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="2"{print $4}')" "Padding"
    chk decode-s2-hbytes "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="2"{print $8}')" "1"
    chk decode-consumed  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="pdu_summary" && $2=="subheaders" && $3 ~ /^[0-9]+$/{c=$NF} END{print c}')" "13"

    # An 8-bit-length subheader (F=0) with L = 127, LCID 5, E = 0:
    #   octet0 = 0x14 (LCID 5, E=0), octet1 = 0xFE (F=0, L=(0xFE>>1)=127)
    #   127 bytes of payload; the chain ends when the payload length is
    # The payload bytes are C3 repeated.
    local big_pdu big_pay
    big_pay=$(printf 'C3%.0s' $(seq 1 127))
    big_pdu="14FE${big_pay}"
    out=$(macl_cmd_decode "$big_pdu" dl); rc=$?
    chk decode-big-rc    "$rc" "0"
    chk decode-big-len   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $7}')" "127"
    chk decode-big-pay   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $10}' | wc -c | tr -d ' ')" "255"
    chk decode-big-subs  "$(rkf "$out" pdu subheaders 3)" "1"

    # The 16-bit length form (F=1). L=200 needs both length octets, so the
    # F flag does real work. The length is assembled as
    #   L = (octet1 >> 1) | (octet2 << 7)
    # so for L = 200: octet1 = ((200 & 0x7F) << 1) | 1 = 0x91 and
    # octet2 = 200 >> 7 = 1. The payload byte 0xD5 has bit 0 set, so a
    # mis-walk cannot silently land on padding.
    local big16 pdu16
    big16=$(printf 'D5%.0s' $(seq 1 200))
    pdu16="149101${big16}"
    out=$(macl_cmd_decode "$pdu16" dl); rc=$?
    chk decode-16bit-rc  "$rc" "0"
    chk decode-16bit-len "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $7}')" "200"
    chk decode-16bit-f   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $5}')" "1"   # 0x91 & 1 = F = 1
    chk decode-16bit-hb  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $9}')" "3"


    # ── a UL PDU with a Timing Advance Command CE (LCID 54) ─────────────
    # The chain is that single subheader, so its E bit is 0 and
    #   octet0 = (54 << 2) | 0 = 0xD8: LCID = (0xD8 >> 2) & 0x3F = 54
    #   octet1 = 0x02: F = 0, L = 1
    #   payload = 0x8D = 1000 1101: TA tag = 10b = 2, TA index = 001101b = 13
    #   terminator octet for UL padding: LCID 63 -> (63 << 2) | 0 = 0xFC
    #   = 1111 1100, so LCID = 63 and E = 0; the padding subheader is one
    #   octet and ends the chain. The PDU is D9 02 8D FC (4 bytes).
    out=$(macl_cmd_decode "D8028D" ul); rc=$?
    chk ul-ta-rc      "$rc" "0"
    chk ul-ta-lcid    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $3}')" "54"
    chk ul-ta-name    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sub" && $2=="0"{print $4}')" "Timing Advance Command"
    chk ul-ta-ce-name "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ce" && $2=="0"{print $3}')" "Timing Advance Command"
    chk ul-ta-ce-pay  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ce" && $2=="0"{print $4}')" "1"
    chk ul-ta-ce-exp  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ce" && $2=="0"{print $5}')" "1"
    chk ul-ta-ce-ok   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ce" && $2=="0"{print $6}')" "yes"
    # 0x8D: top 2 bits 10b = tag 2; low 6 bits 001101b = index 13.
    chk ul-ta-tag     "$(rkf "$out" ce_ta tag 3)" "2"
    chk ul-ta-index   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ce_ta" && $2=="tag" && $4=="index"{print $NF}')" "13"
    chk ul-ta-exec    "$(macl_ta_fields 8D | awk -F'\t' '$1=="index"{print $2}')" "13"
    chk ul-ta-tag2    "$(macl_ta_fields 8D | awk -F'\t' '$1=="tag"{print $2}')" "2"
    chk ul-ta-bad     "$(macl_ta_fields zz >/dev/null 2>&1; echo $?)" "1"
    # LCID 11 flips meaning with direction on the same bytes.
    out_dl=$(macl_run decode "2C02FF" dl)   # octet0 0x2C: LCID = 11, E=0
    out_ul=$(macl_run decode "2C02FF" ul)
    chk lcid11-byte-dl "$(printf '%s\n' "$out_dl" | awk -F'\t' '$1=="sub" && $2=="0"{print $4}')" "Reserved"
    chk lcid11-byte-ul "$(printf '%s\n' "$out_ul" | awk -F'\t' '$1=="sub" && $2=="0"{print $4}')" "CCCH"

    # ── malformed input returns non-zero, naming the reason ─────────────
    chk malformed-odd      "$(macl_cmd_decode "ABC" dl >/dev/null 2>&1; echo $?)" "1"
    chk malformed-nothex   "$(macl_cmd_decode "ZZZZ" dl >/dev/null 2>&1; echo $?)" "1"
    chk malformed-empty    "$(macl_cmd_decode "" dl >/dev/null 2>&1; echo $?)" "2"
    chk malformed-baddir   "$(macl_cmd_decode "110D" xx >/dev/null 2>&1; echo $?)" "2"
    # A subheader claiming more payload than the PDU carries must fail, not
    # return a short segment.
    out=$(macl_cmd_decode "110AAAAAAA" dl 2>&1); rc=$?
    chk truncated-rc  "$rc" "1"
    chk truncated-msg "$(printf '%s\n' "$out" | grep -c 'truncated or the subheader chain')" "1"
    # Trailing bytes the chain does not cover must fail.
    out=$(macl_cmd_decode "100A4A4A4A4A4A4A" dl 2>&1); rc=$?
    chk trailing-rc  "$rc" "1"
    chk trailing-msg "$(printf '%s\n' "$out" | grep -c 'trailing bytes')" "1"
    # A CE whose length disagrees with the spec must be flagged.
    out=$(macl_cmd_decode "D8028D" ul 2>&1); rc=$?
    chk ce-len-ok    "$rc" "0"
    # Now a contention resolution CE (LCID 53) with 2 bytes instead of 6.
    out=$(macl_cmd_decode "D402D5D5" ul 2>&1); rc=$?
    chk ce-badlen-rc  "$rc" "1"
    chk ce-badlen-msg "$(printf '%s\n' "$out" | grep -c 'the spec fixes 6')" "1"

    # ── DCI decode ──────────────────────────────────────────────────────
    out=$(macl_cmd_dci "3FE1A0" 1); rc=$?
    chk dci-rc    "$rc" "0"
    chk dci-bytes "$(rkf "$out" dci bytes 3)" "3"
    chk dci-bits  "$(rkf "$out" dci bits 3)" "24"
    chk dci-needs "$(rkf "$out" dci needs | grep -c 'bandwidth')" "1"
    chk dci-badfmt "$(macl_cmd_dci "3FE1A0" 3 >/dev/null 2>&1; echo $?)" "1"
    chk dci-nothex "$(macl_cmd_dci "zz" 1 >/dev/null 2>&1; echo $?)" "1"

    # ── scheduling pattern: 8 ms cadence, known periodicity ─────────────
    # Ten grants, RNTI 0x4E21, one every 8 ms, MCS 9 (QPSK), 6 PRBs.
    local grants=() i
    for (( i = 0; i < 10; i++ )); do
        grants+=("$(awk -v i="$i" 'BEGIN{printf "%.3f", i*0.008}'):4E21:9:6")
    done
    out=$(macl_cmd_sched_grants "${grants[@]}"); rc=$?
    chk sched-rc      "$rc" "0"
    chk sched-rntis   "$(rkf "$out" sched rntis 3)" "1"
    chk sched-grants  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_sched" && $2=="0x4E21"{print $4}')" "10"
    # The periodicity is the dominant inter-grant interval: 8.000 ms.
    chk sched-period  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_sched" && $2=="0x4E21"{print $7}')" "8.000"
    chk sched-pcount  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_sched" && $2=="0x4E21"{print $8}')" "9"
    chk sched-prbs    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_sched" && $2=="0x4E21"{print $11}')" "6"
    chk sched-prbsum  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_sched" && $2=="0x4E21"{print $12}')" "60"
    # MCS 9 is QPSK per TS 36.213 Table 7.1.7.1-1.
    chk sched-mod     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_app" && $3=="mcs_median"{print $6}')" "QPSK"
    chk sched-badgrant "$(macl_cmd_sched_grants "1:zz:2:3" >/dev/null 2>&1; echo $?)" "1"
    chk sched-noargs   "$(macl_cmd_sched_grants >/dev/null 2>&1; echo $?)" "2"
    # Two RNTIs on different cadences must be kept separate.
    out=$(macl_cmd_sched_grants "0.000:4E21:9:6" "0.008:4E21:9:6" \
                                "0.000:0A0B:20:25" "0.100:0A0B:20:25")
    chk sched-two "$(rkf "$out" sched rntis 3)" "2"
    chk sched-two-a "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_sched" && $2=="0x4E21"{print $7}')" "8.000"
    chk sched-two-b "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_sched" && $2=="0x0A0B"{print $7}')" "100.000"
    # MCS 20 is 16QAM; MCS 27 is 64QAM. Known values from the same table.
    chk mcs-qpsk   "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import macl_engine as e
print(e.mcs_modulation(9))")" "QPSK"
    # TS 36.213 Table 7.1.7.1-1: QPSK for MCS 0-9, 16QAM for 10-16,
    # 64QAM for 17-28. MCS 20 is therefore 64QAM, and MCS 16 is 16QAM.
    chk mcs-16qam  "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import macl_engine as e
print(e.mcs_modulation(16))")" "16QAM"
    chk mcs-64qam20 "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import macl_engine as e
print(e.mcs_modulation(20))")" "64QAM"
    chk mcs-64qam  "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import macl_engine as e
print(e.mcs_modulation(27))")" "64QAM"
    chk mcs-resv   "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import macl_engine as e
print(e.mcs_modulation(31))")" "64QAM"

    # ── RNTI track / sched pattern from a synthetic pcap ────────────────
    local cap="$d/mac.pcap"
    # Two UDP frames carrying the hand-built PDU, 8 ms apart. Ethernet +
    # IPv4 + UDP + the 13-byte PDU.
    python3 - "$cap" "$pdu" << 'PYFIX'
import sys, struct
path, pduhex = sys.argv[1], sys.argv[2]
pdu = bytes.fromhex(pduhex)
def frame(sport, dport):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(pdu), 0) + pdu
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x2222, 0, 64,
                     17, 0, bytes([10, 1, 0, 1]), bytes([10, 1, 0, 2]))
    eth = bytes.fromhex("0200000000aa0200000000bb0800")
    return eth + ip + udp
with open(path, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for i, sport in enumerate((40001, 40001)):
        f = frame(sport, 2152)
        ts = 1700000000.0 + i * 0.008
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        fh.write(struct.pack("<IIII", sec, usec, len(f), len(f)))
        fh.write(f)
PYFIX
    out=$(macl_cmd_rnti_track "$cap" dl); rc=$?
    chk track-rc        "$rc" "0"
    chk track-candidates "$(rkf "$out" track candidate_pdus 3)" "2"
    chk track-decoded   "$(rkf "$out" track decoded_pdus 3)" "2"
    chk track-undecoded "$(rkf "$out" track undecoded_pdus 3)" "0"
    chk track-lcids     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rnti_flow" && $2=="0"{print $9}')" "4,3,15"
    out=$(macl_cmd_sched_pattern "$cap" 1.0 dl); rc=$?
    chk schedp-rc      "$rc" "0"
    chk schedp-pdus    "$(rkf "$out" sched_pcap data_pdus 3)" "2"
    chk schedp-dom     "$(rkf "$out" sched_pcap dominant_interval_ms 3)" "8.000"
    chk schedp-bursts  "$(rkf "$out" sched_pcap bursts 3)" "1"
    chk track-nofile   "$(macl_cmd_rnti_track /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk sched-nofile   "$(macl_cmd_sched_pattern /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    # A pcapng must be refused with a reason, not misparsed as pcap.
    printf '\x0a\x0d\x0d\x0a' > "$d/x.pcapng"
    chk pcapng-rc  "$(macl_cmd_rnti_track "$d/x.pcapng" >/dev/null 2>&1; echo $?)" "1"
    chk pcapng-msg "$(macl_cmd_rnti_track "$d/x.pcapng" 2>&1 | grep -c 'pcapng')" "1"

    # ── integrity gap: BOTH halves must be present ──────────────────────
    # This is the assertion the module exists to keep honest. A report that
    # claimed "LTE has no integrity" without the control-plane half would be
    # wrong, and a report that claimed the control plane is unprotected
    # would be wrong in the other direction. Both are asserted.
    out=$(macl_cmd_integrity_gap); rc=$?
    chk gap-rc            "$rc" "0"
    chk gap-user-absent   "$(rkf "$out" integrity_gap user_plane_integrity 3)" "absent"
    chk gap-ctrl-present  "$(rkf "$out" integrity_gap control_plane_integrity 3)" "present"
    chk gap-precondition  "$(rkf "$out" integrity_gap alte_precondition 3)" "satisfied"
    chk gap-owner         "$(rkf "$out" integrity_gap owner_of_the_attack 3)" "32_cellular_dns (O10)"
    chk gap-has-both      "$(rkf "$out" integrity_gap conclusion | grep -c 'USER plane has no integrity protection; the CONTROL')" "1"
    # DRB integrity must be recorded as absent and SRB/NAS integrity as
    # present, in the detail table, not only in the summary line.
    chk gap-drb          "$(printf '%s\n' "$out" | awk -F'\t' '$1=="integrity" && $2=="user_plane" && $3=="DRB" && $4=="integrity"{print $5}')" "no"
    chk gap-srb          "$(printf '%s\n' "$out" | awk -F'\t' '$1=="integrity" && $2=="control_plane" && $3=="SRB" && $4=="integrity"{print $5}')" "yes"
    chk gap-nas          "$(printf '%s\n' "$out" | awk -F'\t' '$1=="integrity" && $2=="control_plane" && $3=="NAS" && $4=="integrity"{print $5}')" "yes"
    chk gap-drb-cipher   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="integrity" && $2=="user_plane" && $3=="DRB" && $4=="ciphering"{print $5}')" "yes"
    # The forbidden claim: nothing in the output may say the control plane
    # lacks integrity. Catch the string "no" in a control-plane integrity row.
    chk gap-no-false-claim "$(printf '%s\n' "$out" | awk -F'\t' '$1=="integrity" && $2=="control_plane" && $4=="integrity" && $5=="no"' | grep -c .)" "0"

    # ── RNTI table verb ─────────────────────────────────────────────────
    out=$(macl_cmd_rnti_table)
    chk rnti-table-si   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="0xFFFF"{print $2}')" "SI-RNTI"
    chk rnti-table-p    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="0xFFFE"{print $2}')" "P-RNTI"
    chk rnti-table-zero "$(printf '%s\n' "$out" | awk -F'\t' '$1=="0x0000"{print $2}')" "reserved"
    chk rnti-table-hd   "$(printf '%s\n' "$out" | head -n1 | awk -F'\t' '{print NF}')" "3"

    # ── sanitisation: a tab in a capture-derived string ─────────────────
    local evil
    evil=$(macl_sanitize $'evil\tlcid\r\nrow')
    chk sanitize-no-tabs "$(printf '%s' "$evil" | tr -d '\t\r\n' | wc -c | tr -d ' ')" \
        "$(printf '%s' "$evil" | wc -c | tr -d ' ')"
    chk sanitize-text "$(printf '%s' "$evil" | grep -c 'evil lcid')" "1"

    # ── status TSV contract ─────────────────────────────────────────────
    out=$(macl_cli_status_tsv)
    chk status-engine "$(fld "$out" engine)" "ready"
    chk status-path   "$(fld "$out" engine_path)" "$MOD_TMP/macl_engine.py"
    chk status-user   "$(fld "$out" user_plane_integrity)" "absent"
    chk status-ctrl   "$(fld "$out" control_plane_integrity)" "present"
    chk status-radio  "$(fld "$out" radio_required)" "no"
    chk status-attack "$(fld "$out" attack_coverage)" "P9"
    chk status-lcid   "$(fld "$out" lcid_source)" "TS 36.321 Table 6.2.1-1 (DL) / 6.2.1-2 (UL)"

    chk dispatch-unknown "$(macl_cli_main --nonsense >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-empty   "$(macl_cli_main >/dev/null 2>&1; echo $?)" "2"

    # The decoder must be pure stdlib.
    chk engine-no-numpy "$(grep -c 'import numpy' "$MOD_TMP/macl_engine.py")" "0"
    chk engine-no-scapy "$(grep -c 'import scapy\|from scapy' "$MOD_TMP/macl_engine.py")" "0"

    printf 'assertions\t%s\n' "$(( npass + bad ))"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
macl_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== cellular MAC layer ===${C_RESET}"
        echo -e "  ${C_DIM}LTE MAC/RLC/PDCP, RNTI tracking, scheduling patterns${C_RESET}"
        echo -e "  ${C_DIM}offline: hex PDU or a pcap; no radio needed${C_RESET}\n"
        cat << 'M'
  [1]  decode a MAC PDU (hex)
  [2]  LCID table (TS 36.321 6.2.1-1 / 6.2.1-2)
  [3]  RNTI table and classification
  [4]  track RNTIs across a pcap
  [5]  scheduling pattern from a pcap
  [6]  scheduling pattern from a grant list
  [7]  the integrity gap (aLTEr precondition)
  [8]  decode a DCI bit string
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                read -rp "  PDU hex> " h
                read -rp "  direction (dl|ul) [dl]> " dr
                macl_cmd_decode "$h" "${dr:-dl}" | column -t -s$'\t' 2>/dev/null || macl_cmd_decode "$h" "${dr:-dl}"
                read -rp "  press enter " _ ;;
            2) macl_cmd_lcid_table | column -t -s$'\t' 2>/dev/null || macl_cmd_lcid_table
               read -rp "  press enter " _ ;;
            3) macl_cmd_rnti_table | column -t -s$'\t' 2>/dev/null || macl_cmd_rnti_table
               read -rp "  press enter " _ ;;
            4)
                read -rp "  pcap path> " p
                read -rp "  direction (dl|ul) [dl]> " dr
                macl_cmd_rnti_track "$p" "${dr:-dl}" | column -t -s$'\t' 2>/dev/null || macl_cmd_rnti_track "$p" "${dr:-dl}"
                read -rp "  press enter " _ ;;
            5)
                read -rp "  pcap path> " p
                read -rp "  direction (dl|ul) [dl]> " dr
                macl_cmd_sched_pattern "$p" 1.0 "${dr:-dl}" | column -t -s$'\t' 2>/dev/null || macl_cmd_sched_pattern "$p" 1.0 "${dr:-dl}"
                read -rp "  press enter " _ ;;
            6)
                read -rp "  grants (ts:rnti:mcs:prbs, space separated)> " g
                # shellcheck disable=SC2086
                macl_cmd_sched_grants $g | column -t -s$'\t' 2>/dev/null || macl_cmd_sched_grants $g
                read -rp "  press enter " _ ;;
            7) macl_cmd_integrity_gap | column -t -s$'\t' 2>/dev/null || macl_cmd_integrity_gap
               read -rp "  press enter " _ ;;
            8)
                read -rp "  DCI hex> " h
                read -rp "  format (1|1A) [1]> " fm
                macl_cmd_dci "$h" "${fm:-1}" | column -t -s$'\t' 2>/dev/null || macl_cmd_dci "$h" "${fm:-1}"
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
macl_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     macl_cli_status_tsv ;;
        --decode-mac)     macl_cmd_decode "${1:-}" "${2:-dl}" ;;
        --lcid-table)     macl_cmd_lcid_table ;;
        --rnti-table)     macl_cmd_rnti_table ;;
        --rnti-track)     macl_cmd_rnti_track "${1:-}" "${2:-dl}" ;;
        --sched-pattern)  macl_cmd_sched_pattern "${1:-}" "${2:-1.0}" "${3:-dl}" ;;
        --sched-parse)    shift; macl_cmd_sched_grants "$@" ;;
        --integrity-gap)  macl_cmd_integrity_gap ;;
        --dci)            macl_cmd_dci "${1:-}" "${2:-1}" ;;
        --selftest)       macl_selftest ;;
        --menu)           macl_menu ;;
        *)
            cat >&2 <<EOF
Cellular MAC Layer - P9

Offline: a hex MAC PDU or a pcap. No radio, no root, no network.

Usage: $0 COMMAND
  --status-tsv                       decoder and store state as TSV
  --decode-mac <hex> [dl|ul]         decode an LTE MAC PDU: subheader chain,
                                     LCID, L, SDU/CE boundaries, TA TLV
  --lcid-table                       LCID table, TS 36.321 6.2.1-1 / -2
  --rnti-table                       RNTI space and its reserved values
  --rnti-track <pcap> [dl|ul]        RNTI/LCID evidence across a capture
  --sched-pattern <pcap> [idle] [dl|ul]
                                     grant cadence from MAC PDUs in a capture
  --sched-parse <ts:rnti:mcs:prbs>...
                                     cadence and allocation from a grant list
  --integrity-gap                    the aLTEr precondition: user plane has
                                     no integrity, control plane does
  --dci <hex> [1|1A]                 decode a DCI bit string
  --selftest                         verify tables and decoder offline
  --menu                             interactive menu

Direction matters: LCID 11 is Reserved in DL-SCH and CCCH in UL-SCH, so
the direction is an explicit argument rather than a guess.
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
    macl_cli_main "$@"
fi
