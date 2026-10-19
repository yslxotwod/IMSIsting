#!/usr/bin/env python3
"""Read the identity out of a NAS message, and say what it proves.

Why this file exists
--------------------
``17_pcap_analysis`` finds IMSIs by scanning payloads for BCD digits, and
``09_lte_attach --identity-exposure`` answers a different question: whether the
NETWORK asked for the IMSI in the clear.  Neither reads the identity the
subscriber itself sends.  On LTE that identity is in the EPS mobile identity
information element, and it is the one field a small cell can harvest without
touching the key material.

This module decodes that element structurally instead of guessing at digit
strings, because a scan cannot tell an IMSI from a byte coincidence and cannot
tell an IMSI from a GUTI.  It reports the identity it found with the message it
came from, and refuses the cases it does not implement rather than printing a
number that looks plausible.

Octet layout, and why the shifts look odd
-----------------------------------------
The EPS mobile identity is a length octet followed by a value.  The value's
first octet carries, in the low three bits, the type of identity, and in bit 4
the odd/even indication:

    bit  8 7 6 5 | 4 | 3 2 1
         spare   | O | type      -> type = octet & 0x07, odd = (octet >> 3) & 1

``tshark`` confirms both fields on a synthetic message (type 1 = IMSI for the
octets 0x01, 0x09; type 2 for 0x02, which it names "reserved"), and
``pycrate_mobile.TS24008_IE.IDDigit`` agrees on the same bit positions.

The digits are BCD with the LOW nibble first, which is the encoding TS 24.008
uses for the MCC and MNC inside an IMSI.  ``tshark`` prints its IMSI field with
one extra leading digit taken from the spare nibble of the identity octet (for
the octets above, ``IMSI: 0208010123456789`` for the digits
``208010123456789``), so the referee in ``tools/nas-oracle`` compares against
that field with the spare digit removed and says so in its own output.  The
digit order is not taken on trust from either program: the selftest carries a
vector whose digits differ under the two orders.

What it does not do
-------------------
It does not decrypt anything.  A NAS message whose security header says the
body is ciphered is reported ``protected`` and its body is not read, because
there is nothing to read.  5GMM identity coding is a different discriminator and
is reported ``unbuilt`` rather than half-parsed.
"""

from __future__ import annotations

import argparse
import sys

# Protocol discriminators (TS 24.007 §11.2.3.1.1).
DISC_EPMM = 0x07
DISC_5GMM = 0x7E

# Security header types worth naming.  Only type 0 leaves the body in the clear.
SECURITY = {
    0x0: ("plain", True),
    0x1: ("integrity-protected", False),
    0x2: ("integrity-protected-and-ciphered", False),
    0x3: ("integrity-protected-with-new-context", False),
    0x4: ("integrity-protected-and-ciphered-with-new-context", False),
    0x5: ("integrity-protected", False),
    0xC: ("service-request", False),
}

# EPS mobility management message types this file reads (TS 24.301 §9.8).
MESSAGES = {
    0x41: "Attach Request",
    0x48: "Tracking Area Update Request",
    0x50: "GUTI Reallocation Command",
    0x53: "Identity Request",
    0x56: "Identity Response",
}

# Type of identity, the low three bits of the value's first octet (§9.9.3.4).
# Only the types a referee confirms are named: tshark's dissector reports 1 as
# IMSI and 3 as IMEI on a synthetic message, and 2 as reserved.  A type this file
# has not confirmed is printed by number rather than guessed at, and types 1, 2
# and 3 are the digit-coded ones (the rest are fixed-width identifiers).
IDENTITY_KIND = {
    0x0: "no-identity",
    0x1: "imsi",
    0x2: "type-2",
    0x3: "imei",
    0x4: "type-4",
    0x5: "type-5",
    0x6: "guti",
    0x7: "type-7",
}
DIGIT_KINDS = (0x1, 0x2, 0x3)
NAMED_KINDS = ("imsi", "imei")


class NasError(Exception):
    """A message this file will not read, with the reason in the text."""


def _digits(data: bytes, count: int | None = None) -> str:
    """BCD digits, LOW nibble first, with a trailing filler removed.

    ``count`` is the expected number of digits when the caller knows it; the
    odd/even indication supplies it for an identity, where the last nibble is
    a filler of 0xf when the count is odd.
    """
    out = []
    for octet in data:
        out.append("%x" % (octet & 0x0F))
        out.append("%x" % ((octet >> 4) & 0x0F))
    text = "".join(out)
    if count is not None:
        return text[:count]
    return text.rstrip("f")


def _plmn(digits: str) -> tuple[str, str, str, str, str]:
    """MCC plus both readings of the MNC.

    An IMSI does not say how many digits its MNC has: that is an operator fact.
    Rather than pick, this returns both readings and the MSIN that follows each,
    so the caller can say "the MNC is two or three digits" instead of inventing
    one answer.
    """
    mcc = digits[0:3]
    return mcc, digits[3:5], digits[3:6], digits[5:], digits[6:]


def _plmn_octets(octets: bytes) -> tuple[str, str, str]:
    """MCC and both MNC readings from the three PLMN octets.

    The order is the one TS 24.008 §10.5.1.3 uses and the one S1AP shares:
    octet 1 holds MCC digits 2 and 1, octet 2 holds the MNC's third digit in its
    high nibble and MCC digit 3 in its low nibble, and octet 3 holds MNC digits
    1 and 2.  The MNC's third digit is the filler 0xf when the MNC is two digits,
    which is why both readings are reported rather than one chosen.
    """
    if len(octets) != 3:
        raise NasError("a PLMN is three octets, this is %d" % len(octets))
    o1, o2, o3 = octets
    mcc = "%x%x%x" % (o1 & 0x0F, (o1 >> 4) & 0x0F, o2 & 0x0F)
    mnc2 = "%x%x" % (o3 & 0x0F, (o3 >> 4) & 0x0F)
    mnc3 = "%x%x%x" % (o3 & 0x0F, (o3 >> 4) & 0x0F, (o2 >> 4) & 0x0F)
    if (o2 >> 4) & 0x0F == 0x0F:
        mnc3 = mnc3  # the filler is kept so a two-digit MNC is visible as one
    return mcc, mnc2, mnc3


def _row(rows: list[tuple[str, str]], key: str, value: object) -> None:
    rows.append((key, "" if value is None else str(value)))


def _identity_value(rows: list[tuple[str, str]], raw: bytes, where: str) -> None:
    """Decode the value of an EPS mobile identity element."""
    if not raw:
        raise NasError("%s carries no identity octet" % where)
    first = raw[0]
    kind = IDENTITY_KIND.get(first & 0x07, "reserved")
    odd = bool((first >> 3) & 0x01)
    body = raw[1:]
    _row(rows, "identity_kind", kind)
    _row(rows, "odd_even", "odd" if odd else "even")

    if (first & 0x07) in DIGIT_KINDS:
        count = len(body) * 2 - (1 if odd else 0)
        digits = _digits(body, count)
        # The filler nibble is only a filler when it is the last one and the
        # count is odd; a digit f anywhere else means the octets are not an
        # identity and the number below would be a coincidence.
        stray = [i for i, c in enumerate(digits) if c == "f"]
        if stray:
            raise NasError("%s: filler digit inside the number at position %d"
                           % (where, stray[0] + 1))
        _row(rows, "identity", digits)
        _row(rows, "digit_count", len(digits))
        if kind not in NAMED_KINDS:
            _row(rows, "name_asserted", "no: type %d is not a name a referee confirmed"
                 % (first & 0x07))
        if (first & 0x07) == 0x1:
            mcc, mnc2, mnc3, msin2, msin3 = _plmn(digits)
            _row(rows, "mcc", mcc)
            _row(rows, "mnc_2digit", mnc2)
            _row(rows, "mnc_3digit", mnc3)
            _row(rows, "msin_2digit", msin2)
            _row(rows, "msin_3digit", msin3)
            _row(rows, "mnc_length", "not carried: %s or %s" % (mnc2, mnc3))
        if (first & 0x07) == 0x1 and len(digits) != 15:
            _row(rows, "note", "an IMSI is 15 digits; this one is %d" % len(digits))
        return

    if kind == "guti":
        if len(body) != 10:
            raise NasError("%s: a GUTI is 10 octets after its type, this is %d"
                           % (where, len(body)))
        mcc, mnc2, mnc3 = _plmn_octets(body[0:3])
        mmegi = int.from_bytes(body[3:5], "big")
        mmec = body[5]
        mtmsi = int.from_bytes(body[6:10], "big")
        _row(rows, "mcc", mcc)
        _row(rows, "mnc_2digit", mnc2)
        _row(rows, "mnc_3digit", mnc3)
        _row(rows, "mme_group_id", "0x%04x" % mmegi)
        _row(rows, "mme_code", "0x%02x" % mmec)
        _row(rows, "m_tmsi", "0x%08x" % mtmsi)
        _row(rows, "identity", "mmegi=%d mme_code=%d m-tmsi=0x%08x"
             % (mmegi, mmec, mtmsi))
        return

    if (first & 0x07) == 0x4:
        if len(body) != 4:
            raise NasError("%s: a TMSI is 4 octets, this is %d" % (where, len(body)))
        _row(rows, "tmsi", "0x%08x" % int.from_bytes(body, "big"))
        _row(rows, "identity", "tmsi=0x%08x" % int.from_bytes(body, "big"))
        return

    if kind == "no-identity":
        _row(rows, "identity", "no identity provided")
        return

    raise NasError("%s: identity type %d is %s, not something this file decodes"
                   % (where, first & 0x07, kind))


def decode(hex_text: str) -> list[tuple[str, str]]:
    """Rows for one NAS message.  Raises NasError with the reason."""
    text = "".join(hex_text.split()).replace(":", "").replace("-", "")
    if not text:
        raise NasError("no octets given")
    if len(text) % 2:
        raise NasError("odd number of hex digits")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise NasError("not hex octets: %s" % exc)
    if len(raw) < 3:
        raise NasError("shorter than a NAS header")

    # 5GS puts the whole extended protocol discriminator in octet 1, so it must
    # be recognised before the nibble split that EPS uses.
    if raw[0] == DISC_5GMM:
        raise NasError("5GMM discriminator 0x7e: 5GS identity coding is not built "
                       "in this file (the EPS element is a different layout)")
    disc = raw[0] & 0x0F
    header = (raw[0] >> 4) & 0x0F
    rows: list[tuple[str, str]] = []
    if disc != DISC_EPMM:
        raise NasError("discriminator 0x%x is not EMM (0x%02x)" % (disc, DISC_EPMM))

    stage_name, plain = SECURITY.get(header, ("unknown", False))
    message_type = raw[1]
    _row(rows, "generation", "eps")
    _row(rows, "discriminator", "0x%02x" % disc)
    _row(rows, "security_header", header)
    _row(rows, "stage", stage_name)
    _row(rows, "message_type", "0x%02x" % message_type)
    _row(rows, "message_name", MESSAGES.get(message_type, "message 0x%02x" % message_type))

    if not plain:
        _row(rows, "identity_kind", "unreadable")
        _row(rows, "identity", "not read")
        _row(rows, "proves",
             "the body is ciphered or integrity protected; the identity is not in "
             "the clear here")
        return rows

    body = raw[2:]
    if message_type in (0x41, 0x48):
        if len(body) < 2:
            raise NasError("message 0x%02x ends before its mobile identity"
                           % message_type)
        length = body[1]
        if length < 2:
            raise NasError("mobile identity length %d is shorter than its type octet"
                           % length)
        value = body[2:2 + length]
        if len(value) != length:
            raise NasError("mobile identity says %d octets, %d are present"
                           % (length, len(value)))
        _row(rows, "identity_ie", "EPS mobile identity (length %d)" % length)
        _identity_value(rows, value, "EPS mobile identity")
    elif message_type == 0x50:
        if len(body) < 2:
            raise NasError("GUTI reallocation command ends before its identity")
        length = body[1]
        value = body[2:2 + length]
        if len(value) != length:
            raise NasError("GUTI says %d octets, %d are present" % (length, len(value)))
        _row(rows, "identity_ie", "EPS mobile identity (length %d)" % length)
        _identity_value(rows, value, "GUTI reallocation command")
    elif message_type == 0x56:
        # The element is a length/value pair even though the value is the last
        # thing in the message: pycrate types it Type4LV and tshark reads the
        # octet as a length, so a response without one is read as a one-octet
        # identity of type IMEI.
        if len(body) < 2:
            raise NasError("identity response carries no identity element")
        length = body[0]
        value = body[1:1 + length]
        if length == 0 or len(value) != length:
            raise NasError("identity response says %d octets, %d are present"
                           % (length, len(value)))
        _row(rows, "identity_ie", "EPS mobile identity (length %d)" % length)
        _identity_value(rows, value, "identity response")
    elif message_type == 0x53:
        if not body:
            raise NasError("identity request carries no identity type")
        first = body[0]
        kind = IDENTITY_KIND.get(first & 0x07, "reserved")
        _row(rows, "identity_ie", "identity request")
        _row(rows, "requested_kind", kind)
        _row(rows, "identity_kind", "requested")
        _row(rows, "identity", "the network asked for %s" % kind)
        _row(rows, "proves",
             "what was asked for, not what was sent; the answer is a separate "
             "message")
    else:
        _row(rows, "identity_ie", "none")
        _row(rows, "identity_kind", "none")
        _row(rows, "proves",
             "%s carries no subscriber identity in this file's reading"
             % MESSAGES.get(message_type, "message 0x%02x" % message_type))
    return rows


def _proves(rows: list[tuple[str, str]]) -> None:
    """One sentence naming what the identity establishes, from the rows."""
    table = dict(rows)
    kind = table.get("identity_kind", "none")
    stage = table.get("stage", "")
    if stage == "plain" and kind == "imsi":
        _row(rows, "exposure",
             "the subscriber sent its IMSI in a plain NAS message: readable to "
             "anyone holding the air interface")
        _row(rows, "severity", "high")
        return
    if stage == "plain" and kind in ("guti", "tmsi"):
        _row(rows, "exposure",
             "a temporary identity in the clear: the permanent identity stayed "
             "in the network")
        _row(rows, "severity", "low")
        return
    if stage != "plain":
        _row(rows, "exposure", "nothing read: the body is protected")
        _row(rows, "severity", "none")
        return
    _row(rows, "exposure", "no identity in this message")
    _row(rows, "severity", "none")


def _emit(rows: list[tuple[str, str]]) -> None:
    for key, value in rows:
        if "\t" in key or "\n" in key:
            continue
        print("%s\t%s" % (key, value.replace("\t", " ").replace("\n", " ")))


def cmd_decode(hex_text: str) -> int:
    try:
        rows = decode(hex_text)
    except NasError as exc:
        print("status\trefused", file=sys.stdout)
        print("why\t%s" % exc, file=sys.stdout)
        return 1
    _proves(rows)
    _emit(rows)
    return 0


# ── selftest ────────────────────────────────────────────────────────────
# Fixtures are written here as octet strings, and each one is a layout claim:
# the assertion names the claim, so a layout that changes fails a named test.
V_ATTACH_IMSI_ODD = "074101" "09" "09" "02080121436587f9"
V_ATTACH_GUTI = "074101" "0b" "06" "00f110" "0001" "02" "0a0b0c0d"
V_ID_RESPONSE_IMSI_EVEN = "0756" "08" "01" "02080121436587"
V_ID_REQUEST = "075301"
V_PROTECTED = "274101090902080121436587f9"
V_FIVEG = "7e4101"


def selftest() -> int:
    checks: list[tuple[str, bool, str]] = []

    def chk(name: str, got: object, want: object) -> None:
        checks.append((name, str(got) == str(want), "%r" % (got,)))

    def table(hex_text: str) -> dict[str, str]:
        rows = decode(hex_text)
        _proves(rows)
        return dict(rows)

    t = table(V_ATTACH_IMSI_ODD)
    chk("attach-message-name", t.get("message_name"), "Attach Request")
    chk("attach-kind", t.get("identity_kind"), "imsi")
    chk("attach-digits", t.get("identity"), "208010123456789")
    chk("attach-digit-count", t.get("digit_count"), "15")
    chk("attach-odd", t.get("odd_even"), "odd")
    chk("attach-mcc", t.get("mcc"), "208")
    chk("attach-mnc-two", t.get("mnc_2digit"), "01")
    chk("attach-mnc-three", t.get("mnc_3digit"), "010")
    chk("attach-msin-two", t.get("msin_2digit"), "0123456789")
    chk("attach-msin-three", t.get("msin_3digit"), "123456789")
    chk("attach-exposure", t.get("exposure") is not None and
        t.get("exposure", "").startswith("the subscriber sent its IMSI"), True)
    chk("attach-severity", t.get("severity"), "high")

    # The digit order is a claim, so a vector proves the other order is wrong.
    chk("digit-order", _digits(bytes.fromhex("21436587092143f5"), 15),
        "123456789012345")

    g = table(V_ATTACH_GUTI)
    chk("guti-kind", g.get("identity_kind"), "guti")
    chk("guti-mme-group", g.get("mme_group_id"), "0x0001")
    chk("guti-mme-code", g.get("mme_code"), "0x02")
    chk("guti-mtmsi", g.get("m_tmsi"), "0x0a0b0c0d")
    chk("guti-mcc", g.get("mcc"), "001")
    chk("guti-mnc", g.get("mnc_2digit"), "01")
    chk("guti-severity", g.get("severity"), "low")

    r = table(V_ID_RESPONSE_IMSI_EVEN)
    chk("response-kind", r.get("identity_kind"), "imsi")
    chk("response-digits", r.get("identity"), "20801012345678")
    chk("response-even", r.get("odd_even"), "even")
    chk("response-count", r.get("digit_count"), "14")

    q = table(V_ID_REQUEST)
    chk("request-kind", q.get("identity_kind"), "requested")
    chk("request-wanted", q.get("requested_kind"), "imsi")
    chk("request-proves", q.get("proves") is not None and
        "not what was sent" in q.get("proves", ""), True)

    p = table(V_PROTECTED)
    chk("protected-stage", p.get("stage"), "integrity-protected-and-ciphered")
    chk("protected-kind", p.get("identity_kind"), "unreadable")
    chk("protected-severity", p.get("severity"), "none")

    for name, text, want in (
        ("fiv-eg-unbuilt", V_FIVEG, "5GMM"),
        ("garbage", "zz", "not hex"),
        ("short", "07", "shorter"),
        ("odd-length", "074", "odd number"),
        ("bad-length", "0741010909" "02", "says 9 octets"),
    ):
        try:
            decode(text)
            checks.append((name, False, "no refusal"))
        except NasError as exc:
            checks.append((name, want.lower() in str(exc).lower(), str(exc)))

    failed = 0
    for name, ok, got in checks:
        print("ASSERTION\t%s\t%s\t%s" % (name, "PASS" if ok else "FAIL", got))
        if not ok:
            failed += 1
    print("ASSERTIONS\t%d" % len(checks))
    print("RESULT\t%s" % ("PASS" if failed == 0 else "FAIL %d" % failed))
    return 0 if failed == 0 else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Read the subscriber identity out of a NAS message")
    sub = parser.add_subparsers(dest="verb")
    p = sub.add_parser("decode", help="rows for one NAS message")
    p.add_argument("hex")
    sub.add_parser("selftest", help="assert the layouts against fixed vectors")
    args = parser.parse_args(argv)
    if args.verb == "decode":
        return cmd_decode(args.hex)
    if args.verb == "selftest":
        return selftest()
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
