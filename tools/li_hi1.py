#!/usr/bin/env python3
"""li_hi1.py — the TS 33.108 HI1 notification operation as BER (X.690).

3GPP lawful interception names three handover interfaces: X1/HI1 carries the
administration (activation, deactivation, modification, alarms), X2/HI2 the
intercept-related information and X3/HI3 the content. TS 33.108 Annex M
("ASN.1 description of LI management notification operation (HI1 interface)")
gives HI1 an ASN.1 module, and TS 33.108 clause 5.2.1 says its parameters use
the basic encoding rules. That module is transcribed in
tools/asn/ts33108-hi1.asn, and this file is a BER encoder for it.

Why an encoder here rather than a codegen: the tree must encode HI1 with no
third-party runtime dependency, so this is standard-library Python and a
hand-written X.690 encoder. What keeps it honest is a second implementation:
tools/check-li-ber.sh builds the same values with pycrate (the referee), calls
.to_ber() and compares octet for octet. This file is not trusted, it is checked.

MODELLED (every type below is in tools/asn/ts33108-hi1.asn, verbatim):

  ThreeGPP-HI1-Operation  CHOICE [1] liActivated, [2] liDeactivated,
                                 [3] liModified, [4] alarms-indicator
  Notification            lawfulInterceptionIdentifier [1],
                          communicationIdentifier [2] (its
                          communication-Identity-Number [0] and
                          network-Identifier [1]), timeStamp [3],
                          target-Information [6] (its targetType [3] only),
                          network-Identifier [7]
  Alarm-Indicator         timeStamp [2], alarm-information [3],
                          lawfulInterceptionIdentifier [4],
                          network-Identifier [7]
  TimeStamp               localTime [0] LocalTimeStamp (generalizedTime [0],
                          winterSummerIndication [1]), utcTime [1] UTCTime
  Network-Identifier      operator-Identifier [0] (OCTET STRING 1..5),
                          network-Element-Identifier [1] (e164-Format [1],
                          x25-Format [2], iP-Format [3], dNS-Format [4])
  Target-Information      targetType [3] TargetType
  LawfulInterceptionIdentifier  OCTET STRING (SIZE (1..25))
  TargetType              ENUMERATED mSISDN(0) iMSI(1) iMEI(2) e164-Format(3)
                          nAI(4) sip-URI(5) tel-URI(6) iMPU(7) iMPI(8)

NOT MODELLED, and refused rather than dropped: domainID [0] (an OBJECT
IDENTIFIER), threeGPP-National-HI1-ASN1parameters [5], broadcastStatus [8],
the alarm's network-Element-Information [8], Target-Information's
broadcastArea [2] / deliveryInformation [4] / liActivatedTime [5] /
liDeactivatedTime [6] / liModificationTime [7] / interceptionType [8] /
liSetUpTime [9], DeliveryInformation, InterceptionType, BroadcastStatus,
Network-Element-Identifier's iP-Address [5] arm, IPAddress and IP-value,
CalledPartyNumber and ThreeGPP-National-HI1-ASN1parameters. A flag for any of
them is a refusal with exit 3: this encoder will not encode a field it does not
implement, and it will not silently write a PDU that lacks what its caller
asked for.

Encoding rules that matter here, since the module says DEFINITIONS IMPLICIT
TAGS: a context tag replaces the universal tag of the type it is applied to
(so [1] OCTET STRING is a primitive 0x81 with the octets as the value). A tag
applied to a CHOICE cannot be implicit, so [3] TimeStamp is a constructed
wrapper (0xA3) around the chosen alternative's own tag — the same shape
pycrate produces, which is how the differential check pins it down.

Exit: 0 encoded (or --selfcheck passed), 3 refused (a value that would be a
lie), 1 an internal error, 2 a usage error.

Usage:
  tools/li_hi1.py --selfcheck
  tools/li_hi1.py --encode --operation liActivated --liid LIID-0001 \\
                  [--epoch 1767225600 | --utc 2026-01-01T00:00:00Z |
                   --local-time 2026-01-01T00:00:00 [--winter-summer S]]
                  [--operator-id OP01] [--ne-id e164:1234]
                  [--target-type imsi] [--comm-id-num 12345678]
                  [--alarm-info ALARM-1] [--hex]
"""

import re
import sys
import time

# ── refusals ────────────────────────────────────────────────────────────
# Two shapes, because two different things went wrong: a Refusal is "this
# encoder will not write that, it would be a lie" (exit 3), and a UsageError is
# "that is not how this program is called" (exit 2). Neither ever prints a PDU.


class Refusal(Exception):
    def __init__(self, msg, why):
        Exception.__init__(self, msg)
        self.msg = msg
        self.why = why


class UsageError(Exception):
    pass


def refuse(msg, why):
    raise Refusal(msg, why)


# ── BER (X.690) primitives ──────────────────────────────────────────────
# Definite lengths only: BER allows the indefinite form, but nothing in HI1
# needs it and a definite length is what makes a PDU comparable octet for octet.
CLASS_CONTEXT = 0x80
CONSTRUCTED = 0x20


def def_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def tag_octet(num, constructed):
    """A context tag with a number below 31 is one octet."""
    if not 0 <= num <= 30:
        refuse("tag [%d] does not fit one octet" % num,
               "this encoder only writes the low tag numbers HI1 uses")
    return CLASS_CONTEXT | (CONSTRUCTED if constructed else 0) | num


class Node(object):
    """One TLV: either a primitive with octets, or a constructed node with
    children. Keeping the tree lets --encode print each field's offset, tag and
    length next to the PDU instead of re-parsing its own output."""

    __slots__ = ('path', 'tag', 'value', 'children')

    def __init__(self, path, tag, value=None, children=None):
        self.path = path
        self.tag = tag
        self.value = value
        self.children = children

    def content(self):
        if self.children is None:
            return self.value
        return b''.join(tlv(c.tag, c.content()) for c in self.children)


def tlv(tag, content):
    return bytes([tag]) + def_len(len(content)) + content


def prim(path, num, value):
    return Node(path, tag_octet(num, False), value=value)


def choice_wrap(path, num, child):
    """A tag applied to a CHOICE is always explicit: it wraps the alternative."""
    return Node(path, tag_octet(num, True), children=[child])


def seq(path, num, children):
    return Node(path, tag_octet(num, True), children=children)


def enum_octets(n):
    """ENUMERATED and INTEGER both encode as two's-complement minimal octets;
    every enumerator here is a small non-negative number."""
    if n == 0:
        return b'\x00'
    if n < 0:
        refuse("negative enumerator", "no HI1 enumerator is negative")
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if body[0] & 0x80:          # keep the leading octet below 0x80 so the
        body = b'\x00' + body   # value does not read back as negative
    return body


def render(root):
    """The PDU plus one row per TLV: path, tag octet, offset, length, octets."""
    pdu = tlv(root.tag, root.content())
    rows = []

    def walk(node, base):
        content = node.content()
        shown = '-' if node.children is not None else content.hex().upper()
        rows.append((node.path, node.tag, base, len(content), shown))
        if node.children is not None:
            off = base + 1 + len(def_len(len(content)))
            for child in node.children:
                walk(child, off)
                off += len(tlv(child.tag, child.content()))

    walk(root, 0)
    return pdu, rows


# ── value validation ────────────────────────────────────────────────────


def octets(name, text, lo, hi, charset_ok=None):
    """A string that becomes the octets of an OCTET STRING, checked against its
    SIZE constraint before anything is written."""
    if text is None or text == "":
        refuse("%s is empty" % name,
               "the ASN.1 type has SIZE (%d..%d) and an empty value is outside "
               "it" % (lo, hi))
    raw = text.encode('utf-8')
    if not lo <= len(raw) <= hi:
        refuse("%s is %d octet(s), outside SIZE (%d..%d)" % (name, len(raw), lo, hi),
               "TS 33.108 writes this field as an OCTET STRING with a fixed size "
               "range; a value outside it cannot be encoded, only truncated, and "
               "a truncated identifier names a different thing")
    if charset_ok is not None:
        for i, b in enumerate(raw):
            if not charset_ok(b):
                refuse("%s has a byte outside the permitted set at offset %d (0x%02X)"
                       % (name, i, b),
                       "this field is an ASCII string in the standard; a "
                       "control character or a non-ASCII byte would be encoded "
                       "as an octet the receiver cannot read back as text")
    return raw


def printable(b):
    return 0x20 <= b <= 0x7E


ID_OK = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.')
ID_OK_CTRL = set(range(0x20, 0x7F))


def liid_octets(text):
    """LawfulInterceptionIdentifier ::= OCTET STRING (SIZE (1..25)).
    The standard recommends a-z A-Z - _ . 0-9; anything printable is accepted
    here and nothing else is, so the recommendation is not passed off as a
    constraint this encoder enforces."""
    return octets("lawfulInterceptionIdentifier", text, 1, 25, printable)


MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def days_in_month(year, month):
    if month == 2 and (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)):
        return 29
    return MONTH_DAYS[month - 1]


def checked_fields(year, month, day, hour, minute, second):
    if not 1 <= month <= 12:
        refuse("month %d is outside 1..12" % month,
               "a time whose month is out of range is not a time; the encoder "
               "refuses it rather than writing a value the receiver has to guess at")
    if not 1 <= day <= days_in_month(year, month):
        refuse("day %d is outside 1..%d for %04d-%02d"
               % (day, days_in_month(year, month), year, month),
               "the day is checked against the month it is in, including "
               "February in a leap year")
    if not 0 <= hour <= 23:
        refuse("hour %d is outside 0..23" % hour,
               "UTCTime and GeneralizedTime carry a 24-hour clock; 24 and above "
               "is not an hour of the day")
    if not 0 <= minute <= 59:
        refuse("minute %d is outside 0..59" % minute,
               "a minute of the hour runs 0..59")
    if not 0 <= second <= 59:
        refuse("second %d is outside 0..59" % second,
               "a second of the minute runs 0..59; leap seconds are not carried "
               "by this encoding and 60 is refused rather than folded to 59")


UTC_RE = None


def parse_utc_text(text):
    """'YYYY-MM-DDTHH:MM:SSZ' -> (year, month, day, hour, minute, second)."""
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$', text or '')
    if not m:
        refuse("--utc '%s' is not YYYY-MM-DDTHH:MM:SSZ" % (text or ''),
               "the timestamp is written as UTC with an explicit Z; a value this "
               "encoder cannot read is refused rather than guessed at")
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    checked_fields(y, mo, d, h, mi, s)
    return (y, mo, d, h, mi, s)


def parse_local_text(text):
    """'YYYY-MM-DDTHH:MM:SS' (no Z: local time carries no zone)."""
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$', text or '')
    if not m:
        refuse("--local-time '%s' is not YYYY-MM-DDTHH:MM:SS" % (text or ''),
               "localTime is a local wall clock with no zone; the "
               "winterSummerIndication field says what that clock means, so a "
               "trailing Z here would claim UTC under a name that does not")
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    checked_fields(y, mo, d, h, mi, s)
    return (y, mo, d, h, mi, s)


def utc_octets(fields):
    """UTCTime: a two-digit year, so 1950..2049 and nothing else."""
    y, mo, d, h, mi, s = fields
    if not 1950 <= y <= 2049:
        refuse("year %04d cannot be written as a UTCTime" % y,
               "UTCTime carries YY; 1950..2049 is the range it can name. "
               "TS 33.108's TimeStamp offers localTime with a GeneralizedTime "
               "for other years, and this encoder does not write a two-digit "
               "year that would read as a different century")
    return ('%02d%02d%02d%02d%02d%02dZ'
            % (y % 100, mo, d, h, mi, s)).encode('ascii')


def gen_time_octets(fields):
    """GeneralizedTime in local time: four-digit year, no zone."""
    y, mo, d, h, mi, s = fields
    return ('%04d%02d%02d%02d%02d%02d' % (y, mo, d, h, mi, s)).encode('ascii')


WINTER_SUMMER = {'notProvided': 0, 'winterTime': 1, 'summerTime': 2}

TARGET_TYPES = {
    'msisdn': 0, 'imsi': 1, 'imei': 2, 'e164': 3, 'e164-format': 3,
    'nai': 4, 'sip-uri': 5, 'tel-uri': 6, 'impu': 7, 'impi': 8,
}

NE_FORMS = {
    'e164': 1, 'x25': 2, 'ip': 3, 'dns': 4,
}


# ── the HI1 types ───────────────────────────────────────────────────────


def network_element_identifier(spec, field_num, path):
    """Network-Element-Identifier CHOICE, four OCTET STRING arms modelled.

    Parsed as 'form:value' with form one of e164, x25, ip, dns. The fifth arm,
    iP-Address [5], is an IPAddress SEQUENCE this encoder does not model, so it
    is refused by name instead of being approximated with a text address.

    The field tag (field_num, 1 in both places the type appears) is explicit
    because a tag on a CHOICE cannot be implicit: it wraps the arm, whose own
    context tag stays. Tagging the wrapper with the arm number instead would
    collide with e164-Format [1] and be wrong for every other arm."""
    if ':' not in spec:
        refuse("--ne-id '%s' has no form" % spec,
               "the network element identifier is a CHOICE: write "
               "e164:NUMBER, x25:ADDRESS, ip:ADDRESS or dns:NAME")
    form, value = spec.split(':', 1)
    if form == 'iP-Address' or form == 'ip-address':
        refuse("Network-Element-Identifier iP-Address [5] is not modelled",
               "that arm is an IPAddress SEQUENCE (iP-type, iP-value, "
               "iP-assignment, prefix length, subnet mask) and this encoder "
               "implements none of it; encoding the address as text would be a "
               "different type with the same name")
    if form not in NE_FORMS:
        refuse("network element identifier form '%s' is not one of e164, x25, ip, dns"
               % form,
               "Network-Element-Identifier's other arms are the ones named; there "
               "is no silent default because a wrong arm is a wrong identifier")
    raw = octets("network-Element-Identifier/%s" % form, value, 1, 25, printable)
    return choice_wrap(path, field_num,
                       prim(path + '.%s' % form, NE_FORMS[form], raw))


def network_identifier(num, operator_id, ne_spec, path):
    """Network-Identifier ::= SEQUENCE { operator-Identifier [0] OCTET STRING
    (SIZE (1..5)), network-Element-Identifier [1] OPTIONAL, ... }

    Written with the caller's context tag in place of the universal SEQUENCE
    tag, which is what IMPLICIT TAGS means for a field of type SEQUENCE."""
    kids = [prim(path + '.operator-Identifier', 0,
                 octets("operator-Identifier", operator_id, 1, 5, printable))]
    if ne_spec:
        kids.append(network_element_identifier(
            ne_spec, 1, path + '.network-Element-Identifier'))
    return seq(path, num, kids)


def network_identifier_field(num, operator_id, ne_spec, path):
    return network_identifier(num, operator_id, ne_spec, path)


def timestamp_node(num, opts, path):
    """TimeStamp ::= CHOICE { localTime [0] LocalTimeStamp, utcTime [1] UTCTime }

    Exactly one of --epoch/--utc (UTC time) and --local-time (local time with a
    winterSummerIndication) is written, and a local time without an indication
    is refused because the field is not OPTIONAL in the standard."""
    has_local = opts.local_time is not None
    has_utc = opts.epoch is not None or opts.utc is not None
    if has_local and has_utc:
        refuse("--local-time and --utc/--epoch are both given",
               "TimeStamp is a CHOICE: it carries one time, either utcTime or a "
               "localTime with its winter/summer indication, never both")
    if not has_local and not has_utc:
        refuse("no timestamp given",
               "timeStamp is a mandatory field of Notification and of "
               "Alarm-Indicator; a record with no time is not a record")
    if has_local:
        if opts.winter_summer is None:
            refuse("--local-time needs --winter-summer",
               "LocalTimeStamp's winterSummerIndication [1] is not OPTIONAL, and "
               "a local wall clock means nothing without it: notProvided(0), "
               "winterTime(1) or summerTime(2)")
        if opts.winter_summer not in WINTER_SUMMER:
            refuse("--winter-summer '%s' is not notProvided, winterTime or summerTime"
                   % opts.winter_summer,
                   "the ENUMERATED has three named values; anything else would be "
                   "an enumerator this encoder invented")
        fields = parse_local_text(opts.local_time)
        inner = seq(path + '.localTime', 0, [
            prim(path + '.localTime.generalizedTime', 0, gen_time_octets(fields)),
            prim(path + '.localTime.winterSummerIndication', 1,
                 enum_octets(WINTER_SUMMER[opts.winter_summer])),
        ])
        inner.tag = tag_octet(0, True)
        return choice_wrap(path, num, inner)
    if opts.epoch is not None:
        fields = time.gmtime(opts.epoch)[:6]
        if fields[0] < 1970:
            refuse("--epoch %d is before 1970" % opts.epoch,
                   "the epoch is whole seconds since 1970-01-01T00:00:00Z")
        checked_fields(*fields)
    else:
        fields = parse_utc_text(opts.utc)
    utc = prim(path + '.utcTime', 1, utc_octets(fields))
    return choice_wrap(path, num, utc)


def target_information_node(num, opts, path):
    """Target-Information, targetType [3] only. The rest of the type
    (broadcastArea, deliveryInformation, the three times, interceptionType,
    liSetUpTime) is not modelled and has no flag."""
    if opts.target_type not in TARGET_TYPES:
        refuse("--target-type '%s' is not a TargetType enumerator" % opts.target_type,
               "the named values are mSISDN, iMSI, iMEI, e164-Format, nAI, sip-URI, "
               "tel-URI, iMPU and iMPI; this encoder will not write an enumerator "
               "that is not in the standard")
    inner = seq(path, 3, [
        prim(path + '.targetType', 3, enum_octets(TARGET_TYPES[opts.target_type])),
    ])
    inner.tag = tag_octet(num, True)
    return inner


def communication_identifier_node(num, opts, path):
    """CommunicationIdentifier, both of its modelled fields."""
    if opts.comm_id_num is None:
        refuse("--comm-id-num is required for communicationIdentifier",
               "CommunicationIdentifier's other field is the mandatory "
               "network-Identifier, which this encoder writes only through "
               "--operator-id; an empty SEQUENCE is not a value of this type")
    digits = opts.comm_id_num
    if not digits.isdigit():
        refuse("--comm-id-num '%s' is not digits" % digits,
               "the standard encodes the communication identity number as ASCII "
               "digits, e.g. '12345678'")
    raw = octets("communication-Identity-Number", digits, 1, 8, printable)
    kids = [prim(path + '.communication-Identity-Number', 0, raw)]
    # The operator identifier inside CommunicationIdentifier is its own flag:
    # --operator-id means Notification's top-level network-Identifier [7], and
    # one flag filling two places in the PDU is how a caller ends up with a
    # field it did not ask for.
    if opts.comm_operator_id is None:
        refuse("--comm-operator-id is required with --comm-id-num",
               "CommunicationIdentifier.network-Identifier [1] is not OPTIONAL; "
               "--operator-id is the top-level network-Identifier [7] and is not "
               "reused here")
    kids.append(network_identifier_field(1, opts.comm_operator_id, None,
                                         path + '.network-Identifier'))
    node = seq(path, num, kids)
    return node


def notification_node(tag_num, opts, path):
    """Notification ::= SEQUENCE {
         domainID [0] OPTIONAL, lawfulInterceptionIdentifier [1],
         communicationIdentifier [2] OPTIONAL, timeStamp [3],
         threeGPP-National-HI1-ASN1parameters [5] OPTIONAL,
         target-Information [6] OPTIONAL, network-Identifier [7] OPTIONAL,
         broadcastStatus [8] OPTIONAL, ... }"""
    # The components are written in the order the SEQUENCE declares them, which
    # is not the order they were thought of in: [2] sits between the two
    # mandatory fields. A SEQUENCE cannot be reordered the way a SET can.
    kids = [prim(path + '.lawfulInterceptionIdentifier', 1, liid_octets(opts.liid))]
    if opts.comm_id_num is not None:
        kids.append(communication_identifier_node(2, opts,
                                                  path + '.communicationIdentifier'))
    kids.append(timestamp_node(3, opts, path + '.timeStamp'))
    if opts.target_type is not None:
        kids.append(target_information_node(6, opts, path + '.target-Information'))
    if opts.operator_id is not None:
        kids.append(network_identifier_field(7, opts.operator_id, opts.ne_id,
                                             path + '.network-Identifier'))
    elif opts.ne_id is not None:
        refuse("--ne-id was given but --operator-id was not",
               "network-Element-Identifier is a field of Network-Identifier, and "
               "Network-Identifier's operator-Identifier is mandatory; refusing "
               "rather than writing the element identifier somewhere else")
    node = seq(path, tag_num, kids)
    return node


def alarm_indicator_node(tag_num, opts, path):
    """Alarm-Indicator ::= SEQUENCE {
         domainID [0] OPTIONAL, communicationIdentifier [1] OPTIONAL,
         timeStamp [2], alarm-information [3] OCTET STRING (SIZE (1..25)),
         lawfulInterceptionIdentifier [4] OPTIONAL,
         threeGPP-National-HI1-ASN1parameters [5] OPTIONAL,
         target-Information [6] OPTIONAL, network-Identifier [7] OPTIONAL,
         network-Element-Information [8] OPTIONAL, ... }"""
    if opts.alarm_info is None:
        refuse("--operation alarms-indicator needs --alarm-info",
               "alarm-information [3] is a mandatory field of Alarm-Indicator; "
               "an alarm with no information is not one")
    kids = [
        timestamp_node(2, opts, path + '.timeStamp'),
        prim(path + '.alarm-information', 3,
             octets("alarm-information", opts.alarm_info, 1, 25, printable)),
    ]
    if opts.liid is not None:
        kids.append(prim(path + '.lawfulInterceptionIdentifier', 4,
                         liid_octets(opts.liid)))
    if opts.operator_id is not None:
        kids.append(network_identifier_field(7, opts.operator_id, opts.ne_id,
                                             path + '.network-Identifier'))
    elif opts.ne_id is not None:
        refuse("--ne-id was given but --operator-id was not",
               "network-Element-Identifier is a field of Network-Identifier and "
               "operator-Identifier is mandatory in it")
    return seq(path, tag_num, kids)


OPERATIONS = {
    'liActivated': 1,
    'liDeactivated': 2,
    'liModified': 3,
    'alarms-indicator': 4,
}


def encode(opts):
    """Build the ThreeGPP-HI1-Operation CHOICE for one operation."""
    if opts.operation not in OPERATIONS:
        refuse("--operation '%s' is not an HI1 operation" % opts.operation,
               "the CHOICE has liActivated [1], liDeactivated [2], liModified [3] "
               "and alarms-indicator [4]; the fifth alternative (national "
               "parameters) is not modelled")
    tag_num = OPERATIONS[opts.operation]
    if opts.operation == 'alarms-indicator':
        if opts.liid is not None and opts.target_type is not None:
            refuse("Alarm-Indicator has no targetType field",
                   "target-Information is reachable from Alarm-Indicator, but "
                   "this encoder models only its targetType [3] and would have "
                   "nowhere to put it; drop --target-type or encode a "
                   "Notification instead")
        root = alarm_indicator_node(tag_num, opts, opts.operation)
    else:
        if opts.alarm_info is not None:
            refuse("--alarm-info was given for %s" % opts.operation,
                   "alarm-information belongs to Alarm-Indicator [4]; the other "
                   "three alternatives carry a Notification, which has no such "
                   "field")
        if opts.liid is None:
            refuse("--liid is required for %s" % opts.operation,
                   "lawfulInterceptionIdentifier [1] is mandatory in Notification "
                   "and is the identifier the DFs and the LEMF correlate on")
        root = notification_node(tag_num, opts, opts.operation)
    return root


# ── --encode output ─────────────────────────────────────────────────────
STANDARD = ('3GPP TS 33.108 Annex M HI1 notification operation '
            '(ThreeGPP-HI1NotificationOperations), BER per X.690')


def emit(node, operation, hex_only):
    pdu, rows = render(node)
    if hex_only:
        sys.stdout.write(pdu.hex().upper() + '\n')
        return 0
    print('standard\t%s' % STANDARD)
    print('encoding\tber/definite-length; the module says DEFINITIONS IMPLICIT TAGS')
    print('operation\t%s' % operation)
    print('pdu_bytes\t%d' % len(pdu))
    print('pdu_hex\t%s' % pdu.hex().upper())
    for path, tag, off, length, shown in rows:
        print('tlv\t%s\t0x%02X\t%d\t%d\t%s' % (path, tag, length, off, shown))
    print('field_count\t%d' % len(rows))
    return 0


# ── --selfcheck ─────────────────────────────────────────────────────────
# Known-answer vectors, each written out by hand from the standard's tags. The
# differential check in tools/check-li-ber.sh is the referee; these literals
# exist so the encoder fails by itself when it is run without the oracle.
SELFCHECK = [
    # liActivated: A1 (Notification [1]) with LIID [1] and a utcTime [3].
    (['--operation', 'liActivated', '--liid', 'LIID-0001',
      '--utc', '2026-01-01T00:00:00Z'],
     'A11C81094C4949442D30303031A30F810D3236303130313030303030305A'),
    # liDeactivated: the same Notification under [2].
    (['--operation', 'liDeactivated', '--liid', 'LIID-0001',
      '--utc', '2026-01-01T00:00:00Z'],
     'A21C81094C4949442D30303031A30F810D3236303130313030303030305A'),
    # liModified under [3].
    (['--operation', 'liModified', '--liid', 'LIID-0001',
      '--utc', '2026-01-01T00:00:00Z'],
     'A31C81094C4949442D30303031A30F810D3236303130313030303030305A'),
    # localTime with summerTime: timeStamp [3] wraps the TimeStamp CHOICE, so
    # A3 holds A0 (localTime [0] LocalTimeStamp as a SEQUENCE) holding
    # 80 0E "20260101000000" (generalizedTime, local: no trailing Z) and
    # 81 01 02 (winterSummerIndication summerTime).
    (['--operation', 'liActivated', '--liid', 'LIID-0001',
      '--local-time', '2026-01-01T00:00:00', '--winter-summer', 'summerTime'],
     'A12281094C4949442D30303031A315A013800E3230323630313031303030303030810102'),
    # A Network-Identifier [7]: operator-Identifier [0] "OP01" and an e164
    # network-Element-Identifier [1], wrapped explicitly (A1) because a tag on a
    # CHOICE cannot be implicit, around [1] "1234".
    (['--operation', 'liActivated', '--liid', 'LIID-0001',
      '--utc', '2026-01-01T00:00:00Z',
      '--operator-id', 'OP01', '--ne-id', 'e164:1234'],
     'A12C81094C4949442D30303031A30F810D3236303130313030303030305AA70E80044F503031A106810431323334'),
    # A target-Information [6] carrying targetType [3] iMSI(1).
    (['--operation', 'liActivated', '--liid', 'LIID-0001',
      '--utc', '2026-01-01T00:00:00Z', '--target-type', 'imsi'],
     'A12181094C4949442D30303031A30F810D3236303130313030303030305AA603830101'),
    # A communicationIdentifier [2] with an 8-digit identity number and the
    # mandatory network-Identifier; note [2] precedes [3] in the SEQUENCE.
    (['--operation', 'liActivated', '--liid', 'LIID-0001',
      '--utc', '2026-01-01T00:00:00Z', '--comm-id-num', '12345678',
      '--comm-operator-id', 'OP01'],
     'A13081094C4949442D30303031A21280083132333435363738A10680044F503031A30F810D3236303130313030303030305A'),
    # --epoch is converted to UTCTime here, so a harness run needs no date
    # formatting: 1700000000 is 2023-11-14T22:13:20Z -> "231114221320Z".
    (['--operation', 'liActivated', '--liid', 'L', '--epoch', '1700000000'],
     'A11481014CA30F810D3233313131343232313332305A'),
    # The other Network-Element-Identifier arms keep their own context tag
    # inside the explicit [1] wrapper: dNS-Format is [4], so 84. A wrapper
    # tagged with the arm number would read A4 here and be untranslatable.
    (['--operation', 'liActivated', '--liid', 'LIID-0001',
      '--utc', '2026-01-01T00:00:00Z',
      '--operator-id', 'AB', '--ne-id', 'dns:df2.example.invalid'],
     'A13981094C4949442D30303031A30F810D3236303130313030303030305AA71B80024142A11584136466322E6578616D706C652E696E76616C6964'),
    # An alarms-indicator [4]: timeStamp [2] and alarm-information [3], no LIID.
    (['--operation', 'alarms-indicator', '--alarm-info', 'ALARM-1',
      '--utc', '2026-01-01T00:00:00Z'],
     'A41AA20F810D3236303130313030303030305A8307414C41524D2D31'),
    # alarms-indicator with an x25-Format [2] network element, which also pins
    # that the wrapper tag is the field's [1] and not the arm's [2].
    (['--operation', 'alarms-indicator', '--alarm-info', 'ALARM-1',
      '--utc', '2026-01-01T00:00:00Z', '--liid', 'LIID-0001',
      '--operator-id', 'OP01', '--ne-id', 'x25:12345'],
     'A436A20F810D3236303130313030303030305A8307414C41524D2D3184094C4949442D30303031A70F80044F503031A10782053132333435'),
]

REFUSALS = [
    (['--operation', 'liActivated', '--liid', 'X' * 26,
      '--utc', '2026-01-01T00:00:00Z'], 'identifier longer than SIZE (1..25)'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T25:00:00Z'], 'hour 25'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T00:60:00Z'], 'minute 60'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T00:00:60Z'], 'second 60'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-02-30T00:00:00Z'], 'day outside the month'),
    (['--operation', 'liActivated', '--liid', 'L', '--epoch', '4294967295'],
     'epoch beyond UTCTime range'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--local-time', '2026-01-01T00:00:00'], 'localTime with no indication'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T00:00:00Z', '--operator-id', 'TOOLONG'],
     'operator-Identifier over SIZE (1..5)'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T00:00:00Z', '--ne-id', 'iP-Address:1.2.3.4'],
     'the iP-Address arm'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T00:00:00Z', '--domain-id', '1.2.3'],
     'an unmodelled field'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T00:00:00Z', '--broadcast-status', 'succesfull'],
     'an unmodelled field'),
    (['--operation', 'threeGPP-National-HI1-ASN1parameters', '--liid', 'L',
      '--utc', '2026-01-01T00:00:00Z'], 'an alternative that is not modelled'),
    (['--operation', 'liActivated', '--liid', 'L',
      '--utc', '2026-01-01T00:00:00Z', '--comm-id-num', '1234'],
     'a communication identity number with no network-Identifier'),
]


def selfcheck():
    bad = 0
    nchk = 0
    for args, want in SELFCHECK:
        nchk += 1
        try:
            opts = parse_args(args)
            node = encode(opts)
            pdu, _ = render(node)
            got = pdu.hex().upper()
        except (Refusal, UsageError) as e:
            got = 'REFUSED: %s' % e
        if got == want:
            print('selfcheck-encode-%d\tPASS' % nchk)
        else:
            print('selfcheck-encode-%d\tFAIL\n  want=%s\n  got=%s' % (nchk, want, got))
            bad += 1
    for args, what in REFUSALS:
        nchk += 1
        try:
            opts = parse_args(args)
            node = encode(opts)
            pdu, _ = render(node)
            got = 'ENCODED %s' % pdu.hex().upper()
        except Refusal:
            got = 'refused'
        except UsageError:
            got = 'usage'
        if got == 'refused':
            print('selfcheck-refuse-%d\tPASS\t%s' % (nchk, what))
        else:
            print('selfcheck-refuse-%d\tFAIL want=refused got=%s (%s)'
                  % (nchk, got, what))
            bad += 1
    # A refusal is a refusal for the right reason: the message has to name the
    # constraint, not merely fail.
    nchk += 1
    try:
        encode(parse_args(['--operation', 'liActivated', '--liid', 'X' * 26,
                           '--utc', '2026-01-01T00:00:00Z']))
        print('selfcheck-refusal-names-constraint\tFAIL want=a refusal got=none')
        bad += 1
    except Refusal as e:
        ok = ('SIZE' in e.msg or 'SIZE' in e.why)
        print('selfcheck-refusal-names-constraint\t%s' % ('PASS' if ok else
              'FAIL want=a message naming SIZE got=%s' % e.msg))
        if not ok:
            bad += 1
    print('ASSERTIONS\t%d' % nchk)
    print('RESULT\t%s' % ('PASS' if bad == 0 else 'FAIL(%d)' % bad))
    return 0 if bad == 0 else 1


# ── CLI ─────────────────────────────────────────────────────────────────
class Options(object):
    def __init__(self):
        self.operation = None
        self.liid = None
        self.epoch = None
        self.utc = None
        self.local_time = None
        self.winter_summer = None
        self.operator_id = None
        self.ne_id = None
        self.target_type = None
        self.comm_id_num = None
        self.comm_operator_id = None
        self.alarm_info = None
        self.hex_only = False


# Every flag this encoder does not implement, named so the refusal can say what
# it is. A field the standard has and this file does not model is exactly the
# thing that must not be dropped in silence.
UNMODELLED = {
    '--domain-id': 'Notification/Alarm-Indicator domainID [0], an OBJECT IDENTIFIER',
    '--national-parameters': 'threeGPP-National-HI1-ASN1parameters [5]',
    '--broadcast-status': 'Notification broadcastStatus [8]',
    '--ne-information': "Alarm-Indicator's network-Element-Information [8]",
    '--broadcast-area': 'Target-Information broadcastArea [2]',
    '--delivery-ip': 'Target-Information deliveryInformation [4]',
    '--delivery-number': 'Target-Information deliveryInformation [4]',
    '--li-activated-time': 'Target-Information liActivatedTime [5]',
    '--li-deactivated-time': 'Target-Information liDeactivatedTime [6]',
    '--li-modification-time': 'Target-Information liModificationTime [7]',
    '--interception-type': 'Target-Information interceptionType [8]',
    '--li-setup-time': 'Target-Information liSetUpTime [9]',
    '--winter-summer-indication': 'LocalTimeStamp winterSummerIndication [1] '
                                  '(spelled --winter-summer here)',
    '--timestamp': 'TimeStamp (use --utc, --epoch or --local-time)',
    '--target-information': 'Target-Information beyond its targetType [3]',
}


def parse_args(argv):
    opts = Options()
    i = 0
    n = len(argv)
    value_flags = ('--operation', '--liid', '--epoch', '--utc', '--local-time',
                   '--winter-summer', '--operator-id', '--ne-id', '--target-type',
                   '--comm-id-num', '--comm-operator-id', '--alarm-info')
    while i < n:
        a = argv[i]
        if a == '--hex':
            opts.hex_only = True
            i += 1
            continue
        if a in UNMODELLED:
            refuse("%s is not modelled by this encoder" % a,
                   "%s is in tools/asn/ts33108-hi1.asn and this encoder has no "
                   "code for it; dropping it would write a PDU that is missing a "
                   "field its caller asked for, so it is refused instead" % UNMODELLED[a])
        if a not in value_flags:
            raise UsageError('unknown option %s' % a)
        if i + 1 >= n:
            raise UsageError('%s takes a value' % a)
        v = argv[i + 1]
        if a == '--operation':
            opts.operation = v
        elif a == '--liid':
            opts.liid = v
        elif a == '--epoch':
            if not v.isdigit():
                raise UsageError('--epoch takes whole seconds')
            opts.epoch = int(v)
        elif a == '--utc':
            opts.utc = v
        elif a == '--local-time':
            opts.local_time = v
        elif a == '--winter-summer':
            opts.winter_summer = v
        elif a == '--operator-id':
            opts.operator_id = v
        elif a == '--ne-id':
            opts.ne_id = v
        elif a == '--target-type':
            opts.target_type = v
        elif a == '--comm-id-num':
            opts.comm_id_num = v
        elif a == '--comm-operator-id':
            opts.comm_operator_id = v
        elif a == '--alarm-info':
            opts.alarm_info = v
        i += 2
    return opts


USAGE = """li_hi1.py — TS 33.108 Annex M HI1 notification operation, BER encoder.

Usage:
  tools/li_hi1.py --selfcheck
  tools/li_hi1.py --encode --operation liActivated|liDeactivated|liModified|alarms-indicator
                  --liid <1..25 octets>            (Notification arms only)
                 [--epoch <seconds> | --utc YYYY-MM-DDTHH:MM:SSZ |
                  --local-time YYYY-MM-DDTHH:MM:SS --winter-summer notProvided|winterTime|summerTime]
                 [--operator-id <1..5 chars>] [--ne-id e164:|x25:|ip:|dns:<1..25>]
                 [--target-type msisdn|imsi|imei|e164|nai|sip-uri|tel-uri|impu|impi]
                 [--comm-id-num <1..8 digits> --comm-operator-id <1..5 chars>]
                 [--alarm-info <1..25 octets>]   (alarms-indicator only)
                 [--hex]

--encode prints TSV: standard, encoding, operation, pdu_bytes, pdu_hex, then one
`tlv` row per field (path, tag octet, length, offset, octets; '-' for a
constructed node) and field_count. --hex prints the PDU hex alone.

Exit: 0 encoded, 3 refused (the value cannot be written as the standard defines
it, or a field this encoder does not model was asked for), 2 usage, 1 internal.
"""


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        sys.stderr.write(USAGE)
        return 0 if argv else 2
    if argv[0] == '--selfcheck':
        return selfcheck()
    if argv[0] != '--encode':
        sys.stderr.write(USAGE)
        return 2
    try:
        opts = parse_args(argv[1:])
        root = encode(opts)
    except Refusal as e:
        sys.stderr.write('ERROR\t%s\n' % e.msg)
        sys.stderr.write('WHY\t%s\n' % e.why)
        return 3
    except UsageError as e:
        sys.stderr.write('ERROR\t%s\n' % e)
        sys.stderr.write('WHY\trun tools/li_hi1.py --help for the interface\n')
        return 2
    return emit(root, opts.operation, opts.hex_only)


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except Refusal as e:                     # a refusal raised outside --encode
        sys.stderr.write('ERROR\t%s\n' % e.msg)
        sys.stderr.write('WHY\t%s\n' % e.why)
        sys.exit(3)
