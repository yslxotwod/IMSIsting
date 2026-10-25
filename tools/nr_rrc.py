#!/usr/bin/env python3
"""NR RRC (TS 38.331) decode, over the generated unaligned-PER table.

This is the read half only, and deliberately so: `49_ntn` needs to read the
SIB19 a satellite cell broadcasts, and nothing here yet needs to build an NR
message.  An encoder would have to survive `describe`/refusal checks like
`tools/lte_rrc.py` does, and there is no caller for it.

The bits come from `tools/nr_rrc_layout.py`, generated from pycrate's RRCNR
namespace by `tools/asn1gen.py --family nr` and certified case by case with
`tools/lte-per-oracle/verify_per.py --table tools/nr_rrc_layout.py`.

Regenerate (needs the oracle venv):
    /home/ysl/.lte-oracles/venv/bin/python tools/asn1gen.py --family nr
Re-certify:
    /home/ysl/.lte-oracles/venv/bin/python \\
        tools/lte-per-oracle/verify_per.py --table tools/nr_rrc_layout.py

Why a walker and not a hand-written decoder: SIB19 spends most of its bits in
`NTN-Config-r17`, whose ephemeris is a CHOICE of three orbit models, and a
hand-written reader would either invent fields or ignore the ones it did not
expect.  Every field this prints is a field the schema names.
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import lte_per  # noqa: E402  (the path fix-up has to come first)
import nr_rrc_layout  # noqa: E402

CODEC = lte_per.codec_from_module(nr_rrc_layout)
TYPES = nr_rrc_layout.TYPES
ROOTS = list(nr_rrc_layout.ROOTS)
FAMILY = nr_rrc_layout.FAMILY


class Refused(ValueError):
    """A question this tool will not answer, because the answer would lie."""


def _bits_of_hex(hexstr, nbits=None):
    """A hex string as a bit string, refusing anything that is not hex.

    An odd number of nibbles is refused rather than padded: padding invents
    four bits, and a decoder handed invented bits answers about a message
    nobody sent.
    """
    s = (hexstr or "").strip().replace(" ", "").replace(":", "")
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    if not s:
        raise Refused("no bits: pass the message as hex")
    if len(s) % 2:
        raise Refused("odd number of hex digits (%d): a byte string has an "
                      "even count, and padding would invent four bits"
                      % len(s))
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        raise Refused("%r is not hex" % hexstr)
    bits = "".join(format(b, "08b") for b in raw)
    if nbits is not None:
        if nbits > len(bits):
            raise Refused("asked for %d bits but the hex carries %d"
                          % (nbits, len(bits)))
        bits = bits[:nbits]
    return bits


def decode_hex(typename, hexstr, nbits=None):
    if typename not in TYPES:
        raise Refused("%s is not a type in this table (%d types, e.g. %s)"
                      % (typename, len(TYPES), ", ".join(sorted(TYPES)[:3])))
    bits = _bits_of_hex(hexstr, nbits)
    try:
        # exact=False: decode the longest prefix that is a message.  A capture
        # knows its transport block size, hex alone does not, so the trailing
        # bits are reported rather than the whole read being refused.
        value = CODEC.decode_bits(typename, bits, exact=False)
    except lte_per.PerError as exc:
        raise Refused("the bits are not a %s: %s" % (typename, exc))
    used = _bits_consumed(typename, value)
    return value, used, len(bits)


def _bits_consumed(typename, value):
    """How many bits the decoded message occupies.

    The engine returns the value, not the count.  Re-encoding that value with
    the same table gives the field's own length: the round trip is checked
    against pycrate case by case by tools/lte-per-oracle/verify_per.py, so the
    length is the encoder's answer rather than a guess from the value's shape.
    """
    return len(CODEC.encode_bits(typename, value))


def _rows(path, value, out):
    """Flatten a decoded value into (path, text) rows.

    The engine hands back dicts for SEQUENCE/SET, 2-tuples for CHOICE (the
    alternative's name and its value), lists for SEQUENCE OF, bytes for an
    octet string and plain scalars otherwise.  Every shape is written the way
    an operator reads it, and nothing is summarised away.
    """
    if isinstance(value, dict):
        if not value:
            out.append((path, "(empty)"))
            return
        for k, v in value.items():
            _rows("%s.%s" % (path, k) if path else k, v, out)
        return
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and isinstance(value[0], str):
            # A CHOICE: name the alternative, then its contents.
            _rows("%s.%s" % (path, value[0]) if path else value[0],
                  value[1], out)
            return
        for i, v in enumerate(value):
            _rows("%s[%d]" % (path, i), v, out)
        return
    if isinstance(value, bytes):
        out.append((path, "0x%s (%d octets)" % (value.hex().upper(),
                                                len(value))))
        return
    if isinstance(value, bool):
        out.append((path, "true" if value else "false"))
        return
    if value is None:
        out.append((path, "null"))
        return
    out.append((path, str(value)))


def cmd_decode(args):
    value, used, total = decode_hex(args.type, args.hex, args.bits)
    rows = []
    _rows("", value, rows)
    print("type\t%s" % args.type)
    print("family\t%s" % FAMILY)
    print("ref\tTS 38.331, unaligned PER, generated table tools/nr_rrc_layout.py")
    print("bits_read\t%d" % used)
    print("bits_given\t%d" % total)
    if used < total:
        print("bits_left\t%d" % (total - used))
        print("limit\tthe message ended %d bits before the input did; the "
              "trailing bits are counted rather than decoded, because a "
              "decoder that reads past a message invents the difference"
              % (total - used))
    for path, text in rows:
        print("%s\t%s" % (path or "(root)", text))
    return 0


def cmd_encode(args):
    import json as _json
    try:
        text = sys.stdin.read() if args.json == "-" else open(args.json).read()
        value = _json.loads(text)
    except (OSError, ValueError) as exc:
        raise Refused("the value is not JSON: %s" % exc)
    def _dehex(v):
        # JSON cannot spell a byte string, so {"$hex": "AABB"} is the spelling
        # this tree uses, and anything else is left as it came in
        if isinstance(v, dict):
            if set(v) == {"$hex"}:
                try:
                    return bytes.fromhex(v["$hex"])
                except ValueError:
                    raise Refused("$hex wants an even number of hex digits")
            return {k: _dehex(x) for k, x in v.items()}
        if isinstance(v, list):
            return [_dehex(x) for x in v]
        return v

    value = _dehex(value)
    try:
        bits = CODEC.encode_bits(args.type, value)
    except lte_per.PerError as exc:
        raise Refused("the value is not a %s: %s" % (args.type, exc))
    back = CODEC.decode_bits(args.type, bits, exact=False)
    if back != value:
        raise Refused("the encoding does not decode back to the value it was "
                      "built from (a field name the table does not have is "
                      "dropped rather than guessed, so the value must name only "
                      "fields this %s has)" % args.type)
    nib = (len(bits) + 3) // 4
    hexs = "%0*x" % (nib, int(bits.ljust(nib * 4, "0"), 2))
    print("type\t%s" % args.type)
    print("family\t%s" % FAMILY)
    print("bits\t%d" % len(bits))
    print("hex\t%s" % hexs.upper())
    print("read_back\tyes")
    return 0


def cmd_types(args):
    print("family\t%s" % FAMILY)
    for r in ROOTS:
        print("root\t%s" % r)
    print("count\t%d" % len(TYPES))
    if args.match:
        needle = args.match.lower()
        for name in sorted(TYPES):
            if needle in name.lower():
                print("type\t%s" % name)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="nr_rrc.py",
        description="Decode and encode NR RRC (TS 38.331) messages over the "
                    "generated unaligned-PER table. An encoding is accepted only "
                    "when it decodes back to the value it was built from.")
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("decode", help="decode one message from hex")
    d.add_argument("type", help="a type name from this table, e.g. NR.SIB19_r17")
    d.add_argument("hex", help="the message as hex")
    d.add_argument("--bits", type=int, default=None,
                   help="decode only this many leading bits (a capture knows "
                        "the transport block size; hex alone does not)")
    d.set_defaults(func=cmd_decode)

    e = sub.add_parser("encode", help="encode one value (JSON) into a message")
    e.add_argument("type", help="a type name from this table, e.g. SIB19_r17")
    e.add_argument("json", help="the value as a JSON file, or - for stdin")
    e.set_defaults(func=cmd_encode)

    t = sub.add_parser("types", help="list the roots, and any type matching a word")
    t.add_argument("--match", default=None)
    t.set_defaults(func=cmd_types)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    try:
        return args.func(args)
    except Refused as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
