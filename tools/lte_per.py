#!/usr/bin/env python3
"""Generic unaligned-PER (ITU-T X.691) codec driven by a declarative layout table.

This module is the *runtime* half of the table-driven LTE RRC codec.  It has no
imports beyond the standard library and knows nothing about ASN.1, pycrate, or
LTE: it interprets a plain-data layout table produced by ``tools/asn1gen.py``.

Values
------
A value is plain Python, in exactly the shape pycrate uses, so that the two can
be compared directly:

============================  ===================================
layout node ``k``             Python value
============================  ===================================
``seq``                       ``dict`` ``{component_name: value}``; a component
                              that is absent is simply not a key
``choice``                    ``(alternative_name, value)`` 2-tuple
``seqof``                     ``list`` of element values
``enum``                      ``str``: the enumeration item name
``int``                       ``int``
``bool``                      ``bool``
``null``                      ``0`` (pycrate uses the single value 0; ``None``
                              is also accepted when encoding)
``bits``                      ``(raw_int, bit_length)`` 2-tuple, MSB first
``octets``                    ``bytes``
============================  ===================================

Table schema
------------
A table is ``{type_name: node}``.  Every node is a dict with a ``"k"`` key:

``{"k": "ref", "t": <type name>}``
    Named-type reference.  Lets the table be recursive and keeps one entry per
    named ASN.1 type instead of infinitely inlining.

``{"k": "bool"}`` / ``{"k": "null"}``
    No payload.

``{"k": "int", "lb": L, "ub": U, "ext": bool}``
    Value range.  Encoded as ``ceil(log2(U-L+1))`` bits of ``value - L``.
    ``"ub": null`` means semi-constrained (``lb`` only) and ``"lb": null``
    unconstrained; both are emitted as an unconstrained-integer length
    determinant plus big-endian octets.  ``"ext": true`` spends a leading
    extension bit and falls back to the unconstrained form outside ``[L, U]``.

``{"k": "enum", "names": [...], "ext": [...] or null}``
    Constrained index over ``names``.  ``ext`` non-null marks the type
    extensible; an extension item is carried as a normally-small index.

``{"k": "bits", "size": [L, U] or null, "ext": bool}``
    ``size`` of ``[N, N]`` is a fixed size (no length determinant).  ``null``
    size is an unconstrained bit string (length determinant in *bits*).

``{"k": "octets", "size": [L, U] or null, "ext": bool, "containing": name}``
    Same, but the length determinant of an unconstrained string counts octets.
    ``containing`` is documentation only (it records an ASN.1 ``CONTAINING``
    clause); the content is treated as raw octets.

``{"k": "seq", "ext": bool, "comp": [[name, node, optional, default], ...],
  "extadd": [node, ...]}``
    ``comp`` is the root part in declaration order.  ``optional`` marks an
    OPTIONAL component and ``default`` (or ``None``) a DEFAULT value; both kinds
    take a bit in the preamble, in declaration order, followed by the present
    components in the same order.  ``extadd`` holds the extension additions in
    wire order, each entry being one OPEN TYPE, in one of two shapes:

    ``{"k": "extgrp", "names": [...], "node": <seq node>}``
        Several additions wrapped by the ASN.1 syntax into one group.  ``node``
        is the group's ``seq`` node whose components are exactly ``names``; the
        group is present when any of ``names`` is present, and the OPEN TYPE
        carries the group's own preamble.
    ``{"k": "extone", "name": str, "node": <node>}``
        A lone addition encoded directly as the component's own type, with no
        extra preamble.

    ``extadd`` is ``[]`` (not ``None``) for an extensible type with no
    additions -- it still spends the extension bit, which is the ``_ext == []``
    trap this schema makes explicit.

``{"k": "choice", "ext": bool, "alts": [[name, node], ...],
  "extadd": [[name, node], ...]}``
    Root alternatives are a constrained index over ``alts``; an extension
    alternative is a normally-small index plus an OPEN TYPE.

``{"k": "seqof", "size": [L, U] or null, "ext": bool, "of": node}``
    Constrained element count (``count - L``) then that many elements.

``{"k": "unsupported", "why": str}``
    The generator could not express the construct.  Encoding or decoding it
    raises :class:`PerError` naming the reason.  It is never guessed at.

DEFAULT handling follows X.691 canonical PER (which is what pycrate emits by
default): a component whose value equals its DEFAULT is treated as absent.
Pass ``canonical=False`` to encode it explicitly instead.
"""

__all__ = [
    "PerError",
    "BitWriter",
    "BitReader",
    "Codec",
    "codec_from_module",
]

# Fragmentation of strings/counts at 16384 units (X.691 10.9 / 11.9) is not
# implemented; every place it could arise checks and refuses.


class PerError(ValueError):
    """Raised when a value or table cannot be encoded/decoded.

    Never raised for a construct the engine understands; always for one it does
    not, so that a plausible-looking wrong answer is impossible.
    """


# ---------------------------------------------------------------------------
# Bit-level primitives.  MSB first, no alignment, ever.
# ---------------------------------------------------------------------------


class BitWriter(object):
    """Accumulates bits MSB-first into a list of 0/1 ints."""

    __slots__ = ("bits",)

    def __init__(self):
        self.bits = []

    def put(self, value, nbits):
        """Append the low ``nbits`` bits of ``value``, most significant first."""
        if nbits < 0:
            raise PerError("negative bit count %d" % nbits)
        if nbits == 0:
            return
        if value < 0:
            value += 1 << nbits
        if value < 0 or value >> nbits:
            raise PerError("value %r does not fit in %d bits" % (value, nbits))
        bits = self.bits
        for i in range(nbits - 1, -1, -1):
            bits.append((value >> i) & 1)

    def bit(self, value):
        self.bits.append(1 if value else 0)

    def octets(self, data):
        for byte in bytearray(data):
            self.put(byte, 8)

    def nbits(self):
        return len(self.bits)

    def to_bits(self):
        return "".join("1" if b else "0" for b in self.bits)

    def to_bytes(self):
        """Octet-aligned big-endian bytes, final octet zero-padded."""
        bits = self.bits
        out = bytearray((len(bits) + 7) // 8)
        for i, b in enumerate(bits):
            if b:
                out[i >> 3] |= 1 << (7 - (i & 7))
        return bytes(out)

    def to_hex(self):
        return self.to_bytes().hex().upper()


class BitReader(object):
    """Reads bits MSB-first from a bit string or from bytes."""

    __slots__ = ("bits", "pos")

    def __init__(self, data):
        if isinstance(data, (bytes, bytearray, memoryview)):
            b = bytearray(data)
            self.bits = "".join(format(x, "08b") for x in b)
        elif isinstance(data, str):
            for ch in data:
                if ch not in "01":
                    raise PerError("bit string contains %r" % ch)
            self.bits = data
        else:
            raise PerError("cannot read bits from %r" % (type(data).__name__,))
        self.pos = 0

    def remaining(self):
        return len(self.bits) - self.pos

    def require(self, nbits):
        if self.pos + nbits > len(self.bits):
            raise PerError(
                "truncated: want %d bits at offset %d, only %d left"
                % (nbits, self.pos, len(self.bits) - self.pos)
            )

    def get(self, nbits):
        if nbits == 0:
            return 0
        self.require(nbits)
        chunk = self.bits[self.pos:self.pos + nbits]
        self.pos += nbits
        return int(chunk, 2)

    def bit(self):
        return self.get(1) == 1

    def octets(self, count):
        return self.get(8 * count).to_bytes(count, "big") if count else b""


# ---------------------------------------------------------------------------
# Helpers shared by both directions.
# ---------------------------------------------------------------------------


def _ceil_log2(n):
    """Number of bits needed to encode one of ``n`` equally likely values."""
    if n <= 1:
        return 0
    return (n - 1).bit_length()


def _uint_bytelen(value):
    """Minimal number of octets able to hold a non-negative integer."""
    if value < 0:
        raise PerError("unconstrained integer must be non-negative, got %d" % value)
    if value == 0:
        return 1
    return (value.bit_length() + 7) // 8


def _extadd_names(entry):
    """The component names an extension-addition entry carries."""
    if entry["k"] == "extgrp":
        return entry["names"]
    return (entry["name"],)


class Codec(object):
    """Encodes and decodes values against a layout table."""

    def __init__(self, types, canonical=True):
        if not isinstance(types, dict):
            raise PerError("layout table must be a dict of {type name: node}")
        self.types = types
        self.canonical = canonical

    # -- public API --------------------------------------------------------

    def node(self, typename):
        try:
            return self.types[typename]
        except KeyError:
            raise PerError("unknown type %r in layout table" % (typename,))

    def encode_bits(self, typename, value, canonical=None):
        """Encode to a bit string of the TRUE (unpadded) length."""
        w = BitWriter()
        self._enc(w, self.node(typename), value, typename)
        return w.to_bits()

    def encode_hex(self, typename, value, canonical=None):
        """Encode to octet-padded uppercase hex (X.691 10.9 style padding)."""
        w = BitWriter()
        self._enc(w, self.node(typename), value, typename)
        return w.to_hex()

    def encode_bitlen(self, typename, value):
        w = BitWriter()
        self._enc(w, self.node(typename), value, typename)
        return w.nbits()

    def decode_bits(self, typename, bits, exact=True):
        """Decode a bit string.

        ``exact`` requires every bit to be consumed; this is what catches a
        layout that is one bit too short for the message it claims to read.
        """
        r = BitReader(bits)
        value = self._dec(r, self.node(typename), typename)
        if exact and r.remaining():
            raise PerError(
                "%s: %d bit(s) left over after decoding"
                % (typename, r.remaining())
            )
        return value

    def decode_hex(self, typename, hexstr, exact=True):
        return self.decode_bits(typename, bytes.fromhex(hexstr), exact=exact)

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def _enc(self, w, node, value, path):
        kind = node["k"]
        handler = _ENCODERS.get(kind)
        if handler is None:
            raise PerError("%s: unknown layout node kind %r" % (path, kind))
        handler(self, w, node, value, path)

    def _unsupported(self, node, path):
        raise PerError(
            "%s: unsupported construct: %s" % (path, node.get("why", "?"))
        )

    def _enc_choice(self, w, node, value, path):
        if not (isinstance(value, tuple) and len(value) == 2):
            raise PerError(
                "%s: CHOICE needs a (name, value) tuple, got %r" % (path, value)
            )
        name, payload = value
        alts = node["alts"]
        root_names = [n for n, _ in alts]
        if node["ext"]:
            if name in root_names:
                w.bit(0)
                index = root_names.index(name)
            else:
                w.bit(1)
                ext_names = [n for n, _ in node["extadd"]]
                if name not in ext_names:
                    raise PerError(
                        "%s: %r is not an alternative (have %r)"
                        % (path, name, root_names + ext_names)
                    )
                self._enc_norm_small(w, ext_names.index(name))
                self._enc_open(w, node["extadd"][ext_names.index(name)][1],
                               payload, "%s.%s" % (path, name))
                return
        else:
            if name not in root_names:
                raise PerError("%s: %r is not an alternative" % (path, name))
            index = root_names.index(name)
        if len(alts) > 1:
            w.put(index, _ceil_log2(len(alts)))
        self._enc(w, alts[index][1], payload, "%s.%s" % (path, name))

    def _enc_seq(self, w, node, value, path):
        if not isinstance(value, dict):
            raise PerError("%s: SEQUENCE needs a dict, got %r" % (path, value))
        comp = node["comp"]
        groups = node["extadd"]
        present_groups = []
        if node["ext"]:
            for gi, grp in enumerate(groups):
                if any(nm in value for nm in _extadd_names(grp)):
                    present_groups.append(gi)
            w.bit(1 if present_groups else 0)
        for nm, _nd, opt, dflt in comp:
            if opt or dflt is not None:
                w.bit(1 if self._present(value, nm, dflt) else 0)
        for nm, nd, opt, dflt in comp:
            if self._present(value, nm, dflt):
                self._enc(w, nd, value[nm], "%s.%s" % (path, nm))
            elif not opt and dflt is None:
                raise PerError("%s: mandatory component %r is absent" % (path, nm))
        if present_groups:
            ldet = max(present_groups) + 1
            if len(groups) > ldet:
                ldet = len(groups)
            self._enc_ext_bitmap_head(w, ldet)
            bitmap = 0
            for gi in present_groups:
                bitmap |= 1 << (ldet - (gi + 1))
            w.put(bitmap, ldet)
            for gi in present_groups:
                self._enc_extadd(
                    w, groups[gi], value, "%s.<ext %d>" % (path, gi)
                )

    def _present(self, value, name, default):
        if name not in value:
            return False
        if default is not None and self.canonical and value[name] == default:
            return False
        return True

    def _enc_int(self, w, node, value, path):
        if isinstance(value, str):
            raise PerError("%s: INTEGER needs an int, got %r" % (path, value))
        lb, ub = node["lb"], node["ub"]
        if node["ext"]:
            if ub is None or lb is None or not (lb <= value <= ub):
                w.bit(1)
                self._enc_intunconst(w, value, None, path)
                return
            w.bit(0)
        if ub is None:
            self._enc_intunconst(w, value, lb, path)
            return
        span = ub - lb + 1
        if span > 1:
            w.put(value - lb, _ceil_log2(span))

    def _enc_intunconst(self, w, value, offset, path):
        if offset is not None:
            value = value - offset
        if value < 0:
            raise PerError(
                "%s: negative unconstrained integer %d is not supported"
                % (path, value)
            )
        ldet = _uint_bytelen(value)
        if ldet >= 16384:
            raise PerError("%s: fragmentation (X.691 11.9) is not implemented" % path)
        self._enc_count(w, ldet, path)
        w.put(value, 8 * ldet)

    def _enc_enum(self, w, node, value, path):
        names = node["names"]
        if not isinstance(value, str):
            raise PerError("%s: ENUMERATED needs a name, got %r" % (path, value))
        if node["ext"] is not None:
            if value in names:
                w.bit(0)
                index = names.index(value)
            else:
                ext = node["ext"]
                if value not in ext:
                    raise PerError(
                        "%s: %r is not an enumeration item (have %r)"
                        % (path, value, names + list(ext))
                    )
                w.bit(1)
                self._enc_norm_small(w, ext.index(value))
                return
        else:
            if value not in names:
                raise PerError(
                    "%s: %r is not an enumeration item (have %r)"
                    % (path, value, names)
                )
            index = names.index(value)
        if len(names) > 1:
            w.put(index, _ceil_log2(len(names)))

    def _enc_bits(self, w, node, value, path):
        if not (isinstance(value, tuple) and len(value) == 2):
            raise PerError(
                "%s: BIT STRING needs an (int, bitlen) tuple, got %r" % (path, value)
            )
        raw, blen = value
        if node["ext"]:
            w.bit(0)
        size = node["size"]
        if size is None:
            if blen >= 16384:
                raise PerError(
                    "%s: fragmentation (X.691 11.9) is not implemented" % path
                )
            self._enc_count(w, blen, path)
        elif size[0] != size[1]:
            w.put(blen - size[0], _ceil_log2(size[1] - size[0] + 1))
        w.put(raw, blen)

    def _enc_octets(self, w, node, value, path):
        if isinstance(value, (bytes, bytearray, memoryview)):
            data = bytes(value)
        else:
            raise PerError("%s: OCTET STRING needs bytes, got %r" % (path, value))
        if node["ext"]:
            w.bit(0)
        size = node["size"]
        if size is None:
            if len(data) >= 16384:
                raise PerError(
                    "%s: fragmentation (X.691 11.9) is not implemented" % path
                )
            self._enc_count(w, len(data), path)
        elif size[0] != size[1]:
            w.put(len(data) - size[0], _ceil_log2(size[1] - size[0] + 1))
        w.octets(data)

    def _enc_seqof(self, w, node, value, path):
        if not isinstance(value, (list, tuple)):
            raise PerError("%s: SEQUENCE OF needs a list, got %r" % (path, value))
        count = len(value)
        size = node["size"]
        if size is None:
            self._enc_count(w, count, path)
        elif size[0] != size[1]:
            w.put(count - size[0], _ceil_log2(size[1] - size[0] + 1))
        for i, item in enumerate(value):
            self._enc(w, node["of"], item, "%s[%d]" % (path, i))

    # -- X.691 primitives --------------------------------------------------

    def _enc_count(self, w, count, path):
        """Length determinant: one octet below 128, else two (X.691 10.9)."""
        if 0 <= count <= 127:
            w.put(count, 8)
        elif 128 <= count <= 16383:
            w.put(0x8000 | count, 16)
        else:
            raise PerError("%s: count %d out of range" % (path, count))

    def _enc_norm_small(self, w, index, path="<normally-small>"):
        """Normally small non-negative whole number (7-bit form, or UINT)."""
        if index < 64:
            w.put(index, 7)
        else:
            w.bit(1)
            self._enc_intunconst(w, index, None, path)

    def _enc_ext_bitmap_head(self, w, ldet, path="<extension bitmap>"):
        if ldet > 64:
            w.bit(1)
            self._enc_intunconst(w, ldet - 1, None, path)
        else:
            w.put(ldet - 1, 7)

    def _enc_open(self, w, node, value, path):
        """OPEN TYPE: length determinant then octet-padded content."""
        sub = BitWriter()
        self._enc(sub, node, value, path)
        data = sub.to_bytes()
        if len(data) >= 16384:
            raise PerError("%s: fragmentation (X.691 11.9) is not implemented" % path)
        self._enc_count(w, len(data), path)
        w.octets(data)

    def _enc_extadd(self, w, entry, value, path):
        """Encode one extension-addition OPEN TYPE against the parent dict."""
        if entry["k"] == "extgrp":
            sub = {}
            for nm in entry["names"]:
                if nm in value:
                    sub[nm] = value[nm]
            self._enc_open(w, entry["node"], sub, path)
        else:
            nm = entry["name"]
            if nm not in value:
                raise PerError("%s: extension addition %r is absent" % (path, nm))
            self._enc_open(w, entry["node"], value[nm], "%s.%s" % (path, nm))

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------

    def _dec(self, r, node, path):
        kind = node["k"]
        handler = _DECODERS.get(kind)
        if handler is None:
            raise PerError("%s: unknown layout node kind %r" % (path, kind))
        return handler(self, r, node, path)

    def _dec_choice(self, r, node, path):
        alts = node["alts"]
        if node["ext"] and r.bit():
            index = self._dec_norm_small(r, path)
            ext = node["extadd"]
            if index >= len(ext):
                raise PerError("%s: unknown extension alternative %d" % (path, index))
            name, nd = ext[index]
            return (name, self._dec_open(r, nd, "%s.%s" % (path, name)))
        index = r.get(_ceil_log2(len(alts))) if len(alts) > 1 else 0
        if index >= len(alts):
            raise PerError("%s: alternative index %d out of range" % (path, index))
        name, nd = alts[index]
        return (name, self._dec(r, nd, "%s.%s" % (path, name)))

    def _dec_seq(self, r, node, path):
        comp = node["comp"]
        out = {}
        extended = node["ext"] and r.bit()
        flags = {}
        for nm, _nd, opt, dflt in comp:
            if opt or dflt is not None:
                flags[nm] = r.bit()
        for nm, nd, opt, dflt in comp:
            if opt or dflt is not None:
                if flags[nm]:
                    out[nm] = self._dec(r, nd, "%s.%s" % (path, nm))
                elif dflt is not None and not self.canonical:
                    out[nm] = dflt
            else:
                out[nm] = self._dec(r, nd, "%s.%s" % (path, nm))
        if extended:
            groups = node["extadd"]
            ldet = self._dec_ext_bitmap_head(r, path)
            bitmap = r.get(ldet)
            for gi in range(ldet):
                if bitmap & (1 << (ldet - (gi + 1))):
                    if gi >= len(groups):
                        raise PerError(
                            "%s: extension group %d is unknown" % (path, gi)
                        )
                    entry = groups[gi]
                    gpath = "%s.<ext %d>" % (path, gi)
                    if entry["k"] == "extgrp":
                        out.update(self._dec_open(r, entry["node"], gpath))
                    else:
                        out[entry["name"]] = self._dec_open(
                            r, entry["node"], "%s.%s" % (gpath, entry["name"])
                        )
        return out

    def _dec_int(self, r, node, path):
        lb, ub = node["lb"], node["ub"]
        if node["ext"] and r.bit():
            return self._dec_intunconst(r, None, path)
        if ub is None:
            return self._dec_intunconst(r, lb, path)
        span = ub - lb + 1
        if span <= 1:
            return lb
        return lb + r.get(_ceil_log2(span))

    def _dec_intunconst(self, r, offset, path):
        ldet = self._dec_count(r, path)
        if ldet == 0:
            raise PerError("%s: zero-length unconstrained integer" % path)
        value = r.get(8 * ldet)
        return value if offset is None else value + offset

    def _dec_enum(self, r, node, path):
        names = node["names"]
        if node["ext"] is not None and r.bit():
            index = self._dec_norm_small(r, path)
            ext = node["ext"]
            if index >= len(ext):
                raise PerError("%s: unknown enumeration extension %d" % (path, index))
            return ext[index]
        index = r.get(_ceil_log2(len(names))) if len(names) > 1 else 0
        if index >= len(names):
            raise PerError("%s: enumeration index %d out of range" % (path, index))
        return names[index]

    def _dec_bits(self, r, node, path):
        if node["ext"]:
            r.bit()
        size = node["size"]
        if size is None:
            blen = self._dec_count(r, path)
        elif size[0] != size[1]:
            blen = size[0] + r.get(_ceil_log2(size[1] - size[0] + 1))
        else:
            blen = size[0]
        return (r.get(blen), blen)

    def _dec_octets(self, r, node, path):
        if node["ext"]:
            r.bit()
        size = node["size"]
        if size is None:
            count = self._dec_count(r, path)
        elif size[0] != size[1]:
            count = size[0] + r.get(_ceil_log2(size[1] - size[0] + 1))
        else:
            count = size[0]
        return r.octets(count)

    def _dec_seqof(self, r, node, path):
        size = node["size"]
        if size is None:
            count = self._dec_count(r, path)
        elif size[0] != size[1]:
            count = size[0] + r.get(_ceil_log2(size[1] - size[0] + 1))
        else:
            count = size[0]
        return [self._dec(r, node["of"], "%s[%d]" % (path, i)) for i in range(count)]

    def _dec_count(self, r, path):
        first = r.get(8)
        if first < 128:
            return first
        if first & 0xC0 != 0x80:
            raise PerError("%s: fragmented length determinant is not implemented" % path)
        return ((first & 0x3F) << 8) | r.get(8)

    def _dec_norm_small(self, r, path):
        head = r.get(7)
        if head < 64:
            return head
        if head != 64:
            raise PerError("%s: invalid normally-small head %d" % (path, head))
        return self._dec_intunconst(r, None, path)

    def _dec_ext_bitmap_head(self, r, path):
        head = r.get(7)
        if head < 64:
            return head + 1
        if head != 64:
            raise PerError("%s: invalid extension bitmap head %d" % (path, head))
        return self._dec_intunconst(r, None, path) + 1

    def _dec_open(self, r, node, path):
        count = self._dec_count(r, path)
        bits = r.get(8 * count)
        sub = BitReader(format(bits, "0%db" % (8 * count)))
        value = self._dec(sub, node, path)
        # The open type is octet-padded; trailing zero bits are not significant.
        if sub.remaining() and sub.bits[sub.pos:].strip("0"):
            raise PerError(
                "%s: %d non-padding bit(s) left in open type"
                % (path, sub.remaining())
            )
        return value


def _enc_bool(codec, w, node, value, path):
    if not isinstance(value, bool):
        raise PerError("%s: BOOLEAN needs a bool, got %r" % (path, value))
    w.bit(1 if value else 0)


def _enc_null(codec, w, node, value, path):
    # NULL has a single value and carries no bits.  pycrate spells it 0;
    # None is accepted too so a caller need not care.
    if value not in (0, None):
        raise PerError("%s: NULL needs 0, got %r" % (path, value))


def _dec_bool(codec, r, node, path):
    return r.bit()


def _dec_null(codec, r, node, path):
    return 0


def _enc_ref(codec, w, node, value, path):
    codec._enc(w, codec.node(node["t"]), value, path)


def _dec_ref(codec, r, node, path):
    return codec._dec(r, codec.node(node["t"]), path)


def _enc_unsupported(codec, w, node, value, path):
    codec._unsupported(node, path)


def _dec_unsupported(codec, r, node, path):
    codec._unsupported(node, path)


_ENCODERS = {
    "ref": _enc_ref,
    "bool": _enc_bool,
    "null": _enc_null,
    "int": Codec._enc_int,
    "enum": Codec._enc_enum,
    "bits": Codec._enc_bits,
    "octets": Codec._enc_octets,
    "seq": Codec._enc_seq,
    "choice": Codec._enc_choice,
    "seqof": Codec._enc_seqof,
    "unsupported": _enc_unsupported,
}

_DECODERS = {
    "ref": _dec_ref,
    "bool": _dec_bool,
    "null": _dec_null,
    "int": Codec._dec_int,
    "enum": Codec._dec_enum,
    "bits": Codec._dec_bits,
    "octets": Codec._dec_octets,
    "seq": Codec._dec_seq,
    "choice": Codec._dec_choice,
    "seqof": Codec._dec_seqof,
    "unsupported": _dec_unsupported,
}


def codec_from_module(module, canonical=True):
    """Build a :class:`Codec` from a generated table module (one with TYPES)."""
    try:
        types = module.TYPES
    except AttributeError:
        raise PerError("module %r has no TYPES table" % (module,))
    return Codec(types, canonical=canonical)
