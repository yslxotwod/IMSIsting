#!/usr/bin/env python3
"""Differential check of the HPACK decoder in modules/40_sba_pivot.sh.

The statement of the clauses, written out here as code:

* RFC 7541 2.3 - a header list is encoded with HPACK; entries may be indexed
  (an index into the static or the dynamic table), literal with incremental
  indexing, literal without indexing, literal never indexed, or a dynamic
  table size update.
* RFC 7541 4 - the dynamic table is a FIFO list: a new entry is inserted at
  the front, the oldest is evicted from the back when the size (name length +
  value length + 32 per entry) passes the limit.
* RFC 7541 5.1 - an integer of N-bit prefix: the first octet carries the low
  bits, the prefix value all ones means continuation, and each following
  octet adds seven bits, its high bit saying whether another follows.
* RFC 7541 5.2 - a string literal: bit 8 says Huffman, the remaining seven
  bits are the length as an integer, and the octets follow; Huffman codes are
  Appendix B, padded with the ones of the EOS prefix (at most seven bits).
* RFC 7541 6.1/6.2/6.3 - the four representations and their prefix bits
  (1 + 7, 01 + 6, 001 + 5, 0001 + 4).
* RFC 7541 Appendix A - the 61-entry static table.
* RFC 7540 6.2/6.10 - a HEADERS or CONTINUATION frame carries a header block
  after the pad length octet (flag 0x08) and the five priority octets (flag
  0x20), and the pad bytes are at the end of the frame.

The second implementation is the `hpack` library (hpack 4.2.0): the module's
(name, value) list and its dynamic table size are compared with what that
library decodes from the same block, and with the encoder this file builds
from the clause text. Appendix C's examples are kept as known answers.

Run:  python3 tools/sba-oracle/check_hpack.py [--module PATH] [--negctl]
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

MODULE = "modules/40_sba_pivot.sh"
BASH = os.environ.get("BASH", "bash")

CASES = 0
MISMATCHES = 0
NOTES = 0

# RFC 7541 Appendix A: index|name|value.
STATIC = {}
for _line in """1|:authority|
2|:method|GET
3|:method|POST
4|:path|/
5|:path|/index.html
6|:scheme|http
7|:scheme|https
8|:status|200
9|:status|204
10|:status|206
11|:status|304
12|:status|400
13|:status|404
14|:status|500
15|accept-charset|
16|accept-encoding|gzip, deflate
17|accept-language|
18|accept-ranges|
19|accept|
20|access-control-allow-origin|
21|age|
22|allow|
23|authorization|
24|cache-control|
25|content-disposition|
26|content-encoding|
27|content-language|
28|content-length|
29|content-location|
30|content-range|
31|content-type|
32|cookie|
33|date|
34|etag|
35|expect|
36|expires|
37|from|
38|host|
39|if-match|
40|if-modified-since|
41|if-none-match|
42|if-range|
43|if-unmodified-since|
44|last-modified|
45|link|
46|location|
47|max-forwards|
48|proxy-authenticate|
49|proxy-authorization|
50|range|
51|referer|
52|refresh|
53|retry-after|
54|server|
55|set-cookie|
56|strict-transport-security|
57|transfer-encoding|
58|user-agent|
59|vary|
60|via|
61|www-authenticate|""".splitlines():
    _i, _n, _v = _line.split("|")
    STATIC[int(_i)] = (_n, _v)

# RFC 7541 Appendix B: symbol:code hex:code length in bits.
HUFF = {}
for _line in """0:1ff8:13
1:7fffd8:23
2:fffffe2:28
3:fffffe3:28
4:fffffe4:28
5:fffffe5:28
6:fffffe6:28
7:fffffe7:28
8:fffffe8:28
9:ffffea:24
10:3ffffffc:30
11:fffffe9:28
12:fffffea:28
13:3ffffffd:30
14:fffffeb:28
15:fffffec:28
16:fffffed:28
17:fffffee:28
18:fffffef:28
19:ffffff0:28
20:ffffff1:28
21:ffffff2:28
22:3ffffffe:30
23:ffffff3:28
24:ffffff4:28
25:ffffff5:28
26:ffffff6:28
27:ffffff7:28
28:ffffff8:28
29:ffffff9:28
30:ffffffa:28
31:ffffffb:28
32:0014:6
33:03f8:10
34:03f9:10
35:0ffa:12
36:1ff9:13
37:0015:6
38:00f8:8
39:07fa:11
40:03fa:10
41:03fb:10
42:00f9:8
43:07fb:11
44:00fa:8
45:0016:6
46:0017:6
47:0018:6
48:0000:5
49:0001:5
50:0002:5
51:0019:6
52:001a:6
53:001b:6
54:001c:6
55:001d:6
56:001e:6
57:001f:6
58:005c:7
59:00fb:8
60:7ffc:15
61:0020:6
62:0ffb:12
63:03fc:10
64:1ffa:13
65:0021:6
66:005d:7
67:005e:7
68:005f:7
69:0060:7
70:0061:7
71:0062:7
72:0063:7
73:0064:7
74:0065:7
75:0066:7
76:0067:7
77:0068:7
78:0069:7
79:006a:7
80:006b:7
81:006c:7
82:006d:7
83:006e:7
84:006f:7
85:0070:7
86:0071:7
87:0072:7
88:00fc:8
89:0073:7
90:00fd:8
91:1ffb:13
92:7fff0:19
93:1ffc:13
94:3ffc:14
95:0022:6
96:7ffd:15
97:0003:5
98:0023:6
99:0004:5
100:0024:6
101:0005:5
102:0025:6
103:0026:6
104:0027:6
105:0006:5
106:0074:7
107:0075:7
108:0028:6
109:0029:6
110:002a:6
111:0007:5
112:002b:6
113:0076:7
114:002c:6
115:0008:5
116:0009:5
117:002d:6
118:0077:7
119:0078:7
120:0079:7
121:007a:7
122:007b:7
123:7ffe:15
124:07fc:11
125:3ffd:14
126:1ffd:13
127:ffffffc:28
128:fffe6:20
129:3fffd2:22
130:fffe7:20
131:fffe8:20
132:3fffd3:22
133:3fffd4:22
134:3fffd5:22
135:7fffd9:23
136:3fffd6:22
137:7fffda:23
138:7fffdb:23
139:7fffdc:23
140:7fffdd:23
141:7fffde:23
142:ffffeb:24
143:7fffdf:23
144:ffffec:24
145:ffffed:24
146:3fffd7:22
147:7fffe0:23
148:ffffee:24
149:7fffe1:23
150:7fffe2:23
151:7fffe3:23
152:7fffe4:23
153:1fffdc:21
154:3fffd8:22
155:7fffe5:23
156:3fffd9:22
157:7fffe6:23
158:7fffe7:23
159:ffffef:24
160:3fffda:22
161:1fffdd:21
162:fffe9:20
163:3fffdb:22
164:3fffdc:22
165:7fffe8:23
166:7fffe9:23
167:1fffde:21
168:7fffea:23
169:3fffdd:22
170:3fffde:22
171:fffff0:24
172:1fffdf:21
173:3fffdf:22
174:7fffeb:23
175:7fffec:23
176:1fffe0:21
177:1fffe1:21
178:3fffe0:22
179:1fffe2:21
180:7fffed:23
181:3fffe1:22
182:7fffee:23
183:7fffef:23
184:fffea:20
185:3fffe2:22
186:3fffe3:22
187:3fffe4:22
188:7ffff0:23
189:3fffe5:22
190:3fffe6:22
191:7ffff1:23
192:3ffffe0:26
193:3ffffe1:26
194:fffeb:20
195:7fff1:19
196:3fffe7:22
197:7ffff2:23
198:3fffe8:22
199:1ffffec:25
200:3ffffe2:26
201:3ffffe3:26
202:3ffffe4:26
203:7ffffde:27
204:7ffffdf:27
205:3ffffe5:26
206:fffff1:24
207:1ffffed:25
208:7fff2:19
209:1fffe3:21
210:3ffffe6:26
211:7ffffe0:27
212:7ffffe1:27
213:3ffffe7:26
214:7ffffe2:27
215:fffff2:24
216:1fffe4:21
217:1fffe5:21
218:3ffffe8:26
219:3ffffe9:26
220:ffffffd:28
221:7ffffe3:27
222:7ffffe4:27
223:7ffffe5:27
224:fffec:20
225:fffff3:24
226:fffed:20
227:1fffe6:21
228:3fffe9:22
229:1fffe7:21
230:1fffe8:21
231:7ffff3:23
232:3fffea:22
233:3fffeb:22
234:1ffffee:25
235:1ffffef:25
236:fffff4:24
237:fffff5:24
238:3ffffea:26
239:7ffff4:23
240:3ffffeb:26
241:7ffffe6:27
242:3ffffec:26
243:3ffffed:26
244:7ffffe7:27
245:7ffffe8:27
246:7ffffe9:27
247:7ffffea:27
248:7ffffeb:27
249:ffffffe:28
250:7ffffec:27
251:7ffffed:27
252:7ffffee:27
253:7ffffef:27
254:7fffff0:27
255:3ffffee:26
256:3fffffff:30""".splitlines():
    _s, _h, _l = _line.split(":")
    HUFF[int(_s)] = (int(_h, 16), int(_l))


QUIET = False


def ok(case, want, got):
    global CASES, MISMATCHES
    CASES += 1
    if want != got:
        MISMATCHES += 1
        if not QUIET:
            print("MISMATCH	%s	want=%r	got=%r" % (case, want, got))


def note(text):
    global NOTES
    NOTES += 1
    print("NOTE	%s" % text)


def run(module, *args):
    # A header value is a byte string: decode as latin-1 so that an octet
    # above 0x7F survives the comparison instead of failing utf-8.
    p = subprocess.run([BASH, module, *args], capture_output=True)
    return (p.returncode, p.stdout.decode("latin-1"), p.stderr.decode("latin-1"))


def fields(out):
    # A header value may contain \x0b, \x0c, \x1c-\x1e or \x85, and
    # str.splitlines() treats every one of those as a line break; the module
    # terminates lines with \n only, so split on that.
    d = {}
    for line in out.split("\n"):
        if "	" in line:
            k, v = line.split("	", 1)
            d[k] = v
    return d


def header_list(out, prefix="hpack"):
    d = fields(out)
    try:
        n = int(d.get(prefix + ".count", "0"))
    except ValueError:
        n = 0
    rows = []
    for i in range(n):
        rows.append((d.get("%s.%d.name" % (prefix, i), ""),
                     d.get("%s.%d.value" % (prefix, i), "")))
    return rows


def int_enc(value, prefix_bits):
    """RFC 7541 5.1 integer representation with an N-bit prefix."""
    mx = (1 << prefix_bits) - 1
    if value < mx:
        return bytes([value])
    out = bytearray([mx])
    value -= mx
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def huff_bits(data):
    """The Appendix B code of each octet, concatenated."""
    bits = ""
    for b in data:
        code, ln = HUFF[b]
        bits += format(code, "0%db" % ln)
    return bits


def huff_pad(bits):
    """Pad to an octet boundary with the ones of the EOS prefix (5.2)."""
    rem = len(bits) % 8
    if rem:
        bits += "1" * (8 - rem)
    return int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""


def str_enc(value, huffman=False):
    """RFC 7541 5.2 string literal."""
    raw = value.encode("latin-1")
    if huffman:
        data = huff_pad(huff_bits(raw))
        first = int_enc(len(data), 7)
        first = bytes([first[0] | 0x80]) + first[1:]
        return first + data
    first = int_enc(len(raw), 7)
    return first + raw


def prefixed(prefix, value, bits):
    """A representation byte: the pattern bits, then the integer in the
    remaining bits of the first octet (5.1). The pattern is OR'd into the
    first octet AFTER the integer is encoded, not before - OR-ing first makes
    a value that reaches the prefix maximum look like a continuation."""
    b = int_enc(value, bits)
    return bytes([b[0] | prefix]) + b[1:]


def indexed(index):
    """RFC 7541 6.1 indexed header field."""
    return prefixed(0x80, index, 7)


def literal(name, value, kind="without", name_index=None, huffman=False):
    """RFC 7541 6.2.1-6.2.3 literal header field."""
    prefix = {"with": 0x40, "without": 0x00, "never": 0x10}[kind]
    bits7 = 6 if kind == "with" else 4
    out = bytearray()
    if name_index is None:
        out += prefixed(prefix, 0, bits7)
        out += str_enc(name, huffman)
    else:
        out += prefixed(prefix, name_index, bits7)
    out += str_enc(value, huffman)
    return bytes(out)


def size_update(size):
    """RFC 7541 6.3 dynamic table size update."""
    return prefixed(0x20, size, 5)


def ref_decode(blocks):
    """The second implementation: the hpack library."""
    import hpack
    d = hpack.Decoder()
    rows = []
    for b in blocks:
        rows.extend(d.decode(b))
    table = d.header_table
    return rows, table.maxsize, len(table.dynamic_entries)


# ── the checks ────────────────────────────────────────────────────────────
def check_static(module):
    """Appendix A: every static entry is reachable and carries its value."""
    for idx in sorted(STATIC):
        rc, out, err = run(module, "--hpack", indexed(idx).hex())
        ok("static-index-%d" % idx, [STATIC[idx]], header_list(out))
        ok("static-index-%d-rc" % idx, 0, rc)
    # an entry with an empty value (1, 15, 19...) prints an empty field.
    rc, out, _ = run(module, "--hpack", indexed(1).hex())
    ok("static-empty-value", (":authority", ""), header_list(out)[0] if header_list(out) else None)


def check_literals(module):
    """6.2.1-6.2.3: the three literal forms, raw and Huffman, named by a
    literal and by a static index."""
    cases = [
        ("with-literal-name-raw", literal("x-test", "some-value", "with")),
        ("with-literal-name-huffman", literal("x-test", "some-value", "with", huffman=True)),
        ("without-literal-name-raw", literal("x-test", "some-value", "without")),
        ("never-literal-name-raw", literal("x-test", "some-value", "never")),
        ("with-static-name", literal(None, "POST", "with", name_index=3)),
        ("without-static-name", literal(None, "/api/v1/ue-contexts", "without", name_index=4)),
        ("never-static-name-huffman", literal(None, "Bearer eyJhbGciOiJSUzI1NiJ9", "never",
                                              name_index=23, huffman=True)),
        ("with-empty-name", literal("", "", "with")),
    ]
    for case, blk in cases:
        want, want_max, want_entries = ref_decode([blk])
        rc, out, err = run(module, "--hpack", blk.hex())
        ok(case, want, header_list(out))
        ok(case + "-rc", 0, rc)
        ok(case + "-entries", str(want_entries), fields(out).get("hpack.dynamic_entries"))
        ok(case + "-max", str(want_max), fields(out).get("hpack.max_size"))


def check_huffman_symbols(module):
    """Appendix B: each octet's code decodes back to that octet. NUL, TAB, LF
    and CR cannot survive a line-oriented shell output, so they are skipped
    and said to be skipped."""
    skip = {0, 9, 10, 13}
    for sym in range(256):
        if sym in skip:
            continue
        ch = bytes([sym]).decode("latin-1")
        blk = b"\x00" + str_enc(ch, huffman=True) + b"\x00"
        rc, out, err = run(module, "--hpack", blk.hex())
        row = header_list(out)
        ok("huffman-symbol-%d" % sym, [(ch, "")], row)
    for sym in sorted(skip):
        note("huffman symbol %d (0x%02X) is not compared: a shell line cannot carry it" % (sym, sym))


def check_integers(module):
    """5.1: the encoded integers, including the C.1 examples."""
    # C.1: 1337 with a 5-bit prefix is 3f 9a 0a; as a table size update the
    # module must read 1337 out of it.
    rc, out, _ = run(module, "--hpack", size_update(1337).hex())
    ok("integer-1337-5bit", "1337", fields(out).get("hpack.max_size"))
    ok("integer-c1-bytes", "3f9a0a", size_update(1337).hex())
    # 42 with a 5-bit prefix fits in the prefix itself.
    # the size-update pattern is 001 + a 5-bit integer, so 10 is 2a and 42
    # needs the continuation octet: 3f 0b.
    ok("integer-10-5bit-bytes", "2a", size_update(10).hex())
    ok("integer-42-5bit-bytes", "3f0b", size_update(42).hex())
    rc, out, _ = run(module, "--hpack", size_update(42).hex())
    ok("integer-42-5bit-value", "42", fields(out).get("hpack.max_size"))
    # a string length over 127 uses continuation octets: 200 = 7f 49.
    name = "x" * 200
    blk = literal(name, "v", "without")
    want, _, _ = ref_decode([blk])
    rc, out, _ = run(module, "--hpack", blk.hex())
    ok("integer-length-200", want, header_list(out))



def check_sequence(module):
    """Appendix C.3: three blocks on one connection share the dynamic table,
    and the second indexes the entry the first inserted."""
    blocks = [
        "828684410f7777772e6578616d706c652e636f6d",
        "828684be58086e6f2d6361636865",
        "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    ]
    want, want_max, want_entries = ref_decode([bytes.fromhex(b) for b in blocks])
    rc, out, _ = run(module, "--hpack", *blocks)
    ok("sequence-c3-headers", want, header_list(out))
    ok("sequence-c3-size", "164", fields(out).get("hpack.table_size"))
    ok("sequence-c3-entries", str(want_entries), fields(out).get("hpack.dynamic_entries"))
    # two blocks where the second uses a dynamic index the first created.
    re_blocks = ["828684410f7777772e6578616d706c652e636f6d", "828684be58086e6f2d6361636865"]
    want, _, _ = ref_decode([bytes.fromhex(b) for b in re_blocks])
    rc, out, _ = run(module, "--hpack", *re_blocks)
    ok("sequence-dynamic-reuse", want, header_list(out))


def check_table_eviction(module):
    """4.3/4.4: inserting past the limit evicts the oldest entry, and a size
    update smaller than the table evicts until it fits."""
    # 90 entries of 64 octets: 90 * (64 + 32) = 8640 > 4096, so entries are
    # evicted and the table ends below the limit.
    blocks = []
    for i in range(90):
        blocks.append(literal("k%02d" % i, "v" * 64, "with").hex())
    want, want_max, want_entries = ref_decode([bytes.fromhex(b) for b in blocks])
    rc, out, _ = run(module, "--hpack", *blocks)
    ok("eviction-headers", want, header_list(out))
    ok("eviction-entries", str(want_entries), fields(out).get("hpack.dynamic_entries"))
    ok("eviction-size-below-limit", "yes",
       "yes" if int(fields(out).get("hpack.table_size", "0")) <= want_max else "no")
    # a size update to 0 then a literal with indexing: nothing may be kept.
    rc, out, _ = run(module, "--hpack", size_update(0).hex(), literal("a", "b", "with").hex())
    ok("size-update-0-entries", "0", fields(out).get("hpack.dynamic_entries"))
    ok("size-update-0-max", "0", fields(out).get("hpack.max_size"))


def check_frames(module):
    """RFC 7540 6.2/6.10: the frame wraps the block, and the padding and
    priority fields are stripped before HPACK sees it."""
    block = literal(":method", "GET", "with", name_index=1) + literal(None, "/nudm-uecm/v1/imsi-1", "without", name_index=4)

    def frame(ptype, flags, sid, payload):
        return (len(payload).to_bytes(3, "big") + bytes([ptype, flags])
                + (sid & 0x7FFFFFFF).to_bytes(4, "big") + payload)

    want, _, _ = ref_decode([block])

    # plain HEADERS with END_HEADERS.
    f = frame(1, 0x04, 1, block)
    rc, out, _ = run(module, "--h2-parse", f.hex())
    ok("frame-headers", want, header_list(out, "header"))
    ok("frame-headers-type", "HEADERS", fields(out).get("type_name"))
    # PADDED: the pad length octet counts the trailing padding, not itself.
    for pad in (1, 3, 255):
        f = frame(1, 0x08 | 0x04, 1, bytes([pad]) + block + b"\x00" * pad)
        rc, out, _ = run(module, "--h2-parse", f.hex())
        ok("frame-padded-%d" % pad, want, header_list(out, "header"))
        ok("frame-padded-%d-padlen" % pad, str(pad), fields(out).get("pad_length"))
    # PRIORITY: exclusive + dependency + weight, weight is the octet plus one.
    for excl, dep, weight in ((0, 1, 10), (1, 5, 0), (0, 0x7FFFFFFF, 255)):
        first = ((excl << 31) | (dep & 0x7FFFFFFF)).to_bytes(4, "big")
        f = frame(1, 0x20 | 0x04, 1, first + bytes([weight]) + block)
        rc, out, _ = run(module, "--h2-parse", f.hex())
        ok("frame-priority-%d-%d-%d-headers" % (excl, dep, weight), want, header_list(out, "header"))
        ok("frame-priority-weight", str(weight + 1), fields(out).get("weight"))
        ok("frame-priority-dep", str(dep), fields(out).get("dependency"))
        ok("frame-priority-exclusive", str(excl), fields(out).get("exclusive"))
    # PADDED and PRIORITY together.
    f = frame(1, 0x08 | 0x20 | 0x04, 3, bytes([2]) + b"\x00\x00\x00\x01" + bytes([0]) + block + b"\x00\x00")
    rc, out, _ = run(module, "--h2-parse", f.hex())
    ok("frame-padded-priority", want, header_list(out, "header"))
    # CONTINUATION carries the block too (6.10).
    f = frame(9, 0x04, 1, block)
    rc, out, _ = run(module, "--h2-parse", f.hex())
    ok("frame-continuation", want, header_list(out, "header"))
    # a DATA frame carries no header block.
    f = frame(0, 0x01, 1, b"\xde\xad\xbe\xef")
    rc, out, _ = run(module, "--h2-parse", f.hex())
    ok("frame-data-no-headers", None, fields(out).get("header.count"))
    # a payload shorter than the declared length is reported, not decoded.
    f = frame(1, 0x04, 1, block)[:-1]
    rc, out, _ = run(module, "--h2-parse", f.hex())
    ok("frame-truncated", "true (payload shorter than the declared length)", fields(out).get("truncated"))


def check_errors(module):
    """The refusals: index 0, an index past the table, a string longer than
    the block, bad Huffman padding, the EOS symbol, bad hex."""
    cases = [
        ("index-0", "80", 1, "index 0"),
        ("index-past-table", "be", 1, "past the static table"),
        ("string-past-block", "000f61", 1, "claims"),
        ("huffman-bad-padding", "00811800", 1, "padding is not"),
        ("huffman-eos", "0084ffffffff00", 1, "EOS"),
        ("bad-hex", "zz", 2, "not valid hex"),
    ]
    for case, blk, want_rc, want_text in cases:
        rc, out, err = run(module, "--hpack", blk)
        ok("error-" + case + "-rc", want_rc, rc)
        ok("error-" + case + "-text", True, want_text in (err + out))


def check_h2_build(module):
    """The module's own frame builder produces the 9-octet header the
    clause states, and its parser reads it back."""
    rc, out, _ = run(module, "--h2-build", "1", "4", "1", "8286")
    body = out.strip().splitlines()[-1] if out.strip() else ""
    ok("h2-build-length", "000002", body[:6])
    ok("h2-build-type", "01", body[6:8])
    ok("h2-build-flags", "04", body[8:10])
    ok("h2-build-sid", "00000001", body[10:18])


# ── the mutants ───────────────────────────────────────────────────────────
MUTANTS = [
    ("huffman-bits-read-from-the-msb",
     '        for (( k = len - 1; k >= 0; k-- )); do\n'
     '            if (( (v >> k) & 1 )); then bits+="1"; else bits+="0"; fi\n'
     '        done',
     '        for (( k = 0; k < len; k++ )); do\n'
     '            if (( (v >> k) & 1 )); then bits+="0"; else bits+="1"; fi\n'
     '        done'),
    ("static-table-index-61-unreachable",
     "    if (( idx <= 61 )); then",
     "    if (( idx < 61 )); then"),
    ("dynamic-entry-inserted-at-the-tail",
     '            SBAP_HPACK_NAME=("$name" "${SBAP_HPACK_NAME[@]}")\n'
     '            SBAP_HPACK_VALUE=("$value" "${SBAP_HPACK_VALUE[@]}")',
     '            SBAP_HPACK_NAME+=("$name")\n'
     '            SBAP_HPACK_VALUE+=("$value")'),
    ("huffman-string-read-as-identity",
     '        if (( huff == 1 )); then\n'
     '            value=$(sbap_hpack_huff_decode "$hexv") || return 1',
     '        if (( 0 )); then\n'
     '            value=$(sbap_hpack_huff_decode "$hexv") || return 1'),
    ("frame-padding-left-in-the-block",
     '            body="${body:0:${#body}-pad*2}"',
     '            body="${body}"'),
    ("never-indexed-entry-inserted",
     '        if [[ "$repr" == with-indexing ]]; then',
     '        if [[ "$repr" == with-indexing || "$repr" == never-indexed ]]; then'),
]


def suite(module, quick=False):
    global CASES, MISMATCHES
    CASES = 0
    MISMATCHES = 0
    check_static(module)
    check_literals(module)
    if not quick:
        check_huffman_symbols(module)
    check_integers(module)
    check_sequence(module)
    check_table_eviction(module)
    check_frames(module)
    check_errors(module)
    check_h2_build(module)
    return CASES, MISMATCHES


def negctl(module):
    global QUIET
    caught = 0
    tmp = tempfile.mkdtemp(prefix="hpack-negctl.")
    try:
        base = open(module).read()
        for name, old, new in MUTANTS:
            if old not in base:
                print("NEGCTL\t%s\tMISSED (anchor not in %s)" % (name, module))
                continue
            path = os.path.join(tmp, "mutant.sh")
            with open(path, "w") as fh:
                fh.write(base.replace(old, new, 1))
            QUIET = True
            try:
                cases, mism = suite(path, quick=True)
            finally:
                QUIET = False
            if mism > 0:
                caught += 1
                print("NEGCTL\t%s\tCAUGHT (%d of %d cases)" % (name, mism, cases))
            else:
                print("NEGCTL\t%s\tMISSED (%d cases agreed)" % (name, cases))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("NEGCTL-CAUGHT\t%d of %d" % (caught, len(MUTANTS)))
    return 0 if caught == len(MUTANTS) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--module", default=MODULE)
    ap.add_argument("--negctl", action="store_true")
    args = ap.parse_args()
    try:
        import hpack  # noqa: F401
    except ImportError:
        print("SKIP\tpython hpack is not installed; pip install hpack", file=sys.stderr)
        return 2
    cases, mism = suite(args.module)
    print("CASES\t%d" % cases)
    print("MISMATCHES\t%d" % mism)
    print("RESULT\t%s" % ("PASS" if mism == 0 else "FAIL(%d)" % mism))
    rc = 0 if mism == 0 else 1
    if args.negctl:
        rc = max(rc, negctl(args.module))
    return rc


if __name__ == "__main__":
    sys.exit(main())
