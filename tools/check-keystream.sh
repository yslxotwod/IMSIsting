#!/usr/bin/env bash
# check-keystream.sh — referee the keystream-reuse detector against tshark.
#
# The detector makes two claims: which datagrams form a stream, and whether two
# streams drew the same keystream. tshark can referee the first — SSRC, packet
# count, sequence order, one stream per direction. It has no opinion on the
# second, so that half is compared against captures whose ground truth is
# written here by construction (the same pad on two calls, a different pad, and
# one call's two legs sharing a pad on purpose).
#
# The fixtures are NOT imported from the module: a defect in the module's own
# fixture could otherwise hide itself.
#
# Exits 0 only when every assertion passes.
set -u

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MOD="$ROOT/modules/30_volte_ims.sh"
TSHARK="${TSHARK_BIN:-$(command -v tshark || echo /usr/bin/tshark)}"
PYP="${KEYSTREAM_ORACLE_PY:-$(command -v python3 || echo python3)}"

[[ -x "$MOD" ]] || { printf 'ERROR\tmissing %s\n' "$MOD" >&2; exit 2; }
[[ -x "$TSHARK" ]] || { printf 'ERROR\tmissing tshark; this referee is %s\n' "$TSHARK" >&2; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-keystream.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

"$PYP" - "$tmp" << 'PYFIX'
import os, struct, sys

out = sys.argv[1]
ETH = bytes.fromhex("0200000000010200000000020800")
FRAME = 160
PAD_A = bytes((i * 7 + 3) & 0xff for i in range(FRAME * 20))
PAD_B = bytes((i * 11 + 5) & 0xff for i in range(FRAME * 20))
# codec-ish plaintext: long silent runs with a short voiced phrase
PLAIN_A = bytes([0x00] * 80 + [0x04, 0x0c] * 8 + [0x00] * 64)
PLAIN_B = bytes([0x00] * 96 + [0x04, 0x0c] * 4 + [0x00] * 64)


def frame(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64,
                     17, 0, bytes(src), bytes(dst))
    return ETH + ip + udp


def rtp(ssrc, seq, body, pt=96):
    return struct.pack(">BBHII", 0x80, pt, seq & 0xffff, 160 * seq, ssrc) + body


def xorb(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def call(pad, plain, ssrc, sport, dport, src, dst, t0, n=12):
    frames = []
    for k in range(n):
        body = xorb(plain, pad[k * FRAME:(k + 1) * FRAME])
        frames.append((t0 + 0.02 * k,
                       frame(src, dst, sport, dport, rtp(ssrc, 1000 + k, body))))
    return frames


def w(path, frames):
    frames.sort(key=lambda t: t[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt in frames:
            s = int(ts)
            us = int(round((ts - s) * 1000000))
            f.write(struct.pack("<IIII", s, us, len(pkt), len(pkt)))
            f.write(pkt)


A = (10, 0, 0, 1)
B = (10, 0, 0, 2)
# two calls, the same pad: reuse by construction
w(os.path.join(out, "reuse.pcap"),
  call(PAD_A, PLAIN_A, 0x11111111, 5004, 5005, A, B, 0.0) +
  call(PAD_A, PLAIN_B, 0x22222222, 5006, 5007, A, B, 0.01))
# two calls, different pads: no reuse
w(os.path.join(out, "noreuse.pcap"),
  call(PAD_A, PLAIN_A, 0x11111111, 5004, 5005, A, B, 0.0) +
  call(PAD_B, PLAIN_B, 0x22222222, 5006, 5007, A, B, 0.01))
# one call's two legs, fed the same pad on purpose: two keys, not two calls
w(os.path.join(out, "legs.pcap"),
  call(PAD_A, PLAIN_A, 0x11111111, 5004, 5005, A, B, 0.0) +
  call(PAD_A, PLAIN_B, 0x22222222, 5005, 5004, B, A, 0.01))
print("fixtures\t3")
PYFIX

"$PYP" - "$tmp" "$MOD" "$TSHARK" << 'PYCOMPARE'
import re, subprocess, sys

tmp, mod, tshark = sys.argv[1], sys.argv[2], sys.argv[3]
fails = []
checks = 0


def chk(name, got, want):
    global checks
    checks += 1
    if got != want:
        fails.append(name)
        print("ASSERTION\t%s\tFAIL want=%r got=%r" % (name, want, got))
    else:
        print("ASSERTION\t%s\tPASS" % name)


def rows(text):
    out = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            out.setdefault(parts[0], []).append(parts[1])
    return out


def one(text, key):
    v = rows(text).get(key)
    return v[0] if v else ""


def detect(path, extra=()):
    r = subprocess.run(["bash", mod, "--detect-keystream-reuse", path] + list(extra),
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def tshark_rtp(path, ports):
    args = [tshark, "-r", path, "-T", "fields", "-e", "rtp.ssrc", "-e", "rtp.seq"]
    for p in ports:
        args += ["-d", "udp.port==%d,rtp" % p]
    r = subprocess.run(args, capture_output=True, text=True)
    seen = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            seen.setdefault(parts[0], []).append(int(parts[1]))
    return seen


# ── 1. stream identity and framing, against tshark ─────────────────────
rc, text = detect(tmp + "/reuse.pcap")
chk("detect-rc", rc, 0)
chk("verdict-reuse", one(text, "status"), "keystream_reuse")
mine = {}
for key, val in rows(text).items():
    m = re.match(r"^stream\.(\d+)$", key)
    if not m:
        continue
    ssrc = re.search(r"ssrc 0x([0-9a-f]{8})", val[0])
    frames = re.search(r"frames (\d+)$", val[0])
    mine[ssrc.group(1) if ssrc else "bare"] = (int(frames.group(1)), val[0])
chk("stream-count", one(text, "ciphertext_streams"), "2")
chk("ssrc-set", sorted(mine), ["11111111", "22222222"])

tseen = tshark_rtp(tmp + "/reuse.pcap", (5004, 5005, 5006, 5007))
chk("tshark-ssrc-set", sorted(x.lstrip("0x") for x in tseen), ["11111111", "22222222"])
for ssrc, (count, _) in sorted(mine.items()):
    chk("count-%s" % ssrc, count, len(tseen["0x" + ssrc]))
    chk("seq-order-%s" % ssrc, True, sorted(tseen["0x" + ssrc]) ==
        list(range(1000, 1000 + count)))

# the finding names two streams and counts its aligned frames
chk("finding-streams", one(text, "finding.0.streams"), "0:1")
chk("aligned", one(text, "finding.0.aligned_frames"), "12")

# ── 2. the two ways a pair must be refused ─────────────────────────────
rc, text = detect(tmp + "/noreuse.pcap")
chk("verdict-noreuse", one(text, "status"), "no_reuse")
rc, text = detect(tmp + "/legs.pcap")
chk("verdict-legs", one(text, "status"), "no_reuse")
chk("legs-excluded", one(text, "excluded_reverse"), "1")
chk("legs-pairs", one(text, "pairs_compared"), "0")
# tshark sees the same two streams: refusing to compare them is the module's
# claim, not the dissector's
chk("tshark-legs-ssrc-count", len(tshark_rtp(tmp + "/legs.pcap", (5004, 5005))), 2)

print("ASSERTION\t%s\t%s" % ("referee", "tshark"))
print("ASSERTION\t%s\t%s" % ("not-compared",
                             "the reuse verdict: no external oracle, ground truth is the constructed pad"))
sys.exit(1 if fails else 0)
PYCOMPARE
rc=$?

printf 'RESULT\t%s\n' "$([[ $rc -eq 0 ]] && echo 'PASS every assertion agrees with tshark' || echo "FAIL($rc)")"
exit $rc
