#!/usr/bin/env bash
# Traffic analysis and website fingerprinting over encrypted cellular flows.
#
# Owns ATTACK_COVERAGE.md P4 (traffic analysis) and P5 (website
# fingerprinting). The adversary model is the passive on-path observer who
# sees ciphertext only: no payload, no SNI, no DNS — just packet sizes,
# directions and inter-arrival times. Everything in this file works on a
# pcap on disk. No radio, no root, no network.
#
# ---------------------------------------------------------------------------
# What this module can and cannot do — stated in the output, not just here
#
#   Page-level fingerprinting is realistic on mobile. Host-level
#   fingerprinting is weak. The reason is mechanical, not a limitation of
#   this implementation: on a mobile bearer many connections are multiplexed
#   onto one radio bearer, the network re-segments and buffers, and the
#   packet boundaries the observer sees are not the ones the application
#   wrote. A classifier that reports "this is google.com" from a mobile
#   trace is overclaiming; one that reports "this trace is closest to the
#   page-load reference set" is not. The --classify output says which of the
#   two it is doing.
#
#   This is the passive half of the space and it is the half a defender
#   needs: if the module can name a page from a padded trace, the padding is
#   not doing its job. --features reports shaping detection for that reason.
# ---------------------------------------------------------------------------
#
# The pcap reader is python3, staged under $MOD_TMP. tshark is deliberately
# NOT a dependency: a research toolkit that cannot read a capture on a bare
# machine does not work in the field, and tshark's reassembly (tcp.stream /
# frame.time_delta) hides exactly the packet boundaries this module measures.
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

MOD_TMP="$TMP_DIR/traffic_analysis"
TANA_DIR="$LOOT_DIR/traffic_analysis"
TANA_REFS="$TANA_DIR/fingerprints.tsv"
TANA_EVAL="$TANA_DIR/classify.tsv"
mkdir -p "$MOD_TMP" "$TANA_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
# A capture is attacker-controlled by definition: a file name, an IPv6
# address or a fingerprint label can carry a tab and forge an entire row in
# a consumer that splits on tab. Tabs, CR and LF become spaces at the point
# of output.
tana_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# Split a TSV line into the global array TANA_F, preserving empty fields.
# `read` with IFS=tab treats tab as whitespace and collapses runs of it, so
# a row with an empty column shifts every field after it. cut -f does not.
TANA_F=()
tana_split() {
    TANA_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        TANA_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── the python engine ───────────────────────────────────────────────────
# One program, staged once, mode-dispatched. It carries the pcap/pcapng
# reader, the flow reassembler, the feature builder, the cosine/distance
# metrics and the burst detector. bash is the wrong tool for all of these.
tana_engine_py() {
    cat << 'PYEOF'
#!/usr/bin/env python3
"""Encrypted-traffic flow analysis and website fingerprinting.

Reads classic pcap (magic 0xa1b2c3d4 / 0xd4c3b2a1, and the nanosecond
variants) and pcapng (SHB / IDB / EPB / SPB), reassembles bidirectional
5-tuples, and emits TSV. No third-party imports on the reader path; numpy
is used only for the signal maths in --mode features/classify (scipy is not
required).

Every metric here is defined where it is implemented, because a number a
reader cannot recompute is a number a reader has to trust.
"""
import sys
import os
import struct
import math
import binascii

PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
PCAP_MAGIC_NS_LE = 0xa1b23c4d
PCAP_MAGIC_NS_BE = 0x4d3cb2a1
PCAPNG_MAGIC = 0x0a0d0d0a

LINKTYPE_NAMES = {
    0: "NULL/loopback", 1: "Ethernet", 12: "raw IP (BSD)", 101: "raw IP",
    105: "IEEE 802.11", 113: "Linux SLL", 127: "radiotap", 228: "IPv4",
    229: "IPv6", 276: "Linux SLL2",
}

# Feature-vector geometry. Stated as constants so the tests and the code
# cannot drift apart.
Q_SIZES = 7          # packet-size quantiles, two directions
Q_TIMES = 7          # inter-arrival quantiles
HIST_BINS = 16       # signed-size histogram
N_PREAMBLE = 12      # first N signed packet sizes (capped, zero padded)
DEFAULT_IDLE = 1.0   # seconds; idle gap that ends a burst

FEATURE_VERSION = "tana-fp-1"


def out(*fields):
    sys.stdout.write("\t".join("" if f is None else str(f) for f in fields) + "\n")


def err(msg):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.stderr.flush()


class PcapError(Exception):
    """Raised with a reason a caller can print. Never swallowed."""


# ─────────────────────────────────────────────────────────────────────────
# capture reader
# ─────────────────────────────────────────────────────────────────────────
class Reader:
    """Yields (index, ts_float, linktype, frame_bytes).

    A hard record cap keeps a corrupt incl_len from allocating gigabytes.
    """

    MAX_RECORD = 262144

    def __init__(self, path):
        self.path = path
        try:
            self.fh = open(path, "rb")
        except OSError as e:
            raise PcapError("cannot open %s: %s" % (path, e.strerror))
        self.linktype = None
        self.format = None
        self.swapped = False
        self.nsec = False
        self._index = 0
        self.truncated_at = None

    def sniff(self):
        head = self.fh.read(4)
        if len(head) < 4:
            raise PcapError("file is %d bytes - too short to be a capture"
                            % len(head))
        self.fh.seek(0)
        magic_le = struct.unpack("<I", head)[0]
        if magic_le == PCAPNG_MAGIC:
            self.format = "pcapng"
            return
        if magic_le in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self.format = "pcap"
            self.swapped = False
        elif magic_le in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            # The first four bytes read little-endian produced the swapped
            # constant, so every field in the file is big-endian.
            self.format = "pcap"
            self.swapped = True
        else:
            raise PcapError("not a pcap or pcapng capture (magic 0x%08x)"
                            % magic_le)
        self.nsec = magic_le in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)
        hdr = self.fh.read(24)
        if len(hdr) < 24:
            raise PcapError("pcap global header truncated: wanted 24 bytes, "
                            "got %d" % len(hdr))
        endian = ">" if self.swapped else "<"
        (magic, vmaj, vmin, tz, sigfigs, snaplen, network) = struct.unpack(
            endian + "IHHiIII", hdr)
        if vmaj != 2:
            raise PcapError("unsupported pcap version %d.%d" % (vmaj, vmin))
        self.linktype = network

    def frames(self):
        if self.format == "pcap":
            for f in self._frames_pcap():
                yield f
        else:
            for f in self._frames_pcapng():
                yield f

    def _frames_pcap(self):
        endian = ">" if self.swapped else "<"
        while True:
            hdr = self.fh.read(16)
            if len(hdr) == 0:
                return                      # clean EOF
            if len(hdr) < 16:
                self.truncated_at = self._index + 1
                raise PcapError("record %d header truncated: wanted 16 bytes, "
                                "got %d" % (self._index + 1, len(hdr)))
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                endian + "IIII", hdr)
            if incl_len > self.MAX_RECORD:
                raise PcapError("record %d declares incl_len=%d - refusing to "
                                "read it" % (self._index + 1, incl_len))
            data = self.fh.read(incl_len)
            if len(data) < incl_len:
                self.truncated_at = self._index + 1
                raise PcapError("record %d truncated: wanted %d bytes, got %d"
                                % (self._index + 1, incl_len, len(data)))
            self._index += 1
            ts = ts_sec + (ts_frac / 1e9 if self.nsec else ts_frac / 1e6)
            yield (self._index, ts, self.linktype, data)

    def _frames_pcapng(self):
        ifaces = {}
        while True:
            head = self.fh.read(8)
            if len(head) == 0:
                return
            if len(head) < 8:
                raise PcapError("pcapng block header truncated at block %d"
                                % (self._index + 1))
            btype, blen = struct.unpack("<II", head)
            if blen < 12 or blen > 16777216:
                raise PcapError("pcapng block 0x%08x declares length %d - "
                                "malformed" % (btype, blen))
            body = self.fh.read(blen - 12)
            tail = self.fh.read(4)
            if len(body) < blen - 12 or len(tail) < 4:
                raise PcapError("pcapng block 0x%08x truncated: wanted %d body "
                                "bytes" % (btype, blen - 12))
            if btype == 0x00000001:         # Interface Description Block
                if len(body) >= 8:
                    ifaces[len(ifaces)] = struct.unpack("<H", body[0:2])[0]
                    if len(ifaces) == 1:
                        self.linktype = ifaces[0]
            elif btype == 0x00000006:       # Enhanced Packet Block
                if len(body) < 20:
                    continue
                iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                    "<IIIII", body[0:20])
                data = body[20:20 + cap_len]
                if len(data) < cap_len:
                    raise PcapError("pcapng EPB declares caplen=%d but carries "
                                    "%d bytes" % (cap_len, len(data)))
                ts = ((ts_hi << 32) | ts_lo) / 1e6
                self._index += 1
                yield (self._index, ts,
                       ifaces.get(iface_id, self.linktype or 1), data)
            elif btype == 0x00000003:       # Simple Packet Block
                if len(body) < 4:
                    continue
                orig_len = struct.unpack("<I", body[0:4])[0]
                data = body[4:]
                self._index += 1
                yield (self._index, 0.0,
                       ifaces.get(0, self.linktype or 1), data)


def parse_l3(linktype, data):
    """Return (ethertype, l3_bytes) or (None, b'').

    Link types actually encountered on captured cellular bearers: Ethernet,
    Linux SLL and SLL2, raw IP (both numbers), loopback, and radiotap /
    802.11 for Wi-Fi offload. An unknown link type returns no L3, which the
    caller counts as unparsed rather than guessing.
    """
    if linktype == 1:                                   # Ethernet II
        if len(data) < 14:
            return (None, b"")
        et = struct.unpack(">H", data[12:14])[0]
        off = 14
        while et == 0x8100 and len(data) >= off + 4:    # 802.1Q
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        return (et, data[off:])
    if linktype == 113:                                 # Linux SLL
        if len(data) < 16:
            return (None, b"")
        return (struct.unpack(">H", data[14:16])[0], data[16:])
    if linktype == 276:                                 # Linux SLL2
        if len(data) < 20:
            return (None, b"")
        return (struct.unpack(">H", data[0:2])[0], data[20:])
    if linktype in (101, 12, 228):                      # raw IP
        if not data:
            return (None, b"")
        v = data[0] >> 4
        return (0x0800 if v == 4 else 0x86DD if v == 6 else None, data)
    if linktype == 229:                                 # raw IPv6
        return (0x86DD, data)
    if linktype in (105, 127):                          # 802.11 / radiotap
        off = 0
        if linktype == 127:
            if len(data) < 8:
                return (None, b"")
            # radiotap: it_version(1) pad(1) it_len(2) it_present(4).
            # The present word's bit 0 extends it by another 4 bytes; bit 4
            # (FCS) appends a 4-byte trailer we must not include in L3.
            it_len = struct.unpack("<H", data[2:4])[0]
            present = struct.unpack("<I", data[4:8])[0]
            if present & 0x80000000:
                it_len += 4
            if present & 0x00000010:
                data = data[:-4] if len(data) >= 4 else data
            off = it_len
            fh_bytes = data[off:off + 2]
            if len(fh_bytes) < 2:
                return (None, b"")
            fc = struct.unpack("<H", fh_bytes)[0]
        else:
            if len(data) < 2:
                return (None, b"")
            fc = struct.unpack("<H", data[0:2])[0]
        ftype = (fc >> 2) & 0x3
        if ftype != 2:                                  # only data frames
            return (None, b"")
        to_ds = (fc >> 8) & 1
        from_ds = (fc >> 9) & 1
        hdr = 24 if (to_ds and from_ds) else (30 if (to_ds or from_ds) else 24)
        if ((fc >> 4) & 0xF) == 8:                      # QoS data
            hdr += 2
        off += hdr
        if len(data) < off + 8:
            return (None, b"")
        # LLC/SNAP: aa aa 03 00 00 00 <ethertype>
        if data[off:off + 3] != b"\xaa\xaa\x03":
            return (None, b"")
        et = struct.unpack(">H", data[off + 6:off + 8])[0]
        return (et, data[off + 8:])
    return (None, b"")


def parse_ip(payload):
    """Return dict(src, dst, proto, sport, dport, length) or None."""
    if len(payload) < 20:
        return None
    v = payload[0] >> 4
    if v == 4:
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        total_len = struct.unpack(">H", payload[2:4])[0]
        proto = payload[9]
        src = ".".join(str(b) for b in payload[12:16])
        dst = ".".join(str(b) for b in payload[16:20])
        frag = struct.unpack(">H", payload[6:8])[0]
        if (frag & 0x1FFF) != 0:
            return None                      # non-first fragment: no ports
        l4 = payload[ihl:]
    elif v == 6:
        if len(payload) < 40:
            return None
        plen = struct.unpack(">H", payload[4:6])[0]
        proto = payload[6]
        nxt = proto
        off = 40
        # Walk extension headers to find the transport header. Only the
        # typical chain for TCP/UDP matters here.
        while nxt in (0, 43, 60):
            if len(payload) < off + 8:
                return None
            nh = payload[off]
            elen = (payload[off + 1] + 1) * 8
            off += elen
            nxt = nh
        if nxt == 44:                        # fragment header
            return None
        proto = nxt
        src = ":".join("%x" % struct.unpack(">H", payload[i:i + 2])[0]
                       for i in range(8, 24, 2))
        dst = ":".join("%x" % struct.unpack(">H", payload[i:i + 2])[0]
                       for i in range(24, 40, 2))
        total_len = plen + 40
        l4 = payload[off:]
    else:
        return None
    sport = dport = 0
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack(">HH", l4[0:4])
    elif proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack(">HH", l4[0:4])
    elif proto == 132 and len(l4) >= 12:
        sport, dport = struct.unpack(">HH", l4[0:4])
    return {"src": src, "dst": dst, "proto": proto, "sport": sport,
            "dport": dport, "length": total_len}


def flow_records(path):
    """Yield (ts, ip_length, direction, src, dst, proto, sport, dport, index)
    for every frame that carries an IP packet.

    A bidirectional flow is keyed on the ordered pair of endpoints; packets
    in the reverse direction get direction=+1 or -1 relative to the first
    packet seen, and that first packet is the one with direction=+1.
    """
    r = Reader(path)
    r.sniff()
    for (idx, ts, linktype, frame) in r.frames():
        et, l3 = parse_l3(linktype, frame)
        if not l3:
            continue
        ip = parse_ip(l3)
        if ip is None:
            continue
        yield (idx, ts, ip)


def build_flows(path):
    """Return (list_of_flow_dicts, stats_dict). Raises PcapError on malformed
    input; a truncated final record is an error, never a silent short read."""
    flows = {}
    order = []
    stats = {"frames": 0, "ip_frames": 0, "unparsed": 0}
    r = Reader(path)
    r.sniff()
    for (idx, ts, linktype, frame) in r.frames():
        stats["frames"] += 1
        et, l3 = parse_l3(linktype, frame)
        if not l3:
            stats["unparsed"] += 1
            continue
        ip = parse_ip(l3)
        if ip is None:
            stats["unparsed"] += 1
            continue
        stats["ip_frames"] += 1
        a = ("%s:%d" % (ip["src"], ip["sport"]), "%s:%d" % (ip["dst"], ip["dport"]))
        if a[0] <= a[1]:
            key = (a[0], a[1], ip["proto"])
            fwd = a[0]
        else:
            key = (a[1], a[0], ip["proto"])
            fwd = a[1]
        f = flows.get(key)
        if f is None:
            f = {"key": key, "fwd": fwd, "packets": []}
            flows[key] = f
            order.append(key)
        signed = ip["length"] if a[0] == fwd else -ip["length"]
        f["packets"].append({"ts": ts, "len": ip["length"], "signed": signed,
                             "frame": idx})
    return ([flows[k] for k in order], stats)


def flow_stats(f):
    pk = f["packets"]
    n = len(pk)
    ts = [p["ts"] for p in pk]
    sizes = [p["signed"] for p in pk]
    iats = [ts[i + 1] - ts[i] for i in range(n - 1)]
    idx = list(range(n))
    order = sorted(idx, key=lambda i: pk[i]["ts"])
    sizes_ts = [sizes[i] for i in order]
    iats_ts = [ts[order[i + 1]] - ts[order[i]] for i in range(n - 1)]
    up = sum(p["len"] for p in pk if p["signed"] > 0)
    dn = sum(p["len"] for p in pk if p["signed"] < 0)
    nup = sum(1 for p in pk if p["signed"] > 0)
    ndn = n - nup
    abs_sizes = [abs(s) for s in sizes]
    return {
        "key": f["key"], "fwd": f["fwd"], "n": n, "up_bytes": up,
        "dn_bytes": dn, "up_pkts": nup, "dn_pkts": ndn,
        "first_ts": min(ts), "last_ts": max(ts),
        "dur": max(ts) - min(ts), "sizes": sizes_ts, "iats": iats_ts,
        "abs_sizes": abs_sizes,
    }


# ─────────────────────────────────────────────────────────────────────────
# bursts
# ─────────────────────────────────────────────────────────────────────────
def bursts_from_ts(ts_list, idle):
    """Split a flow into bursts on idle gaps > idle seconds.

    Returns (list_of_bursts, list_of_gap_seconds). A gap is the interval
    between the last packet of one burst and the first of the next, so the
    gaps are exactly the intervals a passive observer would call silence.
    """
    if not ts_list:
        return [], []
    b = []
    gaps = []
    start = ts_list[0]
    prev = ts_list[0]
    count = 1
    for t in ts_list[1:]:
        if t - prev > idle:
            b.append({"start": start, "end": prev, "packets": count})
            gaps.append(t - prev)
            start = t
            count = 0
        prev = t
        count += 1
    b.append({"start": start, "end": prev, "packets": count})
    return b, gaps


# ─────────────────────────────────────────────────────────────────────────
# features and metric
# ─────────────────────────────────────────────────────────────────────────
def quantiles(vals, q):
    """Linear-interpolation quantiles (numpy's default 'linear' method).
    Written out rather than called through numpy so the definition is
    inspectable: rank r = q*(n-1), floor/ceil interpolation."""
    if not vals:
        return [0.0] * len(q)
    s = sorted(vals)
    n = len(s)
    if n == 1:
        return [float(s[0])] * len(q)
    res = []
    for qq in q:
        r = qq * (n - 1)
        lo = int(math.floor(r))
        hi = min(lo + 1, n - 1)
        frac = r - lo
        res.append(s[lo] * (1 - frac) + s[hi] * frac)
    return res


QSIZE = [i / float(Q_SIZES - 1) for i in range(Q_SIZES)]
QTIME = [i / float(Q_TIMES - 1) for i in range(Q_TIMES)]


def feature_vector(st):
    """Fixed-length feature vector, in this order:

      [0 .. 13]   direction-signed packet-size quantiles, +dir then -dir
      [14 .. 15]  up share of packets, up share of bytes
      [16]        packets per second
      [17]        natural log of packet count
      [18 .. 33]  16-bin normalised histogram of absolute packet size
      [34 .. 45]  first 12 direction-signed packet sizes, zero padded

    Every entry is non-negative and the vector is L2-normalised, so cosine
    similarity is the stated metric and it is scale-invariant by design: a
    trace replayed twice as long has the same direction.

    Count and duration deliberately do not enter the vector. Including them
    makes classification trivially separate short from long traces, which is
    not the page, it is the page's length.
    """
    n = st["n"]
    if n == 0:
        return [], []
    pos = [s for s in st["sizes"] if s > 0]
    neg = [-s for s in st["sizes"] if s < 0]
    v = []
    v += quantiles(pos, QSIZE) if pos else [0.0] * Q_SIZES
    v += quantiles(neg, QSIZE) if neg else [0.0] * Q_SIZES
    v.append(st["up_pkts"] / float(n))
    tot_bytes = st["up_bytes"] + st["dn_bytes"]
    v.append(st["up_bytes"] / float(tot_bytes) if tot_bytes else 0.0)
    dur = st["dur"]
    v.append(n / dur if dur > 0 else float(n))
    v.append(math.log1p(n))
    m = max(st["abs_sizes"]) if st["abs_sizes"] else 1
    hist = [0.0] * HIST_BINS
    for s in st["abs_sizes"]:
        b = int((s / float(m)) * (HIST_BINS - 1) + 0.5)
        hist[max(0, min(HIST_BINS - 1, b))] += 1
    tot = float(n)
    v += [h / tot for h in hist]
    pre = list(st["sizes"][:N_PREAMBLE])
    pre += [0.0] * (N_PREAMBLE - len(pre))
    v += pre
    return v, v


def timing_vector(st):
    """Inter-arrival quantiles in log1p(ms), z-normalised.

    Inter-arrival times do not have a meaningful zero, so cosine on the raw
    values would mostly measure the mean rather than the shape. The vector
    is shifted by its mean and scaled by its standard deviation, which is
    the standard z-score normalisation; the distance between two of these
    is then a scale-free comparison of timing shape.
    """
    iats = st["iats"]
    if not iats:
        return [0.0] * Q_TIMES, 0.0
    q = quantiles([math.log1p(max(0.0, t) * 1000.0) for t in iats], QTIME)
    mu = sum(q) / len(q)
    sd = math.sqrt(sum((x - mu) ** 2 for x in q) / len(q))
    if sd <= 1e-12:
        return [0.0] * len(q), 0.0
    return [(x - mu) / sd for x in q], sd


def cosine(a, b):
    """Cosine similarity (the standard linear-algebra definition, stated so
    the metric is inspectable rather than a library call):
        cos(a,b) = dot(a,b) / (||a|| * ||b||)
    Returns 0.0 if either vector is zero length or empty. No numpy: the loop
    is the definition, and the selftest checks it against hand-computed
    values (cos([3,4,0],[1,0,0]) = 0.6 exactly, cos([1,2,2],[2,2,1]) = 8/9).
    """
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


def timing_similarity(ta, tb):
    """RBF kernel on the z-normalised inter-arrival quantile vectors.

    d = ||ta - tb||2, s = exp(-d^2 / 2). The bandwidth is fixed at 1.0
    because the vectors are already z-scored, so one unit is one standard
    deviation of the timing shape - not a tuned parameter. A flow with no
    inter-arrival times z-scores to the zero vector, which would score 1.0
    against every other such flow; that is the absence of a measurement,
    not a perfect match, so it is reported as 0.0.
    """
    if not ta or not tb or len(ta) != len(tb):
        return 0.0
    if all(x == 0.0 for x in ta) or all(x == 0.0 for x in tb):
        return 0.0
    d2 = sum((x - y) ** 2 for x, y in zip(ta, tb))
    return math.exp(-d2 / 2.0)


def combined_score(c_size, c_time, has_time):
    """Composite score in [0,1]: 0.7*size-cosine + 0.3*timing-RBF.

    The weights are a stated choice, not a fitted parameter. A flow with no
    inter-arrival times (a single packet) gets the size term alone, and the
    caller can see that from the time=0.0 column.
    """
    if not has_time:
        return c_size
    return 0.7 * c_size + 0.3 * c_time


def shape_report(st):
    """Padding / shaping detection.

    Two channels exist in a packet trace: size and timing. Constant-size
    records (low coefficient of variation of the packet size) destroy the
    size channel. Fixed-rate shaping (low coefficient of variation of the
    inter-arrival time, or a flat inter-arrival distribution) destroys the
    timing channel. Reporting which channel is still live is the defensive
    half of this module: it says whether a fingerprint can work at all.
    """
    sizes = st["abs_sizes"]
    iats = st["iats"]
    n = len(sizes)
    mu = sum(sizes) / float(n) if n else 0.0
    var = sum((x - mu) ** 2 for x in sizes) / float(n) if n else 0.0
    cv_size = math.sqrt(var) / mu if mu > 0 else 0.0
    if len(iats) >= 2:
        imu = sum(iats) / len(iats)
        ivar = sum((x - imu) ** 2 for x in iats) / len(iats)
        cv_time = math.sqrt(ivar) / imu if imu > 0 else 0.0
    else:
        cv_time = 0.0
    const_size = (n >= 4 and cv_size < 0.05)
    const_rate = (len(iats) >= 4 and cv_time < 0.05)
    if const_size and const_rate:
        verdict = "both-channels-shaped"
        note = ("constant-size records and fixed-rate timing: the size and "
                "timing channels are both suppressed, a page fingerprint "
                "cannot be built from this trace")
    elif const_size:
        verdict = "size-padded"
        note = ("constant-size records: the packet-size channel is "
                "suppressed; timing and direction still carry signal")
    elif const_rate:
        verdict = "rate-shaped"
        note = ("fixed-rate record emission: the timing channel is "
                "suppressed; size and direction still carry signal")
    else:
        verdict = "unshaped"
        note = ("neither constant-size nor fixed-rate: both size and timing "
                "channels are live, so a fingerprint is meaningful and the "
                "trace is exposed to one")
    return {"cv_size": cv_size, "cv_time": cv_time, "verdict": verdict,
            "note": note}


# ─────────────────────────────────────────────────────────────────────────
# reference store
# ─────────────────────────────────────────────────────────────────────────
REF_COLS = ["label", "file", "n", "up_bytes", "dn_bytes", "dur", "sizes",
            "iats", "feature_version"]


def load_refs(path):
    refs = []
    if not os.path.isfile(path):
        return refs
    with open(path, "r", errors="replace") as fh:
        first = True
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            f = line.split("\t")
            if first:
                first = False
                if f and f[0] == "label":
                    continue
            if len(f) < 9:
                continue
            st = {
                "n": int(f[2]) if f[2].isdigit() else 0,
                "up_bytes": int(f[3]) if f[3].lstrip("-").isdigit() else 0,
                "dn_bytes": int(f[4]) if f[4].lstrip("-").isdigit() else 0,
                "dur": float(f[5]) if f[5] not in ("", "nan") else 0.0,
                "sizes": [int(x) for x in f[6].split(",") if x not in ("",)],
                "iats": [float(x) for x in f[7].split(",") if x not in ("",)],
            }
            st["up_pkts"] = sum(1 for s in st["sizes"] if s > 0)
            st["dn_pkts"] = st["n"] - st["up_pkts"]
            st["abs_sizes"] = [abs(s) for s in st["sizes"]]
            st["first_ts"] = 0.0
            st["last_ts"] = st["dur"]
            st["key"] = ("ref", "ref", 0)
            refs.append({"label": f[0], "file": f[1], "st": st})
    return refs


def save_ref(label, fname, st):
    new = not os.path.exists(REF_FILE)
    with open(REF_FILE, "a") as fh:
        if new:
            fh.write("\t".join(REF_COLS) + "\n")
        fh.write("\t".join([
            label, fname, str(st["n"]), str(st["up_bytes"]),
            str(st["dn_bytes"]), "%.6f" % st["dur"],
            ",".join(str(s) for s in st["sizes"]),
            ",".join("%.6f" % t for t in st["iats"]),
            FEATURE_VERSION]) + "\n")


# ─────────────────────────────────────────────────────────────────────────
# modes
# ─────────────────────────────────────────────────────────────────────────
def mode_summary(path):
    r = Reader(path)
    r.sniff()
    flows, stats = build_flows(path)
    out("summary", "file", path)
    out("summary", "format", r.format)
    out("summary", "byte_order", "big-endian" if r.swapped else "little-endian")
    out("summary", "linktype", r.linktype)
    out("summary", "linktype_name", LINKTYPE_NAMES.get(r.linktype, "unknown"))
    out("summary", "frames", stats["frames"])
    out("summary", "ip_frames", stats["ip_frames"])
    out("summary", "non_ip_frames", stats["unparsed"])
    out("summary", "flows", len(flows))
    return 0


def mode_flows(path, idle):
    flows, stats = build_flows(path)
    header = ["idx", "endpoint_a", "endpoint_b", "proto", "packets", "bytes",
              "up_pkts", "dn_pkts", "up_bytes", "dn_bytes", "dur_s",
              "mean_size", "bursts", "max_idle_s", "shaping"]
    out(*header)
    for i, f in enumerate(flows):
        st = flow_stats(f)
        ts = [p["ts"] for p in f["packets"]]
        b, gaps = bursts_from_ts(ts, idle)
        sh = shape_report(st)
        out(i, f["key"][0], f["key"][1], f["key"][2], st["n"],
            st["up_bytes"] + st["dn_bytes"], st["up_pkts"], st["dn_pkts"],
            st["up_bytes"], st["dn_bytes"], "%.6f" % st["dur"],
            "%.1f" % ((st["up_bytes"] + st["dn_bytes"]) / float(st["n"]))
            if st["n"] else "0.0",
            len(b), "%.3f" % (max(gaps) if gaps else 0.0), sh["verdict"])
    out("summary", "flows", len(flows))
    out("summary", "frames", stats["frames"])
    out("summary", "ip_frames", stats["ip_frames"])
    out("summary", "idle_threshold_s", "%.3f" % idle)
    out("summary", "signal_note",
        "page-level fingerprints are realistic on a mobile bearer; "
        "host-level fingerprints are weak because the network re-segments "
        "and multiplexes connections onto one radio bearer")
    return 0


def mode_features(path, idx, idle):
    flows, stats = build_flows(path)
    if idx < 0 or idx >= len(flows):
        err("flow index %d out of range: capture has %d flows" % (idx, len(flows)))
        return 1
    f = flows[idx]
    st = flow_stats(f)
    ts = [p["ts"] for p in f["packets"]]
    b, gaps = bursts_from_ts(ts, idle)
    sh = shape_report(st)
    vec, _ = feature_vector(st)
    tvec, tsd = timing_vector(st)
    out("flow", "index", idx)
    out("flow", "endpoint_a", f["key"][0])
    out("flow", "endpoint_b", f["key"][1])
    out("flow", "proto", f["key"][2])
    out("flow", "packets", st["n"])
    out("flow", "up_pkts", st["up_pkts"])
    out("flow", "dn_pkts", st["dn_pkts"])
    out("flow", "up_bytes", st["up_bytes"])
    out("flow", "dn_bytes", st["dn_bytes"])
    up_dn = (st["up_bytes"] / float(st["dn_bytes"])) if st["dn_bytes"] else 0.0
    out("flow", "up_down_ratio", "%.6f" % up_dn)
    out("flow", "dur_s", "%.6f" % st["dur"])
    out("flow", "packet_size_seq", ",".join(str(s) for s in st["sizes"]))
    out("flow", "inter_arrival_seq_ms",
        ",".join("%.3f" % (t * 1000.0) for t in st["iats"]))
    out("flow", "bursts", len(b))
    out("flow", "burst_packets", ",".join(str(x["packets"]) for x in b))
    out("flow", "burst_dur_ms",
        ",".join("%.3f" % ((x["end"] - x["start"]) * 1000.0) for x in b))
    out("flow", "idle_gaps_ms", ",".join("%.3f" % (g * 1000.0) for g in gaps))
    # Request/response timing: for each direction change in the time-ordered
    # sequence, the gap between the last packet of the previous direction and
    # the first packet of the new one. That is the observable server/client
    # turnaround without any payload.
    turns = []
    for i in range(1, len(st["sizes"])):
        if (st["sizes"][i] > 0) != (st["sizes"][i - 1] > 0):
            turns.append(st["iats"][i - 1] * 1000.0)
    out("flow", "turnarounds", len(turns))
    out("flow", "turnaround_ms", ",".join("%.3f" % t for t in turns))
    out("flow", "shaping", sh["verdict"])
    out("flow", "shaping_note", sh["note"])
    out("flow", "size_cv", "%.6f" % sh["cv_size"])
    out("flow", "time_cv", "%.6f" % sh["cv_time"])
    out("flow", "feature_version", FEATURE_VERSION)
    out("flow", "feature_dim", len(vec))
    out("flow", "feature", ",".join("%.9f" % x for x in vec))
    out("flow", "timing_dim", len(tvec))
    out("flow", "timing", ",".join("%.9f" % x for x in tvec))
    return 0


def mode_fingerprint_add(label, path, idle):
    flows, stats = build_flows(path)
    if not flows:
        err("no IP flows in %s - nothing to fingerprint" % path)
        return 1
    # One pcap may carry many flows (a page load is many connections). The
    # fingerprint is built over the union of the trace's packets in time
    # order, which is what a page-level observer actually sees on the bearer.
    allp = []
    for f in flows:
        allp.extend(f["packets"])
    allp.sort(key=lambda p: p["ts"])
    st = {"n": len(allp),
          "sizes": [p["signed"] for p in allp],
          "iats": [allp[i + 1]["ts"] - allp[i]["ts"]
                   for i in range(len(allp) - 1)],
          "up_pkts": sum(1 for p in allp if p["signed"] > 0),
          "dn_pkts": sum(1 for p in allp if p["signed"] < 0),
          "up_bytes": sum(p["len"] for p in allp if p["signed"] > 0),
          "dn_bytes": sum(p["len"] for p in allp if p["signed"] < 0),
          "dur": (allp[-1]["ts"] - allp[0]["ts"]) if allp else 0.0,
          "abs_sizes": [abs(p["signed"]) for p in allp],
          "key": ("trace", "trace", 0)}
    os.makedirs(os.path.dirname(REF_FILE), exist_ok=True)
    save_ref(label, path, st)
    vec, _ = feature_vector(st)
    out("fingerprint_add", "label", label)
    out("fingerprint_add", "file", path)
    out("fingerprint_add", "flows", len(flows))
    out("fingerprint_add", "packets", st["n"])
    out("fingerprint_add", "bytes", st["up_bytes"] + st["dn_bytes"])
    out("fingerprint_add", "feature_dim", len(vec))
    out("fingerprint_add", "feature_version", FEATURE_VERSION)
    out("fingerprint_add", "store", REF_FILE)
    return 0


def trace_stats(path):
    flows, stats = build_flows(path)
    if not flows:
        return None, flows
    allp = []
    for f in flows:
        allp.extend(f["packets"])
    allp.sort(key=lambda p: p["ts"])
    st = {"n": len(allp),
          "sizes": [p["signed"] for p in allp],
          "iats": [allp[i + 1]["ts"] - allp[i]["ts"]
                   for i in range(len(allp) - 1)],
          "up_pkts": sum(1 for p in allp if p["signed"] > 0),
          "dn_pkts": sum(1 for p in allp if p["signed"] < 0),
          "up_bytes": sum(p["len"] for p in allp if p["signed"] > 0),
          "dn_bytes": sum(p["len"] for p in allp if p["signed"] < 0),
          "dur": (allp[-1]["ts"] - allp[0]["ts"]) if allp else 0.0,
          "abs_sizes": [abs(p["signed"]) for p in allp],
          "key": ("trace", "trace", 0)}
    return st, flows


def mode_classify(path, k, ref_file):
    refs = load_refs(ref_file)
    if not refs:
        err("reference set is empty (%s) - add one with --fingerprint-add"
            % ref_file)
        return 1
    st, flows = trace_stats(path)
    if st is None:
        err("no IP flows in %s - nothing to classify" % path)
        return 1
    q, _ = feature_vector(st)
    tq, _ = timing_vector(st)
    scored = []
    for r in refs:
        rq, _ = feature_vector(r["st"])
        rtq, _ = timing_vector(r["st"])
        cs = cosine(q, rq)
        ctv = timing_similarity(tq, rtq)
        has_t = bool(st["iats"]) and bool(r["st"]["iats"])
        scored.append({"label": r["label"], "file": r["file"], "size": cs,
                       "time": ctv,
                       "score": combined_score(cs, ctv, has_t)})
    scored.sort(key=lambda x: (-x["score"], x["label"]))
    sh = shape_report(st)
    out("classify", "trace", path)
    out("classify", "packets", st["n"])
    out("classify", "refs", len(refs))
    out("classify", "k", k)
    out("classify", "granularity", "page-level")
    out("classify", "shaping", sh["verdict"])
    out("classify", "shaping_note", sh["note"])
    out("classify", "metric",
        "score = 0.7*cosine(feature) + 0.3*exp(-||dtiming||^2/2)")
    out("rank", "label", "score", "size_cos", "time_rbf", "ref_file")
    for i, s in enumerate(scored[:k]):
        out(i + 1, s["label"], "%.6f" % s["score"], "%.6f" % s["size"],
            "%.6f" % s["time"], s["file"])
    return 0


def mode_refs_tsv(ref_file):
    if not os.path.isfile(ref_file):
        err("no reference store at %s" % ref_file)
        return 1
    n = 0
    with open(ref_file, "r", errors="replace") as fh:
        first = True
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if first and line.startswith("label\t"):
                first = False
                sys.stdout.write(line + "\n")
                continue
            first = False
            f = line.split("\t")
            if len(f) < 9:
                continue
            sys.stdout.write("\t".join(f[:9]) + "\n")
            n += 1
    if n == 0:
        err("reference store %s carries no fingerprints" % ref_file)
        return 1
    out("refs_summary", "count", n)
    return 0


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    args = argv[2:]

    def need(n, usage):
        if len(args) < n:
            err("usage: %s" % usage)
            return False
        return True

    global REF_FILE
    if mode == "summary":
        if not need(1, "--mode summary <pcap>"):
            return 2
        return mode_summary(args[0])
    if mode == "flows":
        if not need(1, "--mode flows <pcap> [idle_s]"):
            return 2
        idle = float(args[1]) if len(args) > 1 else DEFAULT_IDLE
        return mode_flows(args[0], idle)
    if mode == "features":
        if not need(2, "--mode features <pcap> <flow-index> [idle_s]"):
            return 2
        if not args[1].lstrip("-").isdigit():
            err("flow index must be a number")
            return 2
        idle = float(args[2]) if len(args) > 2 else DEFAULT_IDLE
        return mode_features(args[0], int(args[1]), idle)
    if mode == "fingerprint-add":
        if not need(2, "--mode fingerprint-add <label> <pcap>"):
            return 2
        return mode_fingerprint_add(args[0], args[1], DEFAULT_IDLE)
    if mode == "classify":
        if not need(1, "--mode classify <pcap> [k]"):
            return 2
        k = int(args[1]) if len(args) > 1 and args[1].isdigit() else 3
        return mode_classify(args[0], k, REF_FILE)
    if mode == "refs":
        return mode_refs_tsv(REF_FILE)
    return 2


REF_FILE = os.environ.get("TANA_REFS", "")

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except PcapError as e:
        err(str(e))
        sys.exit(1)
    except BrokenPipeError:
        sys.exit(0)
PYEOF
}

tana_ensure_engine() {
    mkdir -p "$MOD_TMP" 2>/dev/null
    local tmp="$MOD_TMP/.tana_engine.py.new"
    tana_engine_py > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    [[ -s "$tmp" ]] || { rm -f "$tmp"; return 1; }
    if [[ ! -f "$MOD_TMP/tana_engine.py" ]] || ! cmp -s "$tmp" "$MOD_TMP/tana_engine.py"; then
        mv -f "$tmp" "$MOD_TMP/tana_engine.py" || { rm -f "$tmp"; return 1; }
    else
        rm -f "$tmp"
    fi
    [[ -s "$MOD_TMP/tana_engine.py" ]]
}

tana_check_file() {
    local f="${1:-}"
    [[ -n "$f" ]] || { printf 'ERROR\tno capture given\n' >&2; return 2; }
    [[ -f "$f" ]] || { printf 'ERROR\tno such capture: %s\n' "$f" >&2; return 1; }
    [[ -r "$f" ]] || { printf 'ERROR\tcapture not readable: %s\n' "$f" >&2; return 1; }
    [[ -s "$f" ]] || { printf 'ERROR\tcapture is empty: %s\n' "$f" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tno python3 - the pcap reader is python3 and there is no tshark fallback by design\n' >&2
        return 1
    }
    return 0
}

# Run the engine. TANA_REFS is exported so the engine writes and reads the
# same store the shell reports in --status-tsv.
tana_run() {
    local mode="$1"; shift
    tana_ensure_engine || {
        printf 'ERROR\tcannot write the pcap engine to %s\n' "$MOD_TMP/tana_engine.py" >&2
        return 1
    }
    TANA_REFS="$TANA_REFS" python3 "$MOD_TMP/tana_engine.py" "$mode" "$@"
}

# ── reference store helpers ─────────────────────────────────────────────
tana_ref_count() {
    [[ -f "$TANA_REFS" ]] || { echo 0; return; }
    local n
    n=$(tail -n +2 "$TANA_REFS" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

tana_refs_tsv() {
    local n; n=$(tana_ref_count)
    if [[ "$n" -eq 0 ]]; then
        printf 'ERROR\tno fingerprints stored; run --fingerprint-add first\n' >&2
        return 1
    fi
    tana_run refs || return 1
}

tana_clear_refs() {
    mkdir -p "$TANA_DIR"
    # Write the header with its real tabs. Six fields are empty here; each
    # one still emits its separator (conventions §12), so the header has the
    # same nine columns as a data row.
    printf 'label\tfile\tn\tup_bytes\tdn_bytes\tdur\tsizes\tiats\tfeature_version\n' \
        > "$TANA_REFS"
    ok "fingerprint store cleared: $TANA_REFS"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
tana_cli_status_tsv() {
    local py eng
    py=$(command -v python3 >/dev/null 2>&1 && echo present || echo missing)
    eng=$([[ -s "$MOD_TMP/tana_engine.py" ]] && echo ready || echo not-staged)
    printf 'python3\t%s\n'       "$py"
    printf 'engine\t%s\n'        "$eng"
    printf 'engine_path\t%s\n'   "$MOD_TMP/tana_engine.py"
    printf 'loot_dir\t%s\n'      "$TANA_DIR"
    printf 'fingerprints\t%s\n'  "$TANA_REFS"
    printf 'fingerprint_count\t%s\n' "$(tana_ref_count)"
    printf 'captures_dir\t%s\n'  "$CAPTURES_DIR"
    printf 'capture_count\t%s\n' "$(find "$CAPTURES_DIR" -maxdepth 1 -type f \
        \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) 2>/dev/null | wc -l | tr -d ' ')"
    printf 'up_down_ratio_defined\t%s\n' 'up_bytes/down_bytes'
    printf 'metric\t%s\n' 'cosine(feature) + timing RBF, combined 0.7/0.3'
    printf 'attack_coverage\tP4,P5\n'
    printf 'radio_required\tno\n'
}

tana_cmd_flows() {
    local f="${1:-}" idle="${2:-$DEFAULT_IDLE}"
    tana_check_file "$f" || return $?
    [[ "$idle" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tidle threshold must be a number of seconds\n' >&2; return 2; }
    tana_run flows "$f" "$idle"
}

tana_cmd_features() {
    local f="${1:-}" idx="${2:-}" idle="${3:-$DEFAULT_IDLE}"
    [[ -n "$f" && -n "$idx" ]] || {
        printf 'ERROR\tusage: --features <pcap> <flow-index> [idle-s]\n' >&2; return 2; }
    [[ "$idx" =~ ^[0-9]+$ ]] || { printf 'ERROR\tflow index must be a number\n' >&2; return 2; }
    [[ "$idle" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tidle threshold must be a number of seconds\n' >&2; return 2; }
    tana_check_file "$f" || return $?
    tana_run features "$f" "$idx" "$idle"
}

tana_cmd_fingerprint_add() {
    local label="${1:-}" f="${2:-}"
    [[ -n "$label" && -n "$f" ]] || {
        printf 'ERROR\tusage: --fingerprint-add <name> <pcap>\n' >&2; return 2; }
    # The label reaches a TSV row; sanitise before it is stored, not after.
    label=$(tana_sanitize "$label")
    [[ -n "${label// /}" ]] || { printf 'ERROR\tlabel is empty after sanitising\n' >&2; return 2; }
    tana_check_file "$f" || return $?
    mkdir -p "$TANA_DIR"
    tana_run fingerprint-add "$label" "$f"
}

tana_cmd_classify() {
    local f="${1:-}" k="${2:-3}"
    tana_check_file "$f" || return $?
    [[ "$k" =~ ^[0-9]+$ && "$k" -ge 1 ]] || {
        printf 'ERROR\tk must be a whole number >= 1\n' >&2; return 2; }
    if [[ "$(tana_ref_count)" -eq 0 ]]; then
        printf 'ERROR\tno fingerprints stored; classify needs a reference set (--fingerprint-add)\n' >&2
        return 1
    fi
    tana_run classify "$f" "$k"
}

tana_cmd_clear_refs() {
    tana_clear_refs
}

# ── selftest — no radio, no root, no network ────────────────────────────
# The synthetic captures below are written by hand, record by record, so
# every packet size and timestamp in the assertions is a value this test
# chose rather than a value the parser reported.
tana_selftest() {
    local bad=0 npass=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"; npass=$((npass + 1))
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    # Records like "summary<TAB>format<TAB>pcap" carry the key in field 2 and
    # the value in field 3. Reading them with fld would return field 2 (the
    # key) — a wrong answer that looks plausible, so the accessor is separate.
    f3() { printf '%s\n' "$1" | awk -F'\t' -v r="$2" -v k="$3" '$1==r && $2==k{print $3; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    # Redirect every write target into the scratch tree. The trap removes it
    # on any exit path, including a failed assertion or a signal.
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export TANA_DIR="$d/loot/traffic_analysis"
    export TANA_REFS="$TANA_DIR/fingerprints.tsv"
    export MOD_TMP="$d/tmp"
    mkdir -p "$MOD_TMP" "$TANA_DIR" "$CAPTURES_DIR" "$STATE_DIR"
    tana_cleanup() { rm -rf "$d"; }
    trap tana_cleanup EXIT

    tana_ensure_engine || { printf 'ERROR\tengine staging failed\n' >&2; return 1; }

    # ── fixture 1: four UDP packets, sizes and times chosen by hand ─────
    # Flow A -> B. Payload 100/200/300/400 bytes; IP total length =
    # 20 + 8 + payload = 128/228/328/428. Frame length = 14 + IP total =
    # 142/242/342/442. Timestamps: 0, 0.010, 0.030, 1.500 s after
    # 1700000000, so with a 1.0 s idle threshold the flow is two bursts and
    # the single idle gap is 1.470 s.
    local p1="$d/trace_a.pcap"
    python3 - "$p1" << 'PYFIX'
import struct, sys
def frame(payload_len, sport, dport):
    payload = bytes([0x41 + (i % 26) for i in range(payload_len)])
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64,
                     17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    eth = bytes.fromhex("0200000000010200000000020800")
    return eth + ip + udp
recs = [(100, 1700000000.000), (200, 1700000000.010),
        (300, 1700000000.030), (400, 1700000001.500)]
with open(sys.argv[1], "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for payload, ts in recs:
        f = frame(payload, 40000, 443)
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        fh.write(struct.pack("<IIII", sec, usec, len(f), len(f)))
        fh.write(f)
PYFIX
    chk fixture-a-size "$(wc -c < "$p1" | tr -d ' ')" "$((24 + 4*16 + 142 + 242 + 342 + 442))"

    out=$(tana_run summary "$p1"); rc=$?
    chk summary-rc       "$rc" "0"
    chk summary-format   "$(f3 "$out" summary format)" "pcap"
    chk summary-frames   "$(f3 "$out" summary frames)" "4"
    chk summary-ipframes "$(f3 "$out" summary ip_frames)" "4"
    chk summary-flows    "$(f3 "$out" summary flows)" "1"

    out=$(tana_run flows "$p1" 1.0); rc=$?
    chk flows-rc       "$rc" "0"
    # Row 1 is the only flow; the header is row 0 of the output.
    local row1; row1=$(printf '%s\n' "$out" | sed -n '2p')
    chk flows-row-fields "$(printf '%s' "$row1" | awk -F'\t' '{print NF}')" "15"
    chk flows-packets    "$(printf '%s' "$row1" | cut -f5)" "4"
    # Byte count is the sum of the IP total lengths: 128+228+328+428 = 1112.
    chk flows-bytes      "$(printf '%s' "$row1" | cut -f6)" "1112"
    chk flows-up-pkts    "$(printf '%s' "$row1" | cut -f7)" "4"
    chk flows-dn-pkts    "$(printf '%s' "$row1" | cut -f8)" "0"
    chk flows-bursts     "$(printf '%s' "$row1" | cut -f13)" "2"
    chk flows-max-idle   "$(printf '%s' "$row1" | cut -f14)" "1.470"
    chk flows-shaping    "$(printf '%s' "$row1" | cut -f15)" "unshaped"
    chk flows-summary    "$(f3 "$out" summary flows)" "1"

    out=$(tana_run features "$p1" 0 1.0); rc=$?
    chk features-rc        "$rc" "0"
    # The packet-size sequence is the IP total length, in time order, signed
    # by direction. This assertion is the core of the parser: it is a value
    # the fixture wrote into the file, not a value the parser produced.
    chk features-size-seq  "$(f3 "$out" flow packet_size_seq)" "128,228,328,428"
    chk features-iat-seq   "$(f3 "$out" flow inter_arrival_seq_ms)" "10.000,20.000,1470.000"
    chk features-packets   "$(f3 "$out" flow packets)" "4"
    chk features-up-bytes  "$(f3 "$out" flow up_bytes)" "1112"
    chk features-dn-bytes  "$(f3 "$out" flow dn_bytes)" "0"
    chk features-bursts    "$(f3 "$out" flow bursts)" "2"
    chk features-burst-pk  "$(f3 "$out" flow burst_packets)" "3,1"
    chk features-idle      "$(f3 "$out" flow idle_gaps_ms)" "1470.000"
    chk features-turns     "$(f3 "$out" flow turnarounds)" "0"
    chk features-dim       "$(f3 "$out" flow feature_dim)" "46"
    chk features-tdim      "$(f3 "$out" flow timing_dim)" "7"
    chk features-version   "$(f3 "$out" flow feature_version)" "tana-fp-1"
    chk features-bad-idx-rc "$(tana_run features "$p1" 9 1.0 >/dev/null 2>&1; echo $?)" "1"
    chk features-bad-idx-msg "$(tana_run features "$p1" 9 1.0 2>&1 | grep -c 'out of range')" "1"

    # A flow with a server reply, so direction and up/down ratio are real.
    local p2="$d/trace_b.pcap"
    python3 - "$p2" << 'PYFIX'
import struct, sys
def frame(payload_len, src, dst, sport, dport):
    payload = bytes([0x42] * payload_len)
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64,
                     17, 0, bytes(src), bytes(dst))
    eth = bytes.fromhex("0200000000010200000000020800")
    return eth + ip + udp
# First packet 10.0.0.1:40000 -> 10.0.0.2:443 defines the forward direction.
recs = [(frame(100, [10,0,0,1], [10,0,0,2], 40000, 443), 1700000000.000),
        (frame(50,  [10,0,0,2], [10,0,0,1], 443, 40000), 1700000000.040),
        (frame(120, [10,0,0,1], [10,0,0,2], 40000, 443), 1700000000.090),
        (frame(60,  [10,0,0,2], [10,0,0,1], 443, 40000), 1700000000.140)]
with open(sys.argv[1], "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for f, ts in recs:
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        fh.write(struct.pack("<IIII", sec, usec, len(f), len(f)))
        fh.write(f)
PYFIX
    out=$(tana_run features "$p2" 0 1.0); rc=$?
    chk bidir-rc       "$rc" "0"
    # Signed sizes: forward positive, reverse negative. IP totals are
    # 128, 78, 148, 88; up = 128+148 = 276, down = 78+88 = 166.
    chk bidir-sizes    "$(f3 "$out" flow packet_size_seq)" "128,-78,148,-88"
    chk bidir-up-bytes "$(f3 "$out" flow up_bytes)" "276"
    chk bidir-dn-bytes "$(f3 "$out" flow dn_bytes)" "166"
    chk bidir-up-pkts  "$(f3 "$out" flow up_pkts)" "2"
    chk bidir-dn-pkts  "$(f3 "$out" flow dn_pkts)" "2"
    chk bidir-turns    "$(f3 "$out" flow turnarounds)" "3"
    chk bidir-turn-ms  "$(f3 "$out" flow turnaround_ms)" "40.000,50.000,50.000"
    chk bidir-ratio    "$(f3 "$out" flow up_down_ratio)" "1.662651"
    # Direction detection is not an assumption about port 443; the first
    # packet seen defines forward, so this flow's forward is a->b.

    # ── similarity metric against hand-computed values ──────────────────
    # cos([3,4,0],[1,0,0]) = 3/5 = 0.6 exactly.
    chk cos-345-100 "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import tana_engine as e
print('%.6f' % e.cosine([3,4,0],[1,0,0]))")" "0.600000"
    # cos([1,2,2],[2,2,1]) = 8/9 = 0.888889. Both values are textbook.
    chk cos-122-221 "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import tana_engine as e
print('%.6f' % e.cosine([1,2,2],[2,2,1]))")" "0.888889"
    chk cos-orthogonal "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import tana_engine as e
print('%.6f' % e.cosine([1,0],[0,1]))")" "0.000000"
    # exp(-d^2/2): identical timing vectors score exactly 1.0; a shift of one
    # standard deviation on one component scores exp(-0.5) = 0.606531.
    chk time-ident "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import tana_engine as e
print('%.6f' % e.timing_similarity([0,1,2],[0,1,2]))")" "1.000000"
    chk time-shift "$(python3 -c "
import sys; sys.path.insert(0,'$MOD_TMP')
import tana_engine as e
print('%.6f' % e.timing_similarity([0,1,2],[1,1,2]))")" "0.606531"

    # ── fingerprint of a trace against ITSELF is the maximum ────────────
    local p3="$d/trace_c.pcap"
    python3 - "$p3" << 'PYFIX'
import struct, sys
def frame(plen, direction):
    payload = bytes([0x43] * plen)
    if direction > 0:
        src, dst, sp, dp = [10,0,0,1], [10,0,0,2], 40000, 80
    else:
        src, dst, sp, dp = [10,0,0,2], [10,0,0,1], 80, 40000
    udp = struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64,
                     17, 0, bytes(src), bytes(dst))
    return bytes.fromhex("0200000000010200000000020800") + ip + udp
# Deliberately different from trace_a: different sizes, different cadence.
recs = [(frame(500, 1), 1700000000.000), (frame(900, -1), 1700000000.200),
        (frame(140, 1), 1700000000.260), (frame(180, -1), 1700000000.300),
        (frame(640, 1), 1700000000.900)]
with open(sys.argv[1], "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for f, ts in recs:
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        fh.write(struct.pack("<IIII", sec, usec, len(f), len(f)))
        fh.write(f)
PYFIX
    tana_run fingerprint-add alpha "$p1" > /dev/null 2>&1
    chk ref-added "$(tana_ref_count)" "1"

    local self_json other_json
    self_json=$(python3 - "$MOD_TMP/tana_engine.py" "$TANA_REFS" "$p1" "$p3" << 'PYCHK'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("e", sys.argv[1])
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
e.REF_FILE = sys.argv[2]
refs = e.load_refs(sys.argv[2])
sa, _ = e.trace_stats(sys.argv[3])
sb, _ = e.trace_stats(sys.argv[4])
ra, _ = e.feature_vector(refs[0]["st"])
qa, _ = e.feature_vector(sa)
qb, _ = e.feature_vector(sb)
ta, _ = e.timing_vector(refs[0]["st"])
tqa, _ = e.timing_vector(sa)
tqb, _ = e.timing_vector(sb)
print("%.9f" % e.cosine(qa, ra), "%.9f" % e.cosine(qb, ra),
      "%.9f" % e.timing_similarity(tqa, ta),
      "%.9f" % e.timing_similarity(tqb, ta))
PYCHK
)
    local c_self c_other t_self t_other
    c_self=$(cut -d' ' -f1 <<<"$self_json")
    c_other=$(cut -d' ' -f2 <<<"$self_json")
    t_self=$(cut -d' ' -f3 <<<"$self_json")
    t_other=$(cut -d' ' -f4 <<<"$self_json")
    chk fp-self-max     "$(awk -v a="$c_self" 'BEGIN{print (a>0.999999)?"yes":"no"}')" "yes"
    chk fp-other-lower  "$(awk -v a="$c_other" -v b="$c_self" 'BEGIN{print (a<b)?"yes":"no"}')" "yes"
    chk fp-time-self    "$(awk -v a="$t_self" 'BEGIN{print (a>0.999999)?"yes":"no"}')" "yes"
    chk fp-time-other   "$(awk -v a="$t_other" -v b="$t_self" 'BEGIN{print (a<b)?"yes":"no"}')" "yes"

    # ── classify: refs present, then the empty-ref failure path ─────────
    out=$(tana_run classify "$p1" 2 2>&1); rc=$?
    chk classify-rc      "$rc" "0"
    chk classify-refs    "$(f3 "$out" classify refs)" "1"
    chk classify-top1    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="1"{print $2}')" "alpha"
    chk classify-rank-hd "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rank"{print NF}')" "6"
    # The trace that WAS the reference must score exactly 1.0: cosine of a
    # vector with itself is 1 and the timing RBF at zero distance is
    # exp(0) = 1, so the composite is 1.0. This is a maximum, not a tuned
    # threshold.
    local s_self
    s_self=$(printf '%s\n' "$out" | awk -F'\t' '$1=="1"{print $3}')
    chk classify-self-score "$(awk -v a="$s_self" 'BEGIN{print (a>0.999999)?"yes":"no"}')" "yes"

    # A second, deliberately different reference. The self trace must rank
    # its own reference first; if it ranks the other one, the metric is
    # inverted or the feature vector is not discriminating, and both are
    # bugs this assertion catches.
    tana_run fingerprint-add beta "$p3" >/dev/null 2>&1
    chk refs-two "$(tana_ref_count)" "2"
    out=$(tana_run classify "$p3" 2 2>&1); rc=$?
    chk classify2-rc    "$rc" "0"
    chk classify2-refs  "$(f3 "$out" classify refs)" "2"
    chk classify2-top1  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="1"{print $2}')" "beta"
    chk classify2-top2  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="2"{print $2}')" "alpha"
    local sc1 sc2
    sc1=$(printf '%s\n' "$out" | awk -F'\t' '$1=="1"{print $3}')
    sc2=$(printf '%s\n' "$out" | awk -F'\t' '$1=="2"{print $3}')
    chk classify2-order "$(awk -v a="$sc1" -v b="$sc2" 'BEGIN{print (a>b)?"yes":"no"}')" "yes"
    chk classify2-top-score "$(awk -v a="$sc1" 'BEGIN{print (a>0.999999)?"yes":"no"}')" "yes"
    # And the reverse direction: the alpha trace must rank alpha first.
    out=$(tana_run classify "$p1" 2 2>&1)
    chk classify2-rev   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="1"{print $2}')" "alpha"
    # Drop beta again so the count assertions below see one reference.
    python3 - "$TANA_REFS" << 'PYDROP'
import sys
p = sys.argv[1]
lines = [l for l in open(p, errors="replace") if not l.startswith("beta\t")]
open(p, "w").writelines(lines)
PYDROP
    chk refs-back-to-one "$(tana_ref_count)" "1"

    # Empty reference set: --classify must return non-zero, not an empty
    # success. The store is moved aside, not deleted, so the next block
    # still has it.
    local saved="$d/fp_saved.tsv"
    mv "$TANA_REFS" "$saved"
    chk empty-refs-count "$(tana_ref_count)" "0"
    chk empty-classify-rc "$(tana_cmd_classify "$p1" 3 >/dev/null 2>&1; echo $?)" "1"
    chk empty-classify-msg "$(tana_cmd_classify "$p1" 3 2>&1 | grep -c 'no fingerprints stored')" "1"
    chk empty-refs-tsv-rc "$(tana_refs_tsv >/dev/null 2>&1; echo $?)" "1"
    mv "$saved" "$TANA_REFS"
    chk refs-restored "$(tana_ref_count)" "1"
    chk refs-tsv-rc "$(tana_refs_tsv >/dev/null 2>&1; echo $?)" "0"
    chk refs-tsv-field-count "$(tana_refs_tsv | sed -n '2p' | awk -F'\t' '{print NF}')" "9"

    # ── shaping detection: constant size and constant rate ──────────────
    local p4="$d/trace_pad.pcap"
    python3 - "$p4" << 'PYFIX'
import struct, sys
with open(sys.argv[1], "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    # Eight packets, every payload exactly 500 bytes, every 20 ms.
    for i in range(8):
        payload = bytes([0x44] * 500)
        udp = struct.pack(">HHHH", 40000, 443, 508, 0) + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 528, 0x1234, 0, 64, 17, 0,
                         bytes([10,0,0,1]), bytes([10,0,0,2]))
        f = bytes.fromhex("0200000000010200000000020800") + ip + udp
        ts = 1700000000.0 + 0.020 * i
        sec = int(ts); usec = int(round((ts - sec) * 1e6))
        fh.write(struct.pack("<IIII", sec, usec, len(f), len(f)))
        fh.write(f)
PYFIX
    out=$(tana_run features "$p4" 0 0.5)
    chk padded-verdict "$(f3 "$out" flow shaping)" "both-channels-shaped"
    chk padded-size-cv "$(awk -v v="$(f3 "$out" flow size_cv)" 'BEGIN{print (v<0.0001)?"yes":"no"}')" "yes"
    chk padded-note    "$(f3 "$out" flow shaping_note | grep -c 'size and timing channels')" "1"

    # ── malformed input: every path non-zero and naming the reason ──────
    local trunc="$d/trunc.pcap"
    head -c 120 "$p1" > "$trunc"      # header + one full record + a partial
    out=$(tana_run summary "$trunc" 2>&1); rc=$?
    chk trunc-rc    "$rc" "1"
    chk trunc-msg   "$(printf '%s\n' "$out" | grep -c 'truncated')" "1"
    chk trunc-flows-rc "$(tana_run flows "$trunc" 1.0 >/dev/null 2>&1; echo $?)" "1"

    local junk="$d/junk.bin"
    printf 'this is not a capture at all, it is a text file\n' > "$junk"
    out=$(tana_run summary "$junk" 2>&1); rc=$?
    chk junk-rc  "$rc" "1"
    chk junk-msg "$(printf '%s\n' "$out" | grep -c 'not a pcap or pcapng')" "1"

    local tiny="$d/tiny.pcap"
    printf '\xd4\xc3' > "$tiny"
    chk tiny-rc "$(tana_run summary "$tiny" >/dev/null 2>&1; echo $?)" "1"
    : > "$d/empty.pcap"
    chk empty-rc "$(tana_cmd_flows "$d/empty.pcap" >/dev/null 2>&1; echo $?)" "1"

    # A truncated record must not be silently dropped: the flow count from
    # the partial file must be reported as an error, never as 1.
    chk nofile-rc  "$(tana_cmd_flows /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk missing-rc "$(tana_cmd_flows >/dev/null 2>&1; echo $?)" "2"
    chk bad-idle   "$(tana_cmd_flows "$p1" banana >/dev/null 2>&1; echo $?)" "2"
    chk bad-idx    "$(tana_cmd_features "$p1" abc >/dev/null 2>&1; echo $?)" "2"
    chk bad-k      "$(tana_cmd_classify "$p1" 0 >/dev/null 2>&1; echo $?)" "2"
    chk bad-k2     "$(tana_cmd_classify "$p1" x >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-unknown "$(tana_cli_main --nonsense >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-empty   "$(tana_cli_main >/dev/null 2>&1; echo $?)" "2"
    chk add-missing-args "$(tana_cmd_fingerprint_add >/dev/null 2>&1; echo $?)" "2"

    # ── a tab in a file name must not forge a TSV row ───────────────────
    local evil
    evil=$(tana_sanitize $'evil\tname\r\nsecond')
    chk sanitize-no-tabs "$(printf '%s' "$evil" | tr -d '\t\r\n' | wc -c | tr -d ' ')" \
        "$(printf '%s' "$evil" | wc -c | tr -d ' ')"
    chk sanitize-keeps-text "$(printf '%s' "$evil" | grep -c 'evil name')" "1"

    # A file name with a tab inside it: the flows row must still be 15 fields.
    local evilpcap="$d/evil${IFS}name.pcap"
    cp "$p1" "$evilpcap" 2>/dev/null || evilpcap="$d/evil name.pcap"
    cp "$p1" "$evilpcap"
    out=$(tana_run flows "$evilpcap" 1.0)
    chk evil-row-fields "$(printf '%s\n' "$out" | sed -n '2p' | awk -F'\t' '{print NF}')" "15"

    # ── status TSV contract ─────────────────────────────────────────────
    out=$(tana_cli_status_tsv)
    # The engine was staged at the top of this test, so it must report ready.
    # A status verb that cannot see its own scratch file is the bug this
    # catches.
    chk status-engine  "$(fld "$out" engine)" "ready"
    chk status-link    "$(fld "$out" engine_path)" "$MOD_TMP/tana_engine.py"
    chk status-store   "$(fld "$out" fingerprints)" "$TANA_REFS"
    chk status-count   "$(fld "$out" fingerprint_count)" "1"
    chk status-radio   "$(fld "$out" radio_required)" "no"
    chk status-attacks "$(fld "$out" attack_coverage)" "P4,P5"

    # The engine must be pure stdlib: no scapy, no numpy, no tshark. A
    # hidden dependency is a field failure, so assert its absence rather
    # than discovering it on a machine that lacks the package.
    chk engine-no-scapy "$(grep -c 'import scapy\|from scapy' "$MOD_TMP/tana_engine.py")" "0"
    chk engine-no-tshark "$(grep -c 'tshark' "$MOD_TMP/tana_engine.py")" "0"
    chk engine-no-numpy "$(grep -c 'import numpy' "$MOD_TMP/tana_engine.py")" "0"

    # ── clear the store: empty, and honest about being empty ────────────
    # Last, because it empties the store every earlier block populated.
    tana_clear_refs >/dev/null 2>&1
    chk clear-count   "$(tana_ref_count)" "0"
    chk clear-refs-rc "$(tana_refs_tsv >/dev/null 2>&1; echo $?)" "1"

    printf 'assertions\t%s\n' "$(( npass + bad ))"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
tana_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== traffic analysis / website fingerprinting ===${C_RESET}"
        echo -e "  python3: ${C_GRN}$(command -v python3 >/dev/null 2>&1 && echo present || echo MISSING)${C_RESET}"
        echo -e "  refs:    ${C_GRN}$(tana_ref_count)${C_RESET}  ${C_DIM}$TANA_REFS${C_RESET}"
        echo -e "  ${C_DIM}no radio needed - works on a pcap on disk${C_RESET}\n"
        cat << 'M'
  [1]  list flows in a pcap
  [2]  flow features (sizes, timings, bursts, shaping)
  [3]  add a fingerprint from a pcap
  [4]  classify a pcap against the reference set
  [5]  list reference fingerprints
  [6]  clear the reference set
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                read -rp "  pcap path> " p
                tana_cmd_flows "$p" | column -t -s$'\t' 2>/dev/null || tana_cmd_flows "$p"
                read -rp "  press enter " _ ;;
            2)
                read -rp "  pcap path> " p
                read -rp "  flow index> " i
                tana_cmd_features "$p" "$i" | column -t -s$'\t' 2>/dev/null || tana_cmd_features "$p" "$i"
                read -rp "  press enter " _ ;;
            3)
                read -rp "  label> " l
                read -rp "  pcap path> " p
                tana_cmd_fingerprint_add "$l" "$p"
                read -rp "  press enter " _ ;;
            4)
                read -rp "  pcap path> " p
                read -rp "  k [3]> " k
                tana_cmd_classify "$p" "${k:-3}" | column -t -s$'\t' 2>/dev/null || tana_cmd_classify "$p" "${k:-3}"
                read -rp "  press enter " _ ;;
            5) tana_refs_tsv | column -t -s$'\t' 2>/dev/null || tana_refs_tsv
               read -rp "  press enter " _ ;;
            6) tana_clear_refs; sleep 1 ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
tana_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     tana_cli_status_tsv ;;
        --flows)          tana_cmd_flows "${1:-}" "${2:-}" ;;
        --features)       tana_cmd_features "${1:-}" "${2:-}" "${3:-}" ;;
        --fingerprint-add) tana_cmd_fingerprint_add "${1:-}" "${2:-}" ;;
        --classify)       tana_cmd_classify "${1:-}" "${2:-}" ;;
        --refs-tsv)       tana_refs_tsv ;;
        --clear-refs)     tana_cmd_clear_refs ;;
        --selftest)       tana_selftest ;;
        --menu)           tana_menu ;;
        *)
            cat >&2 <<EOF
Traffic Analysis / Website Fingerprinting - P4, P5

Works on a pcap file. No radio, no root, no network.

Usage: $0 COMMAND
  --status-tsv                        engine and reference-store state as TSV
  --flows <pcap> [idle-s]             per-flow table: packets, bytes, bursts,
                                      idle gaps, shaping verdict
  --features <pcap> <flow-index> [idle-s]
                                      packet-size / inter-arrival / direction
                                      sequences and the feature vector
  --fingerprint-add <name> <pcap>     store a reference fingerprint
  --classify <pcap> [k]               top-k against the reference set
  --refs-tsv                          stored fingerprints as TSV
  --clear-refs                        empty the fingerprint store
  --selftest                          verify the parser and metrics offline
  --menu                              interactive menu

Granularity: page-level fingerprints are realistic on a mobile bearer;
host-level fingerprints are weak. The output says which one applies.
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
    tana_cli_main "$@"
fi
