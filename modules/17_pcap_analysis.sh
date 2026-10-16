#!/usr/bin/env bash
# Capture analysis for cellular protocols — pcap and pcapng, GSMTAP, SCTP,
# Diameter, NGAP, S1AP, MAP over M3UA, GTP-C/U, PFCP and RTP for VoLTE.
#
# Design note that matters more than any other in this file:
#
#   The module MUST work on a bare machine. tshark gives a far better
#   dissection when it is present, but a research toolkit that cannot read
#   a capture without a system package is a toolkit that does not work in
#   the field. So there are two complete paths:
#
#     with tshark    field extraction per protocol via -T fields
#     without tshark a real classic-pcap reader (magic 0xa1b2c3d4 and the
#                    byte-swapped 0xd4c3b2a1), a pcapng reader (SHB/IDB/EPB),
#                    and an Ethernet/IPv4/IPv6/UDP/TCP/SCTP walker in python3
#
#   --selftest exercises the fallback path only, on a synthetic capture it
#   builds by hand, so a machine with tshark installed still proves the
#   fallback works.
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

MOD_TMP="$TMP_DIR/pcap"
PCAP_DIR="$LOOT_DIR/pcap_analysis"
PCAP_IDENT="$PCAP_DIR/identities.tsv"
mkdir -p "$MOD_TMP" "$PCAP_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
# Every string that reaches a TSV row is untrusted: a capture is attacker
# controlled by definition, and a hostname or an SSID carrying a tab can
# forge an entire row in a consumer that splits on tab.
pcap_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# Split a TSV line into the global array PCAP_F, preserving empty fields.
# The python emitter writes "" for a field it has no value for (an identity
# seen on a layer with no IP addressing, for instance), and `read` with
# IFS=tab collapses a run of tabs into one delimiter — so `read` would shift
# every later column left. `cut -f` preserves the empty field.
PCAP_F=()
pcap_split() {
    PCAP_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        PCAP_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── protocol constants ──────────────────────────────────────────────────
# Ports and payload protocol identifiers as registered. The values are the
# real ones: 4729 GSMTAP, 2123 GTP-C, 2152 GTP-U, 8805 PFCP, 3868 Diameter
# over TCP/SCTP, 2905 M3UA, 4739 IPFIX. SCTP PPIDs: 3 M3UA, 18 S1AP,
# 46 Diameter, 60 NGAP, 141 SM/MMS.
pcap_proto_name() {
    case "${1:-}" in
        gsmtap)   echo "GSMTAP (UDP 4729)" ;;
        sctp)     echo "SCTP (IP proto 132)" ;;
        diameter) echo "Diameter (SCTP ppid 46 / TCP 3868)" ;;
        ngap)     echo "NGAP (SCTP ppid 60)" ;;
        s1ap)     echo "S1AP (SCTP ppid 18)" ;;
        m3ua)     echo "M3UA (SCTP ppid 3)" ;;
        map)      echo "MAP over M3UA/TCAP" ;;
        gtpc)     echo "GTP-C (UDP 2123)" ;;
        gtpu)     echo "GTP-U (UDP 2152)" ;;
        pfcp)     echo "PFCP (UDP 8805)" ;;
        rtp)      echo "RTP (VoLTE media)" ;;
        nas)      echo "NAS-EPS/5GS (S1AP/NGAP)" ;;
        *)        echo "unknown" ;;
    esac
}

# Port -> protocol. A UDP/TCP port alone never proves the protocol, which is
# why the dissectors below also check the payload (GTP version bits, PFCP
# message header, SCTP ppid) before believing the port.
pcap_port_proto() {
    case "${1:-}" in
        4729) echo "gsmtap" ;;
        2123|2124) echo "gtpc" ;;
        2152) echo "gtpu" ;;
        8805) echo "pfcp" ;;
        3868) echo "diameter" ;;
        2905) echo "m3ua" ;;
        *)    echo "" ;;
    esac
}

# SCTP payload protocol identifier -> protocol.
pcap_ppid_proto() {
    case "${1:-}" in
        3)   echo "m3ua" ;;
        18)  echo "s1ap" ;;
        46)  echo "diameter" ;;
        60)  echo "ngap" ;;
        *)   echo "" ;;
    esac
}

# ── the python fallback parser ──────────────────────────────────────────
# Written to a file under $MOD_TMP once, then run. Kept as a single python
# program rather than a pile of shell because pcap record walking in bash
# is both slow and full of traps (the byte-swapped magic, 64-bit nanosecond
# timestamps, per-interface link types in pcapng).
pcap_writer_py() {
    cat << 'PYEOF'
#!/usr/bin/env python3
"""Classic-pcap / pcapng reader and cellular dissector.

Reads link-layer frames, walks Ethernet / Linux cooked (SLL, SLL2) / raw IP
/ loopback, then IPv4 / IPv6, then UDP / TCP / SCTP, and reports what it
found. No external dependency: this is the path that runs on a bare box.

Emits TSV with a leading record-type column so the shell caller can switch
on it without a second pass over the file.
"""
import struct
import sys
import binascii

PCAP_MAGIC_LE = 0xa1b2c3d4          # native little-endian file
PCAP_MAGIC_BE = 0xd4c3b2a1          # byte-swapped (big-endian file)
PCAP_MAGIC_NS_LE = 0xa1b23c4d       # nanosecond resolution, LE
PCAP_MAGIC_NS_BE = 0x4d3cb2a1       # nanosecond resolution, BE
PCAPNG_MAGIC = 0x0a0d0d0a           # Section Header Block

LINKTYPES = {
    0: "NULL/loopback", 1: "Ethernet", 101: "raw IP", 113: "Linux SLL",
    276: "Linux SLL2", 105: "IEEE 802.11", 127: "radiotap",
    147: "USER0", 228: "IPv4", 229: "IPv6", 12: "raw IP (BSD)",
}
ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "VLAN"}
IPPROTOS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 132: "SCTP", 47: "GRE", 50: "ESP"}
PORTS = {4729: "gsmtap", 2123: "gtpc", 2124: "gtpc", 2152: "gtpu",
         8805: "pfcp", 3868: "diameter", 2905: "m3ua", 5060: "sip"}
PPIDS = {3: "m3ua", 18: "s1ap", 46: "diameter", 60: "ngap", 141: "sm"}

# SCTP chunk types (RFC 4960 §3.2). DATA = 0, INIT = 1.
SCTP_CHUNK = {0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT",
              5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK",
              9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 14: "SHUTDOWN_COMPLETE"}


def out(*fields):
    sys.stdout.write("\t".join("" if f is None else str(f) for f in fields) + "\n")


def err(msg):
    sys.stderr.write("ERROR\t%s\n" % msg)


class Reader:
    """A frame source: yields (idx, ts_sec, ts_usec, linktype, packet_bytes)."""

    def __init__(self, path):
        self.path = path
        self.fh = open(path, "rb")
        self.linktype = None
        self.format = None
        self.swapped = False
        self.nsec = False
        self._index = 0
        self._ng_ifaces = {}

    def sniff(self):
        head = self.fh.read(4)
        if len(head) < 4:
            err("file is %d bytes — too short to be a capture" % len(head))
            return False
        self.fh.seek(0)
        magic_le = struct.unpack("<I", head)[0]
        magic_be = struct.unpack(">I", head)[0]
        if magic_le == PCAPNG_MAGIC or magic_be == PCAPNG_MAGIC:
            self.format = "pcapng"
            return True
        if magic_le in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self.format = "pcap"
            self.swapped = False
        elif magic_le in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            # Reading the file's first four bytes as little-endian produced
            # the swapped constant, so the file stores big-endian integers.
            self.format = "pcap"
            self.swapped = True
        else:
            err("not a pcap or pcapng file (magic 0x%08x)" % magic_le)
            return False
        self.nsec = magic_le in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)
        hdr = self.fh.read(24)
        if len(hdr) < 24:
            err("pcap global header truncated")
            return False
        endian = ">" if self.swapped else "<"
        (magic, vmaj, vmin, tz, sigfigs, snaplen, network) = struct.unpack(
            endian + "IHHiIII", hdr)
        self.linktype = network
        out("global", "format", "pcap")
        out("global", "magic", "0x%08x" % magic)
        out("global", "byte_order", "big-endian" if self.swapped else "little-endian")
        out("global", "swapped", "yes" if self.swapped else "no")
        out("global", "version", "%d.%d" % (vmaj, vmin))
        out("global", "snaplen", snaplen)
        out("global", "linktype", network)
        out("global", "linktype_name", LINKTYPES.get(network, "unknown"))
        out("global", "timestamp_resolution", "nanosecond" if self.nsec else "microsecond")
        return True

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
            if len(hdr) < 16:
                return
            (ts_sec, ts_frac, incl_len, orig_len) = struct.unpack(endian + "IIII", hdr)
            if incl_len > 262144:
                err("frame %d declares incl_len=%d — refusing to read it"
                    % (self._index, incl_len))
                return
            data = self.fh.read(incl_len)
            if len(data) < incl_len:
                err("frame %d truncated: wanted %d bytes, got %d"
                    % (self._index, incl_len, len(data)))
                return
            self._index += 1
            yield (self._index, ts_sec, ts_frac, self.linktype, data, incl_len, orig_len)

    def _frames_pcapng(self):
        # pcapng is a sequence of blocks: type(4) length(4) body length(4).
        # Interface Description Blocks carry a per-interface link type, so a
        # capture with two interfaces cannot use one global value.
        ifaces = {}
        while True:
            head = self.fh.read(8)
            if len(head) < 8:
                return
            btype, blen = struct.unpack("<II", head)
            if blen < 12 or blen > 16777216:
                err("pcapng block %d declares length %d — malformed" % (btype, blen))
                return
            body = self.fh.read(blen - 12)
            tail = self.fh.read(4)
            if len(body) < blen - 12 or len(tail) < 4:
                err("pcapng block truncated")
                return
            if btype == 0x00000001:            # Interface Description Block
                if len(body) >= 8:
                    lt = struct.unpack("<H", body[0:2])[0]
                    ifaces[len(ifaces)] = lt
                    if len(ifaces) == 1:
                        self.linktype = lt
            elif btype == 0x00000006:          # Enhanced Packet Block
                if len(body) < 20:
                    continue
                iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                    "<IIIII", body[0:20])
                data = body[20:20 + cap_len]
                ts = (ts_hi << 32) | ts_lo
                lt = ifaces.get(iface_id, self.linktype or 1)
                self._index += 1
                yield (self._index, ts // 1000000, ts % 1000000, lt, data,
                       cap_len, orig_len)
            elif btype == 0x00000003:          # Simple Packet Block
                if len(body) < 4:
                    continue
                orig_len = struct.unpack("<I", body[0:4])[0]
                data = body[4:]
                self._index += 1
                lt = ifaces.get(0, self.linktype or 1)
                yield (self._index, 0, 0, lt, data, len(data), orig_len)
            # Section Header Block (0x0A0D0D0A) and everything else: skip.


def parse_link(linktype, data):
    """Return (ethertype_or_None, payload, note)."""
    if linktype == 1:                       # Ethernet II
        if len(data) < 14:
            return (None, b"", "short-ethernet")
        et = struct.unpack(">H", data[12:14])[0]
        off = 14
        # 802.1Q VLAN: the real ethertype follows the 4-byte tag.
        while et == 0x8100 and len(data) >= off + 4:
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        return (et, data[off:], "")
    if linktype == 113:                     # Linux SLL
        if len(data) < 16:
            return (None, b"", "short-sll")
        et = struct.unpack(">H", data[14:16])[0]
        return (et, data[16:], "")
    if linktype == 276:                     # Linux SLL2
        if len(data) < 20:
            return (None, b"", "short-sll2")
        et = struct.unpack(">H", data[0:2])[0]
        return (et, data[20:], "")
    if linktype in (101, 12, 228, 229):     # raw IP
        if not data:
            return (None, b"", "short-raw")
        ver = data[0] >> 4
        return (0x0800 if ver == 4 else 0x86DD, data, "")
    if linktype == 0:                       # NULL/loopback: 4-byte family
        if len(data) < 4:
            return (None, b"", "short-null")
        fam = struct.unpack("<I", data[0:4])[0]
        return (0x0800 if fam == 2 else 0x86DD, data[4:], "")
    return (None, b"", "unsupported-linktype-%d" % linktype)


def parse_ip(ethertype, data):
    """Return (proto, src, dst, l4_payload, note)."""
    if ethertype == 0x0800:
        if len(data) < 20:
            return (None, "", "", b"", "short-ipv4")
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20:
            return (None, "", "", b"", "bad-ipv4-ihl")
        proto = data[9]
        src = ".".join(str(b) for b in data[12:16])
        dst = ".".join(str(b) for b in data[16:20])
        total = struct.unpack(">H", data[2:4])[0]
        # IPv4 fragmentation: a non-first fragment has no L4 header, so
        # dissecting it would produce garbage ports. Report and stop.
        frag = struct.unpack(">H", data[6:8])[0]
        if (frag & 0x1FFF) != 0:
            return (proto, src, dst, b"", "ipv4-fragment")
        end = min(len(data), total) if total else len(data)
        return (proto, src, dst, data[ihl:end], "")
    if ethertype == 0x86DD:
        if len(data) < 40:
            return (None, "", "", b"", "short-ipv6")
        nxt = data[6]
        src = ":".join("%02x%02x" % (data[8 + i * 2], data[9 + i * 2]) for i in range(8))
        dst = ":".join("%02x%02x" % (data[24 + i * 2], data[25 + i * 2]) for i in range(8))
        off = 40
        # Walk the extension header chain. A capture with a Hop-by-Hop
        # header otherwise reads its first bytes as a UDP header.
        guard = 0
        while nxt in (0, 43, 44, 60) and guard < 8:
            guard += 1
            if len(data) < off + 8:
                return (nxt, src, dst, b"", "short-ipv6-ext")
            nxt2 = data[off]
            hlen = (data[off + 1] + 1) * 8
            if nxt == 44:                    # fragment header: fixed 8 bytes
                hlen = 8
                if struct.unpack(">H", data[off + 2:off + 4])[0] & 0xFFF8:
                    return (nxt2, src, dst, b"", "ipv6-fragment")
            off += hlen
            nxt = nxt2
        return (nxt, src, dst, data[off:], "")
    return (None, "", "", b"", "non-ip")


def parse_l4(proto, payload):
    """Return (sport, dport, l4name, app_payload, extra_dict)."""
    extra = {}
    if proto == 17:
        if len(payload) < 8:
            return (None, None, "UDP", b"", {"note": "short-udp"})
        sport, dport, ulen, _ = struct.unpack(">HHHH", payload[0:8])
        return (sport, dport, "UDP", payload[8:], extra)
    if proto == 6:
        if len(payload) < 20:
            return (None, None, "TCP", b"", {"note": "short-tcp"})
        sport, dport = struct.unpack(">HH", payload[0:4])
        doff = (payload[12] >> 4) * 4
        if doff < 20:
            return (sport, dport, "TCP", b"", {"note": "bad-tcp-doff"})
        flags = payload[13]
        extra["tcp_flags"] = flags
        return (sport, dport, "TCP", payload[doff:], extra)
    if proto == 132:
        return parse_sctp(payload)
    return (None, None, IPPROTOS.get(proto, "IP-%d" % proto), b"", extra)


def parse_sctp(payload):
    """SCTP common header (12 bytes) then chunks. Returns ppid of first DATA."""
    if len(payload) < 12:
        return (None, None, "SCTP", b"", {"note": "short-sctp"})
    sport, dport, vtag, csum = struct.unpack(">HHII", payload[0:12])
    off = 12
    ppid = None
    chunks = []
    app = b""
    while off + 4 <= len(payload):
        ctype, cflags, clen = struct.unpack(">BBH", payload[off:off + 4])
        if clen < 4 or off + clen > len(payload):
            chunks.append("%s(bad-len %d)" % (SCTP_CHUNK.get(ctype, ctype), clen))
            break
        cdata = payload[off + 4:off + clen]
        chunks.append(SCTP_CHUNK.get(ctype, "chunk-%d" % ctype))
        if ctype == 0 and len(cdata) >= 12:      # DATA chunk
            # DATA: TSN(4) stream id(2) stream seq(2) ppid(4) user data
            this_ppid = struct.unpack(">I", cdata[8:12])[0]
            if ppid is None:
                ppid = this_ppid
                app = cdata[12:]
        off += clen + ((4 - clen % 4) % 4)       # chunks are 4-byte aligned
    extra = {"ppid": ppid, "chunks": ",".join(chunks) if chunks else "-",
             "vtag": vtag}
    return (sport, dport, "SCTP", app, extra)


def hexdump_head(b, n=64):
    return binascii.hexlify(b[:n]).decode().upper()


def main():
    import argparse
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--file", required=True)
    ap.add_argument("--mode", default="summary",
                    choices=["summary", "list", "hierarchy", "conversations",
                             "extract", "identities"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--frame", type=int, default=0)
    ap.add_argument("--layer", default="")
    ap.add_argument("--max-frames", type=int, default=0)
    a = ap.parse_args()

    try:
        r = Reader(a.file)
    except OSError as e:
        err("cannot open %s: %s" % (a.file, e))
        return 2

    if not r.sniff():
        return 1

    nframes = 0
    total_bytes = 0
    first_ts = None
    last_ts = None
    hierarchy = {}
    conversations = {}
    identities = []
    extracted = None
    per_link = {}

    for (idx, ts_sec, ts_frac, linktype, data, incl_len, orig_len) in r.frames():
        nframes += 1
        total_bytes += incl_len
        if first_ts is None:
            first_ts = ts_sec
        last_ts = ts_sec
        per_link[linktype] = per_link.get(linktype, 0) + 1

        if a.mode == "summary" and a.max_frames and nframes > a.max_frames:
            break

        et, l3, lnote = parse_link(linktype, data)
        proto, src, dst, l4, inote = parse_ip(et, l3) if et else (None, "", "", b"", lnote)
        sport = dport = None
        l4name = "-"
        app = b""
        extra = {}
        if proto is not None:
            sport, dport, l4name, app, extra = parse_l4(proto, l4)

        # Protocol classification: port first, then a payload sanity check
        # so a random flow on 2152 is not reported as GTP-U.
        pname = ""
        detail = []
        if l4name == "UDP":
            for p in (sport, dport):
                cand = PORTS.get(p)
                if cand:
                    pname = cand
                    break
            if pname == "gsmtap":
                # GSMTAP header (osmocore gsmtap.h):
                #   version(1) hdr_len(1, 4-byte units) type(1) timeslot(1)
                #   arfcn(2) signal_dbm(1) snr_db(1) [frame_number(4)]
                # hdr_len counts 4-byte words, so the ARFCN and signal
                # fields are present when hdr_len >= 2 (8 bytes). Reading a
                # fixed 16 bytes drops them on every normal capture.
                if len(app) >= 4:
                    v = app[0] & 0x0F
                    hdr_len = app[1] * 4
                    detail.append("gsmtap_ver=%d" % v)
                    detail.append("gsmtap_type=%d" % app[2])
                    detail.append("gsmtap_hdr_len=%d" % hdr_len)
                    if hdr_len >= 8 and len(app) >= 8:
                        arfcn = struct.unpack(">H", app[4:6])[0]
                        signal = struct.unpack(">b", app[6:7])[0]
                        snr = struct.unpack(">b", app[7:8])[0]
                        detail.append("arfcn=%d" % arfcn)
                        detail.append("signal_dbm=%d" % signal)
                        detail.append("snr_db=%d" % snr)
                    if hdr_len >= 12 and len(app) >= 12:
                        detail.append("frame_number=%d"
                                      % struct.unpack(">I", app[8:12])[0])
                else:
                    pname = "gsmtap?"      # port says GSMTAP but header is short
            elif pname == "gtpu":
                # GTP-U: flags(1) msgtype(1) length(2) TEID(4).
                if len(app) >= 8 and (app[0] & 0xE0) == 0x20:
                    detail.append("gtp_msgtype=%d" % app[1])
                    detail.append("teid=0x%08x" % struct.unpack(">I", app[4:8])[0])
                else:
                    pname = "gtpu?"
            elif pname == "gtpc":
                if len(app) >= 8 and (app[0] & 0xE0) == 0x20:
                    detail.append("gtp_msgtype=%d" % app[1])
                    detail.append("teid=0x%08x" % struct.unpack(">I", app[4:8])[0])
                else:
                    pname = "gtpc?"
            elif pname == "pfcp":
                if len(app) >= 8 and app[1] in (1, 2, 3, 4, 5, 6, 50, 51, 52, 53, 54, 55):
                    detail.append("pfcp_msgtype=%d" % app[1])
                    detail.append("seid=0x%016x" % struct.unpack(">Q", app[4:12])[0]
                                  if len(app) >= 12 else "seid=?")
                else:
                    pname = "pfcp?"
            elif pname == "diameter":
                if len(app) >= 5:
                    dver = app[0]
                    dlen = int.from_bytes(app[1:4], "big")
                    detail.append("diameter_ver=%d" % dver)
                    detail.append("diameter_len=%d" % dlen)
        elif l4name == "SCTP":
            ppid = extra.get("ppid")
            if ppid is not None:
                pname = PPIDS.get(ppid, "")
                detail.append("ppid=%d" % ppid)
            detail.append("chunks=%s" % extra.get("chunks", "-"))
            if pname == "diameter" and len(app) >= 5:
                detail.append("diameter_ver=%d" % app[0])
        elif l4name == "TCP":
            for p in (sport, dport):
                if PORTS.get(p):
                    pname = PORTS[p]
                    break

        # RTP: VoLTE media is RTP over UDP on an even port, version bits 10.
        if not pname and l4name == "UDP" and len(app) >= 12 and (app[0] >> 6) == 2:
            pt = app[1] & 0x7F
            if pt in (0, 8, 9, 18, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
                      107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
                      119, 120, 121, 122, 123, 124, 125, 126, 127):
                pname = "rtp"
                detail.append("rtp_pt=%d" % pt)
                detail.append("rtp_ssrc=0x%08x" % struct.unpack(">I", app[8:12])[0])

        if pname:
            key = pname.rstrip("?")
            hierarchy[key] = hierarchy.get(key, 0) + 1
        if l4name and l4name != "-":
            hierarchy[l4name] = hierarchy.get(l4name, 0) + 1
        if et:
            l3name = ETHERTYPES.get(et, "0x%04x" % et)
            hierarchy[l3name] = hierarchy.get(l3name, 0) + 1

        # A conversation key is the unordered endpoint pair plus protocol.
        if src and dst:
            a1 = "%s:%s" % (src, sport if sport is not None else "-")
            a2 = "%s:%s" % (dst, dport if dport is not None else "-")
            lo, hi = (a1, a2) if a1 <= a2 else (a2, a1)
            ckey = (pname or l4name, lo, hi)
            c = conversations.setdefault(ckey, {"frames": 0, "bytes": 0,
                                                "first": ts_sec, "last": ts_sec})
            c["frames"] += 1
            c["bytes"] += incl_len
            c["first"] = min(c["first"], ts_sec)
            c["last"] = max(c["last"], ts_sec)

        if a.mode == "list":
            if a.limit and nframes > a.limit:
                break
            out("frame", idx, "%.6f" % (ts_sec + ts_frac / 1e6), src or "-", dst or "-",
                sport if sport is not None else "-",
                dport if dport is not None else "-",
                l4name, pname or "-", incl_len, orig_len,
                " ".join(detail) if detail else "-")

        elif a.mode == "extract":
            if idx == a.frame:
                layers = {"raw": data, "l3": l3, "l4": l4, "app": app}
                want = a.layer.lower()
                blob = None
                if want in layers:
                    blob = layers[want]
                elif want == "gsmtap" and pname and pname.startswith("gsmtap"):
                    blob = app
                elif want in ("gtpu", "gtpc", "pfcp", "rtp") and pname == want:
                    blob = app
                elif want in ("diameter", "s1ap", "ngap", "m3ua") and pname == want:
                    blob = app
                elif want == "ip" or want == "l3":
                    blob = l3
                if blob is not None:
                    extracted = (idx, want, blob)
                else:
                    err("frame %d has no '%s' layer (protocol %s, l4 %s)"
                        % (idx, a.layer, pname or "none", l4name))
                    return 1
                break

        elif a.mode == "identities":
            found = find_identities(app, pname or l4name)
            for (kind, value, where) in found:
                identities.append((idx, kind, value, pname or l4name, src, dst, where))

    # ── output per mode ────────────────────────────────────────────────
    if a.mode == "summary":
        out("summary", "frames", nframes)
        out("summary", "bytes", total_bytes)
        out("summary", "first_ts", first_ts if first_ts is not None else 0)
        out("summary", "last_ts", last_ts if last_ts is not None else 0)
        out("summary", "duration_s", (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0)
        for lt, c in sorted(per_link.items()):
            out("linktype", lt, LINKTYPES.get(lt, "unknown"), c)
        out("summary", "protocols_seen", len(hierarchy))
        out("end", "ok")
        return 0

    if a.mode == "hierarchy":
        for k in sorted(hierarchy, key=lambda x: (-hierarchy[x], x)):
            out("hierarchy", k, hierarchy[k])
        out("end", "ok")
        return 0

    if a.mode == "conversations":
        rows = sorted(conversations.items(), key=lambda kv: -kv[1]["bytes"])
        for (proto, lo, hi), c in rows:
            out("conversation", proto, lo, hi, c["frames"], c["bytes"],
                c["first"], c["last"], c["last"] - c["first"])
        out("end", "ok")
        return 0

    if a.mode == "extract":
        if extracted is None:
            err("frame %d not found in %s" % (a.frame, a.file))
            return 1
        idx, layer, blob = extracted
        out("extract", "frame", idx)
        out("extract", "layer", layer)
        out("extract", "len", len(blob))
        out("extract", "hex", binascii.hexlify(blob).decode().upper())
        return 0

    if a.mode == "identities":
        seen = set()
        for (idx, kind, value, proto, src, dst, where) in identities:
            key = (kind, value)
            if key in seen:
                # Keep the first sighting, note the frame it repeats in.
                continue
            seen.add(key)
            out("identity", idx, kind, value, proto, src, dst, where)
        out("end", "ok")
        return 0

    out("end", "ok")
    return 0


# ── identity scanning ───────────────────────────────────────────────────
# An IMSI/IMEI on the wire is BCD with the nibbles swapped, and it is
# carried as a length-prefixed field in a NAS/DTAP/S1AP IE. Rather than
# guess at every IE layout, the scanner looks for the encodings that are
# unambiguous:
#   * a length octet in 5..8 followed by that many BCD octets whose digits
#     decode to a plausible MCC, for IMSI
#   * an 8-octet BCD field for IMEI/IMEISV
#   * a 4-octet BCD field for TMSI/MSISDN in the DTAP IE encodings
# Anything found is reported with the byte offset so a human can confirm it.
def bcd_swap(b):
    s = ""
    for x in b:
        s += "%X%X" % (x & 0x0F, (x >> 4) & 0x0F)
    return s


def looks_like_imsi(digits):
    if len(digits) < 14 or len(digits) > 16:
        return False
    if not digits.isdigit():
        return False
    mcc = int(digits[0:3])
    # Real MCCs start 2..7 in the first digit. 0xx is the test network range
    # and is accepted because test captures use it.
    return digits[0] in "01234567" and mcc != 0


def find_identities(app, proto):
    """Return [(kind, value, where)] for a link-layer application payload.

    Both IMSI and IMEI travel as BCD with the nibbles swapped. Scanning for
    them by "8 bytes that look like BCD" produces a flood of false
    positives, so each candidate is validated against the real structure:

      IMSI  TS 24.008 10.5.1.4: length octet (5..8) then that many BCD
            octets. The first three digits are the MCC, which must be a
            plausible assigned value.
      IMEI  TS 24.008 10.5.1.4 / TS 23.003: 8 BCD octets giving a 15-digit
            IMEI or 16-digit IMEISV. The first two digits are the Reporting
            Body Identifier and must be one of the assigned values, and the
            final digit of an IMEI is the Luhn check digit.
    """
    res = []
    if not app:
        return res
    n = len(app)

    # ── IMSI: length-prefixed BCD ──────────────────────────────────────
    for i in range(0, n - 1):
        ln = app[i]
        if not (5 <= ln <= 8):
            continue
        if i + 1 + ln > n:
            continue
        digits = bcd_swap(app[i + 1:i + 1 + ln])
        # The odd-digit filler F lands in the LAST nibble after the swap,
        # whatever the byte count, so it is stripped by position rather
        # than by parity: a 15-digit IMSI in 8 BCD octets swaps to 16
        # characters ending in F, and a 16-digit IMSI swaps to 16 digits.
        if digits.endswith("F"):
            digits = digits[:-1]
        if not digits.isdigit():
            continue
        if not (14 <= len(digits) <= 16):
            continue
        if digits[0] not in "01234567":
            continue
        mcc = int(digits[0:3])
        if mcc in MCC_ASSIGNED:
            res.append(("imsi", digits, "length-prefixed BCD at offset %d" % i))

    # ── IMEI / IMEISV: 8 BCD octets ────────────────────────────────────
    for i in range(0, max(0, n - 7)):
        digits = bcd_swap(app[i:i + 8])
        if not digits.isdigit():
            continue
        # An IMEI's TAC begins with an assigned Reporting Body Identifier.
        # Without this gate every 8-byte run of BCD in a Diameter or SCTP
        # header is reported as an IMEI, which is pure noise.
        if digits[0:2] not in RBI_VALID:
            continue
        # IMEI is 15 digits whose last digit is the Luhn check digit. The
        # 16th digit, when present, is the IMEISV software version and the
        # check digit is then the 15th. Both readings are reported with the
        # one that validates, so a capture never yields a fabricated IMEI.
        if luhn_ok(digits[:15]):
            res.append(("imei", digits[:15], "8-octet BCD at offset %d" % i))
        elif luhn_ok(digits[:14] + digits[14]):
            res.append(("imeisv", digits, "8-octet BCD at offset %d" % i))

    # ── TMSI / GUTI: only meaningful inside an identity message ────────
    # The IE is 0xF4 (TMSI) or 0xF5 (IMEISV request) inside the 24.008
    # identity exchange. Reporting every 0xF4 byte in a capture would be
    # noise, so the surrounding protocol must be a NAS carrier.
    if proto in ("s1ap", "ngap", "m3ua", "gsmtap"):
        for i in range(0, max(0, n - 5)):
            if app[i] == 0xF4 and app[i + 1] == 0x04:
                res.append(("tmsi",
                            binascii.hexlify(app[i + 2:i + 6]).decode().upper(),
                            "TMSI IE at offset %d" % i))
    return res


# MCCs actually assigned (ITU-T E.212). A scan that accepts any three
# digits reports every BCD string in the capture as an IMSI, which is
# worse than reporting nothing.
MCC_ASSIGNED = {
    202, 204, 206, 208, 212, 213, 214, 216, 218, 219, 220, 221, 222, 226,
    228, 230, 231, 232, 234, 235, 238, 240, 242, 244, 246, 247, 248, 250,
    255, 256, 257, 259, 260, 262, 266, 267, 268, 270, 272, 274, 276, 278,
    280, 282, 283, 284, 286, 288, 289, 290, 292, 293, 294, 295, 297, 302,
    308, 310, 311, 312, 313, 314, 315, 316, 330, 332, 334, 338, 340, 342,
    344, 346, 348, 350, 352, 354, 356, 358, 360, 362, 363, 364, 365, 366,
    368, 370, 372, 374, 376, 400, 401, 402, 404, 405, 406, 410, 412, 413,
    414, 415, 416, 417, 418, 419, 420, 421, 422, 424, 425, 426, 427, 428,
    429, 430, 431, 432, 434, 436, 437, 438, 440, 441, 442, 450, 452, 454,
    455, 456, 457, 460, 461, 466, 467, 470, 472, 502, 505, 510, 514, 515,
    520, 525, 528, 530, 536, 537, 539, 540, 541, 542, 543, 544, 545, 546,
    547, 548, 549, 550, 551, 552, 553, 555, 602, 603, 604, 605, 606, 607,
    608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621,
    622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635,
    636, 637, 638, 639, 640, 641, 642, 643, 645, 646, 647, 648, 649, 650,
    651, 652, 653, 654, 655, 657, 658, 659, 660, 661, 662, 663, 664, 665,
    666, 667, 668, 670, 672, 674, 675, 676, 677, 678, 679, 680, 681, 682,
    683, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697,
    698, 699, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711,
    712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725,
    726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739,
    740, 741, 742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753,
    754, 755, 901,
}

# Reporting Body Identifiers assigned by the IMEI oversight bodies. The
# leading two digits of an IMEI TAC come from this set; anything else is
# not an IMEI and the byte string is a coincidence.
RBI_VALID = {
    "01", "02", "10", "30", "33", "35", "44", "45", "49", "50", "51",
    "52", "53", "54", "86", "91", "98", "99",
}


def luhn_ok(digits):
    """Luhn check digit validation, used by IMEI (TS 23.003 §6.2.1)."""
    if not digits.isdigit():
        return False
    total = 0
    # Doubling starts at the rightmost digit of the payload, which for a
    # check-digit-validated string is the second digit from the right.
    for idx, ch in enumerate(reversed(digits)):
        d = int(ch)
        if idx % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF
}

# Ensure the parser exists and matches the copy embedded in this module.
# The heredoc is emitted once to a temp file and compared with cmp, so the
# scratch copy is only replaced when the module actually changed. Using a
# byte count here would miss an edit that preserved the length.
pcap_ensure_parser() {
    mkdir -p "$MOD_TMP"
    local tmp="$MOD_TMP/.pcap_read.py.new"
    pcap_writer_py > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    [[ -s "$tmp" ]] || { rm -f "$tmp"; return 1; }
    if [[ ! -f "$MOD_TMP/pcap_read.py" ]] || ! cmp -s "$tmp" "$MOD_TMP/pcap_read.py"; then
        mv -f "$tmp" "$MOD_TMP/pcap_read.py" || { rm -f "$tmp"; return 1; }
    else
        rm -f "$tmp"
    fi
    [[ -s "$MOD_TMP/pcap_read.py" ]]
}

pcap_find_tshark() {
    command -v tshark >/dev/null 2>&1 && { echo "tshark"; return 0; }
    command -v wireshark >/dev/null 2>&1 && { echo "wireshark"; return 0; }
    return 1
}

# ── capture validation ──────────────────────────────────────────────────
pcap_check_file() {
    local f="${1:-}"
    [[ -n "$f" ]] || { printf 'ERROR\tno capture given\n' >&2; return 2; }
    [[ -f "$f" ]] || { printf 'ERROR\tno such capture: %s\n' "$f" >&2; return 1; }
    [[ -r "$f" ]] || { printf 'ERROR\tcapture not readable: %s\n' "$f" >&2; return 1; }
    [[ -s "$f" ]] || { printf 'ERROR\tcapture is empty: %s\n' "$f" >&2; return 1; }
    return 0
}

# Read the global header without python, so the magic check itself does not
# depend on the python fallback being correct.
pcap_magic_check() {
    local f="$1"
    local m
    m=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
    case "${m,,}" in
        d4c3b2a1) echo "pcap-le" ;;   # a1b2c3d4 stored LE, read back by od as the LE bytes of the value
        a1b2c3d4) echo "pcap-be" ;;
        4d3cb2a1) echo "pcap-ns-le" ;;
        a1b23c4d) echo "pcap-ns-be" ;;
        0a0d0d0a) echo "pcapng" ;;
        *)        echo "unknown" ;;
    esac
}

# ── backend dispatch: tshark when present, python always available ──────
pcap_run() {
    # Usage: pcap_run <mode> <file> [extra python args...]
    # The file is consumed here so it is never passed twice.
    local mode="$1"; shift
    local file="${1:-}"; shift || true
    pcap_check_file "$file" || return $?
    pcap_ensure_parser || {
        printf 'ERROR\tcannot write the fallback parser to %s\n' "$MOD_TMP/pcap_read.py" >&2
        return 1
    }
    python3 "$MOD_TMP/pcap_read.py" --mode "$mode" --file "$file" "$@"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
pcap_cli_status_tsv() {
    local ts python
    ts=$(pcap_find_tshark) || ts="none"
    python=$(command -v python3 >/dev/null 2>&1 && echo present || echo missing)
    printf 'tshark\t%s\n' "$(pcap_sanitize "$ts")"
    printf 'python3\t%s\n' "$python"
    printf 'fallback_parser\t%s\n' "$MOD_TMP/pcap_read.py"
    printf 'fallback_ready\t%s\n' "$([[ -s "$MOD_TMP/pcap_read.py" ]] && echo yes || echo no)"
    printf 'identities\t%s\n' "$PCAP_IDENT"
    printf 'identity_count\t%s\n' "$(pcap_identity_count)"
    printf 'captures_dir\t%s\n' "$CAPTURES_DIR"
    printf 'capture_count\t%s\n' "$(find "$CAPTURES_DIR" -maxdepth 1 -type f \
        \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) 2>/dev/null | wc -l | tr -d ' ')"
    printf 'dir\t%s\n' "$PCAP_DIR"
}

pcap_identity_count() {
    [[ -f "$PCAP_IDENT" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$PCAP_IDENT" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# Global-header summary: format, byte order, link type, record count. This
# is the verb a caller uses to decide whether the file is even a capture,
# and it must work with no tshark.
pcap_cmd_summary() {
    local f="${1:-}"
    pcap_check_file "$f" || return $?
    local magic; magic=$(pcap_magic_check "$f")
    printf 'file\t%s\n' "$(pcap_sanitize "$f")"
    printf 'size\t%s\n' "$(wc -c < "$f" | tr -d ' ')"
    printf 'magic_class\t%s\n' "$magic"
    case "$magic" in
        unknown) printf 'ERROR\t%s is not a pcap or pcapng capture\n' "$f" >&2; return 1 ;;
    esac
    pcap_run summary "$f" || return 1
    # Identity inventory is the other half of a useful summary.
    local nid; nid=$(pcap_identity_count)
    printf 'identities_known\t%s\n' "$nid"
}

pcap_cmd_list() {
    local f="${1:-}" limit="${2:-0}"
    [[ "$limit" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlimit must be a number\n' >&2; return 2; }
    pcap_check_file "$f" || return $?
    pcap_run list "$f" --limit "$limit"
}

pcap_cmd_hierarchy() {
    local f="${1:-}"
    pcap_check_file "$f" || return $?
    pcap_run hierarchy "$f"
}

pcap_cmd_conversations() {
    local f="${1:-}"
    pcap_check_file "$f" || return $?
    pcap_run conversations "$f"
}

pcap_cmd_extract() {
    local f="${1:-}" frame="${2:-}" layer="${3:-}"
    [[ -n "$f" && -n "$frame" && -n "$layer" ]] || {
        printf 'ERROR\tusage: --extract <pcap> <frame> <layer>\n' >&2; return 2; }
    [[ "$frame" =~ ^[0-9]+$ ]] || { printf 'ERROR\tframe must be a number\n' >&2; return 2; }
    pcap_check_file "$f" || return $?
    pcap_run extract "$f" --frame "$frame" --layer "$layer"
}

pcap_ident_load() {
    # Harvest identities into the loot store and print the rows found. The
    # row shape is what module 18 consumes:
    #   file  frame  kind  value  protocol  src  dst  where
    local f="${1:-}" tmp
    pcap_check_file "$f" || return $?
    tmp=$(mktemp "$MOD_TMP/ident.XXXXXX") || return 1
    pcap_run identities "$f" > "$tmp" || { rm -f "$tmp"; return 1; }
    pcap_init_store
    local n=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pcap_split "$line"
        [[ "${PCAP_F[0]:-}" == "identity" ]] || continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(pcap_sanitize "$f")" "$(pcap_sanitize "${PCAP_F[1]:-}")" \
            "$(pcap_sanitize "${PCAP_F[2]:-}")" "$(pcap_sanitize "${PCAP_F[3]:-}")" \
            "$(pcap_sanitize "${PCAP_F[4]:-}")" "$(pcap_sanitize "${PCAP_F[5]:-}")" \
            "$(pcap_sanitize "${PCAP_F[6]:-}")" "$(pcap_sanitize "${PCAP_F[7]:-}")" >> "$PCAP_IDENT"
        n=$(( n + 1 ))
    done < "$tmp"
    rm -f "$tmp"
    # Print the harvested rows themselves so the caller can consume them
    # directly, then the counters. A verb that only prints a count forces
    # every consumer to re-read the store.
    printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n'
    tail -n +2 "$PCAP_IDENT"
    printf 'summary\tidentities\t%s\n' "$n"
}

pcap_cmd_identities() {
    local f="${1:-}"
    if [[ -z "$f" ]]; then
        [[ -f "$PCAP_IDENT" ]] || { printf 'ERROR\tno identity store; run --identities on a capture\n' >&2; return 1; }
        printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n'
        tail -n +2 "$PCAP_IDENT"
        return 0
    fi
    pcap_check_file "$f" || return $?
    pcap_ident_load "$f"
}

pcap_cmd_ident_list() {
    [[ -f "$PCAP_IDENT" ]] || { printf 'ERROR\tno identity store; run --identities on a capture\n' >&2; return 1; }
    local n; n=$(pcap_identity_count)
    (( n > 0 )) || { printf 'ERROR\tidentity store is empty\n' >&2; return 1; }
    printf 'kind\tvalue\tprotocol\tframes\tfile\n'
    tail -n +2 "$PCAP_IDENT" | awk -F'\t' '
        { key = $3 "\t" $4 "\t" $5
          if (!(key in seen)) { seen[key] = $2; order[++n] = key }
          last[key] = $2
          cnt[key]++ }
        END { for (i = 1; i <= n; i++) {
                  k = order[i]
                  printf "%s\t%s\t%s\t%s\n", k, cnt[k], seen[k] ".." last[k], ""
              } }'
}

pcap_cmd_clear() {
    pcap_init_store
    printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n' > "$PCAP_IDENT"
    ok "identity store cleared"
}

pcap_init_store() {
    mkdir -p "$PCAP_DIR"
    [[ -f "$PCAP_IDENT" ]] || printf 'file\tframe\tkind\tvalue\tprotocol\tsrc\tdst\twhere\n' > "$PCAP_IDENT"
}

# ── synthetic capture builder (used by the selftest) ────────────────────
# Builds a real little-endian pcap with a hand-written global header and
# two records: a GSMTAP/UDP frame and a Diameter/SCTP frame. Kept in the
# module (not the selftest) because a "make me a test capture" path is
# genuinely useful when checking a new dissector.
pcap_build_sample() {
    local out="${1:-}"
    [[ -n "$out" ]] || { printf 'ERROR\tusage: --build-sample <out.pcap>\n' >&2; return 2; }
    pcap_ensure_parser >/dev/null 2>&1
    python3 - "$out" << 'PYEOF'
import struct, sys, binascii

path = sys.argv[1]

def eth_ip_udp(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 17, 0,
                     bytes(int(x) for x in src.split(".")),
                     bytes(int(x) for x in dst.split(".")))
    eth = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
    return eth + ip + udp

def eth_ip_sctp(src, dst, sport, dport, ppid, payload):
    # SCTP common header: sport dport vtag csum(4) -- checksum forced 0.
    sctp = struct.pack(">HHII", sport, dport, 0x00000001, 0) 
    # One DATA chunk: type 0, flags 0x03 (B|E), len, TSN, sid, ssn, ppid, data
    data = payload
    clen = 16 + len(data)
    chunk = struct.pack(">BBHIIHH", 0, 0x03, clen, 0x00000001, 0, 0, ppid) + data
    chunk += b"\x00" * ((4 - clen % 4) % 4)
    sctp += chunk
    total = 20 + len(sctp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1235, 0, 64, 132, 0,
                     bytes(int(x) for x in src.split(".")),
                     bytes(int(x) for x in dst.split(".")))
    eth = b"\x02\x00\x00\x00\x00\x03\x02\x00\x00\x00\x00\x04\x08\x00"
    return eth + ip + sctp

# GSMTAP: version 2, hdr_len 4, type 1 (BCCH), timeslot 0, arfcn 42,
# signal -70 dBm, snr 25, then a 4-byte "L3" body.
gsmtap = struct.pack(">BBBBHbb", 0x02, 4, 1, 0, 42, -70, 25) + b"\x00\x01\x02\x03"
f1 = eth_ip_udp("10.0.0.1", "10.0.0.2", 40000, 4729, gsmtap)

# Diameter header: version 1, length, flags 0x80 (request), cmd 316 (UER),
# app id 16777251 (S6a), hop id, end-to-end id, then an IMSI AVP body.
diam_body = b"\x00\x00\x01\x0a" + b"\x00\x00\x00\x01" + b"\x01\x02\x03\x04\x05\x06\x07\x08"
diam = struct.pack(">B3sB3sII", 1, struct.pack(">I", 20 + len(diam_body))[1:], 0x80,
                   struct.pack(">I", 316)[1:], 16777251, 0x00000001) + \
       struct.pack(">II", 0x00000002, 0x00000003) + diam_body
f2 = eth_ip_sctp("10.0.0.3", "10.0.0.4", 30000, 3868, 46, diam)

with open(path, "wb") as fh:
    # Little-endian magic 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0,
    # snaplen 262144, linktype 1 (Ethernet).
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for i, frame in enumerate((f1, f2)):
        fh.write(struct.pack("<IIII", 1700000000 + i, i * 1000, len(frame), len(frame)))
        fh.write(frame)
print("wrote %s" % path)
PYEOF
}

# ── selftest — no tshark required, no network, no root ──────────────────
pcap_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    # Two output shapes reach this helper:
    #   python parser rows   "<record-type>\t<key>\t<value>"
    #   status-tsv rows      "<key>\t<value>"
    # so match field 2 first and fall back to field 1.
    fld() {
        printf '%s\n' "$1" | awk -F'\t' -v k="$2" '
            $2==k { print $3; found=1; exit }
            $1==k && NF>=2 { print $2; found=1; exit }
            END { if (!found) exit 1 }'
    }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export PCAP_DIR="$d/loot/pcap_analysis"
    export PCAP_IDENT="$PCAP_DIR/identities.tsv"
    mkdir -p "$PCAP_DIR" "$CAPTURES_DIR"

    # Build the synthetic capture by hand: a real global header plus two
    # records. Written with python's struct so the layout is exact.
    local pcap="$d/sample.pcap"
    pcap_build_sample "$pcap" >/dev/null 2>&1
    chk sample-exists "$([[ -s "$pcap" ]] && echo yes || echo no)" "yes"

    # ── 1. Global header: magic, byte order, link type, snaplen ─────────
    # a1 b2 c3 d4 in file order means the value 0xa1b2c3d4 stored little-endian,
    # which is a native little-endian capture (NOT swapped).
    local m
    m=$(od -An -tx1 -N4 "$pcap" | tr -d ' \n')
    chk magic-bytes    "${m,,}" "d4c3b2a1"
    chk magic-class    "$(pcap_magic_check "$pcap")" "pcap-le"
    chk header-version "$(od -An -tu4 -j4 -N4 "$pcap" | tr -s ' ' | sed 's/^ //')" "262146"

    out=$(pcap_run summary "$pcap"); rc=$?
    chk summary-rc       "$rc" "0"
    chk summary-format   "$(fld "$out" format)"       "pcap"
    chk summary-magic    "$(fld "$out" magic)"        "0xa1b2c3d4"
    chk summary-order    "$(fld "$out" byte_order)"   "little-endian"
    chk summary-swapped  "$(fld "$out" swapped)"      "no"
    chk summary-linktype "$(fld "$out" linktype)"     "1"
    chk summary-linkname "$(fld "$out" linktype_name)" "Ethernet"
    chk summary-snaplen  "$(fld "$out" snaplen)"      "262144"
    chk summary-frames   "$(awk -F'\t' '$1=="summary" && $2=="frames"{print $3}' <<<"$out")" "2"
    chk summary-proto-count "$(awk -F'\t' '$1=="summary" && $2=="protocols_seen"{print $3}' <<<"$out")" "5"

    # ── 2. The payload offset is exactly where the record says ──────────
    # Record 0 header starts at byte 24; its 16-byte header is
    # ts_sec(4) ts_usec(4) incl_len(4) orig_len(4), so the frame payload
    # starts at byte 40.
    local rec0
    rec0=$(od -An -tu4 -j24 -N16 "$pcap" | tr -s ' ' | sed 's/^ //;s/ $//')
    chk rec0-header      "$rec0" "1700000000 0 54 54"
    # The frame payload starts at byte 40 (24-byte global header + 16-byte
    # record header). Layout: Ethernet(14) IPv4(20) UDP(8) then GSMTAP.
    local fo=40
    chk rec0-ethertype "$(od -An -tu1 -j$(( fo + 12 )) -N2 "$pcap" | tr -s ' ' | sed 's/^ //')" "8 0"
    chk rec0-ipproto   "$(od -An -tu1 -j$(( fo + 14 + 9 )) -N1 "$pcap" | tr -d ' \n')" "17"
    # UDP source/destination ports are big-endian: 40000 = 0x9C40 -> 156 64,
    # and 4729 = 0x1279 -> 18 121.
    chk rec0-srcport   "$(od -An -tu1 -j$(( fo + 14 + 20 + 0 )) -N2 "$pcap" | tr -s ' ' | sed 's/^ //')" "156 64"
    chk rec0-dstport   "$(od -An -tu1 -j$(( fo + 14 + 20 + 2 )) -N2 "$pcap" | tr -s ' ' | sed 's/^ //')" "18 121"
    # GSMTAP payload begins at 40 + 14 + 20 + 8 = 82: version 2, header
    # length 4, type 1, timeslot 0, arfcn 42 (big-endian), then 2 bytes.
    chk rec0-gsmtap-ver "$(od -An -tu1 -j$(( fo + 42 )) -N1 "$pcap" | tr -d ' \n')" "2"
    chk rec0-gsmtap-hdr "$(od -An -tu1 -j$(( fo + 43 )) -N1 "$pcap" | tr -d ' \n')" "4"
    chk rec0-gsmtap-typ "$(od -An -tu1 -j$(( fo + 44 )) -N1 "$pcap" | tr -d ' \n')" "1"
    chk rec0-gsmtap-arfcn "$(od -An -tu1 -j$(( fo + 46 )) -N2 "$pcap" | tr -s ' ' | sed 's/^ //')" "0 42"

    # ── 3. Frame listing: ports, protocols, lengths ─────────────────────
    out=$(pcap_run list "$pcap"); rc=$?
    chk list-rc     "$rc" "0"
    chk list-rows   "$(printf '%s\n' "$out" | grep -c '^frame')" "2"
    local row1 row2
    row1=$(printf '%s\n' "$out" | grep '^frame' | sed -n '1p')
    row2=$(printf '%s\n' "$out" | grep '^frame' | sed -n '2p')
    # Columns: 1=frame 2=index 3=ts 4=src 5=dst 6=sport 7=dport 8=l4
    #          9=proto 10=incl_len 11=orig_len 12=detail
    chk list-f1-src      "$(cut -f4 <<<"$row1")" "10.0.0.1"
    chk list-f1-dst      "$(cut -f5 <<<"$row1")" "10.0.0.2"
    chk list-f1-srcport  "$(cut -f6 <<<"$row1")" "40000"
    chk list-f1-dstport  "$(cut -f7 <<<"$row1")" "4729"
    chk list-f1-l4       "$(cut -f8 <<<"$row1")" "UDP"
    chk list-f1-proto    "$(cut -f9 <<<"$row1")" "gsmtap"
    chk list-f1-len      "$(cut -f10 <<<"$row1")" "54"
    chk list-f1-arfcn    "$(cut -f12 <<<"$row1" | grep -o 'arfcn=42')" "arfcn=42"
    chk list-f1-signal   "$(cut -f12 <<<"$row1" | grep -o 'signal_dbm=-70')" "signal_dbm=-70"
    chk list-f1-ver      "$(cut -f12 <<<"$row1" | grep -o 'gsmtap_ver=2')" "gsmtap_ver=2"
    chk list-f2-l4       "$(cut -f8 <<<"$row2")" "SCTP"
    chk list-f2-proto    "$(cut -f9 <<<"$row2")" "diameter"
    chk list-f2-ppid     "$(cut -f12 <<<"$row2" | grep -o 'ppid=46')" "ppid=46"
    chk list-f2-msgtype  "$(cut -f12 <<<"$row2" | grep -o 'diameter_ver=1')" "diameter_ver=1"
    # A limit must truncate the listing without failing.
    chk list-limit "$(pcap_run list "$pcap" --limit 1 | grep -c '^frame')" "1"

    out=$(pcap_run hierarchy "$pcap")
    chk hier-rows      "$(printf '%s\n' "$out" | grep -c '^hierarchy')" "$(( $(printf '%s\n' "$out" | grep -c '^hierarchy') ))"
    chk hier-has-ipv4  "$(printf '%s\n' "$out" | grep -c $'^hierarchy\tIPv4\t')" "1"
    chk hier-ipv4-n    "$(awk -F'\t' '$1=="hierarchy" && $2=="IPv4"{print $3}' <<<"$out")" "2"
    chk hier-has-sctp  "$(printf '%s\n' "$out" | grep -c $'^hierarchy\tSCTP\t')" "1"
    chk hier-has-udp   "$(printf '%s\n' "$out" | grep -c $'^hierarchy\tUDP\t')" "1"
    chk hier-diam-n    "$(awk -F'\t' '$1=="hierarchy" && $2=="diameter"{print $3}' <<<"$out")" "1"
    chk hier-gsmtap-n  "$(awk -F'\t' '$1=="hierarchy" && $2=="gsmtap"{print $3}' <<<"$out")" "1"

    out=$(pcap_run conversations "$pcap")
    chk conv-rows   "$(printf '%s\n' "$out" | grep -c '^conversation')" "2"
    chk conv-gsmtap "$(printf '%s\n' "$out" | grep -c $'^conversation\tgsmtap')" "1"
    chk conv-diam   "$(printf '%s\n' "$out" | grep -c $'^conversation\tdiameter')" "1"
    # The GSMTAP conversation must name both endpoints with their ports.
    chk conv-endpoints "$(printf '%s\n' "$out" | grep $'^conversation\tgsmtap' | grep -c '10.0.0.1:40000')" "1"
    chk conv-frames    "$(awk -F'\t' '$1=="conversation" && $2=="gsmtap"{print $5}' <<<"$out")" "1"
    chk conv-bytes-nonzero "$(awk -F'\t' '$1=="conversation" && $2=="gsmtap"{print ($6>0)?"y":"n"}' <<<"$out")" "y"

    # ── 4. Layer extraction feeds another module's decoder ──────────────
    out=$(pcap_run extract "$pcap" --frame 1 --layer gsmtap); rc=$?
    chk extract-rc    "$rc" "0"
    chk extract-frame "$(fld "$out" frame)" "1"
    chk extract-layer "$(fld "$out" layer)" "gsmtap"
    chk extract-len   "$(fld "$out" len)"   "12"
    chk extract-hex   "$(fld "$out" hex)"   "02040100002ABA1900010203"
    out=$(pcap_run extract "$pcap" --frame 2 --layer diameter)
    chk extract-diam-layer "$(fld "$out" layer)" "diameter"
    chk extract-diam-len   "$(fld "$out" len)"   "40"
    chk extract-diam-hex   "$(fld "$out" hex | cut -c1-8)" "01000024"
    # Extracting a layer the frame does not carry must fail, not print hex.
    chk extract-missing-rc "$(pcap_run extract "$pcap" --frame 1 --layer diameter >/dev/null 2>&1; echo $?)" "1"
    chk extract-badframe-rc "$(pcap_run extract "$pcap" --frame 99 --layer gsmtap >/dev/null 2>&1; echo $?)" "1"
    chk extract-badlayer-rc "$(pcap_run extract "$pcap" --frame 1 --layer nosuchlayer >/dev/null 2>&1; echo $?)" "1"

    # ── 5. Byte-swapped (big-endian) capture detection ──────────────────
    # Write a big-endian global header claiming link type 1 and zero records.
    # A big-endian capture stores the magic 0xa1b2c3d4 as the bytes
    # a1 b2 c3 d4; read back as little-endian that is 0xd4c3b2a1. Reading
    # the first four bytes as little-endian is exactly how the sniff works,
    # so the file must start with a1 b2 c3 d4 for a big-endian file.
    local be="$d/bigendian.pcap"
    python3 - "$be" << 'PYBE'
import struct, sys
# Version 2.4, thiszone 0, sigfigs 0, snaplen 262144, linktype 1, no records.
open(sys.argv[1], "wb").write(
    struct.pack(">IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
PYBE
    chk be-magic-bytes "$(od -An -tx1 -N4 "$be" | tr -d ' \n')" "a1b2c3d4"
    out=$(pcap_run summary "$be"); rc=$?
    chk be-rc      "$rc" "0"
    chk be-order   "$(fld "$out" byte_order)" "big-endian"
    chk be-swapped "$(fld "$out" swapped)"    "yes"
    chk be-linktype "$(fld "$out" linktype)"  "1"
    chk be-snaplen  "$(fld "$out" snaplen)"   "262144"
    chk be-frames   "$(awk -F'\t' '$1=="summary" && $2=="frames"{print $3}' <<<"$out")" "0"

    # ── 6. A byte-swapped capture's record count must still be right ────
    # Same two frames, header and records written big-endian.
    local be2="$d/bigendian2.pcap"
    python3 - "$pcap" "$be2" << 'PYEOF'
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = open(src, "rb").read()
magic, vmaj, vmin, tz, sig, snap, net = struct.unpack("<IHHiIII", d[0:24])
# Write the global header in the SAME byte order as the file magic: a
# big-endian capture begins a1 b2 c3 d4 and every field is big-endian.
out = bytearray(struct.pack(">IHHiIII", 0xa1b2c3d4, vmaj, vmin, tz, sig, snap, net))
off = 24
while off + 16 <= len(d):
    sec, usec, incl, orig = struct.unpack("<IIII", d[off:off+16])
    body = d[off+16:off+16+incl]
    out += struct.pack(">IIII", sec, usec, incl, orig) + body
    off += 16 + incl
open(dst, "wb").write(bytes(out))
PYEOF
    out=$(pcap_run summary "$be2")
    chk be2-swapped "$(fld "$out" swapped)" "yes"
    chk be2-frames  "$(awk -F'\t' '$1=="summary" && $2=="frames"{print $3}' <<<"$out")" "2"
    chk be2-ts      "$(awk -F'\t' '$1=="summary" && $2=="first_ts"{print $3}' <<<"$out")" "1700000000"
    out=$(pcap_run list "$be2")
    chk be2-list-proto "$(printf '%s\n' "$out" | grep '^frame' | sed -n '1p' | cut -f9)" "gsmtap"
    chk be2-list-port  "$(printf '%s\n' "$out" | grep '^frame' | sed -n '1p' | cut -f7)" "4729"

    # ── 7. A malformed capture must fail with a clear error ─────────────
    local junk="$d/junk.bin"
    printf 'this is not a capture at all, it is a text file\n' > "$junk"
    out=$(pcap_run summary "$junk" 2>&1); rc=$?
    chk junk-rc     "$rc" "1"
    chk junk-error  "$(printf '%s\n' "$out" | grep -c 'not a pcap or pcapng')" "1"

    # A file shorter than a global header.
    local tiny="$d/tiny.pcap"
    printf '\xd4\xc3' > "$tiny"
    chk tiny-rc    "$(pcap_run summary "$tiny" >/dev/null 2>&1; echo $?)" "1"
    # An empty file.
    : > "$d/empty.pcap"
    chk empty-rc   "$(pcap_check_file "$d/empty.pcap" >/dev/null 2>&1; echo $?)" "1"
    # A valid header with a truncated final record.
    local trunc="$d/trunc.pcap"
    head -c 60 "$pcap" > "$trunc"
    out=$(pcap_run summary "$trunc" 2>&1)
    chk trunc-warns "$(printf '%s\n' "$out" | grep -c 'truncated')" "1"
    # A non-existent path.
    chk nofile-rc  "$(pcap_check_file /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk nonum-rc   "$(pcap_run summary >/dev/null 2>&1; echo $?)" "2"

    # ── 8. Identity harvest ─────────────────────────────────────────────
    # Build a capture carrying a length-prefixed BCD IMSI in a Diameter AVP
    # so the scanner has something real to find.
    local idp="$d/ident.pcap"
    python3 - "$idp" << 'PYEOF'
import struct, sys
path = sys.argv[1]
# IMSI 310260123456789 -> length byte 08, body 13 20 06 21 43 65 87 F9
imsi_field = b"\x08" + bytes.fromhex("13200621436587F9")
# Diameter-ish payload: header + the IMSI field inside an AVP body.
body = b"\x00\x00\x01\x0a" + b"\x00\x00\x00\x01" + imsi_field
payload = struct.pack(">B3sB3sII", 1, struct.pack(">I", 20+len(body))[1:], 0x80,
                      struct.pack(">I", 316)[1:], 16777251, 1) + \
          struct.pack(">II", 2, 3) + body
sctp = struct.pack(">HHII", 30000, 3868, 1, 0)
clen = 16 + len(payload)
sctp += struct.pack(">BBHIIHH", 0, 3, clen, 1, 0, 0, 46) + payload
sctp += b"\x00" * ((4 - clen % 4) % 4)
ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20+len(sctp), 0x1235, 0, 64, 132, 0,
                 bytes([10,0,0,3]), bytes([10,0,0,4]))
eth = b"\x02\x00\x00\x00\x00\x03\x02\x00\x00\x00\x00\x04\x08\x00"
frame = eth + ip + sctp
with open(path, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    fh.write(struct.pack("<IIII", 1700000100, 0, len(frame), len(frame)))
    fh.write(frame)
PYEOF
    out=$(pcap_cmd_identities "$idp"); rc=$?
    chk ident-rc     "$rc" "0"
    chk ident-found  "$(awk -F'\t' '$1=="summary" && $2=="identities"{print $3}' <<<"$out")" "1"
    chk ident-rows   "$(printf '%s\n' "$out" | grep -c $'^/')" "1"
    local irow; irow=$(printf '%s\n' "$out" | grep $'\timsi\t' | head -n1)
    chk ident-kind   "$(cut -f3 <<<"$irow")" "imsi"
    chk ident-value  "$(cut -f4 <<<"$irow")" "310260123456789"
    chk ident-proto  "$(cut -f5 <<<"$irow")" "diameter"
    chk ident-frame  "$(cut -f2 <<<"$irow")" "1"
    chk ident-file   "$(cut -f1 <<<"$irow")" "$idp"
    chk ident-store  "$(pcap_identity_count)" "1"
    chk ident-header "$(head -n1 "$PCAP_IDENT" | awk -F'\t' '{print NF}')" "8"
    chk ident-row-fields "$(tail -n1 "$PCAP_IDENT" | awk -F'\t' '{print NF}')" "8"
    # The sample capture carries no identity, so it must report zero rather
    # than inventing one.
    out=$(pcap_cmd_identities "$pcap")
    chk ident-none "$(awk -F'\t' '$1=="summary" && $2=="identities"{print $3}' <<<"$out")" "0"

    # ── 9. tshark is optional — assert the fallback is what we tested ───
    # The parser is pure python with no third-party imports, so it runs
    # even with tshark uninstalled.
    chk fallback-has-no-scapy "$(grep -c '^import scapy\|^from scapy' "$MOD_TMP/pcap_read.py")" "0"
    chk fallback-has-no-tshark "$(grep -c 'tshark' "$MOD_TMP/pcap_read.py")" "0"
    chk fallback-imports "$(grep -c '^import struct' "$MOD_TMP/pcap_read.py")" "1"
    chk fallback-runs "$(python3 "$MOD_TMP/pcap_read.py" --mode summary --file "$pcap" | grep -c '^summary')" "6"

    # ── 10. Argument validation ─────────────────────────────────────────
    chk cmd-summary-missing "$(pcap_cmd_summary >/dev/null 2>&1; echo $?)" "2"
    chk cmd-list-missing    "$(pcap_cmd_list >/dev/null 2>&1; echo $?)" "2"
    chk cmd-list-badlimit   "$(pcap_cmd_list "$pcap" abc >/dev/null 2>&1; echo $?)" "2"
    chk cmd-hier-missing    "$(pcap_cmd_hierarchy >/dev/null 2>&1; echo $?)" "2"
    chk cmd-conv-missing    "$(pcap_cmd_conversations >/dev/null 2>&1; echo $?)" "2"
    chk cmd-extract-partial "$(pcap_cmd_extract "$pcap" 1 >/dev/null 2>&1; echo $?)" "2"
    chk cmd-extract-badnum  "$(pcap_cmd_extract "$pcap" abc gsmtap >/dev/null 2>&1; echo $?)" "2"
    # With a file: harvest. Without: list the store. With neither and an
    # empty store: an error, never an empty success.
    chk cmd-ident-nofile "$(PCAP_IDENT="$d/nostore.tsv" pcap_cmd_identities >/dev/null 2>&1; echo $?)" "1"
    chk dispatch-unknown    "$(pcap_cli_main --nonsense >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-empty      "$(pcap_cli_main >/dev/null 2>&1; echo $?)" "2"
    chk cmd-nofile          "$(pcap_cmd_summary /nope.pcap >/dev/null 2>&1; echo $?)" "1"

    # ── 11. Sanitisation: a tab in a capture-derived string ─────────────
    local evil
    evil=$(pcap_sanitize $'evil\tname\r\nsecond')
    chk sanitize-no-tabs "$(printf '%s' "$evil" | tr -d '\t\r\n' | wc -c | tr -d ' ')" \
        "$(printf '%s' "$evil" | wc -c | tr -d ' ')"

    # ── 12. Status TSV contract ─────────────────────────────────────────
    out=$(pcap_cli_status_tsv)
    chk status-dir      "$(fld "$out" dir)"            "$PCAP_DIR"
    chk status-ident    "$(fld "$out" identities)"     "$PCAP_IDENT"
    chk status-fallback "$(fld "$out" fallback_parser)" "$MOD_TMP/pcap_read.py"
    chk status-python   "$(fld "$out" python3)"        "present"
    chk status-count    "$(fld "$out" identity_count)" "1"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
pcap_menu() {
    local c p
    while true; do
        banner
        echo -e "  ${C_MAG}=== capture analysis ===${C_RESET}"
        echo -e "  tshark: ${C_GRN}$(pcap_find_tshark || echo none)${C_RESET}"
        echo -e "  parser: ${C_DIM}python3 fallback${C_RESET}"
        echo -e "  loot:   ${C_DIM}$PCAP_DIR${C_RESET}\n"
        cat << 'M'
  [1]  summarize a capture (format, link type, frames)
  [2]  list frames
  [3]  protocol hierarchy
  [4]  conversations
  [5]  extract a layer's hex from a frame
  [6]  harvest identities (IMSI/IMEI/TMSI) into loot
  [7]  show the harvested identity store
  [8]  build a synthetic sample capture
  [9]  clear the identity store
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) read -rp "  pcap path> " p
               pcap_cmd_summary "$p" | column -t -s$'\t' 2>/dev/null || pcap_cmd_summary "$p"
               read -rp "  press enter " _ ;;
            2) read -rp "  pcap path> " p; read -rp "  limit (0=all)> " l
               pcap_cmd_list "$p" "$l" | column -t -s$'\t' 2>/dev/null || pcap_cmd_list "$p" "$l"
               read -rp "  press enter " _ ;;
            3) read -rp "  pcap path> " p
               pcap_cmd_hierarchy "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            4) read -rp "  pcap path> " p
               pcap_cmd_conversations "$p" | column -t -s$'\t' 2>/dev/null || pcap_cmd_conversations "$p"
               read -rp "  press enter " _ ;;
            5) read -rp "  pcap path> " p
               read -rp "  frame> " n
               read -rp "  layer (gsmtap|diameter|s1ap|ngap|gtpu|pfcp|rtp|app|l4|l3|raw)> " y
               pcap_cmd_extract "$p" "$n" "$y" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            6) read -rp "  pcap path> " p
               pcap_cmd_identities "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            7) pcap_cmd_ident_list | column -t -s$'\t' 2>/dev/null || pcap_cmd_ident_list
               read -rp "  press enter " _ ;;
            8) read -rp "  output path> " p
               pcap_build_sample "$p"
               read -rp "  press enter " _ ;;
            9) pcap_cmd_clear; sleep 1 ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
pcap_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    pcap_cli_status_tsv ;;
        --summary)       pcap_cmd_summary "${1:-}" ;;
        --list)          pcap_cmd_list "${1:-}" "${2:-0}" ;;
        --hierarchy)     pcap_cmd_hierarchy "${1:-}" ;;
        --conversations) pcap_cmd_conversations "${1:-}" ;;
        --extract)       pcap_cmd_extract "${1:-}" "${2:-}" "${3:-}" ;;
        --identities)    pcap_cmd_identities "${1:-}" ;;
        --ident-list)    pcap_cmd_ident_list ;;
        --build-sample)  pcap_build_sample "${1:-}" ;;
        --clear)         pcap_cmd_clear ;;
        --selftest)      pcap_selftest ;;
        --menu)          pcap_menu ;;
        *)
            cat >&2 <<EOF
Capture Analysis — pcap/pcapng dissection for cellular protocols

Works with or without tshark. Without it, a built-in classic-pcap and
pcapng reader plus an Ethernet/IP/UDP/TCP/SCTP walker is used, so a bare
machine can still read a capture.

Usage: $0 COMMAND
  --status-tsv                  backend and store state as TSV
  --summary <pcap>              global header, frame count, link type
  --list <pcap> [limit]         one row per frame
  --hierarchy <pcap>            protocol hierarchy counts
  --conversations <pcap>        endpoints, frames and bytes per conversation
  --extract <pcap> <frame> <layer>
                                a layer's hex, for another decoder
  --identities <pcap>           harvest IMSI/IMEI/TMSI into loot and report
  --ident-list                  the harvested identity store, deduplicated
  --build-sample <out.pcap>     write a small synthetic capture
  --clear                       empty the identity store
  --selftest                    verify the fallback parser (no tshark needed)
  --menu                        interactive menu

Protocols recognised: GSMTAP (UDP 4729), SCTP (IP 132) with Diameter
(ppid 46), NGAP (ppid 60), S1AP (ppid 18) and MAP over M3UA (ppid 3),
GTP-C (2123), GTP-U (2152), PFCP (8805) and RTP for VoLTE.
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
    pcap_cli_main "$@"
fi
