#!/usr/bin/env python3
"""A MAP peer that answers, so an SS7 dialogue can close.

Why this exists
---------------
``26_ss7_map`` could build a SendRoutingInfo request and read an answer, but
nothing in the tree produced an answer, so no dialogue ever completed: with a
real Signalling Transfer Point the DATA went in and came back as "no route",
because a switchboard forwards and never replies. This is the far side -- an ASP
that announces itself over M3UA, takes the request off the wire, and answers it.

Where the answer comes from
---------------------------
The MAP parameter is encoded by **pycrate**, not by this tree. That is deliberate:
a responder that reused ``--build-response``'s encoder would agree with the
module by construction and prove nothing, which is the exact trap the GTPv2
padding bug set. The transport around the parameter is the module's own
(``--build-response --parameter``), because those layers are already refereed by
tshark and duplicating them here would only add a second thing to get wrong.

What it does not do
-------------------
No AKA, no authentication, no subscriber data beyond a table of
MSISDN -> IMSI/VMSC. It answers routing queries; it is a lab peer, not an HLR.
"""
import argparse, json, os, re, socket, struct, subprocess, sys, time

PPID_M3UA = 132
M3UA_MGMT, M3UA_TRANSFER, M3UA_ASPSM, M3UA_ASPTM = 0, 1, 3, 4
T_ASPUP, T_ASPDN, T_BEAT, T_ASPUP_ACK, T_ASPDN_ACK, T_BEAT_ACK = 1, 2, 3, 4, 5, 6
T_ASPAC, T_ASPIA, T_ASPAC_ACK, T_ASPIA_ACK = 1, 2, 3, 4
T_DATA = 1
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.path.join(ROOT, "modules", "26_ss7_map.sh")
ORACLE_PY = os.environ.get("SS7_ORACLE_PY", "/home/ysl/.lte-oracles/venv/bin/python")


def log(*row):
    print("\t".join(str(c) for c in row), flush=True)


SCTP_SNDINFO = 2          # the cmsg type; python's socket module does not export it


def sndinfo(sid, flags, ppid):
    """struct sctp_sndinfo: the PPID is in NETWORK byte order (the kernel keeps it
    that way and returns it the same way in sctp_rcvinfo, which is why readers
    call ntohl). Packing it little-endian put 0x03000000 on the wire."""
    return struct.pack("<HH", sid, flags) + struct.pack(">I", ppid) + struct.pack("<II", 0, 0)


def send_m3ua(sock, payload):
    sock.sendmsg([payload], [(socket.IPPROTO_SCTP, SCTP_SNDINFO, sndinfo(0, 0, PPID_M3UA))])


def recv_m3ua(sock, limit=262144):
    return sock.recvmsg(limit, 4096)[0]


def m3ua(cls, mtype, params=()):
    body = b"".join(params)
    return struct.pack(">BBHI", 1, 0, 8 + len(body), cls << 8 | mtype) + body


def param(tag, value):
    pad = (4 - len(value) % 4) % 4
    return struct.pack(">HH", tag, 4 + len(value)) + value + b"\x00" * pad


def params_of(msg):
    out, off = [], 8
    while off + 4 <= len(msg):
        tag, ln = struct.unpack(">HH", msg[off:off + 4])
        if ln < 4 or off + ln > len(msg):
            break
        out.append((tag, msg[off + 4:off + ln]))
        off += ln + ((4 - ln % 4) % 4)
    return out


def protocol_data(msg):
    for tag, value in params_of(msg):
        if tag == 0x0210 and len(value) >= 4:
            return value[4:]
    return None


def oracle_parameter(imsi, msc):
    """Encode SendRoutingInfoRes with pycrate, so the answer is not our own."""
    # pycrate's OCTET STRING fields take BYTES: an int is read as an object
    # reference and a hex string as a two-element path, both of which fail with
    # messages that do not say so.
    script = (
        "from pycrate_asn1dir import TCAP_MAP as T\n"
        "t = T.MAP_CH_DataTypes.SendRoutingInfoRes\n"
        "t.set_val({'imsi': bytes.fromhex(%r), "
        "'extendedRoutingInfo': ('routingInfo', ('roamingNumber', bytes.fromhex(%r)))})\n"
        "print(t.to_ber().hex())\n" % (tbcd(imsi), "91" + tbcd(msc))
    )
    r = subprocess.run([ORACLE_PY, "-c", script], capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "oracle failed"
    return r.stdout.strip(), None


def tbcd(digits):
    d = digits if len(digits) % 2 == 0 else digits + "F"
    return "".join(d[i + 1] + d[i] for i in range(0, len(d), 2))


def map_ids(msu_hex):
    """Pull otid, invoke id and opcode out of a Begin, without decoding MAP."""
    m = re.search(r"4804([0-9a-fA-F]{8})", msu_hex)
    otid = m.group(1).lower() if m else None
    m = re.search(r"0201([0-9a-fA-F]{2})0201([0-9a-fA-F]{2})", msu_hex)
    iid, op = (int(m.group(1), 16), int(m.group(2), 16)) if m else (1, 22)
    return otid, iid, op


def module(*args):
    r = subprocess.run(["bash", MODULE] + list(args), capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def build_answer(msu_hex, table, dpc=1, opc=2):
    otid, iid, op = map_ids(msu_hex)
    if op != 22:
        return None, "only sendRoutingInfo (opCode 22) is answered"
    m = re.search(r"8007([0-9a-fA-F]{6})", msu_hex) or re.search(r"8006([0-9a-fA-F]{6})", msu_hex)
    msisdn = ""
    if m:
        raw = m.group(1)
        digits = "".join(raw[i + 1] + raw[i] for i in range(0, len(raw), 2)).rstrip("fF")
        msisdn = digits
    entry = table.get(msisdn) or table.get("*")
    if not entry:
        return None, "no subscriber table entry for %s (add one, or a '*' default)" % (msisdn or "?")
    par, err = oracle_parameter(entry["imsi"], entry["msc"])
    if par is None:
        return None, "pycrate could not encode SendRoutingInfoRes: %s" % err
    args = ["--build-response", "sri-ack", "--parameter", par, "--invoke", str(iid),
            "--wrap", "msu", "--dpc", str(opc), "--opc", str(dpc), "--cssn", "6", "--ossn", "8"]
    if otid:
        args += ["--otid", otid]
    rc, out, err = module(*args)
    if rc != 0:
        return None, "the module refused to wrap the answer: %s" % (err.strip().splitlines() or ["rc=%d" % rc])[0]
    for line in out.splitlines():
        k, _, v = line.partition("\t")
        if k == "msu_hex":
            return v.strip(), None
    return None, "the module printed no msu_hex"


def main():
    ap = argparse.ArgumentParser(description="answer MAP routing queries over M3UA")
    ap.add_argument("--port", type=int, default=2905)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--table", help="JSON: {\"17045550001\": {\"imsi\": \"...\", \"msc\": \"...\"}}")
    ap.add_argument("--once", action="store_true", help="answer one request and exit")
    ap.add_argument("--wait", type=float, default=20.0)
    a = ap.parse_args()

    table = {"*": {"imsi": "310150123456789", "msc": "310150987654321"}}
    if a.table:
        try:
            table = json.load(open(a.table))
        except Exception as e:
            log("ERROR", "could not read %s: %s" % (a.table, e))
            return 2
    if not os.path.exists(ORACLE_PY):
        log("ERROR", "no pycrate interpreter at %s; the answer must be encoded by an "
                     "independent implementation or the test proves nothing" % ORACLE_PY)
        return 2

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((a.bind, a.port))
    except OSError as e:
        log("ERROR", "cannot bind %s:%d over SCTP: %s" % (a.bind, a.port, e))
        return 1
    srv.listen(1)
    srv.settimeout(a.wait)
    log("listening", "%s:%d" % (a.bind, a.port), "sctp", "ppid", PPID_M3UA)
    try:
        conn, peer = srv.accept()
    except socket.timeout:
        log("status", "timeout", "waited", a.wait, "no association arrived")
        return 1
    log("associated", "%s:%d" % peer)
    conn.settimeout(a.wait)
    answered = 0
    try:
        while True:
            msg = recv_m3ua(conn)
            if not msg:
                break
            cls, mtype = msg[2], msg[3]
            if cls == M3UA_ASPSM and mtype == T_ASPUP:
                send_m3ua(conn, m3ua(M3UA_ASPSM, T_ASPUP_ACK, [param(0x0011, struct.pack(">I", 1))]))
                log("phase", "ASPUP", "answered", "ASPUP-ACK")
                continue
            if cls == M3UA_ASPTM and mtype == T_ASPAC:
                send_m3ua(conn, m3ua(M3UA_ASPTM, T_ASPAC_ACK))
                log("phase", "ASPAC", "answered", "ASPAC-ACK")
                continue
            if cls == M3UA_ASPSM and mtype == T_BEAT:
                send_m3ua(conn, m3ua(M3UA_ASPSM, T_BEAT_ACK))
                log("phase", "BEAT", "answered", "BEAT-ACK")
                continue
            if cls == M3UA_TRANSFER and mtype == T_DATA:
                msu = protocol_data(msg)
                if msu is None:
                    log("request", "DATA", "no", "protocol data parameter")
                    continue
                msu_hex = msu.hex()
                log("request", "DATA", "msu_octets", len(msu), "hex", msu_hex[:64] + ("…" if len(msu_hex) > 64 else ""))
                answer, err = build_answer(msu_hex, table)
                if answer is None:
                    log("answer", "refused", "why", err)
                    conn.close()
                    return 1
                octets = bytes.fromhex(answer)
                send_m3ua(conn, m3ua(M3UA_TRANSFER, T_DATA, [param(0x0210, struct.pack(">II", 0, 0) + octets)]))
                log("answer", "sent", "msu_octets", len(octets), "hex", answer[:64] + ("…" if len(answer) > 64 else ""))
                answered += 1
                if a.once:
                    break
                continue
            log("message", "ignored", "class", cls, "type", mtype)
    finally:
        conn.close()
        srv.close()
    log("status", "answered", answered)
    return 0 if answered else 1


if __name__ == "__main__":
    sys.exit(main())
