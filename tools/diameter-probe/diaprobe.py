#!/usr/bin/env python3
"""
diaprobe — Diameter interconnect probe kit.

Sends real Diameter messages over SCTP (or TCP) to an interconnect edge and
reports what the peer did with them. This is not a port scanner: an interconnect
that answers CER with a CEA is a working DRA and the answer tells you its
capabilities, its realm, and whether it authenticated you at all.

Doctrine (see AGENTS.md §3): measured, advertised, unobserved. Every result row
is one of those three. A silent peer is UNOBSERVED, never "closed".

Test targets are your own IMSI/MSISDN and your own realm unless told otherwise.

Usage:
  diaprobe.py cer   --host 1.2.3.4 [--port 3868] [--transport sctp|tcp]
  diaprobe.py ulr   --host H --imsi <IMSI> --dest-realm R --origin-realm R2
  diaprobe.py air   --host H --imsi <IMSI> --mcc 470 --mnc 01
  diaprobe.py slr   --host H --imsi <IMSI>
  diaprobe.py sri   --host H --msisdn <MSISDN>
  diaprobe.py sweep --prefix-file F [--ports 3868,2905,3869]

Every verb prints a TSV row set and appends to the store.
"""

import argparse
import os
import socket
import struct
import sys
import time

# pycrate ships as several top-level packages (pycrate_diameter, ...) rather
# than one "pycrate" package, so a plain `import pycrate` fails even when it is
# installed. Load it from the user site explicitly.
for _p in (
    os.path.expanduser("~/.local/lib/python3.12/site-packages"),
    os.path.expanduser("~/.local/lib/python3/dist-packages"),
):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from pycrate_diameter.Diameter import DiameterGeneric, AVPGeneric  # noqa: E402

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

CMD_CER = 257
CMD_CEA = 257
CMD_DWR = 280
CMD_DWA = 280
CMD_DPR = 282
CMD_DPA = 282
CMD_ULR = 316
CMD_ULA = 316
CMD_AIR = 318
CMD_AIA = 318
CMD_SLR = 8388635   # SRR is 8388636
CMD_SLA = 8388635
CMD_SRI_SM = 45     # MAP, S6c/MAP not Diameter; kept for completeness
CMD_CLR = 317
CMD_IDR = 319

APP_DIAM_BASE = 0            # Common Message = 0, Base = 0 in the header
APP_S6A = 16777251
APP_S6D = 16777251
APP_SGd = 16777313           # SRR/SLA for 5G
APP_3GPP_OAM = 16777216 + 1  # not used, placeholder

# RFC 6733 Result-Code
RESULT_NAMES = {
    1001: "DIAMETER_MULTI_ROUND_AUTH",
    2001: "DIAMETER_SUCCESS",
    2002: "DIAMETER_LIMITED_SUCCESS",
    3001: "DIAMETER_COMMAND_UNSUPPORTED",
    3002: "DIAMETER_UNABLE_TO_DELIVER",
    3003: "DIAMETER_REALM_NOT_SERVED",
    3004: "DIAMETER_TOO_BUSY",
    3005: "DIAMETER_LOOP_DETECTED",
    3006: "DIAMETER_REDIRECT_INDICATION",
    3007: "DIAMETER_APPLICATION_UNSUPPORTED",
    3008: "DIAMETER_INVALID_HDR_BITS",
    3009: "DIAMETER_INVALID_AVP_BITS",
    3010: "DIAMETER_UNKNOWN_PEER",
    4001: "DIAMETER_AUTHENTICATION_REJECTED",
    4010: "DIAMETER_MISSING_AVP",
    5001: "DIAMETER_AVP_UNSUPPORTED",
    5002: "DIAMETER_UNKNOWN_SESSION_ID",
    5004: "DIAMETER_INVALID_AVP_VALUE",
}

# AVP codes used below (RFC 6733 / TS 29.272 / TS 29.338)
AVP_ORIGIN_HOST = 264
AVP_ORIGIN_REALM = 296
AVP_DEST_REALM = 283
AVP_DEST_HOST = 293
AVP_RESULT_CODE = 268
AVP_SESSION_ID = 263
AVP_USER_NAME = 1
AVP_VENDOR_SPECIFIC = 32
AVP_VENDOR_ID = 266
AVP_PRODUCT_NAME = 269
AVP_SUPPORTED_VENDOR = 265
AVP_USER_IMSI = 1
AVP_RAT_TYPE = 1032
AVP_ULR_FLAGS = 1405
AVP_VISITED_PLMN_ID = 1407
AVP_ULA_FLAGS = 1406
AVP_SUBSCRIPTION_DATA = 1400
AVP_AIR_FLAGS = 1471
AVP_HOST_IP = 257
AVP_ORIGIN_STATE = 278
AVP_ACCT_APPLICATION_ID = 258
AVP_AUTH_APPLICATION_ID = 259

# RFC 3539 watchdog
RFC3539_OKAY, RFC3539_DOWN = 0, 1


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------

def _open_socket(host, port, transport, timeout):
    """Return a connected socket, raising on failure. transport is sctp or tcp."""
    if transport == "sctp":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        except OSError as e:
            raise RuntimeError(f"SCTP socket unavailable: {e}") from e
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def _recv_msg(sock, transport):
    """
    Read exactly one Diameter message off the wire.

    The Diameter length is the third and fourth bytes of the 20-byte header
    (Version is one byte, then a 24-bit length), so the first read gets the
    header and the second gets the remainder.
    """
    head = _recv_exact(sock, 20, transport)
    if head is None:
        return None
    if len(head) < 4:
        raise ValueError("short diameter header")
    length = (head[1] << 16) | (head[2] << 8) | head[3]
    if length < 20 or length > 65535:
        raise ValueError(f"implausible diameter length {length}")
    body = _recv_exact(sock, length - 20, transport)
    if body is None:
        return None
    return head + body


def _recv_exact(sock, n, transport):
    """Read n bytes; returns None on clean peer close."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise
        if not chunk:
            return None
        buf += chunk
    return buf


# --------------------------------------------------------------------------
# message construction
# --------------------------------------------------------------------------

def _mk_avp(code, data, vendor=0, mandatory=True):
    """
    Build one AVPGeneric element.

    The Sequence in DiameterGeneric only accepts Elt children, not dicts, so the
    AVP has to exist as an object before it is appended. set_val_hdr() is what
    swaps the generic data buffer for the AVP's real type, and AVPPad is
    automated off the data length so the 4-byte boundary is handled here.
    """
    a = AVPGeneric()
    a.set_val_hdr({
        "Code": code,
        "V": 1 if vendor else 0,
        "M": 1 if mandatory else 0,
        "P": 0,
        "VendorID": vendor,
    })
    a.set_val_data(data)
    return a


def _identity(s):
    return s.encode() if isinstance(s, str) else s


def _session_id(host):
    return f"{host};{int(time.time())};{os.getpid()}".encode()


def build_cer(origin_host, origin_realm, host_ip, vendor_id=0,
              product="diaprobe", origin_state=0):
    """
    Capabilities-Exchange-Request.

    The CER is the single most useful probe on an interconnect: it is a legal
    first message from any peer, and the peer's answer (CEA) discloses its
    Origin-Host, Origin-Realm, supported applications, its vendor and its
    firmware string — without any authentication having taken place yet. That
    is advertised, not measured, but it is the peer you are talking to.
    """
    avps = [
        _mk_avp(AVP_ORIGIN_HOST, _identity(origin_host)),
        _mk_avp(AVP_ORIGIN_REALM, _identity(origin_realm)),
        _mk_avp(AVP_HOST_IP, socket.inet_aton(host_ip)),
        _mk_avp(AVP_VENDOR_ID, struct.pack("!I", vendor_id)),
        _mk_avp(AVP_PRODUCT_NAME, product.encode()),
        _mk_avp(AVP_ORIGIN_STATE, struct.pack("!I", origin_state)),
        # we speak the applications we intend to interrogate
        _mk_avp(AVP_ACCT_APPLICATION_ID, struct.pack("!I", APP_S6A), mandatory=True),
        _mk_avp(AVP_AUTH_APPLICATION_ID, struct.pack("!I", APP_S6A), mandatory=True),
    ]
    return _build(CMD_CER, 0x80, APP_DIAM_BASE, origin_host, avps)


def build_dwr(origin_host, origin_realm):
    avps = [
        _mk_avp(AVP_ORIGIN_HOST, _identity(origin_host)),
        _mk_avp(AVP_ORIGIN_REALM, _identity(origin_realm)),
    ]
    return _build(CMD_DWR, 0x80, APP_DIAM_BASE, origin_host, avps)


def build_ulr(origin_host, origin_realm, dest_realm, imsi, rat_type=0,
              ulr_flags=0b11111, visited_plmn=None):
    """
    Update-Location-Request toward an HSS (S6a).

    ULR is the message that makes an HSS insert a subscriber into a VLR/MME.
    Answering it is not yet "access"; the interesting rows are the Result-Code
    and, on success, the Subscription-Data that comes back.
    """
    avps = [
        _mk_avp(AVP_SESSION_ID, _session_id(origin_host)),
        _mk_avp(AVP_ORIGIN_HOST, _identity(origin_host)),
        _mk_avp(AVP_ORIGIN_REALM, _identity(origin_realm)),
        _mk_avp(AVP_DEST_REALM, _identity(dest_realm)),
        _mk_avp(AVP_USER_NAME, _identity(imsi)),
        _mk_avp(AVP_USER_IMSI, _identity(imsi)),
        _mk_avp(AVP_RAT_TYPE, struct.pack("!I", rat_type)),
        _mk_avp(AVP_ULR_FLAGS, struct.pack("!I", ulr_flags)),
    ]
    if visited_plmn:
        avps.append(_mk_avp(AVP_VISITED_PLMN_ID, bytes.fromhex(visited_plmn)))
    return _build(CMD_ULR, 0xC0, APP_S6A, origin_host, avps)


def build_air(origin_host, origin_realm, dest_realm, imsi, mcc, mnc):
    """
    Authentication-Information-Request toward an HSS (S6a).

    AIR pulls authentication vectors. If an HSS answers 2001 to an AIR for a
    subscriber whose IMSI is not yours, that is the finding worth writing down:
    the interconnect accepted a request for subscriber state it should have
    rejected.
    """
    plmn = _plmn_bytes(mcc, mnc)
    avps = [
        _mk_avp(AVP_SESSION_ID, _session_id(origin_host)),
        _mk_avp(AVP_ORIGIN_HOST, _identity(origin_host)),
        _mk_avp(AVP_ORIGIN_REALM, _identity(origin_realm)),
        _mk_avp(AVP_DEST_REALM, _identity(dest_realm)),
        _mk_avp(AVP_USER_NAME, _identity(imsi)),
        _mk_avp(AVP_USER_IMSI, _identity(imsi)),
        _mk_avp(AVP_VISITED_PLMN_ID, plmn),
        _mk_avp(AVP_AIR_FLAGS, struct.pack("!I", 0b111)),
    ]
    return _build(CMD_AIR, 0xC0, APP_S6A, origin_host, avps)


def build_slr(origin_host, origin_realm, dest_realm, imsi):
    """
    SRR via SGd (5G). Also covered indirectly on older nets by S6c.

    8388635 is SRR; the answer SLA carries steering information. On a 5G
    interconnect the SGd interface is exactly the one that governs roaming
    steering, which is what a HAF finding looks like.
    """
    avps = [
        _mk_avp(AVP_SESSION_ID, _session_id(origin_host)),
        _mk_avp(AVP_ORIGIN_HOST, _identity(origin_host)),
        _mk_avp(AVP_ORIGIN_REALM, _identity(origin_realm)),
        _mk_avp(AVP_DEST_REALM, _identity(dest_realm)),
        _mk_avp(AVP_USER_NAME, _identity(imsi)),
        _mk_avp(AVP_USER_IMSI, _identity(imsi)),
    ]
    return _build(CMD_SLR, 0xC0, APP_SGd, origin_host, avps)


def _plmn_bytes(mcc, mnc):
    """
    Encode a PLMN as VISITED-PLMN-ID expects: 3 octets, BCD nibbles, swapped.

    mcc 470 / mnc 01 -> 47 00 10
    mcc 470 / mnc 001 -> 47 00 01
    """
    mcc, mnc = str(mcc).zfill(3), str(mnc).zfill(3)
    if len(mnc) == 2:
        mnc = "0" + mnc
    d = mcc + mnc
    b = [int(d[i:i + 2][::-1], 16) for i in (0, 2, 4)]
    # the third octet for a 2-digit MNC carries an F nibble, handled by caller
    return bytes([b[0], b[1], int(d[4:6][::-1], 16)])


def _build(cmd, hh_ee_flags, app_id, origin_host, avps):
    msg = DiameterGeneric()
    msg[0]["Vers"] = 1
    msg[0]["R"] = (hh_ee_flags >> 7) & 1
    msg[0]["P"] = (hh_ee_flags >> 6) & 1
    msg[0]["E"] = (hh_ee_flags >> 5) & 1
    msg[0]["T"] = (hh_ee_flags >> 4) & 1
    msg[0]["Cmd"] = cmd
    msg[0]["AppID"] = app_id
    msg[0]["HHID"] = _hp(origin_host)
    msg[0]["EEID"] = _hp(origin_host)
    for a in avps:
        msg[1].append(a)
    return msg


def _hp(s):
    """Hop-by-hop / end-to-end identifier: a nonzero u32 per message."""
    return (hash((s, time.time())) & 0x7FFFFFFF) | 1


# --------------------------------------------------------------------------
# message decoding
# --------------------------------------------------------------------------

def decode(raw):
    """
    Decode a Diameter message into a plain dict.

    pycrate's DiameterGeneric expects the wire buffer, so hand it that and pull
    the fields out; anything that fails to parse is reported raw rather than
    guessed at.
    """
    msg = DiameterGeneric()
    msg.from_bytes(raw)
    hdr = msg[0]
    out = {
        "cmd": hdr["Cmd"].get_val(),
        "app_id": hdr["AppID"].get_val(),
        "flags": {
            "R": hdr["R"].get_val(), "P": hdr["P"].get_val(),
            "E": hdr["E"].get_val(), "T": hdr["T"].get_val(),
        },
        "avps": [],
    }
    for avp in msg[1]:
        code = avp[0]["Code"].get_val()
        hdr_v = avp[0]["V"].get_val()
        data = bytes(avp[1].to_bytes())
        out["avps"].append({"code": code, "vendor": hdr_v, "raw": data})
    return out


def avp_map(decoded):
    """Collapse a decoded AVP list to {code: last-raw-bytes}."""
    m = {}
    for a in decoded["avps"]:
        m[a["code"]] = a["raw"]
    return m


def result_code(decoded):
    raw = avp_map(decoded).get(AVP_RESULT_CODE)
    if raw and len(raw) >= 4:
        return struct.unpack("!I", raw[:4])[0]
    return None


def origin_host(decoded):
    raw = avp_map(decoded).get(AVP_ORIGIN_HOST)
    return raw.split(b"\x00")[0].decode(errors="replace") if raw else None


def origin_realm(decoded):
    raw = avp_map(decoded).get(AVP_ORIGIN_REALM)
    return raw.split(b"\x00")[0].decode(errors="replace") if raw else None


def supported_apps(decoded):
    """
    Every Vendor-Specific AVP Grouped pair of Vendor-Id + Vendor-Id as the peer
    advertised in its CEA. Reported as a list of ints; unparsed stays empty.
    """
    apps = []
    group = {}
    for a in decoded["avps"]:
        if a["code"] == AVP_SUPPORTED_VENDOR:
            if len(a["raw"]) == 4:
                group.setdefault("vendor", struct.unpack("!I", a["raw"])[0])
        if a["code"] == AVP_AUTH_APPLICATION_ID:
            if len(a["raw"]) == 4:
                apps.append(struct.unpack("!I", a["raw"])[0])
    return apps


# --------------------------------------------------------------------------
# store
# --------------------------------------------------------------------------

def store_path():
    base = os.environ.get("LOOT_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "loot"
    )
    d = os.path.join(base, "diameter-probe")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "probes.tsv")


STORE_HEADER = ["utc", "verb", "host", "port", "transport", "cmd", "result_code",
                "result_name", "origin_host", "origin_realm", "verdict", "note"]


def store(row):
    p = store_path()
    new = not os.path.exists(p)
    with open(p, "a") as f:
        if new:
            f.write("\t".join(STORE_HEADER) + "\n")
        f.write("\t".join("" if v is None else str(v) for v in row) + "\n")


def emit(row):
    print("\t".join("" if v is None else str(v) for v in row))


# --------------------------------------------------------------------------
# verbs
# --------------------------------------------------------------------------

def do_cer(args):
    """Send a CER and report what the peer answers. No auth happens before CEA."""
    out = None
    try:
        sock = _open_socket(args.host, args.port, args.transport, args.timeout)
    except Exception as e:
        row = [now(), "cer", args.host, args.port, args.transport, CMD_CER,
               None, None, None, None, "UNOBSERVED", f"connect failed: {e}"]
        emit(row); store(row); return 1

    try:
        cer = build_cer(args.origin_host or f"diaprobe.{args.host}",
                        args.origin_realm or args.host,
                        args.host_ip or local_ip(args.host))
        sock.sendall(cer.to_bytes())
        raw = _recv_msg(sock, args.transport)
        if raw is None:
            row = [now(), "cer", args.host, args.port, args.transport, CMD_CER,
                   None, None, None, None, "UNOBSERVED",
                   "peer closed before CEA"]
            emit(row); store(row); return 1
        out = decode(raw)
    except socket.timeout:
        row = [now(), "cer", args.host, args.port, args.transport, CMD_CER,
               None, None, None, None, "UNOBSERVED", "no CEA within timeout"]
        emit(row); store(row); return 1
    except Exception as e:
        row = [now(), "cer", args.host, args.port, args.transport, CMD_CER,
               None, None, None, None, "UNOBSERVED", f"error: {e}"]
        emit(row); store(row); return 1
    finally:
        try:
            sock.close()
        except Exception:
            pass

    rc = result_code(out)
    row = [now(), "cer", args.host, args.port, args.transport, out["cmd"],
           rc, RESULT_NAMES.get(rc, "unknown"),
           origin_host(out), origin_realm(out), "MEASURED",
           f"apps={supported_apps(out)}"]
    emit(row)
    store(row)
    return 0 if rc in (2001, 2002) else 1


def do_dwr(args):
    """Watchdog probe: is the peer alive and does it accept us as a peer."""
    return _simple(args, "dwr", build_dwr(args.origin_host or f"diaprobe.{args.host}",
                                          args.origin_realm or args.host), CMD_DWR)


def do_ulr(args):
    return _simple(args, "ulr", build_ulr(
        args.origin_host or f"diaprobe.{args.host}",
        args.origin_realm or args.host,
        args.dest_realm or args.origin_realm or args.host,
        args.imsi), CMD_ULR)


def do_air(args):
    return _simple(args, "air", build_air(
        args.origin_host or f"diaprobe.{args.host}",
        args.origin_realm or args.host,
        args.dest_realm or args.origin_realm or args.host,
        args.imsi, args.mcc, args.mnc), CMD_AIR)


def do_slr(args):
    return _simple(args, "slr", build_slr(
        args.origin_host or f"diaprobe.{args.host}",
        args.origin_realm or args.host,
        args.dest_realm or args.origin_realm or args.host,
        args.imsi), CMD_SLR)


def _simple(args, verb, msg, cmd):
    try:
        sock = _open_socket(args.host, args.port, args.transport, args.timeout)
    except Exception as e:
        row = [now(), verb, args.host, args.port, args.transport, cmd,
               None, None, None, None, "UNOBSERVED", f"connect failed: {e}"]
        emit(row); store(row); return 1
    try:
        sock.sendall(msg.to_bytes())
        raw = _recv_msg(sock, args.transport)
        if raw is None:
            row = [now(), verb, args.host, args.port, args.transport, cmd,
                   None, None, None, None, "UNOBSERVED", "peer closed without answer"]
            emit(row); store(row); return 1
        out = decode(raw)
    except socket.timeout:
        row = [now(), verb, args.host, args.port, args.transport, cmd,
               None, None, None, None, "UNOBSERVED", "no answer within timeout"]
        emit(row); store(row); return 1
    except Exception as e:
        row = [now(), verb, args.host, args.port, args.transport, cmd,
               None, None, None, None, "UNOBSERVED", f"error: {e}"]
        emit(row); store(row); return 1
    finally:
        try:
            sock.close()
        except Exception:
            pass

    rc = result_code(out)
    # A 2001 on a verb we had no business sending is the finding; anything
    # else is a peer declining us, which is also information.
    verdict = "MEASURED"
    row = [now(), verb, args.host, args.port, args.transport, out["cmd"],
           rc, RESULT_NAMES.get(rc, "unknown"),
           origin_host(out), origin_realm(out), verdict,
           " "[:0]]
    emit(row); store(row)
    return 0 if rc in (2001, 2002) else 1


def do_sweep(args):
    """
    Sweep a prefix file for open Diameter ports.

    Deliberately tcp-first and slow: SCTP connect over a wide prefix is noisy
    and slow, and a carrier interconnect answers on one or two addresses, not on
    every /24. This is a discovery aid, not the assessment.
    """
    hosts = []
    with open(args.prefix_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "/" in line:
                hosts.extend(_expand(line))
            else:
                hosts.append(line)
    print(f"# sweeping {len(hosts)} hosts, ports {args.ports}", file=sys.stderr)
    for h in hosts:
        for p in [int(x) for x in args.ports.split(",")]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(args.timeout)
                s.connect((h, p))
                s.close()
                row = [now(), "sweep", h, p, "tcp", None, None, None, None, None,
                       "MEASURED", "tcp port open"]
                emit(row); store(row)
            except Exception:
                pass
    return 0


def _expand(cidr):
    """Expand a CIDR to host addresses without importing ipaddress twice."""
    import ipaddress
    return [str(ip) for ip in ipaddress.ip_network(cidr, strict=False).hosts()]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def local_ip(dest):
    """Ask the kernel which source address it would use toward dest."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest, 9))
        return s.getsockname()[0]
    finally:
        s.close()


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="diaprobe", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="verb", required=True)

    def add_common(p):
        p.add_argument("--host", required=True)
        p.add_argument("--port", type=int, default=3868)
        p.add_argument("--transport", choices=["sctp", "tcp"], default="sctp")
        p.add_argument("--timeout", type=float, default=8.0)
        p.add_argument("--origin-host")
        p.add_argument("--origin-realm")
        p.add_argument("--host-ip")

    for name, fn in (("cer", do_cer), ("dwr", do_dwr), ("ulr", do_ulr),
                     ("air", do_air), ("slr", do_slr)):
        p = sub.add_parser(name)
        add_common(p)
        if name in ("ulr", "air", "slr"):
            p.add_argument("--imsi", required=True)
            p.add_argument("--dest-realm")
        if name == "air":
            p.add_argument("--mcc", required=True)
            p.add_argument("--mnc", required=True)
        p.set_defaults(func=fn)

    ps = sub.add_parser("sweep")
    ps.add_argument("--prefix-file", required=True)
    ps.add_argument("--ports", default="3868")
    ps.add_argument("--timeout", type=float, default=3.0)
    ps.set_defaults(func=do_sweep)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
