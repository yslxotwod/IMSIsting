#!/usr/bin/env python3
"""smpp_client.py -- carry a built SMPP 3.4 PDU over TCP and read its answer.

`modules/41_ota_sms.sh --smpp-build` owns the octets: the 16-octet header, the
C-Octet Strings whose terminator counts in the field, the integer body fields.
This file owns only the transport, because the one thing a shell cannot do
honestly is read "command_length octets, then again" off a socket with a
deadline. It frames, it sends, it reads the matching *_resp, and it names the
command_status it got back (SMPP 3.4 5.1.3, Table 5-3).

An SMSC authenticates an ESME by system_id/password in bind_transceiver
(5.2.1), not by a SIM, which is why a submit_sm needs no subscriber identity
on this side of the wire.

Rows go to stdout, one `key<TAB>value` per line, so the module can pass them
through unchanged. Exit: 0 done, 1 remote non-zero status, 2 usage, 3 socket.

`--self-test` runs a loopback SMSC in this process (accept, answer bind, answer
submit) so the framing and the response parse are proven with no network.
"""

import argparse
import socket
import struct
import sys
import threading
import time

HEADER = 16
MAX_PDU = 1 << 20

CMD = {
    0x00000004: "submit_sm",
    0x80000004: "submit_sm_resp",
    0x00000005: "deliver_sm",
    0x80000005: "deliver_sm_resp",
    0x00000009: "bind_transceiver",
    0x80000009: "bind_transceiver_resp",
    0x00000006: "unbind",
    0x80000006: "unbind_resp",
    0x00000015: "enquire_link",
    0x80000015: "enquire_link_resp",
    0x00000003: "enquire_link_alt",
}

# SMPP 3.4 5.1.3 Table 5-3, the statuses an ESME meets in practice.
STATUS = {
    0x00000000: "esme_rok",
    0x00000001: "esme_rinvmsglen",
    0x00000002: "esme_rinvcmdlen",
    0x00000003: "esme_rinvcmdid",
    0x00000004: "esme_rinvbndsts",
    0x00000005: "esme_ralybnd",
    0x00000006: "esme_rinvprtflg",
    0x00000007: "esme_rinvregdlvflg",
    0x00000008: "esme_rsyserr",
    0x0000000A: "esme_rinvsrcadr",
    0x0000000B: "esme_rinvdstadr",
    0x0000000C: "esme_rinvmsgid",
    0x0000000D: "esme_rbindfail",
    0x0000000E: "esme_rinvpaswd",
    0x0000000F: "esme_rinvsysid",
    0x00000010: "esme_rcancel",
    0x00000011: "esme_rreplace",
    0x00000013: "esme_rqueryfail",
    0x00000014: "esme_rsysbusy",
    0x00000015: "esme_rthrottled",
    0x00000042: "esme_rinvntli",
    0x00000045: "esme_rsubmittimeout",
}


def status_name(code):
    return STATUS.get(code, "status_0x%08x" % code)


def cmd_name(code):
    return CMD.get(code, "0x%08x" % code)


def row(key, value=""):
    sys.stdout.write("%s\t%s\n" % (key, value))


def die(key, value, text, code=2):
    row(key, value)
    sys.stderr.write("ERROR\t%s\n" % text)
    return code


def parse_header(pdu):
    if len(pdu) < HEADER:
        raise ValueError("PDU is %d octets, shorter than the 16-octet header" % len(pdu))
    length, cmd_id, status, seq = struct.unpack(">IIII", pdu[:HEADER])
    if length != len(pdu):
        raise ValueError(
            "command_length says %d octets but %d arrived" % (length, len(pdu)))
    return {
        "command_length": length,
        "command_id": cmd_id,
        "command_status": status,
        "sequence_number": seq,
        "body": pdu[HEADER:],
    }


def cstring(body, offset, limit, field):
    """Read a C-Octet String: the NUL terminator is inside the field."""
    end = body.find(b"\x00", offset)
    if end < 0:
        raise ValueError("%s has no NUL terminator" % field)
    if end - offset + 1 > limit:
        raise ValueError("%s is %d octets, above its %d-octet maximum"
                         % (field, end - offset + 1, limit))
    try:
        text = body[offset:end].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("%s is not ASCII" % field)
    return text, end + 1


def recv_exact(sock, count, deadline):
    buf = b""
    while len(buf) < count:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("deadline passed with %d of %d octets read"
                               % (len(buf), count))
        sock.settimeout(left)
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("SMSC closed the connection after %d octets" % len(buf))
        buf += chunk
    return buf


def recv_pdu(sock, deadline):
    head = recv_exact(sock, 4, deadline)
    (length,) = struct.unpack(">I", head)
    if length < HEADER or length > MAX_PDU:
        raise ValueError("command_length %d is outside %d..%d" % (length, HEADER, MAX_PDU))
    return head + recv_exact(sock, length - 4, deadline)


def send_pdu(sock, hex_text):
    try:
        pdu = bytes.fromhex(hex_text)
    except ValueError:
        raise ValueError("PDU is not whole octets of hex")
    parsed = parse_header(pdu)
    sock.sendall(pdu)
    row("tx_command_id", "0x%08x\t%s" % (parsed["command_id"], cmd_name(parsed["command_id"])))
    row("tx_sequence_number", "%08x" % parsed["sequence_number"])
    row("tx_octets", str(len(pdu)))
    return parsed


def read_response(sock, expect_id, deadline, label):
    pdu = recv_pdu(sock, deadline)
    hdr = parse_header(pdu)
    row("%s_resp_command_id" % label, "0x%08x\t%s" % (hdr["command_id"], cmd_name(hdr["command_id"])))
    row("%s_resp_sequence_number" % label, "%08x" % hdr["sequence_number"])
    row("%s_resp_status" % label, "0x%08x\t%s" % (hdr["command_status"], status_name(hdr["command_status"])))
    row("%s_resp_octets" % label, str(hdr["command_length"]))
    row("%s_resp_hex" % label, pdu.hex())
    if hdr["command_id"] != expect_id:
        raise ValueError("%s: expected command_id 0x%08x (%s), got 0x%08x (%s)"
                         % (label, expect_id, cmd_name(expect_id),
                            hdr["command_id"], cmd_name(hdr["command_id"])))
    return hdr


def run_transaction(host, port, timeout, bind_hex, submit_hexes, no_bind):
    deadline = time.monotonic() + timeout
    row("connect", "%s:%d" % (host, port))
    started = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return die("sent", "no", "connect to %s:%d failed: %s" % (host, port, exc), 3)
    try:
        if bind_hex and not no_bind:
            row("bind", "requested")
            send_pdu(sock, bind_hex)
            hdr = read_response(sock, 0x80000009, deadline, "bind")
            if hdr["command_status"]:
                return 1
            try:
                system_id, _ = cstring(hdr["body"], 0, 16, "system_id")
                row("bind_system_id", system_id or "(null)")
            except ValueError as exc:
                row("bind_system_id", "unreadable: %s" % exc)
            row("bound", "yes")
        else:
            row("bind", "not-requested")
        seq_index = 0
        for hex_text in submit_hexes:
            seq_index += 1
            label = "submit" if len(submit_hexes) == 1 else "submit%d" % seq_index
            row("%s_requested" % label, "yes")
            send_pdu(sock, hex_text)
            hdr = read_response(sock, 0x80000004, deadline, label)
            try:
                message_id, _ = cstring(hdr["body"], 0, 65, "message_id")
                row("%s_message_id" % label, message_id or "(empty)")
            except ValueError as exc:
                row("%s_message_id" % label, "unreadable: %s" % exc)
            if hdr["command_status"]:
                row("sent", "no")
                return 1
        row("sent", "yes")
        return 0
    except (TimeoutError, ConnectionError, ValueError, OSError) as exc:
        row("sent", "no")
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 3 if isinstance(exc, (TimeoutError, ConnectionError, OSError)) else 1
    finally:
        row("elapsed_ms", "%d" % int((time.monotonic() - started) * 1000))
        try:
            sock.close()
        except OSError:
            pass


# TS 23.038 6.2.1, the GSM 7-bit default alphabet, one character per septet
# 0x00-0x7F. The escape septet 0x1B introduces the extension table, which this
# reader does not decode: a message using it is reported as escaped rather than
# rendered wrong.
GSM7 = (
    "@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5"
    "\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u001b\u00c6\u00e6\u00df\u00c9"
    " !\"#\u00a4%&'()*+,-./"
    "0123456789:;<=>?"
    "\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7"
    "\u00bfabcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0"
)


def gsm7_unpack(octets, septets=None):
    """Unpack packed septets back to text (TS 23.038 6.1.2.1.1, the inverse)."""
    value = 0
    bits = 0
    index = 0
    out = []
    total = len(octets) * 8 // 7 if septets is None else septets
    for _ in range(total):
        while bits < 7 and index < len(octets):
            value |= octets[index] << bits
            index += 1
            bits += 8
        code = value & 0x7F
        value >>= 7
        bits -= 7
        if code == 0x1B:
            out.append("\\")
            continue
        out.append(GSM7[code])
    return "".join(out)


# ── loopback SMSC, so the framing is proven without a network ─────────────
def _fake_smsc(listener, submit_answers, seen):
    conn, _ = listener.accept()
    try:
        pdu = recv_pdu(conn, time.monotonic() + 5)
        hdr = parse_header(pdu)
        seen.append(hdr)
        if hdr["command_id"] != 0x00000009:
            raise ValueError("first PDU was 0x%08x, not bind_transceiver" % hdr["command_id"])
        system_id, _ = cstring(hdr["body"], 0, 16, "system_id")
        body = system_id.encode("ascii") + b"\x00"
        resp = struct.pack(">IIII", HEADER + len(body), 0x80000009, 0,
                           hdr["sequence_number"]) + body
        conn.sendall(resp)
        for message_id in submit_answers:
            pdu = recv_pdu(conn, time.monotonic() + 5)
            hdr = parse_header(pdu)
            seen.append(hdr)
            if hdr["command_id"] != 0x00000004:
                raise ValueError("second PDU was 0x%08x, not submit_sm" % hdr["command_id"])
            body = message_id.encode("ascii") + b"\x00"
            resp = struct.pack(">IIII", HEADER + len(body), 0x80000004, 0,
                               hdr["sequence_number"]) + body
            conn.sendall(resp)
    finally:
        conn.close()


def _pdu(cmd_id, seq, body):
    return (struct.pack(">IIII", HEADER + len(body), cmd_id, 0, seq) + body).hex()


def _cstr(text):
    return text.encode("ascii") + b"\x00"


def self_test():
    """Loopback: bind_transceiver, then submit_sm, answered by a fake SMSC."""
    checks = []

    bind_hex = _pdu(0x00000009, 1, _cstr("est") + _cstr("pw") + _cstr("") +
                    b"\x34" + b"\x00\x00" + _cstr(""))
    submit_hex = _pdu(0x00000004, 2, _cstr("") + b"\x05\x00" + _cstr("12345") +
                      b"\x01\x01" + _cstr("67890") + b"\x00\x00\x00" +
                      b"\x00\x00" + b"\x00" + b"\x00" + b"\x00" + b"\x00" +
                      b"\x05" + bytes.fromhex("48656c6c6f"))
    checks.append(("bind-length", int(bind_hex[0:8], 16) == len(bind_hex) // 2))
    checks.append(("submit-length", int(submit_hex[0:8], 16) == len(submit_hex) // 2))
    checks.append(("submit-command-id", submit_hex[8:16] == "00000004"))
    checks.append(("sequence-number", submit_hex[24:32] == "00000002"))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen = []
    worker = threading.Thread(target=_fake_smsc,
                              args=(listener, ["cafebabe"], seen), daemon=True)
    worker.start()
    rc = run_transaction("127.0.0.1", port, 5, bind_hex, [submit_hex], False)
    worker.join(timeout=5)
    listener.close()

    checks.append(("transaction-rc", rc == 0))
    checks.append(("pdu-count", len(seen) == 2))
    if len(seen) == 2:
        checks.append(("bind-primary", seen[0]["command_id"] == 0x00000009))
        checks.append(("bind-seq", seen[0]["sequence_number"] == 1))
        checks.append(("submit-primary", seen[1]["command_id"] == 0x00000004))
        checks.append(("submit-seq", seen[1]["sequence_number"] == 2))
        checks.append(("submit-status", seen[1]["command_status"] == 0))
    checks.append(("parse-header", parse_header(bytes.fromhex(submit_hex))["command_id"] == 4))
    checks.append(("status-name", status_name(0x00000000) == "esme_rok"))
    checks.append(("status-unknown", status_name(0xDEADBEEF) == "status_0xdeadbeef"))
    checks.append(("cmd-name", cmd_name(0x80000004) == "submit_sm_resp"))
    # the reader's inverse, cross-checked against the module's own packer
    checks.append(("gsm7-hello",
                   gsm7_unpack(bytes.fromhex("e8329bfd06")) == "hello"))
    checks.append(("gsm7-first-breath",
                   gsm7_unpack(bytes.fromhex("e6b47c4e0789e5e5301d0d")) == "first breath"))
    # a submit_sm body decoded the way the loopback SMSC decodes it: c-strings
    # for service_type/schedule/validity mean an empty one is a single NULL octet
    submit_body = (_cstr("") + b"\x05\x00" + _cstr("15551234567")
                   + b"\x01\x01" + _cstr("15559876543")
                   + b"\x00\x00\x00"            # esm_class, protocol_id, priority
                   + _cstr("") + _cstr("")          # schedule_delivery_time, validity_period
                   + b"\x00\x00\x00\x00"          # registered_delivery, replace, dcs, default
                   + b"\x05" + bytes.fromhex("e8329bfd06"))
    src, dst, dcs, short = decode_submit(submit_body)
    checks.append(("submit-decode-src", src == "15551234567"))
    checks.append(("submit-decode-dst", dst == "15559876543"))
    checks.append(("submit-decode-dcs", dcs == 0x00))
    checks.append(("submit-decode-short", short == bytes.fromhex("e8329bfd06")))
    # a truncated PDU must be refused, not guessed at
    try:
        parse_header(bytes.fromhex("00000010"))
        checks.append(("truncated-refused", False))
    except ValueError:
        checks.append(("truncated-refused", True))
    # a command_length that disagrees with the bytes on the wire must be refused
    try:
        parse_header(bytes.fromhex("00000030") + b"\x00" * 12)
        checks.append(("length-mismatch-refused", False))
    except ValueError:
        checks.append(("length-mismatch-refused", True))
    # a body field with no NUL terminator must be refused
    try:
        cstring(b"abc", 0, 16, "system_id")
        checks.append(("unterminated-cstring-refused", False))
    except ValueError:
        checks.append(("unterminated-cstring-refused", True))
    # a C-Octet String longer than its field maximum must be refused
    try:
        cstring(b"toolongsystemid\x00", 0, 4, "system_id")
        checks.append(("overlong-cstring-refused", False))
    except ValueError:
        checks.append(("overlong-cstring-refused", True))

    row("checks", str(len(checks)))
    failed = 0
    for name, ok in checks:
        if not ok:
            failed += 1
            row("FAIL", name)
    row("failed", str(failed))
    row("result", "PASS" if not failed else "FAIL")
    return 0 if not failed else 1


# ── serve mode: the SMSC end of the same session ──────────────────────────
# A loopback SMSC is the only way to watch a submit land without a carrier
# account: it binds anyone, answers every PDU, decodes the submitted message and
# routes nothing. It is a simulator and says so -- no subscription, no handset.
def serve(listen_addr, port, once, timeout):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((listen_addr, port))
    except OSError as exc:
        return die("listen", "%s:%d" % (listen_addr, port),
                   "cannot listen on %s:%d: %s" % (listen_addr, port, exc), 3)
    srv.listen(8)
    row("listen", "%s:%d" % (listen_addr, port))
    row("mode", "loopback-smsc")
    row("routes_nothing", "this answers PDUs and decodes them; it delivers no message")
    served = 0
    message_seq = 0
    try:
        while True:
            conn, peer = srv.accept()
            row("accepted", "%s:%d" % (peer[0], peer[1]))
            deadline_master = time.monotonic() + timeout
            try:
                while True:
                    deadline = time.monotonic() + timeout
                    try:
                        pdu = recv_pdu(conn, deadline)
                    except (TimeoutError, ConnectionError):
                        break
                    hdr = parse_header(pdu)
                    row("serve_rx_command_id",
                        "0x%08x\t%s" % (hdr["command_id"], cmd_name(hdr["command_id"])))
                    row("serve_rx_sequence_number", "%08x" % hdr["sequence_number"])
                    row("serve_rx_octets", str(hdr["command_length"]))
                    status = 0
                    body = b"\x00"
                    if hdr["command_id"] == 0x00000009:
                        try:
                            system_id, _ = cstring(hdr["body"], 0, 16, "system_id")
                        except ValueError:
                            system_id = ""
                            status = 0x0000000F
                        row("bind_system_id", system_id or "(null)")
                        body = (system_id or "loopback").encode("ascii") + b"\x00"
                        resp_id = 0x80000009
                    elif hdr["command_id"] == 0x00000004:
                        message_seq += 1
                        message_id = "loopback%04d" % message_seq
                        try:
                            src, dst, dcs, short = decode_submit(hdr["body"])
                            row("serve_submit_source", src)
                            row("serve_submit_destination", dst)
                            row("serve_submit_data_coding", "0x%02x" % dcs)
                            row("serve_short_message", short.hex())
                            if dcs == 0x00:
                                try:
                                    row("serve_short_message_text",
                                        gsm7_unpack(short, len(short) * 8 // 7).rstrip("@"))
                                except IndexError:
                                    row("serve_short_message_text", "(not 7-bit)")
                        except ValueError as exc:
                            status = 0x00000001
                            row("serve_body_problem", str(exc))
                        body = message_id.encode("ascii") + b"\x00"
                        row("serve_message_id", message_id if not status else "-")
                        resp_id = 0x80000004
                    elif hdr["command_id"] == 0x00000015:
                        body = b""
                        resp_id = 0x80000015
                    elif hdr["command_id"] == 0x00000006:
                        body = b""
                        resp_id = 0x80000006
                        conn.sendall(struct.pack(">IIII", HEADER, resp_id, 0,
                                                 hdr["sequence_number"]))
                        served += 1
                        row("serve_answered", "%s\t0x%08x" % (cmd_name(0x80000006), 0))
                        break
                    else:
                        body = b""
                        status = 0x00000003
                        resp_id = hdr["command_id"] | 0x80000000
                    resp = struct.pack(">IIII", HEADER + len(body), resp_id, status,
                                       hdr["sequence_number"]) + body
                    conn.sendall(resp)
                    row("serve_answered", "0x%08x\t%s\t%s"
                        % (resp_id, cmd_name(resp_id), status_name(status)))
                    if status:
                        row("serve_refused", status_name(status))
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            served += 1
            row("clients", str(served))
            if once:
                break
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
    row("served", str(served))
    row("result", "serve-done")
    return 0


def decode_submit(body):
    """service_type, then the addresses, then the message: SMPP 3.4 5.2.5 order."""
    offset = 0
    _, offset = cstring(body, offset, 6, "service_type")
    offset += 2  # source_addr_ton, source_addr_npi
    src, offset = cstring(body, offset, 21, "source_addr")
    offset += 2  # dest_addr_ton, dest_addr_npi
    dst, offset = cstring(body, offset, 21, "destination_addr")
    offset += 3  # esm_class, protocol_id, priority_flag
    offset += 2  # schedule_delivery_time, validity_period (both NULL here)
    offset += 1  # registered_delivery
    offset += 1  # replace_if_present_flag
    dcs = body[offset]
    offset += 1
    offset += 1  # sm_default_msg_id
    sm_len = body[offset]
    offset += 1
    short = body[offset:offset + sm_len]
    if len(short) != sm_len:
        raise ValueError("sm_length says %d octets but %d arrived" % (sm_len, len(short)))
    return src, dst, dcs, short

def main(argv):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--host", default="")
    ap.add_argument("--port", type=int, default=2775)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--bind", default="")
    ap.add_argument("--submit", action="append", default=[])
    ap.add_argument("--no-bind", action="store_true")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.serve:
        if not (0 < args.port < 65536):
            return die("listen", "", "--port %d is outside 1..65535" % args.port, 2)
        return serve(args.listen, args.port, args.once, args.timeout)
    if not args.host:
        return die("connect", "", "--host is required; without an SMSC address there is nowhere to send", 2)
    if not args.bind and not args.submit and not args.no_bind:
        return die("connect", "", "nothing to send: pass --bind and/or --submit with a built PDU", 2)
    if not args.submit and args.bind and not args.no_bind:
        return die("connect", "", "only a bind would be sent; pass --submit or use the module's --smpp-build", 2)
    if not (0 < args.port < 65536):
        return die("connect", "", "--port %d is outside 1..65535" % args.port, 2)
    if not (0 < args.timeout <= 600):
        return die("connect", "", "--timeout %g is outside 0..600 seconds" % args.timeout, 2)
    return run_transaction(args.host, args.port, args.timeout,
                           args.bind, args.submit, args.no_bind)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
