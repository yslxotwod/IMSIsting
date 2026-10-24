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


def main(argv):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--host", default="")
    ap.add_argument("--port", type=int, default=2775)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--bind", default="")
    ap.add_argument("--submit", action="append", default=[])
    ap.add_argument("--no-bind", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
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
