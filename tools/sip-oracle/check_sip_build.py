#!/usr/bin/env python3
"""SIP builder checks for modules/30_volte_ims.sh.

Two independent reads of every message the builder emits:

  1. The bytes themselves. A fresh checker in this file (it shares no code with
     the module) re-derives the invariants RFC 3261 actually requires -- CRLF
     line endings, one header/body separator, the mandatory headers, and a
     Content-Length equal to the body's byte count.

  2. tshark's SIP dissector, which was written by someone else. Every header
     it reports is compared against what we told the builder to put there. A
     builder and a parser written by the same person agree with each other
     while both being wrong; a third party is the only way to see it.

The control at the end takes a message that passed both reads and breaks it in
five ways, requiring each break to be caught. A check that cannot fail is not
a check.

Exit 0 all agree, 1 a disagreement, 2 the check could not run (no tshark).
"""
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULE = os.path.join(ROOT, "modules", "30_volte_ims.sh")
TSHARK = shutil.which("tshark")

REQUESTS = ("register", "register-auth", "challenge", "invite")


# ── the module under test ──────────────────────────────────────────────
def build(kind, **kw):
    args = [kind] + ["%s=%s" % (k, v) for k, v in sorted(kw.items())]
    proc = subprocess.run(["bash", MODULE, "--sip-build"] + args,
                          capture_output=True)
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", "replace")


# ── an independent view of the bytes ───────────────────────────────────
def problems_with(raw, expect):
    """Return what is wrong with this message. Empty list means well formed."""
    out = []
    if b"\0" in raw:
        out.append("a NUL byte is in the message")
    # Every LF must be preceded by CR, and the message must end with CRLF.
    for i, ch in enumerate(raw):
        if ch == 0x0A and (i == 0 or raw[i - 1] != 0x0D):
            out.append("bare LF at byte %d (RFC 3261 wants CRLF)" % i)
            break
    if not raw.endswith(b"\r\n"):
        out.append("message does not end with CRLF")
    if raw.count(b"\r\n\r\n") != 1:
        out.append("expected exactly one header/body separator, found %d"
                   % raw.count(b"\r\n\r\n"))
        return out
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        out.append("no start line")
        return out
    start = lines[0].decode("utf-8", "replace")
    if expect.get("status"):
        want = "SIP/2.0 %s" % expect["status"]
        if not start.startswith(want):
            out.append("start line %r does not start with %r" % (start, want))
    else:
        want = expect.get("method", "")
        if not start.startswith(want + " "):
            out.append("start line %r is not a %s request" % (start, want))
        if not start.endswith(" SIP/2.0"):
            out.append("start line %r does not end with SIP/2.0" % start)

    headers = {}
    for ln in lines[1:]:
        if not ln:
            out.append("blank line inside the header block")
            continue
        if b":" not in ln:
            out.append("header line %r has no colon" % ln)
            continue
        k, v = ln.split(b":", 1)
        headers.setdefault(k.strip().lower().decode(), []).append(
            v.strip().decode("utf-8", "replace"))

    mandatory = ["via", "from", "to", "call-id", "cseq", "content-length"]
    if not expect.get("status"):
        # Max-Forwards is a request header (RFC 3261 20.22); a response has no
        # forwarding decision left to make, so requiring it here would demand a
        # 401 carry something the protocol says it must not.
        mandatory.append("max-forwards")
    if expect.get("contact"):
        mandatory.append("contact")
    for h in mandatory:
        if h not in headers:
            out.append("mandatory header %r is missing" % h)
        elif len(headers[h]) != 1:
            out.append("header %r appears %d times" % (h, len(headers[h])))

    if "content-length" not in headers:
        return out
    try:
        declared = int(headers["content-length"][0])
    except (TypeError, ValueError):
        out.append("Content-Length is not a number")
        return out
    if declared != len(body):
        out.append("Content-Length says %d, the body is %d bytes"
                   % (declared, len(body)))
    if body and "content-type" not in headers:
        out.append("a body is present with no Content-Type")
    if not body and "content-type" in headers:
        out.append("a Content-Type is present with no body")
    # A sip: URI must carry a host part; a Via needs a branch.
    via = headers.get("via", [""])[0]
    if "branch=" not in via:
        out.append("Via has no branch parameter")
    if expect.get("from_tag") and ("tag=" not in headers.get("from", [""])[0]):
        out.append("From has no tag")
    return out


# ── a pcap tshark will dissect ─────────────────────────────────────────
def ethernet_udp(payload, sport=5060, dport=5060):
    eth = bytes.fromhex("0000000000010000000000020800")
    total = 20 + 8 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     socket.inet_aton("10.0.0.9"), socket.inet_aton("10.0.0.1"))
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return eth + ip + udp + payload


def write_pcap(path, payload):
    frame = ethernet_udp(payload)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        fh.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
        fh.write(frame)


def dissect(path, fields):
    cmd = [TSHARK, "-r", path, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    line = proc.stdout.splitlines()[0] if proc.stdout.splitlines() else ""
    vals = line.split("\t")
    while len(vals) < len(fields):
        vals.append("")
    return dict(zip(fields, vals))


FIELDS = ["sip.Method", "sip.Status-Code", "sip.r-uri", "sip.from.user",
          "sip.from.tag", "sip.to.user", "sip.to.tag", "sip.Call-ID",
          "sip.CSeq.seq", "sip.CSeq.method", "sip.Contact",
          "sip.Content-Length", "sip.Content-Type", "sip.Authorization",
          "sip.WWW-Authenticate", "sip.pai.user", "sip.msg_body"]

DOMAIN = "ims.mnc001.mcc310.3gppnetwork.org"
IMPI = "310150123456789@" + DOMAIN
CONTACT = "310150123456789@10.0.0.9:5060"
CALLID = "deadbeefcafe0001@10.0.0.9"
BRANCH = "z9hG4bKfixed0001"

COMMON = dict(impi=IMPI, contact=CONTACT, host="10.0.0.9", port="5060",
              domain=DOMAIN, branch=BRANCH, callid=CALLID, from_tag="ftag1")

CASES = [
    ("register", dict(COMMON, cseq="1", expires="600000"),
     dict(method="REGISTER", contact=True, from_tag="ftag1",
          tshark={"sip.Method": "REGISTER", "sip.Status-Code": "",
                  "sip.from.user": "310150123456789", "sip.from.tag": "ftag1",
                  "sip.to.user": "310150123456789", "sip.to.tag": "",
                  "sip.Call-ID": CALLID, "sip.CSeq.seq": "1",
                  "sip.CSeq.method": "REGISTER",
                  "sip.Contact": "<sip:%s>;expires=600000" % CONTACT,
                  "sip.Content-Length": "0", "sip.Content-Type": "",
                  "sip.msg_body": ""})),
    ("register-auth", dict(COMMON, cseq="2", expires="600000",
                           realm=DOMAIN, nonce="cafebabe00", uri="sip:" + DOMAIN,
                           response="0123456789abcdef0123456789abcdef",
                           algorithm="AKAv1-MD5", qop="auth", nc="00000001",
                           cnonce="1234abcd"),
     dict(method="REGISTER", contact=True, from_tag="ftag1",
          tshark={"sip.Method": "REGISTER", "sip.CSeq.method": "REGISTER",
                  "sip.CSeq.seq": "2", "sip.Content-Length": "0"})),
    ("challenge", dict(COMMON, cseq="1", to_tag="ttag9", realm=DOMAIN,
                       nonce="cafebabe00", algorithm="AKAv1-MD5", qop="auth"),
     dict(status="401 Unauthorized", from_tag="ftag1",
          tshark={"sip.Method": "", "sip.Status-Code": "401",
                  "sip.from.user": "310150123456789", "sip.from.tag": "ftag1",
                  "sip.to.user": "310150123456789", "sip.to.tag": "ttag9",
                  "sip.CSeq.seq": "1", "sip.CSeq.method": "REGISTER",
                  "sip.Content-Length": "0"})),
    ("invite", dict(COMMON, cseq="2", to_tag="ttag9", rtp_port="49152",
                    media_ip="10.0.0.9"),
     dict(method="INVITE", contact=True, from_tag="ftag1",
          tshark={"sip.Method": "INVITE", "sip.CSeq.method": "INVITE",
                  "sip.CSeq.seq": "2", "sip.to.tag": "ttag9",
                  "sip.Content-Type": "application/sdp"})),
]


def main():
    if not TSHARK:
        print("SKIP\tno tshark: it is the independent dissector this check "
              "compares against", file=sys.stderr)
        return 2
    failures = []
    tmp = tempfile.mkdtemp(prefix="sip-oracle-")

    for kind, kw, expect in CASES:
        rc, raw, err = build(kind, **kw)
        if rc != 0:
            failures.append("%s: the builder refused a valid message (rc %d): %s"
                            % (kind, rc, err.strip()))
            continue
        for p in problems_with(raw, expect):
            failures.append("%s: %s" % (kind, p))

        path = os.path.join(tmp, kind + ".pcap")
        write_pcap(path, raw)
        got = dissect(path, FIELDS)
        if got is None:
            failures.append("%s: tshark could not read the capture" % kind)
            continue
        for field, want in expect.get("tshark", {}).items():
            if got[field] != want:
                failures.append("%s: tshark reports %s = %r, built %r"
                                % (kind, field, got[field], want))

        if kind == "invite":
            body = raw.split(b"\r\n\r\n", 1)[1]
            if got["sip.msg_body"].lower() != body.hex():
                failures.append("invite: tshark's body does not match the "
                                "bytes after the separator")
            # The offer lists PCMU and PCMA first because the media leg can
            # actually encode and decode those two, and AMR last because an
            # IMS core expects to see it. All three must be in the same audio
            # line: a second m= line would be a second stream nobody answers.
            if b"m=audio 49152 RTP/AVP 0 8 96" not in body:
                failures.append("invite: the audio line does not offer "
                                "PCMU, PCMA and AMR")
            for line in (b"a=rtpmap:0 PCMU/8000", b"a=rtpmap:8 PCMA/8000",
                         b"a=rtpmap:96 AMR/8000", b"a=ptime:20"):
                if line not in body:
                    failures.append("invite: the SDP lacks %r"
                                    % line.decode())
        if kind == "register-auth":
            auth = got["sip.Authorization"]
            for piece in ('username="310150123456789"', 'realm="%s"' % DOMAIN,
                          'nonce="cafebabe00"', "algorithm=AKAv1-MD5",
                          "qop=auth", "nc=00000001", 'cnonce="1234abcd"'):
                if piece not in auth:
                    failures.append("register-auth: Authorization lacks %r "
                                    "(tshark read %r)" % (piece, auth))
        if kind == "challenge":
            chal = got["sip.WWW-Authenticate"]
            for piece in ('realm="%s"' % DOMAIN, 'nonce="cafebabe00"',
                          "algorithm=AKAv1-MD5", 'qop="auth"'):
                if piece not in chal:
                    failures.append("challenge: WWW-Authenticate lacks %r "
                                    "(tshark read %r)" % (piece, chal))

    # the spoofed REGISTER: the same strictness applies to the message the
    # module sends on its own, not just to the one a caller asked for
    proc = subprocess.run(["bash", MODULE, "--register-spoof", IMPI, CONTACT],
                          capture_output=True)
    if proc.returncode != 0:
        failures.append("spoof: refused a valid registration (rc %d): %s"
                        % (proc.returncode,
                           proc.stderr.decode("utf-8", "replace").strip()))
    else:
        raw = proc.stdout
        for p in problems_with(raw, dict(method="REGISTER", contact=True,
                                         from_tag="any")):
            failures.append("spoof: %s" % p)
        if b"attack\t" in raw:
            failures.append("spoof: the attack note is inside the datagram, "
                            "after a Content-Length of 0")
        if b"P-Asserted-Identity: <sip:%s>" % IMPI.encode() not in raw:
            failures.append("spoof: no P-Asserted-Identity for the identity "
                            "the message claims")
        path = os.path.join(tmp, "spoof.pcap")
        write_pcap(path, raw)
        got = dissect(path, FIELDS)
        if got is None:
            failures.append("spoof: tshark could not read the capture")
        else:
            for field, want in (("sip.Method", "REGISTER"),
                                ("sip.Contact", "<sip:%s>;expires=600000" % CONTACT),
                                ("sip.pai.user", "310150123456789"),
                                ("sip.Content-Length", "0"),
                                ("sip.msg_body", "")):
                if got[field] != want:
                    failures.append("spoof: tshark reports %s = %r, built %r"
                                    % (field, got[field], want))

    # header injection: a value with a CRLF in it must be refused, not emitted
    rc, raw, err = build("register", impi="a@b\r\nX-Evil: 1")
    if rc == 0:
        failures.append("a CRLF inside the IMPI was accepted and built")
    if raw:
        failures.append("a rejected build still wrote %d bytes to stdout" % len(raw))
    if rc == 0 or "ERROR" not in err:
        failures.append("a rejected build did not say why on stderr")

    # unknown kind and missing kind must be usage errors, not empty successes
    for args, label in ((["nosuchkind"], "unknown kind"), ([], "no kind")):
        proc = subprocess.run(["bash", MODULE, "--sip-build"] + args,
                              capture_output=True)
        if proc.returncode != 2:
            failures.append("%s: exit %d, want 2"
                            % (label, proc.returncode))
        if proc.stdout:
            failures.append("%s: wrote a message anyway" % label)

    # ── the control ────────────────────────────────────────────────────
    rc, good, _ = build("invite", **dict(COMMON, cseq="2", to_tag="ttag9"))
    expect = dict(method="INVITE", contact=True, from_tag="ftag1")
    if rc != 0 or problems_with(good, expect):
        failures.append("control: the message chosen to corrupt is already "
                        "malformed, so the control proves nothing")
    else:
        head, body = good.split(b"\r\n\r\n", 1)
        mutants = [
            ("LF-only line endings", good.replace(b"\r\n", b"\n"), expect),
            ("no Via header", b"\r\n".join(
                ln for ln in head.split(b"\r\n") if not ln.startswith(b"Via:"))
             + b"\r\n\r\n" + body, expect),
            ("Content-Length five too large", head.replace(
                b"Content-Length: %d" % len(body),
                b"Content-Length: %d" % (len(body) + 5)) + b"\r\n\r\n" + body,
             expect),
            ("a second Content-Length", head + b"\r\nContent-Length: 0"
             + b"\r\n\r\n" + body, expect),
            ("no header/body separator",
             head + b"\r\n" + body, expect),
            # exactly the defect this file was written for: a diagnostics line
            # on the wire after a Content-Length that says there is no body
            ("a note after an honest zero Content-Length",
             head.replace(b"Content-Length: %d" % len(body),
                          b"Content-Length: 0") + b"\r\n\r\nattack\tx\r\n",
             expect),
        ]
        for label, mutant, exp in mutants:
            if not problems_with(mutant, exp):
                failures.append("control FAIL: %r was not caught" % label)

    print("CASES\t%d" % len(CASES))
    for f in failures:
        print("FAIL\t%s" % f)
    print("MISMATCHES\t%d" % len(failures))
    print("RESULT\t%s" % ("PASS" if not failures else "FAIL(%d)" % len(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
