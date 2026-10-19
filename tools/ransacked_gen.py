#!/usr/bin/env python3
#
#  ransacked_gen.py — the four message-shape families from the RANSacked
#  corpus, each generated from a real base message this tree already builds.
#
#  Why families and not one file per CVE: the report's own §5 groups 119
#  findings into a handful of recurring shapes -- a length field trusted past
#  the buffer, an ASN.1 container whose declared member count disagrees with
#  the rows present, a check that exists in one branch and not the other, and
#  a decode whose failure is used as if it were success.  An entry with a CVE
#  number is one instance of a shape.  A crash in a lab core is attributable to
#  the shape, not to the number, only if the shape is what the corpus varies.
#
#  Everything here is a message. Nothing here sends anything: the module's
#  contract is build/handoff, and the handoff is a person with a lab core.
#
#  usage: ransacked_gen.py list
#         ransacked_gen.py gen <pattern> [--out DIR]
#         ransacked_gen.py bases
#         ransacked_gen.py selftest

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# The three base messages, each produced by the codec that owns its layout.
# `selftest` re-derives them from those codecs, so a stale constant here is a
# failing assertion rather than a corpus that tests the wrong bytes.
NAS_BASE = "074101090902080121436587f9"
S1AP_BASE = "000c0021000003000800020002000000020001001a000e0d074101090902080121436587f9"
NGAP_BASE = None  # filled by _ngap_base(); see below

PATTERNS = ("len-unchecked", "asn1c-rows", "branch-asymmetry", "trust-failed-decode")

PATTERN_CAUSE = {
    "len-unchecked": "a length field that describes more, or less, than the bytes that follow it",
    "asn1c-rows": "a container whose declared member count disagrees with the members present",
    "branch-asymmetry": "a check present in one branch of the message and absent in the other",
    "trust-failed-decode": "a decode that failed, whose partial result is used anyway",
}


# ── container walking ────────────────────────────────────────────────────
def _open_len(buf, i):
    """One-octet open type length, plus its width.  The long form is not used
    by any base here, and refusing it loudly beats silently mis-parsing."""
    if i >= len(buf):
        raise ValueError("open type length past end")
    n = buf[i]
    if n & 0x80:
        raise ValueError("long-form open type length is not handled")
    return n, 1


def parse_container(pdu):
    """Split an S1AP/NGAP PDU into envelope + IE fields (id, crit, body)."""
    buf = bytes.fromhex(pdu)
    if len(buf) < 8:
        raise ValueError("PDU too short to be an initiatingMessage")
    body_len, width = _open_len(buf, 3)
    body = buf[3 + width:3 + width + body_len]
    if len(body) < 3:
        raise ValueError("container shorter than its own header")
    count = int.from_bytes(body[1:3], "big")
    i = 3
    ies = []
    for _ in range(count):
        if i + 3 > len(body):
            # A container that declares more rows than it carries is one of the
            # shapes this corpus exists to emit, so it must parse, not throw.
            return {"head": buf[:3], "count": count, "ies": ies,
                    "tail": b"", "declared": count, "found": len(ies)}
        ie_id = int.from_bytes(body[i:i + 2], "big")
        crit = body[i + 2]
        n, w = _open_len(body, i + 3)
        start = i + 3 + w
        ies.append({"id": ie_id, "crit": crit, "body": body[start:start + n]})
        i = start + n
    return {"head": buf[:3], "count": count, "ies": ies, "tail": body[i:],
            "declared": count, "found": len(ies)}


def build_container(parsed, count=None, ies=None, tail=None, head=None,
                    ie_len=None, open_len=None):
    """Re-serialise a container, with the option to LIE about a length.

    A corpus of length-confusion cases needs a writer that can emit a field
    that describes something other than what follows it.  That is the whole
    point, so the lie is an explicit argument rather than a byte patch that
    silently depends on where an IE happens to sit.
    """
    ies = parsed["ies"] if ies is None else ies
    tail = parsed["tail"] if tail is None else tail
    count = len(ies) if count is None else count
    ie_len = ie_len or {}
    body = bytes([0x00]) + count.to_bytes(2, "big")
    for i, ie in enumerate(ies):
        declared = ie_len.get(i, len(ie["body"]))
        body += ie["id"].to_bytes(2, "big") + bytes([ie["crit"]])
        body += bytes([declared & 0xFF]) + ie["body"]
    body += tail
    length = len(body) if open_len is None else open_len
    return ((parsed["head"] if head is None else head) +
            bytes([length & 0xFF]) + body).hex()


# ── the four families ────────────────────────────────────────────────────
def _variant(name, pattern, hexstr, rule, expected):
    return {"name": name, "pattern": pattern, "hex": hexstr,
            "octets": len(hexstr) // 2, "rule": rule, "expected": expected}


def family_len_unchecked():
    out = []
    # NAS: the mobile identity length counts the type octet, so a 15-digit IMSI
    # arrives as 0x09.  A reader that trusts the field and copies it reads past
    # the buffer; a reader that trusts it as a *count of digits* reads short.
    out.append(_variant("nas-identity-len-32", "len-unchecked",
                        "074101" + "20" + "09" + "02080121436587f9",
                        "identity length 0x09 -> 0x20, digits unchanged",
                        "reader copies 32 octets where 8 exist"))
    out.append(_variant("nas-identity-len-255", "len-unchecked",
                        "074101" + "ff" + "09" + "02080121436587f9",
                        "identity length 0x09 -> 0xff",
                        "reader copies 255 octets, or rejects the message"))
    out.append(_variant("nas-identity-len-short", "len-unchecked",
                        "074101" + "01" + "09" + "02080121436587f9",
                        "identity length 0x09 -> 0x01, digit octets left in place",
                        "reader takes one octet and the rest is a second IE"))
    # S1AP: the NAS-PDU IE's open type says how long the NAS is.  The IE length
    # and the container length must agree; one of them can be made to lie.
    p = parse_container(S1AP_BASE)
    ies = [dict(ie) for ie in p["ies"]]
    for ie in ies:
        if ie["id"] == 0x001a:  # id-NAS-PDU
            ie["body"] = bytes([len(ie["body"])]) + ie["body"]
    nas_at = next(i for i, ie in enumerate(p["ies"]) if ie["id"] == 0x001A)
    out.append(_variant("s1ap-nas-ie-len-ff", "len-unchecked",
                        build_container(p, ies=ies, ie_len={nas_at: 0xFF}),
                        "NAS-PDU open type length -> 0xff, body unchanged",
                        "reader copies 255 octets out of a 37-octet PDU"))
    out.append(_variant("s1ap-nas-ie-len-zero", "len-unchecked",
                        build_container(p, ies=ies, ie_len={nas_at: 0x00}),
                        "NAS-PDU open type length -> 0x00, body unchanged",
                        "reader takes an empty NAS and leaves 14 octets unread"))
    # NGAP: same shape in a different container, to show the family is not
    # about one protocol.
    ng = parse_container(_ngap_base())
    ngies = [dict(ie) for ie in ng["ies"]]
    for i, ie in enumerate(ngies):
        if i == 0:
            ie["body"] = b"\x00" + ie["body"]
    out.append(_variant("ngap-first-ie-len-ff", "len-unchecked",
                        build_container(ng, ies=ngies, ie_len={0: 0xFF}),
                        "first NGAP IE open type length -> 0xff",
                        "reader copies past the container"))
    return out


def family_asn1c_rows():
    out = []
    p = parse_container(S1AP_BASE)
    out.append(_variant("s1ap-count-plus-one", "asn1c-rows",
                        build_container(p, count=p["count"] + 1),
                        "container count %d -> %d, members unchanged" % (p["count"], p["count"] + 1),
                        "asn1c walks one row past the member list"))
    out.append(_variant("s1ap-count-minus-one", "asn1c-rows",
                        build_container(p, count=p["count"] - 1),
                        "container count %d -> %d, members unchanged" % (p["count"], p["count"] - 1),
                        "one member is never examined"))
    out.append(_variant("s1ap-count-max", "asn1c-rows",
                        build_container(p, count=0xFFFF),
                        "container count -> 0xffff",
                        "reader iterates 65535 rows"))
    out.append(_variant("s1ap-unassigned-ie", "asn1c-rows",
                        build_container(p, ies=[dict(p["ies"][0], id=0x7FFF)] + p["ies"][1:]),
                        "first IE id -> 0x7fff (unassigned)",
                        "reader finds no member for the id and dereferences the null one"))
    ng = parse_container(_ngap_base())
    out.append(_variant("ngap-count-plus-one", "asn1c-rows",
                        build_container(ng, count=ng["count"] + 1),
                        "container count + 1",
                        "row/member mismatch in the NGAP container"))
    out.append(_variant("ngap-unassigned-ie", "asn1c-rows",
                        build_container(ng, ies=[dict(ng["ies"][0], id=0x7FFF)] + ng["ies"][1:]),
                        "first NGAP IE id -> 0x7fff",
                        "no member for the id, null dereference"))
    return out


def family_branch_asymmetry():
    out = []
    p = parse_container(S1AP_BASE)
    out.append(_variant("s1ap-mandatory-absent", "branch-asymmetry",
                        build_container(p, ies=p["ies"][1:]),
                        "first IE (mandatory) removed, count follows",
                        "reader that checks the first IE in one path only now reads what is not there"))
    out.append(_variant("s1ap-criticality-flip", "branch-asymmetry",
                        build_container(p, ies=[dict(p["ies"][0], crit=0x40)] + p["ies"][1:]),
                        "first IE criticality reject 0x00 -> ignore 0x40",
                        "a decoder that honours criticality in one branch skips what the other reads"))
    out.append(_variant("s1ap-procedure-swap", "branch-asymmetry",
                        build_container(p, head=b"\x00\x15\x00"),
                        "procedureCode 0x0c (InitialUEMessage) -> 0x15 (Paging)",
                        "the body is read by the Paging handler, which has different checks"))
    out.append(_variant("s1ap-choice-swap", "branch-asymmetry",
                        build_container(p, head=b"\x20\x0c\x00"),
                        "CHOICE 0x00 (initiatingMessage) -> 0x20 (successfulOutcome)",
                        "the successfulOutcome branch accepts a body only initiating handles"))
    ng = parse_container(_ngap_base())
    out.append(_variant("ngap-procedure-swap", "branch-asymmetry",
                        build_container(ng, head=bytes.fromhex(_ngap_base())[:1] + b"\x0e" + bytes.fromhex(_ngap_base())[2:3]),
                        "NGAP procedureCode -> 0x0e (a different procedure)",
                        "the other handler's validation is the one that runs"))
    out.append(_variant("ngap-choice-swap", "branch-asymmetry",
                        build_container(ng, head=b"\x20" + bytes.fromhex(_ngap_base())[1:3]),
                        "NGAP CHOICE initiatingMessage -> successfulOutcome",
                        "unsupported branch/body tuple"))
    return out


def family_trust_failed_decode():
    out = []
    p = parse_container(S1AP_BASE)
    trunc = [dict(ie) for ie in p["ies"]]
    trunc[-1]["body"] = trunc[-1]["body"][:4]
    out.append(_variant("s1ap-truncated-last-ie", "trust-failed-decode",
                        build_container(p, ies=trunc),
                        "last IE body cut to 4 octets, declared lengths kept",
                        "decode fails partway; a reader that keeps the struct reads defaults"))
    out.append(_variant("s1ap-trailing-garbage", "trust-failed-decode",
                        build_container(p, tail=b"\xde\xad\xbe\xef"),
                        "4 octets appended after the container",
                        "decode stops cleanly and the trailing bytes are never validated"))
    out.append(_variant("s1ap-zero-length-ie", "trust-failed-decode",
                        build_container(p, ies=[dict(p["ies"][0], body=b"")] + p["ies"][1:]),
                        "first IE body emptied, lengths follow",
                        "an IE with no value, read as a null pointer"))
    ng = parse_container(_ngap_base())
    ngtrunc = [dict(ie) for ie in ng["ies"]]
    ngtrunc[-1]["body"] = ngtrunc[-1]["body"][:3]
    out.append(_variant("ngap-truncated-last-ie", "trust-failed-decode",
                        build_container(ng, ies=ngtrunc),
                        "last NGAP IE body cut to 3 octets",
                        "decode fails partway, partial struct used"))
    out.append(_variant("ngap-trailing-garbage", "trust-failed-decode",
                        build_container(ng, tail=b"\xde\xad\xbe\xef"),
                        "4 octets appended after the NGAP container",
                        "decode stops cleanly and the trailing bytes are never validated"))
    out.append(_variant("nas-unsupported-message-type", "trust-failed-decode",
                        NAS_BASE[:2] + "7f" + NAS_BASE[4:],
                        "NAS message type 0x41 (Attach Request) -> 0x7f (unassigned)",
                        "decoder rejects the type and the caller uses the empty message"))
    return out


FAMILIES = {
    "len-unchecked": family_len_unchecked,
    "asn1c-rows": family_asn1c_rows,
    "branch-asymmetry": family_branch_asymmetry,
    "trust-failed-decode": family_trust_failed_decode,
}


def _ngap_base():
    """Ask the NGAP codec for the base, so this file never restates a layout."""
    global NGAP_BASE
    if NGAP_BASE:
        return NGAP_BASE
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "ngap_asn1.py"), "initial-ue",
         "--ran-ue-id", "0x01", "--nas", NAS_BASE],
        capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if line.startswith("hex\t"):
            NGAP_BASE = line.split("\t", 1)[1].strip()
            return NGAP_BASE
    raise SystemExit("ngap_asn1.py did not print a hex row:\n" + out.stderr)


def emit(rows, out_dir):
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    for i, row in enumerate(rows, 1):
        if out_dir:
            path = os.path.join(out_dir, "%02d-%s.hex" % (i, row["name"]))
            with open(path, "w") as f:
                f.write(row["hex"] + "\n")
            row["file"] = path
    sys.stdout.write("variant\tpattern\toctets\tname\trule\texpected\n")
    for row in rows:
        sys.stdout.write("%s\t%s\t%d\t%s\t%s\t%s\n" % (
            row.get("file", "-"), row["pattern"], row["octets"],
            row["name"], row["rule"], row["expected"]))
        sys.stdout.write("hex.%s\t%s\n" % (row["name"], row["hex"]))


def selftest():
    fails = 0

    def chk(name, ok, detail=""):
        nonlocal fails
        if not ok:
            fails += 1
        sys.stdout.write("%-38s %s%s\n" % (name, "PASS" if ok else "FAIL", "" if ok else "  " + detail))

    # Bases are re-derived, not trusted: a codec change must break this loud.
    out = subprocess.run([sys.executable, os.path.join(HERE, "s1ap_asn1.py"),
                          "initial-ue", "--mme-ue-id", "0x1", "--enb-ue-id", "0x2",
                          "--nas", NAS_BASE], capture_output=True, text=True)
    got = next((l.split("\t", 1)[1] for l in out.stdout.splitlines() if l.startswith("hex\t")), "")
    chk("s1ap-base-matches-codec", got.strip() == S1AP_BASE, got.strip())

    all_rows = []
    for pattern in PATTERNS:
        rows = FAMILIES[pattern]()
        all_rows += rows
        chk("family-%s-count" % pattern, len(rows) >= 5, str(len(rows)))
        chk("family-%s-labelled" % pattern, all(r["pattern"] == pattern for r in rows))

    chk("variant-names-unique", len({r["name"] for r in all_rows}) == len(all_rows))
    bad = [r["name"] for r in all_rows if len(r["hex"]) % 2]
    chk("every-variant-is-whole-octets", not bad, ",".join(bad))
    bad = [r["name"] for r in all_rows
           if not all(c in "0123456789abcdef" for c in r["hex"])]
    chk("every-variant-is-hex", not bad, ",".join(bad))
    chk("variant-total", len(all_rows) >= 20, str(len(all_rows)))

    # The claim each family makes must be arithmetic, not prose: a container
    # declaring more members than it carries is checkable, and is checked.
    base_p = parse_container(S1AP_BASE)
    lie = parse_container(build_container(base_p, count=base_p["count"] + 1))
    chk("count-lie-is-present",
        lie["declared"] == base_p["count"] + 1 and lie["found"] == base_p["count"],
        "declared %d found %d" % (lie["declared"], lie["found"]))

    # A truncation must actually shorten the PDU, or the family tests nothing.
    base_octets = len(S1AP_BASE) // 2
    trunc = next(r for r in all_rows if r["name"] == "s1ap-truncated-last-ie")
    chk("truncation-shortens", trunc["octets"] < base_octets,
        "%d vs %d" % (trunc["octets"], base_octets))
    # A trailing-garbage variant must be longer, for the same reason.
    tail = next(r for r in all_rows if r["name"] == "s1ap-trailing-garbage")
    chk("garbage-lengthens", tail["octets"] == base_octets + 4,
        "%d vs %d" % (tail["octets"], base_octets))
    # The procedure swap must differ in exactly one octet.
    swap = next(r for r in all_rows if r["name"] == "s1ap-procedure-swap")
    diff = sum(1 for a, b in zip(swap["hex"], S1AP_BASE) if a != b)
    chk("procedure-swap-one-octet", diff == 2 and swap["hex"][:2] == S1AP_BASE[:2],
        "%d hex digits differ" % diff)

    sys.stdout.write("\nRESULT %s (%d failed, %d variants)\n" % (
        "PASS" if fails == 0 else "FAIL", fails, len(all_rows)))
    return 0 if fails == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("verb", choices=("list", "gen", "bases", "selftest"))
    ap.add_argument("pattern", nargs="?", default="")
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)
    if args.verb == "list":
        sys.stdout.write("pattern\tcause\n")
        for pattern in PATTERNS:
            sys.stdout.write("%s\t%s\n" % (pattern, PATTERN_CAUSE[pattern]))
        return 0
    if args.verb == "bases":
        sys.stdout.write("base\toctets\thex\n")
        for name, value in (("nas", NAS_BASE), ("s1ap", S1AP_BASE), ("ngap", _ngap_base())):
            sys.stdout.write("%s\t%d\t%s\n" % (name, len(value) // 2, value))
        return 0
    if args.verb == "selftest":
        return selftest()
    if args.pattern not in FAMILIES:
        sys.stderr.write("unknown pattern %r; one of %s\n" % (args.pattern, ", ".join(PATTERNS)))
        return 2
    emit(FAMILIES[args.pattern](), args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
