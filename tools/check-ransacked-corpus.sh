#!/usr/bin/env bash
#
#  check-ransacked-corpus.sh — the catalogue and the four generated families,
#  checked against the report and against tshark.
#
#  Two different questions, and they need two different referees:
#
#   * Does the catalogue say what the report says?  That is arithmetic over
#     the table: row counts, id shapes, which pattern each row claims, and a
#     sum over implementations that has to land on the row count.  A wrong
#     number here is a wrong claim about somebody else's research.
#
#   * Does each generated family actually produce a message that differs from
#     the base it came from?  That is tshark's question, and tshark is the only
#     referee this tree has for a malformed PDU.  Some variants are NOT
#     observable to a dissector — a flipped criticality changes a value the
#     dissector prints nowhere, and a trailing garbage octet after a complete
#     container is not dissected at all.  Those are named, not counted as
#     caught, because a corpus that reports 24/24 is a corpus that lied.
#
#  usage: tools/check-ransacked-corpus.sh [--verbose]

set -u

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="$ROOT/tools/ransacked_catalog.tsv"
GEN="$ROOT/tools/ransacked_gen.py"
TSHARK="${TSHARK:-tshark}"
VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

if ! command -v "$TSHARK" >/dev/null 2>&1; then
    printf 'SKIP\tno tshark on PATH; the corpus shapes cannot be refereed without a dissector\n'
    exit 0
fi
if [[ ! -r "$CATALOG" ]]; then
    printf 'FAIL\tthe catalogue is missing: %s\n' "$CATALOG"
    exit 1
fi
if [[ ! -r "$GEN" ]]; then
    printf 'FAIL\tthe generator is missing: %s\n' "$GEN"
    exit 1
fi

python3 - "$CATALOG" "$GEN" "$TSHARK" "$VERBOSE" <<'PY'
import os
import struct
import subprocess
import sys
import tempfile

CATALOG, GEN, TSHARK, VERBOSE = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(CATALOG)))

FAILS = []


def chk(name, got, want):
    ok = got == want
    if not ok:
        FAILS.append("%s want=%r got=%r" % (name, want, got))
    sys.stdout.write("ASSERTION %-32s %s%s\n" % (
        name, "PASS" if ok else "FAIL", "" if ok else "  want=%r got=%r" % (want, got)))


def note(text):
    sys.stdout.write("NOTE %s\n" % text)


# ── 1. the catalogue against itself ─────────────────────────────────────
rows = [l.rstrip("\n").split("\t") for l in open(CATALOG, encoding="utf-8") if l.strip()]
chk("catalog-rows", len(rows), 98)
chk("catalog-fields", max(len(r) for r in rows), 10)
chk("catalog-no-wide-rows", sum(1 for r in rows if len(r) != 10), 0)

ids = [r[0] for r in rows]
chk("catalog-row-key-unique", sorted(r[0] + "/" + r[1] for r in rows),
    sorted(set(r[0] + "/" + r[1] for r in rows)))
# CVE-2024-24447 is one CVE with two entries on the page (VULN-B04, VULN-B11):
# two different overflow sites in the same AMF routine. The primary id repeats
# on purpose; the row key is the pair.
note("primary ids repeat where one CVE covers two entries on the page: " +
     ", ".join(sorted({i for i in ids if ids.count(i) > 1})))
chk("catalog-id-shaped", sum(1 for i in ids if not (i.startswith("CVE-") or i.startswith("VULN-"))), 0)
alts = [a for r in rows for a in r[1].split(",") if a]
chk("catalog-alt-shaped", sum(1 for a in alts if not a.startswith("VULN-")), 0)
chk("catalog-alt-not-primary", len({*ids} & {*alts}), 0)

PATTERNS = {"len-unchecked", "asn1c-rows", "branch-asymmetry",
            "trust-failed-decode", "assert-unchecked", "other"}
chk("catalog-pattern-known", sum(1 for r in rows if r[5] not in PATTERNS), 0)
REACHES = {"nas-no-sim", "s1-access", "n2-access", "gtp-bearer", "unknown"}
chk("catalog-reach-known", sum(1 for r in rows if r[6] not in REACHES), 0)
chk("catalog-kind-known", sum(1 for r in rows if r[7] not in ("probe", "handoff")), 0)
chk("catalog-label-present", sum(1 for r in rows if len(r[9].strip()) < 20), 0)

IMPLS = {"Open5GS", "Magma", "Magma/OpenAirInterface", "OpenAirInterface",
         "Athonet", "SD-Core", "NextEPC", "srsRAN"}
chk("catalog-impl-known", sum(1 for r in rows if r[2] not in IMPLS), 0)
chk("catalog-impl-sum", sum(1 for r in rows), len(rows))
gens = {r[3] for r in rows}
chk("catalog-generation-known", sum(1 for g in gens if g not in ("LTE", "5G")), 0)

# The report's own totals, so a future edit to the table has to face them.
cve_rows = [r for r in rows if r[0].startswith("CVE-")]
note("the page claims 119 vulnerabilities; this catalogue holds %d entries "
     "(%d with a CVE, %d distict CVEs, %d VULN-only ids, %d alternate VULN ids). "
     "The gap is entries the page groups: one prose entry covering 19 assertion "
     "locations is one row here." % (
         len(rows), len(cve_rows), len({r[0] for r in cve_rows}),
         sum(1 for r in rows if r[0].startswith("VULN-")), len(alts)))

by_impl = {}
for r in rows:
    by_impl[r[2]] = by_impl.get(r[2], 0) + 1
note("per implementation: " + ", ".join("%s %d" % kv for kv in sorted(by_impl.items())))
by_proto = {}
for r in rows:
    by_proto[r[4]] = by_proto.get(r[4], 0) + 1
note("per protocol: " + ", ".join("%s %d" % kv for kv in sorted(by_proto.items())))
by_reach = {}
for r in rows:
    by_reach[r[6]] = by_reach.get(r[6], 0) + 1
note("per reach: " + ", ".join("%s %d" % kv for kv in sorted(by_reach.items())))

# Every probe row must name a protocol this tree can actually build. A probe
# against a protocol with no codec would be a probe that cannot run.
BUILDABLE = {"NAS", "S1AP", "NGAP", "GTP"}
chk("catalog-probes-are-buildable",
    sum(1 for r in rows if r[7] == "probe" and r[4] not in BUILDABLE), 0)

# ── 2. the families, against the generator ──────────────────────────────
FAMILIES = ("len-unchecked", "asn1c-rows", "branch-asymmetry", "trust-failed-decode")
variants = {}
for pattern in FAMILIES:
    out = subprocess.run([sys.executable, GEN, "gen", pattern],
                         capture_output=True, text=True)
    chk("gen-%s-rc" % pattern, out.returncode, 0)
    got = {}
    for line in out.stdout.splitlines():
        if line.startswith("hex."):
            key, value = line.split("\t", 1)
            got[key[4:]] = value.strip()
    chk("gen-%s-nonempty" % pattern, len(got) >= 5, True)
    chk("gen-%s-hex" % pattern,
        sum(1 for v in got.values() if not all(c in "0123456789abcdef" for c in v)), 0)
    variants.update(got)
chk("variant-total", len(variants), 24)

selftest = subprocess.run([sys.executable, GEN, "selftest"], capture_output=True, text=True)
chk("generator-selftest-rc", selftest.returncode, 0)

# ── 3. the families, against tshark ────────────────────────────────────
BASE = ("000c0021000003000800020002000000020001001a000e0d"
        "074101090902080121436587f9")

FIELDS = ["frame.protocols", "s1ap.procedureCode",
          "s1ap.protocolIEs", "s1ap.ProtocolIE_Field_element", "s1ap.iMSI",
          "ngap.procedureCode", "ngap.protocolIEs", "ngap.ProtocolIE_Field_element",
          "nas_eps.nas_msg_emm_type", "nas-5gs.mm.message_type"]

# Measured, not assumed: a variant is here because a dissector disagreed with
# the base. Variants in SAME were run and were NOT visible to the dissector --
# they are named in the output so nobody counts them as caught.
SAME = {"s1ap-unassigned-ie", "s1ap-criticality-flip",
        "s1ap-trailing-garbage", "s1ap-zero-length-ie"}
# The base is not a clean message and is not claimed to be: it is one NAS
# message that stops after the identity, so the dissector prints its own
# warnings about the fixture. Variants are compared on the printed fields AND
# on how many expert warnings the frame raises, which is what keeps a length
# lie visible even when the dissector's summary line reads the same.


def _ip_csum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + (hdr[i + 1] if i + 1 < len(hdr) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def write_pcap(path, payload_hex, ppid=18, sport=36412, dport=36412):
    data = bytes.fromhex(payload_hex)
    chunk = struct.pack("!BBH", 0, 0x03, 16 + len(data)) + \
        struct.pack("!IHHI", 0x11223344, 0, 0, ppid) + data
    while len(chunk) % 4:
        chunk += b"\x00"
    sctp = struct.pack("!HHII", sport, dport, 0x0A0B0C0D, 0) + chunk
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(sctp), 0, 0, 64, 132, 0,
                      b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    hdr = hdr[:10] + struct.pack("!H", _ip_csum(hdr)) + hdr[12:]
    frame = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + \
        b"\x08\x00" + hdr + sctp
    blob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + \
        struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    with open(path, "wb") as f:
        f.write(blob)


def facts(payload_hex, ppid, port, proto, tmp):
    path = os.path.join(tmp, "one.pcap")
    write_pcap(path, payload_hex, ppid, port, port)
    cmd = [TSHARK, "-r", path, "-d", "sctp.ppi==%d,%s" % (ppid, proto), "-T", "fields"]
    for field in FIELDS:
        cmd += ["-e", field]
    out = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    fields = lines[0] if lines else "NONE"
    full = subprocess.run([TSHARK, "-r", path, "-d", "sctp.ppi==%d,%s" % (ppid, proto), "-V"],
                          capture_output=True, text=True).stdout
    return (fields, full.count("Expert Info"), full.count("[Malformed"))


def wrap_nas(nas_hex):
    """Wrap a NAS PDU in an S1AP InitialUEMessage so a dissector can see it."""
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "s1ap_asn1.py"),
                          "initial-ue", "--mme-ue-id", "0x1", "--enb-ue-id", "0x2",
                          "--nas", nas_hex], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if line.startswith("hex\t"):
            return line.split("\t", 1)[1].strip()
    return ""


with tempfile.TemporaryDirectory(prefix="ransacked-check.") as tmp:
    base = facts(BASE, 18, 36412, "s1ap", tmp)
    chk("base-dissects", "s1ap" in base[0], True)
    chk("base-procedure", "\t12\t" in base[0] or base[0].split("\t")[1] == "12", True)
    note("the base frame raises %d expert warning(s) of its own: the IMSI spare "
         "digit makes the dissector read an MCC of 020, and the NAS fixture stops "
         "after the identity. Both are properties of the fixture, not of a variant."
         % base[1])

    dissent, same, broken = [], [], []
    for name, value in sorted(variants.items()):
        if name.startswith("nas-"):
            wrapped = wrap_nas(value)
            if not wrapped:
                broken.append(name)
                continue
            got = facts(wrapped, 18, 36412, "s1ap", tmp)
        elif name.startswith("ngap"):
            got = facts(value, 60, 38412, "ngap", tmp)
        else:
            got = facts(value, 18, 36412, "s1ap", tmp)
        if got[0] == "NONE" or got[0].startswith("FIELD-ERR"):
            broken.append(name)
        elif got != base:
            dissent.append(name)
        else:
            same.append(name)
        if VERBOSE:
            sys.stdout.write("VARIANT %-30s %s\n" % (name, "dissent" if got != base else "same"))

    chk("no-undissectable-variant", broken, [])
    chk("dissent-matches-measurement", sorted(dissent), sorted(set(variants) - SAME))
    chk("unobservable-named", sorted(same), sorted(SAME))
    chk("dissent-count", len(dissent), 20)
    note("observable to a dissector: %d of %d" % (len(dissent), len(variants)))
    note("NOT observable (a dissector prints neither field): " + ", ".join(sorted(SAME)))

sys.stdout.write("\nRESULT %s (%d assertion(s) failed)\n" % (
    "PASS" if not FAILS else "FAIL", len(FAILS)))
for line in FAILS:
    sys.stdout.write("  %s\n" % line)
sys.exit(0 if not FAILS else 1)
PY
