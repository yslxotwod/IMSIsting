#!/usr/bin/env python3
"""Assert the LTE RRC/SIB codec against the vendored real-capture corpus.

The corpus in tools/lte-corpus/ holds real LTE RRC PDUs captured from real
hardware (see tools/lte-corpus/README.md and vectors.json for provenance and
licences). This program runs tools/lte_asn1.py on those bytes and checks the
decoded values against what each capture is independently known to contain
(Wireshark's lte-rrc dissector of the same pcap). A decode that "succeeds" but
produces implausible values is a FAILURE.

It never writes inside the repository and needs no network unless
--upstream-dir is given, in which case the upstream pcaps are re-extracted and
the extracted PDUs must be byte-identical to the vendored ones (so the vendored
hex is provably capture data, not something this repository generated).

Exit: 0 every assertion holds, 1 an assertion failed, 2 could not set up.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

# Never leave a __pycache__ inside the repository when importing extract.py.
sys.dont_write_bytecode = True

# TS 36.331 / TS 36.101 sanity ranges. These are deliberately *plausibility*
# bounds on top of the exact per-vector expectations: they are what turns a
# silent mis-decode into a failure.
VALID_BANDS = set(range(1, 65))                      # freqBandIndicator (1..64)
SI_WINDOWS = ("ms1", "ms2", "ms5", "ms10", "ms15", "ms20", "ms40")
SI_PERIODS = ("rf8", "rf16", "rf32", "rf64", "rf128", "rf256", "rf512")
BARRED = ("barred", "notBarred")
RESELECT = ("allowed", "notAllowed")
SIB_TYPES = tuple("sibType%d" % n for n in range(1, 14)) + \
            ("sibType13-v920", "sibType15-v920", "sibType15-v1020",
             "sibType16-v1100", "sibType17-v1250", "sibType18-v1250",
             "sibType19-v1250", "sibType20-r13")


class SetupError(Exception):
    """The checker cannot run at all -- exit 2, never a silent skip."""


class Report:
    def __init__(self):
        self.checks = 0
        self.failures = []

    def check(self, cond, ok, bad):
        self.checks += 1
        if cond:
            print("   OK   %s" % ok)
        else:
            print("   FAIL %s" % bad)
            self.failures.append(bad)
        return bool(cond)

    def note(self, msg):
        print("   ..   %s" % msg)


def run_codec(root, argv):
    cmd = [sys.executable, os.path.join(root, "tools", "lte_asn1.py")] + argv
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def parse_fields(stdout):
    """Our decode CLI prints tab-separated key/value lines."""
    fields, sched = {}, []
    for line in stdout.splitlines():
        if "\t" not in line:
            continue
        key, val = line.split("\t", 1)
        key, val = key.strip(), val.strip()
        if key == "scheduling":
            sched.append(val)
        elif key:
            fields[key] = val
    return fields, sched


def read_hex_file(path):
    """pdus/*.hex: '#' comments, whitespace and newlines are ignored."""
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0]
            out.append("".join(line.split()))
    return "".join(out)


def check_pdu_integrity(rep, corpus, vec):
    path = os.path.join(corpus, vec["pdu_file"])
    if not os.path.exists(path):
        raise SetupError("missing vector file: %s" % path)
    hexs = read_hex_file(path)
    rep.check(hexs.lower() == vec["pdu_hex"].lower(),
              "%s: pdus file matches vectors.json" % vec["id"],
              "%s: pdus file %s does not match vectors.json (%s vs %s)"
              % (vec["id"], vec["pdu_file"], hexs[:40], vec["pdu_hex"][:40]))
    raw = bytes.fromhex(hexs)
    rep.check(len(raw) * 8 == vec["pdu_bits"],
              "%s: %d bytes = %d bits as recorded" % (vec["id"], len(raw), vec["pdu_bits"]),
              "%s: %d bytes is not the recorded %d bits"
              % (vec["id"], len(raw), vec["pdu_bits"]))
    sha = hashlib.sha256(raw).hexdigest()
    rep.check(sha == vec["pdu_sha256"],
              "%s: sha256 %s" % (vec["id"], sha[:16] + "..."),
              "%s: sha256 %s does not match the recorded %s"
              % (vec["id"], sha, vec["pdu_sha256"]))
    return hexs


def check_expected(rep, vec, fields, sched):
    for key, want in sorted(vec["expect"].items()):
        got = fields.get(key)
        rep.check(got == want, "%s: %s = %s" % (vec["id"], key, got),
                  "%s: %s is %r, expected %r" % (vec["id"], key, got, want))
    if "expect_scheduling" in vec:
        want = [s.strip() for s in vec["expect_scheduling"]]
        got = [s.strip() for s in sched]
        rep.check(got == want, "%s: scheduling = %s" % (vec["id"], "; ".join(got)),
                  "%s: scheduling is %r, expected %r" % (vec["id"], got, want))
    for key in vec.get("expect_absent", []):
        rep.check(key not in fields,
                  "%s: %s absent as the capture requires" % (vec["id"], key),
                  "%s: %s is present (%r) but this capture has none"
                  % (vec["id"], key, fields.get(key)))
    if "expect_regression" in vec:
        for key, want in sorted(vec["expect_regression"].items()):
            if key.startswith("_"):
                continue
            got = fields.get(key)
            rep.check(got == want,
                      "%s: %s matches the recorded decode (regression lock)" % (vec["id"], key),
                      "%s: %s is %r, recorded %r" % (vec["id"], key, got, want))


def check_plausible(rep, vec, fields, sched, nbytes):
    """Range/consistency checks: a plausible-looking but wrong decode fails."""
    vid = vec["id"]
    cmd = vec["command"]
    if cmd == "si":
        rep.check(fields.get("message") == "BCCH-DL-SCH-Message",
                  "%s: message is a BCCH-DL-SCH-Message" % vid,
                  "%s: message is %r" % (vid, fields.get("message")))
        rep.check(fields.get("c1") == "systemInformation",
                  "%s: c1 is systemInformation" % vid,
                  "%s: c1 is %r" % (vid, fields.get("c1")))
        rep.check(fields.get("sib_type") in SIB_TYPES,
                  "%s: sib_type %s is a known SIB" % (vid, fields.get("sib_type")),
                  "%s: sib_type %r is not a known SIB type" % (vid, fields.get("sib_type")))
        for key in ("sib_count", "header_bits", "body_bits", "total_bits"):
            rep.check(str(fields.get(key, "")).isdigit(),
                      "%s: %s = %s is numeric" % (vid, key, fields.get(key)),
                      "%s: %s is %r, not numeric" % (vid, key, fields.get(key)))
            if not str(fields.get(key, "")).isdigit():
                return
        total = int(fields["total_bits"])
        header = int(fields["header_bits"])
        body = int(fields["body_bits"])
        count = int(fields["sib_count"])
        rep.check(total == 8 * nbytes,
                  "%s: total_bits == 8 * %d bytes (capture length agrees)" % (vid, nbytes),
                  "%s: total_bits %d does not match the %d-byte capture (%d bits)"
                  % (vid, total, nbytes, 8 * nbytes))
        rep.check(body == total - header,
                  "%s: body_bits %d == total_bits - header_bits" % (vid, body),
                  "%s: body_bits %d != total_bits %d - header_bits %d"
                  % (vid, body, total, header))
        rep.check(1 <= count <= 32,
                  "%s: sib_count %d is in 1..32" % (vid, count),
                  "%s: sib_count %d is outside 1..32" % (vid, count))
        body_hex = fields.get("body_hex", "")
        rep.check(len(body_hex) == 2 * ((body + 7) // 8),
                  "%s: body_hex is %d bytes for %d body bits (padded)" % (vid, len(body_hex) // 2, body),
                  "%s: body_hex is %d bytes, expected %d for %d body bits"
                  % (vid, len(body_hex) // 2, (body + 7) // 8, body))
        if body_hex:
            pad = 8 * ((body + 7) // 8) - body
            rep.check(pad == 0 or (int(body_hex, 16) & ((1 << pad) - 1)) == 0,
                      "%s: the %d hex pad bits are zero" % (vid, pad),
                      "%s: the %d hex pad bits are not zero" % (vid, pad))
        return

    # SIB1
    rep.check(fields.get("message") == "BCCH-DL-SCH-Message",
              "%s: message is a BCCH-DL-SCH-Message" % vid,
              "%s: message is %r" % (vid, fields.get("message")))
    rep.check(fields.get("sib") == "SystemInformationBlockType1",
              "%s: sib is SystemInformationBlockType1" % vid,
              "%s: sib is %r" % (vid, fields.get("sib")))

    mcc = fields.get("mcc", "")
    rep.check(len(mcc) == 3 and mcc.isdigit() and 200 <= int(mcc) <= 999,
              "%s: mcc %s is a 3-digit assigned-range MCC (200..999)" % (vid, mcc),
              "%s: mcc %r is not a 3-digit MCC in the ITU assigned range 200..999"
              % (vid, mcc))
    mnc = fields.get("mnc", "")
    rep.check(mnc.isdigit() and 2 <= len(mnc) <= 3,
              "%s: mnc %s has 2 or 3 digits" % (vid, mnc),
              "%s: mnc %r is not a 2- or 3-digit MNC" % (vid, mnc))

    plmn_count = fields.get("plmn_count", "")
    rep.check(plmn_count.isdigit() and 1 <= int(plmn_count) <= 6,
              "%s: plmn_count %s is in 1..6" % (vid, plmn_count),
              "%s: plmn_count %r is outside 1..6" % (vid, plmn_count))

    tac = fields.get("tac", "")
    rep.check(len(tac) == 4 and all(c in "0123456789abcdefABCDEF" for c in tac)
              and int(tac, 16) not in (0x0000, 0xFFFE, 0xFFFF),
              "%s: tac %s is non-zero and not a reserved value" % (vid, tac),
              "%s: tac %r is zero or a reserved value (0000/FFFE/FFFF)" % (vid, tac))

    cellid = fields.get("cellid", "")
    ok_cell = (cellid and all(c in "0123456789abcdefABCDEF" for c in cellid)
               and 0 < int(cellid, 16) < 2 ** 28)
    rep.check(ok_cell,
              "%s: cellid %s is non-zero and inside the 28-bit range" % (vid, cellid),
              "%s: cellid %r is zero or outside the 28-bit range 1..268435455" % (vid, cellid))

    band = fields.get("band", "")
    rep.check(band.isdigit() and int(band) in VALID_BANDS,
              "%s: band %s is a defined E-UTRA band indicator (1..64)" % (vid, band),
              "%s: band %r is not a defined E-UTRA band indicator (1..64)" % (vid, band))

    qrx = fields.get("q_rx_lev_min", "")
    ok_qrx = qrx.lstrip("-").isdigit() and -70 <= int(qrx) <= -22
    rep.check(ok_qrx,
              "%s: q_rx_lev_min %s is inside -70..-22 as TS 36.331 requires" % (vid, qrx),
              "%s: q_rx_lev_min %r is outside the TS 36.331 range -70..-22" % (vid, qrx))

    if "p_max" in fields:
        pmax = fields["p_max"]
        rep.check(pmax.lstrip("-").isdigit() and -30 <= int(pmax) <= 33,
                  "%s: p_max %s is inside -30..33" % (vid, pmax),
                  "%s: p_max %r is outside the TS 36.331 range -30..33" % (vid, pmax))
    if "q_rx_lev_min_offset" in fields:
        off = fields["q_rx_lev_min_offset"]
        rep.check(off.isdigit() and 1 <= int(off) <= 8,
                  "%s: q_rx_lev_min_offset %s is inside 1..8" % (vid, off),
                  "%s: q_rx_lev_min_offset %r is outside 1..8" % (vid, off))

    win = fields.get("si_window_length", "")
    rep.check(win in SI_WINDOWS,
              "%s: si_window_length %s is a defined value" % (vid, win),
              "%s: si_window_length %r is not one of %s" % (vid, win, "/".join(SI_WINDOWS)))

    tag = fields.get("system_info_value_tag", "")
    rep.check(tag.isdigit() and 0 <= int(tag) <= 31,
              "%s: system_info_value_tag %s is in 0..31" % (vid, tag),
              "%s: system_info_value_tag %r is outside 0..31" % (vid, tag))

    rep.check(fields.get("barred") in BARRED,
              "%s: barred = %s" % (vid, fields.get("barred")),
              "%s: barred is %r" % (vid, fields.get("barred")))
    rep.check(fields.get("intra_freq_reselection") in RESELECT,
              "%s: intra_freq_reselection = %s" % (vid, fields.get("intra_freq_reselection")),
              "%s: intra_freq_reselection is %r" % (vid, fields.get("intra_freq_reselection")))

    rep.check(1 <= len(sched) <= 32,
              "%s: %d scheduling entries is in 1..32" % (vid, len(sched)),
              "%s: %d scheduling entries is outside 1..32" % (vid, len(sched)))
    seen = []
    bad_period = []
    bad_type = []
    for entry in sched:
        parts = entry.split()
        if not parts or parts[0] not in SI_PERIODS:
            bad_period.append(entry)
        for name in parts[1:]:
            if name not in SIB_TYPES:
                bad_type.append(name)
        for name in parts[1:]:
            if name in seen:
                rep.check(False, "", "%s: SIB %s is scheduled twice" % (vid, name))
            seen.append(name)
    rep.check(not bad_period,
              "%s: every si-Periodicity is a defined value" % vid,
              "%s: undefined si-Periodicity in %r" % (vid, bad_period))
    rep.check(not bad_type,
              "%s: every scheduled sibType name is a known SIB" % vid,
              "%s: unknown sibType name(s) %r" % (vid, bad_type))

    bits = fields.get("bits_consumed", "")
    ok_bits = bits.isdigit() and 8 * (nbytes - 8) <= int(bits) <= 8 * nbytes
    rep.check(ok_bits,
              "%s: bits_consumed %s fits inside the %d-byte capture" % (vid, bits, nbytes),
              "%s: bits_consumed %r does not fit a %d-byte capture (%d..%d bits)"
              % (vid, bits, nbytes, 8 * (nbytes - 8), 8 * nbytes))


def check_negative(rep, root, corpus, manifest, vectors_by_id):
    for neg in manifest.get("negative_controls", []):
        vec = vectors_by_id[neg["vector"]]
        subs = {"${pdu}": vec["pdu_hex"],
                "${body}": vec.get("expect_regression", {}).get("body_hex", "")}
        args = [subs.get(a, a) for a in neg["args"]]
        if any(a == "" for a in args):
            raise SetupError("negative control %s has an unfilled substitution" % neg["id"])
        rc, out, err = run_codec(root, [neg["command"]] + args)
        want_err = neg.get("expect_stderr_contains")
        rep.check(rc != 0,
                  "negative %s: %s exits %d as required (%s)"
                  % (neg["id"], neg["command"], rc, neg.get("why", "")),
                  "negative %s: %s exited 0 but must fail (%s)"
                  % (neg["id"], neg["command"], neg.get("why", "")))
        if want_err:
            rep.check(rc != 0 and want_err in err,
                      "negative %s: stderr says %r" % (neg["id"], want_err),
                      "negative %s: stderr does not contain %r (got %r)"
                      % (neg["id"], want_err, err.strip()[:200]))


def check_mutations(rep, root, manifest, vectors_by_id):
    """The assertions must bind to the actual bits, not to a filename."""
    for mut in manifest.get("mutations", []):
        vec = vectors_by_id[mut["vector"]]
        raw = bytearray(bytes.fromhex(vec["pdu_hex"]))
        idx = mut["byte"]
        raw[idx] ^= mut["xor"]
        rc, out, err = run_codec(root, [vec["command"], raw.hex()])
        if rc != 0:
            rep.check(True, "mutation %s: corrupted frame is rejected (rc=%d: %s)"
                      % (mut["id"], rc, err.strip().splitlines()[0][:70] if err.strip() else ""),
                      "")
            continue
        fields, sched = parse_fields(out)
        same = all(fields.get(k) == v for k, v in vec["expect"].items())
        rep.check(not same,
                  "mutation %s: decoded values change (recorded: %s)"
                  % (mut["id"], mut.get("observed", "?")),
                  "mutation %s: byte %d ^ 0x%02x decoded to exactly the recorded "
                  "values, so the assertions are not bit-sensitive"
                  % (mut["id"], idx, mut["xor"]))


def check_consistency_groups(rep, manifest, vectors_by_id):
    for grp in manifest.get("consistency_groups", []):
        base = vectors_by_id[grp["vectors"][0]]
        for other_id in grp["vectors"][1:]:
            other = vectors_by_id[other_id]
            for key in grp["same_fields"]:
                want = base["expect"].get(key)
                got = other["expect"].get(key)
                rep.check(want == got,
                          "%s: %s and %s agree on %s = %s"
                          % (grp["id"], base["id"], other["id"], key, want),
                          "%s: %s says %s=%r but %s says %r -- captures of the same "
                          "network must agree" % (grp["id"], base["id"], key, want,
                                                  other["id"], got))
            if "same_scheduling" in grp.get("same_fields", []) or grp.get("same_scheduling"):
                rep.check(base.get("expect_scheduling") == other.get("expect_scheduling"),
                          "%s: %s and %s agree on the scheduling list"
                          % (grp["id"], base["id"], other["id"]),
                          "%s: scheduling differs between %s and %s"
                          % (grp["id"], base["id"], other["id"]))


def verify_upstream(rep, corpus, manifest, dirpath):
    sys.path.insert(0, corpus)
    import extract                                    # noqa: E402

    wanted = {u["id"]: u for u in manifest["upstream"]}
    index = {}
    for uid, up in wanted.items():
        path = os.path.join(dirpath, os.path.basename(up["file"]))
        if not os.path.exists(path):
            raise SetupError("%s: upstream capture not found in %s" % (up["file"], dirpath))
        sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
        rep.check(sha == up["sha256"],
                  "upstream %s: sha256 %s matches the manifest" % (uid, sha[:16] + "..."),
                  "upstream %s: sha256 is %s, manifest says %s"
                  % (uid, sha, up["sha256"]))
        frames = extract.EXTRACTORS[up["extractor"]](path)
        index[uid] = {fr["frame"]: fr["pdu"].lower() for fr in frames}
    for vec in manifest["vectors"]:
        idx = index[vec["upstream"]]
        for frame in vec["frames"]:
            got = idx.get(frame)
            rep.check(got == vec["pdu_hex"].lower(),
                      "upstream re-extract: frame %d of %s == the vendored PDU"
                      % (frame, vec["id"]),
                      "upstream re-extract: frame %d gives %s, vendored bytes are %s"
                      % (frame, got, vec["pdu_hex"].lower()))


def print_coverage(manifest, vec_count, per_cmd, upstream_dir):
    print("")
    print("== coverage")
    print("   vectors asserted: %d (%s)"
          % (vec_count, ", ".join("%d x %s" % (n, c) for c, n in sorted(per_cmd.items()))))
    print("   captures: 2 independent sources")
    print("     QCSuper, @4510c22f: real commercial LTE network MCC 208/MNC 10 (SFR France),")
    print("                              Sony Xperia phone diag log, 2018-03-24 (GPL-3.0 pcap, not vendored)")
    print("     LTESniffer, @a6948030: over-the-air from an srsRAN srseNB lab testbed, MCC 901/MNC 55,")
    print("                              2023-04-25 (AGPL-3.0 pcap, not vendored)")
    print("   independent evidence for every expected value: Wireshark's lte-rrc dissector on the")
    print("     same bytes -- not this codec and not pycrate.")
    print("   upstream re-extraction: %s"
          % ("verified against %s" % upstream_dir if upstream_dir
             else "NOT performed (offline run; pass --upstream-dir or --upstream)"))
    print("   gaps (fully stated in tools/lte-corpus/README.md):")
    for gap in manifest.get("coverage_gaps", []):
        print("     - %s" % gap)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    ap.add_argument("--corpus", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--upstream-dir")
    ap.add_argument("--list-upstream", action="store_true")
    args = ap.parse_args(argv[1:])

    manifest_path = os.path.join(args.corpus, "vectors.json")
    if not os.path.exists(manifest_path):
        sys.stderr.write("ERROR\tcorpus manifest not found: %s\n" % manifest_path)
        return 2
    with open(manifest_path) as fh:
        manifest = json.load(fh)

    if args.list_upstream:
        for up in manifest["upstream"]:
            print("%s\t%s\t%s" % (os.path.basename(up["file"]), up["url"], up["sha256"]))
        return 0

    codec = os.path.join(args.root, "tools", "lte_asn1.py")
    if not os.path.exists(codec):
        sys.stderr.write("ERROR\tcodec not found: %s\n" % codec)
        return 2

    rep = Report()
    vectors_by_id = {v["id"]: v for v in manifest["vectors"]}
    try:
        print("== corpus integrity")
        for vec in manifest["vectors"]:
            check_pdu_integrity(rep, args.corpus, vec)

        print("== decoded against the captures' known contents")
        per_cmd = {}
        for vec in manifest["vectors"]:
            per_cmd[vec["command"]] = per_cmd.get(vec["command"], 0) + 1
            print("-- %s" % vec["id"])
            rep.note("%s (%s)" % (vec["what"], vec["channel"]))
            rep.note("expectations from: %s" % vec["independent_evidence"])
            hexs = vec["pdu_hex"]
            # A vector may point at a slice of the captured PDU rather than the
            # whole thing -- a SIB body pulled out of the SI container, for
            # instance. The offset is not a free choice: the "items" vector
            # asserts that same offset against Wireshark's item boundaries, so
            # a codec that shifts where a body begins fails there first.
            sub = {"hex": hexs, "bits": str(vec["pdu_bits"])}
            if "slice" in vec:
                off = vec["slice"]["offset"]
                nb = vec["slice"]["bits"]
                bin_all = "".join(format(b, "08b") for b in bytes.fromhex(hexs))
                body = bin_all[off:off + nb]
                if len(body) != nb:
                    raise SetupError("%s: slice %d+%d runs past the %d captured "
                                     "bits" % (vec["id"], off, nb, len(bin_all)))
                # Pad to a whole nibble before slicing into hex digits, or the
                # final partial group is read as a SHORTER integer and the last
                # hex digit comes out wrong -- which then shifts nothing but
                # still changes the last field's value.
                padded = body + "0" * (-nb % 4)
                sub = {"hex": "".join(
                    "%X" % int(padded[i:i + 4], 2)
                    for i in range(0, len(padded), 4)),
                    "bits": str(nb)}
            # Most vectors are "<command> <hex>", but a vector whose subcommand
            # takes its arguments in another order (type-decode wants the type
            # name first) spells the whole argument list out instead.
            if "argv" in vec:
                argv = [a.format(**sub) for a in vec["argv"]]
            else:
                argv = [vec["command"], sub["hex"]] + vec.get("command_args", [])
            rc, out, err = run_codec(args.root, argv)
            if not rep.check(rc == 0,
                             "codec %s exits 0" % vec["command"],
                             "codec %s %s exits %d: %s"
                             % (vec["command"], sub["hex"], rc, err.strip()[:200])):
                continue
            fields, sched = parse_fields(out)
            check_expected(rep, vec, fields, sched)
            # The plausibility sweep below is about a SIB1-shaped decode: MCC,
            # MNC, TAC, cell identity, band, value tag. A vector that decodes
            # something else has none of those keys, so running it there reports
            # a dozen failures about fields the message never had. The vector
            # says which it is rather than the checker guessing from the
            # command, because "which fields must be present" is a property of
            # the capture, not of the subcommand.
            if vec.get("plausible", True):
                check_plausible(rep, vec, fields, sched,
                                len(bytes.fromhex(sub["hex"])))
            print("   decoded: %s" % ", ".join(
                "%s=%s" % (k, fields[k]) for k in sorted(fields) if k != "body_hex"
                and k not in ("layout",)))

        print("== negative controls (things the codec must refuse or that must keep failing)")
        check_negative(rep, args.root, args.corpus, manifest, vectors_by_id)

        print("== mutation controls (the assertions must bind to the captured bits)")
        check_mutations(rep, args.root, manifest, vectors_by_id)

        if manifest.get("consistency_groups"):
            print("== cross-vector consistency")
            check_consistency_groups(rep, manifest, vectors_by_id)

        if args.upstream_dir:
            print("== upstream re-extraction (proves the vendored bytes are capture data)")
            verify_upstream(rep, args.corpus, manifest, args.upstream_dir)
    except SetupError as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2
    except (ValueError, KeyError) as exc:
        sys.stderr.write("ERROR\tcannot read the corpus: %s: %s\n"
                         % (type(exc).__name__, exc))
        return 2

    print_coverage(manifest, len(manifest["vectors"]), per_cmd, args.upstream_dir)
    print("")
    if rep.failures:
        print("== %d of %d checks FAILED" % (len(rep.failures), rep.checks))
        for bad in rep.failures:
            print("   FAIL %s" % bad)
        return 1
    print("== all %d corpus assertions hold" % rep.checks)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
