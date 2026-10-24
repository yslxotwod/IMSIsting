#!/usr/bin/env python3
"""NB-IoT NPRACH frequency hopping -- 3GPP TS 36.211 V16.2.0 clause 10.1.6.1.

An NPRACH preamble is not a 12-subcarrier grid. It is a sequence of symbol
groups, each ONE subcarrier wide, and the subcarrier of each group is chosen by
a rule that is deterministic for the first four groups and pseudo-random after
that (the c(n) of clause 7.2, seeded with the cell id). What this tool answers
is which subcarrier each symbol group of a preamble sits on, and how long the
group lasts in samples at 30.72 MHz.

The Gold generator is imported from tools/lte_phy.py rather than rewritten: it
is certified against pycrate by tools/check-lte-phy-oracle.sh, and a second
copy of clause 7.2 here would be one more thing that can disagree.

    nbiot_nprach.py pattern --cell 0 --init 5 [--offset 0] [--subcarriers 12]
                            [--format 0|1|2] [--groups N]
    nbiot_nprach.py formats
    nbiot_nprach.py selfcheck
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
try:
    import lte_phy
except ImportError:  # pragma: no cover - environment, not logic
    sys.stderr.write(
        "ERROR\tcannot import tools/lte_phy.py from %s\n"
        "WHY\tthe TS 36.211 7.2 Gold generator is taken from there, not "
        "reimplemented here\n" % _HERE)
    raise SystemExit(1)

TS_HZ = 30.72e6
TS_SEC = 1.0 / TS_HZ

# TS 36.211 Table 10.1.6.1-1, frame structure 1.
# format: (G, P, N, TCP in Ts, TSEQ in Ts)
FRAME_STRUCTURE_1 = {
    0: (4, 4, 5, 2048, 5 * 8192),
    1: (4, 4, 5, 8192, 5 * 8192),
    2: (6, 6, 3, 24576, 3 * 24576),
}

# TS 36.211 Table 10.1.6.1-2, frame structure 2.
FRAME_STRUCTURE_2 = {
    0: (2, 4, 1, 4768, 1 * 8192),
    1: (2, 4, 2, 8192, 2 * 8192),
    2: (2, 4, 4, 24576, 4 * 24576),
}

GAP_TS = 40 * 30720


def n_sc_ra(fmt):
    """TS 36.211 10.1.6.1: 12 subcarriers, 36 when format 2 is configured."""
    return 36 if fmt == 2 else 12


def f_of_t(c_init, n_sc, t):
    """The pseudo-random term f(t) of clause 10.1.6.1.

    The sum runs over c(10t+1) .. c(10t+9), the first term is the most
    significant bit, and the whole thing is taken modulo N_sc^RA - 1 before
    the +1, so the result is in 1..N_sc^RA-1.
    """
    if t < 0:
        return 0
    c = lte_phy.gold_sequence(c_init, 10 * t + 10)
    acc = 0
    for n in range(10 * t + 1, 10 * t + 10):
        acc = (acc << 1) | (c[n] & 1)
    return (acc % (n_sc - 1)) + 1


def hop(pattern_len, c_init, n_init, n_sc_offset, n_sc, fmt):
    """The subcarrier index n_sc^RA(i) of each symbol group.

    Returns (n_start, [n_sc^RA(i) for i in range(pattern_len)]).
    """
    n_start = n_sc_offset + (n_init // n_sc) * n_sc
    nt = [0] * pattern_len
    nt[0] = n_init % n_sc
    per = 6 if fmt == 2 else 4
    f_prev = 0
    for i in range(1, pattern_len):
        prev = nt[i - 1]
        k = i % per
        if fmt == 2:
            if k in (1, 5):
                nt[i] = prev + 1 if (prev % 2) == 0 else prev - 1
            elif k in (2, 4):
                nt[i] = prev + 3 if ((prev - 1) // 3) % 2 == 0 else prev - 3
            elif k == 3:
                nt[i] = prev + 18 if prev < 18 else prev - 18
            else:
                f_prev = (f_prev + f_of_t(c_init, n_sc, i // 6)) % n_sc
                nt[i] = f_prev
        else:
            if k in (1, 3):
                nt[i] = prev + 1 if (prev % 2) == 0 else prev - 1
            elif k == 2:
                nt[i] = prev + 6 if prev < 6 else prev - 6
            else:
                f_prev = (f_prev + f_of_t(c_init, n_sc, i // 4)) % n_sc
                nt[i] = f_prev
    return n_start, [n_start + x for x in nt]


def geometry(fmt, fs=1):
    table = FRAME_STRUCTURE_1 if fs == 1 else FRAME_STRUCTURE_2
    if fmt not in table:
        raise KeyError(fmt)
    G, P, N, tcp, tseq = table[fmt]
    return {
        "format": fmt,
        "frame_structure": fs,
        "G_symbol_groups": G,
        "P_contiguous": P,
        "N_symbols": N,
        "cp_ts": tcp,
        "seq_ts": tseq,
        "cp_samples": tcp,
        "seq_samples": tseq,
        "group_samples": tcp + tseq,
        "group_us": (tcp + tseq) * TS_SEC * 1e6,
        "preamble_unit_samples": G * (tcp + tseq),
        "preamble_unit_us": G * (tcp + tseq) * TS_SEC * 1e6,
    }


def cmd_formats(_args):
    for fs, table in ((1, FRAME_STRUCTURE_1), (2, FRAME_STRUCTURE_2)):
        for fmt in sorted(table):
            g = geometry(fmt, fs)
            print("format\t%d\tframe_structure\t%d\tG\t%d\tP\t%d\tN\t%d\t"
                  "cp_ts\t%d\tseq_ts\t%d\tcp_us\t%.2f\tseq_us\t%.2f\t"
                  "group_us\t%.2f" % (
                      fmt, fs, g["G_symbol_groups"], g["P_contiguous"],
                      g["N_symbols"], g["cp_ts"], g["seq_ts"],
                      g["cp_ts"] * TS_SEC * 1e6, g["seq_ts"] * TS_SEC * 1e6,
                      g["group_us"]))
    print("ref\t3GPP TS 36.211 V16.2.0 Table 10.1.6.1-1 (frame structure 1) "
          "and Table 10.1.6.1-2 (frame structure 2); Ts = 1/30.72 us")
    print("gap_ts\t%d\tgap_us\t%.2f\t%s" % (
        GAP_TS, GAP_TS * TS_SEC * 1e6,
        "clause 10.1.6.1: inserted after the preamble, 40*30720 Ts"))
    return 0


def cmd_pattern(args):
    fmt = args.format
    fs = args.frame_structure
    n_sc = n_sc_ra(fmt)
    if args.num_subcarriers < 1 or args.num_subcarriers > n_sc:
        sys.stderr.write(
            "ERROR\t--num-subcarriers %d is outside 1..%d\n"
            "WHY\tTS 36.211 10.1.6.1 gives N_sc^NPRACH subcarriers inside the "
            "%d-subcarrier NPRACH region, and N_sc^offset + N_sc^NPRACH > "
            "N_sc^UL is an invalid configuration\n"
            % (args.num_subcarriers, n_sc, n_sc))
        return 2
    if args.init < 0 or args.init >= args.num_subcarriers:
        sys.stderr.write(
            "ERROR\t--init %d is outside 0..%d\n"
            "WHY\tclause 10.1.6.1: n_init is chosen by MAC from "
            "{0..N_sc^NPRACH-1}\n" % (args.init, args.num_subcarriers - 1))
        return 2
    try:
        geo = geometry(fmt, fs)
    except KeyError:
        sys.stderr.write(
            "ERROR\tpreamble format %d is not defined for frame structure %d\n"
            "WHY\tTS 36.211 Table 10.1.6.1-%d has no format %d row\n"
            % (fmt, fs, 1 if fs == 1 else 2, fmt))
        return 2

    c_init = args.cell
    groups = args.groups if args.groups > 0 else geo["G_symbol_groups"]
    n_start, tones = hop(groups, c_init, args.init, args.offset, n_sc, fmt)

    print("format\t%d" % fmt)
    print("frame_structure\t%d" % fs)
    print("cell_id\t%d" % c_init)
    print("c_init\t%d" % c_init)
    print("n_init\t%d" % args.init)
    print("n_sc_offset\t%d" % args.offset)
    print("n_sc_nprach\t%d" % args.num_subcarriers)
    print("n_sc_ra\t%d" % n_sc)
    print("n_start\t%d" % n_start)
    print("per_symbol_group\t%d" % geo["G_symbol_groups"])
    print("groups\t%d" % groups)
    print("cp_samples\t%d" % geo["cp_samples"])
    print("seq_samples\t%d" % geo["seq_samples"])
    print("group_samples\t%d" % geo["group_samples"])
    print("group_us\t%.2f" % geo["group_us"])
    print("hop_span\t%d..%d" % (min(tones), max(tones)))
    for i, tone in enumerate(tones):
        print("group\t%d\tone_subcarrier\t%d\tn_sc_ra\t%d\tcp_samples\t%d\t"
              "seq_samples\t%d" % (i, tone, tone, geo["cp_samples"],
                                   geo["seq_samples"]))
    print("ref\t3GPP TS 36.211 V16.2.0 10.1.6.1: n_sc^RA(i) = n_start + "
          "n-tilde_sc^RA(i); the first four groups are deterministic and the "
          "rest follow f(t) built from the clause 7.2 sequence seeded with "
          "c_init = N_ID^Ncell")
    if args.offset + args.num_subcarriers > n_sc:
        print("limit\tthe configuration is invalid: n_sc_offset + "
              "n_sc_nprach = %d exceeds the %d usable subcarriers"
              % (args.offset + args.num_subcarriers, n_sc))
    if groups > geo["G_symbol_groups"]:
        print("limit\t%d groups span %d preamble repetitions; clause 10.1.6.1 "
              "does not say a UE repeats the pattern continuously, so treat "
              "the tail as the pattern continued, not as a schedule"
              % (groups, groups // geo["G_symbol_groups"]))
    return 0


def cmd_selfcheck(_args):
    checks = 0
    bad = 0

    def eq(name, got, want):
        nonlocal checks, bad
        checks += 1
        if got != want:
            bad += 1
            print("FAIL\t%s\tgot %r want %r" % (name, got, want))

    # Table 10.1.6.1-1, read off the table above.
    eq("fs1-f0", geometry(0, 1), {
        "format": 0, "frame_structure": 1, "G_symbol_groups": 4,
        "P_contiguous": 4, "N_symbols": 5, "cp_ts": 2048, "seq_ts": 40960,
        "cp_samples": 2048, "seq_samples": 40960, "group_samples": 43008,
        "group_us": 43008 * TS_SEC * 1e6, "preamble_unit_samples": 172032,
        "preamble_unit_us": 172032 * TS_SEC * 1e6})
    eq("fs1-f2-g", geometry(2, 1)["G_symbol_groups"], 6)
    eq("fs1-f2-cp", geometry(2, 1)["cp_ts"], 24576)
    eq("fs2-f0-cp", geometry(0, 2)["cp_ts"], 4768)
    eq("fs2-f0-G", geometry(0, 2)["G_symbol_groups"], 2)
    eq("nsc-f1", n_sc_ra(1), 12)
    eq("nsc-f2", n_sc_ra(2), 36)
    eq("gap", GAP_TS, 1228800)

    # The deterministic prefix, computed by hand from the clause rather than
    # by this file: n_init = 5 in a 12-subcarrier region with no offset is
    # n-tilde(0) = 5; 5 is odd so group 1 is 5-1 = 4; 4 < 6 so group 2 is
    # 4+6 = 10; 10 is even so group 3 is 10+1 = 11.
    _start, tones = hop(4, 0, 5, 0, 12, 0)
    eq("prefix-n_init5", tones, [5, 4, 10, 11])

    # n_init = 0: group 0 is 0, and 0 is even so group 1 is 1; 1 < 6 so group 2
    # is 7; 7 is odd so group 3 is 6. The parity flips back at the third step
    # and that is the point of the rule, not a detail to round off.
    _start, tones0 = hop(4, 0, 0, 0, 12, 0)
    eq("prefix-n_init0", tones0, [0, 1, 7, 6])

    # n_init = 11: 11 odd -> 10; 10 >= 6 -> 4; 4 even -> 5.
    _start, tones11 = hop(4, 0, 11, 0, 12, 0)
    eq("prefix-n_init11", tones11, [11, 10, 4, 5])

    # The offset lands in n_start: n_init = 13 is region 1 of a 12-subcarrier
    # region, so n_start = 24 and the first group is 24 + 1.
    start, tones13 = hop(4, 0, 13, 24, 12, 0)
    eq("offset-n_start", start, 36)
    eq("offset-first", tones13[0], 37)

    # f(t) is in 1..n_sc-1 and the pattern never leaves the region it starts
    # in; both are properties of the clause, not of the implementation.
    n_sc = 12
    n_start, long_tones = hop(64, 300, 3, 0, n_sc, 0)
    eq("f-range", all(1 <= f_of_t(300, n_sc, t) < n_sc for t in range(8)), True)
    eq("inside-region", all(n_start <= t < n_start + n_sc for t in long_tones),
       True)
    eq("not-all-same", len(set(long_tones)) > 4, True)

    # format 2 uses 36 subcarriers and the mod-6 rule.
    _s, t2 = hop(7, 0, 5, 0, 36, 2)
    eq("f2-prefix0", t2[0], 5)
    eq("f2-prefix1", t2[1], 4)
    eq("f2-prefix2", t2[2], 1)      # (4-1)//3 = 1, odd -> prev - 3
    eq("f2-inside", all(0 <= t < 36 for t in t2), True)

    print("CHECKS\t%d" % checks)
    print("FAILED\t%d" % bad)
    print("RESULT\t%s" % ("PASS" if bad == 0 else "FAIL"))
    return 0 if bad == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("pattern")
    p.add_argument("--cell", type=int, default=0)
    p.add_argument("--init", type=int, default=0)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--num-subcarriers", type=int, default=12)
    p.add_argument("--format", type=int, default=0, choices=[0, 1, 2])
    p.add_argument("--frame-structure", type=int, default=1, choices=[1, 2])
    p.add_argument("--groups", type=int, default=0)
    p.set_defaults(func=cmd_pattern)

    p = sub.add_parser("formats")
    p.set_defaults(func=cmd_formats)

    p = sub.add_parser("selfcheck")
    p.set_defaults(func=cmd_selfcheck)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_usage(sys.stderr)
        return 2
    try:
        return args.func(args)
    except ValueError as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
