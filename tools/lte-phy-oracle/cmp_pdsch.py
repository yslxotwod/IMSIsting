#!/usr/bin/env python3
"""Check the LTE downlink transmit chain against srsRAN release_23_11.

This is the end-to-end check: one transport block goes through
CRC attachment, code block segmentation, turbo coding, rate matching,
scrambling, modulation, layer mapping, precoding and resource element
mapping, and every stage is compared against the same stage inside
srsRAN's srsran_dlsch_encode2() and srsran_pdsch_encode().

What is compared, and how:

  * the RATE-MATCHED BITS (E) and the SCRAMBLED BITS are compared exactly,
    bit for bit. They are the composition that length checks cannot see: a
    swapped code block order, a remainder given to the wrong end of the
    E_r split, or a scrambler seeded from the wrong slot all produce a
    stream of exactly the right length;
  * the RE POSITIONS are compared exactly, PER PORT, as a set, against the
    REs the oracle actually wrote -- the driver pre-fills its symbol buffer
    with a sentinel, so this is a change-set and a PDSCH symbol that is
    exactly zero cannot hide -- and then the values are compared in mapping
    order. Keying the written REs by position alone (which this file used to
    do) silently keeps only the LAST port to write a given RE, so three of
    the four ports of a diversity configuration were compared as if they
    were port 0 and every multi-port case looked wrong;
  * the RE COUNT per PRB per slot is compared against srsRAN's own
    ra_re_x_prb(). A total can agree while the individual PRBs are wrong;
    the centre six PRBs are the ones that carry PSS, SSS and the PBCH, and
    with an odd N_RB two of them are half-reserved;
  * the whole RE-AVAILABILITY SWEEP is compared the same way, per subcarrier:
    the 504 configurations tools/lte_phy.py's selftest hashes are driven
    through srsran_pdsch_cp() by the driver's sweep, which dumps one 12-bit
    mask per (slot, symbol, PRB). The digest this file prints is rebuilt from
    those masks -- the selftest's own pdsch-re-digest constant is taken from
    it, never from tools/lte_phy.py -- and so are the six-PRB RE counts the
    selftest asserts;
  * the complex VALUES are compared with a tolerance derived from the
    oracle's own measured single-precision error -- measured here, over
    every dumped symbol, against the exact constellation points of
    TS 36.211 7.1.2-7.1.5 -- and never from a round number. (The rule is
    recorded in check-lte-phy-oracle.sh: a PSS comparison in this directory
    once reported a failure that was entirely srsRAN's float32 error.)

What is NOT compared, deliberately: srsRAN's q->x layer-map buffer for a
single-layer transmission. srsran_pdsch_encode() only fills q->x when it
layer-maps AND precodes (nof_ports > 1 && nof_layers != nof_tb); with one
port it scales q->d[0] into q->symbols[0], and with nof_layers == nof_tb it
points x[] at q->d. In those branches q->x is uninitialised heap, and the
driver does not dump it. Nothing is lost: with one port the oracle's q->x and
q->symbols[0] are the same stream, and that stream IS compared.

Oracle directory comes from $IMSISTING_ORACLE.
"""

import importlib.util
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.environ.get("IMSISTING_ORACLE", "/tmp/ltephy/oracle")
DUMP = os.path.join(ORACLE, "pdsch", "dump.txt")

if not os.path.exists(DUMP):
    print("no srsRAN PDSCH dump at %s" % DUMP)
    print("run ./tools/check-lte-phy-oracle.sh to build it")
    sys.exit(2)

spec = importlib.util.spec_from_file_location(
    "lte_phy", os.path.join(HERE, "..", "lte_phy.py"))
lp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lp)

# --- parse -----------------------------------------------------------------
cases = []
sweeps = []
cur = None
sweep = None
with open(DUMP) as f:
    for line in f:
        fld = line.split()
        if not fld:
            continue
        tag = fld[0]
        if tag == "CASE":
            cur = {
                "idx": int(fld[1]), "n_rb": int(fld[2]), "cell_id": int(fld[3]),
                "subframe": int(fld[4]), "cfi": int(fld[5]),
                "nof_ports": int(fld[6]), "nof_layers": int(fld[7]),
                "tbs": int(fld[8]), "mod": fld[9], "rv": int(fld[10]),
                "rnti": int(fld[11]), "extended_cp": bool(int(fld[12])),
                "tdd": fld[13] == "tdd", "nof_prb_alloc": int(fld[15]),
                "prb": {}, "re": [], "x": {}, "sy": {},
            }
            cases.append(cur)
        elif tag == "RECFG":
            sweep = {
                "n_rb": int(fld[1]), "cell_id": int(fld[2]), "ports": int(fld[3]),
                "subframe": int(fld[4]), "cfi": int(fld[5]),
                "tdd": bool(int(fld[6])), "partial": bool(int(fld[7])),
                "nof_re": int(fld[8]), "nof_symb_slot": (int(fld[9]), int(fld[10])),
                "mask": {}, "counts": None,
            }
            sweeps.append(sweep)
        elif tag == "REPORTS":
            sweep["counts"] = [int(x) for x in fld[1:]]
        elif tag == "REMAP":
            sweep["mask"][(int(fld[1]), int(fld[2]))] = \
                [int(x, 16) for x in fld[3:]]
        elif cur is None:
            continue
        elif tag == "GRANT":
            cur["nof_re"], cur["nof_bits"] = int(fld[1]), int(fld[2])
            cur["nof_symb_slot"] = (int(fld[3]), int(fld[4]))
        elif tag == "PRB":
            cur["prb"][(int(fld[1]), int(fld[2]))] = int(fld[3])
        elif tag in ("TB", "TBCRC", "E", "SCR"):
            cur[tag] = [int(c) for c in fld[1]]
        elif tag == "D":
            cur["D"] = [complex(float(fld[i]), float(fld[i + 1]))
                        for i in range(1, len(fld), 2)]
        elif tag in ("X", "SY"):
            cur[tag.lower()][int(fld[1])] = [
                complex(float(fld[i]), float(fld[i + 1]))
                for i in range(2, len(fld), 2)]
        elif tag == "RE":
            cur["re"].append((int(fld[1]), int(fld[2]), int(fld[3]),
                              complex(float(fld[4]), float(fld[5]))))

if not cases:
    print("no cases in %s" % DUMP)
    sys.exit(2)

# --- measured oracle error -------------------------------------------------
# The transmitted constellation is exact: every value the oracle emits is a
# constellation point times the transmit scaling. Measuring how far the
# oracle's single-precision values sit from those points gives the tolerance
# this file is entitled to use -- twice the measured error, so that a correct
# implementation cannot fail on the oracle's own rounding.
measured = 0.0
for c in cases:
    if "D" not in c:
        continue
    ideal = lp.modulate(c["SCR"], c["mod"])
    for got, want in zip(c["D"], ideal):
        measured = max(measured, abs(got - want))
TOL = max(2.0 * measured, 1e-12)

fails = 0
checked = 0
re_checked = 0
worst = 0.0


def bad(c, msg):
    global fails
    fails += 1
    print("  case %2d %s" % (c["idx"], msg))


# --- the RE-availability sweep ---------------------------------------------
# The oracle's masks are the ground truth for where a PDSCH may go: every RE
# in them was written by srsran_pdsch_cp() into a buffer pre-filled with a
# sentinel, so a written zero is still visible and a reserved RE is absent.
#
# One thing the masks are NOT is a second opinion on the grant's total. For 7
# of the 504 configurations srsRAN disagrees with itself: see the note at the
# end of this file. Where its grant arithmetic and its own mapper part company
# the mapper wins, because the mapper is the set of REs the transmitter fills.
def our_masks(c):
    """The REs we allow, as the same 12-bit mask per (slot, symbol, PRB)."""
    out = {}
    prbs = range(0, c["n_rb"], 3) if c["partial"] else None
    for s in (0, 1):
        for (l, k) in lp.pdsch_available_re(
                c["n_rb"], c["cell_id"], c["subframe"], s, c["ports"],
                False, c["tdd"], prbs, c["cfi"]):
            out.setdefault((s, l), [0] * c["n_rb"])[k // 12] |= 1 << (k % 12)
    return out


def popcount(masks):
    return sum(bin(m).count("1") for ms in masks.values() for m in ms)


def oracle_re(c):
    """The oracle's REs in mapping order, both slots, flattened the way the
    selftest's digest flattens them: slot 1 is the slot-relative symbol plus
    seven, which is exact here because every configuration in the sweep is
    normal CP."""
    out = []
    for s in (0, 1):
        for l in range(c["nof_symb_slot"][s]):
            for n, m in enumerate(c["mask"].get((s, l), [0] * c["n_rb"])):
                for k in range(12):
                    if m >> k & 1:
                        out.append((l + s * 7, n * 12 + k))
    return out


def sha(*chunks):
    import hashlib
    h = hashlib.sha256()
    for chunk in chunks:
        h.update(chunk.encode())
    return h.hexdigest()


sweep_bad = 0
grant_notes = []
sweep_lines = []
for c in sweeps:
    mine = our_masks(c)
    theirs = c["mask"]
    n_mine, n_theirs = popcount(mine), popcount(theirs)
    keys = sorted(set(mine) | set(theirs))
    first = None
    for key in keys:
        a = mine.get(key, [0] * c["n_rb"])
        b = theirs.get(key, [0] * c["n_rb"])
        if a != b:
            first = first or (key, a, b)
    if first is not None:
        key, a, b = first
        sweep_bad += 1
        print("  sweep n_rb=%d cell=%d ports=%d sf=%d cfi=%d tdd=%d partial=%d: "
              "REMAP mismatch first at slot %d symbol %d"
              % (c["n_rb"], c["cell_id"], c["ports"], c["subframe"], c["cfi"],
                 c["tdd"], c["partial"], key[0], key[1]))
        for n, (x, y) in enumerate(zip(a, b)):
            if x != y:
                print("    PRB %d: we say %03x, srsRAN wrote %03x" % (n, x, y))
    for p, n in enumerate(c["counts"][:c["ports"]]):
        if n != n_mine:
            sweep_bad += 1
            print("  sweep n_rb=%d cell=%d ports=%d sf=%d cfi=%d tdd=%d partial=%d: "
                  "port %d wrote %d REs, we allow %d"
                  % (c["n_rb"], c["cell_id"], c["ports"], c["subframe"], c["cfi"],
                     c["tdd"], c["partial"], p, n, n_mine))
    if n_theirs != c["nof_re"]:
        # srsRAN's grant arithmetic against srsRAN's own mapper.
        grant_notes.append((c, n_theirs, c["nof_re"]))
    elif n_mine != c["nof_re"]:
        sweep_bad += 1
        print("  sweep n_rb=%d cell=%d ports=%d sf=%d cfi=%d tdd=%d partial=%d: "
              "RE count: we say %d, srsRAN's grant and mapper both say %d"
              % (c["n_rb"], c["cell_id"], c["ports"], c["subframe"], c["cfi"],
                 c["tdd"], c["partial"], n_mine, c["nof_re"]))
    re = oracle_re(c)
    sweep_lines.append('%d,%d,%d,%d,%d,%d,%d:%d:%s'
                       % (c["n_rb"], c["cell_id"], c["ports"], c["subframe"],
                          c["cfi"], 1 if c["tdd"] else 0,
                          1 if c["partial"] else 0, len(re),
                          sha(';'.join('%d,%d' % x for x in re))))

fails += sweep_bad
print("oracle RE sweep: %d configurations, %d disagree (per subcarrier, per PRB, "
      "per port)" % (len(sweeps), sweep_bad))

# The six-PRB FDD configurations the selftest asserts pdsch-re-count-* against.
print("RE counts for the selftest's pdsch-re-count-* checks "
      "(oracle grant == oracle mapper == our mapper):")
for c in sweeps:
    if (c["n_rb"], c["cell_id"], c["cfi"], c["tdd"], c["partial"]) != (6, 0, 1, False, False):
        continue
    if c["subframe"] not in (0, 1, 5):
        continue
    n = popcount(c["mask"])
    print("  (%d, %d, %d, %d, %d, %d, %d): %d REs"
          % (c["n_rb"], c["cell_id"], c["ports"], c["subframe"], c["cfi"], 0, 0, n))

# The selftest's pdsch-re-digest constant is this value. It is printed on every
# run so that the constant in tools/lte_phy.py always has a visible source.
print("sweep digest (tools/lte_phy.py pdsch-re-digest): %s"
      % sha(';'.join(sorted(sweep_lines))))

# --- the 25 end-to-end cases -----------------------------------------------
for c in cases:
    if "E" not in c or "SCR" not in c or "D" not in c:
        print("case %2d: incomplete dump (too many bits?)" % c["idx"])
        fails += 1
        continue
    checked += 1
    qm = lp.MOD_ORDER[c["mod"]]
    nl = 1 if c["nof_layers"] == 1 else 2
    # The PRB set of the oracle's grant, taken from the PRB lines rather than
    # assumed: the driver's partial allocation is a scattering rule, and the
    # comparator must not re-invent it.
    prbs = sorted(set(j for (s, j) in c["prb"]))

    # 1. CRC attachment, TS 36.212 5.1.1.
    want_crc = lp.lte_crc_attach(c["TB"], "24a")
    if want_crc != c["TBCRC"]:
        bad(c, "transport block CRC attachment differs")

    # 2. The grant's own RE accounting, and the per-PRB detail.
    mine_re = 0
    for s in (0, 1):
        re = lp.pdsch_available_re(c["n_rb"], c["cell_id"], c["subframe"], s,
                                   c["nof_ports"], c["extended_cp"], c["tdd"],
                                   prbs, c["cfi"])
        mine_re += len(re)
        per = {}
        for (l, k) in re:
            per[k // 12] = per.get(k // 12, 0) + 1
        for j in prbs:
            want = c["prb"].get((s, j))
            got = per.get(j, 0)
            if want is None:
                bad(c, "PRB (%d, %d) is missing from the oracle grant" % (s, j))
            elif got != want:
                bad(c, "PER: slot %d PRB %d: we say %d REs, srsRAN says %d"
                    % (s, j, got, want))
    if mine_re != c["nof_re"]:
        bad(c, "RE count: we say %d, srsRAN's grant says %d"
            % (mine_re, c["nof_re"]))
    if mine_re * qm != c["nof_bits"]:
        bad(c, "G = nof_re*Qm: %d vs the oracle's %d"
            % (mine_re * qm, c["nof_bits"]))
    want_symb = (6, 6) if c["extended_cp"] else (7, 7)
    if c["nof_symb_slot"] != want_symb:
        bad(c, "symbols per slot %r, expected %r"
            % (c["nof_symb_slot"], want_symb))

    # 3. Segmentation, turbo coding and rate matching, TS 36.212 5.1.2/5.1.3/5.1.4.
    try:
        e_bits, info = lp.dlsch_encode(c["TB"], qm, c["nof_bits"], rv=c["rv"],
                                       nl=nl)
    except ValueError as exc:
        bad(c, "DLSCH chain raised: %s" % exc)
        continue
    if e_bits != c["E"]:
        first = next((i for i, (a, b) in enumerate(zip(e_bits, c["E"]))
                      if a != b), min(len(e_bits), len(c["E"])))
        bad(c, "rate-matched bits differ at %d of %d (C=%d, E_r=%s)"
            % (first, len(c["E"]), info["segmentation"]["C"],
               info["e_per_cb"][:4]))

    # 4. Scrambling, modulation, layer mapping and precoding, TS 36.211 6.3.
    p = lp.pdsch_encode(c["TB"], qm, c["rnti"], c["cell_id"], c["subframe"],
                        c["nof_re"], c["nof_ports"], c["nof_layers"],
                        rv=c["rv"])
    if p["scrambled"] != c["SCR"]:
        first = next((i for i, (a, b) in enumerate(zip(p["scrambled"], c["SCR"]))
                      if a != b), -1)
        bad(c, "scrambled bits differ at %d (c_init=%d)" % (first, p["c_init"]))
    for name, mine, theirs in (("D", [p["symbols"]], [c["D"]]),
                               ("SY", p["ports"], [c["sy"][i] for i in
                                                   sorted(c["sy"])])):
        for pi, (mseq, tseq) in enumerate(zip(mine, theirs)):
            if len(mseq) != len(tseq):
                bad(c, "%s[%d] length %d vs %d" % (name, pi, len(mseq), len(tseq)))
                continue
            for i, (a, b) in enumerate(zip(mseq, tseq)):
                d = abs(a - b)
                worst = max(worst, d)
                if d > TOL:
                    bad(c, "%s[%d][%d] %r vs %r differs by %.3e > %.3e"
                        % (name, pi, i, a, b, d, TOL))
                    break
    if c["nof_layers"] > 1:
        # srsRAN dumped q->x for this case, so the layer map itself is checked.
        if sorted(c["x"]) != list(range(c["nof_layers"])):
            bad(c, "the driver dumped layers %r of %d"
                % (sorted(c["x"]), c["nof_layers"]))
        layers = lp.layer_map_diversity(p["symbols"], c["nof_layers"])
        for li in sorted(c["x"]):
            if len(layers[li]) != len(c["x"][li]):
                bad(c, "X[%d] length %d vs %d" % (li, len(layers[li]),
                                                  len(c["x"][li])))
                continue
            for i, (a, b) in enumerate(zip(layers[li], c["x"][li])):
                if abs(a - b) > TOL:
                    bad(c, "X[%d][%d] %r vs %r" % (li, i, a, b))
                    break

    # 5. The REs actually written, in mapping order, port by port.
    want = []
    for s in (0, 1):
        re = lp.pdsch_available_re(c["n_rb"], c["cell_id"], c["subframe"], s,
                                   c["nof_ports"], c["extended_cp"], c["tdd"],
                                   prbs, c["cfi"])
        want += [(l + s * want_symb[0], k) for (l, k) in re]
    got = {}
    for (p_, l, k, v) in c["re"]:
        got[(p_, l, k)] = v
    for pi in range(c["nof_ports"]):
        have = set((l, k) for (p_, l, k) in got if p_ == pi)
        if len(have) != len(want) or have != set(want):
            bad(c, "port %d RE positions: %d written vs %d available, %d common"
                % (pi, len(have), len(want), len(have & set(want))))
            continue
        # The order is the mapping order, and so is the port symbol order.
        for i, (l, k) in enumerate(want):
            d = abs(got[(pi, l, k)] - p["ports"][pi][i])
            worst = max(worst, d)
            if d > TOL:
                bad(c, "port %d RE (%d, %d) value %r vs %r differs by %.3e"
                    % (pi, l, k, got[(pi, l, k)], p["ports"][pi][i], d))
                break
    re_checked += len(c["re"])

if grant_notes:
    c, n_map, n_grant = grant_notes[0]
    print("NOTE: srsRAN's grant arithmetic disagrees with srsRAN's own RE mapper "
          "in %d of the %d sweep configurations (all n_rb=%d, ports=%d, subframe=%d, "
          "TDD): the grant says %d REs, srsran_pdsch_cp() writes %d."
          % (len(grant_notes), len(sweeps), c["n_rb"], c["ports"], c["subframe"],
             n_grant, n_map))
    print("      ra_re_x_prb() charges the allocation for the CRS of a second "
          "symbol only when the slot holds at least five symbols, and the DwPTS of "
          "this special subframe holds three; srsran_pdsch_cp() reserves the "
          "references that a four-port cell really transmits there.")
    print("      The mapper is what the transmitter fills, so the count check above "
          "uses it for these configurations; our model agrees with the mapper.")

print("oracle error against the exact constellation: %.3e (tolerance %.3e)"
      % (measured, TOL))
print("cases: %d, resource elements: %d, worst value difference: %.3e"
      % (checked, re_checked, worst))
print("MISMATCHES: %d" % fails)
sys.exit(1 if fails else 0)
