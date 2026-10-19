#!/usr/bin/env python3
#
#  ue_cells.py — the cells `dumpsys telephony.registry` actually printed.
#
#  Why this is not a grep: the registry prints the same serving cell many times
#  (last known, current list, per-phone snapshots), a neighbour list that is a
#  different set of cells, and per-cell signal strength only inside the CellInfo
#  wrapper.  Three layouts are in the wild -- "mCi=1", "mCi = 1", and the same
#  fields inside CellInfoLte -- and a hardened build replaces identifiers with
#  "[****]" rather than a number or a null.  A parser that reads one layout and
#  drops what it does not recognise reports a cell with four fields missing and
#  calls it success, which is exactly what this one did before a GrapheneOS
#  Pixel showed the bug.
#
#  The contract matches the rest of the tree: KEY<TAB>value rows, one row per
#  fact, and an explicit row for what was withheld versus never printed.
#
#  usage: ue_cells.py rows [--file PATH]
#         ue_cells.py selftest

import argparse
import re
import sys

# A field starts at a word boundary, may carry the usual Android "m" prefix,
# and is followed by "=" with or without spaces.
KEY_RX = re.compile(r"(?:^|(?<=[\s,{]))(m?[A-Za-z][A-Za-z0-9_]*)\s*=")
BLOCK_RX = re.compile(r"(CellInfo|CellIdentity)([A-Za-z]*)\s*:\s*\{")

# The four facts a serving cell cannot be described without.  Named as the
# dump prints them so a reader can match the row to the output.
ESSENTIAL = ("Ci", "Pci", "Tac", "Earfcn")

# A value that means "the handset has this and will not tell you".  GrapheneOS
# writes "[****]"; AOSP writes "Unknown" or "null" depending on the field.
WITHHELD_TOKENS = ("[****]", "****", "Unknown", "unknown", "null")


def _depth_map(text):
    """Brace depth at every index, so nested objects are not read as fields."""
    depths = [0] * (len(text) + 1)
    depth = 0
    for i, ch in enumerate(text):
        if ch in "{[":
            depth += 1
            depths[i] = depth
        elif ch in "}]":
            depths[i] = depth
            depth = max(0, depth - 1)
        else:
            depths[i] = depth
    depths[len(text)] = depth
    return depths


def fields(body):
    """Top-level key/value pairs of one block body, in dump order."""
    depths = _depth_map(body)
    marks = [(m.start(), m.group(1), m.end())
             for m in KEY_RX.finditer(body)]
    # Only keys that sit at depth 0 of this block: a nested object's fields
    # belong to that object, and reading them here invents cells.
    top = [(s, k, e) for (s, k, e) in marks if depths[s] == 0]
    out = {}
    for i, (start, key, end) in enumerate(top):
        stop = top[i + 1][0] if i + 1 < len(top) else len(body)
        value = body[end:stop].strip().strip(",").strip()
        value = re.sub(r"\s+", " ", value)
        value = value.rstrip(",").strip()
        if key not in out:
            out[key] = value
    return out


def blocks(text):
    """Every CellInfo/CellIdentity block in the text, by brace matching."""
    found = []
    for m in BLOCK_RX.finditer(text):
        head_at = m.end() - 1
        depth = 0
        end = None
        for i in range(head_at, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end is None:
            end = len(text) - 1
        kind = m.group(1)
        rat = m.group(2) or ""
        found.append({
            "kind": kind,
            "rat": rat or "unknown",
            "span": (m.start(), end + 1),
            "body": text[head_at + 1:end],
            "fields": fields(text[head_at + 1:end]),
        })
    return found


def _scalar(text):
    """The value part of a segment, with any class name in front of it removed."""
    text = re.sub(r"\s*[A-Za-z_][\w.]*\s*:\s*$", "", text.strip().rstrip(",").strip())
    return text.strip().rstrip(",").strip()


def _lift(block_fields):
    """Lift wrapper objects so both block kinds read alike, at any depth.

    A dump does not always name the objects it embeds.  Three shapes reach the
    same field scanner:

        mCellIdentityLte=CellIdentityLte:{...}      named, one object
        mCellConnectionStatus=1 CellIdentityLte:{...} CellSignalStrengthLte:{...}
                                                    unnamed objects glued to the
                                                    value that precedes them
        mConfig=0 android.telephony.CellConfigLte :{...}

    Read literally, the first works and the others put a whole cell, then its
    signal strength, into the string value of a status code -- so the cell's
    identifiers never become fields and a serving cell reports "missing Ci Pci
    Tac Earfcn" while the same dump printed all four, redacted.  A value can
    carry more than one object, so they are walked, not just the first.
    """
    out = {}
    children = []
    for key, value in block_fields.items():
        if key == "mRegistered" and "{" not in value:
            out["Registered"] = "yes" if value.upper().startswith("YES") else "no"
            continue

        rest = value
        kept = None
        while True:
            brace = rest.find("{")
            if brace < 0:
                tail = _scalar(rest)
                if tail and kept is None:
                    kept = tail
                break
            head = _scalar(rest[:brace])
            if head and kept is None:
                kept = head
            depth = 0
            end = len(rest)
            for i in range(brace, len(rest)):
                if rest[i] == "{":
                    depth += 1
                elif rest[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            children.append(fields(rest[brace + 1:end]))
            rest = rest[end + 1:]

        if kept is None and "{" not in value:
            kept = value
        if kept:
            out[key] = kept

    for child in children:
        for name, value in _lift(child).items():
            out.setdefault(name, value)
    return out


def _clean(fields_dict):
    out = {}
    for key, value in fields_dict.items():
        name = key[1:] if key.startswith("m") and len(key) > 1 else key
        if not name or name.lower() in ("registered",):
            pass
        if value.endswith("="):
            continue
        # A nested object that survived the lift is not a value a table can
        # carry, and neither is a class name left over from one.
        if "{" in value or "}" in value:
            continue
        if re.match(r"^[A-Za-z_][\w.]*\s*:$", value):
            continue
        # 2147483647 is Integer.MAX_VALUE, which the platform writes where a
        # measurement was never taken.  Printing it as an RSSI invents a reading
        # of 2.1 billion dBm.
        if value == "2147483647":
            value = "unknown"
        out[name] = value
    return out


IDENTITY_FIELDS = ("Ci", "Pci", "Tac", "Earfcn", "Mcc", "Mnc", "Bands", "Bandwidth")


def _identity_key(cell):
    """What makes two blocks the same cell.

    A redacted field is not compared: when the handset will not name a cell,
    two cells with the same bands and the same operator are indistinguishable
    in this output, and listing them twice would invent a second cell.
    """
    parts = []
    for name in IDENTITY_FIELDS:
        value = cell.get(name, "")
        if value in WITHHELD_TOKENS:
            value = ""
        parts.append((name, value))
    return tuple(parts)


def parse(text):
    """Cells in dump order, merged, with the serving one first."""
    raw = blocks(text)
    infos = [b for b in raw if b["kind"] == "CellInfo"]
    # An identity already inside a CellInfo was read with its signal strength;
    # reading it again as a bare CellIdentity would list the same cell twice.
    bare = [b for b in raw if b["kind"] == "CellIdentity"
            and not any(s <= b["span"][0] < e for (s, e) in (i["span"] for i in infos))]
    ordered = infos + bare

    cells = []
    index = {}
    duplicates = 0
    for block in ordered:
        f = _clean(_lift(block["fields"] if block["kind"] == "CellInfo" else _lift(block["fields"])))
        if not f:
            continue
        key = _identity_key(f)
        if key in index:
            duplicates += 1
            merged = index[key]
            for name, value in f.items():
                if value and not merged.get(name):
                    merged[name] = value
            if f.get("Registered") == "yes":
                merged["Registered"] = "yes"
            continue
        f.setdefault("rat", block["rat"] or "unknown")
        index[key] = f
        cells.append(f)

    # Registration is the fact that decides which cell is serving; dump order
    # is an accident of which snapshot printed first.
    position = next((i for i, c in enumerate(cells) if c.get("Registered") == "yes"), None)
    if position:
        cells.insert(0, cells.pop(position))
    return {"cells": cells, "duplicates": duplicates}


def rows(text, out):
    def row(key, value):
        out.write("%s\t%s\n" % (key, value))

    parsed = parse(text)
    cells = parsed["cells"]
    if not cells:
        row("status", "no-cell-info")
        row("reason", "no CellInfo or CellIdentity block; the handset may be idle or the API withheld it")
        return 1

    row("status", "cell-seen")
    row("blocks", len(cells))
    row("duplicates", parsed["duplicates"])
    serving = cells[0]
    row("rat", serving.get("rat", "unknown"))

    for i, cell in enumerate(cells, 1):
        for name in sorted(cell):
            value = cell[name]
            if not value or value.endswith("="):
                continue
            row("cells.%d.%s" % (i, name), value)
            if i == 1:
                row("cell.%s" % name, value)

    # What the serving cell is missing, split into the two reasons that look
    # the same in a table and need different responses from a human.
    withheld = [f for f in ESSENTIAL if serving.get(f, "") in WITHHELD_TOKENS]
    absent = [f for f in ESSENTIAL if not serving.get(f, "")]
    if withheld:
        row("withheld", " ".join(withheld))
    if absent:
        row("missing", " ".join(absent))

    rsrp = serving.get("Rsrp") or serving.get("rsrp")
    if not rsrp:
        m = re.search(r"(?:mRsrp|rsrp)\s*=\s*(-?[0-9]+)", text)
        if m:
            rsrp = m.group(1)
    if rsrp:
        row("signal_rsrp", rsrp)
    return 0


FIXTURE = """\
  mSignalStrength=SignalStrength: 20 -1 -1 -1 -1 mGsmSignalStrength = 20 mRsrp = -86 mRsrq = -9
  mCellIdentity=CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [3] mBandwidth = 20000 mMcc = 208 mMnc = 20 mAlphaLong = LycaMobile mAlphaShort = LycaMobile mAdditionalPlmns = {} mCsgInfo = null }
  mCellInfo=[CellInfoLte:{ mRegistered=YES mTimeStamp=1 mCellIdentityLte=CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [3] mBandwidth = 20000 mMcc = 208 mMnc = 20 } mCellSignalStrengthLte = { rsrp = -97 rsrq = -12 rssnr = 9 cqi = 11 } }, CellInfoLte:{ mRegistered=NO mTimeStamp=2 mCellIdentityLte=CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [20,3] mBandwidth = 10000 mMcc = null mMnc = null } mCellSignalStrengthLte = { rsrp = -111 rsrq = -18 } }]
  mCellIdentity=CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [3] mBandwidth = 20000 mMcc = 208 mMnc = 20 mAlphaLong = LycaMobile mAlphaShort = LycaMobile mAdditionalPlmns = {} mCsgInfo = null }
"""


# The live shape from a GrapheneOS Pixel: the identity and the signal strength
# are printed right after a status code, with no field name in front of either.
UNNAMED = """\
  mCellInfo=[CellInfoLte:{ mRegistered=YES mTimeStamp=18966047046ns mCellConnectionStatus=1 CellIdentityLte:{ mCi = [****] mPci = [****] mTac = [****] mEarfcn = [****] mBands = [20, 3, 1, 7, 28] mBandwidth = 10000 mMcc = 208 mMnc = 20 mAlphaLong =  mAlphaShort =  mAdditionalPlmns = {} mCsgInfo = null } CellSignalStrengthLte:{ rsrp = -75 rsrq = -5 rssi = 2147483647 cqi = 15 level = 4 } parametersUseForLevel = 0 android.telephony.CellConfigLte :{ isEndcAvailable = false }}]
"""


def selftest():
    import io
    results = []

    def chk(name, got, want):
        ok = got == want
        results.append(ok)
        sys.stdout.write("%-34s %s\n" % (name, "PASS" if ok else "FAIL want=%r got=%r" % (want, got)))

    parsed = parse(FIXTURE)
    cells = parsed["cells"]
    chk("blocks-deduplicated", len(cells), 2)
    # Two folds, not one: the fixture prints the serving cell once bare and once
    # inside CellInfo (merged, so it carries both the alphas and the signal),
    # then prints it bare again.
    chk("duplicates-counted", parsed["duplicates"], 2)
    # The registered CellInfo is the serving cell even though a bare identity
    # was printed first: registration is the fact, dump order is an accident.
    serving, neighbour = cells[0], cells[1]
    chk("serving-is-registered", serving.get("Registered"), "yes")
    chk("serving-rsrp", serving.get("rsrp"), "-97")
    chk("neighbour-not-registered", neighbour.get("Registered"), "no")
    chk("neighbour-rsrp", neighbour.get("rsrp"), "-111")
    # A bracket list must survive as one value: [20,3] is two bands, not the
    # string "[20" and a stray "3]".
    chk("bands-list-intact", neighbour.get("Bands"), "[20,3]")
    chk("null-mcc-is-a-value", neighbour.get("Mcc"), "null")

    buf = io.StringIO()
    rows(FIXTURE, buf)
    out = buf.getvalue()
    chk("status-row", "status\tcell-seen" in out, True)
    chk("withheld-row", [l for l in out.splitlines() if l.startswith("withheld\t")],
        ["withheld\tCi Pci Tac Earfcn"])
    chk("no-missing-row", any(l.startswith("missing\t") for l in out.splitlines()), False)
    chk("serving-rows-mirrored", "cell.Bands\t[3]" in out, True)
    chk("signal-row", "signal_rsrp\t-97" in out, True)
    chk("neighbour-listed", "cells.2.Bands\t[20,3]" in out, True)

    # A dump with no identifier at all is not an empty answer, it is a refusal,
    # and it says which.
    empty = io.StringIO()
    chk("empty-rc", rows("nothing here\n", empty), 1)
    chk("empty-status", "status\tno-cell-info" in empty.getvalue(), True)

    # Numbers, not redactions: the old layout must still read.
    plain = ("mCellIdentity=CellIdentityLte:{ mCi=12345678 mPci=301 mTac=26011 "
             "mEarfcn=6300 mMcc=310 mMnc=260 }")
    buf = io.StringIO()
    rows(plain, buf)
    chk("tight-layout-ci", "cell.Ci\t12345678" in buf.getvalue(), True)
    chk("tight-layout-no-withheld", "withheld\t" in buf.getvalue(), False)

    # A field the dump never printed is missing, not withheld.
    gap = "mCellIdentity=CellIdentityLte:{ mCi=1 mPci=2 }"
    buf = io.StringIO()
    rows(gap, buf)
    chk("absent-fields-named", [l for l in buf.getvalue().splitlines() if l.startswith("missing\t")],
        ["missing\tTac Earfcn"])

    # The unnamed-object layout: the identifiers must still arrive, and no row
    # may carry a whole object or a class name as if it were a value.
    buf = io.StringIO()
    chk("unnamed-rc", rows(UNNAMED, buf), 0)
    live = buf.getvalue()
    chk("unnamed-serving-ci", "cell.Ci\t[****]" in live, True)
    chk("unnamed-withheld", [l for l in live.splitlines() if l.startswith("withheld\t")],
        ["withheld\tCi Pci Tac Earfcn"])
    chk("unnamed-status-scalar", "cell.CellConnectionStatus\t1" in live, True)
    chk("unnamed-signal", "cell.rsrp\t-75" in live, True)
    chk("unnamed-no-object-values", any("{" in l for l in live.splitlines()), False)
    chk("unnamed-maxvalue-is-unknown", "cell.rssi\tunknown" in live, True)

    passed = sum(1 for r in results if r)
    sys.stdout.write("\n%d assertions, %d failed\n" % (len(results), len(results) - passed))
    return 0 if passed == len(results) else 1


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("verb", choices=("rows", "selftest"))
    ap.add_argument("--file", default="")
    args = ap.parse_args(argv)
    if args.verb == "selftest":
        return selftest()
    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    return rows(text, sys.stdout)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
