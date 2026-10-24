#!/usr/bin/env python3
"""Malformed C-APDU corpus for an eUICC/USIM, and a classifier for the answers.

The hardware half of an eUICC fuzz run is a reader and a sacrificial card. The
half that needs neither is the corpus and the judgement: a malformed command is
only interesting if you can say what the card did with it. So this generates the
classes of malformed APDU that matter, drives them at a target, and classifies
each answer:

    refused   the card said no, with a status word
    accepted  the card answered 9000 to a malformed command -- a finding: it
              took garbage as valid
    silent    no status word at all
    hang      the target did not answer in time
    crash     the target exited non-zero

The target is any command that takes one hex APDU per line on stdin and prints a
`sw<TAB>....` row per exchange; `--usim-serve` in modules/16_sim.sh is one.

Exit: 0 nothing misbehaved, 1 a case was accepted/silent/hung/crashed, 2 usage.
"""
from __future__ import annotations

import argparse
import subprocess
import sys

# The valid commands the corpus mutates. The card this tree serves answers all
# of them (16_sim --usim-serve), so a mutation that changes the answer is a real
# change and not a command the target never supported.
VALID = {
    "select-aid": "00A4040009A0000000871002FF86",
    "select-ef": "00A4000C026F07",
    "read": "00B000000A",
    "verify": "00200081083131313131313131",
}


def corpus() -> list[tuple[str, str, str]]:
    """(name, what it tests, hex APDU) — deterministic, no seed needed."""
    cases: list[tuple[str, str, str]] = [
        ("lc-overstates", "a length octet larger than the data that follows",
         "00B000000A00"),
        ("lc-understates", "a length octet smaller than the data that follows",
         "00A4000C026F07FFFF"),
        ("le-with-data", "both Lc and Le on a case-2 command",
         "00B0000A026F0700"),
        ("unknown-ins", "an instruction the card does not implement",
         "00F0000000"),
        ("bad-p1", "SELECT with a P1 that selects nothing defined",
         "00A40900026F07"),
        ("bad-p2", "READ BINARY with an undefined P2",
         "00B000FF0A"),
        ("auth-oversized", "AUTHENTICATE with more data than RAND+AUTN",
         "0088810024" + "00" * 34 + "00"),
        ("auth-truncated", "AUTHENTICATE with half a challenge",
         "0088810010" + "00" * 16),
        ("read-past-eof", "READ BINARY far past the end of the file",
         "00B0FFFF10"),
        ("select-empty", "SELECT with no data field",
         "00A4040000"),
        ("sm-class", "secure messaging on a card with no SCP",
         "8CA40400026F07"),
        ("bad-class", "a class the card does not implement",
         "FFA40400026F07"),
    ]
    for name, valid in VALID.items():
        cases.append(("truncated-" + name, "the valid %s command cut short" % name,
                      valid[:-2]))
        cases.append(("odd-" + name, "the valid %s command with an odd digit count" % name,
                      valid[:-1]))
    return cases


REFUSALS = {"6700", "6A80", "6A81", "6A82", "6A86", "6B00", "6D00", "6E00", "6986", "6882"}


def run(target: list[str], apdu: str, timeout: int) -> tuple[str, str]:
    """One exchange: (verdict, status word)."""
    try:
        done = subprocess.run(target, input=apdu + "\n", capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "hang", ""
    sw = ""
    for line in done.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == "sw":
            sw = parts[1].strip().upper()
    if done.returncode != 0 and not sw:
        return "crash", sw
    if not sw:
        return "silent", sw
    if sw == "9000":
        return "accepted", sw
    return "refused", sw


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True,
                        help="command taking hex APDUs on stdin")
    parser.add_argument("--limit", type=int, default=0, help="stop after N cases")
    parser.add_argument("--timeout", type=int, default=5)
    arguments = parser.parse_args(argv)

    target = arguments.target.split()
    cases = corpus()
    if arguments.limit:
        cases = cases[: arguments.limit]

    counts = {"refused": 0, "accepted": 0, "silent": 0, "hang": 0, "crash": 0}
    print("cases\t%d" % len(cases))
    for name, why, apdu in cases:
        verdict, sw = run(target, apdu, arguments.timeout)
        counts[verdict] += 1
        print("case\t%s\t%s\t%s\t%s\t%s" % (name, why, apdu, verdict, sw))

    for key, label in (("refused", "refused correctly"),
                       ("accepted", "answered 9000 to a malformed command"),
                       ("silent", "no status word"),
                       ("hang", "did not answer in time"),
                       ("crash", "exited non-zero")):
        print("%s\t%d" % (key, counts[key]))

    bad = counts["accepted"] + counts["silent"] + counts["hang"] + counts["crash"]
    print("misbehaved\t%d" % bad)
    if bad:
        print("verdict\tthe target accepted, lost, hung on or crashed into a "
              "malformed command: that is the class of defect worth taking to a "
              "real eUICC")
        return 1
    print("verdict\tthe target refused every malformed command with a status "
          "word: this corpus finds nothing on it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
