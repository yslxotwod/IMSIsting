#!/usr/bin/env python3
"""The AKA oracle -- what an authentication failure tells an observer.

An MME or AMF that answers MAC failure, SYNCH failure and "unknown subscriber"
with different causes, different timings or different retry counts tells an
observer which of the three it hit.  That is the whole of this file: read the
cause codes of TS 24.301 §9.9.3.9 and TS 24.501 §9.7 for what each one proves
about the subscriber behind it, decide whether one network's failures are
distinguishable from each other, and recover the sequence number a genuine
subscriber hands back when it says SYNCH failure.

Two rules carried from the modules this joins:

  * an unknown cause is reported `unknown`, never `ok` -- the same rule
    `19_cipher_audit` applies to an unrecognised cipher id, because a
    toolkit that scores the unfamiliar case as safe reports a false negative
    on exactly the case an operator would choose
  * the oracle states what a cause proves, not what it might suggest; a cause
    that proves nothing says so

Sub-verbs:

  causes                      the EMM and 5GMM cause tables with what each proves
  classify <cause>            one cause, by number or by name
  session <file|->            group authentication outcomes by identity and say
                              whether they are distinguishable, and on which axis
  recover-sqn --ki --op/--opc --rand --auts
                              SQUARE the AUTS a UE returns on SYNCH failure
                              back to its sequence number (own SIM: needs K)
  selftest                    the vectors, including TS 35.208 test set 1

Referee for the sequence-number half: TS 35.208 test set 1 (K, OP, RAND, SQN
and the five expected outputs), computed through `tools/gsm_crypto.py
--milenage`, which already asserts those same vectors in `16_sim --selftest`.
Nothing here re-implements Milenage: the AK is asked for, not recomputed.
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GSM_CRYPTO = os.path.join(HERE, "gsm_crypto.py")

# ---------------------------------------------------------------------------
# The cause tables -- TS 24.301 §9.9.3.9 (EMM) and TS 24.501 §9.7 (5GMM).
# `proves` is the oracle's payload: what an observer learns from the network
# choosing this cause, which is not the same as what the cause means to the UE.
# ---------------------------------------------------------------------------

EMM_CAUSES = {
    2: ("IMSI unknown in HSS",
        "the identity is not provisioned here -- an unused, foreign or "
        "recycled IMSI", "identity"),
    3: ("Illegal UE",
        "the identity is barred, so it was known enough to bar", "identity"),
    5: ("IMEI not accepted",
        "the terminal identity is barred while the subscriber identity was "
        "apparently fine", "device"),
    6: ("Illegal ME",
        "the terminal is barred by policy, not the subscriber", "device"),
    7: ("EPS services not allowed",
        "the subscriber exists and is barred from this service", "identity"),
    9: ("UE identity cannot be derived by the network",
        "the network could not map the identity it was given to a subscriber "
        "-- the SUCI/IMSI resync half, and the usual answer to a corrupted "
        "SUCI", "identity"),
    20: ("MAC failure",
        "the network holds a key for this identity and the UE's MAC did not "
        "verify -- a real subscriber answered a challenge that did not come "
        "from its home network", "aka"),
    21: ("Synch failure",
        "the identity is known AND the key is right (the MAC verified), but "
        "the sequence number is out of range -- the strongest confirmation an "
        "attacker gets without the key, and it comes with AUTS", "aka"),
    22: ("Congestion",
        "nothing about the subscriber; the network is overloaded", "none"),
    23: ("UE security capabilities mismatch",
        "the UE's security capabilities differ from what the network had "
        "stored -- the downgrade this tree's `--downgrade-check` looks for",
        "security"),
    24: ("Security mode rejected, unspecified",
        "the UE refused the security mode command the network sent", "security"),
    25: ("Not authorized for this CSG",
        "the subscriber exists and is not a member of the closed cell", "identity"),
    26: ("Non-EPS authentication unacceptable",
        "the UE rejected the authentication mode, so it found the network's "
        "AKA variant unacceptable before any key was used", "aka"),
    42: ("Severe network failure",
        "the core is failing, which is why the procedure aborted", "none"),
}

FIVEGMM_CAUSES = {
    3: ("Illegal UE",
        "the identity is barred, so it was known enough to bar", "identity"),
    6: ("Illegal ME",
        "the terminal is barred by policy, not the subscriber", "device"),
    7: ("5GS services not allowed",
        "the subscriber exists and is barred from 5GS here", "identity"),
    9: ("UE identity cannot be derived by the network",
        "the network could not resolve the SUCI it was given -- the resync "
        "path that a forged SUCI lands on", "identity"),
    20: ("MAC failure",
        "the network holds a key for this identity and the UE's MAC did not "
        "verify -- a real subscriber answered a foreign challenge", "aka"),
    21: ("Synch failure",
        "identity known and key correct, sequence number out of range; AUTS "
        "follows and carries the UE's own SQN concealed with f5*", "aka"),
    22: ("Congestion", "nothing about the subscriber", "none"),
    23: ("UE security capabilities mismatch",
        "the UE's advertised algorithms differ from the network's record",
        "security"),
    24: ("Security mode rejected, unspecified",
        "the UE refused the security mode command", "security"),
    26: ("Non-5G authentication unacceptable",
        "the UE rejected the network's authentication mode", "aka"),
    65: ("Maximum number of PDU sessions reached",
        "nothing about the subscriber's identity", "none"),
    72: ("Non-3GPP access to 5GCN not allowed",
        "the subscriber exists and is barred from the non-3GPP path", "identity"),
}

MECHANISM = {
    "eps": ("EMM", EMM_CAUSES),
    "5gs": ("5GMM", FIVEGMM_CAUSES),
}

# The second half of Phase 17's two-sided bar: a legitimate exchange has a
# request, a response and no failure cause at all.  A cause of 0 means "no
# failure".  Anything the tables do not list is `unknown`.
NO_FAILURE = 0


def causes_rows(mechanism="eps"):
    name, table = MECHANISM[mechanism]
    for number in sorted(table):
        cause, proves, stage = table[number]
        yield [("cause", str(number)), ("mechanism", name),
               ("name", cause), ("auth-stage", stage), ("proves", proves)]


def _cause_number(cause, mechanism="eps"):
    """Accept a number, a numeric string, or the cause's own name."""
    name, table = MECHANISM[mechanism]
    if isinstance(cause, int):
        return cause
    try:
        return int(str(cause), 0)
    except (TypeError, ValueError):
        pass
    wanted = "".join(str(cause).split()).lower()
    for candidate, (label, _proves, _stage) in table.items():
        if "".join(label.split()).lower() == wanted:
            return candidate
    raise ValueError("%r is not a %s cause this table knows" % (cause, name))


def classify(cause, mechanism="eps"):
    """One cause -> what the network just told the observer."""
    name, table = MECHANISM[mechanism]
    number = _cause_number(cause, mechanism)
    if number == NO_FAILURE:
        return [("cause", "0"), ("mechanism", name), ("name", "no failure"),
                ("auth-stage", "none"),
                ("proves", "the procedure did not fail, so the exchange "
                           "reveals nothing about the subscriber beyond the "
                           "identity that was already sent")]
    if number not in table:
        return [("cause", str(number)), ("mechanism", name), ("name", "unknown"),
                ("auth-stage", "unknown"),
                ("proves", "nothing this table can state; an unlisted cause is "
                           "reported as unknown rather than as harmless")]
    label, proves, stage = table[number]
    return [("cause", str(number)), ("mechanism", name), ("name", label),
            ("auth-stage", stage), ("proves", proves)]


# ---------------------------------------------------------------------------
# The session half: are one network's failures distinguishable from each other?
# ---------------------------------------------------------------------------

def read_session(handle):
    """Read `identity cause ms retries` rows, with or without a header.

    Cause may be a number or one of the names above.  A missing timing or retry
    column is not fatal: the oracle then has fewer axes to work with and says
    so, rather than assuming one.
    """
    rows = []
    for line in handle:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split("\t")]
        if fields[0].lower() in ("identity", "imsi", "suci", "id"):
            continue
        if len(fields) < 2:
            raise ValueError("row has no cause: %r" % line)
        identity = fields[0]
        try:
            cause = _cause_number(fields[1])
        except ValueError as exc:
            raise ValueError("row %r: %s" % (line, exc))
        ms = None
        retries = None
        if len(fields) >= 3 and fields[2] != "":
            try:
                ms = int(fields[2], 0)
            except ValueError:
                ms = None
        if len(fields) >= 4 and fields[3] != "":
            try:
                retries = int(fields[3], 0)
            except ValueError:
                retries = None
        rows.append({"identity": identity, "cause": cause, "ms": ms,
                     "retries": retries})
    return rows


def session_verdicts(rows):
    """Group by identity and say whether the failures are distinguishable."""
    order = []
    groups = {}
    for row in rows:
        if row["identity"] not in groups:
            groups[row["identity"]] = []
            order.append(row["identity"])
        groups[row["identity"]].append(row)
    out = []
    for identity in order:
        group = groups[identity]
        failures = [r for r in group if r["cause"] != NO_FAILURE]
        distinct = sorted({r["cause"] for r in failures})
        axes = []
        if len(distinct) > 1:
            axes.append("cause")
        timings = [r["ms"] for r in failures if r["ms"] is not None]
        if len(timings) >= 2 and min(timings) >= 0:
            if min(timings) == 0:
                if max(timings) > 0:
                    axes.append("timing")
            elif max(timings) >= 2 * min(timings) and max(timings) >= 50:
                axes.append("timing")
        retries = {r["retries"] for r in failures if r["retries"] is not None}
        if len(retries) > 1:
            axes.append("retries")
        if not failures:
            verdict = "uniform"
        elif axes:
            verdict = "distinguishable"
        else:
            verdict = "uniform"
        out.append({
            "identity": identity,
            "attempts": len(group),
            "failures": len(failures),
            "causes": distinct,
            "timings": timings,
            "retries": sorted(retries),
            "axis": ",".join(axes) if axes else "none",
            "verdict": verdict,
        })
    return out


def session_rows(verdicts):
    yield [("identities", str(len(verdicts))),
           ("distinguishable", str(sum(1 for v in verdicts
                                        if v["verdict"] == "distinguishable")))]
    for v in verdicts:
        prefix = "identity.%s." % v["identity"]
        yield [(prefix + "attempts", str(v["attempts"])),
               (prefix + "failures", str(v["failures"])),
               (prefix + "causes", ",".join(str(c) for c in v["causes"]) or "none"),
               (prefix + "timings", ",".join(str(t) for t in v["timings"]) or "none"),
               (prefix + "retries", ",".join(str(r) for r in v["retries"]) or "none"),
               (prefix + "axis", v["axis"]),
               (prefix + "verdict", v["verdict"])]
    for v in verdicts:
        if v["verdict"] == "distinguishable":
            yield [("finding.%s" % v["identity"],
                    "the network answers this identity differently per failure "
                    "(%s), so an observer can tell which failure it hit"
                    % v["axis"])]


# ---------------------------------------------------------------------------
# The sequence number half: AUTS -> SQN, which is the SYNCH failure's payload.
# ---------------------------------------------------------------------------

def milenage(ki, rand, op=None, opc=None):
    """Ask tools/gsm_crypto.py for the Milenage outputs.  One implementation."""
    argv = [sys.executable, GSM_CRYPTO, "--milenage", "--ki", ki, "--rand", rand]
    if opc:
        argv += ["--opc", opc]
    elif op:
        argv += ["--op", op]
    else:
        raise ValueError("need an OP or an OPC")
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("gsm_crypto refused: %s"
                           % (proc.stderr.strip() or proc.stdout.strip()))
    out = {}
    for line in proc.stdout.splitlines():
        if "\t" in line:
            key, value = line.split("\t", 1)
            out[key.strip()] = value.strip()
    return out


def recover_sqn(ki, rand, auts, op=None, opc=None):
    """AUTS = (SQN_MS xor AK*) || MAC-S, so SQN_MS = AUTS[0:6] xor f5*.

    The UE sends AUTS on SYNCH failure so the network can resynchronise.  It
    conceals the sequence number under AK* = f5*(K, RAND) rather than
    encrypting it: with K -- the operator's own card, an own-SIM testbed --
    the number falls out in one XOR.  Without K it stays concealed, and this
    function has nothing to say.
    """
    if len(auts) != 14:
        raise ValueError("AUTS is 14 octets (6 of concealed SQN and 8 of MAC-S)")
    values = milenage(ki, rand, op=op, opc=opc)
    try:
        ak_star = bytes.fromhex(values["f5*"])
    except KeyError:
        raise RuntimeError("gsm_crypto returned no f5*")
    if len(ak_star) != 6:
        raise RuntimeError("f5* must be 6 octets, got %d" % len(ak_star))
    concealed = bytes(a ^ b for a, b in zip(auts[:6], ak_star))
    mac_s = auts[6:]
    seq = int.from_bytes(concealed[:5], "big")
    ind = concealed[5]
    return {
        "ak-star": ak_star.hex(),
        "sqn": concealed.hex(),
        "mac-s": mac_s.hex(),
        "seq": str(seq),
        "ind": str(ind),
        "recovered": "sqn" if True else "",
    }


def sqn_rows(result):
    return [("auts-ak-star", result["ak-star"]),
            ("sqn", result["sqn"]),
            ("sqn-seq", result["seq"]),
            ("sqn-ind", result["ind"]),
            ("mac-s", result["mac-s"]),
            ("proves", "a SYNCH failure plus this AUTS tells the network exactly "
                       "where the subscriber's counter was; with K, so does "
                       "anyone holding the card")]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def emit(pairs):
    """Print one group of key/value pairs; a flat list of pairs, not a list of
    groups.  Groups are separated by the caller so a consumer can split the
    output on a blank line."""
    for key, value in pairs:
        print("%s\t%s" % (key, value))


def _hex(text, label):
    cleaned = "".join(ch for ch in text if not ch.isspace() and ch not in ":-")
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise SystemExit("ERROR %s is not hex" % label)


def main(argv):
    parser = argparse.ArgumentParser(
        prog="nas_auth_oracle.py",
        description="What an AKA failure proves, and what a SYNCH failure hands "
                    "back.")
    sub = parser.add_subparsers(dest="verb")

    p = sub.add_parser("causes", help="the EMM and 5GMM cause tables")
    p.add_argument("--gen", choices=sorted(MECHANISM), default="eps")

    p = sub.add_parser("classify", help="one cause, by number or name")
    p.add_argument("cause")
    p.add_argument("--gen", choices=sorted(MECHANISM), default="eps")

    p = sub.add_parser("session", help="authentication outcomes, grouped")
    p.add_argument("path")

    p = sub.add_parser("recover-sqn", help="AUTS to SQN, with K")
    p.add_argument("--ki", required=True)
    p.add_argument("--rand", required=True)
    p.add_argument("--auts", required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--op")
    group.add_argument("--opc")

    sub.add_parser("selftest", help="run the vectors")

    args = parser.parse_args(argv)
    if args.verb is None:
        parser.print_help()
        return 2

    if args.verb == "causes":
        for row in causes_rows(args.gen):
            emit(row)
            print()
        return 0
    if args.verb == "classify":
        try:
            emit(classify(args.cause, args.gen))
        except ValueError as exc:
            raise SystemExit("ERROR %s" % exc)
        return 0
    if args.verb == "session":
        if args.path == "-":
            verdicts = session_verdicts(read_session(sys.stdin))
        else:
            with open(args.path) as handle:
                verdicts = session_verdicts(read_session(handle))
        for row in session_rows(verdicts):
            emit(row)
        return 0
    if args.verb == "recover-sqn":
        result = recover_sqn(args.ki, args.rand, _hex(args.auts, "AUTS"),
                            op=args.op, opc=args.opc)
        emit(sqn_rows(result))
        return 0
    return selftest()


# ---------------------------------------------------------------------------
# Vectors -- TS 35.208 test set 1 for the sequence number half.
# ---------------------------------------------------------------------------

TS35208_1 = {
    "ki": "465b5ce8b199b49faa5f0a2ee238a6bc",
    "op": "cdc202d5123e20f62b6d676ac72cb318",
    "opc": "cd63cb71954a9f4e48a5994e37a02baf",
    "rand": "23553cbe9637a89d218ae64dae47bf35",
    "sqn": "ff9bb4d0b607",
    "f5star": "451e8beca43b",
    "mac_s": "aabbccddeeff0011",   # a stand-in: this file never computes MAC-S
}


def selftest():
    failures = 0
    checks = 0

    def check(name, condition, detail=""):
        nonlocal failures, checks
        checks += 1
        print("ASSERTION\t%s\t%s" % (name, "PASS" if condition else "FAIL %s" % detail))
        if not condition:
            failures += 1

    # -- the sequence number half, against TS 35.208 test set 1 --------------
    sqn = bytes.fromhex(TS35208_1["sqn"])
    ak_star = bytes.fromhex(TS35208_1["f5star"])
    concealed = bytes(a ^ b for a, b in zip(sqn, ak_star))
    auts = (concealed + bytes.fromhex(TS35208_1["mac_s"])).hex()
    result = recover_sqn(TS35208_1["ki"], TS35208_1["rand"], bytes.fromhex(auts),
                         op=TS35208_1["op"])
    check("sqn-recovers-test-set-1", result["sqn"] == TS35208_1["sqn"],
          "%s != %s" % (result["sqn"], TS35208_1["sqn"]))
    check("sqn-ind-is-the-sixth-octet", result["ind"] == "7", result["ind"])
    check("sqn-seq-is-the-five", result["seq"] == str(int(TS35208_1["sqn"][:10], 16)),
          result["seq"])
    check("ak-star-is-f5-star", result["ak-star"] == TS35208_1["f5star"],
          result["ak-star"])
    # OPC and OP are two spellings of the same key material for this vector.
    via_opc = recover_sqn(TS35208_1["ki"], TS35208_1["rand"],
                          bytes.fromhex(auts), opc=TS35208_1["opc"])
    check("opc-and-op-agree", via_opc["sqn"] == result["sqn"], via_opc["sqn"])
    check("auts-length-refused",
          _rejects(lambda: recover_sqn(TS35208_1["ki"], TS35208_1["rand"],
                                       bytes(13), op=TS35208_1["op"])),
          "a 13-octet AUTS was accepted")

    # -- the cause table ---------------------------------------------------
    mac = dict(classify("20"))
    synch = dict(classify("21"))
    unknown_sub = dict(classify(2))
    check("cause-20-names-mac-failure", mac["name"] == "MAC failure", mac["name"])
    check("cause-21-names-synch-failure", synch["name"] == "Synch failure",
          synch["name"])
    check("cause-2-names-unknown-hss", unknown_sub["name"] == "IMSI unknown in HSS",
          unknown_sub["name"])
    # The oracle's payload: the three causes prove different things.
    check("causes-prove-different-things",
          len({mac["proves"], synch["proves"], unknown_sub["proves"]}) == 3,
          "the three statements collapsed into fewer than three")
    check("synch-names-the-key",
          "key is right" in synch["proves"], synch["proves"])
    check("mac-names-a-subscriber",
          "real subscriber" in mac["proves"], mac["proves"])
    # The module rule carried over: the unfamiliar case is never "ok".
    weird = dict(classify("190"))
    check("unknown-cause-is-unknown", weird["name"] == "unknown", weird["name"])
    check("unknown-cause-proves-nothing", "nothing this table can state"
          in weird["proves"], weird["proves"])
    check("no-failure-is-a-cause",
          dict(classify("0"))["name"] == "no failure", "0 did not classify")
    # 5GMM has its own table and its own numbering for the same events.
    check("five-gmm-classifies", dict(classify("21", "5gs"))["name"]
          == "Synch failure", "5GMM 21 did not classify")
    check("five-gmm-mechanism-row", dict(classify("21", "5gs"))["mechanism"]
          == "5GMM", "mechanism row wrong")

    # -- the session half, both sides of the bar --------------------------
    distinguishable = session_verdicts([
        {"identity": "310260000000001", "cause": 20, "ms": 40, "retries": 1},
        {"identity": "310260000000001", "cause": 21, "ms": 120, "retries": 2},
        {"identity": "310260000000001", "cause": 2, "ms": 44, "retries": 1},
    ])
    check("four-causes-distinguishable",
          distinguishable[0]["verdict"] == "distinguishable",
          distinguishable[0]["verdict"])
    check("cause-axis-named", "cause" in distinguishable[0]["axis"],
          distinguishable[0]["axis"])
    check("timing-axis-named", "timing" in distinguishable[0]["axis"],
          distinguishable[0]["axis"])
    check("retry-axis-named", "retries" in distinguishable[0]["axis"],
          distinguishable[0]["axis"])

    # A legitimate exchange: an identity, no failure cause at all.
    legitimate = session_verdicts([
        {"identity": "310260000000002", "cause": 0, "ms": 55, "retries": 0},
    ])
    check("legitimate-exchange-not-flagged",
          legitimate[0]["verdict"] == "uniform", legitimate[0]["verdict"])
    check("legitimate-exchange-has-no-failures",
          legitimate[0]["failures"] == 0, str(legitimate[0]["failures"]))

    # Uniform failures on one identity: the network is not leaking which one.
    uniform = session_verdicts([
        {"identity": "310260000000003", "cause": 20, "ms": 40, "retries": 1},
        {"identity": "310260000000003", "cause": 20, "ms": 42, "retries": 1},
    ])
    check("uniform-failures-not-flagged", uniform[0]["verdict"] == "uniform",
          uniform[0]["verdict"])

    # Timing alone is enough when the causes agree.
    timing_only = session_verdicts([
        {"identity": "310260000000004", "cause": 20, "ms": 30, "retries": 1},
        {"identity": "310260000000004", "cause": 20, "ms": 400, "retries": 1},
    ])
    check("timing-alone-is-distinguishable",
          timing_only[0]["verdict"] == "distinguishable", timing_only[0]["verdict"])

    print("RESULT\t%s" % ("PASS" if failures == 0 else "FAIL"))
    print("ASSERTIONS\t%d" % checks)
    return 0 if failures == 0 else 1


def _rejects(fn):
    try:
        fn()
    except (ValueError, RuntimeError):
        return True
    return False


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
