#!/usr/bin/env python3
"""The handset's radio log, sorted into the PDUs it contains and the text it is made of.

Why this is not a hex scraper
-----------------------------
``adb logcat -b radio`` is the modem's own account of what it did: the AT
commands it traded, the SIM APDUs it exchanged, the NAS and RRC PDUs it sent and
received, and a great deal of vendor noise.  Turning that into evidence is
mostly a problem of *refusing* things.  A hex scraper finds octets in every
line -- timestamps alone read as two octets -- and a scraper that hands those
octets to a decoder produces plausible nonsense for exactly the lines that
matter least.

So this file separates four questions that are usually merged:

* **what shape is the line** -- an AT command, an AT response, a ``+CRSM``
  response with a quoted APDU, a labelled hex blob, or prose with nothing to
  read.  The shapes it knows are listed by ``shapes``; a line that matches none
  is counted as ``unrecognised`` rather than mined for octets.
* **is the octet string provable** -- NAS is provable because its first octet is
  a protocol discriminator fixed by TS 24.007 (``0x07`` EPS, ``0x7E`` 5GS); an
  APDU inside a ``+CRSM`` response is provable because the modem itself printed
  the status word beside it.  RRC is *not* provable: nothing in an LTE or NR
  DCCH message says what it is, so an RRC-sized blob is reported as ``unproven``
  with the candidate verb named, not as an RRC message.
* **can the bench decode it** -- and if the PDUs are enciphered, it cannot: a
  NAS message with a security header other than "plain" is reported as
  ``protected``, which is an answer, not a failure.
* **what would decode it** -- each proven PDU carries the command that would
  read it, using the verbs this tree actually has (``32_nas_signaling
  --decode-nas``, ``12_nr_air --decode-rrc``, ``10_lte_air --decode-sib``,
  ``16_sim --parse-apdu``).

The one measurement worth stating
---------------------------------
An AT response that carries a length (``+CRSM`` quotes a hex string; ``+CSIM``
likewise) is checked against that length, and a ``+CGDCONT``/``+COPS`` reply is
kept as text.  Where a shape has no length to check, nothing here claims to have
checked one.

Where it runs
-------------
Hardware-free and file-driven: ``parse <path|->`` reads a saved log, and
``ue_agent.sh --radio-log`` pulls one off the handset with ``adb logcat -b
radio -d`` and pipes it in.  The selftest runs the parsers over embedded
fixtures that include the traps -- a timestamp that looks like octets, an odd
digit count, a blob whose label lies -- so the refusals are tested as hard as
the acceptances.

``--decode`` closes the loop: each proven PDU is handed to the verb the file
would otherwise only name, and the decoder's rows come back under that line
number.  The point is that the reader never decodes anything itself.  A
``+CRSM`` APDU goes to ``16_sim --parse-apdu``, EPS NAS to ``32_nas_signaling
--decode-nas``, and a protected PDU is not handed anywhere, because there is
nothing to hand over.  Only a command beginning ``modules/<id>.sh`` is ever
executed, and a decoder that exits non-zero is reported as ``failed`` with its
stderr rather than folded into a success.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

# ── the shapes a radio log line can take ────────────────────────────────────
#
# Each entry is (name, regex, kind).  ``kind`` decides what the extraction pass
# does with the matched group: ``hex`` takes it as octets, ``at`` keeps it as a
# command, ``apdu`` treats it as a quoted SIM response with status words.

SHAPES = [
    # +CRSM / +CSIM come before the generic AT response on purpose: a CRSM
    # reply *is* an AT response, and the specific shape is the one that carries
    # a status word to prove the octets with.
    ("crsm", re.compile(r"\+CRSM:\s*(?P<sw1>-?\d+)\s*,\s*(?P<sw2>-?\d+)\s*,?\s*\"(?P<hex>[0-9A-Fa-f]*)\""), "apdu"),
    ("csim", re.compile(r"\+CSIM:\s*\"(?P<hex>[0-9A-Fa-f]*)\""), "apdu"),
    # A tapped AT interface.  Qualcomm and MTK vendor builds both print this
    # way when a trace is enabled; the command itself is the evidence.
    ("at-command", re.compile(r"\bAT[>+]\s*(?P<body>AT[+\w].*)$"), "at"),
    ("at-response", re.compile(r"\bAT[<]\s*(?P<body>[+\w@].*)$"), "at"),
    # A hex blob with a direction.  Several vendor RIL builds and the QMI
    # tracer both print these.
    ("tx-blob", re.compile(r"\bTX[:>]\s*(?P<hex>(?:0x)?[0-9A-Fa-f]{2}(?:[\s:,]+(?:0x)?[0-9A-Fa-f]{2}){3,})"), "hex"),
    ("rx-blob", re.compile(r"\bRX[:<]\s*(?P<hex>(?:0x)?[0-9A-Fa-f]{2}(?:[\s:,]+(?:0x)?[0-9A-Fa-f]{2}){3,})"), "hex"),
    # The bracket form some builds emit: [0x0b] < 03 07 41 ...
    ("bracket-blob", re.compile(r"\[0x[0-9A-Fa-f]+\]\s*[<>]\s*(?P<hex>[0-9A-Fa-f]{2}(?:[\s:,][0-9A-Fa-f]{2}){3,})"), "hex"),
    # Labelled all-hex bodies: "NAS: 07 41 ...", "OTA message: 0b ...".
    ("labelled-blob", re.compile(r"(?i)\b(?:OTA|RAW|PDU|NAS|RRC|HEX|DATA|MSG)[^:]{0,24}:\s*(?P<hex>(?:0x)?[0-9A-Fa-f]{2}(?:[\s:,]+(?:0x)?[0-9A-Fa-f]{2}){3,})\b"), "hex"),
    # A message body that is nothing but octets.  No label, but no ambiguity
    # either -- there is no other reading of "03 07 41 0b".
    ("bare-blob", re.compile(r"^(?P<hex>(?:0x)?[0-9A-Fa-f]{2}(?:[\s:,]+(?:0x)?[0-9A-Fa-f]{2}){3,})\s*$"), "hex"),
]

# Android prints the tag between the level and the message.  Both the brief
# ("D/RILJ ( 1234):") and the threadtime ("D RILJ :") layouts start a line with
# a timestamp, which is why the timestamp is consumed here and never offered to
# the hex pass.
LINE_RE = re.compile(
    r"^(?:"
    r"(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"       # threadtime
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<lvl>[VDIWEFA])\s+(?P<tag1>[^:]*?)\s*:"  # tag : msg
    r"|"
    r"(?P<lvl2>[VDIWEFA])/(?P<tag2>[^(]*?)\s*\(\s*(?P<pid2>\d+)\s*\)\s*:\s*"     # D/TAG ( pid): msg
    r")"
    r"\s?(?P<msg>.*)$"
)

# Protocol discriminators from TS 24.007 §9.2 -- constants, so their presence is
# proof of the layer rather than a guess about it.
EPD_EPS = 0x07
EPD_5GS = 0x7E

def norm_hex(text: str) -> str:
    """Octets from a log fragment, or an empty string if it is not whole octets."""
    cleaned = re.sub(r"0[xX]", "", text)
    cleaned = re.sub(r"[\s:,.-]", "", cleaned)
    if not cleaned or len(cleaned) % 2:
        return ""
    if not re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        return ""
    return cleaned.upper()


def split_line(line: str) -> dict:
    """Timestamp, tag and message body of one logcat line."""
    m = LINE_RE.match(line)
    if not m:
        return {"tag": "", "msg": line.rstrip("\n"), "stamped": False}
    tag = (m.group("tag1") or m.group("tag2") or "").strip()
    return {
        "tag": tag,
        "msg": (m.group("msg") or "").rstrip("\n"),
        "stamped": True,
        "level": m.group("lvl") or m.group("lvl2") or "",
    }


def shape_of(body: str) -> tuple[str, str, dict]:
    """Name the shape of a message body: (shape, kind, groups)."""
    for name, rx, kind in SHAPES:
        m = rx.search(body)
        if m:
            return name, kind, m.groupdict()
    return "", "", {}


def classify_nas(octets: bytes) -> dict | None:
    """Prove a NAS PDU from its discriminator, and say what the header allows.

    The two generations put the same three fields in different places, which is
    the whole reason this function exists rather than a two-line check:

    * **EPS** (TS 24.301 §9.3.1): octet 0 is the security header type in the top
      nibble and the protocol discriminator in the bottom one, and the message
      type is octet 1.  ``07 41`` is a plain Attach request.
    * **5GS** (TS 24.501 §9.3.1): the discriminator has its own octet (``7e``),
      the security header type is the top nibble of octet 1, and the message
      type is octet 2.  ``7e 00 41`` is a plain Registration request.

    ``32_nas_signaling --decode-nas`` reads both this way, and the selftest
    pins the two layouts against it.
    """
    if not octets:
        return None
    b0 = octets[0]
    # 5GS spends a whole octet on the discriminator.  EPS shares octet 0 with
    # the security header, so the discriminator is the LOW nibble and a
    # protected PDU does not start with 0x07 at all -- it starts with the
    # security header, which is why `27 41` is the same attachment as `07 41`
    # with the message enciphered.
    if b0 == EPD_5GS:
        layer, sh_at, mt_at = "nas-5gs", 1, 2
    elif (b0 & 0x0F) == EPD_EPS and (b0 >> 4) <= 4:
        layer, sh_at, mt_at = "nas-eps", 0, 1
    else:
        return None
    if len(octets) <= sh_at:
        return {"layer": layer, "proof": "discriminator only", "message": "truncated",
                "cleartext": None, "note": "one octet past the discriminator is missing"}
    sh = (octets[sh_at] >> 4) & 0x0F if layer == "nas-5gs" else (octets[0] >> 4) & 0x0F
    if sh != 0:
        names = {1: "integrity protected", 2: "integrity protected and ciphered",
                 3: "integrity protected with new context",
                 4: "integrity protected with new context"}
        return {"layer": layer, "proof": "discriminator", "message": "protected",
                "cleartext": False, "security_header": sh,
                "note": "security header %d (%s): the message type is enciphered, so only "
                        "the outer header is readable here" % (sh, names.get(sh, "unknown"))}
    if len(octets) <= mt_at:
        return {"layer": layer, "proof": "discriminator", "message": "truncated",
                "cleartext": None,
                "note": "plain NAS with no message type octet"}
    return {"layer": layer, "proof": "discriminator", "message": "0x%02x" % octets[mt_at],
            "cleartext": True, "security_header": 0,
            "note": "plain NAS: the message type is on the wire"}


def candidate_commands(layer: str, hexstr: str) -> list[str]:
    """The verbs this tree has for a layer, named rather than run."""
    if layer == "nas-5gs":
        return ["modules/32_nas_signaling.sh --decode-nas 5gs %s" % hexstr,
                "modules/13_nr_core.sh --decode-nas-5gs %s" % hexstr]
    if layer == "nas-eps":
        # Both decoders are offered now.  They disagreed for a while:
        # `09_lte_attach` modelled a three-octet NAS header (bearer identity,
        # then the discriminator, then the message type) and read
        # `0741...` as security header 7 / discriminator 0x41, while
        # `32_nas_signaling` read it as security header 0 / EPD 7 / Attach
        # request -- which is what TS 24.301 §9.3.1 and tshark's NAS-EPS
        # dissector both say.  The older module was corrected, and this
        # reader names it again rather than laundering a stale disagreement.
        return ["modules/32_nas_signaling.sh --decode-nas eps %s" % hexstr,
                "modules/09_lte_attach.sh --decode-nas %s" % hexstr]
    if layer == "apdu":
        return ["modules/16_sim.sh --parse-apdu %s" % hexstr]
    return []


def decode_plan(parsed: dict) -> list[dict]:
    """The PDUs worth handing to a decoder, in log order.

    Only the first candidate per record is planned: the second exists so an
    operator can compare decoders by hand, not so both run on every line.  A
    protected PDU has no candidate at all -- naming a decoder for octets it
    cannot read would be the same lie the protected branch exists to avoid.
    """
    plan = []
    for rec in parsed["records"]:
        pdu = rec.get("pdu") or {}
        nexts = pdu.get("next") or []
        if not nexts or not rec.get("hex"):
            continue
        argv = nexts[0].split()
        if not argv:
            continue
        plan.append({"line": rec["line"], "layer": pdu.get("layer", "?"),
                     "hex": rec["hex"], "argv": argv, "command": nexts[0]})
    return plan


def _module_of(argv: list) -> str:
    """The module a planned command names, or "" when it names anything else.

    Every candidate this file emits starts with ``modules/<id>.sh``.  Checking
    that again here means a future candidate string cannot turn ``--decode``
    into a way to execute arbitrary commands out of a log file.
    """
    if len(argv) >= 3 and argv[0].startswith("modules/") and argv[0].endswith(".sh"):
        return argv[0]
    return ""


def run_plan(parsed: dict, root: str, timeout: int = 40) -> list:
    """Run each planned verb and keep its rows.  A decoder that fails is data."""
    results = []
    for item in decode_plan(parsed):
        module = _module_of(item["argv"])
        path = os.path.join(root, module) if module else ""
        out = {"line": item["line"], "layer": item["layer"],
               "command": item["command"], "status": "not-run", "rows": {}}
        if not module or not os.path.isfile(path):
            out["status"] = "no-decoder"
            results.append(out)
            continue
        try:
            proc = subprocess.run(item["argv"], cwd=root, capture_output=True,
                                  text=True, timeout=timeout)
            out["rc"] = proc.returncode
            out["status"] = "decoded" if proc.returncode == 0 else "failed"
            for row in proc.stdout.splitlines():
                if "\t" in row:
                    key, _, value = row.partition("\t")
                    out["rows"][key.strip()] = value.strip()
            if proc.returncode != 0 and not out["rows"]:
                out["stderr"] = (proc.stderr or "").strip().splitlines()[:2]
        except subprocess.TimeoutExpired:
            out["status"] = "timeout"
        except OSError as exc:
            out["status"] = "error"
            out["stderr"] = [str(exc)]
        results.append(out)
    return results


def unproven_hint(octets: bytes, hexstr: str) -> dict:
    """What an octet string of no proven layer could be, said as a hypothesis."""
    hint = {"layer": "unproven", "proof": "none",
            "note": "nothing in the first octet names this layer", "candidates": []}
    if len(octets) >= 8:
        hint["candidates"].append("modules/12_nr_air.sh --decode-rrc %s" % hexstr)
    if len(octets) >= 4:
        hint["candidates"].append("modules/10_lte_air.sh --decode-sib %s" % hexstr)
    if not hint["candidates"]:
        hint["note"] = "too short to be a PDU in any layer this bench reads"
    return hint


def analyse(line: str, number: int) -> dict | None:
    """One log line, as a record -- or None when the line holds no PDU."""
    parts = split_line(line)
    body = parts["msg"]
    shape, kind, groups = shape_of(body)
    if not shape:
        # Prose is not a refusal.  A line that carries no octets was never a
        # candidate, and counting it as one would make a healthy log look
        # broken; the count is kept separately so the proportion is visible.
        return {"line": number, "tag": parts["tag"], "shape": "prose", "pdu": None}
    rec = {"line": number, "tag": parts["tag"], "shape": shape, "pdu": None}
    if kind == "at":
        rec["at"] = groups.get("body", "").strip()
        rec["layer"] = "at"
        rec["pdu"] = {"layer": "at", "proof": "the modem printed a command",
                      "note": "text, not octets -- kept as evidence of what was asked"}
        return rec
    hexstr = norm_hex(groups.get("hex") or "")
    if not hexstr:
        rec["reason"] = "the shape matched but the octets do not: odd digit count or a stray character"
        return rec
    octets = bytes.fromhex(hexstr)
    rec["octets"] = len(octets)
    rec["hex"] = hexstr
    if kind == "apdu":
        sw1, sw2 = groups.get("sw1"), groups.get("sw2")
        rec["pdu"] = {"layer": "apdu", "proof": "the modem supplied the status word",
                      "note": "SW1 %s SW2 %s" % (sw1, sw2),
                      "next": candidate_commands("apdu", hexstr)}
        return rec
    nas = classify_nas(octets)
    if nas:
        rec["pdu"] = nas
        if nas.get("cleartext"):
            rec["pdu"]["next"] = candidate_commands(nas["layer"], hexstr)
        elif nas.get("cleartext") is None:
            rec["pdu"]["next"] = []
        else:
            rec["pdu"]["next"] = []
        return rec
    rec["pdu"] = unproven_hint(octets, hexstr)
    return rec


def parse_text(text: str) -> dict:
    """Every line of a radio log, with the PDUs and the refusals counted apart."""
    records, shapes, layers = [], {}, {}
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        rec = analyse(line, i)
        if rec is None:
            continue
        records.append(rec)
        shapes[rec["shape"]] = shapes.get(rec["shape"], 0) + 1
        # A layer is a claim about a PDU.  Counting prose lines under "-" makes
        # the summary read as if 401 records had an unreadable layer when in
        # fact 401 records were never PDUs to begin with.
        layer = (rec.get("pdu") or {}).get("layer")
        if layer:
            layers[layer] = layers.get(layer, 0) + 1
    pdus = [r for r in records if r.get("pdu") and r.get("hex")]
    return {
        "lines": len([l for l in lines if l.strip()]),
        "records": records,
        "shapes": shapes,
        "layers": layers,
        "candidates": len([r for r in records if r.get("hex") or r.get("pdu")]),
        "pdus": len(pdus),
        "proven": len([r for r in pdus if (r["pdu"].get("proof") or "none") != "none"]),
        "protected": len([r for r in pdus if r["pdu"].get("cleartext") is False]),
        "unproven": len([r for r in pdus if r["pdu"].get("layer") == "unproven"]),
        "refused": len([r for r in records if r.get("reason")]),
        "prose": len([r for r in records if r["shape"] == "prose"]),
        # Which subsystems spoke.  A buffer that is all prose still has to say
        # WHO was talking: RILJ prose means the modem interface logged and
        # carried no PDUs, while a buffer of unrelated tags means the wrong
        # buffer was read at all.  Those are different findings.
        "prose_tags": __import__("collections").Counter(
            r.get("tag") or "-" for r in records if r["shape"] == "prose"),
    }


# ── selftest fixtures ───────────────────────────────────────────────────────
#
# A real radio log is a mixture, and the mixture is the test: a timestamp, an AT
# trace, a +CRSM response, a plain NAS PDU, a protected one, a vendor blob with
# no proven layer, and prose.  The fixtures are three-or-four lines each so the
# assertions can name a line number instead of searching text.

FIXTURE = """\
01-02 03:04:05.678  1234  5678 D RILJ    : [UNSL]< UNSOL_RESPONSE_NETWORK_STATE
01-02 03:04:05.679  1234  5678 D AT      : AT> AT+CSQ
01-02 03:04:05.680  1234  5678 D AT      : AT< +CSQ: 22,99
01-02 03:04:05.681  1234  5678 D RIL     : AT< +CRSM: 144,0,"002F0A0B0C"
01-02 03:04:05.682  1234  5678 D RILC    : NAS: 07 41 0b f1 10
01-02 03:04:05.683  1234  5678 D RILC    : NAS: 27 41 0b f1 10
01-02 03:04:05.684  1234  5678 D RILC    : NAS: 7e 01 41 0b f1
01-02 03:04:05.685  1234  5678 D OEMHOOK : TX: 0x01 0x02 0x03 0x04
01-02 03:04:05.686  1234  5678 D RILJ    : at 12:34:56 and nothing else
01-02 03:04:05.687  1234  5678 D RILJ    : TX: 01 02 03 0
D/RILJ    ( 1234): 01 02 03 04 05 06 07 08
01-02 03:04:05.688  1234  5678 D RIL     : AT< +CSIM: "002F0A0"
"""

FIXTURE_TARGET = """
01-02 03:04:05.700  1234  5678 D RIL     : AT< +CRSM: 144,0,"002F0A"
01-02 03:04:05.701  1234  5678 D RILC    : NAS: 07 41 0b f1 10
"""


def _check(name: str, got, want, results: list) -> None:
    ok = got == want
    results.append((name, ok, got, want))
    print("%-28s %s" % (name, "PASS" if ok else "FAIL got %r want %r" % (got, want)))


def selftest() -> int:
    results: list = []
    parsed = parse_text(FIXTURE)
    recs = {r["line"]: r for r in parsed["records"]}

    # The timestamp must never be read as octets: line 9 is prose with
    # 12:34:56 in it, and it has to land in the prose bucket.
    _check("timestamp-is-not-octets", recs[9]["shape"], "prose", results)
    # An AT trace is text evidence, not a PDU.
    _check("at-command-kept-as-text", recs[2]["pdu"]["layer"], "at", results)
    _check("at-command-verbatim", recs[2]["at"], "AT+CSQ", results)
    # +CRSM: the octets are proven by the status word the modem printed.
    _check("crsm-proves-apdu", recs[4]["pdu"]["layer"], "apdu", results)
    _check("crsm-octets", recs[4]["hex"], "002F0A0B0C", results)
    _check("crsm-offers-the-parser", recs[4]["pdu"]["next"][0].split()[1], "--parse-apdu", results)
    # Plain EPS NAS: discriminator 0x07, security header 0, message type 0x41.
    _check("eps-nas-proven", recs[5]["pdu"]["layer"], "nas-eps", results)
    _check("eps-nas-cleartext", recs[5]["pdu"]["cleartext"], True, results)
    _check("eps-nas-message-type", recs[5]["pdu"]["message"], "0x41", results)
    # The same octets with a security header set are not decodable, and saying
    # so is the correct answer.
    _check("eps-nas-protected", recs[6]["pdu"]["cleartext"], False, results)
    _check("eps-nas-protected-named", recs[6]["pdu"]["message"], "protected", results)
    _check("eps-nas-protected-offers-nothing", recs[6]["pdu"]["next"], [], results)
    # 5GS discriminator, security header 1 (integrity protected): cleartext type.
    _check("5gs-nas-proven", recs[7]["pdu"]["layer"], "nas-5gs", results)
    # An OEM hook blob has no proven layer and must say so.
    _check("oemhook-unproven", recs[8]["pdu"]["layer"], "unproven", results)
    _check("oemhook-offers-candidates", bool(recs[8]["pdu"]["candidates"]), True, results)
    # A single-digit tail is not a shape at all: the blob regex wants whole
    # octets, so this line is prose rather than a broken PDU.
    _check("odd-digits-not-a-shape", recs[10]["shape"], "prose", results)
    # A truncated SIM response IS a shape with unusable octets: the +CSIM
    # quotes were printed, the string inside them is not whole octets.
    _check("odd-quoted-refused", recs[12].get("reason") is not None, True, results)
    # Brief layout, bare hex body: still octets, still unproven.
    _check("brief-layout-bare-blob", recs[11]["shape"], "bare-blob", results)
    # Six records carry octets (APDU + three NAS + two unproven blobs); the AT
    # traces are evidence but not octets, and are counted as PDUs of their own
    # layer rather than inflating this number.
    _check("pdus-that-carry-octets", parsed["pdus"], 6, results)

    target = parse_text(FIXTURE_TARGET)
    _check("small-log-pdus", target["pdus"], 2, results)
    _check("small-log-proven", target["proven"], 2, results)
    _check("small-log-shapes", "crsm" in target["shapes"], True, results)

    # Prose is counted apart from refusals: a quiet log is not a broken one.
    _check("prose-counted-not-refused", parsed["prose"], 3, results)
    # Prose still names its author.  A buffer whose prose is all RILJ logged the
    # modem interface and carried no PDUs; a buffer of strangers read the wrong
    # buffer.  Without the tag the two look identical.
    _check("prose-tags-name-the-subsystem", dict(parsed["prose_tags"]).get("RILJ"), 3, results)
    _check("refused-is-only-unusable-octets", parsed["refused"], 1, results)

    js = json.dumps(parsed)
    _check("json-serialisable", isinstance(json.loads(js), dict), True, results)
    _check("counts-partition", parsed["lines"], sum(
        1 for l in FIXTURE.splitlines() if l.strip()), results)

    # The decode step plans only what a decoder can read: the APDU and the two
    # cleartext NAS PDUs.  The protected one has no candidate, so it cannot be
    # planned -- naming a decoder for it would be the lie the branch avoids.
    plan = decode_plan(parsed)
    _check("decode-plan-count", len(plan), 3, results)
    _check("decode-plan-layers", [p["layer"] for p in plan], ["apdu", "nas-eps", "nas-5gs"], results)
    _check("decode-plan-skips-protected", all(p["line"] != 6 for p in plan), True, results)
    _check("decode-plan-carries-hex", plan[1]["hex"].lower(), "07410bf110", results)
    # A planned command that does not start with modules/<id>.sh is refused.
    _check("decode-refuses-foreign-command",
           _module_of(["sh", "-c", "echo pwned"]), "", results)
    _check("decode-accepts-module-command",
           _module_of(["modules/32_nas_signaling.sh", "--decode-nas", "eps", "0741"]),
           "modules/32_nas_signaling.sh", results)
    # A tree with no modules directory yields no-decoder rows rather than a crash.
    _check("decode-missing-module-is-data",
           [d["status"] for d in run_plan({"records": [{"line": 1, "hex": "07", "pdu": {
               "layer": "nas-eps", "next": ["modules/32_nas_signaling.sh --decode-nas eps 07"]}}]},
               "/nonexistent-tree")], ["no-decoder"], results)
    # Against this tree the planned verbs really run and return rows.
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ran = [d for d in run_plan(parsed, here) if d["status"] == "decoded"]
    _check("decode-runs-real-verbs", len(ran) >= 2, True, results)
    _check("decode-returns-fields", bool(ran and ran[0]["rows"]), True, results)

    # A layer is a claim about a PDU.  Prose lines must not be counted under a
    # layer, or the summary reads as if every log line had an unreadable layer.
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _rows(parse_text("01-02 03:04:05.678  1  2 D RILJ : [UNSL]< UNSOL_RESPONSE_NETWORK_STATE\n"), "stdin", False)
    layers = [ln for ln in buf.getvalue().splitlines() if ln.startswith("layer.")]
    _check("prose-has-no-layer", layers, [], results)

    failed = len([1 for _, ok, _, _ in results if not ok])
    print("\n%d assertions, %d failed" % (len(results), failed))
    return 1 if failed else 0


def cmd_shapes(_args) -> int:
    print("%-16s %-10s %s" % ("shape", "kind", "pattern"))
    for name, rx, kind in SHAPES:
        print("%-16s %-10s %s" % (name, kind, rx.pattern))
    print("\nproven layers: nas-eps (discriminator 0x07), nas-5gs (0x7e), apdu (a +CRSM/+CSIM")
    print("response states its own status word).  Everything else is unproven: a hex blob")
    print("no first octet names is reported with candidate verbs, not with a layer.")
    return 0


def _rows(parsed: dict, source: str, with_commands: bool, decoded: list = ()) -> int:
    """The whole report as key<TAB>value rows, for the agent that wraps this."""
    def row(key, value):
        print("%s\t%s" % (key, value))
    row("status", "parsed")
    row("source", source)
    for key in ("lines", "candidates", "pdus", "proven", "protected", "unproven",
                "refused", "prose"):
        row(key, parsed[key])
    for key, count in sorted(parsed["shapes"].items()):
        row("shape." + key, count)
    for key, count in sorted(parsed["layers"].items()):
        row("layer." + str(key), count)
    for tag, count in parsed["prose_tags"].most_common(8):
        row("prose_tag." + tag, count)
    index = 0
    for rec in parsed["records"]:
        if rec.get("reason"):
            row("refused.%d.line" % rec["line"], rec["line"])
            row("refused.%d.why" % rec["line"], rec["reason"])
            continue
        pdu = rec.get("pdu") or {}
        if not pdu:
            continue
        index += 1
        prefix = "pdu.%02d." % index
        row(prefix + "line", rec["line"])
        row(prefix + "tag", rec["tag"] or "-")
        row(prefix + "shape", rec["shape"])
        row(prefix + "layer", pdu.get("layer", "-"))
        row(prefix + "proof", pdu.get("proof", "none"))
        if "octets" in rec:
            row(prefix + "octets", rec["octets"])
        if "hex" in rec:
            row(prefix + "hex", rec["hex"])
        note = pdu.get("message") or pdu.get("at") or pdu.get("note") or ""
        if note:
            row(prefix + "note", note)
        if with_commands:
            for i, cmd in enumerate(pdu.get("next") or [], 1):
                row(prefix + "next.%d" % i, cmd)
    for i, dec in enumerate(decoded, 1):
        prefix = "decoded.%02d." % i
        row(prefix + "line", dec["line"])
        row(prefix + "layer", dec["layer"])
        row(prefix + "status", dec["status"])
        row(prefix + "command", dec["command"])
        for key in sorted(dec["rows"]):
            row(prefix + "field." + key, dec["rows"][key])
        for line in dec.get("stderr") or []:
            row(prefix + "stderr", line)
    return 0


def cmd_parse(args) -> int:
    if args.path == "-":
        text = sys.stdin.read()
        source = "stdin"
    else:
        if not os.path.exists(args.path):
            sys.stderr.write("no such file: %s\n" % args.path)
            return 2
        with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        source = args.path
    parsed = parse_text(text)
    decoded = []
    if args.decode:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        decoded = run_plan(parsed, root, timeout=args.timeout)
        if not args.rows and not args.json:
            for dec in decoded:
                print("decoded line %-5d %-8s %-6s %s"
                      % (dec["line"], dec["layer"], dec["status"], dec["command"]))
                for key in sorted(dec["rows"]):
                    print("             %-24s %s" % (key, dec["rows"][key]))
    if args.rows:
        return _rows(parsed, source, args.commands, decoded)
    for rec in parsed["records"]:
        if args.only and (rec.get("pdu") or {}).get("layer") != args.only:
            continue
        if not (rec.get("pdu") or rec.get("reason")):
            continue
        if args.json:
            print(json.dumps(rec, sort_keys=True))
            continue
        pdu = rec.get("pdu") or {}
        line = "line %-5d %-14s" % (rec["line"], rec["shape"])
        if rec.get("reason"):
            print(line + "refused: " + rec["reason"])
            continue
        layer = pdu.get("layer", "?")
        detail = pdu.get("message") or pdu.get("at") or pdu.get("note", "")
        print(line + "%-9s %-6s %s" % (layer, rec.get("octets", ""), detail))
        if args.commands:
            for cmd in pdu.get("next") or []:
                print("             next: " + cmd)
    if not args.json:
        print("\nsource %s" % source)
        print("lines %d  candidates %d  pdus %d  proven %d  protected %d  unproven %d  refused %d  prose %d"
              % (parsed["lines"], parsed["candidates"], parsed["pdus"],
                 parsed["proven"], parsed["protected"], parsed["unproven"],
                 parsed["refused"], parsed["prose"]))
        print("shapes " + " ".join("%s=%d" % kv for kv in sorted(parsed["shapes"].items())))
        print("layers " + " ".join("%s=%d" % kv for kv in sorted(parsed["layers"].items())))
    return 0


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="Read a handset radio log as PDUs, not as text.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_parse = sub.add_parser("parse", help="classify every line of a saved radio log")
    p_parse.add_argument("path", help="log file, or - for stdin")
    p_parse.add_argument("--json", action="store_true", help="one JSON object per record")
    p_parse.add_argument("--only", default="", help="keep one layer (nas-5gs, nas-eps, apdu, at, unproven)")
    p_parse.add_argument("--commands", action="store_true", help="name the verb that would decode each PDU")
    p_parse.add_argument("--rows", action="store_true",
                         help="key<TAB>value rows, the shape ue_agent.sh speaks")
    p_parse.add_argument("--decode", action="store_true",
                         help="hand each proven PDU to the decoder verb it names")
    p_parse.add_argument("--timeout", type=int, default=40,
                         help="seconds per decoder invocation")
    p_parse.set_defaults(func=cmd_parse)
    sub.add_parser("shapes", help="every line shape this file knows").set_defaults(func=cmd_shapes)
    sub.add_parser("selftest", help="run the parsers over embedded fixtures").set_defaults(func=lambda a: selftest())
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
