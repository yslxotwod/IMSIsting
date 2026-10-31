#!/usr/bin/env python3
"""NGAP fuzz corpus for modules/13_nr_core.sh -- generator, plan, pcap, sender.

The corpus is built, never guessed.  Every case is an NGAP-PDU assembled from
the same PER primitives (tools/ngap_asn1.py) that the module's builders use,
so a case differs from a module message in exactly one named field.  Each case
carries the clause of TS 38.413 that governs that field and a predictor: what
a correct implementation must do with the octets.  A case that no clause can
settle is not in the corpus -- a fuzzer with an opinion is just noise.

  * The plan is deterministic: the seed drives the value choices (counts, ids,
    NAS payload), not the structure, so a case name always means the same
    defect.  Re-running a seed reproduces the corpus octet for octet.
  * Nothing leaves the machine unless --transmit is given, and even then the
    sender refuses to run without an SCTP peer address.  That flag is for a
    lab the operator owns; the module reaches it only through a separate verb
    whose usage line says so.
  * --pcap writes the hand-built SCTP frames the referee reads.  text2pcap
    cannot frame a bare PDU, so the SCTP common header, one DATA chunk with
    PPID 60, the IPv4 wrapper and the pcap header are written here.

Exit 0 plan/pcap written, 1 send attempted and some case got no answer, 2
usage or a missing tool.
"""

import argparse
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from ngap_asn1 import (AperWriter, _container, _criticality_octet,  # noqa: E402
                       _ie_field, _open_type, ie_amf_ue_ngap_id, ie_nas_pdu,
                       ie_ran_ue_ngap_id, ie_user_location_information,
                       IE_AMF_UE_NGAP_ID, IE_NAS_PDU, IE_RAN_UE_NGAP_ID,
                       IE_USER_LOCATION_INFORMATION)

# TS 38.413 clause 9.1 (elementary procedures) and 9.3.1.9 (the PDU's fields).
# The two procedure codes are the ones this tree already writes:
#   id-InitialUEMessage = 15, id-DownlinkNASTransport = 4
# tshark 4.2.2 names both out of the bytes the module builds, which is where
# these numbers come from -- not from a summary of the clause.
PROC_INITIAL_UE = 15
PROC_DOWNLINK_NAS = 4
PDU_INITIATING = 0
PDU_CHOICE_UNASSIGNED = 3        # 9.3.1.9: three alternatives plus the
                                 # extension alternative, so index 3 has no
                                 # message behind it and must be discarded.

PLMN = "001/01"
TAC = "000001"
NCI_36 = 0x0000000AB                # 36 bits, TS 38.413 9.3.1.9 NR-CGI


def envelope(choice, procedure_code, criticality, body):
    """NGAP-PDU: the CHOICE sits in the top three bits of the first octet.

    9.3.1.9: the CHOICE is extensible with three alternatives, so the bit
    field is the extension bit plus a two-bit index -- and because the PDU is
    the outermost type it is padded to an octet boundary.  Writing the index
    as two bits and letting the procedure code follow immediately produces a
    message tshark reads with procedureCode 192: the code straddles octets.
    """
    writer = AperWriter()
    writer.octet(choice << 5)       # ext bit + 2-bit index, then pad
    writer.octet(procedure_code)    # ProcedureCode, 0..255
    writer.octet(criticality)       # Criticality, two bits in the top
    _open_type(writer, body)        # the message as an open type
    return writer.taked()


def body(ie_fields):
    return _container(ie_fields)


def ie_with_criticality_octet(ie_id, octet, payload):
    """A ProtocolIE-Field whose Criticality octet is whatever we say."""
    writer = AperWriter()
    writer.bits(ie_id, 16)
    writer.octet(octet)
    _open_type(writer, payload)
    return writer.taked()


# ---------------------------------------------------------------------------
# The cases.  Each one is (name, family, varies, clause, must, build(context)).
# ---------------------------------------------------------------------------

def case_control(ctx):
    """A message this module already builds, kept as the reference row.

    If this case stops decoding as an InitialUEMessage with its three IEs, the
    corpus is broken and no other row means anything.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"]),
                          ie_nas_pdu(ctx["nas"]),
                          ie_user_location_information(PLMN, NCI_36, TAC)]))


def case_pdu_choice_unassigned(ctx):
    """9.3.1.9: the NGAP-PDU CHOICE has no alternative 3.

    A receiver must discard the PDU.  An encoder/receiver pair that reads the
    bit field as a two-bit index with no bound check will decode whatever
    follows as if it were an initiating message.
    """
    writer = AperWriter()
    writer.octet(PDU_CHOICE_UNASSIGNED << 5)   # ext bit 0, index 3 = extensions
    writer.octet(PROC_INITIAL_UE)
    writer.octet(_criticality_octet("reject"))
    _open_type(writer, body([ie_ran_ue_ngap_id(ctx["ran_ue"])]))
    return writer.taked()


def case_procedure_unassigned(ctx):
    """9.1: procedureCode 0 is not an elementary procedure.

    A receiver must reject the message.  An implementation that switches on a
    table without a default silently drops it and reports nothing -- which is
    the failure this case is looking for.
    """
    return envelope(PDU_INITIATING, 0, _criticality_octet("reject"),
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"])]))


def case_criticality_reserved(ctx):
    """9.3.1.9: Criticality is reject(0)/ignore(1)/notify(2); 3 is unassigned.

    A receiver must reject the PDU rather than guess.  The octet carries the
    value in its two most significant bits.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, 0xC0,
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"])]))


def case_ie_id_unknown_reject(ctx):
    """9.3.4: an IE with an id the receiver does not know, criticality reject.

    A receiver must reject the whole message, not the IE.  Discarding just the
    unknown IE is the classic silent-zero failure: the procedure continues
    with a mandatory value missing.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"]),
                          _ie_field(ctx["unknown_ie_id"], "reject", b"\x00")]))


def case_ie_id_unknown_ignore(ctx):
    """9.3.4: the same unknown IE with criticality ignore.

    A receiver must skip the IE and deliver the rest, so the RAN UE NGAP ID
    still arrives.  This is the pair to the case above: the criticality octet
    is the only difference between reject-the-message and skip-the-IE.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"]),
                          _ie_field(ctx["unknown_ie_id"], "ignore", b"\x00")]))


def case_ie_criticality_reserved(ctx):
    """9.3.4: a known IE carrying the unassigned criticality 3.

    A receiver must reject the message; a receiver that masks the two bits and
    treats 3 as ignore accepts a message it should have refused.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_with_criticality_octet(IE_RAN_UE_NGAP_ID, 0xC0,
                                                    b"\x00\x00\x00\x01"),
                          ie_nas_pdu(ctx["nas"])]))


def case_ie_length_overrun(ctx):
    """9.3.3: an IE's length determinant claims more octets than remain.

    A receiver must reject the message on the truncation.  A receiver that
    reads the declared length and trusts the buffer overruns it, and on a
    conformant stack the failure is a discard rather than a crash.
    """
    declared = len(ctx["nas"]) + 8
    writer = AperWriter()
    writer.bits(IE_NAS_PDU, 16)
    writer.octet(_criticality_octet("reject"))
    writer.length_determinant(declared)      # claims too many
    writer.octets(ctx["nas"])                # supplies too few
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"]), writer.taked()]))


def case_ie_length_zero(ctx):
    """9.3.3: a zero-length NAS-PDU.

    An empty NAS PDU is not a legal 5GMM message, so the AMF must not treat
    the IE's presence as content.  The interesting answer is a named cause,
    not a silent success.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"]), ie_nas_pdu(b"")]))


def case_mandatory_ie_missing(ctx):
    """9.3.1.9: RAN-UE-NGAP-ID is mandatory in InitialUEMessage (M).

    A receiver must reject the message.  A receiver that defaults the missing
    id to zero has invented a UE identity -- exactly the silent zero that the
    doctrine vocabulary exists to catch.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_nas_pdu(ctx["nas"]),
                          ie_user_location_information(PLMN, NCI_36, TAC)]))


def case_ie_order_swapped(ctx):
    """9.3.4: ProtocolIE-Container is a SEQUENCE OF, so order is not semantic.

    A receiver must find IEs by id.  A receiver that reads them positionally
    binds the NAS PDU to the RAN UE NGAP ID here, and the case makes that
    mistake visible instead of silent.
    """
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    body([ie_nas_pdu(ctx["nas"]),
                          ie_ran_ue_ngap_id(ctx["ran_ue"]),
                          ie_user_location_information(PLMN, NCI_36, TAC)]))


def case_container_count_lies(ctx):
    """9.3.4: the container count says zero while IE fields follow.

    A receiver that trusts the count delivers nothing and reports success.  A
    correct receiver reports the trailing octets as a decode failure; the
    interesting part is that nothing may be silently accepted.
    """
    writer = AperWriter()
    _open_type(writer, b"")          # count 0, no IE fields at all
    writer.octets(body([ie_ran_ue_ngap_id(ctx["ran_ue"])]))  # trailing garbage
    return envelope(PDU_INITIATING, PROC_INITIAL_UE, _criticality_octet("reject"),
                    writer.taked())


def case_downlink_amf_id_missing(ctx):
    """9.3.1.9: AMF-UE-NGAP-ID is mandatory in DownlinkNASTransport (M).

    A receiver must reject the message.  This is the downlink half of the
    missing-mandatory-IE case: the same defect on the other direction, where
    the victim is the handset rather than the core.
    """
    return envelope(PDU_INITIATING, PROC_DOWNLINK_NAS, _criticality_octet("reject"),
                    body([ie_ran_ue_ngap_id(ctx["ran_ue"]),
                          ie_nas_pdu(ctx["nas"])]))


CASES = [
    ("ngap-control", "control", "nothing (reference)",
     "TS 38.413 9.3.1.9", "decode as InitialUEMessage with its three IEs",
     case_control),
    ("ngap-pdu-choice-unassigned", "header", "NGAP-PDU CHOICE index",
     "TS 38.413 9.3.1.9", "discard the PDU; index 3 has no alternative",
     case_pdu_choice_unassigned),
    ("ngap-procedure-unassigned", "header", "procedureCode",
     "TS 38.413 9.1", "reject the message; code 0 is not a procedure",
     case_procedure_unassigned),
    ("ngap-criticality-reserved", "header", "Criticality octet",
     "TS 38.413 9.3.1.9", "reject the PDU; 3 is unassigned",
     case_criticality_reserved),
    ("ngap-ie-id-unknown-reject", "ies", "one unknown IE id, criticality reject",
     "TS 38.413 9.3.4", "reject the whole message, not just the IE",
     case_ie_id_unknown_reject),
    ("ngap-ie-id-unknown-ignore", "ies", "one unknown IE id, criticality ignore",
     "TS 38.413 9.3.4", "skip the IE and deliver the RAN UE NGAP ID",
     case_ie_id_unknown_ignore),
    ("ngap-ie-criticality-reserved", "ies", "a known IE's Criticality octet",
     "TS 38.413 9.3.4", "reject the message; do not read 3 as ignore",
     case_ie_criticality_reserved),
    ("ngap-ie-length-overrun", "ies", "NAS-PDU open-type length determinant",
     "TS 38.413 9.3.3", "reject on the truncation",
     case_ie_length_overrun),
    ("ngap-ie-length-zero", "ies", "NAS-PDU payload",
     "TS 38.413 9.3.3", "name a cause; an empty NAS PDU is not a 5GMM message",
     case_ie_length_zero),
    ("ngap-mandatory-ie-missing", "ies", "presence of RAN-UE-NGAP-ID",
     "TS 38.413 9.3.1.9", "reject the message; do not default the id to zero",
     case_mandatory_ie_missing),
    ("ngap-ie-order-swapped", "ies", "order of the IE fields",
     "TS 38.413 9.3.4", "find IEs by id; order is not semantic",
     case_ie_order_swapped),
    ("ngap-container-count-lies", "ies", "ProtocolIE-Container count",
     "TS 38.413 9.3.4", "report trailing octets; deliver nothing silently",
     case_container_count_lies),
    ("ngap-downlink-amf-id-missing", "downlink", "presence of AMF-UE-NGAP-ID",
     "TS 38.413 9.3.1.9", "reject the message",
     case_downlink_amf_id_missing),
]

FAMILIES = sorted({case[1] for case in CASES})


# ---------------------------------------------------------------------------
# tshark framing -- written by hand for the reason in the docstring.
# ---------------------------------------------------------------------------

def sctp_datagram(payload):
    chunk = (struct.pack("!BBH", 0, 0x03, 16 + len(payload))
             + struct.pack("!IHHI", 1, 0, 0, 60) + payload)
    return struct.pack("!HHII", 38412, 38412, 0, 0) + chunk


def ipv4_datagram(payload):
    def addr(text):
        return bytes(int(part) for part in text.split("."))
    return (struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                        64, 132, 0, addr("10.0.0.1"), addr("10.0.0.2"))
            + payload)


def write_pcap(path, payloads):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for index, payload in enumerate(payloads):
            frame = ipv4_datagram(sctp_datagram(payload))
            handle.write(struct.pack("<IIII", 1600000000 + index, 0,
                                     len(frame), len(frame)))
            handle.write(frame)


# ---------------------------------------------------------------------------
# Sending.  Reached only with --transmit and a peer.
# ---------------------------------------------------------------------------

def transmit(host, port, hexes, rate, timeout, verbose):
    sender = os.path.join(HERE, "sctp_assoc.py")
    if not os.path.exists(sender):
        raise RuntimeError("no sender at %s" % (sender,))
    gap = 1.0 / rate if rate > 0 else 0.0
    for name, octets in hexes:
        cmd = [sys.executable, sender, "send", host, str(port), octets.hex(),
               "--ppid", "60", "--wait", str(timeout)]
        try:
            done = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=max(2.0, timeout + 2.0))
        except Exception as exc:                     # noqa: BLE001
            yield name, "send-error: %s" % (exc,)
            continue
        out = done.stdout
        if done.returncode != 0:
            yield name, "send-error: rc=%d %s" % (done.returncode,
                                                  done.stderr.strip()[:80])
        elif "\tdata\t" in out or out.strip():
            # Any octets back on PPID 60 are an NGAP answer -- the peer spoke.
            yield name, "answered"
        else:
            yield name, "unobserved"
        if verbose:
            sys.stderr.write("%s -> %s\n" % (name, out.strip()[:120]))
        if gap:
            time.sleep(gap)


def main(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--family", default="")
    parser.add_argument("--max", type=int, default=0)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--plan-tsv", default="")
    parser.add_argument("--pcap", default="")
    parser.add_argument("--transmit", action="store_true")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=38412)
    parser.add_argument("--rate", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    if args.help:
        sys.stdout.write(__doc__)
        return 0
    if args.list:
        for name, family, varies, clause, must, _ in CASES:
            sys.stdout.write("%s\t%s\t%s\t%s\t%s\n"
                             % (name, family, varies, clause, must))
        return 0
    if args.transmit and not args.host:
        sys.stderr.write(
            "ERROR\t--transmit needs --host: this tool sends only at a peer "
            "in a lab the operator owns\n")
        return 2
    if args.family and args.family not in FAMILIES:
        sys.stderr.write("ERROR\tunknown family %s (have: %s)\n"
                         % (args.family, ", ".join(FAMILIES)))
        return 2

    rng = random.Random(args.seed)
    # The seed chooses values, never structure: a case name always means the
    # same defect, so a result row can be compared between runs.
    ctx = {
        "ran_ue": rng.randrange(1, 0xFFFF),
        # The module's own default NAS PDU, so "malformed" in a decode means
        # the NGAP case and not the handset's registration message.
        "nas": bytes.fromhex("7e0041012e0100"),
        "unknown_ie_id": rng.choice([300, 321, 64000]),
    }

    selected = [case for case in CASES
                if not args.family or case[1] == args.family]
    if args.max:
        selected = selected[:args.max]

    rows = []
    octets_by_name = {}
    for name, family, varies, clause, must, build in selected:
        octets = build(ctx)
        octets_by_name[name] = octets
        rows.append({
            "case": name, "family": family, "varies": varies, "clause": clause,
            "must": must, "octets": len(octets), "hex": octets.hex(),
            "verdict": "planned",
        })

    if args.transmit:
        for name, verdict in transmit(args.host, args.port,
                                      [(row["case"], bytes.fromhex(row["hex"]))
                                       for row in rows],
                                      args.rate, args.timeout, args.verbose):
            for row in rows:
                if row["case"] == name:
                    row["verdict"] = verdict

    if args.pcap:
        write_pcap(args.pcap, [bytes.fromhex(row["hex"]) for row in rows])

    columns = ["case", "family", "varies", "clause", "must", "octets", "hex",
               "verdict"]
    if args.plan_tsv:
        with open(args.plan_tsv, "w", encoding="utf-8") as handle:
            handle.write("\t".join(columns) + "\n")
            for row in rows:
                handle.write("\t".join(str(row[column]) for column in columns) + "\n")

    stdout = sys.stdout
    stdout.write("\t".join(columns) + "\n")
    for row in rows:
        stdout.write("\t".join(str(row[column]) for column in columns) + "\n")

    mode = "transmitted" if args.transmit else "planned"
    stdout.write("cases\t%d\n" % (len(rows),))
    stdout.write("mode\t%s\n" % (mode,))
    stdout.write("seed\t%d\n" % (args.seed,))
    for family in FAMILIES:
        stdout.write("family_%s\t%d\n"
                     % (family, sum(1 for row in rows if row["family"] == family)))
    if args.transmit:
        answered = sum(1 for row in rows if row["verdict"].startswith("answered"))
        stdout.write("answered\t%d\n" % (answered,))
        stdout.write("unobserved\t%d\n"
                     % (sum(1 for row in rows if row["verdict"] == "unobserved"),))
        stdout.write("send_error\t%d\n"
                     % (sum(1 for row in rows
                            if row["verdict"].startswith("send-error")),))
        stdout.write("note\tsilence is unobserved, not absent: nothing came "
                     "back, which does not prove the peer rejected the case\n")
    else:
        stdout.write("sent\tnothing: this run built the corpus and planned "
                     "it; --transmit is the only wire path\n")
    stdout.write("clauses\t%s\n"
                 % (", ".join(sorted({row["clause"] for row in rows})),))
    return 0 if not args.transmit else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
