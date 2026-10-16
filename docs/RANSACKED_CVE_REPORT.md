# The RANsacked disclosure: a reading of the CVE corpus

**Source:** <https://cellularsecurity.org/ransacked.html> — Cellular Security / Florida
Institute for Cybersecurity Research (FICS). Paper: <https://nathanielbennett.com/publications/ransacked.pdf>
**Captured:** locally as `/tmp/ransacked.html`, stripped to `/tmp/ransacked.txt` (2,915 lines).
**Status of this document:** the page is external, untrusted material. Everything below is
*what the page states*, re-tabulated and cross-checked against the captured text. No claim here
has been independently reproduced; the numbers we could check against the page's own words are
marked as verified, the rest are the authors' assertions.

---

## 1. What the page claims

- **119 vulnerabilities** in LTE and 5G core-network infrastructure.
- Every one of them can cause **persistent denial of cell service to a whole metropolitan area**.
- Some give **remote compromise of the core**, from which subscriber location and connection data
  can be monitored city-wide, or the attack pivoted to the HSS/UDM for nation-wide disruption.
- Seven LTE cores tested (`Open5GS`, `Magma`, `OpenAirInterface`, `Athonet`, `SD-Core`,
  `NextEPC`, `srsRAN`) and three 5G cores (`Open5GS`, `Magma`, `OpenAirInterface`).
  Vulnerabilities were found in **every implementation tested**.
- A **proof-of-concept RCE** was written for one SD-Core bug.

The stated severity mechanism is uniform: an **unauthenticated** party, with no SIM, sends one
crafted protocol message at the start of a cellular connection and crashes the MME (LTE) or AMF
(5G). Disruption lasts until operators identify and patch it.

Two threat models are named:

1. **Any unauthenticated mobile device** — no valid SIM, only the ability to emit the right
   malformed sequence (e.g. from an SDR). Traditionally bounded by radio distance.
2. **Base-station access to the core** — via a compromised base station/femtocell (physical
   access → RAM/flash dump → IPsec key extraction), or via the IPsec backhaul network directly.

The claim that makes model 1 much larger than it sounds is that **widespread Wi-Fi Calling turns
the NAS-side attacks into internet-reachable ones**: "these same attacks can be exploited by any
entity on the Internet just by sending a few packets — no SIM card or SDR equipment required."

---

## 2. The corpus in numbers (verified against the captured text)

### 2.1 The declared ID space is exactly 119

The page labels entries `VULN-<letter><nn>`, one letter per implementation/generation group.
Counting every ID in every group's declared range:

| Group | Implementation / generation | Range | IDs |
|---|---|---|---|
| A | Open5GS, 5G | A01–A05 | 5 |
| B | OpenAirInterface, 5G NGAP | B01–B11 | 11 |
| C | Magma, 5G | C01–C20 | 20 |
| D | Magma / OpenAirInterface, LTE (shared code) | D01–D25 | 25 |
| E | NextEPC, LTE | E01–E09 | 9 |
| F | Open5GS, LTE | F01–F29 | 29 |
| G | srsRAN, LTE | G01 | 1 |
| H | SD-Core / Nucleus, LTE | H01–H09 | 9 |
| I | Athonet, LTE | I01–I08 | 8 |
| J | OpenAirInterface, LTE GTP | J01–J02 | 2 |
| | | **Total** | **119** |

**The headline number is internally consistent.** 119 is precisely the number of IDs the page
declares. There is no discrepancy to explain.

### 2.2 But only 102 of those IDs are actually printed

A scan of the captured text finds **102 distinct `VULN-` tokens**. The seventeen missing ones are
`C03`–`C19`: the page prints that group as a single heading,

```
CVE-2024-24426 (VULN-C02-VULN-C20):
...
These assertions manifest in 19 locations that require conditional branches to handle.
```

So the range contributes **19 IDs for one CVE and one root cause** — the same macro,
`NGAP_FIND_PROTOCOLIE_BY_ID`, asserting in 19 places. This is the single largest block in the
whole corpus and the one whose counting convention matters most.

### 2.3 92 distinct CVE numbers

- **91** distinct strings matching `CVE-YYYY-NNNN` appear in the text.
- A 92nd number, `CVE-2024-24427`, is printed **without the prefix** — the heading reads literally
  `2024-24427 (VULN-A04):`.
- The 2023 block is **fully contiguous**: `CVE-2023-36997` … `CVE-2023-37044`, 48 values, no gaps.
- The 2024 block has one gap: **`CVE-2024-24448` does not appear anywhere in the page**
  (the sequence runs 24447 → 24449). It is followed by `CVE-2024-34235`.
- **`CVE-2024-24447` is printed twice**, for `VULN-B04` and `VULN-B11` — two entries, one number.
- **9 IDs carry no CVE at all:** `A01`, `A03`, `A05`, `B03`, `J01`, `J02`, `F28`, `F29`, `D25`.

### 2.4 The gap that matters: 119 IDs, 92 CVEs

27 more IDs than CVE numbers. The reason is visible in the tables above: the C group alone
supplies **19 IDs for a single CVE**, and the F group supplies **23 IDs** (`F01`–`F23`) for what
the page itself describes as one repeated pattern — "missing required IE → failure to return an
error response". A reader who treats "119 vulnerabilities" as 119 distinct bugs, each with its own
root cause and its own fix, will overcount substantially. A reader who treats the 92 CVEs as the
unit will undercount, because 9 entries never got one.

**Neither number is a count of independent bugs.** The honest summary is: *119 labelled findings,
92 CVE identifiers, and a much smaller number of distinct root causes* — the page's own
description of the C and F groups implies that directly.

> **A correction to note.** An earlier pass over this page recorded "127 labelled rows" and then
> reasoned about an 8-row gap against the headline 119. That was an arithmetic error: the
> per-implementation table in that pass sums to **101**, not 127 (13 + 34 + 2 + 25 + 9 + 9 + 8 + 1).
> 101 is exactly what you get by collapsing the C02–C20 range to one row: 119 − 20 + 2 = 101.
> The "8-row gap" was an artefact of the bad total and does not exist. The numbers in §2.1–§2.4
> above are recomputed from the captured text.

---

## 3. Per-implementation totals

| Implementation | Generation | IDs | CVEs |
|---|---|---|---|
| Open5GS | 5G (A01–A05) | 5 | 2 |
| Open5GS | LTE (F01–F29) | 29 | 27 |
| Magma / OAI shared LTE code | LTE (D01–D25) | 25 | 25 |
| OpenAirInterface | 5G NGAP (B01–B11) | 11 | 9 |
| OpenAirInterface | LTE GTP (J01–J02) | 2 | 0 |
| Magma | 5G (C01–C20) | 20 declared / 3 printed | 2 |
| NextEPC | LTE (E01–E09) | 9 | 9 |
| SD-Core / Nucleus | LTE (H01–H09) | 9 | 9 |
| Athonet | LTE (I01–I08) | 8 | 8 |
| srsRAN | LTE (G01) | 1 | 1 |

The CVE column counts CVE identifiers attached to each group's headings, so it sums to the 92
distinct CVEs in §2.3. No CVE is shared *between* groups; the two within-group reuses are
`CVE-2024-24447` (B04 and B11) and `CVE-2024-24426` (C02 and C20).

The distribution is the story as much as the total: **Open5GS accounts for 34 of the 119**
(5 in 5G, 29 in LTE), and **Magma/OAI shared LTE code accounts for 25**. Those two lineage
groups are 59 of 119 — half the corpus — and they are the two most widely deployed open-source
cores.

---

## 4. Per-protocol and per-class totals

**By protocol:**

| Protocol | IDs | Note |
|---|---|---|
| S1AP | 56 | The largest surface by far; dominated by the Open5GS F01–F23 family |
| NAS | 47 | The class reachable from the *start* of a connection — the Wi-Fi Calling class |
| NGAP | 12 | 5G core |
| GTP / PFCP | 5 | Requires an established PFCP session in two cases (F28, F29) |
| SCTP socket layer | 2 | B05 (`FD_SET` beyond 1024), B06 (fd leak) |

**By class:**

| Class | IDs |
|---|---|
| Buffer overflow / out-of-bounds write | 27 |
| Reachable assertion | 21 |
| NULL / uninitialised pointer dereference | 17 |
| Invalid memory access (root cause not obtainable) | 8 |
| Out-of-bounds read | 5 |
| Unsigned integer underflow → OOB read | 1 |
| Resource exhaustion (fd leak) | 1 |
| `abort()` on a sentinel key | 1 |
| Unhandled exception | 1 |

The shape here is worth stating plainly: **the most common outcome is a crash, not a compromise.**
Reachable assertions (21) and null dereferences (17) together are 38 entries — a third of the
corpus — and their effect is denial of service, not code execution. The 27 overflows are the ones
that could plausibly reach remote access, and the page itself is careful about them: exploitability
"widely varies", and "in some cases, there may be no practical way of obtaining remote access
despite the presence of a memory corruption error". Only one PoC RCE is demonstrated.

---

## 5. The root causes, in four patterns

### 5.1 A wire-supplied length that is never checked against the buffer

This is the SD-Core group, the Athonet group, and the sharpest of the Magma/OAI NAS bugs.
`VULN-D17` / `CVE-2024-24416`, in `lte/gateway/c/core/oai/lib/3gpp/3gpp_24.008_sm_ies.c`:

```c
  ielen = *(buffer + decoded);
  decoded++;
  CHECK_LENGTH_DECODER(len - decoded, ielen);

  if (1 <= ielen) {
    int length_apn = *(buffer + decoded);
    // ^ length field read from packet, not checked against buffer length
    decoded++;
    *access_point_name = blk2bstr((void*)(buffer + decoded), length_apn);
    // ^ resulting string reads past the end of `buffer`
    decoded += length_apn;
```

The sibling `VULN-D16` / `CVE-2024-24419` in the same file repeats it for the packet filter:

```c
  uint8_t pkflen;
  IES_DECODE_U8(buffer, decoded, pkflen);
  // ^ likewise, more bytes read from wire prior to check
  int pkfstart = decoded;
  while (decoded - pkfstart < pkflen) {
    // ^ length field of packet not checked
```

SD-Core is the same pattern against ASN.1 `OCTET STRING` sizes: unchecked
`transportLayerAddress.size` into a 4-byte field, `gTP_TEID.size` into a `uint32_t`,
`targetToSrcTranspContainer.size` into a fixed struct, and raw `s1apNASPDU_p->size` into
`nasMsgBuf`.

### 5.2 An `asn1c` generator mismatch between the member array and the rows table

The entire NextEPC S1AP group (7 entries), plus Open5GS `F07`, concentrate on one line of
generated code, `OPEN_TYPE.c:440`:

```c
inner_value =
    (char *)*memb_ptr2
    + elm->type->elements[selected.presence_index - 1].memb_offset;
// ^ off-by-one buffer overflow occurs when selecting element type here
```

The cause is a table/array count disagreement in generated code, e.g. `VULN-E03` / `CVE-2024-24438`:

```c
static const asn_ioc_set_t asn_IOS_S1AP_HandoverRequiredIEs_1[] = {
    { 14, 4, asn_IOS_S1AP_HandoverRequiredIEs_1_rows }
};
...
asn_TYPE_descriptor_t asn_DEF_S1AP_value_76 = {
    "value", "value", &asn_OP_OPEN_TYPE,
    0, 0, 0, 0, 0, { 0, 0, OPEN_TYPE_constraint },
    asn_MBR_S1AP_value_76,
    13, /* Elements count */ // BUG: should be 14 elements
};
```

The missing member is an optional secondary value of the *same type as its predecessor*, so the
index does not just overrun — **every subsequent index resolves to the wrong type**. Overflow plus
type confusion, from a code-generation bug rather than a hand-written one. Analogous counts are
quoted for E02 (8 vs 9×4), E04 (25 vs 26×4), E05 (4 vs 6×4), E06 (6 vs 7×4), E07 (13 vs 14×4).

### 5.3 A bounds check present in one branch and missing in the other

`VULN-G01` / `CVE-2023-37001`, srsRAN `src/asn1/asn1_utils.cc` —
`unpack_constrained_whole_number`. The unaligned branch checks:

```cpp
  if (not aligned) {
    HANDLE_CODE(bref.unpack(n, n_bits));
    n += lb;
    if (n > ub) {
      // ^ This check ensures that the number cannot exceed bound constraints...
      log_error(...);
      return SRSASN_ERROR_DECODE_FAIL;
    }
  } else {
    // ALIGNED variant
    if (ra < 256) {
      HANDLE_CODE(bref.unpack(n, n_bits));
      // ^ ...but packed rules fail to check to ensure n <= ub.
    }
```

with the comment that the check "should be moved here to account for both unaligned and aligned
bounds checks". The consequence chain the page gives: a length can come back above its upper
bound, up to the next power of two → `unpack_dyn_seq_of` fills a fixed-size buffer from it → the
overflow overwrites the sequence's **own length field** → arbitrary-length overflow. Observed via
S1AP `SupportedTAs`:

```cpp
for (uint32_t j = 0; j < tas.broadcast_plmns.size(); j++) {
  // ^ tas.broadcast_plmns.size() exceeds bounds due to bad bounds check
  ((uint8_t*)&enb_ctx->bplmns[i][j])[1] = tas.broadcast_plmns[j][0];
  // ^ out-of-bounds read/write on array due to oversized plmns list
```

The page states this is reachable on **any interface with dynamic sequence structs whose bounds
are not an exact power of two**, and names **E1AP, E2AP and F1AP** as likely reachable too — i.e.
the srsRAN finding is not confined to S1AP.

### 5.4 Trust in a decode that failed

`VULN-B07` / `CVE-2024-24442`: `asn_decode()`'s return value is never checked, so a failed decode
leaves the PDU zeroed and the very next logging statement dereferences it.

`VULN-B01` / `CVE-2024-24445`: a message whose `procedureCode`/`present` pair is unsupported
indexes a null entry in the callback table and calls it:

```cpp
(*messages_callback[ngap_msg_pdu->choice.initiatingMessage->procedureCode]
                   [ngap_msg_pdu->present - 1])(
    assoc_id, stream, ngap_msg_pdu);
// ^ function pointer dereference of potentially null value
```

The `FD_SET` case (`VULN-B05`) is the same family in the socket layer: `fd_set` is a fixed 1024-bit
structure, `clientsock` is attacker-influenced by opening connections, and `FD_SET(clientsock,
&master)` overflows it past descriptor 1024.

---

## 6. Reachability

| Interface / layer | Findings | Reach |
|---|---|---|
| NAS / N1 | A01, A02, A04, C01, D01, D09, D16–D24, E08, E09, F24–F27, H08, H09, I08 | Start of a connection; no SIM; **internet-reachable via Wi-Fi Calling**; otherwise radio-limited |
| NGAP over N2 / SCTP | A03, A05, B01–B04, B06–B11, C02–C20 | CVE text names "a remote attacker **with access to the N2 interface**"; otherwise base-station/IPsec model |
| S1AP over S1-MME / SCTP | D02–D15, D25, E01–E07, F01–F23, G01, H01–H07, I01–I07 | Base-station access; several message classes double as the unauthenticated initial-UE entry point |
| GTP-U / PFCP | J01, J02, F28, F29 | F28/F29 need "an attacker that has established a **PFCP session**" — a stateful, more privileged position |
| SCTP socket layer | B05, B06 | Repeated connection establishment against the AMF's SCTP endpoint |
| ASN.1 generated code / memory pools | E01–E07, F07, G01, H02, H07 | Reachable through whatever protocol carries the type; G01 also via E1AP/E2AP/F1AP |

**The Wi-Fi Calling claim is the load-bearing one.** It converts a radio-proximity attack into an
internet one. Nothing in the page's own per-entry text substantiates it beyond the assertion —
the mechanism is that Wi-Fi Calling terminates NAS signalling over an IP path reachable from the
public internet, and the page defers the analysis to the paper. Treat it as the authors' claim
requiring the paper, not as a finding demonstrated on the page.

Two smaller reach caveats the page states honestly: `VULN-H07` and `VULN-I08` come with bare
base64 crash samples rather than code, because SD-Core's ASN.1 routines ship as a precompiled
static library and Athonet's source is unavailable; and `VULN-I08` is presented with a
counterexample that modifies only the NAS field and does *not* crash, which is good evidence the
crash is field-specific rather than generic malformed-input intolerance.

---

## 7. Disclosure and fixes

Each maintainer was given at least 90 days. **NextEPC and SD-Core did not respond**; the authors
disclosed and supplied patches directly on the repositories instead.

| Implementation | Affected | Fixed |
|---|---|---|
| OpenAirInterface 5G AMF | `oai-cn5g-amf` ≤ 2.0.0 | — |
| Open5GS | ≤ 2.6.4 | — |
| Magma (5G and shared LTE) | ≤ 1.8.0 | v1.9, commit `08472ba98b8321f802e95f5622fa90fec2dea486` |
| NextEPC | ≤ 1.0.1 | commit `a8492c9c5bc0a66c6999cb5a263545b32a4109df` |
| SD-Core / Nucleus | ≤ 1.4.0 | Nucleus commit `8c0455035837ad97d5a55bd214d7ab7d35aebdf8` |
| Athonet vEPC MME | ≤ v11.4.0 | — (closed source) |
| srsRAN Project | ≤ 23.5 | 23.10 |

Patch availability is the practical bottom line: **five of the seven LTE cores have a named fixed
version or commit in this page.** An operator running Open5GS ≤ 2.6.4, an unstated OAI AMF build,
or Athonet ≤ v11.4.0 has no fix named here.

---

## 8. What the page does not contain

- **No methodology.** There is no fuzzing, grammar-generation, or "how we found them" section. The
  page says only "to learn more about how we were able to discover these vulnerabilities, take a
  look at our paper". Everything method-shaped here is inferred from the root-cause write-ups:
  crafted single messages against hand-audited decoders, with one bounds-check class that looks
  like differential testing of an ASN.1 runtime.
- **No SGsAP, Diameter, SIP or HTTP-2 findings.** Every entry is NAS, S1AP, NGAP, GTP/PFCP, or an
  ASN.1 / memory-pool implementation detail. That is a real limit on the "core network" framing —
  the 5G service-based interfaces (HTTP/2, SBI) are not covered at all.
- **No exploitation analysis for the overflows**, beyond the one SD-Core PoC and the general
  caution quoted in §4.
- **No per-entry severity or CVSS.** The CVE records themselves are the only severity source.

---

## 9. Summary

The corpus is real in the sense that the identifiers are consistent, the CVE numbers are mostly
contiguous and check out as a block, the fixes are named, and the code snippets are specific
enough to be worth reading. Its shape is more useful than its headline number:

- **119 labelled findings, 92 CVE identifiers**, and — by the page's own descriptions — far fewer
  distinct root causes. 19 of the IDs are one macro asserting in 19 places; 23 more are one
  "missing IE → failed error response" pattern repeated across S1AP handlers.
- **Crash-class bugs dominate** (38 of 119 are assertions or null derefs). The 27 overflows are a
  minority, and their exploitability is explicitly qualified.
- **Two lineages carry half the corpus**: Open5GS (34) and the shared Magma/OAI LTE code (25).
- **Four root causes explain most of it**: unchecked wire lengths into fixed buffers; `asn1c`
  member-array/rows-table count mismatches; a bounds check present in one decoder branch but not
  the other; and trusting a failed decode.
- **The one claim that changes the threat model is the Wi-Fi Calling reachability argument**, and
  it is the least substantiated thing on the page.

---

## Appendix: sources read

- <https://cellularsecurity.org/ransacked.html> — captured to `/tmp/ransacked.html` (316,487 bytes),
  stripped to `/tmp/ransacked.txt` (2,915 lines, ~92 KB).
- <https://nathanielbennett.com/publications/ransacked.pdf> — the accompanying paper; **not
  fetched or read**, so none of the methodology claims in it are reflected here.
