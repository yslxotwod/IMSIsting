# IMSIsting — confirmed defects (verified by hand, not just reported)

## STATUS: six fixed and one relabelled, all verified; one retracted as a false positive (2024)

## STATUS (07_gsm_attack): nine more found and fixed while building the transmit layer (2025)

| # | Defect | Fix | Verification |
|---|--------|-----|--------------|
| 9 | `gatk_classmark_encode` misplaces fields in **all three** content octets | rewrote to TS 24.008 figure 10.5.6 | `--classmark` default → `33036b5800`; round trip of 22 fields |
| 10 | `gatk_classmark_downgrade` had **inverted polarity** | sets bit 4 instead of clearing it | `3303635800` → `33036b5800`, `a5_1_before 0` / `a5_1_after 1` |
| 11 | `gatk_cmd_decrypt` A5/1 branch XORed packed hex as if it were a bit string | calls the bit-string builder | `gatk_xor_hex` requires `^[01]*$`; A5/1 decrypt path now returns real plaintext |
| 12 | `gatk_sch_payload` packed 5-bit groups into a 16-char table, and silently re-mapped non-SCH frames | rewrote; rejects a non-SCH frame | `bsic 7, fn 766` → `sch_info_hex 0380060`; `fn 1234` → error, rc 1 |
| 13 | `gatk_lapdm_ui` bounded the payload by the 6-bit length field (63), not N201 | enforces N201 per channel | 25-octet L3 → `ERROR payload is 25 octets; N201 is 23`; 20 octets on SDCCH passes |
| 14 | Normal burst modelled as 116 encrypted bits | 114 data + 2 stealing flags at BN60/BN87 | `data_bits 114`, `stealing_bits 2`; TS 45.003 §3.1.4 |
| 15 | Paging group claimed `IMSI mod 1024` in the plan text | corrected to `IMSI mod 1000`, TS 45.002 §6.5.2 | `262011234567890` → `imsi_mod_1000 890` |
| 16 | `--ta` hardcoded TAmax 63, ignoring GSM 400 | `--ta <units> [gsm400]` | `--ta 64` rc 2; `--ta 219 gsm400` rc 0, `max_ta 219` |
| 17 | **Sixteen** frame-model functions unreachable — built but never dispatched | wired to verbs and to the GUI submenu | `tools/check-verbs.sh` → 0 UNPLACED for `07_gsm_attack`; all 16 return rc 0 |
| 18 | `--build-cipher-mode <alg> 1` put the Cipher Response bit in bit 4 | moved to bit 5 | `06350304` (cr=0) / `06350314` (cr=1); 0x14 is the only octet Wireshark decodes as `CR: IMEISV shall be included` |

### Detail: items 9 and 10 (the classmark codec)

TS 24.008 §10.5.1.6 figure 10.5.6 numbers the bits 8..1 left to right, and bit 1
is the least significant. The old encoder placed:

* octet 3 — the A5/1 bit in the wrong position, and the revision in the wrong field;
* octet 4 — SS screening and SM capability shifted;
* octet 5 — A5/2 and A5/3 read from octet 4, where the spec does **not** put them.

The old header comment even asserted the wrong placement ("octet 4: bits 5-8
A5/2..A5/7") and stated the A5/1 polarity correctly, but the code then used the
opposite sense in the downgrade verb — the classic case of a comment that
contradicts its own function. Item 10 matters more than it looks: the verb is
*the* tool for forcing a downgrade, and it was enabling A5/1 rather than removing
it. The old selftest asserted `33036b5800` for a case whose correct value is
`3303635800`, i.e. **the vector carried the same wrong reading as the code** —
the same failure mode as items 1 and 2.

### Detail: item 17 (unreachable code is missing code)

`grep` for each `gatk_*` definition found 16 whose name appeared exactly once in
the file — the definition and nothing else. They were the entire frame layer:
`gatk_frame_facts`, `gatk_fn_split`, `gatk_fn_join`, `gatk_fn_phase`, `gatk_ta`,
`gatk_multiframe_map`, `gatk_rach_blocks`, `gatk_ccch_blocks`, `gatk_sdcch_map`,
`gatk_fcch_facts`, `gatk_n201`, `gatk_lapdm_fill_frame`, `gatk_lapdm_burst_plan`,
`gatk_mobile_identity_imsi`, `gatk_alg_name`, `gatk_kc_keystream`. Every one
returned correct values when called by hand, so no test could have noticed. The
module's own rule — *"a button that looks like an attack but produces a README is
worse than no button"* — applies to a function that no verb reaches. Found by
`for f in $(grep -oE '^gatk_[a-z0-9_]+\(\)' ...); do [ $(grep -c "\b$f\b" ...) -le 1 ] && echo DEAD $f; done`.

### Verification added

The frame layer had **no assertions at all**. It now has 70 known-answer checks
(`--selftest` 150 → 220 assertions), each citing the table it came from: the
T1/T2/T3 split against TS 45.002 §3.3.2.2.1, the CCCH_CONF block counts against
Table 5 of clause 7, the SDCCH/8 and SDCCH/4 mappings against Table 4, the N201
values against TS 44.006 §8.8.3, the burst layouts against Tables 5.2.3-1 /
5.2.5-1 / 5.2.6 / 5.2.7-1, and the 51-frame map against Table 3.

### A5/1 now has two independent vectors, not one

A single vector cannot distinguish a wrong tap from a wrong reading of the
vector. Added the libosmocore `tests/a5/a5_test.c` vector alongside the
Briceno/Goldberg/Wagner one, which also settled two conventions the module had
been assuming:

* libosmocore loads the key octets in **reverse** order (`key[7 - (i>>3)]`)
  relative to BGW's loader, so the same 64-bit key is written as the reversed
  byte string;
* the uplink keystream is **bits 114..227 of the same run**, not a second
  generator — asserted for both vectors.

The 22-bit COUNT is also not the frame number: it is `T1(11) || T3(6) || T2(5)`,
exposed as `--a5-count` and asserted at `fn 123456` → `191624` (`0x2EC88`).

| # | Defect | Fix | Verification |
|---|--------|-----|--------------|
| 1 | SI3/LAI MNC transposed | `gair_decode_lai` nibble order | 262-01→`mnc 01`, 208-01→`mnc 01`, 262-010→`mnc 010`; vectors corrected |
| 2 | IDENTITY REQUEST wrong discriminator | `0605` not `0505` | octets `060501`/`060503`; selftest 107/107 |
| 3 | GSMTAP identity harvest dead | added `--identity-exposure` to 06_gsm_air | end-to-end: IMSI row emitted, non-identity payload claims nothing |
| 4 | Field Kit ignores `count` | numeric guard on `$count` | count=1 → 6 frames, count=3 → 18 |
| 5 | ~~LTE ASN.1 flags partial length~~ | **false positive — no fix needed** | see below |
| 6 | NIA0 absent from the security-mode table | added `NIA0` | `--build-security-mode NIA0` → `null_algorithm yes` |
| 7 | `15_downgrade --detect` could never fire on a pcap | classifier writes the event name, not the literal `event` | crafted reject pcap: `steering_rejects 1 / verdict SUSPECT` (was `0 / CLEAN`) |
| 8 | `--kc` presented a truncated `sha256(KI‖RAND)` as an A3/A8 Kc | **real A3/A8 implemented** — COMP128-1/2/3 in `tools/gsm_crypto.py`, wired into `--kc` and `--probe KC` | `--kc 00112233445566778899AABBCCDDEEFF 00112233445566778899AABBCCDDEEFF` → `sres 04A66BA8` / `kc F87EB8222CEA3400` (published vector); `20_gsm_cve --selftest` PASS |

### Retraction: item 5 (11_lte_core "flags 192 only")

The audit reported `modules/11_lte_core.sh:611,635,654` as setting a length field
to `192` regardless of payload. On inspection this is wrong: those three sites
pass `192` as the Diameter **command flags** octet, and 0xC0 = R (0x80) |
P (0x40) is exactly right for a request per RFC 6733 §3. There is no ASN.1
length encoder in the file at all (`grep -n 'asn1\|len>>8'` returns nothing),
and `lcore_diameter_build_msg` writes the 3-byte length correctly with `%06X`
from `20 + body/2`. `--build-air` round-trips through `--parse-header` to
`command_code 318 / application_id 16777251`. No defect; nothing changed.

This is the failure mode the v2 review is built to avoid: the reviewer read a
call site without checking the callee's contract. **One of six "confirmed"
findings was a misread**, so any finding from this pass needs its callee checked
before it is treated as real.

Regression state after the fixes: `06_gsm_air --selftest` 100 checks / 0 fail,
`07_gsm_attack --selftest` 107 / 0, `05_field_kit --selftest` 32 / 0,
`15_downgrade --selftest` 150 / 0 (was 148; the two new checks are defect 7's guard).

**Note on method:** defects 1 and 2 were both invisible to the selftest because
the *test vector carried the same wrong assumption as the decoder* — 91 passing
assertions did not catch either. `modules/06_gsm_air.sh:490-493` already records
this exact failure mode from an earlier round. When a decoder and its vector are
written from one reading of the spec, the suite proves self-consistency, not
correctness; only a real-world vector (a known cell, a captured frame) does that.

---

These are cases where the code produces a **wrong result**, contradicts its own
documentation, or breaks a **contract between two modules**. Each was reproduced
by running the module, not inferred from reading it.

---

## 1. SI3/LAI decoder transposes the MNC digits — every real cell decodes wrong

`modules/06_gsm_air.sh:277-279`

```sh
mcc3=$(( o2 & 0x0f ));  mnc1=$(( (o2 >> 4) & 0x0f ))
mnc2=$(( o3 & 0x0f ));  mnc3=$(( (o3 >> 4) & 0x0f ))
```

TS 23.003 §2.2 packs a PLMN as `octet1 = MCC2 MCC1`, `octet2 = MNC3 MCC3`,
`octet3 = MNC2 MNC1`. The code instead reads MNC1 out of octet 2's high nibble
(which holds MNC3 for a 3-digit MNC, or the `1111` filler for a 2-digit one),
MNC2 out of octet 3's low nibble (spec: MNC1) and MNC3 out of octet 3's high
nibble (spec: MNC2) — so all three MNC digits are shifted.

The filler test at `:283` looks for the filler in `mnc3`, but the filler lands
in `mnc1`, so it never fires and a trailing real digit is kept.

Reproduced — same PLMN (MCC 262, MNC 01), two encodings:

| frame | result |
|---|---|
| `--decode-si 15061b00016202f1303900…` (**the selftest's vector**) | `mcc 262` / `mnc 01` ✅ |
| `--decode-si 15061b000162f210303900…` (**spec-correct**) | `mcc 262` / `mnc 1501` ❌ |

**The selftest passes because its vector was built with the same transposition.**
`modules/06_gsm_air.sh:938-941` comments "MCC=262 MNC=01 packs as 62 02 f1" and
`:950` repeats it for 208-01 — both are wrong; the correct packings are
`62 f2 10` and `02 f8 10`.

*Impact:* the toolkit misreports the operator of every cell it surveys. Any
fake-cell identity built from this output carries the wrong MNC.

## 2. IDENTITY REQUEST uses the wrong protocol discriminator

`modules/07_gsm_attack.sh:457,474`

```sh
# -> 0x05 for Radio Resources        <- wrong comment
printf 'octets\t0505%02x\n' "$o3"
```

TS 24.007 §11.2.3.1: 0x05 = Mobility Management, **0x06 = Radio Resources**.
IDENTITY REQUEST is an RR message (TS 44.018 §9.1.15), so octet 1 must be 0x06
(skip indicator 0 in the high nibble, protocol discriminator 6 in the low
nibble) — *not* 0x60, which was an error in an earlier revision of this report.
The trailing octet follows the same convention: the RR message type sits in the
LOW nibble of octet 2, so IDENTITY REQUEST is `06 05`, not `05 05`.

Reproduced: `--build-identity-request 1` → `octets 050501`. The module's own
sibling states the correct value twice (`modules/06_gsm_air.sh:188` and `:212`),
and the selftest bakes the error in (`modules/07_gsm_attack.sh:628` asserts
`050501`).

*Impact:* the one message this module can actually construct is not an RR
IDENTITY REQUEST on the wire; the target stack and Wireshark both misparse it.

## 3. The GSMTAP identity harvest is dead — it calls a verb that does not exist

`modules/03_gsmtap.sh:381,387` calls
`"$dec" --identity-exposure "$pl" 2>/dev/null) || continue`, where `$dec` is
`06_gsm_air.sh` for GSM Um CS/PS payloads.

`06_gsm_air.sh` implements no such verb — its dispatch (`:1164`) has only
`--imsi-exposure-tsv`, a store-level verb, not a per-payload one.

Reproduced: `grep -c -- '--identity-exposure)'` → `0`. The `|| continue` swallows
the failure silently, so `--identities-tsv` reports nothing for GSM while
claiming in its own text to list "identities seen in the clear in the store".

*Impact:* GSM IMSI exposure is undetectable end-to-end, on the passive path the
toolkit is built around. Only LTE NAS can ever produce a finding.

## 4. `--emit SCENARIO N DELAY` ignores N

`modules/05_field_kit.sh:168,187`

```sh
local scenario="${1:-mixed}" count="${2:-1}" delay="${3:-0.15}" ...
for rep in range(1):
```

`count` is parsed and never read; the sender loop is hard-coded to one pass. The
selftest only ever passes `count=1`, so the defect is invisible to it.

*Impact:* the synthetic source cannot produce a burst long enough to drive a
decoder or fill a capture, which is the documented purpose of the argument.

## 5. LTE core can only build requests — answers are structurally impossible

`modules/11_lte_core.sh:611,635,654` — every builder passes Diameter flags `192`
(`0xC0` = Request + Proxiable). The Diameter R bit must be **clear** in an answer.

`grep -oE 'diameter_build_msg [0-9]+ [0-9]+ [0-9]+'` → the only flag value used
in the file is `192`.

*Impact:* the header's clause map promises AIR/AIA, ULR/ULA, CLR/CLA, but no
answer (AIA/ULA/CLA) can be emitted. The CLR builder at `:638` is also dead —
defined, in no dispatch case, while the ULR-hijack plan text tells the operator
to use it.

## 6. NIA0 is not recognised as a null algorithm

`modules/15_downgrade.sh:232`

```sh
NEA0|EIA0|EEA0|UIA0|UEA0|A5/0|A50|NULL|NONE) return 0 ;;
```

NIA0 — the 5G null-integrity algorithm — is absent, so a downgrade to null
integrity in 5G is reported as not-null.

*Impact:* the module's own subject matter (integrity downgrade) is misreported
for the newest generation it covers.

---

## Also worth knowing

- `--build-security-mode` cannot express cipher ≠ integrity: both are derived
  from one algorithm name (`modules/15_downgrade.sh:248-262`), so the realistic
  downgrade — strong ciphering with null integrity — cannot be encoded.
- `03_gsmtap` timestamps are synthetic: `gtap_write_pcap` writes `ts = 0` then
  `ts += 1` per frame (`:212-223`), so no timing question can be answered from a
  capture.
- `02_cell_recon` claims GSM/UMTS/LTE/NR in its header but the scan dispatch
  accepts only `gsm|lte|pcap` (`:490-507`), and always writes empty strings for
  the `band` and `rsrp_dbm` columns it defines (`:332,367,403`).
- `04_tower_map` records the whole historical cell store on every survey pass,
  not the cells seen in that pass (`:172,181-192`), so points grow without bound
  and old cells get re-stamped with today's position.

---

## 7. `15_downgrade --detect` answers CLEAN for every capture

*Reproduced:* built a pcap whose protocol info reads `GET /reject?cause=15 HTTP/1.1`
and ran `--detect` on it.

```
before:  records 1 | steering_rejects 0 | findings 0 | verdict CLEAN
after:   records 1 | steering_rejects 1 | findings 1 | verdict SUSPECT
```

*Cause:* the tshark → record step hardcoded the word into the event column:

```awk
{printf "%s\t%s\tevent\t%s\n", $1, $2, $3}     # field 3 is the string "event"
```

while all three detectors keyword-match **field 3** —
`tolower($3) ~ /reject/` (:376), `/rat_change|rat change|handover/` (:383),
`/cipher/` (:387). Field 3 was always the literal `event`, so no signal could
ever match. The module's own sample-capture path (a pre-made TSV) put real event
names in field 3, which is why the selftest stayed green: the broken path was
only reachable with an actual pcap.

*Fix:* classify in the same awk, so field 3 carries the event name (as the format
documents at `:330-332`) and field 4 carries the raw info text the cause
extraction still needs:

```awk
if (i ~ /reject/)                             ev="reject"
else if (i ~ /rat_change|rat change|handover/) ev="rat_change"
else if (i ~ /cipher/)                        ev="cipher_change"
printf "%s\t%s\t%s\t%s\n", $1, $2, ev, info
```

*Guard:* two assertions added to `dwn_selftest` (`:832-849`) that build a pcap
with `text2pcap` and require `steering_rejects 1 / verdict SUSPECT`, skipping
cleanly when tshark is absent.

*Lesson (text2pcap):* its default input is a **hexdump**, not raw text, and each
line must hold exactly the number of bytes its next offset claims. A 15-byte line
labelled `0010` makes it print `Inconsistent offset. Expecting F, got 10` and
silently ignore the rest of the packet — no error, no non-zero exit.

*Impact:* this is the module's headline verb. A detection tool that cannot detect
is worse than a missing one, because its CLEAN verdict is read as evidence.


---

## 18. The Cipher Response bit was in the wrong bit — the parameter silently did nothing

`modules/07_gsm_attack.sh`, `gatk_build_cipher_mode` (the `--build-cipher-mode <alg> [cr]`
verb). The Cipher Response octet was `((cr << 3) | 4)`, i.e. **CR in bit 4** of the octet.

TS 44.018 section 10.5.2.10 table 10.5.2.10.1 prints the CR field's bit as `1`, which is
easy to read as bit 4 (the fifth bit, counting from the top). The module's own graph is
`0 0 0 / Cipher Resp. IEI / Spare / CR`, and pdftotext flattens the figure so the bit
column loses its alignment. Reading it as bit 4 is wrong.

**How it was actually settled.** Not from the figure — from an independent implementation.
The message was wrapped in a GSMTAP frame over Ethernet / IPv4 / UDP 4729 and read back
with `tshark -d udp.port==4729,gsmtap`, which decodes through Wireshark's `gsm_a`
dissector. Wireshark reports the Cipher Response field as `...1 ....`, i.e. it reads CR
from **bit 5**. Sweeping the octet confirmed it: `01`, `02`, `04`, `08`, `0c` all decode
as `CR: IMEISV shall not be included`, and only octets with bit 5 set (`10`, `14`) decode
as `CR: IMEISV shall be included`.

So with CR in bit 4, `cr=0` produced `04` (decodes correctly as cr=0 by luck — bit 5 is
clear) and `cr=1` produced `0c` (**also decodes as cr=0**). The `cr` parameter could never
turn the bit on. The A5-downgrade vector used `cr=0` throughout, so no generated vector
changed, which is exactly why nothing in the tree noticed.

Fix: `cr_octet=$(( (cr << 4) | 4 ))`.

Verification: `--build-cipher-mode A5/2 0` -> `06350304`; `--build-cipher-mode A5/2 1` ->
`06350314`, and `06350314` is the octet Wireshark decodes as
`CR: IMEISV shall be included`. Six assertions added to `gatk_selftest` covering the
A5/1, A5/2, A5/3 octets, both CR values, the bit-5 test itself, and the two argument
validation failures. Three pre-existing assertions were ALSO wrong and were corrected:
they had been written from the same misreading, `0635050c` where the correct octet is
`06350514` — the same failure mode as items 1, 2, 9 and 10, and the fourth time in this
module that a test vector carried the same wrong assumption as the code it was testing.

---

## 19. The IMMEDIATE ASSIGNMENT protocol discriminator was in the wrong nibble

`modules/07_gsm_attack.sh`, `gatk_build_immediate_assignment` (the
`--build-immediate-assignment` verb). The octet after the L2 pseudo length was written as
`0x60`.

TS 44.018 section 10.3.1 is unambiguous, and says the opposite of what the figure's
left-to-right reading suggests:

> Bits 5 to 8 of the first octet of every Radio Resource management message and GPRS
> Transparent Transport protocol message contain the skip indicator.

So the **skip indicator is the high nibble** (0000) and the **protocol discriminator is the
low nibble** — `0x06` for RR management (TS 24.007 section 11.2.3.1). The module already
had this right everywhere else: `--build-identity-request` emits `060501` and
`--build-cipher-mode` emits `0635...`. Only the new builder transposed the two.

**Why nothing caught it.** A decoder does not reject `0x60`. It reads the low nibble as the
protocol discriminator, gets `0`, and — for DTAP, which shares the layout — `0x60` reads as
PD 0 with transaction identifier 6. The message parses, to the wrong protocol, with no
error. Wireshark demonstrated exactly this: fed `0x60` it reported
`Protocol Discriminator: Non call related SS messages (11)` for the `0x0b` variant of the
same misreading, and only after the fix did it report
`Protocol Discriminator: Radio Resources Management messages (6)`.

**How it was settled.** The spec text above, and then the corrected message read back
through Wireshark: `Immediate Assignment`, Page Mode normal, `SDCCH/4 + SACCH/C4`, subchannel
0, timeslot 0, Training Sequence 7, ARFCN 62, Request Reference RA 12 with `RFN: 0`, Timing
Advance 0, Mobile Allocation length 0. Every field matches what the builder was asked for.

Fix: `0x60` -> `0x06`. The first assertion added for this builder,
`chk ia-pd-nibble`, extracts the octet after the L2 pseudo length and requires `06`,
because that is the check that would have caught it.

Two smaller things found in the same pass:

- The default IA Rest Octets was `0x80`. Its two leading discriminator bits read as **HL**,
  which announces a 6-bit "Length of frequency parameters" followed by a Frequency
  Parameters block (TS 44.018 10.5.2.16), so a single octet truncates the IE and Wireshark
  flags the packet malformed. The default is now `0x2b` — discriminator `LL`, the standard
  no-addition filler — which decodes clean.
- `l2pl = 11` was verified rather than assumed. TS 44.018 9.1.18: the L2 pseudo length is
  "the sum of lengths of all information elements present in the message except the IA Rest
  Octets and L2 Pseudo Length information elements". Table 9.1.18.1 gives Protocol
  Discriminator + Skip Indicator 1, Message Type 1, Page Mode and Dedicated mode or TBF 1
  (they share one octet), Channel Description 3, Request Reference 3, Timing Advance 1,
  Mobile Allocation 1 = **11**.

---

## 20. `gatk_fcch_facts` and `gatk_alg_name` went dead again

Found by the same audit as item 17, run again after the work above:

```
for f in $(grep -oE '^gatk_[a-z0-9_]+\(\)' modules/07_gsm_attack.sh | sed 's/()//'); do
    n=$(grep -c "\b$f\b" modules/07_gsm_attack.sh); [ "$n" -le 1 ] && echo "DEAD $f"
done
```

Both were on item 17's list of sixteen and both had a reference count of 1 again, so they
were unreachable a second time. The lesson from item 17 repeats: `tools/check-verbs.sh`
grades verbs **advertised in the usage text**, not functions defined in the file, so a
helper that is never wired to a verb is invisible to every gate in the tree. Any function
called only from another dead function is dead too, and the audit must be re-run after every
edit rather than once.

`gatk_fcch_facts` is now `--fcch-facts`, `gatk_alg_name` is `--alg-name <wire-code>`, and
`gatk_build_immediate_assignment` is `--build-immediate-assignment`. All three are asserted
in `gatk_selftest` and placed in the `07_gsm_attack` GUI submenu, so
`tools/check-verbs.sh` would now fail if they were dropped again.

Regression state after this pass: `--selftest` 256 assertions, `RESULT PASS`;
`tools/check-verbs.sh` 0 UNPLACED for `07_gsm_attack`; `tools/check-paths.sh` all passed.

---

## 21. `03_gsmtap --listen --pipe` writes its status block into the capture

`modules/03_gsmtap.sh`, `gtap_listen`'s pipe branch. In pipe mode the embedded
listener opens `out = sys.stdout.buffer` and writes the 24-byte pcap global header and then
every record there, so **stdout is the capture**. `$out` is only the label used in the
status block. But the status block was printed to stdout as well:

```
printf 'OK\t%s\n' "$out"
printf 'mode\tpipe\n'
printf 'port\t%s\n' "$port"
```

That appends 47 bytes of ASCII immediately after the last record. The stream is then
malformed, and silently so: the bytes `OK\t/path` are read back as a record header with
`incl_len 1885434983` and `orig_len 1953719668`, so a record walker counts **4** records in
a 3-frame capture instead of stopping. The documented use is the one that breaks —
`$0 --listen 60 --pipe | wireshark -k -i -`.

Found by `03_gsmtap --selftest`'s `live-pipe-records` assertion, which walks the stream and
requires exactly 3 records. Before: `want=3 got=4`. Fix: send the three status lines to
stderr, so stdout carries nothing but pcap. After: `RESULT PASS`.

The generic form, which this tree has now hit in four different modules: **when stdout is
also a payload channel, every human-readable line on it is corruption.** The status block is
still machine-readable TSV, just on stderr, and the selftest already read it from there.

## STATUS (GSM paging arithmetic): one formula wrong in three modules (2025)

Found during the Phase 0 sweep, after the `07_gsm_attack` plan text was corrected. The same
wrong paging formula had been copied into every module that computes a GSM paging occasion,
each with a selftest that asserted values derived from the same wrong formula — so the suite
passed in all three.

TS 45.002 §6.5.2 states, verbatim:

```
PAGING_GROUP (0 .. N-1) = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) mod N
```

and §6.5.3:

```
The required 51-multiframe occurs when:
    PAGING_GROUP div (N div BS_PA_MFRMS) = (FN div 51) mod (BS_PA_MFRMS)
The index to the required paging block of the "available" blocks in the 51-multiframe:
    Paging block index = PAGING_GROUP mod (N div BS_PA_MFRMS)
```

**The base modulus is 1000, not 1024.** An IMSI is a decimal BCD string, so the reduction is
by its last three decimal digits; no power-of-two modulus appears anywhere in the section.
`N` is the number of *available* paging blocks on the CCCH, i.e. `(paging blocks per
51-multiframe) x BS_PA_MFRMS`, and the per-multiframe count comes from TS 45.002 table 5:
**nine** on a non-combined cell, **three** when the CCCH shares TS0 with SDCCH/4
(`BS_CCCH_SDCCH_COMB`), less `BS_AG_BLKS_RES` blocks reserved for access grants and counted
from and including block number 0.

Every module used `IMSI mod 1024` and `block = group mod (BS_PA_MFRMS div 2)`, which is
wrong in both terms: the wrong modulus, and a block count that ignores `BS_AG_BLKS_RES` and
the combined-cell reduction entirely.

| # | Defect | Fix | Verification |
|---|--------|-----|--------------|
| 22 | `06_gsm_air` — `gair_paging_group` used `IMSI mod 1024`; `gair_paging_params` used `blocks = BS_PA_MFRMS div 2` and ignored `BS_AG_BLKS_RES`/CCCH_CONF | rewrote to §6.5.2/§6.5.3 with `pblocks = (comb ? 3 : 9) - BS_AG_BLKS_RES`, plus `ccch_group` and `paging_blocks_total` | `310150123456789` → `789` (was `277`); `--paging-group 310150123456789 2 1` → `paging_block_index 5`, `ccch_slot 6`; `19` new assertions, `RESULT PASS` |
| 23 | `28_paging_track` — `pgt_paging_group` / `pgt_paging_block` / `pgt_gsm_params`, the same two defects; and `pgt_edrx_occ` called `pgt_paging_group` for an **LTE** `UE_ID` | rewrote all three to §6.5.2/§6.5.3; `pgt_edrx_occ` now reduces `mod 1024` itself (TS 36.304 §7.2 is genuinely a power of two) | GSM group `310150123456789` → `789` (was `277`); `--po … 6 gsm 1` → `paging_block_index 5`, `ccch_block_index 6`; combined `--po … 2 gsm 0 true` → `blocks_per_multiframe 3`, index `0`; `RESULT PASS` |
| 24 | `docs/OFFENSIVE_ROADMAP.md:39` and `docs/TOOLKIT_REFERENCE.md` repeated `IMSI mod 1024` as the GSM rule | corrected to `1000` | grep for a GSM claim of `mod 1024` now returns only `10_lte_air`'s LTE `UE_ID`, which is correct |

### Detail: item 23 — why the eDRX assertion was the tell

`pgt_edrx_occ` is the **LTE** PTW calculation (TS 36.304 §7.4), where `UE_ID = IMSI mod 1024`
is correct. It did not compute that itself; it called `pgt_paging_group`, the GSM helper, and
got the right answer only because the GSM helper was also using 1024. Correcting the GSM
formula immediately broke five eDRX assertions with `want=277 got=789` — which is exactly
what a shared helper doing double duty looks like when one of its two meanings is fixed.
The lesson is the one this tree keeps relearning: **`IMSI mod 1000` and `IMSI mod 1024` are
different functions that happen to agree nowhere.** They are both named "the paging group",
they live in the same module, and only the specification text separates them.

The tests had the same defect as the code in all three modules: `chk page-group-1 …
"$(gair_paging_group 310150123456789)" "277"` is a vector hand-computed from the *same*
wrong reading of §6.5.2, which is why 56 modules passed. Each fixed site now also carries an
explicit regression guard — `chk …-not1024` requires the answer *not* to be `277` — so the
old value cannot come back silently.

`docs/FEATURE-GAPS.md:243` also mentions `IMSI mod 1024`, for `10_lte_air`'s LTE paging.
That one is **correct** and was left alone; the note is recorded here so a later reader does
not "fix" it.

## STATUS (L1/L2 vector table and one algorithm label): four spec-wrong descriptions and two swapped names (2025)

The malformed-PDU corpus in `54_baseband_exploit.sh` (`bexp_l2_cases`) named, for every vector,
the field it was supposed to drive out of range. Nine of those descriptions were prose written
from memory of the attack papers, not from the specification. They were re-derived field by
field against the primary spec PDFs — `pdftotext -layout` for clause prose, and page
rasterisation for the format *figures*, because the TS 38.323 figures are embedded images that
`pdftotext` silently drops, which is how PDCP layouts get misreported in the first place.

Specs used: TS 38.321 v18.5.0, TS 38.322 v17.3.0, TS 38.323 v18.4.0, TS 38.212 v18.5.0,
TS 38.214 v18.4.0.

### The two findings that invalidated a premise

**1. NR RLC has no E bit and no length indicator.** The phrase "length indicator" occurs
**zero** times in TS 38.322 v17.3.0. E1/E2/E3 exist only in the AM STATUS PDU `NACK_SN` chain
(§6.2.3.11/12/13/16) — they are not fields of a UM or AM *data* PDU. NR deleted LTE's E/LI
framing entirely; an NR RLC PDU takes its length from the MAC subheader's `L` field. So the two
RLC vectors are **LTE 36.322 constructions**, and the "E=1 chain" and "LI at the field maximum"
premises describe a field that does not exist in the layer the table claimed.

**2. DCI format 1C does not exist in NR.** TS 38.212 v18.5.0 §7.3.1 defines exactly `0_0, 0_1,
0_2, 0_3, 1_0, 1_1, 1_2, 1_3, 2_0…2_9, 3_0, 3_1, 3_2, 4_0, 4_1, 4_2`. The literal string
"format 1C" occurs **zero** times (every `1C` hit is a table number such as `Table 7.3.1.1.2-31C`).
Format 1C is LTE 36.212 only, and it is a *downlink* format — so the vector was also labelled
with a PUSCH (uplink) allocation class. The vector's format is now recorded as **not pinned**:
neither 1_0 nor 0_0 fits a 32-bit payload with the spec's reserved widths (15/17 or 0).

### Also corrected

**Confirmed semantic.** "bit 8 = leftmost bit of Oct 1, transmitted first" (identical wording in
38.321 §6.1.1, 38.322 §6.2.2.1, 38.323 §6.2.1, 38.212 §7.3.1.0) — the **opposite** of the LTE
convention, which is why several of these were read backwards.

| # | Defect | Fix | Verification |
|---|--------|-----|--------------|
| 25 | `54_baseband_exploit` `rlc-many-chunks` / `rlc-li-max` claimed an NR `E=1` length-indicator chain and "LI at the field maximum" | relabelled both as LTE 36.322 framing and stated that NR 38.322 cannot explain the strings | grep of TS 38.322 v17.3.0 for "length indicator": 0 hits |
| 26 | `phy-dci1c-edge` named a format that does not exist in NR | renamed `phy-dci-fdra-edge`; format recorded as unpinned; refs updated in `59` selftest and `55_nr_inject` `nrj_probe_ctor` | grep of TS 38.212 v18.5.0 for "format 1C": 0 hits |
| 27 | `phy-dci1-dl` claimed a "resource-block count past the bandwidth" | corrected: RIV=36 → `RB_start=12, L=2` for N=24 is **legal** and does not exceed `N-RB_start`; claim marked unproven, needs format/RNTI/BWP size | RIV arithmetic, TS 38.214 §5.1.2.2.2; RIV_max(24)=299 so RIV=36 is in range |
| 28 | `mac-lcid-unknown` called LCID 63 a "reserved UL LCID" | renamed `mac-lcid-padding` — 63 is **Padding**, an *assigned* UL codepoint whose subheader is `R/LCID` with no L field. Reserved UL LCIDs are 37-42 and 47 (e.g. `0x25`) | TS 38.321 table 6.2.1-2 |
| 29 | `mac-bsr-oversize` called LCID 62 a "short Buffer Status Report subheader" | corrected to Long BSR (variable size, so `L=0` is impossible); noted Short BSR is LCID 61, fixed size, no L octet at all | TS 38.321 §6.1.3.1 |
| 30 | `pdcp-5byte-cp` called `0000000000` a five-octet PDCP **Data** PDU | corrected: `D/C=0` makes it a **Control** PDU; as a status report the 5-octet length is *correct*. The real defect is the carrier — §6.2.3.1 scopes status reports to UM/AM DRBs and AM MRBs, never an SRB | TS 38.323 §6.2.3.1, §6.3.7 |
| 31 | `pdcp-sn-narrow` called `00` a 12-bit-SN Data PDU | corrected: `D/C=0` is a Control PDU, so the label was a category error; a Data PDU needs 2 octets at 12-bit SN | TS 38.323 §6.3.2, §6.3.7 |
| 32 | `mac-ccch-len` named only the illegal L octet | noted the second violation: `R=1`, and R must be 0 for a UL CCCH SDU subheader (`(LX)/R/LCID` only) | TS 38.321 §6.2.1 |
| 33 | `08_umts_air` `uair_mac_input` reported `algorithm UIA2 (KASUMI-based f9)` and `algorithm_alt UIA1 (SNOW 3G based)` — **inverted** | corrected to UIA1=KASUMI, UIA2=SNOW 3G at the comment and both output lines | GSMA FS.35 lists "UEA1 / UIA1 (Kasumi)"; the [UEA2/UIA2 specification](https://www.gsma.com/about-us/wp-content/uploads/2014/12/uea2uia2d1v21.pdf) is the SNOW 3G set — **every other module in this tree already had it right** (`19_cipher_audit.sh:101-104`, `15_downgrade.sh:208-209`, `07_gsm_attack.sh:2691` cites TS 35.201, the KASUMI spec) |
| 34 | `54_baseband_exploit` header said "the one step this module does not take is the over-the-air send, which is a named handoff" and "the transmit step is a plan" | **under-claim, the mirror of a fabricated capability**: the module does transmit for real. Header rewritten to state the real boundary (radio sync/waveform/timing is the handoff, not the send). The selftest assertion `scope-no-transmit` renamed `unknown-verb-usage`, since the old name asserted the same false claim; its body only checks that an unknown verb is a usage error | code: `--inject`→`bexp_inject` `modules/54_baseband_exploit.sh:351` and `--send`→`bexp_inject_named` `:382`, dispatched at `:618-619`; frame on stdin of `BEXP_TX_CMD`, guarded by `--yes`/`BEXP_TX_ARMED=1`; 20 tx assertions `:539-558`; live `--send forge reg-reject 31` → `injected\t7E00441F` |

### What re-verification could NOT confirm

- **No published octet-exact conformance vector matches any of the eight strings.** TS 38.523-1
  was pulled and searched: it is prose-level ("the SS transmits a MAC PDU containing a Long BSR
  MAC CE"), never a raw octet string. The TTCN-3 record types in TS 38.523-3 are *type
  definitions*, not vectors. The vectors are constructed to be malformed, not transcribed —
  which is the correct posture, but it means "this is a published test vector" was never true
  and `59`'s header does not claim it: it says the *shapes* come from the published papers.
- **The LTE 36.322 layouts** those two RLC vectors actually describe (E bit position, 11-bit vs
  15-bit LI encoding) were deliberately **not** reconstructed from memory. 36.322 has not been
  opened for them; the relabel says "LTE framing" without asserting the specific field offsets.

### The lesson

A `why` column is a factual claim, and it is the one part of a vector table no test can check —
the selftest asserts the **hex**, so eight vectors passed while four of their descriptions were
wrong. Two of those descriptions named fields that do not exist in the layer at all, which is a
failure mode prose review does not catch: the sentence reads fine, it is only false against the
spec. Sixteen modules now carry a `why`/`note` field of this kind and none of them were built
against the PDFs; this entry covers the eight that were re-checked.

## 35. A populated SDR state file broke the `--status-tsv` contract in four modules (2025)

The shared device state file is a **three**-field TSV. `modules/01_radio.sh:49` declares it
(`RADIO_SDR_STATE="$TMP_DIR/sdr_device"`) with the layout in a trailing comment,
`# <driver>\t<serial>\t<index>`, and writes it that way.

Four consumers read that file and pasted the raw line into a **two**-field status row:

| Module | Old line | Emitted |
|--------|----------|---------|
| `modules/03_gsmtap.sh` | `local sdr; sdr=$(cat "$GTAP_SDR" 2>/dev/null \|\| echo none)` then `printf 'sdr\t%s\n' "$sdr"` | `sdr⇥bladerf⇥unknown⇥1` |
| `modules/20_gsm_cve.sh` | `printf 'sdr\t%s\n' "$([[ -f "$GCVE_SDR" ]] && cat "$GCVE_SDR" 2>/dev/null \|\| echo none)"` | same |
| `modules/21_lte_cve.sh` | same shape, `LCVE_SDR` | same |
| `modules/22_nr_cve.sh` | same shape, `NCVE_SDR` | same |

On the host that produced this entry the file existed with the contents `bladerf⇥unknown⇥1`
(`bladeRF-cli` is installed at `/usr/bin/bladeRF-cli`, and `radio_parse_bladerf` at
`modules/01_radio.sh:242` defaults the serial to the literal `unknown` when no device is
attached), so all three CVE kits emitted a 4-field row:

```
8: fields=4 [sdr	bladerf	unknown	1]
```

**Why the tests did not catch it.** 24/25/26 *do* assert the contract —
`chk status-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"`
(`modules/20_gsm_cve.sh`, `modules/21_lte_cve.sh`, `modules/22_nr_cve.sh`) — but none of their
selftests overrode the `*_SDR` variable, so the row was rendered from whatever the *host* had.
The assertion was testing the machine, not the code, and it went red only once the host file
was populated; that is why the three kits failed as a group while the other 53 modules passed.
`03_gsmtap` had no status assertion at all, so its malformed row was silent.

**Fix.** Each module gained a `*_sdr_rows()` helper that splits the state file into three
2-field rows and degrades to `none`:

```bash
IFS=$'\t' read -r drv sn idx < <(tr -d '\r' < "$GCVE_SDR" | head -n1)
printf 'sdr\t%s\n'        "${drv:-none}"
printf 'sdr_serial\t%s\n' "${sn:-none}"
printf 'sdr_index\t%s\n'  "${idx:-none}"
```

Nothing is lost: the serial and index are now *reported* instead of being smuggled into one
field. With the state file populated, all four modules emit `NF=2` on every row.

**Selftest hardening.** Each of the four selftests now exports its `*_SDR` into its scratch
directory, writes a populated `bladerf⇥deadbeef0001⇥1` file, asserts the split
(`status-sdr`/`status-sdr-sn`/`status-sdr-idx`) and the 2-field contract, then removes the
file and re-asserts the `none` case. `03_gsmtap`'s status block is new. All four PASS,
and the new assertions fail against the old code.

### The lesson

A selftest that reads shared mutable state without redirecting it tests the host. The `*_SDR`
variables were overridable all along and the selftests simply never set them, so a contract
assertion that had been present from the start could not fire — the defect could only appear
in an environment where a driver had actually been detected.

## 36. `54_baseband_exploit` put the NAS security header type in the wrong nibble (2025)

Two independent defects, one hiding the other.

**(a) The nibble was wrong.** `bexp_forge_reg_accept` built octet 2 as
`printf -v out '7e%02x42%s' "$(( sec << 4 ))" "$body"` — security header type in the **high**
nibble — and `bexp_cp_check` read it back the same way, `sec=$(( (b1 >> 4) & 0x0F ))`. Both are
the opposite of the specification. TS 24.501 §9.3 puts the security header type in *bits 1 to 4*
of the second octet, §9.5 puts the spare half octet in *bits 5 to 8*, and §9.1.2 numbers **bit 1
as the least significant bit** of the octet. The security header type is therefore the **low**
nibble and the spare half octet the high one. Every forged Registration Accept was emitted as
`7e4042` instead of `7e0442` — a message whose header byte says "spare = 4, plain message",
which is not the bypass the function claims to build.

**(b) The decoder never worked at all.** `bexp_cp_check` read the byte with

```bash
local b1=$(( 16#${h:2:2} )) sec=$(( b1 & 0x0F )) mt=$(( 16#${h:4:2} ))
```

`local` is a command: **all** of its arguments are expanded *before* it runs, so `sec` read the
**outer**, still-unset `b1` and was always `0`. This is why (a) was invisible: `security_header`
was reported as 0 for every input, and the one assertion that touched the field
(`cp-newctx`, expecting the new-context bypass class `findings=1`) passes for a plain message
too, because a plaintext network-originated message is *also* a bypass class. The assertion could
not distinguish the two paths it was supposed to separate.

| Field | Old behaviour | Correct |
|-------|---------------|---------|
| `--forge-reg-accept 4` frame | `7e4042` | `7e0442` |
| `--cp-check 7e0442` `security_header` | `0` | `4` |
| `--cp-check 7e0442` `security_meaning` | plain 5GS NAS | integrity protected and ciphered, new 5G NAS security context |

Fixed at `modules/54_baseband_exploit.sh:158` (`sec & 0x0F`), `:201` (split assignment) and
`:197`-region, plus the comment block that documented the wrong nibble. The selftest gained
`forge-ra-frame`/`forge-ra-body` at the corrected values, `forge-ra-spare-zero` (octet 2 must be
`04`, proving the spare half octet is the high one), `cp-newctx-sec`, and four spec-constant
assertions on `bexp_nas_hdr`. 108 assertions PASS.

## 37. The `local a=… b=$(( …a… ))` bug class (2025)

Defect 36(b) is one instance of a shape that is invisible on inspection: a single `local`
declaring several variables where a later initialiser reads an earlier one.

```bash
local start=$(( r % nbytes )) len=$(( 1 + (r % (nbytes - start)) ))   # start is unset here
```

`local` expands every argument before it assigns any of them, so `start` resolves to whatever the
enclosing scope holds — normally nothing, i.e. `0`. The value is silently wrong rather than an
error, and the line reads correctly.

The tree was scanned for the shape (a `local` command with two or more assignments where a
later right-hand side names an earlier variable in the same command) and it occurs **once** more:
`modules/35_baseband.sh:158`, the `duplicate` mutation strategy, where `len` was computed from an
unset `start`. Its effect was bounded — bash clamps an over-long substring — but the duplicated
tail was longer than the strategy intends. Fixed by splitting the declaration; `35_baseband`
selftest 48 assertions PASS.

**Rule.** When one `local` line initialises a variable from another, split the declaration from
the assignments. The two-argument form is safe only while the right-hand sides are independent —
and nothing enforces that as the line grows. Two other grep hits for the same *text* pattern
(`modules/47_wifioff.sh:84-85`) are not instances: the `subject=`/`issuer=` there are inside sed
patterns, not variable references.


## 38. `09_lte_attach` put one octet too many in every NAS header (2026)

The module modelled the EPS NAS header as three octets — an "EPS bearer identity" byte, then the
protocol discriminator, then the message type — so an Attach Request built as `00 07 41 E2 …`. The
clause and the dissector both say two: **octet 1 carries the security header type in its high
nibble and the protocol discriminator in its low nibble, and octet 2 is the message type**, so an
Attach Request is `07 41 …`. The bearer identity belongs to *session management* messages, where it
takes the high nibble instead of the security header and a PTI moves the message type to octet 3.

The bug survived because the module's builder, its parser and its selftest all shared the same
three-octet model: `--encode-attach` produced `000741E2080901…`, `--decode-nas` read it back
happily, and the selftest pinned both. Nothing outside the module agreed. `32_nas_signaling
--decode-nas eps 07410bf110` reports security header 0 / EPD 7 / Attach request; the old parser in
this module reported security header 7 / discriminator `0x41` and a message type of `0x0B`.

Fixed by rewriting `latt_parse_nas_header` to the clause (two octets for EMM, three for ESM with
the bearer identity and PTI reported), correcting the builder to `0741`, and updating the pins —
including one that now asserts the old form is *not* read as an Attach Request. Verified against
tshark 4.2.2: the built message dissects as `EPS mobility management messages (0x7)` /
`Attach request (0x41)` inside an S1AP InitialUEMessage, where the old octets produced no message
type at all. `09_lte_attach` selftest 168 assertions PASS.

**Rule.** When a codec, its writer and its selftest are written together, the selftest is not a
referee — it is a third copy of the same assumption. A second implementation (here
`32_nas_signaling`) or an independent dissector has to read the bytes, or the bug is invisible.
