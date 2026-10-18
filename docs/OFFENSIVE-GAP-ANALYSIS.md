# Offensive gap analysis — what is coded, what is documented, and what is absent

Two questions, answered from the code rather than from the docs:

1. **Which modules do not have their offensive side coded yet?**
2. **Which offensive exploits is the tree missing entirely** — i.e. not in
   `ATTACK_COVERAGE.md` (the 27 filings), not in `OFFENSIVE_ROADMAP.md`, and not
   in any module?

**Method.** Per-module line-by-line audit of all 60 scripts in `modules/`, run as
three parallel read-only reviews (00–19, 20–39, 40–60) against
`MODULE_CONVENTIONS.md` §9 (capability split: a plan must print `status: handoff`
and name its hardware; "a button that looks like an attack but produces a README
is worse than no button") and §16 (known-answer tests). Every classification below
carries a `file:line`. The gap list was then produced by absence-grep over
`modules/`, `tools/` and `docs/`, and each absence was re-checked for a
false positive before being written down. **No file in `modules/` was modified by
this audit.**

---

## Part 1 — The offensive side: coded, partial, or documented-only

The honest axis is not "does it have an attack verb" but **"does it compute the
attack's bytes"**. A verb that prints a plan and a verb that prints the octets can
look identical in `--help`.

### 1a. Builders that are genuinely computed

These construct real protocol bytes. The radio or network hop is a named handoff —
which is the tree's stated contract, not a defect.

| Module | What is really built | Evidence |
|---|---|---|
| `07_gsm_attack` | GSM L3 + LAPDm + SCH payload + classmark + CIPHERING MODE COMMAND + IMMEDIATE ASSIGNMENT + RACH/CCCH/SDCCH frame schedules | `gatk_vector_imsi_catcher` `modules/07_gsm_attack.sh:1616`, `gatk_build_immediate_assignment` `:1467`, `gatk_lapdm_ui` `:1251` |
| `09_lte_attach` | Byte-exact NAS Attach / TAU / identity | `latt_cmd_encode_attach` `modules/09_lte_attach.sh:825`, KAT `:900` |
| `10_lte_air` | Rogue eNB: writes both srsRAN configs and **execs srsenb** | `lair_gen_enb_conf` `modules/10_lte_air.sh:1361`, `lair_start` `:1508` |
| `12_nr_air` | Rogue gNB: writes `gnb_tx.conf` and **execs the gNB** | `nair_gen_gnb_tx_conf` `modules/12_nr_air.sh:1845`, `nair_start` `:872` |
| `14_suci` | SUCI de-concealment, ECIES A/B, HKDF, X25519 | `suci_deconceal` `modules/14_suci.sh:393` |
| `26_ss7_map` | Byte-exact MAP/TCAP MSUs and flow `step_hex` | `ss7_build_sri` `modules/26_ss7_map.sh:1017`, `ss7_flow` `:1073` |
| `28_paging_track` | PAGING REQUEST octets (type-1 IE packing) + occasion math | `pgt_build_paging_req` `modules/28_paging_track.sh:743` |
| `36_vowifi` | IKEv2 header, EAP-AKA packet | `vowi_ike_build` `modules/36_vowifi.sh:112` |
| `38_ussd` | USSD 7-bit packing, MMI parse | `ussd_pack` `modules/38_ussd.sh:110` |
| `40_sba_pivot` | HTTP/2 frames incl. Rapid Reset pair | `sbap_h2_build` `modules/40_sba_pivot.sh:100`, `sbap_rapid_reset` `:287` |
| `41_ota_sms` | Full TS 23.048 OTA command packet | `otasm_packet_build` `modules/41_ota_sms.sh:151` |
| `52_stk` | STK proactive command envelope | `stk_proactive_build` `modules/52_stk.sh:163` |
| `54_baseband_exploit` | NAS forgers **but only 3-octet headers**; L2 cases are a static hex table (**no field-level encoder**); **a real transmit verb** — frame hex to `BEXP_TX_CMD` on stdin, tx-guarded by `--yes`/`BEXP_TX_ARMED=1` | `bexp_forge_reg_accept` `modules/54_baseband_exploit.sh:154`, `bexp_l2_cases` `:234`, `bexp_inject` `:373`, `bexp_inject_named` `:404` |
| `55_nr_inject` | Gold LFSR scrambling, MAC-NR, DCI, RAR, NAS frames + **a real transmit verb** (`NRJ_TX_CMD`) | `nrj_gold` `modules/55_nr_inject.sh:160`, `nrj_inject` `:755` |

### 1b. Offensive side documented-only — no computation behind the claim

| Module | Claimed offensive capability | What actually exists | Evidence |
|---|---|---|---|
| `11_lte_core` | Forged Diameter/GTP at a real HSS/S-GW | 4 encoders emit real octets; **zero transport** — no SCTP/GTP/TCP client. Nothing is sent **even with a testbed present** | builders `modules/11_lte_core.sh:1448,1465,1542,1554`; `lcore_require_core` `:1414` only *requires* a core |
| `13_nr_core` | N2 exposure, NRF discovery, SEPP bypass | Decoders + GTP-U header real; all 4 vectors are plan files; no network client | `ncore_cmd_plan` `modules/13_nr_core.sh:1064` |
| `15_downgrade` | "A forged SIB with `cellBarred` set" | **No cellBarred encoder at all** — the string appears only in the header comment | `grep -i cellbarred modules/15_downgrade.sh` → header only, `:17-18` |
| `16_sim` | UICC I/O, programmable-SIM write, OTA SMS send, eUICC profile install | All four are `status: handoff` plan files; the module is a codec only | `sim_plan` `modules/16_sim.sh:1301` |
| `20_gsm_cve` | A5/1 and A5/2 key recovery | **Not recovery — threshold predicates**: `(( seconds >= 120 ))`, `(( frames < 4 ))` | `gcve_a51_recover_feasible` `modules/20_gsm_cve.sh:~395` |
| `24/25/26_*_cve` | Every exploit id | Probe-or-handoff per header; no exploit primitive in any of the three | headers `20_gsm_cve.sh:7-13`, `21_lte_cve.sh:7-12`, `22_nr_cve.sh:9-14` |
| `27_cellular_dns` | aLTEr in-flight DNS rewrite | Spoof DNS bytes real; **no pcap rewriter, no GTP-U re-encapsulation, no inner checksum recompute, no send** | `cdns_build_response` `modules/27_cellular_dns.sh:272`; `cdns_alter_notes` `:948` is a heredoc |
| `30_volte_ims` | IMP4GT, SIP flood | IMP4GT is prose; flood is an arithmetic model; REGISTER spoof is computed but has no transport | `vims_imp4gt_model` `modules/30_volte_ims.sh:551`, `vims_sip_flood` `:764`, `vims_register_spoof` `:795` |
| `34_slicing` | Slice escape | One `status: handoff` plan; the real work is the codec + conservative isolation eval | `slic_cmd_plan` `modules/34_slicing.sh:750` |
| `35_baseband` | O6 baseband exploitation | Real mutator + ASN.1 codec; **no emitter** (declared) | `bbnd_mutate` `modules/35_baseband.sh:127` |
| `46_lpp` | Position-request/response forgery | **Worst case in the tree.** `--build-position` ignores all 3 arguments and returns a constant; `--detect-forgery` **never opens the pcap** and prints a hardcoded `Position outside valid bounds: 0` | `lpp_build_position_request` `modules/46_lpp.sh:116`, `lpp_detect_forgery` `:152-170` |
| `47_wifioff` | LWA steering, ePDG auth | Both are static printouts of fixed values | `wifioff_lwa_config` `modules/47_wifioff.sh:105`, `wifioff_auth_flow` `:122` |
| `48_oran` | "Forged A1 policy PUT (policy poisoning)" | Prints method/path/body descriptors; **no encoder, no transport, and no `status: handoff` label** | `oran_a1_put` `modules/48_oran.sh:255`, `oran_e2_control` `:265` |

### 1c. Documentation gaps — a claim with nothing behind it, not even a plan

- **`08_umts_air`** — the header promises a NodeB handoff "which names its
  hardware", but the module has **no offensive verb and no `.plan` file**. Unlike
  11/15/17/19 there is nothing a reader can pick up.
- **`45_iot`** — no `--plan` verb and no `Attack owned:` line, so its scope is
  *undeclared* rather than declared-defensive.
- **`12_nr_air`** — `NAIR_PLAN_DIR` is declared `modules/12_nr_air.sh:68` and
  `mkdir`'d `:71` but never used; that module has no `--plan` verb.
- **`54_baseband_exploit`** — the 8 `probe`-class rows of `nrj_exploits` (`modules/55_nr_inject.sh:784-799`)
  had **no constructor in either module**; `nrj_exploit` answered `probe`
  with "build the frame with `54_baseband_exploit` … or the RRC/MAC shaper", and
  59's "shaper" was the static hex table at `bexp_l2_cases` `modules/54_baseband_exploit.sh:234`.
  **RESOLVED (Phase 0):** `rrc-reconfig-bad` (V4) and `rrc-setup-downgrade` (V7)
  were added to `bexp_l2_cases` so all five 5Ghoul RRC variants have a case, and
  `55_nr_inject` now carries `nrj_probe_ctor` / `nrj_probe_frame` (`modules/55_nr_inject.sh:782-843`),
  which resolve each probe row to the concrete case in 59 and print its bytes
  plus a copy-pasteable `--l2-case` line. `nrj_exploit` returns 1 and prints
  `constructor_unresolved` when nothing resolves, so a probe row can no longer
  claim a frame that does not exist. Asserted by `expl-probe-*` in 60's selftest.

**Done — field-level constructors.** The corpus is no longer opaque literals. Each of
the 16 L2 cases now declares how its bytes arise, and `--l2-build <name>` prints that
derivation (`bexp_l2_build` `modules/54_baseband_exploit.sh:326`, `bexp_l2_construct`
`:360`, `bexp_l2_cases` `:370`): TS 38.321 §6.1.2/§6.2.1 MAC subheaders and the UL/DL
LCID tables (`bexp_mac_sh` `:256`), TS 38.323 §6.2.2/§6.3 PDCP data and control headers
(`bexp_pdcp_data_hdr` `:280`, `bexp_pdcp_ctrl_hdr` `:294`), TS 24.501
§9.1.1/§9.2/§9.3/§9.5 NAS header (`bexp_nas_hdr` `:304`), TS 38.214 §5.1.2.2.2 RIV
(`bexp_riv` `:313`). 7 cases are true **field** constructions that reproduce their
recorded bytes exactly and are asserted to (`mac-ccch-len`, `mac-lcid-padding`,
`mac-bsr-oversize`, `pdcp-1byte-cp`, `pdcp-5byte-cp`, `pdcp-sn-narrow`,
`nas-unknown-pdu`). The remaining 9 are honest **byte-class** constructs: the RRC/PHY/RLC
strings cannot be decomposed into named fields, because their named fields sit at least
9 bits into an ASN.1 APER structure, or describe LTE framing that NR removed. For those
the `why` column states the byte-level fact the string does encode and what would have to
be true for the named field to exist — `bexp_l2_construct` labels every case `fields` or
`bytes` so a caller can never mistake one class for the other. `docs/CONFIRMED-BUGS.md`
items 36-37 record the two defects the new assertions caught.

Separately, the module has a real transmit path (`bexp_inject`
`modules/54_baseband_exploit.sh:373`), so 59 is no longer build-only: the send
is performed here via `BEXP_TX_CMD` and only radio sync/waveform/timing is the
handoff.

### 1d. Verified defensive by design — superseded by Phase 12

This section used to list four modules as "defensive by design", on the strength
of `scope-no-*` assertions that proved the offensive verb exited 2. Phase 12
reversed that decision and built the verbs, so the assertions now prove the
opposite thing: that the seam holds. `31_sim_defense` (`simd_scope_check`),
`33_jamming_detect` (`jamd_scope_check`), `42_li_probe` and `44_carrier_api` each
assert that their detection verbs are ungated and silent on stderr, and that
every offensive verb refuses without `--i-have-a-lab-and-authorisation`, prints
its disclaimer on stderr before the gate test, and writes nothing on refusal.

What those four modules still do **not** do is act on a live network: the
baseband payload is a handoff, the carrier enumeration stops at a run-file, the
LI artefacts are encoded and never delivered, and the SIM verbs encode APDUs and
plans without opening a reader. The distinction that survives is the one worth
keeping — a verb that produces an artefact is not a verb that produces an
effect.

### 1e. Cross-cutting finding

**No module in the tree invokes a TX-capable SDR to radiate anything.** The only
live network sends anywhere are GSMTAP over UDP to `127.0.0.1`
(`modules/03_gsmtap.sh`, `modules/05_field_kit.sh`) and `55_nr_inject`'s external
`NRJ_TX_CMD`. Every other transmit path is an honest-fail
(`pgt_tx_paging` `modules/28_paging_track.sh:2287` → `status blocked`, rc 3), a
gated refusal (`nasf_cmd_transmit` `modules/32_nas_signaling.sh:1049`), or a plan
file. That is consistent with the stated contract — but it means **the roadmap's
TX tier is still entirely unbuilt**, not partially built.

---

## Part 2 — Offensive exploits missing from the tree

Each of these was absence-verified: `grep -rniE '<pattern>' modules/ tools/ docs/`
returns nothing relevant. They are **not in the 27-filing docket and not in
`OFFENSIVE_ROADMAP.md`** (confirmed: the roadmap scores 0 hits for every one).

Ordered by value ÷ cost, where cost is what it takes to validate.

### 2.1 — Build these first (no SDR required)

Items struck through and marked **DONE** are closed; they are kept in place so the
original ordering and its evidence stay visible. As of Phase 1 that is items 1 and
5 — the AKA algorithms and the A5/1 tradeoff table are implemented, and what
remains for both is *wiring them into modules*, which no longer belongs to this
section.

**1. Milenage and TUAK — ~~the 3GPP AKA algorithm is not implemented anywhere~~
DONE (Phase 1).** ~~Only *mentioned*, in a passing note at
`modules/30_volte_ims.sh:644`. Without it the toolkit cannot compute
RES/XRES/CK/IK/AUTN/MAC-A from K, and therefore cannot validate or forge an
authentication exchange in 3G/4G/5G. `tools/gsm_crypto.py` already carries
COMP128-1/2/3 (A3/A8) with published vectors — **its 3G successor never
followed**, which is the single largest hole in the crypto layer and a bigger
one than the missing ciphers `FEATURE-GAPS.md` catalogues, because every
AKA-relay and fake-authentication vector is blocked behind it. Testable today
against TS 35.208 test sets. *Cost: pure computation.*~~
Milenage f1–f5\* and TUAK f1–f5\* now live in `tools/gsm_crypto.py`, asserted
against all twenty TS 35.208 test sets and the TS 35.231/35.232 TUAK sets, with
the raw Keccak-f[1600] pairs pinning the permutation independently of the
framing. RES/XRES/CK/IK/AUTN/MAC-A are computable from K. What is left is
**wiring**, not capability: no module calls the new verbs yet, so `30_volte_ims`
still only *mentions* AKA.

**2. Baseband diagnostic interfaces — QCDM / DIAG / AT / NV-EFS.** Zero hits for
`qcdm`, `diag`, `qcsuper`, `at+`, `nvitem`. This is a complete attack surface
reached over USB: modem logging, NV-item and EFS reads/writes, IMEI manipulation,
AT command injection on WWAN modules, and baseband traces without any radio. It is
the QCSuper/`Mobile-Security-Framework` surface. **Every other offensive gap in
this list needs an SDR; this one needs a cable**, which makes it the cheapest
high-value item on the list and the one most likely to be validated by whoever
picks the toolkit up. *Cost: serial/diag protocol work only.*

**3. Type-0 "silent SMS" and the TS 23.040 TP layer.** `41_ota_sms` builds
TS 23.048 OTA command packets (the SIM Toolkit *transport*) but nothing in the
tree touches the TP layer: no TP-MTI, no TP-PID, no Type-0. The silent-SMS
presence trigger — a message that leaves no user-visible trace and confirms a
handset is live — is a published tracking primitive and is unconstructible here.
Adjacent: `52_stk` only *detects* the TP-PID 0x7F toolkit-SMS fingerprint
(`stk_simjacker_detect` `modules/52_stk.sh:288`); it never constructs one.
*Cost: pure computation.*

**4. DPA / side-channel SIM cloning.** `tools/gsm_crypto.py` has COMP128-1/2/3,
but there is no side-channel path: no differential-power-analysis model to recover
Ki from a card, no trace-capture interface. `modules/16_sim.sh` already has the
APDU layer the attack would sit next to. *Cost: computation + a capture rig.*

**5. A5/1 time-memory-tradeoff — ~~implements none of it~~ the lookup half is DONE
(Phase 1).** `20_gsm_cve` cites Golic 1997, Biham-Dunkelman-Keller 2000 and Nohl
2009 in its own output (`modules/20_gsm_cve.sh:662`) but implements none of it —
the "recovery" verb is a threshold comparison. `07_gsm_attack`'s `--kc-search` is
the A5/2-style 2^16 shortcut, not the A5/1 TMTO. `tools/gsm_crypto.py` now has
`A51Table` / `a51_tmto_demo`: a rainbow table with a real build-and-lookup
interface, and **the honest limit is width**. The method is exact and is checked
at every column alignment, but the table is built at a reduced index width so it
can be exhaustively verified in seconds; the 2^54 TMTO of the literature is a
precomputed-table or cluster job and is out of scope here. Both published A5/1
vectors (BGW and libosmocore, downlink and uplink) are asserted on the state
transition. *Cost: computation.*

### 2.2 — Published attacks with an existing emitter to ride on

**6. Emergency-alert forgery (PWS / ETWS / CMAS).** `10_lte_air` **decodes**
SIB6/SIB7/SIB8 (`lair_decode_sib6` `modules/10_lte_air.sh:703`, `lair_decode_sib7`
`:732`) but there is no builder, and `12_nr_air` has **zero** NR PWS support
(`grep -niE 'pws|etws|cmas|earthquake|warning' modules/12_nr_air.sh` → nothing).
A forged earthquake/tsunami/presidential alert is a published attack class, needs
only the same srsRAN eNB the toolkit already orchestrates, and the encode side is
small. **This is the highest-impact gap**, and it is also the one that needs the
tree's own scoping discipline applied: unlike a jamming transmitter it has no
legitimate lab-only use that generalises, so it belongs with the `33_jamming_detect`
treatment — encode and detect, name the legal position once, and do not ship a
live alert injector.

**7. 3G/UMTS rogue NodeB (O1 for UMTS).** The docket gives O1 owners for GSM
(`11`), LTE (`13`/`14`) and NR (`16`) but **none for UMTS** — `08_umts_air` has no
offensive verb at all. UTRAN is the one generation with no IMSI-catcher path.

**8. IMS media plane — SRTP / DTLS-SRTP / MIKEY.** Zero hits for `srtp`, `mikey`,
`dtls`. `30_volte_ims` works entirely on signalling and the ReVoLTE keystream
reuse; nothing parses SRTP, derives media keys, or tests MIKEY/DTLS negotiation
failure.

**9. RCS (Rich Communication Services).** `grep -rniw rcs modules/` → nothing. RCS
is the default messaging stack on most carriers, with its own SIP/MSRP surface,
capability discovery, and authentication — a whole class with no coverage.

**10. SUPL / LCS / A-GPS.** No SUPL anywhere; `26_ss7_map` has only MAP LCS
*opcode names* (`:860-864`). SUPL is the control plane behind every handset's
assisted GPS.

**11. Emergency services — eCall / NG112 / PSAP.** Zero hits. Fake
emergency-call origination, PSAP identity, and the eCall MSD payload are uncovered.

**12. CBS / MBS content attacks.** No cell-broadcast *service* attack; the only
mentions are a detection note (`modules/07_gsm_attack.sh:211`) and MBMS GTP-U IE
names (`modules/11_lte_core.sh:1113`).

**13. ANDSF / Hotspot 2.0 (Passpoint) / LWA convergence.** `47_wifioff` claims LWA
but prints constants; ANDSF and Passpoint are absent entirely.

**14. SIM box / IRSF / grey-route fraud.** Zero hits for `irsf`, `sim box`,
`grey route`. A nationally significant fraud class whose signature is entirely
protocol-analysable, and which sits naturally beside the existing
`--cdr-fraud-check` (`modules/11_lte_core.sh`).

**15. 5G RedCap / NR-Light and NR-U (unlicensed NR).** Absent.

**16. Charging abuse via N4/UPF URR.** `11_lte_core` has GTP-CDR fraud detection;
URR-based charging abuse is not modelled.

---

## Part 3 — Proposed build order

### The sequencing rules

1. **Honesty debt before new surface.** A module that prints `Anomalies detected:
   0` for a file it never opened is worse than a module that does not exist,
   because the reader cannot tell. The tree's entire differentiator is that it
   says which parts work.
2. **Validate-now before validate-later.** The audience supplies radios. Anything
   that needs no SDR can be *proved* by whoever writes it, today; anything that
   needs one is a claim until someone else fires it. Spend first where the proof
   is available.
3. **Unblock before instances.** Milenage is one file that makes a dozen
   downstream vectors constructible. A forged SIB is one vector.
4. **One interface before eight clients.** Eight modules are print-only for the
   *same* missing reason (no transport). That is one design decision, not eight
   tasks.

### Phase 0 — Honesty debt (no new capability)

Fix the places where the tree currently overclaims. Small, and it is the repo's
own §9 standard.

| Item | Action |
|---|---|
| `46_lpp` | ~~Implement `--detect-forgery` for real **or** relabel it handoff.~~ **DONE — relabelled to a §9 handoff.** It no longer fabricates a result. |
| `15_downgrade` | ~~Write the SIB1/`cellBarred` encoder the module's header already advertises.~~ **DONE — `dng_forge_sib1` + `dng_sib1_payload`, `sib1-*` assertions.** |
| `08_umts_air` | ~~Write the NodeB plan file the header promises, or correct the header.~~ **Stale item — no action needed.** The header promises no plan file; it already satisfies §9 by naming the hardware ("the only handoff is actually transmitting or intercepting a NodeB, which names its hardware"). The module has no `--plan` verb and needs none, being pure computation. |
| `45_iot` | ~~Add `--plan` and an `Attack owned:` line so its scope is declared.~~ **DONE.** |
| `12_nr_air` | ~~Remove or use `NAIR_PLAN_DIR`.~~ **DONE — removed.** |
| `59`/`60` | ~~Build the 8 `probe`-class frame constructors or relabel them `handoff`.~~ **DONE — 2 cases added to `bexp_l2_cases`; `nrj_probe_ctor`/`nrj_probe_frame` resolve all 8.** |
| Docs | ~~`OFFENSIVE_ROADMAP.md:39`, `TOOLKIT_REFERENCE.md:148`: `IMSI mod 1024` → `1000`.~~ **DONE.** |

**Validate by:** the module's own selftest, plus `tools/run-selftests.sh` green.

### Phase 1 — Crypto core completion (pure computation, published KATs)

**DONE.** **Milenage + TUAK** are in `tools/gsm_crypto.py`, alongside the
COMP128-1/2/3 that were already there. Asserted against **TS 35.208** clause
4.3 — all twenty Milenage test sets, OPC derivation included — and
**TS 35.231/35.232** for TUAK: all six clause-6 f1/f1* sets and all six
clause-7 f2-f5/f5* sets. TUAK is pinned twice over, because the end-to-end
sets alone cannot separate a broken permutation from broken framing: the six
raw clause-5 Keccak-f[1600] 200-byte input/output pairs cover the permutation
on its own, and the instance in-blocks printed in clauses 6 and 7 cover the
key-length-dependent encoding byte-for-byte.

Then **A5/1 time-memory-tradeoff**:
  * The **state transition** is validated against the two independent published
    A5/1 vectors already asserted in `gatk_kat_suite` — Briceno/Goldberg/Wagner
    and libosmocore, the downlink *and* uplink row of each, plus the
    `osmo_a5_fn_count` frame-to-COUNT conversion.
  * The **lookup half** ships as `A51Table` / `a51_tmto_demo`: a rainbow table
    with a real build-and-lookup interface, run at an operator-named width so
    the method is exhaustively checkable, and every hit confirmed by
    regenerating the observed keystream (which is what converts a reduction
    collision into lost time rather than a wrong answer).
  * It is explicitly *not* the 2^54 search. At full width that is a
    precomputed-table or cluster job; `--a51-tmto-demo` prints
    `scope reduced-width demonstration, NOT the 2^54 attack` on every run, and
    the module docstring says the same.

`--selftest` reports PASS for **1** AES FIPS-197 vector, **6** Keccak pairs,
**20** Milenage sets (7 checks each), **2** TUAK groups (12 and 30 checks),
**2** A5/1 vectors (downlink + uplink each), **1** COUNT conversion and **4**
tradeoff-table lookup alignments.

**Unblocked:** 5G-AKA / EAP-AKA' (`13_nr_core`, `36_vowifi`), IMP4GT (`30_volte_ims`),
fake authentication in every rogue-BTS module (`11`, `13`, `14`, `16`),
`19_cipher_audit`'s algorithm tables.

**Size:** M. **Validate by:** published vectors, no hardware.

### Phase 2 — The no-SDR attack surface

This is the only high-value work that can be *proved* without a radio.

**TP layer — DONE.** The **TS 23.040 SMS TP layer** is in `modules/41_ota_sms.sh`
as `otasm_tp_*` / `otasm_tpdu_*`, alongside the TS 23.048 work already there.
Encoded and parsed: **TP-MTI** (all four values, with the reserved value
reported rather than coerced, per §9.2.3.1), **TP-PID** (both coding blocks,
the full telematic-device table, Short Message Type 0, Replace 1–7, Device
Triggering), **TP-DCS** (all nine TS 23.038 §4 coding groups, alphabet, message
class, compression, and the reserved groups §4 warns about), **TP-SCTS** and
**TP-DT** (semi-octet swap plus the signed quarter-hour zone), the **address
field** (§9.1.2.5, odd digit counts with the `F` fill, and the alphanumeric
originator read path), **TP-FCS** and **TP-ST** (both full tables, reserved
ranges interpreted the way the spec says an MS must), **TP-UDL** cross-checked
against the actual TP-UD length *under the alphabet TP-DCS selected* rather
than assumed, **TP-UDHI**, **TP-PI** and **TP-VPF**-dependent TP-VP lengths.

**Delivery-report handling** is the SMS-STATUS-REPORT branch of `--tpdu-parse`
(TP-MR, TP-RA, TP-SCTS, TP-DT, TP-ST, TP-PI, and the optional trailing TP-UD),
with TP-ST's temporary/permanent and retry-vs-gave-up ranges distinguished.

**Type 0 silent SMS** ships as `--type0-build` and `--type0`: the builder emits
the canonical TP-PID 0x40 SMS-DELIVER with an empty TP-UD, and the audit states
what that obliges the ME to do — acknowledge, discard, do not indicate, do not
store (§9.2.3.9) — plus the TP-FCS 0x81 an SC returns when it will not carry
Type 0 at all (§9.2.3.22).

The **GSM 7-bit packer** is anchored to TS 23.038 §6.1.2.1.1's normative
bit-layout tables: `hi`→`e834`, `Hi`→`c834`, `hello`→`e8329bfd06`,
`Hello`→`c8329bfd06`, each with a round-trip check. `hi`→`e834` is the same
vector `38_ussd` already asserts, so a regression in either packer is caught by
the other module. `--selftest` reports **93 assertions, RESULT PASS**, four of
which assert an invariant rather than a value: every line emitted on the
`finding` severity channel is counted in `findings`, and an informational line
arrives as `note`. That invariant is what caught a MEDIUM that was printed but
never counted.

Nothing in this half transmits. `--plan-tp` is the handoff: build the TPDU,
wrap it with `--smsc-wrap`, and hand it to a loopback SMSC you run.

**Size:** S. **Validate by:** a loopback SMSC; the published packing vectors.

**DPA side-channel model — DONE.** COMP128-1's round 0, level 0 reads
`x[a] = T0[(ki[j] + 2*rand[j]) & 511]`, so the power proxy for key byte `j`
is the Hamming weight of one table lookup at an address the attacker chooses
by picking RAND. That model lives in `tools/gsm_crypto.py` next to the
COMP128-1 tables it needs — copying the S-boxes and `T0` into shell is the
drift this tree has already been bitten by. `16_sim` owns the SIM-domain
verbs and delegates:

- `--dpa-model <ki> <rand>` prints the leakage point for all 16 key bytes:
  address, `T0` output and Hamming weight.
- `--dpa-sim <ki> [traces] [sigma]` synthesises traces from the model,
  correlates all 256 candidates per position, then **proves** the result by
  running COMP128-1 on challenges the trace set never contained. A correlation
  peak is not accepted as evidence; `holdout_mismatches` must be 0.
- `--dpa-sweep <ki>` sweeps noise (σ 0…5), trace count (16…512) and a
  deliberately wrong leakage model.

At σ=0 and 512 traces the peak correlation is 0.80 against a runner-up of
0.01. Recovery survives σ=5.0, and 16 traces already separate the key byte
from all 256 candidates. The sweep's discrimination control is the load-bearing
part: when the model targets the wrong quantity (the address rather than the
table output), **16 of 16 bytes come back wrong** — so a passing run is testing
the leakage model, not merely finding structure in the trace matrix.

The traces are synthetic. There is no oscilloscope, no probe and no card in
this path, and none of those numbers is a measurement. `--plan dpa-lab` is the
handoff and names the exact rig (owned UICC, PC/SC reader, current or EM probe,
triggerable scope), plus what real captures add: alignment jitter, and whether
the leakage is `T0`'s Hamming weight at all — a masked card makes that
assumption false, and masking is exactly what COMP128-2/-3 do.

`16_sim --selftest` gained 10 assertions covering the delegation and its
argument validation; the arithmetic is proved in `gsm_crypto.py --selftest`,
which includes the held-out verification and the wrong-model control.

**Size:** S (model) rather than M — the APDU layer already existed, and the
arithmetic sits beside tables that were already there.
**Validate by:** the model's own degradation behaviour; a capture rig for the
real thing.

| Item | Where | Notes |
|---|---|---|
| **QCDM / DIAG / AT / NV-EFS** | new module (nb. `56_baseband_diag`) | DIAG framing, NV/EFS read-write, IMEI surface, AT command handling, baseband log decode. New dep: `pyserial`. Needs a cable, not an SDR. |

**Size:** L for DIAG.
**Validate by:** a USB-attached modem.

### Phase 3 — The emitter layer (one decision, eight modules)

Eight modules are print-only for the same reason: the builders exist, the
transport does not. `55_nr_inject` already demonstrates the pattern —
`NRJ_TX_CMD` plus a `--tx-ack` gate — and `07_gsm_attack`'s `--tx-ack` is the
legal-position template. **Generalise it, do not re-implement it eight times.**

First four clients, in this order (easiest proof first):

1. **`27_cellular_dns` pcap rewriter + GTP-U re-encapsulation.** *Pure software,
   no radio at all* — rewrite a captured pcap, recompute inner IP/UDP checksums,
   re-encapsulate the G-PDU, and diff the result. This is the aLTEr demonstration
   without a transmitter, and it is fully testable today.
2. **`26_ss7_map`** — drive the encoded MSUs at a local `osmo-stp`. Lab-reachable.
3. **`11_lte_core`** — SCTP/GTP-C client against a local Open5GS. Four finished
   builders cannot currently be exercised even with a testbed.
4. **`13_nr_core` / `40_sba_pivot`** — HTTP/2 client against a local free5GC.
   `40_sba_pivot` already encodes the frames.

**Size:** M for the shared interface, S–M per client.
**Validate by:** a local testbed (`osmo-stp`, Open5GS, free5GC) — all of which the
tree already names in its own plan files.

### Phase 4 — Radio-gated offensive build-out

Build to the boundary; each stays `status: handoff` until someone fires it.

| Item | Module |
|---|---|
| GSM radio driver — GMSK modulation + TS 45.003 channel coding + burst TX | `07_gsm_attack` (the missing half of the work just completed) |
| **PWS / ETWS / CMAS** encode + detect | `10_lte_air` (decoder exists), `12_nr_air` (nothing) |
| **UMTS rogue NodeB (O1 for 3G)** | `08_umts_air` |
| Paging transmitter (Torpedo / Piercer TX) | `28_paging_track` — `pgt_tx_paging` is already the honest-fail stub |
| IMP4GT identity-mapping state machine | `30_volte_ims` |

**PWS needs a scope decision before it starts** — see the open decisions below.

### Phase 5 — Long tail

SRTP/MIKEY (IMS media plane) · RCS · SUPL/LCS/A-GPS · eCall/NG112/PSAP ·
CBS/MBS · ANDSF/Hotspot 2.0 · SIM box/IRSF fraud · 5G RedCap/NR-U ·
N4/URR charging abuse. Individually small, collectively the difference between
"covers the surface" and "covers a sample of it" — which is the same argument
`HANDOFF.md` makes for breadth over depth.

### If you only do three things

1. **Phase 0** — it is cheap, and it protects the one property that makes this
   tree worth using.
2. **Phase 1 (Milenage/TUAK)** — one file, published vectors, unblocks the most.
3. **Phase 2 (QCDM/DIAG)** — the only substantial capability anyone can prove
   without buying a radio.

### Open decisions

- **Emitter layer:** one shared gated interface (Phase 3 as written), or per-module
  transports as today? Shared is ~8× less work and one place to audit; per-module
  keeps each module self-contained per `MODULE_CONVENTIONS.md` §2 (no shared lib).
  **This one decides the shape of Phase 3 and it conflicts with the existing
  no-shared-lib convention** — worth settling first.
- **`46_lpp`:** implement, or delete the module?
- **PWS/ETWS:** encode-and-detect only (the `33_jamming_detect` treatment), or
  encode plus a gated injector (the `32_nas_signaling` treatment)? A forged
  earthquake alert has far less lab-only legitimacy than a jamming transmitter, so
  the former is the defensible default.
- **Namespace:** new modules for new surface (`61_…`), or fold into the nearest
  existing module? The 60-module roster is already at the point where the sidebar
  groups by category rather than by generation.

---

## Part 4 — Documentation drift found in passing

- `docs/OFFENSIVE_ROADMAP.md:39` and `docs/TOOLKIT_REFERENCE.md:148` still say
  **"paging group (IMSI mod 1024)"**. TS 45.002 §6.5.2 specifies
  `((IMSI mod 1000) mod (BS_CC_CHANS × N)) mod N`. The code was corrected this
  session (`CONFIRMED-BUGS.md` item 15) — the two docs were not.
- `docs/FEATURE-GAPS.md:243` repeats `IMSI mod 1024`, but that one is about
  `10_lte_air`'s LTE paging (`UE_ID = IMSI mod 1024`), which **is** correct for
  TS 36.304. Not drift.
- `ATTACK_COVERAGE.md`'s roll-up says "33 modules / 27 attacks" for v0.2, while
  the tree now has 60 modules and the v0.3/v0.5 sweeps are undocumented in the
  docket (`EXPLOIT_SOURCES.md` covers them separately). The coverage table should
  either absorb O21+ or state that it stops at v0.2.
