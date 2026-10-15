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
| `11_gsm_attack` | GSM L3 + LAPDm + SCH payload + classmark + CIPHERING MODE COMMAND + IMMEDIATE ASSIGNMENT + RACH/CCCH/SDCCH frame schedules | `gatk_vector_imsi_catcher` `modules/11_gsm_attack.sh:1616`, `gatk_build_immediate_assignment` `:1467`, `gatk_lapdm_ui` `:1251` |
| `13_lte_attach` | Byte-exact NAS Attach / TAU / identity | `latt_cmd_encode_attach` `modules/13_lte_attach.sh:825`, KAT `:900` |
| `14_lte_air` | Rogue eNB: writes both srsRAN configs and **execs srsenb** | `lair_gen_enb_conf` `modules/14_lte_air.sh:1361`, `lair_start` `:1508` |
| `16_nr_air` | Rogue gNB: writes `gnb_tx.conf` and **execs the gNB** | `nair_gen_gnb_tx_conf` `modules/16_nr_air.sh:1845`, `nair_start` `:872` |
| `18_suci` | SUCI de-concealment, ECIES A/B, HKDF, X25519 | `suci_deconceal` `modules/18_suci.sh:393` |
| `31_ss7_map` | Byte-exact MAP/TCAP MSUs and flow `step_hex` | `ss7_build_sri` `modules/31_ss7_map.sh:1017`, `ss7_flow` `:1073` |
| `33_paging_track` | PAGING REQUEST octets (type-1 IE packing) + occasion math | `pgt_build_paging_req` `modules/33_paging_track.sh:743` |
| `41_vowifi` | IKEv2 header, EAP-AKA packet | `vowi_ike_build` `modules/41_vowifi.sh:112` |
| `43_ussd` | USSD 7-bit packing, MMI parse | `ussd_pack` `modules/43_ussd.sh:110` |
| `45_sba_pivot` | HTTP/2 frames incl. Rapid Reset pair | `sbap_h2_build` `modules/45_sba_pivot.sh:100`, `sbap_rapid_reset` `:287` |
| `46_ota_sms` | Full TS 23.048 OTA command packet | `otasm_packet_build` `modules/46_ota_sms.sh:151` |
| `57_stk` | STK proactive command envelope | `stk_proactive_build` `modules/57_stk.sh:163` |
| `59_baseband_exploit` | NAS forgers **but only 3-octet headers**; L2 cases are a static hex table (**no field-level encoder**); **a real transmit verb** — frame hex to `BEXP_TX_CMD` on stdin, tx-guarded by `--yes`/`BEXP_TX_ARMED=1` | `bexp_forge_reg_accept` `modules/59_baseband_exploit.sh:154`, `bexp_l2_cases` `:234`, `bexp_inject` `:373`, `bexp_inject_named` `:404` |
| `60_nr_inject` | Gold LFSR scrambling, MAC-NR, DCI, RAR, NAS frames + **a real transmit verb** (`NRJ_TX_CMD`) | `nrj_gold` `modules/60_nr_inject.sh:160`, `nrj_inject` `:755` |

### 1b. Offensive side documented-only — no computation behind the claim

| Module | Claimed offensive capability | What actually exists | Evidence |
|---|---|---|---|
| `15_lte_core` | Forged Diameter/GTP at a real HSS/S-GW | 4 encoders emit real octets; **zero transport** — no SCTP/GTP/TCP client. Nothing is sent **even with a testbed present** | builders `modules/15_lte_core.sh:1448,1465,1542,1554`; `lcore_require_core` `:1414` only *requires* a core |
| `17_nr_core` | N2 exposure, NRF discovery, SEPP bypass | Decoders + GTP-U header real; all 4 vectors are plan files; no network client | `ncore_cmd_plan` `modules/17_nr_core.sh:1064` |
| `19_downgrade` | "A forged SIB with `cellBarred` set" | **No cellBarred encoder at all** — the string appears only in the header comment | `grep -i cellbarred modules/19_downgrade.sh` → header only, `:17-18` |
| `20_sim` | UICC I/O, programmable-SIM write, OTA SMS send, eUICC profile install | All four are `status: handoff` plan files; the module is a codec only | `sim_plan` `modules/20_sim.sh:1301` |
| `24_gsm_cve` | A5/1 and A5/2 key recovery | **Not recovery — threshold predicates**: `(( seconds >= 120 ))`, `(( frames < 4 ))` | `gcve_a51_recover_feasible` `modules/24_gsm_cve.sh:~395` |
| `24/25/26_*_cve` | Every exploit id | Probe-or-handoff per header; no exploit primitive in any of the three | headers `24_gsm_cve.sh:7-13`, `25_lte_cve.sh:7-12`, `26_nr_cve.sh:9-14` |
| `32_cellular_dns` | aLTEr in-flight DNS rewrite | Spoof DNS bytes real; **no pcap rewriter, no GTP-U re-encapsulation, no inner checksum recompute, no send** | `cdns_build_response` `modules/32_cellular_dns.sh:272`; `cdns_alter_notes` `:948` is a heredoc |
| `35_volte_ims` | IMP4GT, SIP flood | IMP4GT is prose; flood is an arithmetic model; REGISTER spoof is computed but has no transport | `vims_imp4gt_model` `modules/35_volte_ims.sh:551`, `vims_sip_flood` `:764`, `vims_register_spoof` `:795` |
| `39_slicing` | Slice escape | One `status: handoff` plan; the real work is the codec + conservative isolation eval | `slic_cmd_plan` `modules/39_slicing.sh:750` |
| `40_baseband` | O6 baseband exploitation | Real mutator + ASN.1 codec; **no emitter** (declared) | `bbnd_mutate` `modules/40_baseband.sh:127` |
| `51_lpp` | Position-request/response forgery | **Worst case in the tree.** `--build-position` ignores all 3 arguments and returns a constant; `--detect-forgery` **never opens the pcap** and prints a hardcoded `Position outside valid bounds: 0` | `lpp_build_position_request` `modules/51_lpp.sh:116`, `lpp_detect_forgery` `:152-170` |
| `52_wifioff` | LWA steering, ePDG auth | Both are static printouts of fixed values | `wifioff_lwa_config` `modules/52_wifioff.sh:105`, `wifioff_auth_flow` `:122` |
| `53_oran` | "Forged A1 policy PUT (policy poisoning)" | Prints method/path/body descriptors; **no encoder, no transport, and no `status: handoff` label** | `oran_a1_put` `modules/53_oran.sh:255`, `oran_e2_control` `:265` |

### 1c. Documentation gaps — a claim with nothing behind it, not even a plan

- **`12_umts_air`** — the header promises a NodeB handoff "which names its
  hardware", but the module has **no offensive verb and no `.plan` file**. Unlike
  11/15/17/19 there is nothing a reader can pick up.
- **`50_iot`** — no `--plan` verb and no `Attack owned:` line, so its scope is
  *undeclared* rather than declared-defensive.
- **`16_nr_air`** — `NAIR_PLAN_DIR` is declared `modules/16_nr_air.sh:68` and
  `mkdir`'d `:71` but never used; that module has no `--plan` verb.
- **`59_baseband_exploit`** — the 8 `probe`-class rows of `nrj_exploits` (`modules/60_nr_inject.sh:784-799`)
  had **no constructor in either module**; `nrj_exploit` answered `probe`
  with "build the frame with `59_baseband_exploit` … or the RRC/MAC shaper", and
  59's "shaper" was the static hex table at `bexp_l2_cases` `modules/59_baseband_exploit.sh:234`.
  **RESOLVED (Phase 0):** `rrc-reconfig-bad` (V4) and `rrc-setup-downgrade` (V7)
  were added to `bexp_l2_cases` so all five 5Ghoul RRC variants have a case, and
  `60_nr_inject` now carries `nrj_probe_ctor` / `nrj_probe_frame` (`modules/60_nr_inject.sh:782-843`),
  which resolve each probe row to the concrete case in 59 and print its bytes
  plus a copy-pasteable `--l2-case` line. `nrj_exploit` returns 1 and prints
  `constructor_unresolved` when nothing resolves, so a probe row can no longer
  claim a frame that does not exist. Asserted by `expl-probe-*` in 60's selftest.

**Follow-up (in progress).** The corpus is still a fixed heredoc: `bexp_l2_case`
`modules/59_baseband_exploit.sh:254` selects a row and nothing encodes one, so
the hex for all 16 L2 cases is an opaque literal. The open item is to replace
each literal with a field-level constructor derived from the spec (TS 38.321
§6.2.1 MAC, TS 38.323 §6.2.2/§6.3 PDCP, TS 38.322 RLC, TS 38.212 §7.3.1 DCI,
TS 24.501 NAS) and assert the constructor reproduces the recorded bytes.
Separately, the module now has a real transmit path (`bexp_inject`
`modules/59_baseband_exploit.sh:373`), so 59 is no longer build-only: the send
is performed here via `BEXP_TX_CMD` and only radio sync/waveform/timing is the
handoff.

### 1d. Verified defensive by design

`36_sim_defense` (`simd_scope_check` `modules/36_sim_defense.sh:425`),
`38_jamming_detect` (`jamd_scope_check` `modules/38_jamming_detect.sh:570`),
`47_li_probe` (selftest asserts `--activate`/`--intercept`/`--provision-target`
exit 2, `modules/47_li_probe.sh:212-214`), `49_carrier_api` (selftest asserts
`--enumerate`/`--enumerate-subscribers` exit 2, `:344-345`).

### 1e. Cross-cutting finding

**No module in the tree invokes a TX-capable SDR to radiate anything.** The only
live network sends anywhere are GSMTAP over UDP to `127.0.0.1`
(`modules/03_gsmtap.sh`, `modules/05_field_kit.sh`) and `60_nr_inject`'s external
`NRJ_TX_CMD`. Every other transmit path is an honest-fail
(`pgt_tx_paging` `modules/33_paging_track.sh:2287` → `status blocked`, rc 3), a
gated refusal (`nasf_cmd_transmit` `modules/37_nas_signaling.sh:1049`), or a plan
file. That is consistent with the stated contract — but it means **the roadmap's
TX tier is still entirely unbuilt**, not partially built.

---

## Part 2 — Offensive exploits missing from the tree

Each of these was absence-verified: `grep -rniE '<pattern>' modules/ tools/ docs/`
returns nothing relevant. They are **not in the 27-filing docket and not in
`OFFENSIVE_ROADMAP.md`** (confirmed: the roadmap scores 0 hits for every one).

Ordered by value ÷ cost, where cost is what it takes to validate.

### 2.1 — Build these first (no SDR required)

**1. Milenage and TUAK — the 3GPP AKA algorithm is not implemented anywhere.**
Only *mentioned*, in a passing note at `modules/35_volte_ims.sh:644`. Without it
the toolkit cannot compute RES/XRES/CK/IK/AUTN/MAC-A from K, and therefore cannot
validate or forge an authentication exchange in 3G/4G/5G. `tools/gsm_crypto.py`
already carries COMP128-1/2/3 (A3/A8) with published vectors — **its 3G successor
never followed**, which is the single largest hole in the crypto layer and a
bigger one than the missing ciphers `FEATURE-GAPS.md` catalogues, because every
AKA-relay and fake-authentication vector is blocked behind it. Testable today
against TS 35.208 test sets. *Cost: pure computation.*

**2. Baseband diagnostic interfaces — QCDM / DIAG / AT / NV-EFS.** Zero hits for
`qcdm`, `diag`, `qcsuper`, `at+`, `nvitem`. This is a complete attack surface
reached over USB: modem logging, NV-item and EFS reads/writes, IMEI manipulation,
AT command injection on WWAN modules, and baseband traces without any radio. It is
the QCSuper/`Mobile-Security-Framework` surface. **Every other offensive gap in
this list needs an SDR; this one needs a cable**, which makes it the cheapest
high-value item on the list and the one most likely to be validated by whoever
picks the toolkit up. *Cost: serial/diag protocol work only.*

**3. Type-0 "silent SMS" and the TS 23.040 TP layer.** `46_ota_sms` builds
TS 23.048 OTA command packets (the SIM Toolkit *transport*) but nothing in the
tree touches the TP layer: no TP-MTI, no TP-PID, no Type-0. The silent-SMS
presence trigger — a message that leaves no user-visible trace and confirms a
handset is live — is a published tracking primitive and is unconstructible here.
Adjacent: `57_stk` only *detects* the TP-PID 0x7F toolkit-SMS fingerprint
(`stk_simjacker_detect` `modules/57_stk.sh:288`); it never constructs one.
*Cost: pure computation.*

**4. DPA / side-channel SIM cloning.** `tools/gsm_crypto.py` has COMP128-1/2/3,
but there is no side-channel path: no differential-power-analysis model to recover
Ki from a card, no trace-capture interface. `modules/20_sim.sh` already has the
APDU layer the attack would sit next to. *Cost: computation + a capture rig.*

**5. A5/1 time-memory-tradeoff.** `24_gsm_cve` cites Golic 1997, Biham-Dunkelman-Keller
2000 and Nohl 2009 in its own output (`modules/24_gsm_cve.sh:662`) but implements
none of it — the "recovery" verb is a threshold comparison. `11_gsm_attack`'s
`--kc-search` is the A5/2-style 2^16 shortcut, not the A5/1 TMTO.
*Cost: computation.*

### 2.2 — Published attacks with an existing emitter to ride on

**6. Emergency-alert forgery (PWS / ETWS / CMAS).** `14_lte_air` **decodes**
SIB6/SIB7/SIB8 (`lair_decode_sib6` `modules/14_lte_air.sh:703`, `lair_decode_sib7`
`:732`) but there is no builder, and `16_nr_air` has **zero** NR PWS support
(`grep -niE 'pws|etws|cmas|earthquake|warning' modules/16_nr_air.sh` → nothing).
A forged earthquake/tsunami/presidential alert is a published attack class, needs
only the same srsRAN eNB the toolkit already orchestrates, and the encode side is
small. **This is the highest-impact gap**, and it is also the one that needs the
tree's own scoping discipline applied: unlike a jamming transmitter it has no
legitimate lab-only use that generalises, so it belongs with the `38_jamming_detect`
treatment — encode and detect, name the legal position once, and do not ship a
live alert injector.

**7. 3G/UMTS rogue NodeB (O1 for UMTS).** The docket gives O1 owners for GSM
(`11`), LTE (`13`/`14`) and NR (`16`) but **none for UMTS** — `12_umts_air` has no
offensive verb at all. UTRAN is the one generation with no IMSI-catcher path.

**8. IMS media plane — SRTP / DTLS-SRTP / MIKEY.** Zero hits for `srtp`, `mikey`,
`dtls`. `35_volte_ims` works entirely on signalling and the ReVoLTE keystream
reuse; nothing parses SRTP, derives media keys, or tests MIKEY/DTLS negotiation
failure.

**9. RCS (Rich Communication Services).** `grep -rniw rcs modules/` → nothing. RCS
is the default messaging stack on most carriers, with its own SIP/MSRP surface,
capability discovery, and authentication — a whole class with no coverage.

**10. SUPL / LCS / A-GPS.** No SUPL anywhere; `31_ss7_map` has only MAP LCS
*opcode names* (`:860-864`). SUPL is the control plane behind every handset's
assisted GPS.

**11. Emergency services — eCall / NG112 / PSAP.** Zero hits. Fake
emergency-call origination, PSAP identity, and the eCall MSD payload are uncovered.

**12. CBS / MBS content attacks.** No cell-broadcast *service* attack; the only
mentions are a detection note (`modules/11_gsm_attack.sh:211`) and MBMS GTP-U IE
names (`modules/15_lte_core.sh:1113`).

**13. ANDSF / Hotspot 2.0 (Passpoint) / LWA convergence.** `52_wifioff` claims LWA
but prints constants; ANDSF and Passpoint are absent entirely.

**14. SIM box / IRSF / grey-route fraud.** Zero hits for `irsf`, `sim box`,
`grey route`. A nationally significant fraud class whose signature is entirely
protocol-analysable, and which sits naturally beside the existing
`--cdr-fraud-check` (`modules/15_lte_core.sh`).

**15. 5G RedCap / NR-Light and NR-U (unlicensed NR).** Absent.

**16. Charging abuse via N4/UPF URR.** `15_lte_core` has GTP-CDR fraud detection;
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
| `51_lpp` | ~~Implement `--detect-forgery` for real **or** relabel it handoff.~~ **DONE — relabelled to a §9 handoff.** It no longer fabricates a result. |
| `19_downgrade` | ~~Write the SIB1/`cellBarred` encoder the module's header already advertises.~~ **DONE — `dng_forge_sib1` + `dng_sib1_payload`, `sib1-*` assertions.** |
| `12_umts_air` | ~~Write the NodeB plan file the header promises, or correct the header.~~ **Stale item — no action needed.** The header promises no plan file; it already satisfies §9 by naming the hardware ("the only handoff is actually transmitting or intercepting a NodeB, which names its hardware"). The module has no `--plan` verb and needs none, being pure computation. |
| `50_iot` | ~~Add `--plan` and an `Attack owned:` line so its scope is declared.~~ **DONE.** |
| `16_nr_air` | ~~Remove or use `NAIR_PLAN_DIR`.~~ **DONE — removed.** |
| `59`/`60` | ~~Build the 8 `probe`-class frame constructors or relabel them `handoff`.~~ **DONE — 2 cases added to `bexp_l2_cases`; `nrj_probe_ctor`/`nrj_probe_frame` resolve all 8.** |
| Docs | ~~`OFFENSIVE_ROADMAP.md:39`, `TOOLKIT_REFERENCE.md:148`: `IMSI mod 1024` → `1000`.~~ **DONE.** |

**Validate by:** the module's own selftest, plus `tools/run-selftests.sh` green.

### Phase 1 — Crypto core completion (pure computation, published KATs)

**Milenage + TUAK** into `tools/gsm_crypto.py`, alongside the COMP128-1/2/3 that
already lives there. Assert against **TS 35.208** test sets and **TS 35.231/35.232**
for TUAK — the tree's own §16 standard, so this phase has the strongest proof
available anywhere in the list.

Then **A5/1 time-memory-tradeoff**: implement the table-lookup interface and
validate the state transition against the two published A5/1 vectors already
asserted in `gatk_kat_suite` (BGW and libosmocore). Note honestly that the 2^54
search itself is not runnable here, so this ships as the *lookup* half.

**Unblocks:** 5G-AKA / EAP-AKA' (`17_nr_core`, `41_vowifi`), IMP4GT (`35_volte_ims`),
fake authentication in every rogue-BTS module (`11`, `13`, `14`, `16`),
`23_cipher_audit`'s algorithm tables.

**Size:** M. **Validate by:** published vectors, no hardware.

### Phase 2 — The no-SDR attack surface

This is the only high-value work that can be *proved* without a radio.

| Item | Where | Notes |
|---|---|---|
| **QCDM / DIAG / AT / NV-EFS** | new module (nb. `61_baseband_diag`) | DIAG framing, NV/EFS read-write, IMEI surface, AT command handling, baseband log decode. New dep: `pyserial`. Needs a cable, not an SDR. |
| **TS 23.040 TP layer + Type-0 silent SMS** | extend `46_ota_sms` | TP-MTI / TP-PID / TP-DCS encode+parse, delivery-report handling. Natural sibling of the TS 23.048 work already there. |
| **DPA side-channel model** | alongside `20_sim` | Trace→Ki correlation for COMP128; the APDU layer it needs already exists. |

**Size:** L for DIAG, S for the TP layer, M for DPA.
**Validate by:** a USB-attached modem; a loopback SMSC; a capture rig.

### Phase 3 — The emitter layer (one decision, eight modules)

Eight modules are print-only for the same reason: the builders exist, the
transport does not. `60_nr_inject` already demonstrates the pattern —
`NRJ_TX_CMD` plus a `--tx-ack` gate — and `11_gsm_attack`'s `--tx-ack` is the
legal-position template. **Generalise it, do not re-implement it eight times.**

First four clients, in this order (easiest proof first):

1. **`32_cellular_dns` pcap rewriter + GTP-U re-encapsulation.** *Pure software,
   no radio at all* — rewrite a captured pcap, recompute inner IP/UDP checksums,
   re-encapsulate the G-PDU, and diff the result. This is the aLTEr demonstration
   without a transmitter, and it is fully testable today.
2. **`31_ss7_map`** — drive the encoded MSUs at a local `osmo-stp`. Lab-reachable.
3. **`15_lte_core`** — SCTP/GTP-C client against a local Open5GS. Four finished
   builders cannot currently be exercised even with a testbed.
4. **`17_nr_core` / `45_sba_pivot`** — HTTP/2 client against a local free5GC.
   `45_sba_pivot` already encodes the frames.

**Size:** M for the shared interface, S–M per client.
**Validate by:** a local testbed (`osmo-stp`, Open5GS, free5GC) — all of which the
tree already names in its own plan files.

### Phase 4 — Radio-gated offensive build-out

Build to the boundary; each stays `status: handoff` until someone fires it.

| Item | Module |
|---|---|
| GSM radio driver — GMSK modulation + TS 45.003 channel coding + burst TX | `11_gsm_attack` (the missing half of the work just completed) |
| **PWS / ETWS / CMAS** encode + detect | `14_lte_air` (decoder exists), `16_nr_air` (nothing) |
| **UMTS rogue NodeB (O1 for 3G)** | `12_umts_air` |
| Paging transmitter (Torpedo / Piercer TX) | `33_paging_track` — `pgt_tx_paging` is already the honest-fail stub |
| IMP4GT identity-mapping state machine | `35_volte_ims` |

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
- **`51_lpp`:** implement, or delete the module?
- **PWS/ETWS:** encode-and-detect only (the `38_jamming_detect` treatment), or
  encode plus a gated injector (the `37_nas_signaling` treatment)? A forged
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
  `14_lte_air`'s LTE paging (`UE_ID = IMSI mod 1024`), which **is** correct for
  TS 36.304. Not drift.
- `ATTACK_COVERAGE.md`'s roll-up says "33 modules / 27 attacks" for v0.2, while
  the tree now has 60 modules and the v0.3/v0.5 sweeps are undocumented in the
  docket (`EXPLOIT_SOURCES.md` covers them separately). The coverage table should
  either absorb O21+ or state that it stops at v0.2.
