
**Phase 10 — small cells and access.** `37_femtocell`, `36_vowifi`,
`43_ran_share`, `45_iot`, `47_wifioff`, `50_gprs`, `51_sidelink`, `49_ntn`,
`53_non3gpp`.

**Phase 11 — orchestration.** `48_oran`, `34_slicing`, and `25_killchain`
chaining all of the above into repeatable runs.

**Phase 12 — the formerly held four.** `35_baseband` (`--transmit`,
`--send-payload`, the DIAG/QCDM and RF submission paths), `44_carrier_api`
(`--enumerate`, `--enumerate-subscribers`), `42_li_probe` (`--activate`,
`--intercept`, `--provision-target`), and the offensive half of `31_sim_defense`.
These were marked out of scope by an earlier revision of this file; that is
reversed, and each module's `scope-no-*` assertion is deleted when its verb is
built, at which point the `TRANSMIT`/`status` line stops saying "detection only".

The **display names** have already moved, because a name has to describe what the
module does and the offensive half is committed work rather than a question:
`35_baseband` is now *Baseband Fuzzing*, `42_li_probe` *LI Interception*,
`44_carrier_api` *Carrier API Abuse*, `31_sim_defense` *SIM Swap Attack/Defence*.
Until the verb lands the `--status` output is the authority on what is actually
implemented, not the name.

**Phase 13 — the attached phone.** Deferred by request; recorded here so it is
not lost. A handset plugged into the same machine is a **cooperative UE**: a
real modem running a real stack, which is a different instrument from an SDR
and answers questions no SDR in this tree can answer for itself.

What it is for, in the order the value actually falls:

1. **Closing the transmit verification.** Every TX module in the tree ends its
   honest-limit paragraph the same way: gr-gsm decoding a waveform is not a
   handset camping on it. `07_gsm_attack --transmit` builds a real BCCH
   carrier and nothing has ever confirmed a handset accepts it. A phone in the
   room is the only thing that can.
2. **A real capture to decode.** `adb logcat -b radio` prints RRC and NAS
   signalling as text on the device — an independent capture to feed
   `tools/lte_asn1.py` and `09_lte_attach --decode-nas`, rather than only
   vectors this tree generated. It would settle two things currently carried
   as explicit unknowns: the BCCH LAPDm framing question (2-octet versus
   3-octet header), and the three unnamed SIB3 bits at body positions 31..33.
3. **Cell survey without an SDR.** `dumpsys telephony.registry` reports serving
   cell, neighbours, RSRP/RSRQ, ARFCN/EARFCN, TAC, cell identity and MCC/MNC
   natively — the same facts `02_cell_recon` and `04_tower_map` currently
   obtain through `grgsm_scanner` or `cell_search`.
4. **A controlled baseline for `15_downgrade`.** That module forges SIBs to
   push a handset down a generation. On a phone you own,
   `settings put global preferred_network_mode` forces the generation directly,
   which gives the forgery something to be compared against.
5. **A real origin for the network-side modules.** `27_cellular_dns` needs a
   UE-originated IP path (USB tethering is exactly that) and `11_lte_core`
   needs a real attach.
6. **SIM and identity work.** AT over USB serial (`AT+CIMI`, `AT+CSQ`,
   `AT+COPS`, `AT+QENG="servingcell"`) is how `16_sim`, `14_suci`, `38_ussd`
   and `41_ota_sms` already expect to reach a modem.

What is already in the tree, and where it is blind: `56_baseband_diag` already
drives Qualcomm DM/DIAG over `/dev/ttyUSB*`, `/dev/ttyACM*` and `/dev/cdc-wdm*`
— a plugged-in Qualcomm handset *is* one of those devices. `05_field_kit`'s
`fk_probe_tty()` already enumerates `/dev/ttyUSB0`, `/dev/ttyACM0`,
`/dev/ttyUSB1` and `/dev/ttyACM1`. But `09_lte_attach`'s
`latt_find_lte_ue_stack()` only looks for the `srsue`, `srsran` and
`nr-uesoftmodem` binaries, so `--ue-stack` reports `ERROR no LTE UE stack` on a
machine with a working phone attached, and **no file in the tree invokes adb**.

What it is not: not an SDR — it cannot run the GSM transmit path, provide A5/1
keystream, or see a cell it is not camped on. It sees only what its own modem
sees, reports the vendor stack's interpretation rather than a reference
measurement, and on modern retail Android `/dev/diag` is usually not exposed
without root, so DIAG work is most reliable on development boards, older
handsets or USB dongles.

The cheapest first change is not a new module: it is teaching
`latt_find_lte_ue_stack()` and `fk_probe_tty()` that an attached modem counts,
and making adb a first-class transport.

**Phase 14 — the proposed backlog, audited against the tree.** An external
inventory of roughly forty additional attacks was reviewed. Most already have a
home; several are committed to a phase above; two are reversals of a scope line
rather than new work; five are genuinely additive. **None require a new module
number**, and two of the proposed numbers collide.

*Already owned — placement, not construction.*

| Proposed | Home | Note |
|---|---|---|
| Barrage, narrowband, duty-cycle jamming | `33_jamming_detect` | already DECIDED at *Tier 3*; TX path specified there |
| PSS/SSS, PBCH, PUCCH jamming | `38` + `10_lte_air` | new modes; the sequences come from the Phase 2 codec work |
| NR SSB jamming | `38` + `12_nr_air` | `12_nr_air` already builds SSB |
| GPS/GNSS jamming | `38` + `01_radio` | the sync dependency is a `01_radio` question |
| Physical SIM swap, COMP128v1, Milenage, eSIM ES9+ | `16_sim` | APDU build/parse, EF access, DPA, RSP and OTA parse are already built; crypto in `20_gsm_cve` and `tools/gsm_crypto.py` |
| PC/SC transport | `00_deps` | already a declared dependency; hardware paths are `handoff` by contract, not gaps |
| SIMjacker / WIB S@T push | `52_stk` + `41_ota_sms` | `52_stk` builds the `0xD0` envelope and COMPREHENSION-TLVs |
| UMTS IMSI catcher, AKA reflection | `08_umts_air` | the module exists and already does UARFCN, SIB maps, UIA1/UIA2 MAC-I and AKA relay analysis; UMTS *transmit* is the gap |
| 5G AKA linkability | `14_suci` | Phase 3 already says "wire the NET half" |
| TAU/RAU reject builder | `32_nas_signaling` | not `15_downgrade` — `37` is the NAS builder; `19` detects |
| Measurement reports, RLF/RRC release spam, CA/DC | `10_lte_air` | RRC work already in flight |
| PWS / CMAS / ETWS false alert | `10_lte_air` | the SIB codec exists; carries an emergency-services disclaimer like `38`'s |
| GTP-in-GTP, TEID brute force | `11_lte_core` | Phase 7 transport |
| IMS registration hijack | `30_volte_ims` | already named in Phase 5 |
| O-RAN E2/A1/O1, slicing escape, URLLC/TSN | `48_oran`, `34_slicing` | Phase 11 |
| OTDOA/UTDOA/PRS spoofing | `46_lpp` + `10_lte_air` | `46_lpp` owns LPP; PRS is a 36.211 downlink signal |
| MBMS / MooD | `11_lte_core` | hooks present |
| Operator-side SIM swap and portal enumeration | `31_sim_defense`, `44_carrier_api` | **scope reversal**, not placement — see below |

*Two scope reversals, stated as such.* `31_sim_defense`'s header says its
selftest asserts the file contains no port-request template and no dispatchable
verb resembling one; `44_carrier_api`'s says no enumeration verb is exposed and
its selftest asserts that. Phase 12 already commits to building both halves. A
proposal to "move the swap builder into `44_carrier_api`" is therefore not a
filing decision — it is the Phase 12 decision, and those two `scope-no-*`
assertions are deleted when the verbs land, exactly as Phase 12 describes.

*Five that are genuinely additive.*

1. **PRACH jamming, paired with the IMSI catcher.** The only jamming mode here
   that composes with work already in the tree rather than duplicating it: deny
   the genuine cell's access channel and a rogue cell wins by default. It is a
   mechanism, not a modality.
2. **AKA reflection on UMTS.** `08_umts_air` already carries relay analysis;
   this finishes it.
3. **The 5G AKA re-sync oracle.** `14_suci`'s concealment half is built. The
   oracle *is* the attack — without it the module is a privacy feature.
4. **GTP-in-GTP.** Specific, well-defined, poorly tooled, and it lands for free
   once Phase 7 gives `11_lte_core` transport.
5. **The SM-DP+ ES9+ request builder.** The most novel item in the inventory.
   Public offensive eUICC work is close to nonexistent and `16_sim` already
   models RSP profile state to build against.
