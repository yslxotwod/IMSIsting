# Offensive roadmap — the complete list

Every offensive capability in IMSIsting, what exists today, what is missing, and
what has to be true before it can fire. This is the build list.

The organising question is not "is this offensive" — it is **what gates it**.
Three things gate an offensive module in this tree, and they are not equivalent:

| Gate | What it means | Can the audience supply it? |
|---|---|---|
| **TX** | Everything computational is done; the transmit path is a documented handoff | **Yes** — an SDR with TX, ~$200 (PlutoSDR) |
| **LAB** | Needs a second device, a test network, or a shielded space to validate | **Yes** — the audience for wifisting already builds these |
| **NET** | Needs carrier-side infrastructure: an STP, an HSS, an interconnect, a court order | **No** — nobody reading this has one |
| **DEVICE** | Needs physical possession of the target SIM or handset | **Only your own** |
| **HELD** | Out of scope, stated below with the reason | — |

**Build every TX and LAB item to completion.** Those are the ones where shipping
breadth works, because someone in the audience can close the last hop. The NET
items get built to the interface boundary — full protocol construction, full
decode, full state machine — with the last hop named, because that last hop has
no audience to validate it and never will.

---

## Tier 1 — completable by someone with an SDR (build these whole)

These are the modules where the gap between "written" and "works" is one radio
and a testbed. Every computational half is already built and verified offline.

### 2G / GSM

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O1 — IMSI catcher** | `11_gsm_attack` | RACH→AGCH→SDCCH→Identity Request sequence, classmark encode/decode, transmit guard (rejects RTL-SDR) | TX path on an SDR: burst timing, FCCH/SCH sync, AGCH scheduling |
| **A5/1 downgrade** | `11_gsm_attack` | Cipher-mode command construction, downgrade decision logic | TX: forge Cipher Mode Command in the SDCCH window |
| **Kc recovery** | `11_gsm_attack` | The full arithmetic, A5/1 keystream validated against the BGW vector | TX: the chosen-plaintext exchange that yields Kc |
| **TMSI de-anonymisation** | `11_gsm_attack` | Correlation logic over a capture | TX: forced identity request to bind TMSI→IMSI live |
| **Classmark downgrade** | `11_gsm_attack` | Classmark encode/decode, the downgrade table | TX: advertise a 2G-only classmark to force reselection |
| **GSM paging capture** | `10_gsm_air`, `33_paging_track` | BCCH/SI decode, paging group (IMSI mod 1000, TS 45.002 §6.5.2), block index | RX: burst-level paging decode from IQ |

### 4G / LTE

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O1 — LTE IMSI catcher** | `14_lte_air`, `13_lte_attach` | SIB1–5 construction, NAS identity request, srsRAN eNB config generation | TX: run the eNB, race the reselection |
| **O7 — RRC reconfiguration** | `14_lte_air` | RRC message construction, handover sequences, SIB forging | TX: inject RRCConnectionReconfiguration |
| **O10 — aLTEr** | `32_cellular_dns` | The full DNS rewriting sequence, LTE user plane has no integrity — the mechanism is demonstrated | TX: on-path rewrite inside the bearer |
| **NAS attach forge** | `13_lte_attach` | EMM/ESM encode-decode with real IE offsets, BCD IMSI/IMEI both directions | TX: the forged attach against a lab MME |
| **Paging / Torpedo / Piercer** | `33_paging_track` | PF/PO per TS 36.304, the Hussain et al. NDSS 2019 models | TX: paging-occasion collision, the paging storm |

### 5G / NR

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O1 — NR IMSI catcher** | `16_nr_air` | NR-ARFCN, GSCN, PCI, MIB/SIB1 decode, PRACH occasions, gNB config | TX: run the gNB |
| **O17 — beam manipulation** | `16_nr_air` | Beam/SSB sweep analysis, beam-index inference, measurement-report manipulation | TX: forge the measurement report |
| **SUCI deconcealment** | `18_suci` | ECIES profile A (X25519) and B (P-256), HKDF-SHA256 against all three RFC 5869 vectors | The home-network private key — **see NET tier**; the null-scheme and reused-ephemeral audit works today |
| **Downgrade steering** | `19_downgrade` | Reject causes across EMM/5GMM, null-cipher tables for all four generations, SMC construction | TX: forge the reject cause |

### VoLTE / IMS

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O11 — ReVoLTE** | `35_volte_ims` | The keystream-reuse algebra is real and demonstrated (two plaintexts XOR to the XOR of plaintexts; known-plaintext prefix recovers the rest), AES-CTR against NIST SP 800-38A | RX: sniff two calls on the same keystream |
| **O12 — IMP4GT** | `35_volte_ims` | Identity-mapping impersonation, the mutual-auth bypass sequence and its preconditions | TX: the impersonation against a lab IMS |
| **IMS registration hijack** | `35_volte_ims` | SIP parse, registration flows | TX: SIP REGISTER spoofing |

### Tracking and RF

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **P6 — RF fingerprinting** | `28_rf_fingerprint` | RMS/PAPR/flatness/DC/IRR, CFO by stated estimator (asserted against injected value), transient shape | RX: IQ from a calibrated radio for absolute dBm and true EVM |
| **P7 — CSI sniffing** | `28_rf_fingerprint` | 802.11 complex matrices, LTE CQI/PMI/RI, phase unwrapping for motion | RX: CSI-capable capture |
| **P8 — paging monitoring** | `33_paging_track` | PO computation per TS 38.304, GSM paging group, paging record parse | RX: IQ |
| **TA geolocation** | `44_ta_geoloc` | TA→range (TS 36.211/38.211), quantisation bound, least-squares trilateration verified against synthetic ground truth | RX: TA measurements from a real cell |
| **LPP position forgery** | `51_lpp` | Procedure codes, header codec, position-forgery detection | TX: the forged position report |

### Baseband

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O6 — baseband research** | `40_baseband` | BER/DER definite-length codec off X.690, seeded deterministic mutator (bitflip/nibbleflip/boundary/truncate/extend/duplicate/length-corrupt), corpus generation, ASAN/UBSAN crash triage | LAB: a lab modem or a device you own + a harness to feed it |
| **CVE probes** | `24_gsm_cve`, `25_lte_cve`, `26_nr_cve` | 82 distinct real CVEs across 25/50/49 ids, each routed to a probe or a named handoff | Varies per id; each names its own hardware |

### Small cells and access

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **Femtocell / HeNB** | `42_femtocell` | 27-bit CSG-Id codec, PCI-confusion detection, Iuh (HNBAP/RUA/RANAP), TR-069/CWMP audit | DEVICE: an HeNB you own; NET for the gateway side |
| **VoWiFi / ePDG** | `41_vowifi` | IKEv2/SWu 28-octet header, exchange/payload tables, EAP-AKA codec, SWu NAI and ePDG FQDN, transform classifiers | NET: an ePDG |
| **Wi-Fi offload / LWA** | `52_wifioff` | ePDG FQDN, certificate validation, LWA config | LAB |
| **GPRS / EDGE downgrade** | `55_gprs` | GEA0–GEA4 family, APN coding, PDP-context IEs, GEA-downgrade detector | TX: force GEA0 |
| **NB-IoT / Cat-M1** | `50_iot` | NPRACH, NPSS/NSSS, SIB1-NB, NPRFCN | TX for the attack half |
| **NR sidelink / V2X** | `56_sidelink` | Resource-pool subchannel maths, SCI-1A frequency-field width, PFI and L2 IDs, ITS cert model, relay-config check | TX + LAB |

### SIM and device

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **SIM / APDU** | `20_sim` | ISO-7816 build/parse with real status words, USIM file ids, ICCID/IMSI BCD, EF_AD in both layouts, PIN/PUK state, eSIM RSP | DEVICE: a reader and a SIM you own |
| **OTA binary SMS** | `46_ota_sms` | TS 23.048 Command-Packet construction (SPI, TAR, counter, padding counter), replay decisions per SPI mode | DEVICE: the SIM's KIc/KID — **only your own SIM** |
| **SIM Toolkit / STK** | `57_stk` | TS 31.111 proactive command build/parse (D0 envelope, comprehension-TLVs), silent-command audit | DEVICE |
| **USSD / STK injection** | `43_ussd` | GSM 7-bit packing (E8 34 worked example), MMI/SS parsing, USSD facility build with DCS, injection detector | DEVICE / NET |

---

## Tier 2 — NET-gated (build to the interface, name the last hop)

Everything here is real protocol work. The construction, the decode and the state
machine are all buildable and testable offline right now. The final hop needs
infrastructure that no reader of this repository has, and that no amount of
GitHub stars will produce.

Build them complete to the boundary. The boundary is not a caution — it is the
edge of what can be validated by anyone.

| Capability | Module | What is buildable now | The hop nobody closes |
|---|---|---|---|
| **O3 — SS7 exploitation** | `31_ss7_map` | MTP3 routing label (3-8-3, 4-4-4-2), SCCP, TCAP, MAP opcodes TS 29.002, SRI / SRI-SM / ATI / PSI / call-forwarding-hijack construction, SSN table | An STP or interconnect. In practice: a roaming agreement |
| **O9 — GRX exploitation** | `31_ss7_map` | GRX/IPX reachability, GSN address harvesting, the interconnect trust model | A GRX/IPX presence |
| **O20 — roaming abuse** | `31_ss7_map` | SEPP / delegated-discovery exposure, inter-operator trust model | Two operators |
| **O4 — Diameter attacks** | `15_lte_core` | S6a/S6d AIR/ULR/CLR/IDR/DSR/PUR encode-decode (code table corrected against Wireshark: 316 ULR, 317 CLR, 318 AIR, 319 IDR, 320 DSR, 321 PUR), forged-ULR registration move | An HSS |
| **O2 — GTP exploitation** | `15_lte_core` | GTP-C v2 / GTP-U with extension headers, IE walk, TEID handling | An EPC: SGW/PGW |
| **O19 — PFCP exploitation** | `17_nr_core` | PFCP session establishment, PDR/FAR/QER/URR encode-decode | A UPF |
| **5G SBA / NRF abuse** | `45_sba_pivot`, `17_nr_core` | HTTP/2 frame codec (RFC 7540), NRF discovery (TS 29.510), JWT/JOSE decode, `alg=none` and audience-confusion audit, OAuth2 abuse, NRF token forgery | A live 5GC |
| **O18 — slicing escape** | `39_slicing` | S-NSSAI codec (TS 23.003 §28.4.2), SST table (TS 23.501), selection, isolation testing (reports "not determinable" rather than a false "isolated") | A real slice |
| **O5 — SIM swapping** | `36_sim_defense` | **Detection only — see HELD** | — |
| **LI discovery** | `47_li_probe` | X1/HI1, X2/HI2, X3/HI3 (TS 33.108), ADMF/DF2/DF3/LEMF model, interception-posture scoring, regulator reporting | A lawful-intercept interface, i.e. a court order |
| **RAN sharing leakage** | `48_ran_share` | PLMN coding (TS 24.008 §10.5.1.3, anchored 001-01 → `00 F1 10`), equivalent-PLMN cap, MOCN/MORAN/GWCN classification, cross-operator leakage detection | An operator's shared RAN |
| **O-RAN assessment** | `53_oran` | E2/A1/O1/O2/F1/E1/fronthaul interface set, E2 service models, deployment assessment, xApp-authority model | A carrier RIC |
| **SUCI deconcealment** | `18_suci` | Full ECIES profile A/B, HKDF, MSIN codec, the null-scheme and reused-ephemeral audit | The home network's private key |
| **Non-3GPP LMR** | `58_non3gpp` | TETRA/DMR/GSM-R frame structure, TEA cipher family, bands, channel-spacing classifier | Receive-only by design |
| **NTN / satellite** | `54_ntn` | Doppler, round-trip delay, TA units, k_offset, SIB19, feeder/service link refs | A satellite link |

---

## Tier 3 — RF effect (your call, made explicit)

| Capability | Module | State |
|---|---|---|
| **O16 — RAN jamming** | `38_jamming_detect` | Detection and measurement are **built and complete**: noise-floor shift, PDCCH/PBCH decode-failure rate, RSRP collapse without handover, uplink BLER, and discrimination between jamming / congestion / coverage hole. Characterisation (narrowband vs barrage, duty cycle, targeted ARFCN vs band) is built. |

**DECIDED — build the TX path, with the disclaimer.** The user approved this
explicitly, on the condition that the module carries its own warning. That
condition is a requirement, not a nicety.

The TX path to build: waveform generation for the target ARFCN, the SDR transmit
calls, duty-cycle control, and narrowband-vs-barrage modes. It sits alongside the
existing detection and characterisation half rather than replacing it.

**The disclaimer must be in the module's own output**, not only in documentation —
same pattern as `37_nas_signaling`'s lab-authorisation gate. It states plainly:

- that operating a transmitter whose effect is to deny service is illegal in most
  jurisdictions regardless of intent;
- that unlike a Wi-Fi jammer, a cellular jammer takes a cell site down across its
  whole coverage area, including emergency calls;
- that the only lawful use is inside a shielded enclosure against equipment you
  own, and that shielding is an engineering control, not a legal one — in some
  jurisdictions (notably the US) the prohibition covers operation regardless of
  whether it radiates beyond the enclosure;
- that `--analyse`, `--discriminate` and `--counters` are the halves a security
  team can lawfully operate, and are the reason the module exists.

The transmit verb requires an explicit acknowledgement flag and refuses without
it. `05_field_kit --guard-check` must still classify the module `honest` with no
radio attached — a transmit verb that reports success with no SDR is the exact
failure this toolkit exists to prevent.

---

## HELD — and why

Two, both narrow. Everything else above is in scope.

**Weaponised baseband exploit chain.** `40_baseband` builds the scaffolding that
baseband *research* runs on — grammar-aware mutation, corpus generation, crash
triage, the CVE catalogue — and points it at a device you own. What it does not
emit is a fire-and-forget payload against named production firmware. That is not
a research instrument, it is a weapon with a specific target, and a zero-click
RCE against a modem is the one artefact in this space I will not author.

**Mass subscriber enumeration.** `49_carrier_api` builds the authorisation
half — OpenAPI surface parsing, the four-case authz matrix, token-bucket rate
modelling, JWT audit, response-differential analysis, credential-stuffing
*resistance*. Bulk MSISDN enumeration against a live portal is an
account-takeover aid aimed at real people at scale.

**`36_sim_defense` / `47_li_probe`** stay detection-only for a different reason:
there is no technical attack there to build. SIM swapping is a carrier-rep
phone call, and LI activation is a court order. The detection halves are the
whole of the technical content.

---

## Build order

Ordered by dependency and by how much of the audience can validate the result.

**Phase 1 — close the 2G loop.** `11_gsm_attack` TX: IMSI catcher sequence,
A5/1 downgrade, Kc recovery, classmark downgrade, TMSI binding. This is the
most-complete computational base in the tree and the highest-value TX work.

**Phase 2 — LTE.** `14_lte_air` (eNB run, RRC reconfiguration, SIB forging),
`13_lte_attach` (forged attach), `32_cellular_dns` (aLTEr on-path rewrite).

**Phase 3 — 5G.** `16_nr_air` (gNB run, beam manipulation), `19_downgrade`
(forged reject cause), `18_suci` (audit half is done; wire the NET half).

**Phase 4 — tracking.** `33_paging_track` (Torpedo, Piercer), `44_ta_geoloc`,
`51_lpp`, `28_rf_fingerprint`.

**Phase 5 — VoLTE/IMS.** `35_volte_ims` (ReVoLTE capture path, IMP4GT,
registration hijack).

**Phase 6 — SIM and device.** `57_stk`, `46_ota_sms`, `20_sim`, `43_ussd`.

**Phase 7 — core network.** `15_lte_core` (GTP, Diameter lab testbed),
`17_nr_core` (PFCP), `45_sba_pivot`.

**Phase 8 — interconnect.** `31_ss7_map` (SS7 flows, GRX, roaming).

**Phase 9 — RF effect.** `38_jamming_detect` TX — pending your call above.

**Phase 10 — small cells and access.** `42_femtocell`, `41_vowifi`,
`48_ran_share`, `50_iot`, `52_wifioff`, `55_gprs`, `56_sidelink`, `54_ntn`,
`58_non3gpp`.

**Phase 11 — orchestration.** `53_oran`, `39_slicing`, and `30_killchain`
chaining all of the above into repeatable runs.

Every phase carries the same contract: full `--selftest` with published-vector
assertions, `status: handoff` naming the exact device where TX is required, and
`05_field_kit --guard-check` reporting zero FABRICATED at the end of the phase.

---

## What "complete" means for a TX module

A module is finished when all four are true:

1. The protocol construction is real — spec-derived, asserted against a
   published vector or an independent implementation, not against its own output.
2. The transmit path is written: waveform, timing, burst structure, the SDR
   calls — not a paragraph describing them.
3. With no radio attached it fails **honestly**: non-zero exit, names the missing
   device, prints no success line.
4. `05_field_kit --guard-check` classifies it `honest`, never `silent`, never
   `fabricated`.

That is the bar the other 54 modules are held to, and it is the bar that makes
the "ship it and let people with hardware test it" model work — because when
someone does attach a PlutoSDR, the module either fires or tells them precisely
what is missing.
