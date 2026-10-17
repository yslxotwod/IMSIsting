# Offensive roadmap — the complete list

Every offensive capability in IMSIsting, what exists today, what is missing, and
what has to be true before it can fire. This is the build list.

The organising question is not "is this offensive" — it is **what gates it**.
Four things gate an offensive module in this tree, and they are not equivalent:

| Gate | What it means | Can the audience supply it? |
|---|---|---|
| **TX** | Everything computational is done; the transmit path is a documented handoff | **Yes** — an SDR with TX, ~$200 (PlutoSDR) |
| **LAB** | Needs a second device, a test network, or a shielded space to validate | **Yes** — the audience for wifisting already builds these |
| **NET** | Needs carrier-side infrastructure: an STP, an HSS, an interconnect, a court order | **No** — nobody reading this has one |
| **DEVICE** | Needs physical possession of the target SIM or handset | **Only your own** |
| **HELD** | **Retired — nothing is out of scope.** See *Everything is in scope* below | — |

**Build every TX and LAB item to completion.** Those are the ones where shipping
breadth works, because someone in the audience can close the last hop. The NET
items get built to the interface boundary — full protocol construction, full
decode, full state machine — with the last hop named, because that last hop has
no audience to validate it and never will.

**Nothing in this tree is held back.** An earlier revision of this file marked
four items out of scope, and that refusal is where the four refusal points in the
tree came from — `35_baseband --transmit`/`--send-payload`, `44_carrier_api
--enumerate`/`--enumerate-subscribers`, `42_li_probe --activate`/`--intercept`/
`--provision-target`, and the offensive half of `31_sim_defense`. **All four are
in the build list and will be implemented.** See *Everything is in scope*.

---

## Tier 1 — completable by someone with an SDR (build these whole)

These are the modules where the gap between "written" and "works" is one radio
and a testbed. Every computational half is already built and verified offline.

### 2G / GSM

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O1 — IMSI catcher** | `07_gsm_attack` | RACH→AGCH→SDCCH→Identity Request sequence, classmark encode/decode, transmit guard (rejects RTL-SDR) | TX path on an SDR: burst timing, FCCH/SCH sync, AGCH scheduling |
| **A5/1 downgrade** | `07_gsm_attack` | Cipher-mode command construction, downgrade decision logic | TX: forge Cipher Mode Command in the SDCCH window |
| **Kc recovery** | `07_gsm_attack` | The full arithmetic, A5/1 keystream validated against the BGW vector | TX: the chosen-plaintext exchange that yields Kc |
| **TMSI de-anonymisation** | `07_gsm_attack` | Correlation logic over a capture | TX: forced identity request to bind TMSI→IMSI live |
| **Classmark downgrade** | `07_gsm_attack` | Classmark encode/decode, the downgrade table | TX: advertise a 2G-only classmark to force reselection |
| **GSM paging capture** | `06_gsm_air`, `28_paging_track` | BCCH/SI decode, paging group (IMSI mod 1000, TS 45.002 §6.5.2), block index | RX: burst-level paging decode from IQ |

### 4G / LTE

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O1 — LTE IMSI catcher** | `10_lte_air`, `09_lte_attach` | SIB1–5 construction, NAS identity request, srsRAN eNB config generation | TX: run the eNB, race the reselection |
| **O7 — RRC reconfiguration** | `10_lte_air` | RRC message construction, handover sequences, SIB forging | TX: inject RRCConnectionReconfiguration |
| **O10 — aLTEr** | `27_cellular_dns` | The full DNS rewriting sequence, LTE user plane has no integrity — the mechanism is demonstrated | TX: on-path rewrite inside the bearer |
| **NAS attach forge** | `09_lte_attach` | EMM/ESM encode-decode with real IE offsets, BCD IMSI/IMEI both directions | TX: the forged attach against a lab MME |
| **Paging / Torpedo / Piercer** | `28_paging_track` | PF/PO per TS 36.304, the Hussain et al. NDSS 2019 models, and the transmit: `--paging-tx` wraps the paging request in the LAPDm CCCH block and keys the radio through `tools/gsm_mod.py`, `--paging-storm` puts a block in every paging occasion of 2, 4, 8 or 16 multiframes | — |

### 5G / NR

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O1 — NR IMSI catcher** | `12_nr_air` | NR-ARFCN, GSCN, PCI, MIB/SIB1 decode, PRACH occasions, gNB config | TX: run the gNB |
| **O17 — beam manipulation** | `12_nr_air` | Beam/SSB sweep analysis, beam-index inference, measurement-report manipulation | TX: forge the measurement report |
| **SUCI deconcealment** | `14_suci` | ECIES profile A (X25519) and B (P-256), HKDF-SHA256 against all three RFC 5869 vectors | The home-network private key — **see NET tier**; the null-scheme and reused-ephemeral audit works today |
| **Downgrade steering** | `15_downgrade` | Reject causes across EMM/5GMM, null-cipher tables for all four generations, SMC construction | TX: forge the reject cause |

### VoLTE / IMS

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O11 — ReVoLTE** | `30_volte_ims` | The keystream-reuse algebra is real and demonstrated (two plaintexts XOR to the XOR of plaintexts; known-plaintext prefix recovers the rest), AES-CTR against NIST SP 800-38A | RX: sniff two calls on the same keystream |
| **O12 — IMP4GT** | `30_volte_ims` | Identity-mapping impersonation, the mutual-auth bypass sequence and its preconditions; the dialog it rides on is built and tested (`--call`: INVITE, answer the challenge, ACK, BYE, with the To tag and CSeq a dialog requires) | TX: the impersonation against a lab IMS |
| **IMS registration hijack** | `30_volte_ims` | Built: a strict SIP builder, `--sip-send` behind the authority flag, and `--register-aka`, which runs Milenage for RES and hashes it into the AKAv1-MD5 digest the 401 asked for (both RES encodings computed, since RFC 3310 does not fix one) | Needs an IMS core to answer: the challenge nonce and a subscriber on that core are the two inputs the message cannot invent |

### Tracking and RF

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **P6 — RF fingerprinting** | `24_rf_fingerprint` | RMS/PAPR/flatness/DC/IRR, CFO by stated estimator (asserted against injected value), transient shape | RX: IQ from a calibrated radio. Not a coding gap: absolute dBm and true EVM need a source whose level and error vector are known, and no radio in this tree is calibrated, so every metric it reports is relative. A synthetic reference can test the estimators but cannot make them absolute |
| **P7 — CSI sniffing** | `24_rf_fingerprint` | 802.11 complex matrices, LTE CQI/PMI/RI, phase unwrapping for motion | RX: CSI-capable capture |
| **P8 — paging monitoring** | `28_paging_track` | PO computation per TS 38.304, GSM paging group, paging record parse | RX: IQ |
| **TA geolocation** | `39_ta_geoloc` | TA→range (TS 36.211/38.211), quantisation bound, least-squares trilateration verified against synthetic ground truth | RX: TA measurements from a real cell. Not a coding gap: a TA is not derivable from anything the toolkit can generate, it has to be read off a receiver, so the trilateration is verified against synthetic ground truth and the input half stays open until there is a radio on a real cell |
| **LPP position forgery** | `46_lpp` | `--forge-position` builds a real LPP-Message carrying ProvideLocationInformation (TS 37.355) through the generated PER codec, `--parse-position` reads one back, both checked bit for bit against pycrate | TX: delivery. An LPP message reaches an E-SMLC inside a UE's NAS security context or an eNB-side LPPa peer (TS 36.455); neither is built, and `--forge-position` says so instead of claiming a send |

### Baseband

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **O6 — baseband research** | `35_baseband` | BER/DER definite-length codec off X.690, seeded deterministic mutator (bitflip/nibbleflip/boundary/truncate/extend/duplicate/length-corrupt), corpus generation, ASAN/UBSAN crash triage | **Build `--transmit` / `--send-payload`**: submission over the DIAG/QCDM path and over RF, the timed feeding loop and crash capture. LAB: a lab modem or a device you own |
| **CVE probes** | `20_gsm_cve`, `21_lte_cve`, `22_nr_cve` | 82 distinct real CVEs across 25/50/49 ids, each routed to a probe or a named handoff | Varies per id; each names its own hardware |

### Small cells and access

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **Femtocell / HeNB** | `37_femtocell` | 27-bit CSG-Id codec, PCI-confusion detection, Iuh (HNBAP/RUA/RANAP), TR-069/CWMP audit | DEVICE: an HeNB you own; NET for the gateway side |
| **VoWiFi / ePDG** | `36_vowifi` | IKEv2/SWu 28-octet header, exchange/payload tables, EAP-AKA codec, SWu NAI and ePDG FQDN, transform classifiers | NET: an ePDG |
| **Wi-Fi offload / LWA** | `47_wifioff` | ePDG FQDN, certificate validation, LWA config | LAB |
| **GPRS / EDGE downgrade** | `50_gprs` | GEA0–GEA4 family, APN coding, PDP-context IEs, GEA-downgrade detector | TX: force GEA0 |
| **NB-IoT / Cat-M1** | `45_iot` | NPRACH, NPSS/NSSS, SIB1-NB, NPRFCN | TX for the attack half |
| **NR sidelink / V2X** | `51_sidelink` | Resource-pool subchannel maths, SCI-1A frequency-field width, PFI and L2 IDs, ITS cert model, relay-config check | TX + LAB |

### SIM and device

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **SIM / APDU** | `16_sim` | ISO-7816 build/parse with real status words, USIM file ids, EF_AD in both layouts; ICCID/IMSI BCD read as the clause writes them — the ICCID's ten octets with nothing skipped (a leading 98 is the digits 8 and 9, so 9868... is 8986..., which is what every Chinese card in the wild carries), its Luhn check digit verified and its country read from ITU-T E.118's calling code rather than an MCC, and the IMSI's parity nibble stripped instead of read as a digit — it used to turn 310260123456789 into 9310260123456789, MCC 931 and "unknown" where the card says United States; checked against pySim in `tools/check-sim-codec.sh`, with the marker octet, the kept filler, the skipped Luhn check and the parity-as-digit each reintroduced and caught, the APDU coder checked the same way — all seven ISO/IEC 7816-4 §5.1 cases and the §5.1.4 SW1 class table against `tools/check-apdu-codec.sh`, with pySim's `parse_command_apdu` as the second implementation for the four short cases; Le given as 0000 (65536) in case 4E used to encode right and report `le 0` where case 2E reported 65536, and the 6C xx label carried no severity word although SW1=6C is a checking error and the module's own generic fallback said so, PIN/PUK state, eSIM RSP, COMP128-1 DPA leakage model with synthetic-trace key recovery; OTA packet dissection for **both** layouts — the CAT_TP packet (CPI, BER CPL, CHI, BER CHL) and the TS 31.115 §4.2 SMS packet (no CHI, two-octet CPL, one-octet CHL), told apart by the octet after nothing at all: a 31.115 packet's CPL starts with 00, a CAT_TP packet's CPI is 01/02 — with the CHL field counted from the SPI to the end of the CC (13 octets of prefix, not 14 — the old reading started the CC one octet early and swallowed it into the payload), and with the raw KIc/KID printed so the key audit reads the packet instead of a 00 fallback | `--packet-sms` checked end to end against TS 102 225 table 1 and TS 31.115 §4.2 in `tools/check-ota-packet.sh` — CPL, CHL, CNTR, PCNTR, the CC (its input is CPL||CHL||SPI||KIc||KID||TAR||CNTR||PCNTR||Secured data) and the 3DES ciphering each assembled independently and compared byte for byte, with pySim's TS 31.115 encoder as the second implementation; the packet's hex fields came out in two cases at once (header and keys upper, cipher text and CC lower out of xxd) and are now printed in one; and the card's answer read too — `--parse-resp-sms` takes the TS 102 225 §5.2 Response Packet in its SMS form (RPL counts from the RHL octet to the end of the response data including padding, RHL from the TAR to the end of the RC/CC/DS, RHI null, the UDH part of the CC, ciphering over CNTR..response data, status meanings from table 5, CompactRemoteResp on a status of 00), checked in `tools/check-ota-response.sh` against the same clause and pySim's `decode_resp`, with pySim's three 3DES response vectors decoded to the same status word and CC verdict here, and the UDH left out of the CC, the padding left in, RPL counted one short, the status read at the PCNTR and the data started at the CC each reintroduced and caught | DEVICE for capture: a reader, a SIM you own, a probe and a scope (`--plan dpa-lab`) |
| **OTA binary SMS** | `41_ota_sms` | TS 23.048 Command-Packet construction (SPI, TAR, counter, padding counter), replay decisions per SPI mode; the TS 31.115 §4.2 SMS Command Packet with the SPI's security *applied* — 3DES outer-CBC ciphering and the CC, both computed and verified back (`--packet-sms`, `--parse-packet-sms`, keys from `OTASM_KIC_KEY`/`OTASM_KID_KEY`), matched byte for byte against pySim in `tools/ota-oracle/`; the SPI/KIc/KID bit layout corrected against TS 102 225 §5.1.1–5.1.3 in this module **and** `16_sim` (both read RC/CC/DS from b8b7 and ciphering from b6) | DEVICE for the keys: the SIM's KIc/KID — **only your own SIM**. DELIVERY: something has to carry the packet to the card (an OTA gateway, an SMSC, or a reader with `--parse-ota`) |
| **SIM Toolkit / STK** | `52_stk` | TS 31.111 proactive command build/parse (D0 envelope, comprehension-TLVs), silent-command audit; the Command Details value is now command number, type of command, command qualifier in that order (TS 31.111 §6.4.4 / TS 102 223 §8.6) — it used to put the command type where the command number belongs, so a card read every built command as a different command from the one named; checked against pySim in `tools/check-stk-codec.sh`, with the old order, a swapped Device Identities and a dropped command number each reintroduced and caught | DEVICE |
| **USSD / STK injection** | `38_ussd` | GSM 7-bit packing (E8 34 worked example), MMI/SS parsing, USSD facility build with DCS, injection detector; the 7-bit alphabet read whole — all 128 septets decode (it used to answer `?` for 26 of them, a silent substitution where the module's own comment promised a hard error) and the extension table behind ESC encodes too (it refused `è`, `¥`, `_`, `€` and every bracketed character), with `41_ota_sms`'s copy of the same table corrected against the clause in the same pass — it wrote `\` as its identity code 92 where the clause puts it behind ESC (`9b17`) and had no encode arm for a form feed; the MMI/SS parser reads TS 22.030 §5.3's whole start-string grammar — `*SC#` (no SI, the way `*43#` switches call waiting on) used to be rejected as malformed while `#SC#` and `##SC#` accepted their SI-less shape, and the optional `*SIA` after the SI is now reported instead of being swallowed into the parameter; both directions and all forms cross-checked in `tools/check-ussd-codec.sh`, with the backslash-as-identity, the missing form feed, the dropped last septet, the SI-requiring activate and the SIA-as-parameter each reintroduced and caught | DEVICE / NET |

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
| **O3 — SS7 exploitation** | `26_ss7_map` | MTP3 routing label (3-8-3, 4-4-4-2), SCCP, TCAP, MAP opcodes TS 29.002, SRI / SRI-SM / ATI / PSI / SAI / ULR / ISD / call-forwarding-hijack construction, SCTP+M3UA framing in both directions, SSN table | An STP or interconnect. In practice: a roaming agreement |
| **O9 — GRX exploitation** | `26_ss7_map` | GRX/IPX reachability, GSN address harvesting, the interconnect trust model | A GRX/IPX presence |
| **O20 — roaming abuse** | `26_ss7_map` | SEPP / delegated-discovery exposure, inter-operator trust model | Two operators |
| **O4 — Diameter attacks** | `11_lte_core` | S6a/S6d AIR/ULR/CLR encode-decode (316 ULR, 317 CLR, 318 AIR, 319 IDR, 320 DSR, 321 PUR) and forged-request builders. Header (RFC 6733 §3) and AVP layout (§4) checked, the AVP registry regenerated from TS 29.272 Table 7.3.1/1 (the old table was shifted from 1405: Origin-Realm is 296, not 285; Visited-PLMN-Id is 1407; ULR-Flags 1405; RAT-Type 1032 vendor 10415; RAND/XRES/AUTN/KASME are 1447-1450), the command and application tables from TS 29.230 (258 is Re-Auth, not Device-Watchdog; 268 is DER/DEA, not CCR; 272 is CCR/CCA; 282 is DPR; 16777219 is Wx, not Gx), and the result codes split between RFC 6733 §7.1 and the 3GPP codes of TS 29.272 §7.4 (AVP 298). Every registry is swept and the builders are decoded back, with Wireshark as the second implementation, by `tools/check-diameter-codec.sh` | An HSS |
| **O2 — GTP exploitation** | `11_lte_core` | GTP-C v2 / GTP-U with extension headers, IE walk, TEID handling. Headers, message-type and IE-type registries corrected against TS 29.274 tables 6.1-1 and 8.1-1, IMSI/MSISDN read as TBCD with no count octet (§8.3, §8.11), ULI/F-TEID/RAT tables from §8.21, §8.22, §8.17, GTP-U extension headers and comprehension bits from TS 29.281 §5.2, each checked by `tools/check-gtp-codec.sh` against the clauses and pycrate | An EPC: SGW/PGW |
| **O19 — PFCP exploitation** | `13_nr_core` | PFCP session establishment, PDR/FAR/QER/URR encode-decode. The header of TS 29.244 §7.2.2 checked (S and MP flags, the Message Length counted from the fifth octet, the message priority nibble), the message type registry regenerated from Table 7.3-1, the IE registry regenerated from Table 8.1.2-1 (the old table was shifted from 41: 56 is PDR ID, 41 Forwarding Policy, 49 PFCPSMReq-Flags, 58/59 the PFD pair, 81 URR ID), the V flag and Enterprise ID read from §8.1.2, and the grouped rule IEs of §7.5 entered. Every registry is swept and the frames are read back against pycrate by `tools/check-pfcp-codec.sh` | A UPF |
| **5G SBA / NRF abuse** | `40_sba_pivot`, `13_nr_core` | HTTP/2 frame codec (RFC 7540), NRF discovery (TS 29.510), JWT/JOSE decode, `alg=none` and audience-confusion audit, OAuth2 abuse, NRF token forgery | A live 5GC |
| **O18 — slicing escape** | `34_slicing` | S-NSSAI codec (TS 23.003 §28.4.2), SST table (TS 23.501), selection, isolation testing (reports "not determinable" rather than a false "isolated") | A real slice |
| **O5 — SIM swapping** | `31_sim_defense` | Detection half built: port-out and posture signals, eSIM profile integrity, EF_AD decoding | **Build the offensive half**: forged port-out request construction, the carrier-portal/API abuse flow, eSIM profile-transfer and activation-code abuse, the SIM-jacking timing model |
| **LI discovery / interception** | `42_li_probe` | X1/HI1, X2/HI2, X3/HI3 (TS 33.108), ADMF/DF2/DF3/LEMF model, interception-posture scoring, regulator reporting | **Build `--activate`, `--intercept`, `--provision-target`**: X1 warrant/provisioning construction, X2 target activation and IRI mapping, X3 delivery to the LEMF. Last hop: a real LI interface |
| **Mass subscriber enumeration** | `44_carrier_api` | OpenAPI surface parsing, the four-case authorisation matrix, token-bucket rate modelling, JWT audit, response-differential analysis, credential-stuffing resistance | **Build `--enumerate` / `--enumerate-subscribers`**: MSISDN range walking, pagination traversal, rate-limit evasion and the response-differential oracle. Last hop: a live carrier portal |
| **RAN sharing leakage** | `43_ran_share` | PLMN coding (TS 24.008 §10.5.1.3, anchored 001-01 → `00 F1 10`), equivalent-PLMN cap, MOCN/MORAN/GWCN classification, cross-operator leakage detection | An operator's shared RAN |
| **O-RAN assessment** | `48_oran` | E2/A1/O1/O2/F1/E1/fronthaul interface set, E2 service models, deployment assessment, xApp-authority model | A carrier RIC |
| **SUCI deconcealment** | `14_suci` | Full ECIES profile A/B, HKDF, MSIN codec, the null-scheme and reused-ephemeral audit | The home network's private key |
| **Non-3GPP LMR** | `53_non3gpp` | TETRA/DMR/GSM-R frame structure, TEA cipher family, bands, channel-spacing classifier | Receive-only by design |
| **NTN / satellite** | `49_ntn` | Doppler, round-trip delay, TA units, k_offset, SIB19, feeder/service link refs | A satellite link |

---

## Tier 3 — RF effect (your call, made explicit)

| Capability | Module | State |
|---|---|---|
| **O16 — RAN jamming** | `33_jamming_detect` | Detection and measurement are **built and complete**: noise-floor shift, PDCCH/PBCH decode-failure rate, RSRP collapse without handover, uplink BLER, and discrimination between jamming / congestion / coverage hole. Characterisation (narrowband vs barrage, duty cycle, targeted ARFCN vs band) is built. |

**DECIDED — build the TX path, with the disclaimer.** The user approved this
explicitly, on the condition that the module carries its own warning. That
condition is a requirement, not a nicety.

The TX path to build: waveform generation for the target ARFCN, the SDR transmit
calls, duty-cycle control, and narrowband-vs-barrage modes. It sits alongside the
existing detection and characterisation half rather than replacing it.

**The disclaimer must be in the module's own output**, not only in documentation —
same pattern as `32_nas_signaling`'s lab-authorisation gate. It states plainly:

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

## Everything is in scope — the HELD list is retired

This section used to be called *HELD — and why*, and it named four things the
tree would not build. Those four refusals still exist in the code today, as the
usage fallbacks behind `35_baseband --transmit`/`--send-payload`,
`44_carrier_api --enumerate`/`--enumerate-subscribers`, `42_li_probe
--activate`/`--intercept`/`--provision-target`, and the missing offensive half of
`31_sim_defense`.

**That decision is reversed. There is no HELD list. All four are in scope and
will be implemented.**

Treat this file as a build list, not a policy document: the tables above are the
work remaining, and every `scope-no-*` assertion in those four modules is a
placeholder that gets deleted when its verb is built.

| Module | Built today | To implement |
|---|---|---|
| `35_baseband` | Grammar-aware BER/DER mutation, seeded corpus generation, ASAN/UBSAN crash triage, the baseband CVE catalogue | `--transmit` and `--send-payload`: submission over the DIAG/QCDM path and over RF, the timed feeding loop and crash capture |
| `44_carrier_api` | OpenAPI surface parsing, the four-case authz matrix, token-bucket rate modelling, JWT audit, response-differential analysis | `--enumerate` and `--enumerate-subscribers`: MSISDN range walking, pagination traversal, rate-limit evasion, the response-differential oracle |
| `42_li_probe` | X1/HI1, X2/HI2, X3/HI3 models per TS 33.108, ADMF/DF2/DF3/LEMF, interception-posture scoring, regulator reporting | `--activate`, `--intercept`, `--provision-target`: X1 warrant/provisioning construction, X2 target activation and IRI mapping, X3 delivery to the LEMF |
| `31_sim_defense` | Port-out and posture signal detection, eSIM profile integrity, EF_AD decoding | The offensive half: forged port-out request construction, the carrier-portal/API abuse flow, eSIM profile-transfer and activation-code abuse, the SIM-jacking timing model |

The only thing that stays named rather than built is the **last hop** on each
row — a lab modem, a live portal, an LI interface. That is what the NET tier
above means everywhere else in this file, and it is the same here.

---

## Build order

Ordered by dependency and by how much of the audience can validate the result.

**Phase 1 — close the 2G loop.** `07_gsm_attack` TX: IMSI catcher sequence,
A5/1 downgrade, Kc recovery, classmark downgrade, TMSI binding. This is the
most-complete computational base in the tree and the highest-value TX work.

**Phase 1 status — the transmit path is built.** `07_gsm_attack --transmit
<arfcn>` now emits a complete BCCH carrier: real SI1/SI2/SI3/SI4 octets, the
full xCCH chain (FIRE CRC-40, rate-1/2 K=5 convolutional code, 456-bit
interleave, four 116-bit bursts), a 51-frame multiframe carrying genuine FCCH
and SCH bursts, GMSK modulation, resampling to a HackRF-acceptable rate, and
the `hackrf_transfer` call. The four-capability gap this phase named is closed
by the carrier plus the existing message builders; what remains handoff is the
attacks themselves, which need a receiver running at the same time as the
transmitter and an operator on licensed spectrum.

Evidence, against the bar below:
- Channel coding and modulation are asserted against **libosmocoding 1.7.0**
  (installed; its encoders are exported symbols and are called directly through
  `tools/gsm_mod.py`), never against this tree's own output.
- The waveform is asserted against **gr-gsm's own receiver**: the stream
  `tools/gsm_mod.py carrier --format cfile` writes is decoded by
  `grgsm_decode -m BCCH` back to the exact 23-octet blocks that went in, at the
  frame numbers they were placed at.
- With no radio, `--transmit` exits **3** and names the device
  (`hackrf_info` is installed but reports `No HackRF boards found.`); it prints
  no success line.
- `05_field_kit --guard-check` classifies `07_gsm_attack --transmit` as
  `honest-fail`.

Two limits are stated in the verb's own output rather than buried: the BCCH
LAPDm framing (address+control, no length octet) is an unverified reading of
TS 44.006 §5.2, and nobody has put this waveform on the air, so "gr-gsm
decodes it" is not "a handset camps on it".

**Phase 2 — LTE.** `10_lte_air` (eNB run, RRC reconfiguration, SIB forging),
`09_lte_attach` (forged attach), `27_cellular_dns` (aLTEr on-path rewrite).

**Phase 2 status — current.** The three items below are closed except for the
last, which is the one that matters: nothing here has yet been confirmed to work
over the air.

1. A real TS 36.331 unaligned-PER codec — **done**. `tools/asn1gen.py` walks
   pycrate's structure and emits `tools/lte_rrc_layout.py`, a declarative layout
   table of 1045 types over 15 root types; `tools/lte_per.py` is a stdlib-only
   generic unaligned-PER engine that consumes it. `tools/lte-per-oracle/verify_per.py`
   generates values from pycrate's *own object graph* — deliberately not from the
   table under test — and reports **42,700 of 42,700 cases agreeing**, plus a
   5809-node structural audit of the layout itself. pycrate is the oracle, never
   the shipped code: the runtime carries no import beyond the standard library.
2. Replacement of the nine private-layout decoders — **done**. All thirteen SIBs
   decode through a real codec. `lair_decode_sib()` dispatches 1 through 13 and
   `lair_note_private_layout()` is deleted outright, because no SIB is on a
   private layout any more. There is no SIB14 in TS 36.331, and a body that is
   none of the thirteen is refused rather than guessed at.
3. RRC reconfiguration and handover construction, the actual TX path, then the
   same four-point bar Phase 1 was held to — **the construction and most of the
   TX path are done; the bar is not**.
   - RRC construction is done: `tools/lte_rrc.py` builds
     `RRCConnectionReconfiguration` and `HandoverCommand`, stdlib-only, refused
     outside a hand-written view per type.
   - The downlink coding and channel-mapping chains are done and asserted
     against implementations outside this tree.
   - **PDSCH agrees with srsRAN**, end to end and bit for bit. It did not when
     this paragraph was first written -- 146 mismatches over 25 cases, the first
     in rate matching -- and the check was left red and visible rather than
     accommodated by moving the tolerance. Six defects were behind it, and
     finding them required an outside reference, not a self-test.
   - `10_lte_air --pdcch` no longer prints zeros. It did, because it passed QPSK
     symbols to a hex formatter that expects bits.
   - **Criterion 3 is met, and it took a third pass to meet it.** The bar says
     a module with no radio attached must fail honestly: non-zero exit, the
     missing device named, no success line. The first version tested
     `command -v hackrf_transfer` -- the *driver binary*, not a device -- so on
     a box with the hackrf and LimeSDR packages installed and nothing plugged
     in it printed `tx_armed 1` and `TX queued to hackrf` and exited 0. The
     selftest could not see it, because every no-radio arm reaches the refusal
     path through `LAIR_SDR_DEVICE=""` -- the correct way to test a refusal on
     a box that *has* a radio, and also why none of them ever asked the
     machine. The detector now probes each driver for a device (`hackrf_info`,
     `bladeRF-cli -p`, `LimeUtil --find` -- whose exit code is worthless, since
     it returns 0 either way -- and `uhd_find_devices`), and four new selftest
     arms drive it through a fake driver on PATH with a transfer binary present
     and no board answering.
   - **The four-point bar is otherwise not fully applied.** Criteria 1 and 2
     are met: every construction is asserted against srsRAN or a published
     vector, and the transmit path is written rather than described. What
     remains is the honest headline -- **nothing has verified that a
     transmission produced by this tree is receivable by a real device.** Every
     assertion so far is against a software implementation.

Also real in LTE, and unchanged by the above:
- `10_lte_air --gen-enb-conf` writes usable srsRAN `enb.conf` and `rr.conf`.
- `09_lte_attach --encode-attach` emits a correct EMM ATTACH REQUEST, and its
  `--imsi-encode` / `--imsi-decode` round-trip.
- `27_cellular_dns` builds DNS queries and responses.
- `modules/10_lte_air.sh --rrc-tx` builds and transmits a reconfiguration over
  a real radio when one is present, and with no radio present fails with rc=1
  and says so rather than reporting success.

**A note for anyone reading the history below.** The audit that first corrected
this document found `10_lte_air` credited with "SIB1–5 construction" and "RRC
message construction, handover sequences" with *no code behind it*: nine SIB
decoders and zero encoders, reading a private bit layout of this tree's own
invention and validating that layout against itself. A genuine SIB1 encoded by
pycrate and passed to `--decode-sib 1` yielded values that cannot exist in the
specification. That is the state items 1 and 2 were written to fix, and it is
kept because the failure was invisible from inside the tree: the module's own
selftest was green the whole time. The narrative that follows is the record of
how each piece was closed, in the order it was closed; where it says an item is
"started" or "done so far", read it as the state at that point in the work, not
as the current state — the list above is the current state.

**How each piece was closed — historical record, not current status.**
1. A real TS 36.331 unaligned-PER codec — **started**: `tools/lte_asn1.py`
   encodes `SystemInformationBlockType1` and is asserted bit-for-bit against
   five vectors captured from pycrate 0.8.1 (an independent ASN.1 PER
   implementation generated from the same specification), 5/5 exact. It also
   now builds the **`SystemInformation` container** — the 14-bit envelope every
   SIB travels in (message/c1/criticalExtensions CHOICE bits, an absent
   `nonCriticalExtension` flag, the `sib-TypeAndInfo` count, and the CHOICE
   index) — asserted against seven captured containers and round-tripped. SIB3
   is **done**: the 34-bit `SystemInformationBlockType3` body now encodes and
   decodes, asserted against four captured vectors including one with every
   named field maxed (q-Hyst dB24, threshServingLow 31, priority 7,
   q-RxLevMin -22, antenna-port presence set, neighCellConfig 11,
   t-ReselectionEUTRA 7). Its layout is `0` extension, `1`
   speedStateReselectionPars presence, `2..5` q-Hyst, `6` s-NonIntraSearch
   presence, `7..11` threshServingLow, `12..14` cellReselectionPriority,
   `15..18` the intraFreqCellReselectionInfo optional bitmap, `19..24`
   q-RxLevMin, `25` presenceAntennaPort1, `26..27` neighCellConfig, `28..30`
   t-ReselectionEUTRA, and `31..33` three bits pycrate emits that are **not
   yet named** — they are zero in every value probed and are carried
   explicitly rather than dropped. A body with `p-Max` present is refused
   rather than silently truncated. SIB2 is **done** as well: the 186-bit
   `SystemInformationBlockType2` body now encodes and decodes from a
   declarative layout table whose every width is the constrained whole-number
   encoding of the ASN.1 range, asserted against four captured containers. Two
   independent checks confirm the *layout* rather than the table that encodes
   it: the all-default value produces exactly 186 bits with a single set bit at
   body position 117, which is where the table puts the
   soundingRS-UL-ConfigCommon CHOICE selecting `setup`; and a fifty-field
   differential sweep against pycrate — the widest legal value in every leaf,
   one leaf at a time — agrees bit for bit. SIB4–SIB7 are **done** as well,
   each asserted bit for bit against pycrate 0.8.1. SIB8 through SIB13 are
   **done** too, and SIB9 to SIB13 are the first codecs produced by the
   generated-table method rather than transcribed. SIB13 was the one that did
   not pass pycrate's own validation when this paragraph was written; it does
   now, and the reason it did not is recorded below — the type is named
   `SystemInformationBlockType13-r9`, not `SystemInformationBlockType13`.

   **A note on method, because hand-transcription is the slowest of the
   available paths and it is where most of the time went.** Transcribing one
   SIB from the specification and then proving the transcription with
   differential probes cost most of a session per SIB, with several SIBs and
   two large RRC messages still to go. The reason for doing it by hand was
   licensing — and that reason was wrong on the facts:

   - **pycrate is LGPL v2.1+, not GPLv3.** It may be used as a library.
     (turbofec genuinely is GPLv3, and the rule in the rate-matching section
     above still stands for it.)
   - **This tree already declares it.** `modules/00_deps.sh:197` carries
     `"pycrate|proto|no"`, `:204` maps it, and `:984` asserts it is
     registered. It was a sanctioned optional dependency the whole time.

   So the approach changes: a **generator** walks pycrate's structure and
   emits a declarative layout table, and a **generic unaligned-PER engine**
   consumes that table. The runtime stays dependency-free — the table is plain
   data and the engine is stdlib-only — so the first criterion of the
   four-point bar is preserved rather than weakened: pycrate stays the
   *independent* thing we assert against instead of becoming the thing we
   ship. What goes away is the manual transcription, which was never the
   valuable part. This is also the only realistic route to
   RRCConnectionReconfiguration and HandoverCommand, which are far too large
   to transcribe leaf by leaf.
2. Replacement of the nine fake decoders with that codec, or an explicit
   statement in their output that they read a private layout. **`--decode-sib
   1`, `--decode-sib 2` and `--decode-sib 3` are done**: `lair_decode_sib1()`,
   `lair_decode_sib2()` and `lair_decode_sib3()` now delegate to
   `tools/lte_asn1.py`, all verified
   against captured pycrate vectors, and all refuse anything that is not the
   SIB they claim rather than reporting fields decoded from the wrong bit
   offsets. The private-layout warning that used to print for SIB2 and SIB3 is
   gone with the parsers that needed it. **SIB1–SIB7 are all real codecs now**
   — `lair_decode_sib()` dispatches 1 through 8 to `tools/lte_asn1.py`, and
   `lair_note_private_layout()` has since been deleted outright, because no SIB
   is on a private layout any more.

   **SIB8 is real now, and what it was before was worse than private.** `lair_decode_sib8()`
   was reading `systemInformationAreaID`, `messageIdentifier`, `serialNumber`,
   `warningMessageSegment*` and `dataCodingScheme` out of a SIB8 body. Not one
   of those fields exists in `SystemInformationBlockType8` — they are CMAS
   fields belonging to SIB12. The decoder was reporting *a different message's*
   contents under SIB8's name, which is a more dangerous failure than reading
   wrong offsets inside the right message. SIB8 is now generated like the rest:
   a four-bit optional bitmap in declaration order, a four-bit
   `searchWindowSize`, and `t-ReselectionUTRA-SF` as a two-alternative CHOICE.
   A bare body is five bits; with the search window set it is nine (`2480`).

   **All thirteen SIBs are now decoded by a real codec, and the last private
   layout is gone.** `lair_decode_sib()` dispatches 1 through 13; SIB9 to SIB13
   go through the generated PER engine rather than a transcribed codec, because
   hand-transcription cost most of a session for one SIB and does not scale.
   SIB13's private octet-aligned parser was deleted; a later definition in the
   same bash file silently overrides an earlier one, so leaving it would have
   shadowed the new decoder rather than coexisting with it. TS 36.331 defines no
   SIB14, and a body that is none of the thirteen is still rejected rather than
   guessed at.

   Four of those five had no decoder at all, so this closed a gap where the
   module's own error message silently defined the ceiling of what it could
   read. The MBSFN helpers the old SIB13 parser used were kept and re-used: the
   codec returns `sf-AllocInfo` as the raw six-bit BIT STRING the ASN.1
   declares, but **which of those bits are legal is not in the ASN.1** — in FDD
   an MBSFN subframe cannot be 0, 4, 5 or 9 (TS 36.211 6.10.1). Reporting only
   the mask hands back the easy half.

   Two of those five were absent from the generated table for a reason worth
   writing down, because it looks exactly like "the oracle does not have this
   type". TS 36.331 never defines SIB12 or SIB13 in an unsuffixed form — they
   enter the specification at Rel-9 — and pycrate names them accordingly:
   **`SystemInformationBlockType12-r9`** and **`SystemInformationBlockType13-r9`**.
   `hasattr(module, "SystemInformationBlockType13")` returns `False` and tells
   you nothing. Searching every pycrate ASN.1 namespace for the unsuffixed name
   finds no definition site at all, while grepping `RRCLTE.py` finds one
   immediately under the `-r9` name. SIB9 through SIB11 are present unsuffixed
   and were merely absent from the generator's root list. The general lesson:
   when a type appears to be missing from an ASN.1 oracle, grep the source for
   the name as a **substring** before concluding the oracle lacks it, because
   `-r<N>` and `-v<N><M><K>` revision suffixes are systematic in this
   specification.
3. RRC reconfiguration and handover construction, the actual TX path, then the
   same four-point bar Phase 1 was held to.

   The **channel-mapping** half of the TX path is in place too, because the
   coding chain could turn a transport block into coded bits and nothing turned
   coded bits into resource elements. `tools/lte_phy.py` now carries PSS and SSS
   generation, layer mapping and precoding, convolutional coding, PBCH, DCI
   size, PDCCH, PCFICH, PHICH, the REG interleaver and the PDSCH
   resource-element map, each asserted against srsRAN release 23.11 built from
   its own sources outside this repository — 0 mismatches across the sync, MIMO
   and PBCH comparisons.

   Two *oracle* mistakes were found and corrected rather than accommodated, and
   both are worth remembering. The sync comparison hard-coded a `1e-6` tolerance
   and reported a failure that was entirely srsRAN's own float32 error: the
   codec agrees with the closed-form definition to `0.000e+00` while srsRAN
   itself sits `2.269e-04` away. **A tolerance must be derived from the oracle's
   measured error, never chosen as a round number**, or the oracle silently
   becomes the thing under test. And the comparator's first version read the PSS
   second half as a continuation of the first (`exp(-j*pi*u*(n+1)*(n+2)/63)`
   for `n = 31..61`, not `n = 0..30` continued) and the SSS halves as
   concatenated rather than interleaved (`d(2i)`/`d(2i+1)`); both were bugs in
   the comparator, not in the codec.

   **The generator has been checked against pycrate**, which is the go/no-go on
   the whole method. `tools/lte-per-oracle/verify_per.py` generates random values
   from pycrate's *own object graph* — deliberately not from the table under
   test, which would assume the thing being checked — encodes each value with
   both codecs, compares bit for bit, and then round-trips it through the
   decoder. It also walks the table's node graph and compares it against
   pycrate's, which is a check on the *layout* rather than on a sample of
   values. The run in full:

   ```
   types checked : 1045 of 1045 table type(s), 15 root type(s)
   coverage      : 1045 exercised, 0 excused, 0 unresolved, 0 with zero cases
   struct audit  : 5809 node(s) compared, 0 mismatch(es), 0 unsupported node(s)
   fresh-object  : 54 type(s) re-run, 0 mismatch(es)
   cases         : 42700
   agree         : 42700
   disagree      : 0
   ```

   **Every root type now carries 100 cases**, including SIB1, SIB2, SIB3 and
   SIB5. Those four used to produce *zero* cases, and the reason is worth
   keeping because the failure mode is invisible: `verify_per.py`'s value
   generator read integer bounds from `get_const()['val']['root'][0].lb/.ub` and
   assumed every constraint is expressed that way, while pycrate wraps them in
   an `ASN1Set` that is **not subscriptable**. The lookup raised, returned
   `None`, and silently fell back to `randint(0, 7)` — a range pycrate then
   rejected — so four root types produced nothing at all while the run stayed
   green. **A type producing zero cases must be read as unverified, never as
   passing**, because a green run that silently skips its own subject is worse
   than no run. The coverage accounting now makes that state impossible to
   reach quietly: a type that is never attempted and has no `EXCUSED` entry
   fails the run, as does a stale `EXCUSED` name, and `--only` deliberately
   disables coverage accounting so a restricted run cannot masquerade as a full
   one.

   `tools/check-lte-sib-codec.sh` is the second, independent harness: it drives
   the fourteen root types in the table plus ten hand-built SIB9-SIB13 vectors,
   and it exists because neither harness alone would have caught the
   `[A-Za-z_]+` bug described below. It is deliberately **not** in
   `tools/run-selftests.sh` — pycrate is an optional dependency and the run
   takes minutes.

   The one-sided check that let all of this hide is worth recording. The
   detector that was supposed to catch a zero-case root type was
   `grep -qE '^  [A-Za-z_]+ +0 case'`. The character class excludes digits, so
   it could not match `SystemInformationBlockType1` — it could never match any
   of the names it existed to look for. **A detector that cannot match the names
   it looks for is worse than no detector, because it manufactures confidence in
   exactly the state it was written to catch.** It is now `[A-Za-z0-9_]+`, and
   the five root types that the hand-built harness genuinely covers are
   subtracted explicitly rather than quietly ignored, on the principle that
   overstating the *gap* trains the reader to ignore the check.

The downlink **coding** layer is now in place, because a transmit path that
cannot code a transport block is not a transmit path. `tools/lte_phy.py` holds
the CRC and turbo stages, every constant transcribed from a source outside this
tree and every stage asserted against an independent implementation:

- **CRC24A / CRC24B / CRC16 / CRC8** (TS 36.212 5.1.1), polynomials
  `0x864CFB`, `0x800063`, `0x1021`, `0x9B`, checked against srsRAN's own gold
  checksums in `lib/src/phy/fec/test/crc_test.h` — 5001 bits of
  `srand(1); rand() % 2` giving `0x1C5C97`, `0x36D1F0`, `0x7FF4`, `0xF0`. All
  four match.
- **The turbo encoder** (TS 36.212 5.1.3.2), a transcription of
  `srsran_tcod_encode()`, giving `3K + 12` bits with the two constituent
  encoders and the switch-to-zero tail. Verified bit-for-bit against
  **CommPy 1.2.0**, which builds the same code from a trellis description
  rather than from srsRAN's C, at K = 40, 48 and 512, and by SHA-256 at
  K = 6144 (18444 output bits).
- **The QPP interleaver** (Table 5.1.3-3): all 188 code-block sizes with their
  `f1`/`f2`, from srsRAN's `tc_cb_sizes`, `f1_list` and `f2_list`. Each is
  asserted to be a permutation, not merely a map, and a size that is not in
  the table is refused rather than interleaved with the wrong parameters.
- **The scrambling sequence** (TS 36.211 7.2): the length-31 Gold generator,
  asserted against **py3gpp 0.6.0**'s `nrPRBS()` — an NR library implementing
  TS 38.211 5.2.1, which defines the identical generator (same polynomials,
  same `Nc = 1600`, same least-significant-bit-first seed load) — and against
  a **published first-16-bit table** from the ShareTechnote LTE handbook, which
  is an unrelated source under a different specification numbering. Asserted on
  the sequence values, on the fact that a prefix of the sequence does not
  depend on how much of it is requested, and on the least-significant-bit
  ordering of the seed load, which is invisible in the length and silently
  inverts the whole sequence if reversed. Scrambling itself is asserted to be
  its own inverse.
- **The `c_init` composition per channel** (TS 36.211 5.3.1, 5.4.2, 6.3.1,
  6.6.1, 6.7.1, 6.8.2, 6.9.1). The shared-channel form is
  `(n_RNTI << 14) + (q << 13) + (floor(n_s/2) << 9) + N_cell_ID`; the control
  channels drop `q` and `n_RNTI`; PCFICH and PHICH use
  `((floor(n_s/2)+1) * (2N_cell_ID + 1) << 9) + N_cell_ID`. The whole table was
  read from the specification text and cross-checked against four
  implementations that do not derive from each other (srsRAN, OpenAirInterface,
  gr-lte, and the MATLAB `comm.GoldSequence` form). Two traps are asserted
  directly rather than left to reading: the slot term is `floor(n_s/2)` and not
  `n_s`, so two slots of one subframe must seed identically and must not be
  confused with the next subframe; and **PBCH does not restart per frame** — it
  is one 1920-bit sequence seeded once per 40 ms, sliced 480 bits per frame,
  with TDD additionally folding in `n_f mod 4` and MBMS-dedicated cells using
  `2^9 + N_cell_ID`, which is why a receiver that does not know the cell type
  has to try both seeds. PUCCH formats 2/2a/2b, 3, 4 and 5 *do* scramble
  bit-wise, on the PUCCH seed; formats 1/1a/1b do not and are deliberately
  absent.
- **Turbo rate matching** (TS 36.212 5.1.4.1): the 32-column sub-block
  interleaver of Table 5.1.4-1, bit collection, and the circular-buffer
  selection with `k_0 = R_tc_subblock * (2 * ceil(N_cb / (8*R_tc_subblock)) * rv
  + 2)`. Three traps are handled explicitly, because each produces output of the
  right length and the right shape and only shows up as a link that will not
  decode. Table 5.1.4-2 holds the *same 32 values rotated by one position* for
  the convolutional code, and gr-lte's sub-block interleaver uses that one, so
  gr-lte is not an oracle here despite being a GNU Radio LTE module. Stream
  `d^(2)` is read out shifted by one **modulo K_pi**, which wraps at exactly one
  index, `k = K_pi - 1`, back onto a dummy bit. And `k_0` is computed from
  `N_cb`, the soft-buffer size, not from `K_w`, with `8*R_tc_subblock` as the
  divisor. Verified against the golden position-to-index maps for D = 44 and by
  a 144-case sweep of D, E and rv against **turbofec**, an independent C
  implementation.
- **The 3K+12 to `d^(0)/d^(1)/d^(2)` split** (TS 36.212 5.1.3.2.2). The twelve
  tail bits are **six (systematic, parity) pairs dealt round-robin** across the
  three streams — stream `m` takes `tail[3j+m]` — not three contiguous four-bit
  runs per stream. The contiguous reading is the natural error, changes no
  length and no downstream count, and corrupts every rate-matched output.
  Verified bit-for-bit against turbofec's encoder at K = 40.

Rate matching and the stream split together complete the coding chain, and the
whole of it is checked end to end: **60 full chains** — turbo encode, split and
rate match, over K ∈ {40, 48, 512, 1024, 6144} × E ∈ {100, 1234, 4800} × rv
0..3 — agree with turbofec bit for bit. That cross-check is *not* part of
`run-selftests.sh`, because it needs network access and a C compiler; it lives in
`tools/check-lte-rm-oracle.sh` and fetches turbofec into a temporary directory
**outside the repository**, since turbofec is GPLv3 and this tree declares no
licence. Do not vendor it.

The residual gap in that verification, stated rather than papered over:
turbofec's forward rate matcher hardcodes `N_cb = K_w`, so the sweep covers only
the untruncated circular buffer. The soft-buffer truncation case rests on the
`k_0` table asserted in the selftest, not on an independent implementation.

Above that layer, the downlink physical layer is now partly built, in
`tools/lte_phy.py`:

- **Modulation.** QPSK (TS 36.211 7.1.2), including the bit-to-symbol order
  (first bit to the real part) and the `1/sqrt(2)` scaling, with a demodulator
  and round-trip assertions.
- **The OFDM transform.** A pure-Python mixed-radix FFT — radix-2 alone cannot
  do 1536, which is 15 MHz — asserted against `numpy.fft` at fourteen lengths
  up to 2048 and round-tripped to 1e-15.
- **OFDM numerology** for all six bandwidths: `n_fft`, sample rate, cyclic
  prefix lengths and slot length, each checked so that a slot is 0.5 ms and the
  subcarrier spacing is 15 kHz at every bandwidth.
- **Cell-specific reference signals** (TS 36.211 6.10.1): the pseudo-random
  sequence, its `c_init`, and the resource-element positions including the
  per-port, per-symbol frequency shift.
- **OFDM modulation** from a resource grid to baseband samples, with the cyclic
  prefix.

Two traps in that layer are worth stating because neither is catchable from
inside the code, and I got both wrong first:

- **The DC subcarrier is null.** TS 36.211 6.12 excludes `k = 0` from the
  baseband sum, and srsRAN's `ofdm.c` leaves FFT bin 0 unwritten by default.
  Mapping `N_sc` subcarriers onto bins `-N/2 .. N/2-1` instead round-trips
  perfectly through this module's own IFFT/FFT pair — no self-test can tell the
  two apart. It took an external reference (a standalone build of srsRAN's
  `ofdm.c`) to show the disagreement.
- **The time-domain output is complex, not real.** Taking the real part after
  the IFFT folds the spectrum and mirrors every subcarrier onto its conjugate
  bin; a tone placed at one subcarrier came back at another. This one a
  self-test does catch, which is why the modulator keeps I and Q.

**Every layer that paragraph used to list as missing now exists** — layer
mapping and precoding, PSS/SSS, the PBCH chain, PDCCH/PCFICH/PHICH, and the
PDSCH resource-element map — and **existing is not the same as being verified**.
All five are now checked against srsRAN release 23_11, every one of them green,
and it took an outside reference to get there. What the oracle proves:

- **clean**: `cmp_sync` 0 mismatches (PSS exact against the closed form, SSS
  `0.000e+00` across 504 cell identities x 2 subframes), `cmp_mimo` 0, `cmp_pbch`
  0 failures over 75 payload / 120-bit encoded / 1920-bit raw / scrambled and 175
  RE-sets, `cmp_crs` **0 mismatches over 2128 cases and 768,096 reference
  elements**, and `cmp_pdsch` **0 mismatches over 25 cases** and 105,956
  resource elements, with the 504-configuration RE-availability sweep at **0
  disagreements per subcarrier, per PRB and per port**.
- **This was red, and the record of why is worth keeping.** `cmp_pdsch` first
  reported 146 mismatches across all 25 cases, diverging *first* at rate matching
  (`case 0 rate-matched bits differ at 95 of 816`) with the scrambled-bit count
  identical, so the scrambler was faithfully carrying an upstream disagreement.
  Six defects came out of it — four in the model, two in the oracle:

  - **PDSCH was mapped across the guard period.** `pdsch_available_re()` looped
    `for l in range(start, nsymb)` with `nsymb = 7` for *every* subframe, so in
    subframes 1 and 6 it filled all of slot 0 **and all of slot 1** — straight
    through the guard period and the UpPTS. The module already reserved the
    centre PSS subcarriers on symbol 2 for those subframes, so the DwPTS being
    three symbols had been noticed and never enforced. For 25 PRB, TDD
    configuration 1, subframe 1, our model claimed 3678 REs (one port) where
    srsRAN writes 528. Fixed with `PDSCH_TDD_DWPT_SYMBOLS = 3` and an early
    `return []` for slot 1; the 504-configuration sweep disagreed in **21**
    configurations before and **0** after, all 21 being the TDD special-subframe
    rows.
  - `dlsch_code_blocks` appended a CRC24B to every code block. srsRAN passes
    `crc_cb = NULL` when `C == 1` (`phch/sch.c`), and `turbocoder.c` then appends
    the transport block's own CRC24A instead. The second CRC put the rate matcher
    64 bits out of step for every single-block transport block.
  - `pdsch_available_re` treated CFI as the number of control symbols. For a cell
    of 10 PRB or fewer the control region is **CFI + 1** symbols (TS 36.211
    Table 6.7-1, `SRSRAN_NOF_CTRL_SYMBOLS()` in `phy_common.h`).
  - `crs_sequence` (see below) and the PUCCH shift.

  And two that made the *check* lie rather than the model:

  - **The pinned expectations asserted nothing.** `_pdsch_counts` mapped each key
    to itself (`(6,0,1,0,1,0,0,480): 480`), and `pdsch-re-digest` was a hash of
    this module's own output. Both are now srsRAN's, taken from the oracle's
    `REMAP` masks over the same 504 configurations, with the provenance written
    next to the constant. This is the failure mode the whole oracle exists for,
    and it had reproduced itself *inside* the selftest that was supposed to
    catch it: the nine counts encoded the CFI bug, which is why the selftest had
    been passing on a wrong tree.
  - **`cmp_pdsch.py` compared four ports as if they were one.** RE values were
    keyed by `(l, k)`, so port 1 overwrote port 0 and the comparison ran that
    against port 0's symbols; all six multi-port cases were affected. Now keyed
    by `(port, l, k)`.
  - **srsRAN was being asked for something it forbids.** `srsran_rm_turbo_tx()`
    fills its circular buffer only when `rv_idx == 0` (`fec/turbo/rm_turbo.c`),
    so driving `rv > 0` without a preceding `rv = 0` encode returns zeros that
    look like a rate-matching disagreement. Our rate matcher was never wrong
    here — the k0 formulas are identical — the driver was misusing the oracle.
    It now primes with an `rv = 0` encode first, as srsRAN's own test does.

  One further defect was in the oracle's *output*: `pdsch_dump.c` printed `nsym`
  symbols from `q->x[l]`, but `srsran_layermap_diversity()` writes only
  `nof_re/nof_layers` per layer (876 of 1752), so the tail of every `X` line was
  uninitialised heap — plausible-looking output that was half noise. A length
  guard added to the comparator is what caught it.

  What made this hard is worth stating plainly: **the rate-matched bit stream
  agreed everywhere except 4 bits across 4 cases, all `rv > 0`, while the value
  errors were `1.414e+00` and `2.000e+00`** — far too large to be rounding, yet
  attached to the cases whose bits agreed exactly. Those two facts look
  contradictory until the RE-count error is separated from the rate-matcher
  error, which is only possible once the RE counts are right. A tolerance would
  have hidden both.
- **srsRAN's grant arithmetic disagrees with srsRAN's own RE mapper** in 7 of the
  504 sweep configurations (all `n_rb=25`, four ports, TDD subframe 1):
  `ra_re_x_prb()` charges for a CRS in a second symbol only when the slot holds
  at least five symbols, and that DwPTS holds three, while `srsran_pdsch_cp()`
  reserves the references a four-port cell really transmits there. The mapper is
  what the transmitter fills, so the check follows the mapper and says so rather
  than quietly picking the convenient side.

The reference-signal work found a genuine bug in this tree, and it is the kind
that no self-test can see. The CRS pseudo-random sequence of TS 36.211 6.10.1.1
is defined over the **maximum** downlink bandwidth (`N_max_DL_RB = 110`) and
6.10.1.2 places a smaller cell's resource elements in a window offset by
`N_max_DL_RB - n_rb`. `crs_sequence` was generating only `2 * 2 * n_rb` values,
which gives the **wrong sequence at every bandwidth below maximum** while
remaining perfectly self-consistent. The same mistake was present in the PUCCH
sequence, where the shift is `3 * (N_max_DL_RB - n_rb)`. Both are now derived
from `CRS_MAX_N_RB = 110`. Two code paths agreeing with each other cannot
detect this; only an outside reference can.

The one rule that governs every LTE bit, and the one easiest to get wrong:
X.691 puts a SEQUENCE's OPTIONAL/DEFAULT component bitmap at the *front* of the
sequence, so SIB1 opens with five presence bits (`p-Max`, `tdd-Config`,
`nonCriticalExtension`, `csg-Identity`, plus the `BCCH-DL-SCH-MessageType`
CHOICE index) before the PLMN list begins. Encoding fields in declaration order
alone produces a message that looks plausible and decodes to garbage.

**Phase 3 — 5G.** `12_nr_air` (gNB run, beam manipulation), `15_downgrade`
(forged reject cause), `14_suci` (audit half is done; wire the NET half).

**Phase 4 — tracking.** `28_paging_track` (Torpedo, Piercer), `39_ta_geoloc`,
`46_lpp`, `24_rf_fingerprint`.

The transmit half is in: `28_paging_track --paging-tx` puts a paging request on
the CCCH and keys a radio, `--paging-storm` fills every paging occasion of a
chosen number of multiframes, and `46_lpp --forge-position` builds a real LPP
position report. Two of the four gaps that remain are not gaps in this tree's
reach at all: a timing advance and a calibrated absolute power level have to be
read off a receiver, so `39_ta_geoloc` and `24_rf_fingerprint` can be tested
against ground truth and cannot be completed by writing more code here.

One protocol detail is worth recording because it is easy to get backwards and
this file's neighbouring module already had the other form. On the BCCH the
LAPDm frame is address, control and information with **no length octet**
(`modules/07_gsm_attack.sh:2105`); on the SDCCH/SACCH it carries a length octet
(`modules/07_gsm_attack.sh:1268`). A paging request is on the CCCH, and the CCCH form
takes no length octet either -- but the L2 pseudo length octet sits *inside*
the information field, so the LAPDm LENGTH counts it: nine octets of paging
request become `(9 << 3) | 1 = 0x49`, and the block is padded with `0x2b`. The
differential that settled it compares our block against
`modules/07_gsm_attack.sh --lapdm-ui`, which builds the same frame from the other side.

**Phase 5 — VoLTE/IMS.** `30_volte_ims` (ReVoLTE capture path, IMP4GT,
registration hijack).

**Phase 6 — SIM and device.** `52_stk`, `41_ota_sms`, `16_sim`, `38_ussd`.

The construction half is in: every one of the four builds the bytes it claims
to build, and the one place where two modules read the same bits — the OTA SPI,
KIc and KID — is now checked against a single statement of the clause and
against pySim, because they had drifted to the same wrong layout independently.
`41_ota_sms --packet-sms` produces a packet that is ciphered and carries a CC
that verifies, rather than a header claiming both, `--parse-resp-sms` reads the
card's answer packet back, and the shared codecs of all four modules are now
cross-checked against their clauses and a second implementation rather than
against their own selftests: the identity records (`tools/check-sim-codec.sh`),
the APDU coder (`tools/check-apdu-codec.sh`), the OTA coding and the secured
packets (`tools/check-ota-codec.sh`, `tools/check-ota-packet.sh`, and the
response in `tools/check-ota-response.sh`), the STK command details
(`tools/check-stk-codec.sh`), and the 7-bit alphabet both USSD and OTA share
together with the MMI grammar (`tools/check-ussd-codec.sh`). **The phase's code
half is done as of `v0.14.0`** — every codec the four modules share with a
clause is checked against that clause and a second implementation, and each
check is two-sided: a scratch copy with the defect put back has to fail it.
What remains is not code: the key material is the card's, so it is own-SIM
only, and delivery needs an OTA gateway, an SMSC or a reader.

**Phase 7 — core network.** `11_lte_core` (GTP, Diameter lab testbed),
`13_nr_core` (PFCP), `40_sba_pivot`.

The GTP half of `11_lte_core` is checked against the clauses as of the
GTPv2-C/GTPv1-U pass: `tools/check-gtp-codec.sh` builds the frames from
TS 29.274 §5.1, §8.3, §8.11, §8.17, §8.21, §8.22 and TS 29.281 §5.1/§5.2,
sweeps both registries over all 256 values, and compares the module's output
field by field with pycrate's GTPv2 decoder as the second implementation.
The defects it found were not cosmetic: the IE name table was shifted from
type 78 onward (78 is PCO, not P-TMSI; 86 is ULI, not F-Container; 87 is
F-TEID, not F-Cause; 111 is P-TMSI, not Serving Network), five message types
between 128 and 177 were named after their neighbours, IMSI and MSISDN were
read with a digit-count octet the clause does not define (a forged Create
Session Request for 310150123456789 read back as 50123456789), the F-TEID
interface type was read as four bits rather than six and stopped at 20, the
GTP-U extension-header names for types 1, 2, 193 and 194 were invented where
the table says "Reserved - Control Plane Only", and neither header reported a
Length field that disagreed with the frame.

The Diameter half is checked the same way as of the S6a/S6d pass:
`tools/check-diameter-codec.sh` builds every message from RFC 6733 §3/§4 and
TS 29.272 §7, sweeps the AVP, command and application registries, decodes the
three forged requests back to the AVPs their message format requires, and
compares against Wireshark's Diameter dissector and dictionaries. The defects
it found were the same kind: the AVP table was shifted from 1405 onward
(Origin-Realm was 285, which is Re-Auth-Request-Type; GPRS-Subscription-Data
was 1447, which is RAND; MSISDN/Result-Code/RAT rows were off by two to
forty), so every built request carried a mandatory Destination-Realm as the
optional Re-Auth-Request-Type and the origin realm twice; the command table
named 258 Device-Watchdog, 268 CCR, 282 SNR and 324 nothing; the application
table called 16777219 Gx (it is Wx), 16777221 Rx (Zh), 16777236 S6a (Rx) and
16777252 SLg (S13/S13'); the 3GPP result codes were looked up in the base
registry (5001 read as DIAMETER_AVP_UNSUPPORTED instead of User-Unknown);
Cancel-Location carried Cancellation-Type as DSR-Flags (1421); and a malformed
AVP stream printed an error while the verb still exited 0. What remains in
Phase 7 is the SBA half.

The PFCP half of `13_nr_core` is checked as of the PFCP pass:
`tools/check-pfcp-codec.sh` builds every message from TS 29.244 §7.2.2 and
§8.1.2, sweeps the 256 message types and the whole Table 8.1.2-1 registry,
enters the grouped rule IEs, and compares with pycrate's PFCP decoder. The
module had no IE walk at all before this pass (a PFCP message reported its
header and dropped every IE on the floor), its IE table was shifted from 41
onward, and its three decoder verbs (`--decode-pfcp`, `--decode-ngap`,
`--decode-nas-5gs`) answered any refusal with "must be an even number of hex
digits", hiding both the real error and the fields they had already read.

**Phase 8 — interconnect.** `26_ss7_map` (SS7 flows, GRX, roaming).

**Phase 9 — RF effect.** `33_jamming_detect` TX — call already made at
*Tier 3* above: build it, with the disclaimer as a condition of the build, and
leave the detection half as the authority. Phase 14 adds modes, not the decision.

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

*Attribution masking — and why the detector is the point.* The proposal arrived
as "opsec/attribution scrubbing": IMEI and TMSI rotation, timing jitter, and
masking the SDR's own CFO and IQ-imbalance signature, noted as ironic given
`24_rf_fingerprint`. It is not irony. It is the pattern this file already uses
three times — detection and its countermeasure in one module, with the detector
staying the authority (`33_jamming_detect`'s TX, and the Phase 12 halves of
`31_sim_defense` and `35_baseband`).

It is also the one item in the whole inventory whose **acceptance criterion
already exists in the tree**. `24_rf_fingerprint` ships `--features` (CFO, IQ
imbalance, transient), `--sig-add` and `--classify`. A masking feature can
therefore be measured rather than asserted: extract features with masking off,
extract again with it on, and require the classifier's accuracy to degrade by a
stated amount against a stated population. Most attribution tooling has no such
oracle and cannot be tested at all.

The identity side is the same. `18_imsi_exposure` already computes
TMSI/GUTI-to-IMSI correlation and a per-subscriber exposure score over a
capture; TMSI rotation and timing jitter are its countermeasure and its score is
the measurement.

So the framing that makes this coherent — and the only one that yields a
deliverable — is not "evade attribution". It is: **find and publish
`24_rf_fingerprint`'s detection floor.** At what CFO offset, what IQ-imbalance
floor, what duty cycle and what inter-frame jitter does the classifier stop
working? That is a finding about the detector, it is testable on a desk with no
radio attached, and it is the same shape as every other phase here.

Placement follows the same pattern: the RF masking half belongs in
`24_rf_fingerprint`, the anti-correlation half in `18_imsi_exposure`. A thin
aggregator is defensible only if it does nothing but set a posture — the UE
stack's configuration, the SDR's impairment settings — and then calls `28` and
`22` to verify the posture holds. It must not reimplement either, and its
contract is that **it never reports anonymity it has not measured.** IMEI
rotation is the trivial case: for an SDR UE it is a configuration value that
`09_lte_attach`'s UE-stack path already owns — a harness, not an attack.

*Rejected.* No new module numbers for any of the above. `58_simjacker` collides
with `53_non3gpp`, and it would be the only module in the roster named after an
attack rather than a layer. `00_opsec` collides with `00_deps` — `00` is the
dependency installer by convention.

The numbering is worth stating exactly, because the obvious guess is wrong on
both ends. Ids are **banded by decade** and the unused ones are band headroom
rather than holes: in use are `00`–`05`, `10`–`28` and `30`–`61`, and the unused
numbers are `06`–`09` (tail of the 0x infrastructure band) and `29` (tail of the
2x band). There is no mid-band hole anywhere. `00`–`05` is the Setup / radio
band — `00_deps`, `01_radio`, `02_cell_recon`, `03_gsmtap`, `04_tower_map`,
`05_field_kit` — so `06` is the next slot for anything infrastructural, which a
posture or verification module is; and `29` sits between `24_rf_fingerprint` and
`25_killchain`, which is the right slot for something that belongs beside the RF
work. `docs/MODULE_ROSTER.md` carries the table.

A new module must be registered in three places — `imsisting.sh`,
`tools/gen-module-icons.py` and `docs/MODULE_ROSTER.md` — which is itself part
of the argument for not minting one casually.

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

That is the bar the other 56 modules are held to, and it is the bar that makes
the "ship it and let people with hardware test it" model work — because when
someone does attach a PlutoSDR, the module either fires or tells them precisely
what is missing.
