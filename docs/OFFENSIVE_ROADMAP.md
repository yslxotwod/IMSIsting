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
| **Paging / Torpedo / Piercer** | `28_paging_track` | PF/PO per TS 36.304, the Hussain et al. NDSS 2019 models | TX: paging-occasion collision, the paging storm |

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
| **O12 — IMP4GT** | `30_volte_ims` | Identity-mapping impersonation, the mutual-auth bypass sequence and its preconditions | TX: the impersonation against a lab IMS |
| **IMS registration hijack** | `30_volte_ims` | SIP parse, registration flows | TX: SIP REGISTER spoofing |

### Tracking and RF

| Capability | Module | Built today | Missing to fire |
|---|---|---|---|
| **P6 — RF fingerprinting** | `24_rf_fingerprint` | RMS/PAPR/flatness/DC/IRR, CFO by stated estimator (asserted against injected value), transient shape | RX: IQ from a calibrated radio for absolute dBm and true EVM |
| **P7 — CSI sniffing** | `24_rf_fingerprint` | 802.11 complex matrices, LTE CQI/PMI/RI, phase unwrapping for motion | RX: CSI-capable capture |
| **P8 — paging monitoring** | `28_paging_track` | PO computation per TS 38.304, GSM paging group, paging record parse | RX: IQ |
| **TA geolocation** | `39_ta_geoloc` | TA→range (TS 36.211/38.211), quantisation bound, least-squares trilateration verified against synthetic ground truth | RX: TA measurements from a real cell |
| **LPP position forgery** | `46_lpp` | Procedure codes, header codec, position-forgery detection | TX: the forged position report |

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
| **SIM / APDU** | `16_sim` | ISO-7816 build/parse with real status words, USIM file ids, ICCID/IMSI BCD, EF_AD in both layouts, PIN/PUK state, eSIM RSP, COMP128-1 DPA leakage model with synthetic-trace key recovery | DEVICE for capture: a reader, a SIM you own, a probe and a scope (`--plan dpa-lab`) |
| **OTA binary SMS** | `41_ota_sms` | TS 23.048 Command-Packet construction (SPI, TAR, counter, padding counter), replay decisions per SPI mode | DEVICE: the SIM's KIc/KID — **only your own SIM** |
| **SIM Toolkit / STK** | `52_stk` | TS 31.111 proactive command build/parse (D0 envelope, comprehension-TLVs), silent-command audit | DEVICE |
| **USSD / STK injection** | `38_ussd` | GSM 7-bit packing (E8 34 worked example), MMI/SS parsing, USSD facility build with DCS, injection detector | DEVICE / NET |

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
| **O4 — Diameter attacks** | `11_lte_core` | S6a/S6d AIR/ULR/CLR/IDR/DSR/PUR encode-decode (code table corrected against Wireshark: 316 ULR, 317 CLR, 318 AIR, 319 IDR, 320 DSR, 321 PUR), forged-ULR registration move | An HSS |
| **O2 — GTP exploitation** | `11_lte_core` | GTP-C v2 / GTP-U with extension headers, IE walk, TEID handling | An EPC: SGW/PGW |
| **O19 — PFCP exploitation** | `13_nr_core` | PFCP session establishment, PDR/FAR/QER/URR encode-decode | A UPF |
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

**Phase 2 status — audited, and the audit corrected this document.** The
"4G / LTE" entry above credits `10_lte_air` with "SIB1–5 construction" and
"RRC message construction, handover sequences". That is `status handoff` with
*no code behind it*: the module contains **nine SIB decoders and zero SIB or
RRC encoders**. The nine are `lair_decode_sib1()` (`modules/10_lte_air.sh:339`)
through `lair_decode_sib13()` (`modules/10_lte_air.sh:885`), dispatched at
`modules/10_lte_air.sh:1028-1036`.

Worse, they are **not TS 36.331 PER decoders**. They read a private bit layout
of this tree's own invention, and the module's selftest then validates that
layout against itself — the exact anti-pattern the bar below forbids. The
evidence: a genuine SIB1 encoded by pycrate 0.8.1 and passed to
`10_lte_air --decode-sib 1` yields values that cannot exist in the
specification, and pycrate decoding the SIB2 fixture this tree then carried —
a ten-hex-digit body — reports mandatory fields missing.

What is real in LTE today:
- `10_lte_air --gen-enb-conf` writes usable srsRAN `enb.conf` and `rr.conf`.
- `09_lte_attach --encode-attach` emits a correct EMM ATTACH REQUEST, and its
  `--imsi-encode` / `--imsi-decode` round-trip.
- `27_cellular_dns` builds DNS queries and responses.

What Phase 2 now has to add, in order:
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
   one leaf at a time — agrees bit for bit. SIB4–SIB8 body vectors are
   captured but still to be encoded, and SIB13 does not yet pass pycrate's own
   validation.
2. Replacement of the nine fake decoders with that codec, or an explicit
   statement in their output that they read a private layout. **`--decode-sib
   1`, `--decode-sib 2` and `--decode-sib 3` are done**: `lair_decode_sib1()`,
   `lair_decode_sib2()` and `lair_decode_sib3()` now delegate to
   `tools/lte_asn1.py`, all verified
   against captured pycrate vectors, and all refuse anything that is not the
   SIB they claim rather than reporting fields decoded from the wrong bit
   offsets. The private-layout warning that used to print for SIB2 and SIB3 is
   gone with the parsers that needed it. SIB4–SIB13 still read the old
   private layout, and now say so in their own output.
3. RRC reconfiguration and handover construction, the actual TX path, then the
   same four-point bar Phase 1 was held to.

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

What is still missing above this layer is **layer mapping and precoding**,
**PSS/SSS**, the **PBCH chain** (the 24-bit MIB with its CRC and antenna mask,
tail-biting convolutional coding, rate matching to 1920 bits per frame,
scrambling, and the reserved-element exclusion in its RE mapping), and the
**PDCCH/PCFICH/PHICH and PDSCH** resource mapping that carries anything a UE
would act on. Until those exist `10_lte_air` still has no transmit path, and
criteria 2 and 3 of the four-point bar remain unmet for Phase 2.

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

**Phase 5 — VoLTE/IMS.** `30_volte_ims` (ReVoLTE capture path, IMP4GT,
registration hijack).

**Phase 6 — SIM and device.** `52_stk`, `41_ota_sms`, `16_sim`, `38_ussd`.

**Phase 7 — core network.** `11_lte_core` (GTP, Diameter lab testbed),
`13_nr_core` (PFCP), `40_sba_pivot`.

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
