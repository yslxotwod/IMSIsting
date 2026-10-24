# IMSIsting

A GTK4 cellular security toolkit for Linux, with a full CLI behind it. Shell
modules covering 2G/GSM, 3G/UMTS, 4G/LTE and 5G/NR, plus passive analysis over
captures and per-generation CVE kits.

<img width="1196" height="641" alt="image" src="https://github.com/user-attachments/assets/eb755e2e-414e-4132-bf17-15e815aa8c99" />

Every module is a standalone script. The GUI is a view over them, not a
container — nothing is locked behind the interface.

> **Early development, and honest about it.** No module in this tree has been
> run against a real radio. There is no SDR on the machine it was built on, so
> every over-the-air path is written and reviewed but *not* tested. The section
> [What actually works](#what-actually-works) says exactly which is which, and
> it is worth reading before you file a bug.

---

## Why this exists

Cellular tooling is split by layer and by generation. `gr-gsm` is 2G. `srsRAN`
is 4G/5G. `Osmocom` is the stack underneath. Wireshark dissects what you
captured but will not capture it, and none of them share a target view.

This tree is wide on purpose: one desk, one launcher, one place where a cell
survey, a NAS decode, a Diameter message and a cipher audit all land in the
same TSV.

The other thing it does differently: **most tools tell you they worked.** This
one is built to tell you when they didn't. Every module has a `--selftest`, the
hardware-gated ones name the radio they are missing instead of returning an
empty result, and a module that cannot do its job exits non-zero rather than
reporting success.

**No module has an approval gate.** Nothing refuses because a flag or an
environment variable was not set first. The retired `--i-have-a-lab-and-authorisation`,
`--ack-isolated-lab`, `LTE_ARMED`, `NR_ARMED`, `MAP_ARMED`, `FEMT_S1_ARMED`,
`SBA_ARMED`, `BEXP_TX_ARMED`, `NRJ_TX_ARMED` and `JAMD_LAB_AUTHORISED` are
accepted and ignored, so old command lines keep working. `bash modules/00_deps.sh
--preflight` prints the state of the box in one page.

---

## Modules

Fifty-eight modules, grouped by the part of the network they work on. Every verb a
module documents has a control on its page, and every page answers in the card that
asked: a value list for one record, a list of records with per-row Copy for many.

### System
| Module | Description |
|---|---|
| `00_deps` | Inspect the cellular toolchain and install what is missing |
| `01_radio` | Enumerate SDRs, report per-band capability, record IQ |
| `05_field_kit` | RF pre-flight, honesty verification of every radio verb, synthetic GSMTAP source |
| `25_killchain` | Chain module verbs into repeatable, recorded runs |

### Recon
| Module | Description |
|---|---|
| `02_cell_recon` | GSM/LTE/NR cell survey and neighbour discovery |
| `03_gsmtap` | Live GSMTAP feed, header codec, per-type demultiplex to the owning decoder |
| `04_tower_map` | GPS-tagged cell survey with CSV, KML and GeoJSON export |

### 2G / GSM
| Module | Description |
|---|---|
| `06_gsm_air` | BCCH/CCCH decode, paging groups, A5/1 keystream, identity exposure |
| `07_gsm_attack` | The 2G attack surface: forged BCCH, IMSI catcher sequence, A5 downgrade, TMSI deanonymisation, Kc recovery |
| `15_downgrade` | Cross-generation steering: forged reject causes, SIB1 forgery, null-cipher analysis |
| `20_gsm_cve` | Catalogued GSM/UMTS CVEs with reachability checks |

### 3G / UMTS
| Module | Description |
|---|---|
| `08_umts_air` | UTRAN decode and SIB fields, forged RRC setup/reject/paging, the TS 25.212 BCH chain, a WCDMA downlink carrier, SIB1/SIB3/SIB5 packed onto the BCCH-FACH transport, scheduled on non-colliding frames and spread on an S-CCPCH, the MIB derived from that SIB set and split into BCH blocks, and the COUNT/MAC-I AKA walk |

### 4G / LTE
| Module | Description |
|---|---|
| `09_lte_attach` | NAS EMM/ESM encode-decode, BCD IMSI/IMEI, attach forging, identity-exposure detection |
| `10_lte_air` | LTE air interface: MIB/SIB decode, DCCH builders, CMAS/ETWS warning messages (SIB10-12), srsRAN eNB orchestration |
| `11_lte_core` | EPC: Diameter S6a/S6d, GTP-C, GTP-U, S1AP, GTP-in-GTP, MBMS session start |
| `21_lte_cve` | 98 catalogued LTE/5G stack CVEs from the public corpus, filed into the same class views as this tree's own vectors and filterable by reach, plus four message families built from each code pattern |

### 5G / NR
| Module | Description |
|---|---|
| `12_nr_air` | SSB/MIB/SIB1, PRACH, beam sweep, SSB waveform, gNB orchestration |
| `13_nr_core` | 5G SBA: NRF discovery, NGAP, PFCP, 5G-AKA, KSEAF, forgery |
| `58_suci_catcher` | 5G pre-authentication identity capture: gNB and AMF slice build, catcher plan, live SUCI read, SUCI classifier and corpus, NAS and RRC codecs |
| `22_nr_cve` | Catalogued 5G CVEs, with the published NGAP and NAS entries filed beside them |
| `40_sba_pivot` | Pivot across the service-based architecture: NRF, AMF, SMF reachability |
| `49_ntn` | Non-terrestrial access: Doppler, RTT, timing advance, k_offset |
| `51_sidelink` | NR sidelink on PC5: resource pools, SCI-1A limits, ITS certificates, relay checks |

### Land mobile radio
| Module | Description |
|---|---|
| `53_non3gpp` | TETRA, DMR and GSM-R structure, ciphers and band classification |
| `50_gprs` | GPRS/EDGE: GEA0/GEA3/GEA4 ciphering with published vectors, GEA standing, APN and PDP coding |

### The core and the interconnect
| Module | Description |
|---|---|
| `26_ss7_map` | MAP/TCAP decode and forge, SIGTRAN both ways, GRX/roaming interconnect |
| `27_cellular_dns` | DNS over the bearer, the aLTEr sequence, spoof detection |
| `30_volte_ims` | ReVoLTE keystream reuse, IMP4GT model, SIP REGISTER spoofing, IMS registration hijack |
| `32_nas_signaling` | NAS rate and procedure mix, storm detection, and seventeen pre-authentication message builders |
| `48_oran` | O-RAN interfaces, E2SM, xApp authority, A1 policy poisoning, QoS policy |

### Access and the network edge
| Module | Description |
|---|---|
| `34_slicing` | S-NSSAI codec, slice selection, isolation testing, 5QI and TSN assistance |
| `36_vowifi` | IKEv2/IPsec SWu, EAP-AKA', ePDG attach, certificate assertions |
| `37_femtocell` | S1/Iuh attach, femtocell provisioning, GSMTAP and S1 tap |
| `38_ussd` | USSD request forge, response decode, SS/MMI command surface |
| `43_ran_share` | Network sharing: PLMN leaks and MOCN configuration review |
| `45_iot` | NB-IoT: MIB-NB, SIB1-NB and SIB2-NB decoded through the generated PER codec, NPSS/NSSS, NPRACH symbol-group hopping (TS 36.211 10.1.6.1), NPRFCN stated as absent |
| `47_wifioff` | Wi-Fi offload: ePDG FQDN, EAP exchange byte for byte, certificate assertions |

### SIM and identity
| Module | Description |
|---|---|
| `14_suci` | SUCI concealment and de-concealment, X25519 and P-256 profiles, a home network (`--hn-create`, `--hn-deconceal`, `--hn-auth`, `--hn-serve`) and a linkability oracle over observed SUCIs (`--link-oracle`, `--link-demo`) that is both the SIDF and the AUSF: it de-conceals an arriving SUCI with its own private key, finds the subscriber in the `16_sim` key store, runs 5G-AKA and returns the authentication vector |
| `16_sim` | SIM AKA (COMP128 1/2/3, Milenage, TUAK), USIM files, EF_AD, OTA parsing, eSIM profiles, ES9+, plus a subscriber key store and an AKA responder (`--key-add`, `--aka-responder`, `--aka-serve`) that holds K/OPC, SQN and state across calls and derives KAUSF/RES* for 5G |
| `18_imsi_exposure` | IMSI harvest and TMSI/IMSI correlation over a capture |
| `31_sim_defense` | SIM swap: risk scoring, the six detection signals, plus APDU and port-out artefacts |
| `41_ota_sms` | OTA binary SMS: TPDU packing, S@T push with its CONCATENATE / variable-reference / substitution byte code, SMPP 3.4 built/parsed and carried to an SMSC over TCP, an HTTP gateway send that needs a SIM on the far phone rather than in this machine, WIB refused by name |
| `52_stk` | TS 31.111 proactive commands: build, parse, audit for silent off-device actions |

### Baseband and device
| Module | Description |
|---|---|
| `35_baseband` | RRC/NAS mutation, corpus generation, crash triage, DIAG framing, transmit handoff |
| `54_baseband_exploit` | Catalogued baseband CVEs with reachability checks, L2 frame builders |
| `55_nr_inject` | NR random access, MAC/DCI, link-layer sequences, catalogued exploits |
| `56_baseband_diag` | Qualcomm DM/DIAG framing, NV items, EFS, identity and AT surface |

### Analysis and tracking
| Module | Description |
|---|---|
| `17_pcap_analysis` | From-scratch pcap reader: GSMTAP, Diameter, NGAP, S1AP, GTP, PFCP, RTP |
| `19_cipher_audit` | Negotiated cipher audit, downgrade detection, authentication oracle |
| `23_traffic_analysis` | Flow features, application classification, reference store, call records |
| `24_rf_fingerprint` | IQ fingerprinting, CFO/IQ imbalance, transients, CSI motion |
| `28_paging_track` | Paging occasions, Torpedo and Piercer models, storm and flapping detection |
| `29_mac_layer` | MAC/RLC/PDCP decode, RNTI tracking, grant cadence, the user-plane integrity gap |
| `39_ta_geoloc` | Timing-advance geolocation and cell-range estimation |

### Intercept and carrier
| Module | Description |
|---|---|
| `42_li_probe` | Lawful-interception interfaces and posture signals, plus the TS 33.108 HI1 PDUs an interception is built from |
| `44_carrier_api` | Carrier API surface, authorisation matrix, token and rate-limit audit, surface and subscriber enumeration |

### The radio itself
| Module | Description |
|---|---|
| `33_jamming_detect` | Jamming detection and characterisation, and the waveform constructor (no gate; the disclaimer is information, not a lock) |


## The attack inventory

The [Modules](#modules) section answers *what each module is*. This section answers
the other question directly: **what attacks this tree contains**, and what each one
computes rather than describes.

### Identity capture

| Attack | Module | What exists |
|---|---|---|
| IMSI catcher — GSM | `07_gsm_attack` | The full catcher sequence and a forged BCCH carrier a handset can camp on. The attack needs a receiver beside the transmitter and licensed spectrum; the transmit verb is there and the handoff is named. |
| IMSI catcher — LTE | `09_lte_attach`, `10_lte_air` | NAS EMM attach forging, BCD IMSI/IMEI, the identity-request sequence, and srsRAN eNB orchestration. |
| IMSI catcher — NR | `12_nr_air` | SSB/MIB/SIB1 construction, RACH handling, gNB orchestration, and the SSB written as samples. |
| SUCI de-concealment | `14_suci` | X25519 and P-256 profile A/B conceal and de-conceal, HKDF, MSIN BCD, all computed. |
| Be your own home network | `14_suci`, `16_sim` | `--hn-create` mints a home-network profile (PLMN, routing indicator, concealment scheme and the private key), `--hn-deconceal` resolves an arriving SUCI to an IMSI with it, and `--hn-auth` looks the subscriber up in the `16_sim` store, runs 5G-AKA and prints the vector the serving network expects — XRES*, HXRES*, KAUSF and KSEAF per TS 33.501 A.4–A.6, with the KDF key CK‖IK and XRES* as the rightmost 128 bits. `--hn-serve` answers `SUCI`/`AUTH`/`SHOW` lines on stdin so a fake cell can talk to it over a pipe. |
| 5G-AKA linkability oracle | `14_suci` | `--link-oracle` reads a file of observed SUCIs (optionally with the AUTN the network was handed) and judges every pair: linked or not, and which signal joined it — the SUCI octets, the ephemeral key, a cleartext MSIN, the MSIN's length class, or an AUTN given to two rounds. It separates the fields every subscriber of one network shares (scheme, key id, routing indicator) from the ones that identify a subscriber. `--link-demo` builds that fixture on the host's own home network and shows all five shapes. |
| TMSI → IMSI deanonymisation | `07_gsm_attack`, `18_imsi_exposure` | Correlation across a capture via forced-identity and location-update bindings, with a confirm step that needs a second observation. |
| Piercer (IMSI by paging correlation) | `28_paging_track` | The paging-occasion maths and the published model, with the correlation step kept separate from the claim. |

### Cipher and downgrade

| Attack | Module | What exists |
|---|---|---|
| A5/1 keystream | `06_gsm_air`, `07_gsm_attack` | Asserted against the published Briceno/Goldberg/Wagner vector. A5/2 is present for testing and its brokenness is stated. |
| A5/1 downgrade | `07_gsm_attack` | The forcing sequence is constructed; putting it on the air is the same licensed-spectrum handoff as the catcher. |
| Cross-generation steering / null cipher | `15_downgrade` | Reject-cause construction, SIB1 forgery, and cipher-change analysis across all four generations. |
| ReVoLTE keystream reuse | `30_volte_ims` | Key-reuse detection, recovery, and the model of what two ciphertexts under one keystream give. |
| GEA downgrade and ciphering — GPRS/EDGE | `50_gprs` | GEA3 and GEA4 compute against nine published vectors (TS 55.217/55.218/55.226), GEA0 is the identity, GEA1/2 are named as broken in the literature and prohibited, GEA5 as licence-gated; APN and PDP IEs encode for real. |
| Cipher audit and authentication oracle | `19_cipher_audit` | Scores the negotiated cipher, detects a downgrade, reads the cause tables against what each proves, and recovers the SQN a UE conceals in AUTS. |

### Signalling forgery — NAS, RRC and SIB

| Attack | Module | What exists |
|---|---|---|
| NAS pre-authentication messages | `32_nas_signaling` | Seventeen messages built as octets — Attach/TAU/Service reject, Identity Request, Authentication Request/Reject/Failure, Security Mode Command/Reject in EPS and 5GS — each checked against tshark. The NAS-MAC and AUTN are refused rather than placed at an unconfirmed offset. |
| RRC reconfiguration, release and reject | `10_lte_air`, `12_nr_air` | MeasurementReport, RRCConnectionRelease and RRCConnectionReestablishmentReject encoded through the generated PER layout; NR reconfiguration beside them. |
| **CMAS / ETWS / PWS alert forgery** | `10_lte_air` | The full warning chain in RRC: SIB10 carries the primary notification (message identifier, serial, `warningType` split into class and category), SIB11 and SIB12 the segments that follow, and SIB12 the coordinate segment. Every builder is pinned to pycrate vectors — `04400000000040` (SIB10, 50 bits), `048D159E00026F56DF7780` (SIB11, 81 bits), `82468ACF0000FFC00040412040204000` (SIB12 with a warning-area segment, 122 bits). `--enb-sib-schedule` writes the `sib.conf` fragment that would announce one, and refuses on srsRAN release_23_11 by name because that release registers only sib1-sib7, sib9 and sib13 — a SIB10 entry fails in `sib_info_item_c::pack`. Master implements it. |
| SIB1 decode and DCCH forgery | `10_lte_air`, `12_nr_air` | SIB1/SIB2 read; MeasurementReport, RRCConnectionRelease and ReestablishmentReject encoded through the generated PER layout. |
| Forged reject cause | `15_downgrade` | Built, with the transmit verb last on its card. |
| GTP-in-GTP and MBMS session start | `11_lte_core` | Both built and dissected by tshark; the outer layer treats the inner as uninterpreted payload, which is exactly the middlebox gap. |

### Core network and interconnect

| Attack | Module | What exists |
|---|---|---|
| MAP operations | `26_ss7_map` | ATI, SRI, SRI-SM, SAI, PSI, ULR, ISD, RegisterSS and ActivateSS built byte-exact, with M3UA encapsulation both ways. |
| SIP and IMS registration hijack | `30_volte_ims` | A forged REGISTER and the spoofed re-registration sequence; `--sip-flood` is a rate calculation, not a sender. |
| 5G SBA and NGAP | `13_nr_core`, `40_sba_pivot` | NRF discovery, NGAP procedures, PFCP rules, and the reachability map across the service-based architecture. |
| 5G SUCI capture | `58_suci_catcher` | The pre-authentication identity exchange: cell and AMF slice build, catcher plan, and the SUCI a UE hands over before any key exists. |
| O-RAN and slicing | `48_oran`, `34_slicing` | A1 policy poisoning, E2 control shapes, the over-broad xApp model, slice isolation testing, 5QI and TSN assistance. |
| Carrier API enumeration | `44_carrier_api` | A concrete request per operation rendered from the document's own examples, and the ordered subscriber sequence. Both stop at the file. |
| Lawful interception artefacts | `42_li_probe` | The provisioning and activation records as real TS 33.108 HI1 PDUs (liActivated / liDeactivated, BER), and the X3/HI3 product envelope as this module's own framing. Encoded, never delivered. |

### Baseband, device and radio

| Attack | Module | What exists |
|---|---|---|
| Baseband CVEs | `54_baseband_exploit` | The catalogue with the state each needs, L2 frames, forged registration accept/reject, and a send verb that asks for `--yes`. |
| NR access attacks | `55_nr_inject` | RAR construction, backoff, RA-RNTI arithmetic, MAC/DCI, Gold sequence and scrambling, and the catalogued exploits over them. |
| DIAG and NV | `56_baseband_diag`, `35_baseband` | Real DIAG framing, NV read/build/write requests, EFS paths and the AT surface; `35_baseband` owns the transmit handoff and the SCPI command file. |
| Jamming | `33_jamming_detect` | Detection first: barrel, narrowband and pulsed shapes told apart from congestion. The waveform constructor — AWGN/CW/chirp, PSS/SSS/PBCH, PRACH, PRS, GPS C/A, NR SSB — runs on the first invocation and prints its disclaimer on stderr. |
| GPS and PRS jamming | `33_jamming_detect` | Both sequences are generated from the standards — IS-GPS-200N Table 3-Ia for the C/A code, TS 36.211 for PRS — and asserted against an independent implementation. |

### Tracking, positioning and RF

| Attack | Module | What exists |
|---|---|---|
| Timing-advance geolocation | `39_ta_geoloc` | Cell range from TA, with the accuracy limit stated rather than rounded away. |
| OTDOA / UTDOA / PRS | `46_lpp`, `33_jamming_detect` | LPP assistance data and requests through the generated LPP codec, checked against pycrate; PRS generated from TS 36.211 with its RE map written beside it. UTDOA is LPPa, so it is stated as a handoff. |
| RF fingerprinting and CSI sensing | `24_rf_fingerprint` | CFO, IQ imbalance, transients, and a channel that moves without a transmitter moving. |
| Traffic and application fingerprinting | `23_traffic_analysis` | Flow features and classification on behaviour rather than ports. |

### Orchestration

| Attack | Module | What exists |
|---|---|---|
| Repeated runs | `25_killchain` | Nine builtin chains — survey, passive-audit, gsm-assessment, lte-core-audit, 5g-privacy, rf-effect, nbiot-audit, lmr-survey, slice-oran-assess — plus user chains, with pause, resume and a result report per run. |


## Hardware

Nothing on this list is bundled with the tree, and none of it has been verified
on the machine this was built on — that machine has no SDR attached at all. What
follows is what each module's own code asks for, in its own words, together with
what the parts actually cost.

<img width="1335" height="621" alt="image" src="https://github.com/user-attachments/assets/c1de707d-57dd-4a50-9f33-b286c5608cc9" />


### What is on this machine right now

`05_field_kit --guard-check` and `01_radio` probe for these, and the answers are
not impressive:

| Tool | Present? | Consequence |
|---|---|---|
| `bladeRF-cli` | yes (`/usr/bin/bladeRF-cli`) | `01_radio` writes a state file with serial `unknown` — no device is connected |
| `hackrf_transfer` | yes | usable as a `BEXP_TX_CMD` / `NRJ_TX_CMD` wrapper, with a HackRF attached |
| `SoapySDRUtil` | yes | device enumeration only; no radio behind it |
| `grgsm_scanner` | yes (`/usr/bin/grgsm_scanner`) | `02_cell_recon --scan gsm` takes its full ~30 s window and then fails honestly: no SDR |
| `srsenb`, `srsue`, `gnb` | no | `10_lte_air` and `12_nr_air` generate configs and report the missing binary |
| PC/SC reader, `gpsd` | no | every SIM and GPS path is unrunnable |

So the honest summary is: **the software half runs, the radio half has never
run.** "Written" and "works" are different claims and this table is which is which.

### Tier 0 — no radio at all

Everything that is pure protocol work runs today: `--selftest` on all 60 modules,
all encode/decode, all key derivation, pcap dissection, CVE dispatch, corpus
generation and the killchain runner. This is most of the tree and it costs
nothing.

### Tier 1 — receive only (~$30)

An **RTL-SDR** (RTL2832U + R820T2) receives roughly 24 MHz–1.7 GHz. It cannot
transmit, ever — there is no TX path in the silicon.

- Unlocks: `02_cell_recon`, `04_tower_map`, `06_gsm_air`, `17_pcap_analysis`,
  `23_traffic_analysis`, `24_rf_fingerprint`, `33_jamming_detect`, and the
  passive half of `28_paging_track` / `29_mac_layer`.
- Does not unlock: anything with an `--inject`, `--send`, `--start` or
  `--paging-tx`. Those verbs detect the absence and refuse — they do not fail
  silently, which is the point of the status column above.

### Tier 2 — one transmit-capable SDR (~$300–500)

A **HackRF One** (~$300) or **Nuand bladeRF 2.0 micro** (~$500). Half-duplex is
enough for every single-radio attack in the tree.

- Unlocks: `07_gsm_attack` (IMSI catcher, A5/1 downgrade, TMSI de-anonymisation),
  `10_lte_air` (rogue eNB — it writes srsRAN configs and execs `srsenb`),
  `12_nr_air` (rogue gNB), `09_lte_attach`, `15_downgrade`, `28_paging_track
  --paging-tx`, and every `54_baseband_exploit` / `55_nr_inject` frame via
  `BEXP_TX_CMD` / `NRJ_TX_CMD`.
- `59`'s own example command is `hackrf_transfer`, so this tier is what that
  module was written against.
- The bladeRF 2.0 is the one this tree names most often (`01_radio` has a
  dedicated `radio_parse_bladerf` path), and it is the only SDR the host
  currently has CLI tools for.

### Tier 3 — a two-radio lab (~$2,000–5,000)

The baseband work needs **two** radios, and the module headers say why: one must
*be* the gNB and hold timing and frame structure while the second injects into
the UE's current state. One radio cannot do both.

- `54_baseband_exploit --plan` names: "two SDRs (USRP B210 or X310) or one SDR
  plus an amplifier; a lab UE/modem you own; GPSDO for dual-radio timing".
- A **USRP B210** (~$1,100) is the usual choice; an **X310** costs several times
  that. Add a **GPSDO** so the two radios share a clock, an amplifier, a
  sacrificial UE or module you are willing to brick, and a faraday enclosure or
  licensed test cell so the injection does not leave the bench.
- Software side: `srsRAN` or `OpenAirInterface` for the gNB, plus Sni5Gect- or
  5Ghoul-style injection tooling. The tree builds the frames; it does not ship
  the gNB stack.

### Tier 4 — emulation instead of radio (no SDR, but you must own the device)

`54_baseband_exploit --emulate` runs firmware in an emulator rather than over the
air, which is the cheapest way to do baseband work at all. It names the tools by
name: **FirmWire** (Samsung/MediaTek basebands), **srlabs hexagon_fuzz**
(Qualcomm Hexagon), **BaseSAFE**, and **BaseBridge**. You still need the baseband
image from a device you own, and enough RAM to run it.

### SIM and smart-card work

A **PC/SC reader** (any CCID reader, ~$15) for `16_sim`'s USIM file work. For
writing profiles you need a programmable card such as a **sysmoUSIM-SJS1** or a
**5G test USIM**; `16_sim`'s four offensive paths currently stop at a plan file
naming one, because there is no APDU exchange loop in the module to drive it.
The key store and the AKA responder need none of that: they compute the network
side of the AKA from a subscriber's K and OPC/TOP, walk SQN on disk, and answer
on a line protocol.

### GPS

Any **gpsd**-supported receiver (~$15–40) for `04_tower_map` and the survey
paths. Without one those modules still run; they just have no coordinates to
attach.

### Regulated-spectrum note, stated once

Transmitting on licensed cellular spectrum is regulated in every jurisdiction,
and several of the modules above do exactly that. The tree is built for a lab,
a faraday enclosure, or a network you control — which is why the transmit verbs
are guarded, why they name the hardware they need, and why they exit non-zero
rather than pretending. That guard is engineering, not a legal opinion, and it
does not make an unlicensed transmission legal.

---

## How to run it

Build the GUI:

```bash
cd native
meson setup builddir
meson compile -C builddir
```

Then, from the project root:

```bash
sudo ./imsisting.sh          # CLI menu
./imsisting.sh --list        # module list
./imsisting.sh --index       # the module index as TSV
./imsisting.sh --gui         # launch the GUI
./imsisting.sh --tui         # launch the TUI
```

<img width="1366" height="708" alt="image" src="https://github.com/user-attachments/assets/597fcd5c-9694-4c74-95d7-211a0a5c8e3b" />


Or launch the built binary directly:

```bash
./native/builddir/imsisting-gui
```

<img width="964" height="523" alt="imsisting" src="https://github.com/user-attachments/assets/97afe07a-1b0e-43fe-a931-66cd5dc0fd37" />

The GUI asks for your password per action via `pkexec`, not once at startup.

### Dependencies

**Required:** GTK4 (4.14+), meson, ninja, a C compiler, python3.

```bash
# Debian / Ubuntu
sudo apt install build-essential meson ninja-build libgtk-4-dev \
                 python3 python3-numpy python3-scipy

# Arch
sudo pacman -S base-devel meson ninja gtk4 python python-numpy python-scipy
```

**Optional but used by specific modules:** `gnuradio` + `gr-gsm`, `srsRAN`,
`Open5GS`/`free5GC`, `tshark`, `pcsc-tools`, `gpsd`, `python3-cryptography`.
`00_deps` reports what is present and what is missing, and distinguishes a tool
that is installed from a stack that is actually complete.

### The interface

The GUI opens on a **Dashboard** — every module as a card, grouped by category.
Click a card and the module opens as its own tab. Six tabs are permanent:

<img width="335" height="634" alt="image" src="https://github.com/user-attachments/assets/41d9556a-d047-4e7f-aa41-a642c19e3d16" />


| Tab | What it is |
|---|---|
| **Dashboard** | Every module as a card, grouped by category. The main menu. |
| **Live Traffic** | A live GSMTAP view (below). Starts listening when you open it. |
| **Casebook** | Cases, selected cells, evidence/captures, timeline, IDS alerts, passive sensor nodes and HTML/JSON/TSV reports. The Evidence page retains the per-module loot browser and preview. |
| **Stats** | Module and collection counts, and a health line. |
| **Help** | How the tree fits together and how to drive it. |
| **Settings** | Environment facts, plus dependency and SDR probe actions. |

Module tabs appear alongside these and can be closed; the six permanent tabs
cannot.

**A module page** is a left menu of views with the content beside it, grouped
into cards — STATUS, ACTIONS and ALL MODULE VERBS. The action buttons cover
the verbs you reach for most; the generated selector is built from the module
index and exposes everything else, with a separate arguments field and command
copy button, so nothing is unreachable.

**Live Traffic** is a real table (sequence, time, type, channel, ARFCN,
timeslot, signal, direction, length, payload) with a filter box above it that
matches on type, channel or payload. Uplink rows are marked.

**The dashboard is configurable, and it remembers.** Every card carries a star:
pinned modules lead the grid whatever the sort is set to. `Sort`
offers Workflow (category order), Most used (by run count), Name and Category,
and `Density` switches Compact, Comfortable or Spacious card sizing. All of it
survives a restart, because it lives in `state/` rather than in the binary —
and both searches say *no match* instead of going quietly blank.

**Stats** shows headline counts as tiles, a per-category breakdown as bars, and
where everything lives on disk. It recounts when you open it, so a module that
has just written loot is not still showing the numbers from launch.

The **module list on the left collapses** — the *Modules* button in the header
bar. Collapse it when a module page needs the full width.

The **header strip** carries the live cellular state, read from the modules
themselves so it cannot disagree with them:

    SDR    the selected radio (01_radio --status-tsv)
    TX     whether that radio can transmit — most attack verbs need this
    FREQ   the tuned frequency
    CELLS  cells in the survey store (02_cell_recon)
    GPS    the survey position source (04_tower_map)

`--tab N` opens straight to a tab (0 Dashboard, 1 Live Traffic, 2 Casebook,
3 Stats, 4 Help, 5 Settings):

```bash
./native/builddir/imsisting-gui --tab 1
```

### Live Traffic — what it is, and what it is not

There is no way to demodulate GSM or LTE inside a GUI process; that needs a
full PHY. So this is not a raw-radio view and does not pretend to be one.

What it is: a **GSMTAP** listener on UDP 4729. GSMTAP is the format gr-gsm,
srsRAN and Open5GS all emit, and it is what Wireshark keys off. The tab binds
the port, decodes each message's 16-byte header as it arrives, and shows the
type, GSM channel, ARFCN, timeslot, signal, direction, length and payload.

That makes it useful both ways — passively to watch paging, SI and identity
exchanges happen, and offensively to confirm an emitter is actually
transmitting and see what a UE answers with.

It needs an upstream emitter. If nothing arrives within three seconds it says
so and names what to start, rather than showing an empty pane:

```bash
grgsm_livemon            # GSM, via gr-gsm
# or an eNB/gNB started with GSMTAP enabled
```

Two honest limits. The header's `arfcn` field is 16 bits, so an NR-ARFCN
(which runs into the millions) cannot be represented in it — the field is not
a general NR ARFCN carrier. And `sub_type` is a GSM channel type only under a
GSM payload; under LTE/NR it is not a channel, so the column shows `—` rather
than a plausible-looking wrong name.

### First run

1. **Dependencies** — run the check. Half of all confusing failures later are a
   missing tool.
2. **SDR / Radio Manager** — confirm a device is seen and which bands it covers.
   A receive-only device is flagged, because most attack verbs need transmit.
3. **Cell Recon** — try `--status-tsv` first. It works with no radio attached,
   which makes it a good smoke test.

---

## What actually works

**Verified in software, with no radio required** — these run and are covered by
their own selftests:

- ARFCN/EARFCN/NR-ARFCN frequency maths, against published 3GPP values
- PLMN/MCC/MNC decoding, ICCID/IMSI/IMEI BCD codecs
- NAS EMM/ESM, RRC/SIB, Diameter, GTP-C/GTP-U, PFCP, NGAP, TCAP/MAP
  encode-decode against hand-built frames
- A5/1 keystream, against the published Briceno/Goldberg/Wagner vector
- The LTE downlink coding chain — CRC24A/24B/16/8, turbo coding, the QPP
  interleaver over all 188 block sizes, turbo rate matching, the 3K+12 stream
  split and the length-31 Gold scrambling sequence. Each stage is checked
  against an implementation that does not derive from this tree, and the
  encoder, split and rate matcher are checked together over 60 full chains
  against turbofec, from K=40 up to the 6144 maximum
- HKDF-SHA256 against all three RFC 5869 vectors; X25519 and P-256 SUCI
  conceal/deconceal round trips
- AES-CTR against NIST SP 800-38A
- pcap/pcapng parsing with a self-contained reader, no tshark needed
- Cipher and downgrade scoring across all four generations
- CVE-kit dispatch: every documented id routes to a probe or a named handoff

**Written but NOT tested against real hardware** — no SDR was available:

- Every live capture path: GSM survey, LTE cell search, GSMTAP listen, NR scan
- Every transmit path: IMSI catcher, A5/1 downgrade, RRC reconfiguration,
  NAS signalling, slice escape
- RF fingerprinting and CSI analysis (the maths is tested against synthetic IQ;
  a real device signature has never been collected)
- VoLTE capture paths (the crypto is tested; the over-the-air capture is not)
- SIM paths needing a reader or a programmable card
- GPS survey paths

The code is written and reviewed. **"Written" and "works" are not the same
claim,** and this section exists so nobody has to guess which one applies.

That distinction runs the other way too: **a verb existing is not the same claim
as the attack being implemented.** A module that prints a plan file naming an SDR
looks exactly like one that prints protocol octets, unless you read what it
emits. What each module actually implements is in its own `--status-tsv` and in
its `--help`, not in its name.

Two holes are worth naming precisely, because their size is easy to overstate:

- **3G camping, not 3G capture.** `08_umts_air` forges the downlink
  (`--build-rrc-setup`, `--build-rrc-reject`, `--build-paging`, each read back by
  an independent dissector), carries a real MIB through the whole TS 25.212 chain
  onto the P-CCPCH (`--transmit --bch-hex`), builds a WCDMA carrier with CPICH
  and both sync channels, packs SIB1/SIB3/SIB5 onto BCCH-FACH
  (`tools/umts_sib.py pack --timeline`), spreads that frame on an S-CCPCH
  (`tools/umts_sccpch.py`), derives the MIB from the SIB set it is about to
  transmit and splits it into the 24-bit BCH blocks a cell puts out over its
  80 ms period (`--transmit --sibs` with no `--bch-hex`), builds the
  messages a catcher sends *upward*
  (`--catcher-identity` MM IDENTITY REQUEST, `--catcher-auth` replay), and builds
  the handset's side of the random access as chips: the PRACH preamble, the RACH
  message part spread with the signature's channelisation codes, weighted by the
  signalled gain factors and scrambled by `S_r-msg,n` (`--uplink message-part`),
  the two joined into one transmission (`--uplink burst`), and the transport
  channel above them in uplink order -- CRC, convolutional coding, radio frame
  size equalisation, 1st interleaving, radio frame segmentation, per-frame rate
  matching and 2nd interleaving (`--uplink chain`, TS 25.212 4.2) with the
  (32,10) Reed-Muller TFCI encoder (`--uplink tfci`, TS 25.212 4.3.3).
  What it still does not do is run the loop: nothing here receives UMTS uplink
  and answers it in one process, and a handset that already holds an AKA context
  will not answer an unauthenticated network. `--catcher-model` names all eight
  steps and which of them exist rather than implying the chain is complete.
- **The CVE catalogues.** `20_gsm_cve`, `21_lte_cve` and `22_nr_cve` catalogue
  vulnerabilities and check reachability against a stack state. None of the three
  contains an exploit primitive, and none claims to.

---

## What is not built

The tree states its own limits rather than leaving them to be discovered. Every
verb that cannot do something says so in one of two ways: a `limit` row naming
what it did not do and why (89 of them across the modules), or a refusal with an
`ERROR`/`WHY` pair and a non-zero exit (about 2500). A tool in `tools/` that
cannot run its oracle **skips** and exits 2 — a skip is never a pass.

The gaps fall into three classes, and only the first two are code.

### 1. Needs a radio, or a second radio

These build the message, the frame or the samples and stop at the antenna. The
code is complete; the operation needs a licensed transmitter, a receiver beside
it, or both.

| module | what it does | what stops it |
|---|---|---|
| `07_gsm_attack` | full GSM catcher sequence, forged BCCH carrier, A5/1 downgrade forcing | C1 must beat the real cell, the forged command must land in the right LAPDm window, and whether a handset accepts a clone depends on the handset and the location area |
| `08_umts_air` | RRC forgery (setup/reject/paging), BCH through the whole TS 25.212 chain with the MIB split into the blocks an 80 ms period holds, WCDMA carrier with CPICH and both sync channels, SIB1/SIB3/SIB5 through the FACH chain onto an S-CCPCH in the frames the MIB schedules, MM identity request, uplink RACH as chips (preamble, spread/scrambled message part, the burst that joins them) and the uplink transport chain with the TFCI encoder above it | no duplex loop: nothing here receives UMTS uplink and answers it in one process |
| `33_jamming_detect` | ten waveform shapes including PSS/SSS/PBCH, PRACH, PRS and GPS C/A | `pucch` and `lte-ssb` are refused: this tree carries no PUCCH sequence generator, and LTE SSB is covered by pss+sss+pbch |
| `45_iot` | NB-IoT RRC decoders through a generated codec | NPRFCN is refused — the module used to answer a 410 MHz intercept and a 500 MHz branch, neither of which is a band rule, and the column that would settle it is not in TS 36.104 Table 5.7.3-1 at all |
| `35_baseband` | mutation, corpus generation, crash triage, DIAG framing | no modulator: a payload is a handoff to srsRAN or OpenAirInterface |

### 2. Needs the far side to answer

The request is built correctly and the answer is decoded. What is missing is a
peer, and a peer on a carrier network is an authorisation, not a commit.

| module | built | missing |
|---|---|---|
| `26_ss7_map` | ten MAP operations, TCAP/SCCP/MTP3/M3UA/SGsAP, four decoders, **response builders** and **dialogue pairing** (transaction and invoke ids), M3UA over a real SCTP association, **`--lab`** (peer up, ask, pair, verdict in one command), and `tools/ss7_responder.py`, a peer that encodes its answer with pycrate so a pass means two implementations agreed on the wire | an STP that accepts your point code and an HLR that answers. `--m3ua-send` goes out on the first invocation and needs a reachable STP. There is **no TDM MTP2**: an operator peering only over E1/TDM is out of reach. Reach is a routing position (an assigned point code, a routed association, SSN 6 permission) plus admission — no software substitutes for it, and `--lab` says so in its own output |

Identity directions in `26_ss7_map`, stated rather than implied: `SendRoutingInfo`
and `SendRoutingInfoForSM` take a **number** and answer with an IMSI and a serving
MSC; `--imsi` flips both to carry the IMSI instead (tag 81 where TS 29.002
defines `msisdn [0]`, so tshark calls it malformed — some HLRs answer it because
they read the field as TBCD and ignore the tag, and the ones that filter do not).
`AnyTimeInterrogation` takes an IMSI in the standard's CHOICE and `--msisdn` uses
the number arm, which tshark decodes cleanly. The **ATI answer body is not
referee-checked**: pycrate here cannot encode `SubscriberState` (every arm of the
CHOICE rejects its value) and writes `ageOfLocationInformation` untagged where
TS 29.002 defines `[0]`, so `--build-response ati-ack` takes your parameter and
the location and state halves are unverified by this tree.
| `44_carrier_api` | OpenAPI parsing, authorisation matrix, request rendering, subscriber-sequence ordering | no executor — it writes `curl` lines and sends nothing |
| `42_li_probe` | BER encoding of the TS 33.108 Annex M HI1 operation, semi-octet BCD, and this module's own X3/HI3 product envelope | HI1's Notification carries no target-identity field and no host:port, so the subscriber identity, the IRI/CC pair and the DF2/DF3 destinations are printed as `not_encoded` rather than dropped; the HI3 product envelope is still this module's own TLV framing because TS 33.108's HI3 record is not transcribed here; and nothing is delivered to an ADMF |
| `11_lte_core`, `13_nr_core`, `40_sba_pivot`, `30_volte_ims` | GTP-C, Diameter, NGAP, PFCP, SBI and SIP message builders with senders over real SCTP/UDP associations | a core that answers |

### 3. Needs something that is not available here

| module | refused, and why |
|---|---|
| `50_gprs` | GEA1/GEA2: recovered only in the cryptanalysis literature, taps not in this tree. GEA5: algorithm body and test data licence-gated. GEA0/GEA3/GEA4 are computed and vector-tested. |
| `16_sim` | the profile-element chain carried inside the `86` segments (SCP03t protects the block, it does not parse it), `HandleNotification` (the standard defines no response body), AUTS resynchronisation (`--aka-responder` emits the quintet and walks SQN but has no resync path), and a live session — `--es8-scp03t` builds the 84/85/86 TLVs from a supplied key set and both challenges, but a card cryptogram can only be confirmed by an eUICC |
| `41_ota_sms` | SMPP optional TLVs, submit_multi, data_sm and SMPP-over-TLS (the session is plaintext TCP 2775 by design, so the transport is named in the output); WIB push (the leaf command bytes have no citable public encoding) and a deck that binds a terminal response into a variable: S@T's CONCATENATE, variable-reference and substitution encodings are built, but PROVIDE LOCAL INFORMATION returns its datum in the terminal response rather than into a variable, so `--sat-push` emits the fixed-body form and the variable-bound body is assembled from `--sat-concat` / `--sat-varref` / `--sat-subst` by hand |
| `14_suci` | the oracle's signal set is structural, not cryptographic: it joins pairs on octets, the ephemeral key, a cleartext MSIN, the MSIN's length class or a repeated AUTN, so two rounds that differ in every one of those fields come back not-linked even when a cryptanalysis of the concealment would join them. The card side of the 5G-AKA proof: `--hn-auth` produces the network half (XRES*, HXRES*, KAUSF, KSEAF) and the HRES* a handset would return is the same clause on RES*, but the RES the proof needs comes off a physical USIM — a virtual one is not built here. Also not built: KAMF (the SEAF/AMF derivation over ABBA) and the Nausf service itself, which is HTTP/2 JSON on this tree's own key material |
| `49_ntn` | feeder link — SIB19 carries no gateway geometry, so the gateway-satellite distance is not derivable from anything the cell broadcasts |
| `46_lpp` | UTDOA is LPPa, not LPP, so it is stated as a handoff instead of encoded as the wrong protocol |
| `26_ss7_map` | the ATI answer body: below it, `SubscriberState` is not encodable by any referee available here, so the location and state fields are named as unverified rather than shipped on a guess |
| `20_gsm_cve`, `21_lte_cve`, `22_nr_cve` | catalogues and reachability checks. No exploit primitive in any of the three, and none claimed |

### How to audit it yourself

```bash
grep -n "limit" modules/<module>.sh        # what a module says it did not do
bash modules/<module>.sh --help            # a refusal names its reason
bash tools/check-<protocol>.sh             # SKIP (exit 2) when its oracle is absent
```

---

## How it is put together

The GUI is a view over the scripts in `modules/`. Nothing is locked behind it:

```bash
./modules/17_pcap_analysis.sh --summary capture.pcap
./modules/14_suci.sh --parse-suci <hex>
./modules/11_lte_core.sh --decode-diameter <hex>
```

Every module has `--selftest`. Run it first when something misbehaves — it
often identifies the problem with no hardware attached.

```bash
./tools/run-selftests.sh          # every module
./tools/check-paths.sh            # every path and table entry resolves
./tools/check-verbs.sh            # verbs reachable from the GUI
./tools/check-gui-text.sh         # no verb is rendered as interface text
./tools/check-x2ap-codec.sh       # X2AP octets vs pycrate and the clause
./tools/check-xnap-codec.sh       # XnAP octets vs pycrate and the clause
./tools/check-rua-codec.sh        # RUA octets vs pycrate and the clause
./tools/check-nas-identity.sh      # NAS mobile identity vs pycrate and tshark
./tools/check-ranap-codec.sh      # RANAP octets vs pycrate and the clause
./tools/check-auth-oracle.sh      # EMM and 5GMM causes vs tshark's registries
./tools/check-calls.sh            # call grouping vs tshark's RTP and SIP dissectors
./tools/check-keystream.sh        # reuse detection: stream identity vs tshark, verdict vs a constructed pad
./tools/check-ransacked-corpus.sh # the CVE catalogue against itself, and each generated family vs tshark
./tools/gen-module-index.sh       # regenerate the index
./tools/gen-icons-xml.sh --check  # the bundled icon set matches the tree
```

The 57 module icons are compiled into the binary as a GResource, published under
the directory layout GTK's icon theme expects, so the GUI does not depend on the
launcher having installed them into your theme — or on which theme your distro
happens to ship. They stay symbolic, so each category's accent colour still
applies. The launcher still installs them as a fallback.

`check-verbs.sh` grades reachability rather than treating it as binary: a verb
with a clickable control is one a user will find; a verb reachable only by
typing it into a page's run box is one they must already know about. The counts
are reported separately because the difference is real.

### Conventions

Every module follows the same contract: TSV out, `ERROR\t` to stderr, distinct exit
codes (0 success, 1 refused, 2 usage, 3 handoff), a `chk()`-based selftest with
known answers rather than self-consistent ones, and a tab-safe reader. Those rules
exist because ignoring them produced a real bug, not because they read well — the
empty-field trap in `IFS=$'\t' read`, the PYTHONPATH-in-`sudo` trap, and the
perl-vs-`tr` class trap have each cost a working module at least once.

---

## Directories

On first run the toolkit creates `tmp/`, `loot/`, `logs/`, `captures/`,
`state/` and `cases/` automatically. Nothing needs to pre-exist.

**`cases/` is the Casebook store.** It records scope and authorization, the
selected cellular target, SHA-256 evidence provenance, correlated events,
alerts, passive sensor health and exported reports. Files are indexed explicitly
from Casebook so large IQ recordings are not rehashed after every command.
Module completion is appended to the active case timeline automatically.

**`loot/` is where results land** — one subdirectory per module. Everything in
it came off the air or off a target device and **is not redacted**. It contains
real identities: IMSIs, IMEIs, captured messages, and in some cases decrypted
traffic.

**`state/` is what the GUI remembers.** `pins.tsv` holds the starred modules,
`ui.tsv` the dashboard sort and density, and `recent.tsv` the run counts behind
*Most used*. Delete one and that preference resets to its default; the toolkit
writes it again on the next change. Modules also keep their own working data
here, which is why `state/` grows subdirectories as you use them.

Treat a copy of `loot/` the way you would treat the equipment it came from. Do
not commit it, sync it, or email it.

---

## Troubleshooting

**"The module says OK but nothing happened."**
The failure worth reporting. Say which module, what you expected, and what the
target actually did.

**"It says no SDR."**
No device was found. `01_radio --list-tsv` names which vendor tool was probed.

**"A transmit verb refuses."**
It found no transmit-capable radio. An RTL-SDR cannot transmit; the guard is
doing its job.

**"The GUI will not start."**
Check GTK4 is at least 4.14.

---

## Contributing

1. Write `modules/NN_name.sh`. It must self-locate `IMSISTING_ROOT`, emit TSV,
   send errors to stderr, and exit non-zero on failure.
2. Add a `--selftest` that runs with no hardware, and whose assertions come from
   a published source where one exists.
3. Draw `native/resources/icons/symbolic/imsisting-NN_name-symbolic.svg` —
   256×256, stroke-only, `stroke="currentColor"` and no fill of its own, so the
   category colour applies — then re-run `./tools/gen-icons-xml.sh` to bundle it.
4. Register it in `native/src/main1.c` — a `modules[]` table row and a
   `module_registry_register()` call. Its category drives the sidebar,
   dashboard and Stats, and the launcher's table uses the same names, so keep
   the two in step.
5. Add it to `IMSISTING_MODULE_TABLE` in `imsisting.sh`, with the module id as
   the fifth field.
6. Run:

```bash
./tools/gen-module-index.sh
./tools/gen-icons-xml.sh
./tools/run-selftests.sh
./tools/check-paths.sh
./tools/check-verbs.sh
./tools/check-gui-text.sh
```

All of them must pass.

---

## Credits

Built on the work of others, and on published research:

- **gr-gsm**, **srsRAN**, **Osmocom** — the radio stacks everything sits on
- **Wireshark** — the cellular dissectors, and the 3GPP Diameter dictionary
  used to adjudicate the S6a command codes
- **Briceno, Goldberg, Wagner** — the A5/1 known-answer vector
- **Rupprecht, Kohls, Holz, Pöpper — "Breaking LTE on Layer Two"**, IEEE S&P 2019
  — aLTEr, the user-plane DNS redirection in `27_cellular_dns`
- **Rupprecht, Kohls, Holz, Pöpper — "ReVoLTE: Exploiting reused encryption
  keys to decrypt VoLTE calls"**, USENIX Security 2020 — `30_volte_ims`
- **Rupprecht, Kohls, Holz, Pöpper — "IMP4GT: IMPersonation Attacks in 4G
  NeTworks"**, NDSS 2020 — `30_volte_ims`
- **Hussain, Echeverria, Chowdhury, Li, Bertino — "Privacy Attacks to the 4G
  and 5G Cellular Paging Protocols Using Side Channel Information"**,
  NDSS 2019 — ToRPEDO and PIERCER, the paging attacks in `28_paging_track`

  The first draft of this README attributed the paging work to "Lee et al.,
  USENIX Security 2019" and called it "Piercer 2021". Both were wrong: the
  venue is NDSS 2019 and the paper introduces ToRPEDO, PIERCER and
  IMSI-Cracking together. One paper, three names for its parts.
- **scapy**, **numpy**, **scipy** — parsing and signal maths
