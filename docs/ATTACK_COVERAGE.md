# Attack coverage — the 27 filings, and where each one lands

Frozen scope for IMSIsting v0.2. Every attack in the docket maps to exactly one
owning module. A module may own several attacks; an attack never has two owners,
because two owners means two implementations that disagree.

Module ids are the contract (see `MODULE_ROSTER.md`). `NEW` marks a module not
in the v0.1 roster.

## Passive

| # | Attack | Owner module | What is actually built |
|---|---|---|---|
| P1 | IMSI catching | `22_imsi_exposure` (detect) · `11_gsm_attack` (lab emitter) | Detection: scan a capture for the IMSI-request / identity-response signature and flag it. Lab: the emitter sequence, hardware-gated |
| P2 | TMSI deanonymisation | `22_imsi_exposure` | Correlate a TMSI/GUTI to an IMSI across a capture via forced-identity and location-update bindings |
| P3 | Downgrade detection | `19_downgrade` | Reject-cause, cipher-change and missing-measurement signals across 2G/3G/4G/5G |
| P4 | Traffic analysis | `27_traffic_analysis` **NEW** | Flow inference from encrypted traffic: burst timing, direction, volume, inter-arrival |
| P5 | Website fingerprinting | `27_traffic_analysis` **NEW** | Page-identification from packet size and timing sequences; classifier + evaluation harness |
| P6 | RF fingerprinting | `28_rf_fingerprint` **NEW** | Device identification from IQ: transient, CFO, IQ imbalance, EVM signature |
| P7 | CSI sniffing | `28_rf_fingerprint` **NEW** | Channel-state side-channel extraction and motion/occupancy inference |
| P8 | Paging channel monitoring | `33_paging_track` **NEW** | Paging occasion computation and paging-request capture per subscriber |
| P9 | MAC-layer passive | `21_pcap_analysis` · `34_mac_layer` **NEW** | Layer-2 observation, RNTI tracking, scheduling-pattern inference |

## Offensive

| # | Attack | Owner module | What is actually built |
|---|---|---|---|
| O1 | IMSI catcher (Stingray) | `11_gsm_attack` · `14_lte_air` · `16_nr_air` | Full sequence construction and the reselection/race logic; transmit path is a named-hardware plan file |
| O2 | GTP exploitation | `15_lte_core` | GTP-C/GTP-U encode, decode, IE walk, TEID handling; injection is a lab-testbed plan |
| O3 | SS7 exploitation | `31_ss7_map` **NEW** | MAP/TCAP encode-decode: SRI, SRI-SM, PSI, ATI, ULR, SAI (auth-vector retrieval), ISD, registerSS/activateSS; the flows; SIGTRAN (SCTP+M3UA) build and decode; lab STP plan |
| O4 | Diameter attacks | `15_lte_core` | S6a/S6d AIR/ULR/CLR/IDR/DSR/PUR encode-decode; forged-ULR registration move; lab HSS plan |
| O5 | SIM swapping | `36_sim_defense` **NEW** | See the scoping note below |
| O6 | Baseband exploitation | `24_gsm_cve` · `25_lte_cve` · `26_nr_cve` | CVE catalogue with probe-or-handoff per id; ASN.1 length-oracle and vector analysis |
| O7 | RRC reconfiguration | `14_lte_air` · `16_nr_air` | RRC message construction, handover and reconfiguration sequences, SIB forging |
| O8 | DNS spoofing over cellular | `32_cellular_dns` **NEW** | Resolver discovery, response injection at the cellular bearer, capture-side detection |
| O9 | GRX exploitation | `31_ss7_map` **NEW** | Roaming-exchange reachability, GSN address harvesting, interconnect trust model |
| O10 | aLTEr | `32_cellular_dns` **NEW** | The LTE layer-2 DNS redirection sequence and the check that exposes it |
| O11 | ReVoLTE | `35_volte_ims` **NEW** | VoLTE keystream reuse: sniff the first call, recover the second; key-reuse detector |
| O12 | IMP4GT | `35_volte_ims` **NEW** | Identity-mapping impersonation: the mutual-auth bypass sequence and its preconditions |
| O13 | Torpedo | `33_paging_track` **NEW** | Paging-occasion collision exploitation; paging storm amplifier; detection |
| O14 | Piercer | `33_paging_track` **NEW** | IMSI recovery by paging correlation, with its timing budget |
| O15 | NAS flooding DoS | `37_nas_signaling` **NEW** | Lab rate harness and signalling-storm detection; see the scoping note |
| O16 | RAN jamming | `38_jamming_detect` **NEW** | See the scoping note below |
| O17 | 5G NR beam manipulation | `16_nr_air` | Beam/SSB sweep analysis, beam-index inference, measurement-report manipulation |
| O18 | Network slicing escape | `39_slicing` **NEW** | Slice-ID enumeration, cross-slice isolation testing, NSSAI manipulation |
| O19 | PFCP exploitation | `17_nr_core` | PFCP session establishment, PDR/FAR/QER/URR encode-decode, UPF reachability |
| O20 | Roaming interface abuse | `31_ss7_map` **NEW** | Inter-operator trust model, SEPP/delegated-discovery exposure, IPX reachability |

## Two filings deliberately scoped

### O5 — SIM swapping → `36_sim_defense`

SIM swapping is not a technical attack. It is a carrier-rep social-engineering
play, and a toolkit that ships a pretexting script for it is shipping an
identity-theft guide aimed at a real person's phone number. There is no research
value in that direction, so this module is built the other way round:

- **Detection**: the signals that mark a port already in progress — SIM
  re-registration on a new IMSI/IMEI pairing, sudden OTA burst, authentication
  failure streak, simultaneous registration on two networks.
- **Defence**: carrier-side controls (port freeze, number lock, PIN/PUK state per
  `EF_AD`), and what a subscriber can actually enforce.
- **Technical adjacency**: remote SIM provisioning and eSIM profile integrity —
  the part of the space that *is* protocol work, owned by `20_sim`.

If the module cannot detect or defend an action, it does not document how to
perform it.

### O16 — RAN jamming → `38_jamming_detect`

A transmitter whose only function is to raise the noise floor is illegal to
operate in most jurisdictions regardless of intent, and it takes down emergency
calls along with the target. That is not a capability this tree ships.

The module builds the side that a security team needs and that is legal:

- **Detection and measurement**: noise-floor shift, PDCCH/PBCH decode-failure
  rate, RSRP/RSRQ collapse with no handover, uplink BLER spike — the profile that
  distinguishes jamming from congestion.
- **Characterisation**: narrowband vs barrage, duty cycle, targeted ARFCN vs band.
- **Regulatory position**: which regulator to notify, what evidence they need,
  why the operator's own counters are the admissible record.

## Roll-up

| | v0.1 | v0.2 | total |
|---|---|---|---|
| Modules | 23 | 10 NEW | 33 |
| Attacks owned | 12 | 15 | 27 |

New in v0.2: `27_traffic_analysis`, `28_rf_fingerprint`, `31_ss7_map`,
`32_cellular_dns`, `33_paging_track`, `35_volte_ims`, `36_sim_defense`,
`37_nas_signaling`, `38_jamming_detect`, `39_slicing`.
