# IMSIsting module roster

Frozen. Every module below ships. The tag column is the function prefix
(see `MODULE_CONVENTIONS.md` §4). The C GUI gets one `ModuleDefinition` row
and one `module_registry_register()` call per module.

Module ids are the contract between the C app, the index generator and
`imsisting.sh`. Do not rename one without the others.

## Setup / radio

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `00_deps.sh` | `deps` | Dependency Manager | SYSTEM | SDR stacks, gnuradio, srsRAN, protocol tools; install/verify |
| `01_radio.sh` | `radio` | SDR / Radio Manager | SYSTEM | Detect HackRF/BladeRF/USRP/Lime/RTL, set gain/freq, IQ record |

## Recon (passive)

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `02_cell_recon.sh` | `crec` | Cell Recon | RECON | Scan GSM/UMTS/LTE/NR cells: ARFCN, PLMN, TAC/LAC, cell id, band, RSRP |
| `03_gsmtap.sh` | `gtap` | GSMTAP Passive | RECON | Live GSMTAP over UDP from gr-gsm/srsue; decode to pcap; identity harvest |
| `04_tower_map.sh` | `tmap` | Tower Survey / War-drive | RECON | GPS-tagged cell survey, CSV/KML/GeoJSON export, coverage map |

## 2G / GSM

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `10_gsm_air.sh` | `gair` | GSM Air Interface | GSM | BCCH/SI decode, paging analysis, A5/1-A5/3 cipher audit, IMSI exposure |
| `11_gsm_attack.sh` | `gatk` | GSM Attack | GSM | IMSI catcher logic, A5/1 downgrade, TMSI de-anonymisation, Kc recovery |

## 3G / UMTS

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `12_umts_air.sh` | `uair` | UMTS Air Interface | UMTS | UARFCN, SIB decode, RRC integrity, AKA relay analysis |

## 4G / LTE

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `13_lte_attach.sh` | `latt` | LTE Attach / NAS | LTE | NAS EMM/ESM encode-decode, attach forge, TAU, identity request/response |
| `14_lte_air.sh` | `lair` | LTE Air Interface | LTE | RRC/NAS over SDR, srsRAN eNB orchestration, SIB forging, paging |
| `15_lte_core.sh` | `lcore` | LTE Core (EPC) | LTE | Diameter S6a/S6d, GTP-C/GTP-U, S1-MME, MME/HLR vectors |

## 5G / NR

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `16_nr_air.sh` | `nair` | 5G NR Air Interface | 5G | gNB orchestration, NR RRC, SSB/CSI, RACH, SIB1 decode |
| `17_nr_core.sh` | `ncore` | 5G Core (SBA) | 5G | N2/N3/N4, SBA HTTP/2 NF discovery, SEPP, AUSF/UDM flows |
| `18_suci.sh` | `suci` | SUCI / SUPI | 5G | SUCI conceal/deconceal, ECIES profile A/B, home-network key derivation |
| `19_downgrade.sh` | `dwn` | Downgrade Attacks | 5G | 5G→4G→3G→2G steering, NEA/NIA null-cipher, reject-cause forging |

## SIM / eSIM / OTA

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `20_sim.sh` | `sim` | SIM / eSIM / OTA | SIM | APDU ISO-7816, USIM file read, OTA SMS TAR/SPI, eSIM profile ops |

## Analysis

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `21_pcap_analysis.sh` | `pcap` | Capture Analysis | ANALYSIS | Decode pcap/pcapng: SCTP, Diameter, GTP, NAS, RRC, NGAP, PFCP |
| `22_imsi_exposure.sh` | `imsi` | IMSI Exposure Audit | ANALYSIS | Correlate identities across captures, TMSI/IMSI map, exposure report |
| `23_cipher_audit.sh` | `caud` | Cipher Audit | ANALYSIS | Score negotiated ciphers per session, find null/downgraded bearers |

## Scanners

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `24_gsm_cve.sh` | `gcve` | GSM/UMTS CVE Kit | SCANNERS | Per-CVE probes and handoffs for 2G/3G stack bugs |
| `25_lte_cve.sh` | `lcve` | LTE CVE Kit | SCANNERS | LTE stack CVEs: baseband, NAS, ASN.1, Diameter |
| `26_nr_cve.sh` | `ncve` | 5G CVE Kit | SCANNERS | 5G NR / SBA / SUCI CVEs |

## Automation

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `30_killchain.sh` | `kchn` | Cellular Killchain | AUTOMATION | Chain recon → target select → vector → capture → report |

## Verb contract (all modules)

Every module implements, at minimum:

    --status-tsv     machine-readable state, always works
    --selftest       no-radio, no-root verification; exit 0 on pass
    --menu           interactive menu (launcher entry point)

Plus module-specific verbs. Verbs that perform a workflow rather than an
action print `status: handoff` and name the hardware required.

---

# v0.3 — the expansion

Ten new modules and five enhancements. Ids 40–49 continue the existing scheme.

| File | Tag | Menu name | Category | Owns |
|---|---|---|---|---|
| `40_baseband.sh` | `bbnd` | Baseband Research | SCANNERS | RRC/NAS fuzzing, corpus generation, crash triage |
| `41_vowifi.sh` | `vowi` | VoWiFi / ePDG | 4G / LTE | IKEv2/IPsec SWu, EAP-AKA, tunnel analysis |
| `42_femtocell.sh` | `femt` | Femtocell / HeNB | 4G / LTE | HeNB gateway, Iuh, local device assessment |
| `43_ussd.sh` | `ussd` | USSD | 2G / GSM | USSD strings, flash USSD, carrier command handling |
| `44_ta_geoloc.sh` | `tgeo` | TA Geolocation | RECON | Timing-advance ranging and trilateration |
| `45_sba_pivot.sh` | `sbap` | 5G SBA Pivot | 5G / NR | HTTP/2 mesh, NRF abuse, token handling |
| `46_ota_sms.sh` | `otasm` | OTA Binary SMS | SIM | TS 23.048 OTA construction, SPI/key audit |
| `47_li_probe.sh` | `lipr` | LI Discovery | ANALYSIS | X1/X2/X3 fingerprinting, LI-active detection |
| `48_ran_share.sh` | `rans` | RAN Sharing | 4G / LTE | MOCN/MORAN boundary, cross-operator leakage |
| `49_carrier_api.sh` | `capi` | Carrier API Audit | ANALYSIS | API surface discovery, authz and rate-limit testing |

## Enhancements to existing modules

| Module | Added |
|---|---|
| `31_ss7_map` | IPX/GRX pivot — interconnect lateral movement, not just MAP flows |
| `35_volte_ims` | IMS registration hijack, SIP REGISTER spoofing |
| `39_slicing` | SUPI correlation across slices — proving isolation failure by linking identities |
| `17_nr_core` | NRF token forgery, OAuth2 abuse within the SBA |
| `20_sim` | Offensive OTA split out to `46_ota_sms`; 20 keeps the reader/defensive side |

## Two scoping decisions

**`40_baseband` is a research instrument, not a weapon.** A working zero-click RCE
against named production modem firmware is an offensive payload with no
defensive framing; it is not something this tree ships. The module builds the
tooling that baseband *research* actually runs on — ASN.1-grammar-aware
mutation of RRC and NAS, corpus and test-case generation, GSMTAP-driven crash
triage, and the CVE catalogue — and points it at a device you own or a lab
modem. Where a CVE is documented, the module routes to a probe or a named
handoff exactly as `24`/`25`/`26` do. It does not emit a fire-and-forget
payload against live firmware.

**`49_carrier_api` audits an API, it does not enumerate subscribers.** Testing a
carrier's REST surface that you are authorised to test — your own account, a
bug-bounty scope, a contract — is ordinary assessment work. A tool that
mass-enumerates MSISDNs against a live portal is an account-takeover aid aimed
at real people, so the module builds the assessment half: endpoint and OpenAPI
discovery, authorisation-boundary testing, rate-limit and lockout probing,
response-differential analysis and credential-stuffing *resistance* checks. Bulk
enumeration of third-party accounts is not a verb it exposes.

## One worth stating plainly

**`46_ota_sms` is real protocol work with a real precondition.** TS 23.048 OTA
packets are how a carrier updates a SIM. Constructing and analysing them, and
testing them against a SIM you hold, is legitimate research — the S@T and WIB
classes are published. Affecting a SIM you do not hold requires that SIM's
KIc/KID, so the module is built for own-SIM and lab testing plus vulnerability
detection: SPI misconfiguration, weak key derivation, unauthenticated envelope
handling. Pushing to a live subscriber's SIM needs their keys and their
authorisation; the module says so in its own output.

---

# v0.4 — the gap closed

`40`–`49` are now on disk and all pass `tools/run-selftests.sh`. `52_wifioff`'s
selftest was repaired. Six new ids extend coverage into areas no module held.

## Taxonomy — grouped by function, not generation

The GUI (sidebar, dashboard, Stats) and the CLI menu now share one taxonomy
built on what a module *does* rather than which radio generation it touches.
The category column of `modules[]` in `native/src/main1.c` is the single
source; the launcher table and the generated index follow it.

| Category | Modules |
|---|---|
| SYSTEM | deps, radio, field kit, killchain |
| RECON | cell recon, GSMTAP, tower survey, NTN, non-3GPP |
| AIR INTERFACE | GSM, UMTS, LTE, NR, NB-IoT, GPRS/EDGE, sidelink |
| CORE NETWORK | attach/NAS, EPC, 5GC, SS7/MAP, DNS, slicing, VoWiFi, femto, USSD, SBA, RAN sharing, Wi-Fi offload |
| SIM / IDENTITY | SUCI, SIM/eSIM/OTA, SIM-swap defence, OTA SMS, STK |
| ATTACKS | GSM attack, downgrade, the three CVE kits, VoLTE/IMS, baseband, O-RAN |
| ANALYSIS | pcap, IMSI exposure, cipher audit, traffic, MAC, NAS signalling, LI, carrier API |
| RF / TRACKING | RF fingerprint, paging/Torpedo, jamming, TA geolocation, LPP |

Categories are contiguous in every table so a grouping header is emitted once.
Each module also carries a one-line description (`ModuleDefinition.desc`) shown
beneath its title on the module page.

## 40–49 — status

All ten are implemented to the full contract (self-locate header, `declare -F`
shims, TSV output, `status: handoff` where hardware is required, a `--selftest`
with known-answer assertions, and a loot redirect in the selftest). See
`docs/TOOLKIT_REFERENCE.md` §5 for the per-module summary. The `40`–`49` ids in
the table above are no longer plans — they are the modules.

## 53–58 — new

| File | Tag | Menu name | Category | Owns |
|---|---|---|---|---|
| `53_oran.sh` | `oran` | O-RAN / Open RAN | SCANNERS | E2/A1/O1/O2 interfaces, deployment + xApp assessment |
| `54_ntn.sh` | `ntn` | 5G NTN / Satellite | RECON | NTN Doppler, delay, TA, k_offset, SIB19 |
| `55_gprs.sh` | `gprs` | GPRS / EDGE | 2G / GSM | GEA ciphers, APN coding, PDP context, downgrade |
| `56_sidelink.sh` | `slnk` | NR Sidelink / V2X | 5G / NR | PC5 pools, SCI-1A, ITS certs, relay checks |
| `57_stk.sh` | `stk` | SIM Toolkit (STK) | SIM | TS 31.111 proactive commands and audit |
| `58_non3gpp.sh` | `n3g` | TETRA / DMR / GSM-R | RECON | Non-3GPP LMR structure, ciphers, classification |

## Scoping decisions in 53–58

**`53_oran` assesses a deployment; it does not load a rogue xApp.** The
xApp-authority model names the authority a RIC grants an xApp and flags an
unsigned app holding RAN control. Loading into a carrier RIC requires that
carrier's authorisation.

**`58_non3gpp` is receive-only.** Receiving public-safety traffic may itself be
restricted where you are, and the module says so. It demods nothing that needs
keys you are not entitled to.

**`47_li_probe` remains detection-only** and is listed under v0.3 above.
