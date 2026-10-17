# IMSIsting module roster

Frozen. Every module below ships. The tag column is the function prefix
(see `MODULE_CONVENTIONS.md` §4). The C GUI gets one `ModuleDefinition` row
and one `module_registry_register()` call per module.

Module ids are the contract between the C app, the index generator and
`imsisting.sh`. Do not rename one without the others.

**The numbering is contiguous: `00`–`56`, with no gaps, and the next module is
`57`.** Ids are ordered by domain so the menu reads in order, but they are not
banded any more — the ordering is a sequence, not a set of reserved ranges.

This was not always so. The ids were previously banded by decade — `00`–`05`,
`10`–`19`, `20`–`28`, `30`–`61` — which left `06`–`09` and `29` unused. Those
gaps were closed in one pass: everything from `10` to `28` shifted down by 4 and
everything from `30` up shifted down by 5, so that the empty `29` did not simply
relocate to `25`. The old-to-new mapping is mechanical (`10`→`06`, `11`→`07`,
`14`→`10`, `28`→`24`, `30`→`25`, `61`→`56`) and applies to module files, the
symbolic icons, and every reference in the tree.

Two consequences are worth stating, because neither is visible from the code:

- **Any id written down outside this tree is now stale.** That includes
  published notes, saved plans under `loot/`, and this project's own git history
  before the rename. Nothing inside the tree depends on the numbering, but an
  old id in prose has to be read through the mapping above — a note that says
  `38_jamming_detect` is talking about the file now called `33_jamming_detect`.
- **`docs/MODULE_ROSTER.md`, `imsisting.sh` and `native/src/module_index.c` must
  move together.** These are the three consumers of the id; a partial rename
  breaks the menu without breaking any single file's self-test.

No consumer indexes by number. `native/src/main1.c` matches on the id **string**
(`g_strcmp0(modules[i].id, module_id)`), and `imsisting.sh` keeps a separate
sequential menu `KEY` — its own comment states that `KEY` and `MODULE_ID` "are
NOT the same number and are not meant to be".

## Setup / radio

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `00_deps.sh` | `deps` | Dependency Manager | SYSTEM | SDR stacks, gnuradio, srsRAN, protocol tools; install/verify |
| `01_radio.sh` | `radio` | SDR / Radio Manager | SYSTEM | Detect HackRF/BladeRF/USRP/Lime/RTL, set gain/freq, IQ record |

## Recon (passive)

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `02_cell_recon.sh` | `crec` | Cell Recon | RECON | Scan GSM/UMTS/LTE/NR cells: ARFCN, PLMN, TAC/LAC, cell id, band, RSRP |
| `03_gsmtap.sh` | `gtap` | GSMTAP Live Feed | RECON | Live GSMTAP over UDP from gr-gsm/srsue; decode to pcap; identity harvest |
| `04_tower_map.sh` | `tmap` | Tower Survey / War-drive | RECON | GPS-tagged cell survey, CSV/KML/GeoJSON export, coverage map |

## 2G / GSM

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `06_gsm_air.sh` | `gair` | GSM Air Interface | RADIO | BCCH/SI decode, paging analysis, A5/1-A5/3 cipher audit, IMSI exposure |
| `07_gsm_attack.sh` | `gatk` | GSM Attack | RADIO | IMSI catcher logic, A5/1 downgrade, TMSI de-anonymisation, Kc recovery |

## 3G / UMTS

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `08_umts_air.sh` | `uair` | UMTS Air Interface | RADIO | UARFCN, SIB decode, RRC integrity, AKA relay analysis |

## 4G / LTE

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `09_lte_attach.sh` | `latt` | LTE Attach Forge | ACCESS | NAS EMM/ESM encode-decode, attach forge, TAU, identity request/response |
| `10_lte_air.sh` | `lair` | LTE Air Interface | RADIO | RRC/NAS over SDR, srsRAN eNB orchestration, SIB forging, paging |
| `11_lte_core.sh` | `lcore` | LTE Core (EPC) | CORE NETWORK | Diameter S6a/S6d, GTP-C/GTP-U, S1-MME, MME/HLR vectors |

## 5G / NR

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `12_nr_air.sh` | `nair` | 5G NR Air Interface | RADIO | gNB orchestration, NR RRC, SSB/CSI, RACH, SIB1 decode |
| `13_nr_core.sh` | `ncore` | 5G Core (SBA) | CORE NETWORK | N2/N3/N4, SBA HTTP/2 NF discovery, SEPP, AUSF/UDM flows |
| `14_suci.sh` | `suci` | SUCI Deconcealment | SIM / IDENTITY | SUCI conceal/deconceal, ECIES profile A/B, home-network key derivation |
| `15_downgrade.sh` | `dwn` | Downgrade Attacks | RADIO | 5G→4G→3G→2G steering, NEA/NIA null-cipher, reject-cause forging |

## SIM / eSIM / OTA

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `16_sim.sh` | `sim` | SIM / eSIM / OTA Attacks | SIM / IDENTITY | APDU ISO-7816, USIM file read, OTA SMS TAR/SPI, eSIM profile ops, COMP128-1 DPA model |

## Analysis

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `17_pcap_analysis.sh` | `pcap` | Capture Analysis | ANALYSIS | Decode pcap/pcapng: SCTP, Diameter, GTP, NAS, RRC, NGAP, PFCP |
| `18_imsi_exposure.sh` | `imsi` | IMSI Harvest | SIM / IDENTITY | Harvest and correlate identities across captures, TMSI/IMSI map, exposure report |
| `19_cipher_audit.sh` | `caud` | Cipher Audit | ANALYSIS | Score negotiated ciphers per session, find null/downgraded bearers |

## Scanners

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `20_gsm_cve.sh` | `gcve` | GSM/UMTS CVE Kit | EXPLOIT KITS | Per-CVE probes and handoffs for 2G/3G stack bugs |
| `21_lte_cve.sh` | `lcve` | LTE CVE Kit | EXPLOIT KITS | LTE stack CVEs: baseband, NAS, ASN.1, Diameter |
| `22_nr_cve.sh` | `ncve` | 5G CVE Kit | EXPLOIT KITS | 5G NR / SBA / SUCI CVEs |

## Automation

| File | Tag | Menu name | Category | Purpose |
|---|---|---|---|---|
| `25_killchain.sh` | `kchn` | Cellular Killchain | SYSTEM | Chain recon → target select → vector → capture → report |

## Verb contract (all modules)

Every module implements, at minimum:

    --status-tsv     machine-readable state, always works
    --selftest       no-radio, no-root verification; exit 0 on pass
    --menu           interactive menu (launcher entry point)

Plus module-specific verbs. Verbs that perform a workflow rather than an
action print `status: handoff` and name the hardware required.

---

# v0.3 — the expansion

Ten new modules and five enhancements. Ids 35–44 continue the existing scheme.

| File | Tag | Menu name | Category | Owns |
|---|---|---|---|---|
| `35_baseband.sh` | `bbnd` | Baseband Fuzzing | BASEBAND / DEVICE | RRC/NAS fuzzing, corpus generation, crash triage |
| `36_vowifi.sh` | `vowi` | VoWiFi / ePDG Attacks | ACCESS | IKEv2/IPsec SWu, EAP-AKA, tunnel analysis |
| `37_femtocell.sh` | `femt` | Small Cell / eNB Attacks | ACCESS | SCTP backhaul and S1AP bodies, Iuh legacy, CSG/PCI, local device assessment, live subscriber feed, armed SCTP association to an MME or HNB-GW |
| `38_ussd.sh` | `ussd` | USSD Forge | ACCESS | USSD strings, flash USSD, carrier command handling |
| `39_ta_geoloc.sh` | `tgeo` | TA Geolocation | TRACKING | Timing-advance ranging and trilateration |
| `40_sba_pivot.sh` | `sbap` | 5G SBA Pivot | CORE NETWORK | HTTP/2 mesh, NRF abuse, token handling |
| `41_ota_sms.sh` | `otasm` | OTA Binary SMS Attacks | SIM / IDENTITY | TS 23.048 OTA construction, SPI/key audit |
| `42_li_probe.sh` | `lipr` | LI Interception | INTERCEPT / CARRIER | X1/X2/X3 fingerprinting, LI-active detection |
| `43_ran_share.sh` | `rans` | RAN Sharing | ACCESS | MOCN/MORAN boundary, cross-operator leakage |
| `44_carrier_api.sh` | `capi` | Carrier API Abuse | INTERCEPT / CARRIER | API surface discovery, authz and rate-limit testing |

## Enhancements to existing modules

| Module | Added |
|---|---|
| `26_ss7_map` | IPX/GRX pivot — interconnect lateral movement, not just MAP flows |
| `30_volte_ims` | IMS registration hijack, SIP REGISTER spoofing |
| `34_slicing` | SUPI correlation across slices — proving isolation failure by linking identities |
| `13_nr_core` | NRF token forgery, OAuth2 abuse within the SBA |
| `16_sim` | Offensive OTA split out to `41_ota_sms`; 20 keeps the reader/defensive side |

## Two scoping decisions

**`35_baseband` is a research instrument, not a weapon.** A working zero-click RCE
against named production modem firmware is an offensive payload with no
defensive framing; it is not something this tree ships. The module builds the
tooling that baseband *research* actually runs on — ASN.1-grammar-aware
mutation of RRC and NAS, corpus and test-case generation, GSMTAP-driven crash
triage, and the CVE catalogue — and points it at a device you own or a lab
modem. Where a CVE is documented, the module routes to a probe or a named
handoff exactly as `24`/`25`/`26` do. It does not emit a fire-and-forget
payload against live firmware.

**`44_carrier_api` audits an API, it does not enumerate subscribers.** Testing a
carrier's REST surface that you are authorised to test — your own account, a
bug-bounty scope, a contract — is ordinary assessment work. A tool that
mass-enumerates MSISDNs against a live portal is an account-takeover aid aimed
at real people, so the module builds the assessment half: endpoint and OpenAPI
discovery, authorisation-boundary testing, rate-limit and lockout probing,
response-differential analysis and credential-stuffing *resistance* checks. Bulk
enumeration of third-party accounts is not a verb it exposes.

## One worth stating plainly

**`41_ota_sms` is real protocol work with a real precondition.** TS 23.048 OTA
packets are how a carrier updates a SIM. Constructing and analysing them, and
testing them against a SIM you hold, is legitimate research — the S@T and WIB
classes are published. Affecting a SIM you do not hold requires that SIM's
KIc/KID, so the module is built for own-SIM and lab testing plus vulnerability
detection: SPI misconfiguration, weak key derivation, unauthenticated envelope
handling. Pushing to a live subscriber's SIM needs their keys and their
authorisation; the module says so in its own output.

---

# v0.4 — the gap closed

`40`–`49` are now on disk and all pass `tools/run-selftests.sh`. `47_wifioff`'s
selftest was repaired. Six new ids extend coverage into areas no module held.

## Taxonomy — grouped by function, not generation

The GUI (sidebar, dashboard, Stats) and the CLI menu now share one taxonomy
built on what a module *does* rather than which radio generation it touches.
The category column of `modules[]` in `native/src/main1.c` is the single
source; the launcher table and the generated index follow it.

| Category | Modules |
|---|---|
| SYSTEM | deps, radio, field kit, killchain |
| RECON | cell recon, GSMTAP, tower survey |
| RADIO | GSM/UMTS/LTE/NR air, NB-IoT, GPRS/EDGE, sidelink, NTN, non-3GPP, GSM attack, downgrade, jamming |
| ACCESS | attach/NAS, slicing, VoWiFi, femto, USSD, RAN sharing, Wi-Fi offload |
| CORE NETWORK | EPC, 5GC, SS7/MAP, DNS, IMS/VoLTE, NAS signalling, SBA, O-RAN |
| SIM / IDENTITY | SUCI, SIM/eSIM/OTA, IMSI exposure, SIM-swap, OTA SMS, STK |
| BASEBAND / DEVICE | baseband fuzzing, baseband exploits, NR injection, DIAG/NV/EFS |
| TRACKING | RF fingerprint, paging/Torpedo, TA geolocation, LPP |
| ANALYSIS | pcap, cipher audit, traffic, MAC/RLC |
| EXPLOIT KITS | the three CVE kits |
| INTERCEPT / CARRIER | LI, carrier API |

Categories are contiguous in every table so a grouping header is emitted once.
Each module also carries a one-line description (`ModuleDefinition.desc`) shown
beneath its title on the module page.

## 35–44 — status

All ten are implemented to the full contract (self-locate header, `declare -F`
shims, TSV output, `status: handoff` where hardware is required, a `--selftest`
with known-answer assertions, and a loot redirect in the selftest). See
`docs/TOOLKIT_REFERENCE.md` §5 for the per-module summary. The `40`–`49` ids in
the table above are no longer plans — they are the modules.

## 48–53 — new

| File | Tag | Menu name | Category | Owns |
|---|---|---|---|---|
| `48_oran.sh` | `oran` | O-RAN / xApp Attacks | CORE NETWORK | E2/A1/O1/O2 interfaces, deployment + xApp assessment |
| `49_ntn.sh` | `ntn` | 5G NTN / Satellite | RADIO | NTN Doppler, delay, TA, k_offset, SIB19 |
| `50_gprs.sh` | `gprs` | GPRS / EDGE | RADIO | GEA ciphers, APN coding, PDP context, downgrade |
| `51_sidelink.sh` | `slnk` | NR Sidelink / V2X | RADIO | PC5 pools, SCI-1A, ITS certs, relay checks |
| `52_stk.sh` | `stk` | STK Attacks | SIM / IDENTITY | TS 31.111 proactive commands and audit |
| `53_non3gpp.sh` | `n3g` | TETRA / DMR / GSM-R | RADIO | Non-3GPP LMR structure, ciphers, classification |

## Scoping decisions in 48–53

**`48_oran` assesses a deployment; it does not load a rogue xApp.** The
xApp-authority model names the authority a RIC grants an xApp and flags an
unsigned app holding RAN control. Loading into a carrier RIC requires that
carrier's authorisation.

**`53_non3gpp` is receive-only.** Receiving public-safety traffic may itself be
restricted where you are, and the module says so. It demods nothing that needs
keys you are not entitled to.

**`42_li_probe` remains detection-only** and is listed under v0.3 above.

## 54–56 — new

| File | Tag | Menu name | Category | Owns |
|---|---|---|---|---|
| `54_baseband_exploit.sh` | `bexp` | Baseband Exploits | BASEBAND / DEVICE | L1/L2 malformed PDUs, 5G control-plane forgery, CVE catalogue, the TX path |
| `55_nr_inject.sh` | `nrj` | 5G NR Injection | BASEBAND / DEVICE | RNTI arithmetic, MAC-NR, DCI/TBS/RAR, Gold descrambling, injection exploits |
| `56_baseband_diag.sh` | `bbdg` | Baseband NV/EFS | BASEBAND / DEVICE | Qualcomm DM/DIAG framing, NV and EFS2 read/write, state-info identity decode, AT/device I/O |

## Scoping decisions in 54–56

**`56_baseband_diag` has no `--set-imsi`, and that is a decision, not a gap.**
DIAG reaches baseband NV/EFS, and the module can write any NV item or any EFS
path (`--nv-write`, `--efs-write`). What it will not do is pretend to know
*which* item holds the IMSI: no published item-number-to-semantics table exists,
and the item numbers that circulate trace to forum posts rather than to a
specification or an implementation. Hardcoding them would put a confident,
wrong write on the wire — the same failure mode as the S702 work, where 270
assertions encoded the same unverified values. So the module ships discovery
(`--nv-scan`, `--efs-walk`, `--efs-stat`, `--state-info`) and read-back
verification (`--state-info-parse`) instead of a setter that might be pointed at
the wrong item. On LTE/5G the network-visible IMSI comes from the USIM during
attach anyway, so the baseband NV identity is largely a CDMA/legacy path; the
SIM-side reader is `16_sim.sh`, and the core-side forger is
`11_lte_core.sh --gtp-csr-forge`.

**`56_baseband_diag` is ungated by design.** `--nv-write` and `--efs-write` are
raw protocol primitives, so gating them would only obscure what they do. The
module says so in its own `--status` (`GATING none`) and in `--help`.

