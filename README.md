# IMSIsting

A GTK4 cellular security toolkit for Linux, with a full CLI behind it. Shell
modules covering 2G/GSM, 3G/UMTS, 4G/LTE and 5G/NR, plus passive analysis over
captures and per-generation CVE kits.

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

---

## Modules

**Every row carries an attack status, and it is the honest one.** The axis is not
"does the module have an attack verb" — a verb that prints a plan file and a verb
that prints protocol octets look identical in `--help`, and telling them apart is
the whole point of this column. The axis is **does it compute the attack's bytes**.

| Status | Meaning |
|---|---|
| `built` | It constructs the attack's protocol bytes for real and performs every step that is software. The radio or network hop is a named handoff (`status: handoff`, hardware named) — deliberate, per `docs/MODULE_CONVENTIONS.md` §9, not a gap. |
| `built · TX` | As `built`, and it also has a real transmit verb: the frame goes to an external command you supply (`BEXP_TX_CMD` / `NRJ_TX_CMD`), behind an armed guard. |
| `partial` | Some offensive verbs compute real bytes; others are prose, an arithmetic model, or a plan. The description says which. |
| `plan` | No offensive computation at all. The vector is a plan file naming the hardware or testbed it needs. |
| `none` | No offensive side, by design — decode, analysis, or defence. Not a gap; the module does not claim otherwise. |

The long-form audit behind these verdicts, with a `file:line` for every
classification, is in [`docs/OFFENSIVE-GAP-ANALYSIS.md`](docs/OFFENSIVE-GAP-ANALYSIS.md).

### System
| Module | Description | Attack |
|---|---|---|
| `00_deps` | Inspect the cellular toolchain and install what is missing | `none` |
| `01_radio` | Enumerate SDRs, report per-band capability, record IQ | `none` |
| `05_field_kit` | RF pre-flight, honesty verification of every radio verb, synthetic GSMTAP source | `none` |

### Recon (passive)
| Module | Description | Attack |
|---|---|---|
| `02_cell_recon` | Survey GSM/UMTS/LTE/NR cells; ARFCN and PLMN maths | `none` |
| `03_gsmtap` | Live GSMTAP over UDP, and offline decode of a GSMTAP capture | `none` |
| `04_tower_map` | GPS-tagged cell survey with CSV/KML/GeoJSON export | `none` |

### 2G / GSM
| Module | Description | Attack |
|---|---|---|
| `10_gsm_air` | BCCH/SI decode, paging analysis, cipher audit, A5/1 keystream | `none` |
| `11_gsm_attack` | IMSI catcher sequence, A5/1 downgrade, TMSI de-anonymisation | `built` |

### 3G / UMTS
| Module | Description | Attack |
|---|---|---|
| `12_umts_air` | UARFCN, SIB decode, RRC integrity (UIA), AKA relay analysis | **`none`** |

**`12_umts_air` is the honest hole in the tree.** Every other generation has a
rogue-base-station module: GSM has `11_gsm_attack`, LTE has `13_lte_attach` and
`14_lte_air`, NR has `16_nr_air`. UMTS has a decoder and nothing else — no
`--forge-*`, no encoder, no offensive verb of any kind. It is the only generation
with no IMSI-catcher path, and the missing primitive is already sitting unused in
the tree: `11_gsm_attack --f9-mac` is KASUMI f9 (UIA1) verified against all three
official TS 35.203 §5 vectors, and `12_umts_air --mac-input` already emits the
fields f9 consumes. Wiring them into a `--forge-rrc` is about thirty lines. It
has not been done yet.

### 4G / LTE
| Module | Description | Attack |
|---|---|---|
| `13_lte_attach` | NAS EMM/ESM encode-decode, BCD IMSI/IMEI, attach forge | `built` |
| `14_lte_air` | RRC/SIB decode, paging frame maths, srsRAN eNB orchestration | `built` |
| `15_lte_core` | Diameter S6a/S6d, GTP-C/GTP-U, S1-MME, EPC vectors | `plan` |

`14_lte_air` writes both srsRAN configs and execs `srsenb` — a real rogue eNB, as
far as software goes. `15_lte_core` is the opposite case: four finished
Diameter/GTP encoders that emit real octets, and **no transport at all** — no
SCTP, GTP or TCP client anywhere in the module. Nothing is sent even if you point
it at a live core.

### 5G / NR
| Module | Description | Attack |
|---|---|---|
| `16_nr_air` | NR-ARFCN, SSB/MIB/SIB1, RACH, gNB orchestration | `built` |
| `17_nr_core` | N2/N3/N4, SBA service bus, NGAP, PFCP, 5G-AKA | `plan` |
| `18_suci` | SUCI conceal/deconceal, ECIES profile A/B, HKDF, MSIN BCD | `built` |
| `19_downgrade` | Cross-generation steering, null cipher, reject-cause analysis | `built` |

`17_nr_core` decodes NGAP/PFCP/GTP-U for real but every one of its four vectors is
a plan file; there is no network client.

### SIM
| Module | Description | Attack |
|---|---|---|
| `20_sim` | ISO-7816 APDU, USIM files, OTA (TS 23.048), eSIM RSP | `plan` |

`20_sim` builds a real ISO-7816 C-APDU and decodes OTA/IMSI/ICCID, but all four of
its offensive paths — OTA replay to a UICC, programmable-SIM write, eSIM profile
install, live APDU session — are `status: handoff` plan files. There is no PC/SC
or CCID call and no APDU exchange loop in the module.

### Analysis
| Module | Description | Attack |
|---|---|---|
| `21_pcap_analysis` | pcap/pcapng dissection with a self-contained reader | `none` |
| `22_imsi_exposure` | Identity harvest, TMSI→IMSI correlation, exposure scoring | `built` |
| `23_cipher_audit` | Negotiated cipher scoring and downgrade detection | `none` |

`23_cipher_audit` detects a downgrade; it does not perform one — there is no
Security Mode Command injector and no A5/0 forcing anywhere in it.

### Scanners
| Module | Description | Attack |
|---|---|---|
| `24_gsm_cve` | 2G/3G stack CVE kit, probe or handoff per id | `plan` |
| `25_lte_cve` | LTE stack CVE kit | `plan` |
| `26_nr_cve` | 5G/NR and 5GC CVE kit | `plan` |

All three CVE kits have the same contract: a **probe** (a fingerprint, capability
check or config parse — it reports what it observed and never claims a device is
exploitable) or a **handoff**. None of the three contains an exploit primitive — no
GTP-C injector, no Diameter request builder, no HTTP/2 SBA client, no
malformed-ASN.1 generator. `24_gsm_cve` is worse than the other two on one point:
its A5/1 and A5/2 "key recovery" verbs are threshold comparisons
(`(( seconds >= 120 ))`, `(( frames < 4 ))`), not recovery. Nothing recovers a key.

### Automation
| Module | Description | Attack |
|---|---|---|
| `30_killchain` | Chain module verbs into repeatable runs with a result report | `none` |

### v0.2 — the wider attack surface
| Module | Description | Attack |
|---|---|---|
| `27_traffic_analysis` | Flow features, website fingerprinting, defence detection | `none` |
| `28_rf_fingerprint` | IQ fingerprinting, CFO/IQ-imbalance, CSI motion | `none` |
| `31_ss7_map` | MAP/TCAP decode and forge, SIGTRAN both ways, GRX/roaming interconnect | `partial` |
| `32_cellular_dns` | DNS over the bearer, the aLTEr sequence, spoof detection | `partial` |
| `33_paging_track` | Paging occasions, Torpedo, Piercer | `partial` |
| `34_mac_layer` | MAC/RLC/PDCP, RNTI tracking, the user-plane integrity gap | `none` |
| `35_volte_ims` | ReVoLTE keystream reuse, IMP4GT, SIP REGISTER spoofing | `partial` |
| `36_sim_defense` | SIM-swap detection and defence (defensive only) | `none` |
| `37_nas_signaling` | NAS load measurement and signalling-storm detection | `plan` |
| `38_jamming_detect` | Jamming detection and characterisation (defensive only) | `none` |
| `39_slicing` | S-NSSAI, slice selection, isolation testing | `partial` |

Where the `partial` verdicts land, exactly:

- **`31_ss7_map`** builds complete, byte-exact MAP/TCAP MSUs for the operations
  an interconnect test actually needs: `--build-ati`, `--build-sri`,
  `--build-sri-sm`, `--build-sai` (authentication-vector retrieval),
  `--build-psi`, `--build-ulr`, `--build-isd`, `--build-register-ss` and
  `--build-activate-ss`. It also speaks the modern encapsulation in both
  directions — `--build-m3ua` wraps any of those MSUs in a send-ready M3UA DATA
  message, and `--decode-sigtran` walks the SCTP common header, the DATA chunk,
  M3UA and then MTP3/SCCP. What it still has no transport for is the SS7/STP hop
  itself: it produces and parses the bytes, it does not put them on a link, and
  that is the plan.
- **`32_cellular_dns`** builds a real DNS query and response, and its aLTEr
  sequence is modelled. It has no packet rewriter and no send path; `--alter`
  rewrites the module's own record, not traffic on the bearer.
- **`33_paging_track`** computes the paging occasion and builds a real
  `--build-paging-req`. `--paging-tx` is honest-fail without a radio.
- **`35_volte_ims`** is the widest split in the tree: ReVoLTE keystream recovery
  and the forged `--register-spoof` REGISTER are real, computed code; IMP4GT is a
  `--imp4gt-model` arithmetic model, and `--sip-flood` is a rate calculation, not
  a sender.
- **`39_slicing`** encodes and decodes S-NSSAI for real and evaluates isolation
  from observed config. The slice-escape vector itself is a plan.

`27_traffic_analysis`, `28_rf_fingerprint` and `34_mac_layer` are `none` in the
offensive sense: they are passive measurement and detection. `27` will fingerprint
traffic and `28` will fingerprint a radio — both are analysis of a capture you
already hold, and neither emits a frame.

### v0.3 — transport, core and identity
| Module | Description | Attack |
|---|---|---|
| `40_baseband` | RRC/NAS fuzzing, corpus generation, crash triage, baseband CVE catalogue | `built` |
| `41_vowifi` | IKEv2/IPsec SWu, EAP-AKA, ePDG attach flow, tunnel weakness detection | `built` |
| `42_femtocell` | HeNB/Iuh decode, CSG audit, local device assessment | `partial` |
| `43_ussd` | GSM 03.38 7-bit codec, service codes, USSD flow and tunnelling analysis | `built` |
| `44_ta_geoloc` | Timing-advance ranging and multilateration with GDOP | `partial` |
| `45_sba_pivot` | NF discovery, token audience/scope checks, HTTP/2 SBI, pivot mapping | `partial` |
| `46_ota_sms` | TS 23.048 OTA construction, SPI/key audit, replay checking | `built` |
| `47_li_probe` | LI interface fingerprinting and activity indicators (detection only) | `none` |
| `48_ran_share` | MOCN/MORAN boundary, per-PLMN leakage, S1AP/NGAP PLMN checks | `none` |
| `49_carrier_api` | API surface discovery, authz boundary and rate-limit testing | `none` |

The `partial` rows, so the status is not a mystery:

- **`42_femtocell`** encodes CSG identities and parses TR-069 config for real. The
  rogue-HeNB vector is a plan — there is no HeNB stack in the module.
- **`44_ta_geoloc`** does the ranging and multilateration arithmetic that locates a
  UE, and it is real arithmetic with GDOP. It has no measurement front end: the
  timing-advance values it solves from come from a capture or a plan.
- **`45_sba_pivot`** builds HTTP/2 frames byte-exactly, including a real Rapid
  Reset pair (`--rapid-reset`), and audits a JWT's audience and scope. It has no
  HTTP/2 client, so nothing reaches an NF.

Two more honest notes, since they are the kind of thing a status column can hide:

- **`40_baseband` has no emitter at all**, by construction: `modules/40_baseband.sh:446`
  says "It emits no over-the-air payload". It is the mutator, the ASN.1 codec and
  the triage harness. Sending a corpus is `59_baseband_exploit`'s job.
- **`49_carrier_api` is the thinnest offensive module in the tree.** It enumerates
  an API surface and tests rate limits; there is no bulk subscriber-enumeration
  verb and no account-takeover path.
- `47_li_probe` fingerprints lawful-intercept interfaces; it does not receive or
  decode intercepted content.

### v0.4 — the gap closed

Eleven more ids, extending coverage into places none of the above reached —
narrowband IoT, positioning, Wi-Fi offload, satellite access, land mobile
radio, the SIM's own application layer, and the RAN edges.

| Module | Description | Attack |
|---|---|---|
| `50_iot` | NB-IoT and Cat-M1: NPRACH, NPSS/NSSS, SIB1-NB and NPRFCN | `plan` |
| `51_lpp` | LTE Positioning Protocol: procedure codes, header codec, position-forgery detection | `plan` |
| `52_wifioff` | Wi-Fi offload and LWA: ePDG FQDN, certificate validation, LWA configuration | `none` |
| `53_oran` | O-RAN interfaces, deployment assessment and xApp-authority modelling | `none` |
| `54_ntn` | Non-terrestrial access: Doppler, round-trip delay, TA, k_offset and the SIB19 fields | `plan` |
| `55_gprs` | GPRS/EDGE packet-switched: GEA ciphering, APN coding, PDP context, downgrade detection | `partial` |
| `56_sidelink` | NR sidelink on PC5: resource pools, SCI-1A, ITS certificates and relay checks | `partial` |
| `57_stk` | TS 31.111 proactive commands: build, parse and audit for silent off-device actions | `built` |
| `58_non3gpp` | TETRA, DMR and GSM-R structure, ciphers and band classification | `none` |
| `59_baseband_exploit` | L1/L2 malformed-PDU construction, 5G control-plane forgery, baseband CVE catalogue | `built · TX` |
| `60_nr_inject` | NR RNTI tracking, MAC-NR framing, descrambling and the injection exploit set | `built · TX` |
| `61_baseband_diag` | Qualcomm DM/DIAG framing, NV and EFS2 read/write, state-info identity decode, AT/device surface | `built` |

The four modules here that a status column would flatter if left unexplained:

- **`50_iot`** decodes NPRACH, NPSS/NSSS and SIB1-NB for real and computes band
  and NPRFCN maths. Its two offensive verbs (`fake-cell`, `nprach-flood`) are
  `--plan` files naming an SDR, an NB-IoT-capable stack and a sacrificial module.
- **`51_lpp`** was relabelled rather than implemented, and the README says so
  elsewhere: LPP position records are ASN.1 PER (TS 37.355) inside LPPa/NRPPa, so
  a byte-offset parser cannot reach a latitude. `--detect-forgery` now says
  `status: handoff` and names `tshark -Y lpp`, instead of printing a verdict it
  never computed.
- **`54_ntn`** is arithmetic: Doppler, round-trip delay, TA and k_offset from the
  SIB19 fields. The vector is a plan.
- **`55_gprs`** encodes GEA parameters, APN and PDP IEs for real and detects a GEA
  downgrade. It does not perform one — no attach injector.
- **`56_sidelink`** builds SCI-1A and resource-pool descriptors and checks relay
  configuration. PC5 transmission is a plan.

`53_oran` assesses a deployment rather than changing it: the xApp-authority model
names what authority a RIC grants an xApp and flags an unsigned app holding RAN
control. Loading into a carrier RIC is not something the module does.
`58_non3gpp` is receive-only — it decodes TETRA/DMR/GSM-R structure and classifies
bands, and demods nothing that needs keys it does not have.

`59_baseband_exploit` and `60_nr_inject` are the only two modules with a real
transmit verb, and it is deliberately indirect: the frame hex goes to a command
*you* supply (`BEXP_TX_CMD`, `NRJ_TX_CMD`) on stdin, behind an armed guard, and
with no command set they exit 3 rather than pretending to radiate.

The per-module detail, including which tag each module exposes and what it owns,
is in [`docs/MODULE_ROSTER.md`](docs/MODULE_ROSTER.md).

The full attack-to-module mapping is in
[`docs/ATTACK_COVERAGE.md`](docs/ATTACK_COVERAGE.md).

---

## Hardware

Nothing on this list is bundled with the tree, and none of it has been verified
on the machine this was built on — that machine has no SDR attached at all. What
follows is what each module's own code asks for, in its own words, together with
what the parts actually cost.

### What is on this machine right now

`05_field_kit --guard-check` and `01_radio` probe for these, and the answers are
not impressive:

| Tool | Present? | Consequence |
|---|---|---|
| `bladeRF-cli` | yes (`/usr/bin/bladeRF-cli`) | `01_radio` writes a state file with serial `unknown` — no device is connected |
| `hackrf_transfer` | yes | usable as a `BEXP_TX_CMD` / `NRJ_TX_CMD` wrapper, with a HackRF attached |
| `SoapySDRUtil` | yes | device enumeration only; no radio behind it |
| `grgsm_scanner` | yes (`/usr/bin/grgsm_scanner`) | `02_cell_recon --scan gsm` takes its full ~30 s window and then fails honestly: no SDR |
| `srsenb`, `srsue`, `gnb` | no | `14_lte_air` and `16_nr_air` generate configs and report the missing binary |
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

- Unlocks: `02_cell_recon`, `04_tower_map`, `10_gsm_air`, `21_pcap_analysis`,
  `27_traffic_analysis`, `28_rf_fingerprint`, `38_jamming_detect`, and the
  passive half of `33_paging_track` / `34_mac_layer`.
- Does not unlock: anything with an `--inject`, `--send`, `--start` or
  `--paging-tx`. Those verbs detect the absence and refuse — they do not fail
  silently, which is the point of the status column above.

### Tier 2 — one transmit-capable SDR (~$300–500)

A **HackRF One** (~$300) or **Nuand bladeRF 2.0 micro** (~$500). Half-duplex is
enough for every single-radio attack in the tree.

- Unlocks: `11_gsm_attack` (IMSI catcher, A5/1 downgrade, TMSI de-anonymisation),
  `14_lte_air` (rogue eNB — it writes srsRAN configs and execs `srsenb`),
  `16_nr_air` (rogue gNB), `13_lte_attach`, `19_downgrade`, `33_paging_track
  --paging-tx`, and every `59_baseband_exploit` / `60_nr_inject` frame via
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

- `59_baseband_exploit --plan` names: "two SDRs (USRP B210 or X310) or one SDR
  plus an amplifier; a lab UE/modem you own; GPSDO for dual-radio timing".
- A **USRP B210** (~$1,100) is the usual choice; an **X310** costs several times
  that. Add a **GPSDO** so the two radios share a clock, an amplifier, a
  sacrificial UE or module you are willing to brick, and a faraday enclosure or
  licensed test cell so the injection does not leave the bench.
- Software side: `srsRAN` or `OpenAirInterface` for the gNB, plus Sni5Gect- or
  5Ghoul-style injection tooling. The tree builds the frames; it does not ship
  the gNB stack.

### Tier 4 — emulation instead of radio (no SDR, but you must own the device)

`59_baseband_exploit --emulate` runs firmware in an emulator rather than over the
air, which is the cheapest way to do baseband work at all. It names the tools by
name: **FirmWire** (Samsung/MediaTek basebands), **srlabs hexagon_fuzz**
(Qualcomm Hexagon), **BaseSAFE**, and **BaseBridge**. You still need the baseband
image from a device you own, and enough RAM to run it.

### SIM and smart-card work

A **PC/SC reader** (any CCID reader, ~$15) for `20_sim`'s USIM file work. For
writing profiles you need a programmable card such as a **sysmoUSIM-SJS1** or a
**5G test USIM**; `20_sim`'s four offensive paths currently stop at a plan file
naming one, because there is no APDU exchange loop in the module to drive it.

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
```

Or launch the built binary directly:

```bash
./native/builddir/imsisting-gui
```

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

That distinction runs the other way too, and it is the one the [Modules](#modules)
section now answers per module: **a verb existing is not the same claim as the
attack being implemented.** A module that prints a plan file naming an SDR looks
exactly like one that prints protocol octets, unless you read what it emits. The
`Attack` column says which, and the two genuine holes in the tree are named
there — `12_umts_air` has no offensive side at all, and `24_gsm_cve`,
`25_lte_cve` and `26_nr_cve` contain no exploit primitive.

---

## How it is put together

The GUI is a view over the scripts in `modules/`. Nothing is locked behind it:

```bash
./modules/21_pcap_analysis.sh --summary capture.pcap
./modules/18_suci.sh --parse-suci <hex>
./modules/15_lte_core.sh --decode-diameter <hex>
```

Every module has `--selftest`. Run it first when something misbehaves — it
often identifies the problem with no hardware attached.

```bash
./tools/run-selftests.sh          # every module
./tools/check-paths.sh            # every path and table entry resolves
./tools/check-verbs.sh            # verbs reachable from the GUI
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

`docs/MODULE_CONVENTIONS.md` is the contract every module follows, and it is
worth reading before writing one. It is not style guidance — each rule exists
because ignoring it caused a real bug. The sections on the TSV empty-field trap,
the bash traps that produce confidently wrong output, and known-answer testing
are the ones that have already earned their place.

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
  — aLTEr, the user-plane DNS redirection in `32_cellular_dns`
- **Rupprecht, Kohls, Holz, Pöpper — "ReVoLTE: Exploiting reused encryption
  keys to decrypt VoLTE calls"**, USENIX Security 2020 — `35_volte_ims`
- **Rupprecht, Kohls, Holz, Pöpper — "IMP4GT: IMPersonation Attacks in 4G
  NeTworks"**, NDSS 2020 — `35_volte_ims`
- **Hussain, Echeverria, Chowdhury, Li, Bertino — "Privacy Attacks to the 4G
  and 5G Cellular Paging Protocols Using Side Channel Information"**,
  NDSS 2019 — ToRPEDO and PIERCER, the paging attacks in `33_paging_track`

  The first draft of this README attributed the paging work to "Lee et al.,
  USENIX Security 2019" and called it "Piercer 2021". Both were wrong: the
  venue is NDSS 2019 and the paper introduces ToRPEDO, PIERCER and
  IMSI-Cracking together. One paper, three names for its parts.
- **scapy**, **numpy**, **scipy** — parsing and signal maths
