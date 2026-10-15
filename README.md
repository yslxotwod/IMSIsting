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

### The testing discipline

There is exactly one rule that matters in this tree, and it was learned the hard
way three separate times:

> **A selftest that asserts the value your code already produces proves only
> that your code is deterministic. It cannot catch a wrong constant.**

Three real cases, all of which passed their own tests while being wrong:

- **A5/1** passed self-consistent tests with the wrong feedback taps. It was
  caught only by asserting the published Briceno/Goldberg/Wagner vector.
- **The NR-ARFCN raster** was implemented as a flat 5 kHz. The selftest passed
  because the single ARFCN it checked was a band edge, where the offset term is
  zero and a wrong raster still gives the right answer.
- **The S6a command-code table** was shifted by one from 317 upward and passed
  270 assertions that encoded the same wrong values. It was caught against
  Wireshark's own 3GPP Diameter dictionary.

So: where a published vector, spec table or independent implementation exists,
the selftest asserts against that and cites it in a comment. See
`docs/MODULE_CONVENTIONS.md` §16.

---

## Modules

### System
| Module | Description |
|---|---|
| `00_deps` | Inspect the cellular toolchain and install what is missing |
| `01_radio` | Enumerate SDRs, report per-band capability, record IQ |
| `05_field_kit` | RF pre-flight, honesty verification of every radio verb, synthetic GSMTAP source |

### Recon (passive)
| Module | Description |
|---|---|
| `02_cell_recon` | Survey GSM/UMTS/LTE/NR cells; ARFCN and PLMN maths |
| `03_gsmtap` | Live GSMTAP over UDP, and offline decode of a GSMTAP capture |
| `04_tower_map` | GPS-tagged cell survey with CSV/KML/GeoJSON export |

### 2G / GSM
| Module | Description |
|---|---|
| `10_gsm_air` | BCCH/SI decode, paging analysis, cipher audit, A5/1 keystream |
| `11_gsm_attack` | IMSI catcher sequence, A5/1 downgrade, TMSI de-anonymisation |

### 3G / UMTS
| Module | Description |
|---|---|
| `12_umts_air` | UARFCN, SIB decode, RRC integrity (UIA), AKA relay analysis |

### 4G / LTE
| Module | Description |
|---|---|
| `13_lte_attach` | NAS EMM/ESM encode-decode, BCD IMSI/IMEI, attach forge |
| `14_lte_air` | RRC/SIB decode, paging frame maths, srsRAN eNB orchestration |
| `15_lte_core` | Diameter S6a/S6d, GTP-C/GTP-U, S1-MME, EPC vectors |

### 5G / NR
| Module | Description |
|---|---|
| `16_nr_air` | NR-ARFCN, SSB/MIB/SIB1, RACH, gNB orchestration |
| `17_nr_core` | N2/N3/N4, SBA service bus, NGAP, PFCP, 5G-AKA |
| `18_suci` | SUCI conceal/deconceal, ECIES profile A/B, HKDF, MSIN BCD |
| `19_downgrade` | Cross-generation steering, null cipher, reject-cause analysis |

### SIM
| Module | Description |
|---|---|
| `20_sim` | ISO-7816 APDU, USIM files, OTA (TS 23.048), eSIM RSP |

### Analysis
| Module | Description |
|---|---|
| `21_pcap_analysis` | pcap/pcapng dissection with a self-contained reader |
| `22_imsi_exposure` | Identity harvest, TMSI→IMSI correlation, exposure scoring |
| `23_cipher_audit` | Negotiated cipher scoring and downgrade detection |

### Scanners
| Module | Description |
|---|---|
| `24_gsm_cve` | 2G/3G stack CVE kit, probe or handoff per id |
| `25_lte_cve` | LTE stack CVE kit |
| `26_nr_cve` | 5G/NR and 5GC CVE kit |

### Automation
| Module | Description |
|---|---|
| `30_killchain` | Chain module verbs into repeatable runs with a result report |

### v0.2 — the wider attack surface
| Module | Description |
|---|---|
| `27_traffic_analysis` | Flow features, website fingerprinting, defence detection |
| `28_rf_fingerprint` | IQ fingerprinting, CFO/IQ-imbalance, CSI motion |
| `31_ss7_map` | MAP/TCAP, SS7 flows, GRX and the roaming interconnect |
| `32_cellular_dns` | DNS over the bearer, the aLTEr sequence, spoof detection |
| `33_paging_track` | Paging occasions, Torpedo, Piercer |
| `34_mac_layer` | MAC/RLC/PDCP, RNTI tracking, the user-plane integrity gap |
| `35_volte_ims` | ReVoLTE keystream reuse, IMP4GT, IMS/SIP |
| `36_sim_defense` | SIM-swap detection and defence (defensive only) |
| `37_nas_signaling` | NAS load measurement and signalling-storm detection |
| `38_jamming_detect` | Jamming detection and characterisation (defensive only) |
| `39_slicing` | S-NSSAI, slice selection, isolation testing |

### v0.3 — transport, core and identity
| Module | Description |
|---|---|
| `40_baseband` | RRC/NAS fuzzing, corpus generation, crash triage, baseband CVE catalogue |
| `41_vowifi` | IKEv2/IPsec SWu, EAP-AKA, ePDG attach flow, tunnel weakness detection |
| `42_femtocell` | HeNB/Iuh decode, CSG audit, local device assessment |
| `43_ussd` | GSM 03.38 7-bit codec, service codes, USSD flow and tunnelling analysis |
| `44_ta_geoloc` | Timing-advance ranging and multilateration with GDOP |
| `45_sba_pivot` | NF discovery, token audience/scope checks, HTTP/2 SBI, pivot mapping |
| `46_ota_sms` | TS 23.048 OTA construction, SPI/key audit, replay checking |
| `47_li_probe` | LI interface fingerprinting and activity indicators (detection only) |
| `48_ran_share` | MOCN/MORAN boundary, per-PLMN leakage, S1AP/NGAP PLMN checks |
| `49_carrier_api` | API surface discovery, authz boundary and rate-limit testing |

Two of these are scoped deliberately, and the reason is in the module header:

- **`40_baseband` is a research instrument, not a weapon.** It builds the tooling
  baseband research runs on — grammar-aware mutation, corpus generation, crash
  triage — and points it at a device you own or a lab modem. It does not ship a
  fire-and-forget over-the-air payload against live firmware.
- **`49_carrier_api` audits an API you are authorised to test.** Endpoint
  discovery, authorisation-boundary and rate-limit testing, response-differential
  analysis. It exposes no bulk subscriber-enumeration verb, because that is an
  account-takeover aid rather than an assessment.

`47_li_probe` detects and fingerprints lawful-intercept interfaces; it does not
receive or decode intercepted content.

### v0.4 — the gap closed

Eleven more ids, extending coverage into places none of the above reached —
narrowband IoT, positioning, Wi-Fi offload, satellite access, land mobile
radio, the SIM's own application layer, and the RAN edges.

| Module | Description |
|---|---|
| `50_iot` | NB-IoT and Cat-M1: NPRACH, NPSS/NSSS, SIB1-NB and NPRFCN |
| `51_lpp` | LTE Positioning Protocol: procedure codes, header codec, position-forgery detection |
| `52_wifioff` | Wi-Fi offload and LWA: ePDG FQDN, certificate validation, LWA configuration |
| `53_oran` | O-RAN interfaces, deployment assessment and xApp-authority modelling |
| `54_ntn` | Non-terrestrial access: Doppler, round-trip delay, TA, k_offset and the SIB19 fields |
| `55_gprs` | GPRS/EDGE packet-switched: GEA ciphering, APN coding, PDP context, downgrade detection |
| `56_sidelink` | NR sidelink on PC5: resource pools, SCI-1A, ITS certificates and relay checks |
| `57_stk` | TS 31.111 proactive commands: build, parse and audit for silent off-device actions |
| `58_non3gpp` | TETRA, DMR and GSM-R structure, ciphers and band classification |
| `59_baseband_exploit` | L1/L2 malformed-PDU construction, 5G control-plane forgery, baseband CVE catalogue |
| `60_nr_inject` | NR RNTI tracking, MAC-NR framing, descrambling and the injection exploit set |

Two of these carry the same kind of scope note as `40_baseband` and
`49_carrier_api` above:

- **`53_oran` assesses a deployment; it does not load a rogue xApp.** The
  xApp-authority model names the authority a RIC grants an xApp and flags an
  unsigned app holding RAN control. Loading into a carrier RIC requires that
  carrier's authorisation.
- **`58_non3gpp` is receive-only.** Receiving public-safety traffic may itself be
  restricted where you are, and the module says so. It demods nothing that needs
  keys you are not entitled to.

The per-module detail, including which tag each module exposes and what it owns,
is in [`docs/MODULE_ROSTER.md`](docs/MODULE_ROSTER.md).

The full attack-to-module mapping is in
[`docs/ATTACK_COVERAGE.md`](docs/ATTACK_COVERAGE.md).

---

## Hardware

You need an SDR for anything that touches the air. Nothing on this list is
bundled, and none of it has been verified on this machine.

| Purpose | Device |
|---|---|
| GSM receive / gr-gsm | RTL-SDR (receive only), HackRF, BladeRF, USRP, LimeSDR |
| GSM transmit (IMSI catcher, downgrade) | HackRF / BladeRF / USRP / LimeSDR — **not** RTL-SDR |
| LTE / 5G NR | USRP B210, BladeRF, LimeSDR; srsRAN supports a limited device set |
| SIM / eSIM | A PC/SC reader, or a programmable card such as sysmoUSIM-SJS1 |
| GPS (surveys) | Any gpsd-supported receiver |

An RTL-SDR cannot transmit. The transmit-gated verbs detect this and refuse
rather than failing silently, because a silent failure here is the worst
outcome in the tree.

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

The 56 module icons are compiled into the binary as a GResource, published under
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

---

## Legal

**Use this on networks you own or have written permission to test.**

That is not boilerplate. Several modules interfere with radio spectrum or
reconfigure network elements. Doing that to a network you do not control is a
crime in most jurisdictions regardless of why you are doing it, and
transmitting on licensed spectrum is regulated everywhere.

Two modules are deliberately defensive — `36_sim_defense` detects SIM-swap
attempts rather than performing them, and `38_jamming_detect` measures
interference rather than causing it. If you were looking for the other half of
either, that is why it is not here.

If you are not sure whether you are allowed to test something, you are not.
