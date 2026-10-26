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
./imsisting.sh --tui         # launch the TUI (modules listed by their menu keys)
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
| **Map** | One permanent map for everything the toolkit located: cells, TA rings, geolocated frames and areas from `loot/map/layers/*.tsv`, drawn over a bundled Natural Earth basemap. Pan, zoom, and toggle layers. |
| **Fleet** | Remote nodes and what each one measured: class, transport, role, capabilities, last seen and how far behind its event stream is. Survey a node, collect a stream window, copy it into the case, or dispatch a module to run there. |
| **Stats** | Module and collection counts, a health line, and where the toolkit is thick. |
| **Notifications** | What the tree decided to tell you, oldest first. |
| **Help** | How the tree fits together and how to drive it. |
| **Settings** | Environment facts, plus dependency and SDR probe actions. |
| **Workflows** | Saved chains, run from the panel. |

Module tabs appear alongside these and can be closed; the permanent tabs
cannot.

#### Themes

**Settings → Interface → Theme** switches the whole desk between two palettes:
**Night**, the blue-black palette the app was drawn in, and **Ember**, the same
desk one temperature over — near-black surfaces with a warm bias and a single
ember accent.

A theme is one stylesheet and it restates colours, nothing else. It is not
maintained by hand: `tools/gen-theme.py` derives it from `native/resources/style.css`
(the base sheet), so a change there reaches both, and a theme that falls behind
shows up as a diff instead of as one stale panel. The derivation warms the
greys, turns the accent family ember, deepens the surfaces, and deliberately
leaves every status hue alone — green still means ok and red still means danger,
because a theme that recolours them makes the honest chips lie. GTK's own
widgets (entries, popovers, tooltips, switches) are restated at the end of the
generated file, since the base sheet never spoke for them and the system theme's
version kept its navy field in a warm window.

After changing the generator:

```bash
tools/gen-theme.py            # write native/resources/theme-ember.css
tools/check-theme.sh          # packaged? generated? in step with the base sheet?
cd native && ninja -C builddir
```

`tools/check-theme.sh` exists because a theme that is *not* packaged fails
silently: GTK draws the base sheet and the dropdown still reads "Ember". The
GUI's `--selftest` asserts the same thing (`gui-theme-ember PASS packaged`).

### A node as a source

A survey does not have to happen on the machine in front of you. Any module
that reads the air can be pointed at a registered node, and the node answers
with what it actually measured:

```
modules/02_cell_recon.sh --node desk      # survey through the node, store rows here
modules/03_gsmtap.sh --node desk          # fetch its newest capture and decode it
modules/17_pcap_analysis.sh --node desk   # list the captures that node holds
modules/18_imsi_exposure.sh --node desk   # audit the node's newest capture
tools/node_source.py support              # what each transport can answer
tools/node_source.py cells desk           # the node's cells, in the store's table
tools/node_source.py events desk          # the node's spool, as event rows
tools/node_source.py captures desk        # the node's capture store
```

Fetched captures land in `captures/nodes/<name>/`, so every existing verb works
on a local path afterwards and the store keeps both files.

What a node can honestly deliver depends on its transport, and the toolkit says
so rather than filling the gap: `local` and `ssh` nodes run a real survey,
`adb` handsets report their own serving cell and neighbours with withheld
fields marked, `serial`/`qmi`/`mbim` modems report one serving cell and are
labelled that way, and `diag`/`sms` refuse with the missing clause named. Every
row carries `source node:<name>:<transport>:<kind>`, so a table never loses
where a cell was heard. A node with an empty store is a handoff (exit 3), not
an empty survey.

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
3 Stats, 4 Notifications, 5 Help, 6 Settings, 7 Workflows, 8 Map, 9 Fleet):

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

## Modules

Sixty-one modules, grouped by the categories the application itself uses, so this list and the
Dashboard cannot drift apart. Every verb a module documents has a control on its page, and every
page answers in the card that asked: a value list for one record, a list of records with per-row
Copy for many.

### System

| Module | Description |
|---|---|
| `00_deps` | Inspect the cellular toolchain and install what is missing |
| `01_radio` | Enumerate SDRs, report per-band capability, record IQ |
| `05_field_kit` | RF pre-flight, honesty verification of every radio verb, synthetic GSMTAP source |
| `25_killchain` | Chain module verbs into repeatable recorded runs: fourteen builtin chains, a status line per step, and an evidence manifest whose hashes a second party can re-derive |
| `59_remote_node` | Remote cellular nodes: identity, measured capabilities, captured events and dispatch permissions, with eight transports (ssh/local/adb/serial/qmi/mbim/diag/sms) that each say what they can honestly deliver |

### Recon

| Module | Description |
|---|---|
| `02_cell_recon` | GSM/LTE/NR cell survey and neighbour discovery |
| `03_gsmtap` | Live GSMTAP feed, header codec, per-type demultiplex to the owning decoder |
| `04_tower_map` | GPS-tagged cell survey with CSV, KML and GeoJSON export |

### Radio — the air interface and the cells

| Module | Description |
|---|---|
| `06_gsm_air` | BCCH/CCCH decode, paging groups, A5/1 keystream, identity exposure |
| `07_gsm_attack` | The 2G attack surface: forged BCCH, the IMSI catcher sequence with its LAPDm dialogue, A5/1 downgrade forcing, TMSI deanonymisation, Kc recovery. C1 must beat the real cell and the forged command must land in the right LAPDm window; whether a handset accepts a clone depends on the handset and the location area |
| `08_umts_air` | UTRAN decode and SIB fields, forged RRC setup/reject/paging and a real SECURITY MODE COMMAND, the TS 25.212 BCH chain, a WCDMA downlink carrier with CPICH and both sync channels, SIB1/SIB3/SIB5 through the FACH chain onto an S-CCPCH in the frames the MIB schedules, MM identity request, the uplink RACH as chips, and the uplink transport chain with its TFCI encoder. `--duplex-loop` puts both halves on one port and measures the desense; nothing here receives UMTS uplink and answers it in one process |
| `10_lte_air` | LTE air interface: MIB/SIB decode, DCCH builders, CMAS/ETWS warning messages (SIB10-12), srsRAN eNB orchestration |
| `12_nr_air` | SSB/MIB/SIB1, PRACH, beam sweep, SSB waveform, gNB orchestration |
| `15_downgrade` | Cross-generation steering: forged reject causes, SIB1 forgery, null-cipher analysis |
| `33_jamming_detect` | Jamming detection and characterisation, and eleven waveform shapes including PSS/SSS/PBCH, PRACH, PRS, PUCCH and GPS C/A, built on the first invocation with the disclaimer as information rather than a lock. `lte-ssb` is refused by name: pss+sss+pbch already cover it |
| `45_iot` | NB-IoT: MIB-NB, SIB1-NB and SIB2-NB through the generated PER codec, NPSS/NSSS, NPRACH symbol-group hopping checked against TS 36.211 10.1.6.1, the attach and CE-level walk, and `--freq-plan`, which computes the raster position from an anchor carrier and refuses without one because the NREF column is not in this tree |
| `49_ntn` | Non-terrestrial access: Doppler, RTT, timing advance, k_offset, SIB19 both alone and inside its carrier, hostile ephemeris arithmetic, TA-to-position, and behind the satellite — the feeder carrier's six-layer chain, the encryption each layer was measured to carry, the receive-kit cost, a triage of an already-parsed feeder capture, and the GMR-1/GMR-2 satellite-phone air interface as a reference rather than a decoder |
| `50_gprs` | GPRS/EDGE: GEA0/GEA3/GEA4 against published vectors, GEA1/GEA2 recovery cost, GEA5 admitted by name, APN and PDP coding |
| `51_sidelink` | NR sidelink on PC5: resource pools, SCI-1A, ITS certificates, relay checks, BSM kinematics, pseudonym lifecycle and kinematic linkage |
| `53_non3gpp` | TETRA, DMR and GSM-R structure, ciphers, vocoder bit budgets, and the bands you can transmit on legally |
| `57_evil_twin` | An LTE or NR cell built from a survey row: it radiates through a TX-capable SDR under your licence or keeps every peer on loopback, and every run ends by collecting what the phone handed over — NAS identities out of the logs and the capture, each row marked observed or advertised |
| `60_overshadow` | AdaptOver and overshadowing: the subframe map, the timing budget against the 2 ms queue window and the cyclic prefix, the uplink and downlink power budgets, four detectors, and a plan that never keys a radio |

### Access — the attach, the edge and the offload

| Module | Description |
|---|---|
| `09_lte_attach` | NAS EMM/ESM encode-decode, BCD IMSI/IMEI, attach forging, identity-exposure detection, TS 24.008 GMM/SM for the 3G side, and the FlashCatch sequence — a catcher that takes the IMSI without ever causing an outage |
| `34_slicing` | S-NSSAI codec, slice selection, isolation testing, 5QI and TSN assistance |
| `36_vowifi` | IKEv2/IPsec SWu, EAP-AKA', ePDG attach, certificate assertions |
| `37_femtocell` | Small-cell and eNB assessment: CSG/PCI conflicts, the S1 backhaul, Iuh, the ten-item attack surface, certificate posture, and RANAP for the macro Iu-CS side |
| `38_ussd` | USSD request forge, response decode, SS/MMI command surface |
| `43_ran_share` | Network sharing: PLMN leaks and MOCN configuration review |
| `47_wifioff` | Wi-Fi offload: ePDG FQDN, EAP exchange byte for byte, certificate assertions |

### Core network and interconnect

| Module | Description |
|---|---|
| `11_lte_core` | EPC: Diameter S6a/S6d, GTP-C, GTP-U, S1AP, GTP-in-GTP, MBMS session start |
| `13_nr_core` | 5G SBA: NGAP (with a probe that asks an AMF four questions), PFCP session hijack, 5G-GUTI, NAS COUNT and re-key walks, Kairos interleaving and context binding |
| `26_ss7_map` | Ten MAP operations, TCAP/SCCP/MTP3/M3UA/SGsAP, four decoders, response builders (`--build-response sai-ack` returns real triplets and an EPC quintet) and dialogue pairing, M3UA over a real SCTP association, `--lab`, and `tools/ss7_responder.py` as a referee. An ATI answer is refereed too, which is how the untagged `ageOfLocationInformation` TS 29.002 17.7.6 requires is told apart from a tagged one. No TDM MTP2, and reach still needs an assigned point code |
| `27_cellular_dns` | DNS over the bearer, the aLTEr sequence, spoof detection |
| `30_volte_ims` | ReVoLTE keystream reuse, IMP4GT, UMTS COUNT-C reuse and two-stream XOR, SIP REGISTER spoofing, IMS registration hijack, and a call leg that carries G.711 audio |
| `32_nas_signaling` | NAS rate and procedure mix, storm detection, and seventeen pre-authentication message builders |
| `40_sba_pivot` | Pivot across the service-based architecture: HTTP/2 SBI framing, NRF discovery and an inventory walk, OAuth2 token audit, the N32 roaming bridge, and a cloud-metadata callback |
| `48_oran` | O-RAN interfaces, E2SM, xApp authority, A1 policy poisoning, QoS policy |

### SIM and identity

| Module | Description |
|---|---|
| `14_suci` | the oracle's signal set is structural, not cryptographic: it joins pairs on octets, the ephemeral key, a cleartext MSIN, the MSIN's length class or a repeated AUTN, so two rounds that differ in every one of those fields come back not-linked even when a cryptanalysis of the concealment would join them. The card side of the 5G-AKA proof: `--hn-auth` produces the network half (XRES*, HXRES*, KAUSF, KSEAF) and the HRES* a handset would return is the same clause on RES*, but the RES the proof needs comes off a physical USIM — a virtual one is not built here. Also not built: KAMF (the SEAF/AMF derivation over ABBA) and the Nausf service itself, which is HTTP/2 JSON on this tree's own key material |
| `16_sim` | SIM AKA (COMP128 1/2/3, Milenage, TUAK), USIM files, EF_AD, OTA parsing, eSIM profiles, ES9+, SGP.32 eIM/packaging, a subscriber key store, an AKA responder and the AUTS resync responder |
| `18_imsi_exposure` | IMSI harvest and TMSI/IMSI correlation over a capture |
| `31_sim_defense` | SIM swap: risk scoring, the six detection signals, plus APDU and port-out artefacts |
| `41_ota_sms` | OTA binary SMS: TPDU packing, S@T push with its byte code, SMPP 3.4 with optional TLVs, submit_multi, data_sm and the TLS port, an HTTP gateway send, and 3GPP2 originating-address spoofing |
| `52_stk` | TS 31.111 proactive commands: build, parse, RUN AT, and an audit for the silent off-device actions a card can ask for |
| `58_suci_catcher` | 5G pre-authentication identity capture: gNB and AMF slice build, catcher plan, live SUCI read, classifier and corpus, NAS and RRC codecs, and an audit of what a Devilray-style target would notice |

### Analysis — captures, ciphers, traffic

| Module | Description |
|---|---|
| `17_pcap_analysis` | From-scratch pcap reader: GSMTAP, Diameter, NGAP, S1AP, GTP, PFCP, RTP |
| `19_cipher_audit` | Negotiated cipher audit, downgrade detection, authentication oracle |
| `23_traffic_analysis` | Flow features, application classification, reference store, call records |
| `29_mac_layer` | MAC/RLC/PDCP decode, RNTI tracking, grant cadence, the user-plane integrity gap |

### Tracking, positioning and RF

| Module | Description |
|---|---|
| `24_rf_fingerprint` | IQ fingerprinting, CFO/IQ imbalance, transients, CSI motion |
| `28_paging_track` | Paging occasions for LTE and UTRAN, the Torpedo and Piercer models, storm and flapping detection, the AdaptOver keep-awake detector and its sample-exact wake schedule |
| `39_ta_geoloc` | Timing-advance ranging, multi-cell trilateration, cell-range estimation, and the UTRAN side: RTT in chips, Rx-Tx, and the hyperbola each anchor contributes |
| `46_lpp` | UTDOA is LPPa, not LPP, so it is stated as a handoff instead of encoded as the wrong protocol |

### Baseband and device

| Module | Description |
|---|---|
| `35_baseband` | RRC/NAS mutation, corpus generation, crash triage, DIAG framing, the transmit handoff, and `--modulate`, which maps a payload onto the LTE grid as cf32 samples — QPSK on the grid with no coding, CRC or DCI, so it is samples rather than a message a chipset decodes |
| `54_baseband_exploit` | Catalogued baseband CVEs with reachability checks, L2 frame builders |
| `55_nr_inject` | NR random access, MAC/DCI, link-layer sequences, catalogued exploits |
| `56_baseband_diag` | Qualcomm DM/DIAG framing, NV items, EFS, identity and AT surface |

### Exploit kits — catalogued CVEs

| Module | Description |
|---|---|
| `20_gsm_cve` | Catalogued GSM/UMTS CVEs with reachability checks: where each one needs you to stand, and the standing claim that no exploit primitive is shipped for it |
| `21_lte_cve` | 98 catalogued LTE/5G stack CVEs, filed into the same class views as this tree's own vectors, with reachability and message families built from each code pattern |
| `22_nr_cve` | Catalogued 5G NR, SBA and SUCI CVEs, the published NGAP and NAS entries beside them, and the same reachability split between a probe and a handoff |

### Intercept and carrier

| Module | Description |
|---|---|
| `42_li_probe` | Lawful-interception interfaces and posture signals, the TS 33.108 HI1 PDUs an interception is built from (BER, semi-octet BCD), and this module's own X3/HI3 envelope. HI1's Notification carries no target identity and no host:port, so those are printed as `not_encoded` rather than dropped, and nothing is delivered to an ADMF |
| `44_carrier_api` | Carrier API surface from the OpenAPI 3 document (servers, paths, schemes), a four-case authorisation matrix per operation, JWT audit (`alg=none`, expiry, audience), token-bucket rate arithmetic, a differential between two response captures (new/changed/removed), credential-stuffing resistance controls scored by severity, a report and plan skeleton, and request rendering that writes one concrete request per operation plus an ordered subscriber sequence to a run file — it builds and stops, opening no socket. The one gated verb, `--execute`, runs that run file against an API you own and reports a 2xx answer to a deny row as `unauthorised_success` |

## The attack inventory

The [Modules](#modules) section answers *what each module is*. This section answers
the other question directly: **what attacks this tree contains**, and what each one
computes rather than describes. Where an attack needs a transmitter, the sentence
says so; where a piece is missing, it names the missing piece instead of implying
the attack runs end to end.

### Identity capture

| Attack | Module | What exists |
|---|---|---|
| IMSI catcher — GSM | `07_gsm_attack` | The full catcher sequence and a forged BCCH carrier a handset can camp on. The attack needs a receiver beside the transmitter and licensed spectrum; the transmit verb is there and the handoff is named. |
| IMSI catcher — LTE | `09_lte_attach`, `10_lte_air` | NAS EMM attach forging, BCD IMSI/IMEI, the identity-request sequence, and srsRAN eNB orchestration. |
| **IMSI catcher that causes no outage (FlashCatch)** | `09_lte_attach` | `--flashcatch` drives the published WiSec 2025 sequence through the real responder: an attach/TAU request naming an unresolvable GUTI is answered with an Identity Request *instead of a reject*, so the IMSI arrives in two messages and nothing tells the UE to delete its context (TS 24.301 4.4.4.2 is why it answers at all). Three consecutive failed authentications then bar the cell for 300 s (TS 36.304 5.3.1), and the UE walks back to the legitimate cell **keeping its keys and its TMSI** — the linkability the paper describes. The naive path (reject cause 10, up to 25 s reselect) is printed beside it, the paper's own measurements are kept in a separate row, and `--flashcatch-detect` reads a NAS log for the same shape: an IMSI asked for before any establishment request, and three failures with no security mode command between. |
| IMSI catcher — NR | `12_nr_air` | SSB/MIB/SIB1 construction, RACH handling, gNB orchestration, and the SSB written as samples. |
| SUCI de-concealment | `14_suci` | X25519 and P-256 profile A/B conceal and de-conceal, HKDF, MSIN BCD, all computed. |
| Be your own home network | `14_suci`, `16_sim` | `--hn-create` mints a home-network profile (PLMN, routing indicator, concealment scheme and the private key), `--hn-deconceal` resolves an arriving SUCI to an IMSI with it, and `--hn-auth` looks the subscriber up in the `16_sim` store, runs 5G-AKA and prints the vector the serving network expects — XRES*, HXRES*, KAUSF and KSEAF per TS 33.501 A.4–A.6, with the KDF key CK‖IK and XRES* as the rightmost 128 bits. `--hn-serve` answers `SUCI`/`AUTH`/`SHOW` lines on stdin so a fake cell can talk to it over a pipe. |
| 5G-AKA linkability oracle | `14_suci` | `--link-oracle` reads a file of observed SUCIs (optionally with the AUTN the network was handed) and judges every pair: linked or not, and which signal joined it — the SUCI octets, the ephemeral key, a cleartext MSIN, the MSIN's length class, or an AUTN given to two rounds. It separates the fields every subscriber of one network shares (scheme, key id, routing indicator) from the ones that identify a subscriber. `--link-demo` builds that fixture on the host's own home network and shows all five shapes. |
| eSIM profile to device linkability | `16_sim`, `14_suci`, `18_imsi_exposure` | A profile can be moved between devices, so the question is not which IMSI a device holds but whether two sightings are the same handset. The linkability work is the oracle: it joins observations on the fields that survive a profile swap and refuses to join on the ones that do not. |
| eIM / IPA management-plane takeover | `16_sim` | The SGP.32 management plane — eIM, IPA, the profile state machine and the ES10 commands a card accepts — with the boundary stated: what a captured management session can and cannot reach, and which parts are refused by name because the standard gates them (TS 55.251/55.252 licence-gated material stays named, not guessed). |
| TMSI → IMSI deanonymisation | `07_gsm_attack`, `18_imsi_exposure` | Correlation across a capture via forced-identity and location-update bindings, with a confirm step that needs a second observation. |
| Piercer (IMSI by paging correlation) | `28_paging_track` | The paging-occasion maths and the published model, with the correlation step kept separate from the claim. |
| UTRAN paging harvest | `28_paging_track` | PICH/S-CCPCH occasion arithmetic per identity (cycle, NP, PI index), the RRC answer each state produces, and the correlation between a page and the identity the UE disclosed. |
| ePDG / EAP-AKA' identity exposure | `36_vowifi`, `47_wifioff` | The Wi-Fi calling attach in IKEv2: the decorated NAI a handset sends (`0<IMSI>@nai.epc.mnc…`), what it discloses in the clear before any key exists, the pseudonym-versus-permanent-identity question, IKEv2 fragmentation and its reassembly ambiguity, and the ePDG discovery path (NAPTR/SRV, then the FQDN). The certificate assertions on both ends are checked; nothing here terminates a real ePDG. |
| SIM swap and port-out | `31_sim_defense` | Risk scoring over the six detection signals the standards and operators use, plus the APDU and port-out artefacts the swap leaves behind — the defensive half of an attack that needs the operator, not the air. |

### Cipher and downgrade

| Attack | Module | What exists |
|---|---|---|
| A5/1 keystream | `06_gsm_air`, `07_gsm_attack` | Asserted against the published Briceno/Goldberg/Wagner vector. A5/2 is present for testing and its brokenness is stated. |
| A5/1 downgrade | `07_gsm_attack` | The forcing sequence is constructed; putting it on the air is the same licensed-spectrum handoff as the catcher. |
| Cross-generation steering / null cipher | `15_downgrade` | Reject-cause construction, SIB1 forgery, and cipher-change analysis across all four generations. |
| UTRAN ciphering and integrity selection | `08_umts_air` | A real RRC SECURITY MODE COMMAND on DL-DCCH: transaction id plus the ciphering and integrity capability bitmaps, verified against Wireshark's dissector both ways. It is the message that turns UEA0/UIA1 on a forged cell — and the one that shows what a downgraded cell offers. |
| ReVoLTE keystream reuse | `30_volte_ims` | Key-reuse detection, recovery, and the model of what two ciphertexts under one keystream give. |
| UMTS keystream reuse | `30_volte_ims` | COUNT-C as HFN‖CFN, an overlap test on two calls under one CK, the two-stream XOR and the known-plaintext recovery behind it. |
| GEA downgrade and ciphering — GPRS/EDGE | `50_gprs` | GEA3 and GEA4 compute against nine published vectors (TS 55.217/55.218/55.226), GEA0 is the identity, GEA1/GEA2 are named as broken in the literature and prohibited, GEA5 admitted by name as licence-gated; APN and PDP IEs encode for real. |
| GEA1/GEA2 recovery cost | `50_gprs` | The published cryptanalysis turned into arithmetic: 65 keystream bits, 9 ciphertext octets, 2^40 and 2^45 guesses, and the memory figure that decides whether it is a laptop or a cluster. No gamma is ever printed. |
| Cipher audit and authentication oracle | `19_cipher_audit` | Scores the negotiated cipher, detects a downgrade, reads the cause tables against what each proves, and recovers the SQN a UE conceals in AUTS. |

### Signalling forgery — NAS, RRC and SIB

| Attack | Module | What exists |
|---|---|---|
| NAS pre-authentication messages | `32_nas_signaling` | Seventeen messages built as octets — Attach/TAU/Service reject, Identity Request, Authentication Request/Reject/Failure, Security Mode Command/Reject in EPS and 5GS — each checked against tshark. The NAS-MAC and AUTN are refused rather than placed at an unconfirmed offset. |
| TS 24.008 GPRS/GMM and session management | `09_lte_attach` | The 3G message set built and parsed from the octets: GMM and SM bodies, the four IE formats (type-1 through type-4) with their length rules, and the PD-discriminator table that makes `0x41` read as ATTACH REQUEST or ACTIVATE PDP CONTEXT REQUEST depending on the protocol it arrived under. |
| RRC reconfiguration, release and reject | `10_lte_air`, `12_nr_air` | MeasurementReport, RRCConnectionRelease and RRCConnectionReestablishmentReject encoded through the generated PER layout; NR reconfiguration beside them. |
| **CMAS / ETWS / PWS alert forgery** | `10_lte_air` | The full warning chain in RRC: SIB10 carries the primary notification (message identifier, serial, `warningType` split into class and category), SIB11 and SIB12 the segments that follow, and SIB12 the coordinate segment. Every builder is pinned to pycrate vectors — `04400000000040` (SIB10, 50 bits), `048D159E00026F56DF7780` (SIB11, 81 bits), `82468ACF0000FFC00040412040204000` (SIB12 with a warning-area segment, 122 bits). `--enb-sib-schedule` writes the `sib.conf` fragment that would announce one, and refuses on srsRAN release_23_11 by name because that release registers only sib1-sib7, sib9 and sib13 — a SIB10 entry fails in `sib_info_item_c::pack`. Master implements it. |
| SIB19 and the satellite cell | `49_ntn` | SIB19 built on its own and inside the `SystemInformation` carrier that actually carries it (sib-TypeAndInfo, si-Periodicity, window), each read back through the generated codec. |
| SIB1 decode and DCCH forgery | `10_lte_air`, `12_nr_air` | SIB1/SIB2 read; MeasurementReport, RRCConnectionRelease and ReestablishmentReject encoded through the generated PER layout. |
| Forged reject cause | `15_downgrade` | Built, with the transmit verb last on its card. |
| GTP-in-GTP and MBMS session start | `11_lte_core` | Both built and dissected by tshark; the outer layer treats the inner as uninterpreted payload, which is exactly the middlebox gap. |
| Proactive SIM commands (RUN AT) | `52_stk` | A card-originated `RUN AT` command built as the TLV chain a handset receives, and an audit that classifies the string: radio or service change, file or identifier readout, shutdown, browser launch. The chained form for multi-command strings is flagged rather than flattened. |
| SMPP 3.4 beyond bind and submit | `41_ota_sms` | `submit_multi` with its destination list of two shapes, `data_sm`, the optional TLV set walked tag-length-value with unknown tags kept as `unknown_tag_0xNNNN`, a TLV builder, and the TLS port (3550) admitted by shape. Truncated and malformed TLVs are refused rather than guessed. |
| IMS and SMS source spoofing | `41_ota_sms`, `30_volte_ims` | The 3GPP2 originating address as a 128-character name where the standards allow it, and the SIP/IMS path that carries the text, so the claim being tested is what the receiving handset renders, not what the sender typed. |
| USSD and supplementary-service forge | `38_ussd` | 7-bit packing that handles the extension characters, a USSD facility message built from a DCS and the packed text, MMI and SS string parsing per TS 22.030 (SC/SI/SIA), the supplementary-service code reference, and the injection findings a payload raises. Which strings move an account and which are answered before authentication is the point. |

### Core network and interconnect

| Attack | Module | What exists |
|---|---|---|
| MAP operations | `26_ss7_map` | ATI, SRI, SRI-SM, SAI, PSI, ULR, ISD, RegisterSS and ActivateSS built byte-exact, with M3UA encapsulation both ways. The answers exist too: `--build-response sai-ack` returns real GSM triplets and an EPC quintet, and `--ati-answer` referees what a returning ATI actually contains — including the untagged `ageOfLocationInformation` that TS 29.002 17.7.6 requires and a tagged one does not. |
| SIP and IMS registration hijack | `30_volte_ims` | A forged REGISTER and the spoofed re-registration sequence; `--sip-flood` is a rate calculation, not a sender. |
| A call that carries audio | `30_volte_ims` | `--call` drives INVITE → 401 answer → ACK → BYE over UDP with SDP, and the media leg behind it binds a real RTP socket, offers PCMU/PCMA, sends 20 ms frames from the microphone or a wav and plays or records the far end. Verified against a loopback SIP UAS (`tools/check-media-leg.sh`); a handset or an IMS core accepting the offer has not been tested here. |
| 5G SBA and NGAP | `13_nr_core`, `40_sba_pivot` | NRF discovery, NGAP procedures, PFCP rules, and the reachability map across the service-based architecture. |
| PFCP session hijack | `13_nr_core` | A Session Modification Request that rewrites one FAR's outer header towards an attacker endpoint, decoded back by this tree's own PFCP reader. The blunt version of the same move: one message and the downlink follows the attacker. |
| NGAP exposure probe | `13_nr_core` | Four questions to an AMF — NGSetupRequest, InitialUEMessage, UplinkNASTransport, Paging — each with what the answer leaks: cell inventory, whether a UE context is created free of charge, and whether a refusal tells you which identifier was wrong. |
| NAS COUNT and re-key | `13_nr_core` | The 24-bit NAS COUNT gap, the three ways it can move (advance, reuse, reset) and what each means for keystream reuse, plus the NH/NCC walk that decides whether a handover re-keys at all. |
| Interleaving two procedures | `13_nr_core` | Kairos: a timing model for six procedures, the pairs whose steps may not overlap, the offset window that opens each violation, and the state each side believes it is in. |
| Context integrity | `13_nr_core` | A journal of UE/context/owner/authenticated events, judged for the case a security architecture has to rule out: one subscriber landing in another subscriber's context. |
| Flooding depth | `11_lte_core` | Diameter and GTP-C message sizes, the pps that saturates a link, and the conclusion the numbers support — that the capacity that runs out first is the per-subscriber authentication vector pool, not the bandwidth. |
| N32 roaming bridge | `40_sba_pivot` | The inter-PLMN forwarding shape: the visiting NF, the SEPP hop, the N32-c handshake and the headers a home NF trusts, with the type-spoofing and IPX-trust findings named. |
| NRF discovery abuse | `40_sba_pivot` | The thirteen `target-nf-type` queries that enumerate a core, the NF-status subscription that pushes the inventory afterwards, and the absence of consumer authorisation and rate limiting. |
| Cloud metadata through the SBA | `40_sba_pivot` | An NF registration and a status-subscription callback pointed at the instance metadata address, with the three-step chain and what an egress policy would have to catch. |
| RANAP / Iu-CS on the macro side | `37_femtocell` | InitialUE-Message with its NAS payload built through the generated RANAP codec, and the IE ids read from pycrate's own constant table rather than typed in. |
| Shared RAN leakage | `43_ran_share` | EPLMN and MOCN review: which PLMN list a shared cell may broadcast, `--leak-check` over what a neighbour list gives away about the host network, and PLMN decoding of what the cell actually said. |
| 5G SUCI capture | `58_suci_catcher` | The pre-authentication identity exchange: cell and AMF slice build, catcher plan, and the SUCI a UE hands over before any key exists. |
| O-RAN and slicing | `48_oran`, `34_slicing` | A1 policy poisoning, E2 control shapes, the over-broad xApp model, slice isolation testing, 5QI and TSN assistance. |
| Carrier API enumeration and boundary | `44_carrier_api` | A concrete request per operation rendered from the document's own examples, an ordered one-identifier-per-request subscriber sequence with its declared rate limit and stop condition, the four-case authorisation matrix that says which of those requests a correct API must refuse, and the JWT audit (`alg=none`, no expiry, audience) that decides whether the refusal can be bypassed at all. Enumeration stops at the run file; `--execute` runs it only under a lab confirmation word, and a 2xx to a deny row is reported as a finding. |
| Lawful interception artefacts | `42_li_probe` | The provisioning and activation records as real TS 33.108 HI1 PDUs (liActivated / liDeactivated, BER), and the X3/HI3 product envelope as this module's own framing. Encoded, never delivered. |

### Baseband, device and radio

| Attack | Module | What exists |
|---|---|---|
| Baseband CVEs | `54_baseband_exploit` | The catalogue with the state each needs, L2 frames, forged registration accept/reject, and a send verb that asks for `--yes`. The firmware integrity half lives beside it: a manifest of the image and a verify pass that says whether the image you emulated is the image you studied. |
| NR access attacks | `55_nr_inject` | RAR construction, backoff, RA-RNTI arithmetic, MAC/DCI, Gold sequence and scrambling, and the catalogued exploits over them. |
| DIAG and NV | `56_baseband_diag`, `35_baseband` | Real DIAG framing, NV read/build/write requests, EFS paths and the AT surface; `35_baseband` owns the transmit handoff and the SCPI command file, and can modulate a payload onto the LTE grid as samples. |
| Jamming | `33_jamming_detect` | Detection first: barrel, narrowband and pulsed shapes told apart from congestion. The waveform constructor — AWGN/CW/chirp, PSS/SSS/PBCH, PRACH, PRS, PUCCH, GPS C/A, NR SSB — runs on the first invocation and prints its disclaimer on stderr. |
| GPS and PRS jamming | `33_jamming_detect` | Both sequences are generated from the standards — IS-GPS-200N Table 3-Ia for the C/A code, TS 36.211 for PRS — and asserted against an independent implementation. |
| **Overshadowing (AdaptOver)** | `60_overshadow` | A transmitter that fills only an unscheduled grant, so the cell stays up and only one user is affected. The module computes the two budgets that decide whether it is possible — the 2 ms queue window against the cyclic prefix, and the uplink power differential that makes the attack surgical (29 dBm modelled against the paper's measured 28.5) — plus the downlink case that collapses with range, four detectors, and a plan that never keys a radio. |
| Evil twin | `57_evil_twin` | A survey row becomes a radiating eNB or gNB: `--prepare-lte … --radiate` writes the rf section for one named SDR, `--run-lte … --radiate` puts it in the air without a UE of yours, and the verdict is `twin-received-identity`, `twin-accepted-attach` or `twin-radiated-unanswered` rather than a marker that always appears. `--with-capture` records S1AP, NGAP, GTP-U and PFCP and stores every identity it decodes. |
| NB-IoT coverage enhancement | `45_iot` | CE levels with their repetition budgets and what they cost a cell: NPDCCH subframe occupancy, NPRACH congestion, and the suspend/resume state that outlives the session. |
| Sidelink presence attacks | `51_sidelink` | BSM field analysis, the ghost-vehicle detector (speed against position, impossible steps), pseudonym lifecycle auditing and the kinematic linkage that undoes a rotation. |
| Sidelink relay | `51_sidelink` | What a UE-to-network relay sees at layer 2 and layer 3, which traffic it can read in each, and why its position on the path is the whole finding. |
| MAC grants and the user-plane integrity gap | `29_mac_layer` | MAC/RLC/PDCP decoded from the capture: RNTI tracking, grant cadence per UE, and the scheduling view that overshadowing needs — plus where user-plane integrity stops being applied, which is the difference between reading a channel and reading a message. |

### Tracking, positioning and RF

| Attack | Module | What exists |
|---|---|---|
| Timing-advance geolocation | `39_ta_geoloc` | Cell range from TA, with the accuracy limit stated rather than rounded away. |
| UTRAN ranging | `39_ta_geoloc` | RTT in chips to metres (78.0504 m per chip round trip), the Rx-Tx difference that turns a circle into a hyperbola, and the same trilateration once three anchors exist. |
| OTDOA / UTDOA / PRS | `46_lpp`, `33_jamming_detect` | LPP assistance data and requests through the generated LPP codec, checked against pycrate; PRS generated from TS 36.211 with its RE map written beside it. UTDOA has no home in LPP at all, so it is built where it lives — LPPa over S1AP, with the SRS request and the per-cell SRS configuration encoded and read back. |
| Satellite timing | `49_ntn` | A forged ephemeris turned into the timing a phone derives from it, an attacker-chosen k_offset, and the circle two TA measurements narrow to two points. |
| Satellite backhaul | `49_ntn` | A passive Ku-band receive does not touch the air interface at all: a bent-pipe repeater brings an operator's internal links down over a whole footprint, and the published measurement is that 10% of transponders were scrambled, 6% carried IPsec, TLS was near-universal on end-user traffic, and critical infrastructure was largely in the clear — including a cellular backhaul whose IPsec ran a null cipher. The module names each layer, prices the receive-only station, and triages a cleared capture for clear SIP and RTP, DNP3, SNMPv1, card data, or an ESP/TLS session it cannot read. Also stated: GMR-1 and GMR-2, where the cipher is optional at layer 1 and the random access channel carries the dialled number and the terminal position in the clear. |
| RF fingerprinting and CSI sensing | `24_rf_fingerprint` | CFO, IQ imbalance, transients, and a channel that moves without a transmitter moving. |
| Traffic and application fingerprinting | `23_traffic_analysis` | Flow features and classification on behaviour rather than ports. |

### Orchestration

| Attack | Module | What exists |
|---|---|---|
| Repeated runs | `25_killchain` | Fourteen builtin chains — survey, passive-audit, gsm-assessment, lte-core-audit, 5g-privacy, rf-effect, nbiot-audit, lmr-survey, slice-oran-assess, nr-core-exposure, sba-exposure, ntn-timing, sim-resync, gea-posture — plus user chains, with pause, resume and a result report per run. Five of them run end to end without a radio. |
| Evidence you can hand over | `25_killchain` | A manifest of the artefacts a run produced, with the tool version, the commit, the clock and a body hash, and a verify pass that reports what changed, what vanished and what appeared. A report nobody can re-derive is an assertion, not evidence. |
| Catalogue reachability | `20_gsm_cve`, `21_lte_cve`, `22_nr_cve` | Every catalogued CVE placed: over the air, beside the core, at an STP, on the card, or nowhere special — and the standing claim that no exploit primitive ships with the catalogue. |

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

### PlutoSDR / Pluto+ (AD936x over libiio)

A **PlutoSDR** (or a Pluto+/LibreSDR board running the same ADI firmware) is
enumerated as `pluto:<context>` and captured with `iio_readdev`:

```
modules/01_radio.sh --list-tsv      # pluto:usb:1.9.5 and pluto:ip:192.168.2.1 are one board, two doors
modules/01_radio.sh --select 'pluto:ip:192.168.2.1'
modules/01_radio.sh --record 5      # iio_attr tunes, iio_readdev streams ci16
```

- Two contexts, two rows: USB and Ethernet reach the same board differently, and
  the Ethernet door survives a cable pull without re-enumerating.
- The capture is `ci16` (the AD9361 is a 12-bit converter, samples are shifted
  left by four); `01_radio --record` reports `format ci16` with the file so a
  reader never guesses.
- Gain writes set `gain_control_mode manual` first, because a `hardwaregain`
  write in automatic mode is silently ignored.
- Known limit: this tree has no Pluto **transmit** call. The TX verbs name the
  driver they were proved against (`hackrf_transfer`) and refuse for anything
  else rather than shipping an untested `iio_writedev` line.

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
| `49_ntn` | feeder link geometry — SIB19 carries no gateway position, so the gateway-satellite distance is not derivable from anything the cell broadcasts. The feeder *carrier* is described rather than demodulated: there is no DVB-S2 demodulator or FEC decoder in this tree, so `--backhaul` names the layers and `--backhaul-triage` reads a text export someone else parsed. GMR is likewise a reference: no burst is demodulated and no cipher is implemented |
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
