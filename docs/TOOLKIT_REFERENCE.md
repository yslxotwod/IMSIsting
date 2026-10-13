# IMSIsting — toolkit reference

**54 modules** as of this revision. Version 0.4 lineage; the module set is growing.

## 1. What it is

A cellular security research toolkit for Linux. GTK4 GUI plus a full CLI, sitting on **standalone bash modules** covering 2G/GSM, 3G/UMTS, 4G/LTE and 5G/NR.

Two design commitments run through everything:

**The GUI is a view over the scripts, not a container.** Every action a button takes is also a command you can run by hand:
```bash
./modules/02_cell_recon.sh --plmn 208-01
./modules/21_pcap_analysis.sh --summary capture.pcap
./modules/15_lte_core.sh --decode-diameter <hex>
```

**Most tools tell you they worked. This one is built to tell you when they didn't.** Hardware-gated verbs name the missing radio rather than returning an empty result. A module that cannot do its job exits non-zero. There is no path that reports success while doing nothing. `05_field_kit --guard-check` exists to verify that claim mechanically rather than assert it.

## 2. Layout

```
/home/ysl/IMSIsting/
├── imsisting.sh            launcher: CLI menu, --list, --index, --gui
├── modules/                NN_name.sh — all the actual work
├── tools/                  gen-module-index, run-selftests, check-paths, check-verbs
├── native/                 GTK4 app (meson): src/main1.c, resources/style.css
├── docs/                   MODULE_CONVENTIONS.md, MODULE_ROSTER.md,
│                           ATTACK_COVERAGE.md, BRIEF_FOR_AI.md,
│                           TOOLKIT_REFERENCE.md (this file)
├── loot/                   results, one dir per module — NOT redacted
├── captures/  logs/  state/  tmp/   runtime
└── module_index.tsv        generated: id, name, category, verbs, has_selftest
```

Build and run:
```bash
cd native && meson setup builddir && meson compile -C builddir
sudo ./imsisting.sh              # interactive CLI menu
./imsisting.sh --list --index --gui
./native/builddir/imsisting-gui --tab 1        # open straight to Live Traffic
./native/builddir/imsisting-gui --module 15_lte_core
```

`--tab N` and `--module <id>` open directly to a view. Both are stripped from argv before `g_application_run` — GtkApplication rejects an unregistered option outright and, because stderr is redirected to the diagnostics file, exits silently.

## 3. The GUI

Six permanent tabs — **Dashboard, Live Traffic, Loot, Stats, Help, Settings**. Module pages open alongside as closable tabs. The module list on the left collapses via the *Modules* button.

**Header strip** shows live cellular state, each value read from a module's own `--status-tsv` so it cannot disagree with the module: `SDR` (selected radio), `TX` (can it transmit — most attack verbs need this), `FREQ`, `CELLS` (survey count), `GPS`.

**Live Traffic** is a GSMTAP listener on UDP 4729, not a raw-radio view — you cannot demodulate GSM/LTE inside a GUI process. GSMTAP is what gr-gsm, srsRAN and Open5GS all emit and what Wireshark keys off. The table decodes the 16-byte version-2 header as messages arrive, with a filter over type/channel/payload. If nothing is emitting it says so and names `grgsm_livemon`. With no radio at all you can still drive it — see `05_field_kit --emit`.

**Module pages** are a left VIEWS menu with content in cards: STATUS, ACTIONS (verb buttons), RUN ANY VERB (free-text, so no verb is unreachable).

## 4. Verification status — read this before trusting anything

Every module now ships a `--selftest` with real assertions against published
vectors or spec tables, and all 54 pass `tools/run-selftests.sh`. Every
radio-gated verb fails honestly with no radio attached.

The history matters, because it is why the bar is where it is. An earlier batch
of `40`–`49` was removed after failing this check: `passed 0, failed 10`, with
zero assertions between them and silent failures. Those ten ids are now built
properly (see §5) — `40`–`49` and the six `53`–`58` ids — and `52_wifioff`'s
selftest, which shipped red, has been repaired.

**The rule that follows:** a selftest that asserts nothing is worse than no
selftest, because it hides regressions. `05_field_kit --guard-check` will catch
the honesty half mechanically.

## 5. The modules

### System and recon

**`00_deps`** — checks the cellular toolchain (SDR tools, gr-gsm, srsRAN, Open5GS, tshark, pcsc, gpsd, hashcat) against a per-distro package table. Distinguishes *installed* from *a complete stack* — gnuradio present without gr-gsm blocks is reported distinctly. Versions are memoised to files, because callers use `$(...)` and a shell-variable cache dies in the subshell. `--check-versions --missing-only --install-missing --report`.

**`01_radio`** — enumerates SDRs by probing each vendor's tool (hackrf_info, bladeRF-cli, LimeUtil, uhd_find_devices, rtl_test, SoapySDRUtil), reports driver/serial/range/direction, and flags receive-only devices by name. Records the selected device to shared state so every other module sees it. `--list-tsv --caps-tsv --band-check --select --set-freq --set-gain --set-rate --record`.

**`02_cell_recon`** — the reference module. ARFCN/EARFCN/NR-ARFCN to frequency, PLMN to operator/country, cell survey from an SDR or from a GSMTAP pcap. *The NR raster is piecewise* — 5 kHz below 3 GHz, 15 kHz to 24.25 GHz, 60 kHz above — and that bug shipped once because the only ARFCN asserted was a band edge where the offset term is zero. `--scan --arfcn --plmn --list-tsv --export`.

**`03_gsmtap`** — GSMTAP header codec and pcap I/O. Header verified against Wireshark: 16 bytes, `hdr_len` in 32-bit words, GSM channel in `sub_type` (**only** for GSM payloads — under LTE the same octet is not a channel), uplink as `0x4000` in the `arfcn` field. `--listen --read --parse-header --build-header --identities-tsv`.

**`04_tower_map`** — GPS-tagged cell survey with CSV/KML/GeoJSON export. KML places only points with a fix and counts the rest rather than dropping them silently. `--survey --history --export-kml --export-csv --export-geojson --gps-quality-tsv`.

**`05_field_kit`** — RF pre-flight, honesty verification, and a synthetic signal source. Three jobs:
- `--capability` — what radio hardware is actually present (probes each vendor tool and each serial radio), what that means for transmit, and which software emitters exist.
- `--guard-check` — runs every radio-gated verb in the tree and classifies the outcome as **honest** (non-zero *and* says why), **silent** (non-zero, says nothing) or **fabricated** (returns success having done nothing). A fabricated result is the cardinal sin this toolkit exists to prevent. Writes `loot/field_kit/guard-check.tsv`.
- `--emit [SCENARIO] [N] [DELAY] [udp|FILE.pcap]` — generates a deterministic, spec-shaped GSMTAP stream from scenarios `gsm-idle`, `gsm-attach`, `lte-attach`, `mixed`, and sends it to the Live Traffic view or to a pcap. Every byte is known, so it drives the whole receive-and-decode chain from a signal you control — the closest thing to a real signal path when no SDR is present.

The guard matrix deliberately holds only verbs that *cannot* legitimately succeed without a radio. `--earfcn` and `--arfcn` are pure arithmetic; they return 0 on a machine with no SDR and that is correct, not fabrication. Putting them in the matrix reports a working module as broken.

### 2G / GSM

**`10_gsm_air`** — System Information decode (SI1–SI4, SI13), paging analysis, cipher mode audit, A5/1 keystream, identity IE decode. **The A5/1 implementation is validated against the published Briceno/Goldberg/Wagner vector** — `Kc=1223456789abcdef, frame=0x134 → 534eaa582fe8151ab6e1855a728c`. That vector is what caught the wrong R3 taps, the clock-before-read order, and the Kc byte order. Identity decoding follows TS 24.008 §10.5.1.4: type in bits 1–3, parity in bit 4, first digit in the high nibble of the first octet. `--decode-si --paging-group --cipher-audit --a5-1-keystream --decode-sch --decode-pcap`.

**`11_gsm_attack`** — IMSI catcher sequence (RACH→AGCH→SDCCH→Identity Request), A5/1 downgrade, TMSI de-anonymisation, Kc recovery arithmetic, classmark encode/decode. Everything computational is computed; everything requiring transmit is a `status: handoff` plan naming the hardware, and the transmit guard **rejects an RTL-SDR** because it cannot transmit. `--imsi-catcher-sequence --classmark --classmark-downgrade --c1 --plan --build-identity-request`.

### 3G / UMTS

**`12_umts_air`** — UARFCN↔frequency (both rasters), SIB decode, RRC integrity (UIA1/UIA2 MAC-I assembly: COUNT-I ‖ FRESH ‖ DIRECTION ‖ MESSAGE keyed with IK), AKA relay flow between USIM/VLR/HLR. `--uarfcn --mhz --decode-sib --mac-input --count-i --aka-flow --integrity-tsv`.

### 4G / LTE

**`13_lte_attach`** — NAS EMM/ESM encode-decode with real IE offsets, BCD IMSI/IMEI codecs (both directions, odd/even and leading-zero MNC handling), attach forge, identity-exposure detection. An Identity Request for IMSI in an unprotected NAS message is the classic exposure and is flagged. `--decode-nas --encode-attach --imsi-encode --imsi-decode --identity-exposure`.

**`14_lte_air`** — EARFCN, RRC/SIB1-5 decode, paging frame and occasion maths per TS 36.304 (`SFN mod T = (T div N) * (UE_ID mod N)`), srsRAN eNB config generation and start/stop with correct pidfiles. `--earfcn --decode-sib --paging-frame --gen-enb-conf --power-ref --start --stop`.

**`15_lte_core`** — Diameter base protocol and AVP walk (including grouped AVPs), S6a/S6d, GTP-C v2 and GTP-U with extension headers, S1AP overview. **The command-code table was shifted by one and passed 270 self-consistent assertions**; it was corrected against Wireshark's 3GPP Diameter dictionary — *316 ULR/ULA, 317 CLR/CLA, 318 AIR/AIA, 319 IDR/IDA, 320 DSR/DSA, 321 PUR/PUA, 322 Reset, 323 Notify*. Request and answer share a code; direction is the R flag bit. `--decode-diameter --decode-gtp-c --decode-gtp-u --build-air --build-ulr --plan`.

### 5G / NR

**`16_nr_air`** — NR-ARFCN (reusing the corrected piecewise raster), GSCN, PCI derivation, MIB and SIB1 bit-field decode, PRACH occasion computation, gNB config generation. `--arfcn --pci --decode-mib --decode-sib1 --gen-gnb-conf --prach`.

**`17_nr_core`** — 5G SBA: NGAP over SCTP, 5GS NAS (note: `[0x7E][spare|sec-hdr][type]`, *not* the EPS layout), 5G-GUTI decode, PFCP session and PDR/FAR/QER/URR rules, 5G-AKA, NRF discovery. `--decode-ngap --decode-nas-5gs --decode-pfcp --decode-5g-guti --aka-flow`.

**`18_suci`** — SUCI conceal/deconceal. ECIES profile A (X25519) and profile B (P-256), HKDF-SHA256 asserted against **all three RFC 5869 vectors**, BCD MSIN with odd/even handling, and the audit for null-scheme SUCIs (MSIN in the clear) and reused ephemeral keys. `--build-suci --parse-suci --conceal --deconceal --hkdf --msin-encode --msin-decode --audit`.

**`19_downgrade`** — reject causes across EMM/5GMM, the null-cipher tables for all four generations, Security Mode Command construction, and downgrade detection from a capture. `--causes --reject-cause --null-cipher-table --build-security-mode --detect --plan`.

### SIM

**`20_sim`** — ISO-7816 APDU build/parse with the real status-word table, USIM file ids, ICCID/IMSI BCD, **EF_AD parsed as two distinct layouts** (2G TS 51.011 vs USIM TS 31.102 §4.2.18 — the PIN-enable flag and the ciphering indicator are different fields), PIN/PUK state, TS 23.048 OTA parsing with the SPI as **two-bit sub-fields**, eSIM RSP roles and profile state. `--build-apdu --parse-apdu --decode-iccid --decode-imsi --decode-ad --file-id --get-response`.

### Analysis

**`21_pcap_analysis`** — pcap and pcapng reader written from scratch (classic magic both endiannesses, nanosecond variant, SHB/IDB/EPB/SPB). Walks Ethernet/SLL/SLL2/raw-IP → IPv4/IPv6 → UDP/TCP/SCTP, and dissects GSMTAP, Diameter, NGAP, S1AP, M3UA, GTP-C/U, PFCP, RTP. **tshark is not required** and the selftest asserts the fallback path contains no reference to it. `--summary --list --hierarchy --conversations --extract --identities --build-sample`.

**`22_imsi_exposure`** — drives 21 as a subprocess rather than duplicating the parser, builds the TMSI/GUTI→IMSI map with per-binding evidence, cross-capture correlation, per-subscriber exposure scoring, and redaction. `--audit --harvest --map --cross --exposure-tsv --redact --report`.

**`23_cipher_audit`** — full algorithm tables (GSM 8, UMTS 6, LTE 8, 5G 9), Security Mode Command parsing for EPS/5GS NAS and GSM RR, per-generation scoring, three downgrade tests. **This is where the empty-field TSV bug produced a phantom downgrade on every session** — a timestamp was being read as the UE's advertised capability. An unknown algorithm id is never scored as safe. `--table --parse-smc --score --downgrade-check --session --from-pcap`.

**`27_traffic_analysis`** — flow extraction (packet sizes, inter-arrival, direction), burst analysis, and website fingerprinting: a feature vector over a trace's flows scored by cosine + RBF against a reference set, both terms reported. Also detects padding/shaping so you can see what a defence does to the signal. `--flows --features --fingerprint-add --classify --refs-tsv`.

**`28_rf_fingerprint`** — IQ fingerprinting: RMS/PAPR/spectral flatness/DC/IQ-imbalance (image rejection) and carrier frequency offset by a stated estimator, plus burst transient shape. **CFO is asserted against the injected value**, and IRR against the analytic formula. CSI: 802.11 complex matrices and LTE CQI/PMI/RI, with phase unwrapping for a motion indicator. States that absolute dBm and true EVM need a calibrated radio; the comparative features do not. `--features --transient --sig-add --classify --csi-parse --csi-motion`.

**`34_mac_layer`** — LTE MAC PDU parse with the real LCID tables, RNTI handling (SI-RNTI 0xFFFF, P-RNTI 0xFFFE, RA-RNTI range, C-RNTI range), RNTI tracking and scheduling-pattern inference, DCI/MCS mapping. **LCID is six bits, not five** — the five-bit version reported LCID 54 as 22 and failed its own fixtures. `--decode-mac --lcid-table --rnti-table --rnti-track --sched-pattern --dci --integrity-gap`.

**`37_nas_signaling`** — NAS message-rate measurement, procedure mix, cause distribution, cost model for the signalling-storm patterns, and storm-profile detection. **The transmit path is gated**: no `--i-have-a-lab-and-authorisation`, no plan; a live MCC is refused; there is a hard 50 msg/s ceiling. `--rate --procedure-mix --causes --storm-profile --cost-model --plan`.

### Interconnect, tracking and RF

**`31_ss7_map`** — MTP3 routing label (3-8-3 and 4-4-4-2 point-code formats), SCCP, TCAP components, MAP opcodes from TS 29.002, the published attack flows (SRI, SRI-SM, ATI, PSI, call-forwarding hijack), and GRX reachability. **SSN 145 is GMLC; 146 is CAP** — the brief had it wrong and the selftest asserts 146 is *not* GMLC. Call forwarding is `cfu`=33, not 21. `--decode-tcap --decode-map --decode-msu --build-sri --build-ati --flow --grx-recon --detect`.

**`32_cellular_dns`** — DNS message encode/decode per RFC 1035 including compression pointers, the aLTEr sequence (LTE user plane has no integrity, so an on-path attacker can rewrite a DNS response in the tunnel), resolver discovery, and the detection half: answer/question mismatch, unexpected resolver, ID mismatch, TTL anomaly, DNSSEC failure. `--decode-dns --build-query --build-response --resolver-discovery --detect --alter --pco`.

**`33_paging_track`** — paging frame/occasion per TS 36.304 and TS 38.304, GSM paging group (IMSI mod 1024) and block index, paging record parse, Torpedo and Piercer models, and paging-anomaly detection. **The paging attacks are Hussain et al., NDSS 2019** — one paper introducing ToRPEDO, PIERCER and IMSI-Cracking, not "Torpedo, USENIX 2019". `--po --paging-parse --torpedo-model --piercer-correlate --detect`.

**`38_jamming_detect`** — detection and measurement only. Noise-floor shift, PDCB/PBCH decode-failure rate, RSRP collapse without handover, uplink BLER, plus discrimination between **jamming / congestion / coverage hole** (all three branches exercised in the selftest) and narrowband-vs-barrage characterisation. Emits a measurement log for a regulator. A selftest assertion verifies there is no transmit path. `--analyse --noise-floor --characterise --discriminate --counters --report`.

**`35_volte_ims`** — ReVoLTE keystream reuse (the algebraic demonstration is real: two plaintexts under one keystream XOR to the XOR of the plaintexts, and a known-plaintext prefix recovers the rest; AES-CTR asserted against **NIST SP 800-38A**), IMP4GT identity mapping, SIP parse, IMS registration. `--revolte-demo --keystream-recover --ims-registration --sip-parse --imp4gt-model --detect-keystream-reuse --plan`.

**`36_sim_defense`** — **defensive only.** Detection signals for a port in progress (IMSI/IMEI re-pairing, OTA burst, auth-failure streak, dual registration, implausible VLR), defence posture (port freeze, number lock, EF_AD in both layouts, PIN/PUK retry counters, ADM), eSIM profile integrity. A selftest assertion checks the module contains no carrier-impersonation template. `--signals --score --ef-ad --pin-state --esim-profile-parse --defence-checklist`.

**`39_slicing`** — S-NSSAI encode/decode (SST/SD per TS 23.003 §28.4.2), the SST table from TS 23.501, slice selection, and isolation testing. An unknown SST is never folded onto eMBB, and the isolation check reports **"not determinable"** rather than a false "isolated" when the capture lacks the slice→TEID binding. `--encode-s-nssai --decode-s-nssai --nssai-parse --selection --isolation-check --detect`.

### Scanners

**`24_gsm_cve` / `25_lte_cve` / `26_nr_cve`** — 25, 50 and 49 documented ids, 82 distinct real CVEs plus research references. Each id routes to a **probe** or a `status: handoff` plan naming exactly what is required. Nine probe ids once had no `case` arm and vanished silently from coverage; the dispatch is now exhaustive and the selftest asserts the count so a dropped entry fails. `--run-cve <id> --list-cves --probe --plan --runs-tsv`.

### Automation

**`30_killchain`** — chains module verbs into repeatable runs. Chain files are TSV (step, module, verb, args, hardware, description — args use `-` as an explicit empty placeholder, which is why this module does *not* suffer the TSV collapse). A missing module or absent radio records **SKIP with the reason, never PASS**. `--list-chains --show-chain --run --dry-run --keep-going --add-chain --runs-tsv`. Includes a `builtin-verbs-exist` assertion that greps each step's verb out of its module's dispatch, so chain drift fails the test.

### Expansion — baseband, VoWiFi, small cells and SIM (40–49)

**`40_baseband`** — RRC/NAS research scaffolding: a BER/DER definite-length codec off the X.690 worked examples, a seeded deterministic mutator (bitflip, nibbleflip, boundary, truncate, extend, duplicate, length-corrupt), corpus generation, and ASAN/UBSAN crash-log triage. It emits no over-the-air payload; the fuzz step is a handoff. The selftest asserts no transmit verb exists.

**`41_vowifi`** — IKEv2/SWu: the 28-octet header build/parse, exchange-type and payload-type tables, EAP-AKA packet codec, the SWu NAI and ePDG FQDN (TS 23.003), a payload-chain walk, and encryption/integrity transform classifiers where an unknown transform is never scored safe.

**`42_femtocell`** — 27-bit CSG-Id codec, PCI-confusion detection over a cell list, the Iuh (HNBAP/RUA/RANAP) reference, and a TR-069/CWMP local-management audit (default credentials, plaintext ACS, WAN exposure).

**`43_ussd`** — GSM 7-bit default-alphabet packing (asserted on the `E8 34` worked example), MMI/SS parsing (TS 22.030 codes 21/61/62/67/…), USSD facility build with DCS, and a USSD/STK **injection** detector.

**`44_ta_geoloc`** — LTE and NR timing-advance to range (TS 36.211 / TS 38.211), the quantisation error bound, and a linearised least-squares trilateration solver verified to recover a synthetic ground-truth point.

**`45_sba_pivot`** — HTTP/2 frame codec (RFC 7540 types and SETTINGS), NRF discovery request construction (TS 29.510), JWT/JOSE decode, and `alg=none` / audience-confusion auditing.

**`46_ota_sms`** — TS 23.048 OTA Command-Packet construction (SPI, TAR, counter, padding counter), sharing the SPI bit layout with `20_sim`'s decoder, plus counter/replay decisions per the SPI mode. Own-SIM and lab only.

**`47_li_probe`** — **detection only.** The 3GPP LI interfaces (X1/HI1, X2/HI2, X3/HI3; TS 33.108), the ADMF/DF2/DF3/LEMF model, an interception-posture scorer over signalling events, and regulator reporting. The selftest asserts no activation or interception verb exists.

**`48_ran_share`** — PLMN coding (TS 24.008 §10.5.1.3, anchored on 001-01 → `00 F1 10`), equivalent-PLMN cap, MOCN/MORAN/GWCN classification, and cross-operator leakage detection.

**`49_carrier_api`** — **assessment only.** OpenAPI 3 surface parsing, a four-case authorisation test matrix, token-bucket rate-model maths, JWT audit and response-differential analysis. No subscriber-enumeration verb, asserted in the selftest.

### Recent additions — now verified

**`50_iot`** — NB-IoT / Cat-M1: NPRACH, NPSS/NSSS, SIB1-NB, NPRFCN.

**`51_lpp`** — LTE Positioning Protocol: procedure codes, header codec, position-forgery detection.

**`52_wifioff`** — Wi-Fi offload / LWA: ePDG FQDN, certificate validation, LWA config. Its selftest was repaired to emit `RESULT\tPASS`.

### New in v0.4 (53–58)

**`53_oran`** — O-RAN / Open RAN: the E2/A1/O1/O2/F1/E1/fronthaul interface set, E2 service models, a deployment security assessment and an xApp-authority model.

**`54_ntn`** — 5G NTN / satellite: Doppler and round-trip delay, TA units and k_offset, SIB19 and feeder/service link references.

**`55_gprs`** — GPRS / EDGE: the GEA0–GEA4 cipher family, APN coding (TS 23.003), PDP-context IEs, and a GEA-downgrade detector.

**`56_sidelink`** — NR sidelink / V2X: resource-pool subchannel maths, the SCI-1A frequency-field width, PFI and Layer-2 IDs, the ITS certificate model, and a relay-configuration check.

**`57_stk`** — SIM Toolkit: TS 31.111 proactive command (D0 envelope, comprehension-TLVs) build/parse, command/device/result tables, and an audit for silent off-device commands.

**`58_non3gpp`** — TETRA / DMR / GSM-R: frame structure, the TEA cipher family, bands, a channel-spacing classifier and detection notes. Receive-only.

## 6. Getting the code right

Read `docs/MODULE_CONVENTIONS.md` in full. It is a bug log, not style guidance — every rule exists because ignoring it caused a real defect. `docs/BRIEF_FOR_AI.md` is the same material aimed at a contributor picking the project up cold.

### The module skeleton

Copy `modules/02_cell_recon.sh`. The mandatory parts:

**Self-locating header** — resolves `IMSISTING_ROOT` from its own path following symlinks, then repairs `HOME` (under `pkexec`, `HOME=/root`, so `$HOME`-relative paths land in the wrong place).

**Shared scratch** — one `$TMP_DIR` = `/tmp/imsisting`. Cross-module state (`sdr_device`, `target_arfcn`, `target_plmn`) lives there. A private temp root means you cannot see what another module set.

**The `info` shim — `declare -F`, never `command -v`:**
```bash
declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
```
`/usr/bin/info` (texinfo) exists, so `command -v info` succeeds, the shim is never defined, and every `info "msg"` execs texinfo treating the message as a filename.

**Output is TSV** — `KEY\tVALUE`; errors to stderr; non-zero on failure; never a success line when it failed.

**Function names carry a module tag** (`crec_*`, `gtap_*`) because the launcher sources every module into one shell.

**The four verbs are fixed:** `<tag>_cli_main`, `<tag>_cli_status_tsv`, `<tag>_selftest`, `<tag>_menu`.

### The traps that matter

**Never parse TSV with `IFS=$'\t' read`.** Tab is whitespace to `read`, so a run of tabs collapses and a row with an empty column shifts every later field. This shipped twice — it made `23_cipher_audit` read a timestamp as the UE's capability and fire a downgrade alert on every session. Split with `cut -f`:
```bash
F=()
split_tsv() {
    F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do F+=("$(printf '%s' "$1" | cut -f"$i")"); done
}
```

**Bash produces wrong answers rather than errors.** `printf '%02X'` does not truncate — above 255 it emits three hex digits and corrupts whatever it is spliced into; mask at the point of emission. `case` patterns are literal text, so `0x07)` never matches a decimal `7`. `$(( 16#$var ))` aborts the enclosing command substitution on bad input, killing the shell. `$(( func arg ))` does not call the function. `export A=x B="$A/y"` expands `$A` before assignment.

**Never print a success line when the operation failed.** A bare `return 1` with no message is a real bug — it is indistinguishable from a crash. `05_field_kit --guard-check` reports these as `silent-fail`.

**A heredoc replaces stdin.** `python3 - <<'EOF'` discards piped data. Stage it through a file.

### Testing

**Assert against published values, not your own output.** A selftest asserting what the code produces proves only determinism. Three real cases passed their own tests while being wrong:

- A5/1 with wrong feedback taps — caught only by the published BGW vector
- The NR-ARFCN raster as flat 5 kHz — the one ARFCN asserted was a band edge, where the offset is zero
- The S6a command-code table — 270 assertions encoded the same wrong values

Four more, from the same class, caught during the v0.3 work: a GSMTAP header expectation hand-typed from a different input; an SPI read as single bits where the spec defines two-bit sub-fields; a `|`-delimited fixture read by a tab-based split, so each row arrived as one field; and a header-length assertion that forgot to add the payload.

Where a published vector, spec table or independent implementation exists, **assert against it and cite the source in a comment**. Test a point *inside* a piecewise range, never only at a boundary.

**Adjudicate disputed constants locally.** `tshark` decodes most cellular protocols — build a packet with `text2pcap` and read the field name back. That technique settled the S6a table, the GTPv2 ULI IE number, and the GSMTAP channel encoding.

**Test both directions.** A detector that always fires is useless. Every classifier selftest should assert it fires on the positive case *and* abstains on the negative.

**An unknown value must never be classified as safe.** Unknown algorithm → not "ok". Unknown SST → not eMBB. Unknown CSG mode → not "open".

**Never assert that state exists.** A selftest requiring a database, a capture or a previous run fails for every new user while passing on the machine that wrote it. Build your own fixture in the scratch dir, or report SKIP.

**Selftests run with no radio, no root, no network**, redirect `LOOT_DIR`/`CAPTURES_DIR`/`STATE_DIR` into a `mktemp -d`, and trap EXIT to clean it. They must not touch the real loot tree.

### Before you commit a change

```bash
bash -n modules/NN_name.sh
modules/NN_name.sh --selftest          # must exit 0 with RESULT<TAB>PASS
./tools/gen-module-index.sh            # regenerate; --check fails if stale
./tools/check-paths.sh                 # every path and table entry resolves
./tools/check-verbs.sh                 # verbs reachable from the GUI
./tools/run-selftests.sh --all
./modules/05_field_kit.sh --guard-check   # nothing may be FABRICATED
```

Adding a module means four edits: the new file, a `modules[]` row in `native/src/main1.c`, a `module_registry_register()` call, and a row in `IMSISTING_MODULE_TABLE` in `imsisting.sh` with the module id as the **fifth** field. Also regenerate the index — `check-paths` fails if it is stale.

Do not hand-write `native/src/config.h`. meson generates it into the build dir; a copy in `src/` shadows it and bakes the wrong root into the binary.

## 7. Honesty about hardware

No module here has been run against a real radio — there is no SDR on this machine. Every over-the-air path is written and reviewed, not verified. Where a vector needs hardware, write `status: handoff` and name the exact device. **"Written" and "works" are not the same claim**, and this document says which is which.

Two things make that checkable rather than aspirational:

```bash
./modules/05_field_kit.sh --capability    # what hardware actually exists
./modules/05_field_kit.sh --guard-check   # does every radio verb fail honestly?
```

Current state: no SDR, no serial radio, no radio stack installed. All 34 verified modules fail honestly with no radio attached — 16 of 16 radio-gated verbs checked, zero fabricated.

## 8. Scope decisions

Some capabilities are deliberately detection-only or absent. Each carries an in-module scope check that runs inside `--selftest`.

- **`36_sim_defense`** detects SIM-swap attempts rather than performing them.
- **`38_jamming_detect`** measures interference rather than causing it. Transmitting to deny service is illegal in most jurisdictions and takes emergency calls down with it.
- **`37_nas_signaling`** gates its transmit path behind an explicit lab-and-authorisation flag, refuses a live MCC, and caps at 50 msg/s.
- **`47_li_probe`** was scoped as detection-only. The module is not currently in the tree.

The general line: protocol analysis, decoders, fuzzers aimed at a device you own, lab testbeds and reproducing published attacks are in scope. Operating a capability against a network or person you do not control is not. Where a request sits on that line, build the defensive or detection half and say plainly what was left out.
