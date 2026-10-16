# IMSIsting — missing domain capabilities

A per-module review of what the *scripts* cannot do yet: features a cellular
practitioner would expect from a module on that topic, which the module does not
implement. This is about capability in the toolkit, not about the GUI.

**Scope:** all 56 module scripts in `modules/`.

**Method:** seven-agent parallel review. Each agent read its modules, then had to
*verify the absence* — grep the module **and its siblings** — before claiming a
gap, and cite `file:line` for what it checked. Cap: 4 findings per module, ranked
by operator impact. 223 findings.

> **Confidence.** These are absence claims, and absence claims are exactly the kind
> that look right while being wrong. The first pass produced six "confirmed" defects,
> of which **one was a false positive** (a reviewer read a call site without checking
> the callee's contract — see `CONFIRMED-BUGS.md`). Treat a `verified:` field as the
> reviewer's evidence, not as proof; re-check any finding before you build on it.

---

## What recurs across the toolkit

Six themes account for a large share of the findings — these are the highest-value
things to build, because one implementation closes findings in many modules:

| Theme | Findings mentioning it | What is missing |
|---|---|---|
| **No cipher implementations** | 21 | A5/2, A5/3 (KASUMI), UEA1/2 (f8), UIA (f9), EEA/EIA (AES-CMAC), NEA/NIA: still named in plans and status tables with nothing computing them. **What does compute, all in `tools/gsm_crypto.py` and all validated against published vectors: A3/A8 (COMP128-1/2/3) wired into `20_gsm_cve --kc`/`--probe KC`; the AKA pair Milenage f1–f5\* (20 TS 35.208 sets) and TUAK f1–f5\* (TS 35.231/35.232 sets) with the raw Keccak-f[1600] permutation; and the A5/1 keystream plus a reduced-width time-memory-tradeoff table (`A51Table`/`a51_tmto_demo`, checked at every column alignment).** The A5/1 state transition also exists in `06_gsm_air` — the TMTO lookup half is new. Minting RES/XRES/CK/IK is no longer the blocker; *calling* it is, because no module wires the AKA verbs yet. |
| **No decryption anywhere** | 16 | 10 modules reference decryption or a keystream; none XORs a recovered keystream over captured ciphertext, so "can this be read" is never actually answered. |
| **File-only, no live capture** | 47 | 36 findings involve pcaps. Several modules read a file, then advertise tshark they never invoke; no module captures live, so nothing can notice a problem while it is happening. |
| **One direction only** | — | Many modules build a request or parse a message but not the counterpart: decode without encode, or parse without answer. The tests pass because only one direction is exercised. |
| **No persistence between runs** | — | Counters, histories and stores exist in some modules and are never written by any verb, so questions that span captures ("how often was this subscriber paged?") cannot be asked. |
| **Single-shot CLI, no selection** | — | No module accepts a display filter, a time window, an EARFCN/band or a UE selector, so a capture is all-or-nothing and a busy band cannot be narrowed. `02_cell_recon` hardcodes LTE band 7. |

---

## Findings by module

### `00_deps.sh`

- **No udev-rule / device-permission setup, so a non-root operator cannot access the SDRs whose drivers it just installed**
  - *Why it matters:* On Debian/Ubuntu, hackrf_transfer/rtl_sdr/bladeRF-cli fail with "Permission denied" until a rules file grants the plugdev group; the manager reports the tool "installed" and the operator is stuck
  - *Suggested:* `--install-udev-rules [--dry-run] writing /etc/udev/rules.d/20-imsisting-sdr.rules for the roster's USB IDs plus a udevadm control --reload/replug check`
  - *Evidence:* verified: grep -rn -i "udev" --include=*.sh --include=*.py --include=*.md . returned no match; registry at modules/00_deps.sh:112-180 installs packages only
- **No DVB-T kernel-driver conflict detection for RTL-SDR, the classic reason rtl_test fails on a box where the package is present**
  - *Why it matters:* Ubuntu/Kali bind dvb_usb_rtl28xxu/rtl2832 to the dongle and rtl_test reports "usb_claim_interface error -6"; the honest-state probe calls that `installed`
  - *Suggested:* `--driver-conflicts-tsv listing claimed USB IDs per kernel module, and --fix-dvb-conflict emitting the blacklist drop-in plus modprobe -r`
  - *Evidence:* verified: grep -rn -i "dvb_usb\\|blacklist" modules/*.sh → no match (only modules/15_downgrade.sh:83 uses the word "blacklist" for PLMN policy); probe paths are modules/00_deps.sh:399-453 deps_extra_state
- **No SDR firmware/gateware check or flash step (HackRF SPI firmware, bladeRF FPGA image, LimeSDR gateware)**
  - *Why it matters:* A field HackRF with 2014 firmware enumerates fine but misbehaves on newer gr-gsm/gnuradio; nothing here tells the operator their firmware is stale or how to update it
  - *Suggested:* `--check-firmware (version per device vs known-good) and --flash-firmware <device> emitting hackrf_spiflash -w / bladeRF-cli "load fpga" / LimeUtil --update`
  - *Evidence:* verified: grep -rn "hackrf_spiflash\\|gateware\\|fpga" modules/*.sh → no match; only unrelated prose in modules/20_gsm_cve.sh:611-615
- **Source-only stacks are handed off, never built: gr-gsm, osmocom-bb and free5gc (the 2G tools) end as "PLAN … build from source (see docs)" with no recipe**
  - *Why it matters:* An operator on a distro without a gr-gsm package cannot get the toolkit working, which is exactly what a dependency manager is for
  - *Suggested:* `--build-source TOOL printing (and with --yes running) the pinned git tag + cmake/autotools steps per tool, instead of the bare HANDOFF`
  - *Evidence:* verified: modules/00_deps.sh:805-812 (deps_install_missing_cmd srcs → HANDOFF) and modules/00_deps.sh:629-651 (deps_install_plan → "no package in $mgr; build from source (see docs)")

### `modules/01_radio.sh`

- **No frequency-error/PPm calibration of the SDR, so the recorded IQ is off by whatever the crystal drifts**
  - *Why it matters:* GSM needs ~0.1 ppm; a cheap RTL/HackRF drifts several ppm and grgsm_livemon never locks, which the operator cannot see or fix from here despite kalibrate-rtl being a registered dependency
  - *Suggested:* `--calibrate [--secs N] running kal -s GSM900 and storing ppm, plus --set-ppm N applied to subsequent --set-freq/--record (and shown in --status-tsv)`
  - *Evidence:* verified: grep -rn -i "ppm\\|kalibrate" modules/*.sh → kal appears only as the dependency row modules/00_deps.sh:137 and the menu list modules/00_deps.sh:978; no module ever invokes it
- **No band sweep / signal search; device setup goes straight to a single centre frequency**
  - *Why it matters:* The operator cannot answer "where is the BCCH carrier" or measure the noise floor before committing --set-freq, although hackrf_sweep is a declared dependency and the only sibling that computes spectra (24_rf_fingerprint.sh:219 spectrum()) works on a supplied IQ file, not live hardware
  - *Suggested:* `--sweep <fmin_mhz> <fmax_mhz> [--bin-khz N] printing a TSV of peaks/RSSI and the strongest ARFCN to hand to --set-freq`
  - *Evidence:* verified: grep -rn "hackrf_sweep" modules/*.sh → modules/00_deps.sh:119 and :978 only; modules/24_rf_fingerprint.sh Usage has no live/sweep verb (grep "hackrf_sweep\\|--sweep\\|rtl_power" → no match)
- **No bias-tee/LNA power control and no antenna-port selection**
  - *Why it matters:* Field kits routinely run an external LNA or a directional antenna on a specific port; without bias-T the LNA is unpowered and without a port choice the RX path is silently the wrong one
  - *Suggested:* `--set-bias-tee on|off and --set-antenna rx|tx|rx2 (per-driver spelling: hackrf "antenna_enable", LimeSDR --antenna, SoapySDR --antenna/bias) echoed in radio_control_plan`
  - *Evidence:* verified: grep -rn -i "bias\\|antenna" modules/01_radio.sh → only "antenna_nr" in the GSMTAP header of another module; modules/01_radio.sh:558-570 radio_control_plan emits only frequency/sample_rate/gain/direction
- **No transmit setup at all: the module computes can_tx but has no TX frequency/gain/burst verbs and no duty/duration bound**
  - *Why it matters:* It reports a device as RX/TX (modules/01_radio.sh:187-192) yet an operator cannot prepare a legal, power-bounded transmit state from the module that owns the radio — and gain is reused verbatim for the IF and RF stages on HackRF (modules/01_radio.sh:546, :619)
  - *Suggested:* `--tx-plan [--gain-db N] [--burst-ms N] [--duty-pct N] emitting tx_freq/tx_rate/tx_gain_chain and a vendor TX command, with --set-gain --tx split from RX`
  - *Evidence:* verified: modules/01_radio.sh:1360-1400 radio_cli_main has no --tx* verb; grep -rn -- "--tx" modules/*.sh → no match in 01_radio

### `modules/02_cell_recon.sh`

- **No 5G/NR and no 3G/UMTS survey even though the module promises both and already owns the ARFCN maths**
  - *Why it matters:* An operator on a 5G or 3G-only site cannot produce the cell list; crec_nr_arfcn_to_mhz exists but only for the --arfcn calculator, and neither 08_umts_air (decode SIB only), 10_lte_air nor 12_nr_air performs a passive cell survey
  - *Suggested:* `--scan nr [--band n78] and --scan umts [--uarfcn N] driving a cell-search backend and writing the normal 16-column rows`
  - *Evidence:* verified: modules/02_cell_recon.sh:507 "unknown rat: %s (want gsm|lte|pcap)" and :519 "--arfcn <gsm|lte|nr>"; awk over module_index.tsv shows 08_umts_air verbs (--aka-flow --decode-sib --uarfcn …) and 12_nr_air verbs (--decode-mib --decode-sib1 --ssb --start …) with no scan/survey
- **Signal strength is never measured: the rsrp_dbm column is declared and written empty on every row, and there is no RSRQ/SINR/RxLev column**
  - *Why it matters:* A survey with no level cannot rank cells, prove coverage or pick a serving cell — it is a bare ARFCN/PLMN list, and tower_map inherits the empty column
  - *Suggested:* `--scan … --quality parsing rsrp/rsrq/rssi/sinr (and GSM RxLev) into the store, with --list-tsv sorted by level`
  - *Evidence:* verified: grep -n "rsrp\\|rsrq\\|sinr\\|rssi" modules/02_cell_recon.sh → only modules/02_cell_recon.sh:276 (comment) and :290 (header); modules/02_cell_recon.sh:332 passes "" for the rsrp field
- **LTE band/EARFCN selection is ignored — crec_scan_lte hard-codes band 7, so a scan on any other band finds nothing**
  - *Why it matters:* An operator told the site is B20/B3 gets an empty survey and a misleading "is the SDR attached and on band?" error; only the GSM path honours the band argument
  - *Suggested:* `--scan lte <band|earfcn-list> (e.g. --scan lte 3,7,20 or --scan lte 6300) passing -b/--band per value, or --scan lte --all-bands`
  - *Evidence:* verified: modules/02_cell_recon.sh:343 `out=$(timeout 30 cell_search -b 7 …)`; crec_cmd_scan at :487-516 forwards "$band" only in the gsm branch
- **No merge/dedupe of repeated passes: crec_store_rows appends unconditionally while --list dedupes on ARFCN alone, collapsing distinct cells that share an ARFCN**
  - *Why it matters:* A drive test run twice doubles every row, and two operators on the same ARFCN (or a reused ARFCN) appear as one cell, so new-cell discovery is impossible
  - *Suggested:* `--merge with a unique key (arfcn+plmn+cell_id) writing first_seen/last_seen/seen_count, and --new-since <ts> to list cells not seen in an earlier pass`
  - *Evidence:* verified: modules/02_cell_recon.sh:422-431 (append loop) and modules/02_cell_recon.sh:446 `tail -n +2 "$CREC_CELLS"

### `modules/03_gsmtap.sh`

- **UDP port and bind address are fixed at 4729/0.0.0.0 and the pcap reader rejects any other port, so a second GSMTAP source or a non-default port is unusable**
  - *Why it matters:* Running grgsm_livemon (4729) alongside an srsENB/Open5GS GSMTAP feed on another port, or capturing a remote feed, silently yields "no GSMTAP received"
  - *Suggested:* `--port N and --iface ADDR on --listen/--read, and a --any-port read mode`
  - *Evidence:* verified: modules/03_gsmtap.sh:52 GTAP_PORT=4729, :293 `socat -u "UDP4-RECV:$GTAP_PORT,bind=0.0.0.0"`, :269 `if sp != 4729 and dp != 4729: continue`
- **No live streaming or hand-off: --listen buffers into a temp file and only materialises the pcap when the timeout expires, and nothing is piped to a dissector**
  - *Why it matters:* An operator cannot watch frames arrive in Wireshark while walking a site, and a wedged 5-minute listen gives them nothing at all until it ends
  - *Suggested:* `--listen --pipe (write the pcap to stdout / a FIFO for wireshark -k -i -) and --forward HOST:PORT to relay the GSMTAP live`
  - *Evidence:* verified: modules/03_gsmtap.sh:280-310 (timeout … > "$tmp", then gtap_write_pcap after) ; grep -rn -e "-k -i" modules/*.sh → no match
- **Capture timestamps are discarded: the reader prints only an ordinal and the hex payload, and the decode store has no time column**
  - *Why it matters:* Frames cannot be ordered against a tower survey or a drive-test log — the survey ts and the frame are unlinkable, so "what was seen on that cell at 14:32" is unanswerable
  - *Suggested:* `carry the pcap ts_sec/ts_usec into a ts_epoch/ts_utc column in decoded.tsv, plus --since/--until to bound a read`
  - *Evidence:* verified: modules/03_gsmtap.sh:274 `print("%d\	%s" % (n, g.hex()))` (ts parsed at :247 but never emitted) and modules/03_gsmtap.sh:316 store header with no ts field
- **No selective filtering or watchlist: every ARFCN, channel and payload type from every reachable source lands in the store**
  - *Why it matters:* A 30-second listen on a busy site produces thousands of rows the operator must post-filter, and there is no way to watch a specific subscriber identity across a whole capture
  - *Suggested:* `--listen --arfcn N --channel BCCH|SDCCH --uplink, and --watchlist FILE (TMSI/IMSI/IMEI list) flagging hits in identities-tsv`
  - *Evidence:* verified: modules/03_gsmtap.sh:597-620 gtap_cli_main exposes only --listen [SECS] [OUT]/--read/--decode-tsv; grep -rln "watchlist" modules/*.sh → no file

### `modules/04_tower_map.sh`

- **No manual position entry — coordinates come only from gpsd, and with no fix the point is written with empty lat/lon**
  - *Why it matters:* An operator using a phone GNSS or a surveyed reference point, or one whose gpsd will not start, cannot geo-tag a single observation; the data is stored but unplaceable and dropped from every export
  - *Suggested:* `--survey --at <lat,lon> / --record --at <lat,lon> (with optional --alt) bypassing gpsd and still recording ts/speed as empty`
  - *Evidence:* verified: modules/04_tower_map.sh:126-152 tmap_record takes position solely from tmap_gps_read (:69-86); the CLI dispatch at :486-500 has no --at/--lat/--lon
- **No import: a GPX/CSV/NMEA track or a colleague's point file cannot be loaded into the store, although gpsbabel is a declared dependency**
  - *Why it matters:* Two teams' surveys cannot be combined, and a drive test logged by a phone/other tool must be re-walked by hand
  - *Suggested:* `--import FILE [--format gpx|csv|nmea|auto] mapping onto the 12-column store, using gpsbabel for GPX/NMEA`
  - *Evidence:* verified: modules/04_tower_map.sh:486-500 verbs are list-tsv/history/export-*/clear/survey/start-gpsd only; grep -rn "gpsbabel" modules/*.sh → modules/00_deps.sh:175 and :980 only
- **Exports are point-only: the KML writer emits a Placemark per observation and never a LineString/gx:Track, and there are no coverage-radius or cell-area polygons**
  - *Why it matters:* The map shows dots, not the route driven or the area a cell serves, which is the first thing a planner wants from a drive test
  - *Suggested:* `--export-kml --track (ordered LineString from ts) and --export-kml --coverage-radius N computing a circle/hull per cell`
  - *Evidence:* verified: modules/04_tower_map.sh:279 the only geometry emitted is `<Point><coordinates>`; grep -n "LineString\\|Polygon\\|gx:Track" modules/04_tower_map.sh → no match
- **No cell-centric aggregation: history counts distinct cells only, with no per-cell point count, best level, first/last seen or extent**
  - *Why it matters:* The operator cannot say how many observations a cell has, whether a cell is new, or where its edge is — the per-cell view has to be rebuilt in awk by hand
  - *Suggested:* `--cell-summary-tsv emitting plmn, cell_id, arfcn, points, best_rsrp, first_ts, last_ts, lat/lon bbox per cell`
  - *Evidence:* verified: modules/04_tower_map.sh:205-222 tmap_history prints only points/with_fix/without_fix/distinct_cells/all; no per-cell verb in dispatch :486-500 (trilateration is a sibling capability, modules/39_ta_geoloc.sh --trilaterate, so not claimed here)

### `modules/05_field_kit.sh`

- **The UDP emitter is hard-wired to 127.0.0.1:4729 with no host/port option**
  - *Why it matters:* The kit cannot drive a second machine's Wireshark or a remote capture rig — the headline use of a synthetic source on a multi-host test bench
  - *Suggested:* `--emit … [--to HOST:PORT] (default 127.0.0.1:4729) and a --port alias`
  - *Evidence:* verified: modules/05_field_kit.sh:190 `s.sendto(bytes.fromhex(hx), ('127.0.0.1', 4729))`; dispatch modules/05_field_kit.sh:520 passes only scenario/count/delay/target
- **Scenarios cover GSM Um and LTE only — no UMTS RRC, NR RRC/NAS, S1AP, NGAP, Abis or SS7 traffic**
  - *Why it matters:* The toolkit's own GSMTAP module names those payload types (modules/03_gsmtap.sh:84-105), so the 3G/5G decoders and the 03_gsmtap/store path cannot be exercised without live hardware
  - *Suggested:* `add umts-rrc, nr-attach (RRC+NAS), s1ap-attach, ngap-attach and ss7-map scenarios to fk_scenario_frames and to --scenarios`
  - *Evidence:* verified: modules/05_field_kit.sh:108-152 case covers gsm-idle/gsm-attach/lte-attach/mixed/imsi-catcher only; --scenarios list at modules/05_field_kit.sh:523-524
- **Every identity, PLMN, ARFCN and level is baked into the frames — one fixed IMSI (310150123456789f), PLMN 208-01, ARFCN 42/6300**
  - *Why it matters:* A watchlist/identity-exposure or paging-tracker rule cannot be regression-tested against a different operator or a rotated identity set, so a detector that only matches these bytes passes anyway
  - *Suggested:* `--emit … --imsi <hex|list> --plmn <mcc-mnc> --arfcn N --level-dbm N, plus --random-identities N generating a distinct IMSI/TMSI pool per run`
  - *Evidence:* verified: modules/05_field_kit.sh:111-140 hard-coded payload literals (e.g. `062103310150123456789f`); fk_emit signature at :167-169 accepts only scenario/count/delay/target

### `modules/06_gsm_air.sh`

- **Only A5/1 is implemented: A5/2 and A5/3 get a name and a break-status string but no keystream generator**
  - *Why it matters:* A5/2 is the cipher a downgrade forces onto the MS (modules/07_gsm_attack.sh:205-206 tells the operator to "recover the key with the 16-bit-work factor attack and decrypt") yet nothing in the toolkit can produce the A5/2 keystream to do it
  - *Suggested:* `--a5-2-keystream <kc-hex> [bits] [fn] (and --a5-3-keystream / KASUMI for A5/3), reusing the existing hex/bits helpers`
  - *Evidence:* verified: modules/06_gsm_air.sh:589-605 (name + break-status tables only); grep -rn -e "--a5-2" -e "--a5-3" -e "a5_2_keystream" modules/*.sh → no match
- **No decryption: there is no way to XOR a keystream against captured ciphertext to recover plaintext, even with the A5/1 keystream in hand**
  - *Why it matters:* The recovered bits are unusable without hand-rolled bit-order/frame-offset work, so the module stops one step short of the plaintext an analyst needs
  - *Suggested:* `--decrypt <kc-hex> <cipher-hex> [--alg a5/0|a5/1] [--fn N] printing plaintext hex/bits and the frame offset used, plus --decrypt-pcap to apply it per burst`
  - *Evidence:* verified: grep -rn -e "--decrypt" modules/*.sh → no match; modules/06_gsm_air.sh:647-687 implements the keystream only (XOR implementations exist only for VoLTE in modules/30_volte_ims.sh:102)
- **SI5 and SI6 are named but have no field map, so --decode-si aborts on the SACCH messages that carry the neighbour-cell list**
  - *Why it matters:* During a call (and in any drive test) the neighbour ARFCNs and their power offsets arrive in SI5/SI6; an operator cannot read the handover candidate set or compare it with SI2 from BCCH
  - *Suggested:* `add SI5/SI6 cases to gair_decode_si reusing gair_decode_ba_list (plus the SI5 power-offset/indicator octets)`
  - *Evidence:* verified: modules/06_gsm_air.sh:202 names SI5/SI6 but modules/06_gsm_air.sh:388-408 dispatches only SI1/SI2/SI2bis/SI2ter/SI3/SI4/SI13 and :405 prints "no field map for message type 0x%02x"
- **Decoded SI is never persisted: the SI store and its writer exist but no verb calls it, and --decode-pcap only echoes tshark msgtype fields (no ARFCN, frame number or timestamp)**
  - *Why it matters:* A capture yields a transient list no other module can use, so the survey cannot accumulate SI per cell or correlate it with the tower map — despite the store's header promising mcc/mnc/lac/cell_id/t3212/neighbors/ts
  - *Suggested:* `--decode-pcap  --store (and --decode-si --store) writing arfcn/fn/ts/message/mcc/mnc/lac/cell_id/neighbors rows via gair_store_si_row, plus --si-tsv to read them back`
  - *Evidence:* verified: modules/06_gsm_air.sh:881-884 defines gair_store_si_row with no caller (grep call sites: :881 definition, :883 inside it, :1123 selftest init only); modules/06_gsm_air.sh:857-871 gair_decode_pcap prints raw `-e gsm_a.rr.msgtype -e gsm_a.msg_type` lines

### `modules/07_gsm_attack.sh`

- **no GSM RR CIPHERING MODE COMMAND (MT 0x35) frame builder**
  - *Why it matters:* the module's flagship a5-downgrade vector cannot produce the message that actually switches the MS to A5/0 or A5/2; 15_downgrade --build-security-mode GSM emits only a NAS-layout octet (A5/1 → 0x10, not the RR Cipher Mode Setting IE 0x01) and 19_cipher_audit only parses an existing 0635 frame
  - *Suggested:* `--build-cipher-mode <A5/0\\|A5/2\\|A5/3> → hex frame 06 35 0X`
  - *Evidence:* verified: prose row only at modules/07_gsm_attack.sh:291; octet builder modules/15_downgrade.sh:262-267; parser modules/19_cipher_audit.sh:467-474; grep -rnE '0635\\|ciphering_mode\\|CIPHERING MODE' modules/*.sh → no builder
- **no LOCATION UPDATING ACCEPT / TMSI REALLOCATION COMMAND builder**
  - *Why it matters:* the module's own tmsi-deanon plan step 4 orders a TMSI REALLOCATION COMMAND with an attacker-chosen TMSI, and a fake BTS must emit LOCATION UPDATING ACCEPT to keep the MS camped — neither message can be produced
  - *Suggested:* `--build-tmsi-realloc <tmsi> and --build-lu-accept <tmsi>`
  - *Evidence:* verified: plan step modules/07_gsm_attack.sh:218; only RR paging request/response builders exist at modules/28_paging_track.sh:436-442; grep -rnE 'LOCATION UPDATING\\|TMSI REALLOCATION' modules/*.sh → modules/06_gsm_air.sh:558,817 point tables only
- **no Mobile Station Classmark 1 / Classmark 3 codec**
  - *Why it matters:* only CM2 is coded (hard 5-octet input), so an operator cannot read the CM3 GERAN feature/multiband-A5 bits of a captured MS nor answer a CLASSMARK ENQUIRY asking for CM1/CM3
  - *Suggested:* `--classmark3 <hex> (decode) / --classmark3-encode`
  - *Evidence:* verified: `gatk_classmark_decode` requires `^[0-9a-f]{10}$` at modules/07_gsm_attack.sh:402-403; grep -rn 'classmark' modules/*.sh → 11 only plus the fixed blob `03 505886` at modules/28_paging_track.sh:288
- **no A5/3 (KASUMI) or A5/4 keystream**
  - *Why it matters:* live GSM networks run A5/3, so the Kc the module recovers with --kc-recovery cannot decrypt a real capture: the tree implements only A5/1 and A5/0
  - *Suggested:* `--a5-3-keystream <kc> [bits] [fn]`
  - *Evidence:* verified: A5/1 only at modules/06_gsm_air.sh:669-687 (`--a5-1-keystream` 10:1230); grep -rniE 'A5/3\\|KASUMI' modules/*.sh → modules/06_gsm_air.sh:584-603, modules/19_cipher_audit.sh:90-127, modules/50_gprs.sh:76-86, modules/07_gsm_attack.sh:361,599 — names/risk text, no keystream code

### `modules/08_umts_air.sh`

- **no UIA1/UIA2 f9 MAC-I computation or verification**
  - *Why it matters:* the module assembles the f9 input (COUNT-I‖FRESH‖DIRECTION‖MESSAGE) and prints `mac_i_bits 32` but never computes the MAC-I, so a captured RRC message cannot be validated and an integrity-protected message cannot be forged
  - *Suggested:* `--mac-i <ik> <count-i> <fresh> <dir> <msg>`
  - *Evidence:* verified: assembly-only at modules/08_umts_air.sh:371-407; grep -rnE 'f9\\(\\|f9_\\|kasumi_\\|snow3g_' modules/*.sh → no matches
- **no UEA1/UEA2 (f8) ciphering / keystream**
  - *Why it matters:* with the CK known, a captured UMTS session still cannot be decrypted and the module's integrity analysis assumes the cipher; nothing in the tree implements UEA
  - *Suggested:* `--uea-keystream <ck> <count-c> <bearer> <dir> [bits]`
  - *Evidence:* verified: grep -rniE 'UEA' modules/*.sh → modules/19_cipher_audit.sh:101-104 and modules/15_downgrade.sh:208-209,252-255 risk tables only; no f8 code
- **no primary scrambling code handling (PSC → code group / slot offset / slot) and no PSC decode from SIB5/SIB6 neighbours**
  - *Why it matters:* a scanned CPICH cannot be attributed to a scrambling code plan or cell, and the neighbour scrambling codes the SIB advertises are not decoded
  - *Suggested:* `--psc <0-511> and --decode-sib6-neighbours <hex>`
  - *Evidence:* verified: prose only at modules/08_umts_air.sh:254-255 (SIB5/SIB6 field map); grep -rnE 'scrambling\\|psc_\\|code_group\\|slot_offset' modules/*.sh → modules/12_nr_air.sh:9 and modules/55_nr_inject.sh:147-148 (NR) only
- **UARFCN band table is downlink-only and covers bands 1-8**
  - *Why it matters:* an operator capturing a UE uplink carrier gets no band attribution (no UL N ranges) and bands 9-14/19-22/25/26 come back as unknown
  - *Suggested:* `--uarfcn <N> ul (or --band <n> [ul])`
  - *Evidence:* verified: `uair_band_of_uarfcn` modules/08_umts_air.sh:176-190 has DL ranges for bands 1-8 only; grep -rn 'uarfcn' modules/*.sh → modules/08_umts_air.sh only

### `modules/09_lte_attach.sh`

- **no EPS GUTI codec (decode or encode)**
  - *Why it matters:* a captured GUTI is printed as raw hex, so PLMN/MMEGI/MMEC/M-TMSI are unreadable, and the Attach Request builder is IMSI-only — a GUTI-based (type 2) attach cannot be forged
  - *Suggested:* `--decode-guti <hex> and --encode-guti <plmn> <mmegi> <mmec> <m-tmsi>`
  - *Evidence:* verified: raw passthrough modules/09_lte_attach.sh:238, layout comment 13:166, IMSI-only builder 13:447/170; modules/28_paging_track.sh:334 (S-TMSI) and modules/13_nr_core.sh:829 (5G-GUTI) are different formats
- **no NAS integrity (EIA1/EIA2 AES-CMAC) or ciphering (EEA2) computation**
  - *Why it matters:* the decoder prints a `nas_mac` it never checks, so a tampered or forged Security Mode Command / Attach Accept goes undetected and no UE-side NAS message can be signed
  - *Suggested:* `--nas-mac <knas-int> <count> <bearer> <dir> <msg>`
  - *Evidence:* verified: mac printed without verification at modules/09_lte_attach.sh:622,625; grep -rnE 'EIA\\|EEA\\|cmac' modules/*.sh → modules/19_cipher_audit.sh:110-127 and modules/15_downgrade.sh:252-255 tables only
- **no downlink EMM/ESM builders (Attach Accept, TAU Accept, ESM PDN Connectivity)**
  - *Why it matters:* the module can only build the UE side, so it cannot stand in for an MME/eNB and complete an attach — the sole EMM encoder is `latt_build_attach_request`
  - *Suggested:* `--build-attach-accept <guti> [tai-list]`
  - *Evidence:* verified: grep -rnE 'Attach Accept\\|TAU Accept\\|attach-accept' modules/*.sh → modules/27_cellular_dns.sh:860,943 (PCO decode prose) and modules/54_baseband_exploit.sh:226-227 (state names) only; encoder modules/09_lte_attach.sh:447
- **--imsi-decode hardcodes MCC 3 digits + MNC 2 digits with no MNC-length input**
  - *Why it matters:* for a 3-digit-MNC operator (e.g. 310-260) the decode reports mcc=310 mnc=26 msin=0…, silently corrupting the subscriber identity
  - *Suggested:* `--imsi-decode <hex> [mnc_len]`
  - *Evidence:* verified: `mnc\	"${digits:3:2}"` at modules/09_lte_attach.sh:813-818; modules/16_sim.sh:510-535 `sim_decode_imsi` takes no MNC length either

### `modules/10_lte_air.sh`

- **SIB decode limited to types 1/2/3/5**
  - *Why it matters:* SIB4/6/7/8/13 (intra-frequency neighbours, ETWS/CMAS alerts, GERAN neighbours, MBSFN) cannot be read, so neighbour planning, public-warning and inter-RAT reselection analysis are impossible
  - *Suggested:* `--decode-sib <hex> [4\\|6\\|7\\|8\\|13]`
  - *Evidence:* verified: dispatcher/usage/menu modules/10_lte_air.sh:558-567, 1435, 1366; grep -rniE 'sib4\\|sib6\\|sib7\\|sib8\\|etws\\|cmas' modules/*.sh → only UMTS modules/08_umts_air.sh:233-261
- **no LTE MIB (24-bit BCH) decode**
  - *Why it matters:* a captured MIB yields nothing — downlink bandwidth, PHICH config and SFN/antenna info are unavailable; only an NR MIB decoder and an NB-IoT MIB reader exist elsewhere
  - *Suggested:* `--decode-mib <hex>`
  - *Evidence:* verified: grep -rni 'mib' modules/*.sh → modules/12_nr_air.sh:410 (NR) and modules/45_iot.sh:118-121 (NB-IoT); no LTE BCH path in modules/10_lte_air.sh
- **--gen-enb-conf hardcodes FDD (tm=1) with no TDD radio configuration**
  - *Why it matters:* LAIR_BANDS lists TDD bands 38/40/41/42/43, so a generated enb.conf for those bands starts an eNB with the wrong duplex and it never transmits
  - *Suggested:* `--gen-enb-conf … --tdd (writes tm=2 + tdd_ul_dl_config)`
  - *Evidence:* verified: `lair_gen_enb_conf` modules/10_lte_air.sh:681-720; grep -rnE 'tdd_ul_dl\\|subframeAssignment\\|tdd_config' modules/*.sh → modules/12_nr_air.sh:782 (NR) and modules/45_iot.sh:121 (NB-IoT) only
- **paging math has no eDRX/PTW support and ignores the accepted ue-id argument**
  - *Why it matters:* an eDRX (IoT/mMTC) UE is paged on H-SFN boundaries in a prolonged cycle, so the computed PF/PO is wrong and a tracker or attacker misses every paging occasion
  - *Suggested:* `--paging-frame <imsi> <tac> <ue-id> [T] [nB] [--edrx <cycle>] [--ptw <ms>]`
  - *Evidence:* verified: modules/10_lte_air.sh:583-630 (UE_ID always IMSI mod 1024, ue-id parsed then unused); grep -rniE 'edrx\\|h-sfn' modules/*.sh → modules/16_sim.sh:621-634 / modules/31_sim_defense.sh:153-182 (SIM EF_AD bits) only

### `modules/11_lte_core.sh`

- **no S1AP ASN.1 (APER) encoder/decoder — static procedure tables only**
  - *Why it matters:* an operator cannot build a forged InitialUEMessage/UplinkNASTransport to inject NAS over S1-MME, nor read an S1AP PDU without falling back to tshark, even though the module names S1AP identity procedures as a risk
  - *Suggested:* `--s1ap-build <nas-hex> and --s1ap-parse <hex>`
  - *Evidence:* verified: tables only modules/11_lte_core.sh:1136-1196 (CLI --s1ap 15:2228); modules/35_baseband.sh:85-97,418-419 is BER length only; tshark handoff modules/32_nas_signaling.sh:599, modules/17_pcap_analysis.sh:91
- **no S6a answer builders (AIA/ULA/CLA)**
  - *Why it matters:* only the requests (AIR/ULR/CLR) can be built, so the module cannot impersonate an HSS to answer an AIR with authentication vectors or a ULR with a subscription profile — the answer is where vectors and location hijack land
  - *Suggested:* `--build-aia <imsi> and --build-ula <imsi>`
  - *Evidence:* verified: builders modules/11_lte_core.sh:579,615,638 and CLI 15:2217-2218 (requests only); grep -rnE 'build-ula\\|build-aia\\|build_ula\\|build_aia' modules/*.sh → no matches
- **no GTP-C session-teardown / bearer-management forging (Delete Session 36, Create Bearer 95, Release Access Bearers 170)**
  - *Why it matters:* only Create Session (32) and Modify Bearer (34) can be forged, so a live UE session cannot be torn down and a redirected bearer cannot be set up — a top EPC DoS/interception primitive is out of reach
  - *Suggested:* `--gtp-delete-session <imsi> <ebi>`
  - *Evidence:* verified: modules/11_lte_core.sh:1542 (type 32) and 15:1554 (type 34) are the only forged messages; `lcore_gtpc_msg` 15:1511 takes any type but no teardown verb/IE assembly exists
- **no Gx/Gy policy-and-charging (CCR/CCA) build or decode**
  - *Why it matters:* Gx/Gy exists only as an app-id name, so policy-rule abuse and charging fraud — the EPC money path that --cdr-fraud-check reasons about — cannot be inspected on the wire
  - *Suggested:* `--decode-gx <hex> / --build-ccr`
  - *Evidence:* verified: modules/11_lte_core.sh:201 `16777219) echo "3GPP Gx"`, 15:148,150 CCR/CCA command names, 15:208 Gz name; no Gx message code

### `modules/12_nr_air.sh`

- **only SIB1 is decoded — SIB2-SIB21 unsupported**
  - *Why it matters:* the parser recognises the SIB2/SIB3 discriminators (24/26) but does not parse them, so a capture yields no RACH/PRACH config, reselection parameters, slice (S-NSSAI) mapping or SIB19 NTN data
  - *Suggested:* `--decode-sib <type> <hex>`
  - *Evidence:* verified: `nair_decode_sib1` modules/12_nr_air.sh:484 with discriminator switch 16:496-501 (SIB2/SIB3 named, unparsed); CLI 16:1480, usage 16:1499; modules/34_slicing.sh handles S-NSSAI separately
- **no CORESET#0 / searchSpaceZero derivation from pdcch-ConfigSIB1**
  - *Why it matters:* the MIB's key scheduling output is emitted only as a raw 8-bit value plus hi4/lo4 nibbles, so an operator cannot tell where CORESET#0 sits, its RBs/symbols, or which slots carry the SIB1 PDCCH
  - *Suggested:* `--coreset0 <pdcch_config_sib1> [scs]`
  - *Evidence:* verified: comment modules/12_nr_air.sh:405, raw hi4/lo4 at 16:444-446 (tests 16:1219-1221); grep -rniE 'coreset\\|searchspace' modules/*.sh → that comment only
- **no PBCH descrambling / soft-combining — MIB must be supplied already decoded**
  - *Why it matters:* an operator holding raw SSB/PBCH symbols cannot recover the MIB; the header cites TS 38.211 PBCH scrambling but no code implements it
  - *Suggested:* `--descramble-pbch <pci> <i_ssb> <hex>`
  - *Evidence:* verified: `nair_cmd_decode_mib` modules/12_nr_air.sh:1004 takes 6 hex digits of payload; grep -rniE 'pbch' modules/*.sh → modules/12_nr_air.sh:9 (comment) and modules/33_jamming_detect.sh:289,475 (failure counters) only
- **no NEA2/NIA2 RRC (SRB) ciphering or integrity codec**
  - *Why it matters:* a protected RRCReconfiguration / RegistrationAccept cannot be verified or forged and SRB payloads cannot be decrypted; only algorithm risk scoring exists, and 59 gets past the check solely by exploiting UEs that skip it
  - *Suggested:* `--rrc-mac <krrcint> <count> <msg>`
  - *Evidence:* verified: grep -rniE 'NEA\\|NIA' modules/*.sh → modules/19_cipher_audit.sh:123-127 risk rows; modules/54_baseband_exploit.sh:157-160 builds a MAC-less Registration Accept; no AES-CMAC/ZUC code in tree

### `modules/13_nr_core.sh`

- **no NEA2/NIA2 NAS de-protection (ciphering + integrity)**
  - *Why it matters:* any protected NAS PDU is reported as `unreadable-without-5g-nas-keys`, so all 5GMM signalling captured after the Security Mode Command cannot be decoded at all
  - *Suggested:* `--nas-decrypt <knas> <count> <msg> and --nas-mac <knas-int> <count> <msg>`
  - *Evidence:* verified: modules/13_nr_core.sh:806-811 prints `message_type_name\	unreadable-without-5g-nas-keys`; grep -rniE 'NEA\\|NIA' modules/*.sh → modules/19_cipher_audit.sh:123-127 tables only
- **no NGAP ASN.1 (APER) IE decode/encode — header and procedure code only**
  - *Why it matters:* the N2 payload cannot be read or forged: no NAS PDU, 5G-GUTI, cause or UE identity inside an InitialUEMessage/UplinkNASTransport, which is the core value of an NGAP module
  - *Suggested:* `--decode-ngap-ie <hex> / --ngap-build`
  - *Evidence:* verified: modules/13_nr_core.sh:219-277 (explicit comment that the PER body is not decoded); modules/35_baseband.sh:85-97 is BER length only
- **no PFCP wire encoder (Session Establishment with PDR/FAR/QER)**
  - *Why it matters:* --pfcp-rules is descriptive text, so an operator cannot inject an N4 rule to redirect or drop user-plane traffic; 34_slicing can only parse PFCP already present in a pcap
  - *Suggested:* `--pfcp-build <teid> <qfi>`
  - *Evidence:* verified: text rules modules/13_nr_core.sh:581-608, decode-only 17:537; modules/34_slicing.sh:450-492 parses IEs, modules/17_pcap_analysis.sh:544-550 header only
- **no 5G-AKA vector computation (Milenage f1-f5 / RES*, XRES*, AUTN)**
  - *Why it matters:* --aka-flow is a static 12-step description and only KSEAF is derived, so a rogue AUSF/SEAF cannot generate a valid 5G HE AV or validate an Authentication Response — the auth step of every 5G impersonation
  - *Suggested:* `--aka-vectors <ki> <opc> <sqn>`
  - *Evidence:* verified: flow text modules/13_nr_core.sh:627-642, KSEAF only 17:644; grep -rnE 'milenage\\|RES\\*\\|XRES\\|SQN' modules/*.sh → modules/30_volte_ims.sh:644, modules/11_lte_core.sh:413, modules/13_nr_core.sh:616-637, modules/08_umts_air.sh:441-449 — prose only

### `modules/14_suci.sh`

- **SUCI profile B with extended key id (scheme 3) is named and even counted by --audit, but no verb can build, conceal or deconceal it**
  - *Why it matters:* a Rel-17 home network that uses the extended key id cannot have its SUCIs generated, tested or unwrapped here, so the format that actually ships in new deployments is untestable
  - *Suggested:* `--build-suci 3 / --conceal 3 / --genkey 3 emitting scheme_output with the extra key-id byte`
  - *Evidence:* verified: 14_suci.sh:218 names it, :550 counts it as a profile, :603 rejects anything outside ^[012]$, :329 and :1148 restrict --conceal to 1|2
- **the CLI cannot set hn_public_key_id or routing_indicator, although suci_build takes both**
  - *Why it matters:* production networks use non-zero routing indicators and key ids, so the operator cannot produce a SUCI that matches the deployment under test or generate test vectors for a given HN key id
  - *Suggested:* `--build-suci <scheme> <msin> <hn-pub> [mcc] [mnc] [hn-key-id] [routing-indicator]`
  - *Evidence:* verified: suci_build:600-601 declares local hnkey=${6:-1} ri=${7:-0000} and prints both, suci_cmd_build:688-692 forwards five, dispatch 14_suci.sh:1121 passes five, usage :1138
- **no bulk SUCI→MSIN/IMSI audit: --deconceal takes exactly one SUCI plus key, and --audit takes a file but no home-network key**
  - *Why it matters:* an operator holding their own private key still cannot answer "which of the several thousand SUCIs in this capture are my subscribers", which is the audit that proves whether concealment is actually protecting anyone
  - *Suggested:* `--audit <sucis-file> --hn-key <priv-hex> printing per-SUCI scheme, MSIN and validity`
  - *Evidence:* verified: suci_cmd_deconceal:703-708 requires exactly two args, suci_audit:527-530 accepts only a filename, dispatch :1122-1123 has no key argument
- **no known-answer/test-vector mode for the Annex C concealment scheme**
  - *Why it matters:* encrypt-then-decrypt round trips pass even when HKDF, the info string or the initial counter block deviate from the spec, so interop with a real SM/HN cannot be proven
  - *Suggested:* `--kat / --vectors <profile-a|profile-b> running the published TS 33.501 Annex C vectors`
  - *Evidence:* verified: grep -icE 'test.vector|known.answer|\\bkat\\b' 14_suci.sh = 0; the only concealment check is a conceal→deconceal roundtrip at 14_suci.sh:957-958, which SKIPs when python3 is missing

### `modules/15_downgrade.sh`

- **no encoder for a forged SIB1/MIB that bars a cell (cellBarred / cellReservedForOperatorUse)**
  - *Why it matters:* the module's own method section names "a forged SIB with cellBarred set" as the way to suppress a higher-RAT cell, yet the operator can only plan it, never emit the frame
  - *Suggested:* `--forge-sib1 --barred 1 [--rat nr|lte] [--cell-id] emitting the SIB1 ASN.1/P2 payload hex`
  - *Evidence:* verified: 15_downgrade.sh:18 claims it, grep -icE 'sib1|cellbarred' 15_downgrade.sh = 1 (that comment only); sibling 12_nr_air.sh:404-411 parses cellBarred from the MIB only (nair_decode_mib:410, no build/encode function) and 10_lte_air.sh:307 mentions cellReservedForOperatorUse in a comment
- **no CS-domain MM reject causes (TS 24.008 §10.5.5.12) — table and builder carry EMM, 5GMM and GMM only**
  - *Why it matters:* the header cites 10.5.5.12, and the 2G/3G side of a CS-fallback downgrade is exactly where a Location Updating Reject or CM Service Reject with cause 15/22 is used, so the message that steers the UE after the fall cannot be built or decoded
  - *Suggested:* `--reject-cause mm <n> plus an mm arm in the encoding table (protocol discriminator 0x05, Location Updating Reject / CM Service Reject opcodes)`
  - *Evidence:* verified: 15_downgrade.sh:10 cites it, dwn_causes:79 has only emm/5gmm/gmm keys, dwn_reject_encoding:159 switch has no mm arm; sibling 32_nas_signaling.sh:300/344/396 has nasf_emm_cause_name, nasf_5gmm_cause_name and a cause dispatcher for eps/5gs only
- **--detect on a .pcap always reports CLEAN because the tshark→TSV step writes the literal "event" into the column the three detectors keyword-match**
  - *Why it matters:* an operator pointing the module at a capture full of Registration Rejects and RAT changes gets steering_rejects=0, rat_changes=0 and verdict CLEAN, i.e. the flagship detection verb silently never fires on real input
  - *Suggested:* `--detect  must emit ts, rat, <classified event name>, detail (or the detectors must read the detail field)`
  - *Evidence:* verified: 15_downgrade.sh:359-364 builds rows with printf '%s\	%s\	event\	%s\
- **--detect cannot read a capture at all when tshark is absent, with no fallback**
  - *Why it matters:* the tree ships a pure-python capture reader (module 17) and modules 18/19 both drive it, so on a bare field laptop the downgrade detector refuses its own input while its siblings work
  - *Suggested:* `--detect  routing through 17_pcap_analysis.sh --extract/--list when tshark is missing`
  - *Evidence:* verified: 15_downgrade.sh:356-357 prints 'no tshark — install wireshark-cli'; sibling 17_pcap_analysis.sh:920 always runs its own python parser and 18_imsi_exposure.sh:114-123 / 19_cipher_audit.sh:773-784 drive module 17 as a subprocess

### `modules/16_sim.sh`
- **the DPA model has no real trace acquisition: the traces are synthesised, so nothing here proves a card leaks**
  - *Why it matters:* `--dpa-sim` recovers a KI from traces it generated from the leakage model itself, which bounds what the
    attack needs (a correct model and aligned traces) but is not a measurement. A real COMP128-1 card may be masked, and then
    the Hamming-weight assumption the model rests on is simply false — COMP128-2/-3 exist precisely to break it.
  - *Suggested:* a capture path driving a PC/SC reader and a scope (`--plan dpa-lab` names the rig), recording RAND per trace,
    with alignment and a leakage-model check on the real data.
  - *Evidence:* verified: `--dpa-sim` calls tools/gsm_crypto.py `dpa_run`, which builds its traces from `dpa_hw` of the model's
    own table lookup plus seeded Gaussian noise; every verb prints `scope synthetic traces ... not a measured card`;
    `grep -rniE 'pyvisa' modules/*.sh tools/*.py` = 0 hits, so no instrument-control call exists anywhere in the tree. The
    only occurrences of 'oscilloscope' are the dpa-lab plan text and the honesty notes (16_sim.sh:1297, :1565, :1782).
- **only three EF contents can be decoded (ICCID, IMSI, EF_AD); the module names 40+ files but returns raw hex for the rest**
  - *Why it matters:* after --read-binary on EF_LOCI, EF_FPLMN, EF_HPLMNwAct, EF_UST, EF_SPN, EF_KEYS or EF_EPSLOCI the operator gets a hex blob the module cannot interpret, so the classic "where was this card last used / which PLMNs are barred / which services are enabled" questions stay unanswered
  - *Suggested:* `--decode-ef <fid> <hex> covering LOCI/PSLOCI/EPSLOCI (TMSI+LAC), FPLMN/HPLMNwAct/OPLMNwAct (PLMN lists), UST/EST (service bitmaps), EF_KEYS/EF_KEYSPS (CK/IK)`
  - *Evidence:* verified: decoders are only sim_decode_iccid:483, sim_decode_imsi:510, sim_parse_ef_ad:593; the other FIDs appear solely in the sim_file_name table 16_sim.sh:178-224 and its selftest name checks :1902-1904
- **no Milenage / USIM-5G AKA computation (f1–f5) and no OPc derivation**
  - *Why it matters:* the operator cannot compute RES/CK/IK/AUTN from Ki+OPc+RAND, so a USIM cannot be validated and a replayed or forged authentication cannot be distinguished from a real one; the only key derivation in the tree is a fake
  - *Suggested:* `--aka <ki32> <opc32> <rand32> [sqn] [amf] printing mac-a/mac-s/res/ck/ik/autn, plus --opc <ki> <op>`
  - *Evidence:* verified: grep -rniE 'milenage' modules/*.sh = 1 hit and it is prose (30_volte_ims.sh:644); grep -n '\-\-aka' modules/16_sim.sh = 0 hits. NOTE (updated): the arithmetic now DOES exist — tools/gsm_crypto.py implements Milenage f1-f5* and OPC derivation, asserted against TS 35.208 Test Sets 1-20, and 20_gsm_cve.sh:470-472 shells out to it with --comp128 — so what remains is the module-level --aka verb, not the cipher. The earlier claim that 20_gsm_cve.sh:460-466 was sha256(KI||RAND)[0:8] is stale; gcve_comp128_kc no longer exists.
- **no ATR decoder**
  - *Why it matters:* the first thing an operator does with an unknown card in a PC/SC reader is read the ATR, and the module finds the reader and lists it but cannot tell a T=0 GSM card from a T=1 USIM, an eUICC or a Java card, nor flag a malformed checksum
  - *Suggested:* `--atr <hex> decoding TS, T0, TA/TB/TC/TD, the historical bytes and the TCK checksum`
  - *Evidence:* verified: grep -rniE 'atr' modules/*.sh matches only comments at 16_sim.sh:59 and 16_sim.sh:590 (grep -icE 'CHV' and 'UNBLOCK' are 0)
- **no PIN/CHV workflow: no VERIFY/CHANGE/ENABLE/DISABLE CHV and no UNBLOCK with the PUK**
  - *Why it matters:* the module decodes the PIN/PUK/ADM state out of EF_AD (menu item 6) yet gives the operator no way to act on it, so unlocking a card or re-enabling a disabled PIN is hand-built APDU hex with no tracking of the remaining-tries counter that decides whether the next attempt bricks the card
  - *Suggested:* `--pin <verify|change|enable|disable|unblock> <pin> [new-pin] emitting the VERIFY/CHANGE/UNBLOCK APDU and the remaining-attempts count`
  - *Evidence:* verified: grep -icE 'chv' 16_sim.sh = 0 and grep -icE 'unblock' 16_sim.sh = 0 while sim_parse_ef_ad:593 reports PIN/PUK state; sim_build_apdu:283 is generic CLA/INS/P1/P2/data/Le so nothing PIN-aware exists

### `modules/17_pcap_analysis.sh`

- **no display filter or frame/time-window selection on any verb**
  - *Why it matters:* on a multi-gigabyte job capture the operator cannot narrow to one subscriber, one protocol or the two minutes around an event before harvesting identities, and the identity store is polluted by every other test on the network
  - *Suggested:* `--filter <tshark display filter> plus --after/--before <epoch> (and the matching predicate in the fallback reader)`
  - *Evidence:* verified: the embedded parser accepts only --file/--mode/--limit/--frame/--layer/--max-frames (17_pcap_analysis.sh:447-454) and grep -c -- '-Y' 17_pcap_analysis.sh = 0
- **the tshark backend is detected and advertised but never used: every verb runs the hand-written python reader**
  - *Why it matters:* S1AP, NGAP, Diameter and GTP payloads come back as opaque bytes (--extract <frame> <layer> prints hex) and identity harvesting is byte-pattern guessing (find_identities:722), so real dissection fields — message names, causes, UE IDs — are unavailable on a machine that has tshark installed
  - *Suggested:* `--backend tshark|python (or --fields <tshark -e list>) execing tshark -r <file> -T fields -e ...`
  - *Evidence:* verified: pcap_run:908-920 unconditionally runs pcap_read.py, header :12 claims 'field extraction per protocol via -T fields', :907 claims 'backend dispatch: tshark when present', and selftest :1383 asserts grep -c 'tshark' pcap_read.py = 0; pcap_find_tshark:875 only reports the path
- **no way to decrypt a capture with a supplied key**
  - *Why it matters:* after recovering or being handed Kc/KASME the module still cannot present the NAS or user-plane plaintext, so the analyst has to leave the toolkit even though this is the verb that makes a capture readable
  - *Suggested:* `--decrypt  --key <hex> [--bearer <n>] [--alg A5/1|A5/3|EEA2|NEA2] emitting the decrypted frames`
  - *Evidence:* verified: grep -ic 'decrypt' 17_pcap_analysis.sh = 0, and tree-wide the only decrypt hits are prose or unrelated code (07_gsm_attack.sh:200-236, 29_mac_layer.sh:608-655, 30_volte_ims.sh:13, 14_suci.sh:453)
- **no multi-capture merge**
  - *Why it matters:* a job that produces per-RAT or per-interface captures (one file per test, per SDR, per session) cannot be combined, and the identity and conversation views are therefore always partial
  - *Suggested:* `--merge <pcap...> -o <out.pcap>`
  - *Evidence:* verified: grep -icE 'merge|mergecap' 17_pcap_analysis.sh = 0 and grep -rniE 'mergecap|--merge' modules/*.sh = 0 hits tree-wide

### `modules/18_imsi_exposure.sh`

- **--marlin needs a caller-authored conn/gen/msg/exposing TSV that no part of the toolkit produces**
  - *Why it matters:* the IMSI-catcher verdict (z-score against a per-generation baseline) cannot be reached from the capture the operator actually has; the only producer in the repo is the selftest's hand-written fixture
  - *Suggested:* `--marlin-from-pcap  classifying each NAS/RR message against imsi_exposing_msgs:701 and feeding imsi_marlin:732`
  - *Evidence:* verified: imsi_marlin:732-738 reads a file argument, and its only other caller/fixture is the selftest at 18_imsi_exposure.sh:1045-1046; imsi_exposing_msgs:701 emits the catalogue, not per-connection counts
- **no live or streaming capture: harvesting is file-only**
  - *Why it matters:* exposure monitoring is a real-time job — the point is to see a subscriber pushed to a null-cipher cell or an Identity Request as it happens — and the operator has to stop, save a pcap and re-run
  - *Suggested:* `--live <iface> [--duration <s>] streaming the harvest, map and marlin verdicts`
  - *Evidence:* verified: grep -icE 'iface|interface' 18_imsi_exposure.sh = 0; harvest goes only through imsi_harvest_pcap:114-129 calling module 17 --identities on an existing file, and no module implements live capture (13_nr_core.sh:867 and 16_sim.sh:1354 are prose suggestions to run tshark/tcpdump yourself)
- **no 5G temporary-identity harvesting: the map and scorer handle guti/5g-guti/m-tmsi/suci but module 17 never emits them**
  - *Why it matters:* a 5G-GUTI or M-TMSI seen next to a SUCI is never bound, so on an NR capture the module reports no mappings and no 5G exposure at all
  - *Suggested:* `extend the harvester to emit 5g-guti/m-tmsi/suci (module 17 find_identities or a --identities --kinds flag here)`
  - *Evidence:* verified: 18_imsi_exposure.sh:163 whitelists imsi|imei|imeisv|tmsi|ptmsi|m-tmsi|guti|5g-guti|msisdn|suci|supi and :226/:253/:401-402 bind guti|5g-guti|m-tmsi, while 17_pcap_analysis.sh:783-791 only ever appends imsi, imei, imeisv and tmsi
- **the identity rows module 17 produces carry no PLMN, timestamp or cipher, although the scorer reads all three**
  - *Why it matters:* the per-subscriber PLMN list, first/last-seen and the null-cipher score component are permanently empty for captures, so a subscriber dumped to a null-cipher cell is scored the same as one that was not
  - *Suggested:* `--enrich  (or harvest writing plmn/ts/cipher) so the store has the columns imsi_score_one already expects`
  - *Evidence:* verified: 18_imsi_exposure.sh:451/:455/:459 read fields 9, 11 and 12, while module 17's store header and writer emit 8 columns (17_pcap_analysis.sh:1016, :1051) and :686 writes exactly file/frame/kind/value/proto/src/dst/where

### `modules/19_cipher_audit.sh`

- **--from-pcap audits exactly one frame (default frame 1)**
  - *Why it matters:* a one-hour capture with hundreds of Security Mode Commands has to be walked frame by frame by hand, so a network-wide cipher audit is impractical; the module can only score what the operator already narrowed to
  - *Suggested:* `--audit-pcap  iterating the capture and emitting one row per SMC/SMC-Complete with its negotiated and advertised algorithms`
  - *Evidence:* verified: caud_cmd_from_pcap:773-775 declares ` [frame]` with frame="${2:-1}" and extracts a single frame's layer hex at :784-790, with no loop over frames anywhere in the module
- **sessions record a PLMN but no cell identity, and nothing rolls up by cell or PLMN**
  - *Why it matters:* the deliverable of a cipher audit is "which cells still negotiate A5/1 or EEA0", and without a cell/CI column the operator cannot produce that list or track one cell over time
  - *Suggested:* `--cell <mcc-mnc-ci> on --session plus --by-cell/--by-plmn aggregation`
  - *Evidence:* verified: caud_sessions_init:540-543 schema is session, gen, enc_alg, int_alg, ue_enc_caps, ue_int_caps, plmn, ts, note; grep -icE 'cell' 19_cipher_audit.sh = 1 hit and 'per.cell|aggregate|group.by' = 0
- **the UE's advertised algorithm sets cannot be extracted from a capture — --parse-smc rejects every message that is not a Security Mode Command (0x5D)**
  - *Why it matters:* the module's strongest finding, UE_CAPABILITY_DOWNGRADE ("UE advertised ZUC but SNOW 3G was negotiated"), is unreachable from a capture because the advertised list lives in the Security Mode Complete / UE network capability IE, which must be typed in by hand as the 4th and 5th --session arguments
  - *Suggested:* `--parse-smc-complete <hex> (or accept 0x5E and the Attach/Registration Request UE-capability IE) emitting ue_enc_caps/ue_int_caps`
  - *Evidence:* verified: 19_cipher_audit.sh:417-420 and :447-450 abort with "is not a Security Mode Command (0x5D)" for any other message type; caud_cmd_session:554-561 takes enc_caps/int_caps only as positional arguments
- **no cross-generation or per-subscriber chaining: a session row has no subscriber key, so one subscriber's LTE→GSM fallback is scored as two unrelated sessions**
  - *Why it matters:* the inter-RAT downgrade that matters in practice (an EEA2/ZUC session falling to A5/1 or A5/2 at CS fallback) never appears as a single downgrade finding, and the strongest per-generation algorithm baseline is computed across unrelated subscribers
  - *Suggested:* `--session ... --imsi/--tmsi <id> and --downgrade-check --chain flagging a rank regression across generations for the same key`
  - *Evidence:* verified: caud_sessions_init:540-543 has no subscriber column, grep -icE 'imsi' 19_cipher_audit.sh = 0 real hits (only the IMSISTING_ROOT paths), and caud_cmd_downgrade_check:627-737 compares each session against its own generation only

### `modules/20_gsm_cve.sh`

- **[ADDRESSED] `--kc` is now real A3/A8 (COMP128-1/2/3), validated against published known-answer vectors — reproduced above as `04A66BA8`/`F87EB8222CEA3400`. Was: sha256(KI||RAND) truncated to 8 hex**
  - *Why it matters:* the DEFAULT-KEY-SUPPORT finding ("does the card ship a default authentication key") and the --probe KC verdict rest on a hash, so a card with a genuine default key is indistinguishable from one with a random key
  - *Suggested:* `--kc [--comp128-1|--comp128-2|--comp128-3] <ki32> <rand32> implementing TS 51.011 Annex A3/A8, plus --kc-verify <known-answer Kc>`
  - *Evidence:* verified: gcve_comp128_kc:460-466 is printf '%s%s' "$ki" "$rand"
- **no severity or impact ranking on any of the ~30 ids, and no way to order a work list**
  - *Why it matters:* a triage-conscious operator cannot tell a remote-compromise baseband bug from an information-disclosure MAP probe, so the finding list cannot be turned into a priority order
  - *Suggested:* `a severity/CVSS column plus --severity <critical|high|medium|low> and --group-by severity`
  - *Evidence:* verified: grep -icE 'severity|CVSS|impact' 20_gsm_cve.sh = 0; gcve_cve_table:96-131 emits only id, kind, class, needs, description
- **no applicability mapping: no vendor, model, firmware or affected-artefact field ties an id to a target**
  - *Why it matters:* asked "is my handset / this card / this operator exposed", the module can only say what hardware the *test* needs, never what the *bug* affects, so it cannot answer the question that scopes an engagement
  - *Suggested:* `--target <vendor|model|firmware> (affected column per id) filtering the table, e.g. --list-cves --target MediaTek`
  - *Evidence:* verified: grep -icE 'affected|vendor|device|baseband.model' 20_gsm_cve.sh = 6, all inside prose handoff text (:100, :591, :605, :611) and a variable name (:56); the table's field 4 is the testbed requirement only (gcve_needs_of:163)
- **the table cannot be filtered by kind or by what the operator actually has, even though the code already computes both groupings internally**
  - *Why it matters:* with a single emulator and no Faraday cage, the operator gets all ~30 ids dumped and has to read the handoff text of each to find the handful that are runnable today
  - *Suggested:* `--list-cves --kind <ss7-map|sim-toolkit|gsm-cipher|...> and --have <emulator|lab-stp|programmable-sim|...>`
  - *Evidence:* verified: gcve_ids_of_kind:155 and gcve_sort_rank:133 exist but no CLI arm exposes a selector; the dispatch at 20_gsm_cve.sh:1119-1135 offers only --list-cves/--list-findings/--run-cve/--probe/--plan/--bcd/--kc/--runs-tsv/--status-tsv

### `modules/21_lte_cve.sh`

- **no way to point a probe at the operator's own evidence (pcap or raw hex): probe inputs are fixed text corpora at $CAPTURES_DIR/lte/*.txt, overridable only via undocumented LCVE_*_ARTEFACT env vars**
  - *Why it matters:* on a real EPC/radio job the evidence is a pcap of NAS/RRC/Diameter/GTP, not a pre-split .txt corpus, so no probe can be run against the actual traffic and tshark is invoked only for -v
  - *Suggested:* `--probe <WHAT> --pcap <file> (decode with tshark -e nas/rrc/diameter/gtp fields) plus --artefact <kind> <file>`
  - *Evidence:* verified: modules/21_lte_cve.sh:209-221, dispatch :1275-1292 has no pcap/artefact arg, :549-550 tshark version only
- **the CVE table has no affected product, release or fixed-in metadata (columns are id kind class needs label)**
  - *Why it matters:* an operator on a vendor advisory cannot answer "which of these ids apply to this baseband or EPC release" without opening every advisory by hand
  - *Suggested:* `add product/affected/fixed columns and --list-cves --product <name>`
  - *Evidence:* verified: modules/21_lte_cve.sh:85-87
- **no way to consult a CVE outside the hardcoded table: an unknown id is rejected outright, and no import path exists**
  - *Why it matters:* a vendor advisory published after this table (the common case on a live job) cannot be recorded, planned or triaged at all
  - *Suggested:* `--lookup <CVE-ID> and --import-cves <tsv> to extend the table without editing the script`
  - *Evidence:* verified: modules/21_lte_cve.sh:86 hardcoded heredoc table, :870-873 unknown id returns ERROR
- **runs are never stamped with the network under test: LCVE_PLMN is read from $TMP_DIR/target_plmn but nothing ever writes it and no verb sets it**
  - *Why it matters:* the run history's target column can never name the PLMN the evidence came from, so results from two sites are indistinguishable
  - *Suggested:* `--target <mcc-mnc> writing target_plmn, plus a --runs-tsv target filter`
  - *Evidence:* verified: modules/21_lte_cve.sh:53 and :201-202 (read only; grep 'target_plmn' has no writer and no CLI arg)

### `modules/22_nr_cve.sh`

- **no pcap or hex ingest for 5G interfaces and no NGAP/NAS-5GS/SBA message decoder (only --snssai): artefacts are line-text at fixed paths behind NCVE_*_ARTEFACT env vars**
  - *Why it matters:* with a capture of N2/N4 or SBA HTTP/2 the kit cannot be given anything, so its 5GC probes can never be pointed at real evidence
  - *Suggested:* `--probe NGAP --pcap <file> and --decode-ngap <hex> / --decode-nas5gs <hex>`
  - *Evidence:* verified: modules/22_nr_cve.sh:194-205, dispatch :1054-1066 (no pcap/hex/decode verb), grep -i pcap in module = 0 hits
- **the CVE table has no affected NF, product or version column (only kind/class/needs/label) so an id cannot be tied to a 5GC implementation release**
  - *Why it matters:* an operator running Open5GS or free5GC cannot tell which of the listed ids their build is actually exposed to
  - *Suggested:* `product/affected/fixed columns and --list-cves --product open5gs`
  - *Evidence:* verified: modules/22_nr_cve.sh:81-86
- **--list-findings prints a static catalogue of findings, never the findings the captured evidence triggers, and no verb joins recorded runs or artefacts to a finding**
  - *Why it matters:* the operator gets documentation instead of a result: there is no severity, no evidence line and no file to hand over after an assessment
  - *Suggested:* `--report --from-runs emitting finding id, severity, artefact and evidence into loot`
  - *Evidence:* verified: modules/22_nr_cve.sh:629-639 hardcoded heredoc, :670 list-findings calls it only
- **no 5G-GUTI or SUPI-format decoder (the only identity decoder is --snssai)**
  - *Why it matters:* NAS and N2 captures carry the 5G-GUTI (MCC/MNC/AMF region+set+pointer/5G-TMSI) and that is how a subscriber is followed across a capture; a 5G kit that decodes slices but not the identity leaves the subject opaque
  - *Suggested:* `--decode-5guti <hex> and --decode-supi <hex>`
  - *Evidence:* verified: grep -ri guti modules/*.sh = only 09_lte_attach.sh:160-238 (EPS/4G GUTI), no 5G-GUTI anywhere; modules/22_nr_cve.sh:1064 is the only identity decode

### `modules/23_traffic_analysis.sh`

- **no GTP-U or GTP-C handling at all: flows are keyed on the outer 5-tuple**
  - *Why it matters:* on any S1-U/S5/N3 capture every subscriber's traffic collapses into one PGW-to-SGW tunnel flow, so per-UE flows, up/down mix, app mix and fingerprints are all wrong
  - *Suggested:* `--flows --gtp-decap (auto-detect UDP 2152, key on inner IP/port plus TEID, report QFI/5QI)`
  - *Evidence:* verified: grep -ci gtp modules/23_traffic_analysis.sh = 0; flow keys at modules/23_traffic_analysis.sh:831-841 (endpoint_a/endpoint_b/proto)
- **no transport health measurement: no RTT, retransmission, loss, out-of-order or jitter anywhere in the module or the toolkit**
  - *Why it matters:* complaint work is delay and loss, but the kit reports only packet counts, byte ratios and shape, so "the app is slow" cannot be attributed to the bearer
  - *Suggested:* `--stats-tsv <pcap> per flow: RTT estimate, retransmission count, duplicate/out-of-order counts, loss percent`
  - *Evidence:* verified: grep -ci 'retrans/rtt/jitter/throughput' in 27 = 0; toolkit grep for retransmission/srtt hits only 31:1231 comment, 35:566 note, 54:92 NTN math, 17_pcap_analysis.sh = 0
- **flows are never named or attributed; the module states it sees ciphertext only with no payload, no SNI and no DNS**
  - *Why it matters:* fingerprints stay anonymous vectors, so on a job the operator cannot say which service or server a flow represents even though sibling 27_cellular_dns.sh already extracts the QNAMEs that would label it
  - *Suggested:* `--label-flows <pcap> joining DNS answers and SNI to flow keys and adding a service column to --flows`
  - *Evidence:* verified: modules/23_traffic_analysis.sh:6 (comment) and grep -in 'dns' in module = that comment only
- **no subscriber attribution: flows are IP-keyed with no join to GTP-C session state**
  - *Why it matters:* without S11/S5 Create Session (IMSI and MSISDN to UE IP) and the TEID mapping the module cannot answer "whose traffic is this", which is the first question in a cellular traffic investigation
  - *Suggested:* `--subscribers <pcap> emitting per-subscriber rows (IMSI, MSISDN, UE IP, TEID, bytes)`
  - *Evidence:* verified: grep -ci gtp in 27 = 0 and no imsi/s11 handling; sibling 17_pcap_analysis.sh:531-538 only names GTP-U message type and TEID

### `modules/24_rf_fingerprint.sh`

- **no SNR/CNR or EVM in --features: fields cover RMS, peak, PAPR, spectral flatness, DC, IQ imbalance and CFO but never a signal-to-noise split, and noise floor exists only on the --transient path**
  - *Why it matters:* SNR is the first number an RF practitioner records and the basis for judging whether a capture is usable or how far the emitter was, so every signature is stored without a link budget
  - *Suggested:* `snr_db and noise_floor_full_scale in --features (in-band vs out-of-band power ratio) and a dedicated --snr mode`
  - *Evidence:* verified: modules/24_rf_fingerprint.sh:793-822 (all out("iq",...) fields), grep -ci snr = 0, noise_floor only at :844 (transient)
- **only int8/int16/float32 I/Q files, no SigMF and no capture metadata (the signature row holds label/file/format/rate/samples/features only)**
  - *Why it matters:* SigMF is the standard recording format in cellular research and carries centre frequency, gain and time, so the operator must convert by hand and signatures taken on different bands are compared as if identical
  - *Suggested:* `accept SigMF (.sigmf-meta plus data), complex64 and CSV in --features/--sig-add, and store centre_freq/gain/timestamp in the signature row`
  - *Evidence:* verified: modules/24_rf_fingerprint.sh:129-133 IQ_FORMATS, :134-135 SIG_COLS, grep -rli sigmf modules/*.sh = 0 hits
- **--classify never rejects: it always prints top-k rank/label/score/distance with no confidence floor and no unknown verdict**
  - *Why it matters:* in the field an emitter that is not in the signature store is silently given a confident wrong label, which is exactly the case an operator must be able to see
  - *Suggested:* `--classify <iq> <fmt> <rate> --min-score <x> emitting verdict unknown when the best score falls below it`
  - *Evidence:* verified: modules/24_rf_fingerprint.sh:896 (rank header), grep -in unknown = 3 hits, all error strings (unknown sample format/mode/CSI format)
- **--transient describes only the first burst; there is no burst index, offset or window selection**
  - *Why it matters:* any recording with a preamble, a control burst or several transmissions yields burst 1 only, so the operator cannot measure or extract the burst of interest
  - *Suggested:* `--transient <iq> <fmt> <rate> --burst <n> and --window <start>:<len> reporting the selected start/end/len`
  - *Evidence:* verified: modules/24_rf_fingerprint.sh:836-842 (single start/end/len, no selection), dispatch :1711 takes three args only

### `modules/25_killchain.sh`

- **no per-step timeout or hang guard: each step runs as a bare bash invocation of the module with no timeout and no trap anywhere in the module**
  - *Why it matters:* a step blocked on a USB/serial SDR or a socket hangs the whole field chain indefinitely with no escape but Ctrl-C, while sibling 05_field_kit.sh already protects its runs with timeout 25
  - *Suggested:* `--step-timeout <s> recording a TIMEOUT status row in the run report`
  - *Evidence:* verified: modules/25_killchain.sh:443-447 (t0/t1 around the call) and :445 bare bash call, grep -c timeout/trap = 0; modules/05_field_kit.sh:300
- **no teardown or rollback steps: a chain that fails or is aborted leaves whatever earlier steps started (services, transmitters) running, and no module in the toolkit offers a stop or cleanup verb**
  - *Why it matters:* on a real job a failure at step 6 of 12 leaves the operator hunting for what was started, and an RF step keeps radiating with no recorded way to reverse it
  - *Suggested:* `a teardown column in the chain TSV plus --run --teardown executed on FAIL or abort and recorded in the report`
  - *Evidence:* verified: modules/25_killchain.sh:386-470 (loop emits only PASS/FAIL/SKIP), grep -rl for --teardown/--cleanup/--stop-all/--rollback across modules/*.sh = 0 hits
- **no per-step output capture: module stdout is inherited and the report row carries only step, module, verb, status, exit, seconds and detail**
  - *Why it matters:* the TSV, hex and findings each step produced are lost, so a completed job cannot be reviewed, diffed or handed over from the run record
  - *Suggested:* `--log-dir <dir> writing loot/killchain/<run>/<step>_<module>.out plus a log column in the report`
  - *Evidence:* verified: modules/25_killchain.sh:246-252 (report header has no output path), :445 stdout not redirected, no tee/LOG_DIR use in the module
- **no conditional or branching steps: only module presence and the hardware flag gate a step, and nothing reads a previous step's output**
  - *Why it matters:* a twelve-step chain must run to the end even after step 3 proves the target is not vulnerable, burning field time and adding exposure for no result
  - *Suggested:* `a per-step when=<regex> matched against the previous step's output, with the skip recorded like a hardware SKIP`
  - *Evidence:* verified: modules/25_killchain.sh:392-470 (gates are step<start, pause file, module exists, hardware only), :441-443 substitutes only {{target}}, grep -c condition/retry/when = 0

### `modules/26_ss7_map.sh`

- **the MAP operation encoders that already exist are unreachable from the CLI: sendAuthenticationInfo (SAI, opcode 56, authentication-vector retrieval), provideSubscriberInfo, updateLocation, insertSubscriberData and registerSS/activateSS have no --build verb, so only SRI, SRI-SM and ATI can be produced**
  - *Why it matters:* the most-used SS7/MAP attack primitive, SAI against a chosen IMSI, cannot be exercised at all, and the dead builders mean the operator has no way to hand a real MSU to a lab STP
  - *Suggested:* `--build-sai <imsi> [n], --build-psi, --build-ulr, --build-isd, --build-register-ss <ss-code> [forwarded-number]`
  - *Evidence:* verified: modules/26_ss7_map.sh:1026-1037 define the builders, dispatch :2024-2026 exposes only --build-sri/--build-sri-sm/--build-ati, grep for ss7_build_sai/ss7_build_ulr/ss7_build_isd finds definitions with no call sites
  - *Status:* **CLOSED** — `--build-sai/--build-psi/--build-ulr/--build-isd/--build-register-ss/--build-activate-ss` are all dispatched (modules/26_ss7_map.sh:2598-2603) through `ss7_cmd_build_extra` (modules/26_ss7_map.sh:1876), each reporting its opcode and a `roundtrip_opcode` proving builder and parser still agree, and each is reachable from the menu. The router/number arguments also reach the wire: `ss7_build_ulr` takes optional MSC and VLR numbers and `ss7_build_register_ss` takes the forwarded number, both length-prefixed.
- **--flow is hardcoded to a test identity and test point codes**
  - *Why it matters:* the four published flows (intercept, locate, sms-intercept, forward-hijack) can only be built for MSISDN 33612345678, IMSI 310150123456789 and OPC/DPC 00000001/00000002, so nothing can be produced for the operator's own target
  - *Suggested:* `--flow <name> [msisdn] [imsi] [opc] [dpc]`
  - *Evidence:* verified: modules/26_ss7_map.sh:1054-1055 (fixed identity constants), :1061-1068 (hardcoded point codes), :1517 (ss7_cmd_flow takes one arg)
  - *Status:* **CLOSED** — `ss7_cmd_flow` now takes msisdn, imsi, opc and dpc (modules/26_ss7_map.sh:1921) and `ss7_flow` threads them into every built step (modules/26_ss7_map.sh:1086); the selftest parses the built label back out of step 1 to prove the point codes are in the message rather than only in the header output.
- **no SIGTRAN/M3UA layer: the codec is MTP3-only, so an M3UA-over-SCTP capture cannot be decoded and no send-ready M3UA payload can be built even though the module's own plan says to send the MSU as the M3UA payload**
  - *Why it matters:* real interconnect traffic is SCTP/M3UA, which the module itself calls the modern exposure path; the operator must strip SCTP and M3UA headers by hand before --decode-msu sees anything
  - *Suggested:* `--decode-sigtran <hex> (strip SCTP common header and M3UA DATA) and --build-m3ua <msu-hex> [opc] [dpc] [si]`
  - *Evidence:* verified: grep -in m3ua/sctp modules/26_ss7_map.sh returns only :624 comment, :1128/:1133 prose and :1296-1396 plan text, no code path
  - *Status:* **CLOSED** — `--decode-sigtran` (modules/26_ss7_map.sh:1803) walks SCTP common header and DATA chunk, then M3UA, then hands the Protocol Data payload to the existing MTP3/SCCP decoder; `--build-m3ua` (modules/26_ss7_map.sh:1783) emits a send-ready DATA message with the 16-octet Protocol Data parameter and its RFC 4666 4-octet padding, and `ss7_m3ua_parse` (modules/26_ss7_map.sh:1707) round-trips the payload back to the input MSU. The optional arguments are routing-context and network-appearance, not opc/dpc/si — the MSU already carries those, and restating them would be the bug.
- **--detect reports no point code and no global title: the tshark extraction pulls only frame, calling/called SSN and opcode, and the rules key on SSN and opcode alone**
  - *Why it matters:* a finding names the opcode but not the OPC/DPC or called GT that sent it, so the operator cannot act on the offending interconnect peer or confirm which of their own nodes was queried
  - *Suggested:* `add mtp3.opc/dpc and sccp.calling/called.gt to the extraction and finding detail, plus a first-seen or unexpected point-code rule`
  - *Evidence:* verified: modules/26_ss7_map.sh:1249 (-e frame.number -e sccp.calling.ssn -e sccp.called.ssn -e gsm_old.opCode), rules :1200-1240 use SSNs only
  - *Status:* **CLOSED** — the tshark extraction now also pulls `mtp3.opc`, `mtp3.dpc`, `sccp.calling.digits` and `sccp.called.digits` (note: tshark defines no `sccp.calling.gt`, so the global title is the `digits` field), and every finding carries the routing context via `ss7_detect_route` (modules/26_ss7_map.sh:1222). `ss7_detect_stream` (modules/26_ss7_map.sh:1233) buffers the rows and adds a first-message-is-a-query rule: a point code whose very first message in the capture is ATI/SRI/SRI-SM/ULR/forwarding never announced itself with routine traffic. Four-column rows still work unchanged, and no point code is invented when the MTP3 columns are absent.

### `modules/27_cellular_dns.sh`

- **every non-UDP packet is dropped, so DNS over TCP and DoT are never decoded, only listed as an alternate port**
  - *Why it matters:* large answers and the TC=1 retry go over TCP/53 and DoT is TCP/853, so a capture can show a query with no answer and look like spoofing while the real reply sits unparsed on 853
  - *Suggested:* `decode TCP DNS (2-byte length prefix) on ports 53 and 853, and at minimum report queries whose answer arrived over TCP`
  - *Evidence:* verified: modules/27_cellular_dns.sh:580 (if proto != 17: continue), :601 (altport only)
- **encrypted DNS on 443 is invisible: the alternate-transport rule covers only 853 and 5353, with no TLS SNI or HTTP2 authority inspection**
  - *Why it matters:* DoH to a public resolver is the normal handset bypass on a mobile bearer, and the module then reports no resolver at all, so the operator cannot tell whether the aLTEr surface even exists on that UE
  - *Suggested:* `parse SNI or the HTTP2 authority on TCP 443 and report a doh class with the resolver hostname in --resolver-discovery`
  - *Evidence:* verified: modules/27_cellular_dns.sh:601 (ports 853/5353 only), grep -in for sni/authority/443 in the module = 0 hits
- **--build-response can forge only A and AAAA and cannot echo EDNS0: any other qtype is answered as a forced A record and the reply carries no OPT record**
  - *Why it matters:* a forged answer to a CNAME, ANY or HTTPS query is structurally wrong, and omitting OPT when the query had EDNS0 makes the rewrite distinguishable from the real resolver's reply, which defeats the point of building it
  - *Suggested:* `--build-response <query-hex> --rr <type>:<rdata> for CNAME/MX/TXT/SRV/PTR and --echo-edns0 reproducing the query's OPT, DO bit and UDP size`
  - *Evidence:* verified: modules/27_cellular_dns.sh:272-300 (single IP argument, forced A for non-address qtypes), :1087 build-response CLI
- **the RR type table has no NAPTR (35), SVCB (64)/HTTPS (65), CAA or TLSA**
  - *Why it matters:* NAPTR is the IMS/ENUM and MMS service-discovery record a cellular DNS audit is expected to read and SVCB/HTTPS carries ECH, so --decode-dns prints only a number for them and --build-query cannot ask for them
  - *Suggested:* `extend the name and code tables and the parser with NAPTR, SVCB, HTTPS, CAA and TLSA`
  - *Evidence:* verified: modules/27_cellular_dns.sh:115-144 (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT, DS, RRSIG, NSEC, DNSKEY, ANY only)

### `28_paging_track.sh`

- **No eDRX / PTW arithmetic: only legacy DRX paging-frame and occasion maths exists (pgt_gsm_params/pgt_lte_params/pgt_nr_params), so the extended-DRX cycle and the paging time window cannot be computed or predicted**
  - *Why it matters:* eDRX is how LTE-M/NB-IoT and power-saving UEs actually page; a tracker that cannot place the PO inside a PTW mis-times every capture window on those devices, since the HB/eDRX parameters arrive in SIB1 and the Attach Accept
  - *Suggested:* `--edrx-occ <imsi> <TeDRX> <PTW> [lte,nr] printing the PTW start and end frames plus every PO inside the window`
  - *Evidence:* verified: anchored grep -rlnE "eDRX,EDRX,extended DRX" modules/*.sh returned only modules/16_sim.sh and modules/31_sim_defense.sh, both decoding the EF_AD byte 3 eDRX access bit and neither computing a cycle; grep -c "eDRX" modules/28_paging_track.sh returned 0; occasion functions at modules/28_paging_track.sh:118,141,186
- **No WUS / paging-early-indication layer: pgt_parse_paging (modules/28_paging_track.sh:274) decodes the paging record identity and value only, with no PEI or WUS occasion, no PEI subgroup and no PEI-PDCCH monitoring occasion**
  - *Why it matters:* ToRPEDO-style and paging-collision work needs the occasion the UE actually wakes on; without it the module models the paging frame but not the real wake-up instant, and PEI is what NR deployments use to cut UE power
  - *Suggested:* `--pei-occ <imsi> [nr] emitting the PEI monitoring occasion, the PEI subgroup (UE_ID mod N) and the WUS occasion offset`
  - *Evidence:* verified: anchored grep -rlnE "\bWUS\b,paging early indication,\bPEI occasion\b" modules/*.sh matched no file; the loose substring hit in modules/32_nas_signaling.sh:347 is the 5GMM cause text "PEI not accepted" (permanent equipment identifier), not paging early indication
- **No per-UE paging-attempt history: each verb reads one capture per invocation (--detect, --torpedo-model) and there is no paging-attempt counter, no retransmission count and no time-of-day profile per UE_ID or TMSI across files**
  - *Why it matters:* "Was this subscriber paged once or twelve times before it answered?" is the first question in a paging-success investigation, and it is exactly what a paging tracker should hold; today the operator must re-run the module and count by hand
  - *Suggested:* `--paging-history <pcap...> maintaining pd_attempts, pd_first_ts, pd_last_ts and no_response_windows per UE_ID, with --flapping-tsv for repeat-page patterns`
  - *Evidence:* verified: dispatch at modules/28_paging_track.sh:1169-1178 exposes --po, --paging-parse, --torpedo-model, --piercer-correlate, --detect and --plan, each taking a single capture; the only counter in the tree is the intra-file paging_record_density at modules/28_paging_track.sh:757
- **GSM channel-needed and page-mode are not reported and the paging cause is absent: the RR paging request parser drops the channel-needed value (AGCH versus SDCCH), and there is no LTE or 5G paging-cause decode (voice versus data) and no CN-domain decode**
  - *Why it matters:* On a live job "paged but never answered" is usually the UE being pushed to SDCCH for a CS page or receiving a data-only page, and the answer decides whether the fault is coverage, subscription or a spoof; the 5G paging cause also gates whether the UE wakes for an incoming call
  - *Suggested:* `--paging-cause <hex> [lte,nr] and --page-mode <hex> [gsm] emitting cn_domain, paging_cause (voice, video, sms, other) and channel_needed`
  - *Evidence:* verified: anchored grep -rlnE "paging[_ -]?cause" modules/*.sh matched no file; grep -n "channel_needed,page_mode" modules/28_paging_track.sh matched nothing in pgt_parse_paging (modules/28_paging_track.sh:274) or pgt_parse_mi (modules/28_paging_track.sh:234)

### `29_mac_layer.sh`

- **No Random Access Response / contention-resolution decode: macl_ce_len (modules/29_mac_layer.sh:184) covers only the CE LCIDs and the detail parser understands the TA and DRX CEs, so the MAC RAR subPDU (12-bit timing advance, 20-bit uplink grant, temporary C-RNTI) and the RAPID in the RAR subheader are never decoded**
  - *Why it matters:* When UEs fail to attach or a RACH storm hits, the RAR is the first artifact an RF engineer inspects: whether a temporary C-RNTI was assigned and what timing advance the network granted separates coverage failure from preamble collision from a spoofed response
  - *Suggested:* `--rar-parse <hex> printing rapid, timing_advance_index, uplink_grant_rb, mcs, tpc and temporary_c_rnti per RAR subPDU`
  - *Evidence:* verified: grep -rn "RAPID" modules/*.sh matched nothing at all; grep -rn "\bRAR\b,random access" modules/29_mac_layer.sh matched nothing, and the LCID/CE tables at modules/29_mac_layer.sh:141,184 carry no RAR row (the earlier loose match was an unrelated substring)
- **HARQ outcome accounting is absent: --dci (macl_cmd_dci, modules/29_mac_layer.sh:1091) reports only trailing_harq_process, with no ACK or NACK counting, no retransmission statistic, no residual BLER and no PHICH or PUCCH feedback path**
  - *Why it matters:* "Good RSRP, bad throughput" is resolved by the HARQ failure rate per process; without ACK/NACK accounting the module can show grants but never whether the transmissions succeeded, so a practitioner cannot diagnose a failing HARQ process or persistent scheduling
  - *Suggested:* `--harq-stats <pcap> emitting per-process harq_process, tx_attempts, ack_count, nack_count, retx_rate and residual_bler_pct`
  - *Evidence:* verified: grep -n "HARQ,harq" modules/29_mac_layer.sh returned only the DCI fields at modules/29_mac_layer.sh:545,547,561,568; no ACK/NACK/PHICH/PUCCH parser exists (macl_ce_len at modules/29_mac_layer.sh:184 and macl_ta_fields at :201 decode only the TA and DRX CEs)
- **No NR MAC support: the module is LTE-only and no sibling implements an NR MAC decoder, so the TS 38.321 LCID table, the NR MAC CEs (BFR, LBT, SpCell timing advance) and the NR DL-SCH MAC PDU layout cannot be read**
  - *Why it matters:* Any 5G SA deployment is out of scope for the one module that owns layer-2 observation, even though 55_nr_inject.sh injects NR and srsRAN captures are common; worse, the operator gets an LCID misread from the LTE table rather than an explicit "NR not supported" error
  - *Suggested:* `--decode-mac --rat nr selecting the TS 38.321 LCID table and NR CE set, plus an explicit unsupported-RAT error instead of LTE table fallthrough`
  - *Evidence:* verified: grep -rln "38.321" modules/*.sh returned modules/55_nr_inject.sh only (an injection module, not a decoder); modules/29_mac_layer.sh:4-6 and macl_lcid_name (modules/29_mac_layer.sh:141) carry only the TS 36.321 UL and DL tables
- **No BSR, PHR or carrier-aggregation handling: there is no buffer-status-report decode (macl_ce_len at modules/29_mac_layer.sh:184 has no BSR row) and no LCID-1/2/3 short or truncated BSR or PHR, while SCell and carrier aggregation appear only as a LocationReport string in 11_lte_core.sh**
  - *Why it matters:* Buffer status explains the uplink scheduling decision ("why did the scheduler starve this UE"), PHR explains power-limited uplink, and SCell decoding is needed on every CA site; all three are standard MAC-layer evidence an operator expects from a MAC module
  - *Suggested:* `--bsr-parse <hex> [ul] and --phr-parse <hex> emitting buffer_size index and bytes and power_headroom_db, plus --ca-cells to attribute MAC PDUs to serving cells`
  - *Evidence:* verified: anchored grep -rniE "buffer status,\bphr\b,power headroom" modules/*.sh returned modules/54_baseband_exploit.sh only (a malformed-BSR test vector at modules/54_baseband_exploit.sh:242, not a decoder); grep -rln "carrier aggregation,SCell" modules/*.sh returned modules/11_lte_core.sh only, the LocationReport row

### `30_volte_ims.sh`

- **No IMS-AKA vector generation or SQN resynchronisation: --ims-registration (modules/30_volte_ims.sh:585) takes the AKA RES or AUTS as a caller-supplied hex argument, so the module never derives RES or MAC from K and RAND and never handles the AUTS path that follows a 401**
  - *Why it matters:* The digest check exists but depends on the operator already having a RES from the card; on a testbed with a known K the module cannot produce the vector, and after an SQN desynchronisation (the normal failure after a replayed or cloned USIM) it cannot verify or forge the registration at all
  - *Suggested:* `--aka-vector <ki> <rand> <sqn> [amf] emitting RES, CK, IK, AUTN, MAC-A, MAC-S, AK and the SQN, plus --aka-resync <auts> recovering the updated SQN from AUTS`
  - *Evidence:* verified: cmd_digest and its call site exist (modules/30_volte_ims.sh:464-475 and :634), so digest is NOT a gap; grep -nE "milenage,f1,f2,mac_a" modules/30_volte_ims.sh matched nothing, and the CLI list at modules/30_volte_ims.sh:1049-1061 exposes no AKA-vector or resync verb
- **No SIP transaction or call-flow state machine: the parser is message-at-a-time and derives no dialog, no CSeq or transaction matching, no retransmission ladder, no SIP response-code statistics and no RTP quality metrics (MOS, jitter, loss)**
  - *Why it matters:* A VoLTE complaint is "one-way audio" or "the call drops at three seconds": resolving it needs the call-flow pairing of INVITE, 100, 183, 200, ACK and BYE with timing, plus RTP jitter, loss and MOS; message-level parsing cannot answer any of it
  - *Suggested:* `--sip-flows <pcap> emitting per-Call-ID dialogs with method and response pairs, setup latency, retransmissions and teardown cause; --rtp-quality <pcap> emitting jitter_ms, loss_pct and MOS`
  - *Evidence:* verified: the function list of modules/30_volte_ims.sh (grep -n "^vims_[a-z_]*() {") contains only parse, register, revolte, imp4gt, imei, flood and plan helpers with no dialog-state or RTP statistics verb, and the --sip-parse path (modules/30_volte_ims.sh:1053) emits per-message fields only
- **No IMS core interfaces: no Diameter Cx decode (UAR/UAA, MAR/MAA, SAR/SAA) and no Rx or Gm handling, so S-CSCF assignment and the authentication-vector request are invisible even though 26_ss7_map.sh owns TCAP/MAP and 17_pcap_analysis.sh owns pcap reading**
  - *Why it matters:* VoLTE registration failures are diagnosed at Cx: which S-CSCF was assigned and whether the MAR returned a vector tells the operator whether the fault is HSS, P-CSCF or UE; a VoLTE module that stops at SIP cannot answer the question its own topic is about
  - *Suggested:* `--cx-flow <pcap> and --diameter-parse <hex> emitting UAR, UAA, MAR, MAA, SAR and SAA with the S-CSCF name, the AVP result codes and the authentication scheme`
  - *Evidence:* verified: grep -rniE "diameter, MAR" modules/30_volte_ims.sh matched nothing (the only Diameter and TCAP decoder in the tree is modules/26_ss7_map.sh, and the pcap reader is modules/17_pcap_analysis.sh)
- **The registration-spoof path is a plan, not a capability: --register-spoof and --plan emit the steps and the packet shape but the module never transmits and never confirms a live registration, so a testbed run depends on the operator hand-building the flow**
  - *Why it matters:* Without a live registration verb there is no way to confirm that a respelled REGISTER was accepted, which is the difference between modelling IMS security and testing it against the lab's IMS core
  - *Suggested:* `--register-live --target <pcscf> emitting the built REGISTER, the response code and the S-CSCF challenge outcome`
  - *Evidence:* verified: the capability split at modules/30_volte_ims.sh:1-40 marks the transmit path as handoff; the dispatch at modules/30_volte_ims.sh:1049-1061 has no live-register verb (only --register-spoof and --plan)

### `31_sim_defense.sh`

- **No USIM AKA sequence-number tracking or replay detection: no module in the tree parses the SQN value at all, so neither clone detection nor authentication-replay defence exists in the module that owns SIM defence**
  - *Why it matters:* A cloned or OTA-attacked USIM is proven by SQN: a clone that jumps ahead forces AUTS and synchronisation failures, and a replayed Authentication Request shows a repeated or regressed SQN; this module can score events but cannot see the one counter that proves the clone
  - *Suggested:* `--sqn-track <capture-or-log> emitting per-ICCID sqn_first, sqn_last, sqn_regressions, sync_failures and a clone verdict, plus --sqn-parse <autn-hex> decoding the SQN and its 5-bit index`
  - *Evidence:* verified: grep -rn "SQN" modules/*.sh returned only modules/08_umts_air.sh:448-449 (prose that the USIM rejects a replayed AUTN) and modules/13_nr_core.sh:634 (a planned step string); modules/31_sim_defense.sh contains no SQN token
- **No OTA (SCP80 / TS 23.048) security analysis: --signals sees an OTA-SMS burst and --esim-profile-parse reads a profile, but the SPI security level, the KIc/KID key set, the TAR and the counter freshness are never parsed from the command packet**
  - *Why it matters:* The first question about a SIM attack is whether the OTA channel was secured: an SPI showing no ciphering or an unauthenticated TAR converts "a burst arrived" into "an unsigned remote APDU was applied", which is the operator's proof of compromise
  - *Suggested:* `--ota-parse <hex> emitting cpi, tar, spi, security_level (cipher, rc, cc), kic, kid and counter, plus --ota-audit <log> returning a verdict of unsigned or unauthenticated writes`
  - *Evidence:* verified: anchored grep -rlnE "SCP80,23\.048" modules/*.sh returned modules/16_sim.sh and modules/41_ota_sms.sh only (the TS 23.048 packet codec is modules/41_ota_sms.sh:149-192); grep -n "TAR,SCP80,SPI" modules/31_sim_defense.sh matched nothing
- **No SIM file path or access-condition resolution: --ef-ad decodes an access-condition byte but nothing walks an MF/DF/EF path (3F00, 7F20, 6F07), resolves an SFI, or applies the AD and ARR rules for a given access mode**
  - *Why it matters:* A defender asked "can this applet read EF_IMSI or EF_ICCID?" must resolve the path and the access condition together; --ef-ad alone answers the second half, and 16_sim.sh reads and writes files by FID without ever checking the conditions it is allowed to
  - *Suggested:* `--ef-path <mf/df/ef> emitting the resolved FID path, the file type and size, and the per-access-mode (READ, UPDATE, INCREASE, INVALIDATE) permitted or denied verdict from the AD and ARR`
  - *Evidence:* verified: anchored grep -rlnE "\bSFI\b,3F00,7F20,\bARR\b" modules/*.sh returned modules/55_nr_inject.sh only (unrelated SFI use); modules/31_sim_defense.sh exposes --ef-ad and --pin-state but no path resolver, and modules/16_sim.sh --file-id and --select-fid read by FID with no condition check
- **No IMEI/IMEISV parsing or validation: the score consumes an imei column and flags imei_tac_change (weight 10), but no verb parses an IMEI or IMEISV, validates the Luhn check digit, looks up the TAC device model, or correlates a PEI from a 5GS registration**
  - *Why it matters:* "Is this handset the one the subscription belongs to?" is answered by the TAC and a valid check digit; this module can only notice that the operator's feed says the TAC changed, never read or validate the identity itself, so a mistyped or forged IMEI passes unnoticed
  - *Suggested:* `--imei-check <imei,imeisv> emitting tac, serial, luhn_valid, device_model from the TAC and the binding verdict, plus --imei-policy <allow,deny file> flagging a blocked PEI in a capture`
  - *Evidence:* verified: grep -niE "imei,imeisv,device bind" modules/31_sim_defense.sh returned only the scoring input field and the imei_tac_change signal (modules/31_sim_defense.sh:88,93,330-348); anchored grep -rlniE "luhn,\btac\b" modules/*.sh returned modules/02_cell_recon.sh, 09_lte_attach.sh, 10_lte_air.sh, 11_lte_core.sh, 12_nr_air.sh, 17_pcap_analysis.sh, and modules/31_sim_defense.sh is not among them

### `32_nas_signaling.sh`

- **No NAS retransmission-timer or attach-storm analysis: the module counts rates, procedures and causes, and no module anywhere tracks T3410, T3411, T3402, T3412 or T3512 (or the 5G equivalents), so a storm is reported as "a storm" with no statement of which timer was expiring**
  - *Why it matters:* The decisive fact in a signalling storm is whether UEs are re-sending Attach Request because T3410 expired (network not responding) or repeating TAU after T3402: the fix is completely different, and the aggregate rate the module prints cannot distinguish them
  - *Suggested:* `--timer-analysis <pcap> emitting per-subscriber retransmission intervals, the 3GPP timer each interval implicates, expiry counts and a verdict on which timer is too short or the network too slow`
  - *Evidence:* verified: anchored grep -rlnE "T3410,T3411,T3402,T3412,T3512" modules/*.sh matched no file; the only timer arithmetic in the tree is the 2G/3G periodic-update T3212 discussion in modules/06_gsm_air.sh:317, modules/07_gsm_attack.sh:281 and modules/08_umts_air.sh:250
- **No per-subscriber drill-down: --rate groups per subscriber by count and nasf_storm_rows flags single-subscriber-dominates, but --procedure-mix (modules/32_nas_signaling.sh:756) and --causes (modules/32_nas_signaling.sh:782) aggregate globally with no subscriber dimension, so the identity that caused the storm never gets a procedure, cause or timeline of its own**
  - *Why it matters:* After the storm alarm the first operator action is "show me that UE": which procedures it ran, in what order, with what cause and whether it recovered; today they get a global cause histogram and must go back to Wireshark
  - *Suggested:* `--attribution-tsv [--subscriber ID] emitting per-subscriber procedure sequence, cause, inter-message gaps and first and last seen, plus --timeline <subscriber> for the ordered message list`
  - *Evidence:* verified: nasf_procedure_mix_rows (modules/32_nas_signaling.sh:756) and nasf_causes_rows (modules/32_nas_signaling.sh:782) key their accumulators on generation, type and cause only; the subscriber key exists solely in nasf_rate_rows (sub_n, modules/32_nas_signaling.sh:711-755)
- **The capture decoder stops at the message type: nasf_parse (modules/32_nas_signaling.sh:435) emits generation, security_header_type, message_type, procedure and cause and never decodes the message information elements (mobile identity IMSI/GUTI, TAI, ECGI, ESM bearer identity, UE network capability)**
  - *Why it matters:* An identity-leak or roaming investigation needs the identity and the tracking area out of the NAS PDU the operator is already looking at; without IE decode this module cannot answer "which subscriber and which TAI is this message about", and 18_imsi_exposure.sh can only do it because it drives the pcap parser, not this NAS decoder
  - *Suggested:* `--decode-ies <hex> [eps,5gs] emitting eps_mobile_identity (IMSI, IMEI, GUTI, 5G-S-TMSI), tai, ecgi, esm_bearer_identity, ue_network_capability and the 5GMM cause as one TSV block`
  - *Evidence:* verified: nasf_parse (modules/32_nas_signaling.sh:435-478) prints no identity, TAI or EBI field and extracts only the cause (nasf_extract_cause, modules/32_nas_signaling.sh:412); the tree's IE decoders are modules/09_lte_attach.sh and modules/13_nr_core.sh
- **No security-mode or authentication audit inside the signalling view: nasf_parse reports security_header_type and plain_nas per PDU but the normalised row drops both, so nothing reports the unprotected share of a capture, the algorithms negotiated per session, or whether authentication precedes security mode**
  - *Why it matters:* Regulators and operators ask "how much of my NAS traffic is still unciphered and are UEs negotiating NEA0 or EEA0"; the capture is already loaded in this module, yet answering it today needs modules/19_cipher_audit.sh and a manual join, and a plaintext Attach Accept with no preceding Security Mode Command goes unnoticed
  - *Suggested:* `--security-audit <pcap> emitting per-session negotiated NEA/NIA and EEA/EIA, the plaintext-message share, and a finding when an attach reaches Attach Accept without a preceding Security Mode Command`
  - *Evidence:* verified: nasf_parse prints security_header_type and plain_nas (modules/32_nas_signaling.sh:463-464) but the row shape (modules/32_nas_signaling.sh:665-709) carries neither into analysis, and the analysis functions at modules/32_nas_signaling.sh:711,756,782,825 have no security dimension; SMC parsing exists only in modules/19_cipher_audit.sh (--parse-smc, --from-pcap)

### `33_jamming_detect.sh`

- **No victim-signal fingerprint: the analyser is statistical only (features, characterise and duty_pattern inside jamd_py, modules/33_jamming_detect.sh:79-382) with no cell-specific reference-signal, PSS/SSS or GSM FCCH/SCH correlation, so it characterises the energy but never identifies the network signal it is drowning**
  - *Why it matters:* In the field the investigator must show the wanted carrier was still decodable before the onset and gone after: that is what separates "a jammer" from a dead site or a hardware fault, and without reference-signal correlation the report can only say the noise floor rose
  - *Suggested:* `--victim-verify <iq> --rat <lte,nr,gsm> --cell-id <pci,bsic> emitting the per-half reference-signal correlation peak, SNR and a present/degraded/absent verdict for the wanted signal`
  - *Evidence:* verified: grep -rln "PSS,SSS,cell search" modules/*.sh returned modules/02_cell_recon.sh, modules/12_nr_air.sh, modules/15_downgrade.sh and modules/45_iot.sh, none of them the jamming module; modules/33_jamming_detect.sh:79-382 contains only Welch PSD statistics and time-domain power
- **No spectral-emission measurement for the regulatory complaint: there is no adjacent-channel power or ACLR computation, no comparison against a licence emission mask and no absolute field strength, since every figure is emitted in dBFs with only an optional manual receiver centre frequency**
  - *Why it matters:* A jamming notification is acted on by a regulator when it carries an out-of-band emission level against the mask and an absolute power or field-strength figure; the current report is a relative floor shift, which is not citable and cannot bound the interferer's extent
  - *Suggested:* `--aclr <iq> --channel-hz N --centre-mhz F emitting adjacent-channel power in dBc, total in-band power in dBm (calibrated by --rx-gain-cal) and a pass or fail against a --mask reference`
  - *Evidence:* verified: anchored grep -rlnE "ACLR,adjacent.channel,emission mask" modules/*.sh matched no file; the emitted units are dBFs throughout (print_feats inside jamd_py, modules/33_jamming_detect.sh:79-382), and cmd_characterise adds only an affected_centre_mhz note at :424
- **No interference timeline: the feature record carries no absolute start time, the eight-window noise floor prints window indices only, and jamd_report (modules/33_jamming_detect.sh:517) preserves the record without an onset or cessation UTC time or a duration**
  - *Why it matters:* A jamming complaint is filed against the operator's real-clock incident log ("street lights out at 20:15"); a report that cannot state when the interference started and stopped cannot be correlated with the cell's KPI counters or the regulator's complaint, and onset_jump_db is a window-index delta with no clock attached
  - *Suggested:* `--timeline-tsv <iq> --start-utc <ISO8601> emitting onset_utc, cessation_utc, duration_s and the per-window floor with absolute timestamps`
  - *Evidence:* verified: the only time figures produced are samples and duration_s (modules/33_jamming_detect.sh:79-382); cmd_noisefloor prints window indices at :418-423 and jamd_report (:517) has no timestamp field, while its evidence list only asks for counters "with their timestamps"
- **No capture-format or calibration interoperability: load_iq accepts only raw cf32, ci16 and cu8 with a mandatory sample rate, so SigMF, WAV and sc16 recordings from a field receiver cannot be analysed, and there is no receiver noise-figure or gain calibration**
  - *Why it matters:* Field interference evidence usually arrives as a colleague's SigMF recording or an instrument export; without SigMF or WAV support the analyst must re-record, and without gain and noise-figure calibration the noise-floor shift stays relative and cannot be converted to dBm for the report
  - *Suggested:* `--input-format sigmf,raw,wav,sc16 [--sigmf-meta FILE] reading datatype, sample_rate and centre_frequency from the metadata, plus --rx-cal <nf-db,gain-db> converting the floor to dBm`
  - *Evidence:* verified: anchored grep -rlnE "SigMF,sigmf" modules/*.sh matched no file; ITEM = cf32, ci16, cu8 in jamd_py (modules/33_jamming_detect.sh:79-382) with the unknown-format error there, and --analyse, --noise-floor and --characterise all take a positional format and rate

### `34_slicing.sh`

- **Slice selection has no subscription side: --selection (slic_selection, modules/34_slicing.sh:239) accepts only requested, allowed and rejected NSSAI and otherwise answers "not-determinable", so the subscribed S-NSSAI set is never an input and the HPLMN to VPLMN S-NSSAI mapping and the default configured NSSAI are not computed**
  - *Why it matters:* "Why was this UE's slice granted?" is answered by comparing Requested against Subscribed plus the VPLMN mapping; the module correctly warns that the allowed NSSAI must be derived from the subscription but cannot do that derivation, and a roaming UE's mapped slice (the case its own surface note calls roaming-mapping-not-enforced) is unmodelled
  - *Suggested:* `--selection --subscribed <nssai-hex> --mapping <hplmn=vplmn,...> --default <nssai-hex> emitting the authorised set, the mapped S-NSSAI per VPLMN and an unauthorised-grant finding when allowed exceeds subscribed`
  - *Evidence:* verified: slic_selection reads only $1, $2 and $3 (modules/34_slicing.sh:239-243) and prints "outcome not determinable" at :261; grep -rn "mapped_s_nssai,subscribed_s_nssai,default configured" modules/*.sh matched nothing, and the mapping appears only as prose in slic_surface_notes (modules/34_slicing.sh:667)
- **No RAN-side slice isolation evidence: --isolation-check (slic_isolation_check, modules/34_slicing.sh:511) evaluates only N3 GTP-U endpoints and TEIDs from a capture, while the shared-UPF-without-VRF and N2/N3-signalled-but-not-enforced cases exist only as text in slic_surface_notes, with no PRB quota, slice-specific 5QI or RAN admission-control input or check**
  - *Why it matters:* A slice that is isolated at the UPF can still be starved or breached at the RAN; without PRB quota and per-slice 5QI evidence the operator cannot substantiate "the slice boundary is a boundary", which is exactly the failure the module's own notes describe
  - *Suggested:* `--ran-isolation --prb-quota <slice=min/max> --slice-5qi <slice=5qi> consuming the NGAP slice configuration and emitting per-slice PRB share, 5QI set and an isolated, shared or at-risk verdict`
  - *Evidence:* verified: slic_isolation_check keys on N3 transport endpoints (modules/34_slicing.sh:499-610) and the shared-upf-no-vrf and n2-n3-signalled-not-enforced cases are text only in slic_surface_notes (modules/34_slicing.sh:667); anchored grep -rlniE "5qi,qfi" modules/*.sh returned modules/13_nr_core.sh and modules/51_sidelink.sh only
- **No slice admission control or quota accounting: nothing models NSAC or the per-slice maximum UE and PDU-session counts, even though slic_5gmm_cause_name decodes causes 65, 67 and 69 ("maximum number of PDU sessions reached", "insufficient resources for specific slice") with no counter that would predict or explain them**
  - *Why it matters:* A slice outage from hitting the session limit looks identical in a capture to a capacity failure, so the operator cannot answer "is this slice at its quota" before it breaks; the cause names are present but the accounting those causes describe is not
  - *Suggested:* `--nsac <slice=sessions,ues> and --quota-monitor <slice-events.tsv> emitting current sessions and UEs per slice, headroom, and an at-risk finding before the limit is reached`
  - *Evidence:* verified: causes 65, 67 and 69 are decoded in slic_5gmm_cause_name (modules/34_slicing.sh:239-390) and passed through as findings in slic_detect_stream (modules/34_slicing.sh:611-654), but no accumulator or quota verb exists; anchored grep -rlnE "\bNSAC\b,admission control" modules/*.sh matched no file
- **No UE route selection policy handling: the module covers the network's Requested, Allowed and Rejected NSSAI and the SST/SD codec, but there is no URSP rule parsing or matching, so the UE-side decision that binds an application to a slice is unmodelled**
  - *Why it matters:* The recurring complaint "my app does not use the slice I bought" is a URSP and slice-mapping problem on the UE (TS 24.526), not a registration failure; with the capture in hand the operator can prove the network allowed the slice but cannot show which URSP rule should have matched or why the app landed on the default PDU session
  - *Suggested:* `--ursp-parse <hex> and --ursp-match --app <dnn,fqdn,osapp-id> emitting each rule's precedence, traffic descriptor (DNN, FQDN, IP 3-tuple) and route-selection descriptor S-NSSAI and SSC mode, with the winning rule and resulting slice`
  - *Evidence:* verified: anchored grep -rlnE "URSP" modules/*.sh matched no file; the module's own capability list (modules/34_slicing.sh:1-30) covers only the S-NSSAI codec, NSSAI containers, selection outcome and N3 isolation, and slic_sst_table and slic_surface_notes (modules/34_slicing.sh:125,664) add no UE-policy view

### `modules/35_baseband.sh`

- **no post-mutation length repair: duplicate/extend/truncate leave the original BER/TLV length octet in place, and the only length strategy (len-corrupt) deliberately breaks it, so any length-checking decoder rejects the frame before the mutated bytes are reached**
  - *Why it matters:* nearly every generated corpus entry is wasted against a real NAS/RRC/S1AP parser, and the operator has no way to produce a well-formed-but-mutated PDU
  - *Suggested:* `--fix-len <hex> (recompute BER/TLV lengths in place, print each repaired field and its offset)`
  - *Evidence:* verified: modules/35_baseband.sh:136-168 (no strategy rewrites a length), :171-182 (corpus emits the mutated hex verbatim), grep 'fix.?len|recompute|repair' modules/*.sh -> no repair tool
- **no offset/range-scoped mutation and no mid-buffer insert: --mutate takes only hex, strategy and seed, and the extend strategy can only append one byte at the end**
  - *Why it matters:* an operator cannot fuzz one chosen IE or header field, nor grow a PDU in the middle where PER and TLV parsers actually break
  - *Suggested:* `--mutate-range <hex> <start_byte> <len> <strategy> [seed] plus an insert strategy`
  - *Evidence:* verified: modules/35_baseband.sh:127-169 (strategy list, extend at :154-155 appends), :420 (--mutate has exactly 3 args)
- **octet-granular input only: hex must be even-length and mutations rewrite whole bytes, so RRC ASN.1 PER PDUs, which are not octet-aligned, cannot be bit-inserted or bit-deleted to shift the remainder of the bitstream**
  - *Why it matters:* the richest attack surface the module itself names (RRC PER) is only fuzzed at octet boundaries, missing the unaligned-length classes
  - *Suggested:* `accept an odd-length bit string or add --bitshift <hex> <bit_index> <insert|delete>`
  - *Evidence:* verified: modules/35_baseband.sh:65-68, :120-124, :216 (RRC PER named as the richest surface)
- **crash triage only counts sanitizer classes: no stack-hash dedup and no link back to the seed/index that produced each crash**
  - *Why it matters:* a campaign of 500 runs hitting one bug looks like 500 findings, so triage and de-duplication must be done outside the module
  - *Suggested:* `--triage --dedup printing one row per unique top stack frame with the corpus seed and index`
  - *Evidence:* verified: modules/35_baseband.sh:236-256 (grep -c per class), :176 (index/strategy/seed columns already exist in the corpus output)

### `modules/36_vowifi.sh`

- **no SA/Proposal/Transform payload parser: --walk prints payload type names and skips each body, and the transform classifiers must be handed an id the operator already extracted by hand**
  - *Why it matters:* a captured IKE_SA_INIT cannot be read to see which ENCR/PRF/INTEG/DH group and key length the ePDG offered, which is the first thing a VoWiFi job needs
  - *Suggested:* `--sa-parse <hex> printing per proposal the transform type, transform id, key-length attribute and the weak/ok verdict`
  - *Evidence:* verified: modules/36_vowifi.sh:140-156 (off += plen skips bodies), :211-242 (classifiers take a bare id), :250 (plan says to run the classifiers on the proposals)
- **--null-check does not exist although the module's own plan advertises it: no dispatcher verb and no usage line for a child-SA or null-cipher check**
  - *Why it matters:* an operator cannot confirm from this module that the negotiated child SA is ENCR_NULL, i.e. that Wi-Fi calling traffic rides in the clear
  - *Suggested:* `implement --null-check <encr_id> [integrity_id] or --null-check --sa <hex>`
  - *Evidence:* verified: modules/36_vowifi.sh:250 advertises --null-check; dispatcher :388-405 and usage :408-424 define no such flag
- **no IKEv2 Notification payload decode: payload type 42 is listed as a name only, so a NO_PROPOSAL_CHOSEN, AUTHENTICATION_FAILED or TS 24.302 ePDG redirect is invisible**
  - *Why it matters:* after a failed VoWiFi attach the operator cannot tell why the ePDG refused, which is the normal outcome of a lab attempt
  - *Suggested:* `--notify-parse <hex> mapping notify message types to names and decoding the protocol/SPI data`
  - *Evidence:* verified: grep 'NOTIFY|NO_PROPOSAL_CHOSEN|notify_type' modules/*.sh -> only modules/27_cellular_dns.sh:156 (DNS opcode) and modules/21_lte_cve.sh:385 (SIP method)
- **EAP-AKA' (type 50) is unsupported: the builder hardcodes EAP type 23 and the parser rejects any type other than 23**
  - *Why it matters:* an SWu attach toward a 5G core (EAP-AKA') cannot be decoded at all, so the modern VoWiFi/non-3GPP exchange is a blank
  - *Suggested:* `--eap-aka-prime or accept type 50 in --eap-parse and --eap-build`
  - *Evidence:* verified: modules/36_vowifi.sh:169, :188; grep 'EAP-AKA' modules/*.sh -> modules/47_wifioff.sh:121-141 and modules/13_nr_core.sh:610,1498 are flow/plan text with no packet codec

### `modules/37_femtocell.sh`

- **no HNBAP/RUA/RANAP message parse or build: --iuh prints a four-row static protocol table while the module's own plan says "decode HNBAP/RUA/RANAP"**
  - *Why it matters:* on a captured Iuh association the operator cannot read an HNB Register Request or UE Register Request, nor craft one, which is the whole point of owning the backhaul
  - *Suggested:* `--iuh-decode <hex> and --hnbap-register <imsi|ue-id> emitting the HNBAP PDU`
  - *Evidence:* verified: modules/37_femtocell.sh:106-114, :167; grep 'HNBAP|RANAP|RUA|Iuh' modules/*.sh -> modules/37_femtocell.sh:109 and modules/20_gsm_cve.sh:117,427-438 (a port-exposure string probe) only
- **PCI work only finds exact pci+earfcn duplicates: no PCI mod-3 (PSS) or mod-30 (RS) collision test and no neighbour-relation confusion check, and the documented PLMN column is ignored**
  - *Why it matters:* the PCI collisions that actually break handover and cell search are missed, while same-PCI cells in different PLMNs are reported as a conflict
  - *Suggested:* `--pci-mod <tsv> reporting mod-3 and mod-30 collisions plus neighbour-list PCI confusion`
  - *Evidence:* verified: modules/37_femtocell.sh:97-101 (key is pci|earfcn only), :91 (plmn column documented in the same comment), grep 'PCI' modules/*.sh -> only 42 and derivations in 10_lte_air.sh:727, 12_nr_air.sh:334, 45_iot.sh:96
- **CSG support stops at the 27-bit numeric id: no CSG access mode (closed, hybrid, open) and no CSG membership or allow-list check**
  - *Why it matters:* the question an assessor actually asks of a femtocell - is it closed, and which subscribers may attach - cannot be answered from the module
  - *Suggested:* `--csg-audit <tsv> or --csg-access-mode <closed|hybrid|open> with a membership verdict`
  - *Evidence:* verified: modules/37_femtocell.sh:71-85 (id codec only); grep 'access.?mode|hybrid|closed subscriber' modules/*.sh -> modules/31_sim_defense.sh:102,160 and modules/16_sim.sh:625 (EF_AD CSG-display bit) only
- **no local-management exposure check: --tr069-audit only grades a KEY=VALUE config file, so the services actually reachable on the device are never evaluated despite the module claiming "local device assessment"**
  - *Why it matters:* an operator cannot learn from this module that TR-069 7547 or Iuh SCTP 29169 is reachable from the WAN side of the HeNB
  - *Suggested:* `--exposure <port-listing> mapping ports to HeNB services and flagging WAN-reachable management`
  - *Evidence:* verified: modules/37_femtocell.sh:64,120-138 (config file in, findings out); modules/20_gsm_cve.sh:427-438 only greps a listing for an Iuh marker

### `modules/38_ussd.sh`

- **--build always 7-bit packs even when the supplied DCS says UCS2 (0x48) or 8-bit (0x44), so the emitted facility message contradicts its own DCS header**
  - *Why it matters:* any non-default-alphabet USSD string (Arabic, Cyrillic, Chinese menus) is built wrong and will fail to decode at the handset
  - *Suggested:* `make --build honour the DCS and add --build-ucs2 <text> emitting UTF-16BE octets`
  - *Evidence:* verified: modules/38_ussd.sh:157-162 (unconditional ussd_pack), :148-155 (UCS2 named); grep 'ucs2|UCS2|UTF-16' modules/*.sh -> names only (modules/38_ussd.sh:153, modules/16_sim.sh:754, modules/07_gsm_attack.sh:363)
- **no capture-side facility parse: nothing locates the USSD-string IE (IEI 0x1A) inside a NAS/DTAP or MAP message and decodes the DCS plus packed text**
  - *Why it matters:* given a USSD capture the operator must hand-split the hex and re-type it into --unpack, and the DCS is dropped entirely
  - *Suggested:* `--facility-parse <hex> locating IEI 0x1A and printing dcs, dcs_name, septets and text`
  - *Evidence:* verified: modules/38_ussd.sh:147-162 accepts only a bare [DCS][text] string; grep '[Uu][Ss][Ss][Dd]' modules/*.sh -> 43 plus modules/52_stk.sh:12,85,258 (STK SEND USSD naming and result codes) only
- **--unpack cannot accept the septet count that ussd_unpack already implements, so a real padded 7-bit payload (fill bits, TP-UDL-style length) decodes trailing garbage characters**
  - *Why it matters:* a captured USSD or SMS payload whose length is known decodes incorrectly and the operator cannot correct it
  - *Suggested:* `--unpack <hex> [septets] exposing the existing count parameter`
  - *Evidence:* verified: modules/38_ussd.sh:129,136 (count parameter honoured) vs :351 (CLI passes hex only), :367 usage line has no count
- **no MAP/TCAP envelope: the module emits a bare facility string and nothing in the toolkit builds the TS 24.090 unstructuredSS-Request/Notify invoke (MAP opcodes 59/60/61) that carries it over SS7**
  - *Why it matters:* with a lab STP or HLR simulator the operator cannot originate the USSD transaction the module's own plan tells them to send, because the opcode never gets a component wrapper
  - *Suggested:* `--map-ussd <text> emitting the TCAP invoke with the facility payload and a destination point code`
  - *Evidence:* verified: modules/26_ss7_map.sh:829-831 names opcodes 59/60/61 only, its builders :920-997 cover SRI/ATI/PSI; grep 'unstructuredSS|processUnstructured' modules/*.sh -> modules/26_ss7_map.sh:789,829-831 (names)

### `modules/39_ta_geoloc.sh`

- **no geodetic-to-planar conversion: --cells consumes lat/lon and --trilaterate demands x/y, and the plan instructs the operator to "convert to planar anchors" with no command that does it**
  - *Why it matters:* every real cell list has to be projected outside the toolkit before a fix can be computed, so the module cannot run end to end on operator data
  - *Suggested:* `--project <cells.tsv> [ref_lat ref_lon] emitting x/y metres (ENU) per cell`
  - *Evidence:* verified: modules/39_ta_geoloc.sh:147 (plan step), :122-139 (lat/lon in, range out), :95-118 (x/y required); grep 'east|north|utm|haversine|equirect|project_to|planar' modules/*.sh -> no implementation
- **no uncertainty output: the fix carries one residual_rmse and the TA quantisation error that --ta already computes is never propagated into a confidence region**
  - *Why it matters:* an operator cannot state how accurate a localisation is, which is the first question a customer or court asks of a location result
  - *Suggested:* `--ellipse [--confidence 95] printing CEP50/95 and the semi-axes from the anchor geometry GDOP`
  - *Evidence:* verified: modules/39_ta_geoloc.sh:116 (residual_rmse only), :87 (error_bound_m exists); grep 'ellipse|CEP|GDOP|confidence region|uncertainty' modules/*.sh -> no matches
- **RAT coverage is lte and nr only, with gsm explicitly rejected by the selftest**
  - *Why it matters:* the GSM timing advance (0..63 bit periods, handed out in an Immediate Assignment) that field practitioners read most often cannot be converted to a range
  - *Suggested:* `--ta <n> gsm (and umts) with each RAT's granularity and error bound`
  - *Evidence:* verified: modules/39_ta_geoloc.sh:78 (lte|nr only), :180 (selftest asserts gsm returns 2); grep 'timing advance' modules/*.sh -> modules/29_mac_layer.sh:54,196 (LTE MAC CE) and modules/49_ntn.sh:129 (NTN) only
- **no outlier or robustness diagnostic: the least-squares solve is unweighted and prints no per-anchor residual, so one NLOS-biased TA skews the fix with no warning**
  - *Why it matters:* a single bad measurement poisons the position and the operator has no signal that the fix should be distrusted
  - *Suggested:* `--trilaterate <tsv> --robust printing per-anchor residuals and excluding the worst anchor`
  - *Evidence:* verified: modules/39_ta_geoloc.sh:106-116 (one aggregate ss/n), :252 (--trilaterate takes only the file)

### `modules/40_sba_pivot.sh`

- **no HPACK decode: HEADERS and CONTINUATION payloads stay opaque hex, so no SBI request or response header can be read**
  - *Why it matters:* a 5G core capture is unusable above the frame layer - :method, :path and the 3gpp-Sbi-* headers that identify the NF transaction are invisible
  - *Suggested:* `--hpack <hex> [--dynamic-table] printing the decoded header list (static table, literal with/without indexing, Huffman)`
  - *Evidence:* verified: modules/40_sba_pivot.sh:100-118 (payload passed through as hex); grep 'hpack|HPACK|dynamic table|header.*compress' modules/*.sh -> no matches
- **the JWT signature is never verified: the audit reads alg and aud out of the base64 payload, so a forged, re-signed or payload-swapped token produces the same INFO/CRITICAL verdicts as a genuine one**
  - *Why it matters:* token-audit findings are about an unauthenticated blob, and the RS256-to-HS256 key-confusion class cannot be tested at all
  - *Suggested:* `--jwt-verify <token> <pem|jwks> plus a key-confusion mode`
  - *Evidence:* verified: modules/40_sba_pivot.sh:197-220; grep 'jwks|JWKS|verify_sig|sig_verify|signature verification' modules/*.sh -> no matches (modules/44_carrier_api.sh:145-179 audits alg/exp/aud only, still no signature)
- **no NF management body builder and no NF profile parser: the path table lists nnrf-nfm register/update/deregister and the plan says "registering a rogue NF", but only the discovery GET is emitted**
  - *Why it matters:* registering a test NF and extracting endpoints from a discovery response (nfInstanceId, fqdn, ipv4Addresses, nfServices) has to be hand-written JSON outside the module
  - *Suggested:* `--nf-register <nf-type> <fqdn> <ip> emitting the PUT body and --nf-profile <json> extracting endpoints`
  - *Evidence:* verified: modules/40_sba_pivot.sh:146, :154-160, :225; modules/13_nr_core.sh:83-85,130-134 lists the fields but builds nothing
- **no OAuth2 access-token request: the module audits tokens but cannot construct the TS 33.501 Annex A client_credentials request that mints one**
  - *Why it matters:* an operator can inspect a token someone else obtained but cannot reproduce or test the minting path against a lab NRF
  - *Suggested:* `--token-request <nf-instance-id> <scope> [target-nf-type] emitting POST /oauth2/v1/token with its form body`
  - *Evidence:* verified: modules/40_sba_pivot.sh:181-282 (audit only); grep 'oauth2|grant_type|client_credentials' modules/*.sh -> modules/13_nr_core.sh:85 (path string) and modules/44_carrier_api.sh:285-288 (OpenAPI snippet) only

### `modules/41_ota_sms.sh`

- **OTA-specific SMS transport framing is still missing: the module now builds a general SMS-DELIVER/SMS-SUBMIT TPDU (Phase 2 of docs/OFFENSIVE-GAP-ANALYSIS.md, `--tpdu-deliver` / `--tpdu-submit`) but not the OTA one — TP-UDHI=1 with UDH IEI 0x70 and the OTA DCS — and it still cannot segment a packet across 140-octet SMS into concatenated UDHs**
  - *Why it matters:* the 200-octet packet its own selftest builds can never be delivered to a SIM, and no built packet can be handed to a modem as-is
  - *Suggested:* `--sms-deliver <packet-hex> [oa] emitting the TPDU with the 0x70 UDH and 8-bit concatenation UDHs`
  - *Evidence:* verified: `otasm_tpdu_build_deliver` / `otasm_tpdu_build_submit` emit plain TPDUs and `--tpdu-parse` reports `mt_udhi`, but no UDH composer or segmentation loop exists; modules/16_sim.sh:641-790 parses OTA TPDUs (sim_parse_ota) and nothing builds one
- **no PoR/response packet parse: the SPI's PoR request bits are decoded but the SIM's receipt packet, with its own RC/CC and application status, is never read**
  - *Why it matters:* a lab operator can only say a receipt was requested, never whether the card accepted the command or why it refused
  - *Suggested:* `--parse-por <hex> printing the PoR header, application status, receipt CC/RC verdict`
  - *Evidence:* verified: modules/41_ota_sms.sh:135-143 (SPI PoR bits); modules/16_sim.sh:951-1009 decodes only the SPI PoR fields, no response packet
- **--counter-check is single-shot: one counter and one RE from argv with no state, so a capture holding several packets for the same TAR cannot be scanned for a repeated or non-increasing CNTR**
  - *Why it matters:* the replay case that matters on a real capture - the same TAR's counter going backwards - is not detectable, only a hand-fed pair
  - *Suggested:* `--replay-scan <tsv of tar,counter> listing per-TAR monotonicity violations and duplicate counters`
  - *Evidence:* verified: modules/41_ota_sms.sh:197-210, :339 (3 args); STATE_DIR set at :38-39 and never read
- **no RC/CC verification even with an operator-supplied key: the audit asserts ciphering and integrity from SPI bits alone and never checks the packet's RC/CC/DS value**
  - *Why it matters:* the "un-keyed payload" finding cannot be proven, so a truncated or tampered packet with a forged SPI passes the audit, and an own-SIM key set cannot be exercised
  - *Suggested:* `--cc-verify <packet-hex> <kic-or-kid-key-hex> recomputing RC (keyless) and CC (DES-CBC or 3DES per KID)`
  - *Evidence:* verified: modules/41_ota_sms.sh:140-143 (SPI bits only); grep 'openssl.*DES|3DES|DES-CBC|des3' modules/*.sh -> modules/16_sim.sh:881-883 names the modes with no implementation

### `42_li_probe.sh`

- **No pcap/gsmtap ingestion — the detection verb only scores a hand-built TSV, so an operator cannot point it at the capture they actually hold**
  - *Why it matters:* An LI/IMSI-catcher review always starts from a real capture; hand-transcribing signalling into TSV is where cases get lost and where evidence chain-of-custody breaks
  - *Suggested:* `--score-capture <file.pcap> accepting gsmtap/NGAP/S1AP input and emitting the same finding/severity/imsi/detail TSV directly`
  - *Evidence:* verified: grep -n "pcap\|tshark\|gsmtap" 42_li_probe.sh returned nothing; the only inputs are a TSV path at 42_li_probe.sh:104-105 and the awk at 42_li_probe.sh:106-112
- **No silent-SMS detection from the message itself — the scorer only counts rows the operator already labelled 'silent_sms', and the declared 'silent' column is never read**
  - *Why it matters:* Silent SMS (TP-PID 64 / class-0) is the canonical LI target-presence test; a module that claims to score it but cannot recognise it in traffic has no independent detection value
  - *Suggested:* `--detect-silent-sms <file> parsing SMS-DELIVER TP-PID and TP-DCS class-0 (TS 23.040 §9.2.3.9) and flagging short/empty TP-UD pings per IMSI`
  - *Note:* the TPDU-level primitive this needs now exists — `modules/41_ota_sms.sh --tpdu-parse` classifies TP-PID 0x40 on a raw TPDU and `--type0` reports the silent-message properties — so this gap is now only the pcap/TSV plumbing in this module, not the TP-layer decode
  - *Evidence:* verified: awk block 42_li_probe.sh:106-113 uses only $2,$3,$4 — the 5-field header documented at 42_li_probe.sh:101 ('silent') is read nowhere in the file; grep -n "silent" 42_li_probe.sh shows the string only inside literal event names at :121 and :125
- **No TS 33.128 5G LI handover mapping — X1/X2/X3 (TS 33.108) are modelled but the 5G equivalents and their POIs (AMF/SMF/UPF) are only mentioned in a comment**
  - *Why it matters:* Any intercept or audit question on a 5G SA network is answered against TS 33.128 interfaces and PDU-session-level CC, not the 3GPP-rel-8 names the module prints
  - *Suggested:* `--interfaces-5g emitting the TS 33.128 interface/POI set (AMF/SMF/UPF points, IRI vs CC, PDU session granularity) with a --iface5 <name> lookup`
  - *Evidence:* verified: grep -n "33.128" 42_li_probe.sh shows one comment at :6 and one section banner at :69; the actual tables at 42_li_probe.sh:71-76 and :87-94 carry X1/X2/X3, ADMF/POI/DF2/DF3/LEMF only
- **No X1 provisioning/authorisation record audit — the ADMF side is described in prose ('the X1 provisioning record' at 42_li_probe.sh:154) but there is no verb to check one**
  - *Why it matters:* Confirming an intercept is lawful means checking the X1 authorisation: target, authority, validity window, deactivation. An operator or regulator auditor cannot do that here at all
  - *Suggested:* `--x1-audit <x1-record.tsv> reporting targets with no authorisation reference, validity windows past expiry, and intercepts left active after cancel`
  - *Evidence:* verified: grep -n "X1" 42_li_probe.sh hits only :73, :80, :179, :266 (naming/help); grep -n "ASN" 42_li_probe.sh shows no record parsing, and the dispatch table 42_li_probe.sh:250-259 exposes no audit verb

### `43_ran_share.sh`

- **Cannot decode a cell's broadcast PLMN set from the air — the leak check takes the broadcast list as operator-typed CSV, so the module never reads the SIB1 it tells you to capture**
  - *Why it matters:* On a shared-RAN audit the whole question is what the cell actually broadcasts; typing that in by hand is both the error-prone step and the step that destroys the finding's provenance
  - *Suggested:* `--sib1-decode <hex> parsing SIB1/SIB1-NB PLMN-IdentityList (TS 36.331 §6.2.2) into the cell_id<TAB>broadcast_plmns TSV that --leak-check already consumes`
  - *Evidence:* verified: rans_leak_check at 43_ran_share.sh:129-151 reads column 2 as a comma list ('broadcast_plmns' documented at :127); the flow text at 43_ran_share.sh:159 ('capture the cell's SIB1') is prose only — grep -rn "SIB1" modules/*.sh shows no decoder, the hits being comments at :158-159 and test fixtures at :211-212
- **No 5G NPN/SNPN support — private and shared 5G networks identify themselves with an NID and CAG, which have no representation here**
  - *Why it matters:* MOCN-style sharing in 5G SA is expressed via SNPN (MCC/MNC + NID) and CAG cells; a sharing-boundary audit on a 5G deployment cannot encode or check either
  - *Suggested:* `--npn-encode <mcc> <mnc> <nid> / --npn-decode <hex> plus a --cag-check <list> for TS 24.501 NID/CAG coding`
  - *Evidence:* verified: grep -n "NPN\|CAG\|NID\|SNPN" 43_ran_share.sh returned nothing; the only NPN-adjacent lines elsewhere are 5GMM cause names at 32_nas_signaling.sh:373-375, so no sibling owns this
- **EPLMN is only counted, never encoded — the list check validates length and syntax but cannot produce the wire bytes a UE or eNB must be configured with**
  - *Why it matters:* Equivalent-PLMN configuration is exactly how a shared-RAN operator steers reselection between the sharing partners, and it lives on the wire as a coded list
  - *Suggested:* `--eplmn-encode <plmn,plmn,...> emitting the TS 24.008 §10.5.1.13 coded PLMN list (3 octets per entry, length octet) to pair with the existing count check`
  - *Evidence:* verified: rans_eplmn_check at 43_ran_share.sh:101-113 validates with a regex at :107 and prints only count/max/verdict; grep -n "encode" 43_ran_share.sh returns only rans_plmn_encode at :74 for a single PLMN, with the dispatch at :257-259 exposing no list encoder
- **No tracking-area / cell-identity layer — sharing boundaries are enforced at TAC and ECI level (who owns which TA), but the module models only PLMN strings**
  - *Why it matters:* Cross-operator leakage in practice shows up as a UE holding a shared cell's TAC under the wrong operator's core; without TAC/ECI the leak verdict cannot be tied to a real configuration
  - *Suggested:* `--tac-check <tsv> with cell_id, tac, broadcast_plmns, owner_plmn reporting TACs reused across operators or ECIs whose TAC is not in the owner's TA list`
  - *Evidence:* verified: grep -n "TAC\|tracking area\|cell identity\|ECI" 43_ran_share.sh returned nothing; leak input columns are fixed at 43_ran_share.sh:127 and read at :138 as cell_id/broadcast/observed only

### `44_carrier_api.sh`

- **JSON-only spec parsing — a YAML OpenAPI document (the form most carriers publish) is rejected outright, so the assessment cannot start**
  - *Why it matters:* Practically every operator publishes swagger.yaml; a tool that fails on the common artifact forces a manual conversion before any audit work begins
  - *Suggested:* `--openapi-yaml <file.yaml> (or --openapi auto-detecting by content) using the same python3 path already required at 44_carrier_api.sh:76`
  - *Evidence:* verified: capi_openapi_parse calls json.load at 44_carrier_api.sh:80 inside the heredoc at :77-105 and errors 'spec is not valid JSON or OpenAPI 3' at :77; grep -n "yaml\|YAML\|yml" 44_carrier_api.sh returned nothing, and nothing in modules/*.sh parses YAML
- **No operation-level scope coverage analysis — the parser reports only the first security scheme name per operation, so undeclared or partial scopes are invisible**
  - *Why it matters:* The finding an API assessor actually files is 'these endpoints declare no auth' or 'this endpoint needs scope X but any valid token opens it'; the module discards both the security array and the scope lists
  - *Suggested:* `--scope-audit <spec> listing operations with no security, operations whose scopes are empty, and security schemes referenced but never defined`
  - *Evidence:* verified: capi_openapi_parse at 44_carrier_api.sh:98-100 does reqs = op.get("security", []) then ",".join(sorted(reqs[0].keys())) — only the first requirement's key names, discarding scope arrays; grep -n "scope" 44_carrier_api.sh finds scopes only as literal test-case labels at :123-124 and in report prose at :243
- **JWT audit verifies no signature and never looks at aud/iss — the help text promises an 'audience audit' the code does not perform**
  - *Why it matters:* Audience confusion (a token minted for one API accepted by another) is the highest-value token bug on a carrier portal, and the module explicitly names it at :243 while testing nothing about it
  - *Suggested:* `--jwt-verify <token> --jwks <url|file> verifying the signature and reporting aud/iss/kid mismatches, plus alg-key-confusion cases (HS256 signed with the RSA public key)`
  - *Evidence:* verified: capi_jwt_audit at 44_carrier_api.sh:157-183 extracts only alg (:164) and exp (:165) with sed; grep -n "jwks\|signature\|aud\|iss" 44_carrier_api.sh shows aud/iss only in the help text at :409 and prose at :243, and the p selector never reads them
- **No live request builder/executor — 'assessment only' leaves the tool unable to emit the probes whose responses --diff and --token-bucket require**
  - *Why it matters:* The authz matrix prints expected statuses but nobody sends the requests, so every downstream verb depends on the operator hand-running curl and hand-formatting TSVs
  - *Suggested:* `--probe <spec> --token <tok> [--max N] emitting curl-equivalent requests (or a script) for the authz matrix rows and writing endpoint<TAB>method<TAB>status TSVs for --diff`
  - *Evidence:* verified: grep -n "curl\|wget\|https://\|socket" 44_carrier_api.sh finds curl only as prose at :253 ('software curl or a small client'); capi_diff at 44_carrier_api.sh:188-203 requires two pre-existing TSV files, and the diff/token-bucket inputs are described as hand-captured at :254

### `45_iot.sh`

- **SIB1-NB decode is a fixed-offset hex slicer, not an ASN.1 decode — no SIB2-NB through SIB14-NB at all, despite the header claiming coverage**
  - *Why it matters:* NB-IoT attach and power/coverage behaviour is driven by SIB2-NB (RACH/CE), SIB3-NB (reselection), SIB5-NB (neighbours) and SIB14-NB (access barring); an operator optimising NB-IoT needs those, not a 6-field stub
  - *Suggested:* `--decode-sib <type> <hex> (2/3/4/5/14) decoding the real per-SIB field sets per TS 36.331 §6.3.1/6.7`
  - *Evidence:* verified: the header claims SIB1-NB..SIB14-NB at 45_iot.sh:7 but the only decoder is iot_decode_sib1_nb at 45_iot.sh:111-135 slicing fixed offsets (:118-123); grep -n "SIB2-NB\|SIB14\|NPDSCH\|NPDCCH\|NPUSCH" 45_iot.sh hits only the comments at :2 and :6-7, and no sibling has NB-IoT SIB parsing (grep -ln "sib1-nb\|SIB1-NB\|sib14" modules/*.sh returns 45_iot.sh alone)
- **NPRACH parameters are a static template — nprach_cfg and subcarrier spacing are echoed back, N_cp is hardcoded, and no periodicity/start-subcarrier/CE level is ever computed**
  - *Why it matters:* Planning an NB-IoT random-access budget means picking a PRACH configuration index and reading its periodicity, subcarrier offset and repetition; the tool cannot answer any of that
  - *Suggested:* `--nprach-cfg <index> <mode:inband|guardband|standalone> emitting periodicity, start subcarrier, N_cp, repetition count per TS 36.211 Table 10.1.6.1-1`
  - *Evidence:* verified: iot_nprach_params at 45_iot.sh:68-88 sets n_cp=67 unconditionally (:74) and ignores $prach_cfg and $subcar_spacing beyond echoing them (:82-83); the CLI at :238 forwards three arguments that the body never uses
- **NPUSCH/NPDCCH/NPDSCH are absent — the module advertises them in its own header but implements no uplink shared channel, no DCI format N0/N1, and no scheduling/repetition model**
  - *Why it matters:* Uplink throughput, coverage and CE-level planning for NB-IoT are a function of NPUSCH subcarrier count and repetition; without DCI N0/N1 the tool cannot size a link
  - *Suggested:* `--npusch <subcarriers> <repetitions> <mcs> and --dci-nb <format:N0|N1> <hex> decoding the NB-IoT DCI and reporting transport block size and repetition`
  - *Evidence:* verified: grep -n "NPUSCH\|NPDCCH\|NPDSCH" 45_iot.sh shows occurrences only in the header comments at 45_iot.sh:2 and :6; the full function list is iot_status_tsv/iot_nprach_params/iot_npss_to_nss/iot_nprfcn_to_mhz/iot_selftest/iot_menu/iot_cli_main (45_iot.sh:55-233) with no such verb in the dispatch at :236-243
- **No Cat-M1 (eMTC) capability whatsoever — the module is named 'NB-IoT / Cat-M1' but has no MPDCCH, no CE mode A/B, no CE levels 0-3**
  - *Why it matters:* Cat-M1 and NB-IoT differ exactly in coverage-enhancement planning (MPDCCH repetitions, CE mode); an operator deploying either cannot use this for the other
  - *Suggested:* `--catm1-ce <rsrp_dbm> <mode:A|B> mapping to CE level 0-3 and the MPDCCH repetition set per TS 36.213 §7.1.6`
  - *Evidence:* verified: grep -n "Cat-M1\|eMTC\|MPDCCH\|CE level" 45_iot.sh hits only the title comment at 45_iot.sh:2; the only 'Cat-M1' in the tree besides that is 48_oran.sh, and the function list at 45_iot.sh:55-233 contains no eMTC logic

### `46_lpp.sh`

- **No real LPP message decoding — only an 8-hex 'header' extractor; the message bodies (RequestLocationInformation, ProvideLocationInformation) are never parsed**
  - *Why it matters:* LPP is a body-carrying protocol; a header alone tells an operator nothing about which positioning method was requested or what measurements came back
  - *Suggested:* `--decode-message <hex> decoding the LPP PDU envelope and the RequestLocationInformation/ProvideLocationInformation bodies per TS 37.355`
  - *Evidence:* verified: lpp_decode_header at 46_lpp.sh:81-98 reads exactly procedure_code/criticality/length from hex positions 0-8 (:85-87); grep -n "hex\|parse\|decode" 46_lpp.sh shows only header builders/parsers at :81-149, and siblings 11_lte_core.sh:1179-1182 and 13_nr_core.sh:153-200 carry LPPa *transport* messages only, no LPP PDU decode
- **No positioning methods — OTDOA, A-GNSS, ECID and RTT appear nowhere, so the module cannot represent what a position request actually asks for**
  - *Why it matters:* A practitioner's LPP question is always 'which method, what assistance data, what accuracy'; a procedure-code table and a fake latitude cannot answer it
  - *Suggested:* `--position-method <otdoa|agnss|ecid|rtt> emitting the method's request fields and the assistance data it requires (TS 37.355 §6/§7)`
  - *Evidence:* verified: grep -rn "OTDOA\|otdoa\|A-GNSS\|agnss\|ECID\|ecid" modules/*.sh returned no matches at all; the only method-adjacent argument is a numeric 'position_method' defaulted to 1 and never used in lpp_build_position_request at 46_lpp.sh:116-129
- **Position-response parsing is hardcoded to fixed hex offsets with a fixed '10 cm' precision — no per-method accuracy, uncertainty ellipse or confidence**
  - *Why it matters:* A position that arrives without its accuracy cannot be used for E911/emergency or regulatory reporting, and the claimed precision is wrong for every method
  - *Suggested:* `--parse-position with --accuracy decoding the method-specific accuracy/uncertainty fields (TS 37.355) and printing the confidence and method used`
  - *Evidence:* verified: lpp_parse_position_response at 46_lpp.sh:132-149 reads lat at offset 24 and lon at offset 32 (:136-137) and prints a literal 'Precision: ~10 cm' at :147; no accuracy parameter exists in the CLI at 46_lpp.sh:278
- **--detect-forgery is a stub — it never opens the pcap, greps nothing, and prints a hardcoded 'Position outside valid bounds: 0'**
  - *Why it matters:* This is the module's only claimed analytic verb; as written it will report 'no anomalies' for any input, including a nonexistent file, which is worse than not having it
  - *Suggested:* `--detect-forgery <pcap> actually parsing PositionEstimates with tshark/python (reusing the pcap path other modules already have) and flagging jumps, out-of-bounds and timestamp-ordered position deltas`
  - *Evidence:* verified: lpp_detect_forgery at 46_lpp.sh:152-169 only echoes $pcap and prints literal anomaly counts at :162-163; grep -n "pcap\|tshark" 46_lpp.sh shows the variable at :153-154 and the string only in output text at :159,:166 and menu/help at :260,:292

### `47_wifioff.sh`

- **No certificate trust-chain validation or pinning — --validate-cert prints subject/issuer/expiry and a 'VALID/EXPIRED' verdict without ever building a chain to a trust anchor**
  - *Why it matters:* The whole ePDG trust model rests on whether the presented certificate chains to a known 3GPP/WFA anchor and whether its SAN matches the ePDG identity; unchecked, the tool calls a rogue ePDG 'VALID'
  - *Suggested:* `--validate-cert <cert.pem> --ca <bundle.pem> [--expect-fqdn epdg...] performing openssl verify, SAN/CN match against the ePDG FQDN, and reporting pin mismatch`
  - *Evidence:* verified: wifioff_validate_cert at 47_wifioff.sh:79-102 calls only openssl x509 -noout -subject/-issuer/-enddate (:84-86) and -checkend 0 (:97); grep -n "verify\|CAfile\|SAN\|pin" 47_wifioff.sh shows no occurrence, and the sibling 36_vowifi.sh has none either (grep -n "verify\|CAfile\|SAN\|pin" 36_vowifi.sh hits only help text at :423)
- **No LWA/LWIP bearer and Xw interface model — LWA is a bearer-level feature (XwAP to the WT, WLAN measurement reporting in RRC) but the module only prints a channel pair**
  - *Why it matters:* Traffic steering decisions live in XwAP and in the LTE RRC WLAN measurement configuration; without them the module cannot assess whether an offload actually steers as intended
  - *Suggested:* `--xw-ap <hex> decoding the XwAP procedures (TS 36.463) and --lwa-bearer <e-rab> showing the LTE/WLAN split bearer and its steering rule`
  - *Evidence:* verified: wifioff_lwa_config at 47_wifioff.sh:105-119 prints AP MAC, two channels, 'Aggregation: Enabled' and 'Security: AES-GCM' only; grep -rn "Xw\|LWIP\|XwAP" modules/*.sh returns only unrelated hits in 11_lte_core.sh, and the function list at 47_wifioff.sh:54-146 has no bearer or Xw logic
- **No Hotspot 2.0/Passpoint or ANDSF WLAN-selection analysis — how a handset chooses an offload AP is never modelled**
  - *Why it matters:* The most common real-world offload failure is a UE auto-joining an attacker or unmanaged SSID via Passpoint/ANDSF rules; auditing the selection policy is the practical security question
  - *Suggested:* `--passpoint <anqp|hs2-profile> parsing ANQP/HS2.0 elements (per-hotspot provider, NAI realm, required crypto) and --andsf <xml> flagging rules that permit open or untrusted WLANs`
  - *Evidence:* verified: grep -rln "Passpoint\|Hotspot 2.0\|ANDSF" modules/*.sh returns only 11_lte_core.sh (unrelated), so no sibling owns it; the dispatch at 47_wifioff.sh:247-255 exposes only epdg-fqdn/validate-cert/lwa-config/auth-flow/cert-thumb
- **ePDG FQDN builder accepts an invalid PLMN silently — an 8-digit or garbage argument is sliced into a plausible-looking FQDN with no validation**
  - *Why it matters:* A wrong MCC/MNC here sends the operator to the wrong ePDG (or to no DNS record at all) and the tool cannot tell them so; note the sibling 36_vowifi.sh:203 builds the same FQDN and shares the defect
  - *Suggested:* `--epdg-fqdn <plmn> validating MCC (3 digits) and MNC (2-3 digits) exactly as rans_plmn_encode does at modules/43_ran_share.sh:76-77, and erroring instead of padding`
  - *Evidence:* verified: wifioff_epdg_fqdn at 47_wifioff.sh:66-76 slices mcc=${plmn:0:3} and mnc=${plmn:3:3} with no regex check; the selftest at 47_wifioff.sh:191-192 asserts only that the output lacks the literal string 'invalid'

### `48_oran.sh`

- **No E2AP PDU decode — the module names E2AP over SCTP as the E2 trust boundary but can only print a canned procedure code**
  - *Why it matters:* Stand-up and fault-finding of an E2 node is done by reading RIC Subscription Request / Indication PDUs; without a decoder the operator cannot verify what an E2 node actually reports or who it claims to be
  - *Suggested:* `--e2ap-decode <hex|pcap> decoding E2AP-PDU (initiatingMessage, procedureCode, RICrequestID, RANfunctionID) per O-RAN.WG3 E2AP`
  - *Evidence:* verified: grep -n "E2AP" 48_oran.sh hits only :74, :116 and :183 (table row, prose, selftest string); grep -n "hex\|PDU\|decode\|asn" 48_oran.sh returns no parsing function, and grep -n "E2AP" across modules/*.sh shows no match outside 48_oran.sh
- **No A1 policy-type/schema validation — --a1-put writes an arbitrary JSON blob at an arbitrary policy type id and never checks it against the policy type definition**
  - *Why it matters:* A1 policy poisoning is only meaningful against a real policy schema (what fields a type accepts, what scope); without it the tool cannot tell a valid policy from a rejected one, nor diff two versions
  - *Suggested:* `--a1-policy-check <type-id> <policy.json> validating the body against the registered A1 policy type schema and reporting unknown/missing fields`
  - *Evidence:* verified: oran_a1_put at 48_oran.sh:255-262 templates the path from $policy_type (:259) and takes the body verbatim, defaulting it at :258; grep -n "policytype\|schema\|json" 48_oran.sh shows only the path template (:256,:259) and the help/default strings (:258,:305)
- **No O1/O2 inventory or topology assessment — O-Cloud and managed-element state are named in the interface table but never inspected**
  - *Why it matters:* Before any RAN-control question an operator asks what is actually deployed and managed: which E2 nodes, which O-Cloud nodes, what NETCONF datastores; the tool has no answer
  - *Suggested:* `--o1-inventory <host> listing NETCONF capabilities/YANG models and --o2-inventory <endpoint> enumerating O-Cloud nodes via Redfish/K8s`
  - *Evidence:* verified: grep -n "Redfish\|K8s\|SMO\|inventory\|topology" 48_oran.sh hits only the table row at :76 and a prose mention of the SMO in the ingress finding at :117; the dispatch at 48_oran.sh:284-294 has no inventory verb
- **No authentication/authorisation assessment for O1, O2 and A1 — security is read from a hand-written KEY=VALUE file, never from the interface's own auth mechanism**
  - *Why it matters:* O-RAN's actual weaknesses are token handling (OAuth2 on O1/A1), SSH keys on NETCONF and IAM on O2; a config-file boolean cannot find a shared credential or an unauthenticated A1 endpoint
  - *Suggested:* `--o1-auth-audit <host> and --a1-auth-audit <endpoint> testing mTLS/OAuth2 presence, token audience validation and default credentials, instead of trusting a1_tls= in the conf`
  - *Evidence:* verified: oran_assess at 48_oran.sh:94-124 derives every finding from KEY=VALUE lookups (:99-112) and only string-matches true/yes/1/on (:115-120); grep -n "TLS\|mTLS\|token\|OAuth" 48_oran.sh shows these words only inside finding text at :115 and :121

### `49_ntn.sh`

- **no orbital/geometry engine: slant range, range-rate, elevation and azimuth cannot be derived from an ephemeris — the closing velocity is a hand-fed argument**
  - *Why it matters:* an operator planning a pass must already know v and range from another tool, so the module cannot answer "is this pass visible and doppler-compensable"
  - *Suggested:* `--orbit <tle-or-ecef> <t> <ue_lat,lon,alt> → elevation_deg, azimuth_deg, slant_range_km, range_rate_mps, pass_start/end`
  - *Evidence:* verified: grep -Ei 'TLE', 'orbit', 'elevation', 'azimuth', 'ECEF' over modules/*.sh → no orbital geometry in any module; 49_ntn.sh:71 ntn_doppler takes velocity as argv; help 49_ntn.sh:255 "--doppler <hz> <mps> [deg]"
- **k_offset is computed for 15 kHz SCS only**
  - *Why it matters:* NTN FR1 uses 30/60/120 kHz, where a k_offset expressed in slots at 15 kHz is wrong by 2x/4x/8x and the UE will not schedule the grant
  - *Suggested:* `--koffset <rtt_ms> [scs_khz] → k_offset in slots for the chosen numerology`
  - *Evidence:* verified: help 49_ntn.sh:258 "--koffset <rtt_ms>  minimum scheduling offset (slots, 15 kHz)"; 49_ntn.sh:112 ntn_koffset has no SCS parameter or argument
- **no SIB19 encoder/decoder: --sib19 prints a prose field list, so a captured SIB19 IE cannot be turned into ephemeris/TA/k_offset and one cannot be built**
  - *Why it matters:* field verification against a live satellite cell is impossible — the operator cannot confirm the gNB ephemeris agrees with the physics the module computes
  - *Suggested:* `--sib19-decode <hex> and --sib19-encode <k=v,...> → ephemeris, ta_common, ta_common_drift, k_offset, cell_reference_location, ntn_ul_sync_validity`
  - *Evidence:* verified: 49_ntn.sh:126 ntn_sib19 is a heredoc field table with no hex input; help 49_ntn.sh:259 "SIB19 field reference"
- **no NTN mobility: no TA-validity timer expiry, no service-link/feeder-link handover trigger and no cell (re)selection evaluation**
  - *Why it matters:* satellite cells move, so a practitioner needs to know when the TA goes stale and when to re-point; --plan only prints prose and gives no timing
  - *Suggested:* `--ta-validity <sib19_ul_sync_validity_timer> → seconds to TA expiry at the current range-rate; --reselect <elevation_deg> <t> → reselect/handover trigger time`
  - *Evidence:* verified: 49_ntn.sh:144 ntn_plan is a heredoc; function list 49_ntn.sh:51-235 has no timer or selection function

### `50_gprs.sh`

- **no GMM mobility message codec: ATTACH REQUEST, ATTACH COMPLETE, ROUTING AREA UPDATE and the GMM cause values cannot be built or decoded**
  - *Why it matters:* the module's entire surface is APN and PDP-type IEs, so the Gb attach that every later procedure depends on cannot be generated or read
  - *Suggested:* `--gmm-attach <imsi> <ms_class> [tlli] → hex GMM ATTACH REQUEST; --gmm-parse <hex> → message name, IEs, cause`
  - *Evidence:* verified: 50_gprs.sh:276-286 subcommands are only gea/apn/pdp; function list 50_gprs.sh:50-256; siblings are EPS-only (09_lte_attach.sh:160-166 GUTI/IMSI) and EMM/5GMM-only (32_nas_signaling.sh:28-29)
- **no LLC layer: no UI/I frame, SAPI, TLLI or N(U) handling, so a GMM or SN-PDU cannot be framed for the radio interface**
  - *Why it matters:* every real GPRS capture is LLC-framed, so the module can neither emit a transmittable frame nor dissect one it captures
  - *Suggested:* `--llc-frame <sapi> <tlli> <pdu_hex> [n_u] → LLC UI/I frame hex; --llc-parse <hex> → PDU type, SAPI, N(U), TLLI, FCS`
  - *Evidence:* verified: grep -Ei 'LLC' over modules/*.sh → only 23_traffic_analysis.sh (Ethernet LLC/SNAP) and CVE prose; no LLC function in 50_gprs.sh:50-256
- **no GPRS/EGPRS coding scheme or RLC/MAC block structure: CS-1..CS-4 and MCS-1..MCS-9 (modulation, header layout, payload bits, family) are absent**
  - *Why it matters:* EDGE throughput work and RLC/MAC-level testing both start from the coding scheme, and the operator has no way to size or label a block
  - *Suggested:* `--cs-table and --mcs <n> [family] → modulation, payload bits, RLC/MAC header layout, padding`
  - *Evidence:* verified: grep -Ei 'EGPRS', 'MCS-1', 'MCS-9' over modules/*.sh → no coding-scheme table (nearest is 29_mac_layer.sh:1363, an LTE QAM selftest line); help 50_gprs.sh:276-286 lists no cs/mcs verb
- **no GEA cipher operation: --gea names the algorithm family and --gea-downgrade scores a negotiation, but there is no keystream engine**
  - *Why it matters:* an operator holding Kc and a GEA-encrypted LLC PDU still cannot decrypt it here; the sibling 06_gsm_air.sh already ships A5/1, so the missing piece is specifically the GPRS cipher
  - *Suggested:* `--gea-keystream <gea> <kc> <iv> <dir> <bits> → keystream hex; --gea-decrypt <gea> <kc> <iv> <hex> → plaintext`
  - *Evidence:* verified: 06_gsm_air.sh:669 gair_a5_1_keystream exists (help 06_gsm_air.sh:932 "--a5-1-keystream <kc-hex> [bits] [frame]"); 50_gprs.sh:81 gprs_gea_name returns a description only

### `51_sidelink.sh`

- **no 2nd-stage SCI (SCI format 2-A/2-B): HARQ process ID, NDI, RV, source/destination L2 ID, cast type and CSI request are not modelled**
  - *Why it matters:* SCI-2 is what addresses and lets a receiver reassemble the PSSCH, so without it an injected sidelink transmission cannot be accepted by the target
  - *Suggested:* `--sci2a <cast_type> <harq_id> <ndi> <rv> <src_l2id> <dst_l2id> → SCI-2A bit field and hex`
  - *Evidence:* verified: 51_sidelink.sh:290 and help 51_sidelink.sh:290 expose only "--sci1a SCI format 1-A field reference"; function list 51_sidelink.sh:51-265 has no sci2 function
- **no PSSCH TBS/MCS computation (TS 38.214 8.1.3.1): allocated REs, DMRS overhead and 64/256QAM are never combined into a transport-block size**
  - *Why it matters:* the operator cannot size a grant, nor check that an observed SCI-1A allocation is consistent with the TB actually transmitted
  - *Suggested:* `--tbs <prbs> <symbols> <mcs> <dmrs_pattern> → TBS bits, code rate, modulation order`
  - *Evidence:* verified: grep -Ei 'tbs' over modules/*.sh → no TBS size computation in any module (29_mac_layer.sh:577 maps an LTE MCS index to a TBS index only); 51_sidelink.sh:103 slnk_sci_1a sizes the frequency field, not the TB
- **no PQI/PC5 5QI table: --pfi accepts 1..64 but nothing maps a PQI to its 5QI, resource type, priority, PDB, MDBV or default PPPP**
  - *Why it matters:* V2X QoS troubleshooting starts from the PQI, and without the mapping the operator cannot state the latency and reliability a flow actually received
  - *Suggested:* `--pqi <1..65> and --pqi-table → 5QI, resource type, priority level, PDB, MDBV, default PPPP`
  - *Evidence:* verified: grep -Ei '5QI', 'PQI' over modules/*.sh → zero matches in any module; 51_sidelink.sh:90 slnk_pfi returns the PFI number and name only
- **no sidelink resource pool / PSFCH / SL-BWP configuration: no pool PRB range, sensing-and-selection window, PSFCH periodicity or PSFCH-to-PSSCH gap**
  - *Why it matters:* the module can count subchannels but cannot say whether a transmission is even legal in a given pool, which is the first check on a V2X job
  - *Suggested:* `--pool <prb_start> <prb_len> <psfch_period> <sensing_window_ms> → pool validity, PSFCH occasion, required gap`
  - *Evidence:* verified: help 51_sidelink.sh:286-287 offers only "--subchannels" and "--freq-bits"; grep -i 'psfch' over modules/*.sh → hits only inside 51_sidelink.sh, with no configuration function

### `52_stk.sh`

- **--build emits only tag 01 (command details) and tag 02 (device identities) — no command-specific payload TLV, so no usable command can be constructed (no Address, SMS TPDU, URL or alpha identifier)**
  - *Why it matters:* SET UP CALL, SEND SHORT MESSAGE and LAUNCH BROWSER are exactly the Simjacker/WIB primitives, and a D0 with an empty payload is inert
  - *Suggested:* `--build-call <number> / --build-sms <tpdu_hex> / --tlv <tag> <hex> repeatable, composing address, alpha identifier, SMS TPDU and URL TLVs`
  - *Evidence:* verified: 52_stk.sh:168-171 builds only "stk_tlv 01 $type$qualifier00" plus "stk_tlv 02 $src$dst"; 52_stk.sh:435-437 dispatch and help 52_stk.sh:455 "--build <type> <qualifier> [src] [dst]"
- **--parse prints raw tag/length/value rows and special-cases only tags 01 and 02, so device identities are not resolved to roles and Address/alpha-identifier values are not decoded (TON/NPI, BCD digits, text)**
  - *Why it matters:* an operator reading a real capture must decode every payload TLV by hand, which is exactly where a Setup Call target number gets misread
  - *Suggested:* `decode within --parse: address_number, ton, npi, alpha_text, device_role and a per-TLV name (or a standalone --tlv-decode <hex>)`
  - *Evidence:* verified: 52_stk.sh:184 prints a raw "tag	length	value" header; 52_stk.sh:194 prints the raw row; 52_stk.sh:195-199 handle only tags 01 and 02
- **no Terminal Response (tag 0x81) parse and no envelope handling (D1, D3, D6, D7): --parse rejects anything that does not begin with D0**
  - *Why it matters:* the card-initiated half of STK (call control, MO-SMS control, event download) and the result of every command are unreadable, so a command that fails cannot be diagnosed
  - *Suggested:* `--parse-response <hex> → result code, general result, additional information; --envelope <hex> → decoded envelope type and its TLVs`
  - *Evidence:* verified: 52_stk.sh:176 rejects input unless "${h:0:2}" is "d0"; grep -Ei 'terminal response', 'proactive' over modules/*.sh → only 52_stk.sh implements decoding (16_sim.sh:1421 and 16_sim.sh:1369 mention it only as prose evidence to collect)
- **no EF_SST/EF_UST service-table decode, so the audit scores risk without knowing which STK services the card actually provisions**
  - *Why it matters:* a command for a service that is not enabled in the service table can never fire, so the audit verdict can be wrong in the operator's favour
  - *Suggested:* `--sst <hex> → per-service enable/disable bitmap per TS 31.102 4.2.47, plus a verdict on whether the commanded service is provisioned`
  - *Evidence:* verified: 52_stk.sh:433-445 dispatch table has no --sst/--ust verb and 52_stk.sh:76-312 has no service-table function; grep -Ei 'EF_SST', 'EF_UST' over modules/*.sh → 16_sim.sh:189 is a file-ID name entry and 16_sim.sh:1405 is a prose instruction to read them

### `53_non3gpp.sh`

- **no TETRA PDU/stack decode: no MAC block/physical channel structure, no LLC PDU, no MLE mobility (Location Update) and no CMCE call-control message**
  - *Why it matters:* the module describes the frame but cannot read a captured TETRA burst, which is the whole job on a public-safety engagement
  - *Suggested:* `--tetra-pdu <hex> [channel] → decoded MAC block, LLC PDU and MLE/CMCE message with fields`
  - *Evidence:* verified: 53_non3gpp.sh:69 n3g_tetra_table is a frame/band heredoc; help 53_non3gpp.sh:265 "--tetra  TETRA frame/band reference (EN 300 392)"; function list 53_non3gpp.sh:50-274 has no PDU decoder
- **no TEA keystream engine: --tea returns a prose description of TEA1..TEA4 with no key schedule and no keystream**
  - *Why it matters:* identifying TEA1 in a capture is only half the finding — without the cipher the operator cannot demonstrate the confidentiality impact, and the toolkit's own precedent (06_gsm_air.sh A5/1) is to implement
  - *Suggested:* `--tea-keystream <TEA1..TEA4> <key> <iv> <bits> → keystream hex and a decrypted block`
  - *Evidence:* verified: 53_non3gpp.sh:81 n3g_tetra_tea returns text and the selftest asserts that sentence (53_non3gpp.sh:181-183, e.g. "TEA1 - the original cipher, deliberately weakened"); 06_gsm_air.sh:669 gair_a5_1_keystream
- **no carrier-number to frequency mapping and no site parameters: --classify only maps a kHz value the operator already knows, and there is no colour code, location area or MCC/MNC handling**
  - *Why it matters:* TETRA planning and capture work is done in carrier numbers 1..3999 per EN 300 392-2, and converting them by hand is error-prone while the site identity cannot be confirmed
  - *Suggested:* `--tetra-freq <carrier_number> → uplink/downlink MHz and duplex spacing; --site <colour_code> <la> <mcc_mnc> → site identity`
  - *Evidence:* verified: 53_non3gpp.sh:125 n3g_classify takes a kHz value; help 53_non3gpp.sh:264-273 lists no frequency, carrier-number or site verb
- **no DMR or GSM-R PDU decode: --dmr and --gsmr print reference tables only, so there is no DMR colour code/CSBK/Tier II-III slot decode and no GSM-R functional addressing or ASCI/VGCS group call handling**
  - *Why it matters:* the module's own header claims DMR and GSM-R (53_non3gpp.sh:2-4) yet it cannot read a single message from either technology
  - *Suggested:* `--dmr-pdu <hex> → slot, colour code, CSBK/embedded signalling; --gsmr-addr <number> → functional address class and ASCI group ID`
  - *Evidence:* verified: 53_non3gpp.sh:92 n3g_dmr_table and 53_non3gpp.sh:105 n3g_gsmr_table are heredocs; help 53_non3gpp.sh:267-268 shows --dmr and --gsmr accept no input

### `54_baseband_exploit.sh`

- **the L1/L2 cases are 14 hardcoded hex literals with no parameterized construction, so a field (SN, length, LCID, RIV, CellGroupId) cannot be set or swept**
  - *Why it matters:* fuzzing needs length and field sweeps at one layer, not 14 fixed blobs, so a target that only fails at another offset is never reached
  - *Suggested:* `--l2-build <layer> <field=value,...> → constructed PDU hex; --l2-fuzz <layer> <field> <range> → swept corpus`
  - *Evidence:* verified: 54_baseband_exploit.sh:233-249 bexp_l2_cases is a fixed heredoc (one RRC row is literally the two hex octets 00); 54_baseband_exploit.sh:251 bexp_l2_case only selects a row and never builds one
- **no RRC ASN.1 PER encoder: the RRC cases are raw byte literals, so a syntactically valid RRC PDU with one mutated field cannot be produced**
  - *Why it matters:* the 5Ghoul bug class needs a well-formed RRCReconfiguration with a single out-of-range field; a 2-octet literal cannot reach the deep parser
  - *Suggested:* `--rrc-encode <field=value,...> or --rrc-encode <json> → PER-encoded RRC PDU hex`
  - *Evidence:* verified: 54_baseband_exploit.sh:245-247 RRC cases are literals ("00", "0a01", "0b00"); 54_baseband_exploit.sh function list 66-500 has no encoder; the only ASN.1 helper anywhere is BER/DER length (35_baseband.sh:85 bbnd_asn1_len_encode)
- **5G NAS forgery covers only Registration Accept, Registration Reject and Identity Request, all plaintext — no Security Mode Command, Authentication Request/Reject or Deregistration, and no integrity-protected variant**
  - *Why it matters:* the messages that decide whether a UE accepts an unprotected accept cannot be forged, and a MAC-protected variant cannot be tested
  - *Suggested:* `--forge-sec-mode [integrity_alg] , --forge-auth-req [rand] [autn] , --mac <knas> <count> → message with a computed NAS MAC`
  - *Evidence:* verified: 54_baseband_exploit.sh:489-491 shows the three --forge verbs; 54_baseband_exploit.sh:153 bexp_forge_reg_accept; help 54_baseband_exploit.sh:508-511
- **no state detection: --states prints a static prose table (state1..state4) and nothing reads a capture to determine which state a UE is in**
  - *Why it matters:* the module's own flow says to "track the UE to the right state" before injecting (54_baseband_exploit.sh:342), but the operator must do that by hand in Wireshark to pick a case
  - *Suggested:* `--state-detect <pcap> [ue_id] → current attach state, last RRC/NAS message seen, layers reachable`
  - *Evidence:* verified: 54_baseband_exploit.sh:222-230 bexp_states is a heredoc; help 54_baseband_exploit.sh:514 shows --states takes no argument; no capture-input function exists in the 54_baseband_exploit.sh function list

### `55_nr_inject.sh`

- **--descramble is a prose model of the RA-RNTI to TC-RNTI to C-RNTI chain with no Gold sequence (TS 38.211 5.2.1): no c_init and no x1/x2 LFSR, so no real capture byte can be descrambled**
  - *Why it matters:* on an injection job the operator cannot read what the target is transmitting on PUSCH/PDCCH, and that feedback is what makes injection adaptive
  - *Suggested:* `--gold <c_init> <len> → pseudo-random sequence; --descramble <hex> <rnti> <slot> → plaintext hex`
  - *Evidence:* verified: 55_nr_inject.sh:312 dispatch and help 55_nr_inject.sh:330 "--descramble  the RNTI->plaintext model"; nrj_descramble is a heredoc of step1..step4 plus a "seed the descrambler" note; grep -Ei 'c_init', 'x_1', 'gold' over modules/*.sh → no sequence generator in any module
- **no DCI encode or parse: --dci prints a format reference only, so DCI 1_0/1_1 fields (RIV, FDRA, MCS, HARQ, TPC, DAI) cannot be read or set**
  - *Why it matters:* to schedule the target's uplink the attacker must emit a valid DCI, and the sibling 29_mac_layer.sh already extracts LTE DCI fields, so NR is the specific hole
  - *Suggested:* `--dci-parse <hex> <format> → field breakdown; --dci-encode <format> <k=v,...> → DCI hex`
  - *Evidence:* verified: 55_nr_inject.sh:311 "--dci) nrj_dci_formats" and help 55_nr_inject.sh:329 "--dci  NR DCI format reference"; contrast 29_mac_layer.sh:541-567, which parses LTE DCI 1A fields
- **no NR TBS/MCS computation (TS 38.214 5.1.3.2): --mac-pdu takes the subheader length from the operator and nothing maps MCS plus PRB count, symbols and DMRS overhead to a transport block size**
  - *Why it matters:* the grant the attacker sends must match the TB size the UE computes; a mismatch is discarded and the injection fails silently
  - *Suggested:* `--tbs <mcs> <prbs> <symbols> <dmrs> → TBS bits, code rate, modulation order`
  - *Evidence:* verified: grep -Ei 'tbs' over modules/*.sh → no TBS size computation anywhere (29_mac_layer.sh:577 maps an LTE MCS index to a TBS index only); 55_nr_inject.sh:309 "--mac-pdu <lcid> <body_hex>" demands the length implicitly
- **no RAR (Msg2) construction: the RA-RNTI is computed but the MAC RAR subPDU (backoff indicator, RAPID, TA command, T_C-RNTI, uplink grant) cannot be built**
  - *Why it matters:* the module's own flow starts with "read RAR (Msg2)" yet it cannot produce one, so a rogue-cell flow cannot be driven past Msg1 to Msg3
  - *Suggested:* `--rar <rapid> <ta> <tc_rnti> <grant> → MAC RAR subPDU hex, with --rar-backoff <ms> for the BI subheader`
  - *Evidence:* verified: 55_nr_inject.sh:154 step1 says "read RAR (Msg2)"; grep -Ei 'RAPID', 'backoff', 'tc-rnti', 'random access response' over modules/*.sh → no RAR builder in any module; help 55_nr_inject.sh:323-333 lists no rar verb

---

## Defects found while reviewing, already fixed

The review turned up matters of correctness, not just absence. Each was reproduced
by running the module, fixed, and covered by an assertion; details and exact
before/after output are in `CONFIRMED-BUGS.md`:

1. `06_gsm_air` SI3/LAI transposed the MNC digits — every real cell decoded wrong.
2. `07_gsm_attack` built IDENTITY REQUEST with the wrong protocol discriminator.
3. `03_gsmtap` called a verb that did not exist, so identity harvest died silently.
4. `05_field_kit` ignored its own `count` argument.
5. `15_downgrade --detect` could never fire on a pcap — it answered CLEAN for every capture.
6. `20_gsm_cve --kc` presented a truncated hash as an A3/A8 Kc — **since fixed: real COMP128-1/2/3 in `tools/gsm_crypto.py`**, wired into `--kc`/`--probe KC`, validated against published vectors.
7. Retracted: `11_lte_core` "flags 192" was correct Diameter per RFC 6733 §3.

Full suite after these fixes: `tools/run-selftests.sh`.
