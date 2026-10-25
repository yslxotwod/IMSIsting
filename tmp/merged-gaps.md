# IMSIsting — the build queue, most critical first

Two sources, merged and then re-ordered. The left half is the README's **What is
not built**: things the tree already attempts and cannot finish on this machine.
The right half is `tmp/future-exploits.md`: things the tree does not attempt yet.

The order is by how much the entry hurts, not by module number and not by lane.
Every entry is ranked R1..R80 in one continuous queue; the blocks are only there
so the page stays readable. When two entries share a rank, the cheaper one goes
first. Ranks are appended, never renumbered: a block that arrives later takes the
next numbers so that a rank already quoted in a plan or a commit still points at
the same row.

**How a rank was decided**, in order of weight:

1. **Does it put a subscriber in software with no radio?** Identity work outranks
   everything. A capture is evidence; an attach is a subscriber.
2. **Does it create an object the tree does not have?** Resident per-peer state —
   a key store, an AKA responder holding SQN, a NAS state machine. One of those
   unblocks several attacks; nothing else does.
3. **Does it need nothing but a laptop?** Tier 0 beats Tier 3 at equal damage.
4. **Does it execute, rather than observe?** Code that runs on a card or a phone
   outranks code that reads a pcap.
5. **Does it close a refusal the README already admits?** A named gap closed is
   worth more than a new lane opened.
6. Cost. Only as a tiebreak.

Class legend, unchanged: **code** missing work here · **far side** needs a peer
that answers · **hardware** needs a radio, a card or a device · **admission**
needs somebody's permission.

---

## Already shipped — not in the queue

`09_lte_attach` RRC Setup Complete + NAS responder (R4, LTE, 0.92.0) ·
`09_lte_attach` GUTI harvest, parse half (R5, 0.94.0) ·
`10_lte_air --build-sib1` SIB1 PLMN targeting (R6, 0.95.0) ·
`16_sim --usim-serve/--usim-tcp` virtual USIM (R7, 0.96.0) ·
`16_sim --auts-build/--auts-verify` AUTS resynchronisation (R8, 0.97.0) ·
`41_ota_sms --sat-audit/--sat-commands` S@T push audit (R9, 0.98.0) ·
`tools/check-scp03t.sh` + `16_sim --es8-scp03t --card-cryptogram` SCP03t verification (R11, 0.99.0) ·
`16_sim --rsp-audit/--rsp-plan` SGP.22 RSP binding audit (R10, 1.0.0) ·
`16_sim --profile-model` SGP.22 profile state machine (R12, 1.0.1) ·
`16_sim --euicc-fuzz` + `tools/euicc_fuzz.py` eUICC APDU fuzz corpus (R13, 1.0.2) ·
`16_sim --es8-build` SCP03t segment protection + `--es9-notification-build` (R14, 1.0.3) ·
`58_suci_catcher.sh` (A1 classifier + corpus, A2 live half, 0.86.0) ·
`57_evil_twin.sh` (L1 clone + attach) · `41_ota_sms --smpp-send` /
`tools/smpp_client.py --serve` / `--http-send --api textbee` ·
`tools/gsm_gea.py` (50_gprs GEA3/GEA4, nine vectors) · `42_li_probe` HI1
(TS 33.108 Annex M, BER encoder + referee) · `00_deps --preflight`.

---

# Block 1 — R1–R8 · The subscriber, with no radio

> Found while building R3's fixtures: `14_suci`'s null-scheme SUCI layout is
> `08 01 <routing indicator> <MSIN BCD>` and carries no home-network identifier,
> where TS 23.003 §2.2 puts MCC/MNC (and a scheme octet) in front of the routing
> indicator. Build and parse agree with each other, so nothing is invented; the
> layout is the module's own and a real null-scheme SUCI will parse with the
> MCC/MNC where the routing indicator is expected. Tracked as its own row below.

Ranked first because every other identity attack is downstream of R1, and R1
does not need a radio to exist.

| #   | entry                                          | does                                                                                                          | needs                                                   |
| --- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| R1  | ~~**Key store + AKA responder** (L1a, into `16_sim`)~~ **shipped 0.87.0** | `--key-add/--key-list/--key-show/--key-remove` keep IMSI → K/OPC (or TUAK TOP), SQN, AMF and a vector count in one 0600 TSV under `STATE_DIR`; `--aka-responder` returns the quintet from it, or the 5G HE AV inputs with `--5g --sn-name`, and persists the next SQN; `--aka-serve` is the resident responder on stdin (`VECTOR <imsi> [<rand>]`, `LIST`, `QUIT`). KAUSF/RES* are TS 33.220 KDF calls checked against OpenSSL's own HMAC | done — 625-assertion selftest; `--key-add --imsi … --op …` to store, `--aka-responder --imsi …` to answer |
| R2  | ~~**C7 — be your own home network** (SIDF + 5G-AKA)~~ **shipped 0.88.0** | `--hn-create --mcc/--mnc/--mnc-digits/--scheme/--ri [--keyfile]` mints the profile (PLMN, RI, scheme, 0600 private key, `SUCI_HN` name from TS 24.501) under `STATE_DIR/suci_hn`; `--hn-deconceal <suci>` is the SIDF (de-conceals with the profile key, resolves the IMSI, reports whether the `16_sim` store holds it); `--hn-auth <suci> [<rand>]` is the AUSF — de-conceals, looks the subscriber up by IMSI, runs 5G-AKA through `16_sim --aka-responder --5g` and prints XRES*/HXRES*/KAUSF/KSEAF per TS 33.501 A.4–A.6 (KDF key CK‖IK, XRES* = rightmost 128 of the 256-bit MAC); `--hn-serve` answers `SUCI`/`AUTH`/`SHOW` on stdin; `--hn-show` reads the profile | done — selftest adds 39 `hn-*` checks (187 total) including two OpenSSL HMAC referees; the card side of the proof still needs a physical USIM (R7) |
| R3  | ~~**A3 — 5G-AKA linkability oracle**~~ **shipped 0.90.0** | `--link-oracle <file>` judges every pair of observed SUCIs as linked or not and names the signal: identical SUCI octets, a reused ephemeral key, an identical MSIN ciphertext, a cleartext MSIN (null scheme), or an AUTN given to two rounds; fields the whole network shares (scheme, key id, routing indicator) are reported as non-identifying, the MSIN's length class as weak-only. `--link-demo` builds the fixture on the host's own home network: fresh rounds not-linked, reused ephemeral key linked, null scheme, two subscribers, one vector to two rounds | done — 225-assertion selftest; the signal set is structural, so a pair that differs in every field is not-linked even where cryptanalysis would join it |
| R4  | ~~**A5 — RRC Setup Complete + NAS responder**~~ **shipped 0.92.0 (LTE half)** | `09_lte_attach --setup-complete/--parse-setup-complete` wrap and read the UL-DCCH RRCConnectionSetupComplete (tools/lte_rrc.py owns the PER layout); `--nas-responder` holds the attach state across the UE's own NAS PDUs, records the identity a subscriber states, and answers with an identity request or an attach accept. `32_nas_signaling` grew the accept side, tshark-checked. Stops where the tree cannot encode honestly: authentication needs an AUTN at an unconfirmed offset, and the accept carries no ESM container. The NR framing (TS 38.331 / 24.501) is not built — this is the LTE attach | done — selftest 09 (setup-complete round trip, responder transitions) + 32 (accept vectors) + GSMTAP oracle 14/14 |

| R5  | **G2 — GUTI harvest on attach (parse half)**   | makes a phone hand over an identity the network issued; the parser is free, the harvest is radio. `09_lte_attach --guti-decode` reads the PLMN, MME group, MME code and M-TMSI (the order tshark reads, pinned in --selftest); `--guti-map`/`--guti-tsv` keep one binding per GUTI with an attach count, and `--nas-responder` binds the GUTI the moment the identity response supplies the IMSI — so the *next* attach presenting that GUTI resolves without asking. The radio half is unchanged: harvesting outside a lab still needs a cell | done — Tier 0 parse half built; Tier 4 to harvest over the air |

| R6  | ~~**A4 — SIB1 PLMN targeting**~~ **shipped 0.95.0** | `10_lte_air --build-sib1 --plmn <mccmnc> [--tac] [--cellid] [--band] [--qrxlevmin] [--barred]` builds the SIB1 a cell broadcasts: the PLMN list a handset's selection matches (TS 23.122 4.4), the tracking area it compares with its own, and the cell identity it reports. The body is built by the same PER codec that reads it and is decoded back before it is printed, so a target the tree cannot read back is not reported as built; the answer names the operator the codes belong to, says whether the cell is selectable, and states the limit (no MIB, no BCCH scheduling, no PHY) | done — selftest pins the vector, a 3-digit-MNC PLMN, a barred cell and the refusals |
| R7  | ~~**Virtual USIM over a socket**~~ **shipped 0.96.0** | `16_sim --usim-serve --imsi <isim>` is the card: one hex C-APDU per line on stdin, one R-APDU back. SELECT by AID (USIM/ISIM prefix) and by file id, READ BINARY over EF_IMSI (built from the store's IMSI), VERIFY (no PIN record, said so), 3G AUTHENTICATE P1=81 (RES||CK||IK computed from the key store with the SQN counter persisted per vector), GET RESPONSE; secure messaging 6E00, unknown files 6A82, the 2G authenticate refused by name. `--usim-tcp <port>` puts the same card on a socket via socat, one responder fork per connection, sharing the store | done — selftest drives the whole conversation and asserts the R-APDU bytes; AUTS remains R8 |
| R8  | ~~**L1c — AUTS**~~ **shipped 0.97.0** | `16_sim --auts-build <ki> <opc> <rand> <sqn_ms>` computes AUTS = (SQN_MS xor AK) || MAC-S (TS 33.102 6.3.5, MAC-S = f1* with AMF=0000), and `--auts-verify <ki> <opc> <rand> <auts>` is the network half: recover SQN_MS from the masked counter, verify MAC-S, report the next SQN. The USIM responder now compares the AUTN's SQN with the card's own and answers a stale network with 9862 + AUTS instead of a vector, so one stale SQN no longer means an attach that fails with no diagnosis | done — selftest pins the vector, the tamper, and both card paths |

> R7 note: `--sim-auth` already computes RES/CK/IK/AUTN for all five algorithms;
> what is absent is the EF layout a UE reads first and the card-side APDU stream.

---

# Block 2 — R9–R15 · Cards and SIM runtime

Ranked above over-air work because the payload executes on a card or a phone
instead of being observed in the air, and the whole run fits on a desk.

| #   | entry                                          | does                                                                        | needs                                           |
| --- | ---------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------- |
| R9  | ~~**B5 — STK / OTA depth, S@T and WIB payloads**~~ **shipped 0.98.0 (S@T half)** | `41_ota_sms --sat-audit <push_hex>` reads an S@T push back: locates the 0x42 push inside an envelope or bare, walks deck -> card -> every 2D macro with the BER lengths, names each command from TS 102 223 (PROVIDE LOCAL INFORMATION location/IMEI, SEND SHORT MESSAGE) and decodes the exfil TPDU to the destination number, then states the findings and a verdict. `--sat-commands` lists every S@T construct this tree builds with its clause, and carries the WIB row as a refusal. WIB itself stays refused (R15): no citable encoding exists here | done — selftest audits a built push, a wrapped push and a non-push; WIB unaffected |
| R10 | ~~**B1 — SGP.22 RSP attack suite**~~ **shipped 1.0.0 (analysis half)** | `16_sim --rsp-audit <response-json> [--request <json>] [--eid <hex>]` audits a captured ES9+ exchange against the three ties SGP.22 actually relies on -- transactionId binding (6.5.2.6-6.5.2.8), the SM-DP+ signature set, and the EID the profile is bound to -- names each missing tie as a HIGH/MEDIUM finding with its clause, and exits non-zero when a replay or a redirected response would go undetected. `--rsp-plan <profile-move|notification-spoof|smdp-redirect>` is the handoff for each attack B1 names, with what it needs and what it refuses. No signature is forged and no TLS is broken here: the audit shows where the binding is missing | done — selftest covers bound, replayed, unsigned, moved-EID bodies and the plan refusals; running an attack against a live SM-DP+ still needs a test eUICC |
| R11 | ~~**B3 — SCP03t key derivation and verification**~~ **shipped 0.99.0** | `tools/scp03t.py --selfcheck` now hands every KDF input to `openssl mac ... CMAC` and compares all five derived values (S-ENC, S-MAC, S-RMAC, card and host cryptograms) plus the counter-mode property, so the derivation is checked against an implementation that shares no code with this tree; `tools/check-scp03t.sh` is the outside gate and reports SKIP (not PASS) without openssl. `16_sim --es8-scp03t --card-cryptogram <8 octets>` checks a card's cryptogram against what the derivation predicts: match exits 0, mismatch exits 1 with the reason | done — selftest pins the five values, both verify outcomes and the short-input refusal |
| R12 | ~~**B4 — profile state machine modelling**~~ **shipped 1.0.1** | `16_sim --profile-model <events-file>` runs a sequence of install/enable/disable/delete/list operations over ICCIDs through the SGP.22 2.6.1 three-state model (enabled/disabled/deleted) and names every step the spec forbids: a delete while enabled (5.7.7), an enable of a deleted profile, a duplicate install, a double disable/enable -- and reports the one-slot rule when a second profile is enabled (5.7.6) by disabling the first. Exit is non-zero on any forbidden step; the verdict says the sequence is legal by the model, which is not the same as a card having run it | done — selftest runs a legal sequence, a delete-while-enabled, the one-slot case and an enable-after-delete |
| R13 | ~~**B2 — eUICC APDU fuzzer**~~ **shipped 1.0.2 (Tier 0 half)** | `tools/euicc_fuzz.py` generates 20 malformed C-APDUs (length over/understatement, both Lc and Le, unknown INS, bad P1/P2, oversized and truncated AUTHENTICATE, read past EOF, empty SELECT, secure-messaging and unknown classes, truncated and odd-digit variants of every valid command) and classifies each answer: refused / accepted / silent / hang / crash. `16_sim --euicc-fuzz [--target usim|reader]` drives it at the card this tree serves (R7), so the corpus is meaningful with no hardware, and exits non-zero when the target accepts garbage, goes silent, hangs or crashes; `--target reader` is the Tier 1 handoff naming the reader and the sacrificial eUICC. Baseline on R7's card: 20/20 refused | done — selftest runs the corpus, an accept-everything target (caught), a silent target, a crashing target and the refusals |
| R14 | ~~**B2 — ES8+ bodies 87/88/86 and HandleNotification**~~ **shipped 1.0.3** | `--es8-build sequence-86|87|88` with `--k-enc --k-mac --host-challenge --card-challenge` now protects the segment itself: SCP03t's PPP chain (one MCV over the elements, tag 86/87/88) runs locally — no pre-protected bytes asked for, no second tool needed. `--es9-notification-build --iccid <hex> [--result success|failure] [--reason n]` assembles the PendingNotification octets the HandleNotification body carries (BF37 { BF27 { 5A iccid, A2 { 30 { 5F0F aid } } } } for a success, or a '81' errorReason for a failure), and walks them back with the same parser the HandleNotification verb uses. Round trip verified in the selftest: build → walk → root BF37 → pendingNotification → `verify yes`, for success and failure. The SGP.22 5.7.9 euiccSignPIR signature is out of scope here (it is the eUICC's, not the LPA's) and each row says so | done — selftest asserts the wrappers (A3/A0/A1), the 86/87 tag, determinism, the handoff when half the material is missing, both notification results and the refusals |
| R15 | ~~**`41_ota_sms` — WIB push leaf bytes**~~ **refused by design (documented)** | The queue's own instruction was "refused rather than half-built", and that is the state this row lands in, made load-bearing: `--wib-push` refuses with three WHY rows (no clause states the WIB application-request encoding; the S@T and 102 223 text name the S@T browser only; #WIBattack documents the impact, not the leaf tags), an exit 2, empty stdout, and a NOTE naming the exact document that unblocks it (the SIMalliance WIB specification's card command chapter, or one captured WIB push). Inventing bytes would render as a push PDU indistinguishable from a real one -- the failure MODULE_CONVENTIONS §9 rules out. The transport half a WIB push would ride is built and shared (`--sat-push`: TS 31.115 §4.2 packet, SPI/KIc/KID/TAR, TP-PID 0x7F, TP-DCS 0xF6, UDH IEI 70) | selftest asserts the refusal, its three WHY rows, empty stdout, and that it names the unblocking document |

---

# Block 3 — R16–R27 · Over the air: the catcher lane and 2G messaging

The transmitter work, in the order that makes a run finish. R16/R17 need the
Block 1 object before they can do more than clone a cell.

| #   | entry                                                  | does                                                                                                     | stops / needs                                                                                                          |
| --- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| R16 | **A2 — `58_suci_catcher` transmit half**               | pretends to be an NR cell, lets a phone attach far enough to introduce itself                             | Tier 4 for the over-air half                                                                                            |
| R17 | **L1 — `57_evil_twin` transmit half**                  | clones a cell, accepts the attach, reports what came back                                                | Tier 3 (full-duplex 2x2)                                                                                                |
| R18 | **L1b — MAP SAI answer parser**                        | `--build-sai` asks; nothing parses the vectors that come back                                            | Tier 0 build, interconnect to use                                                                                       |
| R19 | **`07_gsm_attack` — fake cell delivering SMS-DELIVER** | RACH → AGCH(IA) → paging response → UA → SABM(SAPI 3) → CP-DATA → CP-ACK → RR release. RR builders exist, TP layer exists, the LAPDm framing and the sequence between them do not | code + hardware; sequence is published in TS 44.006 / 44.018 / 24.011                                                   |
| R20 | **`41_ota_sms` — `--cb-build`**                        | TS 23.041 in CBCH/SMSCB encoding: a CB message in 4 consecutive TDMA blocks plus the CBC's `SMS BROADCAST COMMAND`. LTE PWS already builds (`10_lte_air --build-sib10/11/12`) | code; 4-block TDMA packing is published (TS 44.012 / 23.041 §9), nothing here encodes LAPDm blocks                       |
| R21 | **G3 — GUTI reallocation observation**                 | forces a new temporary identity, records when reallocation happens                                       | Tier 4                                                                                                                  |
| R22 | **G1 — 5G-S-TMSI paging narrowing**                    | narrows to a paging frame and occasion, watches which the phone answers                                  | Tier 2 receive-only for the observation                                                                                 |
| R23 | **K6 — DoLTEst device negative-test corpus**           | normative-rejection cases driven through the existing responder                                          | Tier 4 to send, Tier 0 for the corpus                                                                                   |
| R24 | **K4 — Devilray: being detected**                      | would the phone notice; answers a question the tree has never asked                                      | Tier 0→3                                                                                                                |
| R25 | **`08_umts_air` — duplex loop**                        | RRC forgery, BCH through TS 25.212, WCDMA carrier with CPICH and both sync channels, MM identity request, uplink RACH — nothing receives UMTS uplink and answers it in one process | hardware + code; **A5** is the LTE analogue of the same missing middle                                                  |
| R26 | **`33_jamming_detect` — PUCCH**                        | `pucch` refused: no PUCCH sequence generator in the tree (it is a sequence generator in `tools/phy_seqs.py`) | code                                                                                                                    |
| R27 | **`35_baseband` — modulator**                          | a payload is a handoff to srsRAN or OpenAirInterface                                                     | hardware; **E3** (QEMU harness) is adjacent, not the same thing                                                         |

---

# Block 4 — R28–R43 · Core network: everything runs on IP

A laptop, Open5GS and no radio. Ranked below the identity blocks only because
damage depends on the core answering.

| #   | entry                                          | does                                                                                                        | needs                                        |
| --- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| R28 | **C4 — PFCP session hijack**                   | takes over a user-plane session by speaking SMF↔UPF directly                                                | Tier 0 build, Tier 5 against a real core     |
| R29 | **C2 — SBA boundary bridging / tunnelling**    | can a home-network service be reached from a visited network?                                               | Tier 0 — two Open5GS + a SEPP stand-in       |
| R30 | **C8 — cloud metadata from the SBA**           | reaches a cloud IMDS through the 5G core's own HTTP layer                                                   | Tier 0 — Open5GS + metadata stub             |
| R31 | **C5 — NGAP / AMF exposure**                   | walks what the AMF answers to an unauthenticated peer                                                       | not stated                                   |
| R32 | **C3 — NRF discovery abuse**                   | asks the service directory what exists, maps the core without touching it                                   | Tier 0                                       |
| R33 | **C1 — 5G key reinstallation**                 | forces a re-key, replays old material, sees whether the counter resets                                      | Tier 0 — Open5GS + srsUE over ZMQ            |
| R34 | **C6 — Diameter / GTP flooding depth**         | the DoS half, with message-rate maths done properly                                                         | not stated (`11_lte_core` is analysis-heavy) |
| R35 | **D1 — rogue xApp / A1 poisoning**             | quietly changes how radio resources are divided                                                             | Tier 0 — O-RAN SC Near-RT RIC + E2 simulator |
| R36 | **D3 — slicing isolation attacks**             | can one slice reach another's resources; does S-NSSAI→5QI→PRB hold under abuse                              | not stated                                   |
| R37 | **D2 — E2 subscription abuse**                 | subscribes to the performance stream, gets per-UE telemetry                                                  | not stated                                   |
| R38 | **I2 — VoWiFi / ePDG attack depth**            | past IKEv2 parsing: ePDG selection, EAP-AKA' privacy, fragmentation                                         | Tier 0; a real ePDG for live work            |
| R39 | **`26_ss7_map` — far side**                    | ten MAP operations, TCAP/SCCP/MTP3/M3UA/SGsAP, four decoders, response builders, dialogue pairing, `--lab`, `tools/ss7_responder.py` | an STP that accepts your point code and an HLR that answers. No TDM MTP2: an operator peering only over E1/TDM is out of reach |
| R40 | **`26_ss7_map` — ATI answer referee**          | the ATI answer body is not referee-checked: pycrate here cannot encode `SubscriberState` and writes `ageOfLocationInformation` untagged where TS 29.002 defines `[0]` | Tier 0 (rebuild pycrate) / Tier 5 (a real HLR) |
| R41 | **`42_li_probe` — envelope**                   | TLV framing, semi-octet BCD, provisioning/activation/product artefacts already exist; the envelope is **self-defined**, not the TS 33.108 ASN.1, so nothing reaches an ADMF | code + far side                              |
| R42 | **`44_carrier_api` — executor**                | OpenAPI parsing, authorisation matrix, request rendering, subscriber-sequence ordering exist; no executor — writes `curl` lines and sends nothing | code (by design)                             |
| R43 | **`11_lte_core`, `13_nr_core`, `40_sba_pivot`, `30_volte_ims`** | GTP-C, Diameter, NGAP, PFCP, SBI and SIP builders with senders over real SCTP/UDP | a core that answers                          |

> Identity directions in `26_ss7_map`: SRI/SRI-SM take a number and answer with
> IMSI + serving MSC; `--imsi` flips them (tag 81 where the SEQUENCE defines
> `msisdn [0]`, so tshark calls it malformed). ATI takes an IMSI, `--msisdn` uses
> the CHOICE's number arm and decodes cleanly.

---

# Block 5 — R44–R48 · Detection: the defender's half

Cheap, laptop-only, and each one answers a question no detector in the field
answers today. Ranked below the attack work because it protects rather than
acquires — but it is the cheapest honest material on the page.

| #   | entry                                          | does                                                                | needs                                  |
| --- | ---------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------- |
| R44 | **K7a — AdaptOver/5Gone detection half**       | detects an attack no fake-base-station detector can see              | Tier 0                                 |
| R45 | **K1 — CITesting, uplink context integrity**   | an attacker position that needs no radio: the UE's own report of its context | Tier 0, Open5GS loopback        |
| R46 | **K2 — Kairos, timing-induced interaction faults** | two procedures whose interleaving breaks a state machine         | Tier 0, same lab as K1                 |
| R47 | **K5 — 2026 CVE gap**                          | the corpus stops at CVE-2025-26782 and is documented as current      | Tier 0, half a day                     |
| R48 | **K3 — BASECOMP integrity check**              | completes a check `54_baseband_exploit.sh:191` already half performs | Tier 6 (needs a firmware target)       |

> K5 is a catalogue fix, not an attack: the value is the handoff plan per CVE,
> not the identifier. An entry without a plan is a name — the same complaint
> aimed at `20_gsm_cve` / `21_lte_cve` / `22_nr_cve` in the brief.

---

# Block 6 — R49–R68 · Radio-expensive and research scale

Real work, wrong order to start with: each needs Tier 2–5 of gear or a research
target before the first result exists.

| #   | entry                                          | does                                                                | needs                                                   |
| --- | ---------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------- |
| R49 | **H1 — ghost vehicle, BSM injection**          | broadcasts a safety message for a car that does not exist            | Tier 3 (HackRF reaches 5.9 GHz) + sidelink PHY, the work |
| R50 | **H3 — resource-pool DoS**                     | occupies sidelink resources so real V2X traffic cannot pass          | Tier 3                                                  |
| R51 | **H4 — malicious U2N relay**                   | sits in a UE-to-network relay and sees the traffic                   | not stated (TS 23.303 / 33.303)                         |
| R52 | **H2 — pseudonym certificate linkability**     | analysis over a capture                                              | Tier 0                                                  |
| R53 | **F1 — SIB19 encode/decode**                   | reads and forges the satellite cell's broadcast                      | Tier 0 (closes the `49_ntn` refusal)                    |
| R54 | **F2 — hostile ephemeris / K_offset**          | forged geometry and wrong slot offsets, records what the phone does  | Tier 0 vectors; Tier 1 or 4 to observe                  |
| R55 | **F3 — NTN delay geolocation**                 | timing advance → a position on the ground                            | Tier 2 for live data; the maths is free                 |
| R56 | **F4/F5 — NTN downlink receive / fake cell**   | listen for a satellite cell; or broadcast its downlink on the band it would use | F4 Tier 2 (detection only); F5 Tier 3 **and** duplex, plus a UE that accepts it |
| R57 | **E1 — 5GBaseChecker reproduction**            | same malformed messages at many modems, compare answers              | Tier 6 — firmware, rooted devices, QEMU                 |
| R58 | **E2 — ConSeT property checks**                | the named bad behaviours, without the full framework                  | Tier 6 firmware / Tier 1 device                         |
| R59 | **E3 — firmware extraction + QEMU harness**    | pulls a baseband image and runs it with a fake network               | not stated (the plumbing E1/E2 need)                    |
| R60 | **I5 — adjacent radio: TETRA / DMR / GSM-R**   | the codecs are the work; also the cheapest bands to transmit legally (PMR licences) | Tier 3                                     |
| R61 | **K7b — AdaptOver transmit planner**           | sample-indexed schedule; keys nothing                                | Tier 4 + PA, research                                   |
| R62 | **I3 — femtocell real attack surface**         | the actual attacks against a used femtocell with a valid cert        | Tier 1 — €30–80                                         |
| R63 | **I4 — NB-IoT depth**                          | narrowband attach flow, coverage-enhancement abuse surface           | Tier 2 for the air side                                 |
| R64 | **`45_iot` — NPRACH, NPRFCN**                  | NB-IoT RRC decoders through a generated codec; NPRACH and NPRFCN refused, parameters not verifiable against the standard text, so they are named, not guessed | code (closes with I4)                    |
| R65 | **`46_lpp` — UTDOA**                           | UTDOA is LPPa, not LPP: stated as a handoff, not encoded as the wrong protocol | code                                            |
| R66 | **`49_ntn` — SIB19 layout**                    | no NR RRC layout table in the tree                                   | code (closes with F1)                                   |
| R67 | **`50_gprs` — GEA1/GEA2**                      | recovered only in the cryptanalysis literature (EUROCRYPT 2021, ePrint 2022/424: 2^40, 44 GiB→4 MiB); tap sets not transcribed with a vector here. GEA0/GEA3/GEA4 compute with nine published vectors | code + admission                                        |
| R68 | **`16_sim` — AUTS resync**                     | the responder side of AUTS, distinct from L1c's cause                 | code                                                    |

---

# Block 7 — R69–R73 · Housekeeping

Cheap, unglamorous, and each one keeps the rest honest.

| #   | entry                                          | does                                                                | needs     |
| --- | ---------------------------------------------- | ------------------------------------------------------------------- | --------- |
| R69 | **I7 — evidence and reporting**                | hashes, timestamps, capture provenance so a finding stands up in a report | Tier 0 |
| R70 | **I6 — killchain library expansion**           | more built-in chains wiring new modules together                     | Tier 0    |
| R71 | **`41_ota_sms` — optional TLVs, submit_multi, data_sm, SMPP-over-TLS** | refused by name beside the working bind + submit_sm path | code      |
| R72 | **`20_gsm_cve`, `21_lte_cve`, `22_nr_cve`**    | catalogues and reachability checks. No exploit primitive claimed      | code      |
| R73 | **`50_gprs` — GEA5**                           | TS 55.251 5.3-5.6 and TS 55.252 test data are licence-gated          | admission |
| R74 | **`14_suci` — null-scheme SUCI carries no home-network identifier** | the layout is `08 01 <routing indicator> <MSIN BCD>`; TS 23.003 §2.2 puts MCC/MNC and a scheme octet in front of the routing indicator, so a real null-scheme SUCI parses with the MCC/MNC read as the routing indicator. Build and parse agree, so nothing is invented; the fix is to emit and read the home-network identifier and to keep the old layout readable behind an explicit flag | code — touches build, parse, audit and the R3 fixtures |

---

# Block 8 — R75–R80 · 3G/UTRAN: the messages and objects the tree does not have

The 3G surface is the thinnest of the four generations in this tree, and not
because it was skipped: `08_umts_air` owns the whole downlink chain (CPICH and
both sync channels, the TS 25.212 BCH chain, SIB1/3/5 packed onto BCCH-FACH and
spread on an S-CCPCH, the MIB derived from the SIB set, RRC Setup/Reject/Paging
forgery, the MM IDENTITY REQUEST, AKA replay) and the uplink as chips. What is
missing is the layer above and the layer beside: no Security Mode Command that
selects an algorithm, no 24.008 Session Management, no 3G paging arithmetic, no
positioning that is not timing advance. Each row below was checked against the
tree, not against the standard alone — the absence is named with the command
that shows it.

Ranked after housekeeping because none of them puts a subscriber in software
with no radio: R76 and R78–R80 are a codec, a detector and a parser that change
nothing until a 3G capture or an Iu peer exists, and R75 and R77 need the carrier
(Tier 4) or the loop (R25) before their last step. Appended past R74 so that no
existing rank moves.

| #   | entry                                          | does                                                                | needs     |
| --- | ---------------------------------------------- | ------------------------------------------------------------------- | --------- |
| R75 | **UMTS RRC SECURITY MODE COMMAND** (`08_umts_air`, `19_cipher_audit`) | the RRC message TS 25.331 §8.1.12 defines — ciphering and integrity algorithm capability as bitstrings, activation time, RB downlink ciphering activation time info, RRC transaction id — which is what actually selects UEA0/UIA0 on a forged cell. Absent today: `15_downgrade --build-security-mode` emits a **NAS-shaped single octet** (`smc_octet`, `cipher_id`/`integrity_id`) and takes `UMTS` only as a label for its exposure text, and `19 --parse-smc` parses the NAS form (its minimum-length table is `eps`/`5gs`). With this message, the null-cipher forcing that 08's own `--transmit --sibs` carrier already reaches becomes end-to-end | code — Tier 0 build, Tier 4 to deliver |
| R76 | **TS 24.008 Session Management and the 3G attach** (`09_lte_attach`) | PDP context activation/modification/deactivation, ATTACH REQUEST and ROUTING AREA UPDATE in their 24.008 form, TI/QoS/APN, P-TMSI and RAI. `09` is 24.301 only — **zero references to 24.008** — so the 3G data-attach plane has no codec at all, and the identity fields a 3G catcher harvests live in exactly those messages | code — Tier 0 |
| R77 | **UTRAN paging arithmetic + P-TMSI harvest** (`28_paging_track`, `08`) | PICH/S-CCPCH paging occasions and URA_PCH, and correlating a paged P-TMSI with the identity response. `28` cites TS 45.002, TS 36.304 and TS 38.304 only, so the Piercer-model attack exists for every generation **except** this one | Tier 0 to compute, Tier 4 to harvest |
| R78 | **UMTS CS keystream reuse** (`30_volte_ims`, `07`, `19`) | COUNT-C per radio bearer, the CS domain's ciphering sequence, and the RNC reset that can hand a second CS call the same CK at the same COUNT-C: two AMR streams under one keystream XOR to speech, the same primitive ReVoLTE demonstrates one generation up. `30`'s reuse detector is PDCP/LTE; f8/KASUMI keystream already exists in `07` | code + a capture — Tier 0 |
| R79 | **UMTS positioning: RTT and Rx-Tx** (`39_ta_geoloc`, `08`) | UTRAN has no timing advance. The fix comes from RTT and the Rx-Tx time difference carried in RRC measurement reports, or from U-TDOA at the network. `39` converts TA (78.07 m per unit, LTE/NR) and `46_lpp` is LPP; the geometry here is free and the parser does not exist | code — Tier 0; Tier 2 for real reports |
| R80 | **Macro Iu-CS RANAP surface** (`37_femtocell`, `26_ss7_map`) | RANAP Initial UE Message with a forged IMSI/LAI, Paging, Reset/Overload and Direct Tunnel shaping against a macro Iu-CS. `37` builds these shapes only for the home-node path (Iuh/HNBAP/RUA), where a CSG identity makes them plausible; without that, nothing here is built or even refused | code + far side (an RNC/MSC that answers) |

> Two 3G gaps are already queued elsewhere and are **not** repeated here: the
> duplex loop that would make a 3G catcher complete is **R25**, and the
> responder side of AUTS is **R68**.

> Deliberately **not** a queue entry: UEA1/UIA1 cryptanalysis. The KASUMI
> structural and related-key results (Biham–Dunkelman–Keller, and the later
> biclique work) are real, and none of them is a practical attack with keys you
> do not hold — `19_cipher_audit` already says so in its cipher table. The 3G
> cipher attack that works is not cryptanalysis: it is null-algorithm forcing
> (**R75**) and count reuse (**R78**).

---

# Where the two lists meet

These roadmap entries **close a README gap** rather than open a lane. The
right-hand column names the new rank so the mapping survives the re-sort.

| README gap                                                                    | closed by                                                                    | rank          | cost                         |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------- | ---------------------------- |
| no key store, no AKA responder, no resident state                             | **R1** (`16_sim --aka-responder`) then **R4** (NAS responder)                | R1, R4        | Tier 0 build → Tier 1 run    |
| `16_sim` — SCP03t, ES8+ 87/88/86                                              | **R11** (key derivation + verification), **R10** (RSP suite), **R12** (state model) | R10–R14 | Tier 0 build, €10–20 to test |
| `41_ota_sms` — WIB push leaf bytes                                            | **R9** (S@T and WIB payloads)                                                | R9, R15       | Tier 0 build, Tier 1 to run  |
| `16_sim` — a card that answers an attach                                       | **R7** (virtual USIM over a socket)                                          | R7            | code                         |
| `49_ntn` — SIB19 layout table                                                 | **R53** (SIB19 encode/decode)                                                | R53, R66      | Tier 0                       |
| `45_iot` — NPRACH, NPRFCN                                                     | **R63** (NB-IoT depth)                                                       | R63, R64      | Tier 2 for the air side      |
| `42_li_probe` — X3/HI3 is this module's own LIPR TLV                          | HI1 closed; HI3 not transcribed                                              | R41           | Tier 0                       |
| `33_jamming_detect` — PUCCH                                                   | no roadmap entry; it is a sequence generator in `tools/phy_seqs.py`          | R26           | Tier 0                       |
| no 4G/5G catcher at all                                                       | **R17** (`57_evil_twin`) plus **R1**/**R8** (key store, AUTS) and **R18** (SAI parser) | R1, R8, R17, R18 | Tier 3 + duplex radio   |
| no detector for overshadowing                                                 | **R44** (`59_overshadow.sh --detect`)                                        | R44           | Tier 0                       |
| `26_ss7_map` — TDM MTP2                                                       | no roadmap entry: MTP2 over E1 is a TDM card and an operator                 | R39           | Tier 6 + admission           |
| `26_ss7_map` — ATI answer referee                                             | no roadmap entry: needs a pycrate build that can encode `SubscriberState`, or a real HLR | R40 | Tier 0 (rebuild) / Tier 5 |
| `08_umts_air` — duplex loop                                                    | **R4** is the LTE analogue; for UMTS it is the same missing middle           | R4, R25       | Tier 0 build, Tier 4 to run  |
| `35_baseband` — no modulator                                                    | **R59** (QEMU harness) is adjacent, not the same thing                       | R27, R59      | Tier 6                       |
| `50_gprs` — GEA1/GEA2                                                          | closed for GEA3/GEA4 by `tools/gsm_gea.py` (nine published vectors); GEA1/2 need the recovered taps transcribed with a vector | R67, R73 | Tier 0 for the write-up |

## Module numbering — settled, and one collision fixed

`57` was claimed twice: the plan gives `57_suci_catcher.sh` to **A2** and
`57_evil_twin.sh` to **L1**. Highest module in the tree is `56_baseband_diag.sh`,
so the numbers are assigned once, here:

| number | module                | from              |
| ------ | --------------------- | ----------------- |
| 57     | `57_evil_twin.sh`     | L1 → **R17**      |
| 58     | `58_suci_catcher.sh`  | A2 → **R16**      |
| 59     | `59_overshadow.sh`    | K7 → **R44**      |

`59_overshadow.sh` rather than the `63` the source file proposed: a gap in the
numbering invites someone to fill it with a module that was never planned.

## The finding that matters more than the numbering

**R1 and R4/R16/R17 need the same object** — shipped in 0.87.0: a
subscriber store (`IMSI → Ki/OPc, SQN, state`) plus an AKA responder that holds
state across messages, plus the NAS state machine. Building it twice — once
inside an evil-twin module and once inside a SUCI catcher — is the mistake this
list exists to prevent.

Where it goes: `modules/16_sim.sh`, which already computes Milenage/TUAK
f1..f5\* and assembles AUTN (`modules/16_sim.sh:2055-2133`, AUTN at `:2117`);
the header at `:2065` states plainly that **AUTS is not built**. A
`--aka-responder` verb there, holding SQN and emitting the full quintet (or 5G
HE AV), gives both front ends one implementation, and `13_nr_core` the AV
generator it never had (KAUSF is an input at `modules/13_nr_core.sh:1172`, never
computed). **Built**: the store is
`state/sim_aka/subscribers.tsv` (0600), the responder is
`modules/16_sim.sh --aka-responder`, the resident form is `--aka-serve`, and the
KDF lives in `tools/gsm_crypto.py --kdf` (TS 33.220 Annex B.2, refereed against
OpenSSL).

Consequence: the "exactly one new module survives" answer is **three** now (57,
58, 59), all three for the same reason — resident per-peer state plus
transmission, which no flag on a stateless encoder can supply. Everything else
in K and L is an addition to an existing module.

## The cheapest ten, in order

R1, R2, R3, R6, R32, R44, R45, R46, R47, R69. Every one of them runs on the
laptop with no radio; six of them close a README gap or build the object the
radio work needs first.

Not in that ten, but the same price: **R75** (the RRC Security Mode Command) and
**R76** (24.008 SM and the 3G attach) are Tier 0 builds with no radio and no card.
They sit at R75/R76 because damage decides the order and neither changes what a
catcher can do until R25 exists or a 3G capture is in hand — the build is cheap,
the consequence is not reachable yet.

Then the €10–30 layer: R13, R12, R9, R62, R55, R22.

Then transmit, which is where the money is: R16/R17 (Tier 3–4), R19 (hardware),
R49/R50 (Tier 3), R60 (Tier 3).

## What changed in the re-sort

- The document was ordered by where the gap was found (README first, roadmap
  second). It is now ordered by **damage per unit of gear**, one queue R1–R74.
- The four README-gap sections and the eleven roadmap lanes survive as rows, not
  as sections; each row keeps its original wording and its class.
- The identity work that used to sit at A/B in the roadmap and in the README's
  SMS section now opens the document, because the state object in R1 is what
  everything else waits on. `L1a` is no longer its own entry: it **is** R1, and
  the row says so.
- The Part 3 intersection table now carries ranks instead of lane letters, so a
  closed gap and an open entry can be read in one pass.
- **Appended after the first sort**: Block 8 (R75–R80), the 3G/UTRAN messages and
  objects the tree does not have. They were found by working the 3G surface
  against the code rather than against a roadmap, and they take new numbers so
  the existing queue does not move.

## Gating removed (0.86.0)

No module has an approval gate. Deleted: `--i-have-a-lab-and-authorisation`
(30, 33), `--ack-isolated-lab` (57), `JAMD_LAB_AUTHORISED` (33), and the
`*_ARMED` family (`LTE_ARMED` 11, `NR_ARMED` 13, `MAP_ARMED` 26,
`FEMT_S1_ARMED` 37, `SBA_ARMED` 40, `BEXP_TX_ARMED` 54, `NRJ_TX_ARMED` 55).
Each is accepted and ignored. What remains is hardware and answer: the module
asks the driver whether a radio is present, and a fake radio still produces no
transmission. `00_deps --preflight` prints radio, driver, tx capability,
captures, and `gates none` in one page.
