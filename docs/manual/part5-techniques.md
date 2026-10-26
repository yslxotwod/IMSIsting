# Part 5 — Technique reference

Part 4 told you what exists. This part tells you how to do it: one page per
distinct attack and per distinct passive analysis, numbered by family. The
numbering is stable, so a page can be cited as §5.2.3 from anywhere in the
manual.

Two rules hold for every page here.

**A page describes a technique, not a module.** Where one module owns several
techniques it appears on several pages; where one technique spans modules (a
capture decoded by one module and scored by another) the page names both. The
modules themselves are catalogued in Part 4 and are only mentioned here to say
which verb to type.

**Every page states what the technique needs.** Three need-levels recur:

| Need | Meaning |
|---|---|
| **nothing** | Runs on any machine, no radio, no capture. Most of the analysis in this toolkit is like this. |
| **a capture** | Needs a pcap of GSMTAP, NAS or SIP traffic — from `03_gsmtap`, from a fleet node, or from someone else's network. |
| **a radio** | Needs a transmitting or receiving SDR this machine can key. Every such verb refuses with a stated `WHY` when it cannot, and `05_field_kit --guard-check` proves that refusal. |

The three exploit-kit modules (`20_gsm_cve`, `21_lte_cve`, `22_nr_cve`) are
covered at kit level, one page each, in §5.10 — never one page per CVE, because
a CVE is not a technique: it is one message shape inside a kit whose reach
depends on a testbed this toolkit does not ship.

---

## 5.1 Reading the air without touching it

Everything in this family is passive. Nothing here transmits, nothing here
associates, and every one of these techniques is legal to run against a network
you are authorised to observe. A receiver that never keys a transmitter is the
only instrument in this toolkit that cannot be detected as an instrument.

### 5.1.1 Decode a broadcast channel

*Need: nothing.* Every cell tells you, in the clear, before it knows who you
are: which operator it belongs to, which tracking area it is in, which cell it
is, what it will let you do, and what its neighbours are. That broadcast is the
one part of the network that never has to be attacked — only read.

GSM first, because its broadcast is the most explicit:

```bash
modules/06_gsm_air.sh --decode-si 15061b000162f2100000
# message  SI3 / cell_id 1 / mcc 262 / mnc 01 / lac 0 ...
```

The hex is an L2 BCCH block: a pseudo-length octet, the protocol discriminator,
the RR message type, then the fields. `--decode-si` names the message it finds
rather than assuming one, so the same command reads SI1 through SI13.

LTE and 5G put the same information behind ASN.1 rather than a fixed layout:

```bash
modules/10_lte_air.sh --decode-mib  <24-bit hex>   # bandwidth, PHICH, SFN
modules/10_lte_air.sh --decode-sib  <hex>          # PLMN list, TAC, cell id, barring
modules/12_nr_air.sh --decode-mib  <hex>           # 5G MIB: SCS, SFN, subCarrierSpacingCommon
modules/12_nr_air.sh --decode-sib1 <hex>           # 5G SIB1: PLMN, TAC, cellIdentity, slices
modules/08_umts_air.sh --decode-sib <hex>          # UMTS SIB blob, field map via --sib-fields
```

*What you read:* the operator identity (MCC/MNC), the tracking area, the cell
identity and — the part that matters for everything else in this manual —
whether the cell is barred, whether it permits emergency calls only, and which
ciphering and integrity algorithms it advertises support for. A cell that
advertises A5/0 or NEA0 is telling you it will not encrypt, which makes every
technique in §5.1.5 free.

*When it refuses:* the decoder refuses a block whose length does not match its
own framing, with a stated reason. A `--decode-si` that answers "no field map
for message type 0x00" means the message type is real but this decoder has no
named layout for it — not that the block is invalid. `modules/06_gsm_air.sh`
and `tools/gsm_mod.py` are the referees; `tools/check-gsm-si.sh` proves the four
SI layouts against tshark and pycrate on every gate run.

*Build rather than read:* `10_lte_air.sh --build-sib1` and `15_downgrade.sh
--build-sib1` construct the same message from arguments, which is what you want
when you are the one broadcasting (§5.3.1).

*Read next:* §5.1.2 to turn a receiver into a capture, then §5.2 for what a
catcher does with the identity the broadcast just published.

### 5.1.2 Capture the air and decode it into a store

*Need: a radio, then nothing.*

```bash
modules/03_gsmtap.sh --listen 60 captures/gsm-2024-06-01.pcap   # 60 s from UDP 4729
modules/03_gsmtap.sh --read   captures/gsm-2024-06-01.pcap      # decode into the store
modules/03_gsmtap.sh --decode-tsv | head                        # what it decoded
modules/03_gsmtap.sh --identities-tsv                           # identities seen in the clear
```

`--listen` binds UDP 4729 and writes a pcap; it needs something else — a
gr-gsm, srsRAN or osmocom flowgraph — actually feeding that port, which is why
it reports what it is listening to and how long for. `--read` is the half that
matters afterwards: it walks a GSMTAP capture, decodes each message, and appends
to `loot/gsmtap/decoded.tsv`, which is the store half a dozen other modules
read. A capture decoded twice does not double-count.

The store is the substrate for everything capture-driven in this manual:
`18_imsi_exposure`, `28_paging_track`, `29_mac_layer`, `32_nas_signaling` and
the catcher progress tables all read either this store or the raw pcap.

*What you read:* one row per message, with channel, uplink/downlink direction,
message type, the payload hex and the capture timestamp. Direction is the column
people skip: an identity in the downlink is the network asking, in the uplink is
the handset answering, and only the second one is exposure.

*When it refuses:* with no capture file it says so and exits 1. With a capture
that contains no GSMTAP (an ordinary IP capture, say) `--read` reports zero
frames rather than inventing rows.

*Referees:* `17_pcap_analysis.sh --summary` (independent header check) and
`17_pcap_analysis.sh --hierarchy`. `--build-sample out.pcap` writes a small
synthetic capture when you want to test a verb with no radio at all.

*Read next:* §5.1.5, which is what you do with the store once it exists.

### 5.1.3 Paging arithmetic

*Need: nothing.* Paging is the network's way of calling a handset that is
otherwise silent, and it is the only moment an idle phone must listen. If you
can predict *when* it must listen, you can be listening then — and if you can
predict it from an IMSI, an IMSI you already have is a tracking instrument.

```bash
# GSM: paging group from an IMSI and the cell's BS_PA_MFRMS
modules/06_gsm_air.sh --paging-group 310150123456789 2

# LTE: UE_ID = IMSI mod 1024, so pass the UE_ID, not the IMSI
modules/28_paging_track.sh --po 789 64 lte
# generation lte / pf_sfn 21 / po_subframe 9 / duplex fdd

# NR: same arithmetic with a PF_offset
modules/28_paging_track.sh --po 789 64 nr
```

That the LTE branch wants `789` and not the full IMSI is deliberate: the module
will not guess which modulo you meant, and a full IMSI is not a UE_ID. It
refuses with an out-of-range error rather than quietly reducing it, because a
silently reduced identity produces a wrong paging frame that looks like an
answer.

`10_lte_air.sh --paging-frame <imsi> <tac> <ue-id>` goes further and takes the
TAC and any eDRX configuration, producing the hyperframe and paging time window
as well as PF/PO.

*What you read:* the paging frame (an SFN), the subframe inside it, and for GSM
the paging block and CCCH group. Those three numbers are the whole result: with
them, a receiver that decodes only that one block has spent less than 1% of the
airtime of a receiver that decodes continuously.

*When it refuses:* non-numeric or out-of-range identities, a T that is not one
of 32/64/128/256, an nB that is not a legal fraction of T, a duplex mode that is
neither `fdd` nor `tdd`.

*Read next:* §5.7.3, which is what this arithmetic is for when it is used
against one subscriber rather than for scheduling a receiver.

### 5.1.4 Audit the cipher posture of the air

*Need: nothing for the tables; a capture for the session view.*

The interesting question about ciphering is never "is it encrypted" — it is
"which algorithm did this session negotiate, and was that the best either side
could do". Those are different questions and only the second one is an audit.

```bash
modules/19_cipher_audit.sh --table gsm          # every algorithm, with 3GPP refs and standing
modules/19_cipher_audit.sh --table 5g
modules/06_gsm_air.sh     --cipher-audit 35     # classify a Cipher Mode Command octet
modules/19_cipher_audit.sh --parse-smc <hex>    # what an SMC actually negotiated
modules/19_cipher_audit.sh --score lte EEA2 EIA2
modules/19_cipher_audit.sh --downgrade-check    # find downgrades in the session store
```

The table is the part worth reading once: it carries, per algorithm, the clause
that defines it and its *standing* — `null`, `broken`, `weak`, `ok` — with the
reason. A5/0 is `null`; A5/1 and A5/2 are `broken` with the attacks that broke
them named; A5/3 is `weak` because KASUMI's structural weaknesses survive a
nominal 64-bit key; A5/4 is `ok` because the longer key removes the practical
recovery. "Weak" and "broken" are not synonyms and the table does not treat them
as such.

`--score` turns a negotiated pair into a verdict about the session, and
`--downgrade-check` looks for the case that matters: a session that negotiated
something worse than both ends advertised they could do.

*What you read:* for a session, the negotiated pair and whether it is a
downgrade; for a cell, whether its advertised set includes a null algorithm.
A5/1 keystream is available as a known-answer instrument:
`06_gsm_air.sh --a5-1-keystream <kc> <bits> <frame>` prints the keystream the
algorithm produces, which is what you compare a recovered keystream against.

*When it refuses:* a `--parse-smc` shorter than a Security Mode Command is
refused by length with the byte count it got, rather than decoded into
nonsense.

*Read next:* §5.3.3 for forcing a downgrade rather than observing one, and
§5.2.1 for why a catcher cares.

### 5.1.5 Find where an IMSI crosses the air in the clear

*Need: a capture.* This is the single most consequential passive analysis in the
toolkit, because it converts a passive capture into a persistent subscriber
identifier without transmitting anything.

```bash
modules/06_gsm_air.sh --imsi-exposure-tsv          # where, in one store, an IMSI is readable
modules/06_gsm_air.sh --identity-exposure <hex>    # one Um message -> identity, type, exposure
modules/18_imsi_exposure.sh --audit <pcap|tsv>     # harvest and correlate
modules/18_imsi_exposure.sh --map                  # TMSI/GUTI -> IMSI with the evidence
modules/18_imsi_exposure.sh --subscribers-tsv      # one row per subscriber, with the score
modules/18_imsi_exposure.sh --marlin <tsv>         # identity-exposure ratio (the NDSS '25 detector)
```

`--audit` accepts several inputs and correlates across them, which is the whole
point: a TMSI is only pseudonymous until the same capture (or a second one)
contains the moment the network handed it out alongside a permanent identity.
`--cross` answers the question that makes a capture archive dangerous — the same
IMSI appearing in captures taken at different times and places.

*What you read:* one finding per exposure with the reason it counts, and a
per-subscriber score that separates "identified" from "merely seen". The
`--map` verb prints the binding with its evidence, so a mapping you cannot
justify is visibly unjustified.

*When it refuses:* an input that is neither a pcap nor a TSV store; an empty
store, which reports zero findings rather than a clean bill of health.

*Read next:* §5.2.6, which is the same exposure ratio used in the other
direction — to detect a catcher rather than to be one.

### 5.1.6 Survey the cell layer

*Need: a radio (or a capture).* Which cells exist here, from which operator, on
which frequencies, and where are they.

```bash
modules/02_cell_recon.sh --scan lte 20        # one pass, band 20
modules/02_cell_recon.sh --scan gsm
modules/02_cell_recon.sh --list-tsv           # surveyed cells
modules/02_cell_recon.sh --plmn 310-260       # operator and country for a PLMN
modules/02_cell_recon.sh --arfcn lte 6300     # EARFCN -> downlink MHz

modules/04_tower_map.sh --survey lte 20       # same pass, one point per cell, with a position
modules/04_tower_map.sh --history             # points with and without a fix, distinct cells
modules/04_tower_map.sh --export-kml          # a file a map program can open
```

The two modules are deliberately separate: `02_cell_recon` answers "what is
there", `04_tower_map` answers "where is it". `04` records a point only when it
has a position, and its `--history` line says how many points it could *not*
place — a survey with no fix log is a survey whose map is a guess.

*What you read:* per cell, the RAT, the ARFCN/EARFCN, the PLMN, the physical
cell id and the received power. The interesting anomaly is a cell that is loud
and unlisted: an operator's own cells appear in its own neighbour lists.

*When it refuses:* with no LTE scanner installed, `--scan lte` says which tool it
wanted (`srsran`/`cell_search`) and exits failing. With no GPS, `04_tower_map`
warns that points will be recorded without a position rather than silently
recording them at zero.

*Read next:* §5.3.1, which takes this survey as its input.

---

## 5.2 Being the network: catchers

The techniques in this family all share one trick: present a cell that is more
attractive than the real one, so a handset talks to you instead of to its
operator. That is the definition of an IMSI catcher, and everything in this
section is a variation on it — a different generation, a different field of the
protocol, or a different point at which you stop.

These need a radio and they transmit. Every one of them is detectable
(§5.2.6 describes the detectors), and none of them should be pointed at a
network you do not own or have written permission to test.

### 5.2.1 Run a GSM catcher sequence

*Need: a radio.* The 2G catcher is not one message, it is fourteen: a handset
has to be told about the cell, told to camp, told to identify itself, and then
told that its identity was accepted. Getting any of the middle steps wrong
leaves a session that a handset abandons.

```bash
modules/07_gsm_attack.sh --imsi-catcher-sequence        # the fourteen steps, in order
modules/07_gsm_attack.sh --plan acme                    # write the plan for this run
modules/07_gsm_attack.sh --plan-tsv                     # the plan as a table
```

The plan is the artefact to read before transmitting, because it names, per
step, the channel, the direction, the message and the message type:

```text
step channel direction message                        protocol message_type
1    BCCH    downlink  SYSTEM INFORMATION TYPE 1      RR       0x19
6    RACH    uplink    CHANNEL REQUEST                -        -
8    PCH     downlink  PAGING REQUEST TYPE 1          RR       0x21
11   SDCCH   downlink  IDENTITY REQUEST               MM       0x18
12   SDCCH   uplink    IDENTITY RESPONSE              MM       0x19
```

Each step has a builder, so a wrong octet can be fixed at the source rather
than in a capture:

```bash
modules/07_gsm_attack.sh --build-identity-request 310150123456789
modules/07_gsm_attack.sh --build-immediate-assignment
modules/07_gsm_attack.sh --build-paging-request
modules/07_gsm_attack.sh --build-lu-accept
modules/07_gsm_attack.sh --build-tmsi-realloc 0x4a3f1c22
modules/07_gsm_attack.sh --build-cipher-mode A5/1
```

Every builder prints hex that the toolkit's own decoder accepts, and the four
System Information builders are refereed against tshark and pycrate by
`tools/check-gsm-si.sh` — so the frames this module transmits are the frames
the standard describes, not frames this toolkit invented. That referee exists
because they were once wrong: the LAPDm length indicator used a shift of three
instead of two, and the identity request carried the wrong protocol
discriminator, which Wireshark reported as `SYSTEM INFORMATION TYPE 5bis`.

*What you read:* the plan first, then the run. The plan is what a reviewer
signs off; the run is what the handset did with it, and §5.2.2 is where the two
are compared.

*When it refuses:* every transmitting verb asks `05_field_kit --guard-check`
first and refuses with the reason when there is no keyed radio, no isolated lab
acknowledgement, or no compliance gate. The refusal is the feature.

*Read next:* §5.1.3 for the paging arithmetic this sequence depends on, and
§5.4.1 for what a TMSI reallocation is worth.

### 5.2.2 Observe what a catcher actually got

*Need: a capture, or a radio.* A catcher that says "I got 34 IMSIs" is a
catcher making a claim. The claim is checkable: every step that succeeded has a
message on the air, and every step that did not has an absence.

```bash
modules/07_gsm_attack.sh --catcher-run-start field-1
modules/07_gsm_attack.sh --catcher-watch captures/catcher.pcap --run field-1
# run field-1 / frames 379 / decoded 5 / steps_seen 5 / steps_total 14 / store loot/gsm_attack/catcher.tsv

modules/07_gsm_attack.sh --catcher-progress-tsv --run field-1
modules/07_gsm_attack.sh --catcher-observations-tsv --run field-1 --limit 20
modules/07_gsm_attack.sh --catcher-run-stop
```

`--catcher-watch` delegates the pcap to `03_gsmtap --read` (GSMTAP stays one
parser), then decodes each message against the plan's own numbering — it asks
`--imsi-catcher-sequence` which step a type belongs to rather than keeping a
second copy of the table. The progress table is a left join, so a step nobody
observed appears as `unseen` with its timestamp column empty:

```text
step channel direction message                 state  first_seen             observations
3    BCCH    downlink  SYSTEM INFORMATION TYPE 3 seen   2024-06-01T10:42:19Z   1
9    SDCCH   uplink    PAGING RESPONSE           seen   2024-06-01T10:42:20Z   1
11   SDCCH   downlink  IDENTITY REQUEST          seen   ...                    1
12   SDCCH   uplink    IDENTITY RESPONSE         seen   ...                    1
13   SDCCH   downlink  CIPHERING MODE COMMAND    unseen -                      0
```

*What you read:* `seen` vs `unseen` per step, and the count of observations, so
a second response from the same handset is visible as `observations 2` rather
than as a new step. The GUI's `Catch feed` view redraws this same store every
two seconds while it is open (§3.3), which is how you watch a run instead of
interrogating it.

*When it refuses:* with nothing decodable it exits 1 with a note — the run is
not silently recorded as empty. A frame whose shape it cannot parse is counted
under `unshaped` rather than dropped, and an unnamed-but-legal message type is
counted under `unknown_type` rather than mislabelled.

*Read next:* §5.2.6 to check whether your own catcher was itself caught.

### 5.2.3 Drive a UMTS catcher

*Need: a radio.* 3G is the hardest generation to catch, because the handset
authenticates the network with AKA before it will send anything identifying,
and the ciphering and integrity keys come out of that exchange. The toolkit's
approach is to model the exchange honestly and say where it stops.

```bash
modules/08_umts_air.sh --catcher-model                 # the eight-step model
modules/08_umts_air.sh --catcher-identity              # where identity can be asked for
modules/08_umts_air.sh --catcher-auth                  # what an AKA exchange needs
modules/08_umts_air.sh --aka-flow                      # RAND/XRES/CK/IK through f1..f5
```

`--aka-flow` is the useful reference page in the whole module: it prints the
five functions, what each takes and returns, and which of them a catcher would
need to be able to invert — with the answer, for each, that no practical attack
is known. A catcher page that implied otherwise would be lying.

The message side is decoder-first, so you can build against frames you already
have:

```bash
modules/08_umts_air.sh --parse-rrc dl-ccch:300022468acf0002010001048c48d1...
modules/08_umts_air.sh --build-rrc-setup
modules/08_umts_air.sh --build-security-mode
modules/08_umts_air.sh --build-rrc-reject
modules/08_umts_air.sh --parse-security-mode <hex>
```

`--parse-rrc` classifies and walks; it exits 0 for a message it both classified
and walked, and separately for classified-but-not-walked, truncated and
malformed, so a script can tell "unknown to me" from "invalid". The classifier
is refereed against tshark by `tools/check-umts-rrc.sh` on every gate run.

*What you read:* for `--aka-flow`, which steps a passive capture can and cannot
show (the answer is in §5.2.4). For `--parse-rrc`, the message name, the CHOICE
branch it came from and the integrity check info if present.

*When it refuses:* a frame whose direction contradicts its channel family is
skipped rather than decoded — an UL-CCCH block carrying the downlink bit is not
a message, it is a bug in whatever wrote the capture.

*Read next:* §5.2.4, which is the same model with the observing done for you.

### 5.2.4 Observe a UMTS catcher without a radio

*Need: a capture.* The 3G observation layer exists because the interesting
question about a UMTS catcher is not "did it capture" but "which of the eight
steps did the air actually carry".

```bash
modules/08_umts_air.sh --catcher-run-start umts-1
modules/08_umts_air.sh --observe captures/umts.pcap --run umts-1
modules/08_umts_air.sh --observe --frame dl-dcch:1400060a003002 --run umts-1
modules/08_umts_air.sh --catcher-progress-tsv --run umts-1
modules/08_umts_air.sh --catcher-observations-tsv --run umts-1
```

The progress table has nine rows: the eight model steps plus `answer` (the
uplink direct transfer that carries the response). Three steps are marked
`unobservable` and the table says why — physical sync leaves nothing to record,
a broadcast proves the network sent it and not that a handset read it, and the
authentication request rides inside the same downlink direct transfer as
registration, which this module does not parse NAS out of. Those rows are the
honest part of the table: they are the ones a capture cannot settle, so a run
that shows seven of nine is not seven ninths of a success.

This module reads the pcap itself rather than going through
`03_gsmtap --read`, because the GSMTAP store does not keep the RRC sub-type
byte — and without it a DL-CCCH block and a UL-CCCH block are
indistinguishable, which are different top-level CHOICEs. Message parsing still
goes through `--parse-rrc`; only the framing is local.

*What you read:* the same shape as §5.2.2, with an `integrity` column that says
`none`, `not protected` or the MAC status. A catcher that got as far as ciphering
would show `protected` with a failing MAC, which is the signature of an
interception that guessed the key wrong.

*When it refuses:* a capture with no UMTS GSMTAP frames exits 1 and says the
capture was read but contained nothing it could classify.

*Read next:* §5.5.3, where the same RRC/NAS split matters for a handset.

### 5.2.5 Catch a 5G SUCI, and conceal one back

*Need: a capture, then nothing.* 5G was designed to make this family harder: the
subscription identifier a handset sends is a SUCI (Subscription Concealed
Identifier) instead of a SUPI (the IMSI), and no network — not even the one
serving the handset — is supposed to learn the permanent identity.

Two things follow, and they are different things.

*Catching a SUCI is easy.* It travels in the clear inside the NAS identity
response, so §5.2.4's methods work unchanged: a receiver that can read an RRC
identity response can read a 5G one.

*Turning a SUCI back into an IMSI is not.* By **home network** this manual means
the operator that issued the SIM — the HPLMN, the subscription's own network —
not the network the handset happens to be visiting. The handset conceals the
MSIN with that operator's **public** key using ECIES (TS 33.501 §6.12, profiles
A and B on Curve25519 and secp256r1), generating a fresh ephemeral key pair per
concealment. Only the matching **private** key can reverse it, and it lives in
the home network's SIDF (Subscription Identifier De-concealing Function). The
chain is handset → SUCI → visited network → home network's SIDF → SUPI, with the
visited network receiving authentication results keyed by the SUCI and never
seeing the IMSI. So a SUCI you catch is not a name you can compute your way out
of; it is a stable pseudonym — the same handset returns the same SUCI for the
same home key, which is why it still links sessions across days and cells even
though it does not say who the subscriber is.

The exceptions are the ones worth auditing for, and `--audit` exists for them: a
**null-scheme** SUCI (scheme 0) carries the MSIN in the clear and is an IMSI in a
wrapper, and a home key that is published or shared across operators conceals
nothing from anyone who has it.

```bash
# what a 5G catcher asks for, and what it would see
modules/58_suci_catcher.sh --catch                      # plan + the real frames, in hex
modules/58_suci_catcher.sh --build-cell
modules/58_suci_catcher.sh --build-nas
modules/58_suci_catcher.sh --build-rrc
modules/58_suci_catcher.sh --start                      # keyed run
modules/58_suci_catcher.sh --capture captures/suci.pcap # harvest SUCIs from a trace
modules/58_suci_catcher.sh --classify-capture captures/suci.pcap
modules/58_suci_catcher.sh --check-trace captures/suci.pcap
modules/58_suci_catcher.sh --status-tsv

# and the other direction: build, conceal, deconceal, with a home-network key
modules/14_suci.sh --hn-create acme                     # a test home network
modules/14_suci.sh --build-suci 0 1234567890        # scheme 0 (null), MSIN; MCC/MNC follow
modules/14_suci.sh --conceal <suci-hex> --hn acme
modules/14_suci.sh --deconceal <suci-hex> --hn acme
modules/14_suci.sh --verify-hnkey                       # prove the key pair is what it claims
modules/14_suci.sh --audit                              # which SUCIs are weak (null scheme, short MSIN)
```

`--catch` is the page to read first: it prints the plan path, then the actual
RRC and NAS frames the catcher would transmit — RRC setup complete, registration
request, identity request — as hex you can replay into a decoder. The identity
request is unprotected by design (TS 24.501 8.2.6), which is why the plan says so
next to it.

`14_suci.sh` owns the cryptanalysis side: ECIES with the home network's public
key to conceal, the private key to deconceal, and `--audit` for the weaker
cases — a null-scheme SUCI is an IMSI in a wrapper, and `--msin-decode` shows
why a short MSIN field is a small search space.

*What you read:* from `--classify-capture`, one row per SUCI with its scheme
output, its PLMN and its MSIN field; from `--audit`, the ones that are not
really concealed. From `--deconceal` with a key you own, the IMSI — and, if the
SUCI was concealed with a different home key, a stated refusal rather than
garbage.

*When it refuses:* a SUCI whose scheme output is the wrong length for its
elliptic curve; a deconceal without a matching private key; a `--capture` file
with no NAS identity response in it.

*Read next:* §5.3 is where the passive side ends and §5.3 begins — the same
cell, transmitting rather than listening.

### 5.2.6 Detect a catcher from the handset's side

*Need: a capture.* Everything above is one half of the field; this is the other
half, and it is the half a defensive engineer should read first.

```bash
modules/18_imsi_exposure.sh --marlin <tsv>       # identity-exposure ratio per cell
modules/06_gsm_air.sh --paging-group <imsi> 2    # is this cell paging in the right block
modules/28_paging_track.sh --detect <pcap>       # paging anomalies and a verdict
modules/28_paging_track.sh --adaptover-detect <pcap>
```

A catcher is detectable not by its power but by its *behaviour*: it asks for an
identity more often than a network needs to, it pages in the wrong block, it
never pages the phone that it just identified, and it does not hand out the
ciphering the network advertised. The identity-exposure ratio is the cleanest
single signal — a real network needs a permanent identity roughly once per
attach; a catcher needs it every time.

`--detect` and `--adaptover-detect` report named signals with counts and then a
verdict that states what it did *not* test. The published IMSI-catcher apps test
for a loud cell and nothing else; the module's own comment says so, and the
verdict repeats it, because "looks like a catcher" and "is a catcher" are
different sentences.

*What you read:* signals with evidence and a verdict bounded by what was
measured. A cell that fails one signal out of four is reported as exactly that.

*When it refuses:* an input that is not a pcap or a TSV store; an empty capture,
which reports zero observations rather than a clean verdict.

*Read next:* §4.13.4 for the window that draws these signals, and §5.3.1 for
what the attacker does next once a handset attaches.


## 5.3 Standing up a cell of your own

A catcher asks a question. A rogue cell changes the answer. Everything in this
family is a way of being a network the handset will believe — and every one of
them has the same cost: a real radio, a licence you do not have unless you are
in a shielded room or hold one, and a plan file you should read before you key
anything.

Two modules in this family are unusual in the toolkit because they are *honest
about being unfinished*: `57_evil_twin` and `60_overshadow` both have a
preflight that reports every remaining precondition rather than starting and
failing later.

### 5.3.1 The evil twin

*Need: a survey (§5.1.6) to clone, and a radio to radiate.*

```bash
modules/57_evil_twin.sh --prepare-lte loot/cell_recon/cells.tsv 3 --pci 42 --out loot/evil-twin
modules/57_evil_twin.sh --preflight-lte loot/evil-twin      # what the twin still needs
modules/57_evil_twin.sh --run-lte loot/evil-twin 120 --radiate --with-capture --iface lo
modules/57_evil_twin.sh --evidence-collect loot/evil-twin --rat lte --run twin-1
modules/57_evil_twin.sh --evidence-tsv --run twin-1
```

`--prepare-lte` reads one row of a survey and writes a configuration directory
in which every field is traceable to that row: the PLMN, the TAC, the cell
identity, the EARFCN. `--preflight-lte` is the interesting verb — it lists what
is missing (a core, a radio, a key) and refuses to start until each is
satisfied, which is the difference between a lab exercise and a failed
transmission.

`--evidence-collect` has the honesty property the whole module is built around:
each evidence row is marked `observed` or `advertised`. An `advertised` row is
what the twin *claims* (the PLMN it broadcasts, the EARFCN it sits on); an
`observed` row is what a real receiver or a real handset actually did (attached,
sent an IMSI, sent an IMEI). A run that produced six advertised rows and no
observed rows is a run where the twin radiated and nobody believed it.

*What you read:* the evidence table, with the confidence column deciding what
you may claim. The twin-feed window (§4.13.6) draws both kinds, with the
advertised rows visibly worn.

*When it refuses:* every verb needs a prepared directory and says which; a
missing radio is listed by `--preflight-*` rather than discovered at transmit
time.

*Read next:* §5.3.2 for what to do when the handset refuses to attach, and
§5.2.6 for how the same twins are detected.

### 5.3.2 Overshadowing and AdapOver

*Need: a radio, and a plan.* Overshadowing is the technique of making a
legitimate cell unreadable at the moment a message must be read, so that the
handset takes a signal you sent instead. It does not break ciphering; it removes
the message that would have told the handset to distrust you.

```bash
modules/60_overshadow.sh --info                 # what this module does and refuses to do
modules/60_overshadow.sh --needs                # bill of materials (b210, b205mini, x310, pluto)
modules/60_overshadow.sh --timing-budget        # receive instant to transmit instant vs 2 ms and CP
modules/60_overshadow.sh --power-budget         # required power and range for ul / dl modes
modules/60_overshadow.sh --subframe-map <tsv>   # which subframe and RBs carry which message
modules/60_overshadow.sh --plan <target>        # sample-indexed schedule
modules/60_overshadow.sh --collateral           # what breaks around the target
modules/60_overshadow.sh --detect <tsv>         # unscheduled TB, SIB change without paging, drift
```

`--timing-budget` and `--power-budget` are the two pages to read before believing
anybody's claim about this technique, including this module's. Overshadowing is
a deadline problem (the replacement must arrive inside a window measured in
microseconds) and a power problem (the replacement must be louder than the cell
it replaces at the handset, not at your antenna). Both verbs print the arithmetic
and the margin, and neither claims a plan will work — `--plan` produces a
schedule, and the module says in its own `--info` that it plans and does not
key.

`--collateral` is the honest part: a downlink overshadowing degrades the whole
cell, an uplink one degrades one grant. `--detect` is the defensive use of the
same knowledge: an unscheduled transport block, a SIB change without a paging
message, or a schedule that drifts are all evidence that somebody is doing this.

*What you read:* the budget pages for feasibility, the plan for a schedule, and
`--detect` for evidence.

*When it refuses:* `--needs` prints what hardware would work; every radiating
verb refuses with no radio.

*Read next:* §5.1.3, because paging timing is the mechanism this technique
disturbs, and §5.7.3 for its tracking variant.

### 5.3.3 Force a downgrade with a reject

*Need: nothing to build, a radio to radiate.* The cheapest downgrade is a
message the handset is required to believe: a reject with a cause code that
sends it somewhere the attacker controls.

```bash
modules/15_downgrade.sh --reject-cause 15 EMM           # what cause 15 means, from the spec table
modules/15_downgrade.sh --build-reject EMM 15 attach    # the NAS message to send
modules/15_downgrade.sh --tx-reject EMM 15 attach       # build it and put it on the air
modules/15_downgrade.sh --build-security-mode EEA0      # advertise no ciphering at all
modules/15_downgrade.sh --null-cipher-table             # A5-0/UEA0/EEA0/NEA0 across generations
modules/15_downgrade.sh --detect <pcap|records.tsv>     # find steering rejects in existing traffic
modules/15_downgrade.sh --path <name>                   # describe a downgrade mechanism
```

The cause table is worth knowing by heart if you work on the defensive side:
cause 15 ("No suitable cells in tracking area") steers a handset to another RAT,
cause 22 ("Congestion") makes it retry later, and the security-mode variants
propose a null algorithm. `--build-reject` produces the octets and `--tx-reject`
sends them; between the two there is no difference except the radio, which is
why the module separates them — you can prepare and inspect a message on a
machine with no hardware.

`--detect` is the reverse: it reads a capture or a procedure record and reports
steering rejects, RAT changes without cause, and security modes weaker than both
ends advertised.

*What you read:* the message and what a handset must do on receiving it;
`--detect` for the same pattern in traffic that already exists.

*When it refuses:* an unknown RAT string, a cause code outside the table, a
transmit with no radio.

*Read next:* §5.1.4 for why a null cipher is the point of the exercise, and
§5.2.1 for the catcher that follows it.

### 5.3.4 A femtocell's own management plane

*Need: nothing to build a profile; a network path for the management verbs.*
Small cells are the highest-value rogue target in a real deployment, because
they are an operator-managed box on a consumer-grade network.

```bash
modules/37_femtocell.sh --csg-encode 12345678           # 27-bit CSG id
modules/37_femtocell.sh --cell-profile 310260 2 2500 1 # PLMN, band, EARFCN, PCI
modules/37_femtocell.sh --sib9 home-node-1             # the SIB that publishes the HNB name
modules/37_femtocell.sh --discover 10.0.0.5            # what answers on the management plane
modules/37_femtocell.sh --apply 10.0.0.5               # write the profile to it
```

`--cell-profile` emits the whole commissioning profile — PLMN, band, EARFCN,
PCI, optional CSG identity and HNB name — which is the document a small cell
takes as its identity. `--discover` then asks what management surface answers,
and `--apply` writes the profile to a discovered surface. The two network verbs
are separated from the profile verbs for a reason: building a profile is offline
and safe, applying one is a change to somebody's infrastructure.

*What you read:* the profile as structured data, and for a live box what it
claims about itself. The SIB9 name is often the give-away in a survey: it is
whatever the installer typed.

*When it refuses:* a PLMN that is not 5 or 6 digits (a normalised `310-260` is
refused; the verb wants `310260`), a CSG id outside 27 bits, an unreachable
management host.

*Read next:* §5.1.1 for the broadcast a small cell sends, and §4.13.5 for the
live subscriber window the same module feeds.

### 5.3.5 A rogue cell at the message layer

*Need: nothing.* Two modules build the messages a rogue cell sends without
building the cell: this is the part of the work that can be done entirely on a
laptop, and the part that is worth doing before touching a radio.

```bash
modules/54_baseband_exploit.sh --forge-reg-accept           # 5G Registration Accept, plaintext
modules/54_baseband_exploit.sh --forge-reg-reject 31        # reject with a redirect cause
modules/54_baseband_exploit.sh --forge-identity 1           # identity request by type
modules/54_baseband_exploit.sh --cp-check <hex>             # control-plane property check
modules/55_nr_inject.sh --mac-pdu 1 4142434445              # a MAC-NR PDU with a chosen LCID
modules/55_nr_inject.sh --dci-parse <hex> 1_1 106           # decode a DCI against a bandwidth
```

The reason to separate these from §5.3.1 is that the *message* is the part that
carries the finding. A Registration Accept in the clear is a protocol-level
claim about what a core will accept; a MAC PDU with an LCID the scheduler never
grants is a claim about what the receiver does with it. Neither needs a
transmitter to be worth writing down, and both are refereed by their modules'
selftests.

*What you read:* the octets plus the field-by-field construction
(`--l2-build <name>` shows how one malformed case is assembled, `--l2-case
<layer>` selects a layer). `--cp-check` reports which control-plane properties a
given NAS message violates.

*When it refuses:* `--l2-case` with an unknown layer name lists the layers it
knows; `--dci-parse` with a format it cannot size refuses rather than guessing
the bandwidth.

*Read next:* §5.10.2 and §5.10.3, which are the same message-level work
organised as a corpus.

---

## 5.4 What the core says about a subscriber

The air is only half of a mobile network. The other half is a set of protocols
that were designed in an era when the only people who could reach them were
carriers, and most of them still behave that way. Every technique in this family
runs on a laptop, none of them needs a radio, and all of them need something
you cannot get from a manual: an address, a port, a credential, or a lawful
reason.

The toolkit's position on all of them is the same — it builds and parses the
messages and does not send them at a network it was not pointed at. The verbs
that would open a socket are marked as such in Part 4 and refuse without an
explicit target.

### 5.4.1 Ask a core about a subscriber over S6a

*Need: nothing for the messages; a reachable core for an answer.* Diameter S6a
is the interface between an MME and a home subscriber server, and four of its
requests are enough to learn almost everything about a subscriber.

```bash
modules/11_lte_core.sh --build-air 310150123456789            # Authentication-Information-Request
modules/11_lte_core.sh --build-ulr 310150123456789            # Update-Location-Request
modules/11_lte_core.sh --build-clr 310150123456789            # Cancel-Location-Request (317)
modules/11_lte_core.sh --decode-diameter <hex>                # walk a Diameter message and its AVPs
modules/11_lte_core.sh --decode-gtp-c <hex>                   # GTP-C v2 header and IEs
modules/11_lte_core.sh --gtp-csr-forge 310150123456789 internet 310 260
```

`--build-air` produces the Authentication-Information-Request an MME would send:
the IMSI, the number of vectors, the serving network. `--build-clr` produces the
Cancel-Location-Request, which is the interesting one defensively, because it is
how a subscriber gets detached from a network they are actually attached to.
`--decode-diameter` and `--decode-gtp-*` are the read direction: they name every
AVP, its vendor and its type, so a captured message is legible without a
protocol analyser licence.

*What you read:* for a built message, the command code, application id and every
AVP; for a decoded one, the same in the other direction, with the fields that
carry the subscriber identity called out.

*When it refuses:* a malformed Diameter header is refused by length; a hex
string that is not GTP-C v2 is refused with the version it found.

*Read next:* §5.4.2 for the SS7 equivalent, which is older and still carries the
same question.

### 5.4.2 Anywhere lookups over SS7 and MAP

*Need: nothing for the messages; an SS7 network you are authorised to touch.*
Mobile Application Part is how a network asks "where is this subscriber" — and
the reason SS7 is still a finding in 2024 is that the question has no
authentication behind it.

```bash
modules/26_ss7_map.sh --build-sri 15551234567            # SendRoutingInfo, wire-ready MSU
modules/26_ss7_map.sh --build-sri-sm 15551234567         # the SMS variant
modules/26_ss7_map.sh --decode-map <hex>                 # decode MAP, unwrapping MSU or SCCP
modules/26_ss7_map.sh --decode-tcap <hex>                # the transaction and its components
modules/26_ss7_map.sh --decode-msu <hex>                 # MTP3 and SCCP underneath
modules/26_ss7_map.sh --dialogue <req> <ans>             # pair a request with what a peer sent back
modules/26_ss7_map.sh --build-response <kind>            # the peer's side, for a lab
```

`--dialogue` is the verb that makes this module teach rather than merely encode:
it takes the request you built and the answer you captured and reports whether
the pair is consistent — the opcode matches, the invoke ids line up, the answer
is to *that* question. That comparison is also what tells you whether you are
looking at a real answer or at a lab fixture.

`--build-response` exists so both sides of a dialogue can be produced offline,
which is what a lab needs and what a manual about attacks should demonstrate
without a live SS7 link.

*What you read:* the operation (SRI, SRI-SM, PSI, ATI), the identity it carries,
and for a response the routing information the network was willing to give.

*When it refuses:* an MSISDN that will not encode (a 15-digit IMSI is not an
MSISDN — the verb says `cannot encode MSISDN` and prints what it got).

*Read next:* §5.9.3 for the lawful-intercept interfaces that sit on the same
network, and §5.10.1 for the kit that catalogues GSM-side SS7 exposure.

### 5.4.3 The 5G service-based architecture and its NRF

*Need: nothing for the messages and paths; network reachability for discovery.*
The 5G core replaced point-to-point interfaces with an HTTP/2 service mesh, in
which the NRF is a directory of every function in the core.

```bash
modules/13_nr_core.sh --nf-list                        # every NF with its real API root
modules/13_nr_core.sh --nf-discovery AMF              # what an NRF would return
modules/13_nr_core.sh --decode-ngap <hex>             # NGAP procedure and name
modules/13_nr_core.sh --decode-pfcp <hex>             # PFCP message type, SEID, sequence
modules/13_nr_core.sh --decode-5g-guti <hex>          # PLMN, AMF region/set/pointer, 5G-TMSI

modules/40_sba_pivot.sh --nrf amf                     # the NRF discovery request itself
modules/40_sba_pivot.sh --nf-paths                    # SBI service paths
modules/40_sba_pivot.sh --hpack <hex>                 # decode HPACK header blocks
modules/40_sba_pivot.sh --h2-parse <hex>              # HTTP/2 frame header
modules/40_sba_pivot.sh --settings <hex>              # SETTINGS payload
```

The reason this is one family and not five pages is that the attack surface is a
single shopping list: an NRF that answers unauthenticated discovery is a map of
the core, and every NF in that map speaks HTTP/2 with HPACK-compressed headers
that most capture tools display as binary. `40_sba_pivot` reads that layer
directly, which is what makes a captured SBI exchange legible.

*What you read:* the NF types present, their API roots, and — the important
part — whether the discovery answer was conditional on the requester's identity.
A `target-nf-type=amf` request that returns every AMF is a finding; one that
returns nothing without credentials is the control working.

*When it refuses:* an unknown NF name (the verb wants a registered type such as
`AMF`, `SMF`, `NRF`, or a service name); an HTTP/2 frame shorter than nine
octets.

*Read next:* §5.4.5 for what the slice identifiers in these messages mean, and
§5.10.3 for the kit that catalogues SBA exposure.

### 5.4.4 Cellular DNS and the aLTEr lever

*Need: a capture.* In an LTE network, DNS is the only plaintext application
traffic the user plane carries by default, and the reason that matters is
narrow: an attacker who can rewrite a DNS answer can redirect the user to their
own server without breaking any cipher.

```bash
modules/27_cellular_dns.sh --build-query example.com A
modules/27_cellular_dns.sh --decode-dns <hex>
modules/27_cellular_dns.sh --resolver-discovery captures/lte.pcap   # which resolver the bearer used
modules/27_cellular_dns.sh --detect captures/lte.pcap               # rewrite and spoofing signals
modules/27_cellular_dns.sh --alter                                   # the aLTEr sequence, step by step
modules/27_cellular_dns.sh --pco <hex>                               # walk protocol configuration options
```

`--alter` walks the published aLTEr sequence and, more usefully, states its
preconditions: user-plane integrity protection is not enabled in LTE, DNS is
unprotected, and the attacker must be able to rewrite a packet in flight while
leaving the cipher's counters consistent. `--detect` looks for the artefacts
that sequence leaves — answers that differ from a second vantage point, TTLs that
do not fit the resolver's pattern, a response whose size contradicts its
question.

*What you read:* the resolver the bearer actually used (it is often not the one
the operator documents), and for an altered exchange, which of the signals
fired.

*When it refuses:* a DNS message with a truncated name or a compression pointer
that loops; a pcap with no DNS at all reports zero exchanges.

*Read next:* §5.9.4 for the integrity gap under this technique, and §5.6.2 for
the voice equivalent.

### 5.4.5 Slice selection

*Need: nothing.* Network slicing is sold as isolation, and the question a
security review asks is whether selection actually enforces it.

```bash
modules/34_slicing.sh --sst-table                 # standardised SST values, with sources
modules/34_slicing.sh --encode-s-nssai 1          # S-NSSAI octets for a slice
modules/34_slicing.sh --decode-s-nssai 01000001   # back again, with the SST name
modules/34_slicing.sh --selection 01 01,02        # requested / allowed / rejected outcome
modules/34_slicing.sh --isolation-check <pcap>    # isolation evidence, and what it cannot show
modules/34_slicing.sh --detect <slice-events.tsv> # session-level slice anomaly rules
```

`--selection` is the verb worth reading: given what a handset requests and what
the network allows, it computes which slice the session lands in and why —
including the case where a rejected slice falls back to a default one, which is
the failure mode that turns isolation into a label. `--isolation-check` is
deliberately bounded: it reports evidence of shared resources and states plainly
that absence of evidence in one capture is not isolation.

*What you read:* the SST/SD pair, its standardised meaning, and the selection
outcome; for a capture, which slices appear on which bearers.

*When it refuses:* an S-NSSAI whose declared length is not 1 or 4 (TS 24.501),
an SST outside the standardised table reported as `unknown` rather than guessed.

*Read next:* §5.4.3, where slices are requested in the first place, and §5.10.3
for the slicing findings in the 5G kit.

### 5.4.6 NAS at scale

*Need: a capture.* One NAS message is an event. Ten thousand of them is a
posture: which procedures a network actually runs, which causes it returns, and
whether it is under load.

```bash
modules/32_nas_signaling.sh --rate <pcap>             # messages per second and per procedure
modules/32_nas_signaling.sh --procedure-mix <pcap>    # distribution, and the reject share
modules/32_nas_signaling.sh --causes <pcap>           # cause-code distribution
modules/32_nas_signaling.sh --storm-profile <pcap>    # signalling-storm detection
modules/32_nas_signaling.sh --decode-nas eps <hex>    # one message, header and cause
modules/32_nas_signaling.sh --build-nas 5gs registration-request
modules/32_nas_signaling.sh --cost-model              # documented cost of each load pattern
```

The reject share is the single most informative number: a network whose attach
attempts are 40% rejected is either misconfigured or being steered, and the
cause distribution usually says which. `--cost-model` exists so that a load
figure can be quoted with the resource it consumes rather than as a bare rate.

*What you read:* rates, mixes, causes, and a storm verdict with the thresholds
that produced it.

*When it refuses:* a capture with no NAS (an empty user-plane capture, say)
reports zero messages rather than a zero rate that looks like health.

*Read next:* §4.13's windows for the live view of the same counters, and §5.6.1
for the attach procedure these messages belong to.

---

## 5.5 The SIM and the handset

The SIM is the one part of the system that is supposed to be a safe. Everything
in this family is either reading it, writing to it through the over-the-air
channel, or detecting that somebody else has moved it.

### 5.5.1 Read a USIM

*Need: a reader (or nothing, for the codec layer).* Nearly every technique that
needs a credential starts with the same three commands: select a file, read it,
decode it.

```bash
modules/16_sim.sh --file-id 6f07                       # what file this id is
modules/16_sim.sh --select-fid 6f07                    # the SELECT APDU (A0 A4 00 00 02 6F07)
modules/16_sim.sh --read-binary 0 10                   # READ BINARY
modules/16_sim.sh --read-record 1 04                   # READ RECORD, absolute mode
modules/16_sim.sh --get-response 10                    # GET RESPONSE
modules/16_sim.sh --decode-iccid 89012604201000000010  # EF_ICCID -> ICCID, Luhn checked
modules/16_sim.sh --parse-apdu <hex>                   # command or response, in either direction
```

The APDU verbs are pure codecs: they produce the bytes and do not touch a card,
which is why they work with no reader attached. `--decode-iccid` is the useful
demonstration of why a codec beats a hex editor — ICCID is nibble-swapped BCD
with a Luhn check digit, and reading it wrong is how a lab ends up with two
labels for one card.

*What you read:* the APDU case (1, 2, 3 or 4), the file identity and size, and
for a decoded record the field layout. `--status-tsv` reports whether a reader
and `pcscd` are present, so a failed read is attributable.

*When it refuses:* a file id it has no name for is reported as unknown rather
than mapped to a guess; an APDU whose length fields contradict its data is
refused by length.

*Read next:* §5.5.2 for writing to the card over the air, and §5.5.4 for the
defensive side of the same files.

### 5.5.2 Over-the-air SMS and the SIM toolkit

*Need: nothing for the codecs; a network path and keys for a live delivery.*
OTA SMS is how an operator provisions a card without touching it — and therefore
how anyone who can forge an OTA SMS provisions a card without touching it.

```bash
modules/41_ota_sms.sh --spi-build 11 2 1                  # SPI: cipher, counter, PoR settings
modules/41_ota_sms.sh --packet 02 0000 1 <spi> 1 1 <data>  # one command packet
modules/41_ota_sms.sh --packet-sms 0000 1 <spi> 1 1 <apdu>  # the same over SMS-PP
modules/41_ota_sms.sh --parse-packet-sms <hex>           # decrypt it and check its CC
modules/41_ota_sms.sh --parse-resp-sms <hex>             # the card's Response Packet

modules/52_stk.sh --build <type> <qualifier>             # a proactive command
modules/52_stk.sh --parse <hex>                          # decode one
modules/52_stk.sh --audit <log>                          # flag silent off-device commands
modules/52_stk.sh --sat-cmds                             # the S@T command surface
```

The pairing is deliberate: `41` builds and reads the envelope (SPI, KIC, KID,
counter, ciphering), `52` builds and reads what is inside it (the proactive
command the card is told to run). `--audit` is the defensive verb — it flags
proactive commands that would send data off the device without the user seeing
anything, which is the signature of a card being used as an exfiltration
channel.

*What you read:* for a packet, the SPI and whether its counter is plausible;
for a proactive command, the type, the destination and whether it is silent.
`--spi` parses an SPI on its own and reports which parts of it are weak.

*When it refuses:* a packet whose CC (check) does not match; a counter that
repeats when the cipher is not a stream that tolerates it.

*Read next:* §5.5.4 for what a subscriber can do about a card that has already
been written to.

### 5.5.3 USSD and MMI strings

*Need: nothing.* USSD is the only signalling channel that reaches a handset
without a data session, and MMI strings are the only interface a user has to
supplementary services.

```bash
modules/38_ussd.sh --pack 'hello'                # GSM 7-bit packing, with extension chars
modules/38_ussd.sh --unpack e8329bfd06           # back again
modules/38_ussd.sh --build 15 'hello'            # a USSD facility message
modules/38_ussd.sh --mmi '*#100#'                # parse an MMI string
modules/38_ussd.sh --ss-codes                     # supplementary-service reference
modules/38_ussd.sh --detect <payload>             # USSD/STK injection findings
modules/38_ussd.sh --plan                         # the lab handoff plan
```

Two things make this worth its own page. First, 7-bit packing is where most
home-grown USSD tools break on characters outside the default alphabet; the
extension table is implemented and asserted. Second, `--detect` reads a payload
looking for injection: USSD strings that are passed to a modem without escaping
are a command channel into the device.

*What you read:* the packed septets and the unpacked text; for `--mmi`, the
service code, the supplementary information and the SIA part; for `--detect`, the
specific construction it objects to.

*When it refuses:* a packed string whose declared septet count does not match its
length.

*Read next:* §5.5.2, since a USSD or STK payload is often the delivery vehicle.

### 5.5.4 Detect a port-out or a clone

*Need: history.* This is the defensive counterpart of everything else in the
manual: what a subscriber, or the operator watching for them, can actually check.

```bash
modules/31_sim_defense.sh --signals              # the six detection signals, with meaning
modules/31_sim_defense.sh --score <history-tsv>  # port-in-progress likelihood
modules/31_sim_defense.sh --pin-state            # PIN/PUK retry counters and the ADM key
modules/31_sim_defense.sh --ef-ad <hex>          # EF_AD in either layout
modules/31_sim_defense.sh --defence-checklist    # what a subscriber can enforce
modules/31_sim_defense.sh --esim-profile-parse <hex>
```

The six signals are the page: an IMSI pairing with a new IMEI, an OTA-SMS burst,
an authentication-failure streak, dual-network registration, and two more of the
same kind. Each is individually weak and collectively diagnostic, which is why
`--score` reports a likelihood with the signals that produced it rather than a
verdict. `--defence-checklist` is the only page in the manual that is a list of
things to turn on rather than things to try.

*What you read:* per signal, whether it fired and what it means in one sentence;
for `--score`, the likelihood and its inputs.

*When it refuses:* a history file that is not the expected TSV; an EF_AD hex
whose layout is ambiguous is reported in both layouts rather than one.

*Read next:* §5.5.1 for the files these signals concern, and §5.9.3 for the
interception side of a port.

---

## 5.6 Attaching, calling, and the services around them

These are the procedures a phone runs in its first two minutes on a network, and
the services an operator runs on top of them. All of it is offline work: parse a
capture, build a message, read what a network claims about itself.

### 5.6.1 Attach and the GUTI

*Need: a capture, or nothing for the codec.* A GUTI is the temporary identity a
network hands out so the permanent one need not cross the air — which is exactly
why binding a GUTI to an IMSI is the goal of half the passive work in §5.1.5.

```bash
modules/09_lte_attach.sh --decode-nas <hex>              # an EMM message and its IEs
modules/09_lte_attach.sh --setup-complete <nas_hex>      # what an ATTACH COMPLETE contained
modules/09_lte_attach.sh --guti-decode 080BF600F110123456DEADBEEF
# identity_type GUTI / plmn 001-01 / mme_group 4660 / mme_code 86 / m_tmsi 3735928559
modules/09_lte_attach.sh --guti-map <guti_hex> 001010000000001   # bind it, with evidence
modules/09_lte_attach.sh --guti-tsv                      # the bindings, attached count included
modules/09_lte_attach.sh --realloc-command <hex>         # a GUTI REALLOCATION COMMAND
modules/09_lte_attach.sh --nas-responder <file>          # hold attach state across a dialogue
```

`--guti-map` is the store write: one row per GUTI, with an attach count that
increments rather than appending a duplicate, so a GUTI seen five times is one
binding seen five times. `--realloc-command` matters because the network is
allowed to change the GUTI mid-session, and a mapping that ignores reallocation
silently pairs the wrong subscriber with the wrong temporary identity.

*What you read:* the PLMN, the MME group and code (which locate the subscriber at
network granularity before any timing analysis), the M-TMSI, and the binding's
evidence.

*When it refuses:* a hex string that is not an EPS mobile identity carrying a
GUTI is refused with the identity type it actually found — the commonest error
is passing the bare M-TMSI, which has no type octet.

*Read next:* §5.1.5 to turn a binding into a persistent identifier, and §5.7.1
for what the same attach tells you about location.

### 5.6.2 VoLTE, VoWiFi and the SIP edge

*Need: a capture for the parsing verbs; a target for the sending verbs.* Voice
over LTE carries SIP inside the user plane, and the SIP is protected by the same
cipher as everything else — except when it is not, and except when the operator
reuses a keystream.

```bash
modules/30_volte_ims.sh --sip-parse <hex>                # a SIP request or response
modules/30_volte_ims.sh --sip-build register             # build one
modules/30_volte_ims.sh --revolte-demo <pt1> <pt2>       # same-keystream XOR demonstration
modules/30_volte_ims.sh --keystream-recover <ct> <known> # recover the keystream, decrypt
modules/30_volte_ims.sh --imp4gt-model                   # the IMP4GT sequence and preconditions
modules/30_volte_ims.sh --sip-flood register 100 512 512 # flood / amplification model

modules/36_vowifi.sh --epdg 310 260                       # epdg.epc.mnc260.mcc310.pub.3gppnetwork.org
modules/36_vowifi.sh --eap-privacy                        # what a NAI reveals before auth
modules/36_vowifi.sh --dh <n>                             # is this key exchange acceptable
modules/36_vowifi.sh --transform <n>                      # IKEv2 transform names
```

`--revolte-demo` and `--keystream-recover` are the honest version of the ReVoLTE
finding: two calls that reuse a keystream XOR to a known value, and the module
demonstrates it on chosen inputs so you can see the mechanism rather than take
the paper's word for it. `--imp4gt-model` does the same for the identity-
pointer attack and, like §5.3.2, states its preconditions up front.

VoWiFi is the same voice service over a different transport, and `--epdg` shows
the one thing worth knowing before reading anything else: the ePDG name is
derivable from the PLMN alone, which is why the tunnel endpoint is not a secret.

*What you read:* for SIP, the method, headers and SDP (the SDP is where the
media endpoints are); for the ePDG, the FQDN and, via `--validate-cert`, whether
the certificate that answers it is the one that name should present.

*When it refuses:* `--dh` on a group RFC 8247 forbids reports the verdict rather
than the number; `--validate-cert` with no trust anchor says so instead of
returning "valid".

*Read next:* §5.4.4 for the plaintext lever underneath, and §5.9.4 for the
integrity gap both techniques depend on.

### 5.6.3 Shared RAN and PLMN leaks

*Need: nothing for the codec; a capture for the leak check.* A network built by
one operator and shared with another still broadcasts a PLMN list, and the
interesting question is whether the list is the whole story.

```bash
modules/43_ran_share.sh --plmn-encode 310 260       # 130062
modules/43_ran_share.sh --plmn-decode 130062
modules/43_ran_share.sh --eplmn '310-260,310-410'   # equivalent-PLMN list, cap 15
modules/43_ran_share.sh --mode mocn                  # sharing-mode classification
modules/43_ran_share.sh --leak-check <tsv>           # PLMN outside the broadcast set
modules/43_ran_share.sh --plan                       # two-core lab handoff plan
```

`--leak-check` is the whole point: it compares the PLMNs seen in signalling
against the PLMNs the cell broadcasts, and any PLMN in the first set that is not
in the second is a leak — either a misconfiguration or an interface nobody
documented. `--mode` classifies MOCN, MORAN and GWCN, which matters because the
three share different things and only one of them shares the cell identity.

*What you read:* the encoded PLMN, the effective list and its length limit, and
the leak findings with the message they came from.

*When it refuses:* a fifthteen-plus-one PLMN list, i.e. more than the 15 the
specification allows; a PLMN that is not 5 or 6 digits.

*Read next:* §5.1.1 for where the broadcast set comes from.

### 5.6.4 A carrier's API surface

*Need: the API's own specification or a capture; nothing for the analysis verbs.*
Every carrier now ships a self-service API, and the security review of one is a
checklist rather than an exploit.

```bash
modules/44_carrier_api.sh --openapi spec.json          # paths, servers, schemes
modules/44_carrier_api.sh --authz-matrix spec.json     # four-case test plan per operation
modules/44_carrier_api.sh --jwt-audit <token>          # alg=none, expiry, audience
modules/44_carrier_api.sh --token-bucket 10 20 100 60  # is the rate limit real
modules/44_carrier_api.sh --diff a.json b.json         # response differential between captures
modules/44_carrier_api.sh --stuffing conf.json         # credential-stuffing resistance controls
modules/44_carrier_api.sh --report                     # assessment skeleton
```

`--authz-matrix` is the valuable one: for each operation it lays out the four
cases that must all be tested — owner, other user, no token, expired token — and
the matrix is the finding when any cell behaves like the owner. `--jwt-audit`
checks the three failures that account for most real breaks: unsigned tokens
accepted, expiry not enforced, audience not checked.

*What you read:* the surface (paths, servers, security schemes) and per-operation
the authorisation cases with what a pass looks like.

*When it refuses:* a document that is not OpenAPI 3; a token that is not a JWT.

*Read next:* §5.9.3, since an API is one of the lawful-intercept surfaces the
same operator exposes.

---

## 5.7 Where the subscriber is

Location is the most consequential thing a mobile network knows about a person,
and every technique in this family derives it from something the network itself
has to measure. Three of the four are passive; the fourth forges the answer.

### 5.7.1 Timing advance geolocation

*Need: measurements.* Timing advance is the network telling a handset how late to
transmit because of how far away it is. That number is a range, and three ranges
meet at a point.

```bash
modules/39_ta_geoloc.sh --ta 10 lte          # 10 TA units -> 780.71 m, error bound 39.04 m
modules/39_ta_geoloc.sh --ta 10 nr
modules/39_ta_geoloc.sh --trilaterate anchors.tsv    # least-squares fix from x/y/range rows
modules/39_ta_geoloc.sh --cells cells.tsv            # ranges for a cell list
modules/39_ta_geoloc.sh --plan                       # measurement handoff plan
```

LTE's TA unit is 78.07 m of one-way range; NR's is finer. `--ta` prints the
range *and* the error bound, because a TA-derived position is a band, not a
point: quoting 780 m without ±39 m overstates the instrument. `--trilaterate`
takes anchors and ranges and solves for the intersection, with the residual
reported so a bad geometry is visible rather than silently producing a confident
wrong answer.

*What you read:* per measurement the range and its error, and for a fix the
least-squares solution plus residuals; the plan verb says which measurements a
real collection would need.

*When it refuses:* fewer than three anchors, anchors on one line (collinear
geometry has no unique solution), a RAT whose TA unit it does not know.

*Read next:* §5.7.2 for the position report the network would rather use, and
§5.1.6 for the cell coordinates these anchors come from.

### 5.7.2 Forging an LPP position

*Need: nothing to build; a capture to detect.* LPP is the protocol by which an
E-SMLC asks a handset where it is. A forged response is a handset that lies.

```bash
modules/46_lpp.sh --list-pids                     # LPP procedure codes
modules/46_lpp.sh --forge-position 51.5,-0.12     # a ProvideLocationInformation, built
# status built / pdu_hex D2020028410124FA51FFA8A0
modules/46_lpp.sh --parse-position <hex|file>
modules/46_lpp.sh --detect-forgery <pcap>         # what a forged report looks like
modules/46_lpp.sh --otdoa-assist                  # the assistance data an E-SMLC sends
modules/46_lpp.sh --decode-header <hex>
```

`--forge-position` produces a syntactically valid ProvideLocationInformation,
which is the point: the message is legal, and nothing in it is authenticated
against the device that produced it. `--detect-forgery` is the other half — it
looks for reports whose uncertainty, timing advance or cell measurements do not
fit the claimed position, which is the only way a network catches a lying
handset.

*What you read:* for a forged message, the PDU and its bit length; for detection,
the specific contradictions it found between claim and measurement.

*When it refuses:* coordinates outside the encodable range, a hex string that
fails the LPP header grammar.

*Read next:* §5.7.1, because the TA in the same attach is what catches the lie.

### 5.7.3 Paging-based tracking

*Need: a capture, and a lot of them.*

```bash
modules/28_paging_track.sh --torpedo-model <pcap>        # collision and response timing
modules/28_paging_track.sh --piercer-correlate <cands> <pcap> [mfrms]
modules/28_paging_track.sh --detect <pcap>                # paging anomaly signals
modules/28_paging_track.sh --adaptover-detect <pcap>      # the keep-awake paging pattern
modules/28_paging_track.sh --paging-parse <hex> [gsm|lte|nr]
```

The mechanism is worth understanding even if you never run it: a page is a
broadcast, so the *response* to a page is the only part that identifies a
handset, and a handset that answers a page you sent has told you it is in the
cell. `--torpedo-model` measures the collision and response timing that makes
this work; `--piercer-correlate` takes candidate identities and a capture and
correlates paging behaviour against them; `--adaptover-detect` looks for the
pathological version, a paging stream designed to keep a handset awake and
draining.

The module's own header records a disagreement with its brief: this implements
the NDSS 2019 paper, and says so rather than repeating a venue it could not
verify. That is the same rule as everywhere else in the manual — the citation is
stated as checked or as briefed.

*What you read:* timing distributions, correlation scores with the identity they
imply, and named anomaly signals with counts.

*When it refuses:* a capture with no paging messages at all (`no paging messages
in <path>`), which is a different statement from "no anomalies found".

*Read next:* §5.1.3 for the arithmetic underneath, and §5.3.2 for the same
signalling used to break a cell rather than to track a phone.

### 5.7.4 RF fingerprinting a device

*Need: IQ recordings.* Every transmitter is slightly wrong in its own way, and
the wrongness is stable enough to recognise.

```bash
modules/24_rf_fingerprint.sh --features <iq> cf32 1000000   # RMS, peak, PAPR, flatness, ...
modules/24_rf_fingerprint.sh --transient <iq> cf32 1000000  # burst edge, rise time, envelope
modules/24_rf_fingerprint.sh --sig-add <name> <iq> cf32 1000000
modules/24_rf_fingerprint.sh --classify <iq> cf32 1000000 3
modules/24_rf_fingerprint.sh --csi-parse <hex> [auto|lte|80211]
modules/24_rf_fingerprint.sh --csi-motion <file>            # phase variance across snapshots
```

`--features` computes the statistics that survive a change of channel;
`--transient` looks at the moment a burst starts, which is where a device's
power amplifier is least corrected and most individual. `--csi-motion` is the
odd one out: it uses channel-state-information phase variance across snapshots
to infer that something moved, which is sensing rather than identification, and
the module keeps the two apart.

*What you read:* a feature vector per recording, a ranked match against a stored
signature set, and — stated in the output — how many signatures were in the set,
because a classification against two references is not a classification.

*When it refuses:* an IQ file that does not exist or whose format/sample-rate
does not match the declared ones.

*Read next:* §5.9.1 for the network-traffic equivalent of the same idea.

---

## 5.8 The radio families that are not LTE or 5G

Most cellular security writing stops at LTE and 5G. This toolkit does not, because
the same subscribers are on the other radios at the same time, and because the
narrowband and satellite variants are where the constraints are interesting.

### 5.8.1 NB-IoT and Cat-M1

*Need: nothing.* Narrowband IoT is LTE with the bandwidth turned down to a single
resource block, which changes the arithmetic and the attack surface but not the
protocol family.

```bash
modules/45_iot.sh --nprach                                  # NPRACH configuration walk
modules/45_iot.sh --nprach-decode <hex>                     # read nprach-ConfigSIB-NB out of a SIB2-NB
modules/45_iot.sh --npss-nss 1                              # PCI -> N_ID(1)/N_ID(2)
modules/45_iot.sh --decode-sib1 <hex>                       # SystemInformationBlockType1-NB
modules/45_iot.sh --decode-mib <hex>                        # MIB-NB, 5 octets / 34 bits
modules/45_iot.sh --to-mhz <nprfcn>                         # refuses: the table is per-band
modules/45_iot.sh --nprach-verify
```

`--nprach` is the page worth reading: the preamble format, `n_init`, the
subcarrier offset and the number of groups are what a device must agree with the
cell about, and every one of them is derivable from the SIB the cell broadcasts.
`--to-mhz` is the honest refusal in this module: TS 36.104's NPRFCN table is
per-band and this tree does not carry it, so the verb refuses rather than
returning a plausible-looking frequency.

*What you read:* the NPRACH parameters, the PCI decomposition, and for a MIB/SIB1
the fields with their bit widths.

*When it refuses:* `n_init` outside `0..11` is refused with the clause that
bounds it; `--to-mhz` always refuses with the reason.

*Read next:* §5.1.1 for the parent technology's broadcast.

### 5.8.2 GPRS, EDGE and GEA

*Need: nothing.* GPRS ciphering is the part of 2G that most audits skip, and it
contains the same pattern as the voice side: a null algorithm, a broken one, and
a table nobody reads.

```bash
modules/50_gprs.sh --gea-table                       # per-algorithm clause, sizes, implemented?
modules/50_gprs.sh --gea 3                           # one algorithm with its standing
modules/50_gprs.sh --gea-crypt 3 0011223344556677 00000000 4142434445464748
# gamma e5a60b578241ff6e / ciphertext a4e44813c707b826
modules/50_gprs.sh --gea-kat                         # published test vectors, one row each
modules/50_gprs.sh --apn-encode internet.mnc260.mcc310.gprs
modules/50_gprs.sh --apn-ie <apn>                    # the APN IE itself (IEI 28)
```

The cipher is implemented for real rather than tabulated: `--gea-crypt` produces
a keystream and ciphertext for a given Kc, and `--gea-kat` runs the published
GEA3/GEA4 vectors as known-answer tests so the implementation is checkable. The
APN verbs are there because the APN is where a private network names itself.

*What you read:* the algorithm's clause and standing, the keystream for a chosen
input, and the APN's label coding.

*When it refuses:* GEA3 takes a 64-bit Kc and refuses a 128-bit one by name —
the message says which algorithm wanted which key size, because the alternative
is a silently truncated key.

*Read next:* §5.1.4, which is the voice-side equivalent of the same table.

### 5.8.3 Non-terrestrial networks

*Need: nothing.* A satellite cell is a cell with a 600 km timing advance problem,
and that problem is the whole technique surface.

```bash
modules/49_ntn.sh --doppler 1575420000 7500 30    # Doppler for a closing velocity at an angle
modules/49_ntn.sh --range 600                      # one-way and round-trip delay
modules/49_ntn.sh --ta 600                         # TA units needed vs the LTE TA range
modules/49_ntn.sh --koffset 20 15                  # K_offset in reference slots
modules/49_ntn.sh --ntn-reselect                    # which cell the UE reselects to
modules/49_ntn.sh --scan-plan                       # the three signals that say NTN
modules/49_ntn.sh --fakecell-plan                   # what broadcasting a satellite cell needs
```

`--ta` is the number that matters: a geostationary round trip needs far more
timing advance than the terrestrial TA field can express, which is why NTN has
its own timing-advance mechanisms and why a fake satellite cell fails in a
specific, statable way. `--fakecell-plan` states that failure rather than
pretending the cell can be stood up.

*What you read:* Doppler shift, delay, TA requirement versus the field's range,
and the reselection outcome.

*When it refuses:* a velocity or angle it cannot interpret; `--fakecell-plan` does
not refuse but reports the preconditions it cannot satisfy.

*Read next:* §5.7.1, since the TA arithmetic is the same instrument with a much
bigger number.

### 5.8.4 NR sidelink and V2X

*Need: nothing.* Sidelink is UE-to-UE, which means the security question changes:
there is no network in the middle to trust.

```bash
modules/51_sidelink.sh --subchannels 106 10       # 10 subchannels of 10 PRBs, remainder 6
modules/51_sidelink.sh --freq-bits 10             # SCI-1A frequency resource field width
modules/51_sidelink.sh --pfi 1                    # PC5 QoS flow identifier
modules/51_sidelink.sh --l2id 001122               # 24-bit Layer-2 ID
modules/51_sidelink.sh --sci1a                     # refuses: the widths are not in this tree
modules/51_sidelink.sh --its                       # ETSI/1609.2 certificate roles
modules/51_sidelink.sh --relay-check conf.txt      # UE-to-network relay configuration findings
```

`--sci1a` refusing is the module being honest about scope: the SCI-1A field
widths depend on parameters this tree does not carry, so it refuses instead of
encoding a plausible guess. `--relay-check` is the practical verb — a UE acting
as a relay for another is a policy decision, and misconfigured relays are how a
sidelink deployment leaks traffic between fleets.

*What you read:* subchannel arithmetic, the L2 identity, and for `--its` the
certificate roles (reference only; the module states it has no validator).

*When it refuses:* `--sci1a` always; a bandwidth/subchannel pair that leaves a
remainder larger than a subchannel.

*Read next:* §5.8.3 for the other non-terrestrial-adjacent radio, and §4.13 for
the module pages.

### 5.8.5 TETRA, DMR and GSM-R

*Need: nothing.* The radios that are not cellular but carry the same people.

```bash
modules/53_non3gpp.sh --tetra                 # TETRA frame and band reference (EN 300 392)
modules/53_non3gpp.sh --tea TEA2              # cipher description and standing
modules/53_non3gpp.sh --dmr                   # DMR reference (TS 102 361)
modules/53_non3gpp.sh --gsmr                  # GSM-R band and feature reference (EN 301 515)
modules/53_non3gpp.sh --tdma 56.67 4          # slot arithmetic from a stated frame length
modules/53_non3gpp.sh --frame-math 255 2 4 36000   # derive the frame length from the air interface
modules/53_non3gpp.sh --classify 25           # technology from channel spacing
```

`--classify` is the identification verb: 25 kHz with 4-slot TDMA is TETRA, 12.5
kHz is DMR, 200 kHz is GSM. `--frame-math` is the reason this module is more than
a table: given symbols per slot, bits per symbol, slots and bit rate, it derives
the frame length, which is how a new or undocumented system gets measured rather
than guessed at.

*What you read:* for a technology, its frame structure and cipher standing; for
`--classify`, the most likely technology and the evidence for it.

*When it refuses:* a frame length of zero, a bit rate that does not divide.

*Read next:* §5.1.1, since these systems broadcast their own equivalent of a
SIB and the same reading discipline applies.

### 5.8.6 Open RAN

*Need: nothing to read the authority model; a network path for RIC interaction.*
O-RAN moves control into xApps on a RIC, which means the security question is
"what is an xApp allowed to do, and who checked".

```bash
modules/48_oran.sh --interfaces        # E2/A1/O1/O2/F1/E1/fronthaul map
modules/48_oran.sh --e2sm              # E2 service models
modules/48_oran.sh --assess conf.txt   # deployment findings from a KEY=VALUE config
modules/48_oran.sh --xapp-authority tsv
modules/48_oran.sh --a1-put policy 1 scope '{}'   # a forged A1 policy PUT
modules/48_oran.sh --qos-policy                    # a complete A1 QoS policy body
modules/48_oran.sh --qos-policy-check policy.json  # validate it; unknown keys are reported
```

`--xapp-authority` is the page: per loaded xApp, what it can actually reach,
which is rarely what its documentation says. `--a1-put` builds the policy write
that a compromised xApp would send — the finding is not that the message can be
built but that the A1 interface accepts a policy from anything that can reach it.
`--qos-policy-check` exists so a policy body can be validated against the schema
before it is pushed at anything.

*What you read:* the interfaces and service models, the authority table, and for
`--assess` the findings with the config key behind each.

*When it refuses:* a config path that does not exist (it says `no such config`),
an unknown key in a policy body (reported, not silently dropped).

*Read next:* §5.4.3, since the RIC sits beside the same service-based core.

---

## 5.9 Traffic, jamming and interception

The last family before the kits is the one that treats the network as a system
rather than as a protocol: what the traffic looks like in aggregate, what it
looks like when somebody interferes with it, what it looks like when somebody is
lawfully intercepting it, and how to run a sequence of the above.

### 5.9.1 Traffic analysis and call fingerprinting

*Need: a capture.* Packet-level identification answers "who"; traffic analysis
answers "what were they doing", and it does so without reading a single payload.

```bash
modules/23_traffic_analysis.sh --flows captures/ue.pcap 1     # per-flow table
modules/23_traffic_analysis.sh --features captures/ue.pcap 0 1
modules/23_traffic_analysis.sh --calls-tsv captures/ue.pcap 1  # call table, media grouped
modules/23_traffic_analysis.sh --fingerprint-add whatsapp ref.pcap
modules/23_traffic_analysis.sh --classify captures/ue.pcap 3
modules/23_traffic_analysis.sh --refs-tsv
```

The flow table carries the columns that make classification possible: packets and
bytes each way, duration, mean size, burst count, maximum idle gap, and a
`shaping` verdict. `--calls-tsv` groups media streams into calls, which is the
step that turns anonymous UDP into a conversation with two ends and a duration.

*What you read:* per flow, the shape of the conversation; for `--classify`, the
top-k matches and the reference set size — the module refuses to classify against
an empty set (`no fingerprints stored`) rather than returning a confident
nothing.

*When it refuses:* a non-numeric idle threshold; an empty reference store.

*Read next:* §5.7.4 for the RF-layer equivalent, and §5.6.2 for the voice
service this analysis is looking at.

### 5.9.2 Detecting jamming

*Need: an IQ recording.* Jamming is the one attack that cannot be defeated
cryptographically, so the useful work is telling it apart from congestion and
from a hole in coverage.

```bash
modules/33_jamming_detect.sh --fixture clean /tmp/j.f32          # a known-clean recording
modules/33_jamming_detect.sh --analyse /tmp/j.f32 cf32 2000000   # features, saved as the record
modules/33_jamming_detect.sh --noise-floor /tmp/j.f32 cf32 2000000
modules/33_jamming_detect.sh --characterise /tmp/j.f32 cf32 2000000 20   # narrowband vs barrage
modules/33_jamming_detect.sh --counters counters.txt             # merge receiver counters
modules/33_jamming_detect.sh --discriminate                      # jamming / congestion / coverage hole
modules/33_jamming_detect.sh --report                            # regulatory report (jamming only)
```

`--discriminate` is the verb that matters: jamming raises the noise floor without
raising the error rate in the way congestion does, and a coverage hole raises
neither. The module reports which of the three the evidence supports, and
`--report` produces a regulatory-shaped document only when the verdict is
jamming — because filing a jamming report about congestion is how an operator
stops believing reports.

*What you read:* noise floor over time, the characterisation (narrowband or
barrage, bandwidth, duty cycle), and the verdict with its evidence.

*When it refuses:* an IQ file whose format or rate does not match the declared
ones; `--discriminate` with no record to discriminate on.

*Read next:* §5.3.2, since overshadowing uses the same physical lever
deliberately.

### 5.9.3 Lawful interception from the outside

*Need: nothing for the reference; signalling events for the score.* Interception
interfaces are documented in TS 33.108 and the documentation is the interesting
part: what an operator must be able to deliver says a lot about what exists.

```bash
modules/42_li_probe.sh --interfaces      # X1/HI1, X2/HI2, X3/HI3 — who talks to whom
modules/42_li_probe.sh --iface X2        # one interface in detail
modules/42_li_probe.sh --architecture    # ADMF/POI/DF2/DF3/LEMF roles
modules/42_li_probe.sh --score events.tsv # interception-posture score over signalling
modules/42_li_probe.sh --li-pdu-build     # wrap a product in a delivery header
modules/42_li_probe.sh --li-pdu-parse <hex>
modules/42_li_probe.sh --report           # what to record and where to escalate
```

The distinction the module keeps sharp: X2 carries IRI (who called whom, when),
X3 carries content. A posture score built only from signalling can say whether an
interception is *likely active* against a subscriber, and cannot say what was
said: the module's own `--status-tsv` lists what its PDU model does not cover,
so a report cannot drift into claiming content.

*What you read:* the interface map, the roles, and a score with the events behind
it.

*When it refuses:* a PDU whose header is not the expected delivery header; a score
run with no events.

*Read next:* §5.4.2, since SS7 is where most real interception capability is
provisioned.

### 5.9.4 The user-plane integrity gap

*Need: nothing.* This is a single fact with a large blast radius, and it gets its
own page because three other techniques depend on it.

```bash
modules/29_mac_layer.sh --integrity-gap
# integrity  user_plane  DRB  integrity  no  no MAC-I over DRB payloads; ...
modules/29_mac_layer.sh --decode-mac <hex> [dl|ul]   # an LTE MAC PDU, subheader chain
modules/29_mac_layer.sh --lcid-table                 # TS 36.321 6.2.1-1 / -2
modules/29_mac_layer.sh --rnti-table                 # the RNTI space and reserved values
modules/29_mac_layer.sh --rnti-track <pcap>          # RNTI/LCID evidence across a capture
modules/29_mac_layer.sh --sched-pattern <pcap>       # scheduling pattern
```

LTE ciphers the user plane but does not integrity-protect it (TS 36.323 6.2), so
a flipped ciphertext bit decrypts to a flipped plaintext bit with nothing at the
receiver to notice. NR closed this for signalling; the user plane story is
configuration-dependent, which is why the module prints the plane, the bearer and
the clause rather than a single "protected or not".

*What you read:* the gap table with its sources, the subheader chain of a MAC
PDU, and per capture the RNTI/LCID evidence that identifies which bearer a
payload belonged to.

*When it refuses:* an LCID it has no table entry for is reported as unknown, not
mapped to the nearest neighbour.

*Read next:* §5.4.4 and §5.6.2, the two techniques that ride on this gap.

### 5.9.5 Chains and fleets

*Need: whatever the steps need.* A single technique rarely answers a question; a
sequence of them does, and the toolkit has two ways to sequence: a chain run on
this host, and a fleet of hosts the modules can read from.

```bash
modules/25_killchain.sh --list-chains               # every chain, with step and hardware counts
modules/25_killchain.sh --show-chain survey         # resolve the steps without running them
modules/25_killchain.sh --run survey --dry-run      # what would happen
modules/25_killchain.sh --run survey --keep-going   # run it, continuing past failures
modules/25_killchain.sh --pause                     # cooperative pause between steps
modules/25_killchain.sh --resume                    # resume from the checkpoint
modules/25_killchain.sh --run-multi gsm-sweep bands.tsv   # once per first-column target

modules/59_remote_node.sh --list-tsv                # every node, its class and its last sighting
modules/59_remote_node.sh --probe van-1             # ONLINE / OFFLINE / UNKNOWN
modules/59_remote_node.sh --dispatch van-1 02_cell_recon --scan lte 20
modules/59_remote_node.sh --stream van-1 --follow 5
```

`--show-chain` before `--run` is the habit worth forming: a chain that needs
hardware should be inspected, and `--run --dry-run` prints the resolved commands
without executing them. `--pause`/`--resume` exist because a chain that touches a
radio should be interruptible without losing its checkpoint.

For fleets, `--dispatch` runs a module verb on another host and returns its
output, and `--list-tsv` keeps the honesty column: a node is `ONLINE`, `OFFLINE`
or `UNKNOWN`, and `UNKNOWN` is a distinct state (the node has never been probed),
not a synonym for offline. `--stream` drains that node's spool from this side's
cursor, which is how a survey from a remote receiver arrives without a shared
filesystem.

*What you read:* the chain definition and its hardware count; for a run, per-step
outcomes; for a fleet, per-node status with the reason for it.

*When it refuses:* `--run` on a chain whose hardware steps cannot be satisfied
reports which step and why; `--dispatch` to an offline node reports the
transport's failure rather than a timeout that looks like a hang.

*Read next:* §5.10 for the kits that catalogue what these chains are aimed at.

---

## 5.10 The exploit kits

The last family is the one this manual refuses to expand: three modules that
catalogue several hundred CVEs between them. A CVE is not a technique. It is one
message shape with one vulnerable parser behind it, and whether it works depends
on the baseband, the firmware revision, and the testbed. So each kit gets one
page, and the pages are about *how to use the kit* — how to find out what it
covers, how to run one entry honestly, and how to tell a corpus entry from a
demonstrated capability.

Nothing in this family needs a radio to read. Everything in it needs a lab
device to run.

### 5.10.1 The GSM/GPRS kit

*Need: nothing to enumerate; a lab handset and SIM to run.*

```bash
modules/20_gsm_cve.sh --coverage          # what the corpus covers and its horizon
modules/20_gsm_cve.sh --list-cves        # id, kind, class, needs, label
modules/20_gsm_cve.sh --probe            # what this bench can actually reach
modules/20_gsm_cve.sh --plan             # the run plan for the entries that are reachable
modules/20_gsm_cve.sh --run-cve CVE-2019-16256
modules/20_gsm_cve.sh --runs-tsv         # every run, with its verdict
modules/20_gsm_cve.sh --reachability     # per entry: reachable here, or why not
```

`--coverage` is the page that keeps the kit honest:

```text
corpus         GSM/GPRS CVE corpus
entries        29
years_covered  2010 2015 2017 2018 2019 2020 2021 2022 2024 2025
corpus_horizon 2025-12-31
checked_on     2025-06-01
```

Read the horizon, not the count. A corpus has a date because the world keeps
producing vulnerabilities, and a kit that claimed completeness would be claiming
to have stopped time. `--reachability` then says, per entry, whether this bench
can reach it at all: Simjacker needs a SIM-Toolkit harness, not a radio, and the
kit says so rather than offering a button that would fail.

The `needs` column in `--list-cves` is the single most useful thing here. An
entry marked `programmable-sim` cannot be run against a stock SIM; an entry
marked `sim-toolkit-harness` needs the harness on the bench. `--probe` turns
that into a checklist for the machine you are sitting at.

*What you read:* the run verdict per entry, and the difference between "not
vulnerable", "could not deliver", and "not reachable from this bench". Only the
first is a statement about the device.

*When it refuses:* `--run-cve` with an id not in the corpus is refused with the
nearest match; a run whose prerequisites are missing records the missing
prerequisite rather than a failed exploit.

*Read next:* §5.5.2 for the SIM-Toolkit surface most of this corpus targets.

### 5.10.2 The LTE kit

*Need: nothing to enumerate; a lab eNB/EPC path to run.*

```bash
modules/21_lte_cve.sh --coverage
modules/21_lte_cve.sh --list-cves
modules/21_lte_cve.sh --corpus            # the message corpus the kit carries
modules/21_lte_cve.sh --corpus-entry <id>
modules/21_lte_cve.sh --corpus-stats
modules/21_lte_cve.sh --gen --plmn 310-260 --teid 0x0001
modules/21_lte_cve.sh --run-cve <id>
modules/21_lte_cve.sh --runs-tsv
```

The LTE kit carries a corpus of real message bytes alongside the CVE list,
which is what makes it useful without a vulnerable phone: `--corpus-entry`
prints one, `--gen` materialises the corpus against your own PLMN and TEID, and
`--corpus-stats` says what is in it (message types, generations, plaintext vs
protected). A corpus entry is a test vector, not an exploit — running it against
a healthy stack should produce a clean rejection, and that is the expected
result.

*What you read:* from `--corpus-stats`, whether the corpus has the message you
care about; from `--runs-tsv`, what happened when a vector met a device.

*When it refuses:* `--corpus-entry` with an unknown id; `--gen` without a PLMN,
because a corpus generated against an unstated network is not reproducible.

*Read next:* §5.4.1 for the core-side messages this kit's corpus exercises.

### 5.10.3 The 5G kit

*Need: nothing to enumerate; a lab gNB/core path to run.*

```bash
modules/22_nr_cve.sh --coverage
modules/22_nr_cve.sh --list-cves
modules/22_nr_cve.sh --list-findings      # the write-ups behind the entries
modules/22_nr_cve.sh --run-cve <id>
modules/22_nr_cve.sh --probe
modules/22_nr_cve.sh --reachability
modules/22_nr_cve.sh --snssai <hex>       # scope a run to a slice
modules/22_nr_cve.sh --plan
```

5G's corpus is younger and mostly not in the baseband: a large share of the
entries are service-based-architecture findings — a network function that trusts
a token it should not, an NRF that enumerates more than it should — which is why
`--snssai` exists to scope a run to one slice and why §5.4.3 is the reading
before this page.

`--list-findings` prints the write-up each entry came from, so an entry can be
traced to a published disclosure rather than to a name in a list.

*What you read:* `--reachability`, the same discipline as the GSM kit: which
entries this bench can even attempt.

*When it refuses:* a slice identifier that is not an S-NSSAI; a `--run-cve` for
an entry whose prerequisite network function is absent from `--probe`.

*Read next:* §5.4.3 for NRF discovery, §5.4.5 for slice selection.

### 5.10.4 A baseband research kit

*Need: a lab device, and a lot of patience.* This is the only family member
that operates below the message layer: it is about reaching a baseband's own
code, and it is explicit that the useful part is the harness, not the payload.

```bash
modules/54_baseband_exploit.sh --list-cves
modules/54_baseband_exploit.sh --cve <id>
modules/54_baseband_exploit.sh --states          # baseband state machine
modules/54_baseband_exploit.sh --fw-manifest     # what firmware this bench holds
modules/54_baseband_exploit.sh --fw-verify
modules/54_baseband_exploit.sh --qemu-harness    # can a stripped image run here
modules/54_baseband_exploit.sh --emulate
modules/54_baseband_exploit.sh --l2-build --l2-case <name>
modules/54_baseband_exploit.sh --l2-corpus
modules/54_baseband_exploit.sh --plan
```

`--qemu-harness` and `--emulate` are the honest centre of the module: most
baseband research is spent getting an image to run at all, and the kit reports
what it can and cannot emulate rather than pretending a CVE is a button. The L2
case builder (`--l2-build`, `--l2-corpus`, `--l2-case`) is how a specific parser
gets exercised in that harness.

`--fw-manifest` plus `--fw-verify` is a chain-of-custody tool: which firmware
images are on this bench, and do they still hash to what they did when they were
acquired. A research result you cannot tie to an image is not reproducible.

*When it refuses:* `--emulate` without a verified image; `--cve` with an id the
kit does not carry.

*Read next:* §5.10.5, which is the diagnostic half of the same work.

### 5.10.5 Baseband diagnostics

*Need: a lab device.* Where §5.10.4 tries to reach code, this page is about
seeing what the modem is doing at all — which is the prerequisite for every
baseband result anyone has ever published.

```bash
modules/56_baseband_diag.sh --ports              # diag ports this device exposes
modules/56_baseband_diag.sh --cmd-name 0x0b      # what a diag command id means
modules/56_baseband_diag.sh --frame / --unframe  # the diag framing layer
modules/56_baseband_diag.sh --demux              # split a diag stream by subsystem
modules/56_baseband_diag.sh --log-classify       # sort a log by what it is about
modules/56_baseband_diag.sh --nv-scan --nv-parse # non-volatile item read
modules/56_baseband_diag.sh --state --state-info # modem state machine, decoded
modules/56_baseband_diag.sh --efs-walk --efs-read
modules/56_baseband_diag.sh --at --at-parse
modules/56_baseband_diag.sh --audit
```

The EFS/NV verbs matter beyond diagnostics: a device's non-volatile store is
where identities, calibration and provisioning live, so `--nv-scan`, `--efs-walk`
and `--audit` are how you establish that a lab device is what you think it is
before you trust a result from it.

*What you read:* `--audit`'s summary of what the store exposes; `--log-classify`
per line of a log; `--state-info` for where the modem thinks it is.

*When it refuses:* an unframed stream given to `--demux`; an EFS path outside
the store's own root.

*Read next:* §5.5.1, which reads an identity from the SIM side rather than the
modem side, and the store table in §3.1 for the directories these verbs write
into.
