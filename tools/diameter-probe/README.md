# diaprobe — Diameter interconnect probe kit

Access to SS7/Diameter interconnect is the goal. This is the first thing that
actually reaches for it.

## What this is, and what it is not

It is **not** a port scanner. A Diameter edge is an intentional, documented
interface to peers — the whole point of an interconnect. The question worth
asking is not "is 3868 open" but **what does this DRA accept from a peer it has
never met**, and a real message answers that in one round trip.

It sends genuine Diameter messages over genuine SCTP and reports what came back,
in the doctrine's three states (AGENTS.md §3):

| verdict      | meaning                                                          |
| ------------ | ---------------------------------------------------------------- |
| `MEASURED`   | the peer answered, and the answer was decoded                     |
| `ADVERTISED` | the peer described itself (its CEA) — its claim, not our proof    |
| `UNOBSERVED` | silence, reset, timeout — **never** the same answer as "closed"  |

## Why CER first

A Capabilities-Exchange-Request is the one message that is legal as the *first*
message to any Diameter peer. Nothing authenticates before the CEA. So the CEA
discloses the peer's Origin-Host, Origin-Realm, supported applications, vendor
and firmware — before any credential is presented. That is the reconnaissance
that the rest of the kit hangs off, and it costs one packet.

## Verbs

```bash
tools/diameter-probe/diaprobe.py cer  --host H --port 3868 --transport sctp
tools/diameter-probe/diaprobe.py dwr  --host H            # RFC 3539 liveness
tools/diameter-probe/diaprobe.py ulr  --host H --imsi <IMSI> --dest-realm R
tools/diameter-probe/diaprobe.py air  --host H --imsi <IMSI> --mcc 470 --mnc 01
tools/diameter-probe/diaprobe.py slr  --host H --imsi <IMSI>   # SGd, 5G
tools/diameter-probe/diaprobe.py sweep --prefix-file prefix-as30985.txt --ports 3868
```

Every verb writes a row to `loot/diameter-probe/probes.tsv` and prints the same
row to stdout.

## The four paths onto an interconnect

1. **The edge itself** — DRA/STP on 3868 (Diameter), 2905 (M3UA/SIGTRAN),
   3869 (DSA). Tested by `cer`/`ulr`/`air`, not by knocking.
2. **The roaming partner** — peering is contractual. AS30985's peer list is
   concrete: Opentransit (AS5511), Orange CI (AS29571), SONATEL (AS8346),
   Orange Tunisie (AS328126), ATEL (AS328253), Sotelma (AS328284). Those are
   who can legitimately send you a MAP SRI-SM, and it is auditable.
3. **VAS / SMSC / OCS frontends** — an SMSC or an open SMS gateway gives MAP
   positioning and SMS-intercept primitives without ever touching a DRA.
4. **The BSS chain** — provisioning access is subscriber state, not signaling,
   but it is how you become a peer that looks legitimate.

## Target hygiene

Test against **your own IMSI and your own MSISDN** unless you are acting inside
a lab or an operator-side position. `--imsi`/`--mcc`/`--mnc` exist so the test
subscriber is explicit on the command line and lands in the store next to the
result.

## Prerequisites

- SCTP: the kernel module (`modprobe sctp`), not a userspace shim. Verified
  working on this host — `CONFIG_IP_SCTP=m`.
- `pysctp` and `pycrate` from PyPI. pycrate installs as several top-level
  packages (`pycrate_diameter`, …), so `import pycrate` fails even when it is
  installed; `diaprobe.py` loads it from the user site directly.

## Selftest

```bash
tools/diameter-probe/selftest.sh
```

Stands up a loopback SCTP peer, fires all five message types at it, asserts the
answers decode, asserts an unreachable peer is `UNOBSERVED`, and checks the
store. No radio, no root, no internet.
