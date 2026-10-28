# IMSISting

## A field manual for the 2G · 3G · 4G · 5G cellular research toolkit

**Edition** for version `1.0.81`

---

### What this document is

A description of what IMSISting contains and how to use it, written after the
code rather than before it. Every verb named here exists in the tree, every
store named here is written by a module named here, and every refusal quoted
here is a refusal the toolkit actually performs. Where a capability is absent,
the absence is stated in the place a reader would expect the capability to be.

### What this document is not

It is not a guide to breaking the law, and it does not pretend the toolkit is
harmless. IMSISting transmits on licensed spectrum. Several modules reach a
verdict only after a radio in your hand has radiated: a catcher that accepts an
attach, a twin that a phone answers, a downgrade that a handset obeys. Running
any of those against infrastructure you do not own or have not been authorised
to test is an offence in most jurisdictions and, more practically, it is how a
research toolkit acquires a legal history that ends its usefulness.

The rule the toolkit itself follows, and the rule this manual assumes: **know
which of your verbs transmit before you press them.** The interface says so —
a card that radiates carries a `TRANSMITS` chip, and the module behind it
refuses configurations that would radiate by accident — but the decision is the
operator's, not the software's.

### How to read this manual

The manual is ordered by the questions a new operator asks, not by the order
the code was written:

| Part | Question it answers |
|---|---|
| 1. Orientation | Why is the toolkit shaped this way? |
| 2. Getting it running | What do I install, and what does my first hour look like? |
| 3. Interfaces | Where do I type, click and read? The CLI, the TUI, the GUI. |
| 4. Catalogue | What is this thing? Every module by category, every drawer tab, the target panel. |
| 5. Technique reference | How do I actually do it? One page per attack and per passive analysis. |

Part 4 never tells you how to run anything and Part 5 never explains what a
module is for; they cross-reference each other by section number. A reader who
wants to know whether the toolkit can do a thing should read Part 4. A reader
who already knows and wants to do it should read Part 5.

### Conventions

| Convention | Meaning |
|---|---|
| `modules/07_gsm_attack.sh --selftest` | A command you can type. Paths are relative to the repository root. |
| `--verb` | A verb of the module currently under discussion. |
| `loot/<module>/` | A store directory. Stores are append-only TSV unless stated otherwise. |
| `exit 3` | A handoff, not a failure. See §1.2. |
| **bold** | A word the toolkit uses in a specific sense, defined in §1.4. |
| *Selftest: 357* | The number of assertion rows the module's own `--selftest` passes, quoted from a run on a machine with no radio. |

Three words carry the whole honesty doctrine of this toolkit and are defined
early because the rest of the manual is unintelligible without them:
**measured**, **advertised** and **unobserved**. A measured fact came out of a
device or a capture. An advertised fact is what a network or a configuration
claims about itself. An unobserved dimension is grey, and grey is a legitimate
answer — it is not the same answer as "clean".

---

*Parts 1 to 5 of this manual were written by hand. No page of it is generated
from the source tree, which is a deliberate cost: a generated page can never
drift from the code but also never explains why the code is shaped that way.
The gate suite described in §3.4 is what keeps the underlying claims true.*
