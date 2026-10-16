#!/usr/bin/env python3
"""Check tools/lte_phy.py's PSS and SSS against two independent references.

PSS and SSS are checked two ways, and the two are not interchangeable.

  1. Against the closed-form definition in TS 36.211 6.11.1.1 and 6.11.2.1,
     evaluated here from the specification's own recurrence relations. This is
     the real reference, and it is what decides correctness. Tolerance 1e-12:
     both sides are float64 evaluations of the same formula, so they agree to
     rounding or they do not agree.

  2. Against srsRAN, an independent C implementation, at a tolerance derived
     from srsRAN's OWN error against the closed form -- measured here, not
     guessed. This checks that we and srsRAN read the clause the same way.

Why (2) cannot simply use a small tolerance: srsRAN computes PSS in single
precision, and its error against the closed form is ~2.3e-4, which is larger
than any reasonable guess at "float32 noise" and ~230x a 1e-6 tolerance.
Demanding 1e-6 of srsRAN means demanding that we reproduce its rounding
error; a correct float64 implementation then FAILS. The first version of
this comparison did exactly that and reported three PSS "mismatches" that
were entirely srsRAN's own error.

So the srsRAN tolerance is set to a small multiple of srsRAN's measured
error, with a floor for the cases where it happens to be exact.

Oracle directory comes from $IMSISTING_ORACLE, defaulting to the path this
script was first run from.
"""

import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import lte_phy as L  # noqa: E402

ORACLE = os.environ.get("IMSISTING_ORACLE", "/tmp/ltephy/oracle")
SYNC_TXT = os.path.join(ORACLE, "srsran_sync.txt")

# --- reference implementation: the specification's own recurrences ---------

def _x_advance(x, taps, n):
    """Extend a length-5-seeded LFSR, x(i+5) = sum(x(i+t) for t in taps) mod 2."""
    x = list(x)
    while len(x) < n:
        x.append(sum(x[len(x) - 5 + t] for t in taps) % 2)
    return x


def _tildes():
    """The three length-31 sequences s~, c~ and z~ of TS 36.211 6.11.2.1.

    Each is a different LFSR on the same seed 0,0,0,0,1:
        s~: x(i+5) = (x(i+2) + x(i)) mod 2
        c~: x(i+5) = (x(i+3) + x(i)) mod 2
        z~: x(i+5) = (x(i+4) + x(i+2) + x(i+1) + x(i)) mod 2
    and each maps to +-1 as 1 - 2x(i).
    """
    def seq(taps):
        x = _x_advance([0, 0, 0, 0, 1], taps, 31)
        return [1 - 2 * v for v in x[:31]]
    return seq((2, 0)), seq((3, 0)), seq((4, 2, 1, 0))


def pss_reference(n2):
    """TS 36.211 6.11.1.1.

    The root is a length-63 Zadoff-Chu and the middle element is dropped, so
    d(31..61) is NOT the continuation of d(0..30): the two halves are the two
    ends of the length-63 root, renumbered. Writing
    exp(-j*pi*u*n*(n+1)/63) for all n = 0..61 -- the obvious reading -- still
    gives a unit-modulus constant-amplitude sequence, so nothing but a
    correlation against the real thing distinguishes them. (This comparator
    made exactly that mistake on its first run; the implementation under test
    was right.)
    """
    u = (25, 29, 34)[n2]
    d = []
    for n in range(62):
        if n <= 30:
            a = -math.pi * u * n * (n + 1) / 63.0
        else:
            a = -math.pi * u * (n + 1) * (n + 2) / 63.0
        d.append(complex(math.cos(a), math.sin(a)))
    return d


def sss_reference(cid, subframe):
    """TS 36.211 6.11.2.1: the length-62 SSS for one subframe.

        d(2i)   = s0^(m0)(i) * c0(i)                     subframe 0
        d(2i+1) = s1^(m1)(i) * c1(i) * z1^(m0)(i)
        d(2i)   = s1^(m1)(i) * c0(i)                     subframe 5
        d(2i+1) = s0^(m0)(i) * c1(i) * z1^(m1)(i)

    The two length-31 halves are INTERLEAVED as even and odd, not
    concatenated -- another trap this comparator fell into: concatenating
    them yields a plausible 62-value BPSK sequence that shares about half its
    signs with the real one.
    """
    nid1, nid2 = divmod(cid, 3)
    qp = nid1 // 30
    q = (nid1 + qp * (qp + 1) // 2) // 30
    mp = nid1 + q * (q + 1) // 2
    m0 = mp % 31
    m1 = (m0 + mp // 31 + 1) % 31

    s_tilde, c_tilde, z_tilde = _tildes()

    def rot(seq, m):
        return [seq[(i + m) % 31] for i in range(31)]

    s0, s1 = rot(s_tilde, m0), rot(s_tilde, m1)
    c0 = [c_tilde[(i + nid2) % 31] for i in range(31)]
    c1 = [c_tilde[(i + nid2 + 3) % 31] for i in range(31)]
    z0, z1 = rot(z_tilde, m0 % 8), rot(z_tilde, m1 % 8)

    d = []
    for i in range(31):
        if subframe == 0:
            d.append(s0[i] * c0[i])
            d.append(s1[i] * c1[i] * z0[i])
        else:
            d.append(s1[i] * c0[i])
            d.append(s0[i] * c1[i] * z1[i])
    return [complex(v, 0) for v in d]


# --- load the srsRAN oracle ------------------------------------------------

if not os.path.exists(SYNC_TXT):
    print("no srsRAN sync dump at %s" % SYNC_TXT)
    print("run ./tools/check-lte-phy-oracle.sh to build it")
    sys.exit(2)

pss_oracle, sss_oracle = {}, {}
with open(SYNC_TXT) as f:
    for line in f:
        p = line.split()
        if not p:
            continue
        if p[0] == "PSS":
            v = [float(x) for x in p[2:]]
            pss_oracle[int(p[1])] = [complex(v[2 * i], v[2 * i + 1]) for i in range(62)]
        else:
            v = [float(x) for x in p[2:]]
            sss_oracle[int(p[1])] = ([complex(x, 0) for x in v[:62]],
                                     [complex(x, 0) for x in v[62:]])

EXACT_TOL = 1e-12
fails = 0


def report(what, d, tol):
    global fails
    ok = d <= tol
    if not ok:
        fails += 1
    return ok


# --- 1. against the closed form -------------------------------------------

print("-- against the closed-form definition (tolerance %.0e)" % EXACT_TOL)
for n2 in (0, 1, 2):
    d = max(abs(a - b) for a, b in zip(L.pss_sequence(n2), pss_reference(n2)))
    print("  PSS  n2=%d vs definition  maxdiff=%.3e  %s"
          % (n2, d, "ok" if report("pss", d, EXACT_TOL) else "MISMATCH"))

worst_def = 0.0
for cid in range(504):
    for sf in (0, 5):
        d = max(abs(a - b) for a, b in zip(L.sss_sequence(cid, sf), sss_reference(cid, sf)))
        worst_def = max(worst_def, d)
print("  SSS  504 cell ids x 2 subframes  maxdiff=%.3e  %s"
      % (worst_def, "ok" if report("sss", worst_def, EXACT_TOL) else "MISMATCH"))

# --- 2. against srsRAN, at srsRAN's own precision --------------------------

print("-- against srsRAN (tolerance derived from its own error)")
pss_err = max(max(abs(a - b) for a, b in zip(pss_reference(n2), pss_oracle[n2]))
              for n2 in (0, 1, 2))
sss_err = max(max(abs(a - b) for a, b in zip(sss_reference(cid, sf), sss_oracle[cid][sf // 5]))
              for cid in range(504) for sf in (0, 5))
# A small multiple of the oracle's error, floored so an exactly-agreeing
# oracle does not force a zero tolerance.
pss_tol = max(pss_err * 4, 1e-9)
sss_tol = max(sss_err * 4, 1e-9)
print("  srsRAN's own error vs the definition: PSS %.3e, SSS %.3e" % (pss_err, sss_err))

for n2 in (0, 1, 2):
    d = max(abs(a - b) for a, b in zip(L.pss_sequence(n2), pss_oracle[n2]))
    print("  PSS  n2=%d vs srsRAN     maxdiff=%.3e (tol %.1e)  %s"
          % (n2, d, pss_tol, "ok" if report("pss", d, pss_tol) else "MISMATCH"))

worst_srs = 0.0
for cid in range(504):
    for (sf, i) in ((0, 0), (5, 1)):
        d = max(abs(a - b) for a, b in zip(L.sss_sequence(cid, sf), sss_oracle[cid][i]))
        worst_srs = max(worst_srs, d)
print("  SSS  504 cell ids x 2 subframes  maxdiff=%.3e (tol %.1e)  %s"
      % (worst_srs, sss_tol, "ok" if report("sss", worst_srs, sss_tol) else "MISMATCH"))

print("MISMATCHES: %d" % fails)
sys.exit(1 if fails else 0)
