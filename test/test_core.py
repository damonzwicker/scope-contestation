"""
Soundness + completeness tests for the Scope Contestation core.

Run: python3 test/test_core.py
"""
import os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reference"))
from scope_ref import (k256, leaf_hash, root_of, membership_siblings,
                       verify_membership, verify_non_inclusion, make_non_inclusion)

def b32(i: int) -> bytes:
    return i.to_bytes(32, "big")

PASS = 0; FAIL = 0
def check(cond, name):
    global PASS, FAIL
    if cond: PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")

random.seed(8281)

# ---------------------------------------------------------------------------
# 1. MEMBERSHIP across every size 1..40 and every index, incl. odd/promote levels
# ---------------------------------------------------------------------------
for n in range(1, 41):
    coords = sorted({random.randrange(1, 10**9) for _ in range(n)})
    coords = [b32(x) for x in coords]
    n = len(coords)
    root = root_of(coords)
    for idx in range(n):
        sibs = membership_siblings(coords, idx)
        check(verify_membership(leaf_hash(coords[idx]), idx, n, sibs, root),
              f"membership n={n} idx={idx}")
        # wrong leaf at same position must fail
        bad = leaf_hash(b32(random.randrange(10**9, 2*10**9)))
        check(not verify_membership(bad, idx, n, sibs, root),
              f"membership-reject-wrong-leaf n={n} idx={idx}")

# ---------------------------------------------------------------------------
# 2. COMPLETENESS: every NON-declared coordinate gets a valid non-inclusion proof
#    (below-min, above-max, and interior gaps), across many tree sizes
# ---------------------------------------------------------------------------
for n in range(1, 41):
    # use spaced values so there are interior gaps to nominate into
    vals = sorted(random.sample(range(10, 10_000), n))
    coords = [b32(v * 10) for v in vals]   # multiply to leave gaps
    n = len(coords); root = root_of(coords)
    intvals = [int.from_bytes(c, "big") for c in coords]

    # below min
    c = b32(intvals[0] - 1)
    p = make_non_inclusion(coords, c)
    check(p is not None and verify_non_inclusion(c, root, n, p), f"nonincl below-min n={n}")

    # above max
    c = b32(intvals[-1] + 1)
    p = make_non_inclusion(coords, c)
    check(p is not None and verify_non_inclusion(c, root, n, p), f"nonincl above-max n={n}")

    # interior gaps
    for i in range(n - 1):
        if intvals[i] + 1 < intvals[i + 1]:
            c = b32(intvals[i] + 1)
            p = make_non_inclusion(coords, c)
            check(p is not None and verify_non_inclusion(c, root, n, p),
                  f"nonincl interior n={n} gap={i}")

# ---------------------------------------------------------------------------
# 3. SOUNDNESS (the load-bearing one): a DECLARED coordinate must be
#    impossible to prove non-included -- both via the honest prover (returns None)
#    AND via adversarial hand-crafted forgery attempts.
# ---------------------------------------------------------------------------
for n in range(1, 41):
    vals = sorted(random.sample(range(10, 10_000), n))
    coords = [b32(v * 10) for v in vals]
    n = len(coords); root = root_of(coords)

    for idx in range(n):
        present = coords[idx]
        # honest prover cannot construct a proof
        check(make_non_inclusion(coords, present) is None,
              f"soundness honest-None n={n} idx={idx}")

        # adversarial: try to forge an interior straddle using REAL neighbors.
        # pick the genuine predecessor/successor leaves and try to pass them off
        # as an adjacent pair straddling `present`.
        forged_attempts = []
        if 0 < idx < n - 1:
            # neighbors of present are at idx-1 and idx+1; they are NOT adjacent
            # (present sits between them), so idxLo+1 != idxHi -> must fail.
            forged_attempts.append({
                "case": 0, "loCoord": coords[idx-1], "hiCoord": coords[idx+1],
                "idxLo": idx-1, "idxHi": idx+1,
                "sibsLo": membership_siblings(coords, idx-1),
                "sibsHi": membership_siblings(coords, idx+1),
            })
            # try claiming adjacency by lying idxHi = idxLo+1 while using idx+1's leaf
            forged_attempts.append({
                "case": 0, "loCoord": coords[idx-1], "hiCoord": coords[idx+1],
                "idxLo": idx-1, "idxHi": idx,        # lie: claim consecutive
                "sibsLo": membership_siblings(coords, idx-1),
                "sibsHi": membership_siblings(coords, idx+1),  # but real sibs are for idx+1
            })
        # below-min forgery for a present non-min element
        if idx > 0:
            forged_attempts.append({
                "case": 1, "loCoord": coords[0],
                "sibsLo": membership_siblings(coords, 0),
            })  # requires present < coords[0]; false since present>=coords[0]
        # above-max forgery for a present non-max element
        if idx < n - 1:
            forged_attempts.append({
                "case": 2, "hiCoord": coords[-1],
                "sibsHi": membership_siblings(coords, n-1),
            })  # requires present > coords[-1]; false
        for fp in forged_attempts:
            check(not verify_non_inclusion(present, root, n, fp),
                  f"soundness reject-forgery n={n} idx={idx}")

# ---------------------------------------------------------------------------
# 4. Cross-root forgery: a valid proof under root A must not verify under root B
# ---------------------------------------------------------------------------
A = [b32(x) for x in sorted(random.sample(range(1, 10**6), 12))]
B = [b32(x) for x in sorted(random.sample(range(10**6, 2*10**6), 12))]
rootA, rootB = root_of(A), root_of(B)
ca = b32(int.from_bytes(A[0], "big") - 1)
pa = make_non_inclusion(A, ca)
check(verify_non_inclusion(ca, rootA, len(A), pa), "cross-root valid-under-A")
check(not verify_non_inclusion(ca, rootB, len(B), pa), "cross-root reject-under-B")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
