#!/usr/bin/env python3
"""
source_auth_ref.py — independent reference for SourceAuthResolution (v2).

Matches the CANONICAL IResolutionCommitment interface:
  verifyCoordinateValue(scopeId, key, value) -> bool
  storage keyed by (scopeId, key); attDigest includes scopeId.

House discipline: recompute, don't trust.

Requires: pycryptodome  (pip install pycryptodome)
"""

from Crypto.Hash import keccak
from enum import IntEnum


class Tier(IntEnum):
    ON_CHAIN = 0
    REVERIFIABLE = 1
    SLASHED_ATTESTOR = 2
    BARE_ATTESTOR = 3


class Verdict(IntEnum):
    UNVERIFIABLE = 0
    VERIFIED = 1
    REFUTED = 2


ZERO32 = b"\x00" * 32


def _b32(x) -> bytes:
    if isinstance(x, int):
        return x.to_bytes(32, "big")
    if isinstance(x, str):
        x = bytes.fromhex(x[2:] if x.startswith("0x") else x)
    assert isinstance(x, (bytes, bytearray))
    return bytes(x).rjust(32, b"\x00")


def _u64_word(x: int) -> bytes:
    assert 0 <= x < (1 << 64)
    return x.to_bytes(32, "big")


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def digest_of(scope_id: bytes, inp: dict) -> bytes:
    """
    Mirror of SourceAuthResolution.digestOf(scopeId, in_):
      keccak256(abi.encode(
        scopeId, schemeId, coordinate, sourceId, key,
        keccak256(valueCommitted),   <- bytes blob hashed to fixed-size
        timePin(uint64), parseRuleCommit, certChainCommit, timeAnchorCommit))
    """
    val_hash = keccak256(inp["valueCommitted"])  # bytes -> bytes32
    enc = b"".join([
        _b32(scope_id),
        _b32(inp["schemeId"]),
        _b32(inp["coordinate"]),
        _b32(inp["sourceId"]),
        _b32(inp["key"]),
        val_hash,                    # already 32 bytes
        _u64_word(inp["timePin"]),
        _b32(inp["parseRuleCommit"]),
        _b32(inp["certChainCommit"]),
        _b32(inp["timeAnchorCommit"]),
    ])
    return keccak256(enc)


def classify(inp: dict, *, now: int, tier0_ok=None, tier2_floor: int = 0) -> Verdict:
    """Mirror of SourceAuthResolution._classify."""
    if _b32(inp["certChainCommit"]) == ZERO32:  return Verdict.UNVERIFIABLE
    if _b32(inp["parseRuleCommit"]) == ZERO32:  return Verdict.UNVERIFIABLE
    if inp["timePin"] == 0:                      return Verdict.UNVERIFIABLE
    if inp["timePin"] > now:                     return Verdict.UNVERIFIABLE
    if not inp["valueCommitted"]:                return Verdict.UNVERIFIABLE

    tier = inp["tier"]

    if tier == Tier.ON_CHAIN:
        if tier0_ok is None:                     return Verdict.UNVERIFIABLE
        res = tier0_ok(inp)
        if res is None:                          return Verdict.UNVERIFIABLE
        ok, sourceId, key, value_attested, timePin, certCommit = res
        if not ok:                               return Verdict.UNVERIFIABLE
        if _b32(sourceId) != _b32(inp["sourceId"]): return Verdict.UNVERIFIABLE
        if _b32(key)      != _b32(inp["key"]):       return Verdict.UNVERIFIABLE
        # tier-0 verifier returns bytes32; contract compares against keccak256(valueCommitted)
        if _b32(value_attested) != keccak256(inp["valueCommitted"]): return Verdict.UNVERIFIABLE
        if timePin        != inp["timePin"]:         return Verdict.UNVERIFIABLE
        if _b32(certCommit)!= _b32(inp["certChainCommit"]): return Verdict.UNVERIFIABLE
        return Verdict.VERIFIED

    if tier == Tier.SLASHED_ATTESTOR:
        if inp.get("stakeBacking", 0) < tier2_floor: return Verdict.UNVERIFIABLE
        return Verdict.VERIFIED

    return Verdict.VERIFIED  # REVERIFIABLE(1) and BARE_ATTESTOR(3): well-formed


class SourceAuthRef:
    """Stateful mirror: commit + verifyCoordinateValue + refute."""

    def __init__(self, *, tier0_ok=None, tier2_floor: int = 0, max_accepted_tier: int = 3):
        # Primary index: (scope_id_bytes, key_bytes) -> record
        self.att = {}
        # Secondary index: digest -> (scope_id, key)
        self.digest_index = {}
        self.tier0_ok = tier0_ok
        self.tier2_floor = tier2_floor
        self.max_accepted_tier = max_accepted_tier

    def commit(self, scope_id, inp: dict, *, now: int, committer: str = "0xcommitter"):
        scope_id = _b32(scope_id)
        key = _b32(inp["key"])
        primary = (scope_id, key)
        d = digest_of(scope_id, inp)

        if primary in self.att:
            assert self.att[primary]["attDigest"] == d, "conflicting attestation: use refute()"
            return d

        v = classify(inp, now=now, tier0_ok=self.tier0_ok, tier2_floor=self.tier2_floor)
        val_hash = keccak256(inp["valueCommitted"])

        self.att[primary] = {
            "attDigest":      d,
            "valueRaw":       val_hash,
            "certChainCommit": _b32(inp["certChainCommit"]),
            "parseRuleCommit": _b32(inp["parseRuleCommit"]),
            "timePin":        inp["timePin"],
            "committedAt":    now,
            "tier":           inp["tier"],
            "verdict":        v,
            "committer":      committer,
            "exists":         True,
        }
        self.digest_index[d] = (scope_id, key)
        return d

    def refute(self, scope_id, key, counter: dict, *, now: int):
        """Inline-classify the counter; does not require it to be pre-committed."""
        scope_id = _b32(scope_id)
        key = _b32(key)
        t = self.att.get((scope_id, key))
        assert t and t["exists"],                     "no such attestation"
        assert t["verdict"] == Verdict.VERIFIED,      "target not verified"
        assert _b32(counter["key"]) == key,           "counter key mismatch"

        counter_value_raw = keccak256(counter["valueCommitted"])
        assert counter_value_raw != t["valueRaw"],    "same value - no conflict"
        assert int(counter["tier"]) <= int(t["tier"]), "counter weaker than target"

        cv = classify(counter, now=now, tier0_ok=self.tier0_ok, tier2_floor=self.tier2_floor)
        assert cv == Verdict.VERIFIED,                "counter not verified"

        t["verdict"] = Verdict.REFUTED

    def verify_coordinate_value(self, scope_id, key, value: bytes) -> bool:
        """Mirror of verifyCoordinateValue(scopeId, key, value)."""
        scope_id = _b32(scope_id)
        key = _b32(key)
        r = self.att.get((scope_id, key))
        if not r or not r["exists"]:               return False
        if r["verdict"] != Verdict.VERIFIED:       return False
        if int(r["tier"]) > self.max_accepted_tier: return False
        if keccak256(value) != r["valueRaw"]:      return False  # adversarial-a guard
        return True


# ---------------------------------------------------------------------------
# Assertion suite
# ---------------------------------------------------------------------------

def _base(scope_id=1, **over):
    val = b"\x00" * 31 + b"\x39"  # abi.encode(uint8(57)) — stand-in for delta.option
    inp = dict(
        schemeId=_b32(b"tlsn-mpc-zk-v1".ljust(32)[:32]),
        coordinate=_b32(2),
        sourceId=_b32(b"example.com/api/price".ljust(32)[:32]),
        key=_b32(2),                # key == coordinate == delta.sourceId
        valueCommitted=val,
        timePin=1_700_000_000,
        parseRuleCommit=_b32(0xAB),
        certChainCommit=_b32(0xCD),
        timeAnchorCommit=ZERO32,
        tier=Tier.REVERIFIABLE,
        stakeBacking=0,
    )
    inp.update(over)
    return scope_id, inp


def run():
    NOW = 1_700_000_500
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL: {name}")

    SID = _b32(42)  # scopeId

    # 1. digest determinism + sensitivity
    _, inp = _base()
    check("digest deterministic", digest_of(SID, inp) == digest_of(SID, inp))
    _, inp2 = _base(valueCommitted=b"\x00" * 31 + b"\x07")
    check("digest sensitive to value",  digest_of(SID, inp) != digest_of(SID, inp2))
    check("digest sensitive to scopeId", digest_of(SID, inp) != digest_of(_b32(99), inp))

    # 2. tier-1 happy path
    r = SourceAuthRef(max_accepted_tier=3)
    _, inp = _base()
    d = r.commit(SID, inp, now=NOW)
    check("tier1 VERIFIED", r.att[(_b32(SID), _b32(inp["key"]))]["verdict"] == Verdict.VERIFIED)
    check("guard7 true (faithful, maxTier=3)",
          r.verify_coordinate_value(SID, inp["key"], inp["valueCommitted"]) is True)

    # 3. guard-7 false: wrong value (adversarial-a)
    check("guard7 false on value mismatch",
          r.verify_coordinate_value(SID, inp["key"], b"\x00" * 32) is False)

    # 4. guard-7 false: wrong key
    check("guard7 false on key mismatch",
          r.verify_coordinate_value(SID, _b32(999), inp["valueCommitted"]) is False)

    # 5. guard-7 false: wrong scopeId
    check("guard7 false on scopeId mismatch",
          r.verify_coordinate_value(_b32(99), inp["key"], inp["valueCommitted"]) is False)

    # 6. maxAcceptedTier floor: tier-3 rejected when floor=1
    r_strict = SourceAuthRef(max_accepted_tier=1)
    _, inp3 = _base(tier=Tier.BARE_ATTESTOR)
    r_strict.commit(SID, inp3, now=NOW)
    check("tier3 VERIFIED in registry", r_strict.att[(_b32(SID), _b32(inp3["key"]))]["verdict"] == Verdict.VERIFIED)
    check("guard7 rejects tier3 when maxTier=1",
          r_strict.verify_coordinate_value(SID, inp3["key"], inp3["valueCommitted"]) is False)

    # also check tier-1 passes same strict instance — use a fresh key to avoid collision with tier-3
    _, inp_t1 = _base(coordinate=_b32(200), key=_b32(200), tier=Tier.REVERIFIABLE)
    r_strict.commit(SID, inp_t1, now=NOW)
    check("guard7 accepts tier1 when maxTier=1",
          r_strict.verify_coordinate_value(SID, inp_t1["key"], inp_t1["valueCommitted"]) is True)

    # 7. UNVERIFIABLE honest-boundary cases
    rU = SourceAuthRef(tier2_floor=10**18)
    # Each case gets a unique key (coordinate) to avoid collisions in rU
    cases = {
        "no cert chain":      _base(coordinate=_b32(100), key=_b32(100), certChainCommit=ZERO32)[1],
        "no parse rule":      _base(coordinate=_b32(101), key=_b32(101), parseRuleCommit=ZERO32)[1],
        "zero timePin":       _base(coordinate=_b32(102), key=_b32(102), timePin=0)[1],
        "future timePin":     _base(coordinate=_b32(103), key=_b32(103), timePin=NOW + 10)[1],
        "empty value":        _base(coordinate=_b32(104), key=_b32(104), valueCommitted=b"")[1],
        "tier0 no verifier":  _base(coordinate=_b32(105), key=_b32(105), tier=Tier.ON_CHAIN)[1],
        "tier2 below floor":  _base(coordinate=_b32(106), key=_b32(106), tier=Tier.SLASHED_ATTESTOR, stakeBacking=1)[1],
    }
    for name, cinp in cases.items():
        dd = rU.commit(SID, cinp, now=NOW)
        rec = rU.att[(_b32(SID), _b32(cinp["key"]))]
        check(f"UNVERIFIABLE: {name}", rec["verdict"] == Verdict.UNVERIFIABLE)
        check(f"guard7 false: {name}",
              rU.verify_coordinate_value(SID, cinp["key"], cinp["valueCommitted"]) is False)

    # 8. tier-2 above floor verifies
    r2 = SourceAuthRef(tier2_floor=10**18)
    _, inp2b = _base(tier=Tier.SLASHED_ATTESTOR, stakeBacking=2 * 10**18)
    r2.commit(SID, inp2b, now=NOW)
    check("tier2 above floor VERIFIED",
          r2.att[(_b32(SID), _b32(inp2b["key"]))]["verdict"] == Verdict.VERIFIED)

    # 9. tier-0 accept/reject
    def ok_v(i): return (True, i["sourceId"], i["key"],
                         keccak256(i["valueCommitted"]), i["timePin"], i["certChainCommit"])
    def bad_v(i): return (False, ZERO32, ZERO32, ZERO32, 0, ZERO32)
    r0ok = SourceAuthRef(tier0_ok=ok_v)
    _, inp0 = _base(tier=Tier.ON_CHAIN)
    r0ok.commit(SID, inp0, now=NOW)
    check("tier0 VERIFIED when verifier ok",
          r0ok.att[(_b32(SID), _b32(inp0["key"]))]["verdict"] == Verdict.VERIFIED)
    r0bad = SourceAuthRef(tier0_ok=bad_v)
    _, inp0b = _base(tier=Tier.ON_CHAIN)
    r0bad.commit(SID, inp0b, now=NOW)
    check("tier0 UNVERIFIABLE when verifier rejects",
          r0bad.att[(_b32(SID), _b32(inp0b["key"]))]["verdict"] == Verdict.UNVERIFIABLE)

    # 10. refute: counter is NOT pre-committed (inline-classify); flips to REFUTED
    rR = SourceAuthRef(max_accepted_tier=3)
    _, inp_t = _base()
    dt = rR.commit(SID, inp_t, now=NOW)
    _, inp_c = _base(valueCommitted=b"\x00" * 31 + b"\xff")  # same key, diff value
    # Do NOT commit inp_c — refute() classifies it inline
    rR.refute(SID, inp_t["key"], inp_c, now=NOW)
    check("refuted target -> REFUTED",
          rR.att[(_b32(SID), _b32(inp_t["key"]))]["verdict"] == Verdict.REFUTED)
    check("guard7 false after refute",
          rR.verify_coordinate_value(SID, inp_t["key"], inp_t["valueCommitted"]) is False)

    # 11. idempotent recommit (same digest -> ok, different digest -> assert)
    rI = SourceAuthRef()
    _, inpI = _base()
    d1 = rI.commit(SID, inpI, now=NOW)
    d2 = rI.commit(SID, inpI, now=NOW)  # identical -> no-op
    check("idempotent recommit same digest", d1 == d2)

    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    import sys
    sys.exit(0 if run() else 1)
