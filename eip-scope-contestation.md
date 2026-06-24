---
eip: <TBD>
title: Scope Contestation Registry
description: A permissionless registry that makes the incompleteness of an agent's committed observation scope contestable and recomputable on-chain.
author: Damon Zwicker (@damonzwicker), Tiago Merlini (@TMerlini), Jimmy Shi (@JimmyShi22), Fede (@babyblueviper1)
discussions-to: <Ethereum Magicians thread URL — create before filing>
status: Draft
type: Standards Track
category: ERC
created: 2026-06-24
requires: 165
---

## Abstract

This standard defines an interface for a *scope contestation registry*: a
permissionless mechanism by which an actor commits the set of coordinates it
observed (its **observation scope**), bound to an external commitment, and any
party may prove on-chain that a specific coordinate was **absent** from that
committed set. The registry records such proofs permanently and recomputably. It
**adjudicates nothing** — it does not decide whether a missing coordinate
mattered. Its single guarantee is that no omission from a committed scope is
structurally invisible: every omission is nominable, and once nominated, it is
permanent and verifiable from public data.

## Motivation

Verifiable-agent systems can prove that a recorded verdict is *faithful* — that
it was committed before its outcome, is recomputable from public data, and
depends on no trusted party. They cannot prove that the **observation scope**
behind the verdict was *complete*. An agent can honestly (or deliberately) omit a
coordinate from what it observed, emit a fully valid signed receipt, and pass
every downstream verification check. The proof certifies the integrity of the
*recorded* observation, never the *completeness* of the observation set.

This is a structural blind spot: a system records what is submitted to it and has
nothing to say about what was never submitted. An omitted coordinate leaves no
trace. Completeness cannot be proven a priori — enumerating the full space of
possible coordinates ahead of time is precisely the thing the blind spot
prevents. What *can* be provided is **contestability**: a mechanism that converts
an invisible omission into a permanent, permissionless, recomputable claim.

Concrete instances:

- **Asset recovery.** An agent commissioned to recover assets commits the
  asset set it will search. If it omits a known attacker address, anyone holding
  that address can nominate it, producing permanent on-chain proof the agent did
  not include it in scope.
- **Governance / assessment.** A decision made over an incomplete observation set
  passes every receipt check while resting on a flawed input. Nomination makes
  the omitted input contestable rather than silent.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "MAY" in this document are to be
interpreted as described in RFC 2119 and RFC 8174.

### Definitions

- **Coordinate** — an opaque `bytes32` identifying one element of an observation
  set. The mapping from a real-world object to its `bytes32` coordinate is the
  committing application's responsibility and MUST be deterministic and publicly
  reproducible (see Coordinate Canonicalization).
- **Scope** — a committed set of coordinates, bound to an external commitment.
- **Nomination** — a proof, submitted by any party, that a coordinate is absent
  from a committed scope.

### Interface

Conformant contracts MUST implement `IScopeContestation` and SHOULD implement
ERC-165.

```solidity
interface IScopeContestation {
    event ScopeCommitted(bytes32 indexed scopeId, bytes32 indexed commitmentHash, bytes32 scopeRoot, uint256 count, address committer);
    event CoordinateNominated(bytes32 indexed scopeId, bytes32 indexed coordinate, address nominator);

    function commitScope(bytes32 commitmentHash, bytes32 scopeRoot, uint256 count) external returns (bytes32 scopeId);
    function nominate(bytes32 scopeId, bytes32 coordinate, bytes calldata proof) external;

    function verifyAbsence(bytes32 scopeId, bytes32 coordinate, bytes calldata proof) external view returns (bool);
    function isNominated(bytes32 scopeId, bytes32 coordinate) external view returns (bool);
    function getScope(bytes32 scopeId) external view returns (bytes32 commitmentHash, bytes32 scopeRoot, uint256 count, address committer);
}
```

### Normative guarantees

A conformant implementation MUST satisfy all of the following.

1. **Nominable.** Every coordinate genuinely absent from a committed scope MUST
   be nominable by any caller. A conformant proof scheme MUST be able to prove
   non-membership for every non-member.
2. **Sound.** A coordinate present in a committed scope MUST NOT be nominable;
   `nominate` MUST revert for it.
3. **Well-formedness precondition.** If a proof scheme's soundness depends on a
   structural property of the committed representation (for example, the
   reference scheme requires a *sorted* coordinate set), that property MUST be
   publicly recomputable from data the system already exposes. Soundness MUST NOT
   depend on any property knowable only to the committer. An implementation MUST
   NOT claim conformance for a scheme whose soundness rests on a non-recomputable
   assumption.
4. **Recomputable.** An absence proof MUST be verifiable from public data alone.
5. **Permanent.** A successful nomination MUST be recorded and MUST NOT be
   deletable or modifiable afterward.
6. **Non-adjudicating.** The registry MUST NOT decide whether a nominated
   coordinate mattered.

### `commitScope`

`scopeId` MUST be derived (not caller-supplied) and MUST bind the committer so a
scope cannot be squatted by a third party committing the same root first. `count`
MUST be greater than zero.

### `nominate`

MUST revert if the scope does not exist, if the coordinate is present in the
scope, or if the coordinate has already been nominated for that scope. On success
it MUST record the nomination permanently and emit `CoordinateNominated`.

### `verifyAbsence`

A read-only check that reflects the absence predicate ONLY. It MUST NOT change
state and MUST be recomputable from public data alone. It does not check scope
existence or replay; those are enforced additionally by `nominate`. It exists so
a consumer (for example, an escrow) can treat absence as evidence without
producing the permanent record.

### Coordinate canonicalization

Soundness and completeness are defined over `bytes32` equality only. A
non-canonical real-world-to-`bytes32` mapping voids the completeness guarantee in
practice (the same object under two encodings reads as two coordinates). This
standard does not define the mapping; it requires that one exist and be public.

### Authentication scope

The registry MUST NOT be assumed to authenticate that `committer` is entitled to
commit against `commitmentHash`. Binding an actor to an external commitment is
out of scope and is the identity layer's concern.

## Rationale

**Interface/implementation split.** The proof scheme is opaque (`bytes proof`).
The standard fixes the guarantees, not a wire format, so absence-proof schemes
(sorted-Merkle non-inclusion, range proofs, other accumulators) can evolve
without changing the interface. Proofs are NOT portable across implementations.

**`verifyAbsence` as a read-only surface.** Separating the absence predicate
(`verifyAbsence`, view) from enforcement (`nominate`, state-changing) lets a
consumer — e.g. an escrow — treat absence as evidence without producing the
permanent record, keeping enforcement in one place.

**Motivating binding.** The standard treats `commitmentHash` as opaque. The
motivating binding is a recomputable observation-commitment primitive
(observation -> digest -> on-chain commitment -> verify-inclusion), against which
the scope and downstream verdicts share a common commitment. This is referenced
as motivation only and is not a normative dependency.

**Open question — `count`.** `count` is carried in `commitScope` because
index-based schemes (the reference sorted-Merkle boundary cases) need cardinality
on-chain; pure-accumulator schemes do not. The alternative is to commit
cardinality inside `scopeRoot` for a fully scheme-agnostic signature, at the cost
of changing the reference implementation. This is an open question for discussion.

## Backwards Compatibility

No backwards compatibility issues. This is a new interface.

## Reference Implementation

The reference implementation uses sorted-Merkle non-inclusion.

- **Interface, registry, and verification record** — an independent
  re-implementation of the proof core and a soundness/completeness test suite
  (proof core: 6,364 cases covering membership across tree sizes and indices,
  completeness for every absent coordinate, and soundness including adversarial
  forgery and cross-root attempts; Solidity: clean compile; Foundry: 10/10;
  in-process EVM end-to-end):
  https://github.com/damonzwicker/scope-contestation

- **Live worked example over a real asset-recovery job** — deployed on the
  Sepolia testnet, where "did the recovery include everything?" becomes an
  on-chain, permissionless, recomputable question against an actual job:
  https://github.com/TMerlini/hack-ens-recovery/tree/main/scope-contestation-demo

Live Sepolia reference deployment:

- `ScopeContestationRegistry`: `0xB4012790CC5A9f237Cb570C5e5150912df3E723F`
- A recovery job's observed asset set committed as a scope, bound to the job's
  commitment; a non-observed asset successfully nominated (the omission made
  permanent); the nomination of a *declared* asset reverts with "coordinate is in
  scope", demonstrating soundness against a live job.

The non-inclusion construction: declared coordinates are committed as a Merkle
root over a sorted list; absence of a coordinate `c` is proven by an adjacent
declared pair straddling `c` (interior), or by `c` falling below the minimum or
above the maximum declared coordinate. Verifier orientation is derived from
public `(index, count)` only; leaves and nodes are domain-separated. Soundness
rests on the committed list being sorted, which is publicly recomputable from the
declared set (per guarantee 3).

## Security Considerations

- **Soundness depends on the well-formedness precondition.** See guarantee 3. For
  the reference scheme, soundness holds only if the committed coordinate list is
  sorted; sortedness is publicly recomputable from the declared set, so it is an
  auditable property rather than a trusted one.
- **Spam.** Nomination is permissionless and cheap; any genuinely-absent
  coordinate can be nominated. Filtering/weighting is a downstream concern (e.g. a
  reputation layer). Bonded nomination is out of scope for this version because
  bonding requires an adjudicator, which would violate the non-adjudication
  guarantee.
- **Non-adjudication.** A nomination asserts only that a coordinate was not
  observed, never that it was relevant. Consumers MUST NOT treat a nomination as
  an adjudicated fault.
- **Coordinate canonicalization.** A non-canonical mapping undermines the
  practical completeness guarantee; see Specification.
- **Cross-chain replay.** Nomination de-duplication is per-deployment. Cross-chain
  uniqueness is out of scope for this version.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE).
