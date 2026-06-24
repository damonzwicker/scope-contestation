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
- **Bonded security audit.** An auditing agent commits its reviewed scope set
  (the code paths and selectors it claims to have examined) bound to a signed
  verdict, with a bond escrowed settle-once against that commitment. A slash fires
  if and only if a challenger exhibits both (a) a nomination — a code path
  provably absent from the committed scope set (this registry, w-independent) —
  and (b) a replayable exploit transaction over that path. Because an exploit PoC
  is itself a publicly recomputable witness, the classification function w
  ("secure vs exploitable") is free: no abstract w needs to be published or
  adjudicated. The slash never fires on opinion, only on a replayable exploit
  against a provably-unreviewed path. This is the cleanest worked instance of
  the full stack composing — witnessed verdict + settle-once escrow +
  scope-contestation — on a real accountability problem: liability without
  trusting the auditor, correctness without claiming it.

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
    event ScopeCommitted(bytes32 indexed scopeId, bytes32 indexed commitmentHash, bytes32 scopeRoot, address committer);
    event CoordinateNominated(bytes32 indexed scopeId, bytes32 indexed coordinate, address nominator);

    function commitScope(bytes32 commitmentHash, bytes32 scopeRoot) external returns (bytes32 scopeId);
    function nominate(bytes32 scopeId, bytes32 coordinate, bytes calldata proof) external;

    function verifyAbsence(bytes32 scopeId, bytes32 coordinate, bytes calldata proof) external view returns (bool);
    function isNominated(bytes32 scopeId, bytes32 coordinate) external view returns (bool);
    function getScope(bytes32 scopeId) external view returns (bytes32 commitmentHash, bytes32 scopeRoot, address committer);
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
4. **Cardinality binding (truncation resistance).** A conforming scheme MUST
   non-malleably bind the scope's cardinality to its commitment (e.g. committed
   within `scopeRoot`), such that `verifyAbsence` cannot be satisfied against a
   proper prefix (truncation) of the committed set. Cardinality carried only
   within an opaque proof that is not itself bound to the commitment does NOT
   satisfy this requirement.
5. **Recomputable.** An absence proof MUST be verifiable from public data alone.
6. **Permanent.** A successful nomination MUST be recorded and MUST NOT be
   deletable or modifiable afterward.
7. **Non-adjudicating.** The registry MUST NOT decide whether a nominated
   coordinate mattered.

### `commitScope`

`scopeId` MUST be derived (not caller-supplied) and MUST bind the committer so a
scope cannot be squatted by a third party committing the same root first.
`scopeRoot` MUST bind the scope's cardinality per guarantee 4. Scope cardinality
is intentionally NOT a parameter of this interface; it is implementation data
bound into `scopeRoot`. Implementations MAY surface it through their own extended,
non-normative event or view for forensic readability, which MUST NOT be relied
upon for soundness.

### `nominate`

MUST revert if the scope does not exist, if the coordinate is present in the
scope, if the coordinate has already been nominated for that scope, or if the
proof attempts to satisfy absence against a truncated set (cardinality not
matching the binding in `scopeRoot`). On success it MUST record the nomination
permanently and emit `CoordinateNominated`.

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

**Cardinality is not in the signature (the `count` decision).** An earlier draft
carried `count` in `commitScope`. Because the interface's spine is "guarantees,
not wire format" (opaque proof, non-portable schemes, optional scheme id), an
explicit cardinality field was the one place a scheme-specific artifact leaked
into the normative surface. It is removed; cardinality is bound into `scopeRoot`
instead (guarantee 4). The guarantee the field implicitly provided — resistance
to truncation/omission — does not disappear with the field; it is promoted to a
normative requirement, because cardinality carried in an unbound proof would let a
prover understate the set size and satisfy `verifyAbsence` against a proper
prefix. Implementations keep cardinality as a forensic convenience outside the
normative surface.

## Backwards Compatibility

No backwards compatibility issues. This is a new interface.

## Reference Implementation

The reference implementation uses sorted-Merkle non-inclusion, with cardinality
bound into the commitment as `scopeRoot = H(merkleRoot, count)` (guarantee 4).

- **Interface, registry, and verification record** — an independent
  re-implementation of the proof core and a soundness/completeness test suite
  (proof core: 6,364 cases covering membership across tree sizes and indices,
  completeness for every absent coordinate, and soundness including adversarial
  forgery and cross-root attempts; Solidity: clean compile; Foundry: 10/10;
  in-process EVM end-to-end):
  https://github.com/damonzwicker/scope-contestation

- **Live worked example over a real asset-recovery job** — deployed on the
  Sepolia testnet, where "did the recovery include everything?" becomes an
  on-chain, permissionless, recomputable question against an actual job. Includes
  a truncation test: nominating a *declared* coordinate by understating the count
  and proving against a proper prefix is rejected, because
  `H(root(prefix), N-1) != H(root(full), N)`:
  https://github.com/TMerlini/hack-ens-recovery/tree/main/scope-contestation-demo

Live Sepolia reference deployment:

- `ScopeContestationRegistry`: `0xB4012790CC5A9f237Cb570C5e5150912df3E723F`
- A recovery job's observed asset set committed as a scope, bound to the job's
  commitment; a non-observed asset successfully nominated (the omission made
  permanent); the nomination of a *declared* asset reverts with "coordinate is in
  scope"; a truncation attempt reverts on the cardinality binding — together
  demonstrating soundness against a live job.

The non-inclusion construction: declared coordinates are committed as a Merkle
root over a sorted list, bound with the count; absence of a coordinate `c` is
proven by an adjacent declared pair straddling `c` (interior), or by `c` falling
below the minimum or above the maximum declared coordinate. Verifier orientation
is derived from public `(index, count)` only; leaves and nodes are
domain-separated. Soundness rests on the committed list being sorted, which is
publicly recomputable from the declared set (guarantee 3), and on the cardinality
binding (guarantee 4).

## Security Considerations

- **Soundness depends on the well-formedness precondition.** See guarantee 3. For
  the reference scheme, soundness holds only if the committed coordinate list is
  sorted; sortedness is publicly recomputable from the declared set, so it is an
  auditable property rather than a trusted one.
- **Truncation / omission.** Without cardinality bound to the commitment
  (guarantee 4), a prover could understate the set size and satisfy
  `verifyAbsence` against a proper prefix of the committed set, making a declared
  coordinate appear absent. Binding cardinality into `scopeRoot` closes this; the
  reference implementation includes an adversarial test that a truncated proof is
  rejected.
- **Spam.** Nomination is permissionless and cheap; any genuinely-absent
  coordinate can be nominated. Filtering/weighting is a downstream concern (e.g. a
  reputation layer). Bonded nomination is out of scope for this version because
  bonding requires an adjudicator, which would violate the non-adjudication
  guarantee.
- **Non-adjudication.** A nomination asserts only that a coordinate was not
  observed, never that it was relevant. Consumers MUST NOT treat a nomination as
  an adjudicated fault.
- **Auditor truncation.** In a bonded-audit instance, the reviewed scope set is
  a scope-contestation scope and inherits the cardinality-binding requirement
  (guarantee 4). Without it, an auditor could understate the count of reviewed
  paths and retroactively claim an exploited path was never in scope, evading
  nomination. The cardinality binding closes this: the auditor's claimed scope
  is fixed at commit time and cannot be shrunk post-hoc.
- **Coordinate canonicalization.** A non-canonical mapping undermines the
  practical completeness guarantee; see Specification.
- **Cross-chain replay.** Nomination de-duplication is per-deployment. Cross-chain
  uniqueness is out of scope for this version.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE).
