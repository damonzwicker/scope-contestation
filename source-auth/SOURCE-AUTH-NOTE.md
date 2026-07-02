# Source-Auth Leg — completing guard 7 for off-chain facts

*Design draft, in the house register. Layer 2's four-guard `contest()` resolves a
materiality dispute; guard 7 (`verifyCoordinateValue`) is the value-fidelity leg.
For type-1 (chain-native) it recomputes `valueAt(key, blockPin) == claimed`. For
type-2 (off-chain) it returned **false-by-design** — a deliberate deferral to an
orthogonal source-auth leg that was referenced across the group but never built.
This note builds it, proves it, and marks exactly what it cannot do.*

Read `NOTE.md` (Layers 1–2) and `layer3/LAYER3-NOTE.md` (the bond) first. This is
the type-2 completion of guard 7. Everything here composes by reference, not by
dependency.

---

## 0. The gap this closes

Type-1 (pure on-chain data) is the easy ~20%. Type-2 (off-chain facts — news
outcomes, API results, real-world events, **CMMC compliance evidence**) is the
hard ~80%, and today it is a **wall**: a type-2 dispute reverts cleanly at guard 7
with zero state written. Safe, but terminal. The CompletenessBond inherits the
wall — a type-2 bond challenge is "clean deferral forever."

Source-auth turns the wall into a path: guard 7 resolves a type-2 dispute against
an **attested-fetch (zkTLS) commitment**, without reintroducing a trusted third
party. That is the difference between "an elegant on-chain dispute mechanism" and
"a dispute mechanism that works for real-world claims" — which is what makes
Verafile Sentinel defensible in a CMMC audit.

## 1. The one honest reframing (load-bearing — do not blur)

**Source-auth does NOT promote type-2 to type-1. It cannot.** Type-1 recompute
re-derives a value from *public, persistent* chain state — the source is still
there; anyone re-reads it forever. A TLS session is *ephemeral and private*: no
one can re-FETCH the fact. The best possible zkTLS proof does not change this.

What a second party recomputes is not the fact — it is the **proof of the fact**:

> A fixed, portable, non-repudiable attestation that **at pinned time T, an
> authenticated TLS channel to source S returned value V** — where *authenticated*
> means bound to S's own certificate chain (never to a notary key), and
> *non-repudiable* means any party re-runs the proof against public inputs without
> trusting the party who captured it.

The `recompute` verb survives; its object moves from the fact to the proof. This is
exactly the type-1 (chain-native recompute) vs type-2 (off-chain attested)
provenance line the group already settled. Source-auth is the *discipline for the
attested side*, not a promotion of it to the native side.

## 2. Landscape (surveyed current, 2026-06 — summary)

Three architectures (MPC-TLS, Proxy, TEE), but the axis that matters for us is
orthogonal: **signature-trust vs. re-verifiable-proof.**

- **Signature-trust** (Reclaim proxy; Opacity TEE enclave; single MPC notary): a
  trusted attestor *signs* "S returned V at T"; a verifier checks the signature
  against the attestor's key. Reclaim itself notes user↔attestor collusion forges
  transcripts. This reintroduces the trusted party we exist to remove.
- **Re-verifiable-proof** (TLSNotary MPC + ZK path; zkPass hybrid-ZK): the proof is
  a SNARK/transcript-commitment bound to the *server's own* TLS cert. The 2025
  formalization reduces soundness to **{TLS PRF, SNARK soundness, and — only if
  applicable — notary-signature unforgeability}**. The SNARK path drops the third
  term and supports **offline verification by any auditor**.

Maturity: TLSNotary is EF-backed, no-token, `alpha.15`, added Proxy mode May 2026
(faster, weaker) alongside MPC mode (our target). Reclaim is production at 3M+
verifications but proxy-only. Opacity is production, econ-secured, SGX-dependent
(SGX has a long break history). zkPass has a token-entangled verify path. Primus
(ex-PADO) just launched a decentralized-notary net on BNB. **Verdict: build against
the TLSNotary MPC-ZK re-verifiable model as trust-root; admit proxy/TEE only as an
explicitly-marked lower tier.**

## 3. The primitive — observation → digest → commitment → verify (OCP/8281 shape)

`SourceAuthResolution` is a **third `IResolutionCommitment`** alongside
`ChainNativeResolution` (type-1) and the prior `ResolutionCommitment` (type-2
defer). It plugs into the same four-guard `contest()` flow untouched — it is
injected into `Layer2PreCheck`'s constructor exactly where the old resolution was.

```
off-chain:  run zkTLS session vs S  ->  web-proof π  (binds server cert, disclosed
                                        bytes, committed parse rule, pinned time T)
digest:     attDigest = keccak256(abi.encode(
                schemeId, coordinate, sourceId, key, valueAttested,
                timePin, parseRuleCommit, certChainCommit, timeAnchorCommit))
commit:     commitSourceAuth(input)   -> stores record @ attDigest, classifies
                                         verdict (VERIFIED | UNVERIFIABLE),
                                         records tier, EMITS the verdict
verify:     verifyCoordinateValue(coordinate, claimedValue,
                abi.encode(attDigest, minTier))  -> bool faithful   [guard 7]
```

The commitment is keyed by the **recomputable digest itself**. A second party
(Fede, Jimmy) re-derives `attDigest` from π + public data and reads the record
directly — no trusted index, no committer secret. `digestOf` is a `pure` function;
its output was proven byte-identical across an independent Python reference and the
compiled EVM bytecode (see §8).

**Chosen build (this session):** the *digest-commit* path is the primitive
(matches OCP: the contract holds the digest; re-verification of π is off-chain by
any party). The *on-chain SNARK+cert verifier* is left as a **tier-0 upgrade slot**
(`ISourceAuthVerifier`) that lands later WITHOUT touching storage or the guard-7
path. Ship the 80% tonight; upgrade the trust-maximal tier when zkTLS Solidity
verifiers mature.

## 4. The tier map (mirrors the L2 OTS external-clock anchoring)

Same tier discipline as the value-fidelity precedence anchor: tier-0 trust-maximal
down to a survivor floor. Lower ordinal = stronger trust root. Consumers accept
`<= minTier` — the floor is **consumer-chosen, never registry-imposed**.

| Tier | Name | On-chain meaning of VERIFIED | Trust root | zkTLS mechanism |
|---|---|---|---|---|
| 0 | `ON_CHAIN` | SNARK + cert verified **in consensus** | {TLS PRF, SNARK} | TLSNotary MPC-ZK via `ISourceAuthVerifier` |
| 1 | `REVERIFIABLE` | commitment well-formed; π **re-verifiable off-chain** by anyone | {TLS PRF, SNARK}, discharged off-chain | TLSNotary MPC-ZK (digest-commit) |
| 2 | `SLASHED_ATTESTOR` | well-formed **and** stake ≥ floor | {attestor honesty + slashing} | Opacity (econ-secured) |
| 3 | `BARE_ATTESTOR` | well-formed only (survivor floor) | {attestor honesty} | Reclaim proxy |

**Tier honesty (guarantee 6, load-bearing):** for tiers 1–3, on-chain VERIFIED
means the *commitment* is well-formed — **NOT** that π was verified on-chain. Only
tier-0 is verified in consensus. Tier-1's actual re-verification is the off-chain
recompute step (§6). This must not be blurred: a tier-1 record on-chain is a
*claim to be re-verified*, and the re-verification is what discharges it.

## 5. The honest boundary — `UNVERIFIABLE` as a required output

Each of these is recorded and **emitted** as `UNVERIFIABLE` at commit time — a
permanent, readable fact, never a swallowed `false`. Guard 7 then fails closed
(returns `false`; the contest does not separate; the bond stands — safe).

- **Cert chain absent** (`certChainCommit == 0`) → UNVERIFIABLE. You would be
  attesting an *unauthenticated* channel; "authenticated" is half the claim.
- **Value not bound to bytes** (`parseRuleCommit == 0`) → UNVERIFIABLE. Accepting a
  claimant-supplied scalar is the type-2 form of adversarial-a; the value must be
  derived from disclosed transcript bytes under a committed parse rule.
- **Time pin missing/future** (`timePin == 0` or `> block.timestamp`) →
  UNVERIFIABLE. "At time T" is half the claim; a floating timestamp is a forgeable
  one. (On-chain we enforce the floor: non-zero, not-future. *Strong* anchoring —
  that T is real — is the off-chain **OTS external-clock leg**, reusing the L2
  tiered OpenTimestamps anchoring verbatim. `timeAnchorCommit` carries that anchor
  into the digest; on-chain cannot verify OTS, so it is part of §6.)
- **Tier-0 requested without a verifier, or with a failing proof** →
  UNVERIFIABLE. No silent downgrade to a weaker tier.
- **Tier-2 asserted below its slashing floor** (`stakeBacking < tier2StakeFloor`)
  → UNVERIFIABLE. "Value-at-risk exceeds slashable stake" made mechanical.

What the leg **can** prove (tier-0): given {TLS PRF, SNARK soundness}, that S's own
cert authenticated a channel that returned V at T, re-checkable by anyone in
consensus. What it **cannot** prove, ever: that S told the truth (S can lie inside
a perfectly authenticated channel — source honesty is out of scope and must be
named as such), that V is *still* true now (attestations are point-in-time; F★
drifts — temporal-drift discipline from the bond applies), or that an
un-instrumented coordinate exists (**E-capture** — structurally invisible here as
everywhere; source-auth is robust to W-capture, blind to E-capture).

## 6. The off-chain re-verification recipe (the recompute discipline)

For a tier-1 (`REVERIFIABLE`) commitment, a second party discharges it **without
trusting the committer**:

1. Obtain π (the TLSNotary MPC-ZK web-proof) + the disclosed transcript + the
   parse-rule opening. These are public artifacts of the dispute.
2. Verify π against **S's own certificate chain**, validated to a trusted root at
   `timePin`. (Reject if the chain is to anything but S.)
3. Verify the SNARK/transcript-commitment so soundness rests on {TLS PRF, SNARK}
   only — confirm no notary-key assumption is load-bearing.
4. Apply the committed parse rule to the disclosed bytes; recompute `valueAttested`
   from bytes. Confirm it equals the record's value — **never** trust a supplied
   scalar.
5. Recompute `attDigest = digestOf(...)` from the public inputs; confirm it equals
   the on-chain record's key and the emitted `attDigest`.
6. If `timeAnchorCommit != 0`, independently re-derive the OTS/block anchor and
   confirm T (tiered exactly as the L2 clock anchor).

If any step fails → the tier-1 record is **not** discharged; treat as UNVERIFIABLE
in the consuming decision regardless of its on-chain VERIFIED flag. This is the
"recompute, don't trust" contract for the off-chain half.

## 7. Adversarial pre-registration (house discipline — attacks named before merge)

- **Adversarial-a (type-2 form):** contester supplies a value-adversarial witness
  pair. *Caught:* guard 7 compares `claimedValue` against `valueAttested` bound in
  the committed digest; a mismatch → `false`. Proven (§8, adversarial-value case).
- **Notary/attestor collusion (proxy/TEE):** a colluding attestor forges V.
  *Bounded:* such a proof can only enter as tier-2/3; a consumer with `minTier ≤ 1`
  rejects it (proven, tier-floor case). Never silently admitted.
- **Stale/future time pin:** forged T. *Caught:* on-chain floor (non-zero,
  not-future) → UNVERIFIABLE (proven); strong anchoring off-chain via OTS.
- **Value-not-from-bytes:** claimant asserts a scalar. *Caught:* `parseRuleCommit
  == 0` → UNVERIFIABLE (proven); off-chain recompute re-derives from bytes.
- **Digest squat / index poisoning:** commitment keyed by the recomputable digest
  itself; identical facts collide idempotently, distinct facts cannot alias.
- **Tier-0 downgrade:** requesting on-chain verification with no verifier set or a
  failing proof → UNVERIFIABLE, no downgrade (proven).
- **Refute abuse:** a weaker or unverified counter cannot flip a target;
  `refute` requires a VERIFIED counter of `tier ≤ target.tier`, same coordinate,
  different value.

## 8. Status — proven, not asserted

- `SourceAuthResolution.sol` + `ISourceAuthVerifier.sol` +
  `IResolutionCommitment.reconstructed.sol` — **compile clean, solc 0.8.24, 0
  warnings**, 3862-byte runtime.
- Independent Python reference (`source_auth_ref.py`): **28/28** — digest
  determinism/sensitivity, guard-7 truth table, all UNVERIFIABLE boundary cases,
  tier floor, tier-0 accept/reject, refute.
- Real-bytecode EVM cross-check (`evm_test_sa.mjs`, @ethereumjs/vm): **8/8**,
  including **`digestOf` byte-identical across Python and the EVM** — two
  independent stacks agree on the recompute.

## 9. Interface + type layout — CONFIRMED against canonical (Tiago/Fede review)

Both prior open items are closed against the canonical sources in
`TMerlini/hack-ens-recovery` (`scope-contestation-demo/contracts/src/`):

- **`IResolutionCommitment.sol`** — now the canonical signature verbatim
  (`verifyCoordinateValue(bytes32 scopeId, bytes32 key, bytes value)`,
  plus `commitResolution`, `resolutionRootOf`, `verifyValueFidelity`). No longer a
  reconstruction.
- **`Vote` layout** — confirmed `struct Vote { bytes32 sourceId; uint8 option; }`
  (ScopeTypes.sol, lines 24–27). `option` is a `uint8` enum discriminant, **not**
  an opaque `bytes` blob, and the wire shape is `Vote[]` (array of structs), **not**
  parallel arrays. `_decodeVotes` now decodes `abi.decode(a, (Vote[]))` and reads
  `sourceId`/`option` — the same bytes `MajorityClassifier` decodes
  (`abi.decode(b, (Vote[]))` in both `classify` and `_plurality`). The UNVERIFIED
  marker is removed.

**Two commitments, not one — do not conflate (Tiago's digest-path point).**
There are two distinct hashes in this stack, and this leg touches only one:

- `MajorityClassifier.classificationDigest` commits `keccak256(a)` and
  `keccak256(b)` — raw keccak over the canonical `abi.encode(Vote[])` bytes. It
  never re-encodes. **Guard 7 (`verifyCoordinateValue`) does not decode votes at
  all** — it compares `keccak256(value)` against the committed attestation's
  `valueRaw`. So the source-auth leg is *already* on the classifier's exact bytes;
  there is no drift surface on the guard-7 path.
- `resolutionRootOf(scopeId)` is a **separate** commitment, owned by this contract:
  `commitResolution` stores it, `verifyValueFidelity` recomputes it. The scheme is
  `leaf_i = keccak256(abi.encode(sourceId_i, option_i))`, `root =
  keccak256(abi.encode(sortedLeaves))`, sorted ascending on `sourceId`
  (truncation/duplicate resistance). Because this contract owns both the commit and
  the recompute, the scheme is internally consistent by construction — the decode
  round-trip is confined to the bulk-fidelity path and proven byte-identical across
  three stacks (Python, ethers, Solidity bytecode).

  *Design note for merge:* if the group prefers `resolutionRoot` to be a bare
  `keccak256(a)` over the canonical `Vote[]` blob (matching the classifier's own
  commitment style and deleting the decode round-trip entirely per Tiago's
  suggestion), that is a one-line change to `verifyValueFidelity`/`commitResolution`
  and removes `_recomputeRoot`/`_decodeVotes` wholesale. Kept as sorted-leaf here
  because it preserves per-leaf truncation resistance and matches the prior
  `ResolutionCommitment` semantics; flagged for the group's call.

## 10. Build plan / grant-narrative anchor

**Narrative:** *We built the trustless verification stack. Scope contestation
(L1), materiality (L2), and settlement-via-survived-contestation (L3) are live and
proven. The last missing primitive is trustless off-chain fact attestation —
guard 7 for the 80% of claims that are not pure on-chain data. Here is the design,
grounded in a current survey of what attested-fetch can actually deliver, tiered
honestly from consensus-verified (tier-0) to survivor-floor (tier-3), with
`UNVERIFIABLE` a required output and the recompute discipline preserved for the
off-chain half. It directly completes Jimmy's four-link trustless-AI stack (scope
→ provenance → verification → settlement) and unblocks ERC-8275.*

**Sequenced work:**
1. **[this session — done]** Digest-commit primitive + tier map + honest boundary,
   compiled and proven against an independent reference and the real EVM.
2. Confirm/adapt against canonical `IResolutionCommitment` (§9); wire
   `SourceAuthResolution` into `Layer2PreCheck` in place of the type-2 defer; run
   the existing 26/26 suite green with the type-2 path now *resolving*.
3. Off-chain re-verification kit (§6) as an independent re-deriver (Fede's
   recompute discipline) — a CLI that takes π and re-derives the digest + value.
4. `parseRuleCommit` scheme: pin a canonical, publicly-reproducible parse-rule
   format (the value-from-bytes commitment) — the one genuinely unsolved piece.
5. Tier-0 `ISourceAuthVerifier` against TLSNotary MPC-ZK when a production Solidity
   verifier is viable; drop it into the slot — no storage change.
6. CMMC framing for Verafile Sentinel: SSP/POA&M evidence as tier-1/tier-0
   attestations; the November 2026 L2 enforcement deadline as the urgency driver.
