# Layer 3 — The Completeness Bond

*Design draft. Layers 1 and 2 attack a scope. Layer 3 defends one — and is the
only place the stack produces a positive completeness signal, the only kind the
framework permits: completeness earned through survived contestation, never
proven.*

## The gap this closes

The stack as built is a falsification engine with no termination condition and no
defense side:

- **Layer 1** proves a coordinate was *not observed*. (falsifies presence)
- **Layer 2** proves an unobserved coordinate *mattered*. (falsifies sufficiency, per-coordinate)

Both are attacks. Nothing in the stack produces "this scope is complete" — and
nothing can, by the framework's own result: you cannot enumerate the full
coordinate space a priori (E-capture), so completeness is never provable. You can
nominate omissions forever and never reach "done."

The consequence nobody has named: an honest, thorough agent has **no way to accrue
standing for getting it right**. It can only avoid being nominated. The first
question any real client asks — "which agent is actually good?" — the stack can
only answer "the ones nobody happened to catch." That is the missing half.

## The thesis: sufficiency, survived

The honest move is not to prove completeness but to **stake** it and let it
**survive**. A party posts a bonded claim that a committed scope is *sufficient*
under a public classification function w — a standing, funded invitation to
falsify. It can never be proven. It can only stand. The longer it stands under an
open bounty, the stronger the signal — exactly as an unclaimed bug bounty live for
two years outweighs a fresh audit. **Lindy completeness.**

The strength of the signal lives in the **unclaimed standing bounty**, not in a
proof. Survival under a large funded bounty is strong evidence; survival with
nothing at stake is meaningless. The bond *is* the evidence.

## The core design decision: what slashes the bond

This is the decision that makes Layer 3 coherent rather than worthless.

- If a **bare Layer-1 omission** slashes the bond, "complete" means *nothing
  omitted* — impossible (E-capture), so every bond dies and the signal is noise.
- If a **Layer-2 materiality proof** is required, "complete" means *no material
  omission under w* — achievable, and exactly **F★-completeness**: the minimal
  *sufficient* set. You don't need everything; you need everything that matters.

So the bond is a claim of **sufficiency, not exhaustiveness**, and it is slashable
only by a Layer-2 materiality proof — a coordinate that is both absent from the
committed scope (Layer 1) *and* material under the committed w (Layer 2). A bare
omission is not a defect; a *material* omission is. This is the paper's distinction
(F★ minimal-sufficient) load-bearing in an economic primitive.

A completeness bond is therefore always **relative to a w**: the committer claims
"my scope is sufficient *under this w*." That is the most that can honestly be
claimed, and it inherits Layer 2's pre-commitment discipline directly.

## Mechanism

```
Layer 1:  commitScope            -> cardinality-bound scopeRoot (guarantee 4)
Layer 3:  postBond(scopeId, wCommitment, term)   [stake = standing bounty, locked]
              the claim: "scopeId is sufficient under wCommitment for `term`"
          --- the bond stands, funded, open to challenge ---
Layer 3:  challenge(bondId, X, materialityProof)
              valid iff  X absent from the bound scopeRoot (Layer 1)
                    AND  X material under wCommitment (Layer 2 witness pair)
              -> slash bounty to challenger; bond resolves
          OR
          term passes unchallenged
              -> reclaim; survival signal = full term stood under the bounty
```

The challenge verifies through the Layer-2 verifier configured for the committed
`wCommitment`, and the Layer-1 absence leg runs against the exact cardinality-bound
`scopeRoot`. Both bindings are inherited, not re-implemented — Layer 3 is the
escrow + signal wrapper over the Layers 1/2 it composes.

## The survival signal

`survival(bondId)` exposes only raw facts: stake, start, term, whether and when
challenged/resolved. It computes **no verdict**. "Survived this much contestation
pressure" is a fact; "is complete" is the consumer's interpretation — the
reputation axis, a client choosing an agent, an escrow setting terms. Same
non-adjudicating discipline as Layer 1: the registry surfaces, it never decides.

A weighting a consumer might apply (illustrative, not normative): signal rises with
stake × duration-survived, and is meaningful only to the extent the bounty made
challenging profitable. The registry provides the inputs; the weighting is theirs.

## Adversarial pre-registration

- **Withdrawal gaming → non-withdrawable term.** If the staker could pull the bond
  on seeing a challenge form, survival would be fake. The stake is locked for the
  full term, no early exit. The fixed, non-withdrawable term *is* the integrity
  mechanism; survival means something only because exit was impossible while the
  invitation stood.
- **Self-challenge is self-incriminating, not profitable.** A staker challenging
  their own bond pays the bounty to themselves (net ~zero minus gas) while creating
  a *permanent public record of a material omission* against their own scope. The
  slash going to the challenger makes self-challenge self-defeating.
- **Griefing is filtered by the proof.** A challenge requires a valid Layer-2
  materiality proof (pre-committed public w, witness pair isolating X, anchored to
  the bound scopeRoot). There is no "frivolous valid challenge" — a valid proof *is*
  a real material omission. No challenger bond is needed; the proof is the cost.
- **Temporal drift → renewal, not permanence.** A bond asserts sufficiency for its
  term only. F★ drifts. Ongoing coverage is a chain of renewed bonds; an expired or
  un-renewed bond reads as a stale claim. Drift is handled by making the claim
  explicitly time-bounded rather than pretending completeness is permanent.
- **Underwriting is allowed by design.** `bondedParty` need not be the committer —
  a third party may stake on an agent's sufficiency, an underwriting/insurance
  market for completeness. The signal accrues to the staker; the risk is theirs.
- **What it does NOT do.** Liability ≠ correctness. A survived bond is not proof the
  scope is sufficient; it is evidence no one has shown otherwise under a funded
  bounty. The chain certifies "stood `term` under bounty `B`, unchallenged," never
  "is complete."

## Dependencies / status

This is a **design draft**, not a verified implementation. The interface compiles
clean (solc 0.8.26, zero warnings). The reference implementation's `challenge`
path depends on the Layer-2 pre-check verifier shape (witness-pair format + how the
`IAgentVerifier` proof carries the Layer-1 absence leg), which the group is still
specifying — so the reference impl waits on Layer 2, the same way the Layer-2
conformance conditions wait on the pre-check contract. The interface and the
mechanism are ready ahead of that.

## Composition refs

Layer 1 (IScopeContestation — cardinality-bound scopeRoot, guarantee 4) ·
Layer 2 (materiality under pre-committed public w; IAgentVerifier pre-check) ·
settle-once escrow axis (the bond is inverted escrow: pays on survival, slashes on
proven material omission) · Geometry of Knowability (F★ minimal-sufficiency — the
basis for "sufficiency, not exhaustiveness").
