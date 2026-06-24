# Scope Contestation — the completeness layer

*A primitive draft (2026-06-23). The settlement stack proves a verdict is
**faithful**. It cannot prove the observation **scope** was **complete**. This is
the layer that makes incompleteness contestable instead of invisible.*

## The gap

The family stack — OCP/8281 (commitment) · 8004 (identity) · 1833 (bounded
authority) · 8299/8274 (witnessed action) · escrow/8275 (settlement), under
8301 orchestration — guarantees one thing at every layer: the recorded judgment
is **faithful**. Committed before the outcome, recomputable from public data, no
trusted party.

Every layer is downstream of *what the agent chose to observe and commit*. None
of them can see an omission. A recovery agent can honestly miss an asset, emit a
clean WYRIWE receipt, settle owner-bound, nullify correctly, pass
`valid ∧ match ∧ delivery` — and the rescue was provably **incomplete**. The
proof certifies integrity of the recorded observation, never completeness of the
observation set.

This is **E-capture** at system scale: a coordinate that was never instrumented,
so its absence leaves no trace. Formally (Geometry of Knowability): a verdict
over a coordinate set that does not span the minimal sufficient diagnostic
subspace **F★** can be perfectly faithful and still wrong — and nothing in the
stack can tell the difference.

## What this layer does — and does not

Completeness is **not provable a priori**. Enumerating the full coordinate space
ahead of time is exactly the thing E-capture says you cannot do. So this layer
does not prove completeness. It makes **incompleteness contestable**.

- An agent **commits** the coordinate set it observed (e.g. a recovery job's
  `asset_set`), bound to its OCP layer-0 commitment.
- Anyone may **permissionlessly nominate** a coordinate the agent did *not*
  observe, proving on-chain — recomputably — that the coordinate is genuinely
  absent from the declared set.

The registry **adjudicates nothing**. It does **not** decide whether a nominated
coordinate mattered (was in F★). That question is the contestable one it
*surfaces* and makes permanent. It is **not an oracle**.

Its single guarantee: **no omission is structurally invisible.** Every omission
is nominable; once nominated, it is permanent and recomputable from events. That
is the *maximum achievable contestability* — the honest terminus of the
adversarial analysis, made concrete.

## Where it sits

Not in the 0–4 settlement stack. It is an **orthogonal contestability axis** over
the witnessed-action layer, answering the question no existing layer answers:
*was the thing that was witnessed all of what should have been witnessed?* It
binds **down** to OCP/8281 (the scope commits against the same layer-0
commitment) and composes **by reference**, never by dependency — same discipline
as the rest of the family.

## Mechanism

Sorted-Merkle **non-inclusion**. The declared coordinates are committed as a
Merkle root over a **sorted** list. To nominate `c`, the nominator proves one of:

- **interior** — two adjacent declared leaves `lo, hi` (indices `i, i+1`) with
  `lo < c < hi`. Sorted + adjacent ⇒ no declared leaf lies between them ⇒ `c`
  absent.
- **below-min** — `c <` the leaf at index 0.
- **above-max** — `c >` the leaf at index `count−1`.

Orientation and odd-node promotion are derived by the verifier from the **public
`(index, count)` only** — never from prover-supplied flags. Leaves and nodes are
domain-separated (`0x00`/`0x01` prefixes).

**Soundness** (you cannot nominate a coordinate that *was* declared) holds given
the committed list is sorted. Sortedness is the committer's claim — but the
declared set is public (recomputable from OCP layer-0), so sortedness is itself
**publicly recomputable, not trusted**. The layer stays inside the family spine:
recomputable from public data, no layer a trusted party.

Gate discipline matches the stack: cheap checks first (existence → dedupe), the
expensive non-inclusion verify **last**, replay-guarded, CEI — never trusts the
caller.

## Adversarial pre-registration (open, by design)

- **Spam.** Nomination is cheap and permissionless; anyone can nominate any
  genuinely-absent coordinate. A bond would filter noise but needs an
  adjudicator to slash/return — which reintroduces a trusted party. v1 stays
  bondless: the value is **permanence + recomputability** of the claim, not
  filtering. Weighting/filtering is a downstream reputation question.
- **The F★ question is deliberately unadjudicated.** The registry asserts a
  coordinate was *not observed*, never that it *mattered*. It cannot know F★
  either — that is the whole point of E-capture. It converts an invisible
  omission into a visible, permanent, debatable one. Claiming more would be the
  dishonest version.
- **Sortedness assumption.** Soundness rests on the sorted commitment; it is
  publicly auditable, not enforced on-chain (enforcing it on-chain would cost a
  full-set reveal per commit). An unsorted commit harms only the committer's own
  contestability surface; it cannot hide a declared coordinate.
- **Reputation seam.** A reputation axis MAY read nominations as signal; it MUST
  NOT treat a nomination as an adjudicated fault. Same axis-separation as
  Step 7 (reputation reads outcomes, does not produce them).
- **Out of scope for v1:** cross-chain nomination dedupe (per-chain registry),
  bonded/staked nomination, and the F★-relevance challenge game — all deferred,
  flagged, not silently assumed.

## Verification status

- **Core (sorted-Merkle non-inclusion):** independent Python reference
  (`reference/scope_ref.py`) + suite (`test/test_core.py`) — **6364/0**, covering
  membership across sizes 1–40 and every index (incl. odd/promote levels),
  completeness (every absent coordinate provably nominable), soundness (no
  declared coordinate nominable, incl. hand-crafted forgery attempts), and
  cross-root rejection.
- **Contract:** compiles clean on solc 0.8.26, **0 warnings**.
- **On-chain end-to-end (in-process EVM, `evm_test.mjs`):** deploy → commitScope
  → nominate. Absent (below/interior/above) **succeed**; replay **reverts**;
  a **present coordinate reverts** (soundness holds in real EVM execution).
- **Bug caught by running the EVM:** an earlier draft used `committedAt`
  (timestamp) as the existence sentinel — unsafe, since `block.timestamp` can be
  0. Fixed to key existence on `committer != address(0)`.

*forge/gas profiling not run here — foundry's release binaries are blocked by
the sandbox network allowlist. Compile + dual-implementation core + in-process
EVM execution stand in; gas profiling is a quick confirm in a local forge setup.*

## Composition refs

OCP/8281 (layer-0 commitment the scope binds to) · 8299/8274 (the witnessed
action whose scope is being contested) · escrow/8275 (settlement that a sustained
contestation could gate, downstream) · Geometry of Knowability (F★, E-capture —
the formal basis).
