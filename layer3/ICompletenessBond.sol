// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title ICompletenessBond
/// @notice Layer 3 of the scope-contestation family: the defense side. Layers 1
///         and 2 are falsification engines — Layer 1 proves a coordinate was not
///         observed, Layer 2 proves an unobserved coordinate mattered. Neither
///         can ever produce the positive statement "this scope is complete";
///         completeness is not provable a priori (E-capture). This layer makes
///         the only kind of completeness the framework permits: completeness
///         EARNED THROUGH SURVIVED CONTESTATION.
///
///         A party posts a bonded SUFFICIENCY claim over a committed Layer-1
///         scope, relative to a pre-committed public classification function w.
///         The bond is a standing, funded invitation to falsify that claim. It
///         can never be proven; it can only survive. The longer it stands
///         unchallenged under an open bounty, the stronger the completeness
///         signal — exactly as an unclaimed bug bounty live for two years
///         outweighs a fresh audit. Lindy completeness.
///
/// @dev THE CORE DISTINCTION (sufficiency, not exhaustiveness):
///      The bond is slashable ONLY by a Layer-2 materiality proof — a coordinate
///      that is both (a) absent from the committed scope (Layer 1) and (b)
///      material under the committed w (Layer 2). A bare Layer-1 nomination (mere
///      omission) MUST NOT slash the bond. Exhaustiveness is impossible and a bond
///      on it would always die; sufficiency (no *material* omission under w) is
///      achievable and is exactly F★-completeness. The bond claims sufficiency.
///
/// @dev NORMATIVE GUARANTEES:
///      1. SUFFICIENCY NOT EXHAUSTIVENESS: a bond MUST be slashable only by a
///         valid Layer-2 materiality proof, never by a bare Layer-1 omission.
///      2. SCOPE-BOUND: the challenge MUST verify absence against the exact
///         cardinality-bound `scopeRoot` of the bonded Layer-1 scope (inherits
///         Layer-1 guarantee 4 — no re-declaring or shrinking the scope).
///      3. w PRE-COMMITMENT: `wCommitment` MUST be fixed when the bond is posted,
///         before any challenge; materiality is judged only under that committed
///         w (inherits Layer-2 commit-before-outcome).
///      4. NON-WITHDRAWABLE TERM: stake MUST be locked and slashable for the full
///         committed term; there MUST be no early withdrawal. Survival accrues as
///         a signal only because exit is impossible while the invitation stands.
///      5. SETTLE-ONCE: a bond MUST resolve exactly once — slashed to the
///         challenger, or reclaimed by the bonded party after the term —
///         replay-guarded.
///      6. NON-ADJUDICATING SIGNAL: the registry exposes raw survival facts and
///         MUST NOT compute or assert a completeness verdict. "Survived this much
///         contestation pressure" is a fact; "is complete" is the consumer's
///         interpretation, never the registry's.
///      7. RECOMPUTABLE: challenge validity and survival facts MUST be verifiable
///         from public data alone — no trusted party.
///
/// @dev COMPOSITION:
///      Binds DOWN to a Layer-1 scope (`scopeId`) and to a Layer-2 verifier
///      (materiality under `wCommitment`). Composes with the settle-once escrow
///      axis (the bond is escrow whose release condition is inverted: it pays
///      back on survival, slashes on a proven material omission). Composes by
///      reference, never by dependency.
///
/// @dev TEMPORAL DRIFT:
///      A bond asserts sufficiency for its term only. F★ drifts (new attacker,
///      new code path, new variable). Ongoing coverage is a chain of renewed
///      bonds; an expired or un-renewed bond is a stale claim, readable as such.

interface ICompletenessBond {

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /// @param bondId       Derived identifier (never caller-asserted).
    /// @param scopeId      The committed Layer-1 scope this bond claims sufficient.
    /// @param wCommitment  Pre-committed public classification function (Layer 2).
    /// @param bondedParty  Address whose stake backs the claim (may underwrite a
    ///                     scope it did not itself commit).
    /// @param amount       Staked amount, also the standing bounty on slash.
    /// @param termEnd      Timestamp until which the stake is locked and slashable.
    event BondPosted(
        bytes32 indexed bondId,
        bytes32 indexed scopeId,
        bytes32 wCommitment,
        address bondedParty,
        uint256 amount,
        uint64  termEnd
    );

    /// @notice Emitted when a bond is slashed by a valid material-omission proof.
    event BondChallenged(
        bytes32 indexed bondId,
        bytes32 indexed coordinate,
        address challenger
    );

    /// @notice Emitted when a bond resolves (slashed or reclaimed).
    event BondResolved(bytes32 indexed bondId, bool slashed);

    // -----------------------------------------------------------------------
    // State-changing
    // -----------------------------------------------------------------------

    /// @notice Post a completeness (sufficiency) bond over a Layer-1 scope,
    ///         relative to a pre-committed public w.
    /// @dev    `bondId` MUST be derived and MUST bind `msg.sender`. The bonded
    ///         scope MUST exist (Layer 1). The stake (the bounty) is locked until
    ///         `termEnd` and MUST NOT be withdrawable before then (guarantee 4).
    /// @param scopeId     Committed Layer-1 scope claimed sufficient.
    /// @param wCommitment Pre-committed public classification function.
    /// @param term        Duration the claim stands and the stake is locked.
    /// @return bondId     Derived bond identifier.
    function postBond(bytes32 scopeId, bytes32 wCommitment, uint64 term)
        external
        payable
        returns (bytes32 bondId);

    /// @notice Challenge a bond with a Layer-2 materiality proof and, if valid,
    ///         slash the staked bounty to the challenger.
    /// @dev    MUST revert unless the proof establishes BOTH: (a) `coordinate` is
    ///         absent from the bonded scope's cardinality-bound `scopeRoot`
    ///         (Layer 1), AND (b) `coordinate` is material under the bond's
    ///         committed `wCommitment` (Layer 2 — a witness pair isolating the
    ///         coordinate, recomputable under the committed w). MUST revert if the
    ///         bond is already resolved or its term has ended. A bare omission
    ///         (absence without materiality) MUST NOT slash (guarantee 1).
    /// @param bondId           The bond to challenge.
    /// @param nominatedCoordinate The raw coordinate descriptor X (pre-image) claimed as a material omission.
    /// @param materialityProof Layer-2 proof (carries the Layer-1 absence leg
    ///                         against the bound scopeRoot + the witness pair).
    function challenge(
        bytes32 bondId,
        bytes calldata nominatedCoordinate,
        bytes calldata materialityProof
    ) external;

    /// @notice Reclaim a survived bond's stake after its term ends unchallenged.
    /// @dev    MUST revert before `termEnd`, if already resolved, or if slashed.
    ///         Only the bonded party may reclaim.
    function reclaim(bytes32 bondId) external;

    // -----------------------------------------------------------------------
    // Views (the survival signal — raw facts, non-adjudicating)
    // -----------------------------------------------------------------------

    /// @notice Raw survival facts for a bond. Consumers (reputation, clients,
    ///         escrows) weight these themselves; the registry asserts no verdict.
    /// @return amount      Staked bounty.
    /// @return bondStart   When the claim began standing.
    /// @return termEnd     When the stake unlocks (claim window ends).
    /// @return resolvedAt  Resolution timestamp, or 0 if still live.
    /// @return slashed     True if slashed by a material-omission proof.
    /// @return challenged  True if any successful challenge has landed.
    function survival(bytes32 bondId)
        external
        view
        returns (
            uint256 amount,
            uint64  bondStart,
            uint64  termEnd,
            uint64  resolvedAt,
            bool    slashed,
            bool    challenged
        );

    /// @notice Read a bond's static parameters.
    /// @return scopeId      Bonded Layer-1 scope.
    /// @return wCommitment  Pre-committed classification function.
    /// @return bondedParty  Staker (zero if no such bond).
    /// @return amount       Staked bounty.
    /// @return termEnd      Stake-unlock timestamp.
    function getBond(bytes32 bondId)
        external
        view
        returns (
            bytes32 scopeId,
            bytes32 wCommitment,
            address bondedParty,
            uint256 amount,
            uint64  termEnd
        );
}
