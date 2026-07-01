// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IResolutionCommitment — Layer 1 value-fidelity leg
///
/// @notice The third IScopeContestation guard, sitting between verifyScopeComplete
///         and isolation in contest():
///
///             verifyAbsence → verifyScopeComplete → verifyValueFidelity → isolation → classify
///
///         verifyScopeComplete closed the COORDINATE half of the adversarial-`a` gap:
///         `a`'s sourceIds are the declared set, nothing dropped, added, or foreign.
///         That is necessary but not sufficient: scopeRoot's leaves are id-only and it
///         is committed at market creation — BEFORE the readings exist — so it cannot
///         bind `a`'s VALUES even in principle. A contester who satisfies completeness
///         can still set adversarial values on the declared coords (boundary-tuned) and
///         manufacture separation.
///
///         This guard closes the VALUE half: `a`'s (sourceId, value) pairs MUST
///         reproduce the market's actual resolved readings, pinned by a resolution-time
///         commitment (resolutionRoot) that was committed pre-outcome.
///
///         The verdict then reads "X was material to THE resolution" (S1), not "X was
///         material to some coordinate-complete `a` the contester chose" (S2).
///
/// @dev    Two reference impls — same pluggable shape as the absence/completeness legs:
///
///         type-1 (chain-native readings): values are recomputable from chain state;
///             no extra commitment needed; verifyValueFidelity recomputes and compares.
///
///         type-2 (off-chain / web2 readings): chain cannot recompute them; the guard
///             checks `a`'s (id, value) pairs against a resolution-time commitment —
///             keccak256(abi.encode(sortedLeaves)), committed on-chain pre-outcome via
///             an observation commitment (ERC-8281: observation → digest → on-chain).
///             Source-authentication (zkTLS / input-provenance) is ORTHOGONAL to this
///             guard — it answers "are these readings authentic?" not "does `a` match
///             the committed readings?" Both are needed for the full S1 guarantee under
///             off-chain provenance; this interface covers only the commitment side.
///
/// @notice Pre-outcome MUST: resolutionRoot MUST be committed before the outcome is
///         observable. A root committed post-outcome does not satisfy this requirement
///         — a committer could fudge values after seeing the result and the check would
///         only certify the fudge. The observation-commitment pattern (ERC-8281) carries
///         this property for free: the digest is anchored on-chain before resolution.

interface IResolutionCommitment {

    /// @notice Emitted when a market's resolution readings are committed.
    ///         MUST be emitted before the outcome is observable (pre-outcome MUST).
    event ResolutionCommitted(bytes32 indexed scopeId, bytes32 resolutionRoot);

    /// @notice Commit the resolution-time readings for a market.
    ///         Called by the resolution authority after readings are finalised but
    ///         BEFORE the outcome classification is published.
    ///
    /// @param scopeId        the market identifier (must already have a committed scopeRoot)
    /// @param resolutionRoot commitment to the resolved (sourceId, value) pairs —
    ///                       for the type-2 reference impl:
    ///                           keccak256(abi.encode(sortedLeaves))
    ///                       where leaf_i = keccak256(abi.encode(sourceId_i, value_i)),
    ///                       leaves sorted ascending on sourceId.
    function commitResolution(bytes32 scopeId, bytes32 resolutionRoot) external;

    /// @notice The committed resolution root for a market.
    function resolutionRootOf(bytes32 scopeId) external view returns (bytes32);

    /// @notice Value-fidelity guard. Called by Layer2PreCheck.contest() as a require()
    ///         between verifyScopeComplete and isolation — reverts on failure, never
    ///         encoded in `separated`.
    ///
    ///         Returns true iff `a`'s (sourceId, value) pairs exactly reproduce the
    ///         readings captured in the committed resolutionRoot — i.e. `a` is the
    ///         actual resolved base, not a contester-chosen substitute.
    ///
    /// @param scopeId        the market identifier
    /// @param a              abi.encode(Vote[]) — the witness base (without X); the same
    ///                       `a` passed to classify(); its sourceIds have already been
    ///                       validated against scopeRoot by verifyScopeComplete
    /// @return faithful      true iff `a` reproduces the committed resolution readings
    function verifyValueFidelity(bytes32 scopeId, bytes calldata a)
        external
        view
        returns (bool faithful);

    /// @notice GUARD 7 (adversarial-X): pin the value of a SINGLE coordinate — the omitted
    ///         coordinate X being contested — against the committed resolution. X is not in
    ///         `a` (it was omitted by definition), so it cannot ride the bulk
    ///         verifyValueFidelity(a) check; its value is pinned here independently.
    /// @dev    type-1 (chain-native): recompute value from the pinned chain source at the
    ///         committed block and require equality — same machinery as verifyValueFidelity,
    ///         pointed at one key. type-2 (off-chain): X is in no commitment, so its value
    ///         authenticity is the orthogonal source-auth / zkTLS leg — returns false here,
    ///         deferring to that leg rather than conflating it with value-fidelity.
    /// @param key   the coordinate identity (X's sourceId == coordinateHash)
    /// @param value the contester's claimed reading at X (abi-encoded option/value)
    /// @return ok   true iff X's claimed value reproduces its real committed reading
    function verifyCoordinateValue(bytes32 scopeId, bytes32 key, bytes calldata value)
        external
        view
        returns (bool ok);
}
