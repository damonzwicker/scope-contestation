// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title IScopeContestation
/// @notice Abstract interface for a completeness/contestability layer over
///         verifiable-agent systems. A system that produces signed, recomputable
///         verdicts can prove a verdict is FAITHFUL (committed before the
///         outcome, recomputable, no trusted party) yet cannot prove the
///         observation SCOPE behind it was COMPLETE. This interface makes
///         incompleteness CONTESTABLE: an actor commits the set of coordinates
///         it observed, and anyone may permissionlessly prove a coordinate was
///         absent from that set.
///
/// @dev NORMATIVE GUARANTEES (the standard — implementation-agnostic):
///      1. NOMINABLE:     every coordinate genuinely absent from a committed
///                        scope MUST be nominable by any caller. A conformant
///                        proof scheme MUST be able to prove non-membership for
///                        every non-member.
///      2. SOUND:         a coordinate present in the committed scope MUST NOT
///                        be nominable — `nominate` MUST revert.
///      2a. WELL-FORMEDNESS (the precondition soundness rests on):
///                        if a proof scheme's soundness depends on a structural
///                        property of the committed representation (e.g. the
///                        reference scheme requires a *sorted* coordinate set),
///                        that property MUST be publicly recomputable from data
///                        the system already exposes. Soundness MUST NOT depend
///                        on any property knowable only to the committer. An
///                        implementation MUST NOT claim conformance for a scheme
///                        whose soundness rests on a non-recomputable assumption.
///      3. RECOMPUTABLE:  the absence proof MUST be verifiable from public data
///                        alone. No trusted party, no private store.
///      4. PERMANENT:     a successful nomination MUST be recorded and MUST NOT
///                        be deletable or modifiable afterward.
///      5. NON-ADJUDICATING: the registry MUST NOT decide whether a nominated
///                        coordinate mattered. It surfaces the contestable
///                        question; it never answers it.
///
/// @dev COORDINATE CANONICALIZATION:
///      A `coordinate` is an opaque `bytes32`. Soundness and completeness are
///      defined over `bytes32` equality only. The mapping from a real-world
///      object (an address, an asset id, a measurement dimension) to its
///      `bytes32` coordinate is the committing application's responsibility and
///      MUST be deterministic and publicly reproducible, so that "was X
///      observed" has a single, agreed encoding. A non-canonical mapping voids
///      the completeness guarantee in practice (the same object under two
///      encodings would read as two coordinates). This standard does not define
///      the mapping; it requires only that one exist and be public.
///
/// @dev PROOF OPACITY / PORTABILITY:
///      `proof` is implementation-defined. The standard fixes the *guarantees*,
///      not a wire format: proofs are NOT portable across implementations (a
///      proof valid under one implementation need not verify under another).
///      Implementations MAY expose a scheme identifier for discoverability.
///
/// @dev SCOPE OF THIS INTERFACE (what it does NOT do):
///      The registry does NOT authenticate that `committer` is entitled to
///      commit against `commitmentHash`. Binding an actor to an external
///      commitment is the identity layer's concern. This interface assumes that
///      binding upstream and concerns itself only with scope completeness.
///
/// @dev `commitmentHash` is an opaque external commitment this scope binds to;
///      this standard treats it as an arbitrary 32-byte value and places no
///      requirement on its construction. See the EIP Rationale for the
///      motivating binding (a recomputable observation-commitment primitive).

interface IScopeContestation {

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /// @notice Emitted when an actor commits an observation scope.
    /// @param scopeId        Derived identifier (never caller-asserted).
    /// @param commitmentHash Opaque external commitment this scope binds to.
    /// @param scopeRoot      Commitment to the declared coordinate set
    ///                       (implementation-defined: Merkle root, accumulator).
    /// @param count          Number of declared coordinates (see `commitScope`).
    /// @param committer      Address that committed the scope.
    event ScopeCommitted(
        bytes32 indexed scopeId,
        bytes32 indexed commitmentHash,
        bytes32 scopeRoot,
        uint256 count,
        address committer
    );

    /// @notice Emitted when a coordinate is successfully nominated as absent.
    /// @param scopeId    The scope against which the nomination was made.
    /// @param coordinate The coordinate proved absent.
    /// @param nominator  Address that submitted the nomination.
    event CoordinateNominated(
        bytes32 indexed scopeId,
        bytes32 indexed coordinate,
        address nominator
    );

    // -----------------------------------------------------------------------
    // State-changing
    // -----------------------------------------------------------------------

    /// @notice Commit a declared observation scope, bound to an external
    ///         commitment.
    /// @dev    `scopeId` MUST be derived and MUST bind the committer (e.g.
    ///         include `msg.sender` in the preimage) so a scope cannot be
    ///         squatted by a third party committing the same root first.
    ///
    ///         OPEN CO-AUTHOR QUESTION - `count`:
    ///         `count` is present because index-based proof schemes (e.g. the
    ///         reference sorted-Merkle boundary cases) need the cardinality
    ///         on-chain. Pure-accumulator schemes do not. Carrying it here makes
    ///         the interface mildly Merkle-flavored. Two resolutions for the
    ///         group: (a) keep `count` explicit, schemes that don't need it MAY
    ///         ignore it; (b) drop `count` from the signature and require the
    ///         representation to commit to cardinality inside `scopeRoot`, fully
    ///         scheme-agnostic - at the cost of changing the reference impl.
    ///         Defaulting to (a) pending the group's call.
    /// @param commitmentHash Opaque external commitment.
    /// @param scopeRoot      Commitment to the declared coordinate set.
    /// @param count          Number of declared coordinates (MUST be > 0).
    /// @return scopeId       Derived scope identifier.
    function commitScope(
        bytes32 commitmentHash,
        bytes32 scopeRoot,
        uint256 count
    ) external returns (bytes32 scopeId);

    /// @notice Permissionlessly nominate a coordinate absent from a committed
    ///         scope.
    /// @dev    MUST revert if `coordinate` is present in the scope (soundness).
    ///         MUST revert if `coordinate` was already nominated (replay).
    ///         MUST revert if `scopeId` does not exist.
    ///         On success MUST record the nomination permanently and emit
    ///         `CoordinateNominated`. `proof` is implementation-defined.
    /// @param scopeId    The scope to nominate against.
    /// @param coordinate The coordinate to prove absent.
    /// @param proof      Implementation-defined absence proof.
    function nominate(
        bytes32 scopeId,
        bytes32 coordinate,
        bytes calldata proof
    ) external;

    // -----------------------------------------------------------------------
    // Views (read surface for downstream consumers: reputation, escrow)
    // -----------------------------------------------------------------------

    /// @notice Read-only absence check - surfaces evidence without nominating.
    /// @dev    Returns true iff `coordinate` is provably absent from the scope
    ///         under `proof`. This reflects the ABSENCE PREDICATE ONLY; it does
    ///         NOT check scope existence or replay (those are enforced
    ///         additionally by `nominate`). MUST NOT change state and MUST be
    ///         recomputable from public data alone. Lets an escrow or other
    ///         consumer treat absence as evidence while leaving enforcement (the
    ///         permanent record) to `nominate`.
    /// @param scopeId    The scope to check against.
    /// @param coordinate The coordinate to check.
    /// @param proof      Implementation-defined absence proof.
    /// @return           True if `coordinate` is provably absent.
    function verifyAbsence(
        bytes32 scopeId,
        bytes32 coordinate,
        bytes calldata proof
    ) external view returns (bool);

    /// @notice Whether a coordinate has been successfully nominated for a scope.
    /// @dev    On-chain readable form of the permanence guarantee; lets the
    ///         reputation axis and escrows read nominations directly rather than
    ///         only from events.
    function isNominated(bytes32 scopeId, bytes32 coordinate)
        external
        view
        returns (bool);

    /// @notice Read a committed scope.
    /// @return commitmentHash Opaque external commitment the scope binds to.
    /// @return scopeRoot      Commitment to the declared coordinate set.
    /// @return count          Number of declared coordinates.
    /// @return committer      Address that committed the scope (zero if none).
    function getScope(bytes32 scopeId)
        external
        view
        returns (
            bytes32 commitmentHash,
            bytes32 scopeRoot,
            uint256 count,
            address committer
        );
}
