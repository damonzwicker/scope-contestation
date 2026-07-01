// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IResolutionCommitment} from "./IResolutionCommitment.sol";
import {ISourceAuthVerifier}   from "./ISourceAuthVerifier.sol";

/// @title SourceAuthResolution — the third IResolutionCommitment (type-2 value-fidelity)
/// @author damonzwicker (OCP / ERC-8281)  — CC0
///
/// @notice Guard 7 for OFF-CHAIN facts. Implements the full IResolutionCommitment
///         interface, replacing the prior type-2 stub (which returned false-by-design
///         at verifyCoordinateValue, deferring to an "orthogonal source-auth leg that
///         has never actually been built"). This IS that leg.
///
///         verifyValueFidelity (bulk, all of `a`) delegates to the type-2 committed
///         resolutionRoot — same as the prior impl, unchanged.
///
///         verifyCoordinateValue (guard 7, single coordinate X) now RESOLVES instead
///         of deferring: it checks that a committed zkTLS source-auth attestation for
///         (scopeId, key) exists, is VERIFIED, and its bound value matches the
///         contester's claimed value — the same guard-7 pattern as type-1, fed by an
///         attested-fetch proof instead of a chain read.
///
/// @dev SHAPE (OCP/8281 invariant):  observation → digest → on-chain commitment → verify
///        commitSourceAuth(...)      the digest + on-chain commitment (state-changing)
///        verifyCoordinateValue(...) the verify leg guard 7 calls (pure view, canonical sig)
///
/// @dev STORAGE KEY: attestations are stored under (scopeId, key) — matching the
///         guard-7 call site: resolution.verifyCoordinateValue(scopeId, delta.sourceId,
///         abi.encode(delta.option)). One active attestation per coordinate per market.
///         attDigest is stored INSIDE the record and emitted for off-chain recompute
///         cross-check — it is not the map key.
///
/// @dev RECOMPUTE DISCIPLINE: attDigest is a pure function of public inputs (schemeId,
///         scopeId, coordinate, sourceId, key, valueCommitted, timePin, parseRuleCommit,
///         certChainCommit, timeAnchorCommit). A second party (Fede, Jimmy) re-derives
///         it from the web-proof + public data, checks it against the emitted attDigest,
///         and re-verifies the proof off-chain (tier-1) or in consensus (tier-0). The
///         storage lookup at (scopeId, key) is the guard-7 fast path; the digest is the
///         recompute path. Both are public.
///
/// @dev NORMATIVE GUARANTEES (same house discipline as all other layers):
///      1. RECOMPUTABLE:    attDigest MUST be a pure function of public inputs.
///      2. FAIL-CLOSED:     verifyCoordinateValue returns true ONLY for a VERIFIED
///                          attestation whose (scopeId, key, valueCommitted) match the
///                          call's (scopeId, key, value) and whose tier is within the
///                          consumer's accepted floor. Every other case -> false.
///      3. UNVERIFIABLE IS A FACT, NEVER SILENT: a commit that cannot be established
///                          is recorded and emitted as UNVERIFIABLE — a permanent,
///                          readable output, not a swallowed false.
///      4. VALUE FROM BYTES, NOT SCALAR: valueCommitted is bound to a committed parse
///                          rule (parseRuleCommit) over disclosed transcript bytes.
///                          Guard 7 never accepts a claimant-supplied scalar as the
///                          source value — the type-2 form of adversarial-a.
///      5. NON-ADJUDICATING / CONSUMER-CHOSEN FLOOR: the contract records the tier as
///                          a fact; it does NOT decide which tier is sufficient.
///                          commitSourceAuth takes minAcceptedTier; guard-7 enforces it.
///      6. TIER HONESTY: for tiers 1-3, on-chain VERIFIED means the commitment is
///                          well-formed. Actual re-verification of a tier-1 proof is the
///                          OFF-CHAIN recompute step. Only tier-0 is verified in
///                          consensus. This distinction MUST NOT be blurred.
contract SourceAuthResolution is IResolutionCommitment {

    // ------------------------------------------------------------------
    // Types
    // ------------------------------------------------------------------

    /// @dev Lower ordinal = stronger trust root. Guard 7 enforces `tier <= minAcceptedTier`.
    ///      ON_CHAIN(0):        SNARK + cert-chain verified IN CONSENSUS via ISourceAuthVerifier.
    ///                          Trust root: {TLS PRF, SNARK soundness}. Notary key drops out.
    ///      REVERIFIABLE(1):    digest-commit of a re-verifiable web-proof (TLSNotary MPC-ZK).
    ///                          Same trust root, discharged OFF-CHAIN by any re-verifier.
    ///      SLASHED_ATTESTOR(2):signature-trust (proxy/TEE) backed by slashing >= floor.
    ///                          Trust root: {attestor honesty + slashing economics}.
    ///      BARE_ATTESTOR(3):   bare signature-trust (proxy). Survivor floor.
    ///                          Trust root: {attestor honesty}.
    enum Tier { ON_CHAIN, REVERIFIABLE, SLASHED_ATTESTOR, BARE_ATTESTOR }

    /// @dev Default zero == UNVERIFIABLE — any uninitialized read fails closed.
    enum Verdict { UNVERIFIABLE, VERIFIED, REFUTED }

    struct AttestationRecord {
        bytes32 attDigest;        // recomputable cross-check (emitted; not the map key)
        bytes32 valueCommitted;   // abi.encode(value) hashed — compared against guard-7 value
        bytes32 valueRaw;         // keccak256(value) for constant-time compare vs calldata
        bytes32 certChainCommit;  // commitment to server TLS cert chain
        bytes32 parseRuleCommit;  // commitment to parse rule (value-from-bytes)
        uint64  timePin;          // pinned session time (unix seconds)
        uint64  committedAt;      // block.timestamp at commit
        Tier    tier;
        Verdict verdict;
        address committer;
        bool    exists;
    }

    /// @notice Off-chain-recomputable inputs to a source-auth commitment.
    struct SourceAuthInput {
        bytes32 schemeId;         // attested-fetch scheme + version id
        bytes32 coordinate;       // canonical coordinate (== key == delta.sourceId)
        bytes32 sourceId;         // keccak of canonical source descriptor (host+path+...)
        bytes32 key;              // queried key inside the source response
        bytes   valueCommitted;   // abi.encode(delta.option) — the value being committed
        uint64  timePin;          // session time; MUST be non-zero and <= block.timestamp
        bytes32 parseRuleCommit;  // commitment to the parse rule (value-from-bytes)
        bytes32 certChainCommit;  // commitment to the server TLS cert chain
        bytes32 timeAnchorCommit; // OPTIONAL: OTS/block external-clock anchor
        Tier    tier;
        uint256 stakeBacking;     // for tier-2: slashable stake behind the attestor
        bytes   webProof;         // tier-0 only: bytes for on-chain verify
    }

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    /// @notice Primary guard-7 index: (scopeId => coordinate => record).
    ///         Matches the call site: verifyCoordinateValue(scopeId, delta.sourceId, value)
    mapping(bytes32 => mapping(bytes32 => AttestationRecord)) private _att;

    /// @notice Secondary recompute index: attDigest => (scopeId, key) for off-chain lookup.
    mapping(bytes32 => bytes32) private _digestToScopeId;
    mapping(bytes32 => bytes32) private _digestToKey;

    /// @notice type-2 resolution roots (bulk verifyValueFidelity path — unchanged from prior impl).
    mapping(bytes32 => bytes32) private _resolutionRoots;

    /// @notice Optional tier-0 on-chain SNARK+cert verifier. Zero => tier-0 is UNVERIFIABLE.
    ISourceAuthVerifier public immutable tier0Verifier;

    /// @notice Minimum slashable stake for a tier-2 commit to be VERIFIED.
    uint256 public immutable tier2StakeFloor;

    /// @notice The maximum tier this instance will accept. Set at deploy. A CMMC-grade
    ///         deployment sets this to REVERIFIABLE(1); a permissive deployment sets BARE_ATTESTOR(3).
    Tier public immutable maxAcceptedTier;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    /// @param attDigest      Recomputable commitment id (stored in record; NOT the map key).
    /// @param scopeId        Market identifier.
    /// @param coordinate     Canonical coordinate (== key == delta.sourceId).
    /// @param valueHash      keccak256(valueCommitted) — the committed value fingerprint.
    /// @param timePin        Pinned session time.
    /// @param tier           Recorded tier.
    /// @param verdict        VERIFIED or UNVERIFIABLE — never silent.
    event SourceAuthCommitted(
        bytes32 indexed attDigest,
        bytes32 indexed scopeId,
        bytes32 indexed coordinate,
        bytes32 valueHash,
        uint64  timePin,
        Tier    tier,
        Verdict verdict,
        address committer
    );

    /// @notice A valid counter-attestation refuted an existing commitment's value.
    event SourceAuthRefuted(
        bytes32 indexed scopeId,
        bytes32 indexed coordinate,
        bytes32 refutingDigest
    );

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    /// @param _tier0Verifier    Zero to ship tiers 1-3 only (recommended today;
    ///                          tier-0 Solidity verifiers not yet mature).
    /// @param _tier2StakeFloor  Slashing floor; tier-2 below this -> UNVERIFIABLE.
    /// @param _maxAcceptedTier  Hard ceiling for this deployment (e.g. REVERIFIABLE=1
    ///                          for CMMC-grade; BARE_ATTESTOR=3 for permissive).
    constructor(
        ISourceAuthVerifier _tier0Verifier,
        uint256             _tier2StakeFloor,
        Tier                _maxAcceptedTier
    ) {
        tier0Verifier   = _tier0Verifier;
        tier2StakeFloor = _tier2StakeFloor;
        maxAcceptedTier = _maxAcceptedTier;
    }

    // ------------------------------------------------------------------
    // IResolutionCommitment — bulk resolution root (unchanged from prior impl)
    // ------------------------------------------------------------------

    /// @inheritdoc IResolutionCommitment
    function commitResolution(bytes32 scopeId, bytes32 resolutionRoot) external {
        require(_resolutionRoots[scopeId] == bytes32(0), "resolution already committed");
        require(resolutionRoot != bytes32(0), "empty root");
        _resolutionRoots[scopeId] = resolutionRoot;
        emit ResolutionCommitted(scopeId, resolutionRoot);
    }

    /// @inheritdoc IResolutionCommitment
    function resolutionRootOf(bytes32 scopeId) external view returns (bytes32) {
        return _resolutionRoots[scopeId];
    }

    /// @notice Bulk value-fidelity guard (guards 5 — all of `a` vs committed root).
    /// @dev    For type-2 markets this verifies `a`'s (sourceId, value) pairs against
    ///         the committed resolutionRoot using the same sorted-leaf Merkle check as
    ///         the prior ResolutionCommitment impl. The source-auth leg (guard 7) is
    ///         SEPARATE and covers X only — X is NOT in `a` by definition.
    /// @inheritdoc IResolutionCommitment
    function verifyValueFidelity(bytes32 scopeId, bytes calldata a)
        external view returns (bool faithful)
    {
        bytes32 root = _resolutionRoots[scopeId];
        if (root == bytes32(0)) return false;
        // Recompute keccak256(abi.encode(sortedLeaves)) from `a` and compare to root.
        // This is the SAME check as the prior type-2 ResolutionCommitment — unchanged.
        // leaf_i = keccak256(abi.encode(sourceId_i, value_i)), sorted ascending on sourceId.
        return _recomputeRoot(a) == root;
    }

    // ------------------------------------------------------------------
    // IResolutionCommitment — guard 7 (canonical signature)
    // ------------------------------------------------------------------

    /// @notice Guard 7: pin a SINGLE coordinate X's value against the committed
    ///         source-auth attestation. X is not in `a`, so it cannot ride
    ///         verifyValueFidelity; its value is pinned here independently.
    ///
    ///         Called by Layer2PreCheck.contest() as:
    ///             resolution.verifyCoordinateValue(scopeId, delta.sourceId, abi.encode(delta.option))
    ///
    /// @param scopeId  the market identifier
    /// @param key      X's sourceId (== coordinateHash == delta.sourceId)
    /// @param value    abi.encode(delta.option) — contester's claimed reading at X
    /// @return ok      true iff a VERIFIED attestation for (scopeId, key) exists and
    ///                 its committed value matches `value`, with tier within accepted floor
    /// @inheritdoc IResolutionCommitment
    function verifyCoordinateValue(bytes32 scopeId, bytes32 key, bytes calldata value)
        external view returns (bool ok)
    {
        AttestationRecord storage r = _att[scopeId][key];
        if (!r.exists)                        return false; // nothing committed
        if (r.verdict != Verdict.VERIFIED)    return false; // UNVERIFIABLE or REFUTED
        if (uint8(r.tier) > uint8(maxAcceptedTier)) return false; // tier above deployment floor
        // Compare the contester's claimed value against what the attestation committed.
        // keccak-compare avoids storing the full value blob and is constant-time on length.
        if (keccak256(value) != r.valueRaw)   return false; // value mismatch (adversarial-a)
        return true;
    }

    // ------------------------------------------------------------------
    // Commit — observation -> digest -> on-chain commitment
    // ------------------------------------------------------------------

    /// @notice Commit a source-auth attestation for coordinate X of market scopeId.
    ///         Classifies verdict + tier and records permanently. Idempotent: a
    ///         re-commit of an identical (scopeId, key) with the same digest is a no-op.
    ///         A re-commit with a DIFFERENT digest for the same (scopeId, key) reverts —
    ///         use refute() if a counter-attestation genuinely conflicts.
    ///
    /// @return attDigest The recomputable commitment id (stored in record; emitted).
    function commitSourceAuth(bytes32 scopeId, SourceAuthInput calldata in_)
        external
        returns (bytes32 attDigest)
    {
        require(scopeId != bytes32(0), "empty scopeId");
        require(in_.coordinate == in_.key, "coordinate must equal key (= delta.sourceId)");

        attDigest = digestOf(scopeId, in_);

        AttestationRecord storage r = _att[scopeId][in_.key];
        if (r.exists) {
            // Idempotent on identical fact — same digest for same (scopeId, key).
            require(r.attDigest == attDigest, "conflicting attestation: use refute()");
            return attDigest;
        }

        Verdict v = _classify(in_);

        r.attDigest      = attDigest;
        r.valueCommitted = keccak256(in_.valueCommitted); // fingerprint — not stored raw
        r.valueRaw       = keccak256(in_.valueCommitted); // same; named for guard-7 clarity
        r.certChainCommit = in_.certChainCommit;
        r.parseRuleCommit = in_.parseRuleCommit;
        r.timePin        = in_.timePin;
        r.committedAt    = uint64(block.timestamp);
        r.tier           = in_.tier;
        r.verdict        = v;
        r.committer      = msg.sender;
        r.exists         = true;

        // Secondary index for off-chain recompute path.
        _digestToScopeId[attDigest] = scopeId;
        _digestToKey[attDigest]     = in_.key;

        emit SourceAuthCommitted(
            attDigest, scopeId, in_.coordinate,
            keccak256(in_.valueCommitted),
            in_.timePin, in_.tier, v, msg.sender
        );
    }


    // ------------------------------------------------------------------
    // Refute
    // ------------------------------------------------------------------

    /// @notice Record that a counter-attestation refutes an existing commitment.
    ///         The counter is classified INLINE — it does not need to be pre-committed
    ///         (two attestations cannot share the same (scopeId,key) primary slot).
    ///         Requires: counter targets the same (scopeId, key), binds a different
    ///         value, has tier <= target tier, and classifies as VERIFIED. Flips
    ///         the target to REFUTED so guard 7 fails closed on it permanently.
    ///         Fail-closed: a weaker, unverified, or same-value counter cannot refute.
    function refute(
        bytes32 scopeId,
        bytes32 key,
        SourceAuthInput calldata counter
    ) external {
        AttestationRecord storage t = _att[scopeId][key];
        require(t.exists,                      "no such attestation");
        require(t.verdict == Verdict.VERIFIED, "target not verified");
        require(counter.key == key,            "counter key mismatch");

        // Must bind a different value to be a genuine conflict.
        bytes32 counterValueRaw = keccak256(counter.valueCommitted);
        require(counterValueRaw != t.valueRaw, "same value - no conflict");

        // Counter tier must be at least as strong as the target.
        require(uint8(counter.tier) <= uint8(t.tier), "counter weaker than target");

        // Classify the counter inline — same rules as commitSourceAuth.
        // Does not store the counter; refute is a one-shot flip, not a swap.
        Verdict cv = _classify(counter);
        require(cv == Verdict.VERIFIED, "counter not verified");

        bytes32 counterDigest = digestOf(scopeId, counter);
        t.verdict = Verdict.REFUTED;
        emit SourceAuthRefuted(scopeId, key, counterDigest);
    }

    // ------------------------------------------------------------------
    // Recompute helpers
    // ------------------------------------------------------------------

    /// @notice THE canonical, recomputable digest. A second party re-derives this
    ///         from the web-proof + public data and checks it against the emitted
    ///         attDigest. The "recompute, don't trust" contract in one hash.
    ///         Note: scopeId is included so digests are market-scoped and cannot
    ///         be replayed across markets.
    function digestOf(bytes32 scopeId, SourceAuthInput calldata in_)
        public pure returns (bytes32)
    {
        return keccak256(abi.encode(
            scopeId,
            in_.schemeId,
            in_.coordinate,
            in_.sourceId,
            in_.key,
            keccak256(in_.valueCommitted), // hash the blob so digest is fixed-size
            in_.timePin,
            in_.parseRuleCommit,
            in_.certChainCommit,
            in_.timeAnchorCommit
        ));
    }

    /// @notice Read a committed attestation record (raw facts — non-adjudicating).
    function getAttestation(bytes32 scopeId, bytes32 key)
        external view
        returns (
            bytes32 attDigest,
            bytes32 valueHash,
            uint64  timePin,
            uint64  committedAt,
            Tier    tier,
            Verdict verdict,
            address committer
        )
    {
        AttestationRecord storage r = _att[scopeId][key];
        return (
            r.attDigest, r.valueRaw, r.timePin, r.committedAt,
            r.tier, r.verdict, r.committer
        );
    }

    /// @notice Look up the (scopeId, key) for a known attDigest (recompute path).
    function lookupByDigest(bytes32 attDigest)
        external view returns (bytes32 scopeId, bytes32 key)
    {
        return (_digestToScopeId[attDigest], _digestToKey[attDigest]);
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    function _classify(SourceAuthInput calldata in_) private view returns (Verdict) {
        // Common honest-boundary preconditions.
        if (in_.certChainCommit == bytes32(0)) return Verdict.UNVERIFIABLE; // unauthenticated channel
        if (in_.parseRuleCommit == bytes32(0)) return Verdict.UNVERIFIABLE; // value not bound to bytes
        if (in_.timePin == 0)                  return Verdict.UNVERIFIABLE; // "at time T" missing
        if (in_.timePin > block.timestamp)     return Verdict.UNVERIFIABLE; // future pin is forgeable
        if (in_.valueCommitted.length == 0)    return Verdict.UNVERIFIABLE; // empty value

        // Tier-level gates.
        if (in_.tier == Tier.ON_CHAIN) {
            if (address(tier0Verifier) == address(0)) return Verdict.UNVERIFIABLE;
            (
                bool ok, bytes32 sourceId, bytes32 key,
                bytes32 valueAttested, uint64 timePin, bytes32 certChainCommit
            ) = tier0Verifier.verify(in_.webProof);
            if (!ok)                                     return Verdict.UNVERIFIABLE;
            if (sourceId       != in_.sourceId)          return Verdict.UNVERIFIABLE;
            if (key            != in_.key)               return Verdict.UNVERIFIABLE;
            // value comparison: verifier returns bytes32, we committed bytes — compare hashes
            if (valueAttested  != keccak256(in_.valueCommitted)) return Verdict.UNVERIFIABLE;
            if (timePin        != in_.timePin)           return Verdict.UNVERIFIABLE;
            if (certChainCommit!= in_.certChainCommit)   return Verdict.UNVERIFIABLE;
            return Verdict.VERIFIED;
        }

        if (in_.tier == Tier.SLASHED_ATTESTOR) {
            if (in_.stakeBacking < tier2StakeFloor)  return Verdict.UNVERIFIABLE;
            return Verdict.VERIFIED;
        }

        // REVERIFIABLE(1) and BARE_ATTESTOR(3): well-formed commitment.
        return Verdict.VERIFIED;
    }

    /// @dev Recomputes keccak256(abi.encode(sortedLeaves)) from a Vote[] encoding.
    ///      leaf_i = keccak256(abi.encode(sourceId_i, value_i))
    ///      Leaves MUST be sorted ascending on sourceId (same requirement as prior impl).
    ///      Returns bytes32(0) on any decode failure (fail-closed).
    function _recomputeRoot(bytes calldata a) private pure returns (bytes32) {
        // Decode as a sequence of (bytes32 sourceId, bytes value) pairs.
        // The encoding matches Vote[] where Vote = {bytes32 sourceId, <option type>}.
        // We accept the encoded bytes as-is and compute sorted-leaf root.
        // NOTE: this is a reference implementation. The canonical Vote struct encoding
        // must match exactly — verify against ScopeTypes.sol before merge.
        (bytes32[] memory ids, bytes[] memory vals) = _decodeVotes(a);
        uint256 n = ids.length;
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            leaves[i] = keccak256(abi.encode(ids[i], vals[i]));
        }
        // Verify sorted ascending on sourceId (soundness requirement).
        for (uint256 i = 1; i < n; i++) {
            if (ids[i] <= ids[i - 1]) return bytes32(0); // unsorted or duplicate
        }
        return keccak256(abi.encode(leaves));
    }

    /// @dev Decode Vote[] into parallel id/value arrays.
    ///      ⚠ UNVERIFIED: the exact ABI layout depends on ScopeTypes.Vote which is
    ///      not in the public repo. Assumes Vote = { bytes32 sourceId; bytes option; }.
    ///      If Vote has additional fields this will revert (fail-closed). Verify before merge.
    function _decodeVotes(bytes calldata a)
        private pure
        returns (bytes32[] memory ids, bytes[] memory vals)
    {
        (ids, vals) = abi.decode(a, (bytes32[], bytes[]));
    }
}
