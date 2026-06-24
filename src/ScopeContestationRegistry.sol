// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title ScopeContestationRegistry — the completeness/contestability layer
/// @notice The settlement stack (OCP/8281 → 8004 → 1833 → 8299/8274 → escrow/8275)
///         proves a verdict is FAITHFUL: committed-before-outcome, recomputable,
///         no trusted party. It cannot prove the observation SCOPE was COMPLETE.
///         Completeness is not provable a priori (that is E-capture). But
///         *incompleteness* can be made CONTESTABLE.
///
///         An agent commits the set of coordinates it observed (e.g. the
///         `asset_set` of a recovery job), bound to its OCP layer-0 commitment.
///         Anyone may then permissionlessly NOMINATE a coordinate it did NOT
///         observe — proving, on-chain and recomputably, that the coordinate is
///         genuinely absent from the declared set (sorted-Merkle non-inclusion).
///
///         This registry ADJUDICATES NOTHING. It does not decide whether a
///         nominated coordinate mattered (was in the minimal sufficient subspace
///         F*) — that question is the contestable one it merely SURFACES and makes
///         permanent. It is not an oracle. Its single guarantee: no omission is
///         structurally invisible; every omission is nominable, and once
///         nominated, recomputable forever from events.
///
///         Soundness rests on the committed coordinate list being SORTED. The
///         declared set is public (recomputable from the OCP layer-0 commitment),
///         so sortedness is itself publicly recomputable — not trusted. This keeps
///         the layer inside the family spine: recomputable from public data, no
///         layer a trusted party.
contract ScopeContestationRegistry {
    struct Scope {
        bytes32 commitmentHash; // OCP (8281) layer-0 commitment this scope binds to
        bytes32 scopeRoot;      // Merkle root of the SORTED declared coordinate set
        uint256 count;          // number of declared coordinates
        address committer;
        uint64  committedAt;
    }

    /// @dev mode 0 = interior straddle, 1 = below-min, 2 = above-max
    struct NonInclusion {
        uint8     mode;
        bytes32   loCoord;
        bytes32   hiCoord;
        uint256   idxLo;        // interior only; hi is idxLo+1
        bytes32[] sibsLo;
        bytes32[] sibsHi;
    }

    mapping(bytes32 => Scope) public scopes;     // scopeId => Scope
    mapping(bytes32 => bool)  public nominated;  // keccak(scopeId, coord) => seen

    event ScopeCommitted(
        bytes32 indexed scopeId,
        bytes32 indexed commitmentHash,
        bytes32 scopeRoot,
        uint256 count,
        address committer
    );
    event CoordinateNominated(
        bytes32 indexed scopeId,
        bytes32 indexed coordinate,
        address nominator
    );

    /// @notice Commit a declared observation scope, bound to an OCP commitment.
    /// @dev scopeId is derived (binds scope to its OCP commitment + committer);
    ///      it cannot be asserted by the caller.
    function commitScope(bytes32 commitmentHash, bytes32 scopeRoot, uint256 count)
        external
        returns (bytes32 scopeId)
    {
        require(count > 0, "empty scope");
        scopeId = keccak256(abi.encode(commitmentHash, scopeRoot, count, msg.sender));
        // existence sentinel is committer (always non-zero for a real commit);
        // a timestamp is unsafe as a sentinel since block.timestamp can be 0.
        require(scopes[scopeId].committer == address(0), "exists");
        scopes[scopeId] =
            Scope(commitmentHash, scopeRoot, count, msg.sender, uint64(block.timestamp));
        emit ScopeCommitted(scopeId, commitmentHash, scopeRoot, count, msg.sender);
    }

    /// @notice Permissionlessly nominate a coordinate the scope did NOT observe.
    /// @dev Gate discipline (matches the stack): cheap checks first, the expensive
    ///      non-inclusion verify last, replay-guarded, CEI. Never trusts the caller:
    ///      a coordinate that WAS declared cannot be nominated (verify reverts).
    function nominate(bytes32 scopeId, bytes32 coordinate, NonInclusion calldata proof)
        external
    {
        Scope storage s = scopes[scopeId];
        require(s.committer != address(0), "no scope");                // cheap
        bytes32 dk = keccak256(abi.encodePacked(scopeId, coordinate));
        require(!nominated[dk], "already nominated");                   // cheap, dedupe
        require(                                                        // expensive, last
            _verifyNonInclusion(coordinate, s.scopeRoot, s.count, proof),
            "coordinate is in scope"
        );
        nominated[dk] = true;                                          // effects
        emit CoordinateNominated(scopeId, coordinate, msg.sender);     // interaction
    }

    // ----------------------------------------------------------------------
    // Sorted-Merkle non-inclusion. Orientation/promotion derived from PUBLIC
    // (index, count) only — never from prover-supplied flags. Domain-separated
    // leaves/nodes. Identical logic to reference/scope_ref.py.
    // ----------------------------------------------------------------------
    function _leaf(bytes32 coord) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(0), coord));
    }

    function _node(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(1), l, r));
    }

    function _verifyMembership(
        bytes32 leaf,
        uint256 idx,
        uint256 count,
        bytes32[] calldata sibs,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 h = leaf;
        uint256 pos = idx;
        uint256 size = count;
        uint256 k = 0;
        while (size > 1) {
            if (pos & 1 == 1) {
                if (k >= sibs.length) return false;
                h = _node(sibs[k], h);
                unchecked { k++; }
            } else if (pos + 1 < size) {
                if (k >= sibs.length) return false;
                h = _node(h, sibs[k]);
                unchecked { k++; }
            } // else: promoted odd node, consume no sibling
            pos >>= 1;
            size = (size + 1) >> 1;
        }
        return k == sibs.length && h == root;
    }

    function _verifyNonInclusion(
        bytes32 c,
        bytes32 root,
        uint256 count,
        NonInclusion calldata p
    ) internal pure returns (bool) {
        if (p.mode == 1) {
            // below-min: c < leaf[0] and leaf[0] is the leftmost leaf
            return uint256(c) < uint256(p.loCoord)
                && _verifyMembership(_leaf(p.loCoord), 0, count, p.sibsLo, root);
        }
        if (p.mode == 2) {
            // above-max: c > leaf[count-1] and that leaf is the rightmost
            return uint256(c) > uint256(p.hiCoord)
                && _verifyMembership(_leaf(p.hiCoord), count - 1, count, p.sibsHi, root);
        }
        // interior: lo,hi are adjacent (idxLo, idxLo+1) and strictly straddle c
        if (!(uint256(p.loCoord) < uint256(c) && uint256(c) < uint256(p.hiCoord))) return false;
        if (!_verifyMembership(_leaf(p.loCoord), p.idxLo, count, p.sibsLo, root)) return false;
        if (!_verifyMembership(_leaf(p.hiCoord), p.idxLo + 1, count, p.sibsHi, root)) return false;
        return true;
    }
}
