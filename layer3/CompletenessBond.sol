// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {ICompletenessBond} from "./ICompletenessBond.sol";

interface ILayer2PreCheck {
    function contest(
        bytes32        scopeId,
        bytes calldata nominatedCoordinate,
        bytes calldata proof
    ) external returns (bool separated);
}

/// @notice Minimal Layer-1 read the bond needs: confirm a scope was committed. The
///         canonical Layer-1 contract (ScopeContestation) owns scopeRootOf — the bond
///         binds to Layer 1 for existence and Layer 2 for the materiality verdict,
///         exactly the two bindings in the design note.
interface IScopeRegistry {
    function scopeRootOf(bytes32 scopeId) external view returns (bytes32);
}

/// @title CompletenessBond — Layer 3 reference implementation
/// @notice Defense side of the scope-contestation family. Slashable ONLY by a Layer-2
///         materiality proof (absent at L1 AND material under committed w at L2). A bare
///         L1 nomination MUST NOT slash. Claims F★-sufficiency, not exhaustiveness.
/// @dev    challenge() delegates the whole four-guard materiality decision to
///         layer2.contest() — slash = Layer 2's verdict, never re-implemented. Existence
///         is checked against the Layer-1 registry (scope.scopeRootOf); materiality
///         against Layer 2 (layer2.contest). Two bindings, per the design note.
contract CompletenessBond is ICompletenessBond {

    struct Bond {
        bytes32 scopeId;
        bytes32 wCommitment;
        address bondedParty;
        uint256 amount;        // PERMANENT record (never zeroed) — the standing signal
        uint64  bondStart;
        uint64  termEnd;
        uint64  resolvedAt;    // 0 = live (settle-once guard)
        bool    slashed;
        bool    paidOut;       // anti-double-pay
        bool    exists;
    }

    ILayer2PreCheck public immutable layer2;
    IScopeRegistry  public immutable scope;

    mapping(bytes32 => Bond) private _bonds;
    mapping(address => uint256) private _nonce;

    constructor(IScopeRegistry _scope, ILayer2PreCheck _layer2) {
        require(address(_scope)  != address(0), "zero scope");
        require(address(_layer2) != address(0), "zero layer2");
        scope  = _scope;
        layer2 = _layer2;
    }

    /// @inheritdoc ICompletenessBond
    function postBond(bytes32 scopeId, bytes32 wCommitment, uint64 term)
        external payable returns (bytes32 bondId)
    {
        require(msg.value > 0,             "stake required - the bounty must be real");
        require(term > 0,                  "term required");
        require(wCommitment != bytes32(0), "empty wCommitment");
        require(scope.scopeRootOf(scopeId) != bytes32(0), "scope not committed");

        uint256 n = _nonce[msg.sender]++;
        bondId = keccak256(abi.encode(scopeId, wCommitment, msg.sender, n));
        require(!_bonds[bondId].exists, "bond exists");

        uint64 start = uint64(block.timestamp);
        _bonds[bondId] = Bond({
            scopeId: scopeId, wCommitment: wCommitment, bondedParty: msg.sender,
            amount: msg.value, bondStart: start, termEnd: start + term,
            resolvedAt: 0, slashed: false, paidOut: false, exists: true
        });
        emit BondPosted(bondId, scopeId, wCommitment, msg.sender, msg.value, start + term);
    }

    /// @inheritdoc ICompletenessBond
    /// @notice Slash path — delegates the full four-guard decision to layer2.contest().
    ///         separated==true → material → slash. separated==false → immaterial → bond
    ///         stands, coordinate stays open (no pre-burn lockout). Bare L1 nomination
    ///         does not slash (Guarantee 1).
    function challenge(
        bytes32 bondId,
        bytes calldata nominatedCoordinate,
        bytes calldata materialityProof
    ) external {
        Bond storage b = _bonds[bondId];
        require(b.exists,                    "no such bond");
        require(b.resolvedAt == 0,           "bond already resolved");
        require(block.timestamp < b.termEnd, "bond term ended");

        bool separated = layer2.contest(b.scopeId, nominatedCoordinate, materialityProof);
        if (!separated) return;

        b.slashed    = true;
        b.resolvedAt = uint64(block.timestamp);

        bytes32 coordinateId = keccak256(nominatedCoordinate);
        emit BondChallenged(bondId, coordinateId, msg.sender);
        emit BondResolved(bondId, true);
        _payout(b, payable(msg.sender));
    }

    /// @inheritdoc ICompletenessBond
    function reclaim(bytes32 bondId) external {
        Bond storage b = _bonds[bondId];
        require(b.exists,                     "no such bond");
        require(msg.sender == b.bondedParty,  "not bonded party");
        require(block.timestamp >= b.termEnd, "term not ended");
        require(b.resolvedAt == 0,            "already resolved");
        require(!b.slashed,                   "slashed");

        b.resolvedAt = uint64(block.timestamp);
        emit BondResolved(bondId, false);
        _payout(b, payable(b.bondedParty));
    }

    /// @dev Single pay path; anti-double-pay via paidOut. amount preserved as the
    ///      historical bounty record; settle-once via resolvedAt, double-pay via paidOut.
    function _payout(Bond storage b, address payable to) private {
        require(!b.paidOut, "already paid");
        b.paidOut = true;
        (bool ok,) = to.call{value: b.amount}("");
        require(ok, "transfer failed");
    }

    /// @inheritdoc ICompletenessBond
    function survival(bytes32 bondId)
        external view
        returns (uint256 amount, uint64 bondStart, uint64 termEnd,
                 uint64 resolvedAt, bool slashed, bool challenged)
    {
        Bond storage b = _bonds[bondId];
        return (b.amount, b.bondStart, b.termEnd, b.resolvedAt, b.slashed, b.slashed);
    }

    /// @inheritdoc ICompletenessBond
    function getBond(bytes32 bondId)
        external view
        returns (bytes32 scopeId, bytes32 wCommitment, address bondedParty,
                 uint256 amount, uint64 termEnd)
    {
        Bond storage b = _bonds[bondId];
        return (b.scopeId, b.wCommitment, b.bondedParty, b.amount, b.termEnd);
    }
}
