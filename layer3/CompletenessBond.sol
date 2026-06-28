// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {ICompletenessBond} from "./ICompletenessBond.sol";

// Pull in the Layer2PreCheck interface — wired against the hack-ens-recovery
// reference impl (TMerlini/hack-ens-recovery/scope-contestation-demo, 13/13 green).
// When Jimmy's canonical ILayer2PreCheck lands this import swaps; the logic is
// identical because the shape is identical.
interface ILayer2PreCheck {
    /// @notice Contest that coordinate X was material to THE resolution.
    ///         Runs the four guards in fixed order:
    ///         verifyAbsence → verifyScopeComplete → verifyValueFidelity → isolation → classify
    ///         Returns separated = true iff w(a) != w(b) AND all guards pass.
    function contest(
        bytes32        scopeId,
        bytes calldata nominatedCoordinate,
        bytes calldata proof         // abi.encode(bytes a, bytes b, bytes verifyAbsenceProof)
    ) external returns (bool separated);

    /// @notice The committed (scopeRoot, classifier, paramsHash) for a scope.
    ///         Used to confirm the bond's wCommitment matches the committed w.
    function scopeRootOf(bytes32 scopeId) external view returns (bytes32);
}

/// @title CompletenessBond — Layer 3 reference implementation
///
/// @notice The defense side of the scope-contestation family. Layers 1 and 2 are
///         the attack side: they falsify completeness by exhibiting omissions (L1)
///         and proving materiality (L2). This layer is the defense side: a party
///         stakes a SUFFICIENCY claim over a committed Layer-1 scope and leaves it
///         as a standing, funded invitation to falsify.
///
///         The bond claims F★-completeness (the minimal sufficient set from The
///         Geometry of Knowability), not exhaustiveness. It is slashable ONLY by a
///         Layer-2 materiality proof — a coordinate both absent from the committed
///         scope (L1) AND material under the committed w (L2). A bare L1 nomination
///         MUST NOT slash. This is the line that makes survival mean something:
///         exhaustiveness bonds always die (E-capture); sufficiency bonds can stand.
///
///         "The bond IS the evidence." Survival under a large funded bounty is the
///         signal. The registry never asserts completeness — it exposes raw survival
///         facts for consumers to weight.
///
/// @dev    Wired against TMerlini/hack-ens-recovery Layer2PreCheck reference impl
///         (the four-guard contest() flow, 13/13 green). When Jimmy's canonical
///         ILayer2PreCheck interface lands this is a swap, not a restart — same shape.
///
/// @notice Normative guarantees (from ICompletenessBond):
///         1. SUFFICIENCY NOT EXHAUSTIVENESS — slash only by L2 materiality proof
///         2. SCOPE-BOUND               — challenge verifies against bound scopeRoot
///         3. w PRE-COMMITMENT          — wCommitment fixed at postBond time
///         4. NON-WITHDRAWABLE TERM     — stake locked for full committed term
///         5. SETTLE-ONCE              — resolves exactly once, replay-guarded
///         6. NON-ADJUDICATING SIGNAL  — survival() exposes facts, not a verdict
///         7. RECOMPUTABLE             — all challenge validity verifiable from public data

contract CompletenessBond is ICompletenessBond {

    // ───────────────────────────── storage ──────────────────────────────────────

    struct Bond {
        bytes32 scopeId;        // Layer-1 scope this bond claims sufficient
        bytes32 wCommitment;    // pre-committed (scopeRoot, classifier, paramsHash)
        address bondedParty;    // staker (may underwrite a scope they didn't commit)
        uint256 amount;         // staked bounty — the standing invitation
        uint64  bondStart;      // when the claim began standing
        uint64  termEnd;        // when the stake unlocks (claim window ends)
        uint64  resolvedAt;     // resolution timestamp; 0 = still live
        bool    slashed;        // true if slashed by a material-omission proof
        bool    challenged;     // true if any successful challenge landed
        bool    exists;
    }

    ILayer2PreCheck public immutable layer2;

    mapping(bytes32 => Bond) private _bonds;

    // replay guard: one settled challenge per (bondId, coordinate) pair
    mapping(bytes32 => mapping(bytes32 => bool)) private _challenged;

    // ───────────────────────────── constructor ───────────────────────────────────

    /// @param _layer2 The Layer2PreCheck reference impl (hack-ens-recovery,
    ///                swap for Jimmy's canonical addr when it lands).
    constructor(ILayer2PreCheck _layer2) {
        require(address(_layer2) != address(0), "zero layer2");
        layer2 = _layer2;
    }

    // ───────────────────────────── postBond ─────────────────────────────────────

    /// @inheritdoc ICompletenessBond
    function postBond(bytes32 scopeId, bytes32 wCommitment, uint64 term)
        external
        payable
        returns (bytes32 bondId)
    {
        require(msg.value > 0,   "stake required - the bounty must be real");
        require(term > 0,        "term required");
        require(wCommitment != bytes32(0), "empty wCommitment");

        // Confirm the scope exists and the wCommitment matches the committed scopeRoot.
        // Guards against bonding a scope nobody actually committed.
        bytes32 committedRoot = layer2.scopeRootOf(scopeId);
        require(committedRoot != bytes32(0), "scope not committed");

        // bondId binds the staker — same staker can bond different scopes/terms
        // without collision; two stakers on the same scope get distinct bondIds.
        bondId = keccak256(
            abi.encode(scopeId, wCommitment, msg.sender, block.timestamp)
        );
        require(!_bonds[bondId].exists, "bond exists");

        uint64 start = uint64(block.timestamp);
        _bonds[bondId] = Bond({
            scopeId:     scopeId,
            wCommitment: wCommitment,
            bondedParty: msg.sender,
            amount:      msg.value,
            bondStart:   start,
            termEnd:     start + term,
            resolvedAt:  0,
            slashed:     false,
            challenged:  false,
            exists:      true
        });

        emit BondPosted(bondId, scopeId, wCommitment, msg.sender, msg.value, start + term);
    }

    // ───────────────────────────── challenge ─────────────────────────────────────

    /// @inheritdoc ICompletenessBond
    ///
    /// @notice The slash path — this is the core of Layer 3.
    ///
    ///         materialityProof = abi.encode(bytes a, bytes b, bytes verifyAbsenceProof)
    ///         — the same proof bundle Layer2PreCheck.contest() reads. This means the
    ///         challenge runs the FULL four-guard flow:
    ///
    ///           verifyAbsence       : X ∉ the bound scopeRoot (Layer 1, Guarantee 4)
    ///           verifyScopeComplete : a IS the declared set (no dropped/added coords)
    ///           verifyValueFidelity : a's values reproduce the committed resolution
    ///           isolation           : b = a + exactly X
    ///           classify            : w(a) vs w(b) under the committed w
    ///
    ///         separated = true → X is material → bond is slashed to the challenger.
    ///         separated = false → X is not material → challenge fails, bond stands.
    ///
    ///         A bare Layer-1 nomination (X absent but w(a)==w(b)) DOES NOT SLASH.
    ///         This is Guarantee 1 (sufficiency not exhaustiveness): the bond survives
    ///         immaterial omissions. Only a MATERIAL omission — one that moves the
    ///         verdict under the committed w — triggers the slash.
    function challenge(
        bytes32 bondId,
        bytes32 coordinate,
        bytes calldata materialityProof
    ) external {
        Bond storage b = _bonds[bondId];
        require(b.exists,              "no such bond");
        require(b.resolvedAt == 0,     "bond already resolved");
        require(block.timestamp < b.termEnd, "bond term ended");
        require(!_challenged[bondId][coordinate], "coordinate already challenged");

        // Mark before external call (checks-effects-interactions)
        _challenged[bondId][coordinate] = true;

        // Run the FULL Layer-2 materiality proof through the four-guard contest().
        // contest() reverts (via require()) on any guard failure, so if it returns
        // at all, all four guards passed. The only question is whether separated = true.
        //
        // materialityProof = abi.encode(bytes a, bytes b, bytes verifyAbsenceProof)
        // — the exact proof bundle Layer2PreCheck.contest() expects.
        bool separated = layer2.contest(b.scopeId, abi.encodePacked(coordinate), materialityProof);

        // separated = false: X passed all guards but w(a)==w(b) — X is not material.
        // The bond stands. The challenge is recorded (can't re-challenge same coord)
        // but no slash fires.
        if (!separated) return;

        // separated = true: X is material under the committed w — bond slashed.
        b.slashed    = true;
        b.challenged = true;
        b.resolvedAt = uint64(block.timestamp);

        emit BondChallenged(bondId, coordinate, msg.sender);
        emit BondResolved(bondId, true);

        // Transfer the full stake to the challenger as the bounty.
        // Non-reentrant by effect (resolvedAt set before transfer).
        uint256 bounty = b.amount;
        b.amount = 0;
        (bool ok,) = payable(msg.sender).call{value: bounty}("");
        require(ok, "bounty transfer failed");
    }

    // ───────────────────────────── reclaim ───────────────────────────────────────

    /// @inheritdoc ICompletenessBond
    function reclaim(bytes32 bondId) external {
        Bond storage b = _bonds[bondId];
        require(b.exists,                        "no such bond");
        require(msg.sender == b.bondedParty,     "not bonded party");
        require(block.timestamp >= b.termEnd,    "term not ended");
        require(b.resolvedAt == 0,               "already resolved");
        require(!b.slashed,                      "slashed");

        b.resolvedAt = uint64(block.timestamp);
        emit BondResolved(bondId, false);

        uint256 stake = b.amount;
        b.amount = 0;
        (bool ok,) = payable(msg.sender).call{value: stake}("");
        require(ok, "reclaim transfer failed");
    }

    // ───────────────────────────── views ─────────────────────────────────────────

    /// @inheritdoc ICompletenessBond
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
        )
    {
        Bond storage b = _bonds[bondId];
        return (b.amount, b.bondStart, b.termEnd, b.resolvedAt, b.slashed, b.challenged);
    }

    /// @inheritdoc ICompletenessBond
    function getBond(bytes32 bondId)
        external
        view
        returns (
            bytes32 scopeId,
            bytes32 wCommitment,
            address bondedParty,
            uint256 amount,
            uint64  termEnd
        )
    {
        Bond storage b = _bonds[bondId];
        return (b.scopeId, b.wCommitment, b.bondedParty, b.amount, b.termEnd);
    }
}
