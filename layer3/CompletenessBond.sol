// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {ICompletenessBond} from "./ICompletenessBond.sol";

// Layer2PreCheck interface — wired against the hack-ens-recovery reference impl
// (TMerlini/hack-ens-recovery/scope-contestation-demo, four-guard contest(), 13/13
// green). When Jimmy's canonical ILayer2PreCheck lands this import swaps; the logic
// is identical because the shape is identical (Tiago confirmed: swap, not restart).
interface ILayer2PreCheck {
    /// @notice Contest that coordinate X was material to THE resolution. Runs the four
    ///         guards in fixed order, reverting on any guard failure:
    ///         verifyAbsence → verifyScopeComplete → verifyValueFidelity → isolation → classify
    /// @param nominatedCoordinate the RAW coordinate descriptor (pre-image); contest()
    ///        derives coordinateHash = keccak256(nominatedCoordinate) internally.
    /// @param proof abi.encode(bytes a, bytes b, bytes verifyAbsenceProof)
    /// @return separated true iff w(a) != w(b) AND all four guards pass.
    function contest(
        bytes32        scopeId,
        bytes calldata nominatedCoordinate,
        bytes calldata proof
    ) external returns (bool separated);

    /// @notice The committed scopeRoot for a market (provenance check on postBond).
    function scopeRootOf(bytes32 scopeId) external view returns (bytes32);
}

/// @title CompletenessBond — Layer 3 reference implementation
///
/// @notice The defense side of the scope-contestation family. Layers 1 and 2 are the
///         attack side — they falsify completeness by exhibiting omissions (L1) and
///         proving materiality (L2). This is the defense side: a party stakes a
///         SUFFICIENCY claim over a committed Layer-1 scope and leaves it as a
///         standing, funded invitation to falsify.
///
///         The bond claims F★-completeness (the minimal sufficient set from The
///         Geometry of Knowability), not exhaustiveness. It is slashable ONLY by a
///         Layer-2 materiality proof — a coordinate both absent from the committed
///         scope (L1) AND material under the committed w (L2). A bare L1 nomination
///         (immaterial omission) MUST NOT slash. That line is what makes survival mean
///         something: exhaustiveness bonds always die (E-capture guarantees something
///         is always omitted); sufficiency bonds can stand. "The bond IS the evidence."
///
/// @dev    Wired against the hack-ens-recovery Layer2PreCheck reference. challenge()
///         delegates the entire four-guard materiality decision to contest() — so the
///         slash condition is exactly Layer 2's verdict, never re-implemented here.
///
/// @dev    THE ENFORCED w IS THE MARKET'S, NOT THE BOND'S. The slash is judged by
///         layer2.contest(), which evaluates materiality under the MARKET'S committed
///         (scopeRoot, classifier, params) — not the bond's stored `wCommitment`.
///         `wCommitment` is the staker's DECLARED claim, recorded for disclosure and
///         forward-compat. A bond cannot claim sufficiency under a w different from the
///         market's, because the challenge is always evaluated under the market's w.
///         When Jimmy's canonical ILayer2PreCheck exposes the committed (scopeRoot,
///         classifier, paramsHash) triple, postBond MUST assert wCommitment equals it;
///         today the reference Layer2PreCheck exposes only scopeRootOf, so the equality
///         is enforced structurally at challenge time rather than checked at post time.
///
/// @notice Guarantees (ICompletenessBond): 1 sufficiency-not-exhaustiveness · 2 scope-
///         bound · 3 w-precommitment · 4 non-withdrawable term · 5 settle-once ·
///         6 non-adjudicating signal · 7 recomputable.

contract CompletenessBond is ICompletenessBond {

    // ───────────────────────────── storage ──────────────────────────────────────

    struct Bond {
        bytes32 scopeId;        // Layer-1 scope this bond claims sufficient
        bytes32 wCommitment;    // staker's declared (scopeRoot, classifier, paramsHash)
        address bondedParty;    // staker (may underwrite a scope they didn't commit)
        uint256 amount;         // staked bounty — PERMANENT record (never zeroed)
        uint64  bondStart;      // when the claim began standing
        uint64  termEnd;        // when the stake unlocks (claim window ends)
        uint64  resolvedAt;     // resolution timestamp; 0 = still live (settle-once guard)
        bool    slashed;        // true iff slashed by a material-omission proof
        bool    paidOut;        // true once stake has left the contract (anti-double-pay)
        bool    exists;
    }

    ILayer2PreCheck public immutable layer2;

    mapping(bytes32 => Bond) private _bonds;
    mapping(address => uint256) private _nonce;  // per-staker, for bondId uniqueness

    // ───────────────────────────── constructor ───────────────────────────────────

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
        require(msg.value > 0,              "stake required - the bounty must be real");
        require(term > 0,                   "term required");
        require(wCommitment != bytes32(0),  "empty wCommitment");

        // Scope must exist (can't bond a scope nobody committed). The bond's w is
        // enforced at challenge time via contest() against the market's committed w.
        require(layer2.scopeRootOf(scopeId) != bytes32(0), "scope not committed");

        // bondId binds the staker + a per-staker nonce — no same-block collision, and
        // a staker can post any number of bonds over the same scope/w.
        uint256 n = _nonce[msg.sender]++;
        bondId = keccak256(abi.encode(scopeId, wCommitment, msg.sender, n));
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
            paidOut:     false,
            exists:      true
        });

        emit BondPosted(bondId, scopeId, wCommitment, msg.sender, msg.value, start + term);
    }

    // ───────────────────────────── challenge ─────────────────────────────────────

    /// @inheritdoc ICompletenessBond
    ///
    /// @notice The slash path. The entire four-guard materiality decision is delegated
    ///         to layer2.contest() — the slash condition is exactly Layer 2's verdict.
    ///
    ///         contest() runs: verifyAbsence (X ∉ bound scopeRoot, Guarantee 4) →
    ///         verifyScopeComplete (a IS the declared set) → verifyValueFidelity (a's
    ///         values reproduce the committed resolution) → isolation (b = a + exactly
    ///         X) → classify (w(a) vs w(b)). It reverts on any guard failure, so if it
    ///         returns, all four guards passed; the only question is `separated`.
    ///
    ///         separated == true  → X is material → bond slashed to challenger.
    ///         separated == false → X immaterial → bond stands, coordinate stays
    ///                              challengeable with a stronger witness pair (no
    ///                              per-coordinate lockout — that would let a defender
    ///                              pre-burn a known-material coordinate with a weak pair).
    ///
    ///         A bare L1 nomination (X absent but w(a)==w(b)) does NOT slash. Guarantee 1.
    ///
    /// @param bondId             the bond to challenge
    /// @param nominatedCoordinate the RAW coordinate descriptor X (passed straight to
    ///        contest(), which hashes it once — no double-hash, matches the leaf id)
    /// @param materialityProof   abi.encode(bytes a, bytes b, bytes verifyAbsenceProof)
    function challenge(
        bytes32 bondId,
        bytes calldata nominatedCoordinate,
        bytes calldata materialityProof
    ) external {
        Bond storage b = _bonds[bondId];
        require(b.exists,                     "no such bond");
        require(b.resolvedAt == 0,            "bond already resolved");  // settle-once
        require(block.timestamp < b.termEnd,  "bond term ended");        // strict: termEnd is the boundary

        // Delegate the full four-guard materiality decision to Layer 2. Reverts here
        // (bubbling contest()'s guard reverts) leave the bond untouched — no state
        // change, so an immaterial/invalid attempt costs only the challenger's gas and
        // the coordinate remains open.
        bool separated = layer2.contest(b.scopeId, nominatedCoordinate, materialityProof);

        if (!separated) return; // immaterial — bond stands, no lockout

        // Material omission proven under the committed w — slash.
        b.slashed    = true;
        b.resolvedAt = uint64(block.timestamp);   // settle-once: blocks any re-entry/re-challenge

        bytes32 coordinateId = keccak256(nominatedCoordinate);
        emit BondChallenged(bondId, coordinateId, msg.sender);
        emit BondResolved(bondId, true);

        _payout(b, payable(msg.sender));          // bounty → challenger
    }

    // ───────────────────────────── reclaim ───────────────────────────────────────

    /// @inheritdoc ICompletenessBond
    function reclaim(bytes32 bondId) external {
        Bond storage b = _bonds[bondId];
        require(b.exists,                     "no such bond");
        require(msg.sender == b.bondedParty,  "not bonded party");
        require(block.timestamp >= b.termEnd, "term not ended");   // survived the full term
        require(b.resolvedAt == 0,            "already resolved");
        require(!b.slashed,                   "slashed");

        b.resolvedAt = uint64(block.timestamp);
        emit BondResolved(bondId, false);

        _payout(b, payable(b.bondedParty));       // stake → staker
    }

    // ───────────────────────────── internals ─────────────────────────────────────

    /// @dev Single pay path, anti-double-pay via paidOut. `amount` is preserved as the
    ///      permanent historical record of bounty size (the standing signal reads it);
    ///      settle-once is enforced by resolvedAt, double-pay by paidOut.
    function _payout(Bond storage b, address payable to) private {
        require(!b.paidOut, "already paid");
        b.paidOut = true;
        (bool ok,) = to.call{value: b.amount}("");
        require(ok, "transfer failed");
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
        // `amount` is the historical bounty (preserved through resolution).
        // `challenged` == slashed: the only successful challenge is a slash.
        return (b.amount, b.bondStart, b.termEnd, b.resolvedAt, b.slashed, b.slashed);
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
