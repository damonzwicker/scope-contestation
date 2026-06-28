// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CompletenessBond}   from "../src/CompletenessBond.sol";
import {ICompletenessBond}  from "../src/ICompletenessBond.sol";

import {Layer2PreCheck}        from "../src/Layer2PreCheck.sol";
import {ScopeContestation}     from "../src/ScopeContestation.sol";
import {ResolutionCommitment}  from "../src/ResolutionCommitment.sol";
import {MajorityClassifier}    from "../src/MajorityClassifier.sol";
import {IScopeContestation}    from "../src/IScopeContestation.sol";
import {IResolutionCommitment} from "../src/IResolutionCommitment.sol";
import {IScopeClassifier}      from "../src/IScopeClassifier.sol";
import {Vote, NIProof}         from "../src/ScopeTypes.sol";

/// @title CompletenessBondTest
/// @notice Layer-3 bond mechanics wired against the live Layer2PreCheck reference
///         (the same four-guard contest() the ContestFlow suite proves, 13/13 green).
///         These tests exercise the BOND, not the guards. A MockLayer2 isolates the
///         bond's branching on separated/revert; the full four-guard path is covered
///         by ContestFlow 13/13.
contract CompletenessBondTest is Test {

    CompletenessBond bond;
    MockLayer2       l2;

    address constant STAKER     = address(0x5742);
    address constant CHALLENGER = address(0xC0FFEE);

    bytes32 constant SCOPE   = keccak256("scope-A");
    bytes32 constant WCOMMIT = keccak256("w-(root,classifier,params)");

    function setUp() public {
        l2 = new MockLayer2();
        l2.setScopeRoot(SCOPE, keccak256("committed-root"));
        bond = new CompletenessBond(l2);
        vm.deal(STAKER, 100 ether);
        vm.deal(CHALLENGER, 1 ether);
    }

    function test_postBond_storesAndEscrows() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        (bytes32 sId, bytes32 w, address party, uint256 amt, uint64 termEnd) = bond.getBond(id);
        assertEq(sId, SCOPE);
        assertEq(w, WCOMMIT);
        assertEq(party, STAKER);
        assertEq(amt, 10 ether);
        assertEq(uint256(termEnd), block.timestamp + 30 days);
        assertEq(address(bond).balance, 10 ether);
    }

    function test_postBond_zeroStakeReverts() public {
        vm.prank(STAKER);
        vm.expectRevert("stake required - the bounty must be real");
        bond.postBond{value: 0}(SCOPE, WCOMMIT, 30 days);
    }

    function test_postBond_uncommittedScopeReverts() public {
        vm.prank(STAKER);
        vm.expectRevert("scope not committed");
        bond.postBond{value: 1 ether}(keccak256("ghost"), WCOMMIT, 30 days);
    }

    function test_postBond_nonceMakesDistinctIds() public {
        vm.startPrank(STAKER);
        bytes32 a = bond.postBond{value: 1 ether}(SCOPE, WCOMMIT, 30 days);
        bytes32 b = bond.postBond{value: 1 ether}(SCOPE, WCOMMIT, 30 days);
        vm.stopPrank();
        assertTrue(a != b, "distinct bondIds");
    }

    function test_challenge_materialOmission_slashes() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        l2.setSeparated(true);
        uint256 before = CHALLENGER.balance;
        vm.prank(CHALLENGER);
        bond.challenge(id, bytes("X-descriptor"), bytes("a,b,absence"));
        (uint256 amt,,, uint64 resolvedAt, bool slashed, bool challenged) = bond.survival(id);
        assertTrue(slashed,    "material omission must slash");
        assertTrue(challenged, "challenged flag set on slash");
        assertGt(uint256(resolvedAt), 0, "resolved");
        assertEq(amt, 10 ether, "amount PRESERVED, not zeroed");
        assertEq(CHALLENGER.balance, before + 10 ether, "bounty paid");
        assertEq(address(bond).balance, 0, "stake left contract");
    }

    function test_challenge_immaterialOmission_doesNotSlash() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        l2.setSeparated(false);
        vm.prank(CHALLENGER);
        bond.challenge(id, bytes("X-immaterial"), bytes("a,b,absence"));
        (uint256 amt,,, uint64 resolvedAt, bool slashed,) = bond.survival(id);
        assertFalse(slashed,           "immaterial must NOT slash");
        assertEq(uint256(resolvedAt), 0, "still live");
        assertEq(amt, 10 ether,         "stake untouched");
        assertEq(address(bond).balance, 10 ether, "no payout");
    }

    function test_challenge_immaterialThenMaterial_sameCoordinate_stillSlashes() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        l2.setSeparated(false);
        vm.prank(CHALLENGER);
        bond.challenge(id, bytes("X"), bytes("weak-pair"));
        l2.setSeparated(true);
        vm.prank(CHALLENGER);
        bond.challenge(id, bytes("X"), bytes("strong-pair"));
        (,,,, bool slashed,) = bond.survival(id);
        assertTrue(slashed, "stronger pair on same coordinate must still slash");
    }

    function test_challenge_guardRevertBubbles() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        l2.setRevert(true);
        vm.prank(CHALLENGER);
        vm.expectRevert("mock: guard failed");
        bond.challenge(id, bytes("X"), bytes("bad-proof"));
        (uint256 amt,,, uint64 resolvedAt,,) = bond.survival(id);
        assertEq(uint256(resolvedAt), 0, "guard revert leaves bond untouched");
        assertEq(amt, 10 ether);
    }

    function test_challenge_afterSlash_reverts() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        l2.setSeparated(true);
        vm.prank(CHALLENGER);
        bond.challenge(id, bytes("X"), bytes("proof"));
        vm.prank(CHALLENGER);
        vm.expectRevert("bond already resolved");
        bond.challenge(id, bytes("Y"), bytes("proof2"));
    }

    function test_reclaim_afterTerm_survived() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        vm.warp(block.timestamp + 30 days);
        uint256 before = STAKER.balance;
        vm.prank(STAKER);
        bond.reclaim(id);
        (,,, uint64 resolvedAt, bool slashed,) = bond.survival(id);
        assertFalse(slashed);
        assertGt(uint256(resolvedAt), 0, "resolved by reclaim");
        assertEq(STAKER.balance, before + 10 ether, "stake returned");
    }

    function test_reclaim_beforeTermReverts() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        vm.prank(STAKER);
        vm.expectRevert("term not ended");
        bond.reclaim(id);
    }

    function test_reclaim_notBondedPartyReverts() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        vm.warp(block.timestamp + 30 days);
        vm.prank(CHALLENGER);
        vm.expectRevert("not bonded party");
        bond.reclaim(id);
    }

    function test_reclaim_afterSlashReverts() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        l2.setSeparated(true);
        vm.prank(CHALLENGER);
        bond.challenge(id, bytes("X"), bytes("proof"));
        vm.warp(block.timestamp + 30 days);
        vm.prank(STAKER);
        vm.expectRevert("already resolved");
        bond.reclaim(id);
    }

    function test_challenge_atTermEnd_reverts() public {
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        vm.warp(block.timestamp + 30 days);
        l2.setSeparated(true);
        vm.prank(CHALLENGER);
        vm.expectRevert("bond term ended");
        bond.challenge(id, bytes("X"), bytes("proof"));
    }

    function test_challenge_reentrancyGuarded() public {
        ReentrantChallenger r = new ReentrantChallenger(bond);
        vm.deal(address(r), 0);
        vm.prank(STAKER);
        bytes32 id = bond.postBond{value: 10 ether}(SCOPE, WCOMMIT, 30 days);
        l2.setSeparated(true);
        r.attack(id);
        assertEq(address(bond).balance, 0);
        assertEq(address(r).balance, 10 ether, "exactly one bounty, no double-spend");
    }
}

contract MockLayer2 {
    mapping(bytes32 => bytes32) public roots;
    bool private _separated;
    bool private _revert;
    function setScopeRoot(bytes32 id, bytes32 r) external { roots[id] = r; }
    function setSeparated(bool s) external { _separated = s; }
    function setRevert(bool r) external { _revert = r; }
    function scopeRootOf(bytes32 id) external view returns (bytes32) { return roots[id]; }
    function contest(bytes32, bytes calldata, bytes calldata) external view returns (bool) {
        require(!_revert, "mock: guard failed");
        return _separated;
    }
}

contract ReentrantChallenger {
    CompletenessBond bond;
    bytes32 target;
    bool entered;
    constructor(CompletenessBond _bond) { bond = _bond; }
    function attack(bytes32 id) external {
        target = id;
        bond.challenge(id, bytes("X"), bytes("proof"));
    }
    receive() external payable {
        if (!entered) {
            entered = true;
            try bond.challenge(target, bytes("X"), bytes("proof")) {} catch {}
        }
    }
}
