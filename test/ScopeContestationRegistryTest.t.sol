// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ScopeContestationRegistry.sol";

contract ScopeContestationRegistryTest is Test {
    ScopeContestationRegistry registry;

    // 6 sorted coordinates matching gen_vectors.py (seed=123, vals*7)
    // vals = sorted(sample(range(1000,9000), 6)) * 7
    // We use simple hand-chosen sorted coords for determinism
    bytes32 constant C0 = bytes32(uint256(1000));
    bytes32 constant C1 = bytes32(uint256(2000));
    bytes32 constant C2 = bytes32(uint256(3000));
    bytes32 constant C3 = bytes32(uint256(4000));
    bytes32 constant C4 = bytes32(uint256(5000));
    bytes32 constant C5 = bytes32(uint256(6000));

    bytes32 commitmentHash = bytes32(uint256(0xABCDEF));

    bytes32[] coords;
    bytes32 scopeRoot;
    bytes32 scopeId;

    function leafHash(bytes32 c) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(0), c));
    }

    function nodeHash(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(1), l, r));
    }

    // Build root for 6 sorted leaves
    // Level 0: L0..L5
    // Level 1: N(L0,L1), N(L2,L3), N(L4,L5)
    // Level 2: N(N01,N23), N45 promoted
    // Level 3: N(N0123, N45)
    function buildRoot() internal view returns (bytes32) {
        bytes32 l0 = leafHash(C0); bytes32 l1 = leafHash(C1);
        bytes32 l2 = leafHash(C2); bytes32 l3 = leafHash(C3);
        bytes32 l4 = leafHash(C4); bytes32 l5 = leafHash(C5);
        bytes32 n01 = nodeHash(l0, l1);
        bytes32 n23 = nodeHash(l2, l3);
        bytes32 n45 = nodeHash(l4, l5);
        bytes32 n0123 = nodeHash(n01, n23);
        return nodeHash(n0123, n45);
    }

    // Siblings for leaf at idx in 6-leaf tree
    // idx=0: right=L1, parent-right=N23, parent-right=N45
    function sibsFor0() internal view returns (bytes32[] memory s) {
        s = new bytes32[](3);
        s[0] = leafHash(C1);
        s[1] = nodeHash(leafHash(C2), leafHash(C3));
        s[2] = nodeHash(leafHash(C4), leafHash(C5));
    }
    // idx=1: left=L0, parent-right=N23, parent-right=N45
    function sibsFor1() internal view returns (bytes32[] memory s) {
        s = new bytes32[](3);
        s[0] = leafHash(C0);
        s[1] = nodeHash(leafHash(C2), leafHash(C3));
        s[2] = nodeHash(leafHash(C4), leafHash(C5));
    }
    // idx=2: right=L3, parent-left=N01, parent-right=N45
    function sibsFor2() internal view returns (bytes32[] memory s) {
        s = new bytes32[](3);
        s[0] = leafHash(C3);
        s[1] = nodeHash(leafHash(C0), leafHash(C1));
        s[2] = nodeHash(leafHash(C4), leafHash(C5));
    }
    // idx=3: left=L2, parent-left=N01, parent-right=N45
    function sibsFor3() internal view returns (bytes32[] memory s) {
        s = new bytes32[](3);
        s[0] = leafHash(C2);
        s[1] = nodeHash(leafHash(C0), leafHash(C1));
        s[2] = nodeHash(leafHash(C4), leafHash(C5));
    }
    // idx=4: right=L5, parent-left=N0123 (promoted at level2, no sib), root
    function sibsFor4() internal view returns (bytes32[] memory s) {
        s = new bytes32[](2);
        s[0] = leafHash(C5);
        s[1] = nodeHash(nodeHash(leafHash(C0),leafHash(C1)), nodeHash(leafHash(C2),leafHash(C3)));
    }
    // idx=5: left=L4, parent-left=N0123
    function sibsFor5() internal view returns (bytes32[] memory s) {
        s = new bytes32[](2);
        s[0] = leafHash(C4);
        s[1] = nodeHash(nodeHash(leafHash(C0),leafHash(C1)), nodeHash(leafHash(C2),leafHash(C3)));
    }

    function setUp() public {
        registry = new ScopeContestationRegistry();
        scopeRoot = buildRoot();
        scopeId = registry.commitScope(commitmentHash, scopeRoot, 6);
    }

    // -----------------------------------------------------------------------
    // commitScope
    // -----------------------------------------------------------------------
    function test_commitScope_stores() public view {
        (bytes32 ch, bytes32 sr, uint256 cnt, address committer,) = registry.scopes(scopeId);
        assertEq(ch, commitmentHash);
        assertEq(sr, scopeRoot);
        assertEq(cnt, 6);
        assertEq(committer, address(this));
    }

    function test_commitScope_rejects_duplicate() public {
        vm.expectRevert("exists");
        registry.commitScope(commitmentHash, scopeRoot, 6);
    }

    function test_commitScope_rejects_empty() public {
        vm.expectRevert("empty scope");
        registry.commitScope(commitmentHash, scopeRoot, 0);
    }

    // -----------------------------------------------------------------------
    // nominate — below-min (C < C0)
    // -----------------------------------------------------------------------
    function test_nominate_below_min() public {
        bytes32 absent = bytes32(uint256(500)); // < C0=1000
        ScopeContestationRegistry.NonInclusion memory proof;
        proof.mode = 1;
        proof.loCoord = C0;
        proof.sibsLo = sibsFor0();
        registry.nominate(scopeId, absent, proof);
        assertTrue(registry.nominated(keccak256(abi.encodePacked(scopeId, absent))));
    }

    // -----------------------------------------------------------------------
    // nominate — above-max (C > C5)
    // -----------------------------------------------------------------------
    function test_nominate_above_max() public {
        bytes32 absent = bytes32(uint256(9000)); // > C5=6000
        ScopeContestationRegistry.NonInclusion memory proof;
        proof.mode = 2;
        proof.hiCoord = C5;
        proof.sibsHi = sibsFor5();
        registry.nominate(scopeId, absent, proof);
        assertTrue(registry.nominated(keccak256(abi.encodePacked(scopeId, absent))));
    }

    // -----------------------------------------------------------------------
    // nominate — interior (C1 < absent < C2)
    // -----------------------------------------------------------------------
    function test_nominate_interior() public {
        bytes32 absent = bytes32(uint256(2500)); // C1=2000 < 2500 < C2=3000
        ScopeContestationRegistry.NonInclusion memory proof;
        proof.mode = 0;
        proof.loCoord = C1;
        proof.hiCoord = C2;
        proof.idxLo = 1;
        proof.sibsLo = sibsFor1();
        proof.sibsHi = sibsFor2();
        registry.nominate(scopeId, absent, proof);
        assertTrue(registry.nominated(keccak256(abi.encodePacked(scopeId, absent))));
    }

    // -----------------------------------------------------------------------
    // soundness: DECLARED coordinate must revert
    // -----------------------------------------------------------------------
    function test_soundness_present_coord_reverts() public {
        // Try to nominate C2 (declared at idx=2) using a forged interior proof
        // with non-adjacent neighbors C1(idx=1) and C3(idx=3). idxLo+1 != idxHi -> revert.
        bytes32 present = C2;
        ScopeContestationRegistry.NonInclusion memory proof;
        proof.mode = 0;
        proof.loCoord = C1; proof.hiCoord = C3;
        proof.idxLo = 1; // idxHi would be 3, not idxLo+1=2 -> revert
        proof.sibsLo = sibsFor1();
        proof.sibsHi = sibsFor3();
        vm.expectRevert("coordinate is in scope");
        registry.nominate(scopeId, present, proof);
    }

    // -----------------------------------------------------------------------
    // replay protection
    // -----------------------------------------------------------------------
    function test_replay_reverts() public {
        bytes32 absent = bytes32(uint256(500));
        ScopeContestationRegistry.NonInclusion memory proof;
        proof.mode = 1; proof.loCoord = C0; proof.sibsLo = sibsFor0();
        registry.nominate(scopeId, absent, proof);
        vm.expectRevert("already nominated");
        registry.nominate(scopeId, absent, proof);
    }

    // -----------------------------------------------------------------------
    // no scope
    // -----------------------------------------------------------------------
    function test_nominate_no_scope_reverts() public {
        bytes32 absent = bytes32(uint256(500));
        ScopeContestationRegistry.NonInclusion memory proof;
        proof.mode = 1; proof.loCoord = C0; proof.sibsLo = sibsFor0();
        vm.expectRevert("no scope");
        registry.nominate(bytes32(uint256(0xDEAD)), absent, proof);
    }

    // -----------------------------------------------------------------------
    // gas snapshot: nominate below-min
    // -----------------------------------------------------------------------
    function test_gas_nominate_below_min() public {
        bytes32 absent = bytes32(uint256(500));
        ScopeContestationRegistry.NonInclusion memory proof;
        proof.mode = 1; proof.loCoord = C0; proof.sibsLo = sibsFor0();
        uint256 g = gasleft();
        registry.nominate(scopeId, absent, proof);
        console.log("gas: nominate below-min:", g - gasleft());
    }
}
