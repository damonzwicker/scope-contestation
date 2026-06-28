// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";

import {ScopeContestation}    from "../src/ScopeContestation.sol";
import {ResolutionCommitment} from "../src/ResolutionCommitment.sol";
import {MajorityClassifier}   from "../src/MajorityClassifier.sol";
import {Layer2PreCheck}       from "../src/Layer2PreCheck.sol";
import {CompletenessBond, IScopeRegistry, ILayer2PreCheck} from "../src/CompletenessBond.sol";

import {IScopeContestation}    from "../src/IScopeContestation.sol";
import {IResolutionCommitment} from "../src/IResolutionCommitment.sol";

/// @title DeployStack — wires the full scope-contestation stack (L1 + L2 + L3) and
///        prints pinned addresses for the Layer-3 integration test.
///
/// @notice Deployment order is dependency order:
///           1. ScopeContestation    (L1 — owns scopeRootOf)
///           2. ResolutionCommitment (L1 value-fidelity, type-2)
///           3. MajorityClassifier   (L2 reference classifier)
///           4. Layer2PreCheck       (L2; ctor: scope, resolution)
///           5. CompletenessBond     (L3; ctor: scope [existence], layer2 [verdict])
///
///        The bond binds to TWO contracts — Layer-1 registry for the postBond existence
///        check (scope.scopeRootOf), Layer-2 pre-check for the challenge() materiality
///        verdict (layer2.contest). A mock can't exercise this wiring.
///
/// Usage: forge script script/Deploy.s.sol:DeployStack --rpc-url <url> --broadcast
contract DeployStack is Script {

    struct Deployed {
        address scope;
        address resolution;
        address classifier;
        address layer2;
        address bond;
    }

    function run() external returns (Deployed memory d) {
        vm.startBroadcast();

        ScopeContestation    scope      = new ScopeContestation();
        ResolutionCommitment resolution = new ResolutionCommitment();
        MajorityClassifier   classifier = new MajorityClassifier();

        Layer2PreCheck layer2 = new Layer2PreCheck(
            IScopeContestation(address(scope)),
            IResolutionCommitment(address(resolution))
        );

        CompletenessBond bond = new CompletenessBond(
            IScopeRegistry(address(scope)),
            ILayer2PreCheck(address(layer2))
        );

        vm.stopBroadcast();

        d = Deployed({
            scope:      address(scope),
            resolution: address(resolution),
            classifier: address(classifier),
            layer2:     address(layer2),
            bond:       address(bond)
        });

        console.log("=== scope-contestation stack deployed ===");
        console.log("ScopeContestation   (L1):", d.scope);
        console.log("ResolutionCommitment(L1):", d.resolution);
        console.log("MajorityClassifier  (L2):", d.classifier);
        console.log("Layer2PreCheck      (L2):", d.layer2);
        console.log("CompletenessBond    (L3):", d.bond);
    }
}
