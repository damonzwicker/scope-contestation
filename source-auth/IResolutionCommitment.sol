// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IResolutionCommitment — canonical (copied verbatim from
///        hack-ens-recovery/scope-contestation-demo/contracts/src/IResolutionCommitment.sol)
interface IResolutionCommitment {

    event ResolutionCommitted(bytes32 indexed scopeId, bytes32 resolutionRoot);

    function commitResolution(bytes32 scopeId, bytes32 resolutionRoot) external;

    function resolutionRootOf(bytes32 scopeId) external view returns (bytes32);

    /// @notice Bulk value-fidelity guard (a's (id,value) pairs vs committed root).
    function verifyValueFidelity(bytes32 scopeId, bytes calldata a)
        external view returns (bool faithful);

    /// @notice Guard 7 — pin a SINGLE coordinate X's value against the committed
    ///         resolution. X is not in `a` so it cannot ride verifyValueFidelity.
    /// @param scopeId  the market identifier
    /// @param key      X's sourceId (== coordinateHash)
    /// @param value    abi.encode(delta.option) — contester's claimed reading at X
    /// @return ok      true iff X's claimed value reproduces its committed reading
    function verifyCoordinateValue(bytes32 scopeId, bytes32 key, bytes calldata value)
        external view returns (bool ok);
}
