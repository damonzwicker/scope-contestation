// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title ISourceAuthVerifier — the tier-0 upgrade slot
/// @notice Fully on-chain verification of a web-proof (zkTLS attested-fetch):
///         a Solidity verifier for the SNARK + TLS certificate-chain check. When
///         a SourceAuthResolution is configured with a non-zero verifier, tier-0
///         commits are verified IN CONSENSUS and settle with no off-chain
///         re-verification trust — the trust-maximal tier, mirroring the tier-0
///         (Bitcoin-PoW / trust-maximal) leg of the L2 OpenTimestamps anchoring.
///
/// @dev This is deliberately a SLOT, not a shipped verifier. Production zkTLS
///      Solidity verifiers are not yet mature enough to hard-wire (see
///      SOURCE-AUTH-NOTE.md §Landscape). Leaving it as an injectable interface
///      lets tier-1..3 digest-commit ship TONIGHT while tier-0 lands later
///      WITHOUT changing SourceAuthResolution's storage or the guard-7 path.
///
/// @dev A conforming verifier MUST:
///      1. bind the proof to the SERVER'S OWN certificate chain, validated to a
///         trusted root at `timePin` (not to any notary/attestor key);
///      2. verify the transcript-commitment / SNARK so that soundness reduces to
///         {TLS PRF, SNARK soundness} ONLY — the notary-signature assumption MUST
///         drop out (this is what separates tier-0 from tier-2/3);
///      3. bind the extracted (key ⇒ valueAttested) to a COMMITTED parse rule, so
///         the value is derived from disclosed transcript bytes, never accepted as
///         a claimant-supplied scalar;
///      4. be a pure function of `webProof` and public inputs — RECOMPUTABLE by
///         anyone, on or off chain, with identical result.
interface ISourceAuthVerifier {
    /// @param webProof  Opaque proof bytes (e.g. TLSNotary MPC-ZK web proof +
    ///                  disclosed transcript + parse-rule opening).
    /// @return ok            True iff the proof verifies under (1)–(4).
    /// @return sourceId      keccak of the canonical source descriptor (host+path+…).
    /// @return key           The queried key inside the source response.
    /// @return valueAttested The value bound by the proof for `key`.
    /// @return timePin       The pinned time the session occurred (unix seconds).
    /// @return certChainCommit Commitment to the server cert chain the proof bound to.
    function verify(bytes calldata webProof)
        external
        view
        returns (
            bool    ok,
            bytes32 sourceId,
            bytes32 key,
            bytes32 valueAttested,
            uint64  timePin,
            bytes32 certChainCommit
        );
}
