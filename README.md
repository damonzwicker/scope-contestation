# scope-contestation

The completeness/contestability layer for the agent-economics stack. An agent
commits the coordinate set it observed (bound to its OCP/8281 layer-0
commitment); anyone can permissionlessly **nominate** a coordinate it did *not*
observe, proving on-chain (sorted-Merkle non-inclusion) that the coordinate is
genuinely absent. The registry adjudicates nothing — it makes omission
contestable and permanent, never invisible.

Read `NOTE.md` first — it's the spec, the soundness argument, and the
adversarial pre-registration.

## Layout

```
scope-contestation/
├── NOTE.md                              spec + principle + adversarial notes
├── README.md                            this file
├── src/ScopeContestationRegistry.sol    the contract (CC0)
├── reference/scope_ref.py               independent Python reference (the core)
├── test/test_core.py                    soundness + completeness suite
├── compile.js                           solc compile check
├── gen_vectors.py                       generates vectors.json for the EVM test
└── evm_test.mjs                         end-to-end in-process EVM run
```

## Run it

Run everything from THIS directory (the one containing this README). Do **not**
run inside another project — it installs its own node deps.

### 1. Core suite (no deps beyond Python + pycryptodome)

```bash
pip install pycryptodome
python3 test/test_core.py
```
Expect: `6364 passed, 0 failed`.

### 2. Compile + on-chain end-to-end

```bash
npm init -y
npm install solc@0.8.26 @ethereumjs/vm@8.1.1 @ethereumjs/common@4.4.0 @ethereumjs/tx@5.4.0 @ethereumjs/util@9.1.0 ethers@6
node compile.js          # clean compile, 0 warnings
python3 gen_vectors.py    # writes vectors.json from the verified reference
node evm_test.mjs        # all on-chain checks pass
```

`evm_test.mjs` deploys the contract, commits a scope, then nominates: absent
coordinates (below-min / interior / above-max) succeed, a replay reverts, and a
**present coordinate reverts** (soundness in real EVM execution).

### 3. forge (your toolchain — the one check not run in the sandbox)

Drop `src/ScopeContestationRegistry.sol` into a foundry project and run your own
tests + gas profiling. The sandbox couldn't fetch foundry binaries; this is the
remaining confirm.

## Status

Core: 6364/0 (membership all sizes/indices incl. odd-promote, completeness,
soundness incl. forgery + cross-root). Contract: solc 0.8.26, 0 warnings.
On-chain end-to-end: pass. See `NOTE.md` for the full verification record.

CC0-1.0.
