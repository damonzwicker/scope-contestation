# Forge confirmation — ScopeContestationRegistry

Independent run of the one check the sandbox couldn't (`forge`), on a real Foundry toolchain — the
reciprocal of the on-EVM reproduction Damon ran for hack-ens-recovery's `BIP340Verifier`.

**Run by:** @TMerlini · Foundry (`forge`) · solc 0.8.26 · 2026-06-24.

## Result — 10/10 green
`forge test` over `test/ScopeContestationRegistryTest.t.sol` against `src/ScopeContestationRegistry.sol`:

```
[PASS] test_commitScope_stores
[PASS] test_commitScope_rejects_empty
[PASS] test_commitScope_rejects_duplicate
[PASS] test_nominate_below_min
[PASS] test_nominate_interior
[PASS] test_nominate_above_max
[PASS] test_nominate_no_scope_reverts
[PASS] test_replay_reverts
[PASS] test_soundness_present_coord_reverts
[PASS] test_gas_nominate_below_min
10 passed, 0 failed, 0 skipped
```
Clean compile (solc 0.8.26; only the standard view-mutability lint).

## Gas (`forge --gas-report`)
| function | min | avg | median | max | calls |
|---|---|---|---|---|---|
| `commitScope` | 22,888 | 100,277 | 115,466 | 115,466 | 12 |
| `nominate`    | 27,410 | 52,449  | 61,318  | 68,572  | 8 |
| `nominated`   | 2,829  | 2,829   | 2,829   | 2,829   | 3 |

`nominate`: ~27k on the cheap reverts (no-scope / already-nominated), up to ~69k for an interior
non-inclusion proof — cheap-checks-first + CEI hold under real execution.

## What it confirms (in real EVM)
- **Soundness:** a *present* coordinate reverts (`test_soundness_present_coord_reverts`); a replay reverts.
- **Completeness:** absent coordinates — below-min, interior, above-max — all nominate successfully.
- Matches the Python reference (6364/0) and the in-process `@ethereumjs` EVM run.

So the verification record is now complete across all three harnesses — **Python core · in-process EVM ·
forge** — on three independent toolchains.
