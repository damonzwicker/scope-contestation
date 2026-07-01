import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const solc = require('solc');
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork, Chain } = require('@ethereumjs/common');
const { Block } = require('@ethereumjs/block');
const { LegacyTransaction } = require('@ethereumjs/tx');
const { Account, Address, hexToBytes, privateToAddress } = require('@ethereumjs/util');
const { ethers } = require('ethers');
const path = require('path');

// compile
const dir = 'source-auth';
const files = ['IResolutionCommitment.sol', 'ISourceAuthVerifier.sol', 'SourceAuthResolution.sol'];
const sources = {};
for (const f of files) sources[f] = { content: readFileSync(path.join(dir, f), 'utf8') };
function findImports(p) {
  const base = path.basename(p);
  try { return { contents: sources[base]?.content ?? readFileSync(path.join(dir, base), 'utf8') }; }
  catch (e) { return { error: 'not found: ' + p }; }
}
const input = { language: 'Solidity', sources,
  settings: { optimizer: { enabled: true, runs: 200 }, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } };
const out = JSON.parse(solc.compile(JSON.stringify(input), { import: findImports }));
const errs = (out.errors || []).filter(e => e.severity === 'error');
if (errs.length) { errs.forEach(e => console.log(e.formattedMessage)); process.exit(1); }
const C = out.contracts['SourceAuthResolution.sol']['SourceAuthResolution'];
const abi = C.abi;
const bytecode = '0x' + C.evm.bytecode.object;
const iface = new ethers.Interface(abi);

// EVM
const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Shanghai });
const testBlock = Block.fromBlockData(
  { header: { number: 1n, timestamp: 1_700_001_000n, gasLimit: 30_000_000n } },
  { common });
const vm = await VM.create({ common });
const pk = hexToBytes('0x' + '11'.repeat(32));
const senderAddr = new Address(privateToAddress(pk));
await vm.stateManager.putAccount(senderAddr, new Account(0n, 10n ** 20n));

async function send(to, data, value = 0n) {
  const acct = await vm.stateManager.getAccount(senderAddr);
  const tx = LegacyTransaction.fromTxData(
    { to: to ?? undefined, data, gasLimit: 8_000_000n, gasPrice: 100n, nonce: acct.nonce, value },
    { common }).sign(pk);
  return vm.runTx({ tx, block: testBlock, skipBalance: true });
}
async function call(to, data) {
  const res = await vm.evm.runCall({
    to: new Address(hexToBytes(to)), caller: senderAddr, origin: senderAddr,
    data: hexToBytes(data), gasLimit: 8_000_000n,
  });
  return '0x' + Buffer.from(res.execResult.returnValue).toString('hex');
}

// deploy: constructor(ISourceAuthVerifier=0, uint256 tier2Floor, Tier maxTier)
// Tier.BARE_ATTESTOR = 3 => accept all tiers in tests
const ctor = iface.encodeDeploy([ethers.ZeroAddress, ethers.parseEther('1'), 3]);
let r = await send(null, hexToBytes(bytecode + ctor.slice(2)));
if (r.execResult.exceptionError) { console.log('DEPLOY FAIL', r.execResult.exceptionError); process.exit(1); }
const addr = r.createdAddress.toString();
console.log('deployed at', addr);

// shared test data
const SCOPE_ID = '0x' + '42'.padStart(64, '0');
const VALUE    = ethers.toBeHex(57, 32);  // abi.encode(uint256(57)) — stand-in for delta.option
const VALUE_BAD= ethers.toBeHex(99, 32);
const tupleArr = [
  '0x' + Buffer.from('tlsn-mpc-zk-v1'.padEnd(32,'\0')).toString('hex'),  // schemeId
  ethers.toBeHex(2, 32),   // coordinate
  '0x' + Buffer.from('example.com/api'.padEnd(32,'\0')).toString('hex'),  // sourceId
  ethers.toBeHex(2, 32),   // key (== coordinate == delta.sourceId)
  VALUE,                    // valueCommitted (bytes)
  1_700_000_000n,           // timePin (uint64)
  ethers.toBeHex(0xAB, 32), // parseRuleCommit
  ethers.toBeHex(0xCD, 32), // certChainCommit
  ethers.toBeHex(0, 32),    // timeAnchorCommit
  1,                        // tier: REVERIFIABLE
  0n,                       // stakeBacking
  '0x',                     // webProof
];

let pass = 0, fail = 0;
const check = (name, cond) => { if (cond) pass++; else { fail++; console.log('  FAIL:', name); } };
function parseLogs(logs, iface) {
  const parsed = [];
  for (const [, topics, data] of (logs || [])) {
    try {
      const p = iface.parseLog({
        topics: topics.map(t => '0x' + Buffer.from(t).toString('hex')),
        data: '0x' + Buffer.from(data).toString('hex'),
      });
      if (p) parsed.push(p);
    } catch (e) {}
  }
  return parsed;
}

// 1. digestOf — cross-check vs Python reference
// Python produced: we'll compute the reference independently via ethers
const digest_data = iface.encodeFunctionData('digestOf', [SCOPE_ID, tupleArr]);
const digest_ret  = await call(addr, digest_data);
const evmDigest   = iface.decodeFunctionResult('digestOf', digest_ret)[0];
console.log('EVM digestOf:', evmDigest);
// Re-derive via ethers ABI encode (independent of Python)
const valueHash = ethers.keccak256(VALUE);
const recomputed = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','uint64','bytes32','bytes32','bytes32'],
  [SCOPE_ID, tupleArr[0], tupleArr[1], tupleArr[2], tupleArr[3],
   valueHash, 1_700_000_000n, tupleArr[6], tupleArr[7], tupleArr[8]]
));
console.log('ethers recompute:', recomputed);
check('digestOf: EVM == ethers recompute', evmDigest.toLowerCase() === recomputed.toLowerCase());

// 2. commitSourceAuth -> VERIFIED
r = await send(addr, hexToBytes(iface.encodeFunctionData('commitSourceAuth', [SCOPE_ID, tupleArr])));
if (r.execResult.exceptionError) { console.log('COMMIT FAIL', r.execResult.exceptionError); process.exit(1); }
const logs2 = parseLogs(r.execResult.logs, iface);
const committed = logs2.find(l => l.name === 'SourceAuthCommitted');
check('commit emitted SourceAuthCommitted', !!committed);
check('emitted attDigest == digestOf', committed?.args?.attDigest?.toLowerCase() === evmDigest.toLowerCase());
check('verdict == VERIFIED (1)', Number(committed?.args?.verdict) === 1);

// 3. verifyCoordinateValue: faithful -> true
const vcv = (scope, key, val) =>
  iface.encodeFunctionData('verifyCoordinateValue', [scope, key, val]);
const key = ethers.toBeHex(2, 32);
let ret = await call(addr, vcv(SCOPE_ID, key, VALUE));
check('guard7 true (faithful)',
  iface.decodeFunctionResult('verifyCoordinateValue', ret)[0] === true);

// 4. guard7: adversarial value -> false
ret = await call(addr, vcv(SCOPE_ID, key, VALUE_BAD));
check('guard7 false (adversarial value)',
  iface.decodeFunctionResult('verifyCoordinateValue', ret)[0] === false);

// 5. guard7: wrong scopeId -> false
ret = await call(addr, vcv(ethers.toBeHex(99, 32), key, VALUE));
check('guard7 false (wrong scopeId)',
  iface.decodeFunctionResult('verifyCoordinateValue', ret)[0] === false);

// 6. guard7: wrong key -> false
ret = await call(addr, vcv(SCOPE_ID, ethers.toBeHex(999, 32), VALUE));
check('guard7 false (wrong key)',
  iface.decodeFunctionResult('verifyCoordinateValue', ret)[0] === false);

// 7. honest-boundary: certChainCommit=0 -> UNVERIFIABLE
const badTuple = [...tupleArr]; badTuple[7] = ethers.toBeHex(0, 32);
// use a different key so it's a fresh slot
const badTuple2 = [...badTuple]; badTuple2[1] = ethers.toBeHex(3, 32); badTuple2[3] = ethers.toBeHex(3, 32);
r = await send(addr, hexToBytes(iface.encodeFunctionData('commitSourceAuth', [SCOPE_ID, badTuple2])));
const logs7 = parseLogs(r.execResult.logs, iface);
const c7 = logs7.find(l => l.name === 'SourceAuthCommitted');
check('no-cert-chain -> UNVERIFIABLE (0)', c7 && Number(c7.args.verdict) === 0);

// 8. idempotent recommit (same input -> same digest, no re-emit)
r = await send(addr, hexToBytes(iface.encodeFunctionData('commitSourceAuth', [SCOPE_ID, tupleArr])));
const logs8 = parseLogs(r.execResult.logs, iface);
check('idempotent recommit: no SourceAuthCommitted re-emitted',
  logs8.filter(l => l.name === 'SourceAuthCommitted').length === 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
