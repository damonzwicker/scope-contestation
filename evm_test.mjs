import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const solc = require('solc');
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork, Chain } = require('@ethereumjs/common');
const { LegacyTransaction } = require('@ethereumjs/tx');
const { Account, Address, hexToBytes } = require('@ethereumjs/util');
const { ethers } = require('ethers');

// compile
const src = readFileSync('src/ScopeContestationRegistry.sol','utf8');
const input = { language:'Solidity', sources:{'C.sol':{content:src}},
  settings:{optimizer:{enabled:true,runs:200}, outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const C = out.contracts['C.sol']['ScopeContestationRegistry'];
const abi = C.abi;
const bytecode = '0x'+C.evm.bytecode.object;
const iface = new ethers.Interface(abi);

const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Shanghai });
const vm = await VM.create({ common });

// fund a sender
const pk = hexToBytes('0x'+'11'.repeat(32));
const { privateToAddress } = require('@ethereumjs/util');
const senderAddr = new Address(privateToAddress(pk));
await vm.stateManager.putAccount(senderAddr, new Account(0n, 10n**20n));

let nonce = 0n;
async function send(to, data) {
  const tx = LegacyTransaction.fromTxData({
    to: to ?? undefined, data, gasLimit: 6_000_000n, gasPrice: 100n, nonce, value:0n
  }, { common }).sign(pk);
  nonce++;
  const res = await vm.runTx({ tx, skipBalance:true });
  return res;
}

// deploy
let r = await send(null, hexToBytes(bytecode));
if (r.execResult.exceptionError) { console.log('DEPLOY FAIL', r.execResult.exceptionError); process.exit(1); }
const addr = r.createdAddress;
console.log('deployed at', addr.toString());

const V = JSON.parse(readFileSync('vectors.json','utf8'));

// commitScope
let data = iface.encodeFunctionData('commitScope', [V.commitmentHash, V.scopeRoot, V.count]);
r = await send(addr, hexToBytes(data));
if (r.execResult.exceptionError){console.log('commit FAIL',r.execResult.exceptionError);process.exit(1);}
const scopeId = '0x'+r.execResult.returnValue.slice(-32) ? ethers.zeroPadValue('0x'+Buffer.from(r.execResult.returnValue).toString('hex'),32) : null;
// decode return
const decoded = iface.decodeFunctionResult('commitScope', r.execResult.returnValue);
const SID = decoded[0];
console.log('scopeId', SID.slice(0,18)+'...');

function packProof(p){
  return { mode:p.mode, loCoord:p.loCoord, hiCoord:p.hiCoord, idxLo:p.idxLo, sibsLo:p.sibsLo, sibsHi:p.sibsHi };
}
async function nominate(label, coord, proof, expectOk){
  const d = iface.encodeFunctionData('nominate', [SID, coord, packProof(proof)]);
  const rr = await send(addr, hexToBytes(d));
  const ok = !rr.execResult.exceptionError;
  const got = ok ? 'SUCCESS' : 'REVERT';
  const want = expectOk ? 'SUCCESS' : 'REVERT';
  const pass = (ok === expectOk);
  console.log(`  [${pass?'PASS':'FAIL'}] nominate ${label}: got ${got}, want ${want}`);
  return pass;
}

let all = true;
all &= await nominate('absent-below',    V.absent.below.coord,    V.absent.below.proof,    true);
all &= await nominate('absent-interior', V.absent.interior.coord, V.absent.interior.proof, true);
all &= await nominate('absent-above',    V.absent.above.coord,    V.absent.above.proof,    true);
// re-nominate same absent coord -> should revert (dedupe)
all &= await nominate('absent-below-REPLAY', V.absent.below.coord, V.absent.below.proof,  false);
// present coordinate -> must revert (soundness on-chain)
all &= await nominate('present-coord-MUST-REVERT', V.present.coord, V.present.proof,      false);

console.log(all ? '\nALL ON-CHAIN CHECKS PASSED' : '\nSOME CHECKS FAILED');
process.exit(all?0:1);
