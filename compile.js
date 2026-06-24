const solc = require('solc');
const fs = require('fs');
const src = fs.readFileSync('src/ScopeContestationRegistry.sol', 'utf8');
const input = {
  language: 'Solidity',
  sources: { 'ScopeContestationRegistry.sol': { content: src } },
  settings: { optimizer: { enabled: true, runs: 200 },
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } }
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errs = (out.errors || []).filter(e => e.severity === 'error');
if (errs.length) { errs.forEach(e => console.log(e.formattedMessage)); process.exit(1); }
const warns = (out.errors || []).filter(e => e.severity === 'warning');
console.log('compiled OK with solc', solc.version());
console.log('warnings:', warns.length);
const c = out.contracts['ScopeContestationRegistry.sol']['ScopeContestationRegistry'];
console.log('bytecode bytes:', c.evm.bytecode.object.length / 2);
console.log('abi entries:', c.abi.length);
