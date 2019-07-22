'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const script_1 = require('./script');
const multisig = require('./templates/multisig');
const nullData = require('./templates/nulldata');
const pubKey = require('./templates/pubkey');
const pubKeyHash = require('./templates/pubkeyhash');
const scriptHash = require('./templates/scripthash');
const types = {
  P2MS: 'multisig',
  NONSTANDARD: 'nonstandard',
  NULLDATA: 'nulldata',
  P2PK: 'pubkey',
  P2PKH: 'pubkeyhash',
  P2SH: 'scripthash',
};
exports.types = types;
function classifyOutput(script) {
  if (pubKeyHash.output.check(script)) return types.P2PKH;
  if (scriptHash.output.check(script)) return types.P2SH;
  // XXX: optimization, below functions .decompile before use
  const chunks = script_1.decompile(script);
  if (!chunks) throw new TypeError('Invalid script');
  if (multisig.output.check(chunks)) return types.P2MS;
  if (pubKey.output.check(chunks)) return types.P2PK;
  if (nullData.output.check(chunks)) return types.NULLDATA;
  return types.NONSTANDARD;
}
exports.output = classifyOutput;
function classifyInput(script, allowIncomplete) {
  // XXX: optimization, below functions .decompile before use
  const chunks = script_1.decompile(script);
  if (!chunks) throw new TypeError('Invalid script');
  if (pubKeyHash.input.check(chunks)) return types.P2PKH;
  if (scriptHash.input.check(chunks, allowIncomplete)) return types.P2SH;
  if (multisig.input.check(chunks, allowIncomplete)) return types.P2MS;
  if (pubKey.input.check(chunks)) return types.P2PK;
  return types.NONSTANDARD;
}
exports.input = classifyInput;
