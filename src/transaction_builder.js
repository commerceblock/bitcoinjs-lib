'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const baddress = require('./address');
const bufferutils_1 = require('./bufferutils');
const classify = require('./classify');
const bcrypto = require('./crypto');
const ECPair = require('./ecpair');
const networks = require('./networks');
const payments = require('./payments');
const bscript = require('./script');
const script_1 = require('./script');
const transaction_1 = require('./transaction');
const types = require('./types');
const typeforce = require('typeforce');
const SCRIPT_TYPES = classify.types;
const OUTPOINT_ISSUANCE_FLAG = (1 << 31) >>> 0;
const MINUS_1 = 4294967295;
function txIsString(tx) {
  return typeof tx === 'string' || tx instanceof String;
}
function txIsTransaction(tx) {
  return tx instanceof transaction_1.Transaction;
}
class TransactionBuilder {
  // WARNING: maximumFeeRate is __NOT__ to be relied on,
  //          it's just another potential safety mechanism (safety in-depth)
  constructor(network = networks.bitcoin, maximumFeeRate = 2500) {
    this.network = network;
    this.maximumFeeRate = maximumFeeRate;
    this.__PREV_TX_SET = {};
    this.__INPUTS = [];
    this.__TX = new transaction_1.Transaction();
    this.__TX.version = 2;
    this.__TX.flag = 0;
    this.__USE_LOW_R = false;
  }
  static fromTransaction(transaction, network) {
    const txb = new TransactionBuilder(network);
    // Copy transaction fields
    txb.setVersion(transaction.version);
    txb.setLockTime(transaction.locktime);
    txb.setFlag(transaction.flag);
    // Copy outputs (done first to avoid signature invalidation)
    transaction.outs.forEach(txOut => {
      txb.addOutput(txOut.asset, txOut.nValue, txOut.nonce, txOut.script);
    });
    // Copy inputs
    transaction.ins.forEach(txIn => {
      txb.__addInputUnsafe(txIn.hash, txIn.index, {
        sequence: txIn.sequence,
        script: txIn.script,
        issuance: txIn.issuance,
      });
    });
    txb.setWitnessIn(transaction.witnessIn);
    txb.setWitnessOut(transaction.witnessOut);
    // fix some things not possible through the public API
    txb.__INPUTS.forEach((input, i) => {
      fixMultisigOrder(input, transaction, i);
    });
    return txb;
  }
  setLowR(setting) {
    typeforce(typeforce.maybe(typeforce.Boolean), setting);
    if (setting === undefined) {
      setting = true;
    }
    this.__USE_LOW_R = setting;
    return setting;
  }
  setLockTime(locktime) {
    typeforce(types.UInt32, locktime);
    // if any signatures exist, throw
    if (
      this.__INPUTS.some(input => {
        if (!input.signatures) return false;
        return input.signatures.some(s => s !== undefined);
      })
    ) {
      throw new Error('No, this would invalidate signatures');
    }
    this.__TX.locktime = locktime;
  }
  setVersion(version) {
    typeforce(types.UInt32, version);
    // XXX: this might eventually become more complex depending on what the versions represent
    this.__TX.version = version;
  }
  // Simple validation method for witness input being not undefined and of the correct type
  validateWitnessIn(
    issuanceRangeProof,
    inflationRangeProof,
    scriptWitness,
    peginWitness,
  ) {
    typeforce(types.Buffer, issuanceRangeProof);
    typeforce(types.Buffer, inflationRangeProof);
    typeforce(typeforce.arrayOf('Buffer'), scriptWitness);
    typeforce(typeforce.arrayOf('Buffer'), peginWitness);
    return true;
  }
  // Simple validation method for witness output being not undefined and of the correct type
  validateWitnessOut(surjectionProof, rangeProof) {
    typeforce(types.Buffer, surjectionProof);
    typeforce(types.Buffer, rangeProof);
    return true;
  }
  setWitnessIn(witnessIn) {
    typeforce(types.Array, witnessIn);
    if (witnessIn.length > 0) {
      if (this.__TX.ins.length !== witnessIn.length)
        throw new Error(
          'Witness Input length does not match TX input length in TransactionBuilder',
        );
      try {
        for (const obj of witnessIn) {
          this.validateWitnessIn(
            obj.issuanceRangeProof,
            obj.inflationRangeProof,
            obj.scriptWitness,
            obj.peginWitness,
          );
        }
      } catch (err) {
        throw new Error(
          'One of the Witness inputs has a field that is undefined or of wrong type',
        );
      }
      this.setFlag(1);
    }
    this.__TX.witnessIn = witnessIn;
  }
  setWitnessOut(witnessOut) {
    typeforce(types.Array, witnessOut);
    if (witnessOut.length > 0) {
      if (this.__TX.outs.length !== witnessOut.length)
        throw new Error(
          'Witness Output length does not match TX output length in TransactionBuilder',
        );
      try {
        for (const obj of witnessOut) {
          this.validateWitnessOut(obj.surjectionProof, obj.rangeProof);
        }
      } catch (err) {
        throw new Error(
          'One of the Witness outputs has a field that is undefined or of wrong type',
        );
      }
      this.setFlag(1);
    }
    this.__TX.witnessOut = witnessOut;
  }
  setFlag(flag) {
    typeforce(types.UInt8, flag);
    this.__TX.flag = flag;
  }
  addInput(txHash, vout, inSequence, inPrevOutScript, inIssuance) {
    if (!this.__canModifyInputs()) {
      throw new Error('No, this would invalidate signatures');
    }
    let inAmount;
    // is it a hex string?
    if (txIsString(txHash)) {
      // transaction hashs's are displayed in reverse order, un-reverse it
      txHash = bufferutils_1.reverseBuffer(Buffer.from(txHash, 'hex'));
      // is it a Transaction object?
    } else if (txIsTransaction(txHash)) {
      const txOut = txHash.outs[vout];
      inPrevOutScript = txOut.script;
      const amountNum = txOut.amount;
      if (amountNum) inAmount = amountNum;
      txHash = txHash.getHash();
    }
    let passIssuance;
    if (inIssuance) {
      if (!(vout & OUTPOINT_ISSUANCE_FLAG) || vout === MINUS_1)
        throw new Error(
          'Issuance flag has not been set or index is max yet addInput has received an issuance object',
        );
      if (
        inIssuance.assetBlindingNonce &&
        inIssuance.assetEntropy &&
        inIssuance.assetamount &&
        inIssuance.tokenamount
      ) {
        if (
          typeof inIssuance.assetBlindingNonce === 'string' &&
          typeof inIssuance.assetEntropy === 'string' &&
          typeof inIssuance.assetamount === 'string' &&
          typeof inIssuance.tokenamount === 'string'
        ) {
          passIssuance = {
            assetBlindingNonce: Buffer.from(
              inIssuance.assetBlindingNonce,
              'hex',
            ),
            assetEntropy: Buffer.from(inIssuance.assetEntropy, 'hex'),
            assetamount: Buffer.from(inIssuance.assetamount, 'hex'),
            tokenamount: Buffer.from(inIssuance.tokenamount, 'hex'),
          };
        } else if (
          Buffer.isBuffer(inIssuance.assetBlindingNonce) &&
          Buffer.isBuffer(inIssuance.assetEntropy) &&
          Buffer.isBuffer(inIssuance.assetamount) &&
          Buffer.isBuffer(inIssuance.tokenamount)
        ) {
          passIssuance = {
            assetBlindingNonce: inIssuance.assetBlindingNonce,
            assetEntropy: inIssuance.assetEntropy,
            assetamount: inIssuance.assetamount,
            tokenamount: inIssuance.tokenamount,
          };
        } else
          throw new Error('Issuance has mixed or invalid object parameters');
      } else
        throw new Error(
          'Issuance does not contain all four of the necessary fields',
        );
    }
    return this.__addInputUnsafe(txHash, vout, {
      sequence: inSequence,
      prevOutScript: inPrevOutScript,
      amount: inAmount,
      issuance: passIssuance,
    });
  }
  addOutput(asset, nValue, nonce, scriptPubKey) {
    if (!this.__canModifyOutputs()) {
      throw new Error('No, this would invalidate signatures');
    }
    // Attempt to get a script if it's a base58 address string
    if (typeof scriptPubKey === 'string') {
      scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network);
    }
    if (typeof asset === 'string') {
      asset = Buffer.from(asset, 'hex');
    }
    if (typeof nonce === 'string') {
      nonce = Buffer.from(nonce, 'hex');
    }
    const numToBuffer = Buffer.alloc(8);
    if (typeof nValue === 'number') {
      bufferutils_1.writeUInt64LE(numToBuffer, nValue, 0);
      nValue = Buffer.concat([
        Buffer.from('01', 'hex'),
        bufferutils_1.reverseBuffer(numToBuffer),
      ]);
    }
    return this.__TX.addOutput(asset, nValue, nonce, scriptPubKey);
  }
  build() {
    return this.__build(false);
  }
  buildIncomplete() {
    return this.__build(true);
  }
  sign(vin, keyPair, redeemScript, hashType) {
    // TODO: remove keyPair.network matching in 4.0.0
    if (keyPair.network && keyPair.network !== this.network)
      throw new TypeError('Inconsistent network');
    if (!this.__INPUTS[vin]) throw new Error('No input at index: ' + vin);
    hashType = hashType || transaction_1.Transaction.SIGHASH_ALL;
    if (this.__needsOutputs(hashType))
      throw new Error('Transaction needs outputs');
    const input = this.__INPUTS[vin];
    // if redeemScript was previously provided, enforce consistency
    if (
      input.redeemScript !== undefined &&
      redeemScript &&
      !input.redeemScript.equals(redeemScript)
    ) {
      throw new Error('Inconsistent redeemScript');
    }
    const ourPubKey = keyPair.publicKey || keyPair.getPublicKey();
    if (!canSign(input)) {
      if (!canSign(input)) {
        const prepared = prepareInput(input, ourPubKey, redeemScript);
        // updates inline
        Object.assign(input, prepared);
      }
      if (!canSign(input)) throw Error(input.prevOutType + ' not supported');
    }
    // ready to sign
    let signatureHash;
    signatureHash = this.__TX.hashForSignature(vin, input.signScript, hashType);
    // enforce in order signing of public keys
    const signed = input.pubkeys.some((pubKey, i) => {
      if (!ourPubKey.equals(pubKey)) return false;
      if (input.signatures[i]) throw new Error('Signature already exists');
      const signature = keyPair.sign(signatureHash, this.__USE_LOW_R);
      input.signatures[i] = bscript.signature.encode(signature, hashType);
      return true;
    });
    if (!signed) throw new Error('Key pair cannot sign for this input');
  }
  __addInputUnsafe(txHash, vout, options) {
    if (transaction_1.Transaction.isCoinbaseHash(txHash)) {
      throw new Error('coinbase inputs not supported');
    }
    const prevTxOut = txHash.toString('hex') + ':' + vout;
    if (this.__PREV_TX_SET[prevTxOut] !== undefined)
      throw new Error('Duplicate TxOut: ' + prevTxOut);
    let input = {};
    // derive what we can from the scriptSig
    if (options.script !== undefined) {
      input = expandInput(options.script);
    }
    // if an input amount was given, retain it
    if (options.amount !== undefined) {
      input.amount = options.amount;
    }
    // derive what we can from the previous transactions output script
    if (!input.prevOutScript && options.prevOutScript) {
      let prevOutType;
      if (!input.pubkeys && !input.signatures) {
        const expanded = expandOutput(options.prevOutScript);
        if (expanded.pubkeys) {
          input.pubkeys = expanded.pubkeys;
          input.signatures = expanded.signatures;
        }
        prevOutType = expanded.type;
      }
      input.prevOutScript = options.prevOutScript;
      input.prevOutType = prevOutType || classify.output(options.prevOutScript);
    }
    const vin = this.__TX.addInput(
      txHash,
      vout,
      options.sequence,
      options.scriptSig,
      options.issuance,
    );
    this.__INPUTS[vin] = input;
    this.__PREV_TX_SET[prevTxOut] = true;
    return vin;
  }
  __build(allowIncomplete) {
    if (!allowIncomplete) {
      if (!this.__TX.ins.length) throw new Error('Transaction has no inputs');
      if (!this.__TX.outs.length) throw new Error('Transaction has no outputs');
    }
    const tx = this.__TX.clone();
    // create script signatures from inputs
    this.__INPUTS.forEach((input, i) => {
      if (!input.prevOutType && !allowIncomplete)
        throw new Error('Transaction is not complete');
      const result = build(input.prevOutType, input, allowIncomplete);
      if (!result) {
        if (!allowIncomplete && input.prevOutType === SCRIPT_TYPES.NONSTANDARD)
          throw new Error('Unknown input type');
        if (!allowIncomplete) throw new Error('Not enough information');
        return;
      }
      tx.setInputScript(i, result.input);
    });
    if (!allowIncomplete) {
      // do not rely on this, its merely a last resort
      if (this.__overMaximumFees(tx.virtualSize())) {
        throw new Error('Transaction has absurd fees');
      }
    }
    return tx;
  }
  __canModifyInputs() {
    return this.__INPUTS.every(input => {
      if (!input.signatures) return true;
      return input.signatures.every(signature => {
        if (!signature) return true;
        const hashType = signatureHashType(signature);
        // if SIGHASH_ANYONECANPAY is set, signatures would not
        // be invalidated by more inputs
        return (
          (hashType & transaction_1.Transaction.SIGHASH_ANYONECANPAY) !== 0
        );
      });
    });
  }
  __needsOutputs(signingHashType) {
    if (signingHashType === transaction_1.Transaction.SIGHASH_ALL) {
      return this.__TX.outs.length === 0;
    }
    // if inputs are being signed with SIGHASH_NONE, we don't strictly need outputs
    // .build() will fail, but .buildIncomplete() is OK
    return (
      this.__TX.outs.length === 0 &&
      this.__INPUTS.some(input => {
        if (!input.signatures) return false;
        return input.signatures.some(signature => {
          if (!signature) return false; // no signature, no issue
          const hashType = signatureHashType(signature);
          if (hashType & transaction_1.Transaction.SIGHASH_NONE) return false; // SIGHASH_NONE doesn't care about outputs
          return true; // SIGHASH_* does care
        });
      })
    );
  }
  __canModifyOutputs() {
    const nInputs = this.__TX.ins.length;
    const nOutputs = this.__TX.outs.length;
    return this.__INPUTS.every(input => {
      if (input.signatures === undefined) return true;
      return input.signatures.every(signature => {
        if (!signature) return true;
        const hashType = signatureHashType(signature);
        const hashTypeMod = hashType & 0x1f;
        if (hashTypeMod === transaction_1.Transaction.SIGHASH_NONE) return true;
        if (hashTypeMod === transaction_1.Transaction.SIGHASH_SINGLE) {
          // if SIGHASH_SINGLE is set, and nInputs > nOutputs
          // some signatures would be invalidated by the addition
          // of more outputs
          return nInputs <= nOutputs;
        }
        return false;
      });
    });
  }
  __overMaximumFees(bytes) {
    // not all inputs will have .amount defined
    const incoming = this.__INPUTS.reduce((a, x) => a + (x.amount >>> 0), 0);
    // but all outputs do, and if we have any input value
    // we can immediately determine if the outputs are too small
    const outgoing = this.__TX.outs.reduce((a, x) => {
      const amountNum = x.amount;
      return a + (amountNum ? amountNum : 0);
    }, 0);
    const fee = incoming - outgoing;
    const feeRate = fee / bytes;
    return feeRate > this.maximumFeeRate;
  }
}
exports.TransactionBuilder = TransactionBuilder;
function expandInput(scriptSig, type, scriptPubKey) {
  if (scriptSig.length === 0) return {};
  if (!type) {
    let ssType = classify.input(scriptSig, true);
    if (ssType === SCRIPT_TYPES.NONSTANDARD) ssType = undefined;
    type = ssType;
  }
  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      const { output, pubkey, signature } = payments.p2pkh({
        input: scriptSig,
      });
      return {
        prevOutScript: output,
        prevOutType: SCRIPT_TYPES.P2PKH,
        pubkeys: [pubkey],
        signatures: [signature],
      };
    }
    case SCRIPT_TYPES.P2PK: {
      const { signature } = payments.p2pk({ input: scriptSig });
      return {
        prevOutType: SCRIPT_TYPES.P2PK,
        pubkeys: [undefined],
        signatures: [signature],
      };
    }
    case SCRIPT_TYPES.P2MS: {
      const { m, pubkeys, signatures } = payments.p2ms(
        {
          input: scriptSig,
          output: scriptPubKey,
        },
        { allowIncomplete: true },
      );
      return {
        prevOutType: SCRIPT_TYPES.P2MS,
        pubkeys,
        signatures,
        maxSignatures: m,
      };
    }
  }
  if (type === SCRIPT_TYPES.P2SH) {
    const { output, redeem } = payments.p2sh({
      input: scriptSig,
    });
    const outputType = classify.output(redeem.output);
    const expanded = expandInput(redeem.input, outputType, redeem.output);
    if (!expanded.prevOutType) return {};
    return {
      prevOutScript: output,
      prevOutType: SCRIPT_TYPES.P2SH,
      redeemScript: redeem.output,
      redeemScriptType: expanded.prevOutType,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
    };
  }
  return {
    prevOutType: SCRIPT_TYPES.NONSTANDARD,
    prevOutScript: scriptSig,
  };
}
// could be done in expandInput, but requires the original Transaction for hashForSignature
function fixMultisigOrder(input, transaction, vin) {
  if (input.redeemScriptType !== SCRIPT_TYPES.P2MS || !input.redeemScript)
    return;
  if (input.pubkeys.length === input.signatures.length) return;
  const unmatched = input.signatures.concat();
  input.signatures = input.pubkeys.map(pubKey => {
    const keyPair = ECPair.fromPublicKey(pubKey);
    let match;
    // check for a signature
    unmatched.some((signature, i) => {
      // skip if undefined || OP_0
      if (!signature) return false;
      // TODO: avoid O(n) hashForSignature
      const parsed = bscript.signature.decode(signature);
      const hash = transaction.hashForSignature(
        vin,
        input.redeemScript,
        parsed.hashType,
      );
      // skip if signature does not match pubKey
      if (!keyPair.verify(hash, parsed.signature)) return false;
      // remove matched signature from unmatched
      unmatched[i] = undefined;
      match = signature;
      return true;
    });
    return match;
  });
}
function expandOutput(script, ourPubKey) {
  typeforce(types.Buffer, script);
  const type = classify.output(script);
  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      if (!ourPubKey) return { type };
      // does our hash160(pubKey) match the output scripts?
      const pkh1 = payments.p2pkh({ output: script }).hash;
      const pkh2 = bcrypto.hash160(ourPubKey);
      if (!pkh1.equals(pkh2)) return { type };
      return {
        type,
        pubkeys: [ourPubKey],
        signatures: [undefined],
      };
    }
    case SCRIPT_TYPES.P2PK: {
      const p2pk = payments.p2pk({ output: script });
      return {
        type,
        pubkeys: [p2pk.pubkey],
        signatures: [undefined],
      };
    }
    case SCRIPT_TYPES.P2MS: {
      const p2ms = payments.p2ms({ output: script });
      return {
        type,
        pubkeys: p2ms.pubkeys,
        signatures: p2ms.pubkeys.map(() => undefined),
        maxSignatures: p2ms.m,
      };
    }
  }
  return { type };
}
function prepareInput(input, ourPubKey, redeemScript) {
  if (redeemScript) {
    const p2sh = payments.p2sh({ redeem: { output: redeemScript } });
    if (input.prevOutScript) {
      let p2shAlt;
      try {
        p2shAlt = payments.p2sh({ output: input.prevOutScript });
      } catch (e) {
        throw new Error('PrevOutScript must be P2SH');
      }
      if (!p2sh.hash.equals(p2shAlt.hash))
        throw new Error('Redeem script inconsistent with prevOutScript');
    }
    const expanded = expandOutput(p2sh.redeem.output, ourPubKey);
    if (!expanded.pubkeys)
      throw new Error(
        expanded.type +
          ' not supported as redeemScript (' +
          bscript.toASM(redeemScript) +
          ')',
      );
    if (input.signatures && input.signatures.some(x => x !== undefined)) {
      expanded.signatures = input.signatures;
    }
    const signScript = redeemScript;
    return {
      redeemScript,
      redeemScriptType: expanded.type,
      prevOutType: SCRIPT_TYPES.P2SH,
      prevOutScript: p2sh.output,
      signScript,
      signType: expanded.type,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
      maxSignatures: expanded.maxSignatures,
    };
  }
  if (input.prevOutType && input.prevOutScript) {
    // embedded scripts are not possible without extra information
    if (input.prevOutType === SCRIPT_TYPES.P2SH)
      throw new Error(
        'PrevOutScript is ' + input.prevOutType + ', requires redeemScript',
      );
    if (!input.prevOutScript) throw new Error('PrevOutScript is missing');
    const expanded = expandOutput(input.prevOutScript, ourPubKey);
    if (!expanded.pubkeys)
      throw new Error(
        expanded.type +
          ' not supported (' +
          bscript.toASM(input.prevOutScript) +
          ')',
      );
    if (input.signatures && input.signatures.some(x => x !== undefined)) {
      expanded.signatures = input.signatures;
    }
    const signScript = input.prevOutScript;
    return {
      prevOutType: expanded.type,
      prevOutScript: input.prevOutScript,
      signScript,
      signType: expanded.type,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
      maxSignatures: expanded.maxSignatures,
    };
  }
  const prevOutScript = payments.p2pkh({ pubkey: ourPubKey }).output;
  return {
    prevOutType: SCRIPT_TYPES.P2PKH,
    prevOutScript,
    signScript: prevOutScript,
    signType: SCRIPT_TYPES.P2PKH,
    pubkeys: [ourPubKey],
    signatures: [undefined],
  };
}
function build(type, input, allowIncomplete) {
  const pubkeys = input.pubkeys || [];
  let signatures = input.signatures || [];
  switch (type) {
    case SCRIPT_TYPES.P2PKH: {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.p2pkh({ pubkey: pubkeys[0], signature: signatures[0] });
    }
    case SCRIPT_TYPES.P2PK: {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.p2pk({ signature: signatures[0] });
    }
    case SCRIPT_TYPES.P2MS: {
      const m = input.maxSignatures;
      if (allowIncomplete) {
        signatures = signatures.map(x => x || script_1.OPS.OP_0);
      } else {
        signatures = signatures.filter(x => x);
      }
      // if the transaction is not not complete (complete), or if signatures.length === m, validate
      // otherwise, the number of OP_0's may be >= m, so don't validate (boo)
      const validate = !allowIncomplete || m === signatures.length;
      return payments.p2ms(
        { m, pubkeys, signatures },
        { allowIncomplete, validate },
      );
    }
    case SCRIPT_TYPES.P2SH: {
      const redeem = build(input.redeemScriptType, input, allowIncomplete);
      if (!redeem) return;
      return payments.p2sh({
        redeem: {
          output: redeem.output || input.redeemScript,
          input: redeem.input,
        },
      });
    }
  }
}
function canSign(input) {
  return (
    input.signScript !== undefined &&
    input.signType !== undefined &&
    input.pubkeys !== undefined &&
    input.signatures !== undefined &&
    input.signatures.length === input.pubkeys.length &&
    input.pubkeys.length > 0
  );
}
function signatureHashType(buffer) {
  return buffer.readUInt8(buffer.length - 1);
}
