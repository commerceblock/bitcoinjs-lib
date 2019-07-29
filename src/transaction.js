'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const bufferutils = require('./bufferutils');
const bufferutils_1 = require('./bufferutils');
const bcrypto = require('./crypto');
const bscript = require('./script');
const script_1 = require('./script');
const types = require('./types');
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');
function varSliceSize(someScript) {
  const length = someScript.length;
  return varuint.encodingLength(length) + length;
}
const COIN = 100000000;
function valueFromAmount(amount) {
  const sign = amount < 0;
  let prefix = '';
  if (sign) prefix = '-';
  const nAbs = sign ? -amount : amount;
  const quotient = Math.floor(nAbs / COIN);
  const remainder = nAbs % COIN;
  // Have to pad zeros manually as typescript does not support padStart
  // unless it is defined to compile with newer ES2017 standard
  let remainderStr = remainder.toString();
  remainderStr = '0'.repeat(8 - remainderStr.length) + remainderStr;
  let numString = prefix + quotient.toString() + '.' + remainderStr;
  // Doing this to remove the trailing zeros on the right hand side.
  numString = parseFloat(numString).toString();
  return numString;
}
const EMPTY_SCRIPT = Buffer.allocUnsafe(0);
const ZERO = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const WITNESS_SCALE_FACTOR = 4;
const OUTPOINT_ISSUANCE_FLAG = (1 << 31) >>> 0;
const OUTPOINT_PEGIN_FLAG = (1 << 30) >>> 0;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const MINUS_1 = 4294967295;
const CONFIDENTIAL_COMMITMENT = 33; // default size of confidential commitments (i.e. asset, value, nonce)
const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values
const VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
  asset: ZERO,
  nValue: VALUE_UINT64_MAX,
  nonce: ZERO,
  script: EMPTY_SCRIPT,
};
class Transaction {
  constructor() {
    this.version = 1;
    this.locktime = 0;
    this.flag = 0;
    this.ins = [];
    this.outs = [];
    this.witnessIn = [];
    this.witnessOut = [];
  }
  static fromBuffer(buffer, _NO_STRICT) {
    let offset = 0;
    function readSlice(n) {
      offset += n;
      return buffer.slice(offset - n, offset);
    }
    function readUInt32() {
      const i = buffer.readUInt32LE(offset);
      offset += 4;
      return i;
    }
    function readInt32() {
      const i = buffer.readInt32LE(offset);
      offset += 4;
      return i;
    }
    function readVarInt() {
      const vi = varuint.decode(buffer, offset);
      offset += varuint.decode.bytes;
      return vi;
    }
    function readVarSlice() {
      return readSlice(readVarInt());
    }
    function readUInt8() {
      const i = buffer.readUInt8(offset);
      offset += 1;
      return i;
    }
    function readIterableVarSlice() {
      const itSize = readVarInt();
      const itList = [];
      for (let i = 0; i < itSize; ++i) itList.push(readVarSlice());
      return itList;
    }
    // CConfidentialAsset size 33, prefixA 10, prefixB 11
    function readConfidentialAsset() {
      const version = readUInt8();
      const versionBuffer = buffer.slice(offset - 1, offset);
      if (version === 1 || version === 0xff)
        return Buffer.concat([
          versionBuffer,
          readSlice(CONFIDENTIAL_COMMITMENT - 1),
        ]);
      else if (version === 10 || version === 11)
        return Buffer.concat([
          versionBuffer,
          readSlice(CONFIDENTIAL_COMMITMENT - 1),
        ]);
      return versionBuffer;
    }
    // CConfidentialNonce size 33, prefixA 2, prefixB 3
    function readConfidentialNonce() {
      const version = readUInt8();
      const versionBuffer = buffer.slice(offset - 1, offset);
      if (version === 1 || version === 0xff)
        return Buffer.concat([
          versionBuffer,
          readSlice(CONFIDENTIAL_COMMITMENT - 1),
        ]);
      else if (version === 2 || version === 3)
        return Buffer.concat([
          versionBuffer,
          readSlice(CONFIDENTIAL_COMMITMENT - 1),
        ]);
      return versionBuffer;
    }
    // CConfidentialValue size 9, prefixA 8, prefixB 9
    function readConfidentialValue() {
      const version = readUInt8();
      const versionBuffer = buffer.slice(offset - 1, offset);
      if (version === 1 || version === 0xff)
        return Buffer.concat([
          versionBuffer,
          readSlice(CONFIDENTIAL_VALUE - 1),
        ]);
      else if (version === 8 || version === 9)
        return Buffer.concat([
          versionBuffer,
          readSlice(CONFIDENTIAL_COMMITMENT - 1),
        ]);
      return versionBuffer;
    }
    function readWitnessIn(fields) {
      const witInputArray = [];
      for (let i = 0; i < fields; ++i) witInputArray.push(readWitnessInField());
      return witInputArray;
    }
    function readWitnessInField() {
      const issuancerangeproof = readVarSlice();
      const inflationrangeproof = readVarSlice();
      const scriptWitnessArr = readIterableVarSlice();
      const peginWitnessArr = readIterableVarSlice();
      return {
        issuanceRangeProof: issuancerangeproof,
        inflationRangeProof: inflationrangeproof,
        scriptWitness: scriptWitnessArr,
        peginWitness: peginWitnessArr,
      };
    }
    function readWitnessOut(fields) {
      const witOutputArray = [];
      for (let i = 0; i < fields; ++i)
        witOutputArray.push(readWitnessOutField());
      return witOutputArray;
    }
    function readWitnessOutField() {
      const surjectionproof = readVarSlice();
      const rangeproof = readVarSlice();
      return { surjectionProof: surjectionproof, rangeProof: rangeproof };
    }
    function readIssuance() {
      const issuanceNonce = readSlice(32);
      const issuanceEntropy = readSlice(32);
      const amount = readConfidentialValue();
      const inflation = readConfidentialValue();
      return {
        assetBlindingNonce: issuanceNonce,
        assetEntropy: issuanceEntropy,
        assetamount: amount,
        tokenamount: inflation,
      };
    }
    const tx = new Transaction();
    tx.version = readInt32();
    tx.flag = readUInt8();
    const vinLen = readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      const inHash = readSlice(32);
      let inIndex = readUInt32();
      const inScript = readVarSlice();
      const inSequence = readUInt32();
      let inIsPegin = false;
      let inIssuance;
      if (inIndex !== MINUS_1) {
        if (inIndex & OUTPOINT_ISSUANCE_FLAG) {
          inIssuance = readIssuance();
        }
        if (inIndex & OUTPOINT_PEGIN_FLAG) {
          inIsPegin = true;
        }
        inIndex &= OUTPOINT_INDEX_MASK;
      }
      tx.ins.push({
        hash: inHash,
        index: inIndex,
        script: inScript,
        sequence: inSequence,
        isPegin: inIsPegin,
        issuance: inIssuance,
      });
    }
    const voutLen = readVarInt();
    for (let i = 0; i < voutLen; ++i) {
      const assetBuffer = readConfidentialAsset();
      const outValueBuffer = readConfidentialValue();
      // TODO We are not handling confidential values
      let outValue;
      let outAmountCommitment;
      let outAmount;
      if (
        outValueBuffer.readUIntLE(0, 1) === 1 &&
        outValueBuffer.length === 9
      ) {
        const reverseValueBuffer = Buffer.allocUnsafe(8);
        outValueBuffer.slice(1, 9).copy(reverseValueBuffer, 0);
        bufferutils_1.reverseBuffer(reverseValueBuffer);
        outAmount = bufferutils.readUInt64LE(reverseValueBuffer, 0);
        outValue = valueFromAmount(outAmount);
      } else outAmountCommitment = outValueBuffer.toString('hex');
      tx.outs.push({
        asset: assetBuffer,
        nValue: outValueBuffer,
        nonce: readConfidentialNonce(),
        script: readVarSlice(),
        value: outValue,
        amount: outAmount,
        amountCommitment: outAmountCommitment,
      });
    }
    tx.locktime = readUInt32();
    let witnessIn = [];
    let witnessOut = [];
    if (tx.flag === 1) {
      witnessIn = readWitnessIn(tx.ins.length);
      witnessOut = readWitnessOut(tx.outs.length);
      if (
        !(
          tx.ins.length === witnessIn.length &&
          tx.outs.length === witnessOut.length
        )
      ) {
        throw new Error(
          'The read witness input or output length does ' +
            'not match their respective tx input or output lengths',
        );
      }
    }
    tx.witnessIn = tx.witnessIn.concat(witnessIn);
    tx.witnessOut = tx.witnessOut.concat(witnessOut);
    if (_NO_STRICT) return tx;
    if (offset !== buffer.length)
      throw new Error('Transaction has unexpected data');
    return tx;
  }
  static fromHex(hex) {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), false);
  }
  static isCoinbaseHash(buffer) {
    typeforce(types.Hash256bit, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }
  isCoinbase() {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }
  // A quick and reliable way to validate that all the buffers are of correct type and length
  ValidateIssuance(assetBlindingNonce, assetEntropy, assetamount, tokenamount) {
    typeforce(types.Hash256bit, assetBlindingNonce);
    typeforce(types.Hash256bit, assetEntropy);
    typeforce(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      assetamount,
    );
    typeforce(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      tokenamount,
    );
    return true;
  }
  addInput(hash, index, sequence, scriptSig, inIssuance) {
    typeforce(
      types.tuple(
        types.Hash256bit,
        types.UInt32,
        types.maybe(types.UInt32),
        types.maybe(types.Buffer),
        types.maybe(types.Object),
      ),
      arguments,
    );
    if (types.Null(sequence)) {
      sequence = Transaction.DEFAULT_SEQUENCE;
    }
    let inIsPegin = false;
    if (index !== MINUS_1) {
      if (index & OUTPOINT_ISSUANCE_FLAG) {
        if (!inIssuance) {
          throw new Error(
            'Issuance flag has been set but the Issuance object is not defined or invalid',
          );
        } else
          this.ValidateIssuance(
            inIssuance.assetBlindingNonce,
            inIssuance.assetEntropy,
            inIssuance.assetamount,
            inIssuance.tokenamount,
          );
      }
      if (index & OUTPOINT_PEGIN_FLAG) {
        inIsPegin = true;
      }
      index &= OUTPOINT_INDEX_MASK;
    }
    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence,
        isPegin: inIsPegin,
        issuance: inIssuance,
      }) - 1
    );
  }
  addOutput(_asset, _nValue, _nonce, scriptPubKey) {
    typeforce(
      types.tuple(
        types.oneOf(types.ConfidentialCommitment, types.BufferOne),
        types.oneOf(
          types.ConfidentialValue,
          types.ConfidentialCommitment,
          types.BufferOne,
        ),
        types.oneOf(types.ConfidentialCommitment, types.BufferOne),
        types.Buffer,
      ),
      arguments,
    );
    let outValue;
    let outAmountCommitment;
    let outAmount;
    if (_nValue.readUIntLE(0, 1) === 1 && _nValue.length === 9) {
      const reverseValueBuffer = Buffer.allocUnsafe(8);
      _nValue.slice(1, 9).copy(reverseValueBuffer, 0);
      bufferutils_1.reverseBuffer(reverseValueBuffer);
      outAmount = bufferutils.readUInt64LE(reverseValueBuffer, 0);
      outValue = valueFromAmount(outAmount);
    } else outAmountCommitment = _nValue.toString('hex');
    // Add the output and return the output's index
    return (
      this.outs.push({
        asset: _asset,
        nValue: _nValue,
        nonce: _nonce,
        script: scriptPubKey,
        value: outValue,
        amount: outAmount,
        amountCommitment: outAmountCommitment,
      }) - 1
    );
  }
  hasWitnesses() {
    return (
      this.witnessIn.length > 0 && this.witnessOut.length > 0 && this.flag === 1
    );
  }
  weight() {
    const base = this.__byteLength(false);
    const total = this.__byteLength(true);
    return base * (WITNESS_SCALE_FACTOR - 1) + total;
  }
  virtualSize() {
    const vsize =
      (this.weight() + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    return Math.floor(vsize);
  }
  byteLength() {
    return this.__byteLength(true);
  }
  clone() {
    const newTx = new Transaction();
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.flag = this.flag;
    newTx.ins = this.ins.map(txIn => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
        isPegin: txIn.isPegin,
        issuance: txIn.issuance,
      };
    });
    newTx.outs = this.outs.map(txOut => {
      return {
        asset: txOut.asset,
        nValue: txOut.nValue,
        nonce: txOut.nonce,
        script: txOut.script,
        value: txOut.value,
        amount: txOut.amount,
        amountCommitment: txOut.amountCommitment,
      };
    });
    newTx.witnessIn = this.witnessIn;
    newTx.witnessOut = this.witnessOut;
    return newTx;
  }
  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input.
   * This method copies the transaction, makes the necessary changes based on the
   * hashType, and then hashes the result.
   * This hash can then be used to sign the provided transaction input.
   */
  hashForSignature(inIndex, prevOutScript, hashType) {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number),
      arguments,
    );
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;
    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript).filter(x => {
        return x !== script_1.OPS.OP_CODESEPARATOR;
      }),
    );
    const txTmp = this.clone();
    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
      txTmp.outs = [];
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, i) => {
        if (i === inIndex) return;
        input.sequence = 0;
      });
      // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
      // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
      if (inIndex >= this.outs.length) return ONE;
      // truncate outputs after
      txTmp.outs.length = inIndex + 1;
      // "blank" outputs before
      for (let i = 0; i < inIndex; i++) {
        txTmp.outs[i] = BLANK_OUTPUT;
      }
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, y) => {
        if (y === inIndex) return;
        input.sequence = 0;
      });
    }
    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
      txTmp.ins[0].script = ourScript;
      // SIGHASH_ALL: only ignore input scripts
    } else {
      // "blank" others input scripts
      txTmp.ins.forEach(input => {
        input.script = EMPTY_SCRIPT;
      });
      txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    const buffer = Buffer.allocUnsafe(txTmp.__byteLength(false) + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false, true);
    return bcrypto.hash256(buffer);
  }
  getHash() {
    return bcrypto.hash256(this.__toBuffer(undefined, undefined, false, true));
  }
  getId() {
    // transaction hash's are displayed in reverse order
    return bufferutils_1.reverseBuffer(this.getHash()).toString('hex');
  }
  toBuffer(buffer, initialOffset) {
    return this.__toBuffer(buffer, initialOffset, true);
  }
  toHex() {
    return this.toBuffer(undefined, undefined).toString('hex');
  }
  setInputScript(index, scriptSig) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.ins[index].script = scriptSig;
  }
  __byteLength(_ALLOW_WITNESS) {
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    return (
      9 +
      varuint.encodingLength(this.ins.length) +
      varuint.encodingLength(this.outs.length) +
      this.ins.reduce((sum, input) => {
        return (
          sum +
          40 +
          varSliceSize(input.script) +
          (input.issuance
            ? 64 +
              input.issuance.assetamount.length +
              input.issuance.tokenamount.length
            : 0)
        );
      }, 0) +
      this.outs.reduce((sum, output) => {
        return (
          sum +
          output.asset.length +
          output.nValue.length +
          output.nonce.length +
          varSliceSize(output.script)
        );
      }, 0) +
      (hasWitnesses
        ? this.witnessIn.reduce((sum, witnessIn) => {
            return (
              sum +
              varSliceSize(witnessIn.issuanceRangeProof) +
              varSliceSize(witnessIn.inflationRangeProof) +
              varuint.encodingLength(witnessIn.scriptWitness.length) +
              witnessIn.scriptWitness.reduce((scriptSum, scriptWit) => {
                return scriptSum + varSliceSize(scriptWit);
              }, 0) +
              varuint.encodingLength(witnessIn.peginWitness.length) +
              witnessIn.peginWitness.reduce((peginSum, peginWit) => {
                return peginSum + varSliceSize(peginWit);
              }, 0)
            );
          }, 0)
        : 0) +
      (hasWitnesses
        ? this.witnessOut.reduce((sum, witnessOut) => {
            return (
              sum +
              varSliceSize(witnessOut.surjectionProof) +
              varSliceSize(witnessOut.rangeProof)
            );
          }, 0)
        : 0)
    );
  }
  __toBuffer(buffer, initialOffset, _ALLOW_WITNESS, forceZeroFlag) {
    if (!buffer) buffer = Buffer.allocUnsafe(this.__byteLength(_ALLOW_WITNESS));
    let offset = initialOffset || 0;
    function writeSlice(slice) {
      offset += slice.copy(buffer, offset);
    }
    function writeUInt8(i) {
      offset = buffer.writeUInt8(i, offset);
    }
    function writeUInt32(i) {
      offset = buffer.writeUInt32LE(i, offset);
    }
    function writeInt32(i) {
      offset = buffer.writeInt32LE(i, offset);
    }
    function writeVarInt(i) {
      varuint.encode(i, buffer, offset);
      offset += varuint.encode.bytes;
    }
    function writeVarSlice(slice) {
      writeVarInt(slice.length);
      writeSlice(slice);
    }
    function writeWitnessIn(witnessInputArray) {
      for (const witnessInput of witnessInputArray)
        writeWitnessInField(witnessInput);
    }
    function writeWitnessInField(witnessInput) {
      writeVarSlice(witnessInput.issuanceRangeProof);
      writeVarSlice(witnessInput.inflationRangeProof);
      writeVarInt(witnessInput.scriptWitness.length);
      for (const it of witnessInput.scriptWitness) writeVarSlice(it);
      writeVarInt(witnessInput.peginWitness.length);
      for (const it of witnessInput.peginWitness) writeVarSlice(it);
    }
    function writeWitnessOut(witnessOutputArray) {
      for (const it of witnessOutputArray) writeWitnessOutField(it);
    }
    function writeWitnessOutField(witnessOutput) {
      writeVarSlice(witnessOutput.surjectionProof);
      writeVarSlice(witnessOutput.rangeProof);
    }
    writeInt32(this.version);
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    if (
      hasWitnesses &&
      (forceZeroFlag === false || forceZeroFlag === undefined)
    )
      writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
    else writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
    writeVarInt(this.ins.length);
    this.ins.forEach(txIn => {
      writeSlice(txIn.hash);
      let prevIndex = txIn.index;
      if (forceZeroFlag === false || forceZeroFlag === undefined) {
        if (txIn.issuance) {
          prevIndex = (prevIndex | OUTPOINT_ISSUANCE_FLAG) >>> 0;
        }
        if (txIn.isPegin) {
          prevIndex = (prevIndex | OUTPOINT_PEGIN_FLAG) >>> 0;
        }
      }
      writeUInt32(prevIndex);
      writeVarSlice(txIn.script);
      writeUInt32(txIn.sequence);
      if (txIn.issuance) {
        writeSlice(txIn.issuance.assetBlindingNonce);
        writeSlice(txIn.issuance.assetEntropy);
        writeSlice(txIn.issuance.assetamount);
        writeSlice(txIn.issuance.tokenamount);
      }
    });
    writeVarInt(this.outs.length);
    this.outs.forEach(txOut => {
      writeSlice(txOut.asset);
      writeSlice(txOut.nValue);
      writeSlice(txOut.nonce);
      writeVarSlice(txOut.script);
    });
    writeUInt32(this.locktime);
    if (hasWitnesses) {
      if (
        this.ins.length === this.witnessIn.length &&
        this.outs.length === this.witnessOut.length
      ) {
        if (this.witnessIn.length > 0) writeWitnessIn(this.witnessIn);
        if (this.witnessOut.length > 0) writeWitnessOut(this.witnessOut);
      } else
        throw new Error('Transaction witness in or out length does not match');
    }
    // avoid slicing unless necessary
    if (initialOffset !== undefined) return buffer.slice(initialOffset, offset);
    return buffer;
  }
}
Transaction.DEFAULT_SEQUENCE = 0xffffffff;
Transaction.SIGHASH_ALL = 0x01;
Transaction.SIGHASH_NONE = 0x02;
Transaction.SIGHASH_SINGLE = 0x03;
Transaction.SIGHASH_ANYONECANPAY = 0x80;
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00;
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01;
exports.Transaction = Transaction;
