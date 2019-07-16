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
const EMPTY_SCRIPT = Buffer.allocUnsafe(0);
const ZERO = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
  script: EMPTY_SCRIPT,
  valueBuffer: VALUE_UINT64_MAX,
  asset: ZERO,
};
function isOutput(out) {
  return out.value !== undefined;
}
class Transaction {
  constructor() {
    this.version = 1;
    this.locktime = 0;
    this.ins = [];
    this.outs = [];
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
    function readUInt64() {
      const i = bufferutils.readUInt64LE(buffer, offset);
      offset += 8;
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
    const tx = new Transaction();
    tx.version = readInt32();
    offset += 1;
    const vinLen = readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      tx.ins.push({
        hash: readSlice(32),
        index: readUInt32(),
        script: readVarSlice(),
        sequence: readUInt32(),
      });
    }
    const voutLen = readVarInt();
    for (let i = 0; i < voutLen; ++i) {
      tx.outs.push({
        value: readUInt64(),
        script: readVarSlice(),
        asset: readSlice(32),
      });
    }
    tx.locktime = readUInt32();
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
  addInput(hash, index, sequence, scriptSig) {
    typeforce(
      types.tuple(
        types.Hash256bit,
        types.UInt32,
        types.maybe(types.UInt32),
        types.maybe(types.Buffer),
      ),
      arguments,
    );
    if (types.Null(sequence)) {
      sequence = Transaction.DEFAULT_SEQUENCE;
    }
    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence,
      }) - 1
    );
  }
  addOutput(scriptPubKey, value, asset) {
    typeforce(
      types.tuple(types.Buffer, types.Satoshi, types.Buffer),
      arguments,
    );
    // Add the output and return the output's index
    return (
      this.outs.push({
        script: scriptPubKey,
        value,
        asset,
      }) - 1
    );
  }
  weight() {
    const base = this.__byteLength();
    return base * 3;
  }
  virtualSize() {
    return Math.ceil(this.weight() / 4);
  }
  byteLength() {
    return this.__byteLength();
  }
  clone() {
    const newTx = new Transaction();
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.ins = this.ins.map(txIn => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
      };
    });
    newTx.outs = this.outs.map(txOut => {
      return {
        script: txOut.script,
        value: txOut.value,
        asset: txOut.asset,
      };
    });
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
    const buffer = Buffer.allocUnsafe(txTmp.__byteLength() + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0);
    return bcrypto.hash256(buffer);
  }
  getHash() {
    return bcrypto.hash256(this.__toBuffer(undefined, undefined));
  }
  getId() {
    // transaction hash's are displayed in reverse order
    return bufferutils_1.reverseBuffer(this.getHash()).toString('hex');
  }
  toBuffer(buffer, initialOffset) {
    return this.__toBuffer(buffer, initialOffset);
  }
  toHex() {
    return this.toBuffer(undefined, undefined).toString('hex');
  }
  setInputScript(index, scriptSig) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.ins[index].script = scriptSig;
  }
  __byteLength() {
    return (
      9 +
      varuint.encodingLength(this.ins.length) +
      varuint.encodingLength(this.outs.length) +
      this.ins.reduce((sum, input) => {
        return sum + 40 + varSliceSize(input.script);
      }, 0) +
      this.outs.reduce((sum, output) => {
        return sum + 40 + varSliceSize(output.script);
      }, 0)
    );
  }
  __toBuffer(buffer, initialOffset) {
    if (!buffer) buffer = Buffer.allocUnsafe(this.__byteLength());
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
    function writeUInt64(i) {
      offset = bufferutils.writeUInt64LE(buffer, i, offset);
    }
    function writeVarInt(i) {
      varuint.encode(i, buffer, offset);
      offset += varuint.encode.bytes;
    }
    function writeVarSlice(slice) {
      writeVarInt(slice.length);
      writeSlice(slice);
    }
    writeInt32(this.version);
    // No segwit support at the moment, flags are 00
    writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
    writeVarInt(this.ins.length);
    this.ins.forEach(txIn => {
      writeSlice(txIn.hash);
      writeUInt32(txIn.index);
      writeVarSlice(txIn.script);
      writeUInt32(txIn.sequence);
    });
    writeVarInt(this.outs.length);
    this.outs.forEach(txOut => {
      if (isOutput(txOut)) {
        writeUInt64(txOut.value);
      } else {
        writeSlice(txOut.valueBuffer);
      }
      writeVarSlice(txOut.script);
      writeSlice(txOut.asset);
    });
    writeUInt32(this.locktime);
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
