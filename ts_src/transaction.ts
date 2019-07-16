import * as bufferutils from './bufferutils';
import { reverseBuffer } from './bufferutils';
import * as bcrypto from './crypto';
import * as bscript from './script';
import { OPS as opcodes } from './script';
import * as types from './types';

const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');

function varSliceSize(someScript: Buffer): number {
  const length = someScript.length;

  return varuint.encodingLength(length) + length;
}

const EMPTY_SCRIPT: Buffer = Buffer.allocUnsafe(0);
const ZERO: Buffer = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE: Buffer = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const VALUE_UINT64_MAX: Buffer = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT: BlankOutput = {
  script: EMPTY_SCRIPT,
  valueBuffer: VALUE_UINT64_MAX,
  asset: ZERO,
};

function isOutput(out: Output | BlankOutput): out is Output {
  return (out as Output).value !== undefined;
}

export interface BlankOutput {
  script: Buffer;
  valueBuffer: Buffer;
  asset: Buffer;
}

export interface Output {
  script: Buffer;
  value: number;
  asset: Buffer;
}

type OpenOutput = Output | BlankOutput;

export interface Input {
  hash: Buffer;
  index: number;
  script: Buffer;
  sequence: number;
}

export class Transaction {
  static readonly DEFAULT_SEQUENCE = 0xffffffff;
  static readonly SIGHASH_ALL = 0x01;
  static readonly SIGHASH_NONE = 0x02;
  static readonly SIGHASH_SINGLE = 0x03;
  static readonly SIGHASH_ANYONECANPAY = 0x80;
  static readonly ADVANCED_TRANSACTION_MARKER = 0x00;
  static readonly ADVANCED_TRANSACTION_FLAG = 0x01;

  static fromBuffer(buffer: Buffer, _NO_STRICT?: boolean): Transaction {
    let offset: number = 0;

    function readSlice(n: number): Buffer {
      offset += n;
      return buffer.slice(offset - n, offset);
    }

    function readUInt32(): number {
      const i = buffer.readUInt32LE(offset);
      offset += 4;
      return i;
    }

    function readInt32(): number {
      const i = buffer.readInt32LE(offset);
      offset += 4;
      return i;
    }

    function readUInt64(): number {
      const i = bufferutils.readUInt64LE(buffer, offset);
      offset += 8;
      return i;
    }

    function readVarInt(): number {
      const vi = varuint.decode(buffer, offset);
      offset += varuint.decode.bytes;
      return vi;
    }

    function readVarSlice(): Buffer {
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

  static fromHex(hex: string): Transaction {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), false);
  }

  static isCoinbaseHash(buffer: Buffer): boolean {
    typeforce(types.Hash256bit, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }

  version: number = 1;
  locktime: number = 0;
  ins: Input[] = [];
  outs: OpenOutput[] = [];

  isCoinbase(): boolean {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }

  addInput(
    hash: Buffer,
    index: number,
    sequence?: number,
    scriptSig?: Buffer,
  ): number {
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
        sequence: sequence as number,
      }) - 1
    );
  }

  addOutput(scriptPubKey: Buffer, value: number, asset: Buffer): number {
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

  weight(): number {
    const base = this.__byteLength();
    return base * 3;
  }

  virtualSize(): number {
    return Math.ceil(this.weight() / 4);
  }

  byteLength(): number {
    return this.__byteLength();
  }

  clone(): Transaction {
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
        value: (txOut as Output).value,
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
  hashForSignature(
    inIndex: number,
    prevOutScript: Buffer,
    hashType: number,
  ): Buffer {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number),
      arguments,
    );

    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;

    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript)!.filter(x => {
        return x !== opcodes.OP_CODESEPARATOR;
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
    const buffer: Buffer = Buffer.allocUnsafe(txTmp.__byteLength() + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0);

    return bcrypto.hash256(buffer);
  }

  getHash(): Buffer {
    return bcrypto.hash256(this.__toBuffer(undefined, undefined));
  }

  getId(): string {
    // transaction hash's are displayed in reverse order
    return reverseBuffer(this.getHash()).toString('hex');
  }

  toBuffer(buffer?: Buffer, initialOffset?: number): Buffer {
    return this.__toBuffer(buffer, initialOffset);
  }

  toHex(): string {
    return this.toBuffer(undefined, undefined).toString('hex');
  }

  setInputScript(index: number, scriptSig: Buffer): void {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);

    this.ins[index].script = scriptSig;
  }

  private __byteLength(): number {
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

  private __toBuffer(buffer?: Buffer, initialOffset?: number): Buffer {
    if (!buffer) buffer = Buffer.allocUnsafe(this.__byteLength()) as Buffer;

    let offset = initialOffset || 0;

    function writeSlice(slice: Buffer): void {
      offset += slice.copy(buffer!, offset);
    }

    function writeUInt8(i: number): void {
      offset = buffer!.writeUInt8(i, offset);
    }

    function writeUInt32(i: number): void {
      offset = buffer!.writeUInt32LE(i, offset);
    }

    function writeInt32(i: number): void {
      offset = buffer!.writeInt32LE(i, offset);
    }

    function writeUInt64(i: number): void {
      offset = bufferutils.writeUInt64LE(buffer!, i, offset);
    }

    function writeVarInt(i: number): void {
      varuint.encode(i, buffer, offset);
      offset += varuint.encode.bytes;
    }

    function writeVarSlice(slice: Buffer): void {
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
