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
const MINUS_1 = 4294967295;
const OUTPOINT_ISSUANCE_FLAG = 1 << 31;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const CONFIDENTIAL_COMMITMENT = 33; // default size of confidential commitments (i.e. asset, value, nonce)
const CONFIDENTIAL_VALUE = 9; // explciti size of confidential values
const VALUE_UINT64_MAX: Buffer = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT: BlankOutput = {
  asset: ZERO,
  valueBuffer: VALUE_UINT64_MAX,
  nonce: ZERO,
  script: EMPTY_SCRIPT,
};

export interface BlankOutput {
  asset: Buffer;
  valueBuffer: Buffer;
  nonce: Buffer;
  script: Buffer;
}

export interface Output {
  asset: Buffer;
  amount: Buffer;
  nonce: Buffer;
  script: Buffer;
  value?: number;
}

export interface WitnessInput{
  issuanceRangeProof: Buffer;
  inflationRangeProof: Buffer;
  scriptWitness: Array<Buffer>;
  peginWitness: Array<Buffer>;
}

export interface WitnessOutput{
  surjectionProof: Buffer;
  rangeProof: Buffer;
}

type OpenOutput = Output | BlankOutput;

export interface Input {
  hash: Buffer;
  index: number;
  script: Buffer;
  sequence: number;
  issuance: object;
}

declare function createObject(o: object | undefined): object;

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

    function readVarInt(): number {
      const vi = varuint.decode(buffer, offset);
      offset += varuint.decode.bytes;
      return vi;
    }

    function readVarSlice(): Buffer {
      return readSlice(readVarInt());
    }

    function readUInt8(): number {
      const i = buffer.readUInt8(offset);
      offset += 1;
      return i;
    }

    // CConfidentialAsset size 33, prefixA 10, prefixB 11
    function readConfidentialAsset(): Buffer {
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
    function readConfidentialNonce(): Buffer {
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
    function readConfidentialValue(): Buffer {
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

    function readWitnessIn(fields: number): Array<WitnessInput> {
        const witInputArray = [];
        for (let i = 0; i < fields; ++i)
          witInputArray.push(readWitnessInField());
        return witInputArray;
    }

    function readWitnessInField(): WitnessInput {
        const issuance_range_proof = readVarSlice();
        const inflation_range_proof = readVarSlice();

        const scriptSize = readVarInt();
        const scriptWitness = [];
        for (let i = 0; i < scriptSize; ++i)
          scriptWitness.push(readVarSlice());

        const peginSize = readVarInt();
        const peginWitness = [];
        for (let i = 0; i < peginSize; ++i)
          peginWitness.push(readVarSlice());

        return {issuanceRangeProof: issuance_range_proof, inflationRangeProof: inflation_range_proof, 
            scriptWitness: scriptWitness, peginWitness: peginWitness}
    }

    function readWitnessOut(fields: number): Array<WitnessOutput> {
        const witOutputArray = [];
        for (let i = 0; i < fields; ++i)
          witOutputArray.push(readWitnessOutField());
        return witOutputArray;
    }

    function readWitnessOutField(): WitnessOutput {
        const surjection_proof = readVarSlice();
        const range_proof = readVarSlice();

        return {surjectionProof: surjection_proof, rangeProof: range_proof}
    }

    function valueFromAmount(amount : number): number {
    {
        const sign = amount < 0;
        let prefix = ""
        if (sign)
          prefix = "-"

        const n_abs = (sign ? -amount : amount);
        const quotient = n_abs / 100000000;
        const remainder = n_abs % 100000000;
        const numString = prefix + (quotient.toPrecision(remainder)).toString();
        return numString;
                // strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
    }

    const tx = new Transaction();
    tx.version = readInt32();

    const flag = readUInt8();

    const vinLen = readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      const inHash = readSlice(32);
      let inIndex = readUInt32();
      const inScript = readVarSlice();
      const inSequence = readUInt32();

      let inIssuance = {};
      if (inIndex !== MINUS_1) {
        if (inIndex & OUTPOINT_ISSUANCE_FLAG) {
          const issuanceNonce = readSlice(32);
          const issuanceEntropy = readSlice(32);

          const amount = readConfidentialValue();
          const inflation = readConfidentialValue();

          inIssuance = createObject({
            assetBlindingNonce: issuanceNonce,
            assetEntropy: issuanceEntropy,
            assetamount: amount,
            tokenamount: inflation,
          });
        }
      }
      inIndex &= OUTPOINT_INDEX_MASK;

      tx.ins.push({
        hash: inHash,
        index: inIndex,
        script: inScript,
        sequence: inSequence,
        issuance: inIssuance,
      });
    }

    const voutLen = readVarInt();
    for (let i = 0; i < voutLen; ++i) {

      const outValueBuffer = readConfidentialValue();

      // TODO we are not transforming amount into value and are not handling confidential values (they are represented as -1)
      let outValue = -1;

      if (outValueBuffer.readUIntBE(0, 1) == 1 && outValueBuffer.length == 9)
        outValue = bufferutils.readUInt64LE(reverseBuffer(outValueBuffer.slice(1,9)), 0);

      tx.outs.push({
        asset: readConfidentialAsset(),
        value: outValue,
        nonce: readConfidentialNonce(),
        script: readVarSlice(),
      });

    }

    tx.locktime = readUInt32();

    let witness_in: Array<WitnessInput> = [];
    let witness_out: Array<WitnessOutput> = [];

    if (flag === 1){
      witness_in = readWitnessIn(tx.ins.length)
      witness_out = readWitnessOut(tx.outs.length)
      // done in electrum, may have to modify this to produce hashes
      // flag ^= 1
    }

    tx.witness_in = tx.witness_in.concat(witness_in);
    tx.witness_out = tx.witness_out.concat(witness_out);

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
  witness_in: WitnessInput[] = [];
  witness_out: WitnessOutput[] = [];

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
    inIssuance?: object,
  ): number {
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

    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence as number,
        issuance: inIssuance || {},
      }) - 1
    );
  }

  addOutput(asset: Buffer, value: Buffer, nonce: Buffer, scriptPubKey: Buffer): number {
    typeforce(
      types.tuple(types.Buffer, types.Satoshi, types.Buffer, types.Buffer),
      arguments,
    );

    // Add the output and return the output's index
    return (
      this.outs.push({
        asset,
        value,
        nonce,
        script: scriptPubKey,
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
    newTx.witness_in = this.witness_in;
    newTx.witness_out = this.witness_out;

    newTx.ins = this.ins.map(txIn => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
        issuance: txIn.issuance,
      };
    });

    newTx.outs = this.outs.map(txOut => {
      return {
        asset: txOut.asset,
        value: (txOut as Output).value,
        nonce: txOut.nonce,
        script: txOut.script,
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

    function writeValue(slice: Buffer): void {
      if (slice.length == 8){
        writeUInt8(1);
        let tempBuffer = bufferutils.writeUInt64LE()
        write
      }
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
      writeSlice(txOut.asset);
      if (isOutput(txOut)) {
        writeUInt64(txOut.value);
      } else {
        writeSlice(txOut.valueBuffer);
      }
      writeSlice(txOut.value);
      writeSlice(txOut.nonce);
      writeVarSlice(txOut.script);
    });

    writeUInt32(this.locktime);

    // avoid slicing unless necessary
    if (initialOffset !== undefined) return buffer.slice(initialOffset, offset);
    return buffer;
  }
}
