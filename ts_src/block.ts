import { reverseBuffer } from './bufferutils';
import * as bcrypto from './crypto';
import { Transaction } from './transaction';
import * as types from './types';

const fastMerkleRoot = require('merkle-lib/fastRoot');
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');

const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);

export class Block {
  static fromBuffer(buffer: Buffer): Block {
    if (buffer.length < 173) throw new Error('Buffer too small (< 173 bytes)');

    let offset: number = 0;
    const readSlice = (n: number): Buffer => {
      offset += n;
      return buffer.slice(offset - n, offset);
    };

    const readUInt32 = (): number => {
      const i = buffer.readUInt32LE(offset);
      offset += 4;
      return i;
    };

    const readInt32 = (): number => {
      const i = buffer.readInt32LE(offset);
      offset += 4;
      return i;
    };

    const readUInt8 = (): number => {
      const i = buffer.readUInt8(offset);
      offset += 1;
      return i;
    };

    const block = new Block();
    block.version = readInt32();
    block.prevHash = readSlice(32);
    block.merkleRoot = readSlice(32);
    block.contractHash = readSlice(32);
    block.attestationHash = readSlice(32);
    block.mappingHash = readSlice(32);
    block.timestamp = readUInt32();
    block.blockHeight = readUInt32();

    const challengeSize = readUInt8();

    if (buffer.length === 173) return block;

    let proofSize = 0;

    if (challengeSize > 0) {
      block.challenge = readSlice(challengeSize);
      proofSize = readUInt8();
      if (proofSize > 0) {
        block.proof = readSlice(proofSize);
      }
    }

    if (buffer.length === 173 + challengeSize + 1 + proofSize) return block;

    const readVarInt = (): number => {
      const vi = varuint.decode(buffer, offset);
      offset += varuint.decode.bytes;
      return vi;
    };

    const readTransaction = (): any => {
      const tx = Transaction.fromBuffer(buffer.slice(offset), true);
      offset += tx.byteLength();
      return tx;
    };

    const nTransactions = readVarInt();
    block.transactions = [];

    for (let i = 0; i < nTransactions; ++i) {
      const tx = readTransaction();
      block.transactions.push(tx);
    }

    return block;
  }

  static fromHex(hex: string): Block {
    return Block.fromBuffer(Buffer.from(hex, 'hex'));
  }

  static calculateTarget(bits: number): Buffer {
    const exponent = ((bits & 0xff000000) >> 24) - 3;
    const mantissa = bits & 0x007fffff;
    const target = Buffer.alloc(32, 0);
    target.writeUIntBE(mantissa, 29 - exponent, 3);
    return target;
  }

  static calculateMerkleRoot(transactions: Transaction[]): Buffer {
    typeforce([{ getHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;

    const hashes = transactions.map(transaction => transaction.getHash());

    const rootHash = fastMerkleRoot(hashes, bcrypto.hash256);

    return rootHash;
  }

  version: number = 1;
  prevHash?: Buffer = undefined;
  merkleRoot?: Buffer = undefined;
  contractHash?: Buffer = undefined;
  attestationHash?: Buffer = undefined;
  mappingHash?: Buffer = undefined;
  timestamp: number = 0;
  blockHeight: number = 0;
  challenge?: Buffer = undefined;
  proof?: Buffer = undefined;
  transactions?: Transaction[] = undefined;

  byteLength(headersOnly: boolean): number {
    let bLength = 173;

    if (this.challenge) bLength = bLength + this.challenge.length + 1;

    if (headersOnly) return bLength;

    if (this.proof) {
      bLength = bLength + this.proof.length;
    }

    if (!this.transactions) return bLength;

    return (
      bLength +
      varuint.encodingLength(this.transactions.length) +
      this.transactions.reduce((a, x) => a + x.byteLength(), 0)
    );
  }

  getHash(): Buffer {
    return bcrypto.hash256(this.toBuffer(true));
  }

  getId(): string {
    return reverseBuffer(this.getHash()).toString('hex');
  }

  getUTCDate(): Date {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);

    return date;
  }

  // TODO: buffer, offset compatibility
  toBuffer(headersOnly: boolean): Buffer {
    const buffer: Buffer = Buffer.allocUnsafe(this.byteLength(headersOnly));

    let offset: number = 0;
    const writeSlice = (slice: Buffer): void => {
      slice.copy(buffer, offset);
      offset += slice.length;
    };

    const writeInt32 = (i: number): void => {
      buffer.writeInt32LE(i, offset);
      offset += 4;
    };
    const writeUInt32 = (i: number): void => {
      buffer.writeUInt32LE(i, offset);
      offset += 4;
    };
    function writeUInt8(i: number): void {
      buffer.writeUInt8(i, offset);
      offset += 1;
    }

    writeInt32(this.version);
    writeSlice(this.prevHash!);
    writeSlice(this.merkleRoot!);
    writeSlice(this.contractHash!);
    writeSlice(this.attestationHash!);
    writeSlice(this.mappingHash!);
    writeUInt32(this.timestamp);
    writeUInt32(this.blockHeight);

    if (this.challenge) {
      writeUInt8(this.challenge.length);
      writeSlice(this.challenge!);
    } else writeUInt8(0);

    if (headersOnly) return buffer;

    if (this.proof) {
      writeUInt8(this.proof.length);
      writeSlice(this.proof!);
    } else writeUInt8(0);

    if (!this.transactions) return buffer;

    varuint.encode(this.transactions.length, buffer, offset);
    offset += varuint.encode.bytes;

    this.transactions.forEach(tx => {
      const txSize = tx.byteLength(); // TODO: extract from toBuffer?
      tx.toBuffer(buffer, offset);
      offset += txSize;
    });

    return buffer;
  }

  toHex(headersOnly: boolean): string {
    return this.toBuffer(headersOnly).toString('hex');
  }

  checkTxRoots(): boolean {
    return this.__checkMerkleRoot();
  }

  checkProofOfWork(): boolean {
    // const hash: Buffer = reverseBuffer(this.getHash());
    // const target = Block.calculateTarget(this.bits);
    // return hash.compare(target) <= 0;
    // broken at the moment as we do not have bits field in the ocean
    return true;
  }

  private __checkMerkleRoot(): boolean {
    if (!this.transactions) throw errorMerkleNoTxes;

    const actualMerkleRoot = Block.calculateMerkleRoot(this.transactions);
    return this.merkleRoot!.compare(actualMerkleRoot) === 0;
  }
}
