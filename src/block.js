'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const bufferutils_1 = require('./bufferutils');
const bcrypto = require('./crypto');
const transaction_1 = require('./transaction');
const types = require('./types');
const fastMerkleRoot = require('merkle-lib/fastRoot');
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');
const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);
class Block {
  constructor() {
    this.version = 1;
    this.prevHash = undefined;
    this.merkleRoot = undefined;
    this.timestamp = 0;
    this.bits = 0;
    this.nonce = 0;
    this.transactions = undefined;
  }
  static fromBuffer(buffer) {
    if (buffer.length < 80) throw new Error('Buffer too small (< 80 bytes)');
    let offset = 0;
    const readSlice = n => {
      offset += n;
      return buffer.slice(offset - n, offset);
    };
    const readUInt32 = () => {
      const i = buffer.readUInt32LE(offset);
      offset += 4;
      return i;
    };
    const readInt32 = () => {
      const i = buffer.readInt32LE(offset);
      offset += 4;
      return i;
    };
    const block = new Block();
    block.version = readInt32();
    block.prevHash = readSlice(32);
    block.merkleRoot = readSlice(32);
    block.timestamp = readUInt32();
    block.bits = readUInt32();
    block.nonce = readUInt32();
    if (buffer.length === 80) return block;
    const readVarInt = () => {
      const vi = varuint.decode(buffer, offset);
      offset += varuint.decode.bytes;
      return vi;
    };
    const readTransaction = () => {
      const tx = transaction_1.Transaction.fromBuffer(
        buffer.slice(offset),
        true,
      );
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
  static fromHex(hex) {
    return Block.fromBuffer(Buffer.from(hex, 'hex'));
  }
  static calculateTarget(bits) {
    const exponent = ((bits & 0xff000000) >> 24) - 3;
    const mantissa = bits & 0x007fffff;
    const target = Buffer.alloc(32, 0);
    target.writeUIntBE(mantissa, 29 - exponent, 3);
    return target;
  }
  static calculateMerkleRoot(transactions) {
    typeforce([{ getHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;
    const hashes = transactions.map(transaction => transaction.getHash());
    const rootHash = fastMerkleRoot(hashes, bcrypto.hash256);
    return rootHash;
  }
  byteLength(headersOnly) {
    if (headersOnly || !this.transactions) return 80;
    return (
      80 +
      varuint.encodingLength(this.transactions.length) +
      this.transactions.reduce((a, x) => a + x.byteLength(), 0)
    );
  }
  getHash() {
    return bcrypto.hash256(this.toBuffer(true));
  }
  getId() {
    return bufferutils_1.reverseBuffer(this.getHash()).toString('hex');
  }
  getUTCDate() {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);
    return date;
  }
  // TODO: buffer, offset compatibility
  toBuffer(headersOnly) {
    const buffer = Buffer.allocUnsafe(this.byteLength(headersOnly));
    let offset = 0;
    const writeSlice = slice => {
      slice.copy(buffer, offset);
      offset += slice.length;
    };
    const writeInt32 = i => {
      buffer.writeInt32LE(i, offset);
      offset += 4;
    };
    const writeUInt32 = i => {
      buffer.writeUInt32LE(i, offset);
      offset += 4;
    };
    writeInt32(this.version);
    writeSlice(this.prevHash);
    writeSlice(this.merkleRoot);
    writeUInt32(this.timestamp);
    writeUInt32(this.bits);
    writeUInt32(this.nonce);
    if (headersOnly || !this.transactions) return buffer;
    varuint.encode(this.transactions.length, buffer, offset);
    offset += varuint.encode.bytes;
    this.transactions.forEach(tx => {
      const txSize = tx.byteLength(); // TODO: extract from toBuffer?
      tx.toBuffer(buffer, offset);
      offset += txSize;
    });
    return buffer;
  }
  toHex(headersOnly) {
    return this.toBuffer(headersOnly).toString('hex');
  }
  checkTxRoots() {
    return this.__checkMerkleRoot();
  }
  checkProofOfWork() {
    const hash = bufferutils_1.reverseBuffer(this.getHash());
    const target = Block.calculateTarget(this.bits);
    return hash.compare(target) <= 0;
  }
  __checkMerkleRoot() {
    if (!this.transactions) throw errorMerkleNoTxes;
    const actualMerkleRoot = Block.calculateMerkleRoot(this.transactions);
    return this.merkleRoot.compare(actualMerkleRoot) === 0;
  }
}
exports.Block = Block;
