"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const bufferutils = require("./bufferutils");
const bufferutils_1 = require("./bufferutils");
const bcrypto = require("./crypto");
const bscript = require("./script");
const script_1 = require("./script");
const types = require("./types");
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');
function varSliceSize(someScript) {
    const length = someScript.length;
    return varuint.encodingLength(length) + length;
}
const EMPTY_SCRIPT = Buffer.allocUnsafe(0);
const ZERO = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
const ONE = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const MINUS_1 = 4294967295;
const OUTPOINT_ISSUANCE_FLAG = 1 << 31;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const CONFIDENTIAL_COMMITMENT = 33; // default size of confidential commitments (i.e. asset, value, nonce)
const CONFIDENTIAL_VALUE = 9; // explciti size of confidential values
const VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
    asset: ZERO,
    valueBuffer: VALUE_UINT64_MAX,
    nonce: ZERO,
    script: EMPTY_SCRIPT,
};
class Transaction {
    constructor() {
        this.version = 1;
        this.locktime = 0;
        this.ins = [];
        this.outs = [];
        this.witness_in = [];
        this.witness_out = [];
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
            for (let i = 0; i < fields; ++i)
                witInputArray.push(readWitnessInField());
            return witInputArray;
        }
        function readWitnessInField() {
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
            return { issuanceRangeProof: issuance_range_proof, inflationRangeProof: inflation_range_proof,
                scriptWitness: scriptWitness, peginWitness: peginWitness };
        }
        function readWitnessOut(fields) {
            const witOutputArray = [];
            for (let i = 0; i < fields; ++i)
                witOutputArray.push(readWitnessOutField());
            return witOutputArray;
        }
        function readWitnessOutField() {
            const surjection_proof = readVarSlice();
            const range_proof = readVarSlice();
            return { surjectionProof: surjection_proof, rangeProof: range_proof };
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
                outValue = bufferutils.readUInt64LE(bufferutils_1.reverseBuffer(outValueBuffer.slice(1, 9)), 0);
            tx.outs.push({
                asset: readConfidentialAsset(),
                value: outValue,
                nonce: readConfidentialNonce(),
                script: readVarSlice(),
            });
        }
        tx.locktime = readUInt32();
        let witness_in = [];
        let witness_out = [];
        if (flag === 1) {
            witness_in = readWitnessIn(tx.ins.length);
            witness_out = readWitnessOut(tx.outs.length);
            // done in electrum, may have to modify this to produce hashes
            // flag ^= 1
        }
        tx.witness_in = tx.witness_in.concat(witness_in);
        tx.witness_out = tx.witness_out.concat(witness_out);
        if (_NO_STRICT)
            return tx;
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
            if (buffer[i] !== 0)
                return false;
        }
        return true;
    }
    isCoinbase() {
        return (this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash));
    }
    addInput(hash, index, sequence, scriptSig, inIssuance) {
        typeforce(types.tuple(types.Hash256bit, types.UInt32, types.maybe(types.UInt32), types.maybe(types.Buffer), types.maybe(types.Object)), arguments);
        if (types.Null(sequence)) {
            sequence = Transaction.DEFAULT_SEQUENCE;
        }
        // Add the input and return the input's index
        return (this.ins.push({
            hash,
            index,
            script: scriptSig || EMPTY_SCRIPT,
            sequence: sequence,
            issuance: inIssuance || {},
        }) - 1);
    }
    addOutput(asset, value, nonce, scriptPubKey) {
        typeforce(types.tuple(types.Buffer, types.Satoshi, types.Buffer, types.Buffer), arguments);
        // Add the output and return the output's index
        return (this.outs.push({
            asset,
            value,
            nonce,
            script: scriptPubKey,
        }) - 1);
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
                value: txOut.value,
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
    hashForSignature(inIndex, prevOutScript, hashType) {
        typeforce(types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number), arguments);
        // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
        if (inIndex >= this.ins.length)
            return ONE;
        // ignore OP_CODESEPARATOR
        const ourScript = bscript.compile(bscript.decompile(prevOutScript).filter(x => {
            return x !== script_1.OPS.OP_CODESEPARATOR;
        }));
        const txTmp = this.clone();
        // SIGHASH_NONE: ignore all outputs? (wildcard payee)
        if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
            txTmp.outs = [];
            // ignore sequence numbers (except at inIndex)
            txTmp.ins.forEach((input, i) => {
                if (i === inIndex)
                    return;
                input.sequence = 0;
            });
            // SIGHASH_SINGLE: ignore all outputs, except at the same index?
        }
        else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
            // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
            if (inIndex >= this.outs.length)
                return ONE;
            // truncate outputs after
            txTmp.outs.length = inIndex + 1;
            // "blank" outputs before
            for (let i = 0; i < inIndex; i++) {
                txTmp.outs[i] = BLANK_OUTPUT;
            }
            // ignore sequence numbers (except at inIndex)
            txTmp.ins.forEach((input, y) => {
                if (y === inIndex)
                    return;
                input.sequence = 0;
            });
        }
        // SIGHASH_ANYONECANPAY: ignore inputs entirely?
        if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
            txTmp.ins = [txTmp.ins[inIndex]];
            txTmp.ins[0].script = ourScript;
            // SIGHASH_ALL: only ignore input scripts
        }
        else {
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
        return (9 +
            varuint.encodingLength(this.ins.length) +
            varuint.encodingLength(this.outs.length) +
            this.ins.reduce((sum, input) => {
                return sum + 40 + varSliceSize(input.script);
            }, 0) +
            this.outs.reduce((sum, output) => {
                return sum + 40 + varSliceSize(output.script);
            }, 0));
    }
    __toBuffer(buffer, initialOffset) {
        if (!buffer)
            buffer = Buffer.allocUnsafe(this.__byteLength());
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
        // function writeUInt64(i: number): void {
        //   offset = bufferutils.writeUInt64LE(buffer!, i, offset);
        // }
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
            writeSlice(txOut.asset);
            writeSlice(txOut.value);
            writeSlice(txOut.nonce);
            writeVarSlice(txOut.script);
        });
        writeUInt32(this.locktime);
        // avoid slicing unless necessary
        if (initialOffset !== undefined)
            return buffer.slice(initialOffset, offset);
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
