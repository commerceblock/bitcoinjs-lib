/// <reference types="node" />
import { Transaction } from './transaction';
export declare class Block {
    static fromBuffer(buffer: Buffer): Block;
    static fromHex(hex: string): Block;
    static calculateTarget(bits: number): Buffer;
    static calculateMerkleRoot(transactions: Transaction[]): Buffer;
    version: number;
    prevHash?: Buffer;
    merkleRoot?: Buffer;
    contractHash?: Buffer;
    attestationHash?: Buffer;
    mappingHash?: Buffer;
    timestamp: number;
    blockHeight: number;
    challenge?: Buffer;
    proof?: Buffer;
    transactions?: Transaction[];
    byteLength(headersOnly: boolean): number;
    getHash(): Buffer;
    getId(): string;
    getUTCDate(): Date;
    toBuffer(headersOnly: boolean): Buffer;
    toHex(headersOnly: boolean): string;
    checkTxRoots(): boolean;
    checkProofOfWork(): boolean;
    private __checkMerkleRoot;
}
