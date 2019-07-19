/// <reference types="node" />
export interface BlankOutput {
    asset: Buffer;
    valueBuffer: Buffer;
    nonce: Buffer;
    script: Buffer;
}
export interface Output {
    asset: Buffer;
    value: number;
    nonce: Buffer;
    script: Buffer;
}
export interface WitnessInput {
    issuanceRangeProof: Buffer;
    inflationRangeProof: Buffer;
    scriptWitness: Array<Buffer>;
    peginWitness: Array<Buffer>;
}
export interface WitnessOutput {
    surjectionProof: Buffer;
    rangeProof: Buffer;
}
declare type OpenOutput = Output | BlankOutput;
export interface Input {
    hash: Buffer;
    index: number;
    script: Buffer;
    sequence: number;
    issuance: object;
}
export declare class Transaction {
    static readonly DEFAULT_SEQUENCE = 4294967295;
    static readonly SIGHASH_ALL = 1;
    static readonly SIGHASH_NONE = 2;
    static readonly SIGHASH_SINGLE = 3;
    static readonly SIGHASH_ANYONECANPAY = 128;
    static readonly ADVANCED_TRANSACTION_MARKER = 0;
    static readonly ADVANCED_TRANSACTION_FLAG = 1;
    static fromBuffer(buffer: Buffer, _NO_STRICT?: boolean): Transaction;
    static fromHex(hex: string): Transaction;
    static isCoinbaseHash(buffer: Buffer): boolean;
    version: number;
    locktime: number;
    ins: Input[];
    outs: OpenOutput[];
    witness_in: WitnessInput[];
    witness_out: WitnessOutput[];
    isCoinbase(): boolean;
    addInput(hash: Buffer, index: number, sequence?: number, scriptSig?: Buffer, inIssuance?: object): number;
    addOutput(asset: Buffer, value: Buffer, nonce: Buffer, scriptPubKey: Buffer): number;
    weight(): number;
    virtualSize(): number;
    byteLength(): number;
    clone(): Transaction;
    /**
     * Hash transaction for signing a specific input.
     *
     * Bitcoin uses a different hash for each signed transaction input.
     * This method copies the transaction, makes the necessary changes based on the
     * hashType, and then hashes the result.
     * This hash can then be used to sign the provided transaction input.
     */
    hashForSignature(inIndex: number, prevOutScript: Buffer, hashType: number): Buffer;
    getHash(): Buffer;
    getId(): string;
    toBuffer(buffer?: Buffer, initialOffset?: number): Buffer;
    toHex(): string;
    setInputScript(index: number, scriptSig: Buffer): void;
    private __byteLength;
    private __toBuffer;
}
export {};
