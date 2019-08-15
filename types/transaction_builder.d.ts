/// <reference types="node" />
import { ECPairInterface } from './ecpair';
import { Network } from './networks';
import { Transaction, WitnessInput, WitnessOutput } from './transaction';
export interface TxbIssuance {
    assetBlindingNonce: Buffer | string;
    assetEntropy: Buffer | string;
    assetamount: Buffer | string;
    tokenamount: Buffer | string;
}
export declare class TransactionBuilder {
    network: Network;
    maximumFeeRate: number;
    static fromTransaction(transaction: Transaction, network?: Network): TransactionBuilder;
    private __PREV_TX_SET;
    private __INPUTS;
    private __TX;
    private __USE_LOW_R;
    constructor(network?: Network, maximumFeeRate?: number);
    setLowR(setting?: boolean): boolean;
    setLockTime(locktime: number): void;
    setVersion(version: number): void;
    validateWitnessIn(issuanceRangeProof: Buffer, inflationRangeProof: Buffer, scriptWitness: Buffer[], peginWitness: Buffer[]): boolean;
    validateWitnessOut(surjectionProof: Buffer, rangeProof: Buffer): boolean;
    setWitnessIn(witnessIn: WitnessInput[]): void;
    setWitnessOut(witnessOut: WitnessOutput[]): void;
    setFlag(flag: number): void;
    addInput(txHash: Buffer | string | Transaction, vout: number, inSequence?: number, inPrevOutScript?: Buffer, inIssuance?: TxbIssuance): number;
    addContract(contract: Buffer | string): number;
    addOutput(asset: string | Buffer, nValue: number | Buffer, nonce: string | Buffer, scriptPubKey: string | Buffer): number;
    build(): Transaction;
    buildIncomplete(): Transaction;
    sign(vin: number, keyPair: ECPairInterface, redeemScript?: Buffer, hashType?: number): void;
    private __addInputUnsafe;
    private __build;
    private __canModifyInputs;
    private __needsOutputs;
    private __canModifyOutputs;
    private __overMaximumFees;
}
