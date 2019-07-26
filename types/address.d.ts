/// <reference types="node" />
import { Network } from './networks';
export interface Base58CheckResult {
    hash: Buffer;
    version: number;
}
export declare function fromBase58Check(address: string): Base58CheckResult;
export declare function toBase58Check(hash: Buffer, version: number): string;
export declare function fromOutputScript(output: Buffer, network?: Network): string;
export declare function toOutputScript(address: string, network?: Network): Buffer;
