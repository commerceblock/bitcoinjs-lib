export interface Network {
    messagePrefix: string;
    bip32: Bip32;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}
interface Bip32 {
    public: number;
    private: number;
}
export declare const gold_main: Network;
export declare const ocean_main: Network;
export declare const gold_test: Network;
export declare const ocean_test: Network;
export {};
