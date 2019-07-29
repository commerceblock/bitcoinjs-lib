// https://en.bitcoin.it/wiki/List_of_address_prefixes
// Dogecoin BIP32 is a proposed standard: https://bitcointalk.org/index.php?topic=409731
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

export const gold_main: Network = {
  messagePrefix: '\x18Gold Signed Message:\n',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 38,
  scriptHash: 97,
  wif: 0xb4,
};
export const ocean_main: Network = {
  messagePrefix: '\x18Ocean Signed Message:\n',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0,
  scriptHash: 5,
  wif: 0x80,
};
export const gold_test: Network = {
  messagePrefix: '\x18GoldTest Signed Message:\n',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 235,
  scriptHash: 75,
  wif: 0xef,
};
export const ocean_test: Network = {
  messagePrefix: '\x18OceanTest Signed Message:\n',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 235,
  scriptHash: 75,
  wif: 0xef,
};
