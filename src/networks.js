'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.gold_main = {
  messagePrefix: '\x18Gold Signed Message:\n',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 38,
  scriptHash: 97,
  wif: 0xb4,
};
exports.ocean_main = {
  messagePrefix: '\x18Ocean Signed Message:\n',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0,
  scriptHash: 5,
  wif: 0x80,
};
exports.gold_test = {
  messagePrefix: '\x18GoldTest Signed Message:\n',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 235,
  scriptHash: 75,
  wif: 0xef,
};
exports.ocean_test = {
  messagePrefix: '\x18OceanTest Signed Message:\n',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 235,
  scriptHash: 75,
  wif: 0xef,
};
