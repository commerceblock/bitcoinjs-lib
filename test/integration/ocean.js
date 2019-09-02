const ocean = require('../../')
const assert = require('assert')
const network = require('../../src/networks')
const bufferutils = require('../../src/bufferutils')
const gold_main = network.ocean_test

// 4294967295
// scriptpubkey input 76a914cbd2fbe7639a0149a4612b956ba1717d20a1020188ac

const raw = {
  "version": 2,
  "flag": 0,
  "ins": [
    {
      "hash": "060977d597a965d139eb87ea8c44693f70376d92e6e6f48422b53a49d7638c82",
      "index": 54,
    }
  ],
  "outs": [
    {
      "value": 10000000000000,
      "data": "76a9144ded105f3a0b4b09d6792df58a114deefdab54b688ac",
      "asset": "0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce",
      "nonce": "00"
    },
    {
      "value": 10000000000000,
      "data": "76a914b62117b2778caa01237a0cc081b2556a1c324fad88ac",
      "asset": "0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce",
      "nonce": "00"
    },
    {
      "value": 1000000000000,
      "data": "76a914ec07dce2b29a58354471c27da0204ef720cbc61688ac",
      "asset": "0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce",
      "nonce": "00"
    }
  ],
  "locktime": 0
}


//Example how to construct a transaction from raw JSON + witness
const txb = new ocean.TransactionBuilder(gold_main)
txb.setVersion(raw.version)
txb.setLockTime(raw.locktime)

if(raw.flag)
  txb.setFlag(raw.flag)

raw.ins.forEach((txIn, i) => {
  txb.addInput(txIn.hash, txIn.index)
})

raw.outs.forEach(txOut => {
  let script

  if (txOut.data) {
    script = Buffer.from(txOut.data, 'hex')
  } else if (txOut.script) {
    script = bscript.fromASM(txOut.script)
  }

  let value = Buffer.from('010000000000000000', 'hex')
  const numToBuffer = Buffer.alloc(8);

  if (txOut.value) {
    bufferutils.writeUInt64LE(numToBuffer, txOut.value, 0)
    value = Buffer.concat([
      Buffer.from('01', 'hex'),
      bufferutils.reverseBuffer(numToBuffer),
    ])
  }
  else if (txOut.nValue) value = Buffer.from(txOut.nValue, 'hex')

  txb.addOutput(Buffer.from(txOut.asset, 'hex'), value, Buffer.from(txOut.nonce, 'hex'), script)
})

const key = ocean.ECPair.fromPrivateKey(Buffer.from('c7d0ace3243ce144860def4c275076239dd512d73c034464cf8cf649f49f3aac', 'hex'), {network: gold_main})

txb.sign(0, key)
console.log("space")
console.log(txb.build().toHex())

console.log(key.publicKey.toString('hex'))