const assert = require('assert')
const ocean = require('../../')
const network = require('../../src/networks')
const gold_main = network.gold_main

function rng () {
  return Buffer.from('YT8dAtK4d16A3P1z+TpwB2jJ4aFH3g9M1EioIBkLEV4=', 'base64')
}

// can create a typical p2pkh Transaction --------------------------------------------------------------------------
const alice1 = ocean.ECPair.makeRandom({ network: gold_main })
const alice2 = ocean.ECPair.makeRandom({ network: gold_main })
const aliceChange = ocean.ECPair.makeRandom({ network: gold_main, rng: rng })
const bobdestination = ocean.ECPair.makeRandom({ network: gold_main })

const alice1pkh = ocean.payments.p2pkh({ pubkey: alice1.publicKey, network: gold_main })
const alice2pkh = ocean.payments.p2pkh({ pubkey: alice2.publicKey, network: gold_main })
const aliceCpkh = ocean.payments.p2pkh({ pubkey: aliceChange.publicKey, network: gold_main })
const bobpkh = ocean.payments.p2pkh({ pubkey: bobdestination.publicKey, network: gold_main })

// give Alice 2 unspent outputs
//const unspent0 = regtestUtils.faucet(alice1pkh.address, 5e4) This is not used as ocean can't use regtest. At this
//const unspent1 = regtestUtils.faucet(alice2pkh.address, 7e4) point it would retrieve unspent outputs from a node/website.
const unspent0 = {
  'txId': 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c',
  'vout': 6
}
const unspent1 = {
  'txId': '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730',
  'vout': 0
}

const txb1 = new ocean.TransactionBuilder(gold_main)
txb1.addInput(unspent0.txId, unspent0.vout) // alice1 unspent
txb1.addInput(unspent1.txId, unspent1.vout) // alice2 unspent
txb1.addOutput('01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d', 
              8e4, '00', bobpkh.address) // the actual "spend"
txb1.addOutput('01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d', 
              1e4, '00', aliceCpkh.address) // Alice's change
// (in)(5e4 + 7e4) - (out)(8e4 + 1e4) = (fee)3e4 = 30000, this is the miner fee

// Alice signs each input with the respective private keys
txb1.sign(0, alice1)
txb1.sign(1, alice2)

// build and broadcast our gold_main network
// At this point the transaction would be broadcast to a node/website like regtest, but we can't use it as ocean is different.
//regtestUtils.broadcast(txb.build().toHex()) 

// can create a typical p2sh multisig Transaction --------------------------------------------------------------------------
const keyPairs = [
  ocean.ECPair.makeRandom({ network: gold_main }),
  ocean.ECPair.makeRandom({ network: gold_main }),
  ocean.ECPair.makeRandom({ network: gold_main }),
  ocean.ECPair.makeRandom({ network: gold_main })
]
const pubkeys = keyPairs.map(x => x.publicKey)
const p2ms = ocean.payments.p2ms({ m: 2, pubkeys: pubkeys, network: gold_main })
const p2sh = ocean.payments.p2sh({ redeem: p2ms, network: gold_main })

//This is not used as ocean can't use regtest. At this
//point it would retrieve unspent outputs from a 3rd party.
//const unspent = await regtestUtils.faucet(p2sh.address, 2e4) 
const unspent = {
  'txId': 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c',
  'vout': 6
}

const txb2 = new ocean.TransactionBuilder(gold_main)
txb2.addInput(unspent.txId, unspent.vout)
txb2.addOutput('01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d', 1e4, '00', bobpkh.address)

txb2.sign(0, keyPairs[0], p2sh.redeem.output)
txb2.sign(0, keyPairs[2], p2sh.redeem.output)
const tx = txb2.build()

// The hex can then be used for broadcasting
const p2shHex = tx.toHex()

// At this point the transaction would be broadcast to a node/website like regtest, but we can't use it as ocean is different.
//await regtestUtils.broadcast(p2shHex)

// Example of a transaction with issuance --------------------------------------------------------------------------
const issuanceHex = "01000000000100000000000000000000000000000000000000000000000000000000000000000000008000ffffffff000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f01000775f05a0740000100000000000000000101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100001319718a500000015100000000"

const issuanceTx = ocean.Transaction.fromHex(issuanceHex)
// Can only read issuance transactions as they have prevhash of 0's and are similar to coinbase
//const txb3 = ocean.TransactionBuilder.fromTransaction(issuanceTx, gold_main)

console.log('\nIssuance data:')
console.log(issuanceTx.ins[0].issuance)

// Example of a transaction with ocean witness --------------------------------------------------------------------------
const witnessHex = "02000000010178fdfddeafc3bac34abe63efee0d64f7d817cee508ded08746ba4ae6df5349cbffffffff03550101ffffffff02011b37916db32188c32baa4a7d70ab3ebbe68b6dada8b0ac39333a159eb5cad13301000000000000000000016a011b37916db32188c32baa4a7d70ab3ebbe68b6dada8b0ac39333a159eb5cad13301000000000000000000266a24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000"

const witnessTx = ocean.Transaction.fromHex(witnessHex)
 
const txb4 = ocean.TransactionBuilder.fromTransaction(witnessTx, gold_main)

console.log("\nWitness In data:")
console.log(txb4.__TX.witnessIn)
console.log("\nWitness Out data:")
console.log(txb4.__TX.witnessOut)
