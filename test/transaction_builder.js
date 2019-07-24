const { describe, it, beforeEach } = require('mocha')
const assert = require('assert')
const baddress = require('../src/address')
const bscript = require('../src/script')
const payments = require('../src/payments')

const ECPair = require('../src/ecpair')
const Transaction = require('..').Transaction
const TransactionBuilder = require('..').TransactionBuilder
const NETWORKS = require('../src/networks')

const fixtures = require('./fixtures/transaction_builder')

const assethex = '01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d'
const emptyNonce = Buffer.from('00', 'hex');

function constructSign (f, txb) {
  const network = NETWORKS[f.network]
  const stages = f.stages && f.stages.concat()

  f.inputs.forEach((input, index) => {
    if (!input.signs) return
    input.signs.forEach(sign => {
      const keyPair = ECPair.fromWIF(sign.keyPair, network)
      let redeemScript
      let value

      if (sign.redeemScript) {
        redeemScript = bscript.fromASM(sign.redeemScript)
      }

      if (sign.value) {
        value = sign.value
      }

      txb.sign(index, keyPair, redeemScript, sign.hashType, value)

      if (sign.stage) {
        const tx = txb.buildIncomplete()
        assert.strictEqual(tx.toHex(), stages.shift())
        txb = TransactionBuilder.fromTransaction(tx, network)
      }
    })
  })

  return txb
}

function construct (f, dontSign) {
  const network = NETWORKS[f.network]
  const txb = new TransactionBuilder(network)

  if (Number.isFinite(f.version)) txb.setVersion(f.version)
  if (f.locktime !== undefined) txb.setLockTime(f.locktime)

  f.inputs.forEach(input => {
    let prevTx
    if (input.txRaw) {
      const constructed = construct(input.txRaw)
      if (input.txRaw.incomplete) prevTx = constructed.buildIncomplete()
      else prevTx = constructed.build()
    } else if (input.txHex) {
      prevTx = Transaction.fromHex(input.txHex)
    } else {
      prevTx = input.txId
    }

    let prevTxScript
    if (input.prevTxScript) {
      prevTxScript = bscript.fromASM(input.prevTxScript)
    }

    txb.addInput(prevTx, input.vout, input.sequence, prevTxScript)
  })

  f.outputs.forEach(output => {
    if (output.address) {
      txb.addOutput(output.asset, output.nValue, output.nonce, output.address)
    } else {
      txb.addOutput(output.asset, output.nValue, output.nonce, bscript.fromASM(output.script))
    }
  })

  if (dontSign) return txb
  return constructSign(f, txb)
}

describe('TransactionBuilder', () => {
  // constants
  const keyPair = ECPair.fromPrivateKey(Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex'))
  const scripts = [
    '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
    '1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP'
  ].map(x => {
    return baddress.toOutputScript(x)
  })
  const txHash = Buffer.from('0e7cea811c0be9f73c0aca591034396e7264473fc25c1ca45195d7417b36cbe2', 'hex')

  describe('fromTransaction', () => {
    fixtures.valid.build.forEach(f => {
      it('returns TransactionBuilder, with ' + f.description, () => {
        const network = NETWORKS[f.network || 'bitcoin']

        const tx = Transaction.fromHex(f.txHex)
        const txb = TransactionBuilder.fromTransaction(tx, network)
        const txAfter = f.incomplete ? txb.buildIncomplete() : txb.build()

        assert.strictEqual(txAfter.toHex(), f.txHex)
        assert.strictEqual(txb.network, network)
      })
    })

    fixtures.valid.fromTransaction.forEach(f => {
      it('returns TransactionBuilder, with ' + f.description, () => {
        const tx = new Transaction()

        f.inputs.forEach(input => {
          const txHash2 = Buffer.from(input.txId, 'hex').reverse()

          tx.addInput(txHash2, input.vout, undefined, bscript.fromASM(input.scriptSig))
        })

        f.outputs.forEach(output => {
          tx.addOutput(Buffer.from(output.asset, 'hex'), output.nValue, output.nonce, bscript.fromASM(output.script))
        })

        const txb = TransactionBuilder.fromTransaction(tx)
        const txAfter = f.incomplete ? txb.buildIncomplete() : txb.build()

        txAfter.ins.forEach((input, i) => {
          assert.strictEqual(bscript.toASM(input.script), f.inputs[i].scriptSigAfter)
        })

        txAfter.outs.forEach((output, i) => {
          assert.strictEqual(bscript.toASM(output.script), f.outputs[i].script)
        })
      })
    })

    fixtures.valid.fromTransactionSequential.forEach(f => {
      it('with ' + f.description, () => {
        const network = NETWORKS[f.network]
        const tx = Transaction.fromHex(f.txHex)
        const txb = TransactionBuilder.fromTransaction(tx, network)

        tx.ins.forEach((input, i) => {
          assert.strictEqual(bscript.toASM(input.script), f.inputs[i].scriptSig)
        })

        constructSign(f, txb)
        const txAfter = f.incomplete ? txb.buildIncomplete() : txb.build()

        txAfter.ins.forEach((input, i) => {
          assert.strictEqual(bscript.toASM(input.script), f.inputs[i].scriptSigAfter)
        })

        assert.strictEqual(txAfter.toHex(), f.txHexAfter)
      })
    })

    it('classifies transaction inputs', () => {
      const tx = Transaction.fromHex(fixtures.valid.classification.hex)
      const txb = TransactionBuilder.fromTransaction(tx)

      txb.__INPUTS.forEach(i => {
        assert.strictEqual(i.prevOutType, 'scripthash')
        assert.strictEqual(i.redeemScriptType, 'multisig')
      })
    })

    fixtures.invalid.fromTransaction.forEach(f => {
      it('throws ' + f.exception, () => {
        const tx = Transaction.fromHex(f.txHex)

        assert.throws(() => {
          TransactionBuilder.fromTransaction(tx)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('addInput', () => {
    let txb
    beforeEach(() => {
      txb = new TransactionBuilder()
    })

    it('accepts a txHash, index [and sequence number]', () => {
      const vin = txb.addInput(txHash, 1, 54)
      assert.strictEqual(vin, 0)

      const txIn = txb.__TX.ins[0]
      assert.strictEqual(txIn.hash, txHash)
      assert.strictEqual(txIn.index, 1)
      assert.strictEqual(txIn.sequence, 54)
      assert.strictEqual(txb.__INPUTS[0].prevOutScript, undefined)
    })

    it('accepts a txHash, index [, sequence number and scriptPubKey]', () => {
      const vin = txb.addInput(txHash, 1, 54, scripts[1])
      assert.strictEqual(vin, 0)

      const txIn = txb.__TX.ins[0]
      assert.strictEqual(txIn.hash, txHash)
      assert.strictEqual(txIn.index, 1)
      assert.strictEqual(txIn.sequence, 54)
      assert.strictEqual(txb.__INPUTS[0].prevOutScript, scripts[1])
    })

    it('accepts a prevTx, index [and sequence number]', () => {
      const prevTx = new Transaction()
      prevTx.addOutput(Buffer.from(assethex, 'hex'), Buffer.from('010000000000000000', 'hex'), emptyNonce, scripts[0])
      prevTx.addOutput(Buffer.from(assethex, 'hex'), Buffer.from('010100000000000000', 'hex'), emptyNonce, scripts[1])

      const vin = txb.addInput(prevTx, 1, 54)
      assert.strictEqual(vin, 0)

      const txIn = txb.__TX.ins[0]
      assert.deepStrictEqual(txIn.hash, prevTx.getHash())
      assert.strictEqual(txIn.index, 1)
      assert.strictEqual(txIn.sequence, 54)
      assert.strictEqual(txb.__INPUTS[0].prevOutScript, scripts[1])
    })

    it('returns the input index', () => {
      assert.strictEqual(txb.addInput(txHash, 0), 0)
      assert.strictEqual(txb.addInput(txHash, 1), 1)
    })

    it('throws if SIGHASH_ALL has been used to sign any existing scriptSigs', () => {
      txb.addInput(txHash, 0)
      txb.addOutput(assethex, 1000, emptyNonce, scripts[0])
      txb.sign(0, keyPair)

      assert.throws(() => {
        txb.addInput(txHash, 0)
      }, /No, this would invalidate signatures/)
    })
  })

  describe('addOutput', () => {
    let txb
    beforeEach(() => {
      txb = new TransactionBuilder()
    })

    it('accepts an address string and value', () => {
      const { address } = payments.p2pkh({ pubkey: keyPair.publicKey })
      const vout = txb.addOutput(assethex, 1000, emptyNonce, address)
      assert.strictEqual(vout, 0)

      const txout = txb.__TX.outs[0]
      assert.deepStrictEqual(txout.script, scripts[0])
      assert.strictEqual(txout.value, 1000)
    })

    it('accepts a ScriptPubKey and value', () => {
      const vout = txb.addOutput(assethex, 1000, emptyNonce, scripts[0])
      assert.strictEqual(vout, 0)

      const txout = txb.__TX.outs[0]
      assert.deepStrictEqual(txout.script, scripts[0])
      assert.strictEqual(txout.value, 1000)
    })

    it('throws if address is of the wrong network', () => {
      assert.throws(() => {
        txb.addOutput(assethex, 1000, emptyNonce, '2NGHjvjw83pcVFgMcA7QvSMh2c246rxLVz9')
      }, /2NGHjvjw83pcVFgMcA7QvSMh2c246rxLVz9 has no matching Script/)
    })

    it('add second output after signed first input with SIGHASH_NONE', () => {
      txb.addInput(txHash, 0)
      txb.addOutput(assethex, 2000, emptyNonce, scripts[0])
      txb.sign(0, keyPair, undefined, Transaction.SIGHASH_NONE)
      assert.strictEqual(txb.addOutput(assethex, 9000, emptyNonce, scripts[1]), 1)
    })

    it('add first output after signed first input with SIGHASH_NONE', () => {
      txb.addInput(txHash, 0)
      txb.sign(0, keyPair, undefined, Transaction.SIGHASH_NONE)
      assert.strictEqual(txb.addOutput(assethex, 2000, emptyNonce, scripts[0]), 0)
    })

    it('add second output after signed first input with SIGHASH_SINGLE', () => {
      txb.addInput(txHash, 0)
      txb.addOutput(assethex, 2000, emptyNonce, scripts[0])
      txb.sign(0, keyPair, undefined, Transaction.SIGHASH_SINGLE)
      assert.strictEqual(txb.addOutput(assethex, 9000, emptyNonce, scripts[1]), 1)
    })

    it('add first output after signed first input with SIGHASH_SINGLE', () => {
      txb.addInput(txHash, 0)
      txb.sign(0, keyPair, undefined, Transaction.SIGHASH_SINGLE)
      assert.throws(() => {
        txb.addOutput(assethex, 2000, emptyNonce, scripts[0])
      }, /No, this would invalidate signatures/)
    })

    it('throws if SIGHASH_ALL has been used to sign any existing scriptSigs', () => {
      txb.addInput(txHash, 0)
      txb.addOutput(assethex, 2000, emptyNonce, scripts[0])
      txb.sign(0, keyPair)

      assert.throws(() => {
        txb.addOutput(assethex, 9000, emptyNonce, scripts[1])
      }, /No, this would invalidate signatures/)
    })
  })

  describe('setLockTime', () => {
    it('throws if if there exist any scriptSigs', () => {
      const txb = new TransactionBuilder()
      txb.addInput(txHash, 0)
      txb.addOutput(assethex, 100, emptyNonce, scripts[0])
      txb.sign(0, keyPair)

      assert.throws(() => {
        txb.setLockTime(65535)
      }, /No, this would invalidate signatures/)
    })
  })

  describe('sign', () => {
    it('supports the alternative abstract interface { publicKey, sign }', () => {
      const keyPair = {
        publicKey: ECPair.makeRandom({ rng: () => { return Buffer.alloc(32, 1) } }).publicKey,
        sign: hash => { return Buffer.alloc(64, 0x5f) }
      }

      const txb = new TransactionBuilder()
      txb.setVersion(1)
      txb.addInput('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1)
      txb.addOutput(assethex, 100000, emptyNonce, '1111111111111111111114oLvT2')
      txb.sign(0, keyPair)
      assert.strictEqual(txb.build().toHex(), '010000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000006a47304402205f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f02205f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff01a0860100000000001976a914000000000000000000000000000000000000000088ace44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d00000000')
    })

    it('supports low R signature signing', () => {
      let txb = new TransactionBuilder()
      txb.setVersion(1)
      txb.addInput('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1)
      txb.addOutput(assethex, 100000, emptyNonce, '1111111111111111111114oLvT2')
      txb.sign(0, keyPair)
      // high R
      assert.strictEqual(txb.build().toHex(), '010000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000006a473044022067ac145ee9cbf7c512aea4b5a35957965a61fbe376451a0eee06ce71ea4eaf600220503e6cca17d38fd8028543c65136c8d1f75307e4fd897e3f3557c4cd4731d5ad01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff01a0860100000000001976a914000000000000000000000000000000000000000088ace44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d00000000')

      txb = new TransactionBuilder()
      txb.setVersion(1)
      txb.addInput('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 1)
      txb.addOutput(assethex, 100000, emptyNonce, '1111111111111111111114oLvT2')
      txb.setLowR()
      txb.sign(0, keyPair)
      // low R
      assert.strictEqual(txb.build().toHex(), '010000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000006a473044022067ac145ee9cbf7c512aea4b5a35957965a61fbe376451a0eee06ce71ea4eaf600220503e6cca17d38fd8028543c65136c8d1f75307e4fd897e3f3557c4cd4731d5ad01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff01a0860100000000001976a914000000000000000000000000000000000000000088ace44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d00000000')
    })

    fixtures.invalid.sign.forEach(f => {
      it('throws ' + f.exception + (f.description ? ' (' + f.description + ')' : ''), () => {
        const txb = construct(f, true)

        let threw = false
        f.inputs.forEach((input, index) => {
          input.signs.forEach(sign => {
            const keyPairNetwork = NETWORKS[sign.network || f.network]
            const keyPair2 = ECPair.fromWIF(sign.keyPair, keyPairNetwork)
            let redeemScript

            if (sign.redeemScript) {
              redeemScript = bscript.fromASM(sign.redeemScript)
            }

            if (sign.throws) {
              assert.throws(() => {
                txb.sign(index, keyPair2, redeemScript, sign.hashType, sign.value)
              }, new RegExp(f.exception))
              threw = true
            } else {
              txb.sign(index, keyPair2, redeemScript, sign.hashType, sign.value)
            }
          })
        })

        assert.strictEqual(threw, true)
      })
    })
  })

  describe('build', () => {
    fixtures.valid.build.forEach(f => {
      it('builds "' + f.description + '"', () => {
        const txb = construct(f)
        const tx = f.incomplete ? txb.buildIncomplete() : txb.build()

        assert.strictEqual(tx.toHex(), f.txHex)
      })
    })

    // TODO: remove duplicate test code
    fixtures.invalid.build.forEach(f => {
      describe('for ' + (f.description || f.exception), () => {
        it('throws ' + f.exception, () => {
          assert.throws(() => {
            let txb
            if (f.txHex) {
              txb = TransactionBuilder.fromTransaction(Transaction.fromHex(f.txHex))
            } else {
              txb = construct(f)
            }

            txb.build()
          }, new RegExp(f.exception))
        })

        // if throws on incomplete too, enforce that
        if (f.incomplete) {
          it('throws ' + f.exception, () => {
            assert.throws(() => {
              let txb
              if (f.txHex) {
                txb = TransactionBuilder.fromTransaction(Transaction.fromHex(f.txHex))
              } else {
                txb = construct(f)
              }

              txb.buildIncomplete()
            }, new RegExp(f.exception))
          })
        } else {
          it('does not throw if buildIncomplete', () => {
            let txb
            if (f.txHex) {
              txb = TransactionBuilder.fromTransaction(Transaction.fromHex(f.txHex))
            } else {
              txb = construct(f)
            }

            txb.buildIncomplete()
          })
        }
      })
    })

    it('for incomplete with 0 signatures', () => {
      const randomTxData = '01000000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ace44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d00000000'
      const randomAddress = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'

      const randomTx = Transaction.fromHex(randomTxData)
      let tx = new TransactionBuilder()
      tx.addInput(randomTx, 0)
      tx.addOutput(Buffer.from(assethex, 'hex'), 1000, emptyNonce, randomAddress)
      tx = tx.buildIncomplete()
      assert(tx)
    })

    it('for incomplete P2SH with 0 signatures', () => {
      const inp = Buffer.from('01000000000173120703f67318aef51f7251272a6816d3f7523bb25e34b136d80be959391c100000000000ffffffff0100c817a80400000017a91471a8ec07ff69c6c4fee489184c462a9b1b92374887e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d00000000', 'hex') // arbitrary P2SH input
      const inpTx = Transaction.fromBuffer(inp)

      const txb = new TransactionBuilder(NETWORKS.testnet)
      txb.addInput(inpTx, 0)
      txb.addOutput(assethex, 1e8, emptyNonce, '2NAkqp5xffoomp5RLBcakuGpZ12GU4twdz4') // arbitrary output

      txb.buildIncomplete()
    })
  })
  describe('multisig', () => {
    fixtures.valid.multisig.forEach(f => {
      it(f.description, () => {
        const network = NETWORKS[f.network]
        let txb = construct(f, true)
        let tx

        f.inputs.forEach((input, i) => {
          const redeemScript = bscript.fromASM(input.redeemScript)

          input.signs.forEach(sign => {
            // rebuild the transaction each-time after the first
            if (tx) {
              // manually override the scriptSig?
              if (sign.scriptSigBefore) {
                tx.ins[i].script = bscript.fromASM(sign.scriptSigBefore)
              }

              // rebuild
              txb = TransactionBuilder.fromTransaction(tx, network)
            }

            const keyPair2 = ECPair.fromWIF(sign.keyPair, network)
            txb.sign(i, keyPair2, redeemScript, sign.hashType)

            // update the tx
            tx = txb.buildIncomplete()

            // now verify the serialized scriptSig is as expected
            assert.strictEqual(bscript.toASM(tx.ins[i].script), sign.scriptSig)
          })
        })

        tx = txb.build()
        assert.strictEqual(tx.toHex(), f.txHex)
      })
    })
  })

  describe('various edge case', () => {
    const network = NETWORKS.testnet

    it('should handle badly pre-filled OP_0s', () => {
      // OP_0 is used where a signature is missing
      const redeemScripSig = bscript.fromASM('OP_0 OP_0 3045022100daf0f4f3339d9fbab42b098045c1e4958ee3b308f4ae17be80b63808558d0adb02202f07e3d1f79dc8da285ae0d7f68083d769c11f5621ebd9691d6b48c0d4283d7d01 52410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b84104c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a4104f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e67253ae')
      const redeemScript = bscript.fromASM('OP_2 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a 04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672 OP_3 OP_CHECKMULTISIG')

      const tx = new Transaction()
      tx.addInput(Buffer.from('cff58855426469d0ef16442ee9c644c4fb13832467bcbc3173168a7916f07149', 'hex'), 0, undefined, redeemScripSig)
      tx.addOutput(Buffer.from(assethex, 'hex'), 1000, emptyNonce, Buffer.from('76a914aa4d7985c57e011a8b3dd8e0e5a73aaef41629c588ac', 'hex'))

      // now import the Transaction
      const txb = TransactionBuilder.fromTransaction(tx, NETWORKS.testnet)

      const keyPair2 = ECPair.fromWIF('91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgx3cTMqe', network)
      txb.sign(0, keyPair2, redeemScript)

      const tx2 = txb.build()
      assert.strictEqual(tx2.getId(), 'eab59618a564e361adef6d918bd792903c3d41bcf1220137364fb847880467f9')
      assert.strictEqual(bscript.toASM(tx2.ins[0].script), 'OP_0 3045022100daf0f4f3339d9fbab42b098045c1e4958ee3b308f4ae17be80b63808558d0adb02202f07e3d1f79dc8da285ae0d7f68083d769c11f5621ebd9691d6b48c0d4283d7d01 3045022100a346c61738304eac5e7702188764d19cdf68f4466196729db096d6c87ce18cdd022018c0e8ad03054b0e7e235cda6bedecf35881d7aa7d94ff425a8ace7220f38af001 52410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b84104c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a4104f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e67253ae')
    })

    it('should not classify blank scripts as nonstandard', () => {
      let txb = new TransactionBuilder()
      txb.setVersion(1)
      txb.addInput('aa94ab02c182214f090e99a0d57021caffd0f195a81c24602b1028b130b63e31', 0)

      const incomplete = txb.buildIncomplete().toHex()
      const keyPair = ECPair.fromWIF('L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy')

      // sign, as expected
      txb.addOutput(assethex, 15000, emptyNonce, '1Gokm82v6DmtwKEB8AiVhm82hyFSsEvBDK')
      txb.sign(0, keyPair)
      const txId = txb.build().getId()
      assert.strictEqual(txId, 'bcd4e60597fe9a6fd730cbc5762e29f549e1c6d48199bf79fe8016df90016c9e')

      // and, repeat
      txb = TransactionBuilder.fromTransaction(Transaction.fromHex(incomplete))
      txb.addOutput(assethex, 15000, emptyNonce, '1Gokm82v6DmtwKEB8AiVhm82hyFSsEvBDK')
      txb.sign(0, keyPair)
      const txId2 = txb.build().getId()
      assert.strictEqual(txId, txId2)
    })
  })
})