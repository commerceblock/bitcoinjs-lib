const { describe, it, beforeEach } = require('mocha')
const assert = require('assert')
const bscript = require('../src/script')
const fixtures = require('./fixtures/transaction')
const Transaction = require('..').Transaction
const BufferUtils = require('../src/bufferutils')

const emptyNonce = Buffer.from('00', 'hex');

describe('Transaction', () => {
  function fromRaw (raw) {
    const tx = new Transaction()
    tx.version = raw.version
    tx.locktime = raw.locktime

    raw.ins.forEach((txIn, i) => {
      const txHash = Buffer.from(txIn.hash, 'hex')
      let scriptSig

      if (txIn.data) {
        scriptSig = Buffer.from(txIn.data, 'hex')
      } else if (txIn.script) {
        scriptSig = bscript.fromASM(txIn.script)
      }

      tx.addInput(txHash, txIn.index, txIn.sequence, scriptSig)
    })

    raw.outs.forEach(txOut => {
      let script

      if (txOut.data) {
        script = Buffer.from(txOut.data, 'hex')
      } else if (txOut.script) {
        script = bscript.fromASM(txOut.script)
      }

      let value
      const numToBuffer = Buffer.alloc(8);

      if (txOut.value) {
        numToBuffer.writeUInt32LE(txOut.value, 0);
        value = Buffer.concat([
          Buffer.from('01', 'hex'),
          BufferUtils.reverseBuffer(numToBuffer),
        ]);
      }

      tx.addOutput(Buffer.from(txOut.asset, 'hex'), value, Buffer.from(txOut.nonce, 'hex'), script)
    })

    return tx
  }

  describe('fromBuffer/fromHex', () => {
    function importExport (f) {
      const id = f.id || f.hash
      const txHex = f.hex || f.txHex

      it('imports ' + f.description + ' (' + id + ')', () => {
        const actual = Transaction.fromHex(txHex)

        assert.strictEqual(actual.toHex(), txHex)
      })
    }

    fixtures.valid.forEach(importExport)
    fixtures.hashForSignature.forEach(importExport)

    fixtures.invalid.fromBuffer.forEach(f => {
      it('throws on ' + f.exception, () => {
        assert.throws(() => {
          Transaction.fromHex(f.hex)
        }, new RegExp(f.exception))
      })
    })

    it('.version should be interpreted as an int32le', () => {
      const txHex = 'ffffffff000000ffffffff'
      const tx = Transaction.fromHex(txHex)
      assert.strictEqual(-1, tx.version)
      assert.strictEqual(0xffffffff, tx.locktime)
    })
  })

  describe('toBuffer/toHex', () => {
    fixtures.valid.forEach(f => {
      it('exports ' + f.description + ' (' + f.id + ')', () => {
        const actual = fromRaw(f.raw)
        assert.strictEqual(actual.toHex(), f.hex)
      })
    })

    it('accepts target Buffer and offset parameters', () => {
      const f = fixtures.valid[0]
      const actual = fromRaw(f.raw)
      const byteLength = actual.byteLength()

      const target = Buffer.alloc(byteLength * 2)
      const a = actual.toBuffer(target, 0)
      const b = actual.toBuffer(target, byteLength)

      assert.strictEqual(a.length, byteLength)
      assert.strictEqual(b.length, byteLength)
      assert.strictEqual(a.toString('hex'), f.hex)
      assert.strictEqual(b.toString('hex'), f.hex)
      assert.deepStrictEqual(a, b)
      assert.deepStrictEqual(a, target.slice(0, byteLength))
      assert.deepStrictEqual(b, target.slice(byteLength))
    })
  })

  describe('weight/virtualSize', () => {
    it('computes virtual size', () => {
      fixtures.valid.forEach(f => {
        const transaction = Transaction.fromHex(f.hex)

        assert.strictEqual(transaction.virtualSize(), f.virtualSize)
      })
    })

    it('computes weight', () => {
      fixtures.valid.forEach(f => {
        const transaction = Transaction.fromHex(f.hex)

        assert.strictEqual(transaction.weight(), f.weight)
      })
    })
  })

  describe('addInput', () => {
    let prevTxHash
    beforeEach(() => {
      prevTxHash = Buffer.from('ffffffff00ffff000000000000000000000000000000000000000000101010ff', 'hex')
    })

    it('returns an index', () => {
      const tx = new Transaction()
      assert.strictEqual(tx.addInput(prevTxHash, 0), 0)
      assert.strictEqual(tx.addInput(prevTxHash, 0), 1)
    })

    it('defaults to empty script, 0xffffffff SEQUENCE number', () => {
      const tx = new Transaction()
      tx.addInput(prevTxHash, 0)

      assert.strictEqual(tx.ins[0].script.length, 0)
      assert.strictEqual(tx.ins[0].sequence, 0xffffffff)
    })

    fixtures.invalid.addInput.forEach(f => {
      it('throws on ' + f.exception, () => {
        const tx = new Transaction()
        const hash = Buffer.from(f.hash, 'hex')

        assert.throws(() => {
          tx.addInput(hash, f.index)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('addOutput', () => {
    it('returns an index', () => {
      const tx = new Transaction()
      assert.strictEqual(tx.addOutput(Buffer.from('01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d', 'hex'), Buffer.alloc(1), Buffer.alloc(1), Buffer.alloc(0)), 0)
      assert.strictEqual(tx.addOutput(Buffer.from('01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d', 'hex'), Buffer.alloc(1), Buffer.alloc(1), Buffer.alloc(0)), 1)
    })
  })

  describe('clone', () => {
    fixtures.valid.forEach(f => {
      let actual
      let expected

      beforeEach(() => {
        expected = Transaction.fromHex(f.hex)
        actual = expected.clone()
      })

      it('should have value equality', () => {
        assert.deepStrictEqual(actual, expected)
      })

      it('should not have reference equality', () => {
        assert.notStrictEqual(actual, expected)
      })
    })
  })

  describe('getHash/getId', () => {
    function verify (f) {
      it('should return the id for ' + f.id + '(' + f.description + ')', () => {
        const tx = Transaction.fromHex(f.hex)

        assert.strictEqual(tx.getHash().toString('hex'), f.hash)
        assert.strictEqual(tx.getId(), f.id)
      })
    }

    fixtures.valid.forEach(verify)
  })

  describe('isCoinbase', () => {
    function verify (f) {
      it('should return ' + f.coinbase + ' for ' + f.id + '(' + f.description + ')', () => {
        const tx = Transaction.fromHex(f.hex)

        assert.strictEqual(tx.isCoinbase(), f.coinbase)
      })
    }

    fixtures.valid.forEach(verify)
  })

  describe('hashForSignature', () => {
    it('does not use Witness serialization', () => {
      const randScript = Buffer.from('6a', 'hex')

      const tx = new Transaction()
      tx.addInput(Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 0)
      tx.addOutput(Buffer.from('01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d', 'hex'), Buffer.from('010000000050000000', 'hex'), emptyNonce, randScript)

      const original = tx.__toBuffer
      tx.__toBuffer = (a, b, c) => {
        if (c !== false) throw new Error('hashForSignature MUST pass false')

        return original.call(this, a, b, c)
      }

      assert.throws(() => {
        tx.__toBuffer(undefined, undefined, true)
      }, /hashForSignature MUST pass false/)

      // assert hashForSignature does not pass false
      assert.doesNotThrow(() => {
        tx.hashForSignature(0, randScript, 1)
      })
    })

    fixtures.hashForSignature.forEach(f => {
      it('should return ' + f.hash + ' for ' + (f.description ? ('case "' + f.description + '"') : f.script), () => {
        const tx = Transaction.fromHex(f.txHex)
        const script = bscript.fromASM(f.script)

        assert.strictEqual(tx.hashForSignature(f.inIndex, script, f.type).toString('hex'), f.hash)
      })
    })
  })
})
