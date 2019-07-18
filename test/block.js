const { describe, it, beforeEach } = require('mocha')
const assert = require('assert')
const Block = require('..').Block

const fixtures = require('./fixtures/block')

describe('Block', () => {

  describe('calculateTarget', () => {
    fixtures.targets.forEach(f => {
      it('returns ' + f.expected + ' for 0x' + f.bits, () => {
        const bits = parseInt(f.bits, 16)

        assert.strictEqual(Block.calculateTarget(bits).toString('hex'), f.expected)
      })
    })
  })

  describe('fromBuffer/fromHex', () => {
    fixtures.valid.forEach(f => {
      it('imports ' + f.description, () => {
        const block = Block.fromHex(f.hex)

        assert.strictEqual(block.version, f.version)
        assert.strictEqual(block.prevHash.toString('hex'), f.prevHash)
        assert.strictEqual(block.merkleRoot.toString('hex'), f.merkleRoot)
        assert.strictEqual(block.timestamp, f.timestamp)
        assert.strictEqual(block.bits, f.bits)
        assert.strictEqual(block.nonce, f.nonce)
        assert.strictEqual(!block.transactions, f.hex.length === 160)
      })
    })

    fixtures.invalid.forEach(f => {
      it('throws on ' + f.exception, () => {
        assert.throws(() => {
          Block.fromHex(f.hex)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('toBuffer/toHex', () => {
    fixtures.valid.forEach(f => {
      let block

      beforeEach(() => {
        block = Block.fromHex(f.hex)
      })

      it('exports ' + f.description, () => {
        assert.strictEqual(block.toHex(true), !f.challenge ? f.hex.slice(0, 346) : f.hex.slice(0, 346 + f.challenge.length + 2))
        assert.strictEqual(block.toHex(), f.hex)
      })
    })
  })

  describe('getHash/getId', () => {
    fixtures.valid.forEach(f => {
      let block

      beforeEach(() => {
        block = Block.fromHex(f.hex)
      })

      it('returns ' + f.id + ' for ' + f.description, () => {
        assert.strictEqual(block.getHash().toString('hex'), f.hash)
        assert.strictEqual(block.getId(), f.id)
      })
    })
  })

  describe('getUTCDate', () => {
    fixtures.valid.forEach(f => {
      let block

      beforeEach(() => {
        block = Block.fromHex(f.hex)
      })

      it('returns UTC date of ' + f.id, () => {
        const utcDate = block.getUTCDate().getTime()

        assert.strictEqual(utcDate, f.timestamp * 1e3)
      })
    })
  })

  describe('calculateMerkleRoot', () => {
    it('should throw on zero-length transaction array', () => {
      assert.throws(() => {
        Block.calculateMerkleRoot([])
      }, /Cannot compute merkle root for zero transactions/)
    })

    fixtures.valid.forEach(f => {
      if (f.transactions === undefined) return

      let block

      beforeEach(() => {
        block = Block.fromHex(f.hex)
      })

      it('returns ' + f.merkleRoot + ' for ' + f.id, () => {
        assert.strictEqual(Block.calculateMerkleRoot(block.transactions).toString('hex'), f.merkleRoot)
      })
    })
  })

  describe('checkTxRoots', () => {
    fixtures.valid.forEach(f => {
      if (f.transactions === undefined) return

      let block

      beforeEach(() => {
        block = Block.fromHex(f.hex)
      })

      it('returns ' + f.valid + ' for ' + f.id, () => {
        assert.strictEqual(block.checkTxRoots(), true)
      })
    })
  })

  describe('checkProofOfWork', () => {
    fixtures.valid.forEach(f => {
      let block

      beforeEach(() => {
        block = Block.fromHex(f.hex)
      })

      it('returns ' + f.valid + ' for ' + f.id, () => {
        assert.strictEqual(block.checkProofOfWork(), f.valid)
      })
    })
  })
})
