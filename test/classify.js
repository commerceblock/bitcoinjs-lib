const { describe, it } = require('mocha')
const assert = require('assert')
const bscript = require('../src/script')
const classify = require('../src/classify')

const fixtures = require('./fixtures/templates.json')

const multisig = require('../src/templates/multisig')
const nullData = require('../src/templates/nulldata')
const pubKey = require('../src/templates/pubkey')
const pubKeyHash = require('../src/templates/pubkeyhash')
const scriptHash = require('../src/templates/scripthash')

const tmap = {
  pubKey,
  pubKeyHash,
  scriptHash,
  multisig,
  nullData
}

describe('classify', () => {
  describe('input', () => {
    fixtures.valid.forEach(f => {
      if (!f.input) return

      it('classifies ' + f.input + ' as ' + f.type, () => {
        const input = bscript.fromASM(f.input)
        const type = classify.input(input)

        assert.strictEqual(type, f.type)
      })
    })

    fixtures.valid.forEach(f => {
      if (!f.input) return
      if (!f.typeIncomplete) return

      it('classifies incomplete ' + f.input + ' as ' + f.typeIncomplete, () => {
        const input = bscript.fromASM(f.input)
        const type = classify.input(input, true)

        assert.strictEqual(type, f.typeIncomplete)
      })
    })
  })

  describe('classifyOutput', () => {
    fixtures.valid.forEach(f => {
      if (!f.output) return

      it('classifies ' + f.output + ' as ' + f.type, () => {
        const output = bscript.fromASM(f.output)
        const type = classify.output(output)

        assert.strictEqual(type, f.type)
      })
    })
  })

  ;[
    'pubKey',
    'pubKeyHash',
    'scriptHash',
    'multisig',
    'nullData'
  ].forEach(name => {
    const inputType = tmap[name].input
    const outputType = tmap[name].output

    describe(name + '.input.check', () => {
      fixtures.valid.forEach(f => {
        const expected = name.toLowerCase() === f.type.toLowerCase()

        if (inputType && f.input) {
          const input = bscript.fromASM(f.input)

          it('returns ' + expected + ' for ' + f.input, () => {
            assert.strictEqual(inputType.check(input), expected)
          })

          if (f.typeIncomplete) {
            const expectedIncomplete = name.toLowerCase() === f.typeIncomplete

            it('returns ' + expected + ' for ' + f.input, () => {
              assert.strictEqual(inputType.check(input, true), expectedIncomplete)
            })
          }
        }
      })

      if (!(fixtures.invalid[name])) return

      fixtures.invalid[name].inputs.forEach(f => {
        if (!f.input && !f.inputHex) return

        it('returns false for ' + f.description + ' (' + (f.input || f.inputHex) + ')', () => {
          let input

          if (f.input) {
            input = bscript.fromASM(f.input)
          } else {
            input = Buffer.from(f.inputHex, 'hex')
          }

          assert.strictEqual(inputType.check(input), false)
        })
      })
    })

    describe(name + '.output.check', () => {
      fixtures.valid.forEach(f => {
        const expected = name.toLowerCase() === f.type

        if (outputType && f.output) {
          it('returns ' + expected + ' for ' + f.output, () => {
            const output = bscript.fromASM(f.output)

            assert.strictEqual(outputType.check(output), expected)
          })
        }
      })

      if (!(fixtures.invalid[name])) return

      fixtures.invalid[name].outputs.forEach(f => {
        if (!f.output && !f.outputHex) return

        it('returns false for ' + f.description + ' (' + (f.output || f.outputHex) + ')', () => {
          let output

          if (f.output) {
            output = bscript.fromASM(f.output)
          } else {
            output = Buffer.from(f.outputHex, 'hex')
          }

          assert.strictEqual(outputType.check(output), false)
        })
      })
    })
  })
})
