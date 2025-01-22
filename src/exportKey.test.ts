import {assert} from 'jsr:@std/assert@^1.0.10/assert'
import {assertEquals} from 'jsr:@std/assert@^1.0.10/equals'
import {exportKey} from './exportKey.ts'
import {generateKeyPair} from './keys.ts'

Deno.test({
  name: 'exportKey ECDSA',
  fn: async (t) => {
    for (const alg of ['P-256', 'P-384', 'P-521'] as const) {
      await t.step({
        name: `alg ${alg}`,
        ignore: 'Deno' in globalThis && alg === 'P-521',
        fn: async () => {
          const {privateKey, publicKey} = await generateKeyPair(alg)

          // CryptoKey
          assertEquals(typeof (await exportKey('hex', privateKey)), 'string')
          assertEquals(typeof (await exportKey('hex', publicKey)), 'string')

          assert((await exportKey('raw', privateKey)) instanceof Uint8Array)
          assert((await exportKey('raw', publicKey)) instanceof Uint8Array)

          // CryptoKeyPair
          const pairHex = await exportKey('hex', {privateKey, publicKey})
          assertEquals(typeof pairHex.privateKey, 'string')
          assertEquals(typeof pairHex.publicKey, 'string')

          const pairRaw = await exportKey('raw', {privateKey, publicKey})
          assert(pairRaw.privateKey instanceof Uint8Array)
          assert(pairRaw.publicKey instanceof Uint8Array)
        },
      })
    }
  },
})

Deno.test('exportKey Ed25519', async () => {
  const {privateKey, publicKey} = await generateKeyPair('Ed25519')

  // CryptoKey
  assertEquals(typeof (await exportKey('hex', privateKey)), 'string')
  assertEquals(typeof (await exportKey('hex', publicKey)), 'string')

  assert((await exportKey('raw', privateKey)) instanceof Uint8Array)
  assert((await exportKey('raw', publicKey)) instanceof Uint8Array)

  // CryptoKeyPair
  const pairHex = await exportKey('hex', {privateKey, publicKey})
  assertEquals(typeof pairHex.privateKey, 'string')
  assertEquals(typeof pairHex.publicKey, 'string')

  const pairRaw = await exportKey('raw', {privateKey, publicKey})
  assert(pairRaw.privateKey instanceof Uint8Array)
  assert(pairRaw.publicKey instanceof Uint8Array)
})

Deno.test('exportKey X25519', async () => {
  const {privateKey, publicKey} = await generateKeyPair('X25519')

  // CryptoKey
  assertEquals(typeof (await exportKey('hex', privateKey)), 'string')
  assertEquals(typeof (await exportKey('hex', publicKey)), 'string')

  assert((await exportKey('raw', privateKey)) instanceof Uint8Array)
  assert((await exportKey('raw', publicKey)) instanceof Uint8Array)

  // CryptoKeyPair
  const pairHex = await exportKey('hex', {privateKey, publicKey})
  assertEquals(typeof pairHex.privateKey, 'string')
  assertEquals(typeof pairHex.publicKey, 'string')

  const pairRaw = await exportKey('raw', {privateKey, publicKey})
  assert(pairRaw.privateKey instanceof Uint8Array)
  assert(pairRaw.publicKey instanceof Uint8Array)
})
