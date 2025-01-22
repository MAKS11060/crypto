import {assertEquals} from 'jsr:@std/assert'
import {generateKeyPair} from './keys.ts'

Deno.test({
  name: 'GenerateKey ECDSA',
  fn: async (t) => {
    for (const alg of ['P-256', 'P-384', 'P-521'] as const) {
      await t.step({
        name: `alg ${alg}`,
        ignore: 'Deno' in globalThis && alg === 'P-521',
        fn: async (t) => {
          const {privateKey, publicKey} = await generateKeyPair(alg)

          assertEquals(privateKey.type, 'private')
          assertEquals(privateKey.extractable, true)
          assertEquals(privateKey.algorithm.name, 'ECDSA')
          assertEquals(privateKey.usages, ['sign'])

          assertEquals(publicKey.type, 'public')
          assertEquals(publicKey.extractable, true)
          assertEquals(publicKey.algorithm.name, 'ECDSA')
          assertEquals(publicKey.usages, ['verify'])
        },
      })
    }
  },
})

Deno.test('generateKeyPair Ed25519', async () => {
  const {privateKey, publicKey} = await generateKeyPair('Ed25519')

  assertEquals(privateKey.type, 'private')
  assertEquals(privateKey.extractable, true)
  assertEquals(privateKey.algorithm.name, 'Ed25519')
  assertEquals(privateKey.usages, ['sign'])

  assertEquals(publicKey.type, 'public')
  assertEquals(publicKey.extractable, true)
  assertEquals(publicKey.algorithm.name, 'Ed25519')
  assertEquals(publicKey.usages, ['verify'])
})

Deno.test('generateKeyPair X25519', async () => {
  const {privateKey, publicKey} = await generateKeyPair('X25519')

  assertEquals(privateKey.type, 'private')
  assertEquals(privateKey.extractable, true)
  assertEquals(privateKey.algorithm.name, 'X25519')
  assertEquals(privateKey.usages, ['deriveKey'])

  assertEquals(publicKey.type, 'public')
  assertEquals(publicKey.extractable, true)
  assertEquals(publicKey.algorithm.name, 'X25519')
  assertEquals(publicKey.usages, [])
})
