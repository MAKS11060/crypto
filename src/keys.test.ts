import {assertEquals} from 'https://deno.land/std/assert/mod.ts'
import {generateKeyPair} from './keys.ts'

Deno.test('generateKeyPair', async () => {
  const keys = await generateKeyPair('Ed25519')

  assertEquals(keys.privateKey.type, 'private')
  assertEquals(keys.privateKey.extractable, true)
  assertEquals(keys.privateKey.algorithm.name, 'Ed25519')
  assertEquals(keys.privateKey.usages, ['sign'])

  assertEquals(keys.publicKey.type, 'public')
  assertEquals(keys.publicKey.extractable, true)
  assertEquals(keys.publicKey.algorithm.name, 'Ed25519')
  assertEquals(keys.publicKey.usages, ['verify'])
})

Deno.test('generateKeyPair P-256', async () => {
  const keys = await generateKeyPair('P-256')

  assertEquals(keys.privateKey.type, 'private')
  assertEquals(keys.privateKey.extractable, true)
  assertEquals(keys.privateKey.algorithm.name, 'ECDSA')
  assertEquals(keys.privateKey.usages, ['sign'])

  assertEquals(keys.publicKey.type, 'public')
  assertEquals(keys.publicKey.extractable, true)
  assertEquals(keys.publicKey.algorithm.name, 'ECDSA')
  assertEquals(keys.publicKey.usages, ['verify'])
})
