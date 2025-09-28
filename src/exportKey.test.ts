import {expect} from 'jsr:@std/expect/expect'
import {exportKey} from './exportKey.ts'
import {importKey} from './importKey.ts'
import {generateKeyPair} from './keys.ts'
import {KeyAlg} from './utils.ts'

Deno.test('exportKey', async (t) => {
  const algs: KeyAlg[] = [
    'Ed25519',
    'X25519',
    'P-256',
    'ES256',
    'P-384',
    'ES384',
    // 'P-521', // DENO: not supported
    // 'ES512',
  ]

  for (const alg of algs) {
    const {privateKey, publicKey} = await generateKeyPair(alg)

    // export
    await t.step(`exportKey raw ${alg}`, async (t) => {
      expect(await exportKey('raw', privateKey)).toBeInstanceOf(Uint8Array)
      expect(await exportKey('raw', publicKey)).toBeInstanceOf(Uint8Array)
    })

    await t.step(`exportKey hex ${alg}`, async (t) => {
      expect(typeof await exportKey('hex', privateKey)).toEqual('string')
      expect(typeof await exportKey('hex', publicKey)).toEqual('string')
    })

    await t.step(`exportKey jwk ${alg}`, async (t) => {
      const a = await exportKey('jwk', privateKey)
      const b = await exportKey('jwk', publicKey)

      expect(a.kty).toBeTruthy()
      expect(a.x).toBeTruthy()
      expect(a.d).toBeTruthy()
      expect(a.key_ops).toBeTruthy()

      expect(b.kty).toBeTruthy()
      expect(b.x).toBeTruthy()
      expect(b.d).toBeUndefined()
      expect(b.key_ops).toBeTruthy()
    })

    // export pair
    await t.step(`exportKey pair raw ${alg}`, async (t) => {
      const {privateKey: a, publicKey: b} = await exportKey('raw', {publicKey, privateKey})
      expect(a).toBeInstanceOf(Uint8Array)
      expect(b).toBeInstanceOf(Uint8Array)
    })

    await t.step(`exportKey pair hex ${alg}`, async (t) => {
      const {privateKey: a, publicKey: b} = await exportKey('hex', {publicKey, privateKey})
      expect(typeof a).toEqual('string')
      expect(typeof b).toEqual('string')
    })

    await t.step(`exportKey pair jwk ${alg}`, async (t) => {
      const {privateKey: a, publicKey: b} = await exportKey('jwk', {publicKey, privateKey})

      expect(a.kty).toBeTruthy()
      expect(a.x).toBeTruthy()
      expect(a.d).toBeTruthy()
      expect(a.key_ops).toBeTruthy()

      expect(b.kty).toBeTruthy()
      expect(b.x).toBeTruthy()
      expect(b.d).toBeUndefined()
      expect(b.key_ops).toBeTruthy()
    })

    // import
    await t.step(`import raw ${alg}`, async (t) => {
      const a = await exportKey('raw', privateKey)
      const b = await exportKey('raw', publicKey)

      await importKey('raw', {alg, publicKey: b, privateKey: a})
      await importKey('raw', {alg, publicKey: b})
    })

    await t.step(`import hex ${alg}`, async (t) => {
      const a = await exportKey('hex', privateKey)
      const b = await exportKey('hex', publicKey)

      await importKey('hex', {alg, publicKey: b, privateKey: a})
      await importKey('hex', {alg, publicKey: b})
    })

    await t.step(`import jwk ${alg}`, async (t) => {
      const a = await exportKey('jwk', privateKey)
      const b = await exportKey('jwk', publicKey)

      await importKey('jwk', a)
      await importKey('jwk', b)
    })
  }
})
