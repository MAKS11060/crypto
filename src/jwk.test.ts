import {assertEquals} from 'https://deno.land/std/assert/mod.ts'
import {exportKeyRaw, importKeyRaw, type KeyAlg} from './jwk.ts'
import {generateKeyPair} from './keys.ts'

const algs: Partial<Record<KeyAlg, {publicLen: number; privateLen: number}>> = {
  Ed25519: {publicLen: 64, privateLen: 64},
  'P-256': {publicLen: 128, privateLen: 64},
  'P-384': {publicLen: 192, privateLen: 96},
}

for (let [_alg, option] of Object.entries(algs)) {
  const alg = _alg as KeyAlg
  Deno.test(`exportKeyRaw-${alg}`, async (c) => {
    const keys = await generateKeyPair(alg)
    const key = await exportKeyRaw(keys.privateKey)
    assertEquals(key.public.length, option.publicLen)
    assertEquals(key.private.length, option.privateLen)

    await c.step(`importKeyRaw-${alg}`, async () => {
      const privateKey = await importKeyRaw({alg, ...key})
      assertEquals(privateKey.type, 'private')
      assertEquals(privateKey.usages, ['sign'])

      const {public: pub} = key
      const publicKey = await importKeyRaw({alg, public: pub})
      assertEquals(publicKey.type, 'public')
      assertEquals(publicKey.usages, ['verify'])
    })
  })
}
