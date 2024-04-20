import {assertEquals} from 'https://deno.land/std/assert/mod.ts'
import {exportKeyRaw, importKeyRaw, type KeyAlg} from './jwk.ts'
import {generateKeyPair} from './keys.ts'

Deno.test('export/import Ed25519', async () => {
  const alg: KeyAlg = 'Ed25519'
  const keyPair = await generateKeyPair(alg)

  const keys = await exportKeyRaw(keyPair.privateKey) // to raw

  const priv = await importKeyRaw({
    alg,
    public: keys.public,
    private: keys.private,
  })
  const pub = await importKeyRaw({
    alg,
    public: keys.public,
  })

  assertEquals(priv.type, 'private')
  assertEquals(priv.usages, ['sign'])

  assertEquals(pub.type, 'public')
  assertEquals(pub.usages, ['verify'])
})

Deno.test('export/import P-256', async () => {
  const alg: KeyAlg = 'P-256'
  const keyPair = await generateKeyPair(alg)

  const keys = await exportKeyRaw(keyPair.privateKey) // to raw

  const priv = await importKeyRaw({
    alg,
    public: keys.public,
    private: keys.private,
  })
  const pub = await importKeyRaw({
    alg,
    public: keys.public,
  })

  assertEquals(priv.type, 'private')
  assertEquals(priv.usages, ['sign'])

  assertEquals(pub.type, 'public')
  assertEquals(pub.usages, ['verify'])
})
