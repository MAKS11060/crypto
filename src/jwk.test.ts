import {type KeyAlg, exportKeyRaw, importKeyRaw} from './jwk.ts'
import {generateKeyPair} from './keys.ts'

Deno.test('', async () => {
  const alg: KeyAlg = 'Ed25519'
  const keyPair = await generateKeyPair(alg)
  const keys = await exportKeyRaw(keyPair.privateKey)

  const priv = await importKeyRaw({
    alg,
    public: keys.public,
    private: keys.private,
  })
  const pub = await importKeyRaw({alg, public: keys.public})
})

