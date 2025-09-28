import {exportKey} from './src/exportKey.ts'
import {importKey} from './src/importKey.ts'
import {generateKeyPair} from './src/keys.ts'

Deno.test('Test 265816', async (t) => {
  const {privateKey, publicKey} = await generateKeyPair('X25519')
  console.log(
    await crypto.subtle.exportKey('jwk', privateKey),
    await crypto.subtle.exportKey('jwk', publicKey),
  )
})

Deno.test('Test 160878', async (t) => {
  const {privateKey, publicKey} = await generateKeyPair('Ed25519')
  console.log(
    await crypto.subtle.exportKey('jwk', privateKey),
    await crypto.subtle.exportKey('jwk', publicKey),
  )
})

Deno.test('Test 2123', async (t) => {
  const {privateKey, publicKey} = await generateKeyPair('Ed25519')
  console.log(await exportKey('hex', privateKey))
  console.log(await exportKey('hex', publicKey))
})

Deno.test('Test 200472', async (t) => {
  const priv: JsonWebKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: '5RHf-3e9vJtVS099LxMpFXOpgfo8JQACp6dt-thyS3A',
    key_ops: ['sign'],
    ext: true,
    d: 'wKeqNFkpRKLck4TaPDE0nLjQeuk40Ee_lycMeVzNgNA',
  }
  const pub: JsonWebKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: '5RHf-3e9vJtVS099LxMpFXOpgfo8JQACp6dt-thyS3A',
    key_ops: ['verify'],
    ext: true,
    alg: '',
  }

  await importKey('jwk', priv)
  await importKey('jwk', pub)
})
