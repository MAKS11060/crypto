import {exportKey, importKey} from '@maks11060/crypto'
import {aesCodec, aesEncrypt, deriveKey, exportSecret, generateAesSecret, importSecret} from '@maks11060/crypto/aes'
import {expect} from 'jsr:@std/expect/expect'

Deno.test('AES gen/export(jwk)/import(jwk)', async (t) => {
  for (const name of [`AES-GCM`, `AES-CBC`, `AES-CTR`, `AES-KW`] as const) {
    for (const length of [128, 192, 256] as const) {
      await t.step(`generateAesSecret() ${name} ${length}`, async (t) => {
        const secret = await generateAesSecret({name, length})
        expect(secret.type).toBe('secret')

        await t.step(`exportKey() jwk ${name} ${length}`, async (t) => {
          const jwk = await exportKey('jwk', secret)
          await t.step(`importKey() jwk ${name} ${length}`, async (t) => {
            const imported = await importKey('jwk', jwk, true)
            expect(imported).toEqual(secret)
          })
        })
      })
    }
  }
})

Deno.test('Test 992404', async (t) => {
  for (const name of [`AES-GCM`, `AES-CBC`, `AES-CTR`, `AES-KW`] as const) {
    for (const length of [128, 192, 256] as const) {
      const secret = await generateAesSecret({name, length})

      const raw = await exportSecret('raw', secret)
      expect(raw.byteLength).toBe(length / 8)

      const hex = await exportSecret('hex', secret)
      expect(typeof hex === 'string').toBeTruthy()

      const base64url = await exportSecret('base64url', secret)
      expect(typeof base64url === 'string').toBeTruthy()

      //
      await importSecret('raw', {name, length, extractable: true}, raw)
      await importSecret('hex', {name, length, extractable: true}, hex)
      await importSecret('base64url', {name, length, extractable: true}, base64url)
    }
  }
})

Deno.test('Test 159524', async (t) => {
  const aes128 = await importSecret('raw', {name: 'AES-GCM', length: 128, extractable: true}, new Uint8Array(16))
  const aes192 = await importSecret('raw', {name: 'AES-GCM', length: 192, extractable: true}, new Uint8Array(24))
  const aes256 = await importSecret('raw', {name: 'AES-GCM', length: 256, extractable: true}, new Uint8Array(32))
  expect(await exportSecret('raw', aes128)).toEqual(new Uint8Array(16))
  expect(await exportSecret('raw', aes192)).toEqual(new Uint8Array(24))
  expect(await exportSecret('raw', aes256)).toEqual(new Uint8Array(32))
})

Deno.test('deriveKey', async (t) => {
  const key = await deriveKey('secret')
  // console.log(await crypto.subtle.exportKey('jwk', key))
})

//
Deno.test('initAesEncrypt', async (t) => {
  const key = await deriveKey('secret')
  // const aes = initAesEncrypt(key, aesCodec.base64)
  const aes = aesEncrypt(key, aesCodec.base64url)
  // const aes = initAesEncrypt(key, aesCodec.hex)

  const enc = await aes.encryptJson('1234')
  const dec = await aes.decryptJson(enc)
  // console.log({enc, dec})
  expect(dec).toBe('1234')
})
