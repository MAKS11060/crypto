import {jwkAlgorithm} from './jwk.ts'

Deno.test('jwkAlgorithm', async (t) => {
  const options: [any, KeyUsage[]][] = []

  // EC
  options.push([{name: 'ECDSA', namedCurve: 'P-256'}, ['sign', 'verify']])
  options.push([{name: 'ECDSA', namedCurve: 'P-384'}, ['sign', 'verify']])
  // options.push([{name: 'ECDSA', namedCurve: 'P-521'}, ['sign', 'verify']]) // DENO: not impl

  options.push([{name: 'Ed25519'}, ['sign', 'verify']])
  options.push([{name: 'X25519'}, ['deriveKey', 'deriveBits']])

  // RSA RSASSA-PKCS1-v1_5
  const hashes = [/* 'SHA-1', */ 'SHA-256', 'SHA-384', 'SHA-512']
  const publicExponent = new Uint8Array([0x01, 0x00, 0x01])
  for (let i = 0; i < 3; i++) { // 1024 2048 4096
    for (const hash of hashes) {
      options.push([
        {name: 'RSASSA-PKCS1-v1_5', modulusLength: 2 ** (10 + i), publicExponent, hash},
        ['sign', 'verify'],
      ])
    }
  }

  // RSA-PSS
  for (let i = 0; i < 3; i++) { // 1024 2048 4096
    for (const hash of hashes) {
      options.push([
        {name: 'RSA-PSS', modulusLength: 2 ** (10 + i), publicExponent, hash, saltLength: 32},
        ['sign', 'verify'],
      ])
    }
  }

  // Test
  for (const [alg, keyUsage] of options) {
    const key = await crypto.subtle.generateKey(alg, true, keyUsage)

    const testName = JSON.stringify({
      name: alg.name,
      namedCurve: alg.namedCurve,
      modulusLength: alg.modulusLength,
      hash: alg.hash,
    })
    await t.step(`importKey priv ${testName}`, async (t) => {
      const jwk = await crypto.subtle.exportKey('jwk', key.privateKey)

      const {options, keyUsage} = jwkAlgorithm(jwk)
      // console.log(options, keyUsage, jwk)
      await crypto.subtle.importKey('jwk', jwk, options, true, keyUsage)
    })

    await t.step(`importKey pub ${testName}`, async (t) => {
      const jwk = await crypto.subtle.exportKey('jwk', key.publicKey)

      const {options, keyUsage} = jwkAlgorithm(jwk)
      // console.log(options, keyUsage)
      await crypto.subtle.importKey('jwk', jwk, options, true, keyUsage)
    })
  }
})
