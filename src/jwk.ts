type JwkAlgorithmResult = {
  options: KeyAlgorithm | EcKeyAlgorithm | RsaHashedKeyGenParams | RsaPssParams
  keyUsage: KeyUsage[]
}

export const jwkAlgorithm = (jwk: JsonWebKey): JwkAlgorithmResult => {
  const keyUsage: KeyUsage[] = []

  if (jwk.key_ops) {
    for (const op of jwk.key_ops) {
      if (op === 'sign') keyUsage.push(op)
      else if (op === 'verify') keyUsage.push(op)
      else if (op === 'encrypt') keyUsage.push(op)
      else if (op === 'decrypt') keyUsage.push(op)
      else if (op === 'wrapKey') keyUsage.push(op)
      else if (op === 'unwrapKey') keyUsage.push(op)
      else if (op === 'deriveKey') keyUsage.push(op)
      else if (op === 'deriveBits') keyUsage.push(op)
    }
  } else if (jwk.use) {
    if (jwk.use === 'sig') {
      keyUsage.push('sign', 'verify')
    } else if (jwk.use === 'enc') {
      keyUsage.push('encrypt', 'decrypt', 'wrapKey', 'unwrapKey')
    }
  }

  // Detect by kty + crv + alg
  switch (jwk.kty) {
    case 'EC':
      if (!jwk.crv) throw new Error('Missing curve (crv) in EC key')

      switch (jwk.crv) {
        case 'P-256':
        case 'P-384':
        case 'P-521':
          return {keyUsage, options: {name: 'ECDSA', namedCurve: jwk.crv}}
        default:
          throw new Error(`Unsupported EC curve: ${jwk.crv}`)
      }
      break

    case 'OKP':
      if (!jwk.crv) throw new Error('Missing curve (crv) in OKP key')

      switch (jwk.crv) {
        case 'Ed25519':
          return {keyUsage, options: {name: 'Ed25519'}}
        case 'X25519':
          return {keyUsage, options: {name: 'X25519'}}
        default:
          throw new Error(`Unsupported OKP curve: ${jwk.crv}`)
      }

    case 'RSA':
      if (jwk.alg?.startsWith('RS') || jwk.alg?.startsWith('PS')) {
        const hash = jwk.alg.slice(2) // RS256 → 256
        const hashName = `SHA-${hash}`

        // PKCS#1 v1.5 or PSS
        if (['RS1', 'RS256', 'RS384', 'RS512'].includes(jwk.alg)) {
          return {keyUsage, options: {name: 'RSASSA-PKCS1-v1_5', hash: {name: hashName}}}
        } else if (['PS256', 'PS384', 'PS512'].includes(jwk.alg)) {
          return {
            keyUsage,
            options: {name: 'RSA-PSS', hash: {name: hashName} /* saltLength: 32 */},
          }
        } else {
          throw new Error(`Unsupported RSA algorithm: ${jwk.alg}`)
        }
      } else {
        throw new Error('Cannot determine RSA algorithm without "alg" field')
      }

    // case 'oct': // TODO
    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`)
  }
}

Deno.test('Test 116903', async (t) => {
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
