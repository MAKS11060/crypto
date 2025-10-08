type JwkAlgorithmResult = {
  options: KeyAlgorithm | EcKeyAlgorithm | RsaHashedKeyGenParams | RsaPssParams | AesKeyGenParams
  keyUsage: KeyUsage[]
}

/**
 * Infers the cryptographic algorithm and key usage options from a given JSON Web Key (JWK).
 *
 * This function analyzes the provided JWK object to determine the appropriate Web Crypto API algorithm
 * parameters and key usages. It supports EC (Elliptic Curve), OKP (Octet Key Pair), and RSA key types,
 * and maps JWK properties such as `kty`, `crv`, `alg`, `key_ops`, and `use` to corresponding algorithm
 * options and usages.
 *
 * @param jwk - The JSON Web Key to analyze.
 * @returns An object containing the inferred key usages and algorithm options suitable for Web Crypto API operations.
 * @throws If the JWK is missing required properties or specifies unsupported key types, curves, or algorithms.
 */
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

    case 'oct': // AES
      if (jwk.alg?.startsWith('A')) { // A256GCM
        const length = jwk.alg.slice(1, 4) // A256GCM → 256
        const type = jwk.alg.slice(4) // A256GCM → GCM
        if (!['256', '192', '128'].includes(length)) throw new Error(`Unsupported AES length ${length}`)
        if (!['GCM', 'CBC', 'CTR', 'KW'].includes(type)) throw new Error(`Unsupported AES type ${type}`)

        return {
          keyUsage,
          options: {
            name: `AES-${type}`,
            length: +length,
          },
        }
      } else {
        throw new Error('Cannot determine AES algorithm without "alg" field')
      }

    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`)
  }
}
