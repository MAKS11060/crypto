import {concat} from '@std/bytes/concat'
import {decodeBase64Url, encodeBase64Url} from '@std/encoding/base64url'
import {encodeHex} from '@std/encoding/hex'
import {isPair, type Uint8Array_} from './utils.ts'

type ExportKey = {
  (format: 'hex' | 'base64url', key: CryptoKey): Promise<string>
  (format: 'raw', key: CryptoKey): Promise<Uint8Array_>
  (format: 'jwk', key: CryptoKey): Promise<JsonWebKey>

  (format: 'hex' | 'base64url', key: CryptoKeyPair): Promise<{
    privateKey: string
    publicKey: string
  }>
  (format: 'raw', key: CryptoKeyPair): Promise<{
    privateKey: Uint8Array_
    publicKey: Uint8Array_
  }>
  (format: 'jwk', key: CryptoKeyPair): Promise<{
    privateKey: JsonWebKey
    publicKey: JsonWebKey
  }>
}

/**
 * Exports a cryptographic key or key pair in the specified format.
 *
 * Supported formats:
 * - `'hex'` — returns a hexadecimal string (or an object with such strings for key pairs)
 * - `'base64url'` — returns a base64url string (or an object with such strings for key pairs)
 * - `'raw'` — returns a {@linkcode Uint8Array} (or an object with such arrays for key pairs)
 * - `'jwk'` — returns a JsonWebKey object (or an object with such objects for key pairs)
 *
 * Supported algorithms:
 * - Ed25519, X25519
 * - ECDSA (P-256, P-384, P-521)
 * - RSASSA-PKCS1-v1_5 (only 'jwk' format)
 *
 * @example
 * ```ts
 * import {exportKey, generateKeyPair} from '@maks11060/crypto'
 *
 * const keys = await generateKeyPair('Ed25519')
 * const {privateKey, publicKey} = await exportKey('hex', keys)
 * console.log(privateKey) // hex string of the private key
 * console.log(publicKey)  // hex string of the public key
 * ```
 *
 * @param format The export format: 'hex', 'base64url', 'raw', or 'jwk'.
 * @param key The key or key pair to export.
 * @returns A promise that resolves to the exported key or key pair in the specified format.
 * @throws If the key algorithm is not supported or the format is not allowed for the algorithm.
 */
export const exportKey: ExportKey = async (
  format,
  key,
): Promise<any> => {
  if (isPair(key)) {
    return {
      privateKey: await exportKey(format as any, key.privateKey),
      publicKey: await exportKey(format as any, key.publicKey),
    }
  }

  // P-256 / P-384 / P-521
  if (key.algorithm.name === 'ECDSA') {
    const jwk = await crypto.subtle.exportKey('jwk', key)
    if (format === 'jwk') return jwk
    if (format === 'raw' || format === 'hex' || format === 'base64url') {
      const raw = key.type === 'private' //
        ? decodeBase64Url(jwk.d!)
        : concat([decodeBase64Url(jwk.x!), decodeBase64Url(jwk.y!)]) // xy

      if (format === 'raw') return raw
      if (format === 'hex') return encodeHex(raw)
      if (format === 'base64url') return encodeBase64Url(raw)
    }
  }

  if (key.algorithm.name === 'Ed25519' || key.algorithm.name === 'X25519') {
    const jwk = await crypto.subtle.exportKey('jwk', key)
    if (format === 'jwk') return jwk
    if (format === 'raw' || format === 'hex' || format === 'base64url') {
      const raw = key.type === 'private' //
        ? decodeBase64Url(jwk.d!)
        : decodeBase64Url(jwk.x!)

      if (format === 'raw') return raw
      if (format === 'hex') return encodeHex(raw)
      if (format === 'base64url') return encodeBase64Url(raw)
    }
  }

  switch (key.algorithm.name) {
    // RSA
    case 'RSASSA-PKCS1-v1_5':
    // AES
    case 'AES-CBC':
    case 'AES-CTR':
    case 'AES-GCM':
    case 'AES-KW':
      if (format !== 'jwk') {
        throw new Error(`The key export with the ${key.algorithm.name} algorithm is supported only in jwk format`)
      }
      return await crypto.subtle.exportKey('jwk', key)
  }

  throw new Error(`key algorithm not supported: '${key.algorithm.name}'`)
}
