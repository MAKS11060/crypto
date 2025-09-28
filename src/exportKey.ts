import {concat} from '@std/bytes/concat'
import {decodeBase64Url} from '@std/encoding/base64url'
import {encodeHex} from '@std/encoding/hex'
import {isPair, type Uint8Array_} from './utils.ts'

type ExportKey = {
  (format: 'hex', key: CryptoKey): Promise<string>
  (format: 'raw', key: CryptoKey): Promise<Uint8Array_>
  (format: 'jwk', key: CryptoKey): Promise<JsonWebKey>

  (format: 'hex', key: CryptoKeyPair): Promise<{
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
 * Exports a cryptographic key in the specified format.
 *
 * @example
 * ```ts
 * import {exportKey, generateKeyPair} from '@maks11060/crypto'
 *
 * const keys = await generateKeyPair('Ed25519')
 *
 * const {privateKey, publicKey} = await exportKey('hex', keys)
 * console.log(privateKey) // e6cc65db53dcdce37d095c5bd792a5114e8ca575190979dfaea1afa6da1daef9
 * console.log(publicKey) // b504196a380c1dcb0526c88df4f947b8d8e32f3e7a5ac57d852f439fc4fc80bc
 * ```
 *
 * @param format - The `format` to export the key in. Can be `hex`, `raw`, or `jwk`.
 * @param key - The cryptographic key to export.
 * @returns A promise that resolves to the exported key in the specified `format`.
 */
export const exportKey: ExportKey = async (
  format: 'jwk' | 'raw' | 'hex',
  key: CryptoKey | CryptoKeyPair,
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
    if (format === 'raw' || format === 'hex') {
      const raw = key.type === 'private' //
        ? decodeBase64Url(jwk.d!)
        : concat([decodeBase64Url(jwk.x!), decodeBase64Url(jwk.y!)]) // xy

      return format === 'raw' ? raw : encodeHex(raw)
    }
  }

  if (key.algorithm.name === 'Ed25519' || key.algorithm.name === 'X25519') {
    const jwk = await crypto.subtle.exportKey('jwk', key)
    if (format === 'jwk') return jwk
    if (format === 'raw' || format === 'hex') {
      const raw = key.type === 'private' //
        ? decodeBase64Url(jwk.d!)
        : decodeBase64Url(jwk.x!)

      return format === 'raw' ? raw : encodeHex(raw)
    }
  }

  if (key.algorithm.name === 'RSASSA-PKCS1-v1_5') {
    if (format !== 'jwk') throw new Error(`The key export with the RSA algorithm is supported only in jwk format`)
    return await crypto.subtle.exportKey('jwk', key)
  }

  throw new Error(`key algorithm not supported: '${key.algorithm.name}'`)
}
