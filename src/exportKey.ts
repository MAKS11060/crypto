#!/usr/bin/env -S deno run -A --watch-hmr

import {concat} from '@std/bytes/concat'
import {decodeBase64Url} from '@std/encoding/base64url'
import {encodeHex} from '@std/encoding/hex'
import {extractX25519PrivateKeyRaw} from './x25519.ts'

type ExportKey = {
  (format: 'hex', key: CryptoKey): Promise<string>
  (format: 'raw', key: CryptoKey): Promise<Uint8Array>
  (format: 'jwk', key: CryptoKey): Promise<JsonWebKey>

  (format: 'hex', key: CryptoKeyPair): Promise<{
    privateKey: string
    publicKey: string
  }>
  (format: 'raw', key: CryptoKeyPair): Promise<{
    privateKey: Uint8Array
    publicKey: Uint8Array
  }>
  (format: 'jwk', key: CryptoKeyPair): Promise<{
    privateKey: JsonWebKey
    publicKey: JsonWebKey
  }>
}

const isDeno = 'Deno' in globalThis

const isPair = (keys: CryptoKey | CryptoKeyPair): keys is CryptoKeyPair => {
  return 'privateKey' in keys && 'publicKey' in keys
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
 * @param {string} format - The `format` to export the key in. Can be `hex`, `raw`, or `jwk`.
 * @param {CryptoKey | CryptoKeyPair} key - The cryptographic key to export.
 * @returns {Promise<string | Uint8Array | JsonWebKey | { privateKey: string | Uint8Array | JsonWebKey, publicKey: string | Uint8Array | JsonWebKey }>} - A promise that resolves to the exported key in the specified `format`.
 */
export const exportKey: ExportKey = async (
  format: string,
  key: CryptoKey | CryptoKeyPair
): Promise<any> => {
  if (isPair(key)) {
    return {
      privateKey: await exportKey(format as any, key.privateKey),
      publicKey: await exportKey(format as any, key.publicKey),
    }
  }

  // P-256 / P-384 / P-521
  if (key.algorithm.name === 'ECDSA') {
    if (key.type === 'private') {
      const jwk = await crypto.subtle.exportKey('jwk', key)
      if (format === 'raw') return decodeBase64Url(jwk.d!)
      else if (format === 'hex') return encodeHex(decodeBase64Url(jwk.d!))
      else return jwk
    } else {
      const jwk = await crypto.subtle.exportKey('jwk', key)
      if (format === 'raw')
        return concat([decodeBase64Url(jwk.x!), decodeBase64Url(jwk.y!)]) // xy
      else if (format === 'hex')
        return encodeHex(
          concat([decodeBase64Url(jwk.x!), decodeBase64Url(jwk.y!)])
        )
      else return jwk
    }
  }

  if (key.algorithm.name === 'Ed25519') {
    const jwk = await crypto.subtle.exportKey('jwk', key)
    if (key.type === 'private') {
      if (format === 'raw') return decodeBase64Url(jwk.d!)
      else if (format === 'hex') return encodeHex(decodeBase64Url(jwk.d!))
      else return jwk
    } else {
      if (format === 'raw') return decodeBase64Url(jwk.x!)
      else if (format === 'hex') return encodeHex(decodeBase64Url(jwk.x!))
      else return jwk
    }
  }

  if (key.algorithm.name === 'X25519') {
    if (key.type === 'private') {
      // workaround
      if (isDeno) {
        const v = await crypto.subtle.exportKey('pkcs8', key)
        if (format === 'raw')
          return extractX25519PrivateKeyRaw(new Uint8Array(v)) // d
        else if (format === 'hex')
          return encodeHex(extractX25519PrivateKeyRaw(new Uint8Array(v))) // d
        else throw new Error('jwk export not implemented')
      }

      const jwk = await crypto.subtle.exportKey('jwk', key)
      if (format === 'raw') return decodeBase64Url(jwk.d!)
      else if (format === 'hex') return encodeHex(decodeBase64Url(jwk.d!))
      else return jwk
    } else {
      const jwk = await crypto.subtle.exportKey('jwk', key)
      if (format === 'raw') return decodeBase64Url(jwk.x!)
      else if (format === 'hex') return encodeHex(decodeBase64Url(jwk.x!))
      else return jwk
    }
  }

  throw new Error(`key algorithm not supported: '${key.algorithm.name}'`)
}
