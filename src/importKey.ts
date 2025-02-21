import {encodeBase64Url} from '@std/encoding/base64url'
import {decodeHex} from '@std/encoding/hex'
import type {KeyAlg} from './utils.ts'

type ImportKeyOptions = {
  alg: KeyAlg
  extractable?: boolean
}

type ImportKey = {
  (
    format: 'hex',
    options: ImportKeyOptions & {publicKey: string; privateKey?: string}
  ): Promise<CryptoKey>
  (
    format: 'raw',
    options: ImportKeyOptions & {publicKey: Uint8Array; privateKey?: Uint8Array}
  ): Promise<CryptoKey>
}

type ImportKeyPair = {
  (
    format: 'hex',
    options: ImportKeyOptions & {publicKey: string; privateKey: string}
  ): Promise<CryptoKeyPair>
  (
    format: 'raw',
    options: ImportKeyOptions & {publicKey: Uint8Array; privateKey: Uint8Array}
  ): Promise<CryptoKeyPair>
}

// privateKey = d + x+[y]
// publicKey  =     x+[y]
const _importXY_D = (
  alg: KeyAlg,
  publicKey: Uint8Array,
  privateKey?: Uint8Array
) => {
  switch (alg) {
    case 'Ed25519': {
      if (publicKey.byteLength !== 32) {
        throw new Error('publicKey length must be 32 bytes')
      }
      if (privateKey && privateKey.byteLength !== 32) {
        throw new Error('privateKey length must be 32 bytes')
      }

      return {
        x: encodeBase64Url(publicKey),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
      }
    }
    case 'P-256':
    case 'ES256': {
      if (publicKey.byteLength !== 64) {
        throw new Error('publicKey length must be 64 bytes')
      }
      if (privateKey && privateKey.byteLength !== 32) {
        throw new Error('privateKey length must be 32 bytes')
      }

      return {
        x: encodeBase64Url(publicKey.slice(0, 32)),
        y: encodeBase64Url(publicKey.slice(32)),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
      }
    }
    case 'P-384':
    case 'ES384': {
      if (publicKey.byteLength !== 96) {
        throw new Error('publicKey length must be 96 bytes')
      }
      if (privateKey && privateKey.byteLength !== 48) {
        throw new Error('privateKey length must be 48 bytes')
      }

      return {
        x: encodeBase64Url(publicKey.slice(0, 48)),
        y: encodeBase64Url(publicKey.slice(48)),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
      }
    }
    case 'P-521':
    case 'ES512': {
      if (publicKey.byteLength !== 132) {
        throw new Error('publicKey length must be 132 bytes')
      }
      if (privateKey && privateKey.byteLength !== 66) {
        throw new Error('privateKey length must be 66 bytes')
      }

      return {
        x: encodeBase64Url(publicKey.slice(0, 66)),
        y: encodeBase64Url(publicKey.slice(66)),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
      }
    }
    default:
      throw new Error(`key algorithm not supported ${alg}`)
  }
}

/**
 * Imports a cryptographic key in the specified format.
 *
 * @example
 * ```ts
 * import {importKey} from '@maks11060/crypto'
 *
 * const privateKey = 'e6cc65db53dcdce37d095c5bd792a5114e8ca575190979dfaea1afa6da1daef9'
 * const publicKey = 'b504196a380c1dcb0526c88df4f947b8d8e32f3e7a5ac57d852f439fc4fc80bc'
 *
 * await importKey('hex', {alg: 'Ed25519', publicKey, privateKey}) // CryptoKey( PrivateKey )
 * await importKey('hex', {alg: 'Ed25519', publicKey}) // CryptoKey( PublicKey )
 * ```
 *
 * @param {string} format - The format of the key to import. Can be 'hex' or 'raw'.
 * @param {ImportKeyOptions & {publicKey: string; privateKey?: string}} options - The options for importing the key, including the algorithm, extractable flag, and the public key (and optionally the private key) in hex format.
 * @returns {Promise<CryptoKey>} - A promise that resolves to the imported cryptographic key.
 */
export const importKey: ImportKey = (format, options): Promise<any> => {
  options.extractable ??= false

  const jwk = _importXY_D(
    options.alg,
    format === 'hex'
      ? decodeHex(options.publicKey as string)
      : new Uint8Array(options.publicKey as Uint8Array),
    options.privateKey
      ? format === 'hex'
        ? decodeHex(options.privateKey as string)
        : new Uint8Array(options.privateKey as Uint8Array)
      : undefined
  )

  switch (options.alg) {
    case 'Ed25519':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'OKP', crv: 'Ed25519', ...jwk},
        {name: 'Ed25519'},
        options.extractable,
        [options.privateKey ? 'sign' : 'verify']
      )
    case 'P-256':
    case 'ES256':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'EC', crv: 'P-256', ...jwk},
        {name: 'ECDSA', namedCurve: 'P-256'},
        options.extractable,
        [options.privateKey ? 'sign' : 'verify']
      )
    case 'P-384':
    case 'ES384':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'EC', crv: 'P-384', ...jwk},
        {name: 'ECDSA', namedCurve: 'P-384'},
        options.extractable,
        [options.privateKey ? 'sign' : 'verify']
      )
    case 'P-521':
    case 'ES512':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'EC', crv: 'P-521', ...jwk},
        {name: 'ECDSA', namedCurve: 'P-521'},
        options.extractable,
        [options.privateKey ? 'sign' : 'verify']
      )
    default:
      throw new Error(`key algorithm not supported ${options.alg}`)
  }
}

/**
 * Imports a cryptographic key pair in the specified format.
 *
 * @example
 * ```ts
 * import {importKeyPair} from '@maks11060/crypto'
 *
 * const privateKey = 'e6cc65db53dcdce37d095c5bd792a5114e8ca575190979dfaea1afa6da1daef9'
 * const publicKey = 'b504196a380c1dcb0526c88df4f947b8d8e32f3e7a5ac57d852f439fc4fc80bc'
 *
 * const keys = await importKeyPair('hex', {alg: 'Ed25519', publicKey, privateKey})
 * keys.privateKey // CryptoKey
 * keys.publicKey // CryptoKey
 * ```
 *
 * @param {string} format - The format of the key pair to import. Can be 'hex' or 'raw'.
 * @param {ImportKeyOptions & {publicKey: string; privateKey: string}} options - The options for importing the key pair, including the algorithm, extractable flag, and the public and private keys in hex format.
 * @returns {Promise<CryptoKeyPair>} - A promise that resolves to the imported cryptographic key pair.
 */
export const importKeyPair: ImportKeyPair = async (
  format,
  {privateKey, ...options}
): Promise<any> => {
  return {
    privateKey: await importKey(format as any, {privateKey, ...options} as any),
    publicKey: await importKey(format as any, options as any),
  }
}
