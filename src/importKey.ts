import {decodeBase64Url, encodeBase64Url} from '@std/encoding/base64url'
import {decodeHex} from '@std/encoding/hex'
import {jwkAlgorithm} from './jwk.ts'
import type {KeyAlg, Uint8Array_} from './utils.ts'

type ImportKeyOptions = {
  alg: KeyAlg
  extractable?: boolean
}

type ImportKey = {
  (
    format: 'raw',
    options: ImportKeyOptions & {
      /**
       * Public key in `Binary` form
       *
       * - jwk `x` + `?y` component
       */
      publicKey: Uint8Array_ | ArrayBuffer

      /**
       * Private key in `Binary` form
       *
       * - jwk `d` component
       */
      privateKey?: Uint8Array_ | ArrayBuffer
    },
  ): Promise<CryptoKey>
  (
    format: 'hex' | 'base64url',
    options: ImportKeyOptions & {
      /**
       * Public key in `HEX` encoded
       *
       * - jwk `x` + `?y` component
       */
      publicKey: string

      /**
       * Private key in `HEX` encoded
       *
       * - jwk `d` component
       */
      privateKey?: string
    },
  ): Promise<CryptoKey>
  (
    format: 'jwk',
    jwk: Omit<JsonWebKey, 'alg'>,
    extractable?: boolean,
  ): Promise<CryptoKey>
}

type ImportKeyPair = {
  (
    format: 'hex' | 'base64url',
    options: ImportKeyOptions & {publicKey: string; privateKey: string},
  ): Promise<CryptoKeyPair>
  (
    format: 'raw',
    options: ImportKeyOptions & {publicKey: Uint8Array; privateKey: Uint8Array},
  ): Promise<CryptoKeyPair>
}

const checkLen = (pub: number, priv: number, publicKey: Uint8Array_, privateKey?: Uint8Array_) => {
  if (publicKey.byteLength !== pub) {
    throw new Error(`publicKey length must be ${pub} bytes`)
  }
  if (privateKey && privateKey.byteLength !== priv) {
    throw new Error(`privateKey length must be ${priv} bytes`)
  }
}

const makeJwkEC = (alg: KeyAlg, publicKey: Uint8Array_, privateKey?: Uint8Array_): JsonWebKey => {
  switch (alg) {
    case 'Ed25519':
    case 'X25519': {
      checkLen(32, 32, publicKey, privateKey)
      return {
        kty: 'OKP',
        crv: alg,
        x: encodeBase64Url(publicKey),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
        // deno-fmt-ignore
        key_ops: privateKey
          ? alg === 'Ed25519' ? ['sign'] : ['deriveKey']
          : alg === 'Ed25519' ? ['verify'] : [],
      }
    }
    case 'P-256':
    case 'ES256': {
      checkLen(64, 32, publicKey, privateKey)
      return {
        kty: 'EC',
        crv: 'P-256',
        x: encodeBase64Url(publicKey.slice(0, 32)),
        y: encodeBase64Url(publicKey.slice(32)),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
        key_ops: privateKey ? ['sign'] : ['verify'],
      }
    }
    case 'P-384':
    case 'ES384': {
      checkLen(96, 48, publicKey, privateKey)
      return {
        kty: 'EC',
        crv: 'P-384',
        x: encodeBase64Url(publicKey.slice(0, 48)),
        y: encodeBase64Url(publicKey.slice(48)),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
        key_ops: privateKey ? ['sign'] : ['verify'],
      }
    }
    case 'P-521':
    case 'ES512': {
      checkLen(132, 66, publicKey, privateKey)
      return {
        kty: 'EC',
        crv: 'P-521',
        x: encodeBase64Url(publicKey.slice(0, 66)),
        y: encodeBase64Url(publicKey.slice(66)),
        ...(privateKey && {d: encodeBase64Url(privateKey)}),
        key_ops: privateKey ? ['sign'] : ['verify'],
      }
    }
    default:
      throw new Error(`importKey key algorithm not supported ${alg}`)
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
 * @param format - The format of the key to import. Can be 'hex' or 'raw'.
 * @param options - The options for importing the key, including the algorithm, extractable flag, and the public key (and optionally the private key) in hex format.
 * @returns A promise that resolves to the imported cryptographic key.
 */
export const importKey: ImportKey = async (format, ...args): Promise<CryptoKey> => {
  if (format === 'jwk') {
    const [jwk, extractable = false] = args as [jwk: JsonWebKey, extractable?: boolean]
    const {options, keyUsage} = jwkAlgorithm(jwk)
    return await crypto.subtle.importKey('jwk', jwk, options, extractable, keyUsage)
  }

  const [options] = args as [
    ImportKeyOptions & {
      publicKey: string | Uint8Array_ | ArrayBuffer
      privateKey?: string | Uint8Array_ | ArrayBuffer
    },
  ]

  // pub/priv to Uint8Array
  if (format === 'hex') {
    options.publicKey = decodeHex(options.publicKey as string)
    if (options.privateKey) {
      options.privateKey = decodeHex(options.privateKey as string)
    }
  } else if (format === 'base64url') {
    options.publicKey = decodeBase64Url(options.publicKey as string)
    if (options.privateKey) {
      options.privateKey = decodeBase64Url(options.privateKey as string)
    }
  } else if (format === 'raw') {
    options.publicKey = new Uint8Array(options.publicKey as Uint8Array_)
    if (options.privateKey) {
      options.privateKey = new Uint8Array(options.privateKey as Uint8Array_)
    }
  }

  const jwk = makeJwkEC(
    options.alg,
    options.publicKey as Uint8Array_,
    options.privateKey as Uint8Array_ | undefined,
  )

  const {options: keyOptions, keyUsage} = jwkAlgorithm(jwk)
  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    keyOptions,
    options.extractable ?? false,
    keyUsage,
  )
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
 * @param format - The format of the key pair to import. Can be 'hex' or 'raw'.
 * @param options - The options for importing the key pair, including the algorithm, extractable flag, and the public and private keys in hex format.
 * @returns A promise that resolves to the imported cryptographic key pair.
 */
export const importKeyPair: ImportKeyPair = async (
  format,
  {privateKey, ...options},
): Promise<CryptoKeyPair> => {
  return {
    privateKey: await importKey(format as any, {privateKey, ...options} as any),
    publicKey: await importKey(format as any, options as any),
  }
}
