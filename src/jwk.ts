import {concat} from '@std/bytes/concat'
import {decodeBase64Url, encodeBase64Url} from '@std/encoding/base64url'
import {decodeHex, encodeHex} from '@std/encoding/hex'
import type {
  ExportKeyResult,
  ImportKeyPairRaw,
  ImportKeyRaw,
  ImportPubKeyRaw,
  ImportPubKeyRawResult,
} from './utils.ts'

/**
 * Export a {@linkcode CryptoKey private key} to raw format
 *
 * @example
 * ```ts
 * import {exportKeyRaw} from '@maks11060/crypto'
 *
 * const keyPair = await generateKeyPair('Ed25519')
 * const keys = await exportKeyRaw(keyPair.privateKey)
 * keys.private // 88f913..8491ab
 * keys.public // 372375..eaf2e9
 * ```
 *
 * @param {CryptoKey} key - The private key to export.
 * @returns {Promise<ExportKeyResult>} A Promise that resolves to an object containing the exported public and private keys in hexadecimal format.
 * @throws {Error} If the key type is not 'private' or the key algorithm is not supported.
 */
export const exportKeyRaw = async (
  key: CryptoKey
): Promise<ExportKeyResult> => {
  if (key.type !== 'private') throw new Error(`key type must be a 'private'`)
  // https://openid.net/specs/draft-jones-json-web-key-03.html#anchor7
  const jwk = await crypto.subtle.exportKey('jwk', key)

  if (key.algorithm.name === 'ECDSA') {
    const x = decodeBase64Url(jwk.x!)
    const y = decodeBase64Url(jwk.y!)
    const d = decodeBase64Url(jwk.d!)
    const xy = concat([x, y])
    return {
      public: encodeHex(xy),
      private: encodeHex(d),
    }
  }

  if (key.algorithm.name === 'Ed25519') {
    const x = decodeBase64Url(jwk.x!)
    const d = decodeBase64Url(jwk.d!)
    return {
      public: encodeHex(x),
      private: encodeHex(d),
    }
  }

  // TODO: add import
  // if (key.algorithm.name === 'ECDH') {
  //   const x = decodeBase64Url(jwk.x!)
  //   const y = decodeBase64Url(jwk.y!)
  //   const d = decodeBase64Url(jwk.d!)
  //   const xy = concat([x, y])
  //   return {
  //     public: encodeHex(xy),
  //     private: encodeHex(d),
  //   }
  // }

  throw new Error(`key algorithm not supported '${key.algorithm.name}'`)
}

const importPubKeyRaw = (options: ImportPubKeyRaw): ImportPubKeyRawResult => {
  switch (options.alg) {
    case 'Ed25519': {
      const xy = decodeHex(options.public)
      if (xy.byteLength !== 32) {
        throw new Error('public key length must be 32 bytes')
      }
      const x = encodeBase64Url(xy)
      return {x}
    }
    case 'P-256':
    case 'ES256': {
      const xy = decodeHex(options.public)
      if (xy.byteLength !== 64) {
        throw new Error('public key length must be 64 bytes')
      }
      const x = encodeBase64Url(xy.slice(0, 32))
      const y = encodeBase64Url(xy.slice(32))
      return {x, y}
    }
    case 'P-384':
    case 'ES384': {
      const xy = decodeHex(options.public)
      if (xy.byteLength !== 96) {
        throw new Error('public key length must be 96 bytes')
      }
      const x = encodeBase64Url(xy.slice(0, 48))
      const y = encodeBase64Url(xy.slice(48))
      return {x, y}
    }
    case 'P-521':
    case 'ES512': {
      const xy = decodeHex(options.public)
      if (xy.byteLength !== 132) {
        throw new Error('public key length must be 132 bytes')
      }
      const x = encodeBase64Url(xy.slice(0, 66))
      const y = encodeBase64Url(xy.slice(66))
      return {x, y}
    }
    default:
      throw new Error(`key algorithm not supported ${options.alg}`)
  }
}

/**
 * import key in raw format to {@linkcode CryptoKey}
 *
 * @example
 * ```ts
 * import {importKeyRaw} from '@maks11060/crypto'
 *
 * const priv = await importKeyRaw({
 *   alg: 'Ed25519',
 *   public: '372375338143fc7958125af71e3d36220dccc442702657c128f89960508491ab',
 *   private: '88f913625ae98c00193cbc91d7b6fa36cd99d56379485937fb408a7500eaf2e9',
 * })
 * const pub = await importKeyRaw({
 *   alg: 'Ed25519',
 *   public: '372375338143fc7958125af71e3d36220dccc442702657c128f89960508491ab',
 * })
 * ```
 */
export const importKeyRaw = (options: ImportKeyRaw): Promise<CryptoKey> => {
  options.extractable ??= false

  const getD = (keyLen: number) => {
    if (!options.private) return {}
    const buf = decodeHex(options.private)
    if (buf.byteLength !== keyLen) {
      throw new Error(`private key length must be ${keyLen} bytes`)
    }
    return {d: encodeBase64Url(buf)}
  }

  switch (options.alg) {
    case 'Ed25519':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'OKP', crv: 'Ed25519', ...importPubKeyRaw(options), ...getD(32)},
        {name: 'Ed25519'},
        options.extractable,
        [options.private ? 'sign' : 'verify']
      )
    case 'P-256':
    case 'ES256':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'EC', crv: 'P-256', ...importPubKeyRaw(options), ...getD(32)},
        {name: 'ECDSA', namedCurve: 'P-256'},
        options.extractable,
        [options.private ? 'sign' : 'verify']
      )
    case 'P-384':
    case 'ES384':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'EC', crv: 'P-384', ...importPubKeyRaw(options), ...getD(48)},
        {name: 'ECDSA', namedCurve: 'P-384'},
        options.extractable,
        [options.private ? 'sign' : 'verify']
      )
    case 'P-521':
    case 'ES512':
      return crypto.subtle.importKey(
        'jwk',
        {kty: 'EC', crv: 'P-521', ...importPubKeyRaw(options), ...getD(66)},
        {name: 'ECDSA', namedCurve: 'P-521'},
        options.extractable,
        [options.private ? 'sign' : 'verify']
      )
    default:
      throw new Error(`key algorithm not supported ${options.alg}`)
  }
}

/**
 * import key pair in raw format to {@linkcode CryptoKey}
 *
 * @example
 * ```ts
 * import {importKeyPairRaw} from '@maks11060/crypto'
 *
 * const keys = await importKeyPairRaw({
 *   alg: 'Ed25519',
 *   public: '372375338143fc7958125af71e3d36220dccc442702657c128f89960508491ab',
 *   private: '88f913625ae98c00193cbc91d7b6fa36cd99d56379485937fb408a7500eaf2e9',
 * })
 * ```
 */
export const importKeyPairRaw = async (
  options: ImportKeyPairRaw
): Promise<CryptoKeyPair> => {
  const privateKey = await importKeyRaw(options)
  const {private: _, ...rest} = options
  const publicKey = await importKeyRaw(rest)
  return {privateKey, publicKey} as CryptoKeyPair
}
