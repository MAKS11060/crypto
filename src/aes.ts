/**
 * AES key helpers for Web Crypto.
 *
 * Provides utilities to generate, import, export and derive AES secret keys
 * using the Web Crypto SubtleCrypto API. Supports AES-GCM, AES-CBC, AES-CTR
 * and AES-KW (key wrapping).
 *
 * @packageDocumentation
 *
 * @remarks
 * - This module works with raw key material (Uint8Array/ArrayBuffer) as well
 *   as hex and base64url string encodings.
 * - For AES-KW the generated/imported key usages are `wrapKey`/`unwrapKey`.
 *   For other AES modes the usages are `encrypt`/`decrypt`.
 * - The deriveKey helper is a simple deterministic derivation that hashes the
 *   input with SHA-256 and imports the digest as an AES-GCM key. It is NOT a
 *   password-based KDF (e.g. PBKDF2 or HKDF) and should not be used for
 *   deriving keys from low-entropy secrets without additional key stretching.
 */

/**
 * Options used when generating or importing an AES secret key.
 *
 * @property name - The AES algorithm name. One of: 'AES-CBC', 'AES-CTR',
 *  'AES-GCM', 'AES-KW'.
 * @property length - Key length in bits. Supported values: 128, 192, 256.
 *  Default: 256.
 * @property extractable - Whether the created/imported CryptoKey should be
 *  extractable. Default: true for generation; default false when importing if
 *  not provided.
 *
 * @example
 * const opts: AesSecretOptions = { name: 'AES-GCM', length: 256, extractable: true }
 */
export type AesSecretOptions = {
  name: 'AES-CBC' | 'AES-CTR' | 'AES-GCM' | 'AES-KW'
  length?: 128 | 192 | 256
  extractable?: boolean
}

/**
 * Overloads for exporting a secret key.
 *
 * - When `format` is 'hex' or 'base64url' the returned Promise resolves to a string.
 * - When `format` is 'raw' the returned Promise resolves to a Uint8Array containing the raw key bytes.
 */
export type ExportSecret = {
  (format: 'hex' | 'base64url', key: CryptoKey): Promise<string>
  (format: 'raw', key: CryptoKey): Promise<Uint8Array>
}

/**
 * Generate a new AES secret CryptoKey.
 *
 * @param options - AesSecretOptions controlling algorithm, key length and extractability.
 * @returns A Promise that resolves to a newly generated CryptoKey.
 *
 * @remarks
 * - If `options.length` is omitted it defaults to 256 bits.
 * - For AES-KW the returned key is intended for wrapping/unwrapping (usages:
 *   ['wrapKey', 'unwrapKey']). For other modes the usages are ['encrypt', 'decrypt'].
 *
 * @example
 * const key = await generateAesSecret({ name: 'AES-GCM', length: 256 })
 */
export async function generateAesSecret(options: AesSecretOptions): Promise<CryptoKey> {}

/**
 * Export a secret CryptoKey into a chosen format.
 *
 * @param format - One of 'raw', 'hex', or 'base64url'.
 *   - 'raw' returns a Uint8Array of the key bytes.
 *   - 'hex' returns a hex-encoded string.
 *   - 'base64url' returns a URL-safe base64 string.
 * @param key - The CryptoKey to export. Must be of type 'secret'.
 * @returns A Promise that resolves to the exported key in the requested format.
 *
 * @throws If `key.type !== 'secret'`.
 * @throws If `format` is not one of 'raw' | 'hex' | 'base64url'.
 *
 * @example
 * const hex = await exportSecret('hex', key)
 * const raw = await exportSecret('raw', key)
 */
export const exportSecret: ExportSecret = async (format, key): Promise<any> => {}

/**
 * Import raw key material as a CryptoKey for the specified AES algorithm.
 *
 * @param format - Format of the provided secret: 'raw', 'hex', or 'base64url'.
 * @param options - AesSecretOptions describing the target algorithm and length.
 *                 `options.length` defaults to 256 if omitted.
 * @param secret - The secret key material. When `format` is:
 *   - 'raw' provide an ArrayBuffer | Uint8Array
 *   - 'hex' provide a hex string
 *   - 'base64url' provide a base64url string
 * @returns A Promise that resolves to the imported CryptoKey.
 *
 * @throws If the provided key material length (in bytes) does not match the expected
 *   key length (options.length / 8).
 *
 * @remarks
 * - After decoding the input, the function checks that the byte length equals
 *   the requested AES key length (e.g. 32 bytes for 256-bit keys).
 * - For AES-KW the resulting key usages are ['wrapKey', 'unwrapKey']; for other
 *   AES modes the usages are ['encrypt', 'decrypt'].
 *
 * @example
 * const key = await importSecret('hex', { name: 'AES-GCM', length: 256 }, hexString)
 */
export async function importSecret(
  format: 'raw' | 'hex' | 'base64url',
  options: AesSecretOptions,
  secret: string | ArrayBuffer | Uint8Array,
): Promise<CryptoKey> {}

/**
 * Deterministically derive a 256-bit AES-GCM key from a UTF-8 string.
 *
 * @param secret - Input string to derive the key from.
 * @returns A Promise that resolves to a CryptoKey usable for AES-GCM
 *   encrypt/decrypt operations.
 *
 * @remarks
 * - The function encodes the input string as UTF-8, computes SHA-256 over it,
 *   and imports the 32-byte digest as an AES-GCM key (thus a 256-bit key).
 * - This is a simple deterministic derivation and is NOT a secure password
 *   key derivation function. Use PBKDF2, scrypt, or Argon2 for deriving keys
 *   from low-entropy passwords in production.
 *
 * @example
 * const key = await deriveKey('my secret passphrase')
 */
export async function deriveKey(secret: string): Promise<CryptoKey> {}
import {decodeBase64Url, encodeBase64Url} from '@std/encoding/base64url'
import {decodeHex, encodeHex} from '@std/encoding/hex'
import type {Uint8Array_} from './utils.ts'

const encoder = new TextEncoder()

export interface AesSecretOptions {
  /**
   * Supported `AES` algorithms:
   *
   * - `AES-GCM`
   * - `AES-CBC`
   * - `AES-CTR`
   * - `AES-KW`
   */
  name: 'AES-CBC' | 'AES-CTR' | 'AES-GCM' | 'AES-KW'

  /**
   * - `128`
   * - `192`
   * - `256`
   *
   * @default 256
   */
  length?: 128 | 192 | 256

  /**
   * @default true
   */
  extractable?: boolean
}

type ExportSecret = {
  (format: 'hex' | 'base64url', key: CryptoKey): Promise<string>
  (format: 'raw', key: CryptoKey): Promise<Uint8Array_>
}

export const generateAesSecret = async (options: AesSecretOptions): Promise<CryptoKey> => {
  options.length ??= 256

  return await crypto.subtle.generateKey(
    options,
    options.extractable ?? true,
    options.name !== 'AES-KW' ? ['encrypt', 'decrypt'] : ['wrapKey', 'unwrapKey'],
  ) as CryptoKey
}

export const exportSecret: ExportSecret = async (format, key): Promise<any> => {
  if (key.type !== 'secret') throw new Error('key type most be secret')
  const raw = await crypto.subtle.exportKey('raw', key)

  if (format === 'raw') return new Uint8Array(raw)
  if (format === 'hex') return encodeHex(raw)
  if (format === 'base64url') return encodeBase64Url(raw)

  throw new Error(`Unknown format ${format} to export`)
}

export const importSecret = async (
  format: 'raw' | 'hex' | 'base64url',
  options: AesSecretOptions,
  secret: string | ArrayBuffer | Uint8Array_,
): Promise<CryptoKey> => {
  // const [, length, type] = alg.split('-', 3)
  // const [, type, length] = alg.split('-', 3)
  // if (!['256', '192', '128'].includes(length)) throw new Error(`Unsupported AES length ${length}`)
  // if (!['GCM', 'CBC', 'CTR', 'KW'].includes(type)) throw new Error(`Unsupported AES type ${type}`)
  // const {name} = alg
  options.length ??= 256

  if (format === 'hex') secret = decodeHex(secret as string)
  if (format === 'base64url') secret = decodeBase64Url(secret as string)
  if (format === 'raw') secret = new Uint8Array(secret as Uint8Array_)

  if ((secret as Uint8Array_).byteLength !== options.length / 8) { // byte !== bits
    throw new Error(`AES expected secret length: ${options.length / 8}`)
  }

  return await crypto.subtle.importKey(
    'raw',
    secret as Uint8Array_,
    options,
    options.extractable ?? false,
    options.name !== 'AES-KW' ? ['encrypt', 'decrypt'] : ['wrapKey', 'unwrapKey'],
  )
}

//
export const deriveKey = async (secret: string): Promise<CryptoKey> => {
  const secretBuffer = encoder.encode(secret)
  const hashBuffer = await crypto.subtle.digest('SHA-256', secretBuffer)
  return await crypto.subtle.importKey(
    'raw',
    hashBuffer,
    {name: 'AES-GCM'},
    true,
    ['encrypt', 'decrypt'],
  )
}
