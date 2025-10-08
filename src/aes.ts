import {decodeBase64Url, encodeBase64Url} from '@std/encoding/base64url'
import {decodeHex, encodeHex} from '@std/encoding/hex'
import type {Uint8Array_} from './utils.ts'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

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

// enc
export interface AesEncryptOptions<I, O> {
  encode(output: Uint8Array_): O
  decode(input: I): Uint8Array_
}

export const aesEncrypt = <I = string, O = string>(key: CryptoKey, options: AesEncryptOptions<I, O>) => {
  return {
    async encrypt(data: Uint8Array_): Promise<O> {
      const iv = crypto.getRandomValues(new Uint8Array(12)) // 96-bit IV

      const encrypted = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv},
        key,
        data,
      )

      const result = new Uint8Array(iv.byteLength + encrypted.byteLength)
      result.set(iv, 0)
      result.set(new Uint8Array(encrypted), iv.byteLength)

      return options.encode(result)
    },

    async decrypt(encrypted: I): Promise<Uint8Array_> {
      const buffer = options.decode(encrypted)

      const iv = buffer.subarray(0, 12)
      const encryptedData = buffer.subarray(12)

      const decrypted = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv},
        key,
        encryptedData,
      )
      return new Uint8Array(decrypted)
    },

    async encryptJson<T>(data: T): Promise<O> {
      const jsonBytes = encoder.encode(JSON.stringify(data))
      return await this.encrypt(jsonBytes)
    },

    async decryptJson<T>(encrypted: I): Promise<T> {
      const decrypted = await this.decrypt(encrypted)
      const jsonString = decoder.decode(decrypted)
      return JSON.parse(jsonString) as T
    },
  }
}

const aesCodecBase64: AesEncryptOptions<string, string> = {
  encode: (output) => output.toBase64(),
  decode: (input) => Uint8Array.fromBase64(input),
}
const aesCodecBase64url: AesEncryptOptions<string, string> = {
  encode: (output) => output.toBase64({alphabet: 'base64url', omitPadding: true}),
  decode: (input) => Uint8Array.fromBase64(input, {alphabet: 'base64url'}),
}
const aesCodecHex: AesEncryptOptions<string, string> = {
  encode: (output) => output.toHex(),
  decode: (input) => Uint8Array.fromHex(input),
}

export const aesCodec = {
  base64: aesCodecBase64,
  base64url: aesCodecBase64url,
  hex: aesCodecHex,
}
