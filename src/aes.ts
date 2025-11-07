/**
 * AES encryption/decryption utilities using Web Crypto API
 */

import type {Uint8Array_} from './utils.ts'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/**
 * Options for AES secret key generation
 */
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

/**
 * Function type for importing secret keys from different formats
 */
export type ImportSecret = {
  (
    format: 'hex' | 'base64url',
    options: AesSecretOptions,
    secret: string,
  ): Promise<CryptoKey>
  (
    format: 'raw',
    options: AesSecretOptions,
    secret: ArrayBuffer | Uint8Array_,
  ): Promise<CryptoKey>
}

/** */
export type ExportSecret = {
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

export const exportSecret: ExportSecret = async (
  format,
  key,
): Promise<any> => {
  if (key.type !== 'secret') throw new Error('key type most be secret')
  const raw = await crypto.subtle.exportKey('raw', key)

  if (format === 'raw') return new Uint8Array(raw)
  if (format === 'hex') return new Uint8Array(raw).toHex()
  if (format === 'base64url') return new Uint8Array(raw).toBase64({alphabet: 'base64url', omitPadding: true})

  throw new Error(`Unknown format ${format} to export`)
}

export const importSecret: ImportSecret = async (
  format,
  options,
  secret,
): Promise<CryptoKey> => {
  options.length ??= 256

  if (format === 'hex') secret = Uint8Array.fromHex(secret as string)
  if (format === 'base64url') secret = Uint8Array.fromBase64(secret as string, {alphabet: 'base64url'})
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

export const aesEncrypt = <I = Uint8Array_, O = string>(
  key: CryptoKey,
  options: AesEncryptOptions<I, O>,
) => {
  const ivLen = 12 // 96-bit IV

  return {
    async encrypt(data: Uint8Array_ | ArrayBuffer): Promise<O> {
      const iv = crypto.getRandomValues(new Uint8Array(ivLen)) // 96-bit IV

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

      const iv = buffer.subarray(0, ivLen)
      const encryptedData = buffer.subarray(ivLen)

      const decrypted = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv},
        key,
        encryptedData,
      )
      return new Uint8Array(decrypted)
    },

    async encryptText(data: string): Promise<O> {
      return await this.encrypt(encoder.encode(data))
    },

    async decryptText(encrypted: I): Promise<string> {
      return decoder.decode(await this.decrypt(encrypted))
    },

    async encryptJson<T>(data: T): Promise<O> {
      const jsonBytes = encoder.encode(JSON.stringify(data))
      return await this.encrypt(jsonBytes)
    },

    async decryptJson<T>(encrypted: I): Promise<T> {
      const decrypted = await this.decrypt(encrypted)
      return JSON.parse(decoder.decode(decrypted))
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

const aesCodecBytes: AesEncryptOptions<Uint8Array_ | ArrayBuffer, Uint8Array_> = {
  encode: (output) => output,
  decode: (input) => new Uint8Array(input),
}

export const aesCodec = {
  base64: aesCodecBase64,
  base64url: aesCodecBase64url,
  hex: aesCodecHex,
  bytes: aesCodecBytes,
}
