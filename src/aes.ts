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
   * Key length in bits
   * - `128`
   * - `192`
   * - `256`
   *
   * @default 256
   */
  length?: 128 | 192 | 256

  /**
   * Whether the key can be exported
   * @default true
   */
  extractable?: boolean
}

/**
 * Function type for importing secret keys from different formats
 */
export type ImportSecret = {
  /**
   * Import secret key from hex or base64url string
   * @param format - Format of the input string
   * @param options - {@link AesSecretOptions} AES options
   * @param secret - Secret string in specified format
   * @returns Promise resolving to {@linkcode CryptoKey}
   */
  (
    format: 'hex' | 'base64url',
    options: AesSecretOptions,
    secret: string,
  ): Promise<CryptoKey>
  /**
   * Import secret key from raw binary data
   * @param format - Format of the input data
   * @param options - {@link AesSecretOptions} AES options
   * @param secret - Secret data as ArrayBuffer or {@linkcode Uint8Array_}
   * @returns Promise resolving to {@linkcode CryptoKey}
   */
  (
    format: 'raw',
    options: AesSecretOptions,
    secret: ArrayBuffer | Uint8Array_,
  ): Promise<CryptoKey>
}

/**
 * Function type for exporting secret keys to different formats
 */
export type ExportSecret = {
  /**
   * Export secret key to hex or base64url string
   * @param format - Output format
   * @param key - {@linkcode CryptoKey} to export
   * @returns Promise resolving to string representation
   */
  (format: 'hex' | 'base64url', key: CryptoKey): Promise<string>
  /**
   * Export secret key to raw binary data
   * @param format - Output format
   * @param key - {@linkcode CryptoKey} to export
   * @returns Promise resolving to {@linkcode Uint8Array_}
   */
  (format: 'raw', key: CryptoKey): Promise<Uint8Array_>
}

/**
 * Generate a new AES secret key with specified options
 * @param options - {@link AesSecretOptions} AES secret key options
 * @returns Promise resolving to generated {@linkcode CryptoKey}
 */
export const generateAesSecret = async (options: AesSecretOptions): Promise<CryptoKey> => {
  options.length ??= 256

  return await crypto.subtle.generateKey(
    options,
    options.extractable ?? true,
    options.name !== 'AES-KW' ? ['encrypt', 'decrypt'] : ['wrapKey', 'unwrapKey'],
  ) as CryptoKey
}

/**
 * Export a secret key to specified format
 * @param format - Format to export the key in
 * @param key - {@linkcode CryptoKey} to export
 * @returns Promise resolving to exported key data
 * @throws Error if key type is not 'secret'
 */
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

/**
 * Import a secret key from specified format
 * @param format - Format of the input data
 * @param options - {@link AesSecretOptions} AES secret key options
 * @param secret - Secret data in specified format
 * @returns Promise resolving to imported {@linkcode CryptoKey}
 * @throws Error if secret length doesn't match expected length
 */
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

/**
 * Derive an AES-GCM key from a string secret using SHA-256 hashing
 * @param secret - Input string secret
 * @returns Promise resolving to derived {@linkcode CryptoKey}
 */
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

/**
 * Interface for AES encryption options with custom encoding/decoding
 * @template I - Input type for decryption
 * @template O - Output type for encryption
 */
export interface AesEncryptOptions<I, O> {
  /** Encode function to transform encrypted bytes to output format */
  encode(output: Uint8Array_): O
  /** Decode function to transform input format to bytes for decryption */
  decode(input: I): Uint8Array_
}

/**
 * Create AES encryption/decryption instance with specified key and options
 * @template I - Input type for decryption
 * @template O - Output type for encryption
 * @param key - AES key to use for encryption/decryption ({@linkcode CryptoKey})
 * @param options - {@link AesEncryptOptions} Encoding/decoding options
 * @returns Object with encryption/decryption methods
 */
export const aesEncrypt = <I = string, O = string>(
  key: CryptoKey,
  options: AesEncryptOptions<I, O>,
) => {
  const ivLen = 12 // 96-bit IV

  return {
    /**
     * Encrypt data using AES-GCM
     * @param data - Data to encrypt ({@linkcode Uint8Array_} or ArrayBuffer)
     * @returns Promise resolving to encrypted data in specified output format
     */
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

    /**
     * Decrypt data using AES-GCM
     * @param encrypted - Encrypted data in input format
     * @returns Promise resolving to decrypted bytes
     */
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

    /**
     * Encrypt text string
     * @param data - Text to encrypt
     * @returns Promise resolving to encrypted data in specified output format
     */
    async encryptText(data: string): Promise<O> {
      return await this.encrypt(encoder.encode(data))
    },

    /**
     * Decrypt text string
     * @param encrypted - Encrypted data in input format
     * @returns Promise resolving to decrypted text
     */
    async decryptText(encrypted: I): Promise<string> {
      return decoder.decode(await this.decrypt(encrypted))
    },

    /**
     * Encrypt JSON object
     * @template T - Type of JSON data
     * @param data - JSON object to encrypt
     * @returns Promise resolving to encrypted data in specified output format
     */
    async encryptJson<T>(data: T): Promise<O> {
      const jsonBytes = encoder.encode(JSON.stringify(data))
      return await this.encrypt(jsonBytes)
    },

    /**
     * Decrypt JSON object
     * @template T - Type of JSON data
     * @param encrypted - Encrypted data in input format
     * @returns Promise resolving to decrypted JSON object
     */
    async decryptJson<T>(encrypted: I): Promise<T> {
      const decrypted = await this.decrypt(encrypted)
      return JSON.parse(decoder.decode(decrypted))
    },
  }
}

/**
 * AES codec for base64 format
 */
const aesCodecBase64: AesEncryptOptions<string, string> = {
  encode: (output) => output.toBase64(),
  decode: (input) => Uint8Array.fromBase64(input),
}

/**
 * AES codec for base64url format
 */
const aesCodecBase64url: AesEncryptOptions<string, string> = {
  encode: (output) => output.toBase64({alphabet: 'base64url', omitPadding: true}),
  decode: (input) => Uint8Array.fromBase64(input, {alphabet: 'base64url'}),
}

/**
 * AES codec for hex format
 */
const aesCodecHex: AesEncryptOptions<string, string> = {
  encode: (output) => output.toHex(),
  decode: (input) => Uint8Array.fromHex(input),
}

/**
 * AES codec for raw bytes format
 */
const aesCodecBytes: AesEncryptOptions<Uint8Array_ | ArrayBuffer, Uint8Array_> = {
  encode: (output) => output,
  decode: (input) => new Uint8Array(input),
}

/**
 * Collection of predefined AES codecs for different formats
 */
export const aesCodec = {
  base64: aesCodecBase64,
  base64url: aesCodecBase64url,
  hex: aesCodecHex,
  bytes: aesCodecBytes,
}
