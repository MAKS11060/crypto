import {decodeHex} from '@std/encoding/hex'

interface AesKeyOptions {
  /** @default 256 */
  length?: 128 | 196 | 256
  /** @default 12 */
  ivLen?: 12 | 16
}

interface AesGcmKey {
  key: CryptoKey
  iv: ArrayBuffer
}

/** generate key for `aes` encrypt */
export const generateKeyAesGcm = async (
  options: AesKeyOptions = {}
): Promise<AesGcmKey> => {
  options.length ??= 256
  options.ivLen ??= 12

  const iv = crypto.getRandomValues(new Uint8Array(options.ivLen))
  const key = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: options.length,
    },
    true,
    ['encrypt', 'decrypt']
  )
  return {key, iv}
}

interface ImportAesGcmOptions {
  /** string contain 12-16 bytes  */
  iv: string
  key: string
}

/** import key for `aes` encrypt */
export const importAesGcm = async (
  options: ImportAesGcmOptions
): Promise<AesGcmKey> => {
  const iv = decodeHex(options.iv)
  const key = await crypto.subtle.importKey(
    'raw',
    decodeHex(options.key),
    {name: 'AES-GCM'},
    true,
    ['encrypt', 'decrypt']
  )
  return {key, iv}
}

interface AesEncryptConfig {
  key: CryptoKey
  iv: ArrayBuffer
}

interface AesEncryptString {
  encrypt(data: string): Promise<ArrayBuffer>
  decrypt(data: ArrayBuffer): Promise<string>
}
interface AesEncryptObject<T extends object> {
  encrypt(data: T): Promise<ArrayBuffer>
  decrypt(data: ArrayBuffer): Promise<T>
}

/**
 * Encrypt object using aes with types
 *
 * @example
 * ```ts
 * const key = await generateKeyAesGcm()
 * const {encrypt, decrypt} = aesEncryptString(key)
 * const buf = await encrypt('super secret string')
 * const str = await decrypt(buf)
 * console.log(str)
 * ```
 */
export const aesEncryptString = ({
  key,
  iv,
}: AesEncryptConfig): AesEncryptString => {
  const decoder = new TextDecoder()
  const encoder = new TextEncoder()

  const encrypt = async (data: string): Promise<ArrayBuffer> => {
    return await crypto.subtle.encrypt(
      {name: key.algorithm.name, iv},
      key,
      encoder.encode(data)
    )
  }

  const decrypt = async (data: ArrayBuffer): Promise<string> => {
    const out = await crypto.subtle.decrypt(
      {name: key.algorithm.name, iv},
      key,
      data
    )
    return decoder.decode(out)
  }

  return {encrypt, decrypt}
}

/**
 * Encrypt object using aes with types
 *
 * @example
 * ```ts
 * interface User {
 *   name: string
 * }
 * const key = await generateKeyAesGcm()
 * const {encrypt, decrypt} = aesEncryptObject<User>(key)
 * const buf = await encrypt({name: 'admin'})
 * const {name} = await decrypt(buf)
 * console.log(name)
 * ```
 */
export const aesEncryptObject = <T extends object>(
  init: AesEncryptConfig
): AesEncryptObject<T> => {
  const aes = aesEncryptString(init)

  const encrypt = (data: T): Promise<ArrayBuffer> => {
    return aes.encrypt(JSON.stringify(data))
  }

  const decrypt = async <R extends T>(data: ArrayBuffer): Promise<R> => {
    return JSON.parse(await aes.decrypt(data))
  }

  return {encrypt, decrypt}
}
