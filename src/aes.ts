import {decodeHex} from '@std/encoding/hex'

const decoder = new TextDecoder()
const encoder = new TextEncoder()

interface AesKeyOptions {
  /** @default 256 */
  length?: 128 | 196 | 256
  /** @default 12 */
  ivLen?: 12 | 16
}

/** generate key for `aes` encrypt */
export const generateKeyAesGcm = async (options: AesKeyOptions = {}) => {
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
export const importAesGcm = async (options: ImportAesGcmOptions) => {
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

interface aesEncryptConfig {
  key: CryptoKey
  iv: ArrayBuffer
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
export const aesEncryptString = ({key, iv}: aesEncryptConfig) => {
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
export const aesEncryptObject = <T extends object>(init: aesEncryptConfig) => {
  const aes = aesEncryptString(init)

  const encrypt = (data: T): Promise<ArrayBuffer> => {
    return aes.encrypt(JSON.stringify(data))
  }

  const decrypt = async <R extends T>(data: ArrayBuffer): Promise<R> => {
    return JSON.parse(await aes.decrypt(data))
  }

  return {encrypt, decrypt}
}

