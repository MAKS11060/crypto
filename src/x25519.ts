import {encodeHex} from '@std/encoding/hex'
import type {ExportKeyResult} from './utils.ts'

const extractX25519PrivateKeyRaw = (pkcs8: Uint8Array): Uint8Array => {
  let index = 0

  if (pkcs8[index++] !== 0x30) {
    throw new Error('Invalid format: expected SEQUENCE')
  }

  const sequenceLength = pkcs8[index++]
  if (sequenceLength !== pkcs8.length - 2) {
    throw new Error('Invalid sequence length')
  }

  if (
    pkcs8[index++] !== 0x02 ||
    pkcs8[index++] !== 0x01 ||
    pkcs8[index++] !== 0x00
  ) {
    throw new Error('Invalid version format')
  }

  if (pkcs8[index++] !== 0x30) {
    throw new Error(
      'Invalid format: expected SEQUENCE for algorithm identifier'
    )
  }

  const algorithmLength = pkcs8[index++]
  if (algorithmLength !== 5) {
    throw new Error('Invalid algorithm identifier length')
  }

  const oid = pkcs8.slice(index, index + algorithmLength)
  if (!oid.every((value, i) => value === [0x06, 0x03, 0x2b, 0x65, 0x6e][i])) {
    throw new Error('Invalid OID for X25519')
  }
  index += algorithmLength

  index += 2
  // if (pkcs8[index++] !== 0x05 || pkcs8[index++] !== 0x00) {
  //   throw new Error('Invalid parameters format')
  // }

  if (pkcs8[index++] !== 0x04) {
    throw new Error('Invalid format: expected OCTET STRING for private key')
  }

  const privateKeyLength = pkcs8[index++]
  if (privateKeyLength !== 32) {
    throw new Error('Invalid private key length')
  }

  const privateKey = pkcs8.slice(index, index + privateKeyLength)

  return privateKey
}

/**
 * Exports the `public` and `private` keys of a given {@linkcode CryptoKeyPair} in `raw` format.
 *
 * @example
 * ```ts
 * import {exportKeyRawX25519, generateKeyPair} from '@maks11060/crypto'
 *
 * const keyPair = await generateKeyPair('X25519')
 * const keys = await exportKeyRawX25519(keyPair)
 * keys.private // 'hexadecimal representation of the private key'
 * keys.public // 'hexadecimal representation of the public key'
 * ```
 *
 * @param {CryptoKeyPair} keys - The CryptoKeyPair object containing the `public` and `private` keys.
 * @returns {Promise<ExportKeyResult>} A Promise that resolves to an object containing the exported `public` and `private` keys in hexadecimal format.
 * @throws {Error} If the key algorithm is not '`X25519`'.
 */
export const exportKeyRawX25519 = async (
  keys: CryptoKeyPair
): Promise<ExportKeyResult> => {
  if (keys.privateKey.algorithm.name === 'X25519') {
    const pub = await crypto.subtle.exportKey('raw', keys.publicKey)
    const v = await crypto.subtle.exportKey('pkcs8', keys.privateKey)
    const d = extractX25519PrivateKeyRaw(new Uint8Array(v))
    return {
      public: encodeHex(pub),
      private: encodeHex(d),
    }
  }

  throw new Error(`The key algorithm must be 'X25519'`)
}
