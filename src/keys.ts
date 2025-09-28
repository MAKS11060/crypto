import {type KeyAlg, keyAlg, keyAlgUsage} from './utils.ts'

/**
 * Generates a cryptographic key pair for the specified algorithm.
 *
 * @example
 * ```ts
 * import {generateKeyPair} from '@maks11060/crypto'
 *
 * const keys = await generateKeyPair('Ed25519')
 * keys.privateKey // CryptoKey
 * keys.publicKey // CryptoKey
 * ```
 *
 * @param alg - The key algorithm to use for generating the key pair.
 * @param extractable - Whether the generated keys should be extractable.
 * @returns A promise that resolves to the generated cryptographic key pair.
 */
export const generateKeyPair = async (
  alg: KeyAlg,
  extractable: boolean = true,
): Promise<CryptoKeyPair> => {
  const keys = await crypto.subtle.generateKey(
    keyAlg(alg),
    extractable,
    keyAlgUsage(alg),
  )
  return keys as CryptoKeyPair
}
