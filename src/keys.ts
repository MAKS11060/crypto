import {type KeyAlg, keyAlg, keyAlgUsage} from './utils.ts'

/**
 * Generate key pair.
 *
 * @example
 * ```ts
 * import {generateKeyPair} from '@maks11060/crypto'
 *
 * const keys = await generateKeyPair('Ed25519')
 * ```
 */
export const generateKeyPair = async (
  alg: KeyAlg,
  extractable: boolean = true
): Promise<CryptoKeyPair> => {
  const keys = await crypto.subtle.generateKey(
    keyAlg(alg),
    extractable,
    keyAlgUsage(alg)
  )
  return keys as CryptoKeyPair
}
