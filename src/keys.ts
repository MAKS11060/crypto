import {keyAlg, type KeyAlg} from './jwk.ts'

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
export const generateKeyPair = async (alg: KeyAlg): Promise<CryptoKeyPair> => {
  const keys = await crypto.subtle.generateKey(keyAlg(alg), true, [
    'sign',
    'verify',
  ])
  return keys as CryptoKeyPair
}
