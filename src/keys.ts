import {keyAlg, type KeyAlg} from './jwk.ts'

export const generateKeyPair = async (alg: KeyAlg): Promise<CryptoKeyPair> => {
  const keys = await crypto.subtle.generateKey(keyAlg(alg), true, [
    'sign',
    'verify',
  ])
  return keys as CryptoKeyPair
}
