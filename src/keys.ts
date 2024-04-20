import {KeyAlg, importKeyRaw, keyAlg} from './jwk.ts'

interface LoadKey {
  alg: KeyAlg
  public: string
  private?: string
}

interface LoadKeyPair {
  alg: KeyAlg
  public: string
  private: string
}

/**
 * import key in raw format.
 * @param options - `key` in raw format
 */
export const importRawKey = async (options: LoadKey): Promise<CryptoKey> => {
  return options.private
    ? await importKeyRaw(options)
    : await importKeyRaw(options)
}

/**
 * import keys in raw format.
 * @param options - `keys` in raw format
 */
export const importKeyPairRaw = async (
  options: LoadKeyPair
): Promise<CryptoKeyPair> => {
  const {alg, private: _private, public: _pub} = options
  const privateKey = await importKeyRaw({alg, public: _pub, private: _private})
  const publicKey = await importKeyRaw({alg, public: _pub})
  return {privateKey, publicKey} as CryptoKeyPair
}

export const generateKeyPair = async (alg: KeyAlg): Promise<CryptoKeyPair> => {
  const keys = await crypto.subtle.generateKey(keyAlg(alg), true, [
    'sign',
    'verify',
  ])
  return keys as CryptoKeyPair
}
