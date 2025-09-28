export type Uint8Array_ = ReturnType<Uint8Array['slice']>

export const isDeno = 'Deno' in globalThis

export const algList = {
  Ed25519: true,
  ES256: true,
  ES384: true,
  ES512: !isDeno,
  'P-256': true,
  'P-384': true,
  'P-521': !isDeno,
  X25519: true,
} satisfies Record<KeyAlg, boolean>

export type KeyAlg =
  | 'Ed25519'
  | 'ES256' // alias
  | 'ES384' // alias
  | 'ES512' // alias
  | 'P-256'
  | 'P-384'
  | 'P-521'
  | 'X25519'

/**
 * Checks if a given string is a valid key algorithm.
 *
 * @example
 * ```ts
 * import {isKeyAlg} from '@maks11060/crypto'
 *
 * let alg: string = 'P-256'
 * if (isKeyAlg(alg)) {
 *   alg === 'P-256' // TS Check
 * }
 * ```
 *
 * @param alg - The algorithm to check.
 * @returns True if the algorithm is a valid key algorithm, false otherwise.
 */
export const isKeyAlg = (alg: string): alg is KeyAlg => alg in algList

export const isPair = (
  keys: CryptoKey | CryptoKeyPair,
): keys is CryptoKeyPair => {
  return 'privateKey' in keys && 'publicKey' in keys
}

/** Get options by alg */
export const keyAlg = (alg: KeyAlg): Algorithm | EcKeyAlgorithm => {
  switch (alg) {
    case 'Ed25519':
      return {name: 'Ed25519'}
    case 'X25519':
      return {name: 'X25519'}
    case 'P-256':
    case 'ES256':
      return {name: 'ECDSA', namedCurve: 'P-256'}
    case 'P-384':
    case 'ES384':
      return {name: 'ECDSA', namedCurve: 'P-384'}
    case 'P-521':
    case 'ES512':
      return {name: 'ECDSA', namedCurve: 'P-521'}
    default:
      throw new Error(`key algorithm not supported ${alg}`)
  }
}

export const keyAlgUsage = (alg: KeyAlg): KeyUsage[] => {
  return alg !== 'X25519' ? ['sign', 'verify'] : ['deriveKey']
}
