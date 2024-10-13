export type KeyAlg =
  | 'Ed25519'
  | 'X25519' // Curve25519?
  | 'P-256'
  | 'ES256'
  | 'P-384'
  | 'ES384'
  | 'P-521'
  | 'ES512'

export interface ImportPubKeyRaw {
  alg: KeyAlg
  public: string
}

export interface ImportKeyRaw extends ImportPubKeyRaw {
  private?: string
  extractable?: boolean
}

export interface ImportKeyPairRaw extends ImportKeyRaw {
  private: string
}

export interface ExportKeyResult {
  public: string
  private: string
}

export interface ImportPubKeyRawResult {
  x: string
  y?: string
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
