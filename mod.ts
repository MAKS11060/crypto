/**
 * Provide crypto utils for ec keys.
 *
 * ```ts
 * import {generateKeyPair, exportKeyRaw, importKeyRaw} from "@maks11060/crypto";
 *
 * const pub = await importKeyRaw({
 *   alg: 'Ed25519',
 *   public: '372375338143fc7958125af71e3d36220dccc442702657c128f89960508491ab'
 * })
 * ```
 *
 * @module
 */

export * from './src/jwk.ts'
export * from './src/keys.ts'

