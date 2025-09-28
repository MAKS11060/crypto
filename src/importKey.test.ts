#!/usr/bin/env -S deno test -A --watch

// import {exportKey} from './exportKey.ts'
// import {importKey} from './importKey.ts'
// import {generateKeyPair} from './keys.ts'

// const {privateKey, publicKey} = await generateKeyPair('Ed25519')

// const privateKeyHEX = await exportKey('hex', privateKey)
// const publicKeyHEX = await exportKey('hex', publicKey)

// console.log({privateKeyHEX, publicKeyHEX})

// Deno.test({
//   name: 'importKey hex',
//   fn: async () => {
//     const privateKey = await importKey('hex', {
//       alg: 'Ed25519',
//       publicKey: publicKeyHEX,
//       privateKey: privateKeyHEX,
//     })
//     const publicKey = await importKey('hex', {
//       alg: 'Ed25519',
//       publicKey: publicKeyHEX,
//     })

//     console.log(privateKey)
//     console.log(publicKey)
//   },
// })

import {assertEquals} from 'jsr:@std/assert@^1.0.10/equals'
import {exportKey} from './exportKey.ts'
import {importKey} from './importKey.ts'
import {generateKeyPair} from './keys.ts'
import {isKeyAlg} from './utils.ts'

Deno.test({
  name: 'importKey',
  fn: async (t) => {
    const algs = ['Ed25519', 'P-256', 'P-384', 'P-521']
    for (const alg of algs) {
      if (!isKeyAlg(alg)) break
      await t.step({
        name: `import ${alg}`,
        ignore: 'Deno' in globalThis && alg === 'P-521',
        fn: async (t) => {
          const keys = await generateKeyPair(alg)
          const {privateKey, publicKey} = await exportKey('hex', keys)

          const privKey = await importKey('hex', {alg, privateKey, publicKey})
          assertEquals(keys.privateKey.type, privKey.type)
          assertEquals(keys.privateKey.algorithm, privKey.algorithm)
          assertEquals(keys.privateKey.usages, privKey.usages)

          const pubKey = await importKey('hex', {alg, publicKey})
          assertEquals(keys.publicKey.algorithm, pubKey.algorithm)
          assertEquals(keys.publicKey.type, pubKey.type)
          assertEquals(keys.publicKey.usages, pubKey.usages)
        },
      })
    }
  },
})
