#!/usr/bin/env -S deno test -A --watch

import {expect} from 'jsr:@std/expect/expect'
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
          expect(keys.privateKey.type).toEqual(privKey.type)
          expect(keys.privateKey.algorithm).toEqual(privKey.algorithm)
          expect(keys.privateKey.usages).toEqual(privKey.usages)

          const pubKey = await importKey('hex', {alg, publicKey})
          expect(keys.publicKey.algorithm).toEqual(pubKey.algorithm)
          expect(keys.publicKey.type).toEqual(pubKey.type)
          expect(keys.publicKey.usages).toEqual(pubKey.usages)
        },
      })
    }
  },
})
