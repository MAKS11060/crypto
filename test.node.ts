#!/usr/bin/env -S node --watch --experimental-transform-types

import {importKey} from './src/importKey.ts'
import {generateKeyPair} from './src/keys.ts'

// const {privateKey, publicKey} = await generateKeyPair('P-521')
const {privateKey, publicKey} = await generateKeyPair('P-256')
console.log(
  await crypto.subtle.exportKey('jwk', privateKey),
  await crypto.subtle.exportKey('jwk', publicKey),
)

console.log(importKey('jwk', await crypto.subtle.exportKey('jwk', privateKey)))
