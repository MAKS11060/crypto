#!/usr/bin/env -S deno run -A

import {importKeyPair} from './mod.ts'

// const keys = await generateKeyPair('Ed25519')
// const {privateKey, publicKey} = await exportKey('hex', keys)
// console.log(privateKey) // e6cc65db53dcdce37d095c5bd792a5114e8ca575190979dfaea1afa6da1daef9
// console.log(publicKey) // b504196a380c1dcb0526c88df4f947b8d8e32f3e7a5ac57d852f439fc4fc80bc

const privateKey =
  'e6cc65db53dcdce37d095c5bd792a5114e8ca575190979dfaea1afa6da1daef9'
const publicKey =
  'b504196a380c1dcb0526c88df4f947b8d8e32f3e7a5ac57d852f439fc4fc80bc'

const keys = await importKeyPair('hex', {alg: 'Ed25519', publicKey, privateKey})
keys.privateKey // CryptoKey
keys.publicKey // CryptoKey
