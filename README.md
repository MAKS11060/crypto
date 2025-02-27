# WebCrypto keys utilities

[![JSR][JSR badge]][JSR]
[![CI](https://github.com/MAKS11060/crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/MAKS11060/crypto/actions/workflows/ci.yml)

[JSR]: https://jsr.io/@maks11060/crypto
[JSR badge]: https://jsr.io/badges/@maks11060/crypto


This library provides a set of functions for generating, importing, and exporting cryptographic keys and key pairs

- [WebCrypto keys utilities](#webcrypto-keys-utilities)
  - [Key Features](#key-features)
  - [Install](#install)
  - [Usage](#usage)
    - [Algorithms](#algorithms)

## Key Features
 - Import and export keys in different formats such as `hex`, `raw`, and `jwk`
 - Algorithm Support: `Ed25519`, `P-256`,` P-384`,` P-521`, and `X25519`

## Install
```ts
// deno add jsr:@maks11060/crypto
import {generateKeyPair} from '@maks11060/crypto'

// or
import {generateKeyPair} from 'jsr:@maks11060/crypto'
```

## Usage

```ts
import {exportKey, generateKeyPair, importKey, importKeyPair} from '@maks11060/crypto'

const keys = await generateKeyPair('Ed25519')
keys.privateKey // CryptoKey
keys.publicKey // CryptoKey

// export key pair
const {privateKey, publicKey} = await exportKey('hex', keys)
console.log(privateKey) // e6cc65db53dcdce37d095c5bd792a5114e8ca575190979dfaea1afa6da1daef9
console.log(publicKey) // b504196a380c1dcb0526c88df4f947b8d8e32f3e7a5ac57d852f439fc4fc80bc

// export single key
const privateKey_2 = await exportKey('hex', keys.privateKey)
const publicKey_2 = await exportKey('hex', keys.publicKey)
console.log(privateKey_2) // e6cc65db53dcdce37d095c5bd792a5114e8ca575190979dfaea1afa6da1daef9
console.log(publicKey_2) // b504196a380c1dcb0526c88df4f947b8d8e32f3e7a5ac57d852f439fc4fc80bc

// import private key
await importKey('hex', {alg: 'Ed25519', publicKey, privateKey})

// import public key
await importKey('hex', {alg: 'Ed25519', publicKey})

// import key pair
await importKeyPair('hex', {alg: 'Ed25519', publicKey, privateKey})
```

### Algorithms
| Algorithm        | generateKeyPair | exportKey | importKey |
| ---------------- | :-------------: | :-------: | :-------: |
| `Ed25519`        |        ✔        |     ✔     |     ✔     |
| `X25519`         |        ✔        |     ✔     |           |
| `P-256`, `ES256` |        ✔        |     ✔     |     ✔     |
| `P-384`, `ES384` |        ✔        |     ✔     |     ✔     |
| `P-521`, `ES512` |        ✔        |   ✔ 1*    |   ✔ 1*    |

1. Deno is not supported
