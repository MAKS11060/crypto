# WebCrypto Key Utilities

[![JSR][JSR badge]][JSR]
[![CI](https://github.com/MAKS11060/crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/MAKS11060/crypto/actions/workflows/ci.yml)

[JSR]: https://jsr.io/@maks11060/crypto
[JSR badge]: https://jsr.io/badges/@maks11060/crypto

A lightweight library for working with WebCrypto keys: generate, import, export, and convert cryptographic keys and key
pairs in various formats.

## Features

- Generate cryptographic key pairs for modern algorithms
- Import and export keys and key pairs in `hex`, `raw`, and `jwk` formats
- Convert between supported formats
- Supports `Ed25519`, `X25519`, `P-256`, `P-384`, `P-521`, and `RSASSA-PKCS1-v1_5`

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

### Import / Export

|      Algorithm      |    exportKey(format)     |    importKey(format)     |
| :-----------------: | :----------------------: | :----------------------: |
|      `Ed25519`      |   `raw`, `hex`, `jwk`    |   `raw`, `hex`, `jwk`    |
|      `X25519`       |   `raw`, `hex`, `jwk`    |   `raw`, `hex`, `jwk`    |
|  `P-256`, `ES256`   |   `raw`, `hex`, `jwk`    |   `raw`, `hex`, `jwk`    |
|  `P-384`, `ES384`   |   `raw`, `hex`, `jwk`    |   `raw`, `hex`, `jwk`    |
|  `P-521`, `ES512`   | [^1] `raw`, `hex`, `jwk` | [^1] `raw`, `hex`, `jwk` |
|                     |                          |                          |
| `RSASSA-PKCS1-v1_5` |          `jwk`           |          `jwk`           |
|      `RSA-PSS`      |          `jwk`           |          `jwk`           |

### generateKeyPair

|    Algorithm     | generateKeyPair(alg) |
| :--------------: | :------------------: |
|    `Ed25519`     |          ✔           |
|     `X25519`     |          ✔           |
| `P-256`, `ES256` |          ✔           |
| `P-384`, `ES384` |          ✔           |
| `P-521`, `ES512` |          ✔           |

[^1]: Deno is not supported
