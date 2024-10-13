# Crypto utils for `EC` keys

[![JSR][JSR badge]][JSR]
[![CI][CI badge]][CI]

[JSR]: https://jsr.io/@maks11060/crypto
[JSR badge]: https://jsr.io/badges/@maks11060/crypto
[CI]: https://github.com/MAKS11060/crypto/actions/workflows/ci.yml
[CI badge]: https://github.com/maks11060/crypto/actions/workflows/ci.yml/badge.svg


- [Crypto utils for `EC` keys](#crypto-utils-for-ec-keys)
  - [Install](#install)
  - [Usage](#usage)
    - [Import Key](#import-key)
    - [Import Key Pair](#import-key-pair)
    - [Generate / Export Key](#generate--export-key)
    - [X25519](#x25519)
  - [Algorithms](#algorithms)


Provide crypto utilities for importing, exporting, and generating EC keys.


## Install
```ts
// deno add jsr:@maks11060/crypto
import {generateKeyPair} from '@maks11060/crypto'

// or
import {generateKeyPair} from 'jsr:@maks11060/crypto'
```

## Usage

### Import Key

Import a public or private key from a raw format.

```ts
import {importKeyRaw} from '@maks11060/crypto'

const pub = await importKeyRaw({
  alg: 'Ed25519',
  public: '8a4f5d16b246de737965a97ee997f4e4080ccf361d3a16178b689b10321453d4'
})

const priv = await importKeyRaw({
  alg: 'Ed25519',
  public: '8a4f5d16b246de737965a97ee997f4e4080ccf361d3a16178b689b10321453d4',
  private: '3ac0c3792c389759ae813828b9efffb4bdc13b47b71cfab869f365423b3c4e57'
})
```

### Import Key Pair

Import a key pair from a raw format.

```ts
import {importKeyPairRaw} from '@maks11060/crypto'

const keys = await importKeyPairRaw({
  alg: 'Ed25519',
  public: '8a4f5d16b246de737965a97ee997f4e4080ccf361d3a16178b689b10321453d4',
  private: '3ac0c3792c389759ae813828b9efffb4bdc13b47b71cfab869f365423b3c4e57'
})

console.log(keys) // {privateKey, publicKey}
```

### Generate / Export Key

Generate a new key pair and export it to a raw format.

```ts
import {generateKeyPair, exportKeyRaw} from '@maks11060/crypto'

const keyPair = await generateKeyPair('Ed25519')
const keys = await exportKeyRaw(keyPair.privateKey)

console.log(keys.private) // 88f913..8491ab
console.log(keys.public) // 372375..eaf2e9
```

### X25519

Generate a new `X25519` key pair and export it to a raw format.

```ts
import {generateKeyPair, exportKeyRawX25519} from '@maks11060/crypto'

const keyPair = await generateKeyPair('X25519')
const keys = await exportKeyRawX25519(keyPair)

console.log(keys.private) // e54f32..1234ab
console.log(keys.public) // 372375..eaf2e9
```

## Algorithms
| Algorithm         | Deno  | Node.js |
| ----------------- | :---: | :-----: |
| `Ed25519`         |   ✔   |    ✔    |
| `X25519`          |   ✔   |    ✔    |
| `P-256` / `ES256` |   ✔   |    ✔    |
| `P-384` / `ES384` |   ✔   |    ✔    |
| `P-521` / `ES512` |       |    ✔    |
