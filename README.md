# Crypto utils

[![JSR][JSR badge]][JSR]
[![CI][CI badge]][CI]

[JSR]: https://jsr.io/@maks11060/crypto
[JSR badge]: https://jsr.io/badges/@maks11060/crypto
[CI]: https://github.com/MAKS11060/crypto/actions/workflows/ci.yml
[CI badge]: https://github.com/maks11060/crypto/actions/workflows/ci.yml/badge.svg

Provide crypto utils for import/export/gen ec keys.

## Usage

### import key
```ts
import {importKeyRaw} from '@maks11060/crypto'

const pub = await importKeyRaw({
  alg: 'Ed25519',
  public: '8a4f5d16b246de737965a97ee997f4e4080ccf361d3a16178b689b10321453d4'
})
const priv = await importKeyRaw({
  alg: 'Ed25519',
  public: "8a4f5d16b246de737965a97ee997f4e4080ccf361d3a16178b689b10321453d4",
  private: "3ac0c3792c389759ae813828b9efffb4bdc13b47b71cfab869f365423b3c4e57"
})
```

### import key pair
```ts
import {importKeyPairRaw} from '@maks11060/crypto'

const keys = await importKeyPairRaw({
  alg: 'Ed25519',
  public: "8a4f5d16b246de737965a97ee997f4e4080ccf361d3a16178b689b10321453d4",
  private: "3ac0c3792c389759ae813828b9efffb4bdc13b47b71cfab869f365423b3c4e57"
})
keys // {privateKey, publicKey}
```

### generate / export key
```ts
import {generateKeyPair, exportKeyRaw} from '@maks11060/crypto'

const keyPair = await generateKeyPair('Ed25519')
const keys = await exportKeyRaw(keyPair.privateKey)
keys.private // 88f913..8491ab
keys.public // 372375..eaf2e9
```

## Algorithm supported

| Algorithm         | Deno  | Node.js |
| ----------------- | :---: | :-----: |
| `Ed25519`         |   ✔   |    ✔    |
| `P-256` / `ES256` |   ✔   |    ✔    |
| `P-384` / `ES384` |   ✔   |    ✔    |
| `P-521` / `ES512` |       |    ✔    |
