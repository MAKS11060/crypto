# Crypto utils

[![JSR][JSR badge]][JSR]
[![Publish workflow][Publish workflow badge]][Publish workflow]

[JSR]: https://jsr.io/@maks11060/crypto
[JSR badge]: https://jsr.io/badges/@maks11060/crypto?v=0.1.1
[Publish workflow]: https://github.com/MAKS11060/crypto/actions/workflows/publish.yml
[Publish workflow badge]: https://github.com/maks11060/crypto/actions/workflows/publish.yml/badge.svg

## jwk

Generate key / export key
```ts
import {generateKeyPair, exportKeyRaw} from '@maks11060/crypto'
const keyPair = await generateKeyPair('Ed25519') // CryptoKeyPair

const keys = await exportKeyRaw(keyPair.privateKey)
keys.private // 88f913...eaf2e9
keys.public  // 372375...8491ab
```

Import key
```ts
import {importKeyRaw} from '@maks11060/crypto'

const priv = await importKeyRaw({
  alg: 'Ed25519',
  public: '372375338143fc7958125af71e3d36220dccc442702657c128f89960508491ab',
  private: '88f913625ae98c00193cbc91d7b6fa36cd99d56379485937fb408a7500eaf2e9',
})
const pub = await importKeyRaw({
  alg: 'Ed25519',
  public: '372375338143fc7958125af71e3d36220dccc442702657c128f89960508491ab',
})
```

### Algorithm supported

| Algorithm         | Deno  | Node.js |
| ----------------- | :---: | :-----: |
| `Ed25519`         |   ✔   |    ✔    |
| `P-256` / `ES256` |   ✔   |    ✔    |
| `P-384` / `ES384` |   ✔   |    ✔    |
| `P-521` / `ES512` |       |    ✔    |
