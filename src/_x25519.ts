export const extractX25519PrivateKeyRaw = (pkcs8: Uint8Array): Uint8Array => {
  let index = 0

  if (pkcs8[index++] !== 0x30) {
    throw new Error('Invalid format: expected SEQUENCE')
  }

  const sequenceLength = pkcs8[index++]
  if (sequenceLength !== pkcs8.length - 2) {
    throw new Error('Invalid sequence length')
  }

  if (
    pkcs8[index++] !== 0x02 ||
    pkcs8[index++] !== 0x01 ||
    pkcs8[index++] !== 0x00
  ) {
    throw new Error('Invalid version format')
  }

  if (pkcs8[index++] !== 0x30) {
    throw new Error(
      'Invalid format: expected SEQUENCE for algorithm identifier'
    )
  }

  const algorithmLength = pkcs8[index++]
  if (algorithmLength !== 5) {
    throw new Error('Invalid algorithm identifier length')
  }

  const oid = pkcs8.slice(index, index + algorithmLength)
  if (!oid.every((value, i) => value === [0x06, 0x03, 0x2b, 0x65, 0x6e][i])) {
    throw new Error('Invalid OID for X25519')
  }
  index += algorithmLength

  index += 2
  // if (pkcs8[index++] !== 0x05 || pkcs8[index++] !== 0x00) {
  //   throw new Error('Invalid parameters format')
  // }

  if (pkcs8[index++] !== 0x04) {
    throw new Error('Invalid format: expected OCTET STRING for private key')
  }

  const privateKeyLength = pkcs8[index++]
  if (privateKeyLength !== 32) {
    throw new Error('Invalid private key length')
  }

  const privateKey = pkcs8.slice(index, index + privateKeyLength)

  return privateKey
}
