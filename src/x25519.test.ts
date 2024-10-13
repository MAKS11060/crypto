#!/usr/bin/env -S deno run -A --watch-hmr

import {assertEquals} from 'jsr:@std/assert/equals'
import {exportKeyRawX25519, generateKeyPair} from '../mod.ts'

const keyPair = await generateKeyPair('X25519')

Deno.test('exportKeyRawX25519', async () => {
  const keys = await exportKeyRawX25519(keyPair)

  assertEquals(typeof keys.public, 'string')
  assertEquals(keys.public.length, 64) // 32 Bytes

  assertEquals(typeof keys.private, 'string')
  assertEquals(keys.private.length, 64) // 32 Bytes
})
