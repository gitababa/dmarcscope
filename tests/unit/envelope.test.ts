// The secret envelope, against vectors shared with the Python worker
// (ingestor/tests/test_crypto.py reads the same file).

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { EnvelopeError, decrypt, encrypt } from '@/lib/envelope.mjs'
import { decryptSecret, encryptSecret } from '@/lib/crypto'

type Case = { producer: string; secret: string; purpose: string; context: string; plaintext: string; nonce: string; envelope: string }
const vectors = JSON.parse(readFileSync(path.resolve(__dirname, '../vectors/envelope.json'), 'utf8')) as {
  secrets: Record<string, string>
  cases: Case[]
}
const S = vectors.secrets

const fails = (fn: () => unknown, code: string) => {
  try {
    fn()
  } catch (e) {
    expect(e).toBeInstanceOf(EnvelopeError)
    expect((e as EnvelopeError).code).toBe(code)
    return
  }
  throw new Error(`expected EnvelopeError ${code}`)
}

describe('secret envelope', () => {
  it('has vectors from both languages', () => {
    expect(new Set(vectors.cases.map((c) => c.producer))).toEqual(new Set(['typescript', 'python']))
  })

  it.each(vectors.cases)('decrypts the $producer vector for $context', (c) => {
    const out = decrypt({ secrets: [S.current, S.previous], purpose: c.purpose, context: c.context, envelope: c.envelope })
    expect(out.plaintext).toBe(c.plaintext)
    expect(out.keyIndex).toBe(c.secret === 'current' ? 0 : 1)
  })

  it.each(vectors.cases)('re-encrypts the $producer vector for $context to the same bytes', (c) => {
    const again = encrypt({ secret: S[c.secret], purpose: c.purpose, context: c.context, plaintext: c.plaintext, nonce: Buffer.from(c.nonce, 'hex') })
    expect(again).toBe(c.envelope)
  })

  it('fails loudly with the wrong key', () => {
    for (const c of vectors.cases) {
      fails(() => decrypt({ secrets: [S.other], purpose: c.purpose, context: c.context, envelope: c.envelope }), 'unknown_key')
    }
    // the previous key alone cannot read what the current one wrote
    const current = vectors.cases.find((c) => c.secret === 'current')!
    fails(() => decrypt({ secrets: [S.previous], purpose: current.purpose, context: current.context, envelope: current.envelope }), 'unknown_key')
  })

  it('fails loudly on a truncated envelope', () => {
    const c = vectors.cases[0]
    const raw = Buffer.from(c.envelope, 'base64url')
    for (const len of [0, 1, 5, 17, 32, raw.length - 1]) {
      const cut = raw.subarray(0, len).toString('base64url')
      const code = len === 0 ? 'malformed' : len < 33 ? 'malformed' : 'auth_failed'
      fails(() => decrypt({ secrets: [S.current], purpose: c.purpose, context: c.context, envelope: cut }), code)
    }
  })

  it('fails loudly when any single bit is flipped', () => {
    const c = vectors.cases[0]
    const raw = Buffer.from(c.envelope, 'base64url')
    for (let byte = 0; byte < raw.length; byte++) {
      const bad = Buffer.from(raw)
      bad[byte] ^= 0x01
      const expected = byte === 0 ? 'version' : byte < 5 ? 'unknown_key' : 'auth_failed'
      fails(() => decrypt({ secrets: [S.current], purpose: c.purpose, context: c.context, envelope: bad.toString('base64url') }), expected)
    }
  })

  it('refuses an envelope moved to another record or purpose', () => {
    const c = vectors.cases[0]
    fails(() => decrypt({ secrets: [S.current], purpose: c.purpose, context: 'other.setting', envelope: c.envelope }), 'auth_failed')
    fails(() => decrypt({ secrets: [S.current], purpose: 'totp', context: c.context, envelope: c.envelope }), 'auth_failed')
  })

  it('refuses garbage and an unknown version', () => {
    fails(() => decrypt({ secrets: [S.current], purpose: 'setting', context: 'x', envelope: 'not base64!' }), 'malformed')
    const raw = Buffer.from(vectors.cases[0].envelope, 'base64url')
    raw[0] = 2
    fails(() => decrypt({ secrets: [S.current], purpose: 'setting', context: 'x', envelope: raw.toString('base64url') }), 'version')
  })

  it('needs a real key', () => {
    fails(() => encrypt({ secret: 'short', purpose: 'setting', context: 'x', plaintext: 'y' }), 'no_key')
    fails(() => decrypt({ secrets: [], purpose: 'setting', context: 'x', envelope: vectors.cases[0].envelope }), 'no_key')
  })

  it('uses a fresh nonce every time', () => {
    const a = encrypt({ secret: S.current, purpose: 'setting', context: 'x', plaintext: 'same' })
    const b = encrypt({ secret: S.current, purpose: 'setting', context: 'x', plaintext: 'same' })
    expect(a).not.toBe(b)
  })
})

describe('APP_SECRET rotation', () => {
  it('reads values written under APP_SECRET_PREVIOUS and says so', () => {
    const old = encryptSecret('setting', 'cron.secret', 'value', { APP_SECRET: S.previous })
    const env = { APP_SECRET: S.current, APP_SECRET_PREVIOUS: S.previous }
    expect(decryptSecret('setting', 'cron.secret', old, env)).toEqual({ plaintext: 'value', rotated: true })
    expect(() => decryptSecret('setting', 'cron.secret', old, { APP_SECRET: S.current })).toThrow(EnvelopeError)
  })
})
