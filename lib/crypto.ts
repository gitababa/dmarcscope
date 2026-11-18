// Cryptography for 2.0, on node:crypto only:
//
//   secrets at rest      AES-256-GCM envelopes under keys derived from
//                        APP_SECRET (format in lib/envelope.mjs)
//   passwords            scrypt, parameters stored in the hash string
//   TOTP                 RFC 6238 (SHA-1, 6 digits, 30-second steps)
//   tokens and codes     random, stored as SHA-256 digests

import { createHash, createHmac, randomBytes, randomInt, scrypt as scryptCb, timingSafeEqual } from 'node:crypto'
import { ConfigError, type Env } from './config'
import { EnvelopeError, decrypt, encrypt } from './envelope.mjs'

export { EnvelopeError }

// ---------- APP_SECRET ----------

export function appSecret(env: Env = process.env): string {
  const s = env.APP_SECRET || ''
  if (s.length < 32) {
    throw new ConfigError('APP_SECRET must be set to at least 32 random characters (generate one with: openssl rand -base64 32).')
  }
  return s
}

function secretsForDecryption(env: Env): string[] {
  const out = [appSecret(env)]
  const previous = env.APP_SECRET_PREVIOUS || ''
  if (previous) {
    if (previous.length < 32) throw new ConfigError('APP_SECRET_PREVIOUS must be at least 32 characters when set.')
    out.push(previous)
  }
  return out
}

// Purposes the web app may both encrypt and decrypt. 'mailbox' is not one of
// them: mailbox credentials are encrypted here (encryptMailboxSecret) and
// decrypted only by the worker, so they are never readable through the web app.
export type SecretPurpose = 'setting' | 'totp'

export function encryptMailboxSecret(context: string, plaintext: string, env: Env = process.env): string {
  return encrypt({ secret: appSecret(env), purpose: 'mailbox', context, plaintext })
}

export function encryptSecret(purpose: SecretPurpose, context: string, plaintext: string, env: Env = process.env): string {
  return encrypt({ secret: appSecret(env), purpose, context, plaintext })
}

// Throws EnvelopeError (never returns a fallback) when the value cannot be
// decrypted. `rotated` tells the caller the value is under APP_SECRET_PREVIOUS.
export function decryptSecret(
  purpose: SecretPurpose,
  context: string,
  envelope: string,
  env: Env = process.env
): { plaintext: string; rotated: boolean } {
  if (purpose !== 'setting' && purpose !== 'totp') throw new Error(`purpose ${String(purpose)} cannot be decrypted by the web app`)
  const { plaintext, keyIndex } = decrypt({ secrets: secretsForDecryption(env), purpose, context, envelope })
  return { plaintext, rotated: keyIndex > 0 }
}

// ---------- digests and random values ----------

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

export function constantTimeEqual(a: string, b: string): boolean {
  const x = createHash('sha256').update(a, 'utf8').digest()
  const y = createHash('sha256').update(b, 'utf8').digest()
  return timingSafeEqual(x, y) && a.length === b.length
}

// ---------- passwords (scrypt) ----------

// OWASP's scrypt equivalents: N=2^15, r=8, p=3 needs 32 MiB per hash, which a
// small container can afford for concurrent sign-ins (N=2^17 needs 128 MiB).
// The parameters are part of the stored string, so they can be raised later
// without invalidating existing hashes.
const SCRYPT = { N: 2 ** 15, r: 8, p: 3, keylen: 32 }
const SCRYPT_LIMITS = { maxN: 2 ** 20, maxR: 32, maxP: 16 }

function scrypt(password: string, salt: Buffer, N: number, r: number, p: number, keylen: number): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scryptCb(password.normalize('NFKC'), salt, keylen, { N, r, p, maxmem: 256 * N * r + 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key)
    )
  )
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const { N, r, p, keylen } = SCRYPT
  const key = await scrypt(password, salt, N, r, p, keylen)
  return `scrypt$N=${N},r=${r},p=${p}$${salt.toString('base64url')}$${key.toString('base64url')}`
}

// A stored hash that cannot be parsed is an error, not a failed comparison:
// it means the row is corrupt, and the caller should say so in the log.
export class PasswordHashError extends Error {}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const m = /^scrypt\$N=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9_-]{16,})\$([A-Za-z0-9_-]{32,})$/.exec(stored)
  if (!m) throw new PasswordHashError('Stored password hash has an unknown format')
  const [N, r, p] = [Number(m[1]), Number(m[2]), Number(m[3])]
  if (N < 2 || (N & (N - 1)) !== 0 || N > SCRYPT_LIMITS.maxN || r < 1 || r > SCRYPT_LIMITS.maxR || p < 1 || p > SCRYPT_LIMITS.maxP) {
    throw new PasswordHashError('Stored password hash has out-of-range parameters')
  }
  const salt = Buffer.from(m[4], 'base64url')
  const expected = Buffer.from(m[5], 'base64url')
  const actual = await scrypt(password, salt, N, r, p, expected.length)
  return timingSafeEqual(actual, expected)
}

// Verifies against a fixed dummy hash, so that "no such account" costs the
// same time as "wrong password".
let dummyHash: Promise<string> | null = null
export async function burnPasswordCheck(password: string): Promise<void> {
  dummyHash ??= hashPassword(randomToken(16))
  await verifyPassword(password, await dummyHash)
}

// ---------- TOTP (RFC 6238) ----------

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32Encode(buf: Buffer): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buf) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=]/g, '').toUpperCase()
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const ch of clean) {
    const idx = B32.indexOf(ch)
    if (idx === -1) throw new Error('Invalid base32 character')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

export const TOTP_STEP_SECONDS = 30
export const TOTP_DIGITS = 6

export function newTotpSecret(): string {
  return base32Encode(randomBytes(20))
}

export function totpStep(nowMs = Date.now()): number {
  return Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS)
}

export function hotp(secret: Buffer, counter: number, digits = TOTP_DIGITS, algorithm: 'sha1' | 'sha256' | 'sha512' = 'sha1'): string {
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(counter))
  const mac = createHmac(algorithm, secret).update(msg).digest()
  const offset = mac[mac.length - 1] & 0x0f
  const code = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]
  return String(code % 10 ** digits).padStart(digits, '0')
}

export function totpCode(secretBase32: string, step = totpStep()): string {
  return hotp(base32Decode(secretBase32), step)
}

// Returns the step the code belongs to (current, one before or one after,
// to allow for clock drift), or null. The caller must refuse a step at or
// below the last one accepted for this account: that is what makes a code
// single-use.
export function matchTotp(secretBase32: string, code: string, nowMs = Date.now()): number | null {
  const clean = code.replace(/\s/g, '')
  if (!/^\d{6}$/.test(clean)) return null
  const key = base32Decode(secretBase32)
  const now = totpStep(nowMs)
  let found: number | null = null
  for (const step of [now - 1, now, now + 1]) {
    // Compare every candidate so timing does not depend on which matched.
    if (timingSafeEqual(Buffer.from(hotp(key, step)), Buffer.from(clean)) && found === null) found = step
  }
  return found
}

export function otpauthUri(secretBase32: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`)
  const q = new URLSearchParams({ secret: secretBase32, issuer, algorithm: 'SHA1', digits: String(TOTP_DIGITS), period: String(TOTP_STEP_SECONDS) })
  return `otpauth://totp/${label}?${q}`
}

// ---------- recovery codes ----------

// Ten codes of 16 base32 characters (80 bits each), shown as xxxx-xxxx-xxxx-xxxx.
// That much entropy makes a plain SHA-256 digest a safe way to store them.
export function newRecoveryCodes(count = 10): string[] {
  return Array.from({ length: count }, () => {
    let s = ''
    for (let i = 0; i < 16; i++) s += B32[randomInt(32)]
    return s.toLowerCase().match(/.{4}/g)!.join('-')
  })
}

export function normalizeRecoveryCode(input: string): string | null {
  const clean = input.replace(/[\s-]/g, '').toLowerCase()
  return /^[a-z2-7]{16}$/.test(clean) ? clean : null
}

export function hashRecoveryCode(code: string): string {
  return sha256Hex(`recovery:${normalizeRecoveryCode(code) ?? ''}`)
}
