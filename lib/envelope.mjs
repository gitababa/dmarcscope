// Encrypted envelope for secrets stored in the database (OIDC client secret,
// mailbox credentials, webhook URLs, TOTP seeds, ...).
//
// Plain JavaScript so that the command-line scripts (scripts/*.mjs) can use
// it without a build step; types are in envelope.d.mts. The Python worker has
// a byte-for-byte equivalent in ingestor/crypto.py, and both test suites
// decrypt the shared vectors in tests/vectors/envelope.json.
//
// Format (then base64url, no padding):
//
//   offset  size  field
//   0       1     version          0x01
//   1       4     key identifier   HKDF(APP_SECRET, info "dmarcscope/key-id/v1")[0:4]
//   5       12    nonce            random per encryption
//   17      n     ciphertext       AES-256-GCM
//   17+n    16    tag
//
// Key: HKDF-SHA256(ikm = APP_SECRET, salt = "dmarcscope", info =
// "dmarcscope/secret/v1/" + purpose), 32 bytes, one key per purpose.
// Additional authenticated data: the 5 header bytes, then
// purpose + 0x00 + context (UTF-8). The context names the record the value
// belongs to (a setting key, a user id), so an envelope copied to another
// record or another purpose does not decrypt.
//
// Decryption never falls back to anything: a wrong key, a truncated or
// altered envelope, or an unknown version is an EnvelopeError.

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'

export const VERSION = 1
const HEADER = 5
const NONCE = 12
const TAG = 16
const MIN_SECRET = 32

export class EnvelopeError extends Error {
  /** @param {'malformed' | 'version' | 'unknown_key' | 'auth_failed' | 'no_key'} code */
  constructor(code, message) {
    super(message)
    this.name = 'EnvelopeError'
    this.code = code
  }
}

function checkSecret(secret, name) {
  if (typeof secret !== 'string' || secret.length < MIN_SECRET) {
    throw new EnvelopeError('no_key', `${name} must be set to at least ${MIN_SECRET} random characters.`)
  }
}

function hkdf(secret, info, length) {
  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from('dmarcscope', 'utf8'), Buffer.from(info, 'utf8'), length))
}

export function keyId(secret) {
  checkSecret(secret, 'APP_SECRET')
  return hkdf(secret, 'dmarcscope/key-id/v1', 4)
}

function purposeKey(secret, purpose) {
  return hkdf(secret, `dmarcscope/secret/v1/${purpose}`, 32)
}

function checkLabel(value, name) {
  if (typeof value !== 'string' || !/^[a-z0-9._:-]{1,100}$/.test(value)) {
    throw new EnvelopeError('malformed', `${name} must be a short identifier`)
  }
}

function aad(header, purpose, context) {
  return Buffer.concat([header, Buffer.from(`${purpose}\0${context}`, 'utf8')])
}

/**
 * @param {{ secret: string, purpose: string, context: string, plaintext: string, nonce?: Buffer }} args
 * @returns {string}
 */
export function encrypt({ secret, purpose, context, plaintext, nonce }) {
  checkSecret(secret, 'APP_SECRET')
  checkLabel(purpose, 'purpose')
  checkLabel(context, 'context')
  if (typeof plaintext !== 'string') throw new EnvelopeError('malformed', 'plaintext must be a string')
  const iv = nonce ?? randomBytes(NONCE)
  if (iv.length !== NONCE) throw new EnvelopeError('malformed', 'nonce must be 12 bytes')
  const header = Buffer.concat([Buffer.from([VERSION]), keyId(secret)])
  const cipher = createCipheriv('aes-256-gcm', purposeKey(secret, purpose), iv, { authTagLength: TAG })
  cipher.setAAD(aad(header, purpose, context))
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  return Buffer.concat([header, iv, body, cipher.getAuthTag()]).toString('base64url')
}

/**
 * @param {{ secrets: Array<string | undefined>, purpose: string, context: string, envelope: string }} args
 *   secrets: the current APP_SECRET first, then APP_SECRET_PREVIOUS if set.
 * @returns {{ plaintext: string, keyIndex: number }}
 */
export function decrypt({ secrets, purpose, context, envelope }) {
  checkLabel(purpose, 'purpose')
  checkLabel(context, 'context')
  if (typeof envelope !== 'string' || !/^[A-Za-z0-9_-]+$/.test(envelope)) {
    throw new EnvelopeError('malformed', 'Encrypted value is not base64url text')
  }
  const raw = Buffer.from(envelope, 'base64url')
  if (raw.length < HEADER + NONCE + TAG) throw new EnvelopeError('malformed', 'Encrypted value is truncated')
  if (raw[0] !== VERSION) throw new EnvelopeError('version', `Encrypted value has unknown format version ${raw[0]}`)
  const header = raw.subarray(0, HEADER)
  const kid = raw.subarray(1, HEADER)

  const usable = secrets.filter((s) => typeof s === 'string' && s.length > 0)
  if (usable.length === 0) checkSecret(undefined, 'APP_SECRET')
  const index = usable.findIndex((s) => {
    checkSecret(s, 'APP_SECRET')
    return keyId(s).equals(kid)
  })
  if (index === -1) {
    throw new EnvelopeError('unknown_key', 'Encrypted value was written under a different APP_SECRET (set APP_SECRET_PREVIOUS to the old one)')
  }

  const iv = raw.subarray(HEADER, HEADER + NONCE)
  const tag = raw.subarray(raw.length - TAG)
  const body = raw.subarray(HEADER + NONCE, raw.length - TAG)
  const decipher = createDecipheriv('aes-256-gcm', purposeKey(usable[index], purpose), iv, { authTagLength: TAG })
  decipher.setAAD(aad(header, purpose, context))
  decipher.setAuthTag(tag)
  let out
  try {
    out = Buffer.concat([decipher.update(body), decipher.final()])
  } catch {
    throw new EnvelopeError('auth_failed', 'Encrypted value failed its integrity check (altered, or bound to another record)')
  }
  return { plaintext: out.toString('utf8'), keyIndex: index }
}
