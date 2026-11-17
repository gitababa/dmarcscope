import { describe, expect, it } from 'vitest'
import {
  PasswordHashError,
  base32Decode,
  base32Encode,
  hashPassword,
  hashRecoveryCode,
  hotp,
  matchTotp,
  newRecoveryCodes,
  newTotpSecret,
  normalizeRecoveryCode,
  otpauthUri,
  totpCode,
  verifyPassword,
} from '@/lib/crypto'
import { passwordProblem } from '@/lib/auth/password-policy'

describe('TOTP (RFC 6238)', () => {
  // Appendix B: the SHA-1 seed is the ASCII string "12345678901234567890",
  // codes are 8 digits, 30-second steps from T0 = 0.
  const seed = Buffer.from('12345678901234567890')
  const vectors: Array<[number, string]> = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ]
  it.each(vectors)('at t=%i the code is %s', (t, code) => {
    expect(hotp(seed, Math.floor(t / 30), 8)).toBe(code)
  })

  it('round-trips base32', () => {
    expect(base32Encode(seed)).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
    expect(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ').equals(seed)).toBe(true)
    expect(() => base32Decode('not base32!')).toThrow()
  })

  it('accepts the current step and one either side, and nothing else', () => {
    const secret = newTotpSecret()
    const now = 1_800_000_000_000
    const step = Math.floor(now / 30_000)
    for (const offset of [-1, 0, 1]) expect(matchTotp(secret, totpCode(secret, step + offset), now)).toBe(step + offset)
    for (const offset of [-3, -2, 2, 3]) expect(matchTotp(secret, totpCode(secret, step + offset), now)).toBeNull()
  })

  it('refuses malformed codes and another secret', () => {
    const secret = newTotpSecret()
    const code = totpCode(secret)
    expect(matchTotp(secret, '12345')).toBeNull()
    expect(matchTotp(secret, 'abcdef')).toBeNull()
    expect(matchTotp(secret, `${code}0`)).toBeNull()
    expect(matchTotp(newTotpSecret(), code)).toBeNull()
    expect(matchTotp(secret, `${code.slice(0, 3)} ${code.slice(3)}`)).not.toBeNull()
  })

  it('builds an otpauth URI', () => {
    const uri = otpauthUri('ABCD', 'owner@example.com', 'DMARCscope')
    expect(uri).toBe('otpauth://totp/DMARCscope%3Aowner%40example.com?secret=ABCD&issuer=DMARCscope&algorithm=SHA1&digits=6&period=30')
  })
})

describe('password hashing (scrypt)', () => {
  it('stores its parameters and verifies', async () => {
    const hash = await hashPassword('correct horse battery')
    expect(hash).toMatch(/^scrypt\$N=32768,r=8,p=3\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/)
    expect(await verifyPassword('correct horse battery', hash)).toBe(true)
    expect(await verifyPassword('correct horse batterz', hash)).toBe(false)
    expect(await hashPassword('correct horse battery')).not.toBe(hash) // salted
  })

  it('verifies hashes made with other parameters (so they can be raised later)', async () => {
    const hash = await hashPassword('another password')
    const weaker = hash.replace('N=32768,r=8,p=3', 'N=16384,r=8,p=1')
    // same salt and key under other parameters: must not verify
    expect(await verifyPassword('another password', weaker)).toBe(false)
  })

  it('treats a malformed or absurd stored hash as an error, not a mismatch', async () => {
    for (const bad of ['', 'plain', 'scrypt$N=3,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$' + 'A'.repeat(43), 'scrypt$N=1073741824,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$' + 'A'.repeat(43)]) {
      await expect(verifyPassword('x', bad)).rejects.toBeInstanceOf(PasswordHashError)
    }
  })
})

describe('recovery codes', () => {
  it('are ten distinct 80-bit codes, matched loosely but stored exactly', () => {
    const codes = newRecoveryCodes()
    expect(codes).toHaveLength(10)
    expect(new Set(codes).size).toBe(10)
    for (const c of codes) expect(c).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/)
    const c = codes[0]
    expect(hashRecoveryCode(c.toUpperCase().replace(/-/g, ' '))).toBe(hashRecoveryCode(c))
    expect(normalizeRecoveryCode('not-a-code')).toBeNull()
  })
})

describe('password policy', () => {
  it('refuses short, long, common, repetitive and self-referencing passwords', () => {
    expect(passwordProblem('short', 'a@example.com')).toMatch(/at least 12/)
    expect(passwordProblem('x'.repeat(257), 'a@example.com')).toMatch(/at most/)
    expect(passwordProblem('Password1234', 'a@example.com')).toMatch(/common/)
    expect(passwordProblem('123456789012', 'a@example.com')).toMatch(/common/)
    expect(passwordProblem('abababababab', 'a@example.com')).toMatch(/repeats/)
    expect(passwordProblem('jane.doe.smith', 'jane.doe.smith@example.com')).toMatch(/email/)
    expect(passwordProblem('quiet violet lantern', 'a@example.com')).toBeNull()
  })
})
