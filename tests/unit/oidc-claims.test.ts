import { describe, expect, it } from 'vitest'
import { LoginError, identityFromClaims, parseRequiredClaims } from '@/lib/auth/oidc'

const base = { sub: 'u1', email: 'Ada@Example.com', email_verified: true, name: 'Ada' }

const codeOf = (fn: () => unknown): string => {
  try {
    fn()
  } catch (e) {
    return e instanceof LoginError ? e.code : `threw ${String(e)}`
  }
  return 'accepted'
}

describe('identityFromClaims', () => {
  it('accepts a verified email and lower-cases it', () => {
    expect(identityFromClaims(base, {})).toEqual({ sub: 'u1', email: 'ada@example.com', name: 'Ada', groups: [] })
  })

  it('keeps only the groups that access rules refer to', () => {
    const id = identityFromClaims({ ...base, groups: ['staff', 'DMARC-Admins', 'x'] }, { ADMIN_GROUPS: 'dmarc-admins' })
    expect(id.groups).toEqual(['DMARC-Admins'])
  })

  it('refuses an email that is not explicitly verified', () => {
    expect(codeOf(() => identityFromClaims({ ...base, email_verified: false }, {}))).toBe('unverified_email')
    // absent, or "true" as a string, is not a verification
    expect(codeOf(() => identityFromClaims({ sub: 'u1', email: 'a@example.com' }, {}))).toBe('unverified_email')
    expect(codeOf(() => identityFromClaims({ ...base, email_verified: 'true' }, {}))).toBe('unverified_email')
    expect(codeOf(() => identityFromClaims({ sub: 'u1', email: 'a@example.com' }, { OIDC_ALLOW_UNVERIFIED_EMAIL: 'true' }))).toBe('accepted')
  })

  it('does not fall back to other claims for the address', () => {
    const entra = { sub: 'u1', preferred_username: 'ada@example.com', upn: 'ada@example.com' }
    expect(codeOf(() => identityFromClaims(entra, {}))).toBe('no_email')
    // ...unless the operator names the claim
    expect(identityFromClaims(entra, { OIDC_EMAIL_CLAIM: 'preferred_username' }).email).toBe('ada@example.com')
  })

  it('refuses a missing subject or a non-address', () => {
    expect(codeOf(() => identityFromClaims({ email: 'a@example.com', email_verified: true }, {}))).toBe('failed')
    expect(codeOf(() => identityFromClaims({ ...base, email: 'not-an-address' }, {}))).toBe('no_email')
    expect(codeOf(() => identityFromClaims({ ...base, email: ['a@example.com'] }, {}))).toBe('no_email')
  })

  it('enforces required claims before anything else', () => {
    const env = { OIDC_REQUIRED_CLAIMS: 'hd=example.com' }
    expect(codeOf(() => identityFromClaims({ ...base, hd: 'example.com' }, env))).toBe('accepted')
    // a personal account with a work address has no hd claim at all
    expect(codeOf(() => identityFromClaims(base, env))).toBe('wrong_account')
    expect(codeOf(() => identityFromClaims({ ...base, hd: 'evil.test' }, env))).toBe('wrong_account')
    expect(codeOf(() => identityFromClaims({ ...base, hd: 'Example.com' }, env))).toBe('wrong_account') // exact match
    expect(codeOf(() => identityFromClaims({ ...base, hd: { toString: () => 'example.com' } }, env))).toBe('wrong_account')
  })

  it('supports alternatives, several claims and list-valued claims', () => {
    const env = { OIDC_REQUIRED_CLAIMS: ' tid = 1111|2222 , roles=dmarc ' }
    expect(codeOf(() => identityFromClaims({ ...base, tid: '2222', roles: ['other', 'dmarc'] }, env))).toBe('accepted')
    expect(codeOf(() => identityFromClaims({ ...base, tid: '3333', roles: ['dmarc'] }, env))).toBe('wrong_account')
    expect(codeOf(() => identityFromClaims({ ...base, tid: '1111', roles: ['other'] }, env))).toBe('wrong_account')
  })
})

describe('parseRequiredClaims', () => {
  it('parses pairs and ignores empty entries', () => {
    expect(parseRequiredClaims(undefined)).toEqual([])
    expect(parseRequiredClaims('hd=example.com,,tid=a|b')).toEqual([
      { claim: 'hd', values: ['example.com'] },
      { claim: 'tid', values: ['a', 'b'] },
    ])
  })
  it('rejects a malformed value instead of silently requiring nothing', () => {
    for (const bad of ['hd', 'hd=', '=x', 'hd=|']) {
      expect(() => parseRequiredClaims(bad)).toThrow(/OIDC_REQUIRED_CLAIMS/)
    }
  })
})
