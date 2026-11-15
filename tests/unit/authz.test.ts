import { describe, expect, it } from 'vitest'
import { relevantGroups, resolveRole } from '@/lib/auth/authz'

const id = (email: string, groups: string[] = []) => ({ sub: 's', email, groups })

describe('resolveRole', () => {
  it('denies everyone when no access rule is configured', () => {
    expect(resolveRole(id('a@example.com'), {})).toBeNull()
  })

  it('grants admin by email, case-insensitively', () => {
    expect(resolveRole(id('Boss@Example.com'), { ADMIN_EMAILS: 'x@example.com, boss@example.com' })).toBe('admin')
  })

  it('grants viewer by email, domain or group', () => {
    expect(resolveRole(id('a@example.com'), { ALLOWED_EMAILS: 'a@example.com' })).toBe('viewer')
    expect(resolveRole(id('a@example.com'), { ALLOWED_EMAIL_DOMAINS: 'example.com' })).toBe('viewer')
    expect(resolveRole(id('a@other.com', ['Mail-Team']), { ALLOWED_GROUPS: 'mail-team' })).toBe('viewer')
  })

  it('does not treat a lookalike domain as allowed', () => {
    const env = { ALLOWED_EMAIL_DOMAINS: 'example.com' }
    expect(resolveRole(id('a@notexample.com'), env)).toBeNull()
    expect(resolveRole(id('a@example.com.evil.test'), env)).toBeNull()
    expect(resolveRole(id('example.com'), env)).toBeNull()
  })

  it('admin group wins over viewer rules', () => {
    expect(resolveRole(id('a@example.com', ['admins']), { ADMIN_GROUPS: 'admins', ALLOWED_EMAILS: 'a@example.com' })).toBe('admin')
  })

  it('AUTH_ALLOW_ANY_AUTHENTICATED opens viewing only', () => {
    expect(resolveRole(id('anyone@anywhere.test'), { AUTH_ALLOW_ANY_AUTHENTICATED: 'true' })).toBe('viewer')
  })

  it('rejects an empty email', () => {
    expect(resolveRole(id(''), { AUTH_ALLOW_ANY_AUTHENTICATED: 'true' })).toBeNull()
  })
})

describe('relevantGroups', () => {
  it('keeps only groups that affect authorization', () => {
    const env = { ADMIN_GROUPS: 'admins', ALLOWED_GROUPS: 'viewers' }
    expect(relevantGroups(['Admins', 'everyone', 'viewers', 'hr'], env)).toEqual(['Admins', 'viewers'])
    expect(relevantGroups(['a', 'b'], {})).toEqual([])
  })
})
