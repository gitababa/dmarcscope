// The rules of milestone 6 that need no database: how a person's domain scope
// is resolved, token formats and validation, scope input, SCIM filters.

import { describe, expect, it } from 'vitest'
import { TokenRefusal, bearer, hashToken, newToken, validateToken } from '@/lib/api-tokens'
import { ScopeRefusal, parseScope } from '@/lib/access-admin'
import { type ScopeRow, allDomains, assertScope, intersectScopes, limitedTo, resolveScope, scopeAllows, scopeNames } from '@/lib/auth/access'
import { ScimError, parseFilter } from '@/lib/scim'

const limited = (...domains: string[]): ScopeRow => ({ kind: 'user', mode: 'limited', domains })
const all = (): ScopeRow => ({ kind: 'user', mode: 'all', domains: [] })
const group = (mode: 'all' | 'limited', ...domains: string[]): ScopeRow => ({ kind: 'group', mode, domains })

describe('domain scope resolution', () => {
  const base = { role: 'viewer' as const, own: null, groups: [] as ScopeRow[], defaultMode: 'all' as const }
  const names = (s: ReturnType<typeof resolveScope>) => scopeNames(s)

  it('gives owners and administrators every domain, whatever rows say', () => {
    for (const role of ['owner', 'admin'] as const) {
      expect(names(resolveScope({ ...base, role, own: limited('a.example'), defaultMode: 'none' }))).toBeNull()
    }
  })

  it('keeps today’s behaviour when nothing is configured', () => {
    expect(names(resolveScope(base))).toBeNull()
  })

  it('shows a viewer with no rows nothing when the default is none', () => {
    expect(names(resolveScope({ ...base, defaultMode: 'none' }))).toEqual([])
  })

  it('limits a viewer to their grants, and an empty list sees nothing, not everything', () => {
    expect(names(resolveScope({ ...base, own: limited('b.example', 'a.example') }))).toEqual(['a.example', 'b.example'])
    expect(names(resolveScope({ ...base, own: limited() }))).toEqual([])
  })

  it('lets the person’s own row beat their groups', () => {
    expect(names(resolveScope({ ...base, own: all(), groups: [group('limited', 'a.example')] }))).toBeNull()
    expect(names(resolveScope({ ...base, own: limited('a.example'), groups: [group('all')] }))).toEqual(['a.example'])
  })

  it('adds the grants of limited groups to a limited person', () => {
    const s = resolveScope({ ...base, own: limited('a.example'), groups: [group('limited', 'b.example'), group('all')] })
    expect(names(s)).toEqual(['a.example', 'b.example'])
  })

  it('unions limited groups, and one "all" group makes everything visible when there is no own row', () => {
    expect(names(resolveScope({ ...base, groups: [group('limited', 'a.example'), group('limited', 'b.example')] }))).toEqual(['a.example', 'b.example'])
    expect(names(resolveScope({ ...base, groups: [group('limited', 'a.example'), group('all')] }))).toBeNull()
  })

  it('treats a group that has a row but no grants as seeing nothing', () => {
    expect(names(resolveScope({ ...base, groups: [group('limited')] }))).toEqual([])
  })

  it('lower-cases and de-duplicates names', () => {
    expect(names(limitedTo(['A.Example', 'a.example ', 'b.example']))).toEqual(['a.example', 'b.example'])
  })
})

describe('scopes', () => {
  it('refuses anything that is not a scope from the authorization function', () => {
    expect(() => assertScope({ kind: 'all' })).toThrow(/domain scope/)
    expect(() => assertScope(undefined)).toThrow(/domain scope/)
    expect(() => assertScope(allDomains())).not.toThrow()
  })

  it('intersects without ever widening', () => {
    expect(scopeNames(intersectScopes(allDomains(), limitedTo(['a.example'])))).toEqual(['a.example'])
    expect(scopeNames(intersectScopes(limitedTo(['a.example', 'b.example']), limitedTo(['b.example', 'c.example'])))).toEqual(['b.example'])
    expect(scopeNames(intersectScopes(limitedTo(['a.example']), limitedTo(['b.example'])))).toEqual([])
    expect(scopeNames(intersectScopes(allDomains(), allDomains()))).toBeNull()
  })

  it('allows a domain case-insensitively, and nothing outside', () => {
    const s = limitedTo(['a.example'])
    expect(scopeAllows(s, 'A.EXAMPLE')).toBe(true)
    expect(scopeAllows(s, 'b.example')).toBe(false)
    expect(scopeAllows(allDomains(), 'anything.example')).toBe(true)
  })
})

describe('scope input', () => {
  it('parses all and limited, normalizing domains', () => {
    expect(parseScope({ mode: 'limited', domains: 'A.example, b.example\nb.example' })).toEqual({ mode: 'limited', domains: ['a.example', 'b.example'] })
    expect(parseScope({ mode: 'all', domains: 'ignored.example' })).toEqual({ mode: 'all', domains: [] })
    expect(parseScope({ mode: 'limited', domains: '' })).toEqual({ mode: 'limited', domains: [] })
  })

  it('refuses a bad mode and a bad domain', () => {
    expect(() => parseScope({ mode: 'some', domains: '' })).toThrow(ScopeRefusal)
    expect(() => parseScope({ mode: null, domains: '' })).toThrow(ScopeRefusal)
    expect(() => parseScope({ mode: 'limited', domains: 'not a domain!' })).toThrow(ScopeRefusal)
    expect(() => parseScope({ mode: 'limited', domains: 'a.example, -bad-.example-' })).toThrow(ScopeRefusal)
  })
})

describe('tokens', () => {
  it('makes tokens with a kind prefix and stores only their hash', () => {
    const a = newToken('api')
    const s = newToken('scim')
    expect(a.token).toMatch(/^dsa_[A-Za-z0-9_-]{43}$/)
    expect(s.token).toMatch(/^dss_[A-Za-z0-9_-]{43}$/)
    expect(a.hash).toBe(hashToken(a.token))
    expect(a.hash).not.toContain(a.token.slice(4, 20))
    expect(a.hash).toHaveLength(64)
    expect(newToken('api').token).not.toBe(a.token)
    expect(a.prefix).toBe(a.token.slice(0, 8))
  })

  it('reads only a well-formed bearer header', () => {
    const t = newToken('api').token
    expect(bearer(`Bearer ${t}`)).toBe(t)
    for (const bad of [null, undefined, '', t, `bearer ${t}`, `Bearer  ${t}`, `Bearer ${t} extra`, 'Bearer short', `Basic ${t}`, `Bearer ${t}x`]) {
      expect(bearer(bad as string | null | undefined)).toBeNull()
    }
  })

  it('validates a new token', () => {
    const ok = validateToken({ name: ' Reporting ', scopes: ['domains:read', 'dns:read'], mode: 'limited', domains: 'A.example', expiresInDays: '30' })
    expect(ok).toEqual({ name: 'Reporting', scopes: ['domains:read', 'dns:read'], mode: 'limited', domains: ['a.example'], expiresInDays: 30 })
    expect(validateToken({ name: 'x', scopes: ['domains:read'], mode: 'all', domains: 'ignored.example', expiresInDays: '' }).domains).toEqual([])
    expect(validateToken({ name: 'x', scopes: ['domains:read'], mode: 'all', domains: '', expiresInDays: '' }).expiresInDays).toBe(90)
  })

  it('refuses a bad name, scope, mode, domain or expiry', () => {
    const good = { name: 'x', scopes: ['domains:read'], mode: 'all', domains: '', expiresInDays: '10' }
    const refuse = (patch: Partial<typeof good>, field: string) => {
      try {
        validateToken({ ...good, ...patch })
        throw new Error('not refused')
      } catch (e) {
        expect(e).toBeInstanceOf(TokenRefusal)
        expect((e as TokenRefusal).field).toBe(field)
      }
    }
    refuse({ name: ' ' }, 'name')
    refuse({ name: 'x'.repeat(101) }, 'name')
    refuse({ scopes: [] }, 'scopes')
    refuse({ scopes: ['admin:write'] }, 'scopes')
    refuse({ mode: 'everything' }, 'mode')
    refuse({ mode: 'limited', domains: 'nope!' }, 'domains')
    refuse({ expiresInDays: '0' }, 'expires')
    refuse({ expiresInDays: '366' }, 'expires')
    refuse({ expiresInDays: 'soon' }, 'expires')
    refuse({ expiresInDays: '-5' }, 'expires')
  })
})

describe('SCIM filters', () => {
  it('accepts eq on the supported attributes only', () => {
    expect(parseFilter('userName eq "Ann@Example.com"', ['userName', 'externalId'])).toEqual({ attr: 'userName', value: 'Ann@Example.com' })
    expect(parseFilter('USERNAME EQ "x"', ['userName'])).toEqual({ attr: 'userName', value: 'x' })
    expect(parseFilter('displayName eq "Say \\"hi\\""', ['displayName'])).toEqual({ attr: 'displayName', value: 'Say "hi"' })
    expect(parseFilter(null, ['userName'])).toBeNull()
  })

  it('refuses everything else as invalidFilter', () => {
    for (const f of ['userName co "a"', 'userName eq a', 'active eq "true"', 'userName eq "a" and externalId eq "b"', 'emails[type eq "work"]', 'userName pr', 'password eq "x"']) {
      try {
        parseFilter(f, ['userName', 'externalId'])
        throw new Error(`accepted ${f}`)
      } catch (e) {
        expect(e).toBeInstanceOf(ScimError)
        expect((e as ScimError).scimType).toBe('invalidFilter')
        expect((e as ScimError).status).toBe(400)
      }
    }
  })
})
