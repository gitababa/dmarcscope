// Server actions re-check the caller themselves: a viewer, or nobody at all,
// must not be able to trigger a DNS check by posting to the action directly.

import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  auth: { status: 'unauthenticated' } as unknown,
  runs: [] as string[],
  outcome: { status: 'ok' } as { status: string },
  cookiesSet: [] as Array<[string, string]>,
}))

class Redirect extends Error {
  constructor(public to: string) {
    super(`redirect:${to}`)
  }
}

vi.mock('next/navigation', () => ({
  redirect: (to: string) => {
    throw new Redirect(to)
  },
}))
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }))
vi.mock('next/headers', () => ({
  cookies: async () => ({ set: (name: string, value: string) => state.cookiesSet.push([name, value]) }),
  headers: async () => new Headers(),
}))
vi.mock('@/lib/auth/server', () => ({
  audit: vi.fn(),
  getAuth: async () => state.auth,
  getAccessWithRole: async (minimum: string) => {
    const a = state.auth as { status: string; session?: { role: string } }
    const rank: Record<string, number> = { viewer: 1, admin: 2, owner: 3 }
    return a.status === 'ok' && rank[a.session!.role] >= rank[minimum] ? { session: a.session, role: a.session!.role, domains: { kind: 'all' } } : null
  },
}))
vi.mock('@/lib/dns-run', async (original) => ({
  ...(await original<typeof import('@/lib/dns-run')>()),
  runAndStoreDnsCheck: async (_scope: unknown, domain: string) => {
    state.runs.push(domain)
    return state.outcome
  },
}))

import { runDnsCheckAction, signOutAction } from '@/app/actions'

const session = (role: 'admin' | 'viewer') => ({
  status: 'ok',
  session: { role, identity: { sub: 'u', email: `${role}@example.com`, groups: [] } },
})
const form = (fields: Record<string, string>) => {
  const f = new FormData()
  for (const [k, v] of Object.entries(fields)) f.set(k, v)
  return f
}
const target = async (p: Promise<void>): Promise<string> => {
  try {
    await p
  } catch (e) {
    if (e instanceof Redirect) return e.to
    throw e
  }
  return 'no redirect'
}

beforeEach(() => {
  state.runs.length = 0
  state.cookiesSet.length = 0
  state.outcome = { status: 'ok' }
  process.env.AUTH_PROVIDER = 'oidc'
  process.env.APP_URL = 'http://localhost:3000'
  delete process.env.OIDC_LOGOUT_AT_IDP
})

describe('runDnsCheckAction', () => {
  it('refuses anyone who is not an admin, before doing anything', async () => {
    for (const auth of [{ status: 'unauthenticated' }, { status: 'forbidden', identity: { email: 'x@example.com' } }, session('viewer')]) {
      state.auth = auth
      expect(await target(runDnsCheckAction(form({ domain: 'example.com' })))).toBe('/denied')
    }
    expect(state.runs).toEqual([])
  })

  it('runs the check for an admin and returns to the domain page, keeping the range', async () => {
    state.auth = session('admin')
    expect(await target(runDnsCheckAction(form({ domain: ' Example.COM ', range: '30d' })))).toBe('/domains/example.com?range=30d')
    expect(state.runs).toEqual(['example.com'])
    state.outcome = { status: 'cooldown' }
    expect(await target(runDnsCheckAction(form({ domain: 'example.com', range: 'bogus' })))).toMatch(/^\/domains\/example\.com\?range=\w+&notice=cooldown$/)
  })

  it('never passes a malformed name to the resolver', async () => {
    state.auth = session('admin')
    for (const domain of ['', 'localhost', 'a b.com', 'example.com/../x', 'http://example.com', '127.0.0.1;rm']) {
      expect(await target(runDnsCheckAction(form({ domain })))).toBe('/')
    }
    expect(state.runs).toEqual([])
  })
})

describe('signOutAction', () => {
  it('expires the session cookie and returns to the login page', async () => {
    state.auth = session('viewer')
    expect(await target(signOutAction())).toBe('/login?signed_out=1')
    expect(state.cookiesSet).toEqual([['dmarcscope_session', '']])
  })

  it('does nothing when sign-in is handled by a proxy', async () => {
    process.env.AUTH_PROVIDER = 'proxy-header'
    expect(await target(signOutAction())).toBe('/')
    expect(state.cookiesSet).toEqual([])
  })
})
