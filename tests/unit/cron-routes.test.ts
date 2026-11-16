// The bearer-protected machine endpoints.

import { NextRequest } from 'next/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  domains: ['a.example', 'b.example'],
  fail: new Set<string>(),
  checked: [] as string[],
  health: { status: 'ok' } as Record<string, unknown>,
}))

vi.mock('@/lib/queries', () => ({
  getDomainNames: async () => state.domains,
  getIngestHealth: async () => {
    if (state.health.throw) throw new Error('connection refused')
    return state.health
  },
}))
vi.mock('@/lib/dns-run', async (original) => ({
  ...(await original<typeof import('@/lib/dns-run')>()),
  runAndStoreDnsCheck: async (domain: string) => {
    state.checked.push(domain)
    if (state.fail.has(domain)) throw new Error('resolver down')
    if (domain === 'unknown.example') return { status: 'unknown_domain' }
    const ok = { status: 'ok' }
    return { status: 'ok', results: { mx: ok, spf: ok, dmarc: ok, dkim: ok } }
  },
}))

import { GET as dnsCheck } from '@/app/api/cron/dns-check/route'
import { GET as status } from '@/app/api/cron/status/route'

const SECRET = 'c'.repeat(32)
const call = (path: string, token: string | null = SECRET) =>
  new NextRequest(`http://localhost${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} })

beforeEach(() => {
  process.env.CRON_SECRET = SECRET
  state.fail.clear()
  state.checked.length = 0
  state.health = { status: 'ok' }
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('/api/cron/dns-check', () => {
  it('does nothing without the exact token, or while no secret is configured', async () => {
    expect((await dnsCheck(call('/api/cron/dns-check', null))).status).toBe(401)
    expect((await dnsCheck(call('/api/cron/dns-check', 'wrong'))).status).toBe(401)
    delete process.env.CRON_SECRET
    expect((await dnsCheck(call('/api/cron/dns-check', 'undefined'))).status).toBe(401)
    process.env.CRON_SECRET = 'short'
    expect((await dnsCheck(call('/api/cron/dns-check', 'short'))).status).toBe(401)
    expect(state.checked).toEqual([])
  })

  it('checks every tracked domain', async () => {
    const res = await dnsCheck(call('/api/cron/dns-check'))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ok: true, checked: 2, failed: 0 })
    expect(state.checked.sort()).toEqual(['a.example', 'b.example'])
  })

  it('still succeeds when some domains fail, but not when all do', async () => {
    state.fail.add('a.example')
    const partial = await dnsCheck(call('/api/cron/dns-check'))
    expect(partial.status).toBe(200)
    expect(await partial.json()).toMatchObject({ ok: true, failed: 1, results: { 'a.example': 'error' } })

    state.fail.add('b.example')
    const all = await dnsCheck(call('/api/cron/dns-check'))
    expect(all.status).toBe(500)
    expect(await all.json()).toMatchObject({ ok: false, checked: 2, failed: 2 })
  })

  it('validates the single-domain form', async () => {
    expect((await dnsCheck(call('/api/cron/dns-check?domain=not%20a%20domain'))).status).toBe(400)
    expect((await dnsCheck(call('/api/cron/dns-check?domain=unknown.example'))).status).toBe(404)
    expect((await dnsCheck(call('/api/cron/dns-check?domain=A.Example'))).status).toBe(200)
    expect(state.checked).toEqual(['unknown.example', 'a.example'])
  })
})

describe('/api/cron/status', () => {
  it('requires the token', async () => {
    expect((await status(call('/api/cron/status', null))).status).toBe(401)
  })

  it('is 200 only while ingest is healthy', async () => {
    expect((await status(call('/api/cron/status'))).status).toBe(200)
    for (const s of ['stale', 'never']) {
      state.health = { status: s }
      const res = await status(call('/api/cron/status'))
      expect(res.status).toBe(503)
      expect(await res.json()).toMatchObject({ ok: false, status: s })
    }
    state.health = { throw: true }
    const down = await status(call('/api/cron/status'))
    expect(down.status).toBe(503)
    expect(await down.json()).toEqual({ ok: false, error: 'database unavailable' })
  })
})
