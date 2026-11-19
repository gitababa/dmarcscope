// /api/cron/alerts: bearer-protected, and a failed rule is a failed job.

import { NextRequest } from 'next/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ result: { ran: true, rules: 1, opened: 0, resolved: 0, failed: 0, sent: 0, retried: 0 } as Record<string, unknown>, throws: false, calls: 0 }))
vi.mock('@/lib/alerts/run', () => ({
  runAlerts: async () => {
    state.calls++
    if (state.throws) throw new Error('database down')
    return state.result
  },
}))

import { GET, POST } from '@/app/api/cron/alerts/route'

const SECRET = 'c'.repeat(32)
const call = (token: string | null = SECRET) => new NextRequest('http://localhost/api/cron/alerts', { headers: token ? { authorization: `Bearer ${token}` } : {} })

beforeEach(() => {
  process.env.CRON_SECRET = SECRET
  state.calls = 0
  state.throws = false
  state.result = { ran: true, rules: 1, opened: 0, resolved: 0, failed: 0, sent: 0, retried: 0 }
})

describe('/api/cron/alerts', () => {
  it('refuses a request without the token, or with a wrong one, and runs nothing', async () => {
    expect((await GET(call(null))).status).toBe(401)
    expect((await GET(call('wrong'))).status).toBe(401)
    delete process.env.CRON_SECRET
    expect((await GET(call())).status).toBe(401)
    expect(state.calls).toBe(0)
  })
  it('runs on GET and POST', async () => {
    expect((await GET(call())).status).toBe(200)
    expect((await POST(call())).status).toBe(200)
    expect(state.calls).toBe(2)
  })
  it('answers 500 when a rule failed, or the run threw, so a scheduler sees it', async () => {
    state.result = { ...state.result, failed: 1 }
    expect((await GET(call())).status).toBe(500)
    state.throws = true
    const res = await GET(call())
    expect(res.status).toBe(500)
    expect(JSON.stringify(await res.json())).not.toContain('database down')
  })
})
