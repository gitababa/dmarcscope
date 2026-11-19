import { describe, expect, it, vi } from 'vitest'
import { TRIGGER_HEADER, startsWorkItself, triggerIngest, triggerSignature, triggerTarget } from '@/lib/ingest-trigger'
import { passStatus } from '@/lib/mail'

const SECRET = 'a'.repeat(40)
const prod = {
  VERCEL: '1',
  VERCEL_ENV: 'production',
  VERCEL_URL: 'dmarcscope-abc123-team.vercel.app',
  VERCEL_PROJECT_PRODUCTION_URL: 'dmarc.example.com',
  APP_SECRET: SECRET,
}

describe('triggerSignature', () => {
  it('matches the worker (same vector as ingestor/tests/test_vercel_adapter.py)', () => {
    expect(triggerSignature('s'.repeat(32), 1795000000, 'job:12')).toBe('99b494f413376a057b621dedf83fbb4c010022ff48837930ccb621affcab7887')
  })
})

describe('triggerTarget', () => {
  it('does nothing outside Vercel: a long-running worker picks the request up', () => {
    expect(startsWorkItself({})).toBe(false)
    expect(triggerTarget('job:1', { APP_SECRET: SECRET })).toBeNull()
  })

  it('calls the production domain in production, never the protected deployment URL', () => {
    const t = triggerTarget('job:7', prod, 1795000000_000)!
    expect(t.url).toBe('https://dmarc.example.com/api/cron/ingest?task=job%3A7')
    expect(t.headers[TRIGGER_HEADER]).toBe(`1795000000.${triggerSignature(SECRET, 1795000000, 'job:7')}`)
    expect(t.headers['x-vercel-protection-bypass']).toBeUndefined()
  })

  it('calls the deployment itself on a preview, with the bypass secret when there is one', () => {
    const t = triggerTarget('release', { ...prod, VERCEL_ENV: 'preview', VERCEL_AUTOMATION_BYPASS_SECRET: 'bypass-1' })!
    expect(t.url).toBe('https://dmarcscope-abc123-team.vercel.app/api/cron/ingest?task=release')
    expect(t.headers['x-vercel-protection-bypass']).toBe('bypass-1')
  })

  it('refuses without a usable APP_SECRET or address', () => {
    expect(triggerTarget('job:1', { ...prod, APP_SECRET: 'short' })).toBeNull()
    expect(triggerTarget('job:1', { ...prod, VERCEL_PROJECT_PRODUCTION_URL: undefined, VERCEL_URL: undefined })).toBeNull()
    expect(triggerTarget('job:1', { ...prod, VERCEL_PROJECT_PRODUCTION_URL: 'evil.example/x?y=' })).toBeNull()
  })
})

describe('triggerIngest', () => {
  const reply = (status: number, body: unknown) => vi.fn(async () => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status }))

  it('reports success', async () => {
    const fetchImpl = reply(200, { ok: true })
    expect(await triggerIngest('job:3', { timeoutMs: 1000, env: prod, fetchImpl })).toEqual({ ok: true })
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toContain('task=job%3A3')
    expect(init.method).toBe('POST')
    expect(init.redirect).toBe('manual')
  })

  it('tells Deployment Protection apart from a signature the function refused', async () => {
    const vercel = await triggerIngest('job:3', { timeoutMs: 1000, env: prod, fetchImpl: reply(401, '<html>Authentication Required</html>') })
    expect(vercel).toMatchObject({ ok: false, timedOut: false })
    expect(!vercel.ok && vercel.reason).toMatch(/Protection Bypass for Automation/)

    const ours = await triggerIngest('job:3', { timeoutMs: 1000, env: prod, fetchImpl: reply(401, { ok: false, error: 'unauthorized' }) })
    expect(!ours.ok && ours.reason).toMatch(/APP_SECRET/)
  })

  it('passes on a configuration error and treats a timeout as still running', async () => {
    const failed = await triggerIngest('job:3', { timeoutMs: 1000, env: prod, fetchImpl: reply(500, { ok: false, error: 'configuration: Missing required setting: DATABASE_URL' }) })
    expect(!failed.ok && failed.reason).toMatch(/HTTP 500.*DATABASE_URL/)

    const slow = vi.fn(async () => {
      throw Object.assign(new Error('timed out'), { name: 'TimeoutError' })
    })
    expect(await triggerIngest('job:3', { timeoutMs: 1000, env: prod, fetchImpl: slow })).toEqual({ ok: false, timedOut: true, reason: 'still running' })

    const down = vi.fn(async () => {
      throw new TypeError('fetch failed')
    })
    const unreachable = await triggerIngest('job:3', { timeoutMs: 1000, env: prod, fetchImpl: down })
    expect(unreachable).toMatchObject({ ok: false, timedOut: false })
  })

  it('does not call anything when it cannot sign', async () => {
    const fetchImpl = reply(200, {})
    const r = await triggerIngest('job:3', { timeoutMs: 1000, env: { ...prod, APP_SECRET: '' }, fetchImpl })
    expect(r.ok).toBe(false)
    expect(fetchImpl).not.toHaveBeenCalled()
  })
})

describe('passStatus', () => {
  it('reports the last scheduled pass and the typical gap between them', async () => {
    const at = (h: number) => new Date(Date.UTC(2026, 10, 19, h)).toISOString()
    const db = { query: vi.fn(async () => ({ rows: [{ started_at: at(12) }, { started_at: at(6) }, { started_at: at(0) }] })) }
    expect(await passStatus(db as never)).toEqual({ lastAt: at(12), typicalGapMinutes: 360, count: 3 })
    const none = { query: vi.fn(async () => ({ rows: [] })) }
    expect(await passStatus(none as never)).toEqual({ lastAt: null, typicalGapMinutes: null, count: 0 })
  })
})
