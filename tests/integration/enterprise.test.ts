// Milestone 6 against PostgreSQL: every query filtered by scope, scope
// resolution from the database, domain scope administration, API tokens, the
// JSON API and CSV, and SCIM.

import pg from 'pg'
import { NextRequest } from 'next/server'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'

const SCHEMA = 'dmarcscope_enterprise_test'
const APP_SECRET = 'enterprise-test-app-secret-0123456789-abcdefgh'
const FOREIGN = ['b.example', '203.0.113.9', 'MARKER_B']

describe.skipIf(!TEST_DATABASE_URL)('enterprise access', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let pool: pg.Pool
  let access: typeof import('@/lib/auth/access')
  let q: typeof import('@/lib/queries')
  let scopes: typeof import('@/lib/access-admin')
  let tokens: typeof import('@/lib/api-tokens')
  const ids: Record<string, number> = {}
  const actor = (who: 'owner' | 'admin' | 'viewer') => ({ userId: ids[who], email: `${who}@example.com`, ip: null, role: who })

  const user = async (email: string, role: string, status = 'active') =>
    Number((await pool.query(`INSERT INTO users (email, role, status, source) VALUES ($1, $2, $3, 'oidc') RETURNING id`, [email, role, status])).rows[0].id)

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    Object.assign(process.env, { DATABASE_URL: db.url, APP_SECRET, APP_URL: 'https://dmarc.test', SETTINGS_CACHE_SECONDS: '0' })
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    pool = new pg.Pool({ connectionString: db.url })
    access = await import('@/lib/auth/access')
    q = await import('@/lib/queries')
    scopes = await import('@/lib/access-admin')
    tokens = await import('@/lib/api-tokens')

    ids.owner = await user('owner@example.com', 'owner')
    ids.admin = await user('admin@example.com', 'admin')
    ids.viewer = await user('viewer@example.com', 'viewer')
    ids.viewer2 = await user('viewer2@example.com', 'viewer')

    // Two domains with their own sources, reports and DNS checks.
    await db.admin.query(`
      INSERT INTO domains (id, name) VALUES (1, 'a.example'), (2, 'b.example');
      INSERT INTO reports (id, domain_id, org_name, report_id, begin_date, end_date, policy_published) VALUES
        (1, 1, 'google.com', 'ra', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', '{"p":"reject"}'),
        (2, 2, 'MARKER_B', 'rb', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', '{"p":"none"}');
      INSERT INTO records (report_id, domain_id, source_ip, message_count, dkim_aligned, spf_aligned, dmarc_aligned, envelope_from, dkim_results, spf_results, period_start, period_end) VALUES
        (1, 1, '192.0.2.10', 100, true, true, true, 'a.example', '[{"domain":"a.example","selector":"s1","result":"pass"}]', '[]', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
        (1, 1, '192.0.2.77', 30, false, false, false, 'a.example', '[]', '[]', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
        (2, 2, '203.0.113.9', 700, false, false, false, 'b.example', '[{"domain":"b.example","selector":"sb","result":"pass"}]', '[]', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day');
      INSERT INTO dns_checks (domain_id, results) VALUES (1, '{"who":"a"}'), (2, '{"who":"MARKER_B"}');
      INSERT INTO ingest_runs (started_at, finished_at, messages_fetched, reports_parsed) VALUES (NOW() - INTERVAL '1 hour', NOW() - INTERVAL '59 minutes', 4242, 4242);
    `)
  })

  afterAll(async () => {
    const { closePool } = await import('@/lib/db')
    await closePool()
    await pool?.end()
    await db?.drop()
  })

  const leaks = (v: unknown) => FOREIGN.some((m) => JSON.stringify(v, (_k, x) => (x instanceof Map ? [...x] : x)).includes(m))

  describe('every query is filtered by scope', () => {
    // One case per export. A new export without a case fails the first test,
    // so a query cannot skip the scope.
    type S = import('@/lib/auth/access').DomainScope
    const CASES: Record<string, (s: S) => Promise<unknown>> = {
      getDomainSummaries: (s) => q.getDomainSummaries(s, 0),
      getTopSources: (s) => q.getTopSources(s, 0),
      getRecentIngestRuns: (s) => q.getRecentIngestRuns(s),
      getIngestHealth: (s) => q.getIngestHealth(s),
      getDataExtent: (s) => q.getDataExtent(s),
      getVolumeTimeseries: (s) => q.getVolumeTimeseries(s, 0),
      getVolumeTimeseriesForDomain: (s) => q.getVolumeTimeseries(s, 0, 'b.example'),
      getDomainNames: (s) => q.getDomainNames(s),
      getDomainPolicy: (s) => q.getDomainPolicy(s, 'b.example'),
      getSourcesForDomain: (s) => q.getSourcesForDomain(s, 'b.example', 0),
      getAlignmentBreakdown: (s) => q.getAlignmentBreakdown(s, 'b.example', 0),
      getObservedDkimSigners: (s) => q.getObservedDkimSigners(s, 'b.example'),
      getLatestDnsCheck: (s) => q.getLatestDnsCheck(s, 'b.example'),
      getProblemSources: (s) => q.getProblemSources(s, 0, 50),
      getProblemSourcesForDomain: (s) => q.getProblemSources(s, 0, 50, 'b.example'),
      getLatestDnsChecksByDomain: (s) => q.getLatestDnsChecksByDomain(s),
    }

    it('has a case for every exported query', () => {
      const exported = Object.entries(q).filter(([, v]) => typeof v === 'function').map(([k]) => k)
      const covered = new Set(Object.keys(CASES).flatMap((k) => [k, k.replace(/ForDomain$/, '')]))
      expect(exported.filter((e) => !covered.has(e))).toEqual([])
    })

    it('shows a limited scope nothing of another domain, from any query', async () => {
      const onlyA = access.limitedTo(['a.example'])
      for (const [name, run] of Object.entries(CASES)) {
        const result = await run(onlyA)
        expect(leaks(result), `${name} leaked another domain`).toBe(false)
      }
      // ...and the cases are not vacuous: the same calls see b.example's data in full.
      expect(leaks(await CASES.getDomainSummaries(access.allDomains()))).toBe(true)
      expect(leaks(await CASES.getTopSources(access.allDomains()))).toBe(true)
      expect(leaks(await CASES.getDomainPolicy(access.allDomains()))).toBe(true)
      expect(leaks(await CASES.getSourcesForDomain(access.allDomains()))).toBe(true)
      expect(leaks(await CASES.getLatestDnsCheck(access.allDomains()))).toBe(true)
      expect(leaks(await CASES.getProblemSources(access.allDomains()))).toBe(true)
      expect(leaks(await CASES.getLatestDnsChecksByDomain(access.allDomains()))).toBe(true)
    })

    it('shows a scope with no domains nothing at all', async () => {
      const none = access.limitedTo([])
      expect(await q.getDomainNames(none)).toEqual([])
      expect(await q.getDomainSummaries(none, 0)).toEqual([])
      expect(await q.getTopSources(none, 0)).toEqual([])
      expect(await q.getProblemSources(none, 0, 50)).toEqual([])
      expect((await q.getDataExtent(none)).total_messages).toBe(0)
      expect(await q.getVolumeTimeseries(none, 0)).toEqual([])
      expect((await q.getLatestDnsChecksByDomain(none)).size).toBe(0)
      expect(await q.getDomainPolicy(none, 'a.example')).toBeNull()
    })

    it('shows a limited scope its own domain, in full', async () => {
      const onlyA = access.limitedTo(['A.example'])
      expect(await q.getDomainNames(onlyA)).toEqual(['a.example'])
      expect((await q.getDomainSummaries(onlyA, 0)).map((d) => [d.name, d.total_messages])).toEqual([['a.example', 130]])
      expect((await q.getDataExtent(onlyA)).total_messages).toBe(130)
      expect((await q.getTopSources(onlyA, 0)).map((s) => s.source_ip).sort()).toEqual(['192.0.2.10', '192.0.2.77'])
      expect((await q.getDomainPolicy(onlyA, 'a.example'))?.policy).toBe('reject')
      expect((await q.getLatestDnsCheck(onlyA, 'a.example'))?.who).toBe('a')
      // Ingest runs are about the mailboxes, whose counts show other domains' volume.
      expect(await q.getRecentIngestRuns(onlyA)).toEqual([])
      expect((await q.getRecentIngestRuns(access.allDomains())).length).toBe(1)
    })
  })

  describe('resolution from the database', () => {
    const session = (userId: number, role: 'viewer' | 'admin' | 'owner' = 'viewer', groups: string[] = []) => ({
      identity: { sub: 's', email: 'x@example.com', groups },
      role,
      userId,
    })
    const names = async (s: ReturnType<typeof session>) => access.scopeNames((await access.authorize(s)).domains)
    const clear = () => pool.query(`DELETE FROM domain_scopes; DELETE FROM groups; DELETE FROM group_members; UPDATE settings SET value = '"all"'::jsonb WHERE key = 'access.domain_default'`)

    it('gives viewers everything until someone limits them, and administrators always', async () => {
      await clear()
      expect(await names(session(ids.viewer))).toBeNull()
      await scopes.setUserScope(pool, actor('admin'), ids.viewer, { mode: 'limited', domains: 'a.example' })
      expect(await names(session(ids.viewer))).toEqual(['a.example'])
      expect(await names(session(ids.viewer2))).toBeNull()
      expect(await names(session(ids.admin, 'admin'))).toBeNull()
      expect(await names(session(ids.owner, 'owner'))).toBeNull()
    })

    it('applies a change on the next request, in both directions', async () => {
      await clear()
      await scopes.setUserScope(pool, actor('admin'), ids.viewer, { mode: 'limited', domains: 'a.example\nb.example' })
      expect(await names(session(ids.viewer))).toEqual(['a.example', 'b.example'])
      await scopes.setUserScope(pool, actor('admin'), ids.viewer, { mode: 'limited', domains: 'a.example' })
      expect(await names(session(ids.viewer))).toEqual(['a.example'])
      await scopes.clearUserScope(pool, actor('admin'), ids.viewer)
      expect(await names(session(ids.viewer))).toBeNull()
    })

    it('limits through a group named in the identity provider’s claim', async () => {
      await clear()
      await scopes.setGroupScope(pool, actor('admin'), 'Sales Team', { mode: 'limited', domains: 'a.example' })
      expect(await names(session(ids.viewer, 'viewer', ['sales team']))).toEqual(['a.example'])
      expect(await names(session(ids.viewer, 'viewer', ['SALES TEAM']))).toEqual(['a.example'])
      expect(await names(session(ids.viewer, 'viewer', ['other']))).toBeNull()
    })

    it('does not widen anyone when the identity provider stops sending groups and the default is none', async () => {
      await clear()
      await scopes.setGroupScope(pool, actor('admin'), 'sales', { mode: 'limited', domains: 'a.example' })
      expect(await names(session(ids.viewer, 'viewer', []))).toBeNull() // default all: the gap the setting exists for
      await pool.query(`INSERT INTO settings (key, value) VALUES ('access.domain_default', '"none"'::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`)
      await pool.query(`UPDATE config_version SET version = version + 1`)
      expect(await names(session(ids.viewer, 'viewer', []))).toEqual([])
      expect(await names(session(ids.viewer, 'viewer', ['sales']))).toEqual(['a.example'])
      expect(await names(session(ids.admin, 'admin', []))).toBeNull()
    })

    it('uses SCIM group membership, and drops it when the membership goes', async () => {
      await clear()
      await scopes.setGroupScope(pool, actor('admin'), 'finance', { mode: 'limited', domains: 'b.example' })
      const g = Number((await pool.query(`INSERT INTO groups (display_name, source) VALUES ('Finance', 'scim') RETURNING id`)).rows[0].id)
      expect(await names(session(ids.viewer))).toBeNull()
      await pool.query(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, [g, ids.viewer])
      expect(await names(session(ids.viewer))).toEqual(['b.example'])
      await pool.query(`DELETE FROM group_members WHERE group_id = $1`, [g])
      expect(await names(session(ids.viewer))).toBeNull()
    })

    it('keeps the group names a sign-in must keep in the settings snapshot', async () => {
      await clear()
      await scopes.setGroupScope(pool, actor('admin'), 'Sales Team', { mode: 'limited', domains: 'a.example' })
      const { configStore } = await import('@/lib/settings')
      expect((await configStore().snapshot({ fresh: true })).scopeGroups).toEqual(['sales team'])
    })
  })

  describe('administering scopes', () => {
    const refusal = async (p: Promise<unknown>) => {
      try {
        await p
      } catch (e) {
        return (e as { code?: string }).code
      }
      return 'none'
    }
    const audited = async (action: string) => Number((await pool.query(`SELECT count(*) FROM audit_log WHERE action = $1`, [action])).rows[0].count)

    it('refuses a viewer, and audits the refusal', async () => {
      const before = await audited('action_refused')
      expect(await refusal(scopes.setUserScope(pool, actor('viewer'), ids.viewer2, { mode: 'limited', domains: '' }))).toBe('not_allowed')
      expect(await refusal(scopes.setGroupScope(pool, actor('viewer'), 'x', { mode: 'all', domains: '' }))).toBe('not_allowed')
      expect(await audited('action_refused')).toBe(before + 2)
    })

    it('refuses a limit on an administrator or an owner, and on someone who does not exist', async () => {
      expect(await refusal(scopes.setUserScope(pool, actor('admin'), ids.admin, { mode: 'limited', domains: '' }))).toBe('not_applicable')
      expect(await refusal(scopes.setUserScope(pool, actor('owner'), ids.owner, { mode: 'limited', domains: '' }))).toBe('not_applicable')
      expect(await refusal(scopes.setUserScope(pool, actor('admin'), 999999, { mode: 'limited', domains: '' }))).toBe('not_found')
    })

    it('refuses a bad mode, domain or group name', async () => {
      expect(await refusal(scopes.setUserScope(pool, actor('admin'), ids.viewer, { mode: 'some', domains: '' }))).toBe('invalid')
      expect(await refusal(scopes.setUserScope(pool, actor('admin'), ids.viewer, { mode: 'limited', domains: 'no spaces allowed.example!' }))).toBe('invalid')
      expect(await refusal(scopes.setGroupScope(pool, actor('admin'), '   ', { mode: 'all', domains: '' }))).toBe('invalid')
    })

    it('stops a caller who was disabled meanwhile', async () => {
      const gone = await user('gone@example.com', 'admin', 'disabled')
      expect(await refusal(scopes.setUserScope(pool, { userId: gone, email: 'gone@example.com', ip: null, role: 'admin' }, ids.viewer, { mode: 'limited', domains: '' }))).toBe('not_allowed')
    })

    it('records what changed, and that a limited scope may be empty on purpose', async () => {
      await scopes.setUserScope(pool, actor('admin'), ids.viewer2, { mode: 'limited', domains: '' })
      expect(await scopes.getUserScope(pool, ids.viewer2)).toEqual({ mode: 'limited', domains: [] })
      const last = (await pool.query(`SELECT detail FROM audit_log WHERE action = 'domain_scope_changed' ORDER BY id DESC LIMIT 1`)).rows[0].detail
      expect(last).toMatchObject({ email: 'viewer2@example.com', mode: 'limited', domains: [] })
    })

    it('lists every group the deployment knows of, with what each adds', async () => {
      await pool.query(`INSERT INTO access_rules (kind, value, role) VALUES ('group', 'from-rule', 'viewer')`)
      await scopes.setGroupScope(pool, actor('admin'), 'only-scope', { mode: 'all', domains: '' })
      const list = await scopes.listGroups(pool)
      expect(list.find((g) => g.name === 'from-rule')).toMatchObject({ in_rules: true, scope: null })
      expect(list.find((g) => g.name === 'only-scope')).toMatchObject({ scope: { mode: 'all' } })
    })
  })

  describe('API tokens', () => {
    const create = (who: 'owner' | 'admin' | 'viewer' = 'admin', over: Record<string, unknown> = {}) =>
      tokens.createApiToken(pool, actor(who), { name: 'ci', scopes: ['domains:read', 'reports:read', 'dns:read'], mode: 'limited', domains: 'a.example', expiresInDays: '30', ...over } as never)
    const auth = (t: string, kind: 'api' | 'scim' = 'api') => tokens.authenticateToken(pool, `Bearer ${t}`, kind)

    it('refuses a viewer', async () => {
      await expect(create('viewer')).rejects.toMatchObject({ code: 'not_allowed' })
    })

    it('shows the token once, stores only its hash, and never writes it to the audit log', async () => {
      const { token, id } = await create()
      expect(token).toMatch(/^dsa_/)
      const row = (await pool.query(`SELECT * FROM api_tokens WHERE id = $1`, [id])).rows[0]
      expect(JSON.stringify(row)).not.toContain(token)
      expect(JSON.stringify(row)).not.toContain(token.slice(8))
      expect(row.token_hash).toBe(tokens.hashToken(token))
      const audit = JSON.stringify((await pool.query(`SELECT detail FROM audit_log WHERE target = $1`, [`api_token:${id}`])).rows)
      expect(audit).not.toContain(token.slice(8))
      expect(JSON.stringify((await tokens.listTokens(pool, 'api')))).not.toContain(token.slice(8))
    })

    it('authenticates a good token with its own scope and domains', async () => {
      const { token } = await create('admin', { scopes: ['dns:read'], domains: 'B.example' })
      const a = await auth(token)
      expect(a?.scopes).toEqual(['dns:read'])
      expect(access.scopeNames(a!.domains)).toEqual(['b.example'])
    })

    it('answers null, and nothing more, for every kind of bad token', async () => {
      const { token, id } = await create()
      const good = await auth(token)
      expect(good).not.toBeNull()
      const other = tokens.newToken('api').token
      for (const bad of [other, 'dsa_short', '', token.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'))]) expect(await auth(bad)).toBeNull()
      expect(await tokens.authenticateToken(pool, null, 'api')).toBeNull()
      expect(await tokens.authenticateToken(pool, token, 'api')).toBeNull() // no "Bearer"
      expect(await auth(token, 'scim')).toBeNull() // an API token is not a SCIM token

      await pool.query(`UPDATE api_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, [id])
      expect(await auth(token)).toBeNull() // expired
      await pool.query(`UPDATE api_tokens SET expires_at = NOW() + INTERVAL '1 day' WHERE id = $1`, [id])
      expect(await auth(token)).not.toBeNull()
      await tokens.revokeToken(pool, actor('admin'), id)
      expect(await auth(token)).toBeNull() // revoked
      await expect(tokens.revokeToken(pool, actor('admin'), id)).rejects.toMatchObject({ code: 'not_found' })
    })

    it('fails when the creator is disabled, demoted or removed: never wider than who made it', async () => {
      const a2 = await user('creator@example.com', 'admin')
      const t = await tokens.createApiToken(pool, { userId: a2, email: 'creator@example.com', ip: null, role: 'admin' }, { name: 'c', scopes: ['domains:read'], mode: 'all', domains: '', expiresInDays: '5' })
      expect(await auth(t.token)).not.toBeNull()
      await pool.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [a2])
      expect(await auth(t.token)).toBeNull()
      await pool.query(`UPDATE users SET status = 'active', role = 'viewer' WHERE id = $1`, [a2])
      expect(await auth(t.token)).toBeNull()
      await pool.query(`UPDATE users SET role = 'admin' WHERE id = $1`, [a2])
      expect(await auth(t.token)).not.toBeNull()
      await pool.query(`DELETE FROM users WHERE id = $1`, [a2])
      expect(await auth(t.token)).toBeNull()
    })

    it('only an owner makes a SCIM token, and a new one ends the old', async () => {
      await expect(tokens.createScimToken(pool, actor('admin'), 'okta')).rejects.toMatchObject({ code: 'not_allowed' })
      const first = await tokens.createScimToken(pool, actor('owner'), 'okta')
      expect(first.token).toMatch(/^dss_/)
      expect(await auth(first.token, 'scim')).not.toBeNull()
      expect(await auth(first.token, 'api')).toBeNull()
      const second = await tokens.createScimToken(pool, actor('owner'), 'okta 2')
      expect(await auth(first.token, 'scim')).toBeNull()
      expect(await auth(second.token, 'scim')).not.toBeNull()
      // An administrator cannot end it.
      const id = (await pool.query(`SELECT id FROM api_tokens WHERE kind = 'scim' AND revoked_at IS NULL`)).rows[0].id
      await expect(tokens.revokeToken(pool, actor('admin'), Number(id))).rejects.toMatchObject({ code: 'not_allowed' })
      expect(await auth(second.token, 'scim')).not.toBeNull()
    })

    it('limits how many tokens are active', async () => {
      await pool.query(`DELETE FROM api_tokens WHERE kind = 'api'`)
      await pool.query(
        `INSERT INTO api_tokens (kind, name, prefix, token_hash, scopes, created_by, expires_at)
         SELECT 'api', 'filler ' || n, 'dsa_fill', 'fill-' || n, '{}', $1, NOW() + INTERVAL '1 day' FROM generate_series(1, $2::int) n`,
        [ids.admin, tokens.MAX_ACTIVE_TOKENS]
      )
      await expect(create()).rejects.toMatchObject({ code: 'limit' })
      await pool.query(`DELETE FROM api_tokens WHERE kind = 'api'`)
      await expect(create()).resolves.toMatchObject({ id: expect.any(Number) })
    })
  })

  describe('the JSON API', () => {
    let routes: Record<string, { GET: (req: NextRequest, ctx?: { params: Promise<Record<string, string>> }) => Promise<Response> }>
    let aToken: string
    let allToken: string
    let dnsOnly: string

    const call = async (route: string, path: string, init: { token?: string; headers?: Record<string, string>; params?: Record<string, string> } = {}) => {
      const headers: Record<string, string> = { ...(init.headers ?? {}) }
      if (init.token) headers.authorization = `Bearer ${init.token}`
      const req = new NextRequest(`https://dmarc.test${path}`, { headers })
      const res = await routes[route].GET(req, { params: Promise.resolve(init.params ?? {}) })
      return { res, text: await res.text() }
    }
    const json = (t: string) => JSON.parse(t) as { data?: unknown; error?: { code: string } }

    beforeAll(async () => {
      routes = {
        domains: await import('../../app/api/v1/domains/route'),
        summary: await import('../../app/api/v1/domains/[domain]/summary/route'),
        timeseries: await import('../../app/api/v1/domains/[domain]/timeseries/route'),
        sources: await import('../../app/api/v1/domains/[domain]/sources/route'),
        dns: await import('../../app/api/v1/domains/[domain]/dns/route'),
        problems: await import('../../app/api/v1/problems/route'),
      } as never
      const make = (over: Record<string, unknown>) => tokens.createApiToken(pool, actor('admin'), { name: 'api', scopes: ['domains:read', 'reports:read', 'dns:read'], mode: 'limited', domains: 'a.example', expiresInDays: '30', ...over } as never)
      aToken = (await make({})).token
      allToken = (await make({ mode: 'all' })).token
      dnsOnly = (await make({ scopes: ['dns:read'], mode: 'all' })).token
    })

    it('answers 401 without a token, with a bad one, or with the token anywhere but the header', async () => {
      const inits: Array<{ token?: string; headers?: Record<string, string> }> = [{}, { token: tokens.newToken('api').token }, { headers: { cookie: 'session=anything' } }, { headers: { authorization: `Basic ${aToken}` } }]
      for (const init of inits) {
        const { res, text } = await call('domains', '/api/v1/domains', init)
        expect(res.status).toBe(401)
        expect(res.headers.get('www-authenticate')).toBe('Bearer')
        expect(json(text).error?.code).toBe('unauthorized')
      }
      expect((await call('domains', `/api/v1/domains?token=${aToken}&access_token=${aToken}`)).res.status).toBe(401)
    })

    it('lists only the token’s domains', async () => {
      const { res, text } = await call('domains', '/api/v1/domains?days=30', { token: aToken })
      expect(res.status).toBe(200)
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect((json(text).data as Array<{ name: string }>).map((d) => d.name)).toEqual(['a.example'])
      expect(FOREIGN.some((m) => text.includes(m))).toBe(false)
      const all = await call('domains', '/api/v1/domains?days=30', { token: allToken })
      expect((json(all.text).data as Array<{ name: string }>).map((d) => d.name).sort()).toEqual(['a.example', 'b.example'])
    })

    it('answers 404, as for a domain that does not exist, for a domain outside the scope, on every endpoint', async () => {
      for (const r of ['summary', 'timeseries', 'sources', 'dns']) {
        const outside = await call(r, '/api/v1/x', { token: aToken, params: { domain: 'b.example' } })
        const missing = await call(r, '/api/v1/x', { token: aToken, params: { domain: 'nothing.example' } })
        expect(outside.res.status, r).toBe(404)
        expect(outside.text, r).toBe(missing.text)
        expect(outside.text).not.toContain('MARKER_B')
      }
    })

    it('answers 404, not a server error, for a malformed domain in the path', async () => {
      for (const r of ['summary', 'timeseries', 'sources', 'dns']) {
        expect((await call(r, '/x', { token: aToken, params: { domain: '%E0%A4%A' } })).res.status, r).toBe(404)
      }
    })

    it('serves a domain inside the scope on every endpoint', async () => {
      const p = { domain: 'a.example' }
      expect(json((await call('summary', '/x', { token: aToken, params: p })).text).data).toMatchObject({ policy: { domain: 'a.example', policy: 'reject' } })
      expect((json((await call('timeseries', '/x?days=30', { token: aToken, params: p })).text).data as unknown[]).length).toBeGreaterThan(0)
      expect((json((await call('sources', '/x?days=30', { token: aToken, params: p })).text).data as unknown[]).length).toBe(2)
      expect(json((await call('dns', '/x', { token: aToken, params: p })).text).data).toEqual({ who: 'a' })
      const problems = json((await call('problems', '/api/v1/problems?days=30', { token: aToken })).text).data as Array<{ domain: string }>
      expect(problems.map((x) => x.domain)).toEqual(['a.example'])
      // Asking for another domain's problems through the filter finds nothing.
      expect((json((await call('problems', '/api/v1/problems?days=30&domain=b.example', { token: aToken })).text).data as unknown[]).length).toBe(0)
    })

    it('refuses a token without the scope the endpoint needs', async () => {
      expect((await call('domains', '/api/v1/domains', { token: dnsOnly })).res.status).toBe(403)
      expect((await call('sources', '/x', { token: dnsOnly, params: { domain: 'a.example' } })).res.status).toBe(403)
      expect((await call('dns', '/x', { token: dnsOnly, params: { domain: 'a.example' } })).res.status).toBe(200)
    })

    it('shows a token limited to no domains nothing', async () => {
      const t = (await tokens.createApiToken(pool, actor('admin'), { name: 'none', scopes: ['domains:read'], mode: 'limited', domains: '', expiresInDays: '5' })).token
      expect(json((await call('domains', '/api/v1/domains', { token: t })).text).data).toEqual([])
    })

    it('validates days and format', async () => {
      for (const bad of ['0', '91', 'x', '-1', '7.5']) expect((await call('domains', `/api/v1/domains?days=${bad}`, { token: aToken })).res.status).toBe(400)
      expect((await call('domains', '/api/v1/domains?format=xml', { token: aToken })).res.status).toBe(400)
    })

    it('exports CSV with formulas neutralized, from the same scoped data', async () => {
      await pool.query(`INSERT INTO ip_metadata (ip, reverse_dns, provider_name) VALUES ('192.0.2.77', '=HYPERLINK("http://evil")', '+cmd') ON CONFLICT (ip) DO UPDATE SET reverse_dns = EXCLUDED.reverse_dns, provider_name = EXCLUDED.provider_name`)
      const { res, text } = await call('sources', '/x?days=30&format=csv', { token: aToken, params: { domain: 'a.example' } })
      expect(res.headers.get('content-type')).toContain('text/csv')
      expect(res.headers.get('content-disposition')).toContain('attachment')
      expect(text.split('\r\n')[0]).toContain('source_ip')
      expect(text).not.toMatch(/(^|,)"?=HYPERLINK/m)
      expect(text).toContain("'=HYPERLINK")
      expect(FOREIGN.some((m) => text.includes(m))).toBe(false)
      const csv = await call('domains', '/api/v1/domains?days=30&format=csv', { token: aToken })
      expect(csv.text).toContain('a.example')
      expect(csv.text).not.toContain('b.example')
    })
  })

  describe('SCIM', () => {
    let scimToken: string
    let apiToken: string
    let R: Record<string, Record<string, (req: NextRequest, ctx?: { params: Promise<{ id: string }> }) => Promise<Response>>>

    const call = async (route: string, method: string, opts: { path?: string; id?: string; body?: unknown; raw?: string; token?: string | null; headers?: Record<string, string> } = {}) => {
      const headers: Record<string, string> = { ...(opts.headers ?? {}) }
      const token = opts.token === undefined ? scimToken : opts.token
      if (token) headers.authorization = `Bearer ${token}`
      if (opts.body !== undefined || opts.raw !== undefined) headers['content-type'] = 'application/scim+json'
      const req = new NextRequest(`https://dmarc.test/scim/v2/${opts.path ?? route}`, {
        method,
        headers,
        body: opts.raw ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body)),
      })
      const res = await R[route][method](req, { params: Promise.resolve({ id: opts.id ?? '' }) })
      const text = await res.text()
      return { res, body: text ? JSON.parse(text) : null }
    }
    const status = async (email: string) => (await pool.query(`SELECT status, role, sessions_valid_after, source FROM users WHERE email = $1`, [email])).rows[0]

    beforeAll(async () => {
      scimToken = (await tokens.createScimToken(pool, actor('owner'), 'okta')).token
      apiToken = (await tokens.createApiToken(pool, actor('admin'), { name: 'a', scopes: ['domains:read'], mode: 'all', domains: '', expiresInDays: '5' })).token
      R = {
        Users: await import('../../app/scim/v2/Users/route'),
        UserId: await import('../../app/scim/v2/Users/[id]/route'),
        Groups: await import('../../app/scim/v2/Groups/route'),
        GroupId: await import('../../app/scim/v2/Groups/[id]/route'),
        Config: await import('../../app/scim/v2/ServiceProviderConfig/route'),
      } as never
    })

    it('answers 401 in the SCIM format for a missing, wrong or API token, and the reverse', async () => {
      for (const token of [null, tokens.newToken('scim').token, apiToken]) {
        const { res, body } = await call('Users', 'GET', { token })
        expect(res.status).toBe(401)
        expect(res.headers.get('content-type')).toContain('application/scim+json')
        expect(body).toMatchObject({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401' })
      }
      // A SCIM token does not open the API.
      const api = await import('../../app/api/v1/domains/route')
      const res = await api.GET(new NextRequest('https://dmarc.test/api/v1/domains', { headers: { authorization: `Bearer ${scimToken}` } }))
      expect(res.status).toBe(401)
      expect((await call('Config', 'GET')).res.status).toBe(200)
    })

    it('creates a viewer, never anything else, and refuses a duplicate', async () => {
      const { res, body } = await call('Users', 'POST', { body: { userName: 'Ann@Example.com', externalId: 'ext-ann', displayName: 'Ann', active: true, roles: [{ value: 'owner' }], role: 'admin' } })
      expect(res.status).toBe(201)
      expect(body).toMatchObject({ userName: 'ann@example.com', active: true, externalId: 'ext-ann' })
      expect(await status('ann@example.com')).toMatchObject({ status: 'active', role: 'viewer', source: 'scim' })
      expect((await call('Users', 'POST', { body: { userName: 'ann@example.com' } })).res.status).toBe(409)
      expect((await call('Users', 'POST', { body: { userName: 'other@example.com', externalId: 'ext-ann' } })).res.status).toBe(409)
      expect((await call('Users', 'POST', { body: { userName: 'not an address' } })).res.status).toBe(400)
      expect((await call('Users', 'POST', { body: { displayName: 'no name' } })).res.status).toBe(400)
      expect((await call('Users', 'POST', { raw: '{nope' })).res.status).toBe(400)
      expect((await call('Users', 'POST', { body: [] })).res.status).toBe(400)
    })

    it('finds a user by filter, and refuses filters it does not support', async () => {
      const found = await call('Users', 'GET', { path: 'Users?filter=' + encodeURIComponent('userName eq "ANN@example.com"') })
      expect(found.body.totalResults).toBe(1)
      expect(found.body.Resources[0].userName).toBe('ann@example.com')
      const none = await call('Users', 'GET', { path: 'Users?filter=' + encodeURIComponent('userName eq "nobody@example.com"') })
      expect(none.body.totalResults).toBe(0)
      const bad = await call('Users', 'GET', { path: 'Users?filter=' + encodeURIComponent('userName co "a"') })
      expect(bad.res.status).toBe(400)
      expect(bad.body.scimType).toBe('invalidFilter')
      const page = await call('Users', 'GET', { path: 'Users?count=2&startIndex=1' })
      expect(page.body.itemsPerPage).toBeLessThanOrEqual(2)
    })

    it('deactivates at once: disabled, signed out, and the person’s next request is refused', async () => {
      const id = String((await call('Users', 'GET', { path: 'Users?filter=' + encodeURIComponent('userName eq "ann@example.com"') })).body.Resources[0].id)
      const { resolveAccess } = await import('@/lib/auth/resolve')
      const { PgDirectory } = await import('@/lib/auth/directory')
      const dir = new PgDirectory(() => pool)
      const identity = { sub: 's', email: 'ann@example.com', groups: [] }
      const before = await resolveAccess(identity, 'oidc', { userId: Number(id), issuedAt: Math.floor(Date.now() / 1000) }, {}, dir)
      expect(before.status).toBe('ok')

      const patched = await call('UserId', 'PATCH', { path: `Users/${id}`, id, body: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'Replace', path: 'active', value: 'False' }] } })
      expect(patched.res.status).toBe(200)
      expect(patched.body.active).toBe(false)
      const row = await status('ann@example.com')
      expect(row.status).toBe('disabled')
      expect(row.sessions_valid_after).not.toBeNull()
      const after = await resolveAccess(identity, 'oidc', { userId: Number(id), issuedAt: Math.floor(Date.now() / 1000) }, {}, dir)
      expect(after.status).toBe('forbidden')

      const back = await call('UserId', 'PATCH', { path: `Users/${id}`, id, body: { Operations: [{ op: 'replace', value: { active: true, displayName: 'Ann B' } }] } })
      expect(back.body).toMatchObject({ active: true, displayName: 'Ann B' })
      expect((await resolveAccess(identity, 'oidc', { userId: Number(id), issuedAt: Math.floor(Date.now() / 1000) + 5 }, {}, dir)).status).toBe('ok')
    })

    it('never touches an owner, and never renames, re-roles or sets a password', async () => {
      const owner = String(ids.owner)
      for (const [method, body] of [
        ['PATCH', { Operations: [{ op: 'replace', path: 'active', value: false }] }],
        ['PUT', { userName: 'owner@example.com', active: false }],
      ] as const) {
        const { res } = await call('UserId', method, { path: `Users/${owner}`, id: owner, body })
        expect(res.status, method).toBe(403)
      }
      expect((await call('UserId', 'DELETE', { path: `Users/${owner}`, id: owner })).res.status).toBe(403)
      expect(await status('owner@example.com')).toMatchObject({ status: 'active', role: 'owner' })

      const id = String(ids.viewer2)
      const rename = await call('UserId', 'PUT', { path: `Users/${id}`, id, body: { userName: 'attacker@example.com' } })
      expect(rename.res.status).toBe(400)
      expect(rename.body.scimType).toBe('mutability')
      const viaPatch = await call('UserId', 'PATCH', { path: `Users/${id}`, id, body: { Operations: [{ op: 'replace', path: 'userName', value: 'attacker@example.com' }] } })
      expect(viaPatch.res.status).toBe(400)
      for (const path of ['roles', 'password', 'groups', 'entitlements']) {
        const r = await call('UserId', 'PATCH', { path: `Users/${id}`, id, body: { Operations: [{ op: 'replace', path, value: 'x' }] } })
        expect(r.res.status, path).toBe(400)
        expect(r.body.scimType).toBe('invalidPath')
      }
      expect((await pool.query(`SELECT email, role FROM users WHERE id = $1`, [id])).rows[0]).toEqual({ email: 'viewer2@example.com', role: 'viewer' })
      // Harmless profile attributes an identity provider sends are accepted.
      const ok = await call('UserId', 'PATCH', { path: `Users/${id}`, id, body: { Operations: [{ op: 'replace', path: 'emails[type eq "work"].value', value: 'viewer2@example.com' }, { op: 'replace', path: 'name.givenName', value: 'V' }] } })
      expect(ok.res.status).toBe(200)
    })

    it('may deactivate an administrator but never activate one', async () => {
      const live = await user('scim-admin@example.com', 'admin')
      const off = await user('scim-admin-off@example.com', 'admin', 'disabled')
      const patch = (id: number, active: boolean) => call('UserId', 'PATCH', { path: `Users/${id}`, id: String(id), body: { Operations: [{ op: 'replace', path: 'active', value: active }] } })
      expect((await patch(live, false)).res.status).toBe(200)
      expect(await status('scim-admin@example.com')).toMatchObject({ status: 'disabled' })
      const refused = await patch(off, true)
      expect(refused.res.status).toBe(403)
      expect(refused.body.scimType).toBe('forbidden')
      expect(await status('scim-admin-off@example.com')).toMatchObject({ status: 'disabled' })
      expect((await patch(live, true)).res.status).toBe(403)
    })

    it('answers 404 for an unknown or malformed id, and 400 for no operations', async () => {
      expect((await call('UserId', 'GET', { path: 'Users/999999', id: '999999' })).res.status).toBe(404)
      expect((await call('UserId', 'GET', { path: 'Users/abc', id: 'abc' })).res.status).toBe(404)
      expect((await call('UserId', 'GET', { path: "Users/1;DROP", id: '1;DROP' })).res.status).toBe(404)
      const id = String(ids.viewer2)
      expect((await call('UserId', 'PATCH', { path: `Users/${id}`, id, body: { Operations: [] } })).res.status).toBe(400)
      expect((await call('UserId', 'PATCH', { path: `Users/${id}`, id, body: { Operations: [{ op: 'move', path: 'active' }] } })).res.status).toBe(400)
    })

    it('refuses a body over the size limit', async () => {
      const { res } = await call('Users', 'POST', { raw: JSON.stringify({ userName: 'big@example.com', displayName: 'x'.repeat(300 * 1024) }) })
      expect(res.status).toBe(413)
      expect(await status('big@example.com')).toBeUndefined()
    })

    it('manages groups and members, and a membership change changes the person’s scope', async () => {
      const aid = String(ids.viewer)
      const created = await call('Groups', 'POST', { body: { displayName: 'Finance', externalId: 'g-fin', members: [{ value: aid }] } })
      expect(created.res.status).toBe(201)
      const gid = String(created.body.id)
      expect(created.body.members).toEqual([{ value: aid, display: 'viewer@example.com' }])
      expect((await call('Groups', 'POST', { body: { displayName: 'finance' } })).res.status).toBe(409)
      expect((await call('Groups', 'POST', { body: { displayName: 'ghosts', members: [{ value: '987654' }] } })).res.status).toBe(400)
      expect((await call('Groups', 'POST', { body: { displayName: '  ' } })).res.status).toBe(400)

      await scopes.setGroupScope(pool, actor('admin'), 'finance', { mode: 'limited', domains: 'b.example' })
      await pool.query(`DELETE FROM domain_scopes WHERE kind = 'user'`)
      const names = async (userId: number) => access.scopeNames((await access.authorize({ identity: { sub: 's', email: 'x', groups: [] }, role: 'viewer', userId })).domains)
      expect(await names(ids.viewer)).toEqual(['b.example'])

      const bid = String(ids.viewer2)
      await call('GroupId', 'PATCH', { path: `Groups/${gid}`, id: gid, body: { Operations: [{ op: 'add', path: 'members', value: [{ value: bid }] }] } })
      expect(await names(ids.viewer2)).toEqual(['b.example'])
      await call('GroupId', 'PATCH', { path: `Groups/${gid}`, id: gid, body: { Operations: [{ op: 'remove', path: `members[value eq "${bid}"]` }] } })
      expect(await names(ids.viewer2)).toBeNull()
      await call('GroupId', 'PATCH', { path: `Groups/${gid}`, id: gid, body: { Operations: [{ op: 'replace', path: 'members', value: [] }] } })
      expect(await names(ids.viewer)).toBeNull()

      const renamed = await call('GroupId', 'PATCH', { path: `Groups/${gid}`, id: gid, body: { Operations: [{ op: 'replace', path: 'displayName', value: 'Finance EU' }] } })
      expect(renamed.body.displayName).toBe('Finance EU')
      const bad = await call('GroupId', 'PATCH', { path: `Groups/${gid}`, id: gid, body: { Operations: [{ op: 'replace', path: 'roles', value: 'admin' }] } })
      expect(bad.res.status).toBe(400)
      expect((await call('GroupId', 'DELETE', { path: `Groups/${gid}`, id: gid })).res.status).toBe(204)
      expect((await call('GroupId', 'GET', { path: `Groups/${gid}`, id: gid })).res.status).toBe(404)
    })

    it('does not let a SCIM group grant a role by being named like an access-rule group', async () => {
      await pool.query(`INSERT INTO access_rules (kind, value, role) VALUES ('group', 'admins', 'admin') ON CONFLICT DO NOTHING`)
      const bid = String(ids.viewer2)
      const g = await call('Groups', 'POST', { body: { displayName: 'Admins', members: [{ value: bid }] } })
      expect(g.res.status).toBe(201)
      const { PgDirectory } = await import('@/lib/auth/directory')
      const { resolveAccess } = await import('@/lib/auth/resolve')
      const r = await resolveAccess({ sub: 's', email: 'viewer2@example.com', groups: [] }, 'oidc', { userId: ids.viewer2 }, {}, new PgDirectory(() => pool))
      expect(r.status === 'ok' && r.session.role).toBe('viewer')
    })

    it('deactivating through DELETE removes the person from every group', async () => {
      const made = await call('Users', 'POST', { body: { userName: 'carl@example.com' } })
      const cid = String(made.body.id)
      const g = await call('Groups', 'POST', { body: { displayName: 'Temp', members: [{ value: cid }] } })
      expect((await call('UserId', 'DELETE', { path: `Users/${cid}`, id: cid })).res.status).toBe(204)
      expect(await status('carl@example.com')).toMatchObject({ status: 'disabled' })
      expect((await call('GroupId', 'GET', { path: `Groups/${g.body.id}`, id: String(g.body.id) })).body.members).toEqual([])
    })

    it('audits every change as the SCIM token, never with a secret', async () => {
      const rows = (await pool.query(`SELECT actor_email, action, detail FROM audit_log WHERE action LIKE 'scim\\_user\\_%' OR action LIKE 'scim\\_group\\_%' ORDER BY id`)).rows
      expect(rows.length).toBeGreaterThan(5)
      expect(rows.every((r) => r.actor_email === 'scim:okta')).toBe(true)
      expect(JSON.stringify(rows)).not.toContain(scimToken.slice(8))
      expect(rows.map((r) => r.action)).toEqual(expect.arrayContaining(['scim_user_created', 'scim_user_deactivated', 'scim_user_activated', 'scim_group_created']))
    })
  })
})
