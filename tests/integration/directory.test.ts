// The request gate against PostgreSQL in the modes a 1.1.0 deployment uses
// (access lists in the environment), through the real users table.

import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { authenticate } from '@/lib/auth'
import { PgDirectory } from '@/lib/auth/directory'
import { ConfigStore } from '@/lib/settings/store'
import { setConfigStoreForTests } from '@/lib/settings'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'

const SCHEMA = 'dmarcscope_directory_test'

describe.skipIf(!TEST_DATABASE_URL)('users in the database', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let pool: pg.Pool
  let dir: PgDirectory

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    pool = new pg.Pool({ connectionString: db.url })
    setConfigStoreForTests(new ConfigStore(() => pool, () => 0))
    dir = new PgDirectory(() => pool)
  })
  afterAll(async () => {
    setConfigStoreForTests(null)
    await pool?.end()
    await db?.drop()
  })

  const proxyReq = (email: string, groups = '') => ({
    headers: { get: (n: string) => (n === 'x-forwarded-email' ? email : n === 'x-forwarded-groups' ? groups : null) },
    cookie: () => undefined,
  })
  const env = { AUTH_PROVIDER: 'proxy-header', ADMIN_EMAILS: 'ops@example.com', ALLOWED_GROUPS: 'staff' }

  it('records rule-admitted people and pending requests, once each', async () => {
    expect(await authenticate(proxyReq('ops@example.com'), env, dir)).toMatchObject({ status: 'ok', session: { role: 'admin' } })
    expect(await authenticate(proxyReq('team@example.com', 'staff'), env, dir)).toMatchObject({ status: 'ok', session: { role: 'viewer' } })
    expect(await authenticate(proxyReq('stranger@elsewhere.test'), env, dir)).toMatchObject({ status: 'forbidden' })
    expect(await authenticate(proxyReq('stranger@elsewhere.test'), env, dir)).toMatchObject({ status: 'forbidden' })
    // concurrent first requests do not create duplicates or fail
    await Promise.all(Array.from({ length: 5 }, () => authenticate(proxyReq('burst@example.com', 'staff'), env, dir)))

    const users = (await db.admin.query(`SELECT email, role, role_source, status, source FROM users ORDER BY email`)).rows
    expect(users).toEqual([
      { email: 'burst@example.com', role: 'viewer', role_source: 'rule', status: 'active', source: 'proxy' },
      { email: 'ops@example.com', role: 'admin', role_source: 'rule', status: 'active', source: 'proxy' },
      { email: 'stranger@elsewhere.test', role: 'viewer', role_source: 'rule', status: 'pending', source: 'proxy' },
      { email: 'team@example.com', role: 'viewer', role_source: 'rule', status: 'active', source: 'proxy' },
    ])
    const requested = (await db.admin.query(`SELECT COUNT(*)::int AS n FROM audit_log WHERE action = 'access_requested'`)).rows[0].n
    expect(requested).toBe(1)
  })

  it('follows the rules on the next request, and a disabled row overrides them', async () => {
    // removed from ADMIN_EMAILS: the access it gave is gone
    expect(await authenticate(proxyReq('ops@example.com'), { ...env, ADMIN_EMAILS: '' }, dir)).toMatchObject({ status: 'forbidden' })
    // a database rule admits the pending person
    await db.admin.query(`INSERT INTO access_rules (kind, value, role) VALUES ('email_domain', 'elsewhere.test', 'viewer'); UPDATE config_version SET version = version + 1`)
    expect(await authenticate(proxyReq('stranger@elsewhere.test'), env, dir)).toMatchObject({ status: 'ok', session: { role: 'viewer' } })
    expect((await db.admin.query(`SELECT status FROM users WHERE email = 'stranger@elsewhere.test'`)).rows[0].status).toBe('active')

    await db.admin.query(`UPDATE users SET status = 'disabled' WHERE email = 'team@example.com'`)
    expect(await authenticate(proxyReq('team@example.com', 'staff'), env, dir)).toMatchObject({ status: 'forbidden' })
  })
})
