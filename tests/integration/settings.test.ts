// The settings store against PostgreSQL: resolution, validation, encryption,
// the version counter, and a change made through one connection pool being
// seen through another within the cache window.

import pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfigStore, SettingError } from '@/lib/settings/store'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'

const SCHEMA = 'dmarcscope_settings_test'
const APP_SECRET = 'settings-test-app-secret-0123456789abcdef'
const ENV = { APP_SECRET }
const ACTOR = { userId: null, email: 'owner@example.com', ip: '192.0.2.1' }

describe.skipIf(!TEST_DATABASE_URL)('settings store', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let poolA: pg.Pool
  let poolB: pg.Pool

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    poolA = new pg.Pool({ connectionString: db.url, max: 2 })
    poolB = new pg.Pool({ connectionString: db.url, max: 2 })
  })
  afterAll(async () => {
    await poolA?.end()
    await poolB?.end()
    await db?.drop()
  })
  beforeEach(async () => {
    await db.admin.query(`TRUNCATE settings`)
    vi.restoreAllMocks()
  })

  const store = (pool: pg.Pool, ttlMs = 0) => new ConfigStore(() => pool, () => ttlMs)

  it('resolves environment, then database, then default', async () => {
    const s = store(poolA)
    expect(await s.get('ingest.stale_hours', ENV)).toBe(36)
    await s.write('ingest.stale_hours', '48', ACTOR, ENV)
    expect(await s.get('ingest.stale_hours', ENV)).toBe(48)
    expect(await s.get('ingest.stale_hours', { ...ENV, INGEST_STALE_HOURS: '12' })).toBe(12)
    const listed = (await s.list({ ...ENV, INGEST_STALE_HOURS: '12' })).find((x) => x.key === 'ingest.stale_hours')!
    expect(listed).toMatchObject({ source: 'environment', value: 12, error: null })
  })

  it('refuses to change a setting the environment manages, and refuses invalid values', async () => {
    const s = store(poolA)
    await expect(s.write('app.name', 'X', ACTOR, { ...ENV, APP_NAME: 'Managed' })).rejects.toMatchObject({ code: 'managed_by_environment' })
    await expect(s.write('ingest.stale_hours', 'twelve', ACTOR, ENV)).rejects.toMatchObject({ code: 'invalid' })
    await expect(s.write('ingest.stale_hours', '0', ACTOR, ENV)).rejects.toMatchObject({ code: 'invalid' })
    await expect(s.write('cron.secret', 'too-short', ACTOR, ENV)).rejects.toMatchObject({ code: 'invalid' })
    await expect(s.write('no.such.setting', 'x', ACTOR, ENV)).rejects.toBeInstanceOf(SettingError)
    expect((await db.admin.query('SELECT COUNT(*)::int AS n FROM settings')).rows[0].n).toBe(0)
  })

  it('bumps the version and writes an audit entry in the same transaction', async () => {
    const before = Number((await db.admin.query('SELECT version FROM config_version')).rows[0].version)
    await store(poolA).write('app.name', 'Mail Health', ACTOR, ENV)
    const after = Number((await db.admin.query('SELECT version FROM config_version')).rows[0].version)
    expect(after).toBe(before + 1)
    const audit = (await db.admin.query(`SELECT * FROM audit_log WHERE action = 'setting_changed' ORDER BY id DESC LIMIT 1`)).rows[0]
    expect(audit).toMatchObject({ actor_email: 'owner@example.com', target: 'app.name', ip: '192.0.2.1' })
    expect(audit.detail).toEqual({ key: 'app.name', value: 'Mail Health' })
  })

  it('encrypts secrets, never returns them through a read path, and records only that they changed', async () => {
    const canary = 'canary-cron-secret-7f3a9c2e5b1d'
    const s = store(poolA)
    await s.write('cron.secret', canary, ACTOR, ENV)

    const row = (await db.admin.query(`SELECT value, is_secret FROM settings WHERE key = 'cron.secret'`)).rows[0]
    expect(row.is_secret).toBe(true)
    expect(JSON.stringify(row.value)).not.toContain(canary)

    // the general read path refuses, the display path has no value at all
    await expect(s.get('cron.secret' as never, ENV)).rejects.toMatchObject({ code: 'secret_not_readable' })
    const listed = (await s.list(ENV)).find((x) => x.key === 'cron.secret')!
    expect(listed).toMatchObject({ isSet: true, source: 'database', error: null })
    expect('value' in listed).toBe(false)
    expect(JSON.stringify(await s.list(ENV))).not.toContain(canary)

    // only the consumer gets it
    expect(await s.readSecret('cron.secret', ENV)).toBe(canary)

    const audit = (await db.admin.query(`SELECT detail FROM audit_log WHERE target = 'cron.secret'`)).rows
    expect(JSON.stringify(audit)).not.toContain(canary)
    expect(audit.at(-1).detail).toEqual({ key: 'cron.secret', secret: true, replaced: true })
  })

  it('reports an invalid stored value instead of silently using the default', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    await db.admin.query(`INSERT INTO settings (key, value) VALUES ('ingest.stale_hours', '"soon"')`)
    await db.admin.query(`UPDATE config_version SET version = version + 1`)
    const s = store(poolA)
    const listed = (await s.list(ENV)).find((x) => x.key === 'ingest.stale_hours')!
    expect(listed).toMatchObject({ source: 'database', error: expect.stringMatching(/whole number/) })
    expect(error).toHaveBeenCalledWith(expect.stringContaining('ingest.stale_hours'))
    // the value of a broken setting is never echoed into the log
    expect(error.mock.calls.flat().join(' ')).not.toContain('soon')
  })

  it('reports a secret it cannot decrypt (wrong APP_SECRET) and treats it as unset', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await store(poolA).write('cron.secret', 'x'.repeat(32), ACTOR, ENV)
    const other = { APP_SECRET: 'a-completely-different-app-secret-000000' }
    const s = store(poolA)
    expect(await s.readSecret('cron.secret', other)).toBeNull()
    expect((await s.list(other)).find((x) => x.key === 'cron.secret')).toMatchObject({ isSet: true, error: expect.stringMatching(/unknown_key/) })
    // ...and reads it again once the old secret is given as APP_SECRET_PREVIOUS
    expect(await s.readSecret('cron.secret', { ...other, APP_SECRET_PREVIOUS: APP_SECRET })).toBe('x'.repeat(32))
  })

  it('shows a change made through one pool through another within the cache window', async () => {
    const ttl = 400
    const writer = store(poolA, ttl)
    const reader = store(poolB, ttl)
    expect(await reader.get('app.name', ENV)).toBe('DMARCscope')

    await writer.write('app.name', 'Changed Elsewhere', ACTOR, ENV)
    // inside the window the reader may still answer from its cache...
    const soon = await reader.get('app.name', ENV)
    expect(['DMARCscope', 'Changed Elsewhere']).toContain(soon)
    // ...but never later than the window
    await new Promise((r) => setTimeout(r, ttl + 50))
    expect(await reader.get('app.name', ENV)).toBe('Changed Elsewhere')

    // and an unchanged version does not reload the data
    const spy = vi.spyOn(poolB, 'query')
    await new Promise((r) => setTimeout(r, ttl + 50))
    await reader.get('app.name', ENV)
    expect(spy.mock.calls.map((c) => String(c[0]))).toEqual(['SELECT version FROM config_version'])
  })
})
