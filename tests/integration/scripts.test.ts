// The operator commands, run as real processes against PostgreSQL:
//   npm run settings:import     environment access lists → database
//   npm run secrets:reencrypt   APP_SECRET rotation

import { execFile } from 'node:child_process'
import path from 'node:path'
import { promisify } from 'node:util'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { decrypt, encrypt } from '@/lib/envelope.mjs'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'

const run = promisify(execFile)
const ROOT = path.resolve(__dirname, '../..')
const SCHEMA = 'dmarcscope_scripts_test'
const OLD = 'old-app-secret-for-rotation-test-000000000'
const NEW = 'new-app-secret-for-rotation-test-111111111'

async function script(name: string, env: Record<string, string>, args: string[] = []) {
  try {
    const { stdout, stderr } = await run(process.execPath, [path.join(ROOT, 'scripts', name), ...args], { env: { PATH: process.env.PATH, ...env } as unknown as NodeJS.ProcessEnv })
    return { code: 0, json: JSON.parse(stdout.trim().split('\n').at(-1)!), stderr }
  } catch (err) {
    const e = err as { code: number; stdout: string; stderr: string }
    return { code: e.code, json: e.stdout ? JSON.parse(e.stdout.trim().split('\n').at(-1)!) : null, stderr: e.stderr }
  }
}

describe.skipIf(!TEST_DATABASE_URL)('operator commands', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  beforeAll(async () => {
    db = await createSchema(SCHEMA)
  })
  afterAll(async () => {
    await db?.drop()
  })

  it('imports the access lists idempotently, never lowering a role or touching the owner', async () => {
    await db.admin.query(`
      INSERT INTO users (email, role, role_source, status, source) VALUES
        ('owner@example.com', 'owner', 'assigned', 'active', 'local'),
        ('pending@example.com', 'viewer', 'rule', 'pending', 'oidc'),
        ('gone@example.com', 'viewer', 'assigned', 'disabled', 'oidc')`)
    const env = {
      DATABASE_URL: db.url,
      AUTH_PROVIDER: 'oidc',
      ADMIN_EMAILS: 'Admin@Example.com, owner@example.com, gone@example.com',
      ALLOWED_EMAILS: 'viewer@example.com,pending@example.com,admin@example.com,not-an-address',
      ALLOWED_EMAIL_DOMAINS: 'example.org',
      ADMIN_GROUPS: 'dmarc-admins',
      ALLOWED_GROUPS: 'staff,dmarc-admins',
      AUTH_ALLOW_ANY_AUTHENTICATED: 'true',
    }

    const dry = await script('settings-import.mjs', env, ['--dry-run'])
    expect(dry.code).toBe(0)
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM access_rules`)).rows[0].n).toBe(0)

    const first = await script('settings-import.mjs', env)
    expect(first.code).toBe(0)
    expect(first.json).toMatchObject({ users_added: 2, users_updated: 1, rules_added: 3, skipped: ['not an email address: not-an-address'] })
    expect(first.stderr).toMatch(/AUTH_ALLOW_ANY_AUTHENTICATED/)

    const users = Object.fromEntries((await db.admin.query(`SELECT email, role, role_source, status FROM users`)).rows.map((r) => [r.email, r]))
    expect(users['owner@example.com']).toMatchObject({ role: 'owner', status: 'active' })
    expect(users['admin@example.com']).toMatchObject({ role: 'admin', role_source: 'assigned', status: 'active' })
    expect(users['viewer@example.com']).toMatchObject({ role: 'viewer', status: 'active' })
    expect(users['pending@example.com']).toMatchObject({ role: 'viewer', role_source: 'assigned', status: 'active' })
    expect(users['gone@example.com']).toMatchObject({ status: 'disabled' })
    const rules = (await db.admin.query(`SELECT kind, value, role FROM access_rules ORDER BY kind, value`)).rows
    expect(rules).toEqual([
      { kind: 'email_domain', value: 'example.org', role: 'viewer' },
      { kind: 'group', value: 'dmarc-admins', role: 'admin' },
      { kind: 'group', value: 'staff', role: 'viewer' },
    ])

    const second = await script('settings-import.mjs', env)
    expect(second.json).toMatchObject({ users_added: 0, users_updated: 0, rules_added: 0, rules_updated: 0 })
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM audit_log WHERE action = 'settings_imported'`)).rows[0].n).toBe(1)
  })

  it('re-encrypts secrets under the new APP_SECRET, all or nothing', async () => {
    await db.admin.query(`INSERT INTO settings (key, value, is_secret) VALUES ('cron.secret', $1, TRUE)`, [
      JSON.stringify(encrypt({ secret: OLD, purpose: 'setting', context: 'cron.secret', plaintext: 'rotation-canary-value-1' })),
    ])
    const { rows } = await db.admin.query(`SELECT id FROM users WHERE email = 'owner@example.com'`)
    const ownerId = rows[0].id
    await db.admin.query(`UPDATE users SET totp_secret = $2 WHERE id = $1`, [
      ownerId,
      encrypt({ secret: OLD, purpose: 'totp', context: `user:${ownerId}`, plaintext: 'JBSWY3DPEHPK3PXP' }),
    ])
    const sso = (await db.admin.query(`INSERT INTO sso_connections (state, preset, issuer, client_id) VALUES ('draft', 'generic', 'https://idp.example', 'c') RETURNING id`)).rows[0].id
    await db.admin.query(`UPDATE sso_connections SET client_secret = $2 WHERE id = $1`, [
      sso,
      encrypt({ secret: OLD, purpose: 'setting', context: `sso:${sso}`, plaintext: 'rotation-canary-sso' }),
    ])
    const mbx = (await db.admin.query(`INSERT INTO mailboxes (name, kind, host, port, security, username) VALUES ('m', 'imap', 'imap.example', 993, 'ssl', 'r@example.com') RETURNING id`)).rows[0].id
    await db.admin.query(`UPDATE mailboxes SET secret = $2 WHERE id = $1`, [
      mbx,
      encrypt({ secret: OLD, purpose: 'mailbox', context: `mailbox:${mbx}`, plaintext: 'rotation-canary-mailbox' }),
    ])

    // without the old secret nothing can be read, so nothing changes
    const blind = await script('secrets-reencrypt.mjs', { DATABASE_URL: db.url, APP_SECRET: NEW })
    expect(blind.code).toBe(1)
    expect(blind.json.failed).toHaveLength(4)
    expect(blind.stderr).not.toMatch(/rotation-canary/)

    const env = { DATABASE_URL: db.url, APP_SECRET: NEW, APP_SECRET_PREVIOUS: OLD }
    const done = await script('secrets-reencrypt.mjs', env)
    expect(done.code).toBe(0)
    expect(done.json).toMatchObject({ checked: 4, reencrypted: 4, failed: [] })
    const after = await db.admin.query(
      `SELECT (SELECT client_secret FROM sso_connections WHERE id = $1) AS s, (SELECT secret FROM mailboxes WHERE id = $2) AS m`,
      [sso, mbx]
    )
    expect(decrypt({ secrets: [NEW], purpose: 'setting', context: `sso:${sso}`, envelope: after.rows[0].s }).plaintext).toBe('rotation-canary-sso')
    expect(decrypt({ secrets: [NEW], purpose: 'mailbox', context: `mailbox:${mbx}`, envelope: after.rows[0].m }).plaintext).toBe('rotation-canary-mailbox')

    // now readable with the new secret alone
    const { ConfigStore } = await import('@/lib/settings/store')
    const pg = (await import('pg')).default
    const pool = new pg.Pool({ connectionString: db.url })
    try {
      expect(await new ConfigStore(() => pool, () => 0).readSecret('cron.secret', { APP_SECRET: NEW })).toBe('rotation-canary-value-1')
    } finally {
      await pool.end()
    }
    expect((await script('secrets-reencrypt.mjs', { DATABASE_URL: db.url, APP_SECRET: NEW })).json).toMatchObject({ checked: 4, reencrypted: 0 })
  })

  it('refuses to run without its configuration', async () => {
    expect((await script('secrets-reencrypt.mjs', { DATABASE_URL: db.url, APP_SECRET: 'short' })).code).toBe(2)
    expect((await script('settings-import.mjs', {})).code).toBe(2)
  })
})
