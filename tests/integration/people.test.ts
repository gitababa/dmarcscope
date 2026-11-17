// Managing people and access rules (lib/people.ts) against PostgreSQL: every
// action, every guard rail's refusal, and that each is audited.

import pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { authenticate } from '@/lib/auth'
import { PgDirectory } from '@/lib/auth/directory'
import { atLeast } from '@/lib/auth/roles'
import type { Role } from '@/lib/auth/types'
import { setConfigStoreForTests } from '@/lib/settings'
import { ConfigStore } from '@/lib/settings/store'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'

const SCHEMA = 'dmarcscope_people_test'

describe.skipIf(!TEST_DATABASE_URL)('managing people', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let pool: pg.Pool
  let people: typeof import('@/lib/people')
  let admin: typeof import('@/lib/admin')
  const ids: Record<string, number> = {}

  const actor = (who: string, role: Role) => ({ userId: ids[who] ?? null, email: `${who}@example.com`, ip: '192.0.2.9', role })
  const OWNER = () => actor('owner', 'owner')
  const OWNER2 = () => actor('owner2', 'owner')
  const ADMIN = () => actor('admin', 'admin')
  const VIEWER = () => actor('viewer', 'viewer')

  const refused = async (p: Promise<unknown>, code: string) => {
    await expect(p).rejects.toMatchObject({ name: 'Refusal', code })
  }
  const row = async (who: string) => (await db.admin.query(`SELECT * FROM users WHERE id = $1`, [ids[who]])).rows[0]
  const lastAudit = async () => (await db.admin.query(`SELECT action, target, detail, actor_email FROM audit_log ORDER BY id DESC LIMIT 1`)).rows[0]

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    pool = new pg.Pool({ connectionString: db.url, max: 6 })
    setConfigStoreForTests(new ConfigStore(() => pool, () => 0))
    vi.spyOn(console, 'log').mockImplementation(() => {})
    process.env.DATABASE_URL = db.url
    people = await import('@/lib/people')
    admin = await import('@/lib/admin')
  })
  afterAll(async () => {
    vi.restoreAllMocks()
    setConfigStoreForTests(null)
    const { closePool } = await import('@/lib/db')
    await closePool()
    await pool?.end()
    await db?.drop()
  })

  beforeEach(async () => {
    await db.admin.query(`TRUNCATE users, access_rules RESTART IDENTITY CASCADE`)
    const seed: Array<[string, Role, string]> = [
      ['owner', 'owner', 'active'],
      ['owner2', 'owner', 'disabled'],
      ['admin', 'admin', 'active'],
      ['admin2', 'admin', 'active'],
      ['viewer', 'viewer', 'active'],
    ]
    for (const [who, role, status] of seed) {
      const { rows } = await db.admin.query(
        `INSERT INTO users (email, role, role_source, status, source) VALUES ($1, $2, 'assigned', $3, 'oidc') RETURNING id`,
        [`${who}@example.com`, role, status]
      )
      ids[who] = Number(rows[0].id)
    }
    const { rows } = await db.admin.query(
      `INSERT INTO users (email, role, role_source, status, source) VALUES ('asker@elsewhere.test', 'viewer', 'rule', 'pending', 'oidc') RETURNING id`
    )
    ids.asker = Number(rows[0].id)
  })

  it('refuses everything to a viewer, and audits the refusal', async () => {
    await refused(people.inviteUser(pool, VIEWER(), { email: 'x@example.com', role: 'viewer' }), 'not_allowed')
    await refused(people.changeRole(pool, VIEWER(), ids.admin2, 'viewer'), 'not_allowed')
    await refused(people.setDisabled(pool, VIEWER(), ids.admin2, true), 'not_allowed')
    await refused(people.signOutEverywhere(pool, VIEWER(), ids.admin2), 'not_allowed')
    await refused(people.removeUser(pool, VIEWER(), ids.admin2), 'not_allowed')
    await refused(people.approveRequest(pool, VIEWER(), ids.asker, 'viewer'), 'not_allowed')
    await refused(people.rejectRequest(pool, VIEWER(), ids.asker), 'not_allowed')
    await refused(people.addRule(pool, VIEWER(), { kind: 'email_domain', value: 'example.com', role: 'viewer' }), 'not_allowed')
    expect(await lastAudit()).toMatchObject({ action: 'action_refused', actor_email: 'viewer@example.com', detail: { action: 'rule_added', reason: 'not_allowed' } })
    expect((await row('admin2')).role).toBe('admin')
  })

  it('does not let an admin touch an owner or grant owner', async () => {
    await refused(people.changeRole(pool, ADMIN(), ids.owner, 'viewer'), 'target_above_you')
    await refused(people.setDisabled(pool, ADMIN(), ids.owner, true), 'target_above_you')
    await refused(people.signOutEverywhere(pool, ADMIN(), ids.owner), 'target_above_you')
    await refused(people.removeUser(pool, ADMIN(), ids.owner), 'target_above_you')
    await refused(people.changeRole(pool, ADMIN(), ids.viewer, 'owner'), 'role_above_you')
    await refused(people.inviteUser(pool, ADMIN(), { email: 'boss@example.com', role: 'owner' }), 'role_above_you')
    await refused(people.approveRequest(pool, ADMIN(), ids.asker, 'owner'), 'role_above_you')
    expect(await row('owner')).toMatchObject({ role: 'owner', status: 'active', sessions_valid_after: null })
    expect(await lastAudit()).toMatchObject({ action: 'action_refused', detail: { reason: 'role_above_you' } })
  })

  it('lets an admin manage admins and viewers', async () => {
    await people.changeRole(pool, ADMIN(), ids.viewer, 'admin')
    expect(await row('viewer')).toMatchObject({ role: 'admin', role_source: 'assigned' })
    await people.setDisabled(pool, ADMIN(), ids.admin2, true)
    expect((await row('admin2')).status).toBe('disabled')
    expect(await lastAudit()).toMatchObject({ action: 'user_disabled', target: `user:${ids.admin2}`, actor_email: 'admin@example.com' })
    await people.setDisabled(pool, ADMIN(), ids.admin2, false)
    expect((await row('admin2')).status).toBe('active')
    await people.signOutEverywhere(pool, ADMIN(), ids.admin2)
    expect((await row('admin2')).sessions_valid_after).not.toBeNull()
    await people.removeUser(pool, ADMIN(), ids.admin2)
    expect(await row('admin2')).toBeUndefined()
    expect(await lastAudit()).toMatchObject({ action: 'user_removed', detail: { email: 'admin2@example.com', role: 'admin' } })
  })

  it('never leaves no active owner', async () => {
    // the only active owner cannot be demoted, disabled or removed...
    await refused(people.changeRole(pool, OWNER(), ids.owner, 'admin'), 'last_owner')
    // (acting as an owner without a users row, as with AUTH_PROVIDER=none)
    await refused(people.removeUser(pool, { ...OWNER(), userId: null }, ids.owner), 'last_owner')
    await refused(people.setDisabled(pool, { ...OWNER(), userId: null }, ids.owner, true), 'last_owner')
    // ...a disabled owner does not count
    await people.setDisabled(pool, OWNER(), ids.owner2, false)
    // with two active owners, one can step down
    await people.changeRole(pool, OWNER(), ids.owner, 'admin')
    expect((await row('owner')).role).toBe('admin')
    await refused(people.changeRole(pool, OWNER2(), ids.owner2, 'viewer'), 'last_owner')
  })

  it('decides "last owner" atomically when two owners demote each other at once', async () => {
    await people.setDisabled(pool, OWNER(), ids.owner2, false)
    const results = await Promise.allSettled([
      people.changeRole(pool, OWNER(), ids.owner2, 'admin'),
      people.changeRole(pool, OWNER2(), ids.owner, 'admin'),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect(results.filter((r) => r.status === 'rejected' && (r.reason as { code: string }).code === 'last_owner')).toHaveLength(1)
    const owners = (await db.admin.query(`SELECT COUNT(*)::int AS n FROM users WHERE role = 'owner' AND status = 'active'`)).rows[0].n
    expect(owners).toBe(1)
  })

  it('does not let anyone disable or remove themselves', async () => {
    await refused(people.setDisabled(pool, ADMIN(), ids.admin, true), 'self')
    await refused(people.removeUser(pool, ADMIN(), ids.admin), 'self')
    // signing yourself out everywhere is fine
    await people.signOutEverywhere(pool, ADMIN(), ids.admin)
  })

  it('reports a user that is gone instead of acting on stale data', async () => {
    await refused(people.changeRole(pool, ADMIN(), 999_999, 'viewer'), 'not_found')
    await refused(people.removeUser(pool, ADMIN(), 999_999), 'not_found')
  })

  it('approves and rejects requests, and nothing else', async () => {
    await refused(people.approveRequest(pool, ADMIN(), ids.viewer, 'viewer'), 'not_pending')
    await refused(people.rejectRequest(pool, ADMIN(), ids.viewer), 'not_pending')
    await refused(people.approveRequest(pool, ADMIN(), ids.asker, 'superuser'), 'invalid')
    await people.approveRequest(pool, ADMIN(), ids.asker, 'admin')
    expect(await row('asker')).toMatchObject({ status: 'active', role: 'admin', role_source: 'assigned' })
    await refused(people.rejectRequest(pool, ADMIN(), ids.asker), 'not_pending')
  })

  it('rejects a request by disabling it, so the person stays refused', async () => {
    await people.rejectRequest(pool, ADMIN(), ids.asker)
    expect((await row('asker')).status).toBe('disabled')
    expect(await lastAudit()).toMatchObject({ action: 'request_rejected', detail: { email: 'asker@elsewhere.test' } })
  })

  it('invites people, refusing bad and known addresses, and the invitation becomes a user at first sign-in', async () => {
    await refused(people.inviteUser(pool, ADMIN(), { email: 'not an address', role: 'viewer' }), 'invalid')
    await refused(people.inviteUser(pool, ADMIN(), { email: 'Viewer@Example.com', role: 'viewer' }), 'exists')
    await refused(people.inviteUser(pool, ADMIN(), { email: 'asker@elsewhere.test', role: 'viewer' }), 'exists')
    const id = await people.inviteUser(pool, ADMIN(), { email: ' New.Person@Example.com ', role: 'admin' })
    expect((await db.admin.query(`SELECT * FROM users WHERE id = $1`, [id])).rows[0]).toMatchObject({
      email: 'new.person@example.com',
      status: 'pending',
      role: 'admin',
      role_source: 'assigned',
      invited_by: String(ids.admin),
    })
    // an invitation is not a request: it cannot be "approved" or "rejected"
    await refused(people.rejectRequest(pool, ADMIN(), id), 'not_pending')

    const proxyReq = { headers: { get: (n: string) => (n === 'x-forwarded-email' ? 'new.person@example.com' : null) }, cookie: () => undefined }
    const result = await authenticate(proxyReq, { AUTH_PROVIDER: 'proxy-header' }, new PgDirectory(() => pool))
    expect(result).toMatchObject({ status: 'ok', session: { role: 'admin', userId: id } })
    expect((await db.admin.query(`SELECT status FROM users WHERE id = $1`, [id])).rows[0].status).toBe('active')
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM audit_log WHERE action = 'invitation_accepted'`)).rows[0].n).toBe(1)
  })

  it('takes the panel away from a demoted admin on their next request', async () => {
    const dir = new PgDirectory(() => pool)
    const req = { headers: { get: (n: string) => (n === 'x-forwarded-email' ? 'admin2@example.com' : null) }, cookie: () => undefined }
    const env = { AUTH_PROVIDER: 'proxy-header' }
    const before = await authenticate(req, env, dir)
    expect(before.status === 'ok' && atLeast(before.session.role, 'admin')).toBe(true)
    await people.changeRole(pool, ADMIN(), ids.admin2, 'viewer')
    const after = await authenticate(req, env, dir)
    expect(after).toMatchObject({ status: 'ok', session: { role: 'viewer' } })
    expect(after.status === 'ok' && atLeast(after.session.role, 'admin')).toBe(false)
    // and the admin reads refuse them even if a page forgot to check
    await expect(admin.listUsers({ role: 'viewer', session: {}, domains: {} } as never)).rejects.toBeInstanceOf(admin.AdminAccessError)
  })

  it('manages access rules within the caller’s role', async () => {
    await refused(people.addRule(pool, ADMIN(), { kind: 'email_domain', value: 'not a domain', role: 'viewer' }), 'invalid')
    await refused(people.addRule(pool, ADMIN(), { kind: 'group', value: 'a,b', role: 'viewer' }), 'invalid')
    await refused(people.addRule(pool, ADMIN(), { kind: 'regex', value: 'x', role: 'viewer' }), 'invalid')
    await refused(people.addRule(pool, OWNER(), { kind: 'group', value: 'bosses', role: 'owner' }), 'invalid')
    const before = Number((await db.admin.query(`SELECT version FROM config_version`)).rows[0].version)
    const id = await people.addRule(pool, ADMIN(), { kind: 'email_domain', value: 'Example.ORG', role: 'admin' })
    expect(Number((await db.admin.query(`SELECT version FROM config_version`)).rows[0].version)).toBeGreaterThan(before)
    await refused(people.addRule(pool, ADMIN(), { kind: 'email_domain', value: 'example.org', role: 'viewer' }), 'duplicate')
    const rules = await admin.listRules({ role: 'admin', session: {}, domains: {} } as never)
    expect(rules).toMatchObject([{ id, kind: 'email_domain', value: 'example.org', role: 'admin', created_by_email: 'admin@example.com' }])
    await refused(people.deleteRule(pool, VIEWER(), id), 'not_allowed')
    await people.deleteRule(pool, ADMIN(), id)
    await refused(people.deleteRule(pool, ADMIN(), id), 'not_found')
    expect(await lastAudit()).toMatchObject({ action: 'action_refused', detail: { action: 'rule_deleted', reason: 'not_found' } })
  })

  it('refuses a caller whose own account was disabled or removed since their request started', async () => {
    await db.admin.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [ids.admin])
    await refused(people.changeRole(pool, ADMIN(), ids.viewer, 'admin'), 'not_allowed')
    await db.admin.query(`DELETE FROM users WHERE id = $1`, [ids.admin])
    await refused(people.signOutEverywhere(pool, ADMIN(), ids.viewer), 'not_allowed')
    expect((await row('viewer')).role).toBe('viewer')
  })

  it('does not let an admin approve or reject a request an owner raised to owner', async () => {
    await db.admin.query(`UPDATE users SET role = 'owner' WHERE id = $1`, [ids.asker])
    await refused(people.approveRequest(pool, ADMIN(), ids.asker, 'viewer'), 'target_above_you')
    await refused(people.rejectRequest(pool, ADMIN(), ids.asker), 'target_above_you')
  })

  it('lets a rejected person in when an administrator enables them again', async () => {
    await people.rejectRequest(pool, ADMIN(), ids.asker)
    const req = { headers: { get: (n: string) => (n === 'x-forwarded-email' ? 'asker@elsewhere.test' : null) }, cookie: () => undefined }
    const dir = new PgDirectory(() => pool)
    expect(await authenticate(req, { AUTH_PROVIDER: 'proxy-header' }, dir)).toMatchObject({ status: 'forbidden' })
    await people.setDisabled(pool, ADMIN(), ids.asker, false)
    expect(await authenticate(req, { AUTH_PROVIDER: 'proxy-header' }, dir)).toMatchObject({ status: 'ok', session: { role: 'viewer' } })
  })

  it('does not accept an invitation that was disabled at the same moment', async () => {
    const id = await people.inviteUser(pool, ADMIN(), { email: 'race@example.com', role: 'admin' })
    const real = new PgDirectory(() => pool)
    // the invitation is disabled between reading the row and accepting it
    const racing = Object.assign(Object.create(real), {
      acceptInvitation: async (uid: number) => {
        await db.admin.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [uid])
        return real.acceptInvitation(uid)
      },
    })
    const req = { headers: { get: (n: string) => (n === 'x-forwarded-email' ? 'race@example.com' : null) }, cookie: () => undefined }
    expect(await authenticate(req, { AUTH_PROVIDER: 'proxy-header' }, racing)).toMatchObject({ status: 'forbidden' })
    expect((await db.admin.query(`SELECT status FROM users WHERE id = $1`, [id])).rows[0].status).toBe('disabled')
  })

  it('lists people with search and filters, matching % and _ literally', async () => {
    const access = { role: 'admin', session: {}, domains: {} } as never
    expect((await admin.listUsers(access, { q: 'ADMIN' })).rows.map((r) => r.email)).toEqual(['admin2@example.com', 'admin@example.com'])
    expect((await admin.listUsers(access, { status: 'pending' })).rows.map((r) => r.email)).toEqual(['asker@elsewhere.test'])
    expect((await admin.listUsers(access, { role: 'owner' })).total).toBe(2)
    expect((await admin.listUsers(access, { q: '%' })).total).toBe(0)
    expect((await admin.listUsers(access, { q: '_' })).total).toBe(0)
    expect((await admin.listPendingRequests(access)).map((r) => r.email)).toEqual(['asker@elsewhere.test'])
    expect(admin.parseUserFilters({ status: 'weird', role: 'god', page: '-3', q: '  x  ' })).toEqual({ q: 'x', status: undefined, role: undefined, source: undefined, page: 1 })
  })

  it('filters the audit log and exports it as CSV that spreadsheets will not execute', async () => {
    const access = { role: 'admin', session: {}, domains: {} } as never
    await db.admin.query(
      `INSERT INTO audit_log (actor_email, action, target, detail) VALUES ('=HYPERLINK("http://evil")@x.test', 'sign_in_failed', NULL, '{"reason":"wrong_password"}')`
    )
    const rows = await admin.listAudit(access, { action: 'sign_in_failed' })
    expect(rows.map((r) => r.action)).toEqual(['sign_in_failed'])
    expect(await admin.listAudit(access, { actor: 'hyperlink' })).toHaveLength(1)
    expect(await admin.listAudit(access, { from: '2999-01-01' })).toEqual([])
    const csv = admin.auditCsv(await admin.exportAudit(access, { action: 'sign_in_failed' }))
    expect(csv.split('\r\n')[0]).toBe('id,at,actor_email,action,target,ip,detail')
    expect(csv).toContain(`"'=HYPERLINK(""http://evil"")@x.test"`)
    expect(csv).not.toMatch(/,=HYPERLINK/)
  })
})
