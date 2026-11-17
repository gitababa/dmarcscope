// Managing people and access rules (milestone 2). The server actions in
// app/(app)/admin/ call these; they hold every rule about who may do what, so
// that the rules are tested against the database without Next.js.
//
//   - Only admins and owners may change anything here.
//   - An actor may change only users whose role is at or below their own,
//     and grant only roles at or below their own (only an owner makes owners).
//   - Nobody disables or removes themselves.
//   - The last active owner cannot be demoted, disabled or removed. Decided in
//     the transaction with every owner row locked, so two owners acting at once
//     cannot leave none.
//   - Each change runs in one transaction with the target row locked and
//     re-read, writes an audit entry, and bumps config_version (the cached
//     owner flag and access rules). A refusal is audited too.

import type { Pool, PoolClient } from 'pg'
import { type Actor, recordAudit, writeAudit } from './audit'
import { authProvider } from './auth'
import { atLeast, isRole } from './auth/roles'
import type { Role } from './auth/types'

export type PeopleActor = Actor & { userId: number | null; role: Role }

export type RefusalCode =
  | 'not_allowed' // caller is not an admin
  | 'not_found' // no such user or rule (or it changed meanwhile)
  | 'target_above_you' // the user's role is above the caller's
  | 'role_above_you' // the role to grant is above the caller's
  | 'last_owner' // would leave no active owner
  | 'self' // disable or remove yourself
  | 'not_pending' // approve or reject something that is not a request
  | 'exists' // invite an address that is already known
  | 'invalid' // malformed address, role, rule value
  | 'duplicate' // that rule exists already

export class Refusal extends Error {
  constructor(public code: RefusalCode) {
    super(code)
    this.name = 'Refusal'
  }
}

const EMAIL = /^[^@\s,<>"]+@[^@\s,<>"]+\.[^@\s,<>"]+$/
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

export function normalizeEmail(raw: string): string | null {
  const email = raw.trim().toLowerCase()
  return email.length <= 254 && EMAIL.test(email) ? email : null
}

function parseRole(raw: unknown): Role {
  if (!isRole(raw)) throw new Refusal('invalid')
  return raw
}

type Locked = { id: number; email: string; role: Role; status: string; invited_at: string | null; role_source: string }

async function transaction<T>(db: Pool, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await db.connect()
  try {
    await client.query('BEGIN')
    const out = await fn(client)
    await client.query('UPDATE config_version SET version = version + 1')
    await client.query('COMMIT')
    return out
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    client.release()
  }
}

// Locks every owner row (in id order, so concurrent calls queue instead of
// deadlocking), then the target. Returns the target as it is now and the
// number of active owners.
async function lockTarget(c: PoolClient, id: number): Promise<{ target: Locked; activeOwners: number }> {
  const owners = await c.query<{ id: string; status: string }>(`SELECT id, status FROM users WHERE role = 'owner' ORDER BY id FOR UPDATE`)
  const { rows } = await c.query<Locked & { id: string }>(
    `SELECT id, email, role, status, invited_at, role_source FROM users WHERE id = $1 FOR UPDATE`,
    [id]
  )
  if (!rows[0]) throw new Refusal('not_found')
  return { target: { ...rows[0], id: Number(rows[0].id) }, activeOwners: owners.rows.filter((o) => o.status === 'active').length }
}

function mayActOn(actor: PeopleActor, target: Locked): void {
  if (!atLeast(actor.role, target.role)) throw new Refusal('target_above_you')
}

function mayGrant(actor: PeopleActor, role: Role): void {
  if (!atLeast(actor.role, role)) throw new Refusal('role_above_you')
}

// Would this change leave no active owner?
function guardLastOwner(target: Locked, activeOwners: number, stillActiveOwner: boolean): void {
  if (target.role === 'owner' && target.status === 'active' && !stillActiveOwner && activeOwners <= 1) {
    throw new Refusal('last_owner')
  }
}

// Runs one action: role check, transaction, audit of success or refusal.
async function act<T>(
  db: Pool,
  actor: PeopleActor,
  action: string,
  target: string,
  fn: (c: PoolClient) => Promise<{ result: T; detail: Record<string, unknown>; target?: string }>
): Promise<T> {
  try {
    if (!atLeast(actor.role, 'admin')) throw new Refusal('not_allowed')
    return await transaction(db, async (c) => {
      const { result, detail, target: finalTarget } = await fn(c)
      await writeAudit(c, { action, actor, target: finalTarget ?? target, detail })
      return result
    })
  } catch (err) {
    if (err instanceof Refusal) {
      await recordAudit(db, { action: 'action_refused', actor, target, detail: { action, reason: err.code } })
    }
    throw err
  }
}

const userTarget = (id: number) => `user:${id}`

// ---------- users ----------

// How an invited person will sign in: through the proxy in front, or single
// sign-on (configured in the environment now, in the panel from milestone 3).
function inviteSource(): 'proxy' | 'oidc' {
  const p = authProvider()
  return p === 'proxy-jwt' || p === 'proxy-header' ? 'proxy' : 'oidc'
}

export async function inviteUser(db: Pool, actor: PeopleActor, input: { email: string; role: unknown }): Promise<number> {
  return act(db, actor, 'user_invited', `email:${input.email.trim().toLowerCase().slice(0, 254)}`, async (c) => {
    const email = normalizeEmail(input.email)
    if (!email) throw new Refusal('invalid')
    const role = parseRole(input.role)
    mayGrant(actor, role)
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO users (email, role, role_source, status, source, invited_at, invited_by, created_by)
       VALUES ($1, $2, 'assigned', 'pending', $4, NOW(), $3, $3)
       ON CONFLICT (email) DO NOTHING RETURNING id`,
      [email, role, actor.userId, inviteSource()]
    )
    if (!rows[0]) throw new Refusal('exists')
    const id = Number(rows[0].id)
    return { result: id, detail: { email, role }, target: userTarget(id) }
  })
}

export async function approveRequest(db: Pool, actor: PeopleActor, id: number, roleInput: unknown): Promise<void> {
  await act(db, actor, 'request_approved', userTarget(id), async (c) => {
    const role = parseRole(roleInput)
    mayGrant(actor, role)
    const { target } = await lockTarget(c, id)
    if (target.status !== 'pending' || target.invited_at) throw new Refusal('not_pending')
    await c.query(`UPDATE users SET role = $2, role_source = 'assigned', status = 'active' WHERE id = $1`, [id, role])
    return { result: undefined, detail: { email: target.email, role } }
  })
}

export async function rejectRequest(db: Pool, actor: PeopleActor, id: number): Promise<void> {
  await act(db, actor, 'request_rejected', userTarget(id), async (c) => {
    const { target } = await lockTarget(c, id)
    if (target.status !== 'pending' || target.invited_at) throw new Refusal('not_pending')
    await c.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [id])
    return { result: undefined, detail: { email: target.email } }
  })
}

export async function changeRole(db: Pool, actor: PeopleActor, id: number, roleInput: unknown): Promise<void> {
  await act(db, actor, 'role_changed', userTarget(id), async (c) => {
    const role = parseRole(roleInput)
    const { target, activeOwners } = await lockTarget(c, id)
    mayActOn(actor, target)
    mayGrant(actor, role)
    guardLastOwner(target, activeOwners, role === 'owner')
    await c.query(`UPDATE users SET role = $2, role_source = 'assigned' WHERE id = $1`, [id, role])
    return { result: undefined, detail: { email: target.email, from: target.role, to: role } }
  })
}

export async function setDisabled(db: Pool, actor: PeopleActor, id: number, disabled: boolean): Promise<void> {
  await act(db, actor, disabled ? 'user_disabled' : 'user_enabled', userTarget(id), async (c) => {
    const { target, activeOwners } = await lockTarget(c, id)
    mayActOn(actor, target)
    if (disabled && actor.userId === id) throw new Refusal('self')
    if (disabled) guardLastOwner(target, activeOwners, false)
    // Re-enabling a pending request means letting the person in: same as approving.
    await c.query(`UPDATE users SET status = $2 WHERE id = $1`, [id, disabled ? 'disabled' : 'active'])
    return { result: undefined, detail: { email: target.email, from: target.status } }
  })
}

export async function signOutEverywhere(db: Pool, actor: PeopleActor, id: number): Promise<void> {
  await act(db, actor, 'sessions_revoked', userTarget(id), async (c) => {
    const { target } = await lockTarget(c, id)
    mayActOn(actor, target)
    await c.query(`UPDATE users SET sessions_valid_after = NOW() WHERE id = $1`, [id])
    return { result: undefined, detail: { email: target.email } }
  })
}

export async function removeUser(db: Pool, actor: PeopleActor, id: number): Promise<void> {
  await act(db, actor, 'user_removed', userTarget(id), async (c) => {
    const { target, activeOwners } = await lockTarget(c, id)
    mayActOn(actor, target)
    if (actor.userId === id) throw new Refusal('self')
    guardLastOwner(target, activeOwners, false)
    await c.query(`DELETE FROM users WHERE id = $1`, [id])
    return { result: undefined, detail: { email: target.email, role: target.role } }
  })
}

// ---------- access rules ----------

export function normalizeRuleValue(kind: unknown, raw: string): { kind: 'email_domain' | 'group'; value: string } | null {
  const value = raw.trim().toLowerCase()
  if (kind === 'email_domain') return DOMAIN.test(value) ? { kind, value } : null
  if (kind === 'group') return value.length >= 1 && value.length <= 256 && !/[\x00-\x1f\x7f,]/.test(value) ? { kind, value } : null
  return null
}

export async function addRule(db: Pool, actor: PeopleActor, input: { kind: unknown; value: string; role: unknown }): Promise<number> {
  return act(db, actor, 'rule_added', 'rule:new', async (c) => {
    const rule = normalizeRuleValue(input.kind, input.value)
    if (!rule) throw new Refusal('invalid')
    const role = parseRole(input.role)
    if (role === 'owner') throw new Refusal('invalid') // rules never make owners
    mayGrant(actor, role)
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO access_rules (kind, value, role, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (kind, value) DO NOTHING RETURNING id`,
      [rule.kind, rule.value, role, actor.userId]
    )
    if (!rows[0]) throw new Refusal('duplicate')
    const id = Number(rows[0].id)
    return { result: id, detail: { kind: rule.kind, value: rule.value, role }, target: `rule:${id}` }
  })
}

export async function deleteRule(db: Pool, actor: PeopleActor, id: number): Promise<void> {
  await act(db, actor, 'rule_deleted', `rule:${id}`, async (c) => {
    const { rows } = await c.query<{ kind: string; value: string; role: Role }>(
      `SELECT kind, value, role FROM access_rules WHERE id = $1 FOR UPDATE`,
      [id]
    )
    if (!rows[0]) throw new Refusal('not_found')
    // Removing a rule takes access away; an admin may not take away what only
    // an owner could have granted.
    mayGrant(actor, rows[0].role)
    await c.query(`DELETE FROM access_rules WHERE id = $1`, [id])
    return { result: undefined, detail: rows[0] }
  })
}
