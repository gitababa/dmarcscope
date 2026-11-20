// SCIM 2.0 (RFC 7643, 7644) for users and groups, behind the SCIM token.
//
// What SCIM may and may not do (docs/enterprise.md, SCIM provisioning):
//   - create viewers; never any other role, and it cannot change anyone's role;
//   - never touch an owner (every operation on one is refused);
//   - never change a user's userName (the e-mail address is the identity: a
//     rename could hand an administrator's account to someone else);
//   - deactivate (active:false, or DELETE) takes effect on the person's next
//     request: status becomes 'disabled' and their sessions are cut off;
//   - groups count for domain scopes only. They never feed access rules, so a
//     SCIM group cannot grant a role by being named like an administrators group.
// Every change is audited as `scim:<token name>`.

import type { Pool, PoolClient } from 'pg'
import { type Actor, writeAudit } from './audit'
import { normalizeEmail } from './people'

export const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
export const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group'
export const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
export const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
export const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error'

export const MAX_BODY_BYTES = 256 * 1024
export const MAX_MEMBERS = 1000
export const MAX_PAGE = 100

export class ScimError extends Error {
  constructor(
    public status: number,
    public detail: string,
    public scimType?: string
  ) {
    super(detail)
    this.name = 'ScimError'
  }
}

type Ctx = { db: Pool; actor: Actor; base: string }

// ---------- resources ----------

type UserRow = { id: string; email: string; name: string | null; status: string; role: string; external_id: string | null; created_at: string; source: string }

const USER_COLUMNS = 'id, email, name, status, role, external_id, created_at, source'

function userResource(r: UserRow, base: string, groups: Array<{ value: string; display: string }> = []) {
  return {
    schemas: [USER_SCHEMA],
    id: String(r.id),
    ...(r.external_id ? { externalId: r.external_id } : {}),
    userName: r.email,
    ...(r.name ? { name: { formatted: r.name }, displayName: r.name } : {}),
    emails: [{ value: r.email, primary: true }],
    active: r.status === 'active',
    groups,
    meta: { resourceType: 'User', created: r.created_at, location: `${base}/scim/v2/Users/${r.id}` },
  }
}

type GroupRow = { id: string; display_name: string; external_id: string | null; created_at: string; updated_at: string }

function groupResource(r: GroupRow, base: string, members: Array<{ value: string; display?: string }>) {
  return {
    schemas: [GROUP_SCHEMA],
    id: String(r.id),
    ...(r.external_id ? { externalId: r.external_id } : {}),
    displayName: r.display_name,
    members,
    meta: { resourceType: 'Group', created: r.created_at, lastModified: r.updated_at, location: `${base}/scim/v2/Groups/${r.id}` },
  }
}

// ---------- input helpers ----------

const asObject = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new ScimError(400, 'The body must be a JSON object.', 'invalidSyntax')
  return v as Record<string, unknown>
}

const str = (v: unknown, field: string, max: number): string | null => {
  if (v == null) return null
  if (typeof v !== 'string' || v.length > max || /[\x00-\x1f\x7f]/.test(v)) throw new ScimError(400, `${field} is not valid.`, 'invalidValue')
  return v
}

// Entra sends booleans as the strings "True" and "False".
const bool = (v: unknown): boolean => {
  if (typeof v === 'boolean') return v
  if (typeof v === 'string' && /^(true|false)$/i.test(v)) return v.toLowerCase() === 'true'
  throw new ScimError(400, 'active must be true or false.', 'invalidValue')
}

const idOf = (raw: string): number => {
  if (!/^\d{1,15}$/.test(raw)) throw new ScimError(404, 'Resource not found.')
  return Number(raw)
}

// Only: userName eq "x", externalId eq "x", displayName eq "x".
export function parseFilter(raw: string | null, allowed: string[]): { attr: string; value: string } | null {
  if (!raw) return null
  const m = /^\s*([A-Za-z]+)\s+eq\s+"((?:[^"\\]|\\.){0,300})"\s*$/i.exec(raw)
  const attr = m && allowed.find((a) => a.toLowerCase() === m[1].toLowerCase())
  if (!m || !attr) throw new ScimError(400, `Only "eq" filters on ${allowed.join(', ')} are supported.`, 'invalidFilter')
  return { attr, value: m[2].replace(/\\(.)/g, '$1') }
}

function page(startIndex: string | null, count: string | null): { offset: number; limit: number; start: number } {
  const start = startIndex && /^\d{1,9}$/.test(startIndex) ? Math.max(1, Number(startIndex)) : 1
  const limit = count && /^\d{1,9}$/.test(count) ? Math.min(MAX_PAGE, Number(count)) : MAX_PAGE
  return { offset: start - 1, limit, start }
}

async function tx<T>(db: Pool, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await db.connect()
  try {
    await c.query('BEGIN')
    const out = await fn(c)
    await c.query('COMMIT')
    return out
  } catch (err) {
    await c.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    c.release()
  }
}

const refuseOwner = (role: string) => {
  if (role === 'owner') throw new ScimError(403, 'SCIM cannot change an owner account.', 'forbidden')
}

// ---------- users ----------

async function userGroups(db: Pick<Pool, 'query'>, ids: number[]): Promise<Map<number, Array<{ value: string; display: string }>>> {
  const out = new Map<number, Array<{ value: string; display: string }>>()
  if (ids.length === 0) return out
  const { rows } = await db.query<{ user_id: string; id: string; display_name: string }>(
    `SELECT m.user_id, g.id, g.display_name FROM group_members m JOIN groups g ON g.id = m.group_id WHERE m.user_id = ANY($1::bigint[]) ORDER BY g.id`,
    [ids]
  )
  for (const r of rows) {
    const list = out.get(Number(r.user_id)) ?? []
    list.push({ value: String(r.id), display: r.display_name })
    out.set(Number(r.user_id), list)
  }
  return out
}

export async function listUsers(ctx: Ctx, q: URLSearchParams) {
  const f = parseFilter(q.get('filter'), ['userName', 'externalId', 'displayName'])
  const p = page(q.get('startIndex'), q.get('count'))
  const where = !f ? 'TRUE' : f.attr === 'userName' ? 'email = lower($1)' : f.attr === 'externalId' ? 'external_id = $1' : 'name = $1'
  const args = f ? [f.value] : []
  const total = Number((await ctx.db.query<{ n: string }>(`SELECT count(*) AS n FROM users WHERE ${where}`, args)).rows[0].n)
  const { rows } = await ctx.db.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE ${where} ORDER BY id LIMIT ${p.limit} OFFSET ${p.offset}`, args)
  const groups = await userGroups(ctx.db, rows.map((r) => Number(r.id)))
  return { schemas: [LIST_SCHEMA], totalResults: total, startIndex: p.start, itemsPerPage: rows.length, Resources: rows.map((r) => userResource(r, ctx.base, groups.get(Number(r.id)))) }
}

export async function getUser(ctx: Ctx, rawId: string) {
  const id = idOf(rawId)
  const r = (await ctx.db.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = $1`, [id])).rows[0]
  if (!r) throw new ScimError(404, 'Resource not found.')
  return userResource(r, ctx.base, (await userGroups(ctx.db, [id])).get(id))
}

function displayName(b: Record<string, unknown>): string | null {
  const name = b.name && typeof b.name === 'object' ? (b.name as Record<string, unknown>).formatted : undefined
  return str(b.displayName ?? name, 'displayName', 200)
}

export async function createUser(ctx: Ctx, body: unknown) {
  const b = asObject(body)
  const email = normalizeEmail(str(b.userName, 'userName', 254) ?? '')
  if (!email) throw new ScimError(400, 'userName must be an e-mail address.', 'invalidValue')
  const externalId = str(b.externalId, 'externalId', 200)
  const active = b.active === undefined ? true : bool(b.active)
  const created = await tx(ctx.db, async (c) => {
    const dup = await c.query(`SELECT 1 FROM users WHERE email = $1 OR ($2::text IS NOT NULL AND external_id = $2)`, [email, externalId])
    if (dup.rowCount) throw new ScimError(409, 'A user with this userName or externalId exists.', 'uniqueness')
    const { rows } = await c.query<UserRow>(
      `INSERT INTO users (email, name, role, role_source, status, source, external_id)
       VALUES ($1, $2, 'viewer', 'assigned', $3, 'scim', $4) RETURNING ${USER_COLUMNS}`,
      [email, displayName(b), active ? 'active' : 'disabled', externalId]
    )
    await writeAudit(c, { action: 'scim_user_created', actor: ctx.actor, target: `user:${rows[0].id}`, detail: { email, active } })
    return rows[0]
  })
  return userResource(created, ctx.base)
}

type UserChange = { name?: string | null; externalId?: string | null; active?: boolean }

async function applyUserChange(ctx: Ctx, c: PoolClient, id: number, change: UserChange) {
  const cur = (await c.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = $1 FOR UPDATE`, [id])).rows[0]
  if (!cur) throw new ScimError(404, 'Resource not found.')
  refuseOwner(cur.role)
  const sets: string[] = []
  const args: unknown[] = [id]
  const set = (col: string, v: unknown) => {
    args.push(v)
    sets.push(`${col} = $${args.length}`)
  }
  if (change.name !== undefined) set('name', change.name)
  if (change.externalId !== undefined) {
    if (change.externalId !== null && change.externalId !== cur.external_id) {
      const taken = await c.query(`SELECT 1 FROM users WHERE external_id = $1 AND id <> $2`, [change.externalId, id])
      if (taken.rowCount) throw new ScimError(409, 'That externalId belongs to another user.', 'uniqueness')
    }
    set('external_id', change.externalId)
  }
  let action = 'scim_user_updated'
  if (change.active === false && cur.status !== 'disabled') {
    set('status', 'disabled')
    sets.push('sessions_valid_after = NOW()')
    action = 'scim_user_deactivated'
  } else if (change.active === true && cur.status !== 'active') {
    // A person an administrator disabled stays disabled until an administrator
    // enables them: the identity provider may switch off, never switch on, a
    // role above viewer.
    if (cur.role !== 'viewer') throw new ScimError(403, 'SCIM cannot activate an administrator; enable them in the panel.', 'forbidden')
    set('status', 'active')
    sets.push(`role_source = 'assigned'`)
    action = 'scim_user_activated'
  }
  if (sets.length) await c.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $1`, args)
  await writeAudit(c, { action, actor: ctx.actor, target: `user:${id}`, detail: { email: cur.email, ...(change.active !== undefined ? { active: change.active } : {}) } })
}

export async function replaceUser(ctx: Ctx, rawId: string, body: unknown) {
  const id = idOf(rawId)
  const b = asObject(body)
  await tx(ctx.db, async (c) => {
    const cur = (await c.query<{ email: string }>(`SELECT email FROM users WHERE id = $1`, [id])).rows[0]
    if (!cur) throw new ScimError(404, 'Resource not found.')
    const want = normalizeEmail(str(b.userName, 'userName', 254) ?? '')
    if (want !== cur.email) throw new ScimError(400, 'userName cannot be changed.', 'mutability')
    await applyUserChange(ctx, c, id, {
      name: displayName(b),
      externalId: str(b.externalId, 'externalId', 200),
      ...(b.active !== undefined ? { active: bool(b.active) } : {}),
    })
  })
  return getUser(ctx, rawId)
}

// Profile attributes an identity provider sends along that have no meaning
// here: accepted and ignored. Anything else is refused, notably roles, groups
// (read-only) and passwords.
const IGNORED = /^(emails|phoneNumbers|addresses|name\.(givenName|familyName|middleName|honorificPrefix|honorificSuffix)|nickName|profileUrl|title|userType|preferredLanguage|locale|timezone|photos|ims|x509Certificates|urn:ietf:params:scim:schemas:extension:enterprise:2\.0:User(:.*)?)(\[.*\])?(\.[A-Za-z.]+)?$/i

function collectOps(body: unknown): Array<{ op: string; path: string | null; value: unknown }> {
  const b = asObject(body)
  if (!Array.isArray(b.Operations) || b.Operations.length === 0 || b.Operations.length > 100) throw new ScimError(400, 'Operations must be a list of 1 to 100 operations.', 'invalidSyntax')
  return b.Operations.map((o) => {
    const op = asObject(o)
    const name = typeof op.op === 'string' ? op.op.toLowerCase() : ''
    if (!['add', 'replace', 'remove'].includes(name)) throw new ScimError(400, 'op must be add, replace or remove.', 'invalidSyntax')
    return { op: name, path: typeof op.path === 'string' ? op.path : null, value: op.value }
  })
}

export async function patchUser(ctx: Ctx, rawId: string, body: unknown) {
  const id = idOf(rawId)
  const change: UserChange = {}
  let wantedName: string | undefined
  const take = (path: string, value: unknown) => {
    const p = path.toLowerCase()
    if (p === 'active') change.active = bool(value)
    else if (p === 'displayname' || p === 'name.formatted') change.name = str(value, 'displayName', 200)
    else if (p === 'externalid') change.externalId = str(value, 'externalId', 200)
    else if (p === 'username') wantedName = str(value, 'userName', 254) ?? ''
    else if (!IGNORED.test(path)) throw new ScimError(400, `The attribute ${path.slice(0, 60)} cannot be changed here.`, 'invalidPath')
  }
  for (const o of collectOps(body)) {
    if (o.op === 'remove') {
      if (o.path && /^(displayName|name\.formatted)$/i.test(o.path)) change.name = null
      else if (o.path && /^externalId$/i.test(o.path)) change.externalId = null
      else if (!o.path || !IGNORED.test(o.path)) throw new ScimError(400, 'That attribute cannot be removed.', 'invalidPath')
    } else if (o.path) take(o.path, o.value)
    else for (const [k, v] of Object.entries(asObject(o.value))) take(k, v)
  }
  await tx(ctx.db, async (c) => {
    if (wantedName !== undefined) {
      const cur = (await c.query<{ email: string }>(`SELECT email FROM users WHERE id = $1`, [id])).rows[0]
      if (!cur) throw new ScimError(404, 'Resource not found.')
      if (normalizeEmail(wantedName) !== cur.email) throw new ScimError(400, 'userName cannot be changed.', 'mutability')
    }
    await applyUserChange(ctx, c, id, change)
  })
  return getUser(ctx, rawId)
}

// DELETE deactivates: the row stays (audit entries refer to it) but the
// person is signed out of everything and out of every group.
export async function deleteUser(ctx: Ctx, rawId: string): Promise<void> {
  const id = idOf(rawId)
  await tx(ctx.db, async (c) => {
    await applyUserChange(ctx, c, id, { active: false })
    await c.query(`DELETE FROM group_members WHERE user_id = $1`, [id])
  })
}

// ---------- groups ----------

async function members(db: Pick<Pool, 'query'>, groupId: number): Promise<Array<{ value: string; display: string }>> {
  const { rows } = await db.query<{ id: string; email: string }>(`SELECT u.id, u.email FROM group_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = $1 ORDER BY u.id`, [groupId])
  return rows.map((r) => ({ value: String(r.id), display: r.email }))
}

function groupName(v: unknown): string {
  const s = str(v, 'displayName', 200)
  if (!s || !s.trim()) throw new ScimError(400, 'displayName is required.', 'invalidValue')
  return s.trim()
}

function memberIds(v: unknown): number[] {
  if (v == null) return []
  if (!Array.isArray(v) || v.length > MAX_MEMBERS) throw new ScimError(400, `members must be a list of at most ${MAX_MEMBERS}.`, 'invalidValue')
  return v.map((m) => {
    const raw = asObject(m).value
    if (typeof raw !== 'string' || !/^\d{1,15}$/.test(raw)) throw new ScimError(400, 'A member value is not a user id.', 'invalidValue')
    return Number(raw)
  })
}

async function checkUsersExist(c: PoolClient, ids: number[]) {
  if (ids.length === 0) return
  const { rowCount } = await c.query(`SELECT 1 FROM users WHERE id = ANY($1::bigint[])`, [ids])
  if (rowCount !== new Set(ids).size) throw new ScimError(400, 'A member is not a known user.', 'invalidValue')
}

export async function listGroups(ctx: Ctx, q: URLSearchParams) {
  const f = parseFilter(q.get('filter'), ['displayName', 'externalId'])
  const p = page(q.get('startIndex'), q.get('count'))
  const where = !f ? 'TRUE' : f.attr === 'displayName' ? 'lower(display_name) = lower($1)' : 'external_id = $1'
  const args = f ? [f.value] : []
  const total = Number((await ctx.db.query<{ n: string }>(`SELECT count(*) AS n FROM groups WHERE ${where}`, args)).rows[0].n)
  const { rows } = await ctx.db.query<GroupRow>(`SELECT id, display_name, external_id, created_at, updated_at FROM groups WHERE ${where} ORDER BY id LIMIT ${p.limit} OFFSET ${p.offset}`, args)
  const out = []
  for (const r of rows) out.push(groupResource(r, ctx.base, await members(ctx.db, Number(r.id))))
  return { schemas: [LIST_SCHEMA], totalResults: total, startIndex: p.start, itemsPerPage: rows.length, Resources: out }
}

export async function getGroup(ctx: Ctx, rawId: string) {
  const id = idOf(rawId)
  const r = (await ctx.db.query<GroupRow>(`SELECT id, display_name, external_id, created_at, updated_at FROM groups WHERE id = $1`, [id])).rows[0]
  if (!r) throw new ScimError(404, 'Resource not found.')
  return groupResource(r, ctx.base, await members(ctx.db, id))
}

async function setMembers(c: PoolClient, groupId: number, ids: number[]) {
  await c.query(`DELETE FROM group_members WHERE group_id = $1`, [groupId])
  if (ids.length) await c.query(`INSERT INTO group_members (group_id, user_id) SELECT $1, UNNEST($2::bigint[]) ON CONFLICT DO NOTHING`, [groupId, [...new Set(ids)]])
}

export async function createGroup(ctx: Ctx, body: unknown) {
  const b = asObject(body)
  const name = groupName(b.displayName)
  const externalId = str(b.externalId, 'externalId', 200)
  const ids = memberIds(b.members)
  const id = await tx(ctx.db, async (c) => {
    const dup = await c.query(`SELECT 1 FROM groups WHERE lower(display_name) = lower($1) OR ($2::text IS NOT NULL AND external_id = $2)`, [name, externalId])
    if (dup.rowCount) throw new ScimError(409, 'A group with this displayName or externalId exists.', 'uniqueness')
    await checkUsersExist(c, ids)
    const { rows } = await c.query<{ id: string }>(`INSERT INTO groups (display_name, external_id, source) VALUES ($1, $2, 'scim') RETURNING id`, [name, externalId])
    await setMembers(c, Number(rows[0].id), ids)
    await writeAudit(c, { action: 'scim_group_created', actor: ctx.actor, target: `group:${name.toLowerCase()}`, detail: { name, members: ids.length } })
    return rows[0].id
  })
  return getGroup(ctx, String(id))
}

export async function replaceGroup(ctx: Ctx, rawId: string, body: unknown) {
  const id = idOf(rawId)
  const b = asObject(body)
  const name = groupName(b.displayName)
  const externalId = str(b.externalId, 'externalId', 200)
  const ids = memberIds(b.members)
  await tx(ctx.db, async (c) => {
    const cur = (await c.query(`SELECT id FROM groups WHERE id = $1 FOR UPDATE`, [id])).rows[0]
    if (!cur) throw new ScimError(404, 'Resource not found.')
    const dup = await c.query(`SELECT 1 FROM groups WHERE id <> $3 AND (lower(display_name) = lower($1) OR ($2::text IS NOT NULL AND external_id = $2))`, [name, externalId, id])
    if (dup.rowCount) throw new ScimError(409, 'Another group has this displayName or externalId.', 'uniqueness')
    await checkUsersExist(c, ids)
    await c.query(`UPDATE groups SET display_name = $2, external_id = $3, updated_at = NOW() WHERE id = $1`, [id, name, externalId])
    await setMembers(c, id, ids)
    await writeAudit(c, { action: 'scim_group_updated', actor: ctx.actor, target: `group:${name.toLowerCase()}`, detail: { name, members: ids.length } })
  })
  return getGroup(ctx, rawId)
}

export async function patchGroup(ctx: Ctx, rawId: string, body: unknown) {
  const id = idOf(rawId)
  const ops = collectOps(body)
  await tx(ctx.db, async (c) => {
    const cur = (await c.query<{ display_name: string }>(`SELECT display_name FROM groups WHERE id = $1 FOR UPDATE`, [id])).rows[0]
    if (!cur) throw new ScimError(404, 'Resource not found.')
    let name = cur.display_name
    const touched = { renamed: false, added: 0, removed: 0, replaced: false }
    for (const o of ops) {
      const path = o.path ?? ''
      const filtered = /^members\[value\s+eq\s+"(\d{1,15})"\]$/i.exec(path)
      if (/^displayName$/i.test(path) && o.op !== 'remove') {
        name = groupName(o.value)
        touched.renamed = true
      } else if (/^members$/i.test(path) || filtered || (!o.path && o.value && typeof o.value === 'object' && 'members' in (o.value as object))) {
        const raw = filtered ? [{ value: filtered[1] }] : !o.path ? (o.value as Record<string, unknown>).members : o.value
        if (o.op === 'remove') {
          const ids = filtered ? [Number(filtered[1])] : o.value === undefined ? null : memberIds(raw)
          if (ids === null) await c.query(`DELETE FROM group_members WHERE group_id = $1`, [id])
          else await c.query(`DELETE FROM group_members WHERE group_id = $1 AND user_id = ANY($2::bigint[])`, [id, ids])
          touched.removed++
        } else {
          const ids = memberIds(raw)
          await checkUsersExist(c, ids)
          if (o.op === 'replace') {
            await setMembers(c, id, ids)
            touched.replaced = true
          } else {
            const total = Number((await c.query<{ n: string }>(`SELECT count(*) AS n FROM group_members WHERE group_id = $1`, [id])).rows[0].n)
            if (total + ids.length > MAX_MEMBERS * 5) throw new ScimError(400, 'The group would be too large.', 'invalidValue')
            if (ids.length) await c.query(`INSERT INTO group_members (group_id, user_id) SELECT $1, UNNEST($2::bigint[]) ON CONFLICT DO NOTHING`, [id, [...new Set(ids)]])
            touched.added += ids.length
          }
        }
      } else if (/^externalId$/i.test(path)) {
        await c.query(`UPDATE groups SET external_id = $2 WHERE id = $1`, [id, o.op === 'remove' ? null : str(o.value, 'externalId', 200)])
      } else {
        throw new ScimError(400, `The attribute ${path.slice(0, 60) || '(none)'} cannot be changed here.`, 'invalidPath')
      }
    }
    if (touched.renamed) {
      const dup = await c.query(`SELECT 1 FROM groups WHERE id <> $2 AND lower(display_name) = lower($1)`, [name, id])
      if (dup.rowCount) throw new ScimError(409, 'Another group has this displayName.', 'uniqueness')
    }
    await c.query(`UPDATE groups SET display_name = $2, updated_at = NOW() WHERE id = $1`, [id, name])
    await writeAudit(c, { action: 'scim_group_updated', actor: ctx.actor, target: `group:${name.toLowerCase()}`, detail: { name, ...touched } })
  })
  return getGroup(ctx, rawId)
}

export async function deleteGroup(ctx: Ctx, rawId: string): Promise<void> {
  const id = idOf(rawId)
  await tx(ctx.db, async (c) => {
    const { rows } = await c.query<{ display_name: string }>(`DELETE FROM groups WHERE id = $1 RETURNING display_name`, [id])
    if (!rows[0]) throw new ScimError(404, 'Resource not found.')
    await writeAudit(c, { action: 'scim_group_deleted', actor: ctx.actor, target: `group:${rows[0].display_name.toLowerCase()}`, detail: { name: rows[0].display_name } })
  })
}
