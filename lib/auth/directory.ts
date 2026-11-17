// Where the request gate finds people: the users table, plus the cached
// access rules and "is there an owner yet" from the settings store.
//
// An interface so the gate's decisions can be tested without a database
// (tests/helpers/memory-directory.ts); the PostgreSQL implementation below is
// the only one the application uses.

import type { Pool } from 'pg'
import { type AuditEntry, recordAudit } from '../audit'
import { getPool } from '../db'
import { configStore } from '../settings'
import type { AccessRule } from '../settings/store'
import type { Identity, Role } from './types'

export type UserSource = 'local' | 'oidc' | 'proxy' | 'scim'

export type UserRow = {
  id: number
  email: string
  name: string | null
  role: Role
  role_source: 'assigned' | 'rule'
  status: 'pending' | 'active' | 'disabled'
  source: UserSource
  sessions_valid_after: string | null
  // Set on an invitation (milestone 2): a pending row with an assigned role
  // that becomes active at the person's first sign-in.
  invited_at: string | null
}

export interface Directory {
  // Cached (see lib/settings/store.ts).
  config(): Promise<{ rules: readonly AccessRule[]; ownerExists: boolean }>
  // One indexed query each; never cached, so a removal, a role change or a
  // revocation applies on the person's next request.
  findById(id: number): Promise<UserRow | null>
  findByEmail(email: string): Promise<UserRow | null>
  // Someone an access rule admits, seen for the first time.
  admit(identity: Identity, role: Role, source: UserSource): Promise<UserRow>
  // Someone no rule admits, seen for the first time. Null if a row appeared
  // in the meantime.
  requestAccess(identity: Identity, source: UserSource): Promise<UserRow | null>
  // A rule-admitted person's role changed, or a pending one is now admitted.
  syncRuleRole(id: number, role: Role): Promise<void>
  // An invited person signed in for the first time. False if the invitation
  // changed meanwhile (disabled, removed, already accepted).
  acceptInvitation(id: number): Promise<boolean>
  audit(entry: AuditEntry): Promise<void>
}

const COLUMNS = 'id, email, name, role, role_source, status, source, sessions_valid_after, invited_at'

type Row = Omit<UserRow, 'id'> & { id: string | number }
const toUser = (r: Row | undefined): UserRow | null => (r ? { ...r, id: Number(r.id) } : null)

export class PgDirectory implements Directory {
  constructor(private pool: () => Pool = getPool) {}

  async config() {
    let snap = await configStore().snapshot()
    // "No owner yet" is only ever true before setup, and acting on a stale
    // copy would send the new owner back to /setup: confirm it every time.
    if (!snap.ownerExists) snap = await configStore().snapshot({ fresh: true })
    return { rules: snap.rules, ownerExists: snap.ownerExists }
  }

  async findById(id: number) {
    const { rows } = await this.pool().query<Row>(`SELECT ${COLUMNS} FROM users WHERE id = $1`, [id])
    return toUser(rows[0])
  }

  async findByEmail(email: string) {
    const { rows } = await this.pool().query<Row>(`SELECT ${COLUMNS} FROM users WHERE email = $1`, [email.toLowerCase()])
    return toUser(rows[0])
  }

  async admit(identity: Identity, role: Role, source: UserSource) {
    // ON CONFLICT: two first requests at once both try to insert; whichever
    // loses reads the row the other wrote.
    const { rows } = await this.pool().query<Row>(
      `INSERT INTO users (email, name, role, role_source, status, source, oidc_subject)
       VALUES ($1, $2, $3, 'rule', 'active', $4, $5)
       ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
       RETURNING ${COLUMNS}`,
      [identity.email.toLowerCase(), identity.name?.slice(0, 200) ?? null, role, source, source === 'oidc' ? identity.sub : null]
    )
    return toUser(rows[0])!
  }

  async requestAccess(identity: Identity, source: UserSource) {
    const { rows } = await this.pool().query<Row>(
      `INSERT INTO users (email, name, role, role_source, status, source, oidc_subject)
       VALUES ($1, $2, 'viewer', 'rule', 'pending', $3, $4)
       ON CONFLICT (email) DO NOTHING
       RETURNING ${COLUMNS}`,
      [identity.email.toLowerCase(), identity.name?.slice(0, 200) ?? null, source, source === 'oidc' ? identity.sub : null]
    )
    return toUser(rows[0])
  }

  async syncRuleRole(id: number, role: Role) {
    await this.pool().query(
      `UPDATE users SET role = $2, status = 'active' WHERE id = $1 AND role_source = 'rule' AND status <> 'disabled'`,
      [id, role]
    )
  }

  async acceptInvitation(id: number) {
    const { rowCount } = await this.pool().query(
      `UPDATE users SET status = 'active' WHERE id = $1 AND status = 'pending' AND invited_at IS NOT NULL AND role_source = 'assigned'`,
      [id]
    )
    return rowCount === 1
  }

  async audit(entry: AuditEntry) {
    await recordAudit(this.pool(), entry)
  }
}

let directory: Directory | null = null

export function defaultDirectory(): Directory {
  directory ??= new PgDirectory()
  return directory
}

// Tests replace the directory; nothing else should.
export function setDirectoryForTests(d: Directory | null): void {
  directory = d
}
