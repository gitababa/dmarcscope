// Reads for the administration pages. Each takes the caller's Access and
// refuses a caller below admin, so that a page that forgets its own check
// still cannot show this.

import type { Access } from './auth/access'
import { atLeast } from './auth/roles'
import { sql } from './db'

export class AdminAccessError extends Error {}

function requireAdmin(access: Access): void {
  if (!atLeast(access.role, 'admin')) throw new AdminAccessError('Administrator role required')
}

export type UserListRow = {
  id: number
  email: string
  name: string | null
  role: string
  role_source: string
  status: string
  source: string
  locked: boolean
  has_totp: boolean
  last_login_at: string | null
  created_at: string
}

export async function listUsers(access: Access): Promise<UserListRow[]> {
  requireAdmin(access)
  const rows = await sql<UserListRow & { id: string }>`
    SELECT id, email, name, role, role_source, status, source,
           COALESCE(locked_until > NOW(), FALSE) AS locked,
           totp_confirmed_at IS NOT NULL AS has_totp,
           last_login_at, created_at
    FROM users
    ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, email
    LIMIT 1000`
  return rows.map((r) => ({ ...r, id: Number(r.id) }))
}

export type AuditRow = {
  id: number
  at: string
  actor_email: string | null
  action: string
  target: string | null
  detail: Record<string, unknown>
  ip: string | null
}

export const AUDIT_PAGE = 100

export async function listAudit(access: Access, before?: number): Promise<AuditRow[]> {
  requireAdmin(access)
  const cursor = before && Number.isSafeInteger(before) && before > 0 ? before : null
  const rows = await sql<AuditRow & { id: string }>`
    SELECT id, at, actor_email, action, target, detail, ip
    FROM audit_log
    WHERE (${cursor}::bigint IS NULL OR id < ${cursor}::bigint)
    ORDER BY id DESC
    LIMIT ${AUDIT_PAGE}`
  return rows.map((r) => ({ ...r, id: Number(r.id) }))
}
