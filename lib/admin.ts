// Reads for the administration pages. Each takes the caller's Access and
// refuses a caller below admin, so that a page that forgets its own check
// still cannot show this.

import type { Access } from './auth/access'
import { atLeast, isRole } from './auth/roles'
import { sql } from './db'

export class AdminAccessError extends Error {}

function requireAdmin(access: Access): void {
  if (!atLeast(access.role, 'admin')) throw new AdminAccessError('Administrator role required')
}

// For ILIKE: the search text is a bind parameter, and its own % and _ are
// matched literally.
function likePattern(text: string): string {
  return `%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`
}

// ---------- users ----------

export type UserListRow = {
  id: number
  email: string
  name: string | null
  role: string
  role_source: string
  status: string
  source: string
  invited: boolean
  locked: boolean
  has_totp: boolean
  last_login_at: string | null
  created_at: string
}

export type UserFilters = { q?: string; status?: string; role?: string; source?: string; page?: number }

export const USERS_PAGE = 50
const STATUSES = ['pending', 'active', 'disabled']
const SOURCES = ['local', 'oidc', 'proxy', 'scim']

export function parseUserFilters(raw: Record<string, string | undefined>): UserFilters {
  const page = Number.parseInt(raw.page || '', 10)
  return {
    q: raw.q?.trim().slice(0, 200) || undefined,
    status: raw.status && STATUSES.includes(raw.status) ? raw.status : undefined,
    role: raw.role && isRole(raw.role) ? raw.role : undefined,
    source: raw.source && SOURCES.includes(raw.source) ? raw.source : undefined,
    page: Number.isSafeInteger(page) && page > 1 && page < 100_000 ? page : 1,
  }
}

export async function listUsers(access: Access, f: UserFilters = {}): Promise<{ rows: UserListRow[]; total: number }> {
  requireAdmin(access)
  const q = f.q ? likePattern(f.q) : null
  const offset = ((f.page ?? 1) - 1) * USERS_PAGE
  const rows = await sql<UserListRow & { id: string; total: string }>`
    SELECT id, email, name, role, role_source, status, source,
           invited_at IS NOT NULL AS invited,
           COALESCE(locked_until > NOW(), FALSE) AS locked,
           totp_confirmed_at IS NOT NULL AS has_totp,
           last_login_at, created_at,
           COUNT(*) OVER () AS total
    FROM users
    WHERE (${q}::text IS NULL OR email ILIKE ${q} OR name ILIKE ${q})
      AND (${f.status ?? null}::text IS NULL OR status = ${f.status ?? null})
      AND (${f.role ?? null}::text IS NULL OR role = ${f.role ?? null})
      AND (${f.source ?? null}::text IS NULL OR source = ${f.source ?? null})
    ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, email
    LIMIT ${USERS_PAGE} OFFSET ${offset}`
  return { rows: rows.map(({ total: _t, ...r }) => ({ ...r, id: Number(r.id) })), total: Number(rows[0]?.total ?? 0) }
}

export async function listPendingRequests(access: Access): Promise<UserListRow[]> {
  requireAdmin(access)
  const rows = await sql<UserListRow & { id: string }>`
    SELECT id, email, name, role, role_source, status, source,
           invited_at IS NOT NULL AS invited,
           COALESCE(locked_until > NOW(), FALSE) AS locked,
           totp_confirmed_at IS NOT NULL AS has_totp,
           last_login_at, created_at
    FROM users
    WHERE status = 'pending' AND invited_at IS NULL
    ORDER BY created_at
    LIMIT 200`
  return rows.map((r) => ({ ...r, id: Number(r.id) }))
}

export type UserDetail = UserListRow & {
  failed_logins: number
  locked_until: string | null
  sessions_valid_after: string | null
  invited_at: string | null
  invited_by_email: string | null
  oidc_subject: string | null
}

export async function getUser(access: Access, id: number): Promise<UserDetail | null> {
  requireAdmin(access)
  if (!Number.isSafeInteger(id) || id < 1) return null
  const rows = await sql<UserDetail & { id: string }>`
    SELECT u.id, u.email, u.name, u.role, u.role_source, u.status, u.source,
           u.invited_at IS NOT NULL AS invited,
           COALESCE(u.locked_until > NOW(), FALSE) AS locked,
           u.totp_confirmed_at IS NOT NULL AS has_totp,
           u.last_login_at, u.created_at,
           u.failed_logins, u.locked_until, u.sessions_valid_after, u.invited_at, u.oidc_subject,
           i.email AS invited_by_email
    FROM users u LEFT JOIN users i ON i.id = u.invited_by
    WHERE u.id = ${id}`
  return rows[0] ? { ...rows[0], id: Number(rows[0].id) } : null
}

// ---------- access rules ----------

export type RuleRow = { id: number; kind: 'email_domain' | 'group'; value: string; role: string; created_at: string; created_by_email: string | null }

export async function listRules(access: Access): Promise<RuleRow[]> {
  requireAdmin(access)
  const rows = await sql<RuleRow & { id: string }>`
    SELECT r.id, r.kind, r.value, r.role, r.created_at, u.email AS created_by_email
    FROM access_rules r LEFT JOIN users u ON u.id = r.created_by
    ORDER BY r.kind, r.value`
  return rows.map((r) => ({ ...r, id: Number(r.id) }))
}

// ---------- audit log ----------

export type AuditRow = {
  id: number
  at: string
  actor_email: string | null
  action: string
  target: string | null
  detail: Record<string, unknown>
  ip: string | null
}

export type AuditFilters = { action?: string; actor?: string; target?: string; from?: string; to?: string }

export const AUDIT_PAGE = 100
export const AUDIT_EXPORT_LIMIT = 100_000

const DAY = /^\d{4}-\d{2}-\d{2}$/

export function parseAuditFilters(raw: Record<string, string | undefined>): AuditFilters {
  const clean = (v: string | undefined, n: number) => v?.trim().slice(0, n) || undefined
  const day = (v: string | undefined) => (v && DAY.test(v) && !Number.isNaN(Date.parse(`${v}T00:00:00Z`)) ? v : undefined)
  return {
    action: clean(raw.action, 64)?.replace(/[^a-z_]/g, '') || undefined,
    actor: clean(raw.actor, 320),
    target: clean(raw.target, 200),
    from: day(raw.from),
    to: day(raw.to),
  }
}

function auditQuery(f: AuditFilters, before: number | null, limit: number) {
  const actor = f.actor ? likePattern(f.actor.toLowerCase()) : null
  const target = f.target ? likePattern(f.target) : null
  // Dates are whole UTC days; "to" includes that day.
  return sql<AuditRow & { id: string }>`
    SELECT id, at, actor_email, action, target, detail, ip
    FROM audit_log
    WHERE (${before}::bigint IS NULL OR id < ${before}::bigint)
      AND (${f.action ?? null}::text IS NULL OR action = ${f.action ?? null})
      AND (${actor}::text IS NULL OR lower(actor_email) LIKE ${actor})
      AND (${target}::text IS NULL OR target ILIKE ${target})
      AND (${f.from ?? null}::date IS NULL OR at >= ${f.from ?? null}::date::timestamp AT TIME ZONE 'UTC')
      AND (${f.to ?? null}::date IS NULL OR at < (${f.to ?? null}::date + 1)::timestamp AT TIME ZONE 'UTC')
    ORDER BY id DESC
    LIMIT ${limit}`
}

export async function listAudit(access: Access, filters: AuditFilters = {}, before?: number): Promise<AuditRow[]> {
  requireAdmin(access)
  const cursor = before && Number.isSafeInteger(before) && before > 0 ? before : null
  const rows = await auditQuery(filters, cursor, AUDIT_PAGE)
  return rows.map((r) => ({ ...r, id: Number(r.id) }))
}

export async function auditActions(access: Access): Promise<string[]> {
  requireAdmin(access)
  const rows = await sql<{ action: string }>`SELECT DISTINCT action FROM audit_log ORDER BY action`
  return rows.map((r) => r.action)
}

// The whole filtered log, newest first, at most AUDIT_EXPORT_LIMIT rows.
export async function exportAudit(access: Access, filters: AuditFilters): Promise<AuditRow[]> {
  requireAdmin(access)
  const rows = await auditQuery(filters, null, AUDIT_EXPORT_LIMIT)
  return rows.map((r) => ({ ...r, id: Number(r.id) }))
}

// A CSV cell. Text a spreadsheet would run as a formula is prefixed with ',
// because the audit log holds addresses and values typed by strangers.
export function csvCell(value: unknown): string {
  let s = value == null ? '' : typeof value === 'string' ? value : JSON.stringify(value)
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s
}

export function auditCsv(rows: AuditRow[]): string {
  const header = ['id', 'at', 'actor_email', 'action', 'target', 'ip', 'detail']
  const lines = [header.join(',')]
  for (const r of rows) {
    lines.push([r.id, new Date(r.at).toISOString(), r.actor_email, r.action, r.target, r.ip, r.detail].map(csvCell).join(','))
  }
  return `${lines.join('\r\n')}\r\n`
}
