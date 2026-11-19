// Failed-attempt counting with exponential lockout, in the database so that
// every replica sees the same counts.
//
//   per account          users.failed_logins / locked_until; for an address
//                        with no account, an auth_throttle row keyed on its
//                        digest, so that a lockout looks the same either way
//   per client address   auth_throttle rows keyed on the address
//
// Lockout starts at the threshold: 1 minute, doubling with every further
// failure, at most 1 hour. Counts reset after a successful sign-in, and an
// auth_throttle row forgets failures older than 24 hours.

import type { Pool } from 'pg'
import { sha256Hex } from '../crypto'

type Queryable = Pick<Pool, 'query'>

export const ACCOUNT_THRESHOLD = 5
export const ADDRESS_THRESHOLD = 20
const MAX_LOCK_SECONDS = 3600

export function lockSeconds(failures: number, threshold: number): number | null {
  if (failures < threshold) return null
  return Math.min(MAX_LOCK_SECONDS, 60 * 2 ** Math.min(failures - threshold, 16))
}

export const addressKey = (scope: string, ip: string) => `${scope}-ip:${ip}`
export const unknownAccountKey = (email: string) => `account:${sha256Hex(email.toLowerCase())}`

export async function isThrottled(db: Queryable, key: string): Promise<boolean> {
  const { rows } = await db.query<{ locked: boolean }>(
    `SELECT locked_until > NOW() AS locked FROM auth_throttle WHERE key = $1`,
    [key]
  )
  return rows[0]?.locked === true
}

export async function recordThrottleFailure(db: Queryable, key: string, threshold: number): Promise<number> {
  const { rows } = await db.query<{ failures: number }>(
    `INSERT INTO auth_throttle (key, failures, updated_at) VALUES ($1, 1, NOW())
     ON CONFLICT (key) DO UPDATE SET
       failures = CASE WHEN auth_throttle.updated_at < NOW() - INTERVAL '24 hours' THEN 1 ELSE auth_throttle.failures + 1 END,
       updated_at = NOW()
     RETURNING failures`,
    [key]
  )
  const failures = rows[0].failures
  const lock = lockSeconds(failures, threshold)
  if (lock != null) {
    await db.query(`UPDATE auth_throttle SET locked_until = NOW() + make_interval(secs => $2) WHERE key = $1`, [key, lock])
  }
  // Old rows are only clutter; trim a few on the way.
  await db.query(`DELETE FROM auth_throttle WHERE key IN (SELECT key FROM auth_throttle WHERE updated_at < NOW() - INTERVAL '2 days' LIMIT 100)`)
  return failures
}

export async function clearThrottle(db: Queryable, key: string): Promise<void> {
  await db.query(`DELETE FROM auth_throttle WHERE key = $1`, [key])
}

export async function isAccountLocked(db: Queryable, userId: number): Promise<boolean> {
  const { rows } = await db.query<{ locked: boolean }>(`SELECT locked_until > NOW() AS locked FROM users WHERE id = $1`, [userId])
  return rows[0]?.locked === true
}

export async function recordAccountFailure(db: Queryable, userId: number): Promise<number> {
  const { rows } = await db.query<{ failed_logins: number }>(
    `UPDATE users SET failed_logins = failed_logins + 1 WHERE id = $1 RETURNING failed_logins`,
    [userId]
  )
  const failures = rows[0]?.failed_logins ?? 0
  const lock = lockSeconds(failures, ACCOUNT_THRESHOLD)
  if (lock != null) {
    await db.query(`UPDATE users SET locked_until = NOW() + make_interval(secs => $2) WHERE id = $1`, [userId, lock])
  }
  return failures
}
