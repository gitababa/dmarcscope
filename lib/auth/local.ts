// The local account's sign-in: password (scrypt), then a TOTP code or a
// recovery code.
//
// Until single sign-on is configured in the panel (milestone 3), only the
// owner can sign in this way; local sign-in for anyone else is off.
//
// What a caller learns is deliberately coarse: "invalid" or "locked". A
// wrong password, an unknown address, a disabled account and an account
// that may not sign in locally are all "invalid", take the same time (one
// scrypt computation), and count toward the same kind of lockout.

import type { Pool } from 'pg'
import { recordAudit } from '../audit'
import { EnvelopeError, PasswordHashError, burnPasswordCheck, decryptSecret, hashRecoveryCode, matchTotp, normalizeRecoveryCode, verifyPassword } from '../crypto'
import type { Env } from '../config'
import {
  ACCOUNT_THRESHOLD,
  ADDRESS_THRESHOLD,
  addressKey,
  isAccountLocked,
  isThrottled,
  recordAccountFailure,
  recordThrottleFailure,
  unknownAccountKey,
} from './throttle'

export type StepOutcome = { ok: true; userId: number; email: string } | { ok: false; reason: 'invalid' | 'locked' }

type Candidate = {
  id: string
  email: string
  role: string
  status: string
  password_hash: string | null
  totp_secret: string | null
  totp_confirmed_at: string | null
  totp_last_step: string | null
  locked: boolean
}

const MAX_EMAIL = 320
const MAX_PASSWORD = 1024

async function findCandidate(db: Pool, by: { email: string } | { id: number }): Promise<Candidate | null> {
  const where = 'email' in by ? 'email = $1' : 'id = $1'
  const { rows } = await db.query<Candidate>(
    `SELECT id, email, role, status, password_hash, totp_secret, totp_confirmed_at, totp_last_step,
            COALESCE(locked_until > NOW(), FALSE) AS locked
     FROM users WHERE ${where}`,
    ['email' in by ? by.email : by.id]
  )
  return rows[0] ?? null
}

// May this account sign in with a password at all?
function eligible(u: Candidate): boolean {
  return u.status === 'active' && u.role === 'owner' && !!u.password_hash && !!u.totp_secret && !!u.totp_confirmed_at
}

async function fail(db: Pool, ip: string | null, account: { userId: number } | { email: string }, stage: 'password' | 'second_factor', reason: string) {
  if ('userId' in account) await recordAccountFailure(db, account.userId)
  else await recordThrottleFailure(db, unknownAccountKey(account.email), ACCOUNT_THRESHOLD)
  if (ip) await recordThrottleFailure(db, addressKey('signin', ip), ADDRESS_THRESHOLD)
  await recordAudit(db, {
    action: 'sign_in_failed',
    actor: { userId: 'userId' in account ? account.userId : null, email: 'email' in account ? account.email.slice(0, MAX_EMAIL) : null, ip },
    detail: { method: 'password', stage, reason },
  })
}

export async function checkPassword(db: Pool, rawEmail: string, password: string, ip: string | null): Promise<StepOutcome> {
  const email = rawEmail.trim().toLowerCase()
  if (!email || email.length > MAX_EMAIL || !password || password.length > MAX_PASSWORD) {
    return { ok: false, reason: 'invalid' }
  }

  if (ip && (await isThrottled(db, addressKey('signin', ip)))) {
    await recordAudit(db, { action: 'sign_in_refused', actor: { userId: null, email, ip }, detail: { reason: 'address_locked' } })
    return { ok: false, reason: 'locked' }
  }

  const user = await findCandidate(db, { email })
  const locked = user ? user.locked : await isThrottled(db, unknownAccountKey(email))
  if (locked) {
    await recordAudit(db, { action: 'sign_in_refused', actor: { userId: user ? Number(user.id) : null, email, ip }, detail: { reason: 'account_locked' } })
    return { ok: false, reason: 'locked' }
  }

  let valid = false
  if (user?.password_hash) {
    try {
      valid = await verifyPassword(password, user.password_hash)
    } catch (err) {
      if (!(err instanceof PasswordHashError)) throw err
      console.error(`[auth] user ${user.id}: ${err.message}`)
    }
  } else {
    await burnPasswordCheck(password)
  }

  if (!user) {
    await fail(db, ip, { email }, 'password', 'unknown_account')
    return { ok: false, reason: 'invalid' }
  }
  if (!valid || !eligible(user)) {
    await fail(db, ip, { userId: Number(user.id) }, 'password', valid ? 'not_allowed' : 'wrong_password')
    return { ok: false, reason: 'invalid' }
  }
  return { ok: true, userId: Number(user.id), email: user.email }
}

export async function checkSecondFactor(db: Pool, userId: number, input: string, ip: string | null, env: Env = process.env): Promise<StepOutcome & { method?: 'totp' | 'recovery_code' }> {
  if (ip && (await isThrottled(db, addressKey('signin', ip)))) {
    await recordAudit(db, { action: 'sign_in_refused', actor: { userId, email: null, ip }, detail: { reason: 'address_locked' } })
    return { ok: false, reason: 'locked' }
  }
  const user = await findCandidate(db, { id: userId })
  if (!user || !eligible(user)) {
    // The account changed between the two steps (disabled, demoted).
    if (user) await fail(db, ip, { userId }, 'second_factor', 'not_allowed')
    return { ok: false, reason: 'invalid' }
  }
  if (user.locked || (await isAccountLocked(db, userId))) {
    await recordAudit(db, { action: 'sign_in_refused', actor: { userId, email: user.email, ip }, detail: { reason: 'account_locked' } })
    return { ok: false, reason: 'locked' }
  }

  const code = input.replace(/\s/g, '')
  if (/^\d{6}$/.test(code)) {
    let secret: string
    try {
      secret = decryptSecret('totp', `user:${userId}`, user.totp_secret!, env).plaintext
    } catch (err) {
      if (!(err instanceof EnvelopeError)) throw err
      // Not the person's fault and not something to retry: say so in the log.
      console.error(`[auth] user ${userId}: TOTP secret cannot be decrypted (${err.code}); use a recovery code`)
      await fail(db, ip, { userId }, 'second_factor', 'totp_unreadable')
      return { ok: false, reason: 'invalid' }
    }
    const step = matchTotp(secret, code)
    if (step != null) {
      // Each code works once: accept a step only if it is later than the
      // last one accepted. Conditional update, so two simultaneous
      // submissions of the same code cannot both succeed.
      const { rowCount } = await db.query(
        `UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)`,
        [userId, step]
      )
      if (rowCount === 1) return { ok: true, userId, email: user.email, method: 'totp' }
      await fail(db, ip, { userId }, 'second_factor', 'code_reused')
      return { ok: false, reason: 'invalid' }
    }
    await fail(db, ip, { userId }, 'second_factor', 'wrong_code')
    return { ok: false, reason: 'invalid' }
  }

  if (normalizeRecoveryCode(code)) {
    const { rowCount } = await db.query(
      `UPDATE recovery_codes SET used_at = NOW() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
      [userId, hashRecoveryCode(code)]
    )
    if (rowCount === 1) {
      const { rows } = await db.query<{ left: string }>(`SELECT COUNT(*) AS left FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`, [userId])
      await recordAudit(db, { action: 'recovery_code_used', actor: { userId, email: user.email, ip }, detail: { remaining: Number(rows[0].left) } })
      return { ok: true, userId, email: user.email, method: 'recovery_code' }
    }
    await fail(db, ip, { userId }, 'second_factor', 'wrong_recovery_code')
    return { ok: false, reason: 'invalid' }
  }

  await fail(db, ip, { userId }, 'second_factor', 'malformed_code')
  return { ok: false, reason: 'invalid' }
}

export async function recordSuccessfulSignIn(db: Pool, userId: number): Promise<void> {
  await db.query(`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1`, [userId])
}
