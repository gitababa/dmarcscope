// First run: while no owner exists, /setup creates one. It is unlocked by a
// one-time setup token:
//
//   - generated when the app starts (and when /setup is opened) if there is
//     no usable one, stored as a SHA-256 digest, written to the server log
//     once, valid for 24 hours;
//   - or supplied by the operator as SETUP_TOKEN (then nothing is generated).
//
// A token is spent when setup completes. After that, /setup answers 404 for
// good: completion and "is there an owner" are decided in one transaction.

import type { Pool, PoolClient } from 'pg'
import { type Actor, writeAudit } from './audit'
import { type Env, appUrl } from './config'
import { constantTimeEqual, encryptSecret, hashRecoveryCode, newRecoveryCodes, randomToken, sha256Hex, totpStep } from './crypto'

const TOKEN_TTL_HOURS = 24
const SETUP_LOCK = 4117230902 // advisory lock key, next to the migration runner's
export const SETUP_TOKEN_MIN = 24

export type TokenRef = { kind: 'generated'; id: number } | { kind: 'environment'; hash: string }

export type TokenCheck = { ok: true; ref: TokenRef } | { ok: false; reason: 'invalid' | 'expired' | 'used' }

export async function ownerExists(db: Pick<Pool, 'query'>): Promise<boolean> {
  const { rows } = await db.query<{ exists: boolean }>(`SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner') AS exists`)
  return rows[0].exists
}

function envToken(env: Env): string | null {
  const t = env.SETUP_TOKEN?.trim()
  return t ? t : null
}

// Called at startup and whenever /setup is opened with no owner yet. Logs a
// new token only if none is usable, so it is printed once per token.
export async function ensureSetupToken(db: Pool, env: Env = process.env, log: (line: string) => void = console.log): Promise<void> {
  const fromEnv = envToken(env)
  if (fromEnv) {
    if (fromEnv.length < SETUP_TOKEN_MIN) console.error(`[setup] SETUP_TOKEN is shorter than ${SETUP_TOKEN_MIN} characters and is refused.`)
    return
  }
  const client = await db.connect()
  let token: string | null = null
  try {
    await client.query('BEGIN')
    // Two replicas starting together must not both mint (and log) a token.
    await client.query('SELECT pg_advisory_xact_lock($1)', [SETUP_LOCK])
    const { rows } = await client.query<{ owner: boolean; usable: boolean }>(`
      SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner') AS owner,
             EXISTS (SELECT 1 FROM setup_tokens WHERE used_at IS NULL AND expires_at > NOW()) AS usable`)
    if (!rows[0].owner && !rows[0].usable) {
      token = randomToken(32)
      await client.query(`INSERT INTO setup_tokens (token_hash, expires_at) VALUES ($1, NOW() + make_interval(hours => $2))`, [
        sha256Hex(token),
        TOKEN_TTL_HOURS,
      ])
      await writeAudit(client, { action: 'setup_token_created', detail: { valid_hours: TOKEN_TTL_HOURS } })
    }
    await client.query('COMMIT')
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    client.release()
  }
  if (token) {
    let where = '/setup'
    try {
      where = `${appUrl(env)}/setup`
    } catch {
      // APP_URL problems are reported elsewhere
    }
    log(`[setup] No owner account exists yet. Open ${where} and enter this one-time setup token (valid for ${TOKEN_TTL_HOURS} hours): ${token}`)
  }
}

export async function checkSetupToken(db: Pick<Pool, 'query'>, presented: string, env: Env = process.env): Promise<TokenCheck> {
  const token = presented.trim()
  if (!token || token.length > 200) return { ok: false, reason: 'invalid' }
  const hash = sha256Hex(token)

  const fromEnv = envToken(env)
  if (fromEnv) {
    if (fromEnv.length < SETUP_TOKEN_MIN || !constantTimeEqual(token, fromEnv)) return { ok: false, reason: 'invalid' }
    const { rows } = await db.query<{ used: boolean }>(`SELECT used_at IS NOT NULL AS used FROM setup_tokens WHERE token_hash = $1`, [hash])
    return rows[0]?.used ? { ok: false, reason: 'used' } : { ok: true, ref: { kind: 'environment', hash } }
  }

  const { rows } = await db.query<{ id: string; used: boolean; expired: boolean }>(
    `SELECT id, used_at IS NOT NULL AS used, COALESCE(expires_at <= NOW(), FALSE) AS expired FROM setup_tokens WHERE token_hash = $1`,
    [hash]
  )
  const row = rows[0]
  if (!row) return { ok: false, reason: 'invalid' }
  if (row.used) return { ok: false, reason: 'used' }
  if (row.expired) return { ok: false, reason: 'expired' }
  return { ok: true, ref: { kind: 'generated', id: Number(row.id) } }
}

export type NewOwner = {
  email: string
  name: string | null
  passwordHash: string
  totpSecret: string
  // The TOTP step of the code that confirmed enrolment: that code cannot be
  // used again to sign in.
  confirmedStep: number
}

export type SetupResult = { ok: true; userId: number; recoveryCodes: string[] } | { ok: false; reason: 'owner_exists' | 'token' }

export async function completeSetup(db: Pool, ref: TokenRef, owner: NewOwner, actor: Actor, env: Env = process.env): Promise<SetupResult> {
  const client: PoolClient = await db.connect()
  try {
    await client.query('BEGIN')
    await client.query('SELECT pg_advisory_xact_lock($1)', [SETUP_LOCK])
    if (await ownerExists(client)) {
      await client.query('ROLLBACK')
      return { ok: false, reason: 'owner_exists' }
    }

    // Spend the token. Generated tokens: still unused and unexpired.
    // SETUP_TOKEN: recorded as spent, so it cannot be used twice.
    const spent =
      ref.kind === 'generated'
        ? await client.query(`UPDATE setup_tokens SET used_at = NOW() WHERE id = $1 AND used_at IS NULL AND expires_at > NOW()`, [ref.id])
        : await client.query(`INSERT INTO setup_tokens (token_hash, expires_at, used_at) VALUES ($1, NULL, NOW()) ON CONFLICT (token_hash) DO NOTHING`, [
            ref.hash,
          ])
    if (spent.rowCount !== 1) {
      await client.query('ROLLBACK')
      return { ok: false, reason: 'token' }
    }

    // An earlier pending or rule-admitted row for the same address (for
    // example from sign-ins before the upgrade) becomes the owner.
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO users (email, name, role, role_source, status, source, password_hash, totp_confirmed_at, totp_last_step, last_login_at)
       VALUES ($1, $2, 'owner', 'assigned', 'active', 'local', $3, NOW(), $4, NOW())
       ON CONFLICT (email) DO UPDATE SET
         name = COALESCE(EXCLUDED.name, users.name), role = 'owner', role_source = 'assigned', status = 'active',
         password_hash = EXCLUDED.password_hash, totp_confirmed_at = NOW(), totp_last_step = EXCLUDED.totp_last_step,
         failed_logins = 0, locked_until = NULL, last_login_at = NOW()
       RETURNING id`,
      [owner.email, owner.name, owner.passwordHash, owner.confirmedStep]
    )
    const userId = Number(rows[0].id)
    // The TOTP secret is bound to the user id, which only now exists.
    await client.query(`UPDATE users SET totp_secret = $2 WHERE id = $1`, [userId, encryptSecret('totp', `user:${userId}`, owner.totpSecret, env)])

    const codes = newRecoveryCodes()
    await client.query(`DELETE FROM recovery_codes WHERE user_id = $1`, [userId])
    for (const code of codes) {
      await client.query(`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, [userId, hashRecoveryCode(code)])
    }
    await client.query('UPDATE config_version SET version = version + 1')
    await writeAudit(client, {
      action: 'setup_completed',
      actor: { ...actor, userId, email: owner.email },
      target: `user:${userId}`,
      detail: { role: 'owner', token: ref.kind, recovery_codes: codes.length },
    })
    await client.query('COMMIT')
    return { ok: true, userId, recoveryCodes: codes }
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  } finally {
    client.release()
  }
}

export { totpStep }
