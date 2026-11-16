// The setup wizard's form posts. Each step re-checks everything the previous
// steps established, because the browser holds the progress (in an encrypted
// cookie) and could replay an old step.
//
//   POST /setup/token     the one-time setup token
//   POST /setup/account   the owner's address, name and password
//   POST /setup/totp      a code from the authenticator app: creates the owner
//   POST /setup/restart   start over

import { NextResponse, type NextRequest } from 'next/server'
import { authProvider } from '@/lib/auth'
import { getPool } from '@/lib/db'
import { recordAudit } from '@/lib/audit'
import { clientIp } from '@/lib/client-ip'
import { hashPassword, matchTotp, newTotpSecret, sha256Hex } from '@/lib/crypto'
import { formFields, forbiddenOrigin, isSameOrigin, notFoundResponse, seeOther } from '@/lib/http'
import { identityFromProxyHeader, identityFromProxyJwt } from '@/lib/auth/proxy-providers'
import { passwordProblem } from '@/lib/auth/password-policy'
import { cookieOptions, purposeCookieName, sealSession, sessionCookieName } from '@/lib/auth/session'
import { addressKey, isThrottled, recordThrottleFailure } from '@/lib/auth/throttle'
import { configStore, getSessionTtlSeconds } from '@/lib/settings'
import { type TokenRef, checkSetupToken, completeSetup, ownerExists } from '@/lib/setup'
import { RECOVERY_TTL_SECONDS, SETUP_TTL_SECONDS, sealRecoveryCodes, sealSetupState, unsealSetupState } from '@/lib/setup-state'

export const dynamic = 'force-dynamic'

const EMAIL = /^[^@\s,<>"]+@[^@\s,<>"]+\.[^@\s,<>"]+$/
const SETUP_ADDRESS_THRESHOLD = 10

type Ctx = { params: Promise<{ step: string }> }

export async function POST(req: NextRequest, { params }: Ctx) {
  const { step } = await params
  if (!['token', 'account', 'totp', 'restart'].includes(step)) return notFoundResponse()
  if (!isSameOrigin(req)) return forbiddenOrigin()

  const db = getPool()
  // Once there is an owner, setup is gone for good.
  if (await ownerExists(db)) return notFoundResponse()

  const ip = clientIp(req.headers)
  const actor = { userId: null, email: null, ip }
  const stateCookie = purposeCookieName('setup')
  const state = await unsealSetupState(req.cookies.get(stateCookie)?.value)

  const back = (error?: string) => seeOther(error ? `/setup?error=${error}` : '/setup')
  const withState = async (res: NextResponse, next: Parameters<typeof sealSetupState>[0]) => {
    res.cookies.set(stateCookie, await sealSetupState(next), cookieOptions(SETUP_TTL_SECONDS))
    return res
  }
  const clearState = (res: NextResponse) => {
    res.cookies.set(stateCookie, '', cookieOptions(0))
    return res
  }

  if (step === 'restart') return clearState(back())

  // ---------- 1. setup token ----------
  if (step === 'token') {
    const fields = await formFields(req, ['token'], 300)
    if (!fields) return back('form')
    if (ip && (await isThrottled(db, addressKey('setup', ip)))) {
      await recordAudit(db, { action: 'setup_token_refused', actor, detail: { reason: 'address_locked' } })
      return back('locked')
    }
    const check = await checkSetupToken(db, fields.token)
    if (!check.ok) {
      if (ip) await recordThrottleFailure(db, addressKey('setup', ip), SETUP_ADDRESS_THRESHOLD)
      await recordAudit(db, { action: 'setup_token_refused', actor, detail: { reason: check.reason } })
      return clearState(back(`token_${check.reason}`))
    }
    await recordAudit(db, { action: 'setup_token_accepted', actor, detail: { token: check.ref.kind } })
    return withState(back(), { step: 'account', token: check.ref })
  }

  // Every later step needs a token that is still good.
  if (!state) return clearState(back('expired'))
  const recheck = await recheckToken(state.token)
  if (!recheck) {
    await recordAudit(db, { action: 'setup_refused', actor, detail: { step, reason: 'token_no_longer_valid' } })
    return clearState(back('token_expired'))
  }

  // ---------- 2. owner account ----------
  if (step === 'account') {
    const fields = await formFields(req, ['email', 'name', 'password', 'password_confirm'], 1024)
    if (!fields) return back('form')
    let email = fields.email.trim().toLowerCase()
    // Behind an authenticating proxy, the owner is whoever the proxy says is
    // completing setup: otherwise the owner account could never be used.
    const provider = authProvider()
    if (provider === 'proxy-jwt' || provider === 'proxy-header') {
      const identity = provider === 'proxy-jwt' ? await identityFromProxyJwt(req.headers) : identityFromProxyHeader(req.headers)
      if (!identity) return back('proxy_identity')
      email = identity.email
    }
    const name = fields.name.trim().replace(/[\x00-\x1f\x7f]/g, '').slice(0, 200) || null
    if (!EMAIL.test(email) || email.length > 254) return back('email')
    const problem = passwordProblem(fields.password, email)
    if (problem) return back(`password_${problemCode(problem)}`)
    if (fields.password !== fields.password_confirm) return back('password_mismatch')

    await recordAudit(db, { action: 'setup_account_entered', actor: { ...actor, email }, detail: {} })
    return withState(back(), {
      step: 'totp',
      token: state.token,
      email,
      name,
      passwordHash: await hashPassword(fields.password),
      totpSecret: newTotpSecret(),
    })
  }

  // ---------- 3. confirm TOTP, create the owner ----------
  if (state.step !== 'totp') return back('expired')
  const fields = await formFields(req, ['code'], 50)
  if (!fields) return back('form')
  const step30 = matchTotp(state.totpSecret, fields.code)
  if (step30 == null) {
    if (ip) await recordThrottleFailure(db, addressKey('setup', ip), SETUP_ADDRESS_THRESHOLD)
    await recordAudit(db, { action: 'setup_refused', actor: { ...actor, email: state.email }, detail: { step: 'totp', reason: 'wrong_code' } })
    return back('code')
  }

  const result = await completeSetup(
    db,
    state.token,
    { email: state.email, name: state.name, passwordHash: state.passwordHash, totpSecret: state.totpSecret, confirmedStep: step30 },
    actor
  )
  if (!result.ok) {
    await recordAudit(db, { action: 'setup_refused', actor: { ...actor, email: state.email }, detail: { step: 'complete', reason: result.reason } })
    if (result.reason === 'owner_exists') return clearState(notFoundResponse())
    return clearState(back('token_used'))
  }
  configStore().invalidate()

  const res = seeOther('/welcome')
  clearState(res)
  res.cookies.set(
    sessionCookieName(),
    await sealSession(
      { sub: `user:${result.userId}`, email: state.email, name: state.name ?? undefined, groups: [] },
      process.env,
      { userId: result.userId, method: 'password', ttlSeconds: await getSessionTtlSeconds() }
    ),
    cookieOptions(await getSessionTtlSeconds())
  )
  res.cookies.set(purposeCookieName('recovery'), await sealRecoveryCodes(result.userId, result.recoveryCodes), cookieOptions(RECOVERY_TTL_SECONDS))
  return res

  async function recheckToken(ref: TokenRef): Promise<boolean> {
    if (ref.kind === 'environment') {
      const current = process.env.SETUP_TOKEN?.trim()
      if (!current || sha256Hex(current) !== ref.hash) return false
      const { rows } = await db.query<{ used: boolean }>(`SELECT used_at IS NOT NULL AS used FROM setup_tokens WHERE token_hash = $1`, [ref.hash])
      return !rows[0]?.used
    }
    const { rows } = await db.query<{ ok: boolean }>(`SELECT used_at IS NULL AND expires_at > NOW() AS ok FROM setup_tokens WHERE id = $1`, [ref.id])
    return rows[0]?.ok === true
  }
}

function problemCode(message: string): string {
  if (message.startsWith('Use at least')) return 'short'
  if (message.startsWith('Use at most')) return 'long'
  if (message.includes('common') || message.includes('repeats')) return 'common'
  return 'email'
}
