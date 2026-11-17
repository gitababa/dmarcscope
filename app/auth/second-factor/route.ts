// Local sign-in, step 2: a code from the authenticator app, or a recovery
// code. Only now is a session issued.

import type { NextRequest } from 'next/server'
import { recordAudit } from '@/lib/audit'
import { authProvider, hasSignInPage } from '@/lib/auth'
import { checkSecondFactor, recordSuccessfulSignIn } from '@/lib/auth/local'
import { unsealMfaState } from '@/lib/auth/mfa-state'
import { cookieOptions, purposeCookieName, sealSession, sessionCookieName } from '@/lib/auth/session'
import { clientIp } from '@/lib/client-ip'
import { getPool } from '@/lib/db'
import { formFields, forbiddenOrigin, isSameOrigin, seeOther } from '@/lib/http'
import { getSessionTtlSeconds } from '@/lib/settings'

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return forbiddenOrigin()
  if (!hasSignInPage(authProvider())) return seeOther('/')

  const mfaCookie = purposeCookieName('mfa')
  const state = await unsealMfaState(req.cookies.get(mfaCookie)?.value)
  const startOver = (error: string) => {
    const res = seeOther(`/login?method=password&error=${error}`)
    res.cookies.set(mfaCookie, '', cookieOptions(0))
    return res
  }
  if (!state) return startOver('expired')

  const fields = await formFields(req, ['code'], 64)
  if (!fields) return seeOther('/login?method=password&step=code&error=code')

  const db = getPool()
  const ip = clientIp(req.headers)
  const outcome = await checkSecondFactor(db, state.userId, fields.code, ip)
  if (!outcome.ok) {
    // A lockout ends this attempt; a wrong code may be retried.
    return outcome.reason === 'locked' ? startOver('locked') : seeOther('/login?method=password&step=code&error=code')
  }

  await recordSuccessfulSignIn(db, outcome.userId)
  await recordAudit(db, {
    action: 'sign_in',
    actor: { userId: outcome.userId, email: outcome.email, ip },
    detail: { method: 'password', second_factor: outcome.method },
  })

  const ttl = await getSessionTtlSeconds()
  const res = seeOther(state.returnTo)
  res.cookies.set(
    sessionCookieName(),
    await sealSession({ sub: `user:${outcome.userId}`, email: outcome.email, groups: [] }, process.env, {
      userId: outcome.userId,
      method: 'password',
      ttlSeconds: ttl,
    }),
    cookieOptions(ttl)
  )
  res.cookies.set(mfaCookie, '', cookieOptions(0))
  return res
}
