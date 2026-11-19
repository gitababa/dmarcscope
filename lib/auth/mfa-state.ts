// Between the password and the second factor: an encrypted, five-minute
// cookie saying which account passed the password check. It proves nothing
// on its own; a session is only issued after the second factor.

import type { Env } from '../config'
import { seal, unseal } from './session'

export const MFA_TTL_SECONDS = 5 * 60

export type MfaState = { userId: number; returnTo: string }

export async function sealMfaState(state: MfaState, env: Env = process.env): Promise<string> {
  return seal({ uid: state.userId, returnTo: state.returnTo }, 'mfa', MFA_TTL_SECONDS, env)
}

export async function unsealMfaState(token: string | undefined, env: Env = process.env): Promise<MfaState | null> {
  const p = await unseal(token, 'mfa', env)
  if (!p || typeof p.uid !== 'number' || typeof p.returnTo !== 'string') return null
  return { userId: p.uid, returnTo: p.returnTo }
}
