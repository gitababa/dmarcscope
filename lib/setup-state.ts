// The setup wizard's progress between its steps, in a short-lived encrypted
// cookie (nothing is written to the database until the last step succeeds).

import type { Env } from './config'
import { seal, unseal } from './auth/session'
import type { TokenRef } from './setup'

export const SETUP_TTL_SECONDS = 30 * 60
export const RECOVERY_TTL_SECONDS = 15 * 60

export type SetupState =
  // draft: what was typed before a validation error, to fill the form again
  | { step: 'account'; token: TokenRef; draft?: { email: string; name: string } }
  | { step: 'totp'; token: TokenRef; email: string; name: string | null; passwordHash: string; totpSecret: string }

function isTokenRef(v: unknown): v is TokenRef {
  if (!v || typeof v !== 'object') return false
  const t = v as Record<string, unknown>
  return (t.kind === 'generated' && typeof t.id === 'number') || (t.kind === 'environment' && typeof t.hash === 'string')
}

export async function sealSetupState(state: SetupState, env: Env = process.env): Promise<string> {
  return seal({ ...state }, 'setup', SETUP_TTL_SECONDS, env)
}

export async function unsealSetupState(token: string | undefined, env: Env = process.env): Promise<SetupState | null> {
  const p = await unseal(token, 'setup', env)
  if (!p || !isTokenRef(p.token)) return null
  if (p.step === 'account') {
    const d = p.draft as Record<string, unknown> | undefined
    const draft = d && typeof d.email === 'string' && typeof d.name === 'string' ? { email: d.email, name: d.name } : undefined
    return { step: 'account', token: p.token, ...(draft ? { draft } : {}) }
  }
  if (
    p.step === 'totp' &&
    typeof p.email === 'string' &&
    (p.name === null || typeof p.name === 'string') &&
    typeof p.passwordHash === 'string' &&
    typeof p.totpSecret === 'string'
  ) {
    return { step: 'totp', token: p.token, email: p.email, name: p.name as string | null, passwordHash: p.passwordHash, totpSecret: p.totpSecret }
  }
  return null
}

// The owner's recovery codes, shown once on /welcome right after setup.
export async function sealRecoveryCodes(userId: number, codes: string[], env: Env = process.env): Promise<string> {
  return seal({ uid: userId, codes }, 'recovery', RECOVERY_TTL_SECONDS, env)
}

export async function unsealRecoveryCodes(token: string | undefined, env: Env = process.env): Promise<{ userId: number; codes: string[] } | null> {
  const p = await unseal(token, 'recovery', env)
  if (!p || typeof p.uid !== 'number' || !Array.isArray(p.codes) || !p.codes.every((c) => typeof c === 'string')) return null
  return { userId: p.uid, codes: p.codes as string[] }
}
