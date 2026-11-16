// The process-wide settings store and typed accessors for the settings the
// application reads. See store.ts for how values resolve and are cached.

import { type Env, safeEqual } from '../config'
import { getPool } from '../db'
import { ConfigStore } from './store'

export { ConfigStore, SettingError, type AccessRule, type ResolvedSetting, type Snapshot } from './store'
export { REGISTRY, settingDef, type SettingKey } from './registry'

let store: ConfigStore | null = null

export function configStore(): ConfigStore {
  store ??= new ConfigStore(getPool)
  return store
}

// Tests replace the store; nothing else should.
export function setConfigStoreForTests(s: ConfigStore | null): void {
  store = s
}

// The application name is on every page, including the sign-in and error
// pages. If the database cannot be read it falls back to the environment and
// the default rather than taking those pages down with it.
export async function getAppName(env: Env = process.env): Promise<string> {
  try {
    return String(await configStore().get('app.name', env))
  } catch (err) {
    console.error('[settings] could not read app.name:', err instanceof Error ? err.message : String(err))
    return env.APP_NAME?.trim() || 'DMARCscope'
  }
}

export async function getIngestStaleHours(env: Env = process.env): Promise<number> {
  return Number(await configStore().get('ingest.stale_hours', env))
}

export async function getSessionTtlSeconds(env: Env = process.env): Promise<number> {
  return Number(await configStore().get('session.max_age_hours', env)) * 3600
}

// `Authorization: Bearer <token>` for the machine endpoints. Closed while no
// valid token is configured (an invalid one is logged by the store).
export async function hasValidMachineToken(authorization: string | null, env: Env = process.env): Promise<boolean> {
  if (!authorization) return false
  let secret: string | null
  try {
    secret = await configStore().readSecret('cron.secret', env)
  } catch (err) {
    console.error('[settings] could not read the machine endpoint token:', err instanceof Error ? err.message : String(err))
    return false
  }
  if (!secret) return false
  return safeEqual(authorization, `Bearer ${secret}`)
}
