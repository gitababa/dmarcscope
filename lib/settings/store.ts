// The settings store: resolves every setting (environment → database →
// default), and caches what it read from the database together with the
// access rules and whether an owner exists.
//
// Caching: each process keeps one snapshot. After SETTINGS_CACHE_SECONDS
// (default 5) it asks the database for the version counter
// (config_version), and reloads only if the counter moved. Every write bumps
// the counter in the same transaction, so a change made on one replica is
// seen by all of them within the cache window, with no restart.
//
// An invalid value is never silently replaced: resolution reports it as an
// error (shown to administrators in /admin, and logged once), and the setting
// falls back to its default only where that is safe (never for secrets).

import type { Pool, PoolClient } from 'pg'
import { type Actor, writeAudit } from '../audit'
import { type Env, envInt } from '../config'
import { EnvelopeError, decryptSecret, encryptSecret } from '../crypto'
import { REGISTRY, type PlainSettingKey, type SecretSettingKey, type SettingDef, settingDef } from './registry'

export type AccessRule = { kind: 'email_domain' | 'group'; value: string; role: 'admin' | 'viewer' }

// The active single sign-on connection (milestone 3), secret still encrypted.
export type SsoConnectionRow = {
  id: number
  preset: string
  issuer: string
  client_id: string
  client_secret: string | null
  scopes: string
  email_claim: string
  groups_claim: string
  required_claims: string
  button_label: string
  revision: number
}

export type Snapshot = {
  version: number
  rows: ReadonlyMap<string, { value: unknown; isSecret: boolean }>
  rules: readonly AccessRule[]
  // Group names domain scopes are keyed on (lower-case). Kept in the session
  // along with the groups access rules mention.
  scopeGroups: readonly string[]
  ownerExists: boolean
  sso: SsoConnectionRow | null
}

export type SettingSource = 'environment' | 'database' | 'default'

// What any read path returns. For a secret setting there is no value field
// at all: only whether one is set, and whether it is usable.
export type ResolvedSetting = {
  key: string
  label: string
  description: string
  type: SettingDef['type']
  ownerOnly: boolean
  source: SettingSource
  envVar: string
  isSet: boolean
  error: string | null
  value?: string | number | boolean | null
}

export class SettingError extends Error {
  constructor(
    public code: 'unknown' | 'managed_by_environment' | 'invalid' | 'secret_not_readable',
    message: string
  ) {
    super(message)
    this.name = 'SettingError'
  }
}

type Cached = { snapshot: Snapshot; checkedAt: number }

export function cacheTtlMs(env: Env = process.env): number {
  return envInt(env.SETTINGS_CACHE_SECONDS, 5, 0, 300) * 1000
}

export class ConfigStore {
  private cached: Cached | null = null
  private loading: Promise<Snapshot> | null = null
  private warned = new Set<string>()

  constructor(
    private pool: () => Pool,
    private ttlMs: () => number = () => cacheTtlMs()
  ) {}

  invalidate(): void {
    this.cached = null
  }

  // `fresh`: skip the cache window and check the version now.
  async snapshot(opts: { fresh?: boolean } = {}): Promise<Snapshot> {
    const now = Date.now()
    const c = this.cached
    if (c && !opts.fresh && now - c.checkedAt < this.ttlMs()) return c.snapshot
    this.loading ??= this.refresh(c).finally(() => {
      this.loading = null
    })
    return this.loading
  }

  private async refresh(previous: Cached | null): Promise<Snapshot> {
    if (previous) {
      const { rows } = await this.pool().query<{ version: string }>('SELECT version FROM config_version')
      if (rows[0] && Number(rows[0].version) === previous.snapshot.version) {
        this.cached = { snapshot: previous.snapshot, checkedAt: Date.now() }
        return previous.snapshot
      }
    }
    // One statement, so the version and the data come from the same snapshot
    // of the database: a write that commits halfway through cannot be cached
    // under the old version number.
    const { rows } = await this.pool().query<{
      version: string
      settings: Array<{ key: string; value: unknown; is_secret: boolean }>
      rules: AccessRule[]
      scope_groups: string[]
      owner_exists: boolean
      sso: (Omit<SsoConnectionRow, 'id'> & { id: string | number }) | null
    }>(`
      SELECT
        (SELECT version FROM config_version) AS version,
        (SELECT COALESCE(json_agg(json_build_object('key', key, 'value', value, 'is_secret', is_secret)), '[]'::json) FROM settings) AS settings,
        (SELECT COALESCE(json_agg(json_build_object('kind', kind, 'value', value, 'role', role) ORDER BY id), '[]'::json) FROM access_rules) AS rules,
        (SELECT COALESCE(array_agg(DISTINCT principal), '{}') FROM domain_scopes WHERE kind = 'group') AS scope_groups,
        EXISTS (SELECT 1 FROM users WHERE role = 'owner') AS owner_exists,
        (SELECT row_to_json(c) FROM (
           SELECT id, preset, issuer, client_id, client_secret, scopes, email_claim, groups_claim,
                  required_claims, button_label, revision
           FROM sso_connections WHERE state = 'active') c) AS sso
    `)
    const r = rows[0]
    const snapshot: Snapshot = {
      version: Number(r.version ?? 0),
      rows: new Map(r.settings.map((s) => [s.key, { value: s.value, isSecret: s.is_secret }])),
      rules: r.rules,
      scopeGroups: r.scope_groups ?? [],
      ownerExists: r.owner_exists,
      sso: r.sso ? { ...r.sso, id: Number(r.sso.id) } : null,
    }
    this.cached = { snapshot, checkedAt: Date.now() }
    return snapshot
  }

  // ---------- reading ----------

  private warnOnce(key: string, source: SettingSource, error: string, version: number): void {
    const id = `${key}|${source}|${version}|${error}`
    if (this.warned.has(id)) return
    this.warned.add(id)
    // The value itself is never logged: it may be a secret, and it may be
    // something a stranger typed.
    console.error(`[settings] ${key} (${source === 'environment' ? `environment variable ${settingDef(key).env}` : source}) is invalid: ${error}`)
  }

  // The one place a value is worked out. `plain` is the usable value (null
  // for an invalid secret); it never leaves this module for secrets except
  // through readSecret().
  private async resolveInternal(def: SettingDef, env: Env): Promise<{ meta: ResolvedSetting; plain: string | number | boolean | null }> {
    const base = {
      key: def.key,
      label: def.label,
      description: def.description,
      type: def.type,
      ownerOnly: def.ownerOnly,
      envVar: def.env,
    }
    const fallback = def.type === 'secret' ? null : def.default

    const fromEnv = env[def.env]
    if (fromEnv != null && fromEnv !== '') {
      const parsed = def.parseEnv(fromEnv)
      if (parsed.ok) return { meta: { ...base, source: 'environment', isSet: true, error: null }, plain: parsed.value }
      this.warnOnce(def.key, 'environment', parsed.error, 0)
      return { meta: { ...base, source: 'environment', isSet: true, error: parsed.error }, plain: fallback }
    }

    const snap = await this.snapshot()
    const row = snap.rows.get(def.key)
    if (row) {
      let raw: unknown = row.value
      let error: string | null = null
      if (def.type === 'secret') {
        if (!row.isSecret || typeof raw !== 'string') {
          error = 'is stored unencrypted or in an unknown shape'
          raw = undefined
        } else {
          try {
            raw = decryptSecret('setting', def.key, raw, env).plaintext
          } catch (err) {
            if (!(err instanceof EnvelopeError) && !(err instanceof Error && err.name === 'ConfigError')) throw err
            error = `cannot be decrypted (${err instanceof EnvelopeError ? err.code : 'APP_SECRET is not set'})`
            raw = undefined
          }
        }
      }
      if (!error) {
        const parsed = def.parse(raw)
        if (parsed.ok) return { meta: { ...base, source: 'database', isSet: true, error: null }, plain: parsed.value }
        error = parsed.error
      }
      this.warnOnce(def.key, 'database', error, snap.version)
      return { meta: { ...base, source: 'database', isSet: true, error }, plain: fallback }
    }

    return { meta: { ...base, source: 'default', isSet: def.default != null, error: null }, plain: def.default }
  }

  // Display: every setting, never a secret value.
  async list(env: Env = process.env): Promise<ResolvedSetting[]> {
    const out: ResolvedSetting[] = []
    for (const def of REGISTRY.values()) {
      const { meta, plain } = await this.resolveInternal(def, env)
      out.push(def.type === 'secret' ? meta : { ...meta, value: plain })
    }
    return out
  }

  async get(key: PlainSettingKey, env: Env = process.env): Promise<string | number | boolean | null> {
    const def = settingDef(key)
    if (def.type === 'secret') {
      throw new SettingError('secret_not_readable', `Setting "${key}" is a secret and cannot be read through this path`)
    }
    return (await this.resolveInternal(def, env)).plain
  }

  // For the code that uses a secret (the bearer-token check, later the OIDC
  // client and the worker). Never call it to display anything.
  async readSecret(key: SecretSettingKey, env: Env = process.env): Promise<string | null> {
    const def = settingDef(key)
    if (def.type !== 'secret') throw new SettingError('unknown', `Setting "${key}" is not a secret`)
    const { plain } = await this.resolveInternal(def, env)
    return typeof plain === 'string' ? plain : null
  }

  // ---------- writing ----------

  // `raw` null clears the stored value (back to the default). Validation,
  // encryption, the version bump and the audit entry happen in one
  // transaction. Authorization is the caller's job (see app/admin/actions.ts),
  // because only the caller knows who is asking.
  async write(key: string, raw: unknown, actor: Actor, env: Env = process.env): Promise<void> {
    const def = REGISTRY.get(key)
    if (!def) throw new SettingError('unknown', `Unknown setting "${key}"`)
    const fromEnv = env[def.env]
    if (fromEnv != null && fromEnv !== '') {
      throw new SettingError('managed_by_environment', `${def.label} is set by the environment variable ${def.env} and cannot be changed here`)
    }

    let stored: string | null = null
    let detail: Record<string, unknown>
    if (raw == null) {
      detail = { key, cleared: true }
    } else {
      const parsed = def.parse(raw)
      if (!parsed.ok) throw new SettingError('invalid', `${def.label} ${parsed.error}`)
      if (def.type === 'secret') {
        stored = JSON.stringify(encryptSecret('setting', def.key, String(parsed.value), env))
        detail = { key, secret: true, replaced: true }
      } else {
        stored = JSON.stringify(parsed.value)
        detail = { key, value: parsed.value }
      }
    }

    const client: PoolClient = await this.pool().connect()
    try {
      await client.query('BEGIN')
      if (stored == null) {
        await client.query('DELETE FROM settings WHERE key = $1', [key])
      } else {
        await client.query(
          `INSERT INTO settings (key, value, is_secret, updated_at, updated_by) VALUES ($1, $2::jsonb, $3, NOW(), $4)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, is_secret = EXCLUDED.is_secret, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
          [key, stored, def.type === 'secret', actor.userId]
        )
      }
      await client.query('UPDATE config_version SET version = version + 1')
      await writeAudit(client, { action: 'setting_changed', actor, target: key, detail })
      await client.query('COMMIT')
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    } finally {
      client.release()
    }
    this.invalidate()
  }
}
