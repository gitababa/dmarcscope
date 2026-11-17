// Single sign-on configured in the panel (milestone 3; AUTH_PROVIDER unset).
//
// One draft and at most one active connection (sso_connections). Saving the
// draft changes nothing about how anyone signs in. A test runs the real
// sign-in flow against the draft and records the outcome for that revision;
// only a successful test of the current revision, less than a day old, lets
// an owner activate it. Everything here is owner-only and audited.

import type { Pool, PoolClient } from 'pg'
import { type Actor, recordAudit, writeAudit } from './audit'
import { ruleRole } from './auth/authz'
import { type OidcSettings, parseRequiredClaims } from './auth/oidc'
import { atLeast, higherRole } from './auth/roles'
import type { Identity, Role } from './auth/types'
import { type Env, ConfigError, envBool } from './config'
import { decryptSecret, encryptSecret } from './crypto'
import type { AccessRule, SsoConnectionRow } from './settings/store'

export type SsoActor = Actor & { role: Role }

export type Preset = 'google' | 'entra' | 'okta' | 'generic'

export const PRESETS: Record<Preset, { label: string; issuer: string; emailClaim: string; groupsClaim: string; scopes: string; requiredClaims: string; note: string }> = {
  google: {
    label: 'Google',
    issuer: 'https://accounts.google.com',
    emailClaim: 'email',
    groupsClaim: 'groups',
    scopes: 'openid email profile',
    requiredClaims: 'hd=example.com',
    note: 'Google accepts any Google account: set the hd required claim to your Workspace domain (replace example.com). Google sends no groups.',
  },
  entra: {
    label: 'Microsoft',
    issuer: 'https://login.microsoftonline.com/TENANT-ID/v2.0',
    emailClaim: 'preferred_username',
    groupsClaim: 'groups',
    scopes: 'openid email profile',
    requiredClaims: '',
    note: 'Use your tenant ID in the issuer (single tenant). Entra sends no email_verified and its email claim is editable, so people are identified by preferred_username. Whoever can change sign-in names in the tenant can therefore sign in here as anyone, the owner included. Groups arrive as object IDs.',
  },
  okta: {
    label: 'Okta',
    issuer: 'https://YOUR-ORG.okta.com',
    emailClaim: 'email',
    groupsClaim: 'groups',
    scopes: 'openid email profile groups',
    requiredClaims: '',
    note: 'With a custom authorization server the issuer is https://YOUR-ORG.okta.com/oauth2/default. Add a groups claim to use group rules.',
  },
  generic: {
    label: 'Single sign-on',
    issuer: '',
    emailClaim: 'email',
    groupsClaim: 'groups',
    scopes: 'openid email profile',
    requiredClaims: '',
    note: 'Any OpenID Connect provider: use the issuer shown in its settings (its discovery document lives at ISSUER/.well-known/openid-configuration).',
  },
}

export function isPreset(v: unknown): v is Preset {
  return typeof v === 'string' && v in PRESETS
}

export type SsoRefusalCode =
  | 'not_allowed'
  | 'invalid'
  | 'no_draft'
  | 'no_active'
  | 'not_tested'
  | 'test_failed'
  | 'test_stale'
  | 'environment'

export class SsoRefusal extends Error {
  constructor(
    public code: SsoRefusalCode,
    public field?: string
  ) {
    super(field ? `${code}:${field}` : code)
    this.name = 'SsoRefusal'
  }
}

export type TestResult = {
  ok: boolean
  at: string
  revision: number
  by: { userId: number; email: string | null }
  error?: { code: string; message: string }
  claims?: Record<string, unknown>
  identity?: { email: string; name: string | null; groups: string[] }
  admission?: { role: Role | null; via: 'existing user' | 'access rule' | 'none'; status: string | null }
}

export type ConnectionRow = SsoConnectionRow & {
  state: string
  last_test: TestResult | null
  updated_at: string
  activated_at: string | null
}

const COLUMNS = `id, state, preset, issuer, client_id, client_secret, scopes, email_claim, groups_claim,
  required_claims, button_label, revision, last_test, updated_at, activated_at`

const TEST_VALID_HOURS = 24

function toRow(r: (Omit<ConnectionRow, 'id'> & { id: string | number }) | undefined): ConnectionRow | null {
  return r ? { ...r, id: Number(r.id) } : null
}

export async function getConnection(db: Pick<Pool, 'query'>, state: 'draft' | 'active'): Promise<ConnectionRow | null> {
  const { rows } = await db.query(`SELECT ${COLUMNS} FROM sso_connections WHERE state = $1`, [state])
  return toRow(rows[0])
}

// ---------- settings for the sign-in code ----------

const secretContext = (id: number) => `sso:${id}`

export function settingsFromRow(row: SsoConnectionRow, env: Env = process.env): OidcSettings {
  const clientSecret = row.client_secret ? decryptSecret('setting', secretContext(row.id), row.client_secret, env).plaintext : null
  return {
    issuer: row.issuer,
    clientId: row.client_id,
    clientSecret,
    scopes: row.scopes,
    emailClaim: row.email_claim,
    groupsClaim: row.groups_claim,
    requiredClaims: row.required_claims,
    prompt: null,
    // Trusted, environment-only switch for a local test provider.
    allowInsecureIssuer: envBool(env.OIDC_ALLOW_INSECURE_ISSUER),
    allowUnverifiedEmail: false,
  }
}

// ---------- validation ----------

export type DraftInput = {
  preset: unknown
  issuer: string
  clientId: string
  clientSecret: string // '' = keep the saved one
  clearSecret: boolean // public client (PKCE only)
  scopes: string
  emailClaim: string
  groupsClaim: string
  requiredClaims: string
  buttonLabel: string
}

const CLAIM = /^[A-Za-z0-9_:./-]{1,100}$/
// The presets' issuer patterns still waiting to be filled in.
const PLACEHOLDER = /TENANT-ID|YOUR-ORG/
const PRINTABLE = /^[^\x00-\x1f\x7f]*$/

export function validateDraft(input: DraftInput, env: Env = process.env): Omit<DraftInput, 'clientSecret' | 'clearSecret'> & { preset: Preset } {
  const bad = (field: string): never => {
    throw new SsoRefusal('invalid', field)
  }
  if (!isPreset(input.preset)) bad('preset')
  const issuer = input.issuer.trim().replace(/\/+$/, '')
  let url: URL | null = null
  try {
    url = new URL(issuer)
  } catch {
    bad('issuer')
  }
  const insecureOk = envBool(env.OIDC_ALLOW_INSECURE_ISSUER)
  if (!url || !(url.protocol === 'https:' || (insecureOk && url.protocol === 'http:')) || url.search || url.hash || url.username || issuer.length > 500 || PLACEHOLDER.test(issuer)) {
    bad('issuer')
  }
  const clientId = input.clientId.trim()
  if (!clientId || clientId.length > 300 || /\s/.test(clientId) || !PRINTABLE.test(clientId)) bad('client_id')
  if (input.clientSecret.length > 2000 || /[\x00-\x1f\x7f]/.test(input.clientSecret)) bad('client_secret')
  const scopes = input.scopes.trim().replace(/\s+/g, ' ')
  if (!scopes.split(' ').includes('openid') || scopes.length > 500 || !/^[A-Za-z0-9_:./ -]+$/.test(scopes)) bad('scopes')
  const emailClaim = input.emailClaim.trim()
  if (!CLAIM.test(emailClaim)) bad('email_claim')
  const groupsClaim = input.groupsClaim.trim()
  if (!CLAIM.test(groupsClaim)) bad('groups_claim')
  const requiredClaims = input.requiredClaims.trim()
  if (requiredClaims.length > 1000 || !PRINTABLE.test(requiredClaims) || /=\s*example\.com\b/i.test(requiredClaims)) bad('required_claims')
  try {
    parseRequiredClaims(requiredClaims)
  } catch (err) {
    if (!(err instanceof ConfigError)) throw err
    bad('required_claims')
  }
  const buttonLabel = input.buttonLabel.trim()
  if (buttonLabel.length > 60 || !PRINTABLE.test(buttonLabel)) bad('button_label')
  return { preset: input.preset as Preset, issuer, clientId, scopes, emailClaim, groupsClaim, requiredClaims, buttonLabel }
}

// ---------- changes (owner only) ----------

async function owned<T>(db: Pool, actor: SsoActor, action: string, fn: (c: PoolClient) => Promise<{ result: T; detail: Record<string, unknown>; target: string }>): Promise<T> {
  try {
    if (!atLeast(actor.role, 'owner')) throw new SsoRefusal('not_allowed')
    if (process.env.AUTH_PROVIDER?.trim()) throw new SsoRefusal('environment')
    const client = await db.connect()
    try {
      await client.query('BEGIN')
      if (actor.userId != null) {
        const me = await client.query<{ status: string; role: string }>(`SELECT status, role FROM users WHERE id = $1`, [actor.userId])
        if (me.rows[0]?.status !== 'active' || me.rows[0]?.role !== 'owner') throw new SsoRefusal('not_allowed')
      }
      const { result, detail, target } = await fn(client)
      await client.query('UPDATE config_version SET version = version + 1')
      await writeAudit(client, { action, actor, target, detail })
      await client.query('COMMIT')
      return result
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    if (err instanceof SsoRefusal) {
      await recordAudit(db, { action: 'action_refused', actor, target: 'sso', detail: { action, reason: err.code, ...(err.field ? { field: err.field } : {}) } })
    }
    throw err
  }
}

// The draft to edit: the existing one, else a copy of the active connection,
// else a new one from a preset.
export async function startDraft(db: Pool, actor: SsoActor, presetInput: unknown, env: Env = process.env): Promise<number> {
  return owned(db, actor, 'sso_draft_started', async (c) => {
    const existing = await c.query<{ id: string }>(`SELECT id FROM sso_connections WHERE state = 'draft' FOR UPDATE`)
    if (existing.rows[0]) return { result: Number(existing.rows[0].id), detail: { reused: true }, target: `sso:${existing.rows[0].id}` }
    const active = toRow((await c.query(`SELECT ${COLUMNS} FROM sso_connections WHERE state = 'active'`)).rows[0])
    let id: number
    if (active) {
      const { rows } = await c.query<{ id: string }>(
        `INSERT INTO sso_connections (state, preset, issuer, client_id, scopes, email_claim, groups_claim, required_claims, button_label, created_by, updated_by)
         SELECT 'draft', preset, issuer, client_id, scopes, email_claim, groups_claim, required_claims, button_label, $2, $2
         FROM sso_connections WHERE id = $1 RETURNING id`,
        [active.id, actor.userId]
      )
      id = Number(rows[0].id)
      if (active.client_secret) {
        // Re-encrypted for the new row: each envelope is bound to its row.
        const plain = decryptSecret('setting', secretContext(active.id), active.client_secret, env).plaintext
        await c.query(`UPDATE sso_connections SET client_secret = $2 WHERE id = $1`, [id, encryptSecret('setting', secretContext(id), plain, env)])
      }
      return { result: id, detail: { from: `sso:${active.id}` }, target: `sso:${id}` }
    }
    const preset: Preset = isPreset(presetInput) ? presetInput : 'generic'
    const p = PRESETS[preset]
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO sso_connections (state, preset, issuer, client_id, scopes, email_claim, groups_claim, required_claims, button_label, created_by, updated_by)
       VALUES ('draft', $1, $2, '', $3, $4, $5, $6, $7, $8, $8) RETURNING id`,
      [preset, p.issuer, p.scopes, p.emailClaim, p.groupsClaim, p.requiredClaims, preset === 'generic' ? '' : p.label, actor.userId]
    )
    id = Number(rows[0].id)
    return { result: id, detail: { preset }, target: `sso:${id}` }
  })
}

export async function saveDraft(db: Pool, actor: SsoActor, input: DraftInput, env: Env = process.env): Promise<void> {
  await owned(db, actor, 'sso_draft_saved', async (c) => {
    const draft = (await c.query<{ id: string }>(`SELECT id FROM sso_connections WHERE state = 'draft' FOR UPDATE`)).rows[0]
    if (!draft) throw new SsoRefusal('no_draft')
    const id = Number(draft.id)
    const v = validateDraft(input, env)
    await c.query(
      `UPDATE sso_connections SET preset = $2, issuer = $3, client_id = $4, scopes = $5, email_claim = $6, groups_claim = $7,
         required_claims = $8, button_label = $9, revision = revision + 1, updated_at = NOW(), updated_by = $10
       WHERE id = $1`,
      [id, v.preset, v.issuer, v.clientId, v.scopes, v.emailClaim, v.groupsClaim, v.requiredClaims, v.buttonLabel, actor.userId]
    )
    let secret: 'kept' | 'replaced' | 'removed' = 'kept'
    if (input.clearSecret) {
      await c.query(`UPDATE sso_connections SET client_secret = NULL WHERE id = $1`, [id])
      secret = 'removed'
    } else if (input.clientSecret) {
      await c.query(`UPDATE sso_connections SET client_secret = $2 WHERE id = $1`, [id, encryptSecret('setting', secretContext(id), input.clientSecret, env)])
      secret = 'replaced'
    }
    return {
      result: undefined,
      detail: { preset: v.preset, issuer: v.issuer, client_id: v.clientId, scopes: v.scopes, email_claim: v.emailClaim, groups_claim: v.groupsClaim, required_claims: v.requiredClaims, client_secret: secret },
      target: `sso:${id}`,
    }
  })
}

export async function discardDraft(db: Pool, actor: SsoActor): Promise<void> {
  await owned(db, actor, 'sso_draft_discarded', async (c) => {
    const { rows } = await c.query<{ id: string }>(`DELETE FROM sso_connections WHERE state = 'draft' RETURNING id`)
    if (!rows[0]) throw new SsoRefusal('no_draft')
    return { result: undefined, detail: {}, target: `sso:${rows[0].id}` }
  })
}

// Only a successful test of exactly this revision, recent enough, activates.
export function activationProblem(draft: Pick<ConnectionRow, 'revision' | 'last_test'>, now = Date.now()): SsoRefusalCode | null {
  const t = draft.last_test
  if (!t) return 'not_tested'
  if (t.revision !== draft.revision) return 'not_tested'
  if (!t.ok) return 'test_failed'
  const at = Date.parse(t.at)
  if (Number.isNaN(at) || now - at > TEST_VALID_HOURS * 3600 * 1000) return 'test_stale'
  return null
}

export async function activateDraft(db: Pool, actor: SsoActor): Promise<void> {
  await owned(db, actor, 'sso_activated', async (c) => {
    const draft = toRow((await c.query(`SELECT ${COLUMNS} FROM sso_connections WHERE state = 'draft' FOR UPDATE`)).rows[0])
    if (!draft) throw new SsoRefusal('no_draft')
    const problem = activationProblem(draft)
    if (problem) throw new SsoRefusal(problem)
    const old = await c.query<{ id: string }>(
      `UPDATE sso_connections SET state = 'retired', retired_at = NOW() WHERE state = 'active' RETURNING id`
    )
    await c.query(`UPDATE sso_connections SET state = 'active', activated_at = NOW(), activated_by = $2 WHERE id = $1`, [draft.id, actor.userId])
    return {
      result: undefined,
      detail: { issuer: draft.issuer, client_id: draft.client_id, revision: draft.revision, replaced: old.rows[0] ? `sso:${old.rows[0].id}` : null },
      target: `sso:${draft.id}`,
    }
  })
}

export async function deactivate(db: Pool, actor: SsoActor): Promise<void> {
  await owned(db, actor, 'sso_deactivated', async (c) => {
    const { rows } = await c.query<{ id: string; issuer: string }>(
      `UPDATE sso_connections SET state = 'retired', retired_at = NOW() WHERE state = 'active' RETURNING id, issuer`
    )
    if (!rows[0]) throw new SsoRefusal('no_active')
    return { result: undefined, detail: { issuer: rows[0].issuer }, target: `sso:${rows[0].id}` }
  })
}

// ---------- test results ----------

// What of the returned claims is worth showing the owner: identity-related
// claims, the configured ones, and the required ones. Never tokens.
const SHOWN = ['iss', 'aud', 'sub', 'email', 'email_verified', 'name', 'preferred_username', 'upn', 'hd', 'tid', 'oid']

export function summarizeClaims(claims: Record<string, unknown>, settings: OidcSettings): Record<string, unknown> {
  const keys = new Set([...SHOWN, settings.emailClaim, settings.groupsClaim])
  try {
    for (const { claim } of parseRequiredClaims(settings.requiredClaims)) keys.add(claim)
  } catch {
    // validated when saved
  }
  const out: Record<string, unknown> = {}
  for (const k of keys) {
    const v = claims[k]
    if (v === undefined) continue
    if (Array.isArray(v)) out[k] = v.slice(0, 50).map((x) => (typeof x === 'string' ? x.slice(0, 200) : x))
    else if (typeof v === 'string') out[k] = v.slice(0, 500)
    else if (typeof v === 'number' || typeof v === 'boolean') out[k] = v
  }
  return out
}

// Who would let this person in, without recording anything (a test must not
// create users or requests).
export async function wouldAdmit(db: Pick<Pool, 'query'>, identity: Identity, rules: readonly AccessRule[], env: Env = process.env): Promise<NonNullable<TestResult['admission']>> {
  const { rows } = await db.query<{ role: Role; role_source: string; status: string; invited_at: string | null }>(
    `SELECT role, role_source, status, invited_at FROM users WHERE email = $1`,
    [identity.email]
  )
  const row = rows[0]
  if (row?.status === 'disabled') return { role: null, via: 'existing user', status: 'disabled' }
  const fromRules = ruleRole(identity, env, rules)
  const assigned = row && row.role_source === 'assigned' && (row.status === 'active' || row.invited_at) ? row.role : null
  const role = higherRole(assigned, fromRules)
  return { role, via: assigned && role === assigned ? 'existing user' : fromRules ? 'access rule' : 'none', status: row?.status ?? null }
}

// Records the outcome of a test for the revision it tested. Ignored when the
// draft changed meanwhile (another revision, discarded, activated).
export async function recordTest(db: Pool, test: { connectionId: number; revision: number }, result: TestResult): Promise<boolean> {
  const { rowCount } = await db.query(
    `UPDATE sso_connections SET last_test = $3 WHERE id = $1 AND state = 'draft' AND revision = $2`,
    [test.connectionId, test.revision, JSON.stringify(result)]
  )
  await recordAudit(db, {
    action: result.ok ? 'sso_test_succeeded' : 'sso_test_failed',
    actor: { userId: result.by.userId, email: result.by.email, ip: null },
    target: `sso:${test.connectionId}`,
    detail: { revision: test.revision, ...(result.error ? { error: result.error.code } : {}), recorded: rowCount === 1 },
  })
  return rowCount === 1
}
