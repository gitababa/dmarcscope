// Every setting the application reads through the settings store.
//
// A setting resolves to exactly one value: its environment variable if that
// is set, else the database, else the default. A setting supplied by the
// environment is "managed by environment" and cannot be changed in the panel.
//
// Only settings the application actually reads from the store belong here:
// listing one that nothing reads would show administrators a control that
// does nothing. Milestones 3-5 add sign-in, mailbox and alerting settings.

export type SettingType = 'string' | 'int' | 'bool' | 'secret'

type Parsed<T> = { ok: true; value: T } | { ok: false; error: string }

type Value = string | number | boolean

export type SettingDef = {
  key: string
  label: string
  description: string
  type: SettingType
  env: string
  default: Value | null
  // Owner-only to change: sign-in and secret settings.
  ownerOnly: boolean
  // Validates a value typed into the panel or stored in the database.
  parse(raw: unknown): Parsed<Value>
  // Validates the environment variable. Kept as lenient as 1.1.0 was where
  // 1.1.0 clamped a number into range, so existing deployments keep working.
  parseEnv(raw: string): Parsed<Value>
}

const intParser = (min: number, max: number) => (raw: unknown): Parsed<number> => {
  const text = typeof raw === 'number' ? String(raw) : typeof raw === 'string' ? raw.trim() : ''
  if (!/^-?\d+$/.test(text)) return { ok: false, error: `must be a whole number from ${min} to ${max}` }
  const n = Number(text)
  if (n < min || n > max) return { ok: false, error: `must be a whole number from ${min} to ${max}` }
  return { ok: true, value: n }
}

// 1.1.0 read these with "clamp into range"; a value that is not a number at
// all is now reported as an error instead of silently becoming the default.
const clampedIntEnv = (min: number, max: number) => (raw: string): Parsed<number> => {
  const text = raw.trim()
  if (!/^-?\d+$/.test(text)) return { ok: false, error: `must be a whole number from ${min} to ${max}` }
  return { ok: true, value: Math.min(max, Math.max(min, Number(text))) }
}

// Yes/no. The environment accepts the same spellings as every other boolean
// variable; anything else is an error, not "no".
const boolParser = (raw: unknown): Parsed<boolean> => {
  if (typeof raw === 'boolean') return { ok: true, value: raw }
  const t = typeof raw === 'string' ? raw.trim().toLowerCase() : ''
  if (['1', 'true', 'yes', 'on'].includes(t)) return { ok: true, value: true }
  if (['0', 'false', 'no', 'off'].includes(t)) return { ok: true, value: false }
  return { ok: false, error: 'must be true or false' }
}

const SETTINGS: SettingDef[] = [
  {
    key: 'app.name',
    label: 'Application name',
    description: 'Shown in the header and in page titles.',
    type: 'string',
    env: 'APP_NAME',
    default: 'DMARCscope',
    ownerOnly: false,
    parse(raw) {
      const s = typeof raw === 'string' ? raw.trim() : ''
      if (!s || s.length > 60 || /[\x00-\x1f\x7f]/.test(s)) return { ok: false, error: 'must be 1 to 60 printable characters' }
      return { ok: true, value: s }
    },
    parseEnv(raw) {
      // As in 1.1.0: any non-empty value, and an empty one means the default.
      return { ok: true, value: raw.trim() || 'DMARCscope' }
    },
  },
  {
    key: 'ingest.stale_hours',
    label: 'Ingest staleness warning (hours)',
    description: 'With no completed ingest run for this long, the overview warns and /api/cron/status answers 503.',
    type: 'int',
    env: 'INGEST_STALE_HOURS',
    default: 36,
    ownerOnly: false,
    parse: intParser(1, 2160),
    parseEnv: (raw) => {
      // 1.1.0 treated values below 1 as "unset".
      const r = clampedIntEnv(1, 2160)(raw)
      return r.ok && Number(raw.trim()) < 1 ? { ok: true, value: 36 } : r
    },
  },
  {
    key: 'ingest.retention_days',
    label: 'Keep reports for (days)',
    description:
      'Reports older than this are deleted by the worker (1 to 36500). Unset: reports are kept forever. RETENTION_DAYS=0 in the environment also means forever.',
    type: 'int',
    env: 'RETENTION_DAYS',
    default: null,
    ownerOnly: false,
    parse: intParser(1, 36500),
    parseEnv(raw) {
      // As the worker reads it: 0 means keep forever; negative is an error.
      const text = raw.trim()
      if (!/^\d+$/.test(text)) return { ok: false, error: 'must be a whole number, 0 for forever' }
      return { ok: true, value: Number(text) }
    },
  },
  {
    key: 'session.max_age_hours',
    label: 'Session length (hours)',
    description: 'How long a sign-in lasts (1 to 168).',
    type: 'int',
    env: 'SESSION_MAX_AGE_HOURS',
    default: 12,
    ownerOnly: true,
    parse: intParser(1, 168),
    parseEnv: clampedIntEnv(1, 168),
  },
  {
    key: 'auth.local_signin_non_owners',
    label: 'Password sign-in for non-owners',
    description:
      'Lets people other than the owner who have a password and an authenticator (for example a former owner) use the password sign-in. The owner can always sign in with a password.',
    type: 'bool',
    env: 'AUTH_LOCAL_SIGNIN_NON_OWNERS',
    default: false,
    ownerOnly: true,
    parse: boolParser,
    parseEnv: boolParser,
  },
  {
    key: 'auth.enforce_sso',
    label: 'Require single sign-on',
    description:
      'While a single sign-on connection is active, everyone but the owner must use it; the sign-in page shows the password form only behind "Owner sign-in".',
    type: 'bool',
    env: 'AUTH_ENFORCE_SSO',
    default: false,
    ownerOnly: true,
    parse: boolParser,
    parseEnv: boolParser,
  },
  {
    key: 'cron.secret',
    label: 'Machine endpoint token',
    description: 'Bearer token for /api/cron/*, at least 16 characters. The endpoints refuse every request while it is unset.',
    type: 'secret',
    env: 'CRON_SECRET',
    default: null,
    ownerOnly: true,
    parse(raw) {
      const s = typeof raw === 'string' ? raw : ''
      if (s.length < 16 || s.length > 512) return { ok: false, error: 'must be 16 to 512 characters' }
      if (/[\s\x00-\x1f\x7f]/.test(s)) return { ok: false, error: 'must not contain spaces or control characters' }
      return { ok: true, value: s }
    },
    parseEnv(raw) {
      return this.parse(raw)
    },
  },
]

export const REGISTRY: ReadonlyMap<string, SettingDef> = new Map(SETTINGS.map((s) => [s.key, s]))

export type SettingKey =
  | 'app.name'
  | 'ingest.stale_hours'
  | 'ingest.retention_days'
  | 'session.max_age_hours'
  | 'auth.local_signin_non_owners'
  | 'auth.enforce_sso'
  | 'cron.secret'
export type SecretSettingKey = 'cron.secret'
export type PlainSettingKey = Exclude<SettingKey, SecretSettingKey>

export function settingDef(key: string): SettingDef {
  const def = REGISTRY.get(key)
  if (!def) throw new Error(`Unknown setting "${key}"`)
  return def
}
