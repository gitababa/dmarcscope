// Small helpers for reading configuration from the environment. Everything is
// read lazily (at call time) so tests can vary the environment and so a
// missing variable fails the request that needs it, with a clear message,
// instead of crashing the build.

export type Env = Record<string, string | undefined>

// A configuration problem the operator has to fix. The message is shown in
// server logs and on the error page, so it must never contain secret values.
export class ConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConfigError'
  }
}

export function envList(raw: string | undefined): string[] {
  return (raw || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
}

export function envBool(raw: string | undefined, fallback = false): boolean {
  if (raw == null || raw.trim() === '') return fallback
  return ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase())
}

export function envInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number.parseInt(raw || '', 10)
  if (!Number.isInteger(n)) return fallback
  return Math.min(max, Math.max(min, n))
}

export function appName(env: Env = process.env): string {
  return env.APP_NAME?.trim() || 'DMARCscope'
}

// Public base URL of the deployment, without a trailing slash. Needed to build
// absolute redirect URIs; never derived from request headers in production
// because Host / X-Forwarded-Host are attacker-controlled.
export function appUrl(env: Env = process.env): string {
  const raw = env.APP_URL?.trim()
  if (raw) {
    let url: URL
    try {
      url = new URL(raw)
    } catch {
      throw new ConfigError('APP_URL is not a valid URL (expected e.g. https://dmarc.example.com).')
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      throw new ConfigError('APP_URL must start with https:// (or http:// for local development).')
    }
    return url.origin
  }
  // On Vercel, the project's production address (its shortest custom domain,
  // else its .vercel.app one). Set by the platform, not taken from a request.
  const vercelHost = env.VERCEL === '1' ? env.VERCEL_PROJECT_PRODUCTION_URL?.trim() : undefined
  if (vercelHost && /^[a-z0-9.-]+(:\d+)?$/i.test(vercelHost)) return `https://${vercelHost.toLowerCase()}`
  if (env.NODE_ENV === 'production') {
    throw new ConfigError('APP_URL is not set. Set it to the public URL of this deployment, e.g. https://dmarc.example.com.')
  }
  return 'http://localhost:3000'
}

// Constant-time string comparison for bearer tokens and shared secrets.
export function safeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder()
  const x = enc.encode(a)
  const y = enc.encode(b)
  let diff = x.length ^ y.length
  const len = Math.max(x.length, y.length)
  for (let i = 0; i < len; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0)
  return diff === 0
}

// `Authorization: Bearer <CRON_SECRET>` check for machine-to-machine
// endpoints. Fails closed when the secret is not configured.
export function hasValidBearer(authorization: string | null, env: Env = process.env): boolean {
  const secret = env.CRON_SECRET
  if (secret && secret.length < 16) {
    // Otherwise indistinguishable from a wrong token: every call is a 401.
    if (!warnedShortSecret) console.error('[config] CRON_SECRET is shorter than 16 characters; /api/cron/* rejects every request until it is replaced.')
    warnedShortSecret = true
    return false
  }
  if (!secret || !authorization) return false
  return safeEqual(authorization, `Bearer ${secret}`)
}

let warnedShortSecret = false
