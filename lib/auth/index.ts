// Provider-independent entry point: turn a request's headers and cookies into
// an AuthResult. Used by proxy.ts (the coarse gate in front of every route)
// and again by the pages and actions themselves (lib/auth/server.ts), so a
// misconfigured matcher can never expose data on its own.

import { ConfigError, type Env } from '../config'
import { resolveRole } from './authz'
import { identityFromProxyHeader, identityFromProxyJwt } from './proxy-providers'
import { sessionCookieName, unsealSession } from './session'
import type { AuthProviderName, AuthResult, Identity } from './types'

export type { AuthProviderName, AuthResult, Identity, Role, Session } from './types'

const PROVIDERS: AuthProviderName[] = ['oidc', 'proxy-jwt', 'proxy-header', 'none']

export function authProvider(env: Env = process.env): AuthProviderName {
  const raw = (env.AUTH_PROVIDER || '').trim().toLowerCase()
  if (!raw) {
    throw new ConfigError(`AUTH_PROVIDER is not set. Choose one of: ${PROVIDERS.join(', ')} (see docs/authentication.md).`)
  }
  if (!PROVIDERS.includes(raw as AuthProviderName)) {
    throw new ConfigError(`Unknown AUTH_PROVIDER "${raw}". Choose one of: ${PROVIDERS.join(', ')}.`)
  }
  if (raw === 'none' && env.NODE_ENV === 'production' && env.AUTH_ALLOW_INSECURE_NONE !== 'true') {
    throw new ConfigError(
      'AUTH_PROVIDER=none disables sign-in and is refused in production. Configure a real provider, or set AUTH_ALLOW_INSECURE_NONE=true if access is enforced elsewhere.'
    )
  }
  return raw as AuthProviderName
}

type RequestLike = {
  headers: { get(name: string): string | null }
  cookie(name: string): string | undefined
}

const ANONYMOUS: Identity = { sub: 'anonymous', email: 'anonymous@localhost', name: 'Anonymous', groups: [] }

export async function authenticate(req: RequestLike, env: Env = process.env): Promise<AuthResult> {
  const provider = authProvider(env)

  if (provider === 'none') {
    return { status: 'ok', session: { identity: ANONYMOUS, role: 'admin' } }
  }

  let identity: Identity | null
  if (provider === 'oidc') {
    identity = await unsealSession(req.cookie(sessionCookieName(env)), env)
  } else if (provider === 'proxy-jwt') {
    identity = await identityFromProxyJwt(req.headers, env)
  } else {
    identity = identityFromProxyHeader(req.headers, env)
  }

  if (!identity) return { status: 'unauthenticated' }
  const role = resolveRole(identity, env)
  if (!role) return { status: 'forbidden', identity }
  return { status: 'ok', session: { identity, role } }
}
