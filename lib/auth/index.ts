// Provider-independent entry point: turn a request's headers and cookies into
// an AuthResult. Used by proxy.ts (the coarse gate in front of every route)
// and again by the pages and actions themselves (lib/auth/server.ts), so a
// misconfigured matcher can never expose data on its own.
//
// The provider says who the request is; the database (lib/auth/resolve.ts)
// says whether they may come in and with which role.

import { ConfigError, envBool, type Env } from '../config'
import { trackedGroups } from './authz'
import { type Directory, defaultDirectory } from './directory'
import { identityFromProxyHeader, identityFromProxyJwt } from './proxy-providers'
import { resolveAccess } from './resolve'
import { sessionCookieName, unsealSessionClaims } from './session'
import type { AuthProviderName, AuthResult, Identity } from './types'

export type { AuthProviderName, AuthResult, Identity, Role, Session } from './types'

const PROVIDERS: AuthProviderName[] = ['oidc', 'proxy-jwt', 'proxy-header', 'none']

// AUTH_PROVIDER unset: the application manages sign-in itself ('local').
export function authProvider(env: Env = process.env): AuthProviderName {
  const raw = (env.AUTH_PROVIDER || '').trim().toLowerCase()
  if (!raw) return 'local'
  if (!PROVIDERS.includes(raw as AuthProviderName)) {
    throw new ConfigError(`Unknown AUTH_PROVIDER "${raw}". Choose one of: ${PROVIDERS.join(', ')}, or leave it unset to manage sign-in in the app.`)
  }
  if (raw === 'none' && env.NODE_ENV === 'production' && !envBool(env.AUTH_ALLOW_INSECURE_NONE)) {
    throw new ConfigError(
      'AUTH_PROVIDER=none disables sign-in and is refused in production. Configure a real provider, or set AUTH_ALLOW_INSECURE_NONE=true if access is enforced elsewhere.'
    )
  }
  return raw as AuthProviderName
}

// Whether people sign in on this app's own sign-in page (with a session
// cookie), as opposed to arriving already authenticated by a proxy.
export function hasSignInPage(provider: AuthProviderName): boolean {
  return provider === 'local' || provider === 'oidc'
}

type RequestLike = {
  headers: { get(name: string): string | null }
  cookie(name: string): string | undefined
}

const ANONYMOUS: Identity = { sub: 'anonymous', email: 'anonymous@localhost', name: 'Anonymous', groups: [] }

export async function authenticate(req: RequestLike, env: Env = process.env, dir: Directory = defaultDirectory()): Promise<AuthResult> {
  const provider = authProvider(env)

  // Development only: no sign-in, no users, full access.
  if (provider === 'none') {
    return { status: 'ok', session: { identity: ANONYMOUS, role: 'owner', userId: null } }
  }

  if (provider === 'local') {
    const { ownerExists } = await dir.config()
    if (!ownerExists) return { status: 'setup_required' }
  }

  if (provider === 'local' || provider === 'oidc') {
    // In oidc mode the cookie may also come from the owner's own sign-in.
    const claims = await unsealSessionClaims(req.cookie(sessionCookieName(env)), env)
    if (!claims) return { status: 'unauthenticated' }
    // Without SSO configured in the panel, a cookie in local
    // mode can only come from the password sign-in, which records the user.
    if (provider === 'local' && claims.userId == null) return { status: 'unauthenticated' }
    return resolveAccess(claims.identity, provider, { issuedAt: claims.issuedAt, userId: claims.userId }, env, dir)
  }

  const extraGroups = trackedGroups(await dir.config())
  const identity =
    provider === 'proxy-jwt' ? await identityFromProxyJwt(req.headers, env, extraGroups) : identityFromProxyHeader(req.headers, env, extraGroups)
  if (!identity) return { status: 'unauthenticated' }
  return resolveAccess(identity, provider, {}, env, dir)
}
