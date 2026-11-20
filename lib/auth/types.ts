// owner: everything, including sign-in and secret settings
// admin: users, mailbox, domains, alerts, DNS checks
// viewer: read-only
export type Role = 'owner' | 'admin' | 'viewer'

// 'local' is AUTH_PROVIDER unset: the application manages sign-in itself
// (passwords and TOTP, and single sign-on configured in the panel).
export type AuthProviderName = 'local' | 'oidc' | 'proxy-jwt' | 'proxy-header' | 'none'

// Who the request is, as established by the configured provider.
export type Identity = {
  sub: string
  email: string
  name?: string
  groups: string[]
}

export type Session = {
  identity: Identity
  role: Role
  // The users row. Null only with AUTH_PROVIDER=none, which has no users.
  userId: number | null
}

export type AuthResult =
  | { status: 'ok'; session: Session }
  // No (valid) credentials on the request, or a session that was revoked.
  | { status: 'unauthenticated' }
  // Authenticated, but not admitted: on no access list, waiting for
  // approval, or disabled.
  | { status: 'forbidden'; identity: Identity }
  // AUTH_PROVIDER unset and no owner yet: only the setup wizard is served.
  | { status: 'setup_required' }
