export type Role = 'admin' | 'viewer'

export type AuthProviderName = 'oidc' | 'proxy-jwt' | 'proxy-header' | 'none'

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
}

export type AuthResult =
  | { status: 'ok'; session: Session }
  // No (valid) credentials on the request.
  | { status: 'unauthenticated' }
  // Authenticated, but not on any access list.
  | { status: 'forbidden'; identity: Identity }
