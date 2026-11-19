-- 2.0 milestone 6: per-domain permissions, SCIM groups and API tokens.
-- Nothing here changes what anyone sees until an administrator limits
-- someone: no row means "no opinion" and access.domain_default (default
-- 'all') decides.

-- Who is limited to which domains. A person (kind 'user', principal = the
-- users.id as text) or a group (kind 'group', principal = the lower-cased
-- group name, from the identity provider's claim or from SCIM).
CREATE TABLE IF NOT EXISTS domain_scopes (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'group')),
  principal TEXT NOT NULL CHECK (principal <> '' AND principal = lower(principal) AND length(principal) <= 300),
  mode TEXT NOT NULL CHECK (mode IN ('all', 'limited')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE (kind, principal)
);

-- The domains a 'limited' scope may see. Names, not a foreign key: a grant
-- can precede the domain's first report.
CREATE TABLE IF NOT EXISTS domain_grants (
  id BIGSERIAL PRIMARY KEY,
  scope_id BIGINT NOT NULL REFERENCES domain_scopes(id) ON DELETE CASCADE,
  domain TEXT NOT NULL CHECK (domain <> '' AND domain = lower(domain) AND length(domain) <= 253),
  UNIQUE (scope_id, domain)
);

-- Groups provisioned by SCIM (or created in the panel). A group's name counts
-- as a group claim for access rules and domain scopes.
CREATE TABLE IF NOT EXISTS groups (
  id BIGSERIAL PRIMARY KEY,
  display_name TEXT NOT NULL CHECK (display_name <> '' AND length(display_name) <= 200),
  external_id TEXT CHECK (external_id IS NULL OR length(external_id) <= 200),
  source TEXT NOT NULL CHECK (source IN ('scim', 'local')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS groups_name_idx ON groups (lower(display_name));
CREATE UNIQUE INDEX IF NOT EXISTS groups_external_idx ON groups (external_id) WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS group_members (
  group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS group_members_user_idx ON group_members (user_id);

-- API tokens ('api') and the SCIM token ('scim'). Only the SHA-256 of the
-- token is stored; the token itself is shown once, when it is created.
CREATE TABLE IF NOT EXISTS api_tokens (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('api', 'scim')),
  name TEXT NOT NULL CHECK (name <> '' AND length(name) <= 100),
  prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  -- The token's own domain limit (API tokens). 'limited' with no domains sees
  -- nothing. A token is never wider than its creator, who must still be an
  -- active administrator or owner when it is used (lib/api-tokens.ts).
  domain_mode TEXT NOT NULL DEFAULT 'limited' CHECK (domain_mode IN ('all', 'limited')),
  domains TEXT[] NOT NULL DEFAULT '{}',
  created_by BIGINT REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_tokens_kind_idx ON api_tokens (kind, revoked_at);

-- SCIM's externalId.
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id TEXT CHECK (external_id IS NULL OR length(external_id) <= 200);
CREATE UNIQUE INDEX IF NOT EXISTS users_external_idx ON users (external_id) WHERE external_id IS NOT NULL;
