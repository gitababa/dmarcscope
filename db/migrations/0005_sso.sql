-- 2.0 milestone 3: single sign-on configured in the panel (when AUTH_PROVIDER
-- is unset). One draft, which changes nothing until a real test sign-in with
-- it succeeds and an owner activates it, and at most one active connection.

CREATE TABLE IF NOT EXISTS sso_connections (
  id BIGSERIAL PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('draft', 'active', 'retired')),
  preset TEXT NOT NULL CHECK (preset IN ('google', 'entra', 'okta', 'generic')),
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret TEXT,             -- encrypted envelope bound to this row; NULL: public client (PKCE only)
  scopes TEXT NOT NULL DEFAULT 'openid email profile',
  email_claim TEXT NOT NULL DEFAULT 'email',
  groups_claim TEXT NOT NULL DEFAULT 'groups',
  required_claims TEXT NOT NULL DEFAULT '',
  button_label TEXT NOT NULL DEFAULT '',
  revision INT NOT NULL DEFAULT 1, -- bumped on every save of the draft
  last_test JSONB,                 -- outcome of the latest test sign-in (see lib/sso.ts)
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  activated_at TIMESTAMPTZ,
  activated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  retired_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS sso_connections_one_draft ON sso_connections (state) WHERE state = 'draft';
CREATE UNIQUE INDEX IF NOT EXISTS sso_connections_one_active ON sso_connections (state) WHERE state = 'active';
