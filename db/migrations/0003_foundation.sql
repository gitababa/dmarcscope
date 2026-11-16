-- 2.0 foundation: users and access in the database, settings, audit log,
-- first-run setup. Nothing here changes how a 1.1.0 deployment behaves: with
-- its environment unchanged, every new table starts empty and the
-- environment keeps deciding (see docs/plan-2.0.md).

-- Bumped in the same transaction as every write to settings, access_rules or
-- to who the owner is. Web processes cache what they read from those tables
-- and only reload when this number has moved, so a change reaches every
-- replica within the cache window (SETTINGS_CACHE_SECONDS).
CREATE TABLE IF NOT EXISTS config_version (
  id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  version BIGINT NOT NULL DEFAULT 1
);
INSERT INTO config_version (id, version) VALUES (TRUE, 1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE CHECK (email <> '' AND email = lower(email)),
  name TEXT,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
  -- 'assigned': the role was given to this person (setup wizard, an
  -- administrator, the settings import) and holds until changed.
  -- 'rule': the person was let in by an access rule. The role is worked out
  -- from the rules again on every request; the stored one is for display.
  -- Removing the rule removes the access, as in 1.1.0.
  role_source TEXT NOT NULL DEFAULT 'assigned' CHECK (role_source IN ('assigned', 'rule')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
  source TEXT NOT NULL CHECK (source IN ('local', 'oidc', 'proxy', 'scim')),
  oidc_subject TEXT,
  password_hash TEXT,
  totp_secret TEXT,               -- encrypted envelope (lib/envelope.mjs), never plain
  totp_confirmed_at TIMESTAMPTZ,
  totp_last_step BIGINT,          -- last accepted TOTP time step: each code works once
  failed_logins INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  sessions_valid_after TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS users_owner_idx ON users (id) WHERE role = 'owner';

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,           -- for is_secret rows: a JSON string holding an encrypted envelope
  is_secret BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS access_rules (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('email_domain', 'group')),
  value TEXT NOT NULL CHECK (value <> '' AND value = lower(value)),
  role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at TIMESTAMPTZ,
  UNIQUE (user_id, code_hash)
);

-- Append-only: the application has no UPDATE or DELETE path, and the trigger
-- below refuses both. actor_user_id deliberately has no foreign key, so that
-- removing a user never rewrites the history of what they did.
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_user_id BIGINT,
  actor_email TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_at_idx ON audit_log (at DESC);

CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END
$$;
DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- One-time setup tokens, stored as SHA-256 digests.
CREATE TABLE IF NOT EXISTS setup_tokens (
  id BIGSERIAL PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,         -- NULL for a token supplied as SETUP_TOKEN
  used_at TIMESTAMPTZ
);

-- Failed sign-in and setup attempts per client address, and per address
-- typed into the sign-in form when no such account exists (so that a
-- lockout looks the same whether or not the account is real). Known
-- accounts are counted on users.failed_logins.
CREATE TABLE IF NOT EXISTS auth_throttle (
  key TEXT PRIMARY KEY,
  failures INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS auth_throttle_updated_idx ON auth_throttle (updated_at);
