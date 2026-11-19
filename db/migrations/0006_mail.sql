-- 2.0 milestone 4: reports mailboxes and monitored domains configured in the
-- panel, and the worker's long-running mode (python -m ingestor serve).
--
-- Contract between the web app (lib/mail.ts) and the worker (ingestor/):
-- both read and write these tables. The web app only ever encrypts a
-- mailbox secret; the worker is the only side that decrypts it.

CREATE TABLE IF NOT EXISTS mailboxes (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL CHECK (name <> '' AND length(name) <= 100),
  kind TEXT NOT NULL CHECK (kind IN ('imap', 'microsoft', 'google')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  host TEXT NOT NULL,
  port INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  security TEXT NOT NULL DEFAULT 'ssl' CHECK (security IN ('ssl', 'starttls')),
  username TEXT NOT NULL,             -- the mailbox address (IMAP login, or the mailbox an app signs in as)
  tenant_id TEXT,                     -- microsoft
  client_id TEXT,                     -- microsoft (application ID); google: unused (in the key)
  secret TEXT,                        -- encrypted envelope, purpose 'mailbox', context 'mailbox:<id>'
  secret_updated_at TIMESTAMPTZ,
  folder TEXT NOT NULL DEFAULT 'INBOX',
  processed_folder TEXT,
  invalid_folder TEXT NOT NULL DEFAULT 'DMARC-Invalid',
  interval_minutes INT NOT NULL DEFAULT 60 CHECK (interval_minutes BETWEEN 15 AND 1440),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS monitored_domains (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE CHECK (name <> '' AND name = lower(name)),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);

-- Which mailbox a run read (NULL: environment-configured run or an import),
-- and what started it.
ALTER TABLE ingest_runs ADD COLUMN IF NOT EXISTS mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE SET NULL;
ALTER TABLE ingest_runs ADD COLUMN IF NOT EXISTS trigger TEXT NOT NULL DEFAULT 'environment'
  CHECK (trigger IN ('environment', 'schedule', 'manual'));
CREATE INDEX IF NOT EXISTS ingest_runs_mailbox_idx ON ingest_runs (mailbox_id, started_at DESC);

-- Requests from the panel that only the worker can carry out ("Test
-- connection", "Run now"): the web app never opens a mailbox itself.
CREATE TABLE IF NOT EXISTS worker_jobs (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('test', 'run')),
  mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
  requested_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  claimed_by TEXT,
  claimed_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  result JSONB                          -- {ok, message}: never a secret
);
CREATE INDEX IF NOT EXISTS worker_jobs_queue_idx ON worker_jobs (requested_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS worker_jobs_mailbox_idx ON worker_jobs (mailbox_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
  worker_id TEXT PRIMARY KEY,
  hostname TEXT,
  version TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
