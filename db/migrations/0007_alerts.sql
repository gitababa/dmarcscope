-- 2.0 milestone 5: alert rules, channels, events and the delivery outbox.
-- Everything here is read and written by the web app only (lib/alerts/).

CREATE TABLE IF NOT EXISTS alert_channels (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL CHECK (name <> '' AND length(name) <= 100),
  kind TEXT NOT NULL CHECK (kind IN ('email', 'webhook', 'slack')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,   -- not secret: the recipients of an email channel
  secret TEXT,                                  -- envelope, purpose 'alert', context 'alert:<id>': webhook URL (and signing secret)
  secret_updated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS alert_rules (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL CHECK (name <> '' AND length(name) <= 100),
  kind TEXT NOT NULL CHECK (kind IN ('new_failing_source', 'compliance_drop', 'ingest_stale', 'dns_changed')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  domain TEXT CHECK (domain IS NULL OR domain = lower(domain)),   -- NULL: every domain
  params JSONB NOT NULL DEFAULT '{}'::jsonb,
  quiet_minutes INT NOT NULL DEFAULT 1440 CHECK (quiet_minutes BETWEEN 60 AND 10080),
  notify_resolved BOOLEAN NOT NULL DEFAULT FALSE,
  last_evaluated_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS alert_rule_channels (
  rule_id BIGINT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
  channel_id BIGINT NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, channel_id)
);

CREATE TABLE IF NOT EXISTS alert_events (
  id BIGSERIAL PRIMARY KEY,
  rule_id BIGINT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
  dedupe_key TEXT NOT NULL,
  domain TEXT,
  state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved')),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  last_notified_at TIMESTAMPTZ,
  reminders_sent INT NOT NULL DEFAULT 0,
  summary TEXT NOT NULL,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb
);
-- Deduplication as a database fact: one open event per rule and condition.
CREATE UNIQUE INDEX IF NOT EXISTS alert_events_open_idx ON alert_events (rule_id, dedupe_key) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS alert_events_recent_idx ON alert_events (first_seen_at DESC);

-- The outbox and the delivery history. event_id is NULL for a test.
CREATE TABLE IF NOT EXISTS alert_deliveries (
  id BIGSERIAL PRIMARY KEY,
  event_id BIGINT REFERENCES alert_events(id) ON DELETE CASCADE,
  channel_id BIGINT NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('alert', 'reminder', 'resolved', 'test')),
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'failed')),
  attempts INT NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  error TEXT,
  requested_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS alert_deliveries_queue_idx ON alert_deliveries (next_attempt_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS alert_deliveries_channel_idx ON alert_deliveries (channel_id, created_at DESC);

-- When the evaluator last ran (one row), for the panel.
CREATE TABLE IF NOT EXISTS alert_evaluator (
  id INT PRIMARY KEY CHECK (id = 1),
  last_started_at TIMESTAMPTZ,
  last_finished_at TIMESTAMPTZ,
  last_error TEXT
);
INSERT INTO alert_evaluator (id) VALUES (1) ON CONFLICT DO NOTHING;
