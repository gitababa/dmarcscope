-- Mailboxes set up in the panel, without a long-running worker (Vercel), and
-- the domains found in reports.

-- A heartbeat is written by the long-running worker ('serve') and, for its
-- duration only, by a one-off pass ('pass': the Vercel function). Both keep
-- the jobs they hold from being failed as abandoned; only 'serve' workers
-- count as "a worker is running" in the panel.
ALTER TABLE worker_heartbeats ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'serve'
  CHECK (mode IN ('serve', 'pass'));

-- One-off passes (ingestor/oneshot.py): 'schedule' when a scheduler called
-- (Vercel Cron, or any other with the machine token), 'request' when the web
-- app started one for "Test connection", "Run now" or a newly monitored
-- domain. The panel shows how often scheduled passes actually happen.
CREATE TABLE IF NOT EXISTS ingest_passes (
  id BIGSERIAL PRIMARY KEY,
  trigger TEXT NOT NULL CHECK (trigger IN ('schedule', 'request')),
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  summary JSONB                         -- counts and short reasons; never message content
);
CREATE INDEX IF NOT EXISTS ingest_passes_trigger_idx ON ingest_passes (trigger, started_at DESC);

-- Every domain a report was about, monitored or not: what the panel offers
-- to monitor. base_domain is the registrable domain (public suffix list),
-- NULL when not known yet.
CREATE TABLE IF NOT EXISTS discovered_domains (
  name TEXT PRIMARY KEY CHECK (name <> '' AND name = lower(name) AND length(name) <= 253),
  base_domain TEXT CHECK (base_domain IS NULL OR (base_domain = lower(base_domain) AND length(base_domain) <= 253)),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reports_seen INT NOT NULL DEFAULT 0
);

-- Domains that already have reports.
INSERT INTO discovered_domains (name, reports_seen, first_seen_at, last_seen_at)
SELECT d.name, COUNT(r.id)::int, COALESCE(MIN(r.received_at), d.created_at), COALESCE(MAX(r.received_at), d.created_at)
FROM domains d LEFT JOIN reports r ON r.domain_id = d.id
WHERE d.name <> '' AND d.name = lower(d.name) AND length(d.name) <= 253
GROUP BY d.name, d.created_at
ON CONFLICT (name) DO NOTHING;

-- Reports about domains nobody monitors yet, held for 14 days (purged by the
-- worker): switching monitoring on for a domain imports them. Bounded in size
-- by the worker (anyone can email a report about any domain).
CREATE TABLE IF NOT EXISTS held_reports (
  id BIGSERIAL PRIMARY KEY,
  domain TEXT NOT NULL,
  org_name TEXT NOT NULL,
  report_id TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  report JSONB NOT NULL,
  UNIQUE (domain, org_name, report_id)
);
CREATE INDEX IF NOT EXISTS held_reports_received_idx ON held_reports (received_at);
