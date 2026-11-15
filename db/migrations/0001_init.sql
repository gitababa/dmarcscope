-- DMARCscope initial schema.
-- Applied by `npm run db:migrate` (scripts/migrate.mjs), which records each
-- file in schema_migrations. Every statement is idempotent.

CREATE TABLE IF NOT EXISTS domains (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
  id SERIAL PRIMARY KEY,
  domain_id INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  org_name TEXT NOT NULL,
  org_email TEXT,
  report_id TEXT NOT NULL,
  begin_date TIMESTAMPTZ NOT NULL,
  end_date TIMESTAMPTZ NOT NULL,
  policy_published JSONB NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (domain_id, org_name, report_id)
);

CREATE INDEX IF NOT EXISTS reports_domain_end_idx ON reports (domain_id, end_date DESC);
CREATE INDEX IF NOT EXISTS reports_end_idx ON reports (end_date);

CREATE TABLE IF NOT EXISTS records (
  id BIGSERIAL PRIMARY KEY,
  report_id INT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  domain_id INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  source_ip INET NOT NULL,
  message_count INT NOT NULL,
  disposition TEXT,
  dkim_aligned BOOLEAN NOT NULL DEFAULT FALSE,
  spf_aligned BOOLEAN NOT NULL DEFAULT FALSE,
  dmarc_aligned BOOLEAN NOT NULL DEFAULT FALSE,
  header_from TEXT,
  envelope_from TEXT,
  envelope_to TEXT,
  dkim_results JSONB,
  spf_results JSONB,
  period_start TIMESTAMPTZ NOT NULL,
  period_end TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS records_report_idx ON records (report_id);
CREATE INDEX IF NOT EXISTS records_domain_period_idx ON records (domain_id, period_end DESC);
CREATE INDEX IF NOT EXISTS records_period_idx ON records (period_end DESC);
CREATE INDEX IF NOT EXISTS records_source_ip_idx ON records (source_ip);
CREATE INDEX IF NOT EXISTS records_alignment_idx ON records (domain_id, dmarc_aligned, period_end DESC);

-- One row per sending IP. reverse_dns is filled in by the ingest worker's
-- enrichment pass ('unresolved' is its negative-cache marker); the ASN and
-- provider columns come from the worker's bundled offline IP database.
CREATE TABLE IF NOT EXISTS ip_metadata (
  ip INET PRIMARY KEY,
  reverse_dns TEXT,
  base_domain TEXT,
  country TEXT,
  asn BIGINT,
  as_name TEXT,
  as_domain TEXT,
  provider_name TEXT,
  provider_type TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ingest_runs (
  id BIGSERIAL PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  messages_fetched INT NOT NULL DEFAULT 0,
  reports_parsed INT NOT NULL DEFAULT 0,
  reports_skipped INT NOT NULL DEFAULT 0,
  errors JSONB
);

CREATE INDEX IF NOT EXISTS ingest_runs_started_idx ON ingest_runs (started_at DESC);

CREATE TABLE IF NOT EXISTS dns_checks (
  id BIGSERIAL PRIMARY KEY,
  domain_id INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  results JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS dns_checks_domain_idx ON dns_checks (domain_id, checked_at DESC);
