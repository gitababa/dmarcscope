-- 1. ingest_runs.failed: a run that ended on a fatal error (mailbox or
--    database unreachable), as opposed to one that finished with a few
--    unreadable messages. Lets the dashboard and /api/cron/status tell
--    "ingest is working" from "ingest runs but achieves nothing".
ALTER TABLE ingest_runs ADD COLUMN IF NOT EXISTS failed BOOLEAN NOT NULL DEFAULT FALSE;

-- 2. Per-record flags the Issues page used to compute by unpacking two JSONB
--    arrays for every row on every page load. As generated columns they are
--    computed once, at insert, by the database itself (so the ingest worker
--    needs no change and existing rows are filled in by this statement).
--      dkim_sig_valid: some DKIM signature verified, for whatever domain
--      spf_raw_pass:   SPF passed, for whatever envelope domain
ALTER TABLE records
  ADD COLUMN IF NOT EXISTS dkim_sig_valid BOOLEAN
    GENERATED ALWAYS AS (COALESCE(jsonb_path_exists(dkim_results, '$[*] ? (@.result == "pass")'), FALSE)) STORED,
  ADD COLUMN IF NOT EXISTS spf_raw_pass BOOLEAN
    GENERATED ALWAYS AS (COALESCE(jsonb_path_exists(spf_results, '$[*] ? (@.result == "pass")'), FALSE)) STORED;
