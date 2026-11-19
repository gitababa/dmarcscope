-- Run history used to keep parsedmarc's error text for messages that are not
-- reports, and that text names each message by its Subject header. A mailbox
-- that also receives other mail would leave those subjects here. The worker
-- no longer stores them (ingestor/runner.py, invalid_reason); this removes
-- the ones already stored. Other errors are left as they are.
UPDATE ingest_runs r
SET errors = (
  SELECT jsonb_agg(
    CASE
      WHEN jsonb_typeof(t.e) = 'object' AND (t.e ->> 'error') ILIKE '%subject%'
        THEN jsonb_set(t.e, '{error}', to_jsonb('not a DMARC report (details removed: they named the message by its subject)'::text))
      ELSE t.e
    END
    ORDER BY t.ord
  )
  FROM jsonb_array_elements(r.errors) WITH ORDINALITY AS t(e, ord)
)
WHERE jsonb_typeof(r.errors) = 'array'
  AND jsonb_array_length(r.errors) > 0
  AND r.errors::text ILIKE '%subject%';
