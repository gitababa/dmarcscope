-- 2.0 milestone 2: managing people in the panel.

-- An invitation is a pending users row with an assigned role and invited_at
-- set; it becomes active on that person's first sign-in. A pending row
-- without invited_at is a request from someone no rule admitted.
ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by BIGINT REFERENCES users(id) ON DELETE SET NULL;

-- The audit log viewer filters by action and by who acted, newest first.
CREATE INDEX IF NOT EXISTS audit_log_action_idx ON audit_log (action, id DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log (lower(actor_email), id DESC);
