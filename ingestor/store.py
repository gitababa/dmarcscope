"""PostgreSQL persistence for parsed reports."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import psycopg

from .config import Settings

STORED = "stored"
DUPLICATE = "duplicate"
FILTERED = "filtered"
# About a domain nobody monitors: held for a while instead (hold_report).
NOT_MONITORED = "not_monitored"

_INT4_MAX = 2_147_483_647

# Bounds on what one report may write. A report is an email from a stranger:
# without these, one message could add millions of rows or megabytes of JSON.
MAX_RECORDS_PER_REPORT = 50_000
MAX_AUTH_RESULTS = 20  # DKIM / SPF results kept per record
MAX_JSON_KEYS = 24

# Arbitrary constant identifying this application's "start an ingest run" lock.
_RUN_LOCK_KEY = 4117230902


def connect(settings: Settings) -> psycopg.Connection:
    # Nothing here depends on session state (every timestamp is passed with an
    # explicit UTC offset), so transaction-mode poolers such as PgBouncer work.
    return psycopg.connect(settings.database_url, autocommit=False)


def _parse_ts(value: Any) -> dt.datetime | None:
    """parsedmarc timestamps are 'YYYY-MM-DD HH:MM:SS' in UTC."""
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value)).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _text(value: Any, limit: int = 1000) -> str | None:
    if value is None:
        return None
    # NUL bytes are not storable in PostgreSQL text.
    return str(value).replace("\x00", "")[:limit] or None


def _json_object(value: Any) -> dict:
    """A flat, size-bounded copy of a parsed JSON object: scalar values only,
    strings cut to 255 characters, at most MAX_JSON_KEYS keys."""
    out: dict = {}
    if not isinstance(value, dict):
        return out
    for key, val in list(value.items())[:MAX_JSON_KEYS]:
        if isinstance(val, (bool, int, float)) or val is None:
            out[str(key)[:64]] = val
        elif isinstance(val, str):
            out[str(key)[:64]] = val.replace("\x00", "")[:255]
    return out


def _json_list(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [_json_object(item) for item in value[:MAX_AUTH_RESULTS] if isinstance(item, dict)]


def _bool_alignment(alignment: dict, policy_eval: dict, key: str) -> bool:
    if key in alignment:
        return bool(alignment.get(key))
    return policy_eval.get(key) == "pass"


def insert_aggregate_report(conn: psycopg.Connection, report: dict, settings: Settings) -> str:
    """Insert one aggregate report and its records in the current transaction.

    Returns STORED, DUPLICATE (already ingested — reports are identified by
    domain + reporting org + report id), NOT_MONITORED (about a domain that is
    not monitored) or FILTERED (outside the retention window, or missing
    required fields).
    The caller commits or rolls back.
    """
    meta = report.get("report_metadata") or {}
    policy = report.get("policy_published") or {}
    domain_name = str(policy.get("domain") or "").strip().lower().rstrip(".")
    if not domain_name or len(domain_name) > 253:
        return FILTERED
    if settings.allowed_domains is not None and domain_name not in settings.allowed_domains:
        return NOT_MONITORED

    org_name = _text(meta.get("org_name"), 255) or "unknown"
    report_id = _text(meta.get("report_id"), 255)
    begin = _parse_ts(meta.get("begin_date"))
    end = _parse_ts(meta.get("end_date"))
    if not report_id or begin is None or end is None:
        return FILTERED

    cutoff = settings.cutoff
    if cutoff is not None and end < cutoff:
        return FILTERED

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO domains (name) VALUES (%s)
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            """,
            (domain_name,),
        )
        domain_id = cur.fetchone()[0]

        cur.execute(
            """
            INSERT INTO reports (domain_id, org_name, org_email, report_id, begin_date, end_date, policy_published)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (domain_id, org_name, report_id) DO NOTHING
            RETURNING id
            """,
            (domain_id, org_name, _text(meta.get("org_email"), 320), report_id, begin, end, json.dumps(_json_object(policy))),
        )
        row = cur.fetchone()
        if row is None:
            return DUPLICATE
        report_row_id = row[0]

        record_rows = []
        ip_rows: dict[str, tuple] = {}
        for r in (report.get("records") or [])[:MAX_RECORDS_PER_REPORT]:
            source = r.get("source") or {}
            ip = str(source.get("ip_address") or "").split("/")[0].strip()
            if not ip:
                continue

            policy_eval = r.get("policy_evaluated") or {}
            alignment = r.get("alignment") or {}
            identifiers = r.get("identifiers") or {}
            auth = r.get("auth_results") or {}

            dkim_aligned = _bool_alignment(alignment, policy_eval, "dkim")
            spf_aligned = _bool_alignment(alignment, policy_eval, "spf")
            dmarc_aligned = bool(alignment.get("dmarc")) if "dmarc" in alignment else (dkim_aligned or spf_aligned)

            try:
                count = max(0, min(int(r.get("count") or 0), _INT4_MAX))
            except (TypeError, ValueError):
                count = 0

            record_rows.append(
                (
                    report_row_id,
                    domain_id,
                    ip,
                    count,
                    _text(policy_eval.get("disposition"), 32),
                    dkim_aligned,
                    spf_aligned,
                    dmarc_aligned,
                    _text(identifiers.get("header_from"), 255),
                    _text(identifiers.get("envelope_from"), 255),
                    _text(identifiers.get("envelope_to"), 255),
                    json.dumps(_json_list(auth.get("dkim"))),
                    json.dumps(_json_list(auth.get("spf"))),
                    _parse_ts(r.get("interval_begin")) or begin,
                    _parse_ts(r.get("interval_end")) or end,
                )
            )
            asn = source.get("asn")
            ip_rows[ip] = (
                ip,
                _text(source.get("reverse_dns"), 255),
                _text(source.get("base_domain"), 255),
                _text(source.get("country"), 8),
                int(asn) if isinstance(asn, int) or (isinstance(asn, str) and asn.isdigit()) else None,
                _text(source.get("as_name"), 255),
                _text(source.get("as_domain"), 255),
                _text(source.get("name"), 255),
                _text(source.get("type"), 64),
            )

        if record_rows:
            cur.executemany(
                """
                INSERT INTO records (
                    report_id, domain_id, source_ip, message_count, disposition,
                    dkim_aligned, spf_aligned, dmarc_aligned,
                    header_from, envelope_from, envelope_to,
                    dkim_results, spf_results, period_start, period_end
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                record_rows,
            )
        if ip_rows:
            cur.executemany(
                """
                INSERT INTO ip_metadata (
                    ip, reverse_dns, base_domain, country, asn, as_name, as_domain, provider_name, provider_type
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (ip) DO UPDATE SET
                    reverse_dns = COALESCE(EXCLUDED.reverse_dns, ip_metadata.reverse_dns),
                    base_domain = COALESCE(EXCLUDED.base_domain, ip_metadata.base_domain),
                    country = COALESCE(EXCLUDED.country, ip_metadata.country),
                    asn = COALESCE(EXCLUDED.asn, ip_metadata.asn),
                    as_name = COALESCE(EXCLUDED.as_name, ip_metadata.as_name),
                    as_domain = COALESCE(EXCLUDED.as_domain, ip_metadata.as_domain),
                    provider_name = COALESCE(EXCLUDED.provider_name, ip_metadata.provider_name),
                    provider_type = COALESCE(EXCLUDED.provider_type, ip_metadata.provider_type),
                    last_seen_at = NOW()
                """,
                # Sorted so concurrent writers always lock rows in the same order.
                [ip_rows[k] for k in sorted(ip_rows)],
            )
    return STORED


def apply_retention(conn: psycopg.Connection, settings: Settings) -> int:
    """Delete reports past the retention cutoff (records cascade)."""
    purged = 0
    with conn.cursor() as cur:
        cutoff = settings.cutoff
        if cutoff is not None:
            cur.execute("DELETE FROM reports WHERE end_date < %s", (cutoff,))
            purged = cur.rowcount
            # IPs that no remaining record refers to.
            cur.execute(
                "DELETE FROM ip_metadata m WHERE NOT EXISTS (SELECT 1 FROM records r WHERE r.source_ip = m.ip)"
            )
        cur.execute("DELETE FROM ingest_runs WHERE started_at < NOW() - INTERVAL '180 days'")
    conn.commit()
    return purged


def start_run(
    conn: psycopg.Connection,
    stale_after_seconds: int,
    mailbox_id: int | None = None,
    trigger: str = "environment",
) -> int | None:
    """Record the start of a run. Returns None if another run is in progress.

    Runs of the environment-configured mailbox (mailbox_id None) exclude each
    other; a mailbox configured in the panel only excludes runs of itself
    (and is additionally guarded by its advisory lock in serve mode).

    A run counts as in progress if it has not finished and started less than
    stale_after_seconds ago (older ones are assumed to have crashed). The row
    is the guard, so it holds for the whole run even through a transaction-mode
    connection pooler; the advisory lock only makes "check, then insert" atomic
    when two runs start at the same instant, and is released at commit.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (_RUN_LOCK_KEY,))
        cur.execute(
            """
            INSERT INTO ingest_runs (started_at, mailbox_id, trigger)
            SELECT NOW(), %s, %s
            WHERE NOT EXISTS (
                SELECT 1 FROM ingest_runs
                WHERE finished_at IS NULL
                  AND mailbox_id IS NOT DISTINCT FROM %s
                  AND started_at > NOW() - make_interval(secs => %s)
            )
            RETURNING id
            """,
            (mailbox_id, trigger, mailbox_id, stale_after_seconds),
        )
        row = cur.fetchone()
    conn.commit()
    return row[0] if row else None


def finish_run(conn: psycopg.Connection, run_id: int, stats: dict, failed: bool = False) -> None:
    # Keep the stored error list small; full detail goes to the logs.
    errors = [
        {k: str(v)[:500] for k, v in e.items()} if isinstance(e, dict) else {"error": str(e)[:500]}
        for e in stats.get("errors", [])[:50]
    ]
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE ingest_runs
            SET finished_at = NOW(), messages_fetched = %s, reports_parsed = %s, reports_skipped = %s,
                errors = %s, failed = %s
            WHERE id = %s
            """,
            (
                stats.get("fetched", 0),
                stats.get("stored", 0),
                stats.get("skipped", 0) + stats.get("invalid", 0),
                json.dumps(errors) if errors else None,
                failed,
                run_id,
            ),
        )
    conn.commit()


# ---------- the panel's mailboxes, monitored domains, jobs ----------

# Advisory lock keys: (class, object) pairs, so they cannot collide with the
# single-key locks above. Class 1: "a run of mailbox <id> is active", held for
# the whole run on the worker's lock connection; class 2: housekeeping.
_MAILBOX_LOCK_CLASS = 41172309
_HOUSEKEEPING_LOCK = (41172310, 0)


def try_lock_mailbox(lock_conn: psycopg.Connection, mailbox_id: int) -> bool:
    with lock_conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s, %s)", (_MAILBOX_LOCK_CLASS, mailbox_id))
        return bool(cur.fetchone()[0])


def unlock_mailbox(lock_conn: psycopg.Connection, mailbox_id: int) -> None:
    with lock_conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_unlock(%s, %s)", (_MAILBOX_LOCK_CLASS, mailbox_id))


def try_lock_housekeeping(lock_conn: psycopg.Connection) -> bool:
    with lock_conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s, %s)", _HOUSEKEEPING_LOCK)
        return bool(cur.fetchone()[0])


def unlock_housekeeping(lock_conn: psycopg.Connection) -> None:
    with lock_conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_unlock(%s, %s)", _HOUSEKEEPING_LOCK)


def close_orphaned_runs(conn: psycopg.Connection, mailbox_id: int) -> int:
    """Call while holding the mailbox's lock: any run of it still open belongs
    to a worker that died (its lock went with its connection). Closed as
    failed, so the history shows what happened and the next run proceeds."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE ingest_runs
            SET finished_at = NOW(), failed = TRUE,
                errors = COALESCE(errors, '[]'::jsonb) || '[{"error": "interrupted: the worker stopped during this run"}]'::jsonb
            WHERE mailbox_id = %s AND finished_at IS NULL
            """,
            (mailbox_id,),
        )
        closed = cur.rowcount
    conn.commit()
    return closed


def heartbeat(conn: psycopg.Connection, worker_id: str, hostname: str, version: str, mode: str = "serve") -> None:
    """mode: 'serve' (the long-running worker) or 'pass' (a one-off pass,
    which beats only while it runs; the panel does not count it as a worker)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO worker_heartbeats (worker_id, hostname, version, mode) VALUES (%s, %s, %s, %s)
            ON CONFLICT (worker_id) DO UPDATE SET seen_at = NOW()
            """,
            (worker_id, hostname[:200], version[:50], mode),
        )
        # Forget workers gone for a day.
        cur.execute("DELETE FROM worker_heartbeats WHERE seen_at < NOW() - INTERVAL '1 day'")
    conn.commit()


def remove_heartbeat(conn: psycopg.Connection, worker_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM worker_heartbeats WHERE worker_id = %s", (worker_id,))
    conn.commit()


def fail_abandoned_jobs(conn: psycopg.Connection, alive_seconds: int) -> int:
    """Jobs left "running" by a worker that is no longer alive."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE worker_jobs SET status = 'failed', finished_at = NOW(),
                result = '{"ok": false, "message": "The worker stopped before finishing this."}'::jsonb
            WHERE status = 'running'
              AND claimed_by NOT IN (SELECT worker_id FROM worker_heartbeats WHERE seen_at > NOW() - make_interval(secs => %s))
            """,
            (alive_seconds,),
        )
        n = cur.rowcount
    conn.commit()
    return n


def claim_job_by_id(conn: psycopg.Connection, worker_id: str, job_id: int) -> dict | None:
    """That job, if it is still queued, marked as ours. None if another worker
    took it first (or it does not exist)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE worker_jobs SET status = 'running', claimed_by = %s, claimed_at = NOW()
            WHERE id = (SELECT id FROM worker_jobs WHERE id = %s AND status = 'queued' FOR UPDATE SKIP LOCKED)
            RETURNING id, kind, mailbox_id
            """,
            (worker_id, job_id),
        )
        row = cur.fetchone()
    conn.commit()
    return {"id": row[0], "kind": row[1], "mailbox_id": row[2]} if row else None


def claim_job(conn: psycopg.Connection, worker_id: str) -> dict | None:
    """The oldest queued job, marked as ours. SKIP LOCKED: two workers never
    take the same job."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE worker_jobs SET status = 'running', claimed_by = %s, claimed_at = NOW()
            WHERE id = (
                SELECT id FROM worker_jobs WHERE status = 'queued' ORDER BY requested_at, id
                FOR UPDATE SKIP LOCKED LIMIT 1
            )
            RETURNING id, kind, mailbox_id
            """,
            (worker_id,),
        )
        row = cur.fetchone()
    conn.commit()
    return {"id": row[0], "kind": row[1], "mailbox_id": row[2]} if row else None


def finish_job(conn: psycopg.Connection, job_id: int, ok: bool, message: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE worker_jobs SET status = %s, finished_at = NOW(), result = %s WHERE id = %s",
            ("done" if ok else "failed", json.dumps({"ok": ok, "message": message[:500]}), job_id),
        )
    conn.commit()


MAILBOX_COLUMNS = (
    "id, name, kind, enabled, host, port, security, username, tenant_id, client_id, secret, "
    "folder, processed_folder, invalid_folder, interval_minutes"
)


def load_mailbox(conn: psycopg.Connection, mailbox_id: int) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {MAILBOX_COLUMNS} FROM mailboxes WHERE id = %s", (mailbox_id,))
        row = cur.fetchone()
        names = [d.name for d in cur.description]
    conn.commit()
    return dict(zip(names, row)) if row else None


def due_mailboxes(conn: psycopg.Connection) -> list[int]:
    """Enabled mailboxes whose interval has passed since their last run
    started (or that never ran), most overdue first."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT m.id FROM mailboxes m
            LEFT JOIN LATERAL (
                SELECT MAX(started_at) AS last FROM ingest_runs r WHERE r.mailbox_id = m.id
            ) l ON TRUE
            WHERE m.enabled
              AND (l.last IS NULL OR l.last <= NOW() - make_interval(mins => m.interval_minutes))
            ORDER BY l.last NULLS FIRST, m.id
            """
        )
        ids = [r[0] for r in cur.fetchall()]
    conn.commit()
    return ids


def db_monitored_domains(conn: psycopg.Connection) -> frozenset[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT name FROM monitored_domains")
        names = frozenset(r[0] for r in cur.fetchall())
    conn.commit()
    return names


def db_setting(conn: psycopg.Connection, key: str):
    """A non-secret setting saved in the panel (lib/settings), or None."""
    with conn.cursor() as cur:
        cur.execute("SELECT value, is_secret FROM settings WHERE key = %s", (key,))
        row = cur.fetchone()
    conn.commit()
    if not row or row[1]:
        return None
    return row[0]


# ---------- domains found in reports, and reports held for them ----------

# Anyone can email a report about any domain: what is kept for domains
# nobody monitors is bounded.
MAX_DISCOVERED = 1000
HELD_DAYS = 14
MAX_HELD = 1000
MAX_HELD_PER_DOMAIN = 100
MAX_HELD_BYTES = 256 * 1024


def note_domain(conn: psycopg.Connection, name: str, base_domain: str | None, monitored: bool) -> None:
    """Count a report about `name`. A domain not yet listed is added only
    while the list is under MAX_DISCOVERED, unless it is monitored. In the
    caller's transaction."""
    name = name.strip().lower().rstrip(".")
    if not name or len(name) > 253:
        return
    base = base_domain.lower()[:253] if base_domain else None
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO discovered_domains (name, base_domain, reports_seen)
            SELECT %s, %s, 1
            WHERE %s OR (SELECT COUNT(*) FROM discovered_domains) < %s
            ON CONFLICT (name) DO UPDATE
              SET reports_seen = discovered_domains.reports_seen + 1,
                  last_seen_at = NOW(),
                  base_domain = COALESCE(EXCLUDED.base_domain, discovered_domains.base_domain)
            """,
            (name, base, monitored, MAX_DISCOVERED),
        )


def hold_report(conn: psycopg.Connection, report: dict) -> bool:
    """Keep a report about a domain nobody monitors, for HELD_DAYS. False if it
    was not kept (too large, over a limit, or held already). In the caller's
    transaction."""
    meta = report.get("report_metadata") or {}
    policy = report.get("policy_published") or {}
    domain = str(policy.get("domain") or "").strip().lower().rstrip(".")
    org_name = _text(meta.get("org_name"), 255) or "unknown"
    report_id = _text(meta.get("report_id"), 255)
    if not domain or len(domain) > 253 or not report_id:
        return False
    body = json.dumps(report, default=str)
    if len(body.encode()) > MAX_HELD_BYTES:
        return False
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO held_reports (domain, org_name, report_id, report)
            SELECT %s, %s, %s, %s::jsonb
            WHERE (SELECT COUNT(*) FROM held_reports) < %s
              AND (SELECT COUNT(*) FROM held_reports WHERE domain = %s) < %s
            ON CONFLICT (domain, org_name, report_id) DO NOTHING
            """,
            (domain, org_name, report_id, body, MAX_HELD, domain, MAX_HELD_PER_DOMAIN),
        )
        return cur.rowcount == 1


def has_releasable(conn: psycopg.Connection) -> bool:
    """Whether a held report is about a domain monitored in the panel."""
    with conn.cursor() as cur:
        cur.execute("SELECT EXISTS (SELECT 1 FROM held_reports h JOIN monitored_domains m ON m.name = h.domain)")
        found = bool(cur.fetchone()[0])
    conn.commit()
    return found


def purge_held(conn: psycopg.Connection) -> int:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM held_reports WHERE received_at < NOW() - make_interval(days => %s)", (HELD_DAYS,))
        n = cur.rowcount
    conn.commit()
    return n


def release_held(conn: psycopg.Connection, settings: Settings) -> int:
    """Import the held reports of domains that are monitored now. Returns the
    number stored. Each report in its own transaction."""
    if settings.allowed_domains is None:
        names = None
    else:
        names = sorted(settings.allowed_domains)
        if not names:
            return 0
    with conn.cursor() as cur:
        if names is None:
            cur.execute("SELECT id, report FROM held_reports ORDER BY id LIMIT 500")
        else:
            cur.execute("SELECT id, report FROM held_reports WHERE domain = ANY(%s) ORDER BY id LIMIT 500", (names,))
        rows = cur.fetchall()
    conn.commit()
    stored = 0
    for held_id, report in rows:
        try:
            outcome = insert_aggregate_report(conn, report if isinstance(report, dict) else json.loads(report), settings)
            with conn.cursor() as cur:
                cur.execute("DELETE FROM held_reports WHERE id = %s", (held_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        if outcome == STORED:
            stored += 1
    return stored


def start_pass(conn: psycopg.Connection, trigger: str) -> int:
    with conn.cursor() as cur:
        cur.execute("INSERT INTO ingest_passes (trigger) VALUES (%s) RETURNING id", (trigger,))
        pass_id = cur.fetchone()[0]
        # Keep the last few hundred.
        cur.execute(
            "DELETE FROM ingest_passes WHERE id < (SELECT MIN(id) FROM (SELECT id FROM ingest_passes ORDER BY id DESC LIMIT 300) t)"
        )
    conn.commit()
    return pass_id


def finish_pass(conn: psycopg.Connection, pass_id: int, summary: dict) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE ingest_passes SET finished_at = NOW(), summary = %s WHERE id = %s",
            (json.dumps(summary, default=str), pass_id),
        )
    conn.commit()
