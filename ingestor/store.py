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

_INT4_MAX = 2_147_483_647


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


def _bool_alignment(alignment: dict, policy_eval: dict, key: str) -> bool:
    if key in alignment:
        return bool(alignment.get(key))
    return policy_eval.get(key) == "pass"


def insert_aggregate_report(conn: psycopg.Connection, report: dict, settings: Settings) -> str:
    """Insert one aggregate report and its records in the current transaction.

    Returns STORED, DUPLICATE (already ingested — reports are identified by
    domain + reporting org + report id) or FILTERED (not for an allowed
    domain, outside the retention window, or missing required fields).
    The caller commits or rolls back.
    """
    meta = report.get("report_metadata") or {}
    policy = report.get("policy_published") or {}
    domain_name = str(policy.get("domain") or "").strip().lower().rstrip(".")
    if not domain_name or len(domain_name) > 253:
        return FILTERED
    if settings.allowed_domains is not None and domain_name not in settings.allowed_domains:
        return FILTERED

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
            (domain_id, org_name, _text(meta.get("org_email"), 320), report_id, begin, end, json.dumps(policy)),
        )
        row = cur.fetchone()
        if row is None:
            return DUPLICATE
        report_row_id = row[0]

        record_rows = []
        ip_rows: dict[str, tuple] = {}
        for r in report.get("records") or []:
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
                    json.dumps(auth.get("dkim") or []),
                    json.dumps(auth.get("spf") or []),
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


def start_run(conn: psycopg.Connection, stale_after_seconds: int) -> int | None:
    """Record the start of a run. Returns None if another run is in progress.

    A run counts as in progress if it has not finished and started less than
    stale_after_seconds ago (older ones are assumed to have crashed). This is a
    plain-SQL guard rather than an advisory lock so that it also works through
    transaction-mode connection poolers.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ingest_runs (started_at)
            SELECT NOW()
            WHERE NOT EXISTS (
                SELECT 1 FROM ingest_runs
                WHERE finished_at IS NULL
                  AND started_at > NOW() - make_interval(secs => %s)
            )
            RETURNING id
            """,
            (stale_after_seconds,),
        )
        row = cur.fetchone()
    conn.commit()
    return row[0] if row else None


def finish_run(conn: psycopg.Connection, run_id: int, stats: dict) -> None:
    # Keep the stored error list small; full detail goes to the logs.
    errors = [
        {k: str(v)[:500] for k, v in e.items()} if isinstance(e, dict) else {"error": str(e)[:500]}
        for e in stats.get("errors", [])[:50]
    ]
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE ingest_runs
            SET finished_at = NOW(), messages_fetched = %s, reports_parsed = %s, reports_skipped = %s, errors = %s
            WHERE id = %s
            """,
            (
                stats.get("fetched", 0),
                stats.get("stored", 0),
                stats.get("skipped", 0) + stats.get("invalid", 0),
                json.dumps(errors) if errors else None,
                run_id,
            ),
        )
    conn.commit()
