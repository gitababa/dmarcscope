"""Orchestration: mailbox or files -> parse -> store -> enrich."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import psycopg

from . import enrich, mailbox, store
from .config import Settings
from .parsing import InvalidDMARCReport, ParserError, parse_email, parse_file

log = logging.getLogger("ingestor")

REPORT_SUFFIXES = {".xml", ".gz", ".zip", ".eml", ".msg"}


def _new_stats() -> dict:
    """The counters every command reports. This is the JSON printed on stdout
    (docs/configuration.md); keep the two in step."""
    return {
        "fetched": 0,  # messages / files looked at
        "stored": 0,  # new aggregate reports written
        "skipped": 0,  # duplicates, filtered-out domains, non-aggregate reports
        "invalid": 0,  # not a DMARC report at all
        "enriched": 0,  # IPs given a reverse-DNS name
        "purged": 0,  # reports deleted by retention
        "drained": False,  # run only: the mailbox was emptied
        "already_running": False,  # run only: another run held the slot; nothing was done
        "errors": [],  # one entry per message / file that could not be processed
    }


def _connection_lost(conn) -> bool:
    """The database connection itself is unusable: no later statement can
    work. (Judged from the connection, not the exception class — a deadlock or
    a cancelled statement is also an OperationalError, and is retryable.)"""
    return bool(conn.closed or conn.broken)


def _record_finish(conn, settings: Settings, run_id: int, stats: dict, failed: bool) -> None:
    """Close the run row, whatever state the connection was left in. Never
    raises: this runs while another exception may be on its way out, and that
    one is the error worth reporting."""
    try:
        conn.rollback()  # clear an aborted transaction, if any
        store.finish_run(conn, run_id, stats, failed)
        return
    except Exception:  # noqa: BLE001
        log.warning("could not record the end of run %s on the open connection; retrying on a new one", run_id)
    try:
        fresh = store.connect(settings)
        try:
            store.finish_run(fresh, run_id, stats, failed)
        finally:
            fresh.close()
    except Exception:  # noqa: BLE001
        log.exception("could not record the end of run %s; it will show as unfinished", run_id)


def _store_parsed(conn, parsed: dict, settings: Settings, stats: dict) -> None:
    """Store one parsed report in its own transaction."""
    report = parsed.get("report")
    if parsed.get("report_type") != "aggregate" or not report:
        # Failure (forensic) and SMTP TLS reports are not stored: failure
        # reports carry message samples with personal data.
        stats["skipped"] += 1
        return
    try:
        outcome = store.insert_aggregate_report(conn, report, settings)
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except psycopg.Error:
            pass  # connection gone; the original error is the one to report
        raise
    if outcome == store.STORED:
        stats["stored"] += 1
    else:
        stats["skipped"] += 1


def run_ingest(settings: Settings) -> dict:
    """The scheduled job: drain the mailbox, apply retention, backfill reverse DNS."""
    settings.require_imap()
    stats = _new_stats()
    start = time.monotonic()

    if settings.allowed_domains is None:
        log.warning(
            "ALLOWED_DOMAINS is not set: a report about ANY domain that reaches the mailbox will be stored and "
            "shown, and anyone can email one. Set ALLOWED_DOMAINS to the domains you monitor."
        )

    conn = store.connect(settings)
    try:
        stale_after = max(900, 2 * (settings.mail_budget_seconds + settings.enrich_budget_seconds))
        run_id = store.start_run(conn, stale_after)
        if run_id is None:
            log.warning("another ingest run is in progress; exiting")
            stats["already_running"] = True
            return stats

        failed = True  # until the mailbox phase completes
        try:
            stats["purged"] = store.apply_retention(conn, settings)

            def handle(raw: bytes) -> str:
                try:
                    parsed = parse_email(raw)
                except (InvalidDMARCReport, ParserError) as e:
                    stats["invalid"] += 1
                    stats["errors"].append({"error": f"not a valid DMARC report: {e}"})
                    return "invalid"
                try:
                    _store_parsed(conn, parsed, settings, stats)
                except Exception as e:
                    if _connection_lost(conn):
                        # Every later message would fail the same way; stop
                        # instead of downloading the rest of the mailbox for nothing.
                        raise mailbox.AbortRun(f"database connection lost: {type(e).__name__}: {e}") from e
                    raise
                return "done"

            mailbox.drain(settings, handle, stats, deadline=start + settings.mail_budget_seconds)
            failed = False

            try:
                stats["enriched"] = enrich.enrich_ip_metadata(conn, settings.enrich_budget_seconds)
            except Exception as e:  # noqa: BLE001 - enrichment is best-effort
                log.exception("reverse-DNS enrichment failed")
                stats["errors"].append({"error": f"enrichment: {type(e).__name__}: {e}"})
        except Exception as e:  # noqa: BLE001 - record the failure on the run, then re-raise
            stats["errors"].append({"error": f"fatal: {type(e).__name__}: {e}"})
            raise
        finally:
            _record_finish(conn, settings, run_id, stats, failed)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    log.info(
        "ingest finished: fetched=%(fetched)s stored=%(stored)s skipped=%(skipped)s invalid=%(invalid)s "
        "enriched=%(enriched)s purged=%(purged)s drained=%(drained)s",
        stats,
    )
    return stats


def _iter_files(paths: list[str]):
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix.lower() in REPORT_SUFFIXES:
                    yield child
        else:
            yield p


def import_files(settings: Settings, paths: list[str]) -> dict:
    """Load report files or directories of them (backfills, testing, pipelines
    that drop reports on disk instead of in a mailbox)."""
    stats = _new_stats()
    conn = store.connect(settings)
    try:
        for path in _iter_files(paths):
            stats["fetched"] += 1
            try:
                data = path.read_bytes()
                parsed = parse_email(data) if path.suffix.lower() in (".eml", ".msg") else parse_file(data)
            except (InvalidDMARCReport, ParserError) as e:
                stats["invalid"] += 1
                stats["errors"].append({"file": str(path), "error": f"not a valid DMARC report: {e}"})
                continue
            except OSError as e:
                stats["errors"].append({"file": str(path), "error": str(e)})
                continue
            try:
                _store_parsed(conn, parsed, settings, stats)
            except Exception as e:  # noqa: BLE001
                if _connection_lost(conn):
                    raise  # fatal: nothing further can be stored
                log.exception("could not store %s", path)
                stats["errors"].append({"file": str(path), "error": f"{type(e).__name__}: {e}"})
        if stats["fetched"] == 0:
            stats["errors"].append({"error": "no report files found in the given path(s)"})
        stats["purged"] = store.apply_retention(conn, settings)
    finally:
        conn.close()
    log.info("import finished: files=%(fetched)s stored=%(stored)s skipped=%(skipped)s invalid=%(invalid)s", stats)
    return stats


def run_enrich(settings: Settings) -> dict:
    stats = _new_stats()
    conn = store.connect(settings)
    try:
        stats["enriched"] = enrich.enrich_ip_metadata(conn, settings.enrich_budget_seconds or 60)
    finally:
        conn.close()
    return stats
