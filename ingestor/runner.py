"""Orchestration: mailbox or files -> parse -> store -> enrich."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from . import enrich, mailbox, store
from .config import Settings
from .parsing import InvalidDMARCReport, ParserError, parse_email, parse_file

log = logging.getLogger("ingestor")

REPORT_SUFFIXES = {".xml", ".gz", ".zip", ".eml", ".msg"}


def _new_stats() -> dict:
    return {
        "fetched": 0,  # messages / files looked at
        "stored": 0,  # new aggregate reports written
        "skipped": 0,  # duplicates, filtered-out domains, non-aggregate reports
        "invalid": 0,  # not a DMARC report at all
        "enriched": 0,
        "purged": 0,
        "drained": False,
        "errors": [],
    }


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
        conn.rollback()
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

    conn = store.connect(settings)
    try:
        stale_after = max(900, 2 * (settings.mail_budget_seconds + settings.enrich_budget_seconds))
        run_id = store.start_run(conn, stale_after)
        if run_id is None:
            log.warning("another ingest run is in progress; exiting")
            stats["already_running"] = True
            return stats

        try:
            stats["purged"] = store.apply_retention(conn, settings)

            def handle(raw: bytes) -> str:
                try:
                    parsed = parse_email(raw)
                except (InvalidDMARCReport, ParserError) as e:
                    stats["invalid"] += 1
                    stats["errors"].append({"error": f"not a valid DMARC report: {e}"})
                    return "invalid"
                _store_parsed(conn, parsed, settings, stats)
                return "done"

            try:
                mailbox.drain(settings, handle, stats, deadline=start + settings.mail_budget_seconds)
            except Exception as e:  # noqa: BLE001 - record the failure on the run, then re-raise
                conn.rollback()
                stats["errors"].append({"error": f"mailbox: {type(e).__name__}: {e}"})
                stats["fatal"] = True
                raise

            try:
                stats["enriched"] = enrich.enrich_ip_metadata(conn, settings.enrich_budget_seconds)
            except Exception as e:  # noqa: BLE001 - enrichment is best-effort
                conn.rollback()
                log.exception("reverse-DNS enrichment failed")
                stats["errors"].append({"error": f"enrichment: {type(e).__name__}: {e}"})
        finally:
            store.finish_run(conn, run_id, stats)
    finally:
        conn.close()

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
                log.exception("could not store %s", path)
                stats["errors"].append({"file": str(path), "error": f"{type(e).__name__}: {e}"})
        stats["purged"] = store.apply_retention(conn, settings)
    finally:
        conn.close()
    log.info("import finished: files=%(fetched)s stored=%(stored)s skipped=%(skipped)s invalid=%(invalid)s", stats)
    return stats


def run_enrich(settings: Settings) -> dict:
    conn = store.connect(settings)
    try:
        return {"enriched": enrich.enrich_ip_metadata(conn, settings.enrich_budget_seconds or 60)}
    finally:
        conn.close()
