"""One-off passes (the Vercel function) against PostgreSQL and a real TLS
IMAP server stand-in: a scheduled pass, a single request, held reports."""

from __future__ import annotations

import psycopg
import pytest

from ingestor import oneshot, store

from .test_serve import add_domains, add_mailbox, db, imap, report_for, reports, runs, tls  # noqa: F401 - fixtures


def jobs(settings):
    with db(settings) as c:
        return c.execute("SELECT kind, status, result->>'ok' FROM worker_jobs ORDER BY id").fetchall()


def passes(settings):
    with db(settings) as c:
        return c.execute("SELECT trigger, finished_at IS NOT NULL FROM ingest_passes ORDER BY id").fetchall()


def heartbeats(settings):
    with db(settings) as c:
        return c.execute("SELECT COUNT(*) FROM worker_heartbeats").fetchone()[0]


def test_a_scheduled_pass_answers_requests_and_reads_due_mailboxes(db_settings, imap, monkeypatch):
    for var in ("IMAP_HOST", "IMAP_USER", "IMAP_PASSWORD", "ALLOWED_DOMAINS"):
        monkeypatch.delenv(var, raising=False)
    imap.messages = {1: report_for("example.com", "r1")}
    mid = add_mailbox(db_settings, port=imap.port)
    add_domains(db_settings, "example.com")
    with db(db_settings) as c:
        c.execute("INSERT INTO worker_jobs (kind, mailbox_id) VALUES ('test', %s)", (mid,))

    summary = oneshot.scheduled_pass(db_settings, budget=120)
    assert summary["requests"] == 1 and summary["mailboxes_run"] == 1 and summary["problems"] == []
    assert jobs(db_settings) == [("test", "done", "true")]
    assert reports(db_settings) == ["example.com"]
    assert [r[2] for r in runs(db_settings, mid)] == ["schedule"]
    assert passes(db_settings) == [("schedule", True)]
    assert heartbeats(db_settings) == 0  # a pass leaves no worker behind

    # Nothing is due right after.
    assert oneshot.scheduled_pass(db_settings, budget=120)["mailboxes_run"] == 0


def test_a_pass_never_starts_a_run_it_has_no_time_for(db_settings, imap):
    add_mailbox(db_settings, port=imap.port)
    add_domains(db_settings, "example.com")
    summary = oneshot.scheduled_pass(db_settings, budget=oneshot.MIN_RUN_SECONDS - 1)
    assert summary["mailboxes_run"] == 0 and summary["mailboxes_waiting"] == 1


def test_a_request_is_carried_out_once(db_settings, imap):
    imap.messages = {1: report_for("example.com", "r1")}
    mid = add_mailbox(db_settings, port=imap.port)
    add_domains(db_settings, "example.com")
    with db(db_settings) as c:
        job_id = c.execute("INSERT INTO worker_jobs (kind, mailbox_id) VALUES ('run', %s) RETURNING id", (mid,)).fetchone()[0]

    assert oneshot.run_job(db_settings, job_id, budget=120)["job"] == "run"
    assert jobs(db_settings) == [("run", "done", "true")]
    assert [r[2] for r in runs(db_settings, mid)] == ["manual"]
    # The same request again (a replayed call): already done, nothing runs.
    assert oneshot.run_job(db_settings, job_id, budget=120)["job"] == "taken"
    assert len(runs(db_settings, mid)) == 1
    assert passes(db_settings) == [("request", True), ("request", True)]


def test_release_imports_held_reports_of_a_newly_monitored_domain(db_settings, imap):
    imap.messages = {1: report_for("example.com", "r1")}
    add_mailbox(db_settings, port=imap.port)
    oneshot.scheduled_pass(db_settings, budget=120)  # no monitored domain: held
    assert reports(db_settings) == []
    add_domains(db_settings, "example.com")
    assert oneshot.release(db_settings)["held_imported"] == 1
    assert reports(db_settings) == ["example.com"]


def test_held_reports_are_bounded(db_settings, monkeypatch):
    from ingestor.parsing import parse_file

    from .conftest import report_xml

    monkeypatch.setattr(store, "MAX_HELD_PER_DOMAIN", 2)
    with psycopg.connect(db_settings.database_url) as conn:
        kept = [store.hold_report(conn, parse_file(report_xml(domain="spam.test", report_id=f"r{i}"))["report"]) for i in range(4)]
        conn.commit()
    assert kept == [True, True, False, False]
    huge = parse_file(report_xml(domain="big.test", report_id="x"))["report"]
    huge["padding"] = "x" * (store.MAX_HELD_BYTES + 1)
    with psycopg.connect(db_settings.database_url) as conn:
        assert store.hold_report(conn, huge) is False


@pytest.mark.parametrize("left", [240, 120, 60, 41])
def test_runs_fit_the_pass(left):
    from ingestor.config import Settings

    base = Settings(database_url="postgresql://unused", mail_budget_seconds=170, enrich_budget_seconds=60)
    fitted = oneshot._fit(base, left, enrich=True)
    assert fitted.mail_budget_seconds + fitted.enrich_budget_seconds + oneshot.MARGIN_SECONDS <= left
    assert fitted.mail_budget_seconds >= 10
    assert oneshot._fit(base, left, enrich=False).enrich_budget_seconds == 0


def test_the_pass_budget_comes_from_the_environment():
    assert oneshot.pass_budget({}) == 240
    assert oneshot.pass_budget({"INGEST_PASS_BUDGET_SECONDS": "700"}) == 700
    assert oneshot.pass_budget({"INGEST_PASS_BUDGET_SECONDS": "5"}) == 240  # below the minimum: ignored
