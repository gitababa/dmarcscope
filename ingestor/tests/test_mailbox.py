"""The mailbox loop against an in-memory IMAP stand-in."""

import datetime as dt
from dataclasses import replace

import pytest

from ingestor import mailbox, runner
from ingestor.config import ConfigError, Settings

from .conftest import plain_email, report_email, report_xml, zipped

IMAP = dict(imap_host="imap.test", imap_user="u", imap_password="p")


class FakeImap:
    def __init__(self, messages: dict[bytes, bytes], supports_move: bool = True):
        self.messages = dict(messages)  # uid -> raw message, in INBOX
        self.seen: set[bytes] = set()
        self.moved: dict[bytes, str] = {}
        self.deleted: set[bytes] = set()
        self.created: list[str] = []
        self.searches: list[tuple] = []
        self.supports_move = supports_move
        self.expunged = False
        self.logged_out = False

    def create(self, folder):
        self.created.append(folder)
        return "OK", [b""]

    def select(self, folder):
        return "OK", [b"1"]

    def uid(self, command, *args):
        if command == "SEARCH":
            self.searches.append(args)
            unseen = [u for u in sorted(self.messages, key=int) if u not in self.seen and u not in self.moved]
            return "OK", [b" ".join(unseen)]
        uid = args[0]
        if command == "FETCH":
            assert args[1] == "(BODY.PEEK[])", "must not implicitly mark messages as seen"
            return "OK", [(b"%s (UID %s BODY[] {%d}" % (uid, uid, len(self.messages[uid])), self.messages[uid]), b")"]
        if command == "STORE":
            (self.seen if "Seen" in args[2] else self.deleted).add(uid)
            return "OK", [b""]
        if command == "MOVE":
            if not self.supports_move:
                return "BAD", [b"unknown command"]
            self.moved[uid] = args[1]
            return "OK", [b""]
        if command == "COPY":
            self.moved[uid] = args[1]
            return "OK", [b""]
        raise AssertionError(f"unexpected IMAP command {command}")

    def expunge(self):
        self.expunged = True

    def close(self):
        pass

    def logout(self):
        self.logged_out = True


def _stats():
    return {"fetched": 0, "errors": [], "drained": False}


def _drain(monkeypatch, fake, settings, handle, deadline=None):
    import time

    monkeypatch.setattr(mailbox, "_connect", lambda s: fake)
    stats = _stats()
    mailbox.drain(settings, handle, stats, deadline if deadline is not None else time.monotonic() + 30)
    return stats


def test_requires_imap_settings():
    with pytest.raises(ConfigError, match="IMAP_HOST, IMAP_USER, IMAP_PASSWORD"):
        mailbox.drain(Settings(database_url="x"), lambda raw: "done", _stats(), 0)


def test_marks_done_and_moves_invalid(monkeypatch):
    fake = FakeImap({b"1": b"good", b"2": b"bad", b"3": b"good"})
    settings = Settings(database_url="x", **IMAP)
    stats = _drain(monkeypatch, fake, settings, lambda raw: "invalid" if raw == b"bad" else "done")

    assert stats["fetched"] == 3 and stats["drained"] is True and stats["errors"] == []
    assert fake.seen == {b"1", b"2", b"3"}
    assert fake.moved == {b"2": '"DMARC-Invalid"'}
    assert fake.created == ['"DMARC-Invalid"']
    assert fake.expunged and fake.logged_out


def test_a_failing_message_stays_unseen_and_does_not_loop(monkeypatch):
    fake = FakeImap({b"1": b"boom", b"2": b"ok"})
    calls = []

    def handle(raw):
        calls.append(raw)
        if raw == b"boom":
            raise RuntimeError("database unavailable")
        return "done"

    stats = _drain(monkeypatch, fake, Settings(database_url="x", **IMAP), handle)
    assert calls.count(b"boom") == 1  # attempted once this run, retried by the next
    assert fake.seen == {b"2"}
    assert stats["errors"] == [{"uid": "1", "error": "RuntimeError: database unavailable"}]
    assert stats["drained"] is True


def test_newest_first_respects_cap_and_moves_processed(monkeypatch):
    fake = FakeImap({b"1": b"a", b"2": b"b", b"3": b"c"}, supports_move=False)
    order = []
    settings = Settings(database_url="x", **IMAP, max_messages=2, imap_processed_folder='Done "2026"')
    stats = _drain(monkeypatch, fake, settings, lambda raw: order.append(raw) or "done")

    assert order == [b"c", b"b"]
    assert stats["fetched"] == 2 and stats["drained"] is False
    # COPY + \Deleted fallback, with the folder name quoted safely
    assert fake.moved == {b"3": '"Done \\"2026\\""', b"2": '"Done \\"2026\\""'}
    assert fake.deleted == {b"3", b"2"}


def test_stops_at_the_deadline(monkeypatch):
    fake = FakeImap({b"1": b"a"})
    stats = _drain(monkeypatch, fake, Settings(database_url="x", **IMAP), lambda raw: "done", deadline=0)
    assert stats["fetched"] == 0 and fake.seen == set()


def test_retention_cutoff_limits_the_search(monkeypatch):
    fake = FakeImap({})
    settings = Settings(database_url="x", **IMAP, min_date=dt.date(2026, 1, 5))
    _drain(monkeypatch, fake, settings, lambda raw: "done")
    assert fake.searches[0] == (None, "UNSEEN", "SINCE", "04-Jan-2026")
    assert mailbox.imap_date(dt.date(2026, 12, 31)) == "31-Dec-2026"


def test_full_run_from_mailbox_to_database(monkeypatch, db_settings):
    import psycopg

    fake = FakeImap(
        {
            b"10": report_email(zipped(report_xml(report_id="m1"))),
            b"11": plain_email(),
            b"12": report_email(zipped(report_xml(report_id="m1"))),  # duplicate delivery
            b"13": report_email(zipped(report_xml(report_id="m2", domain="other.test"))),
        }
    )
    monkeypatch.setattr(mailbox, "_connect", lambda s: fake)
    settings = replace(db_settings, **IMAP, allowed_domains=frozenset({"example.com"}), enrich_budget_seconds=0)

    stats = runner.run_ingest(settings)
    assert (stats["fetched"], stats["stored"], stats["skipped"], stats["invalid"]) == (4, 1, 2, 1)
    assert stats["drained"] is True
    assert fake.seen == {b"10", b"11", b"12", b"13"}
    assert fake.moved == {b"11": '"DMARC-Invalid"'}

    with psycopg.connect(settings.database_url) as conn:
        assert conn.execute("SELECT name FROM domains").fetchall() == [("example.com",)]
        run = conn.execute(
            "SELECT messages_fetched, reports_parsed, reports_skipped, finished_at IS NOT NULL, jsonb_array_length(errors) FROM ingest_runs"
        ).fetchall()
    assert run == [(4, 1, 3, True, 1)]


def test_a_mailbox_failure_is_recorded_on_the_run(monkeypatch, db_settings):
    import psycopg

    def refuse(settings):
        raise OSError("connection refused")

    monkeypatch.setattr(mailbox, "_connect", refuse)
    with pytest.raises(OSError):
        runner.run_ingest(replace(db_settings, **IMAP))
    with psycopg.connect(db_settings.database_url) as conn:
        finished, error = conn.execute("SELECT finished_at IS NOT NULL, errors->0->>'error' FROM ingest_runs").fetchone()
    assert finished is True and "connection refused" in error
