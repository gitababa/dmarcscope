"""The Vercel function: a scheduled pass with the machine token, one task
with a request signed by the web app, closed otherwise, and it never returns
per-message error text."""

import importlib.util
import io
import json
import time
from pathlib import Path

import pytest

from ingestor import trigger

SECRET = "c" * 32
APP_SECRET = "a" * 40


@pytest.fixture()
def adapter(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "api" / "cron" / "ingest.py"
    spec = importlib.util.spec_from_file_location("vercel_ingest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("CRON_SECRET", SECRET)
    monkeypatch.setenv("APP_SECRET", APP_SECRET)
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")
    return module


def call(module, authorization=None, path="/api/cron/ingest", signed=None):
    handler = module.handler.__new__(module.handler)  # no socket
    headers = {}
    if authorization:
        headers["authorization"] = authorization
    if signed:
        headers[trigger.HEADER] = signed
    handler.headers = headers
    handler.path = path
    handler.wfile = io.BytesIO()
    sent = {}
    handler.send_response = lambda status: sent.__setitem__("status", status)
    handler.send_header = lambda k, v: sent.__setitem__(k, v)
    handler.end_headers = lambda: None
    handler.do_GET()
    return sent["status"], json.loads(handler.wfile.getvalue())


def sign(task, secret=APP_SECRET, ts=None):
    ts = int(time.time()) if ts is None else ts
    return f"{ts}.{trigger.signature(secret, ts, task)}"


@pytest.fixture()
def calls(adapter, monkeypatch):
    seen = []
    monkeypatch.setattr(adapter.oneshot, "scheduled_pass", lambda s: seen.append("pass") or {"requests": 0, "problems": []})
    monkeypatch.setattr(adapter.oneshot, "run_job", lambda s, job_id: seen.append(f"job:{job_id}") or {"job": "test", "problems": []})
    monkeypatch.setattr(adapter.oneshot, "release", lambda s: seen.append("release") or {"held_imported": 2, "problems": []})
    return seen


def test_rejects_without_the_exact_token(adapter, calls, monkeypatch):
    for presented in (None, "Bearer wrong", SECRET, f"bearer {SECRET}", f"Bearer {SECRET} "):
        assert call(adapter, presented) == (401, {"ok": False, "error": "unauthorized"})
    monkeypatch.setenv("CRON_SECRET", "short")
    assert call(adapter, "Bearer short")[0] == 401
    monkeypatch.delenv("CRON_SECRET")
    assert call(adapter, "Bearer ")[0] == 401
    assert calls == []


def test_the_token_runs_a_scheduled_pass(adapter, calls):
    assert call(adapter, f"Bearer {SECRET}") == (200, {"ok": True, "requests": 0, "problems": 0})
    assert calls == ["pass"]


def test_a_signed_request_runs_only_its_task(adapter, calls):
    assert call(adapter, path="/api/cron/ingest?task=job:42", signed=sign("job:42"))[0] == 200
    assert call(adapter, path="/api/cron/ingest?task=release", signed=sign("release")) == (200, {"ok": True, "held_imported": 2, "problems": 0})
    assert calls == ["job:42", "release"]


def test_a_bad_signature_is_refused(adapter, calls):
    stale = int(time.time()) - 600
    for path, signed in [
        ("/api/cron/ingest?task=job:42", sign("job:43")),  # signed for another task
        ("/api/cron/ingest?task=job:42", sign("job:42", secret="b" * 40)),  # another secret
        ("/api/cron/ingest?task=job:42", sign("job:42", ts=stale)),  # too old
        ("/api/cron/ingest?task=drop-tables", sign("drop-tables")),  # not a task
        ("/api/cron/ingest?task=job:42", "garbage"),
    ]:
        assert call(adapter, path=path, signed=signed)[0] == 401
    assert calls == []


def test_the_previous_app_secret_still_verifies(adapter, calls, monkeypatch):
    monkeypatch.setenv("APP_SECRET", "n" * 40)
    monkeypatch.setenv("APP_SECRET_PREVIOUS", APP_SECRET)
    assert call(adapter, path="/api/cron/ingest?task=job:7", signed=sign("job:7"))[0] == 200


def test_returns_counts_but_not_problem_text(adapter, monkeypatch):
    summary = {"mailboxes_run": 1, "problems": ["mailbox 3: sender-controlled text"]}
    monkeypatch.setattr(adapter.oneshot, "scheduled_pass", lambda s: dict(summary))
    status, body = call(adapter, f"Bearer {SECRET}")
    assert status == 200 and body == {"ok": True, "mailboxes_run": 1, "problems": 1}


def test_failures_are_500_without_detail(adapter, monkeypatch):
    def boom(settings):
        raise RuntimeError("password=hunter2 rejected by imap.example.com")

    monkeypatch.setattr(adapter.oneshot, "scheduled_pass", boom)
    status, body = call(adapter, f"Bearer {SECRET}")
    assert status == 500 and body["ok"] is False and "hunter2" not in json.dumps(body)

    monkeypatch.delenv("DATABASE_URL")
    status, body = call(adapter, f"Bearer {SECRET}")
    assert status == 500 and "DATABASE_URL" in body["error"]


def test_signature_matches_the_web_app():
    # Same vector as tests/unit/ingest-trigger.test.ts.
    assert trigger.signature("s" * 32, 1795000000, "job:12") == VECTOR


VECTOR = "99b494f413376a057b621dedf83fbb4c010022ff48837930ccb621affcab7887"
