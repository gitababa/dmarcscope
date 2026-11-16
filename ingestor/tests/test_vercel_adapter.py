"""The Vercel function wrapper around the worker: closed without the token,
and it never returns per-message error text."""

import importlib.util
import io
import json
from pathlib import Path

import pytest

SECRET = "c" * 32


@pytest.fixture()
def adapter(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "api" / "cron" / "ingest.py"
    spec = importlib.util.spec_from_file_location("vercel_ingest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("CRON_SECRET", SECRET)
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")
    return module


def call(module, authorization=None):
    handler = module.handler.__new__(module.handler)  # no socket
    handler.headers = {"authorization": authorization} if authorization else {}
    handler.wfile = io.BytesIO()
    sent = {}
    handler.send_response = lambda status: sent.__setitem__("status", status)
    handler.send_header = lambda k, v: sent.__setitem__(k, v)
    handler.end_headers = lambda: None
    handler.do_GET()
    return sent["status"], json.loads(handler.wfile.getvalue())


def test_rejects_without_the_exact_token(adapter, monkeypatch):
    ran = []
    monkeypatch.setattr(adapter, "run_ingest", lambda s: ran.append(1) or {})
    for presented in (None, "Bearer wrong", SECRET, f"bearer {SECRET}", f"Bearer {SECRET} "):
        assert call(adapter, presented) == (401, {"ok": False, "error": "unauthorized"})
    monkeypatch.setenv("CRON_SECRET", "short")
    assert call(adapter, "Bearer short")[0] == 401
    monkeypatch.delenv("CRON_SECRET")
    assert call(adapter, "Bearer ")[0] == 401
    assert ran == []


def test_returns_counts_but_not_error_text(adapter, monkeypatch):
    stats = {"fetched": 2, "stored": 1, "errors": [{"uid": "7", "error": "sender-controlled text"}]}
    monkeypatch.setattr(adapter, "run_ingest", lambda s: dict(stats))
    status, body = call(adapter, f"Bearer {SECRET}")
    assert status == 200 and body == {"ok": True, "fetched": 2, "stored": 1, "errors": 1}


def test_failures_are_500_without_detail(adapter, monkeypatch):
    def boom(settings):
        raise RuntimeError("password=hunter2 rejected by imap.example.com")

    monkeypatch.setattr(adapter, "run_ingest", boom)
    status, body = call(adapter, f"Bearer {SECRET}")
    assert status == 500 and body["ok"] is False and "hunter2" not in json.dumps(body)

    monkeypatch.delenv("DATABASE_URL")
    status, body = call(adapter, f"Bearer {SECRET}")
    assert status == 500 and "DATABASE_URL" in body["error"]
