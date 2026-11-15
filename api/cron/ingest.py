"""
Vercel adapter for the ingest worker (only used when deploying on Vercel).

Vercel Cron calls GET /api/cron/ingest on the schedule in vercel.json and
sends `Authorization: Bearer $CRON_SECRET`. Everywhere else, run the worker
directly instead:  python -m ingestor run
"""

from http.server import BaseHTTPRequestHandler
import hmac
import json
import logging
import os
import sys

# Make the repository root importable so `ingestor` resolves inside the
# function bundle.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

# Vercel functions are killed at maxDuration (300s in vercel.json): keep the
# mailbox and reverse-DNS phases comfortably inside it unless overridden.
os.environ.setdefault("INGEST_TIME_BUDGET_SECONDS", "170")
os.environ.setdefault("INGEST_ENRICH_BUDGET_SECONDS", "60")

from ingestor.config import ConfigError, load_settings  # noqa: E402
from ingestor.runner import run_ingest  # noqa: E402

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ingestor.vercel")


class handler(BaseHTTPRequestHandler):
    def _authorized(self) -> bool:
        # Fails closed: without a configured secret nobody can trigger a run.
        secret = os.environ.get("CRON_SECRET") or ""
        presented = self.headers.get("authorization") or ""
        return len(secret) >= 16 and hmac.compare_digest(presented.encode(), f"Bearer {secret}".encode())

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._authorized():
            self._send(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            stats = run_ingest(load_settings())
            # Per-message error text can contain sender-supplied content;
            # return only the count. Details are in the function logs.
            stats["errors"] = len(stats.get("errors", []))
            self._send(200, {"ok": True, **stats})
        except ConfigError as e:
            log.error("configuration error: %s", e)
            self._send(500, {"ok": False, "error": f"configuration: {e}"})
        except Exception:  # noqa: BLE001
            log.exception("ingest failed")
            self._send(500, {"ok": False, "error": "ingest failed; see function logs"})

    do_POST = do_GET
