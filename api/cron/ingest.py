"""
Vercel adapter for the ingest worker (only used when deploying on Vercel).

Vercel Cron calls GET /api/cron/ingest on the schedule in vercel.json and
sends `Authorization: Bearer $CRON_SECRET`; the web app calls it to carry out
"Test connection" and "Run now" at once. Each call is one bounded pass
(ingestor/oneshot.py). Everywhere else, run the worker directly instead:
python -m ingestor serve (or run).
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

# Vercel functions are killed at maxDuration (300s in vercel.json, the
# maximum on Hobby): a pass ends after INGEST_PASS_BUDGET_SECONDS (240), and
# one mailbox run reads mail for at most 170s of it.
os.environ.setdefault("INGEST_TIME_BUDGET_SECONDS", "170")
os.environ.setdefault("INGEST_ENRICH_BUDGET_SECONDS", "60")

from urllib.parse import parse_qs, urlparse  # noqa: E402

from ingestor import crypto, oneshot, trigger  # noqa: E402
from ingestor.config import ConfigError, load_settings  # noqa: E402

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ingestor.vercel")


class handler(BaseHTTPRequestHandler):
    """GET|POST /api/cron/ingest

    - `Authorization: Bearer $CRON_SECRET` (Vercel Cron, or any scheduler):
      one scheduled pass (ingestor/oneshot.py).
    - `X-DMARCscope-Trigger` signed with APP_SECRET, `?task=job:<id>` or
      `?task=release`: that one task, sent by the web app (ingestor/trigger.py).
    """

    def _bearer_ok(self) -> bool:
        # Fails closed: without a configured secret no scheduler can call.
        secret = os.environ.get("CRON_SECRET") or ""
        presented = self.headers.get("authorization") or ""
        return len(secret) >= 16 and hmac.compare_digest(presented.encode(), f"Bearer {secret}".encode())

    def _task(self) -> str:
        values = parse_qs(urlparse(self.path).query).get("task") or [""]
        return values[0][:40]

    def _signed_ok(self, task: str) -> bool:
        try:
            secrets = crypto.secrets_from_env()
        except Exception:  # noqa: BLE001 - APP_SECRET missing or too short: nothing can verify
            return False
        return trigger.verify(self.headers.get(trigger.HEADER), task, secrets)

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        task = self._task()
        if task and self._signed_ok(task):
            run = (lambda s: oneshot.release(s)) if task == "release" else (lambda s: oneshot.run_job(s, int(task.split(":", 1)[1])))
        elif self._bearer_ok():
            run = oneshot.scheduled_pass
        else:
            self._send(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            result = run(load_settings())
            # Counts only: the reasons are in the pass record (admins only).
            result["problems"] = len(result.get("problems", []))
            self._send(200, {"ok": True, **result})
        except ConfigError as e:
            log.error("configuration error: %s", e)
            self._send(500, {"ok": False, "error": f"configuration: {e}"})
        except Exception:  # noqa: BLE001
            log.exception("ingest pass failed")
            self._send(500, {"ok": False, "error": "ingest failed; see function logs"})

    do_POST = do_GET
