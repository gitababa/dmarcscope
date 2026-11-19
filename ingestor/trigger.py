"""Requests the web app sends to the Vercel function (api/cron/ingest.py) to
start work at once: "Test connection", "Run now", or importing the held
reports of a newly monitored domain.

Signed with APP_SECRET, which both sides already hold, so this works however
the machine token (CRON_SECRET) is configured. The header is
`X-DMARCscope-Trigger: <unix time>.<hex HMAC-SHA256>` over
"dmarcscope-ingest-trigger\\n<unix time>\\n<task>", where task is "job:<id>" or
"release". A signature is accepted for five minutes; replaying one can only
repeat that same task, which is idempotent. lib/ingest-trigger.ts signs.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time

HEADER = "X-DMARCscope-Trigger"
MAX_AGE_SECONDS = 300
TASK = re.compile(r"^(job:[1-9][0-9]{0,14}|release)$")


def signature(secret: str, ts: int, task: str) -> str:
    msg = f"dmarcscope-ingest-trigger\n{ts}\n{task}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify(header: str | None, task: str, secrets: list[str], now: float | None = None) -> bool:
    if not header or not TASK.match(task or ""):
        return False
    ts_text, _, sig = header.partition(".")
    if not ts_text.isdigit() or len(sig) != 64:
        return False
    ts = int(ts_text)
    if abs((time.time() if now is None else now) - ts) > MAX_AGE_SECONDS:
        return False
    return any(hmac.compare_digest(signature(s, ts, task), sig) for s in secrets if s)
