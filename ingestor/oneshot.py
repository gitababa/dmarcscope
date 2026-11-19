"""One bounded pass of the worker, for hosts that cannot run
`python -m ingestor serve` (Vercel). api/cron/ingest.py calls it.

  scheduled_pass  what a scheduler calls (Vercel Cron, or any other with the
                  machine token): the mailbox in IMAP_* if one is set, queued
                  panel requests, held reports of newly monitored domains,
                  then every panel mailbox that is due.
  run_job         one panel request ("Test connection" / "Run now"), started
                  by the web app the moment it was made.
  release         import the held reports of newly monitored domains.

Everything is done by a serve.Worker in mode 'pass': the same locks, job
handling and run records as the long-running worker, so a pass and a worker
(or two passes) never read one mailbox at once. Its heartbeat lasts only as
long as the pass, and the panel does not count it as a running worker.

The whole pass stays inside its time budget (INGEST_PASS_BUDGET_SECONDS,
default 240), below the 300-second function limit of every Vercel plan:
each mailbox run gets what is left, and a mailbox that does not fit waits for
the next pass.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import replace

from . import store
from .config import Settings
from .runner import run_ingest
from .serve import HEARTBEAT_ALIVE_SECONDS, Worker, _describe

log = logging.getLogger("ingestor.oneshot")

DEFAULT_BUDGET_SECONDS = 240
# Time kept back at the end of a pass (closing runs, recording the pass).
MARGIN_SECONDS = 15
# A mailbox run is not started with less time than this left.
MIN_RUN_SECONDS = 40


def pass_budget(env: dict | None = None) -> int:
    env = dict(os.environ) if env is None else env
    raw = (env.get("INGEST_PASS_BUDGET_SECONDS") or "").strip()
    if raw.isdigit() and 60 <= int(raw) <= 3600:
        return int(raw)
    return DEFAULT_BUDGET_SECONDS


def _fit(base: Settings, left: float, enrich: bool) -> Settings:
    """Settings for one run that ends before the pass's deadline."""
    enrich_seconds = min(base.enrich_budget_seconds, max(0, int(left) - MIN_RUN_SECONDS)) if enrich else 0
    mail_seconds = max(10, min(base.mail_budget_seconds, int(left) - enrich_seconds - MARGIN_SECONDS))
    return replace(base, mail_budget_seconds=mail_seconds, enrich_budget_seconds=enrich_seconds)


def _brief(stats: dict) -> dict:
    """Counts only: never message content."""
    return {k: stats.get(k, 0) for k in ("fetched", "stored", "skipped", "invalid")} | {"problems": len(stats.get("errors", []))}


class _Pass:
    def __init__(self, base: Settings, trigger: str, budget: int | None, env: dict | None):
        self.base = base
        self.deadline = time.monotonic() + (budget or pass_budget(env))
        self.worker = Worker(base, env=env, mode="pass")
        self.trigger = trigger
        self.summary: dict = {"problems": []}
        # Reverse-DNS backfill takes up to its whole budget: once per pass.
        self.enrich = True

    def left(self) -> float:
        return self.deadline - time.monotonic()

    def fit_worker(self) -> None:
        self.worker.base = _fit(self.base, self.left(), self.enrich)

    def __enter__(self) -> "_Pass":
        self.worker.open()
        self.pass_id = store.start_pass(self.worker.conn, self.trigger)
        return self

    def __exit__(self, *exc) -> None:
        try:
            if exc[0] is not None:
                self.summary["problems"].append(f"pass failed: {_describe(exc[1])}")
            store.finish_pass(self.worker.conn, self.pass_id, self.summary)
        except Exception:  # noqa: BLE001 - the pass record is informational
            log.warning("could not record the end of pass %s", getattr(self, "pass_id", "?"), exc_info=True)
        finally:
            self.worker.close()


def scheduled_pass(base: Settings, *, env: dict | None = None, budget: int | None = None) -> dict:
    with _Pass(base, "schedule", budget, env) as p:
        s = p.summary
        store.fail_abandoned_jobs(p.worker.conn, HEARTBEAT_ALIVE_SECONDS)

        # The mailbox in IMAP_* (the setup of 1.1), when there is one.
        if base.imap_host:
            try:
                s["environment_mailbox"] = _brief(run_ingest(_fit(base, p.left(), p.enrich)))
            except Exception as e:  # noqa: BLE001 - the run row records it; the pass goes on
                s["problems"].append(f"environment mailbox: {_describe(e)}")
            p.enrich = False

        # Requests from the panel that nobody has picked up.
        s["requests"] = 0
        while p.left() > MIN_RUN_SECONDS:
            job = store.claim_job(p.worker.conn, p.worker.worker_id)
            if job is None:
                break
            p.fit_worker()
            p.worker.handle_job(job)
            s["requests"] += 1

        s["held_imported"] = p.worker.release_held()

        # Panel mailboxes whose interval has passed.
        s["mailboxes_run"] = 0
        s["mailboxes_waiting"] = 0
        for mailbox_id in store.due_mailboxes(p.worker.conn):
            if p.left() < MIN_RUN_SECONDS:
                s["mailboxes_waiting"] += 1
                continue
            p.fit_worker()
            outcome = p.worker.run_mailbox(mailbox_id, "schedule")
            if outcome is None:
                continue  # another pass or worker has it
            ok, message = outcome
            s["mailboxes_run"] += 1
            p.enrich = False
            if not ok:
                s["problems"].append(f"mailbox {mailbox_id}: {message[:200]}")
        return s


def run_job(base: Settings, job_id: int, *, env: dict | None = None, budget: int | None = None) -> dict:
    with _Pass(base, "request", budget, env) as p:
        job = store.claim_job_by_id(p.worker.conn, p.worker.worker_id, job_id)
        if job is None:
            # Done already, or a worker (or another pass) is on it.
            p.summary["job"] = "taken"
            return p.summary
        p.fit_worker()
        p.worker.handle_job(job)
        p.summary["job"] = job["kind"]
        p.summary["held_imported"] = p.worker.release_held()
        return p.summary


def release(base: Settings, *, env: dict | None = None, budget: int | None = None) -> dict:
    with _Pass(base, "request", budget, env) as p:
        p.summary["held_imported"] = p.worker.release_held()
        return p.summary
