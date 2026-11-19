"""Long-running worker: python -m ingestor serve.

Reads the mailboxes configured in the panel (table `mailboxes`) and:
  - runs each enabled one when its interval has passed;
  - carries out the panel's requests from `worker_jobs` ("Test connection",
    "Run now"): the web app never opens a mailbox itself;
  - writes a heartbeat so the panel can tell whether a worker is alive.

Any number of workers can run. A run of a mailbox holds a session advisory
lock for it on the worker's lock connection, so one mailbox is never read by
two runs at once; if a worker dies, its lock disappears with its connection,
and the next holder closes the orphaned run as failed before starting.
Jobs are claimed with FOR UPDATE SKIP LOCKED. Retention and reverse-DNS
backfill are done by one run at a time (a global try-lock); a run that does
not get it reads its mailbox and leaves them to the next.

SIGTERM / SIGINT: the current message is finished, the run is closed as
failed ("interrupted"; the rest is retried next time), locks are released.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from dataclasses import replace

from . import __version__, crypto, mailbox, oauth, store
from .config import ConfigError, Settings
from .runner import RunRefused, run_ingest

log = logging.getLogger("ingestor.serve")

POLL_SECONDS = 5
HEARTBEAT_ALIVE_SECONDS = 120


class MailboxConfigError(Exception):
    """A mailbox's saved configuration cannot be used. Safe to show."""


def mailbox_settings(base: Settings, row: dict, env: dict | None = None) -> Settings:
    """The connection settings for one panel mailbox. The secret is decrypted
    here, in the worker, and nowhere in the web app."""
    if not row.get("secret"):
        raise MailboxConfigError("no password, client secret or key has been saved for this mailbox")
    try:
        secret = crypto.decrypt(
            secrets=crypto.secrets_from_env(env),
            purpose="mailbox",
            context=f"mailbox:{row['id']}",
            envelope=row["secret"],
        ).plaintext
    except crypto.EnvelopeError as e:
        raise MailboxConfigError(f"the saved secret cannot be decrypted ({e.code}); check APP_SECRET / APP_SECRET_PREVIOUS") from None

    settings = replace(
        base,
        imap_host=row["host"],
        imap_port=int(row["port"]),
        imap_security=row["security"],
        imap_user=row["username"],
        imap_password=None,
        imap_folder=row["folder"] or "INBOX",
        imap_processed_folder=row["processed_folder"] or None,
        imap_invalid_folder=row["invalid_folder"] or "DMARC-Invalid",
        imap_xoauth2=None,
    )
    kind = row["kind"]
    if kind == "imap":
        return replace(settings, imap_password=secret)

    cache: dict[str, oauth.Token] = {}

    def response() -> bytes:
        token = cache.get("t")
        if token is None or token.expires_at - 60 < time.time():
            if kind == "microsoft":
                token = oauth.microsoft_token(row.get("tenant_id") or "", row.get("client_id") or "", secret)
            elif kind == "google":
                token = oauth.google_token(secret, row["username"])
            else:
                raise MailboxConfigError(f"unknown mailbox kind {kind!r}")
            cache["t"] = token
        return oauth.xoauth2(row["username"], token.value)

    return replace(settings, imap_xoauth2=response)


def _describe(e: BaseException) -> str:
    """A one-line reason for the panel. Never contains a secret: the token
    and mailbox errors carry provider and server messages only."""
    text = str(e).replace("\n", " ").strip()
    if isinstance(e, (MailboxConfigError, oauth.TokenError, RunRefused, mailbox.Interrupted)):
        return text[:400]
    return f"{type(e).__name__}: {text}"[:400]


class Worker:
    def __init__(self, base: Settings, *, poll_seconds: float = POLL_SECONDS, env: dict | None = None, mode: str = "serve"):
        self.base = base
        self.env = env
        # 'serve': python -m ingestor serve. 'pass': a one-off pass
        # (ingestor/oneshot.py), not shown in the panel as a running worker.
        self.mode = mode
        self.poll_seconds = poll_seconds
        self.worker_id = f"{socket.gethostname()[:60]}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.stop = threading.Event()
        self.conn = None
        self.lock_conn = None

    # ---------- lifecycle ----------

    def open(self) -> None:
        self.conn = store.connect(self.base)
        # Session advisory locks live on their own autocommit connection, so a
        # rollback on the work connection never releases them.
        self.lock_conn = store.connect(self.base)
        self.lock_conn.autocommit = True
        store.heartbeat(self.conn, self.worker_id, socket.gethostname(), __version__, self.mode)
        # A run can take longer than HEARTBEAT_ALIVE_SECONDS: keep reporting
        # in from a thread on its own connection, so other workers never take
        # this one for dead mid-run and fail the request it is working on.
        self._beating = threading.Event()
        self._beat_conn = store.connect(self.base)
        self._beat_conn.autocommit = True
        self._beat_thread = threading.Thread(target=self._beat, name="heartbeat", daemon=True)
        self._beat_thread.start()

    def _beat(self) -> None:
        while not self._beating.wait(HEARTBEAT_ALIVE_SECONDS / 4):
            try:
                store.heartbeat(self._beat_conn, self.worker_id, socket.gethostname(), __version__, self.mode)
            except Exception:  # noqa: BLE001 - the main loop's heartbeat still runs
                log.warning("heartbeat failed", exc_info=True)

    def close(self) -> None:
        if getattr(self, "_beat_thread", None) is not None:
            self._beating.set()
            self._beat_thread.join(5)
            try:
                self._beat_conn.close()
            except Exception:  # noqa: BLE001
                pass
        for c in (self.conn,):
            try:
                if c is not None:
                    store.remove_heartbeat(c, self.worker_id)
            except Exception:  # noqa: BLE001
                pass
        for c in (self.conn, self.lock_conn):
            try:
                if c is not None:
                    c.close()
            except Exception:  # noqa: BLE001
                pass

    def serve_forever(self) -> None:
        self.open()
        log.info("worker %s started", self.worker_id)
        try:
            while not self.stop.is_set():
                worked = self.tick()
                if not worked:
                    self.stop.wait(self.poll_seconds)
        finally:
            self.close()
            log.info("worker %s stopped", self.worker_id)

    # ---------- one pass ----------

    def tick(self) -> bool:
        """Heartbeat, one job, then due mailboxes. True if anything was done."""
        store.heartbeat(self.conn, self.worker_id, socket.gethostname(), __version__, self.mode)
        store.fail_abandoned_jobs(self.conn, HEARTBEAT_ALIVE_SECONDS)
        job = store.claim_job(self.conn, self.worker_id)
        if job:
            self.handle_job(job)
            return True
        worked = self.release_held() > 0
        for mailbox_id in store.due_mailboxes(self.conn):
            if self.stop.is_set():
                break
            if self.run_mailbox(mailbox_id, "schedule") is not None:
                worked = True
        return worked

    def handle_job(self, job: dict) -> None:
        mailbox_id = job["mailbox_id"]
        row = store.load_mailbox(self.conn, mailbox_id) if mailbox_id is not None else None
        if row is None:
            store.finish_job(self.conn, job["id"], False, "This mailbox no longer exists.")
            return
        if job["kind"] == "test":
            try:
                message = mailbox.check(mailbox_settings(self.base, row, self.env))
                store.finish_job(self.conn, job["id"], True, message)
            except Exception as e:  # noqa: BLE001 - reported to the panel
                log.warning("connection test of mailbox %s failed: %s", mailbox_id, _describe(e))
                store.finish_job(self.conn, job["id"], False, _describe(e))
            return
        outcome = self.run_mailbox(mailbox_id, "manual")
        if outcome is None:
            store.finish_job(self.conn, job["id"], False, "A run of this mailbox is already in progress.")
        else:
            ok, message = outcome
            store.finish_job(self.conn, job["id"], ok, message)

    def release_held(self) -> int:
        """Import held reports of domains that became monitored. Returns the
        number stored."""
        try:
            if not store.has_releasable(self.conn):
                return 0
            from .runner import with_panel_settings

            settings = with_panel_settings(self.conn, self.base)
            if settings.allowed_domains is None:
                return 0
            return store.release_held(self.conn, settings)
        except Exception as e:  # noqa: BLE001 - retried on the next pass
            log.warning("importing held reports failed: %s", _describe(e))
            return 0

    def run_mailbox(self, mailbox_id: int, trigger: str) -> tuple[bool, str] | None:
        """One run of a mailbox. None if another worker holds it."""
        if not store.try_lock_mailbox(self.lock_conn, mailbox_id):
            return None
        try:
            closed = store.close_orphaned_runs(self.conn, mailbox_id)
            if closed:
                log.warning("closed %s run(s) of mailbox %s left open by a stopped worker", closed, mailbox_id)
            row = store.load_mailbox(self.conn, mailbox_id)
            if row is None:
                return False, "This mailbox no longer exists."
            try:
                settings = mailbox_settings(self.base, row, self.env)
            except MailboxConfigError as e:
                self._record_refused_run(mailbox_id, trigger, str(e))
                return False, str(e)
            # Retention and reverse-DNS backfill are global: one run at a
            # time does them, whichever holds the housekeeping lock.
            housekeeping = store.try_lock_housekeeping(self.lock_conn)
            try:
                stats = run_ingest(settings, mailbox_id=mailbox_id, trigger=trigger, should_stop=self.stop.is_set, housekeeping=housekeeping)
            except Exception as e:  # noqa: BLE001 - the run row records it; the loop goes on
                log.warning("run of mailbox %s failed: %s", mailbox_id, _describe(e))
                return False, _describe(e)
            finally:
                if housekeeping:
                    try:
                        store.unlock_housekeeping(self.lock_conn)
                    except Exception:  # noqa: BLE001 - released with the connection anyway
                        pass
            if stats.get("already_running"):
                return False, "A run of this mailbox is already in progress."
            return True, (
                f"Read {stats['fetched']} message(s): {stats['stored']} new report(s), {stats['skipped']} duplicate(s) or "
                f"other domains, {stats['invalid']} not report(s), {len(stats['errors'])} problem(s)."
            )
        finally:
            try:
                store.unlock_mailbox(self.lock_conn, mailbox_id)
            except Exception:  # noqa: BLE001 - the lock goes with the connection anyway
                pass

    def _record_refused_run(self, mailbox_id: int, trigger: str, message: str) -> None:
        """A run that could not even connect still shows in the history."""
        run_id = store.start_run(self.conn, 900, mailbox_id=mailbox_id, trigger=trigger)
        if run_id is not None:
            store.finish_run(self.conn, run_id, {"errors": [{"error": message}]}, failed=True)


def serve(base: Settings) -> int:
    if not (base.database_url and os.environ.get("APP_SECRET")):
        raise ConfigError("serve needs DATABASE_URL and APP_SECRET (the key the panel encrypts mailbox credentials with)")
    worker = Worker(base)

    import signal

    def _stop(signum, frame):  # noqa: ARG001
        log.info("signal %s: finishing the current message, then stopping", signum)
        worker.stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _stop)
        except ValueError:
            pass
    worker.serve_forever()
    return 0
