"""IMAP source: read unseen report emails from a mailbox.

Messages are addressed by UID (stable across flag changes and expunges) and
fetched with BODY.PEEK[], which does not set \\Seen — a message is only
marked as seen once it has been stored or deliberately skipped, so a crash or
a database error leaves it in place for the next run.
"""

from __future__ import annotations

import datetime as dt
import imaplib
import logging
import ssl
import time
from typing import Callable

from .config import Settings

log = logging.getLogger("ingestor.mailbox")

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
TIMEOUT_SECONDS = 60

# handle(raw_message) -> "done" (mark seen, optionally move to processed) or
# "invalid" (mark seen, move to the invalid folder). Raising leaves the
# message unseen so the next run retries it; raising AbortRun also stops the
# run, for failures that every following message would hit too.
Handler = Callable[[bytes], str]


class AbortRun(Exception):
    """Raised by a handler when carrying on is pointless (database gone)."""


def imap_date(d: dt.date) -> str:
    """2026-01-05 -> 05-Jan-2026 (IMAP SEARCH date format, locale-independent)."""
    return f"{d.day:02d}-{_MONTHS[d.month - 1]}-{d.year}"


def _quote(mailbox: str) -> str:
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _connect(settings: Settings) -> imaplib.IMAP4:
    context = ssl.create_default_context()
    if settings.imap_security == "starttls":
        imap = imaplib.IMAP4(settings.imap_host, settings.imap_port, timeout=TIMEOUT_SECONDS)
        imap.starttls(ssl_context=context)
    else:
        imap = imaplib.IMAP4_SSL(settings.imap_host, settings.imap_port, ssl_context=context, timeout=TIMEOUT_SECONDS)
    imap.login(settings.imap_user, settings.imap_password)
    return imap


def _ensure_folder(imap: imaplib.IMAP4, folder: str) -> None:
    # CREATE on an existing mailbox returns NO, which is fine.
    try:
        imap.create(_quote(folder))
    except imaplib.IMAP4.error:
        pass


def _move(imap: imaplib.IMAP4, uid: bytes, dest: str) -> bool:
    """Move by UID. Uses MOVE where supported, else COPY + \\Deleted."""
    try:
        typ, _ = imap.uid("MOVE", uid, _quote(dest))
        if typ == "OK":
            return True
    except imaplib.IMAP4.error:
        pass
    try:
        typ, _ = imap.uid("COPY", uid, _quote(dest))
        if typ != "OK":
            return False
        imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        return True
    except imaplib.IMAP4.error:
        return False


def _message_bytes(msg_data: list) -> bytes | None:
    for item in msg_data or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
            return bytes(item[1])
    return None


def drain(settings: Settings, handle: Handler, stats: dict, deadline: float) -> None:
    """Process unseen messages until the mailbox is empty, the message cap is
    reached, or the time budget runs out. Updates `stats` in place."""
    settings.require_imap()
    imap = _connect(settings)
    try:
        _ensure_folder(imap, settings.imap_invalid_folder)
        if settings.imap_processed_folder:
            _ensure_folder(imap, settings.imap_processed_folder)
        typ, _ = imap.select(_quote(settings.imap_folder))
        if typ != "OK":
            raise RuntimeError(f"Cannot open IMAP folder {settings.imap_folder!r}")

        criteria: list[str] = ["UNSEEN"]
        cutoff = settings.cutoff
        if cutoff is not None:
            # SINCE filters on arrival date: old mail is never downloaded.
            # One day of slack, since reports arrive after the period they cover.
            criteria += ["SINCE", imap_date((cutoff - dt.timedelta(days=1)).date())]

        # Re-search after each pass so one run clears a backlog; `attempted`
        # stops messages that failed (and stay unseen) from looping forever.
        attempted: set[bytes] = set()
        moved_any = False
        while time.monotonic() < deadline and stats["fetched"] < settings.max_messages:
            typ, data = imap.uid("SEARCH", None, *criteria)
            if typ != "OK":
                raise RuntimeError(f"IMAP search failed: {typ}")
            uids = [u for u in (data[0].split() if data and data[0] else []) if u not in attempted]
            if not uids:
                stats["drained"] = True
                break
            # Newest first: the dashboard reflects current traffic after the
            # first run while an old backlog fills in over later runs.
            uids.reverse()

            for uid in uids:
                if time.monotonic() > deadline or stats["fetched"] >= settings.max_messages:
                    break
                attempted.add(uid)
                stats["fetched"] += 1
                uid_text = uid.decode("ascii", "replace")
                try:
                    typ, msg_data = imap.uid("FETCH", uid, "(BODY.PEEK[])")
                    raw = _message_bytes(msg_data) if typ == "OK" else None
                    if raw is None:
                        stats["errors"].append({"uid": uid_text, "error": "fetch failed"})
                        continue
                    outcome = handle(raw)
                except (imaplib.IMAP4.abort, OSError, AbortRun):
                    raise  # a connection is gone; abort the run
                except Exception as e:  # noqa: BLE001 - one bad message must not stop the run
                    log.exception("message uid=%s failed; left unseen for retry", uid_text)
                    stats["errors"].append({"uid": uid_text, "error": f"{type(e).__name__}: {e}"})
                    continue

                imap.uid("STORE", uid, "+FLAGS", "(\\Seen)")
                if outcome == "invalid":
                    moved_any |= _move(imap, uid, settings.imap_invalid_folder)
                elif settings.imap_processed_folder:
                    moved_any |= _move(imap, uid, settings.imap_processed_folder)

        if moved_any:
            try:
                imap.expunge()
            except imaplib.IMAP4.error:
                pass
    finally:
        try:
            imap.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            imap.logout()
        except Exception:  # noqa: BLE001
            pass
