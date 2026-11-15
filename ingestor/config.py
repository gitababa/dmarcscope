"""Configuration, read from environment variables."""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """A setting is missing or invalid. The message never contains secrets."""


def _str(name: str, default: str | None = None) -> str | None:
    val = (os.environ.get(name) or "").strip()
    return val or default


def _int(name: str, default: int, minimum: int = 0) -> int:
    raw = _str(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from None
    if val < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return val


@dataclass(frozen=True)
class Settings:
    database_url: str

    # Only reports for these domains are stored (None = all). Recommended for
    # a shared mailbox: anyone can email a "report" about any domain.
    allowed_domains: frozenset[str] | None = None
    # Fixed cutoff: reports ending before this date are neither stored nor kept.
    min_date: dt.date | None = None
    # Rolling retention: reports older than this many days are deleted.
    retention_days: int | None = None

    imap_host: str | None = None
    imap_port: int = 993
    imap_security: str = "ssl"  # "ssl" (implicit TLS) or "starttls"
    imap_user: str | None = None
    imap_password: str | None = None
    imap_folder: str = "INBOX"
    imap_processed_folder: str | None = None
    imap_invalid_folder: str = "DMARC-Invalid"

    max_messages: int = 2000
    mail_budget_seconds: int = 600
    enrich_budget_seconds: int = 60

    @property
    def cutoff(self) -> dt.datetime | None:
        """Effective retention cutoff (UTC), combining both retention settings."""
        candidates: list[dt.datetime] = []
        if self.min_date:
            candidates.append(dt.datetime.combine(self.min_date, dt.time.min, tzinfo=dt.timezone.utc))
        if self.retention_days:
            candidates.append(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=self.retention_days))
        return max(candidates) if candidates else None

    def require_imap(self) -> None:
        missing = [
            name
            for name, val in (
                ("IMAP_HOST", self.imap_host),
                ("IMAP_USER", self.imap_user),
                ("IMAP_PASSWORD", self.imap_password),
            )
            if not val
        ]
        if missing:
            raise ConfigError(f"Missing required setting(s): {', '.join(missing)}")


def load_settings() -> Settings:
    database_url = _str("DATABASE_URL")
    if not database_url:
        raise ConfigError("Missing required setting: DATABASE_URL")

    raw_domains = _str("ALLOWED_DOMAINS")
    allowed = frozenset(d.strip().lower().rstrip(".") for d in raw_domains.split(",") if d.strip()) if raw_domains else None

    raw_min = _str("INGEST_MIN_DATE")
    min_date = None
    if raw_min:
        try:
            min_date = dt.date.fromisoformat(raw_min)
        except ValueError:
            raise ConfigError(f"INGEST_MIN_DATE must be an ISO date like 2026-01-01, got {raw_min!r}") from None

    security = (_str("IMAP_SECURITY", "ssl") or "ssl").lower()
    if security not in ("ssl", "starttls"):
        raise ConfigError("IMAP_SECURITY must be 'ssl' or 'starttls'")

    # IMAP_POISON_FOLDER is the pre-1.0 name of IMAP_INVALID_FOLDER.
    invalid_folder = _str("IMAP_INVALID_FOLDER") or _str("IMAP_POISON_FOLDER") or "DMARC-Invalid"

    return Settings(
        database_url=database_url,
        allowed_domains=allowed or None,
        min_date=min_date,
        retention_days=_int("RETENTION_DAYS", 0) or None,
        imap_host=_str("IMAP_HOST"),
        imap_port=_int("IMAP_PORT", 993 if security == "ssl" else 143, 1),
        imap_security=security,
        imap_user=_str("IMAP_USER"),
        # Not stripped: a password may legitimately contain spaces.
        imap_password=os.environ.get("IMAP_PASSWORD") or None,
        imap_folder=_str("IMAP_FOLDER", "INBOX") or "INBOX",
        imap_processed_folder=_str("IMAP_PROCESSED_FOLDER"),
        imap_invalid_folder=invalid_folder,
        max_messages=_int("INGEST_MAX_MESSAGES", 2000, 1),
        mail_budget_seconds=_int("INGEST_TIME_BUDGET_SECONDS", 600, 5),
        enrich_budget_seconds=_int("INGEST_ENRICH_BUDGET_SECONDS", 60, 0),
    )
