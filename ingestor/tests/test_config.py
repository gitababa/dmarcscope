"""Settings are read from the environment; mistakes are named, not guessed around."""

import datetime as dt
import json
from pathlib import Path

import pytest

import ingestor
from ingestor.config import ConfigError, load_settings

VARS = [
    "DATABASE_URL", "ALLOWED_DOMAINS", "INGEST_MIN_DATE", "RETENTION_DAYS", "IMAP_HOST", "IMAP_PORT",
    "IMAP_SECURITY", "IMAP_USER", "IMAP_PASSWORD", "IMAP_FOLDER", "IMAP_PROCESSED_FOLDER", "IMAP_INVALID_FOLDER",
    "IMAP_POISON_FOLDER", "INGEST_MAX_MESSAGES", "INGEST_TIME_BUDGET_SECONDS", "INGEST_ENRICH_BUDGET_SECONDS",
]  # fmt: skip


@pytest.fixture()
def env(monkeypatch):
    for name in VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    return monkeypatch


def test_defaults(env):
    s = load_settings()
    assert s.allowed_domains is None and s.cutoff is None
    assert (s.imap_port, s.imap_security, s.imap_folder, s.imap_invalid_folder) == (993, "ssl", "INBOX", "DMARC-Invalid")
    assert (s.max_messages, s.mail_budget_seconds, s.enrich_budget_seconds) == (2000, 600, 60)
    with pytest.raises(ConfigError, match="IMAP_HOST, IMAP_USER, IMAP_PASSWORD"):
        s.require_imap()


def test_database_url_is_required(env):
    env.delenv("DATABASE_URL")
    with pytest.raises(ConfigError, match="DATABASE_URL"):
        load_settings()


def test_allowed_domains_are_normalized(env):
    env.setenv("ALLOWED_DOMAINS", " Example.COM. , ,mail.example.org ")
    assert load_settings().allowed_domains == frozenset({"example.com", "mail.example.org"})
    env.setenv("ALLOWED_DOMAINS", " , ")
    assert load_settings().allowed_domains is None


def test_starttls_changes_the_default_port_only(env):
    env.setenv("IMAP_SECURITY", "STARTTLS")
    assert load_settings().imap_port == 143
    env.setenv("IMAP_PORT", "1143")
    assert load_settings().imap_port == 1143
    env.setenv("IMAP_SECURITY", "plain")
    with pytest.raises(ConfigError, match="IMAP_SECURITY"):
        load_settings()


def test_password_keeps_its_spaces_and_the_old_folder_name_still_works(env):
    env.setenv("IMAP_PASSWORD", " pass word ")
    env.setenv("IMAP_POISON_FOLDER", "Old")
    s = load_settings()
    assert s.imap_password == " pass word " and s.imap_invalid_folder == "Old"
    env.setenv("IMAP_INVALID_FOLDER", "New")
    assert load_settings().imap_invalid_folder == "New"


@pytest.mark.parametrize(
    "name,value,message",
    [
        ("INGEST_MAX_MESSAGES", "many", "whole number"),
        ("INGEST_MAX_MESSAGES", "0", "at least 1"),
        ("INGEST_TIME_BUDGET_SECONDS", "1", "at least 5"),
        ("RETENTION_DAYS", "-3", "at least 0"),
        ("INGEST_MIN_DATE", "01/02/2026", "ISO date"),
    ],
)
def test_bad_values_are_rejected_by_name(env, name, value, message):
    env.setenv(name, value)
    with pytest.raises(ConfigError, match=f"{name}.*{message}"):
        load_settings()


def test_retention_uses_the_later_of_the_two_cutoffs(env):
    env.setenv("INGEST_MIN_DATE", "2020-01-01")
    assert load_settings().cutoff == dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    env.setenv("RETENTION_DAYS", "30")
    cutoff = load_settings().cutoff
    assert dt.timedelta(days=29, hours=23) < dt.datetime.now(dt.timezone.utc) - cutoff < dt.timedelta(days=30, hours=1)
    env.setenv("RETENTION_DAYS", "0")
    assert load_settings().retention_days is None


def test_one_version_number():
    root = Path(__file__).resolve().parents[2]
    package = json.loads((root / "package.json").read_text())["version"]
    assert ingestor.__version__ == package
    assert f"## {package}" in (root / "CHANGELOG.md").read_text(), "CHANGELOG.md has no entry for the current version"


def test_dns_servers_match_the_panel_rules():
    from ingestor.config import parse_dns_servers, split_server

    assert parse_dns_servers(" 1.1.1.1, 9.9.9.9:53 2620:FE::FE ") == ("1.1.1.1", "9.9.9.9", "2620:fe::fe")
    assert parse_dns_servers("10.0.0.2:5353,[2001:db8::53]:5353") == ("10.0.0.2:5353", "[2001:db8::53]:5353")
    for bad in ["", "dns.google", "1.1.1.1:0", "1.1.1.1:70000", "300.1.1.1", "1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5"]:
        with pytest.raises(ValueError):
            parse_dns_servers(bad)
    assert split_server("10.0.0.2:5353") == ("10.0.0.2", 5353)
    assert split_server("[2001:db8::53]:5353") == ("2001:db8::53", 5353)
    assert split_server("2620:fe::fe") == ("2620:fe::fe", 53)


def test_invalid_dns_servers_in_the_environment_is_a_config_error(monkeypatch):
    from ingestor.config import ConfigError, load_settings

    monkeypatch.setenv("DATABASE_URL", "postgresql://x/y")
    monkeypatch.setenv("DNS_SERVERS", "dns.google")
    with pytest.raises(ConfigError, match="DNS_SERVERS"):
        load_settings()
    monkeypatch.setenv("DNS_SERVERS", "1.1.1.1:5353")
    assert load_settings().dns_servers == ("1.1.1.1:5353",)
