"""Reverse-DNS backfill: bounded in time, and a PTR name only counts when the
name resolves back to the address."""

import threading
import time

import psycopg

from ingestor import enrich, store

FORWARD = {"mail.good.test": "192.0.2.1", "mail.google.com": "142.250.0.1", "v6.good.test": "2001:db8::1"}
PTR = {
    "192.0.2.1": "Mail.Good.Test.",
    "198.51.100.66": "mail.google.com",  # attacker-controlled reverse zone
    "2001:db8::1": "v6.good.test",
}


def fake_dns(monkeypatch, slow: set[str] | None = None, gate: threading.Event | None = None):
    def gethostbyaddr(ip):
        if slow and ip in slow:
            gate.wait(30)
        if ip not in PTR:
            raise OSError("no PTR")
        return PTR[ip], [], [ip]

    def getaddrinfo(host, port):
        if host not in FORWARD:
            raise OSError("no such host")
        return [(None, None, None, "", (FORWARD[host], 0))]

    monkeypatch.setattr(enrich.socket, "gethostbyaddr", gethostbyaddr)
    monkeypatch.setattr(enrich.socket, "getaddrinfo", getaddrinfo)


def test_lookup_requires_forward_confirmation(monkeypatch):
    fake_dns(monkeypatch)
    assert enrich._lookup("192.0.2.1") == ("192.0.2.1", "mail.good.test")
    assert enrich._lookup("2001:db8::1") == ("2001:db8::1", "v6.good.test")
    assert enrich._lookup("198.51.100.66") == ("198.51.100.66", None)  # claims to be Google, is not
    assert enrich._lookup("203.0.113.9") == ("203.0.113.9", None)


def _seed(settings, ips):
    with psycopg.connect(settings.database_url, autocommit=True) as conn:
        for ip in ips:
            conn.execute("INSERT INTO ip_metadata (ip) VALUES (%s)", (ip,))


def _names(settings):
    with psycopg.connect(settings.database_url) as conn:
        return dict(conn.execute("SELECT host(ip), reverse_dns FROM ip_metadata").fetchall())


def test_stores_confirmed_names_and_marks_the_rest(monkeypatch, db_settings):
    fake_dns(monkeypatch)
    _seed(db_settings, ["192.0.2.1", "198.51.100.66", "203.0.113.9"])
    conn = store.connect(db_settings)
    try:
        assert enrich.enrich_ip_metadata(conn, 10) == 1
        assert enrich.enrich_ip_metadata(conn, 0) == 0
    finally:
        conn.close()
    assert _names(db_settings) == {"192.0.2.1": "mail.good.test", "198.51.100.66": "unresolved", "203.0.113.9": "unresolved"}


def test_a_stuck_lookup_costs_only_the_time_budget(monkeypatch, db_settings):
    gate = threading.Event()
    fake_dns(monkeypatch, slow={"203.0.113.9"}, gate=gate)
    _seed(db_settings, ["192.0.2.1", "203.0.113.9"])
    conn = store.connect(db_settings)
    try:
        started = time.monotonic()
        assert enrich.enrich_ip_metadata(conn, 0.5) == 1
        assert time.monotonic() - started < 5
    finally:
        conn.close()
        gate.set()
    # the stuck one is left untouched for the next run; its worker cannot hold the process open
    assert _names(db_settings) == {"192.0.2.1": "mail.good.test", "203.0.113.9": None}
    assert all(t.daemon for t in threading.enumerate() if t.name.startswith("rdns-"))
