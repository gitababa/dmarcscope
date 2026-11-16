"""Reverse-DNS backfill for sending IPs.

Parsing runs offline, so reverse DNS is looked up here afterwards, in bounded
time. Lookups run in a thread pool because gethostbyaddr ignores
socket.setdefaulttimeout — a sequential loop would stall on the resolver's
own timeout for every dead IP.
"""

from __future__ import annotations

import ipaddress
import queue
import socket
import threading
import time

import psycopg
from parsedmarc.utils import get_base_domain

BATCH = 500
WORKERS = 24
# Marker for "looked up, no PTR record", so the same dead IPs are not retried
# ahead of new ones on every run. The dashboard treats it as "no reverse DNS".
UNRESOLVED = "unresolved"


def _lookup(ip: str) -> tuple[str, str | None]:
    """Forward-confirmed reverse DNS: the PTR name, but only if that name
    resolves back to the same address. Whoever controls an IP's reverse zone
    can make its PTR say anything (mail.google.com, say); the forward lookup
    is answered by the named domain itself."""
    try:
        host = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
        if not host:
            return ip, None
        want = ipaddress.ip_address(ip)
        for info in socket.getaddrinfo(host, None):
            if ipaddress.ip_address(info[4][0].split("%")[0]) == want:
                return ip, host
        return ip, None
    except (OSError, UnicodeError, ValueError):
        return ip, None


def _base_domain(host: str) -> str:
    try:
        base = get_base_domain(host)
    except Exception:
        base = None
    if base:
        return base
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def enrich_ip_metadata(conn: psycopg.Connection, budget_seconds: float) -> int:
    """Resolve PTR records for IPs that don't have one yet. Returns the number resolved."""
    if budget_seconds <= 0:
        return 0
    with conn.cursor() as cur:
        # Never-attempted IPs first; previously unresolved ones retry at lower priority.
        cur.execute(
            """
            SELECT host(ip) FROM ip_metadata
            WHERE reverse_dns IS NULL OR reverse_dns = %s
            ORDER BY (reverse_dns IS NULL) DESC, last_seen_at DESC
            LIMIT %s
            """,
            (UNRESOLVED, BATCH),
        )
        ips = [row[0] for row in cur.fetchall()]
    conn.commit()
    if not ips:
        return 0

    # Daemon threads rather than a ThreadPoolExecutor: gethostbyaddr cannot
    # be cancelled, and the interpreter waits for executor threads at exit, so
    # one lookup stuck in the resolver would hold the whole job open.
    todo: queue.SimpleQueue = queue.SimpleQueue()
    done: queue.SimpleQueue = queue.SimpleQueue()
    for ip in ips:
        todo.put(ip)

    def work() -> None:
        while True:
            try:
                ip = todo.get_nowait()
            except queue.Empty:
                return
            done.put(_lookup(ip))

    for i in range(min(WORKERS, len(ips))):
        threading.Thread(target=work, name=f"rdns-{i}", daemon=True).start()

    resolved = 0
    deadline = time.monotonic() + budget_seconds
    for _ in ips:
        try:
            ip, host = done.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            # Out of time. Stop handing out work; the rest is picked up next run.
            while True:
                try:
                    todo.get_nowait()
                except queue.Empty:
                    break
            break
        with conn.cursor() as cur:
            if host:
                cur.execute(
                    "UPDATE ip_metadata SET reverse_dns = %s, base_domain = COALESCE(base_domain, %s) WHERE ip = %s",
                    (host[:255], _base_domain(host)[:255], ip),
                )
                resolved += 1
            else:
                cur.execute(
                    "UPDATE ip_metadata SET reverse_dns = COALESCE(reverse_dns, %s) WHERE ip = %s",
                    (UNRESOLVED, ip),
                )
    conn.commit()
    return resolved
