"""Reverse-DNS backfill for sending IPs.

Parsing runs offline, so reverse DNS is looked up here afterwards, in bounded
time. Lookups run in a thread pool because gethostbyaddr ignores
socket.setdefaulttimeout — a sequential loop would stall on the resolver's
own timeout for every dead IP.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError

import psycopg
from parsedmarc.utils import get_base_domain

BATCH = 500
WORKERS = 24
# Marker for "looked up, no PTR record", so the same dead IPs are not retried
# ahead of new ones on every run. The dashboard treats it as "no reverse DNS".
UNRESOLVED = "unresolved"


def _lookup(ip: str) -> tuple[str, str | None]:
    try:
        return ip, socket.gethostbyaddr(ip)[0].rstrip(".").lower() or None
    except (OSError, UnicodeError):
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

    resolved = 0
    pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="rdns")
    futures = [pool.submit(_lookup, ip) for ip in ips]
    try:
        for fut in as_completed(futures, timeout=budget_seconds):
            ip, host = fut.result()
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
    except FuturesTimeoutError:
        pass  # out of time; the rest are picked up by the next run
    finally:
        # Don't wait for lookups still stuck in the resolver.
        pool.shutdown(wait=False, cancel_futures=True)
    conn.commit()
    return resolved
