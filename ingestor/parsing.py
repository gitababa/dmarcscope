"""Thin wrapper around parsedmarc.

parsedmarc runs fully offline here (no DNS, no downloads): reverse DNS is
backfilled separately in bounded time (see enrich.py), and country / network
owner come from the IP database bundled with parsedmarc.
"""

from __future__ import annotations

import email
import os
import re
import time
from email import policy
from typing import Any

# parsedmarc formats report timestamps with the process's local timezone and
# no offset. Pin the process to UTC so those strings mean the same thing on a
# laptop as in a container, and match the UTC session the database uses.
os.environ["TZ"] = "UTC"
if hasattr(time, "tzset"):
    time.tzset()

import parsedmarc  # noqa: E402
from parsedmarc import InvalidDMARCReport, ParserError  # noqa: E402

__all__ = ["InvalidDMARCReport", "ParserError", "parse_email", "parse_file"]

_OPTIONS = {"offline": True, "always_use_local_files": True}

# A few receivers write source addresses with a prefix length
# ("192.0.2.1/32"), which parsedmarc rejects outright.
_CIDR_SOURCE_IP = re.compile(rb"(<source_ip>\s*[0-9A-Fa-f:.]+)/\d{1,3}(\s*</source_ip>)")
_NOT_AN_IP = "does not appear to be an IPv4 or IPv6 address"


def _aggregate(report: Any) -> dict:
    return {"report_type": "aggregate", "report": report}


def _parse_xml_lenient(xml: str | bytes) -> dict:
    data = xml.encode("utf-8", "replace") if isinstance(xml, str) else xml
    return _aggregate(parsedmarc.parse_aggregate_report_xml(_CIDR_SOURCE_IP.sub(rb"\1\2", data), **_OPTIONS))


def _retry_with_clean_ips(raw: bytes) -> dict | None:
    """Re-parse a report after stripping prefix lengths from source IPs."""
    # Bare report file (.xml / .gz / .zip)?
    try:
        return _parse_xml_lenient(parsedmarc.extract_report(raw))
    except Exception:
        pass
    # Otherwise an email: look for the report among its attachments.
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception:
        return None
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        try:
            return _parse_xml_lenient(parsedmarc.extract_report(payload))
        except Exception:
            continue
    return None


def parse_email(raw: bytes) -> dict:
    """Parse a raw RFC 5322 message containing a DMARC report.

    Returns {"report_type": "aggregate" | "failure" | "smtp_tls", "report": ...}.
    Raises InvalidDMARCReport / ParserError if the message is not a report.
    """
    try:
        return dict(parsedmarc.parse_report_email(raw, **_OPTIONS))
    except ParserError as e:  # InvalidDMARCReport is a ParserError
        if _NOT_AN_IP in str(e):
            retried = _retry_with_clean_ips(raw)
            if retried is not None:
                return retried
        raise


def parse_file(raw: bytes) -> dict:
    """Parse a report file: bare XML, gzip, zip, or a saved email (.eml)."""
    try:
        return dict(parsedmarc.parse_report_file(raw, **_OPTIONS))
    except ParserError as e:  # InvalidDMARCReport is a ParserError
        if _NOT_AN_IP in str(e):
            retried = _retry_with_clean_ips(raw)
            if retried is not None:
                return retried
        raise
