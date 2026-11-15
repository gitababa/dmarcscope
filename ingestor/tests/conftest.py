"""Shared fixtures. Database tests need TEST_DATABASE_URL (a disposable
PostgreSQL database); they are skipped when it is not set."""

from __future__ import annotations

import gzip
import io
import os
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

SCHEMA = "dmarcscope_pytest"
MIGRATIONS = Path(__file__).resolve().parents[2] / "db" / "migrations"


def report_xml(
    *,
    domain: str = "example.com",
    org: str = "google.com",
    report_id: str = "rep-1",
    begin: int = 1763164800,  # 2025-11-15 00:00:00 UTC
    end: int = 1763251199,
    source_ip: str = "209.85.220.41",
    count: int = 12,
    dkim: str = "pass",
    spf: str = "fail",
) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>{org}</org_name>
    <email>noreply@{org}</email>
    <report_id>{report_id}</report_id>
    <date_range><begin>{begin}</begin><end>{end}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>{source_ip}</source_ip>
      <count>{count}</count>
      <policy_evaluated><disposition>none</disposition><dkim>{dkim}</dkim><spf>{spf}</spf></policy_evaluated>
    </row>
    <identifiers><header_from>{domain}</header_from></identifiers>
    <auth_results>
      <dkim><domain>{domain}</domain><selector>s1</selector><result>{dkim}</result></dkim>
      <spf><domain>bounce.vendor.test</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
""".encode()


def gz(data: bytes) -> bytes:
    return gzip.compress(data)


def zipped(data: bytes, name: str = "report.xml") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return buf.getvalue()


def report_email(attachment: bytes, filename: str = "google.com!example.com!1763164800!1763251199.zip") -> bytes:
    msg = EmailMessage()
    msg["From"] = "noreply-dmarc-support@google.com"
    msg["To"] = "dmarc@example.com"
    msg["Subject"] = "Report domain: example.com Submitter: google.com Report-ID: rep-1"
    msg["Date"] = "Sun, 16 Nov 2025 01:00:00 +0000"
    msg.set_content("This is a DMARC aggregate report.")
    subtype = "zip" if filename.endswith(".zip") else "gzip"
    msg.add_attachment(attachment, maintype="application", subtype=subtype, filename=filename)
    return msg.as_bytes()


def plain_email() -> bytes:
    msg = EmailMessage()
    msg["From"] = "someone@example.net"
    msg["To"] = "dmarc@example.com"
    msg["Subject"] = "Lunch?"
    msg["Date"] = "Sun, 16 Nov 2025 01:00:00 +0000"
    msg.set_content("Not a report.")
    return msg.as_bytes()


@pytest.fixture()
def db_settings():
    """Settings pointing at a freshly migrated, empty schema."""
    import psycopg

    from ingestor.config import Settings

    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set")

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
        conn.execute(f"CREATE SCHEMA {SCHEMA}")
        conn.execute(f"SET search_path TO {SCHEMA}")
        for path in sorted(MIGRATIONS.glob("*.sql")):
            conn.execute(path.read_text())

    sep = "&" if "?" in url else "?"
    yield Settings(database_url=f"{url}{sep}options=-csearch_path%3D{SCHEMA}")

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
