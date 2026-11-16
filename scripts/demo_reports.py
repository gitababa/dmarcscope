#!/usr/bin/env python3
"""Generate synthetic DMARC aggregate reports for trying out the dashboard.

    python scripts/demo_reports.py ./demo-reports
    python -m ingestor import ./demo-reports

Writes one XML report per (day, reporting provider, domain) for the last
45 days, covering the situations the dashboard is built to explain: healthy
aligned mail, a forwarder, a marketing service missing DKIM, an unauthorized
sender and spoofing. Domains are RFC 2606 reserved names; the "spoofing" and
"unknown" sources use RFC 5737 documentation addresses.
"""

from __future__ import annotations

import datetime as dt
import random
import sys
import zlib
from pathlib import Path
from xml.sax.saxutils import escape

DAYS = 45

REPORTERS = [
    ("google.com", "noreply-dmarc-support@google.com", 0.55),
    ("Outlook.com", "dmarcreport@microsoft.com", 0.25),
    ("Yahoo", "dmarchelp@yahooinc.com", 0.12),
    ("Mail.Ru", "dmarc_support@corp.mail.ru", 0.08),
]

# (domain, policy, base daily volume)
DOMAINS = [
    ("example.com", "quarantine", 9000),
    ("example.org", "none", 2600),
    ("mail.example.net", "reject", 700),
]

# Sources per domain: ip, share of volume, dkim aligned, spf aligned,
# dkim auth (domain, selector, result), spf auth (domain, result)
def sources_for(domain: str):
    return [
        # Google Workspace: fully aligned
        ("209.85.220.41", 0.46, True, True, (domain, "google", "pass"), (domain, "pass")),
        ("209.85.220.69", 0.20, True, True, (domain, "google", "pass"), (domain, "pass")),
        # Amazon SES with Easy DKIM but default MAIL FROM: DKIM-only alignment
        ("54.240.8.31", 0.16, True, False, (domain, "ses1", "pass"), ("amazonses.com", "pass")),
        # Marketing platform never set up for this domain: fails both
        ("149.72.61.130", 0.07 if domain != "mail.example.net" else 0.0, False, False, ("sendgrid.net", "s1", "pass"), ("sendgrid.net", "pass")),
        # Mailing list / forwarder: original DKIM survives, SPF breaks
        ("203.0.113.25", 0.05, True, False, (domain, "google", "pass"), ("lists.example.edu", "pass")),
        # Forwarder that rewrites the body: DKIM breaks too
        ("203.0.113.77", 0.03, False, False, (domain, "google", "fail"), ("forwarder.example.edu", "pass")),
        # Spoofing
        ("198.51.100.200", 0.03, False, False, None, ("unrelated.example", "fail")),
    ]


def record_xml(domain, policy, ip, count, dkim_ok, spf_ok, dkim_auth, spf_auth) -> str:
    passed = dkim_ok or spf_ok
    disposition = "none" if passed or policy == "none" else policy
    dkim_xml = ""
    if dkim_auth:
        d, sel, res = dkim_auth
        dkim_xml = f"<dkim><domain>{escape(d)}</domain><selector>{escape(sel)}</selector><result>{res}</result></dkim>"
    sd, sres = spf_auth
    return f"""
  <record>
    <row>
      <source_ip>{ip}</source_ip>
      <count>{count}</count>
      <policy_evaluated>
        <disposition>{disposition}</disposition>
        <dkim>{'pass' if dkim_ok else 'fail'}</dkim>
        <spf>{'pass' if spf_ok else 'fail'}</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>{escape(domain)}</header_from></identifiers>
    <auth_results>{dkim_xml}<spf><domain>{escape(sd)}</domain><result>{sres}</result></spf></auth_results>
  </record>"""


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(7)
    today = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    written = 0
    for back in range(DAYS, 0, -1):
        begin = today - dt.timedelta(days=back)
        end = begin + dt.timedelta(days=1) - dt.timedelta(seconds=1)
        weekday_factor = 0.45 if begin.weekday() >= 5 else 1.0
        for org, org_email, share in REPORTERS:
            for domain, policy, volume in DOMAINS:
                records = []
                for ip, src_share, dkim_ok, spf_ok, dkim_auth, spf_auth in sources_for(domain):
                    # The marketing sender gets fixed 12 days ago on example.com.
                    if ip == "149.72.61.130" and domain == "example.com" and back <= 12:
                        dkim_ok, dkim_auth = True, (domain, "s1", "pass")
                    count = int(volume * share * src_share * weekday_factor * rng.uniform(0.75, 1.25))
                    if count > 0:
                        records.append(record_xml(domain, policy, ip, count, dkim_ok, spf_ok, dkim_auth, spf_auth))
                if not records:
                    continue
                # (Kept free of nested same-quote f-strings, which need Python 3.12.)
                checksum = zlib.crc32((org + "|" + domain).encode())
                report_id = f"{begin:%Y%m%d}-{checksum}-{back}"
                xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>{escape(org)}</org_name>
    <email>{escape(org_email)}</email>
    <report_id>{report_id}</report_id>
    <date_range><begin>{int(begin.timestamp())}</begin><end>{int(end.timestamp())}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>{escape(domain)}</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>{policy}</p><sp>{policy}</sp><pct>100</pct>
  </policy_published>{''.join(records)}
</feedback>
"""
                name = f"{org.lower().replace('.', '-')}!{domain}!{int(begin.timestamp())}!{int(end.timestamp())}.xml"
                (out / name).write_text(xml, encoding="utf-8")
                written += 1
    print(f"Wrote {written} reports to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
