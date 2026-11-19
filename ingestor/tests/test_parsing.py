import time

import pytest

from ingestor.parsing import InvalidDMARCReport, ParserError, parse_email, parse_file

from .conftest import gz, plain_email, report_email, report_xml, zipped


def _first_record(parsed):
    assert parsed["report_type"] == "aggregate"
    return parsed["report"]["records"][0]


@pytest.mark.parametrize("wrap", [lambda b: b, gz, zipped], ids=["xml", "gzip", "zip"])
def test_parses_report_files(wrap):
    parsed = parse_file(wrap(report_xml()))
    report = parsed["report"]
    assert report["policy_published"]["domain"] == "example.com"
    assert report["report_metadata"]["report_id"] == "rep-1"
    rec = _first_record(parsed)
    assert rec["source"]["ip_address"] == "209.85.220.41"
    assert rec["count"] == 12
    assert rec["alignment"] == {"spf": False, "dkim": True, "dmarc": True}
    assert rec["auth_results"]["dkim"][0]["selector"] == "s1"


def test_timestamps_are_utc_regardless_of_host_timezone():
    # The module pins the process to UTC; a report covering a UTC day must
    # come back as exactly that day.
    assert time.tzname[0] == "UTC"
    meta = parse_file(report_xml())["report"]["report_metadata"]
    assert meta["begin_date"] == "2025-11-15 00:00:00"
    assert meta["end_date"] == "2025-11-15 23:59:59"


@pytest.mark.parametrize("attachment", [zipped(report_xml()), gz(report_xml())], ids=["zip", "gzip"])
def test_parses_report_emails(attachment):
    name = "report.zip" if attachment[:2] == b"PK" else "report.xml.gz"
    parsed = parse_email(report_email(attachment, name))
    assert _first_record(parsed)["count"] == 12


def test_offline_enrichment_identifies_the_network_owner():
    source = _first_record(parse_file(report_xml()))["source"]
    assert source["reverse_dns"] is None  # no DNS at parse time
    assert source["asn"] == 15169
    assert "Google" in (source["name"] or source["as_name"])


def test_tolerates_prefix_length_on_source_ip():
    xml = report_xml(source_ip="192.0.2.77/32")
    for parsed in (parse_file(xml), parse_file(gz(xml)), parse_email(report_email(zipped(xml)))):
        assert _first_record(parsed)["source"]["ip_address"] == "192.0.2.77"


def test_rejects_non_reports():
    with pytest.raises((InvalidDMARCReport, ParserError)):
        parse_email(plain_email())
    with pytest.raises((InvalidDMARCReport, ParserError)):
        parse_file(b"<html><body>hello</body></html>")
    with pytest.raises((InvalidDMARCReport, ParserError)):
        parse_file(report_xml(source_ip="not-an-address"))


def _private_email(subject: str, attachment: bytes | None = None, date: str = "Sun, 16 Nov 2025 01:00:00 +0000") -> bytes:
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "friend@example.net"
    msg["To"] = "me@example.com"
    msg["Subject"] = subject
    msg["Date"] = date
    msg.set_content("Personal message.")
    if attachment is not None:
        msg.add_attachment(attachment, maintype="application", subtype="zip", filename="report.zip")
    return msg.as_bytes()


@pytest.mark.parametrize(
    "raw",
    [
        _private_email("Your medical results are ready"),
        _private_email("Your medical results are ready", attachment=b"PK\x03\x04 not really a zip"),
        _private_email("Your medical results are ready", attachment=gz(b"<feedback>broken")),
    ],
    ids=["plain", "fake-zip", "broken-xml"],
)
def test_the_reason_for_a_non_report_never_names_its_subject(raw):
    from ingestor.runner import invalid_reason

    with pytest.raises(ParserError) as caught:
        parse_email(raw)
    assert "medical" in str(caught.value)  # parsedmarc's own text does name it
    reason = invalid_reason(caught.value)
    assert "medical" not in reason.lower() and "subject" not in reason.lower()
    assert reason.startswith("not a DMARC report")


def test_a_reason_that_names_no_message_keeps_its_detail():
    from ingestor.runner import invalid_reason

    assert invalid_reason(ParserError("Not a valid zip, gzip, json, or xml file")) == (
        "not a valid DMARC report: Not a valid zip, gzip, json, or xml file"
    )
