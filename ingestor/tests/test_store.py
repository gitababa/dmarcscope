import datetime as dt
import json
from dataclasses import replace

import psycopg

from ingestor import runner, store
from ingestor.parsing import parse_file

from .conftest import gz, plain_email, report_email, report_xml, zipped


def _rows(settings, sql):
    with psycopg.connect(settings.database_url) as conn:
        return conn.execute(sql).fetchall()


def _insert(settings, xml: bytes) -> str:
    conn = store.connect(settings)
    try:
        outcome = store.insert_aggregate_report(conn, parse_file(xml)["report"], settings)
        conn.commit()
        return outcome
    finally:
        conn.close()


def test_stores_report_records_and_ip_metadata(db_settings):
    assert _insert(db_settings, report_xml()) == store.STORED

    assert _rows(db_settings, "SELECT name FROM domains") == [("example.com",)]
    begin, end, policy = _rows(db_settings, "SELECT begin_date, end_date, policy_published->>'p' FROM reports")[0]
    assert begin == dt.datetime(2025, 11, 15, 0, 0, 0, tzinfo=dt.timezone.utc)
    assert end == dt.datetime(2025, 11, 15, 23, 59, 59, tzinfo=dt.timezone.utc)
    assert policy == "none"

    rec = _rows(
        db_settings,
        "SELECT host(source_ip), message_count, dkim_aligned, spf_aligned, dmarc_aligned, header_from, "
        "envelope_from, dkim_results->0->>'selector', spf_results->0->>'result' FROM records",
    )
    assert rec == [("209.85.220.41", 12, True, False, True, "example.com", "bounce.vendor.test", "s1", "pass")]

    asn, provider = _rows(db_settings, "SELECT asn, COALESCE(provider_name, as_name) FROM ip_metadata")[0]
    assert asn == 15169 and "Google" in provider


def test_is_idempotent(db_settings):
    assert _insert(db_settings, report_xml()) == store.STORED
    assert _insert(db_settings, report_xml()) == store.DUPLICATE
    assert _rows(db_settings, "SELECT COUNT(*) FROM reports")[0][0] == 1
    assert _rows(db_settings, "SELECT COUNT(*) FROM records")[0][0] == 1
    # same report id from a different reporter is a different report
    assert _insert(db_settings, report_xml(org="yahoo.com")) == store.STORED


def test_filters_by_allowed_domains_and_retention(db_settings):
    only = replace(db_settings, allowed_domains=frozenset({"example.com"}))
    assert _insert(only, report_xml(domain="evil.test")) == store.FILTERED
    assert _insert(only, report_xml(domain="EXAMPLE.com")) == store.STORED

    cutoff = replace(db_settings, min_date=dt.date(2026, 1, 1))
    assert _insert(cutoff, report_xml(report_id="old")) == store.FILTERED
    recent = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)).timestamp())
    rolling = replace(db_settings, retention_days=30)
    assert _insert(rolling, report_xml(report_id="recent", begin=recent, end=recent + 86399)) == store.STORED
    assert _insert(rolling, report_xml(report_id="ancient")) == store.FILTERED


def test_retention_purges_old_reports_and_orphaned_ips(db_settings):
    recent = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)).timestamp())
    _insert(db_settings, report_xml(report_id="old", source_ip="192.0.2.1"))
    _insert(db_settings, report_xml(report_id="new", source_ip="192.0.2.2", begin=recent, end=recent + 86399))

    conn = store.connect(db_settings)
    try:
        assert store.apply_retention(conn, db_settings) == 0  # no retention configured: keep everything
        assert store.apply_retention(conn, replace(db_settings, retention_days=30)) == 1
    finally:
        conn.close()
    assert _rows(db_settings, "SELECT report_id FROM reports") == [("new",)]
    assert _rows(db_settings, "SELECT host(source_ip) FROM records") == [("192.0.2.2",)]
    assert _rows(db_settings, "SELECT host(ip) FROM ip_metadata") == [("192.0.2.2",)]


def test_import_files_walks_directories_and_reports_bad_files(db_settings, tmp_path):
    (tmp_path / "a.xml").write_bytes(report_xml(report_id="a"))
    (tmp_path / "b.xml.gz").write_bytes(gz(report_xml(report_id="b")))
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.zip").write_bytes(zipped(report_xml(report_id="c")))
    (tmp_path / "sub" / "d.eml").write_bytes(report_email(zipped(report_xml(report_id="d"))))
    (tmp_path / "junk.eml").write_bytes(plain_email())
    (tmp_path / "notes.txt").write_text("ignored")

    stats = runner.import_files(db_settings, [str(tmp_path)])
    assert (stats["fetched"], stats["stored"], stats["invalid"]) == (5, 4, 1)
    assert len(stats["errors"]) == 1 and "junk.eml" in stats["errors"][0]["file"]

    again = runner.import_files(db_settings, [str(tmp_path)])
    assert (again["stored"], again["skipped"]) == (0, 4)


def test_only_one_run_at_a_time(db_settings):
    conn = store.connect(db_settings)
    try:
        first = store.start_run(conn, stale_after_seconds=900)
        assert first is not None
        assert store.start_run(conn, stale_after_seconds=900) is None
        store.finish_run(conn, first, {"fetched": 3, "stored": 2, "skipped": 1, "invalid": 0, "errors": [{"error": "x" * 2000}]})
        assert store.start_run(conn, stale_after_seconds=900) is not None
    finally:
        conn.close()
    fetched, parsed, skipped, err_len = _rows(
        db_settings,
        "SELECT messages_fetched, reports_parsed, reports_skipped, length(errors->0->>'error') "
        "FROM ingest_runs WHERE finished_at IS NOT NULL",
    )[0]
    assert (fetched, parsed, skipped, err_len) == (3, 2, 1, 500)


def test_a_crashed_run_does_not_block_forever(db_settings):
    conn = store.connect(db_settings)
    try:
        assert store.start_run(conn, stale_after_seconds=900) is not None
        with conn.cursor() as cur:
            cur.execute("UPDATE ingest_runs SET started_at = NOW() - INTERVAL '2 hours'")
        conn.commit()
        assert store.start_run(conn, stale_after_seconds=900) is not None
    finally:
        conn.close()


def test_only_one_of_two_simultaneous_starts_wins(db_settings):
    import threading

    barrier = threading.Barrier(8)
    results = []

    def start():
        conn = store.connect(db_settings)
        try:
            barrier.wait(10)
            results.append(store.start_run(conn, stale_after_seconds=900))
        finally:
            conn.close()

    threads = [threading.Thread(target=start) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(results) == 8 and len([r for r in results if r is not None]) == 1
    assert _rows(db_settings, "SELECT count(*) FROM ingest_runs") == [(1,)]


def test_what_one_report_can_write_is_bounded(db_settings, monkeypatch):
    monkeypatch.setattr(store, "MAX_RECORDS_PER_REPORT", 3)
    report = parse_file(report_xml())["report"]
    record = report["records"][0]
    record["auth_results"]["dkim"] = [
        {"domain": "d" * 5000, "selector": "s", "result": "pass", "nested": {"a": ["b"] * 1000}} for _ in range(500)
    ]
    report["records"] = [dict(record, source={**record["source"], "ip_address": f"192.0.2.{i}"}) for i in range(10)]
    report["policy_published"] = {**report["policy_published"], "junk": "j" * 100_000, "deep": {"x": 1}, **{f"k{i}": i for i in range(200)}}

    conn = store.connect(db_settings)
    try:
        assert store.insert_aggregate_report(conn, report, db_settings) == store.STORED
        conn.commit()
    finally:
        conn.close()

    rows, results, longest, valid = _rows(
        db_settings,
        "SELECT count(*), max(jsonb_array_length(dkim_results)), max(length(dkim_results->0->>'domain')), bool_and(dkim_sig_valid) FROM records",
    )[0]
    assert (rows, results, longest, valid) == (3, store.MAX_AUTH_RESULTS, 255, True)
    assert _rows(db_settings, "SELECT bool_or(dkim_results->0 ? 'nested') FROM records") == [(False,)]
    keys, policy, junk = _rows(
        db_settings,
        "SELECT (SELECT count(*) FROM jsonb_object_keys(policy_published)), policy_published->>'p', length(policy_published->>'junk') FROM reports",
    )[0]
    assert keys <= store.MAX_JSON_KEYS and policy == "none" and junk == 255
    assert _rows(db_settings, "SELECT policy_published ? 'deep' FROM reports") == [(False,)]


def test_migration_0009_removes_subjects_already_in_run_history(db_settings):
    from pathlib import Path

    old = [
        {"uid": "7", "error": 'not a valid DMARC report: Message with subject "Your medical results" is not a valid DMARC report: x'},
        {"error": "enrichment: TimeoutError: timed out"},
        "a bare string error",
    ]
    with psycopg.connect(db_settings.database_url, autocommit=True) as conn:
        conn.execute("INSERT INTO ingest_runs (finished_at, errors) VALUES (NOW(), %s::jsonb), (NOW(), NULL)", (json.dumps(old),))
        migration = Path(__file__).resolve().parents[2] / "db" / "migrations" / "0009_scrub_run_error_subjects.sql"
        conn.execute(migration.read_text())
    rows = _rows(db_settings, "SELECT errors FROM ingest_runs ORDER BY id")
    scrubbed = rows[0][0]
    assert "medical" not in json.dumps(scrubbed)
    assert scrubbed[0]["uid"] == "7" and scrubbed[0]["error"].startswith("not a DMARC report (details removed")
    assert scrubbed[1:] == old[1:]  # other errors untouched, order kept
    assert rows[1][0] is None
