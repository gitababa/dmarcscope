"""The command line contract: one JSON line on stdout, documented exit codes."""

import json

import pytest

from ingestor import runner
from ingestor.__main__ import main

from .conftest import plain_email, report_xml

FIELDS = {"ok", "fetched", "stored", "skipped", "invalid", "enriched", "purged", "drained", "already_running", "errors"}


def _run(capsys, argv):
    code = main(argv)
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1, "exactly one line of JSON on stdout"
    return code, json.loads(out[0])


def test_missing_database_url_is_a_configuration_error(monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["run"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "DATABASE_URL" in captured.err


def test_import_reports_the_documented_fields_and_exit_codes(monkeypatch, capsys, db_settings, tmp_path):
    monkeypatch.setenv("DATABASE_URL", db_settings.database_url)
    good = tmp_path / "good"
    good.mkdir()
    (good / "a.xml").write_bytes(report_xml(report_id="a"))

    code, out = _run(capsys, ["import", str(good)])
    assert code == 0 and out["ok"] is True
    assert set(out) == FIELDS
    assert (out["fetched"], out["stored"], out["errors"]) == (1, 1, [])

    # a file that is not a report: the rest is loaded, the command still fails
    (good / "junk.eml").write_bytes(plain_email())
    (good / "b.xml").write_bytes(report_xml(report_id="b"))
    code, out = _run(capsys, ["import", str(good)])
    assert code == 1 and out["ok"] is False
    assert (out["stored"], out["invalid"], len(out["errors"])) == (1, 1, 1)
    # The run history never names a non-report by its subject.
    assert "Lunch?" not in out["errors"][0]["error"]


@pytest.mark.parametrize("target", ["empty-dir", "does-not-exist.xml"])
def test_import_fails_when_nothing_was_imported(monkeypatch, capsys, db_settings, tmp_path, target):
    monkeypatch.setenv("DATABASE_URL", db_settings.database_url)
    (tmp_path / "empty-dir").mkdir()
    code, out = _run(capsys, ["import", str(tmp_path / target)])
    assert code == 1 and out["ok"] is False and out["stored"] == 0
    assert set(out) == FIELDS and len(out["errors"]) == 1


def test_run_and_enrich_use_the_same_fields(monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")
    stats = runner._new_stats()
    monkeypatch.setattr(runner, "run_ingest", lambda settings: {**stats, "already_running": True})
    monkeypatch.setattr(runner, "run_enrich", lambda settings: {**stats, "enriched": 3})

    code, out = _run(capsys, ["run"])
    assert code == 0 and out["ok"] is True and out["already_running"] is True and set(out) == FIELDS
    code, out = _run(capsys, ["enrich"])
    assert code == 0 and out["enriched"] == 3 and set(out) == FIELDS


def test_a_fatal_error_exits_1_with_an_error_line(monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")

    def boom(settings):
        raise OSError("mailbox unreachable")

    monkeypatch.setattr(runner, "run_ingest", boom)
    code, out = _run(capsys, ["run"])
    assert code == 1 and out == {"ok": False, "error": "OSError: mailbox unreachable"}


def test_pass_prints_counts_only(monkeypatch, capsys):
    from ingestor import oneshot

    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")
    monkeypatch.setattr(oneshot, "scheduled_pass", lambda s: {"requests": 1, "mailboxes_run": 2, "problems": ["mailbox 3: secret text"]})
    code, out = _run(capsys, ["pass"])
    assert code == 0 and out == {"ok": False, "requests": 1, "mailboxes_run": 2, "problems": 1}
