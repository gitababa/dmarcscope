"""serve mode against PostgreSQL, a real TLS IMAP server and OAuth token
endpoints (stand-ins): mailboxes configured in the panel, jobs, two workers,
a worker killed mid-run, graceful shutdown."""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ingestor import crypto, oauth, runner, serve, store

from .conftest import plain_email, report_email, report_xml, zipped
from .fake_servers import FakeImapServer, FakeTokenEndpoint, make_tls_files

APP_SECRET = "worker-test-app-secret-0123456789-abcdefghij"
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def tls(tmp_path, monkeypatch):
    cert, key = make_tls_files(tmp_path)
    # The worker verifies certificates; trust the test's own.
    monkeypatch.setenv("SSL_CERT_FILE", cert)
    monkeypatch.setenv("APP_SECRET", APP_SECRET)
    return cert, key


@pytest.fixture()
def imap(tls):
    server = FakeImapServer(*tls)
    yield server
    server.stop()


def db(settings):
    return psycopg.connect(settings.database_url, autocommit=True)


def add_mailbox(settings, *, kind="imap", secret="imap-password", port, username="reports@example.com", tenant=None, client_id=None, enabled=True) -> int:
    with db(settings) as c:
        mid = c.execute(
            """INSERT INTO mailboxes (name, kind, host, port, security, username, tenant_id, client_id, enabled)
               VALUES ('Reports', %s, '127.0.0.1', %s, 'ssl', %s, %s, %s, %s) RETURNING id""",
            (kind, port, username, tenant, client_id, enabled),
        ).fetchone()[0]
        envelope = crypto.encrypt(secret=APP_SECRET, purpose="mailbox", context=f"mailbox:{mid}", plaintext=secret)
        c.execute("UPDATE mailboxes SET secret = %s, secret_updated_at = NOW() WHERE id = %s", (envelope, mid))
    return mid


def add_domains(settings, *names):
    with db(settings) as c:
        for n in names:
            c.execute("INSERT INTO monitored_domains (name) VALUES (%s)", (n,))


def runs(settings, mailbox_id):
    with db(settings) as c:
        return c.execute(
            "SELECT failed, finished_at IS NOT NULL, trigger, reports_parsed, errors FROM ingest_runs WHERE mailbox_id = %s ORDER BY id",
            (mailbox_id,),
        ).fetchall()


def reports(settings):
    with db(settings) as c:
        return [r[0] for r in c.execute("SELECT d.name FROM reports r JOIN domains d ON d.id = r.domain_id ORDER BY d.name").fetchall()]


def report_for(domain: str, rid: str) -> bytes:
    return report_email(zipped(report_xml(domain=domain, report_id=rid)))


def worker(settings, **kw) -> serve.Worker:
    w = serve.Worker(settings, poll_seconds=0.05, **kw)
    w.open()
    return w


def test_reads_a_panel_mailbox_without_any_mailbox_environment_variable(db_settings, imap, monkeypatch):
    for var in ("IMAP_HOST", "IMAP_USER", "IMAP_PASSWORD", "ALLOWED_DOMAINS"):
        monkeypatch.delenv(var, raising=False)
    imap.messages = {1: report_for("example.com", "r1"), 2: report_for("not-ours.test", "r2"), 3: plain_email()}
    mid = add_mailbox(db_settings, port=imap.port)
    add_domains(db_settings, "example.com")
    w = worker(db_settings)
    try:
        assert w.tick() is True
    finally:
        w.close()
    assert reports(db_settings) == ["example.com"]  # the other domain is ignored
    [(failed, finished, trigger, parsed, _)] = runs(db_settings, mid)
    assert (failed, finished, trigger, parsed) == (False, True, "schedule", 1)
    assert imap.logins == ["password"]
    assert imap.seen == {1, 2, 3}
    # not due again until its interval has passed
    w2 = worker(db_settings)
    try:
        assert w2.tick() is False
    finally:
        w2.close()


def test_refuses_to_ingest_while_no_domain_is_monitored(db_settings, imap, monkeypatch):
    monkeypatch.delenv("ALLOWED_DOMAINS", raising=False)
    imap.messages = {1: report_for("example.com", "r1")}
    mid = add_mailbox(db_settings, port=imap.port)
    w = worker(db_settings)
    try:
        w.tick()
    finally:
        w.close()
    [(failed, finished, _, parsed, errors)] = runs(db_settings, mid)
    assert failed and finished and parsed == 0
    assert "no monitored domains" in errors[0]["error"]
    assert reports(db_settings) == [] and imap.seen == set()


def test_a_wrong_password_is_a_failed_run_and_a_failed_test_without_the_password(db_settings, imap, caplog):
    caplog.set_level(logging.DEBUG)
    mid = add_mailbox(db_settings, port=imap.port, secret="wrong-password-canary-1234")
    add_domains(db_settings, "example.com")
    with db(db_settings) as c:
        c.execute("INSERT INTO worker_jobs (kind, mailbox_id) VALUES ('test', %s)", (mid,))
    w = worker(db_settings)
    try:
        w.tick()  # the job
        w.tick()  # the scheduled run
    finally:
        w.close()
    with db(db_settings) as c:
        status, result = c.execute("SELECT status, result FROM worker_jobs").fetchone()
    assert status == "failed" and "Invalid credentials" in result["message"]
    [(failed, _, _, _, errors)] = runs(db_settings, mid)
    assert failed and "Invalid credentials" in json.dumps(errors)
    assert "wrong-password-canary-1234" not in caplog.text + json.dumps(result) + json.dumps(errors)


def test_connection_test_and_run_now(db_settings, imap):
    imap.messages = {1: report_for("example.com", "r1")}
    mid = add_mailbox(db_settings, port=imap.port, enabled=False)  # not scheduled
    add_domains(db_settings, "example.com")
    with db(db_settings) as c:
        c.execute("INSERT INTO worker_jobs (kind, mailbox_id) VALUES ('test', %s), ('run', %s)", (mid, mid))
    w = worker(db_settings)
    try:
        w.tick()
        w.tick()
    finally:
        w.close()
    with db(db_settings) as c:
        jobs = c.execute("SELECT kind, status, result FROM worker_jobs ORDER BY id").fetchall()
    assert jobs[0][:2] == ("test", "done") and "1 unread" in jobs[0][2]["message"]
    assert jobs[1][:2] == ("run", "done") and "1 new report" in jobs[1][2]["message"]
    assert [r[2] for r in runs(db_settings, mid)] == ["manual"]


def test_a_job_for_a_mailbox_deleted_meanwhile(db_settings, imap):
    mid = add_mailbox(db_settings, port=imap.port)
    with db(db_settings) as c:
        c.execute("INSERT INTO worker_jobs (kind, mailbox_id) VALUES ('test', %s)", (mid,))
    w = worker(db_settings)
    try:
        job = store.claim_job(w.conn, w.worker_id)
        with db(db_settings) as c:
            c.execute("DELETE FROM mailboxes WHERE id = %s", (mid,))
        w.handle_job({**job, "mailbox_id": mid})
    finally:
        w.close()
    # the cascade removed the job row with the mailbox; nothing crashed


def test_microsoft_365_client_credentials(db_settings, imap, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    tokens = FakeTokenEndpoint(client_id="app-id", client_secret="ms-client-secret-canary")
    imap.tokens = {tokens.token}
    monkeypatch.setattr(oauth, "MICROSOFT_TOKEN_URL", tokens.url + "/microsoft?tenant={tenant}")
    try:
        imap.messages = {1: report_for("example.com", "r1")}
        add_domains(db_settings, "example.com")
        mid = add_mailbox(db_settings, kind="microsoft", port=imap.port, secret="ms-client-secret-canary", tenant="11111111-2222-3333-4444-555555555555", client_id="app-id")
        w = worker(db_settings)
        try:
            w.tick()
        finally:
            w.close()
        assert imap.logins == ["xoauth2"] and reports(db_settings) == ["example.com"]
        assert tokens.requests[0]["scope"] == "https://outlook.office365.com/.default"

        # a wrong secret: the provider's reason, never the secret
        bad = add_mailbox(db_settings, kind="microsoft", port=imap.port, secret="wrong-ms-secret-canary", tenant="contoso.onmicrosoft.com", client_id="app-id")
        w = worker(db_settings)
        try:
            outcome = w.run_mailbox(bad, "manual")
        finally:
            w.close()
        assert outcome[0] is False and outcome[1].startswith("invalid_client: AADSTS7000215")
        assert "canary" not in outcome[1] + caplog.text + json.dumps(runs(db_settings, bad))
    finally:
        tokens.stop()


def test_token_endpoints_are_fixed():
    assert oauth.GOOGLE_TOKEN_URL == "https://oauth2.googleapis.com/token"
    assert oauth.MICROSOFT_TOKEN_URL.startswith("https://login.microsoftonline.com/{tenant}/")


def test_microsoft_tenant_cannot_change_the_token_url():
    with pytest.raises(oauth.TokenError):
        oauth.microsoft_token("evil.example/../../other", "id", "secret")


def test_google_service_account_with_domain_wide_delegation(db_settings, imap, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    key_json = json.dumps(
        {"type": "service_account", "client_email": "dmarc@project.iam.gserviceaccount.com", "private_key": pem, "private_key_id": "k1",
         # a key file's token_uri is never used
         "token_uri": "https://attacker.example/token"}
    )
    tokens = FakeTokenEndpoint(google_public_key=key.public_key())
    imap.tokens = {tokens.token}
    monkeypatch.setattr(oauth, "GOOGLE_TOKEN_URL", tokens.url + "/google")
    try:
        imap.messages = {1: report_for("example.com", "r1")}
        add_domains(db_settings, "example.com")
        add_mailbox(db_settings, kind="google", port=imap.port, secret=key_json)
        w = worker(db_settings)
        try:
            w.tick()
        finally:
            w.close()
        assert imap.logins == ["xoauth2"] and reports(db_settings) == ["example.com"]
        claims = tokens.requests[0]["claims"]
        assert claims["iss"] == "dmarc@project.iam.gserviceaccount.com"
        assert claims["sub"] == "reports@example.com"
        assert claims["scope"] == "https://mail.google.com/"
        assert claims["exp"] - claims["iat"] <= 3600
        # the audience is the fixed token endpoint the worker posts to, not the key file's token_uri
        assert claims["aud"] == tokens.url + "/google" and "attacker" not in json.dumps(tokens.requests)
    finally:
        tokens.stop()


def test_a_broken_service_account_key_is_reported(db_settings, imap):
    add_domains(db_settings, "example.com")
    mid = add_mailbox(db_settings, kind="google", port=imap.port, secret='{"type": "authorized_user"}')
    w = worker(db_settings)
    try:
        ok, message = w.run_mailbox(mid, "manual")
    finally:
        w.close()
    assert not ok and "service-account key" in message


def test_a_secret_from_another_app_secret_is_reported_not_used(db_settings, imap, monkeypatch):
    add_domains(db_settings, "example.com")
    mid = add_mailbox(db_settings, port=imap.port)
    monkeypatch.setenv("APP_SECRET", "a-different-app-secret-0000000000000000")
    w = worker(db_settings)
    try:
        ok, message = w.run_mailbox(mid, "manual")
    finally:
        w.close()
    assert not ok and "cannot be decrypted (unknown_key)" in message
    assert runs(db_settings, mid)[0][0] is True  # recorded as a failed run


def test_two_workers_never_read_one_mailbox_at_once(db_settings, imap):
    imap.messages = {1: report_for("example.com", "r1"), 2: report_for("example.com", "r2")}
    add_domains(db_settings, "example.com")
    mid = add_mailbox(db_settings, port=imap.port)
    a, b = worker(db_settings), worker(db_settings)
    inside = threading.Event()
    release = threading.Event()

    def slow_fetch(uid):
        inside.set()
        release.wait(5)

    imap.on_fetch = slow_fetch
    t = threading.Thread(target=a.run_mailbox, args=(mid, "schedule"))
    t.start()
    try:
        assert inside.wait(5)
        assert b.run_mailbox(mid, "schedule") is None  # a holds it
    finally:
        imap.on_fetch = None
        release.set()
        t.join(10)
        a.close()
        b.close()
    assert len(runs(db_settings, mid)) == 1


def test_two_workers_never_take_the_same_job(db_settings, imap):
    mid = add_mailbox(db_settings, port=imap.port)
    with db(db_settings) as c:
        c.execute("INSERT INTO worker_jobs (kind, mailbox_id) VALUES ('test', %s), ('test', %s)", (mid, mid))
    a, b = worker(db_settings), worker(db_settings)
    try:
        ja, jb = store.claim_job(a.conn, a.worker_id), store.claim_job(b.conn, b.worker_id)
        assert ja and jb and ja["id"] != jb["id"]
        assert store.claim_job(a.conn, a.worker_id) is None
    finally:
        a.close()
        b.close()


def test_graceful_stop_closes_the_run_and_leaves_the_rest_for_next_time(db_settings, imap):
    imap.messages = {1: report_for("example.com", "r1"), 2: report_for("example.com", "r2"), 3: report_for("example.com", "r3")}
    add_domains(db_settings, "example.com")
    mid = add_mailbox(db_settings, port=imap.port)
    w = worker(db_settings)
    imap.on_fetch = lambda uid: w.stop.set()  # SIGTERM arrives while the first message is read
    try:
        ok, message = w.run_mailbox(mid, "schedule")
    finally:
        imap.on_fetch = None
        w.close()
    assert not ok and "interrupted" in message
    [(failed, finished, _, parsed, errors)] = runs(db_settings, mid)
    assert failed and finished and parsed == 1  # the message in hand was finished
    assert "interrupted" in errors[-1]["error"]
    assert len(imap.seen) == 1  # the others are left for the next run

    w2 = worker(db_settings)
    try:
        ok, _ = w2.run_mailbox(mid, "manual")
    finally:
        w2.close()
    assert ok and len(imap.seen) == 3 and len(reports(db_settings)) == 3


def test_a_killed_worker_leaves_a_closed_failed_run_and_the_next_run_proceeds(db_settings, imap, tls, tmp_path):
    imap.messages = {1: report_for("example.com", "r1"), 2: report_for("example.com", "r2")}
    add_domains(db_settings, "example.com")
    mid = add_mailbox(db_settings, port=imap.port)
    reached = threading.Event()
    hold = threading.Event()

    def stall(uid):
        reached.set()
        hold.wait(20)

    imap.on_fetch = stall
    env = {**os.environ, "DATABASE_URL": db_settings.database_url, "APP_SECRET": APP_SECRET, "SSL_CERT_FILE": tls[0]}
    for var in ("IMAP_HOST", "IMAP_USER", "IMAP_PASSWORD", "ALLOWED_DOMAINS"):
        env.pop(var, None)
    proc = subprocess.Popen([sys.executable, "-m", "ingestor", "serve"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        assert reached.wait(20), proc.stderr.read().decode() if proc.poll() is not None else "worker never fetched"
        proc.send_signal(signal.SIGKILL)  # no chance to clean up
        proc.wait(10)
    finally:
        imap.on_fetch = None
        hold.set()
        if proc.poll() is None:
            proc.kill()
    [(failed, finished, *_)] = runs(db_settings, mid)
    assert (failed, finished) == (False, False)  # left open by the dead worker

    deadline = time.time() + 10
    while time.time() < deadline:  # the server notices the dead connection quickly
        w = worker(db_settings)
        try:
            outcome = w.run_mailbox(mid, "manual")
        finally:
            w.close()
        if outcome is not None:
            break
        time.sleep(0.2)
    assert outcome[0] is True
    first, second = runs(db_settings, mid)
    assert first[0] is True and first[1] is True and "interrupted" in json.dumps(first[4])
    assert second[0] is False and second[1] is True
    assert len(reports(db_settings)) == 2


def test_jobs_left_by_a_dead_worker_are_failed(db_settings, imap):
    mid = add_mailbox(db_settings, port=imap.port)
    with db(db_settings) as c:
        c.execute("INSERT INTO worker_jobs (kind, mailbox_id, status, claimed_by, claimed_at) VALUES ('run', %s, 'running', 'gone:1:x', NOW())", (mid,))
    w = worker(db_settings)
    try:
        assert store.fail_abandoned_jobs(w.conn, 120) == 1
    finally:
        w.close()


def test_environment_runs_pick_up_panel_domains_and_retention(db_settings, monkeypatch):
    add_domains(db_settings, "example.com")
    with db(db_settings) as c:
        c.execute("""INSERT INTO settings (key, value) VALUES ('ingest.retention_days', '30')""")
    conn = store.connect(db_settings)
    try:
        s = runner.with_panel_settings(conn, db_settings)
        assert s.allowed_domains == frozenset({"example.com"}) and s.retention_days == 30
        # the environment wins
        from dataclasses import replace

        s2 = runner.with_panel_settings(conn, replace(db_settings, allowed_domains=frozenset({"env.example"}), retention_days=7))
        assert s2.allowed_domains == frozenset({"env.example"}) and s2.retention_days == 7
        with db(db_settings) as c:
            c.execute("""UPDATE settings SET value = '"forever"' WHERE key = 'ingest.retention_days'""")
        assert runner.with_panel_settings(conn, db_settings).retention_days is None  # invalid: nothing purged
        with db(db_settings) as c:
            c.execute("""UPDATE settings SET value = '30' WHERE key = 'ingest.retention_days'""")
        monkeypatch.setenv("RETENTION_DAYS", "0")  # the environment says forever, and wins
        assert runner.with_panel_settings(conn, db_settings).retention_days is None
    finally:
        conn.close()


def test_an_unreachable_mailbox_is_a_failed_run_and_the_worker_goes_on(db_settings, imap):
    import socket as _socket

    s = _socket.socket()
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()  # nothing listens there now
    add_domains(db_settings, "example.com")
    down = add_mailbox(db_settings, port=closed_port)
    imap.messages = {1: report_for("example.com", "r1")}
    up = add_mailbox(db_settings, port=imap.port)
    w = worker(db_settings)
    try:
        w.tick()  # both are due: the first fails, the second still runs
    finally:
        w.close()
    [(failed, finished, _, _, errors)] = runs(db_settings, down)
    assert failed and finished and "ConnectionRefused" in json.dumps(errors)
    assert runs(db_settings, up)[0][0] is False and reports(db_settings) == ["example.com"]


def test_the_database_lost_mid_run(db_settings, imap):
    imap.messages = {1: report_for("example.com", "r1"), 2: report_for("example.com", "r2"), 3: report_for("example.com", "r3")}
    add_domains(db_settings, "example.com")
    mid = add_mailbox(db_settings, port=imap.port)
    calls = []

    def cut(uid):
        calls.append(uid)
        if len(calls) == 2:
            # Every connection of the run itself (not the test's, not the
            # worker's lock connection) is cut, as by a database restart.
            with db(db_settings) as c:
                c.execute(
                    """SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                       WHERE datname = current_database() AND pid <> pg_backend_pid()
                         AND query NOT ILIKE '%%advisory%%' AND application_name = ''"""
                )

    imap.on_fetch = cut
    w = worker(db_settings)
    try:
        outcome = w.run_mailbox(mid, "manual")
    finally:
        imap.on_fetch = None
        w.close()
    assert outcome is not None and outcome[0] is False and "database connection lost" in outcome[1]
    # Only the message stored before the cut was marked read: the rest is retried.
    assert len(imap.seen) == 1

    w2 = worker(db_settings)
    try:
        ok, _ = w2.run_mailbox(mid, "manual")
    finally:
        w2.close()
    assert ok and len(reports(db_settings)) == 3
    first, second = runs(db_settings, mid)
    assert first[:2] == (True, True) and first[3] == 1 and "database connection lost" in json.dumps(first[4])
    assert second[:2] == (False, True) and second[3] == 2


def test_housekeeping_is_done_by_one_run_at_a_time(db_settings, imap, monkeypatch):
    calls = []
    monkeypatch.setattr(store, "apply_retention", lambda conn, settings: calls.append("retention") or 0)
    from ingestor import enrich as enrich_mod

    monkeypatch.setattr(enrich_mod, "enrich_ip_metadata", lambda conn, budget: calls.append("enrich") or 0)
    add_domains(db_settings, "example.com")
    mid = add_mailbox(db_settings, port=imap.port)
    holder, w = worker(db_settings), worker(db_settings)
    try:
        assert store.try_lock_housekeeping(holder.lock_conn)  # another worker is busy with it
        assert w.run_mailbox(mid, "manual")[0] is True
        assert calls == []
        store.unlock_housekeeping(holder.lock_conn)
        assert w.run_mailbox(mid, "manual")[0] is True
        assert calls == ["retention", "enrich"]
        assert store.try_lock_housekeeping(holder.lock_conn)  # released after the run
    finally:
        holder.close()
        w.close()
