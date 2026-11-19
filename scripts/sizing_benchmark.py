"""Storage and time per aggregate report: the measurements behind lib/sizing.ts.

    DATABASE_URL=postgresql://…/scratch_db PYTHONPATH=. python scripts/sizing_benchmark.py

Point it at a throwaway, migrated database: it empties the report tables.
"""
import json
import os
import random
import time
import tracemalloc

import psycopg
from ingestor.config import Settings
from ingestor import store
from ingestor.parsing import parse_email
from ingestor.tests.conftest import report_email, zipped

URL = os.environ["DATABASE_URL"]
ORGS = ["google.com", "Outlook.com", "Yahoo", "Mail.Ru", "zoho.com", "comcast.net"]

def xml(domain, org, rid, n, seed):
    rnd = random.Random(seed)
    recs = []
    for i in range(n):
        ip = f"{rnd.randint(1,223)}.{rnd.randint(0,255)}.{rnd.randint(0,255)}.{rnd.randint(1,254)}"
        dk = rnd.choice(["pass", "fail"]); sp = rnd.choice(["pass", "fail", "softfail"])
        recs.append(f"""<record><row><source_ip>{ip}</source_ip><count>{rnd.randint(1,500)}</count>
<policy_evaluated><disposition>none</disposition><dkim>{dk}</dkim><spf>{'pass' if sp=='pass' else 'fail'}</spf></policy_evaluated></row>
<identifiers><header_from>{domain}</header_from><envelope_from>bounce.{domain}</envelope_from></identifiers>
<auth_results><dkim><domain>{domain}</domain><selector>s{i%3}</selector><result>{dk}</result></dkim>
<spf><domain>bounce.{domain}</domain><scope>mfrom</scope><result>{sp}</result></spf></auth_results></record>""")
    return f"""<?xml version="1.0" encoding="UTF-8"?><feedback><version>1.0</version><report_metadata><org_name>{org}</org_name>
<email>noreply@{org}</email><report_id>{rid}</report_id><date_range><begin>1763164800</begin><end>1763251199</end></date_range></report_metadata>
<policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published>
{''.join(recs)}</feedback>""".encode()

def sizes(conn):
    q = "SELECT relname, pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND relkind='r'"
    return dict(conn.execute(q).fetchall())

def reset(conn):
    conn.execute("TRUNCATE reports, records, domains, ip_metadata, discovered_domains RESTART IDENTITY CASCADE")
    conn.execute("VACUUM FULL")

settings = Settings(database_url=URL)
out = {}
for n_records in (1, 5, 20, 100):
    reports = 400 if n_records <= 20 else 100
    with psycopg.connect(URL, autocommit=True) as c:
        reset(c)
        before = sizes(c)
    raws = [report_email(zipped(xml(f"d{i%10}.example.com", ORGS[i % len(ORGS)], f"r{n_records}-{i}", n_records, i))) for i in range(reports)]
    tracemalloc.start()
    t0 = time.perf_counter()
    with psycopg.connect(URL) as conn:
        for raw in raws:
            parsed = parse_email(raw)
            store.insert_aggregate_report(conn, parsed["report"], settings)
            conn.commit()
    elapsed = time.perf_counter() - t0
    peak = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
    with psycopg.connect(URL, autocommit=True) as c:
        c.execute("VACUUM ANALYZE")
        after = sizes(c)
        rows = c.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    grown = {k: after.get(k, 0) - before.get(k, 0) for k in after}
    total = sum(v for k, v in grown.items() if k in ("reports", "records", "domains", "ip_metadata", "discovered_domains"))
    out[n_records] = {
        "reports": reports, "records": rows,
        "db_bytes_per_report": round(total / reports),
        "ms_per_report": round(1000 * elapsed / reports, 1),
        "email_kb": round(sum(map(len, raws)) / reports / 1024, 1),
        "py_peak_mb": round(peak / 1e6, 1),
        "by_table": {k: v for k, v in grown.items() if v},
    }
    print(n_records, json.dumps(out[n_records]), flush=True)
