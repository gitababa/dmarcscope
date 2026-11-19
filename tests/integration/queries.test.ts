// Runs the real SQL against PostgreSQL. Needs TEST_DATABASE_URL pointing at a
// disposable database (it creates and drops its own schema); skipped otherwise.

import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { machineScope } from '@/lib/auth/access'

const url = process.env.TEST_DATABASE_URL
const SCHEMA = 'dmarcscope_test'
// Every query takes the caller's domain scope; these tests see everything.
const S = machineScope()

vi.mock('node:dns/promises', () => {
  const notFound = () => Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' })
  const txt: Record<string, string[]> = {
    'example.com': ['v=spf1 ip4:192.0.2.0/24 -all'],
    '_dmarc.example.com': ['v=DMARC1; p=quarantine; rua=mailto:d@example.com'],
    'sel1._domainkey.example.com': ['v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'],
  }
  const fns = {
    resolveTxt: async (name: string) => {
      const r = txt[name.toLowerCase()]
      if (!r) throw notFound()
      return r.map((t) => [t])
    },
    resolveMx: async () => [{ exchange: 'mx.example.com', priority: 10 }],
    resolve4: async () => {
      throw notFound()
    },
    resolve6: async () => {
      throw notFound()
    },
  }
  // lib/dns-resolver.ts makes a Resolver per query.
  class Resolver {
    setServers() {}
    cancel() {}
    resolveTxt = fns.resolveTxt
    resolveMx = fns.resolveMx
    resolve4 = fns.resolve4
    resolve6 = fns.resolve6
  }
  return { ...fns, Resolver }
})

describe.skipIf(!url)('database queries', () => {
  let admin: pg.Client

  beforeAll(async () => {
    admin = new pg.Client({ connectionString: url })
    await admin.connect()
    await admin.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA}; SET search_path TO ${SCHEMA}`)
    const dir = path.resolve(__dirname, '../../db/migrations')
    for (const file of (await readdir(dir)).sort()) {
      await admin.query(await readFile(path.join(dir, file), 'utf8'))
    }

    // Two domains; example.com has one aligned Google source and one failing source.
    await admin.query(`
      INSERT INTO domains (id, name) VALUES (1, 'example.com'), (2, 'quiet.example');
      INSERT INTO reports (id, domain_id, org_name, report_id, begin_date, end_date, policy_published) VALUES
        (1, 1, 'google.com', 'r1', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', '{"p":"quarantine","pct":"100","adkim":"r","aspf":"s"}'),
        (2, 1, 'google.com', 'r0', NOW() - INTERVAL '40 days', NOW() - INTERVAL '39 days', '{"p":"none"}');
      INSERT INTO records (report_id, domain_id, source_ip, message_count, dkim_aligned, spf_aligned, dmarc_aligned,
                           envelope_from, dkim_results, spf_results, period_start, period_end) VALUES
        (1, 1, '192.0.2.10', 900, true, true, true, 'example.com',
          '[{"domain":"example.com","selector":"sel1","result":"pass"}]', '[{"domain":"example.com","result":"pass"}]',
          NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
        (1, 1, '198.51.100.7', 60, false, false, false, 'vendor.test',
          '[{"domain":"vendor.test","selector":"v1","result":"pass"}]', '[{"domain":"vendor.test","result":"pass"}]',
          NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
        (1, 1, '198.51.100.7', 40, false, false, false, 'vendor.test',
          '[]', '[{"domain":"vendor.test","result":"fail"}]',
          NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
        (2, 1, '192.0.2.10', 5000, true, false, true, 'example.com', '[]', '[]',
          NOW() - INTERVAL '40 days', NOW() - INTERVAL '39 days');
      INSERT INTO ip_metadata (ip, reverse_dns, base_domain, provider_name) VALUES
        ('192.0.2.10', 'mail-1.google.com', 'google.com', 'Google'),
        ('198.51.100.7', 'unresolved', NULL, 'Vendor Inc');
      INSERT INTO ingest_runs (started_at, finished_at, messages_fetched, reports_parsed, errors) VALUES
        (NOW() - INTERVAL '3 hours', NULL, 0, 0, NULL),
        (NOW() - INTERVAL '1 hour', NOW() - INTERVAL '59 minutes', 12, 10, '[{"error":"x"}]');
    `)

    const u = new URL(url!)
    u.searchParams.set('options', `-c search_path=${SCHEMA}`)
    process.env.DATABASE_URL = u.toString()
  })

  afterAll(async () => {
    const { closePool } = await import('@/lib/db')
    await closePool()
    await admin?.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`)
    await admin?.end()
  })

  it('summarizes domains within the selected range', async () => {
    const q = await import('@/lib/queries')
    const week = await q.getDomainSummaries(S, 7)
    expect(week.map((d) => d.name)).toEqual(['example.com', 'quiet.example'])
    expect(week[0]).toMatchObject({ total_messages: 1000, dmarc_pass: 900, dmarc_fail: 100, report_count: 1, policy: 'quarantine' })
    expect(week[0].pass_rate).toBeCloseTo(0.9)
    expect(week[1]).toMatchObject({ total_messages: 0, policy: null })

    const all = await q.getDomainSummaries(S, 0)
    expect(all[0].total_messages).toBe(6000)
    expect((await q.getDataExtent(S)).total_messages).toBe(6000)
  })

  it('returns timestamps as ISO strings', async () => {
    const q = await import('@/lib/queries')
    const policy = await q.getDomainPolicy(S, 'EXAMPLE.com')
    expect(policy).toMatchObject({ policy: 'quarantine', aspf: 's', adkim: 'r' })
    expect(policy!.latest_report_end).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/)
    expect(await q.getDomainPolicy(S, 'nope.example')).toBeNull()
  })

  it('lists sources and hides the unresolved marker', async () => {
    const q = await import('@/lib/queries')
    const sources = await q.getSourcesForDomain(S, 'example.com', 7)
    expect(sources).toHaveLength(2)
    expect(sources[0]).toMatchObject({ source_ip: '192.0.2.10', reverse_dns: 'mail-1.google.com', total_messages: 900, passed: 900 })
    expect(sources[1]).toMatchObject({ source_ip: '198.51.100.7', reverse_dns: null, provider_name: 'Vendor Inc', failed: 100 })
    expect((await q.getTopSources(S, 7, 1))).toHaveLength(1)
  })

  it('breaks failing mail down by what authentication it carried', async () => {
    const q = await import('@/lib/queries')
    const problems = await q.getProblemSources(S, 7, 50)
    expect(problems).toHaveLength(1)
    expect(problems[0]).toMatchObject({
      source_ip: '198.51.100.7',
      domain: 'example.com',
      failing: 100,
      fail_with_valid_dkim_sig: 60,
      fail_with_raw_spf_pass: 60,
      fail_with_both: 60,
      top_fail_envelope: 'vendor.test',
    })
    expect(await q.getProblemSources(S, 7, 50, 'quiet.example')).toEqual([])
    expect(await q.getProblemSources(S, 7, 50, 'example.com')).toHaveLength(1)
  })

  it('computes alignment, timeseries, signers and run status', async () => {
    const q = await import('@/lib/queries')
    expect(await q.getAlignmentBreakdown(S, 'example.com', 7)).toEqual({
      dmarc_pass: 900,
      dkim_only: 0,
      spf_only: 0,
      fully_aligned: 900,
      fully_failed: 100,
    })
    const series = await q.getVolumeTimeseries(S, 7, 'example.com')
    expect(series).toHaveLength(1)
    expect(series[0]).toMatchObject({ total: 1000, passed: 900 })
    expect(series[0].day).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    // only signers aligned with the domain, not the vendor's own
    expect(await q.getObservedDkimSigners(S, 'example.com')).toEqual([{ selector: 'sel1', signing_domain: 'example.com' }])

    const runs = await q.getRecentIngestRuns(S, 5)
    expect(runs[0]).toMatchObject({ had_errors: true, failed: false, stalled: false, messages_fetched: 12 })
    expect(runs[1]).toMatchObject({ stalled: true, finished_at: null })
  })

  it('does not treat wildcard characters in a reported signing domain as a match', async () => {
    const q = await import('@/lib/queries')
    await admin.query(`
      INSERT INTO records (report_id, domain_id, source_ip, message_count, dkim_results, spf_results, period_start, period_end) VALUES
        (1, 1, '203.0.113.99', 0, '[{"domain":"%","selector":"evil1","result":"pass"},
                                    {"domain":"e_ample.com","selector":"evil2","result":"pass"},
                                    {"domain":"mail.example.com","selector":"sub1","result":"pass"}]', '[]',
          NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day')
    `)
    const signers = await q.getObservedDkimSigners(S, 'example.com')
    expect(signers.map((s) => s.selector).sort()).toEqual(['sel1', 'sub1'])
    await admin.query(`DELETE FROM records WHERE source_ip = '203.0.113.99'`)
  })

  it('reports ingest health from completed, non-failed runs', async () => {
    const q = await import('@/lib/queries')
    // seeded: one run finished 59 minutes ago
    expect(await q.getIngestHealth(S)).toMatchObject({ status: 'ok', stale_after_hours: 36, last_run_failed: false })

    // a newer run that failed outright does not count as success...
    await admin.query(`INSERT INTO ingest_runs (started_at, finished_at, failed) VALUES (NOW() - INTERVAL '1 minute', NOW(), TRUE)`)
    expect(await q.getIngestHealth(S)).toMatchObject({ status: 'ok', last_run_failed: true })

    // ...so once the last good run ages out, the status is stale
    process.env.INGEST_STALE_HOURS = '1'
    await admin.query(`UPDATE ingest_runs SET finished_at = NOW() - INTERVAL '2 hours' WHERE NOT failed AND finished_at IS NOT NULL`)
    const stale = await q.getIngestHealth(S)
    expect(stale).toMatchObject({ status: 'stale', stale_after_hours: 1, last_run_failed: true })
    expect(stale.last_success_at).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    delete process.env.INGEST_STALE_HOURS

    await admin.query(`DELETE FROM ingest_runs`)
    expect(await q.getIngestHealth(S)).toMatchObject({ status: 'never', last_success_at: null })
  })

  it('runs, stores and rate-limits DNS checks', async () => {
    const { runAndStoreDnsCheck } = await import('@/lib/dns-run')
    const q = await import('@/lib/queries')

    expect(await runAndStoreDnsCheck(S, 'unknown.example')).toEqual({ status: 'unknown_domain' })

    const first = await runAndStoreDnsCheck(S, 'example.com')
    expect(first.status).toBe('ok')
    if (first.status !== 'ok') return
    expect(first.results.spf.status).toBe('ok')
    expect(first.results.dkim.selectors.find((s) => s.selector === 'sel1')).toMatchObject({ found: true, observed: true })
    expect(first.results.spf_expanded?.networks).toEqual([{ cidr: '192.0.2.0/24', via: 'top-level' }])

    expect(await runAndStoreDnsCheck(S, 'example.com')).toEqual({ status: 'cooldown' })
    expect((await runAndStoreDnsCheck(S, 'example.com', { force: true })).status).toBe('ok')

    const latest = await q.getLatestDnsChecksByDomain(S)
    expect([...latest.keys()]).toEqual(['example.com'])
    expect((await q.getLatestDnsCheck(S, 'example.com'))?.spf_expanded).toBeTruthy()
    const count = await admin.query('SELECT COUNT(*)::int AS n FROM dns_checks')
    expect(count.rows[0].n).toBe(2)
  })
})
