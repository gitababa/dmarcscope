import type { Metadata } from 'next'
import Link from 'next/link'
import {
  getDomainSummaries,
  getTopSources,
  getRecentIngestRuns,
  getDataExtent,
  getIngestHealth,
  getVolumeTimeseries,
} from '@/lib/queries'
import { requireViewer } from '@/lib/auth/server'
import { identifySource } from '@/lib/senders'
import { fmtInt, fmtDate, pct, relTime, parseRange, rangeParam, rangeLabel, policyTone } from '@/lib/format'
import { VolumeChart } from '@/components/VolumeChart'
import { CategoryPill, Pill, RangeSwitcher, RateCell, Section, SourceCell, Stat, rateTone } from '@/components/ui'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Overview' }

export default async function OverviewPage({
  searchParams,
}: {
  searchParams: Promise<{ range?: string }>
}) {
  await requireViewer() // each page checks for itself; it does not rely on the layout or the proxy
  const { range: rawRange } = await searchParams
  const days = parseRange(rawRange)

  const [domains, sources, runs, health, timeseries] = await Promise.all([
    getDomainSummaries(days),
    getTopSources(days, 10),
    getRecentIngestRuns(5),
    getIngestHealth(),
    getVolumeTimeseries(days),
  ])

  const totals = domains.reduce(
    (acc, d) => {
      acc.messages += d.total_messages
      acc.pass += d.dmarc_pass
      acc.fail += d.dmarc_fail
      acc.dkim += d.dkim_pass
      acc.spf += d.spf_pass
      return acc
    },
    { messages: 0, pass: 0, fail: 0, dkim: 0, spf: 0 }
  )
  const hasData = totals.messages > 0
  const rate = (n: number) => (hasData ? n / totals.messages : NaN)
  const range = rangeParam(days)
  const lastRun = runs[0]
  // The whole-table extent is only needed to explain an empty window.
  const extent = !hasData && days !== 0 && domains.length > 0 ? await getDataExtent() : null
  const staleNotice = health.status === 'stale' && (
    <div className="notice warn" role="status">
      <span>
        <strong>Reports are not being ingested.</strong>{' '}
        {health.last_success_at
          ? `The last ingest run that completed was ${relTime(health.last_success_at)}`
          : 'No ingest run has completed yet'}
        {health.last_run_failed ? ', and the most recent run failed' : ''}. What you see below may be out of date —
        check the ingest job&apos;s schedule and logs.
      </span>
    </div>
  )

  // Nothing ingested at all yet: show setup guidance instead of empty tables.
  if (domains.length === 0) {
    return (
      <>
        <div className="page-head">
          <div>
            <h1>Overview</h1>
            <p>No DMARC reports have been ingested yet.</p>
          </div>
        </div>
        {staleNotice}
        <Onboarding hasRun={runs.length > 0} />
        {runs.length > 0 && <IngestRuns runs={runs} />}
      </>
    )
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p>
            {rangeLabel(days)} · {domains.length} {domains.length === 1 ? 'domain' : 'domains'}
            {lastRun && <> · last ingest {relTime(lastRun.started_at)}</>}
          </p>
        </div>
        <RangeSwitcher basePath="/" active={days} />
      </div>

      {staleNotice}

      {extent && extent.total_messages > 0 && (
        <div className="notice warn">
          <span>
            No reports fall inside this window, but {fmtInt(extent.total_messages)} messages are on record from{' '}
            {fmtDate(extent.min_date)} to {fmtDate(extent.max_date)}.
          </span>
          <Link href="/?range=all" className="btn btn-sm">
            View all time
          </Link>
        </div>
      )}

      <div className="stat-grid">
        <Stat label="Messages reported" value={fmtInt(totals.messages)} />
        <Stat
          label="DMARC compliance"
          value={pct(rate(totals.pass))}
          tone={hasData ? rateTone(rate(totals.pass)) : undefined}
          rate={hasData ? rate(totals.pass) : undefined}
        />
        <Stat label="DKIM aligned" value={pct(rate(totals.dkim))} />
        <Stat label="SPF aligned" value={pct(rate(totals.spf))} />
        <Stat
          label="Failing messages"
          value={hasData ? fmtInt(totals.fail) : '—'}
          tone={!hasData ? undefined : totals.fail === 0 ? 'ok' : 'bad'}
          sub={hasData && totals.fail > 0 ? 'View problem sources →' : undefined}
          href={`/issues?range=${range}`}
        />
      </div>

      <Section title="Volume">
        <VolumeChart data={timeseries} />
      </Section>

      <Section title="Domains">
        <div className="card flush">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Policy</th>
                  <th className="num">Messages</th>
                  <th className="num">DMARC</th>
                  <th className="num">DKIM</th>
                  <th className="num">SPF</th>
                  <th className="num">Failing</th>
                  <th className="num">Reports</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d) => {
                  const t = d.total_messages
                  return (
                    <tr key={d.name}>
                      <td className="wrap">
                        <Link href={`/domains/${encodeURIComponent(d.name)}?range=${range}`}>{d.name}</Link>
                      </td>
                      <td>
                        <Pill tone={policyTone(d.policy)}>{d.policy ? `p=${d.policy}` : 'unknown'}</Pill>
                      </td>
                      <td className="num">{fmtInt(t)}</td>
                      <td className="num">
                        <RateCell passed={d.dmarc_pass} total={t} />
                      </td>
                      <td className="num muted">{t > 0 ? pct(d.dkim_pass / t) : '—'}</td>
                      <td className="num muted">{t > 0 ? pct(d.spf_pass / t) : '—'}</td>
                      <td className={`num ${d.dmarc_fail > 0 ? 'tone-bad' : 'muted'}`}>
                        {t > 0 ? (
                          d.dmarc_fail > 0 ? (
                            <Link className="tone-bad" href={`/issues?range=${range}&domain=${encodeURIComponent(d.name)}`}>
                              {fmtInt(d.dmarc_fail)}
                            </Link>
                          ) : (
                            '0'
                          )
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="num muted">{fmtInt(d.report_count)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </Section>

      <Section title="Top sending sources">
        {sources.length === 0 ? (
          <div className="empty">No source data in this range.</div>
        ) : (
          <div className="card flush">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Category</th>
                    <th className="num">Messages</th>
                    <th className="num">DMARC</th>
                    <th className="num">DKIM</th>
                    <th className="num">SPF</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map((s) => {
                    const id = identifySource({
                      reverse_dns: s.reverse_dns,
                      base_domain: s.base_domain,
                      provider_name: s.provider_name,
                      as_name: s.as_name,
                      total: s.total_messages,
                      dkim_passed: s.dkim_passed,
                      spf_passed: s.spf_passed,
                      dmarc_passed: s.passed,
                    })
                    const t = s.total_messages
                    return (
                      <tr key={s.source_ip}>
                        <td>
                          <SourceCell identity={id} ip={s.source_ip} reverseDns={s.reverse_dns} />
                        </td>
                        <td>
                          <CategoryPill identity={id} />
                        </td>
                        <td className="num">{fmtInt(t)}</td>
                        <td className="num">
                          <RateCell passed={s.passed} total={t} />
                        </td>
                        <td className="num muted">{t > 0 ? pct(s.dkim_passed / t) : '—'}</td>
                        <td className="num muted">{t > 0 ? pct(s.spf_passed / t) : '—'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Section>

      <IngestRuns runs={runs} />
    </>
  )
}

function IngestRuns({ runs }: { runs: Awaited<ReturnType<typeof getRecentIngestRuns>> }) {
  return (
    <Section title="Recent ingest runs">
      {runs.length === 0 ? (
        <div className="empty">The ingest job has not run yet.</div>
      ) : (
        <div className="card flush">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Started</th>
                  <th className="num">Messages fetched</th>
                  <th className="num">Reports stored</th>
                  <th className="num">Skipped</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td title={r.started_at}>{relTime(r.started_at)}</td>
                    <td className="num">{fmtInt(r.messages_fetched)}</td>
                    <td className="num">{fmtInt(r.reports_parsed)}</td>
                    <td className="num muted">{fmtInt(r.reports_skipped)}</td>
                    <td>
                      {r.failed ? (
                        <Pill tone="bad" title="The mailbox or the database could not be reached; see the ingest job's logs">
                          failed
                        </Pill>
                      ) : r.stalled ? (
                        <Pill tone="bad" title="Started over an hour ago and never finished">
                          did not finish
                        </Pill>
                      ) : r.finished_at == null ? (
                        <Pill tone="info">running</Pill>
                      ) : r.had_errors ? (
                        <Pill tone="warn" title="Some messages could not be processed; see the ingest job's logs">
                          completed with errors
                        </Pill>
                      ) : (
                        <Pill tone="ok">ok</Pill>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Section>
  )
}

function Onboarding({ hasRun }: { hasRun: boolean }) {
  return (
    <div className="card">
      <h2 className="section-title">Getting your first reports</h2>
      <p className="muted" style={{ margin: 0 }}>
        Mailbox providers send a daily aggregate report to the address named in each domain&apos;s DMARC record. This
        app reads those reports from a mailbox and turns them into dashboards.
      </p>
      <ol className="steps">
        <li>
          <strong>Publish a DMARC record that requests reports</strong>
          <span className="muted">
            Add a TXT record at <code>_dmarc.yourdomain.com</code> pointing <code>rua</code> at a mailbox you control.
            Start with <code>p=none</code> — it only monitors.
          </span>
          <pre>v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com</pre>
        </li>
        <li>
          <strong>Give the ingest job access to that mailbox</strong>
          <span className="muted">
            Set <code>IMAP_HOST</code>, <code>IMAP_USER</code> and <code>IMAP_PASSWORD</code> for the ingest job (see
            the README). Reports for a different domain than the mailbox&apos;s need a one-line authorization record
            there too.
          </span>
        </li>
        <li>
          <strong>Run the ingest job</strong>
          <span className="muted">
            {hasRun
              ? 'The job has run, but found no reports yet. Providers usually send the first ones within 24–48 hours of the DNS record going live.'
              : 'Schedule it (daily is plenty) or run it once by hand. Providers usually send the first reports within 24–48 hours of the DNS record going live.'}
          </span>
        </li>
      </ol>
    </div>
  )
}
