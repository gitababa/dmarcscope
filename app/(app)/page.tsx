import type { Metadata } from 'next'
import Link from 'next/link'
import { Icon } from '@/components/icons'
import {
  Card,
  CategoryPill,
  EmptyState,
  Favicon,
  GradeBadge,
  HealthRing,
  Notice,
  PageHeader,
  Pill,
  RangeSwitcher,
  RateCell,
  SourceCell,
  Stat,
  policyLabel,
  rateTone,
} from '@/components/ui'
import { VolumeChart } from '@/components/VolumeChart'
import { requireViewer } from '@/lib/auth/server'
import { fmtDate, fmtInt, parseRange, pct, policyTone, rangeLabel, rangeParam, relTime } from '@/lib/format'
import { domainHealth, gradeFor, overallHealth, toneFor } from '@/lib/health'
import {
  getDataExtent,
  getDomainSummaries,
  getIngestHealth,
  getLatestDnsChecksByDomain,
  getProblemSources,
  getRecentIngestRuns,
  getTopSources,
  getVolumeTimeseries,
} from '@/lib/queries'
import { identifySource } from '@/lib/senders'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Overview' }

type DnsStatus = { dmarc?: { status?: string }; spf?: { status?: string } }

export default async function OverviewPage({ searchParams }: { searchParams: Promise<{ range?: string }> }) {
  // Each page checks for itself; it does not rely on the layout or the proxy.
  const { domains: scope } = await requireViewer()
  const { range: rawRange } = await searchParams
  const days = parseRange(rawRange)

  const [domains, sources, runs, health, timeseries, problems, dnsChecks] = await Promise.all([
    getDomainSummaries(scope, days),
    getTopSources(scope, days, 8),
    getRecentIngestRuns(scope, 5),
    getIngestHealth(scope),
    getVolumeTimeseries(scope, days),
    getProblemSources(scope, days, 5),
    getLatestDnsChecksByDomain(scope),
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
  const extent = !hasData && days !== 0 && domains.length > 0 ? await getDataExtent(scope) : null

  const graded = domains.map((d) => {
    const dns = dnsChecks.get(d.name.toLowerCase()) as DnsStatus | undefined
    return {
      d,
      health: domainHealth({
        total: d.total_messages,
        dmarcPass: d.dmarc_pass,
        dkimPass: d.dkim_pass,
        policy: d.policy,
        dns: dns ? { dmarc: dns.dmarc?.status, spf: dns.spf?.status } : null,
      }),
    }
  })
  const overall = overallHealth(graded.map((g) => ({ total: g.d.total_messages, health: g.health })))
  const overallHealthObj = { score: overall, grade: overall == null ? null : gradeFor(overall), tone: toneFor(overall), factors: [] }
  const enforcing = domains.filter((d) => d.policy === 'reject' || d.policy === 'quarantine').length
  const weakDomains = graded.filter((g) => g.health.score != null && g.health.score < 75).sort((a, b) => (a.health.score ?? 0) - (b.health.score ?? 0))

  const staleNotice = health.status === 'stale' && (
    <Notice tone="warn" role="status" action={<Link href="/admin/mail" className="btn btn-sm">Check mailboxes</Link>}>
      <strong>Reports are not being ingested.</strong>{' '}
      {health.last_success_at ? `The last ingest run that completed was ${relTime(health.last_success_at)}` : 'No ingest run has completed yet'}
      {health.last_run_failed ? ', and the most recent run failed' : ''}. What you see below may be out of date — check the ingest job&apos;s
      schedule and logs.
    </Notice>
  )

  // Nothing ingested at all yet: show setup guidance instead of empty tables.
  if (domains.length === 0) {
    return (
      <>
        <PageHeader title="Welcome" lead="No DMARC reports have been ingested yet. Here is how to get your first ones." />
        {staleNotice}
        <Onboarding hasRun={runs.length > 0} />
        {runs.length > 0 && (
          <div className="section">
            <IngestRuns runs={runs} />
          </div>
        )}
      </>
    )
  }

  const verdict =
    overall == null
      ? 'No mail was reported in this range.'
      : overall >= 90
        ? 'Your domains are well protected and your own mail authenticates.'
        : overall >= 75
          ? 'Mostly healthy. A few things would tighten protection further.'
          : overall >= 60
            ? 'Some legitimate mail is failing, or policies are not enforced yet.'
            : 'Action needed: significant mail fails DMARC, or spoofing is not blocked.'

  return (
    <>
      <PageHeader
        title="Overview"
        lead={
          <>
            {rangeLabel(days)} across {domains.length} {domains.length === 1 ? 'domain' : 'domains'}
            {lastRun && <> · last ingest {relTime(lastRun.started_at)}</>}
          </>
        }
        actions={<RangeSwitcher basePath="/" active={days} />}
      />

      {staleNotice}

      {extent && extent.total_messages > 0 && (
        <Notice tone="warn" action={<Link href="/?range=all" className="btn btn-sm">View all time</Link>}>
          No reports fall inside this window, but {fmtInt(extent.total_messages)} messages are on record from {fmtDate(extent.min_date)} to{' '}
          {fmtDate(extent.max_date)}.
        </Notice>
      )}

      <section className="card hero" aria-labelledby="posture-head">
        <HealthRing health={overallHealthObj} size={132} caption="score" />
        <div>
          <div className="hero-title">
            <h2 id="posture-head">Email security posture</h2>
            {overall != null && <GradeBadge grade={gradeFor(overall)} />}
          </div>
          <p>
            {verdict} The score weighs each domain by its volume: authentication rate, policy enforcement and DKIM coverage.{' '}
            <Link href={`/domains?range=${range}`}>See each domain</Link>.
          </p>
          <div className="hero-stats">
            <div>
              <div className="kv-label">Domains enforcing</div>
              <div className="kv-value">
                {enforcing} <span className="muted small">of {domains.length}</span>
              </div>
            </div>
            <div>
              <div className="kv-label">Needing attention</div>
              <div className={`kv-value${weakDomains.length ? ' tone-warn' : ''}`}>{weakDomains.length}</div>
            </div>
            <div>
              <div className="kv-label">Failing sources</div>
              <div className={`kv-value${problems.length ? ' tone-bad' : ''}`}>{problems.length >= 5 ? '5+' : problems.length}</div>
            </div>
            <div>
              <div className="kv-label">Reports processed</div>
              <div className="kv-value">{fmtInt(domains.reduce((a, d) => a + d.report_count, 0))}</div>
            </div>
          </div>
        </div>
      </section>

      <div className="stat-grid">
        <Stat icon="mail" label="Messages reported" value={fmtInt(totals.messages)} sub={rangeLabel(days)} />
        <Stat
          icon="shield"
          label="DMARC compliance"
          value={pct(rate(totals.pass))}
          tone={hasData ? rateTone(rate(totals.pass)) : undefined}
          rate={hasData ? rate(totals.pass) : undefined}
        />
        <Stat icon="key" label="DKIM aligned" value={pct(rate(totals.dkim))} rate={hasData ? rate(totals.dkim) : undefined} tone={hasData ? rateTone(rate(totals.dkim)) : undefined} />
        <Stat icon="server" label="SPF aligned" value={pct(rate(totals.spf))} rate={hasData ? rate(totals.spf) : undefined} tone={hasData ? rateTone(rate(totals.spf)) : undefined} />
        <Stat
          icon="alert"
          label="Failing messages"
          value={hasData ? fmtInt(totals.fail) : '—'}
          tone={!hasData ? undefined : totals.fail === 0 ? 'ok' : 'bad'}
          sub={hasData && totals.fail > 0 ? 'View the failing sources' : undefined}
          href={`/issues?range=${range}`}
        />
      </div>

      <div className="grid-main-side">
        <Card title="Mail volume & compliance" icon="activity" sub="Daily messages reported by receivers">
          <div className="card-body" style={{ paddingTop: '0.25rem' }}>
            <VolumeChart data={timeseries} />
          </div>
        </Card>

        <Card
          title="Needs attention"
          icon="alert"
          flush
          action={
            <Link href={`/issues?range=${range}`} className="btn btn-sm btn-ghost">
              All issues <Icon name="arrowRight" size={13} />
            </Link>
          }
        >
          {problems.length === 0 && weakDomains.length === 0 ? (
            <EmptyState icon="checkCircle" title="All clear">
              No source fails DMARC in this range, and every domain grades B or better.
            </EmptyState>
          ) : (
            <div>
              {weakDomains.slice(0, 3).map(({ d, health: h }) => (
                <Link key={d.name} href={`/domains/${encodeURIComponent(d.name)}?range=${range}`} className="attn">
                  <GradeBadge grade={h.grade} />
                  <div className="attn-body">
                    <div className="attn-title">{d.name}</div>
                    <div className="attn-sub">
                      {policyLabel(d.policy)} · {pct(d.total_messages ? d.dmarc_pass / d.total_messages : NaN)} compliant
                    </div>
                  </div>
                  <div className="attn-val">
                    {h.score}
                    <small>score</small>
                  </div>
                </Link>
              ))}
              {problems.map((s) => {
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
                return (
                  <Link key={`${s.source_ip}-${s.domain}`} href={`/issues?range=${range}&domain=${encodeURIComponent(s.domain)}`} className="attn">
                    <span className="row-icon bad">
                      <Icon name="xCircle" size={16} />
                    </span>
                    <div className="attn-body">
                      <div className="attn-title">{id.name || s.reverse_dns || s.source_ip}</div>
                      <div className="attn-sub">
                        as {s.domain} · {s.source_ip}
                      </div>
                    </div>
                    <div className="attn-val tone-bad">
                      {fmtInt(s.failing)}
                      <small>failing</small>
                    </div>
                  </Link>
                )
              })}
            </div>
          )}
        </Card>
      </div>

      <div className="section">
        <Card
          title="Domains"
          icon="globe"
          flush
          sub={`${domains.length} monitored`}
          action={
            <Link href={`/domains?range=${range}`} className="btn btn-sm btn-ghost">
              Domain health <Icon name="arrowRight" size={13} />
            </Link>
          }
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Health</th>
                  <th>Policy</th>
                  <th className="num">Messages</th>
                  <th className="num">DMARC</th>
                  <th className="num">DKIM</th>
                  <th className="num">SPF</th>
                  <th className="num">Failing</th>
                </tr>
              </thead>
              <tbody>
                {graded.map(({ d, health: h }) => {
                  const t = d.total_messages
                  return (
                    <tr key={d.name}>
                      <td className="wrap">
                        <div className="cell-main">
                          <Favicon name={d.name} />
                          <Link className="row-link" href={`/domains/${encodeURIComponent(d.name)}?range=${range}`}>
                            {d.name}
                          </Link>
                        </div>
                      </td>
                      <td>
                        <span className="row" style={{ gap: '0.45rem' }}>
                          <GradeBadge grade={h.grade} />
                          <span className="muted small">{h.score ?? '—'}</span>
                        </span>
                      </td>
                      <td>
                        <Pill tone={policyTone(d.policy)}>{policyLabel(d.policy)}</Pill>
                      </td>
                      <td className="num">{fmtInt(t)}</td>
                      <td className="num">
                        <RateCell passed={d.dmarc_pass} total={t} />
                      </td>
                      <td className="num muted">{t > 0 ? pct(d.dkim_pass / t) : '—'}</td>
                      <td className="num muted">{t > 0 ? pct(d.spf_pass / t) : '—'}</td>
                      <td className="num">
                        {t > 0 ? (
                          d.dmarc_fail > 0 ? (
                            <Link className="tone-bad" href={`/issues?range=${range}&domain=${encodeURIComponent(d.name)}`}>
                              {fmtInt(d.dmarc_fail)}
                            </Link>
                          ) : (
                            <span className="muted">0</span>
                          )
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <div className="grid-main-side section">
        <Card
          title="Top sending sources"
          icon="server"
          flush
          action={
            <Link href={`/sources?range=${range}`} className="btn btn-sm btn-ghost">
              All sources <Icon name="arrowRight" size={13} />
            </Link>
          }
        >
          {sources.length === 0 ? (
            <EmptyState icon="server">No source data in this range.</EmptyState>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Category</th>
                    <th className="num">Messages</th>
                    <th className="num">DMARC</th>
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
                    return (
                      <tr key={s.source_ip}>
                        <td>
                          <SourceCell identity={id} ip={s.source_ip} reverseDns={s.reverse_dns} />
                        </td>
                        <td>
                          <CategoryPill identity={id} />
                        </td>
                        <td className="num">{fmtInt(s.total_messages)}</td>
                        <td className="num">
                          <RateCell passed={s.passed} total={s.total_messages} />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <IngestRuns runs={runs} />
      </div>
    </>
  )
}

function RunStatus({ r }: { r: Awaited<ReturnType<typeof getRecentIngestRuns>>[number] }) {
  if (r.failed)
    return (
      <Pill tone="bad" dot title="The mailbox or the database could not be reached; see the ingest job's logs">
        failed
      </Pill>
    )
  if (r.stalled)
    return (
      <Pill tone="bad" dot title="Started over an hour ago and never finished">
        did not finish
      </Pill>
    )
  if (r.finished_at == null)
    return (
      <Pill tone="info" dot>
        running
      </Pill>
    )
  if (r.had_errors)
    return (
      <Pill tone="warn" dot title="Some messages could not be processed; see the ingest job's logs">
        with errors
      </Pill>
    )
  return (
    <Pill tone="ok" dot>
      ok
    </Pill>
  )
}

function IngestRuns({ runs }: { runs: Awaited<ReturnType<typeof getRecentIngestRuns>> }) {
  return (
    <Card title="Recent ingest runs" icon="inbox" flush>
      {runs.length === 0 ? (
        <EmptyState icon="clock">The ingest job has not run yet.</EmptyState>
      ) : (
        <div>
          {runs.map((r) => (
            <div className="list-row" key={r.id}>
              <div className="person-who" style={{ flexBasis: 140 }}>
                <div className="source-name" title={r.started_at} style={{ fontSize: '0.86rem' }}>
                  {relTime(r.started_at)}
                </div>
                <div className="muted small">
                  {fmtInt(r.reports_parsed)} stored · {fmtInt(r.messages_fetched)} fetched
                  {r.reports_skipped ? ` · ${fmtInt(r.reports_skipped)} skipped` : ''}
                </div>
              </div>
              <RunStatus r={r} />
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

function Onboarding({ hasRun }: { hasRun: boolean }) {
  return (
    <Card title="Getting your first reports" icon="zap">
      <p className="muted" style={{ margin: 0 }}>
        Mailbox providers send a daily aggregate report to the address named in each domain&apos;s DMARC record. This app reads those
        reports from a mailbox and turns them into dashboards.
      </p>
      <ol className="steps">
        <li>
          <strong>Publish a DMARC record that requests reports</strong>
          <span className="muted">
            Add a TXT record at <code>_dmarc.yourdomain.com</code> pointing <code>rua</code> at a mailbox you control. Start with{' '}
            <code>p=none</code> — it only monitors.
          </span>
          <pre>v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com</pre>
        </li>
        <li>
          <strong>Connect that mailbox and list your domains</strong>
          <span className="muted">
            An administrator adds the mailbox under <Link href="/admin/mail">Mailboxes</Link> and the domains under{' '}
            <Link href="/admin/domains">Monitored domains</Link> (or sets <code>IMAP_HOST</code>, <code>IMAP_USER</code> and{' '}
            <code>IMAP_PASSWORD</code> for the ingest job). Reports for a different domain than the mailbox&apos;s need a one-line
            authorization record there too.
          </span>
        </li>
        <li>
          <strong>Let the worker run</strong>
          <span className="muted">
            {hasRun
              ? 'The job has run, but found no reports yet. Providers usually send the first ones within 24–48 hours of the DNS record going live.'
              : 'Start the ingest worker (or schedule it). Providers usually send the first reports within 24–48 hours of the DNS record going live.'}
          </span>
        </li>
      </ol>
    </Card>
  )
}
