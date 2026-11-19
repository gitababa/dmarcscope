import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { runDnsCheckAction } from '@/app/actions'
import { SubmitButton } from '@/components/client'
import { Icon } from '@/components/icons'
import {
  Card,
  CategoryPill,
  Donut,
  EmptyState,
  GradeBadge,
  HealthBreakdown,
  HealthRing,
  Notice,
  PageHeader,
  Pill,
  RangeSwitcher,
  RateCell,
  SourceCell,
  policyLabel,
} from '@/components/ui'
import { VolumeChart } from '@/components/VolumeChart'
import { atLeast } from '@/lib/auth/roles'
import { requireViewer } from '@/lib/auth/server'
import type { DnsCheckResults, OptionalStatus } from '@/lib/dns-checks'
import { isValidDomainName } from '@/lib/dns-run'
import { fmtDate, fmtInt, parseRange, pct, policyTone, rangeLabel, rangeParam, relTime } from '@/lib/format'
import { domainHealth } from '@/lib/health'
import {
  getAlignmentBreakdown,
  getDomainPolicy,
  getLatestDnsCheck,
  getSourcesForDomain,
  getVolumeTimeseries,
} from '@/lib/queries'
import { policyAdvice } from '@/lib/readiness'
import { identifySource } from '@/lib/senders'

export const dynamic = 'force-dynamic'

function parseDomainParam(raw: string): string | null {
  let decoded: string
  try {
    decoded = decodeURIComponent(raw)
  } catch {
    return null
  }
  const domain = decoded.trim().toLowerCase()
  return isValidDomainName(domain) ? domain : null
}

export async function generateMetadata({ params }: { params: Promise<{ domain: string }> }): Promise<Metadata> {
  const domain = parseDomainParam((await params).domain)
  return { title: domain ?? 'Domain not found' }
}

export default async function DomainPage({
  params,
  searchParams,
}: {
  params: Promise<{ domain: string }>
  searchParams: Promise<{ range?: string; notice?: string }>
}) {
  const [{ domain: rawDomain }, { range: rawRange, notice }] = await Promise.all([params, searchParams])
  const domain = parseDomainParam(rawDomain)
  if (!domain) notFound()
  const days = parseRange(rawRange)
  const access = await requireViewer()
  const scope = access.domains

  const [policy, sources, alignment, last30, timeseries, dnsCheck] = await Promise.all([
    getDomainPolicy(scope, domain),
    getSourcesForDomain(scope, domain, days, 100),
    getAlignmentBreakdown(scope, domain, days),
    getAlignmentBreakdown(scope, domain, 30),
    getVolumeTimeseries(scope, days, domain),
    getLatestDnsCheck(scope, domain) as Promise<DnsCheckResults | null>,
  ])
  if (policy == null) notFound()

  const isAdmin = atLeast(access.role, 'admin')
  const total = alignment.fully_aligned + alignment.dkim_only + alignment.spf_only + alignment.fully_failed
  const total30 = last30.fully_aligned + last30.dkim_only + last30.spf_only + last30.fully_failed
  const advice = policyAdvice({ policy: policy.policy, total30d: total30, passed30d: last30.dmarc_pass })
  const path = `/domains/${encodeURIComponent(domain)}`
  const range = rangeParam(days)
  const health = domainHealth({
    total,
    dmarcPass: alignment.dmarc_pass,
    dkimPass: alignment.fully_aligned + alignment.dkim_only,
    policy: policy.policy,
    dns: dnsCheck ? { dmarc: dnsCheck.dmarc.status, spf: dnsCheck.spf.status } : null,
  })
  const failingSources = sources.filter((s) => s.failed > 0).length

  return (
    <>
      <PageHeader
        crumbs={[{ href: `/domains?range=${range}`, label: 'Domains' }, { label: domain }]}
        title={domain}
        badge={
          <>
            <GradeBadge grade={health.grade} />
            <Pill tone={policyTone(policy.policy)}>{policyLabel(policy.policy)}</Pill>
          </>
        }
        lead={
          <>
            {rangeLabel(days)} · {fmtInt(total)} messages
            {total > 0 && <> · {pct(alignment.dmarc_pass / total)} DMARC compliant</>} · latest report {fmtDate(policy.latest_report_end)}
          </>
        }
        actions={
          <>
            <a className="btn btn-sm" href={`${path}/export?range=${range}&dataset=sources`} download>
              <Icon name="download" size={14} /> Sources CSV
            </a>
            <a className="btn btn-sm" href={`${path}/export?range=${range}&dataset=timeseries`} download>
              <Icon name="download" size={14} /> Daily CSV
            </a>
            <RangeSwitcher basePath={path} active={days} />
          </>
        }
      />

      <Notice
        tone={advice.tone}
        action={
          (advice.tone === 'warn' || advice.tone === 'bad') && failingSources > 0 ? (
            <Link href={`/issues?range=30d&domain=${encodeURIComponent(domain)}`} className="btn btn-sm">
              View issues
            </Link>
          ) : undefined
        }
      >
        <strong>{advice.title}.</strong> {advice.detail}
      </Notice>

      <div className="grid-3">
        <Card title="Health score" icon="shield" sub="How it is made up">
          <div className="row" style={{ gap: '1rem', marginBottom: '1.1rem' }}>
            <HealthRing health={health} size={96} caption="of 100" />
            <div>
              <GradeBadge grade={health.grade} large />
              <p className="muted small" style={{ margin: '0.4rem 0 0' }}>
                Over {rangeLabel(days).toLowerCase()}.
              </p>
            </div>
          </div>
          <HealthBreakdown health={health} />
        </Card>

        <Card title="Alignment" icon="layers" sub="Which mechanism carries DMARC">
          {total === 0 ? (
            <EmptyState icon="layers">No reports in this range — try a wider one.</EmptyState>
          ) : (
            <>
              <div style={{ display: 'grid', placeItems: 'center', marginBottom: '1rem' }}>
                <Donut
                  parts={ALIGN_PARTS(alignment)}
                  center={pct(alignment.dmarc_pass / total)}
                  caption="pass"
                  size={140}
                  stroke={18}
                />
              </div>
              <div className="option-list" style={{ gap: '0.5rem' }}>
                {ALIGN_PARTS(alignment).map((p) => (
                  <div className="legend-row" key={p.label}>
                    <span className="swatch" style={{ background: p.color, marginTop: 0 }} />
                    <span className="lbl">{p.label}</span>
                    <span className="val">{fmtInt(p.value)}</span>
                    <span className="pc">{pct(p.value / total)}</span>
                  </div>
                ))}
              </div>
              <p className="muted small" style={{ margin: '0.9rem 0 0' }}>
                Mail that relies on SPF alone fails as soon as it is forwarded: aim for DKIM everywhere.
              </p>
            </>
          )}
        </Card>

        <Card title="Published policy" icon="scroll" sub="As receivers saw it in the latest report">
          <dl className="kv-list">
            <dt>Policy (p)</dt>
            <dd>
              <Pill tone={policyTone(policy.policy)}>{policy.policy || 'unknown'}</Pill>
            </dd>
            <dt>Subdomains (sp)</dt>
            <dd>{policy.subdomain_policy || 'inherits p'}</dd>
            <dt>Applied to (pct)</dt>
            <dd>{policy.pct || '100'}%</dd>
            <dt>DKIM alignment</dt>
            <dd>{policy.adkim === 's' ? 'strict' : 'relaxed'}</dd>
            <dt>SPF alignment</dt>
            <dd>{policy.aspf === 's' ? 'strict' : 'relaxed'}</dd>
            <dt>Latest report</dt>
            <dd>{fmtDate(policy.latest_report_end)}</dd>
          </dl>
          <p className="muted small" style={{ margin: '0.9rem 0 0' }}>
            Run the DNS checks below for what is published right now.
          </p>
        </Card>
      </div>

      <div className="section">
        <Card title="Mail volume & compliance" icon="activity" sub={rangeLabel(days)}>
          <div style={{ paddingTop: '0.25rem' }}>
            <VolumeChart data={timeseries} />
          </div>
        </Card>
      </div>

      <div className="section">
        <Card
          title="DNS health"
          icon="dns"
          sub={
            dnsCheck
              ? `Checked ${relTime(dnsCheck.checked_at)} against live DNS${dnsCheck.resolver?.length ? ` via ${dnsCheck.resolver.join(', ')}` : ''}`
              : 'Live MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI records'
          }
          action={
            isAdmin && (
              <form action={runDnsCheckAction}>
                <input type="hidden" name="domain" value={domain} />
                <input type="hidden" name="range" value={range} />
                <SubmitButton className="btn btn-primary btn-sm" pendingLabel="Checking DNS…">
                  <Icon name="refresh" size={14} /> {dnsCheck ? 'Re-run checks' : 'Run checks'}
                </SubmitButton>
              </form>
            )
          }
        >
          {notice === 'cooldown' && <Notice tone="info">Checks ran a moment ago — showing those results. Try again in a few seconds.</Notice>}
          {dnsCheck == null ? (
            <EmptyState icon="dns" title="Not checked yet">
              {isAdmin
                ? 'Run the checks to see its live MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI records.'
                : 'An administrator can run them to show its live MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI records.'}
            </EmptyState>
          ) : (
            <>
              <DnsHealth check={dnsCheck} />
              <p className="muted small" style={{ margin: '0.9rem 0 0' }}>
                DKIM has no discovery mechanism, so only selectors seen in this domain&apos;s reports and a few common defaults are probed.
              </p>
            </>
          )}
        </Card>
      </div>

      <div className="section">
        <Card
          title="Sending sources"
          icon="server"
          flush
          sub={`${fmtInt(sources.length)} ${sources.length === 1 ? 'source' : 'sources'}${failingSources ? ` · ${failingSources} with failures` : ''}`}
          action={
            failingSources > 0 ? (
              <Link href={`/issues?range=${range}&domain=${encodeURIComponent(domain)}`} className="btn btn-sm btn-ghost">
                Diagnose failures <Icon name="arrowRight" size={13} />
              </Link>
            ) : undefined
          }
          foot={sources.length === 100 ? 'Showing the 100 highest-volume sources.' : undefined}
        >
          {sources.length === 0 ? (
            <EmptyState icon="server">No sources reported in this range.</EmptyState>
          ) : (
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
                    <th>Last seen</th>
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
                        <td className="muted nowrap">{fmtDate(s.last_seen)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </>
  )
}

function ALIGN_PARTS(a: { fully_aligned: number; dkim_only: number; spf_only: number; fully_failed: number }) {
  return [
    { label: 'DKIM and SPF aligned', value: a.fully_aligned, color: 'var(--ok-solid)' },
    { label: 'DKIM only', value: a.dkim_only, color: 'color-mix(in srgb, var(--ok-solid) 55%, var(--surface))' },
    { label: 'SPF only', value: a.spf_only, color: 'var(--warn-solid)' },
    { label: 'Neither (fails)', value: a.fully_failed, color: 'var(--bad-solid)' },
  ]
}

function StatusPill({ status }: { status: OptionalStatus }) {
  if (status === 'none') return <Pill tone="muted">Not published</Pill>
  if (status === 'ok')
    return (
      <Pill tone="ok" dot>
        Pass
      </Pill>
    )
  if (status === 'fail')
    return (
      <Pill tone="bad" dot>
        Fail
      </Pill>
    )
  return (
    <Pill tone="warn" dot>
      Warning
    </Pill>
  )
}

function DnsHealth({ check }: { check: DnsCheckResults }) {
  const spf = check.spf_expanded
  const records: Array<{ name: string; label: string; status: OptionalStatus; detail: React.ReactNode; notes: string[] }> = [
    {
      name: 'DMARC',
      label: 'Policy record',
      status: check.dmarc.status,
      detail: check.dmarc.record ? (
        <code className="record">{check.dmarc.record}</code>
      ) : check.dmarc.inherited ? (
        <>
          <code className="record">{check.dmarc.inherited.record}</code>
          <div className="muted small" style={{ marginTop: '0.35rem' }}>
            Inherited from _dmarc.{check.dmarc.inherited.from}
          </div>
        </>
      ) : (
        <span className="muted">No record published</span>
      ),
      notes: check.dmarc.notes,
    },
    {
      name: 'SPF',
      label: 'Authorized senders',
      status: check.spf.status,
      detail: (
        <>
          {check.spf.record ? <code className="record">{check.spf.record}</code> : <span className="muted">No record published</span>}
          {spf && spf.has_spf && (
            <details style={{ marginTop: '0.5rem' }}>
              <summary>
                Authorizes {fmtInt(spf.networks.length)} {spf.networks.length === 1 ? 'network' : 'networks'} · {Math.min(spf.lookups, 10)}
                {spf.lookups > 10 ? '+' : ''} of 10 DNS lookups
              </summary>
              <SpfNetworks networks={spf.networks} />
              {spf.notes.map((n, i) => (
                <div key={i} className="muted small">
                  {n}
                </div>
              ))}
            </details>
          )}
        </>
      ),
      notes: check.spf.notes,
    },
    {
      name: 'DKIM',
      label: 'Signing keys',
      status: check.dkim.status,
      detail: (
        <span className="pill-row">
          {check.dkim.selectors
            .filter((s) => s.found || s.observed)
            .map((s) => (
              <Pill
                key={`${s.selector}@${s.signing_domain || ''}`}
                tone={s.found ? 'ok' : s.lookup_failed ? 'warn' : 'bad'}
                title={`${s.observed ? 'Selector seen in DMARC reports' : 'Common default selector'}${s.lookup_failed ? ' · lookup failed' : ''}`}
              >
                {s.found ? '✓' : s.lookup_failed ? '?' : '✗'} {s.selector}
                {s.signing_domain ? `@${s.signing_domain}` : ''}
              </Pill>
            ))}
          {check.dkim.selectors.every((s) => !s.found && !s.observed) && <span className="muted">No keys found</span>}
        </span>
      ),
      notes: check.dkim.notes,
    },
    {
      name: 'MX',
      label: 'Mail servers',
      status: check.mx.status,
      detail:
        check.mx.records.length > 0 && check.mx.records.some((m) => m.exchange && m.exchange !== '.') ? (
          <div className="mono small" style={{ display: 'grid', gap: '0.15rem' }}>
            {check.mx.records.map((m) => (
              <span key={`${m.priority}-${m.exchange}`}>
                <span className="muted">{m.priority}</span> {m.exchange}
              </span>
            ))}
          </div>
        ) : (
          <span className="muted">None</span>
        ),
      notes: check.mx.notes,
    },
  ]
  const recordOrNone = (record: string | null) =>
    record ? <code className="record">{record}</code> : <span className="muted">No record published</span>
  if (check.mta_sts) {
    const policy = check.mta_sts.policy
    records.push({
      name: 'MTA-STS',
      label: 'Encrypted inbound delivery',
      status: check.mta_sts.status,
      detail: (
        <>
          {recordOrNone(check.mta_sts.record)}
          {policy && (
            <div className="mono small" style={{ display: 'grid', gap: '0.15rem', marginTop: '0.4rem' }}>
              <span>
                <span className="muted">mode</span> {policy.mode ?? '—'} <span className="muted">· max_age</span> {policy.max_age ?? '—'}
              </span>
              {policy.mx.length > 0 && (
                <span>
                  <span className="muted">mx</span> {policy.mx.join(', ')}
                </span>
              )}
            </div>
          )}
        </>
      ),
      notes: check.mta_sts.notes,
    })
  }
  if (check.tls_rpt) {
    records.push({ name: 'TLS-RPT', label: 'TLS failure reports', status: check.tls_rpt.status, detail: recordOrNone(check.tls_rpt.record), notes: check.tls_rpt.notes })
  }
  if (check.bimi) {
    records.push({ name: 'BIMI', label: 'Brand logo', status: check.bimi.status, detail: recordOrNone(check.bimi.record), notes: check.bimi.notes })
  }

  return (
    <div className="dns-grid">
      {records.map((r) => (
        <div className="dns-card" key={r.name}>
          <div className="dns-card-head">
            <span
              className={`row-icon ${r.status === 'ok' ? 'ok' : r.status === 'fail' ? 'bad' : r.status === 'none' ? '' : 'warn'}`}
              style={{ width: 28, height: 28 }}
            >
              <Icon name={r.status === 'ok' ? 'check' : r.status === 'fail' ? 'x' : r.status === 'none' ? 'info' : 'alert'} size={14} />
            </span>
            <div>
              <h3>{r.name}</h3>
              <div className="muted" style={{ fontSize: '0.72rem' }}>
                {r.label}
              </div>
            </div>
            <StatusPill status={r.status} />
          </div>
          {r.detail}
          {r.notes.map((n, i) => (
            <div key={i} className="note">
              <Icon name="info" size={13} style={{ flex: 'none', marginTop: '0.15rem' }} />
              <span>{n}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

// Group the expanded networks by the mechanism chain that authorized them.
function SpfNetworks({ networks }: { networks: Array<{ cidr: string; via: string }> }) {
  const groups = new Map<string, string[]>()
  for (const n of networks) {
    const list = groups.get(n.via) ?? []
    list.push(n.cidr)
    groups.set(n.via, list)
  }
  return (
    <div style={{ display: 'grid', gap: '0.5rem', margin: '0.5rem 0' }}>
      {[...groups.entries()].map(([via, cidrs]) => (
        <div key={via}>
          <div className="small" style={{ fontWeight: 600 }}>
            {via === 'top-level' ? 'Listed directly' : via}
          </div>
          <div className="mono muted small" style={{ overflowWrap: 'anywhere' }}>
            {cidrs.slice(0, 40).join('  ')}
            {cidrs.length > 40 ? `  … and ${cidrs.length - 40} more` : ''}
          </div>
        </div>
      ))}
    </div>
  )
}
