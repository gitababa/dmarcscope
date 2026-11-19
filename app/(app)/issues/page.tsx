import type { Metadata } from 'next'
import Link from 'next/link'
import { Icon } from '@/components/icons'
import { CategoryPill, EmptyState, Favicon, Notice, PageHeader, RangeSwitcher, Stat } from '@/components/ui'
import { requireViewer } from '@/lib/auth/server'
import { diagnoseSource } from '@/lib/diagnose'
import { isValidDomainName } from '@/lib/dns-run'
import { fmtDate, fmtInt, parseRange, pct, rangeLabel, rangeParam } from '@/lib/format'
import { getDomainNames, getLatestDnsChecksByDomain, getProblemSources } from '@/lib/queries'
import { identifySource, remediationFor } from '@/lib/senders'
import type { SpfExpansion } from '@/lib/spf'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Issues' }

const LIMIT = 50

const KINDS = [
  { key: 'all', label: 'All' },
  { key: 'bad', label: 'Unauthorized' },
  { key: 'warn', label: 'Needs a fix' },
  { key: 'ok', label: 'Benign' },
] as const
type Kind = (typeof KINDS)[number]['key']

export default async function IssuesPage({
  searchParams,
}: {
  searchParams: Promise<{ range?: string; domain?: string; kind?: string }>
}) {
  // Each page checks for itself; it does not rely on the layout or the proxy.
  const { domains: scope } = await requireViewer()
  const { range: rawRange, domain: rawDomain, kind: rawKind } = await searchParams
  const days = parseRange(rawRange)
  const range = rangeParam(days)
  const requested = (rawDomain || '').trim().toLowerCase()
  const domainNames = await getDomainNames(scope)
  // Only filter by a domain that is actually tracked.
  const domain = isValidDomainName(requested) && domainNames.includes(requested) ? requested : undefined
  const kind: Kind = KINDS.some((k) => k.key === rawKind) ? (rawKind as Kind) : 'all'

  const [sources, dnsChecks] = await Promise.all([getProblemSources(scope, days, LIMIT, domain), getLatestDnsChecksByDomain(scope)])
  const uncheckedDomains = [...new Set(sources.map((s) => s.domain))].filter(
    (d) => !(dnsChecks.get(d.toLowerCase()) as { spf_expanded?: SpfExpansion } | undefined)?.spf_expanded
  )

  const items = sources.map((s) => {
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
    const spf = (dnsChecks.get(s.domain.toLowerCase()) as { spf_expanded?: SpfExpansion } | undefined)?.spf_expanded
    return { s, id, diagnosis: diagnoseSource(s, spf) }
  })
  const by = (t: 'ok' | 'warn' | 'bad') => items.filter((i) => i.diagnosis.tone === t)
  const failingOf = (list: typeof items) => list.reduce((a, i) => a + i.s.failing, 0)
  const shown = kind === 'all' ? items : by(kind)
  const totalFailing = failingOf(items)

  const href = (over: Record<string, string | undefined>) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries({ range, domain, kind: kind === 'all' ? undefined : kind, ...over })) if (v) q.set(k, v)
    return `/issues?${q}`
  }

  return (
    <>
      <PageHeader
        title="Issues"
        lead={
          <>
            Sources failing DMARC, ranked by failing volume, each with a diagnosis · {rangeLabel(days).toLowerCase()}
            {domain && <> · {domain}</>}
          </>
        }
        actions={
          <>
            <a className="btn btn-sm" href={`/issues/export?range=${range}${domain ? `&domain=${encodeURIComponent(domain)}` : ''}`} download>
              <Icon name="download" size={14} /> CSV
            </a>
            <RangeSwitcher basePath="/issues" active={days} params={{ domain, kind: kind === 'all' ? undefined : kind }} />
          </>
        }
      />

      {items.length > 0 && (
        <div className="stat-grid">
          <Stat icon="alert" label="Failing messages" value={fmtInt(totalFailing)} tone="bad" sub={`${items.length}${items.length === LIMIT ? '+' : ''} source/domain pairs`} />
          <Stat icon="xCircle" label="Unauthorized" value={fmtInt(failingOf(by('bad')))} sub={`${by('bad').length} sources · blocked by quarantine/reject`} href={href({ kind: 'bad' })} />
          <Stat icon="settings" label="Needs a fix" value={fmtInt(failingOf(by('warn')))} sub={`${by('warn').length} sources · set up SPF or DKIM`} href={href({ kind: 'warn' })} />
          <Stat icon="refresh" label="Benign" value={fmtInt(failingOf(by('ok')))} sub={`${by('ok').length} sources · forwarding and lists`} href={href({ kind: 'ok' })} />
        </div>
      )}

      <div className="row" style={{ justifyContent: 'space-between', marginBottom: '1rem' }}>
        <nav className="seg" aria-label="Kind of issue">
          {KINDS.map((k) => (
            <Link key={k.key} href={href({ kind: k.key === 'all' ? undefined : k.key })} aria-current={kind === k.key ? 'true' : undefined}>
              {k.label}
              {k.key !== 'all' && <span className="muted"> {by(k.key).length}</span>}
            </Link>
          ))}
        </nav>
        {domainNames.length > 1 && (
          <form method="get" action="/issues" className="inline-form">
            <input type="hidden" name="range" value={range} />
            {kind !== 'all' && <input type="hidden" name="kind" value={kind} />}
            <label htmlFor="domain-filter" className="visually-hidden">
              Domain
            </label>
            <select id="domain-filter" name="domain" defaultValue={domain ?? ''}>
              <option value="">All domains</option>
              {domainNames.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
            <button type="submit" className="btn btn-sm">
              Apply
            </button>
          </form>
        )}
      </div>

      {uncheckedDomains.length > 0 && (
        <Notice tone="warn">
          SPF attribution is unavailable for{' '}
          {uncheckedDomains.slice(0, 3).map((d, i) => (
            <span key={d}>
              {i > 0 && ', '}
              <Link href={`/domains/${encodeURIComponent(d)}`}>{d}</Link>
            </span>
          ))}
          {uncheckedDomains.length > 3 && ` and ${uncheckedDomains.length - 3} more`} — run DNS checks on the domain page (or schedule them) to
          see whether each source is authorized.
        </Notice>
      )}

      {items.length === 0 ? (
        <EmptyState icon="checkCircle" title="No failing sources">
          Either everything aligns, or no reports have arrived for this window yet.
        </EmptyState>
      ) : shown.length === 0 ? (
        <EmptyState icon="filter">Nothing of this kind in this range.</EmptyState>
      ) : (
        shown.map(({ s, id, diagnosis }) => {
          const hint = remediationFor(id)
          const failRate = s.total_messages > 0 ? s.failing / s.total_messages : 0
          const name = id.name || s.reverse_dns || s.source_ip
          return (
            <article className={`card issue tone-edge-${diagnosis.tone}`} key={`${s.source_ip}-${s.domain}`}>
              <div className="issue-head">
                <div className="cell-main" style={{ alignItems: 'flex-start' }}>
                  <Favicon name={name} />
                  <div style={{ minWidth: 0 }}>
                    <div className="issue-title">
                      {name}
                      <CategoryPill identity={id} />
                    </div>
                    <div className="source-meta" style={{ marginTop: '0.2rem' }}>
                      {s.source_ip}
                      {s.reverse_dns ? ` · ${s.reverse_dns}` : ''}
                    </div>
                    <div className="muted small" style={{ marginTop: '0.2rem' }}>
                      Sending as <Link href={`/domains/${encodeURIComponent(s.domain)}`}>{s.domain}</Link> · last seen {fmtDate(s.last_seen)}
                    </div>
                  </div>
                </div>
                <div className="metrics">
                  <Metric label="failing" value={fmtInt(s.failing)} tone="bad" />
                  <Metric label="of its mail" value={pct(failRate)} tone={failRate >= 0.5 ? 'bad' : undefined} />
                  <Metric label="DKIM aligned" value={pct(s.dkim_passed / s.total_messages)} />
                  <Metric label="SPF aligned" value={pct(s.spf_passed / s.total_messages)} />
                </div>
              </div>
              <div className="issue-body">
                <p className={`verdict tone-${diagnosis.tone}`}>{diagnosis.verdict}</p>
                <ul>
                  {diagnosis.details.map((line, i) => (
                    <li key={i}>{line}</li>
                  ))}
                </ul>
                {diagnosis.showRemediation && (
                  <p className="hint">
                    <Icon name="zap" size={15} />
                    <span>
                      <strong>What to do:</strong> {hint}
                    </span>
                  </p>
                )}
              </div>
            </article>
          )
        })
      )}
    </>
  )
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: 'bad' }) {
  return (
    <div>
      <div className={`metric-value${tone ? ` tone-${tone}` : ''}`}>{value}</div>
      <div className="metric-label">{label}</div>
    </div>
  )
}
