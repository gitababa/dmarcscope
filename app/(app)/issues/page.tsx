import type { Metadata } from 'next'
import Link from 'next/link'
import { CategoryPill, RangeSwitcher } from '@/components/ui'
import { diagnoseSource } from '@/lib/diagnose'
import { isValidDomainName } from '@/lib/dns-run'
import { fmtDate, fmtInt, parseRange, pct, rangeLabel, rangeParam } from '@/lib/format'
import { getDomainNames, getLatestDnsChecksByDomain, getProblemSources } from '@/lib/queries'
import { identifySource, remediationFor } from '@/lib/senders'
import type { SpfExpansion } from '@/lib/spf'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Issues' }

const LIMIT = 50

export default async function IssuesPage({
  searchParams,
}: {
  searchParams: Promise<{ range?: string; domain?: string }>
}) {
  const { range: rawRange, domain: rawDomain } = await searchParams
  const days = parseRange(rawRange)
  const requested = (rawDomain || '').trim().toLowerCase()
  const domainNames = await getDomainNames()
  // Only filter by a domain that is actually tracked.
  const domain = isValidDomainName(requested) && domainNames.includes(requested) ? requested : undefined

  const [sources, dnsChecks] = await Promise.all([getProblemSources(days, LIMIT, domain), getLatestDnsChecksByDomain()])
  const totalFailing = sources.reduce((acc, s) => acc + s.failing, 0)
  const uncheckedDomains = [...new Set(sources.map((s) => s.domain))].filter(
    (d) => !(dnsChecks.get(d.toLowerCase()) as { spf_expanded?: SpfExpansion } | undefined)?.spf_expanded
  )

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Issues</h1>
          <p>
            Sources failing DMARC, ranked by failing volume · {rangeLabel(days).toLowerCase()}
            {domain && <> · {domain}</>}
          </p>
        </div>
        <RangeSwitcher basePath="/issues" active={days} params={{ domain }} />
      </div>

      {domainNames.length > 1 && (
        <form method="get" action="/issues" className="inline-form" style={{ marginBottom: '1rem' }}>
          <input type="hidden" name="range" value={rangeParam(days)} />
          <label htmlFor="domain-filter" className="muted small">
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

      {sources.length === 0 ? (
        <div className="empty">
          No failing sources in this range. Either everything aligns, or no reports have arrived for this window yet.
        </div>
      ) : (
        <>
          <div className="notice">
            <span>
              <strong className="tone-bad">{fmtInt(totalFailing)}</strong> failing messages across {sources.length}{' '}
              source/domain {sources.length === 1 ? 'pair' : 'pairs'}
              {sources.length === LIMIT && ' (showing the top 50)'}. Legitimate services listed here need SPF or DKIM
              set up for your domain; spoofers are what a <code>quarantine</code> or <code>reject</code> policy
              blocks.
            </span>
          </div>

          {uncheckedDomains.length > 0 && (
            <div className="notice warn">
              <span>
                SPF attribution is unavailable for{' '}
                {uncheckedDomains.slice(0, 3).map((d, i) => (
                  <span key={d}>
                    {i > 0 && ', '}
                    <Link href={`/domains/${encodeURIComponent(d)}`}>{d}</Link>
                  </span>
                ))}
                {uncheckedDomains.length > 3 && ` and ${uncheckedDomains.length - 3} more`} — run DNS checks on the
                domain page (or schedule them) to see whether each source is authorized.
              </span>
            </div>
          )}

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
            const spf = (dnsChecks.get(s.domain.toLowerCase()) as { spf_expanded?: SpfExpansion } | undefined)
              ?.spf_expanded
            const diagnosis = diagnoseSource(s, spf)
            const hint = remediationFor(id)
            const failRate = s.total_messages > 0 ? s.failing / s.total_messages : 0
            return (
              <article className={`card issue tone-edge-${diagnosis.tone}`} key={`${s.source_ip}-${s.domain}`}>
                <div className="issue-head">
                  <div>
                    <div className="issue-title">
                      {id.name || s.reverse_dns || s.source_ip}
                      <CategoryPill identity={id} />
                    </div>
                    <div className="source-meta" style={{ marginTop: '0.2rem' }}>
                      {s.source_ip}
                      {s.reverse_dns ? ` · ${s.reverse_dns}` : ''}
                    </div>
                    <div className="muted small" style={{ marginTop: '0.2rem' }}>
                      Sending as <Link href={`/domains/${encodeURIComponent(s.domain)}`}>{s.domain}</Link> · last seen{' '}
                      {fmtDate(s.last_seen)}
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
                      <strong>What to do:</strong> {hint}
                    </p>
                  )}
                </div>
              </article>
            )
          })}
        </>
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
