import type { Metadata } from 'next'
import Link from 'next/link'
import { Icon } from '@/components/icons'
import { EmptyState, GradeBadge, HealthRing, PageHeader, Pill, RangeSwitcher, policyLabel } from '@/components/ui'
import { Sparkline } from '@/components/VolumeChart'
import { atLeast } from '@/lib/auth/roles'
import { requireViewer } from '@/lib/auth/server'
import { fmtInt, parseRange, pct, policyTone, rangeLabel, rangeParam, relTime } from '@/lib/format'
import { domainHealth } from '@/lib/health'
import { getDomainSummaries, getLatestDnsChecksByDomain, getVolumeTimeseries } from '@/lib/queries'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Domains' }

type Dns = { checked_at?: string } & Partial<Record<'mx' | 'spf' | 'dmarc' | 'dkim', { status?: string }>>

const SORTS = [
  { key: 'health', label: 'Health' },
  { key: 'volume', label: 'Volume' },
  { key: 'name', label: 'Name' },
] as const

// Above this many domains the per-card trend lines are left out: each is a query.
const MAX_SPARKLINES = 24

export default async function DomainsPage({ searchParams }: { searchParams: Promise<{ range?: string; sort?: string }> }) {
  const access = await requireViewer()
  const scope = access.domains
  const { range: rawRange, sort: rawSort } = await searchParams
  const days = parseRange(rawRange)
  const range = rangeParam(days)
  const sort = SORTS.some((s) => s.key === rawSort) ? (rawSort as (typeof SORTS)[number]['key']) : 'health'

  const [domains, dnsChecks] = await Promise.all([getDomainSummaries(scope, days), getLatestDnsChecksByDomain(scope)])
  const series = domains.length <= MAX_SPARKLINES ? await Promise.all(domains.map((d) => getVolumeTimeseries(scope, days === 0 ? 90 : days, d.name))) : null

  const cards = domains.map((d, i) => {
    const dns = dnsChecks.get(d.name.toLowerCase()) as Dns | undefined
    return {
      d,
      dns,
      series: series?.[i] ?? null,
      health: domainHealth({
        total: d.total_messages,
        dmarcPass: d.dmarc_pass,
        dkimPass: d.dkim_pass,
        policy: d.policy,
        dns: dns ? { dmarc: dns.dmarc?.status, spf: dns.spf?.status } : null,
      }),
    }
  })
  cards.sort((a, b) =>
    sort === 'name'
      ? a.d.name.localeCompare(b.d.name)
      : sort === 'volume'
        ? b.d.total_messages - a.d.total_messages
        : (a.health.score ?? 101) - (b.health.score ?? 101)
  )

  const counts = {
    ok: cards.filter((c) => c.health.tone === 'ok').length,
    warn: cards.filter((c) => c.health.tone === 'warn').length,
    bad: cards.filter((c) => c.health.tone === 'bad').length,
  }

  return (
    <>
      <PageHeader
        title="Domains"
        lead={
          <>
            Health of every domain you monitor · {rangeLabel(days).toLowerCase()}. Grades combine authentication rate, policy enforcement and DKIM
            coverage.
          </>
        }
        actions={
          <>
            {atLeast(access.role, 'admin') && (
              <Link href="/admin/domains" className="btn btn-sm">
                <Icon name="settings" size={14} /> Manage list
              </Link>
            )}
            <RangeSwitcher basePath="/domains" active={days} params={{ sort }} />
          </>
        }
      />

      {domains.length === 0 ? (
        <EmptyState icon="globe" title="No domains yet">
          Domains appear here once their first DMARC report has been ingested.
        </EmptyState>
      ) : (
        <>
          <div className="row" style={{ marginBottom: '1rem', justifyContent: 'space-between' }}>
            <div className="row">
              <Pill tone="ok" dot>
                {counts.ok} healthy
              </Pill>
              <Pill tone="warn" dot>
                {counts.warn} fair
              </Pill>
              <Pill tone="bad" dot>
                {counts.bad} at risk
              </Pill>
            </div>
            <nav className="seg" aria-label="Sort by">
              {SORTS.map((s) => (
                <Link key={s.key} href={`/domains?range=${range}&sort=${s.key}`} aria-current={sort === s.key ? 'true' : undefined}>
                  {s.label}
                </Link>
              ))}
            </nav>
          </div>

          <div className="domain-grid">
            {cards.map(({ d, dns, health, series: s }) => {
              const t = d.total_messages
              return (
                <Link key={d.name} href={`/domains/${encodeURIComponent(d.name)}?range=${range}`} className={`card domain-card edge-${health.tone === 'muted' ? 'none' : health.tone}`}>
                  <div className="dc-head">
                    <HealthRing health={health} size={52} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="dc-name">{d.name}</div>
                      <div className="row" style={{ gap: '0.4rem', marginTop: '0.3rem' }}>
                        <Pill tone={policyTone(d.policy)}>{policyLabel(d.policy)}</Pill>
                        {d.dmarc_fail > 0 && <Pill tone="bad">{fmtInt(d.dmarc_fail)} failing</Pill>}
                      </div>
                    </div>
                    <GradeBadge grade={health.grade} large />
                  </div>
                  <div className="dc-metrics">
                    <div>
                      <div className="kv-label">Messages</div>
                      <div className="kv-value">{fmtInt(t)}</div>
                    </div>
                    <div>
                      <div className="kv-label">DMARC</div>
                      <div className={`kv-value${t ? (d.dmarc_pass / t >= 0.98 ? ' tone-ok' : d.dmarc_pass / t >= 0.9 ? ' tone-warn' : ' tone-bad') : ''}`}>
                        {t ? pct(d.dmarc_pass / t) : '—'}
                      </div>
                    </div>
                    <div>
                      <div className="kv-label">DKIM</div>
                      <div className="kv-value">{t ? pct(d.dkim_pass / t) : '—'}</div>
                    </div>
                  </div>
                  {s && <Sparkline data={s} width={280} height={34} />}
                  <div className="dc-foot">
                    <span className="row" style={{ gap: '0.55rem' }}>
                      {dns ? (
                        (['mx', 'spf', 'dmarc', 'dkim'] as const).map((k) => {
                          const st = dns[k]?.status
                          return (
                            <span key={k} className="row" style={{ gap: '0.25rem' }} title={`${k.toUpperCase()}: ${st ?? 'unknown'}`}>
                              <span className={`dot ${st === 'ok' ? 'ok' : st === 'fail' ? 'bad' : st ? 'warn' : ''}`} />
                              {k.toUpperCase()}
                            </span>
                          )
                        })
                      ) : (
                        <span>DNS not checked yet</span>
                      )}
                    </span>
                    <span>{dns?.checked_at ? `checked ${relTime(dns.checked_at)}` : `${fmtInt(d.report_count)} reports`}</span>
                  </div>
                </Link>
              )
            })}
          </div>
        </>
      )}
    </>
  )
}
