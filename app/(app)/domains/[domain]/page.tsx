import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { runDnsCheckAction } from '@/app/actions'
import { SubmitButton } from '@/components/client'
import { CategoryPill, Pill, RangeSwitcher, RateCell, Section, SourceCell } from '@/components/ui'
import { VolumeChart } from '@/components/VolumeChart'
import { requireViewer } from '@/lib/auth/server'
import type { CheckStatus, DnsCheckResults } from '@/lib/dns-checks'
import { isValidDomainName } from '@/lib/dns-run'
import { fmtDate, fmtInt, parseRange, pct, policyTone, rangeLabel, rangeParam, relTime } from '@/lib/format'
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
  const session = await requireViewer()

  const [policy, sources, alignment, last30, timeseries, dnsCheck] = await Promise.all([
    getDomainPolicy(domain),
    getSourcesForDomain(domain, days, 100),
    getAlignmentBreakdown(domain, days),
    getAlignmentBreakdown(domain, 30),
    getVolumeTimeseries(days, domain),
    getLatestDnsCheck(domain) as Promise<DnsCheckResults | null>,
  ])
  if (policy == null) notFound()

  const isAdmin = session.role === 'admin'
  const total = alignment.fully_aligned + alignment.dkim_only + alignment.spf_only + alignment.fully_failed
  const total30 = last30.fully_aligned + last30.dkim_only + last30.spf_only + last30.fully_failed
  const advice = policyAdvice({ policy: policy.policy, total30d: total30, passed30d: last30.dmarc_pass })
  const path = `/domains/${encodeURIComponent(domain)}`
  const range = rangeParam(days)

  return (
    <>
      <Link href={`/?range=${range}`} className="crumb">
        ← All domains
      </Link>
      <div className="page-head">
        <div>
          <h1>{domain}</h1>
          <p>
            {rangeLabel(days)} · {fmtInt(total)} messages
            {total > 0 && <> · {pct(alignment.dmarc_pass / total)} DMARC compliant</>}
          </p>
        </div>
        <RangeSwitcher basePath={path} active={days} />
      </div>

      <div className={`notice ${advice.tone === 'info' ? '' : advice.tone}`}>
        <span>
          <strong>{advice.title}.</strong> {advice.detail}
        </span>
        {(advice.tone === 'warn' || advice.tone === 'bad') && (
          <Link href={`/issues?range=30d&domain=${encodeURIComponent(domain)}`} className="btn btn-sm">
            View issues
          </Link>
        )}
      </div>

      <Section title="Published DMARC policy">
        <div className="card">
          <div className="kv-grid">
            <Kv label="Policy (p)">
              <Pill tone={policyTone(policy.policy)}>{policy.policy || 'unknown'}</Pill>
            </Kv>
            <Kv label="Subdomains (sp)">{policy.subdomain_policy || 'inherits p'}</Kv>
            <Kv label="Applied to (pct)">{policy.pct || '100'}%</Kv>
            <Kv label="DKIM alignment">{policy.adkim === 's' ? 'strict' : 'relaxed'}</Kv>
            <Kv label="SPF alignment">{policy.aspf === 's' ? 'strict' : 'relaxed'}</Kv>
            <Kv label="Latest report">{fmtDate(policy.latest_report_end)}</Kv>
          </div>
          <p className="muted small" style={{ margin: '0.9rem 0 0' }}>
            As seen by receivers in the most recent report. Run the DNS checks below for what is published right now.
          </p>
        </div>
      </Section>

      <Section
        title="DNS health"
        action={
          isAdmin && (
            <form action={runDnsCheckAction}>
              <input type="hidden" name="domain" value={domain} />
              <input type="hidden" name="range" value={range} />
              <SubmitButton className="btn btn-primary btn-sm" pendingLabel="Checking DNS…">
                {dnsCheck ? 'Re-run checks' : 'Run checks'}
              </SubmitButton>
            </form>
          )
        }
      >
        {notice === 'cooldown' && (
          <div className="notice">Checks ran a moment ago — showing those results. Try again in a few seconds.</div>
        )}
        {dnsCheck == null ? (
          <div className="empty">
            No DNS checks have been run for this domain yet.{' '}
            {isAdmin
              ? 'Run them to see its live MX, SPF, DMARC and DKIM records.'
              : 'An administrator can run them to show its live MX, SPF, DMARC and DKIM records.'}
          </div>
        ) : (
          <DnsHealthCard check={dnsCheck} />
        )}
      </Section>

      <Section title="Volume">
        <VolumeChart data={timeseries} />
      </Section>

      <Section title="Alignment breakdown">
        {total === 0 ? (
          <div className="empty">No reports in this range — try a wider one.</div>
        ) : (
          <div className="card">
            <AlignmentBar
              parts={[
                { label: 'DKIM and SPF aligned', value: alignment.fully_aligned, color: 'var(--ok-solid)' },
                { label: 'DKIM only', value: alignment.dkim_only, color: 'color-mix(in srgb, var(--ok-solid) 60%, var(--surface))' },
                { label: 'SPF only', value: alignment.spf_only, color: 'var(--warn-solid)' },
                { label: 'Neither (fails DMARC)', value: alignment.fully_failed, color: 'var(--bad-solid)' },
              ]}
              total={total}
            />
            <p className="muted small" style={{ margin: '0.9rem 0 0' }}>
              DMARC passes when either DKIM or SPF aligns. Mail that relies on SPF alone fails as soon as it is
              forwarded, so DKIM alignment is the one to aim for everywhere.
            </p>
          </div>
        )}
      </Section>

      <Section title="Sending sources">
        {sources.length === 0 ? (
          <div className="empty">No sources reported in this range.</div>
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
            {sources.length === 100 && <div className="card-foot">Showing the 100 highest-volume sources.</div>}
          </div>
        )}
      </Section>
    </>
  )
}

function Kv({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="kv-label">{label}</div>
      <div className="kv-value">{children}</div>
    </div>
  )
}

function AlignmentBar({
  parts,
  total,
}: {
  parts: Array<{ label: string; value: number; color: string }>
  total: number
}) {
  return (
    <>
      <div className="stack" role="img" aria-label={parts.map((p) => `${p.label}: ${pct(p.value / total)}`).join(', ')}>
        {parts
          .filter((p) => p.value > 0)
          .map((p) => (
            <span key={p.label} style={{ flex: `${p.value} 0 0`, background: p.color }} title={`${p.label}: ${fmtInt(p.value)}`} />
          ))}
      </div>
      <div className="legend">
        {parts.map((p) => (
          <div className="legend-item" key={p.label}>
            <span className="swatch" style={{ background: p.color }} />
            <div>
              <div className="kv-label">{p.label}</div>
              <div className="kv-value">
                {fmtInt(p.value)} <span className="muted small">{pct(p.value / total)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </>
  )
}

function StatusPill({ status }: { status: CheckStatus }) {
  if (status === 'ok') return <Pill tone="ok">Pass</Pill>
  if (status === 'fail') return <Pill tone="bad">Fail</Pill>
  return <Pill tone="warn">Warning</Pill>
}

function DnsHealthCard({ check }: { check: DnsCheckResults }) {
  const spf = check.spf_expanded
  const rows: Array<{ name: string; status: CheckStatus; detail: React.ReactNode; notes: string[] }> = [
    {
      name: 'MX',
      status: check.mx.status,
      detail:
        check.mx.records.length > 0 && check.mx.records.some((m) => m.exchange && m.exchange !== '.') ? (
          <span className="mono">{check.mx.records.map((m) => `${m.priority} ${m.exchange}`).join(', ')}</span>
        ) : (
          <span className="muted">none</span>
        ),
      notes: check.mx.notes,
    },
    {
      name: 'SPF',
      status: check.spf.status,
      detail: (
        <>
          {check.spf.record ? <code>{check.spf.record}</code> : <span className="muted">no record</span>}
          {spf && spf.has_spf && (
            <details style={{ marginTop: '0.4rem' }}>
              <summary>
                Authorizes {fmtInt(spf.networks.length)} {spf.networks.length === 1 ? 'network' : 'networks'} ·{' '}
                {Math.min(spf.lookups, 10)}
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
      name: 'DMARC',
      status: check.dmarc.status,
      detail: check.dmarc.record ? <code>{check.dmarc.record}</code> : <span className="muted">no record</span>,
      notes: check.dmarc.notes,
    },
    {
      name: 'DKIM',
      status: check.dkim.status,
      detail: (
        <span className="pill-row">
          {check.dkim.selectors
            .filter((s) => s.found || s.observed)
            .map((s) => (
              <Pill
                key={`${s.selector}@${s.signing_domain || ''}`}
                tone={s.found ? 'ok' : 'bad'}
                title={s.observed ? 'Selector seen in DMARC reports' : 'Common default selector'}
              >
                {s.found ? '✓' : '✗'} {s.selector}
                {s.signing_domain ? `@${s.signing_domain}` : ''}
              </Pill>
            ))}
          {check.dkim.selectors.every((s) => !s.found && !s.observed) && <span className="muted">no keys found</span>}
        </span>
      ),
      notes: check.dkim.notes,
    },
  ]

  return (
    <div className="card flush">
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th style={{ width: 90 }}>Record</th>
              <th style={{ width: 100 }}>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.name}>
                <td style={{ fontWeight: 620 }}>{r.name}</td>
                <td>
                  <StatusPill status={r.status} />
                </td>
                <td className="wrap">
                  {r.detail}
                  {r.notes.map((n, i) => (
                    <div key={i} className="muted small" style={{ marginTop: '0.3rem' }}>
                      {n}
                    </div>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card-foot">
        Checked {relTime(check.checked_at)} against live DNS. DKIM has no discovery mechanism, so only selectors seen
        in this domain&apos;s reports and a few common defaults are probed.
      </div>
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
    <div style={{ display: 'grid', gap: '0.5rem', marginBottom: '0.4rem' }}>
      {[...groups.entries()].map(([via, cidrs]) => (
        <div key={via}>
          <div className="small" style={{ fontWeight: 600 }}>
            {via === 'top-level' ? 'Listed directly' : via}
          </div>
          <div className="mono muted">
            {cidrs.slice(0, 40).join('  ')}
            {cidrs.length > 40 ? `  … and ${cidrs.length - 40} more` : ''}
          </div>
        </div>
      ))}
    </div>
  )
}
