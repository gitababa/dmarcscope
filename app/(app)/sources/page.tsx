import type { Metadata } from 'next'
import Link from 'next/link'
import { Card, CategoryPill, Donut, EmptyState, PageHeader, RangeSwitcher, RateCell, SourceCell } from '@/components/ui'
import { requireViewer } from '@/lib/auth/server'
import { isValidDomainName } from '@/lib/dns-run'
import { fmtInt, parseRange, pct, rangeLabel, rangeParam } from '@/lib/format'
import { getDomainNames, getSourcesForDomain, getTopSources } from '@/lib/queries'
import { CATEGORY_LABELS, type SourceCategory, identifySource } from '@/lib/senders'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Sources' }

const LIMIT = 200

const CATEGORY_COLOR: Record<SourceCategory, string> = {
  known: 'var(--ok-solid)',
  aligned: 'color-mix(in srgb, var(--ok-solid) 55%, var(--surface))',
  forwarder: 'var(--info)',
  partial: 'var(--warn-solid)',
  unknown: 'var(--bad-solid)',
}
const ORDER: SourceCategory[] = ['known', 'aligned', 'forwarder', 'partial', 'unknown']

const CATEGORY_HELP: Record<SourceCategory, string> = {
  known: 'Services recognised by their reverse DNS: your own infrastructure and the providers you send through.',
  aligned: 'Not recognised, but every message passes DMARC.',
  forwarder: 'DKIM survives, SPF fails: mailing lists and forwarding. Usually harmless.',
  partial: 'Mixed results: a real sender whose SPF or DKIM is only partly set up.',
  unknown: 'Fails everything: spoofing, or a sender never set up for your domain.',
}

export default async function SourcesPage({
  searchParams,
}: {
  searchParams: Promise<{ range?: string; domain?: string; category?: string }>
}) {
  const { domains: scope } = await requireViewer()
  const { range: rawRange, domain: rawDomain, category: rawCategory } = await searchParams
  const days = parseRange(rawRange)
  const range = rangeParam(days)
  const domainNames = await getDomainNames(scope)
  const requested = (rawDomain || '').trim().toLowerCase()
  const domain = isValidDomainName(requested) && domainNames.includes(requested) ? requested : undefined
  const category = ORDER.includes(rawCategory as SourceCategory) ? (rawCategory as SourceCategory) : undefined

  const rows = domain ? await getSourcesForDomain(scope, domain, days, LIMIT) : await getTopSources(scope, days, LIMIT)
  const all = rows.map((s) => ({
    s,
    id: identifySource({
      reverse_dns: s.reverse_dns,
      base_domain: s.base_domain,
      provider_name: s.provider_name,
      as_name: s.as_name,
      total: s.total_messages,
      dkim_passed: s.dkim_passed,
      spf_passed: s.spf_passed,
      dmarc_passed: s.passed,
    }),
  }))

  const mix = ORDER.map((c) => {
    const items = all.filter((x) => x.id.category === c)
    return { category: c, sources: items.length, messages: items.reduce((a, x) => a + x.s.total_messages, 0) }
  })
  const totalMessages = mix.reduce((a, m) => a + m.messages, 0)
  const shown = category ? all.filter((x) => x.id.category === category) : all

  const href = (over: Record<string, string | undefined>) => {
    const q = new URLSearchParams()
    const merged = { range, domain, category, ...over }
    for (const [k, v] of Object.entries(merged)) if (v) q.set(k, v)
    return `/sources?${q}`
  }

  return (
    <>
      <PageHeader
        title="Sources"
        lead={
          <>
            Every server that sent mail as {domain ?? 'your domains'}, identified and classified · {rangeLabel(days).toLowerCase()}
          </>
        }
        actions={<RangeSwitcher basePath="/sources" active={days} params={{ domain, category }} />}
      />

      {all.length === 0 ? (
        <EmptyState icon="server" title="No sources in this range">
          Try a wider time range{domain ? ' or another domain' : ''}.
        </EmptyState>
      ) : (
        <>
          <div className="grid-side-main">
            <Card title="Sender mix" icon="layers" sub="Share of messages by category">
              <div style={{ display: 'grid', placeItems: 'center', marginBottom: '1rem' }}>
                <Donut
                  parts={mix.map((m) => ({ label: CATEGORY_LABELS[m.category], value: m.messages, color: CATEGORY_COLOR[m.category] }))}
                  center={fmtInt(all.length)}
                  caption="sources"
                  size={150}
                  stroke={20}
                />
              </div>
              <div style={{ display: 'grid', gap: '0.25rem' }}>
                {mix.map((m) => (
                  <Link
                    key={m.category}
                    href={href({ category: category === m.category ? undefined : m.category })}
                    className="legend-row"
                    style={{
                      color: 'inherit',
                      padding: '0.35rem 0.5rem',
                      borderRadius: 7,
                      background: category === m.category ? 'var(--accent-soft)' : undefined,
                    }}
                    aria-current={category === m.category ? 'true' : undefined}
                    title={CATEGORY_HELP[m.category]}
                  >
                    <span className="swatch" style={{ background: CATEGORY_COLOR[m.category], marginTop: 0 }} />
                    <span className="lbl">{CATEGORY_LABELS[m.category]}</span>
                    <span className="val">{m.sources}</span>
                    <span className="pc">{totalMessages ? pct(m.messages / totalMessages) : '—'}</span>
                  </Link>
                ))}
              </div>
              <p className="muted small" style={{ margin: '0.9rem 0 0' }}>
                {category ? CATEGORY_HELP[category] : 'Select a category to filter the list. Counts are sources; percentages are messages.'}
              </p>
            </Card>

            <Card
              title={category ? CATEGORY_LABELS[category] : 'All sources'}
              icon="server"
              flush
              sub={`${fmtInt(shown.length)} shown${rows.length === LIMIT ? `, of the ${LIMIT} highest-volume` : ''}`}
              action={
                domainNames.length > 1 ? (
                  <form method="get" action="/sources" className="inline-form">
                    <input type="hidden" name="range" value={range} />
                    {category && <input type="hidden" name="category" value={category} />}
                    <label htmlFor="src-domain" className="visually-hidden">
                      Domain
                    </label>
                    <select id="src-domain" name="domain" defaultValue={domain ?? ''}>
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
                ) : undefined
              }
            >
              {shown.length === 0 ? (
                <EmptyState icon="filter">No source in this category.</EmptyState>
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
                      </tr>
                    </thead>
                    <tbody>
                      {shown.map(({ s, id }) => {
                        const t = s.total_messages
                        return (
                          <tr key={s.source_ip}>
                            <td>
                              <SourceCell identity={id} ip={s.source_ip} reverseDns={s.reverse_dns} />
                              {s.as_name && (
                                <div className="muted" style={{ fontSize: '0.72rem', marginLeft: 'calc(30px + 0.7rem)' }}>
                                  {s.as_name}
                                </div>
                              )}
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
              )}
            </Card>
          </div>
        </>
      )}
    </>
  )
}
