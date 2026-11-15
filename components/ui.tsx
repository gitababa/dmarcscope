import Link from 'next/link'
import type { ReactNode } from 'react'
import { RANGES, pct } from '@/lib/format'
import { CATEGORY_LABELS, CATEGORY_TONE, type SourceIdentity } from '@/lib/senders'

export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'muted'

export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9.25" stroke="currentColor" strokeWidth="1.5" opacity="0.35" />
      <circle cx="12" cy="12" r="5.25" stroke="currentColor" strokeWidth="1.5" opacity="0.65" />
      <path d="M12 12 19.2 6.4" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
      <circle cx="12" cy="12" r="1.9" fill="currentColor" />
    </svg>
  )
}

export function Pill({ tone = 'muted', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`pill${tone === 'muted' ? '' : ` ${tone}`}`} title={title}>
      {children}
    </span>
  )
}

// Compliance thresholds used consistently across the app.
export function rateTone(rate: number): 'ok' | 'warn' | 'bad' {
  if (rate >= 0.98) return 'ok'
  if (rate >= 0.9) return 'warn'
  return 'bad'
}

export function Meter({ rate, tone }: { rate: number; tone?: 'ok' | 'warn' | 'bad' }) {
  const clamped = Number.isFinite(rate) ? Math.min(1, Math.max(0, rate)) : 0
  const t = tone ?? rateTone(clamped)
  return (
    <div className={`meter${t === 'ok' ? '' : ` ${t}`}`} aria-hidden="true">
      <span style={{ width: `${(clamped * 100).toFixed(1)}%` }} />
    </div>
  )
}

// "97.3%" plus a small bar, right-aligned for table cells.
export function RateCell({ passed, total }: { passed: number; total: number }) {
  if (total <= 0) return <span className="muted">—</span>
  const rate = passed / total
  return (
    <div className="rate-cell">
      <span className={`tone-${rateTone(rate)}`}>{pct(rate)}</span>
      <Meter rate={rate} />
    </div>
  )
}

export function Stat({
  label,
  value,
  sub,
  tone,
  rate,
  href,
}: {
  label: string
  value: string
  sub?: string
  tone?: 'ok' | 'warn' | 'bad'
  rate?: number
  href?: string
}) {
  const body = (
    <>
      <div className="stat-label">{label}</div>
      <div className={`stat-value${tone ? ` tone-${tone}` : ''}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
      {rate != null && Number.isFinite(rate) && <Meter rate={rate} tone={tone} />}
    </>
  )
  return href ? (
    <Link href={href} className="stat">
      {body}
    </Link>
  ) : (
    <div className="stat">{body}</div>
  )
}

export function RangeSwitcher({
  basePath,
  active,
  params,
}: {
  basePath: string
  active: number
  params?: Record<string, string | undefined>
}) {
  return (
    <nav className="seg" aria-label="Time range">
      {RANGES.map((r) => {
        const q = new URLSearchParams()
        for (const [k, v] of Object.entries(params ?? {})) if (v) q.set(k, v)
        q.set('range', r.param)
        return (
          <Link key={r.param} href={`${basePath}?${q}`} aria-current={active === r.days ? 'true' : undefined}>
            {r.label}
          </Link>
        )
      })}
    </nav>
  )
}

export function CategoryPill({ identity }: { identity: SourceIdentity }) {
  const tone = CATEGORY_TONE[identity.category]
  return <Pill tone={tone === 'muted' ? 'info' : tone}>{CATEGORY_LABELS[identity.category]}</Pill>
}

export function SourceCell({
  identity,
  ip,
  reverseDns,
}: {
  identity: SourceIdentity
  ip: string
  reverseDns: string | null
}) {
  return (
    <>
      <div className="source-name">{identity.name || reverseDns || ip}</div>
      <div className="source-meta">
        {ip}
        {identity.name && reverseDns ? ` · ${reverseDns}` : ''}
      </div>
    </>
  )
}

export function Section({
  title,
  action,
  children,
}: {
  title: string
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="section">
      <div className="section-head">
        <h2>{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}
