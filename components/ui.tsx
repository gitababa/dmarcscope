import Link from 'next/link'
import type { ReactNode } from 'react'
import { RANGES, fmtInt, pct } from '@/lib/format'
import type { Health } from '@/lib/health'
import { CATEGORY_LABELS, CATEGORY_TONE, type SourceIdentity } from '@/lib/senders'
import { Icon, type IconName } from './icons'

export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'muted'

export function Logo({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 4.5 5.3v6.1c0 4.7 3.1 8.6 7.5 10.1 4.4-1.5 7.5-5.4 7.5-10.1V5.3L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="m8.6 12.1 2.4 2.4 4.5-4.7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function BrandMark({ size = 18 }: { size?: number }) {
  return (
    <span className="brand-mark">
      <Logo size={size} />
    </span>
  )
}

export function Pill({ tone = 'muted', children, title, dot }: { tone?: Tone | 'accent'; children: ReactNode; title?: string; dot?: boolean }) {
  return (
    <span className={`pill${tone === 'muted' ? '' : ` ${tone}`}`} title={title}>
      {dot && <span className="dot" />}
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

export function Meter({ rate, tone }: { rate: number; tone?: 'ok' | 'warn' | 'bad' | 'accent' }) {
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
  icon,
}: {
  label: string
  value: string
  sub?: ReactNode
  tone?: 'ok' | 'warn' | 'bad'
  rate?: number
  href?: string
  icon?: IconName
}) {
  const body = (
    <>
      <div className="stat-label">
        {icon && (
          <span className={`stat-icon${tone ? ` ${tone}` : ' accent'}`}>
            <Icon name={icon} size={15} />
          </span>
        )}
        {label}
      </div>
      <div className={`stat-value${tone ? ` tone-${tone}` : ''}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
      {rate != null && Number.isFinite(rate) && <Meter rate={rate} tone={tone} />}
    </>
  )
  return href ? (
    <Link href={href} className="stat">
      <Icon name="arrowRight" size={15} className="stat-go" />
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

// A letter tile for a name (domain, source), standing in for a logo the app
// never fetches.
export function Favicon({ name }: { name: string }) {
  const ch = name.replace(/^www\./, '').match(/[a-z0-9]/i)?.[0] ?? '?'
  return (
    <span className="favicon" aria-hidden="true">
      {ch}
    </span>
  )
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
  const name = identity.name || reverseDns || ip
  return (
    <div className="cell-main">
      <Favicon name={name} />
      <div style={{ minWidth: 0 }}>
        <div className="source-name">{name}</div>
        <div className="source-meta">
          {ip}
          {identity.name && reverseDns ? ` · ${reverseDns}` : ''}
        </div>
      </div>
    </div>
  )
}

export function Section({
  title,
  action,
  sub,
  children,
}: {
  title: string
  action?: ReactNode
  sub?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="section">
      <div className="section-head">
        <div>
          <h2>{title}</h2>
          {sub && <div className="sub">{sub}</div>}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

export function Card({
  title,
  icon,
  sub,
  action,
  flush,
  children,
  className,
  id,
  foot,
}: {
  title?: ReactNode
  icon?: IconName
  sub?: ReactNode
  action?: ReactNode
  flush?: boolean
  children: ReactNode
  className?: string
  id?: string
  foot?: ReactNode
}) {
  return (
    <section className={`card${flush ? ' flush' : ''}${className ? ` ${className}` : ''}`} id={id}>
      {title && (
        <div className="card-head">
          <div>
            <h2>
              {icon && <Icon name={icon} size={16} />}
              {title}
            </h2>
            {sub && <div className="sub">{sub}</div>}
          </div>
          {action}
        </div>
      )}
      {children}
      {foot && <div className="card-foot">{foot}</div>}
    </section>
  )
}

export function PageHeader({
  title,
  lead,
  crumbs,
  actions,
  eyebrow,
  badge,
}: {
  title: ReactNode
  lead?: ReactNode
  crumbs?: Array<{ href?: string; label: string }>
  actions?: ReactNode
  eyebrow?: string
  badge?: ReactNode
}) {
  return (
    <div className="page-head">
      <div className="page-head-main">
        {crumbs && crumbs.length > 0 && (
          <nav className="crumbs" aria-label="Breadcrumb">
            {crumbs.map((c, i) => (
              <span key={i} className="row" style={{ gap: '0.35rem' }}>
                {i > 0 && <Icon name="chevronRight" size={12} />}
                {c.href ? <Link href={c.href}>{c.label}</Link> : <span>{c.label}</span>}
              </span>
            ))}
          </nav>
        )}
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <div className="title-row">
          <h1>{title}</h1>
          {badge}
        </div>
        {lead && <p className="lead">{lead}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  )
}

const NOTICE_ICON: Record<string, IconName> = { ok: 'checkCircle', warn: 'alert', bad: 'xCircle', info: 'info' }

export function Notice({
  tone = 'info',
  children,
  action,
  role,
}: {
  tone?: 'ok' | 'warn' | 'bad' | 'info'
  children: ReactNode
  action?: ReactNode
  role?: 'alert' | 'status' | 'note'
}) {
  return (
    <div className={`notice ${tone}`} role={role}>
      <Icon name={NOTICE_ICON[tone]} size={17} />
      <div className="notice-body">{children}</div>
      {action}
    </div>
  )
}

export function EmptyState({ icon = 'inbox', title, children, action }: { icon?: IconName; title?: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name={icon} size={20} />
      </span>
      {title && <strong>{title}</strong>}
      {children && <p>{children}</p>}
      {action && <div style={{ marginTop: '0.5rem' }}>{action}</div>}
    </div>
  )
}

const TONE_VAR: Record<string, string> = {
  ok: 'var(--ok-solid)',
  warn: 'var(--warn-solid)',
  bad: 'var(--bad-solid)',
  muted: 'var(--border-strong)',
  accent: 'var(--accent)',
}

// A progress ring: value 0..1.
export function Ring({
  value,
  size = 120,
  stroke = 10,
  tone = 'accent',
  label,
  caption,
  small,
}: {
  value: number | null
  size?: number
  stroke?: number
  tone?: string
  label: ReactNode
  caption?: string
  small?: boolean
}) {
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const v = value == null || !Number.isFinite(value) ? 0 : Math.min(1, Math.max(0, value))
  return (
    <div className={`ring${small ? ' sm' : ''}`} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle className="ring-track" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} />
        {v > 0 && (
          <circle
            className="ring-value"
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={TONE_VAR[tone] ?? tone}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={c * (1 - v)}
          />
        )}
      </svg>
      <div className="ring-label">
        <strong>{label}</strong>
        {caption && <span>{caption}</span>}
      </div>
    </div>
  )
}

export function HealthRing({ health, size = 120, caption = 'health' }: { health: Health; size?: number; caption?: string }) {
  return (
    <Ring
      value={health.score == null ? null : health.score / 100}
      size={size}
      stroke={size < 60 ? 5 : 10}
      tone={health.tone}
      label={health.score == null ? '—' : health.score}
      caption={caption}
      small={size < 60}
    />
  )
}

export function GradeBadge({ grade, large, title }: { grade: Health['grade']; large?: boolean; title?: string }) {
  return (
    <span className={`grade grade-${grade ? grade.toLowerCase() : 'none'}${large ? ' lg' : ''}`} title={title ?? (grade ? `Health grade ${grade}` : 'No data')}>
      {grade ?? '–'}
    </span>
  )
}

export function HealthBreakdown({ health }: { health: Health }) {
  if (health.score == null) return <p className="muted small">No mail reported in this range, so there is nothing to grade.</p>
  return (
    <div>
      {health.factors.map((f) => (
        <div className="factor" key={f.key}>
          <span>{f.label}</span>
          <span className={`pts${f.points < 0 ? ' tone-bad' : ''}`}>
            {f.max > 0 ? `${f.points} / ${f.max}` : f.points}
          </span>
          {f.max > 0 && <Meter rate={f.points / f.max} tone={f.points / f.max >= 0.75 ? 'ok' : f.points / f.max >= 0.5 ? 'warn' : 'bad'} />}
          <span className="why">{f.why}</span>
        </div>
      ))}
    </div>
  )
}

// A donut of parts, server-rendered SVG.
export function Donut({
  parts,
  size = 150,
  stroke = 22,
  center,
  caption,
}: {
  parts: Array<{ label: string; value: number; color: string }>
  size?: number
  stroke?: number
  center?: ReactNode
  caption?: string
}) {
  const total = parts.reduce((a, p) => a + p.value, 0)
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  let offset = 0
  return (
    <div className="ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={parts.map((p) => `${p.label}: ${total ? pct(p.value / total) : '—'}`).join(', ')}>
        <circle className="ring-track" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} />
        {total > 0 &&
          parts
            .filter((p) => p.value > 0)
            .map((p) => {
              const len = (p.value / total) * c
              const gap = parts.filter((x) => x.value > 0).length > 1 ? Math.min(2, len / 2) : 0
              const el = (
                <circle
                  key={p.label}
                  cx={size / 2}
                  cy={size / 2}
                  r={r}
                  fill="none"
                  stroke={p.color}
                  strokeWidth={stroke}
                  strokeDasharray={`${Math.max(0, len - gap)} ${c}`}
                  strokeDashoffset={-offset}
                >
                  <title>{`${p.label}: ${fmtInt(p.value)} (${pct(p.value / total)})`}</title>
                </circle>
              )
              offset += len
              return el
            })}
      </svg>
      <div className="ring-label">
        <strong>{center}</strong>
        {caption && <span>{caption}</span>}
      </div>
    </div>
  )
}

export function Avatar({ name, large }: { name: string; large?: boolean }) {
  const parts = name
    .replace(/@.*/, '')
    .split(/[\s._-]+/)
    .filter(Boolean)
  const initials = ((parts[0]?.[0] ?? '?') + (parts[1]?.[0] ?? '')).toUpperCase()
  return (
    <span className={`avatar${large ? ' lg' : ''}`} aria-hidden="true">
      {initials}
    </span>
  )
}

export function policyLabel(p: string | null): string {
  return p ? `p=${p}` : 'no policy'
}
