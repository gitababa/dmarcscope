export const RANGES = [
  { days: 7, label: '7d', param: '7d' },
  { days: 30, label: '30d', param: '30d' },
  { days: 90, label: '90d', param: '90d' },
  { days: 0, label: 'All', param: 'all' },
] as const

export function parseRange(raw: string | undefined): number {
  if (!raw) return 7
  if (raw === 'all') return 0
  const match = raw.match(/^(\d+)d$/)
  if (!match) return 7
  const days = Number.parseInt(match[1], 10)
  return RANGES.some((r) => r.days === days) ? days : 7
}

export function rangeParam(days: number): string {
  return days === 0 ? 'all' : `${days}d`
}

export function rangeLabel(days: number): string {
  return days === 0 ? 'All time' : `Last ${days} days`
}

export function pct(n: number): string {
  if (!Number.isFinite(n)) return '—'
  return `${(n * 100).toFixed(1)}%`
}

export function fmtInt(n: number): string {
  return n.toLocaleString('en-US')
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

export function relTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(diff)) return '—'
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

// reject = enforced, quarantine = partly enforced, none = monitoring only.
export function policyTone(policy: string | null | undefined): 'ok' | 'info' | 'warn' | 'muted' {
  if (policy === 'reject') return 'ok'
  if (policy === 'quarantine') return 'info'
  if (policy === 'none') return 'warn'
  return 'muted'
}
