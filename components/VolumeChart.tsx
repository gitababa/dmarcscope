import type { TimeseriesPoint } from '@/lib/queries'
import { fmtDate, fmtInt, pct } from '@/lib/format'
import { EmptyState } from './ui'

function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(n >= 10_000_000 ? 0 : 1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(n >= 10_000 ? 0 : 1)}k`
  return String(Math.round(n))
}

// A round number at or above n, for the y axis.
function niceMax(n: number): number {
  if (n <= 0) return 1
  const p = 10 ** Math.floor(Math.log10(n))
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= n) return m * p
  return 10 * p
}

// Server-rendered chart: DMARC pass vs fail per day as stacked bars, with the
// day's compliance rate as a line on its own 0–100% scale.
// Pure SVG, no client JS. Native <title> elements give hover tooltips, and a
// visually hidden summary carries the same information for screen readers.
export function VolumeChart({ data, height = 230 }: { data: TimeseriesPoint[]; height?: number }) {
  if (data.length === 0) {
    return <EmptyState icon="activity" title="No volume in this range">Try a wider time range.</EmptyState>
  }

  const W = 960
  const H = height
  const PAD_L = 44
  const PAD_R = 40
  const PAD_TOP = 14
  const PAD_BOTTOM = 26

  const max = niceMax(Math.max(...data.map((d) => d.total), 1))
  const innerW = W - PAD_L - PAD_R
  const innerH = H - PAD_TOP - PAD_BOTTOM
  const step = innerW / data.length
  const gap = data.length > 60 ? 1 : data.length > 20 ? 3 : 6
  const barW = Math.max(1.5, Math.min(40, step - gap))
  const baseline = H - PAD_BOTTOM
  const r = Math.min(3, barW / 2)

  const total = data.reduce((a, d) => a + d.total, 0)
  const passed = data.reduce((a, d) => a + d.passed, 0)

  const rateY = (rate: number) => baseline - innerH * rate
  const linePts = data
    .map((d, i) => (d.total > 0 ? `${(PAD_L + i * step + step / 2).toFixed(1)},${rateY(d.passed / d.total).toFixed(1)}` : null))
    .filter(Boolean)
    .join(' ')

  // Up to ~6 date labels along the bottom.
  const every = Math.max(1, Math.ceil(data.length / 6))

  return (
    <div className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Daily message volume, DMARC pass versus fail, with daily compliance rate">
        {[0, 0.25, 0.5, 0.75, 1].map((f) => {
          const y = baseline - innerH * f
          return (
            <g key={f}>
              <line x1={PAD_L} y1={y} x2={W - PAD_R} y2={y} stroke="var(--border)" strokeDasharray={f === 0 ? undefined : '2 5'} />
              <text x={PAD_L - 8} y={y + 4} fontSize="11" textAnchor="end">
                {compact(max * f)}
              </text>
              <text x={W - PAD_R + 8} y={y + 4} fontSize="11">
                {Math.round(f * 100)}%
              </text>
            </g>
          )
        })}

        {data.map((d, i) => {
          const x = PAD_L + i * step + (step - barW) / 2
          const failed = Math.max(0, d.total - d.passed)
          const passH = (d.passed / max) * innerH
          const failH = failed > 0 ? Math.max((failed / max) * innerH, 1.5) : 0
          return (
            <g key={d.day} className="col">
              <title>{`${fmtDate(d.day)}\n${fmtInt(d.total)} messages\n${fmtInt(d.passed)} pass · ${fmtInt(failed)} fail\n${pct(d.total ? d.passed / d.total : NaN)} compliant`}</title>
              <rect x={PAD_L + i * step} y={PAD_TOP} width={step} height={innerH} fill="transparent" />
              {passH > 0 && <rect className="bar" x={x} y={baseline - passH} width={barW} height={passH} fill="var(--ok-solid)" opacity="0.85" rx={failH > 0 ? 0 : r} />}
              {failH > 0 && <rect className="bar" x={x} y={baseline - passH - failH} width={barW} height={failH} fill="var(--bad-solid)" rx={r} />}
              {i % every === 0 && (
                <text x={PAD_L + i * step + step / 2} y={H - 7} fontSize="11" textAnchor="middle">
                  {new Date(d.day).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}
                </text>
              )}
            </g>
          )
        })}

        {data.length > 1 && (
          <polyline points={linePts} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" pointerEvents="none" />
        )}
      </svg>
      <div className="chart-legend" style={{ marginTop: '0.6rem' }}>
        <span>
          <i style={{ background: 'var(--ok-solid)' }} />
          DMARC pass
        </span>
        <span>
          <i style={{ background: 'var(--bad-solid)' }} />
          DMARC fail
        </span>
        <span>
          <i style={{ background: 'var(--accent)', height: 3, borderRadius: 2 }} />
          Compliance rate (right axis)
        </span>
        <span style={{ marginLeft: 'auto' }}>
          {fmtInt(total)} messages · {data.length} {data.length === 1 ? 'day' : 'days'}
        </span>
      </div>
      <p className="sr-only">
        {fmtInt(total)} messages over {data.length} days; {fmtInt(passed)} passed DMARC and {fmtInt(total - passed)} failed.
      </p>
    </div>
  )
}

// A small inline trend of daily compliance, for cards.
export function Sparkline({ data, width = 120, height = 32 }: { data: TimeseriesPoint[]; width?: number; height?: number }) {
  const pts = data.filter((d) => d.total > 0)
  if (pts.length < 2) return <svg className="spark" width={width} height={height} aria-hidden="true" />
  const max = Math.max(...pts.map((d) => d.total))
  const step = width / (pts.length - 1)
  const line = pts.map((d, i) => `${(i * step).toFixed(1)},${(height - 3 - (d.total / max) * (height - 6)).toFixed(1)}`).join(' ')
  return (
    <svg className="spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <polyline points={`0,${height} ${line} ${width},${height}`} fill="var(--accent-soft)" stroke="none" />
      <polyline points={line} fill="none" stroke="var(--accent)" strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}
