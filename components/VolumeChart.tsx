import type { TimeseriesPoint } from '@/lib/queries'
import { fmtInt, fmtDate } from '@/lib/format'

// Server-rendered stacked bar chart: DMARC pass vs fail per day.
// Pure SVG, no client JS. Native <title> elements give hover tooltips, and a
// visually hidden summary carries the same information for screen readers.
export function VolumeChart({ data }: { data: TimeseriesPoint[] }) {
  if (data.length === 0) {
    return <div className="empty">No volume data in this range.</div>
  }

  const W = 960
  const H = 200
  const PAD_L = 8
  const PAD_R = 8
  const PAD_TOP = 18
  const PAD_BOTTOM = 24

  const maxTotal = Math.max(...data.map((d) => d.total), 1)
  const innerW = W - PAD_L - PAD_R
  const innerH = H - PAD_TOP - PAD_BOTTOM
  const step = innerW / data.length
  const gap = data.length > 60 ? 1 : data.length > 20 ? 2 : 4
  const barW = Math.max(1.5, Math.min(48, step - gap))
  const baseline = H - PAD_BOTTOM

  const total = data.reduce((a, d) => a + d.total, 0)
  const passed = data.reduce((a, d) => a + d.passed, 0)

  return (
    <div className="card chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Daily message volume, DMARC pass versus fail">
        {[0, 0.5, 1].map((f) => {
          const y = baseline - innerH * f
          return (
            <line
              key={f}
              x1={PAD_L}
              y1={y}
              x2={W - PAD_R}
              y2={y}
              stroke="var(--border)"
              strokeDasharray={f === 0 ? undefined : '3 4'}
            />
          )
        })}
        <text x={PAD_L} y={PAD_TOP - 6} fontSize="11">
          {fmtInt(maxTotal)} messages / day
        </text>

        {data.map((d, i) => {
          const x = PAD_L + i * step + (step - barW) / 2
          const failed = Math.max(0, d.total - d.passed)
          const passH = (d.passed / maxTotal) * innerH
          const failH = (failed / maxTotal) * innerH
          return (
            <g key={d.day}>
              <title>{`${fmtDate(d.day)}\n${fmtInt(d.passed)} pass · ${fmtInt(failed)} fail`}</title>
              {/* full-height transparent hit area so thin bars are hoverable */}
              <rect x={PAD_L + i * step} y={PAD_TOP} width={step} height={innerH} fill="transparent" />
              {passH > 0 && (
                <rect x={x} y={baseline - passH} width={barW} height={passH} fill="var(--ok-solid)" rx={Math.min(2, barW / 2)} />
              )}
              {failH > 0 && (
                <rect
                  x={x}
                  y={baseline - passH - Math.max(failH, 1.5)}
                  width={barW}
                  height={Math.max(failH, 1.5)}
                  fill="var(--bad-solid)"
                  rx={Math.min(2, barW / 2)}
                />
              )}
            </g>
          )
        })}

        <text x={PAD_L} y={H - 7} fontSize="11">
          {fmtDate(data[0].day)}
        </text>
        {data.length > 1 && (
          <text x={W - PAD_R} y={H - 7} fontSize="11" textAnchor="end">
            {fmtDate(data[data.length - 1].day)}
          </text>
        )}
      </svg>
      <div className="chart-legend">
        <span>
          <i style={{ background: 'var(--ok-solid)' }} />
          DMARC pass
        </span>
        <span>
          <i style={{ background: 'var(--bad-solid)' }} />
          DMARC fail
        </span>
        <span>
          {data.length} {data.length === 1 ? 'day' : 'days'} with data
        </span>
      </div>
      <p className="sr-only">
        {fmtInt(total)} messages over {data.length} days; {fmtInt(passed)} passed DMARC and {fmtInt(total - passed)} failed.
      </p>
    </div>
  )
}
