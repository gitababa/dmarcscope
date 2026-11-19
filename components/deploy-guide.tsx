'use client'

// The deployment guide: a dialog with the steps for the platform the reader
// picks, and resource and schedule recommendations for their volume of
// report emails. Opens from its button, and by itself once after setup
// (/admin?guide=1). Content: lib/deploy-guide.ts and lib/sizing.ts.

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { PLATFORMS, VERCEL_PLAN_NOTES } from '@/lib/deploy-guide'
import { type PlatformId, type VercelPlan, recommendations } from '@/lib/sizing'
import { Icon } from './icons'

const PRESETS = [10, 100, 1_000, 10_000]
const RETENTION: Array<{ label: string; days: number | null }> = [
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
  { label: '2 years', days: 730 },
  { label: 'forever (3 years shown)', days: null },
]

// `code` in backticks becomes <code>; everything is text.
function Text({ children }: { children: string }) {
  const parts = children.split('`')
  return <>{parts.map((p, i) => (i % 2 ? <code key={i}>{p}</code> : p))}</>
}

export function DeploymentGuide({ detected, label = 'Deployment guide', className = 'btn btn-sm' }: { detected: PlatformId | null; label?: ReactNode; className?: string }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  const [platform, setPlatform] = useState<PlatformId>(detected ?? 'vercel')
  const [plan, setPlan] = useState<VercelPlan>('hobby')
  const [perDay, setPerDay] = useState(20)
  const [retention, setRetention] = useState<number | null>(365)

  const open = () => dialog.current?.showModal()

  // Once, right after setup.
  useEffect(() => {
    const url = new URL(window.location.href)
    if (url.searchParams.get('guide') !== '1') return
    url.searchParams.delete('guide')
    window.history.replaceState(null, '', url.pathname + url.search + url.hash)
    open()
  }, [])

  const p = PLATFORMS.find((x) => x.id === platform) ?? PLATFORMS[0]
  const recs = recommendations(platform, { reportsPerDay: perDay, retentionDays: retention }, plan)

  return (
    <>
      <button type="button" className={className} onClick={open} aria-haspopup="dialog">
        <Icon name="server" size={14} /> {label}
      </button>
      <dialog ref={dialog} className="guide-dialog" aria-labelledby={titleId}>
        <div className="guide-head">
          <div>
            <div className="eyebrow">Setup</div>
            <h2 id={titleId}>Deployment guide</h2>
          </div>
          <form method="dialog">
            <button className="btn btn-ghost btn-icon" aria-label="Close">
              <Icon name="x" size={18} />
            </button>
          </form>
        </div>

        <div className="guide-body">
          <div role="radiogroup" aria-label="Platform" className="seg guide-seg">
            {PLATFORMS.map((x) => (
              <button key={x.id} type="button" role="radio" aria-checked={x.id === platform} onClick={() => setPlatform(x.id)}>
                {x.name}
                {x.id === detected ? <span className="guide-here"> · this one</span> : null}
              </button>
            ))}
          </div>
          <p className="muted">{p.summary}</p>

          {platform === 'vercel' && (
            <div className="guide-plan">
              <div role="radiogroup" aria-label="Vercel plan" className="seg guide-seg">
                {(['hobby', 'pro'] as const).map((x) => (
                  <button key={x} type="button" role="radio" aria-checked={x === plan} onClick={() => setPlan(x)}>
                    {x === 'hobby' ? 'Hobby (free)' : 'Pro'}
                  </button>
                ))}
              </div>
              <ul className="guide-notes">
                {VERCEL_PLAN_NOTES[plan].map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
          )}

          <h3>Steps</h3>
          <ol className="guide-steps">
            {p.steps.map((s) => (
              <li key={s.title}>
                <strong>{s.title}.</strong> <Text>{s.body}</Text>
                {s.code && <pre className="guide-code">{s.code}</pre>}
              </li>
            ))}
          </ol>

          <h3>Sizing for your volume</h3>
          <div className="guide-volume">
            <label>
              <span>Report emails per day</span>
              <input
                type="number"
                min={1}
                max={1000000}
                inputMode="numeric"
                value={perDay}
                onChange={(e) => setPerDay(Math.max(1, Math.min(1_000_000, Number(e.target.value) || 1)))}
              />
            </label>
            <div className="seg guide-seg" role="group" aria-label="Typical volumes">
              {PRESETS.map((n) => (
                <button key={n} type="button" aria-pressed={n === perDay} onClick={() => setPerDay(n)}>
                  {n.toLocaleString('en-US')}
                </button>
              ))}
            </div>
            <label>
              <span>Keep reports for</span>
              <select value={retention ?? ''} onChange={(e) => setRetention(e.target.value ? Number(e.target.value) : null)}>
                {RETENTION.map((r) => (
                  <option key={r.label} value={r.days ?? ''}>
                    {r.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <p className="muted small">
            A domain usually gets 5 to 15 reports a day, one from each large mailbox provider its mail reaches. Add them up over your
            domains.
          </p>
          <dl className="guide-recs">
            {recs.map((r) => (
              <div key={r.label} className={r.tone === 'warn' ? 'warn' : undefined}>
                <dt>{r.label}</dt>
                <dd>
                  {r.value}
                  {r.note && <span className="muted small"> — {r.note}</span>}
                </dd>
              </div>
            ))}
          </dl>
          <p className="muted small">
            Based on about 4 KB of database per report (measured), and an assumed 0.3 s to fetch one message from a hosted mailbox. The full
            instructions are in docs/deployment.md, section “{p.docs}”.
          </p>
        </div>
      </dialog>
    </>
  )
}
