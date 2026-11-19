// A domain's health grade: one number that answers "how protected is this
// domain, and how much of its own mail gets through?". It is built only from
// what the reports and the latest DNS check show, and every page that shows
// it also shows how it was made up, so it never stands as an unexplained
// verdict.
//
//   Authentication  50  share of mail passing DMARC (80% or less scores 0)
//   Enforcement     30  the published policy: reject 30, quarantine 20, none 0
//   DKIM coverage   20  share of mail with an aligned DKIM signature
//
// A failing DNS check (no DMARC record, broken SPF) costs 10 points each, so
// a domain with good history but a record that has since vanished drops.

export type HealthFactor = {
  key: 'auth' | 'policy' | 'dkim' | 'dns'
  label: string
  points: number
  max: number
  why: string
}

export type Health = {
  score: number | null
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | null
  tone: 'ok' | 'warn' | 'bad' | 'muted'
  factors: HealthFactor[]
}

type Input = {
  total: number
  dmarcPass: number
  dkimPass: number
  policy: string | null
  // From the latest DNS check, when one has been run.
  dns?: { dmarc?: string; spf?: string } | null
}

const clamp = (n: number) => Math.min(1, Math.max(0, n))
const pc = (n: number) => `${(n * 100).toFixed(1)}%`

export function gradeFor(score: number): NonNullable<Health['grade']> {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

export function toneFor(score: number | null): Health['tone'] {
  if (score == null) return 'muted'
  if (score >= 75) return 'ok'
  if (score >= 60) return 'warn'
  return 'bad'
}

export function domainHealth({ total, dmarcPass, dkimPass, policy, dns }: Input): Health {
  if (total <= 0) return { score: null, grade: null, tone: 'muted', factors: [] }
  const rate = dmarcPass / total
  const dkimRate = dkimPass / total
  const p = (policy || '').toLowerCase()

  const factors: HealthFactor[] = [
    {
      key: 'auth',
      label: 'Authentication',
      max: 50,
      points: Math.round(50 * clamp((rate - 0.8) / 0.2)),
      why: `${pc(rate)} of mail passes DMARC (full marks at 100%, none at 80% or less).`,
    },
    {
      key: 'policy',
      label: 'Enforcement',
      max: 30,
      points: p === 'reject' ? 30 : p === 'quarantine' ? 20 : 0,
      why:
        p === 'reject'
          ? 'p=reject: receivers refuse spoofed mail.'
          : p === 'quarantine'
            ? 'p=quarantine: spoofed mail goes to spam. p=reject scores full marks.'
            : p === 'none'
              ? 'p=none only monitors; spoofed mail is still delivered.'
              : 'No policy seen in reports.',
    },
    {
      key: 'dkim',
      label: 'DKIM coverage',
      max: 20,
      points: Math.round(20 * clamp(dkimRate)),
      why: `${pc(dkimRate)} of mail carries an aligned DKIM signature, which survives forwarding.`,
    },
  ]

  const broken = [dns?.dmarc === 'fail' && 'DMARC', dns?.spf === 'fail' && 'SPF'].filter(Boolean) as string[]
  if (broken.length > 0) {
    factors.push({
      key: 'dns',
      label: 'DNS records',
      max: 0,
      points: -10 * broken.length,
      why: `The latest DNS check failed for ${broken.join(' and ')}.`,
    })
  }

  const score = Math.max(0, Math.min(100, factors.reduce((a, f) => a + f.points, 0)))
  return { score, grade: gradeFor(score), tone: toneFor(score), factors }
}

// Volume-weighted across domains: a tiny domain with a bad grade should not
// drag down an organisation whose real mail is fine (it still shows on its own).
export function overallHealth(items: Array<{ total: number; health: Health }>): number | null {
  let weight = 0
  let sum = 0
  for (const i of items) {
    if (i.health.score == null || i.total <= 0) continue
    weight += i.total
    sum += i.total * i.health.score
  }
  return weight > 0 ? Math.round(sum / weight) : null
}
