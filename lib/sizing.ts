// Resource and schedule recommendations for the deployment guide, from the
// number of report emails a deployment reads per day.
//
// Measured (PostgreSQL 17, the ingest worker on an Apple M-series laptop,
// November 2026; scripts/sizing_benchmark.py):
//   database storage per report: 1.5 KB (1 record), 4.0 KB (5), 13 KB (20),
//   61 KB (100) — about 1 KB plus 600 bytes per record, counting the sending
//   IP's reverse-DNS row; parse and store: 4–14 ms per report up to 20
//   records; worker memory after start: about 70 MB.
// Assumed (not measured here): 0.3 s to fetch one message from a hosted
// IMAP server, which dominates; reports arrive in a burst, about a quarter
// of a day's reports in the busiest hour.

export const MEASURED = {
  dbBytesPerReport: 4_000, // a typical report: 5 records
  workerMemoryMb: 70,
}
export const ASSUMED = {
  fetchSecondsPerMessage: 0.3,
  busiestHourShare: 0.25,
}

// Defaults the worker ships with (docs/configuration.md).
export const WORKER_DEFAULTS = { maxMessagesPerRun: 2000, mailBudgetSeconds: 600, vercelMailBudgetSeconds: 170 }

export type Volume = { reportsPerDay: number; retentionDays: number | null }

export type Rec = { label: string; value: string; note?: string; tone?: 'ok' | 'warn' }

const MB = 1_000_000
const GB = 1_000_000_000

export function storageBytes(v: Volume): { perYear: number; kept: number } {
  const perDay = Math.max(0, v.reportsPerDay) * MEASURED.dbBytesPerReport
  return { perYear: perDay * 365, kept: perDay * (v.retentionDays ?? 365 * 3) }
}

export function formatBytes(bytes: number): string {
  if (bytes < 10 * MB) return `${Math.max(1, Math.round(bytes / MB))} MB`
  if (bytes < GB) return `${Math.round(bytes / MB / 10) * 10} MB`
  return `${(bytes / GB).toFixed(bytes < 10 * GB ? 1 : 0)} GB`
}

// Messages one run can read in its mail budget.
export function messagesPerRun(mailBudgetSeconds: number): number {
  return Math.min(WORKER_DEFAULTS.maxMessagesPerRun, Math.floor(mailBudgetSeconds / ASSUMED.fetchSecondsPerMessage))
}

// The longest interval (one of 15, 30, 60 minutes, or a day) at which a run
// never has more mail waiting than it can read, keeping half in reserve.
export function intervalMinutes(reportsPerDay: number, mailBudgetSeconds: number): number {
  const capacity = messagesPerRun(mailBudgetSeconds) / 2
  for (const minutes of [1440, 60, 30, 15]) {
    const waiting = minutes >= 1440 ? reportsPerDay : reportsPerDay * ASSUMED.busiestHourShare * (minutes / 60)
    if (waiting <= capacity) return minutes
  }
  return 15
}

export function everyLabel(minutes: number): string {
  return minutes >= 1440 ? 'once a day' : minutes === 60 ? 'every hour' : `every ${minutes} minutes`
}

// Days of reports that fit in `bytes`, or null if a long retention fits.
export function retentionFor(v: Volume, bytes: number): number | null {
  const perDay = v.reportsPerDay * MEASURED.dbBytesPerReport
  if (perDay <= 0) return null
  const days = Math.floor(bytes / perDay)
  return days >= 365 * 3 ? null : days
}

function retentionRec(v: Volume, bytes: number, where: string): Rec {
  const { kept } = storageBytes(v)
  const fits = retentionFor(v, bytes)
  if (kept <= bytes) return { label: 'Database size', value: formatBytes(kept), note: `fits ${where}`, tone: 'ok' }
  return {
    label: 'Database size',
    value: formatBytes(kept),
    note: `more than ${where}: set Keep reports for (days) to ${fits ?? 365} or less in Settings, or use a larger plan`,
    tone: 'warn',
  }
}

export type VercelPlan = 'hobby' | 'pro'
export type PlatformId = 'vercel' | 'docker' | 'kubernetes' | 'cloudrun'

// Neon's Free plan: 1 GB per project (neon.com/docs/introduction/plans,
// November 2026). Keep a fifth in reserve.
const NEON_FREE_BYTES = 0.8 * GB

export function recommendations(platform: PlatformId, v: Volume, plan: VercelPlan = 'hobby'): Rec[] {
  const rpd = Math.max(0, Math.round(v.reportsPerDay))
  const { perYear } = storageBytes(v)
  const growth: Rec = { label: 'Database growth', value: `${formatBytes(perYear)} a year`, note: 'about 4 KB per report' }

  if (platform === 'vercel') {
    const perPass = messagesPerRun(WORKER_DEFAULTS.vercelMailBudgetSeconds)
    const needed = intervalMinutes(rpd, WORKER_DEFAULTS.vercelMailBudgetSeconds)
    const out: Rec[] = []
    if (plan === 'hobby') {
      out.push(
        needed >= 1440
          ? { label: 'Schedule', value: 'once a day (as shipped)', note: `one call reads about ${perPass} messages; enough for this volume`, tone: 'ok' }
          : {
              label: 'Schedule',
              value: `${everyLabel(needed)}, from an outside scheduler`,
              note: `Hobby's daily call reads about ${perPass} messages, too few for ${rpd.toLocaleString('en-US')} a day. Call /api/cron/ingest from GitHub Actions or cron-job.org, or move to Pro`,
              tone: 'warn',
            }
      )
    } else {
      out.push({
        label: 'Schedule',
        value: needed >= 1440 ? 'once a day is enough; every hour keeps data fresher' : everyLabel(needed),
        note: 'set it in vercel.json, e.g. "0 * * * *" for every hour',
      })
    }
    out.push(
      { label: 'Mailbox interval', value: needed >= 1440 ? '60 minutes (the default)' : `${Math.max(15, Math.min(needed, 60))} minutes` },
      { label: 'Time limits', value: 'leave as shipped', note: 'each call stops after 240 s, inside the 300 s every plan allows' },
      plan === 'hobby' ? retentionRec(v, NEON_FREE_BYTES, "Neon's free 1 GB") : { ...retentionRec(v, 10 * GB, 'a 10 GB database'), label: 'Database size' },
      growth
    )
    return out
  }

  const interval = intervalMinutes(rpd, WORKER_DEFAULTS.mailBudgetSeconds)
  const mailboxInterval: Rec = {
    label: 'Mailbox interval',
    value: `${Math.max(15, Math.min(interval, 60))} minutes`,
    note: interval < 60 ? 'reports arrive in bursts; shorter runs keep each one small' : 'the default',
  }
  const big = rpd > 5_000
  const huge = rpd > 20_000

  if (platform === 'docker') {
    const disk = Math.max(10 * GB, storageBytes(v).kept * 1.5 + 5 * GB)
    return [
      { label: 'Server', value: huge ? '4 vCPU, 8 GB RAM' : big ? '2 vCPU, 4 GB RAM' : '1 vCPU, 2 GB RAM', note: big ? undefined : '1 GB works for a trial; PostgreSQL, the web app and the worker share it' },
      { label: 'Disk', value: formatBytes(disk), note: 'database at your retention, plus images and room to grow' },
      mailboxInterval,
      growth,
      { label: 'Backups', value: 'the pgdata volume', note: 'nightly pg_dump is plenty' },
    ]
  }

  if (platform === 'kubernetes') {
    return [
      { label: 'Web', value: '2 replicas, 100m CPU, 192Mi (limit 512Mi)', note: 'as in docs/deployment.md' },
      {
        label: 'Worker',
        value: big ? '1 replica, 250m CPU, 512Mi (limit 1Gi)' : '1 replica, 50m CPU, 192Mi (limit 1Gi)',
        note: `about ${MEASURED.workerMemoryMb} MB at rest`,
      },
      { label: 'PostgreSQL volume', value: formatBytes(Math.max(5 * GB, storageBytes(v).kept * 1.5)) },
      mailboxInterval,
      growth,
    ]
  }

  // Cloud Run: the ingest job runs `python -m ingestor pass`.
  const passEvery = Math.min(intervalMinutes(rpd, 420), 60)
  const passesPerDay = 1440 / passEvery
  const secondsPerPass = 20 + (rpd / passesPerDay) * ASSUMED.fetchSecondsPerMessage
  const vcpuSecondsPerMonth = Math.round(passesPerDay * 30 * secondsPerPass)
  return [
    { label: 'Ingest job', value: `python -m ingestor pass, ${everyLabel(passEvery)}`, note: 'Cloud Scheduler; Test connection and Run now are carried out at the next call' },
    {
      label: 'Job resources',
      value: '1 vCPU, 512 MiB, task timeout 10 min',
      note: `about ${vcpuSecondsPerMonth.toLocaleString('en-US')} vCPU-seconds a month; the free tier covers 240,000`,
      tone: vcpuSecondsPerMonth <= 240_000 ? 'ok' : 'warn',
    },
    { label: 'Job time limits', value: 'INGEST_PASS_BUDGET_SECONDS=540, INGEST_TIME_BUDGET_SECONDS=420', note: 'inside the 10-minute task timeout' },
    { label: 'Web service', value: '1 vCPU, 512 MiB, minimum instances 0' },
    {
      label: 'Cloud SQL',
      value: big ? 'a dedicated-core instance' : 'db-g1-small (db-f1-micro to try it out)',
      note: 'shared-core machines are not covered by the Cloud SQL SLA',
    },
    { label: 'Database size', value: formatBytes(storageBytes(v).kept) },
    growth,
  ]
}
