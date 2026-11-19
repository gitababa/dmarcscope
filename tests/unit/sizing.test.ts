import { describe, expect, it } from 'vitest'
import { detectPlatform, PLATFORMS } from '@/lib/deploy-guide'
import { formatBytes, intervalMinutes, messagesPerRun, recommendations, retentionFor, storageBytes } from '@/lib/sizing'

const rec = (recs: ReturnType<typeof recommendations>, label: string) => recs.find((r) => r.label === label)

describe('sizing', () => {
  it('estimates storage from the measured 4 KB per report', () => {
    expect(storageBytes({ reportsPerDay: 100, retentionDays: 365 }).perYear).toBe(146_000_000)
    expect(formatBytes(146_000_000)).toBe('150 MB')
    expect(formatBytes(2_920_000_000)).toBe('2.9 GB')
    expect(formatBytes(1_000)).toBe('1 MB')
  })

  it('reads at most what a run has time for, and never more than INGEST_MAX_MESSAGES', () => {
    expect(messagesPerRun(170)).toBe(566)
    expect(messagesPerRun(600)).toBe(2000)
  })

  it('picks the longest interval that keeps each run within half its capacity', () => {
    expect(intervalMinutes(50, 600)).toBe(1440)
    // 3,000 a day: about 750 in the busiest hour, within half of a 2,000-message run.
    expect(intervalMinutes(3_000, 600)).toBe(60)
    expect(intervalMinutes(5_000, 600)).toBe(30)
    expect(intervalMinutes(10_000, 600)).toBe(15)
    expect(intervalMinutes(1_000_000, 600)).toBe(15)
  })

  it('shortens retention to fit a database limit', () => {
    expect(retentionFor({ reportsPerDay: 1_000, retentionDays: null }, 800_000_000)).toBe(200)
    expect(retentionFor({ reportsPerDay: 10, retentionDays: null }, 800_000_000)).toBeNull()
  })
})

describe('Vercel recommendations', () => {
  it('keep the daily Hobby schedule while one call can read a day of mail', () => {
    const recs = recommendations('vercel', { reportsPerDay: 50, retentionDays: 365 }, 'hobby')
    expect(rec(recs, 'Schedule')).toMatchObject({ tone: 'ok' })
    expect(rec(recs, 'Database size')).toMatchObject({ tone: 'ok' })
  })

  it('send a busy Hobby deployment to an outside scheduler, and warn about the free database', () => {
    const recs = recommendations('vercel', { reportsPerDay: 2_000, retentionDays: 730 }, 'hobby')
    expect(rec(recs, 'Schedule')).toMatchObject({ tone: 'warn' })
    expect(rec(recs, 'Schedule')?.note).toMatch(/outside scheduler|GitHub Actions/)
    expect(rec(recs, 'Database size')).toMatchObject({ tone: 'warn' })
    expect(rec(recs, 'Database size')?.note).toMatch(/Keep reports for \(days\) to 100 or less/)
  })

  it('give Pro a schedule for vercel.json', () => {
    // One call reads about 566 messages; 2,000 a day needs a call every 30 minutes in the busiest hour.
    expect(rec(recommendations('vercel', { reportsPerDay: 2_000, retentionDays: 365 }, 'pro'), 'Schedule')?.value).toBe('every 30 minutes')
  })
})

describe('other platforms', () => {
  it('size a server, a cluster and Cloud Run by volume', () => {
    expect(rec(recommendations('docker', { reportsPerDay: 20, retentionDays: 365 }), 'Server')?.value).toBe('1 vCPU, 2 GB RAM')
    expect(rec(recommendations('docker', { reportsPerDay: 30_000, retentionDays: 365 }), 'Server')?.value).toBe('4 vCPU, 8 GB RAM')
    expect(rec(recommendations('kubernetes', { reportsPerDay: 10_000, retentionDays: 365 }), 'Worker')?.value).toMatch(/250m/)
    const run = recommendations('cloudrun', { reportsPerDay: 100, retentionDays: 365 })
    expect(rec(run, 'Ingest job')?.value).toBe('python -m ingestor pass, every hour')
    expect(rec(run, 'Job resources')).toMatchObject({ tone: 'ok' })
  })
})

describe('detectPlatform', () => {
  it('recognises where it runs from the platform environment', () => {
    expect(detectPlatform({ VERCEL: '1' })).toBe('vercel')
    expect(detectPlatform({ K_SERVICE: 'dmarcscope-web' })).toBe('cloudrun')
    expect(detectPlatform({ KUBERNETES_SERVICE_HOST: '10.0.0.1' })).toBe('kubernetes')
    expect(detectPlatform({ DMARCSCOPE_COMPOSE: '1' })).toBe('docker')
    expect(detectPlatform({})).toBeNull()
  })

  it('has steps for every platform it can detect', () => {
    for (const id of ['vercel', 'docker', 'kubernetes', 'cloudrun'] as const) {
      expect(PLATFORMS.find((p) => p.id === id)?.steps.length).toBeGreaterThan(2)
    }
  })
})
