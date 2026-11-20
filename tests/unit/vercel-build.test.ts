import { describe, expect, it } from 'vitest'
import { migrationPlan } from '../../scripts/vercel-build.mjs'

const PROD = { VERCEL: '1', VERCEL_ENV: 'production' }

describe('migrations on Vercel builds', () => {
  it('run on production builds, over the direct connection', () => {
    const plan = migrationPlan({ ...PROD, DATABASE_URL: 'postgres://u:p@ep-x-pooler.neon.tech/db', DATABASE_URL_UNPOOLED: 'postgres://u:p@ep-x.neon.tech/db' })
    expect(plan).toMatchObject({ migrate: true, url: 'postgres://u:p@ep-x.neon.tech/db' })
    expect(migrationPlan({ ...PROD, POSTGRES_URL_NON_POOLING: 'postgres://direct', DATABASE_URL: 'postgres://pooled' }).url).toBe('postgres://direct')
  })

  it('never run on a preview build, which may hold unmerged migrations', () => {
    expect(migrationPlan({ VERCEL: '1', VERCEL_ENV: 'preview', DATABASE_URL_UNPOOLED: 'postgres://direct' })).toMatchObject({ migrate: false })
    expect(migrationPlan({ DATABASE_URL: 'postgres://local' })).toMatchObject({ migrate: false })
  })

  it('skip before a database is connected, and when turned off', () => {
    expect(migrationPlan(PROD)).toMatchObject({ migrate: false, reason: expect.stringMatching(/No database is connected/) })
    expect(migrationPlan({ ...PROD, MIGRATE_ON_BUILD: '0', DATABASE_URL_UNPOOLED: 'postgres://direct' })).toMatchObject({ migrate: false })
  })

  it('say so when only a pooled connection is available', () => {
    const plan = migrationPlan({ ...PROD, DATABASE_URL: 'postgres://u:p@ep-x-pooler.neon.tech/db' })
    expect(plan.migrate).toBe(true)
    expect(plan.reason).toMatch(/DATABASE_URL_UNPOOLED/)
  })
})
