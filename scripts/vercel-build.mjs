#!/usr/bin/env node
// The build command on Vercel (vercel.json → buildCommand): apply pending
// migrations, then `next build`.
//
// Only production builds migrate. A preview build is a branch that may hold
// migrations nobody has merged; it must never change the production
// database, which previews often share. A failed migration fails the build,
// so the new code never goes live against an old schema, and the previous
// deployment keeps serving. Migrations are additive (new tables and
// columns), so the old code keeps working against the new schema meanwhile.
//
// MIGRATE_ON_BUILD=0 turns this off (then run `npm run db:migrate` yourself).

import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

// What to do for this build. Pure, for tests.
export function migrationPlan(env) {
  if (env.MIGRATE_ON_BUILD === '0') return { migrate: false, reason: 'MIGRATE_ON_BUILD=0: not applying migrations.' }
  if (env.VERCEL_ENV !== 'production') {
    return { migrate: false, reason: `A ${env.VERCEL_ENV || 'local'} build never changes the database: migrations run on production builds only.` }
  }
  // A direct connection: the session advisory lock in scripts/migrate.mjs
  // needs one, which a transaction-mode pooler does not give.
  const url = env.DATABASE_URL_UNPOOLED || env.POSTGRES_URL_NON_POOLING || env.DATABASE_URL
  if (!url) {
    return { migrate: false, reason: 'No database is connected yet (DATABASE_URL is not set): skipping migrations. Add one, then redeploy.' }
  }
  const pooled = !env.DATABASE_URL_UNPOOLED && !env.POSTGRES_URL_NON_POOLING && /-pooler\./.test(url)
  return {
    migrate: true,
    url,
    reason: pooled
      ? 'Applying migrations through a pooled connection (no DATABASE_URL_UNPOOLED is set); if this fails, set DATABASE_URL_UNPOOLED.'
      : 'Applying migrations to the production database.',
  }
}

function run(command, args, env) {
  const result = spawnSync(command, args, { stdio: 'inherit', env })
  if (result.error) throw result.error
  if (result.status !== 0) process.exit(result.status ?? 1)
}

function main() {
  const plan = migrationPlan(process.env)
  console.log(`[vercel-build] ${plan.reason}`)
  if (plan.migrate) run(process.execPath, ['scripts/migrate.mjs'], { ...process.env, DATABASE_URL: plan.url })
  run('npx', ['--no-install', 'next', 'build'], process.env)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main()
