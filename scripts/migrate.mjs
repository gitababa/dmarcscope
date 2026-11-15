#!/usr/bin/env node
// Applies pending SQL files from db/migrations to DATABASE_URL.
//
//   npm run db:migrate
//   node scripts/migrate.mjs            (inside the container image)
//
// Each file runs in its own transaction and is recorded in schema_migrations,
// so re-running is a no-op. A session advisory lock makes concurrent runs
// (for example two replicas starting at once) queue instead of racing.

import { readdir, readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import pg from 'pg'

const MIGRATIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'db', 'migrations')
const LOCK_KEY = 4117230901 // arbitrary constant, unique to this app

async function main() {
  const url = process.env.DATABASE_URL
  if (!url) {
    console.error('DATABASE_URL is not set.')
    process.exit(1)
  }

  const client = new pg.Client({ connectionString: url })
  await client.connect()
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_KEY])
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `)
    const applied = new Set(
      (await client.query('SELECT version FROM schema_migrations')).rows.map((r) => r.version)
    )
    const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort()

    let ran = 0
    for (const file of files) {
      if (applied.has(file)) continue
      const sqlText = await readFile(resolve(MIGRATIONS_DIR, file), 'utf8')
      process.stdout.write(`Applying ${file} ... `)
      try {
        await client.query('BEGIN')
        await client.query(sqlText)
        await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [file])
        await client.query('COMMIT')
      } catch (err) {
        await client.query('ROLLBACK')
        throw err
      }
      process.stdout.write('done\n')
      ran++
    }
    console.log(ran === 0 ? 'Database is up to date.' : `Applied ${ran} migration(s).`)
  } finally {
    await client.end()
  }
}

main().catch((err) => {
  console.error('Migration failed:', err.message || err)
  process.exit(1)
})
