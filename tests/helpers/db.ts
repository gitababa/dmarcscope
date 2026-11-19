// A fresh schema with every migration applied, in the disposable database
// TEST_DATABASE_URL points at. Each test file uses its own schema.

import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import pg from 'pg'

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL

export async function createSchema(schema: string): Promise<{ url: string; admin: pg.Client; drop: () => Promise<void> }> {
  const admin = new pg.Client({ connectionString: TEST_DATABASE_URL })
  await admin.connect()
  await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE; CREATE SCHEMA ${schema}; SET search_path TO ${schema}`)
  const dir = path.resolve(__dirname, '../../db/migrations')
  for (const file of (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort()) {
    await admin.query(await readFile(path.join(dir, file), 'utf8'))
  }
  const u = new URL(TEST_DATABASE_URL!)
  u.searchParams.set('options', `-c search_path=${schema}`)
  return {
    url: u.toString(),
    admin,
    drop: async () => {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`)
      await admin.end()
    },
  }
}
