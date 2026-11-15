import { Pool, types } from 'pg'

// Standard PostgreSQL over node-postgres: works with any Postgres (self-hosted,
// Cloud SQL, RDS, Azure, Neon, Supabase, ...). TLS is controlled through the
// connection string (`?sslmode=require`), as with libpq.
//
// The pool is created lazily so `next build` can load pages without a live
// database (every page is dynamic and never queries at build time).

const TIMESTAMPTZ = 1184
const TIMESTAMP = 1114

// Return timestamps as ISO strings rather than Date objects: they cross the
// server-component boundary and are only ever formatted for display.
const parseDate = types.getTypeParser(TIMESTAMPTZ) as (v: string) => unknown
function isoParser(value: string): string {
  const d = parseDate(value)
  return d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString() : value
}

let pool: Pool | null = null

export function getPool(): Pool {
  if (pool) return pool
  const url = process.env.DATABASE_URL
  if (!url) {
    throw new Error('DATABASE_URL is not set. Point it at a PostgreSQL database (see .env.example).')
  }
  const max = Number.parseInt(process.env.DATABASE_POOL_MAX || '', 10)
  pool = new Pool({
    connectionString: url,
    max: Number.isInteger(max) && max > 0 ? max : 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    types: {
      getTypeParser: ((oid: number, format?: string) => {
        if ((oid === TIMESTAMPTZ || oid === TIMESTAMP) && format !== 'binary') return isoParser
        return types.getTypeParser(oid, format as 'text')
      }) as typeof types.getTypeParser,
    },
  })
  // An idle client erroring (e.g. the server restarted) must not crash the process.
  pool.on('error', (err) => {
    console.error('[db] idle client error:', err.message)
  })
  return pool
}

// Tagged template: sql`SELECT ... WHERE x = ${value}` → parameterized query.
// Interpolated values are always sent as bind parameters, never spliced into
// the SQL text.
export async function sql<T = Record<string, unknown>>(
  strings: TemplateStringsArray,
  ...values: unknown[]
): Promise<T[]> {
  let text = strings[0]
  for (let i = 0; i < values.length; i++) text += `$${i + 1}${strings[i + 1]}`
  const result = await getPool().query(text, values)
  return result.rows as T[]
}

export async function pingDatabase(): Promise<void> {
  await getPool().query('SELECT 1')
}

// For tests and graceful shutdown.
export async function closePool(): Promise<void> {
  if (pool) {
    const p = pool
    pool = null
    await p.end()
  }
}
