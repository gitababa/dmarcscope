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
  const intEnv = (name: string, fallback: number): number => {
    const n = Number.parseInt(process.env[name] || '', 10)
    return Number.isInteger(n) && n >= 0 ? n : fallback
  }
  const serverTimeout = intEnv('DATABASE_STATEMENT_TIMEOUT_MS', 0)
  pool = new Pool({
    connectionString: url,
    // A page runs up to five queries side by side.
    max: intEnv('DATABASE_POOL_MAX', 10) || 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    // Give up on a query after this long and drop its connection, so one slow
    // aggregate cannot hold every pool slot (0 disables). This is enforced on
    // the client and works through any pooler.
    query_timeout: intEnv('DATABASE_QUERY_TIMEOUT_MS', 30_000) || undefined,
    // Optional server-side limit, sent as a connection parameter. Off by
    // default because transaction-mode poolers (PgBouncer) reject unknown
    // startup parameters; there, set it on the role instead:
    //   ALTER ROLE <user> SET statement_timeout = '30s'
    ...(serverTimeout > 0 ? { statement_timeout: serverTimeout } : {}),
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
