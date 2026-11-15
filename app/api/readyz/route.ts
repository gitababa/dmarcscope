import { pingDatabase } from '@/lib/db'

// Readiness probe: can this instance reach its database? Deliberately
// reveals nothing beyond a boolean.
export const dynamic = 'force-dynamic'

export async function GET() {
  try {
    await pingDatabase()
    return Response.json({ ok: true }, { headers: { 'cache-control': 'no-store' } })
  } catch (e) {
    console.error('[readyz] database check failed:', e instanceof Error ? e.message : e)
    return Response.json({ ok: false }, { status: 503, headers: { 'cache-control': 'no-store' } })
  }
}
