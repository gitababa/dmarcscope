import { NextResponse, type NextRequest } from 'next/server'
import { machineScope } from '@/lib/auth/access'
import { getIngestHealth } from '@/lib/queries'
import { hasValidMachineToken } from '@/lib/settings'

export const dynamic = 'force-dynamic'

// Ingest health for a monitor: `Authorization: Bearer <token>` (the
// cron.secret setting, CRON_SECRET).
//
//   GET /api/cron/status   200 while a run has completed within
//                          INGEST_STALE_HOURS (default 36), otherwise 503
//
// Point an uptime checker at it to be told when reports stop arriving in the
// database — the dashboard itself keeps working on old data, so nothing else
// fails. A fresh install with no run yet also answers 503.
export async function GET(req: NextRequest) {
  const headers = { 'cache-control': 'no-store' }
  if (!(await hasValidMachineToken(req.headers.get('authorization')))) {
    return NextResponse.json({ ok: false, error: 'unauthorized' }, { status: 401, headers })
  }
  try {
    const health = await getIngestHealth(machineScope())
    return NextResponse.json({ ok: health.status === 'ok', ...health }, { status: health.status === 'ok' ? 200 : 503, headers })
  } catch (e) {
    console.error('[status] ingest health check failed:', e instanceof Error ? e.message : e)
    return NextResponse.json({ ok: false, error: 'database unavailable' }, { status: 503, headers })
  }
}
