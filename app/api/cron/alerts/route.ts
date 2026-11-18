import { NextResponse, type NextRequest } from 'next/server'
import { runAlerts } from '@/lib/alerts/run'
import { hasValidMachineToken } from '@/lib/settings'

export const dynamic = 'force-dynamic'
export const maxDuration = 120

// Evaluates the alert rules and sends what is due, for serverless
// deployments and external schedulers: `Authorization: Bearer <token>`, the
// token being the cron.secret setting (CRON_SECRET). Long-running processes
// do the same on a timer. GET is accepted because Vercel Cron can only send it.
async function handle(req: NextRequest) {
  if (!(await hasValidMachineToken(req.headers.get('authorization')))) {
    return NextResponse.json({ ok: false, error: 'unauthorized' }, { status: 401 })
  }
  try {
    const r = await runAlerts()
    return NextResponse.json({ ok: r.failed === 0, ...r }, { status: r.failed === 0 ? 200 : 500 })
  } catch (e) {
    console.error('[alerts] cron run failed:', e instanceof Error ? e.message : String(e))
    return NextResponse.json({ ok: false, error: 'failed' }, { status: 500 })
  }
}

export const GET = handle
export const POST = handle
