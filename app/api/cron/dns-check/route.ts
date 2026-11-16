import { NextResponse, type NextRequest } from 'next/server'
import { machineScope } from '@/lib/auth/access'
import { isValidDomainName, runAndStoreDnsCheck } from '@/lib/dns-run'
import { getDomainNames } from '@/lib/queries'
import { hasValidMachineToken } from '@/lib/settings'

export const dynamic = 'force-dynamic'
export const maxDuration = 300

// Scheduled DNS checks for automation: `Authorization: Bearer <token>`, the
// token being the cron.secret setting (CRON_SECRET).
//
//   GET|POST /api/cron/dns-check             refresh every tracked domain
//   GET|POST /api/cron/dns-check?domain=x    refresh one domain
//
// Keeping checks fresh is what lets the Issues page say whether each failing
// source is authorized by the domain's current SPF record. (GET is accepted
// because some schedulers, Vercel Cron among them, can only send GET.)
async function handle(req: NextRequest) {
  if (!(await hasValidMachineToken(req.headers.get('authorization')))) {
    return NextResponse.json({ ok: false, error: 'unauthorized' }, { status: 401 })
  }

  const one = (req.nextUrl.searchParams.get('domain') || '').trim().toLowerCase()
  if (one && !isValidDomainName(one)) {
    return NextResponse.json({ ok: false, error: 'invalid domain' }, { status: 400 })
  }
  const scope = machineScope()
  const domains = one ? [one] : await getDomainNames(scope)

  const deadline = Date.now() + 240_000
  const summary: Record<string, string> = {}
  const queue = [...domains]
  // A few domains at a time: each check fans out into dozens of DNS queries.
  await Promise.all(
    Array.from({ length: Math.min(4, queue.length) }, async () => {
      for (let d = queue.shift(); d; d = queue.shift()) {
        if (Date.now() > deadline) {
          summary[d] = 'skipped (time budget)'
          continue
        }
        try {
          const outcome = await runAndStoreDnsCheck(scope, d, { force: true })
          summary[d] =
            outcome.status === 'ok'
              ? `mx=${outcome.results.mx.status} spf=${outcome.results.spf.status} dmarc=${outcome.results.dmarc.status} dkim=${outcome.results.dkim.status}`
              : outcome.status
        } catch (e) {
          console.error(`[dns-check] ${d} failed:`, e)
          summary[d] = 'error'
        }
      }
    })
  )

  if (one && summary[one] === 'unknown_domain') {
    return NextResponse.json({ ok: false, error: 'unknown domain' }, { status: 404 })
  }
  // "Every domain failed" is a failure of the job (database or resolver
  // down), and a scheduler should see it as one.
  const outcomes = Object.values(summary)
  const failed = outcomes.filter((o) => o === 'error').length
  const ok = outcomes.length === 0 || failed < outcomes.length
  return NextResponse.json({ ok, checked: outcomes.length, failed, results: summary }, { status: ok ? 200 : 500 })
}

export const GET = handle
export const POST = handle
