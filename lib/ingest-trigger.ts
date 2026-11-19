// Starting the worker's work at once on Vercel, where no long-running worker
// exists: the web app calls its own ingest function (api/cron/ingest.py) for
// "Test connection", "Run now" and importing a newly monitored domain's held
// reports. Elsewhere (Docker, python -m ingestor serve) the worker picks the
// request up from worker_jobs by itself, and nothing is called.
//
// The call is signed with APP_SECRET (ingestor/trigger.py verifies), so it
// works however the machine token is configured.
//
// Which address: in production the production domain. A deployment's own
// generated URL (VERCEL_URL) is behind Vercel's Standard Deployment
// Protection, which would refuse the call; previews have only that URL, so
// there the call carries the Protection Bypass for Automation secret when
// the project has one.

import { createHmac } from 'node:crypto'

type Env = Record<string, string | undefined>

export const TRIGGER_HEADER = 'X-DMARCscope-Trigger'

export type IngestTask = `job:${number}` | 'release'

export function triggerSignature(secret: string, ts: number, task: string): string {
  return createHmac('sha256', secret).update(`dmarcscope-ingest-trigger\n${ts}\n${task}`).digest('hex')
}

// Whether this deployment starts work itself (Vercel) rather than leaving it
// to a long-running worker.
export function startsWorkItself(env: Env = process.env): boolean {
  return env.VERCEL === '1'
}

export function triggerTarget(task: IngestTask, env: Env = process.env, now = Date.now()): { url: string; headers: Record<string, string> } | null {
  if (!startsWorkItself(env)) return null
  const host = (env.VERCEL_ENV === 'production' ? env.VERCEL_PROJECT_PRODUCTION_URL : env.VERCEL_URL) || env.VERCEL_URL
  const secret = env.APP_SECRET || ''
  if (!host || !/^[a-z0-9.-]+(:\d+)?$/i.test(host) || secret.length < 32) return null
  const ts = Math.floor(now / 1000)
  const headers: Record<string, string> = { [TRIGGER_HEADER]: `${ts}.${triggerSignature(secret, ts, task)}` }
  if (env.VERCEL_AUTOMATION_BYPASS_SECRET) headers['x-vercel-protection-bypass'] = env.VERCEL_AUTOMATION_BYPASS_SECRET
  return { url: `https://${host}/api/cron/ingest?task=${encodeURIComponent(task)}`, headers }
}

export type TriggerOutcome = { ok: true } | { ok: false; timedOut: boolean; reason: string }

const PROTECTED =
  'the deployment refused the request (HTTP 401): Vercel Deployment Protection covers the address it was sent to. ' +
  'In the Vercel project, under Settings → Deployment Protection, add a Protection Bypass for Automation secret, then redeploy.'

// Calls the function and waits for it (up to timeoutMs). The work itself is
// recorded in the database (the job's result, the run): this only says
// whether the call went through.
export async function triggerIngest(
  task: IngestTask,
  opts: { timeoutMs: number; env?: Env; fetchImpl?: typeof fetch } = { timeoutMs: 60_000 }
): Promise<TriggerOutcome> {
  const target = triggerTarget(task, opts.env)
  if (!target) return { ok: false, timedOut: false, reason: 'this deployment cannot start the worker itself (APP_SECRET or the Vercel address is missing)' }
  const doFetch = opts.fetchImpl ?? fetch
  let res: Response
  try {
    res = await doFetch(target.url, { method: 'POST', headers: target.headers, redirect: 'manual', signal: AbortSignal.timeout(opts.timeoutMs), cache: 'no-store' })
  } catch (e) {
    const name = (e as { name?: string } | null)?.name
    if (name === 'TimeoutError' || name === 'AbortError') return { ok: false, timedOut: true, reason: 'still running' }
    return { ok: false, timedOut: false, reason: `the ingest function could not be reached (${e instanceof Error ? e.message.slice(0, 120) : 'network error'})` }
  }
  if (res.ok) return { ok: true }
  let body: { error?: unknown } | null = null
  try {
    body = (await res.json()) as { error?: unknown }
  } catch {
    body = null
  }
  if (res.status === 401 && body?.error === 'unauthorized') {
    return { ok: false, timedOut: false, reason: 'the ingest function did not accept the request: APP_SECRET must be the same for the web app and the function (set it for all environments)' }
  }
  if (res.status === 401 || res.status === 403) return { ok: false, timedOut: false, reason: PROTECTED }
  if (res.status >= 300 && res.status < 400) return { ok: false, timedOut: false, reason: `the ingest function answered with a redirect (HTTP ${res.status})` }
  const detail = typeof body?.error === 'string' ? `: ${body.error.slice(0, 200)}` : ''
  return { ok: false, timedOut: false, reason: `the ingest function failed (HTTP ${res.status})${detail}` }
}
