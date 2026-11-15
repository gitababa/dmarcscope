// Liveness probe: the process is up and serving. No dependencies checked.
export const dynamic = 'force-dynamic'

export function GET() {
  return Response.json({ ok: true }, { headers: { 'cache-control': 'no-store' } })
}
