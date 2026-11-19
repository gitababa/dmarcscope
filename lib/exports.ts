// What the JSON API and the CSV downloads return, in one place. Every dataset
// goes through lib/queries.ts with the caller's DomainScope; there is no second
// path to the data.

import type { DomainScope } from './auth/access'
import { csvCell } from './admin'
import { getDomainPolicy, getDomainSummaries, getProblemSources, getSourcesForDomain, getVolumeTimeseries } from './queries'

export type Dataset = { columns: string[]; rows: Array<Record<string, unknown>> }

export function toCsv(d: Dataset): string {
  const lines = [d.columns.join(',')]
  for (const r of d.rows) lines.push(d.columns.map((c) => csvCell(r[c])).join(','))
  return `${lines.join('\r\n')}\r\n`
}

export async function domainsDataset(scope: DomainScope, days: number): Promise<Dataset> {
  const rows = await getDomainSummaries(scope, days)
  return {
    columns: ['name', 'policy', 'total_messages', 'dmarc_pass', 'dmarc_fail', 'dkim_pass', 'spf_pass', 'pass_rate', 'report_count'],
    rows: rows.map((r) => ({ ...r })),
  }
}

export async function timeseriesDataset(scope: DomainScope, domain: string, days: number): Promise<Dataset | null> {
  // The policy lookup is the scope check: a domain outside the scope, and one
  // that does not exist, are the same answer.
  if ((await getDomainPolicy(scope, domain)) == null) return null
  return { columns: ['day', 'total', 'passed'], rows: (await getVolumeTimeseries(scope, days, domain)).map((r) => ({ ...r })) }
}

export async function sourcesDataset(scope: DomainScope, domain: string, days: number): Promise<Dataset | null> {
  if ((await getDomainPolicy(scope, domain)) == null) return null
  const rows = await getSourcesForDomain(scope, domain, days, 1000)
  return {
    columns: ['source_ip', 'reverse_dns', 'base_domain', 'provider_name', 'as_name', 'total_messages', 'passed', 'failed', 'dkim_passed', 'spf_passed', 'first_seen', 'last_seen'],
    rows: rows.map((r) => ({ ...r })),
  }
}

export async function problemsDataset(scope: DomainScope, days: number, domain?: string): Promise<Dataset> {
  const rows = await getProblemSources(scope, days, 1000, domain)
  return {
    columns: [
      'domain', 'source_ip', 'reverse_dns', 'provider_name', 'as_name', 'total_messages', 'failing', 'passed', 'dkim_passed', 'spf_passed',
      'fail_with_valid_dkim_sig', 'fail_with_raw_spf_pass', 'fail_with_both', 'top_fail_envelope', 'last_seen',
    ],
    rows: rows.map((r) => ({ ...r })),
  }
}

// A domain from a URL path segment; malformed percent-encoding is "no such
// domain", not a server error.
export function pathDomain(raw: string): string {
  try {
    return decodeURIComponent(raw).trim().toLowerCase()
  } catch {
    return ''
  }
}

export function parseDays(raw: string | null, fallback = 7): number | null {
  if (raw == null || raw === '') return fallback
  if (!/^\d{1,3}$/.test(raw)) return null
  const n = Number(raw)
  return n >= 1 && n <= 90 ? n : null
}

export function csvResponse(body: string, name: string): Response {
  return new Response(body, {
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="${name.replace(/[^a-z0-9._-]/gi, '_')}.csv"`,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  })
}
