// Runs the live DNS checks for one tracked domain and stores the result.
// Shared by the "Run checks" button (server action) and the scheduled
// /api/cron/dns-check endpoint.

import { sql } from './db'
import { runDnsChecks, type DnsCheckResults } from './dns-checks'
import { expandSpf } from './spf'
import { getObservedDkimSigners } from './queries'

const COOLDOWN_SECONDS = 20
const KEEP_CHECKS_PER_DOMAIN = 30

export type DnsRunOutcome =
  | { status: 'ok'; results: DnsCheckResults }
  | { status: 'cooldown' }
  | { status: 'unknown_domain' }

// Hostname syntax only (letters, digits, hyphens, dots). The name is used to
// build DNS queries, never a URL or a shell command.
export function isValidDomainName(domain: string): boolean {
  return (
    domain.length >= 3 &&
    domain.length <= 253 &&
    /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/.test(domain)
  )
}

export async function runAndStoreDnsCheck(domain: string, opts: { force?: boolean } = {}): Promise<DnsRunOutcome> {
  // Only domains we already hold reports for can be checked — this is not a
  // general-purpose DNS lookup service.
  const rows = await sql<{ id: number; recent: boolean }>`
    SELECT d.id,
           EXISTS (
             SELECT 1 FROM dns_checks c
             WHERE c.domain_id = d.id
               AND c.checked_at > NOW() - make_interval(secs => ${COOLDOWN_SECONDS})
           ) AS recent
    FROM domains d
    WHERE d.name = ${domain}
    LIMIT 1
  `
  if (rows.length === 0) return { status: 'unknown_domain' }
  if (rows[0].recent && !opts.force) return { status: 'cooldown' }
  const domainId = rows[0].id

  // Selector and signing domain are copied from reports, i.e. chosen by
  // whoever sent the report: only well-formed names become DNS queries.
  const signers = (await getObservedDkimSigners(domain)).filter(
    (s) => isValidDomainName(s.signing_domain) && /^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$/i.test(s.selector)
  )
  const [results, spfExpanded] = await Promise.all([
    runDnsChecks(domain, signers),
    // SPF expansion powers source attribution on the Issues page: which
    // include chain (if any) authorizes each problem source's IP.
    expandSpf(domain).catch((e) => {
      console.error(`[dns-check] SPF expansion failed for ${domain}:`, e)
      return undefined
    }),
  ])
  if (spfExpanded) {
    results.spf_expanded = spfExpanded
    applyExpansionToSpfStatus(results)
  }

  await sql`INSERT INTO dns_checks (domain_id, results) VALUES (${domainId}, ${JSON.stringify(results)}::jsonb)`
  await sql`
    DELETE FROM dns_checks
    WHERE domain_id = ${domainId}
      AND id NOT IN (
        SELECT id FROM dns_checks WHERE domain_id = ${domainId}
        ORDER BY checked_at DESC LIMIT ${KEEP_CHECKS_PER_DOMAIN}
      )
  `
  return { status: 'ok', results }
}

// The top-level record alone can't tell how many DNS lookups an SPF check
// costs — includes nest. Use the recursive count from the expansion.
function applyExpansionToSpfStatus(results: DnsCheckResults): void {
  const exp = results.spf_expanded
  if (!exp || !exp.has_spf || results.spf.status === 'fail') return
  if (exp.lookups > 10) {
    results.spf.status = 'fail'
    results.spf.notes.push(
      `Evaluating this record needs more than 10 DNS lookups (includes are nested). RFC 7208 caps it at 10; receivers return permerror and SPF fails for all mail.`
    )
  } else if (exp.lookups >= 8) {
    if (results.spf.status === 'ok') results.spf.status = 'warn'
    results.spf.notes.push(`Evaluating this record needs ${exp.lookups} of the 10 DNS lookups RFC 7208 allows. One more nested include could break SPF.`)
  }
}
