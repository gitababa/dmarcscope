// Every exported query takes a DomainScope as its first argument. A page gets
// one only from the authorization function (lib/auth/access.ts), the API from
// the token's resolved scope, and machine endpoints from machineScope().
// Every query filters by it: `only` is the allowed lower-cased domain names or
// null for all, and each statement carries the same predicate on the domain
// row. tests/integration/queries.test.ts calls every export with a limited
// scope and fails if one returns another domain's data, or if an export has
// no case there.

import { type DomainScope, assertScope, scopeNames } from './auth/access'
import { sql } from './db'
import { getIngestStaleHours } from './settings'

// ---------- shared types ----------

export type DomainSummary = {
  name: string
  total_messages: number
  dmarc_pass: number
  dmarc_fail: number
  dkim_pass: number
  spf_pass: number
  pass_rate: number
  report_count: number
  // p= from the most recent report (what receivers currently see published)
  policy: string | null
}

export type TopSource = {
  source_ip: string
  reverse_dns: string | null
  base_domain: string | null
  // From the ingest worker's offline IP database (may all be null).
  provider_name: string | null
  as_name: string | null
  as_domain: string | null
  total_messages: number
  passed: number
  failed: number
  dkim_passed: number
  spf_passed: number
}

export type RecentRun = {
  id: number
  started_at: string
  finished_at: string | null
  messages_fetched: number
  reports_parsed: number
  reports_skipped: number
  had_errors: boolean
  // ended on a fatal error (mailbox or database unreachable)
  failed: boolean
  // started more than an hour ago and never finished (crashed or was killed)
  stalled: boolean
}

export type DomainPolicy = {
  domain: string
  policy: string | null
  subdomain_policy: string | null
  pct: string | null
  adkim: string | null
  aspf: string | null
  latest_report_end: string | null
}

export type DomainSourceRow = TopSource & {
  first_seen: string | null
  last_seen: string | null
}

export type AlignmentBreakdown = {
  dmarc_pass: number
  dkim_only: number
  spf_only: number
  fully_aligned: number
  fully_failed: number
}

export type DataExtent = {
  min_date: string | null
  max_date: string | null
  total_messages: number
}

export type TimeseriesPoint = {
  day: string
  total: number
  passed: number
}

// ---------- helpers ----------

// days === 0 means "all time"
function cutoff(days: number): string {
  if (days === 0) return new Date(0).toISOString()
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString()
}

const num = (v: string | number | null | undefined) => (v == null ? 0 : Number(v))

// ---------- overview queries ----------

export async function getDomainSummaries(scope: DomainScope, days = 7): Promise<DomainSummary[]> {
  assertScope(scope)
  const only = scopeNames(scope)
  const since = cutoff(days)
  const rows = (await sql`
    SELECT
      d.name AS name,
      COALESCE(SUM(r.message_count), 0)::bigint AS total_messages,
      COALESCE(SUM(CASE WHEN r.dmarc_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS dmarc_pass,
      COALESCE(SUM(CASE WHEN NOT r.dmarc_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS dmarc_fail,
      COALESCE(SUM(CASE WHEN r.dkim_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS dkim_pass,
      COALESCE(SUM(CASE WHEN r.spf_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS spf_pass,
      COUNT(DISTINCT r.report_id) AS report_count,
      lp.policy AS policy
    FROM domains d
    LEFT JOIN records r ON r.domain_id = d.id AND r.period_end >= ${since}::timestamptz
    LEFT JOIN LATERAL (
      SELECT policy_published->>'p' AS policy FROM reports
      WHERE domain_id = d.id
      ORDER BY end_date DESC
      LIMIT 1
    ) lp ON true
    WHERE (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
    GROUP BY d.id, d.name, lp.policy
    ORDER BY total_messages DESC, d.name ASC
  `) as Array<Record<string, string | number | null>>

  return rows.map((r) => {
    const total = num(r.total_messages)
    const pass = num(r.dmarc_pass)
    return {
      name: String(r.name),
      total_messages: total,
      dmarc_pass: pass,
      dmarc_fail: num(r.dmarc_fail),
      dkim_pass: num(r.dkim_pass),
      spf_pass: num(r.spf_pass),
      pass_rate: total > 0 ? pass / total : 0,
      report_count: num(r.report_count),
      policy: (r.policy as unknown as string | null) ?? null,
    }
  })
}

export async function getTopSources(scope: DomainScope, days = 7, limit = 10): Promise<TopSource[]> {
  assertScope(scope)
  const only = scopeNames(scope)
  const since = cutoff(days)
  const rows = (await sql`
    SELECT
      host(r.source_ip) AS source_ip,
      m.reverse_dns,
      m.base_domain,
      m.provider_name,
      m.as_name,
      m.as_domain,
      SUM(r.message_count)::bigint AS total_messages,
      SUM(CASE WHEN r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS passed,
      SUM(CASE WHEN NOT r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS failed,
      SUM(CASE WHEN r.dkim_aligned THEN r.message_count ELSE 0 END)::bigint AS dkim_passed,
      SUM(CASE WHEN r.spf_aligned THEN r.message_count ELSE 0 END)::bigint AS spf_passed
    FROM records r
    JOIN domains d ON d.id = r.domain_id
    LEFT JOIN ip_metadata m ON m.ip = r.source_ip
    WHERE r.period_end >= ${since}::timestamptz
      AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
    GROUP BY r.source_ip, m.reverse_dns, m.base_domain, m.provider_name, m.as_name, m.as_domain
    ORDER BY total_messages DESC
    LIMIT ${limit}
  `) as Array<Record<string, string | number | null>>

  return rows.map(mapSourceRow)
}

export async function getRecentIngestRuns(scope: DomainScope, limit = 5): Promise<RecentRun[]> {
  assertScope(scope)
  // Runs are about the deployment's mailboxes, not about a domain, and their
  // counts would show the volume of domains a limited person cannot see.
  if (scopeNames(scope) !== null) return []
  const rows = (await sql`
    SELECT id::int AS id, started_at, finished_at, messages_fetched, reports_parsed, reports_skipped,
           (errors IS NOT NULL AND jsonb_typeof(errors) = 'array' AND jsonb_array_length(errors) > 0) AS had_errors,
           failed,
           (finished_at IS NULL AND started_at < NOW() - INTERVAL '1 hour') AS stalled
    FROM ingest_runs
    ORDER BY started_at DESC
    LIMIT ${limit}
  `) as RecentRun[]

  return rows
}

export type IngestHealth = {
  // 'never'  no run has been recorded at all (fresh install)
  // 'ok'     a run completed inside the window
  // 'stale'  runs exist, but none completed inside the window
  status: 'never' | 'ok' | 'stale'
  stale_after_hours: number
  last_success_at: string | null
  last_run_started_at: string | null
  last_run_failed: boolean
}


export async function getIngestHealth(scope: DomainScope): Promise<IngestHealth> {
  assertScope(scope)
  // How long the dashboard may go without a completed ingest run before it
  // says so (setting ingest.stale_hours, INGEST_STALE_HOURS).
  const hours = await getIngestStaleHours()
  const rows = (await sql`
    SELECT
      (SELECT MAX(finished_at) FROM ingest_runs WHERE finished_at IS NOT NULL AND NOT failed) AS last_success_at,
      (SELECT started_at FROM ingest_runs ORDER BY started_at DESC LIMIT 1) AS last_run_started_at,
      COALESCE((SELECT failed FROM ingest_runs ORDER BY started_at DESC LIMIT 1), FALSE) AS last_run_failed,
      COALESCE(
        (SELECT MAX(finished_at) FROM ingest_runs WHERE finished_at IS NOT NULL AND NOT failed)
          > NOW() - make_interval(hours => ${hours}::int),
        FALSE
      ) AS fresh
  `) as Array<{
    last_success_at: string | null
    last_run_started_at: string | null
    last_run_failed: boolean
    fresh: boolean
  }>
  const r = rows[0]
  return {
    status: r.last_run_started_at == null ? 'never' : r.fresh ? 'ok' : 'stale',
    stale_after_hours: hours,
    last_success_at: r.last_success_at,
    last_run_started_at: r.last_run_started_at,
    last_run_failed: r.last_run_failed,
  }
}

// Scans the whole records table: call it only when its answer will be shown.
export async function getDataExtent(scope: DomainScope): Promise<DataExtent> {
  assertScope(scope)
  const only = scopeNames(scope)
  const rows = (await sql`
    SELECT
      MIN(r.period_start) AS min_date,
      MAX(r.period_end) AS max_date,
      COALESCE(SUM(r.message_count), 0)::bigint AS total_messages
    FROM records r
    JOIN domains d ON d.id = r.domain_id
    WHERE (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
  `) as Array<Record<string, string | number | null>>

  const r = rows[0] ?? {}
  return {
    min_date: (r.min_date as string | null) ?? null,
    max_date: (r.max_date as string | null) ?? null,
    total_messages: num(r.total_messages as string | number),
  }
}

// One bar per UTC day, by the day a record's reporting period began: reports
// cover a UTC day, and a period ending at 23:59:59 or at midnight must land
// in the same bar whatever time zone the database session uses.
export async function getVolumeTimeseries(scope: DomainScope, days = 7, domain?: string): Promise<TimeseriesPoint[]> {
  assertScope(scope)
  const only = scopeNames(scope)
  const since = cutoff(days)
  const rows = domain
    ? ((await sql`
        SELECT
          (r.period_start AT TIME ZONE 'UTC')::date::text AS day,
          SUM(r.message_count)::bigint AS total,
          SUM(CASE WHEN r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS passed
        FROM records r
        JOIN domains d ON d.id = r.domain_id
        WHERE r.period_end >= ${since}::timestamptz
          AND LOWER(d.name) = LOWER(${domain})
          AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
        GROUP BY 1
        ORDER BY 1
      `) as Array<Record<string, string | number>>)
    : ((await sql`
        SELECT
          (r.period_start AT TIME ZONE 'UTC')::date::text AS day,
          SUM(r.message_count)::bigint AS total,
          SUM(CASE WHEN r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS passed
        FROM records r
        JOIN domains d ON d.id = r.domain_id
        WHERE r.period_end >= ${since}::timestamptz
          AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
        GROUP BY 1
        ORDER BY 1
      `) as Array<Record<string, string | number>>)

  return rows.map((r) => ({
    day: String(r.day),
    total: num(r.total),
    passed: num(r.passed),
  }))
}

export async function getDomainNames(scope: DomainScope): Promise<string[]> {
  assertScope(scope)
  const only = scopeNames(scope)
  const rows = await sql<{ name: string }>`SELECT d.name AS name FROM domains d WHERE (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[])) ORDER BY d.name`
  return rows.map((r) => r.name)
}

// ---------- per-domain queries ----------

export async function getDomainPolicy(scope: DomainScope, domain: string): Promise<DomainPolicy | null> {
  assertScope(scope)
  const only = scopeNames(scope)
  const rows = (await sql`
    SELECT
      d.name AS domain,
      r.policy_published->>'p' AS policy,
      r.policy_published->>'sp' AS subdomain_policy,
      r.policy_published->>'pct' AS pct,
      r.policy_published->>'adkim' AS adkim,
      r.policy_published->>'aspf' AS aspf,
      r.end_date AS latest_report_end
    FROM domains d
    LEFT JOIN LATERAL (
      SELECT policy_published, end_date FROM reports
      WHERE domain_id = d.id
      ORDER BY end_date DESC
      LIMIT 1
    ) r ON true
    WHERE LOWER(d.name) = LOWER(${domain})
      AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
    LIMIT 1
  `) as Array<Record<string, string | null>>

  if (rows.length === 0) return null
  const r = rows[0]
  return {
    domain: String(r.domain),
    policy: r.policy ?? null,
    subdomain_policy: r.subdomain_policy ?? null,
    pct: r.pct ?? null,
    adkim: r.adkim ?? null,
    aspf: r.aspf ?? null,
    latest_report_end: r.latest_report_end ?? null,
  }
}

export async function getSourcesForDomain(
  scope: DomainScope,
  domain: string,
  days = 7,
  limit = 100
): Promise<DomainSourceRow[]> {
  assertScope(scope)
  const only = scopeNames(scope)
  const since = cutoff(days)
  const rows = (await sql`
    SELECT
      host(r.source_ip) AS source_ip,
      m.reverse_dns,
      m.base_domain,
      m.provider_name,
      m.as_name,
      m.as_domain,
      SUM(r.message_count)::bigint AS total_messages,
      SUM(CASE WHEN r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS passed,
      SUM(CASE WHEN NOT r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS failed,
      SUM(CASE WHEN r.dkim_aligned THEN r.message_count ELSE 0 END)::bigint AS dkim_passed,
      SUM(CASE WHEN r.spf_aligned THEN r.message_count ELSE 0 END)::bigint AS spf_passed,
      MIN(r.period_start) AS first_seen,
      MAX(r.period_end) AS last_seen
    FROM records r
    JOIN domains d ON d.id = r.domain_id
    LEFT JOIN ip_metadata m ON m.ip = r.source_ip
    WHERE LOWER(d.name) = LOWER(${domain})
      AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
      AND r.period_end >= ${since}::timestamptz
    GROUP BY r.source_ip, m.reverse_dns, m.base_domain, m.provider_name, m.as_name, m.as_domain
    ORDER BY total_messages DESC
    LIMIT ${limit}
  `) as Array<Record<string, string | number | null>>

  return rows.map((r) => ({
    ...mapSourceRow(r),
    first_seen: (r.first_seen as string | null) ?? null,
    last_seen: (r.last_seen as string | null) ?? null,
  }))
}

export async function getAlignmentBreakdown(scope: DomainScope, domain: string, days = 7): Promise<AlignmentBreakdown> {
  assertScope(scope)
  const only = scopeNames(scope)
  const since = cutoff(days)
  const rows = (await sql`
    SELECT
      COALESCE(SUM(CASE WHEN r.dmarc_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS dmarc_pass,
      COALESCE(SUM(CASE WHEN r.dkim_aligned AND NOT r.spf_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS dkim_only,
      COALESCE(SUM(CASE WHEN r.spf_aligned AND NOT r.dkim_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS spf_only,
      COALESCE(SUM(CASE WHEN r.dkim_aligned AND r.spf_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS fully_aligned,
      COALESCE(SUM(CASE WHEN NOT r.dkim_aligned AND NOT r.spf_aligned THEN r.message_count ELSE 0 END), 0)::bigint AS fully_failed
    FROM records r
    JOIN domains d ON d.id = r.domain_id
    WHERE LOWER(d.name) = LOWER(${domain})
      AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
      AND r.period_end >= ${since}::timestamptz
  `) as Array<Record<string, string | number>>

  const r = rows[0] ?? {}
  return {
    dmarc_pass: num(r.dmarc_pass as string | number),
    dkim_only: num(r.dkim_only as string | number),
    spf_only: num(r.spf_only as string | number),
    fully_aligned: num(r.fully_aligned as string | number),
    fully_failed: num(r.fully_failed as string | number),
  }
}

// ---------- DNS checks ----------

export type DkimSigner = { selector: string; signing_domain: string }

// Selectors whose signing domain aligns with the checked domain. A DMARC
// report lists every DKIM signature on a message — including third-party
// signers like amazonses.com whose selectors are irrelevant to this domain's
// own DNS. Alignment here is relaxed: exact match or subdomain either way.
export async function getObservedDkimSigners(scope: DomainScope, domain: string): Promise<DkimSigner[]> {
  assertScope(scope)
  const only = scopeNames(scope)
  // Only the last 30 days: many providers rotate DKIM selectors and delete
  // old keys from DNS, so historical selectors produce false "missing" noise.
  // 'none' is parsedmarc's placeholder when a report omits the selector.
  const rows = (await sql`
    SELECT
      elem->>'selector' AS selector,
      LOWER(elem->>'domain') AS signing_domain,
      MAX(r.period_end) AS last_seen
    FROM records r
    JOIN domains d ON d.id = r.domain_id,
    LATERAL jsonb_array_elements(r.dkim_results) elem
    WHERE LOWER(d.name) = LOWER(${domain})
      AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
      AND elem->>'selector' IS NOT NULL
      AND elem->>'selector' NOT IN ('none', '')
      AND elem->>'domain' IS NOT NULL
      AND r.period_end >= NOW() - INTERVAL '30 days'
      AND (
        -- Suffix comparisons, not LIKE: the signing domain comes from the
        -- report (untrusted) and "%" or "_" in it would act as wildcards.
        LOWER(elem->>'domain') = LOWER(${domain}::text)
        OR RIGHT(LOWER(elem->>'domain'), LENGTH(${domain}::text) + 1) = '.' || LOWER(${domain}::text)
        OR RIGHT(LOWER(${domain}::text), LENGTH(elem->>'domain') + 1) = '.' || LOWER(elem->>'domain')
      )
    GROUP BY 1, 2
    ORDER BY last_seen DESC
    LIMIT 12
  `) as Array<{ selector: string | null; signing_domain: string | null }>
  return rows
    .filter((r): r is { selector: string; signing_domain: string; last_seen: string } => Boolean(r.selector && r.signing_domain))
    .map((r) => ({ selector: r.selector, signing_domain: r.signing_domain }))
}

export async function getLatestDnsCheck(scope: DomainScope, domain: string): Promise<Record<string, unknown> | null> {
  assertScope(scope)
  const only = scopeNames(scope)
  const rows = (await sql`
    SELECT c.results
    FROM dns_checks c
    JOIN domains d ON d.id = c.domain_id
    WHERE LOWER(d.name) = LOWER(${domain})
      AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
    ORDER BY c.checked_at DESC
    LIMIT 1
  `) as Array<{ results: Record<string, unknown> }>
  return rows[0]?.results ?? null
}

// ---------- problem sources (issues page) ----------

export type ProblemSource = {
  source_ip: string
  domain: string
  reverse_dns: string | null
  base_domain: string | null
  provider_name: string | null
  as_name: string | null
  as_domain: string | null
  total_messages: number
  failing: number
  dkim_passed: number
  spf_passed: number
  passed: number
  last_seen: string | null
  // Diagnostics over the FAILING subset (dmarc_aligned = false):
  // messages that still carried a cryptographically valid DKIM signature
  // (just not aligned with the domain) — the forwarding fingerprint...
  fail_with_valid_dkim_sig: number
  // ...and messages where raw SPF evaluated 'pass' for a different envelope
  // domain — an alignment problem, not an authorization problem.
  fail_with_raw_spf_pass: number
  // ...and messages where both were true: authenticated end to end, just
  // for someone else's domain.
  fail_with_both: number
  // Most common envelope-from among failing messages.
  top_fail_envelope: string | null
}

export async function getProblemSources(scope: DomainScope, days = 7, limit = 50, domain?: string): Promise<ProblemSource[]> {
  assertScope(scope)
  const only = scopeNames(scope)
  const since = cutoff(days)
  const onlyDomain = domain ? domain.toLowerCase() : null
  const rows = (await sql`
    SELECT
      host(r.source_ip) AS source_ip,
      d.name AS domain,
      m.reverse_dns,
      m.base_domain,
      m.provider_name,
      m.as_name,
      m.as_domain,
      SUM(r.message_count)::bigint AS total_messages,
      SUM(CASE WHEN NOT r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS failing,
      SUM(CASE WHEN r.dmarc_aligned THEN r.message_count ELSE 0 END)::bigint AS passed,
      SUM(CASE WHEN r.dkim_aligned THEN r.message_count ELSE 0 END)::bigint AS dkim_passed,
      SUM(CASE WHEN r.spf_aligned THEN r.message_count ELSE 0 END)::bigint AS spf_passed,
      MAX(r.period_end) AS last_seen,
      SUM(CASE WHEN NOT r.dmarc_aligned AND r.dkim_sig_valid THEN r.message_count ELSE 0 END)::bigint AS fail_with_valid_dkim_sig,
      SUM(CASE WHEN NOT r.dmarc_aligned AND r.spf_raw_pass THEN r.message_count ELSE 0 END)::bigint AS fail_with_raw_spf_pass,
      SUM(CASE WHEN NOT r.dmarc_aligned AND r.dkim_sig_valid AND r.spf_raw_pass THEN r.message_count ELSE 0 END)::bigint AS fail_with_both,
      mode() WITHIN GROUP (ORDER BY r.envelope_from) FILTER (WHERE NOT r.dmarc_aligned AND r.envelope_from IS NOT NULL) AS top_fail_envelope
    FROM records r
    JOIN domains d ON d.id = r.domain_id
    LEFT JOIN ip_metadata m ON m.ip = r.source_ip
    WHERE r.period_end >= ${since}::timestamptz
      AND (${onlyDomain}::text IS NULL OR d.name = ${onlyDomain}::text)
      AND (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
    GROUP BY r.source_ip, d.name, m.reverse_dns, m.base_domain, m.provider_name, m.as_name, m.as_domain
    HAVING SUM(CASE WHEN NOT r.dmarc_aligned THEN r.message_count ELSE 0 END) > 0
    ORDER BY failing DESC
    LIMIT ${limit}
  `) as Array<Record<string, string | number | null>>

  return rows.map((r) => {
    const rdns = (r.reverse_dns as string | null) ?? null
    return {
      source_ip: String(r.source_ip),
      domain: String(r.domain),
      reverse_dns: rdns === 'unresolved' ? null : rdns,
      base_domain: (r.base_domain as string | null) ?? null,
      provider_name: (r.provider_name as string | null) ?? null,
      as_name: (r.as_name as string | null) ?? null,
      as_domain: (r.as_domain as string | null) ?? null,
      total_messages: num(r.total_messages as string | number),
      failing: num(r.failing as string | number),
      passed: num(r.passed as string | number),
      dkim_passed: num(r.dkim_passed as string | number),
      spf_passed: num(r.spf_passed as string | number),
      last_seen: (r.last_seen as string | null) ?? null,
      fail_with_valid_dkim_sig: num(r.fail_with_valid_dkim_sig as string | number),
      fail_with_raw_spf_pass: num(r.fail_with_raw_spf_pass as string | number),
      fail_with_both: num(r.fail_with_both as string | number),
      top_fail_envelope: (r.top_fail_envelope as string | null) ?? null,
    }
  })
}

// Latest DNS check per domain, in bulk — used by the Issues page for SPF
// attribution across every domain that has problem sources.
export async function getLatestDnsChecksByDomain(scope: DomainScope): Promise<Map<string, Record<string, unknown>>> {
  assertScope(scope)
  const only = scopeNames(scope)
  const rows = (await sql`
    SELECT DISTINCT ON (c.domain_id) d.name AS domain, c.results
    FROM dns_checks c
    JOIN domains d ON d.id = c.domain_id
    WHERE (${only}::text[] IS NULL OR LOWER(d.name) = ANY(${only}::text[]))
    ORDER BY c.domain_id, c.checked_at DESC
  `) as Array<{ domain: string; results: Record<string, unknown> }>
  return new Map(rows.map((r) => [r.domain.toLowerCase(), r.results]))
}

// ---------- shared row mapper ----------

function mapSourceRow(r: Record<string, string | number | null>): TopSource {
  // 'unresolved' is the ingest's negative-cache marker for IPs whose
  // reverse-DNS lookup failed — display-wise it's the same as no rDNS.
  const rdns = (r.reverse_dns as string | null) ?? null
  return {
    source_ip: String(r.source_ip),
    reverse_dns: rdns === 'unresolved' ? null : rdns,
    base_domain: (r.base_domain as string | null) ?? null,
    provider_name: (r.provider_name as string | null) ?? null,
    as_name: (r.as_name as string | null) ?? null,
    as_domain: (r.as_domain as string | null) ?? null,
    total_messages: num(r.total_messages as string | number),
    passed: num(r.passed as string | number),
    failed: num(r.failed as string | number),
    dkim_passed: num(r.dkim_passed as string | number),
    spf_passed: num(r.spf_passed as string | number),
  }
}
