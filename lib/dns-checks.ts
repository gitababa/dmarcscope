// Live DNS health checks for a domain: MX, SPF, DMARC, DKIM, plus the
// optional MTA-STS, TLS-RPT and BIMI records.
// Runs in the Node.js runtime (route handler); every query goes through the
// DnsClient it is given (lib/dns-resolver.ts).
// DKIM has no discovery mechanism in DNS, so we probe the selectors actually
// observed in this domain's DMARC reports plus a few common defaults.

import { createDnsClient, isNoRecord, type DnsClient } from './dns-resolver'
import { fetchMtaStsPolicy, mxMatches, parseMtaStsPolicy, type MtaStsPolicy, type PolicyFetcher } from './mta-sts'
import { isSpfRecord, type SpfExpansion } from './spf'

export type CheckStatus = 'ok' | 'warn' | 'fail'
// For the optional protocols, 'none' means "not published", which is a
// choice rather than a fault.
export type OptionalStatus = CheckStatus | 'none'

export type DkimProbe = { selector: string; signing_domain: string }

type OptionalRecordCheck = { status: OptionalStatus; record: string | null; notes: string[]; lookup_failed?: boolean }

export type DnsCheckResults = {
  checked_at: string
  // The DNS servers asked; empty means the host's own resolver configuration.
  // (Absent on checks stored before this field existed.)
  resolver?: string[]
  mx: { status: CheckStatus; records: Array<{ exchange: string; priority: number }>; notes: string[]; lookup_failed?: boolean }
  // lookup_failed: the lookup timed out or the server failed, so `record` says
  // nothing about what is published (as opposed to null for "no record").
  spf: { status: CheckStatus; record: string | null; notes: string[]; lookup_failed?: boolean }
  // `record` is what is published at _dmarc.<domain> itself. With none there,
  // `inherited` is the record of the parent domain whose policy applies.
  dmarc: {
    status: CheckStatus
    record: string | null
    notes: string[]
    lookup_failed?: boolean
    inherited?: { from: string; record: string }
  }
  dkim: {
    status: CheckStatus
    selectors: Array<{ selector: string; signing_domain?: string; found: boolean; observed: boolean; lookup_failed?: boolean }>
    notes: string[]
  }
  // Absent on checks stored before these were added.
  mta_sts?: OptionalRecordCheck & { policy: MtaStsPolicy | null }
  tls_rpt?: OptionalRecordCheck
  bimi?: OptionalRecordCheck
  // Populated by the dns-check route after runDnsChecks: the SPF record
  // recursively expanded into CIDR networks for source attribution.
  spf_expanded?: SpfExpansion
}

export type DnsCheckOptions = {
  dns?: DnsClient
  // Recorded with the results; what `dns` was built from.
  servers?: string[]
  fetchPolicy?: PolicyFetcher
}

export const COMMON_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 's1', 's2', 'default', 'dkim']

// DMARCbis tree walk: at most this many parent domains are asked.
const MAX_PARENT_LOOKUPS = 7

const RANK: Record<OptionalStatus, number> = { none: 0, ok: 1, warn: 2, fail: 3 }
function worst<T extends OptionalStatus>(a: T, b: T): T {
  return RANK[b] > RANK[a] ? b : a
}

// null = NXDOMAIN / no records; throws only on timeout or server failure.
async function txtRecords(dns: DnsClient, name: string): Promise<string[] | null> {
  try {
    return (await dns.resolveTxt(name)).map((parts) => parts.join(''))
  } catch (e) {
    if (isNoRecord(e)) return null
    throw e
  }
}

// True when the record's first tag is v=<version> ("v=DMARC10" is not
// DMARC1). Whitespace around "=" is allowed, as in every tag-list record.
export function hasVersion(record: string, version: string): boolean {
  const m = /^\s*v\s*=\s*([^;\s]*)\s*(;|$)/i.exec(record)
  return !!m && m[1].toLowerCase() === version.toLowerCase()
}

// Parses "v=DMARC1; p=none; rua=mailto:a@example.com" into { p: 'none', ... }.
// Tag names are lower-cased; values keep their case (rua addresses, etc.).
export function parseTagList(record: string): Record<string, string> {
  const tags: Record<string, string> = {}
  for (const part of record.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const key = part.slice(0, eq).trim().toLowerCase()
    if (key && !(key in tags)) tags[key] = part.slice(eq + 1).trim()
  }
  return tags
}

const POLICIES = ['none', 'quarantine', 'reject']

// ---- MX ----
async function checkMx(dns: DnsClient, domain: string): Promise<DnsCheckResults['mx']> {
  const out: DnsCheckResults['mx'] = { status: 'fail', records: [], notes: [] }
  const none = 'No MX records — this domain cannot receive mail (fine for send-only domains).'
  try {
    const mx = await dns.resolveMx(domain)
    out.records = mx.sort((a, b) => a.priority - b.priority).map((m) => ({ exchange: m.exchange, priority: m.priority }))
    if (mx.length > 0 && mx.every((m) => m.exchange === '' || m.exchange === '.')) {
      out.notes.push('Null MX (RFC 7505): this domain explicitly does not accept mail. Fine for send-only or unused domains.')
      out.status = 'warn'
    } else if (mx.length === 0) {
      out.notes.push(none)
      out.status = 'warn'
    } else {
      out.status = 'ok'
    }
  } catch (e) {
    if (isNoRecord(e)) {
      out.notes.push(none)
      out.status = 'warn'
    } else {
      out.lookup_failed = true
      out.notes.push(`MX lookup failed: ${String(e)}`)
    }
  }
  return out
}

// ---- SPF ----
async function checkSpf(dns: DnsClient, domain: string): Promise<DnsCheckResults['spf']> {
  const out: DnsCheckResults['spf'] = { status: 'fail', record: null, notes: [] }
  try {
    const txts = await txtRecords(dns, domain)
    const spfRecords = (txts || []).filter(isSpfRecord)
    if (spfRecords.length === 0) {
      out.notes.push('No SPF record found. Receivers cannot verify which servers may send for this domain.')
    } else if (spfRecords.length > 1) {
      out.record = spfRecords.join('  |  ')
      out.notes.push('Multiple SPF records found — RFC 7208 requires exactly one; receivers treat this as a permanent error.')
    } else {
      const record = spfRecords[0]
      out.record = record
      out.status = 'ok'
      // (The DNS-lookup budget is assessed from the recursive expansion, in
      // lib/dns-run.ts — the top-level record alone can't show nested includes.)
      const terms = record.toLowerCase().split(/\s+/).slice(1)
      const all = terms.find((t) => /^[+\-~?]?all$/.test(t))
      const hasRedirect = terms.some((t) => t.startsWith('redirect='))
      if (all === 'all' || all === '+all') {
        out.status = 'fail'
        out.notes.push('"+all" allows the entire internet to send as this domain.')
      } else if (all === '?all') {
        out.status = 'warn'
        out.notes.push('"?all" (neutral) provides no protection; use "~all" or "-all".')
      } else if (!all && !hasRedirect) {
        out.status = 'warn'
        out.notes.push('No "all" mechanism: mail from unlisted servers gets a neutral result. End the record with "~all" or "-all".')
      }
      if (terms.some((t) => /^[+\-~?]?ptr(:|$)/.test(t))) {
        if (out.status === 'ok') out.status = 'warn'
        out.notes.push('The "ptr" mechanism is deprecated (RFC 7208 §5.5) and ignored by some receivers.')
      }
    }
  } catch (e) {
    out.lookup_failed = true
    out.notes.push(`SPF lookup failed: ${String(e)}`)
  }
  return out
}

// ---- DMARC ----

type ParentDmarc = { from: string; record: string } | { from: string; multiple: true } | { failedAt: string } | null

// With no record at _dmarc.<domain>, the policy of the closest parent domain
// that publishes one applies (RFC 7489 §6.6.3 finds it via the
// organizational domain; DMARCbis by walking up the tree, as here).
async function findParentDmarc(dns: DnsClient, domain: string): Promise<ParentDmarc> {
  const labels = domain.split('.')
  for (let i = 1; i <= MAX_PARENT_LOOKUPS && labels.length - i >= 2; i++) {
    const name = labels.slice(i).join('.')
    let txts: string[] | null
    try {
      txts = await txtRecords(dns, `_dmarc.${name}`)
    } catch {
      return { failedAt: name }
    }
    const records = (txts || []).filter((t) => hasVersion(t, 'DMARC1'))
    if (records.length > 1) return { from: name, multiple: true }
    if (records.length === 1) return { from: name, record: records[0] }
  }
  return null
}

// Grades the record that applies to `domain`. `parent` is set when the
// record was inherited, in which case sp= (if valid) is the policy in force.
function gradeDmarc(domain: string, record: string, parent?: string): { status: CheckStatus; notes: string[]; enforcing: boolean } {
  const notes: string[] = []
  let status: CheckStatus = 'ok'
  const tags = parseTagList(record)
  const p = (tags.p || '').toLowerCase()
  const sp = (tags.sp || '').toLowerCase()
  const effective = parent && POLICIES.includes(sp) ? sp : p
  if (parent) {
    notes.push(
      `No record at _dmarc.${domain}, so the policy published at _dmarc.${parent} applies to it as a subdomain${parent && POLICIES.includes(sp) ? ` (sp=${sp})` : ''}.`
    )
  }
  if (!p) {
    status = 'fail'
    notes.push('Missing required p= tag.')
  } else if (!POLICIES.includes(p)) {
    status = 'fail'
    notes.push(`Invalid policy p=${tags.p} — must be none, quarantine or reject.`)
  } else if (effective === 'none') {
    status = 'warn'
    notes.push(
      parent
        ? `The policy in force here is "none" (monitoring only): failing mail is still delivered.`
        : 'p=none is monitoring-only: failing mail is still delivered. Move to quarantine/reject once compliance is stable.'
    )
  }
  if (!tags.rua) {
    if (status !== 'fail') status = 'warn'
    notes.push('No rua= tag — no aggregate reports are being requested, so this tool receives no data for the domain.')
  }
  const pct = tags.pct === undefined ? 100 : Number(tags.pct)
  if (tags.pct && pct < 100 && effective !== 'none') {
    notes.push(`pct=${tags.pct}: policy only applies to ${tags.pct}% of failing mail.`)
  }
  const enforcing = (effective === 'quarantine' || effective === 'reject') && pct >= 100 && (parent ? true : sp !== 'none')
  return { status, notes, enforcing }
}

// `enforcing` is null when it is unknown (lookup failed, no valid record).
async function checkDmarc(dns: DnsClient, domain: string): Promise<{ result: DnsCheckResults['dmarc']; enforcing: boolean | null }> {
  const out: DnsCheckResults['dmarc'] = { status: 'fail', record: null, notes: [] }
  let txts: string[] | null
  try {
    txts = await txtRecords(dns, `_dmarc.${domain}`)
  } catch (e) {
    out.lookup_failed = true
    out.notes.push(`DMARC lookup failed: ${String(e)}`)
    return { result: out, enforcing: null }
  }
  const own = (txts || []).filter((t) => hasVersion(t, 'DMARC1'))
  if (own.length > 1) {
    out.record = own.join('  |  ')
    out.notes.push('Multiple DMARC records found — receivers must ignore all of them (RFC 7489 §6.6.3). Publish exactly one.')
    return { result: out, enforcing: false }
  }
  if (own.length === 1) {
    out.record = own[0]
    const g = gradeDmarc(domain, own[0])
    out.status = g.status
    out.notes.push(...g.notes)
    return { result: out, enforcing: g.status === 'fail' ? false : g.enforcing }
  }

  const parent = await findParentDmarc(dns, domain)
  if (parent === null) {
    out.notes.push(`No DMARC record at _dmarc.${domain}${domain.split('.').length > 2 ? ' or at any parent domain' : ''}.`)
    return { result: out, enforcing: false }
  }
  if ('failedAt' in parent) {
    out.status = 'warn'
    out.notes.push(
      `No record at _dmarc.${domain}. The lookup for _dmarc.${parent.failedAt} failed (timeout or server failure), so a parent domain's policy may still apply. Re-run the check.`
    )
    return { result: out, enforcing: null }
  }
  if ('multiple' in parent) {
    out.notes.push(
      `No record at _dmarc.${domain}, and _dmarc.${parent.from} publishes more than one DMARC record, so receivers apply none of them (RFC 7489 §6.6.3).`
    )
    return { result: out, enforcing: false }
  }
  out.inherited = { from: parent.from, record: parent.record }
  const g = gradeDmarc(domain, parent.record, parent.from)
  out.status = g.status
  out.notes.push(...g.notes)
  return { result: out, enforcing: g.status === 'fail' ? false : g.enforcing }
}

// ---- DKIM ----
// Probe observed signers at their actual signing domain (a signature by
// d=mail.example.com lives at selector._domainkey.mail.example.com), plus
// common default selectors at the domain itself.
async function checkDkim(dns: DnsClient, domain: string, observedSigners: DkimProbe[]): Promise<DnsCheckResults['dkim']> {
  const out: DnsCheckResults['dkim'] = { status: 'fail', selectors: [], notes: [] }
  const observedProbes: DkimProbe[] = observedSigners
    .map((s) => ({ selector: s.selector.toLowerCase(), signing_domain: s.signing_domain.toLowerCase() }))
    .filter((s) => s.selector && s.signing_domain)
  const seen = new Set(observedProbes.map((p) => `${p.selector}@${p.signing_domain}`))
  const defaultProbes: DkimProbe[] = COMMON_DKIM_SELECTORS.filter((sel) => !seen.has(`${sel}@${domain}`)).map((sel) => ({
    selector: sel,
    signing_domain: domain,
  }))
  const toProbe = [...observedProbes, ...defaultProbes].slice(0, 14)
  const observedKeys = new Set(observedProbes.map((p) => `${p.selector}@${p.signing_domain}`))

  out.selectors = await Promise.all(
    toProbe.map(async (probe) => {
      let found = false
      let failed = false
      try {
        const txts = await txtRecords(dns, `${probe.selector}._domainkey.${probe.signing_domain}`)
        // A key record with an empty p= is a revoked key (RFC 6376 §3.6.1).
        found = (txts || []).some((t) => /(^|;)\s*p=\s*[A-Za-z0-9+/]/.test(t))
      } catch {
        // Timeout / SERVFAIL: unknown, not "missing".
        failed = true
      }
      return {
        selector: probe.selector,
        signing_domain: probe.signing_domain === domain ? undefined : probe.signing_domain,
        found,
        observed: observedKeys.has(`${probe.selector}@${probe.signing_domain}`),
        ...(failed ? { lookup_failed: true } : {}),
      }
    })
  )
  const foundAny = out.selectors.some((s) => s.found)
  const failed = out.selectors.filter((s) => s.lookup_failed)
  const observedMissing = out.selectors.filter((s) => s.observed && !s.found && !s.lookup_failed)
  const observedFailed = failed.filter((s) => s.observed)
  if (!foundAny && failed.length > 0) {
    out.status = 'warn'
    out.notes.push(
      `No DKIM keys found, but ${failed.length} ${failed.length === 1 ? 'lookup' : 'lookups'} failed (timeout or server failure), so keys may exist. Re-run the check.`
    )
  } else if (!foundAny) {
    out.status = 'fail'
    out.notes.push('No DKIM public keys found on any probed selector.')
  } else if (observedMissing.length > 0) {
    out.status = 'warn'
    out.notes.push(
      `Selector(s) seen in reports but missing from DNS: ${observedMissing.map((s) => s.selector).join(', ')} — possibly rotated out or a signer misconfiguration.`
    )
  } else if (observedFailed.length > 0) {
    out.status = 'warn'
    out.notes.push(`Selector(s) seen in reports could not be checked (lookup failed): ${observedFailed.map((s) => s.selector).join(', ')}. Re-run the check.`)
  } else {
    out.status = 'ok'
  }
  if (observedProbes.length === 0) {
    out.notes.push('No aligned DKIM signers observed in reports yet; probed common default selectors only.')
  }
  return out
}

// The one record of a kind at `name`, or the reason there isn't exactly one.
async function singleRecord(
  dns: DnsClient,
  name: string,
  version: string,
  label: string
): Promise<{ kind: 'one'; record: string } | { kind: 'done'; result: OptionalRecordCheck }> {
  let txts: string[] | null
  try {
    txts = await txtRecords(dns, name)
  } catch (e) {
    return { kind: 'done', result: { status: 'warn', record: null, lookup_failed: true, notes: [`${label} lookup failed: ${String(e)}`] } }
  }
  const records = (txts || []).filter((t) => hasVersion(t, version))
  if (records.length === 0) return { kind: 'done', result: { status: 'none', record: null, notes: [] } }
  if (records.length > 1) {
    return {
      kind: 'done',
      result: { status: 'fail', record: records.join('  |  '), notes: [`Multiple ${label} records at ${name}; receivers ignore all of them. Publish exactly one.`] },
    }
  }
  return { kind: 'one', record: records[0] }
}

// ---- MTA-STS (RFC 8461) ----
async function checkMtaSts(
  dns: DnsClient,
  domain: string,
  mx: DnsCheckResults['mx'],
  fetchPolicy: PolicyFetcher
): Promise<NonNullable<DnsCheckResults['mta_sts']>> {
  const hosts = mx.records.map((m) => m.exchange).filter((h) => h && h !== '.')
  const found = await singleRecord(dns, `_mta-sts.${domain}`, 'STSv1', 'MTA-STS')
  if (found.kind === 'done') {
    if (found.result.status === 'none') {
      found.result.notes.push(
        hosts.length > 0
          ? 'Not published. MTA-STS lets sending servers insist on an encrypted, verified connection when they deliver to your MX hosts.'
          : 'Not published; not needed while the domain receives no mail.'
      )
    }
    return { ...found.result, policy: null }
  }
  const out: NonNullable<DnsCheckResults['mta_sts']> = { status: 'ok', record: found.record, policy: null, notes: [] }
  const id = parseTagList(found.record).id
  if (!id || !/^[A-Za-z0-9]{1,32}$/.test(id)) {
    out.status = 'fail'
    out.notes.push('The record needs id= with 1 to 32 letters and digits; senders ignore it otherwise.')
    return out
  }
  const fetched = await fetchPolicy(domain, dns)
  if (!fetched.ok) {
    out.status = 'fail'
    out.notes.push(`The record is published, but ${fetched.error}. Senders that cannot fetch the policy deliver as if MTA-STS were absent.`)
    return out
  }
  const policy = parseMtaStsPolicy(fetched.text)
  out.policy = policy
  if (!/^text\/plain(\s*;|$)/i.test(fetched.contentType.trim())) {
    out.status = worst(out.status, 'warn')
    out.notes.push(`The policy is served as "${fetched.contentType || 'no content type'}"; RFC 8461 requires text/plain and some senders reject anything else.`)
  }
  if (policy.version !== 'STSv1') {
    out.status = 'fail'
    out.notes.push('The policy file is missing "version: STSv1".')
  }
  if (!policy.mode || !['enforce', 'testing', 'none'].includes(policy.mode)) {
    out.status = 'fail'
    out.notes.push(`The policy mode must be enforce, testing or none${policy.mode ? `, not "${policy.mode}"` : ''}.`)
  } else if (policy.mode === 'none') {
    out.status = worst(out.status, 'warn')
    out.notes.push('mode: none — the policy is switched off.')
  } else if (policy.mode === 'testing') {
    out.status = worst(out.status, 'warn')
    out.notes.push('mode: testing — failed TLS deliveries are only reported (via TLS-RPT), not refused. Switch to enforce once reports are clean.')
  }
  if (policy.max_age === null || policy.max_age > 31557600) {
    out.status = 'fail'
    out.notes.push('max_age must be a number of seconds up to 31557600 (one year).')
  } else if (policy.max_age < 86400) {
    out.status = worst(out.status, 'warn')
    out.notes.push(`max_age is ${policy.max_age} seconds; senders keep the policy for less than a day. Weeks (604800 or more) are usual.`)
  }
  if (policy.mode && policy.mode !== 'none') {
    if (policy.mx.length === 0) {
      out.status = 'fail'
      out.notes.push('The policy lists no mx: patterns, so no MX host is valid under it.')
    } else if (mx.lookup_failed) {
      out.notes.push('The MX lookup failed, so the mx: patterns could not be compared with the MX hosts.')
    } else {
      const uncovered = hosts.filter((h) => !policy.mx.some((p) => mxMatches(p, h)))
      if (uncovered.length > 0) {
        out.status = policy.mode === 'enforce' ? 'fail' : worst(out.status, 'warn')
        out.notes.push(
          `MX ${uncovered.length === 1 ? 'host' : 'hosts'} not matched by the policy's mx: patterns: ${uncovered.join(', ')}. ` +
            (policy.mode === 'enforce' ? 'Senders that enforce MTA-STS will refuse to deliver to them.' : 'Under enforce, senders would refuse to deliver to them.')
        )
      }
    }
  }
  return out
}

// ---- TLS-RPT (RFC 8460) ----
async function checkTlsRpt(dns: DnsClient, domain: string): Promise<OptionalRecordCheck> {
  const found = await singleRecord(dns, `_smtp._tls.${domain}`, 'TLSRPTv1', 'TLS-RPT')
  if (found.kind === 'done') {
    if (found.result.status === 'none') found.result.notes.push('Not published. TLS-RPT asks sending servers to report failed encrypted deliveries to you.')
    return found.result
  }
  const out: OptionalRecordCheck = { status: 'ok', record: found.record, notes: [] }
  const rua = parseTagList(found.record).rua
  if (!rua) {
    out.status = 'fail'
    out.notes.push('Missing rua= — the record says where reports go, and is ignored without it.')
    return out
  }
  for (const uri of rua.split(',').map((u) => u.trim())) {
    if (!/^mailto:[^@\s]+@[^@\s]+$/i.test(uri) && !/^https:\/\/\S+$/i.test(uri)) {
      out.status = 'fail'
      out.notes.push(`rua entry "${uri.slice(0, 120)}" must be a mailto: or https: address.`)
    }
  }
  return out
}

// ---- BIMI ----
async function checkBimi(dns: DnsClient, domain: string, dmarcEnforcing: boolean | null): Promise<OptionalRecordCheck> {
  const found = await singleRecord(dns, `default._bimi.${domain}`, 'BIMI1', 'BIMI')
  if (found.kind === 'done') {
    if (found.result.status === 'none') found.result.notes.push('Not published. BIMI shows your logo next to authenticated mail in inboxes that support it.')
    return found.result
  }
  const out: OptionalRecordCheck = { status: 'ok', record: found.record, notes: [] }
  const tags = parseTagList(found.record)
  const l = tags.l ?? ''
  const a = tags.a ?? ''
  if (!l && !a) {
    out.status = 'none'
    out.notes.push('Published as a declination (empty l= and a=): this domain opts out of logo display.')
    return out
  }
  if (l && !/^https:\/\/\S+$/i.test(l)) {
    out.status = 'fail'
    out.notes.push('l= must be an https:// address of the SVG logo.')
  }
  if (a && !/^https:\/\/\S+$/i.test(a)) {
    out.status = 'fail'
    out.notes.push('a= must be an https:// address of the mark certificate (PEM).')
  }
  if (!a) {
    out.notes.push('No mark certificate (a=). Gmail and Apple Mail only show logos backed by a VMC or CMC.')
  }
  if (dmarcEnforcing === false) {
    out.status = worst(out.status, 'warn')
    out.notes.push('Inboxes only show BIMI logos when DMARC is enforced: p=quarantine or p=reject at pct=100, with sp= not none.')
  }
  return out
}

export async function runDnsChecks(domain: string, observedSigners: DkimProbe[], opts: DnsCheckOptions = {}): Promise<DnsCheckResults> {
  const dns = opts.dns ?? createDnsClient(opts.servers ?? [])
  const fetchPolicy = opts.fetchPolicy ?? fetchMtaStsPolicy

  const [mx, spf, dmarc, dkim, tlsRpt] = await Promise.all([
    checkMx(dns, domain),
    checkSpf(dns, domain),
    checkDmarc(dns, domain),
    checkDkim(dns, domain, observedSigners),
    checkTlsRpt(dns, domain),
  ])
  const [mtaSts, bimi] = await Promise.all([checkMtaSts(dns, domain, mx, fetchPolicy), checkBimi(dns, domain, dmarc.enforcing)])

  if (mtaSts.record && tlsRpt.status === 'none') {
    tlsRpt.status = 'warn'
    tlsRpt.notes.push('MTA-STS is published without TLS-RPT, so nobody hears about deliveries that fail under the policy.')
  }

  return {
    checked_at: new Date().toISOString(),
    resolver: opts.servers ?? [],
    mx,
    spf,
    dmarc: dmarc.result,
    dkim,
    mta_sts: mtaSts,
    tls_rpt: tlsRpt,
    bimi,
  }
}
