// Live DNS health checks for a domain: MX, SPF, DMARC, DKIM.
// Runs in the Node.js runtime (route handler) using dns/promises.
// DKIM has no discovery mechanism in DNS, so we probe the selectors actually
// observed in this domain's DMARC reports plus a few common defaults.

import { resolveMx, resolveTxt } from 'node:dns/promises'
import type { SpfExpansion } from './spf'

export type CheckStatus = 'ok' | 'warn' | 'fail'

export type DkimProbe = { selector: string; signing_domain: string }

export type DnsCheckResults = {
  checked_at: string
  mx: { status: CheckStatus; records: Array<{ exchange: string; priority: number }>; notes: string[] }
  spf: { status: CheckStatus; record: string | null; notes: string[] }
  dmarc: { status: CheckStatus; record: string | null; notes: string[] }
  dkim: {
    status: CheckStatus
    selectors: Array<{ selector: string; signing_domain?: string; found: boolean; observed: boolean }>
    notes: string[]
  }
  // Populated by the dns-check route after runDnsChecks: the SPF record
  // recursively expanded into CIDR networks for source attribution.
  spf_expanded?: SpfExpansion
}

export const COMMON_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 's1', 's2', 'default', 'dkim']

const TIMEOUT_MS = 4000

function withTimeout<T>(p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), TIMEOUT_MS)),
  ])
}

async function txtRecords(name: string): Promise<string[] | null> {
  // null = NXDOMAIN / no records; throws only on timeout or server failure
  try {
    const chunks = await withTimeout(resolveTxt(name))
    return chunks.map((parts) => parts.join(''))
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ENOTFOUND' || code === 'ENODATA') return null
    throw e
  }
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

export async function runDnsChecks(domain: string, observedSigners: DkimProbe[]): Promise<DnsCheckResults> {
  const results: DnsCheckResults = {
    checked_at: new Date().toISOString(),
    mx: { status: 'fail', records: [], notes: [] },
    spf: { status: 'fail', record: null, notes: [] },
    dmarc: { status: 'fail', record: null, notes: [] },
    dkim: { status: 'fail', selectors: [], notes: [] },
  }

  // ---- MX ----
  try {
    const mx = await withTimeout(resolveMx(domain))
    results.mx.records = mx.sort((a, b) => a.priority - b.priority).map((m) => ({ exchange: m.exchange, priority: m.priority }))
    if (mx.length > 0 && mx.every((m) => m.exchange === '' || m.exchange === '.')) {
      results.mx.notes.push('Null MX (RFC 7505): this domain explicitly does not accept mail. Fine for send-only or unused domains.')
      results.mx.status = 'warn'
    } else if (mx.length === 0) {
      results.mx.notes.push('No MX records — this domain cannot receive mail (fine for send-only domains).')
      results.mx.status = 'warn'
    } else {
      results.mx.status = 'ok'
    }
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      results.mx.notes.push('No MX records — this domain cannot receive mail (fine for send-only domains).')
      results.mx.status = 'warn'
    } else {
      results.mx.notes.push(`MX lookup failed: ${String(e)}`)
    }
  }

  // ---- SPF ----
  try {
    const txts = await txtRecords(domain)
    const spfRecords = (txts || []).filter((t) => t.toLowerCase().startsWith('v=spf1'))
    if (spfRecords.length === 0) {
      results.spf.notes.push('No SPF record found. Receivers cannot verify which servers may send for this domain.')
    } else if (spfRecords.length > 1) {
      results.spf.record = spfRecords.join('  |  ')
      results.spf.status = 'fail'
      results.spf.notes.push('Multiple SPF records found — RFC 7208 requires exactly one; receivers treat this as a permanent error.')
    } else {
      const record = spfRecords[0]
      results.spf.record = record
      results.spf.status = 'ok'
      // (The DNS-lookup budget is assessed from the recursive expansion, in
      // lib/dns-run.ts — the top-level record alone can't show nested includes.)
      const terms = record.toLowerCase().split(/\s+/).slice(1)
      const all = terms.find((t) => /^[+\-~?]?all$/.test(t))
      const hasRedirect = terms.some((t) => t.startsWith('redirect='))
      if (all === 'all' || all === '+all') {
        results.spf.status = 'fail'
        results.spf.notes.push('"+all" allows the entire internet to send as this domain.')
      } else if (all === '?all') {
        results.spf.status = 'warn'
        results.spf.notes.push('"?all" (neutral) provides no protection; use "~all" or "-all".')
      } else if (!all && !hasRedirect) {
        results.spf.status = 'warn'
        results.spf.notes.push('No "all" mechanism: mail from unlisted servers gets a neutral result. End the record with "~all" or "-all".')
      }
      if (terms.some((t) => /^[+\-~?]?ptr(:|$)/.test(t))) {
        if (results.spf.status === 'ok') results.spf.status = 'warn'
        results.spf.notes.push('The "ptr" mechanism is deprecated (RFC 7208 §5.5) and ignored by some receivers.')
      }
    }
  } catch (e) {
    results.spf.notes.push(`SPF lookup failed: ${String(e)}`)
  }

  // ---- DMARC ----
  try {
    const txts = await txtRecords(`_dmarc.${domain}`)
    const dmarcRecords = (txts || []).filter((t) => t.toLowerCase().startsWith('v=dmarc1'))
    if (dmarcRecords.length === 0) {
      results.dmarc.notes.push('No DMARC record at _dmarc.' + domain)
    } else if (dmarcRecords.length > 1) {
      results.dmarc.record = dmarcRecords.join('  |  ')
      results.dmarc.notes.push('Multiple DMARC records found — receivers must ignore all of them (RFC 7489 §6.6.3). Publish exactly one.')
    } else {
      const record = dmarcRecords[0]
      results.dmarc.record = record
      results.dmarc.status = 'ok'
      const tags = parseTagList(record)
      const policy = (tags.p || '').toLowerCase()
      if (!policy) {
        results.dmarc.status = 'fail'
        results.dmarc.notes.push('Missing required p= tag.')
      } else if (!['none', 'quarantine', 'reject'].includes(policy)) {
        results.dmarc.status = 'fail'
        results.dmarc.notes.push(`Invalid policy p=${tags.p} — must be none, quarantine or reject.`)
      } else if (policy === 'none') {
        results.dmarc.status = 'warn'
        results.dmarc.notes.push('p=none is monitoring-only: failing mail is still delivered. Move to quarantine/reject once compliance is stable.')
      }
      if (!tags.rua) {
        results.dmarc.status = results.dmarc.status === 'fail' ? 'fail' : 'warn'
        results.dmarc.notes.push('No rua= tag — no aggregate reports are being requested, so this tool receives no data for the domain.')
      }
      if (tags.pct && Number(tags.pct) < 100 && policy !== 'none') {
        results.dmarc.notes.push(`pct=${tags.pct}: policy only applies to ${tags.pct}% of failing mail.`)
      }
    }
  } catch (e) {
    results.dmarc.notes.push(`DMARC lookup failed: ${String(e)}`)
  }

  // ---- DKIM ----
  // Probe observed signers at their actual signing domain (a signature by
  // d=mail.example.com lives at selector._domainkey.mail.example.com), plus
  // common default selectors at the domain itself.
  const observedProbes: DkimProbe[] = observedSigners
    .map((s) => ({ selector: s.selector.toLowerCase(), signing_domain: s.signing_domain.toLowerCase() }))
    .filter((s) => s.selector && s.signing_domain)
  const seen = new Set(observedProbes.map((p) => `${p.selector}@${p.signing_domain}`))
  const defaultProbes: DkimProbe[] = COMMON_DKIM_SELECTORS
    .filter((sel) => !seen.has(`${sel}@${domain}`))
    .map((sel) => ({ selector: sel, signing_domain: domain }))
  const toProbe = [...observedProbes, ...defaultProbes].slice(0, 14)
  const observedKeys = new Set(observedProbes.map((p) => `${p.selector}@${p.signing_domain}`))

  results.dkim.selectors = await Promise.all(
    toProbe.map(async (probe) => {
      let found = false
      try {
        const txts = await txtRecords(`${probe.selector}._domainkey.${probe.signing_domain}`)
        // A key record with an empty p= is a revoked key (RFC 6376 §3.6.1).
        found = (txts || []).some((t) => /(^|;)\s*p=\s*[A-Za-z0-9+/]/.test(t))
      } catch {
        // timeout / SERVFAIL: reported as not found
      }
      return {
        selector: probe.selector,
        signing_domain: probe.signing_domain === domain ? undefined : probe.signing_domain,
        found,
        observed: observedKeys.has(`${probe.selector}@${probe.signing_domain}`),
      }
    })
  )
  const foundAny = results.dkim.selectors.some((s) => s.found)
  const observedMissing = results.dkim.selectors.filter((s) => s.observed && !s.found)
  if (!foundAny) {
    results.dkim.status = 'fail'
    results.dkim.notes.push('No DKIM public keys found on any probed selector.')
  } else if (observedMissing.length > 0) {
    results.dkim.status = 'warn'
    results.dkim.notes.push(
      `Selector(s) seen in reports but missing from DNS: ${observedMissing.map((s) => s.selector).join(', ')} — possibly rotated out or a signer misconfiguration.`
    )
  } else {
    results.dkim.status = 'ok'
  }
  if (observedProbes.length === 0) {
    results.dkim.notes.push('No aligned DKIM signers observed in reports yet; probed common default selectors only.')
  }

  return results
}
