// MTA-STS (RFC 8461): the policy file a domain serves at
// https://mta-sts.<domain>/.well-known/mta-sts.txt, and whether its mx
// patterns cover the domain's MX hosts.

import { DestinationRefused, getText, resolveDestination } from './alerts/net'
import { isNoRecord, type DnsClient } from './dns-resolver'

export type MtaStsPolicy = {
  version: string | null
  mode: string | null
  mx: string[]
  max_age: number | null
}

export type PolicyFetch =
  | { ok: true; text: string; contentType: string }
  | { ok: false; error: string }

// Fetches the policy text; replaceable in tests.
export type PolicyFetcher = (domain: string, dns: DnsClient) => Promise<PolicyFetch>

const MAX_POLICY_BYTES = 64 * 1024 // RFC 8461 §3.3 suggests senders cap at 64 KB
const FETCH_TIMEOUT_MS = 8000

// "key: value" lines, CRLF or LF. Unknown keys are ignored; mx may repeat.
export function parseMtaStsPolicy(text: string): MtaStsPolicy {
  const policy: MtaStsPolicy = { version: null, mode: null, mx: [], max_age: null }
  for (const line of text.split(/\r?\n/)) {
    const colon = line.indexOf(':')
    if (colon === -1) continue
    const key = line.slice(0, colon).trim().toLowerCase()
    const value = line.slice(colon + 1).trim()
    if (key === 'version' && policy.version === null) policy.version = value
    else if (key === 'mode' && policy.mode === null) policy.mode = value
    else if (key === 'mx' && value) policy.mx.push(value.toLowerCase().replace(/\.$/, ''))
    else if (key === 'max_age' && policy.max_age === null && /^\d{1,10}$/.test(value)) policy.max_age = Number(value)
  }
  return policy
}

// RFC 8461 §4.1: a pattern is a host name, or "*." plus a host name, where
// the wildcard stands for exactly one leftmost label.
export function mxMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, '')
  const h = host.toLowerCase().replace(/\.$/, '')
  if (p.startsWith('*.')) {
    const suffix = p.slice(1) // ".example.com"
    if (!h.endsWith(suffix)) return false
    const label = h.slice(0, -suffix.length)
    return label.length > 0 && !label.includes('.')
  }
  return p === h
}

// Resolves the policy host through the configured DNS client, refuses
// private and internal addresses, and fetches with no redirects and a
// verified certificate (which RFC 8461 §3.3 requires of senders too).
export const fetchMtaStsPolicy: PolicyFetcher = async (domain, dns) => {
  const host = `mta-sts.${domain}`
  const resolve = async (name: string): Promise<string[]> => {
    const out: string[] = []
    for (const lookup of [dns.resolve4, dns.resolve6]) {
      try {
        out.push(...(await lookup(name)))
      } catch (e) {
        if (!isNoRecord(e)) throw e
      }
    }
    return out
  }
  let dest
  try {
    dest = await resolveDestination(`https://${host}/.well-known/mta-sts.txt`, { allowPrivate: false, resolve })
  } catch (e) {
    if (e instanceof DestinationRefused) {
      return { ok: false, error: e.message.includes('did not resolve') ? `${host} does not resolve` : `${host}: ${e.message}` }
    }
    return { ok: false, error: `${host} could not be resolved` }
  }
  try {
    const res = await getText(dest, { limit: MAX_POLICY_BYTES, timeoutMs: FETCH_TIMEOUT_MS, userAgent: 'DMARCscope-dns-check' })
    if (res.status >= 300 && res.status < 400) return { ok: false, error: `the policy URL answered with a redirect (${res.status}); senders do not follow redirects` }
    if (res.status !== 200) return { ok: false, error: `the policy URL answered with HTTP ${res.status}` }
    if (res.truncated) return { ok: false, error: 'the policy file is larger than 64 KB' }
    return { ok: true, text: res.body, contentType: res.contentType }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return { ok: false, error: `the policy could not be fetched over HTTPS (${msg.slice(0, 160)})` }
  }
}
