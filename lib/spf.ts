// SPF expansion and IP attribution.
//
// expandSpf() recursively resolves a domain's SPF record (include:, a, mx,
// ip4:, ip6:, redirect=) into a flat list of CIDR networks, each annotated
// with the mechanism chain that authorized it (e.g. "include:_spf.google.com").
// matchIpInNetworks() then answers "is this sending IP authorized, and via
// which include?" — which turns a DMARC failure into a diagnosis.

import { createDnsClient, isNoRecord, type DnsClient } from './dns-resolver'

export type SpfNetwork = {
  cidr: string
  via: string // mechanism chain, e.g. "include:_spf.google.com > ip4"
}

export type SpfExpansion = {
  expanded_at: string
  has_spf: boolean
  networks: SpfNetwork[]
  lookups: number
  notes: string[]
  // True when a lookup timed out or failed (as opposed to "no such record"),
  // or the time budget ran out: `networks` may be missing ranges, so an IP
  // that matches nothing is "unknown", not "unauthorized". (Absent on
  // expansions stored by versions before this field existed.)
  incomplete?: boolean
}

// The DNS calls expandSpf makes; replaceable in tests.
export type SpfResolver = DnsClient

const MAX_LOOKUPS = 10
const TIMEOUT_MS = 12_000
// The record being walked is untrusted (anyone can publish an include tree),
// so the whole expansion is bounded, not just each query.
const TOTAL_BUDGET_MS = 20_000

// Hard cap per query on top of the resolver's own timeout and retries.
function withTimeout<T>(p: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('DNS timeout')), TIMEOUT_MS)
    }),
  ]).finally(() => clearTimeout(timer))
}

// RFC 7208 §4.5: the record starts with exactly "v=spf1", followed by a
// space or nothing ("v=spf10" is some other record).
export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt)
}

// [addr, prefix] for a syntactically valid CIDR, else null.
function parseCidr(cidr: string, family: 4 | 6): [string, number] | null {
  const m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(cidr)
  if (!m) return null
  const max = family === 4 ? 32 : 128
  const prefix = m[2] === undefined ? max : Number(m[2])
  if (prefix > max) return null
  const valid = family === 4 ? ipv4ToInt(m[1]) != null : m[1].includes(':') && ipv6ToBigInt(m[1]) != null
  return valid ? [m[1], prefix] : null
}

export async function expandSpf(
  domain: string,
  opts: { resolver?: SpfResolver; budgetMs?: number } = {}
): Promise<SpfExpansion> {
  const dns: SpfResolver = opts.resolver ?? createDnsClient()
  const deadline = Date.now() + (opts.budgetMs ?? TOTAL_BUDGET_MS)
  const result: SpfExpansion = {
    expanded_at: new Date().toISOString(),
    has_spf: false,
    networks: [],
    lookups: 0,
    notes: [],
    incomplete: false,
  }
  const visited = new Set<string>()

  function failed(what: string): void {
    result.incomplete = true
    if (result.notes.length < 20) result.notes.push(`${what} could not be resolved (DNS timeout or server failure).`)
  }

  let budgetNoted = false
  function outOfTime(): boolean {
    if (Date.now() < deadline) return false
    if (!budgetNoted) result.notes.push('Time budget for SPF expansion reached; the result is partial.')
    budgetNoted = true
    result.incomplete = true
    return true
  }

  // null = lookup failed (already recorded); [] = no such record.
  async function txt(name: string): Promise<string[] | null> {
    try {
      return (await withTimeout(dns.resolveTxt(name))).map((parts) => parts.join(''))
    } catch (e) {
      if (isNoRecord(e)) return []
      failed(`TXT ${name}`)
      return null
    }
  }

  async function addresses(name: string): Promise<string[]> {
    const out: string[] = []
    for (const [label, lookup] of [['A', dns.resolve4], ['AAAA', dns.resolve6]] as const) {
      try {
        out.push(...(await withTimeout(lookup(name))))
      } catch (e) {
        if (!isNoRecord(e)) failed(`${label} ${name}`)
      }
    }
    return out
  }

  async function walk(target: string, via: string[], path: Set<string>): Promise<void> {
    if (outOfTime()) return
    const key = target.toLowerCase()
    if (path.has(key)) {
      result.notes.push(`SPF include cycle detected at ${target}; skipped.`)
      return
    }
    // Same include reachable via two different paths: already expanded, skip
    // silently — its networks are in the result once.
    if (visited.has(key)) return
    visited.add(key)
    path = new Set(path).add(key)

    const txts = await txt(target)
    if (txts === null) return // unknown, not "no SPF record"
    const spf = txts.find(isSpfRecord)
    if (!spf) {
      if (via.length === 0) return
      result.notes.push(`${target} (referenced via ${via.join(' > ')}) has no SPF record.`)
      return
    }
    if (via.length === 0) result.has_spf = true

    const terms = spf.split(/\s+/).slice(1)
    // redirect= only applies when nothing else matched, which cannot happen
    // in a record that has an "all" mechanism (RFC 7208 §6.1).
    const hasAll = terms.some((t) => /^[+\-~?]?all$/i.test(t))
    for (const rawTerm of terms) {
      // Strip qualifiers; a "-"/"~"/"?" prefixed mechanism still declares the
      // network — we only care about attribution, not pass/fail semantics.
      // Mechanism names are case-insensitive (RFC 7208 §4.6.1); only the
      // name is lower-cased, the domain-spec is passed to DNS as written.
      const stripped = rawTerm.replace(/^[+\-~?]/, '')
      const nameEnd = stripped.search(/[:=/]/)
      const term =
        nameEnd === -1 ? stripped.toLowerCase() : stripped.slice(0, nameEnd).toLowerCase() + stripped.slice(nameEnd)
      const viaLabel = via.length > 0 ? via.join(' > ') : 'top-level'

      if (outOfTime()) return
      if (term.startsWith('ip4:') || term.startsWith('ip6:')) {
        const cidr = term.slice(4)
        // Published records contain typos; a malformed range must not reach
        // the matcher (or anything else that reads the stored expansion).
        if (parseCidr(cidr, term.startsWith('ip4:') ? 4 : 6)) {
          result.networks.push({ cidr, via: viaLabel })
        } else if (result.notes.length < 20) {
          result.notes.push(`Ignored malformed mechanism "${term.slice(0, 80)}" (${viaLabel}).`)
        }
      } else if (term.startsWith('include:')) {
        if (++result.lookups > MAX_LOOKUPS) {
          result.notes.push(`Lookup limit (${MAX_LOOKUPS}) reached; expansion truncated at ${term}.`)
          return
        }
        await walk(term.slice(8), [...via, term], path)
      } else if (term.startsWith('redirect=')) {
        if (hasAll) continue
        if (++result.lookups > MAX_LOOKUPS) {
          result.notes.push(`Lookup limit (${MAX_LOOKUPS}) reached; expansion truncated at ${term}.`)
          return
        }
        await walk(term.slice(9), [...via, term], path)
      } else if (term === 'a' || term.startsWith('a:') || term.startsWith('a/')) {
        if (++result.lookups > MAX_LOOKUPS) continue
        const [hostPart, prefixes] = parseHostPrefix(term.slice(1), target)
        for (const ip of await addresses(hostPart)) {
          result.networks.push({ cidr: applyPrefix(ip, prefixes), via: `${viaLabel} > a` })
        }
      } else if (term === 'mx' || term.startsWith('mx:') || term.startsWith('mx/')) {
        if (++result.lookups > MAX_LOOKUPS) continue
        const [hostPart, prefixes] = parseHostPrefix(term.slice(2), target)
        try {
          const mxs = await withTimeout(dns.resolveMx(hostPart))
          for (const mx of mxs.slice(0, 10)) {
            if (outOfTime()) return
            for (const ip of await addresses(mx.exchange)) {
              result.networks.push({ cidr: applyPrefix(ip, prefixes), via: `${viaLabel} > mx:${mx.exchange}` })
            }
          }
        } catch (e) {
          if (!isNoRecord(e)) failed(`MX ${hostPart}`)
        }
      } else if (term.startsWith('exists:') || term === 'ptr' || term.startsWith('ptr:')) {
        // Not expanded, but a receiver still spends one of its 10 lookups on it.
        result.lookups++
        result.notes.push(`Mechanism "${term}" cannot be expanded to IP ranges; ignored for attribution.`)
      }
      // "all" and modifiers: nothing to expand
    }
  }

  await walk(domain, [], new Set())
  // Hostnames resolved via a / mx can repeat; keep each network once.
  const seen = new Set<string>()
  result.networks = result.networks.filter((n) => {
    const k = `${n.cidr}|${n.via}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  return result
}

type Prefixes = { v4: number | null; v6: number | null }

function parseHostPrefix(rest: string, defaultHost: string): [string, Prefixes] {
  // rest is like "", ":host", ":host/24", "/24", "/24//64", "//64"
  // (RFC 7208 §5.3 dual-cidr-length: "/<ip4 bits>" then "//<ip6 bits>").
  let s = rest.startsWith(':') ? rest.slice(1) : rest
  const prefixes: Prefixes = { v4: null, v6: null }
  const slash = s.indexOf('/')
  if (slash !== -1) {
    const [v4, v6] = s.slice(slash + 1).split('//')
    const bits = (raw: string | undefined, max: number): number | null =>
      raw && /^\d{1,3}$/.test(raw) && Number(raw) <= max ? Number(raw) : null
    prefixes.v4 = bits(v4, 32)
    prefixes.v6 = bits(v6, 128)
    s = s.slice(0, slash)
  }
  return [s || defaultHost, prefixes]
}

function applyPrefix(ip: string, prefixes: Prefixes): string {
  const prefix = ip.includes(':') ? prefixes.v6 : prefixes.v4
  return prefix == null ? ip : `${ip}/${prefix}`
}

// ---------- IP matching ----------

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const p of parts) {
    const n = Number(p)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = out * 256 + n
  }
  return out
}

function ipv6ToBigInt(ip: string): bigint | null {
  // Handle "::" expansion; reject embedded IPv4 for simplicity (rare in SPF).
  const doubleColon = ip.indexOf('::')
  let head: string[] = []
  let tail: string[] = []
  if (doubleColon !== -1) {
    head = ip.slice(0, doubleColon).split(':').filter(Boolean)
    tail = ip.slice(doubleColon + 2).split(':').filter(Boolean)
  } else {
    head = ip.split(':')
    if (head.length !== 8) return null
  }
  const missing = 8 - head.length - tail.length
  if (missing < 0) return null
  const groups = [...head, ...Array(missing).fill('0'), ...tail]
  if (groups.length !== 8) return null
  let out = 0n
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null
    out = (out << 16n) | BigInt(Number.parseInt(g, 16))
  }
  return out
}

export function matchIpInNetworks(ip: string, networks: SpfNetwork[]): SpfNetwork | null {
  const isV6 = ip.includes(':')
  const ipV4 = isV6 ? null : ipv4ToInt(ip)
  const ipV6 = isV6 ? ipv6ToBigInt(ip) : null
  if (ipV4 == null && ipV6 == null) return null

  for (const net of networks) {
    // Stored expansions are data: anything malformed is skipped, never thrown on.
    if (typeof net?.cidr !== 'string') continue
    const parsed = parseCidr(net.cidr, isV6 ? 6 : 4)
    if (!parsed) continue
    const [addr, prefix] = parsed

    if (!isV6) {
      const netInt = ipv4ToInt(addr)!
      const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
      if (((ipV4! & mask) >>> 0) === ((netInt & mask) >>> 0)) return net
    } else {
      const shift = BigInt(128 - prefix)
      if (ipV6! >> shift === ipv6ToBigInt(addr)! >> shift) return net
    }
  }
  return null
}
