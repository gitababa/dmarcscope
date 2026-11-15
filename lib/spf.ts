// SPF expansion and IP attribution.
//
// expandSpf() recursively resolves a domain's SPF record (include:, a, mx,
// ip4:, ip6:, redirect=) into a flat list of CIDR networks, each annotated
// with the mechanism chain that authorized it (e.g. "include:_spf.google.com").
// matchIpInNetworks() then answers "is this sending IP authorized, and via
// which include?" — which turns a DMARC failure into a diagnosis.

import { resolveTxt, resolveMx, resolve4, resolve6 } from 'node:dns/promises'

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
}

const MAX_LOOKUPS = 10
const TIMEOUT_MS = 4000

function withTimeout<T>(p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), TIMEOUT_MS)),
  ])
}

async function safeTxt(name: string): Promise<string[]> {
  try {
    const chunks = await withTimeout(resolveTxt(name))
    return chunks.map((parts) => parts.join(''))
  } catch {
    return []
  }
}

async function safeA(name: string): Promise<string[]> {
  const out: string[] = []
  try {
    out.push(...(await withTimeout(resolve4(name))))
  } catch {
    /* no A records */
  }
  try {
    out.push(...(await withTimeout(resolve6(name))))
  } catch {
    /* no AAAA records */
  }
  return out
}

export async function expandSpf(domain: string): Promise<SpfExpansion> {
  const result: SpfExpansion = {
    expanded_at: new Date().toISOString(),
    has_spf: false,
    networks: [],
    lookups: 0,
    notes: [],
  }
  const visited = new Set<string>()

  async function walk(target: string, via: string[], path: Set<string>): Promise<void> {
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

    const txts = await safeTxt(target)
    const spf = txts.find((t) => t.toLowerCase().startsWith('v=spf1'))
    if (!spf) {
      if (via.length === 0) return
      result.notes.push(`${target} (referenced via ${via.join(' > ')}) has no SPF record.`)
      return
    }
    if (via.length === 0) result.has_spf = true

    const terms = spf.split(/\s+/).slice(1)
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

      if (term.startsWith('ip4:') || term.startsWith('ip6:')) {
        const cidr = term.slice(4)
        result.networks.push({ cidr, via: viaLabel })
      } else if (term.startsWith('include:')) {
        if (++result.lookups > MAX_LOOKUPS) {
          result.notes.push(`Lookup limit (${MAX_LOOKUPS}) reached; expansion truncated at ${term}.`)
          return
        }
        await walk(term.slice(8), [...via, term], path)
      } else if (term.startsWith('redirect=')) {
        if (++result.lookups > MAX_LOOKUPS) {
          result.notes.push(`Lookup limit (${MAX_LOOKUPS}) reached; expansion truncated at ${term}.`)
          return
        }
        await walk(term.slice(9), [...via, term], path)
      } else if (term === 'a' || term.startsWith('a:') || term.startsWith('a/')) {
        if (++result.lookups > MAX_LOOKUPS) continue
        const [hostPart, prefix] = parseHostPrefix(term.slice(1), target)
        for (const ip of await safeA(hostPart)) {
          result.networks.push({ cidr: applyPrefix(ip, prefix), via: `${viaLabel} > a` })
        }
      } else if (term === 'mx' || term.startsWith('mx:') || term.startsWith('mx/')) {
        if (++result.lookups > MAX_LOOKUPS) continue
        const [hostPart, prefix] = parseHostPrefix(term.slice(2), target)
        try {
          const mxs = await withTimeout(resolveMx(hostPart))
          for (const mx of mxs.slice(0, 10)) {
            for (const ip of await safeA(mx.exchange)) {
              result.networks.push({ cidr: applyPrefix(ip, prefix), via: `${viaLabel} > mx:${mx.exchange}` })
            }
          }
        } catch {
          /* no MX */
        }
      } else if (term.startsWith('exists:') || term.startsWith('ptr')) {
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

function parseHostPrefix(rest: string, defaultHost: string): [string, number | null] {
  // rest is like "", ":host", ":host/24", "/24"
  let host = defaultHost
  let prefix: number | null = null
  let s = rest
  if (s.startsWith(':')) s = s.slice(1)
  const slash = s.indexOf('/')
  if (slash !== -1) {
    prefix = Number.parseInt(s.slice(slash + 1), 10) || null
    s = s.slice(0, slash)
  }
  if (s) host = s
  return [host, prefix]
}

function applyPrefix(ip: string, prefix: number | null): string {
  if (prefix == null) return ip
  return `${ip}/${prefix}`
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
    const [addr, prefixStr] = net.cidr.split('/')
    const netIsV6 = addr.includes(':')
    if (netIsV6 !== isV6) continue

    if (!isV6) {
      const netInt = ipv4ToInt(addr)
      if (netInt == null) continue
      const prefix = prefixStr ? Number.parseInt(prefixStr, 10) : 32
      if (prefix < 0 || prefix > 32) continue
      const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
      if (((ipV4! & mask) >>> 0) === ((netInt & mask) >>> 0)) return net
    } else {
      const netInt = ipv6ToBigInt(addr)
      if (netInt == null) continue
      const prefix = prefixStr ? Number.parseInt(prefixStr, 10) : 128
      if (prefix < 0 || prefix > 128) continue
      const shift = BigInt(128 - prefix)
      if (ipV6! >> shift === netInt >> shift) return net
    }
  }
  return null
}
