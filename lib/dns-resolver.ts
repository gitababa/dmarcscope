// The one place DNS queries are made from (DNS checks, SPF expansion, the
// MTA-STS policy host). Every query goes through a node:dns Resolver with its
// own per-attempt timeout and retries, so a single dropped UDP packet is
// retried rather than failing a check, and a dead server gives up in bounded
// time. A hard deadline on top cancels the query if the resolver itself hangs.
//
// Which servers are asked: the dns.servers setting (DNS_SERVERS), or the
// host's own resolver configuration when that is unset.

import { Resolver } from 'node:dns/promises'
import net from 'node:net'

export type DnsClient = {
  resolveTxt(name: string): Promise<string[][]>
  resolveMx(name: string): Promise<Array<{ exchange: string; priority: number }>>
  resolve4(name: string): Promise<string[]>
  resolve6(name: string): Promise<string[]>
}

// Per attempt; c-ares backs off on each retry. With TRIES = 2 a dead server
// costs about 7.5 s before the next one is tried.
const ATTEMPT_TIMEOUT_MS = 2500
const TRIES = 2
// Whatever the resolver does, no single query is waited on longer than this.
const HARD_DEADLINE_MS = 12_000

export const MAX_DNS_SERVERS = 4

// "The name exists but has no such record" and "the name does not exist" are
// answers. Everything else (timeout, SERVFAIL, refused) is a failed lookup.
export function isNoRecord(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException | null)?.code
  return code === 'ENOTFOUND' || code === 'ENODATA'
}

type Parsed = { ok: true; value: string } | { ok: false; error: string }

const SERVERS_ERROR = `must be 1 to ${MAX_DNS_SERVERS} IP addresses, optionally with a port (1.1.1.1, 9.9.9.9:53, [2620:fe::fe]:53), separated by commas`

// One server: "1.1.1.1", "1.1.1.1:53", "2606:4700::1111" or
// "[2606:4700::1111]:53". Returns the form node's setServers accepts, with
// the default port left off.
function normalizeServer(raw: string): string | null {
  let host = raw
  let port: string | null = null
  const bracketed = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(raw)
  if (bracketed) {
    host = bracketed[1]
    port = bracketed[2] ?? null
    if (!net.isIPv6(host)) return null
  } else if (net.isIPv6(raw)) {
    host = raw
  } else {
    const v4 = /^([^:]+)(?::(\d{1,5}))?$/.exec(raw)
    if (!v4 || !net.isIPv4(v4[1])) return null
    host = v4[1]
    port = v4[2] ?? null
  }
  if (port !== null && (Number(port) < 1 || Number(port) > 65535)) return null
  const v6 = net.isIPv6(host)
  if (port === null || port === '53') return v6 ? host.toLowerCase() : host
  return v6 ? `[${host.toLowerCase()}]:${Number(port)}` : `${host}:${Number(port)}`
}

// Validates the setting: a list of resolver addresses. Host names are not
// accepted, since resolving them would need a resolver first.
export function parseDnsServers(raw: unknown): Parsed {
  const text = typeof raw === 'string' ? raw.trim() : ''
  const parts = text.split(/[\s,]+/).filter(Boolean)
  if (parts.length === 0 || parts.length > MAX_DNS_SERVERS) return { ok: false, error: SERVERS_ERROR }
  const out: string[] = []
  for (const p of parts) {
    const s = normalizeServer(p)
    if (!s) return { ok: false, error: SERVERS_ERROR }
    if (!out.includes(s)) out.push(s)
  }
  return { ok: true, value: out.join(', ') }
}

export function splitDnsServers(value: string | null | undefined): string[] {
  if (!value) return []
  const parsed = parseDnsServers(value)
  return parsed.ok ? parsed.value.split(', ') : []
}

function withDeadline<T>(p: Promise<T>, cancel: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        cancel()
        reject(Object.assign(new Error('DNS timeout'), { code: 'ETIMEOUT' }))
      }, HARD_DEADLINE_MS)
    }),
  ]).finally(() => clearTimeout(timer))
}

// A client asking `servers`, or the system's configured resolvers when the
// list is empty. Each query gets its own Resolver so the hard deadline can
// cancel exactly that query.
export function createDnsClient(servers: readonly string[] = [], limits: { timeoutMs?: number; tries?: number } = {}): DnsClient {
  function make(): Resolver {
    const r = new Resolver({ timeout: limits.timeoutMs ?? ATTEMPT_TIMEOUT_MS, tries: limits.tries ?? TRIES })
    if (servers.length > 0) r.setServers([...servers])
    return r
  }
  function run<T>(query: (r: Resolver) => Promise<T>): Promise<T> {
    const r = make()
    return withDeadline(query(r), () => r.cancel())
  }
  return {
    resolveTxt: (name) => run((r) => r.resolveTxt(name)),
    resolveMx: (name) => run((r) => r.resolveMx(name)),
    resolve4: (name) => run((r) => r.resolve4(name)),
    resolve6: (name) => run((r) => r.resolve6(name)),
  }
}

// The servers configured in the panel or the environment ([] = the system's).
// A settings store that cannot be read falls back to the system resolver
// rather than failing the check.
export async function configuredDnsServers(): Promise<string[]> {
  try {
    const { configStore } = await import('./settings')
    return splitDnsServers((await configStore().get('dns.servers')) as string | null)
  } catch (err) {
    console.error('[dns] could not read dns.servers, using the system resolver:', err instanceof Error ? err.message : String(err))
    return []
  }
}
