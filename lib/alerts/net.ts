// Outbound requests for webhook and Slack-compatible channels. The rules,
// applied on every delivery and not only when a channel is saved:
//   - https only (http only when an owner allows private destinations);
//   - redirects are never followed: any 3xx is a failure;
//   - the host name is resolved first and the connection is made to that very
//     address, so a name cannot answer differently for the check and for the
//     connection (DNS rebinding);
//   - loopback, private, link-local, unique-local, CGNAT, multicast,
//     unspecified and IPv4-mapped forms of those are refused unless allowed;
//   - 10 s timeout, and the response body is read to at most 4 KB and dropped.

import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'

export class DestinationRefused extends Error {}

const FORBIDDEN_V4: Array<[number, number]> = [
  [0x00000000, 8], // this network
  [0x0a000000, 8], // 10/8
  [0x64400000, 10], // 100.64/10 CGNAT
  [0x7f000000, 8], // loopback
  [0xa9fe0000, 16], // link-local, including 169.254.169.254
  [0xac100000, 12], // 172.16/12
  [0xc0000000, 24], // 192.0.0/24
  [0xc0a80000, 16], // 192.168/16
  [0xc6120000, 15], // 198.18/15 benchmarking
  [0xe0000000, 4], // multicast
  [0xf0000000, 4], // reserved and broadcast
]

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((n, part) => n * 256 + Number(part), 0)
}

function expandV6(ip: string): number[] | null {
  let s = ip.toLowerCase().split('%')[0]
  const tail = s.match(/(\d+\.\d+\.\d+\.\d+)$/)
  if (tail) {
    const n = v4ToInt(tail[1])
    s = s.slice(0, -tail[1].length) + ((n >>> 16) & 0xffff).toString(16) + ':' + (n & 0xffff).toString(16)
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null
  const groups = [...head, ...Array(fill).fill('0'), ...rest].map((g) => parseInt(g, 16))
  return groups.length === 8 && groups.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff) ? groups : null
}

// True when the address is one a webhook must not reach by default. An
// address that cannot be parsed is treated as forbidden.
export function isForbiddenAddress(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const n = v4ToInt(ip)
    return FORBIDDEN_V4.some(([base, bits]) => n >>> (32 - bits) === base >>> (32 - bits))
  }
  if (net.isIPv6(ip)) {
    const g = expandV6(ip)
    if (!g) return true
    const allZeroHead = g.slice(0, 5).every((x) => x === 0)
    // ::, ::1, ::ffff:a.b.c.d (mapped), ::a.b.c.d (compatible), 64:ff9b::/96 (NAT64)
    if (g.slice(0, 7).every((x) => x === 0) && g[7] <= 1) return true
    if (allZeroHead && (g[5] === 0xffff || g[5] === 0)) return isForbiddenAddress(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`)
    if (g[0] === 0x64 && g[1] === 0xff9b) return isForbiddenAddress(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`)
    if ((g[0] & 0xfe00) === 0xfc00) return true // fc00::/7 unique local
    if ((g[0] & 0xffc0) === 0xfe80) return true // fe80::/10 link-local
    if ((g[0] & 0xff00) === 0xff00) return true // multicast
    if (g[0] === 0x2001 && g[1] === 0x0db8) return true // documentation
    return false
  }
  return true
}

export type Resolver = (host: string) => Promise<string[]>

const systemResolver: Resolver = async (host) => (await dns.promises.lookup(host, { all: true, verbatim: true })).map((a) => a.address)

export type Destination = { url: URL; address: string }

// Validates the URL and resolves it once; the caller connects to `address`.
export async function resolveDestination(
  rawUrl: string,
  opts: { allowPrivate: boolean; resolve?: Resolver }
): Promise<Destination> {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new DestinationRefused('the address is not a valid URL')
  }
  if (url.protocol !== 'https:' && !(opts.allowPrivate && url.protocol === 'http:')) throw new DestinationRefused('the address must start with https://')
  if (url.username || url.password) throw new DestinationRefused('the address must not contain a user name or password')
  const host = url.hostname.replace(/^\[|\]$/g, '')
  const resolve = opts.resolve ?? systemResolver
  const addresses = net.isIP(host) ? [host] : await resolve(host).catch(() => [])
  if (addresses.length === 0) throw new DestinationRefused('the host name did not resolve')
  // One forbidden answer refuses the destination: the connection must not be
  // able to fall back to it.
  if (!opts.allowPrivate && addresses.some(isForbiddenAddress)) throw new DestinationRefused('the address points to a private or internal network')
  return { url, address: addresses[0] }
}

export type PostResult = { status: number }

const BODY_LIMIT = 4096
const TIMEOUT_MS = 10_000

// POSTs a body to the destination at its pinned address. Resolves with the
// status; rejects on a network error, a timeout or any redirect.
export function post(dest: Destination, body: string, headers: Record<string, string>, opts: { rejectUnauthorized?: boolean } = {}): Promise<PostResult> {
  const lib = dest.url.protocol === 'https:' ? https : http
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        method: 'POST',
        host: dest.address,
        port: dest.url.port || (dest.url.protocol === 'https:' ? 443 : 80),
        path: `${dest.url.pathname}${dest.url.search}`,
        servername: net.isIP(dest.url.hostname.replace(/^\[|\]$/g, '')) ? undefined : dest.url.hostname,
        headers: { ...headers, Host: dest.url.host, 'Content-Length': String(Buffer.byteLength(body)), 'User-Agent': 'DMARCscope-alerts' },
        timeout: TIMEOUT_MS,
        rejectUnauthorized: opts.rejectUnauthorized ?? true,
      },
      (res) => {
        let seen = 0
        res.on('data', (chunk: Buffer) => {
          seen += chunk.length
          if (seen > BODY_LIMIT) res.destroy()
        })
        const status = res.statusCode ?? 0
        const finish = () => (status >= 300 && status < 400 ? reject(new Error(`the server answered with a redirect (${status}), which is never followed`)) : resolve({ status }))
        res.on('end', finish)
        res.on('close', finish)
        res.on('error', () => finish())
      }
    )
    req.on('timeout', () => req.destroy(new Error('the request timed out')))
    req.on('error', reject)
    req.end(body)
  })
}

export type GetResult = { status: number; contentType: string; body: string; truncated: boolean }

// GETs a small text document from the destination at its pinned address, with
// the same rules as post(): no redirects (a 3xx is returned as its status,
// not followed), certificate always verified, bounded time and size.
export function getText(dest: Destination, opts: { limit: number; timeoutMs: number; userAgent: string }): Promise<GetResult> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: 'GET',
        host: dest.address,
        port: dest.url.port || 443,
        path: `${dest.url.pathname}${dest.url.search}`,
        servername: net.isIP(dest.url.hostname.replace(/^\[|\]$/g, '')) ? undefined : dest.url.hostname,
        headers: { Host: dest.url.host, 'User-Agent': opts.userAgent, Accept: 'text/plain' },
        timeout: opts.timeoutMs,
        rejectUnauthorized: true,
      },
      (res) => {
        const chunks: Buffer[] = []
        let seen = 0
        let truncated = false
        let settled = false
        const finish = () => {
          if (settled) return
          settled = true
          resolve({
            status: res.statusCode ?? 0,
            contentType: String(res.headers['content-type'] ?? ''),
            body: Buffer.concat(chunks).toString('utf8'),
            truncated,
          })
        }
        res.on('data', (chunk: Buffer) => {
          if (truncated) return
          seen += chunk.length
          if (seen > opts.limit) {
            truncated = true
            chunks.push(chunk.subarray(0, chunk.length - (seen - opts.limit)))
            res.destroy()
            finish()
            return
          }
          chunks.push(chunk)
        })
        res.on('end', finish)
        res.on('close', finish)
        res.on('error', finish)
      }
    )
    req.on('timeout', () => req.destroy(new Error('the request timed out')))
    req.on('error', reject)
    req.end()
  })
}
