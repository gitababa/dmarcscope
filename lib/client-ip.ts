// The client's address, for per-address rate limits and the audit log.
//
// The app only sees request headers, and Next.js keeps an X-Forwarded-For a
// client sends itself. So the address is only as trustworthy as the proxy in
// front: CLIENT_IP_HEADER names the header that proxy sets (default
// x-forwarded-for, of which the last entry is used: the one the nearest
// proxy appended). Per-account lockout never depends on it.

import { isIP } from 'node:net'
import type { Env } from './config'

type HeaderBag = { get(name: string): string | null }

export function clientIp(headers: HeaderBag, env: Env = process.env): string | null {
  const name = (env.CLIENT_IP_HEADER?.trim() || 'x-forwarded-for').toLowerCase()
  const raw = headers.get(name)
  if (!raw) return null
  const parts = raw.split(',').map((p) => p.trim()).filter(Boolean)
  let candidate = parts[parts.length - 1] ?? ''
  // [2001:db8::1]:1234 and 192.0.2.1:1234 forms
  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(candidate)
  if (bracket) candidate = bracket[1]
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(candidate)) candidate = candidate.slice(0, candidate.lastIndexOf(':'))
  if (candidate.startsWith('::ffff:') && isIP(candidate.slice(7)) === 4) candidate = candidate.slice(7)
  return isIP(candidate) ? candidate.toLowerCase() : null
}
