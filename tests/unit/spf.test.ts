import { beforeEach, describe, expect, it, vi } from 'vitest'

const records: Record<string, { txt?: string[]; a?: string[]; aaaa?: string[]; mx?: Array<{ exchange: string; priority: number }> }> = {}
const notFound = () => Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' })

vi.mock('node:dns/promises', () => {
  const resolveTxt = vi.fn(async (name: string) => {
    const r = records[name.toLowerCase()]?.txt
    if (!r) throw notFound()
    return r.map((t) => [t])
  })
  const resolve4 = vi.fn(async (name: string) => records[name.toLowerCase()]?.a ?? Promise.reject(notFound()))
  const resolve6 = vi.fn(async (name: string) => records[name.toLowerCase()]?.aaaa ?? Promise.reject(notFound()))
  const resolveMx = vi.fn(async (name: string) => records[name.toLowerCase()]?.mx ?? Promise.reject(notFound()))
  // The default client (lib/dns-resolver.ts) makes a Resolver per query.
  class Resolver {
    setServers() {}
    cancel() {}
    resolveTxt = resolveTxt
    resolve4 = resolve4
    resolve6 = resolve6
    resolveMx = resolveMx
  }
  return { Resolver, resolveTxt, resolve4, resolve6, resolveMx }
})

import { expandSpf, matchIpInNetworks, type SpfResolver } from '@/lib/spf'

beforeEach(() => {
  for (const k of Object.keys(records)) delete records[k]
})

describe('matchIpInNetworks', () => {
  const nets = [
    { cidr: '192.0.2.0/24', via: 'top-level' },
    { cidr: '198.51.100.7', via: 'include:a.example' },
    { cidr: '2001:db8:1::/48', via: 'include:v6.example' },
    { cidr: 'not-an-ip/99', via: 'junk' },
  ]
  it('matches IPv4 by prefix and exact host', () => {
    expect(matchIpInNetworks('192.0.2.200', nets)?.via).toBe('top-level')
    expect(matchIpInNetworks('192.0.3.1', nets)).toBeNull()
    expect(matchIpInNetworks('198.51.100.7', nets)?.via).toBe('include:a.example')
    expect(matchIpInNetworks('198.51.100.8', nets)).toBeNull()
  })
  it('matches IPv6, including :: compression', () => {
    expect(matchIpInNetworks('2001:db8:1:ffff::1', nets)?.via).toBe('include:v6.example')
    expect(matchIpInNetworks('2001:db8:2::1', nets)).toBeNull()
  })
  it('handles /0, the top bit and garbage input', () => {
    expect(matchIpInNetworks('203.0.113.9', [{ cidr: '0.0.0.0/0', via: 'x' }])?.via).toBe('x')
    expect(matchIpInNetworks('200.1.2.3', [{ cidr: '128.0.0.0/1', via: 'x' }])?.via).toBe('x')
    expect(matchIpInNetworks('100.1.2.3', [{ cidr: '128.0.0.0/1', via: 'x' }])).toBeNull()
    expect(matchIpInNetworks('999.1.1.1', nets)).toBeNull()
    expect(matchIpInNetworks('', nets)).toBeNull()
  })
  it('skips malformed stored networks instead of throwing', () => {
    const junk = [
      { cidr: '2001:db8::/abc', via: 'bad prefix' },
      { cidr: '2001:db8::/', via: 'empty prefix' },
      { cidr: '2001:db8::/129', via: 'too long' },
      { cidr: '192.0.2.0/x', via: 'bad v4 prefix' },
      { cidr: '192.0.2.0/24/8', via: 'two prefixes' },
      { via: 'no cidr' } as unknown as { cidr: string; via: string },
      { cidr: '2001:db8::/32', via: 'good v6' },
      { cidr: '192.0.2.0/24', via: 'good v4' },
    ]
    expect(matchIpInNetworks('2001:db8::5', junk)?.via).toBe('good v6')
    expect(matchIpInNetworks('192.0.2.5', junk)?.via).toBe('good v4')
  })
})

describe('expandSpf', () => {
  it('flattens includes, a and mx with their mechanism chain', async () => {
    records['example.com'] = {
      txt: ['unrelated', 'v=spf1 ip4:192.0.2.0/24 Include:_spf.vendor.test a mx:mail.example.com -all'],
      a: ['203.0.113.10'],
    }
    records['_spf.vendor.test'] = { txt: ['v=spf1 ip4:198.51.100.0/25 ip6:2001:db8::/32 ~all'] }
    records['mail.example.com'] = { mx: [{ exchange: 'mx1.example.com', priority: 10 }] }
    records['mx1.example.com'] = { a: ['203.0.113.20'] }

    const r = await expandSpf('example.com')
    expect(r.has_spf).toBe(true)
    expect(r.lookups).toBe(3)
    expect(r.networks).toEqual(
      expect.arrayContaining([
        { cidr: '192.0.2.0/24', via: 'top-level' },
        { cidr: '198.51.100.0/25', via: 'include:_spf.vendor.test' },
        { cidr: '2001:db8::/32', via: 'include:_spf.vendor.test' },
        { cidr: '203.0.113.10', via: 'top-level > a' },
        { cidr: '203.0.113.20', via: 'top-level > mx:mx1.example.com' },
      ])
    )
    expect(matchIpInNetworks('198.51.100.5', r.networks)?.via).toBe('include:_spf.vendor.test')
  })

  it('reports a domain with no SPF record', async () => {
    records['example.com'] = { txt: ['google-site-verification=abc'] }
    const r = await expandSpf('example.com')
    expect(r.has_spf).toBe(false)
    expect(r.networks).toEqual([])
  })

  it('survives include cycles', async () => {
    records['a.test'] = { txt: ['v=spf1 include:b.test ip4:192.0.2.1 -all'] }
    records['b.test'] = { txt: ['v=spf1 include:a.test ip4:192.0.2.2 -all'] }
    const r = await expandSpf('a.test')
    expect(r.networks.map((n) => n.cidr).sort()).toEqual(['192.0.2.1', '192.0.2.2'])
    expect(r.notes.join(' ')).toMatch(/cycle/)
  })

  it('stops at the RFC limit of 10 lookups and says so', async () => {
    const includes = Array.from({ length: 12 }, (_, i) => `include:s${i}.test`).join(' ')
    records['big.test'] = { txt: [`v=spf1 ${includes} -all`] }
    for (let i = 0; i < 12; i++) records[`s${i}.test`] = { txt: [`v=spf1 ip4:10.0.${i}.0/24 -all`] }
    const r = await expandSpf('big.test')
    expect(r.lookups).toBeGreaterThan(10)
    expect(r.networks).toHaveLength(10)
    expect(r.notes.join(' ')).toMatch(/Lookup limit/)
  })

  it('drops malformed ranges instead of storing them', async () => {
    records['typo.test'] = { txt: ['v=spf1 ip6:2001:db8::/abc ip4:192.0.2.0/33 ip4:not-an-ip ip6:2001:db8::/200 ip4:192.0.2.7 -all'] }
    const r = await expandSpf('typo.test')
    expect(r.networks).toEqual([{ cidr: '192.0.2.7', via: 'top-level' }])
    expect(r.notes.filter((n) => /malformed/.test(n))).toHaveLength(4)
    expect(r.incomplete).toBe(false)
  })

  it('applies a/NN to IPv4 and //NN to IPv6 addresses only', async () => {
    records['dual.test'] = { txt: ['v=spf1 a/24//64 a:only4.test/28 -all'], a: ['203.0.113.10'], aaaa: ['2001:db8::1'] }
    records['only4.test'] = { a: ['198.51.100.9'], aaaa: ['2001:db8:1::1'] }
    const r = await expandSpf('dual.test')
    expect(r.networks.map((n) => n.cidr).sort()).toEqual(['198.51.100.9/28', '2001:db8:1::1', '2001:db8::1/64', '203.0.113.10/24'])
  })

  const servfail = () => Object.assign(new Error('SERVFAIL'), { code: 'ESERVFAIL' })
  const resolver = (over: Partial<SpfResolver>): SpfResolver => ({
    resolveTxt: async (name) => {
      const r = records[name.toLowerCase()]?.txt
      if (!r) throw notFound()
      return r.map((t) => [t])
    },
    resolveMx: async () => Promise.reject(notFound()),
    resolve4: async () => Promise.reject(notFound()),
    resolve6: async () => Promise.reject(notFound()),
    ...over,
  })

  it('a failed lookup of the record itself is "unknown", not "no SPF"', async () => {
    const r = await expandSpf('down.test', { resolver: resolver({ resolveTxt: async () => Promise.reject(servfail()) }) })
    expect(r.has_spf).toBe(false)
    expect(r.incomplete).toBe(true)
    expect(r.notes.join(' ')).toMatch(/TXT down\.test could not be resolved/)
  })

  it('a failed include marks the expansion incomplete and keeps the rest', async () => {
    records['half.test'] = { txt: ['v=spf1 include:flaky.test ip4:192.0.2.1 a -all'] }
    const base = resolver({})
    const r = await expandSpf('half.test', {
      resolver: resolver({
        resolveTxt: async (name) => (name === 'flaky.test' ? Promise.reject(servfail()) : base.resolveTxt(name)),
        resolve4: async () => Promise.reject(servfail()),
      }),
    })
    expect(r.has_spf).toBe(true)
    expect(r.incomplete).toBe(true)
    expect(r.networks).toEqual([{ cidr: '192.0.2.1', via: 'top-level' }])
    // "does not exist" is an answer, not a failure
    expect(r.notes.join(' ')).not.toMatch(/AAAA/)
  })

  it('stops when the time budget is spent', async () => {
    records['slow.test'] = { txt: ['v=spf1 include:a.slow.test include:b.slow.test -all'] }
    records['a.slow.test'] = { txt: ['v=spf1 ip4:192.0.2.1 -all'] }
    records['b.slow.test'] = { txt: ['v=spf1 ip4:192.0.2.2 -all'] }
    const r = await expandSpf('slow.test', { budgetMs: -1 })
    expect(r.networks).toEqual([])
    expect(r.incomplete).toBe(true)
    expect(r.notes.join(' ')).toMatch(/Time budget/)
  })

  it('ignores redirect= when the record has an "all", and counts ptr / exists as lookups', async () => {
    records['both.test'] = { txt: ['v=spf1 ip4:192.0.2.1 exists:%{i}.bl.test ptr ptr:other.test -all redirect=_spf.both.test'] }
    records['_spf.both.test'] = { txt: ['v=spf1 ip4:203.0.113.0/24 -all'] }
    const r = await expandSpf('both.test')
    expect(r.networks).toEqual([{ cidr: '192.0.2.1', via: 'top-level' }])
    expect(r.lookups).toBe(3)
  })

  it('follows redirect=', async () => {
    records['r.test'] = { txt: ['v=spf1 redirect=_spf.r.test'] }
    records['_spf.r.test'] = { txt: ['v=spf1 ip4:192.0.2.99 -all'] }
    const r = await expandSpf('r.test')
    expect(r.networks).toEqual([{ cidr: '192.0.2.99', via: 'redirect=_spf.r.test' }])
  })
})
