import { beforeEach, describe, expect, it, vi } from 'vitest'

const records: Record<string, { txt?: string[]; a?: string[]; aaaa?: string[]; mx?: Array<{ exchange: string; priority: number }> }> = {}
const notFound = () => Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' })

vi.mock('node:dns/promises', () => ({
  resolveTxt: vi.fn(async (name: string) => {
    const r = records[name.toLowerCase()]?.txt
    if (!r) throw notFound()
    return r.map((t) => [t])
  }),
  resolve4: vi.fn(async (name: string) => records[name.toLowerCase()]?.a ?? Promise.reject(notFound())),
  resolve6: vi.fn(async (name: string) => records[name.toLowerCase()]?.aaaa ?? Promise.reject(notFound())),
  resolveMx: vi.fn(async (name: string) => records[name.toLowerCase()]?.mx ?? Promise.reject(notFound())),
}))

import { expandSpf, matchIpInNetworks } from '@/lib/spf'

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

  it('follows redirect=', async () => {
    records['r.test'] = { txt: ['v=spf1 redirect=_spf.r.test'] }
    records['_spf.r.test'] = { txt: ['v=spf1 ip4:192.0.2.99 -all'] }
    const r = await expandSpf('r.test')
    expect(r.networks).toEqual([{ cidr: '192.0.2.99', via: 'redirect=_spf.r.test' }])
  })
})
