import dgram from 'node:dgram'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createDnsClient, isNoRecord, parseDnsServers, splitDnsServers } from '@/lib/dns-resolver'
import { mxMatches, parseMtaStsPolicy } from '@/lib/mta-sts'

describe('parseDnsServers', () => {
  it('accepts IPv4 and IPv6, with and without ports, and normalizes them', () => {
    expect(parseDnsServers('1.1.1.1, 8.8.8.8')).toEqual({ ok: true, value: '1.1.1.1, 8.8.8.8' })
    expect(parseDnsServers(' 9.9.9.9:53  2620:FE::FE ')).toEqual({ ok: true, value: '9.9.9.9, 2620:fe::fe' })
    expect(parseDnsServers('10.0.0.2:5353,[2001:db8::53]:5353')).toEqual({ ok: true, value: '10.0.0.2:5353, [2001:db8::53]:5353' })
    expect(parseDnsServers('1.1.1.1,1.1.1.1:53')).toEqual({ ok: true, value: '1.1.1.1' })
  })

  it('rejects host names, bad ports, empty input and more than four servers', () => {
    for (const bad of ['', 'dns.google', '1.1.1.1:0', '1.1.1.1:70000', '300.1.1.1', '[1.1.1.1]:53', '1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5', 'http://1.1.1.1']) {
      expect(parseDnsServers(bad).ok, bad).toBe(false)
    }
  })

  it('splits a stored value, and treats an invalid one as the system resolver', () => {
    expect(splitDnsServers('1.1.1.1, [2001:db8::53]:5353')).toEqual(['1.1.1.1', '[2001:db8::53]:5353'])
    expect(splitDnsServers(null)).toEqual([])
    expect(splitDnsServers('not an address')).toEqual([])
  })
})

// A minimal DNS server on 127.0.0.1: TXT for spf.test, NXDOMAIN otherwise.
function answer(query: Buffer): Buffer {
  let i = 12
  const labels: string[] = []
  while (query[i] !== 0) {
    labels.push(query.subarray(i + 1, i + 1 + query[i]).toString())
    i += query[i] + 1
  }
  const question = query.subarray(12, i + 5)
  const name = labels.join('.').toLowerCase()
  const header = Buffer.from(query.subarray(0, 12))
  header[2] = 0x81 // response, recursion desired
  if (name !== 'spf.test') {
    header[3] = 0x83 // recursion available, NXDOMAIN
    header.writeUInt16BE(0, 6)
    return Buffer.concat([header, question])
  }
  header[3] = 0x80
  header.writeUInt16BE(1, 6) // one answer
  const text = Buffer.from('v=spf1 -all')
  const rdata = Buffer.concat([Buffer.from([text.length]), text])
  const rr = Buffer.alloc(12)
  rr.writeUInt16BE(0xc00c, 0) // pointer to the question name
  rr.writeUInt16BE(16, 2) // TXT
  rr.writeUInt16BE(1, 4) // IN
  rr.writeUInt32BE(60, 6)
  rr.writeUInt16BE(rdata.length, 10)
  return Buffer.concat([header, question, rr, rdata])
}

describe('createDnsClient', () => {
  let server: dgram.Socket
  let silent: dgram.Socket
  let port = 0
  let silentPort = 0

  beforeAll(async () => {
    server = dgram.createSocket('udp4')
    server.on('message', (msg, rinfo) => server.send(answer(msg), rinfo.port, rinfo.address))
    silent = dgram.createSocket('udp4') // receives queries, never answers
    await Promise.all([
      new Promise<void>((r) => server.bind(0, '127.0.0.1', () => r())),
      new Promise<void>((r) => silent.bind(0, '127.0.0.1', () => r())),
    ])
    port = server.address().port
    silentPort = silent.address().port
  })
  afterAll(() => {
    server.close()
    silent.close()
  })

  it('asks the configured server on its port', async () => {
    const dns = createDnsClient([`127.0.0.1:${port}`])
    expect(await dns.resolveTxt('spf.test')).toEqual([['v=spf1 -all']])
  })

  it('reports a missing name as "no record"', async () => {
    const dns = createDnsClient([`127.0.0.1:${port}`])
    const err = await dns.resolveTxt('missing.test').catch((e) => e)
    expect(isNoRecord(err)).toBe(true)
  })

  it('gives up on a server that never answers, as a failure rather than "no record"', async () => {
    const dns = createDnsClient([`127.0.0.1:${silentPort}`], { timeoutMs: 100, tries: 1 })
    const started = Date.now()
    const err = await dns.resolveTxt('spf.test').catch((e) => e)
    expect(err).toBeInstanceOf(Error)
    expect(isNoRecord(err)).toBe(false)
    expect(Date.now() - started).toBeLessThan(3000)
  })
})

describe('MTA-STS policy', () => {
  it('parses key: value lines with CRLF or LF and repeated mx', () => {
    expect(parseMtaStsPolicy('version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com.\nmx: *.Example.com\nmax_age: 86400\n')).toEqual({
      version: 'STSv1',
      mode: 'enforce',
      mx: ['mx1.example.com', '*.example.com'],
      max_age: 86400,
    })
  })

  it('matches a wildcard against exactly one leftmost label', () => {
    expect(mxMatches('*.example.com', 'mx1.example.com')).toBe(true)
    expect(mxMatches('*.example.com', 'a.b.example.com')).toBe(false)
    expect(mxMatches('*.example.com', 'example.com')).toBe(false)
    expect(mxMatches('mx.example.com', 'MX.example.com.')).toBe(true)
  })
})
