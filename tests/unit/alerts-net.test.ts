// The outbound rules for webhook and Slack-compatible channels.

import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DestinationRefused, isForbiddenAddress, post, resolveDestination } from '@/lib/alerts/net'

describe('isForbiddenAddress', () => {
  it.each([
    '127.0.0.1', '127.1.2.3', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:7f00:1',
    '::ffff:169.254.169.254', '::ffff:10.0.0.1', '64:ff9b::7f00:1', 'not-an-ip',
  ])('refuses %s', (ip) => expect(isForbiddenAddress(ip)).toBe(true))

  it.each(['8.8.8.8', '93.184.216.34', '172.15.0.1', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'])('allows %s', (ip) =>
    expect(isForbiddenAddress(ip)).toBe(false)
  )
})

describe('resolveDestination', () => {
  const to = (answers: string[]) => async () => answers
  const refuse = (url: string, opts: Parameters<typeof resolveDestination>[1]) => expect(resolveDestination(url, opts)).rejects.toBeInstanceOf(DestinationRefused)

  it('accepts a public https address and returns the resolved address to connect to', async () => {
    const d = await resolveDestination('https://hooks.example.com/x', { allowPrivate: false, resolve: to(['93.184.216.34']) })
    expect(d.address).toBe('93.184.216.34')
  })
  it('refuses http, credentials and unparsable addresses', async () => {
    await refuse('http://hooks.example.com/x', { allowPrivate: false, resolve: to(['93.184.216.34']) })
    await refuse('https://user:pw@hooks.example.com/x', { allowPrivate: false, resolve: to(['93.184.216.34']) })
    await refuse('not a url', { allowPrivate: false })
    await refuse('ftp://hooks.example.com/x', { allowPrivate: true })
  })
  it('refuses literal private, loopback and metadata addresses', async () => {
    for (const u of ['https://127.0.0.1/x', 'https://169.254.169.254/latest', 'https://[::1]/x', 'https://10.1.2.3/x', 'https://[::ffff:127.0.0.1]/x']) {
      await refuse(u, { allowPrivate: false })
    }
  })
  it('refuses a name that resolves to a private address, or to a mix with one', async () => {
    await refuse('https://internal.example.com/x', { allowPrivate: false, resolve: to(['10.0.0.5']) })
    await refuse('https://sneaky.example.com/x', { allowPrivate: false, resolve: to(['93.184.216.34', '127.0.0.1']) })
  })
  it('refuses a name that does not resolve', async () => {
    await refuse('https://nowhere.example.com/x', { allowPrivate: false, resolve: async () => { throw new Error('ENOTFOUND') } })
    await refuse('https://nowhere.example.com/x', { allowPrivate: false, resolve: to([]) })
  })
  it('lets an owner allow private addresses and http', async () => {
    const d = await resolveDestination('http://127.0.0.1:8080/x', { allowPrivate: true })
    expect(d.address).toBe('127.0.0.1')
  })
})

describe('post', () => {
  let server: http.Server
  let base: string
  const seen: Array<{ method?: string; url?: string; headers: http.IncomingHttpHeaders; body: string }> = []

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = ''
      req.on('data', (c) => (body += c))
      req.on('end', () => {
        seen.push({ method: req.method, url: req.url, headers: req.headers, body })
        if (req.url === '/redirect') {
          res.writeHead(302, { Location: 'http://169.254.169.254/' })
          return res.end()
        }
        if (req.url === '/boom') {
          res.writeHead(500)
          return res.end('nope')
        }
        if (req.url === '/huge') {
          res.writeHead(200)
          return res.end('x'.repeat(5_000_000))
        }
        res.writeHead(200)
        res.end('ok')
      })
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  })
  afterAll(() => new Promise<void>((r) => server.close(() => r())))

  const dest = (path: string) => resolveDestination(`${base}${path}`, { allowPrivate: true })

  it('posts the body with the headers and connects to the pinned address', async () => {
    const res = await post(await dest('/hook?a=1'), '{"a":1}', { 'Content-Type': 'application/json', 'X-Test': 'yes' })
    expect(res.status).toBe(200)
    const last = seen[seen.length - 1]
    expect(last).toMatchObject({ method: 'POST', url: '/hook?a=1', body: '{"a":1}' })
    expect(last.headers['x-test']).toBe('yes')
  })
  it('never follows a redirect', async () => {
    const before = seen.length
    await expect(post(await dest('/redirect'), '{}', {})).rejects.toThrow(/redirect/)
    expect(seen.length).toBe(before + 1) // the redirect target was never requested
  })
  it('reports a server error status', async () => {
    expect((await post(await dest('/boom'), '{}', {})).status).toBe(500)
  })
  it('does not read an oversized response to the end', async () => {
    const res = await post(await dest('/huge'), '{}', {})
    expect(res.status).toBe(200)
  })
})
