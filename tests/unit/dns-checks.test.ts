import { beforeEach, describe, expect, it, vi } from 'vitest'

const txt: Record<string, string[]> = {}
let mx: Array<{ exchange: string; priority: number }> | null = null
const notFound = () => Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' })

vi.mock('node:dns/promises', () => ({
  resolveTxt: vi.fn(async (name: string) => {
    const r = txt[name.toLowerCase()]
    if (!r) throw notFound()
    return r.map((t) => [t.slice(0, 20), t.slice(20)]) // split like real 255-byte chunks
  }),
  resolveMx: vi.fn(async () => {
    if (!mx) throw notFound()
    return mx
  }),
}))

import { parseTagList, runDnsChecks } from '@/lib/dns-checks'

beforeEach(() => {
  for (const k of Object.keys(txt)) delete txt[k]
  mx = [{ exchange: 'mx.example.com', priority: 10 }]
})

describe('parseTagList', () => {
  it('keeps values that contain "=" and lower-cases tag names', () => {
    expect(parseTagList('v=DMARC1; P=reject; rua=mailto:a@example.com?x=1 ;; bogus')).toEqual({
      v: 'DMARC1',
      p: 'reject',
      rua: 'mailto:a@example.com?x=1',
    })
  })
})

describe('runDnsChecks', () => {
  it('passes a well-configured domain', async () => {
    txt['example.com'] = ['v=spf1 include:_spf.example.net -all']
    txt['_dmarc.example.com'] = ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']
    txt['s1._domainkey.example.com'] = ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A']
    const r = await runDnsChecks('example.com', [{ selector: 'S1', signing_domain: 'example.com' }])
    expect(r.mx.status).toBe('ok')
    expect(r.spf.status).toBe('ok')
    expect(r.dmarc.status).toBe('ok')
    expect(r.dkim.status).toBe('ok')
    expect(r.dkim.selectors.find((s) => s.selector === 's1')).toMatchObject({ found: true, observed: true })
  })

  it('flags missing records', async () => {
    mx = null
    const r = await runDnsChecks('example.com', [])
    expect(r.mx.status).toBe('warn')
    expect(r.spf.status).toBe('fail')
    expect(r.dmarc.status).toBe('fail')
    expect(r.dkim.status).toBe('fail')
  })

  it('flags dangerous or invalid SPF', async () => {
    txt['example.com'] = ['v=spf1 +all']
    expect((await runDnsChecks('example.com', [])).spf.status).toBe('fail')
    txt['example.com'] = ['v=spf1 ip4:192.0.2.1 ?all']
    expect((await runDnsChecks('example.com', [])).spf.status).toBe('warn')
    txt['example.com'] = ['v=spf1 ip4:192.0.2.1 -all', 'v=spf1 include:x.test -all']
    const multi = await runDnsChecks('example.com', [])
    expect(multi.spf.status).toBe('fail')
    expect(multi.spf.notes.join(' ')).toMatch(/Multiple SPF/)
    // "-all" inside a longer token must not be mistaken for the all mechanism
    txt['example.com'] = ['v=spf1 include:all-mail.example.net -all']
    expect((await runDnsChecks('example.com', [])).spf.status).toBe('ok')
  })

  it('grades DMARC policy', async () => {
    txt['_dmarc.example.com'] = ['v=DMARC1; p=none; rua=mailto:d@example.com']
    expect((await runDnsChecks('example.com', [])).dmarc.status).toBe('warn')
    txt['_dmarc.example.com'] = ['v=DMARC1; p=reject']
    const noRua = await runDnsChecks('example.com', [])
    expect(noRua.dmarc.status).toBe('warn')
    expect(noRua.dmarc.notes.join(' ')).toMatch(/rua/)
    txt['_dmarc.example.com'] = ['v=DMARC1; rua=mailto:d@example.com']
    expect((await runDnsChecks('example.com', [])).dmarc.status).toBe('fail')
    txt['_dmarc.example.com'] = ['v=DMARC1; p=reject', 'v=DMARC1; p=none']
    expect((await runDnsChecks('example.com', [])).dmarc.status).toBe('fail')
  })

  it('warns when a selector seen in reports is gone, and treats an empty p= as revoked', async () => {
    txt['good._domainkey.example.com'] = ['v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A']
    txt['revoked._domainkey.example.com'] = ['v=DKIM1; p=']
    const r = await runDnsChecks('example.com', [
      { selector: 'good', signing_domain: 'example.com' },
      { selector: 'revoked', signing_domain: 'example.com' },
    ])
    expect(r.dkim.status).toBe('warn')
    expect(r.dkim.selectors.find((s) => s.selector === 'revoked')?.found).toBe(false)
  })
})

describe('null MX', () => {
  it('is reported as a domain that does not accept mail', async () => {
    mx = [{ exchange: '', priority: 0 }]
    const r = await runDnsChecks('example.com', [])
    expect(r.mx.status).toBe('warn')
    expect(r.mx.notes.join(' ')).toMatch(/Null MX/)
  })
})
