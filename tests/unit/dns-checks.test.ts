import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DnsClient } from '@/lib/dns-resolver'
import type { PolicyFetch } from '@/lib/mta-sts'
import { hasVersion, parseTagList, runDnsChecks as run, type DkimProbe } from '@/lib/dns-checks'

const txt: Record<string, string[]> = {}
let mx: Array<{ exchange: string; priority: number }> | null = null
const notFound = () => Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' })

const servfail = () => Object.assign(new Error('ESERVFAIL'), { code: 'ESERVFAIL' })
// Names whose lookups fail with SERVFAIL.
const failing = new Set<string>()
let policyFetch: PolicyFetch = { ok: false, error: 'not set up in this test' }

const fake: DnsClient = {
  resolveTxt: vi.fn(async (name: string) => {
    if (failing.has(name.toLowerCase())) throw servfail()
    const r = txt[name.toLowerCase()]
    if (!r) throw notFound()
    return r.map((t) => [t.slice(0, 20), t.slice(20)]) // split like real 255-byte chunks
  }),
  resolveMx: vi.fn(async () => {
    if (!mx) throw notFound()
    return mx
  }),
  resolve4: vi.fn(async () => Promise.reject(notFound())),
  resolve6: vi.fn(async () => Promise.reject(notFound())),
}

const runDnsChecks = (domain: string, signers: DkimProbe[], opts: { servers?: string[] } = {}) =>
  run(domain, signers, { dns: fake, fetchPolicy: async () => policyFetch, ...opts })

beforeEach(() => {
  for (const k of Object.keys(txt)) delete txt[k]
  failing.clear()
  policyFetch = { ok: false, error: 'not set up in this test' }
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

describe('record versions', () => {
  it('requires the exact version as the first tag', () => {
    expect(hasVersion('v=DMARC1; p=reject', 'DMARC1')).toBe(true)
    expect(hasVersion(' v = dmarc1 ;p=reject', 'DMARC1')).toBe(true)
    expect(hasVersion('v=DMARC10; p=reject', 'DMARC1')).toBe(false)
    expect(hasVersion('p=reject; v=DMARC1', 'DMARC1')).toBe(false)
  })

  it('ignores look-alike SPF and DMARC records', async () => {
    txt['example.com'] = ['v=spf10 -all']
    txt['_dmarc.example.com'] = ['v=DMARC10; p=reject; rua=mailto:d@example.com']
    const r = await runDnsChecks('example.com', [])
    expect(r.spf.record).toBeNull()
    expect(r.spf.status).toBe('fail')
    expect(r.dmarc.record).toBeNull()
    expect(r.dmarc.status).toBe('fail')
  })
})

describe('DMARC on a subdomain', () => {
  it('applies the closest parent record, with sp= in force', async () => {
    txt['_dmarc.example.com'] = ['v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com']
    const r = await runDnsChecks('mail.eu.example.com', [])
    expect(r.dmarc.record).toBeNull()
    expect(r.dmarc.inherited).toEqual({ from: 'example.com', record: 'v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com' })
    expect(r.dmarc.status).toBe('ok')
    expect(r.dmarc.notes.join(' ')).toMatch(/sp=quarantine/)
  })

  it('grades sp=none on the parent as monitoring only', async () => {
    txt['_dmarc.example.com'] = ['v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com']
    const r = await runDnsChecks('mail.example.com', [])
    expect(r.dmarc.status).toBe('warn')
  })

  it('prefers the nearer parent', async () => {
    txt['_dmarc.example.com'] = ['v=DMARC1; p=none; rua=mailto:d@example.com']
    txt['_dmarc.eu.example.com'] = ['v=DMARC1; p=reject; rua=mailto:d@example.com']
    const r = await runDnsChecks('mail.eu.example.com', [])
    expect(r.dmarc.inherited?.from).toBe('eu.example.com')
  })

  it('does not claim "no policy" when a parent lookup failed', async () => {
    failing.add('_dmarc.example.com')
    const r = await runDnsChecks('mail.example.com', [])
    expect(r.dmarc.status).toBe('warn')
    expect(r.dmarc.inherited).toBeUndefined()
    expect(r.dmarc.notes.join(' ')).toMatch(/failed/)
  })

  it('fails when no domain up the tree publishes one', async () => {
    const r = await runDnsChecks('mail.example.com', [])
    expect(r.dmarc.status).toBe('fail')
    expect(r.dmarc.notes.join(' ')).toMatch(/any parent domain/)
  })

  it('never walks up from a domain that has its own record', async () => {
    txt['_dmarc.mail.example.com'] = ['v=DMARC1; p=none; rua=mailto:d@example.com']
    txt['_dmarc.example.com'] = ['v=DMARC1; p=reject; rua=mailto:d@example.com']
    const r = await runDnsChecks('mail.example.com', [])
    expect(r.dmarc.inherited).toBeUndefined()
    expect(r.dmarc.status).toBe('warn')
  })
})

describe('DKIM lookups that fail', () => {
  it('are not reported as missing keys', async () => {
    failing.add('s1._domainkey.example.com')
    const r = await runDnsChecks('example.com', [{ selector: 's1', signing_domain: 'example.com' }])
    expect(r.dkim.selectors.find((s) => s.selector === 's1')).toMatchObject({ found: false, observed: true, lookup_failed: true })
    expect(r.dkim.status).toBe('warn')
    expect(r.dkim.notes.join(' ')).not.toMatch(/missing from DNS/)
  })

  it('leave a found key passing but flag the observed selector that could not be checked', async () => {
    txt['good._domainkey.example.com'] = ['v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A']
    failing.add('other._domainkey.example.com')
    const r = await runDnsChecks('example.com', [
      { selector: 'good', signing_domain: 'example.com' },
      { selector: 'other', signing_domain: 'example.com' },
    ])
    expect(r.dkim.status).toBe('warn')
    expect(r.dkim.notes.join(' ')).toMatch(/could not be checked/)
  })
})

describe('MTA-STS and TLS-RPT', () => {
  const policy = (mode: string, mxLines: string[], maxAge = 604800) =>
    ['version: STSv1', `mode: ${mode}`, ...mxLines.map((m) => `mx: ${m}`), `max_age: ${maxAge}`].join('\r\n')

  it('are "not published" when absent, which is not a failure', async () => {
    const r = await runDnsChecks('example.com', [])
    expect(r.mta_sts?.status).toBe('none')
    expect(r.tls_rpt?.status).toBe('none')
  })

  it('pass an enforced policy that covers every MX host', async () => {
    mx = [
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 },
    ]
    txt['_mta-sts.example.com'] = ['v=STSv1; id=20261119']
    txt['_smtp._tls.example.com'] = ['v=TLSRPTv1; rua=mailto:tls@example.com']
    policyFetch = { ok: true, contentType: 'text/plain; charset=utf-8', text: policy('enforce', ['*.example.com']) }
    const r = await runDnsChecks('example.com', [])
    expect(r.mta_sts?.status).toBe('ok')
    expect(r.mta_sts?.policy).toMatchObject({ mode: 'enforce', mx: ['*.example.com'], max_age: 604800 })
    expect(r.tls_rpt?.status).toBe('ok')
  })

  it('fail an enforced policy that leaves an MX host out', async () => {
    mx = [
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'backup.mail.example.net', priority: 20 },
    ]
    txt['_mta-sts.example.com'] = ['v=STSv1; id=abc']
    policyFetch = { ok: true, contentType: 'text/plain', text: policy('enforce', ['mx1.example.com']) }
    const r = await runDnsChecks('example.com', [])
    expect(r.mta_sts?.status).toBe('fail')
    expect(r.mta_sts?.notes.join(' ')).toMatch(/backup\.mail\.example\.net/)
    // MTA-STS without TLS-RPT: nobody hears about the failures.
    expect(r.tls_rpt?.status).toBe('warn')
  })

  it('fail when the record is published but the policy cannot be fetched', async () => {
    txt['_mta-sts.example.com'] = ['v=STSv1; id=abc']
    policyFetch = { ok: false, error: 'mta-sts.example.com does not resolve' }
    const r = await runDnsChecks('example.com', [])
    expect(r.mta_sts?.status).toBe('fail')
    expect(r.mta_sts?.notes.join(' ')).toMatch(/does not resolve/)
  })

  it('warn about testing mode, a short max_age and the wrong content type', async () => {
    txt['_mta-sts.example.com'] = ['v=STSv1; id=abc']
    policyFetch = { ok: true, contentType: 'text/html', text: policy('testing', ['mx.example.com'], 3600) }
    const r = await runDnsChecks('example.com', [])
    expect(r.mta_sts?.status).toBe('warn')
    const notes = r.mta_sts?.notes.join(' ')
    expect(notes).toMatch(/testing/)
    expect(notes).toMatch(/max_age/)
    expect(notes).toMatch(/text\/plain/)
  })

  it('fail a record without a valid id', async () => {
    txt['_mta-sts.example.com'] = ['v=STSv1; id=not-valid!']
    expect((await runDnsChecks('example.com', [])).mta_sts?.status).toBe('fail')
  })

  it('fail a TLS-RPT record whose rua is not mailto: or https:', async () => {
    txt['_smtp._tls.example.com'] = ['v=TLSRPTv1; rua=http://example.com/report']
    expect((await runDnsChecks('example.com', [])).tls_rpt?.status).toBe('fail')
  })
})

describe('BIMI', () => {
  it('treats an empty record as a declination', async () => {
    txt['default._bimi.example.com'] = ['v=BIMI1; l=; a=']
    expect((await runDnsChecks('example.com', [])).bimi?.status).toBe('none')
  })

  it('warns while DMARC is not enforced', async () => {
    txt['_dmarc.example.com'] = ['v=DMARC1; p=none; rua=mailto:d@example.com']
    txt['default._bimi.example.com'] = ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem']
    const r = await runDnsChecks('example.com', [])
    expect(r.bimi?.status).toBe('warn')
    expect(r.bimi?.notes.join(' ')).toMatch(/enforced/)
  })

  it('passes with DMARC at reject', async () => {
    txt['_dmarc.example.com'] = ['v=DMARC1; p=reject; rua=mailto:d@example.com']
    txt['default._bimi.example.com'] = ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem']
    expect((await runDnsChecks('example.com', [])).bimi?.status).toBe('ok')
  })

  it('fails a logo that is not served over https', async () => {
    txt['default._bimi.example.com'] = ['v=BIMI1; l=http://example.com/logo.svg']
    expect((await runDnsChecks('example.com', [])).bimi?.status).toBe('fail')
  })
})

describe('resolver', () => {
  it('records which servers answered', async () => {
    expect((await runDnsChecks('example.com', [], { servers: ['1.1.1.1', '9.9.9.9'] })).resolver).toEqual(['1.1.1.1', '9.9.9.9'])
    expect((await runDnsChecks('example.com', [])).resolver).toEqual([])
  })
})
