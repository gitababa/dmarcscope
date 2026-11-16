import { describe, expect, it } from 'vitest'
import { diagnoseSource } from '@/lib/diagnose'
import type { ProblemSource } from '@/lib/queries'
import { policyAdvice } from '@/lib/readiness'
import { identifySource, remediationFor } from '@/lib/senders'
import { parseRange, pct, rangeParam } from '@/lib/format'

const source = (over: Partial<ProblemSource>): ProblemSource => ({
  source_ip: '192.0.2.10',
  domain: 'example.com',
  reverse_dns: null,
  base_domain: null,
  provider_name: null,
  as_name: null,
  as_domain: null,
  total_messages: 1000,
  failing: 1000,
  passed: 0,
  dkim_passed: 0,
  spf_passed: 0,
  last_seen: null,
  fail_with_valid_dkim_sig: 0,
  fail_with_raw_spf_pass: 0,
  fail_with_both: 0,
  top_fail_envelope: null,
  ...over,
})

const spf = (cidrs: string[], has = true) => ({
  expanded_at: '',
  has_spf: has,
  networks: cidrs.map((cidr) => ({ cidr, via: 'include:_spf.vendor.test' })),
  lookups: 1,
  notes: [],
})

describe('diagnoseSource', () => {
  it('unauthenticated mail from an IP outside SPF is flagged as unauthorized', () => {
    const d = diagnoseSource(source({}), spf(['198.51.100.0/24']))
    expect(d.tone).toBe('bad')
    expect(d.verdict).toMatch(/Unauthorized sender/)
    expect(d.details.join(' ')).toMatch(/1,000 \(100%\) carried no valid authentication/)
  })

  it('a service using its own DKIM and SPF domain is a setup issue, not forwarding', () => {
    const d = diagnoseSource(
      source({ fail_with_valid_dkim_sig: 900, fail_with_raw_spf_pass: 950, fail_with_both: 900, top_fail_envelope: 'vendor.test' }),
      spf(['198.51.100.0/24'])
    )
    expect(d.tone).toBe('warn')
    expect(d.verdict).toMatch(/set up domain authentication/)
    expect(d.showRemediation).toBe(true)
    // groups are disjoint and add up to the failing total
    expect(d.details.join(' ')).toMatch(/900 of the failing messages \(90%\)/)
    expect(d.details.join(' ')).toMatch(/50 \(5%\) passed SPF for a different envelope/)
    expect(d.details.join(' ')).toMatch(/50 \(5%\) carried no valid authentication/)
  })

  it('an authorized IP whose failures carry foreign signatures is forwarding', () => {
    const d = diagnoseSource(
      source({ total_messages: 5000, failing: 100, passed: 4900, fail_with_valid_dkim_sig: 90 }),
      spf(['192.0.2.0/24'])
    )
    expect(d.tone).toBe('ok')
    expect(d.verdict).toMatch(/forwarded or relayed/)
    expect(d.details[0]).toMatch(/authorized by example.com's SPF \(via include:_spf.vendor.test/)
  })

  it('an authorized IP failing on envelope domain only is an alignment issue', () => {
    const d = diagnoseSource(source({ fail_with_raw_spf_pass: 800, top_fail_envelope: 'bounce.vendor.test' }), spf(['192.0.2.0/24']))
    expect(d.verdict).toMatch(/Return-Path/)
    expect(d.tone).toBe('warn')
  })

  it('does not call a sender unauthorized when the SPF lookup was incomplete', () => {
    // a DNS timeout during the last check: the include that covers this IP is missing
    const partial = { ...spf(['198.51.100.0/24']), incomplete: true }
    const d = diagnoseSource(source({}), partial)
    expect(d.verdict).not.toMatch(/Unauthorized|Not in SPF/)
    expect(d.details.join(' ')).toMatch(/could not be fully resolved/)
    // the record itself could not be fetched: not "publishes no SPF record"
    const unknown = diagnoseSource(source({}), { ...spf([], false), incomplete: true })
    expect(unknown.verdict).not.toMatch(/no SPF record/)
    expect(unknown.details.join(' ')).not.toMatch(/publishes no SPF/)
    // a match found in a partial expansion still counts
    expect(diagnoseSource(source({}), { ...spf(['192.0.2.0/24']), incomplete: true }).details.join(' ')).toMatch(/is authorized/)
  })

  it('survives a malformed stored expansion', () => {
    const broken = { ...spf([]), networks: [{ cidr: '2001:db8::/abc', via: 'x' }, null] } as unknown as ReturnType<typeof spf>
    expect(() => diagnoseSource(source({ source_ip: '2001:db8::1' }), broken)).not.toThrow()
  })

  it('handles a domain with no SPF and missing DNS data', () => {
    expect(diagnoseSource(source({}), spf([], false)).verdict).toMatch(/no SPF record/)
    const unknown = diagnoseSource(source({}), undefined)
    expect(unknown.tone).toBe('bad')
    expect(unknown.verdict).toMatch(/no valid authentication/)
  })
})

describe('identifySource', () => {
  const stats = { total: 100, dkim_passed: 100, spf_passed: 100, dmarc_passed: 100 }
  it('recognizes known senders by reverse DNS', () => {
    expect(identifySource({ reverse_dns: 'mail-sor-f41.google.com', base_domain: 'google.com', ...stats })).toEqual({
      name: 'Google (Gmail / Workspace)',
      category: 'known',
    })
    expect(identifySource({ reverse_dns: 'a8-31.smtp-out.amazonses.com', base_domain: null, ...stats }).name).toBe('Amazon SES')
  })
  it('does not match lookalike hostnames', () => {
    expect(identifySource({ reverse_dns: 'evilgoogle.com', base_domain: 'evilgoogle.com', ...stats, dmarc_passed: 0, dkim_passed: 0, spf_passed: 0 })).toEqual({
      name: null,
      category: 'unknown',
    })
  })
  it('labels by network owner without vouching for the sender', () => {
    const id = identifySource({ reverse_dns: null, base_domain: null, provider_name: 'Twilio SendGrid', total: 100, dkim_passed: 0, spf_passed: 0, dmarc_passed: 0 })
    expect(id).toEqual({ name: 'Twilio SendGrid', category: 'unknown' })
    expect(remediationFor(id)).toMatch(/Domain Authentication/)
  })
  it('spots the forwarder fingerprint', () => {
    expect(identifySource({ reverse_dns: null, base_domain: null, total: 100, dkim_passed: 90, spf_passed: 5, dmarc_passed: 90 }).category).toBe('forwarder')
  })
})

describe('policyAdvice', () => {
  it('waits for data', () => {
    expect(policyAdvice({ policy: 'none', total30d: 10, passed30d: 10 }).tone).toBe('info')
  })
  it('walks none → quarantine → reject', () => {
    expect(policyAdvice({ policy: 'none', total30d: 10000, passed30d: 9900 }).title).toMatch(/Ready to move to p=quarantine/)
    expect(policyAdvice({ policy: 'none', total30d: 10000, passed30d: 9000 }).title).toMatch(/Fix failing senders/)
    expect(policyAdvice({ policy: 'quarantine', total30d: 10000, passed30d: 9950 }).title).toMatch(/Ready to move to p=reject/)
    expect(policyAdvice({ policy: 'quarantine', total30d: 10000, passed30d: 9800 }).tone).toBe('warn')
    expect(policyAdvice({ policy: 'reject', total30d: 10000, passed30d: 9990 }).title).toBe('Fully enforced')
    expect(policyAdvice({ policy: 'reject', total30d: 10000, passed30d: 8000 }).tone).toBe('bad')
    expect(policyAdvice({ policy: null, total30d: 10000, passed30d: 9990 }).title).toMatch(/quarantine/)
  })
  it('never rounds a rate up past a threshold', () => {
    // 97.96% must not be displayed as 98.0% next to "aim for 98%"
    expect(policyAdvice({ policy: 'none', total30d: 10000, passed30d: 9796 }).detail).toMatch(/^97\.9%/)
  })
})

describe('format', () => {
  it('parses only the offered ranges', () => {
    expect(parseRange('30d')).toBe(30)
    expect(parseRange('all')).toBe(0)
    expect(parseRange('31d')).toBe(7)
    expect(parseRange("7d'; DROP TABLE")).toBe(7)
    expect(parseRange(undefined)).toBe(7)
    expect(rangeParam(0)).toBe('all')
  })
  it('formats percentages', () => {
    expect(pct(0.9283)).toBe('92.8%')
    expect(pct(NaN)).toBe('—')
  })
})
