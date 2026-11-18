// Pure parts of alerting: record comparison, and validation of rules and channels.

import { describe, expect, it } from 'vitest'
import { AlertRefusal, validateChannel, validateRule } from '@/lib/alerts/admin'
import { recordChanges } from '@/lib/alerts/evaluate'

const rec = (record: string | null, extra = {}) => ({ status: 'ok', record, ...extra })

describe('recordChanges', () => {
  it('reports a changed DMARC record with before and after', () => {
    const c = recordChanges('example.com', { dmarc: rec('v=DMARC1; p=none') }, { dmarc: rec('v=DMARC1; p=reject') })
    expect(c).toHaveLength(1)
    expect(c[0].summary).toMatch(/DMARC record for example\.com changed/)
    expect(c[0].facts.map((f) => f.value)).toEqual(['DMARC', 'v=DMARC1; p=reject', 'v=DMARC1; p=none'])
  })
  it('reports an SPF record that disappeared, as a real value', () => {
    const c = recordChanges('example.com', { spf: rec(null) }, { spf: rec('v=spf1 -all') })
    expect(c).toHaveLength(1)
    expect(c[0].facts[2].value).toBe('(no record)')
  })
  it('says nothing when the records are the same', () => {
    expect(recordChanges('example.com', { dmarc: rec('v=DMARC1; p=none'), spf: rec(null) }, { dmarc: rec('v=DMARC1; p=none'), spf: rec(null) })).toEqual([])
  })
  it('never reads a failed lookup as a record, in either check', () => {
    expect(recordChanges('example.com', { dmarc: rec(null, { lookup_failed: true }) }, { dmarc: rec('v=DMARC1; p=reject') })).toEqual([])
    expect(recordChanges('example.com', { dmarc: rec('v=DMARC1; p=reject') }, { dmarc: rec(null, { lookup_failed: true }) })).toEqual([])
  })
  it('has nothing to compare when a check has no record field at all', () => {
    expect(recordChanges('example.com', { dmarc: { status: 'ok' } }, { dmarc: rec('v=DMARC1; p=none') })).toEqual([])
    expect(recordChanges('example.com', {}, {})).toEqual([])
  })
  it('keys an event by the new record, so a second change is a new event', () => {
    const a = recordChanges('example.com', { dmarc: rec('v=DMARC1; p=none') }, { dmarc: rec('v=DMARC1; p=reject') })[0].key
    const b = recordChanges('example.com', { dmarc: rec('v=DMARC1; p=quarantine') }, { dmarc: rec('v=DMARC1; p=none') })[0].key
    expect(a).not.toBe(b)
  })
})

const rule = (over = {}) => ({
  name: 'Rule', kind: 'compliance_drop', domain: '', minMessages: '', windowDays: '', thresholdPct: '', quietMinutes: '', notifyResolved: false, enabled: true, channelIds: [1, 1, 2], ...over,
})

const field = (fn: () => unknown) => {
  try {
    fn()
  } catch (e) {
    if (e instanceof AlertRefusal) return `${e.code}:${e.field}`
    throw e
  }
  return 'ok'
}

describe('validateRule', () => {
  it('fills the defaults and de-duplicates channels', () => {
    expect(validateRule(rule())).toMatchObject({ params: { min_messages: 100, window_days: 7, threshold_pct: 95 }, quietMinutes: 1440, channelIds: [1, 2], domain: null })
  })
  it('refuses out-of-range and malformed numbers', () => {
    expect(field(() => validateRule(rule({ thresholdPct: '0' })))).toBe('invalid:threshold_pct')
    expect(field(() => validateRule(rule({ thresholdPct: '101' })))).toBe('invalid:threshold_pct')
    expect(field(() => validateRule(rule({ windowDays: '31' })))).toBe('invalid:window_days')
    expect(field(() => validateRule(rule({ minMessages: '-5' })))).toBe('invalid:min_messages')
    expect(field(() => validateRule(rule({ minMessages: '1e3' })))).toBe('invalid:min_messages')
    expect(field(() => validateRule(rule({ quietMinutes: '59' })))).toBe('invalid:quiet_minutes')
  })
  it('refuses an unknown kind, a bad name, a bad domain, and a domain on ingest-stale', () => {
    expect(field(() => validateRule(rule({ kind: 'nope' })))).toBe('invalid:kind')
    expect(field(() => validateRule(rule({ name: '' })))).toBe('invalid:name')
    expect(field(() => validateRule(rule({ domain: 'not a domain' })))).toBe('invalid:domain')
    expect(field(() => validateRule(rule({ kind: 'ingest_stale', domain: 'example.com' })))).toBe('invalid:domain')
  })
  it('keeps only the parameters the kind uses', () => {
    expect(validateRule(rule({ kind: 'dns_changed', minMessages: '5' })).params).toEqual({})
    expect(validateRule(rule({ kind: 'new_failing_source' })).params).toEqual({ min_messages: 100, window_days: 7 })
  })
})

describe('validateChannel', () => {
  const ch = (over = {}) => ({ name: 'Ops', kind: 'email', recipients: 'a@example.com, b@example.com\nc@example.com', url: '', signingSecret: '', enabled: true, ...over })
  it('splits and de-duplicates recipients', () => {
    expect(validateChannel(ch({ recipients: 'a@example.com a@example.com;b@example.com' })).recipients).toEqual(['a@example.com', 'b@example.com'])
  })
  it('refuses missing, malformed, injected and too many recipients', () => {
    expect(field(() => validateChannel(ch({ recipients: '' })))).toBe('invalid:recipients')
    expect(field(() => validateChannel(ch({ recipients: 'not-an-address' })))).toBe('invalid:recipients')
    expect(field(() => validateChannel(ch({ recipients: 'a@example.com<evil@example.com>' })))).toBe('invalid:recipients')
    expect(field(() => validateChannel(ch({ recipients: Array.from({ length: 11 }, (_, i) => `u${i}@example.com`).join(',') })))).toBe('invalid:recipients')
  })
  it('refuses an unknown kind and a bad name', () => {
    expect(field(() => validateChannel(ch({ kind: 'sms' })))).toBe('invalid:kind')
    expect(field(() => validateChannel(ch({ name: 'x'.repeat(101) })))).toBe('invalid:name')
  })
})
