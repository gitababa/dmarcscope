// An alert is built from report data written by strangers: each channel must
// neutralize it for itself.

import { describe, expect, it } from 'vitest'
import { type AlertContent, clean, renderEmail, renderSlack, renderWebhook, slackEscape } from '@/lib/alerts/render'

const CONTROLS = new RegExp('[' + String.fromCharCode(0) + '-' + String.fromCharCode(8) + String.fromCharCode(11, 12) + String.fromCharCode(14) + '-' + String.fromCharCode(31, 0x2028, 0x202e) + ']')

const HOSTILE = [
  '<!channel> look',
  'x\r\nBcc: attacker@evil.example',
  '<http://evil.example|click me>',
  '[click](http://evil.example)',
  'a' + String.fromCharCode(0) + 'b' + String.fromCharCode(27) + 'c' + String.fromCharCode(0x2028) + 'd' + String.fromCharCode(0x202e) + 'e',
  'N'.repeat(10_000),
]

const content = (over: Partial<AlertContent> = {}): AlertContent => ({
  kind: 'alert',
  eventId: 7,
  ruleName: 'New source',
  ruleKind: 'new_failing_source',
  domain: 'example.com',
  summary: 'New source 192.0.2.1 sent 500 messages',
  facts: [],
  link: 'https://dmarc.example.com/admin/alerts',
  at: '2026-11-18T10:00:00.000Z',
  ...over,
})

describe('clean', () => {
  it('removes control characters, line separators and bidi overrides, and cuts to length', () => {
    expect(clean(['a\r\nb\tc', 'd', 'e'].join(String.fromCharCode(0x2028)).replace('d', 'd' + String.fromCharCode(0x202e)))).toBe('a b c d e')
    expect(clean('N'.repeat(500)).length).toBe(200)
    expect(clean(null)).toBe('')
  })
})

describe.each(HOSTILE.map((h) => [h.slice(0, 20), h]))('hostile report text %j', (_label, hostile) => {
  const c = content({ ruleName: hostile, domain: hostile, summary: hostile, facts: [{ label: hostile, value: hostile }] })

  it('cannot add a header or a line to an email subject', () => {
    const { subject } = renderEmail(c, hostile)
    expect(subject).not.toMatch(/[\r\n]/)
    expect(subject.length).toBeLessThanOrEqual(200)
  })

  it('keeps an email body to plain bounded lines', () => {
    const { text } = renderEmail(c, 'DMARCscope')
    expect(text.split('\r\n').every((l) => l.length <= 500)).toBe(true)
    expect(text).not.toMatch(CONTROLS)
  })

  it('leaves no live mention or link in a Slack message', () => {
    const { text } = renderSlack(c, 'DMARCscope')
    // Any "<" in the output is ours: the single link built from the link field.
    const raw = text.replace(/<https:\/\/dmarc\.example\.com\/admin\/alerts\|Open in DMARCscope>/, '')
    expect(raw).not.toContain('<')
    expect(raw).not.toContain('>')
  })

  it('gives a webhook receiver bounded, clean strings', () => {
    const w = JSON.stringify(renderWebhook(c))
    expect(JSON.parse(w).summary.length).toBeLessThanOrEqual(400)
    expect(w).not.toMatch(/\\u0000|\\u001b|\\u2028|\\u202e/)
  })
})

describe('slackEscape', () => {
  it('escapes only the three characters Slack documents', () => {
    expect(slackEscape('<!channel> & <@U1>')).toBe('&lt;!channel&gt; &amp; &lt;@U1&gt;')
  })
})

describe('Slack link', () => {
  it('is only built from an http(s) link', () => {
    expect(renderSlack(content({ link: 'javascript:alert(1)' }), 'x').text).not.toContain('javascript')
  })
})
