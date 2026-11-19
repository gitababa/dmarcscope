// One alert, rendered for each channel. An alert is structured data; the text
// of each channel is built here and nowhere else. Report data (reverse DNS
// names, organization names, envelope senders) is written by strangers, so
// every field is reduced to printable text and cut to length first, and each
// channel then escapes for itself.

export type AlertKind = 'alert' | 'reminder' | 'resolved' | 'test'

export type AlertFact = { label: string; value: string }

export type AlertContent = {
  kind: AlertKind
  eventId: number | null
  ruleName: string
  ruleKind: string
  domain: string | null
  summary: string
  facts: AlertFact[]
  link: string | null
  at: string // ISO time
}

export const FIELD_MAX = 200

// Printable characters only, one line, shortened. Also removes the Unicode
// line separators and the bidirectional controls that can reorder text.
// C0/C1 controls, line and paragraph separators, bidirectional overrides and isolates.
const UNPRINTABLE = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]+', 'g')

export function clean(value: unknown, max = FIELD_MAX): string {
  const raw = value == null ? '' : String(value)
  const flat = raw.replace(UNPRINTABLE, ' ').replace(/\s+/g, ' ').trim()
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat
}

export function cleanFacts(facts: AlertFact[]): AlertFact[] {
  return facts.slice(0, 12).map((f) => ({ label: clean(f.label, 40), value: clean(f.value) }))
}

const PREFIX: Record<AlertKind, string> = { alert: 'Alert', reminder: 'Reminder', resolved: 'Resolved', test: 'Test' }

export function title(c: AlertContent): string {
  return `${PREFIX[c.kind]}: ${clean(c.ruleName, 100)}${c.domain ? ` (${clean(c.domain, 100)})` : ''}`
}

// ---------- email ----------

// Plain text. The subject is a header: no CR or LF can survive clean().
export function renderEmail(c: AlertContent, appName: string): { subject: string; text: string } {
  const lines = [
    clean(c.summary, 400),
    '',
    ...c.facts.map((f) => `${clean(f.label, 40)}: ${clean(f.value)}`),
    ...(c.link ? ['', `Open: ${clean(c.link, 400)}`] : []),
    '',
    `${clean(appName, 60)} · ${clean(c.at, 40)}`,
  ]
  return { subject: `[${clean(appName, 60)}] ${title(c)}`.slice(0, 200), text: lines.join('\r\n') }
}

// ---------- Slack-compatible ----------

// Slack's documented escaping: only & < > are special, and escaping < is what
// stops <!channel>, <@U123> and <http://…|label> from becoming mentions or
// links.
export function slackEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

export function renderSlack(c: AlertContent, appName: string): { text: string } {
  const lines = [
    `*${slackEscape(title(c))}*`,
    slackEscape(clean(c.summary, 400)),
    ...c.facts.map((f) => `• ${slackEscape(clean(f.label, 40))}: ${slackEscape(clean(f.value))}`),
    ...(c.link && /^https?:\/\//.test(c.link) ? [`<${c.link.replace(/[<>|\s]/g, '')}|Open in ${slackEscape(clean(appName, 60))}>`] : []),
  ]
  return { text: lines.join('\n') }
}

// ---------- signed webhook ----------

// JSON is data: nothing to escape beyond JSON itself, but values are still
// cleaned so a receiver never gets control characters or unbounded text.
export function renderWebhook(c: AlertContent): Record<string, unknown> {
  return {
    event_id: c.eventId,
    type: c.kind,
    rule: { name: clean(c.ruleName, 100), kind: c.ruleKind },
    domain: c.domain ? clean(c.domain, 253) : null,
    summary: clean(c.summary, 400),
    facts: c.facts.map((f) => ({ label: clean(f.label, 40), value: clean(f.value) })),
    link: c.link,
    at: c.at,
  }
}
