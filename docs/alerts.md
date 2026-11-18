# Alerts

DMARCscope can tell you when something needs attention. Set it up under **Admin → Alerts**; the
mail server it sends email through (SMTP) is under **Admin → Settings** and is the owner's to
change. Nothing is sent, and no outbound connection is made, until you add a rule and a channel.

## How it works

A **rule** says what to watch. A **channel** says where to tell you. A rule sends to one or more
channels. The web app evaluates every enabled rule every five minutes, and each condition becomes
an **event**: one notification when it opens, optionally one when it clears.

- Where the evaluation runs: in the web app's own process, on a timer, when the app is a
  long-running process (Docker, a VM, Kubernetes). On a serverless deployment (Vercel) there is
  no such process; call `GET /api/cron/alerts` with `Authorization: Bearer $CRON_SECRET` every five
  minutes instead. Running both is harmless: one evaluation runs at a time across all replicas.
- **No duplicates.** While a condition holds there is one open event. Evaluating again sends
  nothing. A condition that comes back after it cleared is a new event.
- **Quiet period.** An event still open after the rule's quiet period (default 24 hours) is sent
  again as a reminder, at most three times, then stays quiet until it clears.
- **Delivery history.** Every send is recorded, with its short error if it failed. A failed send
  is retried after 1, 5 and 30 minutes (four attempts), then marked failed. One channel being down
  never blocks the others. Delivery is at-least-once: a send whose acknowledgement was lost can be
  repeated, so a webhook receiver should deduplicate on `event_id`.

## Rules

| Rule | Fires when | Notes |
| --- | --- | --- |
| **New source failing DMARC** | a sending IP that has no records before the window sends at least *minimum messages* that fail DMARC for a domain within the window | defaults: 100 messages, 7 days; one event per domain and IP; at most 50 at a time |
| **Compliance below a threshold** | the DMARC pass rate of a domain over the window is under the threshold | defaults: 95%, 100 messages, 7 days. Fewer messages than the minimum give no verdict (not 0%) |
| **Ingest stale** | no ingest run has completed within the staleness window (Settings → Ingest staleness warning) | a fresh install with no run yet is not stale |
| **DMARC or SPF record changed** | the published record differs between a domain's latest two DNS checks | a lookup that timed out is never compared; a record that disappeared does count |

A rule can watch every domain or one. "Record changed" compares what the DNS checks found, so it
needs checks to run: **Run checks** on a domain page, `GET /api/cron/dns-check` on a schedule, or
nothing to do on a long-running web app, which refreshes the checks once a day while such a rule
exists.

## Channels

- **Email.** Up to ten recipients per channel, sent through the SMTP server in Settings
  (`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`). The
  connection is always encrypted (`ssl` for implicit TLS on 465, or `starttls` on 587) and the
  server's certificate is always verified; there is no unencrypted option. Plain-text body.
- **Signed webhook.** A `POST` of JSON:

  ```json
  {"event_id": 42, "type": "alert", "rule": {"name": "…", "kind": "compliance_drop"},
   "domain": "example.com", "summary": "…", "facts": [{"label": "…", "value": "…"}],
   "link": "https://dmarc.example.com/admin/alerts", "at": "2026-11-18T10:00:00.000Z"}
  ```

  `type` is `alert`, `reminder`, `resolved` or `test`. Three headers identify and sign it:
  `X-DMARCscope-Event-Id`, `X-DMARCscope-Timestamp` (Unix seconds) and
  `X-DMARCscope-Signature: v1=<hex>`, the HMAC-SHA256 of `"<timestamp>.<raw body>"` with the
  signing secret you set on the channel. A receiver should recompute it over the raw body with a
  constant-time comparison and reject timestamps older than a few minutes:

  ```js
  const expected = 'v1=' + crypto.createHmac('sha256', secret).update(`${ts}.${rawBody}`).digest('hex')
  ok = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader)) && Math.abs(Date.now() / 1000 - ts) < 300
  ```
- **Slack-compatible webhook.** An incoming-webhook URL of Slack, Mattermost, Microsoft Teams
  (workflow webhook) or anything that accepts `{"text": "…"}`. Not signed; the URL is the secret.

The webhook address and signing secret are encrypted under `APP_SECRET` (purpose `alert`) and
never shown again: the page shows "set" and the host. Replacing the address needs the signing
secret typed again.

## Where alerts can go

Report data is written by whoever sent the report, so alerts are careful in both directions.

- **Outbound requests** (webhook and Slack channels), checked on every delivery and not only when
  saved: `https://` only; redirects are never followed (a redirect is a failure); the host name is
  resolved and the connection is made to that address, so it cannot answer differently for the
  check and the connection; loopback, private (RFC 1918), link-local (including the
  `169.254.169.254` metadata address), unique-local, carrier-grade NAT, multicast and reserved
  addresses, and IPv6 forms that wrap them, are refused; 10 second timeout; the response is read
  to at most 4 KB and never stored.
  The owner can lift the address rule, and allow `http://`, with **Allow alerts to private
  addresses** (`ALERTS_ALLOW_PRIVATE_WEBHOOKS`) — for a Mattermost on your own network, say.
  Leave it off otherwise: anyone with the administrator role can create channels.
- **Text** from reports (reverse DNS names, organization names, envelope senders) is reduced to
  printable text and cut to 200 characters, then escaped for each channel: plain text for email
  (no line break can reach a header), JSON for the signed webhook, Slack's `& < >` escaping for
  Slack-compatible channels (which also stops `<!channel>` and injected links).

## Permissions and audit

Administrators and owners manage rules and channels. The SMTP settings and the private-address
switch are owner-only. Every change, test and refusal is in the audit log; a channel secret is
recorded only as `set`, `kept` or `replaced`.

## Not verified against real services

The tests use local stand-ins for an SMTP server (with TLS) and for webhook receivers. Delivery
to a real SMTP provider, and to Slack, Microsoft Teams or Mattermost, has not been exercised: use
**Send test** on each channel after setting it up.

## Upgrading

Migration `0007` adds the alert tables. A deployment with no rules behaves exactly as before and
makes no new outbound connection. Rotating `APP_SECRET` (`npm run secrets:reencrypt`) covers
channel secrets too.
