# DMARCscope

Self-hosted DMARC monitoring. DMARCscope reads the aggregate reports that mailbox providers
(Google, Microsoft, Yahoo, …) send about your domains, stores them in PostgreSQL, and shows you
who is sending mail as you, whether it authenticates, and what to fix.

It is read-only: it never sends, blocks or changes any mail.

## What you get

- **Overview** — volume, DMARC / DKIM / SPF alignment and published policy for every domain.
- **Per-domain pages** — alignment breakdown, every sending source, live DNS health checks
  (MX, SPF, DMARC, DKIM) and advice on when it is safe to move to `quarantine` or `reject`.
- **Issues** — each source that fails DMARC, with a diagnosis: forwarded mail, a service that was
  never set up for your domain, a Return-Path mismatch, or spoofing — and whether the sending IP
  is covered by your SPF record, and through which `include`.
- **Sign-in that fits your environment** — any OpenID Connect provider, Google Cloud IAP,
  Cloudflare Access, or an authenticating reverse proxy. Access is deny-by-default.
- **Nothing phones home** — no external fonts, scripts or analytics; IP lookups use an offline
  database.

## How it works

```
mailbox providers ──(daily aggregate reports)──▶ your reports mailbox
                                                       │ IMAP
                                              ingest worker (Python, scheduled)
                                                       │
                                                  PostgreSQL
                                                       │
                                            web app (Next.js) ──▶ you
```

Two small components share one database:

| Component | What it is | How it runs |
|---|---|---|
| Web app | Next.js dashboard | a container or Node process, behind your TLS / proxy |
| Ingest worker | `python -m ingestor run` | a scheduled one-shot job (daily is enough) |

## Try it in five minutes

Needs Docker. This starts PostgreSQL and the dashboard with sign-in disabled, and loads
synthetic reports so there is something to look at.

```bash
cp .env.example .env                       # defaults: AUTH_PROVIDER=none
docker compose up -d --build
python3 scripts/demo_reports.py demo-reports
docker compose run --rm ingest import /reports
```

Open http://localhost:3000.

## Set it up for real

1. **Create a mailbox for reports** (for example `dmarc-reports@yourdomain.com`) that can be
   read over IMAP with a password or app password.
2. **Ask for reports.** For each domain, publish a TXT record at `_dmarc.<domain>`:

   ```
   v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com
   ```

   `p=none` only monitors. If the mailbox is on a different domain than the one being
   monitored, the mailbox's domain must also publish
   `<monitored-domain>._report._dmarc.<mailbox-domain>  TXT  "v=DMARC1"`.
3. **Deploy** the web app, the database and the scheduled ingest job —
   see [docs/deployment.md](docs/deployment.md) (Docker Compose, Kubernetes, Google Cloud Run,
   Vercel).
4. **Choose how people sign in** — see [docs/authentication.md](docs/authentication.md).
5. **Configure** the mailbox, retention and access lists —
   see [docs/configuration.md](docs/configuration.md).

Reports usually start arriving 24–48 hours after the DNS record goes live, and domains appear
on the dashboard automatically.

## Development

Requirements: Node.js 20.9+, Python 3.11+, PostgreSQL 13+.

```bash
npm ci
cp .env.example .env.local                 # point DATABASE_URL at your database
npm run db:migrate
npm run dev

python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python scripts/demo_reports.py demo-reports
DATABASE_URL=... .venv/bin/python -m ingestor import demo-reports
```

Tests:

```bash
npm run typecheck
npm test                                   # unit tests; set TEST_DATABASE_URL to include database tests
.venv/bin/python -m pytest ingestor        # set TEST_DATABASE_URL to include database tests
npm run test:e2e                           # sign-in flow against a running build, see tests/e2e/oidc.test.ts
```

`TEST_DATABASE_URL` must point at a disposable database: the tests create and drop their own
schemas in it.

## Limitations

- Only **aggregate** (RUA) reports are stored. Failure (RUF) reports contain message samples
  with personal data and are deliberately skipped, as are SMTP TLS reports.
- The mailbox is read over **IMAP with a password**. Mailboxes that only allow OAuth
  (Microsoft 365 with basic authentication disabled) are not supported directly; forward
  reports to a mailbox that is, or load report files with `python -m ingestor import`.
- DKIM has no discovery mechanism, so DNS checks probe the selectors seen in your reports plus
  a few common defaults.
- One organization per deployment: everyone with access sees all domains.

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report a vulnerability.

## License

[Apache License 2.0](LICENSE).
