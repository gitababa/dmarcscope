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
| Ingest worker | `python -m ingestor serve` | a long-running process reading the mailboxes set up in the app (or `run`, a scheduled one-shot job for a mailbox in the environment) |

## Try it in five minutes

Needs Docker. This starts PostgreSQL and the dashboard with sign-in disabled, and loads
synthetic reports so there is something to look at.

```bash
cp .env.example .env
printf 'AUTH_PROVIDER=none\nAUTH_ALLOW_INSECURE_NONE=true\n' >> .env
python3 scripts/demo_reports.py demo-reports
docker compose up -d --build
docker compose run --rm ingest import /reports
```

Open http://localhost:3000. The second line turns sign-in off, which the production image only
accepts with `AUTH_ALLOW_INSECURE_NONE=true`; Compose publishes the port on localhost only. For
real use, start from a fresh `.env` as below.

## Set it up for real

**1. Deploy it.** The app needs PostgreSQL and three variables: `DATABASE_URL`, `APP_URL` (its
public https address) and `APP_SECRET` (`openssl rand -base64 32`). Step-by-step guides for
Docker Compose, Kubernetes, Google Cloud Run and Vercel are in
[docs/deployment.md](docs/deployment.md).

**2. Create the owner account.** Open the app: it starts a setup wizard. The one-time
**setup token** it asks for is in the app's server log (search for `[setup]`). If you can't
find it, the setup page can write a new one to the log.
[Where to find it on each platform](docs/deployment.md#first-start-create-the-owner).

**3. Connect a mailbox for reports.** Use a dedicated mailbox, for example
`dmarc-reports@yourdomain.com`, readable over IMAP. A Gmail or Google Workspace address with
an app password works, as does any IMAP host. Add it under **Mailboxes**, or as `IMAP_*`
variables on Vercel. See [docs/mail.md](docs/mail.md).

**4. List your domains** under **Monitored domains**. Reports about any other domain are
ignored, since anyone can email a report to the mailbox.

**5. Ask for reports.** For each domain, publish a TXT record at `_dmarc.<domain>`:

```
v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com
```

`p=none` only monitors; it changes nothing for your mail. If the mailbox is on a different
domain than the one being monitored, that mailbox domain must also publish
`<monitored-domain>._report._dmarc.<mailbox-domain>  TXT  "v=DMARC1"`.

Reports usually start arriving 24–48 hours after the DNS record goes live, and domains appear on
the dashboard automatically. Afterwards, as needed: invite people and choose how they sign in
([docs/authentication.md](docs/authentication.md), [docs/sso.md](docs/sso.md)), set up alerts
([docs/alerts.md](docs/alerts.md)), and see every setting in
[docs/configuration.md](docs/configuration.md). Upgrading from 1.1? See the
[upgrade notes](docs/deployment.md#from-11x-to-20).

## Development

Requirements: Node.js 20.9+, Python 3.11+, PostgreSQL 13+.

```bash
npm ci
cp .env.example .env.local                 # set DATABASE_URL, and APP_SECRET (or AUTH_PROVIDER=none to skip sign-in)
DATABASE_URL=... npm run db:migrate        # the migration script does not read .env.local
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
- Mailboxes are read over **IMAP**: with a password, or through OAuth for Microsoft 365 and
  Google Workspace. The two OAuth paths have so far been tested only against local stand-ins,
  not real tenants ([docs/mail.md](docs/mail.md)).
- DKIM has no discovery mechanism, so DNS checks probe the selectors seen in your reports plus
  a few common defaults.
- One organization per deployment: everyone with access sees all domains.

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report a vulnerability.

## License

[Apache License 2.0](LICENSE).
