# Configuration reference

Three environment variables are enough to start: `DATABASE_URL`, `APP_URL` and
`APP_SECRET`. With only those, the app serves its setup wizard (see
[authentication.md](authentication.md#first-run-the-setup-wizard)), and everything else can be
configured in the browser (new in 2.0). Every 1.1.0 variable keeps working
exactly as before.

## How a setting gets its value

Settings that can be changed in the panel (**Settings**) resolve to exactly one value:

1. the environment variable, if it is set — the panel then shows the setting as
   **managed by environment** and does not let you change it there;
2. otherwise the value saved in the panel;
3. otherwise the default.

So an existing deployment behaves as before, and a deployment managed from Git can keep every
setting in its environment. A change saved in the panel reaches every running instance within
`SETTINGS_CACHE_SECONDS` (default 5), without a restart.

A value that is not valid — in the environment or in the database — is never silently replaced:
it is logged once (without the value) and shown to administrators on the settings page. Until it
is fixed the setting uses its default, or, for a secret, counts as not set.

| Setting (panel) | Environment variable | Default | Who may change it |
|---|---|---|---|
| Application name | `APP_NAME` | `DMARCscope` | admins |
| Ingest staleness warning (hours) | `INGEST_STALE_HOURS` | `36` | admins |
| Keep reports for (days) | `RETENTION_DAYS` | — (forever; `0` in the environment also means forever) | admins |
| Session length (hours) | `SESSION_MAX_AGE_HOURS` | `12` | owner |
| Password sign-in for non-owners | `AUTH_LOCAL_SIGNIN_NON_OWNERS` | off | owner |
| Require single sign-on (while a connection is active) | `AUTH_ENFORCE_SSO` | off | owner |
| Machine endpoint token (secret) | `CRON_SECRET` | — (endpoints closed) | owner |
| SMTP server, port, encryption, user name, password (secret), sender address (alerts) | `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_SECURITY` (`starttls` or `ssl`), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | — (email channels cannot send) | owner |
| Allow alerts to private addresses | `ALERTS_ALLOW_PRIVATE_WEBHOOKS` | off | owner |
| Domains a viewer sees without a scope | `ACCESS_DOMAIN_DEFAULT` (`all` or `none`) | `all` | owner |
| DNS servers (DNS checks, SPF expansion, the worker's reverse DNS) | `DNS_SERVERS`, e.g. `1.1.1.1, 8.8.8.8` (up to 4 IP addresses, optional `:port`) | — (the host's own resolver) | owner |

The single sign-on connection itself is configured under **Sign-in** ([sso.md](sso.md)).
Reports mailboxes and monitored domains are configured under **Mailboxes** and **Monitored
domains** ([mail.md](mail.md)). Alert rules and channels are under **Alerts** ([alerts.md](alerts.md)). Domain limits, SCIM and API tokens are under **People**, **Groups** and **API & SCIM** ([enterprise.md](enterprise.md)).

### Secrets in the database

Secrets saved in the panel (and the owner's TOTP seed) are encrypted with AES-256-GCM under a key
derived from `APP_SECRET`, one key per purpose. A saved secret is never sent back to the
browser: the panel shows "set" or "not set" and takes a replacement. The ingest worker reads the
same format (`ingestor/crypto.py`). Mailbox passwords, client secrets and keys are encrypted by
the web app but can only be decrypted by the worker ([mail.md](mail.md#security-notes)).

**Rotating `APP_SECRET`:**

1. Set `APP_SECRET` to a new value and `APP_SECRET_PREVIOUS` to the old one, and deploy. Values
   written under the old secret still decrypt.
2. Run `npm run secrets:reencrypt` (in the image: `node scripts/secrets-reencrypt.mjs`). It
   re-encrypts everything under the new secret (settings, authenticator seeds, the single
   sign-on client secret and mailbox secrets), in one transaction; if anything cannot be
   decrypted it changes nothing and names the records. `--dry-run` only reports.
3. Remove `APP_SECRET_PREVIOUS`.

Rotating `APP_SECRET` also signs everyone out unless `SESSION_SECRET` is set (sessions are
encrypted with `SESSION_SECRET` where that is set, otherwise with a key derived from
`APP_SECRET`).

## Both components

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — (required) | PostgreSQL connection string. Add `?sslmode=require` for TLS. |
| `APP_SECRET` | — (required for the setup wizard, sign-in managed in the app, secrets saved in the panel, and the worker's `serve` mode) | At least 32 random characters (`openssl rand -base64 32`). Keep it in a secret manager; losing it makes the secrets saved in the panel unreadable. |
| `APP_SECRET_PREVIOUS` | — | The previous `APP_SECRET`, while rotating (see above). |

## Web app

| Variable | Default | Purpose |
|---|---|---|
| `APP_URL` | `http://localhost:3000` outside production; required in production | Public URL. Used for sign-in redirects, to decide whether cookies are `Secure`, and to check that form posts come from this site. |
| `APP_NAME` | `DMARCscope` | Name shown in the header and page titles. Also a panel setting. |
| `DATABASE_POOL_MAX` | `10` | Connections per web instance. |
| `DATABASE_QUERY_TIMEOUT_MS` | `30000` | The web app abandons a query after this long and drops its connection. `0` disables. |
| `DATABASE_STATEMENT_TIMEOUT_MS` | — | Also sets PostgreSQL's `statement_timeout` on each connection. Transaction-mode poolers (PgBouncer) reject this; with one, run `ALTER ROLE <user> SET statement_timeout = '30s'` instead. |
| `INGEST_STALE_HOURS` | `36` | With no completed ingest run for this long, the overview shows a warning and `/api/cron/status` answers 503. Also a panel setting. |
| `AUTH_PROVIDER` | — (sign-in managed in the app) | `oidc`, `proxy-jwt`, `proxy-header` or `none`; unset to manage sign-in in the app. See [authentication.md](authentication.md). |
| `CRON_SECRET` | — | Bearer token for `/api/cron/*`; at least 16 characters. Endpoints are closed while neither this nor the panel setting is set. |
| `SETUP_TOKEN` | — (generated) | Unlocks the setup wizard instead of the generated token printed in the log; at least 24 characters. |
| `SETTINGS_CACHE_SECONDS` | `5` | How long each instance trusts what it read from the settings table before checking for changes (0–300). |
| `CLIENT_IP_HEADER` | `x-forwarded-for` | Header the reverse proxy in front of the app puts the client's address in (for `x-forwarded-for`, the last entry is used). Used for the per-address sign-in limit and the audit log. The address is only as trustworthy as that proxy: Next.js passes on an `X-Forwarded-For` a client sent itself. |
| `PORT`, `HOSTNAME` | `3000`, `0.0.0.0` (container) | Listen address. Docker Compose fixes these inside the container; use `WEB_BIND` / `WEB_PORT` (default `127.0.0.1`, `3000`) to choose where the port is published on the host. |

Sign-in (`OIDC_*`, `SESSION_*`, `AUTH_PROXY_*`) and access lists (`ADMIN_*`, `ALLOWED_EMAILS`,
`ALLOWED_EMAIL_DOMAINS`, `ALLOWED_GROUPS`, `AUTH_ALLOW_ANY_AUTHENTICATED`): see
[authentication.md](authentication.md).

### Commands (web image)

```bash
node scripts/migrate.mjs             # npm run db:migrate: apply database migrations
node scripts/settings-import.mjs     # npm run settings:import: access lists → database (--dry-run)
node scripts/secrets-reencrypt.mjs   # npm run secrets:reencrypt: after changing APP_SECRET (--dry-run)
```

## Ingest worker

| Variable | Default | Purpose |
|---|---|---|
| `IMAP_HOST`, `IMAP_USER`, `IMAP_PASSWORD` | — (required for `run`) | The reports mailbox for `run`. `serve` reads the mailboxes set up in the panel instead ([mail.md](mail.md)). |
| `IMAP_PORT` | `993` (`143` with `starttls`) | |
| `IMAP_SECURITY` | `ssl` | `ssl` (implicit TLS) or `starttls`. Certificates are always verified. |
| `IMAP_FOLDER` | `INBOX` | Folder to read. |
| `IMAP_PROCESSED_FOLDER` | — | Move stored reports here. Default: leave them in place, marked as read. |
| `IMAP_INVALID_FOLDER` | `DMARC-Invalid` | Where messages that are not DMARC reports are moved. |
| `ALLOWED_DOMAINS` | — (the list under Domains) | The domains you monitor; reports about any other domain are ignored. When set it wins over the panel's list (set it on the web app too, so the panel shows it). With neither, `run` accepts reports about **any** domain and logs a warning on every run (anyone can email a report about any domain to the mailbox), while a panel mailbox is read but stores nothing: it lists the domains it finds and holds their reports for 14 days ([mail.md](mail.md#monitored-domains)). (Unrelated to `ALLOWED_EMAIL_DOMAINS`, which is about who may sign in.) |
| `RETENTION_DAYS` | — (the panel setting; else keep forever) | Delete reports older than this on every run. `0` means forever and wins over the panel. |
| `INGEST_MIN_DATE` | — | Fixed cutoff (`YYYY-MM-DD`): older reports are never fetched or kept. |
| `INGEST_MAX_MESSAGES` | `2000` | Messages processed per run. |
| `INGEST_TIME_BUDGET_SECONDS` | `600` | Time limit for the mailbox phase of a run. |
| `INGEST_ENRICH_BUDGET_SECONDS` | `60` | Time limit for reverse-DNS lookups; `0` disables them. |
| `INGEST_PASS_BUDGET_SECONDS` | `240` | Vercel only: one call of the ingest function stops starting new work after this many seconds. Keep it below the function's `maxDuration` ([deployment.md](deployment.md#how-often-mailboxes-are-read)). |

### Commands

```bash
python -m ingestor serve            # keep running: the mailboxes set up in the panel (needs APP_SECRET)
python -m ingestor run              # mailbox → database, retention, reverse-DNS backfill
python -m ingestor import PATH...   # load .xml / .gz / .zip / .eml files or directories
python -m ingestor enrich           # reverse-DNS backfill only
```

`serve` is described in [mail.md](mail.md#running-the-worker): it runs until stopped, logs to
stderr, and exits 0 after `SIGTERM`/`SIGINT` (2 on a configuration error). The rest of this
section is about `run`, `import` and `enrich`.

Logs go to stderr. Each of these commands prints exactly one line of JSON on stdout, always with the
same fields:

| Field | Meaning |
|---|---|
| `ok` | `false` when the command failed (see exit codes) |
| `fetched` | messages or files looked at |
| `stored` | new aggregate reports written |
| `skipped` | duplicates, reports for other domains or past retention, non-aggregate reports |
| `invalid` | not a DMARC report at all |
| `enriched` | source IPs given a reverse-DNS name |
| `purged` | reports deleted by retention |
| `drained` | `run`: the mailbox was emptied (otherwise the time or message limit stopped it) |
| `already_running` | `run`: another run was in progress, so this one did nothing |
| `errors` | one entry per message or file that could not be processed |

On a fatal error the line is `{"ok": false, "error": "..."}` instead.

| Exit code | Meaning |
|---|---|
| `0` | Completed. For `run` this includes "another run was in progress" and runs where individual messages failed: those are left unread and retried next time. |
| `1` | Fatal error (mailbox or database unreachable). For `import`: also when any given file could not be loaded, or no report file was found. |
| `2` | Configuration error. |

A run that hits a fatal error is recorded as failed and shown that way on the overview page.

### How messages are handled

| Message | Result |
|---|---|
| New aggregate report for an allowed domain | stored, marked read (moved if `IMAP_PROCESSED_FOLDER` is set) |
| Report already stored, or for another domain, or past retention | skipped, marked read |
| Failure (forensic) or SMTP TLS report | skipped, marked read |
| Not a DMARC report | moved to `IMAP_INVALID_FOLDER` |
| Temporary failure storing one message | left unread; retried next run |
| Database or mailbox connection lost | the run stops and is recorded as failed; remaining messages stay unread |

Only one run proceeds at a time; a second one started while the first is active exits
immediately.

### Data stored

Per report: reporting organization, period, published policy. Per record: source IP, message
count, alignment results, header-from and envelope domains, DKIM/SPF results. Per source IP:
reverse DNS, country, network owner. No message content, subjects or recipient addresses are
stored.
