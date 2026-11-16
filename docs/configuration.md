# Configuration reference

Everything is configured through environment variables. `.env.example` lists them with
defaults; sign-in and access settings are explained in [authentication.md](authentication.md).

## Both components

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — (required) | PostgreSQL connection string. Add `?sslmode=require` for TLS. |

## Web app

| Variable | Default | Purpose |
|---|---|---|
| `APP_URL` | `http://localhost:3000` outside production; required in production | Public URL. Used for sign-in redirects and to decide whether cookies are `Secure`. |
| `APP_NAME` | `DMARCscope` | Name shown in the header and page titles. |
| `DATABASE_POOL_MAX` | `10` | Connections per web instance. |
| `DATABASE_QUERY_TIMEOUT_MS` | `30000` | The web app abandons a query after this long and drops its connection. `0` disables. |
| `DATABASE_STATEMENT_TIMEOUT_MS` | — | Also sets PostgreSQL's `statement_timeout` on each connection. Transaction-mode poolers (PgBouncer) reject this; with one, run `ALTER ROLE <user> SET statement_timeout = '30s'` instead. |
| `INGEST_STALE_HOURS` | `36` | With no completed ingest run for this long, the overview shows a warning and `/api/cron/status` answers 503. |
| `AUTH_PROVIDER` | — (required) | `oidc`, `proxy-jwt`, `proxy-header` or `none`. |
| `CRON_SECRET` | — | Bearer token for `/api/cron/*`; at least 16 characters. Endpoints are closed while unset. |
| `PORT`, `HOSTNAME` | `3000`, `0.0.0.0` (container) | Listen address. Docker Compose fixes these inside the container; use `WEB_BIND` / `WEB_PORT` (default `127.0.0.1`, `3000`) to choose where the port is published on the host. |

Sign-in (`OIDC_*`, `SESSION_*`, `AUTH_PROXY_*`) and access lists (`ADMIN_*`, `ALLOWED_EMAILS`,
`ALLOWED_EMAIL_DOMAINS`, `ALLOWED_GROUPS`, `AUTH_ALLOW_ANY_AUTHENTICATED`): see
[authentication.md](authentication.md).

## Ingest worker

| Variable | Default | Purpose |
|---|---|---|
| `IMAP_HOST`, `IMAP_USER`, `IMAP_PASSWORD` | — (required for `run`) | The reports mailbox. |
| `IMAP_PORT` | `993` (`143` with `starttls`) | |
| `IMAP_SECURITY` | `ssl` | `ssl` (implicit TLS) or `starttls`. Certificates are always verified. |
| `IMAP_FOLDER` | `INBOX` | Folder to read. |
| `IMAP_PROCESSED_FOLDER` | — | Move stored reports here. Default: leave them in place, marked as read. |
| `IMAP_INVALID_FOLDER` | `DMARC-Invalid` | Where messages that are not DMARC reports are moved. |
| `ALLOWED_DOMAINS` | — (all) | The domains you monitor; reports about any other domain are ignored. **Set this in production**: anyone can email a report about any domain to the mailbox, and without this list that domain appears on the dashboard and gets DNS-checked. The worker logs a warning on every run while it is unset. (Unrelated to `ALLOWED_EMAIL_DOMAINS`, which is about who may sign in.) |
| `RETENTION_DAYS` | — (keep forever) | Delete reports older than this on every run. |
| `INGEST_MIN_DATE` | — | Fixed cutoff (`YYYY-MM-DD`): older reports are never fetched or kept. |
| `INGEST_MAX_MESSAGES` | `2000` | Messages processed per run. |
| `INGEST_TIME_BUDGET_SECONDS` | `600` | Time limit for the mailbox phase of a run. |
| `INGEST_ENRICH_BUDGET_SECONDS` | `60` | Time limit for reverse-DNS lookups; `0` disables them. |

### Commands

```bash
python -m ingestor run              # mailbox → database, retention, reverse-DNS backfill
python -m ingestor import PATH...   # load .xml / .gz / .zip / .eml files or directories
python -m ingestor enrich           # reverse-DNS backfill only
```

Logs go to stderr. Each command prints exactly one line of JSON on stdout, always with the
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
