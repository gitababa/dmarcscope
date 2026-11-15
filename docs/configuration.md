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
| `DATABASE_POOL_MAX` | `5` | Connections per web instance. |
| `AUTH_PROVIDER` | — (required) | `oidc`, `proxy-jwt`, `proxy-header` or `none`. |
| `CRON_SECRET` | — | Bearer token for `/api/cron/*`; at least 16 characters. Endpoints are closed while unset. |
| `PORT`, `HOSTNAME` | `3000`, `0.0.0.0` (container) | Listen address. |

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
| `ALLOWED_DOMAINS` | — (all) | Only store reports about these domains. Recommended. |
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

Each prints one line of JSON with the run's counters and exits non-zero on a fatal error
(mailbox or database unreachable). Individual messages that fail are recorded on the run and
left unread, so the next run retries them.

### How messages are handled

| Message | Result |
|---|---|
| New aggregate report for an allowed domain | stored, marked read (moved if `IMAP_PROCESSED_FOLDER` is set) |
| Report already stored, or for another domain, or past retention | skipped, marked read |
| Failure (forensic) or SMTP TLS report | skipped, marked read |
| Not a DMARC report | moved to `IMAP_INVALID_FOLDER` |
| Temporary failure (database error, …) | left unread; retried next run |

Only one run proceeds at a time; a second one started while the first is active exits
immediately.

### Data stored

Per report: reporting organization, period, published policy. Per record: source IP, message
count, alignment results, header-from and envelope domains, DKIM/SPF results. Per source IP:
reverse DNS, country, network owner. No message content, subjects or recipient addresses are
stored.
