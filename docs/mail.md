# Reports mailboxes and monitored domains

DMARC reports arrive by email. The ingest worker reads them from one or more mailboxes,
keeps the reports about the domains you monitor and ignores the rest. Since 2.0 both the
mailboxes and the domain list can be set up in the browser, under **Mailboxes** and
**Monitored domains**, with no mailbox variables in the environment. The 1.1.0 way, a single
mailbox from `IMAP_*` variables read by `python -m ingestor run`, keeps working unchanged
(see [configuration.md](configuration.md#ingest-worker)).

## How it fits together

```
 browser ──► web app ──► PostgreSQL ◄── worker (python -m ingestor serve) ──► mailboxes
             (saves settings,        (reads the mailboxes on schedule,
              encrypts secrets,       carries out "Test connection" and
              queues requests)        "Run now", decrypts the secrets)
```

- The **web app never connects to a mailbox** and **cannot read a saved password, client
  secret or key**. It encrypts them under `APP_SECRET` and stores them, and the pages only show
  "set" or "not set". Only the worker decrypts them, so the worker needs the same `APP_SECRET`
  as the web app.
- **Test connection** and **Run now** are requests to the worker. The page shows "waiting for
  the worker" and updates itself when the worker has answered. If no worker is running, the
  page says so and the requests wait.

## Running the worker

```bash
DATABASE_URL=... APP_SECRET=... python -m ingestor serve
```

Run it as a long-lived service next to the web app. It is in the same image as `run`
(`docker compose` users: see [deployment.md](deployment.md#the-worker-in-serve-mode)). It:

- checks each enabled mailbox when its interval has passed (15 minutes to a day, default an
  hour), and carries out Test connection and Run now within a few seconds;
- writes a heartbeat, so the panel can say whether a worker is running;
- stops cleanly on `SIGTERM` or `SIGINT`: it finishes the message in hand, records the run as
  failed ("interrupted") and exits. The rest of the mailbox is read on the next run.

**More than one worker is safe.** Each mailbox is read by at most one run at a time (a
PostgreSQL advisory lock that disappears with the worker's connection), and each request is
taken by one worker. If a worker is killed mid-run, the next run of that mailbox records the
abandoned run as failed and carries on; requests a dead worker had taken are failed after two
minutes.

`python -m ingestor run` and `serve` can be used together: `run` reads the environment mailbox,
`serve` the panel's.

## Monitored domains

Anyone can email a report about any domain to your mailbox, so DMARCscope only keeps reports
about the domains you list under **Monitored domains**. Reports about other domains are marked
read and ignored.

- **A mailbox set up in the panel reads nothing until at least one domain is listed.** Each
  run fails with a message saying so, rather than accepting reports about any domain.
- If `ALLOWED_DOMAINS` is set (on the worker, and on the web app to show it), it wins: the
  panel shows that list read-only, and the list saved in the panel is ignored. To move to the
  panel, add the same domains there first, then remove `ALLOWED_DOMAINS` from both.
- A domain's subdomains are separate domains: add each one whose reports you want.
- `python -m ingestor run` also uses the panel's list when `ALLOWED_DOMAINS` is not set.

## Retention

**Settings → Keep reports for (days)**: reports older than this are deleted by the
worker on each run. Unset keeps reports forever. `RETENTION_DAYS` in the environment wins over
the panel, and `RETENTION_DAYS=0` means forever, as in 1.1.0.

## Mailbox kinds

Use a mailbox that receives nothing but DMARC reports: the worker marks what it reads as read,
moves non-reports to a separate folder, and (optionally) moves processed reports.

### IMAP with a password

Any IMAP server. TLS on port 993, or STARTTLS on 143. Certificates are always verified. Where
the provider offers app passwords, use one. Folder names may contain letters, digits, spaces
and `. _ - / [ ] & +`.

### Microsoft 365 (unverified)

> **Unverified.** This was built from Microsoft's documentation and tested against a local
> stand-in for Microsoft's token endpoint and an IMAP server. It has not yet been run against a
> real Microsoft 365 tenant. Please report what you find.

The worker signs in as an application (OAuth 2.0 client credentials) with the
`IMAP.AccessAsApp` permission, limited in Exchange Online to the reports mailbox. No user's
password is involved, and the app can open no other mailbox.

1. **Register the app.** In the Microsoft Entra admin center: *App registrations → New
   registration*. Name it (e.g. "DMARCscope"), single tenant, no redirect URI. Note the
   **Application (client) ID** and the **Directory (tenant) ID**.
2. **Add the permission.** *API permissions → Add a permission → APIs my organization uses →
   Office 365 Exchange Online → Application permissions → IMAP.AccessAsApp*. Then **Grant admin
   consent**.
3. **Create a client secret.** *Certificates & secrets → New client secret*. Copy the
   **value** (not the ID). Secrets expire after at most 24 months. The panel shows when you
   saved it, so put a renewal reminder in your calendar.
4. **Register the app in Exchange Online and give it the one mailbox.** In Exchange Online
   PowerShell (`Connect-ExchangeOnline`), using the *Object ID* from *Enterprise applications*
   (not the one from App registrations):

   ```powershell
   New-ServicePrincipal -AppId <application-client-id> -ObjectId <enterprise-app-object-id> -DisplayName "DMARCscope"
   Add-MailboxPermission -Identity "dmarc-reports@example.com" -User <enterprise-app-object-id> -AccessRights FullAccess
   ```

   It can take a while (Microsoft says up to an hour) before the permission works.
5. In **Mailboxes → Add a mailbox → Microsoft 365**, enter the mailbox address, tenant ID,
   client ID and the secret value, then **Test connection**.

The worker requests a token from `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`
with the scope `https://outlook.office365.com/.default` and signs in to
`outlook.office365.com:993` with `XOAUTH2`. The server is fixed for this kind, so the token is
never sent anywhere else. Errors from Microsoft are shown as they come (e.g. `invalid_client:
AADSTS7000215 …` for a wrong secret).

Sources: [Authenticate an IMAP connection using OAuth](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth),
[Add and manage app credentials](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials).

### Google Workspace (unverified)

> **Unverified.** This was built from Google's documentation and tested against a local
> stand-in for Google's token endpoint, which checks the signature, and an IMAP server. It has
> not yet been run against a real Google Workspace domain. Please report what you find.

The worker uses a service account with **domain-wide delegation** to act as the reports
mailbox.

> **This key is the most sensitive secret in the deployment.** With domain-wide delegation for
> `https://mail.google.com/`, the key can read and change *every* mailbox in your Workspace
> domain, not just the reports mailbox. Use a service account created only for this, delegate
> that one scope and nothing else, and rotate the key if it may have leaked.

1. **Create the service account.** In the Google Cloud console, in a project of your
   organization: *IAM & Admin → Service accounts → Create*. No roles are needed. Then *Keys → Add
   key → JSON* and download the key file.
2. **Enable the Gmail API** for that project (*APIs & Services → Library → Gmail API*).
3. **Delegate the scope.** In the Google Admin console (super administrator): *Security →
   Access and data control → API controls → Manage domain-wide delegation → Add new*. Enter the
   service account's **client ID** (the numeric "Unique ID") and the single scope
   `https://mail.google.com/`.
4. **Make sure IMAP is allowed** for the reports mailbox (*Apps → Google Workspace → Gmail →
   End user access*).
5. In **Mailboxes → Add a mailbox → Google Workspace**, enter the mailbox address and paste
   the whole JSON key file, then **Test connection**.

The worker signs a one-hour JWT with the key (issuer: the service account; subject: the mailbox;
audience: `https://oauth2.googleapis.com/token`), exchanges it for a token at that fixed address
(the `token_uri` in the key file is ignored) and signs in to `imap.gmail.com:993` with `XOAUTH2`.

Sources: [OAuth 2.0 for server to server applications](https://developers.google.com/identity/protocols/oauth2/service-account),
[IMAP XOAUTH2 mechanism](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol).

## Run history and problems

Each mailbox's page lists its runs: what started it (schedule or Run now), how many messages
were read, how many new reports were stored, how many were set aside (duplicates, other domains,
non-reports), and the problems. Problem texts can quote the messages they are about, which
anyone can send, so they are shortened, shown on one line and displayed as plain text.

| You see | Meaning |
|---|---|
| `no monitored domains are configured` | Add a domain under Monitored domains. |
| `the saved secret cannot be decrypted (unknown_key)` | The worker's `APP_SECRET` differs from the web app's, or `APP_SECRET` was rotated without `APP_SECRET_PREVIOUS`. Fix the variable, or save the secret again. |
| `[AUTHENTICATIONFAILED] Invalid credentials` (or similar) | Wrong user name or password. |
| `invalid_client: …`, `unauthorized_client: …`, `invalid_grant: …` | The provider refused the app's credentials or the delegation. The text after the colon is the provider's own explanation. |
| `ConnectionRefusedError`, `TimeoutError`, `SSLCertVerificationError` | The worker cannot reach the server, or its certificate does not match. |
| `interrupted: the worker was stopped …` | The worker was stopped or killed mid-run; the next run continues. |
| `database connection lost` | The run stopped; the remaining messages stay unread for the next run. |

## Security notes

- Saved mailbox secrets are encrypted with AES-256-GCM under a key derived from `APP_SECRET`
  for this purpose only, and each is bound to its mailbox. A secret copied to another row does
  not decrypt. `npm run secrets:reencrypt` covers them when rotating `APP_SECRET`
  ([configuration.md](configuration.md#secrets-in-the-database)). It is the only place outside
  the worker that decrypts them, run by an operator, never by the web app.
- A saved secret is only used where it was entered for: changing a mailbox's kind, server,
  port, security, account, tenant or application requires entering the secret again. So an
  administrator cannot point the worker, with someone else's saved password or key, at a server
  they control or at another user's mailbox.
- Who can see and change mailboxes and domains: administrators and owners. Every change,
  request and refusal is in the audit log, which records that a secret was set or replaced,
  never its value.
- An administrator chooses which host an IMAP mailbox connects to, and the worker connects
  there from its own network position. Mailboxes on private networks are allowed, since many
  self-hosted mail servers live there. Microsoft 365 and Google mailboxes always connect to
  their provider's server.
