# Deployment

DMARCscope is three things, and they can run anywhere:

| Piece | Image / command | Notes |
|---|---|---|
| PostgreSQL 13+ | any managed or self-hosted instance | UTF-8 database |
| Web app | `Dockerfile` → `node server.js`, port 3000 | stateless; scale horizontally |
| Ingest worker | `Dockerfile.ingest` → `python -m ingestor serve` | long-running; reads the mailboxes set up in the panel ([mail.md](mail.md)) |
| or, as in 1.1 | `Dockerfile.ingest` → `python -m ingestor run` | one-shot job for the mailbox in `IMAP_*`; schedule it (daily is enough) |

Plus two one-off or scheduled calls:

- **Migrations** — `node scripts/migrate.mjs` in the web image (or `npm run db:migrate` from a
  checkout). Idempotent; run it on every release before the new web version starts. Use a
  direct database connection for it, not a transaction-mode pooler.
- **Scheduled DNS checks** (optional, recommended) — `GET /api/cron/dns-check` with
  `Authorization: Bearer $CRON_SECRET` refreshes the DNS health of every domain, which keeps
  the SPF attribution on the Issues page current.

- **Alerts** (serverless only) — `GET /api/cron/alerts` with the same bearer token every five
  minutes evaluates the alert rules and sends what is due ([alerts.md](alerts.md)). A
  long-running web app does this itself on a timer.
- **Ingest monitoring** (recommended) — `GET /api/cron/status` with the same bearer token
  answers `200` while an ingest run has completed in the last `INGEST_STALE_HOURS` (default
  36) and `503` otherwise. The dashboard keeps working on old data when the job stops, so
  point an uptime monitor at this to hear about it; the overview page shows a warning too.

Terminate TLS in front of the web app and set `APP_URL` to the public https URL.

Probes: `GET /api/healthz` (liveness) and `GET /api/readyz` (database reachable).

On a large database, cap query time in PostgreSQL as well:
`ALTER ROLE <app user> SET statement_timeout = '30s'` (see `DATABASE_QUERY_TIMEOUT_MS` in
[configuration.md](configuration.md)).

## First start: create the owner

Every deployment ends the same way: open the app and create the owner account.

1. Open `https://<your APP_URL>/`. With no owner yet, it sends you to **/setup**.
2. Enter the **setup token**. The app writes it to its **server log** when it starts (and when
   `/setup` is opened while there is none), never to the page, so only someone who runs the
   server can create the owner. Search the log for `[setup]`:

   | Platform | Where |
   |---|---|
   | Docker Compose | `docker compose logs web \| grep setup` |
   | Kubernetes | `kubectl logs deploy/dmarcscope-web \| grep setup` |
   | Vercel | the project → **Logs**, search `[setup]` (the Hobby plan keeps one hour of logs) |
   | Cloud Run | the service → **Logs** |

   Missed it, or the log is gone? Press **Write a new token to the log** on `/setup` and look
   again. Earlier tokens keep working, each is valid for 24 hours, and the page tells you when
   the newest one was written. Or choose the token yourself: set `SETUP_TOKEN` (24 characters
   or more, e.g. `openssl rand -hex 16`) and restart or redeploy.
3. Enter your email address and a password, then scan the QR code with an authenticator app.
4. Save the ten **recovery codes** you are shown, once.

Then, in the app: add the domains you monitor (**Monitored domains**), connect the reports
mailbox (**Mailboxes**, or the `IMAP_*` variables on Vercel), and publish a DMARC record for
each domain that sends reports to that mailbox (see the README). Reports arrive within a day
or two.

## Docker Compose (single host)

```bash
cp .env.example .env
# In .env, set at least:
#   APP_URL            the public https address, e.g. https://dmarc.example.com
#   APP_SECRET         openssl rand -base64 32
#   CRON_SECRET        openssl rand -hex 32
#   POSTGRES_PASSWORD  letters and digits only
docker compose up -d --build
docker compose --profile serve up -d     # the worker that reads the mailboxes set up in the app
docker compose logs web | grep setup     # the setup token, for the first start
```

This runs PostgreSQL, applies migrations, serves the dashboard on `127.0.0.1:3000`, and runs the
worker that reads the mailboxes you add under **Mailboxes**. Put a TLS reverse proxy (Caddy,
nginx, Traefik) on the same host in front of it. To publish the port on another address or
port, set `WEB_BIND` / `WEB_PORT` in `.env`. Then [create the owner](#first-start-create-the-owner).

### The worker in serve mode

The `serve` profile above is the long-running worker that reads the mailboxes set up in the
browser. It needs `APP_SECRET` in `.env`, the same one the web app uses. It stops cleanly on
`docker compose stop` (it finishes the message in hand). It is a separate profile so that a 1.1
setup without `APP_SECRET` keeps starting exactly as before.

### Scheduled jobs

DNS checks keep each domain's DNS health and SPF attribution current. With the mailbox in
`IMAP_*` (1.1 style) instead of the browser, schedule the ingest job too. From the host's crontab:

```cron
0 6 * * *   cd /opt/dmarcscope && docker compose run --rm ingest
30 6 * * *  curl -fsS -H "Authorization: Bearer $CRON_SECRET" https://dmarc.example.com/api/cron/dns-check
```

Set `POSTGRES_PASSWORD` before the first start (it is placed in a connection URL, hence letters
and digits only), and back up the `pgdata` volume.

## Kubernetes

A minimal layout — adapt names, registry and secret management to your cluster. Configuration
lives in a Secret named `dmarcscope` whose keys are the environment variables from
`.env.example`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: dmarcscope-web }
spec:
  replicas: 2
  selector: { matchLabels: { app: dmarcscope-web } }
  template:
    metadata: { labels: { app: dmarcscope-web } }
    spec:
      securityContext: { runAsNonRoot: true, seccompProfile: { type: RuntimeDefault } }
      initContainers:
        - name: migrate
          image: registry.example.com/dmarcscope:2.0.0
          command: ['node', 'scripts/migrate.mjs']
          envFrom: [{ secretRef: { name: dmarcscope } }]
      containers:
        - name: web
          image: registry.example.com/dmarcscope:2.0.0
          ports: [{ containerPort: 3000 }]
          envFrom: [{ secretRef: { name: dmarcscope } }]
          readinessProbe: { httpGet: { path: /api/readyz, port: 3000 } }
          livenessProbe: { httpGet: { path: /api/healthz, port: 3000 } }
          securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
          resources: { requests: { cpu: 100m, memory: 192Mi }, limits: { memory: 512Mi } }
---
apiVersion: v1
kind: Service
metadata: { name: dmarcscope-web }
spec:
  selector: { app: dmarcscope-web }
  ports: [{ port: 80, targetPort: 3000 }]
---
# The worker that reads the mailboxes set up in the browser. One replica is
# enough; more are safe.
apiVersion: apps/v1
kind: Deployment
metadata: { name: dmarcscope-worker }
spec:
  replicas: 1
  selector: { matchLabels: { app: dmarcscope-worker } }
  template:
    metadata: { labels: { app: dmarcscope-worker } }
    spec:
      securityContext: { runAsNonRoot: true, seccompProfile: { type: RuntimeDefault } }
      containers:
        - name: worker
          image: registry.example.com/dmarcscope-ingest:2.0.0
          args: ['serve']
          envFrom: [{ secretRef: { name: dmarcscope } }]
          securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
          resources: { requests: { cpu: 50m, memory: 192Mi }, limits: { memory: 1Gi } }
---
# Only for a mailbox in IMAP_* (1.1 style) instead of the browser.
apiVersion: batch/v1
kind: CronJob
metadata: { name: dmarcscope-ingest }
spec:
  schedule: '0 6 * * *'
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          securityContext: { runAsNonRoot: true, seccompProfile: { type: RuntimeDefault } }
          containers:
            - name: ingest
              image: registry.example.com/dmarcscope-ingest:2.0.0
              envFrom: [{ secretRef: { name: dmarcscope } }]
              securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
              resources: { requests: { cpu: 100m, memory: 256Mi }, limits: { memory: 1Gi } }
```

Both images run as a numeric non-root user (1000 for the web app, 10001 for the worker), which
is what `runAsNonRoot` checks. A Secret holds values literally, so do not copy the comment
lines from `.env.example` into it.

Expose the Service through your Ingress with TLS. The advisory lock in the migration runner
makes it safe for several replicas to start at once. The ingest worker needs outbound access
to the IMAP server, the database, and DNS (for reverse lookups).

## Google Cloud (Cloud Run + Cloud SQL + IAP)

1. **Database** — Cloud SQL for PostgreSQL. Connect over the Cloud SQL socket:

   ```
   DATABASE_URL=postgresql://USER:PASSWORD@/dmarcscope?host=/cloudsql/PROJECT:REGION:INSTANCE
   ```

   (or a private IP with `?sslmode=require`). Keep `DATABASE_URL`, `IMAP_PASSWORD` and
   `CRON_SECRET` in Secret Manager and mount them as environment variables.
2. **Web app** — build `Dockerfile`, push to Artifact Registry, deploy as a Cloud Run service
   with the Cloud SQL instance attached. Run migrations as a Cloud Run job using the same
   image with the command `node scripts/migrate.mjs`.
3. **Sign-in** — enable Identity-Aware Proxy for the service (directly on Cloud Run, or on the
   load balancer in front of it) and configure
   `AUTH_PROVIDER=proxy-jwt`, `AUTH_PROXY_PRESET=gcp-iap`, `AUTH_PROXY_AUDIENCE=…` as described
   in [authentication.md](authentication.md). Restrict the service's ingress so it is only
   reachable through IAP.
4. **Ingest** — build `Dockerfile.ingest`, deploy as a Cloud Run **job**, and trigger it daily
   with Cloud Scheduler.
5. **DNS checks** — a second Cloud Scheduler job calling `/api/cron/dns-check` with the bearer
   token. Because IAP protects the public URL, either call the service's internal URL or grant
   the scheduler's service account access through IAP.

The same shape works on AWS (ECS/Fargate service + scheduled task + RDS) and Azure (Container
Apps + Container Apps job + Azure Database for PostgreSQL).

## Vercel

The repository deploys to Vercel as-is: the Next.js app, plus the ingest worker as a Python
function (`api/cron/ingest.py`) that Vercel Cron calls once a day (`vercel.json`).

**One difference from the other platforms:** Vercel cannot run the long-lived worker that reads
the mailboxes you set up in the browser. On Vercel the reports mailbox goes in **environment
variables** (`IMAP_*`), and the daily cron reads it. Everything else (domains, people, alerts,
settings) is set up in the browser as usual.

1. **Import the repository** in Vercel (*Add New → Project*). The defaults are right.
2. **Add a database.** *Storage → Create → Neon* (or any PostgreSQL), connected to the project.
   It sets `DATABASE_URL` and `DATABASE_URL_UNPOOLED` for you.
3. **Set the environment variables** (*Settings → Environment Variables*, Production):

   | Variable | Value |
   |---|---|
   | `APP_URL` | the production address, e.g. `https://dmarcscope-you.vercel.app` |
   | `APP_SECRET` | `openssl rand -base64 32` — keep a copy: secrets saved in the app need it |
   | `CRON_SECRET` | `openssl rand -hex 32` — Vercel Cron sends it; without it the crons get 401 |
   | `IMAP_HOST`, `IMAP_USER`, `IMAP_PASSWORD` | the reports mailbox, e.g. `imap.gmail.com`, the address, an [app password](mail.md#imap-with-a-password) |

4. **Create the tables** once, and again after each upgrade, from a checkout of the same
   version, with the *unpooled* connection string (*Storage → your database → .env.local*):

   ```bash
   DATABASE_URL='postgres://…unpooled…' npm run db:migrate
   ```

5. **Redeploy** (*Deployments → ⋯ → Redeploy*) so the variables take effect, then
   [create the owner](#first-start-create-the-owner). The token is in the project's **Logs**;
   the Hobby plan keeps an hour of them, so if it is gone, press **Write a new token to the log**
   on `/setup`.
6. In the app, add your domains under **Monitored domains**, **before the first daily run**:
   the cron keeps only reports about the listed domains, but while the list is empty it keeps
   reports about *any* domain (anyone can email one to your mailbox). `ALLOWED_DOMAINS`, if set,
   wins over the list.

Good to know:

- The crons run daily: ingest at 06:00, DNS checks at 06:30, alerts at 07:00 UTC. That is what
  the Hobby plan allows. Reports are not urgent, so daily is enough; for faster alerts see
  [alerts.md](alerts.md).
- The ingest function stops reading after about 170 seconds per run (Vercel's time limit); a
  large backlog is worked through over several days.
- Vercel's *Deployment Protection* puts preview deployments behind a Vercel sign-in. The
  production address is reachable, and protected by the app's own sign-in.
- `CRON_SECRET` stays in Vercel's environment even though the owner can also set a machine
  endpoint token in the app: Vercel Cron sends the environment variable, and the Python function
  reads its configuration from the environment only.

## Upgrades and backups

- Upgrade by deploying the new images and running the migration command. Migrations only move
  forward.
- All state is in PostgreSQL. Back it up with your usual tooling. The data can also be rebuilt
  from the report emails if you keep them (`IMAP_PROCESSED_FOLDER`). Back up `APP_SECRET` too:
  without it, the secrets saved in the panel cannot be decrypted.
- The ingest job is idempotent: re-processing a report is a no-op.

### From 1.1.x to 2.0

Nothing in the environment has to change.

1. Back up the database.
2. Run the migrations with the new image (`node scripts/migrate.mjs`). Migrations `0003` to
   `0006` only add tables, columns and indexes (users, settings, access rules, audit log, setup
   tokens, invitations, single sign-on connections, mailboxes, monitored domains, worker
   requests and heartbeats, and two columns on `ingest_runs`); they change no existing data.
3. Deploy the new web image with the **same environment**. Sign-in, the access lists, the
   machine endpoints and the dashboards behave exactly as before, and existing sessions stay
   valid. People who sign in from now on are recorded in the users table, and the request gate
   reads their role from the database on every request (one indexed query).
4. Optional, to manage things in the browser from now on:
   - add `APP_SECRET` (`openssl rand -base64 32`) and open `/setup` with the one-time setup token
     the new version printed to its log when it first started (after 24 hours it expires; a
     restart, or opening `/setup`, prints a new one). The wizard creates the owner account (see
     [authentication.md](authentication.md#first-run-the-setup-wizard));
   - run `node scripts/settings-import.mjs` to copy `ADMIN_EMAILS`, `ALLOWED_EMAILS`,
     `ALLOWED_EMAIL_DOMAINS`, `ADMIN_GROUPS` and `ALLOWED_GROUPS` into the database, after which
     those variables can be removed;
   - move the mailbox into the panel: add the domains from `ALLOWED_DOMAINS` under Monitored
     domains, add the mailbox under Mailboxes, run `python -m ingestor serve` instead of the
     scheduled `run`, then remove `ALLOWED_DOMAINS` and `IMAP_*` ([mail.md](mail.md)). The
     scheduled `run` keeps working unchanged if you leave it.

Rolling back to 1.1.x after step 3 works: 1.1.x ignores the new tables.

### Starting fresh with 2.0

Set `DATABASE_URL`, `APP_URL` and `APP_SECRET`, run the migrations and start the web app. Its log
prints a one-time setup token; open `/setup` and create the owner account. Then start the worker
with `python -m ingestor serve` (same `DATABASE_URL` and `APP_SECRET`), add your domains under
Monitored domains and your reports mailbox under Mailboxes.
