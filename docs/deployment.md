# Deployment

DMARCscope is three things, and they can run anywhere:

| Piece | Image / command | Notes |
|---|---|---|
| PostgreSQL 13+ | any managed or self-hosted instance | UTF-8 database |
| Web app | `Dockerfile` → `node server.js`, port 3000 | stateless; scale horizontally |
| Ingest worker | `Dockerfile.ingest` → `python -m ingestor serve` | long-running; reads the mailboxes set up in the panel ([mail.md](mail.md)). On Vercel, a function instead ([Vercel](#vercel)) |
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
4. **Ingest** — build `Dockerfile.ingest` and deploy a Cloud Run **job** with the command
   `python -m ingestor pass`, the same `APP_SECRET` as the web app, and Cloud Scheduler starting
   it every 15 to 60 minutes. Each run is one bounded pass: the mailbox in `IMAP_*` if one is
   set, waiting **Test connection** and **Run now** requests, then the mailboxes set up in the
   app that are due. So requests made in the app are carried out at the next call. A job task
   may run 10 minutes by default; keep the pass inside it:

   ```bash
   gcloud run jobs deploy dmarcscope-ingest --image …/dmarcscope-ingest \
     --args pass --task-timeout 10m --memory 512Mi \
     --set-env-vars INGEST_PASS_BUDGET_SECONDS=540,INGEST_TIME_BUDGET_SECONDS=420
   ```

   (`python -m ingestor run`, the earlier setup, reads only the mailbox in `IMAP_*`.)
5. **DNS checks and alerts** — two more Cloud Scheduler jobs calling `/api/cron/dns-check`
   (daily) and `/api/cron/alerts` (every five minutes) with the bearer token; Cloud Run scales
   the web app to zero, so it cannot time alerts itself. With the ingest job that is three
   scheduler jobs, the free allowance per billing account. Because IAP protects the public URL,
   either call the service's internal URL or grant the scheduler's service account access
   through IAP.

The same shape works on AWS (ECS/Fargate service + scheduled task running `pass` + RDS) and
Azure (Container Apps + Container Apps job running `pass` + Azure Database for PostgreSQL).

The app has a **Deployment guide** (in the sidebar, for administrators, and on the setup page)
with these steps per platform, and resource and schedule recommendations for your number of
report emails a day.

## Vercel

The repository deploys to Vercel as-is: the Next.js app, plus the ingest worker as a Python
function (`api/cron/ingest.py`). Vercel has no long-running processes, so instead of the
`serve` worker, each call of that function does one bounded pass: it reads the mailboxes that
are due, answers waiting **Test connection** and **Run now** requests, and imports held reports
of newly monitored domains. Three things call it:

- **Test connection** and **Run now** in the app: the app calls the function straight away, so
  a test answers within seconds and a run starts at once, on any plan.
- **Vercel Cron**, on the schedule in `vercel.json` (once a day as shipped; see
  [How often mailboxes are read](#how-often-mailboxes-are-read)).
- Optionally, any other scheduler, with the machine token.

1. **Import the repository** in Vercel (*Add New → Project*). The defaults are right.
2. **Add a database.** *Storage → Create → Neon* (or any PostgreSQL), connected to the project.
   It sets `DATABASE_URL` and `DATABASE_URL_UNPOOLED` for you.
3. **Set the environment variables** (*Settings → Environment Variables*). Set them for
   **all environments** (Production and Preview): the app and the ingest function must have the
   same `APP_SECRET`.

   | Variable | Value |
   |---|---|
   | `APP_URL` | the production address, e.g. `https://dmarc.example.com` |
   | `APP_SECRET` | `openssl rand -base64 32`. Keep a copy: secrets saved in the app (mailbox passwords) need it |
   | `CRON_SECRET` | `openssl rand -hex 32`. Vercel Cron sends it; without it the scheduled calls get 401 |

4. **Redeploy** (*Deployments → ⋯ → Redeploy*) so the variables take effect. Every
   production build creates and updates the tables itself, before the new version goes live
   (see [Migrations on Vercel](#migrations-on-vercel)). Then
   [create the owner](#first-start-create-the-owner). The token is in the project's **Logs**;
   the Hobby plan keeps an hour of them, so if it is gone, press **Write a new token to the log**
   on `/setup`.
5. **Add the reports mailbox** under **Mailboxes** ([mail.md](mail.md)) and press **Test
   connection**. Then **Run now**.
6. **Choose your domains** under **Domains**. Until you monitor one, mailboxes are read but
   nothing is stored: every domain the reports are about is listed there, with its reports held
   for 14 days, and **Monitor** imports them.

### Migrations on Vercel

The build command (`vercel.json` → `buildCommand`, `scripts/vercel-build.mjs`) applies pending
migrations, then builds:

- **Production builds only.** A preview build may contain migrations that are not merged, so
  it never touches the database, even when previews share the production one.
- **Over the direct connection**: `DATABASE_URL_UNPOOLED` (which the Neon integration sets), else
  `POSTGRES_URL_NON_POOLING`, else `DATABASE_URL`.
- **A failed migration fails the build**, so the new version does not go live and the previous
  deployment keeps serving. The build log shows the error.
- **Before a database is connected** (the very first build), it skips the migrations and says
  so; the redeploy after adding the database runs them.
- `MIGRATE_ON_BUILD=0` turns this off; then run `npm run db:migrate` from a checkout with the
  unpooled connection string after each upgrade.

Migrations only add tables and columns, so the previous deployment keeps working against the
new schema while the new one builds, and an instant rollback in Vercel is safe.

### How often mailboxes are read

What Vercel allows depends on the plan (Vercel's
[cron limits](https://vercel.com/docs/cron-jobs/usage-and-pricing) and
[function limits](https://vercel.com/docs/functions/limitations), checked November 2026):

| | Hobby | Pro and Enterprise |
|---|---|---|
| Cron schedule in `vercel.json` | at most once a day, at any minute of the scheduled hour | as often as every minute, on the minute |
| A schedule more frequent than that | the **deployment fails** ("Hobby accounts are limited to daily cron jobs") | — |
| Function time limit | 300 s | 300 s by default, up to 800 s |

`vercel.json` ships with the daily schedule (ingest at 06:00, DNS checks at 06:30, alerts at
07:00 UTC), because it is the only one that deploys on every plan. A mailbox's interval setting
cannot make it read more often than the schedule calls; the Mailboxes page shows how often
scheduled calls actually happen, and warns about a mailbox set to more than that.

- **On Hobby**, daily is what Vercel Cron can do, and for DMARC reports (sent once a day) it is
  enough. **Run now** reads a mailbox at any time. To read more often anyway, call the function
  from another scheduler (below).
- **On Pro**, change the ingest schedule in your copy of `vercel.json`, e.g. every 15 minutes,
  and deploy:

  ```json
  { "path": "/api/cron/ingest", "schedule": "*/15 * * * *" }
  ```

  Each call reads only the mailboxes whose interval has passed. Don't merge that change into a
  copy that deploys on a Hobby account: its deployments would fail.
- **Another scheduler** (any plan): GitHub Actions, cron-job.org, or a cron job on any machine
  can call `GET https://<your app>/api/cron/ingest` with `Authorization: Bearer <CRON_SECRET>`.
  For example, a workflow in your copy of the repository:

  ```yaml
  on:
    schedule: [{ cron: '*/30 * * * *' }]
  jobs:
    ingest:
      runs-on: ubuntu-latest
      steps:
        - run: curl -fsS -H "Authorization: Bearer ${{ secrets.CRON_SECRET }}" https://dmarc.example.com/api/cron/ingest
  ```

**Time limit.** One call stops starting new work after 240 seconds
(`INGEST_PASS_BUDGET_SECONDS`), and one mailbox run reads mail for at most 170 seconds
(`INGEST_TIME_BUDGET_SECONDS`), so every call ends within the 300 seconds every plan allows. A
mailbox that does not fit waits for the next call, and a large backlog is worked through over
several. On Pro, to get through a backlog faster, raise the function's `maxDuration` in
`vercel.json` (up to 800) and both budgets to match, e.g. 700 and 600.

**Deployment Protection.** The app calls its own function at the production domain
(`VERCEL_PROJECT_PRODUCTION_URL`), which Vercel's Standard Protection leaves open. On preview
deployments, and if you protect production too (a Pro option), the call would be refused: add a
**Protection Bypass for Automation** secret (*Settings → Deployment Protection*) and redeploy;
the app sends it. When a call is refused, the request in the app says so instead of waiting.

Good to know:

- **The mailbox in environment variables still works.** `IMAP_HOST`, `IMAP_USER` and
  `IMAP_PASSWORD` (the earlier setup) are read on every scheduled call. That mailbox keeps
  reports about *any* domain while no domain is monitored (anyone can email one), so add your
  domains first. `ALLOWED_DOMAINS`, if set, wins over the list in the app.
- `CRON_SECRET` stays in Vercel's environment even though the owner can also set a machine
  endpoint token in the app: Vercel Cron sends the environment variable, and the Python function
  reads its configuration from the environment only. The app's own calls to the function are
  signed with `APP_SECRET` instead.
- Vercel calls cron jobs a legacy feature that will move to *Schedules* (in beta). `vercel.json`
  crons keep working; nothing in the app depends on which one calls it.

## Upgrades and backups

- Upgrade by deploying the new images and running the migration command. Migrations only move
  forward. On Vercel, production builds run them ([Migrations on Vercel](#migrations-on-vercel)).
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
