# Deployment

DMARCscope is three things, and they can run anywhere:

| Piece | Image / command | Notes |
|---|---|---|
| PostgreSQL 13+ | any managed or self-hosted instance | UTF-8 database |
| Web app | `Dockerfile` → `node server.js`, port 3000 | stateless; scale horizontally |
| Ingest worker | `Dockerfile.ingest` → `python -m ingestor run` | one-shot job; schedule it (daily is enough) |

Plus two one-off or scheduled calls:

- **Migrations** — `node scripts/migrate.mjs` in the web image (or `npm run db:migrate` from a
  checkout). Idempotent; run it on every release before the new web version starts. Use a
  direct database connection for it, not a transaction-mode pooler.
- **Scheduled DNS checks** (optional, recommended) — `GET /api/cron/dns-check` with
  `Authorization: Bearer $CRON_SECRET` refreshes the DNS health of every domain, which keeps
  the SPF attribution on the Issues page current.

- **Ingest monitoring** (recommended) — `GET /api/cron/status` with the same bearer token
  answers `200` while an ingest run has completed in the last `INGEST_STALE_HOURS` (default
  36) and `503` otherwise. The dashboard keeps working on old data when the job stops, so
  point an uptime monitor at this to hear about it; the overview page shows a warning too.

Terminate TLS in front of the web app and set `APP_URL` to the public https URL.

Probes: `GET /api/healthz` (liveness) and `GET /api/readyz` (database reachable).

On a large database, cap query time in PostgreSQL as well:
`ALTER ROLE <app user> SET statement_timeout = '30s'` (see `DATABASE_QUERY_TIMEOUT_MS` in
[configuration.md](configuration.md)).

## Docker Compose (single host)

```bash
cp .env.example .env        # set APP_URL, APP_SECRET, IMAP_*; AUTH_PROVIDER and access lists if you use them
docker compose up -d --build
```

This runs PostgreSQL, applies migrations, and serves the dashboard on `127.0.0.1:3000`. Put a
TLS reverse proxy (Caddy, nginx, Traefik) on the same host in front of it. To publish the port
on another address or port, set `WEB_BIND` / `WEB_PORT` in `.env`.

Schedule the jobs from the host's crontab:

```cron
0 6 * * *   cd /opt/dmarcscope && docker compose run --rm ingest
30 6 * * *  curl -fsS -H "Authorization: Bearer $CRON_SECRET" https://dmarc.example.com/api/cron/dns-check
```

Set `POSTGRES_PASSWORD` in `.env` before the first start (letters and digits only — it is
placed in a connection URL), and back up the `pgdata` volume.

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
          image: registry.example.com/dmarcscope:1.0.0
          command: ['node', 'scripts/migrate.mjs']
          envFrom: [{ secretRef: { name: dmarcscope } }]
      containers:
        - name: web
          image: registry.example.com/dmarcscope:1.0.0
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
              image: registry.example.com/dmarcscope-ingest:1.0.0
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

The repository is also deployable to Vercel as-is: the Next.js app, plus the ingest worker as
a Python function (`api/cron/ingest.py`) triggered by the crons in `vercel.json`.

1. Import the repository and attach a PostgreSQL database (any provider; set `DATABASE_URL`).
2. Set the environment variables from `.env.example`, including a `CRON_SECRET` you generate
   yourself (`openssl rand -hex 32`). Vercel sends it as the bearer token on every cron
   call; without it the crons are answered with 401.
3. Apply migrations from your machine: `DATABASE_URL=… npm run db:migrate`.

Keep `CRON_SECRET` in Vercel's environment even though the owner can also set a machine endpoint
token in the panel: Vercel Cron sends the environment variable, and the Python ingest function
reads its configuration from the environment only.

Vercel functions have a hard time limit, so the function variant of the ingest job defaults
to a 170-second mailbox budget per run; a large backlog is worked through over several runs.

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
   `0005` only add tables, columns and indexes (users, settings, access rules, audit log, setup
   tokens, invitations, single sign-on connections); they change no existing data.
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
     those variables can be removed.

Rolling back to 1.1.x after step 3 works: 1.1.x ignores the new tables.

### Starting fresh with 2.0

Set `DATABASE_URL`, `APP_URL` and `APP_SECRET`, run the migrations and start the web app. Its log
prints a one-time setup token; open `/setup` and create the owner account.
