// The in-app deployment guide: the steps of docs/deployment.md per platform,
// shortened. Plain text with `code` in backticks (components/deploy-guide.tsx
// renders it); nothing here is HTML. Keep in step with docs/deployment.md.

import type { PlatformId } from './sizing'

export type GuideStep = { title: string; body: string; code?: string }

export type Platform = {
  id: PlatformId
  name: string
  summary: string
  steps: GuideStep[]
  docs: string // section of docs/deployment.md
}

const MIGRATE = 'Run the migrations once, and again before each upgrade starts: `node scripts/migrate.mjs` in the web image (or `npm run db:migrate` from a checkout).'

export const PLATFORMS: Platform[] = [
  {
    id: 'vercel',
    name: 'Vercel',
    summary: 'The web app plus the ingest worker as a Python function. No server to run; Neon (or any PostgreSQL) for the database.',
    docs: 'Vercel',
    steps: [
      { title: 'Import and add a database', body: 'Import the repository (Add New → Project; the defaults are right), then Storage → Create → Neon. It sets `DATABASE_URL` and `DATABASE_URL_UNPOOLED`.' },
      {
        title: 'Environment variables, for all environments',
        body: 'Settings → Environment Variables. The web app and the ingest function must share `APP_SECRET`, so set each one for Production and Preview. Keep a copy of `APP_SECRET`: saved mailbox passwords need it. Generate the two secrets with the commands shown.',
        code: 'APP_URL      https://dmarc.example.com\nAPP_SECRET   the output of: openssl rand -base64 32\nCRON_SECRET  the output of: openssl rand -hex 32',
      },
      {
        title: 'Redeploy',
        body: 'Deployments → ⋯ → Redeploy, so the variables take effect. Each production build creates and updates the tables itself before it goes live (preview builds never touch the database). A failed migration fails the build, and the previous version keeps serving.',
      },
      { title: 'Add the mailbox, then choose domains', body: 'Mailboxes → Add, then Test connection (answers in seconds) and Run now. Then Domains → Monitor on yours.' },
    ],
  },
  {
    id: 'docker',
    name: 'Docker Compose',
    summary: 'One server runs PostgreSQL, the web app and the worker. Put a TLS reverse proxy (Caddy, nginx, Traefik) in front.',
    docs: 'Docker Compose (single host)',
    steps: [
      {
        title: 'Configure',
        body: 'Copy the example and set at least these in `.env`. `POSTGRES_PASSWORD` goes into a connection URL: letters and digits only.',
        code: 'cp .env.example .env\n# APP_URL, APP_SECRET (openssl rand -base64 32),\n# CRON_SECRET (openssl rand -hex 32), POSTGRES_PASSWORD',
      },
      { title: 'Start everything', body: 'Migrations run on start. The `serve` profile is the worker that reads the mailboxes set up here.', code: 'docker compose up -d --build\ndocker compose --profile serve up -d' },
      { title: 'DNS checks (recommended)', body: 'From the host crontab, once a day:', code: '30 6 * * *  curl -fsS -H "Authorization: Bearer $CRON_SECRET" https://dmarc.example.com/api/cron/dns-check' },
      { title: 'Back up', body: 'Back up the `pgdata` volume, e.g. a nightly `pg_dump`.' },
    ],
  },
  {
    id: 'kubernetes',
    name: 'Kubernetes',
    summary: 'A web Deployment (scale freely) and a worker Deployment running `serve`, configured from one Secret. Any PostgreSQL.',
    docs: 'Kubernetes',
    steps: [
      { title: 'Secret', body: 'A Secret named `dmarcscope` whose keys are the variables from `.env.example` (`DATABASE_URL`, `APP_URL`, `APP_SECRET`, `CRON_SECRET`, …). Values only, no comment lines.' },
      { title: 'Web', body: 'Image from `Dockerfile`, port 3000, with an init container running the migrations (an advisory lock makes several replicas safe). Probes: `/api/readyz` and `/api/healthz`.' },
      { title: 'Worker', body: 'Image from `Dockerfile.ingest` with `args: [serve]`. One replica is enough; more are safe. It needs outbound access to the IMAP server, the database and DNS.' },
      { title: 'Expose and schedule', body: 'Expose the Service through your Ingress with TLS. A CronJob calling `/api/cron/dns-check` with the bearer token keeps DNS health current.' },
    ],
  },
  {
    id: 'cloudrun',
    name: 'Google Cloud Run',
    summary: 'The web app as a Cloud Run service, the worker as a Cloud Run job started by Cloud Scheduler, Cloud SQL for PostgreSQL. AWS (ECS) and Azure (Container Apps) take the same shape.',
    docs: 'Google Cloud (Cloud Run + Cloud SQL + IAP)',
    steps: [
      { title: 'Database', body: 'Cloud SQL for PostgreSQL. Connect over the Cloud SQL socket; keep `DATABASE_URL`, `APP_SECRET` and `CRON_SECRET` in Secret Manager.', code: 'DATABASE_URL=postgresql://USER:PASSWORD@/dmarcscope?host=/cloudsql/PROJECT:REGION:INSTANCE' },
      { title: 'Web app', body: `Build \`Dockerfile\`, deploy as a Cloud Run service with the instance attached. ${MIGRATE.replace('in the web image', 'as a Cloud Run job with the web image')}` },
      {
        title: 'Ingest job',
        body: 'Build `Dockerfile.ingest` and deploy a Cloud Run job with the command `python -m ingestor pass` and the same `APP_SECRET`. Each run reads the mailboxes that are due and answers Test connection and Run now, so schedule it often with Cloud Scheduler.',
        code: 'gcloud run jobs deploy dmarcscope-ingest --image …/dmarcscope-ingest \\\n  --args pass --task-timeout 10m --memory 512Mi \\\n  --set-env-vars INGEST_PASS_BUDGET_SECONDS=540,INGEST_TIME_BUDGET_SECONDS=420',
      },
      { title: 'Scheduler', body: 'Three Cloud Scheduler jobs, which is the free allowance per billing account: the ingest job, and `/api/cron/dns-check` and `/api/cron/alerts` with the bearer token (Cloud Run scales the web app to zero, so it cannot time alerts itself).' },
      { title: 'Sign-in (optional)', body: 'Identity-Aware Proxy in front of the service, with `AUTH_PROVIDER=proxy-jwt` and `AUTH_PROXY_PRESET=gcp-iap` (docs/authentication.md).' },
    ],
  },
]

export const VERCEL_PLAN_NOTES: Record<'hobby' | 'pro', string[]> = {
  hobby: [
    'Cron jobs run at most once a day, at any minute of the scheduled hour. A more frequent schedule in vercel.json makes the deployment fail, so the project ships with a daily one.',
    'Run now reads a mailbox at any time. To read more often, call /api/cron/ingest with the bearer token from an outside scheduler (GitHub Actions, cron-job.org).',
    'Functions stop after 300 seconds; each ingest call stops starting new work after 240.',
  ],
  pro: [
    'Cron jobs can run every minute: change the ingest schedule in your copy of vercel.json (don’t let that change reach a Hobby deployment; it would fail to deploy).',
    'Functions can run up to 800 seconds: for a large backlog, raise maxDuration for api/cron/ingest.py and INGEST_PASS_BUDGET_SECONDS / INGEST_TIME_BUDGET_SECONDS to match.',
    'If you protect production deployments too, add a Protection Bypass for Automation secret so the app can call its own ingest function.',
  ],
}

// Where this copy of the app runs, from the environment each platform sets.
export function detectPlatform(env: Record<string, string | undefined> = process.env): PlatformId | null {
  if (env.VERCEL === '1') return 'vercel'
  if (env.K_SERVICE) return 'cloudrun'
  if (env.KUBERNETES_SERVICE_HOST) return 'kubernetes'
  if (env.DMARCSCOPE_COMPOSE === '1') return 'docker'
  return null
}
