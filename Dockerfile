# Web app image (dashboard + /api routes). The ingest worker has its own
# image: Dockerfile.ingest.
#
#   docker build -t dmarcscope .
#   docker run --env-file .env -p 3000:3000 dmarcscope
#   docker run --env-file .env dmarcscope node scripts/migrate.mjs   # apply migrations
#   docker run --env-file .env dmarcscope node scripts/settings-import.mjs
#   docker run --env-file .env dmarcscope node scripts/secrets-reencrypt.mjs

FROM node:26-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:26-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:26-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# Self-contained server from `output: 'standalone'` (includes the pg driver),
# plus the command-line scripts (migrations, settings import, secret
# re-encryption) and what they need.
COPY --from=build --chown=1000:1000 /app/.next/standalone ./
COPY --from=build --chown=1000:1000 /app/.next/static ./.next/static
COPY --chown=1000:1000 scripts/migrate.mjs scripts/settings-import.mjs scripts/secrets-reencrypt.mjs ./scripts/
COPY --chown=1000:1000 lib/envelope.mjs ./lib/envelope.mjs
COPY --chown=1000:1000 db ./db
# The image's "node" user, by number: Kubernetes can only verify
# runAsNonRoot against a numeric UID.
USER 1000:1000
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
