# Web app image (dashboard + /api routes). The ingest worker has its own
# image: Dockerfile.ingest.
#
#   docker build -t dmarcscope .
#   docker run --env-file .env -p 3000:3000 dmarcscope
#   docker run --env-file .env dmarcscope node scripts/migrate.mjs   # apply migrations

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# Self-contained server from `output: 'standalone'` (includes the pg driver),
# plus the migration runner and its SQL files.
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --chown=node:node scripts/migrate.mjs ./scripts/migrate.mjs
COPY --chown=node:node db ./db
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
