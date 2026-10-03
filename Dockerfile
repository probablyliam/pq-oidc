# syntax=docker/dockerfile:1
#
# One image for every service. The command decides what runs:
#   scanner API     node services/api/src/server.ts        (default; serves the web app too)
#   scanner worker  node services/worker/src/server.ts
#   OIDC provider   node packages/provider/src/server.ts
#   demo apps       node packages/rp/src/server.ts         (RP_PRESET=legacy|pq)
#
# The server code has no build step: Node.js runs the TypeScript sources directly
# (type stripping), so what you read in the repo is exactly what runs. Only the web
# app is built, with Vite, in its own stage.

FROM node:25-slim AS web
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/token-kit/package.json packages/token-kit/
COPY packages/scan-core/package.json packages/scan-core/
COPY packages/provider/package.json packages/provider/
COPY packages/rp/package.json packages/rp/
COPY apps/web/package.json apps/web/
COPY services/api/package.json services/api/
COPY services/worker/package.json services/worker/
COPY tsconfig.base.json ./
RUN npm ci --ignore-scripts
COPY packages/token-kit packages/token-kit
COPY packages/scan-core packages/scan-core
COPY apps/web apps/web
RUN npm run build -w apps/web

FROM node:25-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/token-kit/package.json packages/token-kit/
COPY packages/scan-core/package.json packages/scan-core/
COPY packages/provider/package.json packages/provider/
COPY packages/rp/package.json packages/rp/
COPY apps/web/package.json apps/web/
COPY services/api/package.json services/api/
COPY services/worker/package.json services/worker/
# Production dependencies only. Every workspace is installed so the links between them
# (services/api -> @pq-oidc/scan-core -> @pq-oidc/token-kit) all exist; a --workspace filter leaves some out.
RUN npm ci --omit=dev --ignore-scripts

FROM node:25-slim
ENV NODE_ENV=production \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning \
    HOST=0.0.0.0 \
    INTERNAL_HOST=0.0.0.0 \
    WEB_DIR=/app/apps/web/dist \
    DATABASE_PATH=/data/scans.sqlite
WORKDIR /app
COPY --from=deps /app ./
COPY packages ./packages
COPY services ./services
COPY --from=web /app/apps/web/dist ./apps/web/dist
RUN mkdir -p /data && chown node:node /data
VOLUME /data

# Run as the unprivileged user that ships with the Node image.
USER node
EXPOSE 8080 8081 3000 3001 3002
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "services/api/src/server.ts"]
