# syntax=docker/dockerfile:1
#
# One image for all three services. The command decides what runs:
#   provider:  node packages/provider/src/server.ts   (default)
#   demo apps: node packages/rp/src/server.ts          (with RP_PRESET=legacy|pq)
#
# There is no build step: Node.js 24 runs the TypeScript sources directly
# (type stripping), so what you read in the repo is exactly what runs.

FROM node:24-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/token-kit/package.json packages/token-kit/
COPY packages/provider/package.json packages/provider/
COPY packages/rp/package.json packages/rp/
COPY apps/lab/package.json apps/lab/
# Production dependencies of the server packages only (no lab, no test tooling).
RUN npm ci --omit=dev --ignore-scripts --workspace packages/provider --workspace packages/rp

FROM node:24-slim
ENV NODE_ENV=production \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning
WORKDIR /app
COPY --from=deps /app ./
COPY packages ./packages

# Run as the unprivileged user that ships with the Node image.
USER node
EXPOSE 3000 3001 3002
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "packages/provider/src/server.ts"]
