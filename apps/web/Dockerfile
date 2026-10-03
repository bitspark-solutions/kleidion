# syntax=docker/dockerfile:1
# Kleidion web — dev-oriented image (runs `next dev` with hot reload via bind mount in Tilt).
# Prod multi-stage build lands with Phase 3 (`next build` + standalone output).

FROM node:24-alpine AS deps
WORKDIR /app
# Copy workspace-aware manifests: root + web + shared packages (lockfile must see every workspace)
COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/
COPY packages/crypto/package.json ./packages/crypto/
COPY packages/core/package.json ./packages/core/
RUN npm ci --workspace @kleidion/web --include-workspace-root

FROM node:24-alpine AS dev
WORKDIR /app
ENV NODE_ENV=development PORT=3000 HOSTNAME=0.0.0.0 WATCHPACK_POLLING=true
# npm workspaces hoist everything to the root node_modules
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY apps/web ./apps/web
COPY packages ./packages
# Non-root (rootless podman compatible)
RUN addgroup -S nodejs && adduser -S nextjs -G nodejs && chown -R nextjs:nodejs /app
USER nextjs
EXPOSE 3000
CMD ["npm", "run", "dev", "--workspace", "@kleidion/web"]
