# syntax=docker/dockerfile:1
# Kleidion WEB app image.
#
# Lives at the repo root on purpose: the compose build context for `web` is the
# repo root (so the image can access npm-workspace manifests + packages/*), and
# BOTH `docker compose` and `podman-compose` auto-discover `Dockerfile` at the
# context root. (podman-compose 1.6.0 ignores a `build.dockerfile:` key that
# points outside the context, so we keep the Dockerfile at the context root
# instead — see ADR-004.) The Go server has its own context+Dockerfile under
# apps/server.
#
# Dev-oriented image (runs `next dev` with HMR). Prod multi-stage build
# (`next build` + standalone output) lands in Phase 3.

# node:24-alpine = active Node LTS (Krypton) on current Alpine.
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
