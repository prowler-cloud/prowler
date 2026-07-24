# Keep in sync with ui/.nvmrc.
FROM node:24.18.0-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS base

LABEL maintainer="https://github.com/prowler-cloud"

# Patch Alpine OpenSSL runtime packages before all stages inherit the base image.
# The build uses pnpm via corepack, so npm is unused — remove it (and npx) to drop
# the bundled-npm CVE surface (node-tar CVE-2026-59873) from every stage, incl. prod.
RUN apk upgrade --no-cache libcrypto3 libssl3 && corepack enable && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
#hadolint ignore=DL3018
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY scripts ./scripts
ENV NODE_OPTIONS=--max-old-space-size=4096
RUN corepack install && pnpm install --frozen-lockfile


# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Install pinned pnpm so build uses the exact version from package.json.
# Alternative: move COPY package.json + corepack install to base stage to avoid
# re-downloading, at the cost of invalidating all stages on any package.json change.
RUN corepack install

# Next.js collects completely anonymous telemetry data about general usage.
# Learn more here: https://nextjs.org/telemetry
# Uncomment the following line in case you want to disable telemetry during the build.
ENV NEXT_TELEMETRY_DISABLED=1
ARG NEXT_PUBLIC_PROWLER_RELEASE_VERSION
ENV NEXT_PUBLIC_PROWLER_RELEASE_VERSION=${NEXT_PUBLIC_PROWLER_RELEASE_VERSION}

# GTM / API base+docs URLs are runtime container env (prod stage), not build ARGs.

RUN pnpm run build

# Development stage
FROM base AS dev
WORKDIR /app

# Set up environment for development
ENV NODE_ENV=development
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=builder /app /app

# Run development server with hot-reloading
CMD ["pnpm", "run", "dev"]

# Production stage
FROM base AS prod
WORKDIR /app

# Set up environment for production
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs &&\
adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
# Runtime configuration is read by `node server.js` at container start and is
# NOT baked into the image. Supply it via your orchestrator (docker-compose,
# Helm/K8s):
#   - required: UI_API_BASE_URL, AUTH_URL, AUTH_SECRET (missing ⇒ fail fast at boot)
#   - optional: UI_API_DOCS_URL
#   - optional: UI_CLOUD_ENABLED ("true" only in Prowler Cloud deployments)
#   - gated integrations (load only when *_ENABLED="true"; the value is then
#     required or boot fails). Their legacy names (NEXT_PUBLIC_SENTRY_*,
#     NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID, POSTHOG_KEY/HOST) still work:
#       UI_SENTRY_ENABLED + UI_SENTRY_DSN (+ optional UI_SENTRY_ENVIRONMENT)
#       UI_GOOGLE_TAG_MANAGER_ENABLED + UI_GOOGLE_TAG_MANAGER_ID
#       UI_POSTHOG_ENABLED + UI_POSTHOG_KEY + UI_POSTHOG_HOST (no consumer yet)
#   - reserved: REO_DEV_CLIENT_ID (no consumer yet)
# server.js is created by next build from the standalone output
# https://nextjs.org/docs/pages/api-reference/next-config-js/output
CMD ["node", "server.js"]
