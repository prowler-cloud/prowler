# Keep in sync with ui/.nvmrc.
FROM node:24.13.0-alpine@sha256:cd6fb7efa6490f039f3471a189214d5f548c11df1ff9e5b181aa49e22c14383e AS base

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
ARG UI_CLOUD_ENABLED
ENV UI_CLOUD_ENABLED=${UI_CLOUD_ENABLED}
ARG NEXT_PUBLIC_POSTHOG_KEY
ENV NEXT_PUBLIC_POSTHOG_KEY=${NEXT_PUBLIC_POSTHOG_KEY}
ARG NEXT_PUBLIC_POSTHOG_API_HOST
ENV NEXT_PUBLIC_POSTHOG_API_HOST=${NEXT_PUBLIC_POSTHOG_API_HOST}
ARG NEXT_PUBLIC_POSTHOG_UI_HOST
ENV NEXT_PUBLIC_POSTHOG_UI_HOST=${NEXT_PUBLIC_POSTHOG_UI_HOST}

# Cloud/PostHog values above are build-time: Next.js inlines NEXT_PUBLIC_*
# for the feedback survey, and UI_CLOUD_ENABLED controls CSP generation.
# GTM and API base/docs URLs remain runtime configuration.

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
# Remaining runtime configuration is read by `node server.js` at container
# start and is not baked into the image. Supply it through Docker Compose,
# Helm, or Kubernetes:
#   - required: UI_API_BASE_URL, AUTH_URL, AUTH_SECRET (missing ⇒ fail fast at boot)
#   - optional: UI_API_DOCS_URL
#   - Cloud mode: pass UI_CLOUD_ENABLED="true" as a build arg; the value above
#     generates the Cloud CSP
#   - gated integrations (load only when *_ENABLED="true"; the value is then
#     required or boot fails). Their legacy names (NEXT_PUBLIC_SENTRY_*,
#     NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID, POSTHOG_KEY/HOST) still work:
#       UI_SENTRY_ENABLED + UI_SENTRY_DSN (+ optional UI_SENTRY_ENVIRONMENT)
#       UI_GOOGLE_TAG_MANAGER_ENABLED + UI_GOOGLE_TAG_MANAGER_ID
#       UI_POSTHOG_ENABLED + UI_POSTHOG_KEY + UI_POSTHOG_HOST (runtime config;
#       the feedback survey uses the build-time NEXT_PUBLIC_POSTHOG_* above)
#   - reserved: REO_DEV_CLIENT_ID (no consumer yet)
# server.js is created by next build from the standalone output
# https://nextjs.org/docs/pages/api-reference/next-config-js/output
CMD ["node", "server.js"]
