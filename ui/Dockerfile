# Keep in sync with ui/.nvmrc.
FROM node:24.13.0-alpine@sha256:cd6fb7efa6490f039f3471a189214d5f548c11df1ff9e5b181aa49e22c14383e AS base

LABEL maintainer="https://github.com/prowler-cloud"

# Enable corepack for pnpm
RUN corepack enable

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
#hadolint ignore=DL3018
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY scripts ./scripts
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
#   - optional: UI_API_DOCS_URL, UI_GOOGLE_TAG_MANAGER_ID, UI_SENTRY_DSN, UI_SENTRY_ENVIRONMENT
#   - reserved: POSTHOG_KEY, POSTHOG_HOST, REO_DEV_CLIENT_ID (no consumer yet)
# server.js is created by next build from the standalone output
# https://nextjs.org/docs/pages/api-reference/next-config-js/output
CMD ["node", "server.js"]
