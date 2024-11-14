# Base image for building the application
FROM python:3.12-alpine AS base

LABEL maintainer="https://github.com/prowler-cloud/api"

# Install necessary dependencies
# hadolint ignore=DL3018
RUN apk --no-cache add gcc python3-dev musl-dev linux-headers curl-dev

RUN apk --no-cache upgrade && \
    addgroup -g 1000 prowler && \
    adduser -D -u 1000 -G prowler prowler

WORKDIR /home/prowler
USER prowler

# Install Poetry and project dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir poetry
ENV PATH="/home/prowler/.local/bin:$PATH"
RUN poetry install && rm -rf ~/.cache/pip ~/.cache/pypoetry

# Copy backend source code and entrypoint script
COPY src/backend/ ./backend/
COPY docker-entrypoint.sh /home/prowler/docker-entrypoint.sh

WORKDIR /home/prowler/backend

# Development stage
FROM base AS dev
USER 0
# hadolint ignore=DL3018
RUN apk --no-cache add curl vim
USER prowler
ENTRYPOINT ["/home/prowler/docker-entrypoint.sh", "dev"]

# Production stage
FROM base AS prod
ENTRYPOINT ["/home/prowler/docker-entrypoint.sh", "prod"]
