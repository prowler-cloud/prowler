FROM python:3.12-alpine AS build

LABEL maintainer="https://github.com/prowler-cloud/api"

RUN apk --no-cache add gcc=13.2.1_git20240309-r0 python3-dev=3.12.3-r1 musl-dev=1.2.5-r0 linux-headers=6.6-r0 curl-dev=8.9.0-r0

RUN apk --no-cache upgrade && \
    addgroup -g 1000 prowler && \
    adduser -D -u 1000 -G prowler prowler
USER prowler

WORKDIR /home/prowler

COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

COPY src/backend/  ./backend/

ENV PATH="/home/prowler/.local/bin:$PATH"

RUN poetry install && \
    rm -rf ~/.cache/pip

COPY docker-entrypoint.sh ./docker-entrypoint.sh

WORKDIR /home/prowler/backend

# Development image
# hadolint ignore=DL3006
FROM build AS dev

USER 0
RUN apk --no-cache add curl=8.9.0-r0 vim=9.1.0414-r0

USER prowler

ENTRYPOINT ["../docker-entrypoint.sh", "dev"]

# Production image
FROM build

ENTRYPOINT ["../docker-entrypoint.sh", "prod"]
