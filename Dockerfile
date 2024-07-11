FROM python:3.12-alpine as build

LABEL maintainer="https://github.com/prowler-cloud/restful-api"

RUN apk --no-cache upgrade && \
    addgroup -g 1000 prowler && \
    adduser -D -u 1000 -G prowler prowler
USER prowler

WORKDIR /home/prowler

COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

COPY src/backend/  ./backend/
COPY docker-entrypoint.sh ./docker-entrypoint.sh

ENV PATH="/home/prowler/.local/bin:$PATH"

RUN poetry install && \
    rm -rf ~/.cache/pip

WORKDIR /home/prowler/backend

# Development image
# hadolint ignore=DL3006
FROM build as dev

USER 0
RUN apk --no-cache add curl=8.8.0-r0 vim=9.1.0414-r0

USER prowler

ENTRYPOINT ["../docker-entrypoint.sh", "dev"]

# Production image
FROM build

ENTRYPOINT ["../docker-entrypoint.sh", "prod"]
