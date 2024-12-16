FROM python:3.12.8-alpine3.20 AS build

LABEL maintainer="https://github.com/prowler-cloud/api"

# hadolint ignore=DL3018
RUN apk --no-cache add gcc python3-dev musl-dev linux-headers curl-dev

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
# hadolint ignore=DL3018
RUN apk --no-cache add curl vim

USER prowler

ENTRYPOINT ["../docker-entrypoint.sh", "dev"]

# Production image
FROM build

ENTRYPOINT ["../docker-entrypoint.sh", "prod"]
