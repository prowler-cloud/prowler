FROM python:3.12-alpine

LABEL maintainer="https://github.com/prowler-cloud/restful-api"

RUN apk --no-cache upgrade

RUN addgroup -g 1000 prowler && \
    adduser -D -u 1000 -G prowler prowler
USER prowler

WORKDIR /home/prowler

COPY backend/  ./backend/
COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

ENV PATH="/home/prowler/.local/bin:$PATH"

RUN poetry install

RUN rm -rf ~/.cache/pip

# TODO use ASGI
