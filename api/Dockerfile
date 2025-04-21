FROM python:3.12.8-alpine3.20 AS build

LABEL maintainer="https://github.com/prowler-cloud/api"

# hadolint ignore=DL3018
RUN apk --no-cache add gcc python3-dev musl-dev linux-headers curl-dev \
    ca-certificates less ncurses-terminfo-base krb5-libs libgcc libintl libssl3 \
    libstdc++ tzdata userspace-rcu zlib icu-libs curl lttng-ust openssh-client && \
    apk --no-cache upgrade

# Install PowerShell
RUN curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/powershell-7.5.0-linux-musl-x64.tar.gz -o /tmp/powershell.tar.gz && \
    mkdir -p /opt/microsoft/powershell/7 && \
    tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 && \
    chmod +x /opt/microsoft/powershell/7/pwsh && \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
    rm /tmp/powershell.tar.gz

# Add prowler user
RUN addgroup -g 1000 prowler && \
    adduser -D -u 1000 -G prowler prowler

USER prowler

WORKDIR /home/prowler

COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

COPY src/backend/ ./backend/

ENV PATH="/home/prowler/.local/bin:$PATH"

# Add `--no-root` to avoid installing the current project as a package
RUN poetry install --no-root && \
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
