FROM python:3.12-slim-bookworm AS build

LABEL maintainer="https://github.com/prowler-cloud/api"

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev bash \
    libcurl4-openssl-dev ca-certificates less ncurses-base \
    krb5-multidev libgcc-s1 gettext libssl3 \
    libstdc++6 tzdata liburcu8 zlib1g libicu72 curl openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Install PowerShell
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/powershell-7.5.0-linux-x64.tar.gz -o /tmp/powershell.tar.gz ; \
    elif [ "$ARCH" = "aarch64" ]; then \
        curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/powershell-7.5.0-linux-arm64.tar.gz -o /tmp/powershell.tar.gz ; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1 ; \
    fi && \
    mkdir -p /opt/microsoft/powershell/7 && \
    tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 && \
    chmod +x /opt/microsoft/powershell/7/pwsh && \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
    rm /tmp/powershell.tar.gz

# Add prowler user
RUN addgroup --gid 1000 prowler && \
    adduser --uid 1000 --gid 1000 --disabled-password --gecos "" prowler

USER prowler

WORKDIR /home/prowler

COPY pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

COPY src/backend/ ./backend/

ENV PATH="/home/prowler/.local/bin:$PATH"

RUN poetry install --no-root && \
    rm -rf ~/.cache/pip

COPY docker-entrypoint.sh ./docker-entrypoint.sh

WORKDIR /home/prowler/backend

# Development image
FROM build AS dev

USER root
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl vim \
    && rm -rf /var/lib/apt/lists/*

USER prowler

ENTRYPOINT ["../docker-entrypoint.sh", "dev"]

# Production image
FROM build

ENTRYPOINT ["../docker-entrypoint.sh", "prod"]
