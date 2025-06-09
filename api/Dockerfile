FROM python:3.12.10-slim-bookworm AS build

LABEL maintainer="https://github.com/prowler-cloud/api"

ARG POWERSHELL_VERSION=7.5.0
ENV POWERSHELL_VERSION=${POWERSHELL_VERSION}

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    libicu72 \
    gcc \
    g++ \
    make \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    libtool \
    libxslt1-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install PowerShell
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        wget --progress=dot:giga https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-x64.tar.gz -O /tmp/powershell.tar.gz ; \
    elif [ "$ARCH" = "aarch64" ]; then \
        wget --progress=dot:giga https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-arm64.tar.gz -O /tmp/powershell.tar.gz ; \
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

ENV PATH="/home/prowler/.local/bin:$PATH"

# Add `--no-root` to avoid installing the current project as a package
RUN poetry install --no-root && \
    rm -rf ~/.cache/pip

RUN poetry run python "$(poetry env info --path)/src/prowler/prowler/providers/m365/lib/powershell/m365_powershell.py"

# Prevents known compatibility error between lxml and libxml2/libxmlsec versions.
# See: https://github.com/xmlsec/python-xmlsec/issues/320
RUN poetry run pip install --force-reinstall --no-binary lxml lxml

COPY src/backend/ ./backend/
COPY docker-entrypoint.sh ./docker-entrypoint.sh

WORKDIR /home/prowler/backend

# Development image
FROM build AS dev

ENTRYPOINT ["../docker-entrypoint.sh", "dev"]

# Production image
FROM build

ENTRYPOINT ["../docker-entrypoint.sh", "prod"]
