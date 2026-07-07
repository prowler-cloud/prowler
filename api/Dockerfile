FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS build

LABEL maintainer="https://github.com/prowler-cloud/api"

ARG POWERSHELL_VERSION=7.5.0
ENV POWERSHELL_VERSION=${POWERSHELL_VERSION}
# Opt out of PowerShell telemetry (Application Insights -> dc.services.visualstudio.com)
ENV POWERSHELL_TELEMETRY_OPTOUT=1

ARG TRIVY_VERSION=0.71.2
ENV TRIVY_VERSION=${TRIVY_VERSION}

ARG ZIZMOR_VERSION=1.24.1
ENV ZIZMOR_VERSION=${ZIZMOR_VERSION}

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    git \
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
    git \
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

# Install Trivy for IaC scanning
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        TRIVY_ARCH="Linux-64bit" ; \
    elif [ "$ARCH" = "aarch64" ]; then \
        TRIVY_ARCH="Linux-ARM64" ; \
    else \
        echo "Unsupported architecture for Trivy: $ARCH" && exit 1 ; \
    fi && \
    wget --progress=dot:giga "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" -O /tmp/trivy.tar.gz && \
    tar zxf /tmp/trivy.tar.gz -C /tmp && \
    mv /tmp/trivy /usr/local/bin/trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm /tmp/trivy.tar.gz && \
    # Create trivy cache directory with proper permissions
    mkdir -p /tmp/.cache/trivy && \
    chmod 777 /tmp/.cache/trivy

# Install zizmor for GitHub Actions workflow scanning
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        ZIZMOR_ARCH="x86_64-unknown-linux-gnu" ; \
    elif [ "$ARCH" = "aarch64" ]; then \
        ZIZMOR_ARCH="aarch64-unknown-linux-gnu" ; \
    else \
        echo "Unsupported architecture for zizmor: $ARCH" && exit 1 ; \
    fi && \
    wget --progress=dot:giga "https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/zizmor-${ZIZMOR_ARCH}.tar.gz" -O /tmp/zizmor.tar.gz && \
    mkdir -p /tmp/zizmor-extract && \
    tar zxf /tmp/zizmor.tar.gz -C /tmp/zizmor-extract && \
    mv /tmp/zizmor-extract/zizmor /usr/local/bin/zizmor && \
    chmod +x /usr/local/bin/zizmor && \
    rm -rf /tmp/zizmor.tar.gz /tmp/zizmor-extract

# Add prowler user
RUN addgroup --gid 1000 prowler && \
    adduser --uid 1000 --gid 1000 --disabled-password --gecos "" prowler

USER prowler

WORKDIR /home/prowler

# Ensure output directory exists
RUN mkdir -p /tmp/prowler_api_output

COPY --chown=prowler:prowler pyproject.toml uv.lock ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir uv==0.11.14

ENV PATH="/home/prowler/.local/bin:$PATH"

# Add `--no-install-project` to avoid installing the current project as a package
RUN uv sync --locked --no-install-project && \
    rm -rf ~/.cache/uv

RUN .venv/bin/python .venv/lib/python3.12/site-packages/prowler/providers/m365/lib/powershell/m365_powershell.py

USER root

# Remove build-only packages from the final image after Python dependencies are installed.
RUN apt-get purge -y --auto-remove \
    gcc \
    g++ \
    make \
    libxml2-dev \
    libxmlsec1-dev \
    pkg-config \
    libtool \
    libxslt1-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

USER prowler

COPY --chown=prowler:prowler src/backend/ ./backend/
COPY --chown=prowler:prowler docker-entrypoint.sh ./docker-entrypoint.sh

WORKDIR /home/prowler/backend

# Development image
FROM build AS dev

ENTRYPOINT ["../docker-entrypoint.sh", "dev"]

# Production image
FROM build

ENTRYPOINT ["../docker-entrypoint.sh", "prod"]
