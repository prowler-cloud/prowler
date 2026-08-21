FROM python:3.12.13-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS build

LABEL maintainer="https://github.com/prowler-cloud/api"

ARG POWERSHELL_VERSION=7.5.9
ENV POWERSHELL_VERSION=${POWERSHELL_VERSION}
# Opt out of PowerShell telemetry (Application Insights -> dc.services.visualstudio.com)
ENV POWERSHELL_TELEMETRY_OPTOUT=1

ARG TRIVY_VERSION=0.74.0
ENV TRIVY_VERSION=${TRIVY_VERSION}

ARG ZIZMOR_VERSION=1.24.1
ENV ZIZMOR_VERSION=${ZIZMOR_VERSION}

# Pinned here, not fetched with the artefact: a compromised release ships its own checksum.
ARG TRIVY_SHA256_AMD64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
ARG TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
ARG POWERSHELL_SHA256_AMD64=492ff26bb958336bf61e597ce19e07648b4003bd2a08659e02f0e3e0446ebfe0
ARG POWERSHELL_SHA256_ARM64=2503b71da3e83635592b092df59a0aca4c3606b4d9b068217bb00be989cb0d56
ARG ZIZMOR_SHA256_AMD64=a8000f3c683319a523d3b20df0e75457ba591f049cfcbfa98966631b56733c03
ARG ZIZMOR_SHA256_ARM64=d66e37ef8a375fb07939c630ebf9709a6e0f20242bdc3faf672a7ed97e0b768d

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    git \
    libicu76 \
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
    && apt-get install -y --no-install-recommends --only-upgrade util-linux \
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
    if [ "$ARCH" = "x86_64" ]; then EXPECT="$POWERSHELL_SHA256_AMD64" ; else EXPECT="$POWERSHELL_SHA256_ARM64" ; fi && \
    echo "$EXPECT  /tmp/powershell.tar.gz" > /tmp/powershell.sha256 && \
    sha256sum -c /tmp/powershell.sha256 && rm /tmp/powershell.sha256 && \
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
    if [ "$ARCH" = "x86_64" ]; then EXPECT="$TRIVY_SHA256_AMD64" ; else EXPECT="$TRIVY_SHA256_ARM64" ; fi && \
    echo "$EXPECT  /tmp/trivy.tar.gz" > /tmp/trivy.sha256 && \
    sha256sum -c /tmp/trivy.sha256 && rm /tmp/trivy.sha256 && \
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
    if [ "$ARCH" = "x86_64" ]; then EXPECT="$ZIZMOR_SHA256_AMD64" ; else EXPECT="$ZIZMOR_SHA256_ARM64" ; fi && \
    echo "$EXPECT  /tmp/zizmor.tar.gz" > /tmp/zizmor.sha256 && \
    sha256sum -c /tmp/zizmor.sha256 && rm /tmp/zizmor.sha256 && \
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
    pip install --no-cache-dir uv==0.12.0

ENV PATH="/home/prowler/.local/bin:$PATH"

# Add `--no-install-project` to avoid installing the current project as a package
RUN uv sync --locked --no-install-project && \
    rm -rf ~/.cache/uv

# Invoked as a module so the base image's Python minor version is not baked
# into a site-packages path.
RUN .venv/bin/python -m prowler.providers.m365.lib.powershell.m365_powershell

USER root

# Remove build-only packages from the final image after Python dependencies are installed.
# git is only needed by uv sync for the `prowler @ git+...` dependency; purging it drops perl too.
# wget stays: the compose healthcheck shells out to it.
RUN apt-get purge -y --auto-remove \
    gcc \
    g++ \
    git \
    make \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    libxmlsec1t64 \
    libxmlsec1t64-openssl \
    pkg-config \
    libtool \
    libxslt1-dev \
    python3-dev \
    gnupg \
    apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# pip is build-only; the entrypoint runs uv against the prepared venv. uv stays.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
    /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
    /home/prowler/.local/lib/python3.12/site-packages/pip \
    /home/prowler/.local/lib/python3.12/site-packages/pip-*.dist-info \
    /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
    /home/prowler/.local/bin/pip /home/prowler/.local/bin/pip3 /home/prowler/.local/bin/pip3.12

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
