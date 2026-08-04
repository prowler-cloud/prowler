FROM python:3.12.13-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS build

LABEL maintainer="https://github.com/prowler-cloud/prowler"
LABEL org.opencontainers.image.source="https://github.com/prowler-cloud/prowler"

ARG POWERSHELL_VERSION=7.5.9
ENV POWERSHELL_VERSION=${POWERSHELL_VERSION}
# Opt out of PowerShell telemetry (Application Insights -> dc.services.visualstudio.com)
ENV POWERSHELL_TELEMETRY_OPTOUT=1

ARG TRIVY_VERSION=0.72.0
ENV TRIVY_VERSION=${TRIVY_VERSION}

ARG ZIZMOR_VERSION=1.24.1
ENV ZIZMOR_VERSION=${ZIZMOR_VERSION}

# Checksums of the third-party binaries fetched below. They are pinned here rather
# than downloaded alongside the artefact: a compromised release would ship a matching
# checksum file. CVE-2026-33634 was exactly that -- a malicious Trivy release published
# with stolen credentials.
# Trivy and PowerShell values are the vendors' published checksums. zizmor publishes
# none, so its values were computed from the current artefacts and pin them against
# future substitution.
ARG TRIVY_SHA256_AMD64=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
ARG TRIVY_SHA256_ARM64=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467
ARG POWERSHELL_SHA256_AMD64=492ff26bb958336bf61e597ce19e07648b4003bd2a08659e02f0e3e0446ebfe0
ARG POWERSHELL_SHA256_ARM64=2503b71da3e83635592b092df59a0aca4c3606b4d9b068217bb00be989cb0d56
ARG ZIZMOR_SHA256_AMD64=a8000f3c683319a523d3b20df0e75457ba591f049cfcbfa98966631b56733c03
ARG ZIZMOR_SHA256_ARM64=d66e37ef8a375fb07939c630ebf9709a6e0f20242bdc3faf672a7ed97e0b768d

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget libicu76 libunwind8 libssl3 libcurl4 ca-certificates apt-transport-https gnupg \
    build-essential pkg-config libzstd-dev zlib1g-dev \
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
    echo "$EXPECT  /tmp/powershell.tar.gz" | sha256sum -c - && \
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
    echo "$EXPECT  /tmp/trivy.tar.gz" | sha256sum -c - && \
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
    echo "$EXPECT  /tmp/zizmor.tar.gz" | sha256sum -c - && \
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

# Copy necessary files
COPY --chown=prowler:prowler prowler/  /home/prowler/prowler/
COPY --chown=prowler:prowler dashboard/ /home/prowler/dashboard/
COPY --chown=prowler:prowler pyproject.toml uv.lock /home/prowler/
COPY --chown=prowler:prowler README.md /home/prowler/
COPY --chown=prowler:prowler prowler/providers/m365/lib/powershell/m365_powershell.py /home/prowler/prowler/providers/m365/lib/powershell/m365_powershell.py

# Install Python dependencies
ENV HOME='/home/prowler'
ENV PATH="${HOME}/.local/bin:${PATH}"
#hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir uv==0.12.0

RUN uv sync --locked --compile-bytecode && \
    rm -rf ~/.cache/uv

# Install PowerShell modules
RUN .venv/bin/python prowler/providers/m365/lib/powershell/m365_powershell.py

USER root

# Remove build-only packages from the final image after Python dependencies are installed.
RUN apt-get purge -y --auto-remove \
    build-essential \
    pkg-config \
    libzstd-dev \
    zlib1g-dev \
    wget \
    gnupg \
    apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

USER prowler

# Remove deprecated dash dependencies
RUN pip uninstall dash-html-components -y && \
    pip uninstall dash-core-components -y

USER root

# pip is build-only; the entrypoint runs the venv directly.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
    /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
    /home/prowler/.local/lib/python3.12/site-packages/pip \
    /home/prowler/.local/lib/python3.12/site-packages/pip-*.dist-info \
    /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
    /home/prowler/.local/bin/pip /home/prowler/.local/bin/pip3 /home/prowler/.local/bin/pip3.12

USER prowler
ENTRYPOINT ["/home/prowler/.venv/bin/prowler"]
