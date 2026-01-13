FROM python:3.12.11-slim-bookworm AS build

LABEL maintainer="https://github.com/prowler-cloud/prowler"
LABEL org.opencontainers.image.source="https://github.com/prowler-cloud/prowler"

ARG POWERSHELL_VERSION=7.5.0
ENV POWERSHELL_VERSION=${POWERSHELL_VERSION}

ARG TRIVY_VERSION=0.66.0
ENV TRIVY_VERSION=${TRIVY_VERSION}

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget libicu72 libunwind8 libssl3 libcurl4 ca-certificates apt-transport-https gnupg \
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

# Add prowler user
RUN addgroup --gid 1000 prowler && \
    adduser --uid 1000 --gid 1000 --disabled-password --gecos "" prowler

USER prowler

WORKDIR /home/prowler

# Copy necessary files
COPY prowler/  /home/prowler/prowler/
COPY dashboard/ /home/prowler/dashboard/
COPY pyproject.toml /home/prowler
COPY README.md /home/prowler/
COPY prowler/providers/m365/lib/powershell/m365_powershell.py /home/prowler/prowler/providers/m365/lib/powershell/m365_powershell.py

# Install Python dependencies
ENV HOME='/home/prowler'
ENV PATH="${HOME}/.local/bin:${PATH}"
#hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

RUN poetry install --compile && \
    rm -rf ~/.cache/pip

# Install PowerShell modules
RUN poetry run python prowler/providers/m365/lib/powershell/m365_powershell.py

# Remove deprecated dash dependencies
RUN pip uninstall dash-html-components -y && \
    pip uninstall dash-core-components -y

USER prowler
ENTRYPOINT ["poetry", "run", "prowler"]
