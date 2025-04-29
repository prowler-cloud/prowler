FROM python:3.12.10-slim-bookworm AS build

LABEL maintainer="https://github.com/prowler-cloud/prowler"

ARG POWERSHELL_VERSION=7.5.0

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends wget libicu72 \
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

# Copy necessary files
COPY prowler/  /home/prowler/prowler/
COPY dashboard/ /home/prowler/dashboard/
COPY pyproject.toml /home/prowler
COPY README.md /home/prowler/
COPY util/m365/m365_powershell_modules_installation.py /home/prowler/util/m365/m365_powershell_modules_installation.py

# Install Python dependencies
ENV HOME='/home/prowler'
ENV PATH="${HOME}/.local/bin:${PATH}"
#hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry

# By default poetry does not compile Python source files to bytecode during installation.
# This speeds up the installation process, but the first execution may take a little more
# time because Python then compiles source files to bytecode automatically. If you want to
# compile source files to bytecode during installation, you can use the --compile option
RUN poetry install --compile && \
    rm -rf ~/.cache/pip

# Install PowerShell modules
RUN poetry run python util/m365/m365_powershell_modules_installation.py

# Remove deprecated dash dependencies
RUN pip uninstall dash-html-components -y && \
    pip uninstall dash-core-components -y

USER prowler
ENTRYPOINT ["poetry", "run", "prowler"]
