FROM python:3.12.9-alpine3.20

LABEL maintainer="https://github.com/prowler-cloud/prowler"

# Update system dependencies and install essential tools
#hadolint ignore=DL3018
RUN apk --no-cache upgrade && apk --no-cache add curl git gcc python3-dev musl-dev linux-headers

# Create non-root user
RUN mkdir -p /home/prowler && \
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler
USER prowler

# Copy necessary files
WORKDIR /home/prowler
COPY prowler/  /home/prowler/prowler/
COPY dashboard/ /home/prowler/dashboard/
COPY pyproject.toml /home/prowler
COPY README.md /home/prowler/

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

# Remove deprecated dash dependencies
RUN pip uninstall dash-html-components -y && \
    pip uninstall dash-core-components -y

USER prowler
ENTRYPOINT ["poetry", "run", "prowler"]
