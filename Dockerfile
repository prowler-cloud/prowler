FROM python:3.9-slim-buster

LABEL maintainer="https://github.com/prowler-cloud/prowler"

# Update system dependencies
# hadolint ignore=DL3018
RUN apt-get update && \
    apt-get upgrade --no-install-recommends -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
ENV PATH="$HOME/.local/bin:$PATH"
# hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir pipenv setuptools

# Create nonroot user
RUN mkdir -p /home/prowler && \ 
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler

# Copy files
COPY prowler/ /home/prowler/prowler
COPY prowler.py /home/prowler
COPY Pipfile* /tmp

# Export requirements from pipenv
WORKDIR /tmp
RUN pipenv requirements > requirements.txt && \
    pip uninstall -y pipenv

# Install Prowler dependencies
# hadolint ignore=DL3013
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm -rf /tmp

USER prowler
WORKDIR /home/prowler
ENTRYPOINT ["python3", "./prowler.py"]