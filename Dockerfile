FROM python:3.9-alpine

LABEL maintainer="https://github.com/prowler-cloud/prowler"

# Update system dependencies
#hadolint ignore=DL3018
RUN apk --no-cache upgrade && apk --no-cache add curl

# Create nonroot user
RUN mkdir -p /home/prowler && \
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler
USER prowler

# Copy necessary files
WORKDIR /home/prowler
COPY prowler/ /home/prowler/prowler/
COPY pyproject.toml /home/prowler
COPY README.md /home/prowler

# Install dependencies
ENV HOME='/home/prowler'
ENV PATH="$HOME/.local/bin:$PATH"
#hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Remove Prowler directory and build files
USER 0
RUN rm -rf /home/prowler/prowler /home/prowler/pyproject.toml /home/prowler/README.md /home/prowler/build /home/prowler/prowler.egg-info

USER prowler
ENTRYPOINT ["prowler"]
