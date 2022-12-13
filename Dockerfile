FROM python:3.9-alpine

# Update system dependencies
RUN apk --no-cache update && apk --no-cache upgrade

# Install dependencies
ENV PATH="$HOME/.local/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir prowler-cloud

# Create nonroot user
RUN mkdir -p /home/prowler && \ 
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler

USER prowler
WORKDIR /home/prowler

ENTRYPOINT ["prowler"]
