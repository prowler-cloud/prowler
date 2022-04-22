# Build command
# docker build --platform=linux/amd64  --no-cache -t prowler:latest .

FROM public.ecr.aws/amazonlinux/amazonlinux:2022

ARG PROWLERVER=2.9.0
ARG USERNAME=prowler
ARG USERID=34000

# Install Dependencies
RUN \
    dnf update -y && \
    dnf install -y bash file findutils git jq python3 python3-pip \
                   python3-setuptools python3-wheel shadow-utils tar unzip which && \
    dnf remove -y awscli && \
    dnf clean all && \
    useradd -l -s /bin/sh -U -u ${USERID} ${USERNAME} && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir "git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets" && \
    rm -rf aws awscliv2.zip /var/cache/dnf

# Place script and env vars
COPY .awsvariables run-prowler-securityhub.sh /

# Installs prowler and change permissions
RUN \
    curl -L "https://github.com/prowler-cloud/prowler/archive/refs/tags/${PROWLERVER}.tar.gz" -o "prowler.tar.gz" && \
    tar xvzf prowler.tar.gz && \
    rm -f prowler.tar.gz && \
    mv prowler-${PROWLERVER} prowler && \
    chown ${USERNAME}:${USERNAME} /run-prowler-securityhub.sh && \
    chmod 500 /run-prowler-securityhub.sh && \
    chown ${USERNAME}:${USERNAME} /.awsvariables && \
    chmod 400 /.awsvariables && \
    chown ${USERNAME}:${USERNAME} -R /prowler && \
    chmod +x /prowler/prowler

# Drop to user
USER ${USERNAME}

# Run script
ENTRYPOINT ["/run-prowler-securityhub.sh"]