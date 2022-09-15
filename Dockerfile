# Build command
# docker build --platform=linux/amd64  --no-cache -t prowler:latest -f ./Dockerfile .

# hadolint ignore=DL3007
FROM public.ecr.aws/amazonlinux/amazonlinux:latest

LABEL maintainer="https://github.com/prowler-cloud/prowler"

ARG USERNAME=prowler
ARG USERID=34000

# Prepare image as root
USER 0
# System dependencies
# hadolint ignore=DL3006,DL3013,DL3033
RUN yum upgrade -y  && \
  yum install -y python3 bash curl jq coreutils py3-pip which unzip shadow-utils && \
  yum clean all && \
  rm -rf /var/cache/yum

RUN amazon-linux-extras install -y epel postgresql14 && \
    yum clean all && \
    rm -rf /var/cache/yum

# Create non-root user
RUN  useradd -l -s /bin/bash -U -u ${USERID} ${USERNAME}

USER ${USERNAME}

# Python dependencies
# hadolint ignore=DL3006,DL3013,DL3042
RUN pip3 install --upgrade pip && \
  pip3 install --no-cache-dir boto3 detect-secrets==1.0.3 && \
  pip3 cache purge
# Set Python PATH
ENV PATH="/home/${USERNAME}/.local/bin:${PATH}"

USER 0

# Install AWS CLI
RUN curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && \
  unzip -q awscliv2.zip && \
  aws/install && \
  rm -rf aws awscliv2.zip

# Keep Python2 for yum
RUN sed -i '1 s/python/python2.7/' /usr/bin/yum

# Set Python3
RUN rm /usr/bin/python && \
    ln -s /usr/bin/python3 /usr/bin/python

# Set working directory
WORKDIR /prowler

# Copy all files
COPY . ./

# Set files ownership
RUN chown -R prowler .

USER ${USERNAME}

ENTRYPOINT ["./prowler"]
