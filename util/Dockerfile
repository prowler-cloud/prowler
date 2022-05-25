# Build command
# docker build --platform=linux/amd64  --no-cache -t prowler:latest -f util/Dockerfile .

FROM public.ecr.aws/amazonlinux/amazonlinux:latest

LABEL maintainer="https://github.com/prowler-cloud/prowler"

ARG USERNAME=prowler
ARG USERID=34000

RUN yum install -y shadow-utils && \
  useradd -s /bin/sh -U -u ${USERID} ${USERNAME} && \
  yum install -y python3 bash curl jq coreutils py3-pip which unzip && \
  yum upgrade -y && \
  yum clean all && \
  pip3 install --upgrade pip && \
  pip3 install --no-cache-dir boto3 detect-secrets==1.0.3 && \
  pip3 cache purge && \
  curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && \
  unzip -q awscliv2.zip && \
  aws/install && \
  rm -rf aws awscliv2.zip /var/cache/yum && \
  rm /usr/bin/python && \
  ln -s /usr/bin/python3 /usr/bin/python

WORKDIR /prowler

COPY . ./

RUN chown -R prowler .

USER ${USERNAME}

ENTRYPOINT ["./prowler"]
