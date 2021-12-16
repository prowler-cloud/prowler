FROM public.ecr.aws/amazonlinux/amazonlinux:latest

ARG USERNAME=prowler
ARG USERID=34000

RUN yum install -y shadow-utils && \
  useradd -s /bin/sh -U -u ${USERID} ${USERNAME} && \
  yum install -y python3 bash curl jq file coreutils py3-pip which && \
  yum clean all && \
  pip3 install --upgrade pip && \
  pip3 install awscli boto3 detect-secrets

WORKDIR /prowler

COPY . ./

RUN chown -R prowler .

USER ${USERNAME}

ENTRYPOINT ["./prowler"]
