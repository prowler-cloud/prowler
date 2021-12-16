FROM public.ecr.aws/amazonlinux/amazonlinux:latest

ARG USERNAME=prowler
ARG USERID=34000

RUN yum install -y shadow-utils && \
  useradd -s /bin/sh -U -u ${USERID} ${USERNAME} && \
  yum install -y python3 bash curl jq file coreutils py3-pip which unzip && \
  yum clean all && \
  pip3 install --upgrade pip && \
  pip3 install boto3 detect-secrets==1.0.3 && \
  curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && \
  unzip awscliv2.zip && \
  aws/install && \
  rm -rf aws awscliv2.zip

WORKDIR /prowler

COPY . ./

RUN chown -R prowler .

USER ${USERNAME}

ENTRYPOINT ["./prowler"]
