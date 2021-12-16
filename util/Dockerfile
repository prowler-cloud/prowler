FROM amazonlinux:latest

ARG USERNAME=prowler
ARG USERID=34000

RUN \ 
# The YUM stuff and cleanup
  yum upgrade -y && \
  yum install -y shadow-utils python3 bash curl jq coreutils py3-pip which unzip && \
  yum clean all && \
# The PIP stuff and cleanup
  pip3 install --upgrade pip && \
  pip3 install detect-secrets==1.0.3 && \
  pip3 cache purge && \
# The CURL stuff and cleanup 
  curl -L https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && \
  unzip awscliv2.zip && \
  aws/install && \
  rm -rf awscliv2.zip aws /var/cache/yum && \
# The SECURITY stuff
  useradd -s /bin/sh -U -u ${USERID} ${USERNAME}

WORKDIR /prowler

COPY . ./

RUN chown -R prowler .

USER ${USERNAME}

ENTRYPOINT ["./prowler"]
