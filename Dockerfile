FROM python
MAINTAINER Bridgecrew <www.bridgecrew.io>

RUN apt-get update && apt-get upgrade -y && apt-get install jq -y && pip install awscli detect-secrets

RUN curl -sL https://github.com/bridgecrewio/prowler/archive/master.tar.gz | tar xz

RUN run.sh
