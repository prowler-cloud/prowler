FROM python:3.7-slim
MAINTAINER Bridgecrew <www.bridgecrew.io>

RUN apt-get update && apt-get upgrade -y && apt-get install jq curl -y && pip install awscli detect-secrets boto3

RUN curl -sL https://github.com/bridgecrewio/prowler/archive/feature/dockerized_prowler.tar.gz | tar xz

WORKDIR "./prowler-feature-dockerized_prowler"

ENTRYPOINT ["./run.sh"]
