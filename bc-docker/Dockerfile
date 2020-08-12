# To build and push a new version:
# docker build . --no-cache -t bridgecrew/dockerized-prowler:latest -t bridgecrew/dockerized-prowler:VERSION_NUM
# docker push bridgecrew/dockerized-prowler:latest
# docker push bridgecrew/dockerized-prowler:VERSION_NUM

FROM alpine:3.9
MAINTAINER Bridgecrew <www.bridgecrew.io>

ARG USERNAME=prowler
ARG USERID=34000

RUN addgroup -g ${USERID} ${USERNAME} && \
    adduser -s /bin/sh -G ${USERNAME} -D -u ${USERID} ${USERNAME} && \
    apk --update --no-cache add py3-pip bash curl jq coreutils file git && \
    pip3 install --upgrade pip && \
    pip install awscli ansi2html boto3 detect-secrets

RUN git clone https://github.com/bridgecrewio/prowler.git

WORKDIR "./prowler"
COPY "./run.sh" "."

RUN chown -R prowler /prowler/

USER ${USERNAME}

ENTRYPOINT ["./run.sh"]
