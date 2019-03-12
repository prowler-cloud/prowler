FROM alpine:3.9

ARG USERNAME=prowler
ARG USERID=34000

RUN addgroup -g ${USERID} ${USERNAME} && \
    adduser -s /bin/sh -G ${USERNAME} -D -u ${USERID} ${USERNAME} && \
    apk --update --no-cache add python3 bash curl git jq && \
    pip3 install --upgrade pip && \
    pip install awscli ansi2html boto3 &&\
    git clone https://github.com/toniblyx/prowler/

USER ${USERNAME}

ENTRYPOINT ["/prowler/prowler"]