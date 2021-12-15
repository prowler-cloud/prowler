FROM alpine:3.15

ARG USERNAME=prowler
ARG USERID=34000

RUN addgroup -g ${USERID} ${USERNAME} && \
    adduser -s /bin/sh -G ${USERNAME} -D -u ${USERID} ${USERNAME} && \
    apk --update --no-cache add unzip python3 bash curl jq file coreutils py3-pip git && \
    pip3 install --upgrade pip && \
    pip3 install awscli boto3 detect-secrets==1.0.3 && \
    curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && \
    unzip awscliv2.zip &&\
    aws/install && \
    rm -rf aws && \
    rm -rf /var/cache/apk/*

WORKDIR /prowler

COPY . ./

RUN chown -R prowler .

USER ${USERNAME}

ENTRYPOINT ["./prowler"]
