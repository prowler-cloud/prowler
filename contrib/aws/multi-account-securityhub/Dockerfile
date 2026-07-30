# Build command
# docker build --platform=linux/amd64  --no-cache -t prowler:latest .

ARG PROWLER_VERSION=latest@sha256:5481969971af03cac14b194964244c5a0777f5008e64e0616e4f0d7b720ae8a7

FROM toniblyx/prowler:${PROWLER_VERSION}

USER 0
# hadolint ignore=DL3018
RUN apk --no-cache add bash aws-cli jq

ARG MULTI_ACCOUNT_SECURITY_HUB_PATH=/home/prowler/multi-account-securityhub

USER prowler

# Move script and environment variables
RUN mkdir "${MULTI_ACCOUNT_SECURITY_HUB_PATH}"
COPY --chown=prowler:prowler .awsvariables run-prowler-securityhub.sh  "${MULTI_ACCOUNT_SECURITY_HUB_PATH}"/
RUN chmod 500 "${MULTI_ACCOUNT_SECURITY_HUB_PATH}"/run-prowler-securityhub.sh & \
    chmod 400 "${MULTI_ACCOUNT_SECURITY_HUB_PATH}"/.awsvariables

WORKDIR ${MULTI_ACCOUNT_SECURITY_HUB_PATH}

ENTRYPOINT ["./run-prowler-securityhub.sh"]
