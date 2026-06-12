# Build command
# docker build --platform=linux/amd64  --no-cache -t prowler:latest .

ARG PROWLER_VERSION=latest@sha256:aa48c4b5fad9ba70be794fe574166a335309e9688af0f3d35921f1ea36e26713

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
