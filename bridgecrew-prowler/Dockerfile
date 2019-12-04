FROM toniblyx/prowler
MAINTAINER Bridgecrew <www.bridgecrew.io>

USER root

WORKDIR "./prowler"

COPY "./run.sh" "."

RUN chown -R prowler /prowler/

USER prowler

ENTRYPOINT ["./run.sh"]
