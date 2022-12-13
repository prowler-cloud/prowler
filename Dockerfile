FROM python:3.9-alpine

RUN pip install --no-cache-dir prowler-cloud

ENTRYPOINT ["prowler"]
