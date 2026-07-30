from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.resource_limit import get_resource_scan_limit, limit_resources
from prowler.providers.aws.lib.service.service import AWSService


class ContainerEnvVariable(BaseModel):
    """An environment variable name-value pair."""

    name: str
    value: str


class BatchContainerProperties(BaseModel):
    """Container properties for an AWS Batch job definition."""

    image: Optional[str]
    command: list[str] = []
    environment: list[ContainerEnvVariable] = []


class BatchJobDefinition(BaseModel):
    """An AWS Batch job definition with its container properties."""

    name: str
    arn: str
    revision: int
    region: str
    container_properties: BatchContainerProperties


class Batch(AWSService):
    """AWS Batch service client for listing job definitions."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.job_definitions = []
        self.job_definition_limit = get_resource_scan_limit(
            self.audit_config, "max_batch_job_definitions"
        )

        self.__threading_call__(self._list_job_definitions)

    def _list_job_definitions(self, regional_client):
        """List job definitions for a regional client."""
        logger.info("Batch - Listing Job Definitions...")

        try:
            paginator = regional_client.get_paginator(
                "describe_job_definitions"
            )

            regional_job_definitions = []
            for page in paginator.paginate():

                for job in page.get("jobDefinitions", []):

                    environment = []

                    container = job.get("containerProperties", {})

                    for env in container.get("environment", []):
                        environment.append(
                            ContainerEnvVariable(
                                name=env["name"],
                                value=env["value"],
                            )
                        )

                    regional_job_definitions.append(
                        BatchJobDefinition(
                            name=job["jobDefinitionName"],
                            arn=job["jobDefinitionArn"],
                            revision=job["revision"],
                            region=regional_client.region,
                            container_properties=BatchContainerProperties(
                                image=container.get("image"),
                                command=container.get("command", []),
                                environment=environment,
                            ),
                        )
                    )

            self.job_definitions.extend(
                limit_resources(
                    regional_job_definitions, self.job_definition_limit
                )
            )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
