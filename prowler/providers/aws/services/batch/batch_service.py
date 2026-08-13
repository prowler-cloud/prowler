from itertools import zip_longest
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.resource_limit import get_resource_scan_limit, limit_resources
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
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
        self.job_definitions = {}
        self._job_definitions_by_region = {}
        self.job_definition_limit = get_resource_scan_limit(
            self.audit_config, "max_batch_job_definitions"
        )
        self.__threading_call__(self._list_job_definitions)
        self._select_job_definitions_for_analysis()

    def _list_job_definitions(self, regional_client):
        """List ACTIVE job definitions for a regional client."""
        logger.info("Batch - Listing Job Definitions...")
        try:
            paginator = regional_client.get_paginator("describe_job_definitions")
            regional_job_definitions = []
            # Deregistered (INACTIVE) revisions are excluded: they cannot run
            # new jobs, and reporting them would only produce noise.
            for page in paginator.paginate(status="ACTIVE"):
                for job in page.get("jobDefinitions", []):
                    if self.audit_resources and not is_resource_filtered(
                        job["jobDefinitionArn"], self.audit_resources
                    ):
                        continue
                    container = job.get("containerProperties", {})
                    environment = [
                        ContainerEnvVariable(
                            name=env["name"], value=env.get("value", "")
                        )
                        for env in container.get("environment", [])
                    ]
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
            self._job_definitions_by_region[regional_client.region] = (
                regional_job_definitions
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _select_job_definitions_for_analysis(self):
        """Apply the global resource limit, interleaving regions fairly."""
        interleaved = [
            job_definition
            for region_batch in zip_longest(*self._job_definitions_by_region.values())
            for job_definition in region_batch
            if job_definition
        ]
        self.job_definitions = {
            job_definition.arn: job_definition
            for job_definition in limit_resources(
                interleaved, self.job_definition_limit
            )
        }
