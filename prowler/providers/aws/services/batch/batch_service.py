from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class JobDefinitionContainer(BaseModel):
    """Represents a container within a Batch Job Definition."""

    name: str
    environment: list[dict] = Field(default_factory=list)
    command: list[str] = Field(default_factory=list)


class JobDefinition(BaseModel):
    """Represents an AWS Batch Job Definition."""

    name: str
    arn: str
    revision: int
    region: str
    containers: list[JobDefinitionContainer] = Field(default_factory=list)
    tags: list[dict] = Field(default_factory=list)


class Batch(AWSService):
    """AWS Batch service class."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.job_definitions = {}
        self.__threading_call__(self._describe_job_definitions)

    def _describe_job_definitions(self, regional_client) -> None:
        logger.info("Batch - Describing Job Definitions...")
        try:
            describe_job_definitions_paginator = regional_client.get_paginator(
                "describe_job_definitions"
            )
            for page in describe_job_definitions_paginator.paginate(status="ACTIVE"):
                for job_definition in page.get("jobDefinitions", []):
                    job_definition_arn = job_definition.get("jobDefinitionArn")
                    job_definition_name = job_definition.get("jobDefinitionName")
                    if not self.audit_resources or is_resource_filtered(
                        job_definition_arn, self.audit_resources
                    ):
                        containers = []

                        # 1. Single container job definition
                        if "containerProperties" in job_definition:
                            container_props = job_definition["containerProperties"]
                            containers.append(
                                JobDefinitionContainer(
                                    name="containerProperties",
                                    environment=container_props.get("environment", []),
                                    command=container_props.get("command", []),
                                )
                            )

                        # 2. Multi-node parallel job definition
                        if "nodeProperties" in job_definition:
                            node_props = job_definition["nodeProperties"]
                            for idx, range_prop in enumerate(
                                node_props.get("nodeRangeProperties", [])
                            ):
                                if "container" in range_prop:
                                    container_props = range_prop["container"]
                                    containers.append(
                                        JobDefinitionContainer(
                                            name=f"nodeRangeProperties[{idx}].container",
                                            environment=container_props.get(
                                                "environment", []
                                            ),
                                            command=container_props.get("command", []),
                                        )
                                    )

                        # 3. EKS container definition
                        if "eksProperties" in job_definition:
                            eks_props = job_definition["eksProperties"]
                            pod_props = eks_props.get("podProperties", {})
                            for idx, container in enumerate(
                                pod_props.get("containers", [])
                            ):
                                command_and_args = list(
                                    container.get("command", [])
                                ) + list(container.get("args", []))
                                env_list = []
                                for env_var in container.get("env", []):
                                    if "name" in env_var and "value" in env_var:
                                        env_list.append(
                                            {
                                                "name": env_var["name"],
                                                "value": env_var["value"],
                                            }
                                        )
                                containers.append(
                                    JobDefinitionContainer(
                                        name=f"eksProperties.podProperties.containers[{idx}]",
                                        environment=env_list,
                                        command=command_and_args,
                                    )
                                )

                        tags = job_definition.get("tags", {})
                        tags_list = [tags] if tags else []

                        self.job_definitions[job_definition_arn] = JobDefinition(
                            name=job_definition_name,
                            arn=job_definition_arn,
                            revision=job_definition.get("revision"),
                            region=regional_client.region,
                            containers=containers,
                            tags=tags_list,
                        )
        except ClientError as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
