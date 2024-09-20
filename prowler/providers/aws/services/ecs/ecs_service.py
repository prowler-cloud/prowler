from re import sub
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ ECS
class ECS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.task_definitions = {}
        self.services = {}
        self.__threading_call__(self._list_task_definitions)
        self.__threading_call__(
            self._describe_task_definition, self.task_definitions.values()
        )
        self.__threading_call__(self._list_services)
        self.__threading_call__(self._describe_services, self.services.values())

    def _list_task_definitions(self, regional_client):
        logger.info("ECS - Listing Task Definitions...")
        try:
            list_ecs_paginator = regional_client.get_paginator("list_task_definitions")
            for page in list_ecs_paginator.paginate():
                for task_definition in page["taskDefinitionArns"]:
                    if not self.audit_resources or (
                        is_resource_filtered(task_definition, self.audit_resources)
                    ):
                        self.task_definitions[task_definition] = TaskDefinition(
                            # we want the family name without the revision
                            name=sub(":.*", "", task_definition.split("/")[1]),
                            arn=task_definition,
                            revision=task_definition.split(":")[-1],
                            region=regional_client.region,
                            environment_variables=[],
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_task_definition(self, task_definition):
        logger.info("ECS - Describing Task Definitions...")
        try:
            client = self.regional_clients[task_definition.region]
            response = client.describe_task_definition(
                taskDefinition=task_definition.arn,
                include=[
                    "TAGS",
                ],
            )
            container_definitions = response["taskDefinition"]["containerDefinitions"]
            for container in container_definitions:
                environment = []
                if "environment" in container:
                    for env_var in container["environment"]:
                        environment.append(
                            ContainerEnvVariable(
                                name=env_var["name"], value=env_var["value"]
                            )
                        )
                task_definition.container_definitions.append(
                    ContainerDefinition(
                        name=container["name"],
                        privileged=container.get("privileged", False),
                        user=container.get("user", ""),
                        environment=environment,
                    )
                )
            task_definition.tags = response.get("tags")
            task_definition.network_mode = response["taskDefinition"].get("networkMode")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_services(self, regional_client):
        logger.info("ECS - Listing Services...")
        try:
            list_ecs_paginator = regional_client.get_paginator("list_services")
            for page in list_ecs_paginator.paginate():
                for service in page["serviceArns"]:
                    if not self.audit_resources or (
                        is_resource_filtered(service, self.audit_resources)
                    ):
                        self.services[service] = Service(
                            name=sub(":.*", "", service.split("/")[1]),
                            arn=service,
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_services(self, service):
        logger.info("ECS - Describing Services...")
        try:
            client = self.regional_clients[service.region]
            response = client.describe_service(
                taskDefinition=service.arn,
                include=[
                    "TAGS",
                ],
            )
            service.assign_public_ip = (
                response.get("networkConfiguration", {})
                .get("awsvpcConfiguration", {})
                .get("assignPublicIp", "DISABLED")
                == "ENABLED"
            )
            service.tags = response.get("tags")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ContainerEnvVariable(BaseModel):
    name: str
    value: str


class ContainerDefinition(BaseModel):
    name: str
    privileged: bool
    user: str
    environment: list[ContainerEnvVariable]


class TaskDefinition(BaseModel):
    name: str
    arn: str
    revision: str
    region: str
    container_definitions: list[ContainerDefinition] = []
    tags: Optional[list] = []
    network_mode: Optional[str]


class Service(BaseModel):
    name: str
    arn: str
    region: str
    assign_public_ip: Optional[bool]
    tags: Optional[list] = []
