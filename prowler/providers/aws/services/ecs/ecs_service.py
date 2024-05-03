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
        self.task_definitions = []
        self.containers = []
        self.__threading_call__(self.__list_task_definitions__)
        self.__threading_call__(self.__describe_container_instances__)
        self.__describe_task_definition__()

    def __list_task_definitions__(self, regional_client):
        logger.info("ECS - Listing Task Definitions...")
        try:
            list_ecs_paginator = regional_client.get_paginator("list_task_definitions")
            for page in list_ecs_paginator.paginate():
                for task_definition in page["taskDefinitionArns"]:
                    if not self.audit_resources or (
                        is_resource_filtered(task_definition, self.audit_resources)
                    ):
                        self.task_definitions.append(
                            TaskDefinition(
                                # we want the family name without the revision
                                name=sub(":.*", "", task_definition.split("/")[1]),
                                arn=task_definition,
                                revision=task_definition.split(":")[-1],
                                region=regional_client.region,
                                environment_variables=[],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_task_definition__(self):
        logger.info("ECS - Describing Task Definitions...")
        try:
            for task_definition in self.task_definitions:
                client = self.regional_clients[task_definition.region]
                response = client.describe_task_definition(
                    taskDefinition=task_definition.arn,
                    include=[
                        "TAGS",
                    ],
                )
                container_definitions = response["taskDefinition"][
                    "containerDefinitions"
                ]
                for container in container_definitions:
                    if "environment" in container:
                        for env_var in container["environment"]:
                            task_definition.environment_variables.append(
                                ContainerEnvVariable(
                                    name=env_var["name"], value=env_var["value"]
                                )
                            )
                task_definition.tags = response.get("tags")
                task_definition.network_mode = response["taskDefinition"].get(
                    "networkMode"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_container_instances__(self, regional_client):
        logger.info("ECS - Describing Container Instances...")
        try:
            for container in regional_client.describe_container_instances()["containerInstances"]:
                if not self.audit_resources or (
                    is_resource_filtered(container, self.audit_resources)
                ):
                    cont = Containers(
                        arn=container['containerInstanceArn'],
                        tags=container['tags'],
                    )
                    for attachment in container['attachments']:
                        if attachment['type'] == 'ElasticNetworkInterface':
                            for detail in attachment['details']:
                                if detail['name'] == 'networkInterfaceId':
                                    for eni in regional_client.describe_network_interfaces(NetworkInterfaceIds=detail['value'])["NetworkInterfaces"]:
                                        cont.availability_zone = eni['AvailabilityZone']
                                        for ipv6 in eni["Ipv6Addresses"]:
                                            if ipv6['Primary']:
                                                cont.ipv6 = ipv6['Ipv6Addresses']
                                                break
                                        for ipv4 in eni["PrivateIpAddresses"]:
                                            if ipv4['Primary']:
                                                cont.ipv4 = ipv4['PrivateIpAddress']
                                                break

                    self.containers.append(cont)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ContainerEnvVariable(BaseModel):
    name: str
    value: str


class TaskDefinition(BaseModel):
    name: str
    arn: str
    revision: str
    region: str
    environment_variables: list[ContainerEnvVariable]
    tags: Optional[list] = []
    network_mode: Optional[str]

class Containers(BaseModel):
    arn: str
    availability_zone: str
    ipv6: Optional[str]
    ipv4: Optional[str]
    tags: Optional[list] = []