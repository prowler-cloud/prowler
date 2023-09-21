from re import sub
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService
# from prowler.providers.aws.services.ec2.ec2_client import ec2_client
# from prowler.providers.aws.services.autoscaling.autoscaling_client import autoscaling_client


################################ ECS
class ECS(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.task_definitions = []
        self.__threading_call__(self.__list_task_definitions__)
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
                                network_mode=""
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
                task_definition.network_mode = response["taskDefinition"].get("networkMode")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __public_subnets__(self):
        print()
        clusters = self.client.list_clusters()
        print(type(clusters["clusterArns"][0]))
        print()
        print(clusters)
        print()
        described_clusters = self.client.describe_clusters(clusters=clusters["clusterArns"])
        print()
        for cluster in described_clusters["clusters"]:
            print(cluster["clusterName"])
            print(cluster)
            capacity_providers = self.client.describe_capacity_providers(capacityProviders=cluster["capacityProviders"])
            for capacity_provider in capacity_providers["capacityProviders"]:
                print(capacity_provider)
                if capacity_provider.get("autoScalingGroupProvider"):
                    print(capacity_provider.get("autoScalingGroupProvider"))
                    print()
                    print(autoscaling_client.client.describe_auto_scaling_groups(AutoScalingGroupNames=[capacity_provider["autoScalingGroupProvider"]["autoScalingGroupArn"].split('/')[-1]]))

            print()


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
    network_mode: str
