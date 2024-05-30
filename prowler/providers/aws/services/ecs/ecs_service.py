from re import sub
from typing import Dict, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class ECS(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.task_definitions = []
        self.__threading_call__(self.__list_task_definitions__)
        self.__describe_task_definition__()
        self.clusters = {}
        self.__threading_call__(self.__list_clusters__)
        self.__describe_clusters__()
        self.__list_services__()
        self.__describe_services__()

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

    def __list_clusters__(self, regional_client):
        logger.info("ECS - Listing Clusters...")
        try:
            cluster_paginator = regional_client.get_paginator("list_clusters")
            for cluster in cluster_paginator.paginate():
                for cluster_arn in cluster["clusterArns"]:
                    if not self.audit_resources or (
                        is_resource_filtered(cluster, self.audit_resources)
                    ):
                        self.clusters[cluster_arn] = Cluster(
                            name=cluster_arn.split("/")[-1],
                            region=regional_client.region,
                            status="",
                            services={},
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_clusters__(self):
        logger.info("ECS - Describing Clusters...")
        try:
            for cluster_arn, cluster in self.clusters.items():
                client = self.regional_clients[cluster.region]
                response = client.describe_clusters(clusters=[cluster_arn])
                cluster.status = response["clusters"][0]["status"]
                cluster.tags = response["clusters"][0].get("tags")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_services__(self):
        logger.info("ECS - Listing Services...")
        try:
            for cluster_arn, cluster in self.clusters.items():
                client = self.regional_clients[cluster.region]
                service_paginator = client.get_paginator("list_services")
                for service in service_paginator.paginate(cluster=cluster_arn):
                    for service_arn in service["serviceArns"]:
                        if not self.audit_resources or (
                            is_resource_filtered(service_arn, self.audit_resources)
                        ):
                            self.clusters[cluster_arn].services[service_arn] = Service(
                                name=service_arn.split("/")[-1],
                                status="",
                                load_balancers_target_groups=[],
                                security_groups=[],
                                tags=[],
                            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_services__(self):
        logger.info("ECS - Describing Services...")
        try:
            for cluster_arn, cluster in self.clusters.items():
                client = self.regional_clients[cluster.region]

                service_arns = [service_arn for service_arn in cluster.services.keys()]
                # API sets maximum of 10 services per call
                for i in range(0, len(service_arns), 10):
                    response = client.describe_services(
                        cluster=cluster_arn, services=service_arns[i : i + 10]
                    )
                    for service in response["services"]:
                        cluster.services[service["serviceArn"]].status = service[
                            "status"
                        ]
                        cluster.services[
                            service["serviceArn"]
                        ].load_balancers_target_groups = [
                            lb["targetGroupArn"]
                            for lb in service.get("loadBalancers", [])
                        ]
                        cluster.services[service["serviceArn"]].security_groups = (
                            service.get("networkConfiguration", {})
                            .get("awsvpcConfiguration", {})
                            .get("securityGroups", [])
                        )
                        cluster.services[service["serviceArn"]].tags = service.get(
                            "tags", []
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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


class Service(BaseModel):
    name: str
    status: str
    load_balancers_target_groups: list
    security_groups: list
    tags: Optional[list] = []


class Cluster(BaseModel):
    name: str
    region: str
    status: str
    tags: Optional[list] = []
    services: Dict[str, Service]
