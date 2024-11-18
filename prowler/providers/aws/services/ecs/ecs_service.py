from re import sub
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class ECS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.task_definitions = {}
        self.services = {}
        self.clusters = {}
        self.task_sets = {}
        self.__threading_call__(self._list_task_definitions)
        self.__threading_call__(
            self._describe_task_definition, self.task_definitions.values()
        )
        self.__threading_call__(self._list_clusters)
        self.__threading_call__(self._describe_clusters, self.clusters.values())
        self.__threading_call__(self._describe_services, self.clusters.values())

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
                            name=sub(":.*", "", task_definition.split("/")[-1]),
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
        logger.info("ECS - Describing Task Definition...")
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
                        readonly_rootfilesystem=container.get(
                            "readonlyRootFilesystem", False
                        ),
                        user=container.get("user", ""),
                        environment=environment,
                        log_driver=container.get("logConfiguration", {}).get(
                            "logDriver", ""
                        ),
                        log_option=container.get("logConfiguration", {})
                        .get("options", {})
                        .get("mode", ""),
                    )
                )
            task_definition.pid_mode = response["taskDefinition"].get("pidMode", "")
            task_definition.tags = response.get("tags")
            task_definition.network_mode = response["taskDefinition"].get(
                "networkMode", "bridge"
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_services(self, cluster):
        logger.info("ECS - Describing Services for each Cluster...")
        try:
            client = self.regional_clients[cluster.region]

            list_ecs_paginator = client.get_paginator("list_services")
            service_arns = []
            for page in list_ecs_paginator.paginate(cluster=cluster.arn):
                service_arns.extend(page["serviceArns"])

            if service_arns:
                for service_arn in service_arns:
                    describe_response = client.describe_services(
                        cluster=cluster.arn,
                        services=[service_arn],
                        include=["TAGS"],
                    )

                    service_desc = describe_response["services"][0]
                    service_arn = service_desc["serviceArn"]
                    service_obj = Service(
                        name=sub(":.*", "", service_arn.split("/")[-1]),
                        arn=service_arn,
                        region=cluster.region,
                        assign_public_ip=(
                            service_desc.get("networkConfiguration", {})
                            .get("awsvpcConfiguration", {})
                            .get("assignPublicIp", "DISABLED")
                            == "ENABLED"
                        ),
                        launch_type=service_desc.get("launchType", ""),
                        platform_version=service_desc.get("platformVersion", ""),
                        platform_family=service_desc.get("platformFamily", ""),
                        tags=service_desc.get("tags", []),
                    )
                    for task_set in service_desc.get("taskSets", []):
                        self.task_sets[task_set["taskSetArn"]] = TaskSet(
                            id=task_set["id"],
                            arn=task_set["taskSetArn"],
                            cluster_arn=task_set["clusterArn"],
                            service_arn=task_set["serviceArn"],
                            assign_public_ip=task_set.get("networkConfiguration", {})
                            .get("awsvpcConfiguration", {})
                            .get("assignPublicIp", "DISABLED"),
                            region=cluster.region,
                            tags=task_set.get("tags", []),
                        )
                    cluster.services[service_arn] = service_obj
                    self.services[service_arn] = service_obj
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_clusters(self, regional_client):
        logger.info("ECS - Listing Clusters...")
        try:
            list_ecs_paginator = regional_client.get_paginator("list_clusters")
            for page in list_ecs_paginator.paginate():
                for cluster in page["clusterArns"]:
                    if not self.audit_resources or (
                        is_resource_filtered(cluster, self.audit_resources)
                    ):
                        self.clusters[cluster] = Cluster(
                            name=sub(":.*", "", cluster.split("/")[-1]),
                            arn=cluster,
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_clusters(self, cluster):
        logger.info("ECS - Describing Clusters...")
        try:
            client = self.regional_clients[cluster.region]
            response = client.describe_clusters(
                clusters=[cluster.arn],
                include=[
                    "TAGS",
                ],
            )
            cluster.settings = response["clusters"][0].get("settings", [])
            cluster.tags = response["clusters"][0].get("tags", [])
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
    readonly_rootfilesystem: bool = False
    user: str
    environment: list[ContainerEnvVariable]
    log_driver: Optional[str]
    log_option: Optional[str]


class TaskDefinition(BaseModel):
    name: str
    arn: str
    revision: str
    region: str
    container_definitions: list[ContainerDefinition] = []
    pid_mode: Optional[str]
    tags: Optional[list] = []
    network_mode: Optional[str]


class Service(BaseModel):
    name: str
    arn: str
    region: str
    launch_type: str = ""
    platform_version: Optional[str]
    platform_family: Optional[str]
    assign_public_ip: Optional[bool]
    tags: Optional[list] = []


class Cluster(BaseModel):
    name: str
    arn: str
    region: str
    services: dict = {}
    settings: Optional[list] = []
    tags: Optional[list] = []


class TaskSet(BaseModel):
    id: str
    arn: str
    cluster_arn: str
    service_arn: str
    region: str
    assign_public_ip: Optional[str]
    tags: Optional[list] = []
