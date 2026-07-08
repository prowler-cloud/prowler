from datetime import datetime
from itertools import zip_longest
from re import sub
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.resource_limit import (
    get_resource_scan_limit,
    iter_limited_paginator_items,
    limit_resources,
)
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class ECS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        # Task definition ARNs are listed first, then only the selected subset
        # is described and exposed for checks.
        self.task_definitions = {}
        self._task_definition_arns = None
        self._task_definition_arns_by_region = {}
        self.task_definition_limit = get_resource_scan_limit(
            self.audit_config, "max_ecs_task_definitions"
        )
        self.services = {}
        self.clusters = {}
        self.task_sets = {}
        for _ in self._load_task_definitions_for_analysis():
            pass
        self.__threading_call__(self._list_clusters)
        self.__threading_call__(self._describe_clusters, self.clusters.values())
        self.__threading_call__(self._describe_services, self.clusters.values())

    def _list_task_definition_arns(self) -> list:
        """List task definition ARNs newest-first, memoized.

        AWS returns ``list_task_definitions(sort=DESC)`` results per region.
        Prowler limits the task definitions it describes and exposes to checks.
        """
        if self._task_definition_arns is not None:
            return self._task_definition_arns
        logger.info("ECS - Listing Task Definitions...")
        self.__threading_call__(self._list_task_definition_arns_by_region)
        arns_by_region = []
        for region in self.regional_clients:
            arns_by_region.append(self._task_definition_arns_by_region.get(region, []))
        arns = []
        for task_definition_batch in zip_longest(*arns_by_region):
            for task_definition in task_definition_batch:
                if task_definition:
                    arns.append(task_definition)
        self._task_definition_arns = arns
        return arns

    def _list_task_definition_arns_by_region(self, regional_client):
        try:
            list_ecs_paginator = regional_client.get_paginator("list_task_definitions")
            regional_arns = []
            for task_definition in iter_limited_paginator_items(
                list_ecs_paginator,
                "taskDefinitionArns",
                None,
                item_filter=lambda task_definition: not self.audit_resources
                or is_resource_filtered(task_definition, self.audit_resources),
                sort="DESC",
            ):
                regional_arns.append((task_definition, regional_client.region))
            self._task_definition_arns_by_region[regional_client.region] = regional_arns
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _load_task_definitions_for_analysis(self):
        """Yield task definitions lazily, describing each one on demand.

        Resources already fetched are memoized in ``self.task_definitions`` and
        reused across checks (checks run sequentially, so no locking is needed).
        Task definitions are described before applying the configured resource
        limit because AWS exposes ``registeredAt`` only through
        ``describe_task_definition``. The limit bounds the task definitions
        exposed to checks for analysis.
        """
        task_definitions = []
        for arn, region in self._list_task_definition_arns():
            task_definition = self.task_definitions.get(arn)
            if task_definition is None:
                task_definition = TaskDefinition(
                    # we want the family name without the revision
                    name=sub(":.*", "", arn.split("/")[-1]),
                    arn=arn,
                    revision=arn.split(":")[-1],
                    region=region,
                    environment_variables=[],
                )
                self.task_definitions[arn] = task_definition
                task_definitions.append(task_definition)

        self.__threading_call__(self._describe_task_definition, task_definitions)

        selected_task_definitions = list(
            limit_resources(
                self._sort_task_definitions_by_registration_date(
                    self.task_definitions.values()
                ),
                self.task_definition_limit,
            )
        )
        self.task_definitions = {
            task_definition.arn: task_definition
            for task_definition in selected_task_definitions
        }
        for task_definition in selected_task_definitions:
            yield task_definition

    @staticmethod
    def _sort_task_definitions_by_registration_date(task_definitions):
        task_definitions = list(task_definitions)
        if not any(
            task_definition.registered_at for task_definition in task_definitions
        ):
            return task_definitions

        return sorted(
            task_definitions,
            key=lambda task_definition: (
                task_definition.registered_at is None,
                (
                    -task_definition.registered_at.timestamp()
                    if task_definition.registered_at
                    else 0
                ),
                task_definition.arn,
            ),
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
            task_definition.registered_at = response["taskDefinition"].get(
                "registeredAt"
            )
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
                        id=f"{sub(':.*', '', service_arn.split('/')[-2])}/{sub(':.*', '', service_arn.split('/')[-1])}",
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
                    "SETTINGS",
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
    registered_at: Optional[datetime] = None
    tags: Optional[list] = []
    network_mode: Optional[str]


class Service(BaseModel):
    name: str
    id: str
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
