import json
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class DMS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.instances = []
        self.endpoints = {}
        self.replication_tasks = {}
        self.__threading_call__(self._describe_replication_instances)
        self.__threading_call__(self._list_tags, self.instances)
        self.__threading_call__(self._describe_endpoints)
        self.__threading_call__(self._describe_replication_tasks)
        self.__threading_call__(self._list_tags, self.endpoints.values())
        self.__threading_call__(self._describe_replication_tasks)
        self.__threading_call__(self._list_tags, self.replication_tasks.values())

    def _describe_replication_instances(self, regional_client):
        logger.info("DMS - Describing DMS Replication Instances...")
        try:
            describe_replication_instances_paginator = regional_client.get_paginator(
                "describe_replication_instances"
            )
            for page in describe_replication_instances_paginator.paginate():
                for instance in page["ReplicationInstances"]:
                    arn = instance["ReplicationInstanceArn"]
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.instances.append(
                            RepInstance(
                                id=instance["ReplicationInstanceIdentifier"],
                                arn=arn,
                                status=instance["ReplicationInstanceStatus"],
                                public=instance["PubliclyAccessible"],
                                kms_key=instance["KmsKeyId"],
                                auto_minor_version_upgrade=instance[
                                    "AutoMinorVersionUpgrade"
                                ],
                                security_groups=[
                                    sg["VpcSecurityGroupId"]
                                    for sg in instance["VpcSecurityGroups"]
                                    if sg["Status"] == "active"
                                ],
                                multi_az=instance["MultiAZ"],
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_endpoints(self, regional_client):
        logger.info("DMS - Describing DMS Endpoints...")
        try:
            describe_endpoints_paginator = regional_client.get_paginator(
                "describe_endpoints"
            )
            for page in describe_endpoints_paginator.paginate():
                for endpoint in page["Endpoints"]:
                    arn = endpoint["EndpointArn"]
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.endpoints[arn] = Endpoint(
                            arn=arn,
                            id=endpoint["EndpointIdentifier"],
                            region=regional_client.region,
                            ssl_mode=endpoint.get("SslMode", False),
                            redis_ssl_protocol=endpoint.get("RedisSettings", {}).get(
                                "SslSecurityProtocol", "plaintext"
                            ),
                            mongodb_auth_type=endpoint.get("MongoDbSettings", {}).get(
                                "AuthType", "no"
                            ),
                            neptune_iam_auth_enabled=endpoint.get(
                                "NeptuneSettings", {}
                            ).get("IamAuthEnabled", False),
                            engine_name=endpoint["EngineName"],
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_replication_tasks(self, regional_client):
        logger.info("DMS - Describing DMS Replication Tasks for Logging Settings...")
        try:
            paginator = regional_client.get_paginator("describe_replication_tasks")
            for page in paginator.paginate():
                for task in page["ReplicationTasks"]:
                    arn = task["ReplicationTaskArn"]
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        task_settings = json.loads(
                            task.get("ReplicationTaskSettings", "")
                        )
                        self.replication_tasks[arn] = ReplicationTasks(
                            arn=arn,
                            id=task["ReplicationTaskIdentifier"],
                            region=regional_client.region,
                            source_endpoint_arn=task["SourceEndpointArn"],
                            target_endpoint_arn=task["TargetEndpointArn"],
                            logging_enabled=task_settings.get("Logging", {}).get(
                                "EnableLogging", False
                            ),
                            log_components=task_settings.get("Logging", {}).get(
                                "LogComponents", []
                            ),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags(self, resource: any):
        try:
            resource.tags = self.regional_clients[
                resource.region
            ].list_tags_for_resource(ResourceArn=resource.arn)["TagList"]
        except Exception as error:
            logger.error(
                f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Endpoint(BaseModel):
    arn: str
    id: str
    region: str
    ssl_mode: str
    redis_ssl_protocol: str
    mongodb_auth_type: str
    neptune_iam_auth_enabled: bool = False
    engine_name: str
    tags: Optional[list]


class RepInstance(BaseModel):
    id: str
    arn: str
    status: str
    public: bool
    kms_key: str
    auto_minor_version_upgrade: bool
    security_groups: list[str] = []
    multi_az: bool
    region: str
    tags: Optional[list] = []


class ReplicationTasks(BaseModel):
    arn: str
    id: str
    region: str
    source_endpoint_arn: str
    target_endpoint_arn: str
    logging_enabled: bool = False
    log_components: list[dict] = []
    tags: Optional[list] = []
