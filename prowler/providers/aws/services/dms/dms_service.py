from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## Database Migration Service
class DMS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.instances = []
        self.endpoints = {}
        self.__threading_call__(self._describe_replication_instances)
        self.__threading_call__(
            self._list_tags, [instance.arn for instance in self.instances]
        )
        self.__threading_call__(self._describe_endpoints)
        self.__threading_call__(self._list_tags, list(self.endpoints.keys()))

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
                            id=endpoint["EndpointIdentifier"],
                            ssl_mode=endpoint.get("SslMode", False),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags(self, resource_arn: str):
        try:
            tags = self.regional_clients[
                resource_arn.split(":")[3]
            ].list_tags_for_resource(ResourceArn=resource_arn)["TagList"]

            # Based on the resource_arn, we can determine if it's a Replication Instance or an Endpoint
            if resource_arn.split(":")[5] == "rep":
                for instance in self.instances:
                    if instance.arn == resource_arn:
                        instance.tags = tags
                        break
            elif resource_arn.split(":")[5] == "endpoint":
                self.endpoints[resource_arn].tags = tags

        except Exception as error:
            logger.error(
                f"{self.client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Endpoint(BaseModel):
    id: str
    ssl_mode: str
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
    tags: Optional[list]
