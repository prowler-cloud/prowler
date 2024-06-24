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
        self.__threading_call__(self.__describe_replication_instances__)

    def __describe_replication_instances__(self, regional_client):
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
