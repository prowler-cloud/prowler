from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################## DocumentDB
class DocumentDB(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        self.service_name = "docdb"
        super().__init__(self.service_name, audit_info)
        self.db_instances = {}
        self.__threading_call__(self.__describe_db_instances__)
        self.__list_tags_for_resource__()

    def __describe_db_instances__(self, regional_client):
        logger.info("DocumentDB - Describe Instances...")
        try:
            describe_db_instances_paginator = regional_client.get_paginator(
                "describe_db_instances"
            )
            for page in describe_db_instances_paginator.paginate(
                Filters=[
                    {
                        "Name": "engine",
                        "Values": [
                            self.service_name,
                        ],
                    },
                ],
            ):
                for instance in page["DBInstances"]:
                    instance_arn = instance["DBInstanceArn"]
                    self.db_instances[instance_arn] = Instance(
                        id=instance["DBInstanceIdentifier"],
                        arn=instance["DBInstanceArn"],
                        engine=instance["Engine"],
                        engine_version=instance["EngineVersion"],
                        status=instance["DBInstanceStatus"],
                        public=instance["PubliclyAccessible"],
                        encrypted=instance["StorageEncrypted"],
                        cluster_id=instance.get("DBClusterIdentifier"),
                        region=regional_client.region,
                        tags=instance.get("TagList", []),
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("DocumentDB - List Tags...")
        try:
            for instance_arn, instance in self.db_instances.items():
                try:
                    regional_client = self.regional_clients[instance.region]
                    response = regional_client.list_tags_for_resource(
                        ResourceName=instance_arn
                    )["TagList"]
                    instance.tags = response
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Instance(BaseModel):
    id: str
    arn: str
    engine: str
    engine_version: str
    status: str
    public: bool
    encrypted: bool
    cluster_id: Optional[str]
    region: str
    tags: Optional[list]
